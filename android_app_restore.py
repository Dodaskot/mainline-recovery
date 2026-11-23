#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Restore one portable Android application's CE and DE files without replacing its roots."""
from collections import defaultdict
from contextlib import ExitStack, contextmanager, suppress
import hashlib
import os
import re
import shutil
import stat

import android_data as ad
import archive_crypt as crypt
import filesystem as fs
import partition_archive as pa

STAGING_PREFIX = '.a22x-restore-app-'
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
DIR = READ | os.O_DIRECTORY


def inode(st):
    return st.st_dev, st.st_ino


def named(directory, name):
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None


def permission(record):
    # A portable file inherits the destination app's isolation. The archive
    # supplies its owner's access bits, not cross-app modes or privilege bits.
    return record['mode'] & 0o700


class Scope:
    def __init__(self, pin, directory, relative, records, target_uid):
        self.pin, self.directory, self.relative, self.records = pin, directory, relative, records
        owner = os.fstat(directory)
        self.identity = inode(owner)
        self.uid, self.gid = owner.st_uid, owner.st_gid
        ad.require(self.uid == target_uid and self.gid == target_uid,
                   'PACKAGE_DATA_OWNER_MISMATCH', 'Android application directory has the wrong target owner')
        self.label = None
        if not ad.fixture(pin.context):
            self.label = os.getxattr(directory, 'security.selinux')
            ad.require(re.fullmatch(rb'u:object_r:app_data_file:s0(?::c[0-9]+(?:,c[0-9]+)*)?\x00?', self.label),
                       'PACKAGE_LABEL_UNSUPPORTED', 'The target directory requires a special Android SELinux label')
        self.children = defaultdict(set)
        for parts in records:
            self.children[parts[:-1]].add(parts[-1])
        self.pending = set()
        for name in sorted(self.children[()]):
            if named(directory, name) is None:
                self.pending.add(name)
            else:
                self.check_existing(directory, (name,))
        self.stage = None
        self.directories = []

    def recheck(self):
        with self.pin.directory(self.relative) as current:
            st = os.fstat(current)
            ad.require(inode(st) == self.identity and (st.st_uid, st.st_gid) == (self.uid, self.gid),
                       'TARGET_CHANGED', 'The Android application directory changed')
            ad.same_policy(self.pin.context, self.directory, current)
            if self.label is not None:
                ad.require(os.getxattr(current, 'security.selinux') == self.label,
                           'TARGET_CHANGED', 'The Android application label changed')

    def check_existing(self, parent, parts):
        name = parts[-1]
        entry = self.records[parts]
        before = named(parent, name)
        is_dir = entry['type'] == 'directory'
        message = 'Existing application files differ from the backup'
        ad.require(before is not None and (stat.S_ISDIR(before.st_mode) if is_dir else
                   stat.S_ISREG(before.st_mode) and before.st_nlink == 1),
                   'APP_RESTORE_CONFLICT', message)
        fd = os.open(name, DIR if is_dir else READ, dir_fd=parent)
        try:
            self.pin.check_fd(fd)
            ad.require(ad.identity(os.fstat(fd)) == ad.identity(before)
                       and (before.st_uid, before.st_gid) == (self.uid, self.gid)
                       and stat.S_IMODE(before.st_mode) == permission(entry)
                       and before.st_mtime_ns == entry['mtime'] * 10**9,
                       'APP_RESTORE_CONFLICT', message)
            ad.same_policy(self.pin.context, self.directory, fd)
            if self.label is not None:
                ad.require(os.getxattr(fd, 'security.selinux') == self.label,
                           'APP_RESTORE_CONFLICT', message)
            if is_dir:
                ad.require(set(os.listdir(fd)) == self.children[parts], 'APP_RESTORE_CONFLICT', message)
                for child in self.children[parts]:
                    self.check_existing(fd, (*parts, child))
            else:
                ad.require(before.st_size == entry['size'], 'APP_RESTORE_CONFLICT', message)
                with os.fdopen(os.dup(fd), 'rb') as file:
                    digest = hashlib.file_digest(file, 'sha256').hexdigest()
                ad.require(digest == entry['sha256'], 'APP_RESTORE_CONFLICT', message)
            current = named(parent, name)
            ad.require(current is not None and ad.identity(current) == ad.identity(before)
                       and ad.identity(os.fstat(fd)) == ad.identity(before), 'TARGET_CHANGED', message)
        finally:
            os.close(fd)

    @contextmanager
    def staging(self):
        if not self.pending:
            yield
            return
        name = STAGING_PREFIX + os.urandom(12).hex()
        os.mkdir(name, 0o700, dir_fd=self.directory)
        created = inode(os.stat(name, dir_fd=self.directory, follow_symlinks=False))
        try:
            self.stage = os.open(name, DIR, dir_fd=self.directory)
            self.pin.check_fd(self.stage)
            ad.require(inode(os.fstat(self.stage)) == created, 'TARGET_CHANGED', 'The staging directory changed')
            ad.same_policy(self.pin.context, self.directory, self.stage)
            yield
        finally:
            try:
                current = named(self.directory, name)
                if current is not None and inode(current) == created:
                    shutil.rmtree(name, dir_fd=self.directory)
                    os.fsync(self.directory)
            finally:
                if self.stage is not None:
                    os.close(self.stage)

    def set_metadata(self, fd, record):
        self.pin.check_fd(fd)
        ad.same_policy(self.pin.context, self.directory, fd)
        opened = os.fstat(fd)
        if (opened.st_uid, opened.st_gid) != (self.uid, self.gid):
            os.fchown(fd, self.uid, self.gid)
        if self.label is not None:
            os.setxattr(fd, 'security.selinux', self.label)
        os.fchmod(fd, permission(record))
        stamp = record['mtime'] * 10**9
        os.utime(fd, ns=(stamp, stamp))
        os.fsync(fd)

    def write(self, parts, item, reader, progress):
        record = self.records[parts]
        with fs.tree_directory(self.pin, self.stage, '/'.join(parts[:-1])) as parent:
            name = parts[-1]
            if item.isdir():
                os.mkdir(name, 0o700, dir_fd=parent)
                self.directories.append(parts)
                return
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
            try:
                while reader.count < item.size:
                    block = ad.exact(reader, min(item.size - reader.count, ad.CHUNK))
                    pa.write_all(fd, block)
                    progress(reader.count)
                self.set_metadata(fd, record)
            finally:
                os.close(fd)

    def finish(self):
        for parts in reversed(self.directories):
            with fs.tree_directory(self.pin, self.stage, '/'.join(parts)) as fd:
                self.set_metadata(fd, self.records[parts])
        if self.stage is not None:
            os.fsync(self.stage)
        self.recheck()
        for name in self.children[()]:
            if name in self.pending:
                ad.require(named(self.directory, name) is None, 'APP_RESTORE_CONFLICT',
                           'Android application data appeared before publication')
            else:
                self.check_existing(self.directory, (name,))


def payload_for(manifest, package):
    groups = defaultdict(dict)
    for path, entry in manifest['files'].items():
        parts = tuple(path.split('/'))
        if len(parts) > 3 and parts[:2] == ('apps', package) and parts[2] != 'apk':
            ad.require(not parts[3].startswith(STAGING_PREFIX), 'ARCHIVE_UNSAFE',
                       'The application archive contains a reserved restore path')
            groups[parts[2]][parts[3:]] = entry
    ad.require(groups, 'APP_RESTORE_EMPTY', 'This application has no backed-up private files')
    return groups


def restore(context, volume, token, path, expected_sha, target_token, password, package, confirmed,
            progress=lambda *unused: None):
    import android_migration as migration

    context.confirm(confirmed)
    migration.checked_packages([package])
    fs.require_hash(expected_sha, 'expected-sha256')
    fs.require_hash(target_token, 'expected-target-token')
    ad.admitted(context.volume('userdata', target_token), True)
    with ExitStack() as stack:
        fd, _, _, recheck = stack.enter_context(ad.portable_open(context, volume, token, path, migration.SUFFIX))
        manifest = migration.verify_fd(fd, password, expected_sha)['manifest']
        ad.require(manifest['schema'] != ad.MODEL_SCHEMA, 'INVALID_PROFILE_OPTIONS',
                   'Choose a portable app-data archive')
        item = next((row for row in manifest['items'] if row.get('kind') == 'app-data' and row['package'] == package), None)
        ad.require(item is not None, 'PACKAGE_NOT_BACKED_UP', 'The selected application is absent from this backup')
        target = stack.enter_context(fs.PinnedVolume(context, 'userdata', target_token, writing=True))
        registry = migration.package_snapshot(target, [package])
        installed = registry['packages'].get(package)
        status = migration.app_identity_status(installed, item, registry['sdk'], manifest['source']['sdk'])
        ad.require(status == 'identity_matches', 'APP_RESTORE_PACKAGE_MISMATCH',
                   'The installed application is incompatible with this archive: ' + status)
        scopes = {}
        for key, records in payload_for(manifest, package).items():
            base = migration.ce_directory(target) if key == 'ce' else migration.SCOPES[key]
            relative = base + '/' + package
            try:
                directory = stack.enter_context(target.directory(relative))
            except FileNotFoundError:
                fs.fail('APP_RESTORE_TARGET_MISSING', 'Android must prepare the installed application data directories')
            scopes[key] = Scope(target, directory, relative, records, installed['uid'])
        total = sum(entry['size'] for scope in scopes.values() for parts, entry in scope.records.items()
                    if parts[0] in scope.pending)
        ad.capacity(target.fd, total)
        done, written, seen = 0, 0, set()
        for scope in scopes.values():
            stack.enter_context(scope.staging())

        def consume(parts, header, reader):
            nonlocal done, written
            selected = len(parts) > 3 and parts[:2] == ['apps', package] and parts[2] in scopes
            if selected:
                scope = scopes.get(parts[2])
                relative = tuple(parts[3:])
                expected = scope.records.get(relative) if scope is not None else None
                ad.require(expected is not None and migration.entry_record(header, expected['sha256']) == expected,
                           'SOURCE_CHANGED', 'Application archive metadata changed')
                if relative[0] in scope.pending:
                    scope.write(relative, header, reader, lambda n: progress(done + n, written))
                    done += header.size
                    written += 1
                seen.add((parts[2], relative))
            while reader.count < header.size:
                ad.exact(reader, min(header.size - reader.count, ad.CHUNK))
            if selected:
                digest = None if header.isdir() else reader.digest.hexdigest()
                ad.require(digest == expected['sha256'], 'SOURCE_CHANGED', 'Application archive payload changed')

        with crypt.source(fd, password) as plain, os.fdopen(os.dup(plain), 'rb') as stream:
            ad.portable_read_gzip(stream, consume)
        ad.require(seen == {(key, path) for key, scope in scopes.items() for path in scope.records},
                   'SOURCE_CHANGED', 'Application archive file list changed')
        for scope in scopes.values():
            scope.finish()
        recheck()
        target.recheck()
        ad.admitted(context.volume('userdata', target_token), True)
        ad.require(migration.package_snapshot(target, [package]) == registry,
                   'TARGET_CHANGED', 'The installed package registry changed during restore')
        published = []
        try:
            for scope in scopes.values():
                for name in sorted(scope.pending):
                    expected_inode = inode(os.stat(name, dir_fd=scope.stage, follow_symlinks=False))
                    fs.rename_noreplace(scope.stage, name, scope.directory, name)
                    published.append((scope, name, expected_inode))
                    os.fsync(scope.directory)
                    os.fsync(scope.stage)
        except BaseException:
            for scope, name, expected_inode in reversed(published):
                with suppress(OSError, fs.FilesystemError):
                    current = named(scope.directory, name)
                    if current is not None and inode(current) == expected_inode:
                        fs.rename_noreplace(scope.directory, name, scope.stage, name)
                        os.fsync(scope.directory)
                        os.fsync(scope.stage)
            raise
        return {'operation': 'restore-app', 'package': package, 'scope': sorted(scopes),
                'archive_sha256': expected_sha, 'entries_written': written, 'file_bytes': done,
                'installed_data_written': bool(published), 'verified': True}
