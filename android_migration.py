#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Portable, authenticated Android app-data and shared-file backup."""
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time
import xml.etree.ElementTree as ET

import android_data as ad
import android_app_restore as app_restore
import android_package_registry as registry
import android_preferences as preferences
import android_root_adb as root_adb
import android_first_boot as first_boot_restore
import android_personal as personal
import archive_crypt as ac
import file_types
import filesystem as fs
import sysinfo

SCHEMA = 'a22x.android-migration.v1'
SETTINGS_SCHEMA = 'a22x.android-migration.v2'
APK_SCHEMA = 'a22x.android-migration.v4'
# 2026-11-20: adb's settings and keys and Magisk's root rules (android_root_adb).
ROOT_ADB_SCHEMA = 'a22x.android-migration.v5'
PORTABLE_SCHEMAS = (SCHEMA, SETTINGS_SCHEMA, personal.SCHEMA, APK_SCHEMA, ROOT_ADB_SCHEMA)
STORE = ad.MIGRATION_STORE
MANIFEST = 'manifest.json'
SUFFIX = '.tar.gz.enc'
SCOPES = {'ce': 'user/0', 'de': 'user_de/0'}
EXCLUDED_APP_ROOT = frozenset(('cache', 'code_cache', 'lib'))
MAX_PACKAGES = 256
MAX_SOURCE_PACKAGES = 4096
MAX_APKS = 256
APK_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,199}\.apk\Z')
SKIP_REASONS = frozenset(('cache', 'links_or_special', 'excluded_paths'))
# Shared files chosen by their kind (file_types, 2026-11-20): the files of other kinds are counted here.
TYPED_SKIP_REASONS = SKIP_REASONS | {'other_types'}


def checked_packages(names):
    ad.require(len(names) <= MAX_PACKAGES and len(set(names)) == len(names) and
               all(registry.PACKAGE.fullmatch(name) and len(name) <= 200 for name in names),
               'INVALID_PACKAGE', 'Choose distinct Android application package names')
    return sorted(names)


def read_android_file(pin, directory, name):
    with pin.directory(directory) as parent:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            pin.check_fd(fd)
            st = os.fstat(fd)
            ad.require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= registry.MAX_BYTES,
                       'ANDROID_CONFIG_INVALID', 'The Android configuration file is empty or exceeds its size limit')
            with os.fdopen(os.dup(fd), 'rb') as file:
                data = ad.exact(file, st.st_size)
            ad.require(ad.identity(os.fstat(fd)) == ad.identity(st) and
                       ad.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == ad.identity(st),
                       'SOURCE_CHANGED', 'The Android configuration file changed')
        finally:
            os.close(fd)
    return data


def preference_snapshot(pin):
    result = {}
    for ns in preferences.RULES:
        data = read_android_file(pin, 'system/users/0', f'settings_{ns}.xml')
        try:
            result[ns] = preferences.read(data, ns)
        except (ValueError, ET.ParseError):
            fs.fail('SETTINGS_INVALID', 'Unsupported or damaged Android settings file')
    ad.require(preferences.valid_bundle(result), 'SETTINGS_EMPTY', 'No transferable Android settings found')
    return result


def package_snapshot(pin, names, *, include_code_path=False):
    data = read_android_file(pin, 'system', 'packages.xml')
    try:
        value = registry.parse(data, names, include_code_path=include_code_path)
    except (ValueError, ET.ParseError, UnicodeError):
        fs.fail('PACKAGE_REGISTRY_INVALID', 'The Android package registry could not establish a selected application identity')
    value['registry_sha256'] = hashlib.sha256(data).hexdigest()
    return value


def require_password(password):
    ad.require(isinstance(password, str) and len(password) >= 8 and len(password.encode('utf-8')) <= ac.PASSWORD_LIMIT,
               'BACKUP_PASSWORD_REQUIRED', 'Use a backup passphrase of at least eight characters')


def entry_record(item, digest=None):
    return {'type': 'directory' if item.isdir() else 'file', 'mode': item.mode, 'mtime': item.mtime,
            'size': item.size, 'sha256': digest}


class Writer:
    def __init__(self, pin, tar, progress):
        self.pin, self.tar, self.progress = pin, tar, progress
        self.records = {}
        self.done = self.index_bytes = 0

    def record(self, item, payload=None):
        ad.portable_path(item.name)
        self.index_bytes += len(item.name.encode('utf-8')) + 220
        ad.require(item.name not in self.records and len(self.records) < ad.MAX_ENTRIES - 1 and
                   self.index_bytes <= ad.MAX_INDEX and item.size <= ad.MAX_LOGICAL - self.done,
                   'BACKUP_BOUNDS', 'The migration backup exceeds its bounded format')
        self.tar.addfile(item, payload)
        if payload is not None:
            ad.require(payload.count == item.size, 'SOURCE_CHANGED', 'The source file changed size')
        self.records[item.name] = entry_record(item, payload.digest.hexdigest() if payload else None)
        self.done += item.size

    def directory(self, path, source_stat=None):
        item = tarfile.TarInfo(path)
        item.type = tarfile.DIRTYPE
        if source_stat is None:
            item.mode = 0o700
        else:
            item.mode = stat.S_IMODE(source_stat.st_mode) & 0o777
            item.mtime = max(0, min(source_stat.st_mtime_ns // 10**9, 0xffffffff))
        self.record(item)

    def file(self, path, fd, info):
        item = tarfile.TarInfo(path)
        item.size = info.st_size
        item.mode = stat.S_IMODE(info.st_mode) & 0o777
        item.mtime = max(0, min(info.st_mtime_ns // 10**9, 0xffffffff))
        with os.fdopen(os.dup(fd), 'rb') as file:
            payload = ad.HashReader(file, lambda _: self.progress(self.done + payload.count, len(self.records)))
            self.record(item, payload)

    def apks(self, prefix, code_path):
        try:
            with self.pin.directory(code_path.removeprefix('/data/')) as directory:
                baseline = ad.identity(os.fstat(directory))
                names = sorted(name for name in os.listdir(directory) if name.endswith('.apk'))
                ad.require('base.apk' in names and len(names) <= MAX_APKS and all(APK_NAME.fullmatch(name) for name in names),
                           'APP_APKS_UNAVAILABLE', 'The installed package lacks a usable base APK or split set')
                self.directory(prefix)
                for name in names:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    ad.require(stat.S_ISREG(info.st_mode) and info.st_size > 0, 'APP_APKS_UNAVAILABLE',
                               'The installed application contains an invalid APK entry')
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
                    try:
                        self.pin.check_fd(fd)
                        stamp = ad.identity(info)
                        ad.require(ad.identity(os.fstat(fd)) == stamp, 'SOURCE_CHANGED', 'An installed APK was replaced')
                        self.file(prefix + '/' + name, fd, info)
                        ad.require(ad.identity(os.fstat(fd)) == stamp and
                                   ad.identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == stamp,
                                   'SOURCE_CHANGED', 'An installed APK changed during backup')
                    finally:
                        os.close(fd)
                ad.require(ad.identity(os.fstat(directory)) == baseline,
                           'SOURCE_CHANGED', 'The installed package directory changed during backup')
        except FileNotFoundError:
            fs.fail('APP_APKS_UNAVAILABLE', 'The installed application code directory or APK disappeared')
        return names

    def walk(self, directory, prefix, uid=None, relative=(), kinds=None):
        self.pin.check_fd(directory)
        baseline = ad.identity(os.fstat(directory))
        skipped = dict.fromkeys(SKIP_REASONS if kinds is None else TYPED_SKIP_REASONS, 0)
        for name in sorted(os.listdir(directory)):
            parts = (*relative, name)
            path = prefix + '/' + name
            ad.portable_path(path)
            if uid is None and ad.portable_excluded(parts):
                skipped['excluded_paths'] += 1
                continue
            if uid is not None and len(parts) == 1 and name in EXCLUDED_APP_ROOT:
                skipped['cache'] += 1
                continue
            if uid is not None and len(parts) == 1 and name.startswith(app_restore.STAGING_PREFIX):
                skipped['excluded_paths'] += 1
                continue
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            is_dir = stat.S_ISDIR(before.st_mode)
            if not is_dir and not stat.S_ISREG(before.st_mode):
                skipped['links_or_special'] += 1
                continue
            if kinds is not None and not is_dir and file_types.kind_of(name) not in kinds:
                skipped['other_types'] += 1
                continue
            ad.require(uid is None or before.st_uid == uid, 'PACKAGE_DATA_OWNER_MISMATCH',
                       'Selected application data contains an entry owned by a different Android UID')
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            if is_dir:
                flags |= os.O_DIRECTORY
            fd = os.open(name, flags, dir_fd=directory)
            try:
                self.pin.check_fd(fd)
                stamp = ad.identity(before)
                ad.require(ad.identity(os.fstat(fd)) == stamp, 'SOURCE_CHANGED', 'A source entry changed')
                if is_dir:
                    self.directory(path, before)
                    for key, count in self.walk(fd, path, uid, parts, kinds).items():
                        skipped[key] += count
                else:
                    self.file(path, fd, before)
                ad.require(ad.identity(os.fstat(fd)) == stamp and
                           ad.identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == stamp,
                           'SOURCE_CHANGED', 'A source entry changed during backup')
            finally:
                os.close(fd)
        ad.require(ad.identity(os.fstat(directory)) == baseline, 'SOURCE_CHANGED', 'A source folder changed during backup')
        return skipped


def ce_directory(pin):
    # Android installd prefers the real /data/data directory for user 0.
    try:
        if stat.S_ISDIR(os.stat('data', dir_fd=pin.fd, follow_symlinks=False).st_mode):
            return 'data'
    except FileNotFoundError:
        pass
    return SCOPES['ce']


def list_source_apps(context, token):
    fs.require_hash(token, 'expected-volume-token')
    ad.admitted(context.volume('userdata', token))
    with fs.PinnedVolume(context, 'userdata', token) as source, contextlib.ExitStack() as stack:
        snapshot = package_snapshot(source, None)
        roots = []
        for name in (ce_directory(source), SCOPES['de']):
            try:
                roots.append(stack.enter_context(source.directory(name)))
            except FileNotFoundError:
                continue
        packages = []
        for name, package in sorted(snapshot['packages'].items()):
            directories = []
            for root in roots:
                try:
                    directories.append(os.stat(name, dir_fd=root, follow_symlinks=False))
                except FileNotFoundError:
                    continue
            if directories and all(stat.S_ISDIR(info.st_mode) and info.st_uid == package['uid'] for info in directories):
                packages.append(name)
        ad.require(len(packages) <= MAX_SOURCE_PACKAGES, 'APP_LIST_TOO_LARGE', 'The installed application list exceeds the recovery limit')
        source.recheck()
    return {'operation': 'list-apps', 'volume_token': token, 'registry_sha256': snapshot['registry_sha256'],
            'packages': packages}


def write(pin, out, source, include_shared, progress, settings=None, include_personal=False, include_apks=False,
          include_root_adb=False, shared_kinds=None):
    with os.fdopen(os.dup(out), 'wb') as file, gzip.GzipFile(fileobj=file, mode='wb', compresslevel=3, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            writer = Writer(pin, tar, progress)
            items = []
            ce = ce_directory(pin) if source['packages'] else None
            if source['packages']:
                writer.directory('apps')
            for name, identity in source['packages'].items():
                root = 'apps/' + name
                writer.directory(root)
                scopes = {}
                for scope, directory in SCOPES.items():
                    prefix = root + '/' + scope
                    try:
                        with pin.directory(ce if scope == 'ce' else directory) as user:
                            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=user)
                            try:
                                pin.check_fd(fd)
                                before = os.fstat(fd)
                                ad.require(before.st_uid == identity['uid'], 'PACKAGE_DATA_OWNER_MISMATCH',
                                           'The selected package does not own its Android data directory')
                                if scope == 'ce':
                                    ad.same_policy(pin.context, user, fd)
                                writer.directory(prefix, before)
                                scopes[scope] = writer.walk(fd, prefix, identity['uid'])
                                ad.require(ad.identity(os.stat(name, dir_fd=user, follow_symlinks=False)) == ad.identity(before),
                                           'SOURCE_CHANGED', 'The source application directory changed')
                            finally:
                                os.close(fd)
                    except FileNotFoundError:
                        # Only a missing root is optional. A disappearing payload invalidates the backup.
                        if prefix in writer.records:
                            raise
                ad.require(scopes, 'PACKAGE_DATA_MISSING', 'The selected application has no local data directory')
                item = {'kind': 'app-data', **{k: v for k, v in identity.items() if k != 'code_path'},
                        'scopes': scopes, 'keystore_exported': False}
                if include_apks:
                    item['apks'] = writer.apks(root + '/apk', identity['code_path'])
                items.append(item)
            if include_personal:
                items.append(personal.capture(pin, ce or ce_directory(pin), writer))
            if include_shared:
                with pin.directory('media/0') as media:
                    writer.directory('shared')
                    skipped = writer.walk(media, 'shared', kinds=shared_kinds)
                shared_item = {'kind': 'shared-files', 'skipped': skipped}
                if shared_kinds is not None:
                    shared_item['types'] = list(shared_kinds)
                items.append(shared_item)
            carried_root_adb = root_adb.capture(pin, writer, read_android_file) if include_root_adb else None
            if carried_root_adb is not None:
                items.append(carried_root_adb)
            manifest = {'schema': SCHEMA, 'android_user': 0, 'source': {key: source[key] for key in ('sdk', 'fingerprint')},
                        'items': items, 'files': writer.records}
            if settings is not None:
                manifest.update(schema=SETTINGS_SCHEMA, preferences=settings)
            if include_personal:
                manifest['schema'] = personal.SCHEMA
            if include_apks:
                manifest['schema'] = APK_SCHEMA
            if carried_root_adb is not None:
                manifest['schema'] = ROOT_ADB_SCHEMA
            data = ad.encode(manifest)
            ad.require(len(data) <= ad.MAX_INDEX and len(data) <= ad.MAX_LOGICAL - writer.done,
                       'BACKUP_BOUNDS', 'The backup manifest exceeds the format limits')
            item = tarfile.TarInfo(MANIFEST)
            item.mode, item.size = 0o600, len(data)
            tar.addfile(item, io.BytesIO(data))
            return manifest


def unique_mapping(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError('Repeated manifest field')
    return value


def valid_skips(skipped, typed=False):
    return (isinstance(skipped, dict) and skipped.keys() == (TYPED_SKIP_REASONS if typed else SKIP_REASONS)
            and all(type(count) is int and count >= 0 for count in skipped.values()))


def validate_manifest(manifest, records):
    ad.require(isinstance(manifest, dict), 'MIGRATION_MANIFEST_INVALID', 'Expected an Android migration manifest')
    schema, items = manifest.get('schema'), manifest.get('items')
    ad.require(schema in PORTABLE_SCHEMAS and isinstance(items, list), 'MIGRATION_MANIFEST_INVALID',
               'Unsupported Android migration schema or data inventory')
    root = schema == ROOT_ADB_SCHEMA
    apps = [item for item in items if isinstance(item, dict) and item.get('kind') == 'app-data']
    with_apks = schema == APK_SCHEMA or (root and any('apks' in item for item in apps))
    with_personal = schema == personal.SCHEMA or ((schema == APK_SCHEMA or root) and any(isinstance(item, dict) and item.get('kind') == 'personal-data' for item in items))
    settings = schema == SETTINGS_SCHEMA or (schema in (personal.SCHEMA, APK_SCHEMA, ROOT_ADB_SCHEMA) and 'preferences' in manifest)
    ad.require((preferences.valid_bundle(manifest.get('preferences')) if settings else 'preferences' not in manifest) and
               type(manifest.get('android_user')) is int and manifest['android_user'] == 0 and isinstance(manifest.get('source'), dict) and
               int(not settings) <= len(manifest['items']) <= MAX_PACKAGES + 1 + int(with_personal) + int(root) and ad.encode(manifest.get('files')) == ad.encode(records),
               'MIGRATION_MANIFEST_MISMATCH', 'The manifest does not match the authenticated archive')
    source = manifest['source']
    ad.require(type(source.get('sdk')) is int and 21 <= source['sdk'] <= 10000 and
               isinstance(source.get('fingerprint'), str) and 0 < len(source['fingerprint']) <= 1024,
               'MIGRATION_MANIFEST_INVALID', 'Android source version is invalid')
    roots, package_names, apk_paths, has_shared = set(), set(), set(), False
    for item in manifest['items']:
        ad.require(isinstance(item, dict), 'MIGRATION_MANIFEST_INVALID', 'Invalid data type record')
        if item.get('kind') == 'personal-data':
            ad.require(with_personal and 'personal' not in roots and ad.encode(item) == ad.encode(personal.validate(records)),
                       'MIGRATION_MANIFEST_INVALID', 'Personal data inventory differs from the archive')
            roots.add('personal')
            continue
        if item.get('kind') == 'root-adb':
            ad.require(root and root_adb.ROOT not in roots and root_adb.valid_item(item, records),
                       'MIGRATION_MANIFEST_INVALID', 'The adb and root entry is invalid or repeated')
            roots.add(root_adb.ROOT)
            continue
        if item.get('kind') == 'shared-files':
            typed = 'types' in item
            ad.require(not has_shared and item.keys() == ({'kind', 'skipped', 'types'} if typed else {'kind', 'skipped'})
                       and (not typed or file_types.valid(item['types'])) and valid_skips(item.get('skipped'), typed),
                       'MIGRATION_MANIFEST_INVALID', 'The shared storage entry is invalid or repeated')
            roots.add('shared')
            has_shared = True
            continue
        package, signers, scopes = item.get('package'), item.get('signers_sha256'), item.get('scopes')
        ad.require(item.get('kind') == 'app-data' and isinstance(package, str) and registry.PACKAGE.fullmatch(package) and
                   len(package) <= 200 and package not in package_names and isinstance(signers, list) and 1 <= len(signers) <= 16 and
                   type(item.get('uid')) is int and 10000 <= item['uid'] <= 19999 and
                   type(item.get('version_code')) is int and 0 <= item['version_code'] < 1 << 63 and
                   isinstance(scopes, dict) and scopes and scopes.keys() <= SCOPES.keys() and
                   all(valid_skips(skips) for skips in scopes.values()) and item.get('keystore_exported') is False,
                   'MIGRATION_MANIFEST_INVALID', 'Invalid application data identity or storage scope')
        for signer in signers:
            fs.require_hash(signer, 'signers_sha256')
        ad.require(signers == sorted(set(signers)), 'MIGRATION_MANIFEST_INVALID', 'Application signer list must be unique')
        package_names.add(package)
        roots.update('apps/' + package + '/' + scope for scope in scopes)
        if with_apks:
            names = item.get('apks')
            ad.require(isinstance(names, list) and 1 <= len(names) <= MAX_APKS and 'base.apk' in names and
                       all(isinstance(name, str) and APK_NAME.fullmatch(name) for name in names) and names == sorted(set(names)),
                       'MIGRATION_MANIFEST_INVALID', 'Invalid base APK or split inventory')
            prefix = 'apps/' + package + '/apk'
            roots.add(prefix)
            apk_paths.update(prefix + '/' + name for name in names)
        else:
            ad.require('apks' not in item, 'MIGRATION_MANIFEST_INVALID', 'APK data requires the APK migration schema')
    ad.require(schema != APK_SCHEMA or package_names, 'MIGRATION_MANIFEST_INVALID', 'The APK archive has no applications')
    ad.require((root_adb.ROOT in roots) == root, 'MIGRATION_MANIFEST_INVALID', 'Missing adb and root entry')
    ad.require(all(records.get(path, {}).get('type') == 'file' and records[path]['size'] > 0 for path in apk_paths),
               'MIGRATION_MANIFEST_MISMATCH', 'A declared APK is missing or invalid')
    ad.require(('personal' in roots) == with_personal, 'MIGRATION_MANIFEST_INVALID', 'Missing personal data inventory')
    parents = {'apps', *('apps/' + name for name in package_names)} if package_names else set()
    ad.require(all(records.get(root, {}).get('type') == 'directory' for root in roots | parents),
               'MIGRATION_MANIFEST_MISMATCH', 'A declared data directory is missing')
    for path in records:
        parts = path.split('/')
        if parts[0] == 'apps':
            top = '/'.join(parts[:3])
            if len(parts) > 3 and parts[2] == 'apk':
                allowed = path in apk_paths
            else:
                allowed = len(parts) < 4 or parts[3] not in EXCLUDED_APP_ROOT
        else:
            top = parts[0]
            allowed = not ad.portable_excluded(parts[1:]) if len(parts) > 1 else True
        ad.require(allowed and (path in parents or top in roots), 'MIGRATION_MANIFEST_MISMATCH',
                   'A member is outside a declared data directory or inside an excluded path')


def hardware(context):
    phone = sysinfo.Phone(context.root if ad.fixture(context) else '/')
    return {'model': phone.model(), 'codename': phone.codename()}


def check_model_manifest(manifest):
    src = manifest.get('source')
    ad.require(isinstance(src, dict) and src.get('model') in sysinfo.NAMES and src.get('codename') == 'a22x'
               and type(src.get('sdk')) is int and 21 <= src['sdk'] <= 10000
               and isinstance(src.get('fingerprint'), str) and 0 < len(src['fingerprint']) <= 1024
               and src.get('android_user_id') == 0,
               'MODEL_SOURCE_INVALID', 'The backup is missing its Android model or build identity')


def verify_fd(fd, password, expected_sha=None):
    require_password(password)
    before = os.fstat(fd)
    ad.require(stat.S_ISREG(before.st_mode) and ac.is_encrypted(fd), 'NOT_A_MIGRATION_ARCHIVE',
               'Choose an authenticated Android migration archive')
    digest = ad.file_sha(fd)
    if expected_sha is not None:
        fs.require_hash(expected_sha, 'expected-sha256')
        ad.require(digest == expected_sha, 'ARCHIVE_SHA_MISMATCH', 'The archive differs from the expected SHA-256')
    records, manifest = {}, None

    def consume(parts, item, reader):
        nonlocal manifest
        ad.require(manifest is None and item.uid == item.gid == 0 and 0 <= item.mode <= 0o777,
                   'MIGRATION_MANIFEST_INVALID', 'Unexpected entry after the manifest or imported ownership metadata')
        if parts == [MANIFEST]:
            ad.require(item.isfile() and 0 < item.size <= ad.MAX_INDEX, 'MIGRATION_MANIFEST_INVALID', 'Invalid backup manifest')
            manifest = json.loads(ad.exact(reader, item.size), object_pairs_hook=unique_mapping)
        else:
            while reader.count < item.size:
                ad.exact(reader, min(ad.CHUNK, item.size - reader.count))
            records['/'.join(parts)] = entry_record(item, None if item.isdir() else reader.digest.hexdigest())

    key = ac.open_key(fd, password)
    try:
        ac.verify(fd, key)
        signature = key.crypt(os.pread(fd, 4, 16), 0)
    finally:
        key.close()
    with ac.source(fd, password) as plain, os.fdopen(os.dup(plain), 'rb') as file:
        if signature == bytes.fromhex('28b52ffd'):
            manifest = ad.verify_stream(plain, ad.MODEL_SCHEMA)
            check_model_manifest(manifest)
        else:
            ad.portable_read_gzip(file, consume)
            validate_manifest(manifest, records)
    ad.require(ad.identity(os.fstat(fd)) == ad.identity(before), 'SOURCE_CHANGED', 'The migration archive changed during verification')
    return {'archive_sha256': digest, 'archive_bytes': before.st_size, 'verified': True, 'manifest': manifest}


def export_tar(fd, password, path, before):
    """Publish a verified plaintext tar.gz on the offline computer for selective recovery."""
    path = fs.absolute_no_symlinks(path, missing=True)
    parent = os.open(fs.absolute_no_symlinks(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        partial = '.android-migration-' + os.urandom(8).hex() + '.partial'
        out = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            with ac.source(fd, password) as plain:
                while data := os.read(plain, ad.CHUNK):
                    ac.write_all(out, data)
            ad.require(ad.identity(os.fstat(fd)) == ad.identity(before) and
                       ad.identity(os.fstat(out)) == ad.identity(os.stat(partial, dir_fd=parent, follow_symlinks=False)),
                       'SOURCE_CHANGED', 'The migration archive or export file changed')
            os.fsync(out)
            fs.rename_noreplace(parent, partial, parent, path.name)
            os.fsync(parent)
        finally:
            owned = os.fstat(out)
            os.close(out)
            ad.owned_unlink(parent, partial, (owned.st_dev, owned.st_ino))
    finally:
        os.close(parent)
    return str(path)


def create(context, token, packages, include_shared, volume, target_token, password, confirmed, progress=lambda *unused: None,
           *, profile='portable', include_settings=False, include_personal=False, expected_registry=None, include_apks=False,
           include_root_adb=False, shared_kinds=None):
    context.confirm(confirmed)
    ad.require(shared_kinds is None or (include_shared and file_types.valid(list(shared_kinds))),
               'INVALID_FILE_TYPES', 'Choose kinds of files for the shared files')
    packages = checked_packages(packages)
    require_password(password)
    full = profile == 'same-model'
    ad.require(profile in ('portable', 'same-model') and not (full and (packages or include_shared or include_settings or include_personal or include_apks or include_root_adb)),
               'INVALID_PROFILE_OPTIONS', 'The full Data profile includes every supported userdata entry')
    ad.require(not include_apks or packages, 'NOTHING_SELECTED', 'Select applications to include their APKs')
    ad.require(full or packages or include_shared or include_settings or include_personal or include_root_adb, 'NOTHING_SELECTED', 'Select files, settings or an application')
    fs.require_hash(token, 'expected-volume-token')
    fs.require_hash(target_token, 'expected-destination-token')
    ad.portable_volume(volume)
    ad.admitted(context.volume('userdata', token), writing=volume == 'userdata')
    base = '/media/0' if volume == 'userdata' else ''
    with fs.PinnedVolume(context, 'userdata', token) as source, \
            fs.PinnedVolume(context, volume, target_token, writing=True) as target, target.directory(base) as directory:
        snapshot = package_snapshot(source, packages, include_code_path=include_apks)
        if expected_registry is not None:
            fs.require_hash(expected_registry, 'expected-registry-sha256')
            ad.require(snapshot['registry_sha256'] == expected_registry, 'PACKAGE_REGISTRY_CHANGED',
                       'The Android package registry changed. Review the application selection again.')
        settings = preference_snapshot(source) if include_settings else None
        ad.require(set(snapshot['packages']) == set(packages), 'PACKAGE_NOT_INSTALLED', 'A selected application is absent from the Android registry')
        with contextlib.suppress(FileExistsError):
            os.mkdir(STORE, 0o700, dir_fd=directory)
            os.fsync(directory)
        store = base + '/' + STORE
        with target.directory(store) as parent:
            if volume == 'userdata':
                ad.same_policy(context, directory, parent)
            ad.capacity(parent)
            prefix, suffix = ('android-model-data-', '.tar.zst.enc') if full else ('android-migration-', SUFFIX)
            final = prefix + time.strftime('%Y%m%d-%H%M%S', time.gmtime()) + '-' + os.urandom(8).hex() + suffix
            partial = '.' + final + '.partial'
            fd = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                target.check_fd(fd)
                if volume == 'userdata':
                    ad.same_policy(context, directory, fd)
                if full:
                    identity = {**ad.current_source(source), **hardware(context),
                                'sdk': snapshot['sdk'], 'fingerprint': snapshot['fingerprint']}
                    check_model_manifest({'source': identity})
                    entries, skipped = ad.scan(source, ad.MODEL_EXCLUDED)
                    ad.capacity(parent, ad.worst_case(entries) + 72)
                with ac.sink(fd, password) as sealed:
                    if full:
                        expected = ad.write_archive(source, sealed, entries, skipped, progress,
                                                    capacity_fd=parent, model_source=identity)
                    else:
                        expected = write(source, sealed, snapshot, include_shared, progress, settings, include_personal, include_apks,
                                         include_root_adb, shared_kinds=tuple(shared_kinds) if shared_kinds else None)
                os.fsync(fd)
                ad.capacity(parent)
                checked = verify_fd(fd, password)
                ad.require(checked['manifest'] == expected and snapshot == package_snapshot(source, packages, include_code_path=include_apks),
                           'SOURCE_CHANGED', 'The backup copy or the source package registry changed')
                if include_settings:
                    ad.require(settings == preference_snapshot(source), 'SOURCE_CHANGED', 'Android settings changed')
                source.recheck()
                target.recheck()
                ad.admitted(context.volume('userdata', token), writing=volume == 'userdata')
                ad.require(ad.identity(os.fstat(fd)) == ad.identity(os.stat(partial, dir_fd=parent, follow_symlinks=False)),
                           'PARTIAL_IDENTITY_CHANGED', 'The verified partial was replaced')
                fs.rename_noreplace(parent, partial, parent, final)
                os.fsync(parent)
            except BaseException:
                owned = os.fstat(fd)
                ad.owned_unlink(parent, partial, (owned.st_dev, owned.st_ino))
                os.fsync(parent)
                raise
            finally:
                os.close(fd)
    return {'volume': volume, 'path': store + '/' + final, **checked}


@contextlib.contextmanager
def verified_shared(context, volume, token, path, password, expected_sha=None):
    with ad.portable_open(context, volume, token, path, SUFFIX) as (fd, size, clean, recheck):
        checked = verify_fd(fd, password, expected_sha)
        manifest = checked['manifest']
        ad.require(manifest['schema'] in PORTABLE_SCHEMAS
                   and any(item['kind'] == 'shared-files' for item in manifest['items']),
                   'SHARED_FILES_ABSENT', 'This archive contains no shared-storage backup')
        shared = {name: info for name, info in manifest['files'].items() if name.startswith('shared/')}
        digest = checked['archive_sha256']
        total = sum(info['size'] for info in shared.values())
        result = {'schema': manifest['schema'], 'verified': True, 'archive_sha256': digest, 'volume': volume,
                  'path': clean, 'entries': len(shared), 'file_bytes': total, 'scope': ad.PORTABLE_SCOPE,
                  'archive': {'bytes': size, 'volume': volume, 'path': clean, 'sha256': digest},
                  'counts': {'files': sum(info['type'] == 'file' for info in shared.values()), 'file_bytes': total}}
        recheck()
        yield fd, shared, result, recheck


def restore_shared(context, volume, token, path, expected_sha, target_token, password, confirmed, progress=lambda *unused: None):
    context.confirm(confirmed)
    fs.require_hash(expected_sha, 'expected-sha256')
    fs.require_hash(target_token, 'expected-target-token')
    ad.admitted(context.volume('userdata', target_token), True)
    with verified_shared(context, volume, token, path, password, expected_sha) as (fd, shared, result, recheck):
        def extract(write_entry):
            seen = set()

            def consume(parts, item, reader):
                path = '/'.join(parts)
                if parts[0] == 'shared' and len(parts) > 1:
                    expected = shared.get(path)
                    ad.require(expected is not None and expected['size'] == item.size and
                               (expected['type'] == 'directory') == item.isdir(),
                               'SOURCE_CHANGED', 'Shared file metadata changed after verification')
                    write_entry(parts[1:], item, reader)
                    ad.require(entry_record(item, None if item.isdir() else reader.digest.hexdigest()) == expected,
                               'SOURCE_CHANGED', 'A restored file differs from its verified manifest entry')
                    seen.add(path)
                else:
                    while reader.count < item.size:
                        ad.exact(reader, min(item.size - reader.count, ad.CHUNK))

            with ac.source(fd, password) as plain, os.fdopen(os.dup(plain), 'rb') as source:
                ad.portable_read_gzip(source, consume)
            ad.require(seen == shared.keys(), 'SOURCE_CHANGED', 'The shared-storage file list changed')

        folder = ad.restore_media_folder(context, target_token, 'Restored-Migration-' + expected_sha[:24],
                                        result['file_bytes'], extract, recheck, progress)
    return {**result, 'operation': 'restore-shared', 'folder': folder}


def shared_kinds_arg(text):
    try:
        kinds = file_types.parse(text)
    except ValueError:
        fs.fail('INVALID_FILE_TYPES', 'Unknown kind of files', allowed=list(file_types.NAMES))
    return list(kinds) if kinds else None


def kernelsu_boot(context):
    return boot_root(context) == 'kernelsu'


def kept_magisk_apk(context):
    """The Magisk APK root.py kept on cache (the newest), as bytes."""
    volume = context.volume('cache')
    if not volume['mounted']:
        context.mount('cache', 'ro', True, volume['volume_token'])
    with fs.PinnedVolume(context, 'cache') as pin:
        try:
            with pin.directory('a22x-recovery/magisk') as folder:
                names = sorted(name for name in os.listdir(folder) if re.fullmatch(r'Magisk-[A-Za-z0-9._+-]{1,24}\.apk', name))
                ad.require(names, 'MAGISK_APK_ABSENT', 'Install Magisk with this recovery first')
                fd = os.open(names[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=folder)
                try:
                    pin.check_fd(fd)
                    size = os.fstat(fd).st_size
                    ad.require(0 < size <= 64 << 20, 'MAGISK_APK_INVALID', 'The kept Magisk APK has an unexpected size')
                    return os.pread(fd, size, 0)
                finally:
                    os.close(fd)
        except FileNotFoundError:
            fs.fail('MAGISK_APK_ABSENT', 'Install Magisk with this recovery first')


def boot_root(context):
    """The root in the BOOT now in the phone: 'kernelsu', 'magisk', 'apatch' or '' (read through the
    installer's context, which knows the phone's partitions; CONTEXT here is the filesystem's)."""
    import bootimage
    import install
    refused = (OSError, ValueError, bootimage.ImageError, fs.FilesystemError, install._backend_storage().RecoveryError)
    try:
        boot = install.FixtureContext(context.root) if ad.fixture(context) else install.DeviceContext()
        return bootimage.inspect_boot(install.target_bytes(boot, boot.target('boot')))['root']
    except refused:
        return ''


def mount_fresh_userdata(context, token):
    """Freshly formatted userdata that is not mounted yet is mounted for writing here (read-only first,
    which shows that nothing in it is encrypted); its token after mounting."""
    volume = context.volume('userdata', token)
    if volume.get('mounted') or volume.get('fresh_android_data') is not True:
        return token
    context.mount('userdata', 'ro', False, token)
    current = context.volume('userdata')
    ad.require(current.get('fscrypt_unused') is True and current.get('write_supported') is True, 'FRESH_DATA_REQUIRED',
               'Format data for Android and mount it for writing first')
    context.mount('userdata', 'rw', True, current['volume_token'])
    return context.volume('userdata')['volume_token']


def fresh_userdata(volume):
    """Freshly formatted userdata of a system that has not started: mounted for writing by this
    recovery, without Android's encryption."""
    ad.require(volume.get('mounted') is True and volume.get('fs_type') == 'f2fs' and volume.get('read_only') is False
               and volume.get('mount_owner') == 'filesystem', 'FRESH_DATA_REQUIRED',
               'Format data for Android and mount it for writing first')


def step(phase, part='', done=0, total=0):
    """A stage of a new system's first-start preparation, for the recovery's work page (2026-11-21,
    the owner: the stages show that the work has not stopped). Stderr, as the other helpers report."""
    print(json.dumps({'event': 'progress', 'operation': 'restore-root-adb', 'phase': phase, 'partition': part,
                      'bytes_done': done, 'bytes_total': total}, separators=(',', ':')), file=sys.stderr, flush=True)


def stage_first_boot(context, fd, password, manifest, target, apps, wifi, progress=lambda *unused: None, recovery_networks=()):
    """The archive's apps (APKs and data) and Wi-Fi networks staged for the new system's one-time
    script (android_first_boot), every member checked against its verified manifest entry. PROGRESS
    gets what is read (an app's package, else the archive's top folder) and its bytes so far."""
    total = sum(record.get('size') or 0 for record in manifest['files'].values())
    seen = {'done': 0, 'at': 0.0, 'part': None}
    with target.directory('adb/' + root_adb.CARRIED) as kept:
        stager = first_boot_restore.Stager(context, target, manifest, kept, apps=apps, wifi=wifi, contacts=wifi,
                                           recovery_networks=recovery_networks)

        def consume(parts, entry, reader):
            name = '/'.join(parts)
            part = parts[1] if parts[0] == 'apps' and len(parts) > 1 else parts[0]
            now = time.monotonic()
            if part != seen['part'] or now - seen['at'] >= 0.5:
                seen['part'], seen['at'] = part, now
                progress(part, seen['done'], total)
            seen['done'] += entry.size
            if stager.wants(parts):
                stager.take(parts, entry, lambda n: ad.exact(reader, min(n, entry.size - reader.count)))
            while reader.count < entry.size:
                ad.exact(reader, min(entry.size - reader.count, ad.CHUNK))
            record = manifest['files'].get(name)
            if record is not None and stager.wants(parts):
                ad.require(entry_record(entry, None if entry.isdir() else reader.digest.hexdigest()) == record,
                           'SOURCE_CHANGED', 'A staged entry differs from its verified manifest entry')

        with ac.source(fd, password) as plain, os.fdopen(os.dup(plain), 'rb') as source:
            ad.portable_read_gzip(source, consume)
        progress('', total, total)
        return stager.finish()


def recovery_networks(context):
    """The networks the recovery saved: [(SSID in hex, WPA key in hex or '')], as wifi.py keeps them."""
    import wifi
    if ad.fixture(context):
        try:
            found = wifi.networks_of(json.loads((context.root / 'wifi-saved.json').read_text()))
        except FileNotFoundError:
            found = []
    else:
        found = wifi.saved_known()
    ad.require(found is not None, 'WIFI_SAVED_UNAVAILABLE', "The recovery's saved networks cannot be read now")
    return [(n['ssid_hex'], n.get('psk', '')) for n in found]


def recovery_adb_keys(context):
    """The keys of the computers allowed to use this recovery's adb."""
    path = context.root / 'run/adb_keys' if ad.fixture(context) else Path(root_adb.RECOVERY_KEYS)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        fs.fail('RECOVERY_ADB_KEYS_ABSENT', 'No computer is allowed in this recovery yet')
    return [data]


def restore_root_adb(context, volume, token, path, expected_sha, target_token, password, confirmed,
                     first_boot=False, recovery_keys=False, stage_apps=False, stage_wifi=False, recovery_wifi=False):
    """adb's settings and keys and Magisk's root rules into the new system's writable data
    (android_root_adb): the keys at once, the settings by a one-time Magisk boot script. With
    FIRST_BOOT: a new system with KernelSU that has not started yet, in its fresh data (root for the
    adb shell in KernelSU's rules, the keys and settings by a one-time script). RECOVERY_KEYS also
    allows there the computers this recovery allows."""
    context.confirm(confirmed)
    fs.require_hash(expected_sha, 'expected-sha256')
    fs.require_hash(target_token, 'expected-target-token')
    if first_boot:
        step('first-boot-data')
        target_token = mount_fresh_userdata(context, target_token)
        fresh_userdata(context.volume('userdata', target_token))
        step('first-boot-root')
        root_kind = boot_root(context)
        ad.require(root_kind in ('kernelsu', 'magisk'), 'ROOT_REQUIRED',
                   'The BOOT in the phone has neither KernelSU nor Magisk: install the system and root first')
        magisk_apk = kept_magisk_apk(context) if root_kind == 'magisk' else None
    else:
        ad.require(not recovery_keys, 'INVALID_ARGUMENT', "The recovery's keys are carried only before a first start")
        ad.admitted(context.volume('userdata', target_token), True)
    with ad.portable_open(context, volume, token, path, SUFFIX) as (fd, size, clean, recheck):
        if first_boot:
            step('first-boot-verify')
        checked = verify_fd(fd, password, expected_sha)
        manifest = checked['manifest']
        items = [item for item in manifest['items'] if item.get('kind') == 'root-adb']
        ad.require(manifest['schema'] == ROOT_ADB_SCHEMA and len(items) == 1, 'ROOT_ADB_ABSENT',
                   'This archive carries no adb or root settings')
        item = items[0]
        wanted = {root_adb.ROOT + '/' + name: name for name, flag in root_adb.FLAGS.items() if item[flag]}
        carried = {}

        def consume(parts, entry, reader):
            name = '/'.join(parts)
            data = bytearray()
            while reader.count < entry.size:
                data += ad.exact(reader, min(entry.size - reader.count, ad.CHUNK))
            if name in wanted:
                ad.require(entry_record(entry, reader.digest.hexdigest()) == manifest['files'][name],
                           'SOURCE_CHANGED', 'A carried adb or Magisk file differs from its verified manifest entry')
                carried[wanted[name]] = bytes(data)

        if first_boot:
            step('first-boot-read')
        with ac.source(fd, password) as plain, os.fdopen(os.dup(plain), 'rb') as source:
            ad.portable_read_gzip(source, consume)
        ad.require(carried.keys() == set(wanted.values()), 'SOURCE_CHANGED', 'A carried adb or Magisk file is missing')
        recheck()
        if first_boot:
            step('first-boot-write')
            extra = recovery_adb_keys(context) if recovery_keys else []
            networks = recovery_networks(context) if recovery_wifi else []
            staging = stage_apps or stage_wifi or bool(networks)
            lines = first_boot_restore.script_lines() if staging else ()
            with fs.PinnedVolume(context, 'userdata', target_token, writing=True) as target:
                if root_kind == 'magisk':
                    written, key_count = root_adb.write_first_boot_magisk(context, target, carried, item['global'],
                                                                          manifest.get('preferences'), magisk_apk, extra, lines)
                else:
                    written, key_count = root_adb.write_first_boot(context, target, carried, item['global'],
                                                                   manifest.get('preferences'), extra, lines)
                if staging:
                    step('first-boot-stage')
                staged = stage_first_boot(context, fd, password, manifest, target, stage_apps, stage_wifi,
                                          lambda part, done, total: step('first-boot-stage', part, done, total),
                                          networks) if staging else None
            recheck()
            return {'operation': 'restore-root-adb', 'verified': True, 'archive_sha256': checked['archive_sha256'],
                    'volume': volume, 'path': clean, 'written': written, 'global': item['global'], 'adb_keys': key_count,
                    'shell_root': root_kind, 'staged': staged,
                    'applied_at_next_start': ('by /data/adb/service.d, run once by Magisk at the first start' if root_kind == 'magisk'
                                              else 'by /data/adb/ksud, run once by KernelSU at the first start')}
    with fs.PinnedVolume(context, 'userdata', target_token, writing=True) as target:
        written = root_adb.write_target(context, target, carried, item['global'], manifest.get('preferences'))
    return {'operation': 'restore-root-adb', 'verified': True, 'archive_sha256': checked['archive_sha256'],
            'volume': volume, 'path': clean, 'written': written, 'global': item['global'],
            'magisk_rules': 'magisk.db' in carried, 'adb_keys': 'adb_keys' in carried,
            'applied_at_next_start': 'by the Magisk boot script /data/adb/service.d/a22x-migration.sh'}


def app_identity_status(installed, item, sdk, source_sdk):
    if installed is None:
        return 'package_missing'
    if installed['signers_sha256'] != item['signers_sha256']:
        return 'signing_mismatch'
    if sdk < source_sdk:
        return 'older_android'
    if installed['version_code'] != item['version_code']:
        return 'app_version_mismatch'
    return 'identity_matches'


def review_target(context, token, manifest):
    fs.require_hash(token, 'expected-volume-token')
    ad.admitted(context.volume('userdata', token))
    if manifest['schema'] == ad.MODEL_SCHEMA:
        with fs.PinnedVolume(context, 'userdata', token) as target:
            snapshot = package_snapshot(target, [])
            target.recheck()
        device = hardware(context)
        src = manifest['source']
        return {'hardware_matches': all(device[key] and device[key] == src[key] for key in device),
                'build_matches': snapshot['fingerprint'] == src['fingerprint'] and snapshot['sdk'] == src['sdk'],
                'installed_data_written': False, 'restore_supported': False}
    app_items = [item for item in manifest['items'] if item['kind'] == 'app-data']
    with fs.PinnedVolume(context, 'userdata', token) as target:
        snapshot = package_snapshot(target, [item['package'] for item in app_items])
        target.recheck()
    decisions = []
    for item in app_items:
        package = snapshot['packages'].get(item['package'])
        status = app_identity_status(package, item, snapshot['sdk'], manifest['source']['sdk'])
        decisions.append({'package': item['package'], 'status': status})
    return {'target_sdk': snapshot['sdk'], 'applications': decisions, 'installed_data_written': False}


def inspect_apps(context, volume, token, path, target_token, password):
    with ad.portable_open(context, volume, token, path, SUFFIX) as (fd, _, clean_path, recheck):
        checked = verify_fd(fd, password)
        manifest = checked['manifest']
        ad.require(manifest['schema'] != ad.MODEL_SCHEMA, 'INVALID_PROFILE_OPTIONS',
                   'Choose a portable app-data archive')
        review = review_target(context, target_token, manifest)
        with_payload = {parts[1] for name in manifest['files']
                        if (parts := name.split('/', 3))[0] == 'apps' and len(parts) == 4 and parts[2] in SCOPES}
        with_apks = {item['package'] for item in manifest['items'] if item.get('apks')}
        for app in review['applications']:
            app['apk_saved'] = app['package'] in with_apks
            if app['package'] not in with_payload:
                app['status'] = 'no_private_data'
        recheck()
        return {'operation': 'inspect-apps', 'verified': True, 'archive_sha256': checked['archive_sha256'],
                'volume': volume, 'path': clean_path, 'target_token': target_token,
                'applications': review['applications']}


def main(argv=None):
    parser = fs.Parser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--device', action='store_true')
    mode.add_argument('--fixture')
    mode.add_argument('--offline', action='store_true')
    parser.add_argument('--password-file')
    commands = parser.add_subparsers(dest='operation', required=True, parser_class=fs.Parser)
    backup = commands.add_parser('create')
    backup.add_argument('--expected-volume-token', required=True)
    backup.add_argument('--destination-volume', required=True)
    backup.add_argument('--expected-destination-token', required=True)
    backup.add_argument('--profile', choices=('portable', 'same-model'), default='portable')
    backup.add_argument('--package', action='append', default=[])
    backup.add_argument('--include-personal', action='store_true')
    backup.add_argument('--include-settings', action='store_true')
    backup.add_argument('--include-shared', action='store_true')
    backup.add_argument('--shared-types', help='Only these kinds of shared files: ' + ','.join(file_types.NAMES))
    backup.add_argument('--include-apks', action='store_true')
    backup.add_argument('--include-root-adb', action='store_true')
    backup.add_argument('--confirm', action='store_true')
    backup.add_argument('--summary', action='store_true')
    backup.add_argument('--expected-registry-sha256')
    list_apps = commands.add_parser('list-apps')
    list_apps.add_argument('--expected-volume-token', required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('--path', required=True)
    verify.add_argument('--volume')
    verify.add_argument('--expected-volume-token')
    verify.add_argument('--expected-sha256')
    verify.add_argument('--review-for-data-token')
    verify.add_argument('--manifest', action='store_true')
    verify.add_argument('--export-tar', help='Offline only, create a new plaintext compressed tar after verification')
    restore = commands.add_parser('restore-shared')
    restore_app = commands.add_parser('restore-app')
    restore_root = commands.add_parser('restore-root-adb')
    inspect = commands.add_parser('inspect-shared')
    inspect_app = commands.add_parser('inspect-apps')
    for command in (inspect, inspect_app, restore, restore_app, restore_root):
        command.add_argument('--path', required=True)
        command.add_argument('--volume', required=True)
        command.add_argument('--expected-volume-token', required=True)
    for command in (inspect_app, restore, restore_app, restore_root):
        command.add_argument('--expected-target-token', required=True)
    for command in (restore, restore_app, restore_root):
        command.add_argument('--expected-sha256', required=True)
        command.add_argument('--confirm', action='store_true')
    restore_app.add_argument('--package', required=True)
    restore_root.add_argument('--first-boot-kernelsu', action='store_true')
    restore_root.add_argument('--with-recovery-adb-keys', action='store_true')
    restore_root.add_argument('--stage-apps', action='store_true', help='Before a first start: the archive apps, put back by the new system')
    restore_root.add_argument('--stage-wifi', action='store_true', help='Before a first start: the archive Wi-Fi networks')
    restore_root.add_argument('--with-recovery-wifi', action='store_true', help="Before a first start: the recovery's saved networks too")
    try:
        args = parser.parse_args(argv)
        password = None
        if args.operation != 'list-apps':
            ad.require(args.password_file, 'PASSWORD_REQUIRED', 'A backup password file is required')
            password = ac.read_password(args.password_file)
        if args.offline:
            ad.require(args.operation == 'verify' and not any((args.volume, args.expected_volume_token, args.review_for_data_token)),
                       'INVALID_OPERATION', 'Offline mode verifies an archive on a computer')
            fd = fs.open_regular(fs.absolute_no_symlinks(args.path))
            try:
                before = os.fstat(fd)
                result = verify_fd(fd, password, args.expected_sha256)
                if args.export_tar:
                    ad.require(ad.identity(os.fstat(fd)) == ad.identity(before),
                               'SOURCE_CHANGED', 'The migration archive changed before export')
                    result['exported_tar'] = export_tar(fd, password, args.export_tar, before)
            finally:
                os.close(fd)
        else:
            context = fs.FixtureContext(args.fixture) if args.fixture else fs.DeviceContext()
            with context.operation_lock():
                if args.operation == 'create':
                    result = create(context, args.expected_volume_token, args.package, args.include_shared,
                                    args.destination_volume, args.expected_destination_token, password, args.confirm,
                                    profile=args.profile, include_settings=args.include_settings, include_personal=args.include_personal,
                                    expected_registry=args.expected_registry_sha256, include_apks=args.include_apks,
                                    include_root_adb=args.include_root_adb, shared_kinds=shared_kinds_arg(args.shared_types))
                    if args.summary:
                        manifest = result.pop('manifest')
                        result['schema'] = manifest['schema']
                        result['application_count'] = sum(item['kind'] == 'app-data' for item in manifest.get('items', ()))
                elif args.operation == 'list-apps':
                    result = list_source_apps(context, args.expected_volume_token)
                elif args.operation == 'inspect-shared':
                    with verified_shared(context, args.volume, args.expected_volume_token, args.path, password) as checked:
                        result = {**checked[2], 'operation': 'inspect-shared'}
                elif args.operation == 'inspect-apps':
                    result = inspect_apps(context, args.volume, args.expected_volume_token, args.path,
                                          args.expected_target_token, password)
                elif args.operation == 'restore-shared':
                    result = restore_shared(context, args.volume, args.expected_volume_token, args.path,
                                            args.expected_sha256, args.expected_target_token, password, args.confirm)
                elif args.operation == 'restore-root-adb':
                    result = restore_root_adb(context, args.volume, args.expected_volume_token, args.path,
                                              args.expected_sha256, args.expected_target_token, password, args.confirm,
                                              first_boot=args.first_boot_kernelsu, recovery_keys=args.with_recovery_adb_keys,
                                              stage_apps=args.stage_apps, stage_wifi=args.stage_wifi,
                                              recovery_wifi=args.with_recovery_wifi)
                elif args.operation == 'restore-app':
                    result = app_restore.restore(context, args.volume, args.expected_volume_token, args.path,
                                                 args.expected_sha256, args.expected_target_token, password,
                                                 args.package, args.confirm)
                else:
                    ad.require(not args.export_tar, 'INVALID_OPERATION', 'Plaintext tar export is available offline')
                    fs.require_hash(args.expected_volume_token, 'expected-volume-token')
                    ad.portable_volume(args.volume or '')
                    if args.volume == 'userdata':
                        ad.admitted(context.volume(args.volume, args.expected_volume_token))
                    with fs.PinnedVolume(context, args.volume, args.expected_volume_token) as pin, pin.parent(args.path) as (parent, name):
                        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                        try:
                            pin.check_fd(fd)
                            result = verify_fd(fd, password, args.expected_sha256)
                            ad.require(ad.identity(os.fstat(fd)) == ad.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                                       'SOURCE_CHANGED', 'The verified migration archive was replaced')
                            pin.recheck()
                        finally:
                            os.close(fd)
                    if args.review_for_data_token:
                        result['target_review'] = review_target(context, args.review_for_data_token, result['manifest'])
        if 'manifest' in result and not getattr(args, 'manifest', False):
            manifest = result.pop('manifest')
            if manifest['schema'] == ad.MODEL_SCHEMA:
                result.update(schema=ad.MODEL_SCHEMA, source=manifest['source'], counts=manifest['counts'],
                              skipped=manifest['skipped'], restore_supported=False)
            else:
                result.update(schema=manifest['schema'], items=manifest['items'], entries=len(manifest['files']))
                if 'preferences' in manifest:
                    result['preference_count'] = sum(map(len, manifest['preferences'].values()))
        print(json.dumps({'ok': True, **result}, separators=(',', ':')))
        return 0
    except (fs.FilesystemError, ac.CryptError) as error:
        code, message = error.code, str(error)
    except OSError as error:
        code, message = 'MIGRATION_IO_ERROR', 'Migration archive I/O failed (errno=%s)' % error.errno
    except (ValueError, tarfile.TarError, EOFError):
        code, message = 'MIGRATION_MANIFEST_INVALID', 'Invalid migration archive data'
    print(json.dumps({'ok': False, 'error': {'code': code, 'message': message}}, separators=(',', ':')))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
