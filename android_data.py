#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Same-phone logical userdata copy and portable shared-storage archives.

Archive: zstd(PAX tar: payload/<userdata relative entries>, __a22x__/manifest.json).
A22X.meta is base64 of ASCII JSON metadata: numeric owner/mode, mtime_ns,
symlink/hardlink target and base64 xattr values (including security.selinux).
Raw fscrypt context xattrs are excluded, never interpreted/restored. Every
regular payload has its streaming SHA256 in the final complete index. This
archive contains sensitive plaintext logically, protected at rest by inherited
CE policy. Losing/reformatting userdata also loses this same-partition copy.

Portable archives are ordinary gzip-compressed tar streams of shared files.
Restoring them creates a new folder with the destination Android's metadata.
"""
import argparse
import base64
import contextlib
import errno
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time
import zlib

import file_archive as fa
import filesystem as fs
import partition_archive as pa

SCHEMA = 'a22x.android-data.v1'
MODEL_SCHEMA = 'a22x.android-model-data.v1'
# 2026-11-21: the whole of an unencrypted userdata on a card or a stick, restorable (android_userdata.py).
FULL_SCHEMA = 'a22x.android-userdata.v1'
DESTINATION = '/media/0/A22xDataBackups'
MIGRATION_STORE = 'A22xMigrationBackups'
STORES = ('A22xDataBackups', 'A22xBackups', 'A22xArchives', 'A22xAndroidBackups',
          'A22xPartitionBackups', 'A22xIdentityBackups', MIGRATION_STORE)
EXCLUDED = tuple('media/0/' + name for name in STORES)
LEGACY_EXCLUDED = tuple(path for path in EXCLUDED if path != 'media/0/' + MIGRATION_STORE)
PORTABLE_STORE = 'A22xPortableBackups'
MODEL_EXCLUDED = (*EXCLUDED, 'media/0/' + PORTABLE_STORE)
PORTABLE_SKIP_ROOT = frozenset(name.casefold() for name in (*STORES, PORTABLE_STORE))
PORTABLE_SCOPE = 'android-shared-storage-user0'
MANIFEST = '__a22x__/manifest.json'
MAX_ENTRIES = 200000
MAX_DEPTH = 128
MAX_INDEX = 64 << 20
MAX_META = 512 << 10
MAX_XATTRS = 128
MAX_XATTR_BYTES = 64 << 10
MAX_LOGICAL = 1 << 40
RESERVE = 512 << 20
CHUNK = 1 << 20
USER_ROOTS = ('user', 'user_de', 'system_ce', 'system_de', 'misc_ce', 'misc_de',
              'misc/vold/user_keys/ce', 'misc/vold/user_keys/de')


def require(ok, code, message):
    if not ok:
        fs.fail(code, message)


def fixture(context):
    return isinstance(context, fs.FixtureContext) and context.mode == 'fixture'


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')


def plain_open(volume):
    """Android data that encrypts nothing (LineageOS 20 for this phone has no fileencryption in its
    fstab), mounted by the filesystem helper: there is no credential-encrypted storage and no key, so
    nothing to authenticate; its files are read and written as they are (2026-11-21, on the phone: the
    portable copy, the migration and the restores were refused for LineageOS, which asked for an
    unlock that does not exist)."""
    return (volume.get('unencrypted_android_data') is True and volume.get('mounted') is True
            and volume.get('mountable') is True and volume.get('mount_owner') == 'filesystem'
            and volume.get('fs_type') == 'f2fs')


def admitted(volume, writing=False):
    if plain_open(volume):
        if writing:
            require(volume.get('write_supported') is True and volume.get('read_only') is False,
                    'ANDROID_RW_REQUIRED', 'Mount Android data for writing first')
        return
    require(volume.get('mounted') is True and volume.get('mountable') is True,
            'ANDROID_NOT_MOUNTED', 'Retained Android userdata must already be mounted')
    require(volume.get('fs_type') == 'f2fs' and volume.get('mount_owner') == 'android-decrypt'
            and volume.get('ce_authenticated') is True and volume.get('fscrypt_policy_verified') is True,
            'ANDROID_CE_REQUIRED', 'Authenticated user0 CE and its verified retained mount are required')
    require(volume.get('decrypt_state') == 'mounted' and bool(volume.get('decrypt_profile_id')),
            'ANDROID_CE_REQUIRED', 'A current authenticated Android session is required')
    if writing:
        require(volume.get('write_supported') is True and volume.get('read_only') is False,
                'ANDROID_RW_REQUIRED', 'Explicitly enabled and qualified Android writes are required')


def inspect(context):
    v = context.volume('userdata')
    reason = None
    try:
        admitted(v, True)
    except fs.FilesystemError as error:
        reason = error.code
    return {'can_backup': reason is None, 'mounted': bool(v.get('mounted')),
            'ce_authenticated': v.get('ce_authenticated') is True or plain_open(v),
            'read_only': v.get('read_only') is not False,
            'write_supported': v.get('write_supported') is True,
            'volume_token': v['volume_token'], 'destination': DESTINATION, 'reason': reason,
            'same_partition': True, 'portable_android_migration': False, 'restore_supported': False}


def policy(fd):
    """The folder's fscrypt v2 policy, or None for a folder without one (unencrypted Android data,
    plain_open): two folders then match only when neither has a policy."""
    buf = bytearray(32)
    struct.pack_into('=Q', buf, 0, 24)
    try:
        fcntl.ioctl(fd, 0xc0096616, buf, True)
    except OSError as error:
        if error.errno == errno.ENODATA:
            return None
        raise
    require(struct.unpack_from('=Q', buf)[0] == 24 and buf[8] == 2
            and buf[9] == 1 and buf[10] == 4 and buf[11] & ~11 == 0 and buf[12:16] == bytes(4),
            'CE_POLICY_UNSUPPORTED', 'A supported existing fscrypt v2 policy is required')
    return bytes(buf[8:32])


def same_policy(context, media, destination):
    if not fixture(context):
        require(policy(media) == policy(destination), 'CE_POLICY_MISMATCH',
                'Backup destination must inherit the user0 media CE policy')


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def attributes(directory, name):
    path = '/proc/self/fd/%d/%s' % (directory, name)
    values = {}
    names = os.listxattr(path, follow_symlinks=False)
    require(len(names) <= MAX_XATTRS, 'BACKUP_BOUNDS', 'Too many extended attributes')
    total = 0
    for key in sorted(names):
        # Raw encryption contexts are filesystem/key-epoch state, not portable xattrs.
        if key.startswith(('encryption.', 'fscrypt.', 'system.fscrypt', 'trusted.fscrypt')):
            continue
        value = os.getxattr(path, key, follow_symlinks=False)
        total += len(os.fsencode(key)) + len(value)
        require(total <= MAX_XATTR_BYTES, 'BACKUP_BOUNDS', 'Extended attributes exceed the bounded format')
        values[key] = base64.b64encode(value).decode('ascii')
    return values


def excluded(path, exclusions=EXCLUDED):
    return any(path == item or path.startswith(item + '/') for item in exclusions)


def user_scope(path):
    parent, _, leaf = path.rpartition('/')
    if parent in USER_ROOTS or parent == 'media':
        require(not leaf.isdecimal() or int(leaf) == 0, 'ANDROID_OTHER_USERS',
                'Only fully decrypted Android user0 is supported')
    if parent == 'system/users':
        ident = leaf[:-4] if leaf.endswith('.xml') else leaf
        require(not ident.isdecimal() or int(ident) == 0, 'ANDROID_OTHER_USERS',
                'Secondary Android users are outside the supported scope')


def scan(pin, exclusions=EXCLUDED):
    """Descriptor walk with exact mount checks; never follows a symlink."""
    entries = []
    skipped = {'sockets': 0, 'devices': 0, 'stores': 0}
    budget = [0]
    def visit(directory, prefix, depth):
        require(depth <= MAX_DEPTH, 'BACKUP_BOUNDS', 'Directory depth exceeds the bounded format')
        pin.check_fd(directory)
        for name in sorted(os.listdir(directory)):
            path = prefix + '/' + name if prefix else name
            require(len(os.fsencode(path)) <= 4096, 'BACKUP_BOUNDS', 'A pathname exceeds the bounded format')
            if excluded(path, exclusions):
                skipped['stores'] += 1
                continue
            user_scope(path)
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(before.st_dev == pin.stat.st_dev, 'CROSS_MOUNT_REJECTED', 'Nested filesystems cannot be included')
            kind = fs.entry_type(before)
            if kind == 'other':
                require(not stat.S_ISFIFO(before.st_mode), 'ANDROID_FIFO_UNSUPPORTED',
                        'A FIFO requires unsupported special-file handling; no incomplete backup is published')
                field = 'sockets' if stat.S_ISSOCK(before.st_mode) else 'devices' if stat.S_ISCHR(before.st_mode) or stat.S_ISBLK(before.st_mode) else None
                require(field is not None, 'ANDROID_UNREADABLE', 'An unsupported userdata entry cannot be archived')
                skipped[field] += 1
                continue
            meta = {'path': path, 'type': kind, 'mode': stat.S_IMODE(before.st_mode),
                    'uid': before.st_uid, 'gid': before.st_gid, 'mtime_ns': before.st_mtime_ns,
                    'size': before.st_size if kind == 'file' else 0,
                    'xattrs': attributes(directory, name)}
            if kind == 'symlink':
                meta['link'] = os.readlink(name, dir_fd=directory)
            require(identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identity(before),
                    'SOURCE_CHANGED', 'Userdata changed during its offline snapshot')
            budget[0] += len(encode(meta)) + 160
            require(len(entries) < MAX_ENTRIES and budget[0] <= MAX_INDEX,
                    'BACKUP_BOUNDS', 'The complete index exceeds the bounded format')
            entries.append({'meta': meta, 'stat': before})
            if kind == 'directory':
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                try:
                    pin.check_fd(child)
                    require(identity(os.fstat(child)) == identity(before), 'SOURCE_CHANGED', 'A directory changed')
                    visit(child, path, depth + 1)
                    require(identity(os.fstat(child)) == identity(before), 'SOURCE_CHANGED', 'A directory changed')
                finally:
                    os.close(child)
    visit(pin.fd, '', 0)
    pin.recheck()
    return entries, skipped


def free_bytes(fd):
    value = os.fstatvfs(fd)
    return value.f_bavail * value.f_frsize


def capacity(fd, needed=0):
    require(free_bytes(fd) >= RESERVE + needed, 'NO_SPACE',
            'The archive and the required 512 MiB free-space reserve do not fit')


def worst_case(entries):
    # Unique regular inodes only: hardlinks carry no second payload. Deliberately
    # overbound tar/PAX padding and the full JSON index before any file is made.
    seen, data, metadata = set(), 0, 0
    for entry in entries:
        st, meta = entry['stat'], entry['meta']
        inode = (st.st_dev, st.st_ino)
        if meta['type'] == 'file' and inode not in seen:
            data += st.st_size
            seen.add(inode)
        metadata += 16384 + 4 * (len(encode(meta)) + 160)
    require(data <= MAX_LOGICAL, 'BACKUP_BOUNDS', 'Logical userdata size exceeds the bounded format')
    raw = data + metadata + 65536
    return raw + raw // 128 + (1 << 20)


class HashReader:
    def __init__(self, stream, progress):
        self.stream, self.progress, self.digest, self.count = stream, progress, hashlib.sha256(), 0
    def read(self, size=-1):
        value = self.stream.read(min(size, CHUNK) if size >= 0 else CHUNK)
        self.digest.update(value)
        self.count += len(value)
        self.progress(len(value))
        return value


class Sink(fa.Pipe):
    def __init__(self, fd, out, progress):
        super().__init__(fd)
        self.out, self.progress = out, progress
    def write(self, data):
        capacity(self.out)
        return super().write(data)


def mtime_text(value):
    sign = '-' if value < 0 else ''
    seconds, ns = divmod(abs(value), 1000000000)
    return '%s%d.%09d' % (sign, seconds, ns)


def metadata_header(meta, directory, name, st):
    item = fa.tar_info(directory, name, st, 'payload/' + meta['path'])
    if meta['type'] == 'hardlink':
        item.type, item.size, item.linkname = tarfile.LNKTYPE, 0, 'payload/' + meta['link']
    item.uid, item.gid, item.mode = meta['uid'], meta['gid'], meta['mode']
    item.pax_headers = {'A22X.meta': base64.b64encode(encode(meta)).decode('ascii'),
                        'mtime': mtime_text(meta['mtime_ns'])}
    return item


def current_source(pin):
    return {'boot_id': str(getattr(pin.context, 'boot_id', 'fixture')),
            'profile_id': pin.volume.get('decrypt_profile_id'), 'android_user_id': 0,  # none for unencrypted data
            'volume_token': pin.volume['volume_token']}


def root_metadata(pin):
    before = os.fstat(pin.fd)
    value = {'path': '/', 'type': 'directory', 'mode': stat.S_IMODE(before.st_mode),
             'uid': before.st_uid, 'gid': before.st_gid, 'mtime_ns': before.st_mtime_ns,
             'size': 0, 'xattrs': attributes(pin.fd, '.')}
    require(identity(os.fstat(pin.fd)) == identity(before), 'SOURCE_CHANGED', 'Userdata root changed')
    return value, identity(before)


def write_archive(pin, out, entries, skipped, progress, *, capacity_fd=None, model_source=None, full_exclusions=None):
    space = out if capacity_fd is None else capacity_fd
    root, root_ident = root_metadata(pin)
    proc = subprocess.Popen([pa.zstd_path(), '-q', '-3', '-T1', '-c'],
                            stdin=subprocess.PIPE, stdout=out, stderr=subprocess.DEVNULL, bufsize=0)
    index, hardlinks = [], {}
    done, last_check = [0], [0.0]
    def counted(n):
        done[0] += n
        capacity(space)
        if time.monotonic() - last_check[0] >= 1:
            pin.recheck()
            last_check[0] = time.monotonic()
        progress(done[0], len(index))
    try:
        with tarfile.open(fileobj=Sink(proc.stdin.fileno(), space, progress), mode='w|',
                          format=tarfile.PAX_FORMAT, bufsize=CHUNK) as tar:
            for entry in entries:
                if time.monotonic() - last_check[0] >= 1:
                    pin.recheck()
                    last_check[0] = time.monotonic()
                original, before = entry['meta'], entry['stat']
                folder, _, name = original['path'].rpartition('/')
                with fs.tree_directory(pin, pin.fd, folder) as parent:
                    now = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    require(identity(now) == identity(before) and attributes(parent, name) == original['xattrs'],
                            'SOURCE_CHANGED', 'Userdata metadata changed before it was copied')
                    meta = dict(original)
                    inode = (before.st_dev, before.st_ino)
                    if meta['type'] == 'file' and inode in hardlinks:
                        meta.update(type='hardlink', size=0, link=hardlinks[inode])
                    item = metadata_header(meta, parent, name, before)
                    if meta['type'] == 'file':
                        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                        try:
                            pin.check_fd(fd)
                            require(identity(os.fstat(fd)) == identity(before), 'SOURCE_CHANGED', 'A file changed')
                            with os.fdopen(os.dup(fd), 'rb', buffering=0) as stream:
                                reader = HashReader(stream, counted)
                                tar.addfile(item, reader)
                            require(reader.count == before.st_size and identity(os.fstat(fd)) == identity(before),
                                    'SOURCE_CHANGED', 'A file changed while it was copied')
                            meta['sha256'] = reader.digest.hexdigest()
                            hardlinks[inode] = meta['path']
                        finally:
                            os.close(fd)
                    else:
                        if meta['type'] == 'symlink':
                            require(os.readlink(name, dir_fd=parent) == meta['link'], 'SOURCE_CHANGED', 'A link changed')
                        tar.addfile(item)
                    index.append(meta)
                    progress(done[0], len(index))
            # Complete source census again: new/missing/changed entries cannot be
            # hidden behind a successful tar writer. Destination subtree excluded.
            exclusions = MODEL_EXCLUDED if model_source is not None else (list(full_exclusions) if full_exclusions is not None else EXCLUDED)
            after, after_skipped = scan(pin, exclusions)
            require([(e['meta'], identity(e['stat'])) for e in after] ==
                    [(e['meta'], identity(e['stat'])) for e in entries] and after_skipped == skipped,
                    'SOURCE_CHANGED', 'Offline userdata changed during its copy')
            require(root_metadata(pin) == (root, root_ident), 'SOURCE_CHANGED', 'Userdata root changed during its copy')
            manifest = {'schema': SCHEMA, 'root': root, 'source': current_source(pin), 'created': int(time.time()),
                        'same_partition': True, 'restore_supported': False,
                        'excluded': list(exclusions), 'skipped': skipped,
                        'entries': index, 'counts': {'entries': len(index), 'file_bytes': done[0],
                        'files': sum(e['type'] == 'file' for e in index),
                        'hardlinks': sum(e['type'] == 'hardlink' for e in index)}}
            if model_source is not None:
                manifest.update(schema=MODEL_SCHEMA, source=model_source)
                del manifest['same_partition']
            elif full_exclusions is not None:
                manifest.update(schema=FULL_SCHEMA, restore_supported=True)
                del manifest['same_partition']
            data = encode(manifest)
            require(len(data) <= MAX_INDEX, 'BACKUP_BOUNDS', 'Complete manifest exceeds the bounded format')
            item = tarfile.TarInfo(MANIFEST)
            item.size, item.mode = len(data), 0o600
            tar.addfile(item, io.BytesIO(data))
        proc.stdin.close()
        require(proc.wait() == 0, 'ARCHIVE_WRITE_FAILED', 'Compression did not complete')
        capacity(space)
        return manifest
    except BaseException:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        raise
    finally:
        with contextlib.suppress(OSError):
            proc.stdin.close()


def file_sha(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, CHUNK)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def exact(stream, count):
    data = bytearray()
    while len(data) < count:
        chunk = stream.read(min(count - len(data), CHUNK))
        require(bool(chunk), 'ARCHIVE_DAMAGED', 'Archive stream is truncated')
        data.extend(chunk)
    return bytes(data)


def pax_fields(data):
    values, offset = {}, 0
    while offset < len(data):
        space = data.find(b' ', offset, min(len(data), offset + 24))
        require(space > offset, 'ARCHIVE_DAMAGED', 'Invalid bounded PAX record')
        number = data[offset:space]
        require(number.isdigit(), 'ARCHIVE_DAMAGED', 'Invalid PAX size')
        length = int(number)
        require(length > space - offset + 2 and offset + length <= len(data),
                'ARCHIVE_DAMAGED', 'Invalid PAX record length')
        record = data[space+1:offset+length]
        require(record.endswith(b'\n') and b'=' in record, 'ARCHIVE_DAMAGED', 'Invalid PAX record')
        key, value = record[:-1].split(b'=', 1)
        require(key in (b'A22X.meta', b'mtime', b'path', b'linkpath', b'uid', b'gid', b'size', b'hdrcharset')
                and key not in values, 'ARCHIVE_DAMAGED', 'Unsupported or duplicate PAX field')
        require(key != b'hdrcharset' or value == b'BINARY', 'ARCHIVE_DAMAGED', 'Unsupported PAX character set')
        values[key] = value.decode('utf-8', 'surrogateescape')
        offset += length
    return values


def payload_meta(raw, exclusions=EXCLUDED):
    require(len(raw) <= MAX_META, 'ARCHIVE_DAMAGED', 'Metadata exceeds the bounded format')
    try:
        value = json.loads(base64.b64decode(raw, validate=True))
        require(isinstance(value, dict) and value['type'] in ('file', 'directory', 'symlink', 'hardlink')
                and isinstance(value['path'], str) and fs.clean_path(value['path']) == '/' + value['path']
                and value['path'] and len(os.fsencode(value['path'])) <= 4096
                and len(value['path'].split('/')) <= MAX_DEPTH + 1 and not excluded(value['path'], exclusions),
                'ARCHIVE_DAMAGED', 'Invalid payload metadata')
        require(all(isinstance(value[k], int) and not isinstance(value[k], bool) for k in ('uid', 'gid', 'mode', 'mtime_ns', 'size'))
                and 0 <= value['mode'] <= 0o7777 and 0 <= value['uid'] <= 0xffffffff
                and 0 <= value['gid'] <= 0xffffffff and 0 <= value['size'] <= MAX_LOGICAL,
                'ARCHIVE_DAMAGED', 'Invalid numeric metadata')
        attrs = value['xattrs']
        require(isinstance(attrs, dict) and len(attrs) <= MAX_XATTRS, 'ARCHIVE_DAMAGED', 'Invalid xattrs')
        total = 0
        for key, entry in attrs.items():
            require(isinstance(key, str) and isinstance(entry, str) and '\0' not in key
                    and not key.startswith(('encryption.', 'fscrypt.', 'system.fscrypt', 'trusted.fscrypt')),
                    'ARCHIVE_DAMAGED', 'Invalid xattr namespace')
            total += len(os.fsencode(key)) + len(base64.b64decode(entry, validate=True))
        require(total <= MAX_XATTR_BYTES, 'ARCHIVE_DAMAGED', 'Xattrs exceed the bounded format')
        return value
    except (ValueError, TypeError, KeyError):
        fs.fail('ARCHIVE_DAMAGED', 'Payload metadata is malformed')


def verify_fd(fd, expected_sha):
    """Full compressed SHA first, then bounded raw tar/PAX verification; no extraction."""
    fs.require_hash(expected_sha, 'expected-sha256')
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_size > 0, 'NOT_AN_ARCHIVE', 'A regular backup archive is required')
    require(file_sha(fd) == expected_sha, 'ARCHIVE_SHA_MISMATCH', 'Full archive SHA256 does not match')
    require(identity(os.fstat(fd)) == identity(before), 'SOURCE_CHANGED', 'Archive changed during verification')
    os.lseek(fd, 0, os.SEEK_SET)
    manifest = verify_stream(fd, SCHEMA)
    require(identity(os.fstat(fd)) == identity(before), 'SOURCE_CHANGED', 'Archive changed during verification')
    return manifest


def verify_stream(fd, schema, full_exclusions=None):
    proc = subprocess.Popen([pa.zstd_path(), '-q', '-d', '-c'], stdin=fd,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    observed, names, logical_names, manifest, pending = [], set(), set(), None, None
    consumed, metadata_bytes = 0, 0
    try:
        while True:
            block = exact(proc.stdout, 512)
            if block == bytes(512):
                require(pending is None and exact(proc.stdout, 512) == bytes(512),
                        'ARCHIVE_DAMAGED', 'Tar terminator is incomplete')
                trailing = 1024
                while True:
                    more = proc.stdout.read(CHUNK)
                    if not more:
                        break
                    trailing += len(more)
                    # tarfile pads the whole archive to its 10240-byte record after the two zero blocks: up to
                    # 10752 bytes of zeros in all (2026-11-21: a copy ending 512 bytes into a record read as damaged).
                    require(trailing <= tarfile.RECORDSIZE + 512 and not any(more), 'ARCHIVE_DAMAGED', 'Unexpected data after tar terminator')
                break
            item = tarfile.TarInfo.frombuf(block, 'utf-8', 'surrogateescape')
            require(0 <= item.size <= MAX_LOGICAL, 'ARCHIVE_DAMAGED', 'Invalid tar member size')
            if item.type == tarfile.XHDTYPE:
                require(pending is None and manifest is None and item.size <= MAX_META,
                        'ARCHIVE_DAMAGED', 'Invalid bounded PAX header')
                pending = pax_fields(exact(proc.stdout, item.size))
                require(not any(exact(proc.stdout, -item.size % 512)), 'ARCHIVE_DAMAGED', 'Nonzero tar padding')
                continue
            fields, pending = pending or {}, None
            for key, attribute in ((b'path', 'name'), (b'linkpath', 'linkname')):
                if key in fields:
                    setattr(item, attribute, fields[key])
            for key in (b'uid', b'gid', b'size'):
                if key in fields:
                    require(fields[key].isdecimal(), 'ARCHIVE_DAMAGED', 'Invalid PAX numeric field')
                    setattr(item, key.decode(), int(fields[key]))
            require(manifest is None and item.name not in names, 'ARCHIVE_DAMAGED', 'Duplicate or late archive member')
            names.add(item.name)
            if item.name == MANIFEST:
                require(item.type == tarfile.REGTYPE and item.size <= MAX_INDEX and not fields,
                        'ARCHIVE_DAMAGED', 'Invalid complete index member')
                manifest = json.loads(exact(proc.stdout, item.size))
            else:
                require(len(observed) < MAX_ENTRIES and b'A22X.meta' in fields,
                        'ARCHIVE_DAMAGED', 'Missing indexed member metadata')
                meta = payload_meta(fields[b'A22X.meta'], MODEL_EXCLUDED if schema == MODEL_SCHEMA else
                                    (full_exclusions if schema == FULL_SCHEMA else LEGACY_EXCLUDED))
                require(meta['path'] not in logical_names, 'ARCHIVE_DAMAGED', 'Duplicate indexed pathname')
                logical_names.add(meta['path'])
                expected_type = {'file': tarfile.REGTYPE, 'directory': tarfile.DIRTYPE,
                                 'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE}[meta['type']]
                expected_link = ('payload/' + meta['link']) if meta['type'] == 'hardlink' else meta.get('link', '')
                require(item.name.rstrip('/') == 'payload/' + meta['path'] and item.type == expected_type
                        and item.mode == meta['mode'] and item.uid == meta['uid'] and item.gid == meta['gid']
                        and item.size == meta['size'] and item.linkname == expected_link
                        and fields.get(b'mtime') == mtime_text(meta['mtime_ns']),
                        'ARCHIVE_DAMAGED', 'Payload metadata does not match tar headers')
                if meta['type'] == 'hardlink':
                    require(any(e['path'] == meta['link'] and e['type'] == 'file' for e in observed),
                            'ARCHIVE_DAMAGED', 'Hardlink does not refer to an earlier regular member')
                digest = hashlib.sha256()
                left = item.size
                while left:
                    chunk = exact(proc.stdout, min(left, CHUNK))
                    digest.update(chunk)
                    left -= len(chunk)
                consumed += item.size
                require(consumed <= MAX_LOGICAL, 'ARCHIVE_DAMAGED', 'Logical payload exceeds the bounded format')
                if meta['type'] == 'file':
                    meta['sha256'] = digest.hexdigest()
                observed.append(meta)
                metadata_bytes += len(encode(meta))
                require(metadata_bytes <= MAX_INDEX, 'ARCHIVE_DAMAGED', 'Payload index exceeds the bounded format')
            require(not any(exact(proc.stdout, -item.size % 512)), 'ARCHIVE_DAMAGED', 'Nonzero tar padding')
        require(proc.wait() == 0, 'ARCHIVE_DAMAGED', 'Compressed archive is damaged or truncated')
        allowed = ([list(MODEL_EXCLUDED)] if schema == MODEL_SCHEMA else [list(full_exclusions)] if schema == FULL_SCHEMA
                   else [list(EXCLUDED), list(LEGACY_EXCLUDED)])
        require(isinstance(manifest, dict) and manifest.get('schema') == schema
                and manifest.get('entries') == observed and manifest.get('excluded') in allowed
                and (manifest.get('restore_supported') is True and 'same_partition' not in manifest if schema == FULL_SCHEMA else
                     (schema == MODEL_SCHEMA or manifest.get('same_partition') is True) and manifest.get('restore_supported') is False),
                'ARCHIVE_DAMAGED', 'The complete index does not match its payload')
        require(all(not excluded(entry['path'], manifest['excluded']) for entry in observed),
                'ARCHIVE_DAMAGED', 'The backup contains an excluded path')
        root = manifest.get('root')
        require(isinstance(root, dict) and root.get('path') == '/' and root.get('type') == 'directory'
                and root.get('size') == 0, 'ARCHIVE_DAMAGED', 'Missing descriptive userdata root metadata')
        root_copy = dict(root, path='root-descriptor')
        payload_meta(base64.b64encode(encode(root_copy)))
        counts = {'entries': len(observed), 'file_bytes': consumed,
                  'files': sum(e['type'] == 'file' for e in observed),
                  'hardlinks': sum(e['type'] == 'hardlink' for e in observed)}
        require(manifest.get('counts') == counts,
                'ARCHIVE_DAMAGED', 'Archive counts or identity changed')
        return manifest
    except (tarfile.TarError, ValueError, TypeError, KeyError, UnicodeError):
        fs.fail('ARCHIVE_DAMAGED', 'Archive structure is malformed')
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()
        proc.wait()


def owned_unlink(parent, name, ident):
    try:
        st = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    require((st.st_dev, st.st_ino) == ident and stat.S_ISREG(st.st_mode),
            'PARTIAL_IDENTITY_CHANGED', 'An unrelated partial archive will not be removed')
    os.unlink(name, dir_fd=parent)


def publish(parent, partial, final, ident):
    st = os.stat(partial, dir_fd=parent, follow_symlinks=False)
    require((st.st_dev, st.st_ino) == ident and stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
            'PARTIAL_IDENTITY_CHANGED', 'Partial archive ownership changed')
    # linkat creates final atomically and refuses an existing name. The same
    # verified inode is published; no overwrite window exists as with rename.
    try:
        os.link(partial, final, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
    except FileExistsError:
        fs.fail('DESTINATION_EXISTS', 'An existing archive will not be overwritten')
    os.fsync(parent)
    owned_unlink(parent, partial, ident)
    os.fsync(parent)


def backup(context, token, confirmed, progress=lambda *unused: None):
    context.confirm(confirmed)
    fs.require_hash(token, 'expected-volume-token')
    admitted(context.volume('userdata', token), True)
    with fs.PinnedVolume(context, 'userdata', token, writing=True) as pin, pin.directory('media/0') as media:
        store = DESTINATION.rsplit('/', 1)[1]
        try:
            os.mkdir(store, 0o700, dir_fd=media)
            os.fsync(media)
        except FileExistsError:
            pass
        parent = os.open(store, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=media)
        try:
            pin.check_fd(parent)
            dst = os.fstat(parent)
            require(dst.st_uid == os.geteuid() and stat.S_IMODE(dst.st_mode) == 0o700,
                    'DESTINATION_UNSAFE', 'Backup directory must be owned by recovery and private mode0700')
            same_policy(context, media, parent)
            entries, skipped = scan(pin)
            capacity(parent, worst_case(entries))
            final = 'android-data-' + time.strftime('%Y%m%d-%H%M%S', time.gmtime()) + '-' + os.urandom(8).hex() + '.tar.zst'
            partial = '.' + final + '.partial-' + os.urandom(8).hex()
            out = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            ident = (os.fstat(out).st_dev, os.fstat(out).st_ino)
            try:
                pin.check_fd(out)
                require(stat.S_IMODE(os.fstat(out).st_mode) == 0o600, 'DESTINATION_UNSAFE', 'Archive mode must be0600')
                same_policy(context, media, out)
                write_archive(pin, out, entries, skipped, progress)
                os.fsync(out)
                digest, size = file_sha(out), os.fstat(out).st_size
                manifest = verify_fd(out, digest)
                pin.recheck()
                admitted(context.volume('userdata', token), True)
                same_policy(context, media, parent)
                publish(parent, partial, final, ident)
            except BaseException:
                owned_unlink(parent, partial, ident)
                os.fsync(parent)
                raise
            finally:
                os.close(out)
        finally:
            os.close(parent)
    return {'archive': {'volume': 'userdata', 'path': DESTINATION + '/' + final, 'bytes': size, 'sha256': digest},
            'verified': True, 'counts': manifest['counts'], 'skipped': manifest['skipped'],
            'source': manifest['source'], 'current': current_source(pin),
            'same_partition': True, 'limitation': 'SAME_PHONE_LOGICAL_COPY_NOT_PORTABLE_MIGRATION', 'restore_supported': False}


def verify(context, path, token, expected_sha):
    fs.require_hash(token, 'expected-volume-token')
    admitted(context.volume('userdata', token))
    clean = fs.clean_path(path)
    require(clean.startswith(DESTINATION + '/') and clean.count('/') == DESTINATION.count('/') + 1
            and clean.endswith('.tar.zst'), 'INVALID_ARCHIVE_PATH', 'Choose a completed archive in the fixed backup directory')
    with fs.PinnedVolume(context, 'userdata', token) as pin, pin.parent(clean) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            pin.check_fd(fd)
            manifest = verify_fd(fd, expected_sha)
            size = os.fstat(fd).st_size
            pin.recheck()
        finally:
            os.close(fd)
        return {'archive': {'volume': 'userdata', 'path': clean, 'bytes': size, 'sha256': expected_sha},
                'verified': True, 'counts': manifest['counts'], 'source': manifest['source'],
                'current': current_source(pin), 'same_partition': True, 'restore_supported': False}


def portable_path(path):
    parts = path.split('/')
    require(0 < len(path.encode('utf-8')) <= 4096 and len(parts) <= MAX_DEPTH
            and '\\' not in path and '\0' not in path
            and all(part not in ('', '.', '..') and len(part.encode('utf-8')) <= 255 for part in parts),
            'ARCHIVE_UNSAFE', 'A shared-storage path cannot be used in a portable archive')
    return parts


def portable_excluded(parts):
    return (parts[0].casefold() in PORTABLE_SKIP_ROOT or parts[0].startswith('.a22x-restore-')
            or (len(parts) >= 2 and parts[0].casefold() == 'android'
                and parts[1].casefold() in ('data', 'obb')))


def portable_write(pin, media, out, progress):
    records = {}
    done = skipped = index_bytes = 0

    def visit(tar, directory, prefix):
        nonlocal done, skipped, index_bytes
        baseline = identity(os.fstat(directory))
        for name in sorted(os.listdir(directory)):
            path = prefix + name
            parts = portable_path(path)
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            kind = fs.entry_type(before)
            if portable_excluded(parts) or kind not in ('file', 'directory'):
                skipped += 1
                continue
            is_dir = kind == 'directory'
            index_bytes += len(path.encode('utf-8')) + 160
            require(len(records) < MAX_ENTRIES and index_bytes <= MAX_INDEX
                    and done + (0 if is_dir else before.st_size) <= MAX_LOGICAL,
                    'BACKUP_BOUNDS', 'Shared storage exceeds the bounded archive format')
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_DIRECTORY if is_dir else os.O_NONBLOCK)
            fd = os.open(name, flags, dir_fd=directory)
            try:
                pin.check_fd(fd)
                require(identity(os.fstat(fd)) == identity(before), 'SOURCE_CHANGED', 'A shared-storage entry changed')
                entry = tarfile.TarInfo(path)
                entry.mtime = max(0, min(before.st_mtime_ns // 1000000000, 0xffffffff))
                if is_dir:
                    entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                    tar.addfile(entry)
                    records[path] = (entry.type, 0, entry.mtime, None)
                    visit(tar, fd, path + '/')
                else:
                    entry.mode, entry.size = 0o644, before.st_size
                    with os.fdopen(os.dup(fd), 'rb') as stream:
                        payload = HashReader(stream, lambda _: progress(done + payload.count, len(records)))
                        tar.addfile(entry, payload)
                    records[path] = (entry.type, entry.size, entry.mtime, payload.digest.hexdigest())
                    done += entry.size
                require(identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identity(before)
                        and identity(os.fstat(fd)) == identity(before), 'SOURCE_CHANGED', 'A shared-storage entry changed')
            finally:
                os.close(fd)
        require(identity(os.fstat(directory)) == baseline, 'SOURCE_CHANGED', 'A shared-storage folder changed')

    with os.fdopen(os.dup(out), 'wb') as file, gzip.GzipFile(fileobj=file, mode='wb', compresslevel=3, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            visit(tar, media, '')
    require(records, 'NOTHING_SELECTED', 'Shared storage has no portable files or folders')
    return records, skipped


def portable_read(fd, consume=None):
    """Read bounded tar headers and verify all data and gzip checksums."""
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), 'rb') as file:
        return portable_read_gzip(file, consume)


def portable_read_gzip(file, consume=None):
    """Read a gzip archive from a pinned stream, including an authenticated pipe."""
    records, done, index_bytes, pending = {}, 0, 0, None
    try:
        with gzip.GzipFile(fileobj=file) as stream:
            while True:
                block = exact(stream, 512)
                if block == bytes(512):
                    require(pending is None and exact(stream, 512) == bytes(512),
                            'ARCHIVE_DAMAGED', 'Tar terminator is incomplete')
                    # Up to a record less one block after the two zero blocks (see verify_stream, 2026-11-21).
                    tail = stream.read(tarfile.RECORDSIZE - 512 + 1)
                    require(len(tail) <= tarfile.RECORDSIZE - 512 and not any(tail), 'ARCHIVE_DAMAGED', 'Unexpected data after tar terminator')
                    return records, done
                item = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
                if item.type == tarfile.XHDTYPE:
                    require(pending is None and 0 < item.size <= 8192,
                            'ARCHIVE_DAMAGED', 'Invalid portable PAX header')
                    pending = pax_fields(exact(stream, item.size))
                    require(pending.keys() <= {b'path', b'size'}, 'ARCHIVE_UNSAFE', 'Unsupported portable PAX metadata')
                else:
                    if pending:
                        item.name = pending.get(b'path', item.name)
                        if b'size' in pending:
                            size = pending[b'size']
                            require(size.isascii() and size.isdecimal() and len(size) <= 13,
                                    'ARCHIVE_DAMAGED', 'Invalid portable member size')
                            item.size = int(size)
                    pending = None
                    path = item.name.rstrip('/') if item.isdir() else item.name
                    parts = portable_path(path)
                    index_bytes += len(path.encode('utf-8')) + 160
                    require(item.type in (tarfile.REGTYPE, tarfile.DIRTYPE) and not portable_excluded(parts)
                            and path not in records and (len(parts) == 1 or records.get('/'.join(parts[:-1]), (None,))[0] == tarfile.DIRTYPE),
                            'ARCHIVE_UNSAFE', 'An archive contains an unsupported, duplicate or misplaced entry')
                    require(len(records) < MAX_ENTRIES and index_bytes <= MAX_INDEX and 0 <= item.size <= MAX_LOGICAL - done
                            and (not item.isdir() or item.size == 0) and 0 <= item.mtime <= 0xffffffff,
                            'ARCHIVE_DAMAGED', 'A portable member exceeds its format limits')
                    payload = HashReader(stream, lambda *unused: None)
                    if consume is not None:
                        consume(parts, item, payload)
                    else:
                        while payload.count < item.size:
                            exact(payload, min(item.size - payload.count, CHUNK))
                    require(payload.count == item.size, 'ARCHIVE_DAMAGED', 'A portable member has the wrong size')
                    records[path] = (item.type, item.size, item.mtime, None if item.isdir() else payload.digest.hexdigest())
                    done += item.size
                require(not any(exact(stream, -item.size % 512)), 'ARCHIVE_DAMAGED', 'Nonzero tar padding')
    except (gzip.BadGzipFile, zlib.error, EOFError, tarfile.TarError, UnicodeError, ValueError):
        fs.fail('ARCHIVE_DAMAGED', 'The portable archive is damaged or truncated')


def portable_volume(volume):
    require(volume == 'userdata' or volume.startswith(('sdcard-', 'usb-')),
            'INVALID_VOLUME', 'Choose Android userdata, SD or USB storage')


def portable_result(volume, path, size, digest, records, total):
    return {'scope': PORTABLE_SCOPE, 'format': 'tar.gz', 'verified': True,
            'archive': {'volume': volume, 'path': path, 'bytes': size, 'sha256': digest},
            'counts': {'entries': len(records), 'file_bytes': total,
                       'files': sum(record[0] == tarfile.REGTYPE for record in records.values())}}


def portable_backup(context, token, dest_volume, dest_token, confirmed, progress=lambda *unused: None):
    context.confirm(confirmed)
    fs.require_hash(token, 'expected-volume-token')
    fs.require_hash(dest_token, 'expected-destination-token')
    portable_volume(dest_volume)
    admitted(context.volume('userdata', token), writing=dest_volume == 'userdata')
    base = '/media/0' if dest_volume == 'userdata' else ''
    with fs.PinnedVolume(context, 'userdata', token) as source, source.directory('/media/0') as media, \
            fs.PinnedVolume(context, dest_volume, dest_token, writing=True) as target, target.directory(base) as root:
        with contextlib.suppress(FileExistsError):
            os.mkdir(PORTABLE_STORE, 0o700, dir_fd=root)
            os.fsync(root)
        path = base + '/' + PORTABLE_STORE
        with target.directory(path) as parent:
            if dest_volume == 'userdata':
                same_policy(context, media, parent)
            capacity(parent)
            stamp = time.strftime('%Y%m%d-%H%M%S', time.gmtime())
            name = 'android-media-' + stamp + '-' + os.urandom(8).hex() + '.tar.gz'
            partial = '.' + name + '.partial'
            out = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                target.check_fd(out)
                if dest_volume == 'userdata':
                    same_policy(context, media, out)
                checked_at = 0

                def report(done, count):
                    nonlocal checked_at
                    if done - checked_at >= 64 << 20:
                        capacity(parent)
                        checked_at = done
                    progress(done, count)

                records, skipped = portable_write(source, media, out, report)
                os.fsync(out)
                capacity(parent)
                before = identity(os.fstat(out))
                digest = file_sha(out)
                checked, total = portable_read(out)
                require(checked == records and identity(os.stat(partial, dir_fd=parent, follow_symlinks=False)) == before
                        and identity(os.fstat(out)) == before, 'ARCHIVE_DAMAGED', 'Portable archive readback differs from the source')
                source.recheck()
                target.recheck()
                admitted(context.volume('userdata', token), writing=dest_volume == 'userdata')
                fs.rename_noreplace(parent, partial, parent, name)
                os.fsync(parent)
            except BaseException:
                own = os.fstat(out)
                owned_unlink(parent, partial, (own.st_dev, own.st_ino))
                os.fsync(parent)
                raise
            finally:
                os.close(out)
    return {**portable_result(dest_volume, path + '/' + name, before[5], digest, records, total),
            'skipped': skipped}


@contextlib.contextmanager
def portable_open(context, volume, token, path, suffix='.tar.gz'):
    fs.require_hash(token, 'expected-volume-token')
    portable_volume(volume)
    clean = fs.clean_path(path)
    require(clean.lower().endswith(suffix) and (volume != 'userdata' or clean.startswith('/media/0/')),
            'INVALID_ARCHIVE_PATH', 'Choose a ' + suffix + ' archive on the selected volume')
    if volume == 'userdata':
        admitted(context.volume(volume, token))
    with fs.PinnedVolume(context, volume, token) as pin, pin.parent(clean) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            pin.check_fd(fd)
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_size > 0, 'NOT_AN_ARCHIVE', 'A regular portable archive is required')

            def recheck():
                pin.recheck()
                require(identity(os.fstat(fd)) == identity(before)
                        and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before),
                        'SOURCE_CHANGED', 'The selected portable archive changed')

            yield fd, before.st_size, clean, recheck
        finally:
            os.close(fd)


def portable_inspect(context, volume, token, path):
    with portable_open(context, volume, token, path) as (fd, size, clean, recheck):
        digest = file_sha(fd)
        records, total = portable_read(fd)
        recheck()
    require(records, 'NOTHING_SELECTED', 'The portable archive is empty')
    return portable_result(volume, clean, size, digest, records, total)


def portable_restore(context, volume, token, path, expected_sha, target_token, confirmed, progress=lambda *unused: None):
    context.confirm(confirmed)
    fs.require_hash(expected_sha, 'expected-sha256')
    fs.require_hash(target_token, 'expected-target-token')
    admitted(context.volume('userdata', target_token), True)
    with portable_open(context, volume, token, path) as (fd, size, clean, recheck):
        require(file_sha(fd) == expected_sha, 'ARCHIVE_SHA_MISMATCH', 'The portable archive differs from the reviewed copy')
        records, total = portable_read(fd)
        require(records, 'NOTHING_SELECTED', 'The portable archive is empty')
        recheck()

        def extract(write_entry):
            checked, _ = portable_read(fd, write_entry)
            require(checked == records, 'SOURCE_CHANGED', 'The archive payload changed during restore')

        folder = restore_media_folder(context, target_token, 'Restored-Android-' + expected_sha[:24],
                                      total, extract, recheck, progress)
    return {**portable_result(volume, clean, size, expected_sha, records, total), 'folder': folder}


def restore_media_folder(context, target_token, final, total, extract, recheck, progress):
    """Publish shared files under target ownership and fscrypt policy after the reader verifies the stream."""
    with fs.PinnedVolume(context, 'userdata', target_token, writing=True) as target, target.directory('/media/0') as media:
        capacity(media, total)
        owner = os.fstat(media)
        label = None if fixture(context) else os.getxattr(media, 'security.selinux')
        with contextlib.suppress(FileNotFoundError):
            os.stat(final, dir_fd=media, follow_symlinks=False)
            fs.fail('DESTINATION_EXISTS', 'This portable archive already has a folder in shared storage')
        partial = '.a22x-restore-' + os.urandom(12).hex()
        os.mkdir(partial, 0o700, dir_fd=media)
        root = None
        directories = []
        done = count = 0

        @contextlib.contextmanager
        def directory_from_root(parts):
            parent = os.dup(root)
            try:
                for part in parts:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    os.close(parent)
                    parent = child
                    target.check_fd(parent)
                yield parent
            finally:
                os.close(parent)

        def set_metadata(entry, directory, mtime):
            current = os.fstat(entry)
            if (current.st_uid, current.st_gid) != (owner.st_uid, owner.st_gid):
                os.fchown(entry, owner.st_uid, owner.st_gid)
            if label is not None:
                os.setxattr(entry, 'security.selinux', label)
            os.fchmod(entry, 0o775 if directory else 0o664)
            os.utime(entry, (mtime, mtime))
            os.fsync(entry)

        def write_entry(parts, item, payload):
            nonlocal count, done
            name = parts[-1]
            with directory_from_root(parts[:-1]) as parent:
                if item.isdir():
                    os.mkdir(name, 0o700, dir_fd=parent)
                    directories.append((parts, item.mtime))
                else:
                    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                    try:
                        while payload.count < item.size:
                            chunk = exact(payload, min(item.size - payload.count, CHUNK))
                            pa.write_all(out, chunk)
                            progress(done + payload.count, count)
                        set_metadata(out, False, item.mtime)
                    finally:
                        os.close(out)
                    done += item.size
                count += 1

        try:
            root = os.open(partial, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=media)
            target.check_fd(root)
            same_policy(context, media, root)
            extract(write_entry)
            for directory, mtime in reversed(directories):
                with directory_from_root(directory) as child:
                    set_metadata(child, True, mtime)
            recheck()
            target.recheck()
            admitted(context.volume('userdata', target_token), True)
            set_metadata(root, True, int(time.time()))
            named, opened = os.stat(partial, dir_fd=media, follow_symlinks=False), os.fstat(root)
            require((named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino),
                    'PARTIAL_IDENTITY_CHANGED', 'The prepared restore folder changed')
            fs.rename_noreplace(media, partial, media, final)
            os.fsync(media)
        finally:
            if root is not None:
                # Only remove the directory we created if it is still at the private name.
                with contextlib.suppress(FileNotFoundError):
                    named, opened = os.stat(partial, dir_fd=media, follow_symlinks=False), os.fstat(root)
                    if (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino):
                        shutil.rmtree(partial, dir_fd=media)
                        os.fsync(media)
                os.close(root)
    return '/media/0/' + final


def parser():
    p = fs.Parser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--device', action='store_true')
    mode.add_argument('--fixture')
    commands = p.add_subparsers(dest='operation', required=True, parser_class=fs.Parser)
    commands.add_parser('inspect')
    backup_parser = commands.add_parser('backup')
    backup_parser.add_argument('--expected-volume-token', required=True)
    backup_parser.add_argument('--confirm', action='store_true')
    verify_parser = commands.add_parser('verify')
    verify_parser.add_argument('--path', required=True)
    verify_parser.add_argument('--expected-volume-token', required=True)
    verify_parser.add_argument('--expected-sha256', required=True)
    portable = commands.add_parser('media-backup')
    portable.add_argument('--expected-volume-token', required=True)
    portable.add_argument('--destination-volume', required=True)
    portable.add_argument('--expected-destination-token', required=True)
    portable.add_argument('--confirm', action='store_true')
    for name in ('media-inspect', 'media-restore'):
        command = commands.add_parser(name)
        command.add_argument('--volume', required=True)
        command.add_argument('--expected-volume-token', required=True)
        command.add_argument('--path', required=True)
        if name == 'media-restore':
            command.add_argument('--expected-sha256', required=True)
            command.add_argument('--expected-target-token', required=True)
            command.add_argument('--confirm', action='store_true')
    return p


def main(argv=None):
    operation = 'unknown'
    try:
        args = parser().parse_args(argv)
        operation = args.operation
        context = fs.FixtureContext(args.fixture) if args.fixture else fs.DeviceContext()
        last = [0.0]
        def progress(done, count):
            now = time.monotonic()
            if now - last[0] >= 0.5:
                last[0] = now
                phase = operation if operation.startswith('media-') else 'android-data-backup'
                print(json.dumps({'event': 'progress', 'operation': phase, 'phase': phase,
                                  'bytes_done': done, 'entries_done': count}), file=sys.stderr, flush=True)
        with context.operation_lock():
            if operation == 'inspect':
                value = inspect(context)
            elif operation == 'backup':
                value = backup(context, args.expected_volume_token, args.confirm, progress)
            elif operation == 'verify':
                value = verify(context, args.path, args.expected_volume_token, args.expected_sha256)
            elif operation == 'media-backup':
                progress(0, 0)
                value = portable_backup(context, args.expected_volume_token, args.destination_volume,
                                        args.expected_destination_token, args.confirm, progress)
            elif operation == 'media-inspect':
                progress(0, 0)
                value = portable_inspect(context, args.volume, args.expected_volume_token, args.path)
            else:
                progress(0, 0)
                value = portable_restore(context, args.volume, args.expected_volume_token, args.path,
                                         args.expected_sha256, args.expected_target_token, args.confirm, progress)
        print(json.dumps({'ok': True, 'operation': operation, 'mode': context.mode, **value}, ensure_ascii=True, separators=(',', ':')))
        return 0
    except fs.FilesystemError as error:
        code, message = error.code, error.message
    except pa.ArchiveError as error:
        code, message = error.code, 'Archive compression is unavailable or failed'
    except OSError as error:
        code, message = 'IO_ERROR', 'Userdata could not be read or the archive could not be written (errno=%s)' % error.errno
    except (ValueError, tarfile.TarError, EOFError):
        code, message = 'ARCHIVE_DAMAGED', 'Archive data is malformed or truncated'
    print(json.dumps({'ok': False, 'operation': operation, 'error': {'code': code, 'message': message}}, separators=(',', ':')))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
