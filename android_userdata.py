#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""The whole of Android's userdata, copied to a card or a stick and put back (2026-11-21, the owner:
Android backup and restore, userdata included, as the first priority of the release).

For Android data that encrypts nothing (LineageOS 20 here: its fstab has no fileencryption), the copy
is the same archive as android_data's logical copy — zstd(PAX tar of payload/<path> with A22X.meta:
numeric owner, mode, mtime and every xattr, security.selinux included; fscrypt contexts never) and the
complete index last — but it lies on another volume, its index says restore_supported, and it can be
put back: into an empty, freshly formatted userdata, with every owner, mode, label, link and time as
they were. FBE data is refused: its files cannot be put back without the keys of the system that made
them, which a new format does not have.

    android_userdata.py --device backup  --volume userdata-token --dest-volume sdcard-p2 --dest-token T [--without-media] --confirm
    android_userdata.py --device verify  --volume sdcard-p2 --token T --path /A22xUserdataBackups/NAME --expected-sha256 SHA
    android_userdata.py --device restore --volume sdcard-p2 --token T --path ... --expected-sha256 SHA --target-token U --confirm
    android_userdata.py --device list    --volume sdcard-p2 --token T
"""
import base64
import contextlib
import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
import time

import android_data as ad
import filesystem as fs
import partition_archive as pa

STORE = 'A22xUserdataBackups'
PREFIX = 'userdata-'
SUFFIX = '.tar.zst'
# Without the user's shared files (photos, downloads): the copy of the system and the apps only.
MEDIA = 'media'


def require(value, code, message, **details):
    if not value:
        fs.fail(code, message, **details)


def exclusions(without_media):
    return list(ad.EXCLUDED) + ([MEDIA] if without_media else [])


def plain(context, volume):
    """Unencrypted Android data only (FBE cannot be put back into a new format)."""
    if context.mode == 'fixture':
        return volume.get('mounted') is True
    return ad.plain_open(volume)


def fresh_target(context, volume):
    """A userdata the recovery just formatted for this copy: f2fs or ext4, mounted for writing by Files,
    with no encryption policy on its root (2026-11-21, on the phone: a format without the encrypt feature
    is listed as a plain filesystem, not as Android data). Its emptiness is checked when it is pinned."""
    if volume.get('fs_type') not in ('f2fs', 'ext4') or volume.get('mount_owner') not in ('filesystem', None) \
            or not volume.get('mounted') or volume.get('read_only'):
        return False
    if context.mode == 'fixture':
        return True
    fd = os.open(fs.absolute_no_symlinks(volume['mountpoint']), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return fs.encryption_policy(fd) is not True  # no policy, or a filesystem without encryption at all
    finally:
        os.close(fd)


def store(pin, create):
    try:
        if create:
            os.mkdir(STORE, 0o700, dir_fd=pin.fd)
            os.fsync(pin.fd)
    except FileExistsError:
        pass
    fd = os.open(STORE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=pin.fd)
    pin.check_fd(fd)
    return fd


def backup(context, token, dest_volume, dest_token, confirmed, without_media=False, progress=lambda *unused: None):
    with context.operation_lock(shared=True):
        return _backup(context, token, dest_volume, dest_token, confirmed, without_media, progress)


def _backup(context, token, dest_volume, dest_token, confirmed, without_media=False, progress=lambda *unused: None):
    """backup() for a caller that holds the storage lease already (identity_backup's Android copy)."""
    context.confirm(confirmed)
    fs.require_hash(token, 'volume-token')
    fs.require_hash(dest_token, 'dest-token')
    require(dest_volume != 'userdata', 'DESTINATION_NOT_ALLOWED', 'Save userdata to a card or a stick: a format of userdata erases it')
    source = context.volume('userdata', token)
    require(plain(context, source), 'USERDATA_ENCRYPTED',
            'This copy is for Android data that is not encrypted: an encrypted one cannot be put back into a new format')
    excluded = exclusions(without_media)
    with fs.PinnedVolume(context, 'userdata', token) as pin, \
            fs.PinnedVolume(context, dest_volume, dest_token, writing=True) as dest:
        parent = store(dest, True)
        try:
            entries, skipped = ad.scan(pin, excluded)
            ad.capacity(parent, ad.worst_case(entries))
            final = PREFIX + time.strftime('%Y%m%d-%H%M%S', time.gmtime()) + '-' + os.urandom(4).hex() + SUFFIX
            partial = '.' + final + '.partial-' + os.urandom(8).hex()
            out = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            ident = (os.fstat(out).st_dev, os.fstat(out).st_ino)
            try:
                dest.check_fd(out)
                manifest = ad.write_archive(pin, out, entries, skipped, progress, capacity_fd=parent, full_exclusions=excluded)
                os.fsync(out)
                digest, size = ad.file_sha(out), os.fstat(out).st_size
                os.lseek(out, 0, os.SEEK_SET)
                checked = ad.verify_stream(out, ad.FULL_SCHEMA, excluded)
                require(checked['counts'] == manifest['counts'], 'ARCHIVE_DAMAGED', 'The copy read back differs')
                dest.recheck()
                ad.publish(parent, partial, final, ident)
                # Beside it, what a list shows without reading the copy: its hash, sizes and date.
                facts = {'schema': 'a22x.android-userdata.facts.v1', 'sha256': digest, 'bytes': size,
                         'counts': manifest['counts'], 'created_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(manifest['created'])),
                         'without_media': without_media}
                side = os.open(final + '.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                try:
                    os.write(side, json.dumps(facts, sort_keys=True).encode())
                    os.fsync(side)
                finally:
                    os.close(side)
                os.fsync(parent)
            except BaseException:
                with contextlib.suppress(OSError, fs.FilesystemError):
                    ad.owned_unlink(parent, partial, ident)
                    os.fsync(parent)
                raise
            finally:
                os.close(out)
        finally:
            os.close(parent)
    return {'archive': {'volume': dest_volume, 'path': '/' + STORE + '/' + final, 'bytes': size, 'sha256': digest},
            'verified': True, 'counts': manifest['counts'], 'skipped': manifest['skipped'],
            'without_media': without_media, 'restore_supported': True}


@contextlib.contextmanager
def archive_fd(context, volume, token, path):
    fs.require_hash(token, 'volume-token')
    clean = fs.clean_path(path)
    require(clean.startswith('/' + STORE + '/' + PREFIX) and clean.endswith(SUFFIX) and clean.count('/') == 2,
            'NOT_A_USERDATA_COPY', 'Choose a copy from ' + STORE)
    with fs.PinnedVolume(context, volume, token) as pin:
        parent = store(pin, False)
        try:
            fd = os.open(clean.rsplit('/', 1)[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            pin.check_fd(fd)
            yield fd
        finally:
            os.close(fd)


def read_manifest(fd, expected_sha):
    """The full SHA, then the whole stream checked as android_data checks it; the index it ends with."""
    fs.require_hash(expected_sha, 'expected-sha256')
    require(ad.file_sha(fd) == expected_sha, 'ARCHIVE_SHA_MISMATCH', 'The copy differs from the one chosen')
    for excluded in (exclusions(False), exclusions(True)):
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            return ad.verify_stream(fd, ad.FULL_SCHEMA, excluded), excluded
        except fs.FilesystemError as exc:
            if exc.code != 'ARCHIVE_DAMAGED' or excluded == exclusions(True):
                raise
    fs.fail('ARCHIVE_DAMAGED', 'The copy is damaged')


def verify(context, volume, token, path, expected_sha):
    with context.operation_lock(shared=True):
        return _verify(context, volume, token, path, expected_sha)


def _verify(context, volume, token, path, expected_sha):
    with archive_fd(context, volume, token, path) as fd:
        manifest, excluded = read_manifest(fd, expected_sha)
    return {'verified': True, 'counts': manifest['counts'], 'without_media': MEDIA in excluded,
            'created': manifest.get('created'), 'source': manifest.get('source')}


def listing(context, volume, token):
    fs.require_hash(token, 'volume-token')
    with fs.PinnedVolume(context, volume, token) as pin:
        try:
            parent = store(pin, False)
        except FileNotFoundError:
            return {'copies': []}
        try:
            names = sorted((n for n in os.listdir(parent) if n.startswith(PREFIX) and n.endswith(SUFFIX)), reverse=True)
            rows = []
            for name in names[:64]:
                row = {'path': '/' + STORE + '/' + name, 'bytes': os.stat(name, dir_fd=parent, follow_symlinks=False).st_size}
                try:
                    side = os.open(name + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    try:
                        facts = json.loads(os.read(side, 1 << 16))
                    finally:
                        os.close(side)
                    if facts.get('bytes') == row['bytes'] and len(str(facts.get('sha256', ''))) == 64:
                        row.update(sha256=facts['sha256'], counts=facts.get('counts'), created_utc=facts.get('created_utc'),
                                   without_media=bool(facts.get('without_media')))
                except (OSError, ValueError):
                    pass
                rows.append(row)
            return {'copies': rows}
        finally:
            os.close(parent)


def delete(context, volume, token, path, expected_sha, confirmed):
    """One copy and its facts, as identity_backup deletes a copy of partitions."""
    context.confirm(confirmed)
    with archive_fd(context, volume, token, path) as fd:
        require(ad.file_sha(fd) == expected_sha, 'BACKUP_CHANGED', 'The copy changed after it was listed')
    name = fs.clean_path(path).rsplit('/', 1)[1]
    with fs.PinnedVolume(context, volume, token, writing=True) as pin:
        parent = store(pin, False)
        try:
            os.unlink(name, dir_fd=parent)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(name + '.json', dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
    return {'deleted': fs.clean_path(path)}


def empty_target(pin):
    """A freshly formatted userdata: nothing but lost+found in its root."""
    names = [n for n in os.listdir(pin.fd) if n != 'lost+found']
    require(not names, 'USERDATA_NOT_EMPTY', 'Format Android data first: the copy is put back into an empty userdata',
            found=sorted(names)[:8])


def apply_meta(fd, meta, label_first=False):
    """Owner, mode, xattrs and time of an open file or folder, as the copy says (chown before chmod: it
    clears set-id bits)."""
    os.fchown(fd, meta['uid'], meta['gid'])
    os.fchmod(fd, meta['mode'])
    for key, value in meta['xattrs'].items():
        os.setxattr(fd, key, base64.b64decode(value))
    os.utime(fd, ns=(meta['mtime_ns'], meta['mtime_ns']))


def restore(context, volume, token, path, expected_sha, target_token, confirmed, progress=lambda *unused: None):
    with context.operation_lock():
        return _restore(context, volume, token, path, expected_sha, target_token, confirmed, progress)


def _restore(context, volume, token, path, expected_sha, target_token, confirmed, progress=lambda *unused: None):
    context.confirm(confirmed)
    fs.require_hash(target_token, 'target-token')
    target = context.volume('userdata', target_token)
    # Not mounted for writing is said as such (2026-11-22, live: a fresh F2FS not mounted yet was refused as
    # USERDATA_ENCRYPTED, which sent the owner after the wrong problem).
    require(target.get('mounted') and not target.get('read_only'), 'USERDATA_NOT_MOUNTED',
            'Mount userdata for writing in Files first, then put the copy back')
    require(plain(context, target) or fresh_target(context, target), 'USERDATA_ENCRYPTED',
            'Put the copy back only into unencrypted, freshly formatted Android data mounted for writing')
    with archive_fd(context, volume, token, path) as fd:
        manifest, excluded = read_manifest(fd, expected_sha)
        expected = {e['path']: e for e in manifest['entries']}
        with fs.PinnedVolume(context, 'userdata', target_token, writing=True) as pin:
            empty_target(pin)
            written, folders, done = {}, [], [0]
            os.lseek(fd, 0, os.SEEK_SET)
            proc = subprocess.Popen([pa.zstd_path(), '-q', '-d', '-c'], stdin=fd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                with tarfile.open(fileobj=proc.stdout, mode='r|', format=tarfile.PAX_FORMAT) as tar:
                    for item in tar:
                        if item.name == ad.MANIFEST:
                            continue
                        meta = ad.payload_meta(item.pax_headers['A22X.meta'].encode(), excluded)
                        require(expected.get(meta['path'], {}).get('type') == meta['type'], 'ARCHIVE_DAMAGED', 'An entry is not in the index')
                        folder, _, name = meta['path'].rpartition('/')
                        with fs.tree_directory(pin, pin.fd, folder) as parent:
                            if meta['type'] == 'directory':
                                os.mkdir(name, 0o700, dir_fd=parent)
                                folders.append(meta)
                            elif meta['type'] == 'file':
                                out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                                try:
                                    pin.check_fd(out)
                                    digest, source = hashlib.sha256(), tar.extractfile(item)
                                    while chunk := source.read(1 << 20):
                                        digest.update(chunk)
                                        view = memoryview(chunk)
                                        while view:
                                            view = view[os.write(out, view):]
                                        done[0] += len(chunk)
                                        progress(done[0], manifest['counts']['file_bytes'])
                                    written[meta['path']] = digest.hexdigest()
                                    apply_meta(out, meta)
                                finally:
                                    os.close(out)
                            elif meta['type'] == 'hardlink':
                                link_folder, _, link_name = meta['link'].rpartition('/')
                                with fs.tree_directory(pin, pin.fd, link_folder) as source_dir:
                                    os.link(link_name, name, src_dir_fd=source_dir, dst_dir_fd=parent, follow_symlinks=False)
                            else:
                                os.symlink(meta['link'], name, dir_fd=parent)
                                os.chown(name, meta['uid'], meta['gid'], dir_fd=parent, follow_symlinks=False)
                                for key, value in meta['xattrs'].items():
                                    os.setxattr(f'/proc/self/fd/{parent}/{name}', key, base64.b64decode(value), follow_symlinks=False)
                                os.utime(name, ns=(meta['mtime_ns'], meta['mtime_ns']), dir_fd=parent, follow_symlinks=False)
                require(proc.wait() == 0, 'ARCHIVE_DAMAGED', 'The copy could not be read to its end')
                # Folders last, deepest first: their times stay as the copy says once nothing is added in them.
                for meta in reversed(folders):
                    with fs.tree_directory(pin, pin.fd, meta['path']) as folder_fd:
                        apply_meta(folder_fd, meta)
                root = manifest['root']
                apply_meta(pin.fd, dict(root, path='/'))
                os.sync()
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
            # Every file as its copy hashed it, and the whole tree as the index lists it, read back.
            wrong = [e['path'] for e in manifest['entries'] if e['type'] == 'file' and written.get(e['path']) != e.get('sha256')]
            require(not wrong, 'RESTORE_MISMATCH', 'Files differ from the copy; format Android data and put it back again', files=wrong[:8])
            back, _ = ad.scan(pin, excluded)
            keys = ('path', 'type', 'mode', 'uid', 'gid', 'size', 'xattrs', 'link')
            seen = [{k: e['meta'].get(k) for k in keys} for e in back]
            # A hardlink reads back as the file it shares: its owner, mode, size and labels are that file's.
            want = [dict({k: expected[e['link']].get(k) for k in keys}, path=e['path']) if e['type'] == 'hardlink'
                    else {k: e.get(k) for k in keys} for e in manifest['entries']]
            require(sorted(seen, key=lambda r: r['path']) == sorted(want, key=lambda r: r['path']),
                    'RESTORE_MISMATCH', 'Restored metadata differs from the copy; format Android data and put it back again')
            pin.recheck()
    return {'restored': True, 'counts': manifest['counts'], 'without_media': MEDIA in excluded,
            'note': 'Start Android: it finds its data as it was when the copy was made'}


def main(argv=None):
    p = fs.Parser(description=__doc__)
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--device', action='store_true')
    modes.add_argument('--fixture')
    commands = p.add_subparsers(dest='operation', required=True, parser_class=fs.Parser)
    sub = commands.add_parser('backup')
    sub.add_argument('--volume-token', required=True)
    sub.add_argument('--dest-volume', required=True)
    sub.add_argument('--dest-token', required=True)
    sub.add_argument('--without-media', action='store_true')
    sub.add_argument('--confirm', action='store_true')
    for name in ('verify', 'restore'):
        sub = commands.add_parser(name)
        sub.add_argument('--volume', required=True)
        sub.add_argument('--token', required=True)
        sub.add_argument('--path', required=True)
        sub.add_argument('--expected-sha256', required=True)
        if name == 'restore':
            sub.add_argument('--target-token', required=True)
            sub.add_argument('--confirm', action='store_true')
    sub = commands.add_parser('list')
    sub.add_argument('--volume', required=True)
    sub.add_argument('--token', required=True)
    operation = 'unknown'
    last = [0.0]

    def progress(done, total):
        now = time.monotonic()
        if now - last[0] >= 0.5:
            last[0] = now
            with contextlib.suppress(OSError, ValueError):
                print(json.dumps({'event': 'progress', 'bytes_done': done, 'bytes_total': total}), file=sys.stderr, flush=True)
    try:
        args = p.parse_args(argv)
        operation = args.operation
        context = fs.FixtureContext(args.fixture) if args.fixture else fs.DeviceContext()
        if operation == 'backup':
            result = backup(context, args.volume_token, args.dest_volume, args.dest_token, args.confirm, args.without_media,
                            lambda done, entries: progress(done, 0))
        elif operation == 'verify':
            result = verify(context, args.volume, args.token, args.path, args.expected_sha256)
        elif operation == 'restore':
            result = restore(context, args.volume, args.token, args.path, args.expected_sha256, args.target_token, args.confirm, progress)
        else:
            result = listing(context, args.volume, args.token)
        print(json.dumps({'ok': True, 'operation': operation, 'mode': context.mode, **result}, ensure_ascii=True, separators=(',', ':')))
        return 0
    except fs.FilesystemError as exc:
        error = {'code': exc.code, 'message': exc.message, 'details': exc.details}
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as exc:
        error = {'code': 'USERDATA_COPY_FAILED', 'message': str(exc), 'details': {}}
    print(json.dumps({'ok': False, 'operation': operation, 'error': error}, ensure_ascii=True, separators=(',', ':')))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
