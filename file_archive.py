#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Files and folders into one archive, and out of it again (2026-11-13).

The owner asked for backups made in the interface, without commands: some files, some folders, and
moving them from one A22x to another. Chosen in Files (a long press, then "Archive"), they go into
NAME.tar.zst on a card or a stick, the same form as the copies of Android (partition_archive.py):

    zstd( tar: the chosen entries, with their folders, as they are named in their folder )
    skippable frame 0x184D2A5E: manifest.json | u64 its length | b'a22xtar1'

The tar keeps owners, permissions, times and symbolic links as links; so the archive opens on any
computer with `tar --zstd -xf NAME.tar.zst`, and on another phone in Files ("Extract here"). The
manifest after the stream says what is inside without unpacking it.

Read by directory descriptors from the pinned volume: a symbolic link is stored as a link and never
followed, another mounted filesystem inside a folder is left out, and sockets are skipped. Unpacked
into a new folder beside the archive with tarfile's 'tar' filter: no absolute name, nothing outside
that folder, no set-user-id bits; an existing folder is never written into.
"""
import argparse
import contextlib
import errno
import io
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time

import archive_crypt as ac
import filesystem as fs
import partition_archive as pa
from filesystem import fail


def require(condition, code, message, **details):
    if not condition:
        fail(code, message, **details)

SCHEMA = 'a22x.files.v1'
SUFFIXES = ('.tar.zst.enc', '.tar.zst', '.tar.gz', '.tar.xz', '.tgz', '.tar')
STORE = 'A22xArchives'
CHUNK = 1 << 20
MAX_ENTRIES = 1 << 20


def archive_stem(name):
    lower = name.lower()
    for suffix in SUFFIXES:
        if lower.endswith(suffix) and len(name) > len(suffix):
            return name[:-len(suffix)]
    return None


def chosen_names(directory, everything, names):
    present = sorted(os.listdir(directory))
    if everything:
        left_out = set(names)
        return [name for name in present if name not in left_out]
    missing = [name for name in names if name not in present]
    require(not missing, 'SELECTION_CHANGED', 'A selected entry is no longer in this folder', missing=missing[:8])
    return list(dict.fromkeys(names))


def walk(directory, name, device, arcname, out):
    """(dir fd, name, lstat, archive name) for NAME and, for a folder, everything under it on the same
    filesystem. A folder is opened by descriptor; a link inside it is never followed."""
    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if stat.S_ISSOCK(info.st_mode):
        return
    out.append((directory, name, info, arcname))
    require(len(out) <= MAX_ENTRIES, 'SELECTION_TOO_LARGE', 'Too many files are selected at once')
    if stat.S_ISDIR(info.st_mode) and info.st_dev == device:
        inner = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        out.append((inner, None, None, None))  # closed after the archive is written
        for child in sorted(os.listdir(inner)):
            walk(inner, child, device, arcname + '/' + child, out)


def tar_info(directory, name, info, arcname):
    item = tarfile.TarInfo(arcname)
    item.mode, item.uid, item.gid, item.mtime = stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, int(info.st_mtime)
    if stat.S_ISREG(info.st_mode):
        item.type, item.size = tarfile.REGTYPE, info.st_size
    elif stat.S_ISDIR(info.st_mode):
        item.type = tarfile.DIRTYPE
    elif stat.S_ISLNK(info.st_mode):
        item.type, item.linkname = tarfile.SYMTYPE, os.readlink(name, dir_fd=directory)
    elif stat.S_ISFIFO(info.st_mode):
        item.type = tarfile.FIFOTYPE
    elif stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
        item.type = tarfile.CHRTYPE if stat.S_ISCHR(info.st_mode) else tarfile.BLKTYPE
        item.devmajor, item.devminor = os.major(info.st_rdev), os.minor(info.st_rdev)
    else:
        return None
    return item


def destination_name(path):
    clean = fs.clean_path(path)
    folder, _, name = clean.rpartition('/')
    require(name.lower().endswith(('.tar.zst', '.tar.zst.enc')) and len(name) > 8, 'INVALID_DESTINATION',
            'The archive name must end in .tar.zst')
    # 2026-11-13: protected with a password, it is named for what it is.
    if pa.ENCRYPT and pa.PASSWORD and not name.lower().endswith('.enc'):
        name += ac.SUFFIX
    return folder, name


def pack(context, volume, token, path, everything, names, dest_volume, dest_token, destination, confirmed, progress):
    context.confirm(confirmed)
    folder = fs.clean_path(path)
    dest_folder, dest_name = destination_name(destination)
    opened, entries = [], []
    with fs.PinnedVolume(context, volume, token) as source, source.directory(folder) as directory:
        try:
            for name in chosen_names(directory, everything, names):
                walk(directory, name, source.stat.st_dev, name, entries)
            files = [e for e in entries if e[1] is not None]
            opened = [e[0] for e in entries if e[1] is None]
            require(files, 'NOTHING_SELECTED', 'Nothing is selected')
            total = sum(e[2].st_size for e in files if stat.S_ISREG(e[2].st_mode))
            source_label = source.volume.get('label') or volume
            with fs.PinnedVolume(context, dest_volume, dest_token, writing=True) as target:
                with target.directory('') as root:
                    parent = root
                    for part in fs.path_parts(dest_folder):
                        with contextlib.suppress(FileExistsError):
                            os.mkdir(part, 0o755, dir_fd=parent)
                        nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                        if parent != root:
                            os.close(parent)
                        parent = nxt
                    try:
                        target.check_fd(parent)
                        with contextlib.suppress(FileNotFoundError):
                            os.stat(dest_name, dir_fd=parent, follow_symlinks=False)
                            fail('DESTINATION_EXISTS', 'An existing destination will not be overwritten')
                        part_name = '.part-' + dest_name
                        with contextlib.suppress(FileNotFoundError):
                            os.unlink(part_name, dir_fd=parent)
                        out = os.open(part_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644,
                                      dir_fd=parent)
                        try:
                            crypt = contextlib.ExitStack()
                            dest = crypt.enter_context(ac.sink(out, pa.PASSWORD if pa.ENCRYPT else None))
                            done = write_archive(dest, files, total, progress)
                            manifest = json.dumps({'schema': SCHEMA, 'source': {'volume': volume, 'label': source_label,
                                                   'folder': folder}, 'created': int(time.time()), 'entries': len(files),
                                                   'bytes': done, 'top': sorted({e[3].split('/')[0] for e in files})[:64]},
                                                  ensure_ascii=False, separators=(',', ':')).encode()
                            footer(dest, manifest)
                            crypt.close()
                            os.fsync(out)
                            size = os.fstat(out).st_size
                        except BaseException as error:
                            with contextlib.suppress(BaseException):
                                crypt.__exit__(type(error), error, None)
                            os.close(out)
                            with contextlib.suppress(OSError):
                                os.unlink(part_name, dir_fd=parent)
                            raise
                        os.close(out)
                        os.rename(part_name, dest_name, src_dir_fd=parent, dst_dir_fd=parent)
                        os.fsync(parent)
                    finally:
                        if parent != root:
                            os.close(parent)
        finally:
            for fd in opened:
                with contextlib.suppress(OSError):
                    os.close(fd)
    return {'archive': {'volume': dest_volume, 'path': (dest_folder.rstrip('/') + '/' + dest_name) if dest_folder else '/' + dest_name,
                        'bytes': size}, 'entries': len(files), 'bytes': done}


class Pipe:
    """The tar stream into zstd's stdin, as a file object for tarfile."""

    def __init__(self, fd):
        self.fd = fd

    def write(self, data):
        pa.write_all(self.fd, data)
        return len(data)


def write_archive(out, files, total, progress, extra=()):
    """FILES as walk() lists them, after EXTRA: (archive name, bytes, mode) made in memory."""
    proc = subprocess.Popen([pa.zstd_path(), '-q', '-%d' % pa.LEVEL, '-T0', '-c'], stdin=subprocess.PIPE, stdout=out,
                            stderr=subprocess.PIPE, bufsize=0)
    done = 0
    try:
        with tarfile.open(fileobj=Pipe(proc.stdin.fileno()), mode='w|', format=tarfile.PAX_FORMAT, bufsize=CHUNK) as tar:
            for name, data, mode in extra:
                item = tarfile.TarInfo(name)
                item.size, item.mode, item.mtime = len(data), mode, int(time.time())
                tar.addfile(item, io.BytesIO(data))
            for directory, name, info, arcname in files:
                item = tar_info(directory, name, info, arcname)
                if item is None:
                    continue
                if item.type != tarfile.REGTYPE:
                    tar.addfile(item)
                    continue
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                try:
                    now = os.fstat(fd)
                    require(now.st_ino == info.st_ino and now.st_size == info.st_size, 'FILE_CHANGED',
                            'A file changed while it was archived', file=arcname)
                    with os.fdopen(os.dup(fd), 'rb', buffering=0) as stream:
                        counted = Counted(stream, lambda n: progress(done + n, total, arcname))
                        tar.addfile(item, counted)
                    done += info.st_size
                finally:
                    os.close(fd)
                progress(done, total, arcname)
        proc.stdin.close()
        said = proc.stderr.read().decode(errors='replace').strip()[-200:]
        if proc.wait() != 0:
            fail('ARCHIVE_WRITE_FAILED', 'The archive could not be written', said=said)
    except OSError as error:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        if error.errno == errno.ENOSPC or error.errno == errno.EPIPE:
            fail('INSUFFICIENT_SPACE', 'There is not enough space for the archive')
        raise
    except BaseException:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        raise
    finally:
        with contextlib.suppress(OSError, ValueError):
            proc.stdin.close()
        proc.stderr.close()
    return done


class Counted:
    def __init__(self, stream, report):
        self.stream, self.report, self.seen, self.last = stream, report, 0, 0.0

    def read(self, size=-1):
        data = self.stream.read(size)
        self.seen += len(data)
        now = time.monotonic()
        if now - self.last >= 0.25:
            self.report(self.seen)
            self.last = now
        return data


def footer(out, manifest):
    """The manifest after zstd's stream; OUT is the file, or the pipe into the cipher."""
    with contextlib.suppress(OSError):
        os.lseek(out, 0, os.SEEK_END)
    payload = manifest + struct.pack('<Q', len(manifest)) + pa.TRAILER
    pa.write_all(out, struct.pack('<II', pa.SKIPPABLE, len(payload)) + payload)
    with contextlib.suppress(OSError):
        os.fsync(out)


def decompressor(name):
    lower = name.lower()
    if lower.endswith(('.tar.zst', '.tar.zst.enc')):
        return [pa.zstd_path(), '-q', '-d', '-c']
    if lower.endswith(('.tar.gz', '.tgz')):
        return ['gzip', '-dc']
    if lower.endswith('.tar.xz'):
        return ['xz', '-dc']
    return None


def unpack(context, volume, token, path, confirmed, progress):
    """The archive at PATH into a new folder beside it, named after it."""
    context.confirm(confirmed)
    clean = fs.clean_path(path)
    folder, _, name = clean.rpartition('/')
    stem = archive_stem(name)
    require(stem, 'NOT_AN_ARCHIVE', 'This file is not a tar archive')
    with fs.PinnedVolume(context, volume, token, writing=True) as pin, pin.directory(folder) as directory:
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            require(stat.S_ISREG(os.fstat(source).st_mode), 'NOT_AN_ARCHIVE', 'This file is not a tar archive')
            total = os.fstat(source).st_size
            try:
                os.mkdir(stem, 0o755, dir_fd=directory)
            except FileExistsError:
                fail('DESTINATION_EXISTS', 'A folder named as the archive is already here', folder=stem)
            target = os.open(stem, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            try:
                pin.check_fd(target)
                count = extract(source, total, name, '/proc/self/fd/%d' % target, progress)
            except BaseException:
                # Nothing half-unpacked is left behind (2026-11-13: an archive whose password was
                # not given left its empty folder, and the next try found it in the way).
                shutil.rmtree(stem, dir_fd=directory, ignore_errors=True)
                raise
            finally:
                os.close(target)
        finally:
            os.close(source)
        os.fsync(directory)
    return {'folder': (folder.rstrip('/') + '/' + stem) if folder else '/' + stem, 'entries': count}


def extract(source, total, name, destination, progress):
    command = decompressor(name)
    os.lseek(source, 0, os.SEEK_SET)
    crypt = contextlib.ExitStack()
    plain = source
    if ac.is_encrypted(source):
        # Checked whole before one file of it is unpacked.
        key = ac.open_key(source, pa.PASSWORD)
        try:
            ac.verify(source, key, lambda done, size: progress(done // 2, size, ''))
        finally:
            key.close()
        plain = crypt.enter_context(ac.source(source, pa.PASSWORD))
    proc = subprocess.Popen(command, stdin=plain, stdout=subprocess.PIPE, stderr=subprocess.PIPE) if command else None
    stream = proc.stdout if proc else os.fdopen(os.dup(source), 'rb')
    count, finished = 0, False
    try:
        with tarfile.open(fileobj=stream, mode='r|', bufsize=CHUNK) as tar:
            for member in tar:
                # 'tar': no absolute name, nothing outside the folder, no set-user-id bits.
                # Owners as numbers: the names of another system mean nothing in this recovery.
                tar.extract(member, destination, numeric_owner=True, filter='tar')
                count += 1
                if count % 64 == 0:
                    progress(os.lseek(source, 0, os.SEEK_CUR), total, member.name)
        finished = True
        if proc:
            while proc.stdout.read(CHUNK):
                pass
    except tarfile.FilterError as error:
        fail('ARCHIVE_UNSAFE', 'The archive holds an entry that would land outside its folder', reason=str(error)[:200])
    except (tarfile.TarError, EOFError) as error:
        fail('ARCHIVE_DAMAGED', 'The archive is damaged', reason=str(error)[:200])
    finally:
        if proc:
            if not finished and proc.poll() is None:
                proc.kill()
            proc.stdout.close()
            said = proc.stderr.read().decode(errors='replace').strip()[-200:]
            proc.stderr.close()
            code = proc.wait()
        else:
            stream.close()
            code, said = 0, ''
        with contextlib.suppress(ac.CryptError):
            crypt.close()
    if code != 0:
        fail('ARCHIVE_DAMAGED', 'The archive is damaged', said=said)
    progress(total, total, '')
    return count


def manifest_of(context, volume, token, path):
    clean = fs.clean_path(path)
    folder, _, name = clean.rpartition('/')
    with fs.PinnedVolume(context, volume, token) as pin, pin.directory(folder) as directory:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            data = pa.footer(fd)
        finally:
            os.close(fd)
    if data is None:
        return {'manifest': None}
    try:
        value = json.loads(data.decode('utf-8'))
    except ValueError:
        return {'manifest': None}
    return {'manifest': value if isinstance(value, dict) and value.get('schema') == SCHEMA else None}


def parser():
    p = fs.Parser(description=__doc__)
    kind = p.add_mutually_exclusive_group(required=True)
    kind.add_argument('--device', action='store_true')
    kind.add_argument('--fixture')
    commands = p.add_subparsers(dest='operation', required=True, parser_class=fs.Parser)
    for name in ('pack', 'unpack', 'inspect'):
        command = commands.add_parser(name)
        command.add_argument('--volume', required=True)
        command.add_argument('--expected-volume-token')
        command.add_argument('--path', required=True)
        command.add_argument('--password-file')
        command.add_argument('--encrypt', action='store_true')
        if name != 'inspect':
            command.add_argument('--confirm', action='store_true')
        if name == 'pack':
            command.add_argument('--selection-file', required=True)
            command.add_argument('--destination-volume', required=True)
            command.add_argument('--expected-destination-volume-token')
            command.add_argument('--destination', required=True)
    return p


def main(argv=None):
    operation = 'unknown'
    try:
        args = parser().parse_args(argv)
        operation = args.operation
        context = fs.FixtureContext(args.fixture) if args.fixture else fs.DeviceContext()
        pa.PASSWORD = ac.read_password(args.password_file)
        pa.ENCRYPT = bool(args.encrypt)
        require(not pa.ENCRYPT or pa.PASSWORD, 'PASSWORD_REQUIRED', 'A protected archive needs a password')
        last = [0.0]

        def progress(done, total, label):
            now = time.monotonic()
            if now - last[0] >= 0.2 or done >= total:
                last[0] = now
                print(json.dumps({'event': 'progress', 'operation': 'files-' + operation,
                                  'phase': 'Packing' if operation == 'pack' else 'Unpacking', 'partition': label[-120:],
                                  'bytes_done': done, 'bytes_total': max(total, 1)}, separators=(',', ':')),
                      file=sys.stderr, flush=True)
        with context.operation_lock():
            if operation == 'pack':
                everything, names = fs.selection_file(args.selection_file)
                value = pack(context, args.volume, args.expected_volume_token, args.path, everything, names,
                             args.destination_volume, args.expected_destination_volume_token, args.destination,
                             args.confirm, progress)
            elif operation == 'unpack':
                value = unpack(context, args.volume, args.expected_volume_token, args.path, args.confirm, progress)
            else:
                value = manifest_of(context, args.volume, args.expected_volume_token, args.path)
        print(json.dumps({**value, 'ok': True, 'operation': operation, 'mode': context.mode}, ensure_ascii=True, separators=(',', ':')))
        return 0
    except fs.FilesystemError as exc:
        error = {'code': exc.code, 'message': exc.message, 'details': exc.details}
    except (pa.ArchiveError, ac.CryptError) as exc:
        error = {'code': exc.code, 'message': str(exc), 'details': {}}
    except OSError as exc:
        error = {'code': 'IO_ERROR', 'message': str(exc), 'details': {'errno': exc.errno}}
    print(json.dumps({'ok': False, 'operation': operation, 'error': error}, ensure_ascii=True, separators=(',', ':')))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
