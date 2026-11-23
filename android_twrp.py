#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Read-only review of TWRP/OrangeFox Data tar backup sets."""
import argparse
import contextlib
import gzip
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import time
import zlib

import android_data as ad
import filesystem as fs

ARCHIVE = re.compile(r'(data\.(f2fs|ext[234])\.win)([0-8][0-9]{2})?\Z')
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
EMPTY_BLOCK = bytes(512)
DIGESTS = {'.sha2': 'sha256', '.sha256': 'sha256', '.md5': 'md5', '.md5sum': 'md5'}
PACKAGE = re.compile(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+\Z')
APP_ROOTS = ('user/0/', 'user_de/0/', 'data/')
TWRP_METADATA = frozenset((b'TWRP.security.fscrypt', b'RHT.security.selinux', b'SCHILY.xattr.security.capability',
                          b'ANDROID.user.default', b'ANDROID.user.inode_cache', b'ANDROID.user.inode_code_cache'))
MARKERS = frozenset((b'ANDROID.user.default', b'ANDROID.user.inode_cache', b'ANDROID.user.inode_code_cache'))


def piece_set(names, base):
    pieces = sorted(name for name in names if ARCHIVE.fullmatch(name) and name.startswith(base))
    ad.require(pieces and (base not in pieces or pieces == [base]),
               'AMBIGUOUS_TWRP_BACKUP', 'Choose a folder with one Data backup set')
    if pieces != [base]:
        groups = {}
        for name in pieces:
            suffix = name[-3:]
            groups.setdefault(int(suffix[0]), []).append(int(suffix[1:]))
        # TWRP starts at thread zero for an ordinary split or at thread one
        # when the optional encrypted backup uses only encrypted threads.
        first = min(groups)
        ad.require(first <= 1 and sorted(groups) == list(range(first, max(groups) + 1))
                   and all(indices == list(range(len(indices))) for indices in groups.values()),
                   'TWRP_PARTS_MISSING', 'A numbered Data backup segment is missing')
    return pieces


@contextlib.contextmanager
def regular_at(pin, parent, name, minimum=1, maximum=ad.MAX_LOGICAL):
    fd = os.open(name, READ_FLAGS, dir_fd=parent)
    try:
        pin.check_fd(fd)
        value = os.fstat(fd)
        ad.require(stat.S_ISREG(value.st_mode) and minimum <= value.st_size <= maximum,
                   'INVALID_TWRP_FILE', 'A backup member or checksum is not a bounded regular file')
        yield fd, ad.identity(value)
        ad.require(ad.identity(os.fstat(fd)) == ad.identity(value), 'SOURCE_CHANGED', 'A Data backup file changed while it was read')
    finally:
        os.close(fd)


def expected_digests(pin, parent, name, present, stamps):
    expected = []
    for extension, algorithm in DIGESTS.items():
        sidecar = name + extension
        if sidecar not in present:
            continue
        with regular_at(pin, parent, sidecar, maximum=512) as (fd, stamp), os.fdopen(os.dup(fd), 'rb') as file:
            line = ad.exact(file, stamp[5]).rstrip(b'\r\n')
            length = 64 if algorithm == 'sha256' else 32
            token = line[:length]
            ad.require(len(token) == length and re.fullmatch(rb'[0-9A-Fa-f]+', token)
                       and line[length:] in (b'', b'  ' + name.encode('ascii'), b' *' + name.encode('ascii')),
                       'TWRP_DIGEST_INVALID', 'A Data backup checksum names the wrong file or is malformed')
            expected.append((algorithm, token.lower().decode('ascii')))
            stamps[sidecar] = stamp
    return expected


class PieceReader:
    def __init__(self, file, with_md5, report):
        self.file, self.report, self.count = file, report, 0
        self.sha256 = hashlib.sha256()
        self.md5 = hashlib.md5(usedforsecurity=False) if with_md5 else None

    def read(self, length):
        data = self.file.read(length)
        self.sha256.update(data)
        if self.md5 is not None:
            self.md5.update(data)
        self.count += len(data)
        self.report(self.count)
        return data


def pax_records(block):
    cursor = 0
    while cursor < len(block):
        space = block.find(b' ', cursor, cursor + 8)
        number = block[cursor:space] if space >= 0 else b''
        ad.require(number.isdigit(), 'TWRP_TAR_DAMAGED', 'Invalid extended tar record size')
        end = cursor + int(number)
        ad.require(space + 2 < end <= len(block) and block[end - 1] == 10,
                   'TWRP_TAR_DAMAGED', 'Truncated extended tar record')
        name, equals, value = block[space + 1:end - 1].partition(b'=')
        ad.require(re.fullmatch(rb'[A-Za-z0-9_.-]{1,128}', name) and (equals or name in MARKERS),
                   'TWRP_TAR_DAMAGED', 'Malformed extended tar record')
        yield name, value
        cursor = end


def tar_path(name, is_dir, split):
    if name.startswith('./'):
        name = name[2:]
    elif name.startswith('/'):
        name = name[1:]
    if is_dir:
        name = name.rstrip('/')
    if split:
        if name == 'data' and is_dir:
            return ''
        ad.require(name.startswith('data/'), 'TWRP_UNEXPECTED_ROOT', 'A split Data tar must use the Android data root')
        name = name[5:]
    if name in ('', '.') and is_dir:
        return ''
    ad.portable_path(name)
    return name


def tar_entries(stream, split):
    extra, extended_bytes = {}, 0
    while True:
        block = ad.exact(stream, 512)
        if block == EMPTY_BLOCK:
            ad.require(not extra and ad.exact(stream, 512) == EMPTY_BLOCK,
                       'TWRP_TAR_DAMAGED', 'Data tar is missing its end marker')
            ending = stream.read(65537)
            ad.require(len(ending) <= 65536 and not any(ending), 'TWRP_TAR_DAMAGED', 'Unexpected data after the tar end marker')
            return
        item = tarfile.TarInfo.frombuf(block, 'utf-8', 'surrogateescape')
        ad.require(0 <= item.size <= ad.MAX_LOGICAL, 'TWRP_TAR_DAMAGED', 'Invalid Data tar member size')
        if item.type in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            extended_bytes += item.size + 512
            ad.require(0 < item.size <= 65536 and extended_bytes <= 131072,
                       'TWRP_TAR_DAMAGED', 'Extended Data tar headers exceed their size limit')
            content = ad.exact(stream, item.size)
            if item.type == tarfile.XHDTYPE:
                records = pax_records(content)
            else:
                key = b'path' if item.type == tarfile.GNUTYPE_LONGNAME else b'linkpath'
                records = ((key, content.rstrip(b'\0')),)
            for key, value in records:
                ad.require(key not in extra and len(extra) < 128 and not key.startswith(b'GNU.sparse'),
                           'TWRP_TAR_DAMAGED', 'Unsupported or duplicate Data tar metadata')
                extra[key] = value
            ad.require(not any(ad.exact(stream, -item.size % 512)), 'TWRP_TAR_DAMAGED', 'Extended tar padding is invalid')
            continue
        if b'size' in extra:
            value = extra[b'size']
            ad.require(len(value) <= 13 and value.isdigit(), 'TWRP_TAR_DAMAGED', 'Invalid extended Data tar file size')
            item.size = int(value)
        name = extra.get(b'path', os.fsencode(item.name)).decode('utf-8', 'surrogateescape')
        path = tar_path(name, item.isdir(), split)
        ad.require(item.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.LNKTYPE, tarfile.SYMTYPE,
                                 tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE)
                   and 0 <= item.size <= ad.MAX_LOGICAL and (item.isfile() or item.size == 0),
                   'TWRP_TAR_DAMAGED', 'Unsupported Data tar entry type or size')
        yield path, item, TWRP_METADATA.intersection(extra)
        left = item.size
        while left:
            left -= len(ad.exact(stream, min(left, ad.CHUNK)))
        ad.require(not any(ad.exact(stream, -item.size % 512)), 'TWRP_TAR_DAMAGED', 'Data tar padding is invalid')
        extra.clear()
        extended_bytes = 0


def inspect(context, volume, token, path, progress=lambda *unused: None):
    fs.require_hash(token, 'expected-volume-token')
    ad.require(volume in ('cache', 'userdata') or volume.startswith(('sdcard-', 'usb-')),
               'INVALID_VOLUME', 'Choose a mounted backup on Data, cache, SD or USB storage')
    path = fs.clean_path(path)
    if volume == 'userdata':
        ad.admitted(context.volume(volume, token))
        ad.require(path.startswith('/media/0/'), 'INVALID_TWRP_PATH', 'Choose a Data backup in shared storage')
    with fs.PinnedVolume(context, volume, token) as pin, pin.parent(path) as (parent, selected):
        match = ARCHIVE.fullmatch(selected)
        ad.require(match, 'INVALID_TWRP_PATH', 'Choose a data.f2fs.win or data.ext4.win backup segment')
        base, filesystem = match.group(1, 2)
        present = set(os.listdir(parent))
        parts = piece_set(present, base)
        ad.require(selected in parts, 'TWRP_PARTS_MISSING', 'The selected Data backup segment is no longer present')
        split = parts != [base]
        stamps, pieces, seen = {}, [], set()
        packages = {root: set() for root in APP_ROOTS}
        stored = logical = files = entries = index_bytes = 0
        secure_metadata = set()
        for name in parts:
            checks = expected_digests(pin, parent, name, present, stamps)
            with regular_at(pin, parent, name) as (fd, stamp), os.fdopen(os.dup(fd), 'rb') as file:
                signature = os.pread(fd, 2, 0)
                ad.require(signature != b'OA', 'TWRP_ENCRYPTED_BACKUP', 'This backup uses a TWRP archive password')
                reader = PieceReader(file, any(kind == 'md5' for kind, _ in checks), lambda n: progress(stored + n, entries))
                compressed = signature == b'\x1f\x8b'
                try:
                    with (gzip.GzipFile(fileobj=reader) if compressed else contextlib.nullcontext(reader)) as stream:
                        for member, item, metadata in tar_entries(stream, split):
                            index_bytes += len(os.fsencode(member)) + 64
                            ad.require(member not in seen and entries < ad.MAX_ENTRIES and index_bytes <= ad.MAX_INDEX,
                                       'TWRP_TAR_DAMAGED', 'Data tar entries are duplicated or exceed their index limit')
                            seen.add(member)
                            logical += item.size
                            ad.require(logical <= ad.MAX_LOGICAL, 'TWRP_TAR_DAMAGED', 'Data tar exceeds its payload size limit')
                            files += item.isfile()
                            entries += 1
                            secure_metadata.update(metadata)
                            if item.isfile() or item.islnk():
                                for prefix in APP_ROOTS:
                                    if member.startswith(prefix):
                                        package, _, relative = member[len(prefix):].partition('/')
                                        if relative and PACKAGE.fullmatch(package):
                                            packages[prefix].add(package)
                                        break
                except (EOFError, gzip.BadGzipFile, zlib.error, tarfile.TarError, UnicodeError, ValueError):
                    fs.fail('TWRP_TAR_DAMAGED', 'A Data backup segment has damaged tar or gzip data')
                ad.require(reader.count == stamp[5], 'SOURCE_CHANGED', 'Read size differs from the selected Data backup segment')
                digest = reader.sha256.hexdigest()
                for kind, expected in checks:
                    actual = digest if kind == 'sha256' else reader.md5.hexdigest()
                    ad.require(actual == expected, 'TWRP_DIGEST_MISMATCH', 'A Data backup segment differs from its recorded checksum')
                pieces.append({'name': name, 'bytes': reader.count, 'sha256': digest,
                               'format': 'tar.gz' if compressed else 'tar', 'checksums': sorted({kind for kind, _ in checks})})
                stamps[name] = stamp
                stored += reader.count
        ad.require(entries, 'EMPTY_TWRP_BACKUP', 'The Data backup contains no entries')
        pin.recheck()
        now = set(os.listdir(parent))
        ad.require(piece_set(now, base) == parts and all((name + suffix in present) == (name + suffix in now)
                   for name in parts for suffix in DIGESTS)
                   and all(ad.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stamp for name, stamp in stamps.items()),
                   'SOURCE_CHANGED', 'The Data backup set changed during review')
    return {'schema': 'a22x.twrp-data-review.v1', 'archive': {'volume': volume, 'path': path, 'filesystem': filesystem,
            'bytes': stored, 'pieces': pieces, 'sha256': hashlib.sha256(ad.encode(pieces)).hexdigest()},
            'counts': {'entries': entries, 'files': files, 'file_bytes': logical, 'parts': len(pieces),
                       'checked_parts': sum(bool(piece['checksums']) for piece in pieces),
                       'ce_packages': len(packages['user/0/'] | packages['data/']), 'de_packages': len(packages['user_de/0/'])},
            'twrp_metadata': sorted(tag.decode('ascii') for tag in secure_metadata),
            'verified_structure': True, 'source_model_proven': False, 'source_rom_proven': False, 'restore_supported': False}


def main(argv=None):
    parser = fs.Parser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--device', action='store_true')
    mode.add_argument('--fixture')
    parser.add_argument('--volume', required=True)
    parser.add_argument('--expected-volume-token', required=True)
    parser.add_argument('--path', required=True)
    parser.add_argument('--summary', action='store_true')
    try:
        args = parser.parse_args(argv)
        context = fs.FixtureContext(args.fixture) if args.fixture else fs.DeviceContext()
        last = 0.0

        def progress(done, count):
            nonlocal last
            now = time.monotonic()
            if now - last >= 0.5:
                last = now
                print(json.dumps({'event': 'progress', 'phase': 'twrp-review', 'bytes_done': done,
                                  'entries_done': count}), file=sys.stderr, flush=True)

        with context.operation_lock():
            result = inspect(context, args.volume, args.expected_volume_token, args.path, progress)
        if args.summary:
            del result['archive']['pieces']
        print(json.dumps({'ok': True, **result}, separators=(',', ':')))
        return 0
    except fs.FilesystemError as error:
        code, message = error.code, error.message
    except OSError as error:
        code, message = 'TWRP_IO_ERROR', 'The Data backup could not be read (errno=%s)' % error.errno
    print(json.dumps({'ok': False, 'error': {'code': code, 'message': message}}, separators=(',', ':')))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
