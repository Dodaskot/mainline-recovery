#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Android's data without file-based encryption (no-FBE, 2026-11-21, goal item 5).

Android encrypts /data when the vendor's fstab asks for it: the /data line of /vendor/etc/fstab.*
carries fileencryption= (and keydirectory= for metadata encryption). Samsung's firmware for this
phone (A226BXXSBDZC3) has them; LineageOS 20 for it removes them, and its data stays plain, which
this recovery then backs up, carries and restores without a password.

Here the same is done to the vendor in super: in every /vendor/etc/fstab.* the encryption flags of
the /data line are overwritten, byte for byte, by commas (empty flags, which fs_mgr skips, as the
stock fstab's own ",," shows). The file keeps its size and its blocks: nothing of the filesystem
changes but those bytes, read from the filesystem's own block list (debugfs) and written into super
through the vendor partition's extents. Only with vbmeta's verification off (dm-verity would
otherwise refuse the changed vendor), and only before Android's data is formatted: data already
encrypted stays so until it is erased.

    nofbe.py --device|--fixture DIR inspect
    nofbe.py ... patch --confirm
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import filesystem as fs
import flash
from install import require

FLAGS = ('fileencryption', 'metadata_encryption', 'keydirectory', 'forceencrypt', 'forcefdeorfbe')
MAPPING = 'a22x-nofbe-vendor'
SECTOR = 512
LIMIT = 64 << 10


def unencrypted(text):
    """(TEXT with the /data line's encryption flags overwritten by commas, the flags removed). The
    length never changes."""
    out = bytearray(text)
    removed = []
    at = 0
    for line in text.split(b'\n'):
        fields = list(re.finditer(rb'\S+', line))
        if len(fields) >= 5 and not line.lstrip().startswith(b'#') and fields[1].group() == b'/data':
            flags = fields[4]
            start = at + flags.start()
            for flag in re.finditer(rb'[^,]+', flags.group()):
                name = flag.group().split(b'=', 1)[0].decode('ascii', 'replace')
                if name in FLAGS:
                    out[start + flag.start():start + flag.end()] = b',' * (flag.end() - flag.start())
                    removed.append(name)
        at += len(line) + 1
    assert len(out) == len(text)
    return bytes(out), removed


def debugfs(device, request):
    run = subprocess.run(['debugfs', '-R', request, str(device)], capture_output=True, timeout=60)
    require(run.returncode == 0, 'VENDOR_UNREADABLE', 'The vendor filesystem could not be read')
    return run.stdout


def require_ext4(device):
    with open(device, 'rb') as probe:
        probe.seek(1080)
        require(probe.read(2) == b'\x53\xef', 'VENDOR_NOT_EXT4', 'The vendor partition is no ext4 filesystem')


def block_size(device):
    found = re.search(rb'Block size:\s+(\d+)', debugfs(device, 'stats'))
    require(found and int(found.group(1)) in (1024, 2048, 4096), 'VENDOR_UNREADABLE', 'The vendor filesystem has no usable block size')
    return int(found.group(1))


def fstabs(device):
    """[(name, content, its blocks)] of /etc/fstab.* in the vendor filesystem at DEVICE (a block device
    or an image file), in the order of the directory."""
    require_ext4(device)
    found = []
    for line in debugfs(device, 'ls -p /etc').decode('utf-8', 'replace').splitlines():
        parts = line.split('/')
        if len(parts) < 7 or not parts[5].startswith('fstab.') or not parts[2].startswith('100'):
            continue
        name, size = parts[5], int(parts[6] or 0)
        if not re.fullmatch(r'fstab\.[A-Za-z0-9_.-]{1,40}', name) or not 0 < size <= LIMIT:
            continue
        content = debugfs(device, 'cat /etc/' + name)
        blocks = [int(b) for b in debugfs(device, 'blocks /etc/' + name).split()]
        require(len(content) == size and blocks, 'VENDOR_UNREADABLE', 'A vendor fstab could not be read whole', file=name)
        found.append((name, content, blocks))
    return found


def plan_for(device):
    """What the patch changes, read from the filesystem at DEVICE: files, flags, and the byte ranges
    to write as (offset in the filesystem, new bytes)."""
    require_ext4(device)
    size = block_size(device)
    files, writes = [], []
    for name, content, blocks in fstabs(device):
        patched, removed = unencrypted(content)
        files.append({'file': '/vendor/etc/' + name, 'removed': removed})
        if not removed:
            continue
        require(len(blocks) * size >= len(content), 'VENDOR_UNREADABLE', 'A vendor fstab is larger than its blocks', file=name)
        for index, block in enumerate(blocks):
            old = content[index * size:(index + 1) * size]
            new = patched[index * size:(index + 1) * size]
            if old != new:
                writes.append({'offset': block * size, 'old': old, 'new': new})
    return {'files': files, 'writes': writes, 'encrypted': any(f['removed'] for f in files)}


def write_image(path, writes):
    """WRITES into a filesystem image file (tests, and an unpacked vendor)."""
    fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
    try:
        for w in writes:
            require(os.pread(fd, len(w['old']), w['offset']) == w['old'], 'VENDOR_CHANGED', 'The vendor changed while it was read')
            os.pwrite(fd, w['new'], w['offset'])
        os.fsync(fd)
    finally:
        os.close(fd)


def super_offset(extents, offset):
    """The byte in super of the partition's byte OFFSET (extents: [(start sector, sectors)])."""
    at = 0
    for start, sectors in extents:
        if offset < at + sectors * SECTOR:
            return start * SECTOR + offset - at
        at += sectors * SECTOR
    fs.fail('VENDOR_CHANGED', 'The vendor partition is smaller than its filesystem says')


def vendor_extents(found):
    p = found.partition('vendor')
    rows = found.extents_of(p)
    require(rows and all(e.get('type', 0) == 0 for e in rows), 'VENDOR_LAYOUT_UNSUPPORTED', "The vendor partition's layout is not plain")
    return [(e['start'], e['sectors']) for e in rows]


def read_vendor(context):
    """The plan, read through a read-only mapping of vendor (the phone) or its image (fixture)."""
    if context.mode == 'fixture':
        return plan_for(context.root / 'vendor.img'), None
    import dm_linear
    _, sfd, found = flash.open_super(context)
    try:
        extents = vendor_extents(found)
        rdev = os.fstat(sfd).st_rdev
        device = '%d:%d' % (os.major(rdev), os.minor(rdev))
    finally:
        os.close(sfd)
    dm_linear.create(MAPPING, dm_linear.linear_table(extents, device), read_only=True)
    try:
        node = '/dev/' + dm_linear.devices()[MAPPING][1]
        return plan_for(node), extents
    finally:
        dm_linear.remove(MAPPING)


def inspect(context):
    """Whether vendor asks Android to encrypt its data, and whether it may be changed here."""
    import root
    plan, _ = read_vendor(context)
    verification = root.verification_state(context)
    blockers = [] if verification is False else ['NO_FBE_NEEDS_VERIFICATION_OFF']
    return {'encrypted': plan['encrypted'], 'files': plan['files'], 'blockers': blockers if plan['encrypted'] else [],
            'verification': verification}


def patch(context, confirmed, progress=lambda *unused: None):
    """The encryption flags out of vendor's fstab files; read back. Nothing to do when there are none."""
    require(confirmed, 'CONFIRMATION_REQUIRED', 'Changing the vendor must be confirmed')
    import root
    require(root.verification_state(context) is False, 'NO_FBE_NEEDS_VERIFICATION_OFF',
            "vbmeta still verifies the vendor: a changed vendor would not start. Turn verification off first (Root)")
    progress('Reading the vendor', {'label': 'super/vendor', 'size_bytes': 1}, 0)
    plan, extents = read_vendor(context)
    if not plan['writes']:
        return {'changed': False, 'files': plan['files']}
    progress('Writing the vendor', {'label': 'super/vendor', 'size_bytes': 1}, 0)
    if context.mode == 'fixture':
        write_image(context.root / 'vendor.img', plan['writes'])
    else:
        target = context.target('super')
        fd = context.open_target(target, write=True)
        try:
            for w in plan['writes']:
                at = super_offset(extents, w['offset'])
                require(os.pread(fd, len(w['old']), at) == w['old'], 'VENDOR_CHANGED', 'The vendor changed while it was read')
                os.pwrite(fd, w['new'], at)
            os.fsync(fd)
        finally:
            os.close(fd)
    after, _ = read_vendor(context)
    require(not after['encrypted'], 'NO_FBE_NOT_WRITTEN', "The vendor's fstab still asks for encryption after the write")
    progress('Writing the vendor', {'label': 'super/vendor', 'size_bytes': 1}, 1)
    return {'changed': True, 'files': plan['files']}


def main(argv=None):
    import install
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--device', action='store_true')
    mode.add_argument('--fixture', type=Path)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('inspect')
    commands.add_parser('patch').add_argument('--confirm', action='store_true')
    args = parser.parse_args(argv)
    try:
        context = install.FixtureContext(args.fixture) if args.fixture else install.DeviceContext()
        with flash.operation_lock(context.lock_path, context.mode):
            result = inspect(context) if args.command == 'inspect' else patch(context, args.confirm)
        print(json.dumps({'ok': True, 'operation': args.command, **result}, separators=(',', ':')))
        return 0
    except Exception as error:  # noqa: BLE001 - every refusal reaches the caller as JSON
        code = getattr(error, 'code', None) or ('OPERATION_BUSY' if isinstance(error, BlockingIOError) else 'IO_ERROR')
        print(json.dumps({'ok': False, 'operation': args.command, 'error': {'code': code, 'message': str(error)}},
                         separators=(',', ':')))
        return 2


if __name__ == '__main__':
    sys.exit(main())
