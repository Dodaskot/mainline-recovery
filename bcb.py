#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""The bootloader message (BCB) in misc: what Android asked of the recovery (2026-11-10).

When Android cannot mount its data it writes "boot-recovery" with "--prompt_and_wipe_data" and a
reason to the start of misc (seen on the phone: --reason=fs_mgr_mount_all:M02R, after a BOOT that
changed the verified-boot state). Samsung's and AOSP's recovery act on it and clear it; this one
reads it for the screen and clears it once Android's data was reset, so a request that was done
does not stay behind.

    bcb.py --device|--fixture DIR read
    bcb.py --device|--fixture DIR arrive    at the recovery's start: a plain "boot-recovery" is done and cleared
    bcb.py --device|--fixture DIR forget    the owner's word: a request to erase data is dropped, nothing is erased
"""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

MISC = Path('/dev/disk/by-partlabel/misc')
SIZE = 2048  # struct bootloader_message: command[32] status[32] recovery[768] stage[32] reserved[1184]
WIPE_ARGUMENTS = ('--prompt_and_wipe_data', '--wipe_data')


def misc_path(context):
    return context.root / 'misc' if context.mode == 'fixture' else MISC


# Samsung's Android writes its factory reset to /cache/recovery/command, AOSP's older place for it, and
# leaves only "boot-recovery" in misc (2026-11-21, on the owner's phone: "--wipe_data",
# "--reason=MasterClearConfirm,..."). AOSP's recovery reads the file when misc has no arguments; so does
# this one, through a private read-only mount of cache that replays no journal.
CACHE = Path('/dev/disk/by-partlabel/cache')
CACHE_PEEK = Path('/run/a22x-recovery/.bcb-cache')
COMMAND = 'recovery/command'


def _cache_mounted(write):
    if not re.fullmatch(r'/dev/mmcblk0p[0-9]+', os.path.realpath(CACHE)):
        raise OSError('cache is not on the internal storage')
    CACHE_PEEK.mkdir(mode=0o700, parents=True, exist_ok=True)
    options = 'rw,nodev,nosuid,noexec' if write else 'ro,noload,nodev,nosuid,noexec'
    done = subprocess.run(['/bin/busybox', 'mount', '-t', 'ext4', '-o', options, str(CACHE), str(CACHE_PEEK)],
                          capture_output=True, timeout=20)
    if done.returncode:
        raise OSError('cache could not be mounted: ' + done.stderr.decode('utf-8', 'replace')[-120:])


def _cache_mountpoint():
    """Where cache is mounted already in this namespace, or None."""
    st = os.stat(CACHE)
    devno = '%d:%d' % (os.major(st.st_rdev), os.minor(st.st_rdev))
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split(' - ', 1)[0].split()
        if len(fields) >= 5 and fields[2] == devno and fields[3] == '/':
            return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
    return None


def _cache_released():
    subprocess.run(['/bin/busybox', 'umount', str(CACHE_PEEK)], capture_output=True, timeout=20)


def cache_command(context):
    """The lines of /cache/recovery/command, [] when there is none or it cannot be read."""
    try:
        if context.mode == 'fixture':
            text = (context.root / 'cache-command').read_bytes()[:4096]
        else:
            mounted = _cache_mountpoint()
            if mounted:
                # Files already has cache open (Linux takes one mount of it at a time well).
                with open(Path(mounted) / COMMAND, 'rb') as f:
                    text = f.read(4096)
            else:
                _cache_mounted(False)
                try:
                    with open(CACHE_PEEK / COMMAND, 'rb') as f:
                        text = f.read(4096)
                finally:
                    _cache_released()
    except OSError:
        return []
    return [line for line in text.decode('utf-8', 'replace').splitlines() if line][:16]


def forget_cache_command(context):
    """The file removed, as AOSP's recovery does once it acted on it; True when there was one."""
    if context.mode == 'fixture':
        path = context.root / 'cache-command'
        if not path.exists():
            return False
        path.unlink()
        return True
    _cache_mounted(True)
    try:
        path = CACHE_PEEK / COMMAND
        if not path.exists():
            return False
        path.unlink()
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return True
    finally:
        _cache_released()


def request(context):
    """What Android asked: misc, or when misc names no arguments, Samsung's /cache/recovery/command."""
    found = read(misc_path(context))
    if not found['recovery'] and found['command'] in ('', 'boot-recovery'):
        lines = cache_command(context)
        if lines:
            found = {'command': 'boot-recovery', 'recovery': lines, 'source': 'cache',
                     'reason': next((line.split('=', 1)[1] for line in lines if line.startswith('--reason=')), '')[:128],
                     'wipe': any(line in WIPE_ARGUMENTS for line in lines)}
    return found


def read(path):
    """{'command', 'recovery': [lines], 'reason', 'wipe'}; an empty command when nothing is asked.
    A "misc" that is not the phone's own asks nothing: a card's could ask for a wipe."""
    try:
        if not internal(path):
            raise OSError('misc is not on the internal storage')
        with open(path, 'rb') as f:
            data = f.read(SIZE)
    except OSError:
        return {'command': '', 'recovery': [], 'reason': '', 'wipe': False}
    def text(start, size):
        return data[start:start + size].split(b'\0', 1)[0].decode('utf-8', 'replace')
    command = text(0, 32)
    lines = [line for line in text(64, 768).splitlines() if line]
    reason = next((line.split('=', 1)[1] for line in lines if line.startswith('--reason=')), '')
    return {'command': command[:32], 'recovery': lines[:16], 'reason': reason[:128],
            'wipe': command == 'boot-recovery' and any(line in WIPE_ARGUMENTS for line in lines)}


def internal(path):
    """Whether PATH is a partition of the internal eMMC (2026-11-13 review: a card or stick with an
    Android layout has a "misc" of its own, and by-partlabel may name it instead of the phone's)."""
    if Path(path) != MISC:
        return True  # a fixture's file
    return re.fullmatch(r'/dev/mmcblk0p[0-9]+', os.path.realpath(path)) is not None


def clear(path):
    """The message cleared, as recovery does once it acted on it; True when there was one."""
    if not internal(path):
        raise OSError('misc is not on the internal storage')
    if not read(path)['command']:
        return False
    fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
    try:
        os.pwrite(fd, bytes(SIZE), 0)
        os.fsync(fd)
        left = os.pread(fd, SIZE, 0)
    finally:
        os.close(fd)
    if any(left):
        raise OSError('the bootloader message did not clear')
    return True


def clear_wipe_request(context):
    """After Android's data was reset: a wipe request in misc is done, and is cleared."""
    path = misc_path(context)
    if read(path)['wipe']:
        return clear(path)
    return False


def main(argv=None):
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--device', action='store_true')
    mode.add_argument('--fixture', type=Path)
    parser.add_argument('command', choices=('read', 'arrive', 'forget'))
    args = parser.parse_args(argv)
    path = args.fixture / 'misc' if args.fixture else MISC
    context = SimpleNamespace(mode='fixture', root=args.fixture) if args.fixture else SimpleNamespace(mode='device')
    found = request(context)
    cleared = False
    if args.command == 'arrive' and found['command'] == 'boot-recovery' and not found['wipe']:
        # "Start the recovery" (adb reboot recovery, Android's power menu) is done by arriving here:
        # left in misc it would be read again at every later start (2026-11-11, seen after
        # adb reboot recovery). A request to erase data stays until the data is erased.
        try:
            cleared = clear(path)
        except OSError:
            cleared = False
    if args.command == 'forget' and found['wipe']:
        try:
            cleared = forget_cache_command(context) if found.get('source') == 'cache' else False
            cleared = clear(path) or cleared
        except OSError:
            print(json.dumps({'ok': False, **found, 'cleared': False}, separators=(',', ':')))
            return 2
        found = request(context)
    print(json.dumps({'ok': True, **found, 'cleared': cleared}, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
