#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small records of the recovery in the misc partition, each kept twice (2026-11-14).

The settings and the saved Wi-Fi list lived in files on cache, or on userdata: every way a
filesystem can show an older state (a journal not replayed, a volume that will not mount, a copy
restored, a release that wrote elsewhere) became a way to read a password as none. Here they are
kept as U-Boot keeps its redundant environment, and LUKS2 its two headers: two copies of each
record, each with a generation and a SHA-256, on the raw partition. A read takes the whole copy of
the newest generation; a write replaces the other copy, so a write that stops halfway leaves the
one before it whole. No filesystem, no mount, no journal.

Where: the last 128 KiB of misc (512 KiB on this phone). Android uses only its first 64 KiB
(bootloader_message.h: 0-2K the bootloader message, 2K-16K vendor, 16K-32K the wipe package,
32K-64K system space; seen on the phone: the bootloader message at 0, memtag and kcmdline
messages at 32K); the LK writes only the bootloader message (strings of lk.img: "boot-recovery",
"--wipe_data"); the kernel never touches misc (searched: drivers/samsung, drivers/misc/mediatek,
the partition code). Backups of misc from 2026-10-07 and the partition now: nothing beyond 64 KiB
was ever written. A record is written only where it finds its own copies or zeros: bytes there
that are no copy of this recovery's are never written over (Foreign).

Each record: two slots of 32 KiB. A slot: its first sector holds the header (magic, name,
generation, length, SHA-256 of header and payload), the payload starts at 512. The header is
written first and made durable, then the payload: a slot cut short has the magic and a wrong
hash, never a payload that looks like another's.
"""
import contextlib
import errno
import hashlib
import os
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lp_metadata import drop_cached

MISC = Path('/dev/disk/by-partlabel/misc')
MAGIC = b'A22XMSC1'
SECTOR = 512
SLOT = 32 << 10
PAYLOAD_MAX = SLOT - SECTOR
# name -> offset of its first slot; the second follows it.
AREAS = {'settings': 384 << 10, 'wifi': 448 << 10}
END = 512 << 10
HEADER = struct.Struct('<8s8sQII')  # magic, name, generation, length, flags (0)


class Damaged(ValueError):
    """Both copies are there and neither is whole."""


class Foreign(OSError):
    """Bytes that are no copy of this recovery's stand where a record would go: never written over."""


def path():
    """misc of the internal eMMC; A22X_MISC names a file instead (tests)."""
    return Path(os.environ.get('A22X_MISC', str(MISC)))


def _internal(target):
    """Whether TARGET is a partition of the internal eMMC (bcb.internal: a card or stick with an
    Android layout has a misc of its own, and by-partlabel may name it)."""
    if target != MISC:
        return True
    return re.fullmatch(r'/dev/mmcblk0p[0-9]+', os.path.realpath(target)) is not None


def _open(write):
    target = path()
    if not _internal(target):
        raise OSError(errno.ENODEV, 'misc is not on the internal storage')
    fd = os.open(target, (os.O_RDWR if write else os.O_RDONLY) | os.O_CLOEXEC)
    try:
        if os.lseek(fd, 0, os.SEEK_END) < END:
            raise OSError(errno.ENOSPC, 'misc is smaller than the records need')
    except BaseException:
        os.close(fd)
        raise
    return fd


def _name(name):
    if name not in AREAS:
        raise ValueError('No such record: %s' % name)
    return name.encode().ljust(8, b'\0')


def _read_slot(fd, offset):
    data = os.pread(fd, SLOT, offset)
    if len(data) != SLOT:
        raise OSError(errno.EIO, 'misc ended before a record')
    return data


def classify(name, data):
    """('empty',) all zeros; ('valid', generation, payload); ('torn',) this record's magic and
    name, not whole; ('foreign',) anything else."""
    if not any(data):
        return ('empty',)
    magic, label, generation, length, flags = HEADER.unpack_from(data)
    if magic != MAGIC:
        # A first write cut short in the first bytes of its header: a beginning of the magic and
        # nothing else (the test found it read as another's, and every write refused for good).
        start = next(index for index in range(len(MAGIC) + 1) if index == len(MAGIC) or data[index] != MAGIC[index])
        return ('torn',) if start and not any(data[start:]) else ('foreign',)
    if label != _name(name):
        return ('foreign',)
    if flags or length > PAYLOAD_MAX:
        return ('torn',)
    payload = data[SECTOR:SECTOR + length]
    digest = hashlib.sha256(data[:HEADER.size] + payload).digest()
    if data[HEADER.size:HEADER.size + 32] != digest:
        return ('torn',)
    return ('valid', generation, payload)


def _slots(fd, name):
    first = AREAS[name]
    return [classify(name, _read_slot(fd, first + index * SLOT)) for index in (0, 1)]


def decide(slots):
    """The payload the two SLOTS hold (classify's answers): the newest whole copy; None when there
    is none and no record was ever whole (both empty; one empty beside one cut short, which only a
    first write that stopped leaves: every write after it leaves two whole copies); Damaged when
    neither copy is whole and both are this record's or one is."""
    whole = [slot for slot in slots if slot[0] == 'valid']
    if whole:
        return max(whole, key=lambda slot: slot[1])[2]
    kinds = sorted(slot[0] for slot in slots)
    if kinds in (['empty', 'empty'], ['empty', 'torn'], ['empty', 'foreign'], ['foreign', 'foreign']):
        return None
    raise Damaged('Neither copy of the %s record is whole' % 'stored')


def read(name):
    """The payload of record NAME, bytes; None when none was ever kept. OSError when misc cannot be
    read now; Damaged when both copies are damaged."""
    _name(name)
    fd = _open(False)
    try:
        return decide(_slots(fd, name))
    finally:
        os.close(fd)


def _write_slot(fd, name, index, generation, payload):
    offset = AREAS[name] + index * SLOT
    head = HEADER.pack(MAGIC, _name(name), generation, len(payload), 0)
    head += hashlib.sha256(head + payload).digest()
    sector = head.ljust(SECTOR, b'\0')
    body = payload.ljust(SLOT - SECTOR, b'\0')
    os.pwrite(fd, sector, offset)
    os.fsync(fd)
    os.pwrite(fd, body, offset + SECTOR)
    os.fsync(fd)
    drop_cached(fd)
    if os.pread(fd, SLOT, offset) != sector + body:
        raise OSError(errno.EIO, 'misc did not keep the record')


def write(name, payload):
    """PAYLOAD (bytes) as record NAME: over the older copy, so the newest stays whole meanwhile;
    when the other copy is not whole either (the first write, or one damaged), over that one too,
    so a whole record always has two whole copies. Called under the operation lock. OSError when
    misc cannot be written; Foreign when another's bytes stand there."""
    _name(name)
    if len(payload) > PAYLOAD_MAX:
        raise ValueError('The %s record is too large for misc' % name)
    fd = _open(True)
    try:
        slots = _slots(fd, name)
        ours = any(slot[0] in ('valid', 'torn') for slot in slots)
        if not ours and any(slot[0] == 'foreign' for slot in slots):
            raise Foreign(errno.EEXIST, 'Another program keeps data where the %s record would go' % name)
        whole = [index for index in (0, 1) if slots[index][0] == 'valid']
        newest = max(whole, key=lambda index: slots[index][1]) if whole else None
        generation = slots[newest][1] if newest is not None else 0
        target = 0 if newest is None else 1 - newest
        _write_slot(fd, name, target, generation + 1, payload)
        if newest is None:
            _write_slot(fd, name, 1 - target, generation + 2, payload)
    finally:
        os.close(fd)


def clear(name):
    """Record NAME gone, both copies zeroed (the reset of damaged settings): the older first."""
    _name(name)
    fd = _open(True)
    try:
        slots = _slots(fd, name)
        if not any(slot[0] in ('valid', 'torn') for slot in slots) and any(slot[0] == 'foreign' for slot in slots):
            raise Foreign(errno.EEXIST, 'Another program keeps data where the %s record would go' % name)
        order = sorted((0, 1), key=lambda index: slots[index][1] if slots[index][0] == 'valid' else -1)
        for index in order:
            offset = AREAS[name] + index * SLOT
            os.pwrite(fd, bytes(SLOT), offset)
            os.fsync(fd)
        drop_cached(fd)
        for index in (0, 1):
            if any(_read_slot(fd, AREAS[name] + index * SLOT)):
                raise OSError(errno.EIO, 'misc did not clear the record')
    finally:
        os.close(fd)


if __name__ == '__main__':
    with contextlib.suppress(BrokenPipeError):
        for record in AREAS:
            try:
                value = read(record)
                print(record, 'none' if value is None else '%d bytes' % len(value))
            except (OSError, ValueError) as error:
                print(record, 'error:', error)
