#!/usr/bin/env python3
"""One early TZAR/TEE start on an identified boot, with a qualified HW watchdog.

An unreturned start or deployment gets at most 90 seconds of keepalives.
After that, retain the watchdog fd without feeding it and let hardware reset.
No partition writes or automatic retries. SRAM words use scalar 32-bit access.
"""
import argparse
import ctypes
import fcntl
import json
import mmap
import os
from pathlib import Path
import struct
import stat
import subprocess
import time

def report(event, **values):
    print(json.dumps(dict(event=event, monotonic=time.monotonic(), **values)), flush=True)

def integer_ioctl(fd, request, value):
    arg = bytearray(struct.pack('i', value))
    fcntl.ioctl(fd, request, arg, True)
    return struct.unpack('i', arg)[0]

p = argparse.ArgumentParser()
p.add_argument('--boot-id', required=True)
p.add_argument('--common-lock-fd', type=int, required=True)
p.add_argument('--start-once', action='store_true', required=True)
a = p.parse_args()
assert a.common_lock_fd >= 3
lock = os.dup(a.common_lock_fd)
opened = os.fstat(lock)
named = Path('/run/lock/a22x-mainline-recovery.lock').lstat()
assert stat.S_ISREG(opened.st_mode) and opened.st_nlink == named.st_nlink == 1
assert (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino)
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
assert boot == a.boot_id, 'boot changed'
assert 'a22x.recovery=1' in Path('/proc/cmdline').read_text().split()
assert struct.unpack_from('<I', Path('/proc/device-tree/chosen/atag,boot').read_bytes(), 8)[0] == 2
assert Path('/sys/module/tzdev/parameters/deploy_result').read_text().strip() == '-11'
assert Path('/sys/module/tzdev/parameters/early_bootstrap_result').read_text().strip() == '-11'
assert Path('/sys/module/tzdev/parameters/root_task_probe_result').read_text().strip() == '-11'
for name in ('bootstrap_start', 'root_task_probe'):
    node = Path('/sys/module/tzdev/parameters') / name
    assert node.exists() and os.access(node, os.W_OK), 'missing writable driver gate: ' + name
assert not Path('/run/a22x-tzdev/attempted').exists()
for line in Path('/proc/self/mountinfo').read_text().splitlines():
    fields = line.split()
    assert fields[2].split(':')[0] == '0' and not fields[4].startswith('/mnt/'), 'block filesystem mounted'
guard = os.open('/run/a22x-tzdev-bootstrap-watchdog.attempted', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.close(guard)
report('preflight_pass', boot_id=boot)
memfd = os.open('/dev/mem', os.O_RDWR | os.O_SYNC)
mem = mmap.mmap(memfd, 4096, offset=0x11d000)
marker = ctypes.c_uint32.from_buffer(mem, 0x534)
reason = ctypes.c_uint32.from_buffer(mem, 0x538)
old = (marker.value, reason.value)
wd, child = None, None
completed = False
rc = 1
try:
    marker.value, reason.value = (0x12345678, 0x12345674)
    assert (marker.value, reason.value) == (0x12345678, 0x12345674)
    report('recovery_markers_verified')
    wd = os.open('/dev/watchdog0', os.O_WRONLY | os.O_CLOEXEC)
    info = bytearray(40)
    fcntl.ioctl(wd, 0x80285700, info, True)
    options, firmware, identity = struct.unpack('II32s', info)
    assert identity.split(b'\0')[0] == b'mtk-wdt'
    assert options & 0x100
    if options & 0x200:
        assert integer_ioctl(wd, 0xc0045708, 0) == 0
    assert integer_ioctl(wd, 0xc0045706, 16) == 16
    report('watchdog_armed', timeout=16, keepalive_deadline_seconds=90)
    child = subprocess.Popen(['/sbin/a22x-tzdev-bootstrap', '--boot-id', boot,
                              '--watchdog-parent', str(os.getpid()), '--start-once'], close_fds=True)
    deadline = time.monotonic() + 90
    report('start_dispatched', child_pid=child.pid)
    while time.monotonic() < deadline:
        rc = child.poll()
        if rc is not None:
            completed = True
            report('start_returned', returncode=rc,
                   deploy_result=Path('/sys/module/tzdev/parameters/deploy_result').read_text().strip(),
                   handoff_result=Path('/sys/module/tzdev/parameters/early_bootstrap_result').read_text().strip(),
                   root_task_probe_result=Path('/sys/module/tzdev/parameters/root_task_probe_result').read_text().strip())
            break
        os.write(wd, b'.')
        time.sleep(.5)
    if not completed:
        report('deadline_expired_no_more_keepalives', child_pid=child.pid)
except BaseException as error:
    report('guard_exception', kind=type(error).__name__, detail=str(error))
    raise
finally:
    if child is not None and not completed:
        report('waiting_for_hardware_reset_no_retry')
        # Keep the timer descriptor open without feeding it, as in qualification.
        # In particular, never disable it while a secure call may be stuck.
        while True:
            time.sleep(30)
    if wd is not None:
        os.write(wd, b'V')
        os.close(wd)
        report('watchdog_disarmed')
    marker.value, reason.value = old
    assert (marker.value, reason.value) == old
    del marker, reason
    mem.close()
    os.close(memfd)
    os.close(lock)
raise SystemExit(rc)
