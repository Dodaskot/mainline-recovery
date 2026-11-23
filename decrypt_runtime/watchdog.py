"""Qualified mtk-wdt 16-second hardware reset; magic close only after proof."""
import ctypes
import fcntl
import mmap
import os
from pathlib import Path
import struct
import time
from decrypt_runtime.common import require

def int_ioctl(fd, request, value):
    data = bytearray(struct.pack('i', value))
    fcntl.ioctl(fd, request, data, True)
    return struct.unpack('i', data)[0]

class Watchdog:
    def __init__(self):
        self.fd = None
        self.memfd = None
        self.mem = None
        self.armed = False

    def arm(self):
        self.memfd = os.open('/dev/mem', os.O_RDWR | os.O_SYNC | os.O_CLOEXEC)
        self.mem = mmap.mmap(self.memfd, 4096, offset=0x11d000)
        self.marker = ctypes.c_uint32.from_buffer(self.mem, 0x534)
        self.reason = ctypes.c_uint32.from_buffer(self.mem, 0x538)
        self.old = self.marker.value, self.reason.value
        self.marker.value, self.reason.value = 0x12345678, 0x12345674
        require((self.marker.value, self.reason.value) == (0x12345678, 0x12345674))
        self.fd = os.open('/dev/watchdog0', os.O_WRONLY | os.O_CLOEXEC)
        # An opened watchdog is already armed even if later ioctl admission fails.
        self.armed = True
        info = bytearray(40)
        fcntl.ioctl(self.fd, 0x80285700, info, True)
        options, firmware, identity = struct.unpack('II32s', info)
        require(identity.split(b'\0')[0] == b'mtk-wdt' and options & 0x100)
        if options & 0x200:
            require(int_ioctl(self.fd, 0xc0045708, 0) == 0)
        require(int_ioctl(self.fd, 0xc0045706, 16) == 16)

    def pet(self):
        require(self.armed)
        require(os.write(self.fd, b'.') == 1)

    def finish(self):
        require(self.armed)
        require(os.write(self.fd, b'V') == 1)
        os.close(self.fd); self.fd = None; self.armed = False
        self.marker.value, self.reason.value = self.old
        require((self.marker.value, self.reason.value) == self.old)
        del self.marker, self.reason
        self.mem.close(); os.close(self.memfd)

    def reset_required(self):
        # Leave recovery markers in place. Closing without V also preserves reset,
        # but staying alive retains inherited administrative resource ownership.
        while True:
            try: time.sleep(1)
            except BaseException: continue

def preflight(config):
    require('a22x.recovery=1' in Path('/proc/cmdline').read_text().split())
    require(struct.unpack_from('<I', Path('/proc/device-tree/chosen/atag,boot').read_bytes(), 8)[0] == 2)
    params = Path('/sys/module/tzdev/parameters')
    require([(params / n).read_text().strip() for n in
             ('early_bootstrap_result', 'deploy_result', 'root_task_probe_result')] == ['0', '-95', '0'])
    from decrypt_runtime.mounts import mount_records
    for mount in mount_records(Path('/proc/self/mountinfo').read_text()):
        require(mount['device'].split(':')[0] == '0' and not mount['mountpoint'].startswith('/mnt/'),
                message='A block filesystem or /mnt mount already exists')
    for path in Path('/sys/block').glob('dm-*/dm/name'):
        require(not path.read_text().strip().startswith(('a22x-c-', 'a22x-data-ro-')))
    fd = os.open('/run/a22x-c-' + config['run_id'] + '.attempted',
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try: os.write(fd, (config['boot_id'] + '\n').encode('ascii'))
    finally: os.close(fd)
