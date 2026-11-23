"""Strict global bind and mount identity, without opening any CE files."""
import ctypes
import errno
import fcntl
import stat
import os
from pathlib import Path
import re
from decrypt_runtime.common import SessionError, require, same_process

MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
MS_REMOUNT, MS_BIND = 32, 4096

def secure_mountpoint(path):
    require(Path(path).is_absolute() and '..' not in Path(path).parts)
    current = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in Path(path).parts[1:]:
            try: os.mkdir(part, 0o700, dir_fd=current)
            except FileExistsError: pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=current)
            os.close(current); current = child
            info = os.fstat(current)
            require(info.st_uid == 0 and not info.st_mode & 0o022,
                    message='Unsafe session mountpoint component')
        require(not os.listdir(current), message='Session mountpoint is not empty')
    finally:
        os.close(current)

def unescape(value):
    return re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), value)

def mount_records(text):
    records = []
    for line in text.splitlines():
        left, separator, right = line.partition(' - ')
        require(bool(separator), message='Malformed mountinfo')
        before, after = left.split(), right.split()
        require(len(before) >= 6 and len(after) >= 3)
        records.append({'mount_id': int(before[0]), 'device': before[2],
                        'root': unescape(before[3]), 'mountpoint': unescape(before[4]),
                        'options': set(before[5].split(',')), 'fstype': after[0],
                        'super_options': set(after[2].split(','))})
    return records

def mounted_at(path, text=None):
    if text is None:
        text = Path('/proc/self/mountinfo').read_text()
    found = [m for m in mount_records(text) if m['mountpoint'] == path]
    require(len(found) == 1, message='Expected one exact session mount')
    return found[0]

def access_flags(info, read_only):
    require(type(read_only) is bool)
    mode,other=('ro','rw') if read_only else ('rw','ro')
    return ({mode,'nosuid','nodev','noexec'} <= info['options']
        and other not in info['options'] and mode in info['super_options']
        and other not in info['super_options'])

def verify_mount(receipt, text=None):
    info = mounted_at(receipt['mountpoint'], text)
    require(info['mount_id'] == receipt['mount_id']
            and info['device'] == receipt['device'] and info['root'] == '/'
            and info['fstype'] == 'f2fs'
            and access_flags(info, receipt.get('read_only',True)),
            message='Session mount identity or read-only flags changed')
    return info

TREE_SCHEMA = 'a22x.android-decrypt.mount-transfer.v1'
AT_FDCWD, OPEN_TREE_CLONE, MOVE_MOUNT_F_EMPTY_PATH = -100, 1, 4

def syscall(number, *arguments):
    require(os.uname().machine in ('aarch64', 'x86_64'),
            'UNSUPPORTED_PROFILE', 'Mount syscall architecture unsupported')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(ctypes.c_long(number), *arguments)
    if result < 0:
        raise OSError(ctypes.get_errno(), 'Detached mount transfer syscall failed')
    return result

def fd_mount_id(fd):
    text = Path('/proc/self/fdinfo', str(fd)).read_text()
    values = [line.split(':', 1)[1].strip() for line in text.splitlines()
              if line.startswith('mnt_id:')]
    require(len(values) == 1 and values[0].isdecimal(), message='Mount FD identity missing')
    return int(values[0])

def tree_fd_shape(fd, proof, source):
    require(type(fd) is int and fd >= 3 and type(proof) is dict
            and proof.get('schema') == TREE_SCHEMA)
    require(set(proof) == {'schema', 'source_mount_id', 'detached_mount_id',
                          'device', 'root_inode', 'root', 'fstype', 'read_only'})
    opened = os.fstat(fd)
    require(stat.S_ISDIR(opened.st_mode)
            and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_PATH
            and fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
            message='Detached O_PATH mount FD required')
    require(proof['device'] == source['device'] ==
            str(os.major(opened.st_dev)) + ':' + str(os.minor(opened.st_dev))
            and proof['source_mount_id'] == source['mount_id']
            and proof['root_inode'] == opened.st_ino == source['root_inode']
            and proof['root'] == source['root'] == '/'
            and proof['fstype'] == source['fstype']
            and type(source.get('read_only')) is bool
            and proof['read_only'] is source['read_only']
            and bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY) is source['read_only'],
            message='Detached mount source/readonly identity changed')
    identity = fd_mount_id(fd)
    require(proof['detached_mount_id'] == identity != source['mount_id'])
    require(not any(m['mount_id'] == identity for m in
                    mount_records(Path('/proc/self/mountinfo').read_text())),
            message='Transferred mount FD is already attached')

def export_tree(target, read_only=True):
    target = str(target)
    source = mounted_at(target)
    source['root_inode'] = os.stat(target, follow_symlinks=False).st_ino
    source['read_only']=read_only
    require(source['root'] == '/' and source['fstype'] == 'f2fs'
            and access_flags(source,read_only),
            message='Authenticated f2fs source access flags changed')
    fd = syscall(428, ctypes.c_int(AT_FDCWD), ctypes.c_char_p(target.encode()),
                 ctypes.c_uint(OPEN_TREE_CLONE | os.O_CLOEXEC))
    try:
        opened = os.fstat(fd)
        proof = {'schema': TREE_SCHEMA, 'source_mount_id': source['mount_id'],
                 'detached_mount_id': fd_mount_id(fd), 'device': source['device'],
                 'root_inode': opened.st_ino, 'root': '/', 'fstype': 'f2fs', 'read_only': read_only}
        tree_fd_shape(fd, proof, source)
        return fd, proof
    except BaseException:
        os.close(fd)
        raise

class Mounts:
    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                   ctypes.c_ulong, ctypes.c_char_p]
        self.libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]

    def call(self, source, target, flags):
        if self.libc.mount(source.encode() if source else None, target.encode(), None, flags, None):
            raise OSError(ctypes.get_errno(), 'Session bind mount failed')

    def bind(self, worker_pid, worker_ticks, run_id, target, tree_fd, proof, read_only=True):
        require(same_process(worker_pid, worker_ticks), message='Worker PID identity changed')
        source_path = '/run/a22x-c-' + run_id + '/root/mnt/userdata-ro'
        source = mounted_at(source_path, Path('/proc', str(worker_pid), 'mountinfo').read_text())
        source['root_inode'] = os.stat('/proc/' + str(worker_pid) + '/root' + source_path,
                                      follow_symlinks=False).st_ino
        source['read_only']=read_only
        require(source['root'] == '/' and source['fstype'] == 'f2fs'
                and access_flags(source,read_only),
                message='Worker CE f2fs access mode mismatch')
        tree_fd_shape(tree_fd, proof, source)
        root_info = os.stat('/proc/' + str(worker_pid) + '/root' + source_path)
        require((root_info.st_dev, root_info.st_ino) ==
                (os.fstat(tree_fd).st_dev, proof['root_inode']),
                message='Detached mount is not the exact owned worker root')
        require(not any(m['mountpoint'] == target for m in
                        mount_records(Path('/proc/self/mountinfo').read_text())),
                message='Global userdata target is already mounted')
        require(os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/' + str(worker_pid) + '/ns/mnt'),
                message='Worker did not enter private mount namespace')
        secure_mountpoint(target)
        # A proc-root MS_BIND of the foreign source fails may_copy_tree(EINVAL).
        # Only a detached mount cloned inside the worker NS can cross here.
        require(same_process(worker_pid, worker_ticks), message='Worker changed during mount handoff')
        syscall(429, ctypes.c_int(tree_fd), ctypes.c_char_p(b''), ctypes.c_int(AT_FDCWD),
                ctypes.c_char_p(target.encode()), ctypes.c_uint(MOVE_MOUNT_F_EMPTY_PATH))
        try:
            self.call(None, target, MS_BIND | MS_REMOUNT | (MS_RDONLY if read_only else 0) | MS_NOSUID | MS_NODEV | MS_NOEXEC)
            actual = mounted_at(target)
            require(actual['device'] == source['device'] and actual['root'] == source['root'])
            receipt = {'mountpoint': target, 'mount_id': actual['mount_id'], 'device': actual['device'], 'read_only':read_only}
            verify_mount(receipt)
            return receipt
        except BaseException:
            # The descriptor now pins the attached mount and would itself make
            # a normal unmount EBUSY. The caller closes it before safe rollback.
            raise

    def unmount(self, target):
        # Never MNT_DETACH or MNT_FORCE. EBUSY leaves the held CE session intact.
        if self.libc.umount2(target.encode(), 0):
            raise OSError(ctypes.get_errno(), 'Normal session unmount failed')
        require(not any(m['mountpoint'] == target for m in mount_records(Path('/proc/self/mountinfo').read_text())),
                message='Global session mount remains after unmount')
