"""Public-only wire format, process identity and administrative OFD validation."""
import array
import errno
import fcntl
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import struct
from android_profiles import SAMSUNG_PROFILE, EVO_PROFILE, LEGACY_EVO_NONE_PROFILE, PROFILES, ROOT_MANIFEST_SHA, GATEKEEPERD_SHA, validate_namespace

STATE_DIR = '/run/a22x-recovery/android-decrypt'
LOCK_PATH = '/run/lock/a22x-mainline-recovery.lock'
SCHEMA = 'a22x.android-decrypt.session.v1'
MAX_PACKET = 8192

class SessionError(RuntimeError):
    def __init__(self, code='DECRYPT_FAILED', message='Native CE session failed', details=None):
        super().__init__(message)
        self.code, self.message, self.details = code, message, details or {}
    def envelope(self):
        return dict(ok=False, error=dict(code=self.code, message=self.message, details=self.details))

def require(ok, code='DECRYPT_FAILED', message='Session contract rejected'):
    if not ok:
        raise SessionError(code, message)

def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()

def starttime(pid):
    require(type(pid) is int and pid > 1)
    value = Path('/proc', str(pid), 'stat').read_text()
    # comm can contain spaces and parentheses.
    return int(value[value.rindex(')') + 2:].split()[19])

def same_process(pid, ticks):
    try:
        return type(ticks) is int and starttime(pid) == ticks
    except (OSError, ValueError, SessionError):
        return False

def packet_fds(sock, value, fds=()):
    require(len(fds) <= 2)
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii')
    require(len(data) <= MAX_PACKET)
    ancillary = [] if not fds else [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                    array.array('i', fds))]
    require(sock.sendmsg([data], ancillary) == len(data))

def packet(sock, value, fd=None):
    packet_fds(sock, value, () if fd is None else (fd,))

def receive_fds(sock, maximum=2):
    require(type(maximum) is int and 0 <= maximum <= 2)
    data, ancillary, flags, _ = sock.recvmsg(MAX_PACKET, socket.CMSG_SPACE(16 * 4),
                                            getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
    fds = []
    try:
        for level, kind, raw in ancillary:
            require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS)
            values = array.array('i')
            values.frombytes(raw[:len(raw) - len(raw) % values.itemsize])
            fds.extend(values)
        require(data and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
        require(len(fds) <= maximum)
        value = json.loads(data)
        require(type(value) is dict)
        result, fds = fds, []
        return value, result
    finally:
        for fd in fds:
            os.close(fd)

def receive(sock, allow_fd=False):
    value, fds = receive_fds(sock, int(allow_fd))
    return value, fds[0] if fds else None

def promote_credential(fd):
    # SCM_RIGHTS assigns a fresh numeric descriptor. Native admission requires
    # >=64, so duplicate metadata only; never read or decode the secret frame.
    copy = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 64)
    try:
        credential_fd(copy)
        return copy
    except BaseException:
        os.close(copy)
        raise

def peer_root(sock):
    pid, uid, gid = struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(uid == 0, message='Root session controller required')
    return pid

def validate_lease(fd, path=LOCK_PATH):
    require(type(fd) is int and fd >= 3)
    # Refuse links in every path component before checking exact inode.
    for part in (Path(path), *Path(path).parents):
        require(not part.is_symlink(), message='Lease path contains a symlink')
    opened, named = os.fstat(fd), os.stat(path, follow_symlinks=False)
    require(stat.S_ISREG(opened.st_mode) and stat.S_ISREG(named.st_mode)
            and opened.st_nlink == named.st_nlink == 1
            and (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino),
            message='Lease inode changed')
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SessionError(message='Exclusive recovery lease required') from None
    return opened.st_dev, opened.st_ino

def credential_fd(fd):
    require(type(fd) is int and 64 <= fd <= 4096, message='Credential FD number rejected')
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    require(flags & os.O_ACCMODE == os.O_RDONLY
            and stat.S_ISFIFO(os.fstat(fd).st_mode)
            and re.fullmatch(r'pipe:\[[0-9]+\]', os.readlink('/proc/self/fd/' + str(fd))),
            message='Anonymous credential read FD required')
    # Never read, duplicate into Python bytes, seek, or log the payload.

def public_failure(verdict):
    if type(verdict) is dict and verdict.get('success') is False:
        if verdict.get('failure_stage') == 'unsupported_credential' and verdict.get('error_code') == 'WRITE_NOT_QUALIFIED':
            return SessionError('WRITE_NOT_QUALIFIED', 'This stored Android credential does not support write access', {'reboot_required': True})
        timeout, status = verdict.get('native_timeout_ms'), verdict.get('native_auth_status')
        if type(timeout) is int and timeout > 0 and status == 2:
            return SessionError('RETRY_LATER', 'Native authentication is rate limited',
                                {'retry_after_seconds': math.ceil(timeout / 1000),
                                 'reboot_required': True})
        # Gatekeeper ERROR(1) does not prove a credential mismatch. The
        # qualified public protocol has no distinct wrong-password status.
    return SessionError('DECRYPT_FAILED', 'Native authentication or cleanup contract failed',
                        {'reboot_required': True})

def secure_directory(path, create=False, uid=0):
    """Walk O_NOFOLLOW components; reject writable/unowned final directory."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts)
    current = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=current)
            os.close(current)
            current = child
        info = os.fstat(current)
        require(info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700,
                message='Session directory owner/mode rejected')
        return current
    except BaseException:
        os.close(current)
        raise

def read_json_at(directory, name, uid=0):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uid
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_PACKET,
                message='Session state owner/type/mode rejected')
        data = os.read(fd, MAX_PACKET + 1)
        require(len(data) <= MAX_PACKET)
        return json.loads(data)
    finally:
        os.close(fd)

def atomic_json(directory, name, value):
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii')
    require(len(data) <= MAX_PACKET)
    temporary = name + '.tmp-' + str(os.getpid())
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        require(os.write(fd, data) == len(data))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)

def validate_config(config, actual_boot=None):
    require(type(config) is dict)
    require(config.get('read_only', True) is True, 'UNSUPPORTED_PROFILE',
            'Android preparation must begin read-only')
    profile = config.get('profile_id')
    require(profile in PROFILES
            and type(config.get('android_user_id')) is int and config['android_user_id'] == 0,
            'UNSUPPORTED_PROFILE', 'Only qualified Android user 0 is supported')
    require(config.get('boot_id') == (actual_boot or boot_id()),
            'DECRYPT_REBOOT_REQUIRED', 'Session boot identity changed')
    require(re.fullmatch(r'[a-z0-9]{8,24}', config.get('run_id', '')))
    require(config.get('mountpoint') == '/mnt/volumes/userdata')
    require((profile in (SAMSUNG_PROFILE, EVO_PROFILE) and type(config.get('native_efs_policy')) is dict)
            or (profile == LEGACY_EVO_NONE_PROFILE and 'native_efs_policy' in config
                and config['native_efs_policy'] is None),
            'UNSUPPORTED_PROFILE', 'Profile EFS policy mismatch')
    if profile == EVO_PROFILE:
        try:
            validate_namespace(config.get('gatekeeper_namespace'))
        except ValueError:
            require(False, 'UNSUPPORTED_PROFILE', 'Current Android namespace is not admitted')
        require(config.get('gatekeeperd_sha256') == GATEKEEPERD_SHA, 'UNSUPPORTED_PROFILE', 'Gatekeeper binary identity changed')
    require(type(config.get('volume_token')) is str and 0 < len(config['volume_token']) <= 512)
    require(config.get('root_manifest_sha256') == ROOT_MANIFEST_SHA,
            'UNSUPPORTED_PROFILE', 'Runtime manifest identity changed')
    require(config.get('preparation_mode','ro') in ('ro','rw'), 'UNSUPPORTED_PROFILE', 'Unknown preparation mode')
    require(config.get('preparation_mode','ro') != 'rw' or (profile != LEGACY_EVO_NONE_PROFILE and config.get('ce_rw') is not None), 'WRITE_NOT_QUALIFIED', 'Write preparation is not admitted')
    if config.get('ce_rw') is not None:
        require(profile == EVO_PROFILE, 'WRITE_NOT_QUALIFIED', 'Write access is qualified for the exact Evolution 16 profile only')
        from decrypt_runtime.rw_support import capability
        capability(config['ce_rw'])
    if config.get('ce_session') is not None:
        require(profile == EVO_PROFILE, 'UNSUPPORTED_PROFILE', 'Reusable sessions require the qualified Evolution profile')
        from decrypt_runtime.session_support import capability as session_capability
        session_capability(config['ce_session'])
    require(config.get('state_dir') == STATE_DIR)
