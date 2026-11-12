"""One cooperative lease for recovery UI, backups and authorized SSH sessions."""
import contextlib
import errno
import fcntl
import os
from pathlib import Path
import stat

ENV_FD = 'A22X_RECOVERY_LOCK_FD'
DEVICE_LOCK = '/run/lock/a22x-mainline-recovery.lock'
# The leases this process holds now, by lock path. A second flock of the same file through a new
# descriptor would be refused even inside the same process, so a step that needs the lease asks
# held() first and then runs inside the caller's lease (filesystem.py close_logical, 2026-11-12).
_HELD = []


def held(path=DEVICE_LOCK):
    """Whether this process holds the lease for PATH now."""
    return str(Path(path).absolute()) in _HELD


def _regular(fd, path):
    opened = os.fstat(fd)
    named = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode)
            or opened.st_nlink != 1 or named.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
        raise OSError(errno.EINVAL, 'Recovery operation lock changed or is not a regular file')


@contextlib.contextmanager
def operation_lock(path, mode='device'):
    """Yield the held FD. Borrowed inherited leases are never explicitly unlocked.

    FD inheritance coordinates trusted root helpers; it is not a security boundary.
    A helper cannot bypass another session's lock by setting the environment: the
    descriptor must name this exact lock, and flock must still succeed.
    """
    path = Path(path).absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for part in (path, *path.parents):
        if part.is_symlink():
            raise OSError(errno.ELOOP, 'Recovery lock path may not contain a symlink')
    inherited = os.environ.get(ENV_FD) if mode == 'device' else None
    fd = None
    try:
        if inherited is not None:
            if not inherited.isdecimal() or int(inherited) < 3:
                raise OSError(errno.EINVAL, 'Invalid inherited recovery lock descriptor')
            fd = os.dup(int(inherited))
        else:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        _regular(fd, path)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _regular(fd, path)
        _HELD.append(str(path))
        try:
            yield fd
        finally:
            _HELD.remove(str(path))
    finally:
        if fd is not None:
            # Closing the duplicate does not release a parent's shared open-file
            # description. Explicit LOCK_UN here would break the SSH lease.
            os.close(fd)
