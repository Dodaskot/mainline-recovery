"""Explicit CE write admission and owned loading of the two qualified quotas.

No credential data enters this module. A capability is inert until a fresh
credential request binds rw + confirmation under the normal recovery lease.
"""
import ctypes
import hashlib
import os
from pathlib import Path
import re
import stat

from android_profiles import EVO_PROFILE

from decrypt_runtime.common import (SessionError, require, validate_lease,
    secure_directory, read_json_at, atomic_json)

RW_SCHEMA = 'a22x.android-decrypt.ce-rw.v1'
KERNEL_RELEASE = '7.2.0-a22x-recovery-diag1+'
HELPER = '/system/bin/a22x-data-ce-rw'
HELPER_SHA = 'd53611cc91cbfce31d10429d4e6891237c6e800556c49b1682cae51c8d4a8fe0'
QUOTAS = (
    ('quota_tree', '/lib/modules/quota_tree.ko', '50824bbca9fac1f670c482426345dab6e4ea780aa3da0b04e3cbb85eb0e162e1'),
    ('quota_v2', '/lib/modules/quota_v2.ko', '36a102b5b32f4498cbfad7ea2fb558ff33dd5b20f62a49729f94b29377b91491'))
QUOTA_STATE = '/run/a22x-recovery/ce-rw-quota'


def capability(value):
    require(type(value) is dict and set(value) == {'schema', 'qualified', 'helper',
        'helper_sha256', 'kernel_release', 'quota_modules'}, 'WRITE_NOT_QUALIFIED',
        'The exact CE write capability is not configured')
    require(value['schema'] == RW_SCHEMA and value['qualified'] is True
        and value['helper'] == HELPER and value['kernel_release'] == KERNEL_RELEASE
        and type(value['helper_sha256']) is str
        and value['helper_sha256'] == HELPER_SHA
        and value['quota_modules'] == [dict(name=n, path=p, sha256=h) for n,p,h in QUOTAS],
        'WRITE_NOT_QUALIFIED', 'The CE write profile has not been qualified')
    return value


def qualified_credential(profile_id, credential_type):
    # Only this firmware/credential completed the retained durability cycle.
    return profile_id == EVO_PROFILE and credential_type == 'password'


def available(profile, credential_type=None):
    if type(profile) is not dict or profile.get('profile_id') != EVO_PROFILE:
        return False
    if credential_type is not None and not qualified_credential(profile['profile_id'], credential_type):
        return False
    try:
        capability(profile.get('ce_rw'))
        return True
    except SessionError:
        return False


def pinned_fd(path, expected, executable=False):
    for item in (Path(path), *Path(path).parents):
        require(not item.is_symlink(), message='RW public runtime pin contains a symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o022 and 0 < before.st_size <= 8*1024*1024
                and (not executable or bool(before.st_mode & 0o111)),
                message='RW public runtime pin shape rejected')
        digest = hashlib.sha256()
        while chunk := os.read(fd, 65536):
            digest.update(chunk)
        after = os.fstat(fd)
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
                and digest.hexdigest() == expected, message='RW public runtime pin mismatch')
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def module_identity(name):
    path = Path('/sys/module') / name
    if not path.exists():
        return None
    require((path/'initstate').read_text().strip() == 'live', message='Quota module is not live')
    return path.stat().st_ino


def finit_module(fd):
    machine = os.uname().machine
    require(machine in ('aarch64', 'x86_64'), message='Unsupported quota loader architecture')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    number = 273 if machine == 'aarch64' else 313
    if libc.syscall(ctypes.c_long(number), ctypes.c_int(fd), ctypes.c_char_p(b''), ctypes.c_int(0)):
        raise OSError(ctypes.get_errno(), 'Qualified quota module load failed')


def quotas(value, boot, lease, load=False):
    """A preloaded module without our boot+pin+sysfs identity is never adopted."""
    value = capability(value)
    validate_lease(lease)
    require(os.geteuid() == 0 and os.uname().release == value['kernel_release'],
            'WRITE_NOT_QUALIFIED', 'CE write kernel or loader identity changed')
    fds=[]
    directory=None
    try:
        for _,path,digest in QUOTAS:
            fds.append(pinned_fd(path,digest))
        directory=secure_directory(QUOTA_STATE, create=load)
        try:
            receipt=read_json_at(directory,'owned.json')
        except FileNotFoundError:
            receipt={'schema':'a22x.ce-rw.quota.v1','boot_id':boot,
                'kernel_release':value['kernel_release'],'modules':[]}
        require(type(receipt) is dict and set(receipt)=={'schema','boot_id','kernel_release','modules'}
            and receipt['schema']=='a22x.ce-rw.quota.v1' and receipt['boot_id']==boot
            and receipt['kernel_release']==value['kernel_release'] and type(receipt['modules']) is list
            and len(receipt['modules'])<=2, message='Quota ownership receipt changed')
        for i,(name,path,digest) in enumerate(QUOTAS):
            actual=module_identity(name)
            owned=receipt['modules'][i] if i<len(receipt['modules']) else None
            if owned is not None:
                require(owned==dict(name=name,path=path,sha256=digest,sysfs_inode=actual)
                    and type(actual) is int, message='Owned quota module identity changed')
                continue
            require(actual is None, message='Unexpected preloaded quota module refused')
            require(load, 'WRITE_NOT_QUALIFIED', 'Qualified quotas are not loaded')
            finit_module(fds[i])
            actual=module_identity(name)
            require(type(actual) is int, message='Quota load was not observed')
            receipt['modules'].append(dict(name=name,path=path,sha256=digest,sysfs_inode=actual))
            atomic_json(directory,'owned.json',receipt)
        return receipt
    finally:
        for fd in fds: os.close(fd)
        if directory is not None: os.close(directory)
