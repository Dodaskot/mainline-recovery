"""Android CE mounting through the qualified native authentication session.

This module never reads a credential. It passes an anonymous native pipe and
accepts only a live, authenticated session receipt. Plain Linux volumes keep
the existing filesystem path. Hardware-bound keys never leave the phone.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import itertools
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time

from android_profiles import SAMSUNG_PROFILE, EVO_PROFILE, LEGACY_EVO_NONE_PROFILE, FRAMEWORK_PINS, validate_profile

PROFILE = Path('/etc/a22x-recovery/android-decrypt.json')
EVO_PROFILE_PATH = Path('/etc/a22x-recovery/android-decrypt-evox16.json')
STATE_DIR = Path('/run/a22x-recovery/android-decrypt')
SESSION = Path('/opt/a22x-recovery/decrypt_session.py')
MAX_PUBLIC = 32768


def fail(code, message, **details):
    from filesystem import fail as filesystem_fail
    filesystem_fail(code, message, **details)


def regular_json(path, maximum=MAX_PUBLIC):
    path = Path(path)
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('Symlink in private state path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != 0
                or s.st_mode & 0o022 or not 0 < s.st_size <= maximum):
            raise ValueError('Untrusted state shape')
        data = os.read(fd, maximum + 1)
        if len(data) != s.st_size:
            raise ValueError('State changed during read')
        return json.loads(data)
    finally:
        os.close(fd)


def profile(profile_id=SAMSUNG_PROFILE):
    if profile_id not in (SAMSUNG_PROFILE, EVO_PROFILE):
        raise ValueError('Unsupported Android profile')
    p = validate_profile(regular_json(PROFILE if profile_id == SAMSUNG_PROFILE else EVO_PROFILE_PATH), profile_id)
    if '#%d ' % p['kernel_build'] not in Path('/proc/version').read_text():
        raise ValueError('Unqualified recovery kernel')
    return p


def public_framework_hash(path):
    """Bounded public firmware read only; never reads any credential/key database."""
    path = Path(path)
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError('Framework symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        if (not stat.S_ISREG(first.st_mode) or first.st_nlink != 1 or
                not 0 < first.st_size <= 64 * 1024 * 1024 or
                not os.fstatvfs(fd).f_flag & os.ST_RDONLY):
            raise ValueError('Framework regular read-only file required')
        digest, total = hashlib.sha256(), 0
        while chunk := os.read(fd, 65536):
            total += len(chunk)
            if total > first.st_size:
                raise ValueError('Framework changed')
            digest.update(chunk)
        last = os.fstat(fd)
        identity = lambda v: (v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        if total != first.st_size or identity(first) != identity(last):
            raise ValueError('Framework changed')
        return digest.hexdigest()
    finally:
        os.close(fd)


def framework_pair(root):
    found = []
    for relative in ('system/framework', 'framework'):
        hashes = []
        for name in ('services.jar', 'framework.jar'):
            try:
                hashes.append(public_framework_hash(Path(root)/relative/name))
            except (FileNotFoundError, NotADirectoryError):
                hashes.append(None)
        if hashes == [None, None]:
            continue
        if None in hashes:
            raise ValueError('Incomplete framework pair')
        found.append(tuple(hashes))
    if len(found) != 1:
        raise ValueError('Ambiguous or missing framework pair')
    return found[0]


def select_current_profile(context):
    """Select an exact public system before bootstrap, through the existing RO manager."""
    system = context.volume('super-system')
    if (system.get('container') != 'super' or system.get('logical_partition') != 'system'
            or system.get('mounted') or system.get('mapping') is not None
            or system.get('write_supported') is not False):
        fail('DECRYPT_PREPARATION_FAILED', 'Unmount the Android system volume before opening Android data.')
    token = system['volume_token']
    owned = False
    try:
        context.mount('super-system', 'ro', False, token)
        owned = True
        current = context.volume('super-system', token)
        if (current.get('mounted') is not True or current.get('read_only') is not True
                or current.get('mount_owner') != 'filesystem' or
                current.get('read_only_guarded') is not True):
            raise ValueError('System RO mount identity')
        pair = framework_pair(current['mountpoint'])
        matches = [ident for ident, expected in FRAMEWORK_PINS.items() if pair == expected]
        if len(matches) != 1:
            import android_compat
            try:
                rom = android_compat.rom_identity(current['mountpoint'])
            except (OSError, ValueError, android_compat.fs.FilesystemError):
                rom = {}
            fail('UNSUPPORTED_PROFILE', 'This Android framework has not been qualified for decryption.',
                 installed_os=rom, services_sha256=pair[0], framework_sha256=pair[1])
        selected = profile(matches[0])
    finally:
        if owned:
            context.unmount('super-system', token)
            after = context.volume('super-system', token)
            if after.get('mounted') or after.get('mapping') is not None:
                raise ValueError('System profile probe cleanup unconfirmed')
    return selected


def write_available(profile_id, credential_type=None):
    """Advisory UI capability; the supervisor admits the actual request."""
    from decrypt_runtime.rw_support import available
    try:
        return available(profile(profile_id), credential_type)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def credential_descriptor(fd):
    if type(fd) is not int or fd < 64:
        fail('CREDENTIAL_REQUIRED', 'Enter the current Android credential to open the data.')
    try:
        st = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if (not stat.S_ISFIFO(st.st_mode) or flags & os.O_ACCMODE != os.O_RDONLY
                or re.fullmatch(r'pipe:\[[0-9]+\]', os.readlink('/proc/self/fd/' + str(fd))) is None):
            raise ValueError('Not an anonymous read pipe')
    except (OSError, ValueError):
        fail('INVALID_CREDENTIAL_CHANNEL', 'The private credential channel is unavailable.')
    return fd


def session_status(context, physical_token=None):
    import decrypt_session
    return decrypt_session.status(str(STATE_DIR), boot_id=context.boot_id,
                                  volume_token=physical_token, mountpoint='/mnt/volumes/userdata')


def preparation_status(context):
    """Advisory denial only: cannot authorize an authenticated or prepared mount."""
    consumed = False
    code = None
    try:
        children = list(itertools.islice(STATE_DIR.iterdir(), 17))
        if len(children) > 16:
            raise ValueError('Preparation state bound')
        for child in children:
            if re.fullmatch(r'gui[0-9a-f]{14}', child.name) is None:
                continue
            shape = child.lstat()
            if (not stat.S_ISDIR(shape.st_mode) or shape.st_uid != 0
                    or stat.S_IMODE(shape.st_mode) != 0o700):
                continue
            for name in ('tee-consumed.json', 'preparation-failure.json'):
                try:
                    marker = regular_json(child / name)
                    if isinstance(marker, dict) and marker.get('boot_id') == context.boot_id:
                        if name == 'tee-consumed.json':
                            consumed = True
                        elif marker.get('code') in ('DECRYPT_BACKUP_SPACE', 'DECRYPT_REBOOT_REQUIRED',
                                                    'DECRYPT_PREPARATION_FAILED'):
                            code = marker['code']
                except (OSError, ValueError, TypeError):
                    pass
    except (OSError, ValueError):
        pass
    # Also recognizes legacy preparations that consumed TEE before these markers existed.
    try:
        base = Path('/sys/module/tzdev/parameters')
        gates = [(base / name).read_text().strip() for name in
                 ('early_bootstrap_result', 'deploy_result', 'root_task_probe_result')]
        consumed |= any(value != '-11' for value in gates)
    except OSError:
        pass
    if consumed:
        reason = ('The EFS safety copy lacked cache space after secure-world preparation; '
                  'free cache space, then restart recovery.' if code == 'DECRYPT_BACKUP_SPACE' else
                  'Secure-world preparation was already used in this boot; restart recovery before trying again.')
        return {'boot_id': context.boot_id, 'unlock_reason': reason}
    return {}


def preflight_reason(context):
    reasons = {
        'DECRYPT_BACKUP_SPACE': 'Cache needs 12 MiB free for the EFS safety copy; free cache space and retry.',
        'DECRYPT_BACKUP_UNAVAILABLE': 'Cache is not ready for an EFS safety copy; authentication has not started.',
        'DECRYPT_STORAGE_BUSY': 'Stop operations using mounted storage before opening Android data.',
        'DECRYPT_PREPARATION_FAILED': 'Android data preparation failed before authentication.',
        'DECRYPT_BACKUP_REVIEW': 'The managed EFS safety-copy directory needs review; no old snapshots were pruned.'}
    try:
        value = regular_json(STATE_DIR.parent / 'android-decrypt-preflight.json')
        if isinstance(value, dict) and value.get('schema') == 'a22x.decrypt.preflight.v1' and value.get('boot_id') == context.boot_id:
            return reasons.get(value.get('code'))
    except (OSError, ValueError, TypeError):
        pass
    return None


def terminal_status(context):
    # Terminal state is advisory only. It can prohibit another attempt, never
    # authorize a mount or assert that CE is open.
    for name in ('state.json', 'session.json'):
        try:
            s = regular_json(STATE_DIR / name)
            if isinstance(s, dict) and s.get('boot_id') == context.boot_id:
                return s
        except (OSError, ValueError, TypeError):
            pass
    return preparation_status(context)


def reusable_available():
    from decrypt_runtime.session_support import available
    try:
        return available(profile(EVO_PROFILE))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError):
        return False

def session_public(receipt, *, mounted):
    from decrypt_runtime.session_support import IDENTITY_FIELDS, auth_required, password_policy, public_mount_failure
    policy = password_policy(ram_only=True)
    result = {key:receipt[key] for key in IDENTITY_FIELDS if key in receipt}
    result.update(session_reusable=True, reusable_session_supported=True, session_retained=True,
        android_password_policy=policy, mount_requires_credential=auth_required(receipt, policy),
        device_offline=False, reboot_required=False, mode_change_requires_reboot=False)
    if mounted is False:
        result.update(filesystem_unmounted=True)
        failure = public_mount_failure(receipt.get('native_mount_failure'))
        if failure is not None:
            result['native_mount_failure'] = failure
    return result

def authentication_result(receipt):
    if receipt.get('session_reusable') is not True:
        return {}
    return {key:receipt[key] for key in ('authentication_id','auth_generation','mount_generation','session_reusable')}

def retained_mount(context, volume, mode, confirmed, credential, *, require_fresh_authentication=False):
    import decrypt_session
    from decrypt_runtime.session_support import auth_required
    try:
        receipt = decrypt_session.detached_status(str(STATE_DIR), boot_id=context.boot_id,
            volume_token=volume['physical_volume_token'], expected_token=volume['volume_token'])
        needs_password = require_fresh_authentication or auth_required(receipt) or credential is not None
        if needs_password:
            credential_descriptor(credential)
            if credential == context.lock_fd:
                fail('INVALID_CREDENTIAL_CHANNEL', 'The password channel aliases the operation lease.')
        result = decrypt_session.retained_request(str(STATE_DIR), common_lock_fd=context.lock_fd,
            expected_token=volume['volume_token'], requested_mode=mode,
            credential=credential, write_confirmed=confirmed if mode == 'rw' else False,
            require_fresh_authentication=require_fresh_authentication, boot_id=context.boot_id)
        mounted = session_status(context, volume['physical_volume_token'])
        observed = context.volume('userdata')
        if (mounted.get('read_only') is not (mode == 'ro') or not observed.get('mounted')
                or observed.get('session_reusable') is not True
                or observed.get('auth_generation') != mounted.get('auth_generation')
                or observed.get('mount_generation') != mounted.get('mount_generation')
                or result.get('authentication_performed') is not needs_password):
            fail('DECRYPT_FAILED', 'The requested native session mount was not independently observed.')
        return {'volume':observed, 'android_user_id':0, 'ce_authenticated':True,
            'requested_mode':mode, 'authentication_performed':needs_password,
            'authentication_run_id':mounted['run_id'], **authentication_result(mounted)}
    except decrypt_session.SessionError as error:
        fail(error.code, error.message, **error.details)
    except (OSError, ValueError, EOFError, TimeoutError):
        fail('DECRYPT_OUTCOME_UNKNOWN', 'The mount result was not confirmed. Refresh the data status.',
            operation='mount', refresh_required=True, retry_allowed=False)
    finally:
        if credential is not None:
            os.close(credential)

def decorate(context, volumes):
    if getattr(context, 'mode', None) != 'device':
        return volumes
    import filesystem
    for v in volumes:
        if (v['id'] != 'userdata' or v.get('external') or v.get('fs_type') not in ('ext4', 'f2fs')
                or not v.get('fscrypt_feature')):
            continue
        kind = filesystem.plain_userdata(context, v)
        if kind:
            # Just formatted for Android and never started, or an Android that encrypts nothing
            # (2026-11-20): read and written as it is, without a decryption session, also in an
            # image without one (the public betas). It may be mounted for writing at once (a
            # tester: only read-only was offered first).
            v['fresh_android_data'] = kind == 'fresh'
            v['unencrypted_android_data'] = kind == 'unencrypted'
            if v.get('read_only_reason_code') == 'FSCRYPT_KEYS_UNAVAILABLE' and v.get('mountable'):
                v.update(write_supported=True, read_only_reason=filesystem.reason_text(None), read_only_reason_code=None,
                         fscrypt_unused=True)
    try:
        p = profile()
    except (OSError, ValueError, TypeError, KeyError):
        return volumes
    for v in volumes:
        if v['id'] != 'userdata' or v.get('external'):
            continue
        if v.get('fs_type') in ('ext4', 'f2fs') and not v.get('fscrypt_feature'):
            continue  # A plain Linux root is not an Android encrypted volume.
        if v.get('fresh_android_data') or v.get('unencrypted_android_data'):
            continue
        from decrypt_runtime.session_support import password_policy
        original = v['volume_token']
        v.update(android_password_policy=password_policy(ram_only=True), mount_requires_credential=True,
                 reusable_session_supported=reusable_available(), session_reusable=False, session_retained=False)
        v.update(decrypt_supported=True, credential_required=True,
                 credential_type='unknown', preparation_required=True, android_user_id=0,
                 decrypt_state='locked', retry_after_seconds=0,
                 unlock_reason='Check the stored Android credential type before entering it.',
                 decrypt_profile_id='pending', decrypt_write_supported=False,
                 # Provisional choices; discovery narrows them before auth.
                 access_modes=['ro', 'rw'] if write_available(EVO_PROFILE) else ['ro'],
                 access_mode_qualification='pending', current_access_mode=None,
                 mode_change_requires_reboot=False, reboot_required=False)
        try:
            s = session_status(context, original)
        except (ImportError, OSError, ValueError, RuntimeError) as error:
            # SessionError derives Exception in the runtime; handle it below
            # without exposing arbitrary exception text or internal paths.
            s = None
        except Exception:
            s = None
        if s is None:
            import decrypt_session
            try:
                retained = decrypt_session.detached_status(str(STATE_DIR), boot_id=context.boot_id,
                                                          volume_token=original)
            except (OSError, ValueError, RuntimeError, KeyError, TypeError):
                retained = None
            if retained is not None:
                v.update(physical_volume_token=original, volume_token=retained['volume_token'],
                    credential_type='password', preparation_required=False,
                    decrypt_profile_id=retained['profile_id'], decrypt_run_id=retained['run_id'],
                    decrypt_supported=True, decrypt_write_supported=write_available(retained['profile_id'],'password'),
                    decrypt_state='session_unmounted', access_modes=['ro','rw'],
                    available_access_modes=['ro','rw'], access_mode_qualification='retained',
                    current_access_mode=None, ce_authenticated=False, fscrypt_policy_verified=False,
                    mounted=False, mountable=False, write_supported=False, reason=None, reason_code=None,
                    **session_public(retained, mounted=False))
                v['credential_required'] = v['mount_requires_credential']
                v['unlock_reason'] = 'Enter the current Android password.' if v['credential_required'] else 'The current recovery session is unlocked.'
                continue
            try:
                import decrypt_session
                pending = decrypt_session.prepared_status(str(STATE_DIR), boot_id=context.boot_id,
                                                          volume_token=original)
            except (OSError, ValueError, RuntimeError, KeyError):
                pending = None
            if pending is not None:
                v['reusable_session_supported'] = pending.get('session_reusable') is True
                if pending.get('session_reusable') is True:
                    v.update(session_public(pending, mounted=None))
                    v['mount_requires_credential'] = True
                v.update(physical_volume_token=original, volume_token=pending['volume_token'],
                         credential_type=pending['credential_type'], preparation_required=False,
                         decrypt_profile_id=pending.get('profile_id', p['profile_id']),
                         decrypt_write_supported=('rw' in pending.get('access_modes', ['ro']) and
                             write_available(pending.get('profile_id', p['profile_id']), pending['credential_type'])),
                         access_modes=[mode for mode in pending.get('access_modes', ['ro']) if mode == 'ro' or
                             write_available(pending.get('profile_id', p['profile_id']), pending['credential_type'])],
                         access_mode_qualification='prepared', current_access_mode=None,
                         decrypt_state='awaiting_credential', decrypt_run_id=pending['run_id'],
                         ce_authenticated=False, fscrypt_policy_verified=False, mounted=False,
                         mountable=False, write_supported=False, reason=None, reason_code=None,
                         unlock_reason='Draw the current Android pattern.' if
                         pending['credential_type'] == 'pattern' else 'Enter the current Android password.')
                continue
            terminal = terminal_status(context)
            if terminal:
                v.update(decrypt_supported=False, decrypt_state='reboot_required',
                         credential_required=False, preparation_required=False, decrypt_write_supported=False,
                         access_modes=[], access_mode_qualification='closed', current_access_mode=None,
                         mode_change_requires_reboot=False, reboot_required=True,
                         unlock_reason=terminal.get('unlock_reason', 'Restart recovery before another authentication session.'))
                timeout = terminal.get('retry_after_seconds', 0)
                if type(timeout) is int and 0 <= timeout <= 4294968:
                    v['retry_after_seconds'] = timeout
            else:
                reason = preflight_reason(context)
                if reason:
                    v['unlock_reason'] = reason
            continue
        device = s.get('device') or s.get('devno')
        if not isinstance(device, str) or re.fullmatch(r'[0-9]+:[0-9]+', device) is None:
            continue
        sysdev = (Path('/sys/dev/block') / device).resolve()
        node = Path('/dev') / sysdev.name
        try:
            st = node.lstat()
            if (not stat.S_ISBLK(st.st_mode) or f'{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}' != device
                    or (sysdev / 'ro').read_text().strip() != ('1' if s.get('read_only', True) else '0')):
                continue
        except OSError:
            continue
        v['decrypt_write_supported'] = write_available(s['profile_id'], s.get('credential_type'))
        read_only = s.get('read_only', True)
        if type(read_only) is not bool:
            continue
        if not read_only and not v['decrypt_write_supported']:
            continue
        token = hashlib.sha256(json.dumps({'physical': original, 'boot': context.boot_id,
            'run': s['run_id'], 'mount_id': s['mount_id'], 'device': device, 'read_only': read_only,
            **({k:s[k] for k in ('authentication_id','auth_generation','mount_generation')} if s.get('session_reusable') is True else {})},
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        v.update(physical_volume_token=original, physical_device=v['device'],
                 physical_path=v['path'], volume_token=token, device=device, path=str(node),
                 fs_type='f2fs', fscrypt_feature=True, mountable=True, mounted=True,
                 mountpoint='/mnt/volumes/userdata', mount_id=s['mount_id'],
                 mount_owner='android-decrypt', read_only=read_only, block_read_only=read_only,
                 read_only_guarded=read_only, write_supported=not read_only,
                 read_only_reason='Android data is open for reading.' if read_only else None,
                 read_only_reason_code='ANDROID_CE_RO' if read_only else None, reason=None, reason_code=None,
                 credential_required=False, preparation_required=False, decrypt_state='mounted',
                 credential_type=s.get('credential_type', 'password'),
                 ce_authenticated=True, fscrypt_policy_verified=True,
                 decrypt_run_id=s['run_id'], decrypt_profile_id=s['profile_id'],
                 access_modes=['ro' if read_only else 'rw'],
                 available_access_modes=['ro', 'rw'] if v['decrypt_write_supported'] else ['ro'],
                 access_mode_qualification='mounted', current_access_mode='ro' if read_only else 'rw',
                 mode_change_requires_reboot=True, reboot_required=False, unlock_reason=None)
        v['reusable_session_supported'] = s.get('session_reusable') is True
        if s.get('session_reusable') is True:
            v.update(session_public(s, mounted=True))
    return volumes


def read_ready(fd, timeout):
    until = time.monotonic() + timeout
    data = bytearray()
    while True:
        left = until - time.monotonic()
        if left <= 0:
            raise TimeoutError('No authenticated mount receipt')
        if not select.select([fd], [], [], min(left, 1))[0]:
            continue
        chunk = os.read(fd, min(4096, MAX_PUBLIC + 1 - len(data)))
        if not chunk:
            if not data:
                raise EOFError('Session ended without a receipt')
            break
        data.extend(chunk)
        if len(data) > MAX_PUBLIC:
            raise ValueError('Oversize receipt')
        if b'\n' in data:
            if data.count(b'\n') != 1 or not data.endswith(b'\n'):
                raise ValueError('Extra receipt data')
            break
    result = json.loads(data)
    if type(result) is not dict or type(result.get('ok')) is not bool:
        raise ValueError('Invalid receipt envelope')
    return result


def mount(context, volume, mode, confirmed, credential_fd, android_user, *, require_fresh_authentication=False):
    if mode not in ('ro', 'rw'):
        fail('WRITE_NOT_QUALIFIED', 'Unknown Android access mode.')
    if android_user != 0:
        fail('UNSUPPORTED_PROFILE', 'This build has qualified Android user 0 only.')
    if type(require_fresh_authentication) is not bool:
        fail('DECRYPT_FAILED', 'The authentication request is invalid.')
    if volume.get('decrypt_state') == 'mounted' and volume.get('session_reusable') is True and (
            require_fresh_authentication or volume.get('read_only') is not (mode == 'ro')):
        from decrypt_runtime.session_support import auth_required
        receipt = session_status(context, volume.get('physical_volume_token'))
        if mode == 'rw' and confirmed is not True:
            fail('CONFIRMATION_REQUIRED', 'Confirm write access before changing the Android mount.')
        if require_fresh_authentication or auth_required(receipt) or credential_fd is not None:
            credential_descriptor(credential_fd)
        # A global EBUSY returns here before the native credential FD is consumed.
        volume = unmount(context, volume)['volume']
    if volume.get('decrypt_state') == 'mounted':
        if require_fresh_authentication:
            fail('DECRYPT_REBOOT_REQUIRED', 'This older native session cannot verify another password without restarting.',
                 reboot_required=True, session_preserved=True)
        if volume.get('read_only') is not (mode == 'ro'):
            fail('DECRYPT_MODE_FIXED',
                 'Android data is already open in another mode. Unmount it and restart recovery to change access.',
                 current_mode='ro' if volume.get('read_only') else 'rw', requested_mode=mode,
                 reboot_required=True, session_preserved=True)
        # Duplicate requests never submit their credential or approve format.
        return {'volume': volume, 'already_mounted': True,
                'authentication_performed': False, 'requested_mode': mode}
    if not volume.get('decrypt_supported'):
        code = 'DECRYPT_REBOOT_REQUIRED' if volume.get('decrypt_state') == 'reboot_required' else 'UNSUPPORTED_PROFILE'
        fail(code, volume.get('unlock_reason') or 'This Android profile has not been qualified.',
             reboot_required=code == 'DECRYPT_REBOOT_REQUIRED')
    if mode == 'rw' and (not write_available(volume.get('decrypt_profile_id'), volume.get('credential_type'))
                         or not volume.get('decrypt_write_supported')):
        fail('WRITE_NOT_QUALIFIED', 'Write access is qualified only for the current Evolution 16 password profile.',
             requested_mode=mode, credential_submitted=False)
    retained = volume.get('decrypt_state') == 'session_unmounted' and volume.get('session_reusable') is True
    if not retained:
        credential_descriptor(credential_fd)
    if credential_fd is not None and credential_fd == context.lock_fd:
        fail('INVALID_CREDENTIAL_CHANNEL', 'The password channel aliases the operation lease.')
    if mode == 'rw':
        if confirmed is not True:
            fail('CONFIRMATION_REQUIRED', 'Confirm write access before submitting the Android credential.')
        if volume.get('decrypt_state') != 'awaiting_credential' and not retained:
            fail('DECRYPT_PREPARATION_REQUIRED', 'Prepare Android read-only before requesting authenticated write access.')
    # A read-only open can replay the F2FS journal on the RAM snapshot (orphans left by
    # Android). That mount turns on F2FS quotas; without the quota format module the kernel
    # flags the quota file for fsck and the native health check refuses the volume before
    # the password is used (seen on the A22x, 2026-11-19). Load the same qualified pair as
    # write access does, with the same ownership receipt, so a later write session adopts it.
    selected, snapshot = None, False
    if mode != 'rw':
        try:
            selected = profile(volume.get('decrypt_profile_id',SAMSUNG_PROFILE))
        except (OSError, ValueError, KeyError, TypeError):
            selected = None  # no readable profile: the open proceeds exactly as before
        session_cap = selected.get('ce_session') if isinstance(selected, dict) else None
        snapshot = (isinstance(session_cap, dict) and 'ram_snapshot_sha256' in session_cap
                    and selected.get('ce_rw') is not None)
    if mode == 'rw' or snapshot:
        from decrypt_runtime.rw_support import quotas
        from decrypt_runtime.common import SessionError
        try:
            if selected is None:
                selected = profile(volume.get('decrypt_profile_id',SAMSUNG_PROFILE))
            quotas(selected.get('ce_rw'), context.boot_id, context.lock_fd, load=True)
        except SessionError as error:
            fail(error.code, error.message, **error.details)
        except (OSError, ValueError, KeyError):
            fail('WRITE_NOT_QUALIFIED' if mode == 'rw' else 'DECRYPT_QUOTA_UNAVAILABLE',
                 'The qualified quota pair could not be loaded; no Android authentication was submitted.')
    if retained:
        return retained_mount(context, volume, mode, confirmed, credential_fd,
                              require_fresh_authentication=require_fresh_authentication)
    if volume.get('decrypt_state') == 'awaiting_credential':
        return authenticate_prepared(context, volume, credential_fd, mode, confirmed)
    from decrypt_prepare import temporary_bootstrap_mounts
    with temporary_bootstrap_mounts(context) as storage_warnings:
        result = mount_fresh(context, volume, credential_fd)
    if storage_warnings:
        result['storage_restore_failed'] = storage_warnings
    return result


def mount_fresh(context, volume, credential_fd):
    try:
        p = select_current_profile(context)
        if p['profile_id'] in (EVO_PROFILE, LEGACY_EVO_NONE_PROFILE):
            fail('CREDENTIAL_NOT_REQUIRED', 'Use credential discovery for this Android profile.')
        from decrypt_prepare import prepare
        config = prepare(context, volume, p)
    except (OSError, ValueError, KeyError) as error:
        fail('DECRYPT_PREPARATION_FAILED', 'Android authentication preparation failed.',
             failure_class=type(error).__name__)
    reader, writer = os.pipe2(os.O_CLOEXEC)
    child = None
    try:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', A22X_RECOVERY_LOCK_FD=str(context.lock_fd))
        child = subprocess.Popen(['/usr/bin/python3', str(SESSION), 'serve', '--config', str(config),
              '--credential-fd', str(credential_fd), '--common-lock-fd', str(context.lock_fd),
              '--ready-fd', str(writer)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
              stderr=subprocess.DEVNULL, close_fds=True,
              pass_fds=(credential_fd, context.lock_fd, writer), start_new_session=True, env=env)
        os.close(writer); writer = -1
        os.close(credential_fd)  # only the native session retains the read endpoint
        result = read_ready(reader, 285)
        if not result['ok']:
            error = result.get('error', {})
            code = error.get('code', 'DECRYPT_FAILED')
            allowed = {'CREDENTIAL_REJECTED', 'RETRY_LATER', 'DECRYPT_REBOOT_REQUIRED',
                       'UNSUPPORTED_PROFILE', 'DECRYPT_FAILED', 'CANCELLED'}
            if code not in allowed:
                code = 'DECRYPT_FAILED'
            details = error.get('details', {})
            if not isinstance(details, dict):
                details = {}
            retry = details.get('retry_after_seconds', 0)
            if type(retry) is not int or not 0 <= retry <= 4294968:
                retry = 0
            messages = {'CREDENTIAL_REJECTED': 'Android did not accept the password.',
                        'RETRY_LATER': 'Android requires a delay before another attempt.',
                        'DECRYPT_REBOOT_REQUIRED': 'Restart recovery before another session.',
                        'UNSUPPORTED_PROFILE': 'This Android credential profile is not supported.',
                        'CANCELLED': 'The Android unlock was cancelled.',
                        'DECRYPT_FAILED': 'Android data could not be opened; no retry was made.'}
            fail(code, messages[code], retry_after_seconds=retry)
        # Independently reread live PID, mount and kernel read-only identity.
        receipt = session_status(context, volume.get('physical_volume_token', volume['volume_token']))
        observed = context.volume('userdata')
        if not observed.get('ce_authenticated') or observed.get('decrypt_state') != 'mounted':
            fail('DECRYPT_FAILED', 'The authenticated Android mount was not observed.')
        return {'volume': observed, 'android_user_id': 0, 'ce_authenticated': True,
                'authentication_performed': True, 'authentication_run_id': receipt['run_id']}
    except (OSError, ValueError, EOFError, TimeoutError) as error:
        # A live supervisor owns uncertain secure calls and its watchdog. Killing
        # it here would not prove cleanup. Losing ready-fd is its cancel signal.
        fail('DECRYPT_FAILED', 'The unlock session did not return a verified mount.',
             failure_class=type(error).__name__)
    finally:
        os.close(reader)
        if writer >= 0:
            os.close(writer)


def prepare_android(context, volume, android_user=0):
    if android_user != 0 or volume.get('id') != 'userdata' or volume.get('external'):
        fail('UNSUPPORTED_PROFILE', 'Only internal Android user 0 is supported.')
    if volume.get('decrypt_state') == 'session_unmounted' and volume.get('session_reusable') is True:
        import decrypt_session
        try:
            decrypt_session.detached_status(str(STATE_DIR), boot_id=context.boot_id, expected_token=volume['volume_token'])
        except decrypt_session.SessionError as error:
            fail(error.code, error.message, **error.details)
        return {'volume':context.volume('userdata'), 'credential_type':'password',
                'ce_authenticated':False, 'already_prepared':True, 'authentication_performed':False}
    if volume.get('decrypt_state') == 'mounted' and volume.get('mounted') is True:
        return {'volume': volume, 'credential_type': volume['credential_type'],
                'ce_authenticated': True, 'already_mounted': True,
                'authentication_performed': False}
    if volume.get('decrypt_state') == 'awaiting_credential':
        import decrypt_session
        try:
            decrypt_session.prepared_status(str(STATE_DIR), boot_id=context.boot_id,
                                            expected_token=volume['volume_token'])
        except decrypt_session.SessionError as error:
            fail(error.code, error.message, **error.details)
        return {'volume': volume, 'credential_type': volume['credential_type'],
                'ce_authenticated': False, 'already_prepared': True,
                'authentication_performed': False}
    if not volume.get('decrypt_supported') or volume.get('mounted'):
        code = 'DECRYPT_REBOOT_REQUIRED' if volume.get('decrypt_state') == 'reboot_required' else 'UNSUPPORTED_PROFILE'
        fail(code, volume.get('unlock_reason') or 'Android preparation is unavailable in this session.',
             reboot_required=code == 'DECRYPT_REBOOT_REQUIRED')
    from decrypt_prepare import temporary_bootstrap_mounts
    with temporary_bootstrap_mounts(context) as storage_warnings:
        result = discover_credential(context, volume, select_current_profile(context))
    if storage_warnings:
        result['storage_restore_failed'] = storage_warnings
    return result


def discover_credential(context, volume, p):
    from decrypt_prepare import prepare
    config = prepare(context, volume, p)
    reader, writer = os.pipe2(os.O_CLOEXEC)
    try:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
                   A22X_RECOVERY_LOCK_FD=str(context.lock_fd))
        subprocess.Popen(['/usr/bin/python3', str(SESSION), 'serve', '--discover',
                          '--config', str(config), '--common-lock-fd', str(context.lock_fd),
                          '--ready-fd', str(writer)], stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          close_fds=True, pass_fds=(context.lock_fd, writer),
                          start_new_session=True, env=env)
        os.close(writer); writer = -1
        reply = read_ready(reader, 285)
        if reply.get('ok') is not True:
            error = reply.get('error', {})
            fail(error.get('code', 'DECRYPT_FAILED'), 'Android credential preparation failed.')
        import decrypt_session
        if (type(reply.get('state')) is dict and reply['state'].get('credential_type') == 'none'
                and p['profile_id'] == EVO_PROFILE):
            receipt = session_status(context, volume['volume_token'])
            observed = context.volume('userdata')
            if (receipt.get('profile_id') != p['profile_id'] or receipt.get('credential_type') != 'none'
                    or receipt.get('native_efs_persistence') is not (p['profile_id'] == EVO_PROFILE)
                    or observed.get('decrypt_state') != 'mounted' or observed.get('mounted') is not True
                    or observed.get('credential_type') != 'none' or observed.get('read_only') is not True
                    or observed.get('ce_authenticated') is not True or observed.get('fscrypt_policy_verified') is not True
                    or observed.get('credential_required') is not False or observed.get('preparation_required') is not False
                    or observed.get('physical_volume_token') != volume['volume_token']):
                fail('DECRYPT_FAILED', 'The authenticated Android mount was not independently observed.')
            return {'volume': observed, 'credential_type': 'none', 'ce_authenticated': True,
                    'fscrypt_policy_verified': True, 'android_user_id': 0}
        receipt = decrypt_session.prepared_status(str(STATE_DIR), boot_id=context.boot_id,
                                                  volume_token=volume['volume_token'])
        observed = context.volume('userdata')
        if (observed.get('decrypt_state') != 'awaiting_credential'
                or observed.get('volume_token') != receipt['volume_token']
                or observed.get('ce_authenticated') is not False):
            fail('DECRYPT_FAILED', 'Prepared Android session was not observed.')
        return {'volume': observed, 'credential_type': receipt['credential_type'],
                'ce_authenticated': False}
    except (OSError, ValueError, EOFError, TimeoutError):
        # Reader closure requests bounded native cleanup; never kill pending SMC.
        fail('DECRYPT_FAILED', 'Android preparation returned no verified type.')
    finally:
        os.close(reader)
        if writer >= 0: os.close(writer)

def authenticate_prepared(context, volume, credential, mode='ro', confirmed=False):
    import decrypt_session
    try:
        result = decrypt_session.prepared_request(str(STATE_DIR),
            common_lock_fd=context.lock_fd, expected_token=volume['volume_token'],
            credential_type=volume['credential_type'], credential=credential,
            boot_id=context.boot_id, requested_mode=mode, write_confirmed=confirmed if mode == 'rw' else False)
        receipt = session_status(context, volume['physical_volume_token'])
        if receipt.get('read_only') is not (mode == 'ro'):
            fail('DECRYPT_FAILED', 'Authenticated Android mount access mode did not match the request.')
        observed = context.volume('userdata')
        if (not observed.get('ce_authenticated') or observed.get('decrypt_state') != 'mounted'
                or observed.get('read_only') is not (mode == 'ro')):
            fail('DECRYPT_FAILED', 'Authenticated Android mount was not observed in the requested access mode.')
        return {'volume': observed, 'android_user_id': 0, 'ce_authenticated': True, 'requested_mode': mode,
                'authentication_performed': True, 'authentication_run_id': receipt['run_id'],
                **authentication_result(receipt)}
    except decrypt_session.SessionError as error:
        fail(error.code, error.message, **error.details)
    except (OSError, ValueError, EOFError):
        fail('DECRYPT_OUTCOME_UNKNOWN',
             'The unlock result was not confirmed. Refresh the data status before taking another action.',
             operation='authenticate', refresh_required=True, retry_allowed=False)
    finally:
        os.close(credential)

def cancel_android_unlock(context, volume, android_user=0):
    if android_user != 0 or volume.get('id') != 'userdata':
        fail('UNSUPPORTED_PROFILE', 'Only internal Android user 0 is supported.')
    import decrypt_session
    if volume.get('session_reusable') is True and volume.get('decrypt_state') in ('mounted','session_unmounted'):
        if volume['decrypt_state'] == 'mounted':
            session_status(context, volume.get('physical_volume_token'))
        else:
            decrypt_session.detached_status(str(STATE_DIR), boot_id=context.boot_id, expected_token=volume['volume_token'])
        return {'volume':context.volume('userdata'), 'cancelled':True, 'session_preserved':True,
                'session_retained':True, 'reboot_required':False, 'authentication_performed':False}
    try:
        result = decrypt_session.prepared_request(str(STATE_DIR),
            common_lock_fd=context.lock_fd, expected_token=volume['volume_token'],
            boot_id=context.boot_id, cancel=True, timeout=55)
    except decrypt_session.SessionError as error:
        fail(error.code, error.message, **error.details)
    except (OSError, ValueError, EOFError):
        fail('DECRYPT_OUTCOME_UNKNOWN',
             'Cancellation was not confirmed. Refresh the data status before taking another action.',
             operation='cancel', refresh_required=True, retry_allowed=False)
    observed = context.volume('userdata')
    return {'volume':observed, 'reboot_required':bool(result.get('reboot_required')),
            'ce_authenticated':False, 'cancelled':True,
            'session_preserved':observed.get('session_retained') is True,
            'session_retained':observed.get('session_retained') is True}

def unmount(context, volume):
    import decrypt_session
    if volume.get('decrypt_state') == 'session_unmounted' and volume.get('session_reusable') is True:
        decrypt_session.detached_status(str(STATE_DIR), boot_id=context.boot_id, expected_token=volume['volume_token'])
        return {'volume':context.volume('userdata'), 'already_unmounted':True, 'filesystem_unmounted':True,
                'session_retained':True, 'reboot_required':False, 'cleanup_verified':False}
    try:
        result = decrypt_session.unmount(str(STATE_DIR), common_lock_fd=context.lock_fd,
                    boot_id=context.boot_id, run_id=volume.get('decrypt_run_id'), timeout=55)
    except decrypt_session.SessionError as error:
        fail(error.code, error.message, **error.details)
    except (OSError, ValueError, EOFError):
        fail('DECRYPT_OUTCOME_UNKNOWN',
             'Unmount completion was not confirmed. Refresh the data status before taking another action.',
             operation='unmount', refresh_required=True, retry_allowed=False)
    observed = context.volume('userdata')
    if observed.get('mounted'):
        fail('UNMOUNT_NOT_OBSERVED', 'The Android data mount is still present.')
    retained = observed.get('session_retained') is True
    return {'volume':observed, 'reboot_required':bool(result.get('reboot_required')),
            'filesystem_unmounted':True, 'session_retained':retained,
            'cleanup_verified':not retained and result.get('cleanup_verified') is True}

def close_session(context, volume):
    """Terminal closure for format, flash, and reboot; ordinary unmount retains RAM."""
    import decrypt_session
    try:
        result = decrypt_session.close_session(str(STATE_DIR), common_lock_fd=context.lock_fd,
            boot_id=context.boot_id, run_id=volume.get('decrypt_run_id'), timeout=55)
    except decrypt_session.SessionError as error:
        fail(error.code, error.message, **error.details)
    except (OSError, ValueError, EOFError, TimeoutError):
        fail('DECRYPT_OUTCOME_UNKNOWN', 'Terminal session close was not confirmed. Refresh the data status.',
            operation='close_session', refresh_required=True, retry_allowed=False)
    observed = context.volume('userdata')
    if (observed.get('mounted') or observed.get('session_retained') is True
            or result.get('cleanup_verified') is not True):
        fail('UNMOUNT_NOT_OBSERVED', 'The Android native session has not fully closed.')
    return {'volume':observed, 'session_closed':True, 'session_retained':False,
            'cleanup_verified':True, 'reboot_required':True}
