#!/usr/bin/python3
"""Current Android password authorization for userdata formatting.

This module never reads a password. Fresh native FD authentication opens CE
read-only; an expiring, one-use RAM grant authorizes one separately confirmed
format/reset. A normal existing mount is never a new password verification.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import time

import filesystem as fs
import operation_lock

STATE_DIR = Path('/run/a22x-recovery/format-authorization')
SCHEMA = 'a22x.android-format-authorization.v2'
INITIALIZED_SCHEMA = 'a22x.userdata-initialized.v1'
TTL_SECONDS = 120
MOUNT = '/mnt/volumes/userdata'
GET_POLICY_EX = 0xc0096616
SESSION_FIELDS = ('boot_id', 'run_id', 'physical_volume_token', 'profile_id',
                  'android_user_id', 'credential_type', 'supervisor_pid',
                  'supervisor_starttime', 'worker_pid', 'worker_starttime',
                  'mount_id', 'device', 'read_only', 'requested_mode')
REUSABLE_FIELDS = ('session_reusable', 'authentication_id', 'auth_generation', 'mount_generation')
RESTART = ('This Android profile needs a new recovery session for password verification. '
           'Restart recovery, then choose Format Data before opening Android data.')
UNAVAILABLE = ('The current Android password cannot be verified for this data. '
               'Formatting is blocked; missing or damaged encryption metadata is not authorization.')


def require(ok, code, message):
    if not ok:
        fs.fail(code, message)


def protected(volume):
    """An uncertain or encrypted userdata is never guessed to be unprotected."""
    if volume.get('id') != 'userdata':
        return False
    if ((volume.get('fresh_android_data') is True or volume.get('unencrypted_android_data') is True)
            and volume.get('fs_type') == 'f2fs' and not volume.get('decrypt_state')):
        return False  # just formatted, or Android data without encryption: no password protects it
    return not (volume.get('fs_type') in ('ext4', 'f2fs')
                and volume.get('fscrypt_feature') is False
                and volume.get('encrypted_container') is not True
                and not volume.get('decrypt_state')
                and not volume.get('decrypt_supported')
                and not volume.get('ce_authenticated'))


def physical(volume):
    result = {key: volume.get(key) for key in
              ('id', 'device_identity', 'partition_number', 'size_bytes', 'filesystem_uuid')}
    result.update(path=volume.get('physical_path', volume.get('path')),
                  device=volume.get('physical_device', volume.get('device')),
                  token=volume.get('physical_volume_token', volume.get('volume_token')))
    require(result['id'] == 'userdata' and result['partition_number'] == 54
            and result['path'] == '/dev/mmcblk0p54'
            and type(result['size_bytes']) is int and result['size_bytes'] > 0,
            'FORMAT_TARGET_CHANGED', 'The internal userdata identity is unavailable.')
    fs.require_hash(result['device_identity'], 'device-identity')
    fs.require_hash(result['token'], 'physical-volume-token')
    return result


def _ram_directory(create=False):
    from decrypt_runtime.common import secure_directory
    matches = [m for m in fs.read_mounts()
               if str(STATE_DIR).startswith(m['mountpoint'].rstrip('/') + '/')]
    require(matches and max(matches, key=lambda m: len(m['mountpoint']))['fs_type']
            in ('rootfs', 'ramfs', 'tmpfs'), 'FORMAT_RAM_REQUIRED',
            'Format authorization must stay in recovery memory.')
    return secure_directory(STATE_DIR, create=create)


def _write_record(name, value):
    directory = _ram_directory(create=True)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        try:
            raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
            require(os.write(fd, raw) == len(raw), 'FORMAT_STATE_FAILED',
                    'Format authorization could not be saved.')
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_record(name):
    directory = _ram_directory()
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 16384,
                    'FORMAT_STATE_INVALID', 'The format authorization record is invalid.')
            raw = os.read(fd, 16385)
            require(len(raw) == info.st_size, 'FORMAT_STATE_INVALID',
                    'The format authorization record changed.')
            value = json.loads(raw)
            require(type(value) is dict, 'FORMAT_STATE_INVALID',
                    'The format authorization record is invalid.')
            return value
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def _used(token):
    directory = _ram_directory()
    try:
        try:
            os.stat(token + '.used', dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            try:
                os.stat(token + '.attempted', dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return False
        return True
    finally:
        os.close(directory)


def _token(token):
    require(isinstance(token, str) and re.fullmatch('[0-9a-f]{64}', token) is not None,
            'FORMAT_AUTH_REQUIRED', 'Verify the current Android password before formatting userdata.')
    return token


def _held(context):
    require(context.mode == 'device' and operation_lock.held(context.lock_path),
            'FORMAT_LEASE_REQUIRED', 'Formatting requires the recovery operation lease.')


@contextmanager
def writer_lease(context):
    """Use the normal caller lease, or acquire it for a direct backend call."""
    if context.mode != 'device':
        yield
        return
    if not operation_lock.held(context.lock_path):
        with context.operation_lock():
            yield
        return
    previous = getattr(context, 'lock_fd', None)
    inherited = os.environ.get(operation_lock.ENV_FD)
    if previous is None and inherited is not None and inherited.isdecimal():
        from decrypt_runtime.common import validate_lease
        fd = int(inherited)
        validate_lease(fd)
        context.lock_fd = fd
    try:
        yield
    finally:
        if previous is None and hasattr(context, 'lock_fd'):
            del context.lock_fd


def _native_lease(context):
    _held(context)
    from decrypt_runtime.common import validate_lease, SessionError
    try:
        validate_lease(getattr(context, 'lock_fd', None))
    except (OSError, ValueError, TypeError, SessionError):
        fs.fail('FORMAT_LEASE_REQUIRED', 'Formatting requires the current recovery operation lease.')


def _policy(receipt):
    """Public fscrypt policy identity only; never reads key material or file data."""
    from decrypt_runtime.mounts import fd_mount_id
    path = fs.absolute_no_symlinks(MOUNT + '/media/0')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(fd_mount_id(fd) == receipt['mount_id']
                and f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}' == receipt['device']
                and bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY),
                'FORMAT_SESSION_CHANGED', 'The authenticated read-only mount changed.')
        value = bytearray(32)
        struct.pack_into('=Q', value, 0, 24)
        fcntl.ioctl(fd, GET_POLICY_EX, value, True)
        require(struct.unpack_from('=Q', value)[0] == 24 and value[8] == 2,
                'FORMAT_POLICY_UNSUPPORTED', 'The Android encryption policy is unsupported.')
        return hashlib.sha256(value[8:32]).hexdigest()
    finally:
        os.close(fd)


def _session(context, volume):
    import android_decrypt
    try:
        receipt = android_decrypt.session_status(context, physical(volume)['token'])
    except Exception as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        fs.fail('FORMAT_SESSION_CHANGED', 'The password-authenticated Android session is unavailable.')
    require(receipt.get('state') == 'mounted' and receipt.get('boot_id') == context.boot_id
            and receipt.get('android_user_id') == 0 and receipt.get('credential_type') == 'password'
            and receipt.get('read_only') is True and receipt.get('requested_mode') == 'ro'
            and receipt.get('ce_authenticated') is True
            and receipt.get('fscrypt_policy_verified') is True,
            'FORMAT_SESSION_CHANGED', 'The freshly password-authenticated read-only session is unavailable.')
    session = {key: receipt[key] for key in SESSION_FIELDS}
    if receipt.get('session_reusable') is True:
        require(isinstance(receipt.get('authentication_id'), str)
                and re.fullmatch('[0-9a-f]{32}', receipt['authentication_id']) is not None
                and all(type(receipt.get(key)) is int and receipt[key] > 0
                        for key in ('auth_generation', 'mount_generation')),
                'FORMAT_SESSION_CHANGED', 'The native authentication identity is unavailable.')
        session.update({key: receipt[key] for key in REUSABLE_FIELDS})
    return session, _policy(receipt)


def initialized(context, volume):
    """A factual post-erase receipt, never a fallback for unknown Android data."""
    if context.mode != 'device' or volume.get('id') != 'userdata':
        return False
    # An observed credential session takes priority over any post-erase hint.
    if volume.get('ce_authenticated') or volume.get('decrypt_state') == 'awaiting_credential':
        return False
    try:
        p = physical(volume)
        record = _read_record('initialized-' + p['token'] + '.json')
        return (record.get('schema') == INITIALIZED_SCHEMA
                and record.get('boot_id') == context.boot_id
                and record.get('physical') == p
                and volume.get('fs_type') in ('ext4', 'f2fs')
                and bool(volume.get('filesystem_uuid')))
    except (OSError, ValueError, KeyError, fs.FilesystemError):
        return False


# What init recorded of misc when the recovery started (bcb.py arrive).
BCB_ARRIVAL = Path('/run/a22x-recovery/bcb.json')


def android_requested_reset(context, arrival=None):
    """Android's own factory reset (2026-11-21, the owner: data this recovery cannot decrypt is still
    erased that way, as AOSP's and Samsung's recoveries do): Android's Settings checked the owner's
    credential, wrote "--wipe_data" to misc and restarted into this recovery. The request must have
    been in misc when the recovery started (init's record) and still be there, the same; this recovery
    never writes one. "--prompt_and_wipe_data" (Android could not open its data) is no checked request
    and keeps asking for the password."""
    import bcb
    try:
        arrived = json.loads(Path(arrival or BCB_ARRIVAL).read_text())
        now = bcb.request(context) if arrived.get('source') == 'cache' else bcb.read(bcb.misc_path(context))
    except (OSError, ValueError, AttributeError):
        return False

    def asked(found):
        lines = found.get('recovery') if isinstance(found, dict) else None
        return (isinstance(lines, list) and found.get('command') == 'boot-recovery'
                and '--wipe_data' in lines and '--prompt_and_wipe_data' not in lines)
    return (not arrived.get('consumed') and asked(arrived) and asked(now)
            and arrived.get('recovery') == now.get('recovery'))


def consume_android_reset(arrival=None):
    """After the reset: the request recorded at the start authorizes nothing more in this session."""
    path = Path(arrival or BCB_ARRIVAL)
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError):
        return
    if isinstance(record, dict) and record.get('wipe'):
        record['consumed'] = True
        path.write_text(json.dumps(record, separators=(',', ':')) + '\n')


def needs_authorization(context, volume):
    return protected(volume) and not initialized(context, volume)


def annotate(context, volumes):
    for volume in volumes:
        if volume.get('id') != 'userdata':
            continue
        if not needs_authorization(context, volume):
            state, reason = 'not_required', 'No protected Android credential is present in the identified data.'
        elif volume.get('credential_type') in ('none', 'pattern'):
            state, reason = 'unavailable', 'This format flow requires a stored Android password or PIN; no-password and pattern profiles are not admitted.'
        elif volume.get('decrypt_state') == 'reboot_required':
            state, reason = 'restart_required', RESTART
        elif (volume.get('session_reusable') is True
              and volume.get('decrypt_state') in ('mounted', 'session_unmounted')):
            state, reason = 'required', 'Verify the current Android password again before confirming Format Data.'
        elif volume.get('mounted') or volume.get('decrypt_state') == 'mounted':
            state, reason = 'restart_required', RESTART
        elif (volume.get('decrypt_supported') and volume.get('decrypt_state') in ('locked', 'awaiting_credential')
              and volume.get('credential_type') in ('unknown', 'password')):
            state, reason = 'required', 'Verify the current Android password before confirming Format Data.'
        else:
            state, reason = 'unavailable', UNAVAILABLE
        volume.update(format_auth_state=state, format_auth_reason=reason)
    return volumes


def authorize(context, volume, fs_type, purpose, credential_fd, android_user=0):
    _native_lease(context)
    require(volume.get('id') == 'userdata' and android_user == 0
            and fs_type in ('ext4', 'f2fs') and purpose in ('format', 'android-reset')
            and (purpose != 'android-reset' or fs_type == 'f2fs'),
            'FORMAT_INTENT_INVALID', 'Select userdata and the intended formatting operation.')
    require(volume.get('credential_type') not in ('none', 'pattern'),
            'FORMAT_CREDENTIAL_UNSUPPORTED',
            'This format flow requires the stored Android password or PIN. No-password and pattern profiles are not admitted.')
    reusable = volume.get('session_reusable') is True
    state = volume.get('decrypt_state')
    require(state != 'reboot_required'
            and (reusable or (not volume.get('mounted') and state != 'mounted')),
            'FORMAT_AUTH_RESTART_REQUIRED', RESTART)
    require(volume.get('decrypt_supported') is True
            and (state == 'awaiting_credential'
                 or (reusable and state in ('mounted', 'session_unmounted'))),
            'FORMAT_PREPARATION_REQUIRED', 'Prepare Android credential verification before entering its password.')
    require(volume.get('credential_type') == 'password',
            'FORMAT_CREDENTIAL_UNSUPPORTED',
            'This format flow requires the stored Android password or PIN. No-password and pattern profiles are not admitted.')
    before = physical(volume)
    run = volume.get('decrypt_run_id')
    profile = volume.get('decrypt_profile_id')
    import android_decrypt
    previous_auth = None
    if reusable and state in ('mounted', 'session_unmounted'):
        # Each reader verifies its own actual state. The mounted-only reader
        # must never be used for a retained, fully unmounted filesystem.
        import decrypt_session
        try:
            if state == 'session_unmounted':
                previous = decrypt_session.detached_status(str(android_decrypt.STATE_DIR),
                    boot_id=context.boot_id, volume_token=before['token'],
                    expected_token=volume['volume_token'])
            else:
                previous = android_decrypt.session_status(context, before['token'])
        except (decrypt_session.SessionError, OSError, ValueError, KeyError, TypeError):
            fs.fail('FORMAT_SESSION_CHANGED', 'The current reusable Android session changed.')
        require(previous.get('session_reusable') is True
                and previous.get('boot_id') == context.boot_id
                and previous.get('physical_volume_token') == before['token']
                and previous.get('android_user_id') == 0
                and previous.get('credential_type') == 'password'
                and previous.get('run_id') == run and previous.get('profile_id') == profile
                and previous.get('state') == state,
                'FORMAT_SESSION_CHANGED', 'The current reusable Android session changed.')
        generation, identity = previous.get('auth_generation'), previous.get('authentication_id')
        if type(generation) is int and generation > 0:
            require(isinstance(identity, str)
                    and re.fullmatch('[0-9a-f]{32}', identity) is not None,
                    'FORMAT_SESSION_CHANGED', 'The current native authentication identity changed.')
            previous_auth = (identity, generation)
        else:
            # Startup/first-use preparation can be cancelled before any password
            # was accepted. A fully suspended, never-authenticated session may
            # still verify a fresh password without rebooting recovery.
            require(type(generation) is int and generation == 0 and identity is None
                    and state == 'session_unmounted'
                    and previous.get('key_retained') is False
                    and previous.get('ce_authenticated') is False
                    and previous.get('fscrypt_policy_verified') is False,
                    'FORMAT_SESSION_CHANGED', 'The unauthenticated Android session changed.')
    result = android_decrypt.mount(context, volume, 'ro', False, credential_fd, android_user,
                                   require_fresh_authentication=True)
    observed = context.volume('userdata')
    session, policy = _session(context, observed)
    require(result.get('authentication_performed') is True
            and result.get('authentication_run_id') == run
            and session['run_id'] == run and session['profile_id'] == profile
            and physical(observed) == before,
            'FORMAT_AUTH_NOT_FRESH', 'A new verification of the current Android password is required.')
    if reusable or session.get('session_reusable') is True:
        require(session.get('session_reusable') is True
                and isinstance(session.get('authentication_id'), str)
                and re.fullmatch('[0-9a-f]{32}', session['authentication_id']) is not None
                and all(type(session.get(key)) is int and session[key] > 0
                        for key in ('auth_generation', 'mount_generation'))
                and result.get('session_reusable') is True
                and observed.get('session_reusable') is True
                and all(type(obj.get(key)) is int for obj in (result, observed)
                        for key in ('auth_generation', 'mount_generation'))
                and all(result.get(key) == session[key] for key in REUSABLE_FIELDS)
                and all(observed.get(key) == session[key] for key in REUSABLE_FIELDS)
                and (previous_auth is None
                     or (session['authentication_id'] != previous_auth[0]
                         and session['auth_generation'] > previous_auth[1])),
                'FORMAT_AUTH_NOT_FRESH', 'A new native verification of the current Android password is required.')
    token, created = secrets.token_hex(32), time.monotonic()
    record = dict(schema=SCHEMA, boot_id=context.boot_id, purpose=purpose, fs=fs_type,
                  physical=before, session=session, policy_sha256=policy,
                  created_monotonic=created, expires_monotonic=created + TTL_SECONDS)
    _write_record(token + '.json', record)
    return dict(volume=observed, format_authorization=token, format_purpose=purpose,
                format_fs=fs_type, format_volume_token=before['token'],
                expires_in_seconds=TTL_SECONDS, authentication_performed=True,
                authentication_run_id=run, ce_authenticated=True, fscrypt_policy_verified=True,
                **{key: session[key] for key in REUSABLE_FIELDS if key in session})


def validate(context, volume, fs_type, purpose, token):
    _native_lease(context)
    token = _token(token)
    try:
        record = _read_record(token + '.json')
        consumed = _used(token)
    except (OSError, ValueError):
        fs.fail('FORMAT_AUTH_INVALID', 'Format authorization is missing or invalid. No data was erased.')
    now = time.monotonic()
    require(not consumed, 'FORMAT_AUTH_CONSUMED', 'This formatting authorization was already used or cancelled.')
    require(record.get('schema') == SCHEMA and record.get('boot_id') == context.boot_id
            and record.get('purpose') == purpose and record.get('fs') == fs_type,
            'FORMAT_AUTH_MISMATCH', 'Format authorization belongs to another boot or operation.')
    start, end = record.get('created_monotonic'), record.get('expires_monotonic')
    require(type(start) in (int, float) and type(end) in (int, float)
            and math.isfinite(start) and math.isfinite(end)
            and 0 <= start <= now < end <= start + TTL_SECONDS,
            'FORMAT_AUTH_EXPIRED', 'Format authorization expired. Verify the Android password again.')
    require(record.get('physical') == physical(volume),
            'FORMAT_TARGET_CHANGED', 'The authorized userdata volume changed.')
    session, policy = _session(context, volume)
    require(record.get('session') == session and record.get('policy_sha256') == policy,
            'FORMAT_SESSION_CHANGED', 'The authenticated Android session or encryption policy changed.')
    return record


def preflight(context, volume, fs_type, purpose, token=None):
    if context.mode != 'device':
        return
    if token is None and not needs_authorization(context, volume):
        return
    if token is None and purpose == 'android-reset' and fs_type == 'f2fs' and android_requested_reset(context):
        return
    if token is None:
        state = annotate(context, [dict(volume)])[0]
        code = 'FORMAT_AUTH_RESTART_REQUIRED' if state['format_auth_state'] == 'restart_required' else 'FORMAT_AUTH_REQUIRED'
        fs.fail(code, state['format_auth_reason'])
    validate(context, volume, fs_type, purpose, token)


def prepare_write(context, volume, fs_type, purpose, token=None):
    """Reserve before cleanup; consume before write. Unknown outcomes never retry."""
    preflight(context, volume, fs_type, purpose, token)
    if token is None:
        return volume
    expected = physical(volume)
    before_session, before_policy = _session(context, volume)
    attempt = _token(token) + '.attempted'
    try:
        _write_record(attempt, {'boot_id': context.boot_id, 'reason': 'cleanup-started'})
    except FileExistsError:
        fs.fail('FORMAT_AUTH_CONSUMED', 'This formatting attempt already ran; its outcome must be checked.')
    try:
        import android_decrypt
        # Ordinary unmount may retain a RAM session for later mounts. A writer
        # needs terminal closure, including the native key owner and mappings.
        closed = android_decrypt.close_session(context, volume)
        require(closed.get('session_closed') is True
                and closed.get('session_retained') is False
                and closed.get('cleanup_verified') is True,
                'FORMAT_CLEANUP_FAILED', 'The native Android session did not close completely.')
    except fs.FilesystemError as error:
        # A known busy refusal preserves the same live session. Only then can a
        # later explicit confirmation reuse this grant within its original TTL.
        if error.code == 'VOLUME_BUSY' and error.details.get('session_preserved') is True:
            current = context.volume('userdata')
            now_session, now_policy = _session(context, current)
            if physical(current) == expected and now_session == before_session and now_policy == before_policy:
                directory = _ram_directory()
                try:
                    os.unlink(attempt, dir_fd=directory)
                    os.fsync(directory)
                finally:
                    os.close(directory)
        raise
    observed = context.volume('userdata')
    require(not observed.get('mounted') and observed.get('session_retained') is not True
            and physical(observed) == expected,
            'FORMAT_CLEANUP_FAILED', 'Android data did not close cleanly; formatting was not started.')
    holders = Path('/sys/dev/block') / expected['device'] / 'holders'
    require(holders.is_dir() and not any(holders.iterdir())
            and not any(m['devno'] == expected['device'] for m in fs.all_namespace_mounts()),
            'FORMAT_CLEANUP_FAILED', 'The userdata device is still in use; formatting was not started.')
    _write_record(token + '.used', {'boot_id': context.boot_id, 'reason': 'format-started'})
    return observed


def cancel(context, token):
    _native_lease(context)
    token = _token(token)
    try:
        record = _read_record(token + '.json')
    except (OSError, ValueError):
        fs.fail('FORMAT_AUTH_INVALID', 'The format authorization is unavailable.')
    require(record.get('schema') == SCHEMA and record.get('boot_id') == context.boot_id,
            'FORMAT_AUTH_MISMATCH', 'Format authorization belongs to another recovery boot.')
    if not _used(token):
        try:
            _write_record(token + '.used', {'boot_id': context.boot_id, 'reason': 'cancelled'})
        except FileExistsError:
            pass
    return dict(format_authorization_cancelled=True, data_erased=False, mount_changed=False)


def require_unprotected(context, android_reset=False):
    """Automatic installs must stop before any write when old Android data is protected; Android's own
    reset (android_requested_reset) goes on, for the data reset only."""
    if context.mode != 'device':
        return
    if android_reset and android_requested_reset(context):
        return
    volume = context.volume('userdata')
    require(not needs_authorization(context, volume), 'FORMAT_AUTH_REQUIRED',
            'Verify the current Android password and format data in Wipe first, then restart this installation.')


def record_initialized(context, operation, previous, expected_fs, provenance=None):
    """Internal post-write fact only. Call after successful mkfs/readback, never before."""
    if context.mode != 'device':
        return
    _held(context)
    volume = context.volume('userdata')
    require(not volume.get('mounted') and volume.get('fs_type') == expected_fs
            and expected_fs in ('ext4', 'f2fs')
            and isinstance(volume.get('filesystem_uuid'), str) and bool(volume['filesystem_uuid'])
            and volume['filesystem_uuid'] != previous.get('filesystem_uuid'),
            'FORMAT_READBACK_FAILED', 'The initialized userdata filesystem could not be verified.')
    p, old = physical(volume), physical(previous)
    require(all(p[key] == old[key] for key in ('id', 'device_identity', 'partition_number',
            'size_bytes', 'path', 'device')), 'FORMAT_TARGET_CHANGED',
            'The initialized filesystem belongs to another physical device.')
    record = dict(schema=INITIALIZED_SCHEMA, boot_id=context.boot_id, physical=p,
                  operation=operation, provenance=provenance or {},
                  verified_filesystem=volume['fs_type'])
    name = 'initialized-' + p['token'] + '.json'
    try:
        _write_record(name, record)
    except FileExistsError:
        require(initialized(context, volume), 'FORMAT_STATE_INVALID',
                'The post-format filesystem receipt changed.')
