#!/usr/bin/python3
"""Retained Android user0 CE session; native credential FD is never read."""
import argparse
import errno
import fcntl
import hashlib
import math
import json
import os
from pathlib import Path
import selectors
import select
import signal
import socket
import stat
import subprocess
import sys
import time
from android_profiles import SAMSUNG_PROFILE, EVO_PROFILE, LEGACY_EVO_NONE_PROFILE, PROFILES, credential_allowed

from decrypt_runtime.common import (
    LOCK_PATH, SCHEMA, STATE_DIR, SessionError, atomic_json, boot_id as current_boot,
    credential_fd, packet, packet_fds, receive_fds, promote_credential, peer_root, public_failure, read_json_at, receive,
    require, same_process, secure_directory, starttime, validate_config, validate_lease,
)
from decrypt_runtime.mounts import Mounts, verify_mount, mounted_at
from decrypt_runtime.watchdog import Watchdog, preflight

AUTH_SECONDS, CLEANUP_SECONDS, HEARTBEAT_SECONDS = 240.0, 45.0, 5.0
STATE_NAME = 'session.json'
AWAIT_SECONDS = 300.0

def status(state_dir=STATE_DIR, *, boot_id=None, volume_token=None, mountpoint=None):
    """Return only a live verified mounted receipt. Never trusts file alone."""
    directory = secure_directory(state_dir)
    try:
        receipt = read_json_at(directory, STATE_NAME)
    except (OSError, ValueError, KeyError):
        raise SessionError('DECRYPT_FAILED', 'No valid live CE session') from None
    finally:
        os.close(directory)
    try:
        validate_state(receipt, boot_id=boot_id, volume_token=volume_token, mountpoint=mountpoint)
    except (OSError, ValueError, KeyError, TypeError):
        raise SessionError('DECRYPT_REBOOT_REQUIRED', 'CE live session identity is unavailable') from None
    return receipt

def validate_state(receipt, *, boot_id=None, volume_token=None, mountpoint=None,
                   process_check=same_process, mount_check=verify_mount):
    require(type(receipt) is dict and receipt.get('schema') == SCHEMA)
    require(receipt.get('state') == 'mounted' and receipt.get('boot_id') == (boot_id or current_boot()),
            'DECRYPT_REBOOT_REQUIRED', 'CE session is closed or belongs to another boot')
    read_only=receipt.get('read_only')
    require(type(read_only) is bool and receipt.get('requested_mode', 'ro') == ('ro' if read_only else 'rw'))
    require(read_only or receipt.get('credential_type') != 'none', message='NONE RW receipt is unqualified')
    if not read_only:
        from decrypt_runtime.rw_support import capability, qualified_credential
        require(qualified_credential(receipt.get('profile_id'), receipt.get('credential_type')),
                'WRITE_NOT_QUALIFIED', 'This profile and credential are not write-qualified')
        capability(receipt.get('ce_rw'))
        require(receipt.get('ce_rw_native_verified') is True)
    require(receipt.get('ce_authenticated') is True
            and receipt.get('fscrypt_policy_verified') is True
            and type(receipt.get('android_user_id')) is int and receipt['android_user_id'] == 0)
    require((receipt.get('profile_id') in (SAMSUNG_PROFILE, EVO_PROFILE)
             and receipt.get('native_efs_persistence') is True
             and credential_allowed(receipt.get('profile_id'), receipt.get('credential_type')))
            or (receipt.get('profile_id') == LEGACY_EVO_NONE_PROFILE
                and receipt.get('native_efs_persistence') is False
                and receipt.get('credential_type') == 'none'),
            message='Mounted profile/EFS/credential contract mismatch')
    require(process_check(receipt.get('supervisor_pid'), receipt.get('supervisor_starttime'))
            and process_check(receipt.get('worker_pid'), receipt.get('worker_starttime')),
            'DECRYPT_REBOOT_REQUIRED', 'CE session process identity changed')
    require(volume_token is None or receipt.get('physical_volume_token') == volume_token,
            message='CE physical volume token changed')
    require(mountpoint is None or receipt.get('mountpoint') == mountpoint,
            message='CE mountpoint changed')
    if receipt.get('session_reusable') is True:
        from decrypt_runtime.session_support import validate_identity
        validate_identity(receipt, process_check=process_check, mounted=True)
    mount_check(receipt)
    return receipt

def prepared_source(worker_pid, run_id):
    target = '/run/a22x-c-' + run_id + '/root/mnt/userdata-ro'
    source = mounted_at(target, Path('/proc', str(worker_pid), 'mountinfo').read_text())
    require(source['root'] == '/' and source['fstype'] == 'f2fs'
            and 'ro' in source['options'] and 'ro' in source['super_options'])
    root = os.stat('/proc/' + str(worker_pid) + '/root' + target, follow_symlinks=False)
    namespace = os.readlink('/proc/' + str(worker_pid) + '/ns/mnt')
    require(namespace != os.readlink('/proc/self/ns/mnt'), message='Prepared worker namespace is not private')
    return {'mount_id': source['mount_id'], 'device': source['device'], 'root': '/',
            'root_inode': root.st_ino, 'fstype': 'f2fs', 'read_only': True, 'namespace': namespace}

def pending_token(receipt):
    fields = ('schema', 'boot_id', 'run_id', 'supervisor_pid', 'supervisor_starttime',
              'worker_pid', 'worker_starttime', 'physical_volume_token', 'credential_type',
              'android_user_id', 'profile_id', 'source_identity', 'access_modes')
    if receipt.get('session_reusable') is True:
        from decrypt_runtime.session_support import IDENTITY_FIELDS
        fields += IDENTITY_FIELDS
    identity = {name: receipt[name] for name in fields}
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()

def validate_prepared(receipt, *, boot_id=None, volume_token=None, expected_token=None,
                      process_check=same_process, source_check=prepared_source, now=time.monotonic):
    require(type(receipt) is dict and receipt.get('schema') == SCHEMA)
    require(receipt.get('state') == 'awaiting_credential'
            and receipt.get('boot_id') == (boot_id or current_boot()),
            'DECRYPT_REBOOT_REQUIRED', 'Prepared session is stale')
    require(receipt.get('access_modes') in (['ro'], ['rw'], ['ro', 'rw']))
    if 'rw' in receipt['access_modes']:
        from decrypt_runtime.rw_support import qualified_credential
        require(qualified_credential(receipt.get('profile_id'), receipt.get('credential_type')),
                'WRITE_NOT_QUALIFIED', 'Prepared write credential is unqualified')
    require(receipt.get('ce_authenticated') is False and receipt.get('read_only') is True
            and receipt.get('native_preparation_verified') is True
            and receipt.get('credential_type') in ('pattern', 'password')
            and receipt.get('profile_id') in (SAMSUNG_PROFILE, EVO_PROFILE)
            and credential_allowed(receipt.get('profile_id'), receipt.get('credential_type'))
            and type(receipt.get('android_user_id')) is int and receipt['android_user_id'] == 0)
    require(process_check(receipt.get('supervisor_pid'), receipt.get('supervisor_starttime'))
            and process_check(receipt.get('worker_pid'), receipt.get('worker_starttime')),
            'DECRYPT_REBOOT_REQUIRED', 'Prepared session process changed')
    expiry = receipt.get('credential_deadline_monotonic')
    require(type(expiry) in (int, float) and math.isfinite(expiry) and now() < expiry,
            'DECRYPT_REBOOT_REQUIRED', 'Prepared credential window expired')
    require(volume_token is None or receipt['physical_volume_token'] == volume_token,
            message='Physical volume changed')
    require(receipt.get('volume_token') == pending_token(receipt)
            and (expected_token is None or receipt['volume_token'] == expected_token),
            message='Prepared volume token changed')
    if receipt.get('session_reusable') is True:
        from decrypt_runtime.session_support import validate_identity
        validate_identity(receipt, process_check=process_check)
    require(source_check(receipt['worker_pid'], receipt['run_id']) == receipt['source_identity'],
            message='Prepared native mount source changed')
    return receipt

def prepared_status(state_dir=STATE_DIR, *, boot_id=None, volume_token=None, expected_token=None):
    directory = secure_directory(state_dir)
    try:
        receipt = read_json_at(directory, STATE_NAME)
    finally:
        os.close(directory)
    return validate_prepared(receipt, boot_id=boot_id, volume_token=volume_token,
                             expected_token=expected_token)

def prepared_request(state_dir=STATE_DIR, *, common_lock_fd, expected_token,
                     credential_type=None, credential=None, boot_id=None, cancel=False, timeout=285,
                     requested_mode='ro', write_confirmed=False):
    validate_lease(common_lock_fd)
    receipt = prepared_status(state_dir, boot_id=boot_id, expected_token=expected_token)
    if not cancel:
        credential_fd(credential)
        require(credential_type == receipt['credential_type'])
        require(requested_mode in receipt['access_modes'] and type(write_confirmed) is bool
                and write_confirmed is (requested_mode == 'rw'), 'WRITE_NOT_QUALIFIED',
                'The prepared session does not admit this confirmed access mode')
    request = {'op': 'cancel_prepared' if cancel else 'authenticate',
               'boot_id': receipt['boot_id'], 'run_id': receipt['run_id'],
               'volume_token': expected_token, 'credential_type': receipt['credential_type']}
    if not cancel:
        request.update(requested_mode=requested_mode, write_confirmed=write_confirmed)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(timeout)
        client.connect(str(Path(state_dir) / 'control.sock'))
        require(peer_root(client) == receipt['supervisor_pid'])
        packet_fds(client, request, (common_lock_fd,) if cancel else (common_lock_fd, credential))
        reply, fd = receive(client)
        require(fd is None)
        if reply.get('ok') is not True:
            error = reply.get('error', {})
            raise SessionError(error.get('code', 'DECRYPT_FAILED'),
                               error.get('message', 'Prepared session failed'), error.get('details', {}))
        return reply

def detached_status(state_dir=STATE_DIR, *, boot_id=None, volume_token=None, expected_token=None):
    from decrypt_runtime.session_support import validate_detached
    directory = secure_directory(state_dir)
    try:
        receipt = read_json_at(directory, STATE_NAME)
    finally:
        os.close(directory)
    return validate_detached(receipt, boot_id=boot_id, volume_token=volume_token,
                             expected_token=expected_token)

def retained_request(state_dir=STATE_DIR, *, common_lock_fd, expected_token, requested_mode,
                     credential=None, write_confirmed=False, require_fresh_authentication=False,
                     boot_id=None, timeout=285):
    validate_lease(common_lock_fd)
    receipt = detached_status(state_dir, boot_id=boot_id, expected_token=expected_token)
    require(requested_mode in ('ro','rw') and type(write_confirmed) is bool
            and write_confirmed is (requested_mode == 'rw')
            and type(require_fresh_authentication) is bool)
    if credential is not None:
        credential_fd(credential)
        require(credential != common_lock_fd)
    request = {'op':'mount', 'boot_id':receipt['boot_id'], 'run_id':receipt['run_id'],
        'volume_token':expected_token, 'requested_mode':requested_mode,
        'write_confirmed':write_confirmed,
        'require_fresh_authentication':require_fresh_authentication}
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(timeout)
        client.connect(str(Path(state_dir) / 'control.sock'))
        require(peer_root(client) == receipt['supervisor_pid'])
        packet_fds(client, request, (common_lock_fd,) if credential is None else (common_lock_fd, credential))
        reply, fd = receive(client)
        require(fd is None)
        if reply.get('ok') is not True:
            error = reply.get('error', {})
            raise SessionError(error.get('code','DECRYPT_FAILED'),
                error.get('message','Reusable mount did not complete'), error.get('details',{}))
        return reply

def close_session(state_dir=STATE_DIR, *, common_lock_fd, boot_id=None, run_id=None, timeout=55):
    validate_lease(common_lock_fd)
    directory = secure_directory(state_dir)
    try:
        receipt = read_json_at(directory, STATE_NAME)
    finally:
        os.close(directory)
    if receipt.get('state') == 'mounted':
        validate_state(receipt, boot_id=boot_id)
    elif receipt.get('state') == 'awaiting_credential':
        validate_prepared(receipt, boot_id=boot_id)
    else:
        from decrypt_runtime.session_support import validate_detached
        validate_detached(receipt, boot_id=boot_id)
    require(run_id is None or run_id == receipt['run_id'])
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(timeout)
        client.connect(str(Path(state_dir) / 'control.sock'))
        require(peer_root(client) == receipt['supervisor_pid'])
        packet(client, {'op':'close','boot_id':receipt['boot_id'],'run_id':receipt['run_id']},
               common_lock_fd)
        reply, fd = receive(client)
        require(fd is None)
        if reply.get('ok') is not True:
            error = reply.get('error', {})
            raise SessionError(error.get('code','DECRYPT_FAILED'),
                error.get('message','Terminal session close did not complete'), error.get('details',{}))
        require(reply.get('cleanup_verified') is True, message='Terminal session cleanup is unproven')
        return reply

def unmount(state_dir=STATE_DIR, *, common_lock_fd, boot_id=None, run_id=None, timeout=50):
    validate_lease(common_lock_fd)
    receipt = status(state_dir, boot_id=boot_id)
    require(run_id is None or run_id == receipt['run_id'])
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(timeout)
        client.connect(str(Path(state_dir) / 'control.sock'))
        require(peer_root(client) == receipt['supervisor_pid'], message='Controller peer PID changed')
        packet(client, {'op': 'unmount', 'boot_id': receipt['boot_id'],
                        'run_id': receipt['run_id']}, common_lock_fd)
        reply, fd = receive(client)
        require(fd is None)
        if reply.get('ok') is not True:
            error = reply.get('error', {})
            raise SessionError(error.get('code', 'DECRYPT_FAILED'),
                               error.get('message', 'CE unmount failed'), error.get('details', {}))
        return reply

def envelope(error):
    if not isinstance(error, SessionError):
        error = SessionError('DECRYPT_FAILED', 'CE session contract failed')
    return {'ok': False, 'error': {'code': error.code, 'message': error.message,
                                 'details': error.details}}

def verify_cleanup(config, worker_pid, safe_path):
    """Independent named resources; absence of worker alone is insufficient."""
    safe = json.loads(Path(safe_path).read_text())
    require(safe['boot_id'] == config['boot_id'] and safe['run_id'] == config['run_id']
            and safe['worker_pid'] == worker_pid and safe['cleanup_safe'] is True)
    require(safe['process_cleanup_errors'] == safe['mount_cleanup_errors']
            == safe['data_cleanup_errors'] == [])
    require(safe['selinux_enforcing'] == 0 and safe['policy_state']
            in ('NOT_LOADED', 'OWN_FIRST_POLICY_LOADED_PERMISSIVE'))
    for pid in safe['owned_pids']:
        require(type(pid) is int and pid > 1 and not Path('/proc', str(pid)).exists())
    directory = Path('/run/a22x-c-' + config['run_id'])
    g1 = json.loads((directory / 'G1-CLEANUP.json').read_text())
    g2 = json.loads((directory / 'G2-RESULT.json').read_text())
    require(g1['mount_cleanup_errors'] == [] and g1['owned_maps_remaining'] == []
            and g2['all_owned_processes_reaped'] is True and g2['process_cleanup_errors'] == [])
    for path in Path('/sys/block').glob('dm-*/dm/name'):
        require(not path.read_text().strip().startswith(
            ('a22x-c-' + config['run_id'], 'a22x-data-ro-' + config['run_id'])))
    return True

class SessionLifecycle:
    """Testable transitions. Hardware/IPC remain in the owning supervisor loop."""
    def __init__(self, config, *, mounts, commit, send_worker, release_lease,
                 cleanup_check, disarm, now=time.monotonic):
        require(config.get('profile_id') in PROFILES)
        self.config, self.mounts, self.commit = config, mounts, commit
        self.send_worker, self.release_lease = send_worker, release_lease
        self.cleanup_check, self.disarm, self.now = cleanup_check, disarm, now
        self.state = 'authenticating'
        self.deadline = now() + AUTH_SECONDS
        self.receipt = None
        self.bound = False
        self.cancelled = False
        self.worker_done = None
        self.auth_started = config['profile_id'] == LEGACY_EVO_NONE_PROFILE
        self.credential_type = 'none' if config['profile_id'] == LEGACY_EVO_NONE_PROFILE else None
        self.await_deadline = None
        self.requested_mode = 'ro'

    def prepared(self, worker_pid, worker_ticks, credential_type, source):
        require(self.state == 'authenticating' and self.config['profile_id'] in (SAMSUNG_PROFILE, EVO_PROFILE))
        if self.cancelled:
            self.send_worker({'op': 'cancel'}, None)
            return
        require(credential_type in ('pattern', 'password') and credential_allowed(self.config['profile_id'], credential_type))
        self.credential_type = credential_type
        from decrypt_runtime.rw_support import qualified_credential
        rw_admitted = self.config.get('ce_rw') is not None and qualified_credential(self.config['profile_id'], credential_type)
        self.await_deadline = self.now() + AWAIT_SECONDS
        self.receipt = dict(schema=SCHEMA, boot_id=self.config['boot_id'], run_id=self.config['run_id'],
            supervisor_pid=os.getpid(), supervisor_starttime=starttime(os.getpid()),
            worker_pid=worker_pid, worker_starttime=worker_ticks, state='awaiting_credential',
            physical_volume_token=self.config['volume_token'], read_only=True,
            ce_authenticated=False, native_preparation_verified=True, android_user_id=0,
            profile_id=self.config['profile_id'], credential_type=credential_type,
            source_identity=source, credential_deadline_monotonic=self.await_deadline,
            access_modes=(['rw'] if self.config.get('preparation_mode','ro') == 'rw' else ['ro','rw']) if rw_admitted else ['ro'])
        self.receipt['volume_token'] = pending_token(self.receipt)
        self.commit(self.receipt)
        self.state = 'preparing_ready'
        self.send_worker({'op': 'await'}, None)

    def prepared_held(self):
        require(self.state == 'preparing_ready')
        self.release_lease()
        self.state = 'awaiting_credential'
        self.deadline = self.now() + HEARTBEAT_SECONDS
        return self.receipt

    def check_request(self, request):
        require(self.state == 'awaiting_credential' and self.now() < self.await_deadline)
        expected={'op':request.get('op'), 'boot_id':self.config['boot_id'],
            'run_id':self.config['run_id'], 'volume_token':self.receipt['volume_token'],
            'credential_type':self.credential_type}
        require(request.get('op') in ('authenticate','cancel_prepared'))
        if request['op']=='authenticate':
            mode=request.get('requested_mode')
            require(mode in self.receipt['access_modes'] and type(request.get('write_confirmed')) is bool
                and request['write_confirmed'] is (mode=='rw'), 'WRITE_NOT_QUALIFIED',
                'The exact requested write mode was not admitted')
            expected.update(requested_mode=mode,write_confirmed=request['write_confirmed'])
        require(request==expected)

    def start_auth(self, request, lease_fd, credential):
        self.check_request(request)
        require(request['op'] == 'authenticate')
        if request['requested_mode']=='rw':
            from decrypt_runtime.rw_support import quotas, qualified_credential
            require(qualified_credential(self.config['profile_id'], self.credential_type),
                    'WRITE_NOT_QUALIFIED', 'The prepared credential is not write-qualified')
            quotas(self.config.get('ce_rw'), self.config['boot_id'], lease_fd)
        self.requested_mode=request['requested_mode']
        self.state = 'authenticating'
        self.auth_started = True
        self.deadline = self.now() + AUTH_SECONDS
        self.commit(dict(self.receipt, state='authenticating', requested_mode=self.requested_mode))
        self.send_worker({'op': 'authenticate', 'credential_type': self.credential_type,
                          'deadline': self.deadline, 'requested_mode':self.requested_mode,
                          'write_confirmed':self.requested_mode=='rw'}, (lease_fd, credential))

    def cancel_prepared(self, lease_fd):
        require(self.state == 'awaiting_credential')
        self.cancelled = True
        self.state = 'cleaning'
        self.deadline = self.now() + CLEANUP_SECONDS
        self.commit(dict(self.receipt, state='cleaning'))
        self.send_worker({'op': 'cancel_prepared', 'credential_type': self.credential_type}, lease_fd)

    def authenticated(self, worker_pid, worker_ticks, tree_fd=None, proof=None, credential_type=None, requested_mode='ro'):
        require(self.state == 'authenticating')
        if self.cancelled:
            self.send_worker({'op': 'cancel'}, None)
            return
        if self.config['profile_id'] == EVO_PROFILE:
            require(credential_type in ('none', 'password') and credential_allowed(EVO_PROFILE, credential_type))
            require((credential_type == 'none' and self.credential_type is None and not self.auth_started) or
                    (credential_type == 'password' and self.credential_type == 'password' and self.auth_started))
            self.credential_type = credential_type
        require(credential_type != 'none' or requested_mode == 'ro', message='NONE write mode is unsupported')
        require(requested_mode==self.requested_mode, message='Worker authenticated a different access mode')
        if requested_mode=='rw':
            from decrypt_runtime.rw_support import qualified_credential
            require(qualified_credential(self.config['profile_id'], self.credential_type),
                    'WRITE_NOT_QUALIFIED', 'The authenticated credential is not write-qualified')
            require(self.auth_started and self.config.get('ce_rw') is not None
                and type(proof) is dict and proof.get('read_only') is False,
                message='RW authentication or detached proof missing')
            mount=self.mounts.bind(worker_pid,worker_ticks,self.config['run_id'],
                self.config['mountpoint'],tree_fd,proof,read_only=False)
        else:
            mount=self.mounts.bind(worker_pid,worker_ticks,self.config['run_id'],
                self.config['mountpoint'],tree_fd,proof)
        self.bound = True
        require(mount.get('read_only',requested_mode=='ro') is (requested_mode=='ro'),
                message='Global mount receipt mode changed')
        mount={key:value for key,value in mount.items() if key!='read_only'}
        self.receipt = dict(
            schema=SCHEMA, boot_id=self.config['boot_id'], run_id=self.config['run_id'],
            supervisor_pid=os.getpid(), supervisor_starttime=starttime(os.getpid()),
            worker_pid=worker_pid, worker_starttime=worker_ticks, state='mounted',
            physical_volume_token=self.config['volume_token'], read_only=requested_mode=='ro',
            requested_mode=requested_mode, ce_authenticated=True, fscrypt_policy_verified=True, android_user_id=0,
            profile_id=self.config['profile_id'], native_efs_persistence=self.config.get('native_efs_policy') is not None,
            credential_type=self.credential_type or 'password', **mount)
        if requested_mode=='rw':
            self.receipt.update(ce_rw=self.config['ce_rw'], ce_rw_native_verified=True)
        self.commit(self.receipt)
        self.state = 'binding'
        self.send_worker({'op': 'hold'}, None)

    def held(self):
        require(self.state == 'binding')
        # Worker has replaced its old descriptor with a dummy before ACK.
        # Close our original OFD copy; the caller/SSH keeps its own lease until
        # its operation context ends. Borrowed OFDs must never be unlocked.
        self.release_lease()
        self.state = 'mounted'
        self.deadline = self.now() + HEARTBEAT_SECONDS
        return self.receipt

    def pong(self):
        require(self.state in ('mounted', 'awaiting_credential'))
        self.deadline = self.now() + HEARTBEAT_SECONDS

    def cancel_auth(self):
        require(self.state == 'authenticating')
        self.cancelled = True
        self.send_worker({'op': 'cancel'}, None)
        self.deadline = min(self.deadline, self.now() + CLEANUP_SECONDS)

    def request_unmount(self, fd):
        require(self.state == 'mounted')
        # No state mutation on normal EBUSY: caller may close its fresh lease
        # while worker and daemon services remain held and responsive.
        try:
            self.mounts.unmount(self.config['mountpoint'])
        except OSError as error:
            if error.errno == errno.EBUSY:
                raise SessionError('VOLUME_BUSY',
                    'Android data is in use. Close files or other operations, then unmount again.',
                    {'session_preserved': True, 'retry_allowed': True,
                     'reboot_required': False}) from None
            raise
        self.bound = False
        self.state = 'cleaning'
        self.deadline = self.now() + CLEANUP_SECONDS
        self.send_worker({'op': 'unmount'}, fd)

    def complete(self, returncode, worker_result):
        require(self.state in ('authenticating', 'cleaning'))
        require(not self.bound, message='Global CE bind remains')
        require(worker_result is not None and worker_result.get('cleanup_verified') is True)
        require(self.cleanup_check() is True, message='Terminal cleanup is unproven')
        cancelled_before_auth = self.state == 'cleaning' and self.cancelled and not self.auth_started
        failed = self.state == 'cleaning' and not cancelled_before_auth and (
            returncode != 0 or worker_result.get('success') is not True)
        terminal = {'schema': SCHEMA, 'boot_id': self.config['boot_id'],
                    'run_id': self.config['run_id'], 'state': 'failed' if failed else 'closed',
                    'ce_authenticated': False, 'reboot_required': True,
                    'cleanup_verified': True}
        if cancelled_before_auth:
            terminal['error_code'] = 'CANCELLED'
        if self.state == 'authenticating':
            failure = public_failure(worker_result.get('verdict'))
            terminal['state'] = 'failed'
            terminal['error_code'] = failure.code
            if failure.code == 'RETRY_LATER':
                terminal['retry_after_seconds'] = failure.details['retry_after_seconds']
        self.commit(terminal)
        self.disarm()
        self.state = 'closed'
        if failed:
            return envelope(SessionError('DECRYPT_FAILED',
                'Native terminal verdict failed after verified cleanup',
                {'reboot_required': True, 'cleanup_verified': True}))
        return {'ok': True, 'reboot_required': True, 'cleanup_verified': True}

def dispatch(config_path, config, credential, lock, control, deadline, safe_path, discovery=False):
    require(config.get('profile_id') not in (EVO_PROFILE, LEGACY_EVO_NONE_PROFILE) or (discovery and credential is None),
            message='NONE cannot dispatch a credential descriptor')
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
               A22X_C_WD_DEADLINE=str(deadline), A22X_RECOVERY_LOCK_FD=str(lock))
    command = [sys.executable, str(Path(__file__).resolve()), '_worker', '--config', config_path,
               '--common-lock-fd', str(lock), '--control-fd', str(control.fileno()),
               '--safe-receipt', str(safe_path)]
    descriptors = [lock, control.fileno()]
    if discovery:
        command.append('--discover')
    else:
        command += ['--credential-fd', str(credential)]
        descriptors.append(credential)
    return subprocess.Popen(command, close_fds=True, pass_fds=tuple(descriptors),
                            env=env, start_new_session=True, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def reader_gone(fd):
    poller = select.poll()
    poller.register(fd, select.POLLERR | select.POLLHUP | select.POLLNVAL)
    return bool(poller.poll(0))

def ready(fd, value):
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'
    require(len(data) <= 4096)
    try:
        require(os.write(fd, data) == len(data))
    finally:
        os.close(fd)

def serve(args):
    require(os.geteuid() == 0, message='Root session supervisor required')
    os.umask(0o077)
    if not args.discover:
        credential_fd(args.credential_fd)
    else:
        require(args.credential_fd is None)
    descriptors = [args.common_lock_fd, args.ready_fd]
    if args.credential_fd is not None: descriptors.append(args.credential_fd)
    require(len(set(descriptors)) == len(descriptors))
    flags = fcntl.fcntl(args.ready_fd, fcntl.F_GETFL)
    require(flags & os.O_ACCMODE == os.O_WRONLY and stat.S_ISFIFO(os.fstat(args.ready_fd).st_mode)
            and os.readlink('/proc/self/fd/' + str(args.ready_fd)).startswith('pipe:['))
    config = json.loads(Path(args.config).read_text())
    validate_config(config)
    require(config['profile_id'] not in (EVO_PROFILE, LEGACY_EVO_NONE_PROFILE) or
            (args.discover and args.credential_fd is None),
            message='NONE requires no-credential discovery dispatch')
    validate_lease(args.common_lock_fd)
    directory = secure_directory(config.get('state_dir', STATE_DIR), create=True)
    controller_lock = os.open('supervisor.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=directory)
    fcntl.flock(controller_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        old = read_json_at(directory, STATE_NAME)
    except FileNotFoundError:
        old = None
    if old and old.get('boot_id') == config['boot_id']:
        raise SessionError('DECRYPT_REBOOT_REQUIRED', 'This boot already has a CE session attempt')
    socket_path = str(Path(config.get('state_dir', STATE_DIR)) / 'control.sock')
    try:
        info = os.stat('control.sock', dir_fd=directory, follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0)
        os.unlink('control.sock', dir_fd=directory)
    except FileNotFoundError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.bind(socket_path); os.chmod(socket_path, 0o600); listener.listen(4)
    listener.setblocking(False)
    safe_path = Path(config.get('state_dir', STATE_DIR)) / ('cleanup-' + config['run_id'] + '.json')
    require(not safe_path.exists())
    preflight(config)
    watchdog = Watchdog()
    parent, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    selector = selectors.DefaultSelector()
    selector.register(parent, selectors.EVENT_READ, 'worker')
    selector.register(listener, selectors.EVENT_READ, 'listener')
    child = None
    delivered = False
    ready_open = True
    active_client = None
    fresh_lease = None
    worker_result = None
    worker_eof = False
    cancellation = [False]
    old_handlers = {}
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        old_handlers[sig] = signal.signal(sig, lambda signum, frame: cancellation.__setitem__(0, True))
    def release_operation():
        nonlocal fresh_lease
        if fresh_lease is not None:
            os.close(fresh_lease); fresh_lease = None
        if args.common_lock_fd is not None:
            release(args)
    lifecycle_class = SessionLifecycle
    if config.get('ce_session') is not None:
        from decrypt_runtime.reusable_lifecycle import ReusableLifecycle
        lifecycle_class = ReusableLifecycle
    lifecycle = lifecycle_class(
        config, mounts=Mounts(), commit=lambda value: atomic_json(directory, STATE_NAME, value),
        send_worker=lambda value, fd: packet_fds(parent, value,
            fd if isinstance(fd, tuple) else (() if fd is None else (fd,))),
        release_lease=release_operation,
        cleanup_check=lambda: verify_cleanup(config, child.pid, safe_path),
        disarm=watchdog.finish)
    try:
        watchdog.arm()
        # Arm failure is not dispatch; any watchdog uncertainty still resets.
        delivered = True
        child = dispatch(args.config, config, args.credential_fd, args.common_lock_fd, child_sock,
                         lifecycle.deadline, safe_path, args.discover)
        worker_ticks = starttime(child.pid)
        child_sock.close()
        if args.credential_fd is not None:
            os.close(args.credential_fd); args.credential_fd = None
        serial, last_ping, awaiting = 0, 0.0, None
        while True:
            if ready_open and reader_gone(args.ready_fd):
                cancellation[0] = True
            if lifecycle.state == 'awaiting_credential' and time.monotonic() >= lifecycle.await_deadline:
                require(time.monotonic() < lifecycle.await_deadline + CLEANUP_SECONDS)
                if getattr(lifecycle, 'reusable', False):
                    candidate = os.open(LOCK_PATH, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        validate_lease(candidate)
                        lifecycle.cancel_prepared(candidate)
                        fresh_lease = candidate
                    except (OSError, SessionError):
                        os.close(candidate)
                else:
                    cancellation[0] = True
            if active_client is not None and reader_gone(active_client.fileno()):
                cancellation[0] = True
            if cancellation[0] and lifecycle.state == 'authenticating'  and not lifecycle.cancelled:
                lifecycle.cancel_auth()
            # A mounted signal requests a fresh lease, never cleanup under the
            # deliberately unlocked original description.
            if cancellation[0] and lifecycle.state in ('mounted', 'awaiting_credential', 'session_unmounted') and fresh_lease is None:
                candidate = os.open(LOCK_PATH, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    validate_lease(candidate)
                    if getattr(lifecycle, 'reusable', False):
                        lifecycle.request_close(candidate)
                    elif lifecycle.state == 'awaiting_credential':
                        lifecycle.cancel_prepared(candidate)
                    else:
                        lifecycle.request_unmount(candidate)
                    fresh_lease = candidate
                except (OSError, SessionError):
                    os.close(candidate)
            if child.poll() is not None:
                # Drain final worker result before considering process exit.
                for key, mask in selector.select(0):
                    if key.data == 'worker':
                        try:
                            value, fd = receive(parent)
                            if value.get('event') == 'result': worker_result = value
                        except (OSError, SessionError): pass
                completion_phase = lifecycle.state
                response = lifecycle.complete(child.returncode, worker_result)
                if completion_phase == 'authenticating':
                    response = envelope(public_failure((worker_result or {}).get('verdict')))
                if ready_open:
                    failure = public_failure((worker_result or {}).get('verdict'))
                    if lifecycle.cancelled:
                        failure = SessionError('DECRYPT_FAILED', 'Authentication cancelled after verified cleanup',
                                               {'reboot_required': True})
                    try: ready(args.ready_fd, envelope(failure))
                    except BrokenPipeError: pass  # cleanup independently proven
                    ready_open = False
                if active_client is not None:
                    try: packet(active_client, response)
                    except BrokenPipeError: pass
                return 0
            now = time.monotonic()
            require(now < lifecycle.deadline, message='Bounded session deadline expired')
            watchdog.pet()
            if lifecycle.state in ('mounted', 'awaiting_credential', 'session_unmounted') and awaiting is None and now - last_ping >= 0.5:
                serial += 1; awaiting = serial; packet(parent, {'op': 'ping', 'serial': serial})
                last_ping = now
            for key, mask in selector.select(0.2):
                if key.data == 'worker':
                    try:
                        value, fd = receive(parent, True)
                    except SessionError:
                        # Final typed result can precede kernel process exit.
                        # EOF alone grants no success; wait within fixed deadline.
                        require(worker_result is not None)
                        selector.unregister(parent)
                        worker_eof = True
                        continue
                    event = value.get('event')
                    require((fd is not None) == (event == 'authenticated'))
                    if event == 'prepared':
                        require(args.discover and value.get('source_identity') ==
                                prepared_source(child.pid, config['run_id']))
                        lifecycle.prepared(child.pid, worker_ticks, value.get('credential_type'),
                                           value['source_identity'], **({'session_proof':value.get('session_proof')} if config.get('ce_session') is not None else {}))
                    elif event == 'prepared_held':
                        receipt = lifecycle.prepared_held()
                        try: ready(args.ready_fd, {'ok': True, 'state': receipt})
                        except BrokenPipeError: cancellation[0] = True
                        ready_open = False
                    elif event == 'auth_dispatching':
                        require(lifecycle.state == 'authenticating' and lifecycle.auth_started
                                and value.get('requested_mode')==lifecycle.requested_mode)
                    elif event == 'authenticated':
                        try:
                            lifecycle.authenticated(child.pid, worker_ticks, fd, value.get('mount_transfer'),
                                                    credential_type=value.get('credential_type'), requested_mode=value.get('requested_mode','ro'), **({'session_proof':value.get('session_proof')} if config.get('ce_session') is not None else {}))
                        finally:
                            # After move_mount this FD pins the attached mount.
                            # Never retain it across Files or normal unmount.
                            os.close(fd)
                    elif event == 'suspended':
                        require(getattr(lifecycle, 'reusable', False))
                        lifecycle.suspended(value.get('session_proof'), value.get('error'))
                    elif event == 'held':
                        receipt = lifecycle.held()
                        if ready_open:
                            try: ready(args.ready_fd, {'ok': True, 'state': receipt})
                            except BrokenPipeError: cancellation[0] = True
                            ready_open = False
                        elif active_client is not None:
                            try: packet(active_client, lifecycle.reply(receipt) if getattr(lifecycle, 'reusable', False) else {'ok': True, 'state': receipt})
                            except BrokenPipeError: cancellation[0] = True
                            active_client.close(); active_client = None
                    elif event == 'pong':
                        require(value.get('serial') == awaiting)
                        awaiting = None
                        if lifecycle.state in ('mounted', 'awaiting_credential', 'session_unmounted'): lifecycle.pong()
                        else: require(lifecycle.state in ('cleaning', 'authenticating', 'suspending', 'binding_detached', 'binding'))
                    elif event == 'cleaning':
                        require(lifecycle.state == 'cleaning')
                    elif event == 'result':
                        worker_result = value
                    else:
                        raise SessionError(message='Unexpected native worker event')
                elif key.data == 'listener':
                    client, _ = listener.accept()
                    client.settimeout(1)
                    try:
                        peer_root(client)
                        request, incoming = receive_fds(client, 2)
                        try:
                            require(incoming)
                            validate_lease(incoming[0])
                            require(active_client is None)
                            if request.get('op') == 'close':
                                require(len(incoming) == 1 and request == {
                                    'op':'close', 'boot_id':config['boot_id'], 'run_id':config['run_id']})
                                if getattr(lifecycle, 'reusable', False):
                                    lifecycle.request_close(incoming[0])
                                elif lifecycle.state == 'awaiting_credential':
                                    lifecycle.cancel_prepared(incoming[0])
                                else:
                                    lifecycle.request_unmount(incoming[0])
                                fresh_lease = incoming[0]
                            elif lifecycle.state == 'session_unmounted':
                                require(getattr(lifecycle, 'reusable', False) and len(incoming) in (1,2))
                                credential = promote_credential(incoming[1]) if len(incoming) == 2 else None
                                try: lifecycle.resume_request(request, incoming[0], credential)
                                finally:
                                    if credential is not None: os.close(credential)
                                fresh_lease = incoming[0]
                            elif lifecycle.state == 'awaiting_credential':
                                lifecycle.check_request(request)
                                require(prepared_source(child.pid, config['run_id']) ==
                                        lifecycle.receipt['source_identity'])
                                if request['op'] == 'authenticate':
                                    require(len(incoming) == 2)
                                    credential = promote_credential(incoming[1])
                                    try: lifecycle.start_auth(request, incoming[0], credential)
                                    finally: os.close(credential)
                                    args.common_lock_fd = incoming[0]
                                else:
                                    require(len(incoming) == 1)
                                    lifecycle.cancel_prepared(incoming[0])
                                    fresh_lease = incoming[0]
                            else:
                                require(len(incoming) == 1 and request == {
                                    'op': 'unmount', 'boot_id': config['boot_id'], 'run_id': config['run_id']})
                                require(lifecycle.state == 'mounted')
                                verify_mount(lifecycle.receipt)
                                lifecycle.request_unmount(incoming[0])
                                fresh_lease = incoming[0]
                            incoming[0] = None
                            active_client = client; client = None
                        finally:
                            for descriptor in incoming:
                                if descriptor is not None: os.close(descriptor)
                    except OSError as error:
                        code = 'DECRYPT_FAILED'
                        details = {'reason': 'MOUNT_BUSY'} if error.errno == errno.EBUSY else {}
                        if client is not None: packet(client, envelope(SessionError(code, 'CE mount is busy' if details else 'CE unmount failed', details)))
                    except SessionError as error:
                        if client is not None: packet(client, envelope(error))
                    except ValueError:
                        if client is not None: packet(client, envelope(SessionError(message='Invalid session request')))
                    finally:
                        if client is not None: client.close()
    except BaseException:
        if watchdog.armed:
            # No kill, lazy umount, optimistic ACK, V, or cleanup without lease.
            # Hardware deadline is the only authority once native state is unknown.
            watchdog.reset_required()
        raise
    finally:
        for sig, handler in old_handlers.items(): signal.signal(sig, handler)
        if fresh_lease is not None: os.close(fresh_lease)
        if args.common_lock_fd is not None: os.close(args.common_lock_fd)
        for resource in (active_client, listener, parent, child_sock, selector):
            if resource is not None: resource.close()
        os.close(controller_lock); os.close(directory)

def release(args):
    os.close(args.common_lock_fd)
    args.common_lock_fd = None

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    serve_parser = sub.add_parser('serve')
    for name in ('config',): serve_parser.add_argument('--' + name, required=True)
    serve_parser.add_argument('--credential-fd', type=int)
    serve_parser.add_argument('--discover', action='store_true')
    for name in ('common-lock-fd', 'ready-fd'):
        serve_parser.add_argument('--' + name, type=int, required=True)
    stop = sub.add_parser('unmount')
    stop.add_argument('--state-dir', default=STATE_DIR)
    stop.add_argument('--common-lock-fd', type=int, required=True)
    stop.add_argument('--boot-id'); stop.add_argument('--run-id')
    show = sub.add_parser('status'); show.add_argument('--state-dir', default=STATE_DIR)
    worker = sub.add_parser('_worker')
    worker.add_argument('--config', required=True)
    worker.add_argument('--credential-fd', type=int)
    worker.add_argument('--discover', action='store_true')
    for name in ('common-lock-fd', 'control-fd'):
        worker.add_argument('--' + name, type=int, required=True)
    worker.add_argument('--safe-receipt', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == '_worker':
            # Native module paths are public qualified package paths.
            config = json.loads(Path(args.config).read_text())
            sys.path.insert(0, config['module_dir'])
            sys.path.insert(0, str(Path(config['module_dir']).parents[1] / 'sp-prepare-worker'))
            from decrypt_runtime.native_session_worker import main as native_main
            sys.argv = [sys.argv[0], '--config', args.config,
                        '--common-lock-fd', str(args.common_lock_fd), '--control-fd', str(args.control_fd),
                        '--safe-receipt', args.safe_receipt]
            if args.discover: sys.argv.append('--discover')
            else: sys.argv += ['--credential-fd', str(args.credential_fd)]
            return native_main()
        if args.command == 'serve': return serve(args)
        if args.command == 'unmount':
            result = unmount(args.state_dir, common_lock_fd=args.common_lock_fd,
                             boot_id=args.boot_id, run_id=args.run_id)
        else: result = {'ok': True, 'state': status(args.state_dir)}
        print(json.dumps(result)); return 0
    except (SessionError, OSError, ValueError, KeyError):
        error = sys.exception()
        response = envelope(error)
        if args.command == 'serve':
            ready(args.ready_fd, response)
        elif args.command != '_worker':
            print(json.dumps(response))
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
