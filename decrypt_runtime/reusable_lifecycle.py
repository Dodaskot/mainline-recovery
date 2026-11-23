"""Reusable supervisor transitions; the native owner remains the key authority."""
import errno
import os
import secrets

from decrypt_session import SessionLifecycle, AUTH_SECONDS, CLEANUP_SECONDS, HEARTBEAT_SECONDS
from decrypt_runtime.common import require, SessionError, starttime, same_process
from decrypt_runtime import session_support as support

PROOF_SCHEMA = 'a22x.ce-session.native-proof.v1'

def native_proof(value, previous=None, *, state, process_check=same_process):
    require(type(value) is dict and value.get('schema') == PROOF_SCHEMA
            and value.get('state') == state and value.get('lease_released') is True,
            message='Native session response did not commit the expected state')
    require(support.positive(value.get('pid'))
            and process_check(value['pid'], value.get('starttime')),
            message='Native key owner process identity changed')
    for key in ('sequence', 'generation', 'auth_sequence', 'committed_auth_sequence'):
        require(support.nonnegative(value.get(key)), message='Invalid native session sequence')
    require(value['committed_auth_sequence'] <= value['auth_sequence']
            and type(value.get('cache_valid')) is bool)
    if previous is None:
        require(value['sequence'] == value['generation'] == value['auth_sequence']
                == value['committed_auth_sequence'] == 0 and state == 'prepared')
    else:
        require(value['pid'] == previous['pid'] and value['starttime'] == previous['starttime']
                and value['sequence'] == previous['sequence'] + 1
                and value['generation'] == previous['generation'] + 1
                and value['auth_sequence'] >= previous['auth_sequence']
                and value['committed_auth_sequence'] >= previous['committed_auth_sequence'],
                message='Native session transition identity changed')
    if state == 'mounted':
        require(value['mode'] in ('ro', 'rw') and value['cache_valid'] is True
                and value.get('ce_verified') is True
                and support.positive(value['committed_auth_sequence']))
    else:
        require(value['mode'] in ('none', 'ro') and value.get('suspend_clean') is (state == 'suspended'))
    return dict(value)

class ReusableLifecycle(SessionLifecycle):
    def __init__(self, config, **options):
        self.real_commit = options.pop('commit')
        self.reusable = False
        self.native = None
        self.authentication_id = None
        self.password_policy_at_auth = None
        self.pending_authentication_id = None
        self.pending_policy = None
        self.pending_fresh = False
        self.pending_error = None
        self.detached_devices = []
        self.owned_crypto_names = []
        super().__init__(config, commit=self.commit_record, **options)

    def commit_record(self, value):
        if self.reusable and value.get('state') in ('closed', 'failed'):
            value.update(session_reusable=True, session_retained=False, key_retained=False)
        elif self.reusable:
            require(self.native is not None)
            value.update(session_reusable=True, session_retained=True,
                native_owner_pid=self.native['pid'], native_owner_starttime=self.native['starttime'],
                native_generation=self.native['generation'], native_sequence=self.native['sequence'],
                auth_generation=self.native['committed_auth_sequence'],
                mount_generation=self.native['generation'],
                authentication_id=self.authentication_id,
                password_policy_at_auth=self.password_policy_at_auth,
                key_retained=self.native['cache_valid'],
                device_offline=False, reboot_required=False)
            if value.get('state') == 'session_unmounted':
                value['volume_token'] = support.detached_token(value)
            elif value.get('state') == 'awaiting_credential':
                from decrypt_session import pending_token
                value['volume_token'] = pending_token(value)
        self.real_commit(value)

    def prepared(self, worker_pid, worker_ticks, credential_type, source, session_proof=None):
        if session_proof is not None:
            support.capability(self.config.get('ce_session'))
            require(credential_type == 'password')
            self.native = native_proof(session_proof, state='prepared')
            names = session_proof.get('owned_crypto_names')
            require(type(names) is list and len(names) in (6, 8) and len(set(names)) == len(names)
                    and all(type(n) is str and n.startswith('a22x-data-ro-' + self.config['run_id']) for n in names))
            self.owned_crypto_names = names
            require(session_proof.get('physical_device') == self.config['layout']['physical']['userdata']['device'])
            self.detached_devices = [source['device']]
            self.reusable = True
        super().prepared(worker_pid, worker_ticks, credential_type, source)

    def start_auth(self, request, lease_fd, credential):
        if not self.reusable:
            return super().start_auth(request, lease_fd, credential)
        self.check_request(request)
        self.begin_mount(request['requested_mode'], request['write_confirmed'], lease_fd, credential, fresh=True)

    def begin_mount(self, mode, confirmed, lease_fd, credential, *, fresh):
        require(self.state in ('awaiting_credential', 'session_unmounted'))
        require(mode in ('ro', 'rw') and type(confirmed) is bool and confirmed is (mode == 'rw'))
        if mode == 'rw':
            from decrypt_runtime.rw_support import quotas
            quotas(self.config.get('ce_rw'), self.config['boot_id'], lease_fd)
        if fresh:
            require(credential is not None)
            self.pending_authentication_id = secrets.token_hex(16)
            self.pending_policy = support.password_policy()
        else:
            require(credential is None and not support.auth_required(self.receipt),
                    'CREDENTIAL_REQUIRED', 'Enter the current Android password for this mount')
            self.pending_authentication_id = self.authentication_id
            self.pending_policy = self.password_policy_at_auth
        self.pending_fresh = fresh
        self.pending_error = None
        self.cancelled = False
        self.requested_mode = mode
        self.state = 'authenticating'
        self.auth_started = True
        self.deadline = self.now() + AUTH_SECONDS
        self.commit(dict(self.receipt, state='authenticating', requested_mode=mode))
        message = {'op': 'authenticate' if fresh else 'resume', 'credential_type': 'password',
                   'deadline': self.deadline, 'requested_mode': mode,
                   'write_confirmed': confirmed,
                   'authentication_id': self.pending_authentication_id}
        self.send_worker(message, (lease_fd, credential) if fresh else lease_fd)

    def resume_request(self, request, lease_fd, credential=None):
        require(self.reusable and self.state == 'session_unmounted')
        expected = {'op': 'mount', 'boot_id': self.config['boot_id'], 'run_id': self.config['run_id'],
            'volume_token': self.receipt['volume_token'], 'requested_mode': request.get('requested_mode'),
            'write_confirmed': request.get('write_confirmed'),
            'require_fresh_authentication': request.get('require_fresh_authentication')}
        require(request == expected and type(request['require_fresh_authentication']) is bool)
        support.validate_detached(self.receipt, boot_id=self.config['boot_id'])
        retry_at = self.receipt.get('retry_not_before_monotonic', 0)
        require(type(retry_at) in (int,float), message='Authentication retry deadline changed')
        if self.now() < retry_at:
            import math
            raise SessionError('RETRY_LATER', 'Native authentication is rate limited',
                {'retry_after_seconds':math.ceil(retry_at-self.now()),
                 'session_preserved':True, 'reboot_required':False})
        fresh = request['require_fresh_authentication'] or support.auth_required(self.receipt) or credential is not None
        require(not fresh or credential is not None,
                'CREDENTIAL_REQUIRED', 'Enter the current Android password for this mount')
        self.begin_mount(request['requested_mode'], request['write_confirmed'], lease_fd, credential, fresh=fresh)

    def authenticated(self, worker_pid, worker_ticks, tree_fd=None, proof=None,
                      credential_type=None, requested_mode='ro', session_proof=None):
        if not self.reusable:
            return super().authenticated(worker_pid, worker_ticks, tree_fd, proof, credential_type, requested_mode)
        if self.cancelled:
            self.send_worker({'op': 'cancel'}, None)
            return
        new = native_proof(session_proof, self.native, state='mounted')
        require(new['mode'] == requested_mode == self.requested_mode
                and session_proof.get('authentication_id') == self.pending_authentication_id
                and session_proof.get('authentication_performed') is self.pending_fresh)
        if self.pending_fresh:
            require(new['auth_sequence'] == self.native['auth_sequence'] + 1
                    and new['committed_auth_sequence'] == new['auth_sequence'])
            self.authentication_id = self.pending_authentication_id
            self.password_policy_at_auth = self.pending_policy
        else:
            require(new['auth_sequence'] == self.native['auth_sequence']
                    and new['committed_auth_sequence'] == self.native['committed_auth_sequence'])
        self.native = new
        super().authenticated(worker_pid, worker_ticks, tree_fd, proof, credential_type, requested_mode)
        device = self.receipt['device']
        if device not in self.detached_devices:
            # Only current and original devices are needed; older crypto maps
            # were independently removed at preceding suspend transitions.
            self.detached_devices = self.detached_devices[:1] + [device]

    def request_unmount(self, fd):
        if not self.reusable:
            return super().request_unmount(fd)
        require(self.state == 'mounted')
        self.remove_global()
        self.start_suspend(fd)

    def remove_global(self):
        if not self.bound:
            return
        try:
            self.mounts.unmount(self.config['mountpoint'])
        except OSError as error:
            if error.errno == errno.EBUSY:
                raise SessionError('VOLUME_BUSY',
                    'Android data is in use. Close files or other operations, then unmount again.',
                    {'session_preserved': True, 'retry_allowed': True, 'reboot_required': False}) from None
            raise
        self.bound = False

    def cancel_prepared(self, lease_fd):
        if not self.reusable:
            return super().cancel_prepared(lease_fd)
        require(self.state == 'awaiting_credential')
        self.start_suspend(lease_fd)

    def start_suspend(self, lease_fd):
        self.state = 'suspending'
        self.deadline = self.now() + CLEANUP_SECONDS
        self.pending_error = None
        self.pending_fresh = False
        self.commit(dict(self.receipt, state='suspending'))
        self.send_worker({'op': 'suspend', 'deadline': self.deadline}, lease_fd)

    def suspended(self, proof, error=None):
        require(self.reusable and self.state in ('suspending', 'authenticating') and not self.bound)
        self.native = native_proof(proof, self.native, state='suspended')
        if error is not None:
            require(self.state == 'authenticating' and type(error) is dict
                    and error.get('code') in ('CREDENTIAL_REJECTED', 'RETRY_LATER', 'DECRYPT_FAILED')
                    and self.native['cache_valid'] is False)
            self.pending_error = error
        record = {k: self.receipt[k] for k in ('schema', 'boot_id', 'run_id',
            'supervisor_pid', 'supervisor_starttime', 'worker_pid', 'worker_starttime',
            'physical_volume_token', 'profile_id', 'credential_type', 'android_user_id')}
        record.update(state='session_unmounted', detached_proof_schema='a22x.ce-session.suspend.v1', ce_authenticated=False,
            fscrypt_policy_verified=False, filesystem_unmounted=True, read_only=True,
            access_modes=['ro', 'rw'], native_efs_persistence=True,
            physical_device=self.config['layout']['physical']['userdata']['device'],
            detached_devices=list(self.detached_devices),
            owned_crypto_names=list(self.owned_crypto_names))
        if error is not None:
            details = error.get('details', {})
            retry = details.get('retry_after_seconds', 0)
            require(type(retry) is int and 0 <= retry <= 4294968)
            record.update(error_code=error['code'], retry_after_seconds=retry,
                          retry_not_before_monotonic=self.now()+retry)
            if 'native_mount_failure' in details:
                failure = support.public_mount_failure(details['native_mount_failure'])
                require(failure is not None, message='Invalid native mount failure details')
                record['native_mount_failure'] = failure
        self.commit(record)
        self.receipt = record
        support.validate_detached(record, boot_id=self.config['boot_id'])
        self.state = 'binding_detached'
        self.send_worker({'op': 'hold_detached'}, None)

    def held(self):
        if self.state != 'binding_detached':
            return super().held()
        self.release_lease()
        self.state = 'session_unmounted'
        self.deadline = self.now() + HEARTBEAT_SECONDS
        return self.receipt

    def pong(self):
        if self.state == 'session_unmounted':
            self.deadline = self.now() + HEARTBEAT_SECONDS
        else:
            super().pong()

    def reply(self, receipt):
        if self.pending_error:
            error = self.pending_error
            self.pending_error = None
            return {'ok': False, 'error': error, 'state': receipt,
                    'session_preserved': True, 'reboot_required': False}
        return {'ok': True, 'state': receipt,
                'authentication_performed': self.pending_fresh and receipt['state'] == 'mounted',
                'reboot_required': False, 'session_retained': True}

    def request_close(self, lease_fd):
        if not self.reusable:
            if self.state == 'awaiting_credential':
                return super().cancel_prepared(lease_fd)
            return super().request_unmount(lease_fd)
        require(self.state in ('mounted', 'session_unmounted', 'awaiting_credential'))
        self.remove_global()
        self.state = 'cleaning'
        self.deadline = self.now() + CLEANUP_SECONDS
        self.commit(dict(self.receipt, state='cleaning'))
        self.send_worker({'op': 'close', 'deadline': self.deadline}, lease_fd)

    def complete(self, returncode, worker_result):
        # Terminal proof has the same independent EFS/DM/process checks as the
        # old one-shot path; a suspended receipt never passes this branch.
        result = super().complete(returncode, worker_result)
        if self.reusable and result.get('ok') is True:
            result.update(session_closed=True, session_retained=False, cleanup_verified=True)
        return result
