"""Reusable CE callback. All secret transport is native FD-to-FD only."""
import array
import hashlib
import json
import math
import os
from pathlib import Path
import select
import socket
import struct
import time

from android_profiles import EVO_PROFILE
from decrypt_runtime.common import (SessionError, require, packet, receive, receive_fds,
    validate_lease, promote_credential, starttime, credential_fd, public_failure)
from decrypt_runtime.mounts import export_tree, mount_records
from decrypt_runtime import worker_control as control
from decrypt_runtime.session_support import capability, RAM_SNAPSHOT_HELPER
from decrypt_runtime.reusable_lifecycle import PROOF_SCHEMA

REQUEST = struct.Struct('<IHHQQIIq')
RESPONSE = struct.Struct('<IHHQQIIIIiIIIQQ')
MAGIC = 0x41524353
STATES = {1:'prepared', 2:'mounted', 3:'suspended', 4:'closed', 5:'quarantined'}
MODES = {0:'none', 1:'ro', 2:'rw'}
OPS = {'authenticate':1, 'resume':2, 'suspend':3, 'close':4, 'status':5}

def decode_response(data, *, pid, op):
    require(type(data) is bytes and len(data) == RESPONSE.size,
            message='Native session response size changed')
    magic,version,seen_op,sequence,generation,state,mode,flags,phase,error,cleanup,seen_pid,reserved,auth,committed = RESPONSE.unpack(data)
    require(magic == MAGIC and version == 1 and seen_op == op and seen_pid == pid
            and reserved == 0 and state in STATES and mode in MODES and flags & ~111 == 0
            and 1 <= phase <= 14 and -4095 <= error <= 0 and 0 <= cleanup <= 4095
            and committed <= auth and flags & 32
            and (not flags & 64 or (state == 2 and mode == 1 and flags & 4 and not error and not cleanup)),
            message='Native session response contract changed')
    return {'schema':PROOF_SCHEMA, 'pid':pid, 'sequence':sequence, 'generation':generation,
        'state':STATES[state], 'mode':MODES[mode], 'cache_valid':bool(flags & 1),
        'auth_dispatched':bool(flags & 2), 'ce_verified':bool(flags & 4),
        'suspend_clean':bool(flags & 8), 'lease_released':bool(flags & 32), 'ram_snapshot':bool(flags & 64),
        'phase':phase, 'error_errno':error, 'cleanup_errno':cleanup,
        'auth_sequence':auth, 'committed_auth_sequence':committed}

class DiagnosticEpochs:
    """Exact per-operation records, bounded memory, lifetime audit chain.

    Rotation continues the same already-observed READY stream. It never emits
    or consumes a synthetic diagnostic record, and rejects an extra READY.
    """
    def __init__(self, diagnostic):
        self.diagnostic = diagnostic
        diagnostic.drain()
        p = diagnostic.parser
        require(p.error is None and p.ready and not p.eof and not p.pending
                and p.records == [{'kind':'READY','version':2}],
                message='Native diagnostic stream is not initially empty')
        self.ready = dict(p.records[0])
        self.operations = self.auth_attempts = self.auth_successes = self.calls = 0
        self.digest = hashlib.sha256(b'a22x.ce-session.epochs.v1').hexdigest()
        self.recent = []

    def quiet(self):
        self.diagnostic.drain()
        p = self.diagnostic.parser
        require(p.error is None and p.ready and not p.eof and not p.pending
                and p.records == [self.ready], message='Unexpected verification outside an authentication operation')

    def finish(self, op, response, authentication_id=None):
        self.diagnostic.drain()
        p = self.diagnostic.parser
        require(p.error is None and p.ready and not p.eof and not p.pending
                and p.records and p.records[0] == self.ready,
                message='Incomplete native verification diagnostics')
        calls = p.records[1:]
        require(len(calls) <= 2 and all(type(x) is dict and x.get('kind') == 'CALL'
                and x.get('version') == 2 and x.get('cmd') == 126 for x in calls),
                message='Unexpected native verification count or operation')
        fresh = op == 'authenticate' and response['auth_dispatched']
        error = None
        if not fresh:
            require(not calls and not response['auth_dispatched'],
                    message='A cached operation unexpectedly authenticated')
        elif response['error_errno'] == 0:
            require(len(calls) == 2 and all(x.get('result') == 0
                and x.get('ta_present') == 1 and x.get('ta_bound') == 'QUALIFIED'
                and x.get('ta_status') == 0 for x in calls),
                message='Fresh authentication lacks both qualified native verifications')
            self.auth_successes += 1
        else:
            require(response['state'] == 'suspended' and response['cleanup_errno'] == 0
                    and response['cache_valid'] is False)
            if calls and calls[-1].get('result') == 0 and calls[-1].get('ta_present') == 1 and calls[-1].get('ta_bound') == 'QUALIFIED' and calls[-1].get('ta_status') in (1, 2):
                require(all(x.get('result') == 0 and x.get('ta_present') == 1
                    and x.get('ta_bound') == 'QUALIFIED' and x.get('ta_status') == 0 for x in calls[:-1]))
                error = public_failure({'success':False, 'native_auth_status':calls[-1]['ta_status'],
                    'native_timeout_ms':calls[-1].get('ta_timeout',0)})
                # TA ERROR(1) alone does not distinguish a bad password from
                # another verification error. Preserve the qualified wording.
                error.details.update(reboot_required=False, session_preserved=True)
            else:
                error = SessionError('DECRYPT_FAILED', 'Native authentication did not produce a usable key',
                    {'retry_allowed':False, 'session_preserved':True, 'reboot_required':False})
        if op == 'authenticate' and response['error_errno'] and error is None:
            error = SessionError('DECRYPT_FAILED', 'Android data preparation failed before password verification',
                {'credential_submitted':False, 'session_preserved':True, 'reboot_required':False})
        if op == 'resume' and response['error_errno']:
            error = SessionError('DECRYPT_FAILED', 'Could not remount Android data with the retained session',
                {'session_preserved':True, 'reboot_required':False, 'retry_allowed':False})
        if error is not None:
            # The response is already wire-checked. Count only qualified successful verifications.
            verified = sum(x.get('result') == 0 and x.get('ta_present') == 1
                           and x.get('ta_bound') == 'QUALIFIED' and x.get('ta_status') == 0 for x in calls)
            error.details['native_mount_failure'] = {
                'phase':response['phase'], 'errno':-response['error_errno'],
                'auth_dispatched':fresh, 'gatekeeper_verified':verified,
            }
        if fresh:
            self.auth_attempts += 1
        self.operations += 1
        self.calls += len(calls)
        entry = {'operation':op, 'sequence':response['sequence'], 'generation':response['generation'],
            'auth_sequence':response['auth_sequence'], 'committed_auth_sequence':response['committed_auth_sequence'],
            'authentication_id':authentication_id if fresh else None,
            'calls':calls, 'error_errno':response['error_errno'], 'state':response['state']}
        self.digest = hashlib.sha256(bytes.fromhex(self.digest) +
            json.dumps(entry, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        self.recent = (self.recent + [entry])[-16:]
        # Each window starts after a complete, consumed, checked operation.
        # Readiness is inherited from the observed stream, not asserted anew.
        continuation = type(p)()
        continuation.ready = True
        continuation.records = [dict(self.ready)]
        self.diagnostic.parser = continuation
        return error

    def summary(self):
        return {'schema':'a22x.ce-session.epochs.v1', 'operations':self.operations,
            'auth_attempts':self.auth_attempts, 'auth_successes':self.auth_successes,
            'calls':self.calls, 'sha256':self.digest, 'recent':self.recent,
            'continuation_ready_observed':True}

def pin_native_executable(runtime, cap):
    from decrypt_runtime.rw_support import pinned_fd
    target = runtime.backend.at(cap['helper'])
    original = pinned_fd(target, cap['helper_sha256'], executable=True)
    os.close(original)
    digest = cap.get('ram_snapshot_sha256')
    if digest is None:
        return None
    helper = pinned_fd(RAM_SNAPSHOT_HELPER, digest, executable=True)
    bind = 0x1000
    protected = bind | 0x20 | 1 | 2 | 4  # remount, read-only, nosuid, nodev
    try:
        # The executable pins the bind mount while the native owner runs. The
        # runtime records the mount for normal cleanup after that owner exits.
        runtime.backend._mount('/proc/self/fd/' + str(helper), target, None, bind)
        try:
            runtime.backend._mount(None, target, None, protected)
            bound = pinned_fd(target, digest, executable=True)
            os.close(bound)
        except BaseException:
            runtime.backend.unmount(target)
            raise
        return target
    finally:
        os.close(helper)


class NativeSession:
    def __init__(self, runtime, cap, run_id, boot_id, physical_token, *, target, ram,
                 keydir, source, oldwork, oldname, oldcreator):
        self.runtime = runtime
        physical = os.fstat(source).st_rdev
        self.physical_device = '%d:%d' % (os.major(physical), os.minor(physical))
        self.target = target
        self.oldwork, self.oldname = oldwork, oldname
        self.rowork, self.roname = '/run/sp-session-ro', oldname + '-session-ro'
        self.rwwork, self.rwname = '/run/sp-session-rw', oldname + '-session-rw'
        self.names = [n + suffix for n in (oldname, self.roname, self.rwname) for suffix in ('', '-raw')]
        if 'ram_snapshot_sha256' in cap:
            self.names.extend(self.roname + suffix for suffix in ('-cow', '-cow-base'))
        for name in (self.rowork, self.rwwork):
            runtime.backend.at(name).mkdir(mode=0o700)
        self.socket, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        argv = [cap['helper'], 'serve', target, ram, str(keydir), str(source), oldwork, oldname,
            str(oldcreator), self.rowork, self.roname, self.rwwork, self.rwname,
            str(child.fileno()), str(os.getpid()), boot_id, run_id, physical_token]
        try:
            self.snapshot_executable = pin_native_executable(runtime, cap)
            self.process = runtime.spawn(argv, pass_fds=(keydir, source, child.fileno()), verify_label=False)
        except BaseException:
            control.park_for_reset()
        finally:
            child.close()
        self.ticks = starttime(self.process.pid)
        self.reply = self.receive(0, time.monotonic() + 10)
        require(self.reply['state'] == 'prepared' and self.reply['sequence'] == 0
                and self.reply['generation'] == 0 and self.reply['error_errno'] == 0)
        self.current_name, self.current_work = oldname, oldwork
        self.last_requested_mode = 'ro'

    def receive(self, op, deadline):
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, message='Native session operation deadline expired')
            ready, _, _ = select.select([self.socket, self.runtime.gatekeeper_diagnostic.read_fd], [], [], min(remaining, .25))
            self.runtime.gatekeeper_diagnostic.drain()
            if self.socket not in ready:
                self.runtime.assert_alive(self.process)
                continue
            data, ancillary, flags, _ = self.socket.recvmsg(RESPONSE.size + 1, socket.CMSG_SPACE(16))
            received = []
            for level,kind,payload in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    values = array.array('i'); values.frombytes(payload[:len(payload) - len(payload)%values.itemsize])
                    received.extend(values)
            for fd in received:
                os.close(fd)
            require(not ancillary and not flags and not received)
            value = decode_response(data, pid=self.process.pid, op=op)
            value['starttime'] = self.ticks
            return value

    def command(self, op, deadline, lease=None, credential=None, mode='none'):
        number = OPS[op]
        old = dict(self.reply)
        if number == 5:
            seq = generation = 0
            fds = ()
        else:
            validate_lease(lease)
            seq, generation = old['sequence'] + 1, old['generation']
            fds = (lease, credential) if number == 1 else (lease,)
            if number == 1:
                credential_fd(credential)
        data = REQUEST.pack(MAGIC, 1, number, seq, generation,
                            {'none':0,'ro':1,'rw':2}[mode], 0, int(deadline * 1000))
        ancillary = [] if not fds else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))]
        require(self.socket.sendmsg([data], ancillary) == len(data))
        result = self.receive(number, deadline)
        if number == 5:
            require(result['sequence'] == old['sequence'] and result['generation'] == old['generation']
                    and result['state'] == old['state'] and result['mode'] == old['mode']
                    and result['cache_valid'] is old['cache_valid']
                    and result['ce_verified'] is old['ce_verified']
                    and result['suspend_clean'] is old['suspend_clean']
                    and result.get('ram_snapshot', False) is old.get('ram_snapshot', False)
                    and result['auth_sequence'] == old['auth_sequence']
                    and result['committed_auth_sequence'] == old['committed_auth_sequence']
                    and result['error_errno'] == result['cleanup_errno'] == 0,
                    message='Native session state changed without an owned operation')
        else:
            require(result['sequence'] == seq and result['generation'] == generation + 1
                    and result['state'] != 'quarantined' and result['cleanup_errno'] == 0,
                    message='Native session outcome or cleanup is unknown')
            dispatched = number == 1 and result['auth_dispatched']
            require(result['auth_sequence'] == old['auth_sequence'] + int(dispatched)
                    and result['committed_auth_sequence'] == (result['auth_sequence'] if number == 1 and result['error_errno'] == 0 else old['committed_auth_sequence']),
                    message='Native authentication sequence did not match the requested operation')
            self.reply = result
            if result['state'] == 'mounted':
                self.last_requested_mode = mode
                original = old['state'] == 'prepared' and not result['ram_snapshot']
                self.current_name = self.rwname if mode == 'rw' else (self.oldname if original else self.roname)
                self.current_work = self.rwwork if mode == 'rw' else (self.oldwork if original else self.rowork)
        return result

    def proof(self, **extra):
        return dict(self.reply, owned_crypto_names=list(self.names), physical_device=self.physical_device, **extra)

    def close_observed(self):
        require(self.reply['state'] == 'closed' and not self.reply['cache_valid']
                and self.reply['suspend_clean'] is True)
        require(self.process.wait(timeout=5) == 0, message='Native key owner did not exit after wiping')
        self.socket.close()
        if self.snapshot_executable is not None:
            self.runtime.backend.unmount(self.snapshot_executable)
        for name in (self.rowork, self.rwwork):
            require(not any(self.runtime.backend.at(name).iterdir()))
            self.runtime.backend.at(name).rmdir()

def check_private_unmounted(runtime, native):
    path = str(runtime.backend.at(native.target))
    require(not any(m['mountpoint'] == path for m in mount_records(Path('/proc/self/mountinfo').read_text())),
            message='Native suspend left a private userdata filesystem')
    names = {p.read_text().strip() for p in Path('/sys/block').glob('dm-*/dm/name')}
    require(not names.intersection(native.names), message='Native suspend left userdata crypto mappings')

def serve(runtime, cap, config, credential_slot, *, target, ram, keydir, source,
          oldwork, oldname, oldcreator, prepared, initial_operations):
    """One TEE bootstrap; arbitrarily many explicit, bounded native operations."""
    cap = capability(cap)
    services = control.required_services(runtime, EVO_PROFILE)
    control.assert_services_alive(runtime, services, EVO_PROFILE)
    epochs = DiagnosticEpochs(runtime.gatekeeper_diagnostic)
    native = NativeSession(runtime, cap, config['run_id'], config['boot_id'], config['volume_token'],
        target=target, ram=ram, keydir=keydir, source=source, oldwork=oldwork, oldname=oldname, oldcreator=oldcreator)
    proof = native.proof()
    packet(control._control, {'event':'prepared', 'credential_type':'password',
        'source_identity':control.source_identity(runtime), 'session_proof':proof})
    message, fd = receive(control._control)
    require(fd is None and message.get('op') in ('await', 'cancel'))
    if message['op'] == 'cancel':
        native.command('close', time.monotonic()+40, runtime.common_lock_fd)
        epochs.finish('close', native.reply)
        native.close_observed()
        return result(native, epochs, prepared, initial_operations)
    control.reserve_descriptor(runtime.common_lock_fd)
    packet(control._control, {'event':'prepared_held'})
    while True:
        message, fds = receive_fds(control._control, 2)
        try:
            op = message.get('op')
            if op == 'ping':
                require(not fds)
                control.assert_services_alive(runtime, services, EVO_PROFILE)
                epochs.quiet()
                native.command('status', time.monotonic()+3)
                packet(control._control, {'event':'pong','serial':message.get('serial')})
                continue
            require(op in ('authenticate','resume','suspend','close'))
            require(len(fds) == (2 if op == 'authenticate' else 1))
            validate_lease(fds[0])
            control.adopt_lease(fds[0], runtime.common_lock_fd)
            if fds[0] == runtime.common_lock_fd:
                fds[0] = None
            deadline = message.get('deadline')
            require(type(deadline) in (int,float) and math.isfinite(deadline)
                    and time.monotonic() < deadline <= time.monotonic()+241)
            os.environ['A22X_RECOVERY_LOCK_FD'] = str(runtime.common_lock_fd)
            os.environ['A22X_C_WD_DEADLINE'] = str(deadline)
            mode = message.get('requested_mode', 'none')
            credential = None
            if op in ('authenticate','resume'):
                require(mode in ('ro','rw') and message.get('write_confirmed') is (mode == 'rw'))
                if mode == 'rw':
                    from decrypt_runtime.rw_support import quotas
                    quotas(config.get('ce_rw'), config['boot_id'], runtime.common_lock_fd)
                from decrypt_runtime.ro_evox_callback_session import current_framework_identity
                current_framework_identity(runtime, lambda *a,**k:None)
                if op == 'authenticate':
                    credential = promote_credential(fds[1])
                    credential_slot[0] = credential
                packet(control._control, {'event':'auth_dispatching','requested_mode':mode})
            # Close received duplicates before handing the final lease back.
            # Only the reserved native descriptor remains until hold/close.
            for index, received in enumerate(fds):
                if received is not None:
                    os.close(received); fds[index] = None
            epochs.quiet()
            response = native.command(op, deadline, runtime.common_lock_fd, credential, mode)
            if credential is not None:
                os.close(credential); credential_slot[0] = -1
            error = epochs.finish(op, response, message.get('authentication_id'))
            if response['error_errno'] and error is None:
                error = SessionError('DECRYPT_FAILED', 'The native mount operation failed',
                    {'session_preserved':True,'reboot_required':False,'retry_allowed':False})
            if op == 'close':
                require(error is None and response['state'] == 'closed')
                check_private_unmounted(runtime, native)
                native.close_observed()
                packet(control._control, {'event':'cleaning'})
                return result(native, epochs, prepared, initial_operations)
            if response['state'] == 'mounted':
                require(error is None)
                from decrypt_runtime.ro_evox_callback_session import independent_media_proof
                independent = independent_media_proof(runtime, target, config['run_id'], mode=='ro',
                    expected_name=native.current_name, alias_work=native.current_work)
                tree, transfer = export_tree(runtime.backend.at(target), read_only=mode=='ro')
                try:
                    packet(control._control, {'event':'authenticated','mount_transfer':transfer,
                        'credential_type':'password','requested_mode':mode,
                        'session_proof':native.proof(authentication_id=message['authentication_id'],
                            authentication_performed=op=='authenticate',
                            independent_media=independent)}, tree)
                finally:
                    os.close(tree)
                ack, fd = receive(control._control)
                require(fd is None and ack.get('op') in ('hold','cancel'))
                if ack['op'] == 'cancel':
                    native.command('close', time.monotonic()+40, runtime.common_lock_fd)
                    epochs.finish('close', native.reply)
                    check_private_unmounted(runtime, native)
                    native.close_observed()
                    return result(native, epochs, prepared, initial_operations)
            else:
                require(response['state'] == 'suspended' and response['suspend_clean'] is True)
                check_private_unmounted(runtime, native)
                packet(control._control, {'event':'suspended','session_proof':native.proof(),
                    'error':None if error is None else {'code':error.code,'message':error.message,'details':error.details}})
                ack, fd = receive(control._control)
                require(fd is None and ack == {'op':'hold_detached'})
            control.reserve_descriptor(runtime.common_lock_fd)
            packet(control._control, {'event':'held'})
        except BaseException:
            # No kill, implicit cleanup, native command retry, or forged result.
            # The supervisor's bounded watchdog handles an unknown owner state.
            control.park_for_reset()
        finally:
            for fd in fds:
                if fd is not None:
                    os.close(fd)

def result(native, epochs, prepared, initial_operations):
    return {'status':'REUSABLE_CE_SESSION_CLOSED', 'success':True, 'session_reusable':True,
        'credential_type':'password', 'requested_mode':native.last_requested_mode, 'prepared':prepared,
        'operations':list(initial_operations), 'native_final':native.proof(),
        'epochs':epochs.summary(), 'native_owner_reaped':True,
        'password_submissions':epochs.auth_attempts, 'unlock_dispatches':epochs.auth_attempts,
        'synthetic_write_calls':0}

def evaluate(extension, run_id):
    """Terminal proof after both native owner and original runtime are closed."""
    from decrypt_runtime.ro_evox_callback_session import qualify_common, qualify_prepare, discovered_type
    require(extension['status'] == 'G2_REMOTE_TEE_KEYMASTER_GATEKEEPER_DIAGNOSTIC_READY'
            and extension['consumer_run'] is True and extension['all_owned_processes_reaped'] is True
            and extension['process_cleanup_errors'] == [], message='Reusable runtime did not close')
    c = extension['consumer']
    require(c.get('success') is True and c.get('status') == 'REUSABLE_CE_SESSION_CLOSED'
            and c.get('session_reusable') is True and c.get('native_owner_reaped') is True)
    ops = c['operations']
    require(type(ops) is list and len(ops) == 4)
    qualify_common(ops, run_id)
    require(discovered_type(ops[2]['status_lines']) == 'password'
            and ops[3]['operation'] == 'prepare-evox-password-user0'
            and ops[3]['returncode'] == 0
            and c['prepared'] == qualify_prepare(ops[3]['status_lines']))
    final = c['native_final']
    require(final['state'] == 'closed' and final['cache_valid'] is False
            and final['suspend_clean'] is True and final['error_errno'] == final['cleanup_errno'] == 0)
    epochs = c['epochs']
    require(epochs['auth_attempts'] == c['password_submissions'] == c['unlock_dispatches']
            == final['auth_sequence'] and c['synthetic_write_calls'] == 0
            and epochs['operations'] == final['sequence']
            and epochs['continuation_ready_observed'] is True
            and 0 <= epochs['auth_successes'] <= epochs['auth_attempts']
            and epochs['calls'] <= 2 * epochs['auth_attempts'])
    d = extension['gatekeeper_teec_diagnostic']
    require(d['status'] == 'GK_TEEC_DIAGNOSTIC_OBSERVATIONS_CLOSED'
            and d['ready'] is True and d['eof'] is True and d['error'] is None
            and d['records'] == [{'kind':'READY','version':2}]
            and d['record_count'] == 1 and d['bytes'] == 0,
            message='Verification stream did not close at a checked epoch boundary')
    return True
