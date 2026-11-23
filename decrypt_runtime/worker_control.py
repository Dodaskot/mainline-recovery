"""Hold authenticated CE inside the original callback's try/finally."""
import os
import select
import math
import socket
import sys
import time
from android_profiles import SAMSUNG_PROFILE, EVO_PROFILE, LEGACY_EVO_NONE_PROFILE, PROFILES, credential_allowed
from decrypt_runtime.mounts import export_tree, mounted_at
from decrypt_runtime.common import (SessionError, packet, receive, require, validate_lease,
    packet_fds, receive_fds, promote_credential)

_control = None
_held = False
_discovery = False
_profile = SAMSUNG_PROFILE

def initialize(fd, discovery=False, profile_id=SAMSUNG_PROFILE):
    global _control, _discovery, _profile
    require(profile_id in PROFILES)
    require(profile_id not in (EVO_PROFILE, LEGACY_EVO_NONE_PROFILE) or discovery, message="NONE requires discovery dispatch")
    _profile = profile_id
    _control = socket.socket(fileno=fd)
    _discovery = discovery

def emit(event, fields):
    # Only final typed native verdict fields cross to the global supervisor.
    if event == 'c_session_result':
        verdict = {}
        try:
            verdict = fields['outcome']['extension_result']['consumer']
        except (KeyError, TypeError):
            pass
        safe = {key: verdict[key] for key in ('success', 'failure_stage',
                'native_auth_status', 'native_timeout_ms') if key in verdict}
        if fields.get('unsupported_verified') is True and fields.get('public_error_code') == 'WRITE_NOT_QUALIFIED':
            safe.update(success=False, failure_stage='unsupported_credential', error_code='WRITE_NOT_QUALIFIED')
        packet(_control, {'event': 'result', 'cleanup_verified': fields.get('cleanup_verified') is True,
                          'success': fields.get('success') is True, 'verdict': safe})

# Exact long-lived argv/UID/context profiles from qualified Runtime.bootstrap.
# Property GET/SET, probes and G4 commands share runtime.processes but have
# already returned; liveness is required only for these eight owned services.
SERVICE_PROFILES = (
    (('/system/bin/a22x-property-service', '--serve', '/run/properties.seed'),
     0, 'u:r:recovery:s0'),
    (('/system/bin/servicemanager',), 0, 'u:r:recovery:s0'),
    (('/system/bin/hwservicemanager',), 0, 'u:r:recovery:s0'),
    (('/system/bin/vndservicemanager', '/dev/vndbinder'), 0, 'u:r:recovery:s0'),
    (('/vendor/bin/tzdaemon',), 1000, 'u:r:hal_keymaster_default:s0'),
    (('/vendor/bin/tzts_daemon',), 1000, 'u:r:hal_keymaster_default:s0'),
    (('/vendor/bin/hw/android.hardware.keymaster@4.0-service',),
     1000, 'u:r:hal_keymaster_default:s0'),
    (('/vendor/bin/hw/android.hardware.gatekeeper@1.0-service',),
     1000, 'u:r:hal_gatekeeper_default:s0'),
)

def forbid_gatekeeper(runtime):
    require(getattr(runtime, 'gatekeeper', None) is None
            and getattr(runtime, 'gatekeeper_diagnostic', None) is None,
            message='NONE cannot own Gatekeeper or its diagnostic')
    for process in runtime.processes:
        argv = process.args
        require(not (isinstance(argv, (list, tuple)) and argv
                     and 'gatekeeper' in os.path.basename(str(argv[0]))),
                message='Unexpected Gatekeeper process in NONE session')
    require(not any('gatekeeper' in os.path.basename(str(event.get('executable', '')))
                    for event in runtime.events if event.get('event') == 'spawn'),
            message='Unexpected Gatekeeper spawn in NONE session')


def service_profiles(profile_id):
    require(profile_id in PROFILES)
    return SERVICE_PROFILES[:-1] if profile_id == LEGACY_EVO_NONE_PROFILE else SERVICE_PROFILES


def required_services(runtime, profile_id=SAMSUNG_PROFILE):
    """Select by exact admitted argv/evidence, NEVER by current poll result."""
    profiles = service_profiles(profile_id)
    if profile_id == LEGACY_EVO_NONE_PROFILE:
        forbid_gatekeeper(runtime)
    selected, positions = [], []
    for argv, uid, context in profiles:
        matches = [(index, process) for index, process in enumerate(runtime.processes)
                   if isinstance(process.args, (list, tuple)) and tuple(process.args) == argv]
        require(len(matches) == 1, message='Required owned service missing or duplicated')
        index, process = matches[0]
        require(type(process.pid) is int and process.pid > 1)
        events = [event for event in runtime.events
                  if event.get('event') == 'spawn' and event.get('pid') == process.pid]
        require(len(events) == 1, message='Required owned service spawn evidence missing or duplicated')
        event = events[0]
        require(event.get('executable') == argv[0]
                and type(event.get('uid')) is int and event['uid'] == uid
                and event.get('context') == context and event.get('context_verified') is True,
                message='Required owned service path/UID/context mismatch')
        selected.append(process)
        positions.append(index)
    require(positions[0] == 0 and positions == sorted(positions)
            and len({process.pid for process in selected}) == len(profiles),
            message='Required service ownership/order mismatch')
    return tuple(selected)

def assert_services_alive(runtime, services, profile_id=SAMSUNG_PROFILE):
    require(len(services) == len(service_profiles(profile_id)))
    if profile_id == LEGACY_EVO_NONE_PROFILE:
        forbid_gatekeeper(runtime)
    for process in services:
        # A terminated daemon remains REQUIRED and is rejected by the original
        # qualified assertion; filtering poll()==None would conceal its loss.
        runtime.assert_alive(process)

def hold(runtime, verdict, records, storage_trace, requested_mode='ro'):
    require(_profile == SAMSUNG_PROFILE)
    if verdict.get('success') is not True:
        return
    require(storage_trace.get('cleanup_verified') is True
            and storage_trace.get('status') == 'SCALAR_TRACE_COMPLETE')
    diagnostic = runtime.gatekeeper_diagnostic
    diagnostic.drain()
    parser = diagnostic.parser
    calls = parser.records[1:]
    require(parser.error is None and parser.ready and not parser.eof
            and not parser.pending and len(calls) == 2
            and all(r.get('kind') == 'CALL' and r.get('cmd') == 126
                    and r.get('result') == 0 and r.get('ta_present') == 1
                    and r.get('ta_bound') == 'QUALIFIED' and r.get('ta_status') == 0
                    for r in calls), message='Two qualified native verifications required')
    services = required_services(runtime)
    _hold_ce(runtime, services, SAMSUNG_PROFILE, requested_mode=requested_mode)


def hold_none(runtime, records, run_id, independent_media_read):
    require(_profile == LEGACY_EVO_NONE_PROFILE and _discovery,
            message='NONE hold requires selected discovery profile')
    from decrypt_runtime.ro_none_callback_session import qualify_ce
    verdict = qualify_ce(records, run_id, independent_media_read)
    require(verdict['success'] is True)
    services = required_services(runtime, LEGACY_EVO_NONE_PROFILE)
    _hold_ce(runtime, services, LEGACY_EVO_NONE_PROFILE)
    return verdict


def _hold_ce(runtime, services, profile_id, credential_type=None, requested_mode='ro'):
    # Authentication evidence is qualified by each profile BEFORE this shared
    # mount/lease tail. A missing GK is never accepted by the Samsung validator.
    global _held
    assert_services_alive(runtime, services, profile_id)
    require(requested_mode in ('ro','rw') and (credential_type != 'none' or requested_mode == 'ro'))
    if requested_mode == 'rw':
        tree, proof = export_tree(runtime.backend.at('/mnt/userdata-ro'), read_only=False)
    else:
        tree, proof = export_tree(runtime.backend.at('/mnt/userdata-ro'))
    try:
        packet(_control, {'event': 'authenticated', 'mount_transfer': proof, 'requested_mode': requested_mode, **({'credential_type': credential_type} if credential_type else {})}, tree)
    finally:
        os.close(tree)
    # Original lease remains held until global bind and root state commit.
    message, new_fd = receive(_control, True)
    require(new_fd is None)
    require(message.get('op') in ('hold', 'cancel'))
    if message['op'] == 'cancel':
        return
    # Keep the exact native descriptor NUMBER reserved, but close this
    # worker's inherited OFD. Parent/SSH administrative ownership stays intact.
    reserve_descriptor(runtime.common_lock_fd)
    _held = True
    try:
        packet(_control, {'event': 'held'})
    except BaseException:
        park_for_reset()
    while True:
        try:
            message, new_fd = receive(_control, True)
        except BaseException:
            park_for_reset()
        try:
            if message.get('op') == 'ping':
                require(new_fd is None)
                assert_services_alive(runtime, services, profile_id)
                packet(_control, {'event': 'pong', 'serial': message.get('serial')})
            elif message.get('op') == 'unmount':
                require(new_fd is not None, message='Fresh cleanup lease required')
                validate_lease(new_fd)
                # Native cleanup keeps its original descriptor number and now
                # borrows the unmount caller's newly held open-file description.
                target = runtime.common_lock_fd
                adopt_lease(new_fd, target)
                if new_fd == target:
                    new_fd = None
                os.environ['A22X_RECOVERY_LOCK_FD'] = str(target)
                packet(_control, {'event': 'cleaning'})
                return
            else:
                raise SessionError(message='Unexpected held-session operation')
        except BaseException:
            park_for_reset()
        finally:
            if new_fd is not None:
                os.close(new_fd)


def park_for_reset():
    while True:
        try:
            __import__('time').sleep(1)
        except BaseException:
            continue

def reserve_descriptor(target):
    dummy = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
    try:
        if dummy != target:
            os.dup2(dummy, target, inheritable=False)
    finally:
        if dummy != target:
            os.close(dummy)

def adopt_lease(received, target):
    # The same descriptor case is valid and must not close the adopted lease.
    if received != target:
        os.dup2(received, target, inheritable=False)

def check_before_auth():
    # This check only runs BEFORE native credential dispatch. Never interrupt
    # or kill a native process once its secure call may have started.
    if select.select([_control], [], [], 0)[0]:
        message, fd = receive(_control)
        require(fd is None and message.get('op') == 'cancel')
        raise SessionError(message='Authentication cancelled before credential dispatch')


def source_identity(runtime):
    path = str(runtime.backend.at('/mnt/userdata-ro'))
    info = mounted_at(path)
    require(info['root'] == '/' and info['fstype'] == 'f2fs'
            and 'ro' in info['options'] and 'ro' in info['super_options'])
    root = os.stat(path, follow_symlinks=False)
    return {'mount_id': info['mount_id'], 'device': info['device'], 'root': '/',
            'root_inode': root.st_ino, 'fstype': 'f2fs', 'read_only': True,
            'namespace': os.readlink('/proc/self/ns/mnt')}

def require_zero_auth_calls(runtime):
    diagnostic = runtime.gatekeeper_diagnostic
    diagnostic.drain()
    parser = diagnostic.parser
    require(parser.error is None and parser.ready and not parser.eof and not parser.pending
            and parser.records == [{'kind': 'READY', 'version': 2}],
            message='Preparation must have zero Gatekeeper calls')

def awaiting_credential(runtime, credential_slot, credential_type, rw_capability=None):
    """Pause AFTER native prepare, BEFORE any credential/native verification."""
    require(_profile in (SAMSUNG_PROFILE, EVO_PROFILE) and credential_allowed(_profile, credential_type), message='Unqualified credential type')
    if not _discovery:
        require(credential_type == 'password')
        return 'ro'
    require(credential_slot[0] < 0 and credential_type in ('password', 'pattern'))
    require_zero_auth_calls(runtime)
    services = required_services(runtime, _profile)
    assert_services_alive(runtime, services, _profile)
    packet(_control, {'event': 'prepared', 'credential_type': credential_type,
                      'source_identity': source_identity(runtime)})
    message, fd = receive(_control)
    require(fd is None and message.get('op') in ('await', 'cancel'))
    if message['op'] == 'cancel':
        raise SessionError('CANCELLED', 'Preparation cancelled before authentication')
    reserve_descriptor(runtime.common_lock_fd)
    # No exception may unwind original cleanup while its lease slot is dummy.
    try:
        packet(_control, {'event': 'prepared_held'})
        while True:
            message, fds = receive_fds(_control, 2)
            try:
                if message.get('op') == 'ping':
                    require(not fds)
                    assert_services_alive(runtime, services, _profile)
                    require_zero_auth_calls(runtime)
                    packet(_control, {'event': 'pong', 'serial': message.get('serial')})
                    continue
                require_zero_auth_calls(runtime)
                require(message.get('credential_type') == credential_type)
                if message.get('op') == 'authenticate':
                    require(len(fds) == 2)
                    validate_lease(fds[0])
                    mode=message.get('requested_mode')
                    require(mode in ('ro','rw') and type(message.get('write_confirmed')) is bool
                        and message['write_confirmed'] is (mode=='rw'))
                    if mode=='rw':
                        from decrypt_runtime.rw_support import quotas, qualified_credential
                        require(qualified_credential(_profile, credential_type),
                                'WRITE_NOT_QUALIFIED', 'This profile and credential are not write-qualified')
                        quotas(rw_capability, __import__('decrypt_runtime.common',fromlist=['boot_id']).boot_id(), fds[0])
                    deadline = message.get('deadline')
                    require(type(deadline) in (int, float) and math.isfinite(deadline)
                            and time.monotonic() < deadline <= time.monotonic() + 241)
                    credential = promote_credential(fds[1])
                    try:
                        adopt_lease(fds[0], runtime.common_lock_fd)
                    except BaseException:
                        os.close(credential)
                        raise
                    if fds[0] == runtime.common_lock_fd:
                        fds[0] = None
                    credential_slot[0] = credential
                    os.environ['A22X_C_WD_DEADLINE'] = str(deadline)
                    os.environ['A22X_RECOVERY_LOCK_FD'] = str(runtime.common_lock_fd)
                    packet(_control, {'event': 'auth_dispatching','requested_mode':mode})
                    return mode
                require(message.get('op') == 'cancel_prepared' and len(fds) == 1)
                validate_lease(fds[0])
                adopt_lease(fds[0], runtime.common_lock_fd)
                if fds[0] == runtime.common_lock_fd:
                    fds[0] = None
                packet(_control, {'event': 'cleaning'})
                raise PreparationCancelled()
            finally:
                for descriptor in fds:
                    if descriptor is not None:
                        os.close(descriptor)
    except PreparationCancelled:
        raise SessionError('CANCELLED', 'Prepared session cancelled before authentication')
    except BaseException:
        park_for_reset()

class PreparationCancelled(Exception):
    pass


def hold_evox(runtime, verdict, records, run_id, independent, requested_mode='ro'):
    require(_profile == EVO_PROFILE and _discovery, message='Neutral Evo discovery required')
    from decrypt_runtime.ro_evox_callback_session import qualify_retained, discovered_type
    require(requested_mode in ('ro','rw'))
    if requested_mode == 'rw':
        from decrypt_runtime.ro_evox_callback_session import qualify_retained_rw
        qualified=qualify_retained_rw(records,run_id,independent)
    else:
        qualified = qualify_retained(records, run_id, independent)
    require(qualified['success'] is True and verdict['success'] is True)
    if discovered_type(records[2]['status_lines']) == 'none':
        require_zero_auth_calls(runtime)
    else:
        diagnostic = runtime.gatekeeper_diagnostic
        diagnostic.drain()
        parser = diagnostic.parser
        calls = parser.records[1:]
        require(parser.error is None and parser.ready and not parser.eof and not parser.pending
                and parser.records[0] == {'kind':'READY','version':2} and len(calls) == 2
                and all(r.get('kind') == 'CALL' and r.get('version') == 2 and r.get('cmd') == 126
                        and r.get('result') == 0 and r.get('ta_present') == 1
                        and r.get('ta_bound') == 'QUALIFIED' and r.get('ta_status') == 0
                        for r in calls), message='Two qualified native verifications required')
    services = required_services(runtime, EVO_PROFILE)
    _hold_ce(runtime, services, EVO_PROFILE, discovered_type(records[2]['status_lines']), requested_mode=requested_mode)
