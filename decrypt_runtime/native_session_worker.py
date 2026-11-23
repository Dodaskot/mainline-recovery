#!/usr/bin/python3
"""One RO CE attempt; public verdict and closed v2 observations remain distinct."""
import argparse
import json
import os
from pathlib import Path
import sys
import traceback
from android_profiles import SAMSUNG_PROFILE, EVO_PROFILE, LEGACY_EVO_NONE_PROFILE, PROFILES
from decrypt_runtime.common import validate_config
from decrypt_runtime.ro_auth_callback_session import make_consumer, require, validate_credential_fd


def evaluate(extension):
    require(extension['status'] == 'G2_REMOTE_TEE_KEYMASTER_GATEKEEPER_DIAGNOSTIC_READY'
            and extension['consumer_run'] is True, 'Diagnostic runtime not ready')
    c = extension['consumer']
    trace=c['storage_trace']
    require(trace['mode']=='TZDAEMON_STORAGE' and trace['status']=='SCALAR_TRACE_COMPLETE'
            and trace['cleanup_verified'] is True, 'Storage scalar trace incomplete')
    ops = c['operations']
    rw=len(ops)>3 and ops[3]['operation']=='unlock-sp-user0-rw'
    expected=['unwrap-mount','unlock-de-user0','prepare-sp']+(['unlock-sp-user0-rw','cleanup-rw','cleanup'] if rw else ['unlock-sp-user0','cleanup'])
    require([x['operation'] for x in ops]==expected,'Unexpected operation sequence')
    require(all(type(x['returncode']) is int and x['returncode'] == 0 for x in ops[:3] + ops[4:]),
            'Admission or cleanup failed')
    require(c['synthetic_write_calls'] == 0, 'Unexpected write trial')
    if rw:
        from decrypt_runtime.rw_verdict import native_verdict,cleanup_verdict
        cleanup_verdict(ops[4],ops[3]['pid'])
    else:
        from decrypt_runtime.ro_auth_callback_session import native_verdict
    v = native_verdict(ops[3])
    require(c['success'] is v['success'] and c['status'] == v['status']
            and c.get('failure_stage') == v['failure_stage'], 'Native verdict mismatch')
    d = extension['gatekeeper_teec_diagnostic']
    require(d['status'] == 'GK_TEEC_DIAGNOSTIC_OBSERVATIONS_CLOSED' and d['ready'] is True
            and d['eof'] is True and d['error'] is None
            and d['trace_completeness'] == 'NOT_PROVEN_BY_PROTOCOL', 'Diagnostic not closed')
    records = d['records']
    require(type(d['record_count']) is int and d['record_count'] == len(records)
            and 1 <= len(records) <= 64 and type(d['bytes']) is int and 0 < d['bytes'] <= 16384,
            'Diagnostic bounds')
    require(records[0] == {'kind': 'READY', 'version': 2}, 'Missing v2 READY')
    calls = records[1:]
    require(all(r.get('kind') == 'CALL' and r.get('version') == 2 and r.get('cmd') == 126 for r in calls),
            'Unexpected diagnostic record')
    # Reparse each public record with the unchanged qualified parser. No trust in
    # unchecked scalar dictionaries; reject extra keys and invalid semantics.
    import gk_diagnostic
    require(all(type(r[k]) is int for r in calls for k in ('cmd','result','origin_present','origin',
            'ta_present','ta_status','ta_timeout','ta_timeout_valid')), 'Diagnostic scalar type')
    p = gk_diagnostic.Parser()
    p.feed(b'GK_TEEC_DIAG_READY version=2\n')
    for r in calls:
        raw = ('GK_TEEC_CALL_V2 cmd=%d result=0x%08x origin_present=%d origin=0x%08x '
               'ta_present=%d ta_status=%d ta_timeout=%d ta_timeout_valid=%d ta_bound=%s\n') % (
            r['cmd'],r['result'],r['origin_present'],r['origin'],r['ta_present'],r['ta_status'],
            r['ta_timeout'],r['ta_timeout_valid'],r['ta_bound'])
        p.feed(raw.encode('ascii'))
    require(p.error is None and p.records == records, 'Diagnostic scalar mismatch')
    if v['success']:
        require(len(calls) == 2 and all(r['result'] == 0 and r['ta_present'] == 1
                and r['ta_bound'] == 'QUALIFIED' and r['ta_status'] == 0 for r in calls),
                'RO success missing two qualified native verifications')
    elif v['failure_stage'] in ('protector', 'primary'):
        expected = 1 if v['failure_stage'] == 'protector' else 2
        require(len(calls) == expected, 'Auth failure call count mismatch')
        require(all(r['result'] == 0 and r['ta_present'] == 1 and r['ta_status'] == 0
                    for r in calls[:-1]), 'Preceding verification not successful')
    else:
        require(len(calls) <= 2, 'Extra verification call')
    return v['success']


def require_zero_gk_closed(diagnostic):
    require(type(diagnostic) is dict and
        diagnostic.get('status') == 'GK_TEEC_DIAGNOSTIC_OBSERVATIONS_CLOSED' and
        diagnostic.get('ready') is True and diagnostic.get('eof') is True and
        diagnostic.get('error') is None and
        diagnostic.get('records') == [{'kind':'READY','version':2}] and
        type(diagnostic.get('record_count')) is int and diagnostic['record_count'] == 1 and
        type(diagnostic.get('bytes')) is int and 0 < diagnostic['bytes'] <= 16384 and
        diagnostic.get('trace_completeness') == 'NOT_PROVEN_BY_PROTOCOL',
        'NONE_ZERO_VERIFY_PROOF')


def evaluate_evox(extension, run_id):
    if extension.get('consumer', {}).get('session_reusable') is True:
        from decrypt_runtime.reusable_worker import evaluate as evaluate_reusable
        return evaluate_reusable(extension, run_id)
    require(extension['status']=='G2_REMOTE_TEE_KEYMASTER_GATEKEEPER_DIAGNOSTIC_READY'
            and extension['consumer_run'] is True,'RUNTIME_NOT_READY')
    require(extension['all_owned_processes_reaped'] is True and extension['process_cleanup_errors']==[],
            'PROCESSES_NOT_REAPED')
    from decrypt_runtime.ro_evox_callback_session import native_verdict, qualify_prepare, discovered_type, qualify_retained, qualify_common
    c=extension['consumer'];ops=c['operations']
    require(type(ops) is list and len(ops) in (4,6,7), 'EVOX_OPERATION_COUNT')
    qualify_common(ops, run_id)
    kind = discovered_type(ops[2]['status_lines'])
    require(ops[2]['operation'] == 'discover-evox-user0' and type(ops[2]['returncode']) is int and ops[2]['returncode'] == 0, 'DISCOVERY_EXIT')
    if len(ops) == 4:
        require(kind == 'none' and [x['operation'] for x in ops] == ['unwrap-mount','unlock-de-user0','discover-evox-user0','cleanup'] and
            type(ops[3]['returncode']) is int and ops[3]['returncode'] == 0 and ops[3]['status_lines'] == ['G4 CLEANUP_PASS'], 'NONE_RW_REJECTION_SEQUENCE')
        require(c.get('status') == 'EVOX_NONE_RW_UNSUPPORTED_BEFORE_AUTH' and c.get('success') is False and
            c.get('failure_stage') == 'unsupported_credential' and c.get('error_code') == 'WRITE_NOT_QUALIFIED' and
            c.get('credential_type') == 'none' and c.get('requested_mode') == 'rw' and
            all(type(c.get(k)) is int and c[k] == 0 for k in ('password_submissions','unlock_dispatches','synthetic_write_calls')) and
            c.get('independent_media') is None, 'NONE_RW_REJECTION_CONTRACT')
        require_zero_gk_closed(extension.get('gatekeeper_teec_diagnostic'))
        require(c.get('credential_type') == 'none' and c.get('requested_mode') == 'rw' and
            c.get('independent_media') is None and all(type(c.get(k)) is int and c[k] == 0 for k in
            ('password_submissions','unlock_dispatches','synthetic_write_calls')), 'NONE_RW_ZERO_AUTH_PROOF')
        require_zero_gk_closed(extension['gatekeeper_teec_diagnostic'])
        return False
    ops = ops[:2] + ops[3:]
    if kind == 'none':
        require(len(ops)==5 and c.get('requested_mode','ro') == 'ro', 'NONE_RW_UNSUPPORTED_BEFORE_AUTH')
        require(c.get('credential_type') == 'none' and type(c.get('password_submissions')) is int and c['password_submissions'] == 0 and type(c.get('unlock_dispatches')) is int and c['unlock_dispatches'] == 0 and type(c.get('synthetic_write_calls')) is int and c['synthetic_write_calls'] == 0, 'NONE_DISPATCH_CONTRACT')
        from decrypt_runtime.ro_none_callback_session import evaluate_operations
        v = evaluate_operations(ops, run_id)
        qualify_retained(c['operations'][:-1], run_id, c['independent_media'])
        require(c.get('success') is True and c.get('status') == v['status'], 'NONE_VERDICT')
        diagnostic = extension['gatekeeper_teec_diagnostic']
        require(diagnostic.get('status') == 'GK_TEEC_DIAGNOSTIC_OBSERVATIONS_CLOSED' and diagnostic.get('ready') is True and diagnostic.get('eof') is True and diagnostic.get('error') is None and diagnostic.get('records') == [{'kind':'READY','version':2}] and type(diagnostic.get('record_count')) is int and diagnostic['record_count'] == 1 and type(diagnostic.get('bytes')) is int and 0 < diagnostic['bytes'] <= 16384 and diagnostic.get('trace_completeness') == 'NOT_PROVEN_BY_PROTOCOL', 'NONE_ZERO_VERIFY_PROOF')
        return True
    require(c.get('credential_type') == 'password', 'PASSWORD_CREDENTIAL_TYPE')
    rw=ops[3]['operation']=='unlock-evox-password-user0-rw'
    expected=['unwrap-mount','unlock-de-user0','prepare-evox-password-user0'] + (['unlock-evox-password-user0-rw','cleanup-rw','cleanup'] if rw else ['unlock-evox-password-user0','cleanup'])
    require([x['operation'] for x in ops]==expected, 'OPERATION_SEQUENCE')
    require(c.get('requested_mode','ro') == ('rw' if rw else 'ro'), 'CONSUMER_REQUESTED_MODE')
    require(all(type(x['returncode']) is int and x['returncode']==0 for x in ops[:3]+ops[4:]),
            'ADMISSION_OR_CLEANUP_FAILED')
    require(type(c['password_submissions']) is int and c['password_submissions']==1 and
            type(c['unlock_dispatches']) is int and c['unlock_dispatches']==1 and
            c['synthetic_write_calls']==0, 'AUTH_DISPATCH_CONTRACT')
    require(c['prepared']==qualify_prepare(ops[2]['status_lines']), 'PREPARE_EVIDENCE_MISMATCH')
    if rw:
        from decrypt_runtime.rw_verdict import native_verdict as rw_verdict,cleanup_verdict
        v=rw_verdict(ops[3]);cleanup_verdict(ops[4],ops[3]['pid'])
    else:
        v=native_verdict(ops[3])
    require(c['success'] is v['success'] and c['status']==v['status'] and
            c.get('failure_stage')==v['failure_stage'], 'NATIVE_VERDICT_MISMATCH')
    if v['success']:
        if rw:
            from decrypt_runtime.ro_evox_callback_session import qualify_retained_rw
            qualify_retained_rw(c['operations'][:-2],run_id,c['independent_media'])
        else:
            qualify_retained(c['operations'][:-1],run_id,c['independent_media'])
        independent=c['independent_media']
        require(type(independent) is dict and set(independent)=={'entries','complete',
                'policy_v2_supported','fs_ro','dm_ro','raw_dm_ro','alias_ro'} and
                type(independent['entries']) is int and 0 <= independent['entries'] <= 4096 and
                all(independent[k] is True for k in ('complete','policy_v2_supported')) and
                all(independent[k] is (not rw) for k in ('fs_ro','dm_ro','raw_dm_ro','alias_ro')),
                'INDEPENDENT_MEDIA_PROOF_REQUIRED')
    else:
        require(c['independent_media'] is None, 'FAILED_AUTH_WITH_MEDIA_PROOF')
    d = extension['gatekeeper_teec_diagnostic']
    require(d['status'] == 'GK_TEEC_DIAGNOSTIC_OBSERVATIONS_CLOSED' and d['ready'] is True
            and d['eof'] is True and d['error'] is None
            and d['trace_completeness'] == 'NOT_PROVEN_BY_PROTOCOL', 'Diagnostic not closed')
    records = d['records']
    require(type(d['record_count']) is int and d['record_count'] == len(records)
            and 1 <= len(records) <= 64 and type(d['bytes']) is int and 0 < d['bytes'] <= 16384,
            'Diagnostic bounds')
    require(records[0] == {'kind': 'READY', 'version': 2}, 'Missing v2 READY')
    calls = records[1:]
    require(all(r.get('kind') == 'CALL' and r.get('version') == 2 and r.get('cmd') == 126 for r in calls),
            'Unexpected diagnostic record')
    # Reparse each public record with the unchanged qualified parser. No trust in
    # unchecked scalar dictionaries; reject extra keys and invalid semantics.
    import gk_diagnostic
    require(all(type(r[k]) is int for r in calls for k in ('cmd','result','origin_present','origin',
            'ta_present','ta_status','ta_timeout','ta_timeout_valid')), 'Diagnostic scalar type')
    p = gk_diagnostic.Parser()
    p.feed(b'GK_TEEC_DIAG_READY version=2\n')
    for r in calls:
        raw = ('GK_TEEC_CALL_V2 cmd=%d result=0x%08x origin_present=%d origin=0x%08x '
               'ta_present=%d ta_status=%d ta_timeout=%d ta_timeout_valid=%d ta_bound=%s\n') % (
            r['cmd'],r['result'],r['origin_present'],r['origin'],r['ta_present'],r['ta_status'],
            r['ta_timeout'],r['ta_timeout_valid'],r['ta_bound'])
        p.feed(raw.encode('ascii'))
    require(p.error is None and p.records == records, 'Diagnostic scalar mismatch')
    if v['success']:
        require(len(calls) == 2 and all(r['result'] == 0 and r['ta_present'] == 1
                and r['ta_bound'] == 'QUALIFIED' and r['ta_status'] == 0 for r in calls),
                'RO success missing two qualified native verifications')
    elif v['failure_stage'] in ('protector', 'primary'):
        expected = 1 if v['failure_stage'] == 'protector' else 2
        require(len(calls) == expected, 'Auth failure call count mismatch')
        require(all(r['result'] == 0 and r['ta_present'] == 1 and r['ta_status'] == 0
                    for r in calls[:-1]), 'Preceding verification not successful')
    else:
        require(len(calls) <= 2, 'Extra verification call')
    return v['success']


def attempt_mode(config, discovery, credential):
    """Select before launcher: no credential descriptor may enter NONE."""
    profile = config.get('profile_id')
    require(profile in PROFILES, 'Unknown worker profile')
    is_none = profile == LEGACY_EVO_NONE_PROFILE
    if profile == EVO_PROFILE:
        require(discovery is True and credential is None, 'Neutral Evo requires credential-free discovery')
    if is_none:
        require(discovery is True and credential is None
                and 'native_efs_policy' in config and config['native_efs_policy'] is None,
                'NONE requires discovery without credentials or EFS persistence')
    else:
        require(type(config.get('native_efs_policy')) is dict,
                'Samsung native EFS policy required')
    return is_none


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--common-lock-fd',type=int,required=True)
    p.add_argument('--safe-receipt',type=Path,required=True)
    p.add_argument('--credential-fd',type=int)
    p.add_argument('--control-fd',type=int,required=True)
    p.add_argument('--discover',action='store_true')
    a=p.parse_args()
    from decrypt_runtime import worker_control
    c=json.loads(a.config.read_text())
    validate_config(c)
    is_none=attempt_mode(c,a.discover,a.credential_fd)
    worker_control.initialize(a.control_fd, a.discover, c['profile_id'])
    if not a.discover:
        validate_credential_fd(a.credential_fd)
    else:
        require(a.credential_fd is None, 'Preparation cannot accept a credential')
    require(a.credential_fd != a.common_lock_fd, 'Aliased descriptors')
    sys.path.insert(0,c['module_dir'])
    sys.path.insert(0,str(Path(c['module_dir']).parents[1]/'sp-prepare-worker'))
    import launcher_native_efs as launcher
    run_id,boot=c['run_id'],c['boot_id']
    lock=a.common_lock_fd
    credential_slot=[-1 if a.discover else a.credential_fd]
    data_cleanup_errors=[]
    result={'status':'NONE_CE_RO_STARTED' if is_none else 'PASSWORD_CE_RO_STARTED','success':False,'boot_id':boot,'run_id':run_id,
        'filesystem_contract':'NATIVE_EFS_PERSISTENCE' if c.get('native_efs_policy') is not None else 'READ_ONLY',
        'normal_restore_provenance':False}
    public_operations=[]
    def public(event,**fields):
        if event in ('sp_prepare_operation_returned','evox_password_operation_returned'):
            require(len(public_operations)<8,'Native public operation bound')
            public_operations.append(fields)
        worker_control.emit(event, fields)
    exit_code=1
    try:
        if is_none:
            from decrypt_runtime import ro_none_callback_session as none_callback
            none_callback.deadline(0,initial=True)
            consumer=none_callback.make_consumer(run_id,data_cleanup_errors,public)
        elif c['profile_id'] == EVO_PROFILE:
            from decrypt_runtime import ro_evox_callback_session as evo_callback
            consumer=evo_callback.make_consumer(run_id,credential_slot,data_cleanup_errors,public,
                {'password_submissions':0,'unlock_dispatches':0},rw_capability=c.get('ce_rw'),preparation_mode=c.get('preparation_mode','ro'), session_config=c)
        else:
            consumer=make_consumer(run_id,credential_slot,data_cleanup_errors,public,rw_capability=c.get('ce_rw'))
        outcome=launcher.execute_session(c['bundle'],c['layout'],c['tee_receipt'],boot,run_id,
            c['root_manifest_sha256'],lock,allow_policy_load=True,consumer_callback=consumer,
            enable_gatekeeper=not is_none,enable_gatekeeper_diagnostic=not is_none,
            native_efs_policy=None if is_none else c['native_efs_policy'],
            firmware_profile=None if is_none else c['profile_id'])
        # Retain structurally returned expected native failures and all parsed
        # closed records before applying the final success contract.
        result['outcome']=outcome
        if is_none:
            require('native_efs_persistence' not in outcome, 'Unexpected NONE EFS persistence')
            verdict=none_callback.evaluate(outcome['extension_result'],run_id)
            success=verdict['success']
        elif c['profile_id'] == EVO_PROFILE:
            success=evaluate_evox(outcome['extension_result'],run_id)
            if outcome['extension_result']['consumer'].get('error_code') == 'WRITE_NOT_QUALIFIED':
                result['unsupported_verified'] = True
                result['public_error_code'] = 'WRITE_NOT_QUALIFIED'
        else:
            success=evaluate(outcome['extension_result'])
        result.update(status='PASSWORD_CE_RO_MEDIA_PASS' if success else 'PASSWORD_CE_RO_FAILED_NO_RETRY',
                      success=success)
        if is_none:
            result['status']='NONE_CE_RO_MEDIA_PASS' if success else 'NONE_CE_RO_FAILED_NO_RETRY'
        requested_mode = 'rw' if outcome['extension_result']['consumer'].get('requested_mode') == 'rw' or any(x.get('operation') in ('unlock-sp-user0-rw','unlock-evox-password-user0-rw') for x in outcome['extension_result']['consumer']['operations']) else 'ro'
        result.update(requested_mode=requested_mode)
        if c.get('native_efs_policy') is not None:
            require(outcome['native_efs_persistence']['cleanup_errors']==[], 'Native EFS cleanup failed')
            result['status']='NATIVE_EFS_PERSISTENCE_CE_'+requested_mode.upper()+'_MEDIA_PASS' if success else 'NATIVE_EFS_PERSISTENCE_AUTH_FAILED_NO_RETRY'
        if result.get('unsupported_verified') is True:
            result['status']='EVOX_NONE_RW_UNSUPPORTED_BEFORE_AUTH'
        exit_code=0 if success else 1
    except Exception as error:
        result.update(status='NONE_CE_RO_FAILED_NO_RETRY' if is_none else 'PASSWORD_CE_RO_FAILED_NO_RETRY',success=False,
            error={'exception':type(error).__name__,
                   'frames':[{'module':Path(f.filename).name,'function':f.name,'line':f.lineno}
                             for f in traceback.extract_tb(error.__traceback__)[-8:]]})
    finally:
        if credential_slot[0] >= 0:
            os.close(credential_slot[0]); credential_slot[0]=-1
        cleanup_verified = False
        # This receipt is outside the Android chroot. No daemon can create it.
        directory = Path('/run') / ('a22x-c-' + run_id)
        try:
            g1 = json.loads((directory/'G1-CLEANUP.json').read_text())
            g2file = directory/'G2-RESULT.json'
            g2 = json.loads(g2file.read_text()) if g2file.exists() else {'events': [], 'process_cleanup_errors': []}
            owned = [event['pid'] for event in g2.get('events', []) if event.get('event') == 'spawn']
            assert not any(Path('/proc', str(pid)).exists() for pid in owned)
            assert g1['mount_cleanup_errors'] == [] and g2['process_cleanup_errors'] == [] and not data_cleanup_errors
            loaded = g1['global_policy_loaded']
            state = g1.get('selinux_status_before_unmount')
            assert g1['owned_maps_remaining'] == []
            assert not g2file.exists() or g2['all_owned_processes_reaped'] is True
            assert (not loaded) or (state and state['enforcing'] == 0 and state['policyload'] > 0)
            if is_none:
                require(type(loaded) is bool and type(state) is dict
                        and type(state.get('enforcing')) is int and state['enforcing'] == 0,
                        'NONE SELinux cleanup state unconfirmed')
                require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot,
                        'NONE cleanup boot changed')
            for path in Path('/sys/block').glob('dm-*/dm/name'):
                assert not path.read_text().strip().startswith(('a22x-c-'+run_id, 'a22x-data-ro-'+run_id))
            receipt = {'boot_id': boot, 'run_id': run_id, 'worker_pid': os.getpid(), 'cleanup_safe': True,
                       'process_cleanup_errors': [], 'mount_cleanup_errors': [], 'data_cleanup_errors': [],
                       'owned_pids': owned, 'selinux_enforcing': 0,
                       'policy_state': 'OWN_FIRST_POLICY_LOADED_PERMISSIVE' if loaded else 'NOT_LOADED'}
            temporary = a.safe_receipt.with_suffix('.tmp')
            with temporary.open('x') as dst: dst.write(json.dumps(receipt)+'\n')
            os.replace(temporary, a.safe_receipt)
            cleanup_verified = True
            public('c_cleanup_receipt_saved')
        except Exception as error:
            public('c_cleanup_unknown_watchdog_reset_required', kind=type(error).__name__)
            exit_code = 1
        result['cleanup_verified'] = cleanup_verified
        if not cleanup_verified:
            result.update(success=False, status='NONE_CE_RO_CLEANUP_UNKNOWN_NO_RETRY' if is_none else 'PASSWORD_CE_RO_CLEANUP_UNKNOWN_NO_RETRY')
        summary = {k: result[k] for k in ('status','success','boot_id','run_id','cleanup_verified','error','requested_mode','public_error_code') if k in result}
        summary['native_operations']=public_operations
        with a.safe_receipt.with_name('worker-public-' + run_id + '.json').open('x') as dst:
            dst.write(json.dumps(summary)+'\n')
        public('c_session_result', **result)
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
