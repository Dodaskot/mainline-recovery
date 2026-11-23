"""Neutral Evo retained sessions: synthetic public proof and FD/lifecycle only."""
import copy
import os
import unittest
from unittest.mock import patch
from android_profiles import (EVO_PROFILE, SAMSUNG_PROFILE, EVO_NAMESPACE, GATEKEEPERD_SHA,
                              credential_allowed, validate_namespace)
from decrypt_runtime import common, worker_control as wc
from decrypt_runtime import ro_evox_callback_session as cb
from decrypt_runtime import native_session_worker as native
import decrypt_session as session
from tests.test_decrypt_session import CONFIG, BOOT, FakeMounts, service_runtime_fixture
from tests.test_decrypt_discovery import SOURCE
from tests.test_decrypt_none import operations as none_operations, INDEPENDENT as NONE_INDEPENDENT

RUN='evotest123456'
EVO_CONFIG=dict(CONFIG,profile_id=EVO_PROFILE,state_dir=common.STATE_DIR,
                gatekeeper_namespace=dict(EVO_NAMESPACE),gatekeeperd_sha256=GATEKEEPERD_SHA)
PREPARE=['G3 EVOX_PASSWORD_PROFILE schema=2 pwd_layout=2 pwd_bytes=93 kdf=9:3:1 pin_length=-1 ce_secdis=0 primary_present=1',
         'G3 SP_PREPARE_CREDENTIAL type=password',
         'G3 SP_PREPARE_READY auth_calls=0 ce_profile=modern_software_absent',
         'G4 EVOX_PASSWORD_PREPARE_PASS auth_calls=0']
AUTH=['G3 SP_CE_AUTHENTICATED_KEY_DELIVERED','G4 EVOX_PASSWORD_KEY_RECEIVED_ONCE bytes=64',
      'G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS',
      'G4 SP_MEDIA_USER0_READDIR_PASS entries=0 complete=1 fs_ro=1 dm_ro=1 alias_ro=1']
INDEPENDENT=dict(entries=0,complete=True,policy_v2_supported=True,fs_ro=True,dm_ro=True,raw_dm_ro=True,alias_ro=True)

def record(op,lines,code=0):return dict(operation=op,status_lines=list(lines),returncode=code)
def discovery(kind):return record('discover-evox-user0',['G3 EVOX_CREDENTIAL_DISCOVERED type='+kind+' auth_calls=0','G4 EVOX_DISCOVER_PASS auth_calls=0'])
def password_ops():
    return [record('unwrap-mount',['G4 MOUNT_RO_PASS dm=a22x-data-ro-'+RUN+' raw_dm=a22x-data-ro-'+RUN+'-raw device=253:7 sectors=1000','G3 AUTHENTICATED_KEY_DELIVERED']),
            record('unlock-de-user0',['G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS']*2+['G4 DE_ONLY_UNLOCK_PASS ce_calls=0']+['G3 AUTHENTICATED_KEY_DELIVERED']*2),
            discovery('password'),record('prepare-evox-password-user0',PREPARE),record('unlock-evox-password-user0',AUTH)]
def ops_none():
    ops=none_operations()
    for item in ops:
        item['status_lines']=[line.replace('evnonetest123',RUN) for line in item['status_lines']]
    return ops[:2]+[discovery('none')]+ops[2:]
def diagnostic(calls=2):
    try:
        import gk_diagnostic
    except ImportError:  # the TEE diagnostic parser is private: not in this tree (2026-11-22)
        raise unittest.SkipTest('gk_diagnostic is not in this tree')
    p=gk_diagnostic.Parser();p.feed(b'GK_TEEC_DIAG_READY version=2\n')
    line=b'GK_TEEC_CALL_V2 cmd=126 result=0x00000000 origin_present=0 origin=0x00000000 ta_present=1 ta_status=0 ta_timeout=0 ta_timeout_valid=0 ta_bound=QUALIFIED\n'
    p.feed(line*calls);p.end()
    return dict(status='GK_TEEC_DIAGNOSTIC_OBSERVATIONS_CLOSED',ready=True,eof=True,error=None,
                trace_completeness='NOT_PROVEN_BY_PROTOCOL',records=p.records,record_count=len(p.records),bytes=p.total_bytes)
def extension(kind='password'):
    ops=password_ops() if kind=='password' else ops_none()
    independent=INDEPENDENT if kind=='password' else NONE_INDEPENDENT
    verdict=cb.qualify_retained(ops,RUN,independent)
    consumer=dict(verdict,operations=ops+[record('cleanup',['G4 CLEANUP_PASS'])],credential_type=kind,
                  password_submissions=1 if kind=='password' else 0,unlock_dispatches=1 if kind=='password' else 0,
                  synthetic_write_calls=0,independent_media=dict(independent))
    if kind=='password':consumer['prepared']=cb.qualify_prepare(PREPARE)
    return dict(status='G2_REMOTE_TEE_KEYMASTER_GATEKEEPER_DIAGNOSTIC_READY',consumer_run=True,
                all_owned_processes_reaped=True,process_cleanup_errors=[],consumer=consumer,
                gatekeeper_teec_diagnostic=diagnostic(2 if kind=='password' else 0))

class Proofs(unittest.TestCase):
    def test_discovery_exact_type_never_profile_guess(self):
        for kind in ('none','password'):
            lines=discovery(kind)['status_lines'];self.assertEqual(cb.discovered_type(lines),kind)
            self.assertEqual(cb.classify(('\n'.join(lines)+'\n').encode(),b'')['status_lines'],lines)
        for lines in ([],discovery('none')['status_lines']+discovery('password')['status_lines'],
                      discovery('password')['status_lines']*2,discovery('pattern')['status_lines']):
            with self.assertRaises(RuntimeError):cb.discovered_type(lines)
    def test_closed_password_and_none_results_require_original_diagnostics(self):
        for kind in ('password','none'):
            self.assertTrue(native.evaluate_evox(extension(kind),RUN))
            bad=extension(kind);bad['gatekeeper_teec_diagnostic']['records'].append({'kind':'EXTRA'})
            with self.assertRaises((RuntimeError,KeyError)):native.evaluate_evox(bad,RUN)
            bad=extension(kind);bad['consumer']['password_submissions']=2
            with self.assertRaises(RuntimeError):native.evaluate_evox(bad,RUN)
        bad=extension('none');bad['gatekeeper_teec_diagnostic']=diagnostic(1)
        with self.assertRaises(RuntimeError):native.evaluate_evox(bad,RUN)
    def test_exact_retained_password_and_none_proof(self):
        self.assertTrue(cb.qualify_retained(password_ops(),RUN,INDEPENDENT)['success'])
        self.assertTrue(cb.qualify_retained(ops_none(),RUN,NONE_INDEPENDENT)['success'])
    def test_failed_or_wrong_discovery_never_exports(self):
        for change in ('exit','kind','duplicate'):
            ops=password_ops()
            if change=='exit':ops[2]['returncode']=1
            elif change=='kind':ops[2]=discovery('none')
            else:ops[2]['status_lines']*=2
            with self.assertRaises(RuntimeError):cb.qualify_retained(ops,RUN,INDEPENDENT)
    def test_incomplete_metadata_de_or_media_rejected(self):
        for index in (0,1,3,4):
            ops=password_ops();ops[index]['status_lines']=[]
            with self.assertRaises(RuntimeError):cb.qualify_retained(ops,RUN,INDEPENDENT)
        for key in INDEPENDENT:
            bad=dict(INDEPENDENT);bad[key]=False if key!='entries' else -1
            with self.assertRaises(RuntimeError):cb.qualify_retained(password_ops(),RUN,bad)
    def test_closed_password_requires_one_submission_and_two_qualified_calls(self):
        self.assertTrue(native.evaluate_evox(extension(),RUN))
        for key,value in [('password_submissions',0),('password_submissions',2),('unlock_dispatches',2)]:
            bad=extension();bad['consumer'][key]=value
            with self.assertRaises(RuntimeError):native.evaluate_evox(bad,RUN)
        for count in (0,1,3):
            bad=extension();bad['gatekeeper_teec_diagnostic']=diagnostic(count)
            with self.assertRaises(RuntimeError):native.evaluate_evox(bad,RUN)
    def test_neutral_none_infra_requires_zero_verify_and_zero_secret_submission(self):
        self.assertTrue(native.evaluate_evox(extension('none'),RUN))
        for count in (1,2):
            bad=extension('none');bad['gatekeeper_teec_diagnostic']=diagnostic(count)
            with self.assertRaises(RuntimeError):native.evaluate_evox(bad,RUN)
        for key in ('password_submissions','unlock_dispatches','synthetic_write_calls'):
            bad=extension('none');bad['consumer'][key]=1
            with self.assertRaises(RuntimeError):native.evaluate_evox(bad,RUN)
    def test_plain_auth_failure_is_terminal_not_none_fallback(self):
        ops=password_ops();ops[4]=record('unlock-evox-password-user0',['G3 SP_AUTH_FAILED status=2 timeout_ms=30000'],1)
        self.assertFalse(cb.native_verdict(ops[4])['success'])
        with self.assertRaises(RuntimeError):cb.qualify_retained(ops,RUN,INDEPENDENT)
        self.assertEqual([x['operation'] for x in ops].count('unlock-evox-password-user0'),1)
    def test_public_status_unknown_or_secret_never_accepted(self):
        for data in (b'PRIVATE=secret',b'x'*4097,b'G3 EVOX_CREDENTIAL_DISCOVERED type=pin auth_calls=0'):
            with self.assertRaises(RuntimeError):cb.classify(data,b'')
    def test_evo_config_needs_explicit_namespace_and_native_efs_before_dispatch(self):
        common.validate_config(EVO_CONFIG,BOOT)
        self.assertFalse(native.attempt_mode(EVO_CONFIG,True,None))
        for config in (dict(EVO_CONFIG,native_efs_policy=None),dict(EVO_CONFIG,gatekeeperd_sha256='0'*64),
                       dict(EVO_CONFIG,gatekeeper_namespace=dict(EVO_NAMESPACE,image_running_boolean=0))):
            with self.assertRaises(common.SessionError):common.validate_config(config,BOOT)
        for discovery_flag,fd in ((False,None),(True,64),(False,64)):
            with self.assertRaises(RuntimeError):native.attempt_mode(EVO_CONFIG,discovery_flag,fd)
        for kind in ('pin','pattern','unknown'):self.assertFalse(credential_allowed(EVO_PROFILE,kind))
    def test_namespace_strict_types_no_guessed_ids(self):
        for key in EVO_NAMESPACE:
            bad=dict(EVO_NAMESPACE);bad[key]=True if key!='image_running_boolean' else 0
            with self.assertRaises(ValueError):validate_namespace(bad)

class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.sent=[];self.commits=[];self.actions=[];self.mounts=FakeMounts()
        self.life=session.SessionLifecycle(EVO_CONFIG,mounts=self.mounts,commit=self.commits.append,
            send_worker=lambda v,f:self.sent.append((v,f)),release_lease=lambda:self.actions.append('release'),
            cleanup_check=lambda:True,disarm=lambda:self.actions.append('disarm'),now=lambda:100.)
    def prepare(self):
        self.life.prepared(os.getpid(),common.starttime(os.getpid()),'password',SOURCE);self.life.prepared_held()
    def request(self):
        return dict(op='authenticate',boot_id=BOOT,run_id=EVO_CONFIG['run_id'],volume_token=self.life.receipt['volume_token'],credential_type='password',requested_mode='ro',write_confirmed=False)
    def test_password_prompt_then_single_fd_dispatch_retained_mount_and_cleanup(self):
        self.prepare();self.assertFalse(self.life.auth_started);self.assertFalse(self.mounts.bound)
        self.life.start_auth(self.request(),71,91)
        with self.assertRaises(common.SessionError):self.life.start_auth(self.request(),71,91)
        self.life.authenticated(os.getpid(),common.starttime(os.getpid()),credential_type='password');self.life.held()
        self.assertTrue(self.life.receipt['native_efs_persistence']);self.assertEqual(self.life.receipt['credential_type'],'password')
        self.life.request_unmount(77);self.life.complete(0,{'cleanup_verified':True,'success':True})
        self.assertFalse(self.mounts.bound);self.assertEqual(self.actions,['release','release','disarm'])
    def test_cancel_after_prepare_has_zero_auth_and_normal_cleanup(self):
        self.prepare();self.life.cancel_prepared(71)
        self.assertFalse(self.life.auth_started);self.assertFalse(self.mounts.bound)
        reply=self.life.complete(1,{'cleanup_verified':True,'success':False})
        self.assertTrue(reply['ok']);self.assertNotIn('authenticate',[x[0]['op'] for x in self.sent])
    def test_none_mount_has_no_prompt_no_auth_dispatch_but_admitted_efs(self):
        self.assertIsNone(self.life.credential_type);self.assertFalse(self.life.auth_started)
        self.life.authenticated(os.getpid(),common.starttime(os.getpid()),credential_type='none');self.life.held()
        self.assertEqual(self.life.receipt['credential_type'],'none');self.assertTrue(self.life.receipt['native_efs_persistence'])
        self.assertNotIn('authenticate',[x[0]['op'] for x in self.sent])
    def test_pattern_and_pin_never_reach_prompt_or_mount(self):
        for kind in ('pattern','pin'):
            with self.assertRaises(common.SessionError):self.life.prepared(os.getpid(),common.starttime(os.getpid()),kind,SOURCE)
            with self.assertRaises(common.SessionError):self.life.authenticated(os.getpid(),common.starttime(os.getpid()),credential_type=kind)
        self.assertFalse(self.mounts.bound)

if __name__=='__main__':unittest.main(verbosity=2)
