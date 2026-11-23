"""Lifecycle, policy, native wire, and diagnostic continuity regressions."""
import copy
import errno
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import android_decrypt
import decrypt_session
from android_profiles import EVO_PROFILE
from decrypt_runtime.common import SessionError, starttime
from decrypt_runtime import session_support as support
from decrypt_runtime.reusable_lifecycle import ReusableLifecycle, PROOF_SCHEMA, native_proof
from decrypt_runtime.reusable_worker import decode_response, RESPONSE, MAGIC, DiagnosticEpochs

BOOT = '00000000-0000-0000-0000-000000000001'
RUN = 'sessiontest123'
PID = os.getpid()
TICKS = starttime(PID)
CAP = {'schema':support.SCHEMA, 'qualified':True, 'helper':support.HELPER,
       'helper_sha256':'a'*64, 'protocol':1}
CONFIG = {'boot_id':BOOT, 'run_id':RUN, 'mountpoint':'/mnt/volumes/userdata',
    'volume_token':'physical-original', 'profile_id':EVO_PROFILE,
    'android_user_id':0, 'native_efs_policy':{}, 'ce_session':CAP,
    'layout':{'physical':{'userdata':{'device':'259:22'}}}}
NAMES = ['a22x-data-ro-' + RUN + x for x in ('','-raw','-session-ro','-session-ro-raw','-session-rw','-session-rw-raw')]

def proof(state='prepared', seq=0, gen=0, auth=0, committed=0, mode='ro', cache=False):
    return {'schema':PROOF_SCHEMA,'pid':PID,'starttime':TICKS,'state':state,
        'sequence':seq,'generation':gen,'auth_sequence':auth,'committed_auth_sequence':committed,
        'mode':mode,'cache_valid':cache,'lease_released':True,
        'ce_verified':state=='mounted','suspend_clean':state=='suspended',
        'owned_crypto_names':list(NAMES), 'physical_device':'259:22'}

class FakeMounts:
    def __init__(self):
        self.bound=False; self.busy=False; self.mount_id=70
    def bind(self,pid,ticks,run,target,tree_fd=None,proof=None,read_only=True):
        self.bound=True;self.mount_id+=1
        return {'mountpoint':target,'mount_id':self.mount_id,'device':'3599:199','read_only':read_only}
    def unmount(self,target):
        if self.busy: raise OSError(errno.EBUSY,'busy')
        self.bound=False

class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.clock=[100.]
        self.mounts=FakeMounts();self.sent=[];self.saved=[];self.released=[];self.disarmed=[]
        self.policy='first_access'
        self.policy_patch=patch.object(support,'password_policy',side_effect=lambda:self.policy)
        self.policy_patch.start();self.addCleanup(self.policy_patch.stop)
        self.detached_patch=patch.object(support,'validate_detached',side_effect=lambda r,**kw:r)
        self.detached_patch.start();self.addCleanup(self.detached_patch.stop)
        self.life=ReusableLifecycle(CONFIG,mounts=self.mounts,commit=lambda x:self.saved.append(copy.deepcopy(x)),
            send_worker=lambda v,fd:self.sent.append((v,fd)),release_lease=lambda:self.released.append(True),
            cleanup_check=lambda:True,disarm=lambda:self.disarmed.append(True),now=lambda:self.clock[0])
        source={'device':'3599:198','mount_id':2}
        self.life.prepared(PID,TICKS,'password',source,proof())
        self.life.prepared_held()

    def auth(self):
        request={'op':'authenticate','boot_id':BOOT,'run_id':RUN,'volume_token':self.life.receipt['volume_token'],
            'credential_type':'password','requested_mode':'ro','write_confirmed':False}
        self.life.start_auth(request,77,88)
        p=proof('mounted',1,1,1,1,'ro',True)
        p.update(authentication_id=self.life.pending_authentication_id,authentication_performed=True)
        self.life.authenticated(PID,TICKS,99,{},'password','ro',p)
        return self.life.held()

    def suspend(self, seq=2,gen=2,auth=1,committed=1,cache=True):
        self.life.request_unmount(77)
        self.life.suspended(proof('suspended',seq,gen,auth,committed,'none',cache))
        return self.life.held()

    def request(self, fresh=False):
        return {'op':'mount','boot_id':BOOT,'run_id':RUN,'volume_token':self.life.receipt['volume_token'],
                'requested_mode':'ro','write_confirmed':False,'require_fresh_authentication':fresh}

    def test_first_auth_owns_distinct_public_epoch(self):
        r=self.auth()
        self.assertTrue(r['session_reusable']);self.assertEqual(r['auth_generation'],1)
        self.assertEqual(r['mount_generation'],1);self.assertRegex(r['authentication_id'],r'^[0-9a-f]{32}$')
        self.assertEqual(r['password_policy_at_auth'],'first_access')
        self.assertEqual(len(self.released),2);self.assertFalse(self.disarmed)

    def test_full_suspend_retains_key_but_never_claims_mount_or_offline(self):
        a=self.auth();r=self.suspend()
        self.assertFalse(self.mounts.bound);self.assertEqual(self.life.state,'session_unmounted')
        self.assertTrue(r['filesystem_unmounted']);self.assertTrue(r['key_retained'])
        self.assertFalse(r['ce_authenticated']);self.assertFalse(r['fscrypt_policy_verified'])
        self.assertFalse(r['device_offline']);self.assertFalse(r['reboot_required'])
        self.assertNotEqual(r['mount_generation'],a['mount_generation'])
        self.assertEqual(r['authentication_id'],a['authentication_id'])
        self.assertEqual(self.sent[-1][0],{'op':'hold_detached'})

    def test_cached_mount_reuses_auth_only_with_unchanged_cache_policy(self):
        a=self.auth();self.suspend()
        self.life.resume_request(self.request(),77)
        self.assertEqual(self.sent[-1][0]['op'],'resume')
        p=proof('mounted',3,3,1,1,'ro',True)
        p.update(authentication_id=a['authentication_id'],authentication_performed=False)
        self.life.authenticated(PID,TICKS,99,{},'password','ro',p);r=self.life.held()
        self.assertEqual(r['auth_generation'],1);self.assertEqual(r['mount_generation'],3)
        self.assertFalse(self.life.reply(r)['authentication_performed'])

    def test_each_mount_and_policy_change_cannot_use_cached_key(self):
        self.auth();self.suspend()
        for policy in ('each_mount','startup'):
            self.policy=policy
            with self.assertRaises(SessionError) as cm:self.life.resume_request(self.request(),77)
            self.assertEqual(cm.exception.code,'CREDENTIAL_REQUIRED')
            self.assertEqual(self.life.state,'session_unmounted')

    def test_force_auth_requires_new_password_even_in_cached_policy(self):
        a=self.auth();self.suspend()
        with self.assertRaises(SessionError):self.life.resume_request(self.request(True),77)
        self.life.resume_request(self.request(True),77,88)
        self.assertEqual(self.sent[-1][0]['op'],'authenticate')
        self.assertNotEqual(self.life.pending_authentication_id,a['authentication_id'])
        p=proof('mounted',3,3,2,2,'ro',True)
        p.update(authentication_id=self.life.pending_authentication_id,authentication_performed=True)
        self.life.authenticated(PID,TICKS,99,{},'password','ro',p);r=self.life.held()
        self.assertEqual(r['auth_generation'],2)

    def test_busy_global_mount_never_dispatches_private_cleanup(self):
        r=self.auth();before=len(self.sent);self.mounts.busy=True
        with self.assertRaises(SessionError) as cm:self.life.request_unmount(77)
        self.assertEqual(cm.exception.code,'VOLUME_BUSY');self.assertEqual(len(self.sent),before)
        self.assertTrue(self.mounts.bound);self.assertEqual(self.life.receipt,r)
        self.assertEqual(self.life.state,'mounted')

    def test_cancel_before_password_preserves_reusable_empty_key_owner(self):
        self.life.cancel_prepared(77)
        self.life.suspended(proof('suspended',1,1,0,0,'none',False))
        r=self.life.held()
        self.assertFalse(r['key_retained']);self.assertEqual(r['auth_generation'],0)
        self.assertTrue(support.auth_required(r));self.assertFalse(r['reboot_required'])
        self.assertIsNone(r['authentication_id'])

    def test_failed_password_drops_old_cache_and_invalidates_generation(self):
        self.auth();self.suspend();self.life.resume_request(self.request(True),77,88)
        self.life.suspended(proof('suspended',3,3,2,1,'none',False),
            {'code':'CREDENTIAL_REJECTED','message':'Rejected','details':{'reboot_required':False}})
        r=self.life.held();reply=self.life.reply(r)
        self.assertFalse(reply['ok']);self.assertEqual(reply['error']['code'],'CREDENTIAL_REJECTED')
        self.assertTrue(support.auth_required(r));self.assertEqual(r['mount_generation'],3)

    def test_first_wrong_password_then_correct_without_reboot_is_explicit_fresh_auth(self):
        # Initial failed verify must not mint a CE success or a cached-key token.
        self.life.start_auth(self.request_initial(),77,88)
        self.life.suspended(proof('suspended',1,1,1,0,'none',False),
            {'code':'DECRYPT_FAILED','message':'Native verify failed',
             'details':{'reboot_required':False,'session_preserved':True}})
        rejected=self.life.held()
        response=self.life.reply(rejected)
        self.assertFalse(response['ok'])
        self.assertEqual(response['error']['code'],'DECRYPT_FAILED')
        self.assertFalse(rejected['key_retained'])
        self.assertEqual(rejected['auth_generation'],0)
        self.assertIsNone(rejected['authentication_id'])
        self.assertEqual(self.life.state,'session_unmounted')
        self.assertFalse(self.mounts.bound)
        support.validate_detached(rejected,boot_id=BOOT,
            process_check=lambda *_:True,detached_check=lambda *_:True)
        before=len(self.sent)
        with self.assertRaises(SessionError) as cm:
            self.life.resume_request(self.request(),77)
        self.assertEqual(cm.exception.code,'CREDENTIAL_REQUIRED')
        self.assertEqual(len(self.sent),before)
        self.life.resume_request(self.request(True),77,88)
        self.assertEqual(self.sent[-1][0]['op'],'authenticate')
        p=proof('mounted',2,2,2,2,'ro',True)
        p.update(authentication_id=self.life.pending_authentication_id,
                 authentication_performed=True)
        self.life.authenticated(PID,TICKS,99,{},'password','ro',p)
        mounted=self.life.held()
        self.assertTrue(self.life.reply(mounted)['ok'])
        self.assertEqual(mounted['auth_generation'],2)
        self.assertTrue(mounted['key_retained'])
        self.assertFalse(mounted['reboot_required'])
        self.assertTrue(self.mounts.bound)

    def request_initial(self):
        return {'op':'authenticate','boot_id':BOOT,'run_id':RUN,
                'volume_token':self.life.receipt['volume_token'],
                'credential_type':'password','requested_mode':'ro',
                'write_confirmed':False}

    def test_retry_later_blocks_even_correct_password_until_native_deadline(self):
        self.life.start_auth(self.request_initial(),77,88)
        self.life.suspended(proof('suspended',1,1,1,0,'none',False),
            {'code':'RETRY_LATER','message':'Native throttling',
             'details':{'retry_after_seconds':7,'reboot_required':False}})
        rejected=self.life.held()
        self.assertEqual(self.life.reply(rejected)['error']['code'],'RETRY_LATER')
        self.assertEqual(rejected['retry_not_before_monotonic'],107.)
        self.assertFalse(rejected['key_retained'])
        for second,delay in ((100.,7),(106.1,1)):
            self.clock[0]=second
            before=len(self.sent)
            with self.assertRaises(SessionError) as cm:
                self.life.resume_request(self.request(True),77,88)
            self.assertEqual(cm.exception.code,'RETRY_LATER')
            self.assertEqual(cm.exception.details['retry_after_seconds'],delay)
            self.assertFalse(cm.exception.details['reboot_required'])
            self.assertEqual(len(self.sent),before)
        self.clock[0]=107.
        self.life.resume_request(self.request(True),77,88)
        p=proof('mounted',2,2,2,2,'ro',True)
        p.update(authentication_id=self.life.pending_authentication_id,
                 authentication_performed=True)
        self.life.authenticated(PID,TICKS,99,{},'password','ro',p)
        accepted=self.life.held()
        self.assertTrue(self.life.reply(accepted)['ok'])
        self.assertTrue(accepted['key_retained'])
        self.assertTrue(self.mounts.bound)

    def test_wrong_then_retry_later_then_correct_keeps_failed_ce_uncached(self):
        self.life.start_auth(self.request_initial(),77,88)
        self.life.suspended(proof('suspended',1,1,1,0,'none',False),
            {'code':'DECRYPT_FAILED','message':'No qualifying CE verify','details':{}})
        self.life.held()
        self.life.resume_request(self.request(True),77,88)
        self.life.suspended(proof('suspended',2,2,2,0,'none',False),
            {'code':'RETRY_LATER','message':'Native backoff',
             'details':{'retry_after_seconds':5}})
        r=self.life.held()
        self.assertFalse(r['key_retained'])
        self.assertEqual(r['auth_generation'],0)
        self.assertFalse(r['ce_authenticated'])
        self.assertFalse(self.mounts.bound)
        before=len(self.sent)
        with self.assertRaises(SessionError) as cm:
            self.life.resume_request(self.request(True),77,88)
        self.assertEqual(cm.exception.code,'RETRY_LATER')
        self.assertEqual(len(self.sent),before)
        self.clock[0]=105.
        self.life.resume_request(self.request(True),77,88)
        p=proof('mounted',3,3,3,3,'ro',True)
        p.update(authentication_id=self.life.pending_authentication_id,
                 authentication_performed=True)
        self.life.authenticated(PID,TICKS,99,{},'password','ro',p)
        accepted=self.life.held()
        self.assertTrue(self.life.reply(accepted)['ok'])
        self.assertEqual(accepted['auth_generation'],3)
        self.assertEqual(len(self.released),4)
        self.assertTrue(self.mounts.bound)

    def test_wrong_then_correct_mount_unmount_remount_does_not_replay_password(self):
        self.life.start_auth(self.request_initial(),77,88)
        self.life.suspended(proof('suspended',1,1,1,0,'none',False),
            {'code':'DECRYPT_FAILED','message':'Native failed','details':{}})
        self.life.held()
        self.life.resume_request(self.request(True),77,88)
        first=proof('mounted',2,2,2,2,'ro',True)
        first.update(authentication_id=self.life.pending_authentication_id,
                     authentication_performed=True)
        self.life.authenticated(PID,TICKS,99,{},'password','ro',first)
        mounted=self.life.held()
        self.assertTrue(self.life.reply(mounted)['ok'])
        first_mount_id=mounted['mount_id']
        self.life.request_unmount(77)
        self.life.suspended(proof('suspended',3,3,2,2,'none',True))
        detached=self.life.held()
        self.assertFalse(self.mounts.bound)
        self.assertFalse(detached['ce_authenticated'])
        self.life.resume_request(self.request(),77)
        self.assertEqual(self.sent[-1][0]['op'],'resume')
        cached=proof('mounted',4,4,2,2,'ro',True)
        cached.update(authentication_id=self.life.pending_authentication_id,
                      authentication_performed=False)
        self.life.authenticated(PID,TICKS,99,{},'password','ro',cached)
        again=self.life.held()
        self.assertTrue(self.life.reply(again)['ok'])
        self.assertEqual(again['auth_generation'],2)
        self.assertNotEqual(again['mount_id'],first_mount_id)
        self.life.request_unmount(77)
        self.life.suspended(proof('suspended',5,5,2,2,'none',True))
        self.life.held()
        self.policy='each_mount'
        before=len(self.sent)
        with self.assertRaises(SessionError) as cm:
            self.life.resume_request(self.request(),77)
        self.assertEqual(cm.exception.code,'CREDENTIAL_REQUIRED')
        self.assertEqual(len(self.sent),before)
        self.life.resume_request(self.request(True),77,88)
        self.assertEqual(self.sent[-1][0]['op'],'authenticate')
        fresh=proof('mounted',6,6,3,3,'ro',True)
        fresh.update(authentication_id=self.life.pending_authentication_id,
                     authentication_performed=True)
        self.life.authenticated(PID,TICKS,99,{},'password','ro',fresh)
        third=self.life.held()
        self.assertTrue(self.life.reply(third)['ok'])
        self.assertEqual(third['auth_generation'],3)
        self.assertTrue(self.mounts.bound)

    def test_failed_native_receipt_with_retained_ce_cache_does_not_publish(self):
        self.life.start_auth(self.request_initial(),77,88)
        with self.assertRaises(SessionError):
            self.life.suspended(proof('suspended',1,1,1,0,'none',True),
                {'code':'DECRYPT_FAILED','message':'failed','details':{}})
        self.assertEqual(self.life.state,'authenticating')
        self.assertFalse(self.mounts.bound)
        self.assertFalse(any(x.get('state')=='session_unmounted' for x in self.saved))
        self.assertFalse(self.disarmed)

    def test_terminal_close_differs_from_suspend_and_never_retains_key_receipt(self):
        self.auth();self.suspend();self.life.request_close(77)
        self.assertEqual(self.sent[-1][0]['op'],'close');self.assertEqual(self.life.state,'cleaning')
        r=self.life.complete(0,{'cleanup_verified':True,'success':True})
        self.assertTrue(r['session_closed']);self.assertTrue(r['cleanup_verified'])
        self.assertTrue(r['reboot_required']);self.assertFalse(r['session_retained'])
        self.assertFalse(self.saved[-1]['session_retained']);self.assertFalse(self.saved[-1]['key_retained'])

    def test_stale_or_replayed_native_generation_never_publishes(self):
        self.auth();self.life.request_unmount(77)
        for p in (proof('suspended',1,2,1,1,'none',True),proof('suspended',2,1,1,1,'none',True)):
            with self.assertRaises(SessionError):self.life.suspended(p)
        self.assertNotEqual(self.life.state,'session_unmounted')

    def test_idle_heartbeat_keeps_lifecycle_without_changing_operation_deadline(self):
        self.auth();self.suspend();self.clock[0]=10000.;self.life.pong()
        self.assertEqual(self.life.deadline,10005.)
        self.life.resume_request(self.request(),77)
        deadline=self.life.deadline;self.clock[0]+=1
        with self.assertRaises(SessionError):self.life.pong()
        self.assertEqual(self.life.deadline,deadline)

class Identity(unittest.TestCase):
    def receipt(self):
        return {'schema':'a22x.android-decrypt.session.v1','boot_id':BOOT,'run_id':RUN,
            'supervisor_pid':PID,'supervisor_starttime':TICKS,'worker_pid':PID,'worker_starttime':TICKS,
            'physical_volume_token':'physical-original','physical_device':'259:22','profile_id':EVO_PROFILE,'credential_type':'password',
            'state':'session_unmounted','session_reusable':True,'session_retained':True,
            'native_owner_pid':PID,'native_owner_starttime':TICKS,'native_generation':2,'native_sequence':2,
            'auth_generation':1,'mount_generation':2,'authentication_id':'a'*32,
            'password_policy_at_auth':'first_access','key_retained':True,
            'filesystem_unmounted':True,'ce_authenticated':False,'fscrypt_policy_verified':False,
            'device_offline':False,'reboot_required':False,'detached_devices':['3599:198','3599:199'],
            'owned_crypto_names':list(NAMES),'detached_proof_schema':'a22x.ce-session.suspend.v1'}

    def test_token_binds_devices_names_and_each_epoch(self):
        r=self.receipt();r['volume_token']=support.detached_token(r)
        support.validate_detached(r,boot_id=BOOT,detached_check=lambda x:True)
        for key,value in [('detached_devices',['1:1']),('owned_crypto_names',NAMES[:2]),
                ('mount_generation',3),('auth_generation',2),('authentication_id','b'*32),
                ('password_policy_at_auth','startup')]:
            changed=dict(r);changed[key]=value
            with self.assertRaises(SessionError):support.validate_detached(changed,boot_id=BOOT,detached_check=lambda x:True)

    def test_foreign_namespace_mount_at_another_path_is_detected(self):
        r=self.receipt()
        with self.assertRaises(SessionError):
            support.verify_detached(r,mounts=[{'devno':'3599:199','mountpoint':'/other-namespace/private'}],backing_check=lambda *a:False)
        self.assertTrue(support.verify_detached(r,mounts=[{'devno':'0:1','mountpoint':'/other'}]))

    def test_malformed_namespace_record_never_passes_as_absent(self):
        with self.assertRaises(KeyError):
            support.verify_detached(self.receipt(),mounts=[{'device':'3599:199','mountpoint':'/else'}])

    def test_generation_bool_and_dead_owner_are_not_proof(self):
        r=self.receipt();r['auth_generation']=True
        with self.assertRaises(SessionError):support.validate_identity(r)
        r=self.receipt()
        with self.assertRaises(SessionError):support.validate_identity(r,process_check=lambda *a:False)

    def test_policy_ignores_memory_without_native_authentication_epoch(self):
        r=self.receipt()
        self.assertFalse(support.auth_required(r,'first_access'))
        self.assertTrue(support.auth_required(r,'each_mount'))
        for change in ({'key_retained':False},{'auth_generation':0},{'authentication_id':None},
                       {'password_policy_at_auth':'startup'},{'auth_generation':True}):
            self.assertTrue(support.auth_required(dict(r,**change),'first_access'))

class PolicySettings(unittest.TestCase):
    def test_unreadable_settings_default_to_fresh_authentication(self):
        from filesystem import FilesystemError
        cached = {'key_retained':True,'auth_generation':1,
                  'authentication_id':'a'*32,'password_policy_at_auth':'first_access'}
        errors = (FilesystemError('ROOT_REQUIRED','Root required'),
                  FilesystemError('VOLUME_BUSY','Settings device busy'),
                  OSError(errno.EIO,'Settings read failed'),
                  ValueError('Damaged settings'))
        for error in errors:
            with self.subTest(error=type(error).__name__,code=getattr(error,'code',None)):
                def unreadable():
                    raise error
                module = SimpleNamespace(android_password_policy=unreadable)
                with patch.dict('sys.modules',{'settings':module}):
                    self.assertEqual(support.password_policy(),'each_mount')
                    self.assertTrue(support.auth_required(cached))

    def test_only_valid_readable_policy_can_allow_cached_reuse(self):
        for value in ('each_mount','startup','first_access',None,True,'unknown',[]):
            with self.subTest(value=value):
                module = SimpleNamespace(android_password_policy=lambda:value)
                with patch.dict('sys.modules',{'settings':module}):
                    expected = value if type(value) is str and value in support.POLICIES else 'each_mount'
                    self.assertEqual(support.password_policy(),expected)

class Wire(unittest.TestCase):
    def raw(self,**updates):
        v=dict(magic=MAGIC,version=1,op=1,seq=1,gen=1,state=2,mode=1,flags=39,phase=14,
               error=0,cleanup=0,pid=PID,reserved=0,auth=1,committed=1)
        v.update(updates)
        return RESPONSE.pack(*v.values())
    def test_exact_wire_and_rw_pre_auth_phase_are_accepted(self):
        r=decode_response(self.raw(),pid=PID,op=1)
        self.assertEqual(r['phase'],14);self.assertTrue(r['lease_released'])
    def test_snapshot_receipt_is_only_valid_for_a_verified_read_only_mount(self):
        self.assertTrue(decode_response(self.raw(flags=103), pid=PID, op=1)['ram_snapshot'])
        for data in (self.raw(flags=103,mode=2), self.raw(flags=103,state=3), self.raw(flags=103,error=-5)):
            with self.assertRaises(SessionError):
                decode_response(data,pid=PID,op=1)

    def test_snapshot_exec_mount_lives_until_native_exit(self):
        from decrypt_runtime.reusable_worker import NativeSession, pin_native_executable
        from unittest.mock import Mock

        def open_fixture(*args, **kwargs):
            return os.open('/dev/null', os.O_RDONLY)

        backend = Mock()
        backend.at.side_effect = lambda path: Path('/fixture' + path)
        runtime = SimpleNamespace(backend=backend)
        with patch('decrypt_runtime.rw_support.pinned_fd', side_effect=open_fixture):
            target = pin_native_executable(runtime, {
                'helper': '/system/bin/a22x-data-ce-session',
                'helper_sha256': '0' * 64, 'ram_snapshot_sha256': '1' * 64,
            })
        self.assertEqual(backend._mount.call_count, 2)
        backend.unmount.assert_not_called()

        owner = object.__new__(NativeSession)
        owner.runtime = runtime
        owner.snapshot_executable = target
        owner.reply = dict(state='closed', cache_valid=False, suspend_clean=True)
        owner.process = Mock()
        owner.process.wait.side_effect = lambda **kw: backend.unmount.assert_not_called() or 0
        owner.socket = Mock()
        with tempfile.TemporaryDirectory() as directory:
            owner.rowork, owner.rwwork = '/ro', '/rw'
            backend.at.side_effect = lambda path: Path(directory + path)
            for name in ('/ro', '/rw'):
                backend.at(name).mkdir()
            owner.close_observed()
        backend.unmount.assert_called_once_with(target)
    def test_wrong_wire_identity_length_flags_or_phase_are_rejected(self):
        for data in (self.raw()+b'x',self.raw()[:-1],self.raw(pid=PID+1),self.raw(op=2),
                     self.raw(flags=7),self.raw(flags=55),self.raw(phase=0),self.raw(phase=15),
                     self.raw(reserved=1),self.raw(magic=0),self.raw(committed=2)):
            with self.assertRaises(SessionError):decode_response(data,pid=PID,op=1)


    def test_status_poll_rejects_silent_ce_cleanup_flag_drift(self):
        from decrypt_runtime.reusable_worker import NativeSession
        owner = object.__new__(NativeSession)
        old = decode_response(self.raw(op=1, seq=3, gen=3, state=3,
            mode=0, flags=40, phase=14, error=-127, auth=2, committed=1),pid=PID,op=1)
        owner.reply = old

        class NoDeviceSocket:
            def sendmsg(self, parts, ancillary):
                assert ancillary == []
                return len(parts[0])

        owner.socket = NoDeviceSocket()
        baseline = decode_response(self.raw(op=5, seq=3, gen=3, state=3,
            mode=0, flags=40, phase=14, error=0, auth=2, committed=1),pid=PID,op=5)
        owner.receive = lambda op, deadline: baseline
        self.assertEqual(owner.command("status", 1), baseline)
        self.assertEqual(owner.reply, old)
        # Both altered replies retain the same state, cache and counters.
        # status is read-only and must reject silent CE or cleanup drift.
        for flag, reason in ((44, "ce_verified"), (32, "suspend_clean")):
            changed = decode_response(self.raw(op=5, seq=3, gen=3, state=3,
                mode=0, flags=flag, phase=14, error=0, auth=2,
                committed=1),pid=PID,op=5)
            owner.receive = lambda op, deadline, response=changed: response
            with self.subTest(reason=reason), self.assertRaises(SessionError):
                owner.command("status", 1)
            self.assertEqual(owner.reply, old)

class Epochs(unittest.TestCase):
    def setUp(self):
        try:
            import gk_diagnostic
        except ImportError:  # the TEE diagnostic parser is private: not in this tree (2026-11-22)
            self.skipTest('gk_diagnostic is not in this tree')
        self.module=gk_diagnostic
        self.diag=SimpleNamespace(parser=gk_diagnostic.Parser(),drain=lambda:None)
        self.diag.parser.feed(b'GK_TEEC_DIAG_READY version=2\n')
        self.epochs=DiagnosticEpochs(self.diag)
    def feed(self,status=0):
        timeout=1001 if status==2 else 0
        line=f'GK_TEEC_CALL_V2 cmd=126 result=0x00000000 origin_present=0 origin=0x00000000 ta_present=1 ta_status={status} ta_timeout={timeout} ta_timeout_valid={int(status==2)} ta_bound=QUALIFIED\n'
        self.diag.parser.feed(line.encode())
    def response(self,n=1,failed=False):
        return dict(sequence=n,generation=n,auth_sequence=n,committed_auth_sequence=n-int(failed),
                    auth_dispatched=True,error_errno=-127 if failed else 0,cleanup_errno=0,phase=3,
                    state='suspended' if failed else 'mounted',cache_valid=not failed)
    def test_more_than_old_64_record_limit_with_exact_epoch_validation(self):
        for n in range(1,1025):
            self.feed();self.feed()
            self.assertIsNone(self.epochs.finish('authenticate',self.response(n),format(n,'032x')))
            self.epochs.quiet()
            self.assertEqual(self.diag.parser.records,[{'kind':'READY','version':2}])
            self.assertEqual(self.diag.parser.total_bytes,0)
        r=self.epochs.summary()
        self.assertEqual(r['auth_successes'],1024);self.assertEqual(r['calls'],2048)
        self.assertEqual(len(r['recent']),16)
    def test_cached_resume_must_have_no_new_gatekeeper_call(self):
        self.feed()
        with self.assertRaises(SessionError):
            self.epochs.finish('resume',dict(self.response(),auth_dispatched=False))
    def test_missing_or_extra_native_auth_call_is_not_success(self):
        self.feed()
        with self.assertRaises(SessionError):self.epochs.finish('authenticate',self.response())
    def test_known_wrong_password_and_backoff_have_separate_public_results(self):
        for status,expected in ((1,'DECRYPT_FAILED'),(2,'RETRY_LATER')):
            self.setUp();self.feed(status)
            error=self.epochs.finish('authenticate',self.response(failed=True))
            self.assertEqual(error.code,expected)
            self.assertEqual(self.epochs.auth_successes,0)

    def test_public_failure_distinguishes_prepare_from_mount_after_verification(self):
        before = dict(self.response(failed=True), phase=2, auth_dispatched=False, auth_sequence=0)
        error = self.epochs.finish('authenticate', before)
        self.assertEqual(error.details['native_mount_failure'],
                         {'phase':2, 'errno':127, 'auth_dispatched':False, 'gatekeeper_verified':0})
        self.feed(); self.feed()
        after = dict(self.response(2, failed=True), phase=6)
        error = self.epochs.finish('authenticate', after)
        self.assertEqual(error.details['native_mount_failure'],
                         {'phase':6, 'errno':127, 'auth_dispatched':True, 'gatekeeper_verified':2})

    def test_pending_record_cannot_be_discarded_by_rotation(self):
        self.feed();self.feed();self.diag.parser.feed(b'GK_TEEC_')
        before=self.diag.parser
        with self.assertRaises(SessionError):self.epochs.finish('authenticate',self.response())
        self.assertIs(self.diag.parser,before);self.assertTrue(before.pending)
    def test_continuation_rejects_a_second_ready(self):
        self.feed();self.feed();self.epochs.finish('authenticate',self.response())
        with self.assertRaises(self.module.DiagnosticError):
            self.diag.parser.feed(b'GK_TEEC_DIAG_READY version=2\n')


class PublicAPI(unittest.TestCase):
    def test_busy_mode_change_refuses_before_native_password_submission(self):
        from filesystem import FilesystemError
        volume={'id':'userdata','decrypt_state':'mounted','session_reusable':True,
            'read_only':False,'physical_volume_token':'physical-original'}
        context=SimpleNamespace(lock_fd=77,boot_id=BOOT)
        receipt={'key_retained':True,'auth_generation':1,'authentication_id':'a'*32,
            'password_policy_at_auth':'first_access'}
        with patch.object(android_decrypt,'session_status',return_value=receipt), \
             patch.object(android_decrypt,'credential_descriptor',return_value=88), \
             patch.object(android_decrypt,'unmount',side_effect=FilesystemError('VOLUME_BUSY','busy')), \
             patch.object(android_decrypt,'retained_mount') as mount:
            with self.assertRaises(FilesystemError) as cm:
                android_decrypt.mount(context,volume,'ro',False,88,0,require_fresh_authentication=True)
            self.assertEqual(cm.exception.code,'VOLUME_BUSY')
            mount.assert_not_called()

    def test_unmount_all_terminally_closes_even_detached_sessions(self):
        import filesystem
        context=object.__new__(filesystem.DeviceContext)
        context.drop_vanished=lambda:None
        context.close_logical=lambda:[]
        volume={'id':'userdata','decrypt_state':'session_unmounted','session_retained':True,
                'mounted':False,'volume_token':'current'}
        context.volumes=lambda:[volume]
        context.state=lambda:{'volumes':{}}
        with patch.object(android_decrypt,'close_session',return_value={'session_closed':True}) as close, \
             patch.object(filesystem,'read_mounts',return_value=[]):
            result=context.unmount_all()
        close.assert_called_once_with(context,volume)
        self.assertEqual(result,{'unmounted':['userdata']})

    def test_format_force_auth_cannot_be_satisfied_by_same_mode_duplicate(self):
        mounted={'id':'userdata','decrypt_state':'mounted','session_reusable':True,
            'read_only':True,'physical_volume_token':'physical-original'}
        detached={'id':'userdata','decrypt_state':'session_unmounted','session_reusable':True,
            'physical_volume_token':'physical-original','decrypt_supported':True}
        context=SimpleNamespace(lock_fd=77,boot_id=BOOT)
        with patch.object(android_decrypt,'session_status',return_value={}), \
             patch.object(android_decrypt,'credential_descriptor',return_value=88), \
             patch.object(android_decrypt,'unmount',return_value={'volume':detached}) as suspend, \
             patch.object(android_decrypt,'retained_mount',return_value={'authentication_performed':True}) as fresh:
            result=android_decrypt.mount(context,mounted,'ro',False,88,0,require_fresh_authentication=True)
        suspend.assert_called_once_with(context,mounted)
        fresh.assert_called_once_with(context,detached,'ro',False,88,require_fresh_authentication=True)
        self.assertTrue(result['authentication_performed'])


class BackingGraph(unittest.TestCase):
    def graph(self, dev, name, slaves=(), partname=None, physical=False, uuid='foreign'):
        return {'device':dev,'name':name,'uuid':uuid,'slaves':list(slaves),
                'partname':partname,'physical_leaf':physical}
    def test_recycled_userdata_minor_now_backed_by_system_is_allowed(self):
        graph={'253:7':self.graph('253:7','a22x-filesystem-system',['259:12']),
               '259:12':self.graph('259:12','mmcblk0p44',partname='super',physical=True,uuid=None)}
        self.assertTrue(support.excludes_userdata('253:7','259:22',NAMES,reader=graph.__getitem__))
    def test_foreign_name_and_uuid_cannot_hide_userdata_backing(self):
        graph={'253:7':self.graph('253:7','foreign-name',['253:8']),
               '253:8':self.graph('253:8','another-name',['259:22'])}
        self.assertFalse(support.excludes_userdata('253:7','259:22',NAMES,reader=graph.__getitem__))
    def test_ambiguous_missing_leaf_and_cycles_fail_closed(self):
        for graph in ({'253:7':self.graph('253:7','foreign')},
                      {'253:7':self.graph('253:7','foreign',['253:8']),
                       '253:8':self.graph('253:8','another',['253:7'])}):
            with self.assertRaises(SessionError):
                support.excludes_userdata('253:7','259:22',NAMES,reader=graph.__getitem__)
    def test_user_data_partition_name_is_rejected_even_if_device_number_changes(self):
        graph={'8:1':self.graph('8:1','sda1',partname='userdata',physical=True,uuid=None)}
        self.assertFalse(support.excludes_userdata('8:1','259:22',NAMES,reader=graph.__getitem__))
    def test_dependency_change_between_snapshots_is_not_a_proof(self):
        calls=[0]
        def read(dev):
            calls[0]+=1
            return self.graph(dev,'sda1',partname='external' if calls[0]==1 else 'userdata',physical=True,uuid=None)
        with self.assertRaises(SessionError):
            support.excludes_userdata('8:1','259:22',NAMES,reader=read)

if __name__=='__main__':unittest.main()
