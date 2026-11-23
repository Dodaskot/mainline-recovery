"""Writable CE admission, exact native proof and mode binding; no device I/O."""
import copy
import errno
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import android_decrypt as ad
import decrypt_session as session
from decrypt_runtime import common, mounts, rw_support as rw, rw_verdict as verdict
from tests.test_decrypt_session import BOOT, CONFIG, FakeMounts
from android_profiles import EVO_PROFILE
from tests.test_decrypt_discovery import SOURCE

CAP=dict(schema=rw.RW_SCHEMA,qualified=True,helper=rw.HELPER,helper_sha256=rw.HELPER_SHA,
    kernel_release=rw.KERNEL_RELEASE,quota_modules=[dict(name=n,path=p,sha256=h) for n,p,h in rw.QUOTAS])


def success_record():
    lines=['G3 SP_CE_AUTHENTICATED_KEY_DELIVERED','G4 SP_KEY_RECEIVED_ONCE bytes=64']
    lines+=['G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS']*4
    lines+=['G4 SP_MEDIA_USER0_READDIR_PASS entries=14 complete=1 fs_ro=1 dm_ro=1 alias_ro=1',
        'G4 SP_MEDIA_USER0_READDIR_PASS entries=14 complete=1 fs_ro=1 dm_ro=0 alias_ro=0',
        'G4 WP_KERNEL_RO_RECOVERY_CHECK_PASS dm=a22x-data-ro-sessiontestrw raw_dm=a22x-data-ro-sessiontestrw-raw device=253:7 sectors=1000',
        'G4 WP_INITIAL_FS_RO_DM_RW_PASS dm=a22x-data-ro-sessiontestrw raw_dm=a22x-data-ro-sessiontestrw-raw device=253:7 sectors=1000',
        'G4 WP_F2FS_STATUS sb=0x21 cp=0x0 clean_required=0',
        'G4 WP_F2FS_HEALTH_PASS clean_checkpoint=0',
        'G4 CE_RW_MEDIA_PASS entries=14 complete=1',
        'G4 CE_RW_SESSION_PASS version=1 old_removed=1 new_live=1 new_creator=333 fs_ro=0 dm_ro=0 alias_ro=0 ce_policy=1 quota_user_group=1 media_read=1']
    return dict(operation='unlock-sp-user0-rw',pid=333,returncode=0,status_lines=lines)


class NativeRwProofTests(unittest.TestCase):
    def test_success_requires_independent_rw_and_both_ro_proofs(self):
        record=success_record()
        classified=verdict.classify(('\n'.join(record['status_lines'])+'\n').encode(),b'')
        self.assertEqual(classified['status_lines'],record['status_lines'])
        self.assertTrue(verdict.native_verdict(record)['success'])
        for i in range(len(record['status_lines'])):
            bad=copy.deepcopy(record);bad['status_lines'].pop(i)
            # F2FS public health/status are supplementary; their admission is
            # encoded in the exact final native contract, all other lines matter.
            if record['status_lines'][i].startswith(('G4 WP_F2FS_STATUS','G4 WP_F2FS_HEALTH')):
                continue
            with self.assertRaises(RuntimeError,msg=str(i)): verdict.native_verdict(bad)

    def test_ro_success_cannot_authorize_rw_and_creator_is_bound(self):
        good=success_record()
        for change in (dict(operation='unlock-sp-user0'),dict(pid=334),dict(returncode=1)):
            with self.assertRaises(RuntimeError): verdict.native_verdict(dict(good,**change))
        for changed in ('fs_ro=1','dm_ro=1','alias_ro=1','ce_policy=0','quota_user_group=0','media_read=0'):
            bad=copy.deepcopy(good);key=changed.split('=')[0]
            import re
            bad['status_lines'][-1]=re.sub(key+'=[01]',changed,bad['status_lines'][-1])
            with self.assertRaises(RuntimeError): verdict.native_verdict(bad)
        bad=copy.deepcopy(good);bad['status_lines'].append(bad['status_lines'][-1])
        with self.assertRaises(RuntimeError): verdict.native_verdict(bad)
        for raw in (b'G4 CE_RW_SESSION_PASS version=1\n',b'G4 WP_WRITE_PASS secret=anything\n'):
            with self.assertRaises(RuntimeError): verdict.classify(raw,b'')

    def test_auth_failure_never_claims_rw_and_cleanup_error_is_preserved(self):
        # Exact native unwind: auth fails, old creator cleanup succeeds, no new maps.
        failure='G4 CE_RW_SESSION_FAILED version=1 phase=auth errno=10 old_removed=1 new_attempted=0 new_live=0 new_creator=333 cleanup_errno=0'
        record=dict(operation='unlock-sp-user0-rw',pid=333,returncode=1,
            status_lines=['G3 SP_AUTH_FAILED status=2 timeout_ms=2000','G4 CLEANUP_PASS',failure])
        classified=verdict.classify((chr(10).join(record['status_lines'])+chr(10)).encode(),b'')
        self.assertEqual(classified['status_lines'],record['status_lines'])
        got=verdict.native_verdict(record)
        self.assertFalse(got['success']);self.assertFalse(got['new_attempted'])
        self.assertTrue(got['old_removed']);self.assertFalse(got['new_live'])
        self.assertEqual(got['cleanup_errno'],0)
        self.assertEqual(got['status'],'PASSWORD_AUTH_FAILED_NO_RETRY')
        self.assertEqual(got['native_auth_status'],2)
        self.assertEqual(got['native_timeout_ms'],2000)
        for before,after in [('old_removed=1','old_removed=0'),
                ('new_attempted=0','new_attempted=1'),('new_live=0','new_live=1'),
                ('cleanup_errno=0','cleanup_errno=16')]:
            bad=dict(record,status_lines=record['status_lines'][:-1]+[failure.replace(before,after)])
            with self.assertRaises(RuntimeError):verdict.native_verdict(bad)
        # A generic native cleanup failure still retains its quarantine evidence.
        record['status_lines']=[failure.replace('old_removed=1','old_removed=0').replace('cleanup_errno=0','cleanup_errno=16')]
        self.assertEqual(verdict.native_verdict(record)['cleanup_errno'],16)
        self.assertFalse(verdict.native_verdict(record)['success'])

    def test_cleanup_exact_creator_and_no_failure_ack(self):
        record=dict(operation='cleanup-rw',returncode=0,
            status_lines=['G4 CLEANUP_PASS','G4 CE_RW_CLEANUP_PASS version=1 creator=333 new_live=0'])
        self.assertTrue(verdict.cleanup_verdict(record,333))
        with self.assertRaises(RuntimeError):verdict.cleanup_verdict(record,334)
        with self.assertRaises(RuntimeError):verdict.cleanup_verdict(dict(record,returncode=1),333)
        record['status_lines'].append('G4 CE_RW_CLEANUP_FAILED version=1 creator=333 errno=16')
        with self.assertRaises(RuntimeError):verdict.cleanup_verdict(record,333)


class CallbackAuthCleanupTests(unittest.TestCase):
    def exercise(self, mode='clean'):
        import sys
        import time
        from decrypt_runtime import ro_auth_callback_session as callback,worker_control
        run_id='sessiontest1';calls=[];errors=[]
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in ('run','mnt','metadata/vold/metadata_encryption/key','vendor/etc'):
                (root/name).mkdir(parents=True,exist_ok=True)
            (root/'vendor/etc/fstab.mt6833').write_bytes(b'synthetic public fstab')
            source=root/'userdata-source';source.write_bytes(b'SYNTHETIC')
            backend=SimpleNamespace(at=lambda path:root/path.lstrip('/'),
                nodes={'a22x-c-'+run_id+'-userdata':source},_mount=lambda *a:None,unmount=lambda *a:None)
            class Process:
                def __init__(self,argv):
                    self.args=argv;self.pid=333 if argv[1]=='unlock-sp-user0-rw' else 222
                    self.returncode=1 if argv[1]=='unlock-sp-user0-rw' else 0
                def communicate(self,timeout):
                    op=self.args[1]
                    if op=='unwrap-mount':lines=['G4 MOUNT_RO_PASS dm=a22x-data-ro-'+run_id+' raw_dm=a22x-data-ro-'+run_id+'-raw device=253:1 sectors=1000']
                    elif op=='unlock-de-user0':lines=['G4 DE_ONLY_UNLOCK_PASS ce_calls=0']
                    elif op=='prepare-sp':lines=['G3 SP_PREPARE_READY auth_calls=0 ce_profile=legacy_hw_scrypt_v1','G4 SP_PREPARE_PASS auth_calls=0']
                    elif op=='unlock-sp-user0-rw':
                        if mode=='unknown':lines=['unknown native response']
                        else:
                            old,clean=('1','0') if mode=='clean' else ('0','16')
                            lines=['G3 SP_AUTH_FAILED status=2 timeout_ms=2000',
                                'G4 CE_RW_SESSION_FAILED version=1 phase=auth errno=10 old_removed='+old+' new_attempted=0 new_live=0 new_creator=333 cleanup_errno='+clean]
                            if mode=='clean':lines.insert(1,'G4 CLEANUP_PASS')
                    elif op=='cleanup-rw':
                        # Native already removed old and never made new resources:
                        # exact-new absence returns clean without touching old target.
                        self_outer.assertEqual(self.args[5],'333')
                        lines=['G4 CE_RW_CLEANUP_PASS version=1 creator=333 new_live=0']
                    elif op=='cleanup':
                        # Frozen cleanup of already-absent old identity is idempotent.
                        self_outer.assertEqual(self.args[5],'222')
                        self_outer.assertEqual(calls[-2][1],'cleanup-rw')
                        lines=['G4 CLEANUP_PASS']
                    else:raise AssertionError(op)
                    return (chr(10).join(lines)+chr(10)).encode(),b''
            self_outer=self
            def spawn(argv,**kwargs):calls.append(argv);return Process(argv)
            runtime=SimpleNamespace(backend=backend,common_lock_fd=71,spawn=spawn,getprop=lambda name:'2')
            class Trace:
                def __init__(self,*a):pass
                def start(self):pass
                def finish(self):return dict(mode='TZDAEMON_STORAGE',status='SCALAR_TRACE_COMPLETE',cleanup_verified=True)
            modules={'c_crypto_profile':SimpleNamespace(require_profile=lambda *a:{}),
                     'tz_syscall_trace':SimpleNamespace(StorageTrace=Trace)}
            readfd,writefd=os.pipe();os.close(writefd);slot=[readfd]
            try:
                with patch.dict(sys.modules,modules),patch.dict(os.environ,{'A22X_C_WD_DEADLINE':str(time.monotonic()+240)}), \
                     patch.object(callback,'current_framework_identity'), \
                     patch.object(rw,'pinned_fd',side_effect=lambda *a,**k:os.open('/dev/null',os.O_RDONLY)), \
                     patch.object(worker_control,'awaiting_credential',return_value='rw'), \
                     patch.object(worker_control,'check_before_auth'),patch.object(worker_control,'_discovery',False):
                    consumer=callback.make_consumer(run_id,slot,errors,lambda *a,**k:None,rw_capability=CAP)
                    if mode=='clean':result=consumer(runtime)
                    else:
                        with self.assertRaises(RuntimeError):consumer(runtime)
                        result=None
            finally:
                if slot[0]>=0:os.close(slot[0])
            return result,calls,errors
    def test_canonical_auth_failure_cleans_new_then_absent_old_without_quarantine(self):
        result,calls,errors=self.exercise()
        self.assertEqual(result['status'],'PASSWORD_AUTH_FAILED_NO_RETRY')
        self.assertFalse(result['success']);self.assertEqual(errors,[])
        self.assertEqual([a[1] for a in calls if a[1] in ('cleanup','cleanup-rw')],['cleanup-rw','cleanup'])
        self.assertEqual(sum(a[1]=='unlock-sp-user0-rw' for a in calls),1)
    def test_cleanup_failure_is_quarantined_without_replay(self):
        result,calls,errors=self.exercise('cleanupfail')
        self.assertIsNone(result)
        self.assertFalse(any(a[1] in ('cleanup','cleanup-rw') for a in calls))
        self.assertIn({'stage':'ce_rw_quarantined_cleanup_not_replayed'},errors)
    def test_unknown_native_outcome_is_quarantined_without_replay(self):
        result,calls,errors=self.exercise('unknown')
        self.assertIsNone(result)
        self.assertFalse(any(a[1] in ('cleanup','cleanup-rw') for a in calls))
        self.assertIn({'stage':'ce_rw_quarantined_cleanup_not_replayed'},errors)


class AdmissionTests(unittest.TestCase):
    def test_capability_absent_false_malformed_or_cross_kernel_stays_ro(self):
        self.assertFalse(rw.available({}));self.assertTrue(rw.available({'profile_id':EVO_PROFILE,'ce_rw':CAP}))
        for key,bad in [('qualified',False),('helper','/system/bin/a22x-data-ro'),
                        ('kernel_release','old'),('helper_sha256','bad'),('quota_modules',[])]:
            changed=copy.deepcopy(CAP);changed[key]=bad
            self.assertFalse(rw.available({'profile_id':EVO_PROFILE,'ce_rw':changed}))
        self.assertFalse(rw.available({'profile_id':EVO_PROFILE,'ce_rw':dict(CAP,extra=True)}))

    def test_rw_requires_prepared_credential_confirmation_and_capability(self):
        ctx=SimpleNamespace(lock_fd=71,boot_id=BOOT)
        volume=dict(decrypt_supported=True,decrypt_write_supported=True,decrypt_state='awaiting_credential',
                    volume_token='pending',credential_type='password',decrypt_profile_id=EVO_PROFILE)
        with patch.object(ad,'credential_descriptor'),patch.object(rw,'quotas') as loader, \
             patch.object(ad,'authenticate_prepared') as auth,patch.object(ad,'profile',return_value={'profile_id':EVO_PROFILE,'ce_rw':CAP}):
            for bad,mode,confirm,code in [(dict(volume,decrypt_write_supported=False),'rw',True,'WRITE_NOT_QUALIFIED'),
                (volume,'rw',False,'CONFIRMATION_REQUIRED'),
                (dict(volume,decrypt_state='locked'),'rw',True,'DECRYPT_PREPARATION_REQUIRED')]:
                with self.assertRaises(Exception) as e:ad.mount(ctx,bad,mode,confirm,77,0)
                self.assertEqual(e.exception.code,code)
            loader.assert_not_called();auth.assert_not_called()
            ad.mount(ctx,volume,'rw',True,77,0)
            loader.assert_called_once_with(CAP,BOOT,71,load=True)
            auth.assert_called_once_with(ctx,volume,77,'rw',True)

    def test_read_only_snapshot_open_loads_the_qualified_quota_pair_first(self):
        ctx=SimpleNamespace(lock_fd=71,boot_id=BOOT)
        volume=dict(decrypt_supported=True,decrypt_write_supported=True,decrypt_state='awaiting_credential',
                    volume_token='pending',credential_type='password',decrypt_profile_id=EVO_PROFILE)
        snapshot={'profile_id':EVO_PROFILE,'ce_rw':CAP,'ce_session':{'ram_snapshot_sha256':'1'*64}}
        with patch.object(ad,'credential_descriptor'),patch.object(rw,'quotas') as loader, \
             patch.object(ad,'authenticate_prepared') as auth,patch.object(ad,'profile',return_value=snapshot):
            ad.mount(ctx,volume,'ro',False,77,0)
            loader.assert_called_once_with(CAP,BOOT,71,load=True)
            auth.assert_called_once_with(ctx,volume,77,'ro',False)
        for plain in ({'profile_id':EVO_PROFILE,'ce_rw':CAP,'ce_session':{}}, {'profile_id':EVO_PROFILE,'ce_session':snapshot['ce_session']}):
            with patch.object(ad,'credential_descriptor'),patch.object(rw,'quotas') as loader, \
                 patch.object(ad,'authenticate_prepared') as auth,patch.object(ad,'profile',return_value=plain):
                ad.mount(ctx,volume,'ro',False,77,0)
                loader.assert_not_called();auth.assert_called_once()
        with patch.object(ad,'credential_descriptor'),patch.object(rw,'quotas',side_effect=OSError(1,'refused')), \
             patch.object(ad,'authenticate_prepared') as auth,patch.object(ad,'profile',return_value=snapshot):
            with self.assertRaises(Exception) as e:ad.mount(ctx,volume,'ro',False,77,0)
            self.assertEqual(e.exception.code,'DECRYPT_QUOTA_UNAVAILABLE');auth.assert_not_called()

    def test_mounted_mode_changes_require_restart_and_never_reauthenticate(self):
        for current,requested in ((True,'rw'),(False,'ro')):
            v=dict(decrypt_state='mounted',read_only=current,decrypt_write_supported=True)
            with patch.object(ad,'credential_descriptor') as credential:
                with self.assertRaises(Exception) as e:ad.mount(SimpleNamespace(),v,requested,True,None,0)
                self.assertEqual(e.exception.code,'DECRYPT_MODE_FIXED');credential.assert_not_called()


class RwFakeMounts(FakeMounts):
    def bind(self,*args,read_only=True):
        self.bound=True
        return dict(mountpoint=args[3],mount_id=17,device='253:7',read_only=read_only)

class ModeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.sent=[];self.commits=[];self.mounts=RwFakeMounts()
        self.life=session.SessionLifecycle(dict(CONFIG,profile_id=EVO_PROFILE,ce_rw=CAP),mounts=self.mounts,
            commit=self.commits.append,send_worker=lambda v,f:self.sent.append((v,f)),
            release_lease=lambda:None,cleanup_check=lambda:True,disarm=lambda:None,now=lambda:100.)
        self.life.prepared(os.getpid(),common.starttime(os.getpid()),'password',SOURCE)
        self.life.prepared_held()
    def request(self,mode='rw'):
        return dict(op='authenticate',boot_id=BOOT,run_id=CONFIG['run_id'],
            volume_token=self.life.receipt['volume_token'],credential_type='password',
            requested_mode=mode,write_confirmed=mode=='rw')
    def test_cross_mode_missing_confirmation_stale_request_no_dispatch(self):
        for key,value in [('requested_mode','invalid'),('write_confirmed',False),('volume_token','stale')]:
            req=self.request();req[key]=value;before=list(self.sent)
            with self.assertRaises(common.SessionError):self.life.start_auth(req,71,77)
            self.assertFalse(self.life.auth_started);self.assertEqual(self.sent,before)
        req=self.request();del req['requested_mode']
        with self.assertRaises(common.SessionError):self.life.start_auth(req,71,77)
    def test_rw_cannot_bind_ro_proof_or_unauthenticated_event(self):
        with self.assertRaises(common.SessionError):self.life.authenticated(333,1,88,{'read_only':False},credential_type='password',requested_mode='rw')
        with patch.object(rw,'quotas'):self.life.start_auth(self.request(),71,77)
        for mode,proof in [('ro',{'read_only':True}),('rw',{'read_only':True}),('rw',None)]:
            with self.assertRaises(common.SessionError):self.life.authenticated(333,1,88,proof,credential_type='password',requested_mode=mode)
        self.assertFalse(self.mounts.bound)
    def test_rw_receipt_actual_bool_and_busy_unmount_retains_session(self):
        with patch.object(rw,'quotas'):self.life.start_auth(self.request(),71,77)
        self.life.authenticated(os.getpid(),common.starttime(os.getpid()),88,{'read_only':False},credential_type='password',requested_mode='rw')
        self.life.held();receipt=self.life.receipt
        self.assertIs(receipt['read_only'],False);self.assertEqual(receipt['requested_mode'],'rw')
        session.validate_state(receipt,boot_id=BOOT,process_check=lambda p,t:True,mount_check=lambda r:None)
        for bad in (dict(receipt,read_only=True),dict(receipt,ce_rw_native_verified=False),dict(receipt,ce_rw=None)):
            with self.assertRaises(common.SessionError):session.validate_state(bad,boot_id=BOOT,process_check=lambda p,t:True,mount_check=lambda r:None)
        self.mounts.busy=True;before=list(self.sent)
        with self.assertRaises(common.SessionError) as busy:self.life.request_unmount(91)
        self.assertEqual(busy.exception.code,'VOLUME_BUSY');self.assertTrue(busy.exception.details['session_preserved'])
        self.assertTrue(self.life.bound);self.assertEqual(self.life.state,'mounted');self.assertEqual(self.sent,before)
        self.mounts.busy=False;self.life.request_unmount(91)
        self.assertTrue(self.life.complete(0,dict(cleanup_verified=True,success=True))['ok'])


class MountFlagTests(unittest.TestCase):
    def test_actual_mount_access_flags_must_match_receipt(self):
        for mode,readonly in [('ro',True),('rw',False)]:
            text=f'17 1 253:7 / /mnt/volumes/userdata {mode},nosuid,nodev,noexec - f2fs /dev/dm-7 {mode}\n'
            receipt=dict(mountpoint='/mnt/volumes/userdata',mount_id=17,device='253:7',read_only=readonly)
            mounts.verify_mount(receipt,text)
            with self.assertRaises(common.SessionError):mounts.verify_mount(dict(receipt,read_only=not readonly),text)
            with self.assertRaises(common.SessionError):mounts.verify_mount(receipt,text.replace('nodev,',''))


class OwnedQuotaLoaderTests(unittest.TestCase):
    def exercise(self,preloaded=None,fail_second=False):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        state=Path(temp.name)/'state';loaded=dict(preloaded or {});calls=[]
        def pinned(path,digest,executable=False):return os.open('/dev/null',os.O_RDONLY)
        def load(fd):
            name=rw.QUOTAS[len(calls)][0];calls.append(name)
            if fail_second and len(calls)==2:raise OSError(errno.EINVAL,'synthetic load failed')
            loaded[name]=100+len(calls)
        context=patch.multiple(rw,QUOTA_STATE=str(state),pinned_fd=pinned,
            module_identity=lambda n:loaded.get(n),finit_module=load,validate_lease=lambda fd:None)
        return context,state,loaded,calls
    def test_only_two_exact_pins_in_order_then_owned_reuse(self):
        context,state,loaded,calls=self.exercise()
        with context,patch.object(rw.os,'geteuid',return_value=0),patch.object(rw.os,'uname',return_value=SimpleNamespace(release=rw.KERNEL_RELEASE)):
            # The owned receipt directory still uses the current test UID.
            with patch.object(rw,'secure_directory',lambda p,create=False:common.secure_directory(p,create=create,uid=os.getuid())), \
                 patch.object(rw,'read_json_at',lambda d,n:common.read_json_at(d,n,uid=os.getuid())):
                got=rw.quotas(CAP,BOOT,71,load=True)
                self.assertEqual(calls,['quota_tree','quota_v2']);self.assertEqual(len(got['modules']),2)
                rw.quotas(CAP,BOOT,71,load=True);self.assertEqual(len(calls),2)
                loaded['quota_v2']=999
                with self.assertRaises(common.SessionError):rw.quotas(CAP,BOOT,71)
    def test_unowned_preloaded_module_refused_before_load(self):
        context,state,loaded,calls=self.exercise(preloaded={'quota_tree':99})
        with context,patch.object(rw.os,'geteuid',return_value=0),patch.object(rw.os,'uname',return_value=SimpleNamespace(release=rw.KERNEL_RELEASE)), \
             patch.object(rw,'secure_directory',lambda p,create=False:common.secure_directory(p,create=create,uid=os.getuid())):
            with self.assertRaises(common.SessionError):rw.quotas(CAP,BOOT,71,load=True)
            self.assertEqual(calls,[])
    def test_partial_failure_preserves_owned_first_module_without_auth(self):
        context,state,loaded,calls=self.exercise(fail_second=True)
        with context,patch.object(rw.os,'geteuid',return_value=0),patch.object(rw.os,'uname',return_value=SimpleNamespace(release=rw.KERNEL_RELEASE)), \
             patch.object(rw,'secure_directory',lambda p,create=False:common.secure_directory(p,create=create,uid=os.getuid())):
            with self.assertRaises(OSError):rw.quotas(CAP,BOOT,71,load=True)
            self.assertEqual(calls,['quota_tree','quota_v2']);self.assertTrue((state/'owned.json').exists())
            self.assertNotIn('quota_v2',loaded)

if __name__=='__main__':unittest.main()
