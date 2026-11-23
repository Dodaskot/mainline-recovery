"""Modern Evo native RW proof and real callback cleanup paths; no hardware I/O."""
import copy
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from decrypt_runtime import ro_evox_callback_session as cb, worker_control as wc
from decrypt_runtime import rw_support as rw, rw_verdict as rv, native_session_worker as worker, common
from tests.test_decrypt_rw import CAP, success_record
from tests.test_decrypt_evox import RUN, PREPARE, password_ops, extension, record, discovery, diagnostic

RW_MEDIA=dict(entries=14,complete=True,policy_v2_supported=True,fs_ro=False,dm_ro=False,raw_dm_ro=False,alias_ro=False)

def modern_record():
    result=success_record();result['operation']='unlock-evox-password-user0-rw'
    result['status_lines']=[line.replace('G4 SP_KEY_RECEIVED_ONCE','G4 EVOX_PASSWORD_KEY_RECEIVED_ONCE').replace('sessiontestrw',RUN+'rw') for line in result['status_lines']]
    return result

def modern_ops():return password_ops()[:4]+[modern_record()]

class ModernProofs(unittest.TestCase):
    def test_receipts_match_exact_frozen_source04_producer_contract(self):
        # Host-only evidence fixture: pins the actual producer, not a second
        # hand-authored expectation of whether preflight uses OLD or NEW.
        source=Path.home() / ('a22x-work/artifacts/lk-recovery-bridge-20261114/stage-c/password-sp/permanent-rw-backup-20261116/native-rw-sol04/source')
        producers={
            'bridge_rw.c':'f3b9d1866d957cf21c7f0e3bdf8e6b7b79e2ac764f224548a0fb15d16ef1ea6e',
            'evox/donor/write-probe/dm_rw.c':'5c94631f32b94bac787dfd7517cb2b0663dab884ceb15c2c77bf0ebf31d7f487'}
        texts={}
        for rel,digest in producers.items():
            data=(source/rel).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(),digest)
            texts[rel]=data.decode()
        bridge=texts['bridge_rw.c'];donor=texts['evox/donor/write-probe/dm_rw.c']
        self.assertIn('wp_mount_preflight(c->source,c->target,c->work,c->name,',bridge)
        self.assertIn('wp_mount_data(c->source,c->target,c->work,c->name,',bridge)
        for prefix,function in [('G4 WP_KERNEL_RO_RECOVERY_CHECK_PASS ','wp_mount_preflight'),
                                ('G4 WP_INITIAL_FS_RO_DM_RW_PASS ','wp_mount_data')]:
            body=donor.split('static int '+function+'(',1)[1].split('\nstatic int ',1)[0]
            self.assertIn('printf("'+prefix+'dm=%s raw_dm=%s ',body)
            lines=[line for line in modern_record()['status_lines'] if line.startswith(prefix)]
            self.assertEqual(len(lines),1)
            self.assertTrue(lines[0].startswith(prefix+'dm=a22x-data-ro-'+RUN+'rw raw_dm=a22x-data-ro-'+RUN+'rw-raw '))
        self.assertTrue(cb.qualify_retained_rw(modern_ops(),RUN,RW_MEDIA)['success'])

    def test_old_chain_receipt_cannot_stand_in_for_new_preflight_or_initial_mount(self):
        for prefix in ('G4 WP_KERNEL_RO_RECOVERY_CHECK_PASS ','G4 WP_INITIAL_FS_RO_DM_RW_PASS '):
            with self.subTest(prefix=prefix):
                ops=modern_ops()
                ops[-1]['status_lines']=[line.replace(RUN+'rw',RUN) if line.startswith(prefix) else line
                                        for line in ops[-1]['status_lines']]
                with self.assertRaisesRegex(RuntimeError,'EVOX_RW_CHAIN_NAME_BINDING'):
                    cb.qualify_retained_rw(ops,RUN,RW_MEDIA)

    def rejection(self):
        consumer=dict(status='EVOX_NONE_RW_UNSUPPORTED_BEFORE_AUTH',success=False,
            failure_stage='unsupported_credential',error_code='WRITE_NOT_QUALIFIED',
            operations=password_ops()[:2]+[discovery('none'),record('cleanup',['G4 CLEANUP_PASS'])],
            credential_type='none',requested_mode='rw',password_submissions=0,unlock_dispatches=0,
            synthetic_write_calls=0,independent_media=None)
        return dict(status='G2_REMOTE_TEE_KEYMASTER_GATEKEEPER_DIAGNOSTIC_READY',consumer_run=True,
            all_owned_processes_reaped=True,process_cleanup_errors=[],consumer=consumer,
            gatekeeper_teec_diagnostic=diagnostic(0))
    def test_typed_none_rw_rejection_requires_zero_verify_and_normal_cleanup(self):
        self.assertIs(worker.evaluate_evox(self.rejection(),RUN),False)
        for change in ('verify','cleanup','submission','noneunlock'):
            bad=self.rejection()
            if change=='verify':bad['gatekeeper_teec_diagnostic']=diagnostic(1)
            elif change=='cleanup':bad['consumer']['operations'][-1]['returncode']=1
            elif change=='submission':bad['consumer']['password_submissions']=1
            else:bad['consumer']['operations'].insert(3,record('unlock-none-user0',[]))
            with self.assertRaises(RuntimeError):worker.evaluate_evox(bad,RUN)
    def test_public_write_not_qualified_is_allowlisted_only_after_verified_outcome(self):
        fields=dict(success=False,cleanup_verified=True,outcome={'extension_result':self.rejection()})
        with patch.object(wc,'packet') as packet:
            wc.emit('c_session_result',fields)
            self.assertNotIn('error_code',packet.call_args.args[1]['verdict'])
            wc.emit('c_session_result',dict(fields,unsupported_verified=True,public_error_code='WRITE_NOT_QUALIFIED'))
            verdict=packet.call_args.args[1]['verdict']
            self.assertEqual(common.public_failure(verdict).code,'WRITE_NOT_QUALIFIED')
            wc.emit('c_session_result',dict(fields,unsupported_verified=True,public_error_code='ARBITRARY'))
            self.assertNotIn('error_code',packet.call_args.args[1]['verdict'])

    def test_exact_modern_key_marker_and_staged_ro_rw_proofs(self):
        r=modern_record()
        self.assertTrue(rv.native_verdict(r)['success'])
        self.assertEqual(rv.classify(('\n'.join(r['status_lines'])+'\n').encode(),b'',evo=True)['status_lines'],r['status_lines'])
        self.assertTrue(cb.qualify_retained_rw(modern_ops(),RUN,RW_MEDIA)['success'])
        bad=copy.deepcopy(r);bad['status_lines']=[x.replace('EVOX_PASSWORD_KEY_RECEIVED_ONCE','SP_KEY_RECEIVED_ONCE') for x in bad['status_lines']]
        with self.assertRaises(RuntimeError):rv.native_verdict(bad)
        bad=copy.deepcopy(r);bad['operation']='unlock-sp-user0-rw'
        with self.assertRaises(RuntimeError):rv.native_verdict(bad)
    def test_cross_run_rw_preflight_cannot_authorize_current_session(self):
        ops=modern_ops();ops[-1]['status_lines']=[x.replace(RUN+'rw','another_runrw') for x in ops[-1]['status_lines']]
        with self.assertRaises(RuntimeError):cb.qualify_retained_rw(ops,RUN,RW_MEDIA)
    def test_old_ro_new_ro_quota_health_contract_missing_or_wrong_rejected(self):
        for index,line in enumerate(modern_record()['status_lines']):
            if line.startswith(('G4 WP_F2FS_STATUS','G4 WP_F2FS_HEALTH')):continue
            r=modern_record();r['status_lines'].pop(index)
            with self.assertRaises(RuntimeError):rv.native_verdict(r)
        for field in ('fs_ro','dm_ro','raw_dm_ro','alias_ro'):
            with self.assertRaises(RuntimeError):cb.qualify_retained_rw(modern_ops(),RUN,dict(RW_MEDIA,**{field:True}))
    def test_final_modern_rw_result_requires_cleanup_once_and_two_qualified_verifies(self):
        e=extension();c=e['consumer'];ops=modern_ops();v=rv.native_verdict(ops[-1])
        c.update(v,operations=ops+[record('cleanup-rw',['G4 CE_RW_CLEANUP_PASS version=1 creator=333 new_live=0']),record('cleanup',['G4 CLEANUP_PASS'])],requested_mode='rw',independent_media=RW_MEDIA)
        self.assertTrue(worker.evaluate_evox(e,RUN))
        for change in ('secondcleanup','wrongcreator','oneverify'):
            bad=copy.deepcopy(e)
            if change=='secondcleanup':bad['consumer']['operations'].append(record('cleanup',['G4 CLEANUP_PASS']))
            elif change=='wrongcreator':bad['consumer']['operations'][-2]['status_lines']=['G4 CE_RW_CLEANUP_PASS version=1 creator=334 new_live=0']
            else:bad['gatekeeper_teec_diagnostic']=diagnostic(1)
            with self.assertRaises(RuntimeError):worker.evaluate_evox(bad,RUN)
    def test_known_modern_auth_failure_keeps_typed_status_without_rw(self):
        r=record('unlock-evox-password-user0-rw',['G3 SP_AUTH_FAILED status=2 timeout_ms=2000','G4 CLEANUP_PASS','G4 CE_RW_SESSION_FAILED version=1 phase=auth errno=10 old_removed=1 new_attempted=0 new_live=0 new_creator=333 cleanup_errno=0'],1);r['pid']=333
        v=rv.native_verdict(r);self.assertFalse(v['success']);self.assertEqual(v['native_timeout_ms'],2000)
        self.assertFalse(v['new_attempted']);self.assertTrue(v['old_removed'])

class Parked(BaseException):pass

class ActualCallback(unittest.TestCase):
    def exercise(self, mode='success', preparation_mode='ro'):
        calls=[];physical_fds=[];errors=[];progress=dict(password_submissions=0,unlock_dispatches=0);slot=[-1]
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in ('run','mnt','metadata/vold/metadata_encryption/key','vendor/etc','system/bin'):(root/name).mkdir(parents=True,exist_ok=True)
            (root/'vendor/etc/fstab.mt6833').write_bytes(b'public fstab')
            for name in ('a22x-data-ro','a22x-unlock-evox-password'):(root/'system/bin'/name).write_bytes(b'public native')
            source=root/'source';source.write_bytes(b'SYNTHETIC')
            backend=SimpleNamespace(at=lambda p:root/p.lstrip('/'),nodes={'a22x-c-'+RUN+'-userdata':source},_mount=lambda *a:None,unmount=lambda *a:None)
            class Process:
                def __init__(self,argv):self.args=argv;self.pid=333 if argv[1]=='unlock-evox-password-user0-rw' else 222;self.returncode=1 if mode in ('authfail','cleanupfail') and argv[1]=='unlock-evox-password-user0-rw' else 0
                def communicate(self,timeout):
                    op=self.args[1]
                    if op=='unwrap-mount':lines=password_ops()[0]['status_lines']
                    elif op=='unlock-de-user0':lines=password_ops()[1]['status_lines']
                    elif op=='discover-evox-user0':lines=discovery('none' if mode=='none' else 'password')['status_lines']
                    elif op=='prepare-evox-password-user0':lines=PREPARE
                    elif op=='unlock-evox-password-user0-rw':
                        if mode=='unknown':lines=['UNKNOWN PRIVATE OUTPUT DISCARDED']
                        elif mode in ('authfail','cleanupfail'):
                            lines=['G3 SP_AUTH_FAILED status=2 timeout_ms=2000','G4 CLEANUP_PASS','G4 CE_RW_SESSION_FAILED version=1 phase=auth errno=10 old_removed=1 new_attempted=0 new_live=0 new_creator=333 cleanup_errno='+('0' if mode=='authfail' else '16')]
                        else:lines=modern_record()['status_lines']
                    elif op=='cleanup-rw':lines=['G4 CE_RW_CLEANUP_PASS version=1 creator=333 new_live=0']
                    elif op=='cleanup':lines=['G4 CLEANUP_PASS']
                    else:raise AssertionError(op)
                    return ('\n'.join(lines)+'\n').encode(),b''
            def physical_source(*args):
                fd=os.open('/dev/null',os.O_RDONLY);physical_fds.append(fd);return fd
            def spawn(argv,**kwargs):
                calls.append(list(argv))
                if argv[1]=='unlock-evox-password-user0-rw':
                    self.assertEqual(int(argv[5]),physical_fds[0])
                    self.assertNotEqual(argv[5],calls[0][3])
                    self.assertIn(physical_fds[0],kwargs['pass_fds'])
                    self.assertNotIn(int(calls[0][3]),kwargs['pass_fds'])
                elif argv[1]=='cleanup-rw':
                    self.assertEqual(int(argv[6]),physical_fds[0])
                    self.assertIn(physical_fds[0],kwargs['pass_fds'])
                return Process(argv)
            runtime=SimpleNamespace(backend=backend,common_lock_fd=71,spawn=spawn,getprop=lambda n:'2')
            def await_fd(*args):
                fd,write=os.pipe();os.close(write);slot[0]=fd;return 'rw'
            public=lambda *a,**k:None
            pins=hashlib.sha256(b'public native').hexdigest()
            result=None;failure=None
            try:
                with patch.dict(sys.modules,{'c_crypto_profile':SimpleNamespace(require_profile=lambda *a:{})}),patch.dict(os.environ,A22X_C_WD_DEADLINE=str(time.monotonic()+240)),patch.object(cb,'G4_SHA',pins),patch.object(cb,'EVO_NATIVE_SHA',pins),patch.object(cb,'current_framework_identity'),patch.object(cb,'pinned_rw_source',side_effect=physical_source),patch.object(wc,'require_zero_auth_calls'),patch.object(wc,'check_before_auth'),patch.object(wc,'awaiting_credential',side_effect=await_fd),patch.object(wc,'hold_evox'),patch.object(cb,'independent_media_proof',return_value=RW_MEDIA),patch.object(rw,'pinned_fd',side_effect=lambda *a,**k:os.open('/dev/null',os.O_RDONLY)),patch.object(cb,'park_for_reset',side_effect=Parked):
                    consumer=cb.make_consumer(RUN,slot,errors,public,progress,rw_capability=CAP,preparation_mode=preparation_mode)
                    try:result=consumer(runtime)
                    except (RuntimeError,Parked) as e:failure=e
            finally:
                if slot[0]>=0:os.close(slot[0])
                for fd in physical_fds:
                    with self.assertRaises(OSError):os.fstat(fd)
        return result,calls,errors,progress,failure
    def test_single_modern_auth_success_and_ordered_cleanup_once(self):
        result,calls,errors,progress,failure=self.exercise()
        self.assertIsNone(failure);self.assertTrue(result['success']);self.assertEqual(errors,[])
        auth=[a for a in calls if a[1]=='unlock-evox-password-user0-rw'];self.assertEqual(len(auth),1);self.assertEqual(len(auth[0]),14)
        self.assertEqual([a[1] for a in calls[-2:]],['cleanup-rw','cleanup']);self.assertEqual(progress,dict(password_submissions=1,unlock_dispatches=1))
    def test_typed_auth_failure_no_second_auth_cleanup_once(self):
        result,calls,errors,progress,failure=self.exercise('authfail')
        self.assertIsNone(failure);self.assertFalse(result['success']);self.assertEqual(errors,[])
        self.assertEqual([a[1] for a in calls[-2:]],['cleanup-rw','cleanup']);self.assertEqual(progress['unlock_dispatches'],1)
    def test_cleanup_failure_never_replays_new_or_old(self):
        result,calls,errors,progress,failure=self.exercise('cleanupfail')
        self.assertIsNotNone(failure);self.assertFalse(any(a[1] in ('cleanup','cleanup-rw') for a in calls))
        self.assertIn({'stage':'ce_rw_quarantined_cleanup_not_replayed'},errors)
    def test_unknown_native_output_parks_without_cleanup_replay(self):
        result,calls,errors,progress,failure=self.exercise('unknown')
        self.assertIsNotNone(failure);self.assertFalse(any(a[1] in ('cleanup','cleanup-rw') for a in calls))
    def test_requested_rw_none_stops_after_discovery_with_zero_auth_normal_cleanup(self):
        result,calls,errors,progress,failure=self.exercise('none',preparation_mode='rw')
        self.assertIsNone(failure);self.assertEqual(errors,[])
        self.assertFalse(result['success']);self.assertEqual(result['error_code'],'WRITE_NOT_QUALIFIED')
        self.assertEqual(progress,dict(password_submissions=0,unlock_dispatches=0))
        self.assertEqual([a[1] for a in calls],['unwrap-mount','unlock-de-user0','discover-evox-user0','cleanup'])

class PhysicalSourcePins(unittest.TestCase):
    def exercise(self, bad=None, sectors=120000000):
        import fcntl
        import stat
        import struct
        from android_profiles import EVO_PROFILE
        boot='fresh-observed-boot';cid='12'*16
        item=dict(node='/dev/mmcblk0p54',device='179:54',sectors=sectors)
        name='a22x-c-'+RUN+'-userdata'
        table=[(0,sectors,'linear','179:54 0')]
        owned=SimpleNamespace(admitted=True,run=RUN,boot=boot,
            c=dict(boot_id=boot,profile_id=EVO_PROFILE,device_cid=cid),
            layout=dict(boot_id=boot,evidence='RECORDED_READ_ONLY_OBSERVATION',physical={'userdata':item}))
        mapping=dict(name=name,partition='userdata',read_only=True,table=table)
        plan=dict(run_id=RUN,mappings=[mapping])
        status=[copy.deepcopy(table),True]
        backend=SimpleNamespace(native_policy=owned,plan=plan,dm=SimpleNamespace(status=lambda requested:status))
        runtime=SimpleNamespace(backend=backend)
        paths={'/proc/sys/kernel/random/boot_id':boot,
               '/sys/class/block/mmcblk0/device/cid':cid,
               '/sys/dev/block/179:54/uevent':'PARTNAME=userdata\nDEVNAME=mmcblk0p54\n',
               '/sys/dev/block/179:54/size':str(sectors)}
        if bad=='run':owned.run='another_run'
        elif bad=='boot':owned.layout['boot_id']='old-boot'
        elif bad=='cid':owned.c['device_cid']='34'*16
        elif bad=='node':item['node']='/dev/dm-7'
        elif bad=='name':mapping['name']='a22x-c-another-userdata'
        elif bad=='plan-truncated':mapping['table']=[(0,sectors&~7,'linear','179:54 0')]
        elif bad=='readback-truncated':status[0]=[(0,sectors&~7,'linear','179:54 0')]
        elif bad=='plan-offset':mapping['table']=[(0,sectors,'linear','179:54 8')]
        elif bad=='readback-offset':status[0]=[(0,sectors,'linear','179:54 8')]
        elif bad=='readback-rw':status[1]=False
        elif bad=='partition':paths['/sys/dev/block/179:54/uevent']='PARTNAME=metadata\nDEVNAME=mmcblk0p54\n'
        elif bad=='sys-size':paths['/sys/dev/block/179:54/size']=str(sectors-8)
        st=SimpleNamespace(st_mode=(stat.S_IFREG if bad=='regular' else stat.S_IFBLK)|0o400,
            st_rdev=os.makedev(179,55 if bad=='physical-dev' else 54))
        cid_reads=[0]
        def read_text(path,*args,**kwargs):
            key=str(path)
            if key=='/sys/class/block/mmcblk0/device/cid':
                cid_reads[0]+=1
                if bad=='late-cid' and cid_reads[0]>1:return '34'*16
            self.assertIn(key,paths)
            return paths[key]
        def ioctl(fd,command,buffer,mutate):
            self.assertEqual(fd,88);self.assertIs(mutate,True)
            if command==0x80081272:struct.pack_into('=Q',buffer,0,(sectors-(8 if bad=='fd-size' else 0))*512)
            elif command==0x125e:struct.pack_into('=I',buffer,0,1 if bad=='physical-ro' else 0)
            else:self.fail('Unexpected physical source ioctl')
        with patch.object(Path,'read_text',read_text),patch.object(cb.os,'open',return_value=88) as opened,patch.object(cb.os,'fstat',return_value=st),patch.object(cb.os,'close') as closed,patch.object(fcntl,'fcntl',return_value=os.O_RDWR if bad=='fd-rw' else os.O_RDONLY),patch.object(fcntl,'ioctl',side_effect=ioctl):
            if bad:
                with self.assertRaises(RuntimeError):cb.pinned_rw_source(runtime,RUN)
                self.assertEqual(closed.call_count,opened.call_count)
                if opened.call_count:closed.assert_called_once_with(88)
            else:
                self.assertEqual(cb.pinned_rw_source(runtime,RUN),88)
                opened.assert_called_once_with('/dev/mmcblk0p54',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                closed.assert_not_called() # returned FD ownership belongs to callback
        return opened.call_count

    def test_exact_run_cid_geometry_plan_and_physical_fd_ownership(self):
        self.exercise()

    def test_exact_physical_tail7_keeps_full_g1_plan_and_size(self):
        self.exercise(sectors=104292319)
        self.exercise(bad='plan-truncated',sectors=104292319)
        self.exercise(bad='readback-truncated',sectors=104292319)
        self.exercise(bad='fd-size',sectors=104292319)
        self.exercise(bad='too-small',sectors=7)

    def test_wrong_identity_topology_or_readonly_never_admitted(self):
        for bad in ('run','boot','cid','node','name','plan-offset','readback-offset','readback-rw',
                    'partition','sys-size','regular','physical-dev','fd-size','physical-ro','fd-rw','late-cid'):
            with self.subTest(bad=bad):self.exercise(bad)


if __name__=='__main__':unittest.main(verbosity=2)
