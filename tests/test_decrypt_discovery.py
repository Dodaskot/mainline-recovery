"""Two-phase native lifecycle: real anonymous FDs and SCM_RIGHTS; no device I/O."""
import errno
import fcntl
from contextlib import nullcontext
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import android_decrypt as ad
import decrypt_session as session
from decrypt_runtime import common, worker_control as wc, ro_auth_callback_session as callback
import filesystem as fs
from tests.test_decrypt_session import CONFIG, BOOT, FakeMounts, service_runtime_fixture

SOURCE = {'mount_id': 88, 'device': '253:7', 'root': '/', 'root_inode': 3,
          'fstype': 'f2fs', 'read_only': True, 'namespace': 'mnt:[31415]'}

class DiscoveryLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.clock = [100.]
        self.sent, self.commits, self.actions = [], [], []
        self.mounts = FakeMounts()
        self.life = session.SessionLifecycle(CONFIG, mounts=self.mounts,
            commit=self.commits.append, send_worker=lambda v,f: self.sent.append((v,f)),
            release_lease=lambda: self.actions.append('closed'),
            cleanup_check=lambda: True, disarm=lambda: self.actions.append('disarmed'),
            now=lambda: self.clock[0])
    def prepared(self, kind='pattern'):
        self.life.prepared(os.getpid(), common.starttime(os.getpid()), kind, SOURCE)
        self.life.prepared_held()
        return self.life.receipt
    def request(self, op='authenticate'):
        return {'op': op, 'boot_id': CONFIG['boot_id'], 'run_id': CONFIG['run_id'],
                'volume_token': self.life.receipt['volume_token'],
                'credential_type': self.life.credential_type,
                **({'requested_mode':'ro','write_confirmed':False} if op=='authenticate' else {})}
    def test_prepare_auth_mount_has_two_distinct_close_only_handoffs(self):
        receipt = self.prepared()
        self.assertEqual(self.actions, ['closed'])
        self.assertFalse(self.mounts.bound)
        self.assertFalse(receipt['ce_authenticated'])
        self.assertFalse(self.life.auth_started)
        self.life.start_auth(self.request(), 71, 91)
        self.assertEqual(self.sent[-1][1], (71,91))
        self.assertEqual(self.life.deadline, 340)
        self.life.authenticated(os.getpid(), common.starttime(os.getpid()))
        self.life.held()
        self.assertTrue(self.mounts.bound)
        self.assertEqual(self.actions, ['closed','closed'])
    def test_stale_token_type_boot_run_rejected_before_worker_dispatch(self):
        self.prepared()
        for key, bad in [('volume_token','old'), ('credential_type','password'),
                         ('boot_id','old'), ('run_id','other')]:
            request = self.request(); request[key] = bad
            before = list(self.sent)
            with self.assertRaises(common.SessionError): self.life.start_auth(request,71,91)
            self.assertEqual(self.sent,before)
            self.assertFalse(self.life.auth_started)
    def test_pending_cannot_authorize_ce_mount_or_accept_second_auth(self):
        receipt = self.prepared()
        with self.assertRaises(common.SessionError):
            session.validate_state(receipt,boot_id=BOOT,process_check=lambda p,t:True,
                                   mount_check=lambda r: self.fail('pending authorized Files'))
        self.life.start_auth(self.request(),71,91)
        with self.assertRaises(common.SessionError): self.life.start_auth(self.request(),71,91)
    def test_pending_receipt_rechecks_identity_source_expiry_and_token(self):
        receipt = self.prepared()
        verify = dict(boot_id=BOOT,process_check=lambda p,t:True,
                      source_check=lambda p,r: SOURCE,now=lambda:100)
        session.validate_prepared(receipt,**verify)
        for key,bad in [('worker_starttime',0),('physical_volume_token','changed'),
                        ('credential_type','password')]:
            changed=dict(receipt,**{key:bad})
            with self.assertRaises(common.SessionError):session.validate_prepared(changed,**verify)
        with self.assertRaises(common.SessionError):
            session.validate_prepared(receipt,**dict(verify,process_check=lambda p,t:False))
        with self.assertRaises(common.SessionError):
            session.validate_prepared(receipt,**dict(verify,source_check=lambda p,r:dict(SOURCE,mount_id=89)))
        with self.assertRaises(common.SessionError):
            session.validate_prepared(receipt,**dict(verify,now=lambda:401))
    def test_cancel_and_expiry_cleanup_without_auth(self):
        for expired in (False,True):
            self.setUp(); self.prepared()
            if expired:self.clock[0]=401
            self.life.cancel_prepared(71)
            self.assertEqual(self.sent[-1],({'op':'cancel_prepared','credential_type':'pattern'},71))
            self.assertFalse(self.life.auth_started)
            result=self.life.complete(1,{'cleanup_verified':True,'success':False})
            self.assertTrue(result['ok'])
            self.assertTrue(self.commits[-1]['reboot_required'])
            self.assertFalse(self.mounts.bound)
    def test_discovery_dispatch_has_no_credential_fd_or_secret_argument(self):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        try:
            with patch.object(session.subprocess,'Popen') as popen:
                session.dispatch('/public/config',CONFIG,None,71,right,340,'/public/cleanup',True)
            args,kwargs=popen.call_args
            self.assertIn('--discover',args[0])
            self.assertNotIn('--credential-fd',args[0])
            self.assertEqual(kwargs['pass_fds'],(71,right.fileno()))
        finally:left.close();right.close()

class CancelProofTests(unittest.TestCase):
    def test_pre_auth_cancel_ack_is_success_only_after_cleanup_proof(self):
        life = session.SessionLifecycle(CONFIG, mounts=FakeMounts(), commit=lambda r:None,
            send_worker=lambda v,f:None, release_lease=lambda:None,
            cleanup_check=lambda:True, disarm=lambda:None, now=lambda:100.)
        life.prepared(os.getpid(),common.starttime(os.getpid()),'pattern',SOURCE)
        life.prepared_held(); life.cancel_prepared(71)
        response=life.complete(1,{'cleanup_verified':True,'success':False})
        self.assertTrue(response['ok'])
        self.assertTrue(response['reboot_required'])
        self.assertFalse(life.auth_started)

    def test_cancel_failure_never_disarms_or_returns_success(self):
        actions=[]
        life=session.SessionLifecycle(CONFIG,mounts=FakeMounts(),commit=lambda r:None,
            send_worker=lambda v,f:None,release_lease=lambda:None,
            cleanup_check=lambda:False,disarm=lambda:actions.append('disarmed'),now=lambda:100.)
        life.prepared(os.getpid(),common.starttime(os.getpid()),'pattern',SOURCE)
        life.prepared_held();life.cancel_prepared(71)
        with self.assertRaises(common.SessionError):
            life.complete(1,{'cleanup_verified':True,'success':False})
        self.assertEqual(actions,[])

class DiscoveryWireTests(unittest.TestCase):
    def exercise(self, kind, cancel=False):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'lock'
            parent=os.open(path,os.O_RDWR|os.O_CREAT,0o600)
            worker_fd=os.dup(parent); fresh=reader=writer=credential=None
            left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            left.settimeout(2);right.settimeout(2)
            services=service_runtime_fixture()
            parser=SimpleNamespace(error=None,ready=True,eof=False,pending=b'',
                records=[{'kind':'READY','version':2}])
            runtime=SimpleNamespace(common_lock_fd=worker_fd,processes=services.processes,
                events=services.events,assert_alive=services.assert_alive,
                gatekeeper_diagnostic=SimpleNamespace(drain=lambda:None,parser=parser))
            slot=[-1];errors=[];done=[]
            def worker():
                try:
                    wc.awaiting_credential(runtime,slot,kind);done.append(True)
                except BaseException as error:errors.append(error)
            thread=threading.Thread(target=worker,daemon=True)
            try:
                common.validate_lease(parent,str(path))
                with patch.object(wc,'_discovery',True),patch.object(wc,'_control',right), \
                     patch.object(wc,'source_identity',return_value=SOURCE), \
                     patch.object(wc,'validate_lease',lambda fd:common.validate_lease(fd,str(path))), \
                     patch.object(common.os,'read',side_effect=AssertionError('Python consumed secret')):
                    thread.start()
                    value,fd=common.receive(left)
                    self.assertEqual(value['event'],'prepared')
                    self.assertEqual(value['credential_type'],kind)
                    self.assertEqual(parser.records,[{'kind':'READY','version':2}])
                    common.packet(left,{'op':'await'})
                    value,fd=common.receive(left)
                    self.assertEqual(value,{'event':'prepared_held'})
                    self.assertEqual(os.readlink('/proc/self/fd/'+str(worker_fd)),'/dev/null')
                    os.close(parent);parent=None
                    fresh=os.open(path,os.O_RDWR);common.validate_lease(fresh,str(path))
                    common.packet(left,{'op':'ping','serial':1})
                    self.assertEqual(common.receive(left)[0],{'event':'pong','serial':1})
                    if cancel:
                        common.packet(left,{'op':'cancel_prepared','credential_type':kind},fresh)
                        self.assertEqual(common.receive(left)[0],{'event':'cleaning'})
                    else:
                        reader,writer=os.pipe()
                        credential=fcntl.fcntl(reader,fcntl.F_DUPFD_CLOEXEC,64)
                        os.close(reader);reader=None
                        frame=b'A22C'+struct.pack('<II',1 if kind=='pattern' else 4,3)+b'159'
                        os.write(writer,frame);os.close(writer);writer=None
                        common.packet_fds(left,{'op':'authenticate','credential_type':kind,
                                                'deadline':time.monotonic()+240,'requested_mode':'ro','write_confirmed':False},(fresh,credential))
                        self.assertEqual(common.receive(left)[0],{'event':'auth_dispatching','requested_mode':'ro'})
                    thread.join(2);self.assertFalse(thread.is_alive())
                if cancel:
                    self.assertEqual(done,[])
                    self.assertEqual(len(errors),1)
                    self.assertEqual(errors[0].code,'CANCELLED')
                    self.assertEqual(slot,[-1])
                else:
                    self.assertEqual(errors,[]);self.assertEqual(done,[True])
                    self.assertGreaterEqual(slot[0],64)
                    self.assertEqual(os.read(slot[0],100),frame)
                common.validate_lease(worker_fd,str(path))
            finally:
                left.close();right.close()
                for fd in (parent,worker_fd,fresh,reader,writer,credential,slot[0] if slot[0]>=0 else None):
                    if fd is not None:os.close(fd)
    def test_pattern_fresh_lease_and_anonymous_pipe_scm_only(self):self.exercise('pattern')
    def test_password_fresh_lease_and_anonymous_pipe_scm_only(self):self.exercise('password')
    def test_cancel_fresh_lease_without_credential_or_gatekeeper_call(self):self.exercise('pattern',True)
    def test_legacy_direct_password_does_not_pause_or_dispatch_again(self):
        with patch.object(wc,'_discovery',False),patch.object(wc,'packet') as sent:
            wc.awaiting_credential(None,[77],'password')
            sent.assert_not_called()
            with self.assertRaises(common.SessionError):wc.awaiting_credential(None,[77],'pattern')

class NativePublicTypeTests(unittest.TestCase):
    def test_closed_native_type_line_and_duplicates_fail_closed(self):
        for kind in ('pattern','password'):
            line='G3 SP_PREPARE_CREDENTIAL type='+kind
            self.assertEqual(callback.classify((line+'\n').encode(),b'')['status_lines'],[line])
            self.assertEqual(callback.prepared_credential_type([line]),kind)
            with self.assertRaises(RuntimeError):callback.prepared_credential_type([line,line])
        with self.assertRaises(RuntimeError):callback.classify(b'G3 SP_PREPARE_CREDENTIAL type=pin\n',b'')
        with self.assertRaises(RuntimeError):callback.prepared_credential_type([])
        self.assertEqual(callback.prepared_credential_type([],required=False),'password')
    def test_both_pinned_public_jars_required_no_mismatch_auth(self):
        pins=['f4795ef0b1f3ebc45e44258b5d9324b52c3148e3ac3158fe02584862d3e9e055',
              '731db55aa1a0d3a97d28375296cdde04a9a8196028813b15e612c7f39be8e144']
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('services.jar','framework.jar'):
                target=root/'mnt/system_stock/system/framework'/name
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b'public fixture')
            runtime=SimpleNamespace(backend=SimpleNamespace(at=lambda p:root/p.lstrip('/')))
            for second in (pins[1],'0'*64):
                digests=[SimpleNamespace(update=lambda data:None,hexdigest=lambda pin=pin:pin)
                         for pin in (pins[0],second)]
                with patch('hashlib.sha256',side_effect=digests), \
                     patch.object(callback.os,'fstatvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)):
                    if second==pins[1]:callback.current_framework_identity(runtime,lambda *a,**k:None)
                    else:
                        with self.assertRaises(RuntimeError):
                            callback.current_framework_identity(runtime,lambda *a,**k:None)

class DiscoveryFrontendTests(unittest.TestCase):
    def test_inventory_unknown_before_preparation_pending_never_files(self):
        volume={'id':'userdata','volume_token':'physical','fs_type':None}
        context=SimpleNamespace(mode='device',boot_id='boot')
        with patch.object(ad,'profile',return_value={'profile_id':'samsung-a226b-a13'}), \
             patch.object(ad,'session_status',side_effect=RuntimeError), \
             patch.object(session,'prepared_status',side_effect=RuntimeError), \
             patch.object(ad,'terminal_status',return_value={}):
            result=ad.decorate(context,[dict(volume)])[0]
            self.assertEqual(result['credential_type'],'unknown')
            self.assertTrue(result['preparation_required'])
        pending={'credential_type':'pattern','volume_token':'live-token','run_id':'run'}
        with patch.object(ad,'profile',return_value={'profile_id':'samsung-a226b-a13'}), \
             patch.object(ad,'session_status',side_effect=RuntimeError), \
             patch.object(session,'prepared_status',return_value=pending):
            result=ad.decorate(context,[dict(volume)])[0]
            self.assertEqual(result['credential_type'],'pattern')
            self.assertFalse(result['mounted']);self.assertFalse(result['mountable'])
            self.assertFalse(result['ce_authenticated'])
            self.assertEqual(result['physical_volume_token'],'physical')
            self.assertEqual(result['volume_token'],'live-token')
    def test_prepare_and_cancel_cli_dispatch_under_device_lease(self):
        for command,method in [('prepare-android','prepare_android'),
                               ('cancel-android-unlock','cancel_android_unlock')]:
            args=fs.parser().parse_args(['--device',command,'--volume','userdata',
                                        '--expected-volume-token','a'*64,'--android-user','0'])
            volume={'id':'userdata'}
            context=SimpleNamespace(mode='device',operation_lock=lambda shared=False: nullcontext(),
                                    volume=lambda ident,expected:volume)
            with patch.object(ad,method,return_value={'routed':True}) as route:
                self.assertEqual(fs.dispatch(context,args),{'routed':True})
                route.assert_called_once_with(context,volume,0)

if __name__=='__main__':unittest.main()
