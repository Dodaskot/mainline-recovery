"""Real FD/socket/OFD tests plus injected mount and deadline transitions."""
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import decrypt_session as session
from decrypt_runtime import common, mounts
from decrypt_runtime.common import SessionError
from android_profiles import ROOT_MANIFEST_SHA

BOOT = '00000000-0000-0000-0000-000000000001'
CONFIG = dict(boot_id=BOOT, run_id='sessiontest123', mountpoint='/mnt/volumes/userdata',
              volume_token='physical-original', read_only=True, profile_id='samsung-a226b-a13',
              android_user_id=0, native_efs_policy={},
              root_manifest_sha256=ROOT_MANIFEST_SHA)

class FakeMounts:
    def __init__(self):
        self.bound = False
        self.busy = False
    def bind(self, pid, ticks, run_id, target, tree_fd=None, proof=None):
        self.bound = True
        return dict(mountpoint=target, mount_id=17, device='253:7')
    def unmount(self, target):
        if self.busy:
            raise OSError(errno.EBUSY, 'busy')
        self.bound = False

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.clock = [100.0]
        self.mounts = FakeMounts()
        self.commits, self.sent, self.actions = [], [], []
        self.proof = True
        self.life = session.SessionLifecycle(CONFIG, mounts=self.mounts,
            commit=self.commits.append, send_worker=lambda v, f: self.sent.append((v, f)),
            release_lease=lambda: self.actions.append('released'),
            cleanup_check=lambda: self.proof, disarm=lambda: self.actions.append('disarmed'),
            now=lambda: self.clock[0])

    def mounted(self):
        self.life.authenticated(os.getpid(), common.starttime(os.getpid()))
        self.assertEqual(self.actions, [])
        self.assertEqual(self.life.state, 'binding')
        self.life.held()

    def test_authenticated_receipt_requires_held_before_close(self):
        self.mounted()
        self.assertEqual(self.actions, ['released'])
        self.assertTrue(self.commits[-1]['ce_authenticated'])
        self.assertEqual(self.sent[-1][0], {'op': 'hold'})
        self.assertEqual(self.life.deadline, 105.0)

    def test_wrong_password_never_mounts_or_unlocks(self):
        self.life.complete(1, {'cleanup_verified': True, 'verdict': {'success': False}})
        self.assertFalse(self.mounts.bound)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.actions, ['disarmed'])
        self.assertFalse(self.commits[-1]['ce_authenticated'])

    def test_no_success_without_cleanup_proof(self):
        for proof in (False, None):
            self.proof = proof
            with self.assertRaises(SessionError):
                self.life.complete(0, {'cleanup_verified': True, 'success': True})
            self.assertNotIn('disarmed', self.actions)
        with self.assertRaises(SessionError):
            self.life.complete(0, None)

    def test_ebusy_keeps_session_and_lease_handoff_absent(self):
        self.mounted()
        self.mounts.busy = True
        before = list(self.sent)
        with self.assertRaises(SessionError) as error:
            self.life.request_unmount(77)
        self.assertEqual(error.exception.code, 'VOLUME_BUSY')
        self.assertTrue(error.exception.details['session_preserved'])
        self.assertFalse(error.exception.details['reboot_required'])
        self.assertTrue(self.mounts.bound)
        self.assertEqual(self.life.state, 'mounted')
        self.assertEqual(self.sent, before)

    def test_normal_unmount_hands_fresh_fd_then_proves_cleanup(self):
        self.mounted()
        self.life.request_unmount(77)
        self.assertFalse(self.mounts.bound)
        self.assertEqual(self.sent[-1], ({'op': 'unmount'}, 77))
        self.assertEqual(self.life.deadline, 145)
        self.life.complete(0, {'cleanup_verified': True, 'success': True})
        self.assertEqual(self.actions, ['released', 'disarmed'])
        self.assertTrue(self.commits[-1]['reboot_required'])

    def test_terminal_retry_delay_is_preserved_after_cleanup(self):
        self.life.complete(1, {'cleanup_verified': True,
            'verdict': {'success': False, 'native_auth_status': 2, 'native_timeout_ms': 1001}})
        self.assertEqual(self.commits[-1]['retry_after_seconds'], 2)
        self.assertEqual(self.commits[-1]['error_code'], 'RETRY_LATER')
        self.assertEqual(self.commits[-1]['state'], 'failed')

    def test_failed_terminal_native_verdict_does_not_ack_success(self):
        self.mounted()
        self.life.request_unmount(77)
        result = self.life.complete(1, {'cleanup_verified': True, 'success': False})
        self.assertFalse(result['ok'])
        self.assertEqual(result['error']['code'], 'DECRYPT_FAILED')
        self.assertEqual(self.commits[-1]['state'], 'failed')
        self.assertEqual(self.actions, ['released', 'disarmed'])

    def test_cancel_keeps_auth_deadline_bounded_and_no_bind(self):
        self.clock[0] = 150
        self.life.cancel_auth()
        self.assertEqual(self.life.deadline, 195)
        self.life.authenticated(os.getpid(), common.starttime(os.getpid()))
        self.assertFalse(self.mounts.bound)
        self.assertEqual(self.sent[-1][0], {'op': 'cancel'})
        self.life.complete(0, {'cleanup_verified': True, 'success': True})
        self.assertNotIn('released', self.actions)

    def test_only_pong_extends_held_deadline(self):
        self.mounted()
        self.clock[0] = 104
        self.life.pong()
        self.assertEqual(self.life.deadline, 109)
        self.life.request_unmount(55)
        cleanup_deadline = self.life.deadline
        self.clock[0] += 10
        with self.assertRaises(SessionError): self.life.pong()
        self.assertEqual(self.life.deadline, cleanup_deadline)

    def test_cannot_complete_while_bound_or_reauthenticate(self):
        self.mounted()
        with self.assertRaises(SessionError):
            self.life.complete(0, {'cleanup_verified': True, 'success': True})
        with self.assertRaises(SessionError):
            self.life.authenticated(os.getpid(), common.starttime(os.getpid()))

class ActualDescriptorTests(unittest.TestCase):
    def test_ready_reader_close_is_observed_without_payload_read(self):
        reader, writer = os.pipe()
        try:
            self.assertFalse(session.reader_gone(writer))
            os.close(reader); reader = None
            self.assertTrue(session.reader_gone(writer))
            with self.assertRaises(BrokenPipeError):
                session.ready(writer, {'ok': False})
            with self.assertRaises(OSError): os.fstat(writer)
            writer = None
        finally:
            if reader is not None: os.close(reader)
            if writer is not None: os.close(writer)

    def test_pre_auth_cancel_consumes_only_control_socket(self):
        from decrypt_runtime import worker_control
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            with patch.object(worker_control, '_control', right):
                worker_control.check_before_auth()
                common.packet(left, {'op': 'cancel'})
                with self.assertRaises(SessionError):
                    worker_control.check_before_auth()
        finally:
            left.close(); right.close()

    def test_credential_pipe_is_validated_without_read(self):
        r, w = os.pipe()
        high = fcntl.fcntl(r, fcntl.F_DUPFD_CLOEXEC, 64)
        os.close(r)
        try:
            # Patch read to prove descriptor admission never consumes payload.
            with patch.object(common.os, 'read', side_effect=AssertionError('payload read')):
                common.credential_fd(high)
            os.write(w, b'\x03\x00\x00\x00abc')
            self.assertEqual(os.read(high, 7), b'\x03\x00\x00\x00abc')
            with self.assertRaises(SessionError): common.credential_fd(w)
        finally:
            os.close(high); os.close(w)

    def test_fd_handoff_preserves_external_parent_lease_without_unlock(self):
        from decrypt_runtime.worker_control import reserve_descriptor, adopt_lease
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lock'
            parent_fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            supervisor_fd = os.dup(parent_fd)
            worker_fd = os.dup(parent_fd)
            replacement = contender = received = None
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                common.validate_lease(parent_fd, str(path))
                # Hold ACK: worker closes OFD by reserving descriptor number;
                # supervisor closes its OFD. Neither may unlock parent's OFD.
                reserve_descriptor(worker_fd)
                os.close(supervisor_fd); supervisor_fd = None
                contender = os.open(path, os.O_RDWR)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.close(parent_fd); parent_fd = None
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.close(contender); contender = None
                replacement = os.open(path, os.O_RDWR)
                common.validate_lease(replacement, str(path))
                common.packet(left, {'op': 'unmount'}, replacement)
                value, received = common.receive(right, True)
                common.validate_lease(received, str(path))
                adopt_lease(received, worker_fd)
                os.close(received); received = None
                # Same-FD adoption is a no-op and must leave descriptor open.
                adopt_lease(worker_fd, worker_fd)
                common.validate_lease(worker_fd, str(path))
                os.close(replacement); replacement = None
                contender = os.open(path, os.O_RDWR)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                duplicate = os.dup(worker_fd); os.close(duplicate)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.close(worker_fd); worker_fd = None
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                for fd in (parent_fd, supervisor_fd, worker_fd, replacement, contender, received):
                    if fd is not None: os.close(fd)
                left.close(); right.close()

    def test_lease_rejects_foreign_inode_hardlink_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lock'
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            other = os.open(Path(directory) / 'other', os.O_RDWR | os.O_CREAT, 0o600)
            try:
                with self.assertRaises(SessionError): common.validate_lease(other, str(path))
                os.link(path, Path(directory) / 'hard')
                with self.assertRaises(SessionError): common.validate_lease(fd, str(path))
                os.unlink(Path(directory) / 'hard')
                Path(directory, 'link').symlink_to(path)
                with self.assertRaises(SessionError):
                    common.validate_lease(fd, str(Path(directory) / 'link'))
            finally:
                os.close(fd); os.close(other)

    def test_wire_rejects_multiple_fds_and_truncated_message(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        fd = os.open('/dev/null', os.O_RDONLY)
        try:
            import array
            left.sendmsg([b'{}'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd, fd]))])
            with self.assertRaises(SessionError): common.receive(right, True)
            left.send(b'x' * (common.MAX_PACKET + 1))
            with self.assertRaises(SessionError): common.receive(right)
        finally:
            os.close(fd); left.close(); right.close()

    def test_secure_directory_and_atomic_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'state'; target.mkdir(mode=0o700)
            fd = common.secure_directory(str(target), uid=os.getuid())
            try:
                common.atomic_json(fd, 'session.json', {'state': 'closed'})
                self.assertEqual(common.read_json_at(fd, 'session.json', uid=os.getuid()), {'state': 'closed'})
                os.chmod(target / 'session.json', 0o644)
                with self.assertRaises(SessionError):
                    common.read_json_at(fd, 'session.json', uid=os.getuid())
            finally: os.close(fd)
            target.chmod(0o755)
            with self.assertRaises(SessionError): common.secure_directory(str(target), uid=os.getuid())
            link = Path(directory) / 'link'; link.symlink_to(target)
            with self.assertRaises(OSError): common.secure_directory(str(link), uid=os.getuid())

class GuardTests(unittest.TestCase):
    def test_rw_and_unsupported_user_rejected_before_auth(self):
        for change in ({'read_only': False}, {'android_user_id': 1}, {'profile_id': 'other'},
                       {'native_efs_policy': None}):
            with self.assertRaises(SessionError) as error:
                common.validate_config(dict(CONFIG, **change), BOOT)
            self.assertEqual(error.exception.code, 'UNSUPPORTED_PROFILE')

    def test_wrong_native_status_is_not_blindly_wrong_password(self):
        unknown = {'success': False, 'native_auth_status': 99, 'native_timeout_ms': 0,
                   'failure_stage': 'protector'}
        self.assertEqual(common.public_failure(unknown).code, 'DECRYPT_FAILED')
        self.assertEqual(common.public_failure(dict(unknown, native_auth_status=1)).code,
                         'DECRYPT_FAILED')
        limited = common.public_failure(dict(unknown, native_auth_status=2, native_timeout_ms=1001))
        self.assertEqual(limited.code, 'RETRY_LATER')
        self.assertEqual(limited.details['retry_after_seconds'], 2)

    def receipt(self):
        return dict(schema=common.SCHEMA, state='mounted', boot_id=BOOT, read_only=True,
                    ce_authenticated=True, fscrypt_policy_verified=True, native_efs_persistence=True,
                    profile_id='samsung-a226b-a13', credential_type='password', android_user_id=0,
                    supervisor_pid=100, supervisor_starttime=3, worker_pid=101, worker_starttime=4,
                    mountpoint='/mnt/volumes/userdata', mount_id=17, device='253:7',
                    physical_volume_token='physical-original')

    def test_stale_boot_pid_state_and_physical_token_are_rejected(self):
        receipt = self.receipt()
        session.validate_state(receipt, boot_id=BOOT, process_check=lambda p,t: True,
                               mount_check=lambda r: True)
        for change in ({'boot_id': 'other'}, {'state': 'closed'}, {'read_only': False},
                       {'ce_authenticated': False}):
            with self.assertRaises(SessionError):
                session.validate_state(dict(receipt, **change), boot_id=BOOT,
                                       process_check=lambda p,t: True, mount_check=lambda r: True)
        with self.assertRaises(SessionError):
            session.validate_state(receipt, boot_id=BOOT, process_check=lambda p,t: False,
                                   mount_check=lambda r: True)
        with self.assertRaises(SessionError):
            session.validate_state(receipt, boot_id=BOOT, volume_token='replaced',
                                   process_check=lambda p,t: True, mount_check=lambda r: True)

    def test_mountinfo_requires_exact_root_device_id_and_readonly_flags(self):
        line = '17 1 253:7 / /mnt/volumes/userdata ro,nosuid,nodev,noexec - f2fs /dev/dm-7 ro\n'
        mounts.verify_mount(self.receipt(), line)
        for invalid in (line.replace('ro,nosuid,nodev', 'rw,nosuid,nodev'),
                        line.replace('253:7', '253:8'), line.replace('17 1', '18 1'),
                        line.replace(' / /mnt/', ' /subdir /mnt/'),
                        line.replace('ro,nosuid,nodev', 'ro,nodev')):
            with self.assertRaises(SessionError): mounts.verify_mount(self.receipt(), invalid)

    def test_proc_starttime_detects_stale_process(self):
        ticks = common.starttime(os.getpid())
        self.assertTrue(common.same_process(os.getpid(), ticks))
        self.assertFalse(common.same_process(os.getpid(), ticks + 1))
        self.assertFalse(common.same_process(999999999, 1))


def service_runtime_fixture():
    """All eight daemons, interspersed with completed original one-shot helpers."""
    from types import SimpleNamespace
    from decrypt_runtime.worker_control import SERVICE_PROFILES
    processes, events, checked = [], [], []
    for index, (argv, uid, context) in enumerate(SERVICE_PROFILES):
        process = SimpleNamespace(args=list(argv), pid=1000 + index, returncode=None)
        process.poll = lambda p=process: p.returncode
        processes.append(process)
        events.append(dict(event='spawn', executable=argv[0], pid=process.pid, uid=uid,
                           context=context, context_verified=True))
        one_shot = SimpleNamespace(args=['/system/bin/a22x-property-service', '--get',
                                        'ro.property_service.version'],
                                   pid=2000 + index, returncode=0)
        one_shot.poll = lambda p=one_shot: p.returncode
        processes.append(one_shot)
        events.append(dict(event='spawn', executable=one_shot.args[0], pid=one_shot.pid,
                           uid=0, context='u:r:recovery:s0', context_verified=True))
    def assert_alive(process):
        checked.append(process.pid)
        common.require(process.poll() is None, message='Required daemon exited')
    return SimpleNamespace(processes=processes, events=events, checked=checked,
                           assert_alive=assert_alive)

class ServiceLifetimeTests(unittest.TestCase):
    def test_completed_one_shots_are_ignored_but_all_eight_services_checked(self):
        from decrypt_runtime.worker_control import required_services, assert_services_alive
        runtime = service_runtime_fixture()
        services = required_services(runtime)
        self.assertEqual(len(services), 8)
        assert_services_alive(runtime, services)
        self.assertEqual(runtime.checked, list(range(1000, 1008)))
        self.assertTrue(all(p.poll() is None for p in services))

    def test_each_required_daemon_exit_is_refused_initially_and_on_heartbeat(self):
        from decrypt_runtime.worker_control import required_services, assert_services_alive
        for index in range(8):
            for code in (0, 1, -15):
                with self.subTest(daemon=index, returncode=code):
                    runtime = service_runtime_fixture()
                    held_services = required_services(runtime)
                    held_services[index].returncode = code
                    # Both initial admission and the already selected held tuple
                    # must keep the daemon required even after it has exited.
                    with self.assertRaises(SessionError):
                        assert_services_alive(runtime, required_services(runtime))
                    with self.assertRaises(SessionError):
                        assert_services_alive(runtime, held_services)

    def test_missing_and_duplicate_service_are_refused(self):
        from decrypt_runtime.worker_control import required_services
        for index in range(8):
            with self.subTest(daemon=index):
                runtime = service_runtime_fixture()
                daemon = runtime.processes[index * 2]
                runtime.processes.remove(daemon)
                with self.assertRaises(SessionError): required_services(runtime)
                runtime.processes.append(daemon)
                runtime.processes.append(daemon)
                with self.assertRaises(SessionError): required_services(runtime)

    def test_exact_argv_uid_context_verified_spawn_are_required(self):
        from decrypt_runtime.worker_control import required_services
        for index in range(8):
            for field, replacement in [('executable', '/wrong/service'), ('uid', 1234),
                                       ('context', 'u:r:wrong:s0'), ('context_verified', False)]:
                with self.subTest(daemon=index, field=field):
                    runtime = service_runtime_fixture()
                    runtime.events[index * 2][field] = replacement
                    with self.assertRaises(SessionError): required_services(runtime)
            runtime = service_runtime_fixture()
            runtime.processes[index * 2].args.append('--unqualified')
            with self.assertRaises(SessionError): required_services(runtime)

    def test_property_serve_must_be_first_and_evidence_must_be_unique(self):
        from decrypt_runtime.worker_control import required_services
        runtime = service_runtime_fixture()
        runtime.processes[0], runtime.processes[1] = runtime.processes[1], runtime.processes[0]
        with self.assertRaises(SessionError): required_services(runtime)
        runtime = service_runtime_fixture()
        runtime.events.append(dict(runtime.events[0]))
        with self.assertRaises(SessionError): required_services(runtime)

class WorkerHoldTests(unittest.TestCase):
    def test_actual_hold_socket_replaces_original_ofd_then_adopts_cleanup_fd(self):
        import threading
        from types import SimpleNamespace
        from decrypt_runtime import worker_control
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lock'
            lease_parent = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            worker_fd = os.dup(lease_parent)
            fresh = None
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            left.settimeout(2); right.settimeout(2)
            calls = [{'kind': 'CALL', 'cmd': 126, 'result': 0, 'ta_present': 1,
                      'ta_bound': 'QUALIFIED', 'ta_status': 0}] * 2
            parser = SimpleNamespace(records=[{'kind': 'READY'}] + calls, error=None,
                                     ready=True, eof=False, pending=b'')
            services = service_runtime_fixture()
            runtime = SimpleNamespace(common_lock_fd=worker_fd,
                                      processes=services.processes, events=services.events,
                                      assert_alive=services.assert_alive,
                                      backend=SimpleNamespace(at=lambda p: '/fake'),
                                      gatekeeper_diagnostic=SimpleNamespace(drain=lambda: None, parser=parser))
            errors = []
            def held_worker():
                try:
                    worker_control.hold(runtime, {'success': True}, [],
                        {'cleanup_verified': True, 'status': 'SCALAR_TRACE_COMPLETE'})
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=held_worker, daemon=True)
            try:
                common.validate_lease(lease_parent, str(path))
                with patch.object(worker_control, '_control', right), patch.object(
                        worker_control, 'validate_lease', lambda fd: common.validate_lease(fd, str(path))), patch.object(
                        worker_control, 'export_tree', lambda p: (os.open('/', os.O_PATH | os.O_CLOEXEC), {'fixture': True})):
                    thread.start()
                    value, fd = common.receive(left, True)
                    self.assertEqual(value, {'event': 'authenticated', 'mount_transfer': {'fixture': True}, 'requested_mode':'ro'})
                    self.assertIsNotNone(fd)
                    os.close(fd)
                    common.packet(left, {'op': 'hold'})
                    value, fd = common.receive(left)
                    self.assertEqual(value, {'event': 'held'})
                    common.packet(left, {'op': 'ping', 'serial': 1})
                    value, fd = common.receive(left)
                    self.assertEqual(value, {'event': 'pong', 'serial': 1})
                    self.assertEqual(services.checked, list(range(1000, 1008)) * 2)
                    self.assertEqual(os.readlink('/proc/self/fd/' + str(worker_fd)), '/dev/null')
                    contender = os.open(path, os.O_RDWR)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(contender)
                    os.close(lease_parent); lease_parent = None
                    fresh = os.open(path, os.O_RDWR)
                    common.validate_lease(fresh, str(path))
                    common.packet(left, {'op': 'unmount'}, fresh)
                    value, fd = common.receive(left)
                    self.assertEqual(value, {'event': 'cleaning'})
                    thread.join(2)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(errors, [])
                    self.assertEqual(os.fstat(worker_fd).st_ino, os.stat(path).st_ino)
            finally:
                left.close(); right.close()
                for fd in (lease_parent, worker_fd, fresh):
                    if fd is not None: os.close(fd)

if __name__ == '__main__': unittest.main()
