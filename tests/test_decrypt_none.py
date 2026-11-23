"""Host-only NONE proof/profile/retained lifecycle fixtures; no secure/device I/O."""
import copy
import errno
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from android_profiles import SAMSUNG_PROFILE, LEGACY_EVO_NONE_PROFILE as EVO_PROFILE, ROOT_MANIFEST_SHA
import decrypt_session as session
from decrypt_runtime import common, worker_control as wc
from decrypt_runtime import native_session_worker as native
from decrypt_runtime import ro_none_callback_session as none
from tests.test_decrypt_session import BOOT, CONFIG, FakeMounts, service_runtime_fixture

RUN = 'evnonetest123'
NONE_CONFIG = dict(CONFIG, profile_id=EVO_PROFILE, native_efs_policy=None,
                   state_dir=common.STATE_DIR, root_manifest_sha256=ROOT_MANIFEST_SHA)
INDEPENDENT = {'entries': 16, 'complete': True, 'filesystem_ro': True}


def operations(schema=2, cleanup=False):
    lines = [
        ['G4 MOUNT_RO_PASS dm=a22x-data-ro-' + RUN + ' raw_dm=a22x-data-ro-' + RUN
         + '-raw device=253:7 sectors=12345', 'G3 AUTHENTICATED_KEY_DELIVERED'],
        ['G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS'] * 2 + ['G4 DE_ONLY_UNLOCK_PASS ce_calls=0']
        + ['G3 AUTHENTICATED_KEY_DELIVERED'] * 2,
        ['G4 NONE_PREPARE_PASS secure_calls=0', 'G3 NONE_DATABASE_SCHEMA version=' + str(schema),
         none.NONE_READY],
        ['G4 NONE_KEY_RECEIVED_ONCE bytes=64', 'G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS',
         'G4 SP_MEDIA_USER0_READDIR_PASS entries=16 complete=1 fs_ro=1 dm_ro=1 alias_ro=1',
         'G3 NONE_DATABASE_SCHEMA version=' + str(schema), none.NONE_READY, none.NONE_DELIVERED],
    ]
    names = ['unwrap-mount', 'unlock-de-user0', 'prepare-none-user0', 'unlock-none-user0']
    if cleanup:
        names.append('cleanup'); lines.append(['G4 CLEANUP_PASS'])
    return [dict(operation=name, returncode=0, status_lines=value) for name, value in zip(names, lines)]


def none_runtime():
    runtime = service_runtime_fixture()
    gk = wc.SERVICE_PROFILES[-1][0][0]
    runtime.processes = [p for p in runtime.processes if p.args[0] != gk]
    runtime.events = [e for e in runtime.events if e['executable'] != gk]
    runtime.gatekeeper = runtime.gatekeeper_diagnostic = None
    return runtime


class NoneEvidenceTests(unittest.TestCase):
    def test_exact_schema1_and_schema2_native_proofs_authorize_ce(self):
        for schema in (1, 2):
            verdict = none.qualify_ce(operations(schema), RUN, INDEPENDENT)
            self.assertIs(verdict['success'], True)
            self.assertEqual(verdict['keystore_schema'], schema)
            self.assertEqual((verdict['authenticated_key_deliveries'], verdict['policy_matches']), (4, 3))
            self.assertEqual(verdict['gatekeeper_calls'], 0)

    def test_every_native_proof_is_required_before_hold(self):
        for index, record in enumerate(operations()):
            for line in range(len(record['status_lines'])):
                damaged = operations(); del damaged[index]['status_lines'][line]
                with self.subTest(operation=index, omitted=line), self.assertRaises(RuntimeError):
                    none.qualify_ce(damaged, RUN, INDEPENDENT)

    def test_schema_run_media_exit_and_order_mismatches_reject(self):
        cases = []
        bad = operations(); bad[3]['status_lines'][3] = 'G3 NONE_DATABASE_SCHEMA version=1'; cases.append(bad)
        bad = operations(); bad[0]['status_lines'][0] = bad[0]['status_lines'][0].replace(RUN, 'otherrun123'); cases.append(bad)
        bad = operations(); bad[3]['status_lines'][2] = bad[3]['status_lines'][2].replace('complete=1', 'complete=0'); cases.append(bad)
        bad = operations(); bad[3]['returncode'] = 70; cases.append(bad)
        bad = operations(); bad[0], bad[1] = bad[1], bad[0]; cases.append(bad)
        bad = operations(); bad[3]['status_lines'].append(none.NONE_DELIVERED); cases.append(bad)
        for bad in cases:
            with self.assertRaises(RuntimeError): none.qualify_ce(bad, RUN, INDEPENDENT)
        for change in ({'entries': 15}, {'complete': False}, {'filesystem_ro': False}, {'complete': 1}):
            with self.assertRaises(RuntimeError):
                none.qualify_ce(operations(), RUN, dict(INDEPENDENT, **change))

    def test_parser_is_bounded_and_preserves_only_fixed_public_diagnostics(self):
        diag = b'G3 NONE_RESOLVER_DIAG table=3 column=4 reason=20 sqlite=0 schema=2 tag=0 blob_state=1'
        self.assertEqual(none.classify(b'', diag)['status_lines'], [diag.decode()])
        for stdout in (b'PRIVATE_BLOB=secret', b'X' * 4097, none.NONE_READY.encode() + b' extra'):
            with self.assertRaises(RuntimeError): none.classify(stdout, b'')
        with self.assertRaises(RuntimeError): none.classify('', b'')

    def test_final_evaluator_requires_cleanup_reaped_services_and_no_gk(self):
        consumer = dict(success=True, operations=operations(cleanup=True), independent_media_read=INDEPENDENT)
        ext = dict(status='G2_REMOTE_TEE_KEYMASTER_READY', consumer_run=True,
                   all_owned_processes_reaped=True, process_cleanup_errors=[], consumer=consumer)
        self.assertTrue(none.evaluate(ext, RUN)['success'])
        for change in ({'all_owned_processes_reaped': False}, {'process_cleanup_errors': [1]},
                       {'gatekeeper_probe': {}}, {'gatekeeper_teec_diagnostic': {}}):
            with self.assertRaises(RuntimeError): none.evaluate(dict(ext, **change), RUN)
        bad = copy.deepcopy(ext); bad['consumer']['operations'][-1]['status_lines'] = []
        with self.assertRaises(RuntimeError): none.evaluate(bad, RUN)


class ProfileBoundaryTests(unittest.TestCase):
    def test_config_exact_profiles_share_only_the_pinned_manifest(self):
        common.validate_config(NONE_CONFIG, BOOT)
        common.validate_config(dict(CONFIG, state_dir=common.STATE_DIR), BOOT)
        for change in ({'native_efs_policy': {}}, {'profile_id': SAMSUNG_PROFILE},
                       {'android_user_id': 1}, {'read_only': False}, {'root_manifest_sha256': '0' * 64}):
            with self.assertRaises(common.SessionError): common.validate_config(dict(NONE_CONFIG, **change), BOOT)
        with self.assertRaises(common.SessionError):
            common.validate_config(dict(CONFIG, state_dir=common.STATE_DIR, native_efs_policy=None), BOOT)
        missing = dict(NONE_CONFIG); del missing['native_efs_policy']
        with self.assertRaises(common.SessionError): common.validate_config(missing, BOOT)

    def test_none_worker_rejects_any_credential_or_non_discovery_dispatch(self):
        self.assertTrue(native.attempt_mode(NONE_CONFIG, True, None))
        self.assertFalse(native.attempt_mode(CONFIG, True, None))
        self.assertFalse(native.attempt_mode(CONFIG, False, 64))
        for config, discovery, credential in ((NONE_CONFIG, False, None), (NONE_CONFIG, True, 64),
                (dict(NONE_CONFIG, native_efs_policy={}), True, None),
                (dict(NONE_CONFIG, profile_id='unknown'), True, None)):
            with self.assertRaises(RuntimeError): native.attempt_mode(config, discovery, credential)

    def test_none_dispatch_passes_no_credential_fd(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            with patch.object(session.subprocess, 'Popen') as spawn:
                session.dispatch('/public/config', NONE_CONFIG, None, 71, right, 340, '/public/safe', True)
                argv = spawn.call_args.args[0]
                self.assertIn('--discover', argv)
                self.assertNotIn('--credential-fd', argv)
                self.assertEqual(spawn.call_args.kwargs['pass_fds'], (71, right.fileno()))
            with self.assertRaises(common.SessionError):
                session.dispatch('/public/config', NONE_CONFIG, 64, 71, right, 340, '/public/safe', True)
        finally:
            left.close(); right.close()


class NoneServiceTests(unittest.TestCase):
    def test_exact_seven_services_and_samsung_eight_unchanged(self):
        runtime = none_runtime(); selected = wc.required_services(runtime, EVO_PROFILE)
        self.assertEqual(len(selected), 7)
        wc.assert_services_alive(runtime, selected, EVO_PROFILE)
        self.assertEqual(runtime.checked, list(range(1000, 1007)))
        self.assertEqual(len(wc.required_services(service_runtime_fixture())), 8)
        with self.assertRaises(common.SessionError): wc.required_services(runtime)

    def test_gk_object_diagnostic_process_or_spawn_is_forbidden(self):
        for field in ('gatekeeper', 'gatekeeper_diagnostic'):
            runtime = none_runtime(); setattr(runtime, field, object())
            with self.assertRaises(common.SessionError): wc.required_services(runtime, EVO_PROFILE)
        with self.assertRaises(common.SessionError): wc.required_services(service_runtime_fixture(), EVO_PROFILE)
        runtime = none_runtime(); runtime.events.append(dict(event='spawn', executable='/system/bin/gatekeeper-diagnostic', pid=999))
        with self.assertRaises(common.SessionError): wc.required_services(runtime, EVO_PROFILE)

    def test_missing_duplicate_exited_or_wrong_context_never_disappears_from_required_set(self):
        for index in range(7):
            runtime = none_runtime(); selected = wc.required_services(runtime, EVO_PROFILE)
            selected[index].returncode = 0
            with self.assertRaises(common.SessionError): wc.assert_services_alive(runtime, selected, EVO_PROFILE)
            runtime = none_runtime(); daemon = runtime.processes[index * 2]
            runtime.processes.remove(daemon)
            with self.assertRaises(common.SessionError): wc.required_services(runtime, EVO_PROFILE)
            runtime.processes.extend([daemon, daemon])
            with self.assertRaises(common.SessionError): wc.required_services(runtime, EVO_PROFILE)
            runtime = none_runtime(); runtime.events[index * 2]['context_verified'] = False
            with self.assertRaises(common.SessionError): wc.required_services(runtime, EVO_PROFILE)

    def test_invalid_none_evidence_rejected_before_export(self):
        with patch.object(wc, '_profile', EVO_PROFILE), patch.object(wc, '_discovery', True), \
             patch.object(wc, 'export_tree') as export:
            with self.assertRaises(RuntimeError): wc.hold_none(none_runtime(), operations()[:3], RUN, INDEPENDENT)
            export.assert_not_called()

    def test_samsung_hold_still_requires_two_qualified_gk_records(self):
        runtime = service_runtime_fixture()
        runtime.gatekeeper_diagnostic = SimpleNamespace(drain=lambda: None, parser=SimpleNamespace(
            records=[{'kind': 'READY'}], error=None, ready=True, eof=False, pending=b''))
        trace = {'cleanup_verified': True, 'status': 'SCALAR_TRACE_COMPLETE'}
        with patch.object(wc, '_profile', SAMSUNG_PROFILE), patch.object(wc, '_hold_ce') as tail:
            with self.assertRaises(common.SessionError): wc.hold(runtime, {'success': True}, [], trace)
            tail.assert_not_called()
            call = {'kind': 'CALL', 'cmd': 126, 'result': 0, 'ta_present': 1, 'ta_bound': 'QUALIFIED', 'ta_status': 0}
            runtime.gatekeeper_diagnostic.parser.records += [call, dict(call)]
            wc.hold(runtime, {'success': True}, [], trace)
            self.assertEqual(len(tail.call_args.args[1]), 8)
            self.assertEqual(tail.call_args.args[2], SAMSUNG_PROFILE)


class NoneActualHoldTests(unittest.TestCase):
    def test_real_tree_fd_hold_ping_and_fresh_cleanup_lease_for_seven_services(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease'
            original = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            worker_fd = os.dup(original)
            fresh = tree = None
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            left.settimeout(2); right.settimeout(2)
            runtime = none_runtime()
            runtime.common_lock_fd = worker_fd
            runtime.backend = SimpleNamespace(at=lambda p: Path(directory))
            returned, errors = [], []
            def export(_):
                return os.open('/dev/null', os.O_RDONLY), {'fixture': 'detached-tree'}
            def runner():
                try:
                    returned.append(wc.hold_none(runtime, operations(), RUN, INDEPENDENT))
                except BaseException as error:
                    errors.append(error)
            try:
                common.validate_lease(original, str(path))
                with patch.object(wc, '_control', right), patch.object(wc, '_profile', EVO_PROFILE), \
                     patch.object(wc, '_discovery', True), patch.object(wc, '_held', False), \
                     patch.object(wc, 'export_tree', side_effect=export), \
                     patch.object(wc, 'validate_lease', side_effect=lambda fd: common.validate_lease(fd, str(path))), \
                     patch.object(wc, 'park_for_reset', side_effect=WatchdogPark):
                    thread = threading.Thread(target=runner, daemon=True); thread.start()
                    value, tree = common.receive(left, True)
                    self.assertEqual(value, {'event': 'authenticated', 'mount_transfer': {'fixture': 'detached-tree'}, 'requested_mode': 'ro'})
                    self.assertIsNotNone(tree); os.close(tree); tree = None
                    common.packet(left, {'op': 'hold'})
                    self.assertEqual(common.receive(left)[0], {'event': 'held'})
                    # ACK means worker relinquished the original OFD, without unlocking it.
                    self.assertEqual(os.readlink('/proc/self/fd/' + str(worker_fd)), '/dev/null')
                    common.packet(left, {'op': 'ping', 'serial': 19})
                    self.assertEqual(common.receive(left)[0], {'event': 'pong', 'serial': 19})
                    os.close(original); original = None
                    fresh = os.open(path, os.O_RDWR); common.validate_lease(fresh, str(path))
                    common.packet(left, {'op': 'unmount'}, fresh)
                    self.assertEqual(common.receive(left)[0], {'event': 'cleaning'})
                    thread.join(2)
                    self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
                    self.assertTrue(returned[0]['success'])
                    self.assertEqual(len(runtime.checked), 14)  # admission and one heartbeat
                os.close(fresh); fresh = None
                contender = os.open(path, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        __import__('fcntl').flock(contender, __import__('fcntl').LOCK_EX | __import__('fcntl').LOCK_NB)
                    os.close(worker_fd); worker_fd = None
                    common.validate_lease(contender, str(path))
                finally:
                    os.close(contender)
            finally:
                for fd in (original, worker_fd, fresh, tree):
                    if fd is not None: os.close(fd)
                left.close(); right.close()


class NoneReceiptTests(unittest.TestCase):
    def setUp(self):
        self.clock = [100.]; self.mounts = FakeMounts()
        self.commits, self.sent, self.actions = [], [], []
        self.life = session.SessionLifecycle(NONE_CONFIG, mounts=self.mounts,
            commit=self.commits.append, send_worker=lambda v,f: self.sent.append((v,f)),
            release_lease=lambda: self.actions.append('released'), cleanup_check=lambda: True,
            disarm=lambda: self.actions.append('disarmed'), now=lambda: self.clock[0])

    def test_direct_authenticated_then_held_commits_before_lease_release(self):
        self.assertEqual(self.life.credential_type, 'none')
        self.assertTrue(self.life.auth_started)
        self.life.authenticated(os.getpid(), common.starttime(os.getpid()))
        self.assertEqual(self.life.state, 'binding'); self.assertEqual(self.actions, [])
        receipt = self.commits[-1]
        self.assertEqual(receipt['state'], 'mounted'); self.assertEqual(receipt['credential_type'], 'none')
        self.assertIs(receipt['native_efs_persistence'], False)
        self.assertTrue(receipt['ce_authenticated']); self.assertEqual(self.sent[-1], ({'op': 'hold'}, None))
        self.assertIs(self.life.held(), receipt)
        self.assertEqual(self.actions, ['released']); self.assertEqual(self.life.deadline, 105)
        session.validate_state(receipt, boot_id=BOOT, process_check=lambda p,t: True, mount_check=lambda r: True)
        for change in ({'native_efs_persistence': True}, {'credential_type': 'password'}, {'profile_id': SAMSUNG_PROFILE}):
            with self.assertRaises(common.SessionError):
                session.validate_state(dict(receipt, **change), boot_id=BOOT,
                                       process_check=lambda p,t: True, mount_check=lambda r: True)

    def test_none_cannot_enter_awaiting_credential_or_authenticate_prepared(self):
        with self.assertRaises(common.SessionError): self.life.prepared(10, 1, 'password', {})
        with self.assertRaises(common.SessionError): self.life.start_auth({}, 71, 64)
        self.assertEqual(self.sent, []); self.assertFalse(self.mounts.bound)

    def test_ebusy_then_fresh_lease_unmount_and_terminal_cleanup(self):
        self.life.authenticated(os.getpid(), common.starttime(os.getpid())); self.life.held()
        self.mounts.busy = True; before = list(self.sent)
        with self.assertRaises(common.SessionError) as error: self.life.request_unmount(77)
        self.assertEqual(error.exception.code, 'VOLUME_BUSY')
        self.assertTrue(error.exception.details['session_preserved']); self.assertEqual(self.sent, before)
        self.assertEqual(self.life.state, 'mounted')
        self.mounts.busy = False; self.life.request_unmount(77)
        self.assertEqual(self.sent[-1], ({'op': 'unmount'}, 77))
        self.life.complete(0, {'cleanup_verified': True, 'success': True})
        self.assertEqual(self.actions, ['released', 'disarmed'])


class WatchdogPark(BaseException):
    pass


class NoneUnknownTests(unittest.TestCase):
    def process(self, code=0, stdout=b''):
        return Mock(pid=1234, returncode=code,
                    communicate=Mock(return_value=(stdout, b'')), wait=Mock(return_value=code))

    def test_timeout_waits_without_kill_and_never_returns_for_cleanup(self):
        process = self.process(); process.communicate.side_effect = subprocess.TimeoutExpired('native', 130)
        with patch.object(wc, 'park_for_reset', side_effect=WatchdogPark):
            with self.assertRaises(WatchdogPark): none.collect_native_status(process, 130, Mock())
        process.wait.assert_called_once_with(); process.kill.assert_not_called(); process.terminate.assert_not_called()

    def test_signal_control_io_error_and_returned_unknown_park(self):
        cases = [self.process(-14), self.process(stdout=b'G4 NONE_STATE_UNKNOWN_WAIT_WATCHDOG')]
        io_error = self.process(); io_error.communicate.side_effect = OSError('capture lost'); cases.append(io_error)
        for process in cases:
            with patch.object(wc, 'park_for_reset', side_effect=WatchdogPark):
                with self.assertRaises(WatchdogPark): none.collect_native_status(process, 130, Mock())
            process.kill.assert_not_called(); process.terminate.assert_not_called()

    def test_definite_native_failure_returns_fixed_diagnostics_to_clean_failure_path(self):
        process = self.process(1, b'G4 NONE_BRIDGE_FAILED operation=unlock errno=5')
        with patch.object(wc, 'park_for_reset') as park:
            status = none.collect_native_status(process, 130, Mock())
        self.assertEqual(status['status_lines'], ['G4 NONE_BRIDGE_FAILED operation=unlock errno=5'])
        park.assert_not_called()


if __name__ == '__main__':
    unittest.main()
