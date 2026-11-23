"""Format authorization tests use owned temporary files and mocked native/device operations.

No password, block device, mount, authentication request or mkfs is exercised.
"""
import contextlib
import copy
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import android_decrypt
import decrypt_session
from decrypt_runtime import common as session_common
from decrypt_runtime import session_support

import android_gsi
import filesystem as fs
import format_authorization as auth
import install
import samsung_firmware as firmware

REAL_SESSION_STATUS = android_decrypt.session_status
REAL_DETACHED_STATUS = decrypt_session.detached_status

BOOT = 'b8d2fc47-d4f8-4483-a34f-9a9c9e753a48'
TOKEN, VOLUME_TOKEN, POLICY = '1' * 64, '2' * 64, '3' * 64


def protected_volume():
    return dict(id='userdata', device_identity='4' * 64, partition_number=54,
                size_bytes=53397667328, path='/dev/mmcblk0p54', device='259:22',
                physical_volume_token=TOKEN, volume_token=TOKEN,
                filesystem_uuid='original-uuid', fs_type='f2fs', fscrypt_feature=True,
                encrypted_container=False, mounted=False, read_only=True,
                decrypt_supported=True, decrypt_state='awaiting_credential',
                decrypt_run_id='run0123456789', decrypt_profile_id='evolutionx-a226b-a16',
                credential_type='password', ce_authenticated=False,
                fscrypt_policy_verified=False)


class FormatAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='a22x-format-auth-')
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.current = protected_volume()
        self.session = dict(boot_id=BOOT, run_id='run0123456789', physical_volume_token=TOKEN,
            profile_id='evolutionx-a226b-a16', android_user_id=0, credential_type='password',
            supervisor_pid=101, supervisor_starttime=1001, worker_pid=102, worker_starttime=1002,
            mount_id=63, device='251:6', read_only=True, requested_mode='ro')
        self.policy = POLICY
        self.clock = 100.0
        self.ctx = types.SimpleNamespace(mode='device', boot_id=BOOT, lock_path='/test/lock',
            lock_fd=91, volume=lambda ident, expected=None: copy.deepcopy(self.current),
            confirm=lambda confirmed: fs.fail('CONFIRMATION_REQUIRED', 'confirm') if not confirmed else None)
        self.ctx.unmount = mock.Mock(side_effect=self.unmount)
        self.native = self.patch(android_decrypt, 'mount', side_effect=self.native_mount)
        self.terminal = self.patch(android_decrypt, 'close_session', create=True,
            side_effect=lambda context, volume: context.unmount('userdata', volume['volume_token']))
        self.patch(android_decrypt, 'session_status',
            side_effect=lambda context, token: copy.deepcopy(self.session))
        self.patch(decrypt_session, 'detached_status',
             side_effect=lambda state_dir, **kwargs: copy.deepcopy(self.session))
        self.patch(auth, '_native_lease')
        self.patch(auth, '_held')
        self.patch(auth, '_ram_directory',
            side_effect=lambda create=False: os.open(self.root, os.O_RDONLY | os.O_DIRECTORY))
        # The production reader's root ownership checks are intentionally not relaxed;
        # these owned test files use a test-only reader under a non-root host account.
        self.patch(auth, '_read_record',
            side_effect=lambda name: json.loads((self.root / name).read_text()))
        self.patch(auth, '_session',
            side_effect=lambda context, volume: (copy.deepcopy(self.session), self.policy))
        self.patch(auth.time, 'monotonic', side_effect=lambda: self.clock)

    def patch(self, obj, name, **kwargs):
        p = mock.patch.object(obj, name, **kwargs)
        value = p.start()
        self.addCleanup(p.stop)
        return value

    def native_mount(self, context, volume, mode, confirmed, fd, user, *,
                     require_fresh_authentication=False):
        self.assertTrue(require_fresh_authentication)
        if self.session.get('session_reusable') is True:
            self.session.update(state='mounted', key_retained=True,
                                ce_authenticated=True, fscrypt_policy_verified=True)
            self.current['key_retained'] = True
            self.session['auth_generation'] += 1
            self.session['mount_generation'] += 1
            self.session['authentication_id'] = ('%032x' % self.session['auth_generation'])
            self.current.update({key: self.session[key] for key in auth.REUSABLE_FIELDS})
        self.current.update(mounted=True, path='/dev/dm-6', device='251:6',
            physical_path='/dev/mmcblk0p54', physical_device='259:22',
            volume_token=VOLUME_TOKEN, mount_id=63, mount_owner='android-decrypt',
            mountpoint='/mnt/volumes/userdata', decrypt_state='mounted',
            ce_authenticated=True, fscrypt_policy_verified=True, read_only=True)
        return dict(volume=copy.deepcopy(self.current), authentication_performed=True,
                    authentication_run_id=self.session['run_id'],
                    **{key: self.session[key] for key in auth.REUSABLE_FIELDS if key in self.session})

    def unmount(self, ident, expected):
        self.current.update(mounted=False, path='/dev/mmcblk0p54', device='259:22',
            volume_token=TOKEN, mount_id=None, mount_owner=None,
            decrypt_state='reboot_required', ce_authenticated=False,
            fscrypt_policy_verified=False)
        return {'volume': copy.deepcopy(self.current), 'reboot_required': True,
                'session_closed': True, 'session_retained': False, 'cleanup_verified': True}

    def grant(self, purpose='format', target='ext4'):
        return auth.authorize(self.ctx, copy.deepcopy(self.current), target, purpose, 64)

    def error(self, code, function, *args, **kwargs):
        with self.assertRaises(fs.FilesystemError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def offline(self):
        holder = types.SimpleNamespace(is_dir=lambda: True, iterdir=lambda: iter(()))
        return contextlib.ExitStack(), holder

    def finish(self, token):
        holder = types.SimpleNamespace(is_dir=lambda: True, iterdir=lambda: iter(()))
        class HolderPath:
            def __truediv__(self, other):
                return self
            def is_dir(self):
                return True
            def iterdir(self):
                return iter(())
        with mock.patch.object(auth, 'Path', return_value=HolderPath()), \
             mock.patch.object(fs, 'all_namespace_mounts', return_value=[]):
            return auth.prepare_write(self.ctx, copy.deepcopy(self.current), 'ext4', 'format', token)


    def enable_reusable(self, state='session_unmounted', readonly=True):
        self.session.update(session_reusable=True, authentication_id='0' * 31 + '1',
                            auth_generation=1, mount_generation=1, state=state,
                            key_retained=True, ce_authenticated=(state == 'mounted'),
                            fscrypt_policy_verified=(state == 'mounted'))
        self.current.update(session_reusable=True, session_retained=True,
                            decrypt_state=state, mounted=(state == 'mounted'),
                            read_only=readonly)
        self.current.update({key: self.session[key] for key in auth.REUSABLE_FIELDS})

    def test_reusable_mounted_and_unmounted_always_request_fresh_auth(self):
        for state, readonly in [('mounted', False), ('mounted', True), ('session_unmounted', True)]:
            with self.subTest(state=state, readonly=readonly):
                self.current = protected_volume()
                self.enable_reusable(state, readonly)
                result = self.grant()
                self.assertTrue(self.native.call_args.kwargs['require_fresh_authentication'])
                self.assertEqual(result['auth_generation'], 2)
                self.assertEqual(result['authentication_id'], '%032x' % 2)
                self.assertEqual(result['volume']['authentication_id'], result['authentication_id'])
                self.assertEqual(result['mount_generation'], 2)
                self.assertTrue(result['volume']['read_only'])
                self.assertEqual(auth.annotate(self.ctx, [self.current])[0]['format_auth_state'], 'required')

    def real_detached_fixture(self, authenticated=True):
        """Complete receipt for the real validators, without any device access."""
        self.enable_reusable()
        pid = os.getpid()
        ticks = session_common.starttime(pid)
        self.session.update(schema=session_common.SCHEMA,
            supervisor_pid=pid, supervisor_starttime=ticks,
            worker_pid=pid, worker_starttime=ticks,
            native_owner_pid=pid, native_owner_starttime=ticks,
            native_generation=2, native_sequence=2, mount_generation=2,
            password_policy_at_auth='each_mount' if authenticated else None,
            auth_generation=1 if authenticated else 0,
            authentication_id='0' * 31 + '1' if authenticated else None,
            key_retained=authenticated, session_retained=True,
            filesystem_unmounted=True, device_offline=False, reboot_required=False,
            detached_proof_schema='a22x.ce-session.suspend.v1',
            physical_device='259:22', detached_devices=['251:6'],
            owned_crypto_names=['a22x-data-ro-' + self.session['run_id'] + suffix
                                for suffix in ('', '-raw')])
        self.current.update({key: self.session[key] for key in auth.REUSABLE_FIELDS})
        self.refresh_detached_token()

    def refresh_detached_token(self):
        token = session_support.detached_token(self.session)
        self.session['volume_token'] = token
        self.current['volume_token'] = token

    @contextlib.contextmanager
    def production_session_readers(self):
        """Keep both state validators real; replace only fixture I/O observations."""
        owner = self
        class ObservationPath:
            def __init__(self, *parts):
                self.parts = parts
            def read_text(self):
                owner.assertEqual(self.parts, ('/proc', str(os.getpid()), 'mountinfo'))
                return '1 0 0:1 / / rw - rootfs rootfs rw\n'
            def glob(self, pattern):
                owner.assertEqual((self.parts, pattern), (('/sys/block',), 'dm-*/dm/name'))
                return []
        with mock.patch.object(android_decrypt, 'session_status', wraps=REAL_SESSION_STATUS), \
             mock.patch.object(decrypt_session, 'detached_status', wraps=REAL_DETACHED_STATUS), \
             mock.patch.object(decrypt_session, 'secure_directory',
                               side_effect=lambda path: os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)), \
             mock.patch.object(decrypt_session, 'read_json_at',
                               side_effect=lambda directory, name: copy.deepcopy(self.session)), \
             mock.patch.object(session_support, 'Path', ObservationPath), \
             mock.patch.object(fs, 'all_namespace_mounts', return_value=[]):
            yield

    def test_real_detached_reader_admits_fresh_format_after_unmount(self):
        self.real_detached_fixture()
        with self.production_session_readers():
            result = self.grant()
        self.assertTrue(self.native.call_args.kwargs['require_fresh_authentication'])
        self.assertTrue(result['authentication_performed'])
        self.assertEqual(result['auth_generation'], 2)
        self.assertEqual(result['mount_generation'], 3)

    def test_real_detached_reader_admits_fresh_format_after_cancel_before_auth(self):
        self.real_detached_fixture(authenticated=False)
        with self.production_session_readers():
            result = self.grant()
        self.assertTrue(self.native.call_args.kwargs['require_fresh_authentication'])
        self.assertEqual(result['auth_generation'], 1)
        self.assertEqual(result['authentication_id'], '%032x' % 1)

    def test_real_detached_reader_refuses_stale_identity_before_password(self):
        for changed in ('expected_token', 'physical_token', 'boot', 'owner', 'epoch'):
            with self.subTest(changed=changed):
                self.current = protected_volume()
                self.real_detached_fixture()
                if changed == 'expected_token':
                    self.current['volume_token'] = 'f' * 64
                else:
                    if changed == 'physical_token':
                        self.session['physical_volume_token'] = 'f' * 64
                    elif changed == 'boot':
                        self.session['boot_id'] = '00000000-0000-0000-0000-000000000000'
                    elif changed == 'owner':
                        self.session['native_owner_starttime'] += 1
                    else:
                        self.session['auth_generation'] = True
                    self.refresh_detached_token()
                with self.production_session_readers():
                    self.error('FORMAT_SESSION_CHANGED', self.grant)
        self.native.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_mounted_reader_still_rejects_suspended_receipt(self):
        self.real_detached_fixture()
        with self.production_session_readers():
            with self.assertRaises(decrypt_session.SessionError) as raised:
                android_decrypt.session_status(self.ctx, TOKEN)
        self.assertEqual(raised.exception.code, 'DECRYPT_REBOOT_REQUIRED')
        self.native.assert_not_called()

    def test_cached_or_replayed_reusable_auth_never_grants_format(self):
        for field, value in [('authentication_performed', False),
                             ('authentication_id', '0' * 31 + '1'),
                             ('auth_generation', 1), ('mount_generation', 99), ('auth_generation', True),
                             ('session_reusable', False)]:
            with self.subTest(field=field):
                self.current = protected_volume()
                self.enable_reusable()
                def stale(*args, **kwargs):
                    result = self.native_mount(*args, **kwargs)
                    result[field] = value
                    return result
                self.native.side_effect = stale
                self.error('FORMAT_AUTH_NOT_FRESH', self.grant)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_native_reusable_claim_with_same_auth_epoch_is_not_fresh(self):
        self.enable_reusable()
        def repeated(*args, **kwargs):
            result = self.native_mount(*args, **kwargs)
            for obj in (self.session, self.current, result, result['volume']):
                obj.update(auth_generation=1, authentication_id='0' * 31 + '1')
            return result
        self.native.side_effect = repeated
        self.error('FORMAT_AUTH_NOT_FRESH', self.grant)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_reusable_auth_and_mount_generations_invalidate_grant(self):
        self.enable_reusable()
        token = self.grant()['format_authorization']
        for key, value in [('auth_generation', 3), ('mount_generation', 3),
                           ('authentication_id', 'f' * 32)]:
            with self.subTest(key=key):
                old = self.session[key]
                self.session[key] = value
                self.error('FORMAT_SESSION_CHANGED', auth.validate,
                           self.ctx, self.current, 'ext4', 'format', token)
                self.session[key] = old

    def test_format_requires_terminal_close_not_ordinary_suspend(self):
        self.enable_reusable()
        token = self.grant()['format_authorization']
        self.ctx.unmount.side_effect = AssertionError('ordinary suspend is not terminal closure')
        def close(context, volume):
            result = self.unmount('userdata', volume['volume_token'])
            self.current.update(session_retained=False, session_reusable=False)
            return result
        self.terminal.side_effect = close
        self.finish(token)
        self.terminal.assert_called_once()
        self.ctx.unmount.assert_not_called()

    def test_retained_session_after_claimed_close_blocks_format(self):
        self.enable_reusable()
        token = self.grant()['format_authorization']
        self.error('FORMAT_CLEANUP_FAILED', self.finish, token)
        self.error('FORMAT_AUTH_CONSUMED', self.finish, token)
        self.assertFalse((self.root / (token + '.used')).exists())

    def test_missing_reusable_live_epoch_blocks_before_password(self):
        self.enable_reusable()
        self.session['auth_generation'] = True
        self.error('FORMAT_SESSION_CHANGED', self.grant)
        self.native.assert_not_called()

    def test_cancel_before_first_auth_still_allows_fresh_format_password(self):
        self.enable_reusable()
        self.session.update(auth_generation=0, authentication_id=None, key_retained=False)
        self.current.update(auth_generation=0, authentication_id=None, key_retained=False)
        result = self.grant()
        self.assertTrue(result['authentication_performed'])
        self.assertEqual(result['auth_generation'], 1)
        self.assertEqual(result['authentication_id'], '%032x' % 1)
        self.assertTrue(self.native.call_args.kwargs['require_fresh_authentication'])

    def test_mixed_never_authenticated_epoch_is_rejected_before_password(self):
        for key, value in [('authentication_id', 'f' * 32), ('auth_generation', True),
                           ('auth_generation', -1), ('key_retained', True),
                           ('ce_authenticated', True), ('fscrypt_policy_verified', True),
                           ('state', 'mounted')]:
            with self.subTest(key=key):
                self.current = protected_volume()
                self.enable_reusable()
                self.session.update(auth_generation=0, authentication_id=None, key_retained=False)
                self.current.update(auth_generation=0, authentication_id=None, key_retained=False)
                self.session[key] = value
                self.error('FORMAT_SESSION_CHANGED', self.grant)
        self.native.assert_not_called()

    def test_only_fresh_native_password_auth_issues_grant(self):
        result = self.grant()
        self.assertTrue(result['authentication_performed'])
        self.assertEqual(result['format_volume_token'], TOKEN)
        self.assertEqual(result['expires_in_seconds'], 120)
        self.native.assert_called_once()
        record = auth.validate(self.ctx, self.current, 'ext4', 'format', result['format_authorization'])
        self.assertEqual(record['physical'], auth.physical(self.current))
        self.assertEqual(record['session'], self.session)
        self.assertEqual(record['policy_sha256'], POLICY)
        self.ctx.unmount.assert_not_called()
        self.assertFalse(any(p.name.endswith('.used') for p in self.root.iterdir()))

    def test_wrong_password_never_issues_grant_or_touches_data(self):
        self.native.side_effect = lambda *args, **kwargs: fs.fail('CREDENTIAL_REJECTED', 'Rejected')
        self.error('CREDENTIAL_REJECTED', self.grant)
        self.assertEqual(list(self.root.iterdir()), [])
        self.ctx.unmount.assert_not_called()

    def test_old_mount_and_missing_metadata_refused_before_password_submission(self):
        for state, mounted, code in [
            ('mounted', True, 'FORMAT_AUTH_RESTART_REQUIRED'),
            ('reboot_required', False, 'FORMAT_AUTH_RESTART_REQUIRED'),
            ('locked', False, 'FORMAT_PREPARATION_REQUIRED')]:
            with self.subTest(state=state):
                volume = protected_volume()
                volume.update(decrypt_state=state, mounted=mounted)
                self.error(code, auth.authorize, self.ctx, volume, 'f2fs', 'format', 64)
        self.native.assert_not_called()

    def test_none_pattern_unknown_are_not_password_verification(self):
        for kind in ('none', 'pattern', 'unknown', None):
            with self.subTest(kind=kind):
                volume = protected_volume()
                volume['credential_type'] = kind
                self.error('FORMAT_CREDENTIAL_UNSUPPORTED', auth.authorize,
                           self.ctx, volume, 'f2fs', 'format', 64)
        self.native.assert_not_called()

    def test_false_fresh_flag_and_wrong_authentication_run_are_rejected(self):
        for field, value in [('authentication_performed', False), ('authentication_run_id', 'other012345')]:
            with self.subTest(field=field):
                self.current = protected_volume()
                def bad(*args, **kwargs):
                    answer = self.native_mount(*args, **kwargs)
                    answer[field] = value
                    return answer
                self.native.side_effect = bad
                self.error('FORMAT_AUTH_NOT_FRESH', self.grant)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_native_success_on_wrong_physical_volume_never_issues_grant(self):
        def changed(*args, **kwargs):
            result = self.native_mount(*args, **kwargs)
            self.current['physical_volume_token'] = 'f' * 64
            return result
        self.native.side_effect = changed
        self.error('FORMAT_AUTH_NOT_FRESH', self.grant)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_grant_rejects_wrong_boot_operation_filesystem_and_target(self):
        token = self.grant()['format_authorization']
        self.error('FORMAT_AUTH_MISMATCH', auth.validate, self.ctx, self.current, 'f2fs', 'format', token)
        self.error('FORMAT_AUTH_MISMATCH', auth.validate, self.ctx, self.current, 'ext4', 'android-reset', token)
        self.ctx.boot_id = 'another-boot'
        self.error('FORMAT_AUTH_MISMATCH', auth.validate, self.ctx, self.current, 'ext4', 'format', token)
        self.ctx.boot_id = BOOT
        changed = dict(self.current, physical_volume_token='f' * 64)
        self.error('FORMAT_TARGET_CHANGED', auth.validate, self.ctx, changed, 'ext4', 'format', token)
        self.ctx.unmount.assert_not_called()

    def test_grant_rejects_changed_live_worker_policy_and_expiry(self):
        token = self.grant()['format_authorization']
        self.session['worker_starttime'] += 1
        self.error('FORMAT_SESSION_CHANGED', auth.validate, self.ctx, self.current, 'ext4', 'format', token)
        self.session['worker_starttime'] -= 1
        self.policy = 'f' * 64
        self.error('FORMAT_SESSION_CHANGED', auth.validate, self.ctx, self.current, 'ext4', 'format', token)
        self.policy = POLICY
        self.clock = 220.0
        self.error('FORMAT_AUTH_EXPIRED', auth.validate, self.ctx, self.current, 'ext4', 'format', token)
        self.ctx.unmount.assert_not_called()

    def test_successful_cleanup_consumes_exact_grant_before_writer(self):
        token = self.grant()['format_authorization']
        result = self.finish(token)
        self.assertFalse(result['mounted'])
        self.ctx.unmount.assert_called_once_with('userdata', VOLUME_TOKEN)
        self.assertTrue((self.root / (token + '.used')).exists())
        self.error('FORMAT_AUTH_CONSUMED', auth.validate, self.ctx, self.current, 'ext4', 'format', token)

    def test_known_busy_preserved_session_keeps_grant_without_retry(self):
        token = self.grant()['format_authorization']
        self.ctx.unmount.side_effect = lambda *args: fs.fail('VOLUME_BUSY', 'Busy', session_preserved=True)
        self.error('VOLUME_BUSY', self.finish, token)
        self.ctx.unmount.assert_called_once()
        self.assertFalse((self.root / (token + '.attempted')).exists())
        auth.validate(self.ctx, self.current, 'ext4', 'format', token)

    def test_unknown_cleanup_blocks_replay_and_never_claims_erasure(self):
        token = self.grant()['format_authorization']
        self.ctx.unmount.side_effect = lambda *args: fs.fail('DECRYPT_OUTCOME_UNKNOWN', 'Unknown')
        self.error('DECRYPT_OUTCOME_UNKNOWN', self.finish, token)
        self.assertTrue((self.root / (token + '.attempted')).exists())
        self.assertFalse((self.root / (token + '.used')).exists())
        self.error('FORMAT_AUTH_CONSUMED', self.finish, token)
        self.ctx.unmount.assert_called_once()

    def test_busy_claim_with_changed_session_does_not_release_attempt(self):
        token = self.grant()['format_authorization']
        def busy(*args):
            self.session['worker_starttime'] += 1
            fs.fail('VOLUME_BUSY', 'Busy', session_preserved=True)
        self.ctx.unmount.side_effect = busy
        self.error('VOLUME_BUSY', self.finish, token)
        self.assertTrue((self.root / (token + '.attempted')).exists())

    def test_cleanup_without_actual_unmount_blocks_writer_and_replay(self):
        token = self.grant()['format_authorization']
        self.ctx.unmount.side_effect = lambda *args: {}
        self.error('FORMAT_CLEANUP_FAILED', self.finish, token)
        self.error('FORMAT_AUTH_CONSUMED', self.finish, token)
        self.ctx.unmount.assert_called_once()

    def test_cancel_revokes_grant_without_changing_mount(self):
        token = self.grant()['format_authorization']
        result = auth.cancel(self.ctx, token)
        self.assertTrue(result['format_authorization_cancelled'])
        self.assertFalse(result['data_erased'] or result['mount_changed'])
        self.assertTrue(self.current['mounted'])
        self.ctx.unmount.assert_not_called()
        self.error('FORMAT_AUTH_CONSUMED', auth.validate, self.ctx, self.current, 'ext4', 'format', token)

    def test_protected_format_without_grant_never_calls_mkfs(self):
        with mock.patch.object(fs.subprocess, 'run') as writer:
            self.error('FORMAT_AUTH_REQUIRED', fs.DeviceContext.format,
                       self.ctx, 'userdata', 'f2fs', True, TOKEN)
        writer.assert_not_called()
        self.ctx.unmount.assert_not_called()

    def test_reset_guard_runs_before_cache_wipe_and_raw_writer(self):
        context = types.SimpleNamespace(mode='device', fs=self.ctx)
        with mock.patch.object(firmware, 'held_lock', return_value=contextlib.nullcontext()), \
             mock.patch.object(auth, 'writer_lease', return_value=contextlib.nullcontext()), \
             mock.patch.object(fs, 'wipe_contents') as wipe, \
             mock.patch.object(install.subprocess, 'run') as writer:
            self.error('FORMAT_AUTH_REQUIRED', firmware.reset_data, context, True, mock.Mock())
            self.error('FORMAT_AUTH_REQUIRED', install.DeviceContext.reset_android, context)
        wipe.assert_not_called()
        writer.assert_not_called()
        self.ctx.unmount.assert_not_called()

    def test_automatic_firmware_and_gsi_refuse_before_any_inspection_or_flash(self):
        context = types.SimpleNamespace(mode='device', fs=self.ctx)
        with mock.patch.object(firmware, 'held_lock', side_effect=lambda *args: contextlib.nullcontext()), \
             mock.patch.object(firmware, 'inspect') as fwinspect, \
             mock.patch.object(android_gsi, 'inspect') as gsiinspect, \
             mock.patch.object(firmware, 'flash_one') as fwwrite, \
             mock.patch.object(android_gsi, 'flash_gsi') as gsiwrite:
            self.error('FORMAT_AUTH_REQUIRED', firmware.install_firmware,
                       context, 'sdcard-p1', 'x', '/image', 'x', True, mock.Mock())
            self.error('FORMAT_AUTH_REQUIRED', android_gsi.install_gsi,
                       context, 'sdcard-p1', 'x', '/image', 'x', True, mock.Mock())
        for call in (fwinspect, gsiinspect, fwwrite, gsiwrite):
            call.assert_not_called()

    def test_plain_linux_remains_admitted_unknown_and_damaged_do_not(self):
        plain = dict(protected_volume(), fs_type='ext4', fscrypt_feature=False)
        for key in ('decrypt_state', 'decrypt_supported', 'ce_authenticated'):
            plain.pop(key, None)
        self.assertFalse(auth.protected(plain))
        auth.preflight(self.ctx, plain, 'ext4', 'format')
        for change in ({'fs_type': None}, {'fscrypt_feature': None}, {'encrypted_container': True}):
            self.assertTrue(auth.protected(dict(plain, **change)))

    def test_initialized_receipt_binds_new_uuid_device_and_boot(self):
        old = protected_volume()
        self.current.update(decrypt_state='reboot_required', mounted=False,
                            filesystem_uuid='new-uuid', volume_token='a' * 64, physical_volume_token='a' * 64)
        auth.record_initialized(self.ctx, 'android-reset', old, 'f2fs', {'verified': 'synthetic'})
        self.assertTrue(auth.initialized(self.ctx, self.current))
        self.assertFalse(auth.needs_authorization(self.ctx, self.current))
        for field, value in [('filesystem_uuid', 'different'), ('device_identity', 'b' * 64),
                             ('physical_volume_token', 'c' * 64)]:
            self.assertFalse(auth.initialized(self.ctx, dict(self.current, **{field: value})))
        self.ctx.boot_id = 'different-boot'
        self.assertFalse(auth.initialized(self.ctx, self.current))

    def test_unchanged_or_missing_filesystem_cannot_be_marked_initialized(self):
        old = protected_volume()
        self.error('FORMAT_READBACK_FAILED', auth.record_initialized,
                   self.ctx, 'format', old, 'f2fs')
        self.current['filesystem_uuid'] = None
        self.error('FORMAT_READBACK_FAILED', auth.record_initialized,
                   self.ctx, 'format', old, 'f2fs')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_mkfs_creates_no_initialized_receipt(self):
        self.current = dict(protected_volume(), fs_type='ext4', fscrypt_feature=False,
                            decrypt_state=None, decrypt_supported=False)
        # 2026-11-20: a format also asks every namespace and the kernel whether the partition is held.
        with mock.patch.object(fs.subprocess, 'run',
             return_value=types.SimpleNamespace(returncode=1, stdout='synthetic mkfs failure')) as writer, \
             mock.patch.object(fs, 'all_namespace_mounts', return_value=[]), \
             mock.patch.object(fs, 'block_claimed', return_value=False):
            self.error('FORMAT_FAILED', fs.DeviceContext.format,
                       self.ctx, 'userdata', 'ext4', True, TOKEN)
        writer.assert_called_once()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_success_status_without_changed_uuid_is_not_erase_proof(self):
        self.current = dict(protected_volume(), fs_type='ext4', fscrypt_feature=False,
                            decrypt_state=None, decrypt_supported=False)
        with mock.patch.object(fs.subprocess, 'run',
             return_value=types.SimpleNamespace(returncode=0, stdout='')) as writer, \
             mock.patch.object(fs.os, 'sync'), \
             mock.patch.object(fs, 'all_namespace_mounts', return_value=[]), \
             mock.patch.object(fs, 'block_claimed', return_value=False):
            self.error('FORMAT_READBACK_FAILED', fs.DeviceContext.format,
                       self.ctx, 'userdata', 'ext4', True, TOKEN)
        writer.assert_called_once()
        self.assertEqual(list(self.root.iterdir()), [])


    def test_reset_busy_unknown_and_expired_leave_cache_untouched(self):
        token = self.grant(purpose='android-reset', target='f2fs')['format_authorization']
        reset = mock.Mock()
        context = types.SimpleNamespace(mode='device', fs=self.ctx,
            fresh=lambda: types.SimpleNamespace(reset_android=reset))
        with mock.patch.object(firmware, 'held_lock', side_effect=lambda *args: contextlib.nullcontext()), \
             mock.patch.object(auth, 'writer_lease', side_effect=lambda *args: contextlib.nullcontext()), \
             mock.patch.object(fs, 'wipe_contents') as wipe:
            for code in ('VOLUME_BUSY', 'DECRYPT_OUTCOME_UNKNOWN'):
                with self.subTest(code=code):
                    reset.side_effect = lambda **kwargs: fs.fail(code, 'Synthetic cleanup refusal')
                    self.error(code, firmware.reset_data, context, True, mock.Mock(),
                               format_authorization=token)
                    wipe.assert_not_called()
            self.clock = 220.0
            self.error('FORMAT_AUTH_EXPIRED', firmware.reset_data, context, True, mock.Mock(),
                       format_authorization=token)
            wipe.assert_not_called()
            self.assertEqual(reset.call_count, 2)

    def test_reset_reports_already_erased_when_only_cache_fails(self):
        token = self.grant(purpose='android-reset', target='f2fs')['format_authorization']
        reset = mock.Mock()
        context = types.SimpleNamespace(mode='device', fs=self.ctx,
            fresh=lambda: types.SimpleNamespace(reset_android=reset))
        with mock.patch.object(firmware, 'held_lock', return_value=contextlib.nullcontext()), \
             mock.patch.object(auth, 'writer_lease', return_value=contextlib.nullcontext()), \
             mock.patch.object(fs, 'wipe_contents', side_effect=OSError('synthetic cache failure')):
            with self.assertRaises(Exception) as caught:
                firmware.reset_data(context, True, mock.Mock(), format_authorization=token)
        self.assertEqual(caught.exception.code, 'DATA_RESET_CACHE_FAILED')
        self.assertTrue(caught.exception.details['data_erased'])
        reset.assert_called_once_with(format_authorization=token)

    def test_none_and_pattern_hints_do_not_offer_a_futile_reboot(self):
        for kind in ('none', 'pattern'):
            v = dict(protected_volume(), credential_type=kind, mounted=True, decrypt_state='mounted')
            observed = auth.annotate(self.ctx, [v])[0]
            self.assertEqual(observed['format_auth_state'], 'unavailable')
            self.error('FORMAT_CREDENTIAL_UNSUPPORTED', auth.authorize,
                       self.ctx, v, 'f2fs', 'format', 64)
        self.native.assert_not_called()

    def test_stock_install_refuses_protected_original_before_source_or_target_writes(self):
        context = types.SimpleNamespace(mode='device', fs=self.ctx, lock_path='/test/lock')
        context.fresh = lambda: context
        with mock.patch.object(install, 'check_plan'), \
             mock.patch.object(install, 'operation_lock', return_value=contextlib.nullcontext(91)), \
             mock.patch.object(install, 'Source') as source:
            self.error('FORMAT_AUTH_REQUIRED', install.execute,
                       context, {'operation': 'install-stock'}, 'confirmation')
        source.assert_not_called()


if __name__ == '__main__':
    unittest.main()
