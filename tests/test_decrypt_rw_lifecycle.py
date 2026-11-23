"""Permanent RW scope and UI-facing lifecycle regressions; no device I/O."""
import copy
import errno
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import android_decrypt as ad
import android_profiles as profiles
import decrypt_prepare as preparation
import decrypt_session as session
from decrypt_runtime import common, rw_support as rw
from filesystem import FilesystemError
from tests.test_decrypt_rw import CAP, RwFakeMounts
from tests.test_decrypt_session import CONFIG, BOOT
from tests.test_decrypt_discovery import SOURCE


def profile(ident=profiles.EVO_PROFILE):
    return json.loads((Path(__file__).parents[1] / 'profiles/android-decrypt' / (ident + '.json')).read_text())


class QualifiedScopeTests(unittest.TestCase):
    def test_packaged_evo_password_is_enabled_without_granting_other_credentials(self):
        evo = profile()
        self.assertTrue(rw.available(evo))
        self.assertTrue(rw.available(evo, 'password'))
        for credential in ('none', 'pattern', 'unknown', ''):
            self.assertFalse(rw.available(evo, credential))
        for ident in (profiles.SAMSUNG_PROFILE, profiles.LEGACY_EVO_NONE_PROFILE, 'other-gsi', None):
            forged = dict(evo, profile_id=ident)
            self.assertFalse(rw.available(forged, 'password'))
        self.assertFalse(rw.available(profile(profiles.SAMSUNG_PROFILE), 'password'))
        self.assertEqual(evo['ce_rw']['helper_sha256'], rw.HELPER_SHA)
        self.assertEqual(evo['ce_rw_qualified_credential_types'], ['password'])

    def test_stock_config_cannot_inherit_the_evo_write_capability(self):
        config = dict(CONFIG, ce_rw=CAP, state_dir=common.STATE_DIR)
        with self.assertRaises(common.SessionError) as caught:
            common.validate_config(config, actual_boot=BOOT)
        self.assertEqual(caught.exception.code, 'WRITE_NOT_QUALIFIED')

    def test_nonqualified_pending_credential_never_advertises_write(self):
        sent = []
        life = session.SessionLifecycle(dict(CONFIG, ce_rw=CAP),
            mounts=RwFakeMounts(), commit=lambda value: None,
            send_worker=lambda value, fd: sent.append((value, fd)),
            release_lease=lambda: None, cleanup_check=lambda: True,
            disarm=lambda: None, now=lambda: 100.)
        life.prepared(os.getpid(), common.starttime(os.getpid()), 'pattern', SOURCE)
        self.assertEqual(life.receipt['access_modes'], ['ro'])
        life.prepared_held()
        request = dict(op='authenticate', boot_id=BOOT, run_id=CONFIG['run_id'],
            volume_token=life.receipt['volume_token'], credential_type='pattern',
            requested_mode='rw', write_confirmed=True)
        with patch.object(rw, 'quotas') as quota:
            with self.assertRaises(common.SessionError):
                life.start_auth(request, 71, 77)
        quota.assert_not_called()
        self.assertFalse(life.auth_started)

    def test_forged_rw_pending_receipt_is_refused_before_source_lookup(self):
        receipt = dict(schema=common.SCHEMA, state='awaiting_credential', boot_id=BOOT,
            access_modes=['ro', 'rw'], profile_id=profiles.SAMSUNG_PROFILE,
            credential_type='password')
        with patch.object(session, 'prepared_source') as source:
            with self.assertRaises(common.SessionError) as caught:
                session.validate_prepared(receipt, boot_id=BOOT)
        self.assertEqual(caught.exception.code, 'WRITE_NOT_QUALIFIED')
        source.assert_not_called()


class FrontendLifecycleTests(unittest.TestCase):
    def mounted(self, readonly=True):
        return dict(id='userdata', decrypt_state='mounted', mounted=True, read_only=readonly,
            ce_authenticated=True, credential_type='password', decrypt_write_supported=True,
            decrypt_profile_id=profiles.EVO_PROFILE, decrypt_run_id='gui00000000000000')

    def test_duplicate_mount_is_success_but_never_verifies_another_password(self):
        for readonly, mode in ((True, 'ro'), (False, 'rw')):
            volume = self.mounted(readonly)
            with patch.object(ad, 'credential_descriptor') as credential, \
                 patch.object(ad, 'authenticate_prepared') as auth, \
                 patch.object(rw, 'quotas') as quotas:
                got = ad.mount(SimpleNamespace(), volume, mode, False, 77, 0)
            self.assertIs(got['volume'], volume)
            self.assertTrue(got['already_mounted'])
            self.assertFalse(got['authentication_performed'])
            credential.assert_not_called(); auth.assert_not_called(); quotas.assert_not_called()

    def test_mode_change_reports_action_and_keeps_the_existing_session(self):
        for readonly, requested in ((True, 'rw'), (False, 'ro')):
            with patch.object(session, 'unmount') as unmount, \
                 patch.object(ad, 'authenticate_prepared') as auth:
                with self.assertRaises(FilesystemError) as caught:
                    ad.mount(SimpleNamespace(), self.mounted(readonly), requested, True, 77, 0)
            self.assertEqual(caught.exception.code, 'DECRYPT_MODE_FIXED')
            self.assertTrue(caught.exception.details['session_preserved'])
            self.assertTrue(caught.exception.details['reboot_required'])
            self.assertEqual(caught.exception.details['requested_mode'], requested)
            unmount.assert_not_called(); auth.assert_not_called()

    def test_prepare_on_open_data_is_idempotent_without_new_worker(self):
        with patch.object(ad, 'select_current_profile') as select, \
             patch.object(preparation, 'prepare') as prepare, \
             patch.object(ad.subprocess, 'Popen') as spawn:
            got = ad.prepare_android(SimpleNamespace(), self.mounted())
        self.assertTrue(got['already_mounted'])
        self.assertFalse(got['authentication_performed'])
        select.assert_not_called(); prepare.assert_not_called(); spawn.assert_not_called()

    def test_repeated_prepare_rechecks_live_receipt_and_stale_error_stays_typed(self):
        volume = dict(id='userdata', decrypt_state='awaiting_credential',
            credential_type='password', volume_token='pending')
        context = SimpleNamespace(boot_id=BOOT)
        with patch.object(session, 'prepared_status', return_value={}) as existing, \
             patch.object(preparation, 'prepare') as prepare:
            got = ad.prepare_android(context, volume)
            self.assertTrue(got['already_prepared'])
            self.assertFalse(got['authentication_performed'])
            existing.assert_called_once()
            prepare.assert_not_called()
        with patch.object(session, 'prepared_status',
                side_effect=common.SessionError('DECRYPT_REBOOT_REQUIRED', 'Expired preparation')):
            with self.assertRaises(FilesystemError) as caught:
                ad.prepare_android(context, volume)
        self.assertEqual(caught.exception.code, 'DECRYPT_REBOOT_REQUIRED')

    def test_only_a_successful_fresh_auth_result_can_approve_format(self):
        pending = dict(volume_token='prepared', physical_volume_token='physical',
            credential_type='password')
        observed = dict(self.mounted(), volume_token='mounted')
        context = SimpleNamespace(lock_fd=71, boot_id=BOOT, volume=lambda ident: observed)
        with patch.object(session, 'prepared_request', return_value={'ok': True}) as request, \
             patch.object(ad, 'session_status', return_value={'read_only': True, 'run_id': 'current-run'}), \
             patch.object(ad.os, 'close') as close:
            got = ad.authenticate_prepared(context, pending, 77)
        self.assertTrue(got['authentication_performed'])
        self.assertEqual(got['authentication_run_id'], 'current-run')
        request.assert_called_once(); close.assert_called_once_with(77)

    def test_lost_auth_reply_is_unknown_without_retry_or_false_success(self):
        context = SimpleNamespace(lock_fd=71, boot_id=BOOT)
        pending = dict(volume_token='prepared', credential_type='password')
        with patch.object(session, 'prepared_request', side_effect=TimeoutError('synthetic')) as request, \
             patch.object(ad.os, 'close') as close:
            with self.assertRaises(FilesystemError) as caught:
                ad.authenticate_prepared(context, pending, 77)
        self.assertEqual(caught.exception.code, 'DECRYPT_OUTCOME_UNKNOWN')
        self.assertTrue(caught.exception.details['refresh_required'])
        self.assertFalse(caught.exception.details['retry_allowed'])
        request.assert_called_once(); close.assert_called_once_with(77)


    def test_lost_unmount_reply_is_unknown_and_does_not_dispatch_again(self):
        context = SimpleNamespace(lock_fd=71, boot_id=BOOT)
        with patch.object(session, 'unmount', side_effect=TimeoutError('synthetic')) as unmount:
            with self.assertRaises(FilesystemError) as caught:
                ad.unmount(context, self.mounted())
        self.assertEqual(caught.exception.code, 'DECRYPT_OUTCOME_UNKNOWN')
        self.assertEqual(caught.exception.details['operation'], 'unmount')
        self.assertFalse(caught.exception.details['retry_allowed'])
        unmount.assert_called_once()


class InventoryStateTests(unittest.TestCase):
    def raw(self):
        return dict(id='userdata', volume_token='physical', fs_type=None,
            path='/dev/mmcblk0p32', device='179:32')

    def test_locked_mode_choices_are_provisional_and_do_not_grant_rw(self):
        context = SimpleNamespace(mode='device', boot_id=BOOT)
        with patch.object(ad, 'profile', side_effect=profile), \
             patch.object(ad, 'session_status', side_effect=common.SessionError()), \
             patch.object(session, 'prepared_status', side_effect=FileNotFoundError), \
             patch.object(ad, 'terminal_status', return_value={}), \
             patch.object(ad, 'preflight_reason', return_value=None):
            volume = ad.decorate(context, [self.raw()])[0]
        self.assertEqual(volume['access_modes'], ['ro', 'rw'])
        self.assertEqual(volume['access_mode_qualification'], 'pending')
        self.assertFalse(volume['decrypt_write_supported'])
        self.assertFalse(volume.get('ce_authenticated', False))

    def test_stale_session_can_never_appear_ready_for_mount_or_password_retry(self):
        context = SimpleNamespace(mode='device', boot_id=BOOT)
        with patch.object(ad, 'profile', side_effect=profile), \
             patch.object(ad, 'session_status', side_effect=common.SessionError()), \
             patch.object(session, 'prepared_status', side_effect=common.SessionError('DECRYPT_REBOOT_REQUIRED')), \
             patch.object(ad, 'terminal_status', return_value={'boot_id': BOOT, 'state': 'failed'}):
            volume = ad.decorate(context, [self.raw()])[0]
        self.assertEqual(volume['access_modes'], [])
        self.assertTrue(volume['reboot_required'])
        self.assertFalse(volume['decrypt_supported'])
        self.assertFalse(volume['credential_required'])

    def test_mounted_inventory_reports_actual_mode_without_stale_unlock_prompt(self):
        for readonly in (True, False):
            receipt = dict(profile_id=profiles.EVO_PROFILE, credential_type='password',
                read_only=readonly, device='253:7', run_id='current-run', mount_id=19)
            node = SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(253, 7))
            context = SimpleNamespace(mode='device', boot_id=BOOT)
            with patch.object(ad, 'profile', side_effect=profile), \
                 patch.object(ad, 'session_status', return_value=receipt), \
                 patch.object(ad.Path, 'resolve', return_value=Path('/sys/devices/virtual/block/dm-7')), \
                 patch.object(ad.Path, 'lstat', return_value=node), \
                 patch.object(ad.Path, 'read_text', return_value='1' if readonly else '0'):
                # Profiles are fixed before Path.read_text is patched below.
                with patch.object(ad, 'profile', return_value=dict(profile_id=profiles.EVO_PROFILE, ce_rw=CAP)):
                    volume = ad.decorate(context, [self.raw()])[0]
            self.assertEqual(volume['current_access_mode'], 'ro' if readonly else 'rw')
            self.assertEqual(volume['access_modes'], ['ro' if readonly else 'rw'])
            self.assertEqual(volume['available_access_modes'], ['ro', 'rw'])
            self.assertIsNone(volume['unlock_reason'])
            self.assertEqual(volume['write_supported'], not readonly)
            self.assertTrue(volume['mode_change_requires_reboot'])

    def test_malformed_advisory_json_is_not_a_mount_or_an_internal_error(self):
        context = SimpleNamespace(boot_id=BOOT)
        for bad in ([], 'text', 42, None):
            with patch.object(ad, 'regular_json', return_value=bad), \
                 patch.object(ad, 'preparation_status', return_value={}):
                self.assertEqual(ad.terminal_status(context), {})
                self.assertIsNone(ad.preflight_reason(context))


if __name__ == '__main__':
    unittest.main()
