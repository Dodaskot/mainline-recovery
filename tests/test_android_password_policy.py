"""Policy persistence contains an enum only; native unlock state never enters settings."""
import contextlib
import io
import json
import os
from types import SimpleNamespace
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import settings


class AndroidPasswordPolicy(unittest.TestCase):
    def cli(self, argv, record, store=None):
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['settings.py', *argv]), \
             mock.patch.object(settings, 'load', return_value=dict(record)), \
             mock.patch.object(settings, 'store', side_effect=store or (lambda value: 0)) as written, \
             contextlib.redirect_stdout(output):
            rc = settings.main()
        return rc, output.getvalue(), written

    def test_existing_settings_keep_strict_default_without_migration(self):
        record = {'language': 'uk', 'hash': 'ab' * 32, 'salt': '01' * 16}
        rc, output, written = self.cli(['status'], record)
        self.assertEqual(rc, 0)
        public = json.loads(output)
        self.assertEqual(public['android_password_policy'], 'each_mount')
        self.assertTrue(public['password'])
        self.assertNotIn('hash', public)
        self.assertNotIn('salt', public)
        self.assertNotIn('android_password_policy', record)
        written.assert_not_called()

    def test_all_policies_change_only_the_enum(self):
        before = {'language': 'uk', 'hash': 'ab' * 32, 'salt': '01' * 16, 'wifi': 'unchanged'}
        for policy in settings.ANDROID_PASSWORD_POLICIES:
            with self.subTest(policy=policy):
                rc, _, written = self.cli(['set', '--android-password-policy', policy], before)
                self.assertEqual(rc, 0)
                self.assertEqual(written.call_args.args[0], {**before, 'android_password_policy': policy})

    def test_unknown_policy_is_rejected_without_save(self):
        for policy in ('never', 'yes', 'startup ', '', '../../session', 'password=secret'):
            with self.subTest(policy=policy):
                rc, _, written = self.cli(['set', '--android-password-policy', policy], {'language': 'uk'})
                self.assertEqual(rc, 2)
                written.assert_not_called()

    def test_malformed_saved_values_are_never_cached_policy(self):
        for value in (None, 0, 1, True, [], {}, 'never', 'STARTUP', 'startup '):
            with self.subTest(value=value):
                record = {'android_password_policy': value}
                self.assertEqual(settings.android_password_policy(record), 'each_mount')
                rc, output, _ = self.cli(['status'], record)
                self.assertEqual(rc, 0)
                self.assertEqual(json.loads(output)['android_password_policy'], 'each_mount')

    def test_backend_policy_reader_uses_the_saved_value(self):
        for policy in settings.ANDROID_PASSWORD_POLICIES:
            with mock.patch.object(settings, 'load', return_value={'android_password_policy': policy}) as read:
                self.assertEqual(settings.android_password_policy(), policy)
                read.assert_called_once_with()

    def test_policy_survives_loss_of_ram_copy_without_unlock_state(self):
        with tempfile.TemporaryDirectory(prefix='a22x-android-policy-') as temp:
            ram = Path(temp) / 'settings.json'
            disk = {}
            def write(record):
                disk.clear()
                disk.update(record)
                return True
            for policy in settings.ANDROID_PASSWORD_POLICIES:
                record = {'language': 'uk', 'android_password_policy': policy}
                with mock.patch.object(settings, 'RAM_COPY', ram), \
                     mock.patch.object(settings, 'write_disk', side_effect=write), \
                     mock.patch.object(settings, 'read_disk', side_effect=lambda: dict(disk)):
                    self.assertEqual(settings.store(record), 0)
                    ram.unlink()
                    self.assertEqual(settings.load(), record)
                    self.assertEqual(settings.android_password_policy(), policy)
                    self.assertEqual(set(disk), {'language', 'android_password_policy'})
                    self.assertEqual(set(json.loads(ram.read_text())), set(record))

    def test_busy_persistence_keeps_only_policy_in_ram(self):
        with tempfile.TemporaryDirectory(prefix='a22x-android-policy-') as temp:
            ram = Path(temp) / 'settings.json'
            record = {'android_password_policy': 'first_access'}
            with mock.patch.object(settings, 'RAM_COPY', ram), \
                 mock.patch.object(settings, 'write_disk', return_value=False):
                self.assertEqual(settings.store(record), 3)
                self.assertEqual(settings.load(), record)

    def test_actual_misc_two_slot_roundtrip_preserves_other_areas(self):
        ms = settings.misc_store
        with tempfile.TemporaryDirectory(prefix='a22x-policy-misc-') as temp:
            root = Path(temp)
            misc = root / 'misc.fixture'
            ram = root / 'settings.json'
            prefix = b'\x35' * ms.AREAS['settings']
            initial = prefix + bytes(ms.END - len(prefix))
            misc.write_bytes(initial)
            context = SimpleNamespace(lock_path=str(root / 'lock'), mode='fixture')
            with mock.patch.dict(os.environ, {'A22X_MISC': str(misc)}), \
                 mock.patch.object(settings, 'RAM_COPY', ram), \
                 mock.patch.object(settings.fs, 'DeviceContext', return_value=context), \
                 mock.patch.object(settings, '_copy_themes', return_value=False), \
                 mock.patch.object(settings, 'read_volumes', side_effect=AssertionError('No legacy mount is needed')):
                for policy in settings.ANDROID_PASSWORD_POLICIES:
                    record = {'language': 'uk', 'android_password_policy': policy,
                              'hash': 'ab' * 32, 'salt': '01' * 16}
                    self.assertEqual(settings.store(record), 0)
                    data = misc.read_bytes()
                    self.assertEqual(data[:ms.AREAS['settings']], prefix)
                    self.assertEqual(data[ms.AREAS['settings'] + 2 * ms.SLOT:],
                                     initial[ms.AREAS['settings'] + 2 * ms.SLOT:])
                    slots = [ms.classify('settings', data[ms.AREAS['settings'] + n * ms.SLOT:
                                                        ms.AREAS['settings'] + (n + 1) * ms.SLOT])
                             for n in (0, 1)]
                    self.assertEqual([slot[0] for slot in slots], ['valid', 'valid'])
                    self.assertEqual([json.loads(slot[2]) for slot in slots], [record, record])
                    ram.unlink()
                    self.assertEqual(settings.load(), record)
                    self.assertEqual(settings.android_password_policy(), policy)

    def test_invalid_policy_does_not_change_recovery_password_contract(self):
        rc, output, written = self.cli(['status'], {'android_password_policy': 'never', 'hash': 'ab' * 32, 'salt': '01' * 16, 'digits': True})
        self.assertEqual(rc, 0)
        value = json.loads(output)
        self.assertTrue(value['password'])
        self.assertTrue(value['password_digits'])
        self.assertEqual(value['android_password_policy'], 'each_mount')
        written.assert_not_called()


if __name__ == '__main__':
    unittest.main()
