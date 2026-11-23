"""systems_overview.py: what the home page and the Systems tab show as installed (2026-11-22)."""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import systems_overview  # noqa: E402


class OverviewTests(unittest.TestCase):
    def test_android_and_linux_are_told_from_status_and_boot(self):
        status = {'foreign': True, 'mounted': True, 'active': 'ubuntu', 'boot_linux': False,
                  'slots': [{'id': 'ubuntu', 'name': 'Ubuntu 24.04', 'active': True, 'boot_tested': True}]}
        boot = {'kind': 'android', 'release': '4.14.186+', 'root': 'kernelsu', 'android_version': '13.0.0', 'patch_level': '2025-01'}
        with mock.patch.object(systems_overview.distro, 'status', return_value=status), \
             mock.patch.object(systems_overview, 'boot_facts', return_value=boot):
            result = systems_overview.overview(object())
        self.assertEqual(result['android'], {'data': True, 'boot': 'android', 'version': '13', 'patch': '2025-01',
                                             'kernel': '4.14.186+', 'root': 'kernelsu'})
        self.assertEqual(result['linux']['slots'], [{'id': 'ubuntu', 'name': 'Ubuntu 24.04', 'active': True, 'boot_tested': True}])
        self.assertFalse(result['linux']['boot'])

    def test_an_unread_boot_is_unknown_not_a_failure(self):
        with mock.patch.object(systems_overview.distro, 'status', return_value={'foreign': False, 'slots': []}), \
             mock.patch.object(systems_overview, 'boot_facts', return_value={}):
            result = systems_overview.overview(object())
        self.assertTrue(result['ok'])
        self.assertEqual(result['android']['boot'], 'unknown')
        self.assertEqual(result['android']['version'], '')

    def test_a_busy_phone_answers_busy(self):
        class Busy:
            def operation_lock(self, shared=False):
                raise systems_overview.fs.FilesystemError('OPERATION_BUSY', 'Storage is busy')
        with mock.patch.object(systems_overview.fs, 'DeviceContext', return_value=Busy()), \
             mock.patch('builtins.print') as printed:
            code = systems_overview.main(['--device'])
        self.assertEqual(code, 1)
        answer = json.loads(printed.call_args[0][0])
        self.assertEqual((answer['ok'], answer['busy']), (False, True))


if __name__ == '__main__':
    unittest.main()
