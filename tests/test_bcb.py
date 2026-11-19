"""What Android asks of the recovery through misc (bcb.py): read, done on arrival, or forgotten at
the owner's word (2026-11-11)."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import bcb


def message(command=b'', recovery=b'', rest=0x5a):
    """A bootloader message as Android writes it, and what lies after it in misc."""
    head = command.ljust(32, b'\0') + bytes(32) + recovery.ljust(768, b'\0') + bytes(32) + bytes(1184)
    assert len(head) == bcb.SIZE
    return head + bytes([rest]) * 4096


class Request(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-bcb-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.misc = self.root / 'misc'

    def run_helper(self, command):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bcb.main(['--fixture', str(self.root), command])
        return code, json.loads(out.getvalue())

    def test_nothing_asked(self):
        self.misc.write_bytes(message())
        code, found = self.run_helper('read')
        self.assertEqual((code, found['command'], found['wipe'], found['cleared']), (0, '', False, False))
        self.assertEqual(self.run_helper('forget'), (0, {**found}))
        self.assertEqual(self.misc.read_bytes(), message())

    def test_a_plain_start_of_the_recovery_is_done_by_arriving(self):
        self.misc.write_bytes(message(b'boot-recovery', b'recovery\n'))
        code, found = self.run_helper('arrive')
        self.assertEqual((code, found['command'], found['wipe'], found['cleared']), (0, 'boot-recovery', False, True))
        self.assertEqual(self.misc.read_bytes(), message())  # what lies after the message stays

    def test_normal_boot_clears_only_the_stale_plain_request(self):
        self.misc.write_bytes(message(b'boot-recovery', b'recovery\n'))
        code, found = self.run_helper('prepare-normal')
        self.assertEqual((code, found['reason'], found['cleared']), (0, 'NORMAL_BOOT_BCB_READY', True))
        self.assertEqual(self.misc.read_bytes(), message())
        code, found = self.run_helper('prepare-normal')
        self.assertEqual((code, found['reason'], found['cleared']), (0, 'NORMAL_BOOT_BCB_READY', False))

    def test_normal_boot_does_not_discard_a_wipe_request(self):
        asked = message(b'boot-recovery', b'recovery\n--prompt_and_wipe_data\n--reason=fs_mgr_mount_all:M02R\n')
        self.misc.write_bytes(asked)
        code, found = self.run_helper('prepare-normal')
        self.assertEqual((code, found['reason'], found['cleared']), (2, 'WIPE_REQUEST_PENDING', False))
        self.assertEqual(self.misc.read_bytes(), asked)

    def test_normal_boot_does_not_discard_another_boot_command(self):
        asked = message(b'boot-fastboot', b'recovery\n--fastboot\n')
        self.misc.write_bytes(asked)
        code, found = self.run_helper('prepare-normal')
        self.assertEqual((code, found['reason'], found['cleared']), (2, 'OTHER_BCB_COMMAND_PENDING', False))
        self.assertEqual(self.misc.read_bytes(), asked)

    def test_normal_boot_preserves_ota_or_cache_wipe_action(self):
        for action in (b'--update_package=/cache/update.zip', b'--wipe_cache'):
            with self.subTest(action=action):
                asked = message(b'boot-recovery', b'recovery\n' + action + b'\n')
                self.misc.write_bytes(asked)
                code, found = self.run_helper('prepare-normal')
                self.assertEqual((code, found['reason'], found['cleared']),
                                 (2, 'OTHER_RECOVERY_ACTION_PENDING', False))
                self.assertEqual(self.misc.read_bytes(), asked)

    def test_normal_boot_refuses_unreadable_or_truncated_misc(self):
        code, found = self.run_helper('prepare-normal')
        self.assertEqual((code, found['reason']), (2, 'BCB_UNREADABLE_OR_UNWRITABLE'))
        self.misc.write_bytes(b'boot-recovery')
        code, found = self.run_helper('prepare-normal')
        self.assertEqual((code, found['reason']), (2, 'BCB_UNREADABLE_OR_UNWRITABLE'))

    def test_a_reset_from_the_settings_stays_until_it_is_done_or_forgotten(self):
        """Android's Factory data reset: --wipe_data. Arriving here does not clear it."""
        asked = message(b'boot-recovery', b'recovery\n--wipe_data\n--reason=MasterClearConfirm\n--locale=uk_UA\n')
        self.misc.write_bytes(asked)
        code, found = self.run_helper('arrive')
        self.assertEqual((code, found['wipe'], found['cleared'], found['reason']), (0, True, False, 'MasterClearConfirm'))
        self.assertIn('--wipe_data', found['recovery'])
        self.assertEqual(self.misc.read_bytes(), asked)
        # The owner's word: nothing is erased, the request is gone, and what follows it in misc stays.
        code, found = self.run_helper('forget')
        self.assertEqual((code, found['command'], found['wipe'], found['cleared']), (0, '', False, True))
        self.assertEqual(self.misc.read_bytes(), message())

    def test_data_that_cannot_be_opened_asks_with_a_prompt(self):
        self.misc.write_bytes(message(b'boot-recovery', b'recovery\n--prompt_and_wipe_data\n--reason=fs_mgr_mount_all:M02R\n'))
        code, found = self.run_helper('read')
        self.assertEqual((code, found['wipe'], found['reason']), (0, True, 'fs_mgr_mount_all:M02R'))
        self.assertIn('--prompt_and_wipe_data', found['recovery'])

    def test_forget_leaves_other_requests_alone(self):
        asked = message(b'boot-fastboot', b'recovery\n--fastboot\n')
        self.misc.write_bytes(asked)
        code, found = self.run_helper('forget')
        self.assertEqual((code, found['command'], found['cleared']), (0, 'boot-fastboot', False))
        self.assertEqual(self.misc.read_bytes(), asked)

    def test_a_phone_without_misc_asks_nothing(self):
        code, found = self.run_helper('read')
        self.assertEqual((code, found['command'], found['wipe']), (0, '', False))


if __name__ == '__main__':
    unittest.main()
