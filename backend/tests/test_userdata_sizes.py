"""userdata on every SM-A226B, 64 GB or 128 GB (2026-11-13): Samsung's PIT gives it the rest of the
eMMC, so its admitted sizes follow the eMMC's size instead of one phone's."""
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import qualification  # noqa: E402
import storage  # noqa: E402

GB64, GB128 = 122142720, 244285440


class UserdataSizes(unittest.TestCase):
    def test_the_rule_matches_the_64_gb_phone(self):
        self.assertEqual(storage.userdata_sizes(GB64), (53393489920, (GB64 - 33 - 17850368) * 512))

    def test_on_a_computer_any_admitted_emmc_is_accepted(self):
        with mock.patch.object(qualification, 'PHONE', Path('/nonexistent/device.json')):
            for disk in (GB64, GB128):
                for size in storage.userdata_sizes(disk):
                    self.assertTrue(qualification.size_admitted('userdata', size), (disk, size))
            self.assertFalse(qualification.size_admitted('userdata', 4096 * 1000))
            self.assertFalse(qualification.size_admitted('userdata', storage.userdata_sizes(GB64)[0] + 1))
            self.assertFalse(qualification.size_admitted('boot', 4096))
            self.assertTrue(qualification.size_admitted('boot', qualification.GEOMETRY['boot'][1]))

    def test_on_the_phone_its_own_emmc_decides(self):
        with mock.patch.object(qualification, 'PHONE', Path(__file__)), \
                mock.patch.object(qualification, 'DISK', mock.Mock(is_file=lambda: True, read_text=lambda: str(GB128))):
            self.assertTrue(qualification.size_admitted('userdata', storage.userdata_sizes(GB128)[1]))
            self.assertFalse(qualification.size_admitted('userdata', storage.userdata_sizes(GB64)[1]))


if __name__ == '__main__':
    unittest.main()
