"""The platform files as the sources hold them (2026-11-13 review): alsa-lib takes the folder of a
conf.d entry's target as the folder of its includes only when the entry is a symlink; committed as a
plain file, the sound profile of this phone did not load in an installed system."""
from pathlib import Path
import os
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / 'platform/optional/usr/share/alsa/ucm2/conf.d/mt6833_mt6359/mt6833-mt6359.conf'


class PlatformTree(unittest.TestCase):
    def test_the_ucm_entry_is_a_link_to_its_folder(self):
        self.assertTrue(ENTRY.is_symlink())
        self.assertEqual(os.readlink(ENTRY), '../../MediaTek/mt6833/mt6359-sia8109/mt6833-mt6359.conf')
        for name in ('HiFi.conf', 'init.conf'):
            self.assertTrue((ENTRY.resolve().parent / name).is_file(), name)


if __name__ == '__main__':
    unittest.main()
