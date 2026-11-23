"""Android data with the encrypt feature but no policy anywhere (an unencrypted port) may be written."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import filesystem as fs


class Unencrypted(unittest.TestCase):
    def check(self, folders, policies):
        with tempfile.TemporaryDirectory() as tmp:
            for name in folders:
                Path(tmp, name).mkdir()
            seen = {}

            def policy(fd):
                name = os.path.basename(os.readlink('/proc/self/fd/%d' % fd))
                name = '' if os.path.samefile('/proc/self/fd/%d' % fd, tmp) else name
                seen[name] = True
                return policies.get(name, False)
            root = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(fs, 'encryption_policy', policy):
                    return fs.android_data_unencrypted(root)
            finally:
                os.close(root)

    def test_no_policy_on_root_and_android_folders(self):
        self.assertTrue(self.check(('media', 'data', 'system'), {}))

    def test_any_policy_or_unknown_means_encrypted(self):
        self.assertFalse(self.check(('media', 'data'), {'media': True}))
        self.assertFalse(self.check(('media', 'data'), {'data': None}))
        self.assertFalse(self.check(('media', 'data'), {'': True}))

    def test_too_little_evidence(self):
        self.assertFalse(self.check(('media',), {}))
        self.assertFalse(self.check(('Download', 'Pictures'), {}))

    def test_a_folder_that_is_a_link_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'media').mkdir()
            Path(tmp, 'data').symlink_to('/')
            root = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(fs, 'encryption_policy', lambda fd: False):
                    self.assertFalse(fs.android_data_unencrypted(root))
            finally:
                os.close(root)

    def test_host_folder_has_no_readable_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertIsNot(fs.encryption_policy(fd), True)
            finally:
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
