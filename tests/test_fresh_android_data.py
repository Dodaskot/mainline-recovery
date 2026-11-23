"""Data just formatted for Android, never started: seen as unencrypted and writable (2026-11-20)."""
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import filesystem as fs


class FreshDataTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / 'lost+found').mkdir()
        self.policies = {}
        # tmpfs has no fscrypt: the policy of each folder comes from the test (False: none).
        patcher = mock.patch.object(fs, 'encryption_policy', side_effect=lambda fd: self.policies.get(
            os.readlink('/proc/self/fd/%d' % fd), False))
        patcher.start()
        self.addCleanup(patcher.stop)

    def fresh(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            return fs.fresh_android_data(fd), fs.android_data_unencrypted(fd)
        finally:
            os.close(fd)

    def test_fresh_and_prepared_data(self):
        self.assertEqual(self.fresh(), (True, True))
        (self.root / 'adb/ksu').mkdir(parents=True)
        self.assertEqual(self.fresh(), (True, True))

    def test_started_or_encrypted_data_is_not_fresh(self):
        (self.root / 'misc').mkdir()
        self.policies[str(self.root / 'misc')] = True
        self.assertEqual(self.fresh(), (False, False))
        (self.root / 'misc').rmdir()
        (self.root / 'adb').mkdir()
        self.policies[str(self.root / 'adb')] = True
        self.assertEqual(self.fresh()[0], False)
        self.policies[str(self.root / 'adb')] = None  # unreadable counts as encrypted
        self.assertEqual(self.fresh()[0], False)
        self.policies[str(self.root / 'adb')] = False
        (self.root / 'unencrypted').mkdir()
        self.assertEqual(self.fresh()[0], False)

    def test_inode_count_of_the_newest_checkpoint(self):
        image = self.root / 'f2fs.img'
        data = bytearray(4096 * 1100)
        sb = 1024
        data[sb:sb + 4] = b'\x10\x20\xf5\xf2'
        struct.pack_into('<I', data, sb + 20, 9)    # log_blocks_per_seg: 512 blocks
        struct.pack_into('<I', data, sb + 76, 512)  # cp_blkaddr
        for pack, (version, inodes) in enumerate(((7, 5), (8, 9))):
            at = (512 + pack * 512) * 4096
            if at + 4096 <= len(data):
                struct.pack_into('<Q', data, at, version)
                struct.pack_into('<I', data, at + 148, inodes)
        image.write_bytes(bytes(data))
        self.assertEqual(fs.f2fs_inode_count(image), 9)
        image.write_bytes(bytes(4096 * 4))
        self.assertIsNone(fs.f2fs_inode_count(image))

    def test_fresh_userdata_needs_internal_f2fs_with_the_feature(self):
        context = mock.Mock(mode='device')
        for volume in ({'id': 'cache', 'fs_type': 'f2fs', 'fscrypt_feature': True},
                       {'id': 'userdata', 'fs_type': 'ext4', 'fscrypt_feature': True},
                       {'id': 'userdata', 'fs_type': 'f2fs', 'fscrypt_feature': False},
                       {'id': 'userdata', 'fs_type': 'f2fs', 'fscrypt_feature': True, 'external': True}):
            self.assertFalse(fs.fresh_userdata(context, volume))
        self.assertFalse(fs.fresh_userdata(mock.Mock(mode='fixture'),
                                           {'id': 'userdata', 'fs_type': 'f2fs', 'fscrypt_feature': True}))

    def test_android_data_without_encryption(self):
        for name in ('misc', 'system', 'data', 'media'):
            (self.root / name).mkdir()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.assertEqual(fs.plain_kind(fd), 'unencrypted')
            self.policies[str(self.root / 'misc')] = True
            self.assertIsNone(fs.plain_kind(fd))
        finally:
            os.close(fd)

    def test_probe_answer_is_kept_for_the_checkpoint(self):
        image = self.root / 'f2fs.img'
        data = bytearray(4096 * 1100)
        data[1024:1028] = b'\x10\x20\xf5\xf2'
        struct.pack_into('<I', data, 1024 + 20, 9)
        struct.pack_into('<I', data, 1024 + 76, 512)
        struct.pack_into('<Q', data, 512 * 4096, 41)
        image.write_bytes(bytes(data))
        self.assertEqual(fs.f2fs_checkpoint(image), (41, 0))
        kept = self.root / 'probe.json'
        volume = {'id': 'userdata', 'fs_type': 'f2fs', 'fscrypt_feature': True, 'path': str(image), 'device': '259:22',
                  'filesystem_uuid': 'u'}
        kept.write_text(json.dumps({'key': {'device': '259:22', 'uuid': 'u', 'checkpoint': 41}, 'kind': 'unencrypted'}))
        with mock.patch.object(fs, 'USERDATA_PROBE', kept):
            self.assertEqual(fs.plain_userdata(mock.Mock(mode='device'), volume), 'unencrypted')
            self.assertFalse(fs.fresh_userdata(mock.Mock(mode='device'), volume))

    def test_unencrypted_android_data_offers_writing_before_any_mount(self):
        import android_decrypt
        volume = {'id': 'userdata', 'fs_type': 'f2fs', 'fscrypt_feature': True, 'mountable': True, 'write_supported': False,
                  'read_only_reason': fs.reason_text('FSCRYPT_KEYS_UNAVAILABLE'), 'read_only_reason_code': 'FSCRYPT_KEYS_UNAVAILABLE',
                  'volume_token': 'x'}
        context = mock.Mock(mode='device')
        with mock.patch.object(android_decrypt, 'profile', return_value={}), \
                mock.patch.object(fs, 'plain_userdata', return_value='unencrypted'):
            out = android_decrypt.decorate(context, [dict(volume)])[0]
        self.assertTrue(out['write_supported'] and out['unencrypted_android_data'] and out['fscrypt_unused'])
        self.assertIsNone(out['read_only_reason_code'])
        self.assertNotIn('decrypt_state', out)
        with mock.patch.object(android_decrypt, 'profile', return_value={}), \
                mock.patch.object(fs, 'plain_userdata', return_value=None), \
                mock.patch.object(android_decrypt, 'session_status', side_effect=OSError):
            locked = android_decrypt.decorate(context, [dict(volume)])[0]
        self.assertFalse(locked['write_supported'])
        self.assertEqual(locked['decrypt_state'], 'locked')
        # A public image has no decryption profile: plain data is still recognised and writable.
        with mock.patch.object(android_decrypt, 'profile', side_effect=OSError), \
                mock.patch.object(fs, 'plain_userdata', return_value='unencrypted'):
            public = android_decrypt.decorate(context, [dict(volume)])[0]
        self.assertTrue(public['write_supported'] and public['unencrypted_android_data'])

    def test_format_needs_no_password_for_fresh_data(self):
        import format_authorization as authorization
        fresh = {'id': 'userdata', 'fs_type': 'f2fs', 'fscrypt_feature': True, 'fresh_android_data': True}
        self.assertFalse(authorization.protected(fresh))
        self.assertTrue(authorization.protected({**fresh, 'fresh_android_data': False}))
        self.assertTrue(authorization.protected({**fresh, 'decrypt_state': 'locked'}))
        plain = {'id': 'userdata', 'fs_type': 'f2fs', 'fscrypt_feature': True, 'unencrypted_android_data': True}
        self.assertFalse(authorization.protected(plain))


if __name__ == '__main__':
    unittest.main()
