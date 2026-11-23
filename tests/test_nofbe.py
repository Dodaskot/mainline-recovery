"""Android's data without file-based encryption: vendor's fstab patched in place (2026-11-21)."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import nofbe  # noqa: E402

# The /data lines of Samsung's A226BXXSBDZC3 (vendor/etc/fstab.mt6833 and fstab.emmc).
MT6833 = (b'/dev/block/by-name/metadata\t/metadata\text4\tnoatime,nosuid,nodev,noauto_da_alloc,discard,journal_checksum,'
          b'data=ordered,errors=panic,sync\twait,check,formattable,first_stage_mount\n'
          b'/dev/block/by-name/userdata\t/data\tf2fs\tnoatime,nosuid,nodev,discard,usrquota,grpquota,fsync_mode=nobarrier,'
          b'reserve_root=32768,resgid=5678,inlinecrypt\twait,check,,quota,reservedsize=128M,latemount,,checkpoint=fs,'
          b'fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized,keydirectory=/metadata/vold/metadata_encryption,'
          b'fsverity,fscompress\n')
EMMC = MT6833.replace(b'v2+inlinecrypt_optimized', b'v2')


class Flags(unittest.TestCase):
    def test_the_data_line_loses_its_encryption_and_keeps_its_length(self):
        patched, removed = nofbe.unencrypted(MT6833)
        self.assertEqual(len(patched), len(MT6833))
        self.assertEqual(removed, ['fileencryption', 'keydirectory'])
        data = patched.split(b'\n')[1].split()[4]
        self.assertNotIn(b'fileencryption', data)
        self.assertNotIn(b'keydirectory', data)
        self.assertTrue(data.startswith(b'wait,check,,quota,reservedsize=128M,latemount,,checkpoint=fs,,'))
        self.assertTrue(data.endswith(b',fsverity,fscompress'))
        self.assertEqual(patched.split(b'\n')[0], MT6833.split(b'\n')[0])  # /metadata stays

    def test_only_the_data_line_and_not_comments(self):
        text = (b'# /dev/x /data f2fs a fileencryption=aes\n/dev/y /cache ext4 a wait,fileencryption=aes\n')
        self.assertEqual(nofbe.unencrypted(text), (text, []))

    def test_an_fstab_already_plain_is_left_as_it_is(self):
        plain, _ = nofbe.unencrypted(MT6833)
        self.assertEqual(nofbe.unencrypted(plain), (plain, []))


@unittest.skipUnless(shutil.which('mke2fs') and shutil.which('debugfs'), 'no e2fsprogs')
class Vendor(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        tree = self.root / 'tree'
        (tree / 'etc').mkdir(parents=True)
        (tree / 'etc/fstab.mt6833').write_bytes(MT6833 * 3)  # longer than one 1 KiB block
        (tree / 'etc/fstab.emmc').write_bytes(EMMC)
        (tree / 'etc/fstab.ramplus').write_bytes(b'/dev/block/zram0 none swap defaults zramsize=50%\n')
        (tree / 'lib').mkdir()
        (tree / 'lib/other.so').write_bytes(os.urandom(20000))
        self.image = self.root / 'vendor.img'
        subprocess.run(['mke2fs', '-q', '-t', 'ext4', '-b', '1024', '-d', str(tree), str(self.image), '4096'], check=True)

    def test_the_bytes_of_the_fstab_files_change_and_nothing_else(self):
        before = self.image.read_bytes()
        plan = nofbe.plan_for(self.image)
        self.assertTrue(plan['encrypted'])
        self.assertEqual({f['file']: f['removed'] for f in plan['files']},
                         {'/vendor/etc/fstab.mt6833': ['fileencryption', 'keydirectory'] * 3,
                          '/vendor/etc/fstab.emmc': ['fileencryption', 'keydirectory'], '/vendor/etc/fstab.ramplus': []})
        nofbe.write_image(self.image, plan['writes'])
        after = self.image.read_bytes()
        changed = [i for i in range(len(before)) if before[i] != after[i]]
        self.assertTrue(changed and all(after[i] == ord(',') for i in changed))
        self.assertFalse(nofbe.plan_for(self.image)['encrypted'])
        run = subprocess.run(['e2fsck', '-fn', str(self.image)], capture_output=True)
        self.assertEqual(run.returncode, 0, run.stdout[-400:])  # the filesystem is whole
        content = subprocess.run(['debugfs', '-R', 'cat /etc/fstab.mt6833', str(self.image)], capture_output=True).stdout
        self.assertEqual(content, nofbe.unencrypted(MT6833 * 3)[0])

    def test_a_vendor_that_changed_while_it_was_read_is_not_written(self):
        plan = nofbe.plan_for(self.image)
        data = bytearray(self.image.read_bytes())
        data[plan['writes'][0]['offset']] ^= 1
        self.image.write_bytes(bytes(data))
        with self.assertRaises(Exception) as caught:
            nofbe.write_image(self.image, plan['writes'])
        self.assertEqual(getattr(caught.exception, 'code', None), 'VENDOR_CHANGED')

    def test_patch_needs_verification_off_and_reports_what_it_did(self):
        context = mock.Mock(mode='fixture', root=self.root)
        with mock.patch('root.verification_state', return_value=True):
            with self.assertRaises(Exception) as caught:
                nofbe.patch(context, True)
        self.assertEqual(caught.exception.code, 'NO_FBE_NEEDS_VERIFICATION_OFF')
        with mock.patch('root.verification_state', return_value=False):
            self.assertTrue(nofbe.inspect(context)['encrypted'])
            done = nofbe.patch(context, True)
            self.assertTrue(done['changed'])
            self.assertFalse(nofbe.inspect(context)['encrypted'])
            self.assertFalse(nofbe.patch(context, True)['changed'])  # once is enough

    def test_extents_map_a_partition_byte_to_super(self):
        extents = [(2048, 8), (10000, 8)]  # two extents of 4 KiB
        self.assertEqual(nofbe.super_offset(extents, 100), 2048 * 512 + 100)
        self.assertEqual(nofbe.super_offset(extents, 4096 + 7), 10000 * 512 + 7)
        with self.assertRaises(Exception):
            nofbe.super_offset(extents, 8192)

    def test_a_vendor_that_is_no_ext4_is_refused(self):
        self.image.write_bytes(bytes(8192))
        with self.assertRaises(Exception) as caught:
            nofbe.plan_for(self.image)
        self.assertEqual(caught.exception.code, 'VENDOR_NOT_EXT4')


if __name__ == '__main__':
    unittest.main()
