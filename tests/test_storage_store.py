"""The SD backup store (storage.py) on every filesystem the kernel writes (2026-11-20, the owner)."""
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import filesystem  # noqa: E402
import storage  # noqa: E402


def head(kind):
    data = bytearray(filesystem.PROBE_BYTES)
    if kind == 'ext4':
        struct.pack_into('<I', data, 1024 + 24, 2)
        struct.pack_into('<I', data, 1024 + 32, 32768)
        data[1080:1082] = b'\x53\xef'
        data[1024 + 120:1024 + 124] = b'card'
    elif kind == 'exfat':
        data[3:11] = b'EXFAT   '
        data[108], data[110] = 9, 1
        data[510:512] = b'\x55\xaa'
    elif kind == 'vfat':
        data[510:512] = b'\x55\xaa'
        struct.pack_into('<H', data, 11, 512)
        data[13], data[16] = 8, 2
        data[82:90] = b'FAT32   '
    elif kind == 'btrfs':
        data[0x10040:0x10048] = b'_BHRfS_M'
    elif kind == 'erofs':
        data[1024:1028] = b'\xe2\xe1\xf5\xe0'
        data[1024 + 12] = 12
    return bytes(data)


class Store(unittest.TestCase):
    def probe(self, kind):
        with tempfile.TemporaryFile() as card:
            card.write(head(kind))
            card.flush()
            return storage.probe_store(card.fileno())

    def test_every_writable_filesystem_is_a_store(self):
        for kind in ('ext4', 'exfat', 'vfat', 'btrfs'):
            self.assertEqual(self.probe(kind)['filesystem'], kind)
        self.assertEqual(self.probe('ext4')['label'], 'card')

    def test_read_only_or_unknown_keeps_the_code_the_interface_explains(self):
        for kind in ('erofs', 'none'):
            with self.assertRaises(storage.StorageError) as caught:
                self.probe(kind)
            self.assertEqual(str(caught.exception), 'EXT4_MICROSD_REQUIRED_NO_FORMAT_PERFORMED')

    def test_the_store_mounts_with_the_options_files_uses(self):
        self.assertIn('utf8', filesystem.mount_options('vfat', 'rw'))
        self.assertTrue(filesystem.mount_options('exfat', 'rw').startswith('rw,nodev,nosuid,noexec'))


if __name__ == '__main__':
    unittest.main()
