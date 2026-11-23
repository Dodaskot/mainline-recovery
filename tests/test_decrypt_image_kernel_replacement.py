"""Pinned kernel/DTB replacement and touch firmware admission in the recovery image builder."""
import gzip
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import build_decrypt_image as builder


def dtb(payload=b'x'):
    body = payload + bytes(-len(payload) % 4)
    total = 40 + len(body)
    return b'\xd0\x0d\xfe\xed' + struct.pack('>I', total) + bytes(32) + body


def section(tree):
    header = bytearray(64)
    struct.pack_into('>10I', header, 0, 0xd7b7ab1e, 64 + len(tree), 0x20, 0x20, 1, 0x20, 0x800, 0, len(tree), 0x40)
    return bytes(header) + tree


def kernel(release='7.2.0-a22x-recovery-diag1+', build=145, tree=None):
    raw = bytearray(4096)
    raw[56:60] = b'ARMd'
    banner = f'Linux version {release} (fixture) #{build} SMP PREEMPT\x00'.encode()
    raw[200:200 + len(banner)] = banner
    return gzip.compress(bytes(raw), mtime=0) + (tree if tree is not None else dtb())


class MtkTable(unittest.TestCase):
    def test_parse_and_rebuild_keep_the_header(self):
        old, new = dtb(b'old'), dtb(b'a longer replacement tree')
        template = section(old)
        self.assertEqual(builder.mtk_dtb_table(template), old)
        rebuilt = builder.mtk_dtb_section(template, new)
        self.assertEqual(builder.mtk_dtb_table(rebuilt), new)
        self.assertEqual(rebuilt[8:32], template[8:32])

    def test_malformed_tables_are_refused(self):
        good = section(dtb())
        for bad in (b'\0' * 4 + good[4:], good[:16] + struct.pack('>I', 2) + good[20:], good + b'\0'):
            with self.assertRaises(Exception):
                builder.mtk_dtb_table(bad)


class Replacement(unittest.TestCase):
    def args(self, tmp, kernel_bytes, dtb_bytes, **pins):
        k, d = Path(tmp, 'kernel'), Path(tmp, 'dtb')
        k.write_bytes(kernel_bytes); d.write_bytes(dtb_bytes)
        return SimpleNamespace(kernel_section=k, dtb_section=d,
                               kernel_section_sha256=pins.get('kpin', hashlib.sha256(kernel_bytes).hexdigest()),
                               dtb_section_sha256=pins.get('dpin', hashlib.sha256(dtb_bytes).hexdigest()))

    def test_absent_options_leave_the_base(self):
        parts = [kernel(), b'r', b'', b'', section(dtb())]
        self.assertIsNone(builder.replace_kernel_and_dtb(parts, SimpleNamespace()))

    def test_same_release_and_matching_dtb_replace_both_sections(self):
        tree = dtb(b'with novatek')
        new_kernel, new_dtb = kernel(build=146, tree=tree), section(tree)
        parts = [kernel(), b'r', b'', b'', section(dtb())]
        with tempfile.TemporaryDirectory() as tmp:
            record = builder.replace_kernel_and_dtb(parts, self.args(tmp, new_kernel, new_dtb))
        self.assertEqual(parts[0], new_kernel)
        self.assertEqual(parts[4], new_dtb)
        self.assertEqual(record['release'], '7.2.0-a22x-recovery-diag1+')

    def test_refusals(self):
        tree = dtb(b'with novatek')
        base = [kernel(), b'r', b'', b'', section(dtb())]
        cases = [
            (kernel(release='7.2.0-other+', tree=tree), section(tree), {}),
            (kernel(build=146, tree=tree), section(dtb(b'different')), {}),
            (kernel(build=146, tree=tree), section(tree), {'kpin': '0' * 64}),
        ]
        for new_kernel, new_dtb, pins in cases:
            parts = list(base)
            with self.subTest(pins=pins), tempfile.TemporaryDirectory() as tmp, self.assertRaises(Exception):
                builder.replace_kernel_and_dtb(parts, self.args(tmp, new_kernel, new_dtb, **pins))
            self.assertEqual(parts, base)
        with self.assertRaises(Exception):
            builder.replace_kernel_and_dtb(list(base), SimpleNamespace(kernel_section=Path('/x'), kernel_section_sha256=None,
                                                                      dtb_section=None, dtb_section_sha256=None))


class Firmware(unittest.TestCase):
    def test_allowlist_names_pinned_firmware(self):
        self.assertEqual(set(builder.TOUCH_FIRMWARE), {'novatek_ts_fw.bin', 'Himax_firmware_fw_txd.bin'})
        for digest in builder.TOUCH_FIRMWARE.values():
            self.assertRegex(digest, r'^[0-9a-f]{64}$')


if __name__ == '__main__':
    unittest.main()
