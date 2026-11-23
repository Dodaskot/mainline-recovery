"""ELF/tar/kernel bytes fixtures for the real password-image module guards."""
import gzip
import importlib.util
import io
import lzma
import os
from pathlib import Path
import struct
import sys
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_decrypt_image as builder

RELEASE = '7.2.0-a22x-recovery-diag1+'
VERMAGIC = RELEASE + builder.QUALIFIED_VERMAGIC_SUFFIX


def kernel(release=RELEASE):
    data = bytearray(512); data[56:60] = b'ARMd'
    banner = ('Linux version ' + release + ' (fixture) #145 SMP PREEMPT\x00').encode()
    data[128:128+len(banner)] = banner
    return bytes(data)


def module(vermagic=VERMAGIC, machine=183, duplicate=False):
    names = b'\x00.shstrtab\x00.modinfo\x00'
    info = b'license=GPL\x00vermagic=' + vermagic.encode() + b'\x00'
    if duplicate: info += b'vermagic=' + vermagic.encode() + b'\x00'
    shoff, names_at = 64, 64 + 3 * 64
    info_at = names_at + len(names)
    data = bytearray(info_at + len(info))
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', data, 16, 1, machine, 1)
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<6H', data, 52, 64, 0, 0, 64, 3, 1)
    struct.pack_into('<IIQQQQIIQQ', data, shoff + 64, 1, 3, 0, 0, names_at, len(names), 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, shoff + 128, 11, 1, 0, 0, info_at, len(info), 0, 0, 1, 0)
    data[names_at:names_at+len(names)] = names
    data[info_at:] = info
    return bytes(data)


def archive(names=None, payload=None, symlink=None):
    stream = io.BytesIO(); names = names if names is not None else sorted(builder.WIFI_MEMBERS)
    with tarfile.open(fileobj=stream, mode='w:xz') as tar:
        for name in names:
            info = tarfile.TarInfo(name)
            if name == symlink:
                info.type = tarfile.SYMTYPE; info.linkname = '/outside'; tar.addfile(info)
            else:
                data = payload if payload is not None else module()
                info.size = len(data); tar.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def entry(name, data, mode=0o100644):
    return [[1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0], name, data]


class KernelModuleGuardTests(unittest.TestCase):
    def test_actual_release_comes_from_raw_or_compressed_kernel_bytes(self):
        data = kernel()
        for value in (data, gzip.compress(data, mtime=0), gzip.compress(data, mtime=0) + b'\xd0\x0d\xfe\xedfixture'):
            identity = builder.kernel_identity(value)
            self.assertEqual(identity['release'], RELEASE)
            self.assertEqual(identity['expected_vermagic'], VERMAGIC)
            self.assertEqual(identity['encoded_sha256'], builder.sha(value))
        self.assertEqual(builder.kernel_identity(data + data)['release'], RELEASE)
        for bad in (b'x'*512, kernel('other') + data, gzip.compress(data)[:-4], gzip.compress(data)+b'not-dtb'):
            with self.assertRaises(ValueError): builder.kernel_identity(bad)

    def test_elf_modinfo_architecture_and_section_bounds_are_real(self):
        data = module(); result = builder.elf_module(data, VERMAGIC)
        self.assertEqual(result['sha256'], builder.sha(data))
        for bad in (module(machine=62), module('7.2.0-a22x-recovery+ SMP preempt mod_unload aarch64'),
                    module(duplicate=True), data[:-1]):
            with self.assertRaises(ValueError): builder.elf_module(bad, VERMAGIC)
        bad = bytearray(data); struct.pack_into('<Q', bad, 40, len(data)+1)
        with self.assertRaises(ValueError): builder.elf_module(bytes(bad), VERMAGIC)
        # A strings-only implementation could accept this unrelated good string.
        bad = module('wrong') + b'\x00vermagic=' + VERMAGIC.encode() + b'\x00'
        with self.assertRaises(ValueError): builder.elf_module(bad, VERMAGIC)

    def test_exact_four_flat_regular_modules_and_no_duplicates(self):
        self.assertEqual(set(builder.wifi_module_archive(archive(), VERMAGIC)['modules']), builder.WIFI_MEMBERS)
        names = sorted(builder.WIFI_MEMBERS)
        bad_archives = [lzma.decompress(archive()), archive(names[:-1]), archive(names + [names[0]]), archive(names + ['extra.ko']),
                        archive(['../' + names[0]] + names[1:]), archive(symlink=names[0]),
                        archive(payload=module('wrong'))]
        for data in bad_archives:
            with self.assertRaises(ValueError): builder.wifi_module_archive(data, VERMAGIC)

    def test_wrong_inherited_wifi_rejected_matching_explicit_replacement_admitted(self):
        old = archive(payload=module('7.2.0-a22x-recovery+ SMP preempt mod_unload aarch64'))
        entries = [entry(builder.WIFI_PATH, old), entry('lib/modules/a22x_spmfw.ko', module())]
        before = [[list(fields), name, data] for fields, name, data in entries]
        with self.assertRaises(ValueError): builder.validate_kernel_modules(kernel(), entries)
        replacement = archive()
        result = builder.validate_kernel_modules(kernel(), entries, replacement)
        self.assertEqual(result['wifi']['archive_sha256'], builder.sha(replacement))
        self.assertEqual(result['wifi_source'], 'explicit-replacement')
        self.assertEqual(entries, before)  # Guard does not mutate kernel/CPIO entries.

    def test_other_wrong_cpio_module_cannot_hide_behind_wifi_replacement(self):
        entries = [entry(builder.WIFI_PATH, archive()), entry('lib/modules/other.ko', module('wrong'))]
        with self.assertRaises(ValueError): builder.validate_kernel_modules(kernel(), entries, archive())
        entries[-1] = entry('lib/modules/other.ko', b'target', 0o120777)
        with self.assertRaises(ValueError): builder.validate_kernel_modules(kernel(), entries, archive())

    @unittest.skipUnless(os.environ.get('A22X_DECRYPT_BASE_IMAGE') and os.environ.get('A22X_WIFI_MODULES'),
                         'Set pinned base and matching Wi-Fi archive for regression evidence')
    def test_actual_pinned_base_regression_and_rebuilt_modules(self):
        base = Path(os.environ['A22X_DECRYPT_BASE_IMAGE']).read_bytes()
        self.assertEqual(builder.sha(base), builder.BASE_SHA)
        _, parts, _ = builder.parse(base)
        entries = builder.read_cpio(lzma.decompress(parts[1]))
        with self.assertRaisesRegex(ValueError, 'vermagic'): builder.validate_kernel_modules(parts[0], entries)
        wifi = Path(os.environ['A22X_WIFI_MODULES']).read_bytes()
        self.assertEqual(builder.sha(wifi), '985017c54185ec7876ec75eac2ecd28f3a5376638199e19ee6a4df8c5bbe7639')
        result = builder.validate_kernel_modules(parts[0], entries, wifi)
        self.assertEqual(result['kernel']['release'], RELEASE)
        self.assertEqual(set(result['wifi']['modules']), builder.WIFI_MEMBERS)
        self.assertIn('lib/modules/a22x_spmfw.ko', result['cpio_modules'])

if __name__ == '__main__': unittest.main()
