"""Integration guards and real anonymous credential pipes; no device I/O."""
import fcntl
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import android_decrypt as ad
import decrypt_prepare as prep
import filesystem as fs

class FrontendTests(unittest.TestCase):
    def assert_code(self, code, operation):
        with self.assertRaises(Exception) as caught:
            operation()
        self.assertEqual(getattr(caught.exception, 'code', None), code)

    def test_real_device_mount_routes_credential_before_raw_mount_guard(self):
        context = object.__new__(fs.DeviceContext)
        volume = {'id': 'userdata', 'mountable': False, 'decrypt_supported': True}
        context.volume = lambda ident, expected: volume
        with patch.object(ad, 'mount', return_value={'routed': True}) as routed:
            self.assertEqual(context.mount('userdata', 'ro', False, 'token',
                credential_fd=77, android_user=0), {'routed': True})
            routed.assert_called_once_with(context, volume, 'ro', False, 77, 0)

    def test_device_plain_volume_rejects_unexpected_password_channel(self):
        context = object.__new__(fs.DeviceContext)
        context.volume = lambda ident, expected: {'id': 'sdcard-p1'}
        self.assert_code('UNSUPPORTED_PROFILE', lambda: context.mount(
            'sdcard-p1', 'ro', credential_fd=77))

    def test_fixture_dispatch_never_routes_credential(self):
        args = fs.parser().parse_args(['--fixture', '/synthetic', 'mount',
            '--volume', 'userdata', '--credential-fd', '77'])
        context = SimpleNamespace(mode='fixture', operation_lock=lambda shared=False: nullcontext())
        with patch.object(ad, 'mount') as route:
            self.assert_code('FIXTURE_CREDENTIAL_REFUSED', lambda: fs.dispatch(context, args))
            route.assert_not_called()

    def test_unsupported_modes_and_users_do_not_prepare_or_consume(self):
        context = SimpleNamespace(lock_fd=66)
        volume = {'decrypt_supported': True, 'decrypt_state': 'locked'}
        with patch.object(prep, 'prepare') as prepare:
            self.assert_code('WRITE_NOT_QUALIFIED', lambda:
                ad.mount(context, volume, 'rw', True, 77, 0))
            self.assert_code('UNSUPPORTED_PROFILE', lambda:
                ad.mount(context, volume, 'ro', False, 77, 10))
            self.assert_code('CREDENTIAL_REQUIRED', lambda:
                ad.mount(context, volume, 'ro', False, None, 0))
            prepare.assert_not_called()

    def test_native_read_pipe_is_validated_without_reading_a_byte(self):
        read, write = os.pipe2(os.O_CLOEXEC)
        credential = fcntl.fcntl(read, fcntl.F_DUPFD_CLOEXEC, 64)
        os.close(read)
        frame = struct.pack('<I', 16) + b'synthetic secret'
        try:
            os.write(write, frame); os.close(write); write = -1
            self.assertEqual(ad.credential_descriptor(credential), credential)
            self.assertEqual(os.read(credential, 100), frame)
        finally:
            os.close(credential)
            if write >= 0: os.close(write)

    def test_regular_file_and_pipe_writer_refused(self):
        with tempfile.TemporaryFile() as file:
            fd = fcntl.fcntl(file.fileno(), fcntl.F_DUPFD_CLOEXEC, 64)
            try:
                self.assert_code('INVALID_CREDENTIAL_CHANNEL', lambda: ad.credential_descriptor(fd))
            finally: os.close(fd)
        read, write = os.pipe2(os.O_CLOEXEC)
        fd = fcntl.fcntl(write, fcntl.F_DUPFD_CLOEXEC, 64)
        try:
            self.assert_code('INVALID_CREDENTIAL_CHANNEL', lambda: ad.credential_descriptor(fd))
        finally:
            os.close(fd); os.close(read); os.close(write)

    def ready(self, value):
        read, write = os.pipe2(os.O_CLOEXEC)
        try:
            os.write(write, value); os.close(write); write = -1
            return ad.read_ready(read, .1)
        finally:
            os.close(read)
            if write >= 0: os.close(write)

    def test_ready_pipe_is_bounded_typed_public_json(self):
        self.assertEqual(self.ready(b'{"ok":true}\n'), {'ok': True})
        for bad in (b'', b'{}', b'{"ok":1}', b'[]', b'{"ok":true}\n{}\n'):
            with self.assertRaises((ValueError, EOFError)):
                self.ready(bad)
        with patch.object(ad, 'MAX_PUBLIC', 16):
            with self.assertRaises(ValueError): self.ready(b'x' * 20)

    def test_stale_mounted_receipt_only_requires_reboot(self):
        context = SimpleNamespace(mode='device', boot_id='test-boot')
        volume = {'id': 'userdata', 'volume_token': 'physical', 'fs_type': None}
        with patch.object(ad, 'profile', return_value={'profile_id': 'samsung-a226b-a13'}), \
             patch.object(ad, 'session_status', side_effect=RuntimeError('stale')), \
             patch.object(ad, 'regular_json', return_value={
                 'boot_id': 'test-boot', 'state': 'mounted', 'ce_authenticated': True}):
            result = ad.decorate(context, [volume])[0]
        self.assertFalse(result['decrypt_supported'])
        self.assertEqual(result['decrypt_state'], 'reboot_required')
        self.assertNotIn('ce_authenticated', result)

    def test_authenticated_f2fs_receipt_has_bound_new_token(self):
        context = SimpleNamespace(mode='device', boot_id='test-boot')
        volume = {'id': 'userdata', 'volume_token': 'physical', 'fs_type': None,
                  'path': '/dev/mmcblk0p32', 'device': '179:32'}
        receipt = {'device': '253:7', 'run_id': 'test-run', 'mount_id': 19,
                   'profile_id': 'samsung-a226b-a13', 'credential_type': 'password'}
        node = SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(253, 7))
        with patch.object(ad, 'profile', return_value={'profile_id': 'samsung-a226b-a13'}), \
             patch.object(ad, 'session_status', return_value=receipt), \
             patch.object(ad.Path, 'resolve', return_value=Path('/sys/devices/virtual/block/dm-7')), \
             patch.object(ad.Path, 'lstat', return_value=node), \
             patch.object(ad.Path, 'read_text', return_value='1'):
            result = ad.decorate(context, [volume])[0]
        self.assertEqual(result['fs_type'], 'f2fs')
        self.assertEqual(result['mount_owner'], 'android-decrypt')
        self.assertTrue(result['ce_authenticated'])
        self.assertFalse(result['write_supported'])
        self.assertNotEqual(result['volume_token'], 'physical')
        self.assertEqual(result['physical_volume_token'], 'physical')

    def test_private_config_roundtrip_exclusive_and_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'config.json'
            obj = {'boot_id': 'synthetic', 'read_only': True}
            digest = prep.write_private(path, obj)
            self.assertEqual(json.loads(path.read_bytes()), obj)
            self.assertEqual(path.read_bytes()[-1:], b'\n')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(FileExistsError): prep.write_private(path, obj)

    def test_runtime_restores_pinned_modes_under_private_umask(self):
        import io, tarfile
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as archive:
                for name, mode, directory, data in (
                    ('rootfs', 0o755, True, b''),
                    ('rootfs/system', 0o755, True, b''),
                    ('rootfs/system/service', 0o555, False, b'synthetic'),
                    ('rootfs/system/public-data', 0o444, False, b'public'),
                    ('controller', 0o700, True, b'')):
                    member = tarfile.TarInfo(name); member.mode = mode
                    member.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
                    member.size = len(data); archive.addfile(member, io.BytesIO(data))
            old = os.umask(0o077)
            try:
                buffer.seek(0)
                with tarfile.open(fileobj=buffer) as archive:
                    members = archive.getmembers()
                    prep.extract_members(archive, root, members)
                    for member in members:
                        self.assertEqual(stat.S_IMODE((root/member.name).stat().st_mode), member.mode)
            finally:
                os.umask(old)

    def test_cli_canonical_module_keeps_error_type_identity(self):
        import subprocess
        code = r"""
import ast, contextlib, io, json, sys, types
from pathlib import Path
file = Path('filesystem.py').resolve()
source = ast.parse(file.read_text())
# Execute the actual CLI module setup and definitions, without calling main.
source.body = source.body[:-1]
module = types.ModuleType('__main__'); module.__file__ = str(file)
sys.modules['__main__'] = module
exec(compile(source, str(file), 'exec'), module.__dict__)
import android_decrypt
assert sys.modules['filesystem'] is module
try: android_decrypt.fail('SYNTHETIC_FAILURE', 'Synthetic adapter error')
except module.FilesystemError as error:
    assert error.code == 'SYNTHETIC_FAILURE'
else: raise AssertionError('Wrong error identity')
"""
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == '__main__':
    unittest.main()
