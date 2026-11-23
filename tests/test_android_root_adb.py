"""Root over adb carried to a new system: adb settings and keys, Magisk's rules, a one-time boot script."""
import base64
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest import mock

import android_migration as migration
import android_root_adb as root_adb
import filesystem as fs
from test_android_migration import PASSWORD, AndroidFixture, abx, target_xml

KEY = base64.b64encode(bytes(range(256)) * 2).decode() + ' owner@laptop'
OTHER_KEY = base64.b64encode(bytes(reversed(range(256))) * 2).decode() + ' other@desk'
MAGISK_DB = b'SQLite format 3\0' + bytes(4080)


class RootAdbTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.data, self.context = self.fixture('source')
        self.target, self.target_context = self.fixture('target')
        users = self.data / 'system/users/0'
        users.mkdir(parents=True)
        (users / 'settings_global.xml').write_text(
            '<settings><setting name="adb_enabled" value="1"/><setting name="development_settings_enabled" value="1"/>'
            '<setting name="wifi_on" value="1"/></settings>')
        (users / 'settings_system.xml').write_text('<settings><setting name="font_scale" value="1.25"/></settings>')
        (users / 'settings_secure.xml').write_text('<settings><setting name="long_press_timeout" value="600"/></settings>')
        (self.data / 'misc/adb').mkdir(parents=True)
        (self.data / 'misc/adb/adb_keys').write_text(KEY + '\n')
        (self.data / 'adb').mkdir()
        (self.data / 'adb/magisk.db').write_bytes(MAGISK_DB)
        (self.data / 'system/packages.xml').write_bytes(abx(uid=os.getuid()))
        (self.target / 'system/packages.xml').write_bytes(target_xml())
        (self.target / 'misc').mkdir()

    def fixture(self, name):
        root = self.root / name
        (root / 'data/system').mkdir(parents=True)
        (root / 'sd').mkdir()
        (root / 'filesystem-fixture.json').write_text(json.dumps({
            'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
                {'id': 'userdata', 'path': 'data', 'fs_type': 'f2fs', 'mounted': True, 'read_only': False},
                {'id': 'sdcard-p1', 'path': 'sd', 'fs_type': 'exfat', 'mounted': True, 'read_only': False},
            ]}))
        return root / 'data', AndroidFixture(root)

    def backup(self, **options):
        with self.context.operation_lock():
            return migration.create(self.context, self.context.volume('userdata')['volume_token'], [], False, 'sdcard-p1',
                                    self.context.volume('sdcard-p1')['volume_token'], PASSWORD, True, **options)

    def restore(self, result):
        path = result['path'].lstrip('/')
        copy = self.target.parent / 'sd' / path
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.data.parent / 'sd' / path, copy)
        context = self.target_context
        with context.operation_lock():
            return migration.restore_root_adb(context, 'sdcard-p1', context.volume('sdcard-p1')['volume_token'],
                                              result['path'], result['archive_sha256'],
                                              context.volume('userdata')['volume_token'], PASSWORD, True)

    def test_capture_and_restore_root_over_adb(self):
        result = self.backup(include_settings=True, include_root_adb=True)
        manifest = result['manifest']
        self.assertEqual(manifest['schema'], migration.ROOT_ADB_SCHEMA)
        item = next(item for item in manifest['items'] if item['kind'] == 'root-adb')
        self.assertEqual(item, {'kind': 'root-adb', 'global': {'adb_enabled': '1', 'development_settings_enabled': '1'},
                                'adb_keys': True, 'magisk_db': True})
        (self.target / 'misc/adb').mkdir()
        (self.target / 'misc/adb/adb_keys').write_text(OTHER_KEY + '\n')
        restored = self.restore(result)
        self.assertEqual(restored['written'], ['misc/adb/adb_keys', 'adb/a22x-migration/magisk.db',
                                               'adb/service.d/a22x-migration.sh'])
        self.assertEqual((self.target / 'misc/adb/adb_keys').read_text().split('\n'), [OTHER_KEY, KEY, ''])
        self.assertEqual((self.target / 'adb/a22x-migration/magisk.db').read_bytes(), MAGISK_DB)
        script = (self.target / 'adb/service.d/a22x-migration.sh').read_text()
        lines = script.splitlines()
        self.assertLess(lines.index('settings put global development_settings_enabled 1'),
                        lines.index('settings put global adb_enabled 1'))
        for line in ('settings put system font_scale 1.25', 'settings put secure long_press_timeout 600'):
            self.assertIn(line, lines)
        self.assertIn('WHERE uid=2000', script)
        self.assertNotIn('wifi_on', script)
        self.assertEqual(os.stat(self.target / 'adb/service.d/a22x-migration.sh').st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(self.target / 'misc/adb/adb_keys').st_mode & 0o777, 0o640)
        # A second restore keeps one copy of each key.
        self.restore(result)
        self.assertEqual((self.target / 'misc/adb/adb_keys').read_text().count(KEY), 1)

    def test_a_system_without_magisk_or_keys_and_refusals(self):
        (self.data / 'adb/magisk.db').unlink()
        result = self.backup(include_root_adb=True)
        item = next(item for item in result['manifest']['items'] if item['kind'] == 'root-adb')
        self.assertEqual((item['adb_keys'], item['magisk_db']), (True, False))
        shutil.rmtree(self.target / 'misc')
        with self.assertRaises(fs.FilesystemError) as error:
            self.restore(result)
        self.assertEqual(error.exception.code, 'ANDROID_NOT_STARTED')
        plain = self.backup(include_settings=True)
        with self.assertRaises(fs.FilesystemError) as absent:
            self.restore(plain)
        self.assertEqual(absent.exception.code, 'ROOT_ADB_ABSENT')

    def test_foreign_keys_file_is_refused_and_manifest_is_bound(self):
        (self.data / 'misc/adb/adb_keys').write_text('#!/bin/sh\nrm -rf /\n')
        with self.assertRaises(fs.FilesystemError) as error:
            self.backup(include_root_adb=True)
        self.assertEqual(error.exception.code, 'ROOT_ADB_INVALID')
        (self.data / 'misc/adb/adb_keys').write_text(KEY + '\n')
        manifest = self.backup(include_root_adb=True)['manifest']
        lying = json.loads(json.dumps(manifest))
        next(item for item in lying['items'] if item['kind'] == 'root-adb')['magisk_db'] = False
        with self.assertRaises(fs.FilesystemError):
            migration.validate_manifest(lying, lying['files'])

    def restore_first_boot(self, result, recovery_keys=False):
        path = result['path'].lstrip('/')
        copy = self.target.parent / 'sd' / path
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.data.parent / 'sd' / path, copy)
        context = self.target_context
        # The fixture's userdata stands for the fresh data this recovery mounted (fresh_userdata is tested alone).
        with context.operation_lock(), mock.patch.object(migration, 'boot_root', return_value='kernelsu'), \
                mock.patch.object(migration, 'fresh_userdata'):
            return migration.restore_root_adb(context, 'sdcard-p1', context.volume('sdcard-p1')['volume_token'],
                                              result['path'], result['archive_sha256'],
                                              context.volume('userdata')['volume_token'], PASSWORD, True,
                                              first_boot=True, recovery_keys=recovery_keys)

    def test_first_boot_with_kernelsu(self):
        result = self.backup(include_settings=True, include_root_adb=True)
        shutil.rmtree(self.target / 'misc')
        (self.target / 'system/packages.xml').unlink()
        (self.target / 'system').rmdir()
        (self.target.parent / 'run').mkdir()
        (self.target.parent / 'run/adb_keys').write_text(OTHER_KEY + '\n' + KEY + '\n')
        restored = self.restore_first_boot(result, recovery_keys=True)
        self.assertEqual(restored['written'], ['adb/ksu/.allowlist', 'adb/a22x-migration/adb_keys',
                                               'adb/a22x-migration/apply.sh', 'adb/a22x-migration/early-adb', 'adb/ksud'])
        self.assertIn('setprop sys.usb.config adb', (self.target / 'adb/ksud').read_text())
        self.assertEqual(restored['adb_keys'], 2)
        self.assertEqual((self.target / 'adb/a22x-migration/adb_keys').read_text().split('\n'), [KEY, OTHER_KEY, ''])
        allow = (self.target / 'adb/ksu/.allowlist').read_bytes()
        self.assertEqual((len(allow), struct.unpack_from('<IIIi?', allow, 0)[:2]), (784, (0x7f4b5355, 3)))
        profile = allow[8:]
        self.assertEqual(struct.unpack_from('<I', profile, 0)[0], 2)
        self.assertEqual(profile[4:22], b'com.android.shell\0')
        self.assertEqual(struct.unpack_from('<i?', profile, 260), (2000, True))
        self.assertEqual(profile[704:714], b'u:r:su:s0\0')
        apply = (self.target / 'adb/a22x-migration/apply.sh').read_text().splitlines()
        self.assertLess(apply.index('settings put global development_settings_enabled 1'),
                        apply.index('settings put global adb_enabled 1'))
        self.assertIn('settings put system font_scale 1.25', apply)
        self.assertNotIn('magisk', '\n'.join(apply))
        stand_in = (self.target / 'adb/ksud').read_text()
        self.assertIn(root_adb.STAND_IN_TOKEN, stand_in)
        self.assertEqual(os.stat(self.target / 'adb/ksud').st_mode & 0o777, 0o755)
        # Again over its own files: allowed; over KernelSU's own ksud or a started Android: refused.
        self.restore_first_boot(result)
        (self.target / 'adb/ksud').write_bytes(b'\x7fELF real ksud')
        with self.assertRaises(fs.FilesystemError) as present:
            self.restore_first_boot(result)
        self.assertEqual(present.exception.code, 'KERNELSU_DAEMON_PRESENT')
        (self.target / 'adb/ksud').unlink()
        (self.target / 'misc').mkdir()
        with self.assertRaises(fs.FilesystemError) as started:
            self.restore_first_boot(result)
        self.assertEqual(started.exception.code, 'ANDROID_ALREADY_STARTED')

    def test_first_boot_needs_kernelsu_and_fresh_data(self):
        result = self.backup(include_root_adb=True)
        path = result['path'].lstrip('/')
        copy = self.target.parent / 'sd' / path
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.data.parent / 'sd' / path, copy)
        context = self.target_context
        with context.operation_lock(), mock.patch.object(migration, 'boot_root', return_value=''):
            with self.assertRaises(fs.FilesystemError) as error:
                migration.restore_root_adb(context, 'sdcard-p1', context.volume('sdcard-p1')['volume_token'],
                                           result['path'], result['archive_sha256'],
                                           context.volume('userdata')['volume_token'], PASSWORD, True, first_boot=True)
        self.assertIn(error.exception.code, ('ROOT_REQUIRED', 'FRESH_DATA_REQUIRED'))
        with context.operation_lock(), self.assertRaises(fs.FilesystemError) as keys:
            migration.restore_root_adb(context, 'sdcard-p1', context.volume('sdcard-p1')['volume_token'],
                                       result['path'], result['archive_sha256'],
                                       context.volume('userdata')['volume_token'], PASSWORD, True, recovery_keys=True)
        self.assertEqual(keys.exception.code, 'INVALID_ARGUMENT')

    def test_fresh_userdata_is_this_recoverys_writable_f2fs(self):
        good = {'mounted': True, 'fs_type': 'f2fs', 'read_only': False, 'mount_owner': 'filesystem'}
        migration.fresh_userdata(good)
        for change in ({'mount_owner': 'android-decrypt'}, {'read_only': True}, {'fs_type': 'ext4'}, {'mounted': False}):
            with self.assertRaises(fs.FilesystemError):
                migration.fresh_userdata({**good, **change})

    def test_boot_script_only_takes_validated_values(self):
        script = root_adb.boot_script({'adb_enabled': '1'}, {'system': {'font_scale': '1.25'}}, magisk=False).decode()
        self.assertTrue(script.startswith('#!/system/bin/sh\n'))
        self.assertNotIn('magisk --sqlite', script)
        with self.assertRaises(fs.FilesystemError):
            root_adb.boot_script({'adb_enabled': '1; reboot'}, {}, magisk=False)
        with self.assertRaises(fs.FilesystemError):
            root_adb.boot_script({}, {'system': {'font_scale': '9'}}, magisk=False)


if __name__ == '__main__':
    unittest.main()


class NothingToCarry(RootAdbTest):
    def test_a_phone_without_adb_or_magisk_is_copied_without_the_item(self):
        # Root and adb is chosen by default (2026-11-20): a phone that never had adb settings, adb
        # keys or Magisk is copied as without it, instead of failing with ROOT_ADB_EMPTY.
        (self.data / 'adb/magisk.db').unlink()
        (self.data / 'misc/adb/adb_keys').unlink()
        settings = self.data / 'system/users/0/settings_global.xml'
        if settings.exists():
            settings.unlink()
        result = self.backup(include_settings=True, include_root_adb=True)
        self.assertFalse([item for item in result['manifest']['items'] if item['kind'] == 'root-adb'])
        self.assertNotIn('root-adb', json.dumps(result['manifest']['files']))
        self.assertNotEqual(result['manifest']['schema'], migration.ROOT_ADB_SCHEMA)
        self.assertIn('preferences', result['manifest'])
