"""Installing a Magisk module ZIP from its file page (2026-11-21); temporary directories only."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_modules as am
import filesystem as fs


def module_zip(path, ident='hello', extra=None, customize=None, link=False):
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr('META-INF/com/google/android/update-binary', '#!/sbin/sh\n# the module installer of Magisk\n')
        z.writestr('META-INF/com/google/android/updater-script', '#MAGISK\n')
        z.writestr('module.prop', f'id={ident}\nname=Hello\nversion=v2\nversionCode=2\nauthor=Fixture\ndescription=Says hello\n')
        z.writestr('service.sh', '#!/system/bin/sh\nexit 0\n')
        z.writestr('system/bin/hello', '#!/system/bin/sh\necho hello\n')
        z.writestr('system/etc/hello.conf', 'greeting=hello\n')
        z.writestr('README.md', 'not installed\n')
        if customize is not None:
            z.writestr('customize.sh', customize)
        for name, data in (extra or {}).items():
            z.writestr(name, data)
        if link:
            info = zipfile.ZipInfo('system/bin/link')
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, '/system/bin/sh')


class Install(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='a22x-module-install-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data, self.sd = self.root / 'data', self.root / 'sd'
        self.data.mkdir()
        (self.sd / 'Download').mkdir(parents=True)
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
            {'id': 'userdata', 'path': 'data', 'fs_type': 'ext4', 'mounted': True, 'read_only': False},
            {'id': 'sdcard-p1', 'path': 'sd', 'fs_type': 'ext4', 'mounted': True, 'read_only': False}]}))
        self.context = fs.FixtureContext(self.root)
        assets = self.data / 'adb/magisk'
        assets.mkdir(parents=True)
        util, binary = b"MAGISK_VER='31.0'\nMAGISK_VER_CODE=31000\n", b'fixture-only Magisk executable, never executed'
        (assets / 'util_functions.sh').write_bytes(util)
        (assets / 'magisk').write_bytes(binary)
        rule = dict(am.MAGISK_31000, util_sha256=hashlib.sha256(util).hexdigest(), magisk_sha256=hashlib.sha256(binary).hexdigest())
        for target, value in ((am, 'MAGISK_ADAPTERS'),):
            patch = mock.patch.object(target, value, (rule,))
            patch.start()
            self.addCleanup(patch.stop)
        boot = {'kind': 'android', 'root': 'magisk', 'sha256': '1' * 64,
                'magisk_sha256': rule['magisk_sha256'], 'init_sha256': rule['init_sha256']}
        patch = mock.patch.object(am, '_boot_identity', return_value=boot)
        patch.start()
        self.addCleanup(patch.stop)
        self.token = self.context.volume('sdcard-p1')['volume_token']

    def preview(self, name='hello.zip'):
        return am.install_preview(self.context, 'sdcard-p1', self.token, '/Download/' + name)['plan']

    def install(self, name='hello.zip', plan=None):
        plan = plan or self.preview(name)
        return am.install(self.context, 'sdcard-p1', self.token, '/Download/' + name, plan['plan_sha256'], True)

    def test_a_module_goes_to_modules_update_with_its_marker_for_the_app(self):
        module_zip(self.sd / 'Download/hello.zip')
        plan = self.preview()
        self.assertTrue(plan['allowed'], plan['reason'])
        self.assertEqual((plan['module']['id'], plan['module']['version_code'], plan['module']['files']), ('hello', 2, 4))
        self.assertEqual(plan['module']['boot_content'], ['service.sh'])
        done = self.install(plan=plan)
        self.assertEqual(done['status'], 'applied')
        staged = self.data / 'adb/modules_update/hello'
        self.assertEqual(sorted(str(p.relative_to(staged)) for p in staged.rglob('*') if p.is_file()),
                         ['module.prop', 'service.sh', 'system/bin/hello', 'system/etc/hello.conf'])
        self.assertEqual(stat.S_IMODE((staged / 'system/bin/hello').stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((staged / 'system/etc/hello.conf').stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((staged / 'service.sh').stat().st_mode), 0o755)
        self.assertFalse((staged / 'README.md').exists() or (staged / 'META-INF').exists())
        active = self.data / 'adb/modules/hello'
        self.assertTrue((active / 'update').is_file())
        self.assertIn('version=v2', (active / 'module.prop').read_text())
        journal = json.loads((self.data / ('adb/a22x-recovery-module-rescue/' + done['journal']['path'].rsplit('/', 1)[-1])).read_text())
        self.assertEqual(journal['status'], 'applied')
        # Listed afterwards as a pending update.
        listed = am.inventory(self.context)
        self.assertTrue(any(m['id'] == 'hello' for m in listed['modules']))

    def test_an_update_replaces_the_pending_one_and_keeps_it_in_the_journal(self):
        module_zip(self.sd / 'Download/hello.zip')
        self.install()
        (self.sd / 'Download/hello.zip').unlink()
        module_zip(self.sd / 'Download/hello.zip', extra={'system/etc/new.conf': 'new\n'})
        self.install()
        self.assertTrue((self.data / 'adb/modules_update/hello/system/etc/new.conf').is_file())
        kept = list((self.data / 'adb/a22x-recovery-module-rescue').glob('*.previous'))
        self.assertEqual(len(kept), 1)
        self.assertFalse((kept[0] / 'system/etc/new.conf').exists())

    def test_unsafe_or_unsupported_zips_are_refused_before_anything_is_written(self):
        cases = {'link.zip': dict(link=True, code='MODULE_ZIP_UNSAFE'),
                 'skip.zip': dict(customize='SKIPUNZIP=1\nunzip -o "$ZIPFILE" -d $MODPATH\n', code='MODULE_CUSTOM_INSTALL'),
                 'legacy.zip': dict(extra={'install.sh': 'SKIPMOUNT=false\n'}, code='MODULE_LEGACY_INSTALLER')}
        for name, case in cases.items():
            with self.subTest(name=name):
                code = case.pop('code')
                module_zip(self.sd / 'Download' / name, **case)
                with self.assertRaises(fs.FilesystemError) as caught:
                    self.preview(name)
                self.assertEqual(caught.exception.code, code)
        with zipfile.ZipFile(self.sd / 'Download/rom.zip', 'w') as z:
            z.writestr('META-INF/com/google/android/update-binary', '#!/sbin/sh\n')
            z.writestr('system.img', b'\0' * 64)
        with self.assertRaises(fs.FilesystemError) as caught:
            self.preview('rom.zip')
        self.assertEqual(caught.exception.code, 'NOT_A_MODULE')
        self.assertFalse((self.data / 'adb/modules_update').exists())

    def test_a_customize_script_is_named_and_not_run(self):
        module_zip(self.sd / 'Download/hello.zip', customize='ui_print "Hello"\nset_perm $MODPATH/system/bin/hello 0 0 0755\n')
        plan = self.preview()
        self.assertTrue(plan['allowed'])
        self.assertEqual(plan['module']['not_run'], ['customize.sh'])
        self.assertTrue(any('customize.sh' in w for w in plan['warnings']))
        self.install(plan=plan)
        self.assertFalse((self.data / 'adb/modules_update/hello/customize.sh').exists())

    def test_without_a_reviewed_magisk_or_with_kernelsu_nothing_is_installed(self):
        module_zip(self.sd / 'Download/hello.zip')
        (self.data / 'adb/ksu').mkdir()
        # BOOT carries KernelSU without its reviewed ksud: the Magisk directory is a leftover, nothing installs
        identity = mock.patch.object(am, '_boot_identity', return_value={'kind': 'android', 'root': 'kernelsu', 'sha256': '2' * 64})
        identity.start()
        plan = self.preview()
        self.assertFalse(plan['allowed'])
        with self.assertRaises(fs.FilesystemError) as caught:
            self.install(plan=plan)
        self.assertEqual(caught.exception.code, 'MODULE_ACTION_UNSUPPORTED')
        identity.stop()
        (self.data / 'adb/ksu').rmdir()
        (self.data / 'adb/ksu').mkdir()
        (self.data / 'adb/ksu').rmdir()
        (self.data / 'adb/magisk/magisk').write_bytes(b'another build')
        self.assertFalse(self.preview()['allowed'])

    def kernelsu(self):
        for name in ('util_functions.sh', 'magisk'):
            (self.data / 'adb/magisk' / name).unlink()
        (self.data / 'adb/magisk').rmdir()
        (self.data / 'adb/ksu').mkdir()
        (self.data / 'adb/ksud').write_bytes(b'fixture ksud')
        rule = dict(am.KERNELSU_NEXT_33555, ksud_sha256=hashlib.sha256(b'fixture ksud').hexdigest())
        for target, value, new in ((am, 'KERNELSU_ADAPTERS', (rule,)),
                                   (am, '_boot_identity', mock.Mock(return_value={'kind': 'android', 'root': 'kernelsu', 'sha256': '2' * 64}))):
            patch = mock.patch.object(target, value, new)
            patch.start()
            self.addCleanup(patch.stop)

    def test_kernelsu_next_gets_the_layout_its_ksud_moves_in(self):
        """ksud's install_module_to_system: modules_update/ID, and modules/ID with module.prop and an update marker."""
        self.kernelsu()
        module_zip(self.sd / 'Download/hello.zip')
        plan = self.preview()
        self.assertTrue(plan['allowed'], plan['reason'])
        result = self.install(plan=plan)
        self.assertIn('KernelSU Next', result['activation'])
        self.assertTrue((self.data / 'adb/modules_update/hello/system/bin/hello').is_file())
        self.assertEqual(sorted(p.name for p in (self.data / 'adb/modules/hello').iterdir()), ['module.prop', 'update'])

    def test_kernelsu_without_a_metamodule_is_told_system_files_stay_unmounted(self):
        """Live 2026-11-22 (KernelSU Next 33555): scripts ran, system/etc/... did not appear without a metamodule."""
        self.kernelsu()
        module_zip(self.sd / 'Download/hello.zip')
        plan = self.preview()
        self.assertTrue(plan['allowed'])
        self.assertTrue(plan['mount_needs_metamodule'])
        self.assertTrue(any('metamodule' in w for w in plan['warnings']))
        path = self.sd / 'Download/scripts.zip'
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr('module.prop', 'id=scripts\nname=Scripts\nversion=v1\nversionCode=1\n')
            z.writestr('service.sh', '#!/system/bin/sh\nexit 0\n')
        self.assertNotIn('mount_needs_metamodule', self.preview('scripts.zip'))

    def test_magisk_mounts_system_files_itself(self):
        module_zip(self.sd / 'Download/hello.zip')
        self.assertNotIn('mount_needs_metamodule', self.preview())

    def test_kernelsu_metamodules_go_through_the_manager(self):
        self.kernelsu()
        path = self.sd / 'Download/meta2.zip'
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr('module.prop', 'id=meta_overlayfs\nname=Meta\nversion=v1\nversionCode=1\nmetamodule=1\n')
            z.writestr('metamount.sh', '#!/bin/sh\n')
        self.assertIn('metamodule', self.preview('meta2.zip')['reason'])
        installed = self.data / 'adb/modules/meta_overlayfs'
        installed.mkdir(parents=True)
        (installed / 'module.prop').write_text('id=meta_overlayfs\nname=Meta\nversion=v1\nversionCode=1\nmetamodule=1\n')
        module_zip(self.sd / 'Download/hello.zip')
        self.assertIn('metamodule is installed', self.preview()['reason'])

    def test_a_changed_zip_after_the_review_is_refused(self):
        module_zip(self.sd / 'Download/hello.zip')
        plan = self.preview()
        (self.sd / 'Download/hello.zip').unlink()
        module_zip(self.sd / 'Download/hello.zip', extra={'system/etc/other.conf': 'x\n'})
        with self.assertRaises(fs.FilesystemError) as caught:
            self.install(plan=plan)
        self.assertEqual(caught.exception.code, 'MODULE_PLAN_CHANGED')
        self.assertFalse((self.data / 'adb/modules_update/hello').exists())

    def test_a_failure_while_unpacking_leaves_the_pending_update_as_it_was(self):
        module_zip(self.sd / 'Download/hello.zip')
        self.install()
        before = sorted(p.name for p in (self.data / 'adb/modules_update/hello').rglob('*'))
        (self.sd / 'Download/hello.zip').unlink()
        module_zip(self.sd / 'Download/hello.zip', extra={'system/etc/new.conf': 'new\n'})
        plan = self.preview()
        with mock.patch.object(am, '_unpack', side_effect=OSError('card removed')):
            with self.assertRaises(fs.FilesystemError) as caught:
                self.install(plan=plan)
        self.assertEqual(caught.exception.code, 'MODULE_TRANSACTION_INCOMPLETE')
        self.assertEqual(sorted(p.name for p in (self.data / 'adb/modules_update/hello').rglob('*')), before)
        self.assertEqual(list((self.data / 'adb/a22x-recovery-module-rescue').glob('*.stage')), [])

    def test_the_command_line(self):
        module_zip(self.sd / 'Download/hello.zip')
        out = io.StringIO()
        with mock.patch('sys.stdout', out):
            code = am.main(['--fixture', str(self.root), 'install-preview', '--source-volume', 'sdcard-p1',
                            '--source-token', self.token, '--source-path', '/Download/hello.zip'])
        result = json.loads(out.getvalue())
        self.assertEqual((code, result['ok'], result['plan']['module_id']), (0, True, 'hello'))


if __name__ == '__main__':
    unittest.main()
