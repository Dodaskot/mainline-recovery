"""A GSI installed from the recovery (android_gsi.py, 2026-11-10): system.img from Google's GSI ZIP
into super/system, its vbmeta.img into vbmeta, userdata reset for Android; refused on a Linux BOOT."""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
import unittest.mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import android_gsi as ag  # noqa: E402
import test_bootimage as tb  # noqa: E402
import test_lp_metadata as tl  # noqa: E402
from test_flash import boot_image, vbmeta  # noqa: E402

MIB = 1 << 20


def stock_boot():
    props = {'ro.product.bootimage.device': 'a22x', 'ro.product.bootimage.model': 'SM-A226B'}
    return tb.boot(tb.kernel('4.14.186-27218697'), tb.ramdisk(props), tb.dt_table(tb.fdt('MT6833', ['mediatek,MT6833'])))


class Gsi(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-gsi-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.root, True)
        for name in ('targets', 'cache/a22x-recovery', 'data/.a22x-images'):
            (self.root / name).mkdir(parents=True)
        tl.make_super(self.root / 'targets/super')
        boot = bytearray(4 * MIB)
        image = stock_boot()
        boot[:len(image)] = image
        (self.root / 'targets/boot').write_bytes(bytes(boot))
        (self.root / 'targets/vbmeta').write_bytes(vbmeta(b'stock') + bytes((1 << 16) - 325))
        (self.root / 'install-fixture.json').write_text(json.dumps({
            'schema': 'a22x.install.fixture.v1', 'device': {'model': 'SM-A226B', 'identity': 'fixture:test'},
            'targets': {'super': {'path': 'targets/super', 'size_bytes': 64 * MIB}, 'boot': {'path': 'targets/boot', 'size_bytes': 4 * MIB},
                        'vbmeta': {'path': 'targets/vbmeta', 'size_bytes': 1 << 16}}}))
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
            {'id': 'cache', 'path': 'cache', 'fs_type': 'ext4', 'mounted': True, 'read_only': True},
            {'id': 'userdata', 'path': 'data', 'fs_type': 'ext4', 'mounted': True, 'read_only': False}]}))
        (self.root / 'cache/old.log').write_text('old')
        self.system = bytearray(os.urandom(5 * MIB))
        struct.pack_into('<H', self.system, 1080, 0xEF53)
        self.vbmeta = bytearray(vbmeta(b'g' * 700))
        struct.pack_into('>I', self.vbmeta, 120, 2)  # verification disabled, as Google ships it
        self.gsi = self.root / 'data/.a22x-images/aosp_arm64-exp-TQ3A.zip'
        with zipfile.ZipFile(self.gsi, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('system.img', bytes(self.system))
            z.writestr('vbmeta.img', bytes(self.vbmeta))
            z.writestr('build.prop', 'ro.build.version.release=13\nro.build.version.sdk=33\nro.build.id=TQ3A.230805.001.A3\n'
                                     'ro.build.version.security_patch=2023-08-05\n')

    def run_helper(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = ag.main(['--fixture', str(self.root), *args])
        return code, json.loads(stdout.getvalue().splitlines()[-1]), stderr.getvalue()

    def token(self):
        import filesystem as fs
        return fs.FixtureContext(self.root).volume('userdata')['volume_token']

    def inspect(self):
        return self.run_helper('inspect', '--volume', 'userdata', '--volume-token', self.token(), '--path', '/.a22x-images/' + self.gsi.name)

    def install(self, plan):
        return self.run_helper('install', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                               '/.a22x-images/' + self.gsi.name, '--expected-plan', plan, '--confirm')

    def test_flash_check_distinguishes_the_package_digest_from_its_system_member(self):
        context = ag.install.FixtureContext(self.root)
        member_digest = hashlib.sha256(self.system).hexdigest()
        package_digest = hashlib.sha256(self.gsi.read_bytes()).hexdigest()
        args = argparse.Namespace(target='super/system', volume='userdata', volume_token=self.token(),
                                  path='/.a22x-images/' + self.gsi.name, member='system.img',
                                  expected_source_sha256=package_digest)
        checked = ag.flash.check(context, args, ag.quiet)
        self.assertEqual(checked['image']['sha256'], member_digest)
        args.expected_source_sha256 = member_digest
        with self.assertRaises(ag.fs.FilesystemError) as error:
            ag.flash.check(context, args, ag.quiet)
        self.assertEqual(error.exception.code, 'IMAGE_CHANGED')
        args.expected_source_sha256 = package_digest
        args.expected_source_identity = '0' * 64
        with self.assertRaises(ag.fs.FilesystemError) as error:
            ag.flash.check(context, args, ag.quiet)
        self.assertEqual(error.exception.code, 'IMAGE_CHANGED')

    def test_a_google_gsi_goes_into_system_and_vbmeta(self):
        code, plan, _ = self.inspect()
        self.assertEqual(code, 0, plan)
        self.assertEqual((plan['android'], plan['sdk'], plan['fits'], plan['boot'], plan['blockers']), ('13', 33, True, 'android', []))
        self.assertEqual([(w['target'], w['member']) for w in plan['writes']], [('super/system', 'system.img'), ('vbmeta', 'vbmeta.img')])
        code, done, _ = self.install(plan['plan_sha256'])
        self.assertEqual(code, 0, done)
        import lp_metadata as lp
        fd = os.open(self.root / 'targets/super', os.O_RDONLY)
        self.addCleanup(os.close, fd)
        written = b''.join(lp.Super(fd).chunks('system'))
        self.assertEqual(written[:len(self.system)], bytes(self.system))
        self.assertEqual((self.root / 'targets/vbmeta').read_bytes()[:len(self.vbmeta)], bytes(self.vbmeta))
        self.assertTrue((self.root / 'android-reset.json').exists())
        self.assertFalse((self.root / 'cache/old.log').exists())
        self.assertTrue((self.root / 'cache/a22x-recovery').is_dir())

    def test_a_linux_boot_asks_for_stock_android_first(self):
        boot = bytearray(4 * MIB)
        image = boot_image()
        boot[:len(image)] = image
        (self.root / 'targets/boot').write_bytes(bytes(boot))
        code, plan, _ = self.inspect()
        self.assertEqual(code, 0, plan)
        self.assertEqual((plan['boot'], plan['blockers']), ('linux', ['STOCK_ANDROID_FIRST']))
        code, refused, _ = self.install(plan['plan_sha256'])
        self.assertEqual((code, refused['error']['code']), (2, 'PLAN_BLOCKED'))
        self.assertFalse((self.root / 'android-reset.json').exists())

    def test_over_linux_the_stock_boot_kept_on_cache_goes_on_boot(self):
        """2026-11-10: with Linux on BOOT, Samsung's BOOT kept on cache (taken out of the firmware, or
        saved by the app) is written too, last; the Linux BOOT is kept on cache first."""
        import hashlib
        linux = bytearray(4 * MIB)
        image = boot_image()
        linux[:len(image)] = image
        (self.root / 'targets/boot').write_bytes(bytes(linux))
        stock = bytearray(4 * MIB)
        image = stock_boot()
        stock[:len(image)] = image
        folder = self.root / 'cache/a22x-recovery/saved-boot'
        folder.mkdir(parents=True)
        name = 'stock-A226BXXSBDZC3-' + hashlib.sha256(bytes(stock)).hexdigest()[:12] + '.img'
        (folder / name).write_bytes(bytes(stock))
        (folder / (name + '.json')).write_text(json.dumps({'schema': 'a22x.saved-boot.v1', 'kind': 'android', 'release': '4.14.186-27218697',
                                                          'build': 'A226BXXSBDZC3', 'sha256': hashlib.sha256(bytes(stock)).hexdigest(),
                                                          'bytes': len(stock), 'saved': 1}))
        code, plan, _ = self.inspect()
        self.assertEqual(code, 0, plan)
        self.assertEqual((plan['boot'], plan['blockers']), ('linux', []))
        self.assertEqual([w['target'] for w in plan['writes']], ['super/system', 'vbmeta', 'boot'])
        code, done, _ = self.install(plan['plan_sha256'])
        self.assertEqual(code, 0, done)
        self.assertEqual((self.root / 'targets/boot').read_bytes(), bytes(stock))
        kept = [p.name for p in folder.iterdir() if p.name.startswith('linux-') and p.name.endswith('.img')]
        self.assertEqual(len(kept), 1)
        self.assertEqual((folder / kept[0]).read_bytes(), bytes(linux))

    @unittest.skipUnless(shutil.which('7z'), '7-Zip makes the archive')
    def test_a_lineageos_7z_without_vbmeta_gets_verification_disabled(self):
        """2026-11-10: LineageOS ships its GSI as one image in a .7z, without vbmeta.img: the image is
        decoded from the 7z, and an empty vbmeta with verification disabled is written first."""
        import subprocess
        work = self.root / 'src'
        work.mkdir()
        (work / 'LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img').write_bytes(bytes(self.system))
        archive = self.root / 'data/.a22x-images/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.7z'
        subprocess.run(['7z', 'a', '-t7z', '-m0=lzma2', str(archive), 'LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img'], cwd=work,
                       check=True, stdout=subprocess.DEVNULL)
        self.gsi.unlink()
        self.gsi = archive
        code, plan, _ = self.inspect()
        self.assertEqual(code, 0, plan)
        self.assertEqual(plan['blockers'], [])
        self.assertEqual([(w['target'], w.get('generate')) for w in plan['writes']], [('super/system', None), ('vbmeta', 'vbmeta-disabled')])
        code, done, _ = self.install(plan['plan_sha256'])
        self.assertEqual(code, 0, done)
        vb = (self.root / 'targets/vbmeta').read_bytes()
        self.assertEqual((vb[:4], struct.unpack('>I', vb[120:124])[0]), (b'AVB0', 2))
        import lp_metadata as lp
        fd = os.open(self.root / 'targets/super', os.O_RDONLY)
        self.addCleanup(os.close, fd)
        self.assertEqual(b''.join(lp.Super(fd).chunks('system'))[:len(self.system)], bytes(self.system))

    def test_android_15_and_newer_is_warned_about_this_phones_kernel(self):
        """2026-11-12, on the owner's phone: Google's Android 15 restarted for ever ("Android V requires
        kernel 4.19"; the phone's Android kernel is 4.14), and the review had said nothing. It is a
        warning, not a refusal: ROMs made for older phones start."""
        for sdk, warned in (('34', False), ('35', True), ('36', True)):
            with zipfile.ZipFile(self.gsi, 'w') as z:
                z.writestr('system.img', bytes(self.system))
                z.writestr('vbmeta.img', b'AVB0' + bytes(252))
                z.writestr('build.prop', 'ro.build.version.release=x\nro.build.version.sdk=%s\n' % sdk)
            code, plan, _ = self.inspect()
            self.assertEqual(code, 0, plan)
            self.assertEqual(ag.OLD_KERNEL_WARNING in plan['warnings'], warned, sdk)
            self.assertNotIn('KERNEL', ' '.join(plan['blockers']))
        self.assertLess(len(ag.OLD_KERNEL_WARNING.encode()), 200)   # the interface reads a warning into 200 bytes
        self.assertTrue(ag.kernel_older('4.14.186-27218697', (4, 19)) and ag.kernel_older('', (4, 19)))
        self.assertFalse(ag.kernel_older('4.19.191-1', (4, 19)) or ag.kernel_older('5.10.209', (4, 19)))

    def test_newer_android_warns_and_an_image_without_vbmeta_needs_it_disabled(self):
        with zipfile.ZipFile(self.gsi, 'w') as z:
            z.writestr('system.img', bytes(self.system))
            z.writestr('build.prop', 'ro.build.version.release=16\nro.build.version.sdk=36\n')
        code, plan, _ = self.inspect()
        self.assertEqual(code, 0, plan)
        self.assertFalse(plan['fits'])
        self.assertIn('Made for newer vendors: it may not start on this phone', plan['warnings'])
        self.assertEqual(plan['blockers'], [])
        self.assertEqual([w['target'] for w in plan['writes']], ['super/system', 'vbmeta'])  # an empty one, verification off
        disabled = bytearray((self.root / 'targets/vbmeta').read_bytes())
        struct.pack_into('>I', disabled, 120, 2)
        (self.root / 'targets/vbmeta').write_bytes(bytes(disabled))
        code, plan, _ = self.inspect()
        self.assertEqual(plan['blockers'], [])
        self.assertEqual([w['target'] for w in plan['writes']], ['super/system'])


if __name__ == '__main__':
    unittest.main()


class RomKind(unittest.TestCase):
    """2026-11-11: a ROM chosen from a file on a card opens the review that installs it."""
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-romkind-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / 'usb').mkdir()
        (self.root / 'install-fixture.json').write_text(json.dumps({
            'schema': 'a22x.install.fixture.v1', 'device': {'model': 'SM-A226B', 'identity': 'fixture:test'}, 'targets': {}}))
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
            {'id': 'usb-p1', 'path': 'usb', 'fs_type': 'exfat', 'mounted': True, 'read_only': True}]}))

    def kind(self, name):
        import filesystem as fs
        token = fs.FixtureContext(self.root).volume('usb-p1')['volume_token']
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = ag.main(['--fixture', str(self.root), 'classify', '--volume', 'usb-p1', '--volume-token', token, '--path', '/' + name])
        result = json.loads(stdout.getvalue().splitlines()[-1])
        return result['kind'] if code == 0 else result['error']['code']

    def zipped(self, name, members):
        with zipfile.ZipFile(self.root / 'usb' / name, 'w', zipfile.ZIP_DEFLATED) as z:
            for member, data in members.items():
                z.writestr(member, data)
        return name

    def test_each_kind_of_file_is_told_apart(self):
        import gzip
        import lzma
        system = bytearray(2 * MIB)
        struct.pack_into('<H', system, 1080, 0xEF53)
        erofs = bytearray(2 * MIB)
        struct.pack_into('<I', erofs, 1024, 0xE0F5E1E2)
        self.assertEqual(self.kind(self.zipped('lineage-a22x.zip', {
            'META-INF/com/google/android/update-binary': b'\x7fELF', 'META-INF/com/google/android/updater-script': b'', 'system.new.dat.br': b'x'})), 'installer')
        self.assertEqual(self.kind(self.zipped('Magisk-v31.1.zip', {'META-INF/com/google/android/update-binary': b'#!/sbin/sh\n'})), 'installer')
        self.assertEqual(self.kind(self.zipped('aosp_arm64-exp.zip', {'system.img': bytes(system), 'vbmeta.img': b'AVB0'})), 'gsi')
        self.assertEqual(self.kind(self.zipped('SM-A226B_firmware.zip', {'AP_A226BXXSBDYA1.tar.md5': b'x', 'BL_A226B.tar.md5': b'y'})), 'samsung')
        self.assertEqual(self.kind(self.zipped('ota-ab.zip', {'payload.bin': b'CrAU', 'payload_properties.txt': b''})), 'payload')
        self.assertEqual(self.kind(self.zipped('photos.zip', {'a.jpg': b'x', 'vbmeta.img': b'AVB0'})), 'unknown')
        (self.root / 'usb' / 'system.img').write_bytes(bytes(system))
        (self.root / 'usb' / 'lineage-gsi.img.xz').write_bytes(lzma.compress(bytes(erofs)))
        (self.root / 'usb' / 'lineage-gsi.img.gz').write_bytes(gzip.compress(bytes(system)))
        (self.root / 'usb' / 'notes.txt').write_text('no image at all\n' * 4000)
        (self.root / 'usb' / 'movie.gz').write_bytes(gzip.compress(os.urandom(1 << 16)))
        self.assertEqual([self.kind(n) for n in ('system.img', 'lineage-gsi.img.xz', 'lineage-gsi.img.gz')], ['gsi', 'gsi', 'gsi'])
        self.assertEqual([self.kind(n) for n in ('notes.txt', 'movie.gz')], ['unknown', 'unknown'])
        tar = bytearray(1024)
        tar[257:262] = b'ustar'
        (self.root / 'usb' / 'AP_A226B.tar.md5').write_bytes(bytes(tar))
        self.assertEqual(self.kind('AP_A226B.tar.md5'), 'samsung')
        self.assertEqual(self.kind('missing.img'), 'IO_ERROR')  # no such file: the page says so


class KeepData(Gsi):
    """An update that keeps Android's data (2026-11-21): only for a qualified pair, with a copy of
    BOOT, the vbmetas and super kept first on a card; nothing of userdata, metadata or cache erased."""

    def setUp(self):
        super().setUp()
        (self.root / 'sd').mkdir()
        fixture = json.loads((self.root / 'filesystem-fixture.json').read_text())
        fixture['volumes'].append({'id': 'sdcard-p1', 'path': 'sd', 'fs_type': 'exfat', 'mounted': True, 'read_only': False,
                                   'external': True})
        (self.root / 'filesystem-fixture.json').write_text(json.dumps(fixture))
        (self.root / 'data/app-data.txt').write_text('kept')
        self.copies = []

        def copy(volume, progress):
            self.copies.append(volume)
            return {'volume': volume, 'path': '/A22xAndroidBackups/android-test', 'manifest_sha256': 'c' * 64}
        patcher = unittest.mock.patch.object(ag, 'rollback_copy', copy)
        patcher.start()
        self.addCleanup(patcher.stop)

    def inspect_keep(self, *more):
        return self.run_helper('inspect', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                               '/.a22x-images/' + self.gsi.name, '--keep-data', '--rollback-volume', 'sdcard-p1', *more)

    def disable_avb_verification(self):
        path = self.root / 'targets/vbmeta'
        current = bytearray(path.read_bytes())
        struct.pack_into('>I', current, 120, 3)
        path.write_bytes(current)
        return current

    def qualify(self, plan, platform=None):
        pair = {'source_manifest_sha256': plan['keep_data']['source_system_sha256'],
                'target_package_sha256': plan['keep_data']['target_sha256'],
                'target_package_bytes': self.gsi.stat().st_size, 'evidence': 'test',
                'platforms': [platform if platform is not None else plan['keep_data']['platform']]}
        patcher = unittest.mock.patch.object(ag.android_transitions, 'QUALIFIED_TRANSITIONS', (pair,))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_an_unqualified_pair_is_refused_and_says_why(self):
        code, plan, _ = self.inspect_keep()
        self.assertEqual(code, 0)
        self.assertIn('PAIR_NOT_QUALIFIED', plan['blockers'])
        self.assertEqual(plan['erase'], [])
        self.assertFalse(plan['keep_data']['qualified'])
        self.assertIsNone(plan['keep_data']['source_system_sha256'])  # nothing hashed for a file no pair names
        self.assertEqual(plan['rows'][0]['action'], 'copy')

    def test_keep_data_reads_version_facts_only_for_exact_hashes(self):
        self.disable_avb_verification()
        target = ag.android_transitions.MICROG['package_sha256']
        source = ag.android_transitions.VANILLA['system_sha256']
        vendor = ag.android_transitions.LINEAGE20_VENDOR
        platform = dict(ag.android_transitions.KERNELSU_NEXT)
        with unittest.mock.patch.object(ag, 'file_digest', return_value=(target, self.gsi.stat().st_size)), \
             unittest.mock.patch.object(ag, 'system_digest', return_value=source), \
             unittest.mock.patch.object(ag, 'platform_facts', return_value=(platform, {})):
            _, known, _ = self.inspect_keep('--qualification-run')
            self.assertEqual(known['sdk'], 36)
            self.assertEqual(known['android'], '16')
            self.assertTrue(known['keep_data']['qualified'])
            self.assertTrue(known['fits'])
            self.assertEqual(known['keep_data']['versions'], {
                'source_sdk': 36, 'target_sdk': 36, 'target_release': '16',
                'vendor_sdk': 31, 'vendor_vndk': 31,
            })
            self.assertEqual(known['warnings'], [])
            with unittest.mock.patch.dict(ag.VERIFIED_VENDOR_VERSIONS, {vendor: (31, 32)}):
                _, revised, _ = self.inspect_keep('--qualification-run')
                _, stale, _ = self.run_helper('install', '--volume', 'userdata', '--volume-token', self.token(),
                                              '--path', '/.a22x-images/' + self.gsi.name, '--keep-data',
                                              '--qualification-run', '--rollback-volume', 'sdcard-p1',
                                              '--expected-plan', known['plan_sha256'], '--confirm')
            self.assertNotEqual(known['plan_sha256'], revised['plan_sha256'])
            self.assertEqual(stale['error']['code'], 'PLAN_CHANGED')
            self.assertEqual(self.copies, [])

        with unittest.mock.patch.object(ag, 'file_digest', return_value=('a' * 64, self.gsi.stat().st_size)), \
             unittest.mock.patch.object(ag, 'system_digest', return_value='b' * 64), \
             unittest.mock.patch.object(ag, 'platform_facts', return_value=(dict(platform, vendor_sha256='c' * 64), {})):
            _, unknown, _ = self.inspect_keep('--qualification-run')
            self.assertFalse(unknown['keep_data']['qualified'])
            self.assertTrue(all(value is None for value in unknown['keep_data']['versions'].values()))

    def test_a_qualified_pair_updates_the_system_and_keeps_everything_else(self):
        original_vbmeta = self.disable_avb_verification()
        code, probe, _ = self.inspect_keep('--qualification-run')
        self.assertEqual(code, 0)
        self.qualify(probe)
        code, plan, _ = self.inspect_keep()
        self.assertEqual(code, 0, plan)
        self.assertEqual(plan['blockers'], [])
        self.assertTrue(plan['keep_data']['qualified'])
        self.assertEqual([write['target'] for write in plan['writes']], ['super/system'])
        with unittest.mock.patch.object(ag.flash, 'check', wraps=ag.flash.check) as check:
            code, done, _ = self.run_helper('install', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                                            '/.a22x-images/' + self.gsi.name, '--expected-plan', plan['plan_sha256'], '--confirm',
                                            '--keep-data', '--rollback-volume', 'sdcard-p1')
        self.assertEqual(check.call_count, 1)
        self.assertEqual(check.call_args.args[1].expected_source_sha256, plan['keep_data']['target_sha256'])
        self.assertEqual(check.call_args.args[1].expected_source_identity, plan['source_identity'])
        self.assertEqual(code, 0, done)
        self.assertTrue(done['kept_data'])
        self.assertEqual(self.copies, ['sdcard-p1'])
        self.assertEqual(done['rollback_copy']['path'], '/A22xAndroidBackups/android-test')
        self.assertEqual((self.root / 'data/app-data.txt').read_text(), 'kept')
        self.assertEqual((self.root / 'cache/old.log').read_text(), 'old')
        self.assertEqual((self.root / 'targets/vbmeta').read_bytes(), original_vbmeta)
        import filesystem as fs
        import install
        written = ag.system_digest(install.FixtureContext(self.root))
        self.assertNotEqual(written, plan['keep_data']['source_system_sha256'])

    def test_keep_data_cannot_change_vbmeta_to_disable_verification(self):
        code, plan, _ = self.inspect_keep('--qualification-run')
        self.assertEqual(code, 0, plan)
        self.assertEqual([write['target'] for write in plan['writes']], ['super/system'])
        self.assertIn('PLATFORM_NOT_QUALIFIED', plan['blockers'])
        self.assertEqual(plan['keep_data']['platform_differences'], ['vbmeta_flags'])
        self.assertFalse(plan['keep_data']['qualified'])
        code, done, _ = self.run_helper('install', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                                        '/.a22x-images/' + self.gsi.name, '--expected-plan', plan['plan_sha256'], '--confirm',
                                        '--keep-data', '--rollback-volume', 'sdcard-p1', '--qualification-run')
        self.assertNotEqual(code, 0)
        self.assertEqual(done['error']['code'], 'PLAN_BLOCKED')
        self.assertEqual(self.copies, [])

    def test_a_pair_checked_on_another_platform_is_refused_and_names_the_difference(self):
        """2026-11-22: a pair is qualified on a BOOT, a vendor, verification and encryption, not by its files alone."""
        self.disable_avb_verification()
        code, probe, _ = self.inspect_keep('--qualification-run')
        self.assertEqual(code, 0)
        self.assertEqual(set(probe['keep_data']['platform']), set(ag.android_transitions.PLATFORM_KEYS))
        other = dict(probe['keep_data']['platform'], kernel='4.14.186-other', root='apatch')
        self.qualify(probe, other)
        code, plan, _ = self.inspect_keep()
        self.assertEqual(code, 0)
        self.assertIn('PLATFORM_NOT_QUALIFIED', plan['blockers'])
        self.assertNotIn('PAIR_NOT_QUALIFIED', plan['blockers'])
        self.assertFalse(plan['keep_data']['qualified'])
        self.assertEqual(plan['keep_data']['platform_differences'], ['kernel', 'root'])
        code, run, _ = self.inspect_keep('--qualification-run')  # how a new platform is qualified
        self.assertNotIn('PLATFORM_NOT_QUALIFIED', run['blockers'])

    def test_a_system_changed_after_the_review_writes_nothing(self):
        self.disable_avb_verification()
        code, probe, _ = self.inspect_keep('--qualification-run')
        self.qualify(probe)
        code, plan, _ = self.inspect_keep()
        import install
        context = install.FixtureContext(self.root)
        _, sfd, found = ag.flash.open_super(context, write=True)
        try:
            found.write_chunks('system', iter([os.urandom(1 << 20)]))
        finally:
            os.close(sfd)
        code, done, _ = self.run_helper('install', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                                        '/.a22x-images/' + self.gsi.name, '--expected-plan', plan['plan_sha256'], '--confirm',
                                        '--keep-data', '--rollback-volume', 'sdcard-p1')
        self.assertEqual(done['error']['code'], 'PLAN_CHANGED')
        self.assertEqual(self.copies, [])  # refused before the copy

    def test_userdata_protection_blocks_keep_data_before_the_rollback_copy(self):
        self.disable_avb_verification()
        _, probe, _ = self.inspect_keep('--qualification-run')
        self.qualify(probe)
        _, plain, _ = self.inspect_keep()
        self.assertEqual(plain['blockers'], [])
        self.assertEqual(plain['keep_data']['userdata']['protection'], 'unprotected')
        path = self.root / 'filesystem-fixture.json'
        fixture = json.loads(path.read_text())
        next(volume for volume in fixture['volumes'] if volume['id'] == 'userdata')['fscrypt_feature'] = True
        path.write_text(json.dumps(fixture))
        _, encrypted, _ = self.inspect_keep()
        self.assertEqual(encrypted['keep_data']['platform'], plain['keep_data']['platform'])
        self.assertEqual(encrypted['keep_data']['userdata']['volume_token'], plain['keep_data']['userdata']['volume_token'])
        self.assertEqual(encrypted['keep_data']['userdata']['protection'], 'protected_or_unknown')
        self.assertFalse(encrypted['keep_data']['qualified'])
        self.assertIn('userdata_encryption', encrypted['keep_data']['platform_differences'])
        self.assertIn('PLATFORM_NOT_QUALIFIED', encrypted['blockers'])

        args = ('--volume', 'userdata', '--volume-token', self.token(), '--path',
                '/.a22x-images/' + self.gsi.name, '--keep-data', '--rollback-volume', 'sdcard-p1')
        with unittest.mock.patch.object(ag, 'flash_gsi') as write:
            for reviewed, expected in ((plain, 'PLAN_CHANGED'), (encrypted, 'PLAN_BLOCKED')):
                _, result, _ = self.run_helper('install', *args, '--expected-plan', reviewed['plan_sha256'], '--confirm')
                self.assertEqual(result['error']['code'], expected)
            write.assert_not_called()
        self.assertEqual(self.copies, [])

    def test_replaced_userdata_invalidates_review_when_gsi_is_on_sd(self):
        import filesystem as fs
        self.disable_avb_verification()
        self.gsi = self.gsi.rename(self.root / 'sd' / self.gsi.name)
        token = fs.FixtureContext(self.root).volume('sdcard-p1')['volume_token']
        args = ('--volume', 'sdcard-p1', '--volume-token', token, '--path', '/' + self.gsi.name,
                '--keep-data', '--rollback-volume', 'sdcard-p1')
        _, probe, _ = self.run_helper('inspect', *args, '--qualification-run')
        self.qualify(probe)
        _, reviewed, _ = self.run_helper('inspect', *args)
        self.assertEqual(reviewed['blockers'], [])

        (self.root / 'data').rename(self.root / 'replaced-data')
        (self.root / 'data').mkdir()
        _, current, _ = self.run_helper('inspect', *args)
        self.assertEqual(current['blockers'], [])
        self.assertEqual(current['keep_data']['userdata']['protection'], 'unprotected')
        self.assertNotEqual(current['keep_data']['userdata']['volume_token'], reviewed['keep_data']['userdata']['volume_token'])
        with unittest.mock.patch.object(ag, 'flash_gsi') as write:
            _, result, _ = self.run_helper('install', *args, '--expected-plan', reviewed['plan_sha256'], '--confirm')
            self.assertEqual(result['error']['code'], 'PLAN_CHANGED')
            write.assert_not_called()
        self.assertEqual(self.copies, [])

    def test_boot_and_avb_chain_bytes_are_bound_even_when_platform_facts_stay_the_same(self):
        self.disable_avb_verification()
        config_path = self.root / 'install-fixture.json'
        config = json.loads(config_path.read_text())
        for label in ('vbmeta_system', 'vbmeta_vendor'):
            path = 'targets/' + label
            data = (self.root / 'targets/vbmeta').read_bytes()
            (self.root / path).write_bytes(data)
            config['targets'][label] = {'path': path, 'size_bytes': len(data)}
        config_path.write_text(json.dumps(config))

        code, probe, _ = self.inspect_keep('--qualification-run')
        self.assertEqual(code, 0, probe)
        self.qualify(probe)
        code, plan, _ = self.inspect_keep()
        self.assertEqual(code, 0, plan)
        self.assertEqual(plan['blockers'], [])
        self.assertEqual(set(plan['keep_data']['platform_partition_sha256']), set(ag.KEEP_DATA_PARTITIONS))
        for label in ag.KEEP_DATA_PARTITIONS:
            with self.subTest(label=label):
                path = self.root / 'targets' / label
                original = path.read_bytes()
                path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                try:
                    code, changed, _ = self.inspect_keep()
                    self.assertEqual(code, 0, changed)
                    self.assertEqual(changed['keep_data']['platform'], plan['keep_data']['platform'])
                    self.assertEqual(changed['blockers'], [])
                    code, done, _ = self.run_helper('install', '--volume', 'userdata', '--volume-token', self.token(),
                                                    '--path', '/.a22x-images/' + self.gsi.name, '--expected-plan',
                                                    plan['plan_sha256'], '--confirm', '--keep-data',
                                                    '--rollback-volume', 'sdcard-p1')
                    self.assertEqual(done['error']['code'], 'PLAN_CHANGED')
                    self.assertEqual(self.copies, [])
                finally:
                    path.write_bytes(original)

    def test_the_copy_needs_a_card_or_usb_drive(self):
        code, plan, _ = self.run_helper('inspect', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                                        '/.a22x-images/' + self.gsi.name, '--keep-data', '--rollback-volume', 'userdata',
                                        '--qualification-run')
        self.assertIn('ROLLBACK_COPY_NEEDS_CARD', plan['blockers'])

    def current_system_image(self, name, change=False):
        """The image super/system holds now (trailing zeros cut, as a GSI file has none), on the card."""
        import install
        _, sfd, found = ag.flash.open_super(install.FixtureContext(self.root))
        try:
            data = b''.join(found.chunks('system')).rstrip(b'\0')
        finally:
            os.close(sfd)
        if change:
            data = data[:-1] + bytes([data[-1] ^ 1])
        (self.root / 'sd' / name).write_bytes(data)
        return '/' + name

    def install_keep(self, plan, image):
        return self.run_helper('install', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                               '/.a22x-images/' + self.gsi.name, '--expected-plan', plan['plan_sha256'], '--confirm',
                               '--keep-data', '--rollback-image-volume', 'sdcard-p1', '--rollback-image-path', image)

    def test_the_earlier_system_s_own_image_is_the_way_back(self):
        self.disable_avb_verification()
        image = self.current_system_image('earlier.img')
        import install
        self.assertTrue(ag.image_matches_system(install.FixtureContext(self.root), 'sdcard-p1', image))
        code, probe, _ = self.inspect_keep('--qualification-run')
        self.qualify(probe)
        code, plan, _ = self.run_helper('inspect', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                                        '/.a22x-images/' + self.gsi.name, '--keep-data', '--rollback-image-volume', 'sdcard-p1',
                                        '--rollback-image-path', image)
        self.assertEqual(plan['blockers'], [])
        self.assertEqual(plan['rows'][0]['name'], 'earlier.img')
        code, done, _ = self.install_keep(plan, image)
        self.assertEqual(code, 0, done)
        self.assertEqual(done['rollback_copy'], {'volume': 'sdcard-p1', 'path': image, 'image': True})
        self.assertEqual(self.copies, [])  # no partitions copy needed
        self.assertIn('Flash to a partition', done['next'])

    def test_an_image_of_another_system_is_no_way_back_and_nothing_is_written(self):
        self.disable_avb_verification()
        image = self.current_system_image('other.img', change=True)
        code, probe, _ = self.inspect_keep('--qualification-run')
        self.qualify(probe)
        code, plan, _ = self.run_helper('inspect', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                                        '/.a22x-images/' + self.gsi.name, '--keep-data', '--rollback-image-volume', 'sdcard-p1',
                                        '--rollback-image-path', image)
        before = ag.system_digest(__import__('install').FixtureContext(self.root))
        code, done, _ = self.install_keep(plan, image)
        self.assertEqual(done['error']['code'], 'ROLLBACK_IMAGE_DIFFERS')
        self.assertEqual(ag.system_digest(__import__('install').FixtureContext(self.root)), before)

    def test_replacing_the_rollback_image_before_the_write_lock_prevents_any_write(self):
        self.disable_avb_verification()
        image = self.current_system_image('earlier.img')
        args = ('--volume', 'userdata', '--volume-token', self.token(), '--path', '/.a22x-images/' + self.gsi.name,
                '--keep-data', '--rollback-image-volume', 'sdcard-p1', '--rollback-image-path', image)
        _, probe, _ = self.inspect_keep('--qualification-run')
        self.qualify(probe)
        _, plan, _ = self.run_helper('inspect', *args)
        raw_super = self.root / 'targets/super'
        before = hashlib.sha256(raw_super.read_bytes()).hexdigest()
        held_lock = ag.sf.held_lock

        @contextlib.contextmanager
        def replace_before_lock(context):
            self.current_system_image('earlier.img', change=True)
            with held_lock(context):
                yield

        with unittest.mock.patch.object(ag.sf, 'held_lock', replace_before_lock):
            _, result, _ = self.install_keep(plan, image)

        self.assertEqual(result['error']['code'], 'ROLLBACK_IMAGE_DIFFERS')
        self.assertEqual(hashlib.sha256(raw_super.read_bytes()).hexdigest(), before)
        self.assertEqual(self.copies, [])

    def test_an_internal_download_does_not_hide_an_external_rollback_destination(self):
        self.disable_avb_verification()
        image = self.current_system_image('earlier.img')
        saved = self.root / 'sd' / image.lstrip('/')
        data = saved.read_bytes()
        saved.replace(self.gsi.parent / 'earlier.img')
        _, probe, _ = self.inspect_keep('--qualification-run')
        pair = {'source_manifest_sha256': probe['keep_data']['source_system_sha256'],
                'target_package_sha256': probe['keep_data']['target_sha256'],
                'target_package_bytes': self.gsi.stat().st_size,
                'source_package_sha256': hashlib.sha256(data).hexdigest(),
                'source_package_bytes': len(data), 'platforms': [probe['keep_data']['platform']]}
        with unittest.mock.patch.object(ag.android_transitions, 'QUALIFIED_TRANSITIONS', (pair,)):
            _, plan, _ = self.run_helper('inspect', '--volume', 'userdata', '--volume-token', self.token(),
                                         '--path', '/.a22x-images/' + self.gsi.name, '--keep-data')
        self.assertEqual(plan['blockers'], [])
        self.assertEqual(plan['keep_data']['rollback_volume'], 'sdcard-p1')
        self.assertIsNone(plan['keep_data']['rollback_image'])

    def test_without_a_way_back_nothing_is_offered(self):
        code, plan, _ = self.run_helper('inspect', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                                        '/.a22x-images/' + self.gsi.name, '--keep-data', '--qualification-run')
        self.assertIn('ROLLBACK_NEEDED', plan['blockers'])

    def test_the_way_back_is_found_by_itself_and_the_review_offers_the_update(self):
        self.disable_avb_verification()
        (self.root / 'sd/.a22x-images').mkdir()
        image = self.current_system_image('.a22x-images/earlier.img')
        data = (self.root / 'sd' / image.lstrip('/')).read_bytes()
        code, probe, _ = self.inspect_keep('--qualification-run')
        pair = {'source_manifest_sha256': probe['keep_data']['source_system_sha256'],
                'target_package_sha256': probe['keep_data']['target_sha256'], 'target_package_bytes': self.gsi.stat().st_size,
                'source_package_sha256': hashlib.sha256(data).hexdigest(), 'source_package_bytes': len(data),
                'platforms': [probe['keep_data']['platform']]}
        with unittest.mock.patch.object(ag.android_transitions, 'QUALIFIED_TRANSITIONS', (pair,)):
            code, plain, _ = self.inspect()
            self.assertTrue(plain['keep_data_offer'])  # the review of the same file offers the update
            code, plan, _ = self.run_helper('inspect', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                                            '/.a22x-images/' + self.gsi.name, '--keep-data')
            self.assertEqual(plan['blockers'], [])
            self.assertEqual(plan['keep_data']['rollback_image'], ['sdcard-p1', image])
            code, done, _ = self.run_helper('install', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                                            '/.a22x-images/' + self.gsi.name, '--expected-plan', plan['plan_sha256'], '--confirm',
                                            '--keep-data')
            self.assertEqual(code, 0, done)
            self.assertEqual(done['rollback_copy'], {'volume': 'sdcard-p1', 'path': image, 'image': True})
        code, plan, _ = self.inspect()
        self.assertFalse(plan['keep_data_offer'])  # no qualified pair has a target of this size


@unittest.skipUnless(shutil.which('mke2fs') and shutil.which('debugfs'), 'no e2fsprogs')
class NoFbe(Gsi):
    """A GSI with Android's data left unencrypted (2026-11-21): the vendor there asks for no encryption."""

    def setUp(self):
        super().setUp()
        import subprocess
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from test_nofbe import MT6833
        tree = self.root / 'vendor-tree'
        (tree / 'etc').mkdir(parents=True)
        (tree / 'etc/fstab.mt6833').write_bytes(MT6833)
        subprocess.run(['mke2fs', '-q', '-t', 'ext4', '-b', '1024', '-d', str(tree), str(self.root / 'vendor.img'), '2048'], check=True)

    def install_no_fbe(self):
        code, plan, _ = self.run_helper('inspect', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                                        '/.a22x-images/' + self.gsi.name, '--no-fbe')
        return plan, self.run_helper('install', '--volume', 'userdata', '--volume-token', self.token(), '--path',
                                     '/.a22x-images/' + self.gsi.name, '--expected-plan', plan['plan_sha256'], '--confirm', '--no-fbe')

    def test_the_vendor_asks_for_no_encryption_after_the_install(self):
        import nofbe
        with unittest.mock.patch('root.verification_state', return_value=False):
            plan, (code, done, _) = self.install_no_fbe()
        self.assertTrue(plan['no_fbe'])
        self.assertEqual(code, 0, done)
        self.assertTrue(done['no_fbe']['changed'])
        self.assertFalse(nofbe.plan_for(self.root / 'vendor.img')['encrypted'])

    def test_with_verification_on_nothing_is_written(self):
        before = (self.root / 'vendor.img').read_bytes()
        with unittest.mock.patch('root.verification_state', return_value=True):
            plan, (code, done, _) = self.install_no_fbe()
        self.assertIn('NO_FBE_NEEDS_VERIFICATION_OFF', plan['blockers'])
        self.assertEqual(done['error']['code'], 'PLAN_BLOCKED')
        self.assertEqual((self.root / 'vendor.img').read_bytes(), before)

    def test_unsupported_vendor_blocks_before_any_partition_write(self):
        (self.root / 'vendor.img').write_bytes(b'unsupported vendor image')
        with unittest.mock.patch('root.verification_state', return_value=False), \
                unittest.mock.patch.object(ag, 'flash_gsi') as flash_gsi:
            plan, (code, done, _) = self.install_no_fbe()
        self.assertIn('VENDOR_NOT_EXT4', plan['blockers'])
        self.assertNotEqual(code, 0)
        self.assertEqual(done['error']['code'], 'PLAN_BLOCKED')
        flash_gsi.assert_not_called()
        self.assertFalse((self.root / 'android-reset.json').exists())

    def test_changed_fstab_bytes_invalidate_the_no_fbe_review(self):
        import nofbe
        path = self.root / 'vendor.img'
        args = ('--volume', 'userdata', '--volume-token', self.token(), '--path',
                '/.a22x-images/' + self.gsi.name, '--no-fbe')
        with unittest.mock.patch('root.verification_state', return_value=False), \
                unittest.mock.patch.object(ag, 'flash_gsi') as flash_gsi:
            code, plan, _ = self.run_helper('inspect', *args)
            self.assertEqual(code, 0, plan)
            self.assertEqual(plan['blockers'], [])
            row = nofbe.plan_for(path)['writes'][0]
            offset = row['old'].index(b'aes-256-xts')
            with path.open('r+b') as image:
                image.seek(row['offset'] + offset)
                image.write(b'x')
            code, done, _ = self.run_helper('install', *args, '--expected-plan', plan['plan_sha256'], '--confirm')
        self.assertNotEqual(code, 0)
        self.assertEqual(done['error']['code'], 'PLAN_CHANGED')
        flash_gsi.assert_not_called()
        self.assertFalse((self.root / 'android-reset.json').exists())
