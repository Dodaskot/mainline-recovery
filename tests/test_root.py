"""Root from the recovery (root.py, 2026-11-10): the newest Magisk checked by its SHA-256, BOOT
patched, the stock BOOT kept on cache first, refused on a Linux BOOT. The patch itself is
Magisk's boot_patch.sh on the phone; here a stand-in marks the BOOT as Magisk does.
APatch (2026-11-11): KernelPatch's kptools and kpimg come with the recovery; here a stand-in
kptools walks the same steps on a BOOT the test prepared with KernelPatch's magic in its kernel."""
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import root as rt  # noqa: E402
from test_android_gsi import stock_boot  # noqa: E402
import test_bootimage as tb  # noqa: E402
from test_flash import boot_image  # noqa: E402

MIB = 1 << 20


class Root(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-root-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.root, True)
        for name in ('targets', 'cache/a22x-recovery', 'root-downloads'):
            (self.root / name).mkdir(parents=True)
        self.boot(stock_boot())
        apk = self.root / 'root-downloads/Magisk-v31.1.apk'
        with zipfile.ZipFile(apk, 'w') as z:
            z.writestr('assets/boot_patch.sh', '#!/sbin/sh\n')
        data = apk.read_bytes()
        # KernelSU Next's kernel as an AnyKernel3 ZIP of the project's releases (2026-11-21).
        kzip = self.root / 'root-downloads/KernelSU-Next-A226B-4.14.186-v1-AnyKernel3.zip'
        with zipfile.ZipFile(kzip, 'w') as z:
            z.writestr('anykernel.sh', 'properties() { :; }\n')
            z.writestr('Image.gz', b'\x1f\x8b')
            z.writestr('META-INF/com/google/android/update-binary', '#!/sbin/sh\n')
        kdata = kzip.read_bytes()
        self.ksu_sha = hashlib.sha256(kdata).hexdigest()
        (self.root / 'install-fixture.json').write_text(json.dumps({
            'schema': 'a22x.install.fixture.v1', 'device': {'model': 'SM-A226B', 'identity': 'fixture:test'},
            'targets': {'boot': {'path': 'targets/boot', 'size_bytes': 4 * MIB},
                        'vbmeta': {'path': 'targets/vbmeta', 'size_bytes': 1 << 16}},
            'root': {'magisk': {'version': 'v31.1', 'file': apk.name, 'url': 'https://github.com/topjohnwu/Magisk/releases/download/v31.1/' + apk.name,
                                'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()},
                     'kernelsu-next': {'version': 'v1', 'file': kzip.name, 'size': len(kdata), 'sha256': self.ksu_sha,
                                       'url': 'https://github.com/Dodaskot/mainline-recovery/releases/download/kernelsu-next-a22x-v1/' + kzip.name}}}))
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
            {'id': 'cache', 'path': 'cache', 'fs_type': 'ext4', 'mounted': True, 'read_only': True}]}))
        self.sha = hashlib.sha256(data).hexdigest()
        # The phone's vbmeta with verification off (flags 3), as root needs it here.
        from test_flash import vbmeta
        off = bytearray(vbmeta(b'samsung') + bytes((1 << 16) - 327))
        struct.pack_into('>I', off, 120, 3)
        (self.root / 'targets/vbmeta').write_bytes(bytes(off))
        props = {'ro.product.bootimage.device': 'a22x', 'ro.product.bootimage.model': 'SM-A226B'}
        patched = tb.boot(tb.kernel('4.14.186-27218697'), tb.ramdisk(props, {'.backup/.magisk': b'KEEPVERITY=true\n'}),
                          tb.dt_table(tb.fdt('MT6833', ['mediatek,MT6833'])))
        (self.root / 'root-downloads/patched-boot.img').write_bytes(patched)

    KPIMG = b'KP1158\0\0' + bytes([0, 9, 13, 0]) + bytes(116)

    def apatch(self, kallsyms=True):
        """KernelPatch's files as the recovery carries them: kpimg, and a stand-in kptools that takes
        the steps of the APatch app's boot_patch.sh and repacks to a BOOT with KernelPatch in its kernel."""
        folder = self.root / 'apatch'
        folder.mkdir(exist_ok=True)
        (folder / 'kpimg').write_bytes(self.KPIMG)
        image = bytearray(64 * 1024)
        image[56:60] = b'ARMd'
        banner = b'Linux version 4.14.186-27218697 (builder) #1 SMP\n'
        image[4096:4096 + len(banner)] = banner
        image[32768:32768 + len(self.KPIMG)] = self.KPIMG
        props = {'ro.product.bootimage.device': 'a22x', 'ro.product.bootimage.model': 'SM-A226B'}
        patched = tb.boot(gzip.compress(bytes(image), mtime=0), tb.ramdisk(props), tb.dt_table(tb.fdt('MT6833', ['mediatek,MT6833'])))
        (folder / 'patched.img').write_bytes(patched)
        (folder / 'kptools').write_text('#!/bin/sh\ncase "$1" in\n'
                                        'unpack) [ -f "$2" ] || exit 4; grep -q "this recovery stays" "$2" && exit 6; echo kernel > kernel;;\n'
                                        '-i) case "$3" in -f) %s;; -l) echo patched=false;; esac;;\n'
                                        '-p) [ "$2$4$6$8" = "-i-S-k-o" ] && [ -f "$3" ] && [ -f "$7" ] || exit 3; echo "patching with $5"; cat "$3" "$7" > "$9";;\n'
                                        'repack) [ -f kernel ] && [ -f kernel.ori ] || exit 5; cp %s new-boot.img;;\n'
                                        '*) exit 9;;\nesac\n' % ('echo CONFIG_KALLSYMS=y; echo CONFIG_KALLSYMS_ALL=y' if kallsyms else 'true',
                                                                 folder / 'patched.img'))
        (folder / 'kptools').chmod(0o755)
        return hashlib.sha256(self.KPIMG).hexdigest()

    def key_file(self, key):
        path = self.root / 'superkey'
        path.write_text(key + '\n')
        return str(path)

    def boot(self, image):
        data = bytearray(4 * MIB)
        data[:len(image)] = image
        (self.root / 'targets/boot').write_bytes(bytes(data))
        return bytes(data)

    def run_helper(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = rt.main(['--fixture', str(self.root), *args])
        return code, json.loads(stdout.getvalue().splitlines()[-1]), stderr.getvalue()

    def test_the_list_names_what_fits_this_kernel(self):
        code, listed, _ = self.run_helper('list')
        self.assertEqual(code, 0, listed)
        rows = {t['id']: t for t in listed['tools']}
        # KernelSU Next through the project's own 4.14 kernel (2026-11-21); KernelSU's GKI modules do not fit.
        self.assertEqual(list(rows), ['magisk', 'apatch', 'kernelsu-next'])
        self.assertTrue(rows['kernelsu-next']['supported'])
        self.assertTrue(rows['magisk']['supported'])
        self.assertEqual(rows['magisk']['version'], 'v31.1')
        self.assertEqual((listed['boot']['kind'], listed['boot']['magisk'], listed['boot']['root']), ('android', False, ''))
        # APatch needs the tool and image this recovery carries: a build without them says so.
        self.assertEqual((rows['apatch']['supported'], rows['apatch']['reason']), (False, 'This build of the recovery has no APatch'))
        sha = self.apatch()
        row = {t['id']: t for t in self.run_helper('list')[1]['tools']}['apatch']
        self.assertEqual((row['supported'], row['version'], row['sha256'], row['needs_key'], row['bundled']),
                         (True, 'KernelPatch 0.13.9', sha, True, True))
        self.assertEqual(row['manager'], rt.APATCH_MANAGER)

    def test_apatch_goes_into_the_kernel_with_the_owners_superkey(self):
        """2026-11-11: APatch beside Magisk. The steps of its app's boot_patch.sh with the recovery's
        own kptools; the SuperKey comes in a file, is read once and reaches no log or result."""
        sha = self.apatch()
        stock = (self.root / 'targets/boot').read_bytes()
        for key in (None, 'short1A', 'lettersonly', '12345678', 'with space 1a'):
            args = ('--superkey-file', self.key_file(key)) if key else ()
            code, refused, _ = self.run_helper('install', '--id', 'apatch', '--expected-sha256', sha, '--confirm', *args)
            self.assertEqual((code, refused['error']['code']), (2, 'SUPERKEY_INVALID'), key)
            self.assertEqual((self.root / 'targets/boot').read_bytes(), stock)
        code, refused, _ = self.run_helper('install', '--id', 'apatch', '--expected-sha256', '0' * 64, '--confirm',
                                           '--superkey-file', self.key_file('Sup3rKey-2026'))
        self.assertEqual((code, refused['error']['code']), (2, 'ROOT_RELEASE_CHANGED'))
        path = self.key_file('Sup3rKey-2026')
        code, done, progress = self.run_helper('install', '--id', 'apatch', '--expected-sha256', sha, '--confirm', '--superkey-file', path)
        self.assertEqual(code, 0, done)
        self.assertFalse(os.path.exists(path))  # read once, then gone
        self.assertNotIn('Sup3rKey-2026', json.dumps(done) + progress)
        self.assertIn('patching with ***', done['log'])
        boot = (self.root / 'targets/boot').read_bytes()
        self.assertEqual(rt.saved_boot.describe_boot(boot)['root'], 'apatch')
        self.assertEqual((done['root'], done['name'], done['version'], done['apk']), ('apatch', 'APatch', 'KernelPatch 0.13.9', ''))
        self.assertTrue(done['boot'].startswith('/a22x-recovery/root/apatch-KernelPatch_0.13.9-'))
        self.assertEqual((self.root / 'cache' / done['kept_boot'].lstrip('/')).read_bytes(), stock)
        self.assertFalse((self.root / 'root-work').exists())
        listed = self.run_helper('list')[1]
        self.assertEqual((listed['boot']['root'], listed['boot']['magisk']), ('apatch', False))
        # One BOOT carries one root: Magisk is refused on a BOOT with APatch, and the other way round.
        code, refused, _ = self.run_helper('install', '--id', 'magisk', '--expected-sha256', self.sha, '--confirm')
        self.assertEqual((code, refused['error']['code'], refused['error']['details']['present']), (2, 'ROOT_OTHER_PRESENT', 'apatch'))
        self.boot(stock_boot())
        self.assertEqual(self.run_helper('install', '--id', 'magisk', '--expected-sha256', self.sha, '--confirm')[0], 0)
        code, refused, _ = self.run_helper('install', '--id', 'apatch', '--expected-sha256', sha, '--confirm',
                                           '--superkey-file', self.key_file('Sup3rKey-2026'))
        self.assertEqual((code, refused['error']['code'], refused['error']['details']['present']), (2, 'ROOT_OTHER_PRESENT', 'magisk'))

    def test_the_mark_that_keeps_this_recovery_is_not_patched_into_the_image(self):
        """2026-11-11, on the phone: the stock BOOT carries this recovery's mark in its tail; with it
        kptools repacked a BOOT larger than the partition. The patch gets the image without the mark."""
        from test_keep_recovery import signed
        sha = self.apatch()
        stock = bytearray(signed(stock_boot()))
        spot = len(stock) - rt.saved_boot.KEEP_RECOVERY_FROM_END
        stock[spot:spot + len(rt.saved_boot.KEEP_RECOVERY_MARK)] = rt.saved_boot.KEEP_RECOVERY_MARK
        (self.root / 'targets/boot').write_bytes(bytes(stock))
        self.assertEqual(rt.saved_boot.keep_recovery_spot(bytes(stock)), (spot, True))
        code, done, _ = self.run_helper('install', '--id', 'apatch', '--expected-sha256', sha, '--confirm',
                                        '--superkey-file', self.key_file('Sup3rKey-2026'))
        self.assertEqual(code, 0, done)
        self.assertEqual(rt.saved_boot.describe_boot((self.root / 'targets/boot').read_bytes())['root'], 'apatch')

    def test_apatch_stops_before_writing_when_the_kernel_or_the_patch_does_not_fit(self):
        sha = self.apatch(kallsyms=False)
        stock = (self.root / 'targets/boot').read_bytes()
        code, refused, _ = self.run_helper('install', '--id', 'apatch', '--expected-sha256', sha, '--confirm',
                                           '--superkey-file', self.key_file('Sup3rKey-2026'))
        self.assertEqual((code, refused['error']['code']), (2, 'APATCH_KERNEL_UNSUITABLE'))
        self.assertEqual((self.root / 'targets/boot').read_bytes(), stock)
        # A repack that is not a BOOT of this phone with KernelPatch in it is not flashed.
        self.apatch()
        (self.root / 'apatch/patched.img').write_bytes(stock_boot())
        code, refused, _ = self.run_helper('install', '--id', 'apatch', '--expected-sha256', sha, '--confirm',
                                           '--superkey-file', self.key_file('Sup3rKey-2026'))
        self.assertEqual((code, refused['error']['code']), (2, 'APATCH_PATCH_FAILED'))
        self.assertEqual((self.root / 'targets/boot').read_bytes(), stock)
        self.assertFalse((self.root / 'root-work').exists())

    def test_magisk_goes_into_boot_and_the_stock_one_stays_on_cache(self):
        stock = (self.root / 'targets/boot').read_bytes()
        code, refused, _ = self.run_helper('install', '--id', 'magisk', '--expected-sha256', '0' * 64, '--confirm')
        self.assertEqual((code, refused['error']['code']), (2, 'ROOT_RELEASE_CHANGED'))
        code, done, _ = self.run_helper('install', '--id', 'magisk', '--expected-sha256', self.sha, '--confirm')
        self.assertEqual(code, 0, done)
        boot = (self.root / 'targets/boot').read_bytes()
        self.assertEqual(rt.saved_boot.describe_boot(boot)['root'], 'magisk')
        self.assertTrue(done['boot'].startswith('/a22x-recovery/root/magisk-v31.1-'))
        kept = self.root / 'cache' / done['kept_boot'].lstrip('/')
        self.assertEqual(kept.read_bytes(), stock)
        code, listed, _ = self.run_helper('list')
        self.assertTrue(listed['boot']['magisk'])
        code, refused, _ = self.run_helper('install', '--id', 'kernelsu', '--expected-sha256', self.sha, '--confirm')
        self.assertEqual((code, refused['error']['code']), (2, 'ROOT_UNKNOWN'))

    def test_a_vbmeta_that_cannot_be_read_is_not_taken_for_verification_off(self):
        # 2026-11-13 review: a vbmeta read error counted as verification off, and a patched BOOT went in.
        (self.root / 'targets/vbmeta').write_bytes(bytes(1 << 16))
        code, refused, _ = self.run_helper('install', '--id', 'magisk', '--expected-sha256', self.sha, '--confirm')
        self.assertEqual((code, refused['error']['code']), (2, 'VBMETA_UNREADABLE'))
        self.assertEqual((self.root / 'targets/boot').read_bytes()[:4], stock_boot()[:4])

    def test_with_verification_on_root_turns_it_off_and_resets_android_data_once(self):
        """2026-11-10 on the phone: stock vbmeta + a patched BOOT = Android cannot mount its data
        (misc: --prompt_and_wipe_data). As the Magisk app does for Samsung: vbmeta flags 3, data erased
        once. LK write-protects vbmeta while the phone runs, so it is prepared here for Download mode."""
        import struct
        from test_flash import vbmeta
        config = json.loads((self.root / 'install-fixture.json').read_text())
        config['targets']['vbmeta'] = {'path': 'targets/vbmeta', 'size_bytes': 1 << 16}
        config['write_protected'] = ['dtbo', 'vbmeta']
        (self.root / 'install-fixture.json').write_text(json.dumps(config))
        stock = vbmeta(b'samsung') + bytes((1 << 16) - 327)
        (self.root / 'targets/vbmeta').write_bytes(stock)
        misc = bytearray(4096)
        misc[:13] = b'boot-recovery'
        misc[64:64 + 64] = b'recovery\n--prompt_and_wipe_data\n--reason=fs_mgr_mount_all:M02R\n'.ljust(64, b'\0')
        (self.root / 'misc').write_bytes(bytes(misc))
        (self.root / 'data').mkdir()
        volumes = json.loads((self.root / 'filesystem-fixture.json').read_text())
        volumes['volumes'].append({'id': 'userdata', 'path': 'data', 'fs_type': 'f2fs', 'mounted': False, 'read_only': True})
        (self.root / 'filesystem-fixture.json').write_text(json.dumps(volumes))
        listed = self.run_helper('list')[1]
        self.assertEqual((listed['verification'], listed['needs_data_reset']), (True, False))
        code, refused, _ = self.run_helper('install', '--id', 'magisk', '--expected-sha256', self.sha, '--confirm', '--erase-data')
        self.assertEqual((code, refused['error']['code']), (2, 'ROOT_NEEDS_VBMETA'))
        code, prepared, _ = self.run_helper('prepare-vbmeta')
        self.assertEqual(code, 0, prepared)
        made = (self.root / 'cache' / prepared['vbmeta'].lstrip('/')).read_bytes()
        self.assertEqual(struct.unpack_from('>I', made, 120)[0], 3)
        self.assertEqual(made[:120] + made[124:], stock[:120] + stock[124:])
        self.assertEqual(prepared['command'], 'heimdall flash --vbmeta ' + prepared['vbmeta'].rsplit('/', 1)[-1])
        self.assertEqual((self.root / 'targets/vbmeta').read_bytes(), stock)  # locked here: nothing written
        (self.root / 'targets/vbmeta').write_bytes(made)  # flashed in Download mode
        listed = self.run_helper('list')[1]
        self.assertEqual((listed['verification'], listed['needs_data_reset']), (False, True))
        # 2026-11-13 review: a reset of Android's data done another way (Wipe > Data for Android, an
        # installation) counts as the one that is needed; root then needs no second one.
        import samsung_firmware
        import install
        with contextlib.redirect_stdout(io.StringIO()):
            samsung_firmware.reset_data(install.FixtureContext(self.root), True, lambda *a: None)
        listed = self.run_helper('list')[1]
        self.assertEqual((listed['verification'], listed['needs_data_reset']), (False, False))
        code, prepared, _ = self.run_helper('prepare-vbmeta')
        self.assertEqual(code, 0, prepared)
        (self.root / 'misc').write_bytes(bytes(misc))  # Android asks again
        code, refused, _ = self.run_helper('install', '--id', 'magisk', '--expected-sha256', self.sha, '--confirm')
        self.assertEqual((code, refused['error']['code']), (2, 'ROOT_NEEDS_DATA_RESET'))
        code, done, _ = self.run_helper('install', '--id', 'magisk', '--expected-sha256', self.sha, '--confirm', '--erase-data')
        self.assertEqual(code, 0, done)
        self.assertTrue((self.root / 'android-reset.json').exists())
        self.assertTrue(done['data']['request_cleared'])
        self.assertFalse(any((self.root / 'misc').read_bytes()[:2048]))
        self.assertFalse((self.root / 'cache' / prepared['vbmeta'].lstrip('/')).exists())
        listed = self.run_helper('list')[1]
        self.assertEqual((listed['verification'], listed['needs_data_reset']), (False, False))  # later updates: no reset

    def test_a_linux_boot_is_refused_and_a_changed_download_stops(self):
        self.boot(boot_image())
        code, refused, _ = self.run_helper('install', '--id', 'magisk', '--expected-sha256', self.sha, '--confirm')
        self.assertEqual((code, refused['error']['code']), (2, 'ROOT_NEEDS_ANDROID_BOOT'))
        self.boot(stock_boot())
        (self.root / 'root-downloads/Magisk-v31.1.apk').write_bytes(b'PK tampered')
        code, refused, _ = self.run_helper('install', '--id', 'magisk', '--expected-sha256', self.sha, '--confirm')
        self.assertEqual((code, refused['error']['code']), (2, 'DOWNLOAD_CHECKSUM_MISMATCH'))


if __name__ == '__main__':
    unittest.main()


class APatchBootstrap(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix='a22x-apatch-bootstrap-')
        self.addCleanup(work.cleanup)
        self.work = Path(work.name)
        self.adb = self.work / 'data/adb'
        self.adb.mkdir(parents=True)
        self.app = self.work / 'data/app/exact-manager'
        self.libs = self.app / 'lib/arm64'
        self.libs.mkdir(parents=True)
        self.installed_apk = self.app / 'base.apk'
        self.apk = self.work / 'manager.apk'
        self.native = {name: f'{name} binary in the signed APK'.encode() for name in rt.APATCH_LIBRARIES}
        with zipfile.ZipFile(self.apk, 'w') as archive:
            for name, data in self.native.items():
                archive.writestr(f'lib/arm64-v8a/lib{name}.so', data)
                (self.libs / f'lib{name}.so').write_bytes(data)
        shutil.copyfile(self.apk, self.installed_apk)
        data = self.apk.read_bytes()
        manager = {**rt.APATCH_MANAGER, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        with mock.patch.object(rt, 'APATCH_MANAGER', manager):
            code, script, error = self.generate(self.apk)
        self.assertEqual((code, error), (0, ''))
        self.assertTrue(script.startswith('#!/system/bin/sh\n'))
        self.assertIn('MANAGER_VERSION_CODE=11282\n', script)
        self.assertNotIn(str(self.apk), script)
        self.script = self.work / 'apatch-bootstrap.sh'
        self.script.write_text(script.replace('ADB=/data/adb', f'ADB={self.adb}')
                               .replace('package:/data/app/', f'package:{self.app.parent}/')
                               .replace('PATH=/system/bin:/system/xbin', 'PATH="$APATCH_TEST_PATH"'))
        self.bin = self.work / 'bin'
        self.bin.mkdir()
        for name, body in {
            'id': '[ "$*" = -u ] && echo 0',
            'getprop': '[ "$*" = sys.boot_completed ] && echo "${APATCH_TEST_BOOT:-1}"',
            'pm': '''
case "$*" in
    'list packages --show-versioncode --user 0 me.bmax.apatch')
        echo "package:me.bmax.apatch versionCode:${APATCH_TEST_VERSION:-11282}" ;;
    'path --user 0 me.bmax.apatch') echo "package:$APATCH_TEST_APK" ;;
    *) exit 1 ;;
esac
''',
            'ls': '''
[ "$1" = -Zd ] || exit 1
case "$2" in
    */.a22x-apatch-bootstrap/*) scope=stage ;;
    *) scope=live ;;
esac
label=u:object_r:adb_data_file:s0
case "${APATCH_TEST_BAD_LABEL:-}" in
    "$scope"|"$2") label=u:object_r:unlabeled:s0 ;;
esac
printf '%s %s\n' "$label" "$2"
''',
            'restorecon': '''
stage="$APATCH_TEST_ADB/.a22x-apatch-bootstrap"
[ "$*" = "-R $stage" ] && [ ! -L "$stage/ap/bin/apd" ]
''',
            'sync': 'exit 0',
        }.items():
            path = self.bin / name
            path.write_text('#!/bin/sh\n' + body + '\n')
            path.chmod(0o755)

    @staticmethod
    def generate(apk):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = rt.main(['--device', 'apatch-bootstrap', '--manager-apk', str(apk)])
        return code, stdout.getvalue(), stderr.getvalue()

    def run_bootstrap(self, *args, **env):
        return subprocess.run(['/bin/sh', '-s', '--', *args], text=True, input=self.script.read_text(), capture_output=True,
                              env={**os.environ, 'APATCH_TEST_PATH': f'{self.bin}:{os.defpath}',
                                   'APATCH_TEST_APK': str(self.installed_apk), 'APATCH_TEST_ADB': str(self.adb), **env})

    def test_generation_refuses_an_unpinned_apk_without_emitting_a_script(self):
        code, script, error = self.generate(self.apk)
        self.assertEqual((code, script), (2, ''))
        details = json.loads(error)['error']
        self.assertEqual(details['code'], 'APATCH_MANAGER_HASH')
        self.assertEqual(details['details']['manager'], rt.APATCH_MANAGER)

    def test_fresh_setup_and_readonly_recheck_preserve_existing_apatch_data(self):
        check = self.run_bootstrap('--verify-only')
        self.assertEqual(check.returncode, 1, check)
        self.assertIn('APATCH_RUNTIME_MISSING', check.stderr)
        self.assertEqual(list(self.adb.iterdir()), [])
        setup = self.run_bootstrap()
        self.assertEqual(setup.returncode, 0, setup)
        self.assertIn('STATUS=configured\n', setup.stdout)
        self.assertIn('APATCH_ENV=VERIFIED\n', setup.stdout)
        self.assertIn('SELINUX_LABEL=u:object_r:adb_data_file:s0\n', setup.stdout)
        self.assertEqual((self.adb / 'apd').read_bytes(), self.native['apd'])
        ap = self.adb / 'ap'
        for name in ('busybox', 'kptools'):
            self.assertEqual((ap / 'bin' / name).read_bytes(), self.native[name])
        for name in ('apd', 'magiskpolicy', 'resetprop'):
            self.assertEqual((ap / 'bin' / name).readlink(), self.adb / 'apd')
        self.assertEqual((ap / 'su_path').read_text(), '/system/bin/su\n')
        self.assertEqual((ap / 'version').read_text(), '11282\n')
        (ap / 'su_path').write_text('/user/configured/su\n')
        (ap / 'package_config').write_text('user settings\n')
        (ap / 'log/existing.log').write_text('an existing log\n')
        module = self.adb / 'modules/meta-overlayfs'
        module.mkdir(parents=True)
        (module / 'module.prop').write_text('metamodule=1\n')
        identity = (ap / 'package_config').stat().st_ino
        for args in ((), ('--verify-only',)):
            check = self.run_bootstrap(*args)
            self.assertEqual(check.returncode, 0, check)
            self.assertIn('STATUS=already-configured\n', check.stdout)
        self.assertEqual((ap / 'package_config').stat().st_ino, identity)
        self.assertEqual((ap / 'package_config').read_text(), 'user settings\n')
        self.assertEqual((ap / 'su_path').read_text(), '/user/configured/su\n')
        self.assertEqual((ap / 'log/existing.log').read_text(), 'an existing log\n')
        self.assertEqual((module / 'module.prop').read_text(), 'metamodule=1\n')
        self.assertEqual({entry.name for entry in self.adb.iterdir()}, {'ap', 'apd', 'modules'})
        (ap / 'version').write_text('11224\n')
        check = self.run_bootstrap('--verify-only')
        self.assertEqual(check.returncode, 1, check)
        self.assertIn('APATCH_RUNTIME_CONFLICT', check.stderr)
        self.assertEqual((ap / 'version').read_text(), '11224\n')
        (ap / 'version').unlink()
        check = self.run_bootstrap('--verify-only')
        self.assertEqual(check.returncode, 0, check)
        self.assertFalse((ap / 'version').exists())

    def test_manager_version_apk_and_extracted_libraries_must_match_before_writing(self):
        for env, expected in (
            ({'APATCH_TEST_BOOT': '0'}, 'APATCH_ANDROID_REQUIRED'),
            ({'APATCH_TEST_VERSION': '11224'}, 'APATCH_MANAGER_VERSION'),
            ({'APATCH_TEST_VERSION': '11283'}, 'APATCH_MANAGER_VERSION'),
        ):
            done = self.run_bootstrap(**env)
            self.assertEqual(done.returncode, 1, done)
            self.assertIn(expected, done.stderr)
            self.assertEqual(list(self.adb.iterdir()), [])
        self.installed_apk.write_bytes(b'different APK with the same reported version')
        done = self.run_bootstrap()
        self.assertEqual(done.returncode, 1, done)
        self.assertIn('APATCH_MANAGER_HASH', done.stderr)
        shutil.copyfile(self.apk, self.installed_apk)
        (self.libs / 'libapd.so').unlink()
        done = self.run_bootstrap()
        self.assertEqual(done.returncode, 1, done)
        self.assertIn('APATCH_MANAGER_LIBRARIES', done.stderr)
        self.assertEqual(list(self.adb.iterdir()), [])

    def test_recovery_seed_completes_without_replacing_or_relabeling_the_daemon(self):
        seed = self.adb / 'apd'
        seed.write_bytes(self.native['apd'])
        seed.chmod(0o750)
        os.setxattr(seed, 'user.a22x-test', b'existing xattr')
        before = seed.stat()
        ap = self.adb / 'ap'
        check = self.run_bootstrap('--verify-only')
        self.assertEqual(check.returncode, 1, check)
        self.assertIn('APATCH_RUNTIME_MISSING', check.stderr)
        self.assertFalse(ap.exists())
        # A late label failure rolls back only the newly published directory.
        check = self.run_bootstrap(APATCH_TEST_BAD_LABEL=str(ap))
        self.assertEqual(check.returncode, 1, check)
        self.assertIn('APATCH_RUNTIME_INVALID', check.stderr)
        self.assertEqual(list(self.adb.iterdir()), [seed])
        setup = self.run_bootstrap()
        self.assertEqual(setup.returncode, 0, setup)
        self.assertIn('STATUS=configured\n', setup.stdout)
        self.assertEqual((ap / 'bin/apd').readlink(), seed)
        self.assertEqual((ap / 'version').read_text(), '11282\n')
        after = seed.stat()
        self.assertEqual((after.st_ino, after.st_mode, after.st_ctime_ns), (before.st_ino, before.st_mode, before.st_ctime_ns))
        self.assertEqual(seed.read_bytes(), self.native['apd'])
        self.assertEqual(os.getxattr(seed, 'user.a22x-test'), b'existing xattr')
        check = self.run_bootstrap('--verify-only')
        self.assertEqual(check.returncode, 0, check)
        self.assertIn('STATUS=already-configured\n', check.stdout)

    def test_wrong_or_unlabeled_recovery_seed_is_refused_without_changes(self):
        seed = self.adb / 'apd'
        for data, mode, bad_label in (
            (b'another APD', 0o755, ''),
            (self.native['apd'], 0o644, ''),
            (self.native['apd'], 0o755, str(seed)),
        ):
            with self.subTest(mode=mode, bad_label=bad_label, data=data):
                seed.write_bytes(data)
                seed.chmod(mode)
                before = seed.stat()
                done = self.run_bootstrap(APATCH_TEST_BAD_LABEL=bad_label)
                self.assertEqual(done.returncode, 1, done)
                self.assertIn('APATCH_RUNTIME_CONFLICT', done.stderr)
                self.assertEqual(list(self.adb.iterdir()), [seed])
                self.assertEqual(seed.stat().st_ctime_ns, before.st_ctime_ns)
                self.assertEqual(seed.read_bytes(), data)

    def test_partial_runtime_is_preserved_and_fresh_label_failure_rolls_back(self):
        for where, expected in (('stage', 'APATCH_STAGE_INVALID'), ('live', 'APATCH_RUNTIME_INVALID')):
            done = self.run_bootstrap(APATCH_TEST_BAD_LABEL=where)
            self.assertEqual(done.returncode, 1, done)
            self.assertIn(expected, done.stderr)
            self.assertEqual(list(self.adb.iterdir()), [])
        ap = self.adb / 'ap'
        ap.mkdir()
        (ap / 'package_config').write_text('existing data\n')
        (self.adb / 'apd').symlink_to(self.work / 'missing')
        done = self.run_bootstrap()
        self.assertEqual(done.returncode, 1, done)
        self.assertIn('APATCH_RUNTIME_CONFLICT', done.stderr)
        self.assertEqual((ap / 'package_config').read_text(), 'existing data\n')
        self.assertTrue((self.adb / 'apd').is_symlink())
        self.assertEqual({entry.name for entry in self.adb.iterdir()}, {'ap', 'apd'})


class APatchPatchErrors(unittest.TestCase):
    def test_kptools_errors_hide_the_superkey_and_stop_before_flashing(self):
        fixture = Root()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        sha = fixture.apatch()
        key = 'Offline-Test-Key-123'
        stock = (fixture.root / 'targets/boot').read_bytes()
        real_run = subprocess.run

        def run(args, **kwargs):
            if args[:2] != ['./kptools', '-p']:
                return real_run(args, **kwargs)
            if error == 'timeout':
                raise subprocess.TimeoutExpired(args, 1, output=key.encode())
            if error == 'invocation':
                raise subprocess.CalledProcessError(1, args, output=key.encode())
            return subprocess.CompletedProcess(args, 1, stdout=f'failed while patching with {key}'.encode())

        for error in ('timeout', 'invocation', 'exit'):
            with self.subTest(error=error), mock.patch.object(rt.subprocess, 'run', side_effect=run) as commands:
                code, refused, progress = fixture.run_helper('install', '--id', 'apatch', '--expected-sha256', sha, '--confirm',
                                                             '--superkey-file', fixture.key_file(key))
                self.assertEqual((code, refused['error']['code']), (2, 'APATCH_PATCH_FAILED'))
                self.assertEqual(refused['error']['details']['step'], '-p')
                self.assertNotIn(key, json.dumps(refused) + progress)
                self.assertEqual(sum(call.args[0][:2] == ['./kptools', '-p'] for call in commands.call_args_list), 1)
                self.assertEqual((fixture.root / 'targets/boot').read_bytes(), stock)


class KernelSuNext(Root):
    """KernelSU Next (2026-11-21): its kernel ZIP downloaded, checked and kept on cache for the ZIP
    installer's review; BOOT itself is not written here."""

    def test_the_kernel_zip_waits_on_cache_for_its_review(self):
        before = (self.root / 'targets/boot').read_bytes()
        code, done, _ = self.run_helper('install', '--id', 'kernelsu-next', '--expected-sha256', self.ksu_sha, '--confirm')
        self.assertEqual(code, 0, done)
        self.assertEqual(done['root'], 'kernelsu-next')
        self.assertEqual(done['zip']['volume'], 'cache')
        self.assertEqual(done['zip']['sha256'], self.ksu_sha)
        kept = self.root / 'cache' / done['zip']['path'].lstrip('/')
        self.assertEqual(hashlib.sha256(kept.read_bytes()).hexdigest(), self.ksu_sha)
        self.assertEqual((self.root / 'targets/boot').read_bytes(), before)

    def test_magisk_in_boot_is_removed_first(self):
        props = {'ro.product.bootimage.device': 'a22x', 'ro.product.bootimage.model': 'SM-A226B'}
        self.boot(tb.boot(tb.kernel('4.14.186-27218697'), tb.ramdisk(props, {'.backup/.magisk': b'KEEPVERITY=true\n'}),
                          tb.dt_table(tb.fdt('MT6833', ['mediatek,MT6833']))))
        code, done, _ = self.run_helper('install', '--id', 'kernelsu-next', '--expected-sha256', self.ksu_sha, '--confirm')
        self.assertEqual(done['error']['code'], 'ROOT_OTHER_PRESENT')

    def test_a_download_that_is_no_kernel_zip_is_refused(self):
        bad = self.root / 'root-downloads/KernelSU-Next-A226B-4.14.186-v1-AnyKernel3.zip'
        with zipfile.ZipFile(bad, 'w') as z:
            z.writestr('README', 'nothing')
        data = bad.read_bytes()
        fixture = json.loads((self.root / 'install-fixture.json').read_text())
        fixture['root']['kernelsu-next'].update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        (self.root / 'install-fixture.json').write_text(json.dumps(fixture))
        code, done, _ = self.run_helper('install', '--id', 'kernelsu-next', '--expected-sha256', hashlib.sha256(data).hexdigest(),
                                        '--confirm')
        self.assertEqual(done['error']['code'], 'KERNEL_ZIP_INVALID')


class KernelSuNextInBoot(Root):
    def test_kernelsu_next_s_own_domain_is_recognized_as_kernelsu(self):
        """KernelSU Next's kernel starts ksud in u:r:ksu:s0 (its legacy branch): the BOOT counts as
        rooted by KernelSU, so Magisk is not offered over it and KernelSU Next updates over itself."""
        import gzip
        import bootimage as bi
        image = bytearray(64 * 1024)
        image[56:60] = b'ARMd'
        banner = b'Linux version 4.14.186+ (a22x@mainline-recovery) #1 SMP\n'
        image[4096:4096 + len(banner)] = banner
        rc = b'    exec u:r:ksu:s0 root -- /data/adb/ksud post-fs-data\n'
        image[8192:8192 + len(rc)] = rc
        props = {'ro.product.bootimage.device': 'a22x', 'ro.product.bootimage.model': 'SM-A226B'}
        self.boot(tb.boot(gzip.compress(bytes(image), mtime=0), tb.ramdisk(props), tb.dt_table(tb.fdt('MT6833', ['mediatek,MT6833']))))
        code, listed, _ = self.run_helper('list')
        self.assertEqual(listed['boot']['root'], 'kernelsu')
        code, refused, _ = self.run_helper('install', '--id', 'magisk', '--expected-sha256', self.sha, '--confirm')
        self.assertEqual(refused['error']['code'], 'ROOT_OTHER_PRESENT')
        code, done, _ = self.run_helper('install', '--id', 'kernelsu-next', '--expected-sha256', self.ksu_sha, '--confirm')
        self.assertEqual(code, 0, done)
