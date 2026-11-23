"""Apps queued for Android's next start (2026-11-21); temporary directories only."""
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import apk_queue as aq
import filesystem as fs


def apk(path, magisk=False):
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr('AndroidManifest.xml', b'\x03\x00\x08\x00binary manifest')
        z.writestr('classes.dex', b'dex\n035\0')
        if magisk:
            for member, _, _ in __import__('android_root_adb').MAGISK_FILES:
                z.writestr(member, b'magisk part ' + member.encode())
    return Path(path).read_bytes()


class Queue(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='a22x-apk-queue-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data, self.sd = self.root / 'data', self.root / 'sd'
        (self.data / 'adb').mkdir(parents=True)
        (self.sd / 'Download').mkdir(parents=True)
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
            {'id': 'userdata', 'path': 'data', 'fs_type': 'ext4', 'mounted': True, 'read_only': False},
            {'id': 'sdcard-p1', 'path': 'sd', 'fs_type': 'ext4', 'mounted': True, 'read_only': False}]}))
        self.context = fs.FixtureContext(self.root)
        self.token = self.context.volume('sdcard-p1')['volume_token']
        patch = mock.patch.object(aq, 'boot_root', return_value='')
        self.boot = patch.start()
        self.addCleanup(patch.stop)

    def magisk_installed(self):
        (self.data / 'adb/magisk').mkdir()
        (self.data / 'adb/magisk/busybox').write_bytes(b'busybox')

    def preview(self, name='app.apk'):
        return aq.preview(self.context, 'sdcard-p1', self.token, '/Download/' + name)['plan']

    def queue(self, name='app.apk', plan=None):
        plan = plan or self.preview(name)
        return aq.queue(self.context, 'sdcard-p1', self.token, '/Download/' + name, plan['plan_sha256'], True)

    def test_an_apk_is_queued_with_the_script_that_installs_it_at_the_next_start(self):
        data = apk(self.sd / 'Download/app.apk')
        self.magisk_installed()
        plan = self.preview()
        self.assertTrue(plan['allowed'], plan['reason'])
        self.assertEqual((plan['framework'], plan['apk']['sha256']), ('magisk', hashlib.sha256(data).hexdigest()))
        done = self.queue(plan=plan)
        self.assertEqual(done['status'], 'queued')
        queued = list((self.data / 'adb/a22x-apk-queue').glob('*.apk'))
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0].read_bytes(), data)
        script = self.data / 'adb/service.d/a22x-apk-queue.sh'
        self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o755)
        text = script.read_text()
        self.assertIn('pm install -r "$t"', text)
        self.assertNotIn('pm install -r -S', text)  # no descriptor of /data/adb handed to pm (SELinux)
        self.assertIn('sys.boot_completed', text)
        self.assertIn('rm -f "$0"', text)
        self.assertEqual(self.preview()['waiting'], [queued[0].name])

    def test_without_a_root_that_runs_boot_scripts_nothing_is_queued(self):
        apk(self.sd / 'Download/app.apk')
        plan = self.preview()
        self.assertFalse(plan['allowed'])
        with self.assertRaises(fs.FilesystemError) as caught:
            self.queue(plan=plan)
        self.assertEqual(caught.exception.code, 'APK_QUEUE_UNAVAILABLE')
        self.assertFalse((self.data / 'adb/a22x-apk-queue').exists())

    def test_kernelsu_and_apatch_run_the_script_too(self):
        apk(self.sd / 'Download/app.apk')
        (self.data / 'adb/ksu').mkdir()
        (self.data / 'adb/ksud').write_bytes(b'ksud')
        self.assertEqual(self.preview()['framework'], 'kernelsu')
        (self.data / 'adb/ksud').unlink()
        (self.data / 'adb/ap').mkdir()
        (self.data / 'adb/apd').write_bytes(b'apd')
        self.assertEqual(self.preview()['framework'], 'apatch')

    def test_a_fresh_magisk_gets_its_files_from_the_magisk_apk(self):
        """Magisk in the BOOT from its ZIP, the app's setup not done: its files come from the APK (the ZIP)."""
        apk(self.sd / 'Download/Magisk-v31.1.zip', magisk=True)
        apk(self.sd / 'Download/other.apk')
        self.boot.return_value = 'magisk'
        self.assertFalse(self.preview('other.apk')['allowed'])  # an ordinary app cannot set Magisk up
        plan = self.preview('Magisk-v31.1.zip')
        self.assertTrue(plan['allowed'] and plan['magisk_setup'], plan['reason'])
        done = self.queue('Magisk-v31.1.zip', plan)
        self.assertIn('adb/magisk', done['written'])
        self.assertTrue((self.data / 'adb/magisk/busybox').is_file() and (self.data / 'adb/magisk/util_functions.sh').is_file())
        self.assertEqual([p.name.split('-')[0] for p in (self.data / 'adb/a22x-apk-queue').glob('*.apk')], ['Magisk'])

    def test_a_changed_or_false_apk_is_refused(self):
        apk(self.sd / 'Download/app.apk')
        self.magisk_installed()
        plan = self.preview()
        apk(self.sd / 'Download/app.apk', magisk=True)
        with self.assertRaises(fs.FilesystemError) as caught:
            self.queue(plan=plan)
        self.assertEqual(caught.exception.code, 'APK_PLAN_CHANGED')
        (self.sd / 'Download/notes.apk').write_text('not a zip')
        with self.assertRaises(fs.FilesystemError) as caught:
            self.preview('notes.apk')
        self.assertEqual(caught.exception.code, 'APK_INVALID')

    def test_a_manager_is_fetched_from_its_release_and_checked(self):
        self.magisk_installed()
        (self.root / 'root-downloads').mkdir()
        data = apk(self.root / 'root-downloads/KernelSU_v1.0.5_12081-release.apk')
        found = {'version': 'v1.0.5', 'file': 'KernelSU_v1.0.5_12081-release.apk',
                 'url': 'https://example.invalid/KernelSU_v1.0.5_12081-release.apk',
                 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'published': '2026-01-01'}
        with mock.patch('root.latest', return_value=found):
            plan = aq.fetch_preview(self.context, 'kernelsu')['plan']
            self.assertTrue(plan['allowed'])
            self.assertEqual((plan['apk']['label'], plan['apk']['version']), ('KernelSU', 'v1.0.5'))
            done = aq.fetch(self.context, 'kernelsu', plan['plan_sha256'], True)
        self.assertEqual(done['status'], 'queued')
        self.assertEqual([p.read_bytes() for p in (self.data / 'adb/a22x-apk-queue').glob('*.apk')], [data])
        bad = dict(found, sha256='0' * 64)
        with mock.patch('root.latest', return_value=bad):
            plan = aq.fetch_preview(self.context, 'kernelsu')['plan']
            with self.assertRaises(fs.FilesystemError) as caught:
                aq.fetch(self.context, 'kernelsu', plan['plan_sha256'], True)
        self.assertEqual(caught.exception.code, 'DOWNLOAD_CHECKSUM_MISMATCH')

    def test_the_command_line(self):
        apk(self.sd / 'Download/app.apk')
        self.magisk_installed()
        out = io.StringIO()
        with mock.patch('sys.stdout', out):
            code = aq.main(['--fixture', str(self.root), 'preview', '--source-volume', 'sdcard-p1',
                            '--source-token', self.token, '--source-path', '/Download/app.apk'])
        result = json.loads(out.getvalue())
        self.assertEqual((code, result['ok'], result['plan']['allowed']), (0, True, True))


if __name__ == '__main__':
    unittest.main()


class EarlierRootLeftBehind(unittest.TestCase):
    def test_the_root_in_boot_decides_over_files_an_earlier_root_left(self):
        """2026-11-21: Magisk's files stayed in /data/adb after KernelSU Next replaced it in BOOT."""
        pin = mock.Mock()
        found = {'/adb/magisk/busybox': 'file', '/adb/ksu': 'directory', '/adb/ksud': 'file'}
        with mock.patch.object(aq, 'kind', lambda _pin, path: found.get(path)):
            self.assertEqual(aq.runner(pin, 'kernelsu'), ('kernelsu', False))
            self.assertEqual(aq.runner(pin, 'magisk'), ('magisk', False))
            self.assertEqual(aq.runner(pin, ''), ('magisk', False))
