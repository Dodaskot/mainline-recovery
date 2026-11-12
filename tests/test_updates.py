"""Updates of the recovery and of the Linux BOOT from Settings (updates.py, 2026-11-12)."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
import updates
from test_bootimage import boot, dt_table, fdt, kernel, ramdisk

MAINLINE = fdt('Samsung Galaxy A22 5G (SM-A226B)', ['samsung,a22x', 'mediatek,mt6833'])
BOOT_SHA = 'b3f59daa37ad50e0ac6bfaed83f6954147536d07119f1b46a9981ee19d9b17ab'


def recovery_image(tree=MAINLINE):
    image = boot(kernel('7.2.0-a22x-recovery+'), ramdisk(), dt_table(tree))
    return image + bytes(updates.RECOVERY_BYTES - len(image))


class Updates(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-updates-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / 'cache').mkdir()
        (self.root / 'downloads').mkdir()
        self.config = {'schema': 'a22x.filesystem.fixture.v1',
                       'volumes': [{'id': 'cache', 'path': 'cache', 'fs_type': 'ext4', 'mounted': False, 'read_only': True}],
                       'recovery_version': '0.6.199'}
        self.release(recovery_image(), '0.6.201')

    def release(self, image, version):
        name = 'recovery-a22x-%s.img' % version
        (self.root / 'downloads' / name).write_bytes(image)
        self.config['recovery_release'] = {'version': 'v' + version, 'file': name, 'url': 'https://example.invalid/' + name,
                                           'size': len(image), 'sha256': hashlib.sha256(image).hexdigest()}
        self.write()

    def write(self):
        (self.root / 'filesystem-fixture.json').write_text(json.dumps(self.config))

    def call(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = updates.main(['--fixture', str(self.root), *args])
        return code, json.loads(out.getvalue().splitlines()[-1])

    def test_versions_compare_as_numbers(self):
        self.assertGreater(updates.version_key('v0.6.201'), updates.version_key('0.6.199'))
        self.assertGreater(updates.version_key('0.6.1000'), updates.version_key('0.6.999'))
        self.assertEqual(updates.version_key('nightly'), ())
        # 2026-11-12 review: a public build calls itself 0.6.NN-public.
        self.assertEqual(updates.version_key('0.6.206-public'), (0, 6, 206))
        self.assertGreater(updates.version_key('0.6.207'), updates.version_key('0.6.206-public'))
        self.assertGreater(updates.version_key('0.6.206-r2'), updates.version_key('0.6.206'))

    def test_a_newer_recovery_is_offered_and_an_older_one_is_not(self):
        code, found = self.call('check')
        self.assertEqual((code, found['recovery']['installed'], found['recovery']['newer']), (0, '0.6.199', True))
        self.config['recovery_version'] = '0.6.205'
        self.write()
        self.assertFalse(self.call('check')[1]['recovery']['newer'])

    def test_without_wifi_the_answer_comes_at_once(self):
        self.config['offline'] = True
        self.write()
        code, found = self.call('check')
        self.assertEqual((code, found['recovery']['error'], found['recovery']['newer'], found['recovery']['installed']),
                         (0, 'NO_NETWORK', False, '0.6.199'))

    def test_the_linux_boot_is_offered_only_over_an_older_release(self):
        self.config['linux_boot_release'] = {'sha256': 'ab' * 32, 'release': '7.2.0-a22x+', 'url': 'https://example.invalid/boot.img',
                                             'size': 33554432, 'version': 'v147'}
        self.config['linux_boot_older_sha256'] = [BOOT_SHA]
        self.write()
        boot_now = self.call('check')[1]['boot']
        self.assertEqual((boot_now['kind'], boot_now['state'], boot_now['newer']), ('linux', 'older', True))
        self.config['linux_boot_older_sha256'] = []
        self.write()
        self.assertEqual(self.call('check')[1]['boot']['state'], 'own')
        self.config['android_boot'] = True
        self.write()
        self.assertEqual(self.call('check')[1]['boot'], {**self.call('check')[1]['boot'], 'kind': 'android', 'newer': False})

    def test_a_fetched_recovery_waits_on_cache_for_flash_a_partition(self):
        sha = self.config['recovery_release']['sha256']
        code, done = self.call('fetch', '--what', 'recovery', '--sha256', sha)
        self.assertEqual(code, 0, done)
        self.assertEqual((done['volume'], done['target'], done['path']), ('cache', 'recovery', '/a22x-recovery/updates/recovery-0.6.201.img'))
        self.assertEqual(hashlib.sha256((self.root / 'cache' / done['path'].lstrip('/')).read_bytes()).hexdigest(), sha)
        # A newer release only after the next check; an image for another phone is never kept.
        self.assertEqual(self.call('fetch', '--what', 'recovery', '--sha256', '0' * 64)[1]['error']['code'], 'UPDATE_CHANGED')
        self.release(recovery_image(fdt('Redmi', ['xiaomi,camellia', 'mediatek,mt6833'])), '0.6.202')
        code, refused = self.call('fetch', '--what', 'recovery', '--sha256', self.config['recovery_release']['sha256'])
        self.assertEqual((code, refused['error']['code']), (2, 'BOOT_OTHER_PHONE'))
        self.assertFalse((self.root / 'cache/a22x-recovery/updates/recovery-0.6.202.img').exists())
        # 2026-11-12 review: an older download goes when a newer one is fetched (cache was left read-only
        # and nothing was ever removed).
        self.release(recovery_image(), '0.6.203')
        code, done = self.call('fetch', '--what', 'recovery', '--sha256', self.config['recovery_release']['sha256'])
        self.assertEqual(code, 0, done)
        self.assertEqual(sorted(p.name for p in (self.root / 'cache/a22x-recovery/updates').glob('recovery-*.img')), ['recovery-0.6.203.img'])


if __name__ == '__main__':
    unittest.main()
