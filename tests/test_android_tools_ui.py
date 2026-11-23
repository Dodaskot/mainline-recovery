"""Cross-layer host tests for real analyzer reports consumed by the C UI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import android_compat as ac

UI_TEST = ROOT / 'ui/android-tools-test'


@unittest.skipUnless(UI_TEST.is_file(), 'build ui/android-tools-test first')
class AnalyzerUiContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='a22x-compat-ui-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        current = self.directory / 'current'
        current.mkdir()
        (current / 'build.prop').write_text('ro.build.version.sdk=36\n')
        fstab = '/dev/block/userdata /data f2fs noatime fileencryption=aes-256-xts:aes-256-cts:v2\n'
        (current / 'fstab.mt6833').write_text(fstab)
        image = bytearray(8192)
        image[1080:1082] = b'\x53\xef'
        package = self.directory / 'maximum.zip'
        known = ['boot', 'vendor', 'odm', 'dtbo', 'vendor_boot',
                 'vbmeta', 'vbmeta_system', 'vbmeta_vendor']
        with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name in known + ['unknown' + str(n) for n in range(32 - len(known))]:
                archive.writestr(name + '.img', image)
            archive.writestr('fstab.mt6833', fstab)
            archive.writestr(ac.METADATA_PATH,
                             'ota-wipe=no\nota-downgrade=no\npre-build=fixture\n'
                             'pre-build-incremental=fixture\n')
        self.report = ac.analyze_file(package, current_root=current)

    def parse(self, report):
        source = self.directory / 'report.json'
        source.write_text(json.dumps(report))
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run([str(UI_TEST), '--compat-report', str(source)],
                                cwd=ROOT, env=env, capture_output=True, text=True,
                                timeout=20)
        return result, json.loads(result.stdout)

    def test_maximum_package_report_renders_every_check(self):
        self.assertEqual(len(self.report['write_set']), 32)
        self.assertGreater(len(self.report['checks']), 80)
        result, parsed = self.parse(self.report)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(parsed['ok'])
        self.assertEqual(parsed['checks'], len(self.report['checks']))
        self.assertFalse(self.report['preserve_allowed'])

    def test_report_above_display_bound_is_refused_without_partial_result(self):
        report = dict(self.report)
        report['checks'] = [{'id': 'CHECK_' + str(n), 'status': 'unknown',
                             'reason': 'Synthetic overflow boundary'} for n in range(193)]
        result, parsed = self.parse(report)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(parsed['ok'])


if __name__ == '__main__':
    unittest.main()
