"""The init wait accepts known A226B touchscreen names (no phone needed)."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TouchInputWait(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-touch-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.root, True)
        text = (ROOT / 'ramdisk/init').read_text()
        start = text.index('touch_input_ready() {')
        self.function = text[start:text.index('\n}\n', start) + 3]

    def ready(self):
        result = subprocess.run(['sh', '-c', self.function + 'touch_input_ready "$1"', 'sh', str(self.root)],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.stderr, '')
        return result.returncode == 0

    def test_four_touch_families_are_accepted(self):
        self.assertFalse(self.ready())
        node = self.root / 'event2/device/name'
        node.parent.mkdir(parents=True)
        for name in ('himax-touchscreen', 'sec_touchscreen', 'novatek-touchscreen',
                     'fts_ts', 'ILITEK_TDDI_7807S', 'mtk-tpd'):
            node.write_text(name + '\n')
            self.assertTrue(self.ready(), name)
        node.write_text('mtk-pmic-keys\n')
        self.assertFalse(self.ready())

    def test_other_input_node_does_not_mask_a_later_touch(self):
        buttons = self.root / 'event0/device/name'
        buttons.parent.mkdir(parents=True)
        buttons.write_text('mtk-pmic-keys\n')
        touch = self.root / 'event7/device/name'
        touch.parent.mkdir(parents=True)
        touch.write_text('sec_touchscreen\n')
        self.assertTrue(self.ready())

    def test_init_wait_is_bounded_and_ui_still_starts(self):
        text = (ROOT / 'ramdisk/init').read_text()
        self.assertIn('for n in 1 2 3 4 5 6 7 8 9 10; do\n        if [ -c /dev/fb0 ] && touch_input_ready', text)
        self.assertLess(text.index('touch_input_ready; then'), text.index('/bin/recovery-ui --device'))


if __name__ == '__main__':
    unittest.main()
