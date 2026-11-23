"""The boot splash of the theme in use, kept in misc for the kernel (2026-11-21)."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import boot_splash as bs  # noqa: E402
import misc_store as ms  # noqa: E402

W, H = bs.WIDTH, bs.HEIGHT
BOX = (220, 904, 64, 40)


def background(x, y):
    """A gradient like the themes' backdrops."""
    return (8 + x * 40 // W, 15 + y * 60 // H, 31 + (x + y) * 30 // (W + H))


def fake_ui(folder, theme, solid=False):
    """What recovery-ui --splash-pictures writes for THEME: a gradient (or one color) with a box of
    words over it."""
    folder = Path(folder)
    color = {'aurora': (0x4a, 0xe6, 0xd6), 'graphite': (0xff, 0x9a, 0x4b)}.get(theme, (1, 2, 3))
    grids = []
    for scale in (1, 2, 4, 8, 16):
        gw, gh = -(-W // scale), -(-H // scale)
        cells = bytearray()
        for gy in range(gh):
            for gx in range(gw):
                x, y = (gx * W // gw + (gx + 1) * W // gw) // 2, (gy * H // gh + (gy + 1) * H // gh) // 2
                cells += bytes((14, 16, 19) if solid else background(x, y))
        (folder / ('grid-%d.rgb' % scale)).write_bytes(bytes(cells))
        grids.append([scale, gw, gh])
    x0, y0, w, h = BOX
    mask = bytes(1 if (row // 4 + column // 4) % 2 else 0 for row in range(h) for column in range(w))
    (folder / 'crop.bin').write_bytes(mask + bytes(color) * sum(mask))
    return {'ok': True, 'theme': theme, 'width': W, 'height': H, 'bar': [270, 1474, 540, 12], 'track': 0x2b3e57,
            'fill': 0x4ae6d6, 'crop': list(BOX), 'set': sum(mask), 'grids': grids}


class PackTest(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.folder)

    def test_a_plain_color_fits_whole_and_comes_back_exactly(self):
        facts = fake_ui(self.folder, 'graphite', solid=True)
        payload, scale = bs.pack(facts, self.folder, ms.payload_max('splash'))
        self.assertEqual(scale, 1)
        record = bs.parse(payload)
        self.assertEqual((record['grid'], record['box'], record['bar']), ((W, H), BOX, (270, 1474, 540, 12)))
        rows = bs.picture(payload, [0, BOX[1], BOX[1] + 1, H - 1])
        self.assertEqual(rows[0], bytes((14, 16, 19)) * W)
        line = rows[BOX[1] + 1]
        self.assertEqual(line[:BOX[0] * 3], bytes((14, 16, 19)) * BOX[0])
        self.assertEqual(line[(BOX[0] + 4) * 3:(BOX[0] + 5) * 3], bytes((0xff, 0x9a, 0x4b)))  # in the box, set
        self.assertEqual(line[BOX[0] * 3:(BOX[0] + 1) * 3], bytes((14, 16, 19)))  # in the box, its background

    def test_the_finest_grid_that_fits_is_taken(self):
        facts = fake_ui(self.folder, 'aurora')
        whole, _ = bs.pack(facts, self.folder, ms.payload_max('splash'))
        payload, scale = bs.pack(facts, self.folder, len(whole) - 1)  # the whole gradient no longer fits
        self.assertGreater(scale, 1)
        record = bs.parse(payload)
        self.assertEqual(record['grid'], (-(-W // scale), -(-H // scale)))
        # Stretched back, the gradient stays within a level of the original away from the box.
        row = H // 2
        got = bs.picture(payload, [row])[row]
        for column in (0, 100, 540, W - 1):
            want = background(column, row)
            self.assertLessEqual(max(abs(got[column * 3 + k] - want[k]) for k in range(3)), 1, column)
        self.assertEqual(record['source'], bs.parse(whole)['source'])  # the same picture, packed finer or coarser

    def test_nothing_fits_is_an_error(self):
        facts = fake_ui(self.folder, 'aurora')
        with self.assertRaises(bs.SplashError) as caught:
            bs.pack(facts, self.folder, 200)
        self.assertEqual(caught.exception.code, 'SPLASH_TOO_LARGE')

    def test_pictures_that_do_not_match_their_facts_are_refused(self):
        facts = fake_ui(self.folder, 'aurora')
        (self.folder / 'crop.bin').write_bytes((self.folder / 'crop.bin').read_bytes()[:-3])
        with self.assertRaises(bs.SplashError):
            bs.pack(facts, self.folder, ms.payload_max('splash'))

    def test_a_damaged_record_is_refused_as_the_kernel_refuses_it(self):
        payload, _ = bs.pack(fake_ui(self.folder, 'graphite', solid=True), self.folder, ms.payload_max('splash'))
        for broken in (payload[:-1], b'A22XSPL2' + payload[8:], payload[:8] + (1079).to_bytes(2, 'little') + payload[10:],
                       payload[:28] + (W + 1).to_bytes(2, 'little') + payload[30:]):
            with self.assertRaises(bs.SplashError):
                bs.picture(broken, [0])


class SaveTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.misc = self.root / 'misc'
        self.misc.write_bytes(bytes(ms.END))
        patcher = mock.patch.dict(os.environ, {'A22X_MISC': str(self.misc)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.renders = []

        def render(theme, ui, folder):
            self.renders.append(theme)
            return fake_ui(folder, theme, solid=theme == 'graphite')
        patcher = mock.patch.object(bs, 'render', render)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_kept_once_then_left_alone_and_nothing_else_in_misc_changes(self):
        settings = os.urandom(1000)
        ms.write('settings', settings)
        before = self.misc.read_bytes()
        first = bs.save('aurora', lock=False)
        self.assertTrue(first['written'])
        after = self.misc.read_bytes()
        start, end = ms.SPLASH_AREAS['splash'], ms.SPLASH_AREAS['splash'] + 2 * ms.SPLASH_SLOT
        self.assertEqual(after[:start], before[:start])
        self.assertEqual(after[end:], before[end:])  # the settings' area untouched
        self.assertEqual(ms.read('settings'), settings)
        payload = ms.read('splash')
        self.assertEqual(bs.parse(payload)['box'], BOX)
        self.assertFalse(bs.save('aurora', lock=False)['written'])  # misc holds it already
        self.assertEqual(self.misc.read_bytes(), after)
        self.assertTrue(bs.save('graphite', lock=False)['written'])  # another theme
        self.assertEqual(bs.parse(ms.read('splash'))['grid'], (W, H))

    def test_one_copy_left_is_written_again(self):
        bs.save('aurora', lock=False)
        data = bytearray(self.misc.read_bytes())
        data[ms.SPLASH_AREAS['splash'] + 600] ^= 0xff  # the first copy damaged
        self.misc.write_bytes(bytes(data))
        self.assertTrue(bs.save('aurora', lock=False)['written'])
        self.assertTrue(ms.state('splash')[1])

    def test_a_save_for_a_theme_no_longer_in_use_writes_nothing(self):
        themes = iter(['aurora', 'graphite'])  # drawn for Aurora; Graphite chosen meanwhile
        result = bs.save(lock=False, now=lambda: next(themes))
        self.assertEqual((result['written'], result.get('stale')), (False, True))
        self.assertIsNone(ms.read('splash'))
        self.assertEqual(self.renders, ['aurora'])

    def test_the_record_s_layout_is_the_kernel_s(self):
        """mtk_boot_splash.c: two slots of 128 KiB at 128 KiB; header 'A22XMSC1', 'splash', generation,
        length, flags; SHA-256 of the 32 bytes of header and the payload at 32; the payload at 512."""
        bs.save('graphite', lock=False)
        data = self.misc.read_bytes()
        for index in (0, 1):
            slot = data[(128 << 10) + index * (128 << 10):(128 << 10) + (index + 1) * (128 << 10)]
            self.assertEqual(slot[:16], b'A22XMSC1splash\0\0')
            length = int.from_bytes(slot[24:28], 'little')
            self.assertEqual(int.from_bytes(slot[28:32], 'little'), 0)
            payload = slot[512:512 + length]
            self.assertEqual(hashlib.sha256(slot[:32] + payload).digest(), slot[32:64])
            self.assertEqual(payload[:8], b'A22XSPL1')

    def test_show_and_the_command_line(self):
        self.assertEqual(bs.show(), {'kept': False})
        bs.save('graphite', lock=False)
        shown = bs.show()
        self.assertTrue(shown['kept'])
        self.assertEqual((shown['track'], shown['fill']), ('2b3e57', '4ae6d6'))
        with mock.patch.object(bs, 'save', side_effect=bs.SplashError('RENDER_FAILED', 'no')), \
                mock.patch('builtins.print') as printed:
            self.assertEqual(bs.main(['save', '--theme', 'aurora']), 2)
        self.assertEqual(json.loads(printed.call_args[0][0])['error']['code'], 'RENDER_FAILED')

    def test_theme_names_are_checked_before_the_ui_runs(self):
        for bad in ('ab', 'Aurora', 'a/../b', 'x' * 24):
            self.assertFalse(bs.valid_theme(bad))
        self.assertTrue(bs.valid_theme('my-theme-2'))


UI_BINARY = Path(__file__).resolve().parents[1] / 'ui/a22x-recovery-ui'


@unittest.skipUnless(UI_BINARY.exists(), 'the host build of the UI is not there')
class RealUiTest(unittest.TestCase):
    """recovery-ui --splash-pictures: the pictures of a built-in theme pack and come back as drawn."""

    def test_graphite_and_aurora(self):
        for theme, scale in (('graphite', 1), ('aurora', None)):
            folder = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, folder)
            facts = bs.render(theme, str(UI_BINARY), folder)
            self.assertEqual((facts['theme'], facts['bar']), (theme, [270, 1474, 540, 12]))
            x, y, w, h = facts['crop']
            self.assertTrue(200 < x and x + w < W - 200 and 800 < y and y + h < 1474, facts['crop'])  # the logo and its words
            payload, got = bs.pack(facts, folder, ms.payload_max('splash'))
            if scale:
                self.assertEqual(got, scale)
            row = y + h // 2
            line = bs.picture(payload, [row])[row]
            self.assertNotEqual(line[x * 3:(x + w) * 3], line[:w * 3])  # words over the background


class SplashStoreTest(unittest.TestCase):
    """misc_store's splash store stands apart from the settings' one."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.misc = self.root / 'misc'
        patcher = mock.patch.dict(os.environ, {'A22X_MISC': str(self.misc)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_foreign_bytes_in_one_store_never_stop_the_other(self):
        data = bytearray(ms.END)
        data[ms.SPLASH_AREAS['splash'] + 5] = 9  # another's byte where the splash goes
        self.misc.write_bytes(bytes(data))
        ms.write('settings', b'{}')  # the settings are saved all the same
        self.assertEqual(ms.read('settings'), b'{}')
        with self.assertRaises(ms.Foreign):
            ms.write('splash', b'x')  # the splash never writes over it
        data = bytearray(ms.END)
        data[ms.AREAS['settings'] + 5] = 9
        self.misc.write_bytes(bytes(data))
        ms.write('splash', b'picture')
        self.assertEqual(ms.read('splash'), b'picture')

    def test_its_size_and_its_clear(self):
        self.misc.write_bytes(bytes(ms.END))
        with self.assertRaises(ValueError):
            ms.write('splash', bytes(ms.payload_max('splash') + 1))
        ms.write('splash', bytes(range(256)) * (ms.payload_max('splash') // 256))
        self.assertEqual(len(ms.read('splash')), ms.payload_max('splash') // 256 * 256)
        ms.clear('splash')
        self.assertIsNone(ms.read('splash'))
        self.assertEqual(self.misc.read_bytes(), bytes(ms.END))


if __name__ == '__main__':
    unittest.main()
