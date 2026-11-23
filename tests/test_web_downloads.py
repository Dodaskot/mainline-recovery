"""Browser downloads moved from RAM to a card by web_downloads.py (2026-11-20, a tester, #6)."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import unittest.mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import filesystem as fs  # noqa: E402
import web_downloads as wd  # noqa: E402

UID = os.getuid()


class Delivery(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-downloads-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.ram = self.root / 'ram'
        self.ram.mkdir()
        self.source = os.open(self.ram, os.O_DIRECTORY)
        self.addCleanup(os.close, self.source)

    def volumes(self, sd=(True, False), usb=None):
        rows = []
        for ident, state, kind in (('sdcard-p1', sd, 'exfat'), ('usb-p1', usb, 'exfat')):
            if state is not None:
                (self.root / ident).mkdir(exist_ok=True)
                rows.append({'id': ident, 'path': ident, 'fs_type': kind, 'mounted': state[0], 'read_only': state[1]})
        (self.root / 'cache').mkdir(exist_ok=True)
        rows.append({'id': 'cache', 'path': 'cache', 'fs_type': 'ext4', 'mounted': True, 'read_only': False})
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({'schema': 'a22x.filesystem.fixture.v1', 'volumes': rows}))
        return fs.FixtureContext(self.root)

    def test_finished_downloads_go_to_the_card_and_nothing_is_replaced(self):
        context = self.volumes()
        (self.ram / 'photo.jpg').write_bytes(b'jpeg')
        (self.ram / 'video.mp4.crdownload').write_bytes(b'still coming')
        (self.ram / '.hidden').write_bytes(b'x')
        os.symlink('/etc/passwd', self.ram / 'link.txt')
        (self.root / 'sdcard-p1' / 'Download').mkdir()
        (self.root / 'sdcard-p1' / 'Download' / 'photo.jpg').write_bytes(b'older')
        volume, moved = wd.deliver(context, self.source, UID)
        self.assertEqual((volume, moved), ('sdcard-p1', ['photo (1).jpg']))
        self.assertEqual((self.root / 'sdcard-p1/Download/photo.jpg').read_bytes(), b'older')
        self.assertEqual((self.root / 'sdcard-p1/Download/photo (1).jpg').read_bytes(), b'jpeg')
        self.assertEqual(sorted(os.listdir(self.ram)), ['.hidden', 'link.txt', 'video.mp4.crdownload'])
        self.assertFalse([n for n in os.listdir(self.root / 'sdcard-p1/Download') if n.startswith('.a22x-')])

    def test_downloads_wait_in_ram_while_an_operation_runs(self):
        context = self.volumes()
        (self.ram / 'song.mp3').write_bytes(b'mp3')
        hold = self.root / 'hold'
        hold.write_bytes(b'')
        with unittest.mock.patch.object(wd, 'HOLD', hold):
            self.assertEqual(wd.deliver(context, self.source, UID), (None, []))
            self.assertTrue((self.ram / 'song.mp3').is_file())
            self.assertFalse((self.root / 'sdcard-p1/Download').exists())
            hold.unlink()
            self.assertEqual(wd.deliver(context, self.source, UID), ('sdcard-p1', ['song.mp3']))

    def test_the_folder_is_made_and_a_usb_drive_serves_when_the_card_is_read_only(self):
        context = self.volumes(sd=(True, True), usb=(True, False))
        (self.ram / 'a.pdf').write_bytes(b'%PDF')
        self.assertEqual(wd.deliver(context, self.source, UID), ('usb-p1', ['a.pdf']))
        self.assertTrue((self.root / 'usb-p1/Download/a.pdf').is_file())

    def test_the_browser_setting_chooses_the_place(self):
        """2026-11-20, the browser's settings: SD card then USB (auto), only one of them, or RAM."""
        settings = self.root / 'settings.json'
        self.assertEqual(wd.target(settings), 'auto')                     # unread: auto
        for value, expected in (('usb', 'usb'), ('ram', 'ram'), ('sdcard', 'sdcard'), ('elsewhere', 'auto')):
            settings.write_text(json.dumps({'web_downloads': value}))
            self.assertEqual(wd.target(settings), expected)
        context = self.volumes(sd=(True, False), usb=(True, False))
        ids = {where: (wd.card(context, where) or {}).get('id') for where in ('auto', 'sdcard', 'usb', 'ram')}
        self.assertEqual(ids, {'auto': 'sdcard-p1', 'sdcard': 'sdcard-p1', 'usb': 'usb-p1', 'ram': None})
        settings.write_text(json.dumps({'web_downloads': 'usb'}))
        (self.ram / 'b.zip').write_bytes(b'PK')
        with unittest.mock.patch.object(wd, 'SETTINGS', settings):
            self.assertEqual(wd.deliver(context, self.source, UID), ('usb-p1', ['b.zip']))
        settings.write_text(json.dumps({'web_downloads': 'ram'}))
        (self.ram / 'c.zip').write_bytes(b'PK')
        with unittest.mock.patch.object(wd, 'SETTINGS', settings):
            self.assertEqual(wd.deliver(context, self.source, UID), (None, []))
        self.assertTrue((self.ram / 'c.zip').is_file())

    def test_without_a_writable_card_downloads_stay_in_ram(self):
        context = self.volumes(sd=(False, False))
        (self.ram / 'a.zip').write_bytes(b'PK')
        self.assertEqual(wd.deliver(context, self.source, UID), (None, []))
        self.assertEqual(os.listdir(self.ram), ['a.zip'])
        self.assertFalse((self.root / 'cache/Download').exists())  # never another volume

    def test_names(self):
        long = 'x' * 300 + '.tar.gz'
        self.assertEqual(len(wd.short(long).encode()), wd.MAX_NAME)
        self.assertTrue(wd.short(long).endswith('.gz'))
        self.assertEqual(wd.note('sdcard-p1', 1), b'Saved to the SD card: Download')
        self.assertEqual(wd.note('usb-p1', 3), b'3 downloads saved to the USB drive: Download')

    def test_follow_moves_until_the_browser_has_finished(self):
        context = self.volumes()
        (self.ram / 'one.txt').write_bytes(b'1')
        ended, keep = os.pipe()
        ui, control = os.pipe()
        os.close(keep)  # the browser has finished already: one last pass
        wd.follow(self.source, UID, ended, control=control, interval=0.01, context=context)
        os.close(ended)
        self.assertTrue((self.root / 'sdcard-p1/Download/one.txt').is_file())
        self.assertEqual(os.read(ui, 100), b'')  # the UI is not written to after the browser closed
        os.close(ui)


if __name__ == '__main__':
    unittest.main()


class Profile(unittest.TestCase):
    def test_the_marks_of_the_last_browser_go_and_the_profile_stays(self):
        import web_launch
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            profile = Path(folder)
            for name in web_launch.SINGLETON:
                os.symlink('host-7', profile / name)
            (profile / 'Cookies').write_bytes(b'kept')
            with patch.object(web_launch.web_cache, 'profile', lambda uid: profile):
                path, fd = web_launch.session_profile()
            os.close(fd)
            self.assertEqual((path, sorted(os.listdir(profile))), (profile, ['Cookies']))
