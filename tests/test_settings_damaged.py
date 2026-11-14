"""Damaged or unreadable settings never mean "no password" (settings.py, 2026-11-12 audit)."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import settings

GOOD = {'theme': 'aurora', 'hash': 'ab' * 32, 'salt': '0f' * 16}


REAL_COPY_THEMES = settings.copy_themes


class FakeContext:
    lock_path, mode = '/nonexistent', 'fixture'

    def __init__(self, root, calls):
        self.root, self.calls = root, calls

    mountable = {'cache': True, 'userdata': True}

    def volume(self, label):
        return {'mounted': False, 'volume_token': 't-' + label, 'fs_type': 'ext4',
                'mountable': self.mountable[label]}

    def unmount(self, label, token=None):
        self.calls.append(('unmount', label))

    def format(self, label, kind, confirmed, token):
        self.calls.append(('format', label, kind))


class Damaged(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-settings-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls, self.readable = [], {'cache': True, 'userdata': True}
        for label in ('cache', 'userdata'):
            (self.root / label / 'a22x-recovery').mkdir(parents=True)

        @contextlib.contextmanager
        def volume_root(context, label, mode):
            if not self.readable[label]:
                raise OSError('cannot mount ' + label)
            self.calls.append(('open', label, mode))
            yield self.root / label
        patches = [mock.patch.object(settings, 'volume_root', volume_root),
                   mock.patch.object(settings, 'operation_lock', lambda *a, **k: contextlib.nullcontext()),
                   mock.patch.object(settings.fs, 'DeviceContext', lambda: FakeContext(self.root, self.calls)),
                   mock.patch.object(settings, 'RAM_COPY', self.root / 'ram.json'),
                   mock.patch.object(settings, 'copy_themes', lambda root: None)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def write(self, label, text):
        (self.root / label / settings.RELATIVE).write_text(text)

    def test_checked_refuses_what_is_not_whole(self):
        for bad in ([], {'hash': 'abc', 'salt': '00'}, {'hash': 'ab' * 32}, {'salt': '0f' * 16}, {'hash': 'AB' * 32, 'salt': '0f' * 16}):
            with self.assertRaises(settings.Damaged):
                settings.checked(bad)
        self.assertEqual(settings.checked(GOOD), GOOD)
        self.assertEqual(settings.checked({'theme': 'x'}), {'theme': 'x'})

    def test_a_damaged_file_on_cache_is_not_passed_over(self):
        self.write('cache', '{"hash": ')
        self.write('userdata', json.dumps({'theme': 'x'}))
        with self.assertRaises(settings.Damaged) as raised:
            settings.read_disk()
        self.assertEqual(raised.exception.label, 'cache')

    def test_a_file_that_cannot_be_read_now_is_not_damaged_and_opens_nothing(self):
        """2026-11-12 review: EIO or EACCES on the file offered erasing settings and userdata."""
        self.write('cache', json.dumps(GOOD))
        self.write('userdata', json.dumps({'theme': 'x'}))
        real = Path.read_text
        def failing(path, *a, **k):
            if path.parent.parent.name == 'cache':
                raise OSError(5, 'Input/output error')
            return real(path, *a, **k)
        with mock.patch.object(Path, 'read_text', failing):
            with self.assertRaises(settings.Unreadable):
                settings.read_disk()
            self.assertEqual(settings.reset_damaged(), 1)
        self.assertNotIn(('format', 'userdata', 'ext4'), self.calls)

    def test_cache_without_settings_asks_userdata_and_none_is_no_password(self):
        self.write('userdata', json.dumps(GOOD))
        self.assertEqual(settings.read_disk(), GOOD)
        (self.root / 'userdata' / settings.RELATIVE).unlink()
        self.assertEqual(settings.read_disk(), {})
        self.readable = {'cache': False, 'userdata': False}
        with self.assertRaises(OSError):
            settings.read_disk()

    def test_settings_and_themes_go_where_the_next_start_reads_them(self):
        # 2026-11-14 review: a write that failed on cache went to userdata, unread while cache holds settings.
        context = FakeContext(self.root, self.calls)
        self.assertEqual(settings.settings_volume(context), 'cache')  # none yet: the first that opens
        self.write('userdata', json.dumps(GOOD))
        self.assertEqual(settings.settings_volume(context), 'userdata')
        self.write('cache', json.dumps(GOOD))
        self.assertEqual(settings.settings_volume(context), 'cache')
        self.readable = {'cache': False, 'userdata': True}
        with self.assertRaises(settings.Unreadable):
            settings.settings_volume(context)
        self.readable = {'cache': True, 'userdata': False}
        self.calls.clear()
        self.assertTrue(settings.write_disk({'theme': 'y'}))
        self.assertIn(('open', 'cache', 'rw'), self.calls)
        self.assertNotIn(('open', 'userdata', 'rw'), self.calls)

    def test_a_theme_that_cannot_be_copied_does_not_lock_the_phone(self):
        # 2026-11-14 review: an EIO on one theme made read_disk say the settings could not be read.
        self.write('cache', json.dumps(GOOD))
        (self.root / 'cache' / settings.THEMES).mkdir(parents=True)
        (self.root / 'cache' / settings.THEMES / 'mine.theme').write_text('x')
        def broken(*args, **kwargs):
            raise OSError(5, 'Input/output error')
        with mock.patch.object(settings, 'copy_themes', REAL_COPY_THEMES), \
                mock.patch.object(settings, 'RAM_THEMES', self.root / 'ram-themes'), mock.patch.object(settings.shutil, 'copyfile', broken):
            self.assertEqual(settings.read_disk(), GOOD)

    def test_a_cache_that_fails_to_mount_is_not_taken_for_one_without_settings(self):
        # 2026-11-13 review: cache with the password failed to mount, userdata had no settings, and
        # the phone opened without its password.
        self.write('cache', json.dumps(GOOD))
        self.readable = {'cache': False, 'userdata': True}
        with self.assertRaises(settings.Unreadable):
            settings.read_disk()
        # A cache without any filesystem holds no settings: userdata is asked.
        with mock.patch.dict(FakeContext.mountable, {'cache': False}):
            self.write('userdata', json.dumps({'theme': 'x'}))
            self.assertEqual(settings.read_disk(), {'theme': 'x'})

    def test_a_damaged_copy_in_ram_is_read_again_from_the_disk(self):
        (self.root / 'ram.json').write_text('[1, 2')
        self.write('cache', json.dumps(GOOD))
        self.assertEqual(settings.load(), GOOD)
        self.assertEqual(json.loads((self.root / 'ram.json').read_text()), GOOD)
        (self.root / 'ram.json').write_text('{"hash": "x"}')
        self.write('cache', 'garbage')
        with self.assertRaises(settings.Damaged):
            settings.load()

    def test_reset_erases_userdata_before_the_damaged_file(self):
        self.write('cache', json.dumps(GOOD))
        self.assertEqual(settings.reset_damaged(), 1)  # not damaged: nothing erased
        self.assertNotIn('format', [c[0] for c in self.calls])
        self.write('cache', '{"hash": ')
        self.calls.clear()
        self.assertEqual(settings.reset_damaged(), 0)
        kinds = [c[0] for c in self.calls]
        self.assertIn(('open', 'cache', 'rw'), self.calls)
        self.assertLess(self.calls.index(('open', 'cache', 'rw')), kinds.index('format'))
        self.assertFalse((self.root / 'cache' / settings.RELATIVE).exists())
        self.assertEqual(settings.read_disk(), {})

    def test_reset_stops_before_erasing_when_cache_cannot_be_written(self):
        self.write('cache', 'garbage')

        @contextlib.contextmanager
        def refusing(context, label, mode):
            if mode == 'rw':
                raise OSError('read-only')
            yield self.root / label
        with mock.patch.object(settings, 'volume_root', refusing):
            with self.assertRaises(OSError):
                settings.reset_damaged()
        self.assertNotIn('format', [c[0] for c in self.calls])
        self.assertTrue((self.root / 'cache' / settings.RELATIVE).exists())


if __name__ == '__main__':
    unittest.main()
