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
    supported = {'cache': True, 'userdata': True}

    def volume(self, label):
        return {'mounted': False, 'volume_token': 't-' + label, 'fs_type': 'ext4',
                'mountable': self.mountable[label], 'write_supported': self.supported[label]}

    def unmount(self, label, token=None):
        self.calls.append(('unmount', label))

    def format(self, label, kind, confirmed, token):
        self.calls.append(('format', label, kind))


class Damaged(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-settings-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.calls, self.readable = [], {'cache': True, 'userdata': True}
        self.writable = {'cache': True, 'userdata': True}
        for label in ('cache', 'userdata'):
            (self.root / label / 'a22x-recovery').mkdir(parents=True)

        @contextlib.contextmanager
        def volume_root(context, label, mode):
            if not self.readable[label] or (mode == 'rw' and not self.writable[label]):
                raise OSError('cannot mount ' + label)
            self.calls.append(('open', label, mode))
            yield self.root / label
        patches = [mock.patch.object(settings, 'volume_root', volume_root),
                   mock.patch.object(settings, 'lease', lambda *a, **k: contextlib.nullcontext()),
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
        real = settings.fs.open_regular
        def failing(path, *a, **k):
            if Path(path).parent.parent.name == 'cache':
                raise OSError(5, 'Input/output error')
            return real(path, *a, **k)
        with mock.patch.object(settings.fs, 'open_regular', failing):
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

    def chosen(self, mode):
        with settings.settings_root(FakeContext(self.root, self.calls), mode) as (label, root):
            self.assertEqual(root, self.root / label)
            return label

    def test_settings_and_themes_go_where_the_next_start_reads_them(self):
        # 2026-11-14 review: a write that failed on cache went to userdata, unread while cache holds settings.
        for mode in ('ro', 'rw'):
            self.assertEqual(self.chosen(mode), 'cache')  # none yet: the first that opens
        self.write('userdata', json.dumps(GOOD))
        self.assertEqual((self.chosen('ro'), self.chosen('rw')), ('userdata', 'userdata'))
        self.write('cache', json.dumps(GOOD))
        self.assertEqual((self.chosen('ro'), self.chosen('rw')), ('cache', 'cache'))
        self.readable = {'cache': False, 'userdata': True}
        for mode in ('ro', 'rw'):
            with self.assertRaises(settings.Unreadable):
                self.chosen(mode)
        self.readable = {'cache': True, 'userdata': False}
        self.calls.clear()
        self.assertTrue(settings.write_disk({'theme': 'y'}))
        # Opened once, for writing (2026-11-14 review: once read-only to choose it, then again).
        self.assertEqual([call for call in self.calls if call[0] == 'open'], [('open', 'cache', 'rw')])

    def test_a_volume_that_cannot_be_written_and_holds_nothing_is_passed_over(self):
        # 2026-11-14 review: Android's encrypted userdata, never writable here, made every first save
        # of the settings fail while cache held none yet.
        (self.root / 'cache' / settings.RELATIVE).unlink(missing_ok=True)
        self.writable = {'cache': True, 'userdata': False}
        self.calls.clear()
        self.assertTrue(settings.write_disk({'theme': 'y'}))
        self.assertTrue((self.root / 'cache' / settings.RELATIVE).is_file())
        # cache opened once and kept open while userdata was looked at read-only.
        self.assertEqual([call for call in self.calls if call[0] == 'open'], [('open', 'cache', 'rw'), ('open', 'userdata', 'ro')])
        # Where the settings are, a volume that cannot be written fails the write: never another.
        (self.root / 'cache' / settings.RELATIVE).unlink()
        self.write('userdata', json.dumps(GOOD))
        self.assertFalse(settings.write_disk({'theme': 'z'}))
        self.assertFalse((self.root / 'cache' / settings.RELATIVE).exists())

    # Every state a settings volume can be in (2026-11-14, four reviews): there or not, mounted by
    # another owner, never writable here (Android's encryption), writable only later, unreadable;
    # each with the settings file or without it.
    KINDS = {  # mountable, mounted, write_supported, read_only_reason_code, opens read-only, opens for writing
        'absent': (False, False, False, None, False, False),
        'now': (True, False, True, None, True, True),
        'later': (True, False, True, None, True, False),
        'outside': (False, True, False, None, True, False),
        'never': (True, False, False, 'FSCRYPT_KEYS_UNAVAILABLE', True, False),
        'dead': (True, False, True, None, False, False)}
    STATES = ['absent'] + [kind + suffix for kind in ('now', 'later', 'outside', 'never', 'dead') for suffix in ('', '+file')]

    def every_state(self, cache, userdata, probe):
        kinds = {'cache': cache, 'userdata': userdata}
        violations = []

        class Context(FakeContext):
            def volume(self, label):
                mountable, mounted, supported, code = Damaged.KINDS[kinds[label].split('+')[0]][:4]
                return {'mounted': mounted, 'volume_token': 't-' + label, 'fs_type': 'ext4', 'mountable': mountable,
                        'write_supported': supported, 'read_only_reason_code': code}

        @contextlib.contextmanager
        def volume_root(context, label, mode):
            kind = kinds[label].split('+')[0]
            ro, rw = self.KINDS[kind][4:]
            if mode == 'rw' and kind == 'never':
                violations.append(label)
            if not (rw if mode == 'rw' else ro):
                raise OSError('cannot open %s %s' % (label, mode))
            self.calls.append(('open', label, mode))
            yield self.root / label
        for label, state in kinds.items():
            path = self.root / label / settings.RELATIVE
            path.unlink(missing_ok=True)
            if state.endswith('+file'):
                path.write_text(json.dumps({**GOOD, 'theme': 'before-' + label}))
        with mock.patch.object(settings, 'volume_root', volume_root), \
                mock.patch.object(settings.fs, 'DeviceContext', lambda: Context(self.root, self.calls)):
            return probe(), violations

    def read_now(self):
        try:
            return settings.read_disk()
        except OSError as error:
            return error

    def test_every_state_of_both_volumes_writes_only_where_the_next_start_reads(self):
        # One rule (settings.choose), checked against read_disk for all 121 pairs of states.
        for cache in self.STATES:
            for userdata in self.STATES:
                with self.subTest(cache=cache, userdata=userdata):
                    def probe():
                        before = self.read_now()
                        self.calls.clear()
                        written = settings.write_disk({'theme': 'y'})
                        opens = [call[1] for call in self.calls if call[0] == 'open']
                        after = self.read_now()
                        return before, written, opens, after
                    (before, written, opens, after), violations = self.every_state(cache, userdata, probe)
                    self.assertEqual(violations, [])  # a volume never writable here is never opened for writing
                    self.assertLessEqual(max([opens.count(label) for label in ('cache', 'userdata')]), 1, opens)
                    landed = [label for label in ('cache', 'userdata')
                              if (self.root / label / settings.RELATIVE).is_file()
                              and json.loads((self.root / label / settings.RELATIVE).read_text()).get('theme') == 'y']
                    kinds = {'cache': cache.split('+')[0], 'userdata': userdata.split('+')[0]}
                    holder = next((label for label in ('cache', 'userdata') if (cache, userdata)[label == 'userdata'].endswith('+file')
                                   and kinds[label] not in ('absent', 'dead')), None)
                    if written:
                        self.assertEqual(len(landed), 1)
                        # An oracle apart from settings.choose, read_disk's rule as it was written
                        # before both shared it: in order, past volumes not there, the first that
                        # holds the file; one that cannot be looked at first is no reading.
                        reads = None
                        for label in ('cache', 'userdata'):
                            if kinds[label] == 'absent':
                                continue
                            if kinds[label] == 'dead':
                                break
                            if (self.root / label / settings.RELATIVE).exists():
                                reads = label
                                break
                        self.assertEqual(reads, landed[0], (cache, userdata))
                        # Never written while the settings cannot be read now...
                        self.assertNotIsInstance(before, OSError)
                        # ... where they are read from, or with none anywhere, on the first volume that may take them...
                        first = next(label for label in ('cache', 'userdata') if kinds[label] not in ('absent', 'never'))
                        self.assertEqual(landed[0], before.get('theme', '').replace('before-', '') if before else first)
                        # ... and the next start reads what was written.
                        self.assertEqual(after.get('theme'), 'y')
                    else:
                        self.assertEqual(landed, [])
                        if not isinstance(before, OSError):
                            # Readable now, yet not written: the volume to write is not writable at this moment.
                            target = holder or next((label for label in ('cache', 'userdata') if kinds[label] not in ('absent', 'never')), None)
                            self.assertTrue(target is None or kinds[target] != 'now', (target, kinds))

    def test_settings_that_cannot_be_looked_at_are_never_none(self):
        # 2026-11-14 review: Path.is_file() answers False to any error, so a settings file whose stat
        # failed (EIO, EACCES) read as none: the phone opened without its password, and the next save
        # replaced the file with a record without it.
        self.write('cache', json.dumps(GOOD))
        before = (self.root / 'cache' / settings.RELATIVE).read_text()
        real = os.lstat

        def failing(path, *args, **kwargs):
            if str(path).endswith(str(settings.RELATIVE)) and '/cache/' in str(path):
                raise PermissionError(13, 'Permission denied')
            return real(path, *args, **kwargs)
        with mock.patch.object(settings.os, 'lstat', failing):
            with self.assertRaises(settings.Unreadable):
                settings.read_disk()
            self.assertFalse(settings.write_disk({'theme': 'y'}))
        self.assertEqual((self.root / 'cache' / settings.RELATIVE).read_text(), before)
        self.assertFalse((self.root / 'userdata' / settings.RELATIVE).exists())
        self.assertFalse(settings.present(self.root / 'cache' / 'none.json'))

    def test_what_is_no_regular_file_is_damaged_never_none(self):
        # 2026-11-14 review: a folder or a dangling link where settings.json should be read as no
        # settings, and the phone opened without its password.
        target = self.root / 'cache' / settings.RELATIVE
        for make in (lambda: target.mkdir(), lambda: target.symlink_to('/nonexistent/settings.json')):
            if target.is_symlink() or target.is_file():
                target.unlink()
            elif target.is_dir():
                target.rmdir()
            make()
            with self.assertRaises(settings.Damaged):
                settings.read_disk()
        self.assertFalse((self.root / 'userdata' / settings.RELATIVE).exists())

    def test_a_reset_removes_whatever_stands_where_the_settings_should_be(self):
        # 2026-11-14 review: for a folder at settings.json, or a file where its folder should be,
        # unlink failed after userdata was erased; every try erased it again and the phone stayed locked.
        rel = settings.RELATIVE
        for name, make in (('folder', lambda: (self.root / 'cache' / rel).mkdir()),
                           ('file for its folder', lambda: (shutil.rmtree(self.root / 'cache' / rel.parent),
                                                           (self.root / 'cache' / rel.parent).write_text('x'))),
                           ('loop of links', lambda: (shutil.rmtree(self.root / 'cache' / rel.parent),
                                                      os.symlink(rel.parent.name, self.root / 'cache' / rel.parent)))):
            with self.subTest(name):
                parent = self.root / 'cache' / rel.parent
                if parent.is_symlink() or parent.is_file():
                    parent.unlink()
                elif parent.is_dir():
                    shutil.rmtree(parent)
                parent.mkdir()
                make()
                with self.assertRaises(settings.Damaged):
                    settings.read_disk()
                self.calls.clear()
                self.assertEqual(settings.reset_damaged(), 0)
                self.assertEqual([c for c in self.calls if c[0] == 'format'], [('format', 'userdata', 'ext4')])
                self.assertEqual(settings.read_disk(), {})
                (self.root / 'cache' / rel.parent).mkdir(exist_ok=True)

    def test_damaged_settings_stay_damaged_when_a_volume_fails_to_close(self):
        # 2026-11-14 review: the unmount's error replaced Damaged, and the reset was never offered.
        self.write('cache', '{not json')

        @contextlib.contextmanager
        def closing_fails(context, label, mode):
            self.calls.append(('open', label, mode))
            yield self.root / label
            raise OSError(16, 'Device or resource busy')
        with mock.patch.object(settings, 'volume_root', closing_fails):
            with self.assertRaises(settings.Damaged):
                settings.read_disk()

    def test_settings_there_that_cannot_be_opened_are_never_none(self):
        # 2026-11-14 review: any ENOENT from the open (its reopen through /proc too) read as no settings.
        self.write('cache', json.dumps(GOOD))
        with mock.patch.object(settings.fs, 'open_regular', side_effect=FileNotFoundError(2, 'No such file')):
            with self.assertRaises(settings.Unreadable):
                settings.read_disk()

    def test_a_dangling_link_for_the_settings_folder_is_damaged(self):
        # 2026-11-14 review: a link there to a folder not there read as no settings, and the phone opened.
        folder = self.root / 'cache' / settings.RELATIVE.parent
        shutil.rmtree(folder)
        folder.symlink_to('/nonexistent/folder')
        with self.assertRaises(settings.Damaged):
            settings.read_disk()

    def test_a_password_once_set_never_reads_as_none(self):
        # 2026-11-14 review: every way of misreading "not there" opened the phone. The mark of a password
        # set, outside the settings folder, keeps missing settings locked until they are reset.
        record = {**GOOD}
        self.assertTrue(record.get('hash'))
        self.assertTrue(settings.write_disk(record))
        mark = self.root / 'cache' / settings.PASSWORD_MARK
        self.assertTrue(mark.is_file())
        shutil.rmtree(self.root / 'cache' / settings.RELATIVE.parent)  # whatever took the folder
        with self.assertRaises(settings.Damaged) as caught:
            settings.read_disk()
        self.assertEqual(caught.exception.label, 'cache')
        self.assertEqual(settings.reset_damaged(), 0)
        self.assertFalse(mark.exists())
        self.assertEqual(settings.read_disk(), {})
        # Clearing the password removes the mark with it.
        self.assertTrue(settings.write_disk(record))
        self.assertTrue(mark.is_file())
        self.assertTrue(settings.write_disk({k: v for k, v in record.items() if k not in ('hash', 'salt')}))
        self.assertFalse(mark.exists())

    def test_present_says_no_for_a_loop_of_links(self):
        loop = self.root / 'loop'
        loop.symlink_to('loop')
        self.assertFalse(settings.present(loop))

    def test_themes_come_from_the_volume_that_keeps_the_settings(self):
        # 2026-11-14 reviews: themes are written where the settings are; a theme or note left on
        # another volume came back at every start whatever removed it.
        self.write('userdata', json.dumps(GOOD))
        copied = []
        with mock.patch.object(settings, 'copy_themes', lambda root: copied.append(Path(root).name)):
            settings.read_disk()
        self.assertEqual(copied, ['userdata'])

    def test_with_no_settings_anywhere_reads_and_writes_choose_one_volume(self):
        # 2026-11-14 review: beside a cache never written here, themes went to userdata and were read from cache.
        states = [('cache', True, False, 'never'), ('userdata', True, False, 'now')]
        self.assertEqual((settings.choose(states, 'ro'), settings.choose(states, 'rw')), ('userdata', 'userdata'))
        only = [('cache', True, False, 'never')]
        self.assertEqual(settings.choose(only, 'ro'), 'cache')
        with self.assertRaises(settings.NoSettingsVolume):
            settings.choose(only, 'rw')

    def test_a_volume_that_fails_to_close_after_the_work_keeps_the_work(self):
        # 2026-11-14 review: a password written to disk was said kept in RAM because the unmount failed.
        @contextlib.contextmanager
        def closing_fails(context, label, mode):
            self.calls.append(('open', label, mode))
            yield self.root / label
            raise OSError(16, 'Device or resource busy')
        with mock.patch.object(settings, 'volume_root', closing_fails):
            self.assertTrue(settings.write_disk({'theme': 'y'}))
        self.assertEqual(json.loads((self.root / 'cache' / settings.RELATIVE).read_text())['theme'], 'y')

    def test_the_rows_the_reviews_named(self):
        expect = {('later', 'now'): None,          # cache busy a moment: kept in RAM, never moved to userdata
                  ('outside', 'now'): None,        # cache mounted by another owner: the same
                  ('now', 'never'): 'cache',       # Android's userdata beside an empty cache
                  ('never', 'now'): 'userdata',    # a cache this recovery never writes
                  ('absent', 'now'): 'userdata',   # no usable filesystem on cache
                  ('now', 'later+file'): None,     # the settings are on userdata, not writable now
                  ('now', 'dead'): None}           # userdata cannot be looked at: the start could not read either
        for (cache, userdata), target in expect.items():
            with self.subTest(cache=cache, userdata=userdata):
                written, _ = self.every_state(cache, userdata, lambda: settings.write_disk({'theme': 'y'}))
                landed = [label for label in ('cache', 'userdata') if (self.root / label / settings.RELATIVE).is_file()
                          and json.loads((self.root / label / settings.RELATIVE).read_text()).get('theme') == 'y']
                self.assertEqual((written, landed), (target is not None, [target] if target else []))

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
