"""The settings in misc (2026-11-14): read_disk, write_disk, the copy of an older release's file,
and the reset of damaged ones. The store itself: tests/test_misc_store.py; the file of releases up
to 1.0.1: tests/test_settings_damaged.py and tests/test_settings_properties.py."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import misc_store  # noqa: E402
import settings  # noqa: E402

SECRET = {'theme': 'aurora', 'hash': 'ab' * 32, 'salt': '0f' * 16}


class Context:
    mode = 'fixture'

    def __init__(self, root):
        self.lock_path = str(root / 'lock')
        self.formatted = []

    def volume(self, label):
        return {'id': label, 'mounted': False, 'mountable': True, 'fs_type': 'ext4', 'volume_token': 't-' + label}

    def unmount(self, label, token=None):
        pass

    def format(self, label, kind, confirmed, token):
        self.formatted.append(label)


class Misc(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='a22x-smisc-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.misc = self.tmp / 'misc'
        self.misc.write_bytes(bytes(misc_store.END))
        self.context = Context(self.tmp)
        self.legacy = {}
        self.legacy_reads = 0

        def read_volumes(details=None):
            self.legacy_reads += 1
            if isinstance(self.legacy, Exception):
                raise self.legacy
            return dict(self.legacy)
        # The volumes of the older store, as folders: what _retire_volumes and the reset change.
        self.volumes = {label: self.tmp / label for label in settings.VOLUMES}
        for root in self.volumes.values():
            (root / 'a22x-recovery').mkdir(parents=True)

        @contextlib.contextmanager
        def volume_root(context, label, mode):
            yield self.volumes[label]
        for patcher in (mock.patch.dict(os.environ, {'A22X_MISC': str(self.misc), 'A22X_SETTINGS_RAM': str(self.tmp / 'ram.json')}),
                        mock.patch.object(settings, 'volume_root', volume_root),
                        mock.patch.object(settings, 'RAM_COPY', self.tmp / 'ram.json'),
                        mock.patch.object(settings.fs, 'DeviceContext', lambda: self.context),
                        mock.patch.object(settings, 'read_volumes', read_volumes),
                        mock.patch.object(settings, '_copy_themes', lambda context: None)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def legacy_files(self):
        return sorted(str(path.relative_to(self.tmp)) for root in self.volumes.values()
                      for path in (root / settings.RELATIVE, root / settings.PASSWORD_MARK) if os.path.lexists(path))

    def put_legacy(self, label='cache', record=SECRET):
        (self.volumes[label] / settings.RELATIVE).write_text(json.dumps(record))
        (self.volumes[label] / settings.PASSWORD_MARK).touch()

    def test_an_older_release_s_file_is_copied_once_then_misc_decides(self):
        self.legacy = dict(SECRET)
        self.put_legacy('cache')
        (self.volumes['userdata'] / settings.PASSWORD_MARK).touch()
        self.assertEqual(settings.read_disk(), SECRET)
        self.assertEqual(json.loads(misc_store.read('settings')), SECRET)
        # Then the older store is emptied, so it can never come back (2026-11-14 review).
        self.assertEqual(self.legacy_files(), [])
        self.legacy = {}  # the file is never read again: what it says no longer counts
        self.assertEqual(settings.read_disk(), SECRET)
        self.assertEqual(self.legacy_reads, 1)
        self.assertTrue(settings.write_disk({'theme': 'x'}))
        self.assertEqual(settings.read_disk(), {'theme': 'x'})

    def test_no_file_anywhere_is_copied_too_so_userdata_is_never_asked_again(self):
        self.assertEqual(settings.read_disk(), {})
        self.assertEqual(misc_store.read('settings'), b'{}\n')
        self.legacy = settings.Unreadable('userdata will not mount')
        self.assertEqual(settings.read_disk(), {})

    def test_an_older_store_left_behind_is_emptied_at_a_later_start(self):
        settings.write_disk(dict(SECRET))
        self.put_legacy('cache', {'theme': 'old'})
        with mock.patch.object(settings, '_copy_themes', lambda context: True):
            self.assertEqual(settings.read_disk(), SECRET)
        self.assertEqual(self.legacy_files(), [])
        misc_store.clear('settings')  # misc erased in Download Mode: the defaults, never the older file
        self.legacy = {}
        self.assertEqual(settings.read_disk(), {})

    def test_the_older_wifi_list_goes_only_once_misc_holds_its_own(self):
        settings.write_disk(dict(SECRET))
        older = self.volumes['cache'] / settings.WIFI_RELATIVE
        older.write_text('{"networks": []}')
        with mock.patch.object(settings, '_copy_themes', lambda context: True):
            settings.read_disk()
            self.assertTrue(older.exists())  # not copied to misc yet: kept
            misc_store.write('wifi', b'{"networks": []}')
            settings.read_disk()
        self.assertFalse(older.exists())
        import wifi
        self.assertEqual(settings.WIFI_RELATIVE, wifi.SAVED_RELATIVE)

    def test_what_the_older_store_cannot_tell_is_never_copied(self):
        for error in (settings.Unreadable('userdata will not mount'), settings.Damaged('damaged', 'cache')):
            with self.subTest(error=type(error).__name__):
                self.legacy = error
                with self.assertRaises(type(error)):
                    settings.read_disk()
                self.assertIsNone(misc_store.read('settings'))

    def test_a_misc_that_cannot_be_read_is_never_none(self):
        os.environ['A22X_MISC'] = str(self.tmp / 'missing')
        with self.assertRaises(settings.Unreadable):
            settings.read_disk()
        self.assertFalse(settings.write_disk({'theme': 'y'}))
        self.assertEqual(self.legacy_reads, 0)  # never the older file in its place

    def test_damaged_copies_lock_until_the_reset_which_erases_userdata_first(self):
        settings.write_disk(dict(SECRET))
        data = bytearray(self.misc.read_bytes())
        for index in (0, 1):
            data[misc_store.AREAS['settings'] + index * misc_store.SLOT + misc_store.SECTOR] ^= 0xff
        self.misc.write_bytes(bytes(data))
        with self.assertRaises(settings.Damaged) as caught:
            settings.read_disk()
        self.assertEqual(caught.exception.label, 'misc')
        self.assertFalse(settings.write_disk({'theme': 'y'}))  # nothing is saved over them
        self.assertEqual(self.misc.read_bytes(), bytes(data))
        order = []
        self.context.format = lambda *args: order.append(('format', args[0]))
        real_clear = misc_store.clear
        with mock.patch.object(misc_store, 'clear', lambda name: (order.append(('clear', name)), real_clear(name))):
            self.assertEqual(settings.reset_damaged(), 0)
        self.assertEqual(order, [('format', 'userdata'), ('clear', 'settings')])
        self.assertEqual(settings.read_disk(), {})

    def test_the_reset_of_damaged_copies_takes_the_older_store_on_cache_too(self):
        # 2026-11-14 review: the older file on cache brought back the password the reset was for.
        settings.write_disk(dict(SECRET))
        self.put_legacy('cache')
        data = bytearray(self.misc.read_bytes())
        for index in (0, 1):
            data[misc_store.AREAS['settings'] + index * misc_store.SLOT + misc_store.SECTOR] ^= 0xff
        self.misc.write_bytes(bytes(data))
        self.assertEqual(settings.reset_damaged(), 0)
        self.assertEqual(self.legacy_files(), [])
        self.assertIsNone(misc_store.read('settings'))

    def test_a_reset_with_nothing_damaged_erases_nothing(self):
        settings.write_disk(dict(SECRET))
        self.assertEqual(settings.reset_damaged(), 1)
        self.assertEqual(self.context.formatted, [])
        self.assertEqual(settings.read_disk(), SECRET)

    def test_the_command_line_sets_and_clears_the_password_in_misc(self):
        secret = self.tmp / 'secret'
        secret.write_text('2580\n')
        for argv, code in ((['set-password', '--secret-file', str(secret)], 0),
                           (['verify', '--secret-file', str(secret)], 0),
                           (['clear-password'], 1),
                           (['clear-password', '--secret-file', str(secret)], 0)):
            settings.RAM_COPY.unlink(missing_ok=True)  # each command reads misc, as a new start would
            with mock.patch.object(sys, 'argv', ['settings.py', *argv]):
                self.assertEqual(settings.main(), code, argv)
        self.assertFalse(json.loads(misc_store.read('settings')).get('hash'))

    def test_a_misc_that_cannot_be_written_keeps_the_save_in_ram(self):
        settings.write_disk({'theme': 'a'})
        with mock.patch.object(misc_store, 'write', side_effect=OSError(5, 'Input/output error')):
            self.assertEqual(settings.store({'theme': 'b'}), 3)
        self.assertEqual(settings.load(), {'theme': 'b'})
        settings.RAM_COPY.unlink()
        self.assertEqual(settings.load(), {'theme': 'a'})


if __name__ == '__main__':
    unittest.main()
