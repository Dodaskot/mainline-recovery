"""bt_pairings and the bluetooth record of misc (2026-11-22, the owner: pairings kept past a restart,
in misc as the settings and the Wi-Fi list are)."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bt_pairings as bp  # noqa: E402
import misc_store as ms  # noqa: E402

ADAPTER, HEADPHONES, KEYBOARD, SEEN = 'AA:BB:CC:00:00:01', '11:22:33:44:55:66', 'C0:FF:EE:00:00:02', '77:88:99:AA:BB:CC'
LINK = '[General]\nName=Headphones\n\n[LinkKey]\nKey=00112233445566778899AABBCCDDEEFF\nType=4\nPINLength=0\n'
LE = '[General]\nName=Keyboard\nAddressType=static\n\n[LongTermKey]\nKey=FFEEDDCCBBAA99887766554433221100\nAuthenticated=2\n'


class Pairings(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='a22x-bt-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / 'root'
        base = self.root / bp.STATE / ADAPTER
        for device, info in ((HEADPHONES, LINK), (KEYBOARD, LE), (SEEN, '[General]\nName=Seen only\n')):
            (base / device).mkdir(parents=True)
            (base / device / 'info').write_text(info)
        (base / KEYBOARD / 'attributes').write_text('[0x0001]\nUUID=00002800-0000-1000-8000-00805f9b34fb\n')
        (base / 'settings').write_text('[General]\nDiscoverableTimeout=0\n')
        (base / 'cache').mkdir()
        (base / 'cache' / SEEN).write_text('[General]\nName=Seen only\n')

    def test_paired_devices_come_back_into_an_empty_root(self):
        payload = bp.snapshot(self.root, ms.payload_max('pairings'))
        files = json.loads(payload)['files']
        self.assertEqual(sorted(files), sorted([f'{ADAPTER}/{KEYBOARD}/attributes', f'{ADAPTER}/{KEYBOARD}/info',
                                                f'{ADAPTER}/{HEADPHONES}/info', f'{ADAPTER}/settings']))
        fresh = self.tmp / 'fresh'
        self.assertEqual(bp.restore(fresh, payload), 2)
        info = fresh / bp.STATE / ADAPTER / HEADPHONES / 'info'
        self.assertEqual(info.read_text(), LINK)
        self.assertEqual(info.stat().st_mode & 0o777, 0o600)
        self.assertEqual(info.parent.stat().st_mode & 0o777, 0o700)
        # A file BlueZ wrote in this start stays as it is.
        info.write_text('[General]\nName=Newer\n')
        self.assertEqual(bp.restore(fresh, payload), 0)
        self.assertEqual(info.read_text(), '[General]\nName=Newer\n')

    def test_a_record_reaches_no_other_path(self):
        files = {f'{ADAPTER}/../../etc/passwd': 'x', f'{ADAPTER}/{HEADPHONES}/../info': 'x', 'settings': 'x',
                 f'{ADAPTER}/{HEADPHONES}/info': LINK, f'{ADAPTER}/{HEADPHONES}/cache': 'x', f'{ADAPTER.lower()}/settings': 'x'}
        fresh = self.tmp / 'fresh'
        self.assertEqual(bp.restore(fresh, json.dumps({'version': 1, 'files': files}).encode()), 1)
        found = sorted(str(p.relative_to(fresh)) for p in fresh.rglob('*') if p.is_file())
        self.assertEqual(found, [str(bp.STATE / ADAPTER / HEADPHONES / 'info')])
        with self.assertRaises(ValueError):
            bp.restore(fresh, b'{"version":2,"files":{}}')

    def test_past_the_limit_attributes_go_then_the_oldest_pairing(self):
        base = self.root / bp.STATE / ADAPTER
        os.utime(base / HEADPHONES / 'info', (1000, 1000))
        full = bp.snapshot(self.root, 1 << 20)
        without = bp.snapshot(self.root, len(full) - 1)
        self.assertNotIn(f'{ADAPTER}/{KEYBOARD}/attributes', json.loads(without)['files'])
        self.assertIn(f'{ADAPTER}/{HEADPHONES}/info', json.loads(without)['files'])
        newest = bp.snapshot(self.root, len(without) - 1)
        self.assertEqual(sorted(json.loads(newest)['files']), [f'{ADAPTER}/{KEYBOARD}/info', f'{ADAPTER}/settings'])


class Record(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='a22x-misc-bt-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.misc = self.tmp / 'misc'
        # As on the phone: Android's bytes below 64 KiB, nothing from there to the splash.
        self.android = os.urandom(64 << 10)
        self.misc.write_bytes(self.android + bytes(ms.END - (64 << 10)))
        patcher = mock.patch.dict(os.environ, {'A22X_MISC': str(self.misc)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_kept_twice_in_its_own_area(self):
        self.assertIsNone(ms.read('pairings'))
        ms.write('pairings', b'{"files":{},"version":1}')
        ms.write('pairings', b'second')
        self.assertEqual(ms.state('pairings'), (b'second', True, True))
        data = self.misc.read_bytes()
        self.assertEqual(data[:64 << 10], self.android)
        self.assertEqual(data[128 << 10:], bytes(ms.END - (128 << 10)))   # the splash, settings, Wi-Fi untouched
        # The settings take their own area as before.
        ms.write('settings', b'{}')
        self.assertEqual(ms.read('pairings'), b'second')

    def test_another_programs_bytes_stop_only_the_pairings(self):
        with open(self.misc, 'r+b') as f:
            f.seek(100 << 10)
            f.write(b'not ours')
        with self.assertRaises(ms.Foreign):
            ms.write('pairings', b'x')
        ms.write('settings', b'{}')
        ms.write('wifi', b'[]')
        self.assertEqual(ms.read('settings'), b'{}')


class Service(unittest.TestCase):
    """media_service's save after a change and restore at the next start."""
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='a22x-media-bt-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        misc = self.tmp / 'misc'
        misc.write_bytes(bytes(ms.END))
        for patcher in (mock.patch.dict(os.environ, {'A22X_MISC': str(misc)}),):
            patcher.start()
            self.addCleanup(patcher.stop)
        import contextlib
        import filesystem
        import media_service
        import operation_lock
        self.ms = media_service
        context = mock.Mock(lock_path=self.tmp / 'lock', mode='fixture')
        for patcher in (mock.patch.object(filesystem, 'DeviceContext', return_value=context),
                        mock.patch.object(operation_lock, 'lease', lambda *a, **k: contextlib.nullcontext()),
                        mock.patch.object(media_service, 'log', lambda *a: None)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_saved_once_then_back_at_the_next_start(self):
        first = self.tmp / 'first'
        with mock.patch.object(self.ms, 'ROOT', first):
            self.assertEqual(self.ms.save_pairings(None), (None, True))      # nothing paired: no record
            (first / bp.STATE / ADAPTER / HEADPHONES).mkdir(parents=True)
            (first / bp.STATE / ADAPTER / HEADPHONES / 'info').write_text(LINK)
            kept, done = self.ms.save_pairings(None)
            self.assertTrue(done and kept)
            with mock.patch.object(ms, 'write', side_effect=AssertionError('written again')):
                self.assertEqual(self.ms.save_pairings(kept), (kept, True))  # unchanged: misc is not written
        second = self.tmp / 'second'
        with mock.patch.object(self.ms, 'ROOT', second):
            self.assertEqual(self.ms.restore_pairings(), kept)
        self.assertEqual((second / bp.STATE / ADAPTER / HEADPHONES / 'info').read_text(), LINK)

    def test_a_busy_lock_is_tried_again(self):
        root = self.tmp / 'root'
        (root / bp.STATE / ADAPTER / KEYBOARD).mkdir(parents=True)
        (root / bp.STATE / ADAPTER / KEYBOARD / 'info').write_text(LE)
        with mock.patch.object(self.ms, 'ROOT', root), mock.patch.object(ms, 'write', side_effect=BlockingIOError()):
            self.assertEqual(self.ms.save_pairings(None), (None, False))


if __name__ == '__main__':
    unittest.main()
