"""misc_store: two copies of each record in the last 128 KiB of misc (2026-11-14).

The promise checked over every way a write can stop: a record once whole never reads as none and
never as damaged; it reads as the payload before the write or the one being written. And nothing
outside the record's own 64 KiB is ever written."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import misc_store as ms  # noqa: E402


class Crash(Exception):
    """The power went: nothing after this step happened."""


class Store(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='a22x-misc-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.misc = self.tmp / 'misc'
        # Android's part (the bootloader message, the system space) and the rest: bytes that must stay.
        self.outside = os.urandom(ms.END)
        self.misc.write_bytes(self.outside[:ms.AREAS['settings']] + bytes(ms.END - ms.AREAS['settings']))
        patcher = mock.patch.dict(os.environ, {'A22X_MISC': str(self.misc)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def assert_outside_kept(self, name):
        data = self.misc.read_bytes()
        first = ms.AREAS[name]
        self.assertEqual(data[:ms.AREAS['settings']], self.outside[:ms.AREAS['settings']])
        for other, start in ms.AREAS.items():
            if other != name:
                self.assertEqual(data[start:start + 2 * ms.SLOT], bytes(2 * ms.SLOT), other)
        self.assertEqual(len(data), ms.END)
        return data[first:first + 2 * ms.SLOT]

    def test_empty_then_written_then_both_copies_whole(self):
        self.assertIsNone(ms.read('settings'))
        ms.write('settings', b'one')
        self.assertEqual(ms.read('settings'), b'one')
        area = self.assert_outside_kept('settings')
        slots = [ms.classify('settings', area[i * ms.SLOT:(i + 1) * ms.SLOT]) for i in (0, 1)]
        self.assertEqual([s[0] for s in slots], ['valid', 'valid'])  # a first write leaves two copies
        for n in range(2, 7):
            ms.write('settings', b'v%d' % n)
            self.assertEqual(ms.read('settings'), b'v%d' % n)
            area = self.assert_outside_kept('settings')
            slots = [ms.classify('settings', area[i * ms.SLOT:(i + 1) * ms.SLOT]) for i in (0, 1)]
            self.assertEqual(sorted(s[2] for s in slots), sorted([b'v%d' % n, b'v%d' % (n - 1) if n > 2 else b'one']))
        self.assertIsNone(ms.read('wifi'))  # one record never reads another's
        ms.write('wifi', b'{}')
        self.assertEqual((ms.read('wifi'), ms.read('settings')), (b'{}', b'v6'))

    def test_every_stop_of_a_write_leaves_the_old_or_the_new_payload(self):
        real_pwrite, real_fsync = os.pwrite, os.fsync
        histories = ([], [b'first'], [b'first', b'second'], [b'first', b'second', b'third'])
        cases = 0
        for history in histories:
            for step in range(12):
                for cut in (None, 0, 1, ms.SECTOR - 1, ms.SECTOR, 3 * ms.SECTOR + 7):
                    self.misc.write_bytes(self.outside[:ms.AREAS['settings']] + bytes(ms.END - ms.AREAS['settings']))
                    for payload in history:
                        ms.write('settings', payload)
                    before = history[-1] if history else None
                    calls = [0]

                    def pwrite(fd, data, offset, cut=cut, step=step):
                        calls[0] += 1
                        if calls[0] - 1 == step:
                            if cut is not None:  # a write the power cut short: a prefix of it landed
                                real_pwrite(fd, data[:cut], offset)
                            raise Crash()
                        return real_pwrite(fd, data, offset)

                    def fsync(fd, step=step):
                        calls[0] += 1
                        if calls[0] - 1 == step:
                            raise Crash()
                        return real_fsync(fd)
                    with mock.patch('os.pwrite', pwrite), mock.patch('os.fsync', fsync):
                        try:
                            ms.write('settings', b'new-' + b'x' * 900)
                            finished = True
                        except Crash:
                            finished = False
                    seen = ms.read('settings')
                    if finished:
                        self.assertEqual(seen, b'new-' + b'x' * 900)
                    elif before is None:
                        self.assertIn(seen, (None, b'new-' + b'x' * 900), (history, step, cut))
                    else:
                        self.assertIn(seen, (before, b'new-' + b'x' * 900), (history, step, cut))
                    self.assert_outside_kept('settings')
                    # And the next write after the stop is whole.
                    ms.write('settings', b'after')
                    self.assertEqual(ms.read('settings'), b'after')
                    cases += 1
        self.assertGreater(cases, 250)

    def test_one_damaged_copy_is_a_save_that_stopped_both_are_damaged(self):
        ms.write('settings', b'a')
        ms.write('settings', b'b')
        data = bytearray(self.misc.read_bytes())
        first = ms.AREAS['settings']
        newest = max((0, 1), key=lambda i: ms.classify('settings', bytes(data[first + i * ms.SLOT:first + (i + 1) * ms.SLOT]))[1])
        data[first + newest * ms.SLOT + ms.SECTOR] ^= 0xff  # the newest payload damaged
        self.misc.write_bytes(bytes(data))
        self.assertEqual(ms.read('settings'), b'a')
        data[first + (1 - newest) * ms.SLOT + 40] ^= 0xff  # and the other one's header
        self.misc.write_bytes(bytes(data))
        with self.assertRaises(ms.Damaged):
            ms.read('settings')
        ms.clear('settings')
        self.assertIsNone(ms.read('settings'))
        self.assert_outside_kept('settings')

    def test_bytes_of_another_program_are_never_written_over(self):
        data = bytearray(self.misc.read_bytes())
        data[ms.AREAS['wifi'] + 100] = 7
        self.misc.write_bytes(bytes(data))
        self.assertIsNone(ms.read('wifi'))
        with self.assertRaises(ms.Foreign):
            ms.write('wifi', b'x')
        with self.assertRaises(ms.Foreign):
            ms.clear('wifi')
        self.assertEqual(self.misc.read_bytes(), bytes(data))
        ms.write('settings', b'mine')  # the other record is not concerned
        self.assertEqual(ms.read('settings'), b'mine')

    def test_limits_and_a_misc_that_cannot_hold_or_be_read(self):
        with self.assertRaises(ValueError):
            ms.write('settings', b'x' * (ms.PAYLOAD_MAX + 1))
        ms.write('settings', b'x' * ms.PAYLOAD_MAX)
        self.assertEqual(len(ms.read('settings')), ms.PAYLOAD_MAX)
        with self.assertRaises(ValueError):
            ms.read('other')
        small = self.tmp / 'small'
        small.write_bytes(bytes(ms.END - 1))
        with mock.patch.dict(os.environ, {'A22X_MISC': str(small)}):
            with self.assertRaises(OSError):
                ms.read('settings')
        with mock.patch.dict(os.environ, {'A22X_MISC': str(self.tmp / 'none')}):
            with self.assertRaises(OSError):
                ms.read('settings')

    def test_a_readback_that_differs_is_a_failed_write(self):
        real_pread = os.pread

        def pread(fd, size, offset):
            data = real_pread(fd, size, offset)
            return data[:-1] + b'\x01' if size == ms.SLOT and calls.append(1) is None and len(calls) > 2 else data
        calls = []
        with mock.patch('os.pread', pread):
            with self.assertRaises(OSError):
                ms.write('settings', b'z')

    def test_the_real_partition_is_only_the_internal_one(self):
        with mock.patch.dict(os.environ, {'A22X_MISC': str(ms.MISC)}), \
                mock.patch.object(ms.os.path, 'realpath', return_value='/dev/sda4'):
            with self.assertRaises(OSError):
                ms.read('settings')


if __name__ == '__main__':
    unittest.main()
