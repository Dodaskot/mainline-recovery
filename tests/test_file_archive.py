"""Files and folders into NAME.tar.zst and out again (file_archive.py, 2026-11-13)."""
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import file_archive as fa  # noqa: E402
import filesystem as fs  # noqa: E402
import partition_archive as pa  # noqa: E402


@unittest.skipUnless(shutil.which('zstd'), 'zstd is needed')
class FileArchive(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-archive-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.data, self.sd = self.root / 'volumes/data', self.root / 'volumes/sd'
        self.data.mkdir(parents=True)
        self.sd.mkdir()
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
            {'id': 'userdata', 'path': 'volumes/data', 'fs_type': 'ext4', 'mounted': True, 'read_only': False},
            {'id': 'sdcard-p1', 'path': 'volumes/sd', 'fs_type': 'ext4', 'mounted': True, 'read_only': False}]}))
        self.ctx = fs.FixtureContext(self.root)
        home = self.data / 'home'
        (home / 'Документи' / 'вкладене').mkdir(parents=True)
        (home / 'Документи' / 'вкладене' / 'нотатка.txt').write_text('привіт\n')
        (home / 'script.sh').write_text('#!/bin/sh\necho hi\n')
        (home / 'script.sh').chmod(0o750)
        (home / 'big.bin').write_bytes(os.urandom(3 << 20))
        (home / 'link').symlink_to('/etc/passwd')
        (home / 'left-out.txt').write_text('no')
        self.home = home
        self.events = []

    def progress(self, done, total, label):
        self.events.append((done, total))

    def token(self, ident):
        return self.ctx.volume(ident)['volume_token']

    def pack(self, everything, names, destination='/A22xArchives/home.tar.zst'):
        return fa.pack(self.ctx, 'userdata', self.token('userdata'), '/home', everything, names, 'sdcard-p1',
                       self.token('sdcard-p1'), destination, True, self.progress)

    def test_chosen_entries_go_into_one_archive_and_come_out_beside_it(self):
        done = self.pack(False, ['Документи', 'script.sh', 'big.bin', 'link'])
        archive = self.sd / 'A22xArchives/home.tar.zst'
        self.assertEqual(done['archive']['path'], '/A22xArchives/home.tar.zst')
        self.assertEqual(done['bytes'], (3 << 20) + len('привіт\n'.encode()) + len('#!/bin/sh\necho hi\n'))
        self.assertTrue(archive.is_file() and not list((self.sd / 'A22xArchives').glob('.part-*')))
        self.assertTrue(self.events and self.events[-1][0] == done['bytes'])
        # The manifest after the stream, read without unpacking.
        about = fa.manifest_of(self.ctx, 'sdcard-p1', None, '/A22xArchives/home.tar.zst')['manifest']
        self.assertEqual((about['schema'], about['entries'], about['source']['folder']), ('a22x.files.v1', 6, '/home'))
        self.assertEqual(about['top'], sorted(['Документи', 'big.bin', 'link', 'script.sh']))
        # Any computer's tar reads it.
        if subprocess.run(['tar', '--zstd', '--help'], capture_output=True).returncode == 0:
            names = subprocess.run(['tar', '--zstd', '-tf', str(archive)], capture_output=True, text=True, check=True).stdout.split()
            self.assertIn('Документи/вкладене/нотатка.txt', names)
            self.assertNotIn('left-out.txt', names)
        # Out again, beside it, in a folder named after it.
        out = fa.unpack(self.ctx, 'sdcard-p1', self.token('sdcard-p1'), '/A22xArchives/home.tar.zst', True, self.progress)
        here = self.sd / 'A22xArchives/home'
        self.assertEqual((out['folder'], out['entries']), ('/A22xArchives/home', 6))
        self.assertEqual((here / 'Документи/вкладене/нотатка.txt').read_text(), 'привіт\n')
        self.assertEqual((here / 'big.bin').read_bytes(), (self.home / 'big.bin').read_bytes())
        self.assertEqual(stat.S_IMODE((here / 'script.sh').stat().st_mode), 0o750)
        self.assertTrue((here / 'link').is_symlink() and os.readlink(here / 'link') == '/etc/passwd')
        self.assertFalse((here / 'left-out.txt').exists())
        # Never into a folder that is already there, never over an archive that is.
        with self.assertRaises(fs.FilesystemError) as caught:
            fa.unpack(self.ctx, 'sdcard-p1', self.token('sdcard-p1'), '/A22xArchives/home.tar.zst', True, self.progress)
        self.assertEqual(caught.exception.code, 'DESTINATION_EXISTS')
        with self.assertRaises(fs.FilesystemError) as caught:
            self.pack(False, ['script.sh'])
        self.assertEqual(caught.exception.code, 'DESTINATION_EXISTS')

    def test_everything_but_the_ones_left_out(self):
        self.pack(True, ['left-out.txt', 'big.bin'], '/all.tar.zst')
        fa.unpack(self.ctx, 'sdcard-p1', None, '/all.tar.zst', True, self.progress)
        self.assertEqual(sorted(p.name for p in (self.sd / 'all').iterdir()), sorted(['Документи', 'link', 'script.sh']))

    def test_refusals(self):
        with self.assertRaises(fs.FilesystemError) as caught:
            self.pack(False, ['gone.txt'])
        self.assertEqual(caught.exception.code, 'SELECTION_CHANGED')
        with self.assertRaises(fs.FilesystemError) as caught:
            self.pack(False, ['script.sh'], '/x.zip')
        self.assertEqual(caught.exception.code, 'INVALID_DESTINATION')
        with self.assertRaises(fs.FilesystemError) as caught:
            fa.pack(self.ctx, 'userdata', None, '/home', False, ['script.sh'], 'sdcard-p1', None, '/a.tar.zst', False, self.progress)
        self.assertEqual(caught.exception.code, 'CONFIRMATION_REQUIRED')

    def test_an_archive_that_would_write_outside_its_folder_is_refused(self):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as tar:
            info = tarfile.TarInfo('../escaped.txt')
            info.size = 2
            tar.addfile(info, io.BytesIO(b'no'))
        (self.sd / 'evil.tar').write_bytes(raw.getvalue())
        with self.assertRaises(fs.FilesystemError) as caught:
            fa.unpack(self.ctx, 'sdcard-p1', None, '/evil.tar', True, self.progress)
        self.assertEqual(caught.exception.code, 'ARCHIVE_UNSAFE')
        self.assertFalse((self.sd / 'escaped.txt').exists())
        # A damaged zstd archive says so.
        self.pack(False, ['big.bin'], '/damaged.tar.zst')
        blob = bytearray((self.sd / 'damaged.tar.zst').read_bytes())
        blob[len(blob) // 3] ^= 0xff
        (self.sd / 'damaged.tar.zst').write_bytes(bytes(blob))
        with self.assertRaises(fs.FilesystemError) as caught:
            fa.unpack(self.ctx, 'sdcard-p1', None, '/damaged.tar.zst', True, self.progress)
        self.assertEqual(caught.exception.code, 'ARCHIVE_DAMAGED')

    def test_the_command_line(self):
        selection = self.root / 'selection.json'
        selection.write_text(json.dumps({'all': False, 'names': ['script.sh']}))
        run = subprocess.run([sys.executable, str(ROOT / 'file_archive.py'), '--fixture', str(self.root), 'pack', '--volume', 'userdata',
                              '--path', '/home', '--selection-file', str(selection), '--destination-volume', 'sdcard-p1',
                              '--destination', '/one.tar.zst', '--confirm'], capture_output=True, text=True)
        result = json.loads(run.stdout)
        self.assertTrue(result['ok'], result)
        self.assertIn('"phase":"Packing"', run.stderr)
        run = subprocess.run([sys.executable, str(ROOT / 'file_archive.py'), '--fixture', str(self.root), 'unpack', '--volume', 'sdcard-p1',
                              '--path', '/one.tar.zst', '--confirm'], capture_output=True, text=True)
        self.assertTrue(json.loads(run.stdout)['ok'], run.stdout)
        self.assertTrue((self.sd / 'one/script.sh').is_file())


if __name__ == '__main__':
    unittest.main()
