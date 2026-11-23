"""The archive of a copy of Android's partitions (partition_archive.py), 2026-11-14."""
import os
from pathlib import Path
import resource
import subprocess
import shutil
import signal
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import partition_archive as pa  # noqa: E402


@unittest.skipUnless(shutil.which('zstd'), 'zstd is needed')
class EncryptedWriter(unittest.TestCase):
    def test_a_file_too_large_is_said_as_such_and_not_as_a_broken_pipe(self):
        # 2026-11-14 review: the encryption's own error (EFBIG, ENOSPC) was lost behind zstd's EPIPE.
        folder = Path(tempfile.mkdtemp(dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, folder, True)
        self.addCleanup(lambda: (setattr(pa, 'PASSWORD', None), setattr(pa, 'ENCRYPT', False)))
        pa.PASSWORD, pa.ENCRYPT = 'secret 77', True
        old_handler = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        self.addCleanup(signal.signal, signal.SIGXFSZ, old_handler)
        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        self.addCleanup(resource.setrlimit, resource.RLIMIT_FSIZE, (soft, hard))
        fd = os.open(folder / 'copy.tar.zst.enc', os.O_WRONLY | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, hard))
        writer = pa.Writer(fd)
        size = 16 << 20
        with self.assertRaises(pa.ArchiveError) as caught:
            writer.begin('boot.img', size)
            block = os.urandom(1 << 20)
            for _ in range(16):
                writer.write(block)
            writer.finish(b'{}')
        self.assertEqual(caught.exception.code, 'FILE_TOO_LARGE')



@unittest.skipUnless(shutil.which('zstd'), 'zstd is needed')
class PartitionStreamIntegrity(unittest.TestCase):
    def test_truncated_zstd_with_valid_footer_is_rejected(self):
        # Unlike a missing footer, this damaged archive still advertises valid
        # metadata.  A late decompressor failure must not count as verification.
        with tempfile.TemporaryDirectory(prefix='a22x-partial-stream-', dir=os.environ.get('TMPDIR')) as folder:
            archive = Path(folder) / 'copy.tar.zst'
            marker = Path(folder) / 'unrelated.txt'
            marker.write_bytes(b'untouched neighboring file')
            manifest = b'{"schema":"fixture","partitions":["boot"]}'
            data = b'partition image contents' + b'A' * 8192
            fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                writer = pa.Writer(fd, threads=1)
                writer.begin('boot.img', len(data))
                writer.write(data)
                writer.finish(manifest)
            finally:
                os.close(fd)
            complete = archive.read_bytes()
            footer_start = len(complete) - len(manifest) - 24
            self.assertGreater(footer_start, 8)
            corrupted = complete[:footer_start - 1] + complete[footer_start:]
            archive.write_bytes(corrupted)
            # Independent zstd detects the missing last frame byte, even though
            # the complete partition payload has already been streamed.
            decoded = subprocess.run([pa.zstd_path(), '-q', '-d', '-c'],
                                     input=corrupted[:footer_start - 1], capture_output=True)
            self.assertNotEqual(decoded.returncode, 0)
            self.assertIn(data, decoded.stdout)
            with archive.open('rb') as stream:
                self.assertEqual(pa.footer(stream.fileno()), manifest)
                with self.assertRaises(pa.ArchiveError) as caught:
                    with pa.members(stream.fileno()) as entries:
                        for _name, _size, member in entries:
                            member.read()
                self.assertEqual(caught.exception.code, 'BACKUP_DAMAGED')
            self.assertEqual(marker.read_bytes(), b'untouched neighboring file')
            self.assertEqual(archive.read_bytes(), corrupted)
            self.assertEqual({item.name for item in Path(folder).iterdir()},
                             {'copy.tar.zst', 'unrelated.txt'})

if __name__ == '__main__':
    unittest.main()
