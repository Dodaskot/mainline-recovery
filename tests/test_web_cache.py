"""Exercise cold publication, retry after corruption, and reuse without network access."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import web_cache


def member_archive(name, data):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as tar:
        item = tarfile.TarInfo(name)
        item.size = len(data)
        item.mode = 0o755
        tar.addfile(item, io.BytesIO(data))
    return gzip.compress(stream.getvalue())


@unittest.skipUnless(os.geteuid() == 0, 'run the browser runtime setup test in a root user namespace')
class WebCacheTest(unittest.TestCase):
    def test_retry_then_offline_reopen(self):
        path = 'usr/lib/example'
        archive = member_archive('.SIGN.test', b'test') + member_archive(path, b'browser')
        package = dict(path='main/aarch64/test.apk', bytes=len(archive),
                       sha256=hashlib.sha256(archive).hexdigest(), files=[path])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root/'cache'
            cache.mkdir()
            manifest = root/'manifest.json'
            manifest.write_text(json.dumps(dict(packages=[package], links={'usr/bin/example':'../lib/example'}, unpacked_bytes=7)))
            with patch.object(web_cache,'CACHE',cache), patch.object(web_cache,'MANIFEST',manifest), \
                 patch.object(web_cache,'cache_mount'), patch.object(web_cache,'notify'), \
                 patch.object(web_cache.urllib.request,'urlopen') as request:
                request.return_value = io.BytesIO(bytes(len(archive)))
                with self.assertRaisesRegex(RuntimeError, 'SHA-256'):
                    web_cache.ensure()
                self.assertIsNone(web_cache.cached())
                self.assertEqual(list(cache.iterdir()), [])
                request.return_value = io.BytesIO(archive)
                tree = web_cache.ensure()
                self.assertEqual((tree/'usr/bin/example').read_bytes(), b'browser')
                self.assertFalse((tree/'.SIGN.test').exists())
                request.side_effect = AssertionError('Unexpected second download')
                self.assertEqual(web_cache.ensure(), tree)
                # The production owner is root. Allow the unprivileged test
                # runner to remove the published read-only tree on exit.
                for parent in tree.rglob('*'):
                    if parent.is_dir() and not parent.is_symlink():
                        parent.chmod(0o755)
                tree.chmod(0o755)


class DownloadsTest(unittest.TestCase):
    def test_ram_download_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)/'cache'
            cache.mkdir(mode=0o700)
            # Production runs as root; present the test runner's folder as root-owned.
            with patch.object(web_cache,'CACHE',cache), patch.object(web_cache,'cache_mount') as mounted, \
                 patch.object(Path,'lstat',autospec=True,side_effect=lambda p: _root_owned(p)):
                path = web_cache.downloads()
                self.assertEqual(path, cache/'downloads')
                self.assertTrue(path.is_dir())
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o700)
                mounted.assert_called_once_with()
                self.assertEqual(web_cache.downloads(), path)

    def test_refuses_a_link_in_place_of_the_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)/'cache'
            cache.mkdir(mode=0o700)
            (cache/'downloads').symlink_to(tmp)
            with patch.object(web_cache,'CACHE',cache), patch.object(web_cache,'cache_mount'):
                with self.assertRaises((RuntimeError, FileExistsError)):
                    web_cache.downloads()


def _root_owned(path):
    real = os.lstat(path)
    return os.stat_result((real.st_mode, real.st_ino, real.st_dev, real.st_nlink, 0, 0, real.st_size,
                           int(real.st_atime), int(real.st_mtime), int(real.st_ctime)))
