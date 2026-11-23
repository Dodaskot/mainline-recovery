"""The browser runs from RAM: a card's offline packages are only read, verified into sealed memfds."""
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import filesystem as fs
import web_launch


def tree_state(root):
    return sorted((str(p.relative_to(root)), p.stat().st_size, p.stat().st_mtime_ns) for p in Path(root).rglob('*'))


class FakeContext:
    def __init__(self, volumes, error=None):
        self._volumes, self.error = volumes, error

    @contextmanager
    def operation_lock(self, shared=False):
        self.shared = shared
        if self.error:
            raise self.error
        yield

    def volumes(self):
        return self._volumes


class FakePin:
    def __init__(self, root):
        self.root, self.rechecked = root, False

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False

    @contextmanager
    def directory(self, path):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    def recheck(self):
        self.rechecked = True


class LoadPackage(unittest.TestCase):
    def test_verified_copy_is_sealed(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = os.urandom(3 << 20)
            Path(tmp, 'pkg').write_bytes(data)
            directory = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                image = web_launch.load_package(directory, 'pkg', len(data), hashlib.sha256(data).hexdigest())
            finally:
                os.close(directory)
            try:
                self.assertEqual(os.pread(image, len(data) + 1, 0), data)
                seals = fcntl.fcntl(image, fcntl.F_GET_SEALS)
                for seal in (fcntl.F_SEAL_WRITE, fcntl.F_SEAL_SHRINK, fcntl.F_SEAL_GROW, fcntl.F_SEAL_SEAL):
                    self.assertTrue(seals & seal)
                with self.assertRaises(OSError):
                    os.pwrite(image, b'x', 0)
            finally:
                os.close(image)

    def test_missing_wrong_size_and_wrong_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'pkg').write_bytes(b'browser')
            directory = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertIsNone(web_launch.load_package(directory, 'absent', 7, '0' * 64))
                with self.assertRaisesRegex(RuntimeError, 'Incorrect'):
                    web_launch.load_package(directory, 'pkg', 8, hashlib.sha256(b'browser').hexdigest())
                before = len(os.listdir('/proc/self/fd'))
                with self.assertRaisesRegex(RuntimeError, 'verification'):
                    web_launch.load_package(directory, 'pkg', 7, '0' * 64)
                self.assertEqual(len(os.listdir('/proc/self/fd')), before)
            finally:
                os.close(directory)


class OfflinePackages(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.blobs = {key: os.urandom(4096 + n) for n, key in enumerate(('engine', 'mesa', 'wayland'))}
        self.packages = {}
        for key, data in self.blobs.items():
            name = 'web-%s.sqfs' % key
            Path(self.root, name).write_bytes(data)
            self.packages[key] = (name, len(data), hashlib.sha256(data).hexdigest())
        card = dict(id='sdcard-p1', mounted=True, volume_token='t', read_only=True, write_supported=False)
        self.patches = [patch.object(web_launch, 'PACKAGES', self.packages),
                        patch.object(web_launch, 'RAM_RESERVE', 0),
                        patch.object(web_launch, 'ram_available', lambda: 1 << 40),
                        patch.object(web_launch.web_cache, 'notify', lambda message: None),
                        patch.object(web_launch.fs, 'DeviceContext', lambda: FakeContext([card])),
                        patch.object(web_launch.fs, 'PinnedVolume', lambda ctx, ident, token: FakePin(self.root))]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()

    def test_a_read_only_card_supplies_packages_and_stays_unchanged(self):
        before = tree_state(self.root)
        images = web_launch.offline_packages(['engine', 'mesa', 'wayland'])
        try:
            self.assertEqual(set(images), {'engine', 'mesa', 'wayland'})
            for key, image in images.items():
                self.assertEqual(os.pread(image, 1 << 20, 0), self.blobs[key])
        finally:
            for image in images.values():
                os.close(image)
        self.assertEqual(tree_state(self.root), before)

    def test_only_wanted_and_valid_packages(self):
        Path(self.root, 'web-mesa.sqfs').write_bytes(b'damaged')
        images = web_launch.offline_packages(['mesa', 'wayland'])
        try:
            self.assertEqual(set(images), {'wayland'})
        finally:
            for image in images.values():
                os.close(image)

    def test_low_ram_skips_a_package(self):
        with patch.object(web_launch, 'ram_available', lambda: 4095):
            images = web_launch.offline_packages(['engine', 'wayland'])
        try:
            self.assertEqual(set(images), set())
        finally:
            for image in images.values():
                os.close(image)

    def test_no_card_or_a_card_problem_gives_nothing(self):
        with patch.object(web_launch.fs, 'DeviceContext', lambda: FakeContext([])):
            self.assertEqual(web_launch.offline_packages(['engine']), {})
        error = fs.FilesystemError('VOLUME_NOT_MOUNTED', 'gone')
        with patch.object(web_launch.fs, 'DeviceContext', lambda: FakeContext([], error)):
            self.assertEqual(web_launch.offline_packages(['engine']), {})


class Source(unittest.TestCase):
    def test_the_launcher_never_writes_to_a_card(self):
        # The browser's side never opens a card for writing; finished downloads reach a card only
        # through web_downloads (2026-11-20, a tester, #6), into Download/ and never replacing a file.
        text = Path(web_launch.__file__).read_text()
        self.assertNotIn('writing=True', text)
        self.assertNotIn("'SD'", text)
        self.assertIn("web_downloads.follow(3, UID, 4, control=0)", text)
        moving = Path(web_launch.__file__).with_name('web_downloads.py').read_text()
        self.assertEqual(moving.count('writing=True'), 1)
        self.assertIn("FOLDER = 'Download'", moving)
        self.assertIn('os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW', moving)
        self.assertIn('fs.rename_noreplace(directory, temporary, directory, saved)', moving)
        # Shared since 2026-11-21: a download reaches the card while USB files shares it.
        self.assertIn('with context.operation_lock(shared=True):', moving)
        # The card's packages are read under the shared lease: never storage alone (2026-11-22).
        self.assertIn('with ctx.operation_lock(shared=True):', text)
        self.assertNotIn('ctx.operation_lock()', text)


class GpuNodeTest(unittest.TestCase):
    def test_a_root_without_sys_draws_without_the_gpu(self):
        import contextlib
        import io
        import tempfile as tf
        import web_launch
        with tf.TemporaryDirectory() as directory:
            root = Path(directory)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertIsNone(web_launch.gpu_node_for(root, ('renderD128', 57856)))
            self.assertIn('without the GPU', err.getvalue())
            (root / 'sys').mkdir()
            self.assertEqual(web_launch.gpu_node_for(root, ('renderD128', 57856)), ('renderD128', 57856))
            self.assertIsNone(web_launch.gpu_node_for(root, None))



class Namespace(unittest.TestCase):
    def test_the_browser_lets_every_volume_go_deepest_first(self):
        # 2026-11-20, on the phone: its private namespace kept the card's old ext4 mount after Files
        # let it go and the card was formatted FAT32.
        info = ('36 1 0:2 / / rw - rootfs rootfs rw\n'
                '49 39 179:97 / /mnt/volumes/sdcard-p1 rw,nosuid - ext4 /dev/mmcblk1p1 rw\n'
                '50 39 179:98 / /mnt/backup rw - ext4 /dev/mmcblk1p2 rw\n'
                '51 50 0:5 / /mnt/backup/sub rw - tmpfs t rw\n'
                '52 39 259:22 / /mnt/volumes/user\\040data ro - f2fs /dev/x ro\n'
                '53 39 0:6 / /mnt/backupx rw - tmpfs t rw\n'
                '54 39 0:7 / /run/a22x-recovery/web-cache rw - tmpfs t rw\n')
        done = []
        web_launch.detach_cards(info, done.append)
        self.assertEqual(sorted(done), sorted(['/mnt/volumes/sdcard-p1', '/mnt/backup', '/mnt/backup/sub', '/mnt/volumes/user data']))
        self.assertEqual(done[-1], '/mnt/backup')
        self.assertLess(done.index('/mnt/backup/sub'), done.index('/mnt/backup'))


if __name__ == '__main__':
    unittest.main()


class AppLinks(unittest.TestCase):
    """2026-11-21, #6: a link to an app (Google Play's Install) left the tab under Chromium's "Open
    xdg-open?" dialog, which touch did not reach."""

    def test_the_layer_lets_app_schemes_go_to_its_xdg_open(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            mask = os.umask(0o077)
            try:
                layer = web_launch.links_layer(Path(tmp))
            finally:
                os.umask(mask)
            policy = json.loads((layer / 'etc/chromium/policies/managed/a22x-app-links.json').read_text())
            schemes = {item['protocol'] for item in policy['AutoLaunchProtocolsFromOrigins']}
            self.assertTrue({'intent', 'market', 'tel', 'mailto'} <= schemes)
            self.assertTrue(all(item['allowed_origins'] == ['*'] for item in policy['AutoLaunchProtocolsFromOrigins']))
            tool = layer / 'usr/bin/xdg-open'
            self.assertTrue(os.access(tool, os.X_OK))
            # Whatever the umask: the overlay takes these folders' modes for the whole root.
            for folder in ('', 'etc', 'etc/chromium/policies/managed', 'usr', 'usr/bin'):
                self.assertEqual((layer / folder).stat().st_mode & 0o777, 0o755, folder)
            compile(tool.read_text().split('\n', 1)[1], 'xdg-open', 'exec')

    def test_app_links_only_report_the_available_fallback_or_external_app(self):
        import web_session
        url = ('intent://details?id=org.videolan.vlc#Intent;scheme=market;package=com.android.vending;'
               'S.browser_fallback_url=https%3A%2F%2Fplay.google.com%2Fstore%2Fapps%2Fdetails%3Fid%3Dorg.videolan.vlc;end')
        self.assertEqual(web_session.external_link_note(url), web_session.APP_FALLBACK_NOTE)
        self.assertEqual(web_session.external_link_note('market://details?id=org.videolan.vlc'), web_session.APP_NOTE)
        self.assertEqual(web_session.external_link_note('intent://x#Intent;S.browser_fallback_url=javascript%3Aalert(1);end'),
                         web_session.APP_NOTE)
        self.assertEqual(web_session.external_link_note('tel:+4930123'), web_session.OTHER_NOTE)
