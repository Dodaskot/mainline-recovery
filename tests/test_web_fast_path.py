"""The fast browser path from RAM (2026-11-20): the engine with the full Chromium, the GPU layer over it,
how they are prepared after Wi-Fi joins and how the browser stacks them. Host only."""
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import web_cache
import web_launch

ROOT = Path(__file__).resolve().parent.parent
MiB = 1 << 20


def manifest(name):
    return json.loads((ROOT / name).read_text())


def apk(files):
    """An APK v2 lookalike: a signature member, then one data member with FILES."""
    out = []
    for members in ({'.SIGN.test': b'test'}, files):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as tar:
            for name, data in members.items():
                item = tarfile.TarInfo(name)
                item.size = len(data)
                item.mode = 0o755
                tar.addfile(item, io.BytesIO(data))
        out.append(gzip.compress(stream.getvalue()))
    return b''.join(out)


class Manifests(unittest.TestCase):
    def setUp(self):
        self.engine = manifest('web_packages.json')
        self.gpu = manifest('web_gpu_packages.json')

    def files(self, data):
        return {path for package in data['packages'] for path in package['files']}

    def test_the_engine_has_the_full_chromium_and_no_headless_shell(self):
        files = self.files(self.engine)
        for name in ('chromium', 'resources.pak', 'icudtl.dat', 'snapshot_blob.bin', 'v8_context_snapshot.bin',
                     'chrome_crashpad_handler', 'locales/en-US.pak', 'libEGL.so', 'libGLESv2.so'):
            self.assertIn('usr/lib/chromium/' + name, files)
        self.assertNotIn('usr/lib/chromium/chromium-headless-shell', files)
        self.assertFalse(any('chromium-headless-shell' in p['path'] for p in self.engine['packages']))
        for library in ('libwayland-client.so.0', 'libwayland-server.so.0', 'libwayland-cursor.so.0', 'libgbm.so.1'):
            self.assertTrue('usr/lib/' + library in files or 'usr/lib/' + library in self.engine['links'], library)

    def test_the_gpu_layer_has_mesa_for_panfrost(self):
        files, links = self.files(self.gpu), self.gpu['links']
        self.assertEqual(links['usr/lib/dri/panfrost_dri.so'], 'libdril_dri.so')
        for path in ('usr/lib/dri/libdril_dri.so', 'usr/lib/gbm/dri_gbm.so', 'usr/lib/libEGL.so.1.0.0',
                     'usr/lib/libGLESv2.so.2.0.0', 'usr/lib/libLLVM.so.22.1'):
            self.assertIn(path, files)
        for path in ('usr/lib/libEGL.so.1', 'usr/lib/libGLESv2.so.2'):
            self.assertIn(path, links)

    def test_layers_do_not_overlap_and_every_link_lands_on_a_file(self):
        engine = self.files(self.engine) | set(self.engine['links'])
        gpu = self.files(self.gpu) | set(self.gpu['links'])
        self.assertEqual(engine & gpu, set())
        everything = engine | gpu
        for data in (self.engine, self.gpu):
            for link, target in data['links'].items():
                dest = os.path.normpath(str(PurePosixPath(link).parent / target))
                self.assertIn(dest, everything, link)

    def test_packages_are_pinned_alpine_files(self):
        for data in (self.engine, self.gpu):
            for package in data['packages']:
                repository, arch, filename = package['path'].split('/')
                self.assertIn(repository, ('main', 'community'))
                self.assertEqual(arch, 'aarch64')
                self.assertIsNotNone(web_cache.APK_NAME.fullmatch(filename))
                self.assertRegex(package['sha256'], '^[0-9a-f]{64}$')
                self.assertGreater(package['bytes'], 0)
                self.assertTrue(package['files'])
                for path in package['files']:
                    self.assertFalse(path.startswith('/') or '..' in path.split('/'))

    def test_both_layers_fit_the_ram_filesystem(self):
        size = int(web_cache.CACHE_SIZE.rstrip('m')) * MiB
        largest = sorted((p['bytes'] for p in self.gpu['packages']), reverse=True)[:3]
        # The GPU layer is unpacked beside the published engine; downloads keep at least 256 MiB.
        peak = self.engine['unpacked_bytes'] + self.gpu['unpacked_bytes'] + sum(largest) + 16 * MiB
        self.assertLess(peak + 128 * MiB, size)
        self.assertLess(self.engine['unpacked_bytes'] + self.gpu['unpacked_bytes'] + 256 * MiB, size)

    def test_the_image_carries_the_gpu_manifest(self):
        text = (ROOT / 'tools/build_decrypt_image.py').read_text()
        self.assertIn("'web_gpu_packages.json'", text)


class Locks(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir(mode=0o700)
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text('{"packages": [], "links": {}, "unpacked_bytes": 0}')
        for item in (patch.object(web_cache, 'CACHE', self.cache), patch.object(web_cache, 'MANIFEST', self.manifest),
                     patch.object(web_cache, 'PROGRESS', self.root / 'progress'),
                     patch.object(web_cache, 'notify', lambda message: None)):
            item.start()
            self.addCleanup(item.stop)
        self.held = (self.root / 'web-cache.lock').open('a+b')
        self.addCleanup(self.held.close)
        fcntl.flock(self.held, fcntl.LOCK_EX)

    def published(self):
        target = self.cache / hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        target.mkdir()
        return target

    def test_a_published_tree_needs_no_lock(self):
        target = self.published()
        with patch.object(web_cache, 'cache_mount', side_effect=AssertionError('no mount needed')):
            self.assertEqual(web_cache.ensure(), target)

    def test_a_waiting_browser_starts_once_the_engine_is_published(self):
        # The background preparation holds the lock and goes on with the GPU layer.
        timer = threading.Timer(0.3, self.published)
        timer.start()
        self.addCleanup(timer.cancel)
        started = time.monotonic()
        with patch.object(web_cache, 'cache_mount'):
            tree = web_cache.ensure()
        self.assertEqual(tree, web_cache.cached())
        self.assertLess(time.monotonic() - started, 5)

    def test_the_background_preparation_does_not_wait(self):
        with self.assertRaises(BlockingIOError):
            web_cache.ensure(wait=False)

    def test_the_download_folder_does_not_wait_for_a_preparation(self):
        result = []
        with patch.object(web_cache, 'cache_mount'), \
                patch.object(Path, 'lstat', autospec=True, side_effect=lambda p: _root_owned(p)):
            worker = threading.Thread(target=lambda: result.append(web_cache.downloads()), daemon=True)
            worker.start()
            worker.join(5)
        self.assertEqual(result, [self.cache / 'downloads'])


@unittest.skipUnless(os.geteuid() == 0, 'run the browser runtime setup test in a root user namespace')
class GpuLayerPublication(unittest.TestCase):
    def test_engine_and_gpu_layer_are_separate_publications(self):
        engine_archive = apk({'usr/lib/chromium/chromium': b'chromium'})
        gpu_archive = apk({'usr/lib/dri/libdril_dri.so': b'mesa'})
        archives = {'community/aarch64/chromium-1-r0.apk': engine_archive, 'main/aarch64/mesa-dri-gallium-1-r0.apk': gpu_archive}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / 'cache'
            cache.mkdir()
            engine, gpu = root / 'engine.json', root / 'gpu.json'
            for path, (route, data), links in ((engine, list(archives.items())[0], {'usr/lib/chromium/chrome': 'chromium'}),
                                               (gpu, list(archives.items())[1], {'usr/lib/dri/panfrost_dri.so': 'libdril_dri.so'})):
                files = [n for n in ('usr/lib/chromium/chromium', 'usr/lib/dri/libdril_dri.so') if n.split('/')[2] in route or
                         (n.endswith('.so') and 'mesa' in route)]
                path.write_text(json.dumps(dict(packages=[dict(path=route, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                                               files=files)], links=links, unpacked_bytes=8)))

            def urlopen(url, timeout):
                return io.BytesIO(archives[url[len(web_cache.BASE):]])
            with patch.object(web_cache, 'CACHE', cache), patch.object(web_cache, 'MANIFEST', engine), \
                    patch.object(web_cache, 'GPU_MANIFEST', gpu), patch.object(web_cache, 'cache_mount'), \
                    patch.object(web_cache, 'notify'), patch.object(web_cache.urllib.request, 'urlopen', urlopen):
                base = web_cache.ensure()
                layer = web_cache.ensure(manifest=gpu)
                self.assertNotEqual(base, layer)
                self.assertEqual(web_cache.cached(gpu), layer)
                self.assertEqual((base / 'usr/lib/chromium/chrome').read_bytes(), b'chromium')
                self.assertTrue((base / 'opt/web-compositor').is_file())
                self.assertTrue((base / 'opt/web_session.py').is_file())
                self.assertTrue((base / 'sys').is_dir())  # where the GPU's sysfs goes
                self.assertEqual((layer / 'usr/lib/dri/panfrost_dri.so').read_bytes(), b'mesa')
                # A layer over the engine carries no mount points of its own.
                self.assertEqual(sorted(p.name for p in layer.iterdir()), ['usr'])
            for tree in (base, layer):
                for parent in [tree, *tree.rglob('*')]:
                    if parent.is_dir() and not parent.is_symlink():
                        parent.chmod(0o755)


class Prefetch(unittest.TestCase):
    def run_prefetch(self, gpu, failure=None, cached=lambda manifest=None: None):
        calls, progress = [], []

        def ensure(wait=True, manifest=None):
            calls.append(manifest)
            if manifest is not None and failure:
                raise failure
        with patch.object(web_cache, 'gpu_supported', lambda: gpu), patch.object(web_cache, 'ensure', ensure), \
                patch.object(web_cache, 'cached', cached), patch.object(web_cache, 'write_progress', progress.append):
            status = web_cache.prefetch()
        return status, calls, progress

    def test_engine_then_gpu_layer(self):
        status, calls, progress = self.run_prefetch(True)
        self.assertEqual((status, calls, progress[-1]), (0, [None, web_cache.GPU_MANIFEST], 'Web engine ready'))

    def test_no_gpu_layer_without_the_gpu(self):
        status, calls, _ = self.run_prefetch(False)
        self.assertEqual((status, calls), (0, [None]))

    def test_a_failed_gpu_layer_leaves_the_engine_ready(self):
        status, _, progress = self.run_prefetch(True, RuntimeError('Insufficient free RAM for the web graphics'))
        self.assertEqual(status, 0)
        self.assertTrue(progress[-1].startswith('Web engine ready, without GPU: Insufficient'))

    def test_nothing_to_do_when_both_are_published(self):
        status, calls, _ = self.run_prefetch(True, cached=lambda manifest=None: Path('/published'))
        self.assertEqual((status, calls), (0, []))


class GpuSupported(unittest.TestCase):
    def test_bound_driver_or_matching_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            device, driver, module = Path(tmp, 'gpu'), Path(tmp, 'panfrost'), Path(tmp, 'panfrost.ko')
            with patch.object(web_cache, 'PANFROST_DEVICE', device), patch.object(web_cache, 'PANFROST_DRIVER', driver), \
                    patch.object(web_cache, 'PANFROST_MODULE', module), \
                    patch.object(web_cache.os, 'uname', lambda: os.uname_result(('Linux', 'a22x', web_cache.PANFROST_RELEASE, '', 'aarch64'))):
                self.assertFalse(web_cache.gpu_supported())  # no GPU device at all
                device.mkdir()
                self.assertFalse(web_cache.gpu_supported())  # neither driver nor module
                module.write_bytes(b'\x7fELF')
                self.assertTrue(web_cache.gpu_supported())
                module.unlink()
                driver.mkdir()
                (device / 'driver').symlink_to(driver)
                self.assertTrue(web_cache.gpu_supported())
            with patch.object(web_cache, 'PANFROST_DEVICE', Path(tmp, 'gpu2')):
                Path(tmp, 'gpu2').mkdir()
                with patch.object(web_cache, 'PANFROST_MODULE', module):
                    module.write_bytes(b'\x7fELF')
                    with patch.object(web_cache.os, 'uname', lambda: os.uname_result(('Linux', 'x', '6.1.0', '', 'aarch64'))):
                        self.assertFalse(web_cache.gpu_supported())  # a module for another kernel


class RuntimeLayers(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.ram_engine = self.root / 'ram-engine'
        (self.ram_engine / 'usr/lib/chromium').mkdir(parents=True)
        (self.ram_engine / web_launch.FULL_CHROMIUM).write_bytes(b'chromium')
        self.card_engine = self.root / 'card-engine'
        (self.card_engine / 'usr/lib/chromium').mkdir(parents=True)
        (self.card_engine / 'usr/lib/chromium/chromium-headless-shell').write_bytes(b'shell')
        self.graphics = self.root / 'gpu'
        self.graphics.mkdir()
        self.mounted = []
        item = patch.object(web_launch, 'mount_image', lambda image, root: self.mounted.append((image, Path(root).name)))
        item.start()
        self.addCleanup(item.stop)

    def test_ram_gpu_layer_over_the_ram_engine(self):
        with patch.object(web_launch, 'panfrost_render_node', lambda: ('renderD128', 57856)):
            layers, node = web_launch.runtime_layers(self.root, self.ram_engine, {'wayland': 7}, self.graphics)
        self.assertEqual(layers, [self.graphics, self.ram_engine])
        self.assertEqual(node, ('renderD128', 57856))
        self.assertEqual(self.mounted, [])  # the card's Wayland package is not needed with the full Chromium

    def test_no_gpu_layer_when_panfrost_is_unavailable(self):
        def unavailable():
            raise RuntimeError('Panfrost driver unavailable')
        with patch.object(web_launch, 'panfrost_render_node', unavailable):
            layers, node = web_launch.runtime_layers(self.root, self.ram_engine, {}, self.graphics)
        self.assertEqual((layers, node), ([self.ram_engine], None))

    def test_card_packages_complete_the_card_engine(self):
        with patch.object(web_launch, 'panfrost_render_node', lambda: ('renderD128', 57856)):
            layers, node = web_launch.runtime_layers(self.root, self.card_engine, {'mesa': 5, 'wayland': 6})
        self.assertEqual([p.name for p in layers], ['wayland', 'mesa', 'card-engine'])
        self.assertEqual(self.mounted, [(5, 'mesa'), (6, 'wayland')])
        self.assertTrue(web_launch.full_chromium(self.ram_engine))
        self.assertFalse(web_launch.full_chromium(self.card_engine))


class CardWaylandPackage(unittest.TestCase):
    def test_skipped_when_the_card_has_no_engine(self):
        loaded = []

        class Pin:
            def __init__(self, *args):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def directory(self, path):
                class Directory:
                    def __enter__(self):
                        return 3

                    def __exit__(self, *args):
                        return False
                return Directory()

            def recheck(self):
                pass

        class Context:
            def operation_lock(self, shared=False):
                return Pin()

            def volumes(self):
                return [dict(id='sdcard-p1', mounted=True, volume_token='t')]

        def load(directory, name, size, digest):
            loaded.append(name)
            return None if 'engine' in name else 9
        with patch.object(web_launch.fs, 'DeviceContext', Context), patch.object(web_launch.fs, 'PinnedVolume', Pin), \
                patch.object(web_launch, 'load_package', load), patch.object(web_launch, 'ram_available', lambda: 1 << 40), \
                patch.object(web_launch.web_cache, 'notify', lambda message: None):
            self.assertEqual(web_launch.offline_packages(['engine', 'mesa', 'wayland']), {'mesa': 9})
            self.assertEqual(loaded, ['a22x-web-engine.sqfs', 'a22x-web-mesa-panfrost.sqfs'])
            loaded.clear()
            self.assertEqual(web_launch.offline_packages(['mesa', 'wayland']), {'mesa': 9, 'wayland': 9})


class SessionEngine(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(ROOT))
        import web_session
        self.session = web_session

    def arguments(self, executable, direct, gpu=False):
        environment = {'HOME': '/tmp/home', **({'A22X_WEB_GPU': '1'} if gpu else {})}
        with patch.dict(os.environ, environment, clear=True):
            return self.session.engine_arguments(executable, direct)

    def test_screencast_with_the_full_chromium_uses_new_headless(self):
        self.assertIn('--headless=new', self.arguments(self.session.FULL, False))
        shell = self.arguments(self.session.ENGINE, False)
        self.assertIn('--headless', shell)
        self.assertNotIn('--headless=new', shell)
        direct = self.arguments(self.session.FULL, True, gpu=True)
        self.assertIn('--ozone-platform=wayland', direct)
        self.assertIn('--use-angle=gles-egl', direct)
        self.assertFalse(any(a.startswith('--headless') for a in direct))

    def test_screencast_engine_prefers_the_headless_shell(self):
        with patch.object(self.session.os.path, 'exists', lambda path: True):
            self.assertEqual(self.session.screencast_engine(), self.session.ENGINE)
        with patch.object(self.session.os.path, 'exists', lambda path: False):
            self.assertEqual(self.session.screencast_engine(), self.session.FULL)

    def test_a_compositor_that_does_not_start_leaves_the_screencast(self):
        with tempfile.TemporaryDirectory() as tmp:
            quitting = Path(tmp, 'compositor')
            quitting.write_text('#!/bin/sh\nexit 3\n')
            quitting.chmod(0o755)
            # The compositor inherits fd 5 (the frame). Borrow it only when nothing else holds it.
            try:
                os.fstat(5)
                borrowed = None
            except OSError:
                borrowed = os.open('/dev/null', os.O_RDONLY)
                if borrowed != 5:
                    os.dup2(borrowed, 5)
                    os.close(borrowed)
            try:
                for path in (quitting, Path(tmp, 'absent')):
                    with patch.object(self.session, 'COMPOSITOR', str(path)):
                        self.assertEqual(self.session.start_compositor(), (None, False))
                ready = Path(tmp, 'ready')
                ready.write_text('#!/usr/bin/python3\nimport socket, sys\n'
                                 's = socket.socket(fileno=int(sys.argv[1])); s.send(b"S"); s.recv(1)\n')
                ready.chmod(0o755)
                with patch.object(self.session, 'COMPOSITOR', str(ready)):
                    compositor, frames = self.session.start_compositor()
                    self.assertIsInstance(compositor, socket.socket)
                    self.assertFalse(frames)
                    compositor.close()
            finally:
                if borrowed is not None:
                    os.close(5)

    def test_frame_messages_go_straight_to_the_ui_when_the_compositor_takes_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Both the frame (fd 5) and the UI's frame socket (fd 6) are borrowed for the test.
            held = []
            for number in (5, 6):
                try:
                    os.fstat(number)
                except OSError:
                    null = os.open('/dev/null', os.O_RDONLY)
                    if null != number:
                        os.dup2(null, number)
                        os.close(null)
                    held.append(number)
            if len(held) != 2:
                for number in held:
                    os.close(number)
                self.skipTest('fd 5 or 6 is in use by the test runner')
            try:
                taking = Path(tmp, 'taking')
                taking.write_text('#!/usr/bin/python3\nimport os, socket, sys\n'
                                  'assert len(sys.argv) == 3 and sys.argv[2] == "6"; os.fstat(6)\n'
                                  's = socket.socket(fileno=int(sys.argv[1])); s.send(b"S"); s.recv(1)\n')
                older = Path(tmp, 'older')
                older.write_text('#!/usr/bin/python3\nimport socket, sys\n'
                                 'if len(sys.argv) != 2: sys.exit(64)\n'
                                 's = socket.socket(fileno=int(sys.argv[1])); s.send(b"S"); s.recv(1)\n')
                for path in (taking, older):
                    path.chmod(0o755)
                with patch.object(self.session, 'COMPOSITOR', str(taking)):
                    compositor, frames = self.session.start_compositor(frames=True)
                    self.assertTrue(frames)
                    compositor.close()
                # A compositor that takes no frame socket still starts, relayed as before.
                with patch.object(self.session, 'COMPOSITOR', str(older)):
                    compositor, frames = self.session.start_compositor(frames=True)
                    self.assertIsInstance(compositor, socket.socket)
                    self.assertFalse(frames)
                    compositor.close()
            finally:
                for number in held:
                    os.close(number)

    def test_only_chromium_errors_reach_the_log_and_without_addresses(self):
        import io
        reader, writer = os.pipe()
        out = io.StringIO()
        thread = self.session.forward_errors(reader, limit=2, out=out)
        os.write(writer, b'[1:2:1120/110000.1:INFO:main.cc(1)] started\n'
                         b'[16:40:1120/152430.9:ERROR:dbus/bus.cc:405] Failed to connect to the bus\n'
                         b'[1:2:1120/110000.2:ERROR:gpu.cc(5)] failed https://www.youtube.com/watch?v=x\n'
                         b'[1:2:1120/110000.3:FATAL:ozone.cc(9)] no display\n'
                         b'[1:2:1120/110000.4:ERROR:x.cc(1)] beyond the limit\n')
        os.close(writer)
        thread.join(5)
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn('ERROR:gpu.cc(5)] failed <address>', lines[0])
        self.assertNotIn('youtube', out.getvalue())
        self.assertIn('FATAL:ozone.cc(9)] no display', lines[1])
        self.assertIn('--log-level=2', self.arguments(self.session.FULL, True))

    def test_gpu_raster_flags_and_their_switch(self):
        direct = self.arguments(self.session.FULL, True, gpu=True)
        self.assertIn('--ignore-gpu-blocklist', direct)
        self.assertIn('--enable-gpu-rasterization', direct)
        with patch.dict(os.environ, {'HOME': '/tmp/home', 'A22X_WEB_GPU': '1', 'A22X_WEB_RASTER': '0'}, clear=True):
            switched = self.session.engine_arguments(self.session.FULL, True)
        self.assertNotIn('--enable-gpu-rasterization', switched)
        self.assertNotIn('--ignore-gpu-blocklist', self.arguments(self.session.FULL, True))


class FrameSocket(unittest.TestCase):
    """web_launch keeps fd 6 for the UI's frame socket; anything else there becomes /dev/null."""

    def probe(self, setup):
        code = ('import os, socket, sys\n' + setup +
                'sys.path.insert(0, %r)\nimport web_launch\n' % str(ROOT) +
                'ok = web_launch.reserve_frames_fd()\n'
                'import stat\nprint(ok, stat.S_ISSOCK(os.fstat(6).st_mode), os.readlink("/proc/self/fd/6"))\n')
        done = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.split()

    def test_a_seqpacket_socket_is_kept(self):
        setup = ('a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)\n'
                 'os.dup2(b.fileno(), 6, inheritable=True)\n')
        ok, sock, _ = self.probe(setup)
        self.assertEqual((ok, sock), ('True', 'True'))

    def test_nothing_or_another_kind_becomes_dev_null(self):
        for setup in ('os.closerange(6, 7)\n',
                      'a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)\nos.dup2(b.fileno(), 6)\n'):
            ok, sock, target = self.probe(setup)
            self.assertEqual((ok, sock, target), ('False', 'False', '/dev/null'))

    def test_measuring_switches(self):
        sys.path.insert(0, str(ROOT))
        import web_launch
        real_lstat = os.lstat

        def owned(name):
            real = real_lstat(name)
            return os.stat_result((real.st_mode, real.st_ino, real.st_dev, real.st_nlink, 0, 0, real.st_size,
                                   int(real.st_atime), int(real.st_mtime), int(real.st_ctime)))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'web-options.json')
            with patch.object(web_launch, 'OPTIONS', path):
                self.assertEqual(web_launch.options(), {'gpu_raster': True, 'direct_frames': True})
                path.write_text('{"gpu_raster": false, "direct_frames": "no"}')
                with patch.object(web_launch.os, 'lstat', owned):
                    self.assertEqual(web_launch.options(), {'gpu_raster': False, 'direct_frames': True})
                # Not root's file: ignored (said so outright: under tools/run-tests.sh the test runs as root).
                def users(name):
                    real = real_lstat(name)
                    return os.stat_result((real.st_mode, real.st_ino, real.st_dev, real.st_nlink, 1000, 1000,
                                           real.st_size, int(real.st_atime), int(real.st_mtime), int(real.st_ctime)))
                with patch.object(web_launch.os, 'lstat', users):
                    self.assertEqual(web_launch.options(), {'gpu_raster': True, 'direct_frames': True})


def _root_owned(path):
    real = os.lstat(path)
    return os.stat_result((real.st_mode, real.st_ino, real.st_dev, real.st_nlink, 0, 0, real.st_size,
                           int(real.st_atime), int(real.st_mtime), int(real.st_ctime)))


if __name__ == '__main__':
    unittest.main()
