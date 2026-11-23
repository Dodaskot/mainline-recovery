"""Run with A22X_TEST_CHROMIUM pointing at a sandbox-capable Chromium executable.

For the Wayland cases set A22X_TEST_WAYLAND_COMPOSITOR to the executable
built by make -C ui web-compositor-test.
"""
from collections import Counter
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import mmap
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
CHROMIUM = os.environ.get('A22X_TEST_CHROMIUM')
COMPOSITOR = os.environ.get('A22X_TEST_WAYLAND_COMPOSITOR')
FRAME_BYTES = 1080 * 2400 * 4
COLORS = {'a': 'e01010', 'b': '10e010', 'c': '1010e0', 'popup': 'c08010'}

SESSION_CHILD = """
import fcntl
import os
import sys
import web_session as session

folder, chromium, compositor, saturated, *original_fds = sys.argv[1:]
copied_fds = [fcntl.fcntl(int(fd), fcntl.F_DUPFD_CLOEXEC, 10) for fd in original_fds]
for fd, target in zip(copied_fds, (0, 5, 6)):
    os.dup2(fd, target)
    os.close(fd)
for fd in map(int, original_fds):
    if fd not in (0, 5, 6):
        os.close(fd)
session.FULL = chromium
if compositor:
    session.COMPOSITOR = compositor
session.LINKS = os.path.join(folder, 'links')
original_arguments = session.engine_arguments
def test_arguments(*args):
    return [
        '--disk-cache-dir=' + os.path.join(folder, 'cache') if arg.startswith('--disk-cache-dir=') else arg
        for arg in original_arguments(*args)
    ]
session.engine_arguments = test_arguments
if saturated == '1':
    # Keep CDP startup replies unread until the native inputs fill the queue.
    engine_reader = None
    released = False
    launch = session.start_engine
    select_ready = session.select.select
    enqueue = session.queue_command

    def remember_engine_reader(*args):
        global engine_reader
        engine_reader, writer = launch(*args)
        return engine_reader, writer

    def hold_engine_replies(sources, *args):
        if not released:
            sources = [source for source in sources if source != engine_reader]
        return select_ready(sources, *args)

    def enqueue_initial_commands(queue, packet):
        global released
        enqueue(queue, packet)
        if packet.startswith(b'I99 '):
            released = True

    session.start_engine = remember_engine_reader
    session.select.select = hold_engine_replies
    session.queue_command = enqueue_initial_commands

session.run(chromium, folder)
"""


class Pages(BaseHTTPRequestHandler):
    def do_GET(self):
        page = self.path.lstrip('/')
        if page not in COLORS:
            self.send_error(404)
            return
        self.server.requests[page] += 1
        label = page.upper()
        body = f"""<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{label}</title><body style="background:#{COLORS[page]};min-height:100vh">
<input aria-label="State" style="width:200px;height:30px"
 onkeydown="if(event.key==='Enter')window.open('/popup')"
 oninput="document.title='{label}:'+ (this.value.includes('@') ? 'value:'+this.value.replace('@','') : this.value);
          history.pushState({{}},'', '#edited')">
""".encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@unittest.skipUnless(CHROMIUM, 'set A22X_TEST_CHROMIUM to run the live browser tests')
class ChromiumTabs(unittest.TestCase):
    def test_screencast(self):
        self.exercise_tabs('headless')

    @unittest.skipUnless(COMPOSITOR, 'build and set A22X_TEST_WAYLAND_COMPOSITOR for Wayland')
    def test_wayland(self):
        for mode in ('relay', 'direct'):
            with self.subTest(mode=mode):
                self.exercise_tabs(mode)

    def test_saturated_startup_acknowledges_latest_tab(self):
        self.exercise_tabs('headless', saturated=True)

    def exercise_tabs(self, mode, saturated=False):
        with ExitStack() as resources:
            folder = resources.enter_context(tempfile.TemporaryDirectory(prefix='a22x-test-tabs-'))
            http = resources.enter_context(ThreadingHTTPServer(('127.0.0.1', 0), Pages))
            http.requests = Counter()
            server = threading.Thread(target=http.serve_forever, daemon=True)
            server.start()
            resources.callback(server.join)
            resources.callback(http.shutdown)
            base = f'http://127.0.0.1:{http.server_port}'
            control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            frame_queue, child_frames = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            for sock in (control, child_control, frame_queue, child_frames):
                resources.enter_context(sock)
            fd = os.memfd_create('a22x-test-browser')
            resources.callback(os.close, fd)
            os.ftruncate(fd, FRAME_BYTES * 2)
            pixels = resources.enter_context(mmap.mmap(fd, FRAME_BYTES * 2))
            env = dict(os.environ, HOME=folder, XDG_RUNTIME_DIR=folder,
                       A22X_WEB_WAYLAND='0' if mode == 'headless' else '1',
                       A22X_WEB_FRAMES='1' if mode == 'direct' else '0',
                       A22X_WEB_GPU='0', A22X_WEB_SOUND='0')
            fds = (child_control.fileno(), fd, child_frames.fileno())
            process = subprocess.Popen([
                sys.executable, '-B', '-c', SESSION_CHILD, folder, CHROMIUM, COMPOSITOR or '',
                '1' if saturated else '0', *map(str, fds),
            ], cwd=ROOT, env=env, pass_fds=fds)
            child_control.close()
            child_frames.close()
            recent = []

            def stop_process():
                try:
                    control.send(b'Q', socket.MSG_DONTWAIT)
                except OSError:
                    pass
                control.close()
                try:
                    self.assertEqual(process.wait(timeout=8), 0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    self.fail('browser session did not exit')

            resources.callback(stop_process)

            def send(*commands):
                for command in commands:
                    control.send(command.encode())

            def expect(*messages):
                waiting = set(messages)
                deadline = time.monotonic() + 10
                while waiting and time.monotonic() < deadline:
                    sources = [control, frame_queue] if frame_queue.fileno() >= 0 else [control]
                    ready, _, _ = select.select(sources, [], [], max(0, deadline - time.monotonic()))
                    for source in ready:
                        packet = source.recv(4096)
                        if not packet and source == frame_queue:
                            frame_queue.close()
                            continue
                        self.assertTrue(packet, f'browser session exited after {recent[-25:]}')
                        if packet.startswith(b'F'):
                            slot = packet[1:2]
                            offset = (int(slot) if slot.isdigit() else 0) * FRAME_BYTES + (650 * 1080 + 700) * 4
                            packet = ('F' + bytes(pixels[offset:offset + 3])[::-1].hex()).encode()
                            source.send(b'A' + slot if slot.isdigit() else b'A')
                        message = packet.decode('utf-8', 'replace')
                        recent.append(message)
                        waiting.discard(message)
                self.assertFalse(waiting, f'missing {waiting} after {recent[-25:]}')

            if saturated:
                send(*(['L0'] * 32), f'I98 1 {base}/a', f'I99 2 {base}/b')
                expect('I99', 'U' + base + '/b', 'F' + COLORS['b'])
                self.assertNotIn('I98', recent)
                self.assertEqual(http.requests['a'], 0)
                return

            send('I1 1 ', f'N{base}/a')
            expect('I1', 'F' + COLORS['a'])
            send('D15 15', 'E')
            expect('K1')
            send('Tretained')
            expect('WA:retained', 'H10')
            send(f'I2 2 {base}/b')
            expect('I2', 'F' + COLORS['b'])

            # xdg-open can finish an intent from A after B is selected.
            # Its FIFO record contains a URL and no originating target.
            fallback = quote(base + '/c', safe='')
            links = os.open(Path(folder, 'links'), os.O_WRONLY | os.O_NONBLOCK)
            with os.fdopen(links, 'w') as fifo:
                fifo.write(f'intent://example#Intent;S.browser_fallback_url={fallback};end\n')
            expect('SThis Android app link has a web fallback. Recovery could not identify the tab that opened it.')
            self.assertEqual(http.requests['c'], 0)

            send(f'I3 1 {base}/a#edited')
            expect('I3', 'U' + base + '/a#edited', 'WA:retained', 'H10', 'F' + COLORS['a'])
            self.assertEqual(http.requests['a'], 1)
            send('D15 15', 'E')
            expect('K1')
            send('T@')
            expect('WA:value:retained')

            # With B most recently used, opening C evicts A. Selecting A
            # again reports the eviction, fetches once, and gets a fresh DOM.
            send(f'I4 2 {base}/b')
            expect('I4', 'F' + COLORS['b'])
            send(f'I5 3 {base}/c')
            expect('I5', 'F' + COLORS['c'])
            send(f'I6 1 {base}/a#edited')
            expect('I6', 'SReloading tab to limit browser memory', 'F' + COLORS['a'])
            self.assertEqual(http.requests['a'], 2)

            send('D15 15', 'E')
            expect('K1')
            send('KEnter')
            expect('U' + base + '/popup', 'F' + COLORS['popup'])
            send('B')
            expect('U' + base + '/a#edited', 'F' + COLORS['a'])
            self.assertEqual(http.requests['a'], 2)

            # Closing another card keeps the selected target and its URL.
            send('O3', f'I7 2 {base}/b')
            expect('I7', 'F' + COLORS['b'])
            send('I8 1 ')
            expect('I8', 'U' + base + '/a#edited', 'F' + COLORS['a'])
            self.assertEqual(http.requests['a'], 2)


if __name__ == '__main__':
    unittest.main()
