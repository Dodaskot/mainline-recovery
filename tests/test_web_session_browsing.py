"""What the browser does with an address, its last page and YouTube's bot check (2026-11-20, a
tester, #6: no Google search, no session after a short exit, videos stopped after one minute)."""
from collections import deque
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
try:
    import web_session  # noqa: E402
except ImportError as error:  # PIL is missing on this host
    web_session = None
    MISSING = str(error)


@unittest.skipIf(web_session is None, 'web_session needs PIL')
class Visibility(unittest.TestCase):
    def exercise(self, steps, mode):
        ui, compositor = Mock(), Mock()
        reader, writer = 13, 14
        inputs, reads, replies, commands = deque(), deque(), deque(), []
        results = {
            'Browser.getVersion': {'product': 'Chrome/140.0.0.0'},
            'Target.getTargets': {'targetInfos': [{'type': 'page', 'targetId': 'page'}]},
            'Target.attachToTarget': {'sessionId': 'tab'},
            'Target.activateTarget': {},
            'Emulation.setUserAgentOverride': {},
            'Page.getFrameTree': {'frameTree': {'frame': {'id': 'page', 'url': 'about:blank'}}},
        }

        def encoded(message):
            return json.dumps(message).encode() + b'\0'

        def write(fd, data):
            self.assertEqual(fd, writer)
            command = json.loads(bytes(data)[:-1])
            commands.append((command['method'], command['params']))
            if command['method'] in results:
                replies.append(encoded({'id': command['id'], 'result': results[command['method']]}))
            return len(data)

        def select_ready(*_args):
            while steps[0] is None and not replies:
                steps.popleft()
            if steps[0] is None:
                reads.append(replies.popleft())
            else:
                item = steps.popleft()
                if isinstance(item, bytes):
                    inputs.append(item)
                    return [ui], [], []
                reads.append(encoded(item))
            return [reader], [], []

        ui.recv.side_effect = lambda *_: inputs.popleft()
        frame = Mock(size=(web_session.WIDTH, web_session.HEIGHT))
        frame.convert.return_value.tobytes.return_value = b'pixels'
        image = Mock()
        image.__enter__ = Mock(return_value=frame)
        image.__exit__ = Mock(return_value=False)
        environment = {'HOME': '/tmp', 'A22X_WEB_WAYLAND': str(int(mode != 'headless')),
                       'A22X_WEB_FRAMES': str(int(mode == 'direct'))}
        with (patch.dict(os.environ, environment), patch.object(web_session.socket, 'socket', return_value=ui),
              patch.object(web_session, 'start_engine', return_value=(reader, writer)),
              patch.object(web_session, 'start_compositor', return_value=(compositor, mode == 'direct')) as launch,
              patch.object(web_session, 'open_links', return_value=None), patch.object(web_session.os, 'close'),
              patch.object(web_session.os, 'write', side_effect=write),
              patch.object(web_session.os, 'read', side_effect=lambda *_: reads.popleft()),
              patch.object(web_session.select, 'select', side_effect=select_ready),
              patch.object(web_session.mmap, 'mmap', return_value=bytearray()),
              patch.object(web_session.Image, 'open', return_value=image)):
            web_session.run('/chromium')
            if mode != 'headless':
                launch.assert_called_once_with(mode == 'direct')
        ui_packets = [call.args[0] for call in ui.send.call_args_list]
        compositor_packets = [call.args[0] for call in compositor.send.call_args_list]
        return commands, ui_packets, compositor_packets

    def test_wayland_visibility_bypasses_the_startup_queue_in_both_modes(self):
        for mode in ('direct', 'relay'):
            with self.subTest(mode=mode):
                _, _, packets = self.exercise(deque([b'V0', b'V0', b'V1', b'Q']), mode)
                self.assertEqual(packets, [b'V0', b'V1'])

    def test_headless_visibility_does_not_start_capture_before_tab_attachment(self):
        commands, _, _ = self.exercise(deque([None, b'V0', b'V1', b'Q']), 'headless')
        self.assertNotIn('Page.startScreencast', [method for method, _ in commands])
        self.assertNotIn('Page.stopScreencast', [method for method, _ in commands])

    def test_headless_skips_hidden_capture_and_keeps_outstanding_frame_ownership(self):
        def frame(stamp):
            return {'method': 'Page.screencastFrame', 'sessionId': 'tab', 'params': {'sessionId': stamp, 'data': 'AA=='}}

        hidden_navigation = {'method': 'Page.loadEventFired', 'sessionId': 'tab'}
        steps = deque([b'V0', b'I1 1 ', None, hidden_navigation, b'V1', frame(1), frame(2), b'V0',
                       frame(3), b'V1', frame(4), b'A', b'A', b'Q'])
        commands, packets, _ = self.exercise(steps, 'headless')
        methods = ('Page.startScreencast', 'Page.stopScreencast', 'Page.screencastFrameAck')
        capture = [(method.split('.')[1], params.get('sessionId')) for method, params in commands if method in methods]
        self.assertEqual(capture, [('startScreencast', None), ('screencastFrameAck', 2), ('stopScreencast', None),
                                   ('screencastFrameAck', 3), ('startScreencast', None),
                                   ('screencastFrameAck', 1), ('screencastFrameAck', 4)])
        self.assertEqual(packets.count(b'F'), 2)


@unittest.skipIf(web_session is None, 'web_session needs PIL')
class Address(unittest.TestCase):
    def test_addresses_hosts_and_searches(self):
        cases = {
            'https://example.org/a?b=c': 'https://example.org/a?b=c',
            'example.org': 'https://example.org',
            'github.com/Dodaskot/mainline-recovery': 'https://github.com/Dodaskot/mainline-recovery',
            '  example.org  ': 'https://example.org',
            '192.168.1.1': 'https://192.168.1.1',
            'localhost:8080/x': 'https://localhost:8080/x',
            'how to root a22x': 'https://www.google.com/search?q=how+to+root+a22x',
            'a22x': 'https://www.google.com/search?q=a22x',
            'what is 2+2?': 'https://www.google.com/search?q=what+is+2%2B2%3F',
            'https://example.org and more': 'https://www.google.com/search?q=https%3A%2F%2Fexample.org+and+more',
        }
        for typed, expected in cases.items():
            self.assertEqual(web_session.address(typed), expected, typed)

    def test_other_schemes_and_control_characters_are_refused(self):
        for typed in ('file:///etc/passwd', 'ftp://example.org', 'javascript:alert(1)x://y', '', ' ', 'a\nb', 'x' * 2049,
                      'https://user:pass@example.org'):
            with self.assertRaises(ValueError, msg=typed):
                web_session.address(typed)


@unittest.skipIf(web_session is None, 'web_session needs PIL')
class LastPage(unittest.TestCase):
    def test_the_last_web_page_is_kept_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertIsNone(web_session.last_page(folder))
            web_session.remember_page(folder, 'https://example.org/watch?v=1')
            self.assertEqual(web_session.last_page(folder), 'https://example.org/watch?v=1')
            for other in ('about:blank', 'chrome://settings', 'file:///etc/passwd', 'data:text/html,x'):
                web_session.remember_page(folder, other)
            self.assertEqual(web_session.last_page(folder), 'https://example.org/watch?v=1')
            Path(folder, web_session.LAST_PAGE).write_text('javascript:alert(1)')
            self.assertIsNone(web_session.last_page(folder))
            self.assertEqual(os.listdir(folder), [web_session.LAST_PAGE])
        web_session.remember_page('/nonexistent/folder', 'https://example.org')  # ignored


@unittest.skipIf(web_session is None, 'web_session needs PIL')
class EngineFlags(unittest.TestCase):
    def test_no_automation_mark_and_a_session_cache(self):
        with patch.dict(os.environ, {'HOME': '/tmp/home'}, clear=True):
            arguments = web_session.engine_arguments(web_session.FULL, True)
        self.assertIn('--disable-blink-features=AutomationControlled', arguments)
        self.assertIn('--disk-cache-dir=/tmp/cache', arguments)
        self.assertIn('--user-data-dir=/tmp/home/profile', arguments)

    def test_chromium_keeps_its_frame_limit_and_follows_the_compositors_pace(self):
        # 2026-11-21, on the phone: without its limit Chromium drew without pause (two cores over a
        # paused video, YouTube stuttered); the compositor's presentation feedback paces it at 90 Hz.
        with patch.dict(os.environ, {'HOME': '/tmp/home'}, clear=True):
            for direct in (True, False):
                self.assertNotIn('--disable-frame-rate-limit', web_session.engine_arguments(web_session.FULL, direct))


@unittest.skipIf(web_session is None, 'web_session needs PIL')
class PreReadyCommands(unittest.TestCase):
    def test_newest_selection_survives_a_saturated_queue(self):
        initial = [b'I1 1 ', b'Nhttps://example.org/a']
        initial.extend(b'T' + str(i).encode() for i in range(web_session.PENDING_COMMANDS - len(initial)))
        queue = deque()
        for packet in initial:
            web_session.queue_command(queue, packet)
        web_session.queue_command(queue, b'I2 2 https://example.org/b')
        web_session.queue_command(queue, b'Tqueue full')
        for sequence in range(3, 300):
            latest = f'I{sequence} 3 https://example.org/c'.encode()
            web_session.queue_command(queue, latest)
        self.assertEqual(list(queue), initial + [latest])

    def test_selections_keep_order_with_navigation_and_closing_below_capacity(self):
        commands = [b'I1 1 ', b'I2 2 ', b'Nhttps://example.org/b', b'O1', b'I3 3 ', b'I4 4 ']
        queue = deque()
        for packet in commands:
            web_session.queue_command(queue, packet)
        self.assertEqual(list(queue), commands)


if __name__ == '__main__':
    unittest.main()
