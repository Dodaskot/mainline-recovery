"""Android's own factory reset authorizes the data reset (2026-11-21, the owner)."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import format_authorization as authorization  # noqa: E402


def misc(lines, command='boot-recovery'):
    data = bytearray(2048)
    data[0:len(command)] = command.encode()
    text = '\n'.join(lines).encode()
    data[64:64 + len(text)] = text
    return bytes(data)


class Context:
    mode = 'fixture'

    def __init__(self, root):
        self.root = root


class AndroidRequestedReset(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix='a22x-bcb-')
        self.root = Path(self.dir.name)
        self.arrival = self.root / 'bcb.json'
        self.context = Context(self.root)

    def tearDown(self):
        self.dir.cleanup()

    def state(self, at_start, now):
        self.arrival.write_text(json.dumps({'ok': True, 'command': 'boot-recovery', 'recovery': at_start,
                                            'wipe': True, 'cleared': False}))
        (self.root / 'misc').write_bytes(misc(now))
        return authorization.android_requested_reset(self.context, self.arrival)

    def test_a_factory_reset_from_settings_present_since_the_start(self):
        lines = ['recovery', '--wipe_data', '--reason=MasterClearConfirm']
        self.assertTrue(self.state(lines, lines))

    def test_android_that_could_not_open_its_data_still_needs_the_password(self):
        lines = ['recovery', '--prompt_and_wipe_data', '--reason=fs_mgr_mount_all']
        self.assertFalse(self.state(lines, lines))

    def test_a_request_written_after_the_start_or_changed_is_refused(self):
        self.assertFalse(self.state(['recovery'], ['recovery', '--wipe_data']))
        self.assertFalse(self.state(['recovery', '--wipe_data', '--reason=A'], ['recovery', '--wipe_data', '--reason=B']))

    def test_a_request_already_done_is_refused(self):
        lines = ['recovery', '--wipe_data']
        self.arrival.write_text(json.dumps({'command': 'boot-recovery', 'recovery': lines}))
        (self.root / 'misc').write_bytes(bytes(2048))
        self.assertFalse(authorization.android_requested_reset(self.context, self.arrival))

    def test_samsungs_reset_in_cache_and_its_use_once(self):
        lines = ['--wipe_data', '--reason=MasterClearConfirm,2026-11-21T00:57:18Z', '--locale=uk-UA']
        (self.root / 'misc').write_bytes(misc([]))
        (self.root / 'cache-command').write_text('\n'.join(lines) + '\n')
        self.arrival.write_text(json.dumps({'command': 'boot-recovery', 'recovery': lines, 'source': 'cache', 'wipe': True}))
        self.assertTrue(authorization.android_requested_reset(self.context, self.arrival))
        authorization.consume_android_reset(self.arrival)
        self.assertFalse(authorization.android_requested_reset(self.context, self.arrival))

    def test_a_cache_request_that_went_is_refused(self):
        lines = ['--wipe_data']
        (self.root / 'misc').write_bytes(misc([]))
        self.arrival.write_text(json.dumps({'command': 'boot-recovery', 'recovery': lines, 'source': 'cache', 'wipe': True}))
        self.assertFalse(authorization.android_requested_reset(self.context, self.arrival))

    def test_no_record_from_the_start_is_refused(self):
        (self.root / 'misc').write_bytes(misc(['recovery', '--wipe_data']))
        self.assertFalse(authorization.android_requested_reset(self.context, self.root / 'missing.json'))


if __name__ == '__main__':
    unittest.main()
