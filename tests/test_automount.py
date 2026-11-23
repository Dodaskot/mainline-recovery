"""Volumes mounted at start by automount.py (2026-11-20): by kind, by single volume, never formatted."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import automount  # noqa: E402
import filesystem as fs  # noqa: E402
import settings  # noqa: E402

DEFAULT = automount.policy_of({})


class FakeContext:
    """volumes() and mount() of a context, recording the mounts asked for."""
    def __init__(self, volumes, fail=None):
        self.list, self.calls, self.fail = volumes, [], fail or {}

    def volumes(self):
        return [dict(v) for v in self.list]

    def mount(self, ident, mode, confirmed, token):
        assert confirmed and token == 't-' + ident
        self.calls.append((ident, mode))
        if ident in self.fail:
            raise fs.FilesystemError(self.fail[ident], 'refused')
        return {}


def volume(ident, **values):
    base = {'id': ident, 'mounted': False, 'read_only': True, 'mountable': True, 'write_supported': True,
            'volume_token': 't-' + ident}
    return {**base, **values}


class Policy(unittest.TestCase):
    def test_defaults_are_cards_and_data_for_writing(self):
        self.assertEqual(DEFAULT, {'mount_cards': 'rw', 'mount_data': 'rw', 'mount_others': 'off', 'mount_list': ''})
        for key, value in DEFAULT.items():
            self.assertTrue(settings.valid(key, value), key)

    def test_the_settings_accept_only_modes_and_well_formed_lists(self):
        self.assertTrue(settings.valid('mount_list', 'cache:ro,sdcard-p1:off,efs:rw'))
        for bad in ('cache', 'cache:write', 'Cache:ro', 'cache:ro,', ',cache:ro', 'a b:ro', '-x:ro', ','.join(['volume-%02d:rw' % n for n in range(80)])):
            self.assertFalse(settings.valid('mount_list', bad), bad)
        self.assertFalse(settings.valid('mount_cards', 'yes'))
        self.assertEqual(automount.overrides('cache:ro,bad'), {})
        self.assertEqual(automount.policy_of({'mount_data': 'nonsense'})['mount_data'], 'rw')


class Run(unittest.TestCase):
    def test_cards_and_data_for_writing_others_left_alone(self):
        ctx = FakeContext([volume('sdcard-p1'), volume('usb-p1'), volume('userdata'), volume('cache'), volume('efs')])
        result = automount.run(ctx, DEFAULT)
        self.assertEqual(ctx.calls, [('sdcard-p1', 'rw'), ('usb-p1', 'rw'), ('userdata', 'rw')])
        self.assertEqual([r['result'] for r in result['results']], ['mounted'] * 3)
        self.assertFalse(result['needs_password'])

    def test_single_volumes_override_their_kind(self):
        ctx = FakeContext([volume('sdcard-p1'), volume('cache'), volume('efs'), volume('userdata')])
        policy = {**DEFAULT, 'mount_others': 'ro', 'mount_list': 'sdcard-p1:ro,efs:off,userdata:off'}
        automount.run(ctx, policy)
        self.assertEqual(ctx.calls, [('sdcard-p1', 'ro'), ('cache', 'ro')])

    def test_what_is_mounted_as_asked_stays_and_read_only_is_remounted_for_writing(self):
        ctx = FakeContext([volume('sdcard-p1', mounted=True, read_only=False), volume('usb-p1', mounted=True, read_only=True),
                           volume('userdata', mounted=True, read_only=True)])
        result = automount.run(ctx, {**DEFAULT, 'mount_data': 'ro'})
        self.assertEqual(ctx.calls, [('usb-p1', 'rw')])
        self.assertEqual([r['result'] for r in result['results']], ['already', 'mounted', 'already'])

    def test_android_data_is_left_to_the_unlock_of_the_interface(self):
        for values in ({'credential_required': True}, {'credential_required': False}):
            locked = volume('userdata', decrypt_supported=True, decrypt_state='awaiting_credential', **values)
            ctx = FakeContext([volume('sdcard-p1'), locked])
            result = automount.run(ctx, DEFAULT)
            self.assertTrue(result['needs_password'])
            self.assertEqual(ctx.calls, [('sdcard-p1', 'rw')])
            self.assertEqual(result['results'][1], {'id': 'userdata', 'wanted': 'rw', 'result': 'needs_password'})
        ctx = FakeContext([volume('userdata', decrypt_supported=True, mounted=True, read_only=True, mount_owner='android-decrypt')])
        result = automount.run(ctx, DEFAULT)
        self.assertEqual((ctx.calls, result['results'][0]['result'], result['needs_password']), ([], 'already', False))
        ctx = FakeContext([volume('userdata', decrypt_supported=False, decrypt_state='reboot_required')])
        result = automount.run(ctx, DEFAULT)
        self.assertEqual((ctx.calls, result['results'][0]['reason'], result['needs_password']), ([], 'reboot_required', False))
        self.assertFalse(automount.run(FakeContext([volume('userdata', decrypt_supported=True)]), {**DEFAULT, 'mount_data': 'off'})['needs_password'])
        unreadable = volume('userdata', read_only_reason='FSCRYPT_KEYS_UNAVAILABLE', write_supported=False)
        ctx = FakeContext([unreadable])
        result = automount.run(ctx, DEFAULT)
        self.assertEqual((ctx.calls, result['results'][0]['reason']), ([], 'FSCRYPT_KEYS_UNAVAILABLE'))

    def test_a_volume_that_cannot_be_written_is_mounted_read_only_and_a_failure_stops_nothing(self):
        ctx = FakeContext([volume('sdcard-p1', write_supported=False), volume('usb-p1'), volume('usb-p2')], fail={'usb-p1': 'MOUNT_FAILED'})
        result = automount.run(ctx, DEFAULT)
        self.assertEqual(ctx.calls, [('sdcard-p1', 'ro'), ('usb-p1', 'rw'), ('usb-p2', 'rw')])
        self.assertTrue(result['results'][0]['read_only_instead'])
        self.assertEqual(result['results'][1], {'id': 'usb-p1', 'wanted': 'rw', 'result': 'failed', 'code': 'MOUNT_FAILED'})
        self.assertEqual(result['results'][2]['result'], 'mounted')


    def test_metadata_is_written_only_by_its_own_choice(self):
        ctx = FakeContext([volume('metadata'), volume('cache')])
        automount.run(ctx, {**DEFAULT, 'mount_others': 'rw'})
        self.assertEqual(ctx.calls, [('metadata', 'ro'), ('cache', 'rw')])
        ctx = FakeContext([volume('metadata')])
        automount.run(ctx, {**DEFAULT, 'mount_list': 'metadata:rw'})
        self.assertEqual(ctx.calls, [('metadata', 'rw')])

    def test_a_drive_that_arrives_mounts_only_removable_volumes(self):
        ctx = FakeContext([volume('usb-p1', mounted=True, read_only=True), volume('userdata', decrypt_supported=True), volume('cache')])
        result = automount.run(ctx, {**DEFAULT, 'mount_others': 'rw'}, cards_only=True)
        self.assertEqual((ctx.calls, result['needs_password']), ([('usb-p1', 'rw')], False))


class Fixture(unittest.TestCase):
    def test_a_fixture_card_and_cache(self):
        root = Path(tempfile.mkdtemp(prefix='a22x-automount-'))
        self.addCleanup(shutil.rmtree, root, True)
        rows = []
        for ident, kind in (('sdcard-p1', 'exfat'), ('cache', 'ext4'), ('userdata', 'f2fs')):
            (root / ident).mkdir()
            rows.append({'id': ident, 'path': ident, 'fs_type': kind, 'mounted': False,
                         **({'fscrypt_feature': True} if ident == 'userdata' else {})})
        (root / 'filesystem-fixture.json').write_text(json.dumps({'schema': 'a22x.filesystem.fixture.v1', 'volumes': rows}))
        result = automount.run(fs.FixtureContext(root), {**DEFAULT, 'mount_list': 'cache:ro'})
        state = {v['id']: (v['mounted'], v['read_only']) for v in fs.FixtureContext(root).volumes()}
        self.assertEqual(state, {'sdcard-p1': (True, False), 'cache': (True, True), 'userdata': (False, True)})
        self.assertEqual({r['id']: r['result'] for r in result['results']},
                         {'sdcard-p1': 'mounted', 'cache': 'mounted', 'userdata': 'skipped'})


if __name__ == '__main__':
    unittest.main()
