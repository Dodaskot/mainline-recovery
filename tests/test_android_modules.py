"""Real temporary directory adversarial tests; no phone, mount or root scripts."""
import contextlib
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_modules as am
import filesystem as fs


class Modules(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='a22x-module-rescue-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data, self.sd = self.root / 'data', self.root / 'sd'
        self.data.mkdir()
        self.sd.mkdir()
        self.config = {'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
            {'id': 'userdata', 'path': 'data', 'fs_type': 'ext4', 'mounted': True, 'read_only': False},
            {'id': 'sdcard-p1', 'path': 'sd', 'fs_type': 'ext4', 'mounted': True, 'read_only': False}]}
        self.write_config()
        self.context = fs.FixtureContext(self.root)
        assets = self.data / 'adb/magisk'
        assets.mkdir(parents=True)
        util = b"MAGISK_VER='31.0'\nMAGISK_VER_CODE=31000\n"
        binary = b'fixture-only Magisk executable, never executed'
        (assets / 'util_functions.sh').write_bytes(util)
        (assets / 'magisk').write_bytes(binary)
        # Explicit fixture adapter: production constants stay pinned to upstream.
        self.rule = dict(am.MAGISK_31000, util_sha256=hashlib.sha256(util).hexdigest(),
                         magisk_sha256=hashlib.sha256(binary).hexdigest())
        patch = mock.patch.object(am, 'MAGISK_ADAPTERS', (self.rule,))
        patch.start()
        self.addCleanup(patch.stop)
        self.boot = {'kind': 'android', 'root': 'magisk', 'sha256': '1' * 64,
                     'magisk_sha256': self.rule['magisk_sha256'], 'init_sha256': self.rule['init_sha256']}
        self.real_boot_identity = am._boot_identity
        patch = mock.patch.object(am, '_boot_identity', return_value=self.boot)
        self.boot_mock = patch.start()
        self.addCleanup(patch.stop)
        self.module('alpha')

    def write_config(self):
        (self.root / 'filesystem-fixture.json').write_text(json.dumps(self.config))

    def module(self, ident, pending=False, version='1.0'):
        path = self.data / 'adb' / ('modules_update' if pending else 'modules') / ident
        path.mkdir(parents=True)
        (path / 'module.prop').write_text(f'id={ident}\nname={ident.title()}\nversion={version}\nversionCode=1\nauthor=Fixture\ndescription=Test\n')
        (path / 'service.sh').write_text('#!/bin/sh\nexit 99\n')
        return path

    def plan(self, action='disable', ident='alpha'):
        return am.preview(self.context, action, ident)['plan']

    def apply(self, action='disable', ident='alpha', plan=None, **kwargs):
        current = plan or self.plan(action, ident)
        return am.apply(self.context, action, ident, current['plan_sha256'], True, **kwargs)

    def assert_error(self, code, func, *args, **kwargs):
        with self.assertRaises(fs.FilesystemError) as raised:
            func(*args, **kwargs)
        self.assertEqual(raised.exception.code, code, str(raised.exception))
        return raised.exception

    def test_inventory_and_preview_do_not_write_userdata(self):
        before = {str(p.relative_to(self.data)): (p.stat().st_size, p.stat().st_mtime_ns)
                  for p in self.data.rglob('*')}
        state = am.inventory(self.context)
        self.assertEqual(state['framework']['status'], 'supported')
        self.assertEqual(state['modules'][0]['status'], 'enabled')
        plan = self.plan()
        self.assertTrue(plan['allowed'])
        self.assertEqual(plan, self.plan())
        after = {str(p.relative_to(self.data)): (p.stat().st_size, p.stat().st_mtime_ns)
                 for p in self.data.rglob('*')}
        self.assertEqual(before, after)

    def test_disable_enable_deferred_remove_and_cancel(self):
        module = self.data / 'adb/modules/alpha'
        result = self.apply()
        self.assertEqual(result['status'], 'applied')
        self.assertTrue((module / 'disable').is_file())
        receipt = json.loads((self.data / result['journal']['path'].lstrip('/')).read_text())
        self.assertEqual(receipt['status'], 'applied')
        self.assertEqual(receipt['plan']['framework']['boot']['sha256'], '1' * 64)
        self.apply('enable')
        self.assertFalse((module / 'disable').exists())
        self.apply('remove')
        self.assertTrue((module / 'remove').is_file())
        self.assertTrue((module / 'service.sh').is_file())
        self.assertFalse(self.plan('enable')['allowed'])
        self.apply('cancel-remove')
        self.assertFalse((module / 'remove').exists())

    def test_pending_update_markers_changed_with_active_copy(self):
        pending = self.module('alpha', pending=True, version='2.0')
        active = self.data / 'adb/modules/alpha'
        (active / 'update').touch()
        self.assertTrue(am.inventory(self.context)['modules'][0]['pending_update'])
        self.assertEqual(self.apply()['changed'], 2)
        self.assertTrue((active / 'disable').exists() and (pending / 'disable').exists())
        self.apply('enable')
        self.assertFalse((active / 'disable').exists() or (pending / 'disable').exists())
        self.apply('remove')
        self.assertTrue((active / 'remove').exists() and (pending / 'remove').exists())
        self.apply('cancel-remove')
        self.assertFalse((active / 'remove').exists() or (pending / 'remove').exists())

    def test_new_pending_module_is_included_in_disable_all(self):
        pending = self.module('bravo', pending=True)
        result = self.apply('disable-all', None)
        self.assertEqual(result['changed'], 2)
        self.assertTrue((pending / 'disable').exists())

    def test_stale_module_content_refuses_before_marker_write(self):
        plan = self.plan()
        (self.data / 'adb/modules/alpha/service.sh').write_text('changed\n')
        self.assert_error('MODULE_PLAN_CHANGED', self.apply, plan=plan)
        self.assertFalse((self.data / 'adb/modules/alpha/disable').exists())

    def test_stale_framework_or_boot_refuses(self):
        plan = self.plan()
        self.boot['sha256'] = '2' * 64
        self.assert_error('MODULE_PLAN_CHANGED', self.apply, plan=plan)

    def test_module_replacement_after_recheck_gets_no_marker_write(self):
        original = am._journal_open
        module = self.data / 'adb/modules/alpha'
        def swap(pin):
            result = original(pin)
            module.rename(self.data / 'adb/modules/replaced')
            self.module('alpha')
            return result
        with mock.patch.object(am, '_journal_open', side_effect=swap):
            self.assert_error('MODULE_TRANSACTION_INCOMPLETE', self.apply)
        self.assertFalse((module / 'disable').exists())
        self.assertFalse((self.data / 'adb/modules/replaced/disable').exists())

    def test_marker_replacement_after_recheck_is_not_unlinked(self):
        self.apply()
        original = am._journal_open
        marker = self.data / 'adb/modules/alpha/disable'
        def replace(pin):
            result = original(pin)
            marker.rename(marker.with_name('old-disable'))
            marker.touch()
            return result
        with mock.patch.object(am, '_journal_open', side_effect=replace):
            self.assert_error('MODULE_TRANSACTION_INCOMPLETE', self.apply, 'enable')
        self.assertTrue(marker.exists())
        self.assertTrue(marker.with_name('old-disable').exists())

    def test_missing_selinux_label_refuses_before_creating_marker(self):
        plan = self.plan()
        with fs.PinnedVolume(self.context, 'userdata', writing=True) as pin:
            with mock.patch.object(self.context, 'mode', 'device'), mock.patch.object(am.os, 'getxattr', side_effect=OSError('no label')):
                self.assert_error('MODULE_LABEL_UNKNOWN', am._change_marker, pin, plan['changes'][0], False)
        self.assertFalse((self.data / 'adb/modules/alpha/disable').exists())

    def test_unknown_or_mismatching_native_assets_read_only(self):
        self.boot['magisk_sha256'] = 'a' * 64
        self.assertFalse(am.inventory(self.context)['can_mutate'])
        self.assertFalse(self.plan()['allowed'])

    def test_directory_does_not_prove_framework(self):
        self.boot.update(root='', kind='android')
        self.assertFalse(self.plan()['allowed'])
        self.assertEqual(am.inventory(self.context)['framework']['status'], 'unknown')

    def test_ambiguous_or_kernelsu_framework_is_read_only(self):
        (self.data / 'adb/ksu').mkdir()
        self.boot['root'] = ''
        self.assertEqual(am.inventory(self.context)['framework']['id'], 'unknown')
        self.assertFalse(self.plan()['allowed'])

    def test_the_root_in_boot_names_the_framework_among_leftovers(self):
        """Live 2026-11-22: APatch, then KernelSU Next again: /data/adb keeps ap/ beside ksu/."""
        (self.data / 'adb/ksu').mkdir()
        (self.data / 'adb/ap').mkdir()
        framework = am.inventory(self.context)['framework']
        self.assertEqual((framework['id'], framework['status'], framework['leftovers']), ('magisk', 'supported', ['apatch', 'kernelsu']))
        self.assertTrue(self.plan()['allowed'])
        self.assertTrue((self.data / 'adb/ap').is_dir())

    def test_a_leftover_that_is_not_a_plain_directory_stays_read_only(self):
        (self.data / 'adb').joinpath('ap').symlink_to(self.data / 'adb/magisk')
        self.assertEqual(am.inventory(self.context)['framework']['id'], 'unknown')
        self.assertFalse(self.plan()['allowed'])

    def kernelsu(self, daemon=b'fixture-only ksud, never executed'):
        """This Android with KernelSU Next instead of Magisk: its kernel in BOOT, its ksud in /data/adb."""
        for name in ('util_functions.sh', 'magisk'):
            (self.data / 'adb/magisk' / name).unlink()
        (self.data / 'adb/magisk').rmdir()
        (self.data / 'adb/ksu').mkdir()
        (self.data / 'adb/ksud').write_bytes(daemon)
        rule = dict(am.KERNELSU_NEXT_33555, ksud_sha256=hashlib.sha256(b'fixture-only ksud, never executed').hexdigest())
        patch = mock.patch.object(am, 'KERNELSU_ADAPTERS', (rule,))
        patch.start()
        self.addCleanup(patch.stop)
        self.boot.clear()
        self.boot.update(kind='android', root='kernelsu', sha256='2' * 64, kernelpatch='', magisk_sha256=None, init_sha256=None)

    def test_kernelsu_next_markers_are_those_of_its_ksud(self):
        self.kernelsu()
        state = am.inventory(self.context)
        self.assertEqual((state['framework']['id'], state['framework']['status'], state['framework']['version_code']),
                         ('kernelsu', 'supported', 33555))
        self.assertTrue(state['can_mutate'])
        plan = self.plan()
        self.assertIn('KernelSU Next', plan['scope'])
        self.apply(plan=plan)
        self.assertTrue((self.data / 'adb/modules/alpha/disable').exists())
        self.apply('enable')
        self.assertFalse((self.data / 'adb/modules/alpha/disable').exists())
        self.apply('remove')
        self.assertTrue((self.data / 'adb/modules/alpha/remove').exists())
        self.apply('cancel-remove')
        self.assertFalse((self.data / 'adb/modules/alpha/remove').exists())
        self.apply('disable-all', None)
        self.assertTrue((self.data / 'adb/modules/alpha/disable').exists())

    def test_another_ksud_or_none_or_a_boot_without_kernelsu_is_read_only(self):
        self.kernelsu(b'another ksud')
        state = am.inventory(self.context)
        self.assertEqual((state['framework']['status'], state['can_mutate']), ('unknown', False))
        self.assertIn('not the reviewed', state['framework']['reason'])
        self.assertFalse(self.plan()['allowed'])
        (self.data / 'adb/ksud').unlink()
        self.assertIn('open its manager', am.inventory(self.context)['framework']['reason'])
        (self.data / 'adb/ksud').write_bytes(b'fixture-only ksud, never executed')
        self.assertTrue(self.plan()['allowed'])
        self.boot['root'] = 'magisk'
        self.assertFalse(self.plan()['allowed'])

    def test_a_kernelsu_metamodule_and_early_content_stay_with_the_manager(self):
        self.kernelsu()
        meta = self.module('meta_overlayfs')
        with open(meta / 'module.prop', 'a') as prop:
            prop.write('metamodule=1\n')
        rc = self.module('withrc')
        (rc / 'initrc').mkdir()
        rows = {m['id']: m for m in am.inventory(self.context)['modules']}
        self.assertEqual(rows['meta_overlayfs']['actions'], [])
        self.assertIn('metamodule', rows['meta_overlayfs']['reason'])
        self.assertEqual(rows['withrc']['actions'], [])
        self.assertTrue(self.plan('disable', 'alpha')['allowed'])
        self.assertFalse(self.plan('disable', 'meta_overlayfs')['allowed'])
        self.assertFalse(am.preview(self.context, 'disable-all')['plan']['allowed'])

    def test_the_rescue_disables_a_metamodule_with_the_others(self):
        """2026-11-22, live: one metamodule refused disable-all, the rescue after a boot loop."""
        self.kernelsu()
        meta = self.module('meta_overlayfs')
        with open(meta / 'module.prop', 'a') as prop:
            prop.write('metamodule=1\n')
        plan = am.preview(self.context, 'disable-all')['plan']
        self.assertTrue(plan['allowed'], plan['reason'])
        self.assertIn('meta_overlayfs', {c['id'] for c in plan['changes']})
        self.assertTrue(all(c['marker'] == 'disable' and c['after'] for c in plan['changes']))
        self.assertFalse(self.plan('disable', 'meta_overlayfs')['allowed'])  # alone: still the manager's
        self.apply('disable-all', None)
        self.assertTrue((meta / 'disable').exists())

    def test_a_large_metamodule_image_is_bound_by_its_stamp(self):
        """2026-11-22, live: meta-overlayfs's modules.img stopped the rescue at MODULE_LIMIT."""
        self.kernelsu()
        meta = self.module('meta_overlayfs')
        with open(meta / 'module.prop', 'a') as prop:
            prop.write('metamodule=1\n')
        with open(meta / 'modules.img', 'wb') as image:
            image.truncate(am.MAX_BYTES + (1 << 20))  # sparse: larger than the whole hashed budget
        plan = am.preview(self.context, 'disable-all')['plan']
        self.assertTrue(plan['allowed'], plan['reason'])
        self.apply('disable-all', None)
        self.assertTrue((meta / 'disable').exists())

    def test_read_only_mount_cannot_mutate(self):
        self.config['volumes'][0]['read_only'] = True
        self.write_config()
        plan = self.plan()
        self.assertTrue(plan['allowed'])
        self.assert_error('VOLUME_READ_ONLY', self.apply, plan=plan)
        self.assertFalse((self.data / 'adb/a22x-recovery-module-rescue').exists())

    def test_locked_data_returns_clear_empty_inventory(self):
        self.config['volumes'][0]['mounted'] = False
        self.write_config()
        state = am.inventory(self.context)
        self.assertFalse(state['access']['authenticated'])
        self.assertEqual(state['modules'], [])
        self.boot_mock.assert_not_called()

    def test_device_admission_requires_live_authenticated_user0_receipt(self):
        volume = self.context.volume('userdata')
        self.assertFalse(am.access(volume, 'device')['authenticated'])
        volume.update(ce_authenticated=True, fscrypt_policy_verified=True,
                      android_user_id=0, mount_owner='android-decrypt')
        self.assertTrue(am.access(volume, 'device')['authenticated'])
        volume['android_user_id'] = 10
        self.assertFalse(am.access(volume, 'device')['authenticated'])

    def test_invalid_ids_and_traversal_never_reach_write(self):
        for ident in ('../outside', '/tmp/test', 'alpha/../../x', '.', '..', 'a\0b', '1x'):
            self.assert_error('MODULE_ID_INVALID', self.plan, ident=ident)

    def test_one_character_ids_outside_documented_magisk_contract(self):
        # Magisk v31.0/v31.1 documented module.prop ID grammar requires >=2 characters.
        self.module('a')
        self.module('Z')
        self.assertIsNotNone(am.MODULE_ID.fullmatch('ab'))
        self.assertIsNotNone(am.MODULE_ID.fullmatch('Z0'))
        for ident in ('a', 'Z'):
            with self.subTest(ident=ident):
                self.assertIsNone(am.MODULE_ID.fullmatch(ident))
                self.assert_error('MODULE_ID_INVALID', self.plan, ident=ident)
                self.assert_error('MODULE_ID_INVALID', am.backup, self.context,
                                  ident, 'sdcard-p1', '/' + ident + '.tar.zst', True)
                self.assertFalse((self.data / 'adb/modules' / ident / 'disable').exists())
        for unsafe in ('1', '-', '.', '..', '../escape', 'a/../b'):
            with self.subTest(unsafe=unsafe):
                self.assert_error('MODULE_ID_INVALID', self.plan, ident=unsafe)
        self.assertFalse((self.data / 'adb/a22x-recovery-module-rescue').exists())
        self.assertEqual(list(self.sd.iterdir()), [])

    def test_symlinked_module_directory_and_marker_are_rejected(self):
        (self.data / 'adb/modules/bravo').symlink_to(self.sd, target_is_directory=True)
        self.assertFalse(self.plan('disable-all', None)['allowed'])
        (self.data / 'adb/modules/alpha/disable').symlink_to(self.sd / 'sentinel')
        self.assertFalse(self.plan()['allowed'])
        self.assertFalse((self.sd / 'sentinel').exists())

    def test_hardlink_payload_refuses_and_symlinks_are_not_followed(self):
        sentinel = self.sd / 'secret'
        sentinel.write_text('secret')
        os.link(sentinel, self.data / 'adb/modules/alpha/hardlink')
        self.assert_error('MODULE_FILE_UNSAFE', self.plan)
        (self.data / 'adb/modules/alpha/hardlink').unlink()
        (self.data / 'adb/modules/alpha/link').symlink_to(sentinel)
        plan = self.plan()
        sentinel.write_text('different outside content')
        self.assertEqual(plan, self.plan())

    def test_early_policy_rejects_disable_all_without_partial_write(self):
        bravo = self.module('bravo')
        (bravo / 'sepolicy.rule').write_text('allow foo bar:file read;\n')
        plan = self.plan('disable-all', None)
        self.assertFalse(plan['allowed'])
        self.assertEqual(plan['changes'], [])
        self.assert_error('MODULE_ACTION_UNSUPPORTED', self.apply, 'disable-all', None, plan)
        self.assertFalse((self.data / 'adb/modules/alpha/disable').exists())

    def test_orphaned_update_marker_rejected(self):
        (self.data / 'adb/modules/alpha/update').touch()
        self.assertFalse(self.plan()['allowed'])

    def test_duplicate_properties_and_marker_contents_rejected(self):
        prop = self.data / 'adb/modules/alpha/module.prop'
        prop.write_text(prop.read_text() + 'id=bravo\n')
        self.assertFalse(self.plan()['allowed'])
        prop.write_text('id=alpha\nname=Alpha\nversion=1\nversionCode=1\n')
        (prop.parent / 'disable').write_text('unexpected content')
        self.assertFalse(self.plan()['allowed'])

    def test_no_scripts_execute_during_inspection_or_apply(self):
        module = self.data / 'adb/modules/alpha'
        for name in ('uninstall.sh', 'action.sh', 'service.sh'):
            (module / name).write_text(f'#!/bin/sh\ntouch {self.sd}/EXECUTED\n')
            (module / name).chmod(0o755)
        self.apply('remove')
        self.assertFalse((self.sd / 'EXECUTED').exists())
        self.assertTrue((module / 'uninstall.sh').exists())

    def test_failure_is_journaled_as_partial_never_success_or_replay(self):
        self.module('bravo')
        original = am._change_marker
        count = [0]
        def fail_second(*args):
            count[0] += 1
            if count[0] == 2:
                raise OSError('injected I/O failure')
            return original(*args)
        with mock.patch.object(am, '_change_marker', side_effect=fail_second):
            error = self.assert_error('MODULE_TRANSACTION_INCOMPLETE', self.apply, 'disable-all', None)
        journal = json.loads((self.data / error.details['journal'].lstrip('/')).read_text())
        self.assertEqual(journal['status'], 'partial-or-uncertain')
        self.assertEqual(len(journal['completed']), 1)
        self.assertTrue((self.data / 'adb/modules/alpha/disable').exists())
        self.assertFalse((self.data / 'adb/modules/bravo/disable').exists())

    def test_symlinked_journal_never_writes_outside_userdata(self):
        (self.data / 'adb/a22x-recovery-module-rescue').symlink_to(self.sd, target_is_directory=True)
        with self.assertRaises((OSError, fs.FilesystemError)):
            self.apply()
        self.assertEqual(list(self.sd.iterdir()), [])
        self.assertFalse((self.data / 'adb/modules/alpha/disable').exists())

    def test_confirmation_required_and_existing_marker_is_not_rewritten(self):
        plan = self.plan()
        self.assert_error('CONFIRMATION_REQUIRED', am.apply, self.context, 'disable', 'alpha', plan['plan_sha256'], False)
        self.apply()
        marker = self.data / 'adb/modules/alpha/disable'
        before = marker.stat().st_ino
        self.assertEqual(self.apply()['status'], 'unchanged')
        self.assertEqual(marker.stat().st_ino, before)

    def test_backup_uses_existing_archive_engine_and_includes_marker(self):
        self.apply()
        result = am.backup(self.context, 'alpha', 'sdcard-p1', '/alpha.tar.zst', True)
        self.assertTrue((self.sd / 'alpha.tar.zst').is_file())
        self.assertGreater(result['archive']['bytes'], 0)
        self.assertTrue(result['module']['markers']['disable']['present'])
        self.assert_error('MODULE_BACKUP_DESTINATION', am.backup, self.context, 'alpha', 'userdata', '/x.tar.zst', True)

    def test_journal_list_and_detail_are_read_only(self):
        result = self.apply()
        ident = result['journal']['path'].rsplit('/', 1)[-1][:-5]
        before = {str(p.relative_to(self.data)): (p.stat().st_size, p.stat().st_mtime_ns)
                  for p in self.data.rglob('*')}
        listing = am.journals(self.context)
        self.assertEqual(len(listing['journals']), 1)
        row = listing['journals'][0]
        self.assertEqual((row['integrity'], row['status'], row['planned_steps']),
                         ('self-consistent', 'applied', 1))
        detail = am.journals(self.context, ident)['journal']
        self.assertEqual((detail['current_matches_desired'], detail['current_unavailable']), (1, 0))
        self.assertEqual(detail['current_markers'][0]['comparison'], 'matches-desired')
        after = {str(p.relative_to(self.data)): (p.stat().st_size, p.stat().st_mtime_ns)
                 for p in self.data.rglob('*')}
        self.assertEqual(before, after)
        self.apply('enable')
        old = am.journals(self.context, ident)['journal']
        self.assertEqual(old['current_markers'][0]['comparison'], 'matches-before')
        self.assertTrue(old['requires_review'])

    def test_journal_marker_verification_flag_is_explicit_and_fail_closed(self):
        receipt = self.apply('disable')
        ident = receipt['journal']['path'].rsplit('/', 1)[-1][:-5]
        journal_path = self.data / receipt['journal']['path'].lstrip('/')
        journal_before = (journal_path.read_bytes(), journal_path.stat().st_mtime_ns)

        # List is historical-only; detail actually checks current marker state.
        listing = am.journals(self.context)['journals'][0]
        self.assertFalse(listing['requires_review'])
        self.assertIs(listing['current_markers_verified'], False)
        valid = am.journals(self.context, ident)['journal']
        self.assertIs(valid['current_markers_verified'], True)
        self.assertFalse(valid['requires_review'])

        # Controlled drift: detail detects mismatch, but observation is complete.
        module_dir = self.data / 'adb/modules/alpha'
        (module_dir / 'disable').unlink()
        drift_list = am.journals(self.context)['journals'][0]
        self.assertFalse(drift_list['requires_review'])  # historical status only
        self.assertIs(drift_list['current_markers_verified'], False)
        drift = am.journals(self.context, ident)['journal']
        self.assertIs(drift['current_markers_verified'], True)
        self.assertTrue(drift['requires_review'])
        self.assertEqual(drift['current_markers'][0]['comparison'], 'matches-before')

        # Unavailable marker directory: fail-closed, never claim checked state.
        module_dir.rename(self.data / 'adb/modules/alpha-unavailable-fixture')
        missing = am.journals(self.context, ident)['journal']
        self.assertIs(missing['current_markers_verified'], False)
        self.assertEqual(missing['current_unavailable'], 1)
        self.assertTrue(missing['requires_review'])

        # Inspection has not modified journal bytes or timestamps.
        self.assertEqual((journal_path.read_bytes(), journal_path.stat().st_mtime_ns), journal_before)

    def test_journal_rejects_impossible_step_transitions(self):
        result = self.apply()
        file = self.data / result['journal']['path'].lstrip('/')
        original = json.loads(file.read_text())
        current_step = original['plan']['changes'][0]
        scenarios = (
            {'next': current_step},
            {'status': 'prepared'},
            {'status': 'applying', 'next': current_step},
        )
        for changes in scenarios:
            with self.subTest(changes=changes):
                journal = json.loads(json.dumps(original))
                journal.update(changes)
                file.write_text(json.dumps(journal))
                ident = result['journal']['path'].rsplit('/', 1)[-1][:-5]
                self.assertEqual(am.journals(self.context, ident)['journal']['integrity'], 'invalid')


        checkpoint = json.loads(json.dumps(original))
        checkpoint['status'] = 'applying'
        file.write_text(json.dumps(checkpoint))
        ident = result['journal']['path'].rsplit('/', 1)[-1][:-5]
        inspected = am.journals(self.context, ident)['journal']
        self.assertEqual(inspected['integrity'], 'self-consistent')
        self.assertTrue(inspected['requires_review'])
        no_step = json.loads(json.dumps(checkpoint))
        no_step['completed'] = []
        file.write_text(json.dumps(no_step))
        self.assertEqual(am.journals(self.context, ident)['journal']['integrity'], 'invalid')


    def test_journals_cli_json_contract(self):
        self.apply()
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            code = am.main(['--fixture', str(self.root), 'journals'])
        self.assertEqual(code, 0)
        payload = json.loads(capture.getvalue())
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['operation'], 'journals')
        self.assertEqual(payload['journals'][0]['integrity'], 'self-consistent')


    def test_partial_journal_shows_current_markers_without_replaying(self):
        self.module('bravo')
        original = am._change_marker
        count = [0]
        def fail_second(*args):
            count[0] += 1
            if count[0] == 2:
                raise OSError('injected I/O failure')
            return original(*args)
        with mock.patch.object(am, '_change_marker', side_effect=fail_second):
            error = self.assert_error('MODULE_TRANSACTION_INCOMPLETE', self.apply, 'disable-all', None)
        ident = error.details['journal'].rsplit('/', 1)[-1][:-5]
        detail = am.journals(self.context, ident)['journal']
        self.assertEqual((detail['status'], detail['recorded_completed_steps'], detail['planned_steps']),
                         ('partial-or-uncertain', 1, 2))
        self.assertTrue(detail['requires_review'])
        self.assertEqual(detail['current_matches_desired'], 1)
        self.assertEqual([item['comparison'] for item in detail['current_markers']],
                         ['matches-desired', 'matches-before'])
        self.assertFalse((self.data / 'adb/modules/bravo/disable').exists())

    def test_two_journals_partial_then_completed_read_without_replay(self):
        self.module('bravo')
        original = am._change_marker
        calls = [0]

        def fail_second(*args):
            calls[0] += 1
            if calls[0] == 2:
                raise OSError('injected second marker failure')
            return original(*args)

        with mock.patch.object(am, '_change_marker', side_effect=fail_second):
            error = self.assert_error('MODULE_TRANSACTION_INCOMPLETE',
                                      self.apply, 'disable-all', None)
        partial_id = error.details['journal'].rsplit('/', 1)[-1][:-5]
        self.assertTrue((self.data / 'adb/modules/alpha/disable').exists())
        self.assertFalse((self.data / 'adb/modules/bravo/disable').exists())

        completed = self.apply('disable', 'bravo')
        applied_id = completed['journal']['path'].rsplit('/', 1)[-1][:-5]
        self.assertNotEqual(partial_id, applied_id)
        self.assertTrue((self.data / 'adb/modules/bravo/disable').exists())
        sentinel = self.sd / 'no-write-sentinel'
        sentinel.write_bytes(b'journal reader must leave external storage unchanged')

        def snapshot(root):
            return {str(p.relative_to(root)): (
                p.lstat().st_ino, p.lstat().st_size, p.lstat().st_mtime_ns,
                hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
                for p in root.rglob('*')}

        before_data, before_sd = snapshot(self.data), snapshot(self.sd)
        with (mock.patch.object(am, '_change_marker', side_effect=AssertionError('marker replay')),
              mock.patch.object(am, '_journal_open', side_effect=AssertionError('journal creation')),
              mock.patch.object(am, '_journal_write', side_effect=AssertionError('journal write'))):
            listing = am.journals(self.context)['journals']
            partial = am.journals(self.context, partial_id)['journal']
            applied = am.journals(self.context, applied_id)['journal']

        self.assertEqual([row['file'] for row in listing],
                         sorted([partial_id + '.json', applied_id + '.json']))
        self.assertEqual({row['transaction'] for row in listing}, {partial_id, applied_id})
        self.assertEqual({row['status'] for row in listing}, {'partial-or-uncertain', 'applied'})
        self.assertTrue(all(row['integrity'] == 'self-consistent' for row in listing))
        self.assertEqual((partial['status'], partial['recorded_completed_steps'],
                          partial['planned_steps']), ('partial-or-uncertain', 1, 2))
        self.assertTrue(partial['requires_review'])
        self.assertEqual(partial['current_matches_desired'], 2)
        self.assertEqual([row['comparison'] for row in partial['current_markers']],
                         ['matches-desired', 'matches-desired'])
        self.assertEqual((applied['status'], applied['recorded_completed_steps'],
                          applied['planned_steps'], applied['current_matches_desired']),
                         ('applied', 1, 1, 1))
        self.assertFalse(applied['requires_review'])
        self.assertEqual(applied['current_markers'][0]['comparison'], 'matches-desired')
        self.assertEqual(snapshot(self.data), before_data)
        self.assertEqual(snapshot(self.sd), before_sd)

    def test_journal_corruption_and_symlinks_are_reported_not_followed(self):
        self.apply()
        folder = self.data / 'adb/a22x-recovery-module-rescue'
        sentinel = self.sd / 'do-not-read'
        sentinel.write_text('private')
        (folder / ('a' * 32 + '.json')).symlink_to(sentinel)
        (folder / ('b' * 32 + '.json')).write_text('{"schema":"wrong"}')
        (folder / '.tmp-leftover').write_text('incomplete')
        rows = am.journals(self.context)['journals']
        self.assertEqual(len(rows), 4)
        self.assertEqual(sum(row['integrity'] == 'invalid' for row in rows), 3)
        self.assertTrue(all(row['current_markers_verified'] is False for row in rows))
        self.assertEqual(sentinel.read_text(), 'private')
        self.assertEqual(am.journals(self.context, 'a' * 32)['journal']['integrity'], 'invalid')
        self.assert_error('MODULE_JOURNAL_ID_INVALID', am.journals, self.context, '../escape')
        self.assert_error('MODULE_JOURNAL_NOT_FOUND', am.journals, self.context, 'c' * 32)

    def test_journal_requires_authenticated_mount_and_private_directory(self):
        self.assertEqual(am.journals(self.context)['journals'], [])
        self.config['volumes'][0]['mounted'] = False
        self.write_config()
        self.assert_error('MODULE_AUTH_REQUIRED', am.journals, self.context)
        self.config['volumes'][0]['mounted'] = True
        self.write_config()
        folder = self.data / 'adb/a22x-recovery-module-rescue'
        folder.mkdir()
        folder.chmod(0o755)
        self.assert_error('MODULE_JOURNAL_UNSAFE', am.journals, self.context)


    def test_cpio_duplicate_native_asset_rejected(self):
        # Build exact newc records locally to keep duplicate names in one archive.
        def entry(name, data):
            fields = [1, 0o100644, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name) + 1, 0]
            raw = b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + name.encode() + b'\0'
            raw += b'\0' * (-len(raw) % 4)
            raw += data
            return raw + b'\0' * (-len(raw) % 4)
        archive = entry('init', b'first') + entry('init', b'second') + entry('TRAILER!!!', b'')
        self.assert_error('BOOT_ROOT_UNKNOWN', am.strict_cpio, archive)

    def test_real_boot_inspection_binds_embedded_native_assets(self):
        import test_bootimage as tb
        native = b'bounded fixture-native executable'
        init = b'bounded fixture-init executable'
        image = tb.boot(tb.kernel('4.14.186-27218697'), tb.ramdisk(
            {'ro.product.bootimage.device': 'a22x', 'ro.product.bootimage.model': 'SM-A226B'},
            {'.backup/.magisk': b'KEEPVERITY=true\n', 'init': init,
             'overlay.d/sbin/magisk.xz': lzma.compress(native)}),
            tb.dt_table(tb.fdt('MT6833', ['mediatek,MT6833'])))
        (self.root / 'boot.img').write_bytes(image)
        (self.root / 'install-fixture.json').write_text(json.dumps({
            'schema': 'a22x.install.fixture.v1', 'device': {'model': 'SM-A226B', 'identity': 'fixture:modules'},
            'targets': {'boot': {'path': 'boot.img', 'size_bytes': len(image)}}}))
        result = self.real_boot_identity(self.context)
        self.assertEqual(result['root'], 'magisk')
        self.assertEqual(result['sha256'], hashlib.sha256(image).hexdigest())
        self.assertEqual(result['magisk_sha256'], hashlib.sha256(native).hexdigest())
        self.assertEqual(result['init_sha256'], hashlib.sha256(init).hexdigest())


if __name__ == '__main__':
    unittest.main()
