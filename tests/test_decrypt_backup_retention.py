"""Real file/fsync/hash fixtures for cache admission and versioned EFS retention."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import android_decrypt as ad
import decrypt_prepare as prep
import filesystem as fs


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.parent = self.base / 'managed-v1'
        self.parent.mkdir(mode=0o700)
        self.store = prep.BackupRetention(self.parent, owner=os.getuid())

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self, boot=None):
        boot = boot or str(uuid.uuid4())
        path = self.parent / (boot + '.img')
        data = b'public fixture\x00' * (prep.BACKUP_BYTES // 15 + 1)
        data = data[:prep.BACKUP_BYTES]
        with path.open('xb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        path.chmod(0o400)
        digest = hashlib.sha256(data).hexdigest()
        receipt = {'schema': 1, 'status': 'CURRENT_EFS_FULL_BACKUP_FSYNC_AND_REREAD_PASS',
            'backup_boot_id': boot, 'userdata_epoch': 'POST_RESET03',
            'source_path': '/dev/mmcblk0p2', 'source_major': 179, 'source_minor': 2,
            'size_bytes': prep.BACKUP_BYTES, 'source_sha256': digest, 'backup_sha256': digest,
            'backup_fsynced': True, 'independent_reread_match': True, 'backup_mode': 0o400,
            'automatic_restore_authorized': False,
            'backup_relative': str(prep.MANAGED_RELATIVE / (boot + '.img'))}
        prep.write_private(self.parent / (boot + '.json'), receipt)
        prep.sync_directory(self.parent)
        return boot, receipt

    def add(self):
        boot, receipt = self.snapshot(); self.store.commit(boot, receipt); return boot

    def test_three_verified_snapshots_keep_newest_two_and_legacy_untouched(self):
        legacy = self.base / (str(uuid.uuid4()) + '.img'); legacy.write_bytes(b'legacy')
        first, second, third = self.add(), self.add(), self.add()
        self.assertEqual([e['boot_id'] for e in self.store.load()['entries']], [second, third])
        self.assertFalse((self.parent / (first + '.img')).exists())
        self.assertFalse((self.parent / (first + '.json')).exists())
        self.assertEqual(legacy.read_bytes(), b'legacy')

    def test_failed_new_receipt_reread_never_prunes_old(self):
        first, second = self.add(), self.add()
        boot, receipt = self.snapshot()
        (self.parent / (boot + '.json')).write_text('{}')
        with self.assertRaises(ValueError): self.store.commit(boot, receipt)
        self.assertTrue((self.parent / (first + '.img')).exists())
        self.assertTrue((self.parent / (second + '.img')).exists())

    def test_interrupted_image_or_foreign_file_is_not_adopted(self):
        for name in (str(uuid.uuid4()) + '.partial', 'foreign'):
            path = self.parent / name; path.write_bytes(b'untouched')
            with self.assertRaises(ValueError): self.store.load()
            self.assertEqual(path.read_bytes(), b'untouched'); path.unlink()

    def test_symlink_hardlink_wrong_mode_and_hash_are_rejected(self):
        boot = self.add(); image = self.parent / (boot + '.img')
        original = image.read_bytes(); image.unlink(); target = self.base / 'target'; target.write_bytes(original)
        image.symlink_to(target)
        with self.assertRaises(OSError): self.store.load()
        image.unlink(); os.link(target, image); image.chmod(0o400)
        with self.assertRaises(ValueError): self.store.load()
        image.unlink(); image.write_bytes(original); image.chmod(0o600)
        with self.assertRaises(ValueError): self.store.load()
        image.chmod(0o600)
        with image.open('r+b') as f: f.write(b'changed')
        image.chmod(0o400)
        with self.assertRaises(ValueError): self.store.load()
        self.assertTrue(image.exists())

    def test_current_boot_cannot_be_added_again_or_pruned(self):
        boot = self.add()
        receipt = json.loads((self.parent / (boot + '.json')).read_text())
        with self.assertRaises(ValueError): self.store.commit(boot, receipt)
        self.assertTrue((self.parent / (boot + '.img')).exists())

    def test_interrupted_prune_is_explicit_and_never_deletes_unknown_remainder(self):
        first, second = self.add(), self.add(); boot, receipt = self.snapshot()
        original = Path.unlink
        def interrupt(path, *args, **kwargs):
            if path.name == first + '.json': raise OSError('synthetic interrupted delete')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'unlink', interrupt):
            with self.assertRaises(OSError): self.store.commit(boot, receipt)
        self.assertTrue((self.parent / (first + '.json')).exists())
        self.assertTrue((self.parent / (second + '.img')).exists())
        self.assertTrue((self.parent / (boot + '.img')).exists())
        with self.assertRaisesRegex(ValueError, 'manual review'): self.store.load()
        self.assertTrue((self.parent / (first + '.json')).exists())

    def test_new_receipt_durable_before_first_retirement(self):
        first, _ = self.add(), self.add(); boot, receipt = self.snapshot()
        original = Path.unlink
        def observe(path, *args, **kwargs):
            if path.name == first + '.img':
                ledger = json.loads((self.parent / prep.LEDGER_NAME).read_text())
                self.assertEqual(ledger['entries'][-1]['boot_id'], boot)
                self.assertEqual(ledger['pending_prune']['boot_id'], first)
                self.store.pair(ledger['entries'][-1])
            return original(path, *args, **kwargs)
        with patch.object(Path, 'unlink', observe): self.store.commit(boot, receipt)

    def test_wrong_owner_or_malformed_ledger_preserves_files(self):
        wrong = prep.BackupRetention
        with self.assertRaises(ValueError): wrong(self.parent, owner=os.getuid() + 1)
        self.add(); path = self.parent / prep.LEDGER_NAME; path.write_text('{broken')
        before = {p.name: p.read_bytes() for p in self.parent.iterdir()}
        with self.assertRaises(ValueError): self.store.load()
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.parent.iterdir()})


class CacheFixture:
    def __init__(self, path):
        self.path, self.boot_id, self.mounted, self.calls = path, str(uuid.uuid4()), False, []
    def volume(self, ident):
        return {'mounted': self.mounted, 'volume_token': 'cache-token', 'write_supported': True,
                'mountpoint': str(self.path), 'read_only': True, 'mount_owner': 'filesystem'}
    def mount(self, ident, mode, confirmed, token):
        assert ident == 'cache' and mode == 'ro' and not confirmed and token == 'cache-token'
        self.calls.append('mount-ro'); self.mounted = True
    def unmount(self, ident):
        assert ident == 'cache'; self.calls.append('unmount'); self.mounted = False


class AdmissionTests(unittest.TestCase):
    def test_capacity_failure_precedes_runtime_state_and_tee_and_keeps_reason(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); context = CacheFixture(base / 'cache'); context.path.mkdir()
            state = base / 'run' / 'android-decrypt'
            original = prep.private_directory
            # Real path/mode validation with this unprivileged fixture's owner.
            shape = lambda path, owner=0, **kw: original(path, os.getuid(), **kw)
            space = SimpleNamespace(f_bavail=11919360, f_frsize=1)
            with patch.object(prep, 'STATE_DIR', state), patch.object(prep, 'private_directory', shape), \
                 patch.object(prep.os, 'statvfs', return_value=space), patch.object(prep, 'runtime_bundle') as runtime, \
                 patch.object(prep, 'bootstrap') as bootstrap:
                with self.assertRaises(Exception) as caught:
                    profile = json.loads((Path(__file__).resolve().parents[1]/'profiles/android-decrypt/samsung-a226b-a13.json').read_text())
                    prep.prepare(context, {}, profile)
                self.assertEqual(caught.exception.code, 'DECRYPT_BACKUP_SPACE')
                runtime.assert_not_called(); bootstrap.assert_not_called()
            self.assertEqual(context.calls, ['mount-ro', 'unmount'])
            self.assertFalse(state.exists())
            advisory = json.loads((state.parent / 'android-decrypt-preflight.json').read_text())
            self.assertEqual(advisory['boot_id'], context.boot_id)
            self.assertEqual(advisory['code'], 'DECRYPT_BACKUP_SPACE')
            with patch.object(prep.os, 'statvfs', return_value=SimpleNamespace(f_bavail=12*1024*1024, f_frsize=1)):
                prep.cache_preflight(context)  # Exact threshold remains admitted.
            self.assertFalse(context.mounted)

    def test_storage_race_before_watchdog_leaves_no_consumed_run(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            state, runtime = base / 'run' / 'android-decrypt', base / 'runtime'
            runtime.mkdir()
            context = SimpleNamespace(boot_id=str(uuid.uuid4()))
            profile = json.loads((Path(__file__).resolve().parents[1] / 'profiles/android-decrypt/samsung-a226b-a13.json').read_text())

            def blocked(_context, _profile, run_dir):
                prep.write_private(run_dir / 'tee-consumed.json', {'boot_id': context.boot_id})
                fs.fail('DECRYPT_STORAGE_BUSY', 'Storage appeared before watchdog dispatch')

            original = Path.lstat
            def state_owner(path):
                info = original(path)
                if path == state:
                    return SimpleNamespace(st_mode=info.st_mode, st_uid=0)
                return info

            with patch.object(prep, 'STATE_DIR', state), patch.object(prep, 'cache_preflight'), \
                 patch.object(prep, 'record_preflight') as advisory, patch.object(prep, 'runtime_bundle', return_value=runtime), \
                 patch.object(prep, 'collect_layout'), patch.object(prep, 'bootstrap', side_effect=blocked), \
                 patch.object(prep, 'bootstrap_unstarted', return_value=True), patch.object(Path, 'lstat', state_owner):
                with self.assertRaises(fs.FilesystemError) as raised:
                    prep.prepare(context, {}, profile)
            self.assertEqual(raised.exception.code, 'DECRYPT_STORAGE_BUSY')
            self.assertEqual(list(state.iterdir()), [])
            self.assertFalse(runtime.exists())
            advisory.assert_called_with(context, 'DECRYPT_STORAGE_BUSY')

    def test_current_boot_consumed_marker_without_session_requires_reboot(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp); run = state / 'gui0123456789abcd'; run.mkdir(mode=0o700)
            boot = str(uuid.uuid4()); context = SimpleNamespace(boot_id=boot, mode='device')
            prep.write_private(run / 'tee-consumed.json', {'boot_id': boot})
            prep.write_private(run / 'preparation-failure.json', {'boot_id': boot, 'code': 'DECRYPT_BACKUP_SPACE'})
            # Fixture is uid1001 on Arch; retention tests independently exercise actual UID/mode rejection.
            def read(path, **kwargs): return json.loads(Path(path).read_text())
            with patch.object(ad, 'STATE_DIR', state), patch.object(ad, 'regular_json', read), \
                 patch.object(ad.os, 'getuid', return_value=os.getuid()):
                # Marker directory owner is checked; inject only uid for that actual stat result.
                original = Path.lstat
                def owner(path):
                    info = original(path)
                    if path == run:
                        return SimpleNamespace(st_mode=info.st_mode, st_uid=0)
                    return info
                with patch.object(Path, 'lstat', owner): result = ad.terminal_status(context)
            self.assertIn('restart recovery', result['unlock_reason'])
            self.assertIn('cache space', result['unlock_reason'])
            self.assertFalse((state / 'session.json').exists())


class BootstrapStorageTests(unittest.TestCase):
    def setUp(self):
        self.cache = self.volume('cache', False, True, 10)
        self.card = self.volume('sdcard-p1', True, False, 20)
        self.current = {v['id']: v for v in (self.cache, self.card)}
        self.calls = []
        self.busy = None

    @staticmethod
    def volume(ident, external, read_only, mount_id):
        return {'id': ident, 'external': external, 'read_only': read_only, 'mount_id': mount_id,
                'device': f'179:{mount_id}', 'mountpoint': f'/mnt/volumes/{ident}', 'mounted': True,
                'mount_owner': 'filesystem', 'volume_token': ident + '-token'}

    def volumes(self):
        return list(self.current.values())

    def mount_table(self):
        return [{'mount_id': v['mount_id'], 'devno': v['device'], 'mountpoint': v['mountpoint'], 'root': '/'}
                for v in self.current.values() if v['mounted']]

    def unmount(self, ident, token):
        self.assertEqual(token, self.current[ident]['volume_token'])
        self.calls.append(('unmount', ident))
        if ident == self.busy:
            fs.fail('UNMOUNT_FAILED', 'EBUSY')
        self.current[ident]['mounted'] = False

    def mount(self, ident, mode, confirmed, token):
        self.assertEqual(token, self.current[ident]['volume_token'])
        self.assertEqual(confirmed, mode == 'rw')
        self.calls.append((mode, ident))
        self.current[ident].update(mounted=True, read_only=mode == 'ro')
        return {'volume': self.current[ident]}

    def nested_mounts(self, volume, path):
        return []

    def test_cache_and_external_storage_are_released_and_remounted_in_previous_modes(self):
        with patch.object(prep, 'bootstrap_mounts', self.mount_table):
            with prep.temporary_bootstrap_mounts(self) as warnings:
                self.assertEqual(self.mount_table(), [])
            self.assertEqual(warnings, [])
        self.assertEqual(self.calls, [('unmount', 'cache'), ('unmount', 'sdcard-p1'),
                                      ('rw', 'sdcard-p1'), ('ro', 'cache')])

    def test_mounted_system_is_released_before_profile_probe_and_restored_read_only(self):
        system = self.volume('super-system', False, True, 30)
        system.update(container='super', mountable=True)
        self.current[system['id']] = system
        userdata = {'id': 'userdata', 'decrypt_supported': True, 'decrypt_state': 'locked'}
        profile = {'profile_id': 'evolutionx-a226b-a16'}

        def probe(context):
            self.assertIs(context, self)
            self.assertEqual(self.mount_table(), [])
            return profile

        with patch.object(prep, 'bootstrap_mounts', self.mount_table), \
             patch.object(ad, 'select_current_profile', side_effect=probe), \
             patch.object(ad, 'discover_credential', return_value={'credential_type': 'password'}) as discover:
            result = ad.prepare_android(self, userdata)
        discover.assert_called_once_with(self, userdata, profile)
        self.assertEqual(result, {'credential_type': 'password'})
        self.assertTrue(system['mounted'] and system['read_only'])
        self.assertEqual(self.calls[2:4], [('unmount', 'super-system'), ('ro', 'super-system')])

    def test_busy_volume_leaves_tee_unstarted_and_restores_an_earlier_unmount(self):
        self.busy = 'sdcard-p1'
        with patch.object(prep, 'bootstrap_mounts', self.mount_table), patch.object(prep, 'bootstrap_unstarted', return_value=True):
            with self.assertRaises(fs.FilesystemError) as raised:
                with prep.temporary_bootstrap_mounts(self):
                    self.fail('Unexpected preparation entry')
        self.assertEqual(raised.exception.code, 'DECRYPT_STORAGE_BUSY')
        self.assertEqual(raised.exception.details['volume'], 'sdcard-p1')
        self.assertTrue(all(v['mounted'] for v in self.current.values()))
        self.assertFalse(raised.exception.details['authentication_performed'])

    def test_unknown_mount_is_refused_before_changing_any_mount(self):
        self.card['mount_owner'] = 'unmanaged'
        with patch.object(prep, 'bootstrap_mounts', self.mount_table):
            with self.assertRaises(fs.FilesystemError) as raised:
                with prep.temporary_bootstrap_mounts(self):
                    self.fail('Unexpected preparation entry')
        self.assertEqual(raised.exception.code, 'DECRYPT_STORAGE_BUSY')
        self.assertEqual(self.calls, [])

    def test_unqualified_logical_mount_stays_intact(self):
        system = self.volume('super-system', False, True, 30)
        system.update(container='super', mountable=False)
        self.current[system['id']] = system
        with patch.object(prep, 'bootstrap_mounts', self.mount_table):
            with self.assertRaises(fs.FilesystemError) as raised:
                with prep.temporary_bootstrap_mounts(self):
                    self.fail('Unexpected preparation entry')
        self.assertEqual(raised.exception.code, 'DECRYPT_STORAGE_BUSY')
        self.assertEqual(self.calls, [])

    def test_uncertain_native_exit_leaves_storage_offline_for_the_watchdog(self):
        with patch.object(prep, 'bootstrap_mounts', self.mount_table), patch.object(prep, 'bootstrap_unstarted', return_value=False):
            with self.assertRaises(TimeoutError):
                with prep.temporary_bootstrap_mounts(self):
                    raise TimeoutError
        self.assertEqual(self.calls, [('unmount', 'cache'), ('unmount', 'sdcard-p1')])


class NativeReceiptCompatibilityTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('A22X_NATIVE_RUNTIME_ARCHIVE'), 'Set exact native runtime archive for compatibility test')
    def test_unchanged_actual_consumer_accepts_nested_managed_receipt(self):
        import tarfile
        archive = Path(os.environ['A22X_NATIVE_RUNTIME_ARCHIVE'])
        from android_profiles import BUNDLE_SHA
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), BUNDLE_SHA)
        with tarfile.open(archive) as tar:
            source = tar.extractfile('controller/g2/native_efs_policy.py').read()
        self.assertEqual(hashlib.sha256(source).hexdigest(), 'a84e57b243eda505e1640013424f5c6dc4944c502b965415db4ec8dd8ea9d293')
        namespace = {}; exec(compile(source, 'qualified-native-efs-policy', 'exec'), namespace)
        boot, run, digest, manifest = str(uuid.uuid4()), 'gui0123456789abcd', '1' * 64, '2' * 64
        receipt = {'schema': 1, 'status': 'CURRENT_EFS_FULL_BACKUP_FSYNC_AND_REREAD_PASS',
            'backup_boot_id': boot, 'userdata_epoch': 'POST_RESET03', 'source_path': '/dev/mmcblk0p2',
            'source_major': 179, 'source_minor': 2, 'size_bytes': prep.BACKUP_BYTES,
            'source_sha256': digest, 'backup_sha256': digest, 'backup_fsynced': True,
            'independent_reread_match': True, 'backup_mode': 0o400, 'automatic_restore_authorized': False,
            'backup_relative': str(prep.MANAGED_RELATIVE / (boot + '.img'))}
        policy = {'mode': 'NATIVE_EFS_PERSISTENCE', 'journal_policy': 'NATIVE_EXT4_RECOVERY', 'profile_id':'samsung-a226b-a13',
            'normal_restore_provenance': False, 'nonce': '3' * 64, 'boot_id': boot, 'run_id': run,
            'kernel_build': 145, 'root_manifest_sha256': manifest, 'device_cid': '4' * 32}
        layout = {'physical': {'efs': {'node': '/dev/mmcblk0p2', 'device': '179:2', 'sectors': 16384}}}
        self.assertEqual(namespace['validate_receipt'](policy, receipt, boot, run, manifest, layout), digest)
        # The installed consumer binds backup epoch to the selected profile.
        # A nested filename never bypasses this qualified content check.
        missing_profile = dict(policy); missing_profile.pop('profile_id')
        with self.assertRaises(namespace['PolicyError']):
            namespace['validate_receipt'](missing_profile, receipt, boot, run, manifest, layout)
        evolution = dict(policy, profile_id='evolutionx-a226b-a16')
        with self.assertRaises(namespace['PolicyError']):
            namespace['validate_receipt'](evolution, receipt, boot, run, manifest, layout)
        evo_receipt = dict(receipt, userdata_epoch='EVOLUTION16_PASSWORD_20261116')
        self.assertEqual(namespace['validate_receipt'](evolution, evo_receipt, boot, run, manifest, layout), digest)

if __name__ == '__main__': unittest.main()

