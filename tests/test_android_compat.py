"""Offline evidence tests: no fake qualified transition and no hardware access."""
import contextlib
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import android_compat as ac
import test_lp_metadata as tl


def ext4(size=8192):
    data = bytearray(size)
    data[1080:1082] = b'\x53\xef'
    return bytes(data)


class Analyzer(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-compat-'))
        self.addCleanup(shutil.rmtree, self.root, True)
        for folder in ('targets', 'data', 'current', 'target-snapshot', 'rollback'):
            (self.root / folder).mkdir()
        tl.make_super(self.root / 'targets/super')
        (self.root / 'targets/boot').write_bytes(bytes(1 << 20))
        (self.root / 'install-fixture.json').write_text(json.dumps({
            'schema': 'a22x.install.fixture.v1',
            'device': {'model': 'SM-A226B', 'identity': 'fixture:compat'},
            'targets': {'super': {'path': 'targets/super', 'size_bytes': 64 << 20},
                        'boot': {'path': 'targets/boot', 'size_bytes': 1 << 20}}}))
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({
            'schema': 'a22x.filesystem.fixture.v1',
            'volumes': [{'id': 'userdata', 'path': 'data', 'fs_type': 'ext4',
                         'mounted': True, 'read_only': False}]}))
        self.package = self.root / 'data/target.zip'
        self.make_zip()
        self.context = ac.install.FixtureContext(self.root)
        self.token = self.context.fs.volume('userdata')['volume_token']

    def make_zip(self, *, sdk=36, patch='2026-11-05', images=None, extra=None):
        with zipfile.ZipFile(self.package, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, data in (images or {'system.img': ext4()}).items():
                archive.writestr(name, data)
            archive.writestr('build.prop',
                             'ro.build.id=TEST\nro.product.device=a22x\n'
                             'ro.build.version.sdk=' + str(sdk) + '\n'
                             'ro.build.version.security_patch=' + patch + '\n')
            for name, data in (extra or {}).items():
                archive.writestr(name, data)

    def inspect(self, **kwargs):
        return ac.inspect(self.context, 'userdata', self.token, '/target.zip', **kwargs)

    def source(self, sdk=36, patch='2026-10-05', fstab=None):
        current = self.root / 'current'
        (current / 'build.prop').write_text('ro.build.version.sdk=' + str(sdk) + '\n'
                                            'ro.build.version.security_patch=' + patch + '\n')
        if fstab:
            (current / 'fstab.mt6833').write_text(fstab)
        return ac.collect_current(current)

    def checks(self, report):
        return {item['id']: item for item in report['checks']}

    def test_manifest_is_deterministic_and_covers_complete_images(self):
        one, two = self.inspect(), self.inspect()
        self.assertEqual(one, two)
        self.assertEqual(one['manifest_sha256'], ac.digest({k: v for k, v in one.items()
                                                           if k != 'manifest_sha256'}))
        self.assertEqual(one['write_set'][0]['image_sha256'], hashlib.sha256(ext4()).hexdigest())
        self.assertEqual(one['write_set'][0]['image_bytes'], 8192)
        self.assertEqual(one['write_set'][0]['target'], 'super/system')
        self.assertEqual(one['status'], 'unknown')
        self.assertFalse(one['preserve_allowed'])
        self.assertFalse(one['qualification']['hardware_qualified'])
        self.assertIsNotNone(one['geometry']['logical_metadata'])

    def test_no_mount_auth_format_or_writer_called(self):
        # Geometry inspection takes a shared lease. Establish its lock file
        # before comparing the fixture's volume and partition contents.
        with self.context.fs.operation_lock():
            pass
        with contextlib.ExitStack() as stack:
            for obj, name in ((ac.flash, 'write'), (ac.flash, 'save_rollback'),
                              (ac.install.FixtureContext, 'reset_android'),
                              (ac.fs.FixtureContext, 'mount'), (ac.fs.FixtureContext, 'unmount')):
                stack.enter_context(mock.patch.object(obj, name, side_effect=AssertionError(name + ' called')))
            before = sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob('*'))
            self.inspect()
            self.assertEqual(before, sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob('*')))
        self.assertFalse((self.root / 'android-reset.json').exists())

    def test_missing_exact_target_profile_never_becomes_supported(self):
        report = self.inspect(current=self.source())
        self.assertEqual(self.checks(report)['TARGET_PROFILE']['status'], 'unknown')
        self.assertEqual(self.checks(report)['QUALIFIED_TRANSITION']['status'], 'unknown')
        self.assertFalse(report['preserve_allowed'])

    def test_known_detached_jar_pair_does_not_prove_image_binding(self):
        current = self.root / 'current'
        (current / 'framework').mkdir()
        (current / 'framework/services.jar').write_bytes(b'services')
        (current / 'framework/framework.jar').write_bytes(b'framework')
        hashes = (hashlib.sha256(b'services').hexdigest(), hashlib.sha256(b'framework').hexdigest())
        with mock.patch.dict(ac.android_profiles.FRAMEWORK_PINS, {'test-exact': hashes}):
            report = self.inspect(current=ac.collect_current(current))
        self.assertIn('test-exact', self.checks(report)['SOURCE_PROFILE']['reason'])
        self.assertEqual(self.checks(report)['SOURCE_PROFILE']['status'], 'unknown')
        self.assertFalse(report['preserve_allowed'])

    def test_same_size_changed_source_and_restored_mtime_requires_new_preview(self):
        first = self.inspect()
        old = self.package.stat()
        data = bytearray(self.package.read_bytes())
        data[-1] ^= 1  # archive comment length/EOCD change still changes package identity
        self.package.write_bytes(data)
        os.utime(self.package, ns=(old.st_atime_ns, old.st_mtime_ns))
        with self.assertRaises((ac.fs.FilesystemError, zipfile.BadZipFile)):
            ac.revalidate(self.context, 'userdata', self.token, '/target.zip', first['manifest_sha256'])

    def test_changed_valid_package_requires_new_preview(self):
        first = self.inspect()
        self.make_zip(sdk=35)
        with self.assertRaises(ac.fs.FilesystemError) as caught:
            ac.revalidate(self.context, 'userdata', self.token, '/target.zip', first['manifest_sha256'])
        self.assertEqual(caught.exception.code, 'PLAN_CHANGED')

    def test_single_explicit_logical_partitions_keep_their_zip_targets(self):
        for label in ('system_ext', 'system_dlkm'):
            for prefix in ('', 'nested/'):
                with self.subTest(label=label, prefix=prefix):
                    self.make_zip(images={prefix + label + '.img': ext4()})
                    report = self.inspect()
                    self.assertEqual(report['write_set'][0]['partition'], label)
                    self.assertEqual(report['write_set'][0]['target'], 'super/' + label)
                    self.assertIn('GEOMETRY:super/' + label, self.checks(report))
                    self.assertIn('ROLLBACK:super/' + label, self.checks(report))
                    self.assertFalse(report['preserve_allowed'])

    def test_distribution_named_single_images_map_to_system(self):
        for filename in ('lineage-23.0-arm64.img', 'aosp_arm64-ab.img',
                         'system-20261117-arm64.img', 'gsi.img'):
            with self.subTest(filename=filename):
                self.make_zip(images={'nested/' + filename: ext4()})
                report = self.inspect()
                self.assertEqual(report['write_set'][0]['target'], 'super/system')
                raw = self.root / filename
                raw.write_bytes(ext4())
                standalone = ac.analyze_file(raw)
                self.assertEqual(standalone['write_set'][0]['target'], 'super/system')
                self.assertFalse(report['preserve_allowed'])
                self.assertFalse(standalone['preserve_allowed'])

    def test_standalone_refused_and_unknown_labels_are_not_gsi(self):
        for label in ('prism', 'optics', 'radio', 'arbitrary', 'systematic',
                      'system_ext_a', 'system_dlkm_b'):
            with self.subTest(label=label):
                raw = self.root / (label + '.img')
                raw.write_bytes(ext4())
                report = ac.analyze_file(raw)
                self.assertEqual(report['write_set'][0]['partition'], label)
                self.assertEqual(report['write_set'][0]['target'], label)
                self.assertEqual(report['status'], 'incompatible')
                self.assertEqual(self.checks(report)['PROTECTED_TARGET:' + label]['status'],
                                 'incompatible')
                self.assertFalse(report['preserve_allowed'])

    def test_single_zip_refused_and_unknown_labels_are_not_gsi(self):
        for label in ('prism', 'optics', 'radio', 'arbitrary', 'systematic',
                      'system_ext_a', 'system_dlkm_b'):
            with self.subTest(label=label):
                self.make_zip(images={label + '.img': ext4()})
                report = self.inspect()
                self.assertEqual(report['write_set'][0]['partition'], label)
                self.assertEqual(report['write_set'][0]['target'], label)
                self.assertEqual(report['status'], 'incompatible')
                self.assertEqual(self.checks(report)['PROTECTED_TARGET:' + label]['status'],
                                 'incompatible')
                self.assertFalse(report['preserve_allowed'])

    def test_protected_partition_is_reported_not_silently_skipped(self):
        self.make_zip(images={'userdata.img': ext4(), 'system.img': ext4()})
        report = self.inspect()
        self.assertEqual(report['status'], 'incompatible')
        self.assertIn('userdata', [w['target'] for w in report['write_set']])
        self.assertEqual(self.checks(report)['PROTECTED_TARGET:userdata']['status'], 'incompatible')

    def test_path_traversal_and_archive_symlinks_are_rejected(self):
        self.make_zip(extra={'../escape': b'x'})
        with self.assertRaises(ac.fs.FilesystemError) as caught:
            self.inspect()
        self.assertEqual(caught.exception.code, 'UNSAFE_PACKAGE_PATH')
        self.make_zip()
        with zipfile.ZipFile(self.package, 'a') as archive:
            info = zipfile.ZipInfo('link')
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, '../x')
        with self.assertRaises(ac.fs.FilesystemError) as caught:
            self.inspect()
        self.assertEqual(caught.exception.code, 'ZIP_SYMLINK')
        self.assertFalse((self.root / 'escape').exists())

    def test_duplicate_member_and_partition_names_refuse(self):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(self.package, 'a') as archive:
                archive.writestr('system.img', ext4())
        with self.assertRaises(ac.fs.FilesystemError) as caught:
            self.inspect()
        self.assertEqual(caught.exception.code, 'DUPLICATE_ZIP_MEMBER')
        self.make_zip(images={'system.img': ext4(), 'nested/system.img': ext4()})
        with self.assertRaises(ac.fs.FilesystemError) as caught:
            self.inspect()
        self.assertEqual(caught.exception.code, 'DUPLICATE_PARTITION')

    def test_sdk_and_patch_downgrades_are_incompatible(self):
        self.make_zip(sdk=35, patch='2026-09-05')
        report = self.inspect(current=self.source())
        self.assertEqual(self.checks(report)['ANDROID_DOWNGRADE']['status'], 'incompatible')
        self.assertEqual(self.checks(report)['SECURITY_PATCH']['status'], 'incompatible')

    def test_conflicting_ota_versions_are_rejected_without_side_effects(self):
        cases = (
            ('36', '2026-11-05', 'post-sdk-level=35\n', 'ro.build.version.sdk'),
            ('35', '2026-11-05', 'post-sdk-level=36\n', 'ro.build.version.sdk'),
            ('36', '2026-11-05', 'post-security-patch-level=2026-10-05\n',
             'ro.build.version.security_patch'),
            ('36', '2026-10-05', 'post-security-patch-level=2026-11-05\n',
             'ro.build.version.security_patch'),
        )
        for sdk, patch, metadata, primary in cases:
            with self.subTest(metadata=metadata, sdk=sdk, patch=patch):
                self.make_zip(sdk=sdk, patch=patch, extra={ac.METADATA_PATH: metadata})
                with contextlib.ExitStack() as stack:
                    for obj, name in ((ac.flash, 'write'), (ac.flash, 'save_rollback'),
                                      (ac.install.FixtureContext, 'reset_android'),
                                      (ac.fs.FixtureContext, 'mount'),
                                      (ac.fs.FixtureContext, 'unmount')):
                        stack.enter_context(mock.patch.object(
                            obj, name, side_effect=AssertionError(name + ' called')))
                    with self.assertRaises(ac.fs.FilesystemError) as caught:
                        self.inspect(current=self.source())
                self.assertEqual(caught.exception.code, 'AMBIGUOUS_METADATA')
                self.assertEqual(caught.exception.details['keys'],
                                 [primary, metadata.partition('=')[0]])

    def test_empty_version_alias_cannot_be_ignored(self):
        for sdk, patch, metadata in (
                ('36', '2026-11-05', 'post-sdk-level=\n'),
                ('', '2026-11-05', 'post-sdk-level=36\n'),
                ('36', '2026-11-05', 'post-security-patch-level=\n'),
                ('36', '', 'post-security-patch-level=2026-11-05\n')):
            with self.subTest(sdk=sdk, patch=patch, metadata=metadata):
                self.make_zip(sdk=sdk, patch=patch, extra={ac.METADATA_PATH: metadata})
                with self.assertRaises(ac.fs.FilesystemError) as caught:
                    self.inspect()
                self.assertEqual(caught.exception.code, 'AMBIGUOUS_METADATA')

    def test_agreeing_version_aliases_still_only_report_evidence(self):
        self.make_zip(extra={ac.METADATA_PATH:
                             'post-sdk-level=36\npost-security-patch-level=2026-11-05\n'})
        report = self.inspect(current=self.source())
        for ident in ('ANDROID_DOWNGRADE', 'SECURITY_PATCH'):
            self.assertEqual(self.checks(report)[ident]['status'], 'supported')
        self.assertEqual(report['status'], 'unknown')
        self.assertFalse(report['preserve_allowed'])
        self.assertFalse(report['qualification']['hardware_qualified'])

    def test_single_or_missing_version_aliases_keep_existing_semantics(self):
        cases = (
            ('build.prop', 'ro.build.version.sdk=36\n'
             'ro.build.version.security_patch=2026-11-05\n', 'supported'),
            (ac.METADATA_PATH, 'post-sdk-level=36\n'
             'post-security-patch-level=2026-11-05\n', 'supported'),
            ('build.prop', '', 'unknown'),
            ('build.prop', 'ro.build.version.sdk=\npost-sdk-level=\n'
             'ro.build.version.security_patch=\npost-security-patch-level=\n', 'unknown'),
        )
        for member, metadata, expected in cases:
            with self.subTest(member=member, metadata=metadata):
                with zipfile.ZipFile(self.package, 'w') as archive:
                    archive.writestr('system.img', ext4())
                    archive.writestr(member, metadata)
                report = self.inspect(current=self.source())
                for ident in ('ANDROID_DOWNGRADE', 'SECURITY_PATCH'):
                    self.assertEqual(self.checks(report)[ident]['status'], expected)
                self.assertEqual(report['status'], 'unknown')
                self.assertFalse(report['preserve_allowed'])

    def test_conflicting_source_snapshot_versions_are_rejected(self):
        for metadata in ('ro.build.version.sdk=36\npost-sdk-level=35\n',
                         'ro.build.version.security_patch=2026-11-05\n'
                         'post-security-patch-level=2026-10-05\n'):
            with self.subTest(metadata=metadata):
                (self.root / 'current/build.prop').write_text(metadata)
                with self.assertRaises(ac.fs.FilesystemError) as caught:
                    ac.collect_current(self.root / 'current')
                self.assertEqual(caught.exception.code, 'AMBIGUOUS_METADATA')

    def test_version_alias_conflict_across_target_snapshot_and_package_is_rejected(self):
        for primary, alias in (
                ('ro.build.version.sdk=36\n', 'post-sdk-level=35\n'),
                ('ro.build.version.security_patch=2026-11-05\n',
                 'post-security-patch-level=2026-10-05\n')):
            for package_value, snapshot_value in ((primary, alias), (alias, primary)):
                with self.subTest(package=package_value, snapshot=snapshot_value):
                    with zipfile.ZipFile(self.package, 'w') as archive:
                        archive.writestr('system.img', ext4())
                        archive.writestr(ac.METADATA_PATH, package_value)
                    (self.root / 'target-snapshot/build.prop').write_text(snapshot_value)
                    with self.assertRaises(ac.fs.FilesystemError) as caught:
                        ac.analyze_file(self.package, target_root=self.root / 'target-snapshot')
                    self.assertEqual(caught.exception.code, 'AMBIGUOUS_METADATA')

    def test_system_vendor_and_boot_patch_levels_remain_independent(self):
        current = self.root / 'current/build.prop'
        current.write_text('ro.build.version.sdk=36\n'
                           'ro.build.version.security_patch=2026-10-05\n'
                           'ro.vendor.build.version.security_patch=2026-09-05\n'
                           'ro.bootimage.build.version.security_patch=2026-08-05\n')
        self.make_zip(extra={ac.METADATA_PATH:
                             'post-sdk-level=36\npost-security-patch-level=2026-11-05\n'
                             'ro.vendor.build.version.security_patch=2026-09-05\n'
                             'ro.bootimage.build.version.security_patch=2026-08-05\n'})
        report = self.inspect(current=ac.collect_current(current.parent))
        for ident in ('SECURITY_PATCH', 'VENDOR_SECURITY_PATCH', 'BOOT_SECURITY_PATCH'):
            self.assertEqual(self.checks(report)[ident]['status'], 'supported')
        self.assertFalse(report['preserve_allowed'])

    def test_conflicting_version_alias_cli_uses_existing_policy_error_contract(self):
        self.make_zip(extra={ac.METADATA_PATH: 'post-sdk-level=35\n'})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = ac.main(['--fixture', str(self.root), 'inspect', '--volume', 'userdata',
                            '--volume-token', self.token, '--path', '/target.zip'])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertFalse(result['ok'])
        self.assertEqual(result['error']['code'], 'AMBIGUOUS_METADATA')
        self.assertEqual(result['error']['details']['keys'],
                         ['ro.build.version.sdk', 'post-sdk-level'])

    def test_fstab_format_change_blocks_but_inlinecrypt_flag_is_not_disk_format(self):
        template = '/dev/block/userdata /data f2fs {mount} fileencryption=aes-256-xts:aes-256-cts:v{version}\n'
        source = self.source(fstab=template.format(mount='inlinecrypt', version=2))
        self.make_zip(extra={'fstab.mt6833': template.format(mount='noatime', version=1)})
        report = self.inspect(current=source)
        self.assertEqual(self.checks(report)['FSTAB_FILEENCRYPTION']['status'], 'incompatible')
        self.make_zip(extra={'fstab.mt6833': template.format(mount='noatime', version=2)})
        report = self.inspect(current=source)
        self.assertEqual(self.checks(report)['FSTAB_FILEENCRYPTION']['status'], 'supported')
        self.assertEqual(self.checks(report)['FSTAB_METADATA_ENCRYPTION']['status'], 'unknown')

    def test_image_larger_than_partition_refuses_without_lp_resize(self):
        geometry = {'targets': [{'label': 'super/system', 'size_bytes': 4096}]}
        with ac.regular_at(self.package.parent, self.package.name) as fd:
            report = ac.analyze_fd(fd, self.package.name, geometry=geometry)
        self.assertEqual(self.checks(report)['GEOMETRY:super/system']['status'], 'incompatible')

    def test_large_partition_without_full_rollback_copy_remains_unknown(self):
        geometry = {'targets': [{'label': 'super/system', 'size_bytes': 128 << 20}]}
        with ac.regular_at(self.package.parent, self.package.name) as fd:
            report = ac.analyze_fd(fd, self.package.name, geometry=geometry)
        self.assertTrue(report['rollback']['copies'][0]['automatic_copy_limit_exceeded'])
        self.assertEqual(report['rollback']['before_first_boot'], 'unknown')
        self.assertEqual(self.checks(report)['ROLLBACK:super/system']['status'], 'unknown')
        self.assertFalse(report['preserve_allowed'])

    def test_wrong_rollback_copy_is_incompatible(self):
        (self.root / 'current/images').mkdir()
        (self.root / 'current/images/system.img').write_bytes(ext4())
        (self.root / 'rollback/system.img').write_bytes(ext4() + b'bad')
        report = self.inspect(current=ac.collect_current(self.root / 'current'),
                              rollback=self.root / 'rollback')
        self.assertEqual(self.checks(report)['ROLLBACK:super/system']['status'], 'incompatible')

    def test_full_super_copy_admits_rollback_for_system_only(self):
        root = self.root / 'rollback'
        shutil.copyfile(self.root / 'targets/super', root / 'super.img')
        with mock.patch.object(ac.flash, 'open_super', side_effect=AssertionError('opening super offline')):
            report = self.inspect(rollback=root)
        self.assertEqual(report['rollback']['before_first_boot'], 'complete')
        self.assertEqual(report['rollback']['super_copy']['status'], 'matches_live')
        self.assertEqual(report['rollback']['copies'][0]['via'], 'super.img')
        self.assertEqual(self.checks(report)['ROLLBACK:super/system']['status'], 'supported')
        self.assertFalse(report['preserve_allowed'])
        self.assertFalse(report['qualification']['hardware_qualified'])

        self.make_zip(images={'system.img': ext4(), 'boot.img': b'unsupported boot sample'})
        report = self.inspect(rollback=root)
        self.assertEqual(report['rollback']['before_first_boot'], 'unknown')
        self.assertEqual(self.checks(report)['ROLLBACK:boot']['status'], 'unknown')

    def test_full_super_copy_rejects_mismatch_even_outside_logical_partitions(self):
        root = self.root / 'rollback'
        path = root / 'super.img'
        shutil.copyfile(self.root / 'targets/super', path)
        with path.open('r+b') as file:
            file.seek(-1, os.SEEK_END)
            file.write(b'\xff')
        report = self.inspect(rollback=root)
        self.assertEqual(report['rollback']['super_copy']['status'], 'mismatch')
        self.assertEqual(report['rollback']['before_first_boot'], 'unknown')
        self.assertEqual(self.checks(report)['ROLLBACK:super/system']['status'], 'incompatible')

    def test_full_super_copy_without_probe_is_unbound(self):
        root = self.root / 'rollback'
        shutil.copyfile(self.root / 'targets/super', root / 'super.img')
        report = ac.analyze_file(self.package, rollback_root=root)
        self.assertEqual(report['rollback']['super_copy']['status'], 'unbound')
        self.assertEqual(report['rollback']['before_first_boot'], 'unknown')
        with self.assertRaises(ac.fs.FilesystemError) as caught:
            probe = ac.probe_super(self.context)
            probe['observed_super']['boot_id'] = 'other-boot'
            ac.analyze_file(self.package, rollback_root=root, probe=probe)
        self.assertEqual(caught.exception.code, 'GEOMETRY_CHANGED')

    def test_catalog_crdroid_gsi_targets_system_without_device_specific_assumption(self):
        image = self.root / 'crDroid-12.12-GSI_treble_arm64-ab-VANILLA-20260922.img.xz'
        image.write_bytes(lzma.compress(ext4()))
        snapshot = self.root / 'target-snapshot'
        (snapshot / 'build.prop').write_text('ro.product.system.device=generic\nro.product.cpu.abi=arm64-v8a\n')
        root = self.root / 'rollback'
        shutil.copyfile(self.root / 'targets/super', root / 'super.img')
        report = ac.analyze_file(image, target_root=snapshot, rollback_root=root, probe=ac.probe_super(self.context))
        self.assertEqual([write['target'] for write in report['write_set']], ['super/system'])
        self.assertEqual(self.checks(report)['TARGET_DEVICE']['status'], 'unknown')
        self.assertEqual(report['rollback']['before_first_boot'], 'complete')
        self.assertFalse(report['preserve_allowed'])

        (snapshot / 'build.prop').write_text('ro.product.system.device=another_device\n')
        report = ac.analyze_file(image, target_root=snapshot)
        self.assertEqual(self.checks(report)['TARGET_DEVICE']['status'], 'incompatible')

    def test_snapshot_symlink_and_hardlink_refused(self):
        (self.root / 'current/build.prop').symlink_to(self.root / 'data/target.zip')
        with self.assertRaises(ac.fs.FilesystemError):
            ac.collect_current(self.root / 'current')
        (self.root / 'current/build.prop').unlink()
        os.link(self.package, self.root / 'current/build.prop')
        with self.assertRaises(ac.fs.FilesystemError):
            ac.collect_current(self.root / 'current')

    def test_xz_and_sparse_are_hashed_as_native_decoded_bytes(self):
        image = ext4()
        raw = self.root / 'system.img.xz'
        raw.write_bytes(lzma.compress(image))
        report = ac.analyze_file(raw)
        self.assertEqual(report['write_set'][0]['image_sha256'], hashlib.sha256(image).hexdigest())
        sparse = self.root / 'system.img'
        sparse.write_bytes(struct.pack('<IHHHHIIII', 0xed26ff3a, 1, 0, 28, 12, 4096, 2, 1, 0)
                           + struct.pack('<HHII', 0xcac1, 0, 2, 12 + len(image)) + image)
        report = ac.analyze_file(sparse)
        self.assertEqual(report['write_set'][0]['image_sha256'], hashlib.sha256(image).hexdigest())
        self.assertEqual(report['write_set'][0]['image_format'], 'sparse')

    def test_invalid_sparse_extent_is_rejected_before_any_writer(self):
        image = self.root / 'system.img'
        image.write_bytes(struct.pack('<IHHHHIIII', 0xed26ff3a, 1, 0, 28, 12, 4096, 2, 1, 0)
                          + struct.pack('<HHII', 0xcac1, 0, 3, 12 + 12288) + ext4(12288))
        with self.assertRaises(ac.fs.FilesystemError) as caught:
            ac.analyze_file(image)
        self.assertEqual(caught.exception.code, 'SPARSE_OUTPUT_BOUNDS')

    def test_detached_target_snapshot_is_compared_but_never_authorizes(self):
        self.source()
        (self.root / 'target-snapshot/build.prop').write_text('ro.build.version.sdk=35\n')
        # A raw image has no conflicting public property in its container.
        raw = self.root / 'system.img'
        raw.write_bytes(ext4())
        report = ac.analyze_file(raw, current_root=self.root / 'current',
                                 target_root=self.root / 'target-snapshot')
        self.assertEqual(self.checks(report)['ANDROID_DOWNGRADE']['status'], 'incompatible')
        self.assertFalse(report['target']['runtime_files_bound_to_images'])
        self.assertFalse(report['preserve_allowed'])

    def test_changed_current_snapshot_cannot_be_replayed(self):
        current = self.source()
        first = self.inspect(current=current)
        (self.root / 'current/build.prop').write_text('ro.build.version.sdk=34\n')
        with self.assertRaises(ac.fs.FilesystemError) as caught:
            ac.revalidate(self.context, 'userdata', self.token, '/target.zip',
                          first['manifest_sha256'], current=current)
        self.assertEqual(caught.exception.code, 'SNAPSHOT_CHANGED')

    def test_snapshot_assertions_cannot_be_substituted_for_collected_files(self):
        with self.assertRaises(ac.fs.FilesystemError) as caught:
            self.inspect(current={'schema': ac.SNAPSHOT_SCHEMA, 'supported': True})
        self.assertEqual(caught.exception.code, 'INVALID_SNAPSHOT')

    def test_partition_geometry_change_invalidates_preview(self):
        first = self.inspect()
        config = json.loads((self.root / 'install-fixture.json').read_text())
        config['targets']['boot']['partuuid'] = 'fixture-changed-uuid'
        (self.root / 'install-fixture.json').write_text(json.dumps(config))
        context = ac.install.FixtureContext(self.root)
        with self.assertRaises(ac.fs.FilesystemError) as caught:
            ac.revalidate(context, 'userdata', self.token, '/target.zip', first['manifest_sha256'])
        self.assertEqual(caught.exception.code, 'PLAN_CHANGED')

    def test_explicit_ota_wipe_and_downgrade_metadata_are_incompatible(self):
        for key in ('ota-wipe', 'ota-downgrade'):
            self.make_zip(extra={ac.METADATA_PATH: key + '=yes\n'})
            report = self.inspect()
            self.assertEqual(report['status'], 'incompatible')
            self.assertEqual(self.checks(report)[key.upper().replace('-', '_')]['status'],
                             'incompatible')
            self.assertFalse(report['preserve_allowed'])

    def test_incremental_source_requirement_must_match_or_remain_unknown(self):
        self.make_zip(extra={ac.METADATA_PATH: 'pre-build=brand/device/old:16/id/1:user/release-keys\n'
                                               'pre-build-incremental=12345\n'})
        report = self.inspect()
        self.assertEqual(self.checks(report)['PRE_BUILD']['status'], 'unknown')
        self.assertEqual(self.checks(report)['PRE_BUILD_INCREMENTAL']['status'], 'unknown')
        (self.root / 'current/build.prop').write_text(
            'ro.build.fingerprint=brand/device/current:16/id/2:user/release-keys\n'
            'ro.build.version.incremental=67890\n')
        report = self.inspect(current=ac.collect_current(self.root / 'current'))
        self.assertEqual(self.checks(report)['PRE_BUILD']['status'], 'incompatible')
        self.assertEqual(self.checks(report)['PRE_BUILD_INCREMENTAL']['status'], 'incompatible')

    def test_report_source_snapshot_roundtrips_through_revalidation(self):
        report = self.inspect(current=self.source())
        replay = ac.revalidate(self.context, 'userdata', self.token, '/target.zip',
                               report['manifest_sha256'], current=report['source'])
        self.assertEqual(replay['manifest_sha256'], report['manifest_sha256'])
        sealed = report['source']
        self.assertEqual(sealed['snapshot_sha256'],
                         ac.digest({k: v for k, v in sealed.items() if k != 'snapshot_sha256'}))

    def test_explicit_wrong_android_abi_is_incompatible(self):
        self.make_zip(extra={ac.METADATA_PATH: 'ro.product.cpu.abi=x86_64\n'})
        report = self.inspect()
        self.assertEqual(self.checks(report)['TARGET_ABI']['status'], 'incompatible')
        self.assertFalse(report['preserve_allowed'])

    def test_cli_json_contract(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = ac.main(['--fixture', str(self.root), 'inspect', '--volume', 'userdata',
                            '--volume-token', self.token, '--path', '/target.zip'])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(result['ok'])
        self.assertEqual(result['schema'], 'a22x.android-compat.v1')


if __name__ == '__main__':
    unittest.main()
