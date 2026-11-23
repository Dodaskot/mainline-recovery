"""Logical Android userdata backup: real host descriptor/tar/zstd fixtures only."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_data as ad
import filesystem as fs


class AndroidFixture(fs.FixtureContext):
    boot_id = 'fixture-current-boot'
    overrides = None
    def volumes(self):
        result = super().volumes()
        for volume in result:
            if volume['id'] != 'userdata':
                continue
            volume.update(mount_owner='android-decrypt', ce_authenticated=True,
                          fscrypt_policy_verified=True, decrypt_state='mounted',
                          decrypt_profile_id='exact-evox-fixture')
            volume.update(self.overrides or {})
        return result


class AndroidPortable(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='android-media-fixture-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.device('source')
        self.target = self.device('target')
        self.sd = self.root / 'source/sd'
        self.target_sd = self.root / 'target/sd'
        self.media = self.root / 'source/data/media/0'
        self.destination = self.root / 'target/data/media/0'
        for directory in ('DCIM', 'Documents', 'Android/media/example', 'Android/data/example',
                          'Android/obb/example', 'A22xDataBackups'):
            (self.media / directory).mkdir(parents=True)
        self.media_file = self.media / 'DCIM/набережна.jpg'
        self.media_file.write_bytes(bytes(range(256)) * 10000)
        self.media_file.chmod(0o6755)
        os.utime(self.media_file, (1700000000, 1700000000))
        self.deep_item = self.media / 'Documents' / ('a' * 180 + '.txt')
        self.deep_item.write_text('Long pathname\n')
        (self.media / 'Android/media/example/export.txt').write_text('Exported by an app\n')
        (self.media / 'Android/data/example/private.txt').write_text('app-scoped storage')
        (self.media / 'Android/obb/example/cache.txt').write_text('app resources')
        (self.media / 'A22xDataBackups/backup.tar.zst').write_text('old backup')
        (self.root / 'source/data/user/0/secret').write_text('private app database')
        (self.media / 'Documents/outside').symlink_to(self.root / 'source/data/user/0/secret')
        (self.destination / 'DCIM').mkdir()
        (self.destination / 'DCIM/набережна.jpg').write_bytes(b'existing photo')

    def device(self, name):
        root = self.root / name
        (root / 'data/media/0').mkdir(parents=True)
        (root / 'data/user/0').mkdir(parents=True)
        (root / 'sd').mkdir()
        (root / 'filesystem-fixture.json').write_text(json.dumps({
            'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
                {'id': 'userdata', 'path': 'data', 'fs_type': 'f2fs', 'mounted': True, 'read_only': False},
                {'id': 'sdcard-p1', 'path': 'sd', 'fs_type': 'exfat', 'mounted': True, 'read_only': False}]}))
        return AndroidFixture(root)

    def token(self, context, volume='userdata'):
        return context.volume(volume)['volume_token']

    def backup(self, volume='sdcard-p1'):
        result = ad.portable_backup(self.source, self.token(self.source), volume, self.token(self.source, volume), True)
        if volume == 'sdcard-p1':
            folder = result['archive']['path'][1:]
            (self.target_sd / folder).parent.mkdir(exist_ok=True)
            shutil.copy2(self.sd / folder, self.target_sd / folder)
        return result

    def restore(self, path, digest, token=None):
        return ad.portable_restore(self.target, 'sdcard-p1', self.token(self.target, 'sdcard-p1'),
                                   path, digest, token or self.token(self.target), True)

    def assert_error(self, code, action):
        with self.assertRaises(fs.FilesystemError) as error:
            action()
        self.assertEqual(error.exception.code, code)

    def test_standard_archive_and_cross_device_restore_into_new_folder(self):
        result = self.backup()
        archive = result['archive']
        self.assertEqual(result['skipped'], 4)
        self.assertEqual(archive['sha256'], hashlib.sha256((self.sd / archive['path'][1:]).read_bytes()).hexdigest())
        file_names = subprocess.check_output(['tar', '-tzf', str(self.sd / archive['path'][1:])], text=True).splitlines()
        self.assertIn('DCIM/набережна.jpg', file_names)
        self.assertIn('Documents/' + self.deep_item.name, file_names)
        self.assertIn('Android/media/example/export.txt', file_names)
        self.assertTrue(all(not name.endswith(('secret', 'outside', 'private.txt', 'cache.txt', 'backup.tar.zst')) for name in file_names))
        reviewed = ad.portable_inspect(self.target, 'sdcard-p1', self.token(self.target, 'sdcard-p1'), archive['path'])
        self.assertEqual(reviewed['counts'], result['counts'])
        self.assertEqual(reviewed['archive'], archive)
        restored = self.restore(archive['path'], reviewed['archive']['sha256'])
        folder = self.root / 'target/data' / restored['folder'][1:]
        photo = folder / 'DCIM/набережна.jpg'
        self.assertEqual(photo.read_bytes(), self.media_file.read_bytes())
        self.assertEqual(photo.stat().st_mtime, 1700000000)
        self.assertEqual(stat.S_IMODE(photo.stat().st_mode), 0o664)
        self.assertEqual((photo.stat().st_uid, photo.stat().st_gid), (self.destination.stat().st_uid, self.destination.stat().st_gid))
        self.assertEqual((folder / 'DCIM').stat().st_mtime, (self.media / 'DCIM').stat().st_mtime_ns // 10**9)
        self.assertEqual((folder / 'Documents' / self.deep_item.name).read_bytes(), self.deep_item.read_bytes())
        self.assertEqual((self.destination / 'DCIM/набережна.jpg').read_bytes(), b'existing photo')
        self.assert_error('DESTINATION_EXISTS', lambda: self.restore(archive['path'], archive['sha256']))
        self.assertFalse(list(self.destination.glob('.a22x-restore-*')))

    def test_backup_uses_writable_ce_session_and_does_not_archive_its_own_store(self):
        first = self.backup('userdata')
        second = self.backup('userdata')
        self.assertNotEqual(first['archive']['path'], second['archive']['path'])
        self.assertEqual(first['archive']['sha256'], second['archive']['sha256'])
        self.assertEqual(first['counts'], second['counts'])
        self.source.overrides = {'read_only': True}
        self.assertTrue(self.backup()['verified'])
        self.assert_error('ANDROID_RW_REQUIRED', lambda: self.backup('userdata'))
        self.source.overrides = {'ce_authenticated': False}
        self.assert_error('ANDROID_CE_REQUIRED', self.backup)

    def test_wrong_review_hash_or_changed_mount_writes_nothing(self):
        record = self.backup()['archive']
        self.assert_error('ARCHIVE_SHA_MISMATCH', lambda: self.restore(record['path'], 'a' * 64))
        self.assert_error('VOLUME_CHANGED', lambda: self.restore(record['path'], record['sha256'], 'a' * 64))
        self.target.overrides = {'read_only': True}
        self.assert_error('ANDROID_RW_REQUIRED', lambda: self.restore(record['path'], record['sha256']))
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), ['DCIM'])

    def test_unsafe_members_and_bad_gzip_are_rejected_before_writing(self):
        archive = self.target_sd / 'bad.tar.gz'
        for name, kind in (('../escape', tarfile.REGTYPE), ('link', tarfile.SYMTYPE),
                           ('link', tarfile.LNKTYPE), ('child/missing-parent', tarfile.DIRTYPE)):
            with self.subTest(name=name, kind=kind):
                with tarfile.open(archive, 'w:gz') as tar:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    item.linkname = 'DCIM'
                    tar.addfile(item)
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                self.assert_error('ARCHIVE_UNSAFE', lambda: self.restore('/bad.tar.gz', digest))
        record = self.backup()['archive']
        data = (self.sd / record['path'][1:]).read_bytes()
        archive.write_bytes(data[:-8] + bytes(8))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assert_error('ARCHIVE_DAMAGED', lambda: self.restore('/bad.tar.gz', digest))
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), ['DCIM'])

    def test_interrupted_restore_removes_staging_and_can_be_retried(self):
        record = self.backup()['archive']

        def interrupted(done, count):
            raise OSError(5, 'fixture write interrupted')

        with self.assertRaises(OSError):
            ad.portable_restore(self.target, 'sdcard-p1', self.token(self.target, 'sdcard-p1'),
                                record['path'], record['sha256'], self.token(self.target), True, interrupted)
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), ['DCIM'])
        self.assertTrue(self.restore(record['path'], record['sha256'])['verified'])


@unittest.skipUnless(shutil.which('zstd'), 'zstd is required')
class AndroidData(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='android-data-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / 'userdata'
        for path in ('media/0', 'user/0/app', 'user_de/0', 'system/users'):
            (self.data / path).mkdir(parents=True)
        self.secret = self.data / 'user/0/app/private-name'
        self.secret.write_bytes(bytes(range(256)) * 32)
        self.secret.chmod(0o640)
        os.utime(self.secret, ns=(1700000000123456789, 1700000000987654321))
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({
            'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
                {'id': 'userdata', 'path': 'userdata', 'fs_type': 'f2fs',
                 'mounted': True, 'read_only': False}]}))
        self.ctx = AndroidFixture(self.root)
        self.token = self.ctx.volume('userdata')['volume_token']

    def error(self, code, call):
        with self.assertRaises(fs.FilesystemError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def backup(self):
        with self.ctx.operation_lock():
            return ad.backup(self.ctx, self.token, True)

    def archive(self, result):
        return self.data / result['archive']['path'].lstrip('/')

    def manifest(self, result):
        raw = subprocess.run(['zstd', '-q', '-dc', str(self.archive(result))], capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            return json.load(tar.extractfile(ad.MANIFEST))

    def verify(self, result):
        with self.ctx.operation_lock():
            return ad.verify(self.ctx, result['archive']['path'], self.token, result['archive']['sha256'])

    def test_complete_copy_excludes_self_and_existing_stores(self):
        for store in ad.STORES:
            folder = self.data / 'media/0' / store
            folder.mkdir(mode=0o700)
            (folder / 'older-backup.tar.zst').write_bytes(b'never included')
        result = self.backup()
        self.assertTrue(result['verified'] and result['same_partition'])
        self.assertFalse(result['restore_supported'])
        self.assertEqual(self.verify(result)['counts'], result['counts'])
        index = self.manifest(result)
        self.assertEqual(index['excluded'], list(ad.EXCLUDED))
        self.assertEqual(index['skipped']['stores'], len(ad.STORES))
        self.assertTrue(all(not ad.excluded(e['path']) for e in index['entries']))
        self.assertEqual(stat.S_IMODE(self.archive(result).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.archive(result).parent.stat().st_mode), 0o700)
        self.assertEqual(hashlib.sha256(self.archive(result).read_bytes()).hexdigest(), result['archive']['sha256'])

    def test_binary_xattr_owner_mode_time_symlink_hardlink_roundtrip(self):
        os.setxattr(self.secret, 'user.binary', b'\x00\xff\x01binary\x00')
        os.link(self.secret, self.secret.with_name('second-link'))
        self.secret.with_name('absolute-link').symlink_to('/outside/private-content')
        before = self.secret.stat()
        result = self.backup()
        entries = {e['path']: e for e in self.manifest(result)['entries']}
        regular = entries['user/0/app/private-name']
        self.assertEqual((regular['uid'], regular['gid'], regular['mode'], regular['mtime_ns']),
                         (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode), before.st_mtime_ns))
        self.assertEqual(base64.b64decode(regular['xattrs']['user.binary']), b'\x00\xff\x01binary\x00')
        self.assertEqual(regular['sha256'], hashlib.sha256(self.secret.read_bytes()).hexdigest())
        self.assertEqual(entries['user/0/app/second-link']['type'], 'hardlink')
        self.assertEqual(entries['user/0/app/second-link']['link'], 'user/0/app/private-name')
        self.assertEqual(entries['user/0/app/absolute-link']['link'], '/outside/private-content')
        self.assertEqual(result['counts']['hardlinks'], 1)
        self.assertEqual(result['counts']['file_bytes'], self.secret.stat().st_size)
        self.verify(result)

    def test_no_symlink_following_or_external_payload(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'external-private').write_text('not to be copied')
        (self.data / 'media/0/linked').symlink_to(outside)
        result = self.backup()
        index = self.manifest(result)
        self.assertIn('media/0/linked', [e['path'] for e in index['entries']])
        self.assertFalse(any('external-private' in e['path'] for e in index['entries']))

    def test_same_device_nested_mount_rejected_by_kernel_mount_identity(self):
        nested = self.data / 'nested'
        nested.mkdir()
        original = fs.fd_mount_id
        def mount_id(fd):
            return original(fd) + (1 if os.readlink('/proc/self/fd/%d' % fd) == str(nested) else 0)
        with fs.PinnedVolume(self.ctx, 'userdata', self.token) as pin:
            with mock.patch.object(fs, 'fd_mount_id', side_effect=mount_id):
                self.error('CROSS_MOUNT_REJECTED', lambda: ad.scan(pin))

    def test_other_users_fail_before_partial_creation(self):
        (self.data / 'user/10').mkdir()
        self.error('ANDROID_OTHER_USERS', self.backup)
        self.assertFalse(list((self.data / 'media/0/A22xDataBackups').iterdir()))

    def test_insufficient_space_refused_before_archive(self):
        with mock.patch.object(ad, 'free_bytes', return_value=ad.RESERVE + 1):
            self.error('NO_SPACE', self.backup)
        self.assertFalse(list((self.data / 'media/0/A22xDataBackups').iterdir()))

    def test_rw_and_authentication_required_no_implicit_mount(self):
        self.assertTrue(ad.inspect(self.ctx)['can_backup'])
        for override, code in [({'read_only': True}, 'ANDROID_RW_REQUIRED'),
                               ({'write_supported': False}, 'ANDROID_RW_REQUIRED'),
                               ({'ce_authenticated': False}, 'ANDROID_CE_REQUIRED'),
                               ({'mount_owner': 'filesystem'}, 'ANDROID_CE_REQUIRED'),
                               ({'mounted': False}, 'ANDROID_NOT_MOUNTED')]:
            self.ctx.overrides = override
            self.assertFalse(ad.inspect(self.ctx)['can_backup'])
            self.error(code, self.backup)
        self.ctx.overrides = None
        self.assertFalse((self.data / 'media/0/A22xDataBackups').exists())
        self.error('CONFIRMATION_REQUIRED', lambda: ad.backup(self.ctx, self.token, False))
        self.error('VOLUME_CHANGED', lambda: ad.backup(self.ctx, 'a' * 64, True))

    def test_verify_allowed_on_fresh_ro_authenticated_session(self):
        result = self.backup()
        self.ctx.overrides = {'read_only': True, 'write_supported': False}
        self.ctx.boot_id = 'fixture-fresh-boot'
        checked = self.verify(result)
        self.assertTrue(checked['verified'])
        self.assertEqual(checked['current']['boot_id'], 'fixture-fresh-boot')
        self.assertEqual(checked['source']['boot_id'], 'fixture-current-boot')

    def test_corruption_sha_is_checked_before_decompression(self):
        result = self.backup()
        path = self.archive(result)
        data = bytearray(path.read_bytes())
        data[len(data) // 2] ^= 0x80
        path.write_bytes(data)
        with mock.patch.object(ad.subprocess, 'Popen') as popen:
            self.error('ARCHIVE_SHA_MISMATCH', lambda: self.verify(result))
            popen.assert_not_called()

    def test_truncated_archive_with_recomputed_sha_still_fails(self):
        result = self.backup()
        path = self.archive(result)
        path.write_bytes(path.read_bytes()[:-4])
        result['archive']['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.error('ARCHIVE_DAMAGED', lambda: self.verify(result))

    def test_payload_index_hash_mismatch_rejected(self):
        result = self.backup()
        path = self.archive(result)
        raw = subprocess.run(['zstd', '-q', '-dc', str(path)], capture_output=True, check=True).stdout
        output = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw)) as src, tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as dst:
            for member in src:
                stream = src.extractfile(member) if member.isfile() else None
                if member.name == ad.MANIFEST:
                    index = json.load(stream)
                    next(e for e in index['entries'] if e['type'] == 'file')['sha256'] = '0' * 64
                    data = ad.encode(index)
                    member.size, stream = len(data), io.BytesIO(data)
                dst.addfile(member, stream)
        path.write_bytes(subprocess.run(['zstd', '-q', '-c'], input=output.getvalue(), capture_output=True, check=True).stdout)
        result['archive']['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.error('ARCHIVE_DAMAGED', lambda: self.verify(result))

    def test_existing_archives_and_unowned_partials_never_deleted(self):
        with mock.patch.object(ad.time, 'strftime', return_value='fixed'), mock.patch.object(ad.os, 'urandom', return_value=bytes(8)):
            first = self.backup()
            before = self.archive(first).read_bytes()
            unrelated = self.archive(first).parent / '.unrelated.partial'
            unrelated.write_bytes(b'keep this')
            self.error('DESTINATION_EXISTS', self.backup)
            self.assertEqual(self.archive(first).read_bytes(), before)
            self.assertEqual(unrelated.read_bytes(), b'keep this')
            self.assertEqual(len(list(self.archive(first).parent.iterdir())), 2)

    def test_failure_cleans_only_owned_partial_inode(self):
        original = ad.write_archive
        def failure(pin, out, entries, skipped, progress):
            os.write(out, b'partial')
            raise OSError(5, 'fixture')
        with mock.patch.object(ad, 'write_archive', side_effect=failure):
            with self.assertRaises(OSError):
                self.backup()
        folder = self.data / 'media/0/A22xDataBackups'
        self.assertEqual(list(folder.iterdir()), [])
        self.assertIsNotNone(original)
        (folder / 'partial').write_bytes(b'old')
        with fs.PinnedVolume(self.ctx, 'userdata', self.token, writing=True) as pin, pin.directory(ad.DESTINATION) as parent:
            self.error('PARTIAL_IDENTITY_CHANGED', lambda: ad.owned_unlink(parent, 'partial', (-1, -1)))
        self.assertEqual((folder / 'partial').read_bytes(), b'old')

    def test_source_mutation_during_stream_fails_and_removes_partial(self):
        read = ad.HashReader.read
        changed = [False]
        def mutation(reader, size=-1):
            value = read(reader, size)
            if value and not changed[0]:
                changed[0] = True
                os.utime(self.secret, ns=(1700000000000000000, 1700000000000000000))
            return value
        with mock.patch.object(ad.HashReader, 'read', mutation):
            self.error('SOURCE_CHANGED', self.backup)
        self.assertEqual(list((self.data / 'media/0/A22xDataBackups').iterdir()), [])

    def test_unreadable_xattr_is_not_incomplete_success(self):
        with mock.patch.object(ad.os, 'listxattr', side_effect=PermissionError(13, 'fixture')):
            with self.assertRaises(PermissionError):
                self.backup()
        self.assertEqual(list((self.data / 'media/0/A22xDataBackups').iterdir()), [])

    def test_excessive_depth_or_index_is_rejected(self):
        with mock.patch.object(ad, 'MAX_DEPTH', 1):
            self.error('BACKUP_BOUNDS', self.backup)
        with mock.patch.object(ad, 'MAX_INDEX', 8):
            self.error('BACKUP_BOUNDS', self.backup)

    def test_policy_requires_v2_exact_match_and_uses_proven_ioctl(self):
        calls = []
        def ioctl(fd, command, buf, mutate):
            calls.append((fd, command, mutate))
            struct.pack_into('=Q', buf, 0, 24)
            buf[8:32] = bytes([2, 1, 4, 8]) + bytes(4) + bytes([fd]) * 16
        with mock.patch.object(ad.fcntl, 'ioctl', side_effect=ioctl):
            self.error('CE_POLICY_MISMATCH', lambda: ad.same_policy(object(), 3, 4))
        self.assertEqual(calls, [(3, 0xc0096616, True), (4, 0xc0096616, True)])
        def unsupported(fd, command, buf, mutate):
            struct.pack_into('=Q', buf, 0, 24)
            buf[8] = 1
        with mock.patch.object(ad.fcntl, 'ioctl', side_effect=unsupported):
            self.error('CE_POLICY_UNSUPPORTED', lambda: ad.policy(3))
        self.assertEqual(ad.mtime_text(-1), '-0.000000001')

    def test_fifo_refused_explicitly_without_partial(self):
        os.mkfifo(self.data / 'user/0/app/pipe', 0o600)
        self.error('ANDROID_FIFO_UNSUPPORTED', self.backup)
        self.assertEqual(list((self.data / 'media/0/A22xDataBackups').iterdir()), [])

    def test_root_metadata_is_indexed_and_verified(self):
        os.setxattr(self.data, 'user.root-binary', b'\x00\xffroot')
        before = self.data.stat()
        result = self.backup()
        root = self.manifest(result)['root']
        self.assertEqual((root['path'], root['type'], root['size']), ('/', 'directory', 0))
        self.assertEqual((root['uid'], root['gid'], root['mode'], root['mtime_ns']),
                         (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode), before.st_mtime_ns))
        self.assertEqual(base64.b64decode(root['xattrs']['user.root-binary']), b'\x00\xffroot')
        self.verify(result)

    def test_non_utf8_filename_preserves_byte_name_and_is_verified(self):
        name = os.fsdecode(b'non-utf8-\xff')
        (self.data / 'media/0' / name).write_bytes(b'binary filename payload')
        result = self.backup()
        self.assertIn('media/0/' + name, [e['path'] for e in self.manifest(result)['entries']])
        self.verify(result)

    def test_cli_outputs_counts_and_result_only(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(ad.fs, 'DeviceContext', return_value=self.ctx), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ad.main(['--device', 'backup', '--expected-volume-token', self.token, '--confirm'])
        self.assertEqual(code, 0, out.getvalue())
        value = json.loads(out.getvalue())
        self.assertTrue(value['verified'])
        self.assertNotIn('private-name', out.getvalue() + err.getvalue())
        self.assertNotIn('xattrs', out.getvalue() + err.getvalue())


if __name__ == '__main__':
    unittest.main()


class PlainAndroidDataTest(unittest.TestCase):
    """Android data that encrypts nothing (LineageOS 20), mounted by the filesystem helper, is admitted
    without a decryption session; anything else still needs the authenticated one (2026-11-21)."""

    def volume(self, **changes):
        value = {'id': 'userdata', 'fs_type': 'f2fs', 'mounted': True, 'mountable': True,
                 'mount_owner': 'filesystem', 'unencrypted_android_data': True,
                 'write_supported': True, 'read_only': False}
        value.update(changes)
        return value

    def test_plain_open_is_admitted_for_reading_and_writing(self):
        ad.admitted(self.volume())
        ad.admitted(self.volume(), True)

    def test_plain_open_read_only_is_refused_for_writing(self):
        ad.admitted(self.volume(read_only=True))
        with self.assertRaises(ad.fs.FilesystemError) as caught:
            ad.admitted(self.volume(read_only=True), True)
        self.assertEqual(caught.exception.code, 'ANDROID_RW_REQUIRED')

    def test_encrypted_or_foreign_mounts_still_need_the_session(self):
        for changes in ({'unencrypted_android_data': False}, {'mount_owner': 'storage'}, {'fs_type': 'ext4'}):
            with self.assertRaises(ad.fs.FilesystemError):
                ad.admitted(self.volume(**changes))
