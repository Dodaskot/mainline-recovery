"""Data backup verification with single/split tar and TWRP extended headers."""
import contextlib
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import android_twrp as twrp
import filesystem as fs


def entry(name, value=None, kind=None):
    item = tarfile.TarInfo(name)
    if kind is not None:
        item.type = kind
    if value is None:
        if kind is None:
            item.type = tarfile.DIRTYPE
        return item.tobuf(format=tarfile.GNU_FORMAT)
    item.size = len(value)
    return item.tobuf(format=tarfile.GNU_FORMAT) + value + bytes(-len(value) % 512)


def record(field):
    length = len(field) + 3
    while length != len(field) + len(str(length)) + 2:
        length = len(field) + len(str(length)) + 2
    return str(length).encode() + b' ' + field + b'\n'


def tar_with_twrp_metadata(prefix=''):
    name = prefix + 'user/0/com.example'
    fields = record(b'RHT.security.selinux=u:object_r:app_data_file:s0:c42,c256')
    fields += record(b'ANDROID.user.default')
    fscrypt = b'0' + bytes((2, 1, 4, 8)) + bytes(4) + b'2CE0' + bytes(12)
    policy = record(b'TWRP.security.fscrypt=' + fscrypt)
    metadata = entry(name, fields, tarfile.XHDTYPE)
    extended = entry(name, policy, tarfile.XHDTYPE)
    database = entry(name + '/databases/' + 'x' * 170 + '.db', b'example database' * 2000)
    return metadata + extended + entry(name) + database + bytes(1024)


class TwrpReview(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='android-twrp-fixture-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.backup = self.root / 'sd/TWRP/BACKUPS/id/test'
        self.backup.mkdir(parents=True)
        (self.root / 'data').mkdir()
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({
            'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
                {'id': 'sdcard-p1', 'path': 'sd', 'fs_type': 'ext4', 'mounted': True, 'read_only': True},
                {'id': 'userdata', 'path': 'data', 'fs_type': 'f2fs', 'mounted': True, 'read_only': False},
            ]}))
        self.context = fs.FixtureContext(self.root)
        self.token = self.context.volume('sdcard-p1')['volume_token']
        self.path = '/TWRP/BACKUPS/id/test/'

    def review(self, name):
        return twrp.inspect(self.context, 'sdcard-p1', self.token, self.path + name)

    def checksum(self, name, algorithm, suffix):
        value = hashlib.new(algorithm, (self.backup / name).read_bytes()).hexdigest()
        (self.backup / (name + suffix)).write_text(value + '  ' + name + '\n')

    def assert_error(self, expected, name):
        with self.assertRaises(fs.FilesystemError) as caught:
            self.review(name)
        self.assertEqual(caught.exception.code, expected)

    def test_read_only_review_of_split_backup_validates_all_segments_and_metadata(self):
        base = 'data.f2fs.win'
        first, second = base + '000', base + '001'
        (self.backup / first).write_bytes(gzip.compress(tar_with_twrp_metadata('/data/')))
        (self.backup / second).write_bytes(entry('data/user_de/0/com.other/settings.xml', b'data') + bytes(1024))
        (self.backup / 'boot.emmc.win').write_bytes(b'unrelated partition')
        self.checksum(first, 'sha256', '.sha2')
        self.checksum(second, 'md5', '.md5')
        files = {p.name: p.read_bytes() for p in self.backup.iterdir()}
        result = self.review(second)
        self.assertEqual(result['counts'], {'entries': 3, 'files': 2, 'file_bytes': 32004, 'parts': 2,
                                            'checked_parts': 2, 'ce_packages': 1, 'de_packages': 1})
        self.assertEqual(result['twrp_metadata'], ['ANDROID.user.default', 'RHT.security.selinux', 'TWRP.security.fscrypt'])
        self.assertFalse(result['source_model_proven'] or result['source_rom_proven'] or result['restore_supported'])
        self.assertEqual([part['name'] for part in result['archive']['pieces']], [first, second])
        self.assertEqual(result['archive']['sha256'], self.review(first)['archive']['sha256'])
        self.assertEqual(files, {p.name: p.read_bytes() for p in self.backup.iterdir()})

    def test_single_without_checksum_reports_unverified_source_integrity(self):
        base = 'data.ext4.win'
        (self.backup / base).write_bytes(tar_with_twrp_metadata('/'))
        result = self.review(base)
        self.assertTrue(result['verified_structure'])
        self.assertEqual(result['counts']['checked_parts'], 0)
        self.assertEqual(result['archive']['pieces'][0]['sha256'], hashlib.sha256((self.backup / base).read_bytes()).hexdigest())
        args = ['--fixture', str(self.root), '--volume', 'sdcard-p1', '--expected-volume-token', self.token,
                '--path', self.path + base, '--summary']
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(twrp.main(args), 0)
        compact = json.loads(out.getvalue())
        self.assertNotIn('pieces', compact['archive'])
        self.assertEqual(compact['archive']['sha256'], result['archive']['sha256'])

    def test_incomplete_and_ambiguous_segments_do_not_pass(self):
        base = 'data.f2fs.win'
        (self.backup / (base + '002')).write_bytes(bytes(1024))
        self.assert_error('TWRP_PARTS_MISSING', base + '002')
        (self.backup / base).write_bytes(tar_with_twrp_metadata())
        self.assert_error('AMBIGUOUS_TWRP_BACKUP', base)

    def test_checksum_mismatch_and_misnamed_checksum_fail(self):
        name = 'data.ext4.win'
        archive = self.backup / name
        archive.write_bytes(tar_with_twrp_metadata())
        sidecar = self.backup / (name + '.sha256')
        sidecar.write_text('0' * 64 + '  ' + name + '\n')
        self.assert_error('TWRP_DIGEST_MISMATCH', name)
        sidecar.write_text('0' * 64 + '  other.win\n')
        self.assert_error('TWRP_DIGEST_INVALID', name)

    def test_untrusted_paths_password_archives_and_bad_gzip_cannot_pass(self):
        name = 'data.f2fs.win'
        archive = self.backup / name
        for data, code in ((entry('../escape', b'file') + bytes(1024), 'ARCHIVE_UNSAFE'),
                           (b'OAES' + bytes(512), 'TWRP_ENCRYPTED_BACKUP'),
                           (gzip.compress(tar_with_twrp_metadata())[:-4], 'TWRP_TAR_DAMAGED')):
            with self.subTest(code=code):
                archive.write_bytes(data)
                self.assert_error(code, name)
        self.assertFalse(list(self.root.glob('escape')))


if __name__ == '__main__':
    unittest.main()
