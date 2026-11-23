"""The whole of an unencrypted userdata copied to a card and put back (2026-11-21); temporary directories."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_userdata as au
import filesystem as fs


def tree(root):
    """Every entry under ROOT: type, mode, size, link, user xattrs, content hash, shared inode groups."""
    rows, inodes = {}, {}
    for path in sorted(root.rglob('*')):
        rel = str(path.relative_to(root))
        st = path.lstat()
        kind = 'link' if stat.S_ISLNK(st.st_mode) else 'dir' if stat.S_ISDIR(st.st_mode) else 'file'
        row = {'kind': kind, 'mode': stat.S_IMODE(st.st_mode), 'mtime': st.st_mtime_ns if kind != 'link' else None}
        if kind == 'file':
            row['sha'] = hashlib.sha256(path.read_bytes()).hexdigest()
            row['xattrs'] = {k: os.getxattr(path, k) for k in os.listxattr(path) if k.startswith('user.')}
            inodes.setdefault(st.st_ino, []).append(rel)
        if kind == 'link':
            row['target'] = os.readlink(path)
        rows[rel] = row
    links = sorted(sorted(group) for group in inodes.values() if len(group) > 1)
    return rows, links


class Userdata(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='a22x-userdata-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data, self.sd = self.root / 'data', self.root / 'sd'
        self.sd.mkdir()
        self.data.mkdir()
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
            {'id': 'userdata', 'path': 'data', 'fs_type': 'ext4', 'mounted': True, 'read_only': False},
            {'id': 'sdcard-p2', 'path': 'sd', 'fs_type': 'ext4', 'mounted': True, 'read_only': False}]}))
        self.context = fs.FixtureContext(self.root)
        d = self.data
        (d / 'system/users/0').mkdir(parents=True)
        (d / 'system/users/0/settings_secure.xml').write_bytes(b'<settings version="1"/>\n')
        (d / 'data/org.example/files').mkdir(parents=True)
        app = d / 'data/org.example/files/state.db'
        app.write_bytes(os.urandom(300000))
        os.setxattr(app, 'user.a22x', b'label')
        os.chmod(app, 0o660)
        os.link(app, d / 'data/org.example/files/state-link.db')
        (d / 'data/org.example/lib').symlink_to('/data/app/org.example/lib/arm64')
        tool = d / 'system/bin-tool'
        tool.write_bytes(b'#!/system/bin/sh\n')
        os.chmod(tool, 0o4750)
        (d / 'media/0/DCIM').mkdir(parents=True)
        (d / 'media/0/DCIM/photo.jpg').write_bytes(os.urandom(50000))
        (d / 'media/0/A22xDataBackups').mkdir()
        (d / 'media/0/A22xDataBackups/old.tar.zst').write_bytes(b'never copied')
        os.chmod(d / 'data/org.example', 0o751)
        os.utime(d / 'data/org.example', ns=(1700000000000000000, 1700000000000000000))
        self.before = tree(d)

    def token(self, ident):
        return self.context.volume(ident)['volume_token']

    def backup(self, **kwargs):
        return au.backup(self.context, self.token('userdata'), 'sdcard-p2', self.token('sdcard-p2'), True, **kwargs)

    def empty(self):
        for child in self.data.iterdir():
            shutil.rmtree(child) if child.is_dir() and not child.is_symlink() else child.unlink()

    def restore(self, done):
        return au.restore(self.context, 'sdcard-p2', self.token('sdcard-p2'), done['archive']['path'], done['archive']['sha256'],
                          self.token('userdata'), True)

    def test_a_copy_goes_back_into_an_empty_userdata_as_it_was(self):
        done = self.backup()
        self.assertTrue(done['verified'] and done['restore_supported'])
        self.assertTrue(done['archive']['path'].startswith('/A22xUserdataBackups/userdata-'))
        listed = au.listing(self.context, 'sdcard-p2', self.token('sdcard-p2'))['copies']
        self.assertEqual([c['path'] for c in listed], [done['archive']['path']])
        checked = au.verify(self.context, 'sdcard-p2', self.token('sdcard-p2'), done['archive']['path'], done['archive']['sha256'])
        self.assertEqual(checked['counts'], done['counts'])
        self.empty()
        result = self.restore(done)
        self.assertTrue(result['restored'])
        after = tree(self.data)
        expected = ({k: v for k, v in self.before[0].items() if not k.startswith('media/0/A22xDataBackups')}, self.before[1])
        self.assertEqual(after, expected)
        self.assertEqual(stat.S_IMODE((self.data / 'system/bin-tool').stat().st_mode), 0o4750)
        self.assertEqual(os.getxattr(self.data / 'data/org.example/files/state.db', 'user.a22x'), b'label')

    def test_only_into_an_empty_userdata(self):
        done = self.backup()
        with self.assertRaises(fs.FilesystemError) as caught:
            self.restore(done)
        self.assertEqual(caught.exception.code, 'USERDATA_NOT_EMPTY')

    def test_not_into_a_userdata_that_is_not_mounted_for_writing(self):
        """2026-11-22, live: a fresh F2FS not mounted yet was refused as USERDATA_ENCRYPTED."""
        done = self.backup()
        self.empty()
        fixture = json.loads((self.root / 'filesystem-fixture.json').read_text())
        for mounted, read_only in ((False, False), (True, True)):
            fixture['volumes'][0].update(mounted=mounted, read_only=read_only)
            (self.root / 'filesystem-fixture.json').write_text(json.dumps(fixture))
            self.context = fs.FixtureContext(self.root)
            with self.assertRaises(fs.FilesystemError) as caught:
                self.restore(done)
            self.assertEqual(caught.exception.code, 'USERDATA_NOT_MOUNTED')
        self.assertEqual(list(self.data.iterdir()), [])

    def test_a_changed_copy_is_refused_before_anything_is_written(self):
        done = self.backup()
        path = self.sd / done['archive']['path'].lstrip('/')
        data = bytearray(path.read_bytes())
        data[len(data) // 2] ^= 1
        path.write_bytes(bytes(data))
        self.empty()
        with self.assertRaises(fs.FilesystemError) as caught:
            self.restore(done)
        self.assertEqual(caught.exception.code, 'ARCHIVE_SHA_MISMATCH')
        self.assertEqual(list(self.data.iterdir()), [])

    def test_a_copy_without_the_shared_files(self):
        done = self.backup(without_media=True)
        self.assertTrue(done['without_media'])
        self.empty()
        self.restore(done)
        self.assertFalse((self.data / 'media').exists())
        self.assertTrue((self.data / 'data/org.example/files/state.db').is_file())

    def test_not_onto_userdata_itself(self):
        with self.assertRaises(fs.FilesystemError) as caught:
            au.backup(self.context, self.token('userdata'), 'userdata', self.token('userdata'), True)
        self.assertEqual(caught.exception.code, 'DESTINATION_NOT_ALLOWED')


if __name__ == '__main__':
    unittest.main()
