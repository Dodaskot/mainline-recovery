"""Shared files chosen by their kind (2026-11-20): only photos and documents, say."""
import json
from pathlib import Path
import tempfile
import unittest

import android_migration as migration
import file_types
import filesystem as fs
import os
from test_android_migration import PASSWORD, AndroidFixture, abx


class SharedKindsTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / 'source'
        (root / 'data/system').mkdir(parents=True)
        (root / 'sd').mkdir()
        (root / 'filesystem-fixture.json').write_text(json.dumps({
            'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
                {'id': 'userdata', 'path': 'data', 'fs_type': 'f2fs', 'mounted': True, 'read_only': False},
                {'id': 'sdcard-p1', 'path': 'sd', 'fs_type': 'exfat', 'mounted': True, 'read_only': False}]}))
        self.context = AndroidFixture(root)
        (root / 'data/system/packages.xml').write_bytes(abx(uid=os.getuid()))
        media = root / 'data/media/0'
        for name, data in (('DCIM/Camera/IMG_1.JPG', b'jpeg'), ('Pictures/a.webp', b'webp'), ('Movies/v.mp4', b'mp4'),
                           ('Documents/notes.pdf', b'pdf'), ('Download/app.apk', b'apk'), ('Download/README', b'x'),
                           ('Music/song.flac', b'flac')):
            (media / name).parent.mkdir(parents=True, exist_ok=True)
            (media / name).write_bytes(data)

    def backup(self, kinds):
        with self.context.operation_lock():
            return migration.create(self.context, self.context.volume('userdata')['volume_token'], [], True, 'sdcard-p1',
                                    self.context.volume('sdcard-p1')['volume_token'], PASSWORD, True, shared_kinds=kinds)

    def test_only_the_chosen_kinds(self):
        result = self.backup(['documents', 'photos'])
        files = {name for name, record in result['manifest']['files'].items() if record['type'] == 'file'}
        self.assertEqual(files, {'shared/DCIM/Camera/IMG_1.JPG', 'shared/Pictures/a.webp', 'shared/Documents/notes.pdf'})
        item = next(i for i in result['manifest']['items'] if i['kind'] == 'shared-files')
        self.assertEqual(item['types'], ['documents', 'photos'])
        self.assertEqual(item['skipped']['other_types'], 4)
        # Every kind is every file; no choice keeps the format of earlier archives.
        everything = self.backup(None)
        item = next(i for i in everything['manifest']['items'] if i['kind'] == 'shared-files')
        self.assertNotIn('types', item)
        self.assertNotIn('other_types', item['skipped'])
        self.assertEqual(sum(r['type'] == 'file' for r in everything['manifest']['files'].values()), 7)

    def test_manifest_and_choice_are_checked(self):
        manifest = self.backup(['videos'])['manifest']
        lying = json.loads(json.dumps(manifest))
        next(i for i in lying['items'] if i['kind'] == 'shared-files')['types'] = ['videos', 'unknown']
        with self.assertRaises(fs.FilesystemError):
            migration.validate_manifest(lying, lying['files'])
        with self.assertRaises(fs.FilesystemError):
            self.backup(['music'])
        self.assertEqual(file_types.parse('photos, videos'), ('photos', 'videos'))
        self.assertIsNone(file_types.parse(''))
        with self.assertRaises(ValueError):
            file_types.parse('photos,bogus')
        self.assertEqual([file_types.kind_of(n) for n in ('a.JPG', 'b.tar.gz', '.hidden', 'noext', 'c.apk')],
                         ['photos', 'archives', 'other', 'other', 'apks'])


if __name__ == '__main__':
    unittest.main()
