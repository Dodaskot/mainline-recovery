"""Pinned CPIO asset deletion; unrelated assets and distro catalogue survive."""
import lzma
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_decrypt_image as builder

ASSET = 'opt/a22x-recovery/themes/beaver.theme'


def entry(name, data=b'fixture', mode=0o100644):
    return [[1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0], name, data]


class ThemeRemovalTests(unittest.TestCase):
    def fixture(self):
        payload = b'synthetic theme payload'
        manifest = {ASSET: {'sha256': builder.sha(payload), 'size_bytes': len(payload)}}
        return payload, manifest

    def test_only_explicit_theme_is_removed_all_other_entries_survive_unchanged(self):
        payload, manifest = self.fixture()
        others = [entry('opt/a22x-recovery/catalog.json', b'Beaver Linux distro'),
                  entry('opt/a22x-recovery/platform/beaver-rootfs.txt', b'installed system'),
                  entry('opt/a22x-recovery/themes/other.theme', b'other theme')]
        original = [others[0], entry(ASSET, payload), *others[1:]]
        with patch.object(builder, 'REMOVED_BUNDLED_THEMES', manifest):
            retained, removed = builder.remove_bundled_themes(original)
        self.assertEqual(retained, others)
        for a, b in zip(retained, others): self.assertIs(a, b)
        self.assertEqual(len(original), 4)  # Input collection and unrelated metadata stay unchanged.
        self.assertEqual(removed[ASSET]['before'], builder.sha(payload))
        self.assertEqual(removed[ASSET]['size_bytes'], len(payload))
        reread = builder.read_cpio(builder.write_cpio(retained))
        self.assertEqual([e[1] for e in reread], [e[1] for e in others])
        self.assertEqual([e[2] for e in reread], [e[2] for e in others])

    def test_unknown_asset_bytes_type_duplicate_or_missing_path_fail_closed(self):
        payload, manifest = self.fixture()
        for entries in ([], [entry(ASSET, payload+b'x')], [entry(ASSET, payload, 0o120777)],
                        [entry(ASSET, payload), entry(ASSET, payload)]):
            with patch.object(builder, 'REMOVED_BUNDLED_THEMES', manifest):
                with self.assertRaises(ValueError): builder.remove_bundled_themes(entries)

    @unittest.skipUnless(os.environ.get('A22X_DECRYPT_BASE_IMAGE'), 'Set exact pinned base to inspect inherited theme')
    def test_actual_pinned_base_deletes_exact_asset_and_preserves_every_other_entry(self):
        base = Path(os.environ['A22X_DECRYPT_BASE_IMAGE']).read_bytes()
        self.assertEqual(builder.sha(base), builder.BASE_SHA)
        _, parts, _ = builder.parse(base)
        original = builder.read_cpio(lzma.decompress(parts[1]))
        retained, removed = builder.remove_bundled_themes(original)
        self.assertEqual(set(removed), {ASSET})
        self.assertEqual(removed[ASSET]['size_bytes'], 2042511)
        self.assertEqual(removed[ASSET]['before'],
                         'ba9b9126558339a158a4e7b635a7fe2237f2ac5ecb4b1df57cb68e8f2d363d9b')
        expected = [e for e in original if e[1] != ASSET]
        self.assertEqual(retained, expected)
        for a, b in zip(retained, expected): self.assertIs(a, b)
        self.assertEqual(parts[0], builder.parse(base)[1][0])

if __name__ == '__main__': unittest.main()
