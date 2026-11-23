"""Run the real builder on an inert base and inspect its packed source closure.

Only the synthetic platform profile and AVB command are stand-ins. The overlay
selection, replacement, CPIO/XZ/TAR serialization and build manifests are real.
No native runtime, signing tool, device or qualified image is modified.
"""
import argparse
import contextlib
import importlib.util
import io
import json
import lzma
import marshal
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))
import build_decrypt_image as builder
from test_decrypt_image_modules import archive, entry, kernel


@unittest.skipUnless(sys.implementation.cache_tag == 'cpython-314', 'The image builder requires Python 3.14')
class PythonOverlayTests(unittest.TestCase):
    def test_current_sources_are_packed_with_existing_metadata_and_manifest_pins(self):
        current_zip = (ROOT / 'zip_install.py').read_bytes()
        old_zip = b'def require_installable(about):\n    return None  # stale base without module ZIP guard\n'
        old_other = b'# inherited helper stays exact, that has no worktree copy (a helper with one must match it, 2026-11-19 guard)\n'
        old_native = b'inert inherited native fixture'
        recovery_sources = {
            'opt/a22x-recovery/' + name: (ROOT / name).read_bytes()
            for name in ('file_archive.py', 'handoff.py', 'misc_store.py', 'wifi.py', 'flash.py', 'terminal.py', 'distro.py')
        }
        stale_source = b'# stale recovery source from the base image\n'
        image_path = 'opt/a22x-recovery/zip_install.py'
        theme_path = 'opt/a22x-recovery/themes/beaver.theme'
        theme = b'inert theme fixture'
        budget, page = 4 << 20, 4096

        with tempfile.TemporaryDirectory(prefix='a22x-packed-source-') as tmp:
            root = Path(tmp)
            project = root / 'project'
            (project / 'tools').mkdir(parents=True)
            (project / 'ui').mkdir()
            (project / 'ramdisk').mkdir()
            (project / 'ramdisk/init').write_text('#!/bin/busybox sh\n')
            (project / 'usb').mkdir()
            shutil.copyfile(ROOT / 'usb/mtp_sandbox.c', project / 'usb/mtp_sandbox.c')
            usb_runtime = {'schema': 'a22x.usb-files.runtime.v1',
                           'responder': {'path': '/bin/umtprd', 'sha256': '1' * 64, 'version': 'fixture'},
                           'sandbox': {'path': '/bin/a22x-mtp-sandbox', 'sha256': '2' * 64, 'version': 'a22x-mtp-sandbox 2'}}
            (project / 'profiles/android-decrypt').mkdir(parents=True)
            # Worktree fixtures include unrelated helpers: the builder must keep
            # its explicit overlay allowlist instead of copying every Python file.
            for path in ROOT.glob('*.py'):
                shutil.copyfile(path, project / path.name)
            shutil.copytree(ROOT / 'decrypt_runtime', project / 'decrypt_runtime', ignore=shutil.ignore_patterns('__pycache__'))
            (project / 'not_an_overlay.py').write_text('raise RuntimeError("must never enter the image")\n')
            for name in ('web_packages.json', 'web_gpu_packages.json', 'media_packages.json', 'media_full_packages.json', 'migration_agent.dex'):
                shutil.copyfile(ROOT / name, project / name)
            script = project / 'tools/build_decrypt_image.py'
            shutil.copyfile(builder.__file__, script)
            (project / 'android_profiles.py').write_text(
                "SAMSUNG_PROFILE='fixture-samsung'\nEVO_PROFILE='fixture-evolution'\n"
                "def validate_profile(value, ident):\n"
                "    assert value['profile_id'] == ident\n    return value\n")
            runtime = root / 'inert-runtime.tar'
            runtime.write_bytes(b'inert fixture; no CE capability is admitted')
            for filename, ident in [('samsung-a226b-a13.json', 'fixture-samsung'),
                                    ('evolutionx-a226b-a16.json', 'fixture-evolution')]:
                profile = {'profile_id': ident, 'bundle_sha256': builder.sha(runtime.read_bytes()),
                           'bootstrap_wrapper_sha256': builder.sha((project / 'decrypt_bootstrap.py').read_bytes()),
                           'credential_types': ['none']}
                (project / 'profiles/android-decrypt' / filename).write_text(json.dumps(profile))
            ui = bytearray(64); ui[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<H', ui, 18, 183)
            (project / 'ui/a22x-recovery-ui-aarch64').write_bytes(ui)
            (project / 'ui/recovery_ui.c').write_text('/* inert UI fixture */\n')

            stale_cache = (importlib.util.MAGIC_NUMBER + struct.pack('<I', 3) +
                           importlib.util.source_hash(old_zip) + marshal.dumps(compile(old_zip, '/' + image_path, 'exec')))
            entries = [entry(name, b'', 0o40755) for name in
                       ('bin', 'etc', 'etc/a22x-recovery', 'opt', 'opt/a22x-recovery')]
            entries += [entry(image_path, old_zip, 0o100750),
                        entry('opt/a22x-recovery/inherited_only_helper.py', old_other),
                        entry('opt/a22x-recovery/__pycache__/zip_install.cpython-314.pyc', stale_cache),
                        entry('opt/a22x-recovery/native-fixture', old_native, 0o100555),
                        entry(theme_path, theme), entry(builder.WIFI_PATH, archive()),
                        entry('etc/a22x-recovery/build.json', b'{"version":"fixture-base"}'),
                        entry('bin/a22x-mtp-sandbox', b'old sandbox', 0o100700),
                        entry('etc/a22x-recovery/usb-files-runtime.json', json.dumps(usb_runtime).encode())]
            entries.extend(entry(name, stale_source, 0o100640) for name in recovery_sources)
            for index, row in enumerate(entries, 800):
                row[0][0] = index
            old_entry = next(row for row in entries if row[1] == image_path)
            # Non-default metadata makes accidental reconstruction visible.
            old_entry[0][2], old_entry[0][3], old_entry[0][5] = 123, 456, 1700000123
            old_fields = list(old_entry[0])
            parts = [kernel(), lzma.compress(builder.write_cpio(entries)), b'', b'', b'fixture-dtb']
            header = bytearray(page); header[:8] = b'ANDROID!'
            struct.pack_into('<10I', header, 8, len(parts[0]), 0, len(parts[1]), 0, 0, 0, 0, page, 2, 0)
            struct.pack_into('<IQI', header, 1632, 0, 0, 1660)
            struct.pack_into('<I', header, 1648, len(parts[4]))
            header[576:608] = builder.digest(parts)
            base = bytes(header) + b''.join(part + bytes(-len(part) % page) for part in parts)
            base += bytes(budget - len(base))
            base_path = root / 'base.img'; base_path.write_bytes(base)
            output = root / 'output'
            args = argparse.Namespace(base=base_path, runtime=runtime, wifi_modules=None,
                quota_module_dir=None, panfrost_module=None, wayland_compositor=None, sound_modules=[], ce_snapshot_helper=None, output=output,
                version='fixture-source-overlay', dict_mib=8)

            real_run = subprocess.run
            avb_calls = []

            def fake_avb(argv, **kwargs):
                if argv[0] in ('xz', 'aarch64-linux-gnu-gcc'):  # the ramdisk compression and the MTP sandbox run for real
                    return real_run(argv, **kwargs)
                avb_calls.append(argv)
                self.assertEqual(argv[0], 'avbtool')
                self.assertIn(argv[1], ('add_hash_footer', 'verify_image'))
                if argv[1] == 'add_hash_footer':
                    target = Path(argv[argv.index('--image') + 1])
                    payload = target.read_bytes()
                    self.assertLess(len(payload), budget)
                    target.write_bytes(payload + bytes(budget - len(payload)))
                return subprocess.CompletedProcess(argv, 0, '', '')

            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(builder, '__file__', str(script)))
                stack.enter_context(patch.object(builder, 'BASE_SHA', builder.sha(base)))
                stack.enter_context(patch.object(builder, 'PARTITION_SIZE', budget))
                stack.enter_context(patch.object(builder, 'REMOVED_BUNDLED_THEMES', {
                    theme_path: {'sha256': builder.sha(theme), 'size_bytes': len(theme)}}))
                stack.enter_context(patch.object(argparse.ArgumentParser, 'parse_args', return_value=args))
                avb = stack.enter_context(patch.object(builder.subprocess, 'run', side_effect=fake_avb))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                builder.main()
                self.assertEqual(len(avb_calls), 2)

            _, packed_parts, _ = builder.parse((output / 'recovery.img').read_bytes())
            packed = {name: (fields, data) for fields, name, data in builder.read_cpio(lzma.decompress(packed_parts[1]))}
            for helper in ('android_migration.py', 'android_app_restore.py'):
                self.assertEqual(packed['opt/a22x-recovery/' + helper][1], (ROOT / helper).read_bytes())
            fields, payload = packed[image_path]
            self.assertEqual(payload, current_zip)  # The missing allowlist entry failed here before the fix.
            expected_fields = list(old_fields); expected_fields[6] = len(current_zip)
            self.assertEqual(fields, expected_fields)
            self.assertEqual(packed['opt/a22x-recovery/inherited_only_helper.py'][1], old_other)
            # The sandbox is built from the worktree and the USB runtime manifest names it (2026-11-21).
            sandbox = packed['bin/a22x-mtp-sandbox'][1]
            self.assertEqual((sandbox[:4], packed['bin/a22x-mtp-sandbox'][0][1]), (b'\x7fELF', 0o100700))
            packed_runtime = json.loads(packed['etc/a22x-recovery/usb-files-runtime.json'][1])
            self.assertEqual(packed_runtime['sandbox'], {'path': '/bin/a22x-mtp-sandbox', 'sha256': builder.sha(sandbox),
                                                         'version': 'a22x-mtp-sandbox 3'})
            self.assertEqual(packed_runtime['responder'], usb_runtime['responder'])
            self.assertEqual(packed['opt/a22x-recovery/native-fixture'][1], old_native)
            self.assertNotIn('opt/a22x-recovery/not_an_overlay.py', packed)
            self.assertFalse(any(name.endswith('.pyc') for name in packed))
            current_sha = builder.sha(current_zip)
            delta = json.loads((output / 'DELTA.json').read_text())
            result = json.loads((output / 'RESULT.json').read_text())
            expected_record = {'before': builder.sha(old_zip), 'after': current_sha, 'size_bytes': len(current_zip)}
            self.assertEqual(delta[image_path], expected_record)
            self.assertEqual(result['sources'][image_path], expected_record)
            self.assertNotIn('inherited', result['sources'][image_path])
            build = json.loads(packed['etc/a22x-recovery/build.json'][1])
            self.assertEqual(build['source_sha256']['zip_install.py'], current_sha)
            with tarfile.open(output / 'ram-overlay.tar') as overlay:
                self.assertEqual(overlay.extractfile(image_path).read(), current_zip)
                self.assertEqual(overlay.getmember(image_path).mode, 0o750)
                for name, source in recovery_sources.items():
                    with self.subTest(source=name):
                        self.assertEqual(packed[name][1], source, 'stale recovery source')
                        self.assertEqual(packed[name][0][1], 0o100640)
                        source_sha = builder.sha(source)
                        expected_source = {
                            'before': builder.sha(stale_source),
                            'after': source_sha,
                            'size_bytes': len(source),
                        }
                        self.assertEqual(delta[name], expected_source)
                        self.assertEqual(result['sources'][name], expected_source)
                        relative_name = name.removeprefix('opt/a22x-recovery/')
                        self.assertEqual(build['source_sha256'][relative_name], source_sha)
                        self.assertEqual(overlay.extractfile(name).read(), source)
                        self.assertEqual(overlay.getmember(name).mode, 0o640)
            namespace = {'__name__': 'packed_zip_install', '__file__': '/' + image_path}
            exec(compile(payload, '/' + image_path, 'exec'), namespace)
            with self.assertRaises(Exception) as refused:
                namespace['require_installable']({'what': 'module'})
            self.assertEqual(getattr(refused.exception, 'code', None), 'MODULE_ZIP_UNSUPPORTED')


if __name__ == '__main__':
    unittest.main()
