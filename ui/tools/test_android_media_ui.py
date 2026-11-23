"""Run the native UI with the real archive helper on authenticated fixture volumes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

UI = Path(__file__).resolve().parents[1]
ROOT = UI.parent


def write_helpers(root):
    for helper in ('filesystem', 'android_data', 'android_twrp', 'android_migration'):
        (root / (helper + '.py')).write_text(
            f'import sys\nsys.path.insert(0, {str(ROOT)!r})\n'
            'import filesystem\nfrom tests.test_android_data import AndroidFixture\n'
            'filesystem.FixtureContext = AndroidFixture\n'
            f'import {helper}\nraise SystemExit({helper}.main())\n', encoding='utf-8')


def private_workflow():
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / 'tools'))
    import android_migration as migration
    import android_restore_apks
    import filesystem as fs
    from tests.test_android_data import AndroidFixture

    uid = os.getuid()
    assert 10000 <= uid <= 19999, 'Run with a mapped Android app UID'
    packages = ['org.example.' + letter for letter in 'abcdefgh']
    unprepared, linked = 'org.example.y', 'org.example.z'
    all_packages = [*packages, unprepared, linked]
    first, bad_signer, empty, *_, wanted, omitted = packages
    signed_apks = os.environ.get('A22X_TEST_SIGNED_APKS')
    signing_certificate = Path(signed_apks, 'cert.der').read_bytes().hex() if signed_apks else '305643657274'

    def package_xml(app, cert):
        return (f'<package name="{app}" codePath="/data/app/{app}" userId="{uid}" version="42">'
                f'<sigs count="1"><cert index="{all_packages.index(app)}" key="{cert}"/></sigs></package>')

    def registry(*apps):
        return '<packages><version sdkVersion="36" fingerprint="fixture/a22x"/>' + ''.join(apps) + '</packages>'

    with tempfile.TemporaryDirectory(prefix='a22x-app-restore-ui-') as temporary:
        root = Path(temporary)
        data = root / 'data'
        (data / 'system').mkdir(parents=True)
        (root / 'card').mkdir()
        layout = {
            'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
                {'id': 'userdata', 'path': 'data', 'fs_type': 'f2fs', 'mounted': True, 'read_only': True},
                {'id': 'sdcard-p1', 'path': 'card', 'fs_type': 'exfat', 'mounted': True, 'read_only': False},
            ]}
        fixture = root / 'filesystem-fixture.json'
        fixture.write_text(json.dumps(layout), encoding='utf-8')
        write_helpers(root)
        registry_file = data / 'system/packages.xml'
        registry_file.write_text(registry(*(package_xml(app, signing_certificate) for app in all_packages)))
        settings = data / 'system/users/0'
        settings.mkdir(parents=True)
        (settings / 'settings_system.xml').write_text('<settings><setting name="font_scale" value="1.25"/></settings>')
        (settings / 'settings_secure.xml').write_text('<settings/>')
        media = data / 'media/0'
        media.mkdir(parents=True)
        (media / 'photo.jpg').write_bytes(b'fixture photo')
        apks = {}
        content = b'local private data'
        for app in packages:
            folder = data / 'data' / app
            folder.mkdir(parents=True)
            if app != empty:
                (folder / 'state').write_bytes(content)
            code = data / 'app' / app
            code.mkdir(parents=True)
            members = {'base.apk': b'fixture base APK', 'split_config.uk.apk': b'fixture split APK'}
            if app == wanted and signed_apks:
                members = {path.name: path.read_bytes() for path in Path(signed_apks).glob('*.apk')}
            for name, payload in members.items():
                (code / name).write_bytes(payload)
            apks[app] = members
        (data / 'data' / linked).symlink_to(first)
        context = AndroidFixture(root)
        card = 'sdcard-p1'
        with context.operation_lock():
            token = context.volume('userdata')['volume_token']
            discovered = migration.list_source_apps(context, token)
            assert discovered['packages'] == packages
            registry_file.write_text(registry_file.read_text() + '\n')
            try:
                migration.create(context, token, [wanted], False, card, context.volume(card)['volume_token'],
                                 'fixture-password', True, expected_registry=discovered['registry_sha256'])
            except fs.FilesystemError as error:
                assert error.code == 'PACKAGE_REGISTRY_CHANGED'
            else:
                raise AssertionError('A stale registry was accepted for backup')
            assert list((root / 'card').iterdir()) == []
            base_apk = data / 'app' / wanted / 'base.apk'
            original = base_apk.rename(base_apk.with_name('base.apk.original'))
            base_apk.symlink_to(original.name)
            try:
                migration.create(context, token, [wanted], False, card, context.volume(card)['volume_token'],
                                 'fixture-password', True, include_apks=True)
            except fs.FilesystemError as error:
                assert error.code == 'APP_APKS_UNAVAILABLE'
            else:
                raise AssertionError('A linked APK was accepted for backup')
            finally:
                base_apk.unlink()
                original.rename(base_apk)
            assert list((root / 'card/A22xMigrationBackups').iterdir()) == []
        cmd = [str(UI / 'android-data-backup-ui-test'), str(root), sys.executable]
        subprocess.run([*cmd, 'migrate-apps'], check=True, timeout=50)
        archive, = (root / 'card/A22xMigrationBackups').glob('*.tar.gz.enc')
        with archive.open('rb') as stream:
            backup = migration.verify_fd(stream.fileno(), 'fixture-password')
            destination = root / 'extracted-apks'
            destination.mkdir()
            identity, copied = android_restore_apks.extract(stream.fileno(), 'fixture-password', backup['archive_sha256'], wanted, destination)
            assert {path.name: path.read_bytes() for path in copied} == apks[wanted]
            assert sorted(identity['apks']) == sorted(apks[wanted])
            if signed_apks:
                build_tools = Path(os.environ['A22X_TEST_BUILD_TOOLS'])
                splits = {apk.name: android_restore_apks.apk_identity(apk, build_tools, identity) for apk in copied}
                assert splits == {'base.apk': '', 'split_config.uk.apk': 'config.uk'}
                try:
                    android_restore_apks.apk_identity(destination / 'base.apk', build_tools,
                                                      {**identity, 'signers_sha256': ['0' * 64]})
                except fs.FilesystemError as error:
                    assert error.code == 'APK_SIGNER_MISMATCH'
                else:
                    raise AssertionError('An APK with another certificate was accepted')
                print('Android SDK APK signer, version and split verification PASS')
        assert backup['manifest']['schema'] == migration.APK_SCHEMA
        items = backup['manifest']['items']
        assert [item['package'] for item in items if item['kind'] == 'app-data'] == packages[:-1]
        assert 'shared/photo.jpg' in backup['manifest']['files']
        assert any(item['kind'] == 'personal-data' for item in items)
        assert all(f'apps/{wanted}/apk/{name}' in backup['manifest']['files'] for name in apks[wanted])
        assert all(not name.startswith(f'apps/{omitted}/') for name in backup['manifest']['files'])
        registry_file.write_text(registry(package_xml(bad_signer, '30564f74686572'), package_xml(wanted, signing_certificate)))
        target = data / 'data' / wanted
        (target / 'state').unlink()
        inode = target.stat().st_ino
        layout['volumes'][0]['read_only'] = False
        fixture.write_text(json.dumps(layout), encoding='utf-8')
        subprocess.run([*cmd, 'app-restore'], check=True, timeout=50)
        assert (target / 'state').read_bytes() == content and target.stat().st_ino == inode
        assert not (target / 'apk').exists()
        assert (data / 'data' / first / 'state').read_bytes() == content
        assert (data / 'data' / omitted / 'state').read_bytes() == content
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == backup['archive_sha256']


def main():
    with tempfile.TemporaryDirectory(prefix='a22x-portable-ui-') as temporary:
        root = Path(temporary)
        photo = root / 'data/media/0/DCIM/photo.jpg'
        photo.parent.mkdir(parents=True)
        photo.write_bytes(b'user photo from Android\x00' * 125)
        original = hashlib.sha256(photo.read_bytes()).hexdigest()
        (root / 'card').mkdir()
        (root / 'filesystem-fixture.json').write_text(json.dumps({
            'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
                {'id': 'userdata', 'path': 'data', 'fs_type': 'f2fs', 'mounted': True, 'read_only': False},
                {'id': 'sdcard-p1', 'path': 'card', 'fs_type': 'exfat', 'mounted': True, 'read_only': False},
            ]}), encoding='utf-8')
        write_helpers(root)
        subprocess.run([str(UI / 'android-data-backup-ui-test'), str(root), sys.executable, 'portable'],
                       check=True, timeout=40)
        restored = list((root / 'data/media/0').glob('Restored-Android-*/DCIM/photo.jpg'))
        assert len(restored) == 1 and hashlib.sha256(restored[0].read_bytes()).hexdigest() == original
        assert hashlib.sha256(photo.read_bytes()).hexdigest() == original
        backups = list((root / 'card/A22xPortableBackups').glob('*.tar.gz'))
        assert len(backups) == 1
        assert subprocess.check_output(['tar', '-xOzf', backups[0], 'DCIM/photo.jpg']) == photo.read_bytes()

        fixture = root / 'filesystem-fixture.json'
        layout = json.loads(fixture.read_text())
        layout['volumes'][0]['read_only'] = True
        fixture.write_text(json.dumps(layout))

        (root / 'proc').mkdir()
        (root / 'proc/cmdline').write_text('androidboot.bootloader=A226BXXSBDZC3')
        (root / 'sys/firmware/devicetree/base').mkdir(parents=True)
        (root / 'sys/firmware/devicetree/base/compatible').write_bytes(b'samsung,a22x\0mediatek,mt6833\0')
        (root / 'data/system').mkdir()
        (root / 'data/system/packages.xml').write_text('<packages><version sdkVersion="36" fingerprint="fixture/a22x"/></packages>')
        subprocess.run([str(UI / 'android-data-backup-ui-test'), str(root), sys.executable, 'model'],
                       check=True, timeout=40)
        assert len(list((root / 'card/A22xMigrationBackups').glob('*.tar.zst.enc'))) == 1

        owner = root / 'data/system/users/0'
        owner.mkdir(parents=True, exist_ok=True)
        (owner / 'settings_system.xml').write_text('<settings><setting name="font_scale" value="1.25"/></settings>')
        (owner / 'settings_secure.xml').write_text('<settings/>')
        subprocess.run([str(UI / 'android-data-backup-ui-test'), str(root), sys.executable, 'migrate'],
                       check=True, timeout=40)
        assert len(list((root / 'card/A22xMigrationBackups').glob('*.tar.gz.enc'))) == 1

        layout['volumes'][0]['read_only'] = False
        fixture.write_text(json.dumps(layout))
        subprocess.run([str(UI / 'android-data-backup-ui-test'), str(root), sys.executable, 'migration-restore'],
                       check=True, timeout=50)
        folders = list(photo.parents[1].glob('Restored-Migration-*'))
        assert len(folders) == 1 and (folders[0] / 'DCIM/photo.jpg').read_bytes() == photo.read_bytes()
        assert hashlib.sha256(photo.read_bytes()).hexdigest() == original
        assert not (folders[0] / 'manifest.json').exists() and not (folders[0] / 'personal').exists()

        win = root / 'card/data.f2fs.win'
        sample = os.getenv('A22X_VERIFY_TWRP_SAMPLE')
        if sample:
            shutil.copyfile(sample, win)
        else:
            subprocess.run(['tar', '--format=gnu', '--transform=s,^data/media/0/DCIM/photo.jpg$,user/0/com.example/photo.jpg,',
                            '-cf', win, '-C', root, 'data/media/0/DCIM/photo.jpg'], check=True)
        digest = hashlib.sha256(win.read_bytes()).hexdigest()
        win.with_suffix('.win.sha2').write_text(digest + '  data.f2fs.win\n', encoding='ascii')
        subprocess.run([str(UI / 'android-data-backup-ui-test'), str(root), sys.executable, 'twrp-review'],
                       check=True, timeout=40)
        assert hashlib.sha256(win.read_bytes()).hexdigest() == digest
        print(json.dumps({'ok': True, 'real_archive_helper': True, 'twrp_review': True,
                          'upstream_twrp_sample': bool(sample), 'device_io': False}))


if __name__ == '__main__':
    if sys.argv[1:] == ['--app-data']:
        private_workflow()
    else:
        main()
