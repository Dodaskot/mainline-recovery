"""Independent application fixture, ABX source, archive authentication and target preflight."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_migration as migration
import android_package_registry as registry
import archive_crypt as crypt
import filesystem as fs
from test_android_data import AndroidFixture

APP = 'org.example.notes'
CERT = bytes.fromhex('305643657274')
PASSWORD = 'fixture-only-passphrase'
ROOT = Path(__file__).resolve().parents[1]


def abx(app=APP, cert=CERT, uid=10000):
    chunks = [b'ABX\0\x10']
    interns = {}

    def utf(value):
        data = value.encode('utf-8').replace(b'\0', b'\xc0\x80')
        return struct.pack('>H', len(data)) + data

    def intern(value):
        if value in interns:
            return struct.pack('>H', interns[value])
        interns[value] = len(interns)
        return b'\xff\xff' + utf(value)

    def tag(name, fields=None, children=None):
        chunks.append(b'\x32' + intern(name))
        for key, value in (fields or {}).items():
            attr_type = {'key': 4, 'version': 8, 'userId': 6, 'index': 6, 'count': 6, 'sdkVersion': 6}.get(key, 2)
            chunks.append(bytes((attr_type << 4 | 15,)) + intern(key))
            if attr_type == 4:
                chunks.append(struct.pack('>H', len(value)) + value)
            elif attr_type == 8:
                chunks.append(struct.pack('>q', value))
            elif attr_type == 6:
                chunks.append(struct.pack('>i', value))
            else:
                chunks.append(utf(value))
        if children is not None:
            children()
        chunks.append(b'\x33' + intern(name))

    def packages():
        tag('version', {'sdkVersion': 33, 'buildFingerprint': 'samsung/fixture/a13'})
        tag('version', {'sdkVersion': 33, 'volumeUuid': 'primary_physical', 'fingerprint': 'other'})
        # AOSP stores the first certificate in a shared table and later packages reference its index.
        tag('package', {'name': 'org.example.first'},
            lambda: tag('sigs', {'count': 1}, lambda: tag('cert', {'index': 0, 'key': cert})))
        tag('package', {'name': app, 'codePath': '/data/app/~~example/' + app,
                        'userId': uid, 'version': (1 << 32) + 42},
            lambda: tag('sigs', {'count': 1}, lambda: tag('cert', {'index': 0})))

    tag('packages', children=packages)
    return b''.join(chunks) + b'\x11'


def target_xml(app=APP, uid=10039, cert=CERT, sdk=36, version=(1 << 32) + 42):
    return (f'<packages><version sdkVersion="{sdk}" fingerprint="evo/fixture/a16"/>'
            f'<package name="{app}" codePath="/data/app/{app}" userId="{uid}" version="{version}">'
            f'<sigs count="1"><cert index="0" key="{cert.hex()}"/></sigs></package></packages>').encode()


class PackageRegistryTest(unittest.TestCase):
    def test_abx_signature_reference_and_64_bit_app_version(self):
        value = registry.parse(abx(), [APP])
        self.assertEqual(value['sdk'], 33)
        self.assertEqual(value['fingerprint'], 'samsung/fixture/a13')
        self.assertEqual(value['packages'][APP], {
            'uid': 10000, 'package': APP, 'version_code': (1 << 32) + 42,
            'signers_sha256': [hashlib.sha256(CERT).hexdigest()],
        })

    def test_package_identity_is_not_guessed_from_incomplete_registry(self):
        no_certificate = target_xml().replace(b' key="' + CERT.hex().encode() + b'"', b'')
        for data in (abx()[:-1], abx(uid=1000), no_certificate,
                     b'<!DOCTYPE packages [<!ENTITY e "x">]><packages/>'):
            with self.subTest(data=data[:15]), self.assertRaises(ValueError):
                registry.parse(data, [APP])


@unittest.skipUnless(10000 <= os.getuid() <= 19999, 'run in a user namespace with Android app UID 10000')
class AndroidMigrationTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.data, self.context = self.fixture('source')
        self.target, self.target_context = self.fixture('target')
        self.ce = self.data / 'data' / APP
        self.de = self.data / 'user_de/0' / APP
        for branch in (self.ce / 'databases', self.ce / 'cache', self.de, self.data / 'user',
                       self.data / 'media/0/DCIM', self.data / 'media/0/Android/data', self.data / 'misc/keystore'):
            branch.mkdir(parents=True, exist_ok=True)
        (self.data / 'user/0').symlink_to('../data')
        (self.ce / 'databases/db').write_text('private CE SQLite bytes')
        (self.ce / 'databases/db-wal').write_text('WAL bytes')
        (self.ce / 'cache/excluded').write_text('cached data')
        (self.ce / 'outside').symlink_to('/etc/passwd')
        (self.de / 'state.xml').write_text('DE bytes')
        (self.data / 'media/0/DCIM/берег.png').write_bytes(bytes(range(256)))
        (self.data / 'media/0/Android/data/private').write_text('scope not included')
        (self.data / 'misc/keystore/key').write_text('keys are out of scope')
        (self.data / 'system/packages.xml').write_bytes(abx(uid=os.getuid()))
        (self.target / 'system/packages.xml').write_bytes(target_xml())
        self.password_file = self.root / 'password'
        self.password_file.write_text(PASSWORD)
        self.password_file.chmod(0o600)

    def fixture(self, name):
        root = self.root / name
        (root / 'data/system').mkdir(parents=True)
        (root / 'sd').mkdir()
        (root / 'filesystem-fixture.json').write_text(json.dumps({
            'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
                {'id': 'userdata', 'path': 'data', 'fs_type': 'f2fs', 'mounted': True, 'read_only': False},
                {'id': 'sdcard-p1', 'path': 'sd', 'fs_type': 'exfat', 'mounted': True, 'read_only': False},
            ]}))
        return root / 'data', AndroidFixture(root)

    def backup(self, volume='sdcard-p1', package=APP):
        with self.context.operation_lock():
            return migration.create(self.context, self.context.volume('userdata')['volume_token'], [package], True,
                                    volume, self.context.volume(volume)['volume_token'], PASSWORD, True)

    def review(self, manifest):
        return migration.review_target(self.target_context, self.target_context.volume('userdata')['volume_token'], manifest)

    def private_restore(self, result):
        path = result['path'].lstrip('/')
        backup = self.target.parent / 'sd' / path
        backup.parent.mkdir(exist_ok=True)
        shutil.copyfile(self.data.parent / 'sd' / path, backup)
        ce = self.target / 'data' / APP
        de = self.target / 'user_de/0' / APP
        ce.mkdir(parents=True)
        de.mkdir(parents=True)
        (ce / 'cache').mkdir()
        (ce / 'cache/current').write_text('target cache')
        (self.target / 'system/packages.xml').write_bytes(target_xml(uid=os.getuid()))

        def restore(password=PASSWORD, confirmed=True, progress=lambda *args: None):
            context = self.target_context
            volume = 'sdcard-p1'
            with context.operation_lock():
                return migration.app_restore.restore(
                    context, volume, context.volume(volume)['volume_token'], '/' + path, result['archive_sha256'],
                    context.volume('userdata')['volume_token'], password, APP, confirmed, progress,
                )

        return restore, ce, de

    def test_restore_private_ce_and_de_preserves_target_roots_and_resumes(self):
        restore, ce, de = self.private_restore(self.backup())
        identities = ce.stat().st_ino, de.stat().st_ino
        first = restore()
        self.assertEqual(first['scope'], ['ce', 'de'])
        self.assertTrue(first['installed_data_written'])
        self.assertEqual((ce / 'databases/db').read_bytes(), (self.ce / 'databases/db').read_bytes())
        self.assertEqual((ce / 'databases/db-wal').read_bytes(), (self.ce / 'databases/db-wal').read_bytes())
        self.assertEqual((de / 'state.xml').read_bytes(), (self.de / 'state.xml').read_bytes())
        self.assertEqual((ce / 'cache/current').read_text(), 'target cache')
        self.assertEqual((ce.stat().st_ino, de.stat().st_ino), identities)
        self.assertEqual((ce / 'databases/db').stat().st_uid, os.getuid())
        self.assertEqual(stat.S_IMODE((ce / 'databases/db').stat().st_mode), 0o600)
        self.assertFalse(restore()['installed_data_written'])
        database_inode = (ce / 'databases/db').stat().st_ino
        (de / 'state.xml').unlink()
        resumed = restore()
        self.assertEqual(resumed['entries_written'], 1)
        self.assertEqual((ce / 'databases/db').stat().st_ino, database_inode)
        self.assertEqual(sorted(child.name for child in ce.iterdir()), ['cache', 'databases'])
        self.assertEqual(list(de.iterdir()), [de / 'state.xml'])

    def test_restore_private_fails_before_write_on_conflict_signing_or_bad_password(self):
        restore, ce, de = self.private_restore(self.backup())
        with self.assertRaises(crypt.CryptError):
            restore(password='incorrect-archive-password')
        with self.assertRaises(fs.FilesystemError) as caught:
            restore(confirmed=False)
        self.assertEqual(caught.exception.code, 'CONFIRMATION_REQUIRED')
        registry_file = self.target / 'system/packages.xml'
        registry_file.write_bytes(target_xml(uid=os.getuid(), cert=b'different-signing-key'))
        with self.assertRaises(fs.FilesystemError) as caught:
            restore()
        self.assertEqual(caught.exception.code, 'APP_RESTORE_PACKAGE_MISMATCH')
        registry_file.write_bytes(target_xml(uid=os.getuid()))
        (de / 'state.xml').write_text('existing app state')
        with self.assertRaises(fs.FilesystemError) as caught:
            restore()
        self.assertEqual(caught.exception.code, 'APP_RESTORE_CONFLICT')
        self.assertEqual(list(ce.iterdir()), [ce / 'cache'])
        self.assertEqual((de / 'state.xml').read_text(), 'existing app state')

    def test_restore_private_command_runs_from_migration_entrypoint(self):
        saved = self.backup()
        _, ce, de = self.private_restore(saved)
        volume = 'sdcard-p1'
        args = ['--fixture', str(self.target.parent), '--password-file', str(self.password_file),
                'restore-app', '--package', APP, '--path', saved['path'], '--volume', volume,
                '--expected-volume-token', self.target_context.volume(volume)['volume_token'],
                '--expected-target-token', self.target_context.volume('userdata')['volume_token'],
                '--expected-sha256', saved['archive_sha256'], '--confirm']
        original = fs.FixtureContext.volumes

        def data_ready(context):
            rows = original(context)
            for row in rows:
                if row['id'] == 'userdata':
                    row.update(mount_owner='android-decrypt', ce_authenticated=True, fscrypt_policy_verified=True,
                               decrypt_state='mounted', decrypt_profile_id='synthetic')
            return rows

        out = io.StringIO()
        with mock.patch.object(fs.FixtureContext, 'volumes', data_ready), redirect_stdout(out):
            status = migration.main(args)
        self.assertEqual(status, 0, out.getvalue())
        self.assertTrue(json.loads(out.getvalue())['installed_data_written'])
        self.assertTrue((ce / 'databases/db').is_file())
        self.assertTrue((de / 'state.xml').is_file())

    def test_restore_private_rolls_back_if_second_scope_cannot_publish(self):
        restore, ce, de = self.private_restore(self.backup())
        rename = fs.rename_noreplace

        def conflict(source, old, destination, new):
            if new == 'state.xml':
                raise OSError('simulated interrupted DE commit')
            return rename(source, old, destination, new)

        with mock.patch.object(fs, 'rename_noreplace', side_effect=conflict):
            with self.assertRaises(OSError):
                restore()
        self.assertEqual(list(ce.iterdir()), [ce / 'cache'])
        self.assertEqual(list(de.iterdir()), [])
        self.assertTrue(restore()['installed_data_written'])

    def test_archive_scope_file_hashes_and_target_preflight(self):
        result = self.backup()
        manifest = result['manifest']
        self.assertTrue(result['verified'])
        target_snapshot = (self.target / 'system/packages.xml').read_bytes()
        self.assertEqual(self.review(manifest), {'target_sdk': 36, 'installed_data_written': False,
                                                'applications': [{'package': APP, 'status': 'identity_matches'}]})
        self.assertEqual((self.target / 'system/packages.xml').read_bytes(), target_snapshot)
        items = manifest['items']
        self.assertFalse(items[0]['keystore_exported'])
        self.assertEqual(items[0]['scopes']['ce'], {'cache': 1, 'links_or_special': 1, 'excluded_paths': 0})
        self.assertTrue(all('keystore' not in path and '/cache/' not in path and not path.endswith('/outside')
                            and '/Android/data' not in path for path in manifest['files']))
        files = {path: row for path, row in manifest['files'].items() if row['type'] == 'file'}
        self.assertEqual(set(files), {f'apps/{APP}/ce/databases/db', f'apps/{APP}/ce/databases/db-wal',
                                      f'apps/{APP}/de/state.xml', 'shared/DCIM/берег.png'})
        self.assertEqual(files[f'apps/{APP}/ce/databases/db']['sha256'],
                         hashlib.sha256((self.ce / 'databases/db').read_bytes()).hexdigest())
        for changes, expected in (({'app': 'org.example.different'}, 'package_missing'),
                                  ({'cert': b'another-signer'}, 'signing_mismatch'),
                                  ({'sdk': 32}, 'older_android'),
                                  ({'version': 44}, 'app_version_mismatch')):
            with self.subTest(status=expected):
                (self.target / 'system/packages.xml').write_bytes(target_xml(**changes))
                self.assertEqual(self.review(manifest)['applications'][0]['status'], expected)

    def test_backup_and_offline_export_preserve_archive_and_reject_collisions(self):
        result = self.backup()
        archive = self.data.parent / 'sd' / result['path'].lstrip('/')
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        exported = self.root / 'new-copy.tar.gz'
        command = [sys.executable, '-B', str(ROOT / 'android_migration.py'), '--offline', '--password-file',
                   str(self.password_file), 'verify', '--path', str(archive), '--expected-sha256', digest,
                   '--export-tar', str(exported)]
        verified = subprocess.run(command, text=True, capture_output=True, check=True)
        self.assertEqual(json.loads(verified.stdout)['archive_sha256'], digest)
        self.assertEqual(stat.S_IMODE(exported.stat().st_mode), 0o600)
        with tarfile.open(exported) as tar:
            self.assertEqual(tar.extractfile(f'apps/{APP}/ce/databases/db').read(), b'private CE SQLite bytes')
            self.assertEqual(json.load(tar.extractfile('manifest.json')), result['manifest'])
        retry = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(retry.returncode, 2)
        self.assertEqual(json.loads(retry.stdout)['error']['code'], 'DESTINATION_EXISTS')
        self.assertFalse(list(self.root.glob('.android-migration-*.partial')))
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest)

    def test_tamper_wrong_secrets_authentication_and_recursive_store(self):
        result = self.backup('userdata')
        result = self.backup('userdata')
        archive = self.data / result['path'].lstrip('/')
        self.assertFalse(any(migration.STORE in name for name in result['manifest']['files']))
        with archive.open('rb') as file:
            with self.assertRaises(crypt.CryptError) as bad_password:
                migration.verify_fd(file.fileno(), 'another-passphrase')
            self.assertEqual(bad_password.exception.code, 'WRONG_PASSWORD')
        with archive.open('r+b') as file:
            file.seek(117)
            byte = file.read(1)[0]
            file.seek(117)
            file.write(bytes([byte ^ 1]))
            file.flush()
            with self.assertRaises(crypt.CryptError) as damaged:
                migration.verify_fd(file.fileno(), PASSWORD)
            self.assertEqual(damaged.exception.code, 'BACKUP_DAMAGED')
        self.context.overrides = {'ce_authenticated': False}
        with self.assertRaises(fs.FilesystemError) as denied:
            self.backup()
        self.assertEqual(denied.exception.code, 'ANDROID_CE_REQUIRED')

    def test_restore_shared_between_devices_is_atomic_and_excludes_app_data(self):
        result = self.backup()
        volume = 'sdcard-p1'
        path = result['path'].lstrip('/')
        archive = self.target.parent / 'sd' / path
        archive.parent.mkdir()
        shutil.copyfile(self.data.parent / 'sd' / path, archive)
        media = self.target / 'media/0'
        (media / 'DCIM').mkdir(parents=True)
        existing = media / 'DCIM/берег.png'
        existing.write_bytes(b'existing photo')
        token = self.target_context.volume('userdata')['volume_token']
        source_token = self.target_context.volume(volume)['volume_token']

        def restore(progress=lambda *args: None, password=PASSWORD):
            with self.target_context.operation_lock():
                return migration.restore_shared(self.target_context, volume, source_token, result['path'],
                                                result['archive_sha256'], token, password, True, progress)

        def interrupt(*args):
            raise OSError('simulated interrupted write')

        with self.assertRaises(crypt.CryptError):
            restore(password='invalid-archive-password')
        with self.assertRaises(OSError):
            restore(interrupt)
        self.assertEqual(list(media.iterdir()), [media / 'DCIM'])
        restored = restore()
        folder = self.target / restored['folder'].lstrip('/')
        self.assertEqual((folder / 'DCIM/берег.png').read_bytes(), bytes(range(256)))
        self.assertEqual(existing.read_bytes(), b'existing photo')
        self.assertEqual([p for p in folder.rglob('*') if p.is_file()], [folder / 'DCIM/берег.png'])
        self.assertEqual(restored['file_bytes'], 256)
        with self.assertRaises(fs.FilesystemError) as collision:
            restore()
        self.assertEqual(collision.exception.code, 'DESTINATION_EXISTS')

    def test_same_model_copies_settings_wifi_contacts_layout_and_installed_apk(self):
        import io
        import sqlite3
        for root in (self.data.parent, self.target.parent):
            (root / 'proc').mkdir()
            (root / 'proc/cmdline').write_text('androidboot.bootloader=A226BXXSBDZC3')
            (root / 'sys/firmware/devicetree/base').mkdir(parents=True)
            (root / 'sys/firmware/devicetree/base/compatible').write_bytes(b'samsung,a22x\0mediatek,mt6833\0')
        samples = {'system/users/0/settings_secure.xml': b'<settings/>',
                   'misc/apexdata/com.android.wifi/WifiConfigStore.xml': b'''<WifiConfigStoreData><NetworkList>
                   <Network><WifiConfiguration><string name="SSID">"Lab;guest"</string>
                   <string name="ConfigKey">"Lab;guest"WPA_PSK</string>
                   <string name="PreSharedKey">"fixture:123"</string>
                   <boolean name="HiddenSSID" value="true"/></WifiConfiguration></Network>
                   <Network><WifiConfiguration><string name="SSID">"Locked"</string>
                   <string name="ConfigKey">"Locked"WPA_PSK</string>
                   <PreSharedKey><byte-array name="EncryptedData">aa</byte-array></PreSharedKey>
                   </WifiConfiguration></Network></NetworkList></WifiConfigStoreData>''',
                   'app/installed/base.apk': b'fixture installed application'}
        for path, data in samples.items():
            dest = self.data / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        for package, db in (('com.android.providers.contacts', 'contacts2.db'),
                            ('com.sec.android.app.launcher', 'launcher.db')):
            path = f'data/{package}/databases/{db}'
            (self.data / path).parent.mkdir(parents=True)
            with sqlite3.connect(self.data / path) as conn:
                conn.execute('create table fixture(value text)')
                conn.execute("insert into fixture values ('retained')")
            if db == 'contacts2.db':
                self.addCleanup(conn.close)
                conn.execute('PRAGMA journal_mode=WAL')
                conn.execute('PRAGMA wal_autocheckpoint=0')
                conn.executescript('''
                    CREATE TABLE raw_contacts(_id INTEGER, contact_id INTEGER, deleted INTEGER);
                    CREATE TABLE mimetypes(_id INTEGER, mimetype TEXT);
                    CREATE TABLE data(_id INTEGER, raw_contact_id INTEGER, mimetype_id INTEGER,
                                      data1 TEXT, data2 TEXT, data3 TEXT, data4 TEXT, data5 TEXT, data6 TEXT,
                                      is_primary INTEGER DEFAULT 0, is_super_primary INTEGER DEFAULT 0);
                    INSERT INTO raw_contacts VALUES(1,10,0),(2,20,1);
                    INSERT INTO mimetypes VALUES(1,'vnd.android.cursor.item/name'),(2,'vnd.android.cursor.item/phone_v2');
                    INSERT INTO data(_id,raw_contact_id,mimetype_id,data1,data2,data3)
                        VALUES(1,1,1,'Оля, Коваль','Оля','Коваль'),(2,1,2,'+380000000000',NULL,NULL),
                              (3,2,1,'Deleted',NULL,NULL);
                ''')
                self.assertGreater((self.data / (path + '-wal')).stat().st_size, 0)
            else:
                conn.close()
            samples[path] = (self.data / path).read_bytes()
        volume = 'sdcard-p1'
        with self.context.operation_lock():
            result = migration.create(self.context, self.context.volume('userdata')['volume_token'], [], False,
                                      volume, self.context.volume(volume)['volume_token'], PASSWORD, True,
                                      profile='same-model')
        manifest = result['manifest']
        self.assertEqual(manifest['schema'], migration.ad.MODEL_SCHEMA)
        self.assertEqual(manifest['source']['model'], 'SM-A226B')
        self.assertEqual(self.review(manifest), {'hardware_matches': True, 'build_matches': False,
                                                'restore_supported': False, 'installed_data_written': False})
        archive = self.data.parent / 'sd' / result['path'].lstrip('/')
        self.assertNotIn(b'WifiConfigStore', archive.read_bytes())
        exported = self.root / 'full.tar.zst'
        args = [sys.executable, '-B', str(ROOT / 'android_migration.py'), '--offline', '--password-file',
                str(self.password_file), 'verify', '--path', str(archive), '--expected-sha256', result['archive_sha256'],
                '--export-tar', str(exported)]
        checked = json.loads(subprocess.check_output(args))
        self.assertEqual(checked['counts'], manifest['counts'])
        plain = subprocess.check_output(['zstd', '-qdc', str(exported)])
        with tarfile.open(fileobj=io.BytesIO(plain)) as tar:
            for path, expected in samples.items():
                self.assertEqual(tar.extractfile('payload/' + path).read(), expected)
            self.assertEqual(json.load(tar.extractfile(migration.ad.MANIFEST)), manifest)

        wifi = [sys.executable, '-B', str(ROOT / 'tools/android_wifi_qr.py'), '--password-file',
                str(self.password_file), '--expected-sha256', result['archive_sha256'], str(archive)]
        listing = subprocess.check_output(wifi)
        self.assertNotIn(b'fixture:123', listing)
        self.assertEqual([row['status'] for row in json.loads(listing)], ['available', 'encrypted_key'])
        png = self.root / 'wifi.png'
        refused = subprocess.run(wifi + ['--network', '2', '--output', str(png)], capture_output=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse(png.exists())
        if shutil.which('qrencode'):
            self.assertEqual(json.loads(subprocess.check_output(wifi + ['--network', '1', '--output', str(png)])),
                             {'exported': 1})
            self.assertEqual(stat.S_IMODE(png.stat().st_mode), 0o600)
            self.assertTrue(png.read_bytes().startswith(b'\x89PNG'))
            if shutil.which('zbarimg'):
                decoded = subprocess.check_output(['zbarimg', '--nodbus', '-q', '--raw', str(png)]).strip()
                self.assertEqual(decoded, br'WIFI:S:Lab\;guest;T:WPA;P:fixture\:123;H:true;;')

        vcf = self.root / 'contacts.vcf'
        args = [sys.executable, '-B', str(ROOT / 'tools/android_contacts_vcard.py'), '--password-file',
                str(self.password_file), '--expected-sha256', result['archive_sha256'], str(archive), str(vcf)]
        self.assertEqual(json.loads(subprocess.check_output(args))['contacts'], 1)
        self.assertEqual(vcf.read_bytes().decode(), 'BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Оля\\, Коваль\r\n'
                         'N:Коваль;Оля;;;\r\nTEL:+380000000000\r\nEND:VCARD\r\n')
        self.assertEqual(stat.S_IMODE(vcf.stat().st_mode), 0o600)

        # The portable UI profile must also supply the offline exporters without a full Data copy.
        with self.context.operation_lock():
            portable = migration.create(self.context, self.context.volume('userdata')['volume_token'], [], True,
                                        volume, self.context.volume(volume)['volume_token'], PASSWORD, True,
                                        include_personal=True)
        manifest = portable['manifest']
        self.assertEqual(manifest['schema'], migration.personal.SCHEMA)
        self.assertEqual(next(i for i in manifest['items'] if i['kind'] == 'personal-data'),
                         {'kind': 'personal-data', 'contacts': True, 'wifi_stores': 1,
                          'launchers': ['com.sec.android.app.launcher']})
        self.assertFalse(any('base.apk' in p or 'keystore' in p for p in manifest['files']))
        self.assertIn('personal/com.android.providers.contacts.contacts2.db-wal', manifest['files'])
        packed = str(self.data.parent / 'sd' / portable['path'].lstrip('/'))
        wifi[-2:] = [portable['archive_sha256'], packed]
        self.assertEqual(json.loads(subprocess.check_output(wifi)), json.loads(listing))
        target = self.root / 'portable.vcf'
        args[-3:] = [portable['archive_sha256'], packed, str(target)]
        self.assertEqual(json.loads(subprocess.check_output(args))['contacts'], 1)
        self.assertEqual(target.read_bytes(), vcf.read_bytes())

        code = self.data / 'app/~~example' / APP
        code.mkdir(parents=True)
        (code / 'base.apk').write_bytes(samples['app/installed/base.apk'])
        (self.data / 'system/users/0/settings_system.xml').write_text(
            '<settings><setting name="font_scale" value="1.25"/></settings>')
        with self.context.operation_lock():
            with_apks = migration.create(self.context, self.context.volume('userdata')['volume_token'], [APP], True,
                                         volume, self.context.volume(volume)['volume_token'], PASSWORD, True,
                                         include_personal=True, include_settings=True, include_apks=True)
        manifest = with_apks['manifest']
        self.assertEqual(manifest['schema'], migration.APK_SCHEMA)
        self.assertEqual(manifest['preferences']['system']['font_scale'], '1.25')
        self.assertIn(f'apps/{APP}/apk/base.apk', manifest['files'])
        self.assertIn('personal/com.android.providers.contacts.contacts2.db-wal', manifest['files'])
        packed = str(self.data.parent / 'sd' / with_apks['path'].lstrip('/'))
        wifi[-2:] = [with_apks['archive_sha256'], packed]
        self.assertEqual(json.loads(subprocess.check_output(wifi)), json.loads(listing))
        target = self.root / 'with-apks.vcf'
        args[-3:] = [with_apks['archive_sha256'], packed, str(target)]
        self.assertEqual(json.loads(subprocess.check_output(args))['contacts'], 1)
        self.assertEqual(target.read_bytes(), vcf.read_bytes())

    def test_authenticated_readonly_source_can_back_up_to_external_storage(self):
        self.context.overrides = {'read_only': True, 'write_supported': False}
        self.assertTrue(self.backup()['verified'])
        with self.assertRaises(fs.FilesystemError) as error:
            self.backup(volume='userdata')
        self.assertEqual(error.exception.code, 'ANDROID_RW_REQUIRED')

    def test_portable_settings_with_shared_files_restore(self):
        owner = self.data / 'system/users/0'
        owner.mkdir(parents=True)
        (owner / 'settings_system.xml').write_text('<settings><setting name="font_scale" value="1.25"/>'
                                                  '<setting name="screen_off_timeout" value="bogus"/></settings><namespaceHashes/>')
        (owner / 'settings_secure.xml').write_text('<settings><setting name="android_id" value="local-only"/>'
                                                  '<setting name="long_press_timeout" value="600"/></settings>')
        with self.context.operation_lock():
            result = migration.create(self.context, self.context.volume('userdata')['volume_token'], [], True,
                                      'sdcard-p1', self.context.volume('sdcard-p1')['volume_token'], PASSWORD, True,
                                      include_settings=True)
        self.assertEqual(result['manifest']['preferences'],
                         {'system': {'font_scale': '1.25'}, 'secure': {'long_press_timeout': '600'}})
        self.assertEqual(result['manifest']['schema'], migration.SETTINGS_SCHEMA)
        with self.context.operation_lock():
            restored = migration.restore_shared(self.context, 'sdcard-p1', self.context.volume('sdcard-p1')['volume_token'],
                                                result['path'], result['archive_sha256'],
                                                self.context.volume('userdata')['volume_token'], PASSWORD, True)
        self.assertEqual(restored['schema'], migration.SETTINGS_SCHEMA)
        self.assertGreater(restored['file_bytes'], 0)
        with self.assertRaises(fs.FilesystemError):
            manifest = dict(result['manifest'], preferences={'system': {}, 'secure': {'android_id': 'local-only'}})
            migration.validate_manifest(manifest, manifest['files'])

    def test_creation_failure_clears_its_unpublished_partial(self):
        import shutil
        shutil.rmtree(self.ce)
        shutil.rmtree(self.de)
        with self.assertRaises(fs.FilesystemError) as missing:
            self.backup()
        self.assertEqual(missing.exception.code, 'PACKAGE_DATA_MISSING')
        self.assertEqual(list((self.data.parent / 'sd' / migration.STORE).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
