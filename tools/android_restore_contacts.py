#!/usr/bin/env python3
"""Restore local names, phone numbers and email addresses from an authenticated Android backup."""
import argparse
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tarfile
import tempfile

from android_contacts_vcard import contacts
from android_migration_helper import AndroidHelper, build_helper
from android_model_db import ad, crypt, export_database, fs

IMPORTER = 'org.a22x.contacts.ImportContacts'


def contact_payload(db, out):
    count = size = 0
    out.write(b'[')
    for display, name, fields in contacts(db):
        entry = json.dumps({'display': display, 'name': name,
                            'phones': [value for field, value in fields if field == 'TEL'],
                            'emails': [value for field, value in fields if field == 'EMAIL']},
                           ensure_ascii=False, separators=(',', ':')).encode()
        ad.require(len(entry) <= 64000 and size + len(entry) + 1 <= (32 << 20) - 2,
                   'CONTACTS_TOO_LARGE', 'The contact list or an individual contact exceeds the import limit')
        if count:
            out.write(b',')
        out.write(entry)
        size += len(entry) + 1
        count += 1
    out.write(b']')
    ad.require(count > 0, 'NO_CONTACTS', 'No local names, phone numbers or email addresses found')
    return count


def build_importer(root, package, tools, platform):
    manifest = f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="{package}" android:versionCode="1">
      <uses-sdk android:minSdkVersion="30" android:targetSdkVersion="35"/>
      <uses-permission android:name="android.permission.READ_CONTACTS"/>
      <uses-permission android:name="android.permission.WRITE_CONTACTS"/>
      <application android:label="A22x contacts restore" android:debuggable="true" android:allowBackup="false"/>
      <instrumentation android:name="{IMPORTER}" android:targetPackage="{package}"/>
    </manifest>'''
    source = Path(__file__).resolve().with_name('contact-importer') / 'ImportContacts.java'
    return build_helper(root, tools, platform, manifest, source)

def import_contacts(payload, expected, serial, user, tools, platform, root):
    android = AndroidHelper(serial, user)
    package = 'org.a22x.contacts.p' + secrets.token_hex(12)
    apk = build_importer(root, package, tools, platform)
    with android.install(package, apk, grant=True):
        digest = android.input(package, 'contacts.json', payload)
        android.check_target()
        reply = android.shell('am', 'instrument', '--user', android.user, '-w', '-r', '-e', 'sha256',
                              digest, package + '/' + IMPORTER, timeout=300)
        messages = [line.removeprefix('INSTRUMENTATION_RESULT: a22x_result=') for line in reply.splitlines()
                    if line.startswith('INSTRUMENTATION_RESULT: a22x_result=')]
        errors = [line.removeprefix('INSTRUMENTATION_RESULT: a22x_error=') for line in reply.splitlines()
                  if line.startswith('INSTRUMENTATION_RESULT: a22x_error=')]
        ad.require(len(messages) == 1 and 'INSTRUMENTATION_CODE: -1' in reply.splitlines(), 'CONTACT_IMPORT_FAILED',
                   'Android rejected or could not verify the contact import' + (f' ({errors[0]})' if errors else ''))
        result = json.loads(messages[0])
        ad.require(result.get('verified') is True and result.get('contacts') == expected and
                   all(type(result.get(key)) is int and 0 <= result[key] <= expected for key in ('inserted', 'already_present')) and
                   result['inserted'] + result['already_present'] == expected, 'CONTACT_IMPORT_UNVERIFIED',
                   'The Contacts Provider result does not account for every input contact')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--password-file', required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--serial')
    parser.add_argument('--user', type=int, default=0)
    parser.add_argument('--build-tools', type=Path)
    parser.add_argument('--android-jar', type=Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('archive')
    args = parser.parse_args()
    if not 0 <= args.user < 2**31:
        parser.error('Expected a numeric Android user ID')
    if args.apply and not (args.serial and args.build_tools and args.android_jar):
        parser.error('--apply needs --serial, --build-tools and --android-jar')
    try:
        fs.require_hash(args.expected_sha256, 'expected-sha256')
        with tempfile.TemporaryDirectory(prefix='.a22x-contacts-') as directory:
            root = Path(directory)
            output = root / 'contacts.json'
            count = export_database(args.archive, crypt.read_password(args.password_file), output, args.expected_sha256,
                                    'com.android.providers.contacts', 'contacts2.db', contact_payload)
            report = {'contacts': count, 'verified': True, 'status': 'would_import'}
            if args.apply:
                result = import_contacts(output.read_bytes(), count, args.serial, args.user, args.build_tools, args.android_jar, root)
                report = {**result, 'status': 'imported_verified', 'serial': args.serial, 'user': args.user}
        print(json.dumps(report, ensure_ascii=True))
    except (OSError, ValueError, sqlite3.Error, fs.FilesystemError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(2, f'{error}\n')


if __name__ == '__main__':
    main()
