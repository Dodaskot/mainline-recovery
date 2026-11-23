#!/usr/bin/env python3
"""Restore saved Wi-Fi networks from a verified backup through Android Settings approval."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time
from xml.etree import ElementTree

from android_migration_helper import AndroidHelper, build_helper
from android_wifi_qr import ad, crypt, fs, read_networks

ACTIVITY = 'org.a22x.wifi.ImportWifi'
BATCH_SIZE = 5


def make_plan(records, indexes):
    ad.require(len(set(indexes)) == len(indexes) and all(1 <= index <= len(records) for index in indexes),
               'INVALID_NETWORK', 'Choose distinct indexes from the Wi-Fi backup list')
    selected = set(indexes)
    report, by_ssid = [], defaultdict(list)
    for index, (info, secret) in enumerate(records, 1):
        row = dict(info, index=index)
        report.append(row)
        if selected and index not in selected:
            row['status'] = 'not_selected'
        elif secret is not None:
            password = secret['password']
            minimum = 8 if secret['security'] == 'WPA' else 1
            if password and (not password.isascii() or not minimum <= len(password) <= 63):
                row['status'] = 'passphrase_not_supported_by_android_import'
            else:
                by_ssid[secret['ssid']].append((row, secret))
    pending = []
    for items in by_ssid.values():
        first = items[0][1]
        if any(secret != first for _, secret in items):
            for row, _ in items:
                row['status'] = 'conflicting_backup_entries'
            continue
        pending.append(items[0])
        for row, _ in items[1:]:
            row['status'] = 'duplicate_backup_entry'
    return report, pending


def saved_ssids(android):
    android.check_target()
    android.require_unlocked()
    ad.require(android.shell('am', 'get-current-user') == android.user, 'WIFI_USER_NOT_CURRENT',
               'Switch to the selected Android user before restoring saved networks')
    lines = android.shell('cmd', 'wifi', 'list-networks').splitlines()
    if lines == ['No networks']:
        return set()
    ad.require(lines and lines[0].split() == ['Network', 'Id', 'SSID', 'Security', 'type'],
               'WIFI_TARGET_LIST_UNAVAILABLE', 'Could not read the saved networks on the target device')
    saved = set()
    for line in lines[1:]:
        row = re.fullmatch(r'\s*[0-9]+\s+(.*?)\s+([0-9A-Za-z_+^()/.-]+)\s*', line)
        ad.require(row is not None, 'WIFI_TARGET_LIST_INVALID', 'Could not identify an existing target network')
        saved.add(row[1].strip())
    return saved


def build_importer(root, package, tools, platform):
    manifest = f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="{package}" android:versionCode="1">
      <uses-sdk android:minSdkVersion="30" android:targetSdkVersion="35"/>
      <queries><intent><action android:name="android.settings.WIFI_ADD_NETWORKS"/></intent></queries>
      <application android:label="A22x Wi-Fi restore" android:debuggable="true" android:allowBackup="false">
        <activity android:name="{ACTIVITY}" android:exported="true" android:excludeFromRecents="true"
          android:permission="android.permission.DUMP"/>
      </application>
    </manifest>'''
    source = Path(__file__).resolve().with_name('wifi-importer') / 'ImportWifi.java'
    return build_helper(root, tools, platform, manifest, source)


def ask_settings(android, package, networks, wait_seconds):
    payload = json.dumps({'request': secrets.token_hex(16), 'networks': networks}, ensure_ascii=False).encode()
    digest = android.input(package, 'wifi.json', payload)
    print(f'Confirm up to {len(networks)} Wi-Fi networks in Android Settings.', file=sys.stderr, flush=True)
    launch = android.shell('am', 'start', '-W', '--user', android.user, '-n', package + '/' + ACTIVITY,
                           '--es', 'sha256', digest)
    ad.require(any(line.strip() == 'Status: ok' for line in launch.splitlines()), 'WIFI_IMPORT_LAUNCH_FAILED',
               'Android could not open the Wi-Fi restore helper')
    receipt = 'files/result-' + digest + '.json'
    check = f'if [ -f {receipt} ]; then cat {receipt}; fi'
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        android.check_target()
        output = android.shell('run-as', package, '--user', android.user, 'sh', '-c', check)
        if output:
            result = json.loads(output)
            ad.require(isinstance(result, dict) and result.get('sha256') == digest, 'WIFI_IMPORT_UNVERIFIED',
                       'The Android result does not match the submitted Wi-Fi batch')
            return result
        time.sleep(1)
    return {'status': 'confirmation_timeout'}


def apply(pending, serial, user, tools, platform, wait_seconds, root):
    android = AndroidHelper(serial, user)
    existing = saved_ssids(android)
    remaining = [(row, secret) for row, secret in pending if secret['ssid'].strip() not in existing]
    for row, secret in pending:
        row['status'] = 'already_saved' if secret['ssid'].strip() in existing else 'not_submitted'
    if not remaining:
        return
    package = 'org.a22x.wifi.p' + secrets.token_hex(12)
    apk = build_importer(root, package, tools, platform)
    with android.install(package, apk):
        for offset in range(0, len(remaining), BATCH_SIZE):
            existing = saved_ssids(android)
            portion = remaining[offset:offset + BATCH_SIZE]
            batch = []
            for row, secret in portion:
                if secret['ssid'].strip() in existing:
                    row['status'] = 'already_saved'
                else:
                    batch.append((row, secret))
            if not batch:
                continue
            response = ask_settings(android, package, [secret for _, secret in batch], wait_seconds)
            if response.get('status') != 'processed':
                state = response.get('status')
                if state not in ('cancelled', 'unsupported', 'confirmation_timeout'):
                    state = 'result_unverified'
                for row, _ in batch:
                    row['status'] = state
                break
            codes = response.get('codes')
            ad.require(isinstance(codes, list) and len(codes) == len(batch) and
                       all(type(code) is int and code in (0, 1, 2) for code in codes), 'WIFI_IMPORT_UNVERIFIED',
                       'Android did not report a result for each submitted network')
            saved = saved_ssids(android)
            for (row, secret), code in zip(batch, codes):
                if code == 1:
                    row['status'] = 'rejected_by_android'
                elif secret['ssid'].strip() in saved:
                    row['status'] = 'saved' if code == 0 else 'already_saved'
                else:
                    row['status'] = 'result_unverified'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--password-file', required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--network', action='append', type=int, default=[])
    parser.add_argument('--serial')
    parser.add_argument('--user', type=int, default=0)
    parser.add_argument('--build-tools', type=Path)
    parser.add_argument('--android-jar', type=Path)
    parser.add_argument('--wait-seconds', type=int, default=180)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('archive')
    args = parser.parse_args()
    if not 0 <= args.user < 2**31 or not 1 <= args.wait_seconds <= 900:
        parser.error('Expected a numeric user ID and a confirmation timeout from 1 to 900 seconds')
    if args.apply and not (args.serial and args.build_tools and args.android_jar):
        parser.error('--apply needs --serial, --build-tools and --android-jar')
    try:
        fs.require_hash(args.expected_sha256, 'expected-sha256')
        records = read_networks(args.archive, crypt.read_password(args.password_file), args.expected_sha256)
        report, pending = make_plan(records, args.network)
        if args.apply and pending:
            with tempfile.TemporaryDirectory(prefix='.a22x-wifi-import-') as work:
                apply(pending, args.serial, args.user, args.build_tools, args.android_jar, args.wait_seconds, Path(work))
        print(json.dumps({'verified_archive': True, 'networks': report}, ensure_ascii=True))
        return 2 if args.apply and (not pending or any(row['status'] not in ('saved', 'already_saved') for row, _ in pending)) else 0
    except (OSError, ValueError, fs.FilesystemError, ElementTree.ParseError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(2, f'{getattr(error, "code", "WIFI_IMPORT_ERROR")}: {error}\n')


if __name__ == '__main__':
    raise SystemExit(main())
