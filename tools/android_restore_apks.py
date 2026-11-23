#!/usr/bin/env python3
"""Restore a user-installed Android package and its splits from a verified Data archive."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile
from xml.etree import ElementTree

from android_model_db import ad, copy_members, crypt, fs, migration
import android_package_registry as registry


def run(args, timeout=90):
    return subprocess.check_output(args, text=True, timeout=timeout).strip()


def extract(fd, password, digest, package, directory):
    stamp = ad.identity(os.fstat(fd))
    manifest = migration.verify_fd(fd, password, digest)['manifest']
    if manifest['schema'] == migration.APK_SCHEMA:
        identity = next((item for item in manifest['items'] if item.get('package') == package), None)
        ad.require(identity is not None, 'PACKAGE_NOT_INSTALLED', 'The source package is missing from this backup')
        prefix = f'apps/{package}/apk/'
        selected = {prefix + name: (manifest['files'][prefix + name], directory / name) for name in identity['apks']}
        copy_members(fd, password, selected, portable=True)
        ad.require(ad.identity(os.fstat(fd)) == stamp, 'SOURCE_CHANGED', 'The archive changed during export')
        return identity, {local: item['sha256'] for item, local in selected.values()}
    ad.require(manifest['schema'] == ad.MODEL_SCHEMA, 'APK_COPY_REQUIRED', 'Choose a full Data archive or portable copy containing APKs')
    entries = {entry['path']: entry for entry in manifest['entries']}
    index = entries.get('system/packages.xml', {})
    ad.require(index.get('type') == 'file' and 0 < index['size'] <= registry.MAX_BYTES,
               'REGISTRY_MISSING', 'The Android package registry is missing or too large')
    xml = directory / 'packages.xml'
    copy_members(fd, password, {'payload/system/packages.xml': (index, xml)})
    packages = registry.parse(xml.read_bytes(), {package}, include_code_path=True)['packages']
    ad.require(package in packages, 'PACKAGE_NOT_INSTALLED', 'The source package is missing')
    identity = packages[package]
    folder = identity['code_path'].removeprefix('/data/')
    ad.require(entries.get(folder, {}).get('type') == 'directory', 'APK_DIRECTORY_MISSING',
               'The application code directory is missing')
    selected = {}
    expected = {}
    for path, entry in entries.items():
        parent, _, name = path.rpartition('/')
        if parent != folder or not name.endswith('.apk'):
            continue
        ad.require(entry['type'] == 'file' and entry['size'] > 0, 'INVALID_APK_MEMBER',
                   'Expected a regular APK file in the application code directory')
        local = directory / ('base.apk' if name == 'base.apk' else f'part-{len(selected)}.apk')
        selected['payload/' + path] = (entry, local)
        expected[local] = entry['sha256']
    ad.require(directory / 'base.apk' in expected, 'BASE_APK_MISSING', 'The base APK is missing')
    copy_members(fd, password, selected)
    ad.require(ad.identity(os.fstat(fd)) == stamp, 'SOURCE_CHANGED', 'The archive changed during export')
    return identity, expected


def apk_identity(path, tools, wanted):
    ad.require(run([tools / 'aapt2', 'dump', 'packagename', path]) == wanted['package'],
               'APK_PACKAGE_MISMATCH', 'The manifest package differs from the registry')
    tree = run([tools / 'aapt2', 'dump', 'xmltree', path, '--file', 'AndroidManifest.xml'])
    root = re.search(r'^( *)E: manifest \(line=\d+\)$', tree, re.M)
    ad.require(root is not None, 'APK_MANIFEST_INVALID', 'No Android manifest root')
    attrs = []
    for line in tree[root.end():].splitlines():
        if line.lstrip().startswith('E: '):
            break
        if line.startswith(root[1] + '  A: '):
            attrs.append(line.strip())
    values = {}
    split = ''
    for attr in attrs:
        m = re.fullmatch(r'A: http://schemas.android.com/apk/res/android:(versionCode(?:Major)?)\(0x[0-9a-f]+\)=(0x[0-9a-fA-F]+|[0-9]+)', attr)
        if m:
            values[m[1]] = int(m[2], 0)
        if attr.startswith('A: split='):
            m = re.fullmatch(r'A: split="([A-Za-z0-9_.]+)"(?: \(Raw: "\1"\))?', attr)
            ad.require(m is not None, 'APK_MANIFEST_INVALID', 'Invalid split name')
            split = m[1]
    version = (values.get('versionCodeMajor', 0) << 32) | values.get('versionCode', -1)
    ad.require(version == wanted['version_code'], 'APK_VERSION_MISMATCH', 'APK version differs from the registry')
    result = run([tools / 'apksigner', 'verify', '--print-certs', path])
    signers = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})$', result, re.M)
    ad.require(sorted(signers) == wanted['signers_sha256'], 'APK_SIGNER_MISMATCH',
               'APK signing certificates differ from the installed source package')
    return split


def installed_hashes(adb, user, package):
    def shell(*args):
        return run([*adb, 'shell', shlex.join(args)])
    listed = shell('pm', 'list', 'packages', '--user', user, package).splitlines()
    if 'package:' + package not in listed:
        return []
    paths = shell('pm', 'path', '--user', user, package).splitlines()
    ad.require(paths and all(row.startswith('package:/') for row in paths),
               'TARGET_READBACK_FAILED', 'Could not read the installed APK paths')
    rows = shell('sha256sum', *(line.removeprefix('package:') for line in paths)).splitlines()
    hashes = [row.split(' ', 1)[0] for row in rows]
    ad.require(len(hashes) == len(paths) and all(re.fullmatch('[0-9a-f]{64}', h) for h in hashes),
               'TARGET_READBACK_FAILED', 'Could not verify installed APK bytes')
    return sorted(hashes)


def restore(archive, password, digest, package, tools, serial, user, apply):
    ad.require(registry.PACKAGE.fullmatch(package) and 0 <= user < 2**31,
               'INVALID_TARGET', 'Expected an Android package name and numeric user ID')
    adb = ['adb', '-s', serial]
    user = str(user)
    ad.require(run([*adb, 'shell', 'am', 'get-started-user-state', user]) == 'RUNNING_UNLOCKED',
               'USER_LOCKED', 'Start and unlock the target Android profile')
    fd = fs.open_regular(fs.absolute_no_symlinks(archive))
    try:
        with tempfile.TemporaryDirectory(prefix='.a22x-app-') as tmp:
            identity, files = extract(fd, password, digest, package, Path(tmp))
            splits = {path: apk_identity(path, tools, identity) for path in files}
            ad.require(not splits[Path(tmp) / 'base.apk'] and len(set(splits.values())) == len(splits),
                       'APK_SPLIT_MISMATCH', 'Expected one base APK and unique split names')
            wanted = sorted(files.values())
            current = installed_hashes(adb, user, package)
            ad.require(not current or current == wanted, 'DIFFERENT_APP_INSTALLED',
                       'The target already contains a different build of this application')
            status = 'already_installed' if current else 'would_install'
            if apply and not current:
                paths = sorted(files, key=splits.get)
                run([*adb, 'install-multiple', '--no-incremental', '-R', '--user', user, '--pkg', package,
                     '--install-reason', '2', *paths], timeout=600)
                ad.require(installed_hashes(adb, user, package) == wanted, 'TARGET_READBACK_FAILED',
                           'The package installer returned but the installed APK hashes differ')
                status = 'installed_verified'
            return {'package': package, 'user': int(user), 'version_code': identity['version_code'],
                    'splits': sorted(filter(None, splits.values())), 'status': status}
    finally:
        os.close(fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-tools', required=True, type=Path)
    parser.add_argument('--password-file', required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--user', required=True, type=int)
    parser.add_argument('--package', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('archive')
    args = parser.parse_args()
    try:
        print(json.dumps(restore(args.archive, crypt.read_password(args.password_file), args.expected_sha256,
                                 args.package, args.build_tools.resolve(), args.serial, args.user, args.apply)))
    except (OSError, ValueError, fs.FilesystemError, ElementTree.ParseError, tarfile.TarError,
            subprocess.SubprocessError) as error:
        parser.exit(2, f'{error}\n')
