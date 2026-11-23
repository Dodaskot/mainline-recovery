#!/usr/bin/env python3
"""List saved owner networks from a model backup or export one network as a Wi-Fi QR code."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from xml.etree import ElementTree

from android_model_db import ad, copy_members, crypt, fs, migration
def quoted(value):
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return ''


def escape(value):
    return re.sub(r'([\\,:;])', r'\\\1', value)


def network_records(data):
    xml = data.decode('utf-8-sig')
    ad.require('<!DOCTYPE' not in xml and '\x00' not in xml, 'WIFI_SCHEMA_UNSUPPORTED', 'Unsupported XML')
    root = ElementTree.fromstring(xml)
    ad.require(root.tag == 'WifiConfigStoreData', 'WIFI_SCHEMA_UNSUPPORTED', 'Unknown Wi-Fi store')
    for cfg in root.findall('NetworkList/Network/WifiConfiguration'):
        stored = cfg.findtext("string[@name='SSID']", '')
        ssid = quoted(stored)
        key = cfg.findtext("string[@name='ConfigKey']", '')
        kind = key[len(stored):].removesuffix('-0') if key.startswith(stored) else ''
        security = {'WPA_PSK': 'WPA', 'SAE': 'SAE', 'NONE': 'nopass'}.get(kind)
        raw = cfg.findtext("string[@name='PreSharedKey']", '')
        password = quoted(raw)
        if security == 'WPA' and re.fullmatch(r'[0-9a-fA-F]{64}', raw):
            password = raw
        reason = None
        if not ssid or len(ssid.encode()) > 32 or not ssid.isprintable():
            reason = 'unsupported_ssid'
        elif not security:
            reason = 'unsupported_security'
        elif cfg.find('PreSharedKey') is not None:
            reason = 'encrypted_key'
        elif security == 'nopass':
            if raw or cfg.find("null[@name='WEPKeys']") is None or cfg.findtext("byte-array[@name='AllowedKeyMgmt']") != '01':
                reason = 'ambiguous_open_network'
        elif not password or not password.isprintable() or password == '*' or (security == 'WPA' and len(password.encode()) < 8):
            reason = 'password_unavailable'
        hidden = cfg.find("boolean[@name='HiddenSSID']")
        hidden_value = hidden.get('value') if hidden is not None else 'false'
        params = cfg.find('SecurityParamsList')
        if security and params is not None:
            enabled = {node.find("int[@name='SecurityType']").get('value') for node in params.findall('SecurityParams')
                       if node.find("int[@name='SecurityType']") is not None
                       and node.find("boolean[@name='IsEnabled'][@value='true']") is not None}
            if {'nopass': '0', 'WPA': '2', 'SAE': '4'}[security] not in enabled:
                reason = 'security_mode_disabled'
        if hidden_value not in ('true', 'false'):
            reason = 'invalid_hidden_flag'
        credentials = None if reason else {'ssid': ssid, 'security': security, 'password': password,
                                            'hidden': hidden_value == 'true'}
        yield {'ssid': ssid, 'security': security, 'status': reason or 'available'}, credentials


def wifi_uri(network):
    hidden = 'true' if network['hidden'] else 'false'
    return (f"WIFI:S:{escape(network['ssid'])};T:{network['security']};"
            f"P:{escape(network['password'])};H:{hidden};;")


def networks(data):
    for info, secret in network_records(data):
        yield info, wifi_uri(secret) if secret is not None else None


def read_networks(archive, password, digest, work_dir=None):
    fd = fs.open_regular(fs.absolute_no_symlinks(archive))
    try:
        before = ad.identity(os.fstat(fd))
        manifest = migration.verify_fd(fd, password, digest)['manifest']
        portable = manifest['schema'] in (migration.personal.SCHEMA, migration.APK_SCHEMA)
        ad.require(portable or manifest['schema'] == ad.MODEL_SCHEMA, 'WIFI_STORE_UNAVAILABLE', 'Choose a backup containing Wi-Fi data')
        entries = manifest['files'] if portable else {entry['path']: entry for entry in manifest['entries']}
        with tempfile.TemporaryDirectory(prefix='.a22x-wifi-', dir=work_dir) as tmp:
            selected = {}
            for index, path in enumerate(migration.personal.WIFI_STORES):
                if portable:
                    path = migration.personal.wifi_name(index)
                if path in entries:
                    entry = entries[path]
                    ad.require(entry['type'] == 'file' and entry['size'] <= 16 * 1024 * 1024,
                               'WIFI_SCHEMA_UNSUPPORTED', 'Unsupported Wi-Fi store type or size')
                    selected[path if portable else 'payload/' + path] = entry, Path(tmp) / str(index)
            ad.require(selected, 'WIFI_STORE_UNAVAILABLE', 'No supported owner Wi-Fi store in the archive')
            copy_members(fd, password, selected, portable=portable)
            records = [record for _, file in selected.values() for record in network_records(file.read_bytes())]
            ad.require(before == ad.identity(os.fstat(fd)), 'SOURCE_CHANGED', 'Archive changed during export')
            return records
    finally:
        os.close(fd)


def export(archive, password, digest, number, output):
    output = fs.absolute_no_symlinks(output, missing=True) if output is not None else None
    records = read_networks(archive, password, digest, output.parent if output is not None else None)
    if output is None:
        return [dict(info, index=n) for n, (info, _) in enumerate(records, 1)]
    ad.require(1 <= number <= len(records), 'INVALID_NETWORK', 'Choose a listed network index')
    info, credentials = records[number - 1]
    ad.require(credentials is not None, 'WIFI_NETWORK_UNAVAILABLE', info['status'])
    with tempfile.TemporaryDirectory(prefix='.a22x-wifi-', dir=output.parent) as temporary:
        png = Path(temporary) / 'qr.png'
        with png.open('xb') as dest:
            os.fchmod(dest.fileno(), 0o600)
            subprocess.run(['qrencode', '-8', '-s', '8', '-o', '-'], input=wifi_uri(credentials).encode(),
                           stdout=dest, check=True)
            dest.flush()
            os.fsync(dest.fileno())
        os.link(png, output)
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return {'exported': number}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--password-file', required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--network', type=int)
    parser.add_argument('--output')
    parser.add_argument('archive')
    args = parser.parse_args()
    if (args.network is None) != (args.output is None):
        parser.error('--network and --output must be provided together')
    try:
        print(json.dumps(export(args.archive, crypt.read_password(args.password_file), args.expected_sha256,
                                args.network, args.output), ensure_ascii=True))
    except (OSError, ValueError, ElementTree.ParseError, tarfile.TarError, subprocess.CalledProcessError,
            fs.FilesystemError) as error:
        parser.exit(2, f'{error}\n')
