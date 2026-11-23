#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Apps and Wi-Fi of a migration archive put back by the new Android itself (2026-11-20, the owner:
stable data transfer and restore onto different systems).

Before the first start of a new system (its data freshly formatted, nothing encrypted yet), this
recovery stages what the next system has to take back under /data/adb/a22x-migration/restore:

    apps.list                 one package per line, in the archive's order
    apps/PKG/apk/*.apk        the archive's base and split APKs
    apps/PKG/ce.tar, de.tar   the app's credential- and device-encrypted files, relative to its folder
    wifi.list                 SSID<TAB>open|wpa2|wpa3<TAB>passphrase, from the archive's WifiConfigStore
    contacts/contacts2.db     the earlier system's contacts database (and its -wal, -journal)
    agent.dex                 migration_agent.dex (tools/migration_agent), which reads that database

The one-time script (android_root_adb.apply_script) then runs, as root after the start, the lines of
script_lines(): every app not installed yet is installed through Android's package manager from its
APKs (`pm install-create/-write/-commit`, the bytes through a pipe), stopped, its files unpacked into
the folders Android made for it, given its new uid and labelled by restorecon; every network is
added with `cmd wifi add-network`; the contacts are inserted through the new system's contacts
provider by agent.dex under app_process, as local contacts. Android does the writing, so no write access to the new system's
encrypted data is needed, and the uids, labels and package records are the new system's own.
Everything staged is removed with the script."""
import io
import os
import re
import stat
import tarfile
from xml.etree import ElementTree as ET

import android_data as ad
import filesystem as fs

RESTORE = 'restore'
PACKAGE = re.compile(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+')
APK = re.compile(r'(?:base|split_[A-Za-z0-9_.-]{1,96})\.apk')
WIFI_MEMBER = re.compile(r'personal/wifi-[0-9]+\.xml')
CONTACTS_MEMBER = re.compile(r'personal/com\.android\.providers\.contacts\.contacts2\.db(-wal|-journal)?')
AGENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'migration_agent.dex')
SSID_LIMIT = 32


def wifi_networks(xml):
    """(ssid, security, passphrase) of the saved networks in a WifiConfigStore.xml; networks whose
    secret is not stored in the clear (enterprise, keystore-encrypted) are left out."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    found = []
    for network in root.iter('Network'):
        config = network.find('WifiConfiguration')
        if config is None:
            continue
        values = {item.get('name'): (item.text or '') for item in config if item.tag == 'string'}
        ssid = values.get('SSID', '')
        if not (len(ssid) >= 2 and ssid[0] == ssid[-1] == '"'):
            continue  # a hexadecimal SSID is not carried
        ssid = ssid[1:-1]
        key = values.get('PreSharedKey')
        config_key = values.get('ConfigKey', '')
        if key and len(key) >= 2 and key[0] == key[-1] == '"':
            security = 'wpa3' if config_key.endswith('SAE') else 'wpa2'
            secret = key[1:-1]
        elif key is None and config_key.endswith('NONE'):
            security, secret = 'open', ''
        else:
            continue
        if (0 < len(ssid.encode()) <= SSID_LIMIT and '\t' not in ssid + secret and '\n' not in ssid + secret
                and (security == 'open' or 8 <= len(secret) <= 63)):
            found.append((ssid, security, secret))
    return found


RECOVERY_SSID = re.compile(r'(?:[0-9a-f]{2}){1,32}')
RECOVERY_KEY = re.compile(r'[0-9a-f]{64}')


class Stager:
    """Writes the staged files into the pinned, fresh target data while the archive streams by."""

    def __init__(self, context, pin, manifest, folder, apps=True, wifi=True, contacts=True, recovery_networks=()):
        self.context, self.pin, self.manifest = context, pin, manifest
        self.apps = [item['package'] for item in manifest['items'] if item.get('kind') == 'app-data'] if apps else []
        ad.require(all(PACKAGE.fullmatch(name) for name in self.apps), 'MIGRATION_MANIFEST_INVALID', 'Unexpected package name')
        self.want_wifi, self.want_contacts, self.contacts = wifi, contacts, False
        self.folder = folder  # an open directory descriptor: /data/adb/a22x-migration
        self.root = self._dir(folder, RESTORE)
        self.tars, self.files, self.networks = {}, [], []
        self.app_dirs = {}
        # The recovery's own saved networks (2026-11-21, the owner: as the Linux installer carries them):
        # (SSID in hex, WPA key in hex or ''), added by the agent at the first start.
        self.recovery_networks = [(ssid, key) for ssid, key in recovery_networks
                                  if RECOVERY_SSID.fullmatch(ssid) and (key == '' or RECOVERY_KEY.fullmatch(key))]

    def _dir(self, parent, name):
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        self.pin.check_fd(fd)
        return fd

    def _app(self, package):
        if package not in self.app_dirs:
            apps = self.app_dirs.get(None) or self._dir(self.root, 'apps')
            self.app_dirs[None] = apps
            self.app_dirs[package] = self._dir(apps, package)
        return self.app_dirs[package]

    def wants(self, parts):
        if len(parts) >= 3 and parts[0] == 'apps' and parts[1] in self.apps:
            return parts[2] in ('apk', 'ce', 'de')
        name = '/'.join(parts)
        return ((self.want_wifi and WIFI_MEMBER.fullmatch(name) is not None)
                or (self.want_contacts and CONTACTS_MEMBER.fullmatch(name) is not None))

    def take(self, parts, entry, read):
        """One archive member; READ(n) gives its next bytes (the caller checks their digest after)."""
        if parts[0] == 'personal':
            match = CONTACTS_MEMBER.fullmatch('/'.join(parts))
            if match and entry.isfile():
                folder = self._dir(self.root, 'contacts')
                try:
                    stream_write(folder, 'contacts2.db' + (match.group(1) or ''), read, entry.size)
                finally:
                    os.close(folder)
                self.contacts = self.contacts or match.group(1) is None
            elif entry.isfile():
                self.networks += [n for n in wifi_networks(drain(read, entry.size, 4 << 20)) if n not in self.networks]
            return
        package, scope, rest = parts[1], parts[2], parts[3:]
        app = self._app(package)
        if scope == 'apk':
            if entry.isfile() and len(rest) == 1 and APK.fullmatch(rest[0]):
                apk = self._dir(app, 'apk')
                try:
                    stream_write(apk, rest[0], read, entry.size)
                finally:
                    os.close(apk)
            return
        if not rest:
            return
        tar = self.tars.get((package, scope))
        if tar is None:
            fd = os.open(scope + '.tar', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=app)
            self.pin.check_fd(fd)
            out = os.fdopen(fd, 'wb')
            tar = (out, tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT))
            self.tars[(package, scope)] = tar
        info = tarfile.TarInfo('/'.join(rest))
        info.mode = entry.mode & 0o7777
        info.mtime = entry.mtime
        if entry.isdir():
            info.type = tarfile.DIRTYPE
            tar[1].addfile(info)
        elif entry.isfile():
            info.size = entry.size
            tar[1].addfile(info, _Reader(read, entry.size))

    def finish(self):
        for out, tar in self.tars.values():
            tar.close()
            out.flush()
            os.fsync(out.fileno())
            out.close()
        staged = [package for package in self.apps if package in self.app_dirs]
        fs_write(self.root, 'apps.list', ''.join(name + '\n' for name in staged).encode())
        fs_write(self.root, 'wifi.list', ''.join('\t'.join(n) + '\n' for n in self.networks).encode())
        carried = {n[0].encode().hex() for n in self.networks}  # the archive's own entry (its passphrase) wins
        recovery = [n for n in self.recovery_networks if n[0] not in carried]
        fs_write(self.root, 'recovery-wifi.list', ''.join('\t'.join(n) + '\n' for n in recovery).encode())
        if self.contacts or recovery:
            with open(AGENT, 'rb') as agent:
                fs_write(self.root, 'agent.dex', agent.read())
        for key, fd in list(self.app_dirs.items()):
            os.close(fd)
        self.app_dirs.clear()
        os.fsync(self.root)
        os.close(self.root)
        return {'apps': staged, 'wifi_networks': len(self.networks), 'contacts': self.contacts, 'recovery_wifi': len(recovery)}


class _Reader:
    """A file object over READ(n) for exactly SIZE bytes (tarfile reads its member through it)."""
    def __init__(self, read, size):
        self._read, self.left = read, size

    def read(self, n=-1):
        n = self.left if n is None or n < 0 else min(n, self.left)
        if n <= 0:
            return b''
        data = self._read(n)
        self.left -= len(data)
        return data


def drain(read, size, limit):
    ad.require(size <= limit, 'BACKUP_BOUNDS', 'A staged entry is larger than expected')
    data = bytearray()
    while len(data) < size:
        chunk = read(min(1 << 20, size - len(data)))
        ad.require(chunk, 'SOURCE_CHANGED', 'The archive ended inside an entry')
        data += chunk
    return bytes(data)


def stream_write(directory, name, read, size):
    partial = '.' + name + '.partial'
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        done = 0
        while done < size:
            chunk = read(min(1 << 20, size - done))
            ad.require(chunk, 'SOURCE_CHANGED', 'The archive ended inside an entry')
            view = memoryview(chunk)
            while view:
                view = view[os.write(fd, view):]
            done += len(chunk)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(partial, name, src_dir_fd=directory, dst_dir_fd=directory)


def fs_write(directory, name, data):
    partial = '.' + name + '.partial'
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(partial, name, src_dir_fd=directory, dst_dir_fd=directory)


def script_lines():
    """The part of the one-time script that puts the staged apps and networks back (root, after the
    start, with the user unlocked: a new system without a lock screen unlocks at its start).

    The lists are read on descriptor 3 (2026-11-21, crDroid 12): pm, am and cmd hand their stdin to
    the system server, which may not read a file of /data/adb, so a loop over a staged list on stdin
    made every one of them fail ("Failed transaction")."""
    return [
        'R="$D/' + RESTORE + '"',
        'if [ -s "$R/apps.list" ]; then',
        '  until [ "$(am get-started-user-state 0 2>/dev/null)" = RUNNING_UNLOCKED ]; do sleep 3; done',
        '  while IFS= read -r pkg <&3; do',
        '    A="$R/apps/$pkg"',
        '    if ! pm path "$pkg" >/dev/null 2>&1 && [ -f "$A/apk/base.apk" ]; then',
        '      total=$(cat "$A"/apk/*.apk | wc -c)',
        '      sid=$(pm install-create -r -S "$total" | sed -n \'s/.*\\[\\([0-9]*\\)\\].*/\\1/p\')',
        '      for f in "$A"/apk/*.apk; do cat "$f" | pm install-write -S "$(stat -c %s "$f")" "$sid" "$(basename "$f")" -; done',
        '      pm install-commit "$sid"',
        '    fi',
        '    pm path "$pkg" >/dev/null 2>&1 || { echo "app $pkg: not installed"; continue; }',
        '    am force-stop "$pkg"',
        '    for scope in ce de; do',
        '      [ -f "$A/$scope.tar" ] || continue',
        '      base=/data/data; [ "$scope" = de ] && base=/data/user_de/0',
        '      [ -d "$base/$pkg" ] || { echo "app $pkg: no $scope folder"; continue; }',
        '      uid=$(stat -c %u "$base/$pkg")',
        '      tar -xf "$A/$scope.tar" -C "$base/$pkg"',
        '      find "$base/$pkg" -mindepth 1 -maxdepth 1 ! -name cache ! -name code_cache -exec chown -R "$uid:$uid" {} +',
        '      restorecon -RF "$base/$pkg"',
        # restorecon knows no app's categories (2026-11-21, Evolution X: restored files stayed s0 beside
        # the folder's s0:c118,c257,..., so the app could read them but not write them). The folder's
        # own context, which Android made for this app, goes to what was restored.
        '      ctx=$(ls -dZ "$base/$pkg" | cut -d" " -f1)',
        '      case "$ctx" in u:*:s0:c*) find "$base/$pkg" -mindepth 1 -maxdepth 1 ! -name cache ! -name code_cache -exec chcon -R "$ctx" {} + ;; esac',
        '    done',
        '    echo "app $pkg: restored"',
        '  done 3< "$R/apps.list"',
        'fi',
        'if [ -s "$R/contacts/contacts2.db" ] && [ -s "$R/agent.dex" ]; then',
        '  CLASSPATH="$R/agent.dex" app_process /system/bin org.a22x.migration.Agent contacts "$R/contacts/contacts2.db"',
        'fi',
        # The recovery's networks: their keys are hex, which only the agent can hand to Android.
        'if [ -s "$R/recovery-wifi.list" ] && [ -s "$R/agent.dex" ]; then',
        '  while IFS="$(printf \'\\t\')" read -r ssid key <&3; do',
        '    CLASSPATH="$R/agent.dex" app_process /system/bin org.a22x.migration.Agent wifi "$ssid" "$key" >/dev/null && echo "wifi network added from recovery"',
        '  done 3< "$R/recovery-wifi.list"',
        'fi',
        'if [ -s "$R/wifi.list" ]; then',
        '  while IFS="$(printf \'\\t\')" read -r ssid sec pass <&3; do',
        '    if [ "$sec" = open ]; then cmd wifi add-network "$ssid" open; else cmd wifi add-network "$ssid" "$sec" "$pass"; fi',
        '    echo "wifi network added"',
        '  done 3< "$R/wifi.list"',
        'fi',
    ]
