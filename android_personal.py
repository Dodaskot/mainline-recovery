"""Fixed Android owner data sources supported by the portable migration exporters."""
import os
import re
import stat
import tarfile
import android_data as ad

SCHEMA = 'a22x.android-migration.v3'
CONTACTS = 'com.android.providers.contacts'
DATABASES = {CONTACTS: 'contacts2.db', 'com.android.launcher3': 'launcher.db',
             'com.google.android.apps.nexuslauncher': 'launcher.db',
             'com.sec.android.app.launcher': 'launcher.db'}
WIFI_STORES = tuple(f'{parent}/{location}/WifiConfigStore.xml'
                    for parent in ('misc', 'misc_ce/0')
                    for location in ('apexdata/com.android.wifi', 'wifi'))
SIDECARS = ('', '-wal', '-journal')


def database_name(package, database):
    return f'personal/{package}.{database}'


def wifi_name(index):
    return f'personal/wifi-{index}.xml'


def supported_database(package, name):
    return (package in DATABASES and (name == DATABASES[package] or
            (package != CONTACTS and re.fullmatch(r'launcher_[1-9][0-9]?_by_[1-9][0-9]?\.db', name) is not None)))


def sources(pin, ce):
    files = {wifi_name(n): path for n, path in enumerate(WIFI_STORES)}
    for package in DATABASES:
        path = f'{ce}/{package}/databases'
        try:
            with pin.directory(path) as directory:
                names = sorted(name for name in os.listdir(directory) if supported_database(package, name))
        except FileNotFoundError:
            continue
        ad.require(len(names) <= 32, 'BACKUP_BOUNDS', 'Too many launcher layout databases')
        for name in names:
            for suffix in SIDECARS:
                files[database_name(package, name) + suffix] = f'{path}/{name}{suffix}'
    return files


def validate(records):
    members = {name: info for name, info in records.items() if name.startswith('personal/')}
    networks = {wifi_name(n) for n in range(len(WIFI_STORES))}
    launchers = set()
    contacts = False
    for path, info in members.items():
        ad.require(info['type'] == 'file', 'MIGRATION_MANIFEST_INVALID', 'Expected a personal data file')
        if path in networks:
            continue
        base = path.removesuffix('-wal').removesuffix('-journal')
        ad.require(base in members and path[len(base):] in SIDECARS, 'DATABASE_UNAVAILABLE', 'Unmatched database journal')
        for package in DATABASES:
            prefix = 'personal/' + package + '.'
            if base.startswith(prefix) and supported_database(package, base[len(prefix):]):
                if package == CONTACTS:
                    contacts = True
                else:
                    launchers.add(package)
                break
        else:
            ad.require(False, 'MIGRATION_MANIFEST_INVALID', 'Unknown personal data member')
    return {'kind': 'personal-data', 'contacts': contacts, 'launchers': sorted(launchers),
            'wifi_stores': len(networks.intersection(members))}


def snapshot(pin, paths):
    found = {}
    for key, path in paths.items():
        try:
            with pin.parent(path) as (parent, name):
                st = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            continue
        ad.require(stat.S_ISREG(st.st_mode), 'PERSONAL_DATA_INVALID', 'Expected a regular personal data file')
        found[key] = ad.identity(st)
    return found


def capture(pin, ce, writer):
    paths = sources(pin, ce)
    stamps = snapshot(pin, paths)
    writer.directory('personal')
    for key, stamp in stamps.items():
        with pin.parent(paths[key]) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, 'rb') as source:
                pin.check_fd(fd)
                st = os.fstat(fd)
                ad.require(ad.identity(st) == stamp, 'SOURCE_CHANGED', 'A migration source was replaced')
                item = tarfile.TarInfo(key)
                item.size, item.mode = st.st_size, 0o600
                payload = ad.HashReader(source, lambda _: writer.progress(writer.done + payload.count, len(writer.records)))
                writer.record(item, payload)
    ad.require(stamps == snapshot(pin, sources(pin, ce)), 'SOURCE_CHANGED', 'A database, journal or Wi-Fi store changed during backup')
    return validate(writer.records)
