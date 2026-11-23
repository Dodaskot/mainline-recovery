#!/usr/bin/env python3
"""Preview or apply an encrypted backup's portable settings to one unlocked Android user."""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tarfile
import tempfile
from xml.etree import ElementTree

from android_model_db import ad, copy_members, crypt, fs, migration
import android_preferences as prefs
import android_package_registry as registry

IO_ERRORS = (OSError, ValueError, fs.FilesystemError, subprocess.SubprocessError)
JOURNAL_SCHEMA = 'a22x.android-settings-restore.v1'


def read_settings(archive, password, digest):
    fd = fs.open_regular(fs.absolute_no_symlinks(archive))
    try:
        stamp = ad.identity(os.fstat(fd))
        manifest = migration.verify_fd(fd, password, digest)['manifest']
        if manifest['schema'] in (migration.SETTINGS_SCHEMA, migration.personal.SCHEMA, migration.APK_SCHEMA) and 'preferences' in manifest:
            return manifest['preferences']
        ad.require(manifest['schema'] == ad.MODEL_SCHEMA, 'SETTINGS_ABSENT',
                   'Choose a settings migration or a full same-model archive')
        entries = {item['path']: item for item in manifest['entries']}
        with tempfile.TemporaryDirectory(prefix='.a22x-settings-') as tmp:
            selected = {}
            for ns in prefs.RULES:
                path = f'system/users/0/settings_{ns}.xml'
                entry = entries.get(path, {})
                ad.require(entry.get('type') == 'file' and 0 < entry['size'] <= registry.MAX_BYTES,
                           'SETTINGS_ABSENT', 'Expected Android owner settings files')
                selected['payload/' + path] = entry, Path(tmp) / ns
            copy_members(fd, password, selected)
            values = {ns: prefs.read((Path(tmp) / ns).read_bytes(), ns) for ns in prefs.RULES}
        ad.require(ad.identity(os.fstat(fd)) == stamp, 'SOURCE_CHANGED', 'The archive changed')
        ad.require(prefs.valid_bundle(values), 'SETTINGS_EMPTY', 'No transferable preferences')
        return values
    finally:
        os.close(fd)


class AndroidSettings:
    def __init__(self, serial, user):
        self.adb = ['adb', '-s', serial, 'shell', '-T']
        self.command = ('settings', '--user', str(user))
        self.user = str(user)

    def shell(self, *args):
        return subprocess.run([*self.adb, shlex.join(args)], capture_output=True, text=True, check=True,
                              timeout=20).stdout.rstrip('\r\n')

    def identity(self):
        state = self.shell('sh', '-ec', '''
            am get-started-user-state "$1"
            getprop ro.serialno
            getprop ro.build.fingerprint
            settings --user "$1" get secure android_id
        ''', 'a22x-settings', self.user).splitlines()
        ad.require(state and state[0] == 'RUNNING_UNLOCKED', 'USER_LOCKED',
                   'Start and unlock the selected Android user first')
        ad.require(len(state) == 4 and state[1] and state[2] and re.fullmatch('[0-9a-fA-F]{1,16}', state[3]),
                   'TARGET_IDENTITY_UNAVAILABLE', 'Could not distinguish the selected Android device and user')
        return fs.digest([self.user, *state[1:]])

    def require_identity(self, identity):
        ad.require(self.identity() == identity, 'TARGET_CHANGED', 'The connected Android device or user changed')

    def read(self, namespace, names):
        current = {}
        output = self.shell(*self.command, 'list', namespace)
        ad.require(not output or '=' in output, 'SETTINGS_READ_INVALID', 'Android did not return a settings list')
        for line in output.splitlines():
            name, separator, value = line.partition('=')
            if separator and name in names:
                ad.require(name not in current, 'SETTINGS_READ_INVALID', 'Android returned duplicate setting names')
                current[name] = value
        return current

    def before(self, entry):
        ns, name = entry['namespace'], entry['name']
        return self.read(ns, {name}).get(name)

    def write(self, entry, value):
        ns, name = entry['namespace'], entry['name']
        if value is None:
            self.shell(*self.command, 'delete', ns, name)
        else:
            self.shell(*self.command, 'put', ns, name, value)


@contextlib.contextmanager
def locked_journal(identity, state_dir):
    if state_dir is None:
        state_dir = Path(os.environ.get('XDG_STATE_HOME') or Path.home() / '.local/state') / 'a22x-recovery/settings'
    directory = fs.absolute_no_symlinks(state_dir, missing=True)
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.stat()
    ad.require(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077,
               'SETTINGS_STATE_PERMISSIONS', 'Use a private directory for the settings recovery journal')
    fd = os.open(directory / (identity + '.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        ad.require(stat.S_ISREG(os.fstat(fd).st_mode), 'SETTINGS_STATE_INVALID', 'Expected a regular lock file')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fs.fail('SETTINGS_BUSY', 'A settings operation on this Android user is in progress')
        yield directory / (identity + '.json')
    finally:
        os.close(fd)


def save_journal(path, state):
    if state is None:
        path.unlink()
    else:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.settings-', delete=False) as out:
            temporary = Path(out.name)
            try:
                out.write(json.dumps(state, ensure_ascii=True).encode())
                out.flush()
                os.fsync(out.fileno())
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def usable_previous(value):
    return value is None or isinstance(value, str) and len(value) <= 64 and (not value or value.isprintable())


def undo(target, path, state):
    target.require_identity(state['target'])
    conflicts = []
    for entry in reversed(state['attempted'][:]):
        current = target.before(entry)
        if current != entry['before']:
            if current != entry['value']:
                conflicts.append(entry['namespace'] + '.' + entry['name'])
                continue
            target.require_identity(state['target'])
            if target.before(entry) != current:
                conflicts.append(entry['namespace'] + '.' + entry['name'])
                continue
            target.write(entry, entry['before'])
            ad.require(target.before(entry) == entry['before'], 'SETTINGS_ROLLBACK_REJECTED',
                       'Android did not restore the original setting')
        state['attempted'].remove(entry)
        save_journal(path, state)
    ad.require(not conflicts, 'SETTINGS_ROLLBACK_CONFLICT', 'Settings changed separately: ' + ', '.join(conflicts))
    save_journal(path, None)


def rollback(serial, user, state_dir=None):
    target = AndroidSettings(serial, user)
    identity = target.identity()
    with locked_journal(identity, state_dir) as path:
        try:
            state = fs.regular_json(path, maximum=65536)
        except FileNotFoundError:
            return {'status': 'nothing_pending', 'checked': 0}
        ad.require(isinstance(state, dict) and state.get('schema') == JOURNAL_SCHEMA and isinstance(state.get('attempted'), list),
                   'SETTINGS_STATE_INVALID', 'Invalid settings recovery journal')
        fs.require_hash(state.get('target'), 'settings-target')
        seen = set()
        for entry in state['attempted']:
            ad.require(isinstance(entry, dict) and set(entry) == {'namespace', 'name', 'value', 'before'} and
                       isinstance(entry['namespace'], str) and entry['namespace'] in prefs.RULES and
                       isinstance(entry['name'], str) and prefs.valid(entry['namespace'], entry['name'], entry['value']) and
                       usable_previous(entry['before']), 'SETTINGS_STATE_INVALID', 'Invalid setting in the recovery journal')
            key = entry['namespace'], entry['name']
            ad.require(key not in seen, 'SETTINGS_STATE_INVALID', 'Repeated setting in the recovery journal')
            seen.add(key)
        count = len(state['attempted'])
        undo(target, path, state)
        return {'status': 'rolled_back', 'checked': count}


def transfer(values, serial, user, apply, state_dir=None):
    ad.require(prefs.valid_bundle(values), 'SETTINGS_EMPTY', 'No validated transferable Android preferences')
    target = AndroidSettings(serial, user)
    identity = target.identity()
    report = []
    with locked_journal(identity, state_dir) if apply else contextlib.nullcontext() as journal:
        if apply:
            ad.require(not os.path.lexists(journal), 'SETTINGS_RECOVERY_PENDING',
                       'An earlier write is unresolved. Run --rollback for the same device and user')
        for ns, items in values.items():
            snapshot = target.read(ns, items)
            for name, desired in sorted(items.items()):
                previous = snapshot.get(name)
                ad.require(usable_previous(previous), 'SETTINGS_READ_INVALID', 'Could not preserve the current setting')
                report.append({'namespace': ns, 'name': name, 'value': desired, 'before': previous,
                               'status': 'already_set' if previous == desired else 'would_change'})
        target.require_identity(identity)
        changes = [entry for entry in report if entry['status'] == 'would_change']
        if not apply or not changes:
            return report
        transaction = {'schema': JOURNAL_SCHEMA, 'target': identity, 'attempted': []}
        save_journal(journal, transaction)
        try:
            for entry in changes:
                target.require_identity(identity)
                ad.require(target.before(entry) == entry['before'], 'SETTINGS_TARGET_CHANGED',
                           'A setting changed after the preview')
                transaction['attempted'].append({key: value for key, value in entry.items() if key != 'status'})
                save_journal(journal, transaction)
                if target.before(entry) != entry['before']:
                    transaction['attempted'].pop()
                    save_journal(journal, transaction)
                    fs.fail('SETTINGS_TARGET_CHANGED', 'A setting changed before the write could start')
                target.write(entry, entry['value'])
                ad.require(target.before(entry) == entry['value'], 'SETTINGS_WRITE_REJECTED',
                           'Android did not retain ' + entry['namespace'] + '.' + entry['name'])
                entry['status'] = 'verified'
            target.require_identity(identity)
            for ns in values:
                ad.require(target.read(ns, values[ns]) == values[ns], 'SETTINGS_TARGET_CHANGED',
                           'Settings changed during final verification')
        except (KeyboardInterrupt, *IO_ERRORS) as error:
            try:
                undo(target, journal, transaction)
            except IO_ERRORS as recovery_error:
                fs.fail('SETTINGS_RECOVERY_PENDING',
                        f'Rollback remains pending: {recovery_error}. Run --rollback for the same device and user')
            fs.fail('SETTINGS_ROLLED_BACK', f'Original settings restored after the write failed: {error}')
        save_journal(journal, None)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--password-file')
    parser.add_argument('--expected-sha256')
    parser.add_argument('--serial', required=True)
    parser.add_argument('--user', required=True, type=int)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--rollback', action='store_true')
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('archive', nargs='?')
    args = parser.parse_args()
    if not 0 <= args.user < 2**31:
        parser.error('Expected a numeric Android user ID')
    if args.rollback and any((args.archive, args.password_file, args.expected_sha256)):
        parser.error('--rollback uses the saved journal with the selected serial and user')
    if not args.rollback and not all((args.archive, args.password_file, args.expected_sha256)):
        parser.error('Expected an archive, --password-file and --expected-sha256')
    try:
        if args.rollback:
            report = rollback(args.serial, args.user, args.state_dir)
        else:
            fs.require_hash(args.expected_sha256, 'expected-sha256')
            values = read_settings(args.archive, crypt.read_password(args.password_file), args.expected_sha256)
            report = {'entries': transfer(values, args.serial, args.user, args.apply, args.state_dir)}
        print(json.dumps({'serial': args.serial, 'user': args.user, **report}, ensure_ascii=True))
    except (*IO_ERRORS, tarfile.TarError, ElementTree.ParseError) as error:
        parser.exit(2, f'{getattr(error, "code", "SETTINGS_IO_ERROR")}: {error}\n')
