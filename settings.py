#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recovery preferences and the optional password.

Recovery runs from RAM, so they live in one small file on cache, or on userdata
when cache has no usable filesystem. Cache survives a userdata wipe and an
Android install. A copy in RAM avoids a mount for every read.

Exit 0 means yes or done, 1 means no, 2 an error, 3 kept in RAM until reboot,
4 damaged settings. The password also guards SSH, UART and adb, see access_gate.py.

Settings that cannot be read, or are damaged, never mean "no password" (2026-11-12, audit): the
recovery and the gate stay locked, and nothing is saved over them. Damaged ones can be erased only
together with userdata (reset-damaged), as Android's reset does: whoever holds the phone does not
get past the password and keep the data it guarded. Settings that are not there at all, on a
volume that was read, are the defaults: no password was ever set, or cache was erased, which takes
Download Mode, and that the password cannot cover.
"""
import argparse
import contextlib
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import filesystem as fs
from operation_lock import operation_lock

RAM_COPY = Path(os.environ.get('A22X_SETTINGS_RAM', '/run/a22x-recovery/settings.json'))
RELATIVE = Path('a22x-recovery/settings.json')
THEMES = Path('a22x-recovery/themes')
RAM_THEMES = Path(os.environ.get('A22X_THEMES_RAM', '/run/a22x-recovery/themes'))
VOLUMES = ('cache', 'userdata')
ROUNDS = 120000
# Wi-Fi joins at the start with the lock held; settings that cannot be read lock the recovery now.
LOCK_WAIT = 20.0
# timezone: a tz database zone (Europe/Berlin) for the recovery clock with summer time; empty keeps
# the fixed utc_offset (2026-11-09).
DEFAULTS = {'language': 'en', 'theme': 'graphite', 'terminal': 'auto', 'storage': 'sd', 'vibration': 2, 'timeout': 2, 'utc_offset': 0,
            'refresh': 0, 'brightness': 0, 'animation': 'zoom', 'lock': 1, 'access': 1, 'navigation': 0, 'timezone': '',
            'torch': 0,  # the flashlight's level; 0: not chosen yet
            'android_log': ''}  # the id of the failed start of Android the owner has read about (android_log.py)
TEXT_KEYS = ('language', 'theme', 'terminal', 'storage', 'animation', 'timezone', 'android_log')
ANIMATIONS = ('zoom', 'blur', 'slide', 'fade', 'dissolve', 'off')
HEX = re.compile(r'[0-9a-f]+')


class Unreadable(OSError):
    """Settings that are there but cannot be read now: nothing is known, so nothing opens."""


class Damaged(ValueError):
    """Settings that are there but cannot be read as settings; LABEL names the volume."""
    def __init__(self, message, label=''):
        super().__init__(message)
        self.label = label


def checked(record, label=''):
    """RECORD as settings, or Damaged. A password needs its whole hash and its whole salt."""
    if not isinstance(record, dict):
        raise Damaged('The settings are not a record', label)
    digest, salt = record.get('hash'), record.get('salt')
    if digest is not None or salt is not None:
        if not (isinstance(digest, str) and len(digest) == 64 and HEX.fullmatch(digest)
                and isinstance(salt, str) and len(salt) == 32 and HEX.fullmatch(salt)):
            raise Damaged('The password in the settings is damaged', label)
    return record


def valid(key, value):
    if key == 'language':
        return re.fullmatch(r'[a-z]{2}', value) is not None
    if key == 'theme':
        return re.fullmatch(r'[a-z0-9-]{3,23}', value) is not None
    if key == 'terminal':
        return re.fullmatch(r'[a-z0-9-]{3,23}', value) is not None
    if key == 'storage':
        return value in ('sd', 'usb')
    if key == 'animation':
        return value in ANIMATIONS
    if key == 'android_log':
        return re.fullmatch(r'(?:[0-9a-f]{16})?', value) is not None
    if key == 'timezone':
        return value == '' or (len(value) <= 64 and re.fullmatch(r'[A-Z][A-Za-z_]+(?:/[A-Za-z0-9_+-]+){1,2}', value) is not None)
    if not re.fullmatch(r'-?[0-9]{1,4}', value):
        return False
    number = int(value)
    return {'vibration': 0 <= number <= 3, 'timeout': 0 <= number <= 5,
            'utc_offset': -720 <= number <= 840 and number % 15 == 0,
            'refresh': number in (0, 60, 90), 'brightness': 0 <= number <= 100,
            'lock': 0 <= number <= 2, 'access': number in (0, 1), 'navigation': 0 <= number <= 2,
            'torch': 0 <= number <= 255}.get(key, False)


@contextlib.contextmanager
def volume_root(context, label, mode):
    volume = context.volume(label)
    if volume['mounted']:
        if mode == 'rw' and volume['read_only'] and volume.get('write_supported', True) and volume.get('mount_owner') == 'filesystem':
            # 2026-11-12 review: the list of saved BOOTs leaves cache mounted read-only; a change of
            # the settings then went to userdata, and the older copy on cache won at the next start.
            # The recovery's own read-only mount is opened for writing here and left read-only again.
            context.mount(label, 'rw', True, volume['volume_token'])
            try:
                yield Path(context.volume(label)['mountpoint'])
            finally:
                os.sync()
                with contextlib.suppress(OSError, ValueError, fs.FilesystemError):
                    context.mount(label, 'ro', True, context.volume(label)['volume_token'])
            return
        if mode == 'rw' and (volume['read_only'] or not volume['write_supported']):
            raise OSError('Volume is read-only')
        yield Path(volume['mountpoint'])
        return
    context.mount(label, mode, mode == 'rw', volume['volume_token'])
    try:
        yield Path(context.volume(label)['mountpoint'])
    finally:
        os.sync()
        context.unmount(label)


def copy_themes(root):
    """Themes wait in RAM, so choosing one needs no mount."""
    folder = root / THEMES
    if folder.is_dir():
        RAM_THEMES.mkdir(parents=True, exist_ok=True)
        for theme in (*folder.glob('*.theme'), *folder.glob('*.hidden')):
            if theme.is_file() and not theme.is_symlink():
                shutil.copyfile(theme, RAM_THEMES / theme.name)


def read_disk():
    """Empty only when a volume was really looked into and holds no settings.

    A volume that cannot be found or read is not an empty one: taking it for one
    would show the phone unlocked and let the next save replace the password. Nor is a
    file that is there but damaged (2026-11-12, audit): before, the next volume was
    asked, and userdata without settings unlocked the phone.
    """
    context = fs.DeviceContext()
    opened = False
    with operation_lock(context.lock_path, context.mode):
        for label in VOLUMES:
            try:
                with volume_root(context, label, 'ro') as root:
                    opened = True
                    copy_themes(root)
                    if (root / RELATIVE).is_file():
                        # 2026-11-12 review: a file that cannot be read now (EIO, a busy card) is not a
                        # damaged one: it is no reason to offer erasing userdata, and still opens nothing.
                        try:
                            text = (root / RELATIVE).read_text()
                        except UnicodeDecodeError as error:
                            raise Damaged('The settings on %s are damaged' % label, label) from error
                        except OSError as error:
                            raise Unreadable('The settings on %s cannot be read now' % label) from error
                        try:
                            return checked(json.loads(text), label)
                        except ValueError as error:
                            if isinstance(error, Damaged):
                                raise
                            raise Damaged('The settings on %s are damaged' % label, label) from error
            except (Damaged, Unreadable):
                raise
            except (OSError, ValueError, fs.FilesystemError):
                continue
    if not opened:
        raise OSError('No settings volume could be read')
    return {}


def write_disk(record):
    context = fs.DeviceContext()
    with operation_lock(context.lock_path, context.mode):
        for label in VOLUMES:
            try:
                with volume_root(context, label, 'rw') as root:
                    path = root / RELATIVE
                    path.parent.mkdir(mode=0o700, exist_ok=True)
                    temporary = path.with_suffix('.new')
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    try:
                        os.write(fd, json.dumps(record).encode())
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    temporary.replace(path)
                    return True
            except (OSError, ValueError, fs.FilesystemError):
                continue
    return False


def remember(record):
    RAM_COPY.parent.mkdir(parents=True, exist_ok=True)
    temporary = RAM_COPY.with_suffix('.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, json.dumps(record).encode())
    finally:
        os.close(fd)
    temporary.replace(RAM_COPY)


def load():
    """An unread disk is an error. Taking it for an empty one would lose the password on the next save.
    A damaged copy in RAM is read again from the disk."""
    if RAM_COPY.is_file():
        try:
            return checked(json.loads(RAM_COPY.read_text()))
        except ValueError:
            pass
    deadline = time.monotonic() + LOCK_WAIT
    while True:
        try:
            record = read_disk()
            break
        except BlockingIOError:
            if time.monotonic() > deadline:
                raise
            time.sleep(.1)
    remember(record)
    return record


def store(record):
    remember(record)
    try:
        return 0 if write_disk(record) else 3
    except (OSError, ValueError, fs.FilesystemError):
        return 3


def reset_damaged():
    """Erase damaged settings together with userdata. Exit 1 when the settings are not damaged:
    settings that cannot be read now are no proof. Userdata is erased first, so a stop halfway
    leaves the data gone, never the password; cache is opened for writing before that, so a
    cache that cannot be written stops it before anything is erased."""
    try:
        read_disk()
        return 1
    except Damaged as damaged:
        label = damaged.label
    except OSError:
        return 1
    context = fs.DeviceContext()
    with operation_lock(context.lock_path, context.mode):
        with contextlib.ExitStack() as stack:
            cache = stack.enter_context(volume_root(context, 'cache', 'rw')) if label == 'cache' else None
            volume = context.volume('userdata')
            if volume['mounted']:
                context.unmount('userdata', volume['volume_token'])
                volume = context.volume('userdata')
            context.format('userdata', 'ext4' if volume.get('fs_type') == 'ext4' else 'f2fs', True, volume['volume_token'])
            if cache is not None:
                (cache / RELATIVE).unlink(missing_ok=True)
    RAM_COPY.unlink(missing_ok=True)
    os.sync()
    return 0


def derive(secret, salt):
    return hashlib.pbkdf2_hmac('sha256', secret.encode(), bytes.fromhex(salt), ROUNDS).hex()


def matches(record, path):
    """Whether this file holds the current password; with no password anything does."""
    if not record.get('hash'):
        return True
    if path is None:
        return False
    return hmac.compare_digest(derive(path.read_text().rstrip('\n'), record['salt']), record['hash'])


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('status')
    change = commands.add_parser('set')
    for key in DEFAULTS:
        change.add_argument('--' + key.replace('_', '-'))
    commands.add_parser('verify').add_argument('--secret-file', type=Path, required=True)
    password = commands.add_parser('set-password')
    password.add_argument('--secret-file', type=Path, required=True)
    password.add_argument('--old-secret-file', type=Path)
    commands.add_parser('clear-password').add_argument('--secret-file', type=Path)
    commands.add_parser('reset-damaged')
    args = parser.parse_args()
    if args.command == 'reset-damaged':
        return reset_damaged()
    record = load()
    if args.command == 'status':
        print(json.dumps({**DEFAULTS, **{k: v for k, v in record.items() if k in DEFAULTS}, 'password': bool(record.get('hash')), 'password_digits': bool(record.get('digits'))}))
        return 0
    if args.command == 'set':
        for key in DEFAULTS:
            value = getattr(args, key)
            if value is not None:
                if not valid(key, value):
                    return 2
                record[key] = value if key in TEXT_KEYS else int(value)
        return store(record)
    if args.command == 'clear-password':
        if not matches(record, args.secret_file):
            return 1
        record.pop('hash', None)
        record.pop('salt', None)
        record.pop('digits', None)
        return store(record)
    secret = args.secret_file.read_text().rstrip('\n')
    if args.command == 'set-password':
        if not secret:
            return 2
        if not matches(record, args.old_secret_file):
            return 1
        salt = os.urandom(16).hex()
        record.update(salt=salt, hash=derive(secret, salt), digits=secret.isascii() and secret.isdigit())
        return store(record)
    return 0 if matches(record, args.secret_file) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Damaged as error:
        print(error, file=sys.stderr)
        sys.exit(4)
    except (OSError, ValueError, fs.FilesystemError) as error:
        print(error, file=sys.stderr)
        sys.exit(2)
