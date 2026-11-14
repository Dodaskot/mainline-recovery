#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recovery preferences and the optional password.

Recovery runs from RAM, so they live in one small file on cache, or on userdata
when cache has no filesystem this recovery can ever write (see choose()). Cache
survives a userdata wipe and an Android install. A copy in RAM avoids a mount for
every read, and holds a save the volume cannot take at this moment (exit 3).

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
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
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
    """Themes wait in RAM, so choosing one needs no mount. A theme that cannot be copied (EIO, a full
    /run) is left out: it says nothing about the settings, and read_disk must not take it for
    settings that cannot be read (2026-11-14 review: the phone stayed locked at every start)."""
    folder = root / THEMES
    try:
        if not folder.is_dir():
            return
        RAM_THEMES.mkdir(parents=True, exist_ok=True)
        themes = (*folder.glob('*.theme'), *folder.glob('*.hidden'))
    except OSError:
        return
    for theme in themes:
        with contextlib.suppress(OSError):
            if theme.is_file() and not theme.is_symlink():
                shutil.copyfile(theme, RAM_THEMES / theme.name)


def present(path):
    """Whether PATH is a regular file: False only when nothing is there; any other failure to look
    (EIO, EACCES, a damaged inode) is raised (2026-11-14 review: Path.is_file() answers False to
    every error). For a file this recovery ships or keeps in RAM; settings are looked at by entry()."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


def entry(path):
    """Whether anything is at PATH, as the settings file: False only when nothing is (ENOENT); a
    folder, a link, a FIFO, or a file where a folder of the path should be, all count as there, to
    be read and found damaged; any other failure to look is raised (2026-11-14 reviews: an error,
    then anything that was no regular file, read as no settings, and the phone opened without
    its password)."""
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False
    except NotADirectoryError:
        return True


def read_regular(path, label):
    """The text of the settings file at PATH on LABEL: None when nothing is there; Damaged when what
    is there is no regular file or no text; Unreadable when it cannot be read now. Opened as
    filesystem.open_regular opens: its type proven on the descriptor, links never followed, so
    nothing changes between the look and the read (2026-11-14 review)."""
    try:
        fd = fs.open_regular(path)
    except FileNotFoundError:
        return None
    except NotADirectoryError as error:
        raise Damaged('The settings on %s are damaged' % label, label) from error
    except fs.FilesystemError as error:
        if error.code == 'REGULAR_FILE_REQUIRED':
            raise Damaged('The settings on %s are damaged' % label, label) from error
        raise Unreadable('The settings on %s cannot be read now' % label) from error
    except OSError as error:
        if error.errno == errno.ELOOP:  # a link where the file should be
            raise Damaged('The settings on %s are damaged' % label, label) from error
        raise Unreadable('The settings on %s cannot be read now' % label) from error
    try:
        with os.fdopen(fd, 'rb') as stream:
            data = stream.read()
    except OSError as error:
        raise Unreadable('The settings on %s cannot be read now' % label) from error
    try:
        return data.decode()
    except UnicodeDecodeError as error:
        raise Damaged('The settings on %s are damaged' % label, label) from error


def read_disk():
    """Empty only when a volume was really looked into and holds no settings.

    A volume that cannot be found or read is not an empty one: taking it for one
    would show the phone unlocked and let the next save replace the password. Nor is a
    file that is there but damaged (2026-11-12, audit): before, the next volume was
    asked, and userdata without settings unlocked the phone. The volume is the one
    settings_root chooses, by the same rule as every write (2026-11-14 review: two
    copies of the rule).
    """
    context = fs.DeviceContext()
    with operation_lock(context.lock_path, context.mode):
        try:
            # The themes of every volume looked at, as before (2026-11-14 review: only the chosen one's).
            with settings_root(context, 'ro', visit=copy_themes) as (label, root):
                # 2026-11-12 review: a file that cannot be read now (EIO, a busy card) is not a
                # damaged one: it is no reason to offer erasing userdata, and still opens nothing.
                text = read_regular(root / RELATIVE, label)
                if text is None:
                    return {}
                try:
                    return checked(json.loads(text), label)
                except ValueError as error:
                    if isinstance(error, Damaged):
                        raise
                    raise Damaged('The settings on %s are damaged' % label, label) from error
        except (Damaged, Unreadable, NoSettingsVolume):
            raise
        except (OSError, ValueError, fs.FilesystemError) as error:
            raise Unreadable('The settings volume cannot be read now') from error


# A volume whose filesystem this recovery never writes: its read_only_reason_code (filesystem.py)
# is a property of the filesystem, not of the moment (Android's encryption, erofs, a verified
# Android filesystem). Any other reason a volume cannot be written now passes (2026-11-14 review:
# write_supported is also False while another owner has it mounted, or a guard was lost).
NEVER_WRITABLE = frozenset({'FSCRYPT_KEYS_UNAVAILABLE', 'READ_ONLY_FILESYSTEM', 'VERIFIED_ANDROID_FILESYSTEM_RW_NOT_QUALIFIED'})


class NoSettingsVolume(OSError):
    """No volume is there that could hold the settings."""


def choose(states, mode):
    """The volume the settings are read from ('ro') or written to ('rw'), from STATES: in the
    order of VOLUMES, (label, there, holds, write) for each volume looked at, where HOLDS is
    True, False or None (the volume could not be looked at) and WRITE is 'now', 'later' (not
    writable at this moment, for whatever reason) or 'never' (NEVER_WRITABLE).

    One rule, the one every start reads by (read_disk uses it too; 2026-11-14, four reviews of
    four attempts): volumes not there are passed over; the first that holds the file is where the
    settings are; a volume that cannot be looked at before that is Unreadable. When no volume
    holds them, the place for them is the first volume there that can ever take them. Settings
    are written only there, and only when it can be written now; a volume that can take them only
    later is no reason to put them elsewhere: Unreadable, the caller keeps them in RAM and tries
    again. Tested against every pair of states in tests/test_settings_damaged.py."""
    target = fallback = None
    for label, there, holds, write in states:
        if not there:
            continue
        if holds is None:
            raise Unreadable('The settings volume %s cannot be read now' % label)
        if holds:
            target = (label, write)
            break
        # The same place for reading and writing when no volume holds them (2026-11-14 review: a
        # theme written to userdata beside a cache never written here was read from cache).
        if target is None and write != 'never':
            target = (label, write)
        fallback = fallback or (label, write)
    if target is None and mode == 'ro':
        target = fallback  # only volumes never written here: nothing to read, from the first
    if target is None:
        raise NoSettingsVolume('No volume is there for the settings')
    label, write = target
    if mode != 'ro' and write != 'now':
        raise Unreadable('The settings volume %s cannot be written now' % label)
    return label


def _close(opened):
    """Close a volume this call no longer needs: a failure to unmount it is no failure of the work."""
    with contextlib.suppress(OSError, ValueError, fs.FilesystemError):
        opened.close()


def _look(context, label, mode, relative, opened):
    """(there, holds, write, root) of LABEL. ROOT is open in MODE in OPENED when it could be
    opened so: for writing only a volume that may ever be written is tried, and any failure to
    open it so is 'later'; whether it holds the file is then looked at read-only."""
    try:
        volume = context.volume(label)
    except fs.FilesystemError:
        return False, False, None, None
    if not volume.get('mountable') and not volume.get('mounted'):
        return False, False, None, None
    write = 'never' if volume.get('read_only_reason_code') in NEVER_WRITABLE else 'later'
    if mode == 'rw' and write == 'later':
        try:
            root = opened.enter_context(volume_root(context, label, 'rw'))
        except (OSError, ValueError, fs.FilesystemError):
            _close(opened)
        else:
            try:
                return True, entry(root / relative), 'now', root
            except OSError:
                return True, None, 'now', None
    try:
        root = opened.enter_context(volume_root(context, label, 'ro'))
        holds = entry(root / relative)
    except (OSError, ValueError, fs.FilesystemError):
        _close(opened)
        return True, None, write, None
    if mode != 'ro':
        _close(opened)
        root = None
    return True, holds, write, root


@contextlib.contextmanager
def settings_root(context, mode, relative=RELATIVE, visit=None):
    """(label, root) of the volume choose() gives, open in MODE; RELATIVE: another file kept the
    same way (the saved Wi-Fi networks); VISIT(root) for each volume looked at that is open
    read-only (read_disk copies the themes of each). Volumes are looked at in order until one holds
    the file or cannot be looked at, each opened once; every other is closed before the caller works
    in the chosen one, and all of them whatever fails. When the caller's work is done, a failure to
    close a volume afterwards does not undo it (2026-11-14 review: a password written to disk was
    said kept in RAM, a theme added said lost, settings read said unreadable). Called under the
    operation lock."""
    everything = contextlib.ExitStack()
    try:
        looked = []
        for label in VOLUMES:
            opened = contextlib.ExitStack()
            everything.callback(opened.close)
            there, holds, write, root = _look(context, label, mode, relative, opened)
            looked.append((label, there, holds, write, root, opened))
            if visit is not None and mode == 'ro' and root is not None:
                visit(root)
            if holds is not False:  # the holder, or one that cannot be looked at: choose stops there
                break
        label = choose([entry_[:4] for entry_ in looked], mode)
        root = next(entry_[4] for entry_ in looked if entry_[0] == label)
        for entry_ in looked:
            if entry_[0] != label:
                _close(entry_[5])
        if root is None:  # never by choose's contract; said, not asserted (python -O drops asserts)
            raise Unreadable('The settings volume %s was not opened' % label)
    except BaseException:
        everything.close()
        raise
    try:
        yield label, root
    except BaseException:
        everything.close()
        raise
    with contextlib.suppress(OSError, ValueError, fs.FilesystemError):
        everything.close()


def write_disk(record):
    context = fs.DeviceContext()
    with operation_lock(context.lock_path, context.mode):
        try:
            with settings_root(context, 'rw') as (_, root):
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
    # Not there is the only reason to read the disk; a copy that cannot be read now is an error,
    # never replaced by the older one on disk (2026-11-14 review: is_file() said no copy on any error).
    try:
        return checked(json.loads(RAM_COPY.read_text()))
    except FileNotFoundError:
        pass
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
