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
get past the password and keep the data it guarded. "No password" needs proof: settings read
without one, or none at all and no PASSWORD_MARK (a password set leaves that mark beside its
volume's root, see choose and read_disk; 2026-11-14 reviews). Only a regular file counts as
settings. Erasing the volume itself (its format, or cache.img flashed in Download Mode) takes
mark and settings both and gives the defaults: whoever can do that can flash another recovery
too, which no password here covers.
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
from operation_lock import lease

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
    """Settings that are there but cannot be read as settings; LABEL names the volume; MARKS the
    volumes that carry PASSWORD_MARK, which their reset clears too."""
    def __init__(self, message, label='', marks=()):
        super().__init__(message)
        self.label, self.marks = label, tuple(marks)


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
    settings that cannot be read (2026-11-14 review: the phone stayed locked at every start). Only
    from real folders: never through a link where a folder should be (2026-11-14 review)."""
    try:
        if _folders(root, THEMES / 'x') is not True or not stat.S_ISDIR(os.lstat(root / THEMES).st_mode):
            return
        RAM_THEMES.mkdir(parents=True, exist_ok=True)
        themes = (*(root / THEMES).glob('*.theme'), *(root / THEMES).glob('*.hidden'))
    except OSError:
        return
    for theme in themes:
        with contextlib.suppress(OSError):
            if stat.S_ISREG(os.lstat(theme).st_mode):
                shutil.copyfile(theme, RAM_THEMES / theme.name)


def present(path):
    """Whether PATH is a regular file (following links): False when nothing is there and for anything
    that is no regular file, a loop of links too; a failure to look (EIO, EACCES) is raised
    (2026-11-14 reviews: Path.is_file() answers False to every error). For files this recovery ships
    or keeps in RAM; whether a volume holds the settings is holds()'s question."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as error:
        if error.errno == errno.ELOOP:
            return False
        raise


def _bad_folder(root, relative):
    """The first folder of RELATIVE under ROOT that is no real folder (a link, a file), looked at
    one by one without following links; None when all are real folders or one is missing."""
    path = Path(root)
    for part in Path(relative).parts[:-1]:
        path = path / part
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        if not stat.S_ISDIR(st.st_mode):
            return path
    return None


def _folders(root, relative):
    """True when every folder of RELATIVE under ROOT is a real folder, None when one is missing,
    False when one is no real folder."""
    if _bad_folder(root, relative) is not None:
        return False
    path = Path(root)
    for part in Path(relative).parts[:-1]:
        path = path / part
        if not os.path.lexists(path):
            return None
    return True


def holds(root, relative):
    """Whether a regular file is at ROOT/RELATIVE in real folders: only that counts as settings (or
    as the saved Wi-Fi list). Nothing there, a folder, a link, a FIFO, or a folder of the path that is
    no real folder: False, and PASSWORD_MARK decides whether that means no password (2026-11-14
    reviews: read as none, any of these opened the phone; read as damaged, a link a Linux system
    made had userdata erased with no password set). A failure to look is raised."""
    if _folders(root, relative) is not True:
        return False
    try:
        return stat.S_ISREG(os.lstat(Path(root) / relative).st_mode)
    except FileNotFoundError:
        return False


class NotRegular(OSError):
    """Where a file should be there is something else."""


def read_bytes(root, relative):
    """The bytes of the regular file at ROOT/RELATIVE, opened as filesystem.open_regular opens (its
    type proven on the descriptor, links never followed, its folders real folders); None when
    nothing is there; NotRegular when something else is; OSError when it cannot be read now. One
    reader for the settings and the saved Wi-Fi list (2026-11-14 review)."""
    folders = _folders(root, relative)
    if folders is None:
        return None
    if folders is False:
        raise NotRegular(errno.ENOTDIR, 'A folder of the path is no real folder')
    path = Path(root) / relative
    try:
        fd = fs.open_regular(path)
    except FileNotFoundError:
        # Gone between the look and the open, or its reopen failed: "not there" only when a look
        # finds nothing (2026-11-14 review: any ENOENT read as no settings).
        if not os.path.lexists(path):
            return None
        raise OSError(errno.EIO, 'The file is there and could not be opened')
    except NotADirectoryError as error:
        raise NotRegular(errno.ENOTDIR, 'A file stands where a folder should be') from error
    except fs.FilesystemError as error:
        if error.code == 'REGULAR_FILE_REQUIRED':
            raise NotRegular(errno.EINVAL, 'No regular file') from error
        raise OSError(errno.EIO, str(error)) from error
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise NotRegular(errno.ELOOP, 'A link stands where the file should be') from error
        raise
    with os.fdopen(fd, 'rb') as stream:
        return stream.read()


def clear_file(root, relative):
    """Remove ROOT/RELATIVE itself when it is no regular file (a folder, a link, a FIFO), never one of
    its folders: NotRegular when one of them is no real folder (2026-11-14 review: the Wi-Fi list
    removed the folder that also holds the settings, their password with them)."""
    if _bad_folder(root, relative) is not None:
        raise NotRegular(errno.ENOTDIR, 'A folder of the path is no real folder')
    target = Path(root) / relative
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(target)
    elif not stat.S_ISREG(st.st_mode):
        os.unlink(target)


def clear_entry(root, relative):
    """clear_file, after removing a folder of the path that is no real folder: for the settings
    only, on the volume that keeps them (their write, their reset), never for the Wi-Fi list."""
    bad = _bad_folder(root, relative)
    if bad is not None:
        os.unlink(bad)
        return
    clear_file(root, relative)


# Written at a volume's root before settings with a password are written there, removed after they
# are written without one, from every volume, and by the reset of damaged settings. Settings found
# nowhere while a volume carries it, or found without a password while another volume carries it,
# are damaged, never "no password" (2026-11-14 reviews: every way of misreading "not there" opened
# the phone). Outside a22x-recovery, so nothing that befalls that folder takes it; kept by every
# wipe of cache's contents (filesystem.WIPE_KEEP).
PASSWORD_MARK = Path('.a22x-recovery-password')


def set_mark(root):
    """PASSWORD_MARK at ROOT, a regular empty file: whatever else stands there goes first (a FIFO
    would have hung the open under the lease: 2026-11-14 review)."""
    clear_file(root, PASSWORD_MARK)
    try:
        fd = os.open(Path(root) / PASSWORD_MARK, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    _sync_folder(root)


def drop_mark(root):
    """PASSWORD_MARK gone from ROOT, whatever it is."""
    clear_file(root, PASSWORD_MARK)
    target = Path(root) / PASSWORD_MARK
    if os.path.lexists(target):
        target.unlink()
        _sync_folder(root)


def _sync_folder(root):
    folder = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(folder)
    finally:
        os.close(folder)


def read_regular(root, relative, label):
    """The text of the settings file at ROOT/RELATIVE on LABEL: None when no regular file is there
    (see holds); Damaged when it is no text; Unreadable when it cannot be read now."""
    try:
        data = read_bytes(root, relative)
    except NotRegular:
        return None
    except OSError as error:
        raise Unreadable('The settings on %s cannot be read now' % label) from error
    if data is None:
        return None
    try:
        return data.decode()
    except UnicodeDecodeError as error:
        raise Damaged('The settings on %s are damaged' % label, label) from error


def read_disk():
    """Empty only when a volume was really looked into, holds no settings, and no volume carries
    PASSWORD_MARK.

    A volume that cannot be found or read is not an empty one: taking it for one
    would show the phone unlocked and let the next save replace the password. Nor is a
    file that is there but damaged (2026-11-12, audit): before, the next volume was
    asked, and userdata without settings unlocked the phone. The volume is the one
    settings_root chooses, by the same rule as every write (2026-11-14 review: two
    copies of the rule).
    """
    context = fs.DeviceContext()
    with lease(context.lock_path, context.mode):
        try:
            marks = []
            # The themes of the volume that keeps the settings only: themes are written there and
            # nowhere else (settings_root 'rw' chooses the same volume), and a theme or note left on
            # another volume by an older release would come back at every start, whatever removes
            # it (2026-11-14 reviews: first only this volume's, then every volume's, were copied).
            with settings_root(context, 'ro', marks=marks) as (label, root):
                copy_themes(root)
                # 2026-11-12 review: a file that cannot be read now (EIO, a busy card) is not a
                # damaged one: it is no reason to offer erasing userdata, and still opens nothing.
                text = read_regular(root, RELATIVE, label)
                if text is not None:
                    try:
                        record = checked(json.loads(text), label)
                    except ValueError as error:
                        if isinstance(error, Damaged):
                            raise
                        raise Damaged('The settings on %s are damaged' % label, label, marks) from error
                    elsewhere = [mark for mark in marks if mark != label]
                    if not record.get('hash') and elsewhere:
                        # Settings without a password while another volume says one was set: an older
                        # copy, never proof (2026-11-14 review: it opened the phone).
                        raise Damaged('The settings on %s hold no password, and %s says one was set'
                                      % (label, elsewhere[0]), elsewhere[0], marks)
                    return record
            if marks:
                raise Damaged('The settings are missing, and %s says a password was set' % marks[0], marks[0], marks)
            return {}
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
    """(there, holds, write, root, marked) of LABEL. ROOT is open in MODE in OPENED when it could be
    opened so: for writing only a volume that may ever be written is tried, and any failure to
    open it so is 'later'; whether it holds the file, and carries PASSWORD_MARK, is then looked at
    read-only."""
    try:
        volume = context.volume(label)
    except fs.FilesystemError:
        return False, False, None, None, False
    if not volume.get('mountable') and not volume.get('mounted'):
        return False, False, None, None, False
    write = 'never' if volume.get('read_only_reason_code') in NEVER_WRITABLE else 'later'
    if mode == 'rw' and write == 'later':
        try:
            root = opened.enter_context(volume_root(context, label, 'rw'))
        except (OSError, ValueError, fs.FilesystemError):
            _close(opened)
        else:
            try:
                return True, holds(root, relative), 'now', root, os.path.lexists(root / PASSWORD_MARK)
            except OSError:
                return True, None, 'now', None, False
    try:
        root = opened.enter_context(volume_root(context, label, 'ro'))
        found, marked = holds(root, relative), os.path.lexists(root / PASSWORD_MARK)
    except (OSError, ValueError, fs.FilesystemError):
        _close(opened)
        return True, None, write, None, False
    if mode != 'ro':
        _close(opened)
        root = None
    return True, found, write, root, marked


@contextlib.contextmanager
def settings_root(context, mode, relative=RELATIVE, marks=None):
    """(label, root) of the volume choose() gives, open in MODE; RELATIVE: another file kept the
    same way (the saved Wi-Fi networks). Volumes are looked at in order until one holds
    the file or cannot be looked at, each opened once; every other is closed before the caller works
    in the chosen one, and all of them whatever fails. MARKS, a list, gets the labels of the volumes
    looked at that carry PASSWORD_MARK, seen while they were open (2026-11-14 review: each was mounted
    again to look). When the caller's work is done, a failure to close a volume afterwards does not
    undo it (2026-11-14 review: a password written to disk was said kept in RAM, a theme added said
    lost, settings read said unreadable). Called under the operation lock."""
    everything = contextlib.ExitStack()
    try:
        looked = []
        for label in VOLUMES:
            opened = contextlib.ExitStack()
            everything.callback(opened.close)
            there, found, write, root, marked = _look(context, label, mode, relative, opened)
            looked.append((label, there, found, write, root, opened))
            if marked and marks is not None:
                marks.append(label)
            if found is not False:  # the holder, or one that cannot be looked at: choose stops there
                break
        label = choose([entry_[:4] for entry_ in looked], mode)
        root = next(entry_[4] for entry_ in looked if entry_[0] == label)
        for entry_ in looked:
            if entry_[0] != label:
                _close(entry_[5])
        if root is None:  # never by choose's contract; said, not asserted (python -O drops asserts)
            raise Unreadable('The settings volume %s was not opened' % label)
    except BaseException:
        _close(everything)
        raise
    try:
        yield label, root
    except BaseException:
        # The caller's own error stands: a volume that fails to close never replaces it (2026-11-14
        # review: Damaged settings became Unreadable, and their reset was never offered).
        _close(everything)
        raise
    _close(everything)


def write_disk(record):
    """RECORD on the volume settings_root chooses. With a password, PASSWORD_MARK goes there first,
    so a stop between the two leaves the mark beside the older settings, never a password without
    it; without one, the settings go first and then the mark from every volume, so a stop leaves
    the older password in force (2026-11-14 review of the order). False when any of it failed."""
    context = fs.DeviceContext()
    with lease(context.lock_path, context.mode):
        try:
            marks = []
            with settings_root(context, 'rw', marks=marks) as (label, root):
                if record.get('hash'):
                    set_mark(root)
                path = root / RELATIVE
                # The volume chosen holds no regular settings file: whatever else stands in their
                # way (a link or a file for their folder, a folder for the file) goes, or they could
                # never be saved there (2026-11-14 review).
                clear_entry(root, RELATIVE)
                path.parent.mkdir(mode=0o700, exist_ok=True)
                temporary = path.with_suffix('.new')
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    os.write(fd, json.dumps(record).encode())
                    os.fsync(fd)
                finally:
                    os.close(fd)
                temporary.replace(path)
                if not record.get('hash'):
                    drop_mark(root)
            if not record.get('hash'):
                # Marks left on other volumes (settings that moved) go too, or the next loss of the
                # settings would ask for userdata to be erased though no password is set (2026-11-14
                # review); one that cannot be removed now is a save not done.
                for other in marks:
                    if other != label:
                        with volume_root(context, other, 'rw') as other_root:
                            drop_mark(other_root)
            return True
        except (OSError, ValueError, fs.FilesystemError):
            return False


def ensure_mark(record):
    """PASSWORD_MARK beside settings with a password that a release before it wrote (2026-11-14
    review: for those the new guarantee did not hold until some setting changed). Best effort, at
    the start, once the settings were read from the disk."""
    if not record.get('hash'):
        return
    context = fs.DeviceContext()
    with contextlib.suppress(OSError, ValueError, fs.FilesystemError):
        with lease(context.lock_path, context.mode):
            marks = []
            with settings_root(context, 'rw', marks=marks) as (label, root):
                if label not in marks and holds(root, RELATIVE):
                    set_mark(root)


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
    except (FileNotFoundError, ValueError):
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
    ensure_mark(record)
    return record


def store(record):
    remember(record)
    try:
        return 0 if write_disk(record) else 3
    except (OSError, ValueError, fs.FilesystemError):
        return 3


def reset_damaged():
    """Erase damaged settings together with userdata. Exit 1 when the settings are not damaged:
    settings that cannot be read now are no proof. Every volume besides userdata that must change
    (cache when it holds them, each volume that carries PASSWORD_MARK) is opened for writing first,
    so one that cannot be written stops the reset before anything is erased (2026-11-14 review: a
    mark that could not be removed afterwards asked for the reset again). Userdata is erased
    before the settings, so a stop halfway leaves the data gone, never the password."""
    try:
        read_disk()
        return 1
    except Damaged as damaged:
        label, marks = damaged.label, damaged.marks
    except OSError:
        return 1
    context = fs.DeviceContext()
    with lease(context.lock_path, context.mode):
        with contextlib.ExitStack() as stack:
            others = {name: stack.enter_context(volume_root(context, name, 'rw'))
                      for name in sorted({label, *marks} - {'userdata'})}
            volume = context.volume('userdata')
            if volume['mounted']:
                context.unmount('userdata', volume['volume_token'])
                volume = context.volume('userdata')
            context.format('userdata', 'ext4' if volume.get('fs_type') == 'ext4' else 'f2fs', True, volume['volume_token'])
            for root in others.values():
                # Whatever stands there goes: a folder, a link, a file where a folder should be
                # (2026-11-14 review: unlink failed on those after userdata was erased, every time).
                clear_entry(root, RELATIVE)
                (root / RELATIVE).unlink(missing_ok=True)
                drop_mark(root)
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
