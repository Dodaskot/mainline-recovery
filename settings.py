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
    settings that cannot be read (2026-11-14 review: the phone stayed locked at every start). Read
    as the settings are, through a link to their folder too; only regular files are copied."""
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
            if stat.S_ISREG(os.lstat(theme).st_mode):
                shutil.copyfile(theme, RAM_THEMES / theme.name)


def present(path):
    """Whether PATH is a regular file (following links): False when nothing is there and for anything
    that is no regular file, a loop of links too; a failure to look (EIO, EACCES) is raised
    (2026-11-14 reviews: Path.is_file() answers False to every error). For files this recovery ships
    or keeps in RAM, and as holds() for the settings."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as error:
        if error.errno == errno.ELOOP:
            return False
        raise


def holds(root, relative):
    """Whether the settings (or the saved Wi-Fi list) are at ROOT/RELATIVE: a regular file reached
    there, through links as the releases before this one read and wrote them (2026-11-14 review: a
    password behind a link read as none). Nothing there, a folder, a FIFO, a dangling link or a loop:
    False, and PASSWORD_MARK decides what that means. A failure to look is raised."""
    return present(Path(root) / relative)


class NotRegular(OSError):
    """Where a file should be there is something else."""


def read_bytes(root, relative):
    """The bytes of the regular file at ROOT/RELATIVE (through links, never blocking on a FIFO); None
    when holds() finds nothing; NotRegular when something else is there; OSError when it cannot be
    read now, a file that holds() still sees but cannot be opened too (2026-11-14 reviews: an error
    there read as nothing). One reader for the settings and the saved Wi-Fi list."""
    path = Path(root) / relative
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except (FileNotFoundError, NotADirectoryError):
        if holds(root, relative):
            raise OSError(errno.EIO, 'The file is there and could not be opened')
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise NotRegular(errno.ELOOP, 'A loop of links stands where the file should be') from error
        raise
    try:
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
    except OSError:
        os.close(fd)
        raise
    if not regular:  # a folder too: its type is proven on the descriptor before it is read
        os.close(fd)
        raise NotRegular(errno.EINVAL, 'No regular file')
    with os.fdopen(fd, 'rb') as stream:
        return stream.read()


def _walk(root, relative):
    """How the folders of RELATIVE under ROOT are, looked at once each without following links:
    ('ok', None) all real folders; ('missing', None) one is not there; ('bad', path) one is no real
    folder (a link, a file)."""
    path = Path(root)
    for part in Path(relative).parts[:-1]:
        path = path / part
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return 'missing', None
        if not stat.S_ISDIR(st.st_mode):
            return 'bad', path
    return 'ok', None


def clear_file(root, relative):
    """Remove ROOT/RELATIVE itself when it is no regular file (a folder, a link, a FIFO), never one of
    its folders: NotRegular when one of them is no real folder (2026-11-14 review: the Wi-Fi list
    removed the folder that also holds the settings, their password with them)."""
    state, _ = _walk(root, relative)
    if state == 'missing':
        return
    if state == 'bad':
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
    """clear_file, after removing a folder of the path that is no real folder (a link, a file): for
    the settings only, on the volume that keeps them (their write, their reset), so they are written
    in a real folder; never for the Wi-Fi list."""
    state, bad = _walk(root, relative)
    if state == 'bad':
        os.unlink(bad)
        return
    clear_file(root, relative)


# The mark that a password is set, at a volume's root (filesystem.PASSWORD_MARK, kept by every wipe
# of cache's contents). "No password" needs proof (2026-11-14 reviews: every way of misreading "not
# there" opened the phone): settings read without one, while no other volume carries the mark and
# every volume there was looked at; or no settings anywhere and no mark anywhere. See verdict().
PASSWORD_MARK = Path(fs.PASSWORD_MARK)


def marked(root):
    """Whether ROOT carries PASSWORD_MARK, whatever it is; a failure to look is raised, never "no mark"
    (2026-11-14 review: os.path.lexists said no mark on EIO)."""
    try:
        os.lstat(Path(root) / PASSWORD_MARK)
        return True
    except FileNotFoundError:
        return False


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


def verdict(looks):
    """Where the settings are, by what every volume showed: LOOKS in the order of VOLUMES, each
    {'label', 'there', 'known', 'holds', 'marked'} ('known': it could be looked at). Returns
    (holder or None, the labels that carry PASSWORD_MARK). Volumes not there are passed over (erased,
    or no filesystem: the defaults, which only Download Mode can bring about, see the module); a
    volume there that could not be looked at before the holder is Unreadable; with no holder, a mark
    anywhere is Damaged (2026-11-14 reviews). See settled() for what the holder's record must show."""
    if not any(look['there'] for look in looks):
        # None is there at all: no volume was looked into, so nothing says "no settings" (2026-11-07:
        # the eMMC came up as mmcblk1, cache was not found, and the defaults were shown).
        raise NoSettingsVolume('No settings volume could be read')
    holder = None
    for look in looks:
        if not look['there']:
            continue
        if not look['known']:
            raise Unreadable('The settings volume %s cannot be read now' % look['label'])
        if look['holds']:
            holder = look['label']
            break
    marks = [look['label'] for look in looks if look['there'] and look['known'] and look['marked']]
    if holder is None and marks:
        raise Damaged('The settings are missing, and %s says a password was set' % marks[0], marks[0], marks)
    return holder, marks


def settled(looks, holder, record, marks):
    """RECORD as read from HOLDER, when it may stand: a password always; no password only when no
    other volume carries PASSWORD_MARK (an older copy otherwise: Damaged, 2026-11-14 review) and every
    volume there could be looked at (a mark on one that could not is unknown: Unreadable)."""
    if record.get('hash'):
        return record
    others = [label for label in marks if label != holder]
    if others:
        raise Damaged('The settings on %s hold no password, and %s says one was set' % (holder, others[0]),
                      others[0], marks)
    unknown = [look['label'] for look in looks if look['there'] and not look['known']]
    if unknown:
        raise Unreadable('The settings volume %s cannot be read now' % unknown[0])
    return record


# What the last read_disk of this process found: the holder, and whether it carries the mark
# (ensure_mark adds one only where it is missing: 2026-11-14 review).
LAST_READ = {'holder': None, 'marked': False}


def read_disk():
    """The settings, by verdict() and settled() over every volume, each looked at once read-only in
    one pass (2026-11-14 review: a mark on a volume after the holder was never seen). Empty only
    when no volume there holds settings and none carries the mark.

    A volume that cannot be found or read is not an empty one: taking it for one
    would show the phone unlocked and let the next save replace the password. Nor is a
    file that is there but damaged (2026-11-12, audit): before, the next volume was
    asked, and userdata without settings unlocked the phone.
    """
    context = fs.DeviceContext()
    with lease(context.lock_path, context.mode):
        opened = contextlib.ExitStack()
        try:
            looks = []
            for label in VOLUMES:
                look = {'label': label, 'there': False, 'known': False, 'holds': False, 'marked': False,
                        'write': None, 'root': None}
                looks.append(look)
                try:
                    volume = context.volume(label)
                except fs.FilesystemError:
                    continue
                if not volume.get('mountable') and not volume.get('mounted'):
                    continue
                look.update(there=True, write='never' if volume.get('read_only_reason_code') in NEVER_WRITABLE else 'later')
                try:
                    root = opened.enter_context(volume_root(context, label, 'ro'))
                    look.update(root=root, holds=holds(root, RELATIVE), marked=marked(root), known=True)
                except (OSError, ValueError, fs.FilesystemError):
                    pass
            holder, marks = verdict(looks)
            # The themes of the volume that keeps the settings, or would keep them: written there and
            # nowhere else, so one left elsewhere never comes back (2026-11-14 reviews).
            source = holder or next((look['label'] for look in looks if look['known'] and look['write'] != 'never'), None)
            roots = {look['label']: look['root'] for look in looks}
            if source is not None:
                copy_themes(roots[source])
            if holder is None:
                LAST_READ.update(holder=None, marked=False)
                return {}
            # 2026-11-12 review: a file that cannot be read now (EIO, a busy card) is not a
            # damaged one: it is no reason to offer erasing userdata, and still opens nothing.
            try:
                text = read_regular(roots[holder], RELATIVE, holder)
            except Damaged as error:
                raise Damaged(str(error), holder, marks) from error  # its reset clears every mark (2026-11-14 review)
            if text is None:
                raise Unreadable('The settings on %s changed while they were read' % holder)
            try:
                record = checked(json.loads(text), holder)
            except ValueError as error:
                raise Damaged('The settings on %s are damaged' % holder, holder, marks) from error
            record = settled(looks, holder, record, marks)
            LAST_READ.update(holder=holder, marked=holder in marks)
            return record
        except (Damaged, Unreadable, NoSettingsVolume):
            raise
        except (OSError, ValueError, fs.FilesystemError) as error:
            raise Unreadable('The settings volume cannot be read now') from error
        finally:
            _close(opened)


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
    """(there, holds, write, root, marked) of LABEL, for writing: ROOT is open in MODE in OPENED when
    it could be opened so: only a volume that may ever be written is tried for writing, and any
    failure to open it so is 'later'; whether it holds the file, and carries PASSWORD_MARK, is then
    looked at read-only. A volume that cannot be looked at gives holds None."""
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
                return True, holds(root, relative), 'now', root, marked(root)
            except OSError:
                return True, None, 'now', None, False
    try:
        root = opened.enter_context(volume_root(context, label, 'ro'))
        found, mark = holds(root, relative), marked(root)
    except (OSError, ValueError, fs.FilesystemError):
        _close(opened)
        return True, None, write, None, False
    if mode != 'ro':
        _close(opened)
        root = None
    return True, found, write, root, mark


@contextlib.contextmanager
def settings_root(context, mode, relative=RELATIVE, seen=None):
    """(label, root) of the volume choose() gives, open in MODE; RELATIVE: the file whose holder
    decides (the settings). Volumes are looked at in order until one holds the file or cannot be
    looked at, each opened once; every other is closed before the caller works in the chosen one,
    and all of them whatever fails. SEEN, a dict, gets {label: carries PASSWORD_MARK} of each volume
    looked at, seen while it was open. When the caller's work is done, a failure to close a volume
    afterwards does not undo it (2026-11-14 review). Called under the operation lock."""
    everything = contextlib.ExitStack()
    try:
        looked = []
        for label in VOLUMES:
            opened = contextlib.ExitStack()
            everything.callback(opened.close)
            there, found, write, root, mark = _look(context, label, mode, relative, opened)
            looked.append((label, there, found, write, root, opened))
            if seen is not None and there and found is not None:
                seen[label] = mark
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


def _drop_other_marks(context, keep, seen):
    """PASSWORD_MARK gone from every volume there but KEEP: SEEN says what settings_root saw while
    each was open; one it did not look at (after the holder) is looked at read-only now. A volume
    with a mark is opened for writing; one that cannot be looked at or written now raises: nothing
    may be said cleared while a mark may stay (2026-11-14 reviews)."""
    for label in VOLUMES:
        if label == keep:
            continue
        try:
            volume = context.volume(label)
        except fs.FilesystemError:
            continue
        if not volume.get('mountable') and not volume.get('mounted'):
            continue
        found = seen.get(label)
        if found is None:
            with volume_root(context, label, 'ro') as root:
                found = marked(root)
        if found:
            with volume_root(context, label, 'rw') as root:
                drop_mark(root)


def write_disk(record):
    """RECORD on the volume settings_root chooses, in the order that keeps both promises whatever
    stops it (2026-11-14 reviews):
      with a password: the settings, then PASSWORD_MARK beside them; a stop between leaves the
      password on disk, never a mark beside no settings (which would ask for userdata to go);
      without one: first the mark of every other volume, then the settings, then this volume's
      mark; a stop leaves the older password in force, or settings without one beside their own
      mark only, which read as no password.
    Written as filesystem.atomic_state writes (a unique temporary name, fsync of the file and its
    folder). True only when all of it was done."""
    context = fs.DeviceContext()
    with lease(context.lock_path, context.mode):
        try:
            seen = {}
            with settings_root(context, 'rw', seen=seen) as (label, root):
                if not record.get('hash'):
                    _drop_other_marks(context, label, seen)
                # The volume chosen holds no regular settings file: whatever else stands in their
                # way (a link or a file for their folder, a folder for the file) goes, or they could
                # never be saved there (2026-11-14 review).
                clear_entry(root, RELATIVE)
                fs.atomic_state(root / RELATIVE, record)
                if record.get('hash'):
                    set_mark(root)
                else:
                    drop_mark(root)
            return True
        except (OSError, ValueError, fs.FilesystemError):
            return False


def ensure_mark(record):
    """PASSWORD_MARK beside settings with a password that a release before it wrote, only where the
    last read found it missing (2026-11-14 reviews: the guarantee did not hold for those; then every
    start mounted cache for writing to add a mark that was there). The settings are read again under
    the lease, so a password cleared meanwhile gets no mark. Best effort, at the start."""
    holder = LAST_READ.get('holder')
    if not record.get('hash') or holder is None or LAST_READ.get('marked'):
        return
    context = fs.DeviceContext()
    with contextlib.suppress(OSError, ValueError, fs.FilesystemError):
        with lease(context.lock_path, context.mode):
            with settings_root(context, 'rw') as (label, root):
                text = read_regular(root, RELATIVE, label) if label == holder else None
                if text is not None and json.loads(text).get('hash'):
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
    (the one that holds them, each that carries PASSWORD_MARK) is opened for writing first, so one
    that cannot be written stops the reset before anything is erased (2026-11-14 review: a mark that
    could not be removed afterwards asked for the reset again). Userdata is erased before the
    settings, so a stop halfway leaves the data gone, never the password."""
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
