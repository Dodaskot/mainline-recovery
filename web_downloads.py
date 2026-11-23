#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Browser downloads moved from RAM to a card (2026-11-20, a tester, #6: "Browser downloads get
saved in RAM but there's no way to access them").

The browser still writes only its own RAM folder (web_launch: a web download cannot replace a
recovery image). This trusted step runs beside it in the recovery's own mount namespace, under the
operation lock as every storage helper, and moves each finished download into Download/ of an SD
card or a USB drive that is mounted for writing (an SD card first). It takes only regular files of
the browser's user straight in the RAM folder: no link, no folder, nothing hidden, nothing Chromium
still writes (.crdownload). A name already in Download/ gets " (1)", " (2)"... before its
extension: nothing there is replaced. Without such a card the downloads stay in RAM until the
recovery restarts, as before, and the browser says so once.
"""
import json
import os
from pathlib import Path
import select
import stat
import time

import filesystem as fs

PARTIAL = ('.crdownload', '.tmp')
FOLDER = 'Download'
MAX_NAME = 200


def finished(source, uid):
    """Names of the downloads in the open folder SOURCE that are complete and may be moved."""
    names = []
    for name in sorted(os.listdir(source)):
        if name.startswith('.') or name.endswith(PARTIAL) or any(ord(c) < 32 or c == '\x7f' for c in name):
            continue
        try:
            st = os.stat(name, dir_fd=source, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_uid == uid and st.st_nlink == 1:
            names.append(name)
    return names


SETTINGS = Path('/run/a22x-recovery/settings.json')
# Present while the interface runs an operation (2026-11-22, the owner: nothing beside an operation writes
# to storage): finished downloads wait in RAM until it has ended.
HOLD = Path('/run/a22x-recovery/web-downloads-hold')


def held(path=None):
    """Whether an operation of the interface runs now."""
    return Path(path or HOLD).exists()


def target(path=None):
    """The browser setting of where downloads go (settings.py web_downloads); 'auto' when unread."""
    try:
        value = json.loads(Path(path or SETTINGS).read_text()).get('web_downloads', 'auto')
    except (OSError, ValueError, AttributeError):
        return 'auto'
    return value if value in ('auto', 'sdcard', 'usb', 'ram') else 'auto'


def card(context, where='auto'):
    """The SD card (first) or USB drive mounted for writing by the recovery, or None. WHERE limits it
    to one of them, or to none ('ram': downloads stay in RAM, 2026-11-20 browser settings)."""
    if where == 'ram':
        return None
    volumes = [v for v in context.volumes()
               if v.get('mounted') and not v.get('read_only') and v.get('write_supported')
               and v.get('mount_owner') == 'filesystem' and v.get('volume_token')]
    for prefix in {'sdcard': ('sdcard-',), 'usb': ('usb-',)}.get(where, ('sdcard-', 'usb-')):
        for volume in volumes:
            if volume['id'].startswith(prefix):
                return volume
    return None


def short(name):
    """NAME within MAX_NAME bytes of UTF-8, its extension kept."""
    if len(name.encode()) <= MAX_NAME:
        return name
    stem, dot, ext = name.rpartition('.')
    if not dot or len(ext.encode()) > 16:
        stem, ext = name, ''
    room = MAX_NAME - len(ext.encode()) - (1 if ext else 0)
    stem = stem.encode()[:room].decode('utf-8', 'ignore')
    return stem + ('.' + ext if ext else '')


def free_name(directory, name):
    stem, dot, ext = name.rpartition('.')
    if not dot or not stem:
        stem, ext = name, ''
    for n in range(0, 1000):
        candidate = name if n == 0 else short(f'{stem} ({n})' + ('.' + ext if ext else ''))
        try:
            os.stat(candidate, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return candidate
    raise FileExistsError(name)


def move(pin, directory, source, name):
    """Copy NAME from SOURCE into the open DIRECTORY of the pinned volume, then drop the RAM copy.
    Returns the name it has there."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=source)
    temporary = '.a22x-download-' + os.urandom(8).hex()
    target = None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise OSError('not a single regular file')
        target = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=directory)
        done = 0
        while done < st.st_size:
            sent = os.sendfile(target, fd, done, min(st.st_size - done, 8 << 20))
            if not sent:
                break
            done += sent
        if done != st.st_size or os.fstat(fd).st_size != st.st_size:
            raise OSError('the download changed while it was moved')
        os.fsync(target)
        pin.recheck()
        saved = free_name(directory, short(name))
        fs.rename_noreplace(directory, temporary, directory, saved)
        os.fsync(directory)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
        if target is not None:
            os.close(target)
    os.unlink(name, dir_fd=source)
    return saved


def deliver(context, source, uid):
    """Move what is finished in SOURCE (an open folder) to a card. Returns (volume id or None, moved names)."""
    names = finished(source, uid)
    if not names or held():
        return None, []
    with context.operation_lock(shared=True):
        volume = card(context, target())
        if volume is None:
            return None, []
        moved = []
        with fs.PinnedVolume(context, volume['id'], volume['volume_token'], writing=True) as pin:
            with pin.parent('/' + FOLDER) as (root, name):
                try:
                    os.stat(name, dir_fd=root, follow_symlinks=False)
                except FileNotFoundError:
                    pin.recheck()
                    os.mkdir(name, mode=0o755, dir_fd=root)
            with pin.directory('/' + FOLDER) as directory:
                for name in names:
                    try:
                        moved.append(move(pin, directory, source, name))
                    except (OSError, fs.FilesystemError):
                        continue  # left in RAM; tried again later
        return volume['id'], moved


def note(volume, count):
    where = 'the SD card' if volume.startswith('sdcard-') else 'the USB drive'
    return (f'Saved to {where}: {FOLDER}' if count == 1 else f'{count} downloads saved to {where}: {FOLDER}').encode()


def follow(source, uid, ended, control=0, interval=1.5, context=None):
    """Move finished downloads while the browser runs: until the pipe ENDED reaches its end (the
    launcher has finished), then once more. Notes go to the UI on CONTROL while the browser runs."""
    os.environ.pop('A22X_RECOVERY_LOCK_FD', None)  # the UI's lease is not lent to the browser
    context = context or fs.DeviceContext()
    told_ram = False
    while True:
        ready, _, _ = select.select([ended], [], [], interval)
        last = bool(ready) and not os.read(ended, 64)
        if last and control is not None:
            os.close(control)  # the browser has closed: the UI is not kept waiting for this step
            control = None
        try:
            volume, moved = deliver(context, source, uid)
        except (OSError, fs.FilesystemError):
            volume, moved = None, []
        if control is not None:
            try:
                if moved:
                    os.write(control, b'S' + note(volume, len(moved)))
                elif not told_ram and volume is None and not held() and finished(source, uid):
                    told_ram = True
                    os.write(control, b'SDownloads stay in RAM: mount an SD card or a USB drive for writing to keep them')
            except OSError:
                control = None
        if last:
            return
        if not ready:
            time.sleep(0)
