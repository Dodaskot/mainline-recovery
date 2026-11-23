#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bluetooth's pairings kept past a restart of the recovery (2026-11-22, the owner: kept in misc, as
the settings and the Wi-Fi list are).

BlueZ keeps a paired device in /var/lib/bluetooth/ADAPTER/DEVICE/info (its keys: LinkKey for
BR/EDR, LongTermKey and IdentityResolvingKey for LE) and the adapter's own state in
ADAPTER/settings. Here that folder lies in the media service's RAM layer, so every start forgot the
headphones and the keyboard. Their files go to the pairings record of misc (misc_store: two whole
copies, each with its SHA-256), the paired devices only, and come back before bluetoothd starts.
The keys are kept as the Wi-Fi passwords are, in misc of this phone; they never reach a log.
"""
import json
import os
from pathlib import Path
import re

STATE = Path('var/lib/bluetooth')
ADDRESS = re.compile(r'[0-9A-F]{2}(?::[0-9A-F]{2}){5}')
PATH = re.compile(r'(?P<adapter>%s)/(?:settings|(?P<device>%s)/(?:info|attributes))' % (ADDRESS.pattern, ADDRESS.pattern))
KEYS = ('[LinkKey]', '[LongTermKey]', '[PeripheralLongTermKey]', '[SlaveLongTermKey]')
FILE_MAX = 16 << 10
VERSION = 1


def _text(path):
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > FILE_MAX:
            return None
        return path.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError):
        return None


def paired(info):
    """Whether a device's info holds a key of a pairing (a device only seen has none)."""
    return any(line.strip() in KEYS for line in info.splitlines())


def _encode(files):
    return json.dumps({'version': VERSION, 'files': files}, sort_keys=True, separators=(',', ':')).encode()


def snapshot(root, limit):
    """The record for ROOT's pairings, at most LIMIT bytes: the adapters' settings and each paired
    device's info, with its attributes while they fit; past LIMIT, the devices paired longest ago go."""
    base = Path(root) / STATE
    files, devices = {}, []
    adapters = sorted(p for p in base.iterdir() if p.is_dir() and ADDRESS.fullmatch(p.name)) if base.is_dir() else []
    for adapter in adapters:
        settings = _text(adapter / 'settings')
        if settings is not None:
            files[f'{adapter.name}/settings'] = settings
        for device in sorted(p for p in adapter.iterdir() if p.is_dir() and ADDRESS.fullmatch(p.name)):
            info = _text(device / 'info')
            if info is None or not paired(info):
                continue
            files[f'{adapter.name}/{device.name}/info'] = info
            attributes = _text(device / 'attributes')
            if attributes is not None:
                files[f'{adapter.name}/{device.name}/attributes'] = attributes
            try:
                when = (device / 'info').stat().st_mtime
            except OSError:
                when = 0
            devices.append((when, f'{adapter.name}/{device.name}/'))
    payload = _encode(files)
    if len(payload) > limit:
        files = {name: text for name, text in files.items() if not name.endswith('/attributes')}
        payload = _encode(files)
    for _, prefix in sorted(devices):
        if len(payload) <= limit:
            break
        files = {name: text for name, text in files.items() if not name.startswith(prefix)}
        payload = _encode(files)
    return payload if len(payload) <= limit else _encode({})


def restore(root, payload):
    """The files of PAYLOAD (a record of snapshot) into ROOT where none is yet: a file BlueZ wrote in
    this start stays. Returns how many devices came back; ValueError for a record that is no such."""
    data = json.loads(payload.decode())
    if not isinstance(data, dict) or data.get('version') != VERSION or not isinstance(data.get('files'), dict):
        raise ValueError('not a record of Bluetooth pairings')
    base = Path(root) / STATE
    devices = 0
    for name, text in sorted(data['files'].items()):
        match = PATH.fullmatch(name) if isinstance(name, str) else None
        if not match or not isinstance(text, str) or len(text.encode()) > FILE_MAX:
            continue
        target = base / name
        folder = target.parent
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        if folder.is_symlink() or target.exists() or target.is_symlink():
            continue
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            out.write(text)
        if name.endswith('/info'):
            devices += 1
    return devices
