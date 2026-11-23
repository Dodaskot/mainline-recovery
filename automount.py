#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Volumes mounted when the recovery starts (2026-11-20, the owner: the card mounted for writing at
once, with settings to mount everything at start, single partitions for writing or reading, and
Android data at start with a prompt for its password; a tester: "/data/media/0 and the SD card
mounted read-write immediately after booting, like in TWRP or OrangeFox").

The policy is in the settings (settings.py): mount_cards for removable volumes (SD card and USB
partitions), mount_data for userdata, mount_others for every other volume the recovery can mount,
each off, ro or rw; mount_list overrides single volumes ("id:mode,id:mode"). A volume already
mounted as asked stays as it is, one mounted read-only is remounted for writing when that is asked,
and one that cannot be written is mounted read-only instead. Nothing is formatted or unmounted.
Android data (android_decrypt) is never mounted here: it is reported (needs_password) and the UI
unlocks it, asking for the password unless this recovery session is already unlocked.
Each volume on its own: one that fails is reported and the others go on.

    automount.py --device|--fixture DIR run [--cards-only]     (prints one JSON result)
"""
import argparse
import json
from pathlib import Path
import re
import sys

import filesystem as fs
import settings

MODES = ('off', 'ro', 'rw')
ITEM = re.compile(r'([a-z0-9][a-z0-9_.-]{0,39}):(off|ro|rw)')
LIST = settings.MOUNT_LIST
# Android's encryption metadata: a group choice mounts it read-only at most, only its own choice
# (mount_list) mounts it for writing.
GUARDED = frozenset(('metadata',))


def overrides(text):
    """{volume id: mode} of a mount_list value; anything malformed counts as no override."""
    if not text or LIST.fullmatch(text) is None:
        return {}
    return dict(ITEM.fullmatch(part).groups() for part in text.split(','))


def policy_of(record):
    policy = {key: record.get(key, settings.DEFAULTS[key]) for key in ('mount_cards', 'mount_data', 'mount_others', 'mount_list')}
    for key in ('mount_cards', 'mount_data', 'mount_others'):
        if policy[key] not in MODES:
            policy[key] = settings.DEFAULTS[key]
    return policy


def removable(volume):
    """An SD card or USB partition, as the UI's external_volume() tells them."""
    return volume.get('external') is True or volume['id'].startswith(('sdcard-', 'usb-'))


def wanted(volume, policy, extra):
    ident = volume['id']
    if ident in extra:
        return extra[ident]
    if removable(volume):
        return policy['mount_cards']
    if ident == 'userdata':
        return policy['mount_data']
    if ident in GUARDED and policy['mount_others'] == 'rw':
        return 'ro'
    return policy['mount_others']


def android(volume):
    """Android data that only android_decrypt mounts: the UI unlocks it, never this helper."""
    return bool(volume.get('decrypt_supported') or volume.get('decrypt_state'))


def run(context, policy, cards_only=False):
    """CARDS_ONLY: a USB drive has just arrived; only removable volumes are looked at."""
    extra = overrides(policy.get('mount_list', ''))
    results, password = [], False
    for volume in context.volumes():
        if cards_only and not removable(volume):
            continue
        mode = wanted(volume, policy, extra)
        if mode == 'off':
            continue
        entry = {'id': volume['id'], 'wanted': mode}
        results.append(entry)
        if volume.get('mounted') and (mode == 'ro' or not volume.get('read_only')):
            entry.update(result='already', mode='ro' if volume.get('read_only') else 'rw')
            continue
        if android(volume):
            if volume.get('mounted'):
                entry.update(result='already', mode='ro' if volume.get('read_only') else 'rw')
            elif volume.get('decrypt_supported'):
                # The UI's startup unlock asks for the password (or reuses an unlocked session).
                password = True
                entry['result'] = 'needs_password'
            else:
                entry.update(result='skipped', reason=volume.get('reason_code') or volume.get('decrypt_state') or 'NOT_MOUNTABLE')
            continue
        if not volume.get('mountable') or not volume.get('volume_token'):
            entry.update(result='skipped', reason=volume.get('reason_code') or 'NOT_MOUNTABLE')
            continue
        if volume.get('read_only_reason') == 'FSCRYPT_KEYS_UNAVAILABLE':
            # Encrypted Android data that this recovery cannot unlock would show encrypted names only.
            entry.update(result='skipped', reason='FSCRYPT_KEYS_UNAVAILABLE')
            continue
        if mode == 'rw' and not volume.get('write_supported'):
            mode, entry['read_only_instead'] = 'ro', True
        if volume.get('mounted') and mode == 'ro':
            entry.update(result='already', mode='ro')
            continue
        try:
            context.mount(volume['id'], mode, True, volume['volume_token'])
            entry.update(result='mounted', mode=mode)
        except fs.FilesystemError as error:
            entry.update(result='failed', code=error.code)
        except OSError as error:
            entry.update(result='failed', code='IO_ERROR', errno=error.errno)
    return {'ok': True, 'operation': 'automount', 'policy': policy, 'results': results,
            'needs_password': password}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--device', action='store_true')
    mode.add_argument('--fixture', type=Path)
    parser.add_argument('command', choices=('run',))
    parser.add_argument('--cards-only', action='store_true', help='only SD card and USB volumes (a drive has arrived)')
    args = parser.parse_args(argv)
    try:
        context = fs.FixtureContext(args.fixture) if args.fixture else fs.DeviceContext()
        record = settings.load() if args.device else {}
        result = run(context, policy_of(record), args.cards_only)
        code = 0
    except (OSError, ValueError, fs.FilesystemError, settings.Damaged) as error:
        result = {'ok': False, 'operation': 'automount',
                  'error': {'code': getattr(error, 'code', None) or type(error).__name__, 'message': str(error)}}
        code = 2
    print(json.dumps(result, separators=(',', ':')), flush=True)
    return code


if __name__ == '__main__':
    sys.exit(main())
