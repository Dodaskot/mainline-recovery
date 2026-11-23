#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""What is installed on this phone, for the home page and the Systems tab (2026-11-22, the owner's
mock-ups: "installed systems" with real data).

Android: whether userdata holds Android's data, and what BOOT holds (Android or Linux, its Android
version and security patch from the boot header, its kernel release, the root in it). Linux: the
systems on userdata, which one is active. Only reads, under the shared operation lock; while an
operation holds storage alone it answers busy, and the interface keeps what it knew.

    systems_overview.py --device | --fixture DIR
"""
import argparse
import json
import sys

import bootimage
import distro
import filesystem as fs
import install
import saved_boot


def boot_facts(fixture=None):
    """BOOT's kind, release, root and the Android version its header names; {} when it cannot be read."""
    try:
        context = install.FixtureContext(fixture) if fixture else install.DeviceContext()
        data = install.target_bytes(context, context.target('boot'))
    except Exception:  # noqa: BLE001 - BOOT unread is "unknown" on the page, never a failure of the overview
        return {}
    facts = {}
    try:
        found = saved_boot.describe_boot(data)
        facts.update(kind=found.get('kind') or 'unknown', release=found.get('release'), root=found.get('root'))
    except Exception:  # noqa: BLE001 - a BOOT this code does not know is "unknown", not a failure
        facts['kind'] = 'unknown'
    try:
        header = bootimage.boot_header(data)
        if header.get('os'):
            facts.update(android_version=header['os']['version'], patch_level=header['os']['patch_level'])
    except Exception:  # noqa: BLE001
        pass
    return facts


def overview(context, fixture=None):
    state = distro.status(context)
    boot = boot_facts(fixture)
    slots = [{'id': s.get('id', ''), 'name': s.get('name') or s.get('id', ''), 'active': bool(s.get('active')),
              'boot_tested': bool(s.get('boot_tested'))} for s in state.get('slots') or []]
    version = (boot.get('android_version') or '').split('.')[0]
    return {'ok': True, 'operation': 'overview', 'busy': False,
            'android': {'data': bool(state.get('foreign')), 'boot': boot.get('kind', 'unknown'),
                        'version': version if version and version != '0' else '',
                        'patch': boot.get('patch_level') or '', 'kernel': boot.get('release') or '',
                        'root': boot.get('root') or ''},
            'linux': {'mounted': bool(state.get('mounted')), 'active': state.get('active') or '', 'slots': slots,
                      'boot': bool(state.get('boot_linux'))}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    where = parser.add_mutually_exclusive_group(required=True)
    where.add_argument('--device', action='store_true')
    where.add_argument('--fixture')
    args = parser.parse_args(argv)
    context = fs.FixtureContext(args.fixture) if args.fixture else fs.DeviceContext()
    try:
        with context.operation_lock(shared=True):
            result = overview(context, args.fixture)
    except fs.FilesystemError as error:
        code = getattr(error, 'code', 'ERROR')
        result = {'ok': False, 'operation': 'overview', 'busy': code == 'OPERATION_BUSY',
                  'error': {'code': code, 'message': str(error)[:200]}}
    except Exception as error:  # noqa: BLE001 - the home page shows what it knew; the reason is logged
        result = {'ok': False, 'operation': 'overview', 'busy': False,
                  'error': {'code': type(error).__name__, 'message': str(error)[:200]}}
    print(json.dumps(result, separators=(',', ':')))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
