#!/usr/bin/env python3
"""Check a local Android image and rollback copy against the A22x in USB recovery."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

from recovery_backup_usb import RecoverySSH
import android_compat
import filesystem as fs


def probe_recovery(recovery):
    # Run this checkout's analyzer using the installed recovery's read-only
    # partition readers. The phone does not need a rebuilt image for a probe.
    path = Path(android_compat.__file__)
    command = "import sys\nsys.path.insert(0, '/opt/a22x-recovery')\n" + path.read_text()
    argv = [*recovery.command, shlex.join(['python3', '-B', '-c', command, '--device', 'probe-super'])]
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True, timeout=360)
    receipt = json.loads(result.stdout)
    if result.returncode or receipt.get('ok') is not True:
        code = receipt.get('error', {}).get('code', 'PROBE_FAILED')
        raise ValueError('Recovery super probe failed (' + code + ')')
    if (receipt['context_identity']['mode'] != 'device'
            or receipt['context_identity']['boot_id'] != recovery.boot
            or receipt['observed_super']['boot_id'] != recovery.boot):
        raise ValueError('The super fingerprint belongs to a different recovery boot')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--rollback-root', required=True, type=Path, help='Directory containing the complete super.img')
    parser.add_argument('--current-root', type=Path, help='Optional current Android runtime metadata')
    parser.add_argument('--target-root', type=Path, help='Optional extracted target Android runtime metadata')
    parser.add_argument('--serial', default='a22x-recovery')
    parser.add_argument('--identity', type=Path, default=Path.home() / '.ssh/id_ed25519')
    args = parser.parse_args()
    try:
        with android_compat.regular_at(args.rollback_root, 'super.img'):
            pass
        with tempfile.TemporaryDirectory(prefix='a22x-update-check-', dir='/tmp') as work:
            recovery = RecoverySSH(args, Path(work) / 'known_hosts')
            receipt = probe_recovery(recovery)
            report = android_compat.analyze_file(args.target, current_root=args.current_root,
                                                 target_root=args.target_root,
                                                 rollback_root=args.rollback_root, probe=receipt)
            recovery.recheck_boot()
        print(json.dumps({'ok': True, **report}, sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, fs.FilesystemError) as error:
        print(f'Update preflight: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
