#!/usr/bin/env python3
"""Save an authenticated Android archive from A22x recovery to the computer over USB."""
import argparse
from contextlib import suppress
import getpass
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import android_migration as migration
import filesystem as fs

WORKER = Path(__file__).with_name('recovery_backup_usb_device.py')
ADDRESS = '172.16.42.1'
GIB = 1 << 30
ARCHIVE_NAME = re.compile(
    r'/A22xMigrationBackups/(android-model-data-\d{8}-\d{6}-[0-9a-f]{16}\.tar\.zst\.enc'
    r'|android-migration-\d{8}-\d{6}-[0-9a-f]{16}\.tar\.gz\.enc)'
)


def adb_read(serial, path):
    result = subprocess.check_output(['adb', '-s', serial, 'shell', 'cat', path], text=True, timeout=10)
    return result.strip()


class RecoverySSH:
    def __init__(self, args, known_hosts):
        self.serial = args.serial
        devpath = subprocess.check_output(['adb', '-s', self.serial, 'get-devpath'], text=True, timeout=10).strip()
        if not devpath.startswith('usb:'):
            raise ValueError('ADB did not identify the selected phone as a USB device')
        self.boot = adb_read(self.serial, '/proc/sys/kernel/random/boot_id')
        if str(uuid.UUID(self.boot)) != self.boot:
            raise ValueError('The phone did not return a valid recovery boot ID')
        pub = adb_read(self.serial, '/run/a22x-recovery/ssh/ssh_host_ed25519_key.pub').split()
        if len(pub) < 2 or pub[0] != 'ssh-ed25519' or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', pub[1]):
            raise ValueError('The USB recovery host key is missing')
        known_hosts.write_text(f'{ADDRESS} {pub[0]} {pub[1]}\n')
        self.command = ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                        '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={known_hosts}',
                        '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=6',
                        '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3',
                        '-i', str(args.identity), 'root@' + ADDRESS]

    def worker(self, *options):
        remote = shlex.join(['busybox', 'unshare', '-n', 'python3', '-c', WORKER.read_text(), self.boot, *options])
        return [*self.command, remote]

    def probe(self):
        run = subprocess.run(self.worker('--probe'), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             text=True, timeout=20)
        if run.returncode:
            raise ValueError('Recovery did not admit the backup. Check the recovery status above')
        receipt = json.loads(run.stdout)
        if receipt != {'boot_id': self.boot, 'userdata_ready': True}:
            raise ValueError('Recovery did not confirm an authenticated read-only /data')
        return receipt

    def recheck_boot(self):
        if adb_read(self.serial, '/proc/sys/kernel/random/boot_id') != self.boot:
            raise ValueError('The phone rebooted during backup')


def read_secret(path):
    if path is None:
        if not sys.stdin.isatty():
            raise ValueError('Use an interactive terminal or a private --password-file')
        secret = getpass.getpass('Backup passphrase: ')
        if secret != getpass.getpass('Confirm backup passphrase: '):
            raise ValueError('Backup passphrases differ')
    else:
        handle = fs.open_regular(fs.absolute_no_symlinks(path))
        with os.fdopen(handle, 'rb') as source:
            info = os.fstat(source.fileno())
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError('The passphrase file must be private and owned by this user')
            secret = source.read(migration.ac.PASSWORD_LIMIT + 2).decode('utf-8').rstrip('\n')
    migration.require_password(secret)
    return secret


def send_all(fd, data):
    chunk = memoryview(data)
    while chunk:
        chunk = chunk[os.write(fd, chunk):]


def transfer(channel, command, secret):
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0) as ssh:
        def to_phone():
            with suppress(OSError):
                while chunk := channel.recv(128 * 1024):
                    send_all(ssh.stdin.fileno(), chunk)
            with suppress(OSError):
                ssh.stdin.close()

        def to_disk():
            with suppress(OSError):
                while chunk := os.read(ssh.stdout.fileno(), 128 * 1024):
                    channel.sendall(chunk)
                channel.shutdown(socket.SHUT_WR)

        try:
            encoded = secret.encode('utf-8')
            send_all(ssh.stdin.fileno(), len(encoded).to_bytes(2, 'big') + encoded)
            threads = [threading.Thread(target=copy, daemon=True) for copy in (to_phone, to_disk)]
            for worker in threads:
                worker.start()
            status = ssh.wait()
        finally:
            with suppress(OSError):
                channel.shutdown(socket.SHUT_RDWR)
            if ssh.poll() is None:
                ssh.terminate()
                try:
                    ssh.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    ssh.kill()
                    ssh.wait()
        for worker in threads:
            worker.join(timeout=2)
        if status:
            raise ValueError(f'Recovery backup failed with SSH exit status {status}')


def save_to_disk(recovery, stage, socket_dir, args, secret):
    disk = stage / 'disk.ext4'
    with disk.open('xb') as image:
        image.truncate(args.size_gib * GIB)
    disk_uuid = str(uuid.uuid4())
    subprocess.run(['mkfs.ext4', '-q', '-F', '-m', '0', '-b', '4096', '-U', disk_uuid, str(disk)], check=True)
    options = ['--uuid', disk_uuid, '--bytes', str(disk.stat().st_size), '--profile', args.profile]
    for package in args.package:
        options.extend(['--package', package])
    for selection in ('include_shared', 'include_settings', 'include_personal', 'include_apks'):
        if getattr(args, selection):
            options.append('--' + selection.replace('_', '-'))
    address = Path(socket_dir) / 'nbd.sock'
    server = subprocess.Popen(['qemu-nbd', '--persistent', '--format=raw', '--cache=writethrough',
                               '--socket', str(address), str(disk)])
    try:
        for _ in range(50):
            if address.is_socket():
                break
            if server.poll() is not None:
                raise ValueError('Could not start the private USB backup disk')
            time.sleep(0.1)
        with socket.socket(socket.AF_UNIX) as channel:
            channel.connect(str(address))
            transfer(channel, recovery.worker(*options), secret)
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
    recovery.recheck_boot()
    subprocess.run(['e2fsck', '-fn', disk.name], cwd=stage, check=True, stdout=subprocess.DEVNULL)


def verify_from_disk(stage, secret, profile):
    def extract(source, dest):
        result = subprocess.run(['debugfs', '-R', f'dump {source} {dest}', 'disk.ext4'],
                                cwd=stage, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode or not (stage / dest).is_file():
            raise ValueError('The recovery disk is missing a committed archive or receipt')

    extract('/archive-receipt.json', 'receipt.json')
    with (stage / 'receipt.json').open('rb') as receipt_file:
        data = receipt_file.read(4097)
    if len(data) > 4096:
        raise ValueError('Recovery commit receipt exceeds its size limit')
    receipt = json.loads(data)
    if (not isinstance(receipt, dict) or set(receipt) != {'path', 'archive_sha256', 'archive_bytes'}
            or type(receipt['archive_bytes']) is not int or receipt['archive_bytes'] <= 0):
        raise ValueError('The recovery disk reported an invalid commit receipt')
    source = receipt['path']
    if (not isinstance(source, str) or not ARCHIVE_NAME.fullmatch(source)
            or (profile == 'same-model') != source.endswith('.tar.zst.enc')):
        raise ValueError('The recovery disk reported an unexpected archive path')
    fs.require_hash(receipt['archive_sha256'], 'Recovery archive SHA-256')
    extract(source, 'verified.enc')
    path = stage / 'verified.enc'
    fd = fs.open_regular(path)
    try:
        os.fchmod(fd, 0o600)
        if receipt['archive_bytes'] != os.fstat(fd).st_size:
            raise ValueError('The archive size differs from the recovery receipt')
        checked = migration.verify_fd(fd, secret, receipt['archive_sha256'])
        model = checked['manifest']['schema'] == migration.ad.MODEL_SCHEMA
        if model != (profile == 'same-model'):
            raise ValueError('The verified archive profile differs from the request')
        os.fsync(fd)
    finally:
        os.close(fd)
    return path, {'archive_sha256': checked['archive_sha256'], 'archive_bytes': checked['archive_bytes'],
                  'schema': checked['manifest']['schema']}


def publish(source, output):
    fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.link(source, output.name, dst_dir_fd=fd, follow_symlinks=False)
        try:
            os.fsync(fd)
        except OSError:
            owned = source.stat()
            migration.ad.owned_unlink(fd, output.name, (owned.st_dev, owned.st_ino))
            raise
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--check', action='store_true', help='Verify USB SSH and authenticated /data without creating a disk')
    action.add_argument('--output', type=Path, help='New .tar.zst.enc or .tar.gz.enc archive path')
    parser.add_argument('--serial', default='a22x-recovery', help='ADB serial of the phone connected by USB')
    parser.add_argument('--identity', type=Path, default=Path.home() / '.ssh/id_ed25519')
    parser.add_argument('--password-file', type=Path)
    parser.add_argument('--size-gib', type=int, default=64, help='Size of the temporary virtual disk, in GiB')
    parser.add_argument('--profile', choices=('same-model', 'portable'), default='same-model')
    parser.add_argument('--package', action='append', default=[])
    for flag in ('--include-shared', '--include-settings', '--include-personal', '--include-apks'):
        parser.add_argument(flag, action='store_true')
    args = parser.parse_args()
    try:
        if ':' in args.serial:
            raise ValueError('Select the phone connected through USB')
        with tempfile.TemporaryDirectory(prefix='a22x-usb-', dir='/tmp') as session:
            recovery = RecoverySSH(args, Path(session) / 'known_hosts')
            ready = recovery.probe()
            if args.check:
                print(json.dumps(ready))
                return 0
            output = fs.absolute_no_symlinks(args.output, missing=True)
            suffix = '.tar.zst.enc' if args.profile == 'same-model' else migration.SUFFIX
            if not output.name.endswith(suffix) or output.exists():
                raise ValueError(f'Choose a new archive path ending in {suffix}')
            if not 1 <= args.size_gib <= 512:
                raise ValueError('Choose a USB backup disk size from 1 to 512 GiB')
            if shutil.disk_usage(output.parent).free < (2 * args.size_gib + 1) * GIB:
                raise ValueError('The destination needs room for the temporary disk and the verified archive')
            secret = read_secret(args.password_file)
            with tempfile.TemporaryDirectory(prefix='.a22x-backup-', dir=output.parent) as temp:
                stage = Path(temp)
                save_to_disk(recovery, stage, session, args, secret)
                source, verified = verify_from_disk(stage, secret, args.profile)
                publish(source, output)
            print(json.dumps({'output': str(output), **verified}))
    except (ValueError, OSError, subprocess.SubprocessError, fs.FilesystemError) as error:
        print(f'USB backup: {error}', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('USB backup interrupted', file=sys.stderr)
        return 130
    return 0


if __name__ == '__main__':
    sys.exit(main())
