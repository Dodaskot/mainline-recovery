#!/usr/bin/python3
"""Recovery-side worker for a one-time Android archive to a computer over USB SSH."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, '/opt/a22x-recovery')
import android_migration as migration
import filesystem as fs

DESTINATION = 'usb-host-archive'
DEVICE = Path('/dev/nbd15')
SYSFS = Path('/sys/class/block/nbd15')
MOUNT_OPTIONS = {'rw', 'nodev', 'nosuid', 'noexec'}
STDERR = sys.stderr


def source_token(context):
    source = context.volume('userdata')
    migration.ad.admitted(source)
    fs.require_hash(source['volume_token'], 'Android volume token')
    if source.get('read_only_guarded') is not True or source.get('read_only') is not True:
        fs.fail('ANDROID_RO_REQUIRED', 'Unlock Android data for reading in recovery first')
    return source['volume_token']


def sectors():
    return int((SYSFS / 'size').read_text())


def wait_for(predicate, description):
    for _ in range(50):
        if predicate():
            return
        time.sleep(0.1)
    fs.fail('USB_DISK_STATE', description)


def run(*command):
    subprocess.run(command, stdin=subprocess.DEVNULL, stdout=STDERR, check=True)


class HostContext(fs.DeviceContext):
    """Admit only the single host disk mounted by this operation."""
    drive = None
    disk_size = None
    uuid = None

    def volume(self, volume_id, expected=None):
        if volume_id != DESTINATION:
            return super().volume(volume_id, expected)
        path = DEVICE.lstat()
        devno = f'{os.major(path.st_rdev)}:{os.minor(path.st_rdev)}'
        if (self.drive is None or not stat.S_ISBLK(path.st_mode)
                or devno != (SYSFS / 'dev').read_text().strip()
                or not (SYSFS / 'pid').is_file() or sectors() * 512 != self.disk_size):
            fs.fail('USB_DISK_CHANGED', 'The reserved USB disk is missing or changed')
        records = [row for row in fs.read_mounts()
                   if row['devno'] == devno or row['mountpoint'] == str(self.drive)]
        if (len(records) != 1 or records[0]['devno'] != devno or records[0]['root'] != '/'
                or records[0]['source'] != str(DEVICE) or records[0]['fs_type'] != 'ext4'
                or records[0]['mountpoint'] != str(self.drive)
                or not MOUNT_OPTIONS.issubset(records[0]['options'])):
            fs.fail('USB_DISK_CHANGED', 'The reserved USB disk mount has changed')
        disk = records[0]
        token = fs.digest({'boot_id': self.boot_id, 'mount_id': disk['mount_id'], 'pid': (SYSFS / 'pid').read_text().strip(),
                           'device': devno, 'size': self.disk_size, 'uuid': self.uuid})
        if expected is not None and expected != token:
            fs.fail('USB_DISK_CHANGED', 'The reserved USB disk token has changed')
        return {'id': volume_id, 'mounted': True, 'mountable': True, 'mount_owner': 'filesystem',
                'mountpoint': str(self.drive), 'mount_id': disk['mount_id'], 'device': devno,
                'read_only': False, 'write_supported': True, 'volume_token': token}


def relay(connection):
    def receive():
        try:
            while data := os.read(0, 128 * 1024):
                connection.sendall(data)
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def send():
        try:
            while data := connection.recv(128 * 1024):
                tail = memoryview(data)
                while tail:
                    tail = tail[os.write(1, tail):]
        except OSError:
            pass

    for copy in (receive, send):
        threading.Thread(target=copy, daemon=True).start()


@contextmanager
def host_mount(context, drive, size, fs_uuid):
    if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        fs.fail('USB_DISK_NAMESPACE', 'The USB disk bridge needs a private network namespace')
    devno = (SYSFS / 'dev').read_text().strip()
    if (sectors() or (SYSFS / 'pid').exists() or any((SYSFS / 'holders').iterdir())
            or any(row['devno'] == devno for row in fs.read_mounts())):
        fs.fail('USB_DISK_BUSY', 'The reserved USB disk is already in use')
    run('busybox', 'ip', 'link', 'set', 'lo', 'up')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(8)
        args = ['busybox', 'nbd-client', '-t', '30', '127.0.0.1', str(listener.getsockname()[1]), str(DEVICE)]
        client = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=STDERR)
        connection, mounted = None, False
        try:
            connection, _ = listener.accept()
            relay(connection)
            if client.wait(timeout=12):
                fs.fail('USB_DISK_CONNECT', 'The block device handshake failed')
            wait_for(sectors, 'The connected disk did not report its capacity')
            if sectors() * 512 != size:
                fs.fail('USB_DISK_CHANGED', 'The USB disk capacity differs from the request')
            raw = os.open(DEVICE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                node = os.fstat(raw)
                if not stat.S_ISBLK(node.st_mode) or devno != f'{os.major(node.st_rdev)}:{os.minor(node.st_rdev)}':
                    fs.fail('USB_DISK_CHANGED', 'The USB disk node is not owned by the reserved NBD device')
                info = fs.probe_magic(os.pread(raw, 4096, 0))
            finally:
                os.close(raw)
            if info['fs_type'] != 'ext4' or info['filesystem_uuid'] != fs_uuid:
                fs.fail('USB_DISK_CHANGED', 'The USB disk filesystem differs from the request')
            run('mount', '-t', 'ext4', '-o', 'nodev,nosuid,noexec', str(DEVICE), str(drive))
            mounted = True
            context.drive, context.disk_size, context.uuid = drive, size, fs_uuid
            yield context.volume(DESTINATION)
        finally:
            try:
                if mounted:
                    run('umount', str(drive))
            finally:
                if client.poll() is None:
                    client.kill()
                    client.wait()
                try:
                    if (SYSFS / 'pid').exists():
                        run('busybox', 'nbd-client', '-d', str(DEVICE))
                    wait_for(lambda: not sectors(), 'The USB disk did not disconnect')
                finally:
                    if connection is not None:
                        connection.close()


def read_exact(length):
    value = bytearray()
    while len(value) < length:
        data = os.read(0, length - len(value))
        if not data:
            fs.fail('USB_BACKUP_ABORTED', 'The USB session closed before the archive began')
        value.extend(data)
    return value


def read_password():
    length = int.from_bytes(read_exact(2), 'big')
    if not 8 <= length <= migration.ac.PASSWORD_LIMIT:
        fs.fail('BACKUP_PASSWORD_REQUIRED', 'The archive passphrase length is invalid')
    result = read_exact(length).decode('utf-8')
    migration.require_password(result)
    return result


def create_archive(context, token, password, args):
    last_report = 0.0

    def progress(size, entries):
        nonlocal last_report
        now = time.monotonic()
        if now - last_report >= 5:
            print(f'RECOVERY_BACKUP bytes={size} entries={entries}', file=STDERR, flush=True)
            last_report = now

    with tempfile.TemporaryDirectory(prefix='a22x-usb-backup-', dir='/tmp') as staging:
        drive = Path(staging) / 'disk'
        drive.mkdir(mode=0o700)
        with host_mount(context, drive, args.bytes, args.uuid) as target:
            result = migration.create(
                context, token, args.package, args.include_shared, DESTINATION, target['volume_token'],
                password, True, progress, profile=args.profile, include_settings=args.include_settings,
                include_personal=args.include_personal,
                include_apks=args.include_apks,
            )
            receipt = {key: result[key] for key in ('path', 'archive_sha256', 'archive_bytes')}
            with (drive / 'archive-receipt.json').open('x') as out:
                json.dump(receipt, out)
                out.flush()
                os.fsync(out.fileno())
            directory = os.open(drive, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)


def interrupted(_signum, _frame):
    raise InterruptedError()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('boot')
    parser.add_argument('--probe', action='store_true')
    parser.add_argument('--uuid')
    parser.add_argument('--bytes', type=int)
    parser.add_argument('--profile', choices=('same-model', 'portable'), default='same-model')
    parser.add_argument('--package', action='append', default=[])
    for flag in ('--include-shared', '--include-personal', '--include-settings', '--include-apks'):
        parser.add_argument(flag, action='store_true')
    args = parser.parse_args()
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, interrupted)
    try:
        context = HostContext()
        if context.boot_id != args.boot:
            fs.fail('RECOVERY_BOOT_MISMATCH', 'The phone rebooted after its USB identity was checked')
        with context.operation_lock():
            token = source_token(context)
            if args.probe:
                print(json.dumps({'boot_id': context.boot_id, 'userdata_ready': True}))
            else:
                create_archive(context, token, read_password(), args)
    except (fs.FilesystemError, migration.ac.CryptError) as error:
        print(f'RECOVERY_BACKUP {error.code}', file=STDERR)
        return 2
    except (OSError, ValueError, subprocess.SubprocessError):
        print('RECOVERY_BACKUP USB_BACKUP_IO_FAILED', file=STDERR)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
