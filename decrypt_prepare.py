"""Current-boot public runtime admission and private EFS backup for native CE.

Every password byte stays in an inherited anonymous pipe. This module reads
only public firmware/geometry and an opaque EFS backup, never credential data.
A backup is never an authentication backend and is never copied back.
"""
from __future__ import annotations
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import itertools
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

from android_decrypt import STATE_DIR, regular_json, fail
from android_profiles import EVO_PROFILE, LEGACY_EVO_NONE_PROFILE, EVO_NAMESPACE, GATEKEEPERD_SHA, KERNEL_BUILD, validate_profile


def write_private(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as dst:
            dst.write(data); dst.flush(); os.fsync(fd)
    finally:
        os.close(fd)
    return hashlib.sha256(data).hexdigest()


CACHE_RESERVE = 12 * 1024 * 1024
BACKUP_BYTES = 8 * 1024 * 1024
MANAGED_RELATIVE = Path('a22x-recovery/private-efs/managed-v1')
LEDGER_NAME = 'retention-v1.json'
UUID_PATTERN = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
BOOTSTRAP_ATTEMPT = Path('/run/a22x-tzdev-bootstrap-watchdog.attempted')
STORAGE_BUSY = 'DECRYPT_STORAGE_BUSY'


def sync_directory(parent):
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_directory(path, owner=0, shared_parent=False):
    from filesystem import absolute_no_symlinks
    absolute_no_symlinks(path)
    s = path.lstat()
    if (not stat.S_ISDIR(s.st_mode) or s.st_uid != owner
            or (s.st_mode & 0o022 if shared_parent else stat.S_IMODE(s.st_mode) != 0o700)):
        raise ValueError('Private backup directory ownership')


class BackupRetention:
    """Only new versioned snapshots are managed; interrupted pruning fails closed.

    Production always uses uid0. owner is explicit for unprivileged disk fixtures.
    A pending prune is never automatically resumed after interruption.
    """
    def __init__(self, parent, owner=0):
        self.parent, self.owner = Path(parent), owner
        private_directory(self.parent, owner)

    def read(self, name, mode, maximum, exact=None):
        fd = os.open(self.parent / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != self.owner
                    or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != mode
                    or not 0 < before.st_size <= maximum or
                    (exact is not None and before.st_size != exact)):
                raise ValueError('Managed backup file shape')
            digest, data, total = hashlib.sha256(), bytearray(), 0
            while chunk := os.read(fd, 65536):
                total += len(chunk)
                if total > before.st_size:
                    raise ValueError('Managed backup changed')
                digest.update(chunk)
                if exact is None:
                    data.extend(chunk)
            after = os.fstat(fd)
            if (total != before.st_size or
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError('Managed backup changed')
            return bytes(data), digest.hexdigest(), (before.st_dev, before.st_ino)
        finally:
            os.close(fd)

    def pair(self, entry):
        if (not isinstance(entry, dict) or set(entry) != {'boot_id', 'image_sha256', 'receipt_sha256', 'userdata_epoch'}
                or not re.fullmatch(UUID_PATTERN, entry.get('boot_id', ''))
                or any(not re.fullmatch(r'[0-9a-f]{64}', entry.get(k, ''))
                       for k in ('image_sha256', 'receipt_sha256'))
                or not isinstance(entry.get('userdata_epoch'), str)):
            raise ValueError('Managed backup entry')
        boot = entry['boot_id']
        _, image_hash, image_id = self.read(boot + '.img', 0o400, BACKUP_BYTES, BACKUP_BYTES)
        data, receipt_hash, receipt_id = self.read(boot + '.json', 0o600, 16384)
        receipt = json.loads(data)
        if not isinstance(receipt, dict):
            raise ValueError('Managed backup receipt shape')
        expected = {'schema': 1, 'status': 'CURRENT_EFS_FULL_BACKUP_FSYNC_AND_REREAD_PASS',
                    'backup_boot_id': boot, 'userdata_epoch': entry['userdata_epoch'],
                    'source_path': '/dev/mmcblk0p2', 'source_major': 179, 'source_minor': 2,
                    'size_bytes': BACKUP_BYTES, 'source_sha256': image_hash,
                    'backup_sha256': image_hash, 'backup_fsynced': True,
                    'independent_reread_match': True, 'backup_mode': 0o400,
                    'automatic_restore_authorized': False,
                    'backup_relative': str(MANAGED_RELATIVE / (boot + '.img'))}
        if (any(receipt.get(k) != value for k, value in expected.items())
                or image_hash != entry['image_sha256'] or receipt_hash != entry['receipt_sha256']):
            raise ValueError('Managed backup receipt/hash mismatch')
        return image_id, receipt_id

    def load(self, candidate=None):
        names = {x.name for x in itertools.islice(self.parent.iterdir(), 13)}
        if len(names) > 12:
            raise ValueError('Retention directory exceeds managed bound')
        if LEDGER_NAME not in names:
            if names - ({candidate + '.img', candidate + '.json'} if candidate else set()):
                raise ValueError('Unmanaged files in retention directory')
            return {'schema': 'a22x.efs-retention.v1', 'entries': [], 'pending_prune': None}
        data, _, _ = self.read(LEDGER_NAME, 0o600, 16384)
        ledger = json.loads(data)
        if (not isinstance(ledger, dict) or set(ledger) != {'schema', 'entries', 'pending_prune'}
                or ledger['schema'] != 'a22x.efs-retention.v1'
                or not isinstance(ledger['entries'], list) or len(ledger['entries']) > 2
                or ledger['pending_prune'] is not None):
            raise ValueError('Retention ledger needs manual review; nothing pruned')
        boots = []
        for entry in ledger['entries']:
            self.pair(entry)
            boots.append(entry['boot_id'])
        if len(set(boots)) != len(boots):
            raise ValueError('Duplicate retained boot')
        allowed = {LEDGER_NAME, *(b + suffix for b in boots for suffix in ('.img', '.json'))}
        if candidate:
            allowed |= {candidate + '.img', candidate + '.json'}
        if names - allowed:
            raise ValueError('Unexpected retention file; nothing pruned')
        return ledger

    def persist(self, ledger):
        # A stale temporary file is an interrupted commit, never overwritten.
        temporary = self.parent / '.retention-v1.new'
        write_private(temporary, ledger)
        os.replace(temporary, self.parent / LEDGER_NAME)
        sync_directory(self.parent)

    def commit(self, boot, receipt):
        ledger = self.load(candidate=boot)
        if any(e['boot_id'] == boot for e in ledger['entries']):
            raise ValueError('Current boot already retained')
        _, receipt_hash, _ = self.read(boot + '.json', 0o600, 16384)
        entry = {'boot_id': boot, 'image_sha256': receipt['backup_sha256'],
                 'receipt_sha256': receipt_hash, 'userdata_epoch': receipt['userdata_epoch']}
        self.pair(entry)  # Full reread of image and persisted receipt before any pruning.
        entries = ledger['entries'] + [entry]
        old = entries[0] if len(entries) > 2 else None
        self.persist({'schema': ledger['schema'], 'entries': entries, 'pending_prune': old})
        if old is not None:
            if old['boot_id'] == boot:
                raise ValueError('Refuse pruning current boot')
            # Verify all retained snapshots again after durable commit of the new one.
            for item in entries:
                self.pair(item)
            identities = self.pair(old)
            for suffix, expected_id in zip(('.img', '.json'), identities):
                path = self.parent / (old['boot_id'] + suffix)
                current = path.lstat()
                if (current.st_dev, current.st_ino) != expected_id:
                    raise ValueError('Prune inode changed')
                path.unlink()
                sync_directory(self.parent)
            entries = entries[1:]
            self.persist({'schema': ledger['schema'], 'entries': entries, 'pending_prune': None})


def record_preflight(context, code):
    parent = STATE_DIR.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(parent, shared_parent=True)
    path = parent / 'android-decrypt-preflight.json'
    if path.exists() or path.is_symlink():
        # Never replace foreign/malformed advisory files.
        value = regular_json(path)
        s = path.lstat()
        if (stat.S_IMODE(s.st_mode) != 0o600 or
                value.get('schema') != 'a22x.decrypt.preflight.v1'):
            raise ValueError('Preflight advisory ownership')
    temporary = parent / ('.decrypt-preflight-' + secrets.token_hex(8))
    write_private(temporary, {'schema': 'a22x.decrypt.preflight.v1',
                             'boot_id': context.boot_id, 'code': code})
    os.replace(temporary, path)
    sync_directory(parent)


def cache_preflight(context):
    """No cache write or consumed TEE state before this prerequisite passes."""
    cache = context.volume('cache')
    if cache['mounted']:
        fail(STORAGE_BUSY, 'Could not release cache for Android preparation.', volume='cache')
    if cache.get('write_supported') is not True:
        fail('DECRYPT_BACKUP_UNAVAILABLE', 'Cache is not ready for an EFS safety copy.')
    owned = False
    try:
        context.mount('cache', 'ro', False, cache['volume_token'])
        owned = True
        cache = context.volume('cache')
        if (not cache['mounted'] or cache.get('read_only') is not True
                or cache.get('mount_owner') != 'filesystem'):
            raise ValueError('Cache preflight mount identity')
        mountpoint = Path(cache['mountpoint'])
        from filesystem import absolute_no_symlinks
        absolute_no_symlinks(mountpoint)
        for relative in ('a22x-recovery', 'a22x-recovery/private-efs', str(MANAGED_RELATIVE)):
            path = mountpoint / relative
            absolute_no_symlinks(path, missing=True)
            if path.exists():
                private_directory(path, shared_parent=(relative == 'a22x-recovery'))
        managed = mountpoint / MANAGED_RELATIVE
        if managed.exists():
            BackupRetention(managed).load()
        space = os.statvfs(mountpoint)
        if space.f_bavail * space.f_frsize < CACHE_RESERVE:
            fail('DECRYPT_BACKUP_SPACE', 'Cache needs 12 MiB free for the current EFS safety copy; free cache space and retry.')
    finally:
        if owned:
            context.unmount('cache')
            if context.volume('cache')['mounted']:
                raise ValueError('Cache preflight did not unmount')


def bootstrap_mounts():
    from filesystem import read_mounts

    # Match the pinned secure-world and session watchdog preconditions.
    return [row for row in read_mounts()
            if not row['devno'].startswith('0:') or row['mountpoint'].startswith('/mnt/')]


def require_clean_mounts():
    if bootstrap_mounts():
        fail(STORAGE_BUSY, 'Stop operations using mounted storage before opening Android data.',
             authentication_performed=False)


def bootstrap_unstarted():
    # The pinned wrapper creates this guard before touching SRAM or arming the watchdog.
    # Linux driver gates must independently still have their initial values.
    try:
        return (not BOOTSTRAP_ATTEMPT.exists() and not Path('/run/a22x-tzdev/attempted').exists()
                and set(tee_gates().values()) == {'-11'})
    except OSError:
        return False


@contextmanager
def temporary_bootstrap_mounts(context):
    """Hold the caller's operation lease until the native worker has its private mount namespace."""
    from filesystem import FilesystemError, MOUNT_BASE

    mounted = bootstrap_mounts()
    volumes = [v for v in context.volumes()
               if v['mounted'] and v.get('mount_owner') == 'filesystem'
               and (v['id'] == 'cache' or v.get('external') is True
                    or (v.get('container') == 'super' and v.get('mountable') is True
                        and v.get('read_only') is True))
               and v['mountpoint'] == str(MOUNT_BASE / v['id'])] if mounted else []
    by_mount = {(v['mount_id'], v['device'], v['mountpoint']): v for v in volumes}
    planned = []
    for row in mounted:
        v = by_mount.get((row['mount_id'], row['devno'], row['mountpoint']))
        if v is None or row['root'] != '/' or context.nested_mounts(v, '/'):
            fail(STORAGE_BUSY, 'Stop operations using mounted storage before opening Android data.',
                 authentication_performed=False, **({'volume': v['id']} if v else {}))
        planned.append((v['id'], v['volume_token'], 'ro' if v['read_only'] else 'rw'))

    released, warnings = [], []
    initial_error = None
    completed = False
    try:
        for ident, token, mode in planned:
            released.append((ident, token, mode))
            try:
                context.unmount(ident, token)
            except (FilesystemError, OSError) as error:
                fail(STORAGE_BUSY, 'A volume is in use. Close the operation using it and try again.',
                     volume=ident, cause=getattr(error, 'code', 'IO_ERROR'), authentication_performed=False)
        require_clean_mounts()
        yield warnings
        completed = True
    except BaseException as error:
        initial_error = error
        raise
    finally:
        if released and (completed or bootstrap_unstarted()):
            for ident, token, mode in reversed(released):
                try:
                    v = context.mount(ident, mode, mode == 'rw', token)['volume']
                    if not v['mounted'] or v['read_only'] != (mode == 'ro'):
                        warnings.append(ident)
                except (FilesystemError, OSError):
                    warnings.append(ident)
        if warnings and isinstance(initial_error, FilesystemError):
            initial_error.details['storage_restore_failed'] = warnings


def extract_members(archive, root, members):
    """Keep the pinned runtime permissions even under the private 0077 umask.

    Python's data filter deliberately omits directory modes and can add owner
    write permission to regular files. UID 1000 services need the exact public
    rootfs traversal modes. The containing runtime directory stays root-only.
    """
    if len({m.name for m in members}) != len(members):
        raise ValueError('Duplicate runtime archive member')
    for m in members:
        parts = Path(m.name).parts
        allowed_modes = (0o700, 0o755) if m.isdir() else (0o444, 0o555, 0o644, 0o755)
        if (not parts or m.name.startswith('/') or '..' in parts
                or not (m.isfile() or m.isdir()) or m.mode not in allowed_modes):
            raise ValueError('Runtime archive member')
    archive.extractall(root, members=members, filter='data')
    for m in members:
        target = root / m.name
        expected_type = stat.S_ISDIR if m.isdir() else stat.S_ISREG
        if not expected_type(target.lstat().st_mode):
            raise ValueError('Runtime archive type changed')
        target.chmod(m.mode)
    for m in members:
        if stat.S_IMODE((root / m.name).lstat().st_mode) != m.mode:
            raise ValueError('Runtime mode readback')

def _extract_runtime(p, root):
    archive = Path(p['bundle_path'])
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                or st.st_mode & 0o022 or not 0 < st.st_size < 32 * 1024 * 1024):
            raise ValueError('Runtime package shape')
        data = bytearray()
        while chunk := os.read(fd, 65536):
            data.extend(chunk)
            if len(data) > st.st_size:
                raise ValueError('Runtime package grew')
        if len(data) != st.st_size or hashlib.sha256(data).hexdigest() != p['bundle_sha256']:
            raise ValueError('Runtime package pin')
    finally:
        os.close(fd)
    import io
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        members = archive.getmembers()
        if len(members) != p['runtime_member_count'] or sum(m.size for m in members) > 32 * 1024 * 1024:
            raise ValueError('Runtime archive bounds')
        extract_members(archive, root, members)
    manifest = root / 'android-root/ROOT-MANIFEST.json'
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != p['root_manifest_sha256']:
        raise ValueError('Runtime manifest pin')
    spec = importlib.util.spec_from_file_location('decrypt_stage_verify', root / 'controller/stage_android_ro.py')
    stage = importlib.util.module_from_spec(spec); spec.loader.exec_module(stage)
    if stage.verify_bundle(root / 'android-root', check_host_source=False) != p['root_manifest_sha256']:
        raise ValueError('Runtime contents pin')
    return root


def runtime_bundle(p, boot, *, warm_only=False):
    """Publish the verified public bundle once, then claim it once for this boot."""
    if not re.fullmatch(UUID_PATTERN, boot):
        raise ValueError('Invalid boot identity')
    root = Path('/tmp') / ('a22x-decrypt-runtime-' + boot)
    staging = Path('/tmp') / ('a22x-decrypt-staging-' + boot)
    staging.mkdir(mode=0o700, exist_ok=True)
    private_directory(staging)
    lock = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if root.exists():
            if warm_only:
                return None
            raise ValueError('Runtime directory already exists; session is not replayed')
        ready = staging / p['bundle_sha256']
        if not ready.exists():
            with tempfile.TemporaryDirectory(dir=staging) as work:
                candidate = Path(work) / 'runtime'
                candidate.mkdir(mode=0o700)
                _extract_runtime(p, candidate)
                candidate.rename(ready)
        private_directory(ready)
        if warm_only:
            return ready
        ready.rename(root)
        return root
    finally:
        os.close(lock)


def tee_gates():
    base = Path('/sys/module/tzdev/parameters')
    return {n: (base / n).read_text().strip() for n in
            ('early_bootstrap_result', 'deploy_result', 'root_task_probe_result')}


def bootstrap(context, p, run_dir):
    gates = tee_gates()
    if set(gates.values()) != {'-11'}:
        fail('DECRYPT_REBOOT_REQUIRED', 'Restart recovery before starting Android authentication.')
    wrapper = Path('/opt/a22x-recovery/decrypt_bootstrap.py')
    if hashlib.sha256(wrapper.read_bytes()).hexdigest() != p['bootstrap_wrapper_sha256']:
        raise ValueError('Bootstrap wrapper pin')
    require_clean_mounts()
    log = run_dir / 'bootstrap.log'
    with log.open('xb') as dst:
        os.chmod(log, 0o600)
        write_private(run_dir / 'tee-consumed.json', {
            'schema': 'a22x.decrypt.tee-consumed.v1', 'boot_id': context.boot_id,
            'reason': 'Secure-world bootstrap was dispatched; restart recovery before another preparation.'})
        child = subprocess.Popen(['/usr/bin/python3', str(wrapper), '--boot-id', context.boot_id,
                    '--common-lock-fd', str(context.lock_fd), '--start-once'],
                    stdin=subprocess.DEVNULL, stdout=dst, stderr=dst,
                    close_fds=True, pass_fds=(context.lock_fd,), start_new_session=True)
        # The wrapper owns watchdog recovery of an uncertain secure call.
        # Parent cancellation never claims that killing a process undoes it.
        try:
            rc = child.wait(timeout=115)
        except subprocess.TimeoutExpired:
            fail('DECRYPT_REBOOT_REQUIRED', 'The secure-world bootstrap did not finish; wait for watchdog recovery.')
    if rc != 0 and bootstrap_unstarted() and log.stat().st_size <= 16384:
        if b'AssertionError: block filesystem mounted' in log.read_bytes():
            fail(STORAGE_BUSY, 'Storage was mounted again before Android preparation could start.',
                 authentication_performed=False)
    if rc != 0 or tee_gates() != {'early_bootstrap_result': '0', 'deploy_result': '-95', 'root_task_probe_result': '0'}:
        fail('DECRYPT_REBOOT_REQUIRED', 'The secure-world bootstrap failed; no password was submitted.')
    events = []
    if log.stat().st_size > 16384:
        raise ValueError('Bootstrap log bound')
    for line in log.read_text().splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event.get('event'))
    if 'watchdog_disarmed' not in events or 'root_task_probe_returned' not in events:
        raise ValueError('Bootstrap terminal evidence')
    # Independently outlive the qualified 16-second hardware watchdog.
    deadline = time.monotonic() + 17
    while time.monotonic() < deadline:
        time.sleep(min(.5, deadline - time.monotonic()))
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != context.boot_id:
        raise ValueError('Boot changed after bootstrap')
    payload = regular_json('/run/a22x-tzdev/payload.json')
    if payload.get('sha256') != '337dce4db86987b2de2633f65ec87bdbc5d19b90ed42c60101000d61f60345b2':
        raise ValueError('TZAR payload changed')
    return {'status': 'B_RUNTIME_TZAR_DEPLOY_AND_CHECK_VERSION_PASS', 'boot_id': context.boot_id,
            'kernel_build': KERNEL_BUILD, 'lk_mode': 2, 'tzdev_initialized': True,
            'tzar_deployed': True, 'early_swd_ready': True, 'source_partition': 'tzar',
            'payload_sha256': payload['sha256'], 'tee_gates': tee_gates(),
            'watchdog_disarmed_reported': True, 'same_boot_alive_after_watchdog_timeout': True,
            'auth_calls': 0}


def collect_layout(root, boot):
    result = subprocess.run(['/usr/bin/python3', str(root / 'controller/g2/collect_layout.py'),
                '--lp-module', str(root / 'android-root/support/lp_metadata.py'),
                '--expected-boot-id', boot], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode or len(result.stdout) > 16384:
        raise ValueError('Current geometry unavailable')
    layout = json.loads(result.stdout)
    if layout.get('boot_id') != boot or layout.get('evidence') != 'RECORDED_READ_ONLY_OBSERVATION':
        raise ValueError('Geometry identity')
    return layout


def durable_efs_backup(context, root, run_dir, p):
    from filesystem import absolute_no_symlinks
    # Only the existing Files helper admits cache geometry and write access.
    # Close it before C so the qualified initial mount graph remains unchanged.
    cache = context.volume('cache')
    if cache['mounted']:
        fail(STORAGE_BUSY, 'Could not release cache for the EFS safety copy.', volume='cache')
    context.mount('cache', 'rw', True, cache['volume_token'])
    src = dst = -1
    committed = False
    try:
        cache = context.volume('cache')
        parent = Path(cache['mountpoint']) / MANAGED_RELATIVE
        absolute_no_symlinks(parent, missing=True)
        for directory in (parent.parent.parent, parent.parent, parent):
            directory.mkdir(mode=0o700, exist_ok=True)
            private_directory(directory, shared_parent=(directory == parent.parent.parent))
        for directory in (parent, parent.parent, parent.parent.parent, Path(cache['mountpoint'])):
            sync_directory(directory)
        retention = BackupRetention(parent)
        retention.load()
        if os.statvfs(parent).f_bavail * os.statvfs(parent).f_frsize < CACHE_RESERVE:
            fail('DECRYPT_BACKUP_SPACE', 'Cache needs 12 MiB free for the current EFS safety copy.')
        sys.path.insert(0, str(root / 'controller/g2'))
        import native_efs_policy as native
        src = os.open(native.NODE, os.O_RDONLY | os.O_DIRECT | os.O_NOFOLLOW | os.O_CLOEXEC)
        st = os.fstat(src)
        if not stat.S_ISBLK(st.st_mode) or (os.major(st.st_rdev), os.minor(st.st_rdev)) != (179, 2):
            raise ValueError('EFS source identity')
        import fcntl, struct
        if struct.unpack('Q', fcntl.ioctl(src, native.BLKGETSIZE64, bytes(8)))[0] != native.BYTES:
            raise ValueError('EFS source size')
        before = native.superblock(native.read_direct(src, 4096, 0)[1024:2048])
        if before['error_state']:
            raise ValueError('EFS reports an existing error')
        backup = parent / (context.boot_id + '.img')
        partial = parent / (context.boot_id + '.partial')
        dst = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        h = hashlib.sha256()
        for offset in range(0, native.BYTES, 65536):
            data = native.read_direct(src, 65536, offset)
            h.update(data)
            view = memoryview(data)
            while view:
                n = os.write(dst, view)
                if n <= 0:
                    raise OSError('Short backup write')
                view = view[n:]
        os.fsync(dst); os.fchmod(dst, 0o400); os.fsync(dst)
        os.close(dst); dst = -1
        os.link(partial, backup, follow_symlinks=False); partial.unlink()
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        h2 = hashlib.sha256()
        with backup.open('rb') as reread:
            for chunk in iter(lambda: reread.read(65536), b''):
                h2.update(chunk)
        if backup.stat().st_size != native.BYTES or h2.digest() != h.digest():
            raise ValueError('Independent backup reread')
        receipt = {'schema': 1, 'status': 'CURRENT_EFS_FULL_BACKUP_FSYNC_AND_REREAD_PASS',
            'backup_boot_id': context.boot_id, 'userdata_epoch': p['userdata_epoch'],
            'source_path': native.NODE, 'source_major': 179, 'source_minor': 2,
            'size_bytes': native.BYTES, 'source_sha256': h.hexdigest(),
            'backup_sha256': h2.hexdigest(), 'backup_fsynced': True,
            'independent_reread_match': True, 'backup_mode': 0o400,
            'automatic_restore_authorized': False, 'backup_relative': str(backup.relative_to(cache['mountpoint']))}
        write_private(parent / (context.boot_id + '.json'), receipt)
        sync_directory(parent)
        retention.commit(context.boot_id, receipt)
        receipt_path = run_dir / 'efs-backup.json'
        receipt_pin = write_private(receipt_path, receipt)
        committed = True
        return receipt_path, receipt_pin
    finally:
        if dst >= 0:
            os.close(dst)
        if src >= 0:
            os.close(src)
        context.unmount('cache')
        if committed and context.volume('cache')['mounted']:
            raise ValueError('Backup cache did not unmount')


def prepare(context, volume, p):
    validate_profile(p, p.get('profile_id'))
    none_profile = p['profile_id'] == LEGACY_EVO_NONE_PROFILE
    boot = context.boot_id
    if not re.fullmatch(UUID_PATTERN, boot):
        raise ValueError('Boot identity shape')
    # Cache prerequisite must not consume a boot or create a run directory.
    try:
        if not none_profile:
            cache_preflight(context)
    except Exception as error:
        code = getattr(error, 'code', None)
        if code in ('DECRYPT_BACKUP_SPACE', 'DECRYPT_BACKUP_UNAVAILABLE', 'DECRYPT_PREPARATION_FAILED'):
            record_preflight(context, code)
        elif isinstance(error, ValueError):
            record_preflight(context, 'DECRYPT_BACKUP_REVIEW')
        raise
    record_preflight(context, 'PASS')
    for parent in (STATE_DIR, *STATE_DIR.parents):
        if parent.is_symlink():
            raise ValueError('State directory symlink')
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = STATE_DIR.lstat()
    if state.st_uid != 0 or stat.S_IMODE(state.st_mode) != 0o700:
        raise ValueError('State directory ownership')
    if any(STATE_DIR.iterdir()):
        fail('DECRYPT_REBOOT_REQUIRED', 'This boot has already prepared an Android unlock session.')
    run_id = 'gui' + secrets.token_hex(7)
    run_dir = STATE_DIR / run_id
    run_dir.mkdir(mode=0o700)
    root = runtime_bundle(p, boot)
    layout = collect_layout(root, boot)
    try:
        tee = bootstrap(context, p, run_dir)
        if not none_profile:
            receipt, receipt_pin = durable_efs_backup(context, root, run_dir, p)
    except Exception as error:
        code = getattr(error, 'code', 'DECRYPT_PREPARATION_FAILED')
        if code == STORAGE_BUSY and bootstrap_unstarted():
            shutil.rmtree(run_dir)
            shutil.rmtree(root)
            record_preflight(context, code)
            raise
        if code not in ('DECRYPT_BACKUP_SPACE', 'DECRYPT_REBOOT_REQUIRED'):
            code = 'DECRYPT_PREPARATION_FAILED'
        write_private(run_dir / 'preparation-failure.json', {
            'schema': 'a22x.decrypt.preparation-failure.v1', 'boot_id': boot, 'code': code})
        raise
    c = {'boot_id': boot, 'run_id': run_id, 'module_dir': str(root / 'controller/g2'),
         'qualified_dir': str(root), 'bundle': str(root / 'android-root'),
         'layout': layout, 'tee_receipt': tee, 'root_manifest_sha256': p['root_manifest_sha256'],
         'state_dir': str(STATE_DIR), 'mountpoint': '/mnt/volumes/userdata',
         'volume_token': volume['volume_token'], 'profile_id': p['profile_id'],
         'android_user_id': 0, 'read_only': True,
         'native_efs_policy': None if none_profile else {'mode': 'NATIVE_EFS_PERSISTENCE', 'journal_policy': 'NATIVE_EXT4_RECOVERY',
             'normal_restore_provenance': False, 'profile_id': p['profile_id'], 'nonce': secrets.token_hex(32), 'boot_id': boot,
             'run_id': run_id, 'kernel_build': KERNEL_BUILD, 'root_manifest_sha256': p['root_manifest_sha256'],
             'device_cid': Path('/sys/class/block/mmcblk0/device/cid').read_text().strip(),
             'backup_receipt': str(receipt), 'backup_receipt_sha256': receipt_pin}}
    if p['profile_id'] == EVO_PROFILE:
        c.update(gatekeeper_namespace=dict(EVO_NAMESPACE), gatekeeperd_sha256=GATEKEEPERD_SHA)
    from decrypt_runtime.rw_support import available
    if available(p):
        c['ce_rw'] = p['ce_rw']
    from decrypt_runtime.session_support import available as session_available
    if session_available(p):
        c['ce_session'] = p['ce_session']
    path = run_dir / 'config.json'
    write_private(path, c)
    return path

if __name__ == '__main__':
    if sys.argv[1:] != ['--warm-public-runtime']:
        raise SystemExit(2)
    from android_decrypt import PROFILE, profile
    # Public images carry no decryption profile: there is nothing to prepare (2026-11-19, beta1 log).
    if not PROFILE.exists():
        raise SystemExit(0)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    runtime_bundle(profile(), boot, warm_only=True)
