"""Exact Evolution16 NONE admission, private CE delivery and retained RO mount.

The bounded parser/proofs are derived from the physically qualified live05
worker. No credential FD, Gatekeeper, guessed secret, retries or key bytes here.
"""
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from android_profiles import G4_SHA, NONE_SHA

G3_SHA = 'b7cf34453664e1d1da7f9d0df5cd15934c0ff9715df953c5795a8c2a457b6a83'
NONE_READY = 'G3 NONE_PROFILE_READY sp_version=3 primary_absent=1 ce=software_absent secure_calls=0'
NONE_DELIVERED = 'G3 NONE_CE_AUTHENTICATED_KEY_DELIVERED bytes=64 gk_calls=0'
FRAMEWORK = {
    'services.jar': 'ae824be13cfc9f5f7e9673ee9230fdaea5e3fc91230cecbdaf511974c99a533b',
    'framework.jar': '52018a98c6718d17f0c80386d842f1d15bca36b35498e12ecd669e354a34483a',
}
WARNING = b'linker: Warning: failed to find generated linker configuration from "/linkerconfig/ld.config.txt"'
LITERALS = frozenset(x.encode() for x in (
    'G3 INPUT_PROFILE_REQUIRED', 'G3 FD_GUARD_FAILED', 'G3 MEMORY_GUARD_FAILED',
    'G3 INPUT_FORMAT_REJECTED', 'G3 REMOTE_MANAGER_UNAVAILABLE',
    'G3 HAL_TRANSPORT_REJECTED', 'G3 REMOTE_HAL_UNAVAILABLE',
    'G3 PRIVATE_PIPE_FAILED', 'G3 AUTHENTICATED_KEY_DELIVERED',
    'G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS', 'G4 CLEANUP_PASS', 'G4 DE_ONLY_UNLOCK_PASS ce_calls=0',
    'G4 KEY_POLICY_MISMATCH: unmount private data to roll back RAM key state',
    'G4 USER0_STAGE_PASS stage=de_sys', 'G4 USER0_STAGE_PASS stage=de_user0',
    NONE_READY, NONE_DELIVERED, 'G4 NONE_PREPARE_PASS secure_calls=0',
    'G4 NONE_KEY_RECEIVED_ONCE bytes=64', 'G4 NONE_STATE_UNKNOWN_WAIT_WATCHDOG',
))
MOUNT = re.compile(r'G4 MOUNT_RO_PASS dm=(a22x-data-ro-[a-z0-9]{8,24}) raw_dm=\1-raw device=([0-9]{1,10}):([0-9]{1,10}) sectors=([0-9]{1,20})')
MEDIA = re.compile(r'G4 SP_MEDIA_USER0_READDIR_PASS entries=([0-9]{1,4}) complete=1 fs_ro=1 dm_ro=1 alias_ro=1')
DATABASE_SCHEMA = re.compile(r'G3 NONE_DATABASE_SCHEMA version=([12])')
PATTERNS = tuple(re.compile(x.encode()) for x in (
    MOUNT.pattern, MEDIA.pattern, DATABASE_SCHEMA.pattern,
    r'G3 NONE_RESOLVER_DIAG table=[0-9]{1,10} column=[0-9]{1,10} reason=[0-9]{1,10} sqlite=[0-9]{1,10} schema=-?[0-9]{1,3} tag=[0-9]{1,10} blob_state=(?:-1|[012])',
    r'G3 NONE_REJECTED stage=[0-9]{1,2}',
    r'G3 NONE_PREPARE_FAILED code=[0-9]{1,2} stage=[0-9]{1,2} secure_calls=0',
    r'G3 NONE_(?:SERVICE|HARDWARE)_FAILED error=-?[0-9]{1,10} phase=[0-7] tag=[0-9]{1,10}',
    r'G3 NONE_SECURE_STATE_UNKNOWN_WAIT_WATCHDOG phase=[0-7] tag=[0-9]{1,10}',
    r'G4 NONE_BRIDGE_FAILED operation=(?:prepare|unlock) errno=[0-9]{1,10}',
    r'G3 UNWRAP_FAILED error=-?[0-9]{1,10}',
    r'G4 SP_BRIDGE_FAILED operation=de errno=[0-9]{1,10}',
    r'G4 CLEANUP_(?:DM_FAILED|FAIL) errno=[0-9]{1,10}',
    r'G4 CLEANUP_UMOUNT_FAILED errno=[0-9]{1,10}; mappings retained',
    r'G4 (?:FAIL|USER0_FAIL) errno=[0-9]{1,10} \(no retry\)',
    r'G4 USER0_STAGE_BLOCKED stage=(?:de_sys|de_user0|ce_empty_auth_user0) errno=[0-9]{1,10}',
    r'G4 USER0_STAGE_FAILED stage=(?:de_sys|de_user0|ce_empty_auth_user0) errno=[0-9]{1,10}; no SP fallback or retry; unmount for RAM rollback',
))


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def classify(stdout, stderr):
    require(type(stdout) is bytes and type(stderr) is bytes and
            len(stdout) <= 4096 and len(stderr) <= 4096, 'NATIVE_STATUS_BOUND')
    result = {'status_lines': [], 'linker_warnings': 0}
    for line in stdout.splitlines() + stderr.splitlines():
        if line in (WARNING, b'WARNING: ' + WARNING):
            result['linker_warnings'] += 1
        elif line in LITERALS or any(p.fullmatch(line) for p in PATTERNS):
            result['status_lines'].append(line.decode('ascii'))
        else:
            raise RuntimeError('UNKNOWN_NATIVE_STATUS_DISCARDED')
    return result


def evaluate_prepare(lines):
    require(len(lines)==3 and lines[0]=='G4 NONE_PREPARE_PASS secure_calls=0' and
            lines[2]==NONE_READY, 'NONE_ACTIVE_PROFILE_PROOF')
    schema=DATABASE_SCHEMA.fullmatch(lines[1])
    require(schema is not None, 'NONE_PREPARE_SCHEMA_PROOF')
    return int(schema[1])


def evaluate_unlock(lines, schema):
    media=[MEDIA.fullmatch(x) for x in lines if MEDIA.fullmatch(x)]
    require(len(media)==1 and lines==['G4 NONE_KEY_RECEIVED_ONCE bytes=64',
            'G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS',media[0].group(0),
            'G3 NONE_DATABASE_SCHEMA version='+str(schema),NONE_READY,NONE_DELIVERED],
            'NONE_AUTHENTICATED_CE_AND_POLICY_PROOF')
    return int(media[0][1])


def evaluate_operations(ops, run_id, *, cleanup=True):
    expected = ['unwrap-mount', 'unlock-de-user0', 'prepare-none-user0', 'unlock-none-user0']
    if cleanup:
        expected.append('cleanup')
    require(type(ops) is list and [x['operation'] for x in ops] == expected,
            'NONE_OPERATION_SEQUENCE')
    require(all(type(x['returncode']) is int and x['returncode'] == 0 for x in ops),
            'NONE_NATIVE_EXIT')
    mount, de, prepared, unlocked = [x['status_lines'] for x in ops[:4]]
    mounts = [MOUNT.fullmatch(x) for x in mount if MOUNT.fullmatch(x)]
    require(len(mount) == 2 and len(mounts) == 1
            and mounts[0][1] == 'a22x-data-ro-' + run_id
            and mount.count('G3 AUTHENTICATED_KEY_DELIVERED') == 1,
            'NONE_METADATA_PROOF')
    require(de == ['G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS'] * 2
            + ['G4 DE_ONLY_UNLOCK_PASS ce_calls=0']
            + ['G3 AUTHENTICATED_KEY_DELIVERED'] * 2, 'NONE_DE_PROOF')
    schema = evaluate_prepare(prepared)
    entries = evaluate_unlock(unlocked, schema)
    if cleanup:
        require(ops[4]['status_lines'] == ['G4 CLEANUP_PASS'], 'NONE_CLEANUP_PROOF')
    return {'success': True, 'status': 'EVOX_NONE_SP_CE_AUTHENTICATED_RO_PASS',
            'authenticated_key_deliveries': 4, 'policy_matches': 3,
            'gatekeeper_calls': 0, 'password_submissions': 0, 'ce_calls': 1,
            'synthetic_write_calls': 0, 'media_entries': entries,
            'active_none_selected': True, 'keystore_schema': schema}


def qualify_ce(operations, run_id, independent):
    """Only pre-cleanup, authenticated native evidence may authorize hold."""
    verdict = evaluate_operations(operations, run_id, cleanup=False)
    require(independent == {'entries': verdict['media_entries'], 'complete': True,
                            'filesystem_ro': True}, 'NONE_INDEPENDENT_MEDIA_PROOF')
    require(type(independent['entries']) is int and 0 <= independent['entries'] <= 4096
            and independent['complete'] is True and independent['filesystem_ro'] is True,
            'NONE_INDEPENDENT_MEDIA_TYPES')
    return dict(verdict, independent_media_read=dict(independent))


def evaluate(extension, run_id):
    """After fresh-lease unmount, require full returned cleanup evidence too."""
    require(extension.get('status') == 'G2_REMOTE_TEE_KEYMASTER_READY'
            and extension.get('consumer_run') is True
            and extension.get('all_owned_processes_reaped') is True
            and extension.get('process_cleanup_errors') == [], 'NONE_KEYMASTER_SESSION_PROOF')
    require('gatekeeper_probe' not in extension and 'gatekeeper_teec_diagnostic' not in extension,
            'NONE_UNEXPECTED_GATEKEEPER')
    consumer = extension['consumer']
    require(consumer.get('success') is True, 'NONE_CONSUMER_VERDICT')
    verdict = evaluate_operations(consumer['operations'], run_id)
    retained = qualify_ce(consumer['operations'][:4], run_id, consumer['independent_media_read'])
    require(all(verdict[k] == retained[k] for k in verdict), 'NONE_FINAL_VERDICT_MISMATCH')
    return retained


def deadline(timeout, initial=False):
    try:
        remaining = float(os.environ['A22X_C_WD_DEADLINE']) - time.monotonic()
    except (KeyError, ValueError):
        raise RuntimeError('WATCHDOG_DEADLINE_REQUIRED') from None
    require(math.isfinite(remaining) and remaining >= max(timeout + 30, 230 if initial else 0),
            'INSUFFICIENT_WATCHDOG_BUDGET')


def regular(path, maximum=64*1024*1024, private=False):
    path = Path(path)
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'SYMLINK_PATH')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        require(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and
                0 <= first.st_size <= maximum, 'REGULAR_FILE_SHAPE')
        if private:
            require(first.st_uid == 0 and stat.S_IMODE(first.st_mode) == 0o600, 'PRIVATE_FILE_MODE')
        chunks, total = [], 0
        while part := os.read(fd, 65536):
            total += len(part)
            require(total <= first.st_size, 'FILE_CHANGED')
            chunks.append(part)
        last = os.fstat(fd)
        fields = lambda x: (x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        require(total == first.st_size and fields(first) == fields(last), 'FILE_CHANGED')
        return b''.join(chunks)
    finally:
        os.close(fd)


def current_framework_identity(runtime, public):
    for name, expected in FRAMEWORK.items():
        found = []
        for relative in ('/mnt/system_stock/system/framework/'+name, '/mnt/system_stock/framework/'+name):
            try:
                path = runtime.backend.at(relative)
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            except (FileNotFoundError, NotADirectoryError):
                continue
            try:
                require(os.fstatvfs(fd).f_flag & os.ST_RDONLY, 'FRAMEWORK_NOT_RO')
                # regular() reopens no-follow and checks identity; bind this FD too.
                first = os.fstat(fd)
                data = regular(path)
                last = path.stat()
                require((first.st_dev,first.st_ino,first.st_size,first.st_mtime_ns,first.st_ctime_ns) ==
                        (last.st_dev,last.st_ino,last.st_size,last.st_mtime_ns,last.st_ctime_ns), 'FRAMEWORK_CHANGED')
                found.append(sha(data))
            finally:
                os.close(fd)
        public('current_framework_identity', artifact=name, observed_count=len(found),
               matches_expected=(found == [expected]))
        require(found == [expected], 'EVOX_FRAMEWORK_PIN')



def ro_directory(root, relative):
    fd=os.dup(root)
    try:
        for name in relative.split('/'):
            require(name not in ('','.', '..'),'PROFILE_RELATIVE_PATH')
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        return fd
    except BaseException:
        os.close(fd);raise


def independent_media_read(root_path):
    root=os.open(root_path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
    media=-1
    try:
        require(os.fstatvfs(root).f_flag & os.ST_RDONLY,'MEDIA_DATA_NOT_RO')
        media=ro_directory(root,'media/0');count=0
        with os.scandir(media) as entries:
            for entry in entries:
                count+=1;require(count<=4096,'MEDIA_DIRECTORY_BOUND')
        require(os.fstatvfs(media).f_flag & os.ST_RDONLY,'MEDIA_NOT_RO_AFTER')
        return {'entries':count,'complete':True,'filesystem_ro':True}
    finally:
        if media>=0:os.close(media)
        os.close(root)


def collect_native_status(process, timeout, public):
    from decrypt_runtime import worker_control
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        public('native_timeout_waiting_for_outer_watchdog', pid=process.pid)
        try:
            process.wait()  # no kill, retry, normal cleanup or disarm after timeout
        except BaseException:
            worker_control.park_for_reset()
        worker_control.park_for_reset()
    except BaseException:
        worker_control.park_for_reset()
    if process.returncode < 0:
        worker_control.park_for_reset()
    status = classify(stdout, stderr)
    if any('UNKNOWN_WAIT_WATCHDOG' in line for line in status['status_lines']):
        worker_control.park_for_reset()
    return status


def make_consumer(run_id, cleanup_errors, public):
    require(bool(re.fullmatch(r'[a-z0-9]{8,24}', run_id)), 'RUN_ID')

    def consumer(runtime):
        from c_crypto_profile import require_profile
        from decrypt_runtime import worker_control
        backend = runtime.backend
        worker_control.forbid_gatekeeper(runtime)
        current_framework_identity(runtime, public)
        profile = require_profile(regular(backend.at('/vendor/etc/fstab.mt6833'), 1024*1024),
                                  runtime.getprop('ro.crypto.dm_default_key.options_format.version'))
        public('live_crypto_profile_verified', **profile)
        g4 = '/system/bin/a22x-data-ro'
        require(sha(regular(backend.at(g4))) == G4_SHA
                and sha(regular(backend.at('/system/bin/a22x-unlock-none'))) == NONE_SHA
                and sha(regular(backend.at('/system/bin/a22x-keyunwrap-hidl4'))) == G3_SHA,
                'LIVE_NATIVE_DEPENDENCY_PIN')
        target, work, ram = '/mnt/userdata-ro', '/run/data-none-ro', '/run/sp-none'
        name, lock = 'a22x-data-ro-' + run_id, runtime.common_lock_fd
        backend.at(work).mkdir(mode=0o700)
        backend.at(ram).mkdir(mode=0o700)
        backend._mount('tmpfs', backend.at(ram), 'tmpfs', 2 | 4 | 8, 'mode=0700,size=32m')
        records, creator = [], None
        keydir = source = -1

        def run(argv, descriptors, timeout):
            nonlocal creator
            if argv[1] != 'cleanup':
                deadline(max(timeout, 150 if argv[1] == 'unwrap-mount' else timeout))
            process = runtime.spawn(argv, pass_fds=descriptors, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, verify_label=False)
            if argv[1] == 'unwrap-mount':
                creator = process.pid
            status = collect_native_status(process, timeout, public)
            record = dict(operation=argv[1], pid=process.pid, returncode=process.returncode,
                          **status)
            records.append(record)
            public('none_native_operation_returned', **record)
            require(process.returncode == 0, 'NATIVE_FAILED_NO_RETRY')
            return record['status_lines']

        try:
            worker_control.check_before_auth()
            keydir = os.open(backend.at('/metadata/vold/metadata_encryption/key'),
                             os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            source = os.open(backend.nodes['a22x-c-' + run_id + '-userdata'],
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            run([g4, 'unwrap-mount', str(keydir), str(source), target, work, name, str(lock)],
                (keydir, source, lock), 45)
            run([g4, 'unlock-de-user0', target, str(lock)], (lock,), 75)
            prepared = run([g4, 'prepare-none-user0', target, ram, str(lock)], (lock,), 30)
            schema = evaluate_prepare(prepared)
            require(not any(backend.at(ram).iterdir()), 'NONE_PREPARE_SNAPSHOT_RETAINED')
            worker_control.check_before_auth()
            unlocked = run([g4, 'unlock-none-user0', target, ram, str(lock)], (lock,), 130)
            evaluate_unlock(unlocked, schema)
            require(not any(backend.at(ram).iterdir()), 'NONE_UNLOCK_SNAPSHOT_RETAINED')
            observed = independent_media_read(backend.at(target))
            public('none_independent_media_read_verified', **observed)
            verdict = worker_control.hold_none(runtime, records, run_id, observed)
            # hold_none returns only on cancel with the original lease, or after
            # adopting a fresh unmount lease; cleanup below owns that lease.
            return dict(verdict, operations=records)
        finally:
            for fd in (keydir, source):
                if fd >= 0:
                    os.close(fd)
            if creator is not None:
                try:
                    lines = run([g4, 'cleanup', target, work, name, str(creator), str(lock)],
                                (lock,), 10)
                    require(lines == ['G4 CLEANUP_PASS'], 'MISSING_CLEANUP_PROOF')
                except Exception:
                    cleanup_errors.append({'stage': 'data_none_cleanup'})
            try:
                backend.unmount(backend.at(ram))
                backend.at(ram).rmdir()
            except Exception:
                cleanup_errors.append({'stage': 'data_none_private_ram_cleanup'})
            require(not cleanup_errors, 'DATA_CLEANUP_UNCONFIRMED')
    return consumer
