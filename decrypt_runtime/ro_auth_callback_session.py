"""One original native authentication; CE proof through RO mappings only."""
import math
import os
import re
import subprocess
import time


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def classify(stdout, stderr):
    require(len(stdout) <= 4096 and len(stderr) <= 4096, 'Native status exceeds bound')
    warning = b'linker: Warning: failed to find generated linker configuration from "/linkerconfig/ld.config.txt"'
    result = {'status_lines': [], 'linker_warnings': 0}
    for line in stdout.splitlines() + stderr.splitlines():
        if line in (warning, b'WARNING: ' + warning):
            result['linker_warnings'] += 1
        elif (match := CE_BLOB_STATUS.fullmatch(line)) is not None:
            disk, normalized = int(match[1]), int(match[2])
            overhead = 0 if match[3] == b'RAW' else 8
            require(0 < normalized <= disk <= 65536 and normalized == disk - overhead,
                    'Invalid public CE blob size relationship')
            result['status_lines'].append(line.decode('ascii'))
        elif line in PUBLIC_LITERALS or any(pattern.fullmatch(line) for pattern in PUBLIC_PATTERNS):
            result['status_lines'].append(line.decode('ascii'))
        else:
            raise RuntimeError('Unknown native status discarded')
    return result


CE_BLOB_STATUS = re.compile(
    rb'G3 SP_PREPARE_CE_BLOB disk_bytes=([1-9][0-9]{0,4}) normalized_bytes=([1-9][0-9]{0,4}) wrapping=(RAW|PKMBLOB_HW_V0)')


PUBLIC_LITERALS = frozenset(x.encode('ascii') for x in (
    'G3 SP_PREPARE_NATIVE_GUARD name=FD_NUMBER',
    'G3 SP_PREPARE_NATIVE_GUARD name=FD_DISTINCT',
    'G3 SP_PREPARE_NATIVE_GUARD name=EFFECTIVE_UID',
    'G3 SP_PREPARE_NATIVE_GUARD name=ROOT_DIRECTORY',
    'G3 SP_PREPARE_NATIVE_GUARD name=MEMLOCK_LIMIT',
    'G3 SP_PREPARE_NATIVE_GUARD name=PROCESS_HARDEN',
    'G3 SP_PREPARE_NATIVE_GUARD name=PROFILE_MISSING',
    'G3 SP_PREPARE_NATIVE_GUARD name=PROFILE_SP_VERSION',
    'G3 SP_PREPARE_NATIVE_GUARD name=PROFILE_SECURE_MODE',
    'G3 SP_PREPARE_NATIVE_GUARD name=PROFILE_CREDENTIAL_TYPE',
    'G3 SP_PREPARE_NATIVE_GUARD name=PROFILE_CE_CHECKED',
    'G3 SP_PREPARE_NATIVE_GUARD name=PROFILE_CE_SECDISCARDABLE',
    'G3 SP_PREPARE_NATIVE_GUARD name=PROFILE_CE_CANDIDATES',
    'G3 SP_PREPARE_NATIVE_GUARD name=PROFILE_USER_ID',
    'G3 SP_PREPARE_NATIVE_GUARD name=PROFILE_CREATION_DATETIME',
    'G3 SP_PREPARE_NATIVE_GUARD name=PROFILE_CE_KIND',
    'G3 SP_PREPARE_NATIVE_GUARD name=LEGACY_CE_KDF_N',
    'G3 SP_PREPARE_NATIVE_GUARD name=LEGACY_CE_KDF_R',
    'G3 SP_PREPARE_NATIVE_GUARD name=LEGACY_CE_KDF_P',
    'G3 SP_PREPARE_NATIVE_GUARD name=LEGACY_CE_SALT_SIZE',
    'G3 SP_PREPARE_NATIVE_GUARD name=LEGACY_CE_BLOB_SIZE',
    'G3 SP_PREPARE_NATIVE_GUARD name=LEGACY_PRIMARY_HANDLE',
    'G3 SP_PREPARE_NATIVE_GUARD name=SOFTWARE_CE_STRETCHING',
    'G3 SP_PREPARE_NATIVE_GUARD name=PWD_READ',
    'G3 SP_PREPARE_NATIVE_GUARD name=SP_BLOB_READ',
    'G3 SP_PREPARE_NATIVE_GUARD name=SP_SECDIS_READ',
    'G3 SP_PREPARE_NATIVE_GUARD name=PWD_PARSE',
    'G3 SP_PREPARE_NATIVE_GUARD name=PWD_SECURE_MODE',
    'G3 SP_PREPARE_NATIVE_GUARD name=PWD_CREDENTIAL_TYPE',
    'G3 SP_PREPARE_NATIVE_GUARD name=PWD_PROFILE_KDF_N',
    'G3 SP_PREPARE_NATIVE_GUARD name=PWD_PROFILE_KDF_R',
    'G3 SP_PREPARE_NATIVE_GUARD name=PWD_PROFILE_KDF_P',
    'G3 SP_PREPARE_NATIVE_GUARD name=SP_BLOB_VERSION',
    'G3 SP_PREPARE_NATIVE_GUARD name=SP_BLOB_TYPE',
    'G3 SP_PREPARE_NATIVE_GUARD name=KEYBLOB_MISSING',
    'G3 SP_PREPARE_NATIVE_GUARD name=KEYBLOB_EMPTY',
    'G3 SP_PREPARE_NATIVE_GUARD name=KEYBLOB_COPY',
    'G3 SP_PREPARE_NATIVE_GUARD name=KEYMASTER_PREPARE',
    'G3 SP_PREPARE_NATIVE_GUARD name=LEGACY_KDF_PROBE',
    'G3 SP_PREPARE_NATIVE_GUARD name=CE_ENCRYPTED_READ',
    'G3 SP_PREPARE_NATIVE_GUARD name=CE_SECDIS_READ',
    'G3 SP_PREPARE_NATIVE_GUARD name=CE_BLOB_READ',
    'G3 SP_PREPARE_NATIVE_GUARD name=CE_BLOB_NORMALIZE',
    'G3 SP_PREPARE_NATIVE_GUARD name=CE_SALT_READ',
    'G3 SP_PREPARE_NATIVE_GUARD name=PRIMARY_HANDLE_READ',
    'G3 INPUT_PROFILE_REQUIRED', 'G3 FD_GUARD_FAILED', 'G3 MEMORY_GUARD_FAILED',
    'G3 INPUT_FORMAT_REJECTED', 'G3 REMOTE_MANAGER_UNAVAILABLE',
    'G3 HAL_TRANSPORT_REJECTED', 'G3 REMOTE_HAL_UNAVAILABLE',
    'G3 PRIVATE_PIPE_FAILED', 'G3 AUTHENTICATED_KEY_DELIVERED',
    'G3 SP_PREPARE_READY auth_calls=0 ce_profile=software_v1_none',
    'G3 SP_PREPARE_READY auth_calls=0 ce_profile=legacy_hw_scrypt_v1',
    'G4 SP_PREPARE_PASS auth_calls=0', 'G4 DE_ONLY_UNLOCK_PASS ce_calls=0',
    'G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS', 'G4 CLEANUP_PASS',
    'G4 KEY_POLICY_MISMATCH: unmount private data to roll back RAM key state',
))
PUBLIC_PATTERNS = tuple(re.compile(x) for x in (
    rb'G4 SP_PREPARE_CHILD_EXIT code=(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])',
    rb'G4 SP_PREPARE_CHILD_SIGNAL signal=(?:[1-9]|[1-5][0-9]|6[0-4])',
    rb'G3 UNWRAP_FAILED error=-?[0-9]{1,10}',
    rb'G3 SP_PREPARE_FAILED code=[0-9]{1,3}(?: stage=[0-9]{1,2})?',
    rb'G4 SP_BRIDGE_FAILED operation=(?:de|prepare) errno=[0-9]{1,10}',
    rb'G4 CLEANUP_(?:DM_FAILED|FAIL) errno=[0-9]{1,10}',
    rb'G4 CLEANUP_UMOUNT_FAILED errno=[0-9]{1,10}; mappings retained',
    rb'G4 FAIL errno=[0-9]{1,10} \(no retry\)',
    rb'G4 MOUNT_RO_PASS dm=(a22x-data-ro-[a-z0-9]{8,24}) raw_dm=\1-raw device=[0-9]{1,10}:[0-9]{1,10} sectors=[0-9]{1,20}',
))


def current_framework_identity(runtime, public):
    import hashlib
    import stat
    for filename, expected in (
        ('services.jar', 'f4795ef0b1f3ebc45e44258b5d9324b52c3148e3ac3158fe02584862d3e9e055'),
        ('framework.jar', '731db55aa1a0d3a97d28375296cdde04a9a8196028813b15e612c7f39be8e144')):
        candidates = ('/mnt/system_stock/system/framework/' + filename,
                      '/mnt/system_stock/framework/' + filename)
        found = []
        for relative in candidates:
            try:
                fd = os.open(runtime.backend.at(relative), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            except (FileNotFoundError, NotADirectoryError):
                continue
            try:
                first = os.fstat(fd)
                require(stat.S_ISREG(first.st_mode) and 0 < first.st_size <= 64 * 1024 * 1024,
                        'Public framework file shape rejected')
                require(os.fstatvfs(fd).f_flag & os.ST_RDONLY, 'Public framework view is not read-only')
                digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    require(total <= first.st_size, 'Public framework file changed')
                    digest.update(chunk)
                last = os.fstat(fd)
                require(total == first.st_size and
                        (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns, first.st_ctime_ns) ==
                        (last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns, last.st_ctime_ns),
                        'Public framework identity changed')
                found.append(digest.hexdigest())
            finally:
                os.close(fd)
        public('current_framework_identity', artifact=filename, observed_count=len(found),
               sha256=found, expected_sha256=expected,
               matches_expected=(len(found) == 1 and found[0] == expected))
        require(len(found) == 1 and found[0] == expected, 'Current Samsung framework identity mismatch')


def prepared_credential_type(lines, required=True):
    types = [line.removeprefix('G3 SP_PREPARE_CREDENTIAL type=')
             for line in lines if line.startswith('G3 SP_PREPARE_CREDENTIAL type=')]
    require(len(types) == 1 or (not required and not types),
            'Missing or duplicate native credential type')
    value = types[0] if types else 'password'
    require(value in ('pattern', 'password'), 'Unsupported credential type')
    return value

def make_consumer(run_id, credential_slot, cleanup_errors, public, rw_capability=None):
    if credential_slot[0] >= 0:
        validate_credential_fd(credential_slot[0])
    require(bool(re.fullmatch(r'[a-z0-9]{8,24}', run_id)), 'Invalid run identity')

    def consumer(runtime):
        from c_crypto_profile import require_profile
        backend = runtime.backend
        current_framework_identity(runtime, public)
        profile = require_profile(backend.at('/vendor/etc/fstab.mt6833').read_bytes(),
                                  runtime.getprop('ro.crypto.dm_default_key.options_format.version'))
        public('live_crypto_profile_verified', **profile)
        lock = runtime.common_lock_fd
        require(credential_slot[0] != lock, "Credential aliases common lease")
        executable = '/system/bin/a22x-data-ro'
        target, work, ram = '/mnt/userdata-ro', '/run/sp-dm', '/run/sp-ram'
        backend.at(work).mkdir(mode=0o700)
        backend.at(ram).mkdir(mode=0o700)
        # Separate from G2's 4MiB /run: native SQLite snapshots are bounded at
        # 28.25MiB total and remain private tmpfs throughout admission.
        backend._mount('tmpfs', backend.at(ram), 'tmpfs', 2 | 4 | 8,
                       'mode=0700,size=32m')
        keydir = source = -1
        creator = None
        records = []
        new_creator=None
        rw_cleanup_blocked=False
        new_work='/run/sp-dm-rw'
        new_name='a22x-data-ro-'+run_id+'rw'

        def run(argv, descriptors, timeout):
            if argv[1] not in ('cleanup','cleanup-rw'):
                try:
                    remaining = float(os.environ['A22X_C_WD_DEADLINE']) - time.monotonic()
                except (KeyError, ValueError):
                    raise RuntimeError('Missing watchdog deadline') from None
                require(math.isfinite(remaining) and remaining >= max(timeout + 30, 180 if argv[1] == 'unwrap-mount' else 0),
                        'Insufficient watchdog budget')
            process = runtime.spawn(argv, pass_fds=descriptors, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, verify_label=False)
            if argv[1] in ('unlock-sp-user0','unlock-sp-user0-rw'):
                os.close(credential_slot[0])
                credential_slot[0] = -1
            nonlocal creator,new_creator
            if argv[1] == 'unwrap-mount':
                creator = process.pid
            if argv[1]=='unlock-sp-user0-rw':
                new_creator=process.pid
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                public('sp_prepare_timeout_waiting_for_watchdog', pid=process.pid)
                process.wait()
                raise RuntimeError('Native preparation timed out; no retry') from None
            parser=classify
            if argv[1] in ('unlock-sp-user0-rw','cleanup-rw'):
                from decrypt_runtime.rw_verdict import classify as parser
            record = {'operation': argv[1], 'pid': process.pid, 'returncode': process.returncode,
                      **parser(stdout, stderr)}
            records.append(record)
            public('sp_prepare_operation_returned', **record)
            if argv[1] not in ('unlock-sp-user0','unlock-sp-user0-rw'):
                require(process.returncode == 0, 'Native preparation failed; no retry')
            return record['status_lines']

        try:
            keydir = os.open(backend.at('/metadata/vold/metadata_encryption/key'),
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            source = os.open(backend.nodes['a22x-c-' + run_id + '-userdata'],
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            lines = run([executable, 'unwrap-mount', str(keydir), str(source), target,
                         work, 'a22x-data-ro-' + run_id, str(lock)], (keydir, source, lock), 45)
            require(any(x.startswith('G4 MOUNT_RO_PASS ') for x in lines), 'Missing RO mount proof')
            lines = run([executable, 'unlock-de-user0', target, str(lock)], (lock,), 75)
            require('G4 DE_ONLY_UNLOCK_PASS ce_calls=0' in lines, 'Missing DE proof')
            lines = run([executable, 'prepare-sp', target, ram, str(lock)], (lock,), 125)
            require(sum(line.startswith('G3 SP_PREPARE_READY auth_calls=0 ce_profile=') for line in lines)==1 and
                    'G4 SP_PREPARE_PASS auth_calls=0' in lines, 'Missing SP admission proof')
            require('G3 SP_PREPARE_READY auth_calls=0 ce_profile=legacy_hw_scrypt_v1' in lines,
                    'RO-auth successor requires qualified legacy profile')
            from decrypt_runtime import worker_control
            credential_type = prepared_credential_type(lines, required=worker_control._discovery)
            requested_mode=worker_control.awaiting_credential(runtime, credential_slot, credential_type, rw_capability)
            # An idle prepared room must recheck both public framework pins
            # under its freshly adopted lease immediately before native auth.
            current_framework_identity(runtime, public)
            if requested_mode=='rw':
                from decrypt_runtime.rw_support import capability,pinned_fd
                cap=capability(rw_capability)
                helper_fd=pinned_fd(backend.at(cap['helper']),cap['helper_sha256'],executable=True)
                os.close(helper_fd)
                backend.at(new_work).mkdir(mode=0o700)
            fd = credential_slot[0]
            validate_credential_fd(fd)
            from decrypt_runtime.worker_control import check_before_auth
            check_before_auth()
            from tz_syscall_trace import StorageTrace
            observer = StorageTrace(runtime, run_id, cleanup_errors)
            observer.start()
            try:
                if requested_mode=='rw':
                    rw_cleanup_blocked=True  # Unknown native outcome cannot authorize cleanup replay.
                    lines=run([cap['helper'],'unlock-sp-user0-rw',target,ram,str(keydir),str(source),
                        str(fd),str(lock),work,'a22x-data-ro-'+run_id,str(creator),new_work,new_name,
                        str(int(float(os.environ['A22X_C_WD_DEADLINE'])*1000))],
                        (keydir,source,fd,lock),195)
                    from decrypt_runtime.rw_verdict import native_verdict as rw_verdict
                    verdict=rw_verdict(records[-1])
                    rw_cleanup_blocked=verdict['cleanup_errno']!=0
                else:
                    lines = run([executable, 'unlock-sp-user0', target, ram, str(fd), str(lock)],
                                (fd, lock), 125)
                    verdict=native_verdict(records[-1])
            finally:
                storage_trace = observer.finish()
                public('storage_scalar_trace', **storage_trace)
            from decrypt_runtime.worker_control import hold
            if verdict['success']:
                require(storage_trace['mode'] == 'TZDAEMON_STORAGE' and
                    storage_trace['status'] == 'SCALAR_TRACE_COMPLETE' and
                    storage_trace['cleanup_verified'] is True,
                    'Storage scalar trace incomplete')
            if verdict['success']:
                if requested_mode=='rw':
                    hold(runtime,verdict,records,storage_trace,requested_mode='rw')
                else:
                    hold(runtime, verdict, records, storage_trace)
            return dict(verdict, operations=records, synthetic_write_calls=0,
                        storage_trace=storage_trace)
        finally:
            if credential_slot[0] >= 0:
                os.close(credential_slot[0])
                credential_slot[0] = -1
            new_clean=True
            if new_creator is not None:
                if rw_cleanup_blocked:
                    cleanup_errors.append({'stage':'ce_rw_quarantined_cleanup_not_replayed'})
                    new_clean=False
                else:
                    try:
                        run([rw_capability['helper'],'cleanup-rw',target,new_work,new_name,
                            str(new_creator),str(source),str(lock)],(source,lock),30)
                        from decrypt_runtime.rw_verdict import cleanup_verdict
                        cleanup_verdict(records[-1],new_creator)
                    except Exception:
                        cleanup_errors.append({'stage':'ce_rw_normal_cleanup_failed'})
                        new_clean=False
            if creator is not None and new_clean:
                try:
                    lines = run([executable, 'cleanup', target, work, 'a22x-data-ro-' + run_id,
                                 str(creator), str(lock)], (lock,), 15)
                    require('G4 CLEANUP_PASS' in lines, 'Missing cleanup proof')
                except Exception:
                    cleanup_errors.append({'stage': 'sp_prepare_dm_cleanup'})
            if keydir >= 0:
                os.close(keydir)
            if source >= 0:
                os.close(source)
            try:
                backend.unmount(backend.at(ram))
                backend.at(ram).rmdir()
            except Exception:
                cleanup_errors.append({'stage': 'sp_prepare_private_ram_cleanup'})
            require(not cleanup_errors, 'SP preparation cleanup unconfirmed')

    return consumer


# Exact public records emitted by the unchanged native source. No payloads.
PUBLIC_LITERALS = PUBLIC_LITERALS | frozenset((
    b'G3 SP_PREPARE_CREDENTIAL type=password', b'G3 SP_PREPARE_CREDENTIAL type=pattern',
    b'G3 SP_CE_AUTHENTICATED_KEY_DELIVERED', b'G4 SP_KEY_RECEIVED_ONCE bytes=64'))
AUTH_FAIL = re.compile(rb'G3 SP_(AUTH|PRIMARY_AUTH)_FAILED status=([0-9]{1,10}) timeout_ms=([0-9]{1,10})')
MEDIA = re.compile(rb'G4 SP_MEDIA_USER0_READDIR_PASS entries=([0-9]{1,4}) complete=([01]) fs_ro=1 dm_ro=1 alias_ro=1')
PUBLIC_PATTERNS = PUBLIC_PATTERNS + (AUTH_FAIL, MEDIA,
    re.compile(rb'G3 SP_(?:HARDWARE|CE_HARDWARE)_FAILED error=-?[0-9]{1,10}'),
    re.compile(rb'G4 SP_BRIDGE_FAILED operation=unlock errno=[0-9]{1,10}'))


def validate_credential_fd(fd):
    import fcntl
    import stat
    require(type(fd) is int and fd >= 3, 'Credential descriptor rejected')
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    require((flags & os.O_ACCMODE) == os.O_RDONLY and stat.S_ISFIFO(os.fstat(fd).st_mode)
            and re.fullmatch(r'pipe:\[[0-9]+\]', os.readlink('/proc/self/fd/' + str(fd))) is not None,
            'Credential must be anonymous read pipe')


def native_verdict(record):
    lines = record['status_lines']
    require(record['operation'] == 'unlock-sp-user0', 'Wrong native operation')
    failures = [AUTH_FAIL.fullmatch(x.encode('ascii')) for x in lines]
    failures = [m for m in failures if m is not None]
    success = ('G3 SP_CE_AUTHENTICATED_KEY_DELIVERED', 'G4 SP_KEY_RECEIVED_ONCE bytes=64',
               'G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS')
    media = [MEDIA.fullmatch(x.encode('ascii')) for x in lines]
    media = [m for m in media if m is not None]
    if record['returncode'] == 0:
        require(not failures and all(lines.count(x) == 1 for x in success) and len(media) == 1,
                'Incomplete RO CE evidence')
        require(int(media[0][1]) <= 4096 and media[0][2] == b'1', 'Incomplete bounded media proof')
        require(not any('FAILED' in x or 'MISMATCH' in x for x in lines), 'Conflicting native success')
        return dict(status='PASSWORD_CE_RO_MEDIA_PASS', success=True, failure_stage=None)
    require(not media, 'Conflicting failure evidence')
    if failures:
        require(not any(x in lines for x in success), 'Auth failure after CE delivery')
    # Nonzero native exit is always failure. Preserve allowlisted statuses even
    # for native guard/hardware errors without inventing an authentication verdict.
    require(len(failures) <= 1, 'Duplicate native auth verdict')
    if failures:
        m = failures[0]
        status, timeout = int(m[2]), int(m[3])
        require(status <= 0xffffffff and timeout <= 0xffffffff, 'Auth scalar overflow')
        stage = 'protector' if m[1] == b'AUTH' else 'primary'
        return dict(status='PASSWORD_AUTH_FAILED_NO_RETRY', success=False, failure_stage=stage,
                    native_auth_status=status, native_timeout_ms=timeout)
    return dict(status='PASSWORD_CE_RO_NATIVE_FAILED_NO_RETRY', success=False, failure_stage='native')
