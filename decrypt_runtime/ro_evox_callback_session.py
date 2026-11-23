"""One current Evolution password auth; native credential pipe never read here."""
import math
import os
import re
import subprocess
import time
from android_profiles import EVO_NATIVE_SHA, G4_SHA, GATEKEEPERD_SHA
from decrypt_runtime import worker_control
from decrypt_runtime import ro_none_callback_session as none_callback


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def classify(stdout, stderr):
    require(type(stdout) is bytes and type(stderr) is bytes and len(stdout) <= 4096 and len(stderr) <= 4096, 'Native status exceeds bound')
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
    selected_roots = []
    for filename, expected in (
        ('services.jar', 'ae824be13cfc9f5f7e9673ee9230fdaea5e3fc91230cecbdaf511974c99a533b'),
        ('framework.jar', '52018a98c6718d17f0c80386d842f1d15bca36b35498e12ecd669e354a34483a')):
        candidates = ('/mnt/system_stock/system/framework/' + filename,
                      '/mnt/system_stock/framework/' + filename)
        found = []
        roots = []
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
                roots.append(relative.rsplit('/framework/', 1)[0])
            finally:
                os.close(fd)
        public('current_framework_identity', artifact=filename, observed_count=len(found),
               sha256=found, expected_sha256=expected,
               matches_expected=(len(found) == 1 and found[0] == expected))
        require(len(found) == 1 and found[0] == expected, 'Current Evolution framework identity mismatch')
        selected_roots.append(roots[0])

    require(len(selected_roots) == 2 and len(set(selected_roots)) == 1,
            'FRAMEWORK_LAYOUT_MISMATCH')
    # Gatekeeper belongs to the SAME unique firmware layout as both JARs.
    # An unused SAR /bin alias is never probed or followed.
    path = runtime.backend.at(selected_roots[0] + '/bin/gatekeeperd')
    raw = none_callback.regular(path)
    require(os.statvfs(path).f_flag & os.ST_RDONLY, 'Gatekeeper binary view not read-only')
    require(hashlib.sha256(raw).hexdigest() == GATEKEEPERD_SHA, 'CURRENT_GATEKEEPERD_IDENTITY')



def pinned_rw_source(runtime, run_id):
    """Open only the current layout/CID/run-pinned physical userdata for RW.

    The existing G1-owned linear map remains read-only and remains the source
    for unwrap/DE. Only the native RW bridge receives this separate O_RDONLY
    descriptor; its underlying physical block device must be writable.
    """
    import fcntl
    import stat
    import struct
    from pathlib import Path
    from android_profiles import EVO_PROFILE
    backend = runtime.backend
    owned = backend.native_policy
    layout, plan = owned.layout, backend.plan
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(owned.admitted is True and owned.run == run_id and plan['run_id'] == run_id
            and owned.boot == boot == layout['boot_id'] == owned.c['boot_id']
            and owned.c['profile_id'] == EVO_PROFILE
            and layout['evidence'] == 'RECORDED_READ_ONLY_OBSERVATION', 'RW_SOURCE_RUN_BOOT')
    cid = Path('/sys/class/block/mmcblk0/device/cid').read_text().strip()
    require(re.fullmatch(r'[0-9a-f]{32}', cid) is not None and cid == owned.c['device_cid'], 'RW_SOURCE_DEVICE_CID')
    item = layout['physical']['userdata']
    require(type(item['sectors']) is int and item['sectors'] > 0
            and (item['sectors'] & ~7) >= 8
            and 0 <= item['sectors'] - (item['sectors'] & ~7) <= 7
            and re.fullmatch(r'[0-9]+:[0-9]+', item['device']) is not None
            and re.fullmatch(r'/dev/mmcblk0p[0-9]+', item['node']) is not None, 'RW_SOURCE_GEOMETRY')
    expected_name = 'a22x-c-' + run_id + '-userdata'
    expected = [(0, item['sectors'], 'linear', item['device'] + ' 0')]
    mappings = [m for m in plan['mappings'] if m['partition'] == 'userdata']
    require(len(mappings) == 1 and mappings[0]['name'] == expected_name
            and mappings[0]['read_only'] is True
            and [tuple(row) for row in mappings[0]['table']] == expected, 'RW_SOURCE_G1_PLAN')
    table, readonly = backend.dm.status(expected_name)
    require(readonly is True and [tuple(row) for row in table] == expected, 'RW_SOURCE_G1_READBACK')
    public = Path('/sys/dev/block') / item['device']
    fields = dict(line.split('=', 1) for line in (public/'uevent').read_text().splitlines() if '=' in line)
    require(fields.get('PARTNAME') == 'userdata' and fields.get('DEVNAME') == item['node'][5:]
            and (public/'size').read_text().strip() == str(item['sectors']), 'RW_SOURCE_PARTITION')
    fd = os.open(item['node'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        require(stat.S_ISBLK(st.st_mode)
                and '%d:%d' % (os.major(st.st_rdev), os.minor(st.st_rdev)) == item['device']
                and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY, 'RW_SOURCE_FD_IDENTITY')
        size, ro = bytearray(8), bytearray(4)
        fcntl.ioctl(fd, 0x80081272, size, True)
        fcntl.ioctl(fd, 0x125e, ro, True)
        require(struct.unpack('=Q', size)[0] == item['sectors'] * 512
                and struct.unpack('=I', ro)[0] == 0, 'RW_SOURCE_BLOCK_GEOMETRY_OR_READONLY')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot
                and Path('/sys/class/block/mmcblk0/device/cid').read_text().strip() == cid,
                'RW_SOURCE_BINDING_CHANGED')
        return fd
    except BaseException:
        os.close(fd)
        raise


def make_consumer(run_id, credential_slot, cleanup_errors, public, progress, rw_capability=None, preparation_mode='ro', session_config=None):
    require(preparation_mode in ('ro','rw'), 'PREPARATION_MODE')
    if preparation_mode == 'rw':
        from decrypt_runtime.rw_support import capability
        capability(rw_capability)
    require(credential_slot == [-1], "Neutral Evo requires credential-free discovery")
    require(progress == {"password_submissions": 0, "unlock_dispatches": 0}, "Invalid auth dispatch state")
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
        import hashlib
        for path, expected in (('/system/bin/a22x-data-ro', G4_SHA), ('/system/bin/a22x-unlock-evox-password', EVO_NATIVE_SHA)):
            require(hashlib.sha256(none_callback.regular(backend.at(path))).hexdigest() == expected, 'LIVE_NATIVE_DEPENDENCY_PIN')
        executable = '/system/bin/a22x-data-ro'
        target, work, ram = '/mnt/userdata-ro', '/run/sp-dm', '/run/sp-ram'
        backend.at(work).mkdir(mode=0o700)
        backend.at(ram).mkdir(mode=0o700)
        # Separate from G2's 4MiB /run: native SQLite snapshots are bounded at
        # 28.25MiB total and remain private tmpfs throughout admission.
        backend._mount('tmpfs', backend.at(ram), 'tmpfs', 2 | 4 | 8,
                       'mode=0700,size=32m')
        keydir = source = rw_source = -1
        creator = None
        new_creator = None
        rw_cleanup_blocked = False
        new_work, new_name = '/run/sp-dm-rw', 'a22x-data-ro-'+run_id+'rw'
        records = []

        def run(argv, descriptors, timeout):
            if argv[1] not in ('cleanup','cleanup-rw'):
                try:
                    remaining = float(os.environ['A22X_C_WD_DEADLINE']) - time.monotonic()
                except (KeyError, ValueError):
                    raise RuntimeError('Missing watchdog deadline') from None
                require(math.isfinite(remaining) and remaining >= max(timeout + 30, 180 if argv[1] == 'unwrap-mount' else 0),
                        'Insufficient watchdog budget')
            # A spawn exception cannot prove that no secure child exists.
            try:
                process = runtime.spawn(argv, pass_fds=descriptors, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, verify_label=False)
            except BaseException:
                park_for_reset()
            if argv[1] in ('unlock-evox-password-user0','unlock-evox-password-user0-rw'):
                progress['unlock_dispatches'] += 1
                progress['password_submissions'] += 1
                try:
                    os.close(credential_slot[0])
                    credential_slot[0] = -1
                except BaseException:
                    park_for_reset()
            nonlocal creator, new_creator
            if argv[1] == 'unwrap-mount':
                creator = process.pid
            if argv[1] == 'unlock-evox-password-user0-rw':
                new_creator = process.pid
            parser = classify
            if argv[1] in ('unlock-evox-password-user0-rw','cleanup-rw'):
                from decrypt_runtime.rw_verdict import classify as classify_rw
                parser = lambda stdout,stderr: classify_rw(stdout,stderr,evo=True)
            status=collect_native_status(process,timeout,public,parser=parser)
            record={'operation':argv[1],'pid':process.pid,'returncode':process.returncode,**status}
            records.append(record)
            public('evox_password_operation_returned', **record)
            if argv[1] not in ('unlock-evox-password-user0','unlock-evox-password-user0-rw'):
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
            lines = run([executable, 'discover-evox-user0', target, ram, str(lock)], (lock,), 30)
            credential_type = discovered_type(lines)
            worker_control.require_zero_auth_calls(runtime)
            require(not any(backend.at(ram).iterdir()), 'DISCOVERY_SNAPSHOT_RETAINED')
            if credential_type == 'none':
                if preparation_mode == 'rw':
                    return dict(status='EVOX_NONE_RW_UNSUPPORTED_BEFORE_AUTH',success=False,
                        failure_stage='unsupported_credential',error_code='WRITE_NOT_QUALIFIED',
                        operations=records,credential_type='none',requested_mode='rw',
                        password_submissions=0,unlock_dispatches=0,synthetic_write_calls=0,independent_media=None)
                require(credential_slot == [-1] and progress['password_submissions'] == 0, 'NONE_CREDENTIAL_FORBIDDEN')
                lines = run([executable, 'prepare-none-user0', target, ram, str(lock)], (lock,), 30)
                schema = none_callback.evaluate_prepare(lines)
                worker_control.require_zero_auth_calls(runtime)
                worker_control.check_before_auth()
                lines = run([executable, 'unlock-none-user0', target, ram, str(lock)], (lock,), 130)
                none_callback.evaluate_unlock(lines, schema)
                independent = none_callback.independent_media_read(backend.at(target))
                verdict = qualify_retained(records, run_id, independent)
                worker_control.hold_evox(runtime, verdict, records, run_id, independent)
                return dict(verdict, operations=records, credential_type='none',
                            password_submissions=0, unlock_dispatches=0,
                            synthetic_write_calls=0, independent_media=independent)
            lines = run([executable, 'prepare-evox-password-user0', target, ram, str(lock)], (lock,), 125)
            prepared = qualify_prepare(lines)
            worker_control.require_zero_auth_calls(runtime)
            public('evox_password_prepare_admitted', **prepared)
            if session_config is not None and session_config.get('ce_session') is not None:
                from decrypt_runtime.reusable_worker import serve as reusable_serve
                rw_source = pinned_rw_source(runtime, run_id)
                result = reusable_serve(runtime, session_config['ce_session'], session_config, credential_slot,
                    target=target, ram=ram, keydir=keydir, source=rw_source,
                    oldwork=work, oldname='a22x-data-ro-' + run_id, oldcreator=creator,
                    prepared=prepared, initial_operations=records)
                # The persistent native owner proved cleanup of every owned
                # userdata crypto chain before exiting; never replay its close.
                creator = None
                return result
            requested_mode = worker_control.awaiting_credential(runtime, credential_slot, 'password', rw_capability)
            require(preparation_mode != 'rw' or requested_mode == 'rw', 'REQUESTED_WRITE_MODE_CHANGED')
            current_framework_identity(runtime, public)
            worker_control.check_before_auth()
            require(progress['unlock_dispatches'] == 0, 'Duplicate unlock dispatch')
            fd = credential_slot[0]
            validate_credential_fd(fd)
            if requested_mode == 'rw':
                from decrypt_runtime.rw_support import capability, pinned_fd
                cap=capability(rw_capability)
                helper_fd=pinned_fd(backend.at(cap['helper']),cap['helper_sha256'],executable=True)
                os.close(helper_fd)
                rw_source=pinned_rw_source(runtime,run_id)
                require(rw_source not in (source,keydir,fd,lock), 'RW_SOURCE_FD_ALIAS')
                backend.at(new_work).mkdir(mode=0o700)
                rw_cleanup_blocked=True
                run([cap['helper'],'unlock-evox-password-user0-rw',target,ram,str(keydir),str(rw_source),
                     str(fd),str(lock),work,'a22x-data-ro-'+run_id,str(creator),new_work,new_name,
                     str(int(float(os.environ['A22X_C_WD_DEADLINE'])*1000))],
                    (keydir,rw_source,fd,lock),195)
                from decrypt_runtime.rw_verdict import native_verdict as rw_native_verdict
                verdict=rw_native_verdict(records[-1])
                rw_cleanup_blocked=verdict['cleanup_errno'] != 0
            else:
                run([executable, 'unlock-evox-password-user0', target, ram, str(fd), str(lock)],
                    (fd, lock), 125)
                verdict = native_verdict(records[-1])
            independent = independent_media_proof(runtime, target, run_id, read_only=requested_mode=='ro') if verdict['success'] else None
            if independent is not None:
                public('independent_media_access_proof', requested_mode=requested_mode, **independent)
                worker_control.hold_evox(runtime, verdict, records, run_id, independent, requested_mode=requested_mode)
            return dict(verdict, operations=records, prepared=prepared, credential_type='password',
                        password_submissions=progress['password_submissions'],
                        unlock_dispatches=progress['unlock_dispatches'],
                        synthetic_write_calls=0, independent_media=independent, requested_mode=requested_mode)

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
                             str(new_creator),str(rw_source),str(lock)],(rw_source,lock),30)
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
                    cleanup_errors.append({'stage':'sp_prepare_dm_cleanup'})
            if keydir >= 0:os.close(keydir)
            if source >= 0:os.close(source)
            if rw_source >= 0:os.close(rw_source)
            try:
                backend.unmount(backend.at(ram))
                backend.at(ram).rmdir()
            except Exception:
                cleanup_errors.append({'stage': 'sp_prepare_private_ram_cleanup'})
            require(not cleanup_errors, 'SP preparation cleanup unconfirmed')

    return consumer


# Exact public records emitted by the unchanged native source. No payloads.
PUBLIC_LITERALS = PUBLIC_LITERALS | frozenset((
    b'G3 SP_CE_AUTHENTICATED_KEY_DELIVERED', b'G4 EVOX_PASSWORD_KEY_RECEIVED_ONCE bytes=64'))
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


PROFILE = re.compile(r'G3 EVOX_PASSWORD_PROFILE schema=([12]) pwd_layout=([12]) pwd_bytes=(89|93) kdf=9:3:1 pin_length=-1 ce_secdis=([01]) primary_present=1')
PUBLIC_LITERALS = PUBLIC_LITERALS | frozenset((
    b'G3 SP_PREPARE_CREDENTIAL type=password',
    b'G3 SP_PREPARE_READY auth_calls=0 ce_profile=modern_software_absent',
    b'G3 SP_PREPARE_READY auth_calls=0 ce_profile=modern_software_secdis',
    b'G4 EVOX_PASSWORD_PREPARE_PASS auth_calls=0',
))
PUBLIC_PATTERNS = PUBLIC_PATTERNS + (re.compile(PROFILE.pattern.encode()),
    re.compile(rb'G3 EVOX_PASSWORD_RESOLVER_DIAG table=[0-9]{1,10} column=[0-9]{1,10} reason=[0-9]{1,10} sqlite=[0-9]{1,10} schema=(?:-1|[0-9]{1,3}) tag=[0-9]{1,10} blob_state=(?:-1|[012])'),
    re.compile(rb'G3 EVOX_PASSWORD_SERVICE_FAILED error=-?[0-9]{1,10}'),
    re.compile(rb'G4 EVOX_PASSWORD_BRIDGE_FAILED operation=(?:prepare|unlock) errno=[0-9]{1,10}'))

def qualify_prepare(lines):
    records=[PROFILE.fullmatch(x) for x in lines if PROFILE.fullmatch(x)]
    require(len(records)==1,'Missing exact Evolution password profile')
    m=records[0]
    require((int(m[2]),int(m[3])) in ((1,89),(2,93)), 'PasswordData layout and size mismatch')
    expected='modern_software_'+('secdis' if m[4]=='1' else 'absent')
    require(sorted(lines)==sorted([m.group(0),
        'G3 SP_PREPARE_CREDENTIAL type=password',
        'G3 SP_PREPARE_READY auth_calls=0 ce_profile='+expected,
        'G4 EVOX_PASSWORD_PREPARE_PASS auth_calls=0']), 'Conflicting preparation evidence')
    return {'keystore_schema':int(m[1]),'pwd_layout':int(m[2]),'pwd_bytes':int(m[3]),
            'scrypt_log_n':9,'scrypt_log_r':3,'scrypt_log_p':1,'pin_length':-1,
            'ce_secdiscardable_present':m[4]=='1','primary_present':True,
            'credential_type':'password','android_user_id':0,'gatekeeper_calls':0}


def park_for_reset():
    while True:
        try:time.sleep(1)
        except BaseException:continue

def collect_native_status(process,timeout,public,parser=None):
    try:
        stdout,stderr=process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:public('native_timeout_waiting_for_outer_watchdog',pid=process.pid)
        except BaseException:pass
        park_for_reset()
    except BaseException:park_for_reset()
    if type(process.returncode) is not int or process.returncode not in (0,1,64,69,70):
        park_for_reset()
    try:status=(parser or classify)(stdout,stderr)
    except BaseException:
        try:public('native_public_protocol_unknown_waiting_for_watchdog',pid=process.pid)
        except BaseException:pass
        park_for_reset()
    if any('UNKNOWN_WAIT_WATCHDOG' in line for line in status['status_lines']):
        park_for_reset()
    return status

PUBLIC_LITERALS=PUBLIC_LITERALS|frozenset((b'G4 EVOX_PASSWORD_STATE_UNKNOWN_WAIT_WATCHDOG',))
PUBLIC_PATTERNS=PUBLIC_PATTERNS+(re.compile(rb'G3 EVOX_PASSWORD_SECURE_STATE_UNKNOWN_WAIT_WATCHDOG source=(?:GK|KM) phase=[0-6]'),)


def native_verdict(record):
    require(record['operation'] == 'unlock-evox-password-user0', 'Wrong native operation')
    lines = record['status_lines']
    failures = [AUTH_FAIL.fullmatch(x.encode('ascii')) for x in lines]
    failures = [x for x in failures if x is not None]
    success = ['G3 SP_CE_AUTHENTICATED_KEY_DELIVERED',
               'G4 EVOX_PASSWORD_KEY_RECEIVED_ONCE bytes=64',
               'G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS']
    media = [MEDIA.fullmatch(x.encode('ascii')) for x in lines]
    media = [x for x in media if x is not None]
    require(type(record['returncode']) is int, 'Native completion missing')
    if record['returncode'] == 0:
        require(len(media) == 1 and int(media[0][1]) <= 4096 and media[0][2] == b'1',
                'Incomplete native media proof')
        # Profile/READY records occur only on prepare in exact native source.
        require(sorted(lines) == sorted(success + [media[0][0].decode('ascii')]),
                'Conflicting or incomplete native CE proof')
        return dict(status='EVOX_PASSWORD_CE_RO_MEDIA_PASS', success=True, failure_stage=None)
    require(not media, 'Failure with media success')
    require(len(failures) <= 1, 'Duplicate native authentication verdict')
    if failures:
        # A primary failure may follow protector success, never CE delivery.
        require(not any(x in lines for x in success), 'Failure after CE delivery')
        match = failures[0]
        status, timeout = int(match[2]), int(match[3])
        require(status <= 0xffffffff and timeout <= 0xffffffff, 'Auth scalar overflow')
        return dict(status='EVOX_PASSWORD_AUTH_FAILED_NO_RETRY', success=False,
                    failure_stage='protector' if match[1] == b'AUTH' else 'primary',
                    native_auth_status=status, native_timeout_ms=timeout)
    return dict(status='EVOX_PASSWORD_NATIVE_FAILED_NO_RETRY', success=False, failure_stage='native')


def independent_media_proof(runtime, target, run_id, read_only=True, *, expected_name=None, alias_work=None):
    """Separate bounded read-only policy+readdir check; no names/content emitted.

    FS_IOC_GET_ENCRYPTION_POLICY_EX only observes an existing v2 policy. G4
    independently proves its received key identifier matches this media policy.
    Do not expose the policy identifier or any directory entry.
    """
    import fcntl
    import stat
    import struct
    from pathlib import Path
    require(type(read_only) is bool, 'ACCESS_MODE_TYPE')
    backend = runtime.backend
    expected_name = expected_name or 'a22x-data-ro-' + run_id + ('' if read_only else 'rw')
    allowed_names = {'a22x-data-ro-' + run_id + suffix for suffix in ('', 'rw', '-session-ro', '-session-rw')}
    require(expected_name in allowed_names, 'INDEPENDENT_DM_NAME')
    alias_work = alias_work or ('/run/sp-dm' if read_only else '/run/sp-dm-rw')
    require(alias_work in ('/run/sp-dm', '/run/sp-dm-rw', '/run/sp-session-ro', '/run/sp-session-rw'), 'INDEPENDENT_ALIAS_PATH')
    expected_flag='1' if read_only else '0'
    fds = []
    def open_dir(path, parent=None):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                     dir_fd=parent)
        fds.append(fd)
        return fd
    def block_ro(fd):
        value = bytearray(4)
        fcntl.ioctl(fd, 0x125e, value, True)  # BLKROGET, read-only query.
        return struct.unpack('I', value)[0] == 1
    try:
        root = open_dir(backend.at(target))
        media_parent = open_dir('media', root)
        media = open_dir('0', media_parent)
        initial = os.fstat(media)
        require(all(os.fstat(fd).st_dev == initial.st_dev and
                    bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY) is read_only for fd in (root, media_parent, media)),
                'Independent media filesystem not read-only')
        policy = bytearray(32)
        struct.pack_into('=Q', policy, 0, 24)
        fcntl.ioctl(media, 0xc0096616, policy, True)
        size = struct.unpack_from('=Q', policy, 0)[0]
        require(size == 24 and policy[8] == 2 and policy[9] == 1 and policy[10] == 4
                and policy[11] & ~11 == 0 and policy[12:16] == bytes(4),
                'Independent media policy unsupported')
        # A sysfs DM node is selected by the filesystem device, never guessed.
        major, minor = os.major(initial.st_dev), os.minor(initial.st_dev)
        sysnode = Path('/sys/dev/block') / ('%d:%d' % (major, minor))
        require((sysnode/'dm/name').read_text().strip() == expected_name,
                'Independent filesystem DM identity rejected')
        require((sysnode/'ro').read_text().strip() == expected_flag, 'Independent DM not read-only')
        slaves = list((sysnode/'slaves').iterdir())
        require(len(slaves) == 1 and
                (slaves[0]/'dm/name').read_text().strip() == expected_name + '-raw' and
                (slaves[0]/'ro').read_text().strip() == expected_flag,
                'Independent raw DM not read-only')
        alias = os.open(backend.at(alias_work + '/data'), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        fds.append(alias)
        st = os.fstat(alias)
        require(stat.S_ISBLK(st.st_mode) and st.st_rdev == initial.st_dev and block_ro(alias) is read_only,
                'Independent block alias not read-only')
        count = 0
        end = time.monotonic() + 5
        with os.scandir(media) as entries:
            for _entry in entries:
                count += 1
                require(count <= 4096 and time.monotonic() <= end,
                        'Independent media enumeration bound')
        require(time.monotonic() <= end and os.fstat(media).st_dev == initial.st_dev and
                all(bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY) is read_only for fd in (root, media_parent, media))
                and block_ro(alias) is read_only and (sysnode/'ro').read_text().strip() == expected_flag
                and (slaves[0]/'ro').read_text().strip() == expected_flag,
                'Independent media read-only state changed')
        return {'entries': count, 'complete': True, 'policy_v2_supported': True,
                'fs_ro': read_only, 'dm_ro': read_only, 'raw_dm_ro': read_only, 'alias_ro': read_only}
    finally:
        for fd in reversed(fds):
            os.close(fd)


PUBLIC_LITERALS = PUBLIC_LITERALS | none_callback.LITERALS | frozenset((
    b'G3 EVOX_CREDENTIAL_DISCOVERED type=none auth_calls=0',
    b'G3 EVOX_CREDENTIAL_DISCOVERED type=password auth_calls=0',
    b'G4 EVOX_DISCOVER_PASS auth_calls=0',
))
PUBLIC_PATTERNS = PUBLIC_PATTERNS + tuple(none_callback.PATTERNS)


def discovered_type(lines):
    for kind in ('none', 'password'):
        expected = ['G3 EVOX_CREDENTIAL_DISCOVERED type='+kind+' auth_calls=0',
                    'G4 EVOX_DISCOVER_PASS auth_calls=0']
        if sorted(lines) == sorted(expected):
            return kind
    raise RuntimeError('Unqualified native credential discovery')


def qualify_retained(ops, run_id, independent):
    require(type(ops) is list and len(ops) == 5, 'EVOX_RETAINED_OPERATION_COUNT')
    qualify_common(ops, run_id)
    kind = discovered_type(ops[2]['status_lines'])
    require(ops[2]['operation'] == 'discover-evox-user0' and
            type(ops[2]['returncode']) is int and ops[2]['returncode'] == 0,
            'EVOX_DISCOVERY_EXIT')
    if kind == 'none':
        return none_callback.qualify_ce(ops[:2] + ops[3:], run_id, independent)
    require([x['operation'] for x in ops] == ['unwrap-mount','unlock-de-user0',
            'discover-evox-user0','prepare-evox-password-user0','unlock-evox-password-user0'],
            'EVOX_PASSWORD_OPERATION_SEQUENCE')
    require(all(type(x['returncode']) is int and x['returncode'] == 0 for x in ops[:4]),
            'EVOX_PASSWORD_ADMISSION_FAILED')
    qualify_prepare(ops[3]['status_lines'])
    verdict = native_verdict(ops[4])
    require(verdict['success'] is True, 'EVOX_PASSWORD_CE_NOT_AUTHENTICATED')
    require(type(independent) is dict and set(independent) == {'entries','complete',
            'policy_v2_supported','fs_ro','dm_ro','raw_dm_ro','alias_ro'} and
            type(independent['entries']) is int and 0 <= independent['entries'] <= 4096 and
            all(independent[k] is True for k in independent if k != 'entries'),
            'EVOX_PASSWORD_INDEPENDENT_MEDIA_PROOF')
    return verdict


def qualify_common(ops, run_id):
    require(type(ops) is list and len(ops) >= 3, 'EVOX_OPERATION_PREFIX')
    require([x['operation'] for x in ops[:3]] == ['unwrap-mount','unlock-de-user0','discover-evox-user0']
            and all(type(x['returncode']) is int and x['returncode'] == 0 for x in ops[:3]), 'EVOX_ADMISSION_PREFIX')
    mount = ops[0]['status_lines'];de = ops[1]['status_lines']
    matched = [none_callback.MOUNT.fullmatch(x) for x in mount if none_callback.MOUNT.fullmatch(x)]
    require(len(mount) == 2 and len(matched) == 1 and matched[0][1] == 'a22x-data-ro-'+run_id
            and mount.count('G3 AUTHENTICATED_KEY_DELIVERED') == 1, 'EVOX_METADATA_PROOF')
    require(de == ['G4 FSCRYPT_V2_KEY_POLICY_MATCH_PASS'] * 2 + ['G4 DE_ONLY_UNLOCK_PASS ce_calls=0']
            + ['G3 AUTHENTICATED_KEY_DELIVERED'] * 2, 'EVOX_DE_PROOF')


def qualify_retained_rw(ops, run_id, independent):
    require(type(ops) is list and len(ops)==5, 'EVOX_RW_RETAINED_OPERATION_COUNT')
    qualify_common(ops, run_id)
    require(discovered_type(ops[2]['status_lines']) == 'password', 'NONE_RW_UNSUPPORTED_BEFORE_AUTH')
    require(ops[3]['operation']=='prepare-evox-password-user0' and type(ops[3]['returncode']) is int
            and ops[3]['returncode']==0, 'EVOX_RW_PREPARE_EXIT')
    qualify_prepare(ops[3]['status_lines'])
    from decrypt_runtime.rw_verdict import native_verdict as rw_verdict
    verdict=rw_verdict(ops[4])
    require(ops[4]['operation']=='unlock-evox-password-user0-rw' and verdict['success'] is True,
            'EVOX_RW_CE_NOT_AUTHENTICATED')
    require(type(independent) is dict and set(independent)=={'entries','complete','policy_v2_supported',
            'fs_ro','dm_ro','raw_dm_ro','alias_ro'} and type(independent['entries']) is int
            and 0<=independent['entries']<=4096 and independent['complete'] is True
            and independent['policy_v2_supported'] is True
            and all(independent[k] is False for k in ('fs_ro','dm_ro','raw_dm_ro','alias_ro')),
            'EVOX_RW_INDEPENDENT_MEDIA_PROOF')
    # Bind both public chain names to this admitted run, never only their shape.
    lines=ops[4]['status_lines']
    for prefix,name in [('G4 WP_KERNEL_RO_RECOVERY_CHECK_PASS ', 'a22x-data-ro-'+run_id+'rw'),
                        ('G4 WP_INITIAL_FS_RO_DM_RW_PASS ', 'a22x-data-ro-'+run_id+'rw')]:
        found=[line for line in lines if line.startswith(prefix)]
        require(len(found)==1 and found[0].startswith(prefix+'dm='+name+' raw_dm='+name+'-raw '),
                'EVOX_RW_CHAIN_NAME_BINDING')
    return verdict
