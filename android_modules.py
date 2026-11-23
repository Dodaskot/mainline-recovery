#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only Android root inventory and version-pinned module marker rescue.

Nothing here executes Android binaries or module scripts, mounts data, installs
root, installs ZIPs, or writes an Android image. The Files lifecycle owns the
authenticated mount. Recovery marker changes and Android activation are separate
outcomes. See docs/android-modules-p0-20261117.uk.md for the supported scope.
"""
import contextlib
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import stat
import sys
import uuid
import zipfile
import zlib

import filesystem as fs

SCHEMA = 'a22x.android-modules.plan.v1'
JOURNAL_SCHEMA = 'a22x.android-modules.journal.v1'
MODULE_ID = re.compile(r'[A-Za-z][A-Za-z0-9._-]{1,127}\Z')
ACTIONS = ('disable', 'enable', 'remove', 'cancel-remove', 'disable-all')
TREES = ('modules', 'modules_update')
MARKERS = ('disable', 'remove', 'update')
MAX_MODULES, MAX_FILES, MAX_BYTES = 256, 32768, 512 << 20
STAMP_ONLY_BYTES = 8 << 20  # larger regular files are bound by their stamp only (module_digest)
MAX_TEXT, MAX_BINARY = 32768, 16 << 20
JOURNAL_DIR = '/adb/a22x-recovery-module-rescue'
# Exact official release assets, checked against the GitHub release APK digest.
# These are source-reviewed identities, NOT an a22x hardware qualification claim.
MAGISK_31000 = {
    'id': 'magisk', 'version': '31.0', 'version_code': 31000,
    'adapter': 'magisk-31.0-markers-v1',
    'apk_sha256': '2c8a488b9a5293e578e95ae4f07e3c57aba4feec4a52ca4dd852a2692d6dd4e8',
    'magisk_sha256': '44eece7e1faefe3156c289c74b9f747e0d5b029aed84cbeb85be0139fb03d813',
    'init_sha256': 'dc2ea943541e530e786c69d6d2721f1a3625960d9784ade646baec86a074180e',
    'util_sha256': '01c392c8fe1a0da584f85a3738f3f0a19b73e120408ca6f4795027538aad6077',
}
MAGISK_31100 = {
    'id': 'magisk', 'version': '31.1', 'version_code': 31100,
    'adapter': 'magisk-31.1-markers-v1',
    'apk_sha256': '89cefac0a318afa39fb3880c45c87b036c05bc1ebf02a7a715b7f8d7c26ac6e7',
    'magisk_sha256': 'fb0ba1b1f3472d34b8ae21edd3a69c2a44f46a3a7c34e85e37c6b2b57d22b9ec',
    'init_sha256': 'c0c7cc1c8e1afb92bff602164f6aa1bb4103f5028d076216d8bef48496e2f4dc',
    'util_sha256': '417866965cb3845c7ea085f1499393efcf65e6c7cf1321e7911a3bd7c25a6c8d',
}
MAGISK_ADAPTERS = (MAGISK_31000, MAGISK_31100)
# KernelSU Next (2026-11-22, goal item 6): the manager this recovery queues with its own KernelSU Next
# kernel (release kernelsu-next-a22x-v1) installs its ksud as /data/adb/ksud, byte for byte the APK's
# libksud.so. Its module rules were read in that build's source (KernelSU-Next 32e25d58,
# userspace/ksud/src/module.rs, init_event.rs, defs.rs): modules in /data/adb/modules, pending ones in
# /data/adb/modules_update; the markers disable, remove and update, as Magisk's; at post-fs-data ksud
# moves pending modules in, removes the marked ones (running their uninstall.sh), and only then loads
# sepolicy.rule and runs the scripts of the modules left enabled. A module's initrc and preinit reach
# init from /metadata before that, so modules with them stay read-only here, as with Magisk. A metamodule
# (metamodule=1) mounts the other modules for ksud: it is changed in the manager only.
KERNELSU_NEXT_33555 = {
    'id': 'kernelsu', 'version': 'v3.4.2-200-g32e25d58', 'version_code': 33555,
    'adapter': 'kernelsu-next-33555-markers-v1', 'source': 'KernelSU-Next 32e25d58 userspace/ksud',
    'apk_sha256': 'be27972d50a2b44258541778fd021d06005e2e6cdeee254e66bb161580e0b1cb',
    'ksud_sha256': '51356961debf379bff06aa8034db372a587dffb15e7e09a1060f162ca7c08894',
}
KERNELSU_ADAPTERS = (KERNELSU_NEXT_33555,)
FRAMEWORK_NAMES = {'magisk': 'Magisk', 'kernelsu': 'KernelSU Next', 'apatch': 'APatch'}
LIMITATIONS = [
    'Android activation and mount/remount persistence require hardware qualification.',
    'Changes affect module markers for the next Android boot; no scripts run in recovery.',
    'Global /data/adb boot scripts and previous persistent module changes are not undone.',
    'Modules with early policy or preinit content require a separate adapter.',
    'APatch, KernelSU builds other than the reviewed KernelSU Next, forks and unknown versions are read-only.',
]


def require(value, code, message, **details):
    if not value:
        fs.fail(code, message, **details)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(',', ':')).encode()).hexdigest()


def stamp(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink]


def read_regular(pin, folder, name, limit=MAX_TEXT, optional=False, capture=True):
    """No-follow, bounded, same-mount reads, with both inode and name rechecks."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=folder)
    except FileNotFoundError:
        if optional:
            return None
        raise
    try:
        pin.check_fd(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                'MODULE_FILE_UNSAFE', 'Module metadata must be a regular single-link file')
        require(before.st_size <= limit, 'MODULE_FILE_TOO_LARGE', 'Module metadata exceeds its size limit')
        chunks, count, checksum = [], 0, hashlib.sha256()
        while True:
            part = os.read(fd, min(65536, limit + 1 - count))
            if not part:
                break
            if capture:
                chunks.append(part)
            checksum.update(part)
            count += len(part)
            require(count <= limit, 'MODULE_FILE_TOO_LARGE', 'The file grew beyond its size limit')
        require(stamp(before) == stamp(os.fstat(fd)) == stamp(os.stat(name, dir_fd=folder, follow_symlinks=False)),
                'MODULE_CHANGED', 'The module changed while being inspected')
        pin.recheck()
        return {'data': b''.join(chunks), 'stat': stamp(before),
                'sha256': checksum.hexdigest()}
    finally:
        os.close(fd)


def read_path(pin, path, limit=MAX_TEXT, optional=False):
    try:
        with pin.parent(path) as (folder, name):
            return read_regular(pin, folder, name, limit, optional)
    except FileNotFoundError:
        if optional:
            return None
        raise


def path_kind(pin, path):
    try:
        with pin.parent(path) as (folder, name):
            st = os.stat(name, dir_fd=folder, follow_symlinks=False)
            return 'directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'unsafe'
    except FileNotFoundError:
        return None


def strict_cpio(raw):
    """Extract only the two public Magisk assets, rejecting duplicate/truncated CPIO."""
    wanted, found, at, count = {'init', 'overlay.d/sbin/magisk.xz'}, {}, 0, 0
    while at + 110 <= len(raw):
        require(raw[at:at + 6] in (b'070701', b'070702'), 'BOOT_ROOT_UNKNOWN', 'Unsupported ramdisk archive')
        try:
            fields = [int(raw[at + 6 + i * 8:at + 14 + i * 8], 16) for i in range(13)]
        except ValueError:
            fs.fail('BOOT_ROOT_UNKNOWN', 'Invalid ramdisk header')
        size, nsize = fields[6], fields[11]
        require(1 <= nsize <= 4096 and at + 110 + nsize <= len(raw), 'BOOT_ROOT_UNKNOWN', 'Invalid ramdisk name')
        named = raw[at + 110:at + 110 + nsize]
        require(named.endswith(b'\0'), 'BOOT_ROOT_UNKNOWN', 'Unterminated ramdisk name')
        name = named[:-1].decode('utf-8', 'strict')
        if name.startswith('./'):
            name = name[2:]
        start = (at + 110 + nsize + 3) & ~3
        require(start + size <= len(raw), 'BOOT_ROOT_UNKNOWN', 'Truncated ramdisk member')
        if name == 'TRAILER!!!':
            return found
        if name in wanted:
            require(name not in found and stat.S_ISREG(fields[1]) and size <= MAX_BINARY,
                    'BOOT_ROOT_UNKNOWN', 'Ambiguous Magisk ramdisk asset')
            found[name] = raw[start:start + size]
        at = (start + size + 3) & ~3
        count += 1
        require(count <= MAX_FILES, 'BOOT_ROOT_UNKNOWN', 'Too many ramdisk members')
    fs.fail('BOOT_ROOT_UNKNOWN', 'No ramdisk trailer')


def _boot_identity(context):
    import bootimage
    import install
    ctx = install.FixtureContext(context.root) if context.mode == 'fixture' else install.DeviceContext()
    target = ctx.target('boot')
    require(target['size_bytes'] <= 64 << 20, 'BOOT_ROOT_UNKNOWN', 'BOOT exceeds the inspection limit')
    data = install.target_bytes(ctx, target)
    info = bootimage.inspect_boot(data)
    result = {'kind': 'linux' if info.get('mainline') else 'android',
              'root': info.get('root') or '', 'sha256': hashlib.sha256(data).hexdigest(),
              'kernelpatch': info.get('kernelpatch') or '', 'magisk_sha256': None, 'init_sha256': None}
    if result['kind'] != 'android' or result['root'] != 'magisk':
        return result
    header = bootimage.boot_header(data)
    start, size = header['sections']['ramdisk']
    raw = data[start:start + size]
    if raw[:2] == b'\x1f\x8b':
        stream = zlib.decompressobj(31)
        raw = stream.decompress(raw, 64 << 20)
        require(stream.eof and not stream.unconsumed_tail and not stream.unused_data,
                'BOOT_ROOT_UNKNOWN', 'The ramdisk stream is not fully bounded')
    else:
        require(raw[:6] in (b'070701', b'070702') and len(raw) <= 64 << 20,
                'BOOT_ROOT_UNKNOWN', 'This ramdisk compression has no module adapter')
    files = strict_cpio(raw)
    if 'init' in files:
        result['init_sha256'] = hashlib.sha256(files['init']).hexdigest()
    if 'overlay.d/sbin/magisk.xz' in files:
        stream = lzma.LZMADecompressor(memlimit=64 << 20)
        binary = stream.decompress(files['overlay.d/sbin/magisk.xz'], max_length=MAX_BINARY + 1)
        require(stream.eof and not stream.unused_data and len(binary) <= MAX_BINARY,
                'BOOT_ROOT_UNKNOWN', 'Embedded Magisk exceeds the inspection limit')
        result['magisk_sha256'] = hashlib.sha256(binary).hexdigest()
    return result


def framework(pin, boot):
    evidence, candidates = {}, []
    for ident, path in (('magisk', '/adb/magisk'), ('apatch', '/adb/ap'), ('kernelsu', '/adb/ksu')):
        kind = path_kind(pin, path)
        if kind is not None:
            candidates.append(ident)
            evidence[path] = kind
    # Switching root (APatch -> KernelSU, say) leaves the old framework's directory in /data/adb. The
    # root in BOOT is what runs at the next start, so when BOOT names exactly one of the directories
    # found, that one is the framework and the others are leftovers, reported but never touched.
    leftovers = []
    if len(candidates) > 1 and boot.get('root') in candidates and all(v == 'directory' for v in evidence.values()):
        leftovers = [c for c in candidates if c != boot['root']]
        candidates = [boot['root']]
    result = {'id': candidates[0] if len(candidates) == 1 else 'unknown', 'version': None,
              'version_code': None, 'status': 'unknown', 'adapter': None,
              'reason': 'Installed framework and exact version are not established',
              'evidence': evidence, 'boot': boot, 'hardware_qualified': False}
    if leftovers:
        result['leftovers'] = leftovers
    if len(candidates) != 1 or any(v == 'unsafe' for v in evidence.values()):
        result['reason'] = 'Multiple or unsafe framework directories; read-only diagnostics only' if candidates else 'No installed framework assets were found'
        return result
    ident = candidates[0]
    if ident == 'kernelsu':
        return kernelsu_framework(pin, boot, result)
    if ident != 'magisk':
        result['reason'] = 'This framework needs its own version-aware rescue adapter'
        return result
    util = read_path(pin, '/adb/magisk/util_functions.sh', optional=True)
    binary = read_path(pin, '/adb/magisk/magisk', MAX_BINARY, optional=True)
    if util:
        text = util['data'].decode('utf-8', 'replace')
        codes = re.findall(r'^MAGISK_VER_CODE=([0-9]+)$', text, re.M)
        versions = re.findall(r"^MAGISK_VER=['\"]?([A-Za-z0-9.+_-]+)['\"]?$", text, re.M)
        if len(codes) == len(versions) == 1:
            result.update(version=versions[0], version_code=int(codes[0]))
        evidence['util_functions.sh'] = {k: util[k] for k in ('sha256', 'stat')}
    if binary:
        evidence['magisk'] = {k: binary[k] for k in ('sha256', 'stat')}
    rule = next((r for r in MAGISK_ADAPTERS if r['version_code'] == result['version_code']), None)
    matched = (rule and boot.get('kind') == 'android' and boot.get('root') == 'magisk'
               and boot.get('magisk_sha256') == rule['magisk_sha256']
               and boot.get('init_sha256') == rule['init_sha256']
               and util and util['sha256'] == rule['util_sha256']
               and binary and binary['sha256'] == rule['magisk_sha256']
               and result['version'] == rule['version'] and result['version_code'] == rule['version_code'])
    if matched:
        result.update(status='supported', adapter=rule['adapter'], reason=None,
                      version_source='matching official BOOT assets and installed assets')
    else:
        result['reason'] = 'BOOT and installed Magisk assets do not match the exact reviewed release'
    return result


def kernelsu_framework(pin, boot, result):
    """KernelSU Next: its kernel in BOOT (the ksu SELinux domain) and its ksud in /data/adb, exactly
    the reviewed build's."""
    daemon = read_path(pin, '/adb/ksud', MAX_BINARY, optional=True)
    if daemon:
        result['evidence']['ksud'] = {k: daemon[k] for k in ('sha256', 'stat')}
    rule = next((r for r in KERNELSU_ADAPTERS if daemon and daemon['sha256'] == r['ksud_sha256']), None)
    if rule and boot.get('kind') == 'android' and boot.get('root') == 'kernelsu' and result['evidence'].get('/adb/ksu') == 'directory':
        result.update(status='supported', adapter=rule['adapter'], reason=None, version=rule['version'],
                      version_code=rule['version_code'], version_source='KernelSU in BOOT and the reviewed ksud in /data/adb')
    elif not daemon:
        result['reason'] = 'KernelSU Next has no ksud in /data/adb yet: open its manager once in Android'
    elif boot.get('root') != 'kernelsu':
        result['reason'] = 'BOOT does not carry KernelSU'
    else:
        result['reason'] = 'This ksud is not the reviewed KernelSU Next build'
    return result


def parse_prop(data, ident):
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        fs.fail('MODULE_PROP_INVALID', 'module.prop is not UTF-8')
    require('\0' not in text and '\r' not in text, 'MODULE_PROP_INVALID', 'module.prop needs LF text')
    props = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        require(sep and key not in props and len(key) <= 80 and len(value) <= 4096,
                'MODULE_PROP_INVALID', 'module.prop has duplicate or invalid fields')
        props[key] = value
    require(props.get('id') == ident and MODULE_ID.fullmatch(ident),
            'MODULE_ID_MISMATCH', 'Module ID must match its directory')
    require(props.get('name') and props.get('version') and re.fullmatch(r'[0-9]{1,18}', props.get('versionCode', '')),
            'MODULE_PROP_INVALID', 'Module name, version or versionCode is missing or invalid')
    return props


def marker(pin, folder, name):
    value = read_regular(pin, folder, name, 0, optional=True)
    if value is None:
        return {'present': False}
    return {'present': True, 'stat': value['stat'], 'sha256': value['sha256']}


def tree_rows(pin, tree):
    path = '/adb/' + tree
    if path_kind(pin, path) is None:
        return []
    rows = []
    with pin.directory(path) as directory:
        names = sorted(os.listdir(directory))
        require(len(names) <= MAX_MODULES, 'MODULE_LIMIT', 'Too many module directories')
        for ident in names:
            if ident == '.core':
                continue
            row = {'id': ident, 'path': path + '/' + ident, 'tree': tree,
                   'valid': False, 'reason': None, 'markers': {}}
            try:
                require(MODULE_ID.fullmatch(ident), 'MODULE_ID_INVALID', 'Invalid module directory name')
                with pin.directory(row['path']) as folder:
                    prop = read_regular(pin, folder, 'module.prop')
                    parsed = parse_prop(prop['data'], ident)
                    row.update(name=parsed['name'], version=parsed['version'], version_code=int(parsed['versionCode']),
                               prop_sha256=prop['sha256'], prop_stat=prop['stat'], directory_stat=stamp(os.fstat(folder)))
                    row['markers'] = {name: marker(pin, folder, name) for name in MARKERS}
                    row['early_content'] = [name for name in ('sepolicy.rule', 'preinit', 'initrc')
                                            if path_kind(pin, row['path'] + '/' + name) is not None]
                    row['metamodule'] = parsed.get('metamodule', '').strip().lower() in ('1', 'true')
                    row['valid'] = True
            except (fs.FilesystemError, OSError) as exc:
                row['reason'] = str(exc)
                row['error_code'] = getattr(exc, 'code', 'MODULE_PATH_UNSAFE')
            rows.append(row)
    return rows


def access(volume, mode):
    auth = (volume.get('ce_authenticated') is True and volume.get('fscrypt_policy_verified') is True
            and volume.get('android_user_id') == 0 and volume.get('mount_owner') == 'android-decrypt')
    # Android data that encrypts nothing (LineageOS 20 here, 2026-11-21) has no key to authenticate; the
    # same test as android_data.plain_open.
    auth = auth or (mode == 'device' and volume.get('unencrypted_android_data') is True and volume.get('mounted') is True
                    and volume.get('mountable') is True and volume.get('mount_owner') == 'filesystem'
                    and volume.get('fs_type') == 'f2fs')
    # Fixture files are explicitly synthetic; they are never an alternate device admission path.
    if mode == 'fixture':
        auth = volume.get('mounted') is True and not volume.get('fscrypt_feature')
    return {'mounted': bool(volume.get('mounted')), 'authenticated': bool(auth),
            'read_only': bool(volume.get('read_only')), 'write_supported': bool(volume.get('write_supported')),
            'volume_token': volume['volume_token'], 'mount_id': volume.get('mount_id'),
            'physical_volume_token': volume.get('physical_volume_token')}


def _inventory(context, expected_volume=None):
    volume = context.volume('userdata', expected_volume)
    acc = access(volume, context.mode)
    result = {'framework': {'id': 'unknown', 'version': None, 'version_code': None, 'status': 'unknown',
                            'adapter': None, 'reason': 'Unlock and mount Android user 0 through Files first'},
              'access': acc, 'modules': [], 'can_mutate': False, 'limitations': LIMITATIONS, '_rows': []}
    if not acc['mounted'] or not acc['authenticated']:
        return result
    with fs.PinnedVolume(context, 'userdata', volume['volume_token']) as pin:
        try:
            boot = _boot_identity(context)
        except (fs.FilesystemError, OSError, ValueError, lzma.LZMAError, zlib.error) as exc:
            boot = {'kind': 'unknown', 'root': '', 'reason': str(exc)}
        result['framework'] = framework(pin, boot)
        rows = tree_rows(pin, 'modules') + tree_rows(pin, 'modules_update')
        grouped = {}
        for row in rows:
            grouped.setdefault(row['id'], []).append(row)
        for ident, copies in sorted(grouped.items()):
            active = next((r for r in copies if r['tree'] == 'modules'), None)
            current = active or copies[0]
            pending = any(r['tree'] == 'modules_update' for r in copies)
            valid = all(r['valid'] for r in copies)
            disabled = all(r.get('markers', {}).get('disable', {}).get('present', False) for r in copies)
            removing = any(r.get('markers', {}).get('remove', {}).get('present', False) for r in copies)
            reason = next((r['reason'] for r in copies if r['reason']), None)
            if not reason and any(r.get('early_content') for r in copies):
                reason = 'Early policy/preinit content needs a separate adapter'
            if not reason and any(r['markers']['update']['present'] for r in copies) and not pending:
                reason = 'An update marker has no corresponding pending module'
            if not reason and any(r.get('metamodule') for r in copies):
                reason = 'A metamodule mounts the other modules: change it in the KernelSU Next manager'
            capable = valid and not reason and result['framework']['status'] == 'supported'
            actions = ['disable', 'remove'] if capable else []
            if capable and not removing:
                actions.append('enable')
            if capable and removing:
                actions.append('cancel-remove')
            result['modules'].append({'id': ident, 'name': current.get('name', ident),
                'version': current.get('version'), 'version_code': current.get('version_code'),
                'status': 'unsupported' if not valid or reason else 'remove-pending' if removing else
                          'update-pending' if pending else 'disabled' if disabled else 'enabled',
                'disabled': disabled, 'remove_pending': removing, 'pending_update': pending,
                'actions': actions, 'reason': reason, 'copies': copies})
        result['can_mutate'] = result['framework']['status'] == 'supported' and not acc['read_only'] and acc['write_supported']
        result['_rows'] = rows
        pin.recheck()
    return result


def inventory(context):
    with context.operation_lock():
        value = _inventory(context)
    return {key: val for key, val in value.items() if not key.startswith('_')}


def module_digest(pin, path):
    """Hash a selected module without following links or opening device nodes."""
    entries, total = [], [0]
    def walk(directory, prefix, depth):
        require(depth <= 64, 'MODULE_LIMIT', 'Module tree is too deep')
        before = stamp(os.fstat(directory))
        for name in sorted(os.listdir(directory)):
            require(len(entries) < MAX_FILES, 'MODULE_LIMIT', 'Module tree has too many entries')
            st = os.stat(name, dir_fd=directory, follow_symlinks=False)
            rel = prefix + name
            record = [rel, stamp(st)]
            if stat.S_ISDIR(st.st_mode):
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                try:
                    pin.check_fd(fd)
                    require(stamp(os.fstat(fd)) == stamp(st), 'MODULE_CHANGED', 'Module directory changed')
                    entries.append(record)
                    walk(fd, rel + '/', depth + 1)
                    require(stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)) == stamp(os.fstat(fd)),
                            'MODULE_CHANGED', 'Module directory was replaced')
                finally:
                    os.close(fd)
            elif stat.S_ISREG(st.st_mode) and st.st_size > STAMP_ONLY_BYTES:
                # A large file (a metamodule's image of the other modules, hundreds of MB) is bound by its
                # stamp, which a change of it changes too; the plan only writes marker files (2026-11-22, live:
                # meta-overlayfs's modules.img stopped the rescue at MODULE_LIMIT).
                record.append('stamp-only')
                entries.append(record)
            elif stat.S_ISREG(st.st_mode):
                total[0] += st.st_size
                require(total[0] <= MAX_BYTES, 'MODULE_LIMIT', 'Module exceeds the bounded rescue inspection size')
                value = read_regular(pin, directory, name, MAX_BYTES, capture=False)
                record.append(value['sha256'])
                entries.append(record)
            elif stat.S_ISLNK(st.st_mode):
                record.append(os.readlink(name, dir_fd=directory))
                require(stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)) == stamp(st),
                        'MODULE_CHANGED', 'Module symlink changed')
                entries.append(record)
            elif stat.S_ISCHR(st.st_mode) and st.st_rdev == 0:
                # Magisk's documented whiteout; never open it.
                entries.append(record + ['whiteout'])
            else:
                fs.fail('MODULE_FILE_UNSAFE', 'A module contains unsupported special files')
        require(stamp(os.fstat(directory)) == before, 'MODULE_CHANGED', 'Module directory changed while hashing')
    with pin.directory(path) as directory:
        walk(directory, '', 0)
    return {'sha256': digest(entries), 'entries': len(entries), 'bytes': total[0]}


def _preview(context, action, module_id=None):
    require(action in ACTIONS, 'MODULE_ACTION_INVALID', 'Unknown module action')
    require((action == 'disable-all' and module_id is None) or
            (action != 'disable-all' and isinstance(module_id, str) and MODULE_ID.fullmatch(module_id)),
            'MODULE_ID_INVALID', 'Select one valid module, or use disable-all without a module ID')
    state = _inventory(context)
    selected = state['modules'] if action == 'disable-all' else [r for r in state['modules'] if r['id'] == module_id]

    def rescuable(row):
        """disable-all is the rescue after a boot loop: a valid metamodule is disabled with the others, as
        KernelSU's safe mode leaves every module out (2026-11-22, live: one metamodule, which the recovery
        otherwise leaves to the manager, refused the whole rescue). Single actions on it stay the manager's."""
        return (action == 'disable-all' and any(c.get('metamodule') for c in row['copies'])
                and all(c.get('valid') for c in row['copies'])
                and not any(c.get('early_content') for c in row['copies']))
    reason = None
    if not state['access']['mounted'] or not state['access']['authenticated']:
        reason = 'Unlock and mount Android user 0 through Files first'
    elif state['framework']['status'] != 'supported':
        reason = state['framework']['reason']
    elif not selected:
        reason = 'No matching modules were found'
    elif any(('disable' if action == 'disable-all' else action) not in row['actions'] and not rescuable(row) for row in selected):
        reason = next((r['reason'] for r in selected if r['reason']), None) or 'Cancel pending removal before enabling this module'
    changes, fingerprints = [], {}
    if not reason:
        name, desired = ('disable', True) if action in ('disable', 'disable-all') else ('disable', False) if action == 'enable' else ('remove', action == 'remove')
        with fs.PinnedVolume(context, 'userdata', state['access']['volume_token']) as pin:
            for row in selected:
                for copy in row['copies']:
                    fingerprints[copy['path']] = module_digest(pin, copy['path'])
                    before = copy['markers'][name]['present']
                    if before != desired:
                        changes.append({'id': row['id'], 'path': copy['path'], 'marker': name,
                                        'before': before, 'after': desired,
                                        'directory_stat': copy['directory_stat'],
                                        'marker_state': copy['markers'][name]})
    plan = {'schema': SCHEMA, 'action': action, 'module_id': module_id, 'allowed': reason is None,
            'reason': reason, 'changes': changes, 'framework': state['framework'], 'access': state['access'],
            'module_fingerprints': fingerprints, 'inventory_binding': digest(state['_rows']),
            'scope': 'active and pending %s module markers; next Android boot' % FRAMEWORK_NAMES.get(state['framework']['id'], 'root'),
            'writes': 'userdata module markers and bounded rescue journal only',
            'warnings': LIMITATIONS + (['Android may execute uninstall.sh on the next boot.'] if action == 'remove' else [])}
    plan['plan_sha256'] = digest(plan)
    return {'plan': plan}


def preview(context, action, module_id=None):
    with context.operation_lock():
        return _preview(context, action, module_id)


def _journal_open(pin):
    with pin.directory('/adb') as adb:
        name = JOURNAL_DIR.rsplit('/', 1)[-1]
        try:
            os.mkdir(name, 0o700, dir_fd=adb)
            os.fsync(adb)
        except FileExistsError:
            pass
    with pin.directory(JOURNAL_DIR) as directory:
        st = os.fstat(directory)
        require(stat.S_IMODE(st.st_mode) == 0o700 and
                (pin.context.mode != 'device' or st.st_uid == 0),
                'MODULE_JOURNAL_UNSAFE', 'The rescue journal directory is not private and root-owned')
        require(len(os.listdir(directory)) < 128, 'MODULE_JOURNAL_FULL', 'Archive previous rescue journals before continuing')
        return os.dup(directory)


def _journal_write(directory, name, value):
    data = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
    require(len(data) <= 1 << 20, 'MODULE_JOURNAL_TOO_LARGE', 'The rescue journal exceeds its limit')
    temporary = '.tmp-' + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.rename(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=directory)


def _change_marker(pin, change, expected):
    with pin.directory(change['path']) as directory:
        require(stamp(os.fstat(directory)) == change['directory_stat'],
                'MODULE_CHANGED', 'The reviewed module directory was replaced or changed')
        before = marker(pin, directory, change['marker'])
        require(before['present'] == expected and before == change['marker_state'],
                'MODULE_CHANGED', 'The reviewed marker changed before the operation')
        label = None
        if change['after'] and pin.context.mode == 'device':
            try:
                label = os.getxattr(directory, 'security.selinux')
            except OSError:
                fs.fail('MODULE_LABEL_UNKNOWN', 'The module directory has no readable SELinux label')
            require(label.startswith(b'u:object_r:') and len(label) <= 256,
                    'MODULE_LABEL_UNKNOWN', 'The module directory has no known SELinux label')
        pin.recheck()
        if change['after']:
            fd = os.open(change['marker'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o644, dir_fd=directory)
            try:
                pin.check_fd(fd)
                if pin.context.mode == 'device':
                    os.fchown(fd, 0, 0)
                    os.setxattr(fd, 'security.selinux', label)
                os.fchmod(fd, 0o644)
                os.fsync(fd)
            finally:
                os.close(fd)
        else:
            require(stamp(os.stat(change['marker'], dir_fd=directory, follow_symlinks=False)) == before['stat'],
                    'MODULE_CHANGED', 'The reviewed marker was replaced before removal')
            os.unlink(change['marker'], dir_fd=directory)
        os.fsync(directory)
        pin.recheck()
        with pin.directory(change['path']) as named:
            require((os.fstat(named).st_dev, os.fstat(named).st_ino) ==
                    (os.fstat(directory).st_dev, os.fstat(directory).st_ino),
                    'MODULE_CHANGED', 'Module directory moved during mutation')
        require(marker(pin, directory, change['marker'])['present'] == change['after'],
                'MODULE_READBACK_FAILED', 'The module marker did not match the requested state')


def apply(context, action, module_id=None, expected_plan=None, confirmed=False):
    context.confirm(confirmed)
    fs.require_hash(expected_plan, 'expected-plan')
    with context.operation_lock():
        plan = _preview(context, action, module_id)['plan']
        require(plan['plan_sha256'] == expected_plan, 'MODULE_PLAN_CHANGED', 'Module state changed; review a fresh preview')
        require(plan['allowed'], 'MODULE_ACTION_UNSUPPORTED', plan['reason'] or 'Unsupported action')
        require(not plan['access']['read_only'] and plan['access']['write_supported'],
                'VOLUME_READ_ONLY', 'Mount Android data for writing through Files first')
        if not plan['changes']:
            return {'status': 'unchanged', 'changed': 0, 'plan_sha256': expected_plan}
        with fs.PinnedVolume(context, 'userdata', plan['access']['volume_token'], writing=True) as pin:
            journal_dir = _journal_open(pin)
            name = uuid.uuid4().hex + '.json'
            journal = {'schema': JOURNAL_SCHEMA, 'transaction': name[:-5], 'status': 'prepared',
                       'plan': plan, 'completed': [], 'outcome': 'marker persistence only; Android activation unverified'}
            try:
                _journal_write(journal_dir, name, journal)
                for change in plan['changes']:
                    journal['status'], journal['next'] = 'applying', change
                    _journal_write(journal_dir, name, journal)
                    _change_marker(pin, change, change['before'])
                    journal['completed'].append(change)
                    journal.pop('next', None)
                    _journal_write(journal_dir, name, journal)
                journal['status'] = 'applied'
                _journal_write(journal_dir, name, journal)
            except BaseException as exc:
                # A failed fsync can have persisted the last write. Never pretend
                # that a transaction is atomic or blindly replay/revert it.
                journal['status'] = 'partial-or-uncertain'
                journal['error'] = {'code': getattr(exc, 'code', 'IO_ERROR'), 'message': str(exc)}
                with contextlib.suppress(Exception):
                    _journal_write(journal_dir, name, journal)
                fs.fail('MODULE_TRANSACTION_INCOMPLETE', 'A module operation did not complete; inspect its journal and refresh before any retry',
                        journal=JOURNAL_DIR + '/' + name, completed=len(journal['completed']), cause=journal['error'])
            finally:
                os.close(journal_dir)
    return {'status': 'applied', 'changed': len(plan['changes']), 'plan_sha256': expected_plan,
            'journal': {'volume': 'userdata', 'path': JOURNAL_DIR + '/' + name, 'status': 'applied'},
            'activation': 'unverified until Android boots; no script was executed by recovery'}


def _journal_record(pin, directory, name, with_markers=False):
    """Read a journal as untrusted evidence; never execute, replay, or repair it.

    Marker verification means observed *at detail-read time*, not an enduring lock.
    A list row or unavailable/invalid detail never certifies current markers.
    """
    row = {'file': name, 'integrity': 'invalid', 'current_markers_verified': False}
    if not re.fullmatch(r'[0-9a-f]{32}\.json', name):
        row['reason'] = 'Unexpected entry in the rescue journal directory'
        return row
    try:
        raw = read_regular(pin, directory, name, 1 << 20)
        record = json.loads(raw['data'].decode('utf-8'))
        require(isinstance(record, dict) and record.get('schema') == JOURNAL_SCHEMA
                and record.get('transaction') == name[:-5],
                'MODULE_JOURNAL_INVALID', 'Journal identity or schema is invalid')
        plan = record.get('plan')
        require(isinstance(plan, dict) and plan.get('schema') == SCHEMA
                and plan.get('plan_sha256') ==
                digest({key: value for key, value in plan.items() if key != 'plan_sha256'}),
                'MODULE_JOURNAL_INVALID', 'Journal plan is not self-consistent')
        action, module_id = plan.get('action'), plan.get('module_id')
        require(action in ACTIONS and
                ((action == 'disable-all' and module_id is None) or
                 (action != 'disable-all' and isinstance(module_id, str) and MODULE_ID.fullmatch(module_id))),
                'MODULE_JOURNAL_INVALID', 'Journal action or module ID is invalid')
        changes, completed = plan.get('changes'), record.get('completed')
        require(isinstance(changes, list) and 0 < len(changes) <= MAX_MODULES * 2
                and isinstance(completed, list) and completed == changes[:len(completed)],
                'MODULE_JOURNAL_INVALID', 'Journal step sequence is invalid')
        required_marker, required_after = (
            ('disable', True) if action in ('disable', 'disable-all') else
            ('disable', False) if action == 'enable' else
            ('remove', action == 'remove'))
        seen = set()
        for change in changes:
            require(isinstance(change, dict), 'MODULE_JOURNAL_INVALID', 'Invalid journal change')
            ident, path = change.get('id'), change.get('path')
            require(isinstance(ident, str) and MODULE_ID.fullmatch(ident)
                    and (action == 'disable-all' or ident == module_id)
                    and path in ('/adb/modules/' + ident, '/adb/modules_update/' + ident)
                    and change.get('marker') == required_marker
                    and type(change.get('before')) is bool and type(change.get('after')) is bool
                    and change['before'] != change['after'] and change['after'] == required_after
                    and (path, required_marker) not in seen,
                    'MODULE_JOURNAL_INVALID', 'Unsafe or inconsistent journal target')
            seen.add((path, required_marker))
        status = record.get('status')
        pending = record.get('next')
        valid_step = (pending is None or
                      (len(completed) < len(changes) and pending == changes[len(completed)]))
        require(status in ('prepared', 'applying', 'applied', 'partial-or-uncertain')
                and valid_step
                and (status != 'prepared' or (not completed and pending is None))
                and (status != 'applying' or pending is not None or len(completed) > 0)
                and (status != 'applied' or (len(completed) == len(changes) and pending is None)),
                'MODULE_JOURNAL_INVALID', 'Journal status is inconsistent')
        row = {'file': name, 'transaction': name[:-5], 'integrity': 'self-consistent',
               'sha256': raw['sha256'], 'status': status, 'action': action,
               'module_id': module_id, 'planned_steps': len(changes),
               'recorded_completed_steps': len(completed),
               'requires_review': status != 'applied',
               'current_markers_verified': False,
               'warning': 'Self-consistency is not a signature; marker state is not Android boot success'}
        if with_markers:
            current = []
            for change in changes:
                item = {'id': change['id'], 'path': change['path'], 'marker': change['marker'],
                        'before': change['before'], 'desired': change['after']}
                try:
                    with pin.directory(change['path']) as folder:
                        observed = marker(pin, folder, change['marker'])['present']
                    item.update(observed=observed,
                                comparison='matches-desired' if observed == change['after'] else 'matches-before')
                except (fs.FilesystemError, OSError) as exc:
                    item.update(observed=None, comparison='unavailable', reason=str(exc))
                current.append(item)
            row['current_markers'] = current
            row['current_matches_desired'] = sum(item['comparison'] == 'matches-desired' for item in current)
            row['current_unavailable'] = sum(item['comparison'] == 'unavailable' for item in current)
            row['current_markers_verified'] = row['current_unavailable'] == 0
            row['requires_review'] = status != 'applied' or row['current_matches_desired'] != len(changes)
        return row
    except (fs.FilesystemError, OSError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
        row['reason'] = str(exc)
        return row


def journals(context, transaction=None):
    """Bounded read-only journal listing; details compare *current* markers only."""
    require(transaction is None or
            (isinstance(transaction, str) and re.fullmatch(r'[0-9a-f]{32}', transaction)),
            'MODULE_JOURNAL_ID_INVALID', 'Select a 32-character lowercase hexadecimal transaction ID')
    with context.operation_lock():
        volume = context.volume('userdata')
        acc = access(volume, context.mode)
        require(acc['mounted'] and acc['authenticated'], 'MODULE_AUTH_REQUIRED',
                'Unlock and mount Android user 0 through Files first')
        with fs.PinnedVolume(context, 'userdata', acc['volume_token']) as pin:
            if path_kind(pin, JOURNAL_DIR) is None:
                require(transaction is None, 'MODULE_JOURNAL_NOT_FOUND', 'Transaction journal was not found')
                return {'access': acc, 'journals': []}
            with pin.directory(JOURNAL_DIR) as directory:
                st = os.fstat(directory)
                require(stat.S_IMODE(st.st_mode) == 0o700 and
                        (context.mode != 'device' or st.st_uid == 0),
                        'MODULE_JOURNAL_UNSAFE', 'The journal directory is not private and root-owned')
                names = sorted(os.listdir(directory))
                require(len(names) <= 128, 'MODULE_JOURNAL_LIMIT', 'Too many journal entries')
                if transaction:
                    name = transaction + '.json'
                    require(name in names, 'MODULE_JOURNAL_NOT_FOUND', 'Transaction journal was not found')
                    result = {'access': acc, 'journal': _journal_record(pin, directory, name, True)}
                else:
                    result = {'access': acc, 'journals': [_journal_record(pin, directory, name) for name in names]}
                pin.recheck()
                return result


def backup(context, module_id, destination_volume, destination, confirmed=False, scope='active', progress=None):
    import file_archive
    context.confirm(confirmed)
    require(MODULE_ID.fullmatch(module_id or ''), 'MODULE_ID_INVALID', 'Select a valid module ID')
    require(scope in ('active', 'pending'), 'MODULE_SCOPE_INVALID', 'Choose active or pending module data')
    require(destination_volume != 'userdata', 'MODULE_BACKUP_DESTINATION', 'Select a separate mounted backup volume')
    with context.operation_lock():
        state = _inventory(context)
        require(state['access']['authenticated'], 'MODULE_AUTH_REQUIRED', 'Unlock Android data through Files first')
        tree = 'modules' if scope == 'active' else 'modules_update'
        row = next((r for r in state['_rows'] if r['id'] == module_id and r['tree'] == tree), None)
        require(row and row['valid'], 'MODULE_UNAVAILABLE', 'The selected module copy is not safely available')
        dest = context.volume(destination_volume)
        result = file_archive.pack(context, 'userdata', state['access']['volume_token'], '/adb/' + tree,
                                   False, [module_id], destination_volume, dest['volume_token'], destination,
                                   True, progress or (lambda *args: None))
        return {**result, 'module': row, 'framework': state['framework'], 'scope': scope,
                'restoration': 'Archive includes module files and marker state; Android activation is separate'}


# --- Installing a module ZIP (2026-11-21, the owner: a downloaded Magisk module is installed from its
# file page). As Magisk's own install_module does for a simple module: the files go to
# /data/adb/modules_update/<id> (0644, folders and anything in a bin folder 0755, root, system_file), the
# module's folder in /data/adb/modules gets an update marker and its module.prop for the app, and Magisk
# moves it in at the next start of Android. customize.sh is not run here; a module whose customize.sh
# unpacks the files itself (SKIPUNZIP=1) and the legacy install.sh ones are refused, as is any framework
# other than the reviewed Magisk releases. Each step is journaled like the marker changes.
MODULE_ZIP_FILES, MODULE_ZIP_BYTES = 20000, 512 << 20
NOT_INSTALLED = ('customize.sh', 'README.md')
SYSTEM_FILE = b'u:object_r:system_file:s0'
BOOT_CONTENT = ('post-fs-data.sh', 'service.sh', 'action.sh', 'uninstall.sh', 'system.prop', 'sepolicy.rule')


def zip_members(archive):
    """The files a module ZIP installs, after every name and kind in it was checked."""
    infos = archive.infolist()
    require(0 < len(infos) <= MODULE_ZIP_FILES, 'MODULE_ZIP_LIMIT', 'The ZIP has no files or too many')
    seen, files, total = set(), [], 0
    for info in infos:
        name = info.filename
        parts = name.rstrip('/').split('/')
        require(name and not name.startswith('/') and '\\' not in name and '\0' not in name
                and all(part not in ('', '.', '..') for part in parts) and len(name) <= 1024,
                'MODULE_ZIP_UNSAFE', 'The ZIP has an unsafe file name')
        require(name not in seen, 'MODULE_ZIP_UNSAFE', 'The ZIP names a file twice')
        seen.add(name)
        kind = (info.external_attr >> 16) & 0o170000
        require(kind in (0, stat.S_IFREG, stat.S_IFDIR), 'MODULE_ZIP_UNSAFE', 'The ZIP holds links or special files')
        if name.endswith('/') or parts[0] == 'META-INF' or name in NOT_INSTALLED:
            continue
        total += info.file_size
        files.append(info)
    require(total <= MODULE_ZIP_BYTES, 'MODULE_ZIP_LIMIT', 'The module is larger than 512 MiB')
    return seen, files, total


def inspect_zip(fd):
    """A module ZIP read without unpacking: module.prop at its top, what it installs, what is not run."""
    with zipfile.ZipFile(os.fdopen(os.dup(fd), 'rb')) as archive:
        seen, files, total = zip_members(archive)
        require('module.prop' in seen, 'NOT_A_MODULE', 'This ZIP has no module.prop at its top: it is not a root module')
        require(archive.getinfo('module.prop').file_size <= MAX_TEXT, 'MODULE_PROP_INVALID', 'module.prop is too large')
        data = archive.read('module.prop')
        found = re.search(rb'^id=([^\n]*)$', data, re.M)
        props = parse_prop(data, found.group(1).decode('utf-8', 'replace') if found else '')
        require('install.sh' not in seen, 'MODULE_LEGACY_INSTALLER',
                'This module uses the old install.sh (before Magisk 20.4): install it from the root app')
        not_run = []
        if 'customize.sh' in seen:
            script = archive.read('customize.sh') if archive.getinfo('customize.sh').file_size <= 1 << 20 else b'SKIPUNZIP=1'
            require(not re.search(rb'^\s*SKIPUNZIP=1', script, re.M), 'MODULE_CUSTOM_INSTALL',
                    'Its customize.sh unpacks the module itself: install it from the root app')
            not_run.append('customize.sh')
        return {'id': props['id'], 'name': props['name'][:200], 'version': props['version'][:100],
                'version_code': int(props['versionCode']), 'author': props.get('author', '')[:200],
                'description': props.get('description', '')[:500], 'files': len(files), 'bytes': total,
                'not_run': not_run, 'boot_content': [n for n in BOOT_CONTENT if n in seen],
                'metamodule': props.get('metamodule', '').strip().lower() in ('1', 'true'),
                'system_files': any(n.startswith('system/') and not n.endswith('/') for n in seen)}


@contextlib.contextmanager
def source_zip(context, volume, token, path):
    relative = fs.clean_path(path)
    with fs.PinnedVolume(context, volume, token) as pin:
        with pin.parent(relative) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                st = os.fstat(fd)
                require(stat.S_ISREG(st.st_mode) and st.st_size <= 2 << 30, 'MODULE_ZIP_INVALID', 'Choose a module ZIP file')
                pin.check_fd(fd)
                yield fd, st
            finally:
                os.close(fd)


def _install_preview(context, volume, token, path):
    fs.require_hash(token, 'source-volume-token')
    state = _inventory(context)
    with source_zip(context, volume, token, path) as (fd, st):
        sha = hashlib.sha256()
        while chunk := os.read(fd, 1 << 20):
            sha.update(chunk)
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            module = inspect_zip(fd)
        except zipfile.BadZipFile:
            fs.fail('MODULE_ZIP_INVALID', 'This file is not a readable ZIP')
    existing = next((r for r in state['modules'] if r['id'] == module['id']), None)
    reason = None
    if not state['access']['mounted'] or not state['access']['authenticated']:
        reason = 'Mount Android data (user 0) through Files first'
    elif state['access']['read_only'] or not state['access']['write_supported']:
        reason = 'Mount Android data for writing through Files first'
    elif state['framework']['id'] == 'apatch':
        reason = 'APatch keeps its modules its own way: install this ZIP from its app'
    elif state['framework']['status'] != 'supported':
        reason = state['framework']['reason'] or 'No reviewed Magisk or KernelSU Next is installed on this Android'
    elif state['framework']['id'] == 'kernelsu' and module['metamodule']:
        reason = 'A metamodule needs the KernelSU Next manager: install this ZIP from it'
    elif state['framework']['id'] == 'kernelsu' and any(r.get('metamodule') for m in state['modules'] for r in m['copies']):
        # ksud lets an installed metamodule install the others (metainstall.sh) or blocks installs while
        # it is disabled or changing; neither runs here.
        reason = 'A metamodule is installed: install this ZIP from the KernelSU Next manager'
    plan = {'schema': SCHEMA, 'action': 'install', 'module_id': module['id'], 'allowed': reason is None,
            'reason': reason, 'changes': [], 'framework': state['framework'], 'access': state['access'],
            'source': {'volume': volume, 'volume_token': token, 'path': fs.clean_path(path), 'sha256': sha.hexdigest(),
                       'stat': stamp(st)},
            'module': module, 'installed': ({'version': existing.get('version'), 'version_code': existing.get('version_code')}
                                            if existing else None),
            'inventory_binding': digest(state['_rows']),
            'scope': '/data/adb/modules_update/' + module['id'] + ' and its folder in /data/adb/modules; next Android boot',
            'writes': 'the module files, its update marker and module.prop, and a bounded rescue journal',
            'warnings': LIMITATIONS + (['customize.sh is not run here; a module that needs it may not work.'] if module['not_run'] else [])}
    # KernelSU Next 3 (and APatch 11282) mount a module's system/ files only through a metamodule; without
    # one ksud runs its scripts and nothing else (live 2026-11-22: post-fs-data and service ran, the file
    # under system/etc did not appear).
    if state['framework']['id'] == 'kernelsu' and module['system_files'] and not module['metamodule'] and \
            not any(r.get('metamodule') for m in state['modules'] for r in m['copies']):
        plan['mount_needs_metamodule'] = True
        plan['warnings'] = plan['warnings'] + ['KernelSU Next mounts system/ files only through a metamodule; none is installed.']
    plan['plan_sha256'] = digest(plan)
    return {'plan': plan}


def install_preview(context, volume, token, path):
    with context.operation_lock():
        return _install_preview(context, volume, token, path)


def _label(pin, fd, label):
    if pin.context.mode == 'device':
        os.fchown(fd, 0, 0)
        os.setxattr(fd, 'security.selinux', label)


def _mkdir(pin, parent, name, label):
    try:
        os.mkdir(name, 0o755, dir_fd=parent)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    pin.check_fd(fd)
    os.fchmod(fd, 0o755)
    _label(pin, fd, label)
    return fd


def _write(pin, parent, name, source, mode, label):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        while chunk := source.read(1 << 20):
            view = memoryview(chunk)
            while view:
                view = view[os.write(fd, view):]
        os.fchmod(fd, mode)
        _label(pin, fd, label)
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_tree(directory, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    except FileNotFoundError:
        return
    try:
        for entry in os.listdir(fd):
            if stat.S_ISDIR(os.stat(entry, dir_fd=fd, follow_symlinks=False).st_mode):
                _remove_tree(fd, entry)
            else:
                os.unlink(entry, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=directory)


def _unpack(pin, archive, files, stage):
    for info in files:
        parts = info.filename.split('/')
        folder = os.dup(stage)
        try:
            for part in parts[:-1]:
                nxt = _mkdir(pin, folder, part, SYSTEM_FILE)
                os.close(folder)
                folder = nxt
            runs = any(part in ('bin', 'xbin') for part in parts[:-1]) or (len(parts) == 1 and parts[0].endswith('.sh'))
            with archive.open(info) as source:
                _write(pin, folder, parts[-1], source, 0o755 if runs else 0o644, SYSTEM_FILE)
            os.fsync(folder)
        finally:
            os.close(folder)


def install(context, volume, token, path, expected_plan=None, confirmed=False):
    context.confirm(confirmed)
    fs.require_hash(expected_plan, 'expected-plan')
    with context.operation_lock():
        plan = _install_preview(context, volume, token, path)['plan']
        require(plan['plan_sha256'] == expected_plan, 'MODULE_PLAN_CHANGED', 'The module or Android changed; review it again')
        require(plan['allowed'], 'MODULE_ACTION_UNSUPPORTED', plan['reason'] or 'This module cannot be installed here')
        ident = plan['module_id']
        with source_zip(context, volume, token, path) as (fd, st):
            require(stamp(st) == plan['source']['stat'], 'MODULE_PLAN_CHANGED', 'The ZIP changed after its review')
            with zipfile.ZipFile(os.fdopen(os.dup(fd), 'rb')) as archive, \
                    fs.PinnedVolume(context, 'userdata', plan['access']['volume_token'], writing=True) as pin:
                _, files, _ = zip_members(archive)
                journal_dir = _journal_open(pin)
                name = uuid.uuid4().hex + '.json'
                stage, previous = name[:-5] + '.stage', name[:-5] + '.previous'
                journal = {'schema': JOURNAL_SCHEMA, 'transaction': name[:-5], 'status': 'prepared', 'plan': plan,
                           'completed': [], 'outcome': 'module staged for the next Android boot; activation unverified'}
                moved = placed = False
                try:
                    _journal_write(journal_dir, name, journal)
                    with pin.directory('/adb') as adb:
                        parent_label = os.getxattr(adb, 'security.selinux') if pin.context.mode == 'device' else b''
                        os.close(_mkdir(pin, adb, 'modules_update', parent_label))
                        os.close(_mkdir(pin, adb, 'modules', parent_label))
                    staged = _mkdir(pin, journal_dir, stage, SYSTEM_FILE)
                    try:
                        _unpack(pin, archive, files, staged)
                        os.fsync(staged)
                    finally:
                        os.close(staged)
                    journal['completed'].append('unpacked')
                    _journal_write(journal_dir, name, journal)
                    with pin.directory('/adb/modules_update') as updates:
                        try:
                            os.rename(ident, previous, src_dir_fd=updates, dst_dir_fd=journal_dir)
                            moved = True
                            journal['completed'].append('previous pending update kept in the journal')
                        except FileNotFoundError:
                            pass
                        os.rename(stage, ident, src_dir_fd=journal_dir, dst_dir_fd=updates)
                        placed = True
                        os.fsync(updates)
                        os.fsync(journal_dir)
                    journal['completed'].append('modules_update/' + ident)
                    _journal_write(journal_dir, name, journal)
                    with pin.directory('/adb/modules') as modules:
                        folder = _mkdir(pin, modules, ident, SYSTEM_FILE)
                        try:
                            for marker_name in ('disable', 'remove', 'update', 'module.prop'):
                                with contextlib.suppress(FileNotFoundError):
                                    os.unlink(marker_name, dir_fd=folder)
                            _write(pin, folder, 'update', io_empty(), 0o644, SYSTEM_FILE)
                            with archive.open('module.prop') as prop:
                                _write(pin, folder, 'module.prop', prop, 0o644, SYSTEM_FILE)
                            os.fsync(folder)
                        finally:
                            os.close(folder)
                        os.fsync(modules)
                    journal['completed'].append('modules/' + ident + ': update marker and module.prop')
                    journal['status'] = 'applied'
                    _journal_write(journal_dir, name, journal)
                except BaseException as exc:
                    journal['status'] = 'partial-or-uncertain'
                    journal['error'] = {'code': getattr(exc, 'code', 'IO_ERROR'), 'message': str(exc)}
                    with contextlib.suppress(Exception):
                        if not placed:
                            _remove_tree(journal_dir, stage)
                            if moved:
                                with pin.directory('/adb/modules_update') as updates:
                                    os.rename(previous, ident, src_dir_fd=journal_dir, dst_dir_fd=updates)
                                journal['completed'].append('previous pending update put back')
                    with contextlib.suppress(Exception):
                        _journal_write(journal_dir, name, journal)
                    fs.fail('MODULE_TRANSACTION_INCOMPLETE', 'The module was not installed completely; inspect its journal',
                            journal=JOURNAL_DIR + '/' + name, completed=len(journal['completed']), cause=journal['error'])
                finally:
                    os.close(journal_dir)
    return {'status': 'applied', 'module_id': ident, 'plan_sha256': expected_plan,
            'journal': {'volume': 'userdata', 'path': JOURNAL_DIR + '/' + name, 'status': 'applied'},
            'activation': '%s moves the module in at the next start of Android; customize.sh was not run'
                          % FRAMEWORK_NAMES.get(plan['framework']['id'], 'Root')}


def io_empty():
    import io
    return io.BytesIO(b'')


def parser():
    p = fs.Parser(description=__doc__)
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--device', action='store_true')
    modes.add_argument('--fixture')
    commands = p.add_subparsers(dest='operation', required=True, parser_class=fs.Parser)
    commands.add_parser('inventory')
    for operation in ('preview', 'apply'):
        sub = commands.add_parser(operation)
        sub.add_argument('--action', choices=ACTIONS, required=True)
        sub.add_argument('--module-id')
        if operation == 'apply':
            sub.add_argument('--expected-plan', required=True)
            sub.add_argument('--confirm', action='store_true')
    for operation in ('install-preview', 'install'):
        sub = commands.add_parser(operation)
        sub.add_argument('--source-volume', required=True)
        sub.add_argument('--source-token', required=True)
        sub.add_argument('--source-path', required=True)
        if operation == 'install':
            sub.add_argument('--expected-plan', required=True)
            sub.add_argument('--confirm', action='store_true')
    sub = commands.add_parser('journals')
    sub.add_argument('--transaction', help='32-character journal ID; show current marker state')
    sub = commands.add_parser('backup')
    sub.add_argument('--module-id', required=True)
    sub.add_argument('--scope', choices=('active', 'pending'), default='active')
    sub.add_argument('--destination-volume', required=True)
    sub.add_argument('--destination', required=True)
    sub.add_argument('--confirm', action='store_true')
    return p


def main(argv=None):
    operation = 'unknown'
    try:
        args = parser().parse_args(argv)
        operation = args.operation
        context = fs.FixtureContext(args.fixture) if args.fixture else fs.DeviceContext()
        if operation == 'inventory':
            result = inventory(context)
        elif operation == 'preview':
            result = preview(context, args.action, args.module_id)
        elif operation == 'apply':
            result = apply(context, args.action, args.module_id, args.expected_plan, args.confirm)
        elif operation == 'install-preview':
            result = install_preview(context, args.source_volume, args.source_token, args.source_path)
        elif operation == 'install':
            result = install(context, args.source_volume, args.source_token, args.source_path, args.expected_plan, args.confirm)
        elif operation == 'journals':
            result = journals(context, args.transaction)
        else:
            result = backup(context, args.module_id, args.destination_volume, args.destination, args.confirm, args.scope)
        print(json.dumps({'ok': True, 'operation': operation, 'mode': context.mode, **result}, ensure_ascii=True, separators=(',', ':')))
        return 0
    except fs.FilesystemError as exc:
        error = {'code': exc.code, 'message': exc.message, 'details': exc.details}
    except (OSError, ValueError, lzma.LZMAError, zlib.error) as exc:
        error = {'code': 'MODULE_INSPECTION_FAILED', 'message': str(exc), 'details': {}}
    print(json.dumps({'ok': False, 'operation': operation, 'error': error}, ensure_ascii=True, separators=(',', ':')))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
