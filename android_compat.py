#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Read-only Android preserve preflight. It never mounts, authenticates or writes.

P0 inspects a pinned raw/sparse/xz/gzip image or a declarative ZIP of .img files,
and optional already-extracted public runtime snapshots. Snapshot facts are
evidence, not a claim that a running device or image contains those files.
A matching pair of framework JARs is not a transition qualification.
"""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile
import xml.etree.ElementTree as ET

import android_profiles
import android_rom
import android_transitions
import filesystem as fs
import flash
import install

SCHEMA = 'a22x.android-compat.v1'
SNAPSHOT_SCHEMA = 'a22x.android-public-snapshot.v1'
MAX_IMAGE = 16 << 30
MAX_PACKAGE = 32 << 30
MAX_METADATA = 1 << 20
MAX_ENTRIES = 4096
AUTO_ROLLBACK_LIMIT = 64 << 20
LOGICAL = ('system', 'system_ext', 'product', 'vendor', 'odm',
           'vendor_dlkm', 'odm_dlkm', 'system_dlkm')
PHYSICAL = ('boot', 'dtbo', 'vbmeta', 'vbmeta_system', 'vbmeta_vendor')
PROTECTED = ('userdata', 'metadata', 'cache', 'misc', 'efs', 'nvram',
             'nvdata', 'nvcfg', 'protect1', 'protect2', 'persist', 'seccfg',
             'preloader', 'lk', 'lk2', 'tee', 'tee2', 'tzar', 'recovery',
             'frp', 'keydata', 'keyrefuge', 'modem', 'md1img', 'super')
FIXED_FIRST_PAIR = ('boot', 'dtbo', 'vbmeta', 'vbmeta_system',
                    'vbmeta_vendor', 'vendor', 'odm', 'vendor_dlkm', 'odm_dlkm')
PROP_KEYS = frozenset((
    'ro.build.id', 'ro.build.fingerprint', 'ro.system.build.fingerprint', 'ro.build.version.incremental',
    'ro.build.version.release', 'ro.build.version.sdk',
    'ro.build.version.security_patch', 'ro.vendor.build.security_patch',
    'ro.vendor.build.version.security_patch',
    'ro.bootimage.build.version.security_patch', 'ro.product.first_api_level',
    'ro.crdroid.build.version', 'ro.crdroid.display.version', 'ro.crdroid.device',
    'ro.vendor.api_level', 'ro.board.first_api_level', 'ro.product.device',
    'ro.product.system.device', 'ro.product.model', 'ro.product.cpu.abi',
    'ro.product.cpu.abilist', 'ro.product.cpu.abilist64',
))
PROP_PATHS = ('build.prop', 'system/build.prop', 'system/system/build.prop',
              'vendor/build.prop', 'product/build.prop', 'system_ext/build.prop')
JAR_PAIRS = (('system/framework/services.jar', 'system/framework/framework.jar'),
             ('system/system/framework/services.jar', 'system/system/framework/framework.jar'),
             ('framework/services.jar', 'framework/framework.jar'))
FSTAB_PATHS = ('fstab.mt6833', 'vendor/etc/fstab.mt6833',
               'vendor/etc/fstab.mt6853', 'vendor/etc/fstab.samsung',
               'vendor/etc/fstab.a22x')
VINTF_PATHS = ('vendor/etc/vintf/manifest.xml',
               'system/etc/vintf/compatibility_matrix.xml',
               'system/etc/vintf/manifest.xml')
METADATA_PATH = 'META-INF/com/android/metadata'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, code, message, **details):
    install.require(condition, code, message, **details)


def stamp(fd):
    st = os.fstat(fd)
    return [st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns]


def sha_fd(fd, maximum=MAX_PACKAGE):
    before = stamp(fd)
    require(stat.S_ISREG(before[2]) and before[3] == 1,
            'IMAGE_REGULAR_ONLY', 'Use one regular file without hardlink aliases')
    require(0 < before[4] <= maximum, 'SOURCE_SIZE_LIMIT',
            'The file is empty or exceeds the analyzer size bound')
    h, offset = hashlib.sha256(), 0
    while offset < before[4]:
        block = os.pread(fd, min(1 << 20, before[4] - offset), offset)
        require(block, 'SOURCE_CHANGED', 'The source ended while being read')
        h.update(block)
        offset += len(block)
    require(stamp(fd) == before, 'SOURCE_CHANGED', 'The source changed while being read')
    return {'sha256': h.hexdigest(), 'size': offset, 'identity': digest(before)}


def clean_relative(name):
    require(isinstance(name, str) and name and len(name) <= 1024
            and not name.startswith('/') and '\\' not in name and '\x00' not in name
            and all(p not in ('', '.', '..') for p in name.split('/')),
            'UNSAFE_PACKAGE_PATH', 'Package and snapshot paths must stay relative')
    return name


@contextlib.contextmanager
def regular_at(root, relative):
    """Open each component without following symlinks; never open a device node."""
    clean_relative(relative)
    base = fs.absolute_no_symlinks(root)
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parts = relative.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        handle = os.open(parts[-1], os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            st = os.fstat(handle)
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
                    'SNAPSHOT_REGULAR_ONLY', 'Snapshot artifacts must be single regular files',
                    path=relative)
            data_fd = os.open('/proc/self/fd/' + str(handle), os.O_RDONLY | os.O_CLOEXEC)
        finally:
            os.close(handle)
        try:
            yield data_fd
        finally:
            os.close(data_fd)
    finally:
        os.close(fd)


def _properties(data):
    require(len(data) <= MAX_METADATA, 'METADATA_TOO_LARGE', 'Metadata exceeds its bounded size')
    values = {}
    for line in data.decode('utf-8', 'strict').splitlines():
        if not line or line.lstrip().startswith('#'):
            continue
        key, sep, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if sep and (key in PROP_KEYS or key in (
                'pre-device', 'post-build', 'post-sdk-level', 'post-security-patch-level',
                'post-timestamp', 'ota-type', 'ota-wipe', 'ota-downgrade', 'pre-build', 'pre-build-incremental')):
            require(len(value) <= 4096, 'METADATA_VALUE_TOO_LARGE', 'Metadata value is too large')
            require(key not in values or values[key] == value, 'AMBIGUOUS_METADATA',
                    'The same metadata key has different values', key=key)
            values[key] = value
    return values


def _merge_props(values, more):
    for key, value in more.items():
        require(key not in values or values[key] == value, 'AMBIGUOUS_METADATA',
                'Public runtime files disagree on the same property', key=key)
        values[key] = value


def _fstab(data):
    """Only explicit on-disk options. Missing defaults remain unknown."""
    entries = []
    for line in data.decode('utf-8', 'strict').splitlines():
        fields = line.partition('#')[0].split()
        if len(fields) < 5 or fields[1] != '/data':
            continue
        flags = {}
        for flag in fields[4].split(','):
            key, sep, value = flag.partition('=')
            require(key not in flags, 'AMBIGUOUS_FSTAB', 'Duplicate /data fstab flag', key=key)
            flags[key] = value if sep else True
        entries.append({'filesystem': fields[2],
                        'mount_options': sorted(fields[3].split(',')),
                        'fileencryption': flags.get('fileencryption'),
                        'metadata_encryption': flags.get('metadata_encryption'),
                        'keydirectory': flags.get('keydirectory'),
                        'wrappedkey': flags.get('wrappedkey'),
                        'fs_mgr_flags': flags})
    return entries


def rom_identity(root):
    """Read Android OS and crDroid versions from public system/product property files."""
    keys = ('ro.build.version.sdk', 'ro.build.version.release', 'ro.build.version.security_patch',
            'ro.system.build.fingerprint', 'ro.crdroid.build.version', 'ro.crdroid.display.version')
    props = {}
    for path in ('system/build.prop', 'build.prop', 'system/product/etc/build.prop',
                 'product/etc/build.prop', 'system/product/build.prop'):
        try:
            with regular_at(root, path) as fd:
                before = stamp(fd)
                values = _properties(os.pread(fd, MAX_METADATA + 1, 0))
                require(before == stamp(fd), 'SOURCE_CHANGED', 'Android properties changed during inspection')
                _merge_props(props, {k: values[k] for k in keys if k in values})
        except (FileNotFoundError, NotADirectoryError):
            continue
    return props


def crypto_interfaces(data):
    if b'\0' in data or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('Unsupported VINTF XML')
    root = ET.fromstring(data.decode('utf-8-sig'))
    values = []
    for hal in root.findall('hal'):
        name = hal.findtext('name', '')
        if name not in ('android.hardware.security.keymint', 'android.hardware.keymaster',
                        'android.hardware.gatekeeper', 'android.hardware.weaver',
                        'android.system.keystore2', 'android.hardware.security.sharedsecret',
                        'android.hardware.security.secureclock'):
            continue
        values.append({'name': name, 'format': hal.get('format', 'hidl'),
                       'versions': [v.text for v in hal.findall('version') if v.text],
                       'instances': [v.text for v in hal.findall('fqname') if v.text],
                       'declaration': root.tag})
    return values


def _profile(artifacts):
    pairs = []
    for a, b in JAR_PAIRS:
        ah, bh = artifacts.get(a), artifacts.get(b)
        if ah or bh:
            pairs.append((ah and ah['sha256'], bh and bh['sha256']))
    if len(pairs) != 1 or None in pairs[0]:
        return {'profile_id': None, 'reason': 'Missing or ambiguous framework JAR pair'}
    matches = [ident for ident, expected in android_profiles.FRAMEWORK_PINS.items()
               if tuple(expected) == pairs[0]]
    return {'profile_id': matches[0] if len(matches) == 1 else None,
            'services_sha256': pairs[0][0], 'framework_sha256': pairs[0][1],
            'reason': 'Exact known public JAR pair' if len(matches) == 1
                      else 'This exact JAR pair has no qualified decrypt profile'}


def collect_current(root):
    """Hash public files in an already-extracted snapshot; does not mount anything.

    The same routine can collect a target snapshot for offline comparison. It
    deliberately does not read credentials, app databases or hardware key blobs.
    A detached snapshot cannot assert live data, mount or TEE state.
    """
    artifacts, props, fstabs, images = {}, {}, [], {}
    interfaces = {}
    for path in PROP_PATHS + tuple(p for pair in JAR_PAIRS for p in pair) + FSTAB_PATHS + VINTF_PATHS:
        try:
            with regular_at(root, path) as fd:
                value = sha_fd(fd, MAX_IMAGE if path.endswith('.jar') else MAX_METADATA)
                artifacts[path] = value
                if path in PROP_PATHS:
                    _merge_props(props, _properties(os.pread(fd, MAX_METADATA, 0)))
                elif path in FSTAB_PATHS:
                    fstabs.extend(_fstab(os.pread(fd, MAX_METADATA, 0)))
                elif path in VINTF_PATHS:
                    try:
                        interfaces[path] = crypto_interfaces(os.pread(fd, MAX_METADATA, 0))
                    except (ValueError, ET.ParseError):
                        interfaces[path] = None
                require(digest(stamp(fd)) == value['identity'],
                        'SOURCE_CHANGED', 'Snapshot artifact changed while parsing')
        except FileNotFoundError:
            continue
    for label in LOGICAL + PHYSICAL:
        path = 'images/' + label + '.img'
        try:
            with regular_at(root, path) as fd:
                images[label] = sha_fd(fd, MAX_IMAGE)
                artifacts[path] = images[label]
        except FileNotFoundError:
            continue
    result = {'schema': SNAPSHOT_SCHEMA, 'available': bool(artifacts),
              'provenance': 'detached-public-files', 'live_binding_verified': False,
              'snapshot_root': str(fs.absolute_no_symlinks(root)),
              'properties': props, 'fstab': fstabs, 'images': images,
              'crypto_interfaces': interfaces, 'android_rom': rom_identity(root),
              'artifacts': artifacts, 'decrypt_profile': _profile(artifacts), 'build': _build(props)}
    result['snapshot_sha256'] = digest(result)
    return result



def _refresh_snapshot(snapshot):
    require(isinstance(snapshot, dict) and snapshot.get('schema') == SNAPSHOT_SCHEMA
            and isinstance(snapshot.get('snapshot_root'), str)
            and isinstance(snapshot.get('snapshot_sha256'), str),
            'INVALID_SNAPSHOT', 'Use a snapshot collected from public files')
    expected = snapshot['snapshot_sha256']
    require(digest({k: v for k, v in snapshot.items() if k != 'snapshot_sha256'}) == expected,
            'SNAPSHOT_CHANGED', 'The snapshot manifest was edited')
    fresh = collect_current(snapshot['snapshot_root'])
    require(fresh['snapshot_sha256'] == expected, 'SNAPSHOT_CHANGED',
            'Current public snapshot files changed after collection')
    return fresh


def _date(value):
    try:
        return datetime.date.fromisoformat(value) if isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}', value) else None
    except ValueError:
        return None


def _image(fd, compression):
    image_format = flash.layout(fd, compression, MAX_IMAGE)
    reader = flash.open_reader(fd, compression, MAX_IMAGE)
    value, count, prefix = hashlib.sha256(), 0, bytearray()
    try:
        for block in install.decode_image(reader, image_format, MAX_IMAGE):
            # The existing decoder emits target padding after setting payload_bytes.
            # Hash only image bytes; the writer's final zero tail is not an image.
            if reader.payload_bytes is not None:
                break
            count += len(block)
            value.update(block)
            if len(prefix) < 4096:
                prefix.extend(block[:4096 - len(prefix)])
        require(count and reader.payload_bytes == count, 'INVALID_IMAGE',
                'The complete decoded image could not be measured')
    finally:
        flash.close_reader(reader)
    filesystem = ('ext4' if prefix[1080:1082] == b'\x53\xef' else
                  'f2fs' if prefix[1024:1028] == b'\x10\x20\xf5\xf2' else
                  'erofs' if prefix[1024:1028] == b'\xe2\xe1\xf5\xe0' else None)
    return {'image_sha256': value.hexdigest(), 'image_bytes': count,
            'image_format': image_format, 'filesystem': filesystem,
            'header_kind': ('boot' if prefix[:8] == b'ANDROID!' else
                            'vbmeta' if prefix[:4] == b'AVB0' else
                            'dtbo' if prefix[:4] == b'\xd7\xb7\xab\x1e' else
                            'filesystem' if filesystem else 'unknown')}


def _single_image_partition(label):
    """Keep declared partitions before recognizing a distribution-named GSI.

    A slot-suffixed partition is still an explicit target, even when this
    non-A/B device cannot admit it. Unknown names must reach classify() intact.
    """
    label = label.lower()
    base = label[:-2] if label.endswith(('_a', '_b')) else label
    if base in LOGICAL + PHYSICAL + PROTECTED or android_rom.REFUSED.fullmatch(base):
        return label
    if re.fullmatch(r'(?:system|aosp|lineage|gsi)(?:[-_.+][a-z0-9_.+-]+)?', label):
        return 'system'
    if re.fullmatch(r'crdroid-[0-9]+(?:\.[0-9]+)+-gsi[_-]treble[_-][a-z0-9_.+-]+', label):
        return 'system'
    return label


def _package(fd, name):
    before = stamp(fd)
    package = sha_fd(fd)
    props, images, artifacts, fstabs = {}, [], {}, []
    warnings, unsupported = [], None
    head = os.pread(fd, 8, 0)
    if head[:4] == b'PK\x03\x04':
        kind = 'image-zip'
        with flash.shared_offset(fd) as handle, zipfile.ZipFile(handle) as archive:
            infos = archive.infolist()
            require(len(infos) <= MAX_ENTRIES, 'PACKAGE_ENTRY_LIMIT', 'The ZIP has too many entries')
            names = {}
            total = 0
            for info in infos:
                path = info.filename.rstrip('/') if info.is_dir() else info.filename
                clean_relative(path)
                require(info.filename not in names, 'DUPLICATE_ZIP_MEMBER',
                        'The ZIP contains duplicate member names', member=info.filename)
                require(not stat.S_ISLNK(info.external_attr >> 16),
                        'ZIP_SYMLINK', 'Symlink entries are not admitted')
                require(not info.flag_bits & 1 and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                        'UNSUPPORTED_ZIP_COMPRESSION', 'Use an unencrypted stored/deflated ZIP')
                total += info.file_size
                require(0 <= info.file_size <= MAX_IMAGE and total <= MAX_PACKAGE,
                        'PACKAGE_EXPANSION_LIMIT', 'ZIP expansion exceeds the analyzer bound')
                names[info.filename] = info
            if 'payload.bin' in names:
                unsupported = 'Payload OTAs require a separately qualified native plan'
            elif any(n.endswith('.transfer.list') for n in names):
                unsupported = 'Block OTAs require a separately qualified native plan'
            for path in (METADATA_PATH,) + PROP_PATHS + FSTAB_PATHS + tuple(p for pair in JAR_PAIRS for p in pair):
                if path not in names:
                    continue
                limit = (64 << 20) if path.endswith('.jar') else MAX_METADATA
                require(names[path].file_size <= limit, 'METADATA_TOO_LARGE',
                        'Public package metadata exceeds its size bound', member=path)
                data = archive.read(path)
                artifacts[path] = {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
                if path in PROP_PATHS or path == METADATA_PATH:
                    _merge_props(props, _properties(data))
                elif path in FSTAB_PATHS:
                    fstabs.extend(_fstab(data))
            members = []
            for path, info in names.items():
                if info.is_dir() or not path.lower().endswith('.img'):
                    continue
                match = android_rom.IMAGE_NAME.fullmatch(path)
                require(match is not None, 'INVALID_IMAGE_NAME', 'An image member has an invalid name')
                label = match.group(1)
                members.append((label, path))
            if len(members) == 1:
                members[0] = (_single_image_partition(members[0][0]), members[0][1])
            require(len(members) <= 32, 'PACKAGE_IMAGE_LIMIT', 'The ZIP contains too many images')
            require(len({label for label, _ in members}) == len(members),
                    'DUPLICATE_PARTITION', 'Two image members target the same partition')
            if 'META-INF/com/google/android/update-binary' in names:
                warnings.append('The package installer is ignored; only declarative images are inspected')
        for label, member in sorted(members):
            images.append({'partition': label, 'member': member, 'compression': 'zip:' + member,
                           **_image(fd, 'zip:' + member)})
    else:
        kind = 'image'
        if os.pread(fd, 5, 257) == b'ustar':
            kind, compression = 'tar', 'unsupported-tar'
        elif head[:6] == b'7z\xbc\xaf\x27\x1c':
            kind, compression = '7z', 'unsupported-7z'
        else:
            compression = flash.container(fd)
        if compression not in ('none', 'gzip', 'xz'):
            unsupported = 'Only raw, sparse, gzip and xz standalone images are admitted in P0'
        else:
            image = _image(fd, compression)
            base = name.lower()
            for suffix in ('.xz', '.gz', '.img'):
                if base.endswith(suffix):
                    base = base[:-len(suffix)]
            label = _single_image_partition(base)
            images.append({'partition': label, 'member': None, 'compression': compression, **image})
    require(stamp(fd) == before, 'SOURCE_CHANGED', 'The package changed during analysis')
    return {'package': package, 'format': kind, 'properties': props,
            'images': images, 'artifacts': artifacts, 'fstab': fstabs,
            'decrypt_profile': _profile(artifacts), 'warnings': warnings,
            'unsupported_reason': unsupported,
            'runtime_files_bound_to_images': False}


def _build(props):
    # OTA post-* repeats these global properties, not vendor or boot levels.
    # Check presence so an explicit empty value cannot hide a conflicting alias.
    for primary, alias in (
            ('ro.build.version.sdk', 'post-sdk-level'),
            ('ro.build.version.security_patch', 'post-security-patch-level')):
        require(primary not in props or alias not in props or props[primary] == props[alias],
                'AMBIGUOUS_METADATA',
                'Build properties and OTA metadata disagree on the same field',
                keys=[primary, alias])
    return {'fingerprint': props.get('ro.system.build.fingerprint') or props.get('ro.build.fingerprint')
            or props.get('post-build'),
            'id': props.get('ro.build.id'), 'release': props.get('ro.build.version.release'),
            'sdk': props.get('ro.build.version.sdk') or props.get('post-sdk-level'),
            'security_patch': props.get('ro.build.version.security_patch')
            or props.get('post-security-patch-level'),
            'vendor_security_patch': props.get('ro.vendor.build.version.security_patch') or props.get('ro.vendor.build.security_patch'),
            'boot_security_patch': props.get('ro.bootimage.build.version.security_patch'),
            'abi': props.get('ro.product.cpu.abi'), 'abi64': props.get('ro.product.cpu.abilist64'),
            'device': props.get('ro.product.device') or props.get('ro.product.system.device')
            or props.get('pre-device')}


def collect_geometry(context):
    """Existing read-only GPT/LP readers; no mappings or mounts are created."""
    result = flash.targets(context)
    result['targets'] = sorted(result['targets'], key=lambda row: row['label'])
    for row in result['targets']:
        if not row.get('logical'):
            try:
                row['identity'] = context.target(row['label'])
            except (OSError, fs.FilesystemError):
                row['identity'] = None
    try:
        with flash.list_super(context) as super_image:
            result['super_identity'] = context.target('super')
            result['logical_metadata'] = json.loads(json.dumps(super_image.metadata, default=lambda value: {'bytes_sha256': hashlib.sha256(value).hexdigest(), 'size': len(value)}))
    except (OSError, fs.FilesystemError, flash.lp.MetadataError):
        result['logical_metadata'] = None
    result['geometry_sha256'] = digest(result)
    return result


def probe_super(context):
    """Fingerprint live super without closing any logical mappings."""
    with context.fs.operation_lock():
        geometry = collect_geometry(context)
        target = context.target('super')
        require(target == geometry.get('super_identity'), 'GEOMETRY_CHANGED', 'Cannot bind the current super geometry')
        size = target['size_bytes']
        require(0 < size <= MAX_IMAGE, 'SOURCE_SIZE_LIMIT', 'The super partition exceeds the analyzer bound')
        with flash.list_super(context) as disk:
            before = stamp(disk.fd)
            counters = None
            if context.mode == 'device':
                stats = Path('/sys/dev/block') / target['device'] / 'stat'

                def writes():
                    numbers = stats.read_text().split()
                    return numbers[4:7] + numbers[11:14]

                counters = writes()
            value = hashlib.sha256()
            at = 0
            while at < size:
                block = os.pread(disk.fd, min(1 << 20, size - at), at)
                require(block, 'SOURCE_CHANGED', 'The current super partition ended while being read')
                value.update(block)
                at += len(block)
            context.check_target(disk.fd, target)
            require(stamp(disk.fd) == before and (counters is None or writes() == counters),
                    'SOURCE_CHANGED', 'The current super partition changed while being read')
        require(context.target('super') == target, 'GEOMETRY_CHANGED', 'The super partition was replaced')
        return {'geometry': geometry, 'observed_super': {
            'target': target, 'size': size, 'sha256': value.hexdigest(), 'boot_id': context.boot_id,
        }, 'context_identity': {'mode': context.mode, 'boot_id': context.boot_id, 'device': context.device}}


def verify_super_copy(root, observed, geometry, context_identity):
    if root is None:
        return None
    try:
        with regular_at(root, 'super.img') as fd:
            copy = sha_fd(fd, MAX_IMAGE)
    except FileNotFoundError:
        return None
    result = {'status': 'unbound', 'copy': copy}
    if observed is not None:
        fs.require_hash(observed.get('sha256'), 'observed super SHA-256')
        identity = geometry.get('super_identity')
        require(observed.get('boot_id') == context_identity.get('boot_id')
                and isinstance(identity, dict) and canonical(observed.get('target')) == canonical(identity)
                and observed.get('size') == identity.get('size_bytes'),
                'GEOMETRY_CHANGED', 'The super fingerprint belongs to a different recovery boot or layout')
        result.update(observed=observed, status='matches_live' if
                      (copy['sha256'], copy['size']) == (observed['sha256'], observed['size']) else 'mismatch')
    return result


def _checks(source, target, geometry, rollback_root, super_copy=None):
    checks = []
    def check(ident, status, reason):
        checks.append({'id': ident, 'status': status, 'reason': reason})
    check('READ_ONLY_ANALYZER', 'supported', 'No mounts, authentication, format, flash or module scripts are invoked')
    check('PACKAGE_FORMAT', 'unknown' if target['unsupported_reason'] else
          'supported' if target['images'] else 'incompatible',
          target['unsupported_reason'] or ('Complete native image streams inspected' if target['images']
                                         else 'The package contains no declarative images'))
    write_set = []
    for image in target['images']:
        part = image['partition']
        where, why = android_rom.classify(part, LOGICAL)
        label = 'super/' + part if where == 'logical' else part
        row = {**image, 'target': label, 'source_sha256': target['package']['sha256']}
        write_set.append(row)
        if where == 'refused' or part in PROTECTED:
            check('PROTECTED_TARGET:' + part, 'incompatible', why or 'The partition is protected')
        elif (part in LOGICAL and not image['filesystem']) or (
                part == 'boot' and image['header_kind'] != 'boot') or (
                part.startswith('vbmeta') and image['header_kind'] != 'vbmeta') or (
                part == 'dtbo' and image['header_kind'] != 'dtbo'):
            check('IMAGE_KIND:' + part, 'incompatible', 'Image content does not match its target type')
        else:
            check('IMAGE_KIND:' + part, 'supported', 'Image header is consistent with its declared target')
    source_build = _build(source.get('properties', {}))
    target_build = _build(target['properties'])
    target['build'] = target_build
    for flag in ('ota-wipe', 'ota-downgrade'):
        value = target['properties'].get(flag)
        if value is not None:
            normalized = value.lower()
            check(flag.upper().replace('-', '_'),
                  'incompatible' if normalized in ('yes', 'true', '1') else
                  'supported' if normalized in ('no', 'false', '0') else 'unknown',
                  'Package declares ' + flag + '=' + value)
    for key, current_key in (('pre-build', 'ro.build.fingerprint'),
                             ('pre-build-incremental', 'ro.build.version.incremental')):
        required = target['properties'].get(key)
        if required:
            observed = source.get('properties', {}).get(current_key)
            check(key.upper().replace('-', '_'),
                  'unknown' if not observed else
                  'supported' if observed in required.split('|') else 'incompatible',
                  'Package source requirement ' + key + ' must match the current build')
    check('CURRENT_STATE', 'unknown', 'Detached public files do not prove the current boot, data epoch, credentials or TEE state')
    device = target_build.get('device')
    if device:
        devices = re.split(r'[|,\s]+', device)
        generic_system = (devices in (['generic'], ['generic_arm64'])
                          and not target['properties'].get('pre-device')
                          and len(write_set) == 1 and write_set[0]['target'] == 'super/system'
                          and write_set[0]['header_kind'] == 'filesystem')
        if generic_system:
            check('TARGET_DEVICE', 'unknown', 'A generic system image needs vendor and kernel compatibility checks')
        else:
            check('TARGET_DEVICE', 'supported' if any(d in android_rom.DEVICE_NAMES for d in devices) else 'incompatible',
                  'Package device identity: ' + device)
    else:
        check('TARGET_DEVICE', 'unknown', 'The image does not establish its intended device')
    target_abi = target_build.get('abi')
    target_abi64 = target_build.get('abi64')
    if target_abi:
        check('TARGET_ABI', 'supported' if target_abi == 'arm64-v8a' else 'incompatible',
              'The A22x native image profile requires arm64-v8a; package declares ' + target_abi)
    elif target_abi64:
        check('TARGET_ABI', 'supported' if 'arm64-v8a' in target_abi64.split(',') else 'incompatible',
              'Declared 64-bit ABIs: ' + target_abi64)
    else:
        check('TARGET_ABI', 'unknown', 'The package does not establish its Android ABI')
    check('SYSTEM_SET', 'unknown', 'The image set is inventoried; cross-partition build coherence needs an exact transition profile')
    for side, snapshot in (('SOURCE', source), ('TARGET', target)):
        profile = snapshot.get('decrypt_profile', {})
        check(side + '_PROFILE', 'unknown', (
            'Known JAR pair ' + profile['profile_id'] + '; snapshot/image and current epoch binding remain unqualified'
            if profile.get('profile_id') else 'The exact framework JAR pair has no verified recovery profile'))
    current_sdk, target_sdk = source_build.get('sdk'), target_build.get('sdk')
    if current_sdk and target_sdk and current_sdk.isdigit() and target_sdk.isdigit():
        check('ANDROID_DOWNGRADE', 'incompatible' if int(target_sdk) < int(current_sdk) else 'supported',
              'Android SDK comparison: ' + current_sdk + ' -> ' + target_sdk)
    else:
        check('ANDROID_DOWNGRADE', 'unknown', 'Current or target Android SDK is not established')
    for key in ('security_patch', 'vendor_security_patch', 'boot_security_patch'):
        old, new = source_build.get(key), target_build.get(key)
        if _date(old) is not None and _date(new) is not None:
            check(key.upper(), 'incompatible' if new < old else 'supported',
                  key + ': ' + old + ' -> ' + new)
        else:
            check(key.upper(), 'unknown', 'Both current and target patch levels are required')
    sf, tf = source.get('fstab', []), target.get('fstab', [])
    if len(sf) == len(tf) == 1:
        for key in ('filesystem', 'fileencryption', 'metadata_encryption', 'keydirectory', 'wrappedkey'):
            old, new = sf[0].get(key), tf[0].get(key)
            if old is not None and new is not None and old != new:
                check('FSTAB_' + key.upper(), 'incompatible',
                      'Explicit /data on-disk option changed: ' + key)
            elif old is None or new is None:
                check('FSTAB_' + key.upper(), 'unknown',
                      'Effective defaults and first API level must be established for ' + key)
            else:
                check('FSTAB_' + key.upper(), 'supported', 'Explicit option matches: ' + key)
    else:
        check('FSTAB', 'unknown', 'One effective /data fstab entry is required for each build')
    geometry_rows = {row['label']: row for row in geometry.get('targets', [])}
    for write in write_set:
        row = geometry_rows.get(write['target'])
        if row is None:
            check('GEOMETRY:' + write['target'], 'unknown', 'Target geometry and logical extents are unavailable')
        elif write['image_bytes'] > row['size_bytes']:
            # First pair does not resize LP; a separate allocator qualification is needed.
            check('GEOMETRY:' + write['target'], 'incompatible',
                  'The image exceeds the existing partition; preserve does not authorize resizing')
        else:
            check('GEOMETRY:' + write['target'], 'supported', 'Image fits the observed partition size')
        part = write['partition']
        if part in FIXED_FIRST_PAIR:
            old = source.get('images', {}).get(part)
            check('FIXED_RUNTIME:' + part, 'unknown' if not old else
                  'supported' if old['sha256'] == write['image_sha256'] else 'incompatible',
                  'The first transition requires unchanged ' + part + ' bytes')
    for ident, reason in (
        ('VINTF_KERNEL', 'A matching SDK or VINTF file hash is not a VINTF/kernel compatibility result'),
        ('TEE_VERSION_BINDING', 'Gatekeeper, KeyMint, secure firmware, namespace and AVB state are not yet bound'),
        ('APP_DATA_MIGRATION', 'Package signing identities, UID/schema migrations and app keys are not qualified'),
        ('MODULE_COMPATIBILITY', 'Root framework, installed and pending module compatibility require the module adapter'),
        ('SESSION_ADMISSION', 'The writer must separately recheck the operation lock and close conflicting sessions'),
    ):
        check(ident, 'unknown', reason)
    copies = []
    for write in write_set:
        part, old = write['partition'], source.get('images', {}).get(write['partition'])
        row = geometry_rows.get(write['target'], {})
        required = row.get('size_bytes')
        entry = {'target': write['target'], 'status': 'unknown', 'required_bytes': required,
                 'automatic_copy_limit_exceeded': (required or (old or {}).get('size', write['image_bytes'])) > AUTO_ROLLBACK_LIMIT}
        if super_copy and row.get('logical') is True and write['target'].startswith(flash.LOGICAL_PREFIX):
            if super_copy['status'] in ('matches_live', 'mismatch'):
                entry.update(status=super_copy['status'], via='super.img', copy=super_copy['copy'])
        if rollback_root is not None and entry['status'] == 'unknown':
            try:
                with regular_at(rollback_root, part + '.img') as fd:
                    copy = sha_fd(fd, MAX_IMAGE)
                entry['copy'] = copy
                if old and copy['sha256'] == old['sha256'] and copy['size'] == old['size']:
                    entry['status'] = 'matches_snapshot'
                else:
                    entry['status'] = 'mismatch' if old else 'unknown'
            except FileNotFoundError:
                pass
        copies.append(entry)
        status = entry['status']
        if status == 'matches_live':
            check('ROLLBACK:' + write['target'], 'supported', 'The full super backup matches the current block device, including its geometry')
        elif status == 'mismatch':
            check('ROLLBACK:' + write['target'], 'incompatible', 'The rollback copy differs from the source image')
        else:
            check('ROLLBACK:' + write['target'], 'unknown',
                  'Full rollback copy must match the fresh current partition, including its whole size')
    check('QUALIFIED_TRANSITION', 'unknown', 'No concrete source-to-target build pair has completed hardware qualification')
    complete = bool(copies) and all(entry['status'] == 'matches_live' for entry in copies)
    rollback = {'before_first_boot': 'complete' if complete else 'unknown', 'after_first_boot': 'not_guaranteed',
                'auto_limit_bytes': AUTO_ROLLBACK_LIMIT, 'copies': copies}
    if super_copy is not None:
        rollback['super_copy'] = super_copy
    return checks, write_set, rollback


def analyze_fd(fd, name, *, current=None, geometry=None, rollback=None, context_identity=None,
               target_snapshot=None, observed_super=None):
    source = _refresh_snapshot(current) if current is not None else {
        'schema': SNAPSHOT_SCHEMA, 'available': False, 'properties': {},
        'images': {}, 'fstab': [], 'decrypt_profile': {'profile_id': None}, 'build': _build({})}
    geometry = json.loads(json.dumps(geometry or {}))
    target = _package(fd, name)
    if target_snapshot is not None:
        snapshot = _refresh_snapshot(target_snapshot)
        _merge_props(target['properties'], snapshot.get('properties', {}))
        if snapshot.get('fstab'):
            require(not target['fstab'] or target['fstab'] == snapshot['fstab'],
                    'AMBIGUOUS_FSTAB', 'Package and detached snapshot fstab disagree')
            target['fstab'] = snapshot['fstab']
        if snapshot.get('decrypt_profile', {}).get('profile_id'):
            target['decrypt_profile'] = snapshot['decrypt_profile']
        target['detached_snapshot'] = snapshot
    super_copy = verify_super_copy(rollback, observed_super, geometry, context_identity or {})
    checks, writes, coverage = _checks(source, target, geometry, rollback, super_copy)
    status = 'incompatible' if any(c['status'] == 'incompatible' for c in checks) else 'unknown'
    result = {'schema': SCHEMA, 'status': status, 'preserve_allowed': False,
              'source': source, 'target': target, 'write_set': sorted(writes, key=lambda w: w['target']),
              'protected_set': list(PROTECTED), 'geometry': geometry, 'rollback': coverage,
              'context': context_identity or {}, 'checks': checks,
              'qualification': {'catalog_entries': len(android_transitions.QUALIFIED_TRANSITIONS),
                                'matched': False, 'hardware_qualified': False},
              'limitations': [
                  'P0 reports evidence only and cannot authorize writes.',
                  'Public sidecar files are not proof of image contents or the current data epoch.',
                  'Returning old images after the first target boot does not roll back TEE or application migrations.',
              ]}
    result['manifest_sha256'] = digest(result)
    return result


def inspect(context, volume, token, path, *, current=None, rollback=None):
    relative = '/' + fs.clean_path(path).lstrip('/')
    source_volume = context.fs.volume(volume, token)
    with flash.source_file(context, volume, token, relative) as fd:
        before = stamp(fd)
        probe = probe_super(context) if rollback is not None and (Path(rollback) / 'super.img').is_file() else None
        geometry = probe['geometry'] if probe is not None else collect_geometry(context)
        result = analyze_fd(fd, relative.rsplit('/', 1)[-1], current=current, geometry=geometry,
                            rollback=rollback, observed_super=probe['observed_super'] if probe is not None else None,
                            context_identity={
                                'mode': context.mode, 'device': context.device,
                                'boot_id': context.boot_id, 'volume': volume,
                                'volume_token': token, 'path': relative})
        require(stamp(fd) == before, 'SOURCE_CHANGED', 'The image changed during preflight')
        fresh_geometry = collect_geometry(context)
        require(fresh_geometry['geometry_sha256'] == geometry['geometry_sha256'],
                'GEOMETRY_CHANGED', 'Partition geometry changed during preflight')
        fresh_volume = context.fs.volume(volume, token)
        require(all(fresh_volume.get(k) == source_volume.get(k) for k in
                    ('volume_token', 'mount_id', 'mountpoint', 'mount_owner', 'mounted')),
                'SOURCE_VOLUME_CHANGED', 'The source mount changed during preflight')
    return result


def revalidate(context, volume, token, path, expected_manifest_sha256, *, current=None, rollback=None):
    fs.require_hash(expected_manifest_sha256, 'expected_manifest_sha256')
    current_plan = inspect(context, volume, token, path, current=current, rollback=rollback)
    require(current_plan['manifest_sha256'] == expected_manifest_sha256,
            'PLAN_CHANGED', 'Android preflight evidence changed; review the current report')
    return current_plan


def analyze_file(path, *, current_root=None, target_root=None, rollback_root=None, probe=None):
    path = fs.absolute_no_symlinks(path)
    with regular_at(path.parent, path.name) as fd:
        current = collect_current(current_root) if current_root is not None else None
        target_snapshot = collect_current(target_root) if target_root is not None else None
        probe = probe or {}
        return analyze_fd(fd, path.name, current=current, rollback=rollback_root, target_snapshot=target_snapshot,
                          context_identity=probe.get('context_identity'), geometry=probe.get('geometry'),
                          observed_super=probe.get('observed_super'))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--device', action='store_true')
    mode.add_argument('--fixture')
    sub = parser.add_subparsers(dest='action', required=True)
    inspect_args = sub.add_parser('inspect')
    inspect_args.add_argument('--volume', required=True)
    inspect_args.add_argument('--volume-token', required=True)
    inspect_args.add_argument('--path', required=True)
    inspect_args.add_argument('--rollback-root', type=Path)
    sub.add_parser('probe-super')
    files = sub.add_parser('analyze-files')
    files.add_argument('--target', required=True)
    files.add_argument('--current-root')
    files.add_argument('--target-root')
    files.add_argument('--rollback-root')
    args = parser.parse_args(argv)
    try:
        if args.action == 'analyze-files':
            value = analyze_file(args.target, current_root=args.current_root,
                                 target_root=args.target_root, rollback_root=args.rollback_root)
        else:
            require(args.device or args.fixture, 'MODE_REQUIRED', 'Choose device or fixture mode')
            context = install.DeviceContext() if args.device else install.FixtureContext(args.fixture)
            if args.action == 'probe-super':
                value = probe_super(context)
            else:
                value = inspect(context, args.volume, args.volume_token, args.path, rollback=args.rollback_root)
        print(json.dumps({'ok': True, **value}, sort_keys=True, ensure_ascii=True, separators=(',', ':')))
        return 0
    except fs.FilesystemError as error:
        print(json.dumps({'ok': False, 'error': {'code': error.code, 'message': str(error),
                                               'details': error.details}}, ensure_ascii=True))
        return 2
    except (OSError, ValueError, UnicodeError, zipfile.BadZipFile) as error:
        print(json.dumps({'ok': False, 'error': {'code': 'ANALYZER_INPUT_ERROR',
                                               'message': str(error)[:300], 'details': {}}}, ensure_ascii=True))
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
