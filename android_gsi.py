#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""A GSI (Android's generic system image) installed by this recovery (2026-11-10).

A GSI replaces only Android's system: it starts with Samsung's BOOT and vendor, so stock Android
(samsung_firmware.py) comes first. From a GSI ZIP as Google ships it (system.img, vbmeta.img,
build.prop), or one system image (raw, sparse, xz):

  super/system   system.img, decoded straight from the ZIP; system grows when it is larger
  vbmeta         the GSI's vbmeta.img: verification disabled (flags 2), as Google flashes it;
                 an image without one needs vbmeta's verification to be off already
  userdata       formatted for Android, metadata erased, cache wiped (the recovery's folder stays):
                 a GSI never starts on the data of another system

Keeping the data (--keep-data, 2026-11-21): an update of the system already there to a build it
was qualified with on the phone (android_transitions): super/system is written, and userdata,
metadata, cache, BOOT (and its root), vendor and the rest of super stay. The way back is checked
first: the earlier system's own image (--rollback-image-*: the file it was installed from, decoded
and compared with what super/system holds, then flashed back from Files), or a copy of BOOT, the
vbmetas and super made on a card or USB drive and verified (--rollback-volume, identity_backup,
kind android; Restore puts it back). Its bounds: data the new system has changed after its first
start (an app's database it upgraded) does not go back with it. --qualification-run allows
a pair not yet qualified, from the command line only: how a pair is qualified.

The review uses the plan format of samsung_firmware.py, so the same page shows both.

    android_gsi.py --device|--fixture DIR inspect --volume V --volume-token T --path GSI
    android_gsi.py ... install --volume V --volume-token T --path GSI --expected-plan SHA --confirm
    android_gsi.py ... classify --volume V --volume-token T --path FILE

classify (2026-11-11) says what a file chosen as "a ROM" on a card is, so that the page opens the
review that installs it: a ZIP with its own installer, Samsung's firmware, or a system image.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import struct
import sys
import time
import zipfile

import bootimage
import filesystem as fs
import flash
import install
from install import require
import android_transitions
from operation_lock import lease
import samsung_firmware as sf
import saved_boot
import sevenzip

KEEP_DATA_PARTITIONS = ('boot', 'vbmeta', 'vbmeta_system', 'vbmeta_vendor')
ROLLBACK_LABELS = ','.join((*KEEP_DATA_PARTITIONS, 'super'))

# The vendor interface levels (FCM) each Android supports; this phone's vendor is level 5
# (distro.VENDOR_FCM_LEVEL). Android 16 dropped level 5.
SUPPORTED_LEVELS = {33: (4, 5, 6, 7), 34: (5, 6, 7, 8), 35: (5, 6, 7, 8, 202404), 36: (6, 7, 8, 202404, 202504),
                    37: (7, 8, 202404, 202504)}
VENDOR_FCM_LEVEL = 5
AVB_VERIFICATION_DISABLED = 2
PROPS = ('ro.build.version.release', 'ro.build.version.sdk', 'ro.build.id', 'ro.build.version.security_patch',
         'ro.system.build.fingerprint', 'ro.product.system.name')

# SDK metadata independently read from the exact crDroid 12.12 XZ archives and retained
# LineageOS 20 vendor. Pin the content, not a name, size, or future version of the catalog.
# These values describe the reviewed inputs. android_transitions still admits the pair.
VERIFIED_PACKAGE_VERSIONS = {
    'b0797c0c93b7fbfbae4cec0e7440fd6f0527abbbc891cc57ac186445d5ef5871': (36, '16'),
    '1afddd51b6f457f02046cdd0e15abd7d5bd5480a789ac3fb0aa05da040ecf076': (36, '16'),
}
VERIFIED_SYSTEM_SDKS = {
    '5595851f2f6a1f341000d085276bbe28ca584f25ab04236270ece828c27005d0': 36,
    '79a6a0d8c1a092534682558594e55045fc37752a9c114d87325564dfd7b8f2cb': 36,
}
VERIFIED_VENDOR_VERSIONS = {
    '99a3e0ffe51745a0a5003fd4db6f1bf30e8e233bc16e183123f4219933d706bd': (31, 31),
}


def gsi_source(context, volume, token, path):
    """What the file holds: system.img and vbmeta.img inside a ZIP, or one system image."""
    with flash.source_file(context, volume, token, path) as fd:
        st = os.fstat(fd)
        identity = flash.identity(fd)
        props, members = {}, {}
        if os.pread(fd, 4, 0) == b'PK\x03\x04':
            with flash.shared_offset(fd) as handle, zipfile.ZipFile(handle) as archive:
                infos = {i.filename: i for i in archive.infolist() if not i.is_dir()}
                images = [n for n in infos if n.lower().endswith('.img')]
                system = next((n for n in images if n.rsplit('/', 1)[-1].lower() == 'system.img'), None)
                if system is None and len([n for n in images if 'vbmeta' not in n.lower()]) == 1:
                    system = next(n for n in images if 'vbmeta' not in n.lower())
                require(system, 'NOT_A_GSI', 'The ZIP holds no system image')
                members['system'] = (system, infos[system].file_size)
                vbmeta = next((n for n in images if n.rsplit('/', 1)[-1].lower() == 'vbmeta.img'), None)
                if vbmeta:
                    members['vbmeta'] = (vbmeta, infos[vbmeta].file_size)
                prop = next((n for n in infos if n.rsplit('/', 1)[-1] == 'build.prop' and infos[n].file_size < (1 << 20)), None)
                if prop:
                    for line in archive.read(prop).decode('utf-8', 'replace').splitlines():
                        key, sep, value = line.partition('=')
                        if sep and key.strip() in PROPS:
                            props[key.strip()] = value.strip()[:120]
        elif os.pread(fd, 6, 0) == sevenzip.SIGNATURE:
            # LineageOS's GSIs (2026-11-10): one system image inside a .7z.
            try:
                files, _ = sevenzip.entries(fd)
                system = sevenzip.choose(files)
            except sevenzip.SevenZipError as error:
                fs.fail(error.code, str(error))
            members['system'] = (system['name'], system['size'])
        else:
            compression = flash.container(fd)
            members['system'] = (None, st.st_size if compression == 'none' else (xz_size(fd) if compression == 'xz' else
                                                                            (gz_size(fd) if compression == 'gzip' else 0)))
        require(flash.identity(fd) == identity, 'IMAGE_CHANGED', 'The image file changed while it was reviewed')
        return {'identity': identity, 'size': st.st_size, 'members': members, 'props': props}


INSTALLER = 'meta-inf/com/google/android/update-binary'
FIRMWARE_PARTS = ('ap_', 'bl_', 'cp_', 'csc_', 'home_csc_')


def image_prefix(fd, compression, limit=4096):
    """The first bytes of an image as they would go on a partition."""
    largest = 8 << 30
    image_format = flash.layout(fd, compression, largest)
    reader = flash.open_reader(fd, compression, largest)
    prefix = bytearray()
    try:
        for data in install.decode_image(reader, image_format, largest):
            prefix.extend(data)
            if len(prefix) >= limit:
                break
    finally:
        flash.close_reader(reader)
    return bytes(prefix[:limit])


def classify(context, volume, token, path):
    """What the chosen file is, by its content:
    installer  a ZIP with its own update-binary (a custom ROM, Magisk, a kernel): the ZIP page runs it
    samsung    Samsung's firmware: an AP tar, or a ZIP of the AP, BL, CP and CSC files
    gsi        a system image, plain, sparse or compressed, or a ZIP or 7z that holds one
    payload    an OTA for update_engine (payload.bin): made for phones with A/B slots
    unknown    nothing this recovery installs"""
    relative = '/' + fs.clean_path(path).lstrip('/')
    name = relative.rsplit('/', 1)[-1]
    with flash.source_file(context, volume, token, relative) as fd:
        size, head, kind = os.fstat(fd).st_size, os.pread(fd, 8, 0), 'unknown'
        if head[:4] == b'PK\x03\x04':
            try:
                with flash.shared_offset(fd) as handle, zipfile.ZipFile(handle) as archive:
                    names = [i.filename.lower() for i in archive.infolist()[:8192] if not i.is_dir()]
            except (zipfile.BadZipFile, OSError, ValueError):
                names = []
            leaves = [n.rsplit('/', 1)[-1] for n in names]
            if INSTALLER in names:
                kind = 'installer'
            elif any(leaf.startswith(FIRMWARE_PARTS) and '.tar' in leaf for leaf in leaves):
                kind = 'samsung'
            elif 'payload.bin' in leaves:
                kind = 'payload'
            elif any(leaf.endswith('.img') and 'vbmeta' not in leaf for leaf in leaves):
                kind = 'gsi'
        elif head[:6] == sevenzip.SIGNATURE:
            kind = 'gsi'
        elif os.pread(fd, 5, 257) == b'ustar':
            kind = 'samsung'
        else:
            try:
                if flash.image_kind(image_prefix(fd, flash.container(fd))) != 'Raw image':
                    kind = 'gsi'
            except (OSError, ValueError, EOFError, fs.FilesystemError):
                kind = 'unknown'
        return {'kind': kind, 'name': name, 'size': size, 'volume': volume, 'path': relative}


def gz_size(fd):
    """The unpacked size a .gz file states in its last four bytes (LineageOS's .img.gz, 2026-11-11):
    right for one stream below 4 GiB, which a system image is; 0 when the file is too short."""
    try:
        end = os.fstat(fd).st_size
        tail = os.pread(fd, 4, end - 4) if end > 18 else b''
        return struct.unpack('<I', tail)[0] if len(tail) == 4 else 0
    except (OSError, struct.error):
        return 0


def xz_size(fd):
    """The unpacked size of a one-stream .xz file (crDroid's .img.xz) from its index, or 0 when it
    cannot be read that way: then the size is known only once the image is decoded."""
    def varint(data, at):
        value, shift = 0, 0
        while True:
            byte = data[at]
            at += 1
            value |= (byte & 0x7f) << shift
            if not byte & 0x80:
                return value, at
            shift += 7
            if shift > 63:
                raise ValueError('varint')
    try:
        end = os.fstat(fd).st_size
        while end >= 4 and os.pread(fd, 4, end - 4) == bytes(4):  # stream padding
            end -= 4
        footer = os.pread(fd, 12, end - 12)
        if len(footer) != 12 or footer[10:12] != b'YZ':
            return 0
        index_size = (struct.unpack('<I', footer[4:8])[0] + 1) * 4
        index = os.pread(fd, index_size, end - 12 - index_size)
        if len(index) != index_size or index[0] != 0:
            return 0
        records, at = varint(index, 1)
        total, blocks = 0, 0
        for _ in range(records):
            unpadded, at = varint(index, at)
            unpacked, at = varint(index, at)
            total += unpacked
            blocks += (unpadded + 3) // 4 * 4
        # One stream: its header, the blocks and the index fill the file exactly.
        return total if end - 12 - index_size - blocks - 12 == 0 else 0
    except (OSError, ValueError, IndexError, struct.error):
        return 0


# An empty vbmeta with verification disabled, as avbtool make_vbmeta_image --flags 2 makes it:
# GSIs without their own vbmeta.img (LineageOS, crDroid) need verification off to start.
VBMETA_DIR = 'a22x-recovery/vbmeta'
VBMETA_NAME = 'vbmeta-disabled.img'


def disabled_vbmeta():
    header = bytearray(256)
    header[:4] = b'AVB0'
    struct.pack_into('>IIQQIQQQQQQQQQQQII', header, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, AVB_VERIFICATION_DISABLED, 0)
    header[128:128 + 13] = b'avbtool 1.3.0'
    return bytes(header) + bytes(4096 - 256)


def current_boot(context):
    """'android' for Samsung's Android BOOT of this phone, 'linux' for a mainline one, else None."""
    target = context.target('boot')
    fd = context.open_target(target)
    try:
        data = os.pread(fd, target['size_bytes'], 0)
    finally:
        os.close(fd)
    try:
        info = bootimage.inspect_boot(data)
    except bootimage.ImageError:
        return None, ''
    release = info['kernel'].get('release') or ''
    if not info['device'].get('this_phone'):
        return None, release
    return ('linux' if info.get('mainline') else 'android'), release


def vbmeta_flags(context):
    target = context.target('vbmeta')
    fd = context.open_target(target)
    try:
        head = os.pread(fd, 256, 0)
    finally:
        os.close(fd)
    return struct.unpack_from('>I', head, 120)[0] if head[:4] == b'AVB0' else None


KERNEL_FLOOR_SDK, KERNEL_FLOOR = 35, (4, 19)
# One literal on one line: the interface's list of texts is gathered from the sources line by line.
OLD_KERNEL_WARNING = "This is Android 15 or newer. Google's own builds need kernel 4.19 and restart for ever on this phone's Android kernel 4.14; ROMs made for older phones (Treble GSIs) start."


def kernel_older(release, floor):
    """Whether a kernel release ("4.14.186-27218697") is older than FLOOR; one that is not known
    counts as older: this phone's Android kernel is 4.14 whatever the firmware."""
    match = re.match(r'(\d+)\.(\d+)', release or '')
    return not match or (int(match.group(1)), int(match.group(2))) < floor


def quiet(*unused):
    pass


def system_digest(context, progress=quiet):
    """The SHA-256 of what super/system holds now."""
    with flash.list_super(context) as found:
        size, digest, done = found.size_of(found.partition('system')), hashlib.sha256(), 0
        for data in found.chunks('system'):
            digest.update(data)
            done += len(data)
            progress('Reading the system on the phone', {'label': 'super/system', 'size_bytes': size}, done)
        return digest.hexdigest()


def file_digest(context, volume, token, path, progress=quiet, expected_identity=None):
    with flash.source_file(context, volume, token, path) as fd:
        identity = flash.identity(fd)
        require(expected_identity is None or identity == expected_identity, 'IMAGE_CHANGED',
                'The image file changed while it was reviewed')
        facts = flash.source_digest(fd, Path(path).name, progress)
        require(flash.identity(fd) == identity, 'IMAGE_CHANGED', 'The image file changed while it was reviewed')
        return facts


def image_matches_system(context, volume, path, progress=None):
    """Whether the image file at VOLUME:PATH, decoded and padded with zeros to the size of super/system,
    is exactly what super/system holds: then it is the way back to this system."""
    token = context.fs.volume(volume)['volume_token']
    with flash.list_super(context) as found:
        size, held = found.size_of(found.partition('system')), found.read_partition('system')
    with flash.source_file(context, volume, token, path) as fd:
        compression = flash.container(fd)
        image_format = flash.layout(fd, compression, size)
        reader = flash.open_reader(fd, compression, size)
        digest, count = hashlib.sha256(), 0
        try:
            for data in install.decode_image(reader, image_format, size):
                if reader.payload_bytes is not None:
                    break
                digest.update(data)
                count += len(data)
                if progress:
                    progress('Checking the way back', {'label': 'super/system', 'size_bytes': size}, count)
        finally:
            flash.close_reader(reader)
    if not count or count > size:
        return False
    left = size - count
    while left:
        digest.update(bytes(min(left, 1 << 20)))
        left -= min(left, 1 << 20)
    return digest.hexdigest() == held


IMAGE_FOLDERS = ('.a22x-images', 'A22xImages')


def find_package(context, size, sha256, progress=quiet):
    """(volume, path) of a saved rollback image of SIZE bytes and SHA256 on a card or USB drive,
    in the folders the catalog's downloads go to, or None."""
    for volume in context.fs.volumes():
        if not volume.get('mounted') or not fs.backup_partition(volume['id']):
            continue
        for folder in IMAGE_FOLDERS:
            place = Path(volume['mountpoint']) / folder
            try:
                names = sorted(os.listdir(place))
            except OSError:
                continue
            for name in names:
                try:
                    if os.stat(place / name, follow_symlinks=False).st_size != size:
                        continue
                    if file_digest(context, volume['id'], volume['volume_token'], '/' + folder + '/' + name, progress)[0] == sha256:
                        return volume['id'], '/' + folder + '/' + name
                except (OSError, fs.FilesystemError):
                    continue
    return None


def way_back(context, pair, progress=quiet):
    """The way back an update of PAIR takes without being told: the earlier system's own image when
    it is saved, else a partitions copy on the first card or USB drive that is mounted for writing."""
    if pair and pair.get('source_package_bytes'):
        found = find_package(context, pair['source_package_bytes'], pair['source_package_sha256'], progress)
        if found:
            return found, None
    card = next((v['id'] for v in context.fs.volumes() if fs.backup_partition(v['id']) and v.get('mounted')
                 and not v.get('read_only') and v.get('write_supported')), None)
    return None, card


def platform_facts(context, progress=quiet):
    """The qualification facts and exact partition hashes for a keep-data review.

    Pair qualification compares the platform facts. The plan also pins BOOT and the complete
    vbmeta chain so changes with the same kernel, root and verification flags require a new review.
    """
    facts = dict.fromkeys(android_transitions.PLATFORM_KEYS)
    partition_sha256 = {'boot': None}
    try:
        target = context.target('boot')
        data = install.target_bytes(context, target)
        partition_sha256['boot'] = hashlib.sha256(data).hexdigest()
        facts['kernel'] = (bootimage.inspect_boot(data)['kernel'].get('release') or None)
        facts['root'] = saved_boot.describe_boot(data).get('root') or ''
    except (OSError, ValueError, KeyError, bootimage.ImageError, fs.FilesystemError):
        pass
    for label in KEEP_DATA_PARTITIONS[1:]:
        try:
            partition_sha256[label] = install.target_hash(context, context.target(label))
        except (OSError, ValueError, KeyError, fs.FilesystemError) as error:
            if (context.mode == 'fixture' and label != 'vbmeta'
                    and getattr(error, 'code', None) == 'TARGET_UNAVAILABLE'):
                continue  # Host fixtures can model only one vbmeta partition.
            partition_sha256[label] = None
    try:
        with flash.list_super(context) as found:
            size, digest, done = found.size_of(found.partition('vendor')), hashlib.sha256(), 0
            for data in found.chunks('vendor'):
                digest.update(data)
                done += len(data)
                progress('Reading the vendor on the phone', {'label': 'super/vendor', 'size_bytes': size}, done)
            facts['vendor_sha256'] = digest.hexdigest()
    except (OSError, ValueError, KeyError, fs.FilesystemError):
        pass
    try:
        facts['vbmeta_flags'] = vbmeta_flags(context)
    except (OSError, KeyError, struct.error, fs.FilesystemError):
        pass
    try:
        import nofbe
        facts['data_encrypted'] = bool(nofbe.read_vendor(context)[0]['encrypted'])
    except Exception:  # noqa: BLE001 - unread is None: it then differs from every qualified platform
        pass
    return facts, partition_sha256


def keep_data_facts(context, volume, token, path, source, boot, qualification_run, rollback_volume, rollback_image=None, progress=quiet):
    """(facts, blockers) of an update that keeps the data: the pair, and its way back."""
    blockers = []
    if boot != 'android':
        blockers.append('KEEP_DATA_NEEDS_ANDROID')
    sizes = {bytes_ for bytes_, _ in android_transitions.targets()}
    facts = {'qualified': False, 'pair': None, 'source_system_sha256': None, 'target_sha256': None,
             'rollback_volume': rollback_volume, 'rollback_image': rollback_image,
             'rollback_labels': ROLLBACK_LABELS.split(',') if rollback_volume else []}
    if source['size'] in sizes or qualification_run:
        facts['target_sha256'], _ = file_digest(context, volume, token, path, progress, source['identity'])
        facts['source_system_sha256'] = system_digest(context, progress)
        pair = android_transitions.lookup(facts['source_system_sha256'], facts['target_sha256'])
        facts['qualified'], facts['pair'] = pair is not None, pair
        # The platform is read for a qualification run too: it is what the qualified pair then names.
        facts['platform'], facts['platform_partition_sha256'] = platform_facts(context, progress)
        target_sdk, target_release = VERIFIED_PACKAGE_VERSIONS.get(facts['target_sha256'], (None, None))
        vendor_sdk, vendor_vndk = VERIFIED_VENDOR_VERSIONS.get(facts['platform']['vendor_sha256'], (None, None))
        facts['versions'] = {
            'source_sdk': VERIFIED_SYSTEM_SDKS.get(facts['source_system_sha256']),
            'target_sdk': target_sdk, 'target_release': target_release,
            'vendor_sdk': vendor_sdk, 'vendor_vndk': vendor_vndk,
        }
        if pair is not None:
            # The pair's files match; the platform must be one it was checked on too (2026-11-22).
            facts['platform_differences'] = android_transitions.platform_differences(pair, facts['platform'])
            if facts['platform_differences']:
                facts['qualified'] = False
                if not qualification_run:
                    blockers.append('PLATFORM_NOT_QUALIFIED')
        unread = [label for label, sha in facts['platform_partition_sha256'].items() if sha is None]
        if unread:
            blockers.append('PLATFORM_NOT_QUALIFIED')
            facts['qualified'] = False
            facts.setdefault('platform_differences', []).extend(unread)
        # Vendor's fstab describes what it asks Android to create. The live userdata
        # can still hold encrypted data from another installation.
        import format_authorization
        userdata = context.fs.volume('userdata')
        protected = format_authorization.protected(userdata)
        facts['userdata'] = {'volume_token': userdata['volume_token'],
                             'protection': 'protected_or_unknown' if protected else 'unprotected'}
        if protected:
            blockers.append('PLATFORM_NOT_QUALIFIED')
            facts['qualified'] = False
            facts.setdefault('platform_differences', []).append('userdata_encryption')
        if pair is not None and not rollback_image and not rollback_volume:
            rollback_image, rollback_volume = way_back(context, pair, progress)
            facts['rollback_image'], facts['rollback_volume'] = rollback_image, rollback_volume
            facts['rollback_labels'] = ROLLBACK_LABELS.split(',') if rollback_volume else []
    if facts['pair'] is None and not qualification_run:
        blockers.append('PAIR_NOT_QUALIFIED')
    if rollback_image:
        if rollback_image[0] in ('userdata', 'cache', 'metadata') or \
                not any(v['id'] == rollback_image[0] for v in context.fs.volumes()):
            blockers.append('ROLLBACK_COPY_NEEDS_CARD')
    elif rollback_volume:
        copy_to = next((v for v in context.fs.volumes() if v['id'] == rollback_volume), None)
        if copy_to is None or rollback_volume in ('userdata', 'cache', 'metadata'):
            blockers.append('ROLLBACK_COPY_NEEDS_CARD')
    else:
        blockers.append('ROLLBACK_NEEDED')
    return facts, blockers


def inspect(context, volume, token, path, keep_data=False, rollback_volume=None, qualification_run=False, rollback_image=None,
            progress=quiet, no_fbe=False):
    relative = '/' + fs.clean_path(path).lstrip('/')
    name = relative.rsplit('/', 1)[-1]
    source = gsi_source(context, volume, token, relative)
    props = source['props']
    warnings, blockers, rows, writes = [], [], [], []
    boot, release = current_boot(context)
    stock = None
    if boot != 'android':
        # 2026-11-10: with Linux (or nothing usable) on BOOT, Samsung's BOOT kept on cache (taken out of
        # the firmware, or saved by the app or a flash) goes on BOOT too; the Linux BOOT is kept then.
        try:
            stock = next((b for b in saved_boot.saved_boots(context) if b['kind'] == 'android'), None)
        except fs.FilesystemError:
            stock = None
        if stock is None:
            blockers.append('STOCK_ANDROID_FIRST')
    system_name, system_bytes = source['members']['system']
    targets = {t['label']: t for t in flash.targets(context)['targets']}
    room = flash.targets(context).get('super_free_bytes', 0)
    current = targets.get('super/system', {}).get('size_bytes', 0)
    if system_bytes and system_bytes > current + room:
        blockers.append('NO_ROOM_IN_SUPER')
    rows.append({'file': 'GSI', 'name': system_name or name, 'size': system_bytes, 'action': 'write', 'target': 'super/system',
                 'reason': None})
    writes.append({'target': 'super/system', 'path': relative, 'member': system_name, 'size': system_bytes})
    flags = vbmeta_flags(context)
    verification_disabled = flags is not None and bool(flags & AVB_VERIFICATION_DISABLED)
    if keep_data:
        if verification_disabled:
            rows.append({'file': 'PHONE', 'name': 'vbmeta', 'size': 0, 'action': 'kept', 'target': None,
                         'reason': 'Verification is already disabled'})
    elif 'vbmeta' in flash.write_protected(context):
        # 2026-11-10: LK write-protects vbmeta while the phone runs. Verification already off (the
        # vbmeta Root prepares, or one flashed in Download mode): kept. Otherwise it is flashed
        # in Download mode first - Root on the Android page prepares it.
        if verification_disabled:
            rows.append({'file': 'GSI', 'name': 'vbmeta', 'size': 0, 'action': 'kept', 'target': None,
                         'reason': 'Verification is already disabled'})
        else:
            blockers.append('VBMETA_IN_DOWNLOAD_MODE')
    elif 'vbmeta' in source['members']:
        vb_name, vb_bytes = source['members']['vbmeta']
        rows.append({'file': 'GSI', 'name': vb_name, 'size': vb_bytes, 'action': 'write', 'target': 'vbmeta', 'reason': None})
        writes.append({'target': 'vbmeta', 'path': relative, 'member': vb_name, 'size': vb_bytes})
    else:
        if not verification_disabled:
            # No vbmeta of its own: an empty one with verification disabled goes there instead.
            data = disabled_vbmeta()
            rows.append({'file': 'RECOVERY', 'name': VBMETA_NAME, 'size': len(data), 'action': 'write', 'target': 'vbmeta', 'reason': None})
            writes.append({'target': 'vbmeta', 'volume': 'cache', 'path': '/' + VBMETA_DIR + '/' + VBMETA_NAME, 'member': None,
                           'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'generate': 'vbmeta-disabled'})
        else:
            rows.append({'file': 'GSI', 'name': 'vbmeta', 'size': 0, 'action': 'kept', 'target': None,
                         'reason': 'Verification is already disabled'})
    if stock is not None and not keep_data:
        rows.append({'file': 'CACHE', 'name': stock['name'], 'size': stock['bytes'], 'action': 'write', 'target': 'boot', 'reason': None})
        writes.append({'target': 'boot', 'volume': 'cache', 'path': stock['path'], 'member': None, 'size': stock['bytes'],
                       'sha256': stock['sha256']})
    else:
        rows.append({'file': 'PHONE', 'name': 'boot', 'size': 0, 'action': 'kept', 'target': None,
                     'reason': "Samsung's Android BOOT stays" if boot == 'android' else 'Not Android: flash the Samsung firmware first'})
    erase, keep = ['userdata', 'metadata', 'cache'], None
    vendor_review = None
    # Android's data without encryption (nofbe.py, 2026-11-21): a GSI keeps the vendor there, whose fstab
    # then asks for none. Only with the data erased: data already encrypted stays so.
    if no_fbe:
        require(not keep_data, 'INVALID_ARGUMENT', 'Data that is kept keeps its encryption')
        import nofbe
        encryption_blockers = sf.no_fbe_blockers(context)
        blockers += encryption_blockers
        if not encryption_blockers:
            # GSI keeps the installed vendor, so its actual patch can be reviewed before any flash.
            # The mapping uses a fixed name and must share the installation's exclusive lease.
            try:
                with lease(context.lock_path, context.mode):
                    vendor, extents = nofbe.read_vendor(context)
                require(vendor['files'], 'VENDOR_UNREADABLE', 'No vendor fstab could be reviewed for a no-FBE install')
                vendor_review = fs.digest({
                    'files': vendor['files'], 'extents': extents,
                    'writes': [(row['offset'], row['old'].hex(), row['new'].hex()) for row in vendor['writes']],
                })
            except fs.FilesystemError as error:
                blockers.append(error.code)
    if keep_data:
        keep, more = keep_data_facts(context, volume, token, relative, source, boot, qualification_run, rollback_volume,
                                     rollback_image, progress)
        blockers += more
        if not verification_disabled:
            blockers.append('PLATFORM_NOT_QUALIFIED')
            keep['qualified'] = False
            differences = keep.setdefault('platform_differences', [])
            if 'vbmeta_flags' not in differences:
                differences.append('vbmeta_flags')
        rollback_image, rollback_volume = keep['rollback_image'], keep['rollback_volume']
        erase = []
        if rollback_image:
            rows.insert(0, {'file': 'CARD', 'name': rollback_image[1].rsplit('/', 1)[-1], 'size': 0, 'action': 'kept',
                            'target': None, 'reason': "The way back: this system's own image, checked first"})
        else:
            rows.insert(0, {'file': 'PHONE', 'name': ROLLBACK_LABELS.replace(',', ', '), 'size': 0, 'action': 'copy',
                            'target': rollback_volume, 'reason': 'Kept first, to return to this system'})
        rows.append({'file': 'PHONE', 'name': 'userdata', 'size': 0, 'action': 'kept', 'target': None,
                     'reason': 'Apps and their data stay'})
    sdk = int(props.get('ro.build.version.sdk', '0') or 0) if props.get('ro.build.version.sdk', '').isdigit() else 0
    android = props.get('ro.build.version.release', '')
    verified_versions = (keep or {}).get('versions', {})
    if verified_versions.get('target_sdk') is not None:
        sdk, android = verified_versions['target_sdk'], verified_versions['target_release']
    verified_fit = bool(keep and keep['qualified'] and verified_versions.get('target_sdk') is not None)
    fits = verified_fit or VENDOR_FCM_LEVEL in SUPPORTED_LEVELS.get(sdk, ())
    if sdk and not fits:
        warnings.append('Made for newer vendors: it may not start on this phone')
    if not sdk:
        warnings.append('The image does not say its Android version')
    # 2026-11-12, on the owner's phone: Google's Android 15 restarted for ever. Its network loader
    # refuses a kernel older than 4.19 ("NetBpfLoad: Android V requires kernel 4.19"), and this
    # phone's Android kernel is 4.14. ROMs made for older phones take that check out (crDroid and
    # AlphaDroid, both Android 16, started here), and a file does not say which kind it is: so
    # this is said, and never refused.
    if not verified_fit and sdk >= KERNEL_FLOOR_SDK:
        boot_kernel = release if boot == 'android' else (stock or {}).get('release', '')
        if kernel_older(boot_kernel, KERNEL_FLOOR):
            warnings.append(OLD_KERNEL_WARNING)
    plan = {'file': {'path': relative, 'identity': source['identity'], 'size': source['size']},
            'writes': [{k: w.get(k) for k in ('target', 'member', 'size', 'volume', 'path', 'sha256')} for w in writes],
            'erase': erase}
    if no_fbe:
        plan['no_fbe'] = True
        plan['no_fbe_vendor_review_sha256'] = vendor_review
    if keep_data:
        plan['keep_data'] = {k: keep.get(k) for k in ('source_system_sha256', 'target_sha256', 'rollback_volume', 'rollback_image',
                                                     'qualified', 'platform', 'platform_partition_sha256', 'userdata',
                                                     'versions')}
        plan['qualification_run'] = bool(qualification_run)
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    build = props.get('ro.build.id', '')
    return {'volume': volume, 'path': relative, 'build': build, 'android': android, 'sdk': sdk,
            'patch': props.get('ro.build.version.security_patch', ''), 'fits': fits, 'boot': boot or 'unknown', 'boot_release': release,
            'files': [{'name': name, 'path': relative, 'kind': 'GSI', 'build': build, 'size': source['size'], 'md5': None}],
            'rows': rows, 'writes': writes, 'erase': plan['erase'], 'warnings': warnings, 'blockers': sorted(set(blockers)),
            'plan_sha256': digest, 'source_identity': source['identity'],
            'write_bytes': sum(w['size'] for w in writes), 'keep_data': keep,
            'keep_data_offer': (not keep_data and boot == 'android' and android_transitions.offered(source['size'])),
            'no_fbe': bool(no_fbe)}


def flash_gsi(context, volume, token, write, progress, source_identity=None, source_sha256=None):
    args = type('Args', (), {})()
    if write.get('volume') and write['volume'] != volume:
        # Samsung's BOOT kept on cache: its own volume, mounted read-only by saved_boots.
        volume, token = write['volume'], context.fs.volume(write['volume'])['volume_token']
    args.target, args.volume, args.volume_token, args.path, args.member = write['target'], volume, token, write['path'], write['member']
    args.image_bytes, args.confirm = None, True
    # The reviewed package and cache images have a digest of the encoded source.
    # Check it using the same file descriptor as the decoder.
    args.expected_source_sha256 = write.get('sha256') or source_sha256
    args.expected_source_identity = None if write.get('volume') else source_identity
    checked = flash.check(context, args, progress)
    args.expected_sha256, args.expected_identity = checked['image']['sha256'], checked['image']['identity']
    if write['target'].startswith('super/'):
        args.image_bytes = checked['image']['payload_bytes']
    done = flash.write(context, args, progress)
    return {'target': write['target'], 'sha256': done['sha256'], 'partition_sha256': done.get('partition_sha256'),
            'kept_boot': done.get('kept_boot')}


def rollback_copy(volume, progress):
    """BOOT, the vbmetas and super copied to VOLUME and verified (identity_backup, kind android): the way
    back to the system an update replaces. It takes the operation lock itself, so before the update's."""
    import identity_backup as ib
    ib.use('android', ROLLBACK_LABELS)
    copier = ib.Device()
    step = lambda phase, label, done, total: progress(phase, {'label': label, 'size_bytes': total}, done)
    made = ib.backup(copier, argparse.Namespace(volume=volume), step)
    checked = ib.verify(copier, argparse.Namespace(volume=volume, path=made['path']), step)
    require(checked.get('verified') and checked.get('restorable'), 'ROLLBACK_COPY_FAILED',
            'The copy of this system could not be verified: nothing was written')
    return {'volume': volume, 'path': made['path'], 'manifest_sha256': checked['manifest_sha256']}


def install_gsi(context, volume, token, path, expected_plan, confirmed, progress, keep_data=False, rollback_volume=None,
                qualification_run=False, rollback_image=None, no_fbe=False):
    require(confirmed, 'CONFIRMATION_REQUIRED', 'Installing a GSI must be confirmed')
    checked = dict(keep_data=keep_data, rollback_volume=rollback_volume, qualification_run=qualification_run,
                   rollback_image=rollback_image, no_fbe=no_fbe)
    copy = None
    if keep_data:
        # Reviewed again before the copy (minutes of work for nothing otherwise), and again after it.
        first = inspect(context, volume, token, path, progress=progress, **checked)
        require(first['plan_sha256'] == expected_plan, 'PLAN_CHANGED', 'The system or the image changed since the review. Review it again')
        require(not first['blockers'], 'PLAN_BLOCKED', 'This update cannot keep the data', blockers=first['blockers'])
        rollback_image = tuple(first['keep_data']['rollback_image']) if first['keep_data']['rollback_image'] else None
        rollback_volume = first['keep_data']['rollback_volume']
        if not rollback_image:
            copy = rollback_copy(rollback_volume, progress)
    with sf.held_lock(context):
        import format_authorization
        format_authorization.require_unprotected(context.fs)
        plan = inspect(context, volume, token, path, progress=progress, **checked)
        require(plan['plan_sha256'] == expected_plan, 'PLAN_CHANGED', 'The image changed since it was reviewed. Review it again')
        require(not plan['blockers'], 'PLAN_BLOCKED', 'This image cannot be installed', blockers=plan['blockers'])
        if keep_data and rollback_image:
            # Check while holding the installation lock, which prevents another recovery job replacing the file.
            card, earlier = rollback_image
            try:
                matches = image_matches_system(context, card, earlier, progress)
            except FileNotFoundError:
                matches = False
            require(matches, 'ROLLBACK_IMAGE_DIFFERS',
                    "This image is missing or differs from the system on the phone. Nothing was written")
            copy = {'volume': card, 'path': earlier, 'image': True}
        token = context.fs.volume(volume)['volume_token']
        source_sha256 = plan['keep_data']['target_sha256'] if keep_data else None
        if any(w.get('generate') == 'vbmeta-disabled' for w in plan['writes']):
            with flash.source_file(context, volume, token, plan['path']) as fd:
                require(flash.identity(fd) == plan['source_identity'], 'IMAGE_CHANGED',
                        'The image file changed since the review')
            saved_boot.save_on_cache(context, VBMETA_NAME, disabled_vbmeta(), {'kind': 'vbmeta', 'flags': AVB_VERIFICATION_DISABLED},
                                     progress, keep_mounted=True, folder_name=VBMETA_DIR)
        written = [flash_gsi(context, volume, token, write, progress, plan['source_identity'], source_sha256)
                   for write in plan['writes']]
        if keep_data:
            return {'build': plan['build'], 'android': plan['android'], 'written': written, 'kept_data': True,
                    'pair': plan['keep_data']['pair'], 'qualification_run': qualification_run, 'rollback_copy': copy,
                    'saved_boot': None,
                    'next': ('Restart into Android. To return to the earlier system: its image in Files, Flash to a partition, '
                             'super/system' if rollback_image else
                             'Restart into Android. To return to the earlier system: Restore, this copy of the partitions')
                            + '; data the new system changed after its first start does not go back with it.'}
        unencrypted = None
        if no_fbe:
            import nofbe
            unencrypted = nofbe.patch(context, True, progress)
        reset = sf.android_data(context, progress)
        return {'build': plan['build'], 'android': plan['android'], 'written': written, **reset, 'saved_boot': None,
                'no_fbe': unencrypted, 'next': 'Restart into Android. The first start takes several minutes.'}


def parser():
    result = argparse.ArgumentParser()
    mode = result.add_mutually_exclusive_group(required=True)
    mode.add_argument('--device', action='store_true')
    mode.add_argument('--fixture', type=Path)
    commands = result.add_subparsers(dest='command', required=True)
    for name in ('inspect', 'install', 'classify'):
        command = commands.add_parser(name)
        command.add_argument('--volume', required=True)
        command.add_argument('--volume-token', required=True)
        command.add_argument('--path', required=True)
    commands.choices['install'].add_argument('--expected-plan', required=True)
    commands.choices['install'].add_argument('--confirm', action='store_true')
    for name in ('inspect', 'install'):
        commands.choices[name].add_argument('--keep-data', action='store_true')
        commands.choices[name].add_argument('--rollback-volume')
        commands.choices[name].add_argument('--rollback-image-volume')
        commands.choices[name].add_argument('--no-fbe', action='store_true', help="Android's data without encryption (nofbe.py)")
        commands.choices[name].add_argument('--rollback-image-path')
        commands.choices[name].add_argument('--qualification-run', action='store_true',
                                            help='Allow a pair not yet qualified (how a pair is qualified; not offered by the UI)')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    last = [None, 0.0]

    def progress(phase, target, done):
        now = time.monotonic()
        if phase != last[0] or now - last[1] >= 0.2 or done == target['size_bytes']:
            print(json.dumps({'event': 'progress', 'operation': 'gsi-' + args.command, 'phase': phase, 'partition': target['label'],
                              'bytes_done': done, 'bytes_total': target['size_bytes']}, separators=(',', ':')), file=sys.stderr, flush=True)
            last[:] = [phase, now]

    try:
        context = install.FixtureContext(args.fixture) if args.fixture else install.DeviceContext()
        checked = {} if args.command == 'classify' else dict(
            keep_data=args.keep_data, rollback_volume=args.rollback_volume, qualification_run=args.qualification_run,
            rollback_image=(args.rollback_image_volume, '/' + fs.clean_path(args.rollback_image_path).lstrip('/'))
            if args.rollback_image_volume and args.rollback_image_path else None, no_fbe=args.no_fbe)
        if args.command == 'inspect':
            result = inspect(context, args.volume, args.volume_token, args.path, progress=progress, **checked)
        elif args.command == 'classify':
            result = classify(context, args.volume, args.volume_token, args.path)
        else:
            result = install_gsi(context, args.volume, args.volume_token, args.path, args.expected_plan, args.confirm, progress, **checked)
        print(json.dumps({'ok': True, 'operation': args.command, **result}, separators=(',', ':')), flush=True)
        return 0
    except Exception as error:  # noqa: BLE001 - every refusal reaches the page as JSON
        code = getattr(error, 'code', None) or ('OPERATION_BUSY' if isinstance(error, BlockingIOError) else 'IO_ERROR')
        print(json.dumps({'ok': False, 'operation': args.command, 'error': {
            'code': code, 'message': str(error), 'details': getattr(error, 'details', {})}}, separators=(',', ':')), flush=True)
        return 2


if __name__ == '__main__':
    sys.exit(main())
