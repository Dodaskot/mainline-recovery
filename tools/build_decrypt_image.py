#!/usr/bin/env python3
"""Reproducible ramdisk integration on the exact qualified #145 recovery.

Only listed ramdisk files change. Kernel, DTB, DTBO, addresses and command line
are preserved. This program never opens a device or flashes an image.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import lzma
import os
import re
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import sys
import tarfile
import zlib
from build_v06_image import read_cpio, write_cpio

BASE_SHA = 'b83be8c2c39b1fb97452cbfb663c9dd3627f276415cdf1b7627357ba92726a7a'
PARTITION_SIZE = 41943040
SALT = '88529080c91c96032c38f6769f5efac130561988dfb3ff3c96a14e5b36891dbb'


# Bluetooth (2026-11-22): the controller's link to the Wi-Fi chip's STP (btmtk_stp), the stack and
# its keyboards and serial ports; media_service.py loads them from bt-modules/RELEASE-BUILD.
BT_MODULES = ('bluetooth', 'rfcomm', 'hidp', 'btmtk_stp')
# A BD address of a real phone must not be in a module's text (its parameter's example was one).
BT_EXAMPLE = b'e.g. 00:11:22:33:44:55'
SOUND_MODULES = ('soundcore', 'snd', 'snd-timer', 'snd-pcm', 'snd-soc-core', 'snd-soc-mtk-common', 'snd-soc-mt8192-afe',
                 'snd-soc-mt6359', 'mt6359-accdet', 'snd-soc-aw8738', 'mt6833-mt6359')

def compress_ramdisk(raw, dict_mib=64):
    """The ramdisk as the kernel unpacks it (2026-11-20): xz with the ARM64 BCJ filter before LZMA2
    (aarch64 code compresses better once its branch targets are absolute) and a 64 MiB dictionary;
    on image .54 that freed 1.6 MB of the 40 MiB partition. The recovery kernels have
    CONFIG_XZ_DEC_ARM64 and CONFIG_XZ_DEC_BCJ. Python's lzma has no ARM64 filter, so xz (5.4 or
    later) does the work; the result is checked by Python's own decoder, which liblzma serves."""
    import subprocess
    done = subprocess.run(['xz', '--format=xz', '--check=crc32', '--arm64', f'--lzma2=preset=9e,dict={dict_mib}MiB',
                           '--threads=1', '--stdout', '-'], input=raw, capture_output=True, check=True)
    compressed = done.stdout
    if lzma.decompress(compressed) != raw:
        raise RuntimeError('Ramdisk roundtrip')
    return compressed

def require(value, reason):
    if not value: raise ValueError(reason)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def align(n, page):
    return (n + page - 1) // page * page

def digest(parts):
    h = hashlib.sha1()
    for part in parts:
        h.update(part); h.update(struct.pack('<I', len(part)))
    return h.digest() + bytes(12)

def parse(data):
    require(2048 <= len(data) <= 64 << 20 and data[:8] == b'ANDROID!', 'Image bounds/magic')
    k, _, r, _, s, _, _, page, version, _ = struct.unpack_from('<10I', data, 8)
    require(version == 2 and page in (2048, 4096, 8192, 16384), 'Header version/page')
    rd, rd_offset, header_size = struct.unpack_from('<IQI', data, 1632)
    dt = struct.unpack_from('<I', data, 1648)[0]
    require(header_size == 1660 and k > 0 and r > 0 and dt > 0, 'Header structure')
    require(not any(data[header_size:page]) and len(data) % page == 0, 'Header padding')
    parts, offsets, at = [], [], page
    for size in (k, r, s, rd, dt):
        end, stop = at + size, at + align(size, page)
        require(stop <= len(data) and not any(data[end:stop]), 'Section bounds/padding')
        offsets.append(at); parts.append(data[at:end]); at = stop
    require(rd_offset == (offsets[3] if rd else 0), 'DTBO offset')
    require(data[576:608] == digest(parts), 'Header digest')
    return page, parts, at

WIFI_PATH = 'opt/a22x-recovery/platform/wifi-modules.tar.xz'
# Touch firmware loaded by the #146 drivers (NT36675 runtime image; Himax TXD panel). Same bytes as
# shipped in recovery 1.0.2.1; the JDI Himax image is already in the base ramdisk.
TOUCH_FIRMWARE = {
    'novatek_ts_fw.bin': '6a75652cd36b48da932bad83624cd12505b6a536236ec83da9fd30dd116a2cb1',
    'Himax_firmware_fw_txd.bin': 'b58260db3229a4d5339e8b8ba9a497bb7b92f9f5460aba204b54949ca48d7793',
}
# The wireless regulatory database for cfg80211 (wireless-regdb 2026.09.03, ISC; signed by its maintainer,
# whose key the kernel carries). Without it cfg80211 said "failed to load regulatory.db" and kept the world
# domain (2026-11-21, a tester, #12).
REGULATORY_DB = {
    'regulatory.db': '7e236caecd939c8ec98be4870bf30422f28ffef2565a38aaaa2d9ddabd0c2641',
    'regulatory.db.p7s': '50332f0db09b8bcc719235ec4985c27377f2cc2f42abb7b5dcf951866c5a888a',
}
WIFI_MEMBERS = frozenset(('btif.ko', 'wmt_drv.ko', 'wmt_chrdev_wifi.ko', 'wlan_6833_axi.ko'))
# These ABI flags belong to the mandatory exact BASE_SHA kernel config; release
# is independently read from its preserved kernel bytes, never a CLI argument.
QUALIFIED_VERMAGIC_SUFFIX = ' SMP preempt mod_unload aarch64'


def kernel_identity(data):
    require(64 <= len(data) <= 64 << 20, 'Kernel identity bounds')
    compression = 'raw'
    if data.startswith(b'\x1f\x8b'):
        compression = 'gzip'
        decoder = zlib.decompressobj(31)
        raw = decoder.decompress(data, (128 << 20) + 1)
        require(len(raw) <= 128 << 20 and decoder.eof and not decoder.unconsumed_tail,
                'Kernel gzip bounds/incomplete stream')
        # The qualified gzip stream is followed by its appended DTB.
        require(not decoder.unused_data or decoder.unused_data.startswith(b'\xd0\x0d\xfe\xed'),
                'Unexpected appended kernel payload')
    else:
        raw = data
    require(len(raw) >= 64 and raw[56:60] == b'ARMd', 'Kernel AArch64 image header')
    releases = {m.group(1).decode('ascii') for m in re.finditer(
        rb'Linux version ([A-Za-z0-9._+\-]{1,128}) [^\x00]{1,4096}\x00', raw)}
    require(len(releases) == 1, 'Missing or ambiguous kernel release')
    release = next(iter(releases))
    # The build number of the banner (#164): the sound and Bluetooth services look for their modules in
    # <release>-<build>, so a kernel changed without its modules lost sound and Bluetooth (beta21).
    builds = {m.group(1).decode('ascii') for m in re.finditer(
        rb'Linux version ' + re.escape(release.encode()) + rb' [^\x00]{0,512}? #([0-9]{1,6}) ', raw)}
    require(len(builds) == 1, 'Missing or ambiguous kernel build number')
    return {'release': release, 'build': next(iter(builds)), 'architecture': 'aarch64', 'compression': compression,
            'encoded_sha256': sha(data), 'raw_sha256': sha(raw),
            'expected_vermagic': release + QUALIFIED_VERMAGIC_SUFFIX,
            'abi_config_binding': 'exact-qualified-base-sha256', 'base_sha256': BASE_SHA}


def elf_module(data, expected_vermagic):
    """Read the real ELF64 .modinfo section, not an unchecked strings result."""
    require(64 <= len(data) <= 32 << 20, 'Module size bound')
    require(data[:7] == b'\x7fELF\x02\x01\x01', 'Module ELF64 little-endian identity')
    kind, machine, version = struct.unpack_from('<HHI', data, 16)
    require(kind == 1 and machine == 183 and version == 1, 'Module is not AArch64 ET_REL')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    ehsize, _, _, shsize, count, names_index = struct.unpack_from('<6H', data, 52)
    require(ehsize == 64 and shsize == 64 and 0 < count <= 65534 and 0 < names_index < count
            and shoff >= 64 and shoff + count * shsize <= len(data), 'Module ELF section bounds')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * 64) for i in range(count)]
    names = sections[names_index]
    require(names[1] == 3 and 0 < names[5] <= 1 << 20 and names[4] + names[5] <= len(data),
            'Module section name table')
    strings = data[names[4]:names[4] + names[5]]
    matches = []
    for section in sections:
        start = section[0]
        require(start < len(strings) and b'\x00' in strings[start:], 'Module section name bound')
        name = strings[start:].split(b'\x00', 1)[0]
        if name == b'.modinfo':
            require(section[1] == 1 and 0 < section[5] <= 65536 and
                    section[4] + section[5] <= len(data), 'Module modinfo bounds')
            matches.append(data[section[4]:section[4] + section[5]])
    require(len(matches) == 1 and matches[0].endswith(b'\x00'), 'Missing or duplicate module modinfo')
    values = [entry[len(b'vermagic='):] for entry in matches[0].split(b'\x00')
              if entry.startswith(b'vermagic=')]
    require(len(values) == 1, 'Missing or duplicate module vermagic')
    try:
        vermagic = values[0].decode('ascii')
    except UnicodeDecodeError:
        raise ValueError('Non-ASCII module vermagic') from None
    require(vermagic == expected_vermagic, 'Module vermagic incompatible with preserved kernel')
    return {'bytes': len(data), 'sha256': sha(data), 'vermagic': vermagic, 'architecture': 'aarch64'}


def wifi_module_archive(data, expected_vermagic):
    require(0 < len(data) <= 16 << 20, 'Wi-Fi archive size bound')
    require(data.startswith(b'\xfd7zXZ\x00'), 'Wi-Fi runtime requires an XZ archive')
    modules = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:xz') as archive:
        for member in archive:
            require(member.name in WIFI_MEMBERS and member.name not in modules,
                    'Unexpected or duplicate Wi-Fi archive member')
            require(member.isfile() and not member.issparse() and not member.pax_headers
                    and 64 <= member.size <= 32 << 20, 'Wi-Fi module tar shape')
            total += member.size
            require(total <= 48 << 20, 'Wi-Fi archive expanded bound')
            stream = archive.extractfile(member)
            require(stream is not None, 'Wi-Fi module payload missing')
            payload = stream.read(member.size + 1)
            require(len(payload) == member.size, 'Wi-Fi module tar read')
            modules[member.name] = elf_module(payload, expected_vermagic)
    require(set(modules) == WIFI_MEMBERS, 'Wi-Fi archive must contain exactly four modules')
    return {'archive_sha256': sha(data), 'archive_bytes': len(data), 'modules': modules}


def validate_kernel_modules(kernel, entries, wifi_replacement=None):
    identity = kernel_identity(kernel)
    vermagic = identity['expected_vermagic']
    modules = {}
    wifi = None
    for fields, name, data in entries:
        if name.endswith('.ko'):
            require(stat.S_ISREG(fields[1]), 'CPIO module is not regular')
            require(name not in modules, 'Duplicate CPIO kernel module')
            modules[name] = elf_module(data, vermagic)
        if name == WIFI_PATH:
            require(wifi is None and stat.S_ISREG(fields[1]), 'Wi-Fi CPIO archive type/duplicate')
            wifi = data
    require(wifi is not None, 'Missing Wi-Fi module archive')
    # Module folders named for a kernel (<release>-<build>) must name this one: one kernel, one set of
    # modules (2026-11-22, beta21: kernel #164 with the #162 folders, no sound and no Bluetooth).
    folder = identity['release'] + '-' + identity['build']
    for name in modules:
        for part in name.split('/')[:-1]:
            if part.startswith(identity['release'] + '-'):
                require(part == folder, 'Modules of another kernel build: ' + name + ' (this kernel is ' + folder + ')')
    # An explicit replacement supersedes only the inherited Wi-Fi payload;
    # every other original .ko must independently match the preserved kernel.
    wifi = wifi_replacement if wifi_replacement is not None else wifi
    return {'kernel': identity, 'cpio_modules': modules,
            'wifi': wifi_module_archive(wifi, vermagic),
            'wifi_source': 'explicit-replacement' if wifi_replacement is not None else 'inherited'}


QUOTA_MODULE_PINS = (
    ('quota_tree', '/lib/modules/quota_tree.ko', '50824bbca9fac1f670c482426345dab6e4ea780aa3da0b04e3cbb85eb0e162e1'),
    ('quota_v2', '/lib/modules/quota_v2.ko', '36a102b5b32f4498cbfad7ea2fb558ff33dd5b20f62a49729f94b29377b91491'))
RW_HELPER = '/system/bin/a22x-data-ce-rw'


def regular_input(path, maximum):
    path = Path(path).absolute()
    require(not any(item.is_symlink() for item in (path, *path.parents)), 'Input path contains a symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        require(stat.S_ISREG(first.st_mode) and first.st_nlink == 1
                and not first.st_mode & 0o022 and 0 < first.st_size <= maximum,
                'Input must be one regular non-writable-by-others file')
        data = bytearray()
        while chunk := os.read(fd, min(65536, maximum + 1 - len(data))):
            data.extend(chunk)
            require(len(data) <= maximum, 'Input grew beyond bound')
        last, named = os.fstat(fd), path.stat(follow_symlinks=False)
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        require(len(data) == first.st_size and identity(first) == identity(last) == identity(named),
                'Input changed during pin validation')
        return bytes(data)
    finally:
        os.close(fd)


def mtk_dtb_table(section):
    """The MediaTek DTB table in the v2 DTB section: 64-byte header, then one DTB."""
    # Seen in the qualified base: magic, total, 0x20, 0x20, count=1, 0x20, 0x800, 0, dtb size, dtb offset 0x40.
    require(len(section) > 64 and section[:4] == bytes.fromhex('d7b7ab1e'), 'MTK DTB table magic')
    fields = struct.unpack_from('>16I', section, 0)
    total, count, dtb_size, dtb_offset = fields[1], fields[4], fields[8], fields[9]
    require(fields[2:4] == (0x20, 0x20) and fields[5:8] == (0x20, 0x800, 0) and not any(fields[10:])
            and section[40:64] == bytes(24), 'MTK DTB table header shape')
    dtb = section[64:]
    require(total == len(section) and count == 1 and dtb_offset == 64 and dtb_size == len(dtb)
            and dtb[:4] == b'\xd0\x0d\xfe\xed' and struct.unpack_from('>I', dtb, 4)[0] == len(dtb), 'MTK DTB table fields')
    return dtb


def mtk_dtb_section(template, dtb):
    """Same header as the qualified section, with only total and DTB size changed."""
    mtk_dtb_table(template)
    header = bytearray(template[:64])
    struct.pack_into('>I', header, 4, 64 + len(dtb))
    struct.pack_into('>I', header, 32, len(dtb))
    section = bytes(header) + dtb
    require(mtk_dtb_table(section) == dtb, 'MTK DTB table rebuild')
    return section


def replace_kernel_and_dtb(parts, args):
    """Optional pinned kernel/DTB replacement. Same release (and so the same module vermagic),
    and the DTB appended to the kernel must be the DTB in the v2 DTB section."""
    given = tuple(getattr(args, name, None) for name in ('kernel_section', 'kernel_section_sha256', 'dtb_section', 'dtb_section_sha256'))
    if not any(given):
        return None
    require(all(given), 'Kernel replacement needs --kernel-section, --dtb-section and both SHA-256 pins')
    kernel_path, kernel_pin, dtb_path, dtb_pin = given
    kernel = regular_input(kernel_path, 64 << 20)
    dtb_section = regular_input(dtb_path, 4 << 20)
    require(sha(kernel) == kernel_pin and sha(dtb_section) == dtb_pin, 'Kernel/DTB pin mismatch')
    old, new = kernel_identity(parts[0]), kernel_identity(kernel)
    require(new['release'] == old['release'] and new['compression'] == 'gzip', 'Replacement kernel release/compression differs')
    decoder = zlib.decompressobj(31); decoder.decompress(kernel, (128 << 20) + 1)
    require(decoder.unused_data == mtk_dtb_table(dtb_section), 'Appended DTB differs from the DTB section')
    mtk_dtb_table(parts[4])
    record = {'base_kernel_section_sha256': sha(parts[0]), 'base_dtb_section_sha256': sha(parts[4]),
              'kernel_section_sha256': sha(kernel), 'dtb_section_sha256': sha(dtb_section),
              'kernel_raw_sha256': new['raw_sha256'], 'release': new['release'],
              'abi_note': 'same release and vermagic; modules are reused unchanged'}
    parts[0], parts[4] = kernel, dtb_section
    return record


def ce_rw_profile(profile, kernel_release):
    cap = profile.get('ce_rw')
    if cap is None:
        return None
    require(type(cap) is dict and set(cap) == {'schema','qualified','helper','helper_sha256',
        'kernel_release','quota_modules'}, 'CE RW capability keys')
    require(cap['schema'] == 'a22x.android-decrypt.ce-rw.v1' and type(cap['qualified']) is bool
        and cap['helper'] == RW_HELPER and type(cap['helper_sha256']) is str
        and re.fullmatch('[0-9a-f]{64}',cap['helper_sha256']) is not None
        and cap['kernel_release'] == kernel_release
        and cap['quota_modules'] == [dict(name=n,path=p,sha256=h) for n,p,h in QUOTA_MODULE_PINS],
        'CE RW profile kernel/helper/quota pins')
    return cap


def quota_module_inputs(directory, profile, kernel):
    cap = ce_rw_profile(profile, kernel['release'])
    if cap is None:
        require(directory is None, 'Quota modules supplied without a CE RW profile')
        return {}, None
    require(directory is not None, 'CE RW profile requires --quota-module-dir, even while disabled')
    directory = Path(directory).absolute()
    require(directory.is_dir() and not any(item.is_symlink() for item in (directory,*directory.parents)),
            'Quota module directory must not contain symlinks')
    additions, report = {}, {}
    for name,path,digest in QUOTA_MODULE_PINS:
        source = directory / (name+'.ko')
        payload = regular_input(source, 32 << 20)
        require(sha(payload) == digest, 'Quota module profile hash mismatch: '+name)
        info = elf_module(payload, kernel['expected_vermagic'])
        additions[path.lstrip('/')] = (payload, 0o100644)
        report[name] = dict(info,source=str(source),image_path=path)
    return additions, report


def validate_ce_rw_runtime(data, profile, kernel):
    cap = ce_rw_profile(profile,kernel['release'])
    require(sha(data) == profile['bundle_sha256'], 'Runtime package changed')
    if cap is None:
        return None
    expected_members = profile.get('runtime_member_count')
    require(type(expected_members) is int and 0 < expected_members <= 256
            and 0 < len(data) < 32 << 20,
            'CE RW runtime bounds/count pin')
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
        members=archive.getmembers();names=[m.name for m in members]
        require(len(members)==len(set(names))==expected_members, 'CE RW runtime member count/duplicates')
        require(sum(m.size for m in members)<=32 << 20,'CE RW runtime expanded bound')
        for member in members:
            require(0 <= member.size <= 32 << 20 and (member.isfile() or member.isdir()) and not member.issparse()
                and not Path(member.name).is_absolute() and '..' not in Path(member.name).parts,
                'CE RW runtime member shape')
        manifest_data=archive.extractfile('android-root/ROOT-MANIFEST.json').read()
        require(sha(manifest_data)==profile['root_manifest_sha256'], 'Runtime root manifest changed')
        manifest=json.loads(manifest_data)
        row=manifest['files'][RW_HELPER.lstrip('/')]
        member=archive.getmember('android-root/rootfs'+RW_HELPER)
        require(member.isfile() and member.uid==member.gid==0 and member.mode==row['mode']==0o555,
                'CE RW native member ownership/mode')
        payload=archive.extractfile(member).read()
        require(len(payload)==row['size'] and sha(payload)==row['sha256']==cap['helper_sha256'],
                'CE RW helper manifest/profile pin')
        require(64 <= len(payload) <= 8 << 20 and payload[:7]==b'\x7fELF\x02\x01\x01'
            and struct.unpack_from('<HHI',payload,16) in ((2,183,1),(3,183,1)),
            'CE RW native helper AArch64 ELF ABI')
        return dict(helper=RW_HELPER,helper_sha256=sha(payload),members=expected_members,
                    root_manifest_sha256=sha(manifest_data),qualified=cap['qualified'],
                    hardware_qualification='PENDING')


REMOVED_BUNDLED_THEMES = {
    'opt/a22x-recovery/themes/beaver.theme': {
        'sha256': 'ba9b9126558339a158a4e7b635a7fe2237f2ac5ecb4b1df57cb68e8f2d363d9b',
        'size_bytes': 2042511,
    },
}


def remove_bundled_themes(entries):
    """Remove only the explicit pinned asset; never a distro or arbitrary path."""
    removed, retained = {}, []
    for entry in entries:
        fields, name, data = entry
        if name not in REMOVED_BUNDLED_THEMES:
            retained.append(entry)
            continue
        expected = REMOVED_BUNDLED_THEMES[name]
        require(name not in removed and stat.S_ISREG(fields[1]), 'Removed theme type/duplicate')
        require(len(data) == expected['size_bytes'] and sha(data) == expected['sha256'],
                'Removed theme differs from qualified base')
        removed[name] = {'before': sha(data), 'size_bytes': len(data), 'reason': 'user-removed-bundled-theme'}
    require(set(removed) == set(REMOVED_BUNDLED_THEMES), 'Expected removed theme missing from base')
    return retained, removed


def remove_source_caches(entries):
    """Omit only checked-hash project bytecode whose exact source is present.

    Python compiles the unchanged source in RAM. Standard-library bytecode,
    sources, native helpers, drivers and diagnostics remain intact.
    """
    byname = {entry[1]: entry for entry in entries}
    kept, removed = [], {}
    for entry in entries:
        fields, name, data = entry
        if not (name.startswith('opt/a22x-recovery/') and
                '/__pycache__/' in name and name.endswith('.cpython-314.pyc')):
            kept.append(entry)
            continue
        path = Path(name)
        source_name = str(path.parent.parent / (path.name[:-len('.cpython-314.pyc')] + '.py'))
        source = byname.get(source_name)
        require(stat.S_ISREG(fields[1]) and source is not None and
                stat.S_ISREG(source[0][1]), 'Bytecode source missing or non-regular')
        require(len(data) >= 16 and data[:4] == importlib.util.MAGIC_NUMBER and
                struct.unpack_from('<I', data, 4)[0] == 3 and
                data[8:16] == importlib.util.source_hash(source[2]),
                'Bytecode cache is not an exact checked-hash source duplicate')
        removed[name] = {'before': sha(data), 'size_bytes': len(data),
                         'source_path': source_name, 'source_sha256': sha(source[2]),
                         'reason': 'redundant-source-backed-bytecode-cache'}
    require(removed, 'Qualified base contains no project source caches')
    return kept, removed


PANFROST_MODULES = frozenset((
    'e3e25e602819f3b1fa650e746417b9693070906b013425e8069820e8a10d114f',
    'c0167265744b3cd32f8eb4d678680505f69ba7004bcb821c636a3e3f376a7a26',
    # The common kernel's (2026-11-21: one kernel for the phone and the beta), as betas 12-15 carry it.
    'c15771090faaf46e3e510360f470f3f660d2c21eb69b34a0cb72880de90238e3',
    # Kernel #164's own (2026-11-22, build-panfrost164.sh): its tree carries the three panfrost fixes (the
    # cacheable read-only mapping 3606bd4388bb among them); built with no host paths, which the one above
    # named six times (audit, item 8).
    '1c6c4e6232ffa95ae77faf91223832cdf52ded3fa34979b3377360d2790f62dc',
))
EXFAT_TOOLS = {
    'mkfs.exfat': 'd9c56a1fbe9f13ad9b1f6cd46b12bd873adf9356f63bcf2c4d6a70c4d5a18d12',
    'fsck.exfat': '11c1aa01e2f2306ba7fe7395ebef548b0d700b8f8530c44e4eb6d3971a4b739a',
    'libblkid.so.1': '36c2815cbef03db5a25334cf7355d8b4d2b7867398bf7f485806493ec7b92e42',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--wifi-modules', type=Path, help='Replace inherited Wi-Fi archive with four modules matching the preserved kernel')
    parser.add_argument('--quota-module-dir', type=Path, help='Exact pinned #145 quota modules for the Evolution CE write candidate')
    parser.add_argument('--panfrost-module', type=Path, help='Exact A22x recovery Panfrost module for the browser')
    parser.add_argument('--wayland-compositor', type=Path, help='ARM64 off-screen compositor for the browser')
    parser.add_argument('--exfat-tools', type=Path,
                        help="mkfs.exfat, fsck.exfat and libblkid.so.1 from Arch Linux ARM's exfatprogs and util-linux-libs")
    parser.add_argument('--sound-modules', type=Path, action='append', default=[],
                        help='A folder RELEASE-BUILD of the 11 sound modules of one kernel (sound.py), repeatable')
    parser.add_argument('--bt-modules', type=Path, action='append', default=[],
                        help='A folder RELEASE-BUILD of the Bluetooth modules of one kernel (media_service.py), repeatable')
    parser.add_argument('--media-player', type=Path, help='a22x-media: the ARM64 musl player (media/build.sh)')
    parser.add_argument('--sound-switch', type=Path,
                        help="libasound_module_pcm_a22x_switch.so: the browser's sound output (media/build-switch.sh)")
    parser.add_argument('--ce-snapshot-helper', type=Path, help='Verified native Evolution read-only F2FS RAM snapshot candidate')
    parser.add_argument('--touch-firmware', type=Path, action='append', default=[],
                        help='Pinned touch firmware for /lib/firmware (allowlisted names and SHA-256)')
    parser.add_argument('--regulatory-db', type=Path, help='Folder with wireless-regdb regulatory.db and its .p7s (pinned)')
    parser.add_argument('--kernel-section', type=Path, help='Replacement boot-image kernel section (gzip Image + appended DTB)')
    parser.add_argument('--kernel-section-sha256', help='Exact SHA-256 pin of --kernel-section')
    parser.add_argument('--dtb-section', type=Path, help='Replacement boot-image DTB section (MTK table header + the same DTB)')
    parser.add_argument('--dtb-section-sha256', help='Exact SHA-256 pin of --dtb-section')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', default='1.1.0-dev')
    parser.add_argument('--dict-mib', type=int, choices=(8, 16, 32, 64), default=64)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    base = args.base.read_bytes()
    require(len(base) == PARTITION_SIZE and sha(base) == BASE_SHA, 'Unqualified base image')
    page, parts, original_end = parse(base)
    require(parts[1].startswith(b'\xfd7zXZ\x00'), 'Expected qualified XZ ramdisk')
    kernel_replacement = replace_kernel_and_dtb(parts, args)
    entries = read_cpio(lzma.decompress(parts[1]))
    byname = {entry[1]: entry for entry in entries}
    require(len(byname) == len(entries), 'Duplicate base CPIO entry')
    original = {name: (list(entry[0]), entry[2]) for name, entry in byname.items()}
    wifi_data = args.wifi_modules.read_bytes() if args.wifi_modules is not None else None
    module_admission = validate_kernel_modules(parts[0], entries, wifi_data)
    profile_data = (project / 'profiles/android-decrypt/samsung-a226b-a13.json').read_bytes()
    profile = json.loads(profile_data)
    profile_spec = importlib.util.spec_from_file_location('image_android_profiles', project / 'android_profiles.py')
    profile_module = importlib.util.module_from_spec(profile_spec); profile_spec.loader.exec_module(profile_module)
    profile_module.validate_profile(profile, profile_module.SAMSUNG_PROFILE)
    evo_profile_data = (project / 'profiles/android-decrypt/evolutionx-a226b-a16.json').read_bytes()
    evo_profile = profile_module.validate_profile(json.loads(evo_profile_data), profile_module.EVO_PROFILE)
    ce_snapshot = args.ce_snapshot_helper.read_bytes() if args.ce_snapshot_helper is not None else None
    if ce_snapshot is not None:
        require(64 <= len(ce_snapshot) <= 1 << 20 and ce_snapshot[:7] == b'\x7fELF\x02\x01\x01'
                and struct.unpack_from('<HHI',ce_snapshot,16) in ((2,183,1),(3,183,1)),
                'F2FS RAM snapshot native helper architecture')
        require(evo_profile.get('ce_session', {}).get('qualified') is True, 'F2FS RAM snapshot requires the Evolution session')
        evo_profile['ce_session']['ram_snapshot_sha256'] = sha(ce_snapshot)
        evo_profile_data = (json.dumps(evo_profile,indent=2)+'\n').encode()
    runtime_data = regular_input(args.runtime, 32 << 20)
    require(profile['bundle_sha256'] == evo_profile['bundle_sha256'] == sha(runtime_data), 'Runtime package changed')
    runtime_admission = validate_ce_rw_runtime(runtime_data, evo_profile, module_admission['kernel'])
    quota_additions, quota_admission = quota_module_inputs(args.quota_module_dir, evo_profile, module_admission['kernel'])
    require(profile['bootstrap_wrapper_sha256'] == sha((project/'decrypt_bootstrap.py').read_bytes()),
            'Bootstrap wrapper changed')
    ui = (project / 'ui/a22x-recovery-ui-aarch64').read_bytes()
    require(ui[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', ui, 18)[0] == 183, 'UI architecture')
    additions = {
        'init': ((project/'ramdisk/init').read_bytes(), 0o100755),
        'bin/recovery-ui': (ui, 0o100755),
        'etc/a22x-recovery/android-decrypt.json': (profile_data, 0o100644),
        'etc/a22x-recovery/android-decrypt-evox16.json': (evo_profile_data, 0o100644),
        'opt/a22x-recovery/android-decrypt-runtime.tar': (runtime_data, 0o100644),
    }
    additions['opt/a22x-recovery/web_packages.json'] = ((project/'web_packages.json').read_bytes(), 0o100644)
    if ce_snapshot is not None:
        additions['opt/a22x-recovery/a22x-data-ce-snapshot'] = (ce_snapshot, 0o100555)
    if args.panfrost_module is not None:
        payload = args.panfrost_module.read_bytes()
        # 2026-11-21: c0167265, the same source with a cacheable read-only mapping of exported buffers
        # (kernel tree commit 3606bd4388bb, artifacts/panfrost-cached-read-20261121); e3e25e60 before.
        require(sha(payload) in PANFROST_MODULES, 'Panfrost module hash mismatch')
        elf_module(payload, module_admission['kernel']['expected_vermagic'])
        additions['opt/a22x-recovery/panfrost.ko'] = (payload, 0o100644)
    # Sound (2026-11-20): the 11 modules of each kernel this image may run with, in a folder named
    # after its release and build number (sound.py picks it from uname); every one has the image's
    # vermagic.
    for folder in args.sound_modules:
        require(re.fullmatch(r'[0-9A-Za-z.+_-]+-[0-9]+', folder.name) is not None, 'Sound module folder name')
        names = sorted(p.name for p in folder.glob('*.ko'))
        require(names == sorted(n + '.ko' for n in SOUND_MODULES), 'Sound module set')
        for name in names:
            payload = regular_input(folder / name, 4 << 20)
            elf_module(payload, module_admission['kernel']['expected_vermagic'])
            additions[f'opt/a22x-recovery/sound-modules/{folder.name}/{name}'] = (payload, 0o100644)
    # Bluetooth and the media player (2026-11-22, the owner): the modules of each kernel, and the player
    # that media_service.py runs in the browser's engine with the media layer (media_packages.json).
    for folder in getattr(args, 'bt_modules', None) or []:
        require(re.fullmatch(r'[0-9A-Za-z.+_-]+-[0-9]+', folder.name) is not None, 'Bluetooth module folder name')
        names = sorted(p.name for p in folder.glob('*.ko'))
        require(names == sorted(n + '.ko' for n in BT_MODULES), 'Bluetooth module set')
        for name in names:
            payload = regular_input(folder / name, 4 << 20)
            elf_module(payload, module_admission['kernel']['expected_vermagic'])
            if name == 'btmtk_stp.ko':
                require(BT_EXAMPLE in payload and len(re.findall(rb'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', payload)) == 1,
                        'btmtk_stp names a BD address other than its example')
            additions[f'opt/a22x-recovery/bt-modules/{folder.name}/{name}'] = (payload, 0o100644)
    if getattr(args, 'media_player', None) is not None:
        player = regular_input(args.media_player, 512 << 10)
        require(player[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', player, 18)[0] == 183
                and b'/lib/ld-musl-aarch64.so.1' in player, 'Media player architecture')
        additions['opt/a22x-recovery/a22x-media'] = (player, 0o100755)
    # The browser's sound moves between the phone and Bluetooth headphones (2026-11-22, the owner).
    if getattr(args, 'sound_switch', None) is not None:
        plugin = regular_input(args.sound_switch, 256 << 10)
        require(plugin[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', plugin, 16)[0] == 3
                and struct.unpack_from('<H', plugin, 18)[0] == 183 and b'_snd_pcm_a22x_switch_open' in plugin
                and b'libc.musl-aarch64.so.1' in plugin, 'Sound switch plugin architecture')
        additions['opt/a22x-recovery/alsa/libasound_module_pcm_a22x_switch.so'] = (plugin, 0o100644)
    # exFAT made and checked by the recovery (2026-11-20, the owner): Arch Linux ARM's signed exfatprogs
    # 1.4.5 and util-linux-libs 2.42.4 (tools/fetch-fsck-tools.sh), run with the bundled glibc like fsck.fat.
    if getattr(args, "exfat_tools", None) is not None:
        for name, pinned in EXFAT_TOOLS.items():
            payload = regular_input(args.exfat_tools / name, 2 << 20)
            require(sha(payload) == pinned, 'exFAT tool hash mismatch: ' + name)
            library = name.startswith('lib')
            additions['opt/a22x-recovery/glibc/' + ('lib/' if library else 'bin/') + name] = (payload, 0o100644 if library else 0o100755)
            if not library:
                wrapper = ('#!/bin/sh\nunset LD_LIBRARY_PATH\nG=/opt/a22x-recovery/glibc\n'
                           'exec $G/lib/ld-linux-aarch64.so.1 --library-path $G/lib $G/bin/%s "$@"\n' % name).encode()
                additions['bin/' + name] = (wrapper, 0o100755)
    if args.wayland_compositor is not None:
        compositor = args.wayland_compositor.read_bytes()
        require(64 <= len(compositor) <= 256 << 10 and compositor[:6] == b'\x7fELF\x02\x01'
                and struct.unpack_from('<H',compositor,18)[0] == 183, 'Browser compositor architecture')
        additions['opt/a22x-recovery/web-compositor'] = (compositor, 0o100755)
    for path in getattr(args, 'touch_firmware', None) or []:
        payload = regular_input(path, 4 << 20)
        require(TOUCH_FIRMWARE.get(path.name) == sha(payload), 'Touch firmware is not allowlisted: ' + path.name)
        require('lib/firmware/' + path.name not in additions, 'Duplicate touch firmware')
        additions['lib/firmware/' + path.name] = (payload, 0o100644)
    if getattr(args, 'regulatory_db', None) is not None:
        for name, pinned in REGULATORY_DB.items():
            payload = regular_input(args.regulatory_db / name, 64 << 10)
            require(sha(payload) == pinned, 'Regulatory database is not the pinned one: ' + name)
            require('lib/firmware/' + name not in additions, 'Duplicate regulatory database')
            additions['lib/firmware/' + name] = (payload, 0o100644)
    additions.update(quota_additions)
    if wifi_data is not None:
        additions[WIFI_PATH] = (wifi_data, 0o100644)
    # Include every entry point that can format Android userdata. Inheriting
    # install/reset code from the older base would omit the password guard.
    # The generic ZIP runner also carries current admission guards; inheriting
    # it would keep old behavior even when the worktree's tests pass.
    modules = ['filesystem.py', 'android_data.py', 'android_profiles.py', 'android_decrypt.py', 'decrypt_prepare.py',
               'decrypt_bootstrap.py', 'decrypt_session.py', 'format_authorization.py',
               'install.py', 'samsung_firmware.py', 'android_gsi.py', 'zip_install.py', 'settings.py',
               'android_compat.py', 'android_transitions.py', 'android_modules.py',
               'file_archive.py', 'handoff.py', 'misc_store.py', 'wifi.py', 'flash.py', 'terminal.py', 'distro.py']
    modules += [str(path.relative_to(project)) for path in sorted((project/'decrypt_runtime').glob('*.py'))]
    # The Linux backup engine, whole: its parts call each other (2026-11-20, backups on every filesystem).
    modules += [str(path.relative_to(project)) for path in sorted((project/'backend').glob('*.py'))]
    modules.extend(('themes.py', 'web_cache.py', 'web_launch.py', 'web_session.py', 'web_downloads.py', 'android_twrp.py', 'android_package_registry.py', 'android_preferences.py', 'android_personal.py', 'android_migration.py', 'android_app_restore.py',
                    'clock.py', 'web_packages.json', 'web_gpu_packages.json', 'android_root_adb.py', 'file_types.py', 'bootimage.py', 'android_first_boot.py', 'root.py', 'migration_agent.dex', 'management.py', 'display.py', 'automount.py', 'sound.py', 'usb_files.py',
                    # 2026-11-20: backups on every filesystem; the base image's copies knew ext4 only.
                    'storage.py', 'sdcard.py', 'bcb.py', 'a22x_adapter.py', 'operation_lock.py', 'screenshot.py', 'adbd.py', 'apk_queue.py', 'boot_splash.py', 'nofbe.py', 'sysinfo.py', 'android_userdata.py', 'identity_backup.py', 'saved_boot.py',
                    # 2026-11-21: logical partitions sized to the 4 KiB block (#9).
                    'lp_metadata.py',
                    # 2026-11-22: Bluetooth and the media player (the owner).
                    'media_service.py', 'dbus_min.py', 'media_packages.json', 'media_full_packages.json',
                    # 2026-11-22: Bluetooth's pairings kept in misc past a restart (the owner).
                    'bt_pairings.py',
                    # 2026-11-22: incremental payloads (applied to a copy) and payloads in Flash.
                    'android_rom.py',
                    # 2026-11-22: what is installed, for the shell's home page and Systems tab.
                    'systems_overview.py'))
    for name in modules:
        additions['opt/a22x-recovery/' + name] = ((project/name).read_bytes(), 0o100644)
    # 2026-11-22: platform/ (what a new Linux system gets: a22x-firstboot.sh, the build scripts and their
    # keys) stayed the base's. A change to a22x-firstboot.sh and a new build/a22x-phrog-package.sh never
    # reached the image, and Arch built Phrog on the phone for 40 minutes. Its scripts are the worktree's.
    platform_files = [*project.glob('platform/*.sh'), *(p for p in project.glob('platform/build/**/*') if p.is_file())]
    for path in sorted(platform_files):
        additions['opt/a22x-recovery/' + str(path.relative_to(project))] = (
            path.read_bytes(), 0o100755 if path.suffix == '.sh' else 0o100644)
    # 2026-11-21: the MTP sandbox checked its lent lease with LOCK_EX, which turned the supervisor's shared
    # lease exclusive and kept the terminal and copies out while the card was shared. It is built here
    # from the worktree, static, and the USB runtime manifest names its hash.
    with tempfile.TemporaryDirectory() as work:
        sandbox_path = Path(work) / 'a22x-mtp-sandbox'
        subprocess.run(['aarch64-linux-gnu-gcc', '-static', '-O2', '-Wall', '-Wextra', '-Werror', '-s', '-o', str(sandbox_path),
                        str(project/'usb/mtp_sandbox.c')], check=True)
        sandbox = sandbox_path.read_bytes()
    require(sandbox[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', sandbox, 18)[0] == 183,
            'The MTP sandbox must be an AArch64 program')
    phoff, = struct.unpack_from('<Q', sandbox, 32); phentsize, phnum = struct.unpack_from('<HH', sandbox, 54)
    require(all(struct.unpack_from('<I', sandbox, phoff + n * phentsize)[0] != 3 for n in range(phnum)),
            'The MTP sandbox must be static (no PT_INTERP)')
    runtime_name = 'etc/a22x-recovery/usb-files-runtime.json'
    require(runtime_name in byname, 'The base image has no USB runtime manifest')
    usb_runtime = json.loads(byname[runtime_name][2])
    require(usb_runtime.get('schema') == 'a22x.usb-files.runtime.v1' and usb_runtime['sandbox']['path'] == '/bin/a22x-mtp-sandbox',
            'USB runtime manifest changed')
    usb_runtime['sandbox'].update(sha256=sha(sandbox), version='a22x-mtp-sandbox 3')
    additions['bin/a22x-mtp-sandbox'] = (sandbox, 0o100700)
    additions[runtime_name] = ((json.dumps(usb_runtime, indent=2, sort_keys=True) + '\n').encode(), 0o100644)
    # 2026-11-19: clock.py was left out of this list and the image kept the base's older copy while
    # the tests passed. Every helper of the worktree that the image carries must be the worktree's.
    for path in sorted([*project.glob('*.py'), *project.glob('*.json'), *project.glob('backend/*.py'), *platform_files]):
        name = 'opt/a22x-recovery/' + str(path.relative_to(project))
        if name in byname and name not in additions:
            require(byname[name][2] == path.read_bytes(), 'Image would keep an older ' + path.name + '; add it to the helper list')
    inode = max(entry[0][0] for entry in entries) + 1
    changed = {}
    # Allocate new inode IDs from the full original image, preserving prior
    # metadata even if the deleted theme happened to have the highest inode.
    entries, removed = remove_bundled_themes(entries)
    entries, removed_caches = remove_source_caches(entries)
    removed.update(removed_caches)
    byname = {entry[1]: entry for entry in entries}
    overlay_scope = {'complete': False, 'format': 'tar-additions-and-replacements-only',
                     'deletions': sorted(removed), 'deletion_manifest': 'REMOVED.json'}
    def put(name, data, mode):
        nonlocal inode
        require(name and not name.startswith('/') and '..' not in Path(name).parts, 'CPIO path')
        parent = name.rpartition('/')[0]
        if parent and parent not in byname: put(parent, b'', 0o40755)
        if name in byname:
            entry = byname[name]
            require(stat.S_IFMT(entry[0][1]) == stat.S_IFMT(mode), 'CPIO type changed')
            entry[2] = data
        else:
            entry = [[inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0], name, data]
            inode += 1; entries.append(entry); byname[name] = entry
        changed[name] = {'before': sha(original[name][1]) if name in original else None,
                         'after': sha(data), 'size_bytes': len(data)}
    for name, (data, mode) in additions.items(): put(name, data, mode)
    require(sys.implementation.cache_tag == 'cpython-314', 'Image bytecode needs Python 3.14')
    for name in modules:
        if not name.endswith('.py'):
            continue  # data beside the helpers (package lists, the migration agent's dex)
        image_name = 'opt/a22x-recovery/' + name
        source = byname[image_name][2]
        # Syntax validation is retained; redundant pyc copies stay out of the image.
        compile(source, '/' + image_name, 'exec', dont_inherit=True)
    module_admission = validate_kernel_modules(parts[0], entries)
    build = json.loads(byname['etc/a22x-recovery/build.json'][2])
    build.update(version=args.version, decryption=True,
                 installer_android_mount=True, installer_userdata_write=False,
                 android_decrypt={'profile': profile['profile_id'], 'android_user': 0,
                    'read_only': True, 'userdata_filesystem': 'f2fs',
                    'authentication': 'native-gatekeeper-or-none-keymaster',
                     'profiles': [profile['profile_id'], evo_profile['profile_id']],
                     'exact_evolution16_none_password_persistent_mount': 'PENDING',
                    'credential_channel': 'anonymous-native-fd',
                    'credential_types': profile['credential_types'],
                    'credential_discovery': profile.get('credential_discovery') is True,
                    'pattern_hardware_test': 'PENDING',
                    'persistent_session_hardware_test': 'PENDING',
                    'gsi_android14_16': 'UNQUALIFIED'})
    # Pin the complete Python closure from the actual image, including inherited
    # modules. A worktree may intentionally differ from an inherited base module.
    actual_python = {name.removeprefix('opt/a22x-recovery/'): sha(entry[2])
                     for name, entry in byname.items()
                     if name.startswith('opt/a22x-recovery/') and name.endswith('.py')
                     and stat.S_ISREG(entry[0][1])}
    source_metadata = build.setdefault('source_sha256', {})
    for name in list(source_metadata):
        if name.endswith('.py') and name not in actual_python:
            del source_metadata[name]
    source_metadata.update(actual_python)
    build['source_sha256']['ui/recovery_ui.c'] = sha((project/'ui/recovery_ui.c').read_bytes())
    build['ui_binary_sha256'] = sha(ui)
    build['kernel_modules'] = module_admission
    if kernel_replacement is not None:
        build['kernel_replacement'] = kernel_replacement
    build['ce_rw_runtime'] = runtime_admission
    build['ce_rw_quota_modules'] = quota_admission
    enabled_rw_profiles = [p['profile_id'] for p in (profile, evo_profile)
                           if p.get('ce_rw', {}).get('qualified') is True]
    enabled_reusable_profiles = [p['profile_id'] for p in (profile, evo_profile)
                                 if p.get('ce_session', {}).get('qualified') is True]
    if enabled_reusable_profiles:
        cap = evo_profile['ce_session']
        with tarfile.open(fileobj=io.BytesIO(runtime_data)) as archive:
            root = archive.extractfile('android-root/ROOT-MANIFEST.json').read()
            require(sha(root) == evo_profile['root_manifest_sha256'], 'Reusable root manifest pin')
            inventory = json.loads(root)
            name = cap['helper'].lstrip('/')
            item = inventory['files'][name]
            member = archive.getmember('android-root/rootfs/' + name)
            require(member.isfile() and member.uid == member.gid == 0
                    and member.mode == 0o555, 'Reusable native helper ownership or mode')
            binary = archive.extractfile(member).read()
            require(item['sha256'] == cap['helper_sha256'] == sha(binary)
                    and item['mode'] == 0o555 and item['size'] == len(binary)
                    and 64 <= len(binary) <= 8 << 20 and binary[:7] == b'\x7fELF\x02\x01\x01'
                    and struct.unpack_from('<HHI', binary, 16) in ((2,183,1),(3,183,1)),
                    'Reusable native helper pin or architecture')
    build['android_decrypt'].update(
        ce_rw_enabled_profiles=enabled_rw_profiles,
        default_access_mode='ro',
        read_only=not bool(enabled_rw_profiles),
        access_modes_by_profile={p['profile_id']: (['ro', 'rw'] if p['profile_id'] in enabled_rw_profiles else ['ro'])
                                 for p in (profile, evo_profile)},
        rw_qualified_credential_types_by_profile={
            p['profile_id']: p.get('ce_rw_qualified_credential_types', [])
            for p in (profile, evo_profile) if p['profile_id'] in enabled_rw_profiles},
        reusable_session_profiles=enabled_reusable_profiles,
        new_session_after_unmount='profile-and-credential-dependent',
        reusable_session_credential_types_by_profile={name:['password'] for name in enabled_reusable_profiles},
        reusable_session_behavior_by_profile={
            name: {'password': {
                'new_session_after_unmount':'same-boot-native-session',
                'cached_unlock_lifetime':'current-recovery-boot-native-locked-memory',
                'ordinary_unmount':'filesystem-suspend',
                'destructive_cleanup':'terminal-native-key-and-runtime-close'}}
            for name in enabled_reusable_profiles},
        legacy_session_behavior={
            'new_session_after_unmount':'recovery-reboot-required',
            'ordinary_unmount':'terminal-session-close',
            'cached_unlock_lifetime':None},
        password_policy_setting='android_password_policy',
        password_policies=['each_mount', 'startup', 'first_access'],
        default_password_policy='each_mount',
        current_image_hardware_test='PENDING')
    # These are separate from the existing clean installers. No transition is
    # qualified until a source -> target hardware receipt is admitted.
    build['android_compatibility'] = {'available': True, 'read_only': True,
        'preserve_install_available': False, 'qualified_transition_count': 0,
        'scope': 'declarative-images-and-regular-offline-evidence'}
    build['android_module_rescue'] = {'available': True,
        'requires': 'authenticated-user0-data-and-reviewed-framework-version',
        'mutation_requires': 'read-write-mount-and-current-reviewed-plan',
        'magisk_zip_install_available': False, 'hardware_qualification': 'PENDING'}
    build['android_userdata_format_authorization'] = {
        'required_for_protected_android': True,
        'credential_check': 'fresh-native-password-authentication',
        'credential_channel': 'anonymous-native-fd',
        'confirmation': 'separate-final-destructive-confirmation',
        'authorization': 'boot-volume-session-auth-and-mount-generation-purpose-bound-one-use',
        'live_format_test': 'NOT_PERFORMED'}
    build['ui_source_sha256'] = {
        str(p.relative_to(project)): sha(p.read_bytes())
        for p in sorted((project/'ui').iterdir())
        if p.is_file() and (p.suffix in ('.c', '.h') or p.name == 'Makefile')
        and not p.name.startswith('test_')
    }
    build['android_userdata_logical_backup'] = {'available': True, 'requires': 'authenticated-user0-ce-rw', 'destination': '/media/0/A22xDataBackups', 'restore_supported': False}
    build['removed_cpio_entries'] = removed
    build['ram_overlay'] = overlay_scope
    put('etc/a22x-recovery/build.json', (json.dumps(build, indent=2, sort_keys=True)+'\n').encode(), 0o100644)
    for name, (fields, data) in original.items():
        if name in removed:
            require(name not in byname, 'Removed theme reintroduced')
            continue
        require(name in byname, 'Original entry lost')
        if name not in changed: require(byname[name][0] == fields and byname[name][2] == data, 'Unlisted mutation')
    require(validate_kernel_modules(parts[0], entries) == module_admission, 'Final module set changed')
    raw = write_cpio(entries)
    roundtrip = read_cpio(raw)
    require(len(roundtrip) == len(entries), 'CPIO roundtrip count')
    require(validate_kernel_modules(parts[0], roundtrip) == module_admission, 'Roundtrip module set changed')
    for expected, actual in zip(entries, roundtrip):
        require(expected[1:] == actual[1:], 'CPIO payload roundtrip')
        normalized = list(expected[0]); normalized[6] = len(expected[2]); normalized[11] = len(expected[1].encode()) + 1
        require(actual[0] == normalized, 'CPIO metadata roundtrip')
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output/'builder.py').write_bytes(Path(__file__).read_bytes())
    (args.output/'DELTA.json').write_text(json.dumps(changed, indent=2, sort_keys=True)+'\n')
    (args.output/'REMOVED.json').write_text(json.dumps(removed, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'phase':'compressing', 'raw_cpio_bytes':len(raw), 'dict_mib':args.dict_mib}), flush=True)
    compressed = compress_ramdisk(raw, args.dict_mib)
    require(lzma.decompress(compressed) == raw, 'Ramdisk roundtrip')
    parts[1] = compressed
    header = bytearray(base[:page])
    struct.pack_into('<I', header, 8, len(parts[0]))
    struct.pack_into('<I', header, 16, len(compressed))
    struct.pack_into('<I', header, 1648, len(parts[4]))
    struct.pack_into('<Q', header, 1636, page + sum(align(len(p),page) for p in parts[:3]) if parts[3] else 0)
    header[576:608] = digest(parts)
    allowed = set(range(16,20)) | set(range(576,608)) | set(range(1636,1644))
    if kernel_replacement is not None:
        allowed |= set(range(8,12)) | set(range(1648,1652))
    require(all(a == b or i in allowed for i,(a,b) in enumerate(zip(base[:page],header))), 'Unlisted header mutation')
    image = bytearray(header)
    for part in parts:
        image.extend(part); image.extend(bytes(-len(image) % page))
    unsigned_bytes = len(image)
    # Preserve size evidence even if the strict partition budget refuses the build.
    (args.output/'ramdisk.xz').write_bytes(compressed)
    (args.output/'SIZE.json').write_text(json.dumps({'unsigned_bytes':unsigned_bytes,
        'ramdisk_xz_bytes':len(compressed),'reserved_bytes':PARTITION_SIZE-unsigned_bytes,
        'required_reserve':131072,'within_budget':unsigned_bytes < PARTITION_SIZE-131072},indent=2)+'\n')
    require(unsigned_bytes < PARTITION_SIZE - 131072, 'Recovery image exceeds partition budget')
    target = args.output / 'recovery.img'; target.write_bytes(image)
    commands = []
    for command in [
        ['avbtool','add_hash_footer','--image',str(target),'--partition_name','recovery',
         '--partition_size',str(PARTITION_SIZE),'--algorithm','NONE','--salt',SALT],
        ['avbtool','verify_image','--image',str(target)]]:
        run = subprocess.run(command, capture_output=True, text=True)
        commands.append({'argv': command, 'returncode':run.returncode, 'stdout':run.stdout, 'stderr':run.stderr})
        require(run.returncode == 0, 'AVB command failed')
    final = target.read_bytes(); new_page, new_parts, new_end = parse(final)
    require(len(final) == PARTITION_SIZE and new_page == page and new_parts == parts, 'Final image roundtrip')
    _, old_parts, _ = parse(base)
    require(all(new_parts[i] == old_parts[i] for i in (2,3)), 'Second stage or DTBO changed')
    if kernel_replacement is None:
        require(all(new_parts[i] == old_parts[i] for i in (0,4)), 'Kernel or device tree changed')
    else:
        require(sha(new_parts[0]) == kernel_replacement['kernel_section_sha256']
                and sha(new_parts[4]) == kernel_replacement['dtb_section_sha256'], 'Kernel/DTB replacement roundtrip')
    # This additions/replacements TAR cannot express deletions. It is partial;
    # build.json/RESULT explicitly identify REMOVED.json and the omitted paths.
    # No credentials, phone keys or runtime receipts belong in this overlay.
    with tarfile.open(args.output/'ram-overlay.tar', 'w') as archive:
        for name in sorted(changed):
            entry = byname[name]
            if not stat.S_ISREG(entry[0][1]): continue
            info = tarfile.TarInfo(name); info.size = len(entry[2]); info.mode = stat.S_IMODE(entry[0][1])
            info.uid = info.gid = 0; info.mtime = 0
            archive.addfile(info, io.BytesIO(entry[2]))
    source_pins = dict(changed)
    for relative in actual_python:
        name = 'opt/a22x-recovery/' + relative
        if name not in source_pins:
            entry = byname[name]
            source_pins[name] = {'before': sha(original[name][1]) if name in original else None,
                                 'after': sha(entry[2]), 'size_bytes': len(entry[2]),
                                 'inherited': True}
    report = {'schema':'a22x.decrypt-image-build.v1', 'base_sha256':BASE_SHA,
        'image_sha256':sha(final), 'image_bytes':len(final), 'unsigned_bytes':unsigned_bytes,
        'reserved_bytes':PARTITION_SIZE-unsigned_bytes, 'ramdisk_xz_bytes':len(compressed),
        'kernel_dtb_dtbo_unchanged':kernel_replacement is None, 'kernel_replacement':kernel_replacement,
        'header_only_listed_fields':True,
        'kernel_modules':module_admission,
        'removed_cpio_entries':removed, 'ram_overlay':overlay_scope,
        'all_unlisted_cpio_entries_unchanged':True, 'avb_verified':True,
        'persistent_session_hardware_test':'PENDING',
        'overlay_sha256':sha((args.output/'ram-overlay.tar').read_bytes()),
        'profile_sha256':sha(profile_data), 'sources':source_pins,
        'source_scope':'all-replaced-files-and-complete-runtime-python-closure',
        'python_source_count':len(actual_python), 'delta_manifest':'DELTA.json'}
    (args.output/'RESULT.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    (args.output/'COMMANDS.json').write_text(json.dumps(commands, indent=2)+'\n')
    (args.output/'SHA256SUMS').write_text(sha(final)+'  recovery.img\n')
    print(json.dumps({k:v for k,v in report.items() if k != 'sources'}), flush=True)
if __name__ == '__main__':
    main()
