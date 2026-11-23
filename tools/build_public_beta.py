#!/usr/bin/env python3
"""Public beta of recovery 1.1 from a verified device-feedback image (no developer data).

Starts from an exact, AVB-verified device-feedback image and:
  * swaps in a kernel built with CONFIG_UNICODE (same release) and every loadable module
    rebuilt for it (quota_tree, quota_v2, a22x_spmfw, panfrost, the four Wi-Fi modules);
  * leaves out Android decryption: the runtime holds files taken from the developer's phone
    firmware, and both decrypt profiles go with it, so the recovery does not offer it;
  * applies the public-image rules of tools/build-image.sh: no built-in SSH key, the stock
    profile is unqualified and names no eMMC, the Bluetooth address is zeros (conn-start.sh then
    derives one from the phone's own storage chip), and build records name /build, not $HOME.
The DTB, the ramdisk layout and every other file stay as in the base image.
"""
import argparse
import gzip
import hashlib
import io
import json
import lzma
import os
import re
from pathlib import Path
import subprocess
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_decrypt_image as b  # noqa: E402

REMOVED = ('opt/a22x-recovery/android-decrypt-runtime.tar', 'etc/a22x-recovery/android-decrypt.json',
           'etc/a22x-recovery/android-decrypt-evox16.json')
MODULES = {'lib/modules/quota_tree.ko': 'quota_tree.ko', 'lib/modules/quota_v2.ko': 'quota_v2.ko',
           'lib/modules/a22x_spmfw.ko': 'a22x_spmfw.ko', 'opt/a22x-recovery/panfrost.ko': 'panfrost.ko'}
WIFI = 'opt/a22x-recovery/platform/wifi-modules.tar.xz'
PLATFORM = 'opt/a22x-recovery/platform/platform-files.tar.xz'
SOUND = 'opt/a22x-recovery/sound-modules'
KEYS = 'etc/a22x-recovery/authorized_keys'
STOCK = 'etc/a22x-recovery/install-stock-profile.json'
PLATFORM_PROFILE = 'etc/a22x-recovery/distro-platform.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def cids_in(profile):
    found = set()

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == 'parent_cid_sha256' and isinstance(item, str):
                    found.add(item)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(profile)
    return found


NEUTRAL_BT = b'00:11:22:33:44:55'


def neutral_path(home):
    """A path as long as HOME that names no one (2026-11-22 audit: the Wi-Fi modules inside the platform
    archives of beta19-22 named /home/<builder>/...): /build, then "/." pairs, and one more "/" when the
    length is odd. A module's file name keeps its offset and size, so the module is otherwise unchanged."""
    text = '/build'
    b.require(len(home) >= len(text), 'Builder home too short to scrub')
    pad = len(home) - len(text)
    return (text + '/.' * (pad // 2) + '/' * (pad % 2)).encode()


def scrub_binary(name, data, home, neutral):
    """DATA without the builder's home: only unsigned ELF files (modules' __FILE__ strings) may carry it."""
    if home not in data:
        return data
    b.require(data[:4] == b'\x7fELF' and b'Module signature appended' not in data, 'Builder path left in ' + name)
    return data.replace(home, neutral)


def scrub_archive(name, data, home, neutral):
    """A .tar.xz of the image with the builder's home scrubbed out of its members; the archive as it was
    when none names it. Returns (archive, {member: {sha256, bytes}} of the members changed)."""
    patched = {}
    out = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:xz') as src, \
         tarfile.open(fileobj=out, mode='w:xz', format=src.format, preset=9) as dst:
        for member in src.getmembers():
            payload = src.extractfile(member).read() if member.isfile() else None
            if payload is not None and home in payload:
                payload = scrub_binary(name + ':' + member.name, payload, home, neutral)
                patched[member.name] = {'sha256': sha(payload), 'bytes': len(payload)}
                member.size = len(payload)
            dst.addfile(member, io.BytesIO(payload) if payload is not None else None)
    return (out.getvalue() if patched else data), patched


def zero_bt_address(data, developer, home=b'', neutral=b''):
    """Rebuild the platform archive with bt_addr = zeros. A module whose parameter help quotes the
    developer's address as its example gets a neutral address of the same length (unsigned module,
    .modinfo text only); any other file naming that address stops the build."""
    out, patched = io.BytesIO(), {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:xz') as src, \
         tarfile.open(fileobj=out, mode='w:xz', format=src.format, preset=9) as dst:
        found = False
        for member in src.getmembers():
            payload = src.extractfile(member).read() if member.isfile() else None
            if member.name == 'opt/a22x-conn/bt_addr':
                payload, found = b'00:00:00:00:00:00\n', True
            elif payload is not None and developer in payload.upper():
                b.require(member.name.endswith('.ko') and payload.count(developer) == 1
                          and b'Module signature appended' not in payload, 'Developer address in ' + member.name)
                payload = payload.replace(developer, NEUTRAL_BT)
                patched[member.name] = {'sha256': sha(payload), 'bytes': len(payload)}
            if payload is not None and home and home in payload:
                payload = scrub_binary('platform:' + member.name, payload, home, neutral)
                patched[member.name] = {'sha256': sha(payload), 'bytes': len(payload)}
            if payload is not None:
                member.size = len(payload)
            dst.addfile(member, io.BytesIO(payload) if payload is not None else None)
    b.require(found, 'Platform archive has no bt_addr')
    return out.getvalue(), patched


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--base', type=Path, required=True)
    ap.add_argument('--base-sha256', required=True)
    ap.add_argument('--kernel-image', type=Path, required=True, help='Uncompressed arm64 Image (CONFIG_UNICODE=y)')
    ap.add_argument('--modules', type=Path, required=True, help='Directory with the rebuilt modules and wifi-modules.tar.xz')
    ap.add_argument('--version', required=True)
    ap.add_argument('--scrub', action='append', default=[], help='FOLDER: replaced by /build in build records')
    ap.add_argument('--test-adb', type=Path, help='Field-test images only: adbd.py with the test no-auth patch; also adds its flag file')
    ap.add_argument('--extra-cmdline', default='', help='Test variants only: appended to the header command line')
    ap.add_argument('--sound-modules', type=Path, action='append', default=[],
                    help='RELEASE-BUILD folder of the 11 sound modules of the beta kernel; replaces the base\'s sets')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    base = args.base.read_bytes()
    b.require(len(base) == b.PARTITION_SIZE and sha(base) == args.base_sha256, 'Base image pin')
    page, parts, _ = b.parse(base)
    entries = b.read_cpio(lzma.decompress(parts[1]))
    byname = {e[1]: e for e in entries}
    b.require(len(byname) == len(entries), 'Duplicate CPIO entry')
    # The builder's home and name (2026-11-22 audit): scrubbed from records, modules and the archives the
    # image carries, then looked for everywhere once more.
    home = os.path.normpath(os.path.expanduser('~'))
    home_bytes = home.encode() if home.count('/') >= 2 else b''
    neutral = neutral_path(home) if home_bytes else b''
    user = Path(home).name if home_bytes and len(Path(home).name) >= 4 else ''

    # Kernel: same release as the base, new image; the base DTB stays appended and in the DTB section.
    old = b.kernel_identity(parts[0])
    dtb = b.mtk_dtb_table(parts[4])
    decoder = __import__('zlib').decompressobj(31)
    decoder.decompress(parts[0], (128 << 20) + 1)
    b.require(decoder.unused_data == dtb, 'Base appended DTB differs from its DTB section')
    image = args.kernel_image.read_bytes()
    b.require(not home_bytes or home_bytes not in image, 'Builder path in the kernel image')
    kernel = gzip.compress(image, 9, mtime=0) + dtb
    new = b.kernel_identity(kernel)
    b.require(new['release'] == old['release'], 'Kernel release differs from the base')

    changed = {}

    def replace(name, data):
        entry = byname[name]
        changed[name] = {'before': sha(entry[2]), 'after': sha(data), 'size_bytes': len(data)}
        entry[2] = data

    for name, file in MODULES.items():
        data = (args.modules / file).read_bytes()
        b.elf_module(data, new['expected_vermagic'])
        replace(name, data)
    wifi = (args.modules / 'wifi-modules.tar.xz').read_bytes()
    if home_bytes:
        wifi, _ = scrub_archive(WIFI, wifi, home_bytes, neutral)
    replace(WIFI, wifi)

    # Sound (2026-11-20): the base carries the modules of its own kernel build; the beta kernel's
    # sets replace them (sound.py picks the folder of the running build).
    if args.sound_modules:
        prefix = SOUND + '/'
        dropped = [e for e in entries if e[1].startswith(prefix)]
        for entry in dropped:
            changed[entry[1]] = {'before': sha(entry[2]), 'after': None, 'size_bytes': 0}
        entries = [e for e in entries if not e[1].startswith(prefix)]
        byname = {e[1]: e for e in entries}
        b.require(SOUND in byname, 'Base has no sound module folder')
        inode = max(e[0][0] for e in entries) + 1
        for folder in args.sound_modules:
            b.require(re.fullmatch(r'[0-9A-Za-z.+_-]+-[0-9]+', folder.name) is not None, 'Sound module folder name')
            names = sorted(path.name for path in folder.glob('*.ko'))
            b.require(names == sorted(n + '.ko' for n in b.SOUND_MODULES), 'Sound module set')
            additions = [(prefix + folder.name, 0o40755, b'')]
            for name in names:
                data = (folder / name).read_bytes()
                b.elf_module(data, new['expected_vermagic'])
                additions.append((prefix + folder.name + '/' + name, 0o100644, data))
            for name, mode, data in additions:
                entries.append([[inode, mode, 0, 0, 2 if mode & 0o40000 else 1, 0, len(data), 0, 0, 0, 0, len(name) + 1, 0], name, data])
                byname[name] = entries[-1]
                changed[name] = {'before': None, 'after': sha(data), 'size_bytes': len(data)}
                inode += 1

    stock = json.loads(byname[STOCK][2])
    forbidden = cids_in(stock)
    stock.update(qualified=False, blockers=['STOCK_PROFILE_OF_ANOTHER_PHONE'], protected_prefixes={})
    stock_text = json.dumps(stock, indent=2, sort_keys=True) + '\n'
    for cid in forbidden:
        stock_text = stock_text.replace(cid, '')
    replace(STOCK, stock_text.encode())
    replace(KEYS, b'')
    old_bt = None
    with tarfile.open(fileobj=io.BytesIO(byname[PLATFORM][2]), mode='r:xz') as t:
        old_bt = t.extractfile('opt/a22x-conn/bt_addr').read().strip()
    b.require(len(old_bt) == len(NEUTRAL_BT), 'Unexpected bt_addr format')
    platform_archive, patched = zero_bt_address(byname[PLATFORM][2], old_bt.upper(), home_bytes, neutral)
    replace(PLATFORM, platform_archive)
    # The profile pins every platform file's SHA-256 and size: a module changed above must be pinned
    # anew, or installing Linux from this image stops at PLATFORM_BUNDLE_INVALID (live on beta20,
    # 2026-11-22: opt/a22x-conn/btmtk_stp.ko).
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import distro  # the project's own seal (the digest of the profile without its seal field)
    profile = json.loads(byname[PLATFORM_PROFILE][2])
    distro.check_seal(profile)
    if patched:
        profile = {key: item for key, item in profile.items() if key != 'seal'}
        for entry in profile.get('entries', []):
            if entry.get('path') in patched:
                entry.update(patched.pop(entry['path']))
        b.require(not patched, 'Changed platform files the profile does not name: ' + ', '.join(sorted(patched)))
        profile = distro.seal(profile)
        distro.check_seal(profile)
        replace(PLATFORM_PROFILE, (json.dumps(profile, indent=0) + '\n').encode())

    if args.test_adb is not None:
        patched = args.test_adb.read_bytes()
        b.require(b"TEST_NO_AUTH = Path(os.environ.get('A22X_ADB_TEST_NO_AUTH_FLAG'," in patched, 'Unexpected test adbd')
        replace('opt/a22x-recovery/adbd.py', patched)
        template = byname[KEYS]
        flag = [list(template[0]), 'etc/a22x-recovery/adb-test-no-auth', b'']
        flag[0][0] = max(e[0][0] for e in entries) + 1
        flag[0][1] = 0o100644
        b.require(flag[1] not in byname, 'Flag already present')
        entries.append(flag)
        byname[flag[1]] = flag
        changed[flag[1]] = {'before': None, 'after': sha(b''), 'size_bytes': 0}

    removed = []
    for name in REMOVED:
        b.require(name in byname, 'Expected entry missing: ' + name)
        removed.append({'path': name, 'sha256': sha(byname[name][2])})
    entries = [e for e in entries if e[1] not in REMOVED]
    byname = {e[1]: e for e in entries}

    # The builder's home is always scrubbed, not only when asked (2026-11-22 audit: beta19's records
    # kept /home/<builder>/... where --scrub was not given).
    scrubs = sorted({os.path.normpath(f) for f in args.scrub + [home] if f.count('/') >= 2}, key=len, reverse=True)
    user_word = re.compile(r'\b' + re.escape(user) + r'\b') if user else None

    def scrub_text(text):
        for folder in scrubs:
            text = text.replace(folder, '/build')
        # the name alone too: "<builder>@buildhost" and KBUILD_BUILD_USER in kernel records (beta19-22)
        return user_word.sub('builder', text) if user_word else text
    for name, entry in list(byname.items()):
        if name.startswith('etc/a22x-recovery/') and name.endswith('.json'):
            text = entry[2].decode()
            scrubbed = scrub_text(text)
            if scrubbed != text and name != 'etc/a22x-recovery/build.json':
                replace(name, scrubbed.encode())

    # No text the image carries may name the builder's home; kernel modules built without
    # -ffile-prefix-map still do, and are listed in build.json until the kernel is built so.
    host_paths_in_binaries = []
    if home_bytes:
        for entry in list(entries):
            if entry[1] == 'etc/a22x-recovery/build.json' or home_bytes not in entry[2]:
                continue  # build.json is scrubbed just below
            replace(entry[1], scrub_binary(entry[1], entry[2], home_bytes, neutral))
            host_paths_in_binaries.append(entry[1])
    build = json.loads(byname['etc/a22x-recovery/build.json'][2])
    build['version'] = args.version
    build['decryption'] = False
    build['public_beta'] = {
        'base_image_sha256': args.base_sha256, 'kernel_raw_sha256': new['raw_sha256'],
        'kernel_release': new['release'], 'android_decryption': 'not included',
        'removed': removed, 'ssh_keys': 0, 'stock_profile': 'unqualified', 'bt_addr': 'zeros',
        'adb_test_no_auth': args.test_adb is not None, 'builder_path_scrubbed_in_binaries': host_paths_in_binaries}
    build_text = scrub_text(json.dumps(build, indent=2, sort_keys=True) + '\n')
    replace('etc/a22x-recovery/build.json', build_text.encode())

    # Nothing that names the developer's phone may remain.
    secrets = set(forbidden) | ({old_bt.decode()} if old_bt and old_bt != b'00:00:00:00:00:00' else set())
    for entry in entries:
        for value in secrets:
            b.require(value.encode() not in entry[2] and value.upper().encode() not in entry[2], 'Developer identity left in ' + entry[1])
        if entry[1].endswith(('.tar.xz',)):
            with tarfile.open(fileobj=io.BytesIO(entry[2]), mode='r:xz') as t:
                for m in t.getmembers():
                    if m.isfile():
                        payload = t.extractfile(m).read()
                        for value in secrets:
                            b.require(value.encode() not in payload, f'Developer identity left in {entry[1]}:{m.name}')
    if home_bytes:
        name_bytes = re.compile(rb'\b' + re.escape(user.encode()) + rb'\b') if user else None
        for entry in entries:
            b.require(home_bytes not in entry[2], 'Builder path left in ' + entry[1])
            if name_bytes and entry[2][:4] != b'\x7fELF' and name_bytes.search(entry[2]):
                b.require(False, 'Builder name left in ' + entry[1])
            if entry[1].endswith('.tar.xz'):
                with tarfile.open(fileobj=io.BytesIO(entry[2]), mode='r:xz') as t:
                    for m in t.getmembers():
                        if m.isfile():
                            b.require(home_bytes not in t.extractfile(m).read(), f'Builder path left in {entry[1]}:{m.name}')
    module_admission = b.validate_kernel_modules(kernel, entries)

    raw = b.write_cpio(entries)
    compressed = b.compress_ramdisk(raw)
    b.require(lzma.decompress(compressed) == raw, 'Ramdisk roundtrip')
    parts[0], parts[1] = kernel, compressed
    header = bytearray(base[:page])
    import struct
    struct.pack_into('<I', header, 8, len(parts[0]))
    struct.pack_into('<I', header, 16, len(parts[1]))
    struct.pack_into('<Q', header, 1636, page + sum(b.align(len(p), page) for p in parts[:3]) if parts[3] else 0)
    header[576:608] = b.digest(parts)
    allowed = set(range(8, 12)) | set(range(16, 20)) | set(range(576, 608)) | set(range(1636, 1644))
    if args.extra_cmdline:
        # Samsung's LK passes only the 512-byte header command line, not the v2 extra field.
        main = bytes(header[64:576]).rstrip(b'\0')
        added = main + b' ' + args.extra_cmdline.encode()
        b.require(len(added) < 512 and all(32 <= c < 127 for c in added), 'Test command line does not fit')
        header[64:576] = added + bytes(512 - len(added))
        allowed |= set(range(64, 576))
    b.require(all(x == y or i in allowed for i, (x, y) in enumerate(zip(base[:page], header))), 'Unlisted header mutation')
    image_out = bytearray(header)
    for part in parts:
        image_out.extend(part)
        image_out.extend(bytes(-len(image_out) % page))
    b.require(len(image_out) < b.PARTITION_SIZE - 131072, 'Recovery image exceeds partition budget')
    args.output.mkdir(parents=True, exist_ok=False)
    target = args.output / 'recovery.img'
    target.write_bytes(image_out)
    for command in (['avbtool', 'add_hash_footer', '--image', str(target), '--partition_name', 'recovery',
                     '--partition_size', str(b.PARTITION_SIZE), '--algorithm', 'NONE', '--salt', b.SALT],
                    ['avbtool', 'verify_image', '--image', str(target)]):
        subprocess.run(command, check=True, capture_output=True)
    final = target.read_bytes()
    _, final_parts, _ = b.parse(final)
    b.require(final_parts == parts, 'Final image roundtrip')
    report = {'schema': 'a22x.public-beta-build.v1', 'version': args.version, 'image_sha256': sha(final),
              'base_sha256': args.base_sha256, 'kernel': new, 'modules': module_admission, 'changed': changed,
              'removed': removed, 'developer_identity_checked': sorted(len(v) for v in secrets), 'avb_verified': True}
    (args.output / 'RESULT.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    (args.output / 'SHA256SUMS').write_text(sha(final) + '  recovery.img\n')
    print(json.dumps({k: report[k] for k in ('version', 'image_sha256', 'removed')}, indent=2))


if __name__ == '__main__':
    main()
