#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The Android decrypt runtime without Samsung's vendor files (2026-11-20, the owner: the decrypt
must take them from the phone's own firmware, so the same image can be published and work on any
phone of this model).

The runtime already starts tzdaemon, tzts_daemon and the Keymaster and Gatekeeper HALs from the
phone's vendor partition: the launcher mounts it over /vendor, where the bundle's copies were
hidden and never run. Those copies served only as hash references and as the list of programs it
may start. This tool repacks a qualified runtime.tar so that:

  - android-root/rootfs/vendor/** is gone (the empty folder stays: the mount point);
  - ROOT-MANIFEST.json lists those files under "stock_vendor" with their SHA-256, size and mode
    only (a hash is not the file), and no field names a path of the build machine;
  - controller/g2/launcher_native_efs.py checks each of them on the mounted vendor before anything
    runs: a regular file of that mount, an AArch64 ELF where it is code, byte-identical to its pin
    as before, and records what it read in the session result;
  - the host build paths in controller/stage_android_ro.py are neutral, and the two probe helpers
    are stripped of their symbols.

The tar keeps its member order and normalized headers (uid/gid 0, no names, mtime 0).

    repack_decrypt_runtime.py --input runtime.tar --output DIR [--strip LLVM_STRIP] [--kernel-build N]

--kernel-build moves the runtime's binding to another recovery kernel build (KERNEL_BUILD in
controller/g2/native_efs_policy.py, which the native EFS policy finds in /proc/version). The
runtime must then be qualified on that kernel again (TEE, Keymaster and Gatekeeper ready).
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

MANIFEST = 'android-root/ROOT-MANIFEST.json'
LAUNCHER = 'controller/g2/launcher_native_efs.py'
STAGE = 'controller/stage_android_ro.py'
VENDOR = 'android-root/rootfs/vendor/'
STRIP = ('android-root/rootfs/system/bin/a22x-hardware-probe', 'android-root/rootfs/system/bin/a22x-property-service')
POLICY = 'controller/g2/native_efs_policy.py'

LAUNCHER_EDITS = [
    ("""    for name in (GK_HAL, GK_PROBE, '/vendor/lib64/hw/gatekeeper.mt6833.so',
                 '/vendor/lib64/android.hardware.gatekeeper@1.0.so',
                 '/system/lib64/android.hardware.gatekeeper@1.0.so'):
        stage.require(name.lstrip('/') in inventory['files'], 'Gatekeeper dependency missing from manifest')
""", """    for name in (GK_HAL, GK_PROBE, '/vendor/lib64/hw/gatekeeper.mt6833.so',
                 '/vendor/lib64/android.hardware.gatekeeper@1.0.so',
                 '/system/lib64/android.hardware.gatekeeper@1.0.so'):
        stage.require(name.lstrip('/') in inventory['files'] or name.lstrip('/') in inventory.get('stock_vendor', {}),
                      'Gatekeeper dependency missing from manifest')
"""),
    ("""        self.executables = {'/'+name for name, item in inventory['files'].items() if item['mode'] & 0o111}
""", """        self.executables = {'/'+name for name, item in inventory['files'].items() if item['mode'] & 0o111}
        # The phone's own vendor programs (verify_stock_vendor checks them before any is started).
        self.executables |= {'/'+name for name, item in inventory.get('stock_vendor', {}).items()
                             if item['mode'] & 0o111 and name.startswith('vendor/bin/')}
"""),
    ("""        # Hash the actual mounted stock vendor binaries before executing any of them.
        for name, expected in inventory['files'].items():
            if name.startswith(('vendor/bin/', 'vendor/lib64/')):
                stage.require(stage.sha(stage.regular_bytes(backend.at('/'+name))) == expected['sha256'],
                              'Mounted vendor binary differs from qualified snapshot: ' + name)
""", """        # Hash the actual mounted stock vendor binaries before executing any of them.
        result['stock_vendor'] = verify_stock_vendor(backend, inventory)
"""),
    ("""def bootstrap(backend, inventory, allow_policy_load, common_lock_fd, consumer_callback=None,""",
     """def verify_stock_vendor(backend, inventory):
    \"\"\"The vendor programs and libraries this runtime starts come from the phone's own vendor partition,
    mounted over /vendor; the bundle carries only their SHA-256 (2026-11-20: no Samsung file is
    distributed). Each must be a regular file of that mount, an AArch64 ELF where it is code, and,
    for vendor/bin and vendor/lib64, byte-identical to its pin as before. What was read is returned
    for the session result.\"\"\"
    pins = inventory.get('stock_vendor')
    stage.require(type(pins) is dict and pins, 'Stock vendor pins missing from manifest')
    mount = os.stat(backend.at('/vendor'))
    seen = {}
    for name, expected in sorted(pins.items()):
        parts = name.split('/')
        stage.require(parts[0] == 'vendor' and len(parts) > 1 and '..' not in parts and '' not in parts,
                      'Stock vendor path outside /vendor: ' + name)
        fd = os.open(backend.at('/' + name), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            stage.require(stat.S_ISREG(info.st_mode) and info.st_dev == mount.st_dev,
                          'Stock vendor file is not on the mounted vendor: ' + name)
            chunks = []
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
            data = b''.join(chunks)
        finally:
            os.close(fd)
        code = name.startswith(('vendor/bin/', 'vendor/lib64/'))
        if code:
            stage.require(len(data) > 64 and data[:4] == b'\\x7fELF' and data[4] == 2 and data[5] == 1 and
                          int.from_bytes(data[18:20], 'little') == 183 and int.from_bytes(data[16:18], 'little') in (2, 3),
                          'Stock vendor file is not an AArch64 ELF: ' + name)
            if name.startswith('vendor/bin/'):
                stage.require(info.st_mode & 0o111, 'Stock vendor program is not executable: ' + name)
        digest = stage.sha(data)
        seen[name] = {'sha256': digest, 'size': len(data), 'mode': info.st_mode & 0o7777}
        if code:
            stage.require(digest == expected['sha256'] and len(data) == expected['size'],
                          'Mounted vendor binary differs from qualified snapshot: ' + name)
    return seen


def bootstrap(backend, inventory, allow_policy_load, common_lock_fd, consumer_callback=None,"""),
]

STAGE_EDITS = [
    (f"""WORK = Path({str(Path.home() / 'a22x-work')!r})
OLD = WORK/'audits/compare-teegris-old-vs-new-20260616-002603/old-root'
DEVICE = WORK/'publication/A22X_TWRP_RC0_PUBLIC-20260622-001955/source-repo'
DM_SOURCE = WORK/'public/main-wt/dm_linear.py'
LP_SOURCE = WORK/'public/main-wt/lp_metadata.py'
""", """# Build-machine inputs of the offline root builder; on the phone every caller passes the bundle's
# own copies (check_host_source=False, dm_path=bundle/support/...). Set A22X_RUNTIME_WORK to build.
WORK = Path(os.environ.get('A22X_RUNTIME_WORK', '/nonexistent/a22x-runtime-build'))
OLD = WORK/'old-root'
DEVICE = WORK/'device-source'
DM_SOURCE = WORK/'support/dm_linear.py'
LP_SOURCE = WORK/'support/lp_metadata.py'
"""),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def edit(text, edits, name):
    for old, new in edits:
        assert text.count(old) == 1, (name, old[:80])
        text = text.replace(old, new)
    return text


def neutral(value):
    """Strings naming the build machine's paths, replaced by their last two components."""
    if isinstance(value, str) and value.startswith('/home/'):
        return 'build:' + '/'.join(value.rstrip('/').split('/')[-2:])
    if isinstance(value, dict):
        return {k: neutral(v) for k, v in value.items()}
    if isinstance(value, list):
        return [neutral(v) for v in value]
    return value


def strip_elf(data, tool):
    with tempfile.TemporaryDirectory() as work:
        path = Path(work) / 'elf'
        path.write_bytes(data)
        subprocess.run([tool, '--strip-all', str(path)], check=True)
        return path.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--strip', default=str(Path.home() / 'nura-a22x/toolchains/llvm-23.1.1-x86_64/bin/llvm-strip'))
    parser.add_argument('--kernel-build', type=int, help='Bind the runtime to this recovery kernel build')
    args = parser.parse_args()
    with tarfile.open(args.input) as source:
        members = [(m, source.extractfile(m).read() if m.isfile() else None) for m in source.getmembers()]
    body = {m.name: data for m, data in members}
    manifest = json.loads(body[MANIFEST])
    stock = {}
    for name in sorted(manifest['files']):
        if name.startswith('vendor/'):
            entry = manifest['files'].pop(name)
            stock[name] = {'sha256': entry['sha256'], 'size': entry['size'], 'mode': entry['mode']}
    assert stock, 'No vendor files in the manifest'
    manifest['stock_vendor'] = stock
    replaced = {}
    for member in STRIP:
        replaced[member] = strip_elf(body[member], args.strip)
        rel = member[len('android-root/rootfs/'):]
        manifest['files'][rel].update(sha256=sha(replaced[member]), size=len(replaced[member]))
    manifest = neutral(manifest)
    replaced[MANIFEST] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    replaced[LAUNCHER] = edit(body[LAUNCHER].decode(), LAUNCHER_EDITS, LAUNCHER).encode()
    stage_text = body[STAGE].decode()
    if '\nimport os\n' not in stage_text:
        stage_text = stage_text.replace('\nimport re\n', '\nimport os\nimport re\n', 1)
    replaced[STAGE] = edit(stage_text, STAGE_EDITS, STAGE).encode()
    kernel_build = None
    if args.kernel_build is not None:
        policy = body[POLICY].decode()
        lines = [line for line in policy.splitlines() if line.startswith('KERNEL_BUILD=')]
        assert len(lines) == 1, 'KERNEL_BUILD line'
        kernel_build = {'before': lines[0].split('=')[1].split()[0], 'after': args.kernel_build}
        replaced[POLICY] = policy.replace(lines[0], 'KERNEL_BUILD=%d  # exact recovery kernel build this runtime '
                                          'is bound to (repacked from #%s)' % (args.kernel_build, kernel_build['before']),
                                          1).encode()
    args.output.mkdir(parents=True, exist_ok=True)
    out_path = args.output / 'runtime.tar'
    kept = removed = 0
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as out:
        for member, data in members:
            if member.name.startswith(VENDOR) and member.name.rstrip('/') != VENDOR.rstrip('/'):
                removed += 1
                continue
            info = tarfile.TarInfo(member.name)
            info.type, info.mode, info.uid, info.gid, info.uname, info.gname, info.mtime = \
                member.type, member.mode, 0, 0, '', '', 0
            if member.isfile():
                data = replaced.get(member.name, data)
                info.size = len(data)
                out.addfile(info, io.BytesIO(data))
            else:
                out.addfile(info)
            kept += 1
    tar = buffer.getvalue()
    out_path.write_bytes(tar)
    text = tar.decode('latin-1')
    report = {'input_sha256': sha(args.input.read_bytes()), 'bundle_sha256': sha(tar), 'members': kept,
              'removed_vendor_members': removed, 'stock_vendor_pins': len(stock),
              'root_manifest_sha256': sha(replaced[MANIFEST]),
              'host_paths_left': text.count('/home/'), 'stripped': {m: sha(replaced[m]) for m in STRIP},
              'kernel_build': kernel_build}
    (args.output / 'REPACK.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
