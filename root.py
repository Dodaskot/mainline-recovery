#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Root for Android from this recovery (2026-11-10): the newest Magisk, downloaded and put into BOOT.

The newest release of Magisk is asked from GitHub, which states its APK's SHA-256; the APK is
downloaded over Wi-Fi and checked. BOOT is patched the way the Magisk app patches it: by Magisk's
own boot_patch.sh with its magiskboot, magiskinit, magisk and init-ld, run by its busybox in a
private tmpfs, as in a recovery (BOOTMODE=false: nothing of Android is asked; its abort only reports,
it unmounts nothing here). The patched BOOT is checked (still Android's BOOT for this phone, Magisk in
its ramdisk), kept on cache, and written as any BOOT: the BOOT there is kept on cache first, so root
goes away by flashing it back. Magisk 31 puts no app into BOOT: the Magisk app is installed in Android.

Samsung (2026-11-10, on the phone): with the stock vbmeta (verification on, a hash for boot), a
patched BOOT starts, but Android cannot mount its encrypted data (misc: --prompt_and_wipe_data,
--reason=fs_mgr_mount_all) - the changed boot hash changes the verified-boot state its keys depend
on. The Magisk app's Samsung method is the same here: vbmeta flags 3 (hashtree and verification off,
its TarProcessor's putInt(120, 3)) and Android's data erased once. After that a new BOOT (a Magisk
update) needs no reset. LK write-protects vbmeta while the phone runs ([Part_WP]WP(nvram->btd), seen
on the phone: the write was dropped), so this recovery prepares that vbmeta on cache and it is flashed
in Download mode (Heimdall or Odin); seeing it there, the next install erases Android's data once,
and the prepared copy is removed, so later installs need no reset.

KernelSU Next (2026-11-21, the owner's request): its modules load only into GKI kernels, so this
recovery's project builds a kernel for it: Samsung's 4.14.186 source (A226BXXSBDYA1) with KernelSU
Next's legacy branch, as an AnyKernel3 ZIP published in the project's own GitHub releases (tag
kernelsu-next-a22x-*, with GitHub's SHA-256 of the asset). It is downloaded and checked here like
Magisk's APK, then installed by this recovery's ZIP installer, which shows its review first: the
ZIP replaces only BOOT's kernel. Its manager app is queued for Android like Magisk's.

APatch (2026-11-11, asked for by the phone's owner) puts KernelPatch into the kernel itself, which
the 4.14 kernel allows (CONFIG_KALLSYMS and CONFIG_KALLSYMS_ALL are on). BOOT is patched by the
steps of the APatch app's own boot_patch.sh: kptools unpack, the kernel patched with KernelPatch's
image and the owner's SuperKey, kptools repack. The APK's kptools needs Android's linker, so this
recovery carries kptools built from KernelPatch's source at the version of the APK's kpimg, and
that kpimg: nothing is downloaded. The SuperKey is typed on the phone, reaches this helper in a
file of the private RAM folder, and is kept nowhere; the APatch app in Android asks for it.
After Android starts, install the verified APatch Manager 11282 and use the generated bootstrap
with already authorized APatch su. The bootstrap checks the installed package and sets up APD
using the Manager's extracted libraries. If recovery already seeded the verified APD for first
boot, the bootstrap keeps it and creates the missing APatch directory. Re-run with --verify-only
after reboot.

    root.py --device|--fixture DIR list
    root.py ... install --id magisk --expected-sha256 SHA --confirm
    root.py ... install --id apatch --expected-sha256 SHA --superkey-file FILE --confirm
    root.py --device apatch-bootstrap --manager-apk FILE > apatch-bootstrap.sh
    adb -d install --no-incremental -r FILE
    adb -d push apatch-bootstrap.sh /data/local/tmp/a22x-apatch-bootstrap.sh
    adb -d shell -T "su -c 'sh /data/local/tmp/a22x-apatch-bootstrap.sh'"
    adb -d shell -T "su -c 'sh /data/local/tmp/a22x-apatch-bootstrap.sh --verify-only'"
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import types
import urllib.request
import zipfile

import bootimage
import clock
import filesystem as fs
import flash
import install
from install import require
import saved_boot

TOOLS = {
    'magisk': {'name': 'Magisk', 'repo': 'topjohnwu/Magisk', 'asset': re.compile(r'^Magisk-v[0-9.]+\.apk$'), 'supported': True},
    'apatch': {'name': 'APatch', 'bundled': True, 'supported': True},
    'kernelsu-next': {'name': 'KernelSU Next', 'repo': 'Dodaskot/mainline-recovery', 'tag_prefix': 'kernelsu-next-a22x-',
                      'asset': re.compile(r'^KernelSU-Next-A226B-[A-Za-z0-9._+-]{1,48}-AnyKernel3\.zip$'), 'supported': True,
                      'zip': True, 'kernel_root': 'kernelsu'},
}
KERNEL_ZIP_DIR = 'a22x-recovery/kernels'
ZIP_LIMIT = 64 << 20
# KernelPatch's tool and image, part of this recovery (tools/build-image.sh takes them from apatch/out).
APATCH_DIR = Path('/opt/a22x-recovery/apatch')
APATCH_MANAGER = {
    'package': 'me.bmax.apatch',
    'version_code': 11282,
    'file': 'APatch_11282_e8e4651_HEAD-release-signed.apk',
    'sha256': 'd6bf0dbcab95fb9a3aa111c35efd945267bcce3a41377c3297c3c1a9eab421a5',
    'size': 6716426,
}
APATCH_LIBRARIES = ('apd', 'busybox', 'kptools')
# The APatch app's rule for a SuperKey: 8 to 63 characters with a letter and a digit. Here also
# without spaces: it is typed again in Android.
SUPERKEY = re.compile(r'(?=.*[A-Za-z])(?=.*[0-9])[!-~]{8,63}')
# What boot_patch.sh needs beside itself, from the APK: (path in the APK, name in the folder).
MAGISK_FILES = (('lib/arm64-v8a/libmagiskboot.so', 'magiskboot'), ('lib/arm64-v8a/libmagiskinit.so', 'magiskinit'),
                ('lib/arm64-v8a/libmagisk.so', 'magisk'), ('lib/arm64-v8a/libinit-ld.so', 'init-ld'),
                ('lib/arm64-v8a/libbusybox.so', 'busybox'), ('assets/boot_patch.sh', 'boot_patch.sh'),
                ('assets/util_functions.sh', 'util_functions.sh'))
APK_LIMIT = 64 << 20
ROOT_DIR = 'a22x-recovery/root'
# The Magisk APK of the last install, kept for a new system's first start (android_root_adb, 2026-11-20).
MAGISK_APK_DIR = 'a22x-recovery/magisk'
WORK = Path('/run/a22x-recovery/root-work')
API = 'https://api.github.com/repos/%s/releases/latest'
PATCH_SECONDS = 300
WORK_BYTES = 384 << 20
# boot_patch.sh sourced as Magisk's recovery installer sources it, with its abort reduced to a report:
# Magisk's recovery_cleanup unmounts /system, /vendor, /metadata and more, which this recovery owns.
DRIVER = '''. ./util_functions.sh
recovery_cleanup() { :; }
abort() { ui_print "$1"; exit 1; }
SOURCEDMODE=true
set -- boot.img
. ./boot_patch.sh
'''

# Run by the operator under an already authorized su on fully booted Android. This writes only
# a fresh runtime; Android's Manager owns existing configs and runtime files.
APATCH_BOOTSTRAP = r'''
PATH=/system/bin:/system/xbin
ADB=/data/adb
AP="$ADB/ap"
APD="$ADB/apd"
stage="$ADB/.a22x-apatch-bootstrap"
label=u:object_r:adb_data_file:s0

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

present() { [ -e "$1" ] || [ -L "$1" ]; }
plain_file() { [ -f "$1" ] && [ ! -L "$1" ]; }
plain_directory() { [ -d "$1" ] && [ ! -L "$1" ]; }

matches_hash() {
    plain_file "$1" || return 1
    hash=$(sha256sum "$1") || return 1
    [ "${hash%% *}" = "$2" ]
}

matches_label() {
    context=$(ls -Zd "$1") || return 1
    [ "${context%% *}" = "$label" ]
}

apd_matches() {
    matches_hash "$1" "$APD_SHA256" && [ -x "$1" ] && matches_label "$1"
}

runtime_matches() {
    plain_directory "$1" && plain_directory "$1/bin" && plain_directory "$1/log" || return 1
    apd_matches "$2" || return 1
    matches_hash "$1/bin/busybox" "$BUSYBOX_SHA256" && [ -x "$1/bin/busybox" ] || return 1
    matches_hash "$1/bin/kptools" "$KPTOOLS_SHA256" && [ -x "$1/bin/kptools" ] || return 1
    plain_file "$1/package_config" && plain_file "$1/su_path" && [ -s "$1/su_path" ] || return 1
    for link in apd magiskpolicy resetprop; do
        [ -L "$1/bin/$link" ] && [ "$(readlink "$1/bin/$link")" = "$APD" ] || return 1
    done
    for path in "$1" "$1/bin" "$1/log" "$1/bin/busybox" "$1/bin/kptools" "$1/package_config" "$1/su_path"; do
        matches_label "$path" || return 1
    done
    # The earlier supervised installer did not write this marker. The daemon hash
    # and the installed Manager still bind its runtime to this version.
    if present "$1/version"; then
        plain_file "$1/version" && [ "$(cat "$1/version")" = "$MANAGER_VERSION_CODE" ] &&
            matches_label "$1/version" || return 1
    fi
}

case "${1:-}" in
    ''|--verify-only) [ "$#" -le 1 ] || fail "Usage: sh apatch-bootstrap.sh [--verify-only]" ;;
    *) fail "Usage: sh apatch-bootstrap.sh [--verify-only]" ;;
esac
[ "$(id -u)" = 0 ] && [ "$(getprop sys.boot_completed)" = 1 ] ||
    fail "APATCH_ANDROID_REQUIRED: use authorized APatch su in booted Android"

package=$(pm list packages --show-versioncode --user 0 "$MANAGER_PACKAGE" </dev/null) ||
    fail "APATCH_MANAGER_MISSING: Android package manager is unavailable"
[ "$package" = "package:$MANAGER_PACKAGE versionCode:$MANAGER_VERSION_CODE" ] ||
    fail "APATCH_MANAGER_VERSION: install the verified APatch Manager $MANAGER_VERSION_CODE for Android user 0"
package_path=$(pm path --user 0 "$MANAGER_PACKAGE" </dev/null) ||
    fail "APATCH_MANAGER_MISSING: Android could not find the Manager APK"
case "$package_path" in
    package:/data/app/*/base.apk) apk=${package_path#package:} ;;
    *) fail "APATCH_MANAGER_MISSING: expected the Manager APK under /data/app" ;;
esac
matches_hash "$apk" "$MANAGER_SHA256" ||
    fail "APATCH_MANAGER_HASH: the installed APK differs from the verified release"
libs="${apk%/*}/lib/arm64"
plain_directory "$libs" &&
    matches_hash "$libs/libapd.so" "$APD_SHA256" &&
    matches_hash "$libs/libbusybox.so" "$BUSYBOX_SHA256" &&
    matches_hash "$libs/libkptools.so" "$KPTOOLS_SHA256" ||
    fail "APATCH_MANAGER_LIBRARIES: the Manager's extracted arm64 libraries are missing or different"

plain_directory "$ADB" || fail "APATCH_ADB_MISSING: expected Android's /data/adb directory"
if present "$stage"; then
    fail "APATCH_BOOTSTRAP_BUSY: there is already a bootstrap staging directory"
fi
if present "$AP"; then
    runtime_matches "$AP" "$APD" ||
        fail "APATCH_RUNTIME_CONFLICT: the existing runtime is partial or differs from the verified setup"
    status=already-configured
else
    apd_source="$stage/apd"
    seed_identity=
    if present "$APD"; then
        # Recovery may have seeded APD for the first Android boot. Keep its inode and labels.
        apd_matches "$APD" || fail "APATCH_RUNTIME_CONFLICT: the existing APatch daemon does not match the verified seed"
        seed_identity=$(stat -c '%d:%i' "$APD")
        apd_source="$APD"
    fi
    [ "${1:-}" != --verify-only ] || fail "APATCH_RUNTIME_MISSING: the APatch runtime has not been set up"
    umask 077
    mkdir "$stage" || fail "APATCH_BOOTSTRAP_BUSY: could not reserve the bootstrap staging directory"
    ap_identity=
    apd_identity=
    committed=0
    cleanup() {
        # Only roll back entries with the same identity as the files staged by this invocation.
        trap - HUP INT TERM
        if [ "$committed" = 0 ]; then
            if [ -n "$apd_identity" ] && [ "$(stat -c '%d:%i' "$APD" 2>/dev/null)" = "$apd_identity" ]; then
                mv -nT "$APD" "$stage/apd"
            fi
            if [ -n "$ap_identity" ] && [ "$(stat -c '%d:%i' "$AP" 2>/dev/null)" = "$ap_identity" ]; then
                mv -nT "$AP" "$stage/ap"
            fi
        fi
        rm -rf "$stage"
    }
    trap cleanup EXIT
    trap 'exit 1' HUP INT TERM
    if present "$AP" || { [ -z "$seed_identity" ] && present "$APD"; }; then
        fail "APATCH_RUNTIME_CONFLICT: an existing runtime appeared during setup"
    fi
    mkdir "$stage/ap" "$stage/ap/bin" "$stage/ap/log"
    if [ -z "$seed_identity" ]; then
        cp "$libs/libapd.so" "$stage/apd"
        chmod 0755 "$stage/apd"
    fi
    cp "$libs/libbusybox.so" "$stage/ap/bin/busybox"
    cp "$libs/libkptools.so" "$stage/ap/bin/kptools"
    chmod 0755 "$stage/ap/bin/busybox" "$stage/ap/bin/kptools"
    : > "$stage/ap/package_config"
    printf '%s\n' /system/bin/su > "$stage/ap/su_path"
    printf '%s\n' "$MANAGER_VERSION_CODE" > "$stage/ap/version"
    restorecon -R "$stage" || fail "APATCH_STAGE_INVALID: the staged SELinux labels could not be set"
    for link in apd magiskpolicy resetprop; do
        ln -s "$APD" "$stage/ap/bin/$link"
    done
    runtime_matches "$stage/ap" "$apd_source" ||
        fail "APATCH_STAGE_INVALID: the staged files or SELinux labels did not match"
    ap_identity=$(stat -c '%d:%i' "$stage/ap")
    mv -nT "$stage/ap" "$AP"
    [ ! -e "$stage/ap" ] || fail "APATCH_RUNTIME_CONFLICT: the APatch directory already exists"
    if [ -z "$seed_identity" ]; then
        apd_identity=$(stat -c '%d:%i' "$stage/apd")
        mv -nT "$stage/apd" "$APD"
        [ ! -e "$stage/apd" ] || fail "APATCH_RUNTIME_CONFLICT: the APatch daemon already exists"
    elif [ "$(stat -c '%d:%i' "$APD")" != "$seed_identity" ]; then
        fail "APATCH_RUNTIME_CONFLICT: the verified APatch daemon changed during setup"
    fi
    runtime_matches "$AP" "$APD" ||
        fail "APATCH_RUNTIME_INVALID: the installed files or SELinux labels did not match"
    sync
    committed=1
    status=configured
fi

printf 'APATCH_ENV=VERIFIED\nSTATUS=%s\nMANAGER_VERSION_CODE=%s\nAPD_SHA256=%s\nSELINUX_LABEL=%s\n' \
    "$status" "$MANAGER_VERSION_CODE" "$APD_SHA256" "$label"
'''


def fail(code, message, **details):
    fs.fail(code, message, **details)


def latest(repo, asset_name):
    """The newest release's asset: name, URL, size and the SHA-256 GitHub states for it."""
    request = urllib.request.Request(API % repo, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'a22x-recovery'})
    with urllib.request.urlopen(request, timeout=30, context=tls_context()) as reply:
        release = json.loads(reply.read(4 << 20))
    for asset in release.get('assets', []):
        digest = (asset.get('digest') or '').removeprefix('sha256:')
        if asset_name.match(asset.get('name', '')) and re.fullmatch(r'[0-9a-f]{64}', digest):
            return {'version': release.get('tag_name', ''), 'file': asset['name'], 'url': asset['browser_download_url'],
                    'size': int(asset['size']), 'sha256': digest, 'published': (release.get('published_at') or '')[:10]}
    fail('ROOT_RELEASE_UNUSABLE', 'The newest release has no file this recovery can use')


def tagged(repo, prefix, asset_name):
    """As latest, the newest release whose tag starts with PREFIX (a project's second line of releases)."""
    request = urllib.request.Request((API % repo).rsplit('/', 1)[0] + '?per_page=30',
                                     headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'a22x-recovery'})
    with urllib.request.urlopen(request, timeout=30, context=tls_context()) as reply:
        releases = json.loads(reply.read(8 << 20))
    for release in releases:
        if release.get('draft') or not str(release.get('tag_name', '')).startswith(prefix):
            continue
        for asset in release.get('assets', []):
            digest = (asset.get('digest') or '').removeprefix('sha256:')
            if asset_name.match(asset.get('name', '')) and re.fullmatch(r'[0-9a-f]{64}', digest):
                return {'version': release['tag_name'][len(prefix):], 'file': asset['name'], 'url': asset['browser_download_url'],
                        'size': int(asset['size']), 'sha256': digest, 'published': (release.get('published_at') or '')[:10]}
    fail('ROOT_RELEASE_UNUSABLE', 'No release has a file this recovery can use')


def tls_context():
    import distro
    return distro.tls_context()


def apatch_bundle(context):
    """KernelPatch's kptools and kpimg that come with this recovery: their paths, the version and
    SHA-256 of kpimg; None when this build has none."""
    folder = context.root / 'apatch' if context.mode == 'fixture' else APATCH_DIR
    tool, image = folder / 'kptools', folder / 'kpimg'
    try:
        data = image.read_bytes()
        usable = tool.is_file() and os.access(tool, os.X_OK)
    except OSError:
        return None
    version = bootimage.kernelpatch_version(data[:64])
    if not usable or not version:
        return None
    return {'kptools': tool, 'kpimg': image, 'version': version, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def apatch_bootstrap(manager_apk):
    """Generate the Android-side bootstrap for the exact Manager APK validated on the phone."""
    with manager_apk.open('rb') as stream:
        data = stream.read(APATCH_MANAGER['size'] + 1)
    manager_sha = hashlib.sha256(data).hexdigest()
    require(len(data) == APATCH_MANAGER['size'] and manager_sha == APATCH_MANAGER['sha256'],
            'APATCH_MANAGER_HASH', 'Use the verified APatch Manager APK', manager=APATCH_MANAGER)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        hashes = {name: hashlib.sha256(archive.read(f'lib/arm64-v8a/lib{name}.so')).hexdigest()
                  for name in APATCH_LIBRARIES}
    settings = [
        '#!/system/bin/sh',
        'set -eu',
        f'MANAGER_PACKAGE={APATCH_MANAGER["package"]}',
        f'MANAGER_VERSION_CODE={APATCH_MANAGER["version_code"]}',
        f'MANAGER_SHA256={manager_sha}',
        *(f'{name.upper()}_SHA256={sha}' for name, sha in hashes.items()),
    ]
    return '\n'.join(settings) + '\n' + APATCH_BOOTSTRAP


def tool_row(context, ident, tool):
    """One root tool with its newest version; without network, why it needs it."""
    row = {'id': ident, 'name': tool['name'], 'supported': tool['supported'], 'reason': tool.get('reason', '')}
    if tool.get('bundled'):
        bundle = apatch_bundle(context)
        if bundle:
            row.update({'version': "KernelPatch " + bundle['version'], 'file': 'kpimg', 'size': bundle['size'],
                        'sha256': bundle['sha256'], 'bundled': True, 'needs_key': True, 'manager': APATCH_MANAGER})
        else:
            row.update({'supported': False, 'reason': 'This build of the recovery has no APatch'})
    elif context.mode == 'fixture':
        row.update((context.config.get('root') or {}).get(ident, {}))
    else:
        try:
            row.update(tagged(tool['repo'], tool['tag_prefix'], tool['asset']) if tool.get('tag_prefix')
                       else latest(tool['repo'], tool['asset']))
        except (OSError, ValueError, fs.FilesystemError) as error:
            row['error'] = getattr(error, 'code', None) or 'NETWORK_UNAVAILABLE'
    return row


def tools(context):
    """The root tools with their newest version; without network, the names and why they need it."""
    # Certificates need the date: on the phone, a clock that cannot be right asks a time server first.
    clock.ensure(context.mode)
    found = [tool_row(context, ident, tool) for ident, tool in TOOLS.items()]
    try:
        stock = next((b for b in saved_boot.saved_boots(context) if b['kind'] == 'android' and not b['root']), None)
    except fs.FilesystemError:
        stock = None
    cache = context.fs.volume('cache')
    return {'tools': found, 'boot': boot_state(context), 'stock_boot': stock['path'] if stock else '',
            'cache_token': cache['volume_token'] if stock else '', 'verification': verification_on(context),
            'needs_data_reset': bool(prepared_in_place(context))}


def vbmeta_image(context):
    """vbmeta whole, read in a loop that refuses a short read (2026-11-13 review)."""
    target = context.target('vbmeta')
    return target, install.target_bytes(context, target)


def verification_state(context):
    """True while vbmeta still has Android's verification on (flags without bit 2): a patched BOOT
    then changes the verified-boot state, and Android's data must be erased once. False when it is
    off. None when vbmeta cannot be read or is no AVB image: then nothing is known."""
    try:
        _, data = vbmeta_image(context)
    except (OSError, KeyError, fs.FilesystemError):
        return None
    if len(data) < 124 or data[:4] != b'AVB0':
        return None
    return not struct.unpack_from('>I', data, 120)[0] & 2


def verification_on(context):
    """2026-11-13 review: a vbmeta that could not be read was taken for verification off, and a
    patched BOOT went in while it was on; Android then would not open its data. Unknown counts as on."""
    return verification_state(context) is not False


def boot_state(context):
    target = context.target('boot')
    data = install.target_bytes(context, target)
    found = saved_boot.describe_boot(data)
    return {'kind': found['kind'] or 'unknown', 'release': found['release'], 'magisk': found['root'] == 'magisk',
            'root': found['root']}


def download(context, url, size, sha256, target, progress):
    """The APK into TARGET, its size and SHA-256 as GitHub states them."""
    if context.mode == 'fixture':
        source = context.root / 'root-downloads' / url.rsplit('/', 1)[-1]
        shutil.copyfile(source, target)
    else:
        request = urllib.request.Request(url, headers={'User-Agent': 'a22x-recovery'})
        with urllib.request.urlopen(request, timeout=60, context=tls_context()) as reply, open(target, 'wb') as out:
            done = 0
            while True:
                data = reply.read(1 << 20)
                if not data:
                    break
                done += len(data)
                require(done <= APK_LIMIT, 'DOWNLOAD_TOO_LARGE', 'The download is larger than its release says')
                out.write(data)
                progress('Downloading', {'label': Path(target).name[:40], 'size_bytes': size}, done)
    digest = hashlib.sha256(Path(target).read_bytes()).hexdigest()
    require(os.path.getsize(target) == size and digest == sha256, 'DOWNLOAD_CHECKSUM_MISMATCH',
            'The download differs from its release. Try again.')


def patch_magisk(apk, boot, work):
    """BOOT patched by Magisk's own boot_patch.sh, in WORK; the new image's bytes and the log."""
    with zipfile.ZipFile(apk) as archive:
        for member, name in MAGISK_FILES:
            try:
                data = archive.read(member)
            except KeyError:
                fail('MAGISK_APK_INCOMPLETE', 'This Magisk APK lacks a file the patch needs', file=member)
            (work / name).write_bytes(data)
            (work / name).chmod(0o755)
    (work / 'boot.img').write_bytes(boot)
    (work / 'a22x-patch.sh').write_text(DRIVER)
    # PREINITDEVICE: what the Magisk app's own patch chose on this phone (magisk --preinit-device: cache,
    # seen in the .backup/.magisk of a BOOT it patched); outside Android the patch cannot ask.
    env = {'PATH': str(work) + ':/bin:/sbin:/usr/bin', 'ASH_STANDALONE': '1', 'BOOTMODE': 'false', 'OUTFD': '1',
           'KEEPVERITY': 'true', 'KEEPFORCEENCRYPT': 'true', 'PATCHVBMETAFLAG': 'false', 'RECOVERYMODE': 'false',
           'LEGACYSAR': 'false', 'PREINITDEVICE': 'cache', 'HOME': str(work), 'TMPDIR': str(work)}
    done = subprocess.run([str(work / 'busybox'), 'sh', 'a22x-patch.sh'], cwd=work, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=PATCH_SECONDS)
    log = done.stdout.decode('utf-8', 'replace')
    lines = [line[len('ui_print '):] for line in log.splitlines() if line.startswith('ui_print ') and line[len('ui_print '):].strip()]
    require(done.returncode == 0 and (work / 'new-boot.img').is_file(), 'MAGISK_PATCH_FAILED', 'Magisk could not patch BOOT',
            log=lines[-8:] or log[-600:])
    return (work / 'new-boot.img').read_bytes(), lines


def patch_apatch(context, bundle, boot, work, superkey):
    """BOOT patched as the APatch app's boot_patch.sh patches it, in WORK; the new image's bytes and
    the log. kptools runs without privileges on the phone: it needs nothing but the files in WORK."""
    shutil.copyfile(bundle['kptools'], work / 'kptools')
    (work / 'kptools').chmod(0o755)
    shutil.copyfile(bundle['kpimg'], work / 'kpimg')
    (work / 'boot.img').write_bytes(boot)
    identity = {}
    if context.mode == 'device':
        for path in (work, work / 'kptools', work / 'kpimg', work / 'boot.img'):
            os.chown(path, 65534, 65534)
        identity = {'user': 65534, 'group': 65534, 'extra_groups': []}
    log = []

    def run(*args, need=True):
        # By its name in WORK: without privileges the folders above WORK cannot be passed (2026-11-11, on the phone).
        try:
            done = subprocess.run(['./kptools', *args], cwd=work, env={'PATH': '/bin:/usr/bin', 'HOME': '.'},
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=PATCH_SECONDS,
                                  **identity)
        except subprocess.TimeoutExpired:
            fail('APATCH_PATCH_FAILED', 'The APatch patch command timed out', step=args[0])
        except (OSError, subprocess.SubprocessError):
            fail('APATCH_PATCH_FAILED', 'The APatch patch command could not run', step=args[0])
        text = done.stdout.decode('utf-8', 'replace')
        # The SuperKey is an argument of one step: it never reaches a log.
        lines = text.replace(superkey, '***').splitlines()
        log.extend(line for line in lines if line.strip())
        require(done.returncode == 0 or not need, 'APATCH_PATCH_FAILED', 'The kernel in BOOT could not be patched for APatch', step=args[0],
                log=lines[-6:])
        return text

    run('unpack', 'boot.img')
    require((work / 'kernel').is_file(), 'APATCH_PATCH_FAILED', 'No kernel was found in BOOT')
    require('CONFIG_KALLSYMS=y' in run('-i', 'kernel', '-f', need=False), 'APATCH_KERNEL_UNSUITABLE',
            'This kernel was built without CONFIG_KALLSYMS, which APatch needs')
    os.rename(work / 'kernel', work / 'kernel.ori')
    run('-p', '-i', 'kernel.ori', '-S', superkey, '-k', 'kpimg', '-o', 'kernel')
    run('repack', 'boot.img')
    require((work / 'new-boot.img').is_file(), 'APATCH_PATCH_FAILED', 'The patched BOOT was not written')
    return (work / 'new-boot.img').read_bytes(), log


VBMETA_DIR = 'a22x-recovery/vbmeta'


def prepared_in_place(context):
    """The vbmeta this recovery prepared for root (on cache), when it is now in the vbmeta partition:
    Android's data then still has to be erased once. Its path, or ''."""
    try:
        _, data = vbmeta_image(context)
    except (OSError, KeyError, fs.FilesystemError):
        return ''
    name = 'vbmeta-flags3-' + hashlib.sha256(data).hexdigest()[:12] + '.img'
    try:
        kept = {b['name'] for b in saved_boot.saved_boots(context, VBMETA_DIR)}
    except fs.FilesystemError:
        return ''
    return '/' + VBMETA_DIR + '/' + name if name in kept else ''


def prepare_vbmeta(context, progress):
    """vbmeta as it is with flags 3 (as the Magisk app writes it for Samsung), kept on cache for
    Download mode, since the bootloader locks the partition while the phone runs."""
    target, data = vbmeta_image(context)
    require(data[:4] == b'AVB0', 'VBMETA_INVALID', 'There is no AVB vbmeta in the vbmeta partition')
    patched = bytearray(data)
    struct.pack_into('>I', patched, 120, 3)
    digest = hashlib.sha256(bytes(patched)).hexdigest()
    path = saved_boot.save_on_cache(context, 'vbmeta-flags3-' + digest[:12] + '.img', bytes(patched),
                                    {'kind': 'vbmeta', 'flags': 3, 'for': 'root'}, progress, folder_name=VBMETA_DIR)
    return {'vbmeta': path, 'sha256': digest, 'bytes': len(patched),
            'command': 'heimdall flash --vbmeta ' + path.rsplit('/', 1)[-1]}


def install_root(context, ident, expected_sha256, confirmed, progress, erase_data=False, superkey=None):
    require(confirmed, 'CONFIRMATION_REQUIRED', 'Installing root must be confirmed')
    require(verification_state(context) is not None, 'VBMETA_UNREADABLE',
            'The vbmeta partition cannot be read as an AVB image, so whether verification is off is not known')
    require(not verification_on(context), 'ROOT_NEEDS_VBMETA',
            'Root on this Samsung needs vbmeta with verification off, flashed in Download mode: prepare it first')
    prepared = prepared_in_place(context)
    reset = bool(prepared)
    require(not reset or erase_data, 'ROOT_NEEDS_DATA_RESET',
            'On this Samsung, root needs verification off in vbmeta and Android data erased once')
    tool = TOOLS.get(ident)
    require(tool is not None, 'ROOT_UNKNOWN', 'This root tool is unknown')
    require(tool['supported'], 'ROOT_UNSUPPORTED', tool.get('reason', 'Not for this phone'))
    state = boot_state(context)
    require(state['kind'] == 'android', 'ROOT_NEEDS_ANDROID_BOOT', 'Root goes into the BOOT of Android: install Android first')
    # Magisk lives in the ramdisk and APatch in the kernel: one BOOT carries one of them.
    require(state['root'] in ('', tool.get('kernel_root', ident)), 'ROOT_OTHER_PRESENT',
            'This BOOT already has another root: flash the stock BOOT back first (Remove root)', present=state['root'])
    require(not (reset and tool.get('zip')), 'ROOT_NEEDS_DATA_RESET',
            'Android data must be erased once for root on this Samsung: install Magisk first, then KernelSU Next')
    if tool.get('bundled'):
        require(isinstance(superkey, str) and SUPERKEY.fullmatch(superkey), 'SUPERKEY_INVALID',
                'The SuperKey needs 8 to 63 characters without spaces, with a letter and a digit')
    # Only this tool's release (2026-11-13 review: every tool was asked for over the network, and BOOT
    # and vbmeta read again, for one row; APatch offline waited for Magisk's release).
    if not tool.get('bundled'):
        clock.ensure(context.mode)
    release = tool_row(context, ident, tool)
    require(release.get('supported'), 'ROOT_UNSUPPORTED', release.get('reason') or 'Not for this phone')
    require(release.get('sha256') == expected_sha256, 'ROOT_RELEASE_CHANGED', 'A newer release came out since it was shown. Review again')
    work = WORK if context.mode == 'device' else context.root / 'root-work'
    if tool.get('zip'):
        with work_folder(context, work):
            return fetch_kernel_zip(context, ident, tool, release, work, progress)
    with work_folder(context, work):
        result = patch_and_flash(context, ident, tool, release, work, progress, superkey)
    if reset:
        import samsung_firmware
        result['data'] = samsung_firmware.reset_data(context, True, progress)
        # The reset that verification off needed is done: later installs need none.
        with contextlib.suppress(fs.FilesystemError, OSError):
            saved_boot.remove_from_cache(context, prepared)
    return result


@contextlib.contextmanager
def work_folder(context, work):
    """A private folder for the patch; on the phone a tmpfs of its own, which allows running Magisk's tools."""
    if context.mode == 'device' and os.path.ismount(work):
        subprocess.run([fs.BUSYBOX, 'umount', str(work)], capture_output=True, timeout=30)
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, mode=0o700)
    mounted = False
    try:
        if context.mode == 'device':
            done = subprocess.run([fs.BUSYBOX, 'mount', '-t', 'tmpfs', '-o', 'mode=0700,nosuid,nodev,size=%d' % WORK_BYTES, 'a22x-root',
                                   str(work)], capture_output=True, text=True, timeout=30)
            require(done.returncode == 0, 'ROOT_WORK_UNAVAILABLE', 'No room in RAM for the patch', detail=done.stderr.strip()[:300])
            mounted = True
        yield work
    finally:
        if mounted:
            subprocess.run([fs.BUSYBOX, 'umount', str(work)], capture_output=True, timeout=30)
        shutil.rmtree(work, ignore_errors=True)


def patch_and_flash(context, ident, tool, release, work, progress, superkey=None):
    bundle = apatch_bundle(context) if tool.get('bundled') else None
    if not bundle:
        apk = work / release['file']
        download(context, release['url'], release['size'], release['sha256'], apk, progress)
    target = context.target('boot')
    boot = install.target_bytes(context, target)  # 2026-11-13 review: a short read is refused
    # Patched as the image itself, without the mark that keeps this recovery: flashing puts it back.
    # With the mark in the tail kptools found no unused tail and repacked a BOOT larger than its
    # partition (2026-11-11, on the phone).
    marked = saved_boot.keep_recovery_spot(boot)
    if marked and marked[1]:
        boot = boot[:marked[0]] + bytes(len(saved_boot.KEEP_RECOVERY_MARK)) + boot[marked[0] + len(saved_boot.KEEP_RECOVERY_MARK):]
    progress('Patching', {'label': 'boot', 'size_bytes': 1}, 0)
    failed = 'APATCH_PATCH_FAILED' if bundle else 'MAGISK_PATCH_FAILED'
    if bundle:
        patched, log = patch_apatch(context, bundle, boot, work, superkey)
    elif context.mode == 'fixture':
        patched, log = fixture_patch(context, boot, work)
    else:
        patched, log = patch_magisk(apk, boot, work)
    try:
        info = bootimage.inspect_boot(patched)
    except bootimage.ImageError as error:
        fail(failed, 'The patched BOOT is not a complete boot image', reason=str(error))
    require(info['device'].get('this_phone') and not info.get('mainline'), failed, 'The patched BOOT is not for this phone')
    require(info.get('root') == ident, failed, 'The patched BOOT has no APatch in it' if bundle else 'Magisk is not in the patched BOOT')
    require(len(patched) <= target['size_bytes'], failed, 'The patched BOOT does not fit its partition')
    digest = hashlib.sha256(patched).hexdigest()
    name = ident + '-' + re.sub(r'[^A-Za-z0-9._+-]', '_', release['version'])[:24] + '-' + digest[:12] + '.img'
    path = saved_boot.save_on_cache(context, name, patched, {'kind': 'android', 'root': ident, 'version': release['version'],
                                                              'release': info['kernel'].get('release', '')},
                                    progress, keep_mounted=True, folder_name=ROOT_DIR)
    cache = context.fs.volume('cache')
    args = types.SimpleNamespace(target='boot', volume='cache', volume_token=cache['volume_token'], path=path, member=None,
                                 image_bytes=None, confirm=True)
    checked = flash.check(context, args, progress)
    args.expected_sha256, args.expected_identity = checked['image']['sha256'], checked['image']['identity']
    written = flash.write(context, args, progress)
    # The patched BOOT is in the partition now and can be made again: cache keeps only the ways back.
    with contextlib.suppress(fs.FilesystemError, OSError):
        saved_boot.remove_from_cache(context, path)
    if not bundle and context.mode == 'device':
        keep_magisk_apk(context, apk, release, progress)
    return {'root': ident, 'name': tool['name'], 'version': release['version'], 'apk': '' if bundle else release['file'], 'boot': path,
            'sha256': written['sha256'], 'kept_boot': written.get('kept_boot'), 'log': log[-12:]}


def fetch_kernel_zip(context, ident, tool, release, work, progress):
    """The kernel's AnyKernel3 ZIP downloaded, checked against its release and kept on cache, for the
    ZIP installer's review: nothing is written to BOOT here."""
    require(0 < release['size'] <= ZIP_LIMIT, 'DOWNLOAD_TOO_LARGE', 'The kernel ZIP is larger than this recovery takes')
    local = work / release['file']
    download(context, release['url'], release['size'], release['sha256'], local, progress)
    data = local.read_bytes()
    try:
        with zipfile.ZipFile(local) as archive:
            names = set(archive.namelist())
    except zipfile.BadZipFile:
        fail('KERNEL_ZIP_INVALID', 'The download is no ZIP')
    require({'anykernel.sh', 'Image.gz', 'META-INF/com/google/android/update-binary'} <= names, 'KERNEL_ZIP_INVALID',
            'The download is no AnyKernel3 ZIP with a kernel')
    path = saved_boot.save_on_cache(context, release['file'], data, {'kind': 'kernel-zip', 'root': ident, 'version': release['version']},
                                    progress, keep_mounted=True, folder_name=KERNEL_ZIP_DIR)
    cache = context.fs.volume('cache')
    return {'root': ident, 'name': tool['name'], 'version': release['version'], 'apk': '',
            'zip': {'volume': 'cache', 'volume_token': cache['volume_token'], 'path': path, 'sha256': release['sha256']}}


def keep_magisk_apk(context, apk, release, progress):
    """The installed Magisk's APK on cache (only the newest), so that a new system's fresh data can get
    Magisk's files before its first start; a failure here does not undo the install."""
    try:
        data = Path(apk).read_bytes()
        name = 'Magisk-' + re.sub(r'[^A-Za-z0-9._+-]', '_', release['version'])[:24] + '.apk'
        for old in saved_boot.saved_boots(context, MAGISK_APK_DIR):
            if old['name'] != name:
                saved_boot.remove_from_cache(context, old['path'])
        saved_boot.save_on_cache(context, name, data, {'kind': 'magisk-apk', 'version': release['version']}, progress,
                                 folder_name=MAGISK_APK_DIR)
    except (OSError, fs.FilesystemError, ValueError, KeyError):
        pass


def fixture_patch(context, boot, work):
    """Tests: a stand-in for boot_patch.sh, a BOOT the test prepared with Magisk's marker in its ramdisk."""
    return (context.root / 'root-downloads/patched-boot.img').read_bytes(), ['- Unpacking boot image', '- Repacking boot image']


def parser():
    result = argparse.ArgumentParser()
    mode = result.add_mutually_exclusive_group(required=True)
    mode.add_argument('--device', action='store_true')
    mode.add_argument('--fixture', type=Path)
    commands = result.add_subparsers(dest='command', required=True)
    commands.add_parser('list')
    commands.add_parser('prepare-vbmeta')
    bootstrap = commands.add_parser('apatch-bootstrap', help='Generate a bootstrap script for booted Android')
    bootstrap.add_argument('--manager-apk', required=True, type=Path, help='Verified APatch Manager 11282 APK')
    command = commands.add_parser('install')
    command.add_argument('--id', required=True)
    command.add_argument('--expected-sha256', required=True)
    command.add_argument('--confirm', action='store_true')
    command.add_argument('--erase-data', action='store_true')
    command.add_argument('--superkey-file', type=Path)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    last = [None, 0.0]

    def progress(phase, target, done):
        now = time.monotonic()
        if phase != last[0] or now - last[1] >= 0.2 or done == target['size_bytes']:
            print(json.dumps({'event': 'progress', 'operation': 'root-' + args.command, 'phase': phase, 'partition': target['label'],
                              'bytes_done': done, 'bytes_total': target['size_bytes']}, separators=(',', ':')), file=sys.stderr, flush=True)
            last[:] = [phase, now]

    try:
        if args.command == 'apatch-bootstrap':
            print(apatch_bootstrap(args.manager_apk), end='', flush=True)
            return 0
        context = install.FixtureContext(args.fixture) if args.fixture else install.DeviceContext()
        if args.command == 'list':
            result = tools(context)
        elif args.command == 'prepare-vbmeta':
            result = prepare_vbmeta(context, progress)
        else:
            superkey = None
            if args.superkey_file:
                # Typed on the phone and handed over in the private RAM folder: read once, then gone.
                superkey = args.superkey_file.read_text(encoding='utf-8').split('\n', 1)[0]
                args.superkey_file.unlink(missing_ok=True)
            result = install_root(context, args.id, args.expected_sha256, args.confirm, progress, args.erase_data, superkey)
        print(json.dumps({'ok': True, 'operation': args.command, **result}, separators=(',', ':')), flush=True)
        return 0
    except Exception as error:  # noqa: BLE001 - every refusal reaches the page as JSON
        code = getattr(error, 'code', None) or ('OPERATION_BUSY' if isinstance(error, BlockingIOError) else 'IO_ERROR')
        print(json.dumps({'ok': False, 'operation': args.command, 'error': {
            'code': code, 'message': str(error), 'details': getattr(error, 'details', {})}}, separators=(',', ':')),
              file=sys.stderr if args.command == 'apatch-bootstrap' else sys.stdout, flush=True)
        return 2


if __name__ == '__main__':
    sys.exit(main())
