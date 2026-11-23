#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Android apps installed by Android itself at its next start (2026-11-21, the owner: an APK from Files or
a download, the Magisk app with its ZIP, and the KernelSU or APatch manager fetched from its release).

The recovery cannot install an app: Android's package manager does it, while Android runs. So the APK is
queued in /data/adb/a22x-apk-queue (root, 0600, adb_data_file) and a one-time root script,
/data/adb/service.d/a22x-apk-queue.sh, waits for the start to complete, installs each queued APK with
`pm install` (the bytes through a pipe, as the migration does), logs to install.log beside them and
removes itself. Magisk, KernelSU and APatch all run the scripts of /data/adb/service.d, so one of them must
be on that Android. With Magisk in the BOOT but its files not yet in /data/adb/magisk (a fresh Magisk
ZIP, before the app's own setup), they are put there from the Magisk APK, as the app's direct install
does: Magisk runs service.d only with them there.

    apk_queue.py --device preview --source-volume V --source-token T --source-path /Download/app.apk
    apk_queue.py --device queue   --source-volume V --source-token T --source-path ... --expected-plan SHA --confirm
    apk_queue.py --device fetch-preview --app kernelsu|apatch|magisk
    apk_queue.py --device fetch   --app ... --expected-plan SHA --confirm
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import zipfile

import android_data as ad
import android_root_adb as root_adb
import filesystem as fs

SCHEMA = 'a22x.apk-queue.plan.v1'
QUEUE = 'a22x-apk-queue'
SCRIPT_DIR, SCRIPT = 'service.d', 'a22x-apk-queue.sh'
MAX_APK = 1 << 30
MAX_QUEUED = 32
# The releases the managers come from: the newest one's APK, with the SHA-256 GitHub states for it.
APPS = {'magisk': ('Magisk', 'topjohnwu/Magisk', r'^Magisk-v[0-9.]+\.apk$'),
        'kernelsu': ('KernelSU', 'tiann/KernelSU', r'(?i)^KernelSU[^/]*\.apk$'),
        # The manager of KernelSU Next (2026-11-21): the kernel this recovery offers for the 4.14 BOOT
        # (root.py kernelsu-next). The one published beside that kernel: KernelSU Next's own v3.4.2
        # speaks interface 5 and warns that it is too old for its legacy kernel (6), seen on the phone.
        'kernelsu-next': ('KernelSU Next', 'Dodaskot/mainline-recovery',
                          r'^KernelSU_Next_v[0-9.]+(?:-[0-9]+-g[0-9a-f]+)?_[0-9]+-release\.apk$', 'kernelsu-next-a22x-'),
        'apatch': ('APatch', 'bmax121/APatch', r'(?i)^APatch[^/]*\.apk$')}
SCRIPT_TEXT = '''#!/system/bin/sh
# From the A22x recovery: Android's package manager installs the APKs queued in /data/adb/a22x-apk-queue
# once the start has completed. install.log stays beside them; this script removes itself when done.
# pm gets each APK as a file in /data/local/tmp, and its output goes into a variable: a descriptor of a file
# in /data/adb handed to it was refused by SELinux, and the install with it (2026-11-21, on the phone).
Q=/data/adb/a22x-apk-queue
until [ "$(getprop sys.boot_completed)" = 1 ]; do sleep 2; done
sleep 3
for f in "$Q"/*.apk; do
  [ -f "$f" ] || continue
  t=/data/local/tmp/a22x-queue-$$.apk
  cp "$f" "$t" && chmod 0644 "$t" && chcon u:object_r:shell_data_file:s0 "$t" 2>/dev/null
  out=$(pm install -r "$t" 2>&1)
  rm -f "$t"
  echo "${f##*/}: $out" >> "$Q/install.log"
  case "$out" in
    *Success*) rm -f "$f" ;;
    *) mv -f "$f" "$f.failed" ;;
  esac
done
rm -f "$0"
'''


def require(value, code, message, **details):
    if not value:
        fs.fail(code, message, **details)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()


def kind(pin, path):
    try:
        with pin.parent(path) as (parent, name):
            st = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError):
        return None
    return 'directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'other'


def runner(pin, boot_root=''):
    """The root framework on this Android that runs /data/adb/service.d, and whether Magisk's files are
    missing from /data/adb/magisk while the BOOT has Magisk. The root in BOOT decides first: the files
    of an earlier root stay in /data/adb after it is replaced (2026-11-21: Magisk's beside KernelSU
    Next's, and the queue said 'Root: magisk')."""
    ksu = kind(pin, '/adb/ksu') == 'directory' and kind(pin, '/adb/ksud') == 'file'
    apatch = kind(pin, '/adb/ap') == 'directory' and kind(pin, '/adb/apd') == 'file'
    magisk = kind(pin, '/adb/magisk/busybox') == 'file'
    if boot_root == 'kernelsu' and ksu:
        return 'kernelsu', False
    if boot_root == 'apatch' and apatch:
        return 'apatch', False
    if magisk and boot_root in ('', 'magisk'):
        return 'magisk', False
    if ksu and boot_root in ('', 'kernelsu'):
        return 'kernelsu', False
    if apatch and boot_root in ('', 'apatch'):
        return 'apatch', False
    if boot_root == 'magisk':
        return 'magisk', True
    return None, False


def boot_root(context):
    """'magisk' when Android's BOOT carries Magisk (android_modules reads it), else ''."""
    import android_modules
    try:
        return android_modules._boot_identity(context).get('root') or ''
    except (fs.FilesystemError, OSError, ValueError, ImportError, Exception):  # a BOOT that cannot be read has none
        return ''


def inspect_apk(fd, size):
    """An APK read without unpacking: a ZIP with AndroidManifest.xml and code or resources."""
    require(0 < size <= MAX_APK, 'APK_INVALID', 'The APK is empty or larger than 1 GiB')
    try:
        with zipfile.ZipFile(os.fdopen(os.dup(fd), 'rb')) as archive:
            names = set(archive.namelist())
            magisk = 'assets/util_functions.sh' in names and 'lib/arm64-v8a/libmagisk.so' in names
    except zipfile.BadZipFile:
        fs.fail('APK_INVALID', 'This file is not an Android app (APK)')
    require('AndroidManifest.xml' in names and ('classes.dex' in names or 'resources.arsc' in names),
            'APK_INVALID', 'This file is not an Android app (APK)')
    return {'magisk': magisk}


def data_state(context):
    """Android's data, which must be open for writing, and its pinned volume token."""
    volume = context.volume('userdata')
    if context.mode == 'fixture':  # synthetic data: mounted for writing is enough
        return volume, None if volume.get('mounted') and not volume.get('read_only') else 'Mount Android data for writing first'
    try:
        ad.admitted(volume, writing=True)
    except fs.FilesystemError as exc:
        return volume, str(exc.message)
    return volume, None


def queued(pin):
    if kind(pin, '/adb/' + QUEUE) != 'directory':
        return []
    with pin.directory('/adb/' + QUEUE) as folder:
        return sorted(n for n in os.listdir(folder) if n.endswith('.apk'))


def plan_for(context, apk, check):
    """The plan of queueing APK ({name, size, sha256, ...}); CHECK reads the APK's content."""
    volume, closed = data_state(context)
    framework, setup, waiting = None, False, []
    if closed is None:
        with fs.PinnedVolume(context, 'userdata', volume['volume_token']) as pin:
            framework, setup = runner(pin, boot_root(context))
            waiting = queued(pin)
    reason = closed
    if reason is None and framework is None:
        reason = 'No Magisk, KernelSU or APatch is on this Android to install the app at its start'
    elif reason is None and setup and not check.get('magisk'):
        reason = "Magisk's files are not in /data/adb/magisk yet: install the Magisk app first, or open it once"
    elif reason is None and len(waiting) >= MAX_QUEUED:
        reason = 'Too many apps are waiting already; start Android first'
    plan = {'schema': SCHEMA, 'allowed': reason is None, 'reason': reason, 'apk': apk, 'framework': framework,
            'magisk_setup': bool(setup and check.get('magisk')), 'waiting': waiting,
            'data_volume_token': volume['volume_token'],
            'writes': '/data/adb/' + QUEUE + ' and /data/adb/' + SCRIPT_DIR + '/' + SCRIPT +
                      (' and /data/adb/magisk' if setup else ''),
            'activation': 'Android installs it after its next start; nothing is installed in recovery'}
    plan['plan_sha256'] = digest(plan)
    return plan


@contextlib.contextmanager
def source(context, volume, token, path):
    fs.require_hash(token, 'source-token')
    relative = fs.clean_path(path)
    with fs.PinnedVolume(context, volume, token) as pin:
        with pin.parent(relative) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                st = os.fstat(fd)
                require(stat.S_ISREG(st.st_mode), 'APK_INVALID', 'Choose an APK file')
                pin.check_fd(fd)
                yield fd, st, name
            finally:
                os.close(fd)


def file_sha(fd):
    sha = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1 << 20):
        sha.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return sha.hexdigest()


def safe_name(name, sha):
    stem = re.sub(r'[^A-Za-z0-9._-]+', '_', name.rsplit('/', 1)[-1])[:80].removesuffix('.apk').removesuffix('.zip')
    return (stem or 'app') + '-' + sha[:12] + '.apk'


def preview(context, volume, token, path):
    with context.operation_lock(shared=True):
        with source(context, volume, token, path) as (fd, st, name):
            check = inspect_apk(fd, st.st_size)
            apk = {'name': name, 'size': st.st_size, 'sha256': file_sha(fd), 'origin': 'file',
                   'source': {'volume': volume, 'path': fs.clean_path(path)}}
        return {'plan': plan_for(context, apk, check)}


def _write_queue(context, plan, fd):
    """The APK, the script and (for a fresh Magisk) its files, written into Android's data."""
    with fs.PinnedVolume(context, 'userdata', plan['data_volume_token'], writing=True) as pin:
        written = []
        with pin.directory('/adb') as adb:
            folder = root_adb._directory(context, adb, QUEUE, 0o700, 0, 0, 'adb')
            try:
                pin.check_fd(folder)
                name = safe_name(plan['apk']['name'], plan['apk']['sha256'])
                partial = '.' + name + '.partial'
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(partial, dir_fd=folder)
                out = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=folder)
                try:
                    sha = hashlib.sha256()
                    os.lseek(fd, 0, os.SEEK_SET)
                    while chunk := os.read(fd, 1 << 20):
                        sha.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            view = view[os.write(out, view):]
                    require(sha.hexdigest() == plan['apk']['sha256'], 'APK_CHANGED', 'The APK changed after its review')
                    root_adb._owner(context, out, 0, 0)
                    root_adb._label(context, out, 'adb')
                    os.fsync(out)
                finally:
                    os.close(out)
                os.rename(partial, name, src_dir_fd=folder, dst_dir_fd=folder)
                os.fsync(folder)
                written.append('adb/' + QUEUE + '/' + name)
            finally:
                os.close(folder)
            if plan['magisk_setup']:
                os.lseek(fd, 0, os.SEEK_SET)
                data = b''
                while chunk := os.read(fd, 1 << 20):
                    data += chunk
                binaries = root_adb._directory(context, adb, 'magisk', 0o755, 0, 0, 'adb')
                try:
                    pin.check_fd(binaries)
                    for item, content in sorted(root_adb.magisk_files(data).items()):
                        root_adb._publish(context, binaries, item, content, 0o755, 0, 0, 'adb')
                finally:
                    os.close(binaries)
                written.append('adb/magisk')
            service = root_adb._directory(context, adb, SCRIPT_DIR, 0o755, 0, 0, 'adb')
            try:
                pin.check_fd(service)
                root_adb._publish(context, service, SCRIPT, SCRIPT_TEXT.encode(), 0o755, 0, 0, 'adb')
                written.append('adb/' + SCRIPT_DIR + '/' + SCRIPT)
            finally:
                os.close(service)
        pin.recheck()
        return written


def queue(context, volume, token, path, expected_plan=None, confirmed=False):
    context.confirm(confirmed)
    fs.require_hash(expected_plan, 'expected-plan')
    with context.operation_lock(shared=True):
        with source(context, volume, token, path) as (fd, st, name):
            check = inspect_apk(fd, st.st_size)
            apk = {'name': name, 'size': st.st_size, 'sha256': file_sha(fd), 'origin': 'file',
                   'source': {'volume': volume, 'path': fs.clean_path(path)}}
            plan = plan_for(context, apk, check)
            require(plan['plan_sha256'] == expected_plan, 'APK_PLAN_CHANGED', 'The app or Android changed; review it again')
            require(plan['allowed'], 'APK_QUEUE_UNAVAILABLE', plan['reason'] or 'The app cannot be queued here')
            written = _write_queue(context, plan, fd)
    return {'status': 'queued', 'plan_sha256': expected_plan, 'written': written, 'activation': plan['activation']}


def release(app):
    import root
    require(app in APPS, 'APK_APP_UNKNOWN', 'Unknown app')
    label, repo, pattern, *tag = APPS[app]
    found = root.tagged(repo, tag[0], re.compile(pattern)) if tag else root.latest(repo, re.compile(pattern))
    require(0 < found['size'] <= MAX_APK, 'APK_INVALID', 'The release file is empty or too large')
    return label, found


def fetch_preview(context, app):
    label, found = release(app)
    apk = {'name': found['file'], 'size': found['size'], 'sha256': found['sha256'], 'origin': 'release',
           'app': app, 'label': label, 'version': found['version'], 'url': found['url']}
    with context.operation_lock(shared=True):
        return {'plan': plan_for(context, apk, {'magisk': app == 'magisk'})}


def fetch(context, app, expected_plan=None, confirmed=False):
    import root
    context.confirm(confirmed)
    fs.require_hash(expected_plan, 'expected-plan')
    label, found = release(app)
    apk = {'name': found['file'], 'size': found['size'], 'sha256': found['sha256'], 'origin': 'release',
           'app': app, 'label': label, 'version': found['version'], 'url': found['url']}
    with tempfile.TemporaryDirectory(prefix='a22x-apk-', dir='/run' if context.mode == 'device' else None) as work:
        target = Path(work) / 'download.apk'
        root.download(context, found['url'], found['size'], found['sha256'], target, lambda *unused: None)
        fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
        try:
            check = inspect_apk(fd, os.fstat(fd).st_size)
            with context.operation_lock(shared=True):
                plan = plan_for(context, apk, check)
                require(plan['plan_sha256'] == expected_plan, 'APK_PLAN_CHANGED', 'The release or Android changed; review it again')
                require(plan['allowed'], 'APK_QUEUE_UNAVAILABLE', plan['reason'] or 'The app cannot be queued here')
                written = _write_queue(context, plan, fd)
        finally:
            os.close(fd)
    return {'status': 'queued', 'plan_sha256': expected_plan, 'written': written, 'activation': plan['activation']}


def parser():
    p = fs.Parser(description=__doc__)
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--device', action='store_true')
    modes.add_argument('--fixture')
    commands = p.add_subparsers(dest='operation', required=True, parser_class=fs.Parser)
    for operation in ('preview', 'queue'):
        sub = commands.add_parser(operation)
        sub.add_argument('--source-volume', required=True)
        sub.add_argument('--source-token', required=True)
        sub.add_argument('--source-path', required=True)
        if operation == 'queue':
            sub.add_argument('--expected-plan', required=True)
            sub.add_argument('--confirm', action='store_true')
    for operation in ('fetch-preview', 'fetch'):
        sub = commands.add_parser(operation)
        sub.add_argument('--app', choices=sorted(APPS), required=True)
        if operation == 'fetch':
            sub.add_argument('--expected-plan', required=True)
            sub.add_argument('--confirm', action='store_true')
    return p


def main(argv=None):
    operation = 'unknown'
    try:
        args = parser().parse_args(argv)
        operation = args.operation
        context = fs.FixtureContext(args.fixture) if args.fixture else fs.DeviceContext()
        if operation == 'preview':
            result = preview(context, args.source_volume, args.source_token, args.source_path)
        elif operation == 'queue':
            result = queue(context, args.source_volume, args.source_token, args.source_path, args.expected_plan, args.confirm)
        elif operation == 'fetch-preview':
            result = fetch_preview(context, args.app)
        else:
            result = fetch(context, args.app, args.expected_plan, args.confirm)
        print(json.dumps({'ok': True, 'operation': operation, 'mode': context.mode, **result}, ensure_ascii=True, separators=(',', ':')))
        return 0
    except fs.FilesystemError as exc:
        error = {'code': exc.code, 'message': exc.message, 'details': exc.details}
    except OSError as exc:
        error = {'code': 'APK_QUEUE_FAILED', 'message': str(exc), 'details': {}}
    print(json.dumps({'ok': False, 'operation': operation, 'error': error}, ensure_ascii=True, separators=(',', ':')))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
