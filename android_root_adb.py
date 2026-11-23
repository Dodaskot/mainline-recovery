#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Root over adb in the next system (2026-11-20, the owner: root with adb and the settings must come
along when Android is replaced).

The migration archive carries, beside the app data:
  - adb's state: the global settings adb_enabled and development_settings_enabled, and the public
    keys of the computers the owner allowed (/data/misc/adb/adb_keys);
  - Magisk's database (/data/adb/magisk.db): its settings (root for apps and adb, ...) and the root
    rule of the adb shell (uid 2000). App rules are not carried: app uids differ in a new system.

Put back into a new system's data, which must be writable (unencrypted, or opened for writing):
  - adb_keys is merged into /data/misc/adb/adb_keys (system:shell 0640, adb_keys_file);
  - the settings and Magisk's rules are applied by a one-time Magisk boot script
    (/data/adb/service.d/a22x-migration.sh): after the system has started, as root, it runs
    `settings put` for every carried value and merges the rules with `magisk --sqlite` from the
    carried database, writes /data/adb/a22x-migration.log and removes itself. The recovery's
    Python has no SQLite, and Android's own tools write the files in their own format.
The new system needs Magisk (install root after the system) for the script to run.

A system whose BOOT carries KernelSU in its kernel (2026-11-20, H3ckedUI, One UI 8.5 for this phone)
is prepared before its first start instead, while its freshly formatted data is still unencrypted.
That data must then have no misc folder: Android's init gives each folder it creates in /data an
encryption policy and goes to recovery when a folder it expects is already there with files in it,
so only /data/adb (KernelSU's own folder, which Android never creates) is written:
  - /data/adb/ksu/.allowlist: KernelSU's list of root rules with root for the adb shell (uid 2000),
    in the kernel's own format (file version 3, app profiles of version 2, 776 bytes each); the
    kernel reads it when zygote first starts, with or without its ksud;
  - /data/adb/ksud: the path KernelSU's kernel runs as root at post-fs-data, services and boot-
    completed. Until the KernelSU manager installs its own ksud there, this one-time stand-in leaves
    init's process group (init kills it when ksud returns) and starts apply.sh in the background;
  - /data/adb/a22x-migration/apply.sh: after the start, merges the carried adb keys (and the keys
    of the computers allowed in this recovery, when asked) into /data/misc/adb/adb_keys, applies the
    settings with `settings put`, logs to /data/adb/a22x-migration.log, then removes itself and the
    stand-in. Magisk's database is not used: KernelSU keeps its own rules.
"""
import os
import re
import stat
import struct

import android_data as ad
import android_preferences as preferences
import filesystem as fs

ROOT = 'root-adb'
GLOBAL = {'adb_enabled': ('0', '1'), 'development_settings_enabled': ('0', '1')}
# Archive name: (source folder in /data, file name, size limit)
FILES = {'adb_keys': ('misc/adb', 'adb_keys', 64 << 10), 'magisk.db': ('adb', 'magisk.db', 4 << 20)}
FLAGS = {'adb_keys': 'adb_keys', 'magisk.db': 'magisk_db'}
# An adb public key line: base64 of Android's RSA key structure, then an optional user@host comment.
KEY_LINE = re.compile(r'[A-Za-z0-9+/]{360,1200}={0,2}(?: [\x21-\x7e][\x20-\x7e]{0,199})?')
SQLITE_MAGIC = b'SQLite format 3\0'
SHELL_UID = 2000
SYSTEM_UID = 1000
LABELS = {'adb_keys': 'u:object_r:adb_keys_file:s0', 'adb': 'u:object_r:adb_data_file:s0'}
SCRIPT_DIR, SCRIPT = 'service.d', 'a22x-migration.sh'
CARRIED = 'a22x-migration'


def adb_keys_lines(data):
    """The key lines of an adb_keys file; anything else in it is refused."""
    try:
        text = data.decode('ascii')
    except UnicodeDecodeError:
        fs.fail('ROOT_ADB_INVALID', 'The adb keys file is not text')
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    ad.require(lines and len(lines) <= 64 and all(KEY_LINE.fullmatch(line) for line in lines),
               'ROOT_ADB_INVALID', 'The adb keys file holds something other than adb public keys')
    return lines


def capture(pin, writer, read_file):
    """The root-adb item, with its files written to the archive under root-adb/; None when this
    Android has none of them (no adb settings, adb keys or Magisk): the copy then goes on without
    the item (2026-11-20: Root and adb is chosen by default, and a phone that never had adb or
    Magisk failed its whole transfer with ROOT_ADB_EMPTY)."""
    item = {'kind': 'root-adb', 'global': {}, 'adb_keys': False, 'magisk_db': False}
    try:
        item['global'] = preferences.read_rules(read_file(pin, 'system/users/0', 'settings_global.xml'), GLOBAL)
    except FileNotFoundError:
        pass
    except ValueError:
        fs.fail('SETTINGS_INVALID', 'Unsupported or damaged Android global settings file')
    found = []
    try:
        for name, (folder, filename, limit) in FILES.items():
            try:
                with pin.directory(folder) as directory:
                    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            except FileNotFoundError:
                continue
            found.append((name, fd))
            pin.check_fd(fd)
            info = os.fstat(fd)
            ad.require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit,
                       'ROOT_ADB_INVALID', 'An adb or Magisk file is empty or too large')
            head = os.pread(fd, max(len(SQLITE_MAGIC), 1 << 16), 0)
            if name == 'adb_keys':
                adb_keys_lines(os.pread(fd, info.st_size, 0))
            else:
                ad.require(head.startswith(SQLITE_MAGIC), 'ROOT_ADB_INVALID', "Magisk's database is not SQLite")
        if not item['global'] and not found:
            return None
        writer.directory(ROOT)
        for name, fd in found:
            writer.file(ROOT + '/' + name, fd, os.fstat(fd))
            item[FLAGS[name]] = True
        return item
    finally:
        for _, fd in found:
            os.close(fd)


def valid_item(item, records):
    """A root-adb manifest item that matches the archive's own records."""
    if not (isinstance(item, dict) and item.keys() == {'kind', 'global', 'adb_keys', 'magisk_db'}
            and item['kind'] == 'root-adb' and isinstance(item['global'], dict)
            and type(item['adb_keys']) is bool and type(item['magisk_db']) is bool
            and all(GLOBAL.get(key) and value in GLOBAL[key] for key, value in item['global'].items())
            and (item['global'] or item['adb_keys'] or item['magisk_db'])):
        return False
    if records.get(ROOT, {}).get('type') != 'directory':
        return False
    members = {name for name in records if name.startswith(ROOT + '/')}
    wanted = {ROOT + '/' + name for name, flag in FLAGS.items() if item[flag]}
    return members == wanted and all(records[name].get('type') == 'file' and 0 < records[name].get('size', 0)
                                     <= FILES[name.split('/', 1)[1]][2] for name in wanted)


def shell_word(value):
    ad.require(re.fullmatch(r'[0-9A-Za-z_.-]{1,64}', value) is not None, 'ROOT_ADB_INVALID', 'Unexpected setting text')
    return value


def settings_lines(global_values, preference_values):
    """`settings put` for every carried value, developer options before adb; each value validated."""
    lines = []
    ordered = sorted(global_values.items(), key=lambda pair: pair[0] != 'development_settings_enabled')
    for key, value in ordered:
        ad.require(GLOBAL.get(key) is not None and value in GLOBAL[key], 'ROOT_ADB_INVALID', 'An adb setting is invalid')
        lines.append(f'settings put global {shell_word(key)} {shell_word(value)}')
    for namespace in ('system', 'secure'):
        for key, value in sorted((preference_values or {}).get(namespace, {}).items()):
            ad.require(preferences.valid(namespace, key, value), 'ROOT_ADB_INVALID', 'An Android preference is invalid')
            lines.append(f'settings put {namespace} {shell_word(key)} {shell_word(value)}')
    return lines


# The end of the scripts' logged block (2026-11-21, crDroid 12): the commands in it (settings, pm,
# cmd) hand their stdin, stdout and stderr to the system server, which may not use a file of
# /data/adb, so with the block's output on the log itself every one of them failed with "Failed
# transaction". They get /dev/null and a pipe; only cat writes the log.
LOG_TAIL = '} < /dev/null 2>&1 | cat > /data/adb/a22x-migration.log'


def boot_script(global_values, preference_values, magisk):
    """The one-time Magisk boot script; every value in it was validated against its rules."""
    lines = ['#!/system/bin/sh',
             "# Once, from the A22x recovery's migration: adb, settings and Magisk's root rules of the earlier system.",
             'D=/data/adb/' + CARRIED,
             'until [ "$(getprop sys.boot_completed)" = 1 ]; do sleep 2; done',
             '{']
    lines += settings_lines(global_values, preference_values)
    if magisk:
        lines.append('[ -f "$D/magisk.db" ] && magisk --sqlite "ATTACH DATABASE \'$D/magisk.db\' AS old; '
                     'INSERT OR REPLACE INTO settings(key,value) SELECT key,value FROM old.settings; '
                     'INSERT OR REPLACE INTO policies(uid,policy,until,logging,notification) '
                     f'SELECT uid,policy,until,logging,notification FROM old.policies WHERE uid={SHELL_UID}; '
                     'DETACH DATABASE old;"')
    lines += ['echo "done $(date)"', LOG_TAIL, 'rm -rf "$D" "$0"', '']
    return '\n'.join(lines).encode()


def _label(context, fd, name):
    if not ad.fixture(context):
        os.setxattr(fd, 'security.selinux', LABELS[name].encode() + b'\0')


def _owner(context, fd, uid, gid):
    if not ad.fixture(context):
        os.fchown(fd, uid, gid)


def _directory(context, parent, name, mode, uid, gid, label):
    try:
        os.mkdir(name, mode, dir_fd=parent)
        created = True
    except FileExistsError:
        created = False
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    if created:
        os.fchmod(fd, mode)
        _owner(context, fd, uid, gid)
        _label(context, fd, label)
    return fd


def _publish(context, directory, name, data, mode, uid, gid, label):
    partial = '.' + name + '.a22x-partial'
    try:
        os.unlink(partial, dir_fd=directory)
    except FileNotFoundError:
        pass
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fchmod(fd, mode)
        _owner(context, fd, uid, gid)
        _label(context, fd, label)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(partial, name, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)


def write_target(context, pin, carried, global_values, preference_values):
    """Put the carried state into the pinned, writable data of the new system."""
    written = []
    with pin.directory('/') as data:
        if 'adb_keys' in carried:
            new = adb_keys_lines(carried['adb_keys'])
            try:
                misc = os.open('misc', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=data)
            except FileNotFoundError:
                fs.fail('ANDROID_NOT_STARTED', 'Start the new Android once, then put back adb and root')
            try:
                pin.check_fd(misc)
                adb = _directory(context, misc, 'adb', 0o2750, SYSTEM_UID, SHELL_UID, 'adb_keys')
                try:
                    pin.check_fd(adb)
                    try:
                        fd = os.open('adb_keys', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=adb)
                        try:
                            pin.check_fd(fd)
                            ad.require(stat.S_ISREG(os.fstat(fd).st_mode), 'ROOT_ADB_INVALID', 'adb_keys is not a file')
                            old = adb_keys_lines(os.pread(fd, FILES['adb_keys'][2], 0))
                        finally:
                            os.close(fd)
                    except FileNotFoundError:
                        old = []
                    merged = old + [line for line in new if line not in old]
                    _publish(context, adb, 'adb_keys', ('\n'.join(merged) + '\n').encode(), 0o640,
                             SYSTEM_UID, SHELL_UID, 'adb_keys')
                    written.append('misc/adb/adb_keys')
                finally:
                    os.close(adb)
            finally:
                os.close(misc)
        script = boot_script(global_values, preference_values, 'magisk.db' in carried)
        adb_root = _directory(context, data, 'adb', 0o700, 0, 0, 'adb')
        try:
            pin.check_fd(adb_root)
            if 'magisk.db' in carried:
                kept = _directory(context, adb_root, CARRIED, 0o700, 0, 0, 'adb')
                try:
                    pin.check_fd(kept)
                    _publish(context, kept, 'magisk.db', carried['magisk.db'], 0o600, 0, 0, 'adb')
                    written.append('adb/' + CARRIED + '/magisk.db')
                finally:
                    os.close(kept)
            service = _directory(context, adb_root, SCRIPT_DIR, 0o755, 0, 0, 'adb')
            try:
                pin.check_fd(service)
                _publish(context, service, SCRIPT, script, 0o755, 0, 0, 'adb')
                written.append('adb/' + SCRIPT_DIR + '/' + SCRIPT)
            finally:
                os.close(service)
        finally:
            os.close(adb_root)
    pin.recheck()
    return written


# KernelSU, before the first start of a new system (see the top of this file).
KSU_MAGIC, KSU_FILE_VERSION, KSU_PROFILE_VERSION, KSU_PROFILE_BYTES = 0x7f4b5355, 3, 2, 776
KSU_DOMAIN = b'u:r:su:s0'
SHELL_PACKAGE = b'com.android.shell'
STAND_IN, APPLY, ALLOWLIST = 'ksud', 'apply.sh', '.allowlist'
STAND_IN_TOKEN = 'a22x-recovery-ksud-stand-in'
STAND_IN_MARK = ('# ' + STAND_IN_TOKEN + ": run by KernelSU's kernel until its manager installs ksud").encode()
RECOVERY_KEYS = '/run/a22x-recovery/adb/adb_keys'


def kernelsu_shell_profile():
    """KernelSU's app profile (version 2) giving root to the adb shell, laid out as the kernel's
    struct app_profile: version, key[256], current_uid, allow_su, then rp_config at 272 (8-aligned):
    use_default, template_name[256], root_profile at 536 (uid, gid, groups_count, groups[32],
    capabilities at 680, selinux_domain[64] at 704, namespaces at 768), 776 bytes in all."""
    profile = bytearray(KSU_PROFILE_BYTES)
    struct.pack_into('<I', profile, 0, KSU_PROFILE_VERSION)
    profile[4:4 + len(SHELL_PACKAGE)] = SHELL_PACKAGE
    struct.pack_into('<i?', profile, 260, SHELL_UID, True)
    profile[272] = 1  # use_default: the kernel's default root profile (uid 0, every capability, su)
    full = (1 << 38) - 1  # CAP_AUDIT_READ (37) is the last capability of the 4.14 kernel
    struct.pack_into('<QQQ', profile, 680, full, full, full)
    profile[704:704 + len(KSU_DOMAIN)] = KSU_DOMAIN  # the kernel refuses a root profile without a domain
    return bytes(profile)


def kernelsu_allowlist():
    return struct.pack('<II', KSU_MAGIC, KSU_FILE_VERSION) + kernelsu_shell_profile()


def early_adb_lines():
    """At post-fs-data, before Android's framework starts (2026-11-20: a first start that never
    reached its end left no adb at all): the carried keys into /data/misc/adb/adb_keys and adb on in
    the USB configuration, so that a computer the owner allowed reaches the phone during the start."""
    return [
        'if [ -s "$D/adb_keys" ] && [ -d /data/misc ]; then',
        # One UI 8.5 makes this folder only in adbd's own APEX rc, after post-fs-data: made here as it would be.
        '  [ -d /data/misc/adb ] || { mkdir /data/misc/adb; chown 1000:2000 /data/misc/adb; chmod 2750 /data/misc/adb; restorecon /data/misc/adb; }',
        '  K=/data/misc/adb/adb_keys; touch "$K"',
        '  while IFS= read -r key; do [ -n "$key" ] && ! grep -qxF "$key" "$K" && echo "$key" >> "$K"; done < "$D/adb_keys"',
        '  chown 1000:2000 "$K"; chmod 0640 "$K"; restorecon "$K"',
        'fi',
        'if [ -f "$D/early-adb" ]; then',
        '  setprop persist.sys.usb.config adb; setprop sys.usb.config adb',
        'fi',
    ]


KSUD_EVENTS = ('post-fs-data', 'services', 'boot-completed', 'post-mount')
RUN_DIR = '/dev/.a22x-migration'


def stand_in_script():
    """/data/adb/ksud until the KernelSU manager puts its own there. init runs it with an argument
    and waits: at post-fs-data it only puts the keys in and turns adb on (early_adb_lines); at services
    or boot-completed it starts apply.sh, once at a time.

    KernelSU's kernel also sends every su of an allowed uid here ("ksud installed, su goes to ksud"),
    already as root: anything but an event of init is such an su, and runs as a root shell (live
    2026-11-22 on crDroid 16: `su -c id` came here as "-c id" and printed nothing, so the adb shell had
    no root until the manager was installed).

    When it returns, init kills its process group and its cgroup (Android 11+). It moves itself to the
    root cgroup first, as ksud and Magisk do, starts apply.sh in a session of its own (setsid), and
    waits until apply.sh has written its pid from that session: returning before, it lost apply.sh to
    the kill every time (live 2026-11-22: nothing ran at a first start; with a second's wait it did).
    A run that died is started again at the next event: the pid it left is not alive."""
    return '\n'.join([
        '#!/system/bin/sh', STAND_IN_MARK.decode(),
        'D=/data/adb/' + CARRIED,
        # A trace of every call, kept after the migration is done: what ran at a first start that went wrong.
        'echo "$1 $(date +%s) uid=$(id -u) $(cat /proc/self/attr/current 2>/dev/null)" >> /data/adb/a22x-migration.trace',
        'case "$1" in',
        '  ' + '|'.join(KSUD_EVENTS) + ') ;;',
        # su's own options before its command (su 0, su root, su -mm): a root shell is what it asks for.
        '  *) while [ "$1" = 0 ] || [ "$1" = root ] || [ "$1" = -mm ] || [ "$1" = --mount-master ] || [ "$1" = -M ]; do shift; done',
        '     exec /system/bin/sh "$@" ;;',
        'esac',
        'if [ "$1" = post-fs-data ]; then',
        *('  ' + line for line in early_adb_lines()),
        '  exit 0',
        'fi',
        'case "$1" in services|boot-completed) ;; *) exit 0 ;; esac',
        '[ -f "$D/' + APPLY + '" ] || exit 0',
        'R=' + RUN_DIR,
        'mkdir -p "$R"',
        # one apply.sh at a time: the one that wrote its pid and is still alive
        'P=$(cat "$R/pid" 2>/dev/null); [ -n "$P" ] && [ -d "/proc/$P" ] && exit 0',
        'rm -f "$R/pid"',
        'for g in /acct /sys/fs/cgroup /dev/cg2_bpf; do',
        '  [ -w "$g/cgroup.procs" ] && echo $$ > "$g/cgroup.procs" 2>/dev/null',
        'done',
        '/system/bin/setsid /system/bin/sh -c \'echo $$ > "$0/pid"; exec /system/bin/sh "$1"\' "$R" "$D/' + APPLY + '"'
        ' < /dev/null > /dev/null 2>&1 &',
        'n=0; while [ ! -s "$R/pid" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n+1)); done',
        'echo "apply.sh started: pid $(cat "$R/pid" 2>/dev/null)" >> /data/adb/a22x-migration.trace',
        'exit 0', '']).encode()


def apply_script(global_values, preference_values, extra_lines=(), cleanup_lines=()):
    """apply.sh: after the start, the keys into adb_keys, the settings (EXTRA_LINES: what else the
    migration puts back, android_first_boot.script_lines), a log; then it goes away."""
    lines = ['#!/system/bin/sh',
             "# Once, from the A22x recovery's migration: adb keys and settings of the earlier system.",
             'D=/data/adb/' + CARRIED,
             'until [ "$(getprop sys.boot_completed)" = 1 ]; do sleep 2; done',
             '{',
             'K=/data/misc/adb/adb_keys',
             'if [ -s "$D/adb_keys" ]; then',
             '  [ -d /data/misc/adb ] || { mkdir -p /data/misc/adb; chown 1000:2000 /data/misc/adb; chmod 2750 /data/misc/adb; }',
             '  touch "$K"',
             '  while IFS= read -r key; do',
             '    [ -n "$key" ] && ! grep -qxF "$key" "$K" && echo "$key" >> "$K"',
             '  done < "$D/adb_keys"',
             '  chown 1000:2000 "$K"; chmod 0640 "$K"; restorecon "$K"',
             'fi']
    lines += settings_lines(global_values, preference_values)
    lines += list(extra_lines)
    lines += ['echo "done $(date)"', LOG_TAIL,
              'grep -qF ' + STAND_IN_TOKEN + ' /data/adb/' + STAND_IN + ' 2>/dev/null && rm -f /data/adb/' + STAND_IN,
              *cleanup_lines, 'rm -rf "$D"', '']
    return '\n'.join(lines).encode()


def write_first_boot(context, pin, carried, global_values, preference_values, extra_keys=(), extra_lines=()):
    """The carried state into the pinned, writable data of a new system that has never started and
    whose BOOT carries KernelSU: only /data/adb is written."""
    keys = []
    for source in ([carried['adb_keys']] if 'adb_keys' in carried else []) + list(extra_keys):
        keys += [line for line in adb_keys_lines(source) if line not in keys]
    script = apply_script(global_values, preference_values, extra_lines)
    written = []
    with pin.directory('/') as data:
        for name in ('misc', 'system', 'unencrypted'):
            try:
                os.stat(name, dir_fd=data, follow_symlinks=False)
            except FileNotFoundError:
                continue
            fs.fail('ANDROID_ALREADY_STARTED', 'This Android has started already: KernelSU is prepared only before its first start',
                    found=name)
        adb_root = _directory(context, data, 'adb', 0o700, 0, 0, 'adb')
        try:
            pin.check_fd(adb_root)
            try:
                fd = os.open(STAND_IN, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=adb_root)
                try:
                    pin.check_fd(fd)
                    ad.require(STAND_IN_MARK in os.pread(fd, 4096, 0), 'KERNELSU_DAEMON_PRESENT',
                               "KernelSU's own ksud is already in this data")
                finally:
                    os.close(fd)
            except FileNotFoundError:
                pass
            ksu = _directory(context, adb_root, 'ksu', 0o700, 0, 0, 'adb')
            try:
                pin.check_fd(ksu)
                _publish(context, ksu, ALLOWLIST, kernelsu_allowlist(), 0o600, 0, 0, 'adb')
                written.append('adb/ksu/' + ALLOWLIST)
            finally:
                os.close(ksu)
            kept = _directory(context, adb_root, CARRIED, 0o700, 0, 0, 'adb')
            try:
                pin.check_fd(kept)
                _publish(context, kept, 'adb_keys', ''.join(line + '\n' for line in keys).encode(), 0o600, 0, 0, 'adb')
                _publish(context, kept, APPLY, script, 0o700, 0, 0, 'adb')
                written += ['adb/' + CARRIED + '/adb_keys', 'adb/' + CARRIED + '/' + APPLY]
                if global_values.get('adb_enabled') == '1':
                    _publish(context, kept, 'early-adb', b'1\n', 0o600, 0, 0, 'adb')
                    written.append('adb/' + CARRIED + '/early-adb')
            finally:
                os.close(kept)
            _publish(context, adb_root, STAND_IN, stand_in_script(), 0o755, 0, 0, 'adb')
            written.append('adb/' + STAND_IN)
        finally:
            os.close(adb_root)
    pin.recheck()
    return written, len(keys)


# Magisk, before the first start of a new system whose BOOT root.py patched with Magisk (2026-11-20):
# Magisk runs the scripts of /data/adb/service.d only when its files are in /data/adb/magisk (busybox
# first), as the Magisk app's direct install puts them; they come from the APK root.py kept on cache.
MAGISK_FILES = (('lib/arm64-v8a/libbusybox.so', 'busybox', True), ('lib/arm64-v8a/libmagisk.so', 'magisk', True),
                ('lib/arm64-v8a/libmagiskinit.so', 'magiskinit', True), ('lib/arm64-v8a/libmagiskboot.so', 'magiskboot', False),
                ('lib/arm64-v8a/libmagiskpolicy.so', 'magiskpolicy', False), ('lib/arm64-v8a/libinit-ld.so', 'init-ld', False),
                ('assets/util_functions.sh', 'util_functions.sh', True), ('assets/boot_patch.sh', 'boot_patch.sh', False),
                ('assets/addon.d.sh', 'addon.d.sh', False), ('assets/stub.apk', 'stub.apk', False))
MAGISK_SHELL_RULES = [
    "magisk --sqlite \"INSERT OR REPLACE INTO settings (key,value) VALUES('root_access',3)\"",
    f"magisk --sqlite \"INSERT OR REPLACE INTO policies (uid,policy,until,logging,notification) VALUES({SHELL_UID},2,0,1,1)\"",
    'if [ -s "$D/magisk.apk" ] && ! pm path com.topjohnwu.magisk >/dev/null 2>&1; then',
    '  cat "$D/magisk.apk" | pm install -S "$(stat -c %s "$D/magisk.apk")" && echo "Magisk app installed"',
    'fi',
]


def magisk_files(apk_bytes):
    """Magisk's files for /data/adb/magisk from its APK: {name: bytes}."""
    import io
    import zipfile
    try:
        archive = zipfile.ZipFile(io.BytesIO(apk_bytes))
    except zipfile.BadZipFile:
        fs.fail('MAGISK_APK_INVALID', 'The kept Magisk APK is damaged')
    found = {}
    with archive:
        names = set(archive.namelist())
        for member, name, required in MAGISK_FILES:
            if member in names:
                found[name] = archive.read(member)
            else:
                ad.require(not required, 'MAGISK_APK_INVALID', 'The kept Magisk APK lacks a file Magisk needs')
    return found


def write_first_boot_magisk(context, pin, carried, global_values, preference_values, apk_bytes, extra_keys=(), extra_lines=()):
    """As write_first_boot, for a BOOT with Magisk: /data/adb/magisk from the APK, the one-time script in
    /data/adb/service.d, the adb shell's root rule and the Magisk app put in by that script."""
    keys = []
    for source in ([carried['adb_keys']] if 'adb_keys' in carried else []) + list(extra_keys):
        keys += [line for line in adb_keys_lines(source) if line not in keys]
    files = magisk_files(apk_bytes)
    script = apply_script(global_values, preference_values, MAGISK_SHELL_RULES + list(extra_lines),
                          cleanup_lines=['rm -f /data/adb/' + SCRIPT_DIR + '/' + SCRIPT])
    written = []
    with pin.directory('/') as data:
        for name in ('misc', 'system', 'unencrypted'):
            try:
                os.stat(name, dir_fd=data, follow_symlinks=False)
            except FileNotFoundError:
                continue
            fs.fail('ANDROID_ALREADY_STARTED', 'This Android has started already: Magisk is prepared only before its first start',
                    found=name)
        adb_root = _directory(context, data, 'adb', 0o700, 0, 0, 'adb')
        try:
            pin.check_fd(adb_root)
            binaries = _directory(context, adb_root, 'magisk', 0o755, 0, 0, 'adb')
            try:
                pin.check_fd(binaries)
                for name, content in sorted(files.items()):
                    _publish(context, binaries, name, content, 0o755, 0, 0, 'adb')
                written.append('adb/magisk/' + ','.join(sorted(files)))
            finally:
                os.close(binaries)
            kept = _directory(context, adb_root, CARRIED, 0o700, 0, 0, 'adb')
            try:
                pin.check_fd(kept)
                _publish(context, kept, 'adb_keys', ''.join(line + '\n' for line in keys).encode(), 0o600, 0, 0, 'adb')
                _publish(context, kept, 'magisk.apk', apk_bytes, 0o600, 0, 0, 'adb')
                written += ['adb/' + CARRIED + '/adb_keys', 'adb/' + CARRIED + '/magisk.apk']
                if global_values.get('adb_enabled') == '1':
                    _publish(context, kept, 'early-adb', b'1\n', 0o600, 0, 0, 'adb')
                    written.append('adb/' + CARRIED + '/early-adb')
            finally:
                os.close(kept)
            service = _directory(context, adb_root, SCRIPT_DIR, 0o755, 0, 0, 'adb')
            try:
                pin.check_fd(service)
                _publish(context, service, SCRIPT, script, 0o755, 0, 0, 'adb')
                written.append('adb/' + SCRIPT_DIR + '/' + SCRIPT)
            finally:
                os.close(service)
            early = _directory(context, adb_root, 'post-fs-data.d', 0o755, 0, 0, 'adb')
            try:
                pin.check_fd(early)
                lines = ['#!/system/bin/sh', '# Once, from the A22x recovery: adb keys and adb on before the framework starts.',
                         'D=/data/adb/' + CARRIED, *early_adb_lines(), 'rm -f "$0"', '']
                _publish(context, early, SCRIPT, '\n'.join(lines).encode(), 0o755, 0, 0, 'adb')
                written.append('adb/post-fs-data.d/' + SCRIPT)
            finally:
                os.close(early)
        finally:
            os.close(adb_root)
    pin.recheck()
    return written, len(keys)
