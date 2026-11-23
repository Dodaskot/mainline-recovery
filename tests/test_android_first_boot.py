"""Apps and Wi-Fi staged for the new system's one-time script (2026-11-20)."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import time
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import android_first_boot as first_boot
import android_migration as migration
import filesystem as fs
from test_android_migration import PASSWORD
from test_android_root_adb import RootAdbTest

WIFI = ('<?xml version="1.0" encoding="utf-8" standalone="yes" ?><WifiConfigStoreData><NetworkList>'
        '<Network><WifiConfiguration><string name="ConfigKey">&quot;Home&quot;WPA_PSK</string>'
        '<string name="SSID">&quot;Home&quot;</string><string name="PreSharedKey">&quot;secret-pass&quot;</string>'
        '</WifiConfiguration></Network>'
        '<Network><WifiConfiguration><string name="ConfigKey">&quot;Cafe&quot;NONE</string>'
        '<string name="SSID">&quot;Cafe&quot;</string></WifiConfiguration></Network>'
        '<Network><WifiConfiguration><string name="ConfigKey">&quot;Work&quot;WPA_EAP</string>'
        '<string name="SSID">&quot;Work&quot;</string></WifiConfiguration></Network>'
        '<Network><WifiConfiguration><string name="ConfigKey">&quot;New&quot;SAE</string>'
        '<string name="SSID">&quot;New&quot;</string><string name="PreSharedKey">&quot;sae-password&quot;</string>'
        '</WifiConfiguration></Network></NetworkList></WifiConfigStoreData>')


class FirstBootStagingTest(RootAdbTest):
    def test_wifi_staged_for_the_script(self):
        store = self.data / 'misc/apexdata/com.android.wifi'
        store.mkdir(parents=True)
        (store / 'WifiConfigStore.xml').write_text(WIFI)
        contacts = self.data / 'data/com.android.providers.contacts/databases'
        contacts.mkdir(parents=True)
        (contacts / 'contacts2.db').write_bytes(b'SQLite format 3\0' + bytes(4080))
        (contacts / 'contacts2.db-wal').write_bytes(b'wal bytes')
        result = self.backup(include_settings=True, include_root_adb=True, include_personal=True)
        shutil.rmtree(self.target / 'misc')
        (self.target / 'system/packages.xml').unlink()
        (self.target / 'system').rmdir()
        path = result['path'].lstrip('/')
        copy = self.target.parent / 'sd' / path
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.data.parent / 'sd' / path, copy)
        context = self.target_context
        reported = io.StringIO()
        with context.operation_lock(), mock.patch.object(migration, 'boot_root', return_value='kernelsu'), \
                mock.patch.object(migration, 'fresh_userdata'), contextlib.redirect_stderr(reported):
            restored = migration.restore_root_adb(context, 'sdcard-p1', context.volume('sdcard-p1')['volume_token'],
                                                  result['path'], result['archive_sha256'],
                                                  context.volume('userdata')['volume_token'], PASSWORD,
                                                  True, first_boot=True, stage_apps=True, stage_wifi=True)
        self.assertEqual(restored['staged'], {'apps': [], 'wifi_networks': 3, 'contacts': True, 'recovery_wifi': 0})
        # The work page's stages, in order; staging ends with all of the archive's bytes read.
        events = [json.loads(line) for line in reported.getvalue().splitlines()]
        phases = [event['phase'] for event in events]
        self.assertEqual(list(dict.fromkeys(phases)), ['first-boot-data', 'first-boot-root', 'first-boot-verify',
                                                      'first-boot-read', 'first-boot-write', 'first-boot-stage'])
        self.assertTrue(all(event['event'] == 'progress' and event['operation'] == 'restore-root-adb' for event in events))
        self.assertIn('personal', {event['partition'] for event in events})
        self.assertEqual(events[-1]['bytes_done'], events[-1]['bytes_total'])
        self.assertGreater(events[-1]['bytes_total'], 0)
        self.assertEqual((self.target / 'adb/a22x-migration/restore/contacts/contacts2.db-wal').read_bytes(), b'wal bytes')
        self.assertEqual((self.target / 'adb/a22x-migration/restore/agent.dex').read_bytes()[:4], b'dex\n')
        staged = self.target / 'adb/a22x-migration/restore'
        self.assertEqual((staged / 'wifi.list').read_text().splitlines(),
                         ['Home\twpa2\tsecret-pass', 'Cafe\topen\t', 'New\twpa3\tsae-password'])
        self.assertEqual((staged / 'apps.list').read_text(), '')
        apply = (self.target / 'adb/a22x-migration/apply.sh').read_text()
        self.assertIn('cmd wifi add-network', apply)
        self.assertIn('pm install-create', apply)
        self.assertIn('org.a22x.migration.Agent contacts', apply)

    def test_stager_writes_apks_and_per_scope_tars(self):
        root = Path(self.root) / 'stage'
        root.mkdir()
        folder = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, folder)
        pin = mock.Mock()
        manifest = {'items': [{'kind': 'app-data', 'package': 'org.example.app'}]}
        stager = first_boot.Stager(None, pin, manifest, folder)

        def member(name, data=None, directory=False):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
            info.mode, info.mtime, info.size = (0o771 if directory else 0o660), 1700000000, len(data or b'')
            stream = io.BytesIO(data or b'')
            parts = name.split('/')
            self.assertTrue(stager.wants(parts))
            stager.take(parts, info, stream.read)

        member('apps/org.example.app/apk/base.apk', b'PK base')
        member('apps/org.example.app/apk/split_config.arm64_v8a.apk', b'PK split')
        member('apps/org.example.app/ce/databases', directory=True)
        member('apps/org.example.app/ce/databases/app.db', b'sqlite bytes')
        member('apps/org.example.app/de/state.xml', b'<x/>')
        self.assertFalse(stager.wants(['apps', 'other.app', 'ce', 'f']))
        self.assertFalse(stager.wants(['shared', 'DCIM', 'a.jpg']))
        self.assertEqual(stager.finish(), {'apps': ['org.example.app'], 'wifi_networks': 0, 'contacts': False, 'recovery_wifi': 0})
        app = root / 'restore/apps/org.example.app'
        self.assertEqual((app / 'apk/base.apk').read_bytes(), b'PK base')
        self.assertEqual(sorted(p.name for p in (app / 'apk').iterdir()), ['base.apk', 'split_config.arm64_v8a.apk'])
        with tarfile.open(app / 'ce.tar') as tar:
            self.assertEqual(tar.getnames(), ['databases', 'databases/app.db'])
            self.assertEqual(tar.extractfile('databases/app.db').read(), b'sqlite bytes')
        with tarfile.open(app / 'de.tar') as tar:
            self.assertEqual(tar.getnames(), ['state.xml'])
        self.assertEqual((root / 'restore/apps.list').read_text(), 'org.example.app\n')

    def test_magisk_first_start(self):
        import zipfile
        apk = io.BytesIO()
        with zipfile.ZipFile(apk, 'w') as archive:
            for member in ('lib/arm64-v8a/libbusybox.so', 'lib/arm64-v8a/libmagisk.so', 'lib/arm64-v8a/libmagiskinit.so',
                           'assets/util_functions.sh', 'assets/stub.apk'):
                archive.writestr(member, member.encode())
        result = self.backup(include_settings=True, include_root_adb=True)
        shutil.rmtree(self.target / 'misc')
        (self.target / 'system/packages.xml').unlink()
        (self.target / 'system').rmdir()
        path = result['path'].lstrip('/')
        copy = self.target.parent / 'sd' / path
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.data.parent / 'sd' / path, copy)
        context = self.target_context
        with context.operation_lock(), mock.patch.object(migration, 'boot_root', return_value='magisk'), \
                mock.patch.object(migration, 'fresh_userdata'), mock.patch.object(migration, 'kept_magisk_apk', return_value=apk.getvalue()):
            restored = migration.restore_root_adb(context, 'sdcard-p1', context.volume('sdcard-p1')['volume_token'],
                                                  result['path'], result['archive_sha256'],
                                                  context.volume('userdata')['volume_token'], PASSWORD, True, first_boot=True)
        self.assertEqual(restored['shell_root'], 'magisk')
        self.assertEqual(sorted(p.name for p in (self.target / 'adb/magisk').iterdir()),
                         ['busybox', 'magisk', 'magiskinit', 'stub.apk', 'util_functions.sh'])
        script = (self.target / 'adb/service.d/a22x-migration.sh').read_text()
        self.assertIn("VALUES(2000,2,0,1,1)", script)
        self.assertIn('rm -f /data/adb/service.d/a22x-migration.sh', script)
        self.assertFalse((self.target / 'adb/ksud').exists())
        self.assertEqual((self.target / 'adb/a22x-migration/magisk.apk').read_bytes(), apk.getvalue())
        early = (self.target / 'adb/post-fs-data.d/a22x-migration.sh').read_text()
        self.assertIn('setprop persist.sys.usb.config adb', early)
        self.assertTrue((self.target / 'adb/a22x-migration/early-adb').exists())
        with zipfile.ZipFile(apk, 'w') as broken:
            broken.writestr('lib/arm64-v8a/libmagisk.so', b'x')
        import android_root_adb as root_adb
        with self.assertRaises(fs.FilesystemError):
            root_adb.magisk_files(apk.getvalue())

    def test_networks_without_a_clear_secret_are_left_out(self):
        self.assertEqual(first_boot.wifi_networks(WIFI.encode()),
                         [('Home', 'wpa2', 'secret-pass'), ('Cafe', 'open', ''), ('New', 'wpa3', 'sae-password')])
        self.assertEqual(first_boot.wifi_networks(b'not xml'), [])


del RootAdbTest

if __name__ == '__main__':
    unittest.main()


# Android's pm, am, cmd and settings hand their stdin, stdout and stderr to the system server, which
# may not use a file of /data/adb (2026-11-21 on crDroid 12: "Failed transaction" for every pm and cmd
# whose output went into /data/adb/a22x-migration.log or whose input was a staged list). The stand-ins
# note any regular file on those descriptors; the scripts give them pipes and /dev/null only.
FD_GUARD = ('for n in 0 1 2; do t=$(readlink /proc/$$/fd/$n); [ -f "$t" ] && echo "${0##*/} fd$n $t" >> "$LOG.fds"; done; '
            'true')
FAKE_COMMANDS = {
    'am': 'case "$1" in get-started-user-state) echo RUNNING_UNLOCKED ;; *) echo "am $*" >> "$LOG" ;; esac',
    'pm': '\n'.join([
        'case "$1" in',
        '  path) [ -e "$STATE/installed-$2" ] && { echo "package:/data/app/$2/base.apk"; exit 0; }; exit 1 ;;',
        '  install-create) echo "pm $*" >> "$LOG"; echo "Success: created install session [42]" ;;',
        '  install-write) n=$(cat | wc -c); echo "pm $* read=$n" >> "$LOG"; echo Success ;;',
        '  install-commit) echo "pm $*" >> "$LOG"; while read -r p; do touch "$STATE/installed-$p"; done < "$STATE/committing"; echo Success ;;',
        'esac']),
    'cmd': 'printf cmd >> "$LOG"; for a in "$@"; do printf "|%s" "$a" >> "$LOG"; done; echo >> "$LOG"',
    'chown': 'echo "chown $*" >> "$LOG"',
    'restorecon': 'echo "restorecon $*" >> "$LOG"',
    'app_process': 'echo "app_process CLASSPATH=$CLASSPATH $*" >> "$LOG"',
    # Android's toybox: the app folder's context with the app's categories, then chcon of what was restored.
    'ls': 'case "$1" in -dZ) echo "u:object_r:app_data_file:s0:c118,c257,c512,c768 $2" ;; *) /bin/ls "$@" ;; esac',
    'chcon': 'echo "chcon $*" >> "$LOG"',
}


class FirstBootScriptRunTest(unittest.TestCase):
    """script_lines() run by sh, with stand-ins for Android's pm, am, cmd, chown, restorecon and
    app_process, over what the Stager staged: the shell itself (quoting, the session id, the
    tab-separated networks, the folders and owners) is what is checked here."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.bin, self.state, self.log = self.root / 'bin', self.root / 'state', self.root / 'calls.log'
        self.bin.mkdir()
        self.state.mkdir()
        for name, body in FAKE_COMMANDS.items():
            guard = FD_GUARD + '\n' if name in ('am', 'pm', 'cmd') else ''
            (self.bin / name).write_text('#!/bin/sh\n' + guard + body + '\n')
            (self.bin / name).chmod(0o755)

    def stage(self):
        stage = self.root / 'migration'
        stage.mkdir()
        folder = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, folder)
        manifest = {'items': [{'kind': 'app-data', 'package': 'org.example.app'},
                              {'kind': 'app-data', 'package': 'org.example.kept'}]}
        home = 'My Home 5G'.encode().hex()  # also in the archive (with its passphrase): the archive's entry wins
        office = 'Office'.encode().hex()
        stager = first_boot.Stager(None, mock.Mock(), manifest, folder,
                                   recovery_networks=[(home, 'a' * 64), (office, 'b' * 64), ('zz', 'bad')])

        def member(name, data=None, directory=False):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
            info.mode, info.mtime, info.size = (0o771 if directory else 0o660), 1700000000, len(data or b'')
            parts = name.split('/')
            self.assertTrue(stager.wants(parts), name)
            stager.take(parts, info, io.BytesIO(data or b'').read)

        member('apps/org.example.app/apk/base.apk', b'PK base')
        member('apps/org.example.app/apk/split_config.arm64_v8a.apk', b'PK split')
        member('apps/org.example.app/ce/databases', directory=True)
        member('apps/org.example.app/ce/databases/app.db', b'sqlite bytes')
        member('apps/org.example.app/de/state.xml', b'<x/>')
        member('apps/org.example.kept/ce/files/note.txt', b'kept')
        wifi = WIFI.replace('&quot;Home&quot;', '&quot;My Home 5G&quot;').replace('secret-pass', 'p@ss word $1')
        member('personal/wifi-0.xml', wifi.encode())
        member('personal/com.android.providers.contacts.contacts2.db', b'SQLite format 3\0' + bytes(16))
        self.assertEqual(stager.finish(), {'apps': ['org.example.app', 'org.example.kept'],
                                           'wifi_networks': 3, 'contacts': True, 'recovery_wifi': 1})
        self.assertEqual((stage / 'restore/recovery-wifi.list').read_text(), office + '\t' + 'b' * 64 + '\n')
        return stage

    def run_script(self, stage, committing='org.example.app\n', shell=('sh',)):
        data = self.root / 'data'
        for folder in ('data/org.example.app/cache', 'data/org.example.app/code_cache', 'user_de/0/org.example.app',
                       'data/org.example.kept'):
            (data / folder).mkdir(parents=True)
        (self.state / 'installed-org.example.kept').touch()  # already on the new system: only its files
        (self.state / 'committing').write_text(committing)  # what the package manager installs
        script = '\n'.join(first_boot.script_lines())
        script = script.replace('base=/data/data', 'base=%s/data' % data).replace('/data/user_de/0', '%s/user_de/0' % data)
        env = {'PATH': '%s:/usr/bin:/bin' % self.bin, 'D': str(stage), 'LOG': str(self.log), 'STATE': str(self.state)}
        run = subprocess.run([*shell, '-c', script], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        fds = Path(str(self.log) + '.fds')
        self.assertFalse(fds.exists(), fds.read_text() if fds.exists() else '')
        # pm's own "Success" lines go to the migration log as on the phone.
        output = [line for line in run.stdout.splitlines() if not line.startswith('Success')]
        return data, output, self.log.read_text().splitlines()

    def test_apps_networks_and_contacts_come_back_through_android(self):
        stage = self.stage()
        data, output, calls = self.run_script(stage)
        self.assertEqual(output, ['app org.example.app: restored', 'app org.example.kept: restored',
                                  'wifi network added from recovery',
                                  'wifi network added', 'wifi network added', 'wifi network added'])
        app = 'org.example.app'
        apk = stage / 'restore/apps' / app / 'apk'
        self.assertIn('pm install-create -r -S 15', calls)
        self.assertIn('pm install-write -S 7 42 base.apk - read=7', calls)
        self.assertIn('pm install-write -S 8 42 split_config.arm64_v8a.apk - read=8', calls)
        self.assertIn('pm install-commit 42', calls)
        self.assertEqual(sum(line.startswith('pm install-create') for line in calls), 1)  # the kept app is not installed again
        self.assertIn('am force-stop %s' % app, calls)
        self.assertIn('am force-stop org.example.kept', calls)
        self.assertEqual((data / 'data' / app / 'databases/app.db').read_bytes(), b'sqlite bytes')
        self.assertEqual((data / 'user_de/0' / app / 'state.xml').read_bytes(), b'<x/>')
        self.assertEqual((data / 'data/org.example.kept/files/note.txt').read_bytes(), b'kept')
        uid = os.getuid()
        chowned = [line for line in calls if line.startswith('chown ')]
        self.assertIn('chown -R %d:%d %s' % (uid, uid, data / 'data' / app / 'databases'), chowned)
        self.assertFalse([line for line in chowned if line.endswith('/cache') or line.endswith('/code_cache')])
        self.assertIn('restorecon -RF %s' % (data / 'data' / app), calls)
        # What was restored takes the folder's categories; Android's own cache folders are left alone.
        relabelled = [line for line in calls if line.startswith('chcon -R u:object_r:app_data_file:s0:c118,c257,c512,c768 ')]
        self.assertTrue(any(line.endswith('/data/%s/databases' % app) for line in relabelled), relabelled)
        self.assertFalse([line for line in relabelled if line.endswith('/cache') or line.endswith('/code_cache')])
        self.assertIn('restorecon -RF %s' % (data / 'user_de/0' / app), calls)
        self.assertIn('cmd|wifi|add-network|My Home 5G|wpa2|p@ss word $1', calls)
        self.assertIn('cmd|wifi|add-network|Cafe|open', calls)
        self.assertIn('cmd|wifi|add-network|New|wpa3|sae-password', calls)
        restore = stage / 'restore'
        self.assertIn('app_process CLASSPATH=%s/agent.dex /system/bin org.a22x.migration.Agent contacts %s/contacts/contacts2.db'
                      % (restore, restore), calls)
        self.assertIn('app_process CLASSPATH=%s/agent.dex /system/bin org.a22x.migration.Agent wifi %s %s'
                      % (restore, 'Office'.encode().hex(), 'b' * 64), calls)
        self.assertIn('wifi network added from recovery', output)
        self.assertTrue(apk.is_dir())

    @unittest.skipUnless(shutil.which('busybox'), 'no busybox')
    def test_the_script_is_plain_posix_shell(self):
        """Android's shell is mksh; busybox's ash is a stricter stand-in than bash's sh."""
        stage = self.stage()
        data, output, calls = self.run_script(stage, shell=('busybox', 'sh'))
        self.assertEqual(output, ['app org.example.app: restored', 'app org.example.kept: restored',
                                  'wifi network added from recovery',
                                  'wifi network added', 'wifi network added', 'wifi network added'])
        self.assertIn('cmd|wifi|add-network|My Home 5G|wpa2|p@ss word $1', calls)
        self.assertEqual((data / 'data/org.example.app/databases/app.db').read_bytes(), b'sqlite bytes')

    def test_an_app_that_does_not_install_leaves_the_others(self):
        stage = self.stage()
        data, output, calls = self.run_script(stage, committing='')  # the package manager refuses the APKs
        self.assertEqual(output[:2], ['app org.example.app: not installed', 'app org.example.kept: restored'])
        self.assertIn('pm install-commit 42', calls)
        self.assertNotIn('am force-stop org.example.app', calls)
        self.assertFalse((data / 'data/org.example.app/databases').exists())
        self.assertEqual(output.count('wifi network added'), 3)


class KernelSuFirstStartRunTest(unittest.TestCase):
    """The stand-in ksud and apply.sh run by sh, as KernelSU's kernel starts them at post-fs-data,
    services and boot-completed (paths moved into a temporary root; Android's commands stand-ins)."""

    KEYS = ['QAAAAOldKey= owner@pc', 'QAAAANewKey= owner@laptop']

    def setUp(self):
        import android_root_adb as root_adb
        self.root_adb = root_adb
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.bin, self.log = self.root / 'bin', self.root / 'calls.log'
        self.bin.mkdir()
        fakes = {'setprop': 'echo "setprop $*" >> "$LOG"',
                 # Android has started once the test says so (boot-completed): apply.sh waits for it
                 'getprop': '[ "$1" = sys.boot_completed ] && [ -e "$LOG.booted" ] && echo 1',
                 'settings': FD_GUARD + '\necho "settings $*" >> "$LOG"',
                 'chown': 'echo "chown $*" >> "$LOG"',
                 'restorecon': 'echo "restorecon $*" >> "$LOG"'}
        for name, body in fakes.items():
            (self.bin / name).write_text('#!/bin/sh\n' + body + '\n')
            (self.bin / name).chmod(0o755)
        self.adb = self.root / 'data/adb'
        self.carried = self.adb / root_adb.CARRIED
        self.carried.mkdir(parents=True)
        (self.root / 'data/misc').mkdir(parents=True)
        (self.root / 'dev').mkdir()
        (self.root / 'cg').mkdir()
        (self.root / 'cg/cgroup.procs').write_text('')
        (self.carried / 'adb_keys').write_text(''.join(key + '\n' for key in self.KEYS))
        (self.carried / 'early-adb').write_text('1\n')
        apply = root_adb.apply_script({'adb_enabled': '1', 'development_settings_enabled': '1'}, {})
        (self.carried / root_adb.APPLY).write_bytes(self.moved(apply))
        (self.adb / root_adb.STAND_IN).write_bytes(self.moved(root_adb.stand_in_script()))

    def moved(self, script):
        text = script.decode()
        text = text.replace('/data/', '%s/data/' % self.root).replace('/dev/.a22x-migration', '%s/dev/.a22x-migration' % self.root)
        text = text.replace('for g in /acct /sys/fs/cgroup /dev/cg2_bpf; do', 'for g in %s/cg; do' % self.root)
        return text.replace('/system/bin/setsid ', 'setsid ').replace('/system/bin/sh ', 'sh ').encode()

    def ksud(self, stage, *more):
        env = {'PATH': '%s:/usr/bin:/bin' % self.bin, 'LOG': str(self.log)}
        run = subprocess.run(['sh', str(self.adb / self.root_adb.STAND_IN), stage, *more], env=env, stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout

    def events(self):
        trace = (self.adb / 'a22x-migration.trace').read_text().splitlines()
        return [line.split()[0] for line in trace if not line.startswith('apply.sh started')]

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_post_fs_data_turns_adb_on_with_the_owner_s_keys(self):
        keys = self.root / 'data/misc/adb/adb_keys'
        self.ksud('post-fs-data')
        self.assertEqual(keys.read_text().splitlines(), self.KEYS)
        self.assertIn('setprop persist.sys.usb.config adb', self.calls())
        self.assertIn('setprop sys.usb.config adb', self.calls())
        self.assertIn('chown 1000:2000 %s' % keys, self.calls())
        keys.write_text(self.KEYS[1] + '\nQAAAAOther= someone\n')  # a key the new system had already
        self.ksud('post-fs-data')
        self.assertEqual(keys.read_text().splitlines(), [self.KEYS[1], 'QAAAAOther= someone', self.KEYS[0]])
        self.assertTrue((self.carried / self.root_adb.APPLY).exists())  # nothing is applied before the start
        self.assertEqual(self.events(), ['post-fs-data', 'post-fs-data'])

    def test_without_the_early_mark_adb_waits_for_the_settings(self):
        (self.carried / 'early-adb').unlink()
        self.ksud('post-fs-data')
        self.assertFalse([line for line in self.calls() if line.startswith('setprop')])

    def test_services_applies_once_then_everything_goes(self):
        import time
        self.ksud('services')
        self.ksud('boot-completed')  # the second call finds apply.sh started already
        Path(str(self.log) + '.booted').touch()
        for _ in range(200):
            if not self.carried.exists():
                break
            time.sleep(0.05)
        self.assertFalse(self.carried.exists())
        self.assertFalse((self.adb / self.root_adb.STAND_IN).exists())
        settings = [line for line in self.calls() if line.startswith('settings ')]
        self.assertEqual(settings, ['settings put global development_settings_enabled 1',
                                    'settings put global adb_enabled 1'])
        self.assertIn('done', (self.adb / 'a22x-migration.log').read_text())
        fds = Path(str(self.log) + '.fds')
        self.assertFalse(fds.exists(), fds.read_text() if fds.exists() else '')
        self.assertEqual((self.root / 'data/misc/adb/adb_keys').read_text().splitlines(), self.KEYS)
        self.assertEqual(self.events(), ['services', 'boot-completed'])

    def test_an_su_sent_here_by_kernelsu_is_a_root_shell(self):
        """Live 2026-11-22: KernelSU sends `su -c id` of the allowed adb shell here as "-c id"."""
        self.assertEqual(self.ksud('-c', 'echo from-su').strip(), 'from-su')
        self.assertEqual(self.ksud('0', '-c', 'echo as-zero').strip(), 'as-zero')
        self.assertTrue((self.carried / self.root_adb.APPLY).exists())  # an su starts nothing

    def test_apply_writes_its_pid_before_the_stand_in_returns(self):
        """init kills the stand-in's process group when it returns: apply.sh must be in its own session by then."""
        (self.carried / self.root_adb.APPLY).write_text('#!/bin/sh\nsleep 2\n')
        self.ksud('services')
        pid = (self.root / 'dev/.a22x-migration/pid').read_text().strip()
        self.assertTrue(pid.isdigit() and Path('/proc/%s' % pid).exists())
        self.assertNotEqual(os.getsid(int(pid)), os.getsid(0))
        self.ksud('boot-completed')  # alive: not started twice
        self.assertEqual((self.root / 'dev/.a22x-migration/pid').read_text().strip(), pid)

    def test_a_run_that_died_is_started_again(self):
        (self.root / 'dev/.a22x-migration').mkdir()
        (self.root / 'dev/.a22x-migration/pid').write_text('999999\n')  # no such process
        Path(str(self.log) + '.booted').touch()
        self.ksud('boot-completed')
        for _ in range(200):
            if not self.carried.exists():
                break
            time.sleep(0.05)
        self.assertFalse(self.carried.exists())
