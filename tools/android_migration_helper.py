"""Build and run short-lived Android helpers for the portable migration tools."""
import contextlib
import hashlib
from pathlib import Path
import secrets
import shlex
import subprocess
import zipfile

from android_model_db import ad


def build_helper(root, tools, platform, manifest, source):
    tools, platform = tools.resolve(), platform.resolve()
    (root / 'classes').mkdir()
    (root / 'dex').mkdir()
    (root / 'AndroidManifest.xml').write_text(manifest)

    def run(*args):
        subprocess.run(args, cwd=root, stdout=subprocess.DEVNULL, check=True, timeout=60)

    run(tools / 'aapt2', 'link', '-o', 'resources.apk', '-I', platform, '--manifest', 'AndroidManifest.xml')
    run('javac', '--release', '11', '-classpath', platform, '-d', 'classes', source)
    run(tools / 'd8', '--min-api', '30', '--lib', platform, '--output', 'dex',
        *sorted((root / 'classes').rglob('*.class')))
    with zipfile.ZipFile(root / 'resources.apk', 'a', zipfile.ZIP_DEFLATED) as apk:
        apk.write(root / 'dex/classes.dex', 'classes.dex')
    run(tools / 'zipalign', '4', 'resources.apk', 'aligned.apk')
    password = root / 'key-password'
    password.touch(mode=0o600, exist_ok=False)
    password.write_text(secrets.token_urlsafe(32))
    run('keytool', '-genkeypair', '-alias', 'migration', '-keyalg', 'RSA', '-keysize', '2048',
        '-keystore', 'ephemeral.p12', '-storepass:file', password, '-keypass:file', password,
        '-dname', 'CN=Local A22x Migration Helper', '-validity', '30')
    run(tools / 'apksigner', 'sign', '--ks', 'ephemeral.p12', '--ks-pass', 'file:key-password',
        '--out', 'helper.apk', 'aligned.apk')
    run(tools / 'apksigner', 'verify', 'helper.apk')
    return root / 'helper.apk'


class AndroidHelper:
    def __init__(self, serial, user):
        self.user = str(user)
        self.adb = ['adb', '-s', serial]
        self.require_unlocked()
        self.boot = self.shell('cat', '/proc/sys/kernel/random/boot_id')
        ad.require(bool(self.boot), 'TARGET_IDENTITY_UNAVAILABLE', 'Could not identify the Android boot')

    def run(self, *args, data=None, timeout=30):
        return subprocess.run([*self.adb, *args], input=data, capture_output=True, check=True, timeout=timeout).stdout.decode()

    def shell(self, *args, data=None, timeout=30):
        return self.run('shell', '-T', shlex.join(args), data=data, timeout=timeout).strip()

    def require_unlocked(self):
        ad.require(self.shell('am', 'get-started-user-state', self.user) == 'RUNNING_UNLOCKED', 'USER_LOCKED',
                   'Start and unlock the selected Android user first')

    def check_target(self):
        ad.require(self.shell('cat', '/proc/sys/kernel/random/boot_id') == self.boot, 'TARGET_CHANGED',
                   'The selected Android device restarted or changed')

    def installed(self, package):
        packages = self.shell('pm', 'list', 'packages', '--user', self.user, package)
        return 'package:' + package in packages.splitlines()

    @contextlib.contextmanager
    def install(self, package, apk, *, grant=False):
        self.check_target()
        self.require_unlocked()
        ad.require(not self.installed(package), 'HELPER_EXISTS', 'The temporary migration app already exists')
        try:
            self.run('install', '--no-incremental', '--user', self.user, '-R', '--pkg', package,
                     *(['-g'] if grant else []), str(apk), timeout=120)
            self.check_target()
            yield
        finally:
            self.check_target()
            if self.installed(package):
                self.run('uninstall', '--user', self.user, package, timeout=60)
            ad.require(not self.installed(package), 'HELPER_CLEANUP_FAILED', 'Temporary app remains installed: ' + package)

    def input(self, package, name, payload):
        assert Path(name).name == name
        self.check_target()
        self.shell('run-as', package, '--user', self.user, 'sh', '-c',
                   'umask 077; mkdir -p files && cat > ' + shlex.quote('files/' + name), data=payload)
        return hashlib.sha256(payload).hexdigest()
