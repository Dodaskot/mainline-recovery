"""The data of a Linux system into an archive and into another system (linux_data.py, 2026-11-13)."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import filesystem as fs  # noqa: E402
import linux_data as ld  # noqa: E402

STUB = '''#!/bin/sh
# A stand-in for the system's programs: says what it was asked, answers from files of the test.
me=$(basename "$0")
echo "$me $*" >> "$A22X_STUB_LOG"
case $me in
    getent) grep -q "^$2:" "$A22X_ROOT/etc/$1" ;;
    id) case $1 in -u) echo 0 ;; *) grep "^$2:" "$A22X_ROOT/etc/passwd" | cut -d: -f3; grep -q "^$2:" "$A22X_ROOT/etc/passwd" ;; esac ;;
    useradd) for last; do :; done; echo "$last:x:1001:1001::/home/$last:/bin/sh" >> "$A22X_ROOT/etc/passwd" ;;
    apt-cache) [ "$2" = firefox-esr ] || [ "$2" = htop ] && echo "Package: $2" ;;
    dpkg) grep -qx "$2" "$A22X_STUB_LOG.installed" 2>/dev/null && echo "Status: install ok installed" ;;
    apt-get) [ "$1" = install ] && { shift; for p; do case $p in -*) ;; *) echo "$p" >> "$A22X_STUB_LOG.installed" ;; esac; done; } ;;
esac
exit $?
'''


@unittest.skipUnless(shutil.which('zstd'), 'zstd is needed')
class LinuxData(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='a22x-linux-data-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.data, self.sd = self.root / 'data', self.root / 'sd'
        self.sd.mkdir()
        self.make_arch(self.data)
        (self.root / 'filesystem-fixture.json').write_text(json.dumps({'schema': 'a22x.filesystem.fixture.v1', 'volumes': [
            {'id': 'userdata', 'path': 'data', 'fs_type': 'ext4', 'mounted': False, 'read_only': True},
            {'id': 'sdcard-p1', 'path': 'sd', 'fs_type': 'ext4', 'mounted': True, 'read_only': True}]}))
        self.ctx = fs.FixtureContext(self.root)
        stubs = self.root / 'stubs'
        stubs.mkdir()
        for name in ('getent', 'id', 'useradd', 'usermod', 'chown', 'apt-cache', 'apt-get', 'dpkg'):
            (stubs / name).write_text(STUB)
            (stubs / name).chmod(0o755)
        os.environ.update(A22X_LINUX_DATA_PATH=str(stubs), A22X_STUB_LOG=str(self.root / 'calls.log'))
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in ('A22X_LINUX_DATA_PATH', 'A22X_STUB_LOG')])

    def make_arch(self, top):
        for folder in ('etc/NetworkManager/system-connections', 'etc/ssh', 'home/akisha/.cache/junk', 'home/akisha/Документи', 'root',
                       'var/lib/pacman/local/firefox-1-1', 'var/lib/pacman/local/htop-3-1', 'var/lib/pacman/local/libfoo-1-1',
                       'var/lib/pacman/local/zsh-5-1', 'var/lib/pacman/local/linux-aarch64-1-1', 'var/tmp', 'lib/modules/7.2.0'):
            (top / folder).mkdir(parents=True)
        (top / 'etc/os-release').write_text('NAME="Arch Linux ARM"\nID=archarm\nID_LIKE=arch\nPRETTY_NAME="Arch Linux ARM"\n')
        (top / 'etc/passwd').write_text('root:x:0:0::/root:/bin/bash\nakisha:x:1000:1000::/home/akisha:/bin/zsh\nnobody:x:65534:65534::/:/sbin/nologin\n')
        (top / 'etc/shadow').write_text('root:$6$r$R:1::::::\nakisha:$6$salt$HASH:1::::::\n')
        (top / 'etc/group').write_text('wheel:x:998:akisha\nvideo:x:985:akisha\nakisha:x:1000:\n')
        (top / 'etc/hostname').write_text('a22x\n')
        (top / 'etc/locale.conf').write_text('LANG=uk_UA.UTF-8\n')
        (top / 'etc/localtime').symlink_to('/usr/share/zoneinfo/Europe/Berlin')
        (top / 'etc/NetworkManager/system-connections/Home.nmconnection').write_text('[wifi]\nssid=Home\n')
        (top / 'etc/ssh/ssh_host_ed25519_key').write_text('KEY')
        (top / 'etc/ssh/sshd_config').write_text('system file')
        (top / 'etc/fstab').write_text('this phone only')
        (top / 'home/akisha/Документи/нотатка.txt').write_text('моє\n')
        (top / 'home/akisha/.zshrc').write_text('alias ll=ls\n')
        (top / 'home/akisha/.cache/junk/big').write_bytes(b'x' * 4096)
        (top / 'root/.bash_history').write_text('ls\n')
        for name, reason in (('firefox', None), ('htop', '0'), ('libfoo', '1'), ('zsh', None), ('linux-aarch64', None)):
            (top / ('var/lib/pacman/local/%s-%s-1/desc' % (name, '3' if name == 'htop' else '5' if name == 'zsh' else '1'))).write_text(
                '%NAME%\n' + name + '\n\n' + ('%REASON%\n' + reason + '\n\n' if reason else ''))

    def progress(self, *unused):
        pass

    def test_inspect_backup_and_restore_into_another_distribution(self):
        seen = ld.inspect(self.ctx)
        self.assertTrue(seen['linux'], seen)
        self.assertEqual((seen['os']['family'], seen['accounts'], seen['parts']['packages'], seen['parts']['accounts']), ('arch', ['akisha'], 3, 1))
        self.assertEqual([d['volume'] for d in seen['destinations']], ['sdcard-p1'])
        self.assertFalse(self.ctx.volume('userdata')['mounted'])  # left as it was found
        done = ld.backup(self.ctx, ['home', 'accounts', 'settings', 'packages'], 'sdcard-p1', None, True, self.progress)
        archive = self.sd / done['archive']['path'].lstrip('/')
        self.assertTrue(archive.is_file() and done['packages'] == 3 and done['accounts'] == 1)
        names = subprocess.run(['tar', '--zstd', '-tf', str(archive)], capture_output=True, text=True, check=True).stdout.split('\n')
        self.assertIn('home/akisha/Документи/нотатка.txt', names)
        self.assertIn('settings/etc/NetworkManager/system-connections/Home.nmconnection', names)
        self.assertIn('settings/etc/ssh/ssh_host_ed25519_key', names)
        self.assertIn('restore.sh', names)
        for absent in ('home/akisha/.cache/junk/big', 'settings/etc/fstab', 'settings/etc/ssh/sshd_config'):
            self.assertNotIn(absent, names)
        listed = ld.inspect(self.ctx)['archives']
        self.assertEqual((len(listed), listed[0]['parts'], listed[0]['os']['family'], listed[0]['accounts']),
                         (1, list(ld.PARTS), 'arch', ['akisha']))
        # The phone is erased and another distribution installed: Debian, no account of that name.
        shutil.rmtree(self.data)
        for folder in ('etc/NetworkManager', 'etc/ssh', 'home', 'root', 'var/tmp', 'bin'):
            (self.data / folder).mkdir(parents=True)
        (self.data / 'etc/os-release').write_text('ID=debian\nPRETTY_NAME="Debian GNU/Linux 13"\n')
        (self.data / 'etc/passwd').write_text('root:x:0:0::/root:/bin/bash\n')
        (self.data / 'etc/group').write_text('sudo:x:27:\nvideo:x:44:\n')
        (self.data / 'etc/hostname').write_text('debian\n')
        (self.data / 'bin/bash').write_text('#!')
        (self.data / 'bin/bash').chmod(0o755)
        back = ld.restore(fs.FixtureContext(self.root), 'sdcard-p1', None, listed[0]['path'], list(ld.PARTS), True, self.progress)
        self.assertEqual((back['accounts_created'], back['into']['id'], back['owners_changed']), (['akisha'], 'debian', 1))
        self.assertEqual((back['packages_installed'], back['packages_missing'], back['missing']), (2, 1, ['zsh']))
        self.assertEqual((self.data / 'home/akisha/Документи/нотатка.txt').read_text(), 'моє\n')
        self.assertEqual((self.data / 'root/.bash_history').read_text(), 'ls\n')
        self.assertEqual((self.data / 'etc/hostname').read_text(), 'a22x\n')
        self.assertEqual(os.readlink(self.data / 'etc/localtime'), '/usr/share/zoneinfo/Europe/Berlin')
        self.assertTrue((self.data / 'etc/NetworkManager/system-connections/Home.nmconnection').is_file())
        self.assertEqual((self.data / 'etc/ssh/ssh_host_ed25519_key').read_text(), 'KEY')
        self.assertFalse((self.data / 'var/tmp/a22x-restore').exists())
        calls = (self.root / 'calls.log').read_text()
        self.assertIn('useradd -m -u 1000 -s /bin/bash akisha', calls)   # zsh is not there: bash
        self.assertIn('usermod -p $6$salt$HASH akisha', calls)
        self.assertIn('usermod -aG sudo akisha', calls)
        self.assertIn('usermod -aG video akisha', calls)
        self.assertIn('apt-get install -y -q --no-install-recommends firefox-esr htop', calls)  # firefox by Debian's name

    def test_parts_alone_and_refusals(self):
        done = ld.backup(self.ctx, ['settings'], 'sdcard-p1', None, True, self.progress)
        names = subprocess.run(['tar', '--zstd', '-tf', str(self.sd / done['archive']['path'].lstrip('/'))], capture_output=True, text=True).stdout
        self.assertNotIn('home/', names)
        self.assertNotIn('accounts.tsv', names)
        back = ld.restore(self.ctx, 'sdcard-p1', None, done['archive']['path'], ['home', 'settings'], True, self.progress)
        self.assertEqual(back['parts'], ['settings'])
        for call, code in ((lambda: ld.backup(self.ctx, [], 'sdcard-p1', None, True, self.progress), 'NOTHING_SELECTED'),
                           (lambda: ld.backup(self.ctx, ['home'], 'sdcard-p1', None, False, self.progress), 'CONFIRMATION_REQUIRED'),
                           (lambda: ld.restore(self.ctx, 'sdcard-p1', None, done['archive']['path'], ['packages'], True, self.progress), 'NOTHING_SELECTED')):
            with self.assertRaises(fs.FilesystemError) as caught:
                call()
            self.assertEqual(caught.exception.code, code)
        (self.sd / 'A22xDataBackups/other.tar.zst').write_bytes(b'not one')
        with self.assertRaises(fs.FilesystemError) as caught:
            ld.restore(self.ctx, 'sdcard-p1', None, '/A22xDataBackups/other.tar.zst', ['home'], True, self.progress)
        self.assertEqual(caught.exception.code, 'NOT_A_DATA_BACKUP')
        # Android on userdata: nothing to back up, the archives are still listed.
        config = json.loads((self.root / 'filesystem-fixture.json').read_text())
        config['volumes'][0]['fs_type'] = 'f2fs'
        (self.root / 'filesystem-fixture.json').write_text(json.dumps(config))
        seen = ld.inspect(fs.FixtureContext(self.root))
        self.assertEqual((seen['linux'], seen['reason'], len(seen['archives'])), (False, 'NO_LINUX', 1))

    def test_debian_package_list(self):
        top = self.root / 'deb'
        (top / 'var/lib/dpkg').mkdir(parents=True)
        (top / 'var/lib/apt').mkdir(parents=True)
        (top / 'var/lib/dpkg/status').write_text(
            'Package: htop\nStatus: install ok installed\nPriority: optional\n\nPackage: libc6\nStatus: install ok installed\nPriority: required\n\n'
            'Package: libnl\nStatus: install ok installed\nPriority: optional\n\nPackage: gone\nStatus: deinstall ok config-files\nPriority: optional\n')
        (top / 'var/lib/apt/extended_states').write_text('Package: libnl\nArchitecture: arm64\nAuto-Installed: 1\n')
        fd = os.open(top, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        self.assertEqual(ld.packages_of(fd, 'debian'), ['htop'])
        self.assertIsNone(ld.packages_of(fd, 'fedora'))


if __name__ == '__main__':
    unittest.main()
