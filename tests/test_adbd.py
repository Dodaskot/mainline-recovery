#!/usr/bin/env python3
"""The recovery's ADB daemon: keys, signatures, and the real adb client over TCP (2026-11-10)."""
import base64
import contextlib
import errno
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import adbd  # noqa: E402


def android_key(n, e, comment='test@host'):
    """The adb public key line of (n, e): RSAPublicKey with n0inv and R^2, base64."""
    words = 64
    n0inv = (-pow(n, -1, 1 << 32)) % (1 << 32)
    rr = pow(1 << (32 * words), 2, n)
    blob = struct.pack('<II', words, n0inv) + n.to_bytes(4 * words, 'little') + rr.to_bytes(4 * words, 'little') + struct.pack('<I', e)
    return base64.b64encode(blob).decode() + ' ' + comment


def openssl_key(folder):
    private = Path(folder) / 'key.pem'
    subprocess.run(['openssl', 'genrsa', '-out', str(private), '2048'], check=True, capture_output=True)
    text = subprocess.run(['openssl', 'rsa', '-in', str(private), '-noout', '-text'], check=True, capture_output=True, text=True).stdout
    modulus = text.split('modulus:')[1].split('publicExponent')[0]
    n = int(''.join(modulus.split()).replace(':', ''), 16)
    return private, n


@unittest.skipUnless(shutil.which('openssl'), 'openssl is needed to make test keys')
class TestKeys(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='a22x-adbkey-')
        self.addCleanup(self.tmp.cleanup)
        self.private, self.n = openssl_key(self.tmp.name)

    def sign(self, token):
        data = Path(self.tmp.name) / 'token'
        data.write_bytes(token)
        return subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(self.private), '-pkeyopt', 'digest:sha1',
                               '-in', str(data)], check=True, capture_output=True).stdout

    def test_a_key_line_is_read_and_a_signature_checked(self):
        line = android_key(self.n, 65537, 'tester@pc')
        n, e, comment = adbd.parse_android_key(line)
        self.assertEqual((n, e, comment), (self.n, 65537, 'tester@pc'))
        token = os.urandom(20)
        signature = self.sign(token)
        self.assertTrue(adbd.verify(n, e, token, signature))
        self.assertFalse(adbd.verify(n, e, os.urandom(20), signature))
        self.assertFalse(adbd.verify(n, e, token, signature[:-1] + bytes([signature[-1] ^ 1])))
        self.assertTrue(adbd.fingerprint(line).startswith('SHA256:'))

    def test_keys_are_kept_once_and_bad_lines_refused(self):
        keys = adbd.Keys(Path(self.tmp.name) / 'adb' / 'adb_keys')
        line = android_key(self.n, 65537)
        keys.add(line)
        keys.add(line)
        self.assertEqual(len(keys.lines()), 1)
        self.assertEqual(oct((Path(self.tmp.name) / 'adb' / 'adb_keys').stat().st_mode & 0o777), '0o600')
        with self.assertRaises(ValueError):
            keys.add('bm90IGEga2V5 nobody')

    def test_a_request_waits_for_the_phone(self):
        base = Path(self.tmp.name) / 'requests'
        approval = adbd.Approval(base, timeout=5, poll=0.02)
        line = android_key(self.n, 65537, 'tester@pc')
        answers = []

        def phone(decision):
            for _ in range(200):
                found = list(base.glob('request-*.json')) if base.exists() else []
                if found:
                    name = found[0].name[len('request-'):-len('.json')]
                    (base / f'{decision}-{name}').write_text('')
                    return
                time.sleep(0.02)
        for decision in ('allowed', 'denied'):
            thread = threading.Thread(target=phone, args=(decision,))
            thread.start()
            answers.append(approval(line, '172.16.42.2:40000'))
            thread.join()
        self.assertEqual(answers, [True, False])
        self.assertEqual(list(base.iterdir()), [])


class TestSideloadNotice(unittest.TestCase):
    """2026-11-11: what arrived over adb sideload is told to the interface, which opens a ZIP's
    review at once, as TWRP's sideload installs it."""

    def test_the_record_names_the_file_its_volume_and_its_kind(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / 'adb'
            place = {'folder': Path(temporary), 'volume': 'sdcard-p1', 'token': 'a' * 64, 'dir': '/.a22x-images'}
            for name in ('sideload-20261111-000000.zip', 'sideload-20261111-000001-boot.img', 'sideload-20261111-000002.tar.gz'):
                adbd.announce_sideload(base, place, name, 1234)
                time.sleep(0.002)
            records = sorted(base.glob('sideload-*.json'))
            self.assertEqual(len(records), 3)
            self.assertEqual([p.name for p in base.iterdir() if p.name.startswith('.')], [])
            seen = [json.loads(p.read_text()) for p in records]
            self.assertEqual([(r['file'], r['kind']) for r in seen], [('sideload-20261111-000000.zip', 'zip'),
                             ('sideload-20261111-000001-boot.img', 'image'), ('sideload-20261111-000002.tar.gz', 'system')])
            self.assertEqual(seen[0], {'file': 'sideload-20261111-000000.zip', 'volume': 'sdcard-p1', 'token': 'a' * 64,
                                       'path': '/.a22x-images/sideload-20261111-000000.zip', 'kind': 'zip', 'size': 1234})
            adbd.announce_sideload(None, place, 'x.zip', 1)  # No folder for requests: nothing to tell.


class TestUsbFunction(unittest.TestCase):
    """The FunctionFS interface and the protocol over two bulk endpoints (pipes stand for them)."""
    def test_descriptors_are_the_adb_interface(self):
        raw = adbd.ffs_descriptors()
        magic, length, flags, fs_count, hs_count, ss_count = struct.unpack_from('<6I', raw)
        self.assertEqual((magic, length, flags, fs_count, hs_count, ss_count), (3, len(raw), 7, 3, 3, 5))
        interface = raw[24:33]
        self.assertEqual(tuple(interface[4:8]), (2, 0xff, 0x42, 1))
        sizes = [struct.unpack_from('<H', raw, at + 4)[0] for at in range(24, len(raw)) if raw[at:at + 2] == bytes([7, 5])]
        self.assertEqual(sizes, [64, 64, 512, 512, 1024, 1024])
        strings = adbd.ffs_strings()
        self.assertEqual(struct.unpack_from('<4I', strings), (2, len(strings), 1, 1))
        self.assertTrue(strings.endswith(b'ADB Interface\0'))

    @unittest.skipUnless(shutil.which('openssl'), 'openssl is needed to make test keys')
    def test_one_zero_length_packet_is_skipped_and_two_end_the_link(self):
        # A transfer of whole packets ends with a zero-length packet, which a read returns as b''.
        from unittest import mock
        reads = iter([b'head', b'', b'tail', b'', b''])
        with mock.patch.object(adbd.os, 'read', lambda fd, size: next(reads)):
            transport = adbd.EndpointTransport(-1, -1)
            self.assertEqual(transport.read(8), b'headtail')
            with self.assertRaises(adbd.Closed):
                transport.read(4)

    def test_a_computer_signs_in_over_the_endpoints(self):
        with tempfile.TemporaryDirectory(prefix='a22x-ffs-') as tmp:
            private, n = openssl_key(tmp)
            keys = adbd.Keys(Path(tmp) / 'adb_keys')
            keys.add(android_key(n, 65537))
            host_to_phone, phone_to_host = os.pipe(), os.pipe()
            connection = adbd.Connection(adbd.EndpointTransport(host_to_phone[0], phone_to_host[1]), keys,
                                         lambda line, peer: False, 'usb')
            thread = threading.Thread(target=connection.serve, daemon=True)
            thread.start()

            def send(command, a0, a1, data=b''):
                os.write(host_to_phone[1], struct.pack('<6I', command, a0, a1, len(data), sum(data) & 0xffffffff, command ^ 0xffffffff) + data)

            def receive():
                header = b''
                while len(header) < 24:
                    header += os.read(phone_to_host[0], 24 - len(header))
                command, a0, a1, length, _, _ = struct.unpack('<6I', header)
                data = b''
                while len(data) < length:
                    data += os.read(phone_to_host[0], length - len(data))
                return command, a0, a1, data
            send(adbd.A_CNXN, adbd.VERSION, 1 << 20, b'host::\0')
            command, kind, _, token = receive()
            self.assertEqual((command, kind, len(token)), (adbd.A_AUTH, adbd.AUTH_TOKEN, 20))
            (Path(tmp) / 'token').write_bytes(token)
            signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(private), '-pkeyopt', 'digest:sha1',
                                        '-in', str(Path(tmp) / 'token')], check=True, capture_output=True).stdout
            send(adbd.A_AUTH, adbd.AUTH_SIGNATURE, 0, signature)
            command, version, _, banner = receive()
            self.assertEqual((command, version), (adbd.A_CNXN, adbd.VERSION))
            self.assertTrue(banner.startswith(b'recovery::'))
            send(adbd.A_OPEN, 7, 0, b'exec:echo usb\0')
            command, local, remote, _ = receive()
            self.assertEqual((command, remote), (adbd.A_OKAY, 7))
            command, _, _, data = receive()
            self.assertEqual((command, data), (adbd.A_WRTE, b'usb\n'))
            send(adbd.A_OKAY, 7, local)
            self.assertEqual(receive()[0], adbd.A_CLSE)
            os.close(host_to_phone[1])
            thread.join(5)
            self.assertFalse(thread.is_alive())


class TestSyncSend(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='a22x-adb-sync-')
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name) / 'upload.bin'
        self.partial = self.target.with_name(self.target.name + '.adb-part')
        self.payload = b'complete upload contents'

    def send(self, fail_after_short_write=False):
        path = os.fsencode(f'{self.target},420')
        stream = adbd.Stream(mock.Mock(), 1, 2)
        stream.incoming(b'SEND' + struct.pack('<I', len(path)) + path
                        + b'DATA' + struct.pack('<I', len(self.payload)) + self.payload
                        + struct.pack('<4sI4sI', b'DONE', 0, b'QUIT', 0))
        write = os.write
        first = True

        def write_with_short_result(fd, data):
            nonlocal first
            if first:
                first = False
                return write(fd, data[:5])
            if fail_after_short_write:
                raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
            return write(fd, data)

        with mock.patch.object(adbd.os, 'write', side_effect=write_with_short_result), \
                mock.patch.object(adbd, 'fast_clock', contextlib.nullcontext), \
                mock.patch.object(stream, 'write') as reply:
            adbd.service_sync(stream, 'sync:')
        reply.assert_called_once()
        return reply.call_args.args[0]

    def test_send_finishes_a_short_write_before_publishing(self):
        self.assertEqual(self.send(), b'OKAY' + bytes(4))
        self.assertEqual(self.target.read_bytes(), self.payload)
        self.assertFalse(self.partial.exists())

    def test_send_error_after_a_short_write_keeps_the_existing_file(self):
        original = b'previous complete file'
        self.target.write_bytes(original)
        reply = self.send(fail_after_short_write=True)
        self.assertEqual(reply[:4], b'FAIL')
        self.assertEqual(struct.unpack_from('<I', reply, 4)[0], len(reply[8:]))
        self.assertIn(os.strerror(errno.ENOSPC).encode(), reply[8:])
        self.assertEqual(self.target.read_bytes(), original)
        self.assertFalse(self.partial.exists())


class TestSideloadReceive(unittest.TestCase):
    def test_sideload_finishes_a_short_write_before_publishing(self):
        image = b'AVB0' + bytes(range(256)) * 16
        stream = adbd.Stream(mock.Mock(), 1, 2)
        stream.incoming(image)
        write = os.write

        def write_first_five_bytes(fd, data):
            if not os.lseek(fd, 0, os.SEEK_CUR):
                return write(fd, data[:5])
            return write(fd, data)

        with tempfile.TemporaryDirectory(prefix='a22x-adb-sideload-') as temporary:
            folder = Path(temporary)
            with mock.patch.object(adbd.os, 'write', side_effect=write_first_five_bytes), \
                    mock.patch.object(adbd, 'fast_clock', contextlib.nullcontext), \
                    mock.patch.object(stream, 'write') as reply:
                name = adbd.receive_sideload(stream, folder, len(image), 8192)
            self.assertTrue(name.endswith('-vbmeta.img'))
            self.assertEqual(reply.call_args_list, [mock.call(b'00000000'), mock.call(b'DONEDONE')])
            self.assertEqual((folder / name).stat().st_size, len(image))
            self.assertEqual((folder / name).read_bytes(), image)
            self.assertFalse((folder / '.sideload-part').exists())


@unittest.skipUnless(shutil.which('adb'), 'the adb client is needed')
class TestWithTheAdbClient(unittest.TestCase):
    """The real adb client, with its own server and key, against the daemon on 127.0.0.1."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='a22x-adbd-')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / 'home'
        self.home.mkdir()
        self.env = dict(os.environ, HOME=str(self.home), ANDROID_ADB_SERVER_PORT=str(15037 + os.getpid() % 2000))
        self.keys = adbd.Keys(Path(self.tmp.name) / 'adb_keys')
        self.store = Path(self.tmp.name) / 'store'
        self.store.mkdir()
        os.environ['A22X_ADB_SIDELOAD_DIR'] = str(self.store)
        self.addCleanup(os.environ.pop, 'A22X_ADB_SIDELOAD_DIR', None)
        self.offered = []
        port = []
        ready = threading.Event()

        def approve(line, peer):
            self.offered.append(line)
            return True
        thread = threading.Thread(target=adbd.serve_tcp, args=('127.0.0.1', 0, self.keys, approve),
                                  kwargs={'ready': lambda p: (port.append(p), ready.set())}, daemon=True)
        thread.start()
        self.assertTrue(ready.wait(5))
        self.serial = '127.0.0.1:%d' % port[0]
        self.addCleanup(lambda: subprocess.run(['adb', 'kill-server'], env=self.env, capture_output=True, timeout=30))

    def adb(self, *args, timeout=60):
        return subprocess.run(['adb', '-s', self.serial, *args], env=self.env, capture_output=True, text=True, timeout=timeout)

    def wait_online(self):
        for _ in range(100):
            state = subprocess.run(['adb', 'devices'], env=self.env, capture_output=True, text=True, timeout=30).stdout
            if self.serial + '\trecovery' in state:
                return True
            time.sleep(0.2)
        return False

    def test_connect_shell_push_and_pull(self):
        # The first time, the client says "failed to authenticate" while its new key waits for
        # the phone, as with Android; once allowed, the device comes online.
        out = subprocess.run(['adb', 'connect', self.serial], env=self.env, capture_output=True, text=True, timeout=60)
        self.assertTrue('connected' in out.stdout or 'failed to authenticate' in out.stdout, out.stdout)
        self.assertTrue(self.wait_online())
        self.assertEqual(len(self.offered), 1)
        self.assertEqual(self.adb('shell', 'echo hello-$((40+2))').stdout.strip(), 'hello-42')
        data = os.urandom(300000)
        source, target, back = (Path(self.tmp.name) / name for name in ('source.bin', 'remote.bin', 'back.bin'))
        source.write_bytes(data)
        self.assertEqual(self.adb('push', str(source), str(target)).returncode, 0)
        self.assertEqual(target.read_bytes(), data)
        self.assertEqual(self.adb('pull', str(target), str(back)).returncode, 0)
        self.assertEqual(back.read_bytes(), data)
        # A file that cannot be written out is not "pushed" (2026-11-12: an image came back with
        # 16 MiB of zeros in it): the flush fails, adb says so, and nothing is left under the name.
        lost = Path(self.tmp.name) / 'lost.bin'
        with mock.patch.object(adbd.os, 'fsync', side_effect=OSError(28, 'No space left on device')):
            failed = self.adb('push', str(source), str(lost))
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('No space left on device', failed.stdout + failed.stderr)
        self.assertFalse(lost.exists() or Path(str(lost) + '.adb-part').exists())
        listing = self.adb('shell', 'ls ' + self.tmp.name).stdout
        self.assertIn('remote.bin', listing)
        self.assertEqual(self.adb('exec-out', 'printf raw').stdout, 'raw')
        # adb sideload keeps a system image or an Android ZIP in the store, named by what it is.
        import tarfile, io
        image = Path(self.tmp.name) / 'distro.tgz'
        with tarfile.open(image, 'w:gz') as out:
            info = tarfile.TarInfo('etc/os-release'); payload = b'ID=fixture\n' + os.urandom(200000).hex().encode()
            info.size = len(payload); out.addfile(info, io.BytesIO(payload))
        result = self.adb('sideload', str(image), timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        saved = sorted(p.name for p in self.store.iterdir())
        self.assertEqual(len(saved), 1)
        self.assertTrue(saved[0].startswith('sideload-') and saved[0].endswith('.tar.gz'), saved)
        self.assertEqual((self.store / saved[0]).read_bytes(), image.read_bytes())
        rom = Path(self.tmp.name) / 'rom.zip'
        import zipfile
        with zipfile.ZipFile(rom, 'w') as z:
            z.writestr('META-INF/com/android/metadata', 'pre-device=a22x\n')
        self.assertEqual(self.adb('sideload', str(rom), timeout=120).returncode, 0)
        self.assertTrue(any(p.name.endswith('.zip') for p in self.store.iterdir()))
        junk = Path(self.tmp.name) / 'junk.bin'
        junk.write_bytes(b'not an image' * 1000)
        self.assertNotEqual(self.adb('sideload', str(junk), timeout=120).returncode, 0)
        self.assertEqual(len(list(self.store.iterdir())), 2)
        # 2026-11-10: images of the phone's own partitions are kept too, named for Flash a
        # partition; a recovery image is told from a BOOT by the DTBO it carries.
        header = bytearray(b'ANDROID!' + bytes(4088))
        struct.pack_into('<I', header, 40, 2)
        boot, recovery, vbmeta = (Path(self.tmp.name) / name for name in ('boot.img', 'recovery.img', 'vbmeta.img'))
        boot.write_bytes(bytes(header) + os.urandom(60000))
        struct.pack_into('<I', header, 1632, 8192)
        recovery.write_bytes(bytes(header) + os.urandom(60000))
        vbmeta.write_bytes(b'AVB0' + os.urandom(8188))
        for item in (boot, recovery, vbmeta, vbmeta):
            self.assertEqual(self.adb('sideload', str(item), timeout=120).returncode, 0, item)
        names = sorted(p.name for p in self.store.iterdir())
        self.assertEqual(len(names), 6, names)
        for kind in ('boot', 'recovery'):
            self.assertEqual(len([n for n in names if n.endswith('-%s.img' % kind)]), 1, names)
        # The same kind twice, possibly within one second: both stay.
        self.assertEqual(len([n for n in names if '-vbmeta' in n]), 2, names)
        saved = [n for n in names if n.endswith('-recovery.img')][0]
        self.assertEqual((self.store / saved).read_bytes(), recovery.read_bytes())
        # The key approved once is proven by signature next time: no second offer.
        subprocess.run(['adb', 'disconnect', self.serial], env=self.env, capture_output=True, timeout=30)
        out = subprocess.run(['adb', 'connect', self.serial], env=self.env, capture_output=True, text=True, timeout=60)
        self.assertIn('connected to', out.stdout)
        self.assertTrue(self.wait_online())
        self.assertEqual(len(self.offered), 1)
        self.assertEqual(len(self.keys.lines()), 1)


if __name__ == '__main__':
    unittest.main()


class FastClockTest(unittest.TestCase):
    """2026-11-21: a file moving over USB runs the cluster of the USB interrupt at its top clock."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        for policy, cpus, top, low in (('policy0', '0 1 2 3 4 5', '2000000', '500000'), ('policy6', '6 7', '2203000', '1468666')):
            folder = self.root / 'sys/devices/system/cpu/cpufreq' / policy
            folder.mkdir(parents=True)
            (folder / 'related_cpus').write_text(cpus + '\n')
            (folder / 'cpuinfo_max_freq').write_text(top + '\n')
            (folder / 'scaling_min_freq').write_text(low + '\n')
        (self.root / 'proc/irq/148').mkdir(parents=True)
        (self.root / 'proc/interrupts').write_text('           CPU0       CPU1\n 148:   16098854          0  GICv3 128 Level     musb-hdrc.2.auto\n')
        self.irq('0')
        self.clock = adbd.FastClock(self.root)

    def irq(self, cpus):
        (self.root / 'proc/irq/148/effective_affinity_list').write_text(cpus + '\n')

    def floor(self, policy):
        return (self.root / 'sys/devices/system/cpu/cpufreq' / policy / 'scaling_min_freq').read_text().strip()

    def test_the_little_cluster_runs_at_its_top_while_a_file_moves(self):
        with self.clock():
            self.assertEqual(self.floor('policy0'), '2000000')
            with self.clock():  # a second transfer at the same time
                pass
            self.assertEqual(self.floor('policy0'), '2000000')
            self.assertEqual(self.floor('policy6'), '1468666')  # the interface's floor stays
        self.assertEqual(self.floor('policy0'), '500000')

    def test_the_floor_comes_back_though_the_kernel_shows_it_late(self):
        # On the phone the floor is applied later: a read right after the write shows the old one.
        floor = self.root / 'sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq'
        with self.clock():
            floor.write_text('500000\n')
        self.assertEqual(self.floor('policy0'), '500000')
        with self.clock():
            self.assertEqual(self.floor('policy0'), '2000000')
        self.assertEqual(self.floor('policy0'), '500000')

    def test_the_interrupt_on_the_fastest_cluster_changes_nothing(self):
        self.irq('6')
        with self.clock():
            self.assertEqual((self.floor('policy0'), self.floor('policy6')), ('500000', '1468666'))

    def test_without_a_usb_controller_nothing_changes(self):
        (self.root / 'proc/interrupts').write_text('           CPU0\n  11:   5  GICv3  27 Level  arch_timer\n')
        with self.clock():
            self.assertEqual(self.floor('policy0'), '500000')


class ChecksumTest(unittest.TestCase):
    """2026-11-21: a computer of version 0x01000001 or later checks no payload sum; an older one does."""

    def sent(self, version):
        written = []
        transport = mock.Mock(write=written.append)
        connection = adbd.Connection(transport, None, None, 'usb')
        connection.peer_version = version
        connection.send(adbd.A_WRTE, 1, 2, b'\x01\x02\x03')
        return struct.unpack('<6I', written[0])[4]

    def test_the_sum_only_for_an_old_computer(self):
        self.assertEqual(self.sent(adbd.VERSION), 0)
        self.assertEqual(self.sent(0x01000000), 6)
