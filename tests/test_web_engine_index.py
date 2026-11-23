"""A pinned Alpine package that the branch replaced is taken from the signed index, verified as apk does."""
import base64
import fcntl
import gzip
import hashlib
import io
import os
from pathlib import Path
import random
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import web_cache


def prime(bits, rng):
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if all(n % p for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31)) and all(
                pow(a, n - 1, n) == 1 for a in (2, 3, 5, 7, 11, 13, 17)):
            return n


def toy_key():
    rng = random.Random(7)
    e = 65537
    while True:
        p, q = prime(512, rng), prime(512, rng)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            return p * q, e, pow(e, -1, phi)


def sign(data, key):
    n, _, d = key
    size = (n.bit_length() + 7) // 8
    digest = web_cache.SHA1_DIGEST_INFO + hashlib.sha1(data).digest()
    block = b'\x00\x01' + b'\xff' * (size - 3 - len(digest)) + b'\x00' + digest
    return pow(int.from_bytes(block, 'big'), d, n).to_bytes(size, 'big')


def tar_gz(files, end=True):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, data in files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    raw = out.getvalue()
    if not end:  # apk segments omit the tar end blocks except the last
        raw = raw[:len(raw) - 1024]
    return gzip.compress(raw, mtime=0)


def index(entries, key, name=web_cache.ALPINE_KEY_NAME):
    text = '\n\n'.join('\n'.join(f'{k}:{v}' for k, v in e.items()) for e in entries) + '\n\n'
    signed = tar_gz([('APKINDEX', text.encode())])
    return tar_gz([('.SIGN.RSA.' + name, sign(signed, key))], end=False) + signed


def apk(files, key):
    data = tar_gz(files)
    control = tar_gz([('.PKGINFO', f'pkgname = x\ndatahash = {hashlib.sha256(data).hexdigest()}\n'.encode())], end=False)
    signature = tar_gz([('.SIGN.RSA.' + web_cache.ALPINE_KEY_NAME, sign(control, key))], end=False)
    return signature + control + data, 'Q1' + base64.b64encode(hashlib.sha1(control).digest()).decode()


class Signature(unittest.TestCase):
    key = toy_key()

    def test_alpine_key_parses(self):
        n, e = web_cache.rsa_public_key(web_cache.ALPINE_KEY)
        self.assertEqual((n.bit_length(), e), (4096, 65537))

    def test_signed_index_and_refusals(self):
        n, e, _ = self.key
        data = index([{'P': 'libssl3', 'V': '3.5.9-r1', 'C': 'Q1abc=', 'S': '10'}], self.key)
        self.assertEqual(web_cache.verified_index(data, (n, e))['libssl3']['V'], '3.5.9-r1')
        damaged = bytearray(data); damaged[-30] ^= 1
        with self.assertRaises(Exception):
            web_cache.verified_index(bytes(damaged), (n, e))
        other = index([{'P': 'libssl3', 'V': '3.5.9-r1'}], self.key, name='someone-else.rsa.pub')
        with self.assertRaisesRegex(RuntimeError, 'expected Alpine key'):
            web_cache.verified_index(other, (n, e))
        with self.assertRaisesRegex(RuntimeError, 'signature'):
            web_cache.verified_index(data)  # the real Alpine key did not sign this


class Package(unittest.TestCase):
    key = Signature.key

    def test_current_package_is_verified_and_used(self):
        n, e, _ = self.key
        raw, checksum = apk([('usr/lib/libssl.so.3', b'new ssl')], self.key)
        entries = {'libssl3': {'P': 'libssl3', 'V': '3.5.9-r1', 'C': checksum, 'S': str(len(raw))}}
        pinned = {'path': 'main/aarch64/libssl3-3.5.9-r0.apk', 'bytes': 9, 'sha256': '0' * 64,
                  'files': ['usr/lib/libssl.so.3']}
        with patch.object(web_cache, 'branch_index', lambda repository: entries):
            current = web_cache.current_package(pinned)
        self.assertEqual(current['path'], 'main/aarch64/libssl3-3.5.9-r1.apk')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'p.apk')
            path.write_bytes(raw)
            web_cache.verify_indexed(path, current)
            for at in (len(raw) - 40, 60):
                bad = bytearray(raw); bad[at] ^= 0xff
                path.write_bytes(bytes(bad))
                with self.assertRaises(Exception):
                    web_cache.verify_indexed(path, current)

    def test_names(self):
        for filename, name in (('libssl3-3.5.9-r0.apk', 'libssl3'), ('font-noto-cjk-2.004-r6.apk', 'font-noto-cjk'),
                               ('chromium-156.0.8078.79-r0.apk', 'chromium'), ('py3-a-1.0_rc1-r2.apk', 'py3-a')):
            self.assertEqual(web_cache.APK_NAME.fullmatch(filename)['name'], name)

    def test_gone_from_the_branch(self):
        pinned = {'path': 'main/aarch64/libgone-1-r0.apk', 'bytes': 1, 'sha256': '0' * 64, 'files': []}
        with patch.object(web_cache, 'branch_index', lambda repository: {}):
            with self.assertRaisesRegex(RuntimeError, 'no longer'):
                web_cache.current_package(pinned)


class Preparation(unittest.TestCase):
    def test_a_running_preparation_is_shown_to_a_waiting_browser(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock_path, progress = Path(tmp, 'lock'), Path(tmp, 'progress')
            progress.write_text('Web engine · 40 / 152 MiB\n')
            holder = lock_path.open('a+b'); fcntl.flock(holder, fcntl.LOCK_EX)
            shown = []
            with lock_path.open('a+b') as lock, patch.object(web_cache, 'PROGRESS', progress), \
                 patch.object(web_cache, 'notify', shown.append), \
                 patch.object(web_cache.time, 'sleep', lambda s: holder.close()):
                with self.assertRaises(BlockingIOError):
                    web_cache.take_lock(lock, wait=False)
                web_cache.take_lock(lock, wait=True)
            self.assertEqual(shown, ['Web engine · 40 / 152 MiB'])

    def test_prefetch_reports_to_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            progress = Path(tmp, 'progress')
            with patch.object(web_cache, 'PROGRESS', progress), patch.object(web_cache, 'cached', lambda: None), \
                 patch.object(web_cache, 'ensure', lambda wait: web_cache.notify('Web engine · 1 / 2 MiB')):
                self.assertEqual(web_cache.prefetch(), 0)
            self.assertEqual(progress.read_text().strip(), 'Web engine ready')
            web_cache._report = None


if __name__ == '__main__':
    unittest.main()
