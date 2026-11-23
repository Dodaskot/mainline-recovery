"""Prepare the pinned aarch64 browser runtime once per recovery boot, in tmpfs.

2026-11-19: Alpine replaces a package in its stable branch with every security update and removes the
old file (libssl3-3.5.9-r0 answered 404 on the phone and the engine never loaded). A pinned package
that is gone is now taken in its current version from the branch's index. The index's RSA signature
is checked with Alpine's aarch64 key, and the package with the index's checksum of its control part and
the data hash written there, as apk itself does. The files used from it stay the pinned list.

After Wi-Fi joins, the engine is prepared in the background (python3 web_cache.py prefetch) and stays
in RAM until the recovery restarts; a browser started meanwhile shows that progress and waits for it.

2026-11-20 (the owner: "можна вантажити браузер з інета як тільки під'єднаний вайфай"): the fast path
comes from Alpine too. The engine carries the full Chromium in place of chromium-headless-shell: it
draws to the recovery's Wayland compositor, or serves the screencast with --headless=new. Where the
Panfrost GPU can be used, a second layer (web_gpu_packages.json: Mesa's driver, EGL, GLES, GBM, LLVM)
is prepared after the engine, in its own publication, and the browser stacks it over the engine.
A browser does not wait for that layer; it uses it from its next start.
"""
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import fcntl
import gzip
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zlib

CACHE = Path('/run/a22x-recovery/web-cache')
MANIFEST = Path(__file__).with_name('web_packages.json')
GPU_MANIFEST = Path(__file__).with_name('web_gpu_packages.json')
BASE = 'https://dl-cdn.alpinelinux.org/alpine/v3.24/'
ARCH = 'aarch64'
CHUNK = 1024 * 1024
PROGRESS = Path('/run/a22x-recovery/web-cache.progress')
INDEX_LIMIT = 32 << 20
# Alpine's aarch64 signing key: the same bytes at alpinelinux.org/keys and in alpine-keys 2.6-r0.
ALPINE_KEY_NAME = 'alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub'
ALPINE_KEY = '''-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyduVzi1mWm+lYo2Tqt/0
XkCIWrDNP1QBMVPrE0/ZlU2bCGSoo2Z9FHQKz/mTyMRlhNqTfhJ5qU3U9XlyGOPJ
piM+b91g26pnpXJ2Q2kOypSgOMOPA4cQ42PkHBEqhuzssfj9t7x47ppS94bboh46
xLSDRff/NAbtwTpvhStV3URYkxFG++cKGGa5MPXBrxIp+iZf9GnuxVdST5PGiVGP
ODL/b69sPJQNbJHVquqUTOh5Ry8uuD2WZuXfKf7/C0jC/ie9m2+0CttNu9tMciGM
EyKG1/Xhk5iIWO43m4SrrT2WkFlcZ1z2JSf9Pjm4C2+HovYpihwwdM/OdP8Xmsnr
DzVB4YvQiW+IHBjStHVuyiZWc+JsgEPJzisNY0Wyc/kNyNtqVKpX6dRhMLanLmy+
f53cCSI05KPQAcGj6tdL+D60uKDkt+FsDa0BTAobZ31OsFVid0vCXtsbplNhW1IF
HwsGXBTVcfXg44RLyL8Lk/2dQxDHNHzAUslJXzPxaHBLmt++2COa2EI1iWlvtznk
Ok9WP8SOAIj+xdqoiHcC4j72BOVVgiITIJNHrbppZCq6qPR+fgXmXa+sDcGh30m6
9Wpbr28kLMSHiENCWTdsFij+NQTd5S47H7XTROHnalYDuF1RpS+DpQidT5tUimaT
JZDr++FjKrnnijbyNF8b98UCAwEAAQ==
-----END PUBLIC KEY-----
'''
SHA1_DIGEST_INFO = bytes.fromhex('3021300906052b0e03021a05000414')
# The GPU layer is prepared only where the browser can use it (web_launch.panfrost_render_node).
PANFROST_DEVICE = Path('/sys/devices/platform/13000000.gpu')
PANFROST_DRIVER = Path('/sys/bus/platform/drivers/panfrost')
PANFROST_RELEASE = '7.2.0-a22x-recovery-diag1+'
PANFROST_MODULE = Path(__file__).with_name('panfrost.ko')
# The engine (460 MiB unpacked), the GPU layer (206 MiB), the packages being unpacked, and downloads.
CACHE_SIZE = '1024m'
APK_NAME = re.compile(r'(?P<name>[A-Za-z0-9_.+-]+?)-(?P<version>[0-9][^/]*-r[0-9]+)\.apk')

_report = None  # where progress goes when no browser listens (the background preparation)


def notify(message):
    if _report is not None:
        _report(message)
        return
    os.write(0, b'S' + message.encode()[:160])


def write_progress(message):
    try:
        part = PROGRESS.with_name(PROGRESS.name + '.part')
        part.write_text(message[:200] + '\n')
        os.replace(part, PROGRESS)
    except OSError:
        pass


def cache_mount():
    # Its own short lock: a browser's download folder must not wait for a layer being prepared.
    with (CACHE.parent/'web-cache.mount.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _cache_mount()


def _cache_mount():
    CACHE.mkdir(mode=0o700, exist_ok=True)
    st = CACHE.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise RuntimeError('Unexpected browser RAM directory')
    mounts = [l.split(' - ', 1)[1].split()[0] for l in Path('/proc/self/mountinfo').read_text().splitlines()
              if l.split()[4] == str(CACHE)]
    if not mounts:
        subprocess.run(['/bin/mount','-t','tmpfs','-o',f'size={CACHE_SIZE},mode=0700,nosuid,nodev','tmpfs',str(CACHE)],check=True)
    elif mounts != ['tmpfs']:
        raise RuntimeError('Browser cache requires a private RAM filesystem')


def downloads():
    """The browser's download folder: in the private RAM filesystem, never on a card."""
    cache_mount()
    path = CACHE/'downloads'
    path.mkdir(mode=0o700, exist_ok=True)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise RuntimeError('Unexpected browser download directory')
    return path


def profile(uid):
    """The browser's profile for this recovery session (2026-11-20, a tester, #6: the browser did not
    resume its session after a short exit): cookies, logins and the last page stay in the private RAM
    filesystem, owned by the browser's user, until the recovery restarts."""
    cache_mount()
    path = CACHE/'profile'
    try:
        path.mkdir(mode=0o700)
        os.chown(path, uid, uid, follow_symlinks=False)
    except FileExistsError:
        pass
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or st.st_mode & 0o077:
        raise RuntimeError('Unexpected browser profile directory')
    return path


def cached(manifest=None):
    """A successful atomic publication is valid for this boot and this manifest."""
    tag = hashlib.sha256((MANIFEST if manifest is None else manifest).read_bytes()).hexdigest()
    root = CACHE / tag
    return root if root.is_dir() else None


def gpu_supported():
    """The browser can use the Panfrost GPU: its driver is bound, or the image carries the module built
    for the running kernel (web_launch loads it when the browser starts)."""
    if not PANFROST_DEVICE.is_dir():
        return False
    if (PANFROST_DEVICE/'driver').resolve() == PANFROST_DRIVER:
        return True
    return os.uname().release == PANFROST_RELEASE and PANFROST_MODULE.is_file()


# --- Alpine's own trust chain, for a pinned package the branch no longer has ---

def _der(buf, offset):
    tag, length = buf[offset], buf[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(buf[offset:offset + count], 'big')
        offset += count
    return tag, buf[offset:offset + length], offset + length


def rsa_public_key(pem):
    der = base64.b64decode(''.join(line for line in pem.strip().splitlines() if not line.startswith('-----')))
    _, info, _ = _der(der, 0)
    _, _, after_algorithm = _der(info, 0)
    _, bits, _ = _der(info, after_algorithm)
    _, numbers, _ = _der(bits[1:], 0)
    _, modulus, after_modulus = _der(numbers, 0)
    _, exponent, _ = _der(numbers, after_modulus)
    return int.from_bytes(modulus, 'big'), int.from_bytes(exponent, 'big')


def rsa_sha1_valid(signature, data, key):
    """PKCS#1 v1.5 with SHA-1, the scheme of an apk .SIGN.RSA signature."""
    modulus, exponent = key
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    block = pow(int.from_bytes(signature, 'big'), exponent, modulus).to_bytes(size, 'big')
    digest = SHA1_DIGEST_INFO + hashlib.sha1(data).digest()
    return hmac.compare_digest(block, b'\x00\x01' + b'\xff' * (size - 3 - len(digest)) + b'\x00' + digest)


def first_member(data):
    """The first gzip member of DATA decompressed, and the raw bytes after it."""
    stream = zlib.decompressobj(31)
    out = stream.decompress(data)
    if not stream.eof:
        raise RuntimeError('Browser index is cut short')
    return out, stream.unused_data


def parse_index(text):
    entries = {}
    for block in text.split('\n\n'):
        fields = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ':':
                fields[line[0]] = line[2:]
        if fields.get('P') and fields.get('V'):
            entries[fields['P']] = fields
    return entries


def verified_index(data, key=None, key_name=ALPINE_KEY_NAME):
    """The entries of an APKINDEX.tar.gz whose signature is Alpine's own (KEY: (modulus, exponent))."""
    signature_tar, signed = first_member(data)
    with tarfile.open(fileobj=io.BytesIO(signature_tar)) as tar:
        members = tar.getmembers()
        if len(members) != 1 or members[0].name != '.SIGN.RSA.' + key_name or not members[0].isreg():
            raise RuntimeError('Browser index is not signed with the expected Alpine key')
        signature = tar.extractfile(members[0]).read()
    if not rsa_sha1_valid(signature, signed, key or rsa_public_key(ALPINE_KEY)):
        raise RuntimeError('Browser index signature is not valid')
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(signed))) as tar:
        return parse_index(tar.extractfile('APKINDEX').read().decode('utf-8'))


_indexes = {}
_index_lock = threading.Lock()


def branch_index(repository):
    with _index_lock:
        if repository not in _indexes:
            with urllib.request.urlopen(f'{BASE}{repository}/{ARCH}/APKINDEX.tar.gz', timeout=25) as src:
                data = src.read(INDEX_LIMIT + 1)
            if len(data) > INDEX_LIMIT:
                raise RuntimeError('Browser index is too large')
            _indexes[repository] = verified_index(data)
        return _indexes[repository]


def current_package(package):
    """Where the branch has a pinned package now: its path, size and index checksum."""
    repository, arch, filename = package['path'].split('/')
    match = APK_NAME.fullmatch(filename)
    if arch != ARCH or repository not in ('main', 'community') or not match:
        raise RuntimeError('Unexpected browser component name')
    entry = branch_index(repository).get(match['name'])
    if not entry or not entry.get('C', '').startswith('Q1') or not entry.get('S', '').isdigit():
        raise RuntimeError('Browser component is no longer in the Alpine branch: ' + match['name'])
    return {'path': f"{repository}/{ARCH}/{match['name']}-{entry['V']}.apk", 'bytes': int(entry['S']),
            'checksum': base64.b64decode(entry['C'][2:]), 'files': package['files']}


def segment_offsets(path):
    """Where the control and the data part of an APK v2 file begin (after its signature)."""
    offsets, start = [], 0
    with path.open('rb') as source:
        for _ in range(2):
            source.seek(start)
            stream = zlib.decompressobj(31)
            consumed = 0
            while not stream.eof:
                chunk = source.read(65536)
                if not chunk:
                    raise RuntimeError('Browser component is cut short')
                stream.decompress(chunk, 1 << 20)
                consumed += len(chunk)
            start += consumed - len(stream.unused_data)
            offsets.append(start)
    return offsets


def verify_indexed(path, current):
    control_start, data_start = segment_offsets(path)
    with path.open('rb') as source:
        source.seek(control_start)
        control = source.read(data_start - control_start)
        if hashlib.sha1(control).digest() != current['checksum']:
            raise RuntimeError('Browser component does not match the signed index')
        digest = hashlib.sha256()
        while chunk := source.read(CHUNK):
            digest.update(chunk)
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(control))) as tar:
        info = tar.extractfile('.PKGINFO').read().decode('utf-8')
    hashes = [line.split('=', 1)[1].strip() for line in info.splitlines() if line.startswith('datahash')]
    if len(hashes) != 1 or not hmac.compare_digest(hashes[0], digest.hexdigest()):
        raise RuntimeError('Browser component data does not match its signed checksum')


def fetch(package, path, check=True):
    left = package['bytes']
    digest = hashlib.sha256()
    with urllib.request.urlopen(BASE + package['path'],timeout=25) as src, path.open('xb') as out:
        while left:
            data = src.read(min(left,CHUNK))
            if not data:
                raise RuntimeError('Browser component download was interrupted')
            out.write(data)
            digest.update(data)
            left -= len(data)
        if src.read(1) or (check and digest.hexdigest() != package['sha256']):
            raise RuntimeError('Browser component failed SHA-256 verification')


def unpack(package, root, work):
    archive = work / Path(package['path']).name
    try:
        fetch(package, archive)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        # The branch replaced this version (a security update): take the current one, verified.
        archive.unlink(missing_ok=True)
        current = current_package(package)
        archive = work / Path(current['path']).name
        archive.unlink(missing_ok=True)
        fetch(current, archive, check=False)
        verify_indexed(archive, current)
    selected = set(package['files'])
    try:
        # Alpine v2 APKs concatenate signature, control and data gzip members.
        with gzip.open(archive,'rb') as stream, tarfile.open(fileobj=stream,mode='r|',ignore_zeros=True) as tar:
            for member in tar:
                if member.name not in selected:
                    continue
                if not member.isreg() or member.size < 0:
                    raise RuntimeError('Unexpected file in browser component')
                target = root / member.name
                target.parent.mkdir(parents=True,exist_ok=True)
                with tar.extractfile(member) as src, target.open('xb') as out:
                    shutil.copyfileobj(src,out,CHUNK)
                target.chmod(0o555 if member.mode & 0o111 else 0o444)
                selected.remove(member.name)
        if selected:
            raise RuntimeError('Browser component did not contain a required file')
    finally:
        archive.unlink(missing_ok=True)
    return package['bytes']


def take_lock(lock, wait, ready=None):
    """The cache lock. A browser that finds the background preparation running shows its progress.
    False, without the lock, once READY() is true: what it waited for was published meanwhile (the
    preparation goes on with the GPU layer, which a browser does not wait for)."""
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        if not wait:
            raise
    shown = None
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if ready is not None and ready():
                return False
            try:
                now = PROGRESS.read_text().strip()
            except OSError:
                now = ''
            if now and now != shown:
                notify(now)
                shown = now
            time.sleep(0.5)


def ensure(wait=True, manifest=None, label=None):
    """The published tree of MANIFEST (the engine by default), prepared now if it is not yet.
    A publication is an atomic rename that stays until the recovery restarts, so a published tree
    needs no lock. The unprivileged browser can access only a separate read-only bind of it.
    LABEL names it in the progress told (media_service.py: the player and Bluetooth)."""
    manifest = MANIFEST if manifest is None else manifest
    engine = manifest == MANIFEST
    label = label or ('Web engine' if engine else 'Web graphics')
    existing = cached(manifest)
    if existing:
        return existing
    with (CACHE.parent/'web-cache.lock').open('a+b') as lock:
        if not take_lock(lock, wait, ready=lambda: cached(manifest)):
            return cached(manifest)
        cache_mount()
        existing = cached(manifest)
        if existing:
            return existing
        content = manifest.read_bytes()
        target = CACHE / hashlib.sha256(content).hexdigest()
        data = json.loads(content)
        packages = data['packages']
        total = sum(p['bytes'] for p in packages)
        largest = sorted((p['bytes'] for p in packages),reverse=True)[:3]
        required = data['unpacked_bytes'] + sum(largest) + 16 * CHUNK
        available = int(next(l for l in Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:')).split()[1])*1024
        for stale in CACHE.glob('.install-*'):
            if stale.is_dir():
                shutil.rmtree(stale)
        if shutil.disk_usage(CACHE).free < required or available < required + 192*CHUNK:
            raise RuntimeError('Insufficient free RAM for the ' + label.lower())
        notify(f'Downloading {label.lower()} · 0 / {total//CHUNK} MiB')
        with tempfile.TemporaryDirectory(prefix='.install-',dir=CACHE) as tmp:
            work=Path(tmp)
            tree=work/'root'
            tree.mkdir()
            done=0
            last_mib = 0
            with ThreadPoolExecutor(max_workers=3) as pool:
                tasks = [pool.submit(unpack,p,tree,work) for p in sorted(packages,key=lambda p:-p['bytes'])]
                try:
                    for future in as_completed(tasks):
                        done += future.result()
                        if done//CHUNK != last_mib:
                            last_mib=done//CHUNK
                            notify(f'{label} · {last_mib} / {total//CHUNK} MiB')
                except BaseException:
                    for future in tasks:
                        future.cancel()
                    raise
            for link,dest in data['links'].items():
                path=tree/link
                path.parent.mkdir(parents=True,exist_ok=True)
                path.symlink_to(dest)
            if engine:
                # Mount points of the session; a layer over the engine needs none of its own.
                # sys: the GPU's sysfs is put there when the Panfrost layer serves (2026-11-20, a
                # tester: without it every browser start with the GPU layer failed).
                for name in ('proc','dev','tmp','run','sys','downloads','opt','etc/ssl/certs'):
                    (tree/name).mkdir(parents=True,exist_ok=True)
                for name in ('opt/web_session.py','opt/web-compositor','etc/resolv.conf'):
                    (tree/name).touch(mode=0o444)
                bundle=tree/'etc/ssl/certs/ca-certificates.crt'
                shutil.copyfile('/etc/ssl/certs/ca-certificates.crt',bundle)
                bundle.chmod(0o444)
            # Recovery has a private umask. Traversal inside the read-only
            # runtime must also work for the dropped browser UID.
            for directory, _, _ in os.walk(tree):
                os.chmod(directory,0o555)
            os.rename(tree,target)
        return target


def prefetch():
    """After Wi-Fi joins: prepare the engine in RAM, then the GPU layer where the GPU can be used.
    Both stay until the recovery restarts."""
    global _report
    graphics = gpu_supported()
    if cached() and (not graphics or cached(GPU_MANIFEST)):
        return 0
    _report = write_progress
    try:
        ensure(wait=False)
    except BlockingIOError:
        return 0  # a browser (or another preparation) is preparing it already
    except Exception as error:
        write_progress('Web engine not prepared: ' + str(error)[:120])
        return 1
    if graphics:
        try:
            ensure(wait=False, manifest=GPU_MANIFEST)
        except BlockingIOError:
            return 0  # another preparation has it
        except Exception as error:
            # The engine works without it: Chromium then draws in software.
            write_progress('Web engine ready, without GPU: ' + str(error)[:100])
            return 0
    write_progress('Web engine ready')
    return 0


def prefetch_in_background():
    try:
        subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve()), 'prefetch'], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    except OSError:
        pass


if __name__ == '__main__':
    if sys.argv[1:] != ['prefetch']:
        print('usage: web_cache.py prefetch', file=sys.stderr)
        raise SystemExit(64)
    raise SystemExit(prefetch())
