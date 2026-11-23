"""Pin the fast browser path from Alpine's signed v3.24 index (2026-11-20).

The owner: "можна вантажити браузер з інета як тільки під'єднаний вайфай". Until now the full Chromium
for Wayland and Mesa's Panfrost driver came only from developer card packages; this pins them as
Alpine packages that web_cache.py downloads into RAM, as it does the engine.

  web_packages.json      the engine: chromium-headless-shell leaves, the full Chromium (screencast
                         with --headless=new, or direct Wayland output) and its library closure join;
  web_gpu_packages.json  Mesa's Panfrost driver, its EGL/GLES/GBM entry points and their closure,
                         a layer over the engine used only when the Panfrost GPU can be.

Which package owns a file comes from an apk-installed Alpine root (lib/apk/db/installed). The bytes
come from the branch as it is now and are verified as the phone verifies them: the index's RSA
signature (web_cache.verified_index) and the package's control checksum and data hash
(web_cache.verify_indexed). Packages the engine already pins keep their pinned version.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import gzip
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import web_cache  # noqa: E402

HEADLESS_SHELL = 'chromium-headless-shell'
CHROMIUM = 'usr/lib/chromium/'
ENGINE_WANTED = ['usr/lib/libwayland-server.so.0', 'usr/lib/libwayland-cursor.so.0', 'usr/lib/libwayland-client.so.0'] + [
    CHROMIUM + name for name in ('chromium', 'chrome', 'chrome_crashpad_handler', 'chrome_100_percent.pak',
                                 'chrome_200_percent.pak', 'icudtl.dat', 'resources.pak',
                                 'ui_resources_100_percent.pak', 'snapshot_blob.bin', 'locales/en-US.pak')]
GPU_WANTED = ['usr/lib/dri/panfrost_dri.so', 'usr/lib/gbm/dri_gbm.so', 'usr/lib/libEGL.so.1', 'usr/lib/libGLESv2.so.2']


def owners_of(database):
    owners = {}
    for section in database.read_text().split('\n\n'):
        name = folder = None
        for line in section.splitlines():
            if line.startswith('P:'):
                name = line[2:]
            elif line.startswith('F:'):
                folder = line[2:]
            elif line.startswith('R:'):
                owners[str(PurePosixPath(folder, line[2:]))] = name
    return owners


def package_name(route):
    return web_cache.APK_NAME.fullmatch(route.rsplit('/', 1)[1])['name']


class Packages:
    """Downloaded, verified and unpacked Alpine packages, one staging folder each."""

    def __init__(self, cache, engine):
        self.cache = cache
        self.engine = {package_name(p['path']): p for p in engine['packages']}
        self.staged = {}

    def download(self, route, size):
        apk = self.cache / route.rsplit('/', 1)[1]
        if not apk.exists():
            part = apk.with_name(apk.name + '.part')
            with urllib.request.urlopen(web_cache.BASE + route, timeout=60) as src, part.open('wb') as out:
                shutil.copyfileobj(src, out, 1 << 20)
            part.rename(apk)
        if apk.stat().st_size != size:
            raise ValueError('Package size differs from its pin or signed index: ' + route)
        return apk

    def stage(self, name):
        if name in self.staged:
            return self.staged[name]
        pinned = self.engine.get(name)
        if pinned:
            apk = self.download(pinned['path'], pinned['bytes'])
            route, size = pinned['path'], pinned['bytes']
        else:
            repository = next((r for r in ('main', 'community') if name in web_cache.branch_index(r)), None)
            if repository is None:
                raise ValueError('Package is not in the Alpine branch: ' + name)
            entry = web_cache.branch_index(repository)[name]
            route, size = f"{repository}/{web_cache.ARCH}/{name}-{entry['V']}.apk", int(entry['S'])
            apk = self.download(route, size)
            web_cache.verify_indexed(apk, {'checksum': base64.b64decode(entry['C'][2:])})
        with apk.open('rb') as f:
            digest = hashlib.file_digest(f, 'sha256').hexdigest()
        if pinned and digest != pinned['sha256']:
            raise ValueError('Package differs from the engine pin: ' + route)
        stage = self.cache / 'stage' / name
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(parents=True)
        with gzip.open(apk, 'rb') as stream, tarfile.open(fileobj=stream, mode='r|', ignore_zeros=True) as tar:
            for member in tar:
                parts = PurePosixPath(member.name).parts
                if member.name.startswith('.') or not parts or '..' in parts or member.name.startswith('/'):
                    continue
                target = stage / member.name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.issym():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(member.linkname)
                elif member.isreg():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as src, target.open('xb') as out:
                        shutil.copyfileobj(src, out, 1 << 20)
                elif member.islnk():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(stage / member.linkname, target)
        self.staged[name] = (dict(path=route, bytes=size, sha256=digest), stage)
        return self.staged[name]

    def find(self, path):
        for name, (_, stage) in self.staged.items():
            if os.path.lexists(stage / path):
                return name
        return None


def needed(path):
    with path.open('rb') as f:
        if f.read(4) != b'\x7fELF':
            return []
    return re.findall(r'\(NEEDED\).*?\[(.*?)\]', subprocess.check_output(['readelf', '-d', str(path)], text=True))


def closure(wanted, provided, owners, packages):
    """Regular files by owning package and links, for WANTED and every library they need."""
    files, links, pending = {}, {}, list(wanted)
    while pending:
        path = pending.pop()
        if path in provided or path in links or any(path in f for f in files.values()):
            continue
        name = owners.get(path) or packages.find(path)
        if name is None:
            raise ValueError('No package owns ' + path)
        _, stage = packages.stage(name)
        node = stage / path
        if node.is_symlink():
            parent = str(PurePosixPath(path).parent)
            dest = os.path.normpath(os.path.join('/', parent, os.readlink(node))).lstrip('/')
            links[path] = os.path.relpath(dest, parent)
            pending.append(dest)
            continue
        if not node.is_file():
            raise ValueError(f'{name} as pinned has no {path}')
        files.setdefault(name, set()).add(path)
        for library in needed(node):
            candidates = [f'{folder}/{library}' for folder in ('usr/lib', 'lib', str(PurePosixPath(path).parent))]
            found = next((c for c in candidates if c in provided), None) or next(
                (c for c in candidates if c in owners or packages.find(c)), None)
            if found is None:
                raise ValueError(f'Missing dependency {library} of {path}')
            pending.append(found)
    return files, links


def size_of(packages, files):
    return sum((packages.staged[name][1] / path).stat().st_size for name, paths in files.items() for path in paths)


def build(database, engine_path, cache):
    engine = json.loads(engine_path.read_text())
    owners = owners_of(database)
    packages = Packages(cache, engine)
    # The headless shell leaves (its own unpacked size from its pinned package). A manifest made by
    # this tool has none any more, and running it again changes nothing.
    shell = next((p for p in engine['packages'] if package_name(p['path']) == HEADLESS_SHELL), None)
    shell_bytes = 0
    if shell:
        _, shell_stage = packages.stage(HEADLESS_SHELL)
        shell_bytes = sum((shell_stage / path).stat().st_size for path in shell['files'])
    kept = [p for p in engine['packages'] if p is not shell]
    provided = {path for p in kept for path in p['files']} | set(engine['links'])

    files, links = closure(ENGINE_WANTED, provided, owners, packages)
    new_engine = {package_name(p['path']): dict(p, files=list(p['files'])) for p in kept}
    for name, paths in files.items():
        pin, _ = packages.staged[name]
        entry = new_engine.setdefault(name, dict(pin, files=[]))
        entry['files'] = sorted(set(entry['files']) | paths)
    engine_manifest = dict(packages=sorted(new_engine.values(), key=lambda p: p['path']),
                           links=dict(sorted({**engine['links'], **links}.items())),
                           unpacked_bytes=engine['unpacked_bytes'] - shell_bytes + size_of(packages, files))

    provided = {path for p in engine_manifest['packages'] for path in p['files']} | set(engine_manifest['links'])
    gpu_files, gpu_links = closure(GPU_WANTED, provided, owners, packages)
    gpu_manifest = dict(packages=sorted((dict(packages.staged[name][0], files=sorted(paths))
                                         for name, paths in gpu_files.items()), key=lambda p: p['path']),
                        links=dict(sorted(gpu_links.items())), unpacked_bytes=size_of(packages, gpu_files))
    return engine_manifest, gpu_manifest


def write(path, data):
    path.write_text(json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n')
    print(path.name, len(data['packages']), 'packages', sum(p['bytes'] for p in data['packages']), 'download bytes',
          data['unpacked_bytes'], 'unpacked bytes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('database', type=Path, help="An apk-installed Alpine root's lib/apk/db/installed")
    parser.add_argument('cache', type=Path, help='Folder for downloaded and unpacked packages')
    parser.add_argument('--engine', type=Path, default=Path(web_cache.MANIFEST), help='The current engine manifest')
    parser.add_argument('--output', type=Path, default=Path(web_cache.MANIFEST).parent)
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    engine_manifest, gpu_manifest = build(args.database, args.engine, args.cache.resolve())
    write(args.output / 'web_packages.json', engine_manifest)
    write(args.output / 'web_gpu_packages.json', gpu_manifest)
