"""Pin runtime files from an APK-verified Alpine aarch64 installation and repository indexes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import urllib.request

BASE = 'https://dl-cdn.alpinelinux.org/alpine/v3.24/'


def paragraphs(file):
    for section in file.read_text().split('\n\n'):
        fields = {}
        for line in section.splitlines():
            if line[1:2] == ':':
                fields.setdefault(line[0], []).append(line[2:])
        if fields:
            yield fields, section.splitlines()


def build(root, indexes, cache):
    owners, repos = {}, {}
    for path in indexes:
        for fields, _ in paragraphs(path):
            repos[fields['C'][0]] = path.stem
    packages = {}
    for fields, lines in paragraphs(root/'lib/apk/db/installed'):
        name = fields['P'][0]
        packages[name] = (fields['V'][0], int(fields['S'][0]), repos[fields['C'][0]])
        for line in lines:
            if line.startswith('F:'):
                folder = line[2:]
            if line.startswith('R:'):
                owners[str(PurePosixPath(folder, line[2:]))] = name

    selected, links, pending = set(), {}, []
    def select(path):
        if path not in selected:
            if path not in owners:
                raise ValueError('Missing package owner for '+path)
            selected.add(path)
            pending.append(path)

    for path in owners:
        if (path in ('usr/bin/python3','lib/ld-musl-aarch64.so.1','etc/fonts/fonts.conf')
            or path.startswith(('usr/lib/chromium/', 'usr/share/icu/', 'etc/fonts/conf.d/',
                                'usr/share/fontconfig/conf.avail/', 'usr/share/fonts/opensans/OpenSans-Regular',
                                'usr/share/fonts/opensans/OpenSans-Bold.'))
            or path.startswith('usr/lib/python3.14/') and not {'__pycache__','test','tests','idlelib','turtledemo','tkinter','ensurepip'}.intersection(path.split('/'))
            or re.fullmatch(r'usr/lib/lib(nssckbi|freeblpriv3|softokn3)\.so', path)):
            if path.endswith(('libvk_swiftshader.so','vk_swiftshader_icd.json')):
                continue
            select(path)
    while pending:
        path = pending.pop()
        f = root/path
        if f.is_symlink():
            target = os.readlink(f)
            dest = os.path.normpath(os.path.join('/', str(PurePosixPath(path).parent), target)).lstrip('/')
            links[path] = os.path.relpath(dest, str(PurePosixPath(path).parent))
            select(dest)
            continue
        with f.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
        info = subprocess.check_output(['readelf','-d',f], text=True)
        for lib in re.findall(r'\(NEEDED\).*?\[(.*?)\]',info):
            candidates = [f'{p}/{lib}' for p in ('usr/lib','lib','usr/lib/pulseaudio',str(PurePosixPath(path).parent))]
            found = next((p for p in candidates if p in owners), None)
            if not found:
                raise ValueError(f"Missing dependency {lib} for {path}")
            select(found)
    members = {}
    for path in sorted(selected-links.keys()):
        members.setdefault(owners[path],[]).append(path)
    def pin(item):
        name, files = item
        version, size, repo = packages[name]
        route = f'{repo}/aarch64/{name}-{version}.apk'
        apk = cache / Path(route).name
        if not apk.exists():
            with urllib.request.urlopen(BASE + route, timeout=60) as src, apk.with_suffix('.part').open('wb') as dest:
                import shutil
                shutil.copyfileobj(src, dest)
            apk.with_suffix('.part').rename(apk)
        if apk.stat().st_size != size:
            raise ValueError('Package size differs from its verified index: '+route)
        # The index links to the signed control archive. Verify the data and
        # signature too before embedding a pin for all bytes of the .apk.
        loader = cache.parent/'host/lib/ld-musl-x86_64.so.1'
        library = cache.parent/'host/lib'
        subprocess.run([loader,'--library-path',f'{library}:{cache.parent}/host/usr/lib',
                        cache.parent/'host/sbin/apk','--keys-dir',root/'etc/apk/keys','verify',apk],
                       stdout=subprocess.DEVNULL,check=True)
        with apk.open('rb') as f:
            digest = hashlib.file_digest(f,'sha256').hexdigest()
        return dict(path=route, bytes=size, sha256=digest, files=files)
    with ThreadPoolExecutor(max_workers=8) as pool:
        archive = list(pool.map(pin, sorted(members.items())))
    return dict(packages=archive,links=links,unpacked_bytes=sum((root/p).stat().st_size for p in selected-links.keys()))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prepared',type=Path,help='Contains verified root/, host/, main.index and community.index')
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    base=args.prepared.resolve()
    cache=base/'apk-cache'
    cache.mkdir(exist_ok=True)
    data=build(base/'root',[base/'main.index',base/'community.index'],cache)
    args.output.write_text(json.dumps(data,sort_keys=True,separators=(',',':'))+'\n')
    print(len(data['packages']),sum(p['bytes'] for p in data['packages']),data['unpacked_bytes'])
