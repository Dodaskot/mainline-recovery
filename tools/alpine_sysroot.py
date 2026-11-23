#!/usr/bin/env python3
"""An aarch64 Alpine root from the signed v3.24 index, without apk (2026-11-22).

For the media player and Bluetooth (the owner: a player for local music and video, and Bluetooth): their
build needs Alpine's headers and libraries (musl, FFmpeg, ALSA), and the phone's runtime the same
libraries with BlueZ and BlueALSA. The packages named and everything they depend on (by name, so: and
cmd:) are taken from main and community, each checked against the index whose RSA signature is
Alpine's (web_cache.verified_index, verify_indexed: the control part's SHA-1, the data's SHA-256), and
unpacked into ROOT with their links. A JSON list of what was taken is written beside it.

    alpine_sysroot.py ROOT PACKAGE...        e.g. musl-dev ffmpeg-dev alsa-lib-dev linux-headers
"""
import json
import sys
import tarfile
import gzip
from pathlib import Path, PurePosixPath
import re
import base64

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import web_cache  # noqa: E402

REPOSITORIES = ('main', 'community')


def indexes():
    entries = {}
    for repository in REPOSITORIES:
        for name, fields in web_cache.branch_index(repository).items():
            entries.setdefault(name, (repository, fields))
    providers = {}
    for name, (repository, fields) in entries.items():
        for item in fields.get('p', '').split():
            providers.setdefault(re.split(r'[=<>~]', item, maxsplit=1)[0], name)
    return entries, providers


def closure(wanted, entries, providers):
    chosen, pending = [], list(wanted)
    while pending:
        item = re.split(r'[=<>~]', pending.pop(), maxsplit=1)[0]
        if item.startswith('!'):
            continue
        name = item if item in entries else providers.get(item)
        if not name:
            raise SystemExit('Nothing in the index provides ' + item)
        if name in chosen:
            continue
        chosen.append(name)
        pending.extend(entries[name][1].get('D', '').split())
    return chosen


def take(root, work, repository, fields):
    path = f"{repository}/{web_cache.ARCH}/{fields['P']}-{fields['V']}.apk"
    current = {'path': path, 'bytes': int(fields['S']), 'checksum': base64.b64decode(fields['C'][2:])}
    archive = work / Path(path).name
    archive.unlink(missing_ok=True)
    web_cache.fetch(current, archive, check=False)
    web_cache.verify_indexed(archive, current)
    with gzip.open(archive, 'rb') as stream, tarfile.open(fileobj=stream, mode='r|', ignore_zeros=True) as tar:
        for member in tar:
            name = PurePosixPath(member.name)
            if member.name.startswith('.') or name.is_absolute() or '..' in name.parts:
                continue
            target = root / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.issym():
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.is_symlink() or target.exists():
                    target.unlink()
                target.symlink_to(member.linkname)
            elif member.isreg():
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.is_symlink() or target.exists():
                    target.unlink()
                with tar.extractfile(member) as src, target.open('wb') as out:
                    out.write(src.read())
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    archive.unlink()
    return {'name': fields['P'], 'version': fields['V'], 'path': path, 'bytes': int(fields['S'])}


def main(argv):
    root, wanted = Path(argv[1]), argv[2:]
    root.mkdir(parents=True, exist_ok=True)
    work = root.parent / (root.name + '.download')
    work.mkdir(exist_ok=True)
    entries, providers = indexes()
    names = closure(wanted, entries, providers)
    taken = [take(root, work, *entries[name]) for name in names]
    work.rmdir()
    (root.parent / (root.name + '.packages.json')).write_text(json.dumps(taken, indent=1) + '\n')
    print(json.dumps({'packages': len(taken), 'bytes': sum(p['bytes'] for p in taken)}))


if __name__ == '__main__':
    main(sys.argv)
