#!/usr/bin/env python3
"""Pin the media and Bluetooth layer from Alpine's signed v3.24 index (2026-11-22, the owner: a player for
local music and video, and Bluetooth).

The layer stacks over the browser's engine (web_packages.json), which already holds FFmpeg's decoders and
demuxers, ALSA, D-Bus's library and GLib: it adds only what the engine lacks for the player (libswscale)
and Bluetooth (BlueZ's daemon and bluetoothctl, the D-Bus daemon, BlueALSA with its codecs). Every file of
those packages is taken; web_cache.ensure(manifest=...) downloads and checks them on the phone like the
engine's.

    build_media_packages.py OUT.json            over the engine (media_packages.json)
    build_media_packages.py --full OUT.json     on its own (media_full_packages.json)

The second is used while the browser's engine is not in RAM: a whole Chromium (about 460 MB of RAM) only
for FFmpeg and ALSA was too much for Bluetooth headphones (2026-11-22, measured on the phone).
"""
import base64
import hashlib
import json
import re
import sys
import tarfile
import gzip
import tempfile
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import web_cache  # noqa: E402
import alpine_sysroot  # noqa: E402

WANTED = ('ffmpeg-libswscale', 'bluez', 'bluez-alsa', 'bluez-alsa-utils', 'dbus')
# On its own: also what the player links and the engine had (a22x-media: avformat, avcodec, swresample, asound).
FULL = WANTED + ('ffmpeg-libavformat', 'ffmpeg-libavcodec', 'ffmpeg-libswresample', 'ffmpeg-libavutil', 'alsa-lib', 'musl')
# Not wanted in the layer although the closure names them: a shell (the recovery has one), and the
# Vulkan shader compilers swscale links only for its GPU path, which the player does not use... are kept:
# a library the loader needs must be there. Only documentation is left out.
SKIP = re.compile(r'^usr/share/(doc|man|info)/')


def engine_names():
    root = Path(__file__).resolve().parents[1]
    data = json.loads((root / 'web_packages.json').read_text())
    return {re.sub(r'-[0-9][^-]*-r[0-9]+\.apk$', '', p['path'].split('/')[-1]) for p in data['packages']}


def main(out, full=False):
    entries, providers = alpine_sysroot.indexes()
    engine = set() if full else engine_names()
    names = [n for n in alpine_sysroot.closure(FULL if full else WANTED, entries, providers) if n not in engine]
    packages, links, unpacked = [], {}, 0
    with tempfile.TemporaryDirectory() as tmp:
        for name in sorted(names):
            repository, fields = entries[name]
            path = f"{repository}/{web_cache.ARCH}/{fields['P']}-{fields['V']}.apk"
            current = {'path': path, 'bytes': int(fields['S']), 'checksum': base64.b64decode(fields['C'][2:])}
            archive = Path(tmp) / Path(path).name
            web_cache.fetch(current, archive, check=False)
            web_cache.verify_indexed(archive, current)
            files = []
            with gzip.open(archive, 'rb') as stream, tarfile.open(fileobj=stream, mode='r|', ignore_zeros=True) as tar:
                for member in tar:
                    member_path = PurePosixPath(member.name)
                    if member.name.startswith('.') or member_path.is_absolute() or '..' in member_path.parts or SKIP.match(member.name):
                        continue
                    if member.isreg():
                        files.append(member.name)
                        unpacked += member.size
                    elif member.issym():
                        links[member.name] = member.linkname
            packages.append({'path': path, 'bytes': current['bytes'],
                             'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'files': sorted(files)})
            archive.unlink()
    Path(out).write_text(json.dumps({'links': dict(sorted(links.items())), 'packages': packages,
                                     'unpacked_bytes': unpacked}, separators=(',', ':')) + '\n')
    print(json.dumps({'packages': len(packages), 'download_bytes': sum(p['bytes'] for p in packages),
                      'unpacked_bytes': unpacked, 'links': len(links)}))


if __name__ == '__main__':
    if sys.argv[1:2] == ['--full']:
        main(sys.argv[2], full=True)
    else:
        main(sys.argv[1])
