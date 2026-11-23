#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The boot splash of the theme in use, kept in misc for the kernel (2026-11-21, the owner).

Between the bootloader's logo and the recovery's first frame the screen stayed black for about
1.4 s: the kernel's boot splash knows only its three built-in themes and waited for /init to name
one, and /init stopped it before it drew, to read the theme from misc and have the UI draw it. Now
the picture itself waits in misc: the kernel (drivers/gpu/drm/mediatek/mtk_boot_splash.c) reads it
as soon as the eMMC is there, long before the display, and draws it the moment the framebuffer
exists; the UI carries its bar on to 100%. Whenever the theme in use changes (one added, imported
or edited too), its picture is drawn again by the UI (recovery-ui --splash-pictures) and kept here,
only when it differs from what misc holds.

The record (misc_store 'splash', two slots of 128 KiB; all numbers little-endian):
    0   magic 'A22XSPL1'
    8   u16 width, height of the frame (1080 x 2408)
    12  u16 x, y, width, height of the progress bar
    20  u32 colors of the bar's track and fill (0xRRGGBB)
    28  u16 width, height of the background grid
    32  u16 x, y, width, height of the picture box (the logo and its words)
    40  u32 bytes of the deflated grid, then of the deflated box
    48  32 bytes: SHA-256 of what the picture was made from
    80  the grid, raw deflate: RGB, each cell the average of its square of the background; the
        kernel stretches it back (bilinear, from the cells' centres)
        the box, raw deflate: a byte per pixel of the box (1 where the picture is not its
        background), then the RGB of those pixels in order
The finest grid that fits is taken: a plain color fits whole, a gradient in squares of a few pixels.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import misc_store  # noqa: E402

MAGIC = b'A22XSPL1'
HEAD = struct.Struct('<8s6H2I6H2I32s')
WIDTH, HEIGHT = 1080, 2408
UI = '/bin/recovery-ui'
WORK = Path('/run/a22x-recovery')
THEME_CHARS = set('abcdefghijklmnopqrstuvwxyz0123456789-')
LOCK_WAIT = 30.0


class SplashError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def require(condition, code, message):
    if not condition:
        raise SplashError(code, message)


def valid_theme(code):
    return isinstance(code, str) and 3 <= len(code) <= 23 and set(code) <= THEME_CHARS


def deflate(data):
    packer = zlib.compressobj(9, zlib.DEFLATED, -15, 9)
    return packer.compress(data) + packer.flush()


def inflate(data, size):
    unpacker = zlib.decompressobj(-15)
    out = unpacker.decompress(data, size + 1)
    require(unpacker.eof and not unpacker.unconsumed_tail and len(out) == size, 'SPLASH_INVALID', 'A part of the picture is damaged')
    return out


def render(theme, ui, folder):
    """The UI's pictures of THEME's splash in FOLDER; its facts (JSON)."""
    require(valid_theme(theme), 'INVALID_THEME', 'Invalid theme name')
    try:
        run = subprocess.run([ui, '--splash-pictures', theme, '--render', str(folder)], stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SplashError('RENDER_FAILED', 'The recovery UI could not draw the splash: %s' % type(error).__name__) from None
    require(run.returncode == 0, 'RENDER_FAILED', 'The recovery UI could not draw the splash of this theme')
    try:
        facts = json.loads(run.stdout.decode().strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise SplashError('RENDER_FAILED', 'The recovery UI gave no facts of the splash') from None
    numbers = [facts.get('width'), facts.get('height'), *facts.get('bar', ()), facts.get('track'), facts.get('fill'),
               *facts.get('crop', ()), facts.get('set')]
    require(facts.get('ok') is True and len(numbers) == 13 and all(isinstance(n, int) and n >= 0 for n in numbers)
            and (facts['width'], facts['height']) == (WIDTH, HEIGHT), 'RENDER_FAILED', 'Unexpected facts of the splash')
    x, y, w, h = facts['crop']
    require(w > 0 and h > 0 and x + w <= WIDTH and y + h <= HEIGHT, 'RENDER_FAILED', 'The picture lies outside the frame')
    return facts


def pack(facts, folder, room):
    """(payload, scale) of the pictures in FOLDER: the finest grid whose record fits in ROOM bytes."""
    folder = Path(folder)
    x, y, w, h = facts['crop']
    box = (folder / 'crop.bin').read_bytes()
    require(len(box) == w * h + 3 * facts['set'] and sum(box[:w * h]) == facts['set'], 'RENDER_FAILED',
            'The picture box does not match its facts')
    whole = (folder / 'grid-1.rgb').read_bytes()
    require(len(whole) == WIDTH * HEIGHT * 3, 'RENDER_FAILED', 'The background does not match the frame')
    made = {key: facts[key] for key in ('width', 'height', 'bar', 'track', 'fill', 'crop', 'set')}
    source = hashlib.sha256(json.dumps(made, sort_keys=True).encode() + box + whole).digest()
    packed_box = deflate(box)
    for scale, gw, gh in sorted(facts.get('grids', ()), key=lambda grid: grid[0]):
        require(all(isinstance(n, int) for n in (scale, gw, gh)) and 0 < gw <= WIDTH and 0 < gh <= HEIGHT,
                'RENDER_FAILED', 'Unexpected background grid')
        grid = whole if scale == 1 else (folder / ('grid-%d.rgb' % scale)).read_bytes()
        require(len(grid) == gw * gh * 3, 'RENDER_FAILED', 'The background grid does not match its size')
        packed = deflate(grid)
        if HEAD.size + len(packed) + len(packed_box) <= room:
            head = HEAD.pack(MAGIC, WIDTH, HEIGHT, *facts['bar'], facts['track'], facts['fill'], gw, gh, x, y, w, h,
                             len(packed), len(packed_box), source)
            return head + packed + packed_box, scale
    raise SplashError('SPLASH_TOO_LARGE', 'The splash of this theme does not fit in misc')


def parse(payload):
    """The record's fields as a dict, or SplashError: the checks the kernel makes."""
    require(len(payload) >= HEAD.size, 'SPLASH_INVALID', 'The splash record is too short')
    (magic, width, height, bx, by, bw, bh, track, fill, gw, gh, x, y, w, h, grid_len, box_len,
     source) = HEAD.unpack_from(payload)
    require(magic == MAGIC and (width, height) == (WIDTH, HEIGHT), 'SPLASH_INVALID', 'Not a splash record of this phone')
    require(0 < gw <= width and 0 < gh <= height and 0 < w and 0 < h and x + w <= width and y + h <= height
            and bx + bw <= width and by + bh <= height and track < 1 << 24 and fill < 1 << 24,
            'SPLASH_INVALID', 'The splash record is out of bounds')
    require(HEAD.size + grid_len + box_len == len(payload), 'SPLASH_INVALID', 'The splash record has a wrong length')
    return {'bar': (bx, by, bw, bh), 'track': track, 'fill': fill, 'grid': (gw, gh), 'box': (x, y, w, h),
            'grid_data': payload[HEAD.size:HEAD.size + grid_len], 'box_data': payload[HEAD.size + grid_len:],
            'source': source.hex()}


def _taps(size, cells):
    """For every pixel of SIZE: (cell, next cell, weight of the next of 65536), as the kernel computes it."""
    taps = []
    for n in range(size):
        at = ((2 * n + 1) * cells - size) * 65536 // (2 * size)
        if at <= 0:
            taps.append((0, 0, 0))
            continue
        cell, weight = at >> 16, at & 0xffff
        taps.append((cell, cell, 0) if cell >= cells - 1 else (cell, cell + 1, weight))
    return taps


def picture(payload, rows=None):
    """The frame the kernel draws from PAYLOAD, {row: bytes of RGB} for ROWS (all by default): a
    reference of mtk_boot_splash.c for the tests."""
    record = parse(payload)
    gw, gh = record['grid']
    grid = inflate(record['grid_data'], gw * gh * 3)
    x0, y0, w, h = record['box']
    raw = zlib.decompressobj(-15)
    box = raw.decompress(record['box_data'])
    require(raw.eof and len(box) >= w * h, 'SPLASH_INVALID', 'The picture box is damaged')
    mask, colors = box[:w * h], box[w * h:]
    require(len(colors) == 3 * sum(mask) and set(mask) <= {0, 1}, 'SPLASH_INVALID', 'The picture box is damaged')
    xs, ys = _taps(WIDTH, gw), _taps(HEIGHT, gh)
    starts, at = [], 0
    for line in range(h):
        starts.append(at)
        at += 3 * sum(mask[line * w:(line + 1) * w])
    out = {}
    for row in (range(HEIGHT) if rows is None else rows):
        a, b, fy = ys[row]
        line = bytearray(WIDTH * 3)
        for column in range(WIDTH):
            c, d, fx = xs[column]
            for k in range(3):
                top = grid[(a * gw + c) * 3 + k] * (65536 - fx) + grid[(a * gw + d) * 3 + k] * fx
                bottom = grid[(b * gw + c) * 3 + k] * (65536 - fx) + grid[(b * gw + d) * 3 + k] * fx
                line[column * 3 + k] = (top * (65536 - fy) + bottom * fy + (1 << 31)) >> 32
        if y0 <= row < y0 + h:
            at = starts[row - y0]
            for column in range(w):
                if mask[(row - y0) * w + column]:
                    line[(x0 + column) * 3:(x0 + column) * 3 + 3] = colors[at:at + 3]
                    at += 3
        out[row] = bytes(line)
    return out


@contextlib.contextmanager
def device_lease():
    """The recovery's operation lock, as settings.py takes it for misc; waited for, LOCK_WAIT at most."""
    import filesystem as fs
    from operation_lock import lease
    context = fs.DeviceContext()
    deadline = time.monotonic() + LOCK_WAIT
    while True:
        try:
            with lease(context.lock_path, context.mode):
                yield
            return
        except BlockingIOError:
            if time.monotonic() > deadline:
                raise SplashError('BUSY', 'Another operation holds the recovery for too long') from None
            time.sleep(.5)


def current_theme():
    """The theme in use: the settings' (settings.py: the RAM copy, else misc), Graphite without any."""
    import settings
    try:
        theme = settings.load().get('theme')
    except (OSError, ValueError, AttributeError, misc_store.Damaged):
        theme = None
    return theme if valid_theme(theme) else settings.DEFAULTS['theme']


def save(theme=None, ui=UI, lock=True, now=current_theme):
    """The splash of THEME (the theme in use by default) into misc when misc does not hold it
    already, in both copies. Drawn outside the lock; under it, kept only while THEME is still the one
    in use (NOW): a save started before the theme changed never writes over the newer one's."""
    following = theme is None
    theme = now() if following else theme
    folder = tempfile.mkdtemp(prefix='splash-', dir=str(WORK) if WORK.is_dir() else None)
    try:
        facts = render(theme, ui, folder)
        payload, scale = pack(facts, folder, misc_store.payload_max('splash'))
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    parse(payload)
    result = {'theme': theme, 'scale': scale, 'bytes': len(payload), 'source': payload[48:80].hex()}
    with device_lease() if lock else contextlib.nullcontext():
        if following and now() != theme:
            return {**result, 'written': False, 'stale': True}
        try:
            current, twice, _ = misc_store.state('splash')
        except misc_store.Damaged:
            current, twice = None, False
        if current == payload and twice:
            return {**result, 'written': False}
        misc_store.write('splash', payload)
    return {**result, 'written': True}


def show():
    payload = misc_store.read('splash')
    if payload is None:
        return {'kept': False}
    record = parse(payload)
    return {'kept': True, 'bytes': len(payload), 'grid': record['grid'], 'box': record['box'], 'bar': record['bar'],
            'track': '%06x' % record['track'], 'fill': '%06x' % record['fill'], 'source': record['source']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest='operation', required=True)
    keep = commands.add_parser('save')
    keep.add_argument('--theme', help='A theme to keep; the one in use by default')
    keep.add_argument('--ui', default=UI)
    commands.add_parser('show')
    args = parser.parse_args(argv)
    try:
        value = save(args.theme, args.ui) if args.operation == 'save' else show()
        print(json.dumps({'ok': True, 'operation': args.operation, **value}, separators=(',', ':')))
        return 0
    except SplashError as error:
        code, message = error.code, str(error)
    except misc_store.Foreign:
        code, message = 'MISC_FOREIGN', 'The splash area of misc holds bytes of another program'
    except (OSError, misc_store.Damaged) as error:
        code, message = 'MISC_UNAVAILABLE', 'misc cannot be used now (%s)' % type(error).__name__
    print(json.dumps({'ok': False, 'operation': args.operation, 'error': {'code': code, 'message': message}},
                     separators=(',', ':')))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
