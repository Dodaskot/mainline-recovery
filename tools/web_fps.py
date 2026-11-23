#!/usr/bin/python3
"""Browser frame rate on the phone, as the recovery's UI would get it (2026-11-20).

Stands in for the native UI: starts /opt/a22x-recovery/web_launch.py with the frame memfd (fd 5),
the control socket (fd 0) and, unless --relay, the UI's own frame socket (fd 6), opens a page,
scrolls it the way a finger does (moves at 90 Hz) and counts the frames the compositor hands
over, acknowledging them like web_ui.h. With --copy it also copies each frame once, as the UI
does into the panel. Run as root in the recovery, with the UI's own browser closed:

    python3 -B web_fps.py [--relay] [--copy] [--seconds 20] URL

Prints one JSON line: mode (direct, relay or screencast), fps, frames per second, gaps.
Switches for the engine are in /run/a22x-recovery/web-options.json (web_launch.options):
{"gpu_raster": false} turns GPU raster off, {"direct_frames": false} relays frames.
"""
import argparse
import json
import mmap
import os
import select
import socket
import time

WIDTH, HEIGHT = 1080, 2058
BYTES = 1080 * 2400 * 4  # a slot holds a whole screen (full screen video, 2026-11-20)
LAUNCH = '/opt/a22x-recovery/web_launch.py'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('url')
    parser.add_argument('--seconds', type=float, default=20)
    parser.add_argument('--relay', action='store_true', help='no frame socket of the UI: the session relays')
    parser.add_argument('--copy', action='store_true', help='copy every frame once, as the UI does')
    parser.add_argument('--launch', default=LAUNCH)
    args = parser.parse_args()

    frame_fd = os.memfd_create('browser-frame', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.ftruncate(frame_fd, BYTES * 2)
    shared = mmap.mmap(frame_fd, BYTES * 2, prot=mmap.PROT_READ)
    target = bytearray(BYTES) if args.copy else None
    ui, child_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    frames_ui, frames_child = (None, None) if args.relay else socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    start = time.monotonic()
    pid = os.fork()
    if pid == 0:
        try:
            keep = [os.dup(fd) for fd in (child_end.fileno(), frame_fd)]
            direct = os.dup(frames_child.fileno()) if frames_child else None
            os.dup2(keep[0], 0)
            os.dup2(keep[1], 5)
            if direct is not None:
                os.dup2(direct, 6)
            os.closerange(3, 5)
            os.closerange(7 if direct is not None else 6, 65536)
            os.execv('/usr/bin/python3', ['python3', '-B', args.launch])
        finally:
            os._exit(127)
    child_end.close()
    os.close(frame_fd)
    if frames_child:
        frames_child.close()

    state = {'slot': None, 'source': None, 'mode': None}
    stamps, notes = [], []

    def take(sock, message):
        if message[:1] != b'F':
            return False
        stamps.append(time.monotonic())
        if message == b'F':
            state['mode'] = 'screencast'
            sock.send(b'A')
        else:
            state['mode'] = 'relay' if sock is ui else 'direct'
            slot = message[1:2]
            if state['slot'] is not None and (state['slot'] != slot or state['source'] is not sock):
                state['source'].send(b'A' + state['slot'])
            state['slot'], state['source'] = slot, sock
            if target is not None:
                at = (message[1] - 48) * BYTES
                target[:] = shared[at:at + BYTES]
        return True

    sources = [ui] + ([frames_ui] if frames_ui else [])

    def pump(timeout):
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return True
            ready, _, _ = select.select(sources, [], [], left)
            for sock in ready:
                try:
                    message = sock.recv(2200)
                except OSError:
                    message = b''
                if not message:
                    if sock is ui:
                        return False
                    # The session closes the frame socket when it does not use it.
                    sources.remove(sock)
                    sock.close()
                    continue
                if not take(sock, message):
                    notes.append((round(time.monotonic() - start, 1), message[:60].decode('utf-8', 'replace')))

    while not any(note[1] == 'SReady' for note in notes):
        if not pump(1) or time.monotonic() - start > 180:
            break
    ui.send(b'N' + args.url.encode())
    opened = time.monotonic()
    while time.monotonic() - opened < 45:
        if not pump(0.5):
            break
        if any(note[1] == 'L0' for note in notes if note[0] > opened - start):
            break
    pump(3)
    stamps.clear()
    began = time.monotonic()
    while time.monotonic() - began < args.seconds:
        y = 470
        ui.send(b'D180 %d' % y)
        while y > 110 and time.monotonic() - began < args.seconds:
            tick = time.monotonic()
            y -= 6
            ui.send(b'M180 %d' % y)
            pump(max(0.0, 1 / 90 - (time.monotonic() - tick)))
        ui.send(b'E')
        pump(0.15)
    elapsed = time.monotonic() - began
    stamps = [s for s in stamps if s < began + elapsed]  # what came while scrolling
    ui.close()
    os.waitpid(pid, 0)
    gaps = sorted(b - a for a, b in zip(stamps, stamps[1:]))
    seconds = int(args.seconds)
    print(json.dumps({
        'mode': state['mode'], 'frames': len(stamps), 'fps': round(len(stamps) / elapsed, 1) if elapsed else 0,
        'per_second': [sum(1 for s in stamps if began + i <= s < began + i + 1) for i in range(seconds)],
        'p50_gap_ms': round(gaps[len(gaps) // 2] * 1000, 1) if gaps else None,
        'p95_gap_ms': round(gaps[int(len(gaps) * 0.95)] * 1000, 1) if gaps else None,
        'worst_gap_ms': round(gaps[-1] * 1000, 1) if gaps else None,
        'copy': bool(args.copy), 'notes': notes[-6:]}))


if __name__ == '__main__':
    main()
