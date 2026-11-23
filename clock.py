#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""The clock from the internet (2026-11-10).

Samsung's Android keeps the hardware clock in its own form: after it ran, this kernel read the year
2086 (60 years ahead), the screen showed a wrong date and every certificate failed as expired.
When Wi-Fi gives an address, the time comes from a time server (SNTP, as phones ask NTP), so the
screen shows the exact time and downloads work; the hardware clock is left alone.

    clock.py sync     the clock set from the first time server that answers
    clock.py hardware the clock set at start-up from the hardware clock in Android's form

2026-11-19: the form is known now, so the date is right without Wi-Fi too. Samsung's Android stores
the year as year - 1968 (58 for 2026). This kernel's mt6397 driver reads a register below 68 as
1900 + r and moves it into its 128-year window by 46751 days, hence 2086 and one day early.
"""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time

FLOOR = 1793491200  # 2026-11-01 UTC: a clock before it fails every certificate.
CEILING = 2524608000  # 2050-01-01 UTC: a clock beyond it is as wrong (Android's hardware clock form).
SERVERS = ('time.cloudflare.com', 'time.google.com', 'pool.ntp.org')
NTP_EPOCH = 2208988800  # 1900-01-01 to 1970-01-01
STATE = Path('/run/a22x-recovery/clock.json')


def plausible(now=None):
    """Whether the clock can be right: between FLOOR and CEILING."""
    now = time.time() if now is None else now
    return FLOOR <= now < CEILING


def ask(host, port=123, timeout=3.0):
    """The offset (seconds) that makes this clock the server's, half the round trip included."""
    address = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    # 2026-11-13 review: any datagram to the port was taken for the answer, so anyone on the same
    # Wi-Fi could set this clock, and with it what certificates count as valid. The socket now takes
    # only the server's address, and the answer must echo the random transmit time of the request.
    nonce = os.urandom(8)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(timeout)
        udp.connect(address)
        sent = time.time()
        udp.send(b'\x23' + bytes(39) + nonce)  # leap 0, version 4, mode 3 (client); transmit = nonce
        reply = udp.recv(512)
        received = time.time()
    if len(reply) < 48 or reply[0] & 7 != 4 or not 1 <= reply[1] <= 15 or reply[24:32] != nonce:
        raise ValueError('not a time server reply')
    seconds, fraction = struct.unpack('!II', reply[40:48])
    server = seconds - NTP_EPOCH + fraction / 2 ** 32
    return server + (received - sent) / 2 - received


ANDROID_FORM_SHIFT = timedelta(days=46751)  # 1900-01-01 to 2028-01-01, the driver's window move


def from_android_form(now):
    """The real time for a kernel clock read from a hardware clock Android wrote, or None when the
    kernel time does not come from that form (any year outside 2028..2095 as read)."""
    read = datetime.fromtimestamp(now, timezone.utc)
    if not 2028 <= read.year < 2096:
        return None
    register = read - ANDROID_FORM_SHIFT  # 1900 + r, the date the driver started from
    try:
        real = register.replace(year=register.year + 68)  # 1968 + r; both years agree on leap days
    except ValueError:
        return None
    value = real.timestamp()
    return value if plausible(value) else None


def from_hardware(set_clock=True, now=None):
    """At start-up: a clock read from Android's hardware form is set to the time it means."""
    now = time.time() if now is None else now
    if plausible(now):
        return {'set': False, 'reason': 'plausible'}
    value = from_android_form(now)
    if value is None:
        return {'set': False, 'reason': 'unknown form'}
    if set_clock:
        time.clock_settime(time.CLOCK_REALTIME, value + (time.time() - now))
    return {'set': True, 'utc': int(value)}


def sync(servers=SERVERS, set_clock=True, state=STATE):
    """The clock set from the first server that answers with a plausible time:
    {'synced': True, 'offset': seconds, 'server': host}, or {'synced': False}."""
    for server in servers:
        host, _, port = server.partition(':') if server.count(':') == 1 else (server, '', '')
        try:
            offset = ask(host, int(port or 123))
        except (OSError, ValueError, struct.error):
            continue
        if not plausible(time.time() + offset):
            continue
        if set_clock and abs(offset) > 0.5:
            time.clock_settime(time.CLOCK_REALTIME, time.time() + offset)
        result = {'synced': True, 'offset': round(offset, 3), 'server': host, 'utc': int(time.time())}
        if state:
            try:
                state.parent.mkdir(parents=True, exist_ok=True)
                state.write_text(json.dumps(result) + '\n')
            except OSError:
                pass
        return result
    return {'synced': False}


def ensure(mode='device'):
    """Before HTTPS: a clock that cannot be right is set from a time server."""
    if mode != 'fixture' and not plausible():
        sync()


def sync_in_background():
    """After Wi-Fi joins: the time asked in a process of its own, so joining does not wait for it."""
    try:
        import subprocess
        subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve()), 'sync'], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    except OSError:
        pass


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ['hardware']:
        result = from_hardware()
        print(json.dumps(result), flush=True)
        return 0 if result['set'] else 1
    if argv[:1] != ['sync']:
        print('usage: clock.py sync | hardware', file=sys.stderr)
        return 64
    result = sync()
    print(json.dumps(result), flush=True)
    return 0 if result['synced'] else 1


if __name__ == '__main__':
    sys.exit(main())
