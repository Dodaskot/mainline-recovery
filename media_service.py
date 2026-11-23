#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""The recovery's media and Bluetooth service (2026-11-22, the owner: a player for local music and video,
and Bluetooth: headphones, keyboards and mice).

What it runs comes from two layers web_cache.py downloads and checks: the browser's engine (Alpine's
FFmpeg, ALSA, D-Bus and GLib libraries are already there) and the media layer (media_packages.json:
BlueZ, the D-Bus daemon, BlueALSA, libswscale). They are joined read-only under a small RAM layer at
ROOT, and the daemons run in it with chroot: dbus-daemon, bluetoothd, bluealsa (sound to Bluetooth
headphones) and a22x-media (the player, /opt/a22x-recovery/a22x-media). Nothing of a card is mounted
there: the interface opens a file to play and hands its descriptor to the player.

Bluetooth's kernel part is the image's own modules (bt-modules/RELEASE-BUILD: bluetooth, rfcomm, hidp
and btmtk_stp, the HCI driver of the MT6833's combo chip behind its WMT/STP stack); its public address
is read from nvdata (APCFG/APRDEB/BT_Addr) without mounting it.

Backups, restores and flashing come first: the player decodes at nice 10 and idle I/O priority, the
daemons at nice 5.

The interface speaks to it on SOCKET, one JSON object a line:
  {"op":"status"} {"op":"bt-power","on":true} {"op":"bt-scan","on":true}
  {"op":"bt-pair"|"bt-connect"|"bt-disconnect"|"bt-remove","address":"AA:..."}
  {"op":"bt-answer","accept":true}            the answer to a pairing question
and is told {"event":"state",...} whenever something changes, {"event":"pairing",...} when a device asks.

    media_service.py serve
"""
import contextlib
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time

import dbus_min
import sound
import web_cache

HERE = Path(__file__).resolve().parent
RUN = Path('/run/a22x-recovery/media')
ROOT = RUN / 'root'
SOCKET = Path('/run/a22x-recovery/media.sock')
PID_FILE = Path('/run/a22x-recovery/media.pid')
PLAYER_SOCKET = RUN / 'run/a22x-media.sock'
MANIFEST = HERE / 'media_packages.json'
FULL_MANIFEST = HERE / 'media_full_packages.json'
PLAYER = HERE / 'a22x-media'
MODULES = HERE / 'bt-modules'
ASOUNDRC = Path('/run/a22x-recovery/sound/asoundrc')
# BlueALSA's own policy lets root and the group audio use it; the browser's user (nobody) plays to the
# headphones through BlueALSA's ALSA plugin, so it may call BlueALSA, and nothing else that root's is.
BROWSER_SOUND_POLICY = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="nobody">
    <allow send_destination="org.bluealsa"/>
  </policy>
</busconfig>
"""
BLUEZ = 'org.bluez'
INSMOD = ['/bin/busybox', 'insmod']
AGENT = '/a22x/agent'
KINDS = {'audio-headphones': 'audio', 'audio-headset': 'audio', 'audio-card': 'audio', 'audio-speakers': 'audio',
         'input-keyboard': 'keyboard', 'input-mouse': 'mouse', 'input-tablet': 'mouse', 'input-gaming': 'other',
         'phone': 'phone', 'computer': 'other'}
# Profiles of a device that says no Icon (2026-11-22, live: Sennheiser MOMENTUM 4 gives BlueZ neither Icon
# nor Class, only its UUIDs; as "other" it was neither taken for the sound nor listed as an output).
AUDIO_UUIDS = frozenset(('0000110b-0000-1000-8000-00805f9b34fb',   # Audio Sink (A2DP)
                         '00001108-0000-1000-8000-00805f9b34fb',   # Headset (HSP)
                         '0000111e-0000-1000-8000-00805f9b34fb'))  # Handsfree (HFP)
HID_UUIDS = frozenset(('00001124-0000-1000-8000-00805f9b34fb',     # HID (BR/EDR)
                       '00001812-0000-1000-8000-00805f9b34fb'))    # HID over GATT (LE)


# LE on the 1M PHY only (2026-11-22, live: a Logitech POP Icon Keys keyboard failed three times at
# its connection, HCI LE_ExtCreateConnection initiating on 1M, 2M and Coded, the link up and torn down
# 0.3 s later with 0x3e "connection failed to be established"; restricted to 1M it paired at the first
# attempt, in the same place). The kernel offers every PHY again at each power on, so this follows it.
MGMT_GET_PHY, MGMT_SET_PHY = 0x0044, 0x0045
PHY_LE_1M = (1 << 9) | (1 << 10)
PHY_LE_OTHER = (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14)   # 2M and Coded, TX and RX


def le_phy_selection(selected, configurable):
    """The PHYs to select for LE on 1M only, or None when that is the selection already."""
    want = (selected & ~(PHY_LE_OTHER & configurable)) | (PHY_LE_1M & configurable)
    return None if want == selected else want


def limit_le_phy(index=0):
    """Through the kernel's management socket (as btmgmt phy). Returns what was done, for the log."""
    s = socket.socket(31, socket.SOCK_RAW | socket.SOCK_CLOEXEC, 1)   # AF_BLUETOOTH, BTPROTO_HCI
    try:
        address = struct.pack('<HHH', 31, 0xFFFF, 3)                    # HCI_DEV_NONE, HCI_CHANNEL_CONTROL
        if libc.bind(s.fileno(), ctypes.c_char_p(address), len(address)) != 0:
            return 'bind failed: errno %d' % ctypes.get_errno()
        s.settimeout(2.0)

        def mgmt(op, params=b''):
            s.send(struct.pack('<HHH', op, index, len(params)) + params)
            end = time.monotonic() + 3
            while time.monotonic() < end:
                data = s.recv(512)
                event, _, length = struct.unpack_from('<HHH', data)
                if event in (1, 2) and len(data) >= 9 and struct.unpack_from('<H', data, 6)[0] == op:
                    return data[8], data[9:6 + length]
            raise TimeoutError(hex(op))

        status, data = mgmt(MGMT_GET_PHY)
        if status or len(data) < 12:
            return 'phy configuration not read (status %d)' % status
        _, configurable, selected = struct.unpack_from('<III', data)
        want = le_phy_selection(selected, configurable)
        if want is None:
            return ''
        status, _ = mgmt(MGMT_SET_PHY, struct.pack('<I', want))
        return 'LE on 1M only (%#06x -> %#06x, status %d)' % (selected, want, status)
    except (OSError, TimeoutError) as error:
        return 'phy configuration: %s' % error
    finally:
        s.close()


def device_kind(properties):
    """What a device is: its Icon when it names one, else what its profiles say."""
    kind = KINDS.get(properties.get('Icon', ''))
    if kind:
        return kind
    uuids = {str(u).lower() for u in properties.get('UUIDs') or ()}
    if uuids & AUDIO_UUIDS:
        return 'audio'
    if uuids & HID_UUIDS:
        return 'keyboard'
    return 'other'


libc = ctypes.CDLL(None, use_errno=True)


def log(*args):
    print('[media-service]', *args, file=sys.stderr, flush=True)


def mount(*args):
    subprocess.run(['/bin/mount', *map(str, args)], check=True)


def mounted(path):
    return any(line.split()[4] == str(path) for line in Path('/proc/self/mountinfo').read_text().splitlines())


# --- the runtime ------------------------------------------------------------------------------------------
def engine_preparing():
    """The engine's background preparation (web_cache.prefetch, after Wi-Fi joins) holds the cache lock."""
    try:
        with (web_cache.CACHE.parent / 'web-cache.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lock, fcntl.LOCK_UN)
            return False
    except BlockingIOError:
        return True
    except OSError:
        return False


def layers():
    """The trees the player and Bluetooth run in: over the browser's engine when it is in RAM already
    (a small layer of 19 MB), otherwise a layer of their own (about 108 MB) instead of a whole Chromium
    (about 460 MB) only for FFmpeg and ALSA (2026-11-22, measured on the phone). The engine comes into
    RAM by itself after Wi-Fi joins; while that is under way it is waited for: started a minute after
    the restart, Bluetooth had taken its own layer and both stayed in RAM."""
    engine = web_cache.cached(web_cache.MANIFEST)
    if not engine and FULL_MANIFEST.is_file() and engine_preparing():
        web_cache.notify('Waiting for the web engine...')
        engine = web_cache.ensure()
    if engine or not FULL_MANIFEST.is_file():
        engine = engine or web_cache.ensure()
        return [web_cache.ensure(manifest=MANIFEST, label='Player and Bluetooth'), engine]
    return [web_cache.ensure(manifest=FULL_MANIFEST, label='Player and Bluetooth')]


def prepare_root():
    """ROOT: the engine and the media layer under a RAM layer, with the system's /proc, /sys and /dev."""
    if mounted(ROOT):
        return
    lower = ':'.join(str(layer) for layer in layers())
    for d in (RUN, ROOT, RUN / 'upper', RUN / 'work', RUN / 'run'):
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not mounted(RUN):
        mount('-t', 'tmpfs', '-o', 'size=48m,mode=0700', 'tmpfs', RUN)
        for d in (ROOT, RUN / 'upper', RUN / 'work', RUN / 'run'):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
    mount('-t', 'overlay', '-o', f'lowerdir={lower},upperdir={RUN}/upper,workdir={RUN}/work', 'overlay', ROOT)
    for name in ('proc', 'sys', 'dev', 'run', 'tmp', 'etc', 'var/lib/bluetooth', 'opt'):
        (ROOT / name).mkdir(parents=True, exist_ok=True)
    mount('-t', 'proc', 'proc', ROOT / 'proc')
    mount('--rbind', '/sys', ROOT / 'sys')
    mount('--rbind', '/dev', ROOT / 'dev')
    mount('--bind', RUN / 'run', ROOT / 'run')
    (RUN / 'run/dbus').mkdir(exist_ok=True)
    # The browser (nobody, web_launch) reaches the bus for its sound to Bluetooth (2026-11-22): the
    # folder opens to it, and the bus lets it speak to BlueALSA only (BROWSER_SOUND_POLICY).
    (RUN / 'run/dbus').chmod(0o755)
    (ROOT / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\nmessagebus:x:100:101:messagebus:/run/dbus:/sbin/nologin\n'
                                     'nobody:x:65534:65534:nobody:/:/sbin/nologin\n')
    (ROOT / 'etc/group').write_text('root:x:0:\nmessagebus:x:101:\naudio:x:18:\nbluetooth:x:102:\nnobody:x:65534:\n')
    (ROOT / 'etc/dbus-1').mkdir(exist_ok=True)
    (ROOT / 'etc/dbus-1/system-local.conf').write_text(BROWSER_SOUND_POLICY)
    (ROOT / 'etc/bluetooth').mkdir(exist_ok=True)
    # The recovery's name for others; pairing keys stay in RAM until the recovery restarts.
    (ROOT / 'etc/bluetooth/main.conf').write_text('[General]\nName = Mainline Recovery\nClass = 0x5a020c\n'
                                                  'JustWorksRepairing = always\n[Policy]\nAutoEnable=true\n')
    # The player's own copy: the phone's chain for the jack's state now, without the browser's switch.
    try:
        alsa = sound.asoundrc(sound.state().get('output', 'speaker'))
    except (OSError, ValueError):
        alsa = 'pcm.!default { type hw card 0 }\n'
    (ROOT / 'etc/a22x-alsa.conf').write_text(alsa)
    if PLAYER.is_file():
        (ROOT / 'opt/a22x-media').write_bytes(PLAYER.read_bytes())
        (ROOT / 'opt/a22x-media').chmod(0o755)


def module_folder():
    release = os.uname().release
    build = re.match(r'#(\d+)', os.uname().version)
    folder = MODULES / f"{release}-{build.group(1) if build else ''}"
    return folder if folder.is_dir() else None


def bdaddr():
    """The phone's public Bluetooth address from nvdata, as the stock system takes it."""
    try:
        data = subprocess.run(['/usr/sbin/debugfs', '-R', 'cat /APCFG/APRDEB/BT_Addr', '/dev/block/by-name/nvdata'],
                              capture_output=True, timeout=20).stdout[:6]
    except (OSError, subprocess.SubprocessError):
        return None
    if len(data) != 6 or data[0] & 1 or data in (bytes(6), b'\xff' * 6):
        return None
    return ':'.join('%02X' % b for b in data)


def load_modules():
    """Bluetooth's kernel modules. Returns a reason when Bluetooth cannot come up."""
    if Path('/sys/class/bluetooth/hci0').exists():
        return None
    folder = module_folder()
    if folder is None:
        return 'This recovery has no Bluetooth modules for its kernel'
    if not Path('/sys/module/wmt_drv').exists():
        return 'Bluetooth needs the Wi-Fi chip, which did not start'
    loaded = Path('/proc/modules').read_text()
    # The recovery's insmod is busybox's, in /bin (2026-11-22, on the phone: /sbin/insmod is not there).
    for name in ('bluetooth', 'rfcomm', 'hidp'):
        if f'{name} ' not in loaded:
            done = subprocess.run(INSMOD + [str(folder / f'{name}.ko')], capture_output=True, timeout=30)
            if done.returncode:
                log('insmod', name, done.stderr.decode(errors='replace').strip()[:200])
    address = bdaddr()
    args = INSMOD + [str(folder / 'btmtk_stp.ko')] + ([f'bdaddr={address}'] if address else [])
    if 'btmtk_stp ' not in loaded:
        done = subprocess.run(args, capture_output=True, timeout=30)
        if done.returncode:
            log('insmod btmtk_stp', done.stderr.decode(errors='replace').strip()[:200])
    for _ in range(30):
        if Path('/sys/class/bluetooth/hci0').exists():
            return None if address else 'The phone\'s Bluetooth address could not be read'
        time.sleep(0.1)
    return 'The Bluetooth chip did not start'


def lowered(nice, idle_io):
    def setup():
        os.setsid()
        os.nice(nice)
        if idle_io:
            libc.syscall(30, 1, 0, 3 << 13)   # ioprio_set(IOPRIO_WHO_PROCESS, self, IOPRIO_CLASS_IDLE)
        os.chroot(ROOT)
        os.chdir('/')
    return setup


def start(argv, nice=5, idle_io=False, env=None):
    log('start', argv[0])
    return subprocess.Popen(argv, preexec_fn=lowered(nice, idle_io), stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=open(RUN / (Path(argv[0]).name + '.log'), 'ab'),
                            env=env or {'PATH': '/usr/bin:/usr/sbin:/bin:/sbin'})


# --- Bluetooth -------------------------------------------------------------------------------------------
class Bluetooth:
    def __init__(self, service):
        self.service = service
        self.bus = None
        self.devices = {}         # path -> properties
        self.batteries = {}       # path -> percent
        self.adapter = {}
        self.pending = {}         # serial -> (what, address)
        self.question = None      # (call message, kind) waiting for the owner's answer

    def connect(self):
        sock = RUN / 'run/dbus/system_bus_socket'
        for _ in range(50):
            if sock.exists():
                break
            time.sleep(0.1)
        self.bus = dbus_min.Bus(str(sock))
        self.bus.handlers[AGENT] = self.agent_call
        self.bus.match("type='signal',sender='org.bluez'")
        for _ in range(50):
            try:
                objects = self.bus.call(BLUEZ, '/', 'org.freedesktop.DBus.ObjectManager', 'GetManagedObjects')[0]
                break
            except dbus_min.DBusError:
                time.sleep(0.1)
        else:
            raise RuntimeError('BlueZ did not start')
        for path, interfaces in objects.items():
            self.added(path, interfaces)
        if self.adapter.get('Powered'):
            self.powered()
        self.bus.call(BLUEZ, '/org/bluez', 'org.bluez.AgentManager1', 'RegisterAgent', 'os', (AGENT, 'KeyboardDisplay'))
        self.bus.call(BLUEZ, '/org/bluez', 'org.bluez.AgentManager1', 'RequestDefaultAgent', 'o', (AGENT,))
        try:
            self.bus.set(BLUEZ, '/org/bluez/hci0', 'org.bluez.Adapter1', 'Pairable', 'b', True)
        except dbus_min.DBusError:
            pass

    def powered(self):
        done = limit_le_phy()
        if done:
            log('bluetooth', done)

    def added(self, path, interfaces):
        if 'org.bluez.Adapter1' in interfaces:
            self.adapter.update(interfaces['org.bluez.Adapter1'])
        if 'org.bluez.Device1' in interfaces:
            self.devices.setdefault(path, {}).update(interfaces['org.bluez.Device1'])
        if 'org.bluez.Battery1' in interfaces:
            self.batteries[path] = interfaces['org.bluez.Battery1'].get('Percentage', -1)

    def signal(self, message):
        member, path = message.fields.get('member'), message.fields.get('path', '')
        if member == 'InterfacesAdded':
            self.added(message.body[0], message.body[1])
        elif member == 'InterfacesRemoved':
            if 'org.bluez.Device1' in message.body[1]:
                self.devices.pop(message.body[0], None)
                self.service.pairings_due = time.monotonic() + 2   # a device forgotten
            self.batteries.pop(message.body[0], None)
        elif member == 'PropertiesChanged':
            interface, changed = message.body[0], message.body[1]
            if interface == 'org.bluez.Adapter1':
                self.adapter.update(changed)
                if changed.get('Powered'):
                    self.powered()
            elif interface == 'org.bluez.Device1':
                self.devices.setdefault(path, {}).update(changed)
                # BlueZ writes the keys of a pairing as it ends; they are kept a moment later.
                if any(key in changed for key in ('Paired', 'Bonded', 'Trusted', 'Blocked')):
                    self.service.pairings_due = time.monotonic() + 2
            elif interface == 'org.bluez.Battery1' and 'Percentage' in changed:
                self.batteries[path] = changed['Percentage']
        self.service.changed = True

    def state(self):
        rows = []
        for path, p in self.devices.items():
            if not p.get('Address'):
                continue
            rows.append({'address': p['Address'], 'name': p.get('Alias') or p.get('Name') or p['Address'],
                         'kind': device_kind(p), 'paired': bool(p.get('Paired')),
                         'connected': bool(p.get('Connected')), 'trusted': bool(p.get('Trusted')),
                         'battery': self.batteries.get(path, -1), 'rssi': p.get('RSSI', -999),
                         'named': bool(p.get('Name'))})
        # Connected first, then paired, then the ones heard best.
        rows.sort(key=lambda r: (not r['connected'], not r['paired'], not r['named'], -r['rssi']))
        # The state the adapter goes to while it changes (BlueZ's PowerState; 2026-11-22, the owner's video:
        # turned on, the switch went on, back off while the adapter was still powering, then on again).
        power = self.adapter.get('PowerState')
        powered = power in ('on', 'off-enabling') if power else bool(self.adapter.get('Powered'))
        return {'powered': powered, 'scanning': bool(self.adapter.get('Discovering')),
                'devices': rows[:24]}

    def path(self, address):
        for path, p in self.devices.items():
            if p.get('Address') == address:
                return path
        raise RuntimeError('This device is no longer in range')

    def call_async(self, what, address, path, interface, member, signature='', args=()):
        serial = self.bus.send(dbus_min.METHOD_CALL, {'path': path, 'interface': interface, 'member': member,
                                                      'destination': BLUEZ}, signature, args)
        self.pending[serial] = (what, address)

    def command(self, op, request):
        adapter = '/org/bluez/hci0'
        if op == 'bt-power':
            self.bus.set(BLUEZ, adapter, 'org.bluez.Adapter1', 'Powered', 'b', bool(request.get('on')))
        elif op == 'bt-scan':
            if request.get('on'):
                try:
                    self.bus.call(BLUEZ, adapter, 'org.bluez.Adapter1', 'SetDiscoveryFilter', 'a{sv}',
                                  ({'Transport': dbus_min.Variant('s', 'auto')},))
                except dbus_min.DBusError:
                    pass
                self.call_async('scan', '', adapter, 'org.bluez.Adapter1', 'StartDiscovery')
            else:
                self.call_async('scan-stop', '', adapter, 'org.bluez.Adapter1', 'StopDiscovery')
        elif op in ('bt-pair', 'bt-connect', 'bt-disconnect'):
            address = request['address']
            path = self.path(address)
            member = {'bt-pair': 'Pair', 'bt-connect': 'Connect', 'bt-disconnect': 'Disconnect'}[op]
            if op == 'bt-pair' and self.devices[path].get('Paired'):
                member, op = 'Connect', 'bt-connect'
            self.call_async(op[3:], address, path, 'org.bluez.Device1', member)
        elif op == 'bt-remove':
            self.bus.call(BLUEZ, adapter, 'org.bluez.Adapter1', 'RemoveDevice', 'o', (self.path(request['address']),))
        elif op == 'bt-answer' and self.question:
            call, kind = self.question
            self.question = None
            if request.get('accept'):
                self.bus.reply(call)
            else:
                self.bus.error(call, 'org.bluez.Error.Rejected')

    def finished(self, message):
        what, address = self.pending.pop(message.fields.get('reply'), (None, None))
        if what is None:
            return
        if what == 'pair':
            # The pairing has ended, done or not: its number is no longer asked for (2026-11-22, the owner:
            # the keyboard's number stayed on the screen, "Waiting...", after the keyboard was paired).
            self.question = None
            self.service.tell({'event': 'pairing', 'kind': 'none'})
        if message.kind == dbus_min.ERROR:
            name = message.fields.get('error', '')
            text = {'org.bluez.Error.AuthenticationFailed': 'The device refused the pairing',
                    'org.bluez.Error.AuthenticationCanceled': 'The pairing was cancelled',
                    'org.bluez.Error.ConnectionAttemptFailed': 'The device did not answer',
                    'org.bluez.Error.InProgress': None, 'org.bluez.Error.AlreadyExists': None}.get(name, 'Bluetooth: ' + name.split('.')[-1])
            if text:
                self.service.tell({'event': 'error', 'message': text, 'address': address})
        elif what == 'pair':
            # Paired: trusted, so it may come back by itself, then connected.
            try:
                self.bus.set(BLUEZ, self.path(address), 'org.bluez.Device1', 'Trusted', 'b', True)
            except (dbus_min.DBusError, RuntimeError):
                pass
            self.call_async('connect', address, self.path(address), 'org.bluez.Device1', 'Connect')
        self.service.changed = True

    def agent_call(self, call):
        """org.bluez.Agent1: numbers to compare or to type on a keyboard go to the interface."""
        member, body = call.fields.get('member'), call.body
        device = self.devices.get(body[0], {}) if body else {}
        name = device.get('Alias') or device.get('Name') or device.get('Address', '')
        address = device.get('Address', '')
        if member == 'RequestConfirmation':
            self.question = (call, 'confirm')
            self.service.tell({'event': 'pairing', 'kind': 'confirm', 'name': name, 'address': address,
                               'passkey': '%06u' % body[1]})
        elif member == 'DisplayPasskey':
            self.service.tell({'event': 'pairing', 'kind': 'type', 'name': name, 'address': address,
                               'passkey': '%06u' % body[1], 'entered': body[2]})
            self.bus.reply(call)
        elif member == 'DisplayPinCode':
            self.service.tell({'event': 'pairing', 'kind': 'type', 'name': name, 'address': address, 'passkey': body[1]})
            self.bus.reply(call)
        elif member == 'RequestPinCode':
            self.service.tell({'event': 'pairing', 'kind': 'type', 'name': name, 'address': address, 'passkey': '0000'})
            self.bus.reply(call, 's', ('0000',))
        elif member == 'RequestPasskey':
            self.bus.reply(call, 'u', (0,))
        elif member in ('RequestAuthorization', 'AuthorizeService', 'Release'):
            self.bus.reply(call)
        elif member == 'Cancel':
            self.question = None
            self.service.tell({'event': 'pairing', 'kind': 'none'})
            self.bus.reply(call)
        else:
            self.bus.error(call, 'org.bluez.Error.Rejected')

    def pump(self):
        while True:
            message = self.bus.read(block=False)
            if message is None:
                return
            if message.kind == dbus_min.SIGNAL:
                self.signal(message)
            elif message.kind == dbus_min.METHOD_CALL:
                self.bus.dispatch(message)
            else:
                self.finished(message)


# --- the service ------------------------------------------------------------------------------------------
def restore_pairings():
    """The pairings kept in misc, back into ROOT before bluetoothd starts (bt_pairings.py). Returns the
    record read, which a save compares with: None when there is none or it cannot be read now."""
    import bt_pairings
    import misc_store
    try:
        data = misc_store.read('pairings')
    except (OSError, ValueError) as error:  # misc_store.Damaged is a ValueError
        log('bluetooth pairings not read:', type(error).__name__)
        return None
    if data:
        try:
            log('bluetooth pairings restored:', bt_pairings.restore(ROOT, data))
        except (OSError, ValueError) as error:
            log('bluetooth pairings not restored:', type(error).__name__)
    return data


def save_pairings(saved):
    """ROOT's pairings into misc when they changed since SAVED (the record last read or written), under
    the lock the settings and the Wi-Fi list are saved with. Returns (the record now kept, whether this
    is done; False: to be tried again, the lock taken or misc not written now)."""
    import bt_pairings
    import misc_store
    payload = bt_pairings.snapshot(ROOT, misc_store.payload_max('pairings'))
    if payload == saved or (saved is None and not json.loads(payload)['files']):
        return saved, True
    import filesystem as fs
    from operation_lock import lease
    context = fs.DeviceContext()
    try:
        with lease(context.lock_path, context.mode):
            misc_store.write('pairings', payload)
    except BlockingIOError:
        return saved, False
    except misc_store.Foreign:
        log('bluetooth pairings not saved: misc holds another program\'s bytes there')
        return payload, True
    except (OSError, ValueError) as error:
        log('bluetooth pairings not saved:', type(error).__name__)
        return saved, False
    log('bluetooth pairings saved:', sum(name.endswith('/info') for name in json.loads(payload)['files']))
    return payload, True


class Service:
    def __init__(self):
        self.clients = []
        self.changed = True
        self.reason = None
        self.bt = None
        self.processes = {}
        self.pairings = None        # the record of pairings in misc, as last read or written
        self.pairings_due = 0.0     # when to save them: a while after a pairing changed

    def stop(self):
        """What start() began, ended: a daemon left behind would keep its socket for the next start."""
        self.bt = None
        for name, process in list(self.processes.items()):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
            self.processes.pop(name, None)
        (RUN / 'run/dbus/system_bus_socket').unlink(missing_ok=True)

    def tell(self, event):
        line = (json.dumps(event, separators=(',', ':')) + '\n').encode()
        for client in list(self.clients):
            try:
                client.sendall(line)
            except OSError:
                self.clients.remove(client)
                client.close()

    def state(self):
        bt = self.bt.state() if self.bt else {'powered': False, 'scanning': False, 'devices': []}
        return {'event': 'state', 'available': self.bt is not None, 'reason': self.reason,
                'player': PLAYER_SOCKET.exists(), 'player_socket': str(PLAYER_SOCKET), 'bt': bt}

    def start(self):
        # web_cache tells its progress on fd 0, the browser's control socket; here it goes to the interface.
        web_cache.notify = lambda message: (log(message), self.tell({'event': 'progress', 'message': message}))
        prepare_root()
        self.pairings = restore_pairings()
        (RUN / 'run/dbus/system_bus_socket').unlink(missing_ok=True)  # of a service that stopped hard
        dbus = start(['/usr/bin/dbus-daemon', '--system', '--nofork', '--nopidfile'])
        self.processes['dbus'] = dbus
        reason = load_modules()
        if Path('/sys/class/bluetooth/hci0').exists():
            self.processes['bluetoothd'] = start(['/usr/lib/bluetooth/bluetoothd', '-n'])
            self.processes['bluealsa'] = start(['/usr/bin/bluealsa', '-p', 'a2dp-source', '-p', 'hfp-ag', '-p', 'hsp-ag'])
            try:
                self.bt = Bluetooth(self)
                self.bt.connect()
            except (RuntimeError, OSError, dbus_min.DBusError) as error:
                self.bt, reason = None, str(error)
        self.reason = reason
        if (ROOT / 'opt/a22x-media').is_file():
            env = {'PATH': '/usr/bin', 'HOME': '/tmp',
                   'ALSA_CONFIG_PATH': '/etc/a22x-alsa.conf:/etc/alsa/conf.d/20-bluealsa.conf'}
            self.processes['player'] = start(['/opt/a22x-media', '/run/a22x-media.sock'], nice=10, idle_io=True, env=env)

    def request(self, client, line):
        try:
            request = json.loads(line)
            op = request.get('op')
            if op == 'status':
                self.changed = True
            elif op and op.startswith('bt-'):
                if not self.bt:
                    raise RuntimeError(self.reason or 'Bluetooth is not available')
                self.bt.command(op, request)
                self.changed = True
            elif op == 'sound-output':
                # Where the browser's sound goes (sound.py; 2026-11-22): the Bluetooth device the
                # interface chose (the player's output), or the phone with an empty address.
                address = str(request.get('bluetooth') or '').upper() or None
                sound.select_output(address)
                sound.save(bluetooth=address)
        except (ValueError, KeyError, RuntimeError, dbus_min.DBusError, OSError) as error:
            self.tell({'event': 'error', 'message': str(error)})

    def serve(self):
        SOCKET.unlink(missing_ok=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o077)
        server.bind(str(SOCKET))
        os.umask(old)
        server.listen(4)
        try:
            self.start()
        except Exception as error:  # noqa: BLE001 - every failure reaches the interface as a reason
            import traceback
            traceback.print_exc()
            self.reason = str(error) or type(error).__name__
            log('start failed:', self.reason)
            self.stop()
        buffers = {}
        last_state = 0.0
        while True:
            ready = [server] + self.clients + ([self.bt.bus] if self.bt else [])
            readable, _, _ = select.select(ready, [], [], 0.5)
            for item in readable:
                if item is server:
                    client, _ = server.accept()
                    self.clients.append(client)
                    buffers[client] = b''
                    self.changed = True
                elif self.bt and item is self.bt.bus:
                    try:
                        self.bt.pump()
                    except dbus_min.DBusError as error:
                        self.reason, self.bt = 'Bluetooth stopped: ' + str(error), None
                        self.changed = True
                else:
                    try:
                        data = item.recv(4096)
                    except OSError:  # a client gone without a goodbye (2026-11-22: it ended the service)
                        data = b''
                    if not data:
                        self.clients.remove(item)
                        buffers.pop(item, None)
                        item.close()
                        continue
                    buffers[item] += data
                    while b'\n' in buffers[item]:
                        line, buffers[item] = buffers[item].split(b'\n', 1)
                        self.request(item, line)
            for name, process in list(self.processes.items()):
                if process.poll() is not None:
                    log(name, 'ended with', process.returncode)
                    del self.processes[name]
                    self.changed = True
            if self.pairings_due and time.monotonic() >= self.pairings_due:
                self.pairings, done = save_pairings(self.pairings)
                self.pairings_due = 0.0 if done else time.monotonic() + 5
            if self.changed and time.monotonic() - last_state > 0.2:
                self.changed = False
                last_state = time.monotonic()
                self.tell(self.state())


def leftovers():
    """Processes still running in ROOT from a service that ended before it could stop them: its
    dbus-daemon, bluetoothd, bluealsa and player (2026-11-22, on the phone: three of each after the
    interface had started the service again)."""
    found = []
    for pid in os.listdir('/proc'):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            if os.readlink(f'/proc/{pid}/root') == str(ROOT):
                found.append(int(pid))
        except OSError:
            continue
    return found


def end_leftovers():
    pids = leftovers()
    for pid in pids:
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        if not leftovers():
            return
        time.sleep(0.1)
    for pid in leftovers():
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)


def main(argv):
    if argv[1:] != ['serve']:
        print(__doc__, file=sys.stderr)
        return 2
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    end_leftovers()
    service = Service()
    # For init: a power action ends the service before it unmounts storage (its player holds a file).
    PID_FILE.write_text(str(os.getpid()))
    try:
        service.serve()
    finally:
        service.stop()
        PID_FILE.unlink(missing_ok=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
