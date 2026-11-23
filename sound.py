#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Sound in the recovery: the speaker and the headphone jack (2026-11-20, the owner: sound with
the aux jack and a volume setting; a tester, #6: the browser had no audio).

The kernel's MT6833 sound (AFE, MT6359 codec, SIA8109 amplifier through aw8738, MT6359 jack
detection) comes as 11 modules beside this helper (sound-modules/RELEASE/*.ko), loaded in order.
The mixer is set the way the device's UCM profile does (mt6359-sia8109 HiFi), through the ALSA
control ioctls (no alsa-utils in the image):

  common     ADDA_DL_CH1 DL1_CH1, ADDA_DL_CH2 DL1_CH2 on; DAC In Mux = Normal Path
  speaker    LOL Mux = Playback_L_DAC, Lineout Volume 0, Speaker Switch on   (mono, left DAC)
  headphones HP Mux = Audio Playback, Headset Volume 10                      (when "Headphone Jack" is in)

The speaker's level is not a hardware control here (the SIA8109 lowers itself above about -10 dB
line level), so the volume is ALSA's softvol: a user control "Recovery Playback Volume" (0..255,
two channels) that the browser's ALSA configuration (asound_conf) plays through, kept at the level
set last (/run/a22x-recovery/sound.json).

    sound.py start                 modules, card, route for the jack's state
    sound.py route                 speaker or headphones again, for the jack's state now
    sound.py volume PERCENT        0..100
    sound.py status                one JSON line
    sound.py watch                 route again whenever the jack changes (stays running)
"""
import argparse
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
MODULES = ('soundcore', 'snd', 'snd-timer', 'snd-pcm', 'snd-soc-core', 'snd-soc-mtk-common', 'snd-soc-mt8192-afe',
           'snd-soc-mt6359', 'mt6359-accdet', 'snd-soc-aw8738', 'mt6833-mt6359')
STATE = Path('/run/a22x-recovery/sound.json')
# The browser's ALSA configuration, bound into its sandbox as ~/.asoundrc (web_launch). It is written
# in place, never replaced, so a bind made before a change of output follows it.
ASOUNDRC = Path('/run/a22x-recovery/sound/asoundrc')
# Where the browser's sound goes (2026-11-22, the owner: YouTube stayed on the speaker with Bluetooth
# headphones connected). Its "default" is the a22x_switch plugin (media/a22x_switch.c), which plays into
# the PCM this file names and moves its stream at once when the name changes: "a22x_phone" (the speaker
# or the jack, as below) or "a22x_bt:DEV=address" (BlueALSA). Written in place, like ASOUNDRC, and
# bound into the browser's sandbox read only (web_launch).
SELECT = Path('/run/a22x-recovery/sound/output')
SWITCH_PLUGIN = HERE / 'alsa' / 'libasound_module_pcm_a22x_switch.so'
# The folder in the browser's sandbox that web_launch fills with the plugins, and the bound file.
BROWSER_PLUGINS = '/tmp/a22x-sound'
BROWSER_SELECT = '/tmp/home/.a22x-output'
ADDRESS = re.compile(r'[0-9A-F]{2}(:[0-9A-F]{2}){5}')
CONTROL = '/dev/snd/controlC0'
VOLUME = 'Recovery Playback Volume'
LEVELS = 256  # softvol's default resolution

COMMON = (('ADDA_DL_CH1 DL1_CH1', 1), ('ADDA_DL_CH2 DL1_CH2', 1), ('DAC In Mux', 'Normal Path'),
          ('HP Mux', 'Open'), ('RCV Mux', 'Open'), ('LOL Mux', 'Open'), ('Speaker Switch', 0),
          ('Headphone Switch', 0))
SPEAKER = (('LOL Mux', 'Playback_L_DAC'), ('Lineout Volume', 0), ('Speaker Switch', 1))
HEADPHONES = (('HP Mux', 'Audio Playback'), ('Headset Volume', 10), ('Headphone Switch', 1))
JACK_INPUT = 'mt6833-mt6359 Headset Jack'
EV_SW = 5
JACK_SWITCHES = {2, 4, 6}  # SW_HEADPHONE_INSERT, SW_MICROPHONE_INSERT, SW_LINEOUT_INSERT

# ALSA control ioctls (include/uapi/sound/asound.h), for a 64-bit kernel.
ID = struct.Struct('<IiII44sI')            # numid, iface, device, subdevice, name, index: 64 bytes
INFO_SIZE, VALUE_SIZE, LIST_SIZE = 272, 1224, 80
TYPE_BOOLEAN, TYPE_INTEGER, TYPE_ENUMERATED = 1, 2, 3
IFACE_MIXER, IFACE_CARD = 2, 0
ACCESS_READ, ACCESS_WRITE, ACCESS_USER = 1, 2, 1 << 29
ACCESS_TLV_READ, ACCESS_TLV_WRITE = 0x10, 0x20
TLV_DB_SCALE = 1
MIN_DB, MAX_DB = -40.0, 0.0  # the softvol's min_dB and max_dB in asoundrc


def _iowr(nr, size):
    return (3 << 30) | (size << 16) | (ord('U') << 8) | nr


ELEM_LIST, ELEM_INFO, ELEM_READ, ELEM_WRITE, ELEM_ADD = (_iowr(0x10, LIST_SIZE), _iowr(0x11, INFO_SIZE),
                                                        _iowr(0x12, VALUE_SIZE), _iowr(0x13, VALUE_SIZE),
                                                        _iowr(0x17, INFO_SIZE))
ELEM_REMOVE, TLV_WRITE = _iowr(0x19, ID.size), _iowr(0x1b, 8)


def volume_tlv(levels=LEVELS):
    """The dB scale softvol gives its own control (alsa-lib pcm_softvol.c add_tlv_info): type, length,
    the lowest level in 1/100 dB and the step per level. The same bytes mean softvol leaves it as it is."""
    return struct.pack('<IIiI', TLV_DB_SCALE, 8, int(MIN_DB * 100), int((MAX_DB - MIN_DB) * 100 / (levels - 1)))


def elem_id(numid=0, iface=IFACE_MIXER, name=b'', index=0):
    return ID.pack(numid, iface, 0, 0, name[:43], index)


class Card:
    """The controls of card 0 by name, through the control device."""
    def __init__(self, path=CONTROL):
        self.fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        self.ids = self._list()

    def close(self):
        os.close(self.fd)

    def _list(self):
        head = bytearray(LIST_SIZE)
        fcntl.ioctl(self.fd, ELEM_LIST, head, True)
        count = struct.unpack_from('<I', head, 12)[0]
        space = (ctypes.c_char * (ID.size * max(count, 1)))()
        head = bytearray(LIST_SIZE)
        struct.pack_into('<IIIIQ', head, 0, 0, count, 0, 0, ctypes.addressof(space))
        fcntl.ioctl(self.fd, ELEM_LIST, head, True)
        used = struct.unpack_from('<I', head, 8)[0]
        ids = {}
        for n in range(used):
            numid, iface, _, _, name, index = ID.unpack_from(bytes(space), n * ID.size)
            ids[name.split(b'\0', 1)[0].decode('utf-8', 'replace')] = (numid, iface, index)
        return ids

    def info(self, name):
        numid, iface, index = self.ids[name]
        data = bytearray(INFO_SIZE)
        data[:ID.size] = elem_id(numid, iface)
        fcntl.ioctl(self.fd, ELEM_INFO, data, True)
        kind, access, count = struct.unpack_from('<III', data, 64)
        result = {'type': kind, 'access': access, 'count': count}
        if kind == TYPE_INTEGER:
            result.update(zip(('min', 'max', 'step'), struct.unpack_from('<qqq', data, 80)))
        elif kind == TYPE_ENUMERATED:
            result['items'] = [self._item(numid, iface, item) for item in range(struct.unpack_from('<I', data, 80)[0])]
        return result

    def _item(self, numid, iface, item):
        data = bytearray(INFO_SIZE)
        data[:ID.size] = elem_id(numid, iface)
        struct.pack_into('<I', data, 84, item)
        fcntl.ioctl(self.fd, ELEM_INFO, data, True)
        return bytes(data[88:152]).split(b'\0', 1)[0].decode('utf-8', 'replace')

    def read(self, name):
        info = self.info(name)
        numid, iface, _ = self.ids[name]
        data = bytearray(VALUE_SIZE)
        data[:ID.size] = elem_id(numid, iface)
        fcntl.ioctl(self.fd, ELEM_READ, data, True)
        if info['type'] == TYPE_ENUMERATED:
            return [info['items'][v] for v in struct.unpack_from('<%dI' % info['count'], data, 72)]
        return list(struct.unpack_from('<%dq' % info['count'], data, 72))

    def write(self, name, value):
        info = self.info(name)
        numid, iface, _ = self.ids[name]
        data = bytearray(VALUE_SIZE)
        data[:ID.size] = elem_id(numid, iface)
        if info['type'] == TYPE_ENUMERATED:
            struct.pack_into('<%dI' % info['count'], data, 72, *[info['items'].index(value)] * info['count'])
        else:
            if info['type'] == TYPE_INTEGER:
                value = max(info['min'], min(info['max'], int(value)))
            struct.pack_into('<%dq' % info['count'], data, 72, *[int(value)] * info['count'])
        fcntl.ioctl(self.fd, ELEM_WRITE, data, True)

    def add_volume(self):
        """softvol's own control, made before the browser opens its device so that the level set here
        holds from its first sound. It must be the control softvol would make: a user control without
        a readable dB scale is removed and made again by softvol (alsa-lib 1.2.15, pcm_softvol.c), and
        then the browser owns it, so that while it plays the recovery's volume could not write it
        (2026-11-20, the owner on YouTube: the slider did not move and blinked; EPERM)."""
        if VOLUME in self.ids:
            if self.info(VOLUME)['access'] & ACCESS_TLV_READ:
                return
            numid, iface, index = self.ids[VOLUME]
            fcntl.ioctl(self.fd, ELEM_REMOVE, bytearray(elem_id(numid, iface, VOLUME.encode(), index)), True)
            self.ids = self._list()
        data = bytearray(INFO_SIZE)
        data[:ID.size] = elem_id(0, IFACE_MIXER, VOLUME.encode())
        struct.pack_into('<III', data, 64, TYPE_INTEGER,
                         ACCESS_READ | ACCESS_WRITE | ACCESS_TLV_READ | ACCESS_TLV_WRITE | ACCESS_USER, 2)
        struct.pack_into('<qqq', data, 80, 0, LEVELS - 1, 0)
        fcntl.ioctl(self.fd, ELEM_ADD, data, True)
        self.ids = self._list()
        numid = self.ids[VOLUME][0]
        fcntl.ioctl(self.fd, TLV_WRITE, bytearray(struct.pack('<II', numid, 16) + volume_tlv()), True)


def jack_in(card):
    for name in ('Headphone Jack', 'Headset Jack'):
        if name in card.ids:
            return bool(card.read(name)[0])
    return False


def apply(card, steps):
    done = []
    for name, value in steps:
        if name in card.ids:
            card.write(name, value)
            done.append(name)
    return done


def state():
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def save(**values):
    current = {**state(), **values}
    STATE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE.with_suffix('.new')
    temporary.write_text(json.dumps(current))
    temporary.replace(STATE)
    return current


def module_dir():
    """The modules of the running kernel: the image may carry them for several builds of one release."""
    build = os.uname().version.split()[0].lstrip('#')
    return HERE / 'sound-modules' / f'{os.uname().release}-{build}'


def load_modules():
    loaded = {line.split()[0].replace('_', '-') for line in Path('/proc/modules').read_text().splitlines() if line}
    folder = module_dir()
    for name in MODULES:
        if name in loaded:
            continue
        path = folder / (name + '.ko')
        if not path.is_file():
            raise FileNotFoundError(f'Sound module missing for this kernel: {name}')
        subprocess.run(['/bin/busybox', 'insmod', str(path)], check=True, capture_output=True, timeout=20)


def wait_card(seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if os.path.exists(CONTROL):
            return True
        time.sleep(0.2)
    return False


def asoundrc(output, switch=False):
    """plug -> softvol (the recovery's volume) -> route -> plug -> hw:0,0. The speaker hangs on the
    left DAC only, so there both channels are mixed into the left one; headphones keep stereo.
    The file stands alone (the browser gets it as ALSA_CONFIG_PATH): an engine loaded from a card
    carries no /usr/share/alsa, and only plugin types built into alsa-lib are used.

    SWITCH (the browser's file, when the image has the plugin): "default" is a22x_switch, between
    a22x_phone (the chain above) and a22x_bt (softvol, the same control, -> BlueALSA's A2DP), with the
    plugins web_launch puts in BROWSER_PLUGINS. The player's copy (media_service) keeps the chain alone."""
    table = ('ttable.0.0 0.5\n    ttable.1.0 0.5' if output == 'speaker' else
             'ttable.0.0 1.0\n    ttable.1.1 1.0')
    if switch:
        default = f"""pcm_type.a22x_switch {{
    lib "{BROWSER_PLUGINS}/libasound_module_pcm_a22x_switch.so"
}}
pcm_type.bluealsa {{
    lib "{BROWSER_PLUGINS}/libasound_module_pcm_bluealsa.so"
}}
pcm.!default {{
    type a22x_switch
    select "{BROWSER_SELECT}"
    fallback "a22x_phone"
}}
pcm.a22x_phone {{
    type plug
    slave.pcm "a22x_volume"
}}
pcm.a22x_bt {{
    @args [ DEV ]
    @args.DEV {{
        type string
        default "00:00:00:00:00:00"
    }}
    type plug
    slave.pcm {{
        type softvol
        slave.pcm {{
            type bluealsa
            device $DEV
            profile "a2dp"
        }}
        control {{
            name "{VOLUME}"
            card 0
        }}
        min_dB {MIN_DB:.1f}
        max_dB {MAX_DB:.1f}
        resolution {LEVELS}
    }}
}}"""
    else:
        default = """pcm.!default {
    type plug
    slave.pcm "a22x_volume"
}"""
    return f"""# Written by sound.py for the {output}.
# The hw names that alsa.conf would define (softvol opens its control as "hw:0").
pcm.hw {{
    @args [ CARD DEV SUBDEV ]
    @args.CARD {{
        type string
        default "0"
    }}
    @args.DEV {{
        type integer
        default 0
    }}
    @args.SUBDEV {{
        type integer
        default -1
    }}
    type hw
    card $CARD
    device $DEV
    subdevice $SUBDEV
}}
ctl.hw {{
    @args [ CARD ]
    @args.CARD {{
        type string
        default "0"
    }}
    type hw
    card $CARD
}}
{default}
pcm.a22x_volume {{
    type softvol
    slave.pcm "a22x_output"
    control {{
        name "{VOLUME}"
        card 0
    }}
    min_dB {MIN_DB:.1f}
    max_dB {MAX_DB:.1f}
    resolution {LEVELS}
}}
pcm.a22x_output {{
    type route
    slave {{
        pcm {{
            type plug
            slave.pcm {{
                type hw
                card 0
                device 0
            }}
        }}
        channels 2
    }}
    {table}
}}
ctl.!default {{
    type hw
    card 0
}}
"""


def write_asoundrc(output, path=None):
    write_in_place(Path(path or ASOUNDRC), asoundrc(output, switch=SWITCH_PLUGIN.is_file()).encode())


def select_output(address=None, path=None):
    """The browser's sound to the Bluetooth device ADDRESS (A2DP), or to the phone with None."""
    if address is not None and not ADDRESS.fullmatch(address):
        raise ValueError('Not a Bluetooth address')
    write_in_place(Path(path or SELECT), (f'a22x_bt:DEV={address}\n' if address else 'a22x_phone\n').encode())
    return address


def write_in_place(path, data):
    """Written into the same file, never replaced: a bind of it into the browser's sandbox follows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        # Readable by the browser's user whatever the umask (init's is 077: on the phone the file
        # was 0600 and the browser stayed silent, 2026-11-20).
        os.fchmod(fd, 0o644)
        # the new text first, then the length: a reader never finds the file empty
        os.pwrite(fd, data, 0)
        os.ftruncate(fd, len(data))
    finally:
        os.close(fd)


def route(card):
    headphones = jack_in(card)
    apply(card, COMMON)
    apply(card, HEADPHONES if headphones else SPEAKER)
    output = 'headphones' if headphones else 'speaker'
    write_asoundrc(output)
    # Written again as it is: the browser's plugin opens its output anew, with the jack's channels.
    select_output(state().get('bluetooth'))
    return output


def jack_event_device():
    """/dev/input/eventN of the codec's jack detection, by its name."""
    for entry in sorted(Path('/sys/class/input').glob('event*')):
        try:
            if (entry / 'device/name').read_text().strip() == JACK_INPUT:
                return Path('/dev/input') / entry.name
        except OSError:
            continue
    return None


def watch():
    """Speaker or headphones again whenever a plug goes in or out of the jack (runs for the whole
    recovery session, started by init after sound.py start)."""
    device = jack_event_device()
    if device is None:
        raise FileNotFoundError('No headset jack input')
    event = struct.Struct('llHHi')
    fd = os.open(device, os.O_RDONLY | os.O_CLOEXEC)
    try:
        while True:
            data = os.read(fd, event.size * 16)
            if not data:
                return
            changed = any(kind == EV_SW and code in JACK_SWITCHES
                          for _, _, kind, code, _ in event.iter_unpack(data[:len(data) - len(data) % event.size]))
            if changed:
                time.sleep(0.3)  # the plug settles; the codec reports the final state
                card = Card()
                try:
                    save(output=route(card))
                finally:
                    card.close()
    finally:
        os.close(fd)


def set_volume(card, percent):
    percent = max(0, min(100, int(percent)))
    card.add_volume()
    card.write(VOLUME, round(percent * (LEVELS - 1) / 100))
    return percent


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('start', 'route', 'volume', 'status', 'watch', 'bluetooth'))
    parser.add_argument('percent', nargs='?', help='volume: 0..100; bluetooth: an address or "off"')
    args = parser.parse_args(argv)
    if args.command == 'bluetooth':
        # Where the browser's sound goes; the card is not needed (the plugin follows the file).
        try:
            if not args.percent:
                raise ValueError('Give an address or "off"')
            address = None if args.percent == 'off' else args.percent.upper()
            select_output(address)
            save(bluetooth=address)
            result, code = {'ok': True, 'operation': 'bluetooth', 'bluetooth': address is not None}, 0
        except (OSError, ValueError) as error:
            result, code = {'ok': False, 'operation': 'bluetooth', 'error': {'code': type(error).__name__,
                                                                             'message': str(error)[:200]}}, 2
        print(json.dumps(result, separators=(',', ':')), flush=True)
        return code
    if args.percent is not None and args.command == 'volume':
        try:
            args.percent = int(args.percent)
        except ValueError:
            args.percent = None
    if args.command == 'watch':
        try:
            watch()
            return 0
        except (OSError, RuntimeError, KeyError) as error:
            print(json.dumps({'ok': False, 'operation': 'watch', 'error': {'code': type(error).__name__,
                                                                          'message': str(error)[:200]}}), flush=True)
            return 2
    try:
        if args.command == 'start':
            load_modules()
            if not wait_card():
                raise RuntimeError('The sound card did not appear')
        card = Card()
        try:
            result = {'ok': True, 'operation': args.command}
            if args.command in ('start', 'route'):
                result['output'] = route(card)
                result['volume'] = set_volume(card, state().get('volume', 60))
                save(output=result['output'], volume=result['volume'])
            elif args.command == 'volume':
                if args.percent is None:
                    raise ValueError('Give the volume in percent')
                result['volume'] = set_volume(card, args.percent)
                save(volume=result['volume'])
            else:
                result.update({**state(), 'output': 'headphones' if jack_in(card) else 'speaker'})
        finally:
            card.close()
        code = 0
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        result, code = {'ok': False, 'operation': args.command, 'error': {'code': type(error).__name__, 'message': str(error)[:200]}}, 2
    print(json.dumps(result, separators=(',', ':')), flush=True)
    return code


if __name__ == '__main__':
    sys.exit(main())
