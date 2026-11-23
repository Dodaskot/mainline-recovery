"""sound.py without a sound card: the browser's ALSA configuration, the module folder of the running
kernel, the mixer steps applied only where the card has the control, and the CLI's answers."""
import json
import os
from pathlib import Path
import sys
import tempfile
import struct
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sound


class FakeCard:
    def __init__(self, controls):
        self.ids = {name: (n, 2, 0) for n, name in enumerate(controls)}
        self.writes = []
        self.values = {}

    def write(self, name, value):
        self.writes.append((name, value))
        self.values[name] = value

    def read(self, name):
        return [self.values.get(name, 0)]


class SoundTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='a22x-sound-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_the_volume_control_carries_softvols_own_db_scale(self):
        # alsa-lib 1.2.15 removes and makes again a user control without a readable dB scale; the
        # browser then owns it and the recovery cannot set the level while it plays (2026-11-20).
        self.assertEqual(struct.unpack('<IIiI', sound.volume_tlv()), (1, 8, -4000, 15))
        self.assertEqual((sound.ACCESS_TLV_READ, sound.ACCESS_TLV_WRITE), (0x10, 0x20))
        self.assertEqual(sound.TLV_WRITE, (3 << 30) | (8 << 16) | (ord('U') << 8) | 0x1b)
        self.assertEqual(sound.ELEM_REMOVE, (3 << 30) | (64 << 16) | (ord('U') << 8) | 0x19)
        self.assertIn('min_dB %.1f' % sound.MIN_DB, sound.asoundrc('speaker'))
        self.assertIn('max_dB %.1f' % sound.MAX_DB, sound.asoundrc('speaker'))

    def test_speaker_mixes_both_channels_into_the_left_dac(self):
        text = sound.asoundrc('speaker')
        self.assertIn('type softvol', text)
        self.assertIn('name "Recovery Playback Volume"', text)
        self.assertIn('ttable.0.0 0.5', text)
        self.assertIn('ttable.1.0 0.5', text)
        self.assertNotIn('ttable.1.1', text)
        self.assertIn('type hw', text)
        self.assertNotIn('plughw', text)  # no alias of alsa.conf: the file stands alone

    def test_headphones_keep_stereo(self):
        text = sound.asoundrc('headphones')
        self.assertIn('ttable.0.0 1.0', text)
        self.assertIn('ttable.1.1 1.0', text)
        self.assertNotIn('ttable.1.0', text)

    def test_the_configuration_is_rewritten_in_place(self):
        """web_launch binds the file into the browser: a new output must reach the same inode."""
        path = self.root / 'sound/asoundrc'
        sound.write_asoundrc('headphones', path)
        before = path.stat().st_ino
        old_mask = os.umask(0o077)
        try:
            sound.write_asoundrc('speaker', path)
        finally:
            os.umask(old_mask)
        self.assertEqual(path.stat().st_ino, before)
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)  # the browser's user reads it
        self.assertEqual(path.read_text(), sound.asoundrc('speaker'))

    def test_route_follows_the_jack_and_skips_missing_controls(self):
        card = FakeCard([name for name, _ in sound.COMMON + sound.SPEAKER + sound.HEADPHONES] + ['Headphone Jack'])
        with mock.patch.object(sound, 'ASOUNDRC', self.root / 'asoundrc'), \
                mock.patch.object(sound, 'SELECT', self.root / 'output'), \
                mock.patch.object(sound, 'STATE', self.root / 'sound.json'):
            self.assertEqual(sound.route(card), 'speaker')
            self.assertEqual((self.root / 'output').read_text(), 'a22x_phone\n')
            self.assertIn(('Speaker Switch', 1), card.writes)
            card.values['Headphone Jack'] = 1
            card.writes.clear()
            self.assertEqual(sound.route(card), 'headphones')
            self.assertIn(('HP Mux', 'Audio Playback'), card.writes)
            self.assertNotIn(('Speaker Switch', 1), card.writes)
            self.assertIn('ttable.1.1', (self.root / 'asoundrc').read_text())
        small = FakeCard(['Speaker Switch'])
        self.assertEqual(sound.apply(small, sound.SPEAKER), ['Speaker Switch'])

    def test_the_browser_file_switches_between_the_phone_and_bluetooth(self):
        """2026-11-22: the browser's default is a22x_switch, between the phone's chain and BlueALSA."""
        text = sound.asoundrc('speaker', switch=True)
        self.assertIn('type a22x_switch', text)
        self.assertIn('select "%s"' % sound.BROWSER_SELECT, text)
        self.assertIn('fallback "a22x_phone"', text)
        self.assertIn('lib "%s/libasound_module_pcm_a22x_switch.so"' % sound.BROWSER_PLUGINS, text)
        self.assertIn('lib "%s/libasound_module_pcm_bluealsa.so"' % sound.BROWSER_PLUGINS, text)
        self.assertIn('pcm.a22x_bt', text)
        self.assertIn('type bluealsa', text)
        self.assertEqual(text.count('name "%s"' % sound.VOLUME), 2)  # one volume for both outputs
        self.assertIn('ttable.1.0 0.5', text)  # the speaker's mix stays
        plain = sound.asoundrc('speaker')
        self.assertNotIn('a22x_switch', plain)  # the player's copy and an image without the plugin
        self.assertIn('slave.pcm "a22x_volume"', plain)

    def test_the_output_file_names_the_device_and_is_written_in_place(self):
        path = self.root / 'sound/output'
        sound.select_output(None, path)
        before = path.stat().st_ino
        self.assertEqual(path.read_text(), 'a22x_phone\n')
        sound.select_output('AA:BB:CC:DD:EE:0F', path)
        self.assertEqual(path.read_text(), 'a22x_bt:DEV=AA:BB:CC:DD:EE:0F\n')
        sound.select_output(None, path)
        self.assertEqual(path.read_text(), 'a22x_phone\n')  # shorter: no tail of the longer line
        self.assertEqual(path.stat().st_ino, before)
        for bad in ('aa:bb', 'AA:BB:CC:DD:EE:FF\npcm.x', 'AA:BB:CC:DD:EE:FG', '../x'):
            with self.assertRaises(ValueError):
                sound.select_output(bad, path)

    def test_the_bluetooth_command_keeps_the_choice(self):
        with mock.patch.object(sound, 'SELECT', self.root / 'output'), \
                mock.patch.object(sound, 'STATE', self.root / 'sound.json'), \
                mock.patch('builtins.print'):
            self.assertEqual(sound.main(['bluetooth', 'aa:bb:cc:dd:ee:ff']), 0)
            self.assertEqual((self.root / 'output').read_text(), 'a22x_bt:DEV=AA:BB:CC:DD:EE:FF\n')
            self.assertEqual(sound.state()['bluetooth'], 'AA:BB:CC:DD:EE:FF')
            self.assertEqual(sound.main(['bluetooth', 'off']), 0)
            self.assertEqual((self.root / 'output').read_text(), 'a22x_phone\n')
            self.assertIsNone(sound.state()['bluetooth'])
            self.assertEqual(sound.main(['bluetooth', 'nonsense']), 2)

    def test_modules_are_taken_from_the_running_kernel_build(self):
        uname = os.uname_result(('Linux', 'a22x', '7.2.0-a22x-recovery-diag1+',
                                 '#152 SMP PREEMPT Fri Nov 20 19:00:00 UTC 2026', 'aarch64'))
        with mock.patch.object(sound.os, 'uname', return_value=uname):
            self.assertEqual(sound.module_dir().name, '7.2.0-a22x-recovery-diag1+-152')

    def test_a_missing_module_is_an_error_not_a_crash(self):
        with mock.patch.object(sound, 'module_dir', return_value=self.root / 'none'), \
                mock.patch.object(sound.Path, 'read_text', return_value=''), \
                mock.patch('builtins.print') as printed:
            code = sound.main(['start'])
        self.assertEqual(code, 2)
        answer = json.loads(printed.call_args[0][0])
        self.assertEqual((answer['ok'], answer['error']['code']), (False, 'FileNotFoundError'))


if __name__ == '__main__':
    unittest.main()
