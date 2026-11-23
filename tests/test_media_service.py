"""media_service.py: which layers the player and Bluetooth run in, and the processes it leaves (2026-11-22)."""
import fcntl
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import media_service  # noqa: E402


class LayerTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        base = Path(self.folder.name)
        self.cache = base / 'web-cache'
        self.cache.mkdir()
        self.published = {}
        patches = [
            mock.patch.object(media_service.web_cache, 'CACHE', self.cache),
            mock.patch.object(media_service.web_cache, 'cached', lambda manifest=None: self.published.get(
                'engine' if manifest in (None, media_service.web_cache.MANIFEST) else str(manifest))),
            mock.patch.object(media_service.web_cache, 'notify', lambda message: None),
            mock.patch.object(media_service.web_cache, 'ensure', self.ensure),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.ensured = []

    def tearDown(self):
        self.folder.cleanup()

    def ensure(self, wait=True, manifest=None, label=None):
        self.ensured.append(Path(manifest).name if manifest else 'engine')
        if manifest is None:
            # as web_cache.ensure: waits for the lock of a preparation under way, then finds it published
            with (self.cache.parent / 'web-cache.lock').open('a+b') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
            return self.published.get('engine') or Path('/engine')
        return Path('/' + Path(manifest).name)

    def test_the_engine_in_ram_takes_the_small_layer(self):
        self.published['engine'] = Path('/engine')
        self.assertEqual(media_service.layers(), [Path('/media_packages.json'), Path('/engine')])
        self.assertEqual(self.ensured, ['media_packages.json'])

    def test_no_engine_and_none_coming_takes_the_layer_of_its_own(self):
        self.assertEqual(media_service.layers(), [Path('/media_full_packages.json')])

    def test_an_engine_being_prepared_is_waited_for(self):
        lock = (self.cache.parent / 'web-cache.lock').open('a+b')
        fcntl.flock(lock, fcntl.LOCK_EX)

        def publish():
            time.sleep(0.3)
            self.published['engine'] = Path('/engine')
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()
        threading.Thread(target=publish).start()
        self.assertEqual(media_service.layers(), [Path('/media_packages.json'), Path('/engine')])
        self.assertNotIn('media_full_packages.json', self.ensured)


class SoundOutputTests(unittest.TestCase):
    """2026-11-22: the interface tells where the browser's sound goes; the service writes sound.py's file."""
    def test_the_chosen_device_and_the_phone_reach_the_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            service = media_service.Service()
            told = []
            service.tell = told.append
            with mock.patch.object(media_service.sound, 'SELECT', root / 'output'), \
                    mock.patch.object(media_service.sound, 'STATE', root / 'sound.json'):
                service.request(None, '{"op":"sound-output","bluetooth":"aa:bb:cc:dd:ee:ff"}')
                self.assertEqual((root / 'output').read_text(), 'a22x_bt:DEV=AA:BB:CC:DD:EE:FF\n')
                service.request(None, '{"op":"sound-output","bluetooth":""}')
                self.assertEqual((root / 'output').read_text(), 'a22x_phone\n')
                service.request(None, '{"op":"sound-output","bluetooth":"default\\npcm.x"}')
                self.assertEqual((root / 'output').read_text(), 'a22x_phone\n')
            self.assertEqual([e['event'] for e in told], ['error'])

    def test_the_bus_lets_the_browser_speak_to_bluealsa_only(self):
        policy = media_service.BROWSER_SOUND_POLICY
        self.assertIn('<policy user="nobody">', policy)
        self.assertIn('<allow send_destination="org.bluealsa"/>', policy)
        self.assertEqual(policy.count('<allow'), 1)


class BluetoothTests(unittest.TestCase):
    def test_a_device_without_an_icon_is_known_by_its_profiles(self):
        """2026-11-22, live: Sennheiser MOMENTUM 4 gives BlueZ no Icon, only its UUIDs."""
        sink = '0000110B-0000-1000-8000-00805F9B34FB'
        self.assertEqual(media_service.device_kind({'UUIDs': [sink]}), 'audio')
        self.assertEqual(media_service.device_kind({'UUIDs': ['00001124-0000-1000-8000-00805f9b34fb']}), 'keyboard')
        self.assertEqual(media_service.device_kind({'UUIDs': ['00001812-0000-1000-8000-00805f9b34fb']}), 'keyboard')
        self.assertEqual(media_service.device_kind({'Icon': 'input-mouse', 'UUIDs': [sink]}), 'mouse')
        self.assertEqual(media_service.device_kind({}), 'other')

    def test_le_is_kept_on_the_1m_phy(self):
        """2026-11-22, live: the keyboard's LE link failed with 0x3e while 2M and Coded were offered."""
        everything, configurable = 0x7fff, 0x79fe
        want = media_service.le_phy_selection(everything, configurable)
        self.assertEqual(want, 0x07ff)                       # BR/EDR as it was, LE 1M only
        self.assertIsNone(media_service.le_phy_selection(want, configurable))
        # A controller with no 2M or Coded to configure is left alone.
        self.assertIsNone(media_service.le_phy_selection(0x07ff, 0x01fe))


class BluetoothStateTests(unittest.TestCase):
    def bt(self):
        told = []
        service = mock.Mock(tell=told.append)
        bt = media_service.Bluetooth(service)
        bt.bus = mock.Mock()
        return bt, told

    def test_the_switch_shows_where_the_adapter_is_going(self):
        """2026-11-22, the owner's video: on, back off while powering, on again."""
        bt, _ = self.bt()
        for power, powered, shown in (('off-enabling', False, True), ('on', True, True), ('on-disabling', True, False),
                                      ('off', False, False), (None, True, True)):
            bt.adapter = {'Powered': powered} if power is None else {'Powered': powered, 'PowerState': power}
            self.assertEqual(bt.state()['powered'], shown, power)

    def test_the_number_goes_when_the_pairing_ends(self):
        """2026-11-22, the owner: the keyboard's number stayed on the screen after it was paired."""
        bt, told = self.bt()
        for kind in (media_service.dbus_min.METHOD_RETURN if hasattr(media_service.dbus_min, 'METHOD_RETURN') else 2,
                     media_service.dbus_min.ERROR):
            told.clear()
            bt.pending = {7: ('pair', '00:11:22:33:44:66')}
            bt.question = ('call', 'confirm')
            message = mock.Mock(kind=kind, fields={'reply': 7, 'error': 'org.bluez.Error.AuthenticationCanceled'})
            with mock.patch.object(bt, 'call_async'), mock.patch.object(bt, 'path', return_value='/dev'):
                bt.finished(message)
            self.assertIn({'event': 'pairing', 'kind': 'none'}, told)
            self.assertIsNone(bt.question)


class LeftoverTests(unittest.TestCase):
    def test_only_processes_in_the_media_root_are_ours(self):
        with mock.patch.object(media_service, 'ROOT', Path('/run/a22x-recovery/media/root')), \
             mock.patch.object(media_service.os, 'listdir', return_value=['1', '2', str(os.getpid()), 'self']), \
             mock.patch.object(media_service.os, 'readlink',
                               side_effect=lambda p: {'/proc/1/root': '/', '/proc/2/root': '/run/a22x-recovery/media/root'}.get(p, '/')):
            self.assertEqual(media_service.leftovers(), [2])


if __name__ == '__main__':
    unittest.main()
