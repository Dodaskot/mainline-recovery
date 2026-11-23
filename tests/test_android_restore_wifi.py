"""Wi-Fi restore planning and the target's saved-network list (no Android device needed)."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import android_restore_wifi as wifi
from android_wifi_qr import ad, fs


def record(ssid, security='WPA', password='Fixture-Pass-1', hidden=False, status='available'):
    info = {'ssid': ssid, 'security': security, 'status': status}
    secret = None if status != 'available' else {'ssid': ssid, 'security': security, 'password': password, 'hidden': hidden}
    return info, secret


class Plan(unittest.TestCase):
    def test_duplicates_conflicts_and_unavailable_records(self):
        records = [record('Home'), record('Open', 'nopass', ''), record('Home'),
                   record('Twin', password='Twin-Pass-111'), record('Twin', password='Twin-Pass-222'),
                   record('Locked', status='encrypted_key')]
        report, pending = wifi.make_plan(records, [])
        self.assertEqual([row['status'] for row in report],
                         ['available', 'available', 'duplicate_backup_entry', 'conflicting_backup_entries',
                          'conflicting_backup_entries', 'encrypted_key'])
        self.assertEqual([secret['ssid'] for _, secret in pending], ['Home', 'Open'])
        self.assertEqual([row['index'] for row, _ in pending], [1, 2])

    def test_selected_indexes_only(self):
        report, pending = wifi.make_plan([record('A'), record('B'), record('C')], [3, 1])
        self.assertEqual([row['status'] for row in report], ['available', 'not_selected', 'available'])
        self.assertEqual(sorted(secret['ssid'] for _, secret in pending), ['A', 'C'])

    def test_passphrases_android_cannot_import(self):
        records = [record('Short', password='1234567'), record('Hex', password='a' * 64),
                   record('Wide', password='Пароль-123'), record('Sae', 'SAE', 'x'), record('Ok', password='12345678')]
        report, pending = wifi.make_plan(records, [])
        self.assertEqual([row['status'] for row in report][:3], ['passphrase_not_supported_by_android_import'] * 3)
        self.assertEqual([secret['ssid'] for _, secret in pending], ['Sae', 'Ok'])

    def test_invalid_or_repeated_indexes(self):
        for indexes in ([0], [4], [1, 1]):
            with self.subTest(indexes=indexes), self.assertRaises(fs.FilesystemError):
                wifi.make_plan([record('A'), record('B'), record('C')], indexes)


class TargetList(unittest.TestCase):
    """`cmd wifi list-networks` as printed by Android 16 (API 36 emulator, 2026-11-19)."""

    class Android:
        user = '0'

        def __init__(self, listing):
            self.listing = listing

        def check_target(self):
            pass

        def require_unlocked(self):
            pass

        def shell(self, *args):
            return '0' if args == ('am', 'get-current-user') else self.listing

    def test_android16_rows_with_upgradable_security_types(self):
        listing = ('Network Id      SSID                         Security type\n'
                   '0            AndroidWifi                      open\n'
                   '0            AndroidWifi                      owe^\n'
                   '1            A22x WiFi Existing               wpa2-psk\n'
                   '1            A22x WiFi Existing               wpa3-sae^\n'
                   '6            A22x WiFi 05                     wpa3-sae')
        self.assertEqual(wifi.saved_ssids(self.Android(listing)), {'AndroidWifi', 'A22x WiFi Existing', 'A22x WiFi 05'})

    def test_empty_and_unknown_listing(self):
        self.assertEqual(wifi.saved_ssids(self.Android('No networks')), set())
        with self.assertRaises(fs.FilesystemError):
            wifi.saved_ssids(self.Android('Unexpected output'))


if __name__ == '__main__':
    unittest.main()
