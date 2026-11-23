"""dbus_min: the wire format BlueZ is spoken to in (2026-11-22)."""
import socket
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dbus_min  # noqa: E402


class WireTests(unittest.TestCase):
    def test_a_call_with_nested_values_comes_back_whole(self):
        props = {'Powered': dbus_min.Variant('b', True), 'Alias': dbus_min.Variant('s', 'Mainline Recovery'),
                 'UUIDs': dbus_min.Variant('as', ['0000110a-0000-1000-8000-00805f9b34fb'])}
        data = dbus_min.encode(dbus_min.METHOD_CALL, 7,
                               {'path': '/org/bluez/hci0', 'interface': 'org.freedesktop.DBus.Properties',
                                'member': 'Set', 'destination': 'org.bluez'},
                               'sa{sv}(yq)x', ('org.bluez.Adapter1', props, (5, 65535), -2))
        message, used = dbus_min.decode(data + b'tail')
        self.assertEqual(used, len(data))
        self.assertEqual((message.kind, message.serial, message.path, message.member), (dbus_min.METHOD_CALL, 7, '/org/bluez/hci0', 'Set'))
        self.assertEqual(message.signature, 'sa{sv}(yq)x')
        name, back, pair, number = message.body
        self.assertEqual(name, 'org.bluez.Adapter1')
        self.assertEqual(list(pair), [5, 65535])
        self.assertEqual(number, -2)
        values = {key: (value.value if isinstance(value, dbus_min.Variant) else value) for key, value in back.items()}
        self.assertEqual(values['Powered'], True)
        self.assertEqual(values['Alias'], 'Mainline Recovery')
        self.assertEqual(values['UUIDs'], ['0000110a-0000-1000-8000-00805f9b34fb'])

    def test_a_message_not_yet_whole_is_waited_for(self):
        data = dbus_min.encode(dbus_min.SIGNAL, 3, {'path': '/', 'interface': 'a.b', 'member': 'C'}, 's', ('x' * 100,))
        for cut in (0, 8, 15, 16, len(data) - 1):
            self.assertEqual(dbus_min.decode(data[:cut]), (None, 0))
        self.assertEqual(dbus_min.decode(data)[1], len(data))

    def test_alignment_of_the_body_follows_the_header(self):
        data = dbus_min.encode(dbus_min.METHOD_RETURN, 9, {'reply': 4, 'destination': ':1.2'}, 'yt', (1, 2 ** 40))
        head_fields = struct.unpack_from('<I', data, 12)[0]
        start = 16 + head_fields + (-(16 + head_fields)) % 8
        self.assertEqual(data[start], 1)
        self.assertEqual(struct.unpack_from('<Q', data, start + 8)[0], 2 ** 40)

    def test_external_authentication_hello_and_a_signal_met_while_waiting(self):
        import tempfile
        import threading
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / 'bus')
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(1)

            def server():
                there, _ = listener.accept()
                with there:
                    got = b''
                    while b'\r\n' not in got:
                        got += there.recv(4096)
                    assert got.startswith(b'\0AUTH EXTERNAL ')
                    there.sendall(b'OK 0123456789abcdef0123456789abcdef\r\n')
                    while b'BEGIN\r\n' not in got:
                        got += there.recv(4096)
                    buf = bytearray(got[got.index(b'BEGIN\r\n') + 7:])
                    for expected in ('Hello', 'GetManagedObjects'):
                        while True:
                            message, used = dbus_min.decode(bytes(buf))
                            if message:
                                del buf[:used]
                                break
                            buf += there.recv(4096)
                        assert message.member == expected
                        if expected == 'GetManagedObjects':
                            # A signal before the reply: kept for later, not taken as the reply.
                            there.sendall(dbus_min.encode(dbus_min.SIGNAL, 50, {'path': '/org/bluez/hci0', 'interface': 'x.y', 'member': 'Changed'}))
                        there.sendall(dbus_min.encode(dbus_min.METHOD_RETURN, 60 + len(expected),
                                                      {'reply': message.serial, 'destination': ':1.5'}, 's', (':1.5' if expected == 'Hello' else 'objects',)))
            worker = threading.Thread(target=server, daemon=True)
            worker.start()
            bus = dbus_min.Bus(path, timeout=5)
            self.assertEqual(bus.unique, ':1.5')
            self.assertEqual(bus.call('org.bluez', '/', 'org.freedesktop.DBus.ObjectManager', 'GetManagedObjects'), ['objects'])
            worker.join(5)
            queued = bus.read(block=False)
            self.assertIsNotNone(queued)
            self.assertEqual(queued.member, 'Changed')
            listener.close()


if __name__ == '__main__':
    unittest.main()
