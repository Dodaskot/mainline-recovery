#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""The D-Bus wire protocol, as much as BlueZ needs (2026-11-22, the owner: Bluetooth in the recovery).

The recovery's Python has no dbus module, and BlueZ is spoken to over D-Bus only. This is the protocol
itself (the D-Bus specification, little-endian): EXTERNAL authentication on a Unix socket, method calls
and their replies, signals subscribed with AddMatch, and objects of our own (BlueZ's pairing agent) that
answer calls. Types: y b n q i u x t d s o g v, arrays, dicts and structs.
"""
import os
import socket
import struct

METHOD_CALL, METHOD_RETURN, ERROR, SIGNAL = 1, 2, 3, 4
FIELDS = {1: 'path', 2: 'interface', 3: 'member', 4: 'error', 5: 'reply', 6: 'destination', 7: 'sender', 8: 'signature'}
FIXED = {'y': ('B', 1), 'b': ('I', 4), 'n': ('h', 2), 'q': ('H', 2), 'i': ('i', 4), 'u': ('I', 4),
         'x': ('q', 8), 't': ('Q', 8), 'd': ('d', 8), 'h': ('I', 4)}


class DBusError(Exception):
    def __init__(self, name, message=''):
        super().__init__(f'{name}: {message}' if message else name)
        self.name = name


class Variant:
    def __init__(self, signature, value):
        self.signature, self.value = signature, value


def split_signature(sig):
    """The complete types of SIG, in order."""
    out, i = [], 0
    while i < len(sig):
        j = _end(sig, i)
        out.append(sig[i:j])
        i = j
    return out


def _end(sig, i):
    c = sig[i]
    if c == 'a':
        return _end(sig, i + 1)
    if c in '({':
        close, depth, j = ')' if c == '(' else '}', 0, i
        while True:
            if sig[j] in '({':
                depth += 1
            elif sig[j] in ')}':
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
    return i + 1


def _align(n):
    return {'y': 1, 'b': 4, 'n': 2, 'q': 2, 'i': 4, 'u': 4, 'x': 8, 't': 8, 'd': 8, 'h': 4, 's': 4, 'o': 4,
            'g': 1, 'v': 1, 'a': 4, '(': 8, '{': 8}[n[0]]


class Writer:
    def __init__(self):
        self.buf = bytearray()

    def pad(self, n):
        self.buf += bytes((-len(self.buf)) % n)

    def put(self, sig, value):
        c = sig[0]
        if c in FIXED:
            fmt, size = FIXED[c]
            self.pad(size)
            self.buf += struct.pack('<' + fmt, int(value) if c != 'd' else value)
        elif c in 'so':
            data = value.encode()
            self.pad(4)
            self.buf += struct.pack('<I', len(data)) + data + b'\0'
        elif c == 'g':
            data = value.encode()
            self.buf += bytes([len(data)]) + data + b'\0'
        elif c == 'v':
            self.put('g', value.signature)
            self.put(value.signature, value.value)
        elif c == 'a':
            inner = sig[1:]
            self.pad(4)
            at = len(self.buf)
            self.buf += b'\0\0\0\0'
            self.pad(_align(inner))
            start = len(self.buf)
            items = value.items() if inner[0] == '{' else value
            for item in items:
                self.put(inner, item)
            struct.pack_into('<I', self.buf, at, len(self.buf) - start)
        elif c in '({':
            self.pad(8)
            for part, item in zip(split_signature(sig[1:-1]), value):
                self.put(part, item)
        else:
            raise ValueError('Unsupported D-Bus type ' + c)


class Reader:
    def __init__(self, data, pos=0):
        self.data, self.pos = data, pos

    def pad(self, n):
        self.pos += (-self.pos) % n

    def get(self, sig):
        c = sig[0]
        if c in FIXED:
            fmt, size = FIXED[c]
            self.pad(size)
            value = struct.unpack_from('<' + fmt, self.data, self.pos)[0]
            self.pos += size
            return bool(value) if c == 'b' else value
        if c in 'so':
            self.pad(4)
            n = struct.unpack_from('<I', self.data, self.pos)[0]
            value = self.data[self.pos + 4:self.pos + 4 + n].decode('utf-8', 'replace')
            self.pos += 5 + n
            return value
        if c == 'g':
            n = self.data[self.pos]
            value = self.data[self.pos + 1:self.pos + 1 + n].decode()
            self.pos += 2 + n
            return value
        if c == 'v':
            inner = self.get('g')
            return self.get(inner)
        if c == 'a':
            inner = sig[1:]
            self.pad(4)
            n = struct.unpack_from('<I', self.data, self.pos)[0]
            self.pos += 4
            self.pad(_align(inner))
            end = self.pos + n
            if inner[0] == '{':
                out = {}
                while self.pos < end:
                    k, v = self.get(inner)
                    out[k] = v
                return out
            out = []
            while self.pos < end:
                out.append(self.get(inner))
            return out
        if c in '({':
            self.pad(8)
            return tuple(self.get(part) for part in split_signature(sig[1:-1]))
        raise ValueError('Unsupported D-Bus type ' + c)


class Message:
    def __init__(self, kind, fields, body, signature='', serial=0, flags=0):
        self.kind, self.fields, self.body, self.signature, self.serial, self.flags = kind, fields, body, signature, serial, flags

    def __getattr__(self, name):
        try:
            return self.__dict__['fields'][name]
        except KeyError:
            raise AttributeError(name) from None


def encode(kind, serial, fields, signature='', args=(), flags=0):
    body = Writer()
    for part, value in zip(split_signature(signature), args):
        body.put(part, value)
    head = Writer()
    head.buf += b'l' + bytes([kind, flags, 1])
    head.buf += struct.pack('<II', len(body.buf), serial)
    items = []
    codes = {v: k for k, v in FIELDS.items()}
    for name, value in fields.items():
        code = codes[name]
        sig = {1: 'o', 2: 's', 3: 's', 4: 's', 5: 'u', 6: 's', 7: 's', 8: 'g'}[code]
        items.append((code, Variant(sig, value)))
    if signature:
        items.append((8, Variant('g', signature)))
    head.put('a(yv)', items)
    head.pad(8)
    return bytes(head.buf + body.buf)


def decode(data):
    """One message from DATA, or None when it is not complete; and the bytes it took."""
    if len(data) < 16:
        return None, 0
    body_len, serial, fields_len = struct.unpack_from('<III', data, 4)
    head_len = 16 + fields_len + ((-(16 + fields_len)) % 8)
    total = head_len + body_len
    if len(data) < total:
        return None, 0
    reader = Reader(data, 12)
    raw = reader.get('a(yv)')
    fields = {FIELDS[k]: v for k, v in raw if k in FIELDS}
    signature = fields.pop('signature', '')
    body_reader = Reader(data[head_len:total])
    body = [body_reader.get(part) for part in split_signature(signature)]
    return Message(data[1], fields, body, signature, serial, data[2]), total


class Bus:
    """A connection to a bus at PATH (a Unix socket), authenticated as this process's user."""

    def __init__(self, path, timeout=10.0):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self.sock.sendall(b'\0AUTH EXTERNAL ' + str(os.getuid()).encode().hex().encode() + b'\r\n')
        if not self._line().startswith(b'OK'):
            raise DBusError('org.freedesktop.DBus.Error.AuthFailed')
        self.sock.sendall(b'BEGIN\r\n')
        self.serial = 0
        self.inbox = bytearray()
        self.pending = []           # messages read while waiting for a reply
        self.handlers = {}          # path -> handler(message) for calls to our objects
        self.unique = self.call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'Hello')[0]

    def _line(self):
        line = b''
        while not line.endswith(b'\r\n'):
            chunk = self.sock.recv(1)
            if not chunk:
                raise DBusError('org.freedesktop.DBus.Error.Disconnected')
            line += chunk
        return line

    def fileno(self):
        return self.sock.fileno()

    def send(self, kind, fields, signature='', args=(), flags=0):
        self.serial += 1
        self.sock.sendall(encode(kind, self.serial, fields, signature, args, flags))
        return self.serial

    def read(self, block=True, queued=True):
        """The next message (or None without blocking when none has arrived). QUEUED: first those a call
        set aside while it waited for its reply."""
        if queued and self.pending:
            return self.pending.pop(0)
        while True:
            message, used = decode(bytes(self.inbox))
            if message:
                del self.inbox[:used]
                return message
            if not block:
                wait = self.sock.gettimeout()  # kept: a call still gives up on a bus that stopped
                self.sock.setblocking(False)
                try:
                    chunk = self.sock.recv(65536)
                except BlockingIOError:
                    return None
                finally:
                    self.sock.settimeout(wait)
            else:
                chunk = self.sock.recv(65536)
            if not chunk:
                raise DBusError('org.freedesktop.DBus.Error.Disconnected')
            self.inbox += chunk

    def call(self, destination, path, interface, member, signature='', args=()):
        serial = self.send(METHOD_CALL, {'path': path, 'interface': interface, 'member': member,
                                         'destination': destination}, signature, args)
        while True:
            message = self.read(queued=False)
            if message.kind in (METHOD_RETURN, ERROR) and message.fields.get('reply') == serial:
                if message.kind == ERROR:
                    raise DBusError(message.fields.get('error', 'Error'), message.body[0] if message.body else '')
                return message.body
            if message.kind == METHOD_CALL:
                self.dispatch(message)
            else:
                self.pending.append(message)

    def reply(self, call, signature='', args=()):
        self.send(METHOD_RETURN, {'reply': call.serial, 'destination': call.fields.get('sender', '')}, signature, args)

    def error(self, call, name, text=''):
        self.send(ERROR, {'reply': call.serial, 'destination': call.fields.get('sender', ''), 'error': name},
                  's' if text else '', (text,) if text else ())

    def dispatch(self, message):
        handler = self.handlers.get(message.fields.get('path'))
        if handler is None:
            self.error(message, 'org.freedesktop.DBus.Error.UnknownObject')
        else:
            handler(message)

    def match(self, rule):
        self.call('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'AddMatch', 's', (rule,))

    def get_all(self, destination, path, interface):
        return self.call(destination, path, 'org.freedesktop.DBus.Properties', 'GetAll', 's', (interface,))[0]

    def set(self, destination, path, interface, name, signature, value):
        self.call(destination, path, 'org.freedesktop.DBus.Properties', 'Set', 'ssv',
                  (interface, name, Variant(signature, value)))
