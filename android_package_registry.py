#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Read Android PackageManager identities from an offline packages.xml."""
import hashlib
import io
import re
import struct
import xml.etree.ElementTree as ET

MAX_BYTES = 32 << 20
MAX_DEPTH = 64
MAX_NODES = 250_000
PACKAGE = re.compile(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+\Z')


def check(condition):
    if not condition:
        raise ValueError('Malformed Android package registry')


def binary_tree(data, *, fragment=False):
    stream = io.BytesIO(data[4:])
    interned, stack = [], []
    root = ET.Element("document") if fragment else None
    started = ended = False
    nodes = 0

    def read(size):
        value = stream.read(size)
        check(len(value) == size)
        return value

    def integer(size):
        return int.from_bytes(read(size), 'big')

    def utf():
        raw = read(integer(2)).replace(b'\xc0\x80', b'\0')
        # Android uses Java's modified UTF-8, including encoded surrogate pairs.
        return raw.decode('utf-8', 'surrogatepass').encode('utf-16', 'surrogatepass').decode('utf-16')

    def word():
        index = integer(2)
        if index == 0xffff:
            value = utf()
            if len(interned) < 0xffff:
                interned.append(value)
            return value
        check(index < len(interned))
        return interned[index]

    while token := stream.read(1):
        kind, value_type = token[0] & 15, token[0] >> 4
        if kind == 0:
            check(not started and not nodes and value_type == 1)
            started = True
        elif kind == 1:
            check(started and root is not None and not stack and value_type == 1 and not stream.read(1))
            ended = True
            break
        elif kind == 2:
            nodes += 1
            check(started and value_type == 3 and len(stack) < MAX_DEPTH and nodes <= MAX_NODES)
            node = ET.Element(word())
            if stack:
                stack[-1].append(node)
            elif fragment:
                root.append(node)
            else:
                check(root is None)
                root = node
            stack.append(node)
        elif kind == 3:
            check(value_type == 3 and stack and word() == stack[-1].tag)
            stack.pop()
        elif kind == 15:
            check(stack and not len(stack[-1]) and len(stack[-1].attrib) < 128)
            name = word()
            check(name not in stack[-1].attrib)
            if value_type == 2:
                value = utf()
            elif value_type == 3:
                value = word()
            elif value_type in (4, 5):
                value = read(integer(2)).hex()
            elif value_type in (6, 7, 8, 9):
                value = str(int.from_bytes(read(4 if value_type < 8 else 8), 'big', signed=True))
            elif value_type in (10, 11):
                value = str(struct.unpack('>f' if value_type == 10 else '>d', read(4 if value_type == 10 else 8))[0])
            else:
                check(value_type in (1, 12, 13))
                value = {1: '', 12: 'true', 13: 'false'}[value_type]
            stack[-1].set(name, value)
        else:
            check(kind in (4, 5, 7, 8, 9) and value_type in (1, 2))
            if value_type == 2:
                utf()
    check(ended)
    return root


def number(value, maximum, minimum=0):
    check(isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 20)
    result = int(value)
    check(minimum <= result <= maximum)
    return result


def package_identity(item, certs, include_code_path):
    name = item.get('name', '')
    check(len(name) <= 200 and PACKAGE.fullmatch(name))
    signatures = item.find('sigs')
    check(signatures is not None)
    ids = [number(cert.get('index'), MAX_NODES) for cert in signatures.findall('cert')]
    check(ids and len(ids) <= 16 and len(ids) == number(signatures.get('count'), 16, 1)
          and len(set(ids)) == len(ids) and all(index in certs for index in ids))
    code = item.get('codePath', '')
    check(code.startswith('/data/app/') and '\0' not in code)
    uid = number(item.get('userId'), 19999, 10000)
    check(item.get('sharedUserId') is None)
    identity = {'package': name, 'version_code': number(item.get('version'), (1 << 63) - 1),
                'signers_sha256': sorted({certs[index] for index in ids}), 'uid': uid}
    if include_code_path:
        components = code.removeprefix('/data/app/').split('/')
        check(all(part and part not in ('.', '..') for part in components))
        identity['code_path'] = code
    return identity


def parse(data, selected, *, include_code_path=False):
    check(0 < len(data) <= MAX_BYTES)
    if data.startswith(b'ABX\0'):
        root = binary_tree(data)
    else:
        # A package registry has no entity declarations or alternate UTF-16 prologues.
        check(b'\0' not in data and b'<!DOCTYPE' not in data.upper() and b'<!ENTITY' not in data.upper())
        root = ET.fromstring(data.decode('utf-8-sig'))
    check(root.tag == 'packages')
    versions = [entry for entry in root.findall('version') if not entry.get('volumeUuid')]
    check(len(versions) == 1)
    version = versions[0]
    sdk = number(version.get('sdkVersion'), 10000, 21)
    fingerprint = version.get('buildFingerprint') or version.get('fingerprint')
    check(fingerprint and len(fingerprint) <= 1024 and fingerprint.isprintable())
    certs = {}
    for cert in root.iter('cert'):
        index = number(cert.get('index'), MAX_NODES)
        encoded = cert.get('key')
        if encoded is not None:
            check(4 <= len(encoded) <= 65534 and len(encoded) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', encoded))
            digest = hashlib.sha256(bytes.fromhex(encoded)).hexdigest()
            check(index not in certs or certs[index] == digest)
            certs[index] = digest
    targets, seen = {}, set()
    for item in root.findall('package'):
        name = item.get('name')
        if selected is not None and name not in selected:
            continue
        check(name not in seen)
        seen.add(name)
        try:
            targets[name] = package_identity(item, certs, include_code_path)
        except ValueError:
            if selected is not None:
                raise
    return {'sdk': sdk, 'fingerprint': fingerprint, 'packages': targets}
