#!/usr/bin/env python3
"""Export local Android contact names, telephone numbers and emails from an encrypted A22x Data copy."""
import argparse
import itertools
import json
import sqlite3
import tarfile

from android_model_db import ad, crypt, export_database, fs


def escaped(value):
    return str(value or '').replace('\\', '\\\\').replace('\r\n', '\n').replace('\r', '\n').replace(
        '\n', '\\n').replace(';', '\\;').replace(',', '\\,')


def line(out, value):
    # Fold vCard lines on UTF-8 character boundaries, counting the continuation space.
    part = bytearray()
    for char in value:
        data = char.encode('utf-8')
        if len(part) + len(data) > 75:
            out.write(part + b'\r\n')
            part = bytearray(b' ')
        part.extend(data)
    out.write(part + b'\r\n')


def contacts(db):
    tables = db.execute("SELECT name FROM pragma_table_list WHERE schema='main' AND type='table'").fetchall()
    ad.require({'data', 'mimetypes', 'raw_contacts'} <= {name for name, in tables},
               'CONTACT_SCHEMA_UNSUPPORTED', 'Unsupported Android contact database layout')
    rows = db.execute("""
        SELECT r.contact_id, m.mimetype, d.data1, d.data2, d.data3, d.data4, d.data5, d.data6
        FROM raw_contacts r JOIN data d ON d.raw_contact_id = r._id
        JOIN mimetypes m ON m._id = d.mimetype_id
        WHERE r.deleted = 0 AND r.contact_id IS NOT NULL AND r.contact_id > 0
          AND m.mimetype IN ('vnd.android.cursor.item/name', 'vnd.android.cursor.item/phone_v2',
                             'vnd.android.cursor.item/email_v2')
        ORDER BY r.contact_id, d.is_super_primary DESC, d.is_primary DESC, d._id
    """)
    for _, group in itertools.groupby(rows, key=lambda row: row[0]):
        name = ()
        formatted = ''
        fields = {}
        for _, mime, value, given, family, prefix, middle, suffix in group:
            if mime.endswith('/name') and not formatted:
                name = tuple(str(part or '') for part in (family, given, middle, prefix, suffix))
                formatted = str(value or '') or ' '.join(str(x) for x in (given, family) if x)
            elif value and mime.endswith(('/phone_v2', '/email_v2')):
                fields[('TEL' if mime.endswith('/phone_v2') else 'EMAIL', str(value))] = None
        fallback = next((v for _, v in fields), '')
        if formatted or fallback:
            yield formatted or fallback, name or ('',) * 5, tuple(fields)


def cards(db, out):
    count = 0
    for formatted, name, fields in contacts(db):
        for value in ('BEGIN:VCARD', 'VERSION:3.0', 'FN:' + escaped(formatted), 'N:' + ';'.join(map(escaped, name))):
            line(out, value)
        for field, value in fields:
            line(out, field + ':' + escaped(value))
        line(out, 'END:VCARD')
        count += 1
    ad.require(count > 0, 'NO_CONTACTS', 'No local names, phone numbers or email addresses found')
    return count


def export(archive, password, output, digest=None):
    return export_database(archive, password, output, digest, 'com.android.providers.contacts', 'contacts2.db', cards)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--password-file', required=True)
    parser.add_argument('--expected-sha256')
    parser.add_argument('archive')
    parser.add_argument('new_vcf')
    args = parser.parse_args()
    try:
        count = export(args.archive, crypt.read_password(args.password_file), args.new_vcf, args.expected_sha256)
    except (OSError, ValueError, sqlite3.Error, fs.FilesystemError, tarfile.TarError) as error:
        parser.exit(2, f'{error}\n')
    print(json.dumps({'verified': True, 'contacts': count, 'file': args.new_vcf}))
