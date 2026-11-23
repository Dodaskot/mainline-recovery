#!/usr/bin/env python3
"""Convert a Launcher3-compatible layout in a full Android Data backup to initial-workspace XML."""
import argparse
from collections import Counter, defaultdict
import json
import re
import sqlite3
import tarfile
import xml.etree.ElementTree as ET

from android_model_db import ad, crypt, export_database, fs

COMPONENT = re.compile(r'([A-Za-z][\w]*(?:\.[A-Za-z][\w]*)*)/(\.?[A-Za-z_$][\w.$]*)', re.ASCII)
DESKTOP = -100
HOTSEAT = -101


def component(value):
    match = COMPONENT.fullmatch(value or '')
    if match:
        package, cls = match.groups()
        return {'packageName': package, 'className': package + cls if cls.startswith('.') else cls}
    return None


def workspace(db, output):
    ad.require(db.execute("SELECT 1 FROM pragma_table_list WHERE schema='main' AND type='table' AND name='favorites'").fetchone(),
               'LAYOUT_UNSUPPORTED', 'The selected database has no Launcher3 favorites table')
    db.row_factory = sqlite3.Row
    rows = db.execute('SELECT _id, itemType, title, intent, container, screen, cellX, cellY, spanX, spanY, '
                      'appWidgetProvider, rank, profileId FROM favorites ORDER BY rank, _id LIMIT 10001').fetchall()
    ad.require(len(rows) <= 10000, 'LAYOUT_TOO_LARGE', 'Too many launcher items')
    skipped = Counter()
    counts = Counter()
    children = defaultdict(list)
    roots = []
    for row in rows:
        if row['profileId'] != 0:
            skipped['other_profile'] += 1
        elif row['container'] in (DESKTOP, HOTSEAT):
            roots.append(row)
        else:
            children[row['container']].append(row)

    def app(row):
        intent = row['intent']
        fields = intent.split(';') if isinstance(intent, str) and intent.startswith('#Intent;') else []
        matches = [field[10:] for field in fields if field.startswith('component=')]
        main = 'action=android.intent.action.MAIN' in fields and 'category=android.intent.category.LAUNCHER' in fields
        attrs = component(matches[0]) if main and len(matches) == 1 else None
        if row['itemType'] != 0 or attrs is None:
            skipped['unsupported_shortcut_or_component'] += 1
            return None
        return ET.Element('appicon', attrs)

    root = ET.Element('workspace')
    for row in roots:
        screen, x, y = row['screen'], row['cellX'], row['cellY']
        coordinates = (screen,) if row['container'] == HOTSEAT else (screen, x, y)
        if not all(type(v) is int and 0 <= v < 10000 for v in coordinates):
            skipped['invalid_position'] += 1
            continue
        position = ({'container': 'hotseat', 'rank': str(screen)} if row['container'] == HOTSEAT else
                    {'screen': str(screen), 'x': str(x), 'y': str(y)})
        if row['itemType'] == 2:
            icons = [elem for child in children.pop(row['_id'], []) if (elem := app(child)) is not None]
            if len(icons) < 2:
                skipped['folder_with_fewer_than_two_supported_children'] += 1
                if not icons:
                    continue
                element = icons[0]
            else:
                title = row['title'] or ''
                ad.require(all(c in '\t\n\r' or 32 <= ord(c) <= 0x10ffff and ord(c) not in (0xfffe,0xffff)
                               for c in title), 'LAYOUT_UNSUPPORTED', 'Folder title contains invalid XML text')
                element = ET.Element('folder', {'titleText': title})
                element.extend(icons)
                counts['appicon'] += len(icons)
        elif row['itemType'] == 4:
            provider = component(row['appWidgetProvider'])
            spans = (row['spanX'], row['spanY'])
            if not provider or not all(type(n) is int and 1 <= n <= 100 for n in spans):
                skipped['invalid_widget'] += 1
                continue
            element = ET.Element('appwidget', {**provider, 'spanX': str(spans[0]), 'spanY': str(spans[1])})
        else:
            element = app(row)
            if element is None:
                continue
        element.attrib.update(position)
        root.append(element)
        counts[element.tag] += 1
    if children:
        skipped['unplaced_children'] = sum(map(len, children.values()))
    ad.require(len(root) > 0, 'EMPTY_LAYOUT', 'No supported primary-profile workspace items')
    ET.ElementTree(root).write(output, encoding='utf-8', xml_declaration=True)
    return {'items': dict(counts), 'skipped': dict(skipped)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--password-file', required=True)
    parser.add_argument('--expected-sha256')
    parser.add_argument('--package', default='com.android.launcher3')
    parser.add_argument('--database', default='launcher.db')
    parser.add_argument('archive')
    parser.add_argument('new_xml')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z]\w*(?:\.[A-Za-z]\w*)+', args.package, re.ASCII) or not re.fullmatch(r'[\w.-]+\.db', args.database, re.ASCII):
        parser.error('Expected a package name and a database filename')
    try:
        result = export_database(args.archive, crypt.read_password(args.password_file), args.new_xml,
                                 args.expected_sha256, args.package, args.database, workspace)
    except (OSError, ValueError, sqlite3.Error, fs.FilesystemError, tarfile.TarError) as error:
        parser.exit(2, f'{error}\n')
    print(json.dumps(result))
