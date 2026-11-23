import contextlib
import io
from pathlib import Path
import sqlite3
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from android_workspace import workspace


class LayoutExport(unittest.TestCase):
    def test_primary_profile_null_dock_coordinates_and_ordered_folder(self):
        intent = '#Intent;action=android.intent.action.MAIN;category=android.intent.category.LAUNCHER;component=pkg/.Main;end'
        with contextlib.closing(sqlite3.connect(':memory:')) as db:
            db.execute('CREATE TABLE favorites (_id, itemType, title, intent, container, screen, cellX, cellY, '
                       'spanX, spanY, appWidgetProvider, rank, profileId)')
            db.executemany('INSERT INTO favorites VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', [
                (1,0,'Test',intent,-101,4,None,None,1,1,None,0,0),
                (9,2,'A & Б',None,-100,2,3,1,1,1,None,0,0),
                (4,0,'B',intent.replace('.Main','.Second'),9,None,None,None,1,1,None,2,0),
                (7,0,'A',intent,9,None,None,None,1,1,None,0,0),
                (11,4,None,None,-100,2,0,0,2,3,'widget/.Provider',0,0),
                (12,0,None,intent,-100,0,1,2,1,1,None,0,10),
                (15,0,None,intent.replace('action.MAIN','action.VIEW'),-100,1,1,2,1,1,None,0,0),
            ])
            output = io.BytesIO()
            result = workspace(db, output)
        root = ET.fromstring(output.getvalue())
        self.assertEqual(root.find('appicon').get('container'), 'hotseat')
        self.assertEqual(root.find('appicon').get('rank'), '4')
        folder = root.find('folder')
        self.assertEqual(folder.attrib, {'screen':'2', 'x':'3', 'y':'1', 'titleText':'A & Б'})
        self.assertEqual([icon.get('className') for icon in folder], ['pkg.Main','pkg.Second'])
        self.assertEqual(root.find('appwidget').get('spanY'), '3')
        self.assertEqual(result['skipped'], {'other_profile':1,'unsupported_shortcut_or_component':1})
