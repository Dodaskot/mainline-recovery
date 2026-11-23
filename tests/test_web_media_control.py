"""The shade's control of what a browser page plays (2026-11-22).

On the phone the first version did nothing: the interface sent its commands as M..., which the session
reads as a finger's move. The commands are J... now; and a page can hold several media elements
(YouTube's Shorts keep the next ones), so a pause stops every one that plays and the report follows
the one heard and seen most. The watcher runs in node against a small stand-in of the DOM.
"""
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import web_session  # noqa: E402

DOM = r"""
const told = [];
class Media {
  constructor(tag, box, muted) { this.tagName = tag; this.box = box; this.muted = muted; this.paused = false;
    this.ended = false; this.currentTime = 3.5; this.duration = 30; this.isConnected = true; }
  getBoundingClientRect() { return this.box; }
  pause() { this.paused = true; }
  play() { this.paused = false; return Promise.resolve(); }
}
const shown = new Media('VIDEO', {left: 0, top: 0, right: 360, bottom: 640}, false);
const next = new Media('VIDEO', {left: 0, top: 700, right: 360, bottom: 1340}, true);
const listeners = {};
globalThis.window = globalThis; globalThis.innerWidth = 360; globalThis.innerHeight = 686;
globalThis.location = {hostname: 'm.example.org'};
Object.defineProperty(globalThis, 'navigator', {value: {mediaSession: {metadata: {title: 'A short', artist: 'Someone'}}}, configurable: true});
globalThis.document = {title: 'page', querySelectorAll: () => [next, shown],
  addEventListener: (n, f) => { listeners[n] = f; }, dispatchEvent: () => true};
globalThis.CustomEvent = class { constructor(n, o) { this.type = n; Object.assign(this, o); } };
globalThis.a22xMedia = s => told.push(s);
globalThis.setTimeout = f => f();
"""


@unittest.skipUnless(shutil.which('node'), 'node is not installed')
class PageMediaTests(unittest.TestCase):
    def run_js(self, steps):
        script = DOM + web_session.MEDIA_WATCH + ';\n' + steps + '\nconsole.log(JSON.stringify(out));'
        done = subprocess.run(['node', '-e', script], capture_output=True, text=True, timeout=20)
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout)

    def test_the_seen_unmuted_one_is_told_and_a_pause_stops_every_one(self):
        out = self.run_js("listeners.play(); const first = JSON.parse(told[told.length-1]);"
                          "__a22xMediaDo('pause', 0); listeners.pause();"
                          "const out = {first, paused: [shown.paused, next.paused], after: JSON.parse(told[told.length-1])};"
                          "__a22xMediaDo('play', 0); out.again = [shown.paused, next.paused];")
        self.assertEqual(out['first']['t'], 'A short')
        self.assertTrue(out['first']['p'])
        self.assertEqual(out['first']['c'], 3500)
        self.assertEqual(out['paused'], [True, True])
        self.assertFalse(out['after']['p'])
        self.assertEqual(out['again'], [False, False])  # what the pause stopped, back

    def test_seek_moves_the_one_told(self):
        out = self.run_js("listeners.play(); __a22xMediaDo('seek', 12000); const out = [shown.currentTime, next.currentTime];")
        self.assertEqual(out, [12, 3.5])


class CommandLetterTests(unittest.TestCase):
    def test_the_interface_sends_j_and_the_session_reads_j(self):
        client = (ROOT / 'ui/media_client.h').read_text()
        self.assertNotRegex(client, r'web_send\(a,"M')
        self.assertIn('"J%s"', client)
        session = (ROOT / 'web_session.py').read_text()
        self.assertRegex(session, r"elif op == 'J':\n\s+# The shade's controls")
        # M stays a finger's move.
        self.assertTrue(re.search(r"elif op in \('D', 'M'\):", session))


if __name__ == '__main__':
    unittest.main()
