"""The browser tells pages that video above 1080p is unsupported (2026-11-22, a tester, #6: a 4K video was
killed for memory). The script runs in node with a stand-in MediaSource and mediaCapabilities."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import web_session  # noqa: E402

HARNESS = '''
Object.defineProperty(globalThis, 'navigator', {value: {mediaCapabilities: {decodingInfo: async q => ({supported: true})}}, configurable: true});
const window = globalThis; window.MediaSource = {isTypeSupported: t => true};
%s;
(async () => {
  const types = ['video/webm; codecs="vp9"; width=3840; height=2160', 'video/webm; codecs="vp9"; width=2560; height=1440',
                 'video/webm; codecs="vp9"; width=1920; height=1080', 'video/mp4; codecs="avc1.640028"; width=1080; height=1920',
                 'video/webm; codecs="vp9"', 'audio/webm; codecs="opus"'];
  const info = [];
  for (const [w, h] of [[3840, 2160], [1920, 1080]]) info.push((await navigator.mediaCapabilities.decodingInfo({video: {width: w, height: h}})).supported);
  console.log(JSON.stringify({types: types.map(t => MediaSource.isTypeSupported(t)), info}));
})();
'''


@unittest.skipUnless(shutil.which('node'), 'node is needed')
class MediaCap(unittest.TestCase):
    def test_above_1080p_is_unsupported_and_the_rest_is_asked_as_before(self):
        run = subprocess.run(['node', '-e', HARNESS % web_session.MEDIA_CAP], capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout), {'types': [False, False, True, True, True, True], 'info': [False, True]})
