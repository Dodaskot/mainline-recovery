"""Shared and exclusive leases (2026-11-21): work on files runs beside USB files and the terminal;
storage-wide work holds the lease alone; a lent shared lease never turns into an exclusive one."""
import subprocess
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import operation_lock as ol


CHILD = """
import sys
sys.path.insert(0, sys.argv[1])
import operation_lock as ol
try:
    with ol.operation_lock(sys.argv[2], 'device', sys.argv[3] == 'shared'):
        print('ok')
except BlockingIOError:
    print('busy')
"""


class SharedLeaseTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, 'lock')
        os.environ.pop(ol.ENV_FD, None)
        os.environ.pop(ol.ENV_SHARED, None)

    def tearDown(self):
        self.dir.cleanup()

    def other(self, shared, env=None, fds=()):
        environment = {k: v for k, v in os.environ.items() if k not in (ol.ENV_FD, ol.ENV_SHARED)}
        environment.update(env or {})
        root = str(Path(__file__).resolve().parents[1])
        done = subprocess.run([sys.executable, '-c', CHILD, root, self.path, 'shared' if shared else 'alone'],
                              env=environment, pass_fds=fds, capture_output=True, text=True, timeout=30)
        return done.stdout.strip() or done.stderr.strip()[-200:]

    def test_shared_beside_shared_but_not_beside_exclusive(self):
        with ol.operation_lock(self.path, 'device', shared=True):
            self.assertEqual(self.other(True), 'ok')
            self.assertEqual(self.other(False), 'busy')
        with ol.operation_lock(self.path, 'device'):
            self.assertEqual(self.other(True), 'busy')
            self.assertEqual(self.other(False), 'busy')
        self.assertEqual(self.other(False), 'ok')

    def test_a_lent_shared_lease_refuses_exclusive_work_and_stays_shared(self):
        with ol.operation_lock(self.path, 'device', shared=True) as fd:
            env = {ol.ENV_FD: str(fd), ol.ENV_SHARED: '1'}
            self.assertEqual(self.other(True, env, (fd,)), 'ok')
            self.assertEqual(self.other(False, env, (fd,)), 'busy')
            self.assertEqual(self.other(True), 'ok')      # the lender still holds it shared

    def test_a_lent_exclusive_lease_covers_shared_work_and_stays_exclusive(self):
        with ol.operation_lock(self.path, 'device') as fd:
            env = {ol.ENV_FD: str(fd)}
            self.assertEqual(self.other(True, env, (fd,)), 'ok')
            self.assertEqual(self.other(False, env, (fd,)), 'ok')
            self.assertEqual(self.other(True), 'busy')    # still exclusive for everyone else


if __name__ == '__main__':
    unittest.main()
