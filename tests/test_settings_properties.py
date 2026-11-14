"""The password's two promises, checked over every reachable state (2026-11-14: six reviews found
edge cases one by one in both directions; this walks them all, as the review suggested).

P1: a password stored and not cleared never reads as "no password".
P2: with no password stored (never set, cleared, or a set or clear that stopped halfway), nothing
    asks for userdata to be erased.

Each case: a start state, a first operation done whole, a second one stopped at every step it
writes (a crash, or an I/O error), each under several states of the two volumes; then reads under
other states of the volumes and after things that befall the disk from outside (the settings folder
lost, a link or a folder where they should be, an I/O error on the mark or on the file).

Two bounds, both settings.py's: a volume that is not there at the read is as one erased, which gives
the defaults (only Download Mode can bring that about), so P1 leaves such reads out; a volume that
was not there while a password was set or cleared and is there again at the read is as one restored
from an older image, whose older settings come back with it, so P2 leaves such reads out."""
import contextlib
import errno
import itertools
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import settings  # noqa: E402

KINDS = {  # mountable, mounted, write_supported, read_only_reason_code, opens read-only, opens for writing
    'now': (True, False, True, None, True, True),
    'later': (True, False, True, None, True, False),
    'outside': (False, True, False, None, True, False),
    'never': (True, False, False, 'FSCRYPT_KEYS_UNAVAILABLE', True, False),
    'dead': (True, False, True, None, False, False),
    'absent': (False, False, False, None, False, False)}
BASE = {'language': 'uk', 'theme': 'graphite'}
WITH = {**BASE, 'hash': 'ab' * 32, 'salt': 'cd' * 16}
OP_KINDS = (('now', 'now'), ('now', 'later'), ('later', 'now'), ('never', 'now'), ('absent', 'now'), ('now', 'dead'))
READ_KINDS = (('now', 'now'), ('later', 'later'), ('outside', 'now'), ('never', 'now'), ('now', 'dead'), ('dead', 'now'),
              ('absent', 'now'), ('now', 'absent'))
EVENTS = ('none', 'folder lost', 'folder a dangling link', 'settings a folder', 'mark unreadable', 'settings unreadable')


class Crash(BaseException):
    """The power went: nothing after this step happens."""


class World:
    def __init__(self, base):
        self.base = Path(base)
        self.kinds = {'cache': 'now', 'userdata': 'now'}
        self.fault = None  # ('crash' or 'eio', step)
        self.steps = 0
        self.unreadable = set()  # path suffixes whose lookups fail with EIO

    def root(self, label):
        return self.base / label


class Context:
    lock_path, mode = '/nonexistent', 'fixture'

    def __init__(self, world):
        self.world = world

    def volume(self, label):
        mountable, mounted, supported, code = KINDS[self.world.kinds[label]][:4]
        return {'mounted': mounted, 'mountable': mountable, 'write_supported': supported,
                'read_only_reason_code': code, 'volume_token': 't-' + label, 'fs_type': 'ext4'}

    def unmount(self, label, token=None):
        pass

    def format(self, label, kind, confirmed, token):
        root = self.world.root(label)
        for child in list(root.iterdir()):
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()


class Properties(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='a22x-props-', dir=os.environ.get('TMPDIR')))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.world = None

        @contextlib.contextmanager
        def volume_root(context, label, mode):
            ro, rw = KINDS[self.world.kinds[label]][4:]
            if not (rw if mode == 'rw' else ro):
                raise OSError(errno.EBUSY, 'cannot open %s %s' % (label, mode))
            yield self.world.root(label)

        def counted(real):
            def step(*args, **kwargs):
                world = self.world
                if world.fault is not None and world.fault[1] == world.steps:
                    world.steps += 1
                    if world.fault[0] == 'crash':
                        raise Crash()
                    raise OSError(errno.EIO, 'Input/output error')
                world.steps += 1
                return real(*args, **kwargs)
            return step

        real_stat, real_lstat, real_open = os.stat, os.lstat, os.open

        def failing(real):
            def look(path, *args, **kwargs):
                if self.world is not None and any(str(path).endswith(suffix) for suffix in self.world.unreadable):
                    raise OSError(errno.EIO, 'Input/output error')
                return real(path, *args, **kwargs)
            return look
        patches = [mock.patch.object(settings, 'volume_root', volume_root),
                   mock.patch.object(settings, 'lease', lambda *a, **k: contextlib.nullcontext()),
                   mock.patch.object(settings.fs, 'DeviceContext', lambda: Context(self.world)),
                   mock.patch.object(settings, 'RAM_COPY', self.tmp / 'ram.json'),
                   mock.patch.object(settings, 'copy_themes', lambda root: None),
                   mock.patch.object(settings.fs, 'atomic_state', counted(settings.fs.atomic_state)),
                   mock.patch.object(settings, 'set_mark', counted(settings.set_mark)),
                   mock.patch.object(settings, 'drop_mark', counted(settings.drop_mark)),
                   mock.patch.object(settings, 'clear_entry', counted(settings.clear_entry)),
                   mock.patch.object(settings.os, 'stat', failing(real_stat)),
                   mock.patch.object(settings.os, 'lstat', failing(real_lstat)),
                   mock.patch.object(settings.os, 'open', failing(real_open))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def new_world(self, name):
        world = World(self.tmp / name)
        for label in ('cache', 'userdata'):
            world.root(label).mkdir(parents=True)
        return world

    def copy(self, world, name):
        other = World(self.tmp / name)
        shutil.copytree(world.base, other.base, symlinks=True)
        return other

    def run_op(self, world, op, kinds, fault=None):
        """The operation's outcome: True, False, 'crash' or the error of a start."""
        self.world, world.kinds, world.fault, world.steps = world, dict(zip(('cache', 'userdata'), kinds)), fault, 0
        try:
            if op == 'set':
                return settings.write_disk(dict(WITH))
            if op == 'clear':
                return settings.write_disk(dict(BASE))
            settings.RAM_COPY.unlink(missing_ok=True)
            with contextlib.suppress(settings.Damaged, OSError):
                settings.load()
            return True
        except Crash:
            return 'crash'
        finally:
            world.fault = None

    def befall(self, world, event):
        rel = settings.RELATIVE
        for label in ('cache', 'userdata'):
            root = world.root(label)
            folder = root / rel.parent
            if event == 'folder lost' and folder.is_dir() and not folder.is_symlink():
                shutil.rmtree(folder)
            elif event == 'folder a dangling link' and os.path.lexists(folder):
                if folder.is_dir() and not folder.is_symlink():
                    shutil.rmtree(folder)
                else:
                    folder.unlink()
                folder.symlink_to('/nonexistent/folder')
            elif event == 'settings a folder' and (root / rel).is_file():
                (root / rel).unlink()
                (root / rel).mkdir()
        if event == 'mark unreadable':
            world.unreadable.add(str(settings.PASSWORD_MARK))
        if event == 'settings unreadable':
            world.unreadable.add(str(rel))

    def read(self, world, kinds):
        self.world, world.kinds = world, dict(zip(('cache', 'userdata'), kinds))
        try:
            return settings.read_disk()
        except (settings.Damaged, OSError) as error:
            return error

    def check(self, label, world, password, away):
        """PASSWORD: 'yes' (stored and not cleared), 'no', 'maybe-set' or 'maybe-clear' (a set or a
        clear that stopped halfway). AWAY: the volumes that were not there during an operation."""
        counter = itertools.count()
        for kinds in READ_KINDS:
            gone = {label_ for label_, kind in zip(('cache', 'userdata'), kinds) if kind == 'absent'}
            back = bool(away - gone)
            for event in EVENTS if kinds == ('now', 'now') else ('none',):
                seen = self.copy(world, '%s-r%d' % (world.base.name, next(counter)))
                self.befall(seen, event)
                outcome = self.read(seen, kinds)
                case = (label, kinds, event, outcome)
                if password == 'yes' and not gone:
                    self.assertFalse(isinstance(outcome, dict) and not outcome.get('hash'), ('P1',) + case)
                if not back and (password in ('no', 'maybe-set') or (password == 'maybe-clear' and event == 'none')):
                    self.assertNotIsInstance(outcome, settings.Damaged, ('P2',) + case)
                shutil.rmtree(seen.base)

    def starts(self):
        fresh = self.new_world('fresh')
        legacy = self.new_world('legacy')
        (legacy.root('cache') / settings.RELATIVE.parent).mkdir()
        (legacy.root('cache') / settings.RELATIVE).write_text(json.dumps(WITH))
        return (('fresh', fresh, 'no'), ('legacy', legacy, 'legacy'))

    def test_the_two_promises_hold_whatever_stops_a_write_and_whatever_befalls_the_disk(self):
        cases = 0
        for name, start, password in self.starts():
            for first, kinds1 in itertools.product(('none', 'set', 'clear', 'start'), (('now', 'now'), ('absent', 'now'))):
                base = self.copy(start, '%s-%s-%s' % (name, first, '-'.join(kinds1)))
                state = password
                if first != 'none':
                    done = self.run_op(base, first, kinds1)
                    if first == 'set' and done is True:
                        state = 'yes'
                    elif first == 'clear' and done is True:
                        state = 'no'
                    elif first == 'start' and state == 'legacy' and (base.root('cache') / settings.PASSWORD_MARK).is_file():
                        state = 'yes'  # a start that read them added the mark a release before it did not write
                if state == 'legacy':
                    continue  # before its first start, a password of an older release has no mark
                for second, kinds2 in itertools.product(('set', 'clear', 'start'), OP_KINDS):
                    probe = self.copy(base, base.base.name + '-probe')
                    self.run_op(probe, second, kinds2)
                    steps = probe.steps
                    shutil.rmtree(probe.base)
                    for fault in [None] + [(kind, step) for step in range(steps) for kind in ('crash', 'eio')]:
                        world = self.copy(base, '%s-%s-%s-%s' % (base.base.name, second, '-'.join(kinds2), fault and '%s%d' % fault))
                        done = self.run_op(world, second, kinds2, fault)
                        after = state
                        if second == 'set':
                            after = 'yes' if done is True else (state if state == 'yes' else 'maybe-set')
                        elif second == 'clear':
                            after = 'no' if done is True else ('maybe-clear' if state == 'yes' else state)
                        away = {label for kinds in (kinds1 if first != 'none' else (), kinds2)
                                for label, kind in zip(('cache', 'userdata'), kinds) if kind == 'absent'}
                        self.check((name, first, kinds1, second, kinds2, fault, done), world, after, away)
                        shutil.rmtree(world.base)
                        cases += 1
            shutil.rmtree(start.base, ignore_errors=True)
        self.assertGreater(cases, 100)


if __name__ == '__main__':
    unittest.main()
