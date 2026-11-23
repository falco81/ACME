#!/usr/bin/env python3
"""Hunt R, run t8, area "targets": the bugs found and fixed, each kept fixed.

    python3 test/test_hunt_rt8_targets.py

- local: a script or command that failed put the previous files back with the new file's mode
  (a key the service's group read, 0640, came back 0600 - the service could not read it).
- ssh (and the targets writing files through _files: haproxy, strongswan, caddy, esxi...): a
  write that failed half-way (a chown refused) left the old key's copy made only for putting
  it back, <path>.acme-prev, beside the file.
"""
import os
import shutil
import stat
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh, make  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.targets import _files as F  # noqa: E402
from acmelib.plugins.targets._common import SshMixin  # noqa: E402


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


class LocalPutBackModeTest(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix='acme-rt8-local-')
        os.makedirs(os.path.join(self.base, 'www'))
        self.key = os.path.join(self.base, 'www', 'privkey.pem')
        with open(self.key, 'w') as fh:
            fh.write('OLD KEY')
        os.chmod(self.key, 0o640)

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_a_failed_command_puts_the_old_mode_back(self):
        ctx = FakeCtx()
        ctx.run_local = lambda argv, timeout=120, **k: (1, b'', b'reload failed')
        t = make('local', {'base': self.base, 'allow_commands': '/bin/false'}, ctx)
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {'outputs': 'key-pem www/privkey.pem', 'command': '/bin/false',
                                    'backup': False})
        with open(self.key) as fh:
            self.assertEqual(fh.read(), 'OLD KEY')
        self.assertEqual(stat.S_IMODE(os.stat(self.key).st_mode), 0o640)

    def test_a_new_file_still_goes(self):
        ctx = FakeCtx()
        ctx.run_local = lambda argv, timeout=120, **k: (1, b'', b'reload failed')
        t = make('local', {'base': self.base, 'allow_commands': '/bin/false'}, ctx)
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {'outputs': 'cert-pem www/new.crt', 'command': '/bin/false'})
        self.assertFalse(os.path.exists(os.path.join(self.base, 'www', 'new.crt')))


class HalfWrittenPrevTest(unittest.TestCase):
    """The old files there, no copy wanted (backup off): the key's chown refused."""
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='acme-rt8-ssh-')
        for n in ('a.crt', 'a.key'):
            with open(os.path.join(self.d, n), 'w') as fh:
                fh.write('OLD ' + n)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def left(self):
        return sorted(os.listdir(self.d))

    def test_ssh_takes_the_copy_away(self):
        ctx = FakeCtx(ssh=FakeSsh(local=True))
        t = make('ssh', {'host': 'h', 'user': 'u', 'tmp_dir': self.d}, ctx)
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {'outputs': 'fullchain-pem %s/a.crt 0644\nkey-pem %s/a.key '
                                               '0600 nosuchuser9:nosuchgrp9' % (self.d, self.d),
                                    'backup': False})
        self.assertEqual(self.left(), ['a.crt', 'a.key'])
        with open(os.path.join(self.d, 'a.key')) as fh:
            self.assertEqual(fh.read(), 'OLD a.key')
        with open(os.path.join(self.d, 'a.crt')) as fh:
            self.assertEqual(fh.read(), 'OLD a.crt')

    def test_ssh_dated_copy_kept_as_before(self):
        # a copy wanted (dated): it stays - as a deployment that went through keeps it
        ctx = FakeCtx(ssh=FakeSsh(local=True))
        t = make('ssh', {'host': 'h', 'user': 'u', 'tmp_dir': self.d}, ctx)
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {'outputs': 'key-pem %s/a.key 0600 nosuchuser9:nosuchgrp9'
                                               % self.d})
        self.assertFalse([n for n in self.left() if n.endswith('.acme-prev')])
        self.assertTrue([n for n in self.left() if n.startswith('a.key.') and
                         n.endswith('.bak')])

    def test_files_write_files_takes_the_copy_away(self):
        class W(SshMixin):
            def __init__(self, ctx):
                self.ctx = ctx

            def c(self, k, default=None):
                return default
        ctx = FakeCtx()
        w = W(ctx)
        files = [{'path': os.path.join(self.d, 'a.crt'), 'data': b'NEW', 'mode': 0o644,
                  'owner': None},
                 {'path': os.path.join(self.d, 'a.key'), 'data': b'NEW', 'mode': 0o600,
                  'owner': 'nosuchuser9:nosuchgrp9'}]
        with self.assertRaises(PluginError):
            F.write_files(w, FakeSsh(local=True), files, tmp_dir=self.d,
                          options={'backup': False})
        self.assertEqual(self.left(), ['a.crt', 'a.key'])
        with open(os.path.join(self.d, 'a.crt')) as fh:
            self.assertEqual(fh.read(), 'OLD a.crt')


if __name__ == '__main__':
    unittest.main()
