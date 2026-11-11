#!/usr/bin/env python3
"""A deployment's files (1.0.77): a file that already holds the same bytes (SHA-256) is left
alone and the deployment is still fine, unless that is switched off; the one replaced is
just overwritten, kept as .bak, or kept with the date - the older dated copies pruned.
Over the fake SSH session of test_targets.py that runs its commands for real with sh.

    python3 test/test_deploy_same_backup.py
"""
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as TT  # noqa: E402
from test_targets import FakeBundle, FakeSsh, FakeCtx, make, read  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.targets import _files as F  # noqa: E402


def setUpModule():
    TT.setUpModule()


def tearDownModule():
    TT.tearDownModule()


class Choices(unittest.TestCase):
    def test_backup_mode_keeps_the_old_switch(self):
        for v, want in ((True, 'bak'), ('1', 'bak'), ('true', 'bak'), (False, 'none'), ('0', 'none'),
                        (None, 'bak'), ('', 'bak'), ('dated', 'dated'), ('daily', 'daily'),
                        ('none', 'none'), ('weird', 'bak')):
            self.assertEqual(F.backup_mode({'backup': v}), want, v)
        self.assertEqual(F.backup_mode({}, 'none'), 'none')

    def test_suffixes(self):
        when = time.mktime((2026, 11, 11, 15, 30, 0, 0, 0, -1))
        self.assertEqual(F.backup_suffix('dated', when), '.20261111-153000.bak')
        self.assertEqual(F.backup_suffix('daily', when), '.2026-11-11.bak')
        self.assertEqual(F.backup_suffix('bak'), '.bak')
        self.assertEqual(F.backup_suffix('none'), F.PREV)

    def test_skip_same_on_unless_off(self):
        self.assertTrue(F.skip_same({}))
        self.assertFalse(F.skip_same({'skip_same': False}))
        self.assertFalse(F.skip_same({'skip_same': '0'}))

    def test_the_fields_on_the_file_targets(self):
        for kind, conf in (('ssh', {'host': 'h'}), ('local', {'base': '/tmp/x'}),
                           ('windows_ssh', {'host': 'h'})):
            t = make(kind, conf, FakeCtx())
            keys = {f['key']: f for f in t.deploy_fields}
            self.assertTrue(keys['skip_same']['default'], kind)
            self.assertEqual(keys['backup']['type'], 'select', kind)
            self.assertEqual(keys['backup']['from_bool'], ['bak', 'none'])
            self.assertIn('backup_keep', keys)


class Ssh(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=TT.TMP)
        self.ssh = FakeSsh(local=True)
        self.ctx = FakeCtx(ssh=self.ssh)
        self.t = make('ssh', {'host': 'srv', 'user': 'deploy', 'tmp_dir': self.d}, self.ctx)
        self.crt = os.path.join(self.d, 'site.crt')
        self.key = os.path.join(self.d, 'site.key')
        self.opts = {'outputs': 'fullchain-pem %s 0644\nkey-pem %s 0600' % (self.crt, self.key),
                     'test_cmd': 'true', 'reload_cmd': 'echo reloaded'}

    def reloads(self):
        return sum(1 for c, _ in self.ssh.runs if 'echo reloaded' in c and 'with the previous' not in c)

    def test_one_file_the_same_is_left_alone(self):
        b = FakeBundle()
        with open(self.key, 'w') as fh:
            fh.write(b.key_pem)
        os.utime(self.key, (1000, 1000))
        with open(self.crt, 'w') as fh:
            fh.write('OLD\n')
        words = self.t.deploy(b, self.opts)
        self.assertIn('1 file written', words)
        self.assertIn('1 the same left as it was', words)
        self.assertEqual(os.stat(self.key).st_mtime, 1000)        # not touched
        self.assertFalse(os.path.exists(self.key + '.bak'))        # nor copied aside
        self.assertEqual(read(self.crt + '.bak'), 'OLD\n')
        self.assertEqual(read(self.crt), b.fullchain_pem)
        self.assertTrue(any(lv == 'ok' and 'the same SHA-256' in w and self.key in w
                            for lv, w in self.ctx.steps))
        self.assertEqual(self.reloads(), 1)

    def test_every_file_the_same_is_fine_not_a_failure(self):
        b = FakeBundle()
        for p, d in ((self.crt, b.fullchain_pem), (self.key, b.key_pem)):
            with open(p, 'w') as fh:
                fh.write(d)
        n = len(self.ssh.puts)
        # Not deployed here by acme before: nothing written, the reload done all the same.
        words = self.t.deploy(b, self.opts)
        self.assertTrue(words.startswith('0 files written'), words)
        self.assertEqual(len(self.ssh.puts), n)
        self.assertEqual(self.reloads(), 1)
        self.assertTrue(any('none replaced' in w for lv, w in self.ctx.steps if lv == 'ok'))
        self.assertFalse(any(lv == 'bad' for lv, w in self.ctx.steps))
        # Now it was: unchanged, nothing run.
        self.assertTrue(self.t.deploy(b, self.opts).startswith('unchanged'))
        self.assertEqual(self.reloads(), 1)

    def test_switched_off_every_file_written(self):
        b = FakeBundle()
        self.t.deploy(b, self.opts)
        n = len(self.ssh.puts)
        words = self.t.deploy(b, dict(self.opts, skip_same=False))
        self.assertIn('2 files written', words)
        self.assertEqual(len(self.ssh.puts), n + 2)

    def test_just_overwrite(self):
        with open(self.crt, 'w') as fh:
            fh.write('OLD\n')
        self.t.deploy(FakeBundle(), dict(self.opts, backup='none'))
        self.assertEqual([x for x in os.listdir(self.d) if x.startswith('site.crt.')], [])

    def test_old_switch_off_is_overwrite(self):
        with open(self.crt, 'w') as fh:
            fh.write('OLD\n')
        self.t.deploy(FakeBundle(), dict(self.opts, backup=False))
        self.assertFalse(os.path.exists(self.crt + '.bak'))

    def test_dated_copies_pruned(self):
        for i in range(4):
            p = '%s.2025010%d-120000.bak' % (self.crt, i + 1)
            with open(p, 'w') as fh:
                fh.write('v%d\n' % i)
            os.utime(p, (1000 + i, 1000 + i))
        with open(self.crt, 'w') as fh:
            fh.write('OLD\n')
        self.t.deploy(FakeBundle(), dict(self.opts, backup='dated', backup_keep=3))
        kept = sorted(x for x in os.listdir(self.d) if x.startswith('site.crt.') and x.endswith('.bak'))
        self.assertEqual(len(kept), 3, kept)
        newest = [x for x in kept if not x.startswith('site.crt.2025')]
        self.assertEqual(len(newest), 1)
        self.assertEqual(read(os.path.join(self.d, newest[0])), 'OLD\n')
        self.assertIn('site.crt.20250104-120000.bak', kept)
        self.assertNotIn('site.crt.20250101-120000.bak', kept)

    def test_daily_and_rollback_from_it(self):
        with open(self.crt, 'w') as fh:
            fh.write('OLD\n')
        with self.assertRaises(PluginError):
            self.t.deploy(FakeBundle(), dict(self.opts, backup='daily', reload_cmd='false'))
        self.assertEqual(read(self.crt), 'OLD\n')
        self.assertEqual(read(self.crt + F.backup_suffix('daily')), 'OLD\n')

    def test_rollback_with_overwrite_and_a_file_left(self):
        b = FakeBundle()
        with open(self.key, 'w') as fh:
            fh.write(b.key_pem)
        with open(self.crt, 'w') as fh:
            fh.write('OLD\n')
        with self.assertRaises(PluginError):
            self.t.deploy(b, dict(self.opts, backup='none', test_cmd='false'))
        self.assertEqual(read(self.crt), 'OLD\n')
        self.assertEqual(read(self.key), b.key_pem)
        self.assertFalse(os.path.exists(self.crt + F.PREV))


class Local(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(dir=TT.TMP)
        self.ctx = FakeCtx()
        self.t = make('local', {'base': self.base}, self.ctx)
        self.opts = {'outputs': 'fullchain-pem s/full.pem\nkey-pem s/key.pem'}
        self.full = os.path.join(self.base, 's', 'full.pem')
        self.key = os.path.join(self.base, 's', 'key.pem')

    def test_same_left_and_dated_kept(self):
        b = FakeBundle()
        os.makedirs(os.path.dirname(self.full))
        with open(self.key, 'w') as fh:
            fh.write(b.key_pem)
        os.utime(self.key, (1000, 1000))
        with open(self.full, 'w') as fh:
            fh.write('OLD\n')
        words = self.t.deploy(b, dict(self.opts, backup='dated'))
        self.assertIn('1 file written', words)
        self.assertEqual(os.stat(self.key).st_mtime, 1000)
        kept = [x for x in os.listdir(os.path.dirname(self.full)) if x.startswith('full.pem.')]
        self.assertEqual(len(kept), 1)
        self.assertEqual(read(os.path.join(os.path.dirname(self.full), kept[0])), 'OLD\n')

    def test_default_overwrites_and_off_writes_all(self):
        b = FakeBundle()
        self.t.deploy(b, self.opts)
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.full))), ['full.pem', 'key.pem'])
        self.assertTrue(self.t.deploy(b, self.opts).startswith('unchanged'))
        words = self.t.deploy(b, dict(self.opts, skip_same=False))
        self.assertIn('2 files written', words)
        words = self.t.deploy(b, dict(self.opts, force=True))
        self.assertIn('2 files written', words)


if __name__ == '__main__':
    unittest.main(verbosity=2)
