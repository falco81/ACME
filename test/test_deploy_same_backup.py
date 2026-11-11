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
        for v, want in ((True, 'dated'), ('1', 'dated'), ('true', 'dated'), (False, 'none'),
                        ('0', 'none'), (None, 'dated'), ('', 'dated'), ('daily', 'daily'),
                        ('none', 'none')):
            self.assertEqual(F.backup_mode({'backup': v}), want, v)
        self.assertEqual(F.backup_mode({'backup': True, 'backup_format': 'bak'}), 'bak')
        self.assertEqual(F.backup_mode({'backup': False, 'backup_format': 'bak'}), 'none')
        self.assertEqual(F.backup_mode({'backup_format': 'nonsense'}, 'folder'), 'folder')
        self.assertEqual(F.backup_mode({}), 'dated')

    def test_paths(self):
        when = time.mktime((2026, 11, 11, 15, 30, 0, 0, 0, -1))
        self.assertEqual(F.backup_path('/a/b.pem', 'dated', when), '/a/b.pem.20261111-153000.bak')
        self.assertEqual(F.backup_path('/a/b.pem', 'daily', when), '/a/b.pem.2026-11-11.bak')
        self.assertEqual(F.backup_path('/a/b.pem', 'bak'), '/a/b.pem.bak')
        self.assertEqual(F.backup_path('/a/b.pem', 'folder', when), '/a/.acme-backup/b.pem.20261111-153000.bak')
        self.assertEqual(F.backup_path('C:\\c\\b.pfx', 'folder', when), 'C:\\c\\.acme-backup\\b.pfx.20261111-153000.bak')
        self.assertEqual(F.backup_path('/a/b.pem', 'none'), '/a/b.pem' + F.PREV)

    def test_skip_same_on_unless_off(self):
        self.assertTrue(F.skip_same({}))
        self.assertFalse(F.skip_same({'skip_same': False}))
        self.assertFalse(F.skip_same({'skip_same': '0'}))

    def test_the_fields_on_the_file_targets(self):
        for kind, conf in (('ssh', {'host': 'h'}), ('local', {'base': '/tmp/x'}),
                           ('windows_ssh', {'host': 'h'}), ('caddy', {'host': 'h'}),
                           ('esxi', {'host': 'h'}), ('haproxy', {'host': 'h'}),
                           ('strongswan', {'host': 'h'}), ('traefik', {'host': 'h'}),
                           ('zimbra', {'host': 'h'})):
            t = make(kind, conf, FakeCtx())
            keys = {f['key']: f for f in t.deploy_fields}
            self.assertTrue(keys['skip_same']['default'], kind)
            self.assertEqual(keys['backup']['type'], 'bool', kind)
            self.assertTrue(keys['backup']['default'], kind)
            self.assertEqual(keys['backup_format']['type'], 'select', kind)
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
        self.assertFalse([x for x in os.listdir(self.d) if x.startswith('site.key.')])  # nor copied
        dated = [x for x in os.listdir(self.d) if x.startswith('site.crt.') and x.endswith('.bak')]
        self.assertEqual(len(dated), 1)                              # name.YYYYMMDD-HHMMSS.bak
        self.assertRegex(dated[0], r'^site\.crt\.\d{8}-\d{6}\.bak$')
        self.assertEqual(read(os.path.join(self.d, dated[0])), 'OLD\n')
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
        self.t.deploy(FakeBundle(), dict(self.opts, backup=False))
        self.assertEqual([x for x in os.listdir(self.d) if x.startswith('site.crt.')], [])

    def test_old_switch_off_is_overwrite(self):
        with open(self.crt, 'w') as fh:
            fh.write('OLD\n')
        self.t.deploy(FakeBundle(), dict(self.opts, backup=True, backup_format='bak'))
        self.assertEqual(read(self.crt + '.bak'), 'OLD\n')

    def test_folder(self):
        with open(self.crt, 'w') as fh:
            fh.write('OLD\n')
        self.t.deploy(FakeBundle(), dict(self.opts, backup_format='folder'))
        got = os.listdir(os.path.join(self.d, '.acme-backup'))
        self.assertEqual(len(got), 1)
        self.assertEqual(read(os.path.join(self.d, '.acme-backup', got[0])), 'OLD\n')
        self.assertEqual([x for x in os.listdir(self.d) if x.startswith('site.crt.')], [])

    def test_dated_copies_pruned(self):
        for i in range(4):
            p = '%s.2025010%d-120000.bak' % (self.crt, i + 1)
            with open(p, 'w') as fh:
                fh.write('v%d\n' % i)
            os.utime(p, (1000 + i, 1000 + i))
        with open(self.crt, 'w') as fh:
            fh.write('OLD\n')
        self.t.deploy(FakeBundle(), dict(self.opts, backup_keep=3))
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
            self.t.deploy(FakeBundle(), dict(self.opts, backup_format='daily', reload_cmd='false'))
        self.assertEqual(read(self.crt), 'OLD\n')
        self.assertEqual(read(F.backup_path(self.crt, 'daily')), 'OLD\n')

    def test_rollback_with_overwrite_and_a_file_left(self):
        b = FakeBundle()
        with open(self.key, 'w') as fh:
            fh.write(b.key_pem)
        with open(self.crt, 'w') as fh:
            fh.write('OLD\n')
        with self.assertRaises(PluginError):
            self.t.deploy(b, dict(self.opts, backup=False, test_cmd='false'))
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
        words = self.t.deploy(b, self.opts)
        self.assertIn('1 file written', words)
        self.assertEqual(os.stat(self.key).st_mtime, 1000)
        kept = [x for x in os.listdir(os.path.dirname(self.full)) if x.startswith('full.pem.')]
        self.assertEqual(len(kept), 1)
        self.assertEqual(read(os.path.join(os.path.dirname(self.full), kept[0])), 'OLD\n')

    def test_default_overwrites_and_off_writes_all(self):
        b = FakeBundle()
        self.t.deploy(b, dict(self.opts, backup=False))
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.full))), ['full.pem', 'key.pem'])
        self.assertTrue(self.t.deploy(b, dict(self.opts, backup=False)).startswith('unchanged'))
        words = self.t.deploy(b, dict(self.opts, skip_same=False))
        self.assertIn('2 files written', words)
        words = self.t.deploy(b, dict(self.opts, force=True))
        self.assertIn('2 files written', words)


class SharedFiles(unittest.TestCase):
    """_files.write_files for caddy, esxi, haproxy, strongswan, traefik, zimbra."""
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=TT.TMP)
        self.ssh = FakeSsh(local=True)
        self.ctx = FakeCtx(ssh=self.ssh)
        self.t = make('strongswan', {'host': 'srv'}, self.ctx)
        self.p = os.path.join(self.d, 'a.pem')
        self.q = os.path.join(self.d, 'b.pem')

    def files(self, a=b'A', b=b'B'):
        return [{'path': self.p, 'data': a, 'mode': 0o600, 'owner': None},
                {'path': self.q, 'data': b, 'mode': 0o600, 'owner': None}]

    def test_same_left_backup_dated_then_pruned(self):
        with self.ssh as s:
            with open(self.p, 'wb') as fh:
                fh.write(b'A')
            with open(self.q, 'wb') as fh:
                fh.write(b'old')
            fs = self.files()
            existed = F.write_files(self.t, s, fs, self.d, options={})
            self.assertEqual(existed, [None, True])
            self.assertEqual(read(self.q), 'B')
            baks = [x for x in os.listdir(self.d) if x.startswith('b.pem.') and x.endswith('.bak')]
            self.assertEqual(len(baks), 1)
            F.drop_previous(self.t, s, fs, {})
            self.assertTrue(any('the same SHA-256' in w for lv, w in self.ctx.steps))

    def test_off_and_put_back(self):
        with self.ssh as s:
            with open(self.p, 'wb') as fh:
                fh.write(b'A')
            fs = self.files()
            o = {'skip_same': False, 'backup': False}
            existed = F.write_files(self.t, s, fs, self.d, options=o)
            self.assertEqual(existed, [True, False])
            F.put_back(self.t, s, fs, existed)
            self.assertEqual(read(self.p), 'A')
            self.assertFalse(os.path.exists(self.q))
            self.assertFalse(os.path.exists(self.p + F.PREV))

    def test_folder_kept(self):
        with self.ssh as s:
            with open(self.p, 'wb') as fh:
                fh.write(b'old')
            fs = self.files()
            F.write_files(self.t, s, fs, self.d, options={'backup_format': 'folder'})
            F.drop_previous(self.t, s, fs, {'backup_format': 'folder'})
            self.assertEqual(len(os.listdir(os.path.join(self.d, F.FOLDER))), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
