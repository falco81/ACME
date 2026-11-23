#!/usr/bin/env python3
"""Hunt R run t9, the root helper (deploy/acme_web.py): what was found and is fixed - each checked.

    python3 test/test_hunt_rt9_roothelper.py

* PostgreSQL's folders (pg_hba.conf's, the data folder) were checked by pg_path_checked() and then
  used by their path: the postgres account, whose home holds them, put a link to another folder
  (/etc/profile.d) in place of the checked one while root waited on PostgreSQL's answer - and root
  wrote the file there, owned by postgres, its text postgres's (root ran it at its next login).
  Now the folder is used through one descriptor, refused when it is not the one checked.
* The list of ports acme labelled for nginx (selinux-ports) was written by its path in the acme
  account's web folder: a link put in place of that folder had root write it anywhere. Now
  through the folder's one descriptor, as every other file there.
"""
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-huntrt9rh-')
STATE = os.path.join(TMP, 'state')
os.makedirs(os.path.join(STATE, 'web'))
os.environ.update(ACME_STATE=STATE, ACME_VIP_NO_SERVICES='1',
                  ACME_NET_SNAP_DIR=os.path.join(TMP, 'root-only'))
sys.path.insert(0, os.path.join(ROOT, 'deploy'))
import acme_web as W  # noqa: E402

ME = pwd.getpwuid(os.getuid())


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class PgFolderSwapped(unittest.TestCase):
    def setUp(self):
        getattr(W, 'PG_DIRS', {}).clear()
        self.base = tempfile.mkdtemp(dir=TMP)
        self.data = os.path.join(self.base, 'pgsql', 'data')
        os.makedirs(self.data)
        self.other = os.path.join(self.base, 'profile.d')        # a folder of root's
        os.makedirs(self.other)
        with open(os.path.join(self.other, 'lang.sh'), 'w') as f:
            f.write('# the system\'s own\n')
        self.hba = os.path.join(self.data, 'lang.sh')
        with open(self.hba, 'w') as f:
            f.write('touch /tmp/owned\nhost acme acme 192.0.2.7/32 scram-sha-256\n')
        self.swap = True

    def sql(self, port, q, db='postgres'):
        if q == 'SHOW hba_file':
            return self.hba
        if 'pg_hba_file_rules' in q:
            if self.swap and not os.path.islink(self.data):
                os.rename(self.data, self.data + '.real')
                os.symlink(self.other, self.data)
            return '0'
        return ''

    def go(self, fn, r):
        with mock.patch.object(W, 'pg_sql', self.sql), mock.patch('pwd.getpwnam', lambda n: ME):
            return fn(dict({'peer': '192.0.2.7', 'db': 'acme', 'user': 'acme', 'port': 5432}, **r))

    def test_hba_swapped_for_a_link_refused(self):
        with self.assertRaises(W.Refused):
            self.go(W.pgtls_hba, {})
        with open(os.path.join(self.other, 'lang.sh')) as f:
            self.assertEqual(f.read(), '# the system\'s own\n')
        self.assertEqual(sorted(os.listdir(self.other)), ['lang.sh'])

    def test_peer_swapped_for_a_link_refused(self):
        with self.assertRaises(W.Refused):
            self.go(W.pgtls_peer, {'peer': '192.0.2.8', 'old_peer': '192.0.2.7'})
        self.assertEqual(sorted(os.listdir(self.other)), ['lang.sh'])

    def test_as_before_without_a_swap(self):
        self.swap = False
        got = self.go(W.pgtls_hba, {})
        self.assertIn('hostssl', got['said'])
        with open(self.hba) as f:
            self.assertIn('hostssl acme acme 192.0.2.7/32', f.read())
        with open(self.hba + '.acme-before-tls') as f:
            self.assertIn('\nhost acme acme', f.read())
        self.assertFalse([n for n in os.listdir(self.data) if n.startswith('.acme-')])

    def test_put_keeps_mode_and_owner(self):
        p = os.path.join(self.data, 'x.conf')
        W.pg_file_put(p, 'a\n', 0o640, os.getuid(), os.getgid())
        st = os.lstat(p)
        self.assertEqual(oct(st.st_mode & 0o777), oct(0o640))
        self.assertEqual(W.pg_file_read(p), 'a\n')
        W.pg_file_unlink(p)
        self.assertFalse(os.path.exists(p))


class SelinuxPortsList(unittest.TestCase):
    class R:
        def __init__(self, rc=0, out=''):
            self.returncode, self.stdout, self.stderr = rc, out, ''

    def run_cmd(self, cmd, **k):
        return self.R()

    def label(self, port):
        with mock.patch.object(W, 'NO_SERVICES', False), \
                mock.patch.object(W.shutil, 'which', lambda n: '/usr/sbin/' + n), \
                mock.patch.object(W.subprocess, 'run', self.run_cmd):
            return W.certlogin_selinux(port)

    def test_written_in_the_web_folder(self):
        self.assertIn('http_port_t', self.label(9443))
        self.assertIn('http_port_t', self.label(9444))
        self.assertEqual(W.selinux_ports_read(), [9443, 9444])
        self.assertTrue(os.path.isfile(os.path.join(STATE, 'web', 'selinux-ports')))

    def test_web_folder_a_link_nothing_written_there(self):
        state = os.path.join(TMP, 'state2')
        other = os.path.join(TMP, 'elsewhere')
        os.makedirs(state)
        os.makedirs(other)
        os.symlink(other, os.path.join(state, 'web'))
        with mock.patch.object(W, 'FD', [None]), mock.patch.object(W, 'STATE_DIR', state), \
                mock.patch.object(W, 'WEB_DIR', os.path.join(state, 'web')), \
                mock.patch.object(W, 'SELINUX_PORTS', os.path.join(state, 'web', 'selinux-ports')):
            self.label(9445)
            self.assertEqual(W.selinux_ports_read(), [])
        self.assertEqual(os.listdir(other), [])


if __name__ == '__main__':
    unittest.main()
