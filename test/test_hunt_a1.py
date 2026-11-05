#!/usr/bin/env python3
"""The hunt of 1.0.45, round 1 (the API's rights, the root helper, the pages) - each checked.

    python3 test/test_hunt_a1.py
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-hunta1-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_NET_SNAP_DIR=os.path.join(TMP, 'root-only'))
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402
from acmelib.certs import portal as P  # noqa: E402
from acmelib.plugins import base as B  # noqa: E402

spec = importlib.util.spec_from_file_location('acme_web_a1', os.path.join(ROOT, 'deploy', 'acme_web.py'))
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


class Portal(unittest.TestCase):
    def s(self, role):
        return {'name': 'x', 'data': {'kind': 'local', 'role': role}}

    def test_sees_all_follows_the_administration(self):
        with mock.patch.dict(E.CONFIG, {'portal_admins_all': 1, 'certs_certadmin_all': 0}):
            self.assertTrue(E.portal_sees_all(self.s('fulladmin')))
            self.assertFalse(E.portal_sees_all(self.s('certadmin')))
        with mock.patch.dict(E.CONFIG, {'portal_admins_all': 1, 'certs_certadmin_all': 1}):
            self.assertTrue(E.portal_sees_all(self.s('certadmin')))

    def test_the_key_only_to_a_full_administrator_who_sees_all(self):
        with mock.patch.dict(E.CONFIG, {'portal_admins_all': 1, 'certs_certadmin_all': 1}):
            self.assertFalse(P.key_may(self.s('certadmin'), '*', list(P.ALL_RIGHTS)))
            self.assertTrue(P.key_may(self.s('fulladmin'), '*', list(P.ALL_RIGHTS)))
            self.assertTrue(P.key_may(self.s('certadmin'), 'me', []))

    def test_owner_names_from_the_directory_only(self):
        s = {'name': 'falco', 'data': {'kind': 'directory', 'login': 'B\\falco',
                                       'about': {'sam': 'falco', 'upn': 'falco@a.cz'}}}
        self.assertNotIn('b\\falco', P.my_names(s))
        self.assertIn('falco@a.cz', P.my_names(s))

    def test_wildcard_waits(self):
        self.assertIn("not any(n.startswith('*.') for n in names)", read('acmelib', 'certs', 'portal.py'))

    def test_gate_before_password(self):
        src = read('acmelib', 'engine', [n for n in os.listdir(os.path.join(ROOT, 'acmelib', 'engine'))
                                         if n.startswith('390_')][0])
        self.assertIn("if portal_must_change(s) and not gate_ok:", src)
        self.assertIn("raise ApiError(401, 'type the code that was sent to you first')", src)

    def test_approve_guard_reads_as_the_route(self):
        self.assertIn("row = cert_of_ref(store, b.get('id'))", read('acmelib', 'certs', 'teams.py'))


class Helper(unittest.TestCase):
    def test_realip_no_scope_id(self):
        with self.assertRaises(W.Refused):
            W.realip_checked({'from': ['fe80::1%eth0\n}\nserver {']})
        self.assertEqual(W.realip_checked({'from': ['10.0.0.0/8']})[0], ['10.0.0.0/8'])

    def test_pg_not_the_servers_own(self):
        base = {'id': 'abcdef0123', 'do': 'peer', 'db': 'acme', 'user': 'acme', 'peer': '192.0.2.2'}
        for k, v in (('db', 'postgres'), ('db', 'template1'), ('user', 'postgres'),
                     ('user', 'pg_monitor')):
            with self.assertRaises(W.Refused, msg=(k, v)):
                W.pgtls_checked(dict(base, **{k: v}))

    def test_restorecon_not_recursive_on_a_users_folder(self):
        self.assertIn("['restorecon', '--', folder, path]", read('deploy', 'acme_web.py'))

    def test_ps_no_arguments(self):
        self.assertIn("'label,user,pid,comm']", read('deploy', 'acme_web.py'))


class Plugins(unittest.TestCase):
    def test_root_loads_only_roots_own(self):
        d = tempfile.mkdtemp(prefix='acme-rp-')
        f = os.path.join(d, 'm.py')
        with open(f, 'w') as fh:
            fh.write('x = 1\n')
        os.chmod(d, 0o755)
        os.chmod(f, 0o644)
        if os.geteuid() == 0:
            self.assertTrue(B._roots_own(d, f))
            os.chmod(f, 0o666)
            self.assertFalse(B._roots_own(d, f))
            os.chmod(f, 0o644)
            os.chown(f, 65534, -1)
            self.assertFalse(B._roots_own(d, f))


class Pages(unittest.TestCase):
    def test_downloads_from_the_page_only(self):
        php = read('web', 'admin', 'index.php')
        self.assertEqual(php.count("HTTP_X_ACME_DOWNLOAD"), 2)
        self.assertEqual(php.count("!acme_dl_ok("), 2)
        js = read('web', 'assets', 'admin.js')
        self.assertIn("api('dl-ticket'", js)
        self.assertNotIn("window.location.href = '?api=", js)


if __name__ == '__main__':
    unittest.main()
