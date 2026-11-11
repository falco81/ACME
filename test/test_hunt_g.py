#!/usr/bin/env python3
"""Hunt G (1.0.79): what the bug hunt found and was put right.

    python3 test/test_hunt_g.py
"""
import base64
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-g-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
import test_targets as TT  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE


def setUpModule():
    TT.setUpModule()


def tearDownModule():
    TT.tearDownModule()


def src_of(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


class Accounts(unittest.TestCase):
    def test_portal_sign_ins_go_with_the_account(self):
        STORE.add_account('bobg', 'readonly', 'A-Long-Password-1!')
        STORE.session_new('portal', 'bobg', 'readonly', '127.0.0.1', 1, data={'kind': 'local'})
        STORE.drop_account('bobg')
        self.assertFalse(STORE.db.rows("SELECT id FROM sessions WHERE kind = 'portal' "
                                       "AND LOWER(name) = 'bobg'"))


class Targets(unittest.TestCase):
    def test_kubernetes_restart_cut_off_runs_again(self):
        b = TT.FakeBundle()
        data = {'tls.crt': base64.b64encode(b.fullchain_pem.encode()).decode()}
        ctx = TT.FakeCtx([
            ('GET', r'/secrets/web-tls$', (200, {'type': 'kubernetes.io/tls', 'data': data})),
            ('PATCH', r'/secrets/web-tls$', (200, {})),
            ('PATCH', r'/deployments/web$', (500, {})),
        ])
        t = TT.make('kubernetes', {'host': 'https://k8s:6443', 'token': 'BT',
                                   'namespace': 'prod'}, ctx)
        with self.assertRaises(Exception):
            t.deploy(b, {'secret': 'web-tls', 'restart': 'web', 'force': True})
        self.assertTrue(t.pending())
        ctx.routes = [r for r in ctx.routes if 'deployments' not in r[1]] + [
            ('PATCH', r'/deployments/web$', (200, {}))]
        got = t.deploy(b, {'secret': 'web-tls', 'restart': 'web'})
        self.assertIn('restarted web', got)
        self.assertFalse(t.pending())

    def test_nutanix_kept_per_cluster(self):
        ctx = TT.FakeCtx([])
        a = TT.make('nutanix', {'host': 'pc', 'cluster': 'one'}, ctx)
        b = TT.make('nutanix', {'host': 'pc', 'cluster': 'two'}, ctx)
        self.assertNotEqual(a.state_key({}), b.state_key({}))

    def test_windows_old_ones_by_the_whole_name(self):
        src = src_of('acmelib/plugins/targets/_win_roles.py')
        self.assertNotIn("-like ($prefix", src)

    def test_swarm_keeps_the_owner_and_mode(self):
        src = src_of('acmelib/plugins/targets/docker_swarm.py')
        self.assertIn("('UID', 'uid')", src)


class CommandLine(unittest.TestCase):
    def acme(self, *argv):
        import subprocess
        env = dict(os.environ)
        r = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(argv),
                           capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL,
                           timeout=120)
        return r.returncode, r.stdout + r.stderr

    def test_secrets_of_modules_not_written_out(self):
        for body in ('{"action":"save","directory":{"name":"x","bind_pw":"H"}}',):
            rc, said = self.acme('--api', 'POST', '/api/directories', body)
            self.assertNotEqual(rc, 0)
            self.assertIn('bind_pw', said)
        rc, said = self.acme('--api', 'POST', '/api/sources/save',
                             '{"name":"L","kind":"acme","config":{"eab_hmac":"S"}}')
        self.assertIn('eab_hmac', said)

    def test_set_with_another_option_refused(self):
        rc, said = self.acme('--local-policy', '--set', 'site_name=Y')
        self.assertNotEqual(rc, 0)
        self.assertIn('--set goes on its own', said)

    def test_empty_value_and_lone_option(self):
        rc, said = self.acme('--cert-del', '')
        self.assertIn('needs a value', said)
        rc, said = self.acme('--hosts', 'x')
        self.assertIn('asks for nothing alone', said)
        self.assertLess(len(said), 400)
        rc, said = self.acme('--limit', '40')
        self.assertIn('alone asks for nothing', said)

    def test_download_through_api_refused(self):
        rc, said = self.acme('--api', 'GET', '/api/db/download')
        self.assertIn('hands a file', said)
        self.assertNotIn('Traceback', said)


class Privacy(unittest.TestCase):
    def test_portal_code_event_masked(self):
        src = src_of('acmelib/engine/390_the_portal_sign_in.py')
        self.assertFalse(re.search(r"'SMS', dest\)", src))
        self.assertIn('dest_masked(kind, dest)', src)


if __name__ == '__main__':
    unittest.main(verbosity=2)
