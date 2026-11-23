#!/usr/bin/env python3
"""Hunt 1.0.141, run v2, area sec: the security fixes of this round.

- the agents' routes of the administration (/api/agents, /one, /builder, /deployguard) named the
  certificates of other teams deployed to a target's agent (the builder's needs and "Allowed
  names", the certificates whose key the agent makes) to a session kept to its teams - as the
  portal's builder did before it was fixed; a session that sees everything sees them all still;
- /api/teams told a scoped session how many certificates each team it does not see holds;
- viewing as a member: a certificate the member may not see, looked at meanwhile, was noted as the
  member's own refused attempt; a periodic report's file could be downloaded (noted as the
  member's download);
- admin/index.php relayed one part after the family only: agents/keyplace/switch,
  agents/guard/verify, agents/keys/rotate... were "unknown endpoint" from the pages.

    python3 test/test_hunt_rv2_sec.py
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_f140_ui as U  # noqa: E402  (its store, H, cert())

from acmelib import engine as E  # noqa: E402
from acmelib.certs import teams as T, viewas as VA  # noqa: E402

STORE = U.STORE


class H(U.H):
    """U.H whose me() holds to the role a route asks for."""
    def me(self, r='readonly'):
        if E.ROLE_RANK.get(self.role, 0) < E.ROLE_RANK.get(r, 0):
            raise E.ApiError(403, 'no')
        return U.H.me(self, r)


def call(method, path, body=None, **kw):
    return E.ROUTES[(method, path)](H(body=body, **kw))


def setup():
    U.setup()
    STORE.db.run('DELETE FROM cert_deploys')
    T.save_team(STORE, {'name': 'Opsx', 'members': ['local:zed=manage']}, 'x')
    oc = U.cert('opscertq', 20, owner='Opsx', names=['opsnameq.example.test'],
                csr_from='opstgtq')
    wc = U.cert('webcertq', 20, owner='Web', names=['webnameq.example.test'])
    STORE.db.insert('cert_targets', {'name': 'opstgtq', 'kind': 'agent', 'config': '{}',
                                     'enabled': 1, 'owner': 'Opsx'})
    STORE.db.insert('cert_deploys', {'cert_id': oc, 'target': 'opstgtq', 'enabled': 1})
    STORE.db.insert('cert_deploys', {'cert_id': wc, 'target': 'opstgtq', 'enabled': 1})
    tid = STORE.db.row("SELECT id FROM cert_targets WHERE name = 'opstgtq'")['id']
    return oc, wc, tid


class AgentsScoped(unittest.TestCase):
    def setUp(self):
        self.oc, self.wc, self.tid = setup()

    def tearDown(self):
        E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1)

    def text(self, path, role, **args):
        return json.dumps(call('GET', path, who='mgr', role=role,
                               args=dict({'id': str(self.tid)}, **args)), default=str)

    def test_everything_seen_unscoped(self):
        for path in ('/api/agents/builder', '/api/agents/deployguard'):
            got = self.text(path, 'certadmin')
            self.assertIn('opsnameq' if 'guard' in path else 'opscertq', got, path)
        one = call('GET', '/api/agents/one', who='mgr', role='readonly', args={'id': str(self.tid)})
        self.assertEqual(one['keys_of'], ['opscertq'])

    def test_other_teams_not_named(self):
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        for role in ('certadmin', 'readonly'):
            for path in ('/api/agents', '/api/agents/one', '/api/agents/builder',
                         '/api/agents/deployguard'):
                got = self.text(path, role)
                self.assertNotIn('opscertq', got, (role, path))
                self.assertNotIn('opsnameq', got, (role, path))
        b = call('GET', '/api/agents/builder', who='mgr', role='certadmin',
                 args={'id': str(self.tid)})
        self.assertEqual(sorted(n['cert'] for n in b['needs']),
                         ['another owner\'s certificate', 'webcertq'])
        self.assertEqual(b['guard']['names'], ['webnameq.example.test'])
        g = call('GET', '/api/agents/deployguard', who='mgr', role='readonly',
                 args={'id': str(self.tid)})
        self.assertEqual(g['names'], ['webnameq.example.test'])
        rows = call('GET', '/api/agents', who='mgr', role='readonly')['rows']
        self.assertEqual([r['keys_of'] for r in rows if r['name'] == 'opstgtq'], [[]])


class TeamsCounts(unittest.TestCase):
    def setUp(self):
        setup()

    def tearDown(self):
        E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1)

    def test_used_of_unseen_teams(self):
        got = {t['name']: t for t in call('GET', '/api/teams', who='mgr', role='certadmin')['teams']}
        self.assertEqual(got['Opsx']['used'], 1)
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        got = {t['name']: t for t in call('GET', '/api/teams', who='mgr', role='certadmin')['teams']}
        self.assertIsNone(got['Opsx']['used'])
        self.assertEqual(got['Web']['used'], 1)


class ViewAs(unittest.TestCase):
    def setUp(self):
        self.oc, _wc, _tid = setup()

    def tearDown(self):
        E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1)

    def test_refusal_noted_as_the_admin(self):
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        s = {'name': 'mgr', 'role': 'certadmin', 'view_as_by': 'boss',
             'account': {'name': 'mgr', 'role': 'certadmin', 'source': 'local'}}
        n0 = STORE.db.value('SELECT MAX(id) FROM events', (), 0) or 0
        with self.assertRaises(E.ApiError):
            T.deny(STORE, s, 'look at opscertq', 'view')
        ev = STORE.db.rows('SELECT * FROM events WHERE id > ?', (n0,))
        self.assertEqual(len(ev), 1)
        words = json.dumps(ev[0], default=str)
        self.assertIn('boss, viewing the pages as mgr (read-only), was refused', words)
        self.assertEqual(ev[0].get('who'), 'boss')
        # not viewing as: as before
        with self.assertRaises(E.ApiError):
            T.deny(STORE, dict(s, view_as_by=None), 'look at opscertq', 'view')
        ev = STORE.db.rows('SELECT * FROM events WHERE id > ? ORDER BY id', (n0,))
        self.assertIn('mgr was refused: look at opscertq', json.dumps(ev[-1], default=str))

    def test_report_download_refused(self):
        tok = STORE.session_new('admin', 'boss', 'fulladmin', '127.0.0.1', 2,
                                {'view_as': {'who': 'local:mgr', 'by': 'boss',
                                             'since': time.time()}})

        class R(object):
            store = STORE
            headers = {'X-Acme-Session': tok}
        self.assertIsNotNone(VA.refused(R(), 'GET', '/api/reports/download'))
        self.assertIsNone(VA.refused(R(), 'GET', '/api/reports'))
        R.headers = {'X-Acme-Session': 'nothing'}
        self.assertIsNone(VA.refused(R(), 'GET', '/api/reports/download'))


class Relay(unittest.TestCase):
    """admin/index.php: an API route of two parts after its family relayed (php -S)."""

    def test_two_parts(self):
        php = shutil.which('php')
        if not php:
            self.skipTest('no php here')
        sk = socket.socket()
        sk.bind(('127.0.0.1', 0))
        port = sk.getsockname()[1]
        sk.close()
        p = subprocess.Popen([php, '-S', '127.0.0.1:%d' % port, '-t', os.path.join(ROOT, 'web')],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            def ask(what):
                req = urllib.request.Request(
                    'http://127.0.0.1:%d/admin/index.php?api=%s' % (port, what), data=b'{}',
                    headers={'Content-Type': 'application/json',
                             'Origin': 'http://127.0.0.1:%d' % port,
                             'Sec-Fetch-Site': 'same-origin'}, method='POST')
                try:
                    return urllib.request.urlopen(req, timeout=10).read().decode()
                except urllib.error.HTTPError as e:
                    return e.read().decode()
            end = time.time() + 10
            while True:
                try:
                    got = ask('agents/keyplace')
                    break
                except OSError:
                    if time.time() > end:
                        raise
                    time.sleep(0.2)
            self.assertNotIn('unknown endpoint', got)
            for ok in ('agents/keyplace/switch', 'agents/guard/verify', 'agents/keys/rotate',
                       'agents/enroll/revoke', 'agents/design/forget'):
                self.assertNotIn('unknown endpoint', ask(ok), ok)
            for bad in ('agents/a/b/c', 'agents/../db', 'agents/keyplace/Switch',
                        'agents//keyplace', 'db/a/b'):
                self.assertIn('unknown endpoint', ask(bad), bad)
        finally:
            p.terminate()
            p.wait(10)


if __name__ == '__main__':
    unittest.main(verbosity=2)
