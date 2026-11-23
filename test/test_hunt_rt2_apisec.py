#!/usr/bin/env python3
"""Bug hunt R run t2, area apisec: the HTTP routes added since 1.0.124 (the teams' admin routes,
the portal's team workspace, the pages that relay them) - each found with requests against a
running daemon.

    python3 test/test_hunt_rt2_apisec.py

- POST /api/teams/from_groups (dry_run) told a scoped certificate administrator which teams of
  the others each directory group is a member of - GET /api/teams hides those teams' members
  from them. Only the teams they see now (a full administrator: all, as before).
- GET /api/portal/agent_builder (target.view) named every certificate deployed to the team's
  device - acme's own and other teams' - where GET /api/portal/device says "another owner's
  certificate"; the agent's keys_of (portal agent, device) the same. Now as the device says.
- web/admin/index.php relayed GET /api/agents/discover (up to 180 s at the agent) and
  /api/agents/adcs (two asks of 120 s) with 60 s: "the daemon is not answering" while the agent
  was still being asked (the page waits 240 s; the portal relays with 240 s). Now 250 s.
"""
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import threading
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)
import mockldap                      # noqa: E402

BASE = 'DC=corpnet,DC=loc'


class Daemon(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        TCC.CertsCore.setUpClass.__func__(cls)
        # the daemon's output read, or it stops at a full pipe
        threading.Thread(target=lambda: [None for _ in iter(
            lambda: cls.daemon.stdout.read(4096), b'')], daemon=True).start()
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 100,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self',
            'mail_mode': 'off', 'certs_agents_active': 1, 'portal_directory': 'corp'}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        for u in ('rt2owner', 'rt2viewer'):
            cls.must('POST', '/api/users', {'action': 'add', 'name': u, 'role': 'readonly',
                                            'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/teams/save', {'name': 'Top', 'kind': 'unit'})
        cls.must('POST', '/api/teams/save', {'name': 'Web', 'parent': 'Top', 'members': [
            {'who': 'local:rt2owner', 'roles': ['Team owner']},
            {'who': 'local:rt2viewer', 'roles': ['Viewer']}]})
        cls.must('POST', '/api/teams/save', {'name': 'Other', 'parent': 'Top'})
        # a team of the others, a directory group its member
        cls.must('POST', '/api/teams/save', {'name': 'Secret', 'members': [
            {'who': 'group:CERT_USERS', 'roles': ['Team owner']}]})

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)
        cls.ldap_stop.set()

    @classmethod
    def must(cls, method, path, body=None, session=None, args=None):
        st, got = cls.call(method, path, body, session or cls.admin, args)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def portal(self, name):
        st, got = self.call('POST', '/api/portal/login', {'name': name, 'password': self.pw})
        self.assertEqual(st, 200, got)
        return got['token']

    def test_from_groups_preview_keeps_other_teams_members(self):
        self.must('POST', '/api/settings', {'settings': {'certs_certadmin_all': 0}})
        try:
            # /api/teams hides the members of Secret from the scoped certificate administrator
            got = self.must('GET', '/api/teams', session=self.cert_admin)
            sec = [t for t in got['teams'] if t['name'] == 'Secret'][0]
            self.assertEqual(sec['members'], [])
            got = self.must('POST', '/api/teams/from_groups', {'filter': 'CERT_*',
                                                               'dry_run': True},
                            session=self.cert_admin)
            one = [g for g in got['groups'] if g['cn'] == 'CERT_USERS'][0]
            self.assertEqual(one['member_of'], [], got)
            # still a preview only for them
            st, _ = self.call('POST', '/api/teams/from_groups', {'filter': 'CERT_*'},
                              self.cert_admin)
            self.assertEqual(st, 403)
        finally:
            self.must('POST', '/api/settings', {'settings': {'certs_certadmin_all': 1}})
        # unscoped, and a full administrator: as before
        for sess in (self.cert_admin, self.admin):
            got = self.must('POST', '/api/teams/from_groups', {'filter': 'CERT_*',
                                                               'dry_run': True}, session=sess)
            one = [g for g in got['groups'] if g['cn'] == 'CERT_USERS'][0]
            self.assertEqual(one['member_of'], ['Secret'])

    def test_agent_builder_names_no_other_owners_certificate(self):
        tid = self.must('POST', '/api/targets/save', {
            'name': 'rt2-agent', 'kind': 'agent', 'owner': 'Web',
            'config': {'mode': 'passive', 'host': 'a.example.test'}})['id']
        ids = {}
        for name, owner in (('rt2-acme-own', ''), ('rt2-other-team', 'Other'),
                            ('rt2-web-own', 'Web')):
            ids[name] = self.must('POST', '/api/certs/save', {
                'name': name, 'names': ['%s.example.test' % name], 'issuer': 'self',
                'key_type': 'ec-256', 'auto_renew': 0, 'owner': owner})['id']
            self.must('POST', '/api/deploys/save', {'cert_id': ids[name], 'target': 'rt2-agent',
                                                    'options': {}})
        for who in ('rt2viewer', 'rt2owner'):
            s = self.portal(who)
            for route in ('device', 'agent', 'agent_builder'):
                st, got = self.call('GET', '/api/portal/' + route, None, s, {'id': tid})
                self.assertEqual(st, 200, (who, route, got))
                text = json.dumps(got)
                self.assertNotIn('rt2-acme-own', text, (who, route))
                self.assertNotIn('rt2-other-team', text, (who, route))
            # the team's own certificate named as before
            got = self.must('GET', '/api/portal/agent_builder', session=s, args={'id': tid})
            certs = sorted(n['cert'] for n in got['needs'])
            self.assertIn('rt2-web-own', certs)
            self.assertEqual(certs.count("another owner's certificate"), 2, certs)
        # the administration: every name, as before
        got = self.must('GET', '/api/agents/builder', args={'id': tid})
        self.assertIn('rt2-acme-own', json.dumps(got))


class AdminRelay(unittest.TestCase):
    """The administration's page relays a discovery (and the CAs an agent reads) as long as the
    agent may take - a daemon of its own answers after 62 s."""
    SLOW = 62

    def test_discovery_relayed_past_a_minute(self):
        if not shutil.which('php'):
            self.skipTest('no php here')
        tmp = tempfile.mkdtemp(prefix='acme-rt2-apisec-')
        try:
            self.run_in(tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def run_in(self, tmp):
        web, run = os.path.join(tmp, 'web'), os.path.join(tmp, 'run')
        os.makedirs(run)
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        p = os.path.join(web, 'acme-api.php')
        with open(p, encoding='utf-8') as f:
            text = f.read()
        with open(p, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', run + '/'))
        dport, pport = TCC.free_port(), TCC.free_port()
        with open(os.path.join(run, 'api-port'), 'w') as f:
            f.write(str(dport))
        with open(os.path.join(run, 'api-token'), 'w') as f:
            f.write('token')
        slow = self.SLOW

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path.startswith(('/api/agents/discover', '/api/agents/adcs')):
                    time.sleep(slow)
                body = json.dumps({'ok': True, 'path': self.path}).encode()
                try:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', dport), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % pport], cwd=web,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='3'))
        got = {}
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    socket.create_connection(('127.0.0.1', pport), 1).close()
                    break
                except OSError:
                    time.sleep(0.2)

            def ask(what):
                req = urllib.request.Request(
                    'http://127.0.0.1:%d/admin/?api=%s&target=srv' % (pport, what),
                    headers={'Cookie': 'acme_session=abc', 'Sec-Fetch-Site': 'same-origin'})
                try:
                    with urllib.request.urlopen(req, timeout=300) as r:
                        got[what] = (r.status, json.loads(r.read().decode()))
                except urllib.error.HTTPError as e:
                    got[what] = (e.code, e.read().decode()[:300])
            ts = [threading.Thread(target=ask, args=(w,)) for w in ('agents-discover',
                                                                      'agents-adcs')]
            for t in ts:
                t.start()
            for t in ts:
                t.join(320)
        finally:
            php.terminate()
            php.wait(10)
            srv.shutdown()
            srv.server_close()
        self.assertEqual(got['agents-discover'][0], 200, got)
        self.assertEqual(got['agents-discover'][1]['path'], '/api/agents/discover?target=srv')
        self.assertEqual(got['agents-adcs'][0], 200, got)


if __name__ == '__main__':
    unittest.main(verbosity=2)
