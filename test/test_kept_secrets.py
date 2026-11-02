#!/usr/bin/env python3
"""A module's kept secrets are not sent elsewhere by a settings change nobody saved.

    python3 test/test_kept_secrets.py

Test (a source, a validation, a target), Try reaching it and the SSH DNS
discovery take the form's settings over the saved ones and keep the saved
secrets where the form sends dots. Only a full administrator may save those
settings, so a certificate administrator who changed the API address (or the
host) and tried it sent the kept API key, password or TSIG there (1.0.19):
that is refused now; tried as saved, or with the secrets typed in again, it
is not.
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-kept-secrets-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import api_readiness, api_sshkeys  # noqa: E402,F401  (the routes)

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DOTS = '•' * 8


class FakeH(object):
    def __init__(self, role, body=None):
        self.store, self.role, self._body = STORE, role, body or {}

    def me(self, _role):
        return {'name': 'someone', 'role': self.role}

    def body(self):
        return self._body


class KeptSecrets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wg = A.family_save(STORE, 'challenge', {
            'name': 'wg-kept', 'kind': 'webglobe', 'config': {
                'login': 'me@example.cz', 'auth': 'token', 'api_token': 'TOKEN-kept-1',
                'endpoint': 'production', 'api': ''}}, 'tester')
        cls.ssh = A.family_save(STORE, 'challenge', {
            'name': 'sshdns-kept', 'kind': 'ssh_dns', 'config': {
                'host': 'ns1.example.com', 'user': 'acme', 'password': 'SshPw-kept-2'}},
            'tester')

    def call(self, path, role, body):
        return E.ROUTES[('POST', path)](FakeH(role, body))

    def refused(self, path, body):
        with self.assertRaises(E.ApiError) as e:
            self.call(path, 'certadmin', body)
        self.assertEqual(e.exception.status, 403)
        self.assertIn('secrets kept', str(e.exception))

    def test_another_api_address_with_the_kept_key_is_refused(self):
        self.refused('/api/validations/test', {'id': self.wg, 'config': {
            'login': 'me@example.cz', 'auth': 'token', 'api_token': DOTS,
            'endpoint': 'production', 'api': 'https://collector.example.net'}})
        self.refused('/api/validations/test', {'id': self.wg, 'config': {
            'api': 'https://collector.example.net', 'api_token': ''}})

    def test_another_host_for_discovery_or_try_is_refused(self):
        self.refused('/api/validations/ssh_dns_discover', {'id': self.ssh, 'config': {
            'host': 'collector.example.net', 'password': DOTS}})
        self.refused('/api/sshkey/try', {'family': 'challenge', 'id': self.ssh, 'config': {
            'host': 'collector.example.net', 'password': ''}})

    def test_as_saved_or_secrets_given_again_or_full_admin_pass(self):
        fake = FakeH('certadmin')
        s = {'role': 'certadmin'}
        same = {'id': self.wg, 'config': {'login': 'me@example.cz ', 'auth': 'token',
                                          'api_token': DOTS, 'endpoint': 'production',
                                          'api': '', 'ttl': '300'}}
        A.kept_secrets_guard(fake.store, 'challenge', same, s)            # as saved
        A.kept_secrets_guard(fake.store, 'challenge', {'id': self.ssh, 'config': {
            'host': 'ns1.example.com', 'user': 'acme', 'password': DOTS, 'zones': [],
            'sudo': False, 'ttl': 60}}, s)                                  # the form's way
        A.kept_secrets_guard(fake.store, 'challenge', {'id': self.wg}, s)  # no form at all
        own = {'id': self.wg, 'config': {'api': 'https://other.example.net',
                                         'api_token': 'typed-in-again', 'password': ''}}
        A.kept_secrets_guard(fake.store, 'challenge', own, s)             # nothing kept used
        changed = {'id': self.wg, 'config': {'api': 'https://other.example.net'}}
        A.kept_secrets_guard(fake.store, 'challenge', changed, {'role': 'fulladmin'})
        with self.assertRaises(E.ApiError):
            A.kept_secrets_guard(fake.store, 'challenge', changed, s)


class UrlInSteps(unittest.TestCase):
    """1.0.19: with debug on, every request a module made was written into the job's
    steps (shown on the pages) with its whole URL - Duck DNS's token and DreamHost's
    API key are in the query."""

    def test_query_secrets_are_dots(self):
        import http.server
        import threading
        from acmelib.certs import runtime

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'OK')

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        was = E.CONFIG.get('debug')
        E.CONFIG['debug'] = 1
        try:
            ctx = runtime.RunContext(STORE, None, scope='challenge:duck')
            st, _h, body = ctx.http('GET', 'http://127.0.0.1:%d/update?domains=me&token='
                                    'DuckTok-SECRET-9&txt=v&verbose=true' % srv.server_port,
                                    proxy=False)
            self.assertEqual((st, body), (200, b'OK'))
            said = ' '.join(x[2] for x in ctx.steps)
            self.assertIn('/update?domains=me&token=', said)
            self.assertNotIn('DuckTok-SECRET-9', said)
            self.assertIn('verbose=true', said)
        finally:
            E.CONFIG['debug'] = was
            srv.shutdown()
        self.assertNotIn('K-SECRET', runtime.url_shown(
            'https://api.dreamhost.com/?key=K-SECRET&format=json'))
        self.assertNotIn('pw-SECRET', runtime.url_shown('https://me:pw-SECRET@dav.example/x'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
