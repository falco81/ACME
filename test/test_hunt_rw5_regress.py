"""Hunt w5: a regression review of 1.0.143 (since release 1.0.142).

    python3 test/test_hunt_rw5_regress.py
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402


class StandIns(unittest.TestCase):
    """What happens of a webhook deployment: its More headers (a secret since 1.0.143) were one
    stand-in with no colon - the module sent none of them, the request shown lacked them."""

    def test_webhook_headers_kept_by_name(self):
        from acmelib.certs import runplan as R
        from acmelib.plugins.targets import webhook as W
        s = R.Secrets()
        out, marks = s.stand_ins(W.WebhookTarget.fields, {
            'url': 'https://h.example/x',
            'headers': 'Authorization: Bearer TOPSECRET-123\nX-Env: production-eu'})
        got = out['headers']
        self.assertNotIn('TOPSECRET', got)
        self.assertNotIn('production-eu', got)
        lines = got.splitlines()
        self.assertTrue(lines[0].startswith('Authorization: Bearer '), got)
        self.assertTrue(lines[1].startswith('X-Env: '), got)
        self.assertIn('More headers: X-Env', marks.values())
        # what the module sends from it: both headers, their values stand-ins
        t = W.WebhookTarget.__new__(W.WebhookTarget)
        t.config = out
        t.c = lambda k, d=None: out.get(k, d)
        h = t.headers(b'{}')
        self.assertIn('X-Env', h)
        self.assertIn('Authorization', h)
        # the real values are scrubbed at the end
        self.assertIn('TOPSECRET-123', ' '.join(s.real))

    def test_other_secret_one_stand_in(self):
        from acmelib.certs import runplan as R
        s = R.Secrets()
        out, marks = s.stand_ins([{'key': 'headers', 'type': 'secret', 'multiline': True}],
                                 {'headers': 'no header at all'})
        self.assertNotIn('no header', out['headers'])
        out, marks = s.stand_ins([{'key': 'password', 'type': 'secret'}],
                                 {'password': 'Name: value'})
        self.assertNotIn('value', out['password'])


class Store(unittest.TestCase):
    def test_sealed_kept_list(self):
        from acmelib.certs import store as S
        self.assertEqual(S._list_text(['A: b', ' ', 'C: d']), 'A: b\nC: d')
        self.assertEqual(S._list_text('x'), 'x')


class Daemon(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']
    py = TCC.CertsCore.__dict__['py']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def raw(self, table, ident):
        return self.py('r = st.db.row("SELECT config FROM %s WHERE id = ?", (%d,))\n'
                       'print(json.dumps(r["config"]))' % (table, ident))

    def as_142(self, table, ident, value):
        """The headers as 1.0.142 kept them: a list in clear."""
        self.py('r = st.db.row("SELECT config FROM %s WHERE id = ?", (%d,))\n'
                'c = json.loads(r["config"]); c["headers"] = %r\n'
                'st.db.run("UPDATE %s SET config = ? WHERE id = ?", (json.dumps(c), %d))\n'
                'print(1)' % (table, ident, value, table, ident))

    def test_list_sealed_at_first_use(self):
        """The change log says a list kept from before is sealed at its first use: it never
        was (its text compared with the list)."""
        tid = self.ok('POST', '/api/targets/save', {
            'name': 'w5hook', 'kind': 'webhook',
            'config': {'url': 'https://hooks.example.test/z'}})['id']
        self.as_142('cert_targets', tid, ['Authorization: Bearer OLD-W5-TOKEN', 'X-Env: prod'])
        self.assertIn('OLD-W5-TOKEN', self.raw('cert_targets', tid))
        got = self.py('from acmelib.certs import store as S\n'
                      'r = st.db.row("SELECT * FROM cert_targets WHERE id = ?", (%d,))\n'
                      'print(json.dumps(S.plugin_config("target", r)["headers"]))' % tid)
        self.assertEqual(got, 'Authorization: Bearer OLD-W5-TOKEN\nX-Env: prod')
        raw = self.raw('cert_targets', tid)
        self.assertNotIn('OLD-W5-TOKEN', raw)
        self.assertTrue(json.loads(raw)['headers'].startswith('sealed:'))
        # and opened again from the sealed one: the same
        got = self.py('from acmelib.certs import store as S\n'
                      'r = st.db.row("SELECT * FROM cert_targets WHERE id = ?", (%d,))\n'
                      'print(json.dumps(S.plugin_config("target", r)["headers"]))' % tid)
        self.assertEqual(got, 'Authorization: Bearer OLD-W5-TOKEN\nX-Env: prod')

    def test_list_sealed_when_saved_unchanged(self):
        """Saved again from the page (the secret as dots or empty): the list kept from before
        stayed a list in clear."""
        tid = self.ok('POST', '/api/targets/save', {
            'name': 'w5hook2', 'kind': 'webhook',
            'config': {'url': 'https://hooks.example.test/a'}})['id']
        self.as_142('cert_targets', tid, ['Authorization: Bearer OLD-W5-SAVE'])
        self.ok('POST', '/api/targets/save', {'id': tid, 'name': 'w5hook2', 'kind': 'webhook',
                                               'config': {'url': 'https://hooks.example.test/b',
                                                          'headers': ''}})
        raw = self.raw('cert_targets', tid)
        self.assertNotIn('OLD-W5-SAVE', raw)
        self.assertTrue(json.loads(raw)['headers'].startswith('sealed:'))
        got = self.py('from acmelib.certs import store as S\n'
                      'r = st.db.row("SELECT * FROM cert_targets WHERE id = ?", (%d,))\n'
                      'print(json.dumps(S.plugin_config("target", r)["headers"]))' % tid)
        self.assertEqual(got, 'Authorization: Bearer OLD-W5-SAVE')


if __name__ == '__main__':
    unittest.main()
