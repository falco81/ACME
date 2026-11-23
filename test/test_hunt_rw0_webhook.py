"""1.0.143: the webhook target's "More headers" are kept sealed (a token goes there).

    python3 test/test_hunt_rw0_webhook.py
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


class Unit(unittest.TestCase):
    def test_field_is_secret(self):
        from acmelib.plugins.targets import webhook
        f = [x for x in webhook.Target.fields if x['key'] == 'headers'][0] \
            if hasattr(webhook, 'Target') else None
        if f is None:
            from acmelib.certs import store as S
            cls = S.registry().get('target', 'webhook')
            f = [x for x in cls.fields if x['key'] == 'headers'][0]
        self.assertEqual(f['type'], 'secret')
        self.assertTrue(f.get('multiline'))

    def test_list_under_a_secret_becomes_text(self):
        from acmelib.certs import store as S
        out, is_set = S.config_masked({'headers': ['A: b', 'C: d'], 'url': 'x'}, {'headers'})
        self.assertEqual(is_set, ['headers'])
        self.assertNotIn('A: b', json.dumps(out))


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

    def row(self, name):
        return self.py('r = st.db.row("SELECT id, config FROM cert_targets WHERE name = ?", (%r,))\n'
                       'print(json.dumps(r, default=str))' % name)

    def test_sealed_and_masked(self):
        tid = self.ok('POST', '/api/targets/save', {
            'name': 'hook1', 'kind': 'webhook',
            'config': {'url': 'https://hooks.example.test/x',
                       'headers': 'Authorization: Bearer TOPSECRET-123\nX-Env: prod'}})['id']
        raw = self.row('hook1')['config']
        self.assertNotIn('TOPSECRET', raw)
        self.assertIn('sealed:', json.loads(raw)['headers'])
        shown = json.dumps(self.ok('GET', '/api/targets'))
        self.assertNotIn('TOPSECRET', shown)
        # what the module sends: the headers opened
        got = self.py('from acmelib.certs import store as S\n'
                      'r = st.db.row("SELECT * FROM cert_targets WHERE id = ?", (%d,))\n'
                      'c = S.plugin_config("target", r)\n'
                      'print(json.dumps(c["headers"]))' % tid)
        self.assertIn('Authorization: Bearer TOPSECRET-123', got)
        # saved again without the headers (the page sends dots): kept
        self.ok('POST', '/api/targets/save', {'id': tid, 'name': 'hook1', 'kind': 'webhook',
                                               'config': {'url': 'https://hooks.example.test/y',
                                                          'headers': ''}})
        self.assertIn('sealed:', json.loads(self.row('hook1')['config'])['headers'])

    def test_old_list_in_clear_still_works(self):
        tid = self.ok('POST', '/api/targets/save', {
            'name': 'hook2', 'kind': 'webhook',
            'config': {'url': 'https://hooks.example.test/z'}})['id']
        # as 1.0.142 kept it: a list in clear
        self.py('r = st.db.row("SELECT config FROM cert_targets WHERE id = ?", (%d,))\n'
                'c = json.loads(r["config"]); c["headers"] = ["Authorization: Bearer OLD-9"]\n'
                'st.db.run("UPDATE cert_targets SET config = ? WHERE id = ?", (json.dumps(c), %d))\n'
                'print(1)' % (tid, tid))
        self.assertNotIn('OLD-9', json.dumps(self.ok('GET', '/api/targets')))
        got = self.py('from acmelib.certs import store as S\n'
                      'r = st.db.row("SELECT * FROM cert_targets WHERE id = ?", (%d,))\n'
                      'print(json.dumps(S.plugin_config("target", r)["headers"]))' % tid)
        self.assertIn('Authorization: Bearer OLD-9', got)


if __name__ == '__main__':
    unittest.main()
