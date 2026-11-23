"""Hunt w4 (1.0.143): secrets of the modules - kept sealed, never in steps or errors.

    python3 test/test_hunt_rw4_secrets.py

- the HTTPS test's "More headers" are a secret (sealed, masked, an old list still works),
  their values dots in What happens;
- a user name and password written in an http(s) address never reach an error text (the
  job's steps, the last error, isemon) or the Host line of What happens;
- Aruba Central's tokens kept in the module's state sealed, the form's refresh token only
  as a hash of it there.
"""
import json
import os
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
os.environ.setdefault('ACME_STATE', tempfile.mkdtemp(prefix='acme-hunt-w4-secrets-'))

import test_certs_core as TCC        # noqa: E402


def setUpModule():
    import test_targets as T
    T.setUpModule()


class CheckHeaders(unittest.TestCase):
    def field(self):
        from acmelib.certs import store as S
        cls = S.registry().get('check', 'https')
        return cls, [x for x in cls.fields if x['key'] == 'headers'][0]

    def test_field_is_secret(self):
        from acmelib.certs import store as S
        cls, f = self.field()
        self.assertEqual(f['type'], 'secret')
        self.assertTrue(f.get('multiline'))
        self.assertIn('headers', S.secret_fields(cls))

    def test_text_sent_as_the_list_was(self):
        cls, _f = self.field()
        mod = cls({'http': True, 'headers': 'Authorization: Bearer T0K\nX-Env: prod'}, None)
        lines = mod.http_lines('www.example.test', 443)[0]
        self.assertIn('Authorization: Bearer T0K', lines)
        self.assertIn('X-Env: prod', lines)
        mod = cls({'http': True, 'headers': ['X-Old: 1']}, None)        # as kept before
        self.assertIn('X-Old: 1', mod.http_lines('www.example.test', 443)[0])

    def test_what_happens_shows_dots(self):
        from acmelib.certs import runplan as RP
        cls, _f = self.field()
        steps = RP._test_steps(cls, {'http': True, 'host': 'www.example.test',
                                     'headers': 'X-Token: SECRET-VALUE-42\n'
                                                'User-Agent: mine/1'}, ['www.example.test'])
        call = [s for s in steps if s.get('words', '').startswith('Asks ')][0]
        blob = json.dumps(call)
        self.assertNotIn('SECRET-VALUE-42', blob)
        hdrs = {h[0]: h for h in call['detail']['wire']['headers']}
        self.assertIn('X-Token', hdrs)
        # the User-Agent given is the test's own, not one acme added (a text, not a list)
        self.assertFalse(hdrs['User-Agent'][2])


class EchoCtx(object):
    """A device that answers 401 with what it was sent, as some vendors' errors do."""
    node = 'n'
    settings = {}

    def __init__(self):
        self.steps = []

    def step(self, words, level='info'):
        self.steps.append(words)

    def debug(self, words):
        self.steps.append(words)

    def cancelled(self):
        return False

    def http(self, method, url, body=None, headers=None, **kw):
        echo = {'error': 'invalid credentials: %s %s %s' % (
            url, json.dumps(headers), (body or b'').decode() if isinstance(body, bytes)
            else body)}
        return 401, {}, json.dumps(echo).encode()


class EchoedSecrets(unittest.TestCase):
    def test_helper(self):
        from acmelib.plugins import base
        got = base.sent_secrets('https://h/x?api_key=QUERYKEY1&page=2',
                                {'Authorization': 'Bearer BEARER-TOK', 'Accept': 'x/y'},
                                b'{"user": "admin", "password": "BODY-PW-1", "n": {"token": '
                                b'"NESTED-T"}}')
        self.assertTrue({'QUERYKEY1', 'BEARER-TOK', 'BODY-PW-1', 'NESTED-T'} <= got)
        self.assertNotIn('admin', got)
        self.assertNotIn('2', got)
        self.assertIn('FORM-PW-9', base.sent_secrets('', {}, 'user=a&password=FORM-PW-9'))
        self.assertEqual(base.without_sent('x BEARER-TOK y', got), 'x %s y' % ('•' * 8))

    def test_target_error_without_the_echo(self):
        from acmelib.plugins.targets._common import HttpTarget
        from acmelib.plugins.base import PluginError

        class T(HttpTarget):
            kind = 'echo_test'

            def auth_headers(self):
                return {'Authorization': 'Bearer HDR-SECRET-1'}

        t = T({'host': 'dev.example.test'}, EchoCtx())
        with self.assertRaises(PluginError) as e:
            t.req('POST', '/api/login?token=Q-SECRET-2', {'password': 'BODY-SECRET-3'})
        blob = str(e.exception) + str(e.exception.detail)
        for s in ('HDR-SECRET-1', 'Q-SECRET-2', 'BODY-SECRET-3'):
            self.assertNotIn(s, blob)
        self.assertIn('does not let acme in (401)', str(e.exception))

    def test_challenge_error_without_the_echo(self):
        from acmelib.plugins.challenges import _common as CC
        from acmelib.plugins.base import PluginError
        with self.assertRaises(PluginError) as e:
            CC.api(EchoCtx(), 'POST', 'https://dns.example.test/v1?key=Q-SECRET-4',
                   {'secret_key': 'BODY-SECRET-5'}, {'X-Api-Key': 'HDR-SECRET-6'},
                   who='the DNS API')
        blob = str(e.exception) + str(e.exception.detail)
        for s in ('Q-SECRET-4', 'BODY-SECRET-5', 'HDR-SECRET-6'):
            self.assertNotIn(s, blob)
        self.assertIn('the DNS API said 401', str(e.exception))
        self.assertFalse(e.exception.retry)


class IapStageUrl(unittest.TestCase):
    def test_secret_and_empty_is_tftp(self):
        from acmelib.certs import store as S
        cls = S.registry().get('target', 'aruba_iap')
        f = [x for x in cls.fields if x['key'] == 'stage_url'][0]
        self.assertEqual(f['type'], 'secret')
        self.assertIn('stage_url', S.secret_fields(cls))
        mod = cls({'stage_host': 'tftp.example.test', 'stage_dir': '/srv/tftp'}, None)
        self.assertEqual(mod.url('x.pfx'), 'tftp://tftp.example.test/x.pfx')
        mod = cls({'stage_host': 'h', 'stage_url': 'ftp://u:pw@{addr}/{dir}/{file}',
                   'stage_dir': '/c'}, None)
        self.assertEqual(mod.url('x.pfx'), 'ftp://u:pw@h/c/x.pfx')


class UrlUserinfo(unittest.TestCase):
    def test_refused_without_the_password(self):
        from acmelib.certs import runtime as R
        from acmelib.plugins.base import PluginError
        c = R.RunContext(None, scope='target:x', on_hostkey=False)
        for u in ('https://bob:S3cretPW@127.0.0.1:1/hook',
                  'https://bob:S3cretPW@hooks.invalid.example/hook',
                  'https://S3cretPW@hooks.invalid.example/', 'ftp://a:S3cretPW@x/'):
            with self.assertRaises(PluginError) as e:
                c.http('POST', u, body=b'x', timeout=3)
            self.assertNotIn('S3cretPW', str(e.exception))
            self.assertFalse(e.exception.retry)

    def test_helpers(self):
        from acmelib.certs import runtime as R
        self.assertEqual(R._netloc_shown('https://u:pw@h.example:8443/x'), 'h.example:8443')
        self.assertEqual(R._without_userinfo("nonnumeric port: 'pw@h'", 'https://u:pw@h/'),
                         "nonnumeric port: '%s@h'" % ('•' * 8))
        w = R.wire_request('GET', 'https://u:pw@h.example/x')
        self.assertNotIn('pw', json.dumps([h for h in w['headers'] if h[0] == 'Host']))


class CentralTokens(unittest.TestCase):
    def test_sealed_and_hash_of_the_form(self):
        import test_targets_cisco_aruba as TA
        from test_targets import FakeCtx, FakeBundle
        cfg = dict(TA.CCFG, refresh_token='FORM-RTOKEN-77')
        ctx = FakeCtx(TA.central_routes())
        TA.make('aruba_central', '', cfg, ctx).deploy(FakeBundle(), {'cert_name': 'captive'})
        key = [k for k in ctx.kv if k.startswith('central-tokens:')][0]
        kept = ctx.kv[key]
        blob = json.dumps(kept)
        for clear in ('FORM-RTOKEN-77', '"A1"', '"R1"'):
            self.assertNotIn(clear, blob)
        self.assertTrue(kept['access'].startswith('sealed:2:'))
        self.assertTrue(kept['refresh'].startswith('sealed:2:'))
        # the next run takes the kept access token (sealed) - no refresh while it lasts
        ctx.calls = []
        TA.make('aruba_central', '', cfg, ctx).deploy(FakeBundle('b'), {'cert_name': 'captive'})
        self.assertFalse(ctx.find('POST', r'/oauth2/token'))
        self.assertEqual(ctx.calls[0]['headers']['Authorization'], 'Bearer A1')
        # past its time: refreshed with the refresh token Central gave last
        ctx.kv[key]['until'] = 0
        ctx.calls = []
        TA.make('aruba_central', '', cfg, ctx).deploy(FakeBundle(), {'cert_name': 'captive'})
        self.assertEqual(ctx.calls[0]['query']['refresh_token'], ['R1'])
        # another refresh token in the form: the kept ones are not used
        ctx.kv[key]['until'] = 9e9
        ctx.calls = []
        TA.make('aruba_central', '', dict(cfg, refresh_token='NEW-ONE'), ctx).deploy(
            FakeBundle('b'), {'cert_name': 'captive'})
        self.assertEqual(ctx.calls[0]['query']['refresh_token'], ['NEW-ONE'])

    def test_kept_in_clear_before_still_used_then_sealed(self):
        import test_targets_cisco_aruba as TA
        from test_targets import FakeCtx, FakeBundle
        import time
        ctx = FakeCtx(TA.central_routes())
        mod = TA.make('aruba_central', '', TA.CCFG, ctx)
        ctx.kv[mod.tokens_key()] = {'access': 'OLD-ACCESS', 'refresh': 'OLD-REFRESH',
                                    'until': time.time() + 3600, 'from': TA.CCFG['refresh_token']}
        mod.deploy(FakeBundle(), {'cert_name': 'captive'})
        self.assertFalse(ctx.find('POST', r'/oauth2/token'))
        self.assertEqual(ctx.calls[0]['headers']['Authorization'], 'Bearer OLD-ACCESS')
        blob = json.dumps(ctx.kv[mod.tokens_key()])
        self.assertNotIn('OLD-ACCESS', blob)
        self.assertNotIn('OLD-REFRESH', blob)
        self.assertNotIn('"R0"', blob)


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
        return self.py('r = st.db.row("SELECT id, config FROM cert_tests WHERE name = ?", (%r,))\n'
                       'print(json.dumps(r, default=str))' % name)

    def opened(self, ident):
        return self.py('from acmelib.certs import store as S\n'
                       'r = st.db.row("SELECT * FROM cert_tests WHERE id = ?", (%d,))\n'
                       'print(json.dumps(S.plugin_config("check", r)["headers"]))' % ident)

    def test_check_headers_sealed_and_masked(self):
        tid = self.ok('POST', '/api/tests/save', {
            'name': 'site-auth', 'kind': 'https',
            'config': {'host': '127.0.0.1', 'http': True,
                       'headers': 'Authorization: Basic SEEKRIT-99\nX-Env: prod'}})['id']
        raw = self.row('site-auth')['config']
        self.assertNotIn('SEEKRIT', raw)
        self.assertIn('sealed:', json.loads(raw)['headers'])
        self.assertNotIn('SEEKRIT', json.dumps(self.ok('GET', '/api/tests')))
        self.assertIn('Authorization: Basic SEEKRIT-99', self.opened(tid))
        # saved again with what the page shows: kept
        self.ok('POST', '/api/tests/save', {'id': tid, 'name': 'site-auth', 'kind': 'https',
                                             'config': {'host': '127.0.0.2', 'http': True,
                                                        'headers': ''}})
        self.assertIn('Authorization: Basic SEEKRIT-99', self.opened(tid))

    def test_old_list_in_clear_still_works(self):
        tid = self.ok('POST', '/api/tests/save', {
            'name': 'site-old', 'kind': 'https', 'config': {'host': '127.0.0.1'}})['id']
        self.py('r = st.db.row("SELECT config FROM cert_tests WHERE id = ?", (%d,))\n'
                'c = json.loads(r["config"]); c["headers"] = ["Cookie: OLD-COOKIE-5"]\n'
                'st.db.run("UPDATE cert_tests SET config = ? WHERE id = ?", (json.dumps(c), %d))\n'
                'print(1)' % (tid, tid))
        self.assertNotIn('OLD-COOKIE', json.dumps(self.ok('GET', '/api/tests')))
        self.assertIn('Cookie: OLD-COOKIE-5', self.opened(tid))


if __name__ == '__main__':
    unittest.main()
