#!/usr/bin/env python3
"""Hunt R7, area issuers: regressions.

    python3 test/test_hunt_r7_issuers.py
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
TMP = tempfile.mkdtemp(prefix='acme-hr7-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "app1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401  (the engine, as the daemon loads it)
import acmelib.engine as E  # noqa: E402
from acmelib.plugins import base  # noqa: E402
from acmelib.plugins.issuers import gogetssl, ssls  # noqa: E402


class EngineAcceptHeader(unittest.TestCase):
    """The engine's ACME client asked for application/pem-certificate-chain on every POST
    whose URL held "cert" - a CA at acme.cert.example (or /certificate-authority/...) got
    it on newAccount, newOrder, the authorizations: only the certificate's URL takes it."""

    def client(self, base_url):
        a = E.Acme.__new__(E.Acme)
        a.nonce = 'n0'
        a.kid = base_url + '/acct/1'
        a.dir = {'newNonce': base_url + '/nonce', 'newAccount': base_url + '/new-acct',
                 'newOrder': base_url + '/new-order'}
        a.akind = 'ec'
        a._sign = lambda data: b'\x00' * 64
        a._jwk = lambda: {'kty': 'EC'}
        seen = []

        def req(url, data=None, method=None, accept='application/json'):
            seen.append((url, accept))
            a.nonce = 'n%d' % len(seen)
            return b'{"status": "valid"}', {'Location': url}, 200
        a._req = req
        return a, seen

    def test_json_on_a_host_with_cert(self):
        base_url = 'https://acme.cert.example.test/acme'
        a, seen = self.client(base_url)
        a.post_json(base_url + '/new-order', {'identifiers': []})
        a.post_json(base_url + '/authz/1', None)
        a.post_json(base_url + '/order/1/finalize', {'csr': 'x'})
        self.assertEqual([acc for _u, acc in seen], ['application/json'] * 3)

    def test_pem_for_the_certificate_url_only(self):
        a, seen = self.client('https://ca.example.test/acme')
        a.post('https://ca.example.test/acme/c/abc', None,
               accept='application/pem-certificate-chain')
        self.assertEqual(seen[-1][1], 'application/pem-certificate-chain')

    def test_order_downloads_with_pem(self):
        with open(os.path.join(ROOT, 'acmelib', 'engine',
                               '260_certificates_by_acme_let.py')) as fh:
            src = fh.read()
        self.assertIn("self.post(o['certificate'], None, accept='application/pem-certificate-chain')",
                      src)
        self.assertNotIn("'cert' not in url", src)


class RevokeNotOffered(unittest.TestCase):
    """GoGetSSL and SSLS.cz cannot revoke by their API, yet each overrode revoke() only to
    fail - certs/api.py revocable() offers Revoke for any source whose revoke is not the base
    class's, so Revoke was offered and its job failed every time."""

    def test_base_revoke(self):
        for cls in (gogetssl.GoGetSslIssuer, ssls.SslsIssuer):
            self.assertIs(getattr(cls, 'revoke'), getattr(base.Issuer, 'revoke'), cls.__name__)

    def test_still_says_cannot(self):
        class Ctx(object):
            def step(self, *_a):
                pass
        iss = gogetssl.GoGetSslIssuer({}, Ctx())
        with self.assertRaises(base.PluginError) as e:
            iss.revoke('x')
        self.assertIn('cannot revoke', str(e.exception))
        self.assertFalse(e.exception.retry)


class AdcsDeniedWhileHeld(unittest.TestCase):
    """A request held at AD CS for approval, then denied by the certificate manager: the
    denial was raised on every later try and the held request never let go (90 days) - no new
    request could be made. Now the held request is dropped with the denial."""

    def test_denied_lets_go(self):
        sys.path.insert(0, HERE)
        import test_issuers as T
        ca = T.MockAdcs('basic')
        try:
            ctx = T.FakeContext()
            iss = T.MsAdcsIssuer({'url': ca.base, 'template': 'Approve', 'auth': 'basic',
                                  'user': 'svc-acme', 'password': 'S3cret!', 'domain': 'EXAMPLE'},
                                 ctx)
            key, csr_pem, csr_der = T.make_key_csr(['web01.example.local'], 'rsa')
            r = T.CertRequest(names=['web01.example.local'], key_pem=key, csr_pem=csr_pem,
                              csr_der=csr_der, cert_id=7)
            with self.assertRaises(base.PluginError) as cm:
                iss.issue(r)
            self.assertTrue(cm.exception.retry)
            rid = str(ca.n)
            self.assertTrue([k for k in ctx.kv if k.startswith('ms_adcs-pending:')])
            ca.reqs[rid]['state'] = 'denied'
            with self.assertRaises(base.PluginError) as cm:
                iss.issue(r)
            self.assertFalse(cm.exception.retry)
            self.assertIn('denied', str(cm.exception).lower())
            self.assertEqual([k for k in ctx.kv if k.startswith('ms_adcs-pending:')], [])
            with self.assertRaises(base.PluginError):     # a new request, held again
                iss.issue(r)
            self.assertEqual(ca.n, int(rid) + 1)
        finally:
            ca.close()


if __name__ == '__main__':
    unittest.main()
