#!/usr/bin/env python3
"""Hunt R t4 - certificate sources (ACME, ZeroSSL REST, AD CS Web Enrollment).

    python3 test/test_hunt_rt4_issuers.py
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_issuers as TI  # noqa: E402
import test_sources_vendors as V  # noqa: E402
from test_digicert import Board  # noqa: E402
from test_issuers_more import CannedContext, req_for  # noqa: E402

from acmelib.plugins.base import CertRequest, PluginError  # noqa: E402
from acmelib.plugins.issuers import _acme_client as ac  # noqa: E402
from acmelib.plugins.issuers import ms_adcs  # noqa: E402
from acmelib.plugins.issuers.acme import AcmeIssuer  # noqa: E402


class ZeroSslDcvFailedOnce(V.TestZeroSsl):
    """A failed domain validation (domain_control_validation_failed) is asked for again at
    the next try with the records already in place - they were put in place a second time
    (the first ones' handles lost, never taken away)."""

    def test_records_not_placed_twice(self):
        handler, st = self.server()
        fail = [1]
        made = {}

        def h(method, url, body, headers, cc):
            if url.endswith('/challenges') and fail:
                fail.pop()
                return 200, {}, {'success': False, 'error': {
                    'code': 0, 'type': 'domain_control_validation_failed'}}
            code, hd, got = handler(method, url, body, headers, cc)
            if method == 'POST' and url.endswith('/certificates'):
                made['obj'] = got
            elif method == 'GET' and isinstance(got, dict) and got.get('status') == 'draft':
                got = dict(made['obj'], status='draft')       # the object with its validation
            return code, hd, got
        ctx = CannedContext(h)
        board = Board()
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': board})
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx).issue(req)
        self.assertTrue(e.exception.retry)
        out = self.issuer(ctx).issue(req)
        self.check_issued(out, req)
        self.assertEqual(st['made'], 1)
        self.assertEqual([x for x in board.log if x[0] == 'cname'],
                         [('cname', '_abcdef.www.firma.cz', 'aa.bb.id.zerossl.com')])
        self.assertEqual(board.cname, {})
        self.assertEqual(st['method'], 'CNAME_CSR_HASH')

    def test_answer_without_validation_part(self):
        """GET /certificates/{id} without 'validation': the held records are used."""
        handler, st = self.server()
        fail = [1]

        def h(method, url, body, headers, cc):
            if url.endswith('/challenges') and fail:
                fail.pop()
                return 200, {}, {'success': False, 'error': {
                    'code': 0, 'type': 'domain_control_validation_failed'}}
            return handler(method, url, body, headers, cc)
        ctx = CannedContext(h)
        board = Board()
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': board})
        with self.assertRaises(PluginError):
            self.issuer(ctx).issue(req)
        out = self.issuer(ctx).issue(req)
        self.check_issued(out, req)
        self.assertEqual(board.cname, {})


class AcmeReplacesRefused(unittest.TestCase):
    """The CA refuses `replaces` (another account ordered the one before): ordered as a new
    certificate - its info said it replaced the one before all the same."""

    def setUp(self):
        self.ca = TI.MockAcme()
        self.ctx = TI.FakeContext()

    def tearDown(self):
        self.ca.close()

    def test_info_without_replaces(self):
        iss = AcmeIssuer({'directory': 'custom', 'directory_url': self.ca.base + '/dir',
                          'poll_every': 0.2, 'wait_ready': 10, 'wait_valid': 10,
                          'wait_order': 10}, self.ctx)
        names = ['r.example.com']
        key, csr_pem, csr_der = TI.make_key_csr(names)
        web = TI.FakeChallenge(('http-01',), self.ca.board)
        first = iss.issue(CertRequest(names=names, key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                                      challenges={'r.example.com': web}))
        orig = ac.AcmeClient.new_order

        def new_order(cl, names, profile=None, replaces=None, not_after=None):
            if replaces:
                err = PluginError('the CA refused it (malformed): cannot replace this one')
                err.acme_type = 'malformed'
                raise err
            return orig(cl, names, profile, replaces, not_after)
        ac.AcmeClient.new_order = new_order
        try:
            got = iss.issue(CertRequest(names=names, key_pem=key, csr_pem=csr_pem,
                                        csr_der=csr_der, challenges={'r.example.com': web},
                                        previous=first.cert_pem))
        finally:
            ac.AcmeClient.new_order = orig
        self.assertIn('BEGIN CERTIFICATE', got.cert_pem)
        self.assertNotIn('replaces', got.info)
        self.assertTrue(any('ordered as a new certificate' in w for _l, w in self.ctx.steps))


class AdcsClientKeyBox(unittest.TestCase):
    """The client certificate's key of AD CS Web Enrollment is PEM: a one-line password
    box took it with its line breaks taken out, which openssl does not read."""

    def test_field_is_multiline(self):
        f = next(x for x in ms_adcs.MsAdcsIssuer.fields if x['key'] == 'client_key')
        self.assertTrue(f.get('multiline') or (f['type'] == 'pem' and f.get('secret')))
        self.assertEqual(f['type'], 'secret')            # still kept as a secret

    def test_one_line_key_saved_before_still_read(self):
        ca = TI.TestCA('Adcs Client CA')
        try:
            key, csr_pem, csr_der = TI.make_key_csr(['client.example.com'])
            cert = ca.sign_csr(csr_der, ['client.example.com'])
            one = key.replace('\n', '').replace('\r', '')
            h = ms_adcs.AdcsHttp(None, 'https://ca.example/certsrv', 'cert',
                                 client_cert=cert.replace('\n', ''), client_key=one)
            try:
                h._ssl()                                  # raised "do not go together"
            finally:
                h.close()
            self.assertEqual(ms_adcs._pem_lines(key), key)
            self.assertEqual(ms_adcs._pem_lines(one).split(), key.split())
        finally:
            ca.close()


if __name__ == '__main__':
    unittest.main()
