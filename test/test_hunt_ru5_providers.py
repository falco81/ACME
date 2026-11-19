#!/usr/bin/env python3
"""Hunt R u5 (providers): the DNS provider modules and the issuers that are not ACME.

    python3 test/test_hunt_ru5_providers.py
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_digicert as TD  # noqa: E402
from test_digicert import Board  # noqa: E402
from test_issuers_more import Base, CannedContext, req_for  # noqa: E402


class TestDigicertOrdersKnown(Base):
    """The orders acme made are known as its own in Import from a source: since 1.0.80 they
    are kept as digicert-order:<id>:<family>, which _acme_ids() did not read."""

    central = TD.TestCertCentral.central
    issuer = TD.TestCertCentral.issuer

    def test_order_made_is_known_in_the_list(self):
        h, state = self.central()

        def handler(method, url, body, headers, cc):
            if method == 'GET' and url.split('?')[0].endswith('/services/v2/order/certificate'):
                return 200, {}, {'orders': [
                    {'id': 555, 'status': 'pending', 'certificate': {
                        'common_name': 'www.firma.cz', 'dns_names': ['www.firma.cz']},
                     'product': {'name_id': 'ssl_dv_geotrust_flex'}},
                    {'id': 556, 'status': 'pending', 'certificate': {
                        'common_name': 'other.cz'}}], 'page': {'total': 2}}
            return h(method, url, body, headers, cc)
        ctx = CannedContext(handler)
        d = self.issuer(ctx, product='ssl_dv_geotrust_flex', allow_paid=True)
        board = Board()
        d.issue(req_for(['www.firma.cz'], challenges={'www.firma.cz': board}, cert_id=7))
        self.assertEqual(json.loads(ctx.kv['digicert-order:7:ec'])['order_id'], '555')
        # one kept before 1.0.80 (no family) is read as well
        ctx.kv['digicert-order:8'] = json.dumps({'order_id': '556'})
        # a certificate without an id (a hash of its names) is no certificate of acme's
        ctx.kv['digicert-order:ab12cd:rsa'] = json.dumps({'order_id': '557'})
        self.assertEqual(d._acme_ids(), {'555': 7, '556': 8})
        items = {x['ref']: x for x in d.list_existing()}
        self.assertEqual(items['555']['acme_cert_id'], 7)
        self.assertEqual(items['556']['acme_cert_id'], 8)


class TestScepAlgorithms(unittest.TestCase):
    """SCEPStandard implies AES, POSTPKIOperation and SHA-256 (RFC 8894 3.5.2): AES was not
    taken from it - a server that says only SCEPStandard got its request in 3DES."""

    def test_scep_standard_means_aes(self):
        from acmelib.plugins.issuers.scep import ScepIssuer
        s = ScepIssuer({'url': 'https://ca.example/scep'}, None)
        self.assertEqual(s._algos({'SCEPStandard'}), ('aes256', 'sha256'))
        self.assertEqual(s._algos({'AES', 'SHA-256'}), ('aes256', 'sha256'))
        self.assertEqual(s._algos(set()), ('3des', 'sha1'))          # as before
        self.assertEqual(s._algos({'POSTPKIOperation', 'SHA-1'}), ('3des', 'sha1'))
        s = ScepIssuer({'url': 'https://ca.example/scep', 'cipher': '3des'}, None)
        self.assertEqual(s._algos({'SCEPStandard'}), ('3des', 'sha256'))   # set by hand: kept


class TestSaidError(unittest.TestCase):
    """A provider's "rate limit" refusal: a 403 one was said as wrong credentials, and a 400
    or 403 one said "acme tries again" while marked as not worth trying again."""

    def test_slow_down_said_and_marked(self):
        from acmelib.plugins.challenges._common import said_error
        e = said_error('X', 403, {'message': 'Rate limit exceeded'}, b'')
        self.assertIn('slow down', str(e))
        self.assertNotIn('credentials', str(e))
        self.assertTrue(e.retry)
        e = said_error('X', 400, {'message': 'Throttling: rate exceeded'}, b'')
        self.assertIn('slow down', str(e))
        self.assertTrue(e.retry)
        e = said_error('X', 429, None, b'')
        self.assertTrue(e.retry)
        # as before: a plain 403 and 400, a 401
        e = said_error('X', 403, {'message': 'Forbidden'}, b'')
        self.assertIn('credentials are wrong', str(e))
        self.assertFalse(e.retry)
        self.assertFalse(said_error('X', 400, {'message': 'bad name'}, b'').retry)
        self.assertIn('credentials', str(said_error('X', 401, None, b'')))
        self.assertTrue(said_error('X', 502, None, b'').retry)


class TestHetznerZoneSet(unittest.TestCase):
    """The zone set is used for a name in it only: _acme-challenge followed by its CNAME into
    another zone of the project was looked for in the zone set (and refused)."""

    def test_name_outside_the_zone_set_finds_its_own(self):
        from test_challenges import FakeCtx, Router
        from acmelib.plugins.challenges.hetzner import Hetzner
        api = 'https://api.hetzner.cloud/v1'
        r = Router()
        r.on('GET', api + '/zones?name=example.com',
             lambda u, b, h: {'zones': [{'id': 7, 'name': 'example.com'}]})
        r.on('GET', api + '/zones?name=other.org',
             lambda u, b, h: {'zones': [{'id': 9, 'name': 'other.org'}]})
        r.on('GET', api + '/zones?name=', lambda u, b, h: {'zones': []})
        m = Hetzner({'token': 'T', 'zone': 'other.org', 'propagation': 'none'},
                    FakeCtx(http=r))
        self.assertEqual(m._zone('_acme-challenge.www.example.com'), ('7', 'example.com'))
        self.assertEqual(m._zone('_acme-challenge.other.org'), ('9', 'other.org'))   # as before


if __name__ == '__main__':
    unittest.main()
