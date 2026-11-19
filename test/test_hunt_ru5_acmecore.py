#!/usr/bin/env python3
"""Hunt R u5 (the core ACME client, HTTP-01 answered by acme):

- a finalize the CA took but whose answer was lost (a 5xx of a proxy) was sent again by
  post(), the CA said orderNotReady (the order is processing) and the job failed - the
  next try ordered another certificate;
- HTTP-01 answered by acme in a cluster: the token comes to the other node's database by
  replication, the CA was asked at once and could be told 404 by the other node.

    python3 test/test_hunt_ru5_acmecore.py
"""
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import test_issuers as T                                                    # noqa: E402
from acmelib.plugins.base import CertRequest, Context                       # noqa: E402
from acmelib.plugins.challenges.http_local import HttpLocal                 # noqa: E402
from acmelib.plugins.issuers.acme import AcmeIssuer                         # noqa: E402


class TestFinalizeAnswerLost(unittest.TestCase):
    def setUp(self):
        self.ca = T.MockAcme(bad_nonce_once=False)
        H = self.ca.server.httpd.RequestHandlerClass
        orig = H.finalize
        self.calls = calls = []

        def finalize(handler, oid, payload):
            calls.append(oid)
            if len(calls) == 1:
                real = handler.send

                def lost(status, body=b'', ctype='application/json', headers=None):
                    # done at the CA, its answer lost on the way
                    real(503, {'type': 'urn:ietf:params:acme:error:serverInternal',
                               'detail': 'upstream'}, 'application/problem+json',
                         handler.common() + [('Retry-After', '1')])
                handler.send = lost
            return orig(handler, oid, payload)
        H.finalize = finalize

    def tearDown(self):
        self.ca.close()

    def test_the_order_finalized_already_is_taken(self):
        ctx = T.FakeContext()
        names = ['fin.example.com']
        key, csr_pem, csr_der = T.make_key_csr(names)
        web = T.FakeChallenge(('http-01',), self.ca.board)
        iss = AcmeIssuer({'directory': 'custom', 'directory_url': self.ca.base + '/dir',
                          'poll_every': 0.2, 'wait_ready': 10, 'wait_valid': 10,
                          'wait_order': 10}, ctx)
        got = iss.issue(CertRequest(names=names, key_pem=key, csr_pem=csr_pem,
                                    csr_der=csr_der, challenges={names[0]: web}))
        self.assertIn('BEGIN CERTIFICATE', got.cert_pem)
        self.assertEqual(len(self.calls), 2)            # sent again after the 503
        self.assertEqual(len(self.ca.orders), 1)        # and no second order


class ClusterCtx(Context):
    def __init__(self, nodes, answers):
        self.nodes = nodes
        self.answers = answers          # addr -> callable() -> status, or an exception
        self.asked = []
        self.tokens = {}
        self.steps = []

    def step(self, words, level='info'):
        self.steps.append((level, words))

    def debug(self, words):
        pass

    def own_addresses(self):
        return {'vip': '192.0.2.100', 'nodes': list(self.nodes)}

    def http_token_put(self, token, ka):
        self.tokens[token] = ka

    def http_token_drop(self, token):
        self.tokens.pop(token, None)

    def http(self, method, url, body=None, headers=None, timeout=30, verify=True, ca_pem=None,
             client_cert=None, proxy=True):
        addr = url.split('/')[2]
        self.asked.append((addr, (headers or {}).get('Host')))
        st = self.answers[addr]()
        if isinstance(st, Exception):
            raise st
        tok = url.rsplit('/', 1)[1]
        return st, {}, (self.tokens.get(tok, '') if st == 200 else 'not found').encode()


class TestHttp01OnEveryNode(unittest.TestCase):
    TOKEN = 'tok-1234567890'

    def test_waits_for_the_other_node(self):
        lag = {'n': 2}

        def other():
            lag['n'] -= 1
            return 404 if lag['n'] >= 0 else 200
        ctx = ClusterCtx(['192.0.2.1', '192.0.2.2'], {'192.0.2.1': lambda: 200,
                                                      '192.0.2.2': other})
        m = HttpLocal({}, ctx)
        h = m.present('www.example.com', self.TOKEN, self.TOKEN + '.ka', '')
        self.assertFalse(m.ready('www.example.com', h))
        self.assertFalse(m.ready('www.example.com', h))
        self.assertTrue(m.ready('www.example.com', h))
        self.assertIn(('192.0.2.2', 'www.example.com'), ctx.asked)

    def test_not_waited_for_ever_nor_for_a_node_not_reached(self):
        ctx = ClusterCtx(['192.0.2.1', '192.0.2.2'], {'192.0.2.1': lambda: 200,
                                                      '192.0.2.2': lambda: OSError('refused')})
        m = HttpLocal({}, ctx)
        h = m.present('www.example.com', self.TOKEN, self.TOKEN + '.ka', '')
        self.assertTrue(m.ready('www.example.com', h))
        ctx.answers['192.0.2.2'] = lambda: 404
        self.assertFalse(m.ready('www.example.com', h))
        h['at'] = time.time() - HttpLocal.NODES_WAIT - 1
        self.assertTrue(m.ready('www.example.com', h))

    def test_one_node_as_before(self):
        ctx = ClusterCtx(['192.0.2.1'], {'192.0.2.1': lambda: 404})
        m = HttpLocal({}, ctx)
        h = m.present('www.example.com', self.TOKEN, self.TOKEN + '.ka', '')
        self.assertTrue(m.ready('www.example.com', h))
        self.assertEqual(ctx.asked, [])
        # a handle of before (no 'at'): as before
        self.assertTrue(m.ready('www.example.com', {'token': self.TOKEN, 'ka': 'x', 'name': 'a.b'}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
