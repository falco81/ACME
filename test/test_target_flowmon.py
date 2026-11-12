#!/usr/bin/env python3
"""The Flowmon target (1.0.88), against answers as Flowmon REST API 13.1 gives them.

    python3 test/test_target_flowmon.py
"""
import base64
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_targets as TT  # noqa: E402


def setUpModule():
    TT.setUpModule()


def tearDownModule():
    TT.tearDownModule()


TOKEN = (200, {'access_token': 'TOK', 'token_type': 'bearer', 'expires_in': 86400})


class Flowmon(unittest.TestCase):
    def target(self, ctx, **more):
        cfg = {'host': 'flowmon.example.local', 'user': 'admin', 'password': 'P'}
        cfg.update(more)
        return TT.make('flowmon', cfg, ctx)

    def test_signs_in_and_tests(self):
        ctx = TT.FakeCtx([
            ('POST', r'/resources/oauth/token$', TOKEN),
            ('GET', r'/rest/version$', (200, [{'version': '13.1.0'}])),
            ('GET', r'/rest/fcc/reusable-settings-tls$', (200, [{'id': 't1', 'name': 'Web'}])),
            ('GET', r'/rest/fcc/listening-ports$', (200, [{'id': 'p1', 'name': 'TLS', 'secure': True}])),
        ])
        said = self.target(ctx).test()
        self.assertIn('13.1.0', said)
        tok = ctx.calls[0]
        self.assertIn('grant_type=password', tok['body'].decode())
        self.assertIn('client_id=invea-tech', tok['body'].decode())
        self.assertEqual(ctx.calls[1]['headers'].get('Authorization'), 'bearer TOK')

    def test_pair_replaced_in_a_setting(self):
        ctx = TT.FakeCtx([
            ('POST', r'/resources/oauth/token$', TOKEN),
            ('GET', r'/rest/fcc/reusable-settings-tls$', (200, [{'id': 't1', 'name': 'Web servers'}])),
            ('GET', r'/reusable-settings-tls/t1/pairs$', (200, [{'id': 'p9', 'name': 'www', 'usageCount': 2}])),
            ('PUT', r'/reusable-settings-tls/t1/pairs$', (200, {'id': 'p9'})),
        ])
        b = TT.FakeBundle()
        got = self.target(ctx).deploy(b, {'tls_setting': 'Web servers', 'pair': 'www'})
        self.assertIn('replaced', got)
        put = [c for c in ctx.calls if c['method'] == 'PUT'][0]
        body = put['body'].decode('latin-1')
        self.assertIn('name="entity[id]"', body)
        self.assertIn('p9', body)
        self.assertIn('name="entity[tlsPrivateKeyFile]"', body)
        self.assertIn('name="entity[tlsCertificateFile]"', body)
        self.assertIn('PRIVATE KEY', body)
        self.assertIn('multipart/form-data', put['headers']['Content-Type'])
        # the same again: nothing done
        n = len(ctx.calls)
        self.assertIn('unchanged', self.target(ctx).deploy(b, {'tls_setting': 'Web servers',
                                                                 'pair': 'www'}))
        self.assertEqual(len(ctx.calls), n)

    def test_setting_made_and_pair_added(self):
        ctx = TT.FakeCtx([
            ('POST', r'/resources/oauth/token$', TOKEN),
            ('GET', r'/rest/fcc/reusable-settings-tls$', (204, '')),
            ('POST', r'/rest/fcc/reusable-settings-tls$', (201, {'id': 'tnew', 'name': 'New'})),
            ('GET', r'/reusable-settings-tls/tnew/pairs$', (204, '')),
            ('POST', r'/reusable-settings-tls/tnew/pairs$', (201, {'id': 'p1'})),
        ])
        got = self.target(ctx, form_style='dotted').deploy(TT.FakeBundle(), {'tls_setting': 'New'})
        self.assertIn('added', got)
        made = [c for c in ctx.calls if c['method'] == 'POST' and c['path'].endswith('-tls')][0]
        self.assertIn('name="entity.tlsCaFile"', made['body'].decode('latin-1'))

    def test_listening_ports_over_tls(self):
        def put(call):
            put.got = json.loads(call['body'])
            return 200, put.got
        ctx = TT.FakeCtx([
            ('POST', r'/resources/oauth/token$', TOKEN),
            ('GET', r'/rest/fcc/listening-ports$', (200, [
                {'id': 'lp1', 'name': 'IPFIX-TLS', 'secure': False,
                 'tcpCollector': {'name': 'p4739', 'localPort': 4739}, 'stats': {'flows': 1}}])),
            ('PUT', r'/rest/fcc/listening-ports$', put),
        ])
        b = TT.FakeBundle()
        self.target(ctx).deploy(b, {'listening_ports': 'IPFIX-TLS'})
        e = put.got['entity']
        self.assertEqual((e['id'], e['tcpCollector']['name'], e['secure']), ('lp1', 'p4739', True))
        self.assertNotIn('stats', e)
        self.assertIn('BEGIN CERTIFICATE', base64.b64decode(e['certificates']['crt']).decode())
        self.assertIn('PRIVATE KEY', base64.b64decode(e['certificates']['key']).decode())

    def test_refusals(self):
        ctx = TT.FakeCtx([('POST', r'/resources/oauth/token$', (400, {'error': 'invalid_grant'}))])
        with self.assertRaises(Exception) as e:
            self.target(ctx).deploy(TT.FakeBundle(), {'tls_setting': 'X'})
        self.assertIn('invalid_grant', str(e.exception))
        with self.assertRaises(Exception) as e:
            self.target(TT.FakeCtx([])).deploy(TT.FakeBundle(), {})
        self.assertIn('say where', str(e.exception))
        ctx = TT.FakeCtx([
            ('POST', r'/resources/oauth/token$', TOKEN),
            ('GET', r'/rest/fcc/listening-ports$', (200, [])),
        ])
        with self.assertRaises(Exception) as e:
            self.target(ctx).deploy(TT.FakeBundle(), {'listening_ports': 'Nope'})
        self.assertIn('no listening port Nope', str(e.exception))


if __name__ == '__main__':
    unittest.main(verbosity=2)
