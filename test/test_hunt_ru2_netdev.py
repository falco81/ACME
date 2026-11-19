#!/usr/bin/env python3
"""Hunt U2, the network device targets besides FortiGate - without a network:

    python3 test/test_hunt_ru2_netdev.py

  fortimanager      a CA of the chain refused for another reason than "there already" (-2)
                    was said as an info step "(there already?)" - now a warning; -2 is said
                    as there already
  cisco_ise         the same for an intermediate ISE did not import as trusted
  aruba_clearpass   the same for a CA of the chain ClearPass did not add to the trust list
  mikrotik          (REST) an old certificate RouterOS would not remove failed the whole
                    deployment after it was bound, and it was never remembered
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh, make  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
import test_targets_fw_adc as FW  # noqa: E402
import test_targets_more as MORE  # noqa: E402
import test_targets_cisco_aruba as CA  # noqa: E402


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def warns(ctx, about=''):
    return [w for lvl, w in ctx.steps if lvl == 'warn' and about in w]


class FortiManagerCa(unittest.TestCase):
    def deploy(self, code, message):
        routes, state = FW.FortiManagerTest().routes()
        rpc = routes[0][2]

        def ca_refused(call):
            r = FW.body_of(call)
            p = r['params'][0]
            if r['method'] == 'add' and p['url'] == '/cli/global/system/certificate/ca':
                return 200, {'id': r['id'], 'result': [
                    {'status': {'code': code, 'message': message}, 'url': p['url']}]}
            return rpc(call)
        ctx = FakeCtx([('POST', r'/jsonrpc$', ca_refused)])
        got = FW.make('fortimanager', ctx, host='fmg', token='T').deploy(FW.Bundle(), {})
        self.assertIn('GUI', got, 'the deployment goes on either way')
        return ctx

    def test_there_already(self):
        ctx = self.deploy(-2, 'Object already exists')
        self.assertEqual(warns(ctx), [])
        self.assertTrue([w for lvl, w in ctx.steps if 'is there already' in w])

    def test_refused(self):
        ctx = self.deploy(-11, 'No permission for the resource')
        w = warns(ctx)
        self.assertEqual(len(w), 1, ctx.steps)
        self.assertIn('not added', w[0])
        self.assertIn('No permission', w[0])


class IseCa(unittest.TestCase):
    def deploy(self, trusted):
        a = FakeBundle()
        listed = []

        def imp(call):
            import json
            listed.append({'id': 'i9', 'friendlyName': json.loads(call['body'])['name']})
            return 200, {'response': {'id': 'i9', 'status': 'SUCCESS'}}
        ctx = MORE.OpensslCtx([
            ('GET', r'/api/v1/certs/system-certificate/ise01\?size=100$',
             lambda c: (200, {'response': listed})),
            ('POST', r'/api/v1/certs/trusted-certificate/import$', trusted),
            ('POST', r'/api/v1/certs/system-certificate/import$', imp),
        ])
        make('cisco_ise', {'host': 'ise.test', 'user': 'ers', 'password': 'p',
                           'node': 'ise01'}, ctx).deploy(a, {'roles': 'eap'})
        return ctx

    def test_there_already(self):
        ctx = self.deploy((400, {'message': 'Trust certificate already exists in the '
                                            'Trusted Certificates store'}))
        self.assertEqual(warns(ctx), [])

    def test_refused(self):
        ctx = self.deploy((403, {'message': 'Access denied'}))
        w = warns(ctx)
        self.assertEqual(len(w), 1, ctx.steps)
        self.assertIn('not imported', w[0])


class ClearPassCa(unittest.TestCase):
    def deploy(self, trust):
        ctx = FakeCtx(CA.cp_routes(trust=trust))
        CA.make('aruba_clearpass', '', CA.CPCFG, ctx).deploy(FakeBundle(), {})
        return ctx

    def test_there_already(self):
        ctx = self.deploy((422, {'detail': 'Certificate already exists in the trust list'}))
        self.assertEqual(warns(ctx, 'CA'), [])

    def test_refused(self):
        ctx = self.deploy((403, {'detail': 'Forbidden'}))
        w = warns(ctx, 'CA')
        self.assertEqual(len(w), 1, ctx.steps)
        self.assertIn('was not added', w[0])


class MikroTikCleanupRefused(unittest.TestCase):
    def test_refused_removal_is_a_warning(self):
        b = FakeBundle()
        name = C.object_name(b, {})
        prefix = C.name_prefix(b, {})
        certs = [{'.id': '*1', 'name': prefix + '20250101-00000001', 'fingerprint': 'aa'},
                 {'.id': '*2', 'name': prefix + '20250301-00000002', 'fingerprint': 'bb'},
                 {'.id': '*9', 'name': name, 'fingerprint': b.fingerprint,
                  'private-key': 'true'}]
        services = [{'.id': '*A', 'name': 'www-ssl', 'certificate': name}]

        def delete(call):
            if call['path'].endswith('*1'):
                return 400, {'error': 400, 'message': 'Bad Request',
                             'detail': 'failure: certificate is in use'}
            return 204, b''
        ctx = FakeCtx([
            ('GET', r'/rest/certificate$', lambda c: (200, certs)),
            ('GET', r'/rest/ip/service$', lambda c: (200, services)),
            ('PATCH', r'/rest/ip/service/', (200, {})),
            ('GET', r'/rest/interface/', (200, [])),
            ('DELETE', r'/rest/certificate/', delete),
        ], ssh=FakeSsh())
        t = make('mikrotik', {'host': 'rtr', 'user': 'acme', 'password': 'pw'}, ctx)
        got = t.deploy(b, {'services': 'www-ssl', 'keep': 0})
        self.assertIn('www-ssl', got)
        self.assertEqual(len(ctx.find('DELETE', '/rest/certificate/')), 2, 'the next one tried')
        self.assertTrue([w for w in warns(ctx) if certs[0]['name'] in w])
        # remembered: the next run is a no-op
        self.assertTrue(t.deploy(b, {'services': 'www-ssl', 'keep': 0})
                        .startswith('unchanged'))


if __name__ == '__main__':
    unittest.main(verbosity=1)
