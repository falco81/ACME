#!/usr/bin/env python3
"""Discovery of the targets - "Find the settings from the account" (1.0.29).

    python3 test/test_discover_targets.py

A target's popup asks only how acme signs in to the device; the module reads
the rest of its own fields (a partition, a VDOM, a virtual system, a zone, a
resource group, a location, a KV mount, an API version) from the device's API
and the form is offered it. Read-only: the fakes of test_targets.py record
every request, and only reading calls (and the sign-in / sign-out test()
makes) are allowed. A target that can find nothing says discovery = False.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-discover-targets-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme as E  # noqa: E402
from acmelib.certs import api_discover, runtime  # noqa: E402,F401  (the routes)
from acmelib.certs import store as S  # noqa: E402
from acmelib.plugins.base import PluginError, GENERIC_DISCOVERY  # noqa: E402
from test_targets import FakeCtx, make  # noqa: E402
from test_targets_more import OpensslCtx  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)

OK_XML = '<response status="success"><result>%s</result></response>'
ARM = r'^https://management\.azure\.com'
ENTRA = ('POST', r'^https://login\.microsoftonline\.com/tid/oauth2/v2\.0/token$',
         (200, {'access_token': 'TOK', 'expires_in': 3600}))
AZ = {'subscription_id': 'sub1', 'tenant_id': 'tid', 'client_id': 'cid', 'client_secret': 'sec'}


def methods(ctx):
    return {c['method'] for c in ctx.calls}


def opts(got, key):
    return [o[0] for o in got['choices'][key]['options']]


class DescribedTest(unittest.TestCase):
    FOUND = {'fortigate': ['vdom'], 'f5': ['partition'], 'paloalto': ['vsys'],
             'checkpoint': ['domain', 'api_version'], 'cisco_fmc': ['domain_uuid'],
             'avi': ['api_version'], 'azure_appgw': ['resource_group'],
             'azure_appservice': ['resource_group'], 'gcp_certmanager': ['location'],
             'cloudflare_ssl': ['zone'], 'vault': ['mount'], 'nutanix': ['cluster']}

    def test_each_target_says_it(self):
        reg = S.registry()
        for kind, cls in reg.all('target').items():
            if kind == 'webglobe':
                continue
            if kind in self.FOUND:
                self.assertTrue(cls.discover_offered(), kind)
                self.assertIsNotNone(cls.discover_keys, kind)
                keys = cls.discover_keys_of()
                self.assertEqual(keys, [k for k in cls.discover_keys
                                        if k in {f['key'] for f in cls.fields}], kind)
                for k in self.FOUND[kind]:
                    self.assertNotIn(k, keys, '%s asks what it finds (%s)' % (kind, k))
                if kind != 'nutanix':
                    self.assertNotIn(cls.discover_setup, GENERIC_DISCOVERY, kind)
            else:
                self.assertIs(vars(cls).get('discovery'), False, kind)
                self.assertIsNone(cls.describe()['discover'], kind)


class FortiGateTest(unittest.TestCase):
    def test_vdom_from_the_status(self):
        ctx = FakeCtx([('GET', r'/api/v2/monitor/system/status$', (200, {
            'status': 'success', 'vdom': 'dmz', 'version': 'v7.4.3', 'serial': 'FG100F',
            'results': {'hostname': 'fw1', 'model_name': 'FortiGate'}}))])
        got = make('fortigate', {'host': 'fw', 'token': 'TKN', 'vdom': ''}, ctx).discover_setup()
        c = got['choices']['vdom']
        self.assertEqual([o[0] for o in c['options']], ['', 'dmz'])
        self.assertEqual(c['pick'], 'dmz')
        self.assertIn(['FortiOS', 'v7.4.3'], got['facts'])
        self.assertEqual(methods(ctx), {'GET'})
        self.assertNotIn('vdom', ctx.calls[0]['query'], 'asked without a VDOM')


class F5Test(unittest.TestCase):
    def test_partitions_of_the_certificates(self):
        ctx = FakeCtx([
            ('POST', r'/mgmt/shared/authn/login$', (200, {'token': {'token': 'TOK'}})),
            ('DELETE', r'/mgmt/shared/authz/tokens/TOK$', (200, {})),
            ('GET', r'/mgmt/tm/sys/version$', (200, {'entries': {'x': {'nestedStats': {
                'entries': {'Product': {'description': 'BIG-IP'},
                            'Version': {'description': '17.1.0'}}}}}})),
            ('GET', r'/mgmt/tm/sys/crypto/cert$', (200, {'items': [
                {'name': 'default.crt', 'partition': 'Common'},
                {'name': 'a.crt', 'partition': 'Tenant_A'},
                {'name': 'b.crt', 'partition': 'Tenant_A'}]})),
        ])
        got = make('f5', {'host': 'bigip', 'user': 'acme', 'password': 'pw'},
                   ctx).discover_setup()
        self.assertEqual(opts(got, 'partition'), ['Common', 'Tenant_A'])
        self.assertEqual(got['choices']['partition']['pick'], 'Common')
        self.assertIn(['BIG-IP', 'BIG-IP 17.1.0'], got['facts'])
        # only reading - the sign-in and its token deleted again, as test() does
        self.assertEqual([(c['method'], c['path']) for c in ctx.calls if c['method'] != 'GET'],
                         [('POST', '/mgmt/shared/authn/login'),
                          ('DELETE', '/mgmt/shared/authz/tokens/TOK')])


class PaloAltoTest(unittest.TestCase):
    def setUp(self):
        self.asked = []

        def api(call):
            p = urllib.parse.parse_qs(call['body'].decode())
            self.asked.append((p['type'][0], p.get('action', [''])[0]))
            if p['type'][0] == 'version':
                return 200, OK_XML % ('<system><hostname>pa1</hostname><model>PA-440</model>'
                                      '<sw-version>11.1.2</sw-version></system>')
            if p['type'][0] == 'config':
                return 200, OK_XML % (
                    '<vsys><entry name="vsys1"><display-name>Main</display-name>'
                    '<address><entry name="a1"/></address></entry>'
                    '<entry name="vsys2"/></vsys>')
            raise AssertionError(p)
        self.ctx = FakeCtx([('POST', r'/api/$', api)])

    def test_virtual_systems(self):
        got = make('paloalto', {'host': 'pa', 'api_key': 'K'}, self.ctx).discover_setup()
        self.assertEqual(opts(got, 'vsys'), ['', 'vsys1', 'vsys2'])
        self.assertEqual(got['choices']['vsys']['pick'], '')
        self.assertIn(['vsys1', 'Main (vsys1)'], got['choices']['vsys']['options'])
        self.assertIn(['PAN-OS', '11.1.2'], got['facts'])
        self.assertEqual(self.asked, [('version', ''), ('config', 'get')])
        self.assertTrue(all(c['headers'].get('X-PAN-KEY') == 'K' for c in self.ctx.calls))


class CheckPointTest(unittest.TestCase):
    def ctx(self, mds=True):
        self.cmds, self.login = [], None

        def web(call):
            cmd = call['path'].rsplit('/', 1)[1]
            self.cmds.append(cmd)
            b = json.loads(call['body']) if call['body'] else {}
            if cmd == 'login':
                self.login = b
                return 200, {'sid': 'SID1'}
            if cmd == 'logout':
                return 200, {'message': 'OK'}
            if cmd == 'show-api-versions':
                return 200, {'current-version': '1.9', 'supported-versions':
                             ['1', '1.1', '1.10', '1.9']}
            if cmd == 'show-domains':
                if not mds:
                    return 400, {'code': 'generic_err_command_not_found',
                                 'message': 'not a Multi-Domain Server'}
                return 200, {'objects': [{'name': 'Dom_A', 'uid': 'u1'},
                                         {'name': 'Dom_B', 'uid': 'u2'}],
                             'from': 1, 'to': 2, 'total': 2}
            raise AssertionError(cmd)
        return FakeCtx([('POST', r'/web_api/', web)])

    def test_versions_and_domains(self):
        got = make('checkpoint', {'host': 'mgmt', 'user': 'admin', 'password': 'pw'},
                   self.ctx()).discover_setup()
        self.assertEqual(opts(got, 'api_version'), ['', 'v1.10', 'v1.9', 'v1.1', 'v1'])
        self.assertEqual(got['choices']['api_version']['pick'], '')
        self.assertEqual(opts(got, 'domain'), ['', 'Dom_A', 'Dom_B'])
        self.assertIn(['Management API', '1.9'], got['facts'])
        self.assertTrue(self.login.get('read-only'), 'a read-only session')
        self.assertEqual(self.cmds, ['login', 'show-api-versions', 'show-domains', 'logout'])

    def test_no_domains_said(self):
        got = make('checkpoint', {'host': 'mgmt', 'user': 'admin', 'password': 'pw'},
                   self.ctx(mds=False)).discover_setup()
        self.assertNotIn('domain', got['choices'])
        self.assertTrue(any('Multi-Domain' in n for n in got['notes']))
        self.assertEqual(self.cmds[-1], 'logout')


class CiscoFmcTest(unittest.TestCase):
    def test_domain_of_the_sign_in(self):
        dom = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
        ctx = FakeCtx([('POST', r'/api/fmc_platform/v1/auth/generatetoken$',
                        (204, b'', {'X-auth-access-token': 'TOK', 'DOMAIN_UUID': dom}))])
        got = make('cisco_fmc', {'host': 'fmc', 'user': 'api', 'password': 'pw'},
                   ctx).discover_setup()
        self.assertEqual(opts(got, 'domain_uuid'), ['', dom])
        self.assertEqual(got['choices']['domain_uuid']['pick'], '')
        self.assertEqual([c['path'] for c in ctx.calls], ['/api/fmc_platform/v1/auth/generatetoken'])
        # a Domain UUID set stays the one used, the sign-in's still offered
        ctx = FakeCtx([('POST', r'/generatetoken$',
                        (204, b'', {'X-auth-access-token': 'TOK', 'DOMAIN_UUID': dom}))])
        t = make('cisco_fmc', {'host': 'fmc', 'user': 'api', 'password': 'pw',
                               'domain_uuid': 'other'}, ctx)
        got = t.discover_setup()
        self.assertEqual(t.domain, 'other')
        self.assertEqual(opts(got, 'domain_uuid'), ['', dom])


class AviTest(unittest.TestCase):
    def test_version_of_the_controller(self):
        cookies = 'csrftoken=C1; Path=/, sessionid=S1; Path=/; HttpOnly'
        ctx = FakeCtx([
            ('POST', r'/login$', (200, {'version': {'Version': '22.1.6'}},
                                  {'Set-Cookie': cookies})),
            ('POST', r'/logout$', (200, {})),
        ])
        got = make('avi', {'host': 'avi.test', 'user': 'admin', 'password': 'pw'},
                   ctx).discover_setup()
        self.assertEqual(opts(got, 'api_version'), ['', '22.1.6'])
        self.assertEqual(got['choices']['api_version']['pick'], '')
        self.assertEqual([c['path'] for c in ctx.calls], ['/login', '/logout'])


class AzureTest(unittest.TestCase):
    def test_app_gateway_resource_groups(self):
        gws = [{'name': 'agw-www', 'id': '/subscriptions/sub1/resourceGroups/rg-web/providers/'
                                         'Microsoft.Network/applicationGateways/agw-www'},
               {'name': 'agw-api', 'id': '/subscriptions/sub1/resourceGroups/rg-web/providers/'
                                         'Microsoft.Network/applicationGateways/agw-api'}]
        more = [{'name': 'agw-x', 'id': '/subscriptions/sub1/resourceGroups/rg-x/providers/'
                                        'Microsoft.Network/applicationGateways/agw-x'}]
        nxt = 'https://management.azure.com/subscriptions/sub1/providers/Microsoft.Network/' \
              'applicationGateways?api-version=2026-03-01&$skiptoken=2'
        ctx = FakeCtx([
            ENTRA,
            ('GET', ARM + r'/subscriptions/sub1/providers/Microsoft\.Network/applicationGateways'
                          r'\?api-version=2026-03-01$', (200, {'value': gws, 'nextLink': nxt})),
            ('GET', r'skiptoken=2$', (200, {'value': more})),
        ])
        got = make('azure_appgw', dict(AZ), ctx).discover_setup()
        self.assertEqual(opts(got, 'resource_group'), ['rg-web', 'rg-x'])
        self.assertIn(['rg-web', 'rg-web (agw-api, agw-www)'],
                      got['choices']['resource_group']['options'])
        self.assertIn(['Application gateways in the subscription', '3'], got['facts'])
        self.assertEqual([c['method'] for c in ctx.calls], ['POST', 'GET', 'GET'])

    def test_app_service_resource_groups(self):
        ctx = FakeCtx([
            ENTRA,
            ('GET', ARM + r'/subscriptions/sub1/providers/Microsoft\.Web/certificates'
                          r'\?api-version=2023-12-01$', (200, {'value': [
                              {'name': 'c1', 'id': '/subscriptions/sub1/resourceGroups/rg1/'
                                                   'providers/Microsoft.Web/certificates/c1'},
                              {'name': 'c2', 'id': '/subscriptions/sub1/resourceGroups/rg1/'
                                                   'providers/Microsoft.Web/certificates/c2'}]})),
        ])
        got = make('azure_appservice', dict(AZ, resource_group='rg1'), ctx).discover_setup()
        self.assertEqual(got['choices']['resource_group']['options'], [['rg1', 'rg1 (2)']])
        self.assertEqual(got['choices']['resource_group']['pick'], 'rg1')
        self.assertTrue(got['notes'])
        self.assertEqual(methods(ctx), {'POST', 'GET'})
        self.assertEqual(len(ctx.find('POST', '.')), 1, 'only the sign-in')

    def test_no_subscription_said(self):
        with self.assertRaises(PluginError):
            make('azure_appgw', dict(AZ, subscription_id=''), FakeCtx([])).discover_setup()


class GcpTest(unittest.TestCase):
    def test_locations(self):
        key = subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                              'rsa_keygen_bits:2048'], capture_output=True, check=True).stdout
        sa = {'type': 'service_account', 'project_id': 'proj-1',
              'client_email': 'acme@proj-1.iam.gserviceaccount.com',
              'private_key': key.decode(), 'private_key_id': 'kid1'}
        base = r'^https://certificatemanager\.googleapis\.com/v1/projects/proj-1/locations'
        ctx = OpensslCtx([
            ('POST', r'^https://oauth2\.googleapis\.com/token$', (200, {'access_token': 'GT'})),
            ('GET', base + r'\?pageSize=500$', (200, {'locations': [
                {'name': 'projects/proj-1/locations/europe-west3', 'locationId': 'europe-west3',
                 'displayName': 'Frankfurt'}], 'nextPageToken': 'P2'})),
            ('GET', base + r'\?pageSize=500&pageToken=P2$', (200, {'locations': [
                {'name': 'projects/proj-1/locations/global', 'locationId': 'global'}]})),
        ])
        t = make('gcp_certmanager', {'service_account': json.dumps(sa)}, ctx)
        t._now = 1793534400
        got = t.discover_setup()
        self.assertEqual(opts(got, 'location'), ['global', 'europe-west3'])
        self.assertEqual(got['choices']['location']['pick'], 'global')
        self.assertIn(['europe-west3', 'europe-west3 (Frankfurt)'],
                      got['choices']['location']['options'])
        self.assertIn(['Project', 'proj-1'], got['facts'])
        self.assertEqual(len(ctx.find('POST', '.')), 1, 'only the sign-in')
        self.assertEqual(methods(ctx), {'POST', 'GET'})


class CloudflareTest(unittest.TestCase):
    B = r'^https://api\.cloudflare\.com/client/v4'

    def routes(self):
        return [
            ('GET', self.B + r'/zones\?per_page=50&page=1$', (200, {
                'success': True, 'result': [{'id': 'a' * 32, 'name': 'example.test',
                                             'plan': {'name': 'Business'}}],
                'result_info': {'page': 1, 'total_pages': 2}})),
            ('GET', self.B + r'/zones\?per_page=50&page=2$', (200, {
                'success': True, 'result': [{'id': 'b' * 32, 'name': 'another.test'}],
                'result_info': {'page': 2, 'total_pages': 2}})),
        ]

    def test_zones(self):
        ctx = FakeCtx(self.routes())
        got = make('cloudflare_ssl', {'token': 'T'}, ctx).discover_setup()
        self.assertEqual(got['choices']['zone']['options'],
                         [['another.test', 'another.test'],
                          ['example.test', 'example.test (Business)']])
        self.assertEqual(got['choices']['zone']['pick'], '')
        self.assertEqual(methods(ctx), {'GET'})

    def test_through_the_endpoint(self):
        """POST /api/targets/discover: the zones found, nothing saved, Try it said as a
        note (no zone is set yet)."""
        routes = self.routes()
        orig = runtime.RunContext.http

        def http(ctx, method, url, *a, **kw):
            fake = FakeCtx(routes)
            st, hd, data = fake.http(method, url, *a, **kw)
            self.assertEqual(method, 'GET')
            return st, hd, data
        runtime.RunContext.http = http
        try:
            h = type('H', (), {'store': STORE, 'body': lambda s: {
                'kind': 'cloudflare_ssl', 'config': {'token': 'cf-token-x9'}},
                'me': lambda s, r: {'name': 'x', 'role': 'fulladmin'}})()
            got = E.ROUTES[('POST', '/api/targets/discover')](h)
        finally:
            runtime.RunContext.http = orig
        self.assertTrue(got['ok'], got)
        self.assertEqual([o[0] for o in got['found']['choices']['zone']['options']],
                         ['another.test', 'example.test'])
        self.assertNotIn('cf-token-x9', json.dumps(got))
        self.assertTrue(any(n.startswith('Try it:') for n in got['found']['notes']))


class VaultTest(unittest.TestCase):
    def test_kv2_mounts(self):
        ctx = FakeCtx([
            ('POST', r'/v1/auth/approle/login$', (200, {'auth': {'client_token': 'VT'}})),
            ('GET', r'/v1/auth/token/lookup-self$', (200, {'data': {
                'display_name': 'approle', 'policies': ['acme']}})),
            ('GET', r'/v1/sys/internal/ui/mounts$', (200, {'data': {'secret': {
                'secret/': {'type': 'kv', 'options': {'version': '2'}},
                'certs/': {'type': 'kv', 'options': {'version': '2'},
                           'description': 'TLS'},
                'old/': {'type': 'kv', 'options': {'version': '1'}},
                'pki/': {'type': 'pki'}}, 'auth': {'approle/': {'type': 'approle'}}}})),
        ])
        got = make('vault', {'host': 'https://vault:8200', 'auth': 'approle', 'role_id': 'r',
                             'secret_id': 's'}, ctx).discover_setup()
        self.assertEqual(got['choices']['mount']['options'],
                         [['certs', 'certs (TLS)'], ['secret', 'secret']])
        self.assertEqual(got['choices']['mount']['pick'], 'secret')
        self.assertTrue(any('version 1' in n for n in got['notes']))
        self.assertEqual([c['method'] for c in ctx.calls], ['POST', 'GET', 'GET'])
        self.assertEqual(ctx.calls[2]['headers'].get('X-Vault-Token'), 'VT')


class NutanixTest(unittest.TestCase):
    def test_clusters_of_the_list(self):
        ctx = FakeCtx([('GET', r'/api/clustermgmt/v4\.3/config/clusters$', (200, {'data': [
            {'extId': '00061de0-6c4e-25a1-0000-00000000aa11', 'name': 'c1'}]}))])
        got = make('nutanix', {'host': 'pc', 'user': 'admin', 'password': 'pw'},
                   ctx).discover_setup()
        c = got['choices']['cluster_pick']
        self.assertEqual(c['pick'], '00061de0-6c4e-25a1-0000-00000000aa11')
        self.assertEqual(c['sets'][c['pick']], {'cluster': c['pick']})
        self.assertEqual(methods(ctx), {'GET'})


class ErrorsTest(unittest.TestCase):
    def test_refused_sign_in_said(self):
        ctx = FakeCtx([('GET', r'/monitor/system/status$', (401, {'status': 'error'}))])
        with self.assertRaises(PluginError) as e:
            make('fortigate', {'host': 'fw', 'token': 'bad'}, ctx).discover_setup()
        self.assertIn('401', str(e.exception))

    def test_the_f5_token_deleted_on_a_failure(self):
        ctx = FakeCtx([
            ('POST', r'/authn/login$', (200, {'token': {'token': 'TOK'}})),
            ('DELETE', r'/authz/tokens/TOK$', (200, {})),
            ('GET', r'/sys/version$', (500, {'message': 'busy'})),
        ])
        with self.assertRaises(PluginError):
            make('f5', {'host': 'b', 'user': 'u', 'password': 'p'}, ctx).discover_setup()
        self.assertTrue(ctx.find('DELETE', r'/authz/tokens/TOK$'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
