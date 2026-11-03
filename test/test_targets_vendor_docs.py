#!/usr/bin/env python3
"""The target modules added from the vendors' API documents (second set) -
Cisco FTD (FDM), Cisco ASA (HTTP interface), Juniper SRX (REST API), Azure
Application Gateway, ISPConfig, HestiaCP (SSH), Virtualmin, froxlor, Proxmox
Backup Server - without a network.

    python3 -m unittest test/test_targets_vendor_docs.py

The fake Context and certificates are those of test_targets.py: every request is
recorded and answered from a little fake of the device's API; the tests look at
what was asked against the documents, at the same certificate twice being a
no-op, at old ones being cleaned up (never one still in use) and at errors.
"""
import base64
import json
import os
import re
import sys
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh, make, read  # noqa: E402
from test_targets_appliances import p12_ok  # noqa: E402
from acmelib.plugins.base import PluginError, Registry, FIELD_TYPES  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402

KINDS = ('cisco_ftd_fdm', 'cisco_asa', 'juniper_srx', 'azure_appgw', 'ispconfig', 'hestiacp',
         'virtualmin', 'froxlor', 'proxmox_backup')


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def body(call):
    return json.loads(call['body'])


def olds(b, n=3, maxlen=63, prefix=None):
    p = prefix or C.name_prefix(b, {}, maxlen=maxlen)
    return [p + '2026%02d01-aaaa000%d' % (i + 1, i) for i in range(n)]


def form_of(call):
    return dict(urllib.parse.parse_qsl(call['body'].decode(), keep_blank_values=True))


def nosleep(t):
    t._sleep = lambda s: None
    return t


# ---------------------------------------------------------------------------
class FtdFdmTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        o = olds(self.a, maxlen=128)
        self.certs = {('c%d' % i): {'id': 'c%d' % i, 'name': n, 'type': 'internalcertificate',
                                    'version': 'v1'} for i, n in enumerate(o)}
        self.certs['sys'] = {'id': 'sys', 'name': 'DefaultInternalCertificate',
                             'type': 'internalcertificate', 'isSystemDefined': True}
        self.cas = {}
        self.webui = {'id': 'W1', 'name': 'webui', 'type': 'webuicertificate', 'version': 'w1',
                      'certificate': {'id': 'c2', 'name': o[2], 'type': 'internalcertificate'},
                      'trustChain': [], 'links': {'self': 'x'}}
        self.vpn = {'id': 'V1', 'name': 'ravpn', 'type': 'ravpn', 'version': 'r1',
                    'vpnGatewaySettings': {'outsideInterface': {'id': 'if1'},
                                           'serverCertificate': {'id': 'c1', 'name': o[1]}}}
        self.deploys = []

        def token(call):
            b = body(call)
            assert b == {'grant_type': 'password', 'username': 'admin', 'password': 'pw'}, b
            return 200, {'access_token': 'TOK', 'expires_in': 1800, 'token_type': 'Bearer'}

        def page(items, call):
            off = int(call['query'].get('offset', ['0'])[0])
            lim = int(call['query'].get('limit', ['10'])[0])
            assert lim <= 10
            return 200, {'items': items[off:off + lim]}

        def certs(call):
            assert call['headers']['Authorization'] == 'Bearer TOK'
            if call['method'] == 'GET':
                return page(list(self.certs.values()), call)
            if call['method'] == 'POST':
                b = body(call)
                cid = 'n%d' % len(self.certs)
                self.certs[cid] = dict(b, id=cid, version='v1')
                return 200, self.certs[cid]
            del self.certs[call['path'].rsplit('/', 1)[1]]
            return 204, b''

        def cas(call):
            if call['method'] == 'GET':
                return page(list(self.cas.values()), call)
            b = body(call)
            self.cas[b['name']] = dict(b, id='ca%d' % len(self.cas), version='1',
                                       subjectDistinguishedName='CN=Test CA')
            return 200, self.cas[b['name']]

        def webui(call):
            if call['method'] == 'GET':
                return 200, {'items': [self.webui]}
            self.webui = body(call)
            return 200, self.webui

        def vpn(call):
            if call['method'] == 'GET':
                return 200, {'items': [self.vpn]}
            self.vpn = body(call)
            return 200, self.vpn

        def dep(call):
            if call['method'] == 'POST':
                self.deploys.append('D%d' % len(self.deploys))
                return 200, {'id': self.deploys[-1], 'state': 'QUEUED'}
            return 200, {'id': self.deploys[-1], 'state': 'DEPLOYED',
                         'statusMessage': 'Deployed Successfully'}
        api = r'https://ftd\.test/api/fdm/latest'
        self.ctx = FakeCtx([
            ('POST', api + r'/fdm/token$', token),
            ('GET', api + r'/object/internalcertificates\?', certs),
            ('POST', api + r'/object/internalcertificates$', certs),
            ('DELETE', api + r'/object/internalcertificates/', certs),
            ('GET', api + r'/object/externalcacertificates\?', cas),
            ('POST', api + r'/object/externalcacertificates$', cas),
            ('GET', api + r'/devicesettings/default/webuicertificates$', webui),
            ('PUT', api + r'/devicesettings/default/webuicertificates/W1$', webui),
            ('GET', api + r'/ravpns\?', vpn),
            ('PUT', api + r'/ravpns/V1$', vpn),
            ('POST', api + r'/operational/deploy$', dep),
            ('GET', api + r'/operational/deploy/', dep),
        ])
        self.t = nosleep(make('cisco_ftd_fdm', {'host': 'ftd.test', 'user': 'admin',
                                                'password': 'pw'}, self.ctx))

    def test_upload_switch_deploy_cleanup_noop(self):
        name = C.object_name(self.a, {}, maxlen=128)
        o = olds(self.a, maxlen=128)
        words = self.t.deploy(self.a, {'ravpn': True, 'keep': '0'})
        post = body(self.ctx.find('POST', r'/internalcertificates$')[0])
        self.assertEqual(post, {'type': 'internalcertificate', 'name': name, 'certType': 'UPLOAD',
                                'cert': self.a.cert_pem, 'privateKey': self.a.key_pem})
        new = [c for c in self.certs.values() if c.get('name') == name][0]
        self.assertEqual(self.webui['certificate'], {'id': new['id'], 'name': name,
                                                     'type': 'internalcertificate',
                                                     'version': 'v1'})
        self.assertNotIn('links', self.webui)
        self.assertEqual([c['name'] for c in self.webui['trustChain']],
                         ['acme-ca-%s' % C.chain_id(self.a.chain_pems[0])])
        self.assertEqual(self.vpn['vpnGatewaySettings']['serverCertificate']['id'], new['id'])
        self.assertEqual(self.vpn['vpnGatewaySettings']['outsideInterface'], {'id': 'if1'})
        self.assertIn('deployed', words)
        # all older acme ones go (keep 0), the system one stays; deployed again after deleting
        self.assertEqual(sorted(c['name'] for c in self.certs.values()),
                         sorted(['DefaultInternalCertificate', name]))
        self.assertEqual(len(self.deploys), 2)
        self.assertNotIn(o[0], [c['name'] for c in self.certs.values()])
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, {'ravpn': True, 'keep': '0'})
                        .startswith('unchanged'))
        self.assertEqual({c['method'] for c in self.ctx.calls[n:]}, {'GET'})

    def test_paging_and_test_and_errors(self):
        for i in range(25):
            self.certs['x%d' % i] = {'id': 'x%d' % i, 'name': 'other-%d' % i}
        self.assertIn('29 internal certificates', self.t.test())
        self.assertEqual({c['method'] for c in self.ctx.calls}, {'GET', 'POST'})
        ctx = FakeCtx([('POST', r'/fdm/token$', (400, {'message': 'Invalid credentials'}))])
        with self.assertRaises(PluginError) as e:
            make('cisco_ftd_fdm', {'host': 'ftd.test', 'user': 'admin', 'password': 'x'},
                 ctx).test()
        self.assertFalse(e.exception.retry)

    def test_deploy_fails_and_no_deploy(self):
        self.t.deploy(self.a, {'fdm_deploy': False, 'keep': '-1'})
        self.assertEqual(self.deploys, [])
        self.assertTrue(any('pending' in w for _l, w in self.ctx.steps))
        ctx = self.ctx
        ctx.routes = [r for r in ctx.routes if 'operational/deploy/' not in r[1]] + [
            ('GET', r'/operational/deploy/', (200, {'id': 'D0', 'state': 'DEPLOY_FAILED',
                                                    'statusMessage': 'bad'}))]
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'force': True})
        self.assertIn('DEPLOY_FAILED', str(e.exception))


# ---------------------------------------------------------------------------
class CiscoAsaTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        o = olds(self.a, maxlen=128)
        self.o = o
        self.tps = [o[0], o[1], o[2], 'ASDM_TrustPoint0']
        self.ssl = [(o[2], 'outside'), ('ASDM_TrustPoint0', '')]
        self.configs = []

        def ex(call):
            assert call['headers']['User-Agent'] == 'ASDM'
            assert call['headers']['Authorization'] == 'Basic ' + base64.b64encode(
                b'api:pw').decode()
            cmds = [urllib.parse.unquote_plus(x) for x in
                    call['url'].split('/admin/exec/', 1)[1].split('/')]
            out = []
            for c in cmds:
                if c == 'show running-config crypto ca trustpoint':
                    out += ['crypto ca trustpoint %s\n enrollment terminal' % t for t in self.tps]
                elif c == 'show running-config ssl trust-point':
                    out += [('ssl trust-point %s %s' % s).strip() for s in self.ssl]
                elif c == 'show version':
                    out.append('Cisco Adaptive Security Appliance Software Version 9.20(2)')
                elif c == 'write memory':
                    out.append('Building configuration...\nCryptochecksum: 1 2 3 4\n[OK]')
            return 200, '\n'.join(out) + '\n'

        def conf(call):
            lines = call['body'].decode().splitlines()
            self.configs.append(lines)
            out = []
            for ln in lines:
                m = re.match(r'crypto ca import (\S+) pkcs12 (\S+) nointeractive$', ln)
                if m:
                    self.tps.append(m.group(1))
                    out.append('Enter the PKCS12 data in base64 representation....\n'
                               'INFO: Import PKCS12 operation completed successfully')
                m = re.match(r'(no )?ssl trust-point (\S+) ?(.*)$', ln)
                if m:
                    s = (m.group(2), m.group(3).strip())
                    if m.group(1):
                        self.ssl.remove(s)
                    else:
                        self.ssl.append(s)
                m = re.match(r'no crypto ca trustpoint (\S+) noconfirm$', ln)
                if m:
                    self.tps.remove(m.group(1))
                    self.ssl = [s for s in self.ssl if s[0] != m.group(1)]
            return 200, '\n'.join(out + ['Cryptochecksum (changed): 1 2 3 4', 'Config OK'])
        self.ctx = FakeCtx([('GET', r'https://asa\.test/admin/exec/', ex),
                            ('POST', r'https://asa\.test/admin/config$', conf)])
        self.t = make('cisco_asa', {'host': 'asa.test', 'user': 'api', 'password': 'pw'},
                      self.ctx)

    def test_import_switch_cleanup_save_noop(self):
        name = C.object_name(self.a, {}, maxlen=128)
        self.t.deploy(self.a, {'trust_points': 'inside\n-', 'keep': '0'})
        imp = self.configs[0]
        self.assertEqual(imp[:3], ['crypto ca trustpoint %s' % name, 'exit',
                                   imp[2]])
        m = re.match(r'crypto ca import (\S+) pkcs12 (\S+) nointeractive$', imp[2])
        self.assertEqual(m.group(1), name)
        self.assertEqual(imp[-1], 'quit')
        self.assertTrue(all(len(x) <= 64 for x in imp[3:-1]))
        self.assertTrue(p12_ok(''.join(imp[3:-1]),
                               base64.b64encode(m.group(2).encode()).decode()))
        # the older acme one on outside follows, inside and the fallback are added
        self.assertIn((name, 'outside'), self.ssl)
        self.assertIn((name, 'inside'), self.ssl)
        self.assertIn((name, ''), self.ssl)
        self.assertNotIn((self.o[2], 'outside'), self.ssl)
        self.assertIn(('ASDM_TrustPoint0', ''), self.ssl)        # not ours: untouched
        self.assertEqual(sorted(self.tps), sorted(['ASDM_TrustPoint0', name]))
        self.assertTrue(self.ctx.find('GET', r'/admin/exec/write\+memory$'))
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, {'trust_points': 'inside\n-', 'keep': '0'})
                        .startswith('unchanged'))
        self.assertEqual({c['method'] for c in self.ctx.calls[n:]}, {'GET'})

    def test_error_in_a_200(self):
        self.ctx.routes.insert(0, ('POST', r'/admin/config$', (
            200, 'ERROR: NV RAM will not have enough space to save keypair central.')))
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'trust_points': 'outside'})
        self.assertIn('NV RAM', str(e.exception))
        self.assertFalse(e.exception.retry)

    def test_test_reads_only(self):
        self.assertIn('9.20(2)', self.t.test())
        self.assertEqual({c['method'] for c in self.ctx.calls}, {'GET'})


# ---------------------------------------------------------------------------
class JuniperSrxTest(unittest.TestCase):
    def setUp(self):
        from acmelib.plugins.targets import juniper_srx as J
        self.J = J
        self.a = FakeBundle()
        p = J.srx_prefix(self.a, {})
        self.o = [p + '2026%02d01-aaa00%d' % (i + 1, i) for i in range(2)]
        self.ids = list(self.o) + ['system-generated']
        self.posts = []
        self.files = {}

        def get(call):
            assert call['headers']['Authorization'] == 'Basic ' + base64.b64encode(
                b'acme:pw').decode()
            if 'get-software-information' in call['url']:
                return 200, ('<software-information><host-name>srx1</host-name>'
                             '<junos-version>23.4R1</junos-version></software-information>')
            return 200, ('<x509-pki-certificate-info-list xmlns="http://xml.juniper.net/junos/'
                         '23.4R1/junos-pki">%s</x509-pki-certificate-info-list>' % ''.join(
                             '<x509-certificate-info><identifier>%s</identifier>'
                             '</x509-certificate-info>' % i for i in self.ids))

        def post(call):
            x = call['body'].decode()
            self.posts.append(x)
            m = re.search(r'<file-put><filename>(.*?)</filename>.*<file-contents>(.*?)'
                          r'</file-contents>', x, re.S)
            if m:
                self.files[m.group(1)] = base64.b64decode(m.group(2))
            m = re.search(r'<load-pki-local-certificate><certificate-id>(.*?)</certificate-id>',
                          x)
            if m:
                self.ids.append(m.group(1))
            m = re.search(r'<clear-pki-local-certificate><certificate-id>(.*?)<', x)
            if m:
                self.ids.remove(m.group(1))
            return 200, '<rpc-reply><ok/></rpc-reply>'
        self.ctx = FakeCtx([('GET', r'https://srx\.test:3443/rpc/', get),
                            ('POST', r'https://srx\.test:3443/rpc\?stop-on-error=1$', post)])
        self.t = make('juniper_srx', {'host': 'srx.test', 'user': 'acme', 'password': 'pw'},
                      self.ctx)

    def test_id_rules(self):
        cid = self.J.srx_id(self.a, {})
        self.assertLessEqual(len(cid), 32)
        self.assertFalse(re.search(r'[./% ]', cid), cid)
        self.assertTrue(C.ours(cid, self.J.srx_prefix(self.a, {})))
        long = self.J.srx_id(self.a, {'object_name': 'a-very-long-name.of.a.service.example'})
        other = self.J.srx_id(self.a, {'object_name': 'a-very-long-name.of.another.example'})
        self.assertLessEqual(len(long), 32)
        self.assertNotEqual(self.J.srx_prefix(self.a, {'object_name':
                                                       'a-very-long-name.of.a.service.example'}),
                            self.J.srx_prefix(self.a, {'object_name':
                                                       'a-very-long-name.of.another.example'}))
        self.assertNotEqual(long, other)

    def test_load_commit_cleanup_noop(self):
        cid = self.J.srx_id(self.a, {})
        opts = {'ssl_termination': 'tls-in', 'ike_policies': 'ike1', 'keep': '0'}
        self.t.deploy(self.a, opts)
        load = [x for x in self.posts if 'load-pki-local-certificate' in x][0]
        self.assertIn('<filename>/var/tmp/%s.crt</filename><key>/var/tmp/%s.key</key>'
                      % (cid, cid), load)
        # written, then emptied again (no key left in /var/tmp)
        self.assertEqual(self.files['/var/tmp/%s.key' % cid], b'\n')
        puts = [x for x in self.posts if '<file-put>' in x]
        self.assertEqual(len(puts), 4)
        first = base64.b64decode(re.search(r'<file-contents>(.*?)<', puts[0]).group(1))
        self.assertEqual(first.decode(), self.a.fullchain_pem)
        self.assertIn('<delete-if-exist/>', puts[0])
        commit = [x for x in self.posts if 'commit-configuration' in x][0]
        self.assertTrue(commit.startswith('<lock-configuration/><load-configuration action="set" '
                                          'format="text">'))
        self.assertIn('set system services web-management https pki-local-certificate %s'
                      % cid, commit)
        self.assertIn('set services ssl termination profile tls-in server-certificate %s' % cid,
                      commit)
        self.assertIn('delete security ike policy ike1 certificate local-certificate %s'
                      % self.o[0], commit)
        self.assertTrue(commit.endswith('<unlock-configuration/>'))
        self.assertEqual(sorted(self.ids), sorted(['system-generated', cid]))
        self.assertTrue(any('clear-pki-key-pair' in x for x in self.posts))
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, opts).startswith('unchanged'))
        self.assertEqual({c['method'] for c in self.ctx.calls[n:]}, {'GET'})

    def test_error_and_test(self):
        self.assertIn('23.4R1', self.t.test())
        self.ctx.routes.insert(0, ('POST', r'/rpc\?', lambda c: (200, (
            '<rpc-reply><xnm:error xmlns:xnm="x"><message>Failed to load the certificate'
            '</message></xnm:error></rpc-reply>') if 'load-pki' in c['body'].decode() else
            '<rpc-reply><ok/></rpc-reply>')))
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {})
        self.assertIn('Failed to load', str(e.exception))
        # the files were emptied all the same
        self.assertTrue(self.ctx.find('POST', r'/rpc\?'))
        emptied = [c for c in self.ctx.calls if c['method'] == 'POST' and
                   '<file-contents>%s</file-contents>' % base64.b64encode(b'\n').decode()
                   in c['body'].decode()]
        self.assertEqual(len(emptied), 2)


# ---------------------------------------------------------------------------
class AzureAppGwTest(unittest.TestCase):
    SUB, RG = 'sub-1', 'rg-1'

    def setUp(self):
        self.a = FakeBundle()
        o = olds(self.a, maxlen=80)
        self.o = o
        gid = ('/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/'
               'applicationGateways/agw')
        self.gid = gid
        self.gw = {'id': gid, 'name': 'agw', 'etag': 'W/"1"', 'location': 'westeurope',
                   'tags': {'team': 'web'},
                   'identity': {'type': 'UserAssigned', 'userAssignedIdentities': {'x': {}}},
                   'properties': {
                       'provisioningState': 'Succeeded',
                       'sslCertificates': [
                           {'name': n, 'id': gid + '/sslCertificates/' + n,
                            'properties': {'publicCertData': 'xx'}} for n in o] + [
                           {'name': 'manual', 'properties': {'publicCertData': 'yy'}}],
                       'httpListeners': [
                           {'name': 'https-www', 'properties': {
                               'protocol': 'Https', 'hostName': 'www.example.test',
                               'sslCertificate': {'id': gid + '/sslCertificates/' + o[2]}}},
                           {'name': 'https-api', 'properties': {
                               'protocol': 'Https',
                               'sslCertificate': {'id': gid + '/sslCertificates/manual'}}},
                           {'name': 'http', 'properties': {'protocol': 'Http'}}],
                       'listeners': [
                           {'name': 'tls-l4', 'properties': {
                               'protocol': 'Tls',
                               'sslCertificate': {'id': gid + '/sslCertificates/' + o[1]}}}]}}
        self.puts, self.patches = [], []
        self.polls = 0

        def gw(call):
            assert call['headers']['Authorization'] == 'Bearer AZTOKEN'
            assert call['query']['api-version'] == ['2026-03-01']
            if call['method'] == 'GET':
                g = json.loads(json.dumps(self.gw))
                if self.polls:
                    self.polls -= 1
                    g['properties']['provisioningState'] = 'Updating'
                return 200, g
            if call['method'] == 'PUT':
                b = body(call)
                self.puts.append(b)
                b['properties']['provisioningState'] = 'Updating'
                self.gw = json.loads(json.dumps(b))
                self.gw['properties']['provisioningState'] = 'Succeeded'
                for c in self.gw['properties']['sslCertificates']:
                    p = c.setdefault('properties', {})
                    if p.pop('data', None):
                        p.pop('password', None)
                        p['publicCertData'] = 'new'
                self.polls = 1
                return 201, b
            self.patches.append(body(call))
            self.gw['tags'] = body(call)['tags']
            return 200, self.gw
        path = (r'https://management\.azure\.com/subscriptions/sub-1/resourceGroups/rg-1/'
                r'providers/Microsoft\.Network/applicationGateways/agw\?')
        self.ctx = FakeCtx([
            ('POST', r'https://login\.microsoftonline\.com/tenant-1/oauth2/v2\.0/token$',
             (200, {'access_token': 'AZTOKEN', 'expires_in': 3600})),
            ('GET', path, gw), ('PUT', path, gw), ('PATCH', path, gw),
            ('GET', r'/resourceGroups/rg-1/providers/Microsoft\.Network/applicationGateways\?',
             (200, {'value': [{'name': 'agw'}]})),
        ])
        self.t = nosleep(make('azure_appgw', {'subscription_id': self.SUB,
                                              'resource_group': self.RG,
                                              'tenant_id': 'tenant-1', 'client_id': 'app',
                                              'client_secret': 's3'}, self.ctx))

    def test_upload_switch_prune_noop(self):
        name = C.object_name(self.a, {}, maxlen=80)
        opts = {'gateway': 'agw', 'listener': 'https-api', 'keep': '0'}
        self.t.deploy(self.a, opts)
        self.assertEqual(len(self.puts), 1)
        b = self.puts[0]
        self.assertNotIn('etag', b)
        certs = {c['name']: c for c in b['properties']['sslCertificates']}
        self.assertEqual(sorted(certs), sorted([name, 'manual']))     # older acme ones out
        new = certs[name]['properties']
        self.assertTrue(p12_ok(new['data'], base64.b64encode(new['password'].encode()).decode()))
        ls = {li['name']: li['properties'] for li in b['properties']['httpListeners'] +
              b['properties']['listeners']}
        want = {'id': self.gid + '/sslCertificates/' + name}
        self.assertEqual(ls['https-www']['sslCertificate'], want)    # followed the older one
        self.assertEqual(ls['https-api']['sslCertificate'], want)    # named
        self.assertEqual(ls['tls-l4']['sslCertificate'], want)       # a TLS listener too
        self.assertNotIn('sslCertificate', ls['http'])
        self.assertTrue(any('is updated' in w for _l, w in self.ctx.steps))
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, opts).startswith('unchanged'))
        self.assertEqual({c['method'] for c in self.ctx.calls[n:]}, {'GET'})

    def test_in_place_and_errors(self):
        self.t.deploy(self.a, {'gateway': 'agw', 'cert_name': 'manual'})
        certs = {c['name']: c for c in self.puts[0]['properties']['sslCertificates']}
        self.assertIn('data', certs['manual']['properties'])
        self.assertEqual(len(certs), 4)                    # in place: nothing pruned
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {'gateway': 'agw', 'listener': 'nope', 'force': True})
        self.ctx.routes.insert(0, ('GET', r'applicationGateways/nogw\?', (404, {'error': {
            'code': 'ResourceNotFound', 'message': 'not found'}})))
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'gateway': 'nogw'})
        self.assertFalse(e.exception.retry)

    def test_key_vault(self):
        sid = 'https://kv-firma.vault.azure.net/secrets/acme-www/'
        opts = {'gateway': 'agw', 'source': 'keyvault', 'key_vault_secret_id': sid,
                'listener': 'https-www', 'keep': '-1'}
        self.t.deploy(self.a, opts)
        certs = {c['name']: c for c in self.puts[0]['properties']['sslCertificates']}
        kvname = 'acme-www.example.test'
        self.assertEqual(certs[kvname]['properties'], {'keyVaultSecretId': sid})
        self.assertEqual(self.patches[0]['tags']['team'], 'web')
        self.assertEqual(self.patches[0]['tags']['acme-certificate'], C.fp_of(self.a)[:16])
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, opts).startswith('unchanged'))
        self.assertEqual({c['method'] for c in self.ctx.calls[n:]}, {'GET'})
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, dict(opts, key_vault_secret_id=sid + 'abc123/'))
        self.gw.pop('identity')
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, dict(opts, force=True))
        self.assertIn('managed identity', str(e.exception))

    def test_catalog_and_test(self):
        t = make('azure_appgw', {'subscription_id': self.SUB, 'resource_group': self.RG,
                                 'tenant_id': 'tenant-1', 'client_id': 'app',
                                 'client_secret': 's3', 'gateway': 'agw'}, self.ctx)
        got = t.catalog('listeners')['options']
        self.assertEqual([o[0] for o in got], ['https-www', 'https-api', 'tls-l4'])
        self.assertIn('1 application gateway', t.test())
        self.assertEqual({c['method'] for c in self.ctx.calls if 'management' in c['url']},
                         {'GET'})


# ---------------------------------------------------------------------------
class IspConfigTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.sites = {7: {'domain_id': '7', 'domain': 'www.example.test', 'type': 'vhost',
                          'ssl': 'n', 'ssl_letsencrypt': 'y', 'ssl_cert': ''},
                      8: {'domain_id': '8', 'domain': 'alias.example.test', 'type': 'alias'}}
        self.updates = []

        def rpc(call):
            m = call['url'].split('?', 1)[1]
            b = body(call)
            if m == 'login':
                if b != {'username': 'remote', 'password': 'pw'}:
                    return 200, {'code': 'remote_fault', 'message': 'The login failed.',
                                 'response': False}
                return 200, {'code': 'ok', 'message': '', 'response': 'SID1'}
            assert b['session_id'] == 'SID1'
            if m == 'logout':
                return 200, {'code': 'ok', 'response': True}
            if m == 'sites_web_domain_get':
                f = b['primary_id']
                got = [dict(s) for s in self.sites.values()
                       if 'domain' not in f or s['domain'] == f['domain']]
                return 200, {'code': 'ok', 'message': '', 'response': got}
            if m == 'sites_web_domain_update':
                self.updates.append(b)
                self.sites[int(b['primary_id'])].update(b['params'])
                return 200, {'code': 'ok', 'message': '', 'response': 1}
            return 200, {'code': 'invalid_method', 'message': 'no'}
        self.ctx = FakeCtx([('POST', r'https://panel\.test:8080/remote/json\.php\?', rpc)])
        self.t = make('ispconfig', {'host': 'panel.test', 'user': 'remote', 'password': 'pw'},
                      self.ctx)

    def test_save_noop_logout(self):
        self.t.deploy(self.a, {'website': 'www.example.test'})
        u = self.updates[0]
        self.assertEqual(u['client_id'], 0)
        self.assertEqual(u['primary_id'], 7)
        self.assertEqual(u['params'], {'ssl': 'y', 'ssl_letsencrypt': 'n',
                                       'ssl_cert': self.a.cert_pem, 'ssl_key': self.a.key_pem,
                                       'ssl_bundle': self.a.chain_pems[0],
                                       'ssl_action': 'save'})
        self.assertTrue(any("Let's Encrypt" in w for _l, w in self.ctx.steps))
        self.assertTrue(self.ctx.calls[-1]['url'].endswith('?logout'))
        n = len(self.updates)
        self.assertTrue(self.t.deploy(self.a, {'website': 'www.example.test'})
                        .startswith('unchanged'))
        self.assertEqual(len(self.updates), n)
        self.t.deploy(self.a, {'website': 'www.example.test', 'force': True})
        self.assertEqual(len(self.updates), n + 1)

    def test_errors_catalog(self):
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {'website': 'alias.example.test'})
        bad = make('ispconfig', {'host': 'panel.test', 'user': 'x', 'password': 'y'}, self.ctx)
        with self.assertRaises(PluginError) as e:
            bad.test()
        self.assertFalse(e.exception.retry)
        self.assertEqual(self.t.catalog('websites')['options'],
                         [['www.example.test', 'www.example.test']])


# ---------------------------------------------------------------------------
class HestiaCpTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.state = {'SSL': 'yes', 'LETSENCRYPT': 'yes', 'SSL_HOME': 'same', 'CRT': ''}

        def run(cmd, inp):
            if 'v-list-web-domain-ssl' in cmd:
                return 0, json.dumps({'example.test': {'CRT': self.state['CRT']}}), ''
            if 'v-list-web-domain ' in cmd:
                return 0, json.dumps({'example.test': {k: self.state[k] for k in
                                                       ('SSL', 'LETSENCRYPT', 'SSL_HOME')}}), ''
            if 'v-delete-web-domain-ssl' in cmd:
                self.state.update(SSL='no', LETSENCRYPT='no')
                return 0, '', ''
            if 'v-add-web-domain-ssl' in cmd or 'v-change-web-domain-sslcert' in cmd:
                self.state.update(SSL='yes', CRT=self.a.cert_pem)
                return 0, '', ''
            if 'v-list-users' in cmd:
                return 0, json.dumps({'admin': {}, 'bob': {}}), ''
            return 0, '', ''
        self.ssh = FakeSsh([(r'mktemp -d', (0, '/tmp/tmp.abc123\n', '')), (r'v-', run)])
        self.ctx = FakeCtx(ssh=self.ssh)
        self.t = make('hestiacp', {'host': 'h.test', 'user': 'deploy', 'auth': 'password',
                                   'password': 'x', 'sudo': True}, self.ctx)

    def test_le_off_add_then_change_then_noop(self):
        opts = {'hestia_user': 'admin', 'web_domains': 'example.test'}
        self.t.deploy(self.a, opts)
        cmds = [c for c, _i in self.ssh.runs]
        dele = [c for c in cmds if 'v-delete-web-domain-ssl' in c][0]
        self.assertIn('/usr/local/hestia/bin/v-delete-web-domain-ssl admin example.test no', dele)
        self.assertTrue(dele.startswith('sudo -n sh -c '))
        add = [c for c in cmds if 'v-add-web-domain-ssl' in c][0]
        self.assertIn('v-add-web-domain-ssl admin example.test /tmp/tmp.abc123 same yes', add)
        self.assertEqual({p for p, _d, _m in self.ssh.puts},
                         {'/tmp/tmp.abc123/example.test.crt', '/tmp/tmp.abc123/example.test.key',
                          '/tmp/tmp.abc123/example.test.ca'})
        self.assertTrue(all(m == 0o600 for _p, _d, m in self.ssh.puts))
        self.assertIn("rm -rf /tmp/tmp.abc123", cmds[-1])
        n = len(self.ssh.runs)
        self.assertTrue(self.t.deploy(self.a, opts).startswith('unchanged'))
        self.assertFalse(any('v-change' in c or 'v-add' in c for c, _i in self.ssh.runs[n:]))
        self.t.deploy(self.a, dict(opts, force=True))
        self.assertTrue(any('v-change-web-domain-sslcert admin example.test /tmp/tmp.abc123 yes'
                            in c for c, _i in self.ssh.runs[n:]))

    def test_errors(self):
        self.ssh.answers.insert(0, (r'v-change-web-domain-sslcert', (
            2, '', 'Error: SSL intermediate chain is not valid')))
        self.state.update(LETSENCRYPT='no')
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'hestia_user': 'admin', 'web_domains': 'example.test'})
        self.assertIn('intermediate chain', str(e.exception))
        self.assertIn('rm -rf /tmp/tmp.abc123', self.ssh.runs[-1][0])
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {'hestia_user': 'a; rm', 'web_domains': 'example.test'})
        self.assertIn('2 users', self.t.test())


# ---------------------------------------------------------------------------
class VirtualminTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.installed = {}

        def cgi(call):
            assert call['headers']['Authorization'] == 'Basic ' + base64.b64encode(
                b'root:pw').decode()
            f = form_of(call)
            if f['program'] == 'list-domains':
                return 200, 'example.test\nshop.example.test\n\nExit status: 0\n'
            if f['program'] == 'list-certs':
                return 200, self.installed.get(f['domain'], '') + '\nExit status: 0\n'
            if f['program'] == 'install-cert':
                if f['domain'] == 'bad.test':
                    return 200, ('Certificate problems found : key does not match\n\n'
                                 'Exit status: 1\n')
                assert '\n' not in f['cert'] and '\t' in f['cert']
                self.installed[f['domain']] = f['cert'].replace('\t', '\n')
                return 200, 'Installing certificate .. done\n\nExit status: 0\n'
            return 200, 'ERROR: unknown program\n'
        self.ctx = FakeCtx([('POST', r'https://vm\.test:10000/virtual-server/remote\.cgi$',
                             cgi)])
        self.t = make('virtualmin', {'host': 'vm.test', 'user': 'root', 'password': 'pw'},
                      self.ctx)

    def test_install_tabs_noop(self):
        self.t.deploy(self.a, {'domain': 'example.test', 'domains': 'shop.example.test'})
        ins = [form_of(c) for c in self.ctx.calls if form_of(c)['program'] == 'install-cert']
        self.assertEqual([f['domain'] for f in ins], ['example.test', 'shop.example.test'])
        self.assertEqual(ins[0]['key'].replace('\t', '\n'), self.a.key_pem.strip())
        self.assertEqual(ins[0]['ca'].replace('\t', '\n'), self.a.chain_pems[0].strip())
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, {'domain': 'example.test',
                                               'domains': 'shop.example.test'})
                        .startswith('unchanged'))
        self.assertFalse(any(form_of(c)['program'] == 'install-cert'
                             for c in self.ctx.calls[n:]))

    def test_errors_catalog_test(self):
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'domain': 'bad.test'})
        self.assertIn('does not match', str(e.exception))
        self.assertIsNone(e.exception.detail)
        self.assertEqual(self.t.catalog('domains')['options'][1], ['shop.example.test',
                                                                  'shop.example.test'])
        self.assertIn('2 virtual servers', self.t.test())


# ---------------------------------------------------------------------------
class FroxlorTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.certs = {'old.example.test': {'id': 3, 'domainid': 9, 'ssl_cert_file': 'x'}}
        self.cmds = []

        def api(call):
            assert call['headers']['Authorization'] == 'Basic ' + base64.b64encode(
                b'KEY:SECRET').decode()
            b = body(call)
            self.cmds.append(b['command'])
            p = b.get('params') or {}
            if b['command'] == 'Froxlor.listFunctions':
                return 200, {'data': {'count': 2, 'list': [{}, {}]}}
            if b['command'] == 'Certificates.get':
                c = self.certs.get(p['domainname'])
                if not c:
                    return 412, {'message': "Domain '%s' does not have a certificate."
                                 % p['domainname']}
                return 200, {'data': c}
            if p['domainname'] == 'le.example.test':
                return 406, {'message': 'sslcertificateisletsencryptmanaged'}
            if b['command'] == 'Certificates.add':
                assert p['domainname'] not in self.certs
            else:
                assert p['domainname'] in self.certs
            self.certs[p['domainname']] = dict(p, id=len(self.certs) + 1)
            return 200, {'data': self.certs[p['domainname']]}
        self.ctx = FakeCtx([('POST', r'^https://fx\.test/api\.php$', api)])
        self.t = make('froxlor', {'url': 'https://fx.test/api.php', 'api_key': 'KEY',
                                  'api_secret': 'SECRET'}, self.ctx)

    def test_add_update_noop(self):
        self.t.deploy(self.a, {'domains': 'new.example.test\nold.example.test'})
        self.assertEqual([c for c in self.cmds if c != 'Certificates.get'],
                         ['Certificates.add', 'Certificates.update'])
        c = self.certs['new.example.test']
        self.assertEqual((c['ssl_cert_file'], c['ssl_key_file'], c['ssl_cert_chainfile']),
                         (self.a.cert_pem, self.a.key_pem, self.a.chain_pems[0]))
        n = len(self.cmds)
        self.assertTrue(self.t.deploy(self.a, {'domains': 'new.example.test\nold.example.test'})
                        .startswith('unchanged'))
        self.assertEqual(set(self.cmds[n:]), {'Certificates.get'})

    def test_errors_and_test(self):
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'domains': 'le.example.test'})
        self.assertIn('letsencryptmanaged', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertIn('2 API functions', self.t.test())


# ---------------------------------------------------------------------------
class ProxmoxBackupTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.fp = 'AA:BB'

        def info(call):
            assert call['headers']['Authorization'] == 'PBSAPIToken=acme@pbs!deploy:SECRET'
            return 200, {'data': [{'filename': 'proxy.pem', 'fingerprint': self.fp,
                                   'subject': 'CN=pbs', 'notafter': 1}]}

        def up(call):
            f = form_of(call)
            assert f['certificates'] == self.a.fullchain_pem and f['key'] == self.a.key_pem
            assert f['force'] == '1'
            self.fp = ':'.join(self.a.fingerprint[i:i + 2] for i in range(0, 64, 2))
            return 200, {'data': [{'filename': 'proxy.pem'}]}
        self.ctx = FakeCtx([
            ('GET', r'https://pbs\.test:8007/api2/json/nodes/localhost/certificates/info$', info),
            ('POST', r'https://pbs\.test:8007/api2/json/nodes/localhost/certificates/custom$',
             up)])
        self.t = make('proxmox_backup', {'host': 'pbs.test', 'token_id': 'acme@pbs!deploy',
                                         'token_secret': 'SECRET'}, self.ctx)

    def test_upload_noop(self):
        self.t.deploy(self.a, {})
        self.assertTrue(any('fingerprint' in w and l == 'warn' for l, w in self.ctx.steps))
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, {}).startswith('unchanged'))
        self.assertEqual([c['method'] for c in self.ctx.calls[n:]], ['GET'])
        self.assertIn('CN=pbs', self.t.test())


# ---------------------------------------------------------------------------
class DescribeTest(unittest.TestCase):
    def test_every_module(self):
        reg = Registry(extra_dirs=[]).reload()
        self.assertEqual(reg.broken, [])
        kinds = reg.all('target')
        for k in KINDS:
            self.assertIn(k, kinds)
            d = kinds[k].describe()
            json.dumps(d)
            self.assertTrue(d['title'] and d['vendor'] and d['description'], k)
            self.assertEqual(d['doc'], 'targets.md', k)
            keys = [f['key'] for f in d['fields']]
            for f in d['fields'] + d['deploy_fields']:
                self.assertIn(f['type'], FIELD_TYPES, (k, f['key']))
                if f['key'] in ('token', 'password', 'api_key', 'api_secret', 'secret_key',
                                'client_secret', 'token_secret'):
                    self.assertEqual(f['type'], 'secret', (k, f['key']))
            for f in d['deploy_fields']:
                self.assertNotIn(f['key'], keys, (k, f['key']))
                if f['type'] == 'catalog':
                    self.assertFalse(f.get('autoload', True), (k, f['key']))
            src = read(kinds[k]._module_file)
            doc = src.split('"""')[1]
            self.assertIn('https://', doc, '%s cites no source' % k)
            self.assertIn('Less certain', doc, k)
            self.assertIn('api-docs/', doc, k)

    def test_docs_and_czech(self):
        root = os.path.dirname(HERE)
        docs = read(os.path.join(root, 'docs', 'targets.md'))
        readme = read(os.path.join(root, 'README.md'))
        cs = json.loads(read(os.path.join(root, 'web', 'lang', 'cs.json')))
        sources = {v['source'] for v in cs['strings'].values() if v.get('text')}
        reg = Registry(extra_dirs=[]).reload()

        def words_of(d):
            out = [d['title'], d['description']]
            for f in d['fields'] + d['deploy_fields']:
                out += [f['label'], f.get('help', ''), f.get('placeholder', '') and '']
                out += [o[1] for o in f.get('options') or []]
            for a in d['actions']:
                out += [a['label'], a.get('help', '')]
            return [w for w in out if w]
        missing = []
        for k in KINDS:
            self.assertIn('## `%s`' % k, docs)
            self.assertIn('| `%s` |' % k, docs)
            sec = docs.split('## `%s`' % k, 1)[1].split('\n## ', 1)[0]
            self.assertIn('api-docs/', sec, k)
            self.assertIn('Less certain', sec, k)
            d = reg.get('target', k).describe()
            self.assertIn(d['title'].split(' (')[0].lower(), readme.lower(), k)
            missing += ['%s: %s' % (k, w) for w in words_of(d) if w not in sources]
        self.assertEqual(missing, [])
        nothere = docs.split('### Not here', 1)[1].split('\n## ', 1)[0]
        for w in ('Meraki', 'pfSense', 'SonicWall', 'WatchGuard', 'Catalyst 9800'):
            self.assertIn(w, nothere)


if __name__ == '__main__':
    unittest.main()
