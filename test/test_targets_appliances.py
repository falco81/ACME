#!/usr/bin/env python3
"""The target modules of firewalls, load balancers and hosting panels added
with the vendors' API documents - Check Point, VMware NSX, Barracuda WAF,
FortiWeb, FortiADC, Cisco FMC, cPanel / WHM, DirectAdmin, Plesk - without a
network.

    python3 -m unittest test/test_targets_appliances.py

The fake Context and certificates are those of test_targets.py: every request
is recorded and answered from a little fake of the device's API, and the
tests look at what was asked (paths, sign-in headers, bodies) against the
documents, at the same certificate twice being a no-op, at old ones being
cleaned up (never one still in use) and at errors said in words.
"""
import base64
import json
import os
import re
import subprocess
import sys
import unittest
import urllib.parse
import xml.etree.ElementTree as ET
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, make, read  # noqa: E402
from test_targets_more import parts_of  # noqa: E402
from acmelib.plugins.base import PluginError, Registry, FIELD_TYPES  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402

KINDS = ('checkpoint', 'nsx', 'barracuda_waf', 'fortiweb', 'fortiadc', 'cisco_fmc',
         'cpanel_ssl', 'directadmin_ssl', 'plesk')


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def body(call):
    return json.loads(call['body'])


def olds(b, n=3, maxlen=63):
    """n older acme names of this certificate, oldest first."""
    p = C.name_prefix(b, {}, maxlen=maxlen)
    return [p + '2026%02d01-aaaa000%d' % (i + 1, i) for i in range(n)]


def p12_ok(b64_p12, b64_pw):
    """Does the PKCS#12 open with the password (openssl)?"""
    pw = base64.b64decode(b64_pw).decode()
    p = subprocess.run(['openssl', 'pkcs12', '-nokeys', '-passin', 'pass:' + pw],
                       input=base64.b64decode(b64_p12), capture_output=True)
    if p.returncode:
        p = subprocess.run(['openssl', 'pkcs12', '-legacy', '-nokeys', '-passin', 'pass:' + pw],
                           input=base64.b64decode(b64_p12), capture_output=True)
    return p.returncode == 0 and b'BEGIN CERTIFICATE' in p.stdout


# ---------------------------------------------------------------------------
class CheckPointTest(unittest.TestCase):
    RULE = '0b2a1b4e-1c1d-4e5f-8a9b-0123456789ab'

    def setUp(self):
        self.a = FakeBundle()
        o = olds(self.a)
        self.certs = {n: {'name': n} for n in o}
        self.certs['other'] = {'name': 'other'}
        self.inuse = {o[1]: 1}          # o[2] is kept (keep 1), o[1] in use, o[0] goes
        self.rules = {self.RULE: {'name': 'Inbound www', 'certificate': o[2]}}
        self.published, self.installed, self.discarded, self.logouts = 0, [], 0, 0
        self.fail = None

        def web(call):
            cmd = call['path'].rsplit('/', 1)[1]
            b = body(call) if call['body'] else {}
            if cmd != 'login':
                assert call['headers'].get('X-chkp-sid') == 'SID1', cmd
            if self.fail == cmd:
                return 404, {'code': 'generic_err_object_not_found',
                             'message': 'Requested object [x] not found'}
            if cmd == 'login':
                return 200, {'sid': 'SID1', 'uid': 'u'}
            if cmd == 'logout':
                self.logouts += 1
                return 200, {'message': 'OK'}
            if cmd == 'discard':
                self.discarded += 1
                return 200, {'message': 'OK'}
            if cmd == 'show-api-versions':
                return 200, {'current-version': '2.0.1'}
            if cmd == 'show-server-certificate':
                if b['name'] in self.certs:
                    return 200, self.certs[b['name']]
                return 404, {'code': 'generic_err_object_not_found', 'message': 'not found'}
            if cmd == 'show-server-certificates':
                objs = sorted(self.certs.values(), key=lambda x: x['name'])
                part = objs[b['offset']:b['offset'] + b['limit']]
                return 200, {'objects': part, 'total': len(objs), 'from': 1, 'to': len(part)}
            if cmd in ('add-server-certificate', 'set-server-certificate'):
                self.certs[b['name']] = dict(b)
                return 200, {'uid': 'x', 'name': b['name']}
            if cmd == 'set-https-rule':
                uid = b.get('uid') or next((u for u, r in self.rules.items()
                                            if r['name'] == b.get('name')), None)
                if uid not in self.rules:
                    return 404, {'code': 'generic_err_object_not_found', 'message': 'no rule'}
                self.rules[uid]['certificate'] = b['certificate']
                return 200, {'uid': uid}
            if cmd == 'where-used':
                return 200, {'used-directly': {'total': self.inuse.get(b['name'], 0)}}
            if cmd == 'delete-server-certificate':
                del self.certs[b['name']]
                return 200, {'message': 'OK'}
            if cmd in ('set-simple-gateway', 'set-simple-cluster'):
                self.gateway = (cmd, b)
                return 200, {'name': b['name']}
            if cmd == 'publish':
                self.published += 1
                return 200, {'task-id': 'T1'}
            if cmd == 'install-policy':
                self.installed.append(b)
                return 200, {'task-id': 'T2'}
            if cmd == 'show-task':
                return 200, {'tasks': [{'task-id': b['task-id'], 'status': 'succeeded'}]}
            if cmd == 'show-https-layers':
                return 200, {'https-layers': [{'name': 'Inbound Layer'}], 'total': 1}
            if cmd == 'show-https-rulebase':
                return 200, {'rulebase': [{'type': 'https-section', 'name': 'S', 'rulebase': [
                    {'type': 'https-rule', 'uid': self.RULE, 'name': 'Inbound www',
                     'rule-number': 1}]}], 'total': 1}
            if cmd in ('show-simple-gateways', 'show-simple-clusters'):
                return 200, {'objects': [{'name': 'gw1' if 'gateways' in cmd else 'cl1'}],
                             'total': 1}
            if cmd == 'show-packages':
                return 200, {'packages': [{'name': 'Standard'}], 'total': 1}
            raise AssertionError(cmd)
        self.ctx = FakeCtx([('POST', r'^https://mgmt\.test/web_api/', web)])
        self.t = make('checkpoint', {'host': 'mgmt.test', 'user': 'api', 'password': 'pw'},
                      self.ctx)
        self.t._sleep = lambda s: None

    def opts(self, **k):
        o = {'https_rule': self.RULE, 'https_layer': 'Inbound Layer',
             'gateway': 'gw1', 'portal_platform': True, 'portal_captive': True,
             'policy_package': 'Standard', 'install_targets': 'gw1'}
        o.update(k)
        return o

    def test_import_point_publish_install_cleanup_noop(self):
        name = C.object_name(self.a, {})
        o = olds(self.a)
        words = self.t.deploy(self.a, self.opts())
        self.assertIn('imported %s' % name, words)
        login = body(self.ctx.find('POST', r'/web_api/login$')[0])
        self.assertEqual((login['user'], login['password']), ('api', 'pw'))
        self.assertNotIn('read-only', login)
        add = body(self.ctx.find('POST', r'/add-server-certificate$')[0])
        self.assertEqual(add['name'], name)
        self.assertTrue(p12_ok(add['base64-certificate'], add['base64-password']))
        self.assertEqual(self.rules[self.RULE]['certificate'], name)
        rule = body(self.ctx.find('POST', r'/set-https-rule$')[0])
        self.assertEqual((rule['layer'], rule['uid']), ('Inbound Layer', self.RULE))
        cmd, gw = self.gateway
        self.assertEqual(cmd, 'set-simple-gateway')
        cs = gw['platform-portal-settings']['certificate-settings']
        self.assertTrue(p12_ok(cs['base64-certificate'], cs['base64-password']))
        self.assertIn('certificate-settings', gw['identity-awareness-settings'][
            'browser-based-authentication-settings'][
            'browser-based-authentication-portal-settings'])
        self.assertNotIn('usercheck-portal-settings', gw)
        self.assertEqual(self.published, 1)
        self.assertEqual(self.installed, [{'policy-package': 'Standard', 'access': True,
                                           'threat-prevention': False, 'targets': ['gw1']}])
        # keep 1: o[2] stays, o[1] is still used, o[0] is deleted; 'other' untouched
        self.assertEqual(sorted(self.certs), sorted([name, o[1], o[2], 'other']))
        # cleanup before publishing: one publish holds everything
        cmds = [c['path'].rsplit('/', 1)[1] for c in self.ctx.calls]
        self.assertLess(cmds.index('delete-server-certificate'), cmds.index('publish'))
        self.assertEqual((self.discarded, self.logouts), (0, 1))
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, self.opts()).startswith('unchanged'))
        later = [c['path'].rsplit('/', 1)[1] for c in self.ctx.calls[n:]]
        self.assertEqual(later, ['login', 'show-server-certificate', 'logout'])

    def test_object_in_place_and_rule_by_name(self):
        self.certs['www-cert'] = {'name': 'www-cert'}
        words = self.t.deploy(self.a, {'object': 'www-cert', 'https_rules': 'Inbound www',
                                       'https_layer': 'L'})
        self.assertIn('replaced www-cert', words)
        s = body(self.ctx.find('POST', r'/set-server-certificate$')[0])
        self.assertTrue(p12_ok(s['base64-certificate'], s['base64-password']))
        self.assertFalse(self.ctx.find('POST', r'/add-server-certificate$'))
        self.assertFalse(self.ctx.find('POST', r'/delete-server-certificate$'))  # no pruning
        self.assertEqual(body(self.ctx.find('POST', r'/set-https-rule$')[0])['name'],
                         'Inbound www')
        self.assertTrue(any('install it from SmartConsole' in w for _l, w in self.ctx.steps))

    def test_failure_discards_and_logs_out(self):
        self.fail = 'set-https-rule'
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, self.opts())
        self.assertIn('not found', str(e.exception))
        self.assertEqual((self.published, self.discarded, self.logouts), (0, 1, 1))
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {'https_rules': 'x'})            # no layer
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {'portal_saml': True})           # no gateway

    def test_read_only_test_catalog_look(self):
        self.assertIn('Management API 2.0.1', self.t.test())
        self.assertTrue(body(self.ctx.find('POST', r'/login$')[0])['read-only'])
        got = self.t.catalog('https_rules')
        self.assertEqual(got['options'][0][0], self.RULE)
        self.assertEqual(got['sets'][self.RULE], {'https_layer': 'Inbound Layer'})
        gws = self.t.catalog('gateways')
        self.assertEqual(gws['sets'], {'gw1': {'gateway_type': 'simple-gateway'},
                                       'cl1': {'gateway_type': 'simple-cluster'}})
        self.assertEqual(self.t.catalog('packages')['options'], [['Standard', 'Standard']])
        self.t.action('look')
        changed = [c for c in self.ctx.calls if re.search(
            r'/(add|set|delete)-|/publish|/install', c['path'])]
        self.assertEqual(changed, [])
        self.assertTrue(all(body(c).get('read-only') for c in self.ctx.find('POST', '/login$')))

    def test_api_key_domain_version(self):
        t = make('checkpoint', {'host': 'mgmt.test', 'auth': 'api_key', 'api_key': 'K',
                                'domain': 'D1', 'api_version': 'v1.9'}, self.ctx)
        ctx = FakeCtx([('POST', r'/web_api/v1\.9/login$', (200, {'sid': 'SID1'})),
                       ('POST', r'/web_api/v1\.9/', (200, {'objects': [], 'total': 0}))])
        t.ctx = ctx
        t.test()
        b = body(ctx.calls[0])
        self.assertEqual((b['api-key'], b['domain']), ('K', 'D1'))
        self.assertNotIn('user', b)


# ---------------------------------------------------------------------------
class NsxTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        o = olds(self.a)
        self.certs = {n: {'id': n, 'path': '/infra/certificates/' + n} for n in o}
        self.vs = {
            'vs1': {'id': 'vs1', 'resource_type': 'LBVirtualServer', '_revision': 4,
                    'ip_address': '10.0.0.1', 'ports': ['443'],
                    'client_ssl_profile_binding': {
                        'default_certificate_path': '/infra/certificates/' + o[2],
                        'ssl_profile_path': '/infra/lb-client-ssl-profiles/default'}},
            'vs2': {'id': 'vs2', '_revision': 1, 'ip_address': '10.0.0.2', 'ports': ['443'],
                    'client_ssl_profile_binding': {
                        'default_certificate_path': '/infra/certificates/other',
                        'sni_certificate_paths': ['/infra/certificates/' + o[1],
                                                  '/infra/certificates/keep-me']}},
            'vs3': {'id': 'vs3', '_revision': 1, 'ports': ['80']},
        }

        def cert(call):
            cid = urllib.parse.unquote(call['path'].rsplit('/', 1)[1])
            if call['method'] == 'GET':
                return (200, self.certs[cid]) if cid in self.certs else (404, {'error_code': 600})
            if call['method'] == 'PUT':
                self.certs[cid] = dict(body(call), id=cid)
                return 200, self.certs[cid]
            del self.certs[cid]
            return 200, b''

        def listing(call):
            return 200, {'results': list(self.certs.values()), 'result_count': len(self.certs)}

        def vserver(call):
            vid = call['path'].rsplit('/', 1)[1]
            if call['method'] == 'GET':
                return (200, json.loads(json.dumps(self.vs[vid]))) if vid in self.vs else \
                    (404, {'error_message': 'not found'})
            self.vs[vid] = body(call)
            return 200, self.vs[vid]
        self.ctx = FakeCtx([
            ('GET', r'/policy/api/v1/infra/certificates(\?|$)', listing),
            ('GET', r'/policy/api/v1/infra/lb-virtual-servers$',
             lambda c: (200, {'results': list(self.vs.values())})),
            ('GET', r'/policy/api/v1/infra/lb-virtual-servers/', vserver),
            ('PUT', r'/policy/api/v1/infra/lb-virtual-servers/', vserver),
            ('GET', r'/policy/api/v1/infra/certificates/', cert),
            ('PUT', r'/policy/api/v1/infra/certificates/', cert),
            ('DELETE', r'/policy/api/v1/infra/certificates/', cert),
        ])
        self.t = make('nsx', {'host': 'nsx.test', 'user': 'admin', 'password': 'pw'}, self.ctx)

    def test_import_switch_cleanup_noop(self):
        cid = C.object_name(self.a, {})
        o = olds(self.a)
        self.t.deploy(self.a, {'virtual_server': 'vs1', 'virtual_servers': 'vs2',
                               'place': 'both', 'keep': '0'})
        put = body(self.ctx.find('PUT', r'/infra/certificates/')[0])
        self.assertEqual(put['pem_encoded'], self.a.fullchain_pem)
        self.assertEqual(put['private_key'], self.a.key_pem)
        self.assertNotIn('_revision', put)
        self.assertEqual(self.ctx.calls[0]['headers']['Authorization'],
                         'Basic ' + base64.b64encode(b'admin:pw').decode())
        b1 = self.vs['vs1']['client_ssl_profile_binding']
        self.assertEqual(b1['default_certificate_path'], '/infra/certificates/' + cid)
        self.assertEqual(self.vs['vs1']['_revision'], 4)       # sent back as read
        self.assertEqual(b1['ssl_profile_path'], '/infra/lb-client-ssl-profiles/default')
        b2 = self.vs['vs2']['client_ssl_profile_binding']
        self.assertEqual(b2['sni_certificate_paths'], ['/infra/certificates/keep-me',
                                                       '/infra/certificates/' + cid])
        # keep 0: every older one goes - none is used any more
        self.assertEqual(sorted(self.certs), [cid])
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, {'virtual_server': 'vs1', 'virtual_servers': 'vs2',
                                               'place': 'both', 'keep': '0'})
                        .startswith('unchanged'))
        self.assertEqual([c['method'] for c in self.ctx.calls[n:]], ['GET'])
        self.assertTrue(o)

    def test_used_one_stays_and_errors(self):
        o = olds(self.a)
        self.t.deploy(self.a, {'virtual_server': 'vs1', 'keep': '0'})
        self.assertIn(o[1], self.certs)          # vs2 still has it as SNI
        self.assertNotIn(o[0], self.certs)
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'virtual_server': 'vs3', 'force': True})
        self.assertIn('no client SSL', str(e.exception))
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {'virtual_server': 'nope', 'force': True})

    def test_catalog_and_look(self):
        got = self.t.catalog('virtual_servers')
        self.assertEqual([x[0] for x in got['options']], ['vs1', 'vs2', 'vs3'])
        self.assertIn('no client SSL', got['options'][2][1])
        self.t.action('look')
        self.assertEqual({c['method'] for c in self.ctx.calls}, {'GET'})
        self.assertIn('3 virtual servers', self.t.test())


# ---------------------------------------------------------------------------
class BarracudaTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.a.family = 'ec'                 # (a real bundle says its key type)
        o = olds(self.a)
        self.certs = {n: {} for n in o}
        self.certs['vendor'] = {}
        self.ssl = {
            'www': {'status': 'On', 'certificate': o[2], 'enable-sni': 'Yes',
                    'domain': ['shop.example.test'], 'sni-certificate': [o[1]]},
            'api': {'status': 'On', 'certificate': 'vendor', 'sni-certificate': []},
        }
        self.logout = 0
        tok = 'eyJ0b2tlbiI6MX0=\n'

        def auth_ok(call):
            want = 'Basic ' + base64.b64encode((tok + ':').encode()).decode()
            assert call['headers'].get('Authorization') == want, call['headers']

        def login(call):
            self.assertEqual(body(call), {'username': 'admin', 'password': 'pw'})
            return 200, {'token': tok}

        def logout(call):
            self.logout += 1
            return 200, {'msg': 'Token deleted successfully.'}

        def certs(call):
            auth_ok(call)
            name = urllib.parse.unquote(call['path'].rsplit('/', 1)[1])
            if call['method'] == 'POST':
                b = body(call)
                if b['name'] in self.certs:
                    return 400, {'msg': 'Duplicate certificate name is not allowed.'}
                self.certs[b['name']] = b
                return 201, {'id': b['name'], 'msg': 'Successfully created.'}
            if call['method'] == 'DELETE':
                del self.certs[name]
                return 200, {'msg': 'Successfully deleted.'}
            if name == 'signed-certificate':
                return 200, {'data': {n: {} for n in self.certs}}
            return (200, {'data': {name: {}}}) if name in self.certs else (404, {'msg': 'no'})

        def ssl(call):
            auth_ok(call)
            svc = urllib.parse.unquote(call['path'].split('/')[-2])
            if svc not in self.ssl:
                return 404, {'msg': 'no service'}
            if call['method'] == 'GET':
                return 200, {'data': {svc: {'SSL Security': dict(self.ssl[svc])}}}
            self.ssl[svc] = body(call)
            return 200, {'msg': 'Configuration updated'}
        self.ctx = FakeCtx([
            ('POST', r'/restapi/v3\.2/login$', login),
            ('DELETE', r'/restapi/v3\.2/logout$', logout),
            ('GET', r'/restapi/v3\.2/services$',
             lambda c: (200, {'data': {k: {} for k in self.ssl}})),
            ('GET', r'/restapi/v3\.2/services/[^/]+/ssl-security$', ssl),
            ('PUT', r'/restapi/v3\.2/services/[^/]+/ssl-security$', ssl),
            ('GET', r'/restapi/v3\.2/certificates/signed-certificate', certs),
            ('POST', r'/restapi/v3\.2/certificates/signed-certificate$', certs),
            ('DELETE', r'/restapi/v3\.2/certificates/signed-certificate/', certs),
        ])
        self.t = make('barracuda_waf', {'host': 'waf.test', 'user': 'admin', 'password': 'pw'},
                      self.ctx)

    def test_upload_point_cleanup_noop(self):
        name = C.object_name(self.a, {})
        o = olds(self.a)
        self.t.deploy(self.a, {'service': 'www', 'keep': '0'})
        self.assertTrue(self.ctx.calls[0]['url'].startswith('https://waf.test:8443/restapi/'))
        up = self.certs[name]
        self.assertEqual(base64.b64decode(up['signed-certificate']).decode(), self.a.cert_pem)
        self.assertEqual(base64.b64decode(up['certificate-key']).decode(), self.a.key_pem)
        self.assertEqual([base64.b64decode(x).decode() for x in up['intermediary-certificates']],
                         self.a.chain_pems)
        self.assertEqual((up['certificate-type'], up['key-type'], up['allow-private-key-export']),
                         ('PEM Certificate', 'ECDSA', 'No'))
        www = self.ssl['www']
        self.assertEqual(www['certificate'], name)
        self.assertEqual(www['sni-certificate'], [name])      # the older acme SNI one too
        self.assertEqual(www['domain'], ['shop.example.test'])  # the rest as it was
        self.assertEqual(self.ssl['api']['certificate'], 'vendor')
        self.assertEqual(sorted(self.certs), sorted([name, 'vendor']))
        self.assertEqual(self.logout, 1)
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, {'service': 'www', 'keep': '0'})
                        .startswith('unchanged'))
        self.assertEqual([c['method'] for c in self.ctx.calls[n:]], ['POST', 'GET', 'DELETE'])

    def test_used_stays_and_unknown_service(self):
        o = olds(self.a)
        self.t.deploy(self.a, {'service': 'api', 'keep': '0'})
        self.assertIn(o[2], self.certs)          # www still uses both
        self.assertIn(o[1], self.certs)
        self.assertNotIn(o[0], self.certs)
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'service': 'nope', 'force': True})
        self.assertIn('no service', str(e.exception))
        self.assertEqual(self.logout, 2)

    def test_v3_multipart_and_look(self):
        ctx = FakeCtx([('POST', r'/restapi/v3/login$', (200, {'token': 'T'})),
                       ('DELETE', r'/logout$', (200, {})),
                       ('GET', r'/restapi/v3/certificates/', (404, {'msg': 'no'})),
                       ('POST', r'/restapi/v3/certificates\?upload=signed$', (201, {'id': 'x'})),
                       ('GET', r'/restapi/v3/certificates$', (200, {'data': {}}))])
        t = make('barracuda_waf', {'host': 'waf.test', 'user': 'admin', 'password': 'pw',
                                   'api_version': 'v3'}, ctx)
        t.deploy(self.a, {})
        parts = parts_of(ctx.find('POST', r'upload=signed')[0])
        self.assertEqual(parts['type'][1], b'pem')
        self.assertEqual(parts['key_type'][1], b'ecdsa')
        self.assertEqual(parts['signed_certificate'][1], self.a.cert_pem.encode())
        self.assertEqual(parts['key'][1], self.a.key_pem.encode())
        self.assertEqual(parts['intermediary_certificate'][1], self.a.chain_pems[0].encode())
        self.t.action('look')
        self.assertFalse([c for c in self.ctx.calls if c['method'] == 'PUT'])
        self.assertEqual(self.t.catalog('services')['options'], [['www', 'www'], ['api', 'api']])


# ---------------------------------------------------------------------------
class FortiWebTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        o = olds(self.a)
        self.certs = {n: {'name': n} for n in o}
        self.pols = {'www': {'name': 'www', 'ssl': 'enable', 'certificate': o[2],
                             'intermediate-certificate-group': '', 'vserver': 'VS'},
                     'old': {'name': 'old', 'certificate': o[1]}}
        self.groups, self.members, self.inter = {}, [], []

        def certs(call):
            qs = call['query']
            if call['method'] == 'GET':
                if 'mkey' in qs:
                    n = qs['mkey'][0]
                    return (200, {'results': self.certs[n]}) if n in self.certs else \
                        (500, {'results': {'errcode': -3}})
                return 200, {'results': list(self.certs.values())}
            del self.certs[qs['mkey'][0]]
            return 200, {'results': {}}

        def json_cert(call):
            b = body(call)
            self.certs[b['name']] = b
            return 200, {'_id': b['name']}

        def policy(call):
            n = call['query'].get('mkey', [None])[0]
            if call['method'] == 'GET':
                if n is None:
                    return 200, {'results': list(self.pols.values())}
                return (200, {'results': dict(self.pols[n])}) if n in self.pols else \
                    (500, {'results': {'errcode': -3}})
            self.pols[n] = body(call)['data']
            return 200, {'results': self.pols[n]}

        def group(call):
            if call['method'] == 'GET':
                n = call['query']['mkey'][0]
                return (200, {'results': self.groups[n]}) if n in self.groups else \
                    (500, {'results': {'errcode': -3}})
            d = body(call)['data']
            self.groups[d['name']] = d
            return 200, {'results': d}
        self.ctx = FakeCtx([
            ('GET', r'/api/v2\.0/cmdb/system/certificate\.local', certs),
            ('DELETE', r'/api/v2\.0/cmdb/system/certificate\.local', certs),
            ('POST', r'/api/v2\.0/system/certificate\.local\.json_cert$', json_cert),
            ('GET', r'/api/v2\.0/cmdb/server-policy/policy', policy),
            ('PUT', r'/api/v2\.0/cmdb/server-policy/policy', policy),
            ('POST', r'/api/v2\.0/system/certificate\.intermediateca$',
             lambda c: (self.inter.append(parts_of(c)), (200, {'_id': 'x'}))[1]),
            ('POST', r'/certificate\.intermediate-certificate-group/members', lambda c: (
                self.members.append((c['query']['mkey'][0], body(c)['data'])),
                (200, {'results': {}}))[1]),
            ('GET', r'/api/v2\.0/cmdb/system/certificate\.intermediate-certificate-group', group),
            ('POST', r'/api/v2\.0/cmdb/system/certificate\.intermediate-certificate-group$',
             group),
            ('GET', r'/system/status\.systemstatus$', (200, {'results': {'version': 'v7.4.3'}})),
        ])
        self.t = make('fortiweb', {'host': 'fwb.test', 'user': 'admin', 'password': 'pw',
                                   'vdom': 'root'}, self.ctx)

    def test_import_chain_point_cleanup_noop(self):
        name = C.object_name(self.a, {})
        o = olds(self.a)
        self.t.deploy(self.a, {'policy': 'www', 'keep': '0'})
        auth = json.loads(base64.b64decode(self.ctx.calls[0]['headers']['Authorization']))
        self.assertEqual(auth, {'username': 'admin', 'password': 'pw', 'vdom': 'root'})
        imp = self.certs[name]
        self.assertEqual((imp['type'], imp['is-hsm'], imp['status']),
                         ('certificate', 'no', 'ok'))
        self.assertEqual(imp['certificate'], self.a.cert_pem.strip())
        self.assertEqual(imp['private-key'], self.a.key_pem.strip())
        grp = 'acme-chain-%s' % C.chain_id(''.join(self.a.chain_pems))
        ca = 'acme-ca-%s' % C.chain_id(self.a.chain_pems[0])
        self.assertEqual(self.inter[0]['type'][1], b'localPC')
        self.assertEqual(self.inter[0]['uploadedFile'][0], ca + '.crt')
        self.assertEqual(self.members, [(grp, {'name': ca})])
        www = self.pols['www']
        self.assertEqual((www['certificate'], www['intermediate-certificate-group']),
                         (name, grp))
        self.assertEqual(www['vserver'], 'VS')                 # the rest as read
        # keep 0: o[2] o[0] go; o[1] is still used by the policy "old"
        self.assertEqual(sorted(self.certs), sorted([name, o[1]]))
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, {'policy': 'www', 'keep': '0'})
                        .startswith('unchanged'))
        self.assertEqual([c['method'] for c in self.ctx.calls[n:]], ['GET'])
        # the group is there now: not made again
        self.t.deploy(self.a, {'policy': 'old', 'force': True})
        self.assertEqual(len(self.inter), 1)

    def test_own_group_none_and_errors(self):
        self.t.deploy(self.a, {'policy': 'www', 'chain': 'existing',
                               'intermediate_group': 'LE-R'})
        self.assertEqual(self.pols['www']['intermediate-certificate-group'], 'LE-R')
        self.assertEqual(self.inter, [])
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {'policy': 'www', 'chain': 'existing', 'force': True})
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'policy': 'nope', 'chain': 'none', 'force': True})
        self.assertIn('no server policy', str(e.exception))

    def test_test_catalog_look(self):
        self.assertIn('v7.4.3', self.t.test())
        self.assertEqual([x[0] for x in self.t.catalog('policies')['options']], ['www', 'old'])
        self.t.action('look')
        self.assertEqual({c['method'] for c in self.ctx.calls}, {'GET'})


# ---------------------------------------------------------------------------
class FortiAdcTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        o = olds(self.a)
        self.certs = [o[0], o[1], o[2], 'Factory']
        self.members = {'G1': [{'mkey': '1', 'local_cert': o[2], 'default': 'enable'},
                               {'mkey': '2', 'local_cert': 'Factory', 'default': 'disable'}],
                        'G2': [{'mkey': '1', 'local_cert': o[0], 'default': 'enable'}]}
        self.prof = {'P1': {'mkey': 'P1', 'local_certificate_group': 'OLD'}}
        self.vs = {'V1': {'mkey': 'V1', 'client_ssl_profile': 'X'}}
        self.uploads = []

        def login(call):
            return 200, {'token': 'TOK'}, {'Set-Cookie': 'APSCOOKIE=abc; Path=/; HttpOnly'}

        def certs(call):
            if call['method'] == 'GET':
                return 200, {'payload': [{'mkey': n} for n in self.certs]}
            self.certs.remove(call['query']['mkey'][0])
            return 200, {'payload': 0}

        def upload(call):
            assert call['headers']['Authorization'] == 'Bearer TOK'
            assert call['headers']['Cookie'] == 'APSCOOKIE=abc'
            p = parts_of(call)
            self.uploads.append((call['query'], p))
            self.certs.append(p['mkey'][1].decode())
            return 200, {'payload': 0}

        def member(call):
            g = call['query']['pkey'][0]
            if call['method'] == 'GET':
                return 200, {'payload': self.members.get(g, [])}
            if call['method'] == 'POST':
                b = body(call)
                self.members[g].append(dict(b, mkey=str(len(self.members[g]) + 10)))
                return 200, {'payload': 0}
            mk = call['query']['mkey'][0]
            self.members[g] = [m for m in self.members[g] if m['mkey'] != mk]
            return 200, {'payload': 0}

        def obj(store):
            def f(call):
                k = call['query']['mkey'][0]
                if call['method'] == 'GET':
                    return (200, {'payload': dict(store[k])}) if k in store else \
                        (200, {'payload': []})
                store[k] = body(call)
                return 200, {'payload': 0}
            return f
        self.ctx = FakeCtx([
            ('POST', r'/api/user/login$', login),
            ('GET', r'/api/user/logout$', (200, {'payload': 0})),
            ('GET', r'/api/system_certificate_local(\?|$)', certs),
            ('DELETE', r'/api/system_certificate_local\?', certs),
            ('POST', r'/api/upload/certificate_local\?', upload),
            ('GET', r'/api/system_certificate_local_cert_group(\?|$)',
             lambda c: (200, {'payload': [{'mkey': g} for g in self.members]})),
            ('GET', r'/child_group_member|_child_group_member', member),
            ('POST', r'_child_group_member', member),
            ('DELETE', r'_child_group_member', member),
            ('GET', r'/api/load_balance_client_ssl_profile\?', obj(self.prof)),
            ('PUT', r'/api/load_balance_client_ssl_profile\?', obj(self.prof)),
            ('GET', r'/api/load_balance_virtual_server\?', obj(self.vs)),
            ('PUT', r'/api/load_balance_virtual_server\?', obj(self.vs)),
        ])
        self.t = make('fortiadc', {'host': 'adc.test', 'user': 'admin', 'password': 'pw'},
                      self.ctx)

    def test_upload_member_point_cleanup_noop(self):
        name = C.object_name(self.a, {})
        o = olds(self.a)
        opts = {'cert_group': 'G1', 'intermediate_cag': 'LE', 'client_ssl_profiles': 'P1',
                'virtual_servers': 'V1', 'keep': '0'}
        self.t.deploy(self.a, opts)
        q, p = self.uploads[0]
        self.assertEqual(q, {'vdom': ['false']})
        self.assertEqual({k: v[1] for k, v in p.items() if k in ('type', 'mkey', 'upload')},
                         {'type': b'CertKey', 'mkey': name.encode(), 'upload': b'text'})
        self.assertEqual(p['cert'][1], self.a.cert_pem.encode())
        self.assertEqual(p['key'][1], self.a.key_pem.encode())
        g1 = {m['local_cert']: m for m in self.members['G1']}
        self.assertEqual(sorted(g1), sorted(['Factory', name]))
        self.assertEqual((g1[name]['default'], g1[name]['intermediate_cag']), ('enable', 'LE'))
        self.assertEqual(self.prof['P1']['local_certificate_group'], 'G1')
        self.assertEqual(self.vs['V1']['client_ssl_profile'], 'P1')
        # keep 0: o[2] (taken out of G1) and o[1] go, o[0] is still in G2
        self.assertEqual(sorted(self.certs), sorted(['Factory', o[0], name]))
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, opts).startswith('unchanged'))
        self.assertEqual([c['method'] for c in self.ctx.calls[n:]], ['POST', 'GET', 'GET'])

    def test_api_key_vdom_and_errors(self):
        t = make('fortiadc', {'host': 'adc.test', 'auth': 'api_key', 'api_key': 'KEY',
                              'vdom': 'v1'}, self.ctx)
        self.assertIn('2 groups', t.test())
        c = self.ctx.calls[-1]
        self.assertEqual(c['headers']['Authorization'], 'Bearer KEY')
        self.assertEqual(c['query']['vdom'], ['v1'])
        self.assertFalse(self.ctx.find('POST', '/login'))
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {})
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {'cert_group': 'G1', 'virtual_servers': 'V1'})
        ctx = FakeCtx([('POST', r'/login$', (200, {'token': 'T'})),
                       ('GET', r'/logout$', (200, {})),
                       ('GET', r'/api/system_certificate_local', (200, {'payload': -1}))])
        with self.assertRaises(PluginError) as e:
            make('fortiadc', {'host': 'adc.test', 'user': 'u', 'password': 'p'}, ctx).test()
        self.assertIn('error -1', str(e.exception))

    def test_catalog_look_read_only(self):
        self.assertEqual(self.t.catalog('groups')['options'], [['G1', 'G1'], ['G2', 'G2']])
        self.t.action('look')
        self.assertEqual({c['method'] for c in self.ctx.calls}, {'GET', 'POST'})
        self.assertEqual({c['path'] for c in self.ctx.calls if c['method'] == 'POST'},
                         {'/api/user/login'})


# ---------------------------------------------------------------------------
class CiscoFmcTest(unittest.TestCase):
    DOM = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'

    def setUp(self):
        self.a = FakeBundle()
        o = olds(self.a)
        self.certs = {('id%d' % i): {'id': 'id%d' % i, 'name': n, 'type': 'InternalCertificate'}
                      for i, n in enumerate(o)}
        self.rules = {'P1': {'r1': {'id': 'r1', 'name': 'known key', 'action': 'DECRYPT_KNOWN_KEY',
                                    'decryptionCertificates': [{'id': 'id2', 'name': o[2],
                                                                'type': 'InternalCertificate'}],
                                    'links': {'self': 'x'}},
                             'r2': {'id': 'r2', 'name': 'other', 'action': 'DO_NOT_DECRYPT'}},
                      'P2': {'r9': {'id': 'r9', 'name': 'still', 'x': {'id': 'id1'}}}}
        self.deployed = []

        def token(call):
            assert call['headers']['Authorization'] == 'Basic ' + base64.b64encode(
                b'api:pw').decode()
            return 204, b'', {'X-auth-access-token': 'TOK', 'X-auth-refresh-token': 'R',
                              'DOMAIN_UUID': self.DOM}

        def certs(call):
            assert call['headers']['X-auth-access-token'] == 'TOK'
            if call['method'] == 'GET':
                return 200, {'items': list(self.certs.values()),
                             'paging': {'count': len(self.certs)}}
            if call['method'] == 'POST':
                b = body(call)
                cid = 'new%d' % len(self.certs)
                self.certs[cid] = dict(b, id=cid)
                return 201, self.certs[cid]
            del self.certs[call['path'].rsplit('/', 1)[1]]
            return 200, {}

        def rules(call):
            pid = call['path'].split('/')[-2] if call['method'] == 'PUT' else \
                call['path'].split('/')[-2]
            if call['method'] == 'GET':
                return 200, {'items': list(self.rules[pid].values()),
                             'paging': {'count': len(self.rules[pid])}}
            pid = call['path'].split('/')[-3]
            rid = call['path'].rsplit('/', 1)[1]
            self.rules[pid][rid] = body(call)
            return 200, body(call)
        base = r'/api/fmc_config/v1/domain/%s' % self.DOM
        self.ctx = FakeCtx([
            ('POST', r'/api/fmc_platform/v1/auth/generatetoken$', token),
            ('GET', base + r'/object/internalcertificates', certs),
            ('POST', base + r'/object/internalcertificates$', certs),
            ('DELETE', base + r'/object/internalcertificates/', certs),
            ('GET', base + r'/policy/decryptionpolicies\?', lambda c: (200, {'items': [
                {'id': 'P1', 'name': 'Inbound'}, {'id': 'P2', 'name': 'Second'}],
                'paging': {'count': 2}})),
            ('GET', base + r'/policy/decryptionpolicies/[^/]+/decryptionpolicyrules', rules),
            ('PUT', base + r'/policy/decryptionpolicies/[^/]+/decryptionpolicyrules/', rules),
            ('GET', base + r'/deployment/deployabledevices', lambda c: (200, {'items': [
                {'name': 'ftd-1', 'device': {'id': 'D1', 'name': 'ftd-1'}},
                {'name': 'ftd-2', 'device': {'id': 'D2', 'name': 'ftd-2'}}]})),
            ('POST', base + r'/deployment/deploymentrequests$',
             lambda c: (self.deployed.append(body(c)), (202, {'type': 'DeploymentRequest'}))[1]),
        ])
        self.t = make('cisco_fmc', {'host': 'fmc.test', 'user': 'api', 'password': 'pw'},
                      self.ctx)

    def test_new_object_switch_deploy_cleanup_noop(self):
        name = C.object_name(self.a, {})
        o = olds(self.a)
        words = self.t.deploy(self.a, {'decryption_policy': 'Inbound', 'devices': 'ftd-1',
                                       'keep': '0'})
        self.assertIn('Inbound: 1 rule', words)
        post = body(self.ctx.find('POST', r'/internalcertificates$')[0])
        self.assertEqual(post, {'name': name, 'type': 'InternalCertificate',
                                'cert': self.a.cert_pem, 'privateKey': self.a.key_pem})
        new = [c for c in self.certs.values() if c['name'] == name][0]
        r1 = self.rules['P1']['r1']
        self.assertEqual(r1['decryptionCertificates'], [{'id': new['id'], 'name': name,
                                                         'type': 'InternalCertificate'}])
        self.assertNotIn('links', r1)
        self.assertEqual(len(self.ctx.find('PUT', r'decryptionpolicyrules/')), 1)   # r2 alone
        self.assertEqual(self.deployed, [{'type': 'DeploymentRequest', 'ignoreWarning': True,
                                          'deviceList': ['D1'],
                                          'deploymentNote': 'acme: a renewed certificate'}])
        # keep 0: id0 and id2 go; id1 is still named by a rule of P2
        self.assertEqual(sorted(c['name'] for c in self.certs.values()), sorted([o[1], name]))
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, {'decryption_policy': 'Inbound',
                                               'devices': 'ftd-1', 'keep': '0'})
                        .startswith('unchanged'))
        self.assertEqual([c['method'] for c in self.ctx.calls[n:]], ['GET'])

    def test_nothing_to_switch_no_deploy_and_errors(self):
        self.rules['P1'] = {}
        self.t.deploy(self.a, {'decryption_policies': 'P1'})
        self.assertEqual(self.deployed, [])
        self.assertTrue(any('pick' in w for _l, w in self.ctx.steps))
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {'decryption_policy': 'nope', 'force': True})
        ctx = FakeCtx([('POST', r'generatetoken$', (401, {'error': {'messages': [
            {'description': 'Invalid credentials'}]}}))])
        with self.assertRaises(PluginError) as e:
            make('cisco_fmc', {'host': 'fmc.test', 'user': 'u', 'password': 'p'}, ctx).test()
        self.assertFalse(e.exception.retry)

    def test_catalog_look(self):
        self.assertEqual(self.t.catalog('policies')['options'],
                         [['Inbound', 'Inbound'], ['Second', 'Second']])
        self.t.action('look')
        self.assertIn('3 internal certificates', self.t.test())
        self.assertEqual({c['method'] for c in self.ctx.calls}, {'GET', 'POST'})
        self.assertEqual({c['path'] for c in self.ctx.calls if c['method'] == 'POST'},
                         {'/api/fmc_platform/v1/auth/generatetoken'})


# ---------------------------------------------------------------------------
class CpanelSslTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.b = FakeBundle('b')
        self.installed = {'www.example.test': self.b.cert_pem}
        self.store = {}
        self.n = 0

        def hosts(call):
            assert call['headers']['Authorization'] == 'cpanel acct:TOKEN'
            return 200, {'result': {'status': 1, 'data': [
                {'servername': 'www.example.test', 'domains': ['www.example.test',
                                                              'example.test'],
                 'certificate_text': self.installed.get('www.example.test', ''),
                 'certificate': {'not_after': 1}},
                {'servername': 'other.test', 'domains': ['other.test'],
                 'certificate_text': '', 'certificate': {}}]}}

        def install(call):
            f = urllib.parse.parse_qs(call['body'].decode())
            self.n += 1
            cid = 'www_example_test_%d' % self.n
            for k, v in self.store.items():
                v['domain_is_configured'] = 0
            self.store[cid] = {'id': cid, 'domain_is_configured': 1}
            self.installed[f['domain'][0]] = f['cert'][0]
            self.forms.append(f)
            return 200, {'result': {'status': 1, 'data': {
                'cert_id': cid, 'action': 'update', 'message':
                'The SSL certificate is now installed onto the domain "%s".' % f['domain'][0]}}}

        def listc(call):
            return 200, {'result': {'status': 1, 'data': list(self.store.values())}}

        def delete(call):
            del self.store[call['query']['id'][0]]
            return 200, {'result': {'status': 1, 'data': []}}
        self.forms = []
        self.ctx = FakeCtx([
            ('GET', r'^https://cp\.test:2083/execute/SSL/installed_hosts$', hosts),
            ('POST', r'^https://cp\.test:2083/execute/SSL/install_ssl$', install),
            ('GET', r'/execute/SSL/list_certs$', listc),
            ('GET', r'/execute/SSL/delete_cert\?', delete),
        ])
        self.t = make('cpanel_ssl', {'host': 'cp.test', 'user': 'acct', 'token': 'TOKEN'},
                      self.ctx)

    def test_install_covered_site_noop_and_storage(self):
        words = self.t.deploy(self.a, {})
        self.assertEqual(words, 'installed on www.example.test')
        f = self.forms[0]
        self.assertEqual(f['cert'], [self.a.cert_pem])
        self.assertEqual(f['key'], [self.a.key_pem])
        self.assertEqual(f['cabundle'], [self.a.chain_pems[0]])
        self.assertEqual(self.ctx.find('POST', 'install_ssl')[0]['headers']['Content-Type'],
                         'application/x-www-form-urlencoded')
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, {}).startswith('unchanged'))
        self.assertEqual(len(self.ctx.calls), n + 1)
        # the twin, then a third: the first one acme installed goes from SSL storage (keep 1)
        self.t.deploy(self.b, {})
        self.t.deploy(self.a, {'force': True})
        self.assertEqual(sorted(self.store), ['www_example_test_2', 'www_example_test_3'])
        self.assertEqual(len(self.ctx.find('GET', 'delete_cert')), 1)

    def test_given_domain_errors_and_catalog(self):
        self.t.deploy(self.a, {'domain': 'other.test', 'send_chain': False})
        self.assertNotIn('cabundle', self.forms[0])
        self.assertEqual(self.forms[0]['domain'], ['other.test'])
        ctx = FakeCtx([('GET', r'installed_hosts$', (200, {'result': {'status': 1, 'data': []}})),
                       ('POST', r'install_ssl$', (200, {'result': {
                           'status': 0, 'errors': ['The certificate does not match the key.']}}))])
        t = make('cpanel_ssl', {'host': 'cp.test', 'user': 'acct', 'token': 'TOKEN'}, ctx)
        with self.assertRaises(PluginError):
            t.deploy(self.a, {})                         # no site covered
        with self.assertRaises(PluginError) as e:
            t.deploy(self.a, {'domain': 'x.test'})
        self.assertIn('does not match the key', str(e.exception))
        self.assertEqual([o[0] for o in self.t.catalog('domains')['options']],
                         ['www.example.test', 'other.test'])
        self.t.action('look')

    def test_whm(self):
        got = []

        def install(call):
            got.append(call['query'])
            return 200, {'metadata': {'result': 1, 'reason': 'OK'},
                         'data': {'status': 1, 'message': 'installed'}}
        ctx = FakeCtx([
            ('GET', r'^https://whm\.test:2087/json-api/fetch_ssl_vhosts\?api\.version=1$',
             (200, {'metadata': {'result': 1}, 'data': {'vhosts': [
                 {'servername': 'www.example.test', 'domains': ['www.example.test'],
                  'crt': {'not_after': 5}}]}})),
            ('GET', r'^https://whm\.test:2087/json-api/installssl\?', install)])
        t = make('cpanel_ssl', {'host': 'whm.test', 'api': 'whm', 'user': 'root',
                                'token': 'T'}, ctx)
        t.deploy(self.a, {'domain': 'www.example.test'})
        self.assertEqual(ctx.calls[0]['headers']['Authorization'], 'whm root:T')
        q = got[0]
        self.assertEqual((q['api.version'], q['domain'], q['crt'], q['key'], q['cab']),
                         (['1'], ['www.example.test'], [self.a.cert_pem], [self.a.key_pem],
                          [self.a.chain_pems[0]]))


# ---------------------------------------------------------------------------
class DirectAdminSslTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.files = {'c1': {'cert': FakeBundle('b').cert_pem}}
        self.puts = []

        def certs(call):
            return 200, {'certIds': list(self.files), 'missingDNSNames': [], 'certs': [
                {'id': k, 'autorenewEnabled': False, 'error': '',
                 'certificate': {'dnsNames': ['www.example.test', 'example.test']}}
                for k in self.files]}

        def files(call):
            cid = call['path'].split('/')[-2]
            if call['method'] == 'GET':
                return (200, self.files[cid]) if cid in self.files else (404, {'type': 'NOT_FOUND'})
            self.puts.append((call['query'], body(call)))
            if call['query'].get('dry-run') != ['true']:
                self.files[cid] = {'cert': body(call)['cert']}
            return 200, {'cert': body(call)['cert'], 'error': ''}
        self.ctx = FakeCtx([
            ('GET', r'^https://da\.test:2222/api/domain-tls/domains/example\.test/certs$', certs),
            ('GET', r'/api/domain-tls/domains/example\.test/certs/[^/]+/files$', files),
            ('PUT', r'/api/domain-tls/domains/example\.test/certs/[^/]+/files\?', files),
            ('GET', r'/api/session$', (200, {})),
        ])
        self.t = make('directadmin_ssl', {'host': 'da.test', 'user': 'admin',
                                          'password': 'KEY', 'as_user': 'john'}, self.ctx)

    def test_replace_dry_run_first_noop(self):
        words = self.t.deploy(self.a, {'da_domain': 'example.test'})
        self.assertIn('c1', words)
        self.assertEqual(self.ctx.calls[0]['headers']['Authorization'],
                         'Basic ' + base64.b64encode(b'admin|john:KEY').decode())
        (q1, b1), (q2, b2) = self.puts
        self.assertEqual(q1, {'dry-run': ['true'], 'update-acme-skiplist': ['true']})
        self.assertEqual(q2, {'update-acme-skiplist': ['true']})
        self.assertEqual(b2, {'cert': self.a.cert_pem, 'chain': self.a.chain_pems,
                              'key': self.a.key_pem})
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, {'da_domain': 'example.test'})
                        .startswith('unchanged'))
        self.assertEqual([c['method'] for c in self.ctx.calls[n:]], ['GET', 'GET'])

    def test_slots_errors_catalog(self):
        self.files['c2'] = {'cert': ''}
        self.ctx.routes[0] = ('GET', r'/certs$', lambda c: (200, {'certIds': ['c1', 'c2'],
                                                                  'certs': []}))
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'da_domain': 'example.test'})
        self.assertIn('c1, c2', str(e.exception))
        self.t.deploy(self.a, {'da_domain': 'example.test', 'cert_id': 'c2'})
        self.assertEqual(self.files['c2']['cert'], self.a.cert_pem)
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {})
        t = make('directadmin_ssl', {'host': 'da.test', 'user': 'u', 'password': 'p',
                                     'da_domain': 'example.test'}, FakeCtx([
                                         ('GET', r'/certs$', (200, {'certIds': ['default'],
                                          'certs': [{'id': 'default', 'certificate': {
                                              'dnsNames': ['example.test'],
                                              'notAfter': '2027-01-01'}}]}))]))
        self.assertEqual(t.catalog('cert_ids')['options'],
                         [['default', 'default: example.test, until 2027-01-01']])

    def test_legacy(self):
        posts = []

        def post(call):
            posts.append(urllib.parse.parse_qs(call['body'].decode()))
            return 200, 'error=0&text=Certificate%20and%20Key%20Saved.&details='
        ctx = FakeCtx([('GET', r'/CMD_API_SSL\?domain=example\.test$',
                        (200, 'ssl_on=yes&server=no&certificate=&key=')),
                       ('POST', r'/CMD_API_SSL$', post)])
        t = make('directadmin_ssl', {'host': 'da.test', 'user': 'john', 'password': 'K',
                                     'api': 'legacy'}, ctx)
        t.deploy(self.a, {'da_domain': 'example.test'})
        self.assertEqual(posts[0]['type'], ['paste'])
        self.assertEqual(posts[0]['certificate'], [self.a.cert_pem.strip() + '\n' +
                                                   self.a.key_pem.strip() + '\n'])
        self.assertEqual((posts[1]['type'], posts[1]['active'], posts[1]['cacert']),
                         (['cacert'], ['yes'], [self.a.chain_pems[0]]))
        ctx.routes[1] = ('POST', r'/CMD_API_SSL$', (200, 'error=1&text=Invalid%20key&details=x'))
        with self.assertRaises(PluginError) as e:
            t.deploy(self.a, {'da_domain': 'example.test', 'force': True})
        self.assertIn('Invalid key', str(e.exception))


# ---------------------------------------------------------------------------
class PleskTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.pool = olds(self.a) + ['default certificate']
        self.packets = []

        def agent(call):
            assert call['headers']['HTTP_AUTH_LOGIN'] == 'admin'
            assert call['headers']['HTTP_AUTH_PASSWD'] == 'pw'
            root = ET.fromstring(call['body'])
            self.packets.append(root)
            op = root.find('./certificate')[0]
            if op.tag == 'get-pool':
                certs = ''.join('<certificate><name>%s</name></certificate>' % n
                                for n in self.pool)
                return 200, ('<packet><certificate><get-pool><result><status>ok</status>'
                             '<certificates>%s</certificates></result></get-pool></certificate>'
                             '</packet>' % certs)
            if op.tag == 'install':
                self.pool.append(op.findtext('name'))
            if op.tag == 'remove':
                self.pool.remove(op.findtext('./filter/name'))
            return 200, ('<packet><certificate><%s><result><status>ok</status></result></%s>'
                         '</certificate></packet>' % (op.tag, op.tag))
        self.ctx = FakeCtx([('POST', r'^https://plesk\.test:8443/enterprise/control/agent\.php$',
                             agent)])
        self.t = make('plesk', {'host': 'plesk.test', 'user': 'admin', 'password': 'pw'},
                      self.ctx)

    def test_install_says_assign_by_hand_noop(self):
        name = C.object_name(self.a, {})
        words = self.t.deploy(self.a, {'subscription': 'example.test'})
        self.assertIn('assign it to the website in Plesk', words)
        inst = self.packets[1].find('./certificate/install')
        self.assertEqual([e.tag for e in inst], ['name', 'webspace', 'content'])
        self.assertEqual(inst.findtext('webspace'), 'example.test')
        content = inst.find('content')
        self.assertEqual([e.tag for e in content], ['csr', 'pvt', 'cert', 'ca'])
        self.assertEqual(content.findtext('pvt'), self.a.key_pem.strip())
        self.assertEqual(content.findtext('cert'), self.a.cert_pem.strip())
        self.assertEqual(content.findtext('ca'), self.a.chain_pems[0].strip())
        self.assertEqual(self.ctx.calls[1]['headers']['Content-Type'], 'text/xml')
        self.assertTrue(any('does not assign' in w for lv, w in self.ctx.steps if lv == 'warn'))
        self.assertIn(name, self.pool)
        self.assertEqual(len(self.pool), 5)          # keep -1 by default: nothing removed
        n = len(self.packets)
        self.assertTrue(self.t.deploy(self.a, {'subscription': 'example.test'})
                        .startswith('unchanged'))
        self.assertEqual(len(self.packets), n + 1)

    def test_admin_keep_and_errors(self):
        o = olds(self.a)
        self.t.deploy(self.a, {'repository': 'admin', 'keep': '1'})
        self.assertIsNotNone(self.packets[0].find('./certificate/get-pool/admin'))
        self.assertIsNotNone(self.packets[1].find('./certificate/install/admin'))
        rm = [p.find('./certificate/remove') for p in self.packets
              if p.find('./certificate/remove') is not None]
        self.assertEqual([r.findtext('./filter/name') for r in rm], [o[1], o[0]])
        self.assertIsNotNone(rm[0].find('admin'))
        self.assertIn('default certificate', self.pool)
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {})                   # no subscription
        ctx = FakeCtx([('POST', r'agent\.php$', (200, '<packet><system><status>error</status>'
                                                      '<errcode>1001</errcode><errtext>Access '
                                                      'denied</errtext></system></packet>'))])
        t = make('plesk', {'host': 'plesk.test', 'auth': 'key', 'secret_key': 'S'}, ctx)
        with self.assertRaises(PluginError) as e:
            t.test()
        self.assertIn('Access denied', str(e.exception))
        self.assertEqual(ctx.calls[0]['headers']['KEY'], 'S')


# ---------------------------------------------------------------------------
class DeployCatalogTest(unittest.TestCase):
    """A field of the type catalog in a deployment's form: api_catalog asks the target's
    module, with the deployment's options over the target's settings."""
    def test_deploy_field_found(self):
        from acmelib.certs import api_catalog
        cls = Registry(extra_dirs=[]).reload().get('target', 'nsx')
        seen = {}

        class Ctx(object):
            steps = []

            def tidy(self):
                pass

        def fake_catalog(self, key):
            seen['key'], seen['host'], seen['vs'] = key, self.c('host'), self.c('virtual_server')
            return {'options': [['vs1', 'vs one']], 'said': '1'}
        with mock.patch.object(api_catalog.S, 'plugin_row', return_value={
                'id': 3, 'name': 'nsx1', 'kind': 'nsx'}), \
                mock.patch.object(api_catalog.S, 'plugin_class', return_value=cls), \
                mock.patch.object(api_catalog.S, 'plugin_config', return_value={
                    'host': 'nsx.test', 'user': 'u', 'password': 'p'}), \
                mock.patch.object(api_catalog.runtime, 'RunContext', return_value=Ctx()), \
                mock.patch.object(cls, 'catalog', fake_catalog):
            got = api_catalog.catalog(None, 'target', {'id': 3, 'field': 'virtual_server',
                                                       'config': {'virtual_server': 'vs9'}})
        self.assertEqual(got['options'], [['vs1', 'vs one']])
        self.assertEqual(seen, {'key': 'virtual_servers', 'host': 'nsx.test', 'vs': 'vs9'})


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
                if f['key'] in ('token', 'password', 'api_key', 'secret_key'):
                    self.assertEqual(f['type'], 'secret', (k, f['key']))
            for f in d['deploy_fields']:
                # a deployment's key never shadows a setting of the target (api_catalog
                # lays the deployment's options over the target's settings)
                self.assertNotIn(f['key'], keys, (k, f['key']))
                if f['type'] == 'catalog':
                    self.assertFalse(f.get('autoload', True), (k, f['key']))
            for a in d['actions']:
                self.assertFalse(a.get('changes', True), (k, a['key']))   # they only read
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
                out += [f['label'], f.get('help', '')]
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


if __name__ == '__main__':
    unittest.main()
