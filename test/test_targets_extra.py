#!/usr/bin/env python3
"""The target modules of gateways, CDNs, cloud load balancers and appliances
added last - Kong, Hetzner Cloud, DigitalOcean, Avi, bunny.net, Fastly, Nginx
Proxy Manager, A10 Thunder, Nutanix, Azure App Service - without a network.

    python3 -m unittest test/test_targets_extra.py

The fake Context and certificates are those of test_targets.py: every request
is recorded and answered from a little fake of the service's API, and the
tests look at what was asked (paths, sign-in headers, bodies), at the same
certificate twice being a no-op, at old ones being cleaned up (never one still
in use), and at errors said in words.
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
from test_targets import FakeBundle, FakeCtx, make, read  # noqa: E402
from test_targets_more import parts_of  # noqa: E402
from acmelib.plugins.base import PluginError, Registry, FIELD_TYPES  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402

KINDS = ('kong', 'hetzner_lb', 'digitalocean_lb', 'avi', 'bunny', 'fastly',
         'nginx_proxy_manager', 'a10', 'nutanix', 'azure_appservice')


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def body(call):
    return json.loads(call['body'])


def b64d(s):
    return base64.b64decode(s).decode()


class Dual(FakeBundle):
    """A dual certificate: the twin is the other test certificate."""
    def __init__(self):
        FakeBundle.__init__(self, 'a')
        self.alt = FakeBundle('b')
        self.alt.family = 'rsa'
        self.family = 'ec'


# ---------------------------------------------------------------------------
class KongTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        label = 'acme-' + C.label_of(self.a, {}, 40)
        self.certs = [
            {'id': 'old1', 'tags': ['acme', label, 'acme-fp-0', 'acme-at-20260101-aaaa0001'],
             'snis': []},
            {'id': 'old2', 'tags': ['acme', label, 'acme-fp-1', 'acme-at-20260201-aaaa0002'],
             'snis': ['legacy.example.test']},
            {'id': 'old3', 'tags': ['acme', label, 'acme-fp-2', 'acme-at-20260301-aaaa0003'],
             'snis': []},
        ]
        self.snis = {}

        def listed(call):
            tag = call['query']['tags'][0]
            return 200, {'data': [c for c in self.certs if tag in c['tags']], 'next': None}

        def add(call):
            b = body(call)
            c = {'id': 'new%d' % len(self.certs), 'tags': b['tags'], 'snis': []}
            self.certs.append(c)
            return 201, c

        def sni(call):
            name = urllib.parse.unquote(call['path'].rsplit('/', 1)[1])
            self.snis[name] = body(call)['certificate']['id']
            return 200, {'name': name}

        def delete(call):
            cid = call['path'].rsplit('/', 1)[1]
            self.certs = [c for c in self.certs if c['id'] != cid]
            return 204, b''
        self.ctx = FakeCtx([
            ('GET', r'^http://kong\.test:8001/ws1/certificates\?tags=', listed),
            ('POST', r'^http://kong\.test:8001/ws1/certificates$', add),
            ('PUT', r'^http://kong\.test:8001/ws1/snis/', sni),
            ('DELETE', r'/ws1/certificates/', delete),
            ('GET', r'^http://kong\.test:8001/$', (200, {'version': '3.9.1'})),
            ('GET', r'/ws1/certificates\?size=1$', (200, {'data': []})),
        ])
        self.t = make('kong', {'url': 'kong.test:8001', 'token': 'RBAC', 'workspace': 'ws1'},
                      self.ctx)

    def test_add_point_cleanup_noop(self):
        words = self.t.deploy(self.a, {'snis': 'www.example.test\n*.example.test'})
        self.assertIn('2 SNIs', words)
        post = self.ctx.find('POST', r'/certificates$')[0]
        self.assertEqual(post['headers']['Kong-Admin-Token'], 'RBAC')
        b = body(post)
        self.assertEqual(b['cert'], self.a.fullchain_pem)
        self.assertEqual(b['key'], self.a.key_pem)
        self.assertIn('acme-fp-' + self.a.fingerprint[:16], b['tags'])
        self.assertNotIn('cert_alt', b)
        new = self.certs[-1]['id']
        self.assertEqual(self.snis, {'www.example.test': new, '*.example.test': new})
        self.assertIn('/ws1/snis/*.example.test', [c['path'] for c in self.ctx.calls])
        # keep 1: old3 stays, old1 goes, old2 is still used by an SNI and stays
        self.assertEqual(sorted(c['id'] for c in self.certs), sorted(['old2', 'old3', new]))
        self.assertTrue(any('legacy.example.test' in w for _l, w in self.ctx.steps))
        n = len(self.ctx.calls)
        self.assertTrue(self.t.deploy(self.a, {'snis': 'www.example.test\n*.example.test'})
                        .startswith('unchanged'))
        self.assertFalse([c for c in self.ctx.calls[n:] if c['method'] != 'GET'])

    def test_snis_default_and_dual(self):
        d = Dual()
        self.t.deploy(d, {})
        b = body(self.ctx.find('POST', r'/certificates$')[0])
        self.assertEqual(b['cert_alt'], d.alt.fullchain_pem)
        self.assertEqual(b['key_alt'], d.alt.key_pem)
        self.assertEqual(set(self.snis), set(d.names))

    def test_test_and_dbless(self):
        self.assertIn('Kong 3.9.1', self.t.test())
        ctx = FakeCtx([('GET', r'certificates\?tags=', (200, {'data': []})),
                       ('POST', r'/certificates$', (405, {
                           'message': 'cannot create \'certificates\' entities when not '
                                      'using a database (DB-less mode)'}))])
        t = make('kong', {'url': 'http://kong:8001'}, ctx)
        with self.assertRaises(PluginError) as e:
            t.deploy(self.a, {})
        self.assertIn('without a database', str(e.exception))
        self.assertNotIn('Kong-Admin-Token', ctx.calls[0]['headers'])


# ---------------------------------------------------------------------------
class HetznerLbTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.prefix = C.name_prefix(self.a, {}, maxlen=63)
        self.certs = [
            {'id': 11, 'name': self.prefix + '20260101-aaaa0001', 'used_by': []},
            {'id': 12, 'name': self.prefix + '20260601-aaaa0002',
             'used_by': [{'id': 7, 'type': 'load_balancer'}]},
            {'id': 13, 'name': 'someone-elses', 'used_by': [{'id': 7}]},
        ]
        self.lb = {'id': 7, 'name': 'lb-www', 'services': [
            {'protocol': 'https', 'listen_port': 443, 'http': {'certificates': [12, 13]}},
            {'protocol': 'https', 'listen_port': 8443, 'http': {'certificates': [13]}},
            {'protocol': 'tcp', 'listen_port': 22}]}

        def certs(call):
            q = call['query']
            if 'name' in q:
                return 200, {'certificates': [c for c in self.certs if c['name'] == q['name'][0]]}
            return 200, {'certificates': self.certs,
                         'meta': {'pagination': {'next_page': None}}}

        def add(call):
            b = body(call)
            c = {'id': 99, 'name': b['name'], 'used_by': []}
            self.certs.append(c)
            return 201, {'certificate': c, 'action': {'id': 1, 'status': 'success'}}

        def update(call):
            b = body(call)
            for s in self.lb['services']:
                if s['listen_port'] == b['listen_port']:
                    s['http']['certificates'] = b['http']['certificates']
            return 201, {'action': {'id': 5, 'status': 'running'}}

        def delete(call):
            cid = int(call['path'].rsplit('/', 1)[1])
            self.certs = [c for c in self.certs if c['id'] != cid]
            return 204, b''
        self.ctx = FakeCtx([
            ('GET', r'^https://api\.hetzner\.cloud/v1/certificates', certs),
            ('POST', r'^https://api\.hetzner\.cloud/v1/certificates$', add),
            ('GET', r'/v1/load_balancers\?name=lb-www$', lambda c: (200, {
                'load_balancers': [self.lb]})),
            ('POST', r'/v1/load_balancers/7/actions/update_service$', update),
            ('GET', r'/v1/load_balancers/actions/5$', (200, {'action': {
                'id': 5, 'status': 'success'}})),
            ('DELETE', r'/v1/certificates/\d+$', delete),
        ])
        self.t = make('hetzner_lb', {'token': 'HTOK'}, self.ctx)
        self.t._sleep = lambda s: None

    def test_upload_point_cleanup(self):
        words = self.t.deploy(self.a, {'load_balancers': 'lb-www', 'ports': '443'})
        self.assertIn('lb-www:443', words)
        post = self.ctx.find('POST', r'/v1/certificates$')[0]
        self.assertEqual(post['headers']['Authorization'], 'Bearer HTOK')
        b = body(post)
        self.assertEqual((b['type'], b['certificate'], b['private_key']),
                         ('uploaded', self.a.fullchain_pem, self.a.key_pem))
        # the older acme one (12) out, someone else's (13) kept, the new one in; 8443 untouched
        self.assertEqual(self.lb['services'][0]['http']['certificates'], [13, 99])
        self.assertEqual(self.lb['services'][1]['http']['certificates'], [13])
        self.assertEqual(len(self.ctx.find('GET', r'/actions/5$')), 1)
        # keep 1: 11 is older than 12 - deleted; 12 is still "used by" in the listing
        self.assertEqual(sorted(c['id'] for c in self.certs), [12, 13, 99])
        self.assertTrue(self.t.deploy(self.a, {'load_balancers': 'lb-www', 'ports': '443'})
                        .startswith('unchanged'))

    def test_replace_all_and_errors(self):
        self.t.deploy(self.a, {'load_balancers': 'lb-www', 'replace_all': True})
        self.assertEqual(self.lb['services'][1]['http']['certificates'], [99])
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'load_balancers': 'lb-www', 'ports': '80', 'force': True})
        self.assertIn('no HTTPS service on 80', str(e.exception))
        self.assertFalse(e.exception.retry)

    def test_look_changes_nothing(self):
        ctx = FakeCtx([('GET', r'/v1/certificates', (200, {'certificates': [
            {'id': 13, 'name': 'x-cert'}]})),
            ('GET', r'/v1/load_balancers\?page=1', (200, {'load_balancers': [self.lb]}))])
        t = make('hetzner_lb', {'token': 'HTOK'}, ctx)
        self.assertEqual(t.action('look'), '1 load balancer')
        self.assertIn('443 → 12, x-cert', ' '.join(w for _l, w in ctx.steps))
        self.assertTrue(all(c['method'] == 'GET' for c in ctx.calls))
        self.assertFalse([a for a in t.actions if a['changes']])


# ---------------------------------------------------------------------------
class DigitalOceanLbTest(unittest.TestCase):
    LB = 'a1b2c3d4-0000-4000-8000-000000000001'

    def setUp(self):
        self.a = FakeBundle()
        self.prefix = C.name_prefix(self.a, {}, maxlen=63)
        self.certs = [{'id': 'c-old', 'name': self.prefix + '20260101-aaaa0001'},
                      {'id': 'c-older', 'name': self.prefix + '20250101-aaaa0000'}]
        self.lb = {
            'id': self.LB, 'name': 'lb-www', 'ip': '192.0.2.1', 'status': 'active',
            'created_at': '2026-01-01T00:00:00Z', 'region': {'slug': 'fra1', 'name': 'Frankfurt'},
            'size': 'lb-small', 'algorithm': 'round_robin', 'droplet_ids': [1, 2],
            'redirect_http_to_https': True, 'vpc_uuid': 'vpc-1',
            'health_check': {'protocol': 'http', 'port': 80, 'path': '/'},
            'forwarding_rules': [
                {'entry_protocol': 'https', 'entry_port': 443, 'target_protocol': 'http',
                 'target_port': 80, 'certificate_id': 'c-old'},
                {'entry_protocol': 'http', 'entry_port': 80, 'target_protocol': 'http',
                 'target_port': 80},
                {'entry_protocol': 'https', 'entry_port': 8443, 'target_protocol': 'https',
                 'target_port': 443, 'tls_passthrough': True}]}

        def certs(call):
            q = call['query']
            if 'name' in q:
                return 200, {'certificates': [c for c in self.certs if c['name'] == q['name'][0]]}
            return 200, {'certificates': self.certs, 'links': {}}

        def add(call):
            c = {'id': 'c-new', 'name': body(call)['name']}
            self.certs.append(c)
            return 201, {'certificate': c}

        def put(call):
            self.lb = dict(self.lb, forwarding_rules=body(call)['forwarding_rules'])
            return 200, {'load_balancer': self.lb}

        def delete(call):
            cid = call['path'].rsplit('/', 1)[1]
            if cid == 'c-old' and any(r.get('certificate_id') == 'c-old'
                                      for r in self.lb['forwarding_rules']):
                return 422, {'id': 'unprocessable_entity', 'message': 'in use'}
            self.certs = [c for c in self.certs if c['id'] != cid]
            return 204, b''
        self.ctx = FakeCtx([
            ('GET', r'^https://api\.digitalocean\.com/v2/certificates', certs),
            ('POST', r'^https://api\.digitalocean\.com/v2/certificates$', add),
            ('GET', r'/v2/load_balancers/%s$' % self.LB, lambda c: (200, {'load_balancer':
                                                                          self.lb})),
            ('GET', r'/v2/load_balancers\?page=1', lambda c: (200, {'load_balancers': [self.lb],
                                                                    'links': {}})),
            ('PUT', r'/v2/load_balancers/%s$' % self.LB, put),
            ('DELETE', r'/v2/certificates/', delete),
        ])
        self.t = make('digitalocean_lb', {'token': 'DOTOK'}, self.ctx)

    def test_upload_update_cleanup(self):
        self.t.deploy(self.a, {'load_balancers': 'lb-www'})
        post = self.ctx.find('POST', r'/v2/certificates$')[0]
        self.assertEqual(post['headers']['Authorization'], 'Bearer DOTOK')
        b = body(post)
        self.assertEqual((b['type'], b['leaf_certificate'], b['certificate_chain']),
                         ('custom', self.a.cert_pem, self.a.chain_pems[0]))
        put = body(self.ctx.find('PUT', r'/v2/load_balancers/')[0])
        # what godo's AsRequest sends: no id/ip/status, the region as its slug
        self.assertEqual(put['region'], 'fra1')
        for k in ('id', 'ip', 'status', 'created_at'):
            self.assertNotIn(k, put)
        self.assertEqual((put['size'], put['droplet_ids'], put['health_check']['path']),
                         ('lb-small', [1, 2], '/'))
        rules = {r['entry_port']: r for r in put['forwarding_rules']}
        self.assertEqual(rules[443]['certificate_id'], 'c-new')
        self.assertNotIn('certificate_id', rules[80])
        self.assertNotIn('certificate_id', rules[8443])          # TLS passthrough
        # keep 1: c-older deleted, c-old stays (the one before)
        self.assertEqual(sorted(c['id'] for c in self.certs), ['c-new', 'c-old'])
        self.assertTrue(self.t.deploy(self.a, {'load_balancers': 'lb-www'})
                        .startswith('unchanged'))

    def test_by_id_and_keep0(self):
        self.t.deploy(self.a, {'load_balancers': self.LB, 'keep': 0})
        self.assertEqual([c['id'] for c in self.certs], ['c-new'])
        self.assertFalse(self.ctx.find('GET', r'/v2/load_balancers\?page'))

    def test_unknown_lb(self):
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'load_balancers': 'nope'})
        self.assertIn('no load balancer "nope"', str(e.exception))


# ---------------------------------------------------------------------------
class AviTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.prefix = C.name_prefix(self.a, {})
        self.objs = [{'uuid': 'sslkeyandcertificate-old', 'name': self.prefix + '20260101-aaaa0001',
                      'type': 'SSL_CERTIFICATE_TYPE_VIRTUALSERVICE'},
                     {'uuid': 'sslkeyandcertificate-older',
                      'name': self.prefix + '20250101-aaaa0000'},
                     {'uuid': 'sslkeyandcertificate-other', 'name': 'other-cert'}]
        self.vs = {'uuid': 'virtualservice-1', 'name': 'vs-www', 'ssl_key_and_certificate_refs': [
            'https://avi.test/api/sslkeyandcertificate/sslkeyandcertificate-old']}
        self.sc = {'uuid': 'default', 'portal_configuration': {
            'allow_basic_authentication': False,
            'sslkeyandcertificate_refs': ['https://avi.test/api/sslkeyandcertificate/x']}}

        def find(call):
            q = call['query']
            if 'name' in q:
                return 200, {'count': 1, 'results': [o for o in self.objs
                                                     if o['name'] == q['name'][0]]}
            return 200, {'count': len(self.objs), 'results': self.objs}

        def add(call):
            b = body(call)
            o = dict(b, uuid='sslkeyandcertificate-n%d' % len(self.objs))
            self.objs.append(o)
            return 201, o

        def delete(call):
            uid = call['path'].rsplit('/', 1)[1]
            self.objs = [o for o in self.objs if o['uuid'] != uid]
            return 204, b''
        cookies = 'csrftoken=CSRF1; expires=Thu, 01 Jan 2027 00:00:00 GMT; Path=/, ' \
                  'avi-sessionid=SESS1; Path=/; HttpOnly'
        self.ctx = FakeCtx([
            ('POST', r'^https://avi\.test/login$', (200, {
                'session_cookie_name': 'avi-sessionid', 'version': {'Version': '22.1.6'}},
                {'Set-Cookie': cookies})),
            ('POST', r'/logout$', (200, {})),
            ('GET', r'/api/sslkeyandcertificate\?', find),
            ('POST', r'/api/sslkeyandcertificate$', add),
            ('DELETE', r'/api/sslkeyandcertificate/', delete),
            ('GET', r'/api/virtualservice\?name=vs-www$', lambda c: (200, {'results': [self.vs]})),
            ('GET', r'/api/virtualservice\?name=', (200, {'results': []})),
            ('PATCH', r'/api/virtualservice/virtualservice-1$', self.patch_vs),
            ('GET', r'/api/systemconfiguration$', lambda c: (200, self.sc)),
            ('PATCH', r'/api/systemconfiguration$', (200, {})),
        ])
        self.t = make('avi', {'host': 'avi.test', 'user': 'acme', 'password': 'pw',
                              'tenant': 'web'}, self.ctx)

    def patch_vs(self, call):
        self.vs['ssl_key_and_certificate_refs'] = body(call)['replace'][
            'ssl_key_and_certificate_refs']
        return 200, self.vs

    def test_add_point_cleanup(self):
        self.t.deploy(self.a, {'virtual_services': 'vs-www'})
        login = self.ctx.calls[0]
        self.assertEqual(body(login), {'username': 'acme', 'password': 'pw'})
        post = [c for c in self.ctx.find('POST', r'/api/sslkeyandcertificate$')]
        ca, leaf = body(post[0]), body(post[1])
        self.assertEqual((ca['type'], ca['certificate']['certificate']),
                         ('SSL_CERTIFICATE_TYPE_CA', self.a.chain_pems[0]))
        self.assertEqual(leaf['type'], 'SSL_CERTIFICATE_TYPE_VIRTUALSERVICE')
        self.assertEqual((leaf['certificate']['certificate'], leaf['key']),
                         (self.a.cert_pem, self.a.key_pem))
        h = post[1]['headers']
        self.assertEqual(h['X-CSRFToken'], 'CSRF1')
        self.assertIn('avi-sessionid=SESS1', h['Cookie'])
        self.assertEqual((h['X-Avi-Tenant'], h['X-Avi-Version'], h['Referer']),
                         ('web', '22.1.6', 'https://avi.test'))
        new = [o for o in self.objs if o['name'] == leaf['name']][0]['uuid']
        self.assertEqual(self.vs['ssl_key_and_certificate_refs'],
                         ['/api/sslkeyandcertificate/%s' % new])
        names = [o['name'] for o in self.objs]
        self.assertNotIn(self.prefix + '20250101-aaaa0000', names)      # beyond keep 1
        self.assertIn(self.prefix + '20260101-aaaa0001', names)
        self.assertIn('other-cert', names)
        self.assertTrue(self.ctx.find('POST', r'/logout$'))
        self.assertTrue(self.t.deploy(self.a, {'virtual_services': 'vs-www'})
                        .startswith('unchanged'))

    def test_dual_takes_both_places(self):
        d = Dual()
        self.t.deploy(d, {'virtual_services': 'vs-www'})
        leaves = [body(c) for c in self.ctx.find('POST', r'/api/sslkeyandcertificate$')
                  if body(c)['type'] != 'SSL_CERTIFICATE_TYPE_CA']
        self.assertEqual(len(leaves), 2)
        self.assertIn('-rsa-', leaves[1]['name'])
        self.assertEqual(leaves[1]['certificate']['certificate'], d.alt.cert_pem)
        self.assertEqual(len(self.vs['ssl_key_and_certificate_refs']), 2)

    def test_portal_and_errors(self):
        self.t.deploy(self.a, {'portal': True})
        leaf = [body(c) for c in self.ctx.find('POST', r'/api/sslkeyandcertificate$')][-1]
        self.assertEqual(leaf['type'], 'SSL_CERTIFICATE_TYPE_SYSTEM')
        self.assertIn('-portal-', leaf['name'])
        pc = body(self.ctx.find('PATCH', r'/api/systemconfiguration$')[0])['replace'][
            'portal_configuration']
        self.assertFalse(pc['allow_basic_authentication'])          # the rest kept
        self.assertEqual(len(pc['sslkeyandcertificate_refs']), 1)
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {'portal': True, 'virtual_services': 'vs-www'})
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'virtual_services': 'vs-nope'})
        self.assertIn('no virtual service "vs-nope"', str(e.exception))
        ctx = FakeCtx([('POST', r'/login$', (200, {}, {'Set-Cookie': 'x=1'}))])
        with self.assertRaises(PluginError):
            make('avi', {'host': 'avi.test', 'user': 'u', 'password': 'p'}, ctx).test()


# ---------------------------------------------------------------------------
class BunnyTest(unittest.TestCase):
    def setUp(self):
        self.zone = {'Id': 42, 'Name': 'www-example', 'Hostnames': [
            {'Value': 'www-example.b-cdn.net', 'IsSystemHostname': True},
            {'Value': 'www.example.test', 'IsSystemHostname': False},
            {'Value': 'cdn.example.test', 'IsSystemHostname': False},
            {'Value': 'other.test', 'IsSystemHostname': False}]}
        self.ctx = FakeCtx([
            ('GET', r'^https://api\.bunny\.net/pullzone\?search=www-example$',
             lambda c: (200, {'Items': [self.zone]})),
            ('GET', r'^https://api\.bunny\.net/pullzone/42$', lambda c: (200, self.zone)),
            ('POST', r'/pullzone/42/addCertificate$', (200, b'')),
        ])
        self.t = make('bunny', {'api_key': 'BKEY'}, self.ctx)

    def test_covered_hostnames_then_noop(self):
        a = FakeBundle()
        a.names = ['www.example.test', '*.example.test']
        words = self.t.deploy(a, {'pull_zone': 'www-example'})
        adds = self.ctx.find('POST', r'addCertificate')
        self.assertEqual([body(c)['Hostname'] for c in adds],
                         ['www.example.test', 'cdn.example.test'])
        self.assertEqual(adds[0]['headers']['AccessKey'], 'BKEY')
        self.assertEqual(b64d(body(adds[0])['Certificate']), a.fullchain_pem)
        self.assertEqual(b64d(body(adds[0])['CertificateKey']), a.key_pem)
        self.assertIn('www-example', words)
        self.assertTrue(self.t.deploy(a, {'pull_zone': 'www-example'}).startswith('unchanged'))

    def test_listed_by_id_and_missing(self):
        a = FakeBundle()
        self.t.deploy(a, {'pull_zone': '42', 'hostnames': 'other.test'})
        self.assertEqual(body(self.ctx.find('POST', r'addCertificate')[0])['Hostname'],
                         'other.test')
        with self.assertRaises(PluginError) as e:
            self.t.deploy(a, {'pull_zone': '42', 'hostnames': 'nothere.test', 'force': True})
        self.assertIn('no hostname nothere.test', str(e.exception))
        self.assertTrue(C.covers(['*.example.test'], 'a.example.test'))
        self.assertFalse(C.covers(['*.example.test'], 'a.b.example.test'))


# ---------------------------------------------------------------------------
class FastlyTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.prefix = C.name_prefix(self.a, {})
        old = self.prefix + '20260101-aaaa0001'
        self.certs = [{'id': 'CERT1', 'type': 'tls_certificate', 'attributes': {'name': old}},
                      {'id': 'CERT9', 'type': 'tls_certificate', 'attributes': {'name': 'x'}}]
        self.keys = [{'id': 'K0', 'attributes': {'name': self.prefix + '20250101-aaaa0000'}},
                     {'id': 'K1', 'attributes': {'name': old}},
                     {'id': 'K9', 'attributes': {'name': 'not-acmes'}}]

        def keys(call):
            return 200, {'data': self.keys, 'meta': {'total_pages': 1}}

        def addkey(call):
            b = body(call)['data']
            self.keys.append({'id': 'K2', 'attributes': {'name': b['attributes']['name']}})
            return 201, {'data': {'id': 'K2'}}

        def patch(call):
            self.certs[0]['attributes']['name'] = body(call)['data']['attributes']['name']
            return 200, {'data': self.certs[0]}

        def delete(call):
            kid = call['path'].rsplit('/', 1)[1]
            self.keys = [k for k in self.keys if k['id'] != kid]
            return 204, b''
        self.ctx = FakeCtx([
            ('GET', r'^https://api\.fastly\.com/tls/certificates\?', lambda c: (200, {
                'data': self.certs, 'meta': {'total_pages': 1}})),
            ('GET', r'^https://api\.fastly\.com/tls/private_keys\?', keys),
            ('POST', r'/tls/private_keys$', addkey),
            ('PATCH', r'/tls/certificates/CERT1$', patch),
            ('POST', r'/tls/certificates$', (201, {'data': {'id': 'CERTN'}})),
            ('DELETE', r'/tls/private_keys/', delete),
        ])
        self.t = make('fastly', {'token': 'FTOK'}, self.ctx)

    def test_replace_in_place_and_keys(self):
        words = self.t.deploy(self.a, {})
        self.assertEqual(words, 'replaced CERT1')
        key = self.ctx.find('POST', r'/tls/private_keys$')[0]
        self.assertEqual(key['headers']['Fastly-Key'], 'FTOK')
        self.assertEqual(key['headers']['Content-Type'], 'application/vnd.api+json')
        kb = body(key)['data']
        self.assertEqual((kb['type'], kb['attributes']['key']), ('tls_private_key', self.a.key_pem))
        pb = body(self.ctx.find('PATCH', r'CERT1$')[0])['data']
        self.assertEqual((pb['type'], pb['id']), ('tls_certificate', 'CERT1'))
        self.assertEqual(pb['attributes']['cert_blob'], self.a.fullchain_pem)
        self.assertEqual(pb['attributes']['name'], kb['attributes']['name'])
        # keep 1: K1 stays (the one before), K0 goes, K9 is not acme's
        self.assertEqual(sorted(k['id'] for k in self.keys), ['K1', 'K2', 'K9'])
        self.assertIn('filter%5Bin_use%5D=false', self.ctx.find('GET', r'private_keys')[-1]['url'])
        self.assertTrue(self.t.deploy(self.a, {}).startswith('unchanged'))

    def test_first_time_adds(self):
        self.certs[0]['attributes']['name'] = 'manual'
        self.assertIn('added CERTN', self.t.deploy(self.a, {}))
        self.assertTrue(any('activate it once' in w for _l, w in self.ctx.steps))
        with self.assertRaises(PluginError):
            self.t.deploy(self.a, {'certificate_id': 'NOPE', 'force': True})


# ---------------------------------------------------------------------------
class NginxProxyManagerTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.prefix = C.name_prefix(self.a, {})
        self.certs = [
            {'id': 3, 'provider': 'other', 'nice_name': self.prefix + '20260101-aaaa0001',
             'proxy_hosts': [{'id': 7}], 'redirection_hosts': [], 'dead_hosts': []},
            {'id': 2, 'provider': 'other', 'nice_name': self.prefix + '20250101-aaaa0000',
             'proxy_hosts': [], 'redirection_hosts': [], 'dead_hosts': []},
            {'id': 1, 'provider': 'letsencrypt', 'nice_name': 'le', 'proxy_hosts': [{'id': 9}]}]
        self.hosts = {7: None, 8: None, 9: 1}

        def certs(call):
            return 200, self.certs

        def add(call):
            c = dict(body(call), id=10, proxy_hosts=[], redirection_hosts=[], dead_hosts=[])
            self.certs.append(c)
            return 201, c

        def put(call):
            hid = int(call['path'].rsplit('/', 1)[1])
            cid = body(call)['certificate_id']
            for c in self.certs:
                c['proxy_hosts'] = [h for h in c.get('proxy_hosts') or [] if h['id'] != hid]
                if c['id'] == cid:
                    c['proxy_hosts'].append({'id': hid})
            return 200, {'id': hid}

        def delete(call):
            cid = int(call['path'].rsplit('/', 1)[1])
            self.certs = [c for c in self.certs if c['id'] != cid]
            return 200, 'true'
        self.ctx = FakeCtx([
            ('POST', r'^http://npm\.test:81/api/tokens$', (200, {'token': 'JWT',
                                                                 'expires': '2026-11-03'})),
            ('GET', r'/api/nginx/certificates', certs),
            ('POST', r'/api/nginx/certificates$', add),
            ('POST', r'/api/nginx/certificates/10/upload$', (200, {'certificate': '...'})),
            ('GET', r'/api/nginx/proxy-hosts$', (200, [
                {'id': 8, 'domain_names': ['www.example.test']},
                {'id': 7, 'domain_names': ['old.example.test']}])),
            ('PUT', r'/api/nginx/proxy-hosts/\d+$', put),
            ('DELETE', r'/api/nginx/certificates/\d+$', delete),
            ('GET', r'/api/$', (200, {'status': 'OK', 'version': {'major': 2, 'minor': 12,
                                                                  'revision': 3}})),
        ])
        self.t = make('nginx_proxy_manager', {'url': 'http://npm.test:81', 'user': 'a@b.test',
                                              'password': 'pw'}, self.ctx)

    def test_add_upload_point_follow_cleanup(self):
        self.t.deploy(self.a, {'proxy_hosts': 'www.example.test'})
        self.assertEqual(body(self.ctx.calls[0]), {'identity': 'a@b.test', 'secret': 'pw'})
        add = self.ctx.find('POST', r'/certificates$')[0]
        self.assertEqual(add['headers']['Authorization'], 'Bearer JWT')
        self.assertEqual(body(add)['provider'], 'other')
        up = parts_of(self.ctx.find('POST', r'/upload$')[0])
        self.assertEqual(up['certificate'][1].decode(), self.a.cert_pem)
        self.assertEqual(up['certificate_key'][1].decode(), self.a.key_pem)
        self.assertEqual(up['intermediate_certificate'][1].decode(), self.a.chain_pems[0])
        puts = self.ctx.find('PUT', r'/proxy-hosts/')
        self.assertEqual(sorted(c['path'] for c in puts),
                         ['/api/nginx/proxy-hosts/7', '/api/nginx/proxy-hosts/8'])
        self.assertEqual(body(puts[0]), {'certificate_id': 10})
        ids = sorted(c['id'] for c in self.certs)
        self.assertEqual(ids, [1, 3, 10])          # 2 beyond keep, 3 kept, LE never touched
        self.assertTrue(self.t.deploy(self.a, {'proxy_hosts': 'www.example.test'})
                        .startswith('unchanged'))

    def test_2fa_and_unknown_host(self):
        ctx = FakeCtx([('POST', r'/api/tokens$', (200, {'requires_2fa': True,
                                                        'challenge_token': 'x'}))])
        t = make('nginx_proxy_manager', {'url': 'npm.test:81', 'user': 'u', 'password': 'p'},
                 ctx)
        with self.assertRaises(PluginError) as e:
            t.deploy(self.a, {})
        self.assertFalse(e.exception.retry)
        self.assertTrue(ctx.calls[0]['url'].startswith('http://npm.test:81/api/tokens'))
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'proxy_hosts': 'nope.test'})
        self.assertIn('no proxy host "nope.test"', str(e.exception))
        self.assertIn('2.12.3', self.t.test())


# ---------------------------------------------------------------------------
class A10Test(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.prefix = C.name_prefix(self.a, {})
        self.files = [self.prefix + '20250101-aaaa0000', self.prefix + '20260101-aaaa0001',
                      'default']
        self.deleted = []

        def oper(call):
            return 200, {'ssl-cert': {'oper': {'file-list': [{'file': f} for f in self.files]}}}

        def upload(call):
            p = parts_of(call)
            meta = json.loads(p['json'][1])
            kind = list(meta)[0]
            if kind == 'ssl-cert':
                self.files.append(meta[kind]['file'])
            return 200, {'response': {'status': 'OK'}}

        def delete(call):
            d = body(call)['delete']
            self.deleted.append(d)
            if 'cert-name' in d and d['cert-name'] in self.files:
                self.files.remove(d['cert-name'])
            return 200, {'response': {'status': 'OK'}}
        self.ctx = FakeCtx([
            ('POST', r'^https://thunder\.test/axapi/v3/auth$', (200, {
                'authresponse': {'signature': 'SIG1', 'description': 'the signature'}})),
            ('POST', r'/axapi/v3/active-partition/p1$', (200, {'response': {'status': 'OK'}})),
            ('GET', r'/axapi/v3/file/ssl-cert/oper$', oper),
            ('POST', r'/axapi/v3/file/ssl-(cert|key)$', upload),
            ('POST', r'/axapi/v3/slb/template/client-ssl/tpl-www/certificate$', (200, {})),
            ('POST', r'/axapi/v3/slb/template/client-ssl/tpl-nope/certificate$', (404, {
                'response': {'status': 'fail', 'err': {'code': 1023460352,
                                                       'msg': 'Object specified does not exist'}}})),
            ('POST', r'/axapi/v3/write/memory$', (200, {'response': {'status': 'OK'}})),
            ('POST', r'/axapi/v3/pki/delete$', delete),
            ('POST', r'/axapi/v3/logoff$', (200, {})),
            ('GET', r'/axapi/v3/version/oper$', (200, {'version': {'oper': {
                'sw-version': '5.2.1-P9'}}})),
        ])
        self.t = make('a10', {'host': 'thunder.test', 'user': 'admin', 'password': 'pw',
                              'partition': 'p1'}, self.ctx)

    def test_import_point_write_cleanup(self):
        self.t.deploy(self.a, {'templates': 'tpl-www'})
        auth = self.ctx.calls[0]
        self.assertEqual(body(auth), {'credentials': {'username': 'admin', 'password': 'pw'}})
        self.assertEqual(body(self.ctx.calls[1]), {'active-partition': {
            'curr_part_name': 'p1', 'shared': 'false'}})
        ups = self.ctx.find('POST', r'/file/ssl-')
        self.assertEqual(ups[0]['headers']['Authorization'], 'A10 SIG1')
        first = parts_of(ups[0])
        meta = json.loads(first['json'][1])['ssl-cert']
        self.assertEqual((meta['action'], meta['certificate-type']), ('import', 'pem'))
        self.assertEqual(first['file'][1].decode(), self.a.cert_pem)
        key = parts_of(ups[1])
        self.assertEqual(json.loads(key['json'][1])['ssl-key']['file'], meta['file'])
        self.assertEqual(key['file'][1].decode(), self.a.key_pem)
        chain = parts_of(ups[2])
        self.assertTrue(json.loads(chain['json'][1])['ssl-cert']['file'].startswith('acme-ca-'))
        tpl = body(self.ctx.find('POST', r'client-ssl/tpl-www/certificate$')[0])['certificate']
        self.assertEqual((tpl['cert'], tpl['key']), (meta['file'], meta['file']))
        self.assertTrue(tpl['chain-cert'].startswith('acme-ca-'))
        self.assertTrue(self.ctx.find('POST', r'/write/memory$'))
        self.assertEqual(self.deleted, [{'cert-name': self.prefix + '20250101-aaaa0000'},
                                        {'private-key': self.prefix + '20250101-aaaa0000'}])
        self.assertTrue(self.ctx.find('POST', r'/logoff$'))
        self.assertTrue(self.t.deploy(self.a, {'templates': 'tpl-www'}).startswith('unchanged'))

    def test_error_and_version(self):
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'templates': 'tpl-nope'})
        self.assertIn('Object specified does not exist', str(e.exception))
        self.assertTrue(self.ctx.find('POST', r'/logoff$'))
        self.assertIn('ACOS 5.2.1-P9', self.t.test())


# ---------------------------------------------------------------------------
class NutanixTest(unittest.TestCase):
    CID = '00061de0-6c4e-25a1-0000-00000000aa11'

    def setUp(self):
        self.task = ['RUNNING', 'SUCCEEDED']
        base = r'^https://pc\.test:9440/api/clustermgmt/v4\.3/config/clusters'
        self.ctx = FakeCtx([
            ('GET', base + r'$', (200, {'data': [
                {'extId': self.CID, 'name': 'prod', 'config': {'clusterFunction': ['AOS']}},
                {'extId': 'pc-1', 'name': 'pc', 'config': {'clusterFunction': ['PRISM_CENTRAL']}}
            ]})),
            ('GET', base + r'/%s/ssl-certificate$' % self.CID, (200, {
                'data': {'privateKeyAlgorithm': 'RSA_2048'}}, {'ETag': 'W/"etag-1"'})),
            ('PUT', base + r'/%s/ssl-certificate$' % self.CID, (202, {
                'data': {'extId': 'ZXJn:task-1', '$objectType': 'prism.v4.config.TaskReference'}})),
            ('GET', r'/api/prism/v4\.3/config/tasks/ZXJn%3Atask-1$',
             lambda c: (200, {'data': {'status': self.task.pop(0)}})),
        ])
        self.t = make('nutanix', {'host': 'pc.test', 'user': 'admin', 'password': 'pw',
                                  'cluster': 'prod'}, self.ctx)
        self.t._sleep = lambda s: None

    def test_replace_wait_noop(self):
        a = FakeBundle()
        a.key_type = 'ec-256'
        self.t.deploy(a, {})
        put = self.ctx.find('PUT', r'ssl-certificate$')[0]
        self.assertEqual(put['headers']['If-Match'], 'W/"etag-1"')
        self.assertTrue(re.match(r'^[0-9a-f-]{36}$', put['headers']['NTNX-Request-Id']))
        self.assertEqual(put['headers']['Authorization'],
                         'Basic ' + base64.b64encode(b'admin:pw').decode())
        b = body(put)
        self.assertEqual(b['privateKeyAlgorithm'], 'ECDSA_256')
        self.assertEqual(b64d(b['publicCertificate']), a.cert_pem)
        self.assertEqual(b64d(b['privateKey']), a.key_pem)
        self.assertEqual(b64d(b['caChain']), a.chain_pems[0])
        self.assertEqual(self.task, [])
        self.assertTrue(self.t.deploy(a, {}).startswith('unchanged'))

    def test_algorithm_catalog_failed_task(self):
        a = FakeBundle()
        with self.assertRaises(PluginError) as e:            # the size is not known
            self.t.deploy(a, {})
        self.assertFalse(e.exception.retry)
        a.key_type = 'rsa-3072'
        with self.assertRaises(PluginError) as e:
            self.t.deploy(a, {})
        self.assertIn('rsa-3072', str(e.exception))
        cat = self.t.catalog('clusters')
        self.assertEqual(cat['options'][0], [self.CID, 'prod (AOS)'])
        self.assertEqual(cat['sets'][self.CID], {'cluster': self.CID})
        self.task = ['FAILED']
        a.key_type = 'rsa-2048'
        with self.assertRaises(PluginError) as e:
            self.t.deploy(a, {'algorithm': 'RSA_2048'})
        self.assertIn('failed', str(e.exception))
        self.assertIn('RSA_2048', self.t.test())


# ---------------------------------------------------------------------------
class AzureAppServiceTest(unittest.TestCase):
    def setUp(self):
        self.a = FakeBundle()
        self.prefix = C.name_prefix(self.a, {})
        self.certs = {self.prefix + '20250101-aaaa0000': {},
                      self.prefix + '20260101-aaaa0001': {}, 'manual': {}}
        self.binds = {'app-www.azurewebsites.net': {'sslState': 'Disabled'},
                      'www.example.test': {'sslState': 'SniEnabled', 'thumbprint': 'OLD'},
                      'other.test': {'sslState': 'Disabled'}}
        rg = r'^https://management\.azure\.com/subscriptions/sub1/resourceGroups/rg1/' \
             r'providers/Microsoft\.Web'
        self.rg = rg

        def cert(call):
            name = call['path'].rsplit('/', 1)[1]
            if call['method'] == 'GET':
                if name not in self.certs:
                    return 404, {'error': {'code': 'ResourceNotFound', 'message': 'nope'}}
                return 200, {'name': name, 'properties': self.certs[name]}
            if call['method'] == 'DELETE':
                del self.certs[name]
                return 200, {}
            self.certs[name] = {'thumbprint': C.sha1_thumb(self.a)}
            return 200, {'name': name, 'properties': self.certs[name]}

        def bind(call):
            host = urllib.parse.unquote(call['path'].rsplit('/', 1)[1])
            self.binds[host] = body(call)['properties']
            return 200, {}
        self.ctx = FakeCtx([
            ('POST', r'^https://login\.microsoftonline\.com/tid/oauth2/v2\.0/token$',
             (200, {'access_token': 'ARM', 'expires_in': 3600})),
            ('GET', rg + r'/certificates\?api-version=2023-12-01$', lambda c: (200, {
                'value': [{'name': n} for n in self.certs]})),
            ('GET', rg + r'/certificates/[^/?]+\?api-version=2023-12-01$', cert),
            ('PUT', rg + r'/certificates/[^/?]+\?api-version=2023-12-01$', cert),
            ('DELETE', rg + r'/certificates/[^/?]+\?api-version=2023-12-01$', cert),
            ('GET', rg + r'/sites/app-www\?api-version=2023-12-01$', (200, {
                'location': 'West Europe', 'properties': {
                    'serverFarmId': '/subscriptions/sub1/resourceGroups/rg1/providers/'
                                    'Microsoft.Web/serverfarms/plan1'}})),
            ('GET', rg + r'/sites/app-www/hostNameBindings\?api-version', lambda c: (200, {
                'value': [{'name': 'app-www/' + h, 'properties': p}
                          for h, p in self.binds.items()]})),
            ('PUT', rg + r'/sites/app-www/hostNameBindings/[^/?]+\?api-version', bind),
            ('GET', rg + r'/sites/nope\?', (404, {'error': {'code': 'ResourceNotFound'}})),
        ])
        self.t = make('azure_appservice', {
            'subscription_id': 'sub1', 'resource_group': 'rg1', 'tenant_id': 'tid',
            'client_id': 'cid', 'client_secret': 'sec'}, self.ctx)

    def test_upload_bind_cleanup(self):
        a = self.a
        a.names = ['www.example.test', '*.example.test']
        self.t.deploy(a, {'site': 'app-www'})
        tok = urllib.parse.parse_qs(self.ctx.calls[0]['body'].decode())
        self.assertEqual(tok['scope'], ['https://management.azure.com/.default'])
        put = [c for c in self.ctx.find('PUT', r'/certificates/')][0]
        self.assertEqual(put['headers']['Authorization'], 'Bearer ARM')
        b = body(put)
        self.assertEqual(b['location'], 'West Europe')
        self.assertTrue(b['properties']['serverFarmId'].endswith('/serverfarms/plan1'))
        pfx = base64.b64decode(b['properties']['pfxBlob'])
        out = T.openssl('pkcs12', '-in', '-', '-nokeys', '-passin',
                        'pass:' + b['properties']['password'], data=pfx)
        self.assertIn(b'BEGIN CERTIFICATE', out)
        self.assertEqual(self.binds['www.example.test'],
                         {'sslState': 'SniEnabled', 'thumbprint': C.sha1_thumb(a)})
        self.assertEqual(self.binds['other.test'], {'sslState': 'Disabled'})
        self.assertNotIn('thumbprint', self.binds['app-www.azurewebsites.net'])
        self.assertEqual(sorted(self.certs), sorted(['manual', self.prefix + '20260101-aaaa0001',
                                                     put['path'].rsplit('/', 1)[1]]))
        self.assertTrue(self.t.deploy(a, {'site': 'app-www'}).startswith('unchanged'))

    def test_given_hostnames_and_errors(self):
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'site': 'app-www', 'hostnames': 'nothere.test'})
        self.assertIn('no hostname nothere.test', str(e.exception))
        with self.assertRaises(PluginError) as e:
            self.t.deploy(self.a, {'site': 'nope'})
        self.assertIn('no web app "nope"', str(e.exception))
        self.t.deploy(self.a, {'site': 'app-www', 'hostnames': 'other.test', 'force': True})
        self.assertEqual(self.binds['other.test']['sslState'], 'SniEnabled')


# ---------------------------------------------------------------------------
class RuntimeCookiesTest(unittest.TestCase):
    """Two Set-Cookie headers in one answer: both kept (Avi's session and CSRF token)."""
    def test_joined(self):
        import email.message
        from acmelib.certs.runtime import header_dict
        m = email.message.Message()
        m['Content-Type'] = 'application/json'
        m['Set-Cookie'] = 'csrftoken=A; Path=/'
        m['Set-Cookie'] = 'sessionid=B; Path=/; HttpOnly'
        d = header_dict(m)
        self.assertEqual(d['Content-Type'], 'application/json')
        self.assertEqual(d['Set-Cookie'], 'csrftoken=A; Path=/, sessionid=B; Path=/; HttpOnly')
        self.assertEqual(header_dict(None), {})


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
            for f in d['fields'] + d['deploy_fields']:
                self.assertIn(f['type'], FIELD_TYPES, (k, f['key']))
                if f['key'] in ('token', 'password', 'api_key', 'client_secret'):
                    self.assertEqual(f['type'], 'secret', (k, f['key']))
            for a in d['actions']:
                self.assertFalse(a.get('changes', True), (k, a['key']))   # they only read
            src = read(kinds[k]._module_file)
            self.assertIn('https://', src.split('"""')[1], '%s cites no source' % k)

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
            d = reg.get('target', k).describe()
            self.assertIn(d['title'].split(' (')[0].lower(), readme.lower(), k)
            missing += ['%s: %s' % (k, w) for w in words_of(d) if w not in sources]
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main()
