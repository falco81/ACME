#!/usr/bin/env python3
"""The targets of the firewalls and ADCs added from the vendor guides of 2026-11, without
a network:

    python3 test/test_targets_fw_adc.py

  barracuda_cgf   Barracuda CloudGen Firewall / Control Center 10.0 - 10.5: a Certificate
                  Store entry imported in place (REST /rest/config/v1/box/store/... and
                  /rest/cc/v1/config/.../store/...); 9.0 (no store endpoints) said in words
  infoblox        Infoblox NIOS 8.6 - 9.1: WAPI fileop uploadinit, the multipart upload,
                  uploadcertificate ADMIN / CAPTIVE_PORTAL per Grid member
  fortimanager    FortiManager / FortiAnalyzer 7.2.2 - 7.6: JSON-RPC add of a local
                  certificate (key encrypted), the CA, admin setting admin_server_cert

Each fake answers as the vendor's documents say; the calls made (method, path, body) are
asserted. The fake Context and certificates are those of test_targets.py.
"""
import base64
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402

GUIDES = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


class Bundle(FakeBundle):
    """FakeBundle with the encrypted PKCS#8 key FortiManager is given."""
    def as_format(self, fmt, password=None, alias=None):
        if fmt == 'key-pem-enc':
            return subprocess.run(['openssl', 'pkcs8', '-topk8', '-v2', 'aes-256-cbc',
                                   '-in', self.key_file, '-passout', 'pass:%s' % password],
                                  capture_output=True, check=True).stdout
        if fmt == 'key-traditional':
            return self.key_pem.encode()
        return FakeBundle.as_format(self, fmt, password, alias)


def make(kind, ctx, **cfg):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', kind, '')
    return cls(cfg, ctx)


def body_of(call):
    return json.loads(call['body'])


class RegisteredTest(unittest.TestCase):
    def test_kinds_and_guides(self):
        reg = Registry(extra_dirs=[]).reload()
        for kind, vendor in (('barracuda_cgf', 'Barracuda'), ('infoblox', 'Infoblox'),
                             ('fortimanager', 'Fortinet')):
            vers = reg.versions_of('target', kind)
            self.assertEqual(sorted(vers), [''], 'one module: the calls are the same in '
                                                 'every documented version')
            cls = vers['']
            self.assertEqual(cls.vendor, vendor)
            self.assertTrue(cls.description)
            for suffix in ('.md', '.cs.md'):
                with open(os.path.join(GUIDES, kind + suffix), encoding='utf-8') as f:
                    md = f.read()
                self.assertTrue(md.startswith('# '), kind + suffix)
                self.assertIn('```', md)
                self.assertIn('|', md)
        d = [x for x in reg.describe()['target'] if x['kind'] == 'infoblox'][0]
        self.assertEqual(d['default_version'], '')


# ---------------------------------------------------------------------------------------
BOX = '/rest/config/v1/box/store/certificates'


def fp_colons(b):
    fp = C.fp_of(b).upper()
    return ':'.join(fp[i:i + 2] for i in range(0, len(fp), 2))


class CgfTest(unittest.TestCase):
    def routes(self, b, there=True, after=None, store=BOX, store_ok=True):
        """A store with the entry vpn-portal (an older certificate) or without it."""
        state = {'imported': False}

        def entry(call):
            if state['imported']:
                return 200, after if after is not None else {
                    'name': 'vpn-portal', 'subCertificates': [
                        {'subject': {'commonName': 'www.example.test'},
                         'fingerprint': fp_colons(b)}]}
            if there:
                return 200, {'name': 'vpn-portal', 'subCertificates': [
                    {'fingerprint': 'AA:BB'}]}
            return 404, {'message': 'not found'}

        def imp(call):
            state['imported'] = True
            return 200, {}
        return [
            ('GET', store + r'/vpn-portal$', entry),
            ('GET', store + r'(\?expand=true)?$', (200, []) if store_ok else (404, {})),
            ('POST', store + r'$', (200, {})),
            ('PUT', store + r'/vpn-portal$', imp),
        ]

    def test_box_entry_replaced_in_place(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes(b))
        got = make('barracuda_cgf', ctx, host='cgf', token='TKN').deploy(
            b, {'entry': 'vpn-portal'})
        self.assertIn('imported into vpn-portal', got)
        self.assertTrue(all(c['headers']['X-API-Token'] == 'TKN' for c in ctx.calls))
        self.assertEqual(ctx.calls[0]['url'], 'https://cgf:8443' + BOX + '/vpn-portal')
        self.assertFalse(ctx.find('POST', ''), 'the entry is there: not made again')
        put = ctx.find('PUT', 'vpn-portal')
        self.assertEqual(len(put), 1)
        body = body_of(put[0])
        self.assertEqual(body['action'], 'import')
        self.assertEqual(body['certificates'], b.fullchain_pem, 'the leaf, then the chain')
        self.assertEqual(body['key'], b.key_pem)
        self.assertTrue(body['comment'].startswith('acme '))
        # again: the same certificate is there - nothing sent
        ctx2 = FakeCtx(self.routes(b, after=None))
        ctx2.kv = ctx.kv
        t = make('barracuda_cgf', ctx2, host='cgf', token='TKN')
        ctx2.routes[0] = ('GET', BOX + r'/vpn-portal$', (200, {'subCertificates': [
            {'fingerprint': C.fp_of(b)}]}))
        self.assertIn('unchanged', t.deploy(b, {'entry': 'vpn-portal'}))
        self.assertFalse(ctx2.find('PUT', ''))

    def test_entry_made_first(self):
        b = FakeBundle()
        b.family = 'ec'
        ctx = FakeCtx(self.routes(b, there=False))
        make('barracuda_cgf', ctx, host='cgf', token='TKN').deploy(b, {'entry': 'vpn-portal'})
        post = body_of(ctx.find('POST', BOX + '$')[0])
        self.assertEqual(post['name'], 'vpn-portal')
        self.assertEqual(post['key'], {'cryptosystem': 'EC', 'curve': 'prime256v1'},
                         'the placeholder of the kind of the key')
        b.family = 'rsa'
        ctx = FakeCtx(self.routes(b, there=False))
        make('barracuda_cgf', ctx, host='cgf', token='TKN').deploy(b, {'entry': 'vpn-portal'})
        self.assertEqual(body_of(ctx.find('POST', BOX + '$')[0])['key'],
                         {'cryptosystem': 'RSA', 'size': 2048})
        self.assertEqual(post['certificate']['subject']['commonName'], 'www.example.test')
        methods = [c['method'] for c in ctx.calls]
        self.assertLess(methods.index('POST'), methods.index('PUT'), 'made, then imported')

    def test_not_made_when_asked_not_to(self):
        ctx = FakeCtx(self.routes(FakeBundle(), there=False))
        with self.assertRaises(PluginError) as e:
            make('barracuda_cgf', ctx, host='cgf', token='T').deploy(
                FakeBundle(), {'entry': 'vpn-portal', 'create': False})
        self.assertFalse(e.exception.retry)
        self.assertEqual({c['method'] for c in ctx.calls}, {'GET'})

    def test_90_has_no_store(self):
        ctx = FakeCtx(self.routes(FakeBundle(), there=False, store_ok=False))
        with self.assertRaises(PluginError) as e:
            make('barracuda_cgf', ctx, host='cgf', token='T').deploy(
                FakeBundle(), {'entry': 'vpn-portal'})
        self.assertIn('10.0 or later', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertEqual({c['method'] for c in ctx.calls}, {'GET'}, 'nothing changed')
        with self.assertRaises(PluginError) as e:
            make('barracuda_cgf', FakeCtx(self.routes(FakeBundle(), store_ok=False)),
                 host='cgf', token='T').test()
        self.assertIn('9.0', str(e.exception))

    def test_control_center_cluster_with_a_password(self):
        b = FakeBundle()
        store = '/rest/cc/v1/config/ranges/1/clusters/prague/store/certificates'
        ctx = FakeCtx(self.routes(b, store=store))
        make('barracuda_cgf', ctx, host='cc', auth='password', user='svc-cc-cert', password='pw',
             store='cluster', range='1', cluster='prague').deploy(b, {'entry': 'vpn-portal'})
        self.assertEqual(ctx.find('PUT', '')[0]['path'], store + '/vpn-portal')
        self.assertEqual(ctx.calls[0]['headers']['Authorization'],
                         'Basic ' + base64.b64encode(b'svc-cc-cert:pw').decode())
        for where, path in (('global', '/rest/cc/v1/config/global/store/certificates'),
                            ('range', '/rest/cc/v1/config/ranges/1/store/certificates')):
            t = make('barracuda_cgf', FakeCtx(), host='cc', token='T', store=where, range='1')
            self.assertEqual(t.store_path(), path)
        with self.assertRaises(PluginError):
            make('barracuda_cgf', FakeCtx(), host='cc', token='T', store='cluster',
                 range='1').store_path()

    def test_import_not_taken_is_an_error(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes(b, after={'subCertificates': [{'fingerprint': 'AA:BB'}]}))
        with self.assertRaises(PluginError) as e:
            make('barracuda_cgf', ctx, host='cgf', token='T').deploy(b, {'entry': 'vpn-portal'})
        self.assertIn('does not hold the new certificate', str(e.exception))
        self.assertFalse(ctx.kv, 'not remembered')

    def test_bad_entry_name_and_places(self):
        t = make('barracuda_cgf', FakeCtx(), host='cgf', token='T')
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {'entry': 'a b/c'})
        self.assertEqual(t.served_places({'verify': 'vpn.example.test:443\nfw:8443'}),
                         [('vpn.example.test', 443), ('fw', 8443)])
        self.assertIn('signed in to cgf', make('barracuda_cgf', FakeCtx(
            self.routes(FakeBundle())), host='cgf', token='T').test())


# ---------------------------------------------------------------------------------------
WAPI = '/wapi/v2.11/fileop'


class InfobloxTest(unittest.TestCase):
    def routes(self, inits=None):
        n = {'i': 0}

        def init(call):
            n['i'] += 1
            return 200, {'token': 'TOK%d' % n['i'],
                         'url': 'https://10.0.0.5/http_direct_file_io/req_id-UPLOAD-%d/f.pem'
                                % n['i']}
        return [
            ('GET', r'/wapi/v2\.11/grid$', (200, [{'_ref': 'grid/b25lLmNsdXN0ZXIkMA:Infoblox'}])),
            ('POST', r'fileop\?_function=uploadinit$', inits or init),
            ('POST', r'/http_direct_file_io/', (200, '')),
            ('POST', r'fileop\?_function=uploadcertificate$', (200, {})),
        ]

    def test_members_in_order(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes())
        t = make('infoblox', ctx, host='gm.example.test', user='svc-cert', password='pw')
        got = t.deploy(b, {'members': 'gmc.example.test\ngm.example.test'})
        self.assertEqual(got, 'ADMIN certificate of gmc.example.test, gm.example.test')
        auth = 'Basic ' + base64.b64encode(b'svc-cert:pw').decode()
        self.assertTrue(all(c['headers']['Authorization'] == auth for c in ctx.calls))
        self.assertEqual([(c['method'], c['path']) for c in ctx.calls], [
            ('POST', WAPI), ('POST', '/http_direct_file_io/req_id-UPLOAD-1/f.pem'),
            ('POST', WAPI), ('POST', WAPI), ('POST', '/http_direct_file_io/req_id-UPLOAD-2/f.pem'),
            ('POST', WAPI)])
        self.assertTrue(ctx.calls[1]['url'].startswith('https://gm.example.test/'),
                        'the upload goes to the target\'s address, not the 10.0.0.5 it named')
        self.assertTrue(body_of(ctx.calls[0])['filename'].endswith('.pem'))
        up = ctx.calls[1]['body']
        self.assertIn(b'name="file"', up)
        pem = b.fullchain_pem.encode()
        self.assertIn(pem, up)
        self.assertIn(b.key_pem.encode(), up)
        self.assertLess(up.index(pem), up.index(b.key_pem.encode()), 'certificate, chain, key')
        self.assertEqual(body_of(ctx.calls[2]), {'certificate_usage': 'ADMIN',
                                                 'member': 'gmc.example.test', 'token': 'TOK1'})
        self.assertEqual(body_of(ctx.calls[5])['member'], 'gm.example.test')
        self.assertEqual(body_of(ctx.calls[5])['token'], 'TOK2')
        self.assertEqual(t.served_places({'members': 'a\nb'}), [('a', 443), ('b', 443)])
        self.assertEqual(t.served_wait, (10, 6))
        # again: nothing
        ctx2 = FakeCtx(self.routes())
        ctx2.kv = ctx.kv
        self.assertIn('unchanged', make('infoblox', ctx2, host='gm.example.test', user='u',
                                        password='pw').deploy(
            b, {'members': 'gmc.example.test\ngm.example.test'}))
        self.assertFalse(ctx2.calls)

    def test_captive_portal(self):
        ctx = FakeCtx(self.routes())
        t = make('infoblox', ctx, host='gm', user='u', password='p', wapi_version='v2.13.7')
        t.deploy(FakeBundle(), {'members': 'm1', 'usage': 'CAPTIVE_PORTAL'})
        self.assertEqual(ctx.calls[0]['path'], '/wapi/v2.13.7/fileop')
        self.assertEqual(body_of(ctx.calls[2])['certificate_usage'], 'CAPTIVE_PORTAL')
        self.assertEqual(t.served_places({'members': 'm1', 'usage': 'CAPTIVE_PORTAL'}), [])
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {'members': 'm1', 'usage': 'SFNT_CLIENT_CERT'})
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {'members': ''})

    def test_grid_master_restarting_waited_for(self):
        n = {'i': 0}

        def init(call):
            n['i'] += 1
            if n['i'] == 2:
                raise OSError('connection refused')
            return 200, {'token': 'T%d' % n['i'], 'url': 'https://gm/http_direct_file_io/x'}
        ctx = FakeCtx(self.routes(inits=init))
        t = make('infoblox', ctx, host='gm', user='u', password='p')
        slept = []
        t._sleep = slept.append
        t.deploy(FakeBundle(), {'members': 'gm\nm2'})
        self.assertEqual(slept, [10])
        self.assertEqual(body_of(ctx.find('POST', 'uploadcertificate')[1])['token'], 'T3')

    def test_refused_upload_is_an_error(self):
        routes = self.routes()
        routes[3] = ('POST', r'uploadcertificate', (400, {'Error': 'AdmConProtoError: x',
                                                          'text': 'bad certificate'}))
        ctx = FakeCtx(routes)
        with self.assertRaises(PluginError) as e:
            make('infoblox', ctx, host='gm', user='u', password='p').deploy(
                FakeBundle(), {'members': 'gm'})
        self.assertFalse(e.exception.retry)
        self.assertFalse(ctx.kv)

    def test_try(self):
        got = make('infoblox', FakeCtx(self.routes()), host='gm', user='u', password='p').test()
        self.assertIn('WAPI 2.11', got)
        self.assertIn('Infoblox', got)


# ---------------------------------------------------------------------------------------
class FortiManagerTest(unittest.TestCase):
    def routes(self, there=(), gui='server.crt', fail=None):
        """FortiManager answering JSON-RPC: local certificates `there`."""
        state = {'certs': list(there), 'gui': gui}

        def rpc(call):
            r = body_of(call)
            p = r['params'][0]
            m, url = r['method'], p['url']
            if fail and fail[0] == m and url.startswith(fail[1]):
                return 200, {'id': r['id'], 'result': [
                    {'status': {'code': fail[2], 'message': 'No permission for the resource'},
                     'url': url}]}
            ok = {'status': {'code': 0, 'message': 'OK'}, 'url': url}
            if url == '/cli/global/system/admin/setting':
                if m == 'set':
                    state['gui'] = p['data']['admin_server_cert']
                    return 200, {'id': r['id'], 'result': [ok]}
                return 200, {'id': r['id'], 'result': [dict(ok, data={
                    'admin_server_cert': state['gui'], 'https_port': 443})]}
            if url == '/cli/global/system/certificate/local':
                if m == 'add':
                    state['certs'].append(p['data']['name'])
                    return 200, {'id': r['id'], 'result': [ok]}
                return 200, {'id': r['id'], 'result': [dict(ok, data=[
                    {'name': n} for n in state['certs']])]}
            if url.startswith('/cli/global/system/certificate/local/'):
                n = url.rsplit('/', 1)[1]
                if m == 'delete':
                    state['certs'].remove(n)
                    return 200, {'id': r['id'], 'result': [ok]}
                if n in state['certs']:
                    return 200, {'id': r['id'], 'result': [dict(ok, data={'name': n})]}
                return 200, {'id': r['id'], 'result': [
                    {'status': {'code': -3, 'message': 'Object does not exist'}, 'url': url}]}
            if url == '/cli/global/system/certificate/ca':
                return 200, {'id': r['id'], 'result': [ok]}
            raise AssertionError(url)
        return [('POST', r'/jsonrpc$', rpc)], state

    def calls(self, ctx):
        return [(body_of(c)['method'], body_of(c)['params'][0]['url']) for c in ctx.calls]

    def test_deploy(self):
        b = Bundle()
        prefix = C.name_prefix(b, {}, maxlen=35, serial_len=6)
        name = C.object_name(b, {}, maxlen=35, serial_len=6)
        old = prefix + '20250101-aaaaaa'
        older = prefix + '20240101-bbbbbb'
        routes, state = self.routes(there=['Fortinet_Local', older, old], gui=old)
        ctx = FakeCtx(routes)
        got = make('fortimanager', ctx, host='fmg', token='TKN').deploy(b, {'keep': 1})
        self.assertEqual(got, 'added %s, GUI' % name)
        self.assertTrue(all(c['headers']['Authorization'] == 'Bearer TKN' for c in ctx.calls))
        self.assertTrue(all(c['path'] == '/jsonrpc' for c in ctx.calls))
        self.assertEqual(self.calls(ctx), [
            ('get', '/cli/global/system/certificate/local/' + name),
            ('add', '/cli/global/system/certificate/local'),
            ('add', '/cli/global/system/certificate/ca'),
            ('set', '/cli/global/system/admin/setting'),
            ('get', '/cli/global/system/certificate/local'),
            ('delete', '/cli/global/system/certificate/local/' + older)])
        add = body_of(ctx.calls[1])['params'][0]['data']
        self.assertEqual(sorted(add), ['certificate', 'comment', 'name', 'password',
                                       'private-key'])
        self.assertEqual(add['name'], name)
        self.assertLessEqual(len(name), 35)
        self.assertEqual(add['certificate'], b.cert_pem)
        self.assertIn('BEGIN ENCRYPTED PRIVATE KEY', add['private-key'])
        # the key opens with the password sent beside it
        out = subprocess.run(['openssl', 'pkey', '-passin', 'pass:' + add['password']],
                             input=add['private-key'].encode(), capture_output=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        ca = body_of(ctx.calls[2])['params'][0]['data']
        self.assertEqual(ca, {'name': 'acme-ca-%s' % C.chain_id(b.chain_pems[0]),
                              'ca': b.chain_pems[0]})
        self.assertEqual(body_of(ctx.calls[3])['params'][0]['data'],
                         {'admin_server_cert': name})
        self.assertEqual(state['certs'], ['Fortinet_Local', old, name], 'keep 1: the newest '
                                                                         'older one stays')
        self.assertEqual(len({body_of(c)['id'] for c in ctx.calls}), len(ctx.calls))

    def test_gui_off_keeps_the_one_it_uses(self):
        b = Bundle()
        prefix = C.name_prefix(b, {}, maxlen=35, serial_len=6)
        old = prefix + '20250101-aaaaaa'
        routes, state = self.routes(there=[old], gui=old)
        ctx = FakeCtx(routes)
        t = make('fortimanager', ctx, host='fmg', token='T')
        t.deploy(b, {'admin_gui': False, 'import_chain': False, 'keep': 0})
        self.assertNotIn('set', [m for m, _u in self.calls(ctx)])
        self.assertIn(old, state['certs'], 'the GUI still uses it')
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and 'GUI still' in w])
        self.assertEqual(t.served_places({'admin_gui': False}), [])
        self.assertEqual(t.served_places({}), [('fmg', 443)])

    def test_there_already_and_unchanged(self):
        b = Bundle()
        name = C.object_name(b, {}, maxlen=35, serial_len=6)
        routes, state = self.routes(there=[name])
        ctx = FakeCtx(routes)
        make('fortimanager', ctx, host='fmg', token='T').deploy(b, {'import_chain': False})
        self.assertNotIn(('add', '/cli/global/system/certificate/local'), self.calls(ctx))
        ctx2 = FakeCtx(routes)
        ctx2.kv = ctx.kv
        self.assertIn('unchanged', make('fortimanager', ctx2, host='fmg', token='T').deploy(
            b, {'import_chain': False}))
        self.assertEqual([m for m, _u in self.calls(ctx2)], ['get'])

    def test_no_permission(self):
        routes, state = self.routes(fail=('add', '/cli/global/system/certificate/local', -11))
        ctx = FakeCtx(routes)
        with self.assertRaises(PluginError) as e:
            make('fortimanager', ctx, host='fmg', token='T').deploy(Bundle(), {})
        self.assertIn('No permission', str(e.exception))
        self.assertIn('-11', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertNotIn('set', [m for m, _u in self.calls(ctx)])

    def test_try(self):
        routes, state = self.routes()
        self.assertIn('the GUI uses server.crt', make('fortimanager', FakeCtx(routes),
                                                      host='fmg', token='T').test())


if __name__ == '__main__':
    unittest.main(verbosity=1)
