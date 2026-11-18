#!/usr/bin/env python3
"""The FortiGate target's "Replace an existing certificate in place" (1.0.128), against a
fake FortiGate - a real HTTP server on 127.0.0.1 (a port the system gives) that keeps its
local and CA certificates as FortiOS does and answers its REST API.

    python3 test/test_fortigate_replace.py

- Find on the device: the local certificates listed (name, CN, expiry, issuer, uses), the
  Fortinet factory ones left out, the one with the certificate's names suggested; a token
  refused says why and that the name can be typed.
- The deployment: PUT cmdb vpn.certificate/local/<name> with private-key (encrypted, with
  its password) and certificate, in every version of the module; the name and its uses
  kept, nothing imported under a new name, nothing re-pointed unless listed.
- A FortiOS that refuses: a clear error, the old certificate untouched, never deleted. An
  encrypted key refused: the plain key tried once more.
- A name not there (typed by hand) fails before anything changes; a factory one is refused.
- Cleanup of acme's older certificates spares the replaced one.
- A CA certificate there already (FortiOS 500, error -328) is said once, quietly.
- What happens (the recorded dry run) says what is replaced and that its uses stay.
"""
import json
import os
import re
import sys
import threading
import unittest
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, openssl, read  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import fortigate as FG  # noqa: E402

PEMS = {}


def setUpModule():
    T.setUpModule()
    j = lambda n: os.path.join(T.TMP, n)  # noqa: E731
    # the certificates the FortiGate holds before: an RSA one of the same names (to be
    # replaced), one of other names, the factory one
    for leaf, cn, alg in (('old', 'www.example.test', 'rsa:2048'),
                          ('other', 'other.example.test', 'rsa:2048'),
                          ('factory', 'FGT60F0000000000', 'rsa:2048')):
        openssl('req', '-newkey', alg, '-nodes', '-keyout', j(leaf + '.key'),
                '-out', j(leaf + '.csr'), '-subj', '/CN=' + cn)
        with open(j('ext-' + leaf), 'w') as fh:
            fh.write('subjectAltName=DNS:%s\n' % cn)
        openssl('x509', '-req', '-in', j(leaf + '.csr'), '-CA', j('ca.crt'), '-CAkey',
                j('ca.key'), '-CAcreateserial', '-days', '20', '-out', j(leaf + '.crt'),
                '-extfile', j('ext-' + leaf))
        PEMS[leaf] = read(j(leaf + '.crt'))


def tearDownModule():
    T.tearDownModule()


class Bundle(FakeBundle):
    """The test certificate, its key also as encrypted PKCS#8 (as the real Bundle)."""
    key_type = 'ec-256'

    def as_format(self, fmt, password=None, alias=None):
        if fmt == 'key-pem-enc':
            return openssl('pkcs8', '-topk8', '-v2', 'aes-256-cbc', '-passout',
                           'pass:%s' % password, data=self.key_pem.encode())
        return FakeBundle.as_format(self, fmt, password, alias)


def der(pem):
    return C.pem_to_der(pem)


# ---------------------------------------------------------------------------
class FakeFortiGate(object):
    """A FortiGate's REST API as acme uses it, its certificates kept."""

    def __init__(self, version='v7.4.5'):
        self.version = version
        self.local = {}
        self.cas = []
        self.calls = []
        self.refuse_put = None          # (status, error) for every PUT of a local cert
        self.refuse_encrypted = False   # an encrypted private-key refused (-23)
        self.refuse_list = None         # the listing refused with this status
        self.puts = {}                  # other PUTs: path -> [bodies]
        self.lock = threading.Lock()
        fg = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self):
                n = int(self.headers.get('Content-Length') or 0)
                raw = self.rfile.read(n) if n else b''
                body = json.loads(raw.decode()) if raw[:1] == b'{' else None
                u = urllib.parse.urlsplit(self.path)
                q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
                with fg.lock:
                    fg.calls.append({'method': self.command, 'path': u.path, 'query': q,
                                     'body': body,
                                     'auth': self.headers.get('Authorization')})
                    st, out = fg.answer(self.command, urllib.parse.unquote(u.path), q, body)
                data = json.dumps(out).encode()
                self.send_response(st)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            do_GET = do_PUT = do_POST = do_DELETE = _go

        # port 0: one the system gives (never 8092 / 8443)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def add(self, name, pem, source='user', q_ref=0, rng='global'):
        self.local[name] = {'name': name, 'source': source, 'range': rng, 'certificate': pem,
                            'private-key': 'ENC xxxx', 'password': 'ENC xxxx', 'q_ref': q_ref}

    @staticmethod
    def err(status, code):
        return status, {'http_method': '?', 'status': 'error', 'http_status': status,
                        'error': code}

    def answer(self, m, path, q, body):
        ok = {'http_method': m, 'status': 'success', 'http_status': 200}
        if path == '/api/v2/monitor/system/status':
            return 200, dict(ok, version=self.version, serial='FGT60F', vdom='root',
                             results={'hostname': 'fw1', 'model_name': 'FortiGate'})
        lp = '/api/v2/cmdb/vpn.certificate/local'
        if path == lp and m == 'GET':
            if self.refuse_list:
                return self.err(self.refuse_list, -37)
            rows = sorted(self.local.values(), key=lambda r: r['name'])
            if q.get('format') == 'name':
                return 200, dict(ok, results=[{'name': r['name']} for r in rows])
            meta = q.get('with_meta') == '1'
            return 200, dict(ok, results=[{k: v for k, v in r.items()
                                           if meta or k != 'q_ref'} for r in rows])
        if path.startswith(lp + '/'):
            name = path[len(lp) + 1:]
            row = self.local.get(name)
            if m == 'GET':
                if not row:
                    return self.err(404, -3)
                return 200, dict(ok, results=[{k: v for k, v in row.items()
                                               if q.get('with_meta') == '1' or k != 'q_ref'}])
            if m == 'PUT':
                if not row:
                    return self.err(404, -3)
                if self.refuse_put:
                    return self.err(*self.refuse_put)
                key = (body or {}).get('private-key', '')
                if self.refuse_encrypted and 'ENCRYPTED' in key:
                    return self.err(500, -23)
                if 'ENCRYPTED' in key and not (body or {}).get('password'):
                    return self.err(500, -23)
                if 'PRIVATE KEY' not in key or 'BEGIN CERTIFICATE' not in \
                        (body or {}).get('certificate', ''):
                    return self.err(500, -651)
                row.update(certificate=body['certificate'], **{'private-key': 'ENC new'})
                return 200, dict(ok, mkey=name)
            if m == 'DELETE':
                if not row:
                    return self.err(404, -3)
                if row.get('q_ref'):
                    return self.err(500, -23)
                del self.local[name]
                return 200, ok
        if path == '/api/v2/monitor/vpn-certificate/local/import' and m == 'POST':
            name = body['certname']
            if name in self.local:
                return self.err(500, -5)
            self.add(name, '(imported)', rng=body.get('scope', 'global'))
            return 200, dict(ok, results={'mkey': name})
        if path == '/api/v2/monitor/vpn-certificate/ca/import' and m == 'POST':
            import base64
            pem = base64.b64decode(body['file_content']).decode()
            if der(pem) in [der(c) for c in self.cas]:
                return self.err(500, -328)
            self.cas.append(pem)
            return 200, dict(ok, results={'mkey': 'CA_Cert_%d' % len(self.cas)})
        if path == '/api/v2/cmdb/vpn.certificate/ca' and m == 'GET':
            return 200, dict(ok, results=[{'name': 'CA_Cert_%d' % (i + 1), 'ca': c}
                                          for i, c in enumerate(self.cas)])
        if m == 'PUT':
            self.puts.setdefault(path, []).append(body)
            return 200, ok
        if m == 'GET' and path.startswith('/api/v2/cmdb/firewall/'):
            return 200, dict(ok, results=[{'name': path.rsplit('/', 1)[-1]}])
        return self.err(404, -3)

    def find(self, method, rx):
        return [c for c in self.calls if c['method'] == method and re.search(rx, c['path'])]


class HttpCtx(FakeCtx):
    """test_targets' Context, its HTTP sent for real (to the fake FortiGate)."""
    def http(self, method, url, body=None, headers=None, timeout=30, verify=True, ca_pem=None,
             client_cert=None, proxy=True):
        self.calls.append({'method': method, 'url': url, 'body': body})
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers or {}))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()


def make(fg, version='', **cfg):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', 'fortigate', version)
    assert cls.module_version == version
    ctx = HttpCtx([])
    conf = dict({'host': 'http://127.0.0.1:%d' % fg.port, 'token': 'TKN-secret-0001',
                 'vdom': 'root'}, **cfg)
    return cls(conf, ctx), ctx


def said(ctx):
    return [w for _l, w in ctx.steps]


REPLACE = {'mode': 'replace', 'replace_name': 'web-cert'}


class Base(unittest.TestCase):
    version = 'v7.4.5'

    def setUp(self):
        self.fg = FakeFortiGate(self.version)
        self.fg.add('Fortinet_Factory', PEMS['factory'], source='factory', q_ref=4)
        self.fg.add('Fortinet_SSL', PEMS['factory'], source='factory', q_ref=2)
        self.fg.add('web-cert', PEMS['old'], q_ref=7)
        self.fg.add('other', PEMS['other'], q_ref=0, rng='vdom')

    def tearDown(self):
        self.fg.close()


# ---------------------------------------------------------------------------
class DiscoveryTest(Base):
    def test_listing(self):
        t, ctx = make(self.fg)
        t.hint_names = ['www.example.test', 'example.test']
        got = t.catalog('local_certs')
        names = [o[0] for o in got['options']]
        self.assertEqual(names, ['web-cert', 'other'], 'the suggested one first, factory out')
        self.assertEqual(got['pick'], 'web-cert')
        words = dict(got['options'])
        self.assertIn('CN www.example.test', words['web-cert'])
        self.assertIn('Test CA', words['web-cert'])                 # the issuer
        self.assertIn('7×', words['web-cert'])                      # its uses
        self.assertTrue(words['web-cert'].startswith('★ '))
        self.assertRegex(words['web-cert'], r'→ \d{4}-\d\d-\d\d')   # its expiry
        self.assertIn('vdom', words['other'])
        self.assertIn('2 Fortinet factory ones left out', got['said'])
        call = self.fg.find('GET', r'/cmdb/vpn\.certificate/local$')[0]
        self.assertEqual((call['query'].get('with_meta'), call['query'].get('vdom')),
                         ('1', 'root'))
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'], 'read-only')

    def test_no_names_no_pick(self):
        t, ctx = make(self.fg)
        got = t.catalog('local_certs')
        self.assertEqual(got['pick'], '')
        self.assertEqual(sorted(o[0] for o in got['options']), ['other', 'web-cert'])

    def test_refused_says_why_and_to_type_it(self):
        self.fg.refuse_list = 403
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.catalog('local_certs')
        self.assertIn('the token may not read the certificates (403)', str(e.exception))
        self.assertIn('type the name of the certificate instead', str(e.exception))

    def test_unreachable_says_it(self):
        t, ctx = make(self.fg)
        self.fg.close()
        self.fg = FakeFortiGate()           # for tearDown
        with self.assertRaises(PluginError) as e:
            t.catalog('local_certs')
        self.assertIn('type the name of the certificate instead', str(e.exception))

    def test_the_field(self):
        f = {x['key']: x for x in FG.FortiGateTarget.deploy_fields}
        self.assertEqual(f['mode']['default'], 'new')
        self.assertEqual(f['replace_name']['type'], 'catalog')
        self.assertEqual(f['replace_name']['catalog'], 'local_certs')
        self.assertEqual(f['replace_name']['show_if'], {'mode': ['replace']})
        self.assertEqual(f['replace_name']['load_label'], 'Find on the device')
        self.assertFalse(f['replace_name'].get('autoload', True))


# ---------------------------------------------------------------------------
class ReplaceTest(Base):
    def deploy(self, version='', fos=None, **opts):
        if fos:
            self.fg.version = fos
        t, ctx = make(self.fg, version)
        b = Bundle()
        got = t.deploy(b, dict(REPLACE, **opts))
        return t, ctx, b, got

    def check_replaced(self, b):
        row = self.fg.local['web-cert']
        self.assertEqual(der(row['certificate']), der(b.cert_pem))
        self.assertEqual(row['private-key'], 'ENC new')
        self.assertEqual(row['q_ref'], 7, 'its uses kept')
        put = self.fg.find('PUT', r'/vpn\.certificate/local/web-cert$')
        self.assertEqual(len(put), 1)
        body = put[0]['body']
        self.assertEqual(sorted(body), ['certificate', 'password', 'private-key'])
        self.assertIn('BEGIN ENCRYPTED PRIVATE KEY', body['private-key'])
        self.assertTrue(body['password'])
        self.assertEqual(put[0]['query'].get('vdom'), 'root')
        self.assertFalse(self.fg.find('POST', r'/local/import'), 'nothing imported anew')
        self.assertFalse([n for n in self.fg.local if n.startswith('acme-')])

    def test_every_version(self):
        for ver, fos in (('', 'v7.4.5'), ('6.0', 'v6.4.15'), ('7.0', 'v7.2.10'),
                         ('7.4.2', 'v7.6.4'), ('7.4.2', 'v8.0.0')):
            self.tearDown()
            self.setUp()
            t, ctx, b, got = self.deploy(ver, fos)
            self.check_replaced(b)
            self.assertIn('web-cert replaced in place', got)
            self.assertFalse(self.fg.puts, 'nothing re-pointed: %s' % self.fg.puts)
            words = said(ctx)
            self.assertTrue(any('replacing the certificate web-cert in place: the same name, '
                                'everything that uses it keeps using it' in w for w in words))
            self.assertTrue(any('used 7 times' in w for w in words), words)
            self.assertTrue(any('key type changes from RSA to EC' in w for w in words), words)
            self.assertTrue(all(c['auth'] == 'Bearer TKN-secret-0001' for c in self.fg.calls))
            self.assertFalse([w for w in words if 'TKN-secret' in w or 'PRIVATE KEY' in w])

    def test_version_refused_before_anything(self):
        self.fg.version = 'v6.4.15'
        t, ctx = make(self.fg, '7.4.2')
        with self.assertRaises(PluginError):
            t.deploy(Bundle(), dict(REPLACE))
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(PEMS['old']))

    def test_listed_uses_point_at_the_same_name(self):
        t, ctx, b, got = self.deploy('7.4.2', admin=True, sslvpn=True, vips='web')
        self.check_replaced(b)
        self.assertEqual(self.fg.puts['/api/v2/cmdb/system/global'],
                         [{'admin-server-cert': 'web-cert'}])
        self.assertEqual(self.fg.puts['/api/v2/cmdb/vpn.ssl/settings'],
                         [{'servercert': 'web-cert'}])
        self.assertEqual(self.fg.puts['/api/v2/cmdb/firewall/vip/web'],
                         [{'ssl-certificate': [{'name': 'web-cert'}]}])

    def test_again_unchanged(self):
        t, ctx, b, got = self.deploy()
        n = len(self.fg.find('PUT', r'/local/web-cert$'))
        t2, ctx2 = make(self.fg)
        ctx2.kv = ctx.kv
        got = t2.deploy(b, dict(REPLACE))
        self.assertTrue(got.startswith('unchanged'), got)
        self.assertEqual(len(self.fg.find('PUT', r'/local/web-cert$')), n)

    def test_encrypted_key_refused_plain_tried(self):
        self.fg.refuse_encrypted = True
        t, ctx, b, got = self.deploy()
        puts = self.fg.find('PUT', r'/vpn\.certificate/local/web-cert$')
        self.assertEqual(len(puts), 2)
        self.assertIn('BEGIN PRIVATE KEY', puts[1]['body']['private-key'])
        self.assertNotIn('password', puts[1]['body'])
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(b.cert_pem))

    def test_refused_old_untouched(self):
        self.fg.refuse_put = (500, -651)
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), dict(REPLACE, keep=0))
        words = str(e.exception)
        self.assertIn('FortiOS refused to replace web-cert in place', words)
        self.assertIn('-651', words)
        self.assertIn('web-cert is untouched (the old certificate, nothing deleted)', words)
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(PEMS['old']))
        self.assertFalse(self.fg.find('DELETE', r'.'), 'nothing deleted')
        self.assertFalse(self.fg.find('POST', r'.'), 'nothing imported')

    def test_missing_name_fails_early(self):
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), dict(REPLACE, replace_name='web-certt'))
        self.assertIn('there is no local certificate web-certt on the FortiGate (VDOM root)',
                      str(e.exception))
        self.assertIn('nothing was changed', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])

    def test_empty_and_factory_refused(self):
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), {'mode': 'replace', 'replace_name': ' '})
        self.assertIn('no certificate on the FortiGate is chosen', str(e.exception))
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), {'mode': 'replace', 'replace_name': 'Fortinet_SSL'})
        self.assertIn('Fortinet factory certificate', str(e.exception))
        self.fg.add('mine', PEMS['other'], source='factory')
        with self.assertRaises(PluginError):
            t.deploy(Bundle(), {'mode': 'replace', 'replace_name': 'mine'})
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])

    def test_hand_typed_name(self):
        """A name typed (discovery never asked) with characters a URL quotes."""
        self.fg.add('VPN cert/2026 #1', PEMS['other'], q_ref=1)
        t, ctx = make(self.fg)
        b = Bundle()
        t.deploy(b, {'mode': 'replace', 'replace_name': 'VPN cert/2026 #1'})
        self.assertEqual(der(self.fg.local['VPN cert/2026 #1']['certificate']), der(b.cert_pem))
        self.assertFalse([c for c in self.fg.find('GET', r'/cmdb/vpn\.certificate/local$')
                          if c['query'].get('with_meta')], 'discovery never asked')
        self.assertTrue(any('used once' in w for w in said(ctx)))

    def test_cleanup_spares_the_replaced(self):
        b = Bundle()
        prefix = C.name_prefix(b, {}, maxlen=35, serial_len=6)
        # older acme ones of this certificate (from before the mode), and the replaced one
        # itself named as acme names them
        olds = [prefix + '2026%04d-%06x' % (d, d) for d in (101, 201, 301)]
        for n in olds:
            self.fg.add(n, PEMS['other'])
        replaced = prefix + '20260401-0abcde'
        self.fg.add(replaced, PEMS['old'], q_ref=3)
        t, ctx = make(self.fg)
        t.deploy(b, {'mode': 'replace', 'replace_name': replaced, 'keep': 0})
        self.assertIn(replaced, self.fg.local)
        self.assertEqual(der(self.fg.local[replaced]['certificate']), der(b.cert_pem))
        self.assertEqual([n for n in olds if n in self.fg.local], [])
        self.assertNotIn(replaced, [c['path'].rsplit('/', 1)[-1] for c in
                                    self.fg.find('DELETE', r'.')])

    def test_new_mode_unchanged(self):
        """Off by default: imported under a new name as before; a saved deployment's key the
        same with the mode set to "new" as without it."""
        t, ctx = make(self.fg)
        b = Bundle()
        t.deploy(b, {'keep': 1})
        self.assertEqual(len(self.fg.find('POST', r'/local/import')), 1)
        self.assertFalse(self.fg.find('PUT', r'/vpn\.certificate/local/'))
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(PEMS['old']))
        self.assertEqual(t.state_key({'keep': 1}),
                         t.state_key({'keep': 1, 'mode': 'new', 'replace_name': ''}))
        self.assertNotEqual(t.state_key({'keep': 1}), t.state_key(dict(REPLACE, keep=1)))


# ---------------------------------------------------------------------------
class CaQuietTest(Base):
    def test_minus_328_said_once_quietly(self):
        b = Bundle()
        self.fg.cas.append(b.chain_pems[0])     # there already
        t, ctx = make(self.fg)
        t.deploy(b, {'keep': 1})
        words = said(ctx)
        self.assertEqual(len(self.fg.find('POST', r'/ca/import')), 1)
        self.assertFalse([w for w in words if 'not imported' in w or '-328' in w], words)
        quiet = [(lv, w) for lv, w in ctx.steps if 'on the FortiGate already' in w]
        self.assertEqual(quiet, [('info', 'the intermediate CA certificate is on the '
                                           'FortiGate already')])

    def test_minus_328_for_one_not_there_is_said(self):
        b = Bundle()
        t, ctx = make(self.fg)
        orig = self.fg.answer

        def answer(m, path, q, body):
            if path.endswith('/ca/import'):
                return self.fg.err(500, -328)     # yet the CA list does not have it
            return orig(m, path, q, body)
        self.fg.answer = answer
        t.deploy(b, {'keep': 1})
        self.assertTrue([w for w in said(ctx) if 'the CA certificate is not imported' in w])

    def test_replace_imports_the_chain_quietly(self):
        b = Bundle()
        t, ctx = make(self.fg)
        t.deploy(b, dict(REPLACE))
        self.assertEqual([der(c) for c in self.fg.cas], [der(b.chain_pems[0])])
        t2, ctx2 = make(self.fg)
        t2.deploy(b, dict(REPLACE, force=True))
        self.assertIn('the intermediate CA certificate is on the FortiGate already',
                      said(ctx2))

    def test_dup(self):
        e = PluginError('importing a CA certificate: the device said 500 - -328',
                        detail='{"status":"error","error":-328}')
        self.assertTrue(FG.FortiGateTarget.dup(e))
        self.assertFalse(FG.FortiGateTarget.dup(PluginError('x: said 500 - -3281')))
        self.assertFalse(FG.FortiGateTarget.dup(PluginError('x: said 500 - -5')))


# ---------------------------------------------------------------------------
class DryRunTest(unittest.TestCase):
    """What happens: the deployment recorded against the canned FortiGate of runplan."""
    def record(self, version, opts):
        from acmelib.certs import runplan as R
        cfg = {'host': 'fw', 'token': 't', 'vdom': 'root', '_version': version}
        got, err = R.record({'runs': [{
            'id': 'r1', 'family': 'target', 'kind': 'fortigate', 'name': 't', 'op': 'deploy',
            'config': cfg, 'options': opts, 'seconds': 30,
            'answers': R.answers_of('fortigate', cfg, opts, version=version),
            'ssh_answers': R.ssh_answers_of('fortigate', cfg, opts, version=version)}],
            'cert': {'names': ['www.example.com'], 'key_type': 'ec-256'}}, timeout=120)
        self.assertEqual(err, '')
        self.assertFalse(got['r1'].get('error'), got['r1'].get('error'))
        return got['r1']['events']

    def test_says_what_is_replaced(self):
        for ver in ('', '6.0', '7.0', '7.4.2'):
            evs = self.record(ver, dict(REPLACE))
            says = [e.get('words') for e in evs if e['kind'] in ('say', 'step')]
            self.assertTrue([w for w in says if w.startswith(
                'replacing the certificate web-cert in place: the same name, everything that '
                'uses it keeps using it (now www.example.com, valid to ')], says)
            self.assertIn('web-cert replaced in place - its name and every use of it kept',
                          says)
            http = [(e['method'], e['url'].split('?')[0]) for e in evs if e['kind'] == 'http']
            self.assertIn(('PUT', 'https://fw/api/v2/cmdb/vpn.certificate/local/web-cert'),
                          http)
            self.assertNotIn(('POST', 'https://fw/api/v2/monitor/vpn-certificate/local/import'),
                             http)
            put = [e for e in evs if e['kind'] == 'http' and e['method'] == 'PUT'][0]
            self.assertNotIn('PRIVATE KEY-----\nMI', json.dumps(put.get('body')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
