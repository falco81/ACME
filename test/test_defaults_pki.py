#!/usr/bin/env python3
"""The default of every list, the CRLs published on acme, HTTP-01 here -
through a real daemon.

    python3 test/test_defaults_pki.py

No root, no network: a daemon in a folder of its own (unusual ports), asked
over its API the way the pages ask; the pages' relay web/pki.php run by
`php -S` (its two paths pointed at the test's run folder) and fetched with
curl; openssl reads what comes back.

What is tried:
- the defaults: POST /api/{sources,validations,targets}/default {name} and
  /api/cas/default {id} - set, shown (is_default, the overview), used (a new
  certificate's source, the own-CA field of /api/plugins), cleared with '',
  refused for what is missing or switched off, for a reader, written to the
  events, followed through a rename, cleared when the default is deleted; the
  command line (--source-default, --ca-default ... none);
- publishing: a new authority gets acme's own CRL and AIA addresses, so what
  it signs carries them (cert_info: crl, ca_issuers); GET /api/pki/crl and
  /cert give DER (no session), an unknown slug and an authority not
  published are 404; "Use acme's own URLs"; the leader's CRL made again at
  half its life (time moved on) and not before; the relay /pki/<slug>.crl is
  application/pkix-crl that `openssl crl -inform DER` reads, /pki/ lists it,
  and "Check it" (POST /api/cas/pki_check) is right over HTTP;
- port 80 let in from anywhere for /pki/ and HTTP-01 when "who may reach the
  pages" keeps the pages to some networks, and not when neither is on;
- HTTP-01 here: GET /api/validations/info (the URL, this node, port 80, the
  names and where they point), POST /api/validations/check (a probe token,
  in a job, taken away after);
- deploy/acme_web.py putting /pki/ into an nginx file that has none, once.
"""
import base64
import importlib.util
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


ROUTER = r'''<?php
// php -S: /pki/ to pki.php, as nginx sends it.
$p = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($p === '/pki' || str_starts_with($p, '/pki/')) { require __DIR__ . '/pki.php'; return true; }
http_response_code(404);
return true;
'''


class DefaultsPki(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-defaults-pki-')
        for d in ('state', 'run', 'log', 'web'):
            os.makedirs(os.path.join(cls.tmp, d), exist_ok=True)
        cls.port = free_port()
        cls.php_port = free_port()
        conf = {'api_port': cls.port, 'radius_bind': '127.0.0.1',
                'radius_auth_port': free_port(), 'radius_acct_port': free_port(),
                'ssh_gate_port': free_port(), 'node_name': 'testnode', 'upgrade_check': 0}
        cls.conf = os.path.join(cls.tmp, 'config.json')
        with open(cls.conf, 'w') as f:
            json.dump(conf, f)
        cls.env = dict(os.environ, ACME_CONFIG=cls.conf,
                       ACME_STATE=os.path.join(cls.tmp, 'state'),
                       ACME_RUN=os.path.join(cls.tmp, 'run'),
                       ACME_LOGDIR=os.path.join(cls.tmp, 'log'),
                       ACME_STAY_ROOT='1', NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1')
        cls.pw = 'Test-Password-4711!'
        made = subprocess.run([sys.executable, '-c', (
            'import sys; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'st = acme.Storage(acme.open_db()); '
            'st.add_account("tester", "fulladmin", %r); '
            'st.add_account("viewer", "readonly", %r)') % (ROOT, cls.pw, cls.pw)],
            env=cls.env, capture_output=True, text=True, timeout=120)
        if made.returncode != 0:
            raise RuntimeError('the accounts could not be made: %s' % made.stderr[-2000:])
        cls.daemon = subprocess.Popen([sys.executable, os.path.join(ROOT, 'acme.py'), '--daemon'],
                                      env=cls.env, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, cwd=cls.tmp)
        end = time.time() + 60
        while time.time() < end:
            if cls.daemon.poll() is not None:
                raise RuntimeError('the daemon stopped: %s' % cls.daemon.stdout.read()
                                   .decode('utf-8', 'replace')[-3000:])
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/api/health' % cls.port, timeout=2)
                break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.3)
        else:
            raise RuntimeError('the daemon did not answer within a minute')
        with open(os.path.join(cls.tmp, 'run', 'api-token')) as f:
            cls.token = f.read().strip()
        cls.admin = cls.login('tester')
        cls.ro = cls.login('viewer')
        # The relay as shipped, its two paths pointed at this test's run folder.
        cls.php = None
        if shutil.which('php'):
            run = os.path.join(cls.tmp, 'run')
            for name in ('acme-api.php', 'pki.php'):
                with open(os.path.join(ROOT, 'web', name)) as f:
                    text = f.read().replace('/run/acme/', run + '/')
                with open(os.path.join(cls.tmp, 'web', name), 'w') as f:
                    f.write(text)
            with open(os.path.join(cls.tmp, 'web', 'router.php'), 'w') as f:
                f.write(ROUTER)
            cls.php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % cls.php_port, '-t',
                                        os.path.join(cls.tmp, 'web'),
                                        os.path.join(cls.tmp, 'web', 'router.php')],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            end = time.time() + 20
            while time.time() < end:
                try:
                    socket.create_connection(('127.0.0.1', cls.php_port), 1).close()
                    break
                except OSError:
                    time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        for p in (getattr(cls, 'php', None), getattr(cls, 'daemon', None)):
            if p is not None and p.poll() is None:
                p.send_signal(signal.SIGTERM)
                try:
                    p.wait(20)
                except subprocess.TimeoutExpired:
                    p.kill()
        if os.environ.get('ACME_TEST_KEEP'):
            print('kept: %s' % cls.tmp)
        else:
            shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- asking -------------------------------------------------------------------------
    @classmethod
    def call(cls, method, path, body=None, session=None, args=None):
        url = 'http://127.0.0.1:%d%s' % (cls.port, path)
        if args:
            url += '?' + urllib.parse.urlencode(args)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header('X-Acme-Token', cls.token)
        req.add_header('Content-Type', 'application/json')
        if session:
            req.add_header('X-Acme-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    @classmethod
    def login(cls, name):
        st, got = cls.call('POST', '/api/auth/login', {'name': name, 'password': cls.pw})
        if st != 200:
            raise RuntimeError('signing in as %s: %s %s' % (name, st, got))
        return got['token']

    def ok(self, method, path, body=None, session=None, args=None):
        st, got = self.call(method, path, body, session or self.admin, args)
        self.assertEqual(st, 200, '%s %s -> %s %s' % (method, path, st, got))
        self.assertTrue(got.get('ok'), got)
        return got

    def refused(self, status, method, path, body=None, session=None, args=None):
        st, got = self.call(method, path, body, session or self.admin, args)
        self.assertEqual(st, status, '%s %s -> %s %s' % (method, path, st, got))
        return got

    def cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(args),
                              env=self.env, capture_output=True, text=True, input='',
                              timeout=180)

    def cli_ok(self, *args):
        got = self.cli(*args)
        self.assertEqual(got.returncode, 0, '%s: %s %s' % (args, got.stdout[-2000:],
                                                           got.stderr[-2000:]))
        return got

    def py(self, code):
        head = ('import sys, json, time; sys.path.insert(0, %r); import acme; '
                'from acmelib import engine as E; acme.load_config(); '
                'st = acme.Storage(acme.open_db()); E.HA_STORE["store"] = st; '
                'E.load_config(saved=st.settings_saved())\n' % ROOT)
        got = subprocess.run([sys.executable, '-c', head + code], env=self.env,
                             capture_output=True, text=True, timeout=180)
        self.assertEqual(got.returncode, 0, got.stderr[-3000:])
        return json.loads(got.stdout.strip().splitlines()[-1])

    def rows(self, path):
        return {r['name']: r for r in self.ok('GET', path)['rows']}

    def events(self, words):
        got = self.ok('GET', '/api/events', args={'limit': 500})
        rows = got.get('rows') or got.get('events') or []
        return [e for e in rows if words in str(e.get('words') or e.get('text') or
                                                e.get('message') or e)]

    def setting(self, **kw):
        self.ok('POST', '/api/settings', {'settings': kw})

    def make_ca(self, name, **kw):
        body = {'name': name, 'subject': {'CN': name + ' CA', 'O': 'Test'},
                'key_type': 'ec-256', 'days': 3650}
        body.update(kw)
        return self.ok('POST', '/api/cas/create', body)

    # ---- the defaults ---------------------------------------------------------------------
    def test_10_source_default(self):
        src = self.rows('/api/sources')
        self.assertTrue(src['LetsEncrypt']['is_default'])
        got = self.ok('POST', '/api/sources/default', {'name': 'LetsEncrypt staging'})
        self.assertEqual(got['default'], 'LetsEncrypt staging')
        src = self.rows('/api/sources')
        self.assertTrue(src['LetsEncrypt staging']['is_default'])
        self.assertFalse(src['LetsEncrypt']['is_default'])
        self.assertEqual(self.ok('GET', '/api/certs/overview')['defaults']['issuer'],
                         'LetsEncrypt staging')
        cid = self.ok('POST', '/api/certs/save', {'name': 'd1', 'names': ['d1.example.com'],
                                                  'auto_renew': 0})['id']
        self.assertEqual(self.ok('GET', '/api/certs/one', args={'id': cid})['cert']['issuer'],
                         'LetsEncrypt staging')
        self.assertTrue(self.events('is now the default source'))
        # Refused: missing, switched off, a reader.
        self.refused(404, 'POST', '/api/sources/default', {'name': 'nothing such'})
        sid = self.ok('POST', '/api/sources/save', {'name': 'off-src', 'kind': 'selfsigned',
                                                    'config': {}, 'enabled': 0})['id']
        got = self.refused(400, 'POST', '/api/sources/default', {'name': 'off-src'})
        self.assertIn('switched off', got['error'])
        self.refused(403, 'POST', '/api/sources/default', {'name': 'LetsEncrypt'},
                     session=self.ro)
        # None: '' - and a new certificate then has no source (a CSR for outside).
        self.assertEqual(self.ok('POST', '/api/sources/default', {'name': ''})['default'], '')
        self.assertFalse(any(r['is_default'] for r in self.rows('/api/sources').values()))
        cid = self.ok('POST', '/api/certs/save', {'name': 'd2', 'names': ['d2.example.com'],
                                                  'auto_renew': 0})['id']
        self.assertFalse(self.ok('GET', '/api/certs/one', args={'id': cid})['cert']['issuer'])
        self.assertTrue(self.events('no default source any more'))
        # Renamed: the default follows; deleted: there is none.
        self.ok('POST', '/api/sources/save', {'id': sid, 'enabled': 1})
        self.ok('POST', '/api/sources/default', {'name': 'off-src'})
        self.ok('POST', '/api/sources/save', {'id': sid, 'name': 'renamed-src'})
        self.assertTrue(self.rows('/api/sources')['renamed-src']['is_default'])
        self.ok('POST', '/api/sources/delete', {'id': sid})
        self.assertFalse(any(r['is_default'] for r in self.rows('/api/sources').values()))
        self.assertEqual(self.ok('GET', '/api/certs/overview')['defaults']['issuer'], '')
        self.assertTrue(self.events('was the default source: there is none now'))
        # Back to Let's Encrypt, from the command line.
        self.cli_ok('--source-default', 'LetsEncrypt')
        self.assertTrue(self.rows('/api/sources')['LetsEncrypt']['is_default'])

    def test_11_validation_and_target_default(self):
        self.ok('POST', '/api/validations/save', {'name': 'dns-x', 'kind': 'manual',
                                                  'config': {}})
        self.ok('POST', '/api/validations/default', {'name': 'dns-x'})
        vals = self.rows('/api/validations')
        self.assertTrue(vals['dns-x']['is_default'])
        self.assertFalse(vals['This server HTTP-01']['is_default'])
        self.cli_ok('--validation-default', 'none')
        self.assertFalse(any(r['is_default'] for r in self.rows('/api/validations').values()))
        self.cli_ok('--validation-default', 'This server HTTP-01')
        self.ok('POST', '/api/validations/delete', {'name': 'dns-x', 'id': vals['dns-x']['id']})
        self.assertTrue(self.rows('/api/validations')['This server HTTP-01']['is_default'])
        # Targets: none at first; one made the default; is_default on its row.
        tid = self.ok('POST', '/api/targets/save', {'name': 'pages', 'kind': 'appliance',
                                                    'config': {}})['id']
        self.assertFalse(self.rows('/api/targets')['pages']['is_default'])
        self.ok('POST', '/api/targets/default', {'name': 'pages'})
        self.assertTrue(self.rows('/api/targets')['pages']['is_default'])
        self.assertEqual(self.ok('GET', '/api/certs/overview')['defaults']['target'], 'pages')
        out = self.cli_ok('--targets').stdout
        self.assertIn('pages *', out)
        self.ok('POST', '/api/targets/delete', {'id': tid})
        self.assertEqual(self.ok('GET', '/api/certs/overview')['defaults']['target'], '')

    def test_12_ca_default(self):
        a = self.make_ca('dflt-a')['id']
        b = self.make_ca('dflt-b')['id']
        self.ok('POST', '/api/cas/default', {'id': b})
        cas = {r['name']: r for r in self.ok('GET', '/api/cas')['rows']}
        self.assertTrue(cas['dflt-b']['is_default'])
        self.assertFalse(cas['dflt-a']['is_default'])
        self.assertTrue(self.ok('GET', '/api/cas/one', args={'id': b})['ca']['is_default'])
        # A new own-CA source offers it first: the field's default.
        plug = self.ok('GET', '/api/plugins')
        f = [x for x in [p for p in plug['issuer'] if p['kind'] == 'internal_ca'][0]['fields']
             if x['key'] == 'ca'][0]
        self.assertEqual(f.get('default'), 'dflt-b')
        self.assertIn('dflt-a', [o[0] for o in f['options']])
        self.cli_ok('--ca-default', 'dflt-a')
        self.assertTrue({r['name']: r for r in self.ok('GET', '/api/cas')['rows']}
                        ['dflt-a']['is_default'])
        self.refused(404, 'POST', '/api/cas/default', {'id': 99999})
        self.refused(403, 'POST', '/api/cas/default', {'id': a}, session=self.ro)
        # Deleted: no default any more, the field has none.
        self.ok('POST', '/api/cas/delete', {'id': a})
        self.assertFalse(any(r.get('is_default') for r in self.ok('GET', '/api/cas')['rows']))
        self.assertEqual(self.ok('GET', '/api/certs/overview')['defaults']['ca'], '')
        plug = self.ok('GET', '/api/plugins')
        f = [x for x in [p for p in plug['issuer'] if p['kind'] == 'internal_ca'][0]['fields']
             if x['key'] == 'ca'][0]
        self.assertFalse(f.get('default'))
        self.ok('POST', '/api/cas/default', {'id': b})
        self.ok('POST', '/api/cas/default', {'id': ''})
        self.assertFalse(any(r.get('is_default') for r in self.ok('GET', '/api/cas')['rows']))

    # ---- publishing on acme ----------------------------------------------------------------
    def base(self):
        return 'http://127.0.0.1:%d/pki/' % self.php_port

    def test_20_published_urls_in_what_it_signs(self):
        self.setting(pki_base_url=self.base())
        got = self.make_ca('Pub Root')
        self.assertTrue(got['published'])
        self.assertEqual(got['crl_url'], self.base() + 'pub-root.crl')
        self.assertEqual(got['aia_url'], self.base() + 'pub-root.crt')
        pki = self.ok('GET', '/api/cas/one', args={'id': got['id']})['pki']
        self.assertTrue(pki['published'] and pki['own_urls'])
        self.assertEqual(pki['urls']['crl_pem'], self.base() + 'pub-root.crl.pem')
        self.assertTrue(pki['next_update'] > time.time())
        # What it signs carries both.
        from acmelib.certs import pki as P
        key = P.make_key('ec-256')
        csr = P.make_csr(key, ['signed.example.test'])[0]
        cert = self.ok('POST', '/api/cas/sign_csr', {'id': got['id'], 'csr_pem': csr,
                                                     'days': 30})['cert_pem']
        info = P.cert_info(cert)
        self.assertIn(self.base() + 'pub-root.crl', info['crl'])
        self.assertIn(self.base() + 'pub-root.crt', info['ca_issuers'])
        # Given addresses are kept; published: off keeps none.
        got2 = self.make_ca('Own Urls', crl_url='http://pki.example.test/x.crl')
        one = self.ok('GET', '/api/cas/one', args={'id': got2['id']})['ca']
        self.assertEqual(one['crl_url'], 'http://pki.example.test/x.crl')
        self.assertEqual(one['aia_url'], self.base() + 'own-urls.crt')
        got3 = self.make_ca('Not Pub', published=False)
        one = self.ok('GET', '/api/cas/one', args={'id': got3['id']})
        self.assertEqual((one['ca']['crl_url'], one['ca']['aia_url']), ('', ''))
        self.assertFalse(one['pki']['published'])
        # "Use acme's own URLs" on an existing one.
        u = self.ok('POST', '/api/cas/pki_urls', {'id': got3['id']})
        self.assertEqual(u['crl_url'], self.base() + 'not-pub.crl')
        self.refused(403, 'POST', '/api/cas/pki_urls', {'id': got3['id']}, session=self.ro)

    def test_21_public_routes(self):
        cas = {r['name']: r for r in self.ok('GET', '/api/cas')['rows']}
        self.assertTrue(cas['Pub Root']['published'])
        self.assertFalse(cas['Not Pub']['published'])
        # No session at all: the pages' relay asks with the token only.
        got = self.ok('GET', '/api/pki/crl', session='', args={'ca': 'pub-root'})
        self.assertEqual(got['mime'], 'application/pkix-crl')
        der = base64.b64decode(got['data_b64'])
        text = subprocess.run(['openssl', 'crl', '-inform', 'DER', '-noout', '-text'], input=der,
                              capture_output=True)
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn(b'Pub Root CA', text.stdout)
        got = self.ok('GET', '/api/pki/cert', session='', args={'ca': 'pub-root'})
        self.assertEqual(got['mime'], 'application/pkix-cert')
        from acmelib.certs import pki as P
        self.assertEqual(P.cert_info(base64.b64decode(got['data_b64']))['sha256'],
                         cas['Pub Root']['fingerprint'])
        pem = self.ok('GET', '/api/pki/crl', session='', args={'ca': 'pub-root', 'format': 'pem'})
        self.assertIn(b'BEGIN X509 CRL', base64.b64decode(pem['data_b64']))
        self.refused(404, 'GET', '/api/pki/crl', session='', args={'ca': 'no-such-ca'})
        self.refused(404, 'GET', '/api/pki/crl', session='', args={'ca': '../etc'})
        self.refused(404, 'GET', '/api/pki/crl', session='', args={'ca': 'not-pub'})
        self.refused(404, 'GET', '/api/pki/cert', session='', args={'ca': 'not-pub'})
        idx = [r['slug'] for r in self.ok('GET', '/api/pki/index', session='')['published']]
        self.assertIn('pub-root', idx)
        self.assertNotIn('not-pub', idx)
        # Its switch off: gone; on again: back. Publishing off: nothing at all.
        rid = cas['Pub Root']['id']
        self.ok('POST', '/api/cas/publish', {'id': rid, 'published': False})
        self.refused(404, 'GET', '/api/pki/crl', session='', args={'ca': 'pub-root'})
        self.ok('POST', '/api/cas/publish', {'id': rid, 'published': True})
        self.ok('GET', '/api/pki/crl', session='', args={'ca': 'pub-root'})
        self.setting(pki_publish=0)
        try:
            self.refused(404, 'GET', '/api/pki/crl', session='', args={'ca': 'pub-root'})
            self.assertEqual(self.ok('GET', '/api/pki/index', session='')['published'], [])
        finally:
            self.setting(pki_publish=1)

    def test_22_relay(self):
        if not self.php:
            self.skipTest('no php')
        url = self.base() + 'pub-root.crl'
        hdr = subprocess.run(['curl', '-sS', '-D', '-', '-o', os.path.join(self.tmp, 'got.crl'),
                              url], capture_output=True, text=True, timeout=60)
        self.assertEqual(hdr.returncode, 0, hdr.stderr)
        self.assertRegex(hdr.stdout, r'(?i)^HTTP/1\.[01] 200')
        self.assertRegex(hdr.stdout, r'(?im)^content-type: application/pkix-crl')
        rd = subprocess.run(['openssl', 'crl', '-inform', 'DER', '-in',
                             os.path.join(self.tmp, 'got.crl'), '-noout', '-issuer'],
                            capture_output=True, text=True)
        self.assertEqual(rd.returncode, 0, rd.stderr)
        self.assertIn('Pub Root CA', rd.stdout)
        for path, ctype in (('pub-root.crt', 'application/pkix-cert'),
                            ('pub-root.pem', 'application/x-pem-file'),
                            ('pub-root.crl.pem', 'application/x-pem-file')):
            got = subprocess.run(['curl', '-sS', '-o', '/dev/null', '-w',
                                  '%{http_code} %{content_type}', self.base() + path],
                                 capture_output=True, text=True, timeout=60)
            self.assertEqual(got.stdout, '200 ' + ctype, path)
        for path in ('no-such.crl', 'not-pub.crl', '../acme-api.php', 'pub-root.key'):
            got = subprocess.run(['curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}',
                                  self.base() + path], capture_output=True, text=True, timeout=60)
            self.assertEqual(got.stdout, '404', path)
        page = subprocess.run(['curl', '-sS', self.base()], capture_output=True, text=True,
                              timeout=60).stdout
        self.assertIn('pub-root.crl', page)
        self.assertNotIn('not-pub', page)
        # "Check it": fetched over HTTP by the daemon, read with openssl.
        rid = {r['name']: r for r in self.ok('GET', '/api/cas')['rows']}['Pub Root']['id']
        got = self.ok('POST', '/api/cas/pki_check', {'id': rid})
        self.assertTrue(got['ok'], got['steps'])
        words = ' '.join(s[1] for s in got['steps'])
        self.assertIn('openssl crl -inform DER reads it', words)
        self.assertIn('signature is the authority', words)
        out = self.cli_ok('--ca-pki-check', 'Pub Root').stdout
        self.assertIn('what is published is right', out)

    def test_23_crl_made_again_at_half_life(self):
        got = self.py(
            'from acmelib.certs import ca, publish\n'
            'rid = st.db.value("SELECT id FROM cert_cas WHERE name = ?", ("Pub Root",))\n'
            'n0 = int(st.db.value("SELECT crl_number FROM cert_cas WHERE id = ?", (rid,)))\n'
            'first = publish.refresh(st)\n'
            'real = ca._now\n'
            'ca._now = lambda: real() + 3 * 86400\n'          # before half of 7 days
            'early = publish.refresh(st)\n'
            'ca._now = lambda: real() + 4 * 86400\n'          # past it
            'late = publish.refresh(st)\n'
            'n1 = int(st.db.value("SELECT crl_number FROM cert_cas WHERE id = ?", (rid,)))\n'
            'from acmelib.certs import renewer\n'
            'ca._now = lambda: real() + 8 * 86400\n'          # the leader\'s look does it too
            'renewer.scan(st)\n'
            'n2 = int(st.db.value("SELECT crl_number FROM cert_cas WHERE id = ?", (rid,)))\n'
            'print(json.dumps({"first": first, "early": early, "late": late, "n0": n0, '
            '"n1": n1, "n2": n2, "meta": json.loads(st.get_meta("certs:pki:refresh"))}))')
        self.assertNotIn('Pub Root', got['first'])
        self.assertNotIn('Pub Root', got['early'])
        self.assertIn('Pub Root', got['late'])
        self.assertEqual(got['n1'], got['n0'] + 1)
        self.assertEqual(got['n2'], got['n1'] + 1)
        self.assertEqual(got['meta']['node'], 'testnode')

    # ---- port 80 for everybody --------------------------------------------------------------
    def test_30_firewall_port_80(self):
        code = (
            'st.set_meta("web:access", json.dumps({k: {"any": False, "from": ["10.0.0.0/8"]} '
            'for k in ("portal", "admin", "health")}))\n'
            'def p80():\n'
            '    web = [x for x in E.fw_auto(st, E.node_name()) if x["key"] == "web"][0]\n'
            '    return any(r["port"] == "80" and not r["source"] for r in web["rules"])\n'
            'E.CONFIG["acme"] = 0\n'
            'a = p80()\n'
            'E.CONFIG["pki_publish"] = 0\n'
            'b = p80()\n'
            'st.db.run("UPDATE cert_challenges SET enabled = 0 WHERE kind = \'http_local\'")\n'
            'c = p80()\n'
            'st.db.run("UPDATE cert_challenges SET enabled = 1 WHERE kind = \'http_local\'")\n'
            'st.db.run("DELETE FROM meta WHERE k = \'web:access\'")\n'
            'print(json.dumps([a, b, c]))')
        a, b, c = self.py(code)
        self.assertTrue(a)          # /pki/ on (and HTTP-01 here)
        self.assertTrue(b)          # HTTP-01 here still
        self.assertFalse(c)         # neither: only the networks of the lists

    # ---- HTTP-01 answered here ---------------------------------------------------------------
    def test_40_http01_info_and_check(self):
        # (a public CA: a fully qualified name - "localhost" is refused for Let's Encrypt)
        self.ok('POST', '/api/certs/save', {'name': 'here', 'names': ['here.example.com'],
                                            'issuer': 'LetsEncrypt',
                                            'challenge': 'This server HTTP-01',
                                            'auto_renew': 0})
        got = self.ok('GET', '/api/validations/info', args={'name': 'This server HTTP-01'})
        self.assertTrue(got['applies'])
        self.assertEqual(got['url'], 'http://<NAME>/.well-known/acme-challenge/<token>')
        self.assertEqual((got['port'], got['path_fixed']), (80, True))
        self.assertIn('testnode', [n['name'] for n in got['nodes']])
        self.assertTrue(got['firewall'] and got['firewall'][0]['node'] == 'testnode')
        names = {n['name']: n for n in got['names']}
        self.assertIn('here.example.com', names)
        self.assertEqual(names['here.example.com']['cert'], 'here')
        self.assertIn('words', names['here.example.com'])
        self.assertIn('self_check', [f['key'] for f in got['fields']])
        # Another kind: nothing to say.
        self.ok('POST', '/api/validations/save', {'name': 'by-hand', 'kind': 'manual',
                                                  'config': {}})
        self.assertFalse(self.ok('GET', '/api/validations/info',
                                 args={'name': 'by-hand'})['applies'])
        # Check a name: a probe token, fetched, taken away again.
        st, chk = self.call('POST', '/api/validations/check', {'name': 'This server HTTP-01',
                                                               'host': 'localhost'},
                            self.admin)
        self.assertEqual(st, 200, chk)          # nothing answers port 80 here: ok is false
        self.assertIn('job_id', chk)
        self.assertTrue(any('probe token' in str(s) for s in chk['steps']))
        left = self.py('print(json.dumps(st.db.value("SELECT COUNT(*) FROM meta WHERE k LIKE '
                       '\'acme:chal:acme-probe-%\'")))')
        self.assertEqual(left, 0)
        _st, wild = self.call('POST', '/api/validations/check',
                              {'name': 'This server HTTP-01', 'host': '*.example.test'},
                              self.admin)
        self.assertFalse(wild['ok'])
        self.assertIn('wildcard', wild['said'])
        out = self.cli_ok('--validation-show', 'This server HTTP-01').stdout
        self.assertIn('/.well-known/acme-challenge/<token>', out)
        self.assertIn('here.example.com', out)

    # ---- safe names -------------------------------------------------------------------------
    def test_60_safe_name(self):
        from acmelib.certs.store import safe_name, NAME_RE
        cases = {"Let's Encrypt": 'Lets Encrypt', "Let's Encrypt (staging)": 'Lets Encrypt staging',
                 'This server (HTTP-01)': 'This server HTTP-01', 'Šifrování': 'Sifrovani',
                 'Žluťoučký kůň: CA/1': 'Zlutoucky kun CA 1', 'Straße Łódź': 'Strasse Lodz',
                 'a"b`c<d>e': 'abc d e', '  -.x y  ': 'x y', '((()))': 'unnamed',
                 '*.example.com': 'example.com', 'ok-name_1.2@x+y': 'ok-name_1.2@x+y',
                 'tab\there\nnl': 'tab here nl', '中文': 'unnamed'}
        for given, want in cases.items():
            got = safe_name(given)
            self.assertEqual(got, want, given)
            self.assertTrue(NAME_RE.match(got), got)
        self.assertEqual(safe_name('x' * 300), 'x' * 120)
        self.assertEqual(safe_name('dup', ['dup']), 'dup 2')
        self.assertEqual(safe_name('dup', ['dup', 'dup 2']), 'dup 3')
        self.assertTrue(NAME_RE.match(safe_name('y' * 130, ['y' * 120])))
        # The plugins offer safe names to start from.
        plug = self.ok('GET', '/api/plugins')
        for fam in ('issuer', 'challenge', 'target'):
            for one in plug[fam]:
                self.assertTrue(NAME_RE.match(one['default_name']), (fam, one['default_name']))
        hl = [x for x in plug['challenge'] if x['kind'] == 'http_local'][0]
        self.assertEqual(hl['default_name'], 'This server HTTP-01')
        # A certificate with no name said: from its first name, a wildcard as "wildcard.".
        cid = self.ok('POST', '/api/certs/save', {'names': ['*.wild.example.test'],
                                                  'auto_renew': 0, 'issuer': ''})['id']
        self.assertEqual(self.ok('GET', '/api/certs/one', args={'id': cid})['cert']['name'],
                         'wildcard.wild.example.test')
        # An authority with no name said: from its CN, made safe.
        got = self.ok('POST', '/api/cas/create', {'subject': {'CN': "Bob's CA (test)"},
                                                  'key_type': 'ec-256', 'published': False})
        self.assertEqual(self.ok('GET', '/api/cas/one', args={'id': got['id']})['ca']['name'],
                         'Bobs CA test')
        # A name typed that is not safe is still refused.
        self.refused(400, 'POST', '/api/sources/save', {'name': "Bad (name)", 'kind': 'selfsigned',
                                                        'config': {}})

    def test_61_names_made_safe_at_start(self):
        """An installation of before: unsafe names renamed, every reference with them."""
        ca = self.make_ca('mig-ca', published=False)['id']
        self.ok('POST', '/api/sources/save', {'name': 'mig-src', 'kind': 'internal_ca',
                                              'config': {'ca': 'mig-ca'}})
        self.ok('POST', '/api/sources/save', {'name': 'Src old', 'kind': 'selfsigned',
                                              'config': {}})
        self.ok('POST', '/api/validations/save', {'name': 'mig-val', 'kind': 'manual',
                                                  'config': {}})
        self.ok('POST', '/api/targets/save', {'name': 'mig-tg', 'kind': 'appliance', 'config': {}})
        cid = self.ok('POST', '/api/certs/save', {
            'name': 'mig-cert', 'names': ['m.example.test', 'n.example.test'], 'auto_renew': 0,
            'issuer': 'mig-src', 'challenge': 'mig-val',
            'challenge_map': {'n.example.test': 'mig-val'}})['id']
        self.ok('POST', '/api/deploys/save', {'cert_id': cid, 'target': 'mig-tg',
                                              'options': {}, 'enabled': False})
        got = self.py(
            'from acmelib.certs import names as N\n'
            'db = st.db\n'
            'old = {"ca": "Šifrovací CA\'s", "src": "Src (old)", "val": \'Val: "x"\', '
            '"tg": "Tg/1", "cert": "cert\'s one"}\n'
            'db.run("UPDATE cert_cas SET name = ? WHERE name = ?", (old["ca"], "mig-ca"))\n'
            'r = db.row("SELECT id, config FROM cert_issuers WHERE name = ?", ("mig-src",))\n'
            'db.run("UPDATE cert_issuers SET name = ?, config = ? WHERE id = ?", (old["src"], '
            'json.dumps({"ca": old["ca"]}), r["id"]))\n'
            'db.run("UPDATE cert_challenges SET name = ? WHERE name = ?", (old["val"], "mig-val"))\n'
            'db.run("UPDATE cert_targets SET name = ? WHERE name = ?", (old["tg"], "mig-tg"))\n'
            'db.run("UPDATE certs SET name = ?, issuer = ?, challenge = ?, challenge_map = ? '
            'WHERE name = ?", (old["cert"], old["src"], old["val"], '
            'json.dumps({"n.example.test": old["val"]}), "mig-cert"))\n'
            'db.run("UPDATE cert_deploys SET target = ? WHERE target = ?", (old["tg"], "mig-tg"))\n'
            'st.set_meta("certs:default_issuer", old["src"])\n'
            'st.set_meta("certs:default_challenge", old["val"])\n'
            'st.set_meta("certs:default_target", old["tg"])\n'
            'st.set_meta("certs:kv:challenge:" + old["val"] + ":last", "7")\n'
            'st.save_setting("portal_cert_issuers", old["src"] + ", LetsEncrypt")\n'
            'st.save_setting("portal_cert_challenge", old["val"])\n'
            'before = N.check_now(st)\n'
            'done = N.migrate(st)\n'
            'again = N.migrate(st)\n'
            'saved = st.settings_saved()\n'
            'print(json.dumps({"before": before, "done": done, "again": again, '
            '"portal": [saved.get("portal_cert_issuers"), saved.get("portal_cert_challenge")], '
            '"kv": st.get_meta("certs:kv:challenge:Val x:last"), '
            '"meta": [st.get_meta("certs:default_" + k) for k in ("issuer", "challenge", "target")]}))')
        done = {(f, o): n for f, o, n in got['done']}
        self.assertEqual(done[('ca', "Šifrovací CA's")], 'Sifrovaci CAs')
        self.assertEqual(done[('issuer', 'Src (old)')], 'Src old 2')        # "Src old" is taken
        self.assertEqual(done[('challenge', 'Val: "x"')], 'Val x')
        self.assertEqual(done[('target', 'Tg/1')], 'Tg 1')
        self.assertEqual(done[('cert', "cert's one")], 'certs one')
        self.assertEqual(len(got['before']), len(got['done']))
        self.assertEqual(got['again'], [])                                  # once only
        self.assertEqual(got['meta'], ['Src old 2', 'Val x', 'Tg 1'])
        self.assertEqual(got['portal'], ['Src old 2, LetsEncrypt', 'Val x'])
        self.assertEqual(got['kv'], '7')
        one = self.ok('GET', '/api/certs/one', args={'id': cid})
        c = one['cert']
        self.assertEqual((c['name'], c['issuer'], c['challenge']), ('certs one', 'Src old 2', 'Val x'))
        self.assertEqual(c['challenge_map'], {'n.example.test': 'Val x'})
        self.assertEqual([d['target'] for d in one['deploys']], ['Tg 1'])
        self.assertEqual(self.rows('/api/sources')['Src old 2']['config']['ca'], 'Sifrovaci CAs')
        self.assertTrue(self.rows('/api/sources')['Src old 2']['is_default'])
        self.assertEqual(self.ok('GET', '/api/cas/one', args={'id': ca})['ca']['name'],
                         'Sifrovaci CAs')
        self.assertTrue(self.events('names made safe'))
        # Every row editable again (a save of its own name).
        self.ok('POST', '/api/sources/save', {'id': self.rows('/api/sources')['Src old 2']['id'],
                                              'enabled': 1})
        self.cli_ok('--source-default', 'LetsEncrypt')

    # ---- nginx -------------------------------------------------------------------------------
    def test_50_nginx_pki_location(self):
        spec = importlib.util.spec_from_file_location('acme_web_t', os.path.join(
            ROOT, 'deploy', 'acme_web.py'))
        w = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(w)
        with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as f:
            shipped = f.read()
        self.assertEqual(shipped.count('location ^~ /pki/'), 2)
        old = re.sub(r'(?ms)^[ \t]*# The CRLs and certificates.*?# PKI-END\n', '', shipped)
        old = re.sub(r'(?ms)^[ \t]*# ---- the CRLs.*?# PKI-END\n\n', '', old)
        self.assertNotIn('location ^~ /pki/', old)
        new = w.pki_into(old)
        self.assertEqual(new.count('location ^~ /pki/'), 2)
        self.assertEqual(w.pki_into(new), new)
        port80 = new[w.http_block(new)[0]:w.http_block(new)[1]]
        self.assertIn('location ^~ /pki/', port80)
        self.assertLess(port80.index('/pki/'), port80.index('return 301 https'))
        tls = new[w.server_block(new)[0]:w.server_block(new)[1]]
        self.assertIn('pki.php', tls)
        self.assertNotIn('ADMIN-ALLOW', tls[tls.index('location ^~ /pki/'):
                                            tls.index('PKI-END')])


if __name__ == '__main__':
    sys.exit(unittest.main())
