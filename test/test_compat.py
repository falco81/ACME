#!/usr/bin/env python3
"""What fits together (acmelib/certs/compat.py): a certificate's names, its
source, each name's validation, the key type, the twin, the common name and
the e-mail / URI subjectAltNames - and the placement API a commercial CA's DCV
goes through (base.Challenge.place, acmelib/plugins/issuers/_dcv.py).

    python3 test/test_compat.py

No root, no network. The matrix is asked of compat.check against a store in
memory; then (CompatDaemon) through a real daemon: POST /api/certs/save
refuses with 400 and the words, POST /api/certs/compat says what the wizard
greys, the command line refuses, the renewer fails in words without asking a
CA; and (CompatPage, when Playwright is there) the wizard greys an incompatible
validation with its reason.
"""
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
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-compat-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "testnode", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

from acmelib.plugins import base  # noqa: E402
from acmelib.plugins.base import Challenge, Issuer, PluginError  # noqa: E402
from acmelib.certs import compat, store as S  # noqa: E402
from acmelib.plugins.issuers import _dcv  # noqa: E402

S.registry()


# ---------------------------------------------------------------------------
# A store in memory: the rows of cert_issuers and cert_challenges
# ---------------------------------------------------------------------------
class MemDb(object):
    def __init__(self):
        self.tables = {'cert_issuers': [], 'cert_challenges': []}

    def _table(self, sql):
        return re.search(r'FROM (\w+)', sql).group(1)

    def row(self, sql, args=()):
        t = self._table(sql)
        for r in self.tables.get(t, []):
            if 'WHERE id' in sql and r['id'] == args[0]:
                return dict(r)
            if 'WHERE name' in sql and r['name'] == args[0]:
                return dict(r)
        return None

    def rows(self, sql, args=()):
        return [dict(r) for r in sorted(self.tables.get(self._table(sql), []),
                                        key=lambda r: r['name'])]


class MemStore(object):
    def __init__(self):
        self.db = MemDb()

    def add(self, family, name, kind, config=None, enabled=1):
        t = 'cert_issuers' if family == 'issuer' else 'cert_challenges'
        rows = self.db.tables[t]
        rows.append({'id': len(rows) + 1, 'name': name, 'kind': kind, 'enabled': enabled,
                     'config': json.dumps(config or {})})


class SslmarketStyle(Issuer):
    """A source that checks domains as Sectigo (SSLmarket) does: its own DCV shapes."""
    kind = 'test_sectigo'
    title = 'Sectigo-style'
    public_names = True
    needs_challenge = True
    ip_names = False
    key_types = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
    dcv_field = 'dcv'
    dcv_default = 'DNS'
    dcv = {'DNS': {'proof': 'txt-any', 'words': 'TXT', 'record': 'TXT _HASH.NAME'},
           'CNAME': {'proof': 'cname-any', 'words': 'CNAME', 'record': 'CNAME _HASH.NAME'},
           'FILE': {'proof': 'http-file-any', 'words': 'file', 'record': '/.well-known/...'},
           'Email': {'proof': None, 'words': 'e-mail', 'record': 'admin@'}}


base.REGISTRY.found['issuer']['test_sectigo'] = SslmarketStyle

SETTINGS = {'dns_zone': 'acme.example.net'}


def world():
    st = MemStore()
    st.add('issuer', 'LE', 'acme', {'directory': 'letsencrypt'})
    st.add('issuer', 'stepca', 'acme', {'directory': 'custom', 'directory_url': 'https://x/d'})
    st.add('issuer', 'DC txt', 'digicert', {'dcv': 'dns-txt'})
    st.add('issuer', 'DC cname', 'digicert', {'dcv': 'dns-cname'})
    st.add('issuer', 'DC file', 'digicert', {'dcv': 'http-file'})
    st.add('issuer', 'DC mail', 'digicert', {'dcv': 'email'})
    st.add('issuer', 'Sectigo', 'test_sectigo', {'dcv': 'DNS'})
    st.add('issuer', 'Sectigo file', 'test_sectigo', {'dcv': 'FILE'})
    st.add('issuer', 'Own CA', 'internal_ca', {})
    st.add('issuer', 'Self', 'selfsigned', {})
    st.add('issuer', 'SCEP', 'scep', {})
    st.add('issuer', 'ADCS', 'ms_adcs', {'key_kinds': 'rsa'})
    st.add('issuer', 'EST', 'est', {})
    st.add('challenge', 'builtin', 'dns_builtin', {})
    st.add('challenge', 'acmedns', 'acme_dns', {})
    st.add('challenge', 'desec', 'desec', {})
    st.add('challenge', 'cloudflare', 'cloudflare', {})
    st.add('challenge', 'hetzner', 'hetzner', {})
    st.add('challenge', 'rfc2136', 'rfc2136', {})
    st.add('challenge', 'manual', 'manual', {})
    st.add('challenge', 'script', 'script', {})
    st.add('challenge', 'sshdns', 'ssh_dns', {})
    st.add('challenge', 'duck', 'duckdns', {})
    st.add('challenge', 'here', 'http_local', {})
    st.add('challenge', 'web', 'http_ssh', {})
    st.add('challenge', 'web-odd', 'http_ssh', {'webroot': '/srv/tokens'})
    st.add('challenge', 'ftp', 'http_ftp', {})
    st.add('challenge', 's3', 'http_s3', {})
    st.add('challenge', 'blob', 'http_azure_blob', {})
    st.add('challenge', 'dav', 'http_webdav', {})
    st.add('challenge', 'off', 'desec', {}, enabled=0)
    return st


def keys(problems):
    return sorted({p['key'] for p in problems})


class TestMatrix(unittest.TestCase):
    def setUp(self):
        self.st = world()

    def check(self, names, issuer, challenge=None, cmap=None, kt='ec-256', kta='', profile=None):
        return compat.check(self.st, names, issuer, challenge, cmap or {}, kt, kta, SETTINGS,
                            profile=profile)

    def ok(self, *a, **kw):
        got = self.check(*a, **kw)
        self.assertEqual(got, [], compat.words(got))

    def refused(self, key, *a, **kw):
        got = self.check(*a, **kw)
        self.assertIn(key, keys(got), 'expected a %s problem: %s' % (key, got))
        for p in got:
            self.assertTrue(p['what'] and p['fix'], p)
        return compat.words(got)

    # -- ACME and every family of validation --
    def test_acme_every_validation(self):
        for v in ('builtin', 'acmedns', 'desec', 'cloudflare', 'hetzner', 'rfc2136', 'manual',
                  'script', 'sshdns', 'duck', 'here', 'web', 'web-odd', 'ftp', 's3', 'blob',
                  'dav'):
            self.ok(['www.firma.cz'], 'LE', v)
        w = self.refused('validation', ['www.firma.cz'], 'LE', 'off')
        self.assertIn('switched off', w)

    def test_wildcard_needs_dns(self):
        self.ok(['*.firma.cz'], 'LE', 'desec')
        self.ok(['*.firma.cz'], 'LE', 'builtin')
        for v in ('here', 'web', 'ftp', 's3'):
            w = self.refused('validation', ['*.firma.cz', 'firma.cz'], 'LE', v)
            self.assertIn('a wildcard can only be proved by DNS', w)
        # a map: the wildcard by DNS, the rest by HTTP - fits
        self.ok(['*.firma.cz', 'firma.cz'], 'LE', 'here', {'*.firma.cz': 'desec'})
        # the file DCV of a commercial CA cannot prove a wildcard either
        w = self.refused('validation', ['*.firma.cz'], 'DC file', 'here')
        self.assertIn('wildcard', w)

    def test_ip_needs_http(self):
        prof = {'acme_profile': 'shortlived'}
        self.ok(['9.9.9.9'], 'LE', 'here', profile=prof)
        w = self.refused('validation', ['9.9.9.9'], 'LE', 'desec', profile=prof)
        self.assertIn('HTTP-01', w)
        # Let's Encrypt: addresses only in its short-lived profile
        w = self.refused('names', ['9.9.9.9'], 'LE', 'here')
        self.assertIn('shortlived', w)
        # a public CA: no private address; DigiCert: no address at all
        self.refused('names', ['10.1.2.3'], 'LE', 'here', profile=prof)
        self.refused('names', ['9.9.9.9'], 'DC txt', 'desec')
        # an own CA takes any
        self.ok(['10.1.2.3', 'intranet'], 'Own CA')

    def test_public_names(self):
        for n in ('a', 'intranet', 'srv.local', 'x.internal', 'nas.lan', 'h.home.arpa',
                  'localhost', 'w.test', 'w.invalid', 'w.example', 'dc.corp'):
            w = self.refused('names', [n], 'LE', 'here')
            self.assertTrue(re.search(r'single label|never public', w), w)
        self.ok(['www.firma.cz'], 'LE', 'here')
        # your own ACME server (step-ca), an own CA, self-signed, AD CS, SCEP, EST: any name
        for src in ('stepca', 'Own CA', 'Self', 'ADCS', 'SCEP', 'EST'):
            got = [p for p in self.check(['a', 'srv.local'], src, 'here', kt='rsa-2048')
                   if p['key'] == 'names']
            self.assertEqual(got, [], src)

    def test_commercial_dcv(self):
        # TXT at _dnsauth.NAME: an API DNS validation can, acme's own DNS server cannot
        for src in ('DC txt', 'Sectigo'):
            self.ok(['www.firma.cz'], src, 'desec')
            self.ok(['www.firma.cz'], src, 'cloudflare')
            self.ok(['*.firma.cz'], src, 'rfc2136')
            w = self.refused('validation', ['www.firma.cz'], src, 'builtin')
            self.assertIn('own DNS server answers only its own zones', w)
            w = self.refused('validation', ['www.firma.cz'], src, 'acmedns')
            self.assertIn('acme-dns writes only', w)
            self.refused('validation', ['www.firma.cz'], src, 'duck')
            self.refused('validation', ['www.firma.cz'], src, 'here')     # TXT, not a file
        # ... unless the name is inside acme's own zone (delegated)
        self.ok(['www.acme.example.net'], 'DC txt', 'builtin')
        # CNAME: only a validation that writes CNAMEs
        self.ok(['www.firma.cz'], 'DC cname', 'desec')
        self.ok(['www.firma.cz'], 'DC cname', 'manual')
        w = self.refused('validation', ['www.firma.cz'], 'DC cname', 'hetzner')
        self.assertIn('CNAME', w)
        # the file: HTTP validations that upload, this server, nginx over SSH
        for v in ('here', 'web', 'ftp', 's3', 'blob', 'dav'):
            self.ok(['www.firma.cz'], 'DC file', v)
            self.ok(['www.firma.cz'], 'Sectigo file', v)
        w = self.refused('validation', ['www.firma.cz'], 'DC file', 'web-odd')
        self.assertIn('acme-challenge', w)
        self.refused('validation', ['www.firma.cz'], 'DC file', 'desec')
        # e-mail: no validation at all
        self.ok(['www.firma.cz', '*.firma.cz'], 'DC mail')
        self.ok(['www.firma.cz'], 'DC mail', 'builtin')

    def test_key_types_and_twin(self):
        w = self.refused('key', ['vpn.firma.cz'], 'SCEP', kt='ec-256')
        self.assertIn('RSA', w)
        self.ok(['vpn.firma.cz'], 'SCEP', kt='rsa-2048')
        self.refused('key', ['www.firma.cz'], 'ADCS', kt='ec-256')
        self.refused('key', ['www.firma.cz'], 'LE', 'here', kt='ed25519')
        self.ok(['www.firma.cz'], 'Own CA', kt='ed25519')
        # a twin only from a source that gives one
        self.ok(['www.firma.cz'], 'LE', 'here', kta='rsa-2048')
        w = self.refused('twin', ['vpn.firma.cz'], 'SCEP', kt='rsa-2048', kta='ec-256')
        self.assertIn('no twin', w)
        self.refused('twin', ['www.firma.cz'], 'DC txt', 'desec', kta='rsa-2048')
        self.ok(['www.firma.cz'], 'DC txt', 'desec')

    def test_cn_and_other_sans(self):
        prof = {'subject': {'CN': 'Our web server'}, 'san_other': ['email:it@firma.cz']}
        self.ok(['www.firma.cz'], 'Own CA', profile=prof)
        self.ok(['www.firma.cz'], 'Self', profile=prof)
        w = self.refused('names', ['www.firma.cz'], 'LE', 'here', profile=prof)
        self.assertIn('common name', w)
        self.assertIn('e-mail', w)
        self.ok(['www.firma.cz', 'firma.cz'], 'LE', 'here',
                profile={'subject': {'CN': 'firma.cz'}})
        self.refused('names', ['www.firma.cz'], 'DC txt', 'desec',
                     profile={'san_other': ['uri:https://firma.cz/x']})

    def test_options_for_the_wizard(self):
        got = compat.options(self.st, ['www.firma.cz', '*.firma.cz'], 'DC txt', 'desec', {},
                             'ec-256', '', SETTINGS)
        self.assertTrue(got['ok'], got['problems'])
        by = {v['name']: v for v in got['validations']}
        self.assertTrue(by['desec']['ok'])
        self.assertFalse(by['builtin']['ok'])
        self.assertIn('own zones', by['builtin']['why'])
        self.assertFalse(by['here']['ok'])
        self.assertIn('www.firma.cz', by['here']['names'])
        self.assertEqual(got['source']['proofs'], ['txt-any'])
        self.assertFalse(got['twin']['ok'])
        kts = {k['key']: k['ok'] for k in got['key_types']}
        self.assertFalse(kts['ed25519'])
        self.assertTrue(kts['rsa-2048'])
        le = compat.options(self.st, ['*.firma.cz'], 'LE', 'here', {}, 'ec-256', '', SETTINGS)
        by = {v['name']: v for v in le['validations']}
        self.assertFalse(by['here']['ok'])
        self.assertIn('wildcard', by['here']['why'])
        self.assertTrue(by['desec']['ok'])


# ---------------------------------------------------------------------------
# The typed subjectAltNames
# ---------------------------------------------------------------------------
class TestSans(unittest.TestCase):
    def test_each_type(self):
        self.assertEqual(S.san_typed('www.Firma.cz'), ('dns', 'www.firma.cz'))
        self.assertEqual(S.san_typed('žluťoučký.cz')[0], 'dns')
        self.assertTrue(S.san_typed('žluťoučký.cz')[1].startswith('xn--'))
        self.assertEqual(S.san_typed('2001:db8::1'), ('ip', '2001:db8::1'))
        self.assertEqual(S.san_typed('ip:192.0.2.1'), ('ip', '192.0.2.1'))
        self.assertEqual(S.san_typed('it@firma.cz'), ('email', 'it@firma.cz'))
        self.assertEqual(S.san_typed({'type': 'uri', 'value': 'urn:uuid:1234-5678'}),
                         ('uri', 'urn:uuid:1234-5678'))
        self.assertEqual(S.san_typed('https://firma.cz/a?b=1'), ('uri', 'https://firma.cz/a?b=1'))
        for bad in ('email:nope', 'email:a@@b.cz', 'uri:relative/path', 'ip:999.1.1.1',
                    'dns:1.2.3.4', 'dns:-bad-.cz', {'type': 'x400', 'value': 'y'}):
            with self.assertRaises(ValueError, msg=bad):
                S.san_typed(bad)
        self.assertEqual(S.clean_sans(['it@firma.cz', 'email:it@firma.cz', 'urn:x:y']),
                         ['email:it@firma.cz', 'uri:urn:x:y'])
        with self.assertRaises(ValueError):
            S.clean_sans(['www.firma.cz'])          # a DNS name belongs among the names

    def test_csr_and_own_ca(self):
        from acmelib.certs import pki
        key = pki.make_key('ec-256')
        sans = S.sans_of(['www.firma.cz', '192.0.2.1'], {'san_other': ['email:it@firma.cz',
                                                                         'uri:https://firma.cz/x']})
        csr, _der = pki.make_csr(key, sans, subject={'CN': 'Our web server'})
        ci = pki.csr_info(csr)
        self.assertEqual(ci['cn'], 'Our web server')
        self.assertEqual(sorted(ci['san']), sorted([('DNS', 'www.firma.cz'), ('IP', '192.0.2.1'),
                                                    ('email', 'it@firma.cz'),
                                                    ('URI', 'https://firma.cz/x')]))
        from acmelib.plugins.issuers.selfsigned import SelfSignedIssuer

        class Ctx(object):
            def step(self, *a, **k):
                pass
        req = base.CertRequest(names=['www.firma.cz', '192.0.2.1'], sans=sans, key_pem=key,
                               csr_pem=csr, subject={'CN': 'Our web server'})
        out = SelfSignedIssuer({}, Ctx()).issue(req)
        info = pki.cert_info(out.cert_pem)
        self.assertEqual(info['cn'], 'Our web server')
        self.assertIn(('email', 'it@firma.cz'), [tuple(x) for x in info['san']])
        self.assertNotIn('Our web server', info['names'])


# ---------------------------------------------------------------------------
# The placement API
# ---------------------------------------------------------------------------
class Ctx(base.Context):
    def __init__(self, settings=None):
        self.lines, self.kv, self.files, self.dns = [], {}, {}, []
        self.settings = settings or {}

    def step(self, words, level='info'):
        self.lines.append((level, words))

    def kv_get(self, k):
        return self.kv.get(k)

    def kv_set(self, k, v, ttl_s=None):
        self.kv[k] = v

    def http_file_put(self, host, path, content, ttl_s=0):
        self.files[(host, path)] = content

    def http_file_drop(self, host, path):
        self.files.pop((host, path), None)

    def dns_put(self, name, type, value, ttl=60):
        self.dns.append((name, type, value))

    def dns_drop(self, name, type, value=None):
        self.dns = [d for d in self.dns if d[:2] != (name, type)]


class TestPlacement(unittest.TestCase):
    def test_http_local_answers_the_file(self):
        from acmelib.plugins.challenges.http_local import HttpLocal
        ctx = Ctx()
        ch = HttpLocal({}, ctx)
        h = ch.place('file', 'www.firma.cz', '/.well-known/pki-validation/fileauth.txt', 'RND')
        self.assertEqual(ctx.files[('www.firma.cz', '/.well-known/pki-validation/fileauth.txt')],
                         'RND')
        self.assertTrue(ch.placed_ready(h))
        ch.unplace(h)
        self.assertEqual(ctx.files, {})
        with self.assertRaises(PluginError):
            ch.place('file', 'www.firma.cz', '/etc/passwd', 'x')
        with self.assertRaises(NotImplementedError):
            ch.place('txt', 'www.firma.cz', '_dnsauth.www.firma.cz', 'x')

    def test_dns_txt_anywhere_and_cname(self):
        from acmelib.plugins.challenges._common import DnsChallenge

        class Board(DnsChallenge):
            kind = 'board'
            fields = []

            def __init__(self, ctx):
                DnsChallenge.__init__(self, {'follow_cname': False, 'propagation': 'none'}, ctx)
                self.txt, self.cn = {}, {}

            def add_txt(self, fqdn, value):
                self.txt.setdefault(fqdn, []).append(value)

            def del_txt(self, fqdn, value, handle):
                self.txt[fqdn].remove(value)

            def add_cname(self, fqdn, target):
                self.cn[fqdn] = target

            def del_cname(self, fqdn, target, handle):
                self.cn.pop(fqdn, None)
        b = Board(Ctx())
        self.assertEqual(Board.proofs_for({}), ['acme-dns-01', 'txt-any', 'cname-any'])
        h1 = b.place('txt', 'www.firma.cz', '_dnsauth.www.firma.cz', 'RND1')
        h2 = b.place('cname', 'www.firma.cz', '_dnsauth.www.firma.cz', 'rnd.dcv.digicert.com')
        self.assertEqual(b.txt, {'_dnsauth.www.firma.cz': ['RND1']})
        self.assertEqual(b.cn, {'_dnsauth.www.firma.cz': 'rnd.dcv.digicert.com'})
        self.assertTrue(b.placed_ready(h1) and b.placed_ready(h2))
        b.unplace(h1)
        b.unplace(h2)
        self.assertEqual((b.txt, b.cn), ({'_dnsauth.www.firma.cz': []}, {}))

    def test_builtin_only_in_its_zones(self):
        from acmelib.plugins.challenges.dns_builtin import BuiltinDns
        ctx = Ctx({'dns_zone': 'acme.example.net'})
        ch = BuiltinDns({}, ctx)
        with self.assertRaises(PluginError) as e:
            ch.place('txt', 'www.firma.cz', '_dnsauth.www.firma.cz', 'RND')
        self.assertIn('own zones', str(e.exception))
        ch.place('txt', 'x.acme.example.net', '_dnsauth.x.acme.example.net', 'RND')
        self.assertEqual(ctx.dns, [('_dnsauth.x.acme.example.net', 'TXT', 'RND')])

    def test_placer_says_by_hand_where_nothing_can(self):
        from acmelib.plugins.challenges.acme_dns import AcmeDns
        ctx = Ctx()

        class Iss(object):
            pass
        iss = Iss()
        iss.ctx = ctx
        iss.c = lambda k, d=None: 1 if k == 'wait_ready' else d
        iss._sleep = lambda s: None
        req = base.CertRequest(names=['www.firma.cz'],
                               challenges={'www.firma.cz': AcmeDns({}, ctx)})
        placed = _dcv.Placer(iss).place_all(req, [{'domain': 'www.firma.cz', 'type': 'txt',
                                                   'fqdn': '_dnsauth.www.firma.cz',
                                                   'value': 'RND'}])
        self.assertEqual(placed[0]['how'], 'manual')
        self.assertTrue(any('by hand' in w for _l, w in ctx.lines))


# ---------------------------------------------------------------------------
# Through a real daemon: the API, the command line, the renewer
# ---------------------------------------------------------------------------
def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class CompatDaemon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-compat-d-')
        for d in ('state', 'run', 'log', 'plugins'):
            os.makedirs(os.path.join(cls.tmp, d), exist_ok=True)
        cls.port = free_port()
        conf = {'api_port': cls.port, 'radius_bind': '127.0.0.1',
                'radius_auth_port': free_port(), 'radius_acct_port': free_port(),
                'ssh_gate_port': free_port(), 'node_name': 'testnode', 'upgrade_check': 0}
        cls.conf = os.path.join(cls.tmp, 'config.json')
        with open(cls.conf, 'w') as f:
            json.dump(conf, f)
        cls.env = dict(os.environ, ACME_CONFIG=cls.conf, ACME_STATE=os.path.join(cls.tmp, 'state'),
                       ACME_RUN=os.path.join(cls.tmp, 'run'),
                       ACME_LOGDIR=os.path.join(cls.tmp, 'log'),
                       ACME_PLUGINS=os.path.join(cls.tmp, 'plugins'), ACME_STAY_ROOT='1',
                       NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1')
        cls.pw = 'Test-Password-4711!'
        made = subprocess.run([sys.executable, '-c', (
            'import sys; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'st = acme.Storage(acme.open_db()); st.add_account("tester", "fulladmin", %r)')
            % (ROOT, cls.pw)], env=cls.env, capture_output=True, text=True, timeout=120)
        if made.returncode:
            raise RuntimeError(made.stderr[-2000:])
        cls.daemon = subprocess.Popen([sys.executable, os.path.join(ROOT, 'acme.py'), '--daemon'],
                                      env=cls.env, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, cwd=cls.tmp)
        end = time.time() + 60
        while time.time() < end:
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/api/health' % cls.port, timeout=2)
                break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.3)
        with open(os.path.join(cls.tmp, 'run', 'api-token')) as f:
            cls.token = f.read().strip()
        st, got = cls.call('POST', '/api/auth/login', {'name': 'tester', 'password': cls.pw})
        cls.admin = got['token']
        for b in ({'name': 'DC', 'kind': 'digicert', 'config': {'api_key': 'K', 'dcv': 'dns-txt'}},
                  {'name': 'SCEPsrc', 'kind': 'scep', 'config': {'url': 'https://ca.example.com/'
                                                                        'scep'}}):
            st, got = cls.call('POST', '/api/sources/save', b, cls.admin)
            assert st == 200, got
        for b in ({'name': 'own', 'kind': 'dns_builtin', 'config': {}},
                  {'name': 'desec', 'kind': 'desec', 'config': {'token': 'T'}}):
            st, got = cls.call('POST', '/api/validations/save', b, cls.admin)
            assert st == 200, got

    @classmethod
    def tearDownClass(cls):
        d = getattr(cls, 'daemon', None)
        if d is not None and d.poll() is None:
            d.send_signal(signal.SIGTERM)
            try:
                d.wait(20)
            except subprocess.TimeoutExpired:
                d.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def call(cls, method, path, body=None, session=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (cls.port, path),
                                     data=json.dumps(body).encode() if body is not None else None,
                                     method=method)
        req.add_header('X-Acme-Token', cls.token)
        req.add_header('Content-Type', 'application/json')
        if session:
            req.add_header('X-Acme-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(args),
                              env=self.env, capture_output=True, text=True, timeout=120)

    def test_save_refused_in_words(self):
        st, got = self.call('POST', '/api/certs/save', {'name': 'w1', 'names': ['www.firma.cz'],
                                                        'issuer': 'DC', 'challenge': 'own',
                                                        'auto_renew': 0}, self.admin)
        self.assertEqual(st, 400, got)
        self.assertIn('own DNS server answers only its own zones', got['error'])
        st, got = self.call('POST', '/api/certs/save', {'name': 'w2', 'names': ['a'],
                                                        'issuer': 'LetsEncrypt', 'auto_renew': 0},
                            self.admin)
        self.assertEqual(st, 400, got)
        self.assertIn('single label', got['error'])
        st, got = self.call('POST', '/api/certs/save', {'name': 'w3', 'names': ['vpn.firma.cz'],
                                                        'issuer': 'SCEPsrc', 'key_type': 'ec-256',
                                                        'auto_renew': 0}, self.admin)
        self.assertEqual(st, 400, got)
        self.assertIn('RSA', got['error'])
        st, got = self.call('POST', '/api/certs/save', {'name': 'w4', 'names': ['vpn.firma.cz'],
                                                        'issuer': 'SCEPsrc', 'key_type': 'rsa-2048',
                                                        'key_type_alt': 'ec-256',
                                                        'auto_renew': 0}, self.admin)
        self.assertEqual(st, 400, got)
        self.assertIn('no twin', got['error'])
        st, got = self.call('POST', '/api/certs/save', {'name': 'ok1', 'names': ['www.firma.cz'],
                                                        'issuer': 'DC', 'challenge': 'desec',
                                                        'auto_renew': 0}, self.admin)
        self.assertEqual(st, 200, got)
        # an edit that breaks it is refused too; one that keeps it is taken
        st, got = self.call('POST', '/api/certs/save', {'id': got['id'], 'challenge': 'own'},
                            self.admin)
        self.assertEqual(st, 400, got)

    def test_compat_endpoint(self):
        st, got = self.call('POST', '/api/certs/compat', {'names': ['*.firma.cz'],
                                                          'issuer': 'LetsEncrypt',
                                                          'challenge': 'This server HTTP-01'},
                            self.admin)
        self.assertEqual(st, 200, got)
        self.assertFalse(got['ok'])
        by = {v['name']: v for v in got['validations']}
        self.assertFalse(by['This server HTTP-01']['ok'])
        self.assertIn('wildcard', by['This server HTTP-01']['why'])
        self.assertTrue(by['desec']['ok'])

    def test_cli_refuses(self):
        got = self.cli('--cert-add', 'c1', '--names', 'srv.local', '--issuer', 'LetsEncrypt')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('never public', got.stdout + got.stderr)

    def test_renewer_fails_in_words(self):
        # a certificate that fitted, its validation changed underneath it
        code = ('import sys, json; sys.path.insert(0, %r); import acme; '
                'from acmelib import engine as E; acme.load_config(); '
                'st = acme.Storage(acme.open_db()); E.HA_STORE["store"] = st; '
                'E.load_config(saved=st.settings_saved()); '
                'from acmelib.certs import store as S, renewer, jobs; '
                'cid = st.db.insert("certs", {"name": "r1", "cn": "www.firma.cz", '
                '"names": json.dumps(["www.firma.cz"]), "key_type": "ec-256", "issuer": "DC", '
                '"challenge": "own", "challenge_map": "{}", "auto_renew": 0, "profile": "{}", '
                '"state": "new", "version": 0, "fails": 0, "enabled": 1, "ari": "{}", '
                '"source": "issuer", "tags": "[]"}); '
                'j = jobs.run_now(st, "renew", renewer.renew_job(cid, True, "t"), cert_id=cid, '
                'by="t", said="t", echo=None); '
                'print(json.dumps({"ok": j.ok, "said": j.said}))') % ROOT
        got = subprocess.run([sys.executable, '-c', code], env=self.env, capture_output=True,
                             text=True, timeout=120)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        out = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertFalse(out['ok'])
        self.assertIn('does not fit together', out['said'])


if __name__ == '__main__':
    try:
        unittest.main(verbosity=1)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
