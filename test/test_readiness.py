#!/usr/bin/env python3
"""Before the first certificate: what acme tells and tries (acmelib/certs/readiness.py,
Challenge.guide() / dry_run()).

    python3 test/test_readiness.py

No root, no internet. Two of acme's own DNS servers on one high port: the one
on 127.0.0.1 is acme's (acme.example.net), the one on 127.0.0.2 stands for the
customer's DNS (firma.cz, firma.sk and example.net, where acme.example.net is
delegated) - so the CNAMEs and the delegation are looked up for real. HTTP-01
is fetched from a little HTTP server on a high port, the names resolved by a
map. A DNS provider's API (deSEC) is answered by fakes, then by a local HTTP
server for the engine's own context. The renewer's precheck runs in this
process against a fake ACME issuer that counts how often it is asked.
"""
import http.server
import json
import os
import random
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-readiness-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "testnode", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from test_challenges import FakeCtx, MemStore, Router, plugin  # noqa: E402
from acmelib.certs.dnsserver import DnsServer  # noqa: E402
from acmelib.plugins import base  # noqa: E402
from acmelib.plugins.challenges import _common as C  # noqa: E402
from acmelib.plugins.challenges import _dns as D  # noqa: E402

ACME_ZONE = 'acme.example.net'
ACME_IP, CUST_IP = '127.0.0.1', '127.0.0.2'


def free_port_both():
    """A port free for UDP and TCP on both 127.0.0.1 and 127.0.0.2."""
    for _ in range(80):
        p = random.randint(20000, 60000)
        socks = []
        try:
            for a in (ACME_IP, CUST_IP):
                for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                    s = socket.socket(socket.AF_INET, kind)
                    socks.append(s)
                    s.bind((a, p))
            return p
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError('no free port')


PORT = free_port_both()
RESOLVERS = ['%s:%d' % (ACME_IP, PORT), '%s:%d' % (CUST_IP, PORT)]

ACME_CFG = {'dns_server': 1, 'dns_listen': ACME_IP, 'dns_port': PORT, 'dns_zone': ACME_ZONE,
            'dns_ns_names': 'ns1.' + ACME_ZONE, 'dns_ns_addresses': ACME_IP,
            'dns_soa_mail': 'hostmaster@example.net', 'dns_ttl': 60, 'dns_static': '',
            'dns_rate': 0, 'dns_cache': 0.2, 'acme_resolvers': ','.join(RESOLVERS)}
CUSTOMER = '\n'.join([
    # firma.cz: www pointed at acme, wrong pointed elsewhere, shop not at all
    '_acme-challenge.www.firma.cz. CNAME www.firma.cz.acme.example.net.',
    '_acme-challenge.firma.cz. CNAME firma.cz.acme.example.net.',
    '_acme-challenge.wrong.firma.cz. CNAME somewhere.example.net.',
    'www.firma.cz. A 127.0.0.1',
    'elsewhere.firma.cz. A 192.0.2.99',
    'shop.firma.cz. A 127.0.0.1',
    'firma.sk. A 127.0.0.1',
    # acme's zone delegated to acme from example.net, with its glue
    'acme.example.net. NS ns1.acme.example.net.',
    'ns1.acme.example.net. A 127.0.0.1',
])
CUST_CFG = {'dns_listen': CUST_IP, 'dns_port': PORT, 'dns_zone': 'firma.cz,firma.sk,example.net',
            'dns_ns_names': 'ns.firma.cz', 'dns_ns_addresses': CUST_IP,
            'dns_soa_mail': 'hostmaster@firma.cz', 'dns_ttl': 60, 'dns_static': CUSTOMER,
            'dns_rate': 0, 'dns_cache': 1.0}

SERVERS = {}


def setUpModule():
    SERVERS['acme_store'] = MemStore()
    SERVERS['acme'] = DnsServer(SERVERS['acme_store'], ACME_CFG)
    SERVERS['cust'] = DnsServer(MemStore(), CUST_CFG)
    for k in ('acme', 'cust'):
        st = SERVERS[k].start()
        if not st['listening']:
            raise unittest.SkipTest('the DNS servers cannot listen here: %s' % st['failed'])
    # every zone's name servers asked straight on the test port
    SERVERS['auth_port'] = C.DnsChallenge.auth_port
    C.DnsChallenge.auth_port = PORT


def tearDownModule():
    C.DnsChallenge.auth_port = SERVERS.get('auth_port', 53)
    for k in ('acme', 'cust'):
        if SERVERS.get(k):
            SERVERS[k].stop()


def by_key(guide, key):
    return [s for s in guide['steps'] if s['key'] == key]


# ---------------------------------------------------------------------------
# acme's own DNS server (dns_builtin)
# ---------------------------------------------------------------------------
class TestBuiltinGuide(unittest.TestCase):
    def module(self, **cfg):
        cfg.setdefault('resolvers', RESOLVERS)
        cfg.setdefault('public_resolvers', RESOLVERS)
        m = plugin('dns_builtin')(cfg, FakeCtx(SERVERS['acme_store'], settings=ACME_CFG))
        m.dry_every = 0.2
        return m

    def test_guide_all_in_place(self):
        g = self.module().guide('www.firma.cz')
        self.assertTrue(g['ok'], json.dumps(g, indent=1))
        self.assertEqual(by_key(g, 'server')[0]['done'], True)
        deleg = by_key(g, 'delegation')[0]
        self.assertEqual(deleg['record'], {'name': ACME_ZONE, 'type': 'NS',
                                           'value': 'ns1.acme.example.net.', 'ttl': 3600})
        self.assertTrue(deleg['done'])
        self.assertIn('example.net', deleg['where'])
        glue = by_key(g, 'glue')[0]
        self.assertEqual((glue['record']['type'], glue['record']['value'], glue['done']),
                         ('A', ACME_IP, True))
        cname = by_key(g, 'cname')[0]
        self.assertEqual(cname['record']['name'], '_acme-challenge.www.firma.cz')
        self.assertEqual(cname['record']['value'], 'www.firma.cz.acme.example.net.')
        self.assertTrue(cname['done'])
        self.assertEqual(cname['where'], 'your DNS at firma.cz')
        # a wildcard is proved at its base name, the same CNAME
        g2 = self.module().guide('*.firma.cz')
        self.assertEqual(by_key(g2, 'cname')[0]['record']['value'], 'firma.cz.acme.example.net.')
        self.assertTrue(g2['ok'])

    def test_guide_missing_and_wrong_cname(self):
        g = self.module().guide('shop.firma.cz')
        self.assertFalse(g['ok'])
        c = by_key(g, 'cname')[0]
        self.assertFalse(c['done'])
        self.assertTrue(c['blocking'])
        self.assertIn('_acme-challenge.shop.firma.cz. CNAME shop.firma.cz.acme.example.net.',
                      c['fix'])
        self.assertIn('firma.cz', c['fix'])
        g = self.module().guide('wrong.firma.cz')
        c = by_key(g, 'cname')[0]
        self.assertFalse(c['done'])
        self.assertIn('somewhere.example.net', c['said'])
        self.assertIn('Change the CNAME', c['fix'])

    def test_guide_label_scheme(self):
        g = self.module(scheme='label', label='all').guide('www.firma.cz')
        c = by_key(g, 'cname')[0]
        self.assertEqual(c['record']['value'], 'all.acme.example.net.')
        self.assertFalse(c['done'])             # www points at www.firma.cz.acme..., not all.

    def test_guide_no_zone(self):
        m = plugin('dns_builtin')({}, FakeCtx(MemStore(), settings={}))
        g = m.guide('www.firma.cz')
        self.assertFalse(g['ok'])
        self.assertIn('Settings → DNS server', g['steps'][0]['fix'])

    def test_dry_run_works_and_cleans_up(self):
        m = self.module()
        g = m.dry_run('www.firma.cz', wait=10)
        self.assertTrue(g['ok'], json.dumps(g, indent=1))
        self.assertTrue(by_key(g, 'present')[0]['done'])
        self.assertTrue(by_key(g, 'ready')[0]['done'])
        self.assertTrue(by_key(g, 'cname')[0]['done'])
        self.assertTrue(by_key(g, 'authoritative')[0]['done'])
        self.assertEqual(SERVERS['acme_store'].db.rows('SELECT * FROM dns_records'), [])
        lines = [w for _l, w in m.ctx.steps]
        self.assertTrue(any(w.startswith('Dry run for www.firma.cz') for w in lines), lines)
        self.assertTrue(any('taken away again' in w for w in lines), lines)

    def test_dry_run_without_cname_fails(self):
        m = self.module()
        g = m.dry_run('shop.firma.cz', wait=5)
        self.assertFalse(g['ok'])
        c = by_key(g, 'cname')[0]
        self.assertFalse(c['done'])
        self.assertIn('CNAME shop.firma.cz.acme.example.net.', c['fix'])
        self.assertEqual(SERVERS['acme_store'].db.rows('SELECT * FROM dns_records'), [])

    def test_dry_run_server_down_says_so(self):
        cfg = dict(ACME_CFG, dns_port=free_port_both())
        m = plugin('dns_builtin')({'resolvers': RESOLVERS}, FakeCtx(MemStore(), settings=cfg))
        m.dry_every = 0.1
        g = m.dry_run('www.firma.cz', wait=1)
        self.assertFalse(g['ok'])
        self.assertFalse(by_key(g, 'ready')[0]['done'])


# ---------------------------------------------------------------------------
# HTTP-01 answered by acme (http_local)
# ---------------------------------------------------------------------------
class TokenServer(http.server.BaseHTTPRequestHandler):
    tokens = {}
    hosts = []

    def do_GET(self):
        self.hosts.append(self.headers.get('Host'))
        prefix = '/.well-known/acme-challenge/'
        tok = self.path[len(prefix):] if self.path.startswith(prefix) else None
        body = self.tokens.get(tok)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        data = body.encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class HttpCtx(FakeCtx):
    """Plain HTTP for real (no proxy), a name resolved by `names`."""
    def __init__(self, tokens, names, port_open=True, probe=None):
        FakeCtx.__init__(self)
        self.tokens = tokens
        self.names = names
        self._open = port_open
        self._probe = probe

    def http(self, method, url, body=None, headers=None, timeout=30, verify=True, ca_pem=None,
             client_cert=None, proxy=True):
        u = urllib.parse.urlsplit(url)
        headers = dict(headers or {})
        host = u.hostname
        if host in self.names:
            headers.setdefault('Host', host)
            if not self.names[host]:
                raise base.PluginError('%s does not resolve' % host)
            url = url.replace('//' + host, '//' + self.names[host][0], 1)
        req = urllib.request.Request(url, headers=headers, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=5) as r:
                return r.status, dict(r.headers.items()), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers.items()), e.read()
        except OSError as e:
            raise base.PluginError('%s could not be reached: %s' % (u.netloc, e))

    def own_addresses(self):
        return {'vip': None, 'nodes': ['127.0.0.1']}

    def port_open(self, proto, port):
        return self._open

    def http_probe(self):
        return self._probe


class TestHttpLocal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), TokenServer)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    NAMES = {'www.firma.cz': ['127.0.0.1'], 'elsewhere.firma.cz': ['192.0.2.99'],
             'none.firma.cz': []}

    def module(self, cfg=None, **kw):
        TokenServer.tokens.clear()
        ctx = HttpCtx(TokenServer.tokens, self.NAMES, **kw)
        m = plugin('http_local')(cfg or {}, ctx)
        m.http_port = self.port
        m.lookup = lambda n: list(self.NAMES.get(D.norm(n), []))
        m.dry_every = 0.1
        return m

    def test_guide_points_at_acme(self):
        m = self.module(probe=('acme-guide-probe-0001', 'acme-guide-probe-0001.ka'))
        TokenServer.tokens['acme-guide-probe-0001'] = 'acme-guide-probe-0001.ka'
        g = m.guide('www.firma.cz')
        self.assertTrue(g['ok'], json.dumps(g, indent=1))
        self.assertTrue(by_key(g, 'address')[0]['done'])
        self.assertTrue(by_key(g, 'port80')[0]['done'])
        self.assertTrue(by_key(g, 'probe')[0]['done'])
        self.assertIn('www.firma.cz', TokenServer.hosts)

    def test_guide_refuses_a_wildcard(self):
        g = self.module().guide('*.firma.cz')
        self.assertFalse(g['ok'])
        self.assertEqual(g['steps'][0]['key'], 'wildcard')
        self.assertIn('DNS', g['steps'][0]['fix'])

    def test_guide_elsewhere_missing_and_firewall(self):
        g = self.module(port_open=False).guide('elsewhere.firma.cz')
        self.assertFalse(g['ok'])
        a = by_key(g, 'address')[0]
        self.assertIn('192.0.2.99', a['said'])
        self.assertIn('Addresses in front of acme', a['fix'])
        self.assertTrue(by_key(g, 'port80')[0]['blocking'])
        # a NAT in front of acme: that address counts
        g = self.module({'public_addresses': ['192.0.2.99']}).guide('elsewhere.firma.cz')
        self.assertTrue(by_key(g, 'address')[0]['done'])
        g = self.module().guide('none.firma.cz')
        a = by_key(g, 'address')[0]
        self.assertEqual(a['record'], {'name': 'none.firma.cz', 'type': 'A',
                                       'value': '127.0.0.1', 'ttl': None})
        self.assertIn('none.firma.cz. A 127.0.0.1', a['fix'])

    def test_dry_run(self):
        m = self.module()
        g = m.dry_run('www.firma.cz', wait=3)
        self.assertTrue(g['ok'], json.dumps(g, indent=1))
        self.assertTrue(by_key(g, 'by_name')[0]['done'])
        self.assertTrue(by_key(g, 'by_address')[0]['done'])
        self.assertEqual(TokenServer.tokens, {})          # taken away again
        g = self.module().dry_run('*.firma.cz', wait=1)
        self.assertFalse(g['ok'])
        self.assertFalse(by_key(g, 'present')[0]['done'])


# ---------------------------------------------------------------------------
# A DNS provider's API (ApiDns, here deSEC)
# ---------------------------------------------------------------------------
class TestApiDnsGuide(unittest.TestCase):
    def module(self, router, **cfg):
        cfg.setdefault('resolvers', RESOLVERS)
        cfg.setdefault('token', 'tok')
        return plugin('desec')(cfg, FakeCtx(http=router))

    def router(self, zones=('firma.cz',), status=200):
        r = Router()
        r.on('GET', 'https://desec.io/api/v1/domains/', lambda u, b, h: (
            status, [{'name': z, 'minimum_ttl': 3600} for z in zones] if status == 200
            else {'detail': 'Invalid token.'}))
        return r

    def test_zone_at_the_provider(self):
        g = self.module(self.router()).guide('mail.firma.cz')
        self.assertTrue(g['ok'], json.dumps(g, indent=1))
        self.assertTrue(by_key(g, 'access')[0]['done'])
        z = by_key(g, 'zone')[0]
        self.assertTrue(z['done'])
        self.assertIn('firma.cz', z['said'])
        self.assertTrue(by_key(g, 'delegated')[0]['done'])
        w = by_key(g, 'wait')[0]
        self.assertIn('TTL 3600 s', w['said'])
        self.assertIn('anycast', w['said'])
        txt = by_key(g, 'txt')[0]
        self.assertEqual(txt['record']['name'], '_acme-challenge.mail.firma.cz')

    def test_cname_elsewhere_tells_which_zone(self):
        g = self.module(self.router()).guide('www.firma.cz')
        c = by_key(g, 'cname')[0]
        self.assertIn('www.firma.cz.acme.example.net', c['said'])
        z = by_key(g, 'zone')[0]
        self.assertFalse(z['done'])
        self.assertIn('www.firma.cz.acme.example.net', z['said'])
        self.assertFalse(g['ok'])

    def test_zone_not_there(self):
        g = self.module(self.router(zones=('other.cz',))).guide('mail.firma.cz')
        z = by_key(g, 'zone')[0]
        self.assertFalse(z['done'])
        self.assertIn('deSEC', z['fix'])
        self.assertEqual(z['record']['type'], 'CNAME')

    def test_credentials_wrong(self):
        g = self.module(self.router(status=401)).guide('mail.firma.cz')
        a = by_key(g, 'access')[0]
        self.assertFalse(a['done'])
        self.assertIn('401', a['said'])
        self.assertIsNone(by_key(g, 'zone')[0]['done'])
        self.assertFalse(g['ok'])

    def test_a_delegated_subzone_elsewhere(self):
        # the provider holds example.net, but acme.example.net is delegated to acme
        g = self.module(self.router(zones=('example.net',))).guide('www.firma.cz')
        d = by_key(g, 'delegated')[0]
        self.assertFalse(d['done'])
        self.assertIn('acme.example.net', d['said'])


class TestRegistrable(unittest.TestCase):
    def test_suffixes(self):
        self.assertEqual(D.registrable('shop.firma.co.uk'), 'firma.co.uk')
        self.assertEqual(D.registrable('*.www.firma.cz'), 'firma.cz')
        self.assertEqual(D.registrable('a.b.firma.com.au'), 'firma.com.au')
        self.assertEqual(D.registrable('firma.sk'), 'firma.sk')

    def test_guide_step_shape(self):
        s = base.guide_step('x', 'What', done=False, fix='do it', blocking=False)
        self.assertEqual(set(s), {'key', 'what', 'where', 'record', 'done', 'said', 'fix',
                                  'blocking'})
        self.assertIsNone(base.guide_of([s])['ok'])
        self.assertFalse(base.guide_of([base.guide_step('y', 'Y', done=False)])['ok'])
        self.assertTrue(base.guide_of([base.guide_step('y', 'Y', done=True), s])['ok'])
        # an old module: guide() and dry_run() of the base contract
        m = plugin('script')({'path': '/nonexistent'}, FakeCtx())
        self.assertIn('ok', m.guide('www.firma.cz'))


# ---------------------------------------------------------------------------
# The engine: grouping, suggestions, the renewer's precheck
# ---------------------------------------------------------------------------
class DesecApi(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.rstrip('/').endswith('/domains'):
            data = json.dumps([{'name': 'firma.cz', 'minimum_ttl': 3600}]).encode()
            self.send_response(200)
        else:
            data = b'{"detail": "Not found."}'
            self.send_response(404)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class FakeAcme(base.Issuer):
    kind = 'fakeacme'
    title = 'A CA that counts'
    needs_challenge = True
    challenge_types = ('dns-01', 'http-01')
    calls = []

    def issue(self, req):
        FakeAcme.calls.append(list(req.names))
        raise base.PluginError('the fake CA says no')


class TestEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import acme as E
        from acmelib.certs import readiness, renewer, runtime, store as S
        cls.E, cls.R, cls.S, cls.renewer = E, readiness, S, renewer
        cls.store = E.Storage(E.open_db())
        E.CONFIG.update({k: v for k, v in ACME_CFG.items()})
        E.CONFIG['certs_dry_run_s'] = 15
        # acme's DNS server answers what the engine's jobs put in (dns_records)
        cls._mem = SERVERS['acme'].store
        SERVERS['acme'].store = cls.store
        S.registry()
        base.REGISTRY.found['issuer']['fakeacme'] = FakeAcme
        cls.api = http.server.ThreadingHTTPServer(('127.0.0.1', 0), DesecApi)
        threading.Thread(target=cls.api.serve_forever, daemon=True).start()
        cls.api_url = 'http://127.0.0.1:%d/api/v1' % cls.api.server_address[1]
        cls._own = runtime.RunContext.own_addresses
        runtime.RunContext.own_addresses = lambda self: {'vip': None, 'nodes': ['127.0.0.1']}
        cls.add('cert_issuers', 'fake', 'fakeacme', {})
        cls.add('cert_challenges', 'desec', 'desec', {'token': 'tok', 'api': cls.api_url,
                                                      'propagation': 'none'})
        cls.add('cert_challenges', 'builtin', 'dns_builtin', {})
        cls.add('cert_challenges', 'here', 'http_local', {})

    @classmethod
    def tearDownClass(cls):
        from acmelib.certs import runtime
        runtime.RunContext.own_addresses = cls._own
        SERVERS['acme'].store = cls._mem
        cls.api.shutdown()

    @classmethod
    def add(cls, table, name, kind, cfg):
        S = cls.S
        family = {'cert_issuers': 'issuer', 'cert_challenges': 'challenge'}[table]
        ident = cls.store.db.insert(table, {'name': name, 'kind': kind, 'config': '{}',
                                            'enabled': 1, 'created': time.time(),
                                            'updated': time.time()})
        sealed = S.config_seal(cfg, {}, '%s:%s' % (table, ident),
                               S.secret_fields(S.plugin_class(family, kind)))
        cls.store.db.update(table, ident, {'config': json.dumps(sealed)})
        return ident

    def setUp(self):
        self.R.forget()

    NAMES = ['firma.cz', 'www.firma.cz', '*.firma.cz', 'firma.sk', 'shop.firma.co.uk']

    def test_groups_by_domain_as_the_renewer_chooses(self):
        cmap = {'*.firma.cz': 'desec', 'firma.sk': 'builtin'}
        got = self.R.plan(self.store, self.NAMES, issuer='fake', challenge='here',
                          challenge_map=cmap)
        self.assertTrue(got['issuer_needs_validation'])
        groups = {(g['domain'], g['validation']): g['names'] for g in got['groups']}
        self.assertEqual(groups, {('firma.cz', 'desec'): ['firma.cz', 'www.firma.cz', '*.firma.cz'],
                                  ('firma.sk', 'builtin'): ['firma.sk'],
                                  ('firma.co.uk', 'here'): ['shop.firma.co.uk']})
        cert = {'challenge': 'here', 'challenge_map': json.dumps(cmap)}
        for g in got['groups']:
            for n in g['names']:
                self.assertEqual(self.S.challenge_for(cert, n), g['validation'])
        kinds = {g['domain']: g['kind'] for g in got['groups']}
        self.assertEqual(kinds, {'firma.cz': 'desec', 'firma.sk': 'dns_builtin',
                                 'firma.co.uk': 'http_local'})
        # www.firma.cz is a CNAME to acme's zone: the deSEC zone does not hold it
        self.assertFalse(got['ok'])
        self.assertTrue(any(b['name'] == 'www.firma.cz' and b['key'] == 'zone'
                            for b in got['blocking']), got['blocking'])
        # firma.sk has no CNAME to acme yet: exactly what to create, and where
        sk = [g for g in got['groups'] if g['domain'] == 'firma.sk'][0]
        c = [s for s in sk['guide']['steps'] if s['key'] == 'cname'][0]
        self.assertEqual(c['record']['value'], 'firma.sk.acme.example.net.')
        self.assertEqual(c['where'], 'your DNS at firma.sk')
        self.assertLess(got['took_ms'], 60000)

    def test_suggestions(self):
        got = self.R.plan(self.store, ['www.firma.cz', '*.firma.cz'], issuer='fake',
                          challenge='here')
        g, = got['groups']
        self.assertEqual(g['validation'], 'here')
        self.assertFalse(g['guide']['ok'])               # a wildcard by HTTP-01
        sugg = [s['validation'] for s in g['suggested']]
        self.assertEqual(sugg[0], 'desec')               # the zone is at deSEC: first
        self.assertIn('builtin', sugg)
        self.assertNotIn('here', sugg)
        self.assertIn('firma.cz', g['suggested'][0]['why'])
        # names that point at acme, no wildcard: HTTP-01 here is suggested
        got = self.R.plan(self.store, ['firma.sk'], issuer='fake', challenge='builtin')
        sugg = [s['validation'] for s in got['groups'][0]['suggested']]
        self.assertIn('here', sugg)
        self.assertNotIn('desec', sugg)                  # deSEC holds no firma.sk

    def test_check_only_suggests_when_blocking(self):
        got = self.R.check(self.store, ['www.firma.cz'], issuer='fake', challenge='builtin')
        self.assertTrue(got['ok'], json.dumps(got, indent=1))
        self.assertEqual(got['groups'][0]['suggested'], [])

    def test_no_validation_needed(self):
        self.add('cert_issuers', 'selfie', 'selfsigned', {})
        got = self.R.plan(self.store, self.NAMES, issuer='selfie')
        self.assertFalse(got['issuer_needs_validation'])
        self.assertTrue(got['ok'])
        self.assertEqual(sorted(g['domain'] for g in got['groups']),
                         ['firma.co.uk', 'firma.cz', 'firma.sk'])

    def test_dry_run_job(self):
        from acmelib.certs import jobs
        jid = self.R.dry_run(self.store, ['www.firma.cz', 'shop.firma.cz'], challenge='builtin',
                             by='test')
        end = time.time() + 60
        while time.time() < end:
            v = jobs.job_view(self.store, jid)
            if v['state'] not in ('queued', 'running'):
                break
            time.sleep(0.2)
        self.assertEqual(v['kind'], 'dry-run')
        self.assertEqual(v['state'], 'failed', v)           # shop has no CNAME
        words = ' '.join(s[2] for s in v['steps'])
        self.assertIn('Dry run for www.firma.cz', words)
        self.assertIn('CNAME shop.firma.cz.acme.example.net.', words)
        res = self.R.dry_run_result(self.store, jid)
        self.assertFalse(res['ok'])
        self.assertEqual([b['name'] for b in res['blocking']], ['shop.firma.cz'])
        self.assertEqual(self.store.db.rows('SELECT * FROM dns_records'), [])

    def cert(self, name, names, challenge):
        return self.store.db.insert('certs', {
            'name': name, 'names': json.dumps(names), 'issuer': 'fake', 'challenge': challenge,
            'challenge_map': '{}', 'key_type': 'ec-256', 'auto_renew': 1, 'state': 'new',
            'enabled': 1, 'created': time.time()})

    def renew(self, cid):
        from acmelib.certs import jobs
        return jobs.run_now(self.store, 'renew', self.renewer.renew_job(cid, by='test'),
                            cert_id=cid, by='test')

    def test_precheck_keeps_the_ca_out(self):
        FakeAcme.calls[:] = []
        cid = self.cert('shop', ['shop.firma.cz'], 'builtin')
        job = self.renew(cid)
        self.assertFalse(job.ok)
        self.assertEqual(FakeAcme.calls, [])             # the CA was never asked
        row = self.S.cert_get(self.store, cid)
        self.assertEqual(row['state'], 'failed')
        self.assertIn('the CA was not asked', row['last_error'])
        self.assertIn('_acme-challenge.shop.firma.cz. CNAME shop.firma.cz.acme.example.net.',
                      row['last_error'])
        words = '\n'.join(s[2] for s in job.steps)
        self.assertIn('certs_precheck', words)
        self.assertIn('The name is pointed at acme\'s DNS server by a CNAME', words)
        self.assertTrue(self.store.get_meta(self.R.FAILED_KEY + str(cid)))
        # switched off: the CA is asked (and here says no)
        self.E.CONFIG['certs_precheck'] = 0
        try:
            self.store.db.update('certs', cid, {'state': 'new'})
            job = self.renew(cid)
        finally:
            self.E.CONFIG['certs_precheck'] = 1
        self.assertEqual(FakeAcme.calls, [['shop.firma.cz']])
        self.assertIn('the fake CA says no', self.S.cert_get(self.store, cid)['last_error'])

    def test_precheck_lets_a_ready_name_through(self):
        FakeAcme.calls[:] = []
        cid = self.cert('www', ['www.firma.cz'], 'builtin')
        job = self.renew(cid)
        words = '\n'.join(s[2] for s in job.steps)
        self.assertIn('the validation looks ready', words)
        self.assertEqual(FakeAcme.calls, [['www.firma.cz']])

    def test_failed_on_validation(self):
        self.assertTrue(self.R.failed_on_validation(base.PluginError(
            'the CA did not accept www.firma.cz: unauthorized')))
        self.assertFalse(self.R.failed_on_validation(base.PluginError('the CA did not answer')))
        self.assertTrue(self.R.precheck_due(self.store, {'id': 1, 'cert_pem': ''}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
