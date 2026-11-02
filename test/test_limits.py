#!/usr/bin/env python3
"""Kind to other people's servers (acmelib/plugins/limits.py, RunContext.http):
one sign-in per module and its settings, shared reads, a 429 waited out and
asked again once, a host held after "Too Many Attempts", at most two
requests at once to a host, Let's Encrypt's limits for new accounts.

    python3 -m unittest test/test_limits.py -v

No network: a Webglobe-like API on a local port counts its sign-ins and
calls; a DNS server of acme's own answers the zone; the clock of the waits
is a fake one.
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
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-limits-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "testnode", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from test_challenges import MemStore                        # noqa: E402
from acmelib.certs.dnsserver import DnsServer                # noqa: E402
from acmelib.plugins import base, limits as L                # noqa: E402
from acmelib.plugins.challenges import _common as C          # noqa: E402


def free_port():
    for _ in range(80):
        p = random.randint(20000, 60000)
        socks = []
        try:
            for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                s = socket.socket(socket.AF_INET, kind)
                socks.append(s)
                s.bind(('127.0.0.1', p))
            return p
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError('no free port')


DNS_PORT = free_port()
ZONE_RECS = '\n'.join(['www.firma.cz. A 192.0.2.10'] + [
    'site%d.firma.cz. A 192.0.2.%d' % (i, 20 + i) for i in range(1, 7)])
DNS_CFG = {'dns_listen': '127.0.0.1', 'dns_port': DNS_PORT, 'dns_zone': 'firma.cz',
           'dns_ns_names': 'ns.firma.cz', 'dns_ns_addresses': '127.0.0.1',
           'dns_soa_mail': 'hostmaster@firma.cz', 'dns_ttl': 60, 'dns_static': ZONE_RECS,
           'dns_rate': 0, 'dns_cache': 1.0}


# ---------------------------------------------------------------------------
# A Webglobe-like API that counts
# ---------------------------------------------------------------------------
class World(object):
    def __init__(self):
        self.reset()

    def reset(self):
        self.lock = threading.Lock()
        self.logins = 0
        self.login_tries = 0
        self.calls = []
        self.jwts = set()
        self.expired = set()
        self.too_many = False
        self.limit_429 = 0              # this many answers 429 (Retry-After: 1) first
        self.records = {11: []}
        self.next_id = 100
        self.active = 0
        self.most = 0


WORLD = World()


class WebglobeApi(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def answer(self, st, obj, headers=None):
        data = json.dumps(obj).encode()
        self.send_response(st)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        return json.loads(self.rfile.read(n) or b'{}') if n else {}

    def handle_one(self, method):
        w = WORLD
        with w.lock:
            w.active += 1
            w.most = max(w.most, w.active)
        try:
            time.sleep(0.01)
            path = urllib.parse.urlsplit(self.path).path
            with w.lock:
                w.calls.append((method, path))
                if w.limit_429 > 0 and path == '/slow':
                    w.limit_429 -= 1
                    return self.answer(429, {'message': 'Too Many Requests'},
                                       {'Retry-After': '1'})
            if path == '/slow':
                return self.answer(200, {'ok': True})
            if path == '/auth/login':
                b = self.body()
                with w.lock:
                    w.login_tries += 1
                    if w.too_many:
                        return self.answer(400, {'success': False, 'error': {
                            'code': 1, 'message': 'Too Many Attempts'}})
                    if b.get('login') != 'me@firma.cz' or b.get('token') != 'key1':
                        return self.answer(400, {'success': False, 'error': {
                            'code': 5, 'message': 'Incorrect login name or password.'}})
                    w.logins += 1
                    jwt = 'jwt-%d' % w.logins
                    w.jwts.add(jwt)
                return self.answer(200, {'success': True, 'data': {
                    'token': jwt, 'token_type': 'bearer', 'expires_in': 3600}})
            auth = self.headers.get('Authorization', '')
            if not auth.startswith('Bearer ') or auth[7:] not in w.jwts or \
                    auth[7:] in w.expired:
                return self.answer(401, {'message': 'Unauthenticated.'})
            if path == '/domains':
                return self.answer(200, {'success': True, 'data': {
                    '11': {'domain': 'firma.cz', 'domain_id': 11}}})
            if path == '/11/dns' and method == 'GET':
                return self.answer(200, {'success': True, 'data': {
                    'records': list(w.records[11]), 'soa': {'ttl': 3600}}})
            if path == '/11/dns' and method == 'POST':
                b = self.body()
                with w.lock:
                    w.next_id += 1
                    rec = dict(b, id=w.next_id)
                    w.records[11].append(rec)
                return self.answer(200, {'success': True, 'new_id': rec['id']})
            if path.startswith('/11/dns/') and method == 'DELETE':
                rid = int(path.rsplit('/', 1)[1])
                with w.lock:
                    before = len(w.records[11])
                    w.records[11] = [r for r in w.records[11] if r['id'] != rid]
                    gone = before != len(w.records[11])
                if not gone:
                    return self.answer(400, {'success': False, 'error': {
                        'code': 1180, 'message': 'Record not found.'}})
                return self.answer(200, {'success': True})
            return self.answer(404, {'message': 'no such call %s %s' % (method, path)})
        finally:
            with w.lock:
                w.active -= 1

    def do_GET(self):
        self.handle_one('GET')

    def do_POST(self):
        self.handle_one('POST')

    def do_DELETE(self):
        self.handle_one('DELETE')

    def log_message(self, *a):
        pass


SERVERS = {}


def setUpModule():
    SERVERS['dns'] = DnsServer(MemStore(), DNS_CFG)
    st = SERVERS['dns'].start()
    if not st['listening']:
        raise unittest.SkipTest('the DNS server cannot listen here: %s' % st['failed'])
    SERVERS['auth_port'] = C.DnsChallenge.auth_port
    C.DnsChallenge.auth_port = DNS_PORT
    api = http.server.ThreadingHTTPServer(('127.0.0.1', 0), WebglobeApi)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    SERVERS['api'] = api
    SERVERS['url'] = 'http://127.0.0.1:%d' % api.server_address[1]


def tearDownModule():
    C.DnsChallenge.auth_port = SERVERS.get('auth_port', 53)
    if SERVERS.get('dns'):
        SERVERS['dns'].stop()
    if SERVERS.get('api'):
        SERVERS['api'].shutdown()


class Clock(object):
    """The waits of limits.py on a clock of its own: nothing really waits."""
    def __init__(self):
        self.t = time.time()
        self.slept = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import acme as E
        from acmelib.certs import readiness, runtime, store as S
        cls.E, cls.R, cls.S, cls.runtime = E, readiness, S, runtime
        cls.store = E.Storage(E.open_db())
        E.CONFIG['acme_resolvers'] = '127.0.0.1:%d' % DNS_PORT
        S.registry()

    def setUp(self):
        L.forget()
        self.R.forget()
        WORLD.reset()
        self._saved = (L.NOW, L.SLEEP, L.LOCAL_FREE)

    def tearDown(self):
        L.NOW, L.SLEEP, L.LOCAL_FREE = self._saved
        L.forget()

    def clock(self):
        c = Clock()
        L.NOW, L.SLEEP = c.now, c.sleep
        return c

    def ctx(self, scope='challenge:test'):
        return self.runtime.RunContext(self.store, None, scope=scope)

    @classmethod
    def add(cls, table, name, kind, cfg):
        S = cls.S
        old = S.plugin_row(cls.store, {'cert_issuers': 'issuer',
                                       'cert_challenges': 'challenge'}[table], name)
        if old:
            cls.store.db.run('DELETE FROM %s WHERE id = ?' % table, (old['id'],))
        family = {'cert_issuers': 'issuer', 'cert_challenges': 'challenge'}[table]
        ident = cls.store.db.insert(table, {'name': name, 'kind': kind, 'config': '{}',
                                            'enabled': 1, 'created': time.time(),
                                            'updated': time.time()})
        sealed = S.config_seal(cfg, {}, '%s:%s' % (table, ident),
                               S.secret_fields(S.plugin_class(family, kind)))
        cls.store.db.update(table, ident, {'config': json.dumps(sealed)})
        return ident

    def webglobe(self, **more):
        cfg = {'login': 'me@firma.cz', 'api_token': 'key1', 'api': SERVERS['url'],
               'propagation': 'none'}
        cfg.update(more)
        return cfg


# ---------------------------------------------------------------------------
# One sign-in per module and its settings
# ---------------------------------------------------------------------------
class TestOneSignIn(Base):
    def test_readiness_of_six_certificates_signs_in_once(self):
        from acmelib.certs import api, cli          # noqa: F401  (the routes)
        self.add('cert_challenges', 'wg', 'webglobe', self.webglobe())
        self.store.db.run('DELETE FROM certs')
        for i in range(1, 7):
            self.store.db.insert('certs', {
                'name': 'site%d' % i, 'names': json.dumps(['site%d.firma.cz' % i]),
                'issuer': '', 'challenge': 'wg', 'challenge_map': '{}', 'key_type': 'ec-256',
                'auto_renew': 1, 'state': 'new', 'enabled': 1, 'created': time.time()})
        d = cli._Daemon(self.store)
        got = self.E.cli_api(d, 'command line', 'GET', '/api/validations/setup',
                             args={'name': 'wg'})
        self.assertEqual(len(got['certs']), 6)
        for c in got['certs']:
            access = [st for st in c['steps'] if st['key'] == 'access']
            self.assertTrue(all(st['done'] for st in access), c)
        self.assertEqual(WORLD.logins, 1, WORLD.calls)
        self.assertEqual(WORLD.calls.count(('GET', '/domains')), 1, WORLD.calls)
        # "Check again" right after: the API is not asked again
        n = len(WORLD.calls)
        self.E.cli_api(d, 'command line', 'GET', '/api/validations/setup', args={'name': 'wg'})
        self.assertEqual(len(WORLD.calls), n)
        # other settings: a sign-in of their own
        self.add('cert_challenges', 'wg', 'webglobe', self.webglobe(ttl=600))
        self.E.cli_api(d, 'command line', 'GET', '/api/validations/setup', args={'name': 'wg'})
        self.assertEqual(WORLD.logins, 2)

    def test_two_runs_share_the_token_and_a_401_signs_in_once_more(self):
        from acmelib.plugins.challenges.webglobe import Webglobe
        a = Webglobe(self.webglobe(), self.ctx())
        b = Webglobe(self.webglobe(), self.ctx())
        a.present('www.firma.cz', 't', 'k', 'v1')
        b.present('www.firma.cz', 't', 'k', 'v2')
        self.assertEqual(WORLD.logins, 1)
        WORLD.expired.add('jwt-1')
        h = b.present('www.firma.cz', 't', 'k', 'v3')
        self.assertEqual(WORLD.logins, 2)
        a.present('www.firma.cz', 't', 'k', 'v4')       # the new token, shared
        self.assertEqual(WORLD.logins, 2)
        b.cleanup('www.firma.cz', h)
        self.assertEqual(sorted(r['data'] for r in WORLD.records[11]), ['v1', 'v2', 'v4'])

    def test_many_at_once_sign_in_once(self):
        from acmelib.plugins.challenges.webglobe import Webglobe
        errs = []

        def one():
            try:
                Webglobe(self.webglobe(), self.ctx()).wg.token()
            except Exception as e:                      # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=one) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        self.assertEqual(errs, [])
        self.assertEqual(WORLD.logins, 1)

    def test_a_refused_sign_in_is_not_tried_again_at_once(self):
        from acmelib.plugins.challenges.webglobe import Webglobe
        for _ in range(4):
            m = Webglobe(self.webglobe(api_token='wrong'), self.ctx())
            with self.assertRaises(base.PluginError) as e:
                m.test()
            self.assertIn('did not take the login and API key', str(e.exception))
        self.assertEqual(WORLD.login_tries, 1)

    def test_too_many_attempts_holds_the_host(self):
        from acmelib.plugins.challenges.webglobe import Webglobe
        L.LOCAL_FREE = False
        WORLD.too_many = True
        ctx = self.ctx()
        m = Webglobe(self.webglobe(), ctx)
        with self.assertRaises(base.PluginError) as e:
            m.test()
        self.assertIn('Too Many Attempts', str(e.exception))
        self.assertIn('asks acme to slow down', str(e.exception))
        self.assertTrue(e.exception.retry)
        self.assertGreater(L.held(SERVERS['url']), 30)
        self.assertTrue(any('asked acme to slow down' in s[2] for s in ctx.steps), ctx.steps)
        # another run with the same settings: the refusal said again, nothing sent
        with self.assertRaises(base.PluginError):
            Webglobe(self.webglobe(), self.ctx()).test()
        # other settings, the same host: held, nothing sent either
        with self.assertRaises(base.PluginError) as e:
            Webglobe(self.webglobe(login='other@firma.cz'), self.ctx()).test()
        self.assertIn('not asked again before', str(e.exception))
        self.assertEqual(WORLD.login_tries, 1)


# ---------------------------------------------------------------------------
# A 429, the throttle, Let's Encrypt
# ---------------------------------------------------------------------------
class TestHonourLimits(Base):
    def test_429_with_retry_after_is_waited_out_and_asked_again_once(self):
        c = self.clock()
        WORLD.limit_429 = 1
        ctx = self.ctx()
        st, _h, _b = ctx.http('GET', SERVERS['url'] + '/slow')
        self.assertEqual(st, 200)
        self.assertEqual(WORLD.calls.count(('GET', '/slow')), 2)
        self.assertGreaterEqual(sum(c.slept), 1.0)
        self.assertLess(sum(c.slept), 3.0)
        self.assertTrue(any('asked acme to slow down (HTTP 429): waiting' in s[2]
                            for s in ctx.steps), ctx.steps)

    def test_429_asked_again_a_bounded_number_of_times(self):
        self.clock()
        WORLD.limit_429 = 50
        st, _h, _b = self.ctx().http('GET', SERVERS['url'] + '/slow')
        self.assertEqual(st, 429)
        self.assertEqual(WORLD.calls.count(('GET', '/slow')), L.RETRIES + 1)

    def test_a_post_is_not_asked_again(self):
        self.clock()
        WORLD.limit_429 = 5
        st, _h, _b = self.ctx().http('POST', SERVERS['url'] + '/slow', body=b'{}')
        self.assertEqual(st, 429)
        self.assertEqual(WORLD.calls.count(('POST', '/slow')), 1)

    def test_retry_after_as_a_date_and_the_pause(self):
        import email.utils
        when = email.utils.formatdate(time.time() + 120, usegmt=True)
        self.assertAlmostEqual(L.retry_after({'Retry-After': when}), 120, delta=3)
        self.assertEqual(L.retry_after({'retry-after': '7'}), 7.0)
        self.assertIsNone(L.retry_after({}))
        self.assertEqual(L.slowdown(429, {}, b''), 0.0)
        self.assertEqual(L.slowdown(503, {'Retry-After': '4'}, b''), 4.0)
        self.assertEqual(L.slowdown(400, {}, b'{"error": "Too Many Attempts"}'), L.LOCKOUT_S)
        self.assertIsNone(L.slowdown(400, {}, b'{"error": "bad name"}'))
        self.assertIsNone(L.slowdown(200, {}, b'rate limit'))
        p1, p2, p3 = L.pause(0), L.pause(1), L.pause(2)
        self.assertTrue(L.BASE_S <= p1 <= L.BASE_S * 1.2)
        self.assertTrue(2 * L.BASE_S <= p2 <= 2 * L.BASE_S * 1.2)
        self.assertTrue(4 * L.BASE_S <= p3 <= 4 * L.BASE_S * 1.2)
        self.assertTrue(5.0 <= L.pause(0, 5.0) <= 5.5)

    def test_two_at_once_to_one_host(self):
        L.LOCAL_FREE = False
        ctxs = [self.ctx() for _ in range(8)]
        ts = [threading.Thread(target=lambda c=c: c.http('GET', SERVERS['url'] + '/slow'))
              for c in ctxs]
        t0 = time.time()
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        self.assertEqual(WORLD.calls.count(('GET', '/slow')), 8)
        self.assertLessEqual(WORLD.most, L.HOST_CONCURRENT)
        self.assertLessEqual(L.most_at_once(SERVERS['url']), L.HOST_CONCURRENT)
        # eight from a bucket of HOST_BURST, HOST_RATE a second: the rest waited
        self.assertGreaterEqual(time.time() - t0, (8 - L.HOST_BURST) / L.HOST_RATE * 0.8)

    def test_loopback_is_not_throttled_by_default(self):
        self.assertTrue(L.LOCAL_FREE)
        with L.throttle('http://127.0.0.1:1/x') as t:
            self.assertIsNone(t.h)
        with L.throttle('http://localhost:1/x') as t:
            self.assertIsNone(t.h)

    def test_lets_encrypt_new_accounts(self):
        c = self.clock()
        url = 'https://acme-v02.api.letsencrypt.org/acme/new-acct'
        for _ in range(10):
            with L.throttle(url, method='POST'):
                pass
        with self.assertRaises(base.PluginError) as e:
            with L.throttle(url, method='POST'):
                pass
        self.assertIn('10 new accounts in 3 hours', str(e.exception))
        c.t += 3 * 3600 / 10 + 1                        # one more after a while
        with L.throttle(url, method='POST'):
            pass
        # a GET of the directory is not an account
        with L.throttle('https://acme-v02.api.letsencrypt.org/directory'):
            pass

    def test_a_held_host_is_waited_for_a_little(self):
        c = self.clock()
        url = 'https://api.example.test/x'
        L.note_slow(url, 5)
        said = []
        with L.throttle(url, say=said.append):
            pass
        self.assertTrue(said and 'waiting 5 s' in said[0], said)
        self.assertGreaterEqual(sum(c.slept), 5)
        L.note_slow(url, 200)
        with self.assertRaises(base.PluginError):
            with L.throttle(url):
                pass

    def test_shared_reads(self):
        n = []

        def ask():
            n.append(1)
            return ['a']
        self.assertEqual(L.shared('k|zones', ask), ['a'])
        self.assertEqual(L.shared('k|zones', ask), ['a'])
        self.assertEqual(len(n), 1)
        L.forget_shared('k|')
        L.shared('k|zones', ask)
        self.assertEqual(len(n), 2)
        c = self.clock()
        c.t += L.SHARED_S + 1
        L.shared('k|zones', ask)
        self.assertEqual(len(n), 3)

    def test_a_stand_in_ctx_shares_nothing(self):
        from test_challenges import FakeCtx
        self.assertFalse(L.sharing(FakeCtx()))
        self.assertTrue(L.sharing(self.ctx()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
