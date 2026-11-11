#!/usr/bin/env python3
"""Tests of what the servers really serve (acmelib/certs/checks.py, 1.0.32).

    python3 test/test_checks.py

A TLS server of the test's own, on 127.0.0.1, serves one version or another of a
certificate acme keeps: the test of the deployment says ok, old, other, warn,
answer (an HTTP answer not as set) or unreachable - after a deployment, by
itself, through an SSH server, and on the API.
"""
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-checks-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'none'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme as E  # noqa: E402
from acmelib import engine as EN  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import checks as C  # noqa: E402
from acmelib.certs import store as S  # noqa: E402
from test_issuers import TestCA, make_key_csr  # noqa: E402

STORE = E.Storage(E.open_db())
EN.CONFIG['certs_checks_warn_days'] = 0     # the test's certificates live 7 days
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
NAMES = ['www.example.test', 'example.test']


def pem_of(text):
    return text if isinstance(text, str) else text.decode()


class Served(object):
    """A TLS server on 127.0.0.1: serves `self.cert` (leaf PEM, key PEM, chain PEMs) and,
    asked over HTTP, `self.status`."""
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(20)
        self.port = self.sock.getsockname()[1]
        self.cert = None
        self.status = 200
        self.seen_host = None
        self.stop = False
        threading.Thread(target=self.loop, daemon=True).start()

    def ctx(self):
        leaf, key, chain = self.cert
        d = tempfile.mkdtemp(dir=TMP)
        cf, kf = os.path.join(d, 'c.pem'), os.path.join(d, 'k.pem')
        with open(cf, 'w') as f:
            f.write(leaf + ''.join(chain))
        with open(kf, 'w') as f:
            f.write(key)
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c.load_cert_chain(cf, kf)
        return c

    def loop(self):
        while not self.stop:
            try:
                conn, _a = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(conn,), daemon=True).start()

    def one(self, conn):
        try:
            s = self.ctx().wrap_socket(conn, server_side=True)
            s.settimeout(3)
            try:
                got = s.recv(4096)
            except (socket.timeout, ssl.SSLError, OSError):
                got = b''
            if got.startswith((b'GET', b'HEAD')):
                for ln in got.split(b'\r\n'):
                    if ln.lower().startswith(b'host:'):
                        self.seen_host = ln.split(b':', 1)[1].strip().decode()
                s.sendall(b'HTTP/1.1 %d X\r\nServer: fake\r\nContent-Length: 2\r\n\r\nok'
                          % self.status)
            s.close()
        except (ssl.SSLError, OSError):
            pass


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca = TestCA(cn='Checks Test Root')
        key, _csr, der = make_key_csr(NAMES)
        cls.v1 = (pem_of(cls.ca.sign_csr(der, NAMES, serial=101)), key)
        key2, _csr2, der2 = make_key_csr(NAMES)
        cls.v2 = (pem_of(cls.ca.sign_csr(der2, NAMES, serial=102)), key2)
        key3, _c3, der3 = make_key_csr(['other.example.test'])
        cls.other = (pem_of(cls.ca.sign_csr(der3, ['other.example.test'], serial=103)), key3)
        with open(cls.ca.crt) as f:
            cls.root = f.read()
        t = time.time()
        cls.cid = STORE.db.insert('certs', {'name': 'www-' + cls.__name__.lower(), 'cn': NAMES[0],
                                            'names': json.dumps(NAMES), 'created': t,
                                            'state': 'ok', 'version': 0})
        S.save_version(STORE, cls.cid, cls.v1[0], [cls.root], cls.v1[1], 'issue', 'test')
        S.save_version(STORE, cls.cid, cls.v2[0], [cls.root], cls.v2[1], 'renew', 'test')
        cls.srv = Served()
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop = True
        cls.srv.sock.close()
        cls.ca.close()

    def serve(self, which, chain=True):
        self.srv.cert = (which[0], which[1], [self.root] if chain else [])

    def define(self, kind='https', **cfg):
        type(self).n += 1
        name = '%s-%s-%d' % (kind, type(self).__name__.lower(), self.n)
        cfg.setdefault('host', '127.0.0.1')
        A.family_save(STORE, 'check', {'name': name, 'kind': kind, 'config': cfg}, 'test')
        return name

    def add(self, kind='https', **cfg):
        """A test defined and attached to the certificate -> the attachment's id."""
        cfg.setdefault('port', self.srv.port)
        name = self.define(kind, **cfg)
        return C.attach(STORE, self.cid, [name], 'test')[0]

    def run_it(self, ident):
        return C.run(STORE, ident)


class TestJudged(Base):
    def test_current_old_other(self):
        i = self.add()
        self.serve(self.v2)
        got = self.run_it(i)
        self.assertEqual(got['state'], 'ok', got)
        self.assertIn('current certificate (version 2)', got['said'])
        self.assertEqual(got['detail']['trusted'], False, 'a CA of the test\'s own')
        self.serve(self.v1)
        got = self.run_it(i)
        self.assertEqual(got['state'], 'old')
        self.assertIn('old version (1)', got['said'])
        self.serve(self.other)
        self.assertEqual(self.run_it(i)['state'], 'other')
        row = STORE.db.row('SELECT * FROM cert_checks WHERE id = ?', (i,))
        self.assertEqual((row['last_state'], row['fails']), ('other', 2))

    def test_the_twin_acme_does_not_keep_said(self):
        """A dual certificate with only one half in acme (1.0.34): the other half
        served is said as its twin, with what to do - not a stranger's certificate."""
        key, _csr, der = make_key_csr(NAMES, kind='rsa')
        rsa = (pem_of(self.ca.sign_csr(der, NAMES, serial=150)), key)
        i = self.add()
        self.serve(rsa)
        got = self.run_it(i)
        self.assertEqual(got['state'], 'other')
        self.assertIn('RSA twin of this certificate', got['said'])
        self.assertIn('Key asked for', got['said'])
        self.assertEqual(got['detail'].get('twin_missing'), 'RSA')

    def test_what_differs_said(self):
        """Not the certificate: the job's log, the event and the mail say what differs."""
        i = self.add()
        self.serve(self.other)
        steps = []
        got = C.record(STORE, STORE.db.row('SELECT * FROM cert_checks WHERE id = ?', (i,)),
                       C.probe(STORE, STORE.db.row('SELECT * FROM cert_checks WHERE id = ?', (i,))),
                       lambda text, level=None: steps.append(text))
        self.assertEqual(got['state'], 'other')
        lines = [x for x in steps if x.startswith('  ')]
        self.assertTrue(any('✗ names: acme' in x and 'other.example.test' in x for x in lines), lines)
        self.assertTrue(any(x.startswith('  = issued by') for x in lines), lines)
        rows = C.compare(got['detail'])
        from acmelib.certs import texts as T
        for lang in ('en', 'cs'):
            m = T.draw_with('cert_check_failed', T.texts_for('cert_check_failed', lang) if hasattr(
                T, 'texts_for') else {}, {'cert': 'x', 'target': 't', 'check': 'c', 'error': 'e',
                                          '_compare': rows}, lang)
            self.assertIn('other.example.test', m['html'])
            self.assertIn('&#10007;', m['html'])
            self.assertIn('other.example.test', m['text'])

    def test_key_asked_for(self):
        """RSA or ECDSA asked for: TLS 1.2 at most, ciphers of that key only."""
        from acmelib.plugins.checks import _tls
        import ssl
        for want, has, hasnt in (('rsa', 'RSA', 'ECDSA'), ('ecdsa', 'ECDSA', 'RSA')):
            _tls.CURRENT.cfg = {'key_want': want}
            try:
                ctx = _tls.context('x', False)
            finally:
                _tls.CURRENT.cfg = {}
            self.assertEqual(ctx.maximum_version, ssl.TLSVersion.TLSv1_2)
            names = [c['name'] for c in ctx.get_ciphers() if c.get('protocol') != 'TLSv1.3']
            self.assertTrue(names and all(hasnt not in n.split('-')[1:2] for n in names), names)
            self.assertTrue(any(has in n for n in names), names)

    def test_both_keys_asked_for(self):
        """Key asked for: both (1.0.36) - once for RSA, once for ECDSA; the test server
        has an ECDSA certificate only: the RSA half fails, so the test does."""
        i = self.add(key_want='both')
        self.serve(self.v2)
        got = self.run_it(i)
        halves = got['detail']['halves']
        self.assertEqual([h['half'] for h in halves], ['RSA', 'ECDSA'])
        self.assertEqual(halves[1]['state'], 'ok', halves[1])
        self.assertNotEqual(halves[0]['state'], 'ok', halves[0])
        self.assertFalse(got['ok'])
        self.assertIn('RSA:', got['said'])
        self.assertIn('ECDSA:', got['said'])
        self.assertEqual(got['detail']['expect'], 'current')

    def test_expect_any_version(self):
        i = self.add(expect='any')
        self.serve(self.v1)
        self.assertEqual(self.run_it(i)['state'], 'ok')

    def test_ends_soon_is_a_warning(self):
        i = self.add()
        self.serve(self.v2)
        EN.CONFIG['certs_checks_warn_days'] = 14
        try:
            got = self.run_it(i)
        finally:
            EN.CONFIG['certs_checks_warn_days'] = 0
        self.assertEqual(got['state'], 'warn')
        self.assertIn('it ends in', got['said'])

    def test_the_name_checked_and_the_chain(self):
        i = self.add(check_name='nope.example.test')
        self.serve(self.v2)
        got = self.run_it(i)
        self.assertEqual(got['state'], 'warn')
        self.assertIn('nope.example.test is not one of its names', got['said'])
        j = self.add()
        self.serve(self.v2, chain=False)
        got = self.run_it(j)
        self.assertEqual(got['state'], 'warn')
        self.assertIn('no intermediate', got['said'])

    def test_required_trust(self):
        i = self.add(require_trusted=True)
        self.serve(self.v2)
        got = self.run_it(i)
        self.assertEqual(got['state'], 'other')
        self.assertIn('not trusted here', got['said'])

    def test_http_asked_with_its_own_host(self):
        i = self.add(http=True, host_header='intranet.example.test', path='/health',
                     method='GET', expect_status='200')
        self.serve(self.v2)
        self.srv.status = 200
        got = self.run_it(i)
        self.assertEqual(got['state'], 'ok', got)
        self.assertEqual(self.srv.seen_host, 'intranet.example.test')
        self.assertEqual(got['detail']['http']['status'], 200)
        self.srv.status = 503
        got = self.run_it(i)
        self.assertEqual(got['state'], 'answer')
        self.assertIn('503', got['said'])
        self.srv.status = 200

    def test_empty_address_is_the_first_name(self):
        cls = __import__('acmelib.plugins.checks._tls', fromlist=['x'])
        i = self.add(host='')
        seen = []
        orig = cls.connect
        cls.connect = lambda h, p, t: seen.append(h) or orig('127.0.0.1', p, t)
        try:
            self.serve(self.v2)
            self.assertEqual(self.run_it(i)['state'], 'ok')
        finally:
            cls.connect = orig
        self.assertEqual(seen[0], 'www.example.test')

    def test_connect_to_an_ip_sni_given(self):
        i = self.add(host='127.0.0.1', sni='www.example.test', family='4')
        self.serve(self.v2)
        got = self.run_it(i)
        self.assertEqual(got['state'], 'ok')
        self.assertEqual((got['detail']['host'], got['detail']['sni']),
                         ('127.0.0.1', 'www.example.test'))

    def test_tls_limits_and_bad_ciphers(self):
        i = self.add(tls_max='TLSv1_2')
        self.serve(self.v2)
        got = self.run_it(i)
        self.assertEqual(got['detail']['tls'], 'TLSv1.2')
        j = self.add(ciphers='NOT-A-CIPHER')
        self.assertIn('ciphers', self.run_it(j)['said'])

    def test_unreachable(self):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        i = self.add(port=port)
        got = self.run_it(i)
        self.assertEqual(got['state'], 'unreachable')
        self.assertIn('cannot be reached', got['said'])


class TestRuns(Base):
    def test_failure_said_once_and_recovery_said(self):
        i = self.add()
        self.serve(self.v2)
        self.run_it(i)
        n0 = STORE.db.value("SELECT COUNT(*) FROM events WHERE words LIKE ?", ('%test HTTPS%',), 0)
        self.serve(self.v1)
        self.run_it(i)
        self.run_it(i)
        n1 = STORE.db.value("SELECT COUNT(*) FROM events WHERE words LIKE ?", ('%test HTTPS%',), 0)
        self.assertEqual(n1 - n0, 1, 'a test that keeps failing is said once')
        self.serve(self.v2)
        self.run_it(i)
        n2 = STORE.db.value("SELECT COUNT(*) FROM events WHERE words LIKE ?", ('%test HTTPS%',), 0)
        self.assertEqual(n2 - n1, 1, 'working again is said')

    def test_after_deploy_and_by_itself(self):
        STORE.db.run('DELETE FROM cert_checks WHERE cert_id = ?', (self.cid,))
        i = self.add()
        self.serve(self.v2)
        C.AFTER_DEPLOY_TRIES, old = (0, 0), C.AFTER_DEPLOY_TRIES

        class Job(object):
            steps = []

            def step(self, w, level='info'):
                self.steps.append((level, w))

            def check(self):
                pass
        try:
            job = Job()
            self.assertTrue(C.after_deploy(STORE, job, self.cid))
            self.assertTrue(any('current certificate' in w for _l, w in job.steps))
        finally:
            C.AFTER_DEPLOY_TRIES = old
        # Tied to a target (1.0.65): run after a deployment on it only.
        STORE.db.run('DELETE FROM cert_deploys WHERE cert_id = ?', (self.cid,))
        STORE.db.insert('cert_deploys', {'cert_id': self.cid, 'target': 'rpki1', 'enabled': 1})
        with self.assertRaises(ValueError):
            C.after(STORE, i, 'rpki2', 'test')           # not a target of the certificate
        C.after(STORE, i, 'rpki1', 'test')
        with self.assertRaises(ValueError):
            C.attach(STORE, self.cid, ['x'], 'test', 'rpki2')
        C.AFTER_DEPLOY_TRIES, old = (0, 0), C.AFTER_DEPLOY_TRIES
        try:
            job = Job()
            job.steps = []
            self.assertIsNone(C.after_deploy(STORE, job, self.cid, {'rpki3'}))   # none of its own
            self.assertEqual(job.steps, [])
            self.assertTrue(C.after_deploy(STORE, job, self.cid, {'rpki1'}))
            self.assertTrue(job.steps)
            STORE.db.insert('cert_deploys', {'cert_id': self.cid, 'target': 'rpki3', 'enabled': 1})
            C.after(STORE, i, ['rpki1', 'rpki3'], 'test')   # several targets
            job.steps = []
            self.assertTrue(C.after_deploy(STORE, job, self.cid, {'rpki3'}))
            self.assertIsNone(C.after_deploy(STORE, job, self.cid, {'rpki9'}))
            self.assertEqual(C.after_list('rpki1\nrpki3'), ['rpki1', 'rpki3'])
            C.after(STORE, i, '', 'test')                 # any again
            job.steps = []
            self.assertTrue(C.after_deploy(STORE, job, self.cid, {'rpki3'}))
        finally:
            C.AFTER_DEPLOY_TRIES = old
            STORE.db.run('DELETE FROM cert_deploys WHERE cert_id = ?', (self.cid,))
        EN.CONFIG['certs_checks_auto'] = 0
        self.assertEqual(C.due(STORE), [])
        EN.CONFIG['certs_checks_auto'] = 1
        EN.CONFIG['certs_checks_every_min'] = 5
        self.assertNotIn(i, [r['id'] for r in C.due(STORE)], 'just run')
        STORE.db.run('UPDATE cert_checks SET last_at = ? WHERE id = ?', (time.time() - 600, i))
        self.assertIn(i, [r['id'] for r in C.due(STORE)])
        EN.CONFIG['certs_checks_auto'] = 0


class FakeSession(object):
    def __init__(self):
        self.tunnels = []

    def tunnel(self, host, port, timeout):
        self.tunnels.append((host, port))
        return socket.create_connection(('127.0.0.1', port), timeout=timeout)

    def tunnel_said(self):
        return ''

    def close(self):
        pass


class TestRelay(Base):
    def test_a_connector_runs_its_tests_through_ssh(self):
        fake = FakeSession()
        cls = S.plugin_class('check', 'ssh_relay')
        orig = cls.ssh
        cls.ssh = lambda self_: fake
        try:
            self.serve(self.v2)
            m1 = self.define('https', host='10.9.9.9', port=self.srv.port,
                             sni='www.example.test')
            m2 = self.define('tls', host='internal.example.test', port=self.srv.port,
                             sni='www.example.test', expect='any', tls_max='TLSv1_2')
            relay = self.define('ssh_relay', host='jump.example.test', user='acme',
                                auth='password', password='pw', tests=[m1, m2, 'gone'])
            i = C.attach(STORE, self.cid, [relay], 'test')[0]
            got = self.run_it(i)
            subs = got['detail']['subs']
            self.assertEqual([x['state'] for x in subs], ['ok', 'ok', 'unreachable'])
            self.assertIn('there is no test gone', subs[2]['said'])
            self.assertEqual(fake.tunnels[0], ('10.9.9.9', self.srv.port))
            self.assertEqual(subs[1]['tls'], 'TLSv1.2')
            self.assertFalse(got['ok'])
            self.assertIn('1 of 3 from jump.example.test failed', got['said'])
            row = S.plugin_row(STORE, 'check', relay)
            self.assertNotIn('"pw"', row['config'], 'its password sealed')
        finally:
            cls.ssh = orig

    def test_used_by_and_renamed(self):
        m = self.define('https', port=443)
        relay = self.define('ssh_relay', host='j', user='u', auth='password', password='p',
                            tests=[m])
        pub = S.plugin_public(STORE, 'check', S.plugin_row(STORE, 'check', m))
        self.assertEqual(pub['used_by'], 1, 'in the connector')
        rid = S.plugin_row(STORE, 'check', m)['id']
        A.family_save(STORE, 'check', {'id': rid, 'name': m + '-new'}, 'test')
        cfg = S.jload(S.plugin_row(STORE, 'check', relay)['config'], {})
        self.assertEqual(cfg['tests'], [m + '-new'])
        with self.assertRaises(ValueError):
            A.family_delete(STORE, 'check', {'id': rid}, 'test')


class FakeH(object):
    def __init__(self, role, body=None, args=None):
        self.store, self.role, self._body, self._args = STORE, role, body or {}, args or {}

    def me(self, _role):
        return {'name': 'someone', 'role': self.role}

    def body(self):
        return self._body

    def arg(self, k, default=''):
        return self._args.get(k, default)


class TestApi(Base):
    def call(self, m, path, body=None, args=None, role='fulladmin'):
        return E.ROUTES[(m, path)](FakeH(role, body, args))

    def test_define_attach_list_try_run_detach(self):
        self.serve(self.v2)
        self.call('POST', '/api/tests/save', {'name': 'api-https', 'kind': 'https', 'config': {
            'host': '127.0.0.1', 'port': self.srv.port}})
        lst = self.call('GET', '/api/tests')
        self.assertIn('api-https', [r['name'] for r in lst['rows']])
        got = self.call('POST', '/api/checks/attach', {'cert_id': self.cid, 'tests': ['api-https']},
                        role='certadmin')
        cid = got['ids'][0]
        att = self.call('GET', '/api/checks', args={'cert_id': str(self.cid)})
        self.assertIn('api-https', [c['test'] for c in att['checks']])
        tried = self.call('POST', '/api/checks/try', {'cert_id': self.cid, 'kind': 'https',
                                                      'config': {'host': '127.0.0.1',
                                                                 'port': self.srv.port}})
        self.assertEqual(tried['result']['state'], 'ok')
        ran = self.call('POST', '/api/checks/run', {'id': cid})
        self.assertEqual(ran['check']['last_state'], 'ok')
        tested = self.call('POST', '/api/tests/test', {'name': 'api-https', 'id': S.plugin_row(
            STORE, 'check', 'api-https')['id']})
        self.assertIn('serves www.example.test', tested.get('said') or str(tested))
        with self.assertRaises((EN.ApiError, LookupError, ValueError)):
            self.call('POST', '/api/checks/attach', {'cert_id': self.cid, 'tests': ['nope']})
        self.call('POST', '/api/checks/detach', {'id': cid})
        self.assertNotIn('api-https', [c['test'] for c in self.call(
            'GET', '/api/checks', args={'cert_id': str(self.cid)})['checks']])

    def test_a_read_only_account_may_not_attach(self):
        with self.assertRaises(EN.ApiError):
            self.call('POST', '/api/checks/attach', {'cert_id': self.cid, 'tests': ['x']},
                      role='readonly')


if __name__ == '__main__':
    unittest.main(verbosity=2)
