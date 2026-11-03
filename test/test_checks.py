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
        cls.tname = 'web-' + cls.__name__.lower()
        cls.tid = A.family_save(STORE, 'target', {'name': cls.tname, 'kind': 'ssh', 'config': {
            'host': '127.0.0.1', 'user': 'root', 'auth': 'password', 'password': 'x'}}, 'test')
        cls.did = STORE.db.insert('cert_deploys', {'cert_id': cls.cid, 'target': cls.tname,
                                                   'options': '{}', 'enabled': 1,
                                                   'created': t})
        cls.srv = Served()

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop = True
        cls.srv.sock.close()
        cls.ca.close()

    def serve(self, which, chain=True):
        self.srv.cert = (which[0], which[1], [self.root] if chain else [])

    def add(self, kind='https', **cfg):
        cfg.setdefault('port', self.srv.port)
        return C.save(STORE, {'deploy_id': self.did, 'kind': kind, 'config': cfg}, 'test')

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
        STORE.db.run('DELETE FROM cert_checks')
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
            self.assertTrue(C.after_deploy(STORE, job, self.did))
            self.assertTrue(any('current certificate' in w for _l, w in job.steps))
        finally:
            C.AFTER_DEPLOY_TRIES = old
        EN.CONFIG['certs_checks_auto'] = 0
        self.assertEqual(C.due(STORE), [])
        EN.CONFIG['certs_checks_auto'] = 1
        EN.CONFIG['certs_checks_every_min'] = 5
        self.assertEqual(C.due(STORE), [], 'just run')
        STORE.db.run('UPDATE cert_checks SET last_at = ? WHERE id = ?', (time.time() - 600, i))
        self.assertEqual([r['id'] for r in C.due(STORE)], [i])
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
    def test_a_set_run_through_ssh(self):
        fake = FakeSession()

        class Relay(object):
            def ssh(self):
                return fake
        orig = S.plugin_instance
        S.plugin_instance = lambda store, fam, row, ctx, over=None: Relay() \
            if fam == 'target' and row['name'] == self.tname else orig(store, fam, row, ctx, over)
        try:
            self.serve(self.v2)
            i = C.save(STORE, {'deploy_id': self.did, 'kind': 'ssh_relay', 'config': {
                'relay': self.tname, 'checks': [
                    'https 10.9.9.9:%d www.example.test' % self.srv.port,
                    'tls internal.example.test:%d www.example.test expect=any tls_max=TLSv1_2'
                    % self.srv.port,
                    'https 10.9.9.9:%d www.example.test nonsense=1' % self.srv.port]}}, 'test')
            got = self.run_it(i)
            subs = got['detail']['subs']
            self.assertEqual([s['state'] for s in subs], ['ok', 'ok', 'unreachable'])
            self.assertIn('has no setting nonsense', subs[2]['said'])
            self.assertEqual(fake.tunnels[0], ('10.9.9.9', self.srv.port))
            self.assertEqual(subs[1]['tls'], 'TLSv1.2')
            self.assertFalse(got['ok'])
            self.assertIn('1 of 3 from %s failed' % self.tname, got['said'])
        finally:
            S.plugin_instance = orig

    def test_bad_lines_said(self):
        from acmelib.plugins.base import PluginError
        cls = S.plugin_class('check', 'ssh_relay')
        with self.assertRaises(PluginError):
            cls({'relay': 'x', 'checks': ['https']}, None).plan()
        with self.assertRaises(PluginError):
            cls({'relay': 'x', 'checks': ['ssh_relay a.example']}, None).plan()
        p = cls({'checks': ['https [::1]:8443 www.x path=/a http=1']}, None).plan()[0]
        self.assertEqual((p['host'], p['port'], p['sni'], p['options']),
                         ('::1', 8443, 'www.x', {'path': '/a', 'http': '1'}))


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

    def test_save_list_try_run_delete(self):
        self.serve(self.v2)
        got = self.call('POST', '/api/checks/save', {'deploy_id': self.did, 'kind': 'https',
                                                     'config': {'port': self.srv.port}},
                        role='certadmin')
        cid = got['id']
        lst = self.call('GET', '/api/checks', args={'target': self.tname})
        self.assertIn(cid, [c['id'] for c in lst['checks']])
        self.assertEqual(lst['host'], '127.0.0.1')
        self.assertIn('https', [m['kind'] for m in lst['modules']])
        self.assertEqual(lst['deploys'][0]['cert'], 'www-testapi')
        tried = self.call('POST', '/api/checks/try', {'deploy_id': self.did, 'kind': 'https',
                                                      'config': {'port': self.srv.port}})
        self.assertEqual(tried['result']['state'], 'ok')
        ran = self.call('POST', '/api/checks/run', {'id': cid})
        self.assertEqual(ran['check']['last_state'], 'ok')
        with self.assertRaises((EN.ApiError, ValueError)):
            self.call('POST', '/api/checks/save', {'deploy_id': self.did, 'kind': 'nope',
                                                   'config': {}})
        with self.assertRaises((EN.ApiError, ValueError)):
            self.call('POST', '/api/checks/save', {'deploy_id': 999999, 'kind': 'https',
                                                   'config': {}})
        with self.assertRaises((EN.ApiError, ValueError)):
            self.call('POST', '/api/checks/save', {'deploy_id': self.did, 'kind': 'https',
                                                   'config': {'port': 70000}})
        self.call('POST', '/api/checks/delete', {'id': cid})
        self.assertNotIn(cid, [c['id'] for c in self.call(
            'GET', '/api/checks', args={'target': self.tname})['checks']])

    def test_a_read_only_account_may_not_change(self):
        with self.assertRaises(EN.ApiError):
            self.call('POST', '/api/checks/save', {'deploy_id': self.did, 'kind': 'https'},
                      role='readonly')


if __name__ == '__main__':
    unittest.main(verbosity=2)
