#!/usr/bin/env python3
"""The company enrollment code (1.0.120, docs/target-agent.md "Enrolling many servers"): one
code for many servers, each its own target waiting for a person to confirm it - real agents
(both processes, each "server" with a host name of its own: a UTS namespace) against acme's
engine in this process and an agents' port of the test's (as test/test_target_agent.py does
for an active join).

    python3 test/test_agent_windows_enroll.py

What is tried: a code made (the agents' port must be on; shown once, its secret sealed); two
servers join with it -> two targets waiting (each by its host name, the code it came with),
confirmed at once (confirm-many, each by its fingerprint) -> both joined and asked; the same
server asking again (its answer lost) -> the same target, not a second one; a revoked, run
out or used-up code refused, a wrong proof refused, the port off -> nothing answers; confirmed
automatically (said in Events); a Windows server -> a target of kind agent_windows; a passive
code: the agent takes its certificate by asking, then listens - acme marks it joined at its
first answer; the API, the command line (enroll new|list|revoke, waiting) and the console's
menu; the existing join code's behaviour unchanged (ACAG1.).

Needs what test_target_agent.py needs (root, setpriv, openssl) and unshare; never touches port
8092 nor PostgreSQL - temporary folders and ports only.
"""
import base64
import hashlib
import http.server
import io
import json
import os
import pwd
import secrets
import shutil
import ssl
import subprocess
import sys
import threading
import time
import unittest
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
from contextlib import redirect_stdout, redirect_stderr

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_target_agent as T  # noqa: E402  (its folders, its engine, its agents)

E, A, G, S, STORE = T.E, T.A, T.G, T.S, T.STORE
CAN = T.CAN and bool(shutil.which('unshare'))


def setUpModule():
    T.setUpModule()


def tearDownModule():
    for w in list(PortW.ALL):
        w.stop()
    T.tearDownModule()


class FakeH(object):
    def __init__(self, body=None, args=None):
        self._b = body or {}
        self._a = args or {}
        self.store = STORE

    def body(self):
        return self._b

    def arg(self, k, default=None):
        return self._a.get(k, default)


SESSION = {'role': 'fulladmin', 'name': 'tester'}


def api(name, body=None):
    from acmelib.certs import api_agents as AA
    return getattr(AA, name)(FakeH(body), SESSION)


class EnrollHandler(T.WireHandler):
    """The agents' port with /agent/v1/enroll as nginx and web/agent.php relay it."""

    def do_POST(self):
        op = {'/agent/v1/join': 'join', '/agent/v1/join/status': 'status',
              '/agent/v1/poll': 'poll', '/agent/v1/enroll': 'enroll'}.get(self.path)
        n = int(self.headers.get('Content-Length') or 0)
        body = json.loads(self.rfile.read(n) or b'{}')
        der = self.connection.getpeercert(True)
        if op is None:
            st, out = 404, {'ok': False}
        elif op == 'poll' and not der:
            st, out = 403, {'ok': False, 'said': 'nginx: no certificate'}
        else:
            self.server.seen.append(op)
            st, out = G.wire(self.server.store, op, body,
                             ssl.DER_cert_to_PEM_cert(der) if der else '',
                             'SUCCESS' if der else 'NONE', self.client_address[0])
        raw = json.dumps(out).encode()
        self.send_response(st)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class PortW(T.Wire):
    ALL = []

    def __init__(self, store):
        T.Wire.__init__(self, store)
        T.Wire.ALL.remove(self)
        self.srv.shutdown()
        self.srv.server_close()
        c, a = G.ctl(store), G.ca(store)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        for n, v in (('c.pem', c['cert_pem']), ('k.pem', c['key_pem']), ('a.pem', a['cert_pem'])):
            with open(os.path.join(T.TMP, 'e%d-%s' % (self.port, n)), 'w') as fh:
                fh.write(v)
        ctx.load_cert_chain(os.path.join(T.TMP, 'e%d-c.pem' % self.port),
                            os.path.join(T.TMP, 'e%d-k.pem' % self.port))
        ctx.load_verify_locations(os.path.join(T.TMP, 'e%d-a.pem' % self.port))
        ctx.verify_mode = ssl.CERT_OPTIONAL
        self.srv = http.server.ThreadingHTTPServer(('127.0.0.1', self.port), EnrollHandler)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.srv.store = store
        self.srv.seen = []
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        PortW.ALL.append(self)

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        if self in PortW.ALL:
            PortW.ALL.remove(self)


class Server(T.Agent):
    """An agent on a "server" of its own name: both its processes and its command line in a
    UTS namespace whose host name is `host`."""

    def __init__(self, name, host):
        T.Agent.__init__(self, name)
        self.host = host

    def _ns(self):
        return ['unshare', '--uts', 'sh', '-c', 'hostname "$0" && exec "$@"', self.host]

    def cli(self, *args, ok=True):
        got = subprocess.run(self._ns() + [sys.executable, '-I', T.AGENT] + list(args),
                             env=self.env, capture_output=True, text=True, timeout=60)
        if ok and got.returncode != 0:
            raise AssertionError('acme-agent %s: %s %s' % (args, got.stdout, got.stderr))
        return got

    def start_root(self):
        self.root = subprocess.Popen(self._ns() + [sys.executable, '-I', T.AGENT, 'root'],
                                     env=self.env, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE)
        for _ in range(100):
            if os.path.exists(self.d + '/run/root.sock'):
                return
            time.sleep(0.05)
        raise AssertionError('the root side did not start: %s' % self.root.stderr.read())

    def start_net(self):
        pw = pwd.getpwnam(T.USER)
        self.net = subprocess.Popen(self._ns() + [
            'setpriv', '--reuid=%d' % pw.pw_uid, '--regid=%d' % pw.pw_gid, '--clear-groups',
            sys.executable, '-I', T.AGENT, 'serve'], env=self.env, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE)
        time.sleep(0.6)
        if self.net.poll() is not None:
            raise AssertionError('the network side ended: %s' % self.net.stderr.read())


def keypair():
    """A server's key and a CSR of it, as the agent makes them."""
    key = subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                          'ec_paramgen_curve:P-256'], capture_output=True, check=True).stdout
    csr = subprocess.run(['openssl', 'req', '-new', '-key', '/dev/stdin', '-subj',
                          '/CN=acme-agent'], input=key, capture_output=True,
                         check=True).stdout.decode()
    return key, csr


def code_data(code):
    raw = code.split('.', 1)[1]
    return json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))


def enroll_body(data, csr, fqdn, platform='linux', host=None, secret=None, osname='Rocky 9'):
    nonce = secrets.token_hex(16)
    enc = base64.b64encode(secrets.token_bytes(32)).decode()
    sha = hashlib.sha256(csr.encode()).hexdigest()
    return {'e': data['e'], 'nonce': nonce, 'csr': csr, 'enc_pub': enc,
            'host': host or fqdn.split('.')[0], 'fqdn': fqdn, 'os': osname,
            'platform': platform, 'version': '1.0.120', 'code': 'c0de', 'port': 8446,
            'proof': G.proof(secret or data['s'], 'enroll', data['e'], sha, enc, nonce, fqdn)}


def wait_for(fn, most=40, every=0.2):
    end = time.time() + most
    while time.time() < end:
        got = fn()
        if got:
            return got
        time.sleep(every)
    return fn()


def events(since):
    return [r['words'] for r in STORE.db.rows(
        'SELECT * FROM events WHERE ts >= ? ORDER BY id', (since,))]


def drop_targets(*names):
    for n in names:
        row = STORE.db.row('SELECT * FROM cert_targets WHERE name = ?', (n,))
        if row:
            A.family_delete(STORE, 'target', {'id': row['id']}, 'tester')


# ---------------------------------------------------------------------------------------------
class Codes(unittest.TestCase):
    """The code itself: made only with the agents' port on, its words, its secret sealed."""

    def tearDown(self):
        E.CONFIG['certs_agents_active'] = 0

    def test_1_made_listed_revoked(self):
        E.CONFIG['certs_agents_active'] = 0
        with self.assertRaises(T.base.PluginError):
            G.enroll_new(STORE, 'tester', title='Office')
        E.CONFIG['certs_agents_active'] = 1
        E.CONFIG['certs_agents_names'] = '127.0.0.1:18444'
        t0 = time.time() - 1
        got = api('_enroll_new', {'title': 'Office servers', 'mode': 'active', 'days': 3,
                                  'most': 4})
        self.assertTrue(got['code'].startswith('ACAE1.'))
        d = code_data(got['code'])
        self.assertEqual(sorted(d), ['a', 'ca', 'ck', 'e', 'm', 'n', 'p', 's', 'u', 'v'])
        self.assertEqual((d['m'], d['n'], d['a']), ('active', 'Office servers',
                                                    ['127.0.0.1:18444']))
        self.assertEqual(d['ca'], G.ca(STORE)['fp'])
        # the secret is sealed in meta, never in clear; the view never says it
        raw = STORE.get_meta(G.M_E(d['e']))
        self.assertNotIn(d['s'], raw)
        listed = api('_enroll_list')
        mine = [c for c in listed['codes'] if c['id'] == d['e']][0]
        self.assertNotIn('secret', mine)
        self.assertNotIn(d['s'], json.dumps(listed))
        self.assertEqual((mine['state'], mine['uses'], mine['most'], mine['by'], mine['auto']),
                         ('active', 0, 4, 'tester', False))
        self.assertTrue(any('enrollment code "Office servers" was made by tester' in m
                            for m in events(t0)))
        # bounds
        for bad in ({'days': 0}, {'days': 400}, {'most': 0}, {'mode': 'other'},
                    {'port': 70000}):
            with self.assertRaises(T.base.PluginError):
                G.enroll_new(STORE, 'tester', **bad)
        got = api('_enroll_revoke', {'id': d['e']})
        self.assertEqual(got['code']['state'], 'revoked')
        self.assertTrue(any('was revoked by tester' in m for m in events(t0)))
        with self.assertRaises(LookupError):
            G.enroll_revoke(STORE, '000000000000', 'tester')

    def test_2_the_agent_reads_it(self):
        E.CONFIG['certs_agents_active'] = 1
        got = G.enroll_new(STORE, 'tester', title='Read me', mode='passive', port=9446)
        c = T.AG.read_code(got['code'])
        self.assertEqual((c['e'], c['m'], c['p'], c['i'], c['t']),
                         (code_data(got['code'])['e'], 'passive', 9446, '', ''))
        # one that is not whole, one that ran out: said, nothing changed
        with self.assertRaises(SystemExit):
            T.AG.read_code(got['code'][:-12])
        d = code_data(got['code'])
        d['u'] = int(time.time()) - 10
        old = 'ACAE1.' + base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip('=')
        with self.assertRaises(SystemExit) as cm:
            T.AG.read_code(old)
        self.assertIn('ran out', str(cm.exception))
        # the join code of one target as before
        with self.assertRaises(SystemExit) as cm:
            T.AG.read_code('ACAX1.abc')
        self.assertIn('ACAG1.', str(cm.exception))


@unittest.skipUnless(CAN, 'needs root, setpriv, openssl, unshare')
class Enroll(unittest.TestCase):
    """Real agents joining with one code."""

    @classmethod
    def setUpClass(cls):
        E.CONFIG['certs_agents_active'] = 1
        cls.port = PortW(STORE)
        E.CONFIG['certs_agents_names'] = '127.0.0.1:%d' % cls.port.port

    @classmethod
    def tearDownClass(cls):
        cls.port.stop()
        E.CONFIG['certs_agents_active'] = 0

    def setUp(self):
        E.CONFIG['certs_agents_active'] = 1

    def test_1_two_servers_waiting_confirmed_at_once(self):
        t0 = time.time() - 1
        code = G.enroll_new(STORE, 'tester', title='Branch offices', mode='active', days=1,
                            most=5)
        eid = code_data(code['code'])['e']
        ags = [Server('ena', 'weba'), Server('enb', 'webb')]
        for ag in ags:
            T.www_policy(ag)
            ag.start_root()
            out = ag.cli('join', code['code'], '--no-wait')
            self.assertIn('the enrollment code "Branch offices"', out.stdout)
            self.assertIn('confirm it there', out.stdout)
            ag.start_net()
        got = wait_for(lambda: len([w for w in G.waiting(STORE)
                                    if (w.get('enroll') or {}).get('id') == eid]) == 2 and
                       G.waiting(STORE))
        mine = sorted([w for w in got if (w.get('enroll') or {}).get('id') == eid],
                      key=lambda w: w['name'])
        self.assertEqual([w['name'] for w in mine], ['weba', 'webb'])
        for w, ag in zip(mine, ags):
            self.assertEqual(w['kind'], 'agent')
            self.assertEqual(w['platform'], 'linux')
            self.assertEqual(w['mode'], 'active')
            self.assertEqual(w['host'], ag.host)
            self.assertEqual(w['ip'], '127.0.0.1')
            self.assertEqual(w['address'], '127.0.0.1')          # its name has no domain
            self.assertEqual(w['enroll']['title'], 'Branch offices')
            self.assertEqual(w['fp_words'], ag.cli('fingerprint').stdout.strip())
            self.assertTrue(ag.wait('confirm', 20), ag.status())
        # the pages' list says them too; the code counts them
        view = api('_agents')
        self.assertEqual(len([w for w in view['waiting'] if w['name'] in ('weba', 'webb')]), 2)
        ec = [c for c in view['enroll'] if c['id'] == eid][0]
        self.assertEqual((ec['uses'], sorted(ec['targets'])), (2, ['weba', 'webb']))
        # a wrong fingerprint among them: that one refused, the other confirmed
        bad = api('_confirm_many', {'items': [{'id': mine[0]['id'], 'fp': '00' * 32},
                                              {'id': mine[1]['id'], 'fp': mine[1]['fp']}]})
        self.assertEqual([(r['name'], r['ok']) for r in bad['rows']],
                         [('weba', False), ('webb', True)])
        got = api('_confirm_many', {'items': [{'id': mine[0]['id'], 'fp': mine[0]['fp']}]})
        self.assertEqual(got['confirmed'], 1)
        for w, ag in zip(mine, ags):
            self.assertTrue(ag.wait('joined', 30), ag.status())
            row = G.target_row(STORE, w['id'])
            info = wait_for(lambda: not G.info(STORE, row).get('pending') and
                            G.info(STORE, row), 30)
            self.assertTrue(info and info['joined'], G.info(STORE, row))
            self.assertEqual(info['enroll']['title'], 'Branch offices')
            self.assertEqual(G.hello(STORE, row)['host'], ag.host)
            self.assertEqual(T.json.loads(ag.cli('status').stdout)['mode'], 'active')
        msgs = events(t0)
        self.assertTrue(any('a server enrolled with the enrollment code "Branch offices": '
                            'target weba' in m for m in msgs), msgs)
        self.assertTrue(any('the agent of target webb was confirmed by tester' in m
                            for m in msgs))
        for ag in ags:
            ag.stop()
        drop_targets('weba', 'webb')

    def test_2_the_same_server_again_the_same_target(self):
        code = G.enroll_new(STORE, 'tester', title='Again', mode='active', most=1)
        d = code_data(code['code'])
        _key, csr = keypair()
        body = enroll_body(d, csr, 'again1.example.test')
        st, out = G.wire(STORE, 'enroll', body, '', 'NONE', '192.0.2.7')
        self.assertEqual(st, 200, out)
        self.assertEqual(out['target'], 'again1')
        # acme's answer proves the target's code - its secret derived, never sent
        sec = G.proof(d['s'], 'target', d['e'], out['i'])
        self.assertNotIn(sec, json.dumps(out))
        want = G.proof(sec, 'joined', out['i'], hashlib.sha256(out['ca_pem'].encode())
                       .hexdigest(), out['cmd_pub'], out['agent_id'], body['nonce'])
        self.assertEqual(out['proof'], want)
        row = G.target_row(STORE, 'again1')
        self.assertEqual(G.target_conf(row)['host'], 'again1.example.test')
        # its answer lost: asked again (a new CSR of the same key, a new nonce) - the same
        # target, the same join; the code (one server at most) not used up by it
        csr2 = subprocess.run(
            ['openssl', 'req', '-new', '-key', '/dev/stdin', '-subj', '/CN=acme-agent'],
            input=_key, capture_output=True, check=True).stdout.decode()
        body2 = enroll_body(d, csr2, 'again1.example.test')
        body2['enc_pub'] = body['enc_pub']
        body2['proof'] = G.proof(d['s'], 'enroll', d['e'], hashlib.sha256(csr2.encode())
                                 .hexdigest(), body2['enc_pub'], body2['nonce'],
                                 'again1.example.test')
        st, out2 = G.wire(STORE, 'enroll', body2, '', 'NONE', '192.0.2.7')
        self.assertEqual(st, 200, out2)
        self.assertEqual((out2['target'], out2['i'], out2['agent_id']),
                         (out['target'], out['i'], out['agent_id']))
        self.assertEqual(G.enroll_get(STORE, d['e'])['uses'], 1)
        self.assertEqual(len([w for w in G.waiting(STORE) if w['name'].startswith('again1')]),
                         1)
        # the same name with another key: another server - the code allows one only
        _k3, csr3 = keypair()
        st, out3 = G.wire(STORE, 'enroll', enroll_body(d, csr3, 'again1.example.test'), '',
                          'NONE', '192.0.2.8')
        self.assertEqual(st, 403)
        self.assertIn('used by as many servers as it allows', out3['said'])
        # the join's state asked with the derived secret, as the agent asks it
        nonce = secrets.token_hex(16)
        st, got = G.wire(STORE, 'status', {'i': out['i'], 'nonce': nonce,
                                          'proof': G.proof(sec, 'status', out['i'], nonce)},
                         '', 'NONE')
        self.assertEqual((st, got['state']), (200, 'confirm'))
        drop_targets('again1')

    def test_3_refused(self):
        t0 = time.time() - 1
        code = G.enroll_new(STORE, 'tester', title='Refusals', mode='active', most=3)
        d = code_data(code['code'])
        _key, csr = keypair()
        # a wrong proof (another secret), a proof of another name
        st, out = G.wire(STORE, 'enroll', enroll_body(d, csr, 'x1.example.test',
                                                       secret='not-the-secret'), '', 'NONE',
                         '192.0.2.9')
        self.assertEqual((st, out['said']), (403, 'the request does not prove the enrollment '
                                                  'code'))
        body = enroll_body(d, csr, 'x1.example.test')
        body['fqdn'] = 'x2.example.test'
        self.assertEqual(G.wire(STORE, 'enroll', body, '', 'NONE')[0], 403)
        self.assertTrue(any('was refused by the enrollment code "Refusals"' in m
                            for m in events(t0)))
        # no such code
        body = enroll_body(dict(d, e='0123456789ab'), csr, 'x1.example.test')
        self.assertEqual(G.wire(STORE, 'enroll', body, '', 'NONE')[0], 403)
        # run out
        ec = G.enroll_get(STORE, d['e'])
        ec['until'] = time.time() - 5
        G._enroll_put(STORE, ec)
        st, out = G.wire(STORE, 'enroll', enroll_body(d, csr, 'x1.example.test'), '', 'NONE')
        self.assertEqual(st, 403)
        self.assertIn('ran out', out['said'])
        self.assertEqual([c for c in G.enroll_list(STORE) if c['id'] == d['e']][0]['state'],
                         'expired')
        ec['until'] = time.time() + 3600
        G._enroll_put(STORE, ec)
        # revoked
        G.enroll_revoke(STORE, d['e'], 'tester')
        st, out = G.wire(STORE, 'enroll', enroll_body(d, csr, 'x1.example.test'), '', 'NONE')
        self.assertEqual(st, 403)
        self.assertIn('revoked', out['said'])
        self.assertIsNone(STORE.db.row("SELECT id FROM cert_targets WHERE name = 'x1'"))
        # the agents' port off: nothing answers
        code = G.enroll_new(STORE, 'tester', title='Off', mode='active')
        E.CONFIG['certs_agents_active'] = 0
        st, out = G.wire(STORE, 'enroll', enroll_body(code_data(code['code']), csr,
                                                       'x1.example.test'), '', 'NONE')
        self.assertEqual(st, 404)
        E.CONFIG['certs_agents_active'] = 1

    def test_4_confirmed_automatically(self):
        t0 = time.time() - 1
        code = G.enroll_new(STORE, 'tester', title='Lab', mode='active', auto=True)
        self.assertTrue(any('CONFIRMED AUTOMATICALLY' in m for m in events(t0)))
        d = code_data(code['code'])
        _key, csr = keypair()
        st, out = G.wire(STORE, 'enroll', enroll_body(d, csr, 'lab7.example.test'), '', 'NONE',
                         '192.0.2.10')
        self.assertEqual(st, 200, out)
        row = G.target_row(STORE, 'lab7')
        info = G.info(STORE, row)
        self.assertTrue(info['pending']['confirmed'])
        self.assertTrue(info['joined'])
        self.assertFalse([w for w in G.waiting(STORE) if w['name'] == 'lab7'])
        self.assertTrue(any('target lab7' in m and 'confirmed automatically' in m
                            for m in events(t0)))
        self.assertTrue(any('lab7 was confirmed by the enrollment code "Lab" (confirmed '
                            'automatically)' in m for m in events(t0)))
        sec = G.proof(d['s'], 'target', d['e'], out['i'])
        nonce = secrets.token_hex(16)
        st, got = G.wire(STORE, 'status', {'i': out['i'], 'nonce': nonce,
                                          'proof': G.proof(sec, 'status', out['i'], nonce)},
                         '', 'NONE')
        self.assertEqual((st, got['state']), (200, 'done'))
        self.assertIn('BEGIN CERTIFICATE', got['cert_pem'])
        drop_targets('lab7')

    def test_5_a_windows_server(self):
        if S.plugin_class('target', 'agent_windows') is None:
            self.skipTest('the target kind agent_windows is not here yet')
        code = G.enroll_new(STORE, 'tester', title='Windows', mode='passive', port=8446)
        d = code_data(code['code'])
        _key, csr = keypair()
        st, out = G.wire(STORE, 'enroll', enroll_body(
            d, csr, 'winsrv1.corp.example.test', platform='windows', host='WINSRV1',
            osname='Windows Server 2022 Standard (10.0.20348)'), '', 'NONE', '192.0.2.20')
        self.assertEqual(st, 200, out)
        self.assertEqual(out['target'], 'winsrv1')
        row = G.target_row(STORE, 'winsrv1')
        self.assertEqual(row['kind'], 'agent_windows')
        cfg = G.target_conf(row)
        self.assertEqual((cfg['mode'], cfg['host'], int(cfg['port'])),
                         ('passive', 'winsrv1.corp.example.test', 8446))
        w = [x for x in G.waiting(STORE) if x['name'] == 'winsrv1'][0]
        self.assertEqual((w['platform'], w['os']), ('windows', 'Windows Server 2022 Standard '
                                                                '(10.0.20348)'))
        self.assertEqual(G.info(STORE, row)['platform'], 'windows')
        # it is an agent everywhere: the pane's list, the rows the leader looks after
        self.assertIn('winsrv1', [r['name'] for r in G.rows(STORE)])
        drop_targets('winsrv1')

    def test_6_passive_listens_once_joined(self):
        port = T.free_port()
        code = G.enroll_new(STORE, 'tester', title='Passive ones', mode='passive', port=port)
        ag = Server('enp', 'webp')
        T.www_policy(ag)
        ag.start_root()
        ag.cli('join', code['code'], '--no-wait', '--listen', '127.0.0.1')
        ag.start_net()
        w = wait_for(lambda: [x for x in G.waiting(STORE) if x['name'] == 'webp'])
        self.assertTrue(w, G.waiting(STORE))
        w = w[0]
        row = G.target_row(STORE, w['id'])
        cfg = G.target_conf(row)
        self.assertEqual((cfg['mode'], cfg['host'], int(cfg['port'])),
                         ('passive', '127.0.0.1', port))
        # confirmed (the card's Confirm asks look: nothing to reach yet - it asks acme)
        from acmelib.certs import api_agents as AA
        got = AA._confirm(FakeH({'id': w['id'], 'fp': w['fp']}), SESSION)
        self.assertFalse(got.get('said'), got)
        self.assertTrue(ag.wait('joined', 30), ag.status())
        # it listens now: acme asks it, its first answer ends the join
        info = wait_for(lambda: not G.info(STORE, row).get('pending') and G.info(STORE, row),
                        60, 0.5)
        self.assertTrue(info, G.info(STORE, row))
        self.assertEqual(info['state'], 'answers')
        self.assertEqual(G.hello(STORE, row)['host'], 'webp')
        st = T.json.loads(ag.cli('status').stdout)
        self.assertEqual((st['mode'], st['joined'], st['port']), ('passive', True, port))
        ag.stop()
        drop_targets('webp')

    def test_7_command_line_and_console(self):
        from acmelib.certs import cli as C
        import argparse
        cl = C.Cli.__new__(C.Cli)
        cl.store = STORE
        cl.WHO = 'tester'
        cl.json = True
        cl.args = argparse.Namespace(title='From the CLI', mode='active', port=None, days=2,
                                     most=3, auto_confirm=False)
        outs = []
        cl.out = lambda v: outs.append(v)
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            self.assertEqual(C.Cli.target_agent(cl, ['enroll', 'new']), 0)
        made = outs[-1]
        self.assertTrue(made['code'].startswith('ACAE1.'))
        self.assertEqual((made['title'], made['mode'], made['most']), ('From the CLI',
                                                                       'active', 3))
        with redirect_stdout(buf):
            C.Cli.target_agent(cl, ['enroll', 'list'])
        self.assertIn(made['id'], [r['id'] for r in outs[-1]['rows']])
        with redirect_stdout(buf):
            C.Cli.target_agent(cl, ['waiting'])
        self.assertIn('rows', outs[-1])
        cl.json = False
        buf = io.StringIO()
        with redirect_stdout(buf):
            C.Cli.target_agent(cl, ['enroll', 'list'])
            C.Cli.target_agent(cl, ['enroll', 'revoke', made['id']])
            C.Cli.target_agent(cl, ['waiting'])
        text = buf.getvalue()
        self.assertIn('From the CLI', text)
        self.assertIn('revoked: the enrollment code "From the CLI"', text)
        with self.assertRaises(SystemExit):
            C.Cli.target_agent(cl, ['enroll', 'revoke'])
        # the console: Certificates → Target agents
        from acmelib.certs import console as CO

        class Con(object):
            def __init__(self):
                self.subs, self.acts = [], []

            def sub(self, title, items):
                self.subs.append((title, [i[1] for i in items]))
                return items

            def menu_items(self):
                return self.subs
        con = Con()
        items = CO.menu(con)
        self.assertTrue(any('Target agents' in i[1] for i in items))
        agents = [i for i in items if 'Target agents' in i[1]][0][2]()
        self.assertEqual(con.subs[-1][0], 'Target agents')
        self.assertTrue(any('waiting' in w for w in con.subs[-1][1]))
        self.assertTrue(any('enrollment code' in w for w in con.subs[-1][1]))
        self.assertTrue(agents)


class Wiring(unittest.TestCase):
    """The agents' port relays /agent/v1/enroll (nginx, agent.php); kinds are agents."""

    def test_nginx_and_relay(self):
        with open(os.path.join(T.ROOT, 'deploy', 'acme_web.py')) as fh:
            src = fh.read()
        self.assertIn("loc('/agent/v1/enroll', 'enroll', False, 30)", src)
        with open(os.path.join(T.ROOT, 'web', 'agent.php')) as fh:
            php = fh.read()
        self.assertIn("['join', 'status', 'poll', 'enroll']", php)
        from acmelib.certs import api_agents  # noqa: F401  (its routes)
        self.assertIn(('POST', '/api/agent-wire/enroll'), {(m, p) for m, p in _routes()})

    def test_kinds(self):
        self.assertTrue(G.is_agent_kind('agent') and G.is_agent_kind('agent_windows'))
        self.assertFalse(G.is_agent_kind('ssh'))
        # no check of kind 'agent' alone is left in acme's code (the database's agent aside)
        import re
        left = []
        for top, _dirs, files in os.walk(os.path.join(T.ROOT, 'acmelib')):
            for n in files:
                if not n.endswith('.py') or n.startswith('407_'):
                    continue
                with open(os.path.join(top, n), encoding='utf-8') as fh:
                    for i, line in enumerate(fh, 1):
                        if re.search(r"(?:get\('kind'\)|\['kind'\]|\bkind)\s*(?:==|!=)\s*"
                                     r"'agent'(?!_)|WHERE.*\bkind = 'agent'", line):
                            left.append('%s:%d %s' % (n, i, line.strip()))
        self.assertEqual(left, [])


class Pages(unittest.TestCase):
    """The pages in a browser: test/agents_enroll_page.js (node with playwright; skipped
    without) - English and Czech, 1400 and 390 px."""

    def test_enroll_pages(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        argv = [node, os.path.join(HERE, 'agents_enroll_page.js'), os.path.join(T.ROOT, 'web')]
        extra = os.environ.get('ACME_CS_EXTRA')         # Czech not merged into cs.json yet
        if extra:
            argv.append(extra)
        got = subprocess.run(argv, capture_output=True, text=True, timeout=900)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        bad = [k for k, v in (out.get('checks') or {}).items() if not v]
        with open(os.path.join(T.ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as fh:
            merged = '"Enrollment codes"' in fh.read()
        if not extra and not merged:
            # the Czech of 1.0.120 not merged into web/lang/cs.json yet: only that is left out
            bad = [k for k in bad if not k.endswith('czech')]
            out['ok'] = not out.get('error') and not out.get('errors') and not bad
        self.assertTrue(out.get('ok'), json.dumps({'failed': bad, 'error': out.get('error'),
                                                   'errors': out.get('errors'),
                                                   'more': {k: v for k, v in out.items() if k
                                                            not in ('checks', 'ok', 'errors',
                                                                    'error')}})
                        + got.stderr[-2000:])


def _routes():
    return list(getattr(E, 'ROUTES', {}) or {})


if __name__ == '__main__':
    unittest.main(verbosity=2)
