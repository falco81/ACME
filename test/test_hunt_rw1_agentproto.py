#!/usr/bin/env python3
"""Hunt w1 in the target agent's protocol (deploy/agent/acme_agent.py):

    python3 test/test_hunt_rw1_agentproto.py

* passive, during the join: a message of anybody who reaches the port, without the proof of the
  join code's secret, set the join "refused" (`acme-agent join` stopped with it, the
  fingerprint gone from the status) - now refused and audited only, and acme still joins;
* a proof with a letter beyond ASCII stopped the join with a TypeError (no answer at all);
* active: the poll (the results of the jobs, the facts) was sent before acme's certificate
  was checked - to whoever answered with any certificate of the agent authority (another
  agent's); now nothing is sent to such a peer;
* a body nested deeper than Python reads got no answer (the connection closed) - now 400;
  a probe or connection of an endless timeout went wrong unanswered; an active poll's entry of
  no shape stopped the jobs after it;
* `allow file DIR mode=` (no value) allowed the default 0644 - now the line is not read.

Live parts start a real agent as test_target_agent.py does (root, setpriv, openssl); temporary
folders and ports only.
"""
import importlib.util
import json
import os
import socket
import ssl
import subprocess
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location('target_agent_base_w1',
                                               os.path.join(HERE, 'test_target_agent.py'))
TA = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(TA)
AG, G, STORE, CAN = TA.AG, TA.G, TA.STORE, TA.CAN


def setUpModule():
    TA.setUpModule()


def tearDownModule():
    TA.tearDownModule()


class _T(unittest.TestCase):
    pass


def raw_post(port, path, body, ctx, timeout=20):
    s = socket.create_connection(('127.0.0.1', port), timeout)
    t = ctx.wrap_socket(s)
    if isinstance(body, str):
        body = body.encode()
    t.sendall(b'POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n' % (path.encode(),
                                                                             len(body)) + body)
    out = b''
    t.settimeout(timeout)
    try:
        while True:
            g = t.recv(65536)
            if not g:
                break
            out += g
    except OSError:
        pass
    t.close()
    return out


class PolicyWords(unittest.TestCase):
    def test_empty_owner_or_mode_is_no_entry(self):
        for line in ('allow file /srv/x mode=', 'allow file /srv/x owner=',
                     'allow file /srv/x owner=app:app mode='):
            pol = AG.parse_policy(line)
            self.assertEqual(pol['files'], [], line)
            self.assertTrue(pol['problems'] and 'takes a value' in pol['problems'][0], pol)
        # as before
        pol = AG.parse_policy('allow file /srv/x owner=app: mode=0640\nallow file /srv/y\n')
        self.assertEqual(pol['problems'], [])
        self.assertEqual([(f['dir'], f['owner'], f['group'], f['mode']) for f in pol['files']],
                         [('/srv/x', 'app', 'app', 0o640), ('/srv/y', 'root', 'root', 0o644)])


class JoinProofs(unittest.TestCase):
    J = {'s': 'secret', 'i': 'a' * 12, 'ca': '0' * 64, 'ck': '0' * 64}

    def test_proof_beyond_ascii_unproven(self):
        net = AG.Net()
        for ans in ({'proof': 'é' * 64}, {'proof': None}, {}):
            with self.assertRaises(AG.Unproven):
                net.join_answer(self.J, ans, '0' * 32)
            with self.assertRaises(AG.Unproven):
                net.join_finish(dict(self.J, agent_id='ag-0123456789ab'), ans, '0' * 32,
                                'ag-0123456789ab')
        self.assertTrue(issubclass(AG.Unproven, AG.Refused))


class Robust(unittest.TestCase):
    def test_probe_and_connect_of_an_endless_timeout(self):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        net = AG.Net()
        got = net.net_probe({'timeout': float('inf')}, {'dest': ('127.0.0.1', port)})
        self.assertFalse(got['ok'])
        got = net.net_connect({'timeout': float('inf')}, {'dest': ('127.0.0.1', port)})
        self.assertFalse(got['ok'])
        self.assertIn('cannot be reached', got['said'])

    def test_poll_entries_of_no_shape(self):
        class FakeNet(object):
            stopping = False
            ran = []

            def joined(self):
                return True

            def conf(self):
                return {'agent_id': 'ag-0123456789ab'}

            def facts(self):
                return {}

            def job(self, one):
                self.ran.append(one)
                if len(self.ran) == 2:
                    self.stopping = True
                return {'ok': True}
        net = FakeNet()
        a = AG.Active(net)
        a.post = lambda path, body, timeout=60: {
            '_status': 200, 'jobs': [5, {'job': '[1]'}, 'x', {'job': '{"job": "j1"}'}]}
        a.loop()
        self.assertEqual(len(net.ran), 2)
        self.assertEqual([r['job'] for r in a.results], ['', 'j1'])


def _ca_and_certs(d):
    def run(*args):
        subprocess.run(['openssl'] + list(args), check=True, capture_output=True)
    j = lambda n: os.path.join(d, n)  # noqa: E731
    run('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
        '-keyout', j('ca.key'), '-out', j('ca.crt'), '-days', '2', '-subj', '/CN=agents CA')
    with open(j('ext'), 'w') as fh:
        fh.write('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                 'extendedKeyUsage=serverAuth,clientAuth\n')
    for name, cn in (('acme', AG.CTL_CN), ('other', AG.AGENT_CN + 'ag-0123456789ab'),
                     ('tls', AG.AGENT_CN + 'ag-00000000000a')):
        run('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout',
            j(name + '.key'), '-out', j(name + '.csr'), '-subj', '/CN=' + cn)
        run('x509', '-req', '-in', j(name + '.csr'), '-CA', j('ca.crt'), '-CAkey', j('ca.key'),
            '-CAcreateserial', '-days', '2', '-out', j(name + '.crt'), '-extfile', j('ext'))


class _Peer(object):
    """A TLS server of the agent authority: what it was sent, and an answer."""

    def __init__(self, d, name):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(os.path.join(d, name + '.crt'), os.path.join(d, name + '.key'))
        self.ctx.load_verify_locations(os.path.join(d, 'ca.crt'))
        self.ctx.verify_mode = ssl.CERT_OPTIONAL
        self.ls = socket.socket()
        self.ls.bind(('127.0.0.1', 0))
        self.ls.listen(4)
        self.port = self.ls.getsockname()[1]
        self.got = []
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _a = self.ls.accept()
            except OSError:
                return
            try:
                t = self.ctx.wrap_socket(c, server_side=True)
                t.settimeout(3)
                data = b''
                try:
                    while b'\r\n\r\n' not in data or not data.rstrip().endswith(b'}'):
                        g = t.recv(65536)
                        if not g:
                            break
                        data += g
                except OSError:
                    pass
                self.got.append(data)
                if data:
                    body = b'{"ok": true, "jobs": []}'
                    t.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n'
                              b'\r\n' % len(body) + body)
                t.close()
            except (OSError, ssl.SSLError):
                c.close()

    def stop(self):
        self.ls.close()


class ActiveSendsOnlyToAcme(unittest.TestCase):
    def test_nothing_sent_to_another_agents_certificate(self):
        d = os.path.join(TA.TMP, 'w1-active')
        os.makedirs(d + '/st', exist_ok=True)
        _ca_and_certs(d)
        os.rename(d + '/tls.crt', d + '/st/tls.crt')
        os.rename(d + '/tls.key', d + '/st/tls.key')
        m = TA.agent_mod()
        m.STATE, m.CA_FILE, m.CONF = d + '/st', d + '/ca.crt', d + '/agent.json'
        for name, acme in (('other', False), ('acme', True)):
            peer = _Peer(d, name)
            try:
                with open(m.CONF, 'w') as fh:
                    json.dump({'agent_id': 'ag-00000000000a', 'joined': True,
                               'acme': ['127.0.0.1:%d' % peer.port]}, fh)
                a = m.Active(m.Net())
                body = {'agent': 'ag-00000000000a', 'results': [{'job': 'x', 'result': {
                    'said': 'a result only acme may read'}}]}
                if acme:
                    got = a.post('/agent/v1/poll', body)
                    self.assertEqual(got['_status'], 200)
                    self.assertIn(b'a result only acme may read', b''.join(peer.got))
                else:
                    with self.assertRaises(m.Refused) as e:
                        a.post('/agent/v1/poll', body)
                    self.assertIn('acme\'s certificate', str(e.exception))
                    time.sleep(0.5)
                    self.assertNotIn(b'a result only acme may read', b''.join(peer.got))
                    self.assertNotIn(b'POST', b''.join(peer.got))
            finally:
                peer.stop()


@unittest.skipUnless(CAN, 'needs root, setpriv, openssl')
class LiveJoinWindow(unittest.TestCase):
    def test_unproven_messages_leave_the_join_alone(self):
        port = TA.free_port()
        row = TA.target('w1join', mode='passive', host='127.0.0.1', port=port, timeout=20)
        code = G.code_new(STORE, row, 'tester')['code']
        ag = TA.Agent('w1join')
        try:
            ag.start_root()
            ag.cli('join', code, '--no-wait', '--listen', '127.0.0.1')
            ag.start_net()
            self.assertTrue(ag.wait('waiting', 10), ag.status())
            fp = ag.status().get('fp')
            self.assertTrue(fp)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            for path, body in (('/v1/join', '{}'), ('/v1/join/finish', '{}'),
                               ('/v1/join', '{"nonce": "%s", "proof": "\\u00e9"}' % ('0' * 32)),
                               ('/v1/join/finish', '{"nonce": "x", "proof": "\\u00e9"}')):
                out = raw_post(port, path, body, ctx)
                self.assertTrue(out.startswith(b'HTTP/1.1 403'), (path, body, out[:200]))
                st = ag.status()
                self.assertEqual(st.get('state'), 'waiting', (path, body, st))
                self.assertEqual(st.get('fp'), fp)
            # acme still joins it
            for _ in range(50):
                got = G.look(STORE, row, 'tester')
                if got.get('pending'):
                    break
                time.sleep(0.2)
            self.assertTrue(got.get('pending'), got)
            G.confirm(STORE, row, ag.cli('fingerprint').stdout.strip(), 'tester')
            self.assertTrue(ag.wait('joined'), ag.status())
        finally:
            ag.stop()


@unittest.skipUnless(CAN, 'needs root, setpriv, openssl')
class LivePassive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = TA.free_port()
        cls.row, cls.ag = TA.join_passive(_T(), 'w1pass', cls.port)
        cls.ag.policy('allow file %s owner=root:root mode=0644' % (cls.ag.www + '/ssl'),
                      'allow probe local', 'allow connect 127.0.0.1:1')
        c = G.ctl(STORE)
        for n, v in (('w1c.pem', c['cert_pem']), ('w1k.pem', c['key_pem'])):
            with open(os.path.join(TA.TMP, n), 'w') as fh:
                fh.write(v)
        cls.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cls.ctx.check_hostname = False
        cls.ctx.verify_mode = ssl.CERT_NONE
        cls.ctx.load_cert_chain(os.path.join(TA.TMP, 'w1c.pem'), os.path.join(TA.TMP, 'w1k.pem'))

    @classmethod
    def tearDownClass(cls):
        cls.ag.stop()

    def job(self, op, args):
        aid = G.state(STORE, self.row['id'])['agent_id']
        return G._passive_post(STORE, self.row, '/v1/job', G.sign_job(STORE, aid, op, args)[1])[0]

    def test_deep_body_answered(self):
        for path in ('/v1/job', '/v1/tunnel'):
            out = raw_post(self.port, path, '[' * 100000, self.ctx)
            self.assertTrue(out.startswith(b'HTTP/1.1 400'), out[:200])
        out = raw_post(self.port, '/v1/tunnel', json.dumps({'job': '[' * 100000}), self.ctx)
        self.assertTrue(out.startswith(b'HTTP/1.1 400'), out[:200])
        # as before
        out = raw_post(self.port, '/v1/job', '{"job": "x"}', self.ctx)
        self.assertTrue(out.startswith(b'HTTP/1.1 200'), out[:200])
        self.assertIn(b'refused', out)

    def test_endless_timeout_answered(self):
        got = self.job('probe', {'to': '127.0.0.1:1', 'timeout': 1e400})
        self.assertFalse(got['ok'])
        self.assertIn('127.0.0.1:1', got['said'])
        got = self.job('hello', {})
        self.assertTrue(got['ok'])


if __name__ == '__main__':
    unittest.main()
