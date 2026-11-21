#!/usr/bin/env python3
"""1.0.138 (agentsec): a target agent watched more closely - docs/target-agent.md "Watching an
agent". A real acme-agent (both sides, as test_target_agent.py runs it) against acme's engine in
this process:

* A6 the audit chain: the policy's line `audit chain` (its hash unchanged without it), the chain
  file (each entry the hash of the one before), `acme-agent audit verify` finding an entry
  changed; acme off - no key in any answer; on - the head with every answer, the entries read
  and checked, every job acme's; a job acme never sent (signed with its key by "somebody
  else"), a chain written anew: said, an alert, until a full administrator looks at it;
* A7 anomalies: the policy widened on the server, a new network, the clock, a newer agent - only
  when switched on;
* A8 keys: Rotate now (acme's command key changed: announced signed by the old one, proven by the
  new; the old one still taken for the overlap; the agent's key for secrets made anew and a
  deployment sealed to it), the key age report, a backup's keys (meta), once an hour at most;
* B6 what is served: the agent asked what 127.0.0.1:PORT serves (allow probe local) - "deployed
  but still serves the old certificate"; nothing asked without allow probe local;
* the routes refuse a role below theirs; old data (no new keys) is as before.

    python3 test/test_f138_agentsec.py
"""
import base64
import hashlib
import io
import json
import os
import ssl
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_target_agent as T  # noqa: E402

E, G, S, STORE = T.E, T.G, T.S, T.STORE
from acmelib.certs import agent_guard as AG  # noqa: E402


def need_account():
    """The agent's account (acmeagt) there: other agent tests running beside this one take it
    away when they end (userdel) - made again here rather than failing for it."""
    import pwd
    import subprocess
    if not T.CAN:
        return
    try:
        pwd.getpwnam(T.USER)
    except KeyError:
        subprocess.run(['useradd', '--system', '--no-create-home', '--shell',
                        '/usr/sbin/nologin', T.USER], capture_output=True)


def setUpModule():
    T.setUpModule()


def tearDownModule():
    # as test_target_agent's, but the account is left (another agent test may be using it)
    import shutil
    for a in list(T.Agent.ALL):
        a.stop()
    for w in list(T.Wire.ALL):
        w.stop()
    shutil.rmtree(T.TMP, ignore_errors=True)


class Wire(object):
    """A request as the daemon's handler reads it (its role, its body)."""
    def __init__(self, role, body=None, args=None):
        raw = json.dumps(body or {}).encode('utf-8')
        self.headers = {'Content-Length': str(len(raw))}
        self.rfile = io.BytesIO(raw)
        self.role, self.store = role, STORE
        self.args = args or {}

    def body(self):
        return E.ApiHandler.body(self)

    def me(self, level='readonly'):
        return {'role': self.role, 'name': 'f138-' + self.role}

    def arg(self, k, default=None):
        return self.args.get(k, default)


def settled(row, most=20):
    end = time.time() + most
    while time.time() < end and any(k[1] == int(row['id']) for k in AG.BUSY):
        time.sleep(0.1)


def route(method, path, role, body=None, args=None):
    return E.ROUTES[(method, path)](Wire(role, body, args))


# ---------------------------------------------------------------------------------------------
class PolicyLine(unittest.TestCase):
    def test_audit_chain_line(self):
        m = T.AG
        base = 'allow file /srv/ssl owner=root:root mode=0644\nallow unit nginx reload\n'
        p0 = m.parse_policy(base)
        p1 = m.parse_policy(base + 'audit chain\n')
        self.assertFalse(p0['problems'] or p1['problems'])
        self.assertNotIn('audit_chain', m.policy_canon(p0))     # its hash as before
        self.assertNotEqual(m._sha(m.policy_canon(p0)), m._sha(m.policy_canon(p1)))
        self.assertIn('audit chain', m.policy_lines(p1))
        self.assertTrue(m.policy_report(p1, 'x')['audit_chain'])
        self.assertNotIn('audit_chain', m.policy_report(p0, 'x'))
        for bad in ('audit', 'audit chain now', 'audit log'):
            self.assertTrue(m.parse_policy(bad)['problems'], bad)
        got = m.policy_check(base + 'audit chain\n')
        self.assertFalse(got['errors'])
        # acme reads the same canon of an entry as the agent writes
        e = {'n': 3, 'prev': '0' * 64, 'op': 'deploy', 'ok': True, 'ts': 1700000000.123,
             'said': 'ž "x"', 'files': [['/a', 'b' * 64]]}
        self.assertEqual(m.chain_canon(e), AG.chain_canon(e))


class ChainFile(unittest.TestCase):
    def test_chain_written_checked_and_broken(self):
        m = T.AG
        d = os.path.join(T.TMP, 'chainunit')
        os.makedirs(d, exist_ok=True)
        old = m.ROOT_STATE
        m.ROOT_STATE = d
        try:
            for i in range(4):
                e = m.chain_add({'op': 'deploy', 'job': 'j%d' % i, 'ok': i != 2,
                                 'said': 'x' * 400, 'files': [('/p', 'f' * 64)]}, force=True)
                self.assertEqual(e['n'], i + 1)
            self.assertEqual(m.chain_verify()[:2], (True, 4))
            lines = list(m.chain_lines())
            self.assertEqual(json.loads(lines[1])['prev'], json.loads(lines[0])['h'])
            self.assertEqual(len(json.loads(lines[0])['said']), 300)
            self.assertEqual([json.loads(x)['n'] for x in m.chain_read(3)], [3, 4])
            # one entry changed: found
            bad = json.loads(lines[1])
            bad['ok'] = False
            with open(m.chain_path(), 'w') as fh:
                fh.write('\n'.join([lines[0], json.dumps(bad)] + lines[2:]) + '\n')
            ok, _n, why = m.chain_verify()
            self.assertFalse(ok)
            self.assertIn('entry 2 is not what its hash says', why)
            # an entry taken away: a gap
            with open(m.chain_path(), 'w') as fh:
                fh.write('\n'.join([lines[0]] + lines[2:]) + '\n')
            self.assertIn('a gap', m.chain_verify()[2])
        finally:
            m.ROOT_STATE = old

    def test_unseal_with_the_key_before(self):
        m = T.AG
        d = os.path.join(T.TMP, 'encunit')
        os.makedirs(d, exist_ok=True)
        old_rs = m.ROOT_STATE
        m.ROOT_STATE = d
        try:
            k_old, k_new = os.urandom(32), os.urandom(32)
            sealed = G.seal(base64.b64encode(m.x25519_public(k_old)).decode(), 'ag-0011223344',
                            'env', b'hello')
            with self.assertRaises(m.Refused):
                m.unseal(sealed, k_new, 'ag-0011223344', 'env')
            with open(os.path.join(d, 'enc.prev'), 'w') as fh:
                json.dump({'key': k_old.hex(), 'until': time.time() + 60}, fh)
            self.assertEqual(m.unseal(sealed, k_new, 'ag-0011223344', 'env'), b'hello')
            with open(os.path.join(d, 'enc.prev'), 'w') as fh:     # its overlap over
                json.dump({'key': k_old.hex(), 'until': time.time() - 1}, fh)
            with self.assertRaises(m.Refused):
                m.unseal(sealed, k_new, 'ag-0011223344', 'env')
        finally:
            m.ROOT_STATE = old_rs


# ---------------------------------------------------------------------------------------------
@unittest.skipUnless(T.CAN, 'needs root, setpriv and openssl')
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_account()
        cls.port = T.free_port()
        cls.row, cls.ag = T.join_passive(cls(), 'f138web', cls.port)
        T.www_policy(cls.ag)

    @classmethod
    def tearDownClass(cls):
        cls.ag.stop()

    def row_now(self):
        return S.plugin_row(STORE, 'target', 'f138web')

    def test_1_off_is_as_before(self):
        row = self.row_now()
        self.assertEqual(AG.opts(STORE, row['id'])['audit'], False)
        got = G.call(STORE, row, 'hello', {})
        self.assertTrue(got['ok'])
        self.assertNotIn('audit', got)                  # no chain: no key
        self.assertIn('audit-chain', got['features'])
        self.assertFalse(os.path.exists(self.ag.d + '/rs/audit.chain'))
        self.assertFalse(STORE.db.rows("SELECT k FROM meta WHERE k LIKE 'agentsent:%'"))
        info = G.info(STORE, row)
        self.assertEqual(info['guard']['audit']['state'], 'off')
        self.assertIsNone(info['guard']['anomalies'])
        # the routes: a reader sees, may not switch it on
        v = route('GET', '/api/agents/guard', 'readonly', args={'id': row['id']})['guard']
        self.assertFalse(v['opts']['audit'])
        for path, body in (('/api/agents/guard', {'id': row['id'], 'audit': True}),
                           ('/api/agents/guard/ack', {'id': row['id'], 'what': 'audit'}),
                           ('/api/agents/guard/rotate', {'id': row['id'], 'what': 'both'}),
                           ('/api/agents/keys/rotate', {})):
            for role in ('readonly', 'certadmin'):
                with self.assertRaises(E.ApiError) as e:
                    route('POST', path, role, body)
                self.assertEqual(e.exception.status, 403, path)
        with self.assertRaises(E.ApiError) as e:
            route('POST', '/api/agents/guard/verify', 'readonly', {'id': row['id']})
        self.assertEqual(e.exception.status, 403)

    def test_2_audit_chain(self):
        row = self.row_now()
        got = route('POST', '/api/agents/guard', 'fulladmin', {'id': row['id'], 'audit': True})
        self.assertTrue(got['guard']['opts']['audit'])
        # acme on, the agent's policy without the line: said
        G.call(STORE, row, 'hello', {})
        self.assertEqual(AG.view(STORE, row)['audit']['state'], 'agent_off')
        T.www_policy(self.ag, 'audit chain', 'allow probe local')
        hello = G.call(STORE, row, 'hello', {})
        self.assertTrue(hello['audit']['on'])
        n0 = hello['audit']['n']
        t, _ctx = T.module(row, 1)
        t.deploy(T.Bundle('a'), T.opts(self.ag))
        settled(row)                        # the read a deployment starts by itself
        st = AG.read_chain(STORE, row)
        self.assertGreater(st['verified_n'], n0)
        marks = {e['op']: e['mark'] for e in st['entries']}
        self.assertEqual(marks.get('deploy'), 'acme')
        self.assertEqual(marks.get('audit'), 'acme')
        self.assertFalse(st.get('problems'))
        self.assertEqual(AG.view(STORE, row)['audit']['state'], 'ok')
        # the journal of the root side: the chain's lines are in the file, each linked
        ok = self.ag.cli('audit', 'verify')
        self.assertIn('each one following the one before', ok.stdout)
        # a job acme never sent - signed with acme's key, not kept (somebody else holding it);
        # (acme switched it on a minute ago: a job signed just before is not "unknown")
        rec = json.loads(STORE.get_meta(AG.M_AUDIT % row['id']))
        rec['enabled_at'] = rec['base_at'] = time.time() - 60
        STORE.set_meta(AG.M_AUDIT % row['id'], json.dumps(rec))
        stt = G.state(STORE, row['id'])
        _jid, env = G.sign_job(STORE, stt['agent_id'], 'hello', {})
        got, _peer = G._passive_post(STORE, row, '/v1/job', env)
        self.assertTrue(got['ok'])
        st = AG.read_chain(STORE, row)
        self.assertTrue(any(p["kind"] == "unknown" for p in st.get("problems") or []), json.dumps(st, indent=1)[-3000:])
        self.assertTrue(any(e['mark'] == 'unknown' for e in st['entries']))
        self.assertEqual(AG.view(STORE, row)['audit']['state'], 'mismatch')
        al = [a for a in G.alerts(STORE) if a['key'] == 'agent-audit:%s' % row['id']]
        self.assertEqual(len(al), 1)
        self.assertEqual(al[0]['level'], 'bad')
        ev = STORE.db.rows("SELECT words FROM events WHERE words LIKE '%audit chain of the agent "
                           "of target f138web does not agree%'")
        self.assertTrue(ev)
        # looked at: put away (a certificate administrator may not)
        with self.assertRaises(E.ApiError):
            route('POST', '/api/agents/guard/ack', 'certadmin', {'id': row['id'], 'what': 'audit'})
        route('POST', '/api/agents/guard/ack', 'fulladmin', {'id': row['id'], 'what': 'audit'})
        self.assertFalse([a for a in G.alerts(STORE) if a['key'].startswith('agent-audit:')])
        # the chain written anew on the server (root rewrote it): found at the next read
        path = self.ag.d + '/rs/audit.chain'
        lines = open(path).read().splitlines()
        e = json.loads(lines[-2])
        e['said'] = 'nothing happened here'
        e['h'] = hashlib.sha256(AG.chain_canon(e)).hexdigest()
        lines[-2] = json.dumps(e, sort_keys=True, separators=(',', ':'))
        with open(path, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        G.call(STORE, row, 'hello', {})
        st = AG.read_chain(STORE, row)              # from the last one read: not seen yet
        self.assertFalse(st.get('problems'))
        st = route('POST', '/api/agents/guard/verify', 'certadmin', {'id': row['id']})
        st = json.loads(STORE.get_meta(AG.M_AUDIT % row['id']))
        self.assertTrue(any(p['kind'] in ('rewritten', 'changed') for p in st['problems']),
                        st['problems'])
        self.assertIn('BROKEN', self.ag.cli('audit', 'verify', ok=False).stdout)
        route('POST', '/api/agents/guard/ack', 'fulladmin', {'id': row['id'], 'what': 'audit'})
        # the chain is not kept by acme from a new start: switched off - nothing more kept
        route('POST', '/api/agents/guard', 'fulladmin', {'id': row['id'], 'audit': False})
        n = len(STORE.db.rows("SELECT k FROM meta WHERE k LIKE 'agentsent:%'"))
        G.call(STORE, row, 'hello', {})
        self.assertEqual(len(STORE.db.rows("SELECT k FROM meta WHERE k LIKE 'agentsent:%'")), n)
        os.unlink(path)
        T.www_policy(self.ag)

    def test_3_anomalies(self):
        row = self.row_now()
        T.www_policy(self.ag)
        G.call(STORE, row, 'hello', {})
        route('POST', '/api/agents/guard', 'fulladmin', {'id': row['id'], 'anomaly': True})
        self.assertEqual(AG.anomaly_view(STORE, row, G.state(STORE, row['id']))['items'], [])
        # widened on the server: a folder more
        T.www_policy(self.ag, 'allow file /srv/more owner=root:root mode=0644')
        G.call(STORE, row, 'hello', {})
        items = AG.anomaly_view(STORE, row, G.state(STORE, row['id']))['items']
        wide = [i for i in items if i['kind'] == 'widened']
        self.assertEqual(len(wide), 1, items)
        self.assertIn('file /srv/more', wide[0]['words'])
        self.assertTrue([a for a in G.alerts(STORE)
                         if a['key'] == 'agent-anomaly:%s:widened' % row['id']])
        tile = G.info(STORE, row)['guard']['anomalies']
        self.assertTrue(any(a['kind'] == 'widened' and a['level'] == 'bad' for a in tile))
        # narrowed: a change, not a widening
        self.ag.policy('allow file %s owner=root:%s mode=0644' % (self.ag.www + '/ssl', T.USER),
                       'allow unit nginx reload', 'allow test -- /bin/true')
        G.call(STORE, row, 'hello', {})
        kinds = [i['kind'] for i in AG.anomaly_view(STORE, row, G.state(STORE, row['id']))['items']]
        self.assertIn('policy', kinds)
        # a new network (an active agent polls from another address)
        st = G.state(STORE, row['id'])
        st['last_ip'] = '198.51.100.7'
        G.state_put(STORE, row['id'], st)
        AG.evaluate(STORE, row, st)               # the first: its usual
        st['last_ip'] = '203.0.113.9'
        G.state_put(STORE, row['id'], st)
        AG.evaluate(STORE, row, st)
        kinds = [i['kind'] for i in AG.anomaly_view(STORE, row, st)['items']]
        self.assertIn('network', kinds)
        # the clock off by 90 s: amber
        st['skew'], st['skew_at'] = 90, time.time()
        G.state_put(STORE, row['id'], st)
        clock = [i for i in AG.anomalies(STORE, row, st) if i['kind'] == 'clock']
        self.assertEqual(clock[0]['level'], 'warn')
        # looked at: its usual from now
        route('POST', '/api/agents/guard/ack', 'fulladmin', {'id': row['id'], 'what': 'anomaly'})
        st['skew'] = 0
        G.state_put(STORE, row['id'], st)
        kinds = [i['kind'] for i in AG.anomaly_view(STORE, row, G.state(STORE, row['id']))['items']]
        self.assertEqual([k for k in kinds if k in ('widened', 'policy', 'network')], [])
        route('POST', '/api/agents/guard', 'fulladmin', {'id': row['id'], 'anomaly': False})
        self.assertFalse([a for a in G.alerts(STORE) if a['key'].startswith('agent-anomaly:')])

    def test_4_keys(self):
        row = self.row_now()
        st0 = G.state(STORE, row['id'])
        old_fp = G.cmd_key(STORE)['fp']
        conf0 = json.load(open(self.ag.d + '/etc/agent.json'))
        # acme's key made a day ago (a key less than an hour old is not changed again)
        meta = json.loads(STORE.get_meta(G.M_CMD))
        meta['at'] = time.time() - 86400
        STORE.set_meta(G.M_CMD, json.dumps(meta))
        self.assertEqual(conf0['cmd_fp'], old_fp)
        got = route('POST', '/api/agents/guard/rotate', 'fulladmin',
                    {'id': row['id'], 'what': 'both'})
        new_fp = G.cmd_key(STORE)['fp']
        self.assertNotEqual(new_fp, old_fp)
        self.assertEqual(got['rotated']['cmd_fp'], new_fp)
        conf = json.load(open(self.ag.d + '/etc/agent.json'))
        self.assertEqual(conf['cmd_fp'], new_fp)
        self.assertTrue(conf['cmd_prev'] and conf['cmd_prev_until'] > time.time())
        st = G.state(STORE, row['id'])
        self.assertEqual(st['cmd_fp'], new_fp)
        self.assertNotEqual(st['enc_pub'], st0['enc_pub'])
        # the old key kept in acme (a backup carries it), still taken by the agent meanwhile
        self.assertEqual(STORE.get_meta(AG.M_CMDBASE), old_fp)
        old_seed = AG._seed_of(STORE, old_fp)
        self.assertIsNotNone(old_seed)
        _jid, env = G.sign_job(STORE, st['agent_id'], 'hello', {}, old_seed)
        got, _p = G._passive_post(STORE, row, '/v1/job', env)
        self.assertTrue(got['ok'], got)
        # a deployment's key sealed to the new key for secrets
        t, _ctx = T.module(row, 1)
        t.deploy(T.Bundle('b'), T.opts(self.ag))
        self.assertEqual(T.read(os.path.join(self.ag.www, 'ssl', 'site.key')), T.Bundle('b').key_pem)
        # once an hour at most - and a key not proven by itself is refused
        with self.assertRaises(Exception):
            AG.enc_new(STORE, row, 'tester')
        hello = G.call(STORE, row, 'hello', {})
        self.assertEqual(hello['cmd_fp'], new_fp)
        rep = route('GET', '/api/agents/keys', 'readonly')['keys']
        me = [a for a in rep['agents'] if a['name'] == 'f138web'][0]
        self.assertTrue(me['cmd_current'])
        self.assertLess(me['enc_age'], 1)
        cur = [k for k in rep['cmd'] if k['current']][0]
        self.assertIn('f138web', cur['agents'])
        self.assertTrue([k for k in rep['cmd'] if k['fp'] == old_fp])
        # nothing secret in the report
        self.assertNotIn('seed', json.dumps(rep))
        # an old key no agent pins, past its overlap: retired
        rec = json.loads(STORE.get_meta(AG.M_CMDKEY % old_fp))
        rec['replaced_at'] = time.time() - AG.OVERLAP_S - 2 * 86400
        STORE.set_meta(AG.M_CMDKEY % old_fp, json.dumps(rec))
        st = G.state(STORE, row['id'])
        st['cmd_prev_until'] = time.time() - 1
        G.state_put(STORE, row['id'], st)
        for r in G.rows(STORE):              # every other agent of this run pins the new one
            s2 = G.state(STORE, r['id'])
            if s2.get('cert_fp') and not s2.get('cmd_fp'):
                s2['cmd_fp'] = new_fp
                G.state_put(STORE, r['id'], s2)
        AG.retire(STORE)
        self.assertIsNone(AG._seed_of(STORE, old_fp))
        self.assertTrue(json.loads(STORE.get_meta(AG.M_CMDKEY % old_fp))['retired_at'])

    def test_5_served(self):
        """B6: a TLS server on the agent's own 127.0.0.1 serving certificate a, while b is
        deployed - "still serves the old certificate"."""
        row = self.row_now()
        crt, key = T.CERTS['a']
        port = T.free_port()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        import socket
        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(('127.0.0.1', port))
        ls.listen(5)
        stop = threading.Event()

        def serve():
            ls.settimeout(0.5)
            while not stop.is_set():
                try:
                    c, _a = ls.accept()
                except OSError:
                    continue
                try:
                    s2 = ctx.wrap_socket(c, server_side=True)
                    s2.recv(1)
                    s2.close()
                except (OSError, ssl.SSLError):
                    c.close()
        th = threading.Thread(target=serve, daemon=True)
        th.start()
        fa = hashlib.sha256(ssl.PEM_cert_to_DER_cert(T.read(crt))).hexdigest().upper()
        fb = hashlib.sha256(ssl.PEM_cert_to_DER_cert(T.read(T.CERTS['b'][0]))).hexdigest().upper()
        dep = {'id': 9138, 'cert_id': 1, 'target': 'f138web', 'state': 'ok', 'deployed_fp': fb,
               'last_ok': time.time() - 60, 'cert_name': 'www.example.test', 'deployed_version': 2}
        saved = (AG._deploys, T.S.cert_get)
        from acmelib.certs import checks
        saved_c = (checks.served_places, checks.expected)
        AG._deploys = lambda store, r: [dep]
        T.S.cert_get = lambda store, ref: {'id': 1, 'names': '["www.example.test"]'}
        checks.served_places = lambda store, d: [('127.0.0.1', port, '')]
        checks.expected = lambda store, c: {'current': {fb: ('main', 2)}, 'old': {fa: 1}}
        try:
            T.www_policy(self.ag)
            G.call(STORE, row, 'hello', {})
            route('POST', '/api/agents/guard', 'fulladmin', {'id': row['id'], 'health': 'on'})
            self.assertEqual(AG.served_check(STORE, row), {})       # no allow probe local
            T.www_policy(self.ag, 'allow probe local')
            G.call(STORE, row, 'hello', {})
            got = AG.served_check(STORE, row)
            r = got['9138']
            self.assertEqual(r['state'], 'old', r)
            self.assertEqual(r['places'][0]['version'], 1)
            al = [a for a in G.alerts(STORE) if a['key'] == 'agent-served:9138']
            self.assertEqual(len(al), 1)
            self.assertIn('still serves the old certificate', al[0]['words'])
            self.assertEqual(G.info(STORE, row)['guard']['served']['old'], 1)
            view = AG.served_of_deploy(STORE, {'id': 9138, 'target': 'f138web',
                                               'deployed_fp': fb})
            self.assertEqual(view['state'], 'old')
            # switched off on the card: not asked
            route('POST', '/api/agents/guard', 'fulladmin', {'id': row['id'], 'health': 'off'})
            self.assertFalse(AG.served_on(STORE, row, G.state(STORE, row['id'])))
            self.assertFalse([a for a in G.alerts(STORE) if a['key'] == 'agent-served:9138'])
            route('POST', '/api/agents/guard', 'fulladmin', {'id': row['id'], 'health': 'on'})
            # the right one served now: ok
            checks.expected = lambda store, c: {'current': {fa: ('main', 2)}, 'old': {}}
            got = AG.served_check(STORE, row, force=True)
            self.assertEqual(got['9138']['state'], 'ok')
            self.assertFalse([a for a in G.alerts(STORE) if a['key'] == 'agent-served:9138'])
        finally:
            AG._deploys, T.S.cert_get = saved
            checks.served_places, checks.expected = saved_c
            stop.set()
            ls.close()
            STORE.db.run('DELETE FROM meta WHERE k = ?', (AG.M_SERVED % row['id'],))
            route('POST', '/api/agents/guard', 'fulladmin', {'id': row['id'], 'health': 'off'})
            T.www_policy(self.ag)

    def test_6_served_off_by_default(self):
        """B6 off (the default): probe local allowed, a deployment there - no probe job, no
        event, no alert, nothing on the deployment."""
        row = self.row_now()
        self.assertEqual(AG.opts(STORE, row['id'])['health'], 'off')
        T.www_policy(self.ag, 'allow probe local')
        G.call(STORE, row, 'hello', {})
        sent = []
        was = G.call

        def spy(store, r, op, *a, **k):
            sent.append(op)
            return was(store, r, op, *a, **k)
        G.call = spy
        saved = AG._deploys
        AG._deploys = lambda store, r: [{'id': 9139, 'cert_id': 1, 'target': 'f138web',
                                         'state': 'ok', 'deployed_fp': 'AB',
                                         'last_ok': time.time() - 60}]
        try:
            st = G.state(STORE, row['id'])
            self.assertFalse(AG.served_on(STORE, row, st))
            AG.tick(STORE, row, st)
            self.assertEqual(AG.served_check(STORE, row, force=True), {})
            settled(row)
        finally:
            G.call = was
            AG._deploys = saved
            T.www_policy(self.ag)
        self.assertNotIn('probe', sent)
        self.assertFalse(STORE.get_meta(AG.M_SERVED % row['id']))
        self.assertFalse([a for a in G.alerts(STORE) if a['key'].startswith('agent-served:')])
        self.assertIsNone(AG.served_of_deploy(STORE, {'id': 9139, 'target': 'f138web',
                                                      'deployed_fp': 'AB'}))
        self.assertFalse(G.info(STORE, row)['guard']['served']['on'])
        with self.assertRaises(ValueError):
            route('POST', '/api/agents/guard/served', 'certadmin', {'id': row['id']})


class OldData(unittest.TestCase):
    def test_state_without_new_keys(self):
        """An agent's state from before 1.0.138: no choices, no key of its own - as before."""
        row = T.target('f138old', mode='passive', host='127.0.0.1', port=T.free_port())
        st = {'agent_id': 'ag-00112233445566', 'cert_fp': 'a' * 64, 'last_seen': time.time(),
              'policy': {'hash': 'b' * 64, 'files': [], 'probe_local': True}}
        G.state_put(STORE, row['id'], st)
        info = G.info(STORE, row)
        g = info['guard']
        self.assertEqual(g['opts'], AG.DEFAULTS)
        self.assertEqual(g['audit']['state'], 'off')
        self.assertIsNone(g['anomalies'])
        self.assertEqual(g['served'], {'on': False, 'old': 0, 'items': []})     # off: the default
        self.assertIsNone(AG.seed_for(STORE, st) if not STORE.get_meta(AG.M_CMDBASE) else None)
        self.assertEqual(AG.opts(STORE, row['id'])['health'], 'off')
        self.assertFalse([a for a in AG.alerts(STORE, row, st)])
        G.target_gone(STORE, row)


WIN_SCRIPT = r"""
import importlib.util, json, os, subprocess, sys, tempfile
AGENT = sys.argv[1]
TMP = tempfile.mkdtemp(prefix='acme-f138w-')
FAKE = os.path.join(TMP, 'fake')
os.makedirs(FAKE)
for k in ('ACME_AGENT_ETC', 'ACME_AGENT_STATE', 'ACME_AGENT_ROOT_STATE', 'ACME_AGENT_RUN'):
    os.environ.pop(k, None)
os.environ.update(ACME_AGENT_FAKE_WINDOWS='1', ACME_AGENT_FAKE_ROOT=FAKE)
subprocess.run([sys.executable, '-I', '-B', AGENT, 'windows-install'], check=True, capture_output=True)
spec = importlib.util.spec_from_file_location('agw', AGENT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
out = {'windows': m.WINDOWS}
m.audit(op='deploy', job='j0', ok=True, said='before the line')
out['no_chain'] = not os.path.exists(m.chain_path())
m._write(m.POLICY, 'allow store\naudit chain\n', 0o644)
pol = m.policy_load()[0]
out['lines'] = m.policy_lines(pol)
out['problems'] = pol['problems']
m.audit(op='deploy', job='j1', ok=True, said='one')
m.audit(op='deploy', job='j2', ok=False, said='two')
out['verify'] = list(m.chain_verify())
out['events'] = sum(1 for e in m.W.lines('eventlog.jsonl') if e['text'].startswith('chain '))
out['head'] = m.chain_head()
print(json.dumps(out))
"""


class WindowsChain(unittest.TestCase):
    def test_chain_and_the_event_log(self):
        """The Windows agent (its fake on Linux): the same chain, each entry in the event log."""
        import subprocess
        got = subprocess.run([sys.executable, '-c', WIN_SCRIPT, T.AGENT], capture_output=True,
                             text=True, timeout=180)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        out = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertTrue(out['windows'])
        self.assertTrue(out['no_chain'])
        self.assertEqual(out['lines'], ['allow store', 'audit chain'])
        self.assertEqual(out['problems'], [])
        self.assertEqual(out['verify'][:2], [True, 2])
        self.assertEqual(out['events'], 2)
        self.assertEqual(out['head']['n'], 2)


class Pages(unittest.TestCase):
    def test_page(self):
        import shutil
        import subprocess
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        args = [node, os.path.join(HERE, 'f138_agentsec_page.js'), os.path.join(T.ROOT, 'web')]
        extra = os.environ.get('ACME_TEST_CS_EXTRA')
        args.append(extra if extra and os.path.exists(extra) else '')
        if os.environ.get('ACME_TEST_SHOTS'):
            args.append(os.environ['ACME_TEST_SHOTS'])
        got = subprocess.run(args, capture_output=True, text=True, timeout=900)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        bad = [k for k, v in (out.get('checks') or {}).items() if not v]
        self.assertTrue(out.get('ok'), json.dumps({'failed': bad, 'error': out.get('error'),
                                                   'errors': out.get('errors')})
                        + got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
