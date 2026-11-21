#!/usr/bin/env python3
"""Hunt R f1 (area: agent) - the target agent changes of 1.0.138 (agent_guard, fleet rings,
the audit chain file), old/new combinations:

* an acme-agent from BEFORE 1.0.138 (deploy/agent/acme_agent.py at 13c9af7, run as it is)
  joined to this acme: hello and a deployment as before with every new feature off; the audit
  chain switched on in acme says "too old" (no false alarm); "Rotate now" of the command key is
  refused in plain words WITHOUT making acme a new command key (it made one, which an acme
  downgraded later signs with - and a schedule made one every N days for nothing); after a
  change of acme's key made for others, the old agent is still commanded (the key it pins);
* the answer of `cmdkey` lost (a failover, a timeout) after the agent took the new key: acme
  takes the key the agent says it pins in its next hello (it signed with the old one and the
  agent refused every job once the overlap was over - never commanded again);
* "too old to change keys" said once was never tried again after the agent was updated;
* an agent joined anew on the same target (reinstalled - a new, empty chain): no false
  "entries were taken away" alarm;
* the policy's `audit chain` kept in acme's copy of the agent's policy;
* a rollout in rings whose canary group has no agent that can be updated: refused (it updated
  every agent at once, without a canary);
* the chain file whose last line was cut (a crash): the next entry is a line of its own.

    python3 test/test_hunt_rf1_agent.py
"""
import json
import os
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_target_agent as T  # noqa: E402

E, G, S, STORE = T.E, T.G, T.S, T.STORE
from acmelib.certs import agent_guard as AG  # noqa: E402
from acmelib.certs import fleet as FL  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402

OLD_REV = '13c9af7'


def need_account():
    import pwd
    if not T.CAN:
        return
    try:
        pwd.getpwnam(T.USER)
    except KeyError:
        subprocess.run(['useradd', '--system', '--no-create-home', '--shell',
                        '/usr/sbin/nologin', T.USER], capture_output=True)


def old_agent_path():
    """acme-agent as it was before 1.0.138 (git), in the test's folder (readable by the
    agent's account) - or None."""
    # a folder of its own: the agent takes the folder it runs from as its own (never written)
    d = os.path.join(T.TMP, 'oldagent')
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o755)
    p = os.path.join(d, 'acme_agent_old.py')
    if os.path.exists(p):
        return p
    got = subprocess.run(['git', '-C', T.ROOT, 'show', '%s:deploy/agent/acme_agent.py' % OLD_REV],
                         capture_output=True)
    if got.returncode != 0 or not got.stdout:
        return None
    with open(p, 'wb') as fh:
        fh.write(got.stdout)
    os.chmod(p, 0o755)
    return p


def join_with(test, name, script):
    """join_passive, the agent run from `script` (both its sides keep running from it)."""
    keep = T.AGENT
    T.AGENT = script
    try:
        return T.join_passive(test, name, T.free_port())
    finally:
        T.AGENT = keep


def setUpModule():
    T.setUpModule()


def tearDownModule():
    import shutil
    for a in list(T.Agent.ALL):
        a.stop()
    for w in list(T.Wire.ALL):
        w.stop()
    shutil.rmtree(T.TMP, ignore_errors=True)


def cmd_key_a_day_old():
    meta = json.loads(STORE.get_meta(G.M_CMD))
    meta['at'] = time.time() - 86400
    STORE.set_meta(G.M_CMD, json.dumps(meta))


def settled(row, most=20):
    end = time.time() + most
    while time.time() < end and any(k[1] == int(row['id']) for k in AG.BUSY):
        time.sleep(0.1)


# ---------------------------------------------------------------------------------------------
@unittest.skipUnless(T.CAN, 'needs root, setpriv and openssl')
class OldAgentNewAcme(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_account()
        cls.script = old_agent_path()
        if not cls.script:
            raise unittest.SkipTest('the agent of %s is not in git here' % OLD_REV)
        cls.row, cls.ag = join_with(cls(), 'rf1old', cls.script)
        T.www_policy(cls.ag)

    @classmethod
    def tearDownClass(cls):
        cls.ag.stop()

    def row_now(self):
        return S.plugin_row(STORE, 'target', 'rf1old')

    def test_1_as_before_and_rotation(self):
        row = self.row_now()
        got = G.call(STORE, row, 'hello', {})
        self.assertTrue(got['ok'], got)
        self.assertNotIn('features', got)
        st = G.state(STORE, row['id'])
        self.assertEqual(st.get('features'), [])
        t, _ctx = T.module(row, 1)
        t.deploy(T.Bundle('a'), T.opts(self.ag))
        self.assertEqual(T.read(os.path.join(self.ag.www, 'ssl', 'site.key')),
                         T.Bundle('a').key_pem)
        # the audit chain switched on in acme: "too old", no alarm, no alert
        AG.set_opts(STORE, row, {'audit': True}, 'tester')
        G.call(STORE, row, 'hello', {})
        v = AG.view(STORE, row)['audit']
        self.assertEqual(v['state'], 'unsupported')
        self.assertFalse(v['problems'])
        self.assertFalse([a for a in G.alerts(STORE) if a['key'].startswith('agent-audit:')])
        AG.set_opts(STORE, row, {'audit': False}, 'tester')
        # Rotate now (the command key): refused in plain words, acme's key left as it is
        cmd_key_a_day_old()
        fp0 = G.cmd_key(STORE)['fp']
        with self.assertRaises(PluginError) as e:
            AG.rotate_now(STORE, row, 'command', 'tester')
        self.assertIn('too old', str(e.exception))
        self.assertEqual(G.cmd_key(STORE)['fp'], fp0, 'a new command key was made for an agent '
                                                      'that cannot take it')
        # the schedule: no new acme key for it either
        AG.set_opts(STORE, row, {'rotate': True, 'rotate_days': 7}, 'tester')
        meta = json.loads(STORE.get_meta(G.M_CMD))
        meta['at'] = time.time() - 30 * 86400
        STORE.set_meta(G.M_CMD, json.dumps(meta))
        AG._rotate_due(STORE, row, G.state(STORE, row['id']))
        self.assertEqual(G.cmd_key(STORE)['fp'], fp0)
        AG.set_opts(STORE, row, {'rotate': False}, 'tester')
        # acme's key changed for the others: the old agent is still commanded (its pinned key)
        AG.cmd_new(STORE, 'tester')
        self.assertNotEqual(G.cmd_key(STORE)['fp'], fp0)
        got = G.call(STORE, row, 'hello', {})
        self.assertTrue(got['ok'], got)
        t.deploy(T.Bundle('b'), T.opts(self.ag))
        self.assertEqual(T.read(os.path.join(self.ag.www, 'ssl', 'site.key')),
                         T.Bundle('b').key_pem)
        AG.retire(STORE)
        self.assertIsNotNone(AG._seed_of(STORE, fp0))       # kept: the old agent pins it


# ---------------------------------------------------------------------------------------------
@unittest.skipUnless(T.CAN, 'needs root, setpriv and openssl')
class NewAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_account()
        cls.row, cls.ag = T.join_passive(cls(), 'rf1new', T.free_port())
        T.www_policy(cls.ag)

    @classmethod
    def tearDownClass(cls):
        cls.ag.stop()

    def row_now(self):
        return S.plugin_row(STORE, 'target', 'rf1new')

    def test_1_cmdkey_answer_lost(self):
        row = self.row_now()
        G.call(STORE, row, 'hello', {})
        cmd_key_a_day_old()
        before = G.state(STORE, row['id'])
        old_fp = AG.pinned_fp(STORE, before)
        AG.rotate_now(STORE, row, 'command', 'tester')
        new_fp = G.cmd_key(STORE)['fp']
        self.assertNotEqual(new_fp, old_fp)
        # the answer lost: acme's record as before the move (the agent took the new key)
        st = G.state(STORE, row['id'])
        for k in ('cmd_prev_fp', 'cmd_prev_until', 'cmd_moved_at'):
            st.pop(k, None)
        st['cmd_fp'] = old_fp
        G.state_put(STORE, row['id'], st)
        got = G.call(STORE, row, 'hello', {})        # signed with the old key: in the overlap
        self.assertTrue(got['ok'], got)
        self.assertEqual(G.state(STORE, row['id'])['cmd_fp'], new_fp)
        # the overlap over on the agent: acme's jobs still taken
        path = self.ag.d + '/etc/agent.json'
        conf = json.load(open(path))
        conf['cmd_prev_until'] = time.time() - 1
        with open(path, 'w') as fh:
            json.dump(conf, fh)
        got = G.call(STORE, row, 'hello', {})
        self.assertTrue(got['ok'], got)

    def test_2_too_old_said_once_retried_after_update(self):
        row = self.row_now()
        st = G.state(STORE, row['id'])
        st['key_said'] = 'the agent is too old to change keys (update it to 1.0.138 or later)'
        st['features'] = []                 # as an agent before 1.0.138 said
        G.state_put(STORE, row['id'], st)
        G.call(STORE, row, 'hello', {})     # now it can (updated)
        st = G.state(STORE, row['id'])
        self.assertIn('cmdkey', st['features'])
        self.assertFalse(st.get('key_said'))

    def test_3_policy_audit_chain_kept(self):
        row = self.row_now()
        T.www_policy(self.ag, 'audit chain')
        try:
            G.call(STORE, row, 'hello', {})
            self.assertTrue(G.state(STORE, row['id'])['policy'].get('audit_chain'))
            AG.set_opts(STORE, row, {'audit': True}, 'tester')
            self.assertTrue(AG.view(STORE, row)['audit']['agent_on'])
        finally:
            AG.set_opts(STORE, row, {'audit': False}, 'tester')
            T.www_policy(self.ag)

    def test_4_joined_anew_no_false_alarm(self):
        """The agent reinstalled (its state gone, a new chain) and joined again on the same
        target: acme takes the new chain as it is - no "entries were taken away"."""
        row = self.row_now()
        T.www_policy(self.ag, 'audit chain')
        AG.set_opts(STORE, row, {'audit': True}, 'tester')
        try:
            for _ in range(4):
                G.call(STORE, row, 'hello', {})
            settled(row)
            st = AG.read_chain(STORE, row)
            self.assertGreaterEqual(st['verified_n'], 4)
            self.assertFalse(st.get('problems'))
            # reinstalled: a new agent (new folders, no chain), joined on the same target
            self.ag.stop()
            port = int(G.target_conf(row).get('port'))
            code = G.code_new(STORE, row, 'tester')['code']
            ag = T.Agent('rf1new-again')
            ag.start_root()
            ag.cli('join', code, '--no-wait', '--listen', '127.0.0.1')
            ag.start_net()
            for _ in range(50):
                got = G.look(STORE, row, 'tester')
                if got.get('pending'):
                    break
                time.sleep(0.2)
            G.confirm(STORE, row, ag.cli('fingerprint').stdout.strip(), 'tester')
            G.look(STORE, row, 'tester')
            self.assertTrue(ag.wait('joined'), ag.status())
            type(self).ag = ag
            T.www_policy(ag, 'audit chain')
            self.assertEqual(G.target_conf(row).get('port'), port)
            for _ in range(2):
                G.call(STORE, row, 'hello', {})
            settled(row)
            st = AG.read_chain(STORE, self.row_now())
            self.assertFalse(st.get('problems'), st.get('problems'))
            self.assertNotEqual(AG.view(STORE, row)['audit']['state'], 'mismatch')
        finally:
            AG.set_opts(STORE, row, {'audit': False}, 'tester')


# ---------------------------------------------------------------------------------------------
class Rings(unittest.TestCase):
    def setUp(self):
        self.rows = [T.target('rf1ring%d' % i) for i in range(3)]
        self.keep = (G.update_candidates, G.update_agent, G.package)
        self.updated = []
        ids = [r['id'] for r in self.rows]

        def cand(store):
            # ring0 (the canary group's only member) cannot be updated now
            return [{'id': r['id'], 'name': r['name'], 'mode': 'passive', 'platform': 'linux',
                     'version': '1.0.130', 'offered': '1.0.138', 'ok': r['id'] != ids[0],
                     'why': '' if r['id'] != ids[0] else 'acme cannot reach it'}
                    for r in self.rows]

        def upd(store, row, by):
            self.updated.append(row['name'])
            return {'ok': True}
        G.update_candidates, G.update_agent = cand, upd
        G.package = lambda build=True: {'version': '1.0.138', 'signed': True}
        STORE.db.run("DELETE FROM meta WHERE k = 'fleet:rollout'")
        self.g = FL.group_save(STORE, {'name': 'rf1 canary', 'canary': True,
                                       'members': [ids[0]]}, 'tester')

    def tearDown(self):
        G.update_candidates, G.update_agent, G.package = self.keep
        FL.group_delete(STORE, self.g['id'], 'tester')
        STORE.db.run("DELETE FROM meta WHERE k = 'fleet:rollout'")
        for r in self.rows:
            STORE.db.run('DELETE FROM cert_targets WHERE id = ?', (r['id'],))

    def test_canary_group_none_updatable(self):
        with self.assertRaises(ValueError) as e:
            FL.rollout_start(STORE, {'canary': self.g['id'], 'wait': 60}, 'tester')
        self.assertIn('canary', str(e.exception))
        time.sleep(0.5)
        self.assertEqual(self.updated, [])
        self.assertIsNone(FL.rollout_view(STORE))
        # without a group: 5 % (at least one) first, as before
        FL.rollout_start(STORE, {'wait': 60}, 'tester')
        end = time.time() + 20
        while time.time() < end and (FL.rollout_view(STORE) or {}).get('phase') != 'waiting':
            time.sleep(0.1)
        self.assertEqual(len(self.updated), 1)


# ---------------------------------------------------------------------------------------------
class K8sFeatures(unittest.TestCase):
    def test_no_audit_chain_claimed(self):
        """The Kubernetes agent keeps no audit chain (its policy cannot say `audit chain`):
        it does not tell acme it can (acme said "acme-agent audit on" of a pod)."""
        import importlib.util
        d = os.path.join(T.TMP, 'rf1k8s')
        os.makedirs(d, exist_ok=True)
        keys = ('ACME_K8S_STATE', 'ACME_K8S_POLICY', 'ACME_AGENT_ETC', 'ACME_AGENT_STATE',
                'ACME_AGENT_ROOT_STATE', 'ACME_AGENT_RUN', 'ACME_K8S_RUN')
        keep = {k: os.environ.get(k) for k in keys}
        os.environ.update(ACME_K8S_STATE=d, ACME_K8S_RUN=d + '/run',
                          ACME_K8S_POLICY=d + '/policy')
        try:
            path = os.path.join(T.ROOT, 'deploy', 'agent', 'k8s', 'acme_k8s_agent.py')
            spec = importlib.util.spec_from_file_location('acme_k8s_rf1', path)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        finally:
            for k, v in keep.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertIn('audit-chain', m.A.FEATURES)
        self.assertTrue(m.parse('audit chain\n')['problems'])
        real = m.A.Root.op_hello
        m.A.Root.op_hello = lambda self, a, j, msg: {'ok': True, 'features': list(m.A.FEATURES)}
        try:
            out = m.K8sRoot().op_hello({}, {}, {})
        finally:
            m.A.Root.op_hello = real
        self.assertNotIn('audit-chain', out['features'])
        self.assertIn('cmdkey', out['features'])


# ---------------------------------------------------------------------------------------------
class ChainCut(unittest.TestCase):
    def test_last_line_cut(self):
        m = T.AG
        d = os.path.join(T.TMP, 'rf1chain')
        os.makedirs(d, exist_ok=True)
        old = m.ROOT_STATE
        m.ROOT_STATE = d
        try:
            for i in range(2):
                m.chain_add({'op': 'deploy', 'job': 'j%d' % i}, force=True)
            with open(m.chain_path(), 'ab') as fh:
                fh.write(b'{"n":3,"op":"dep')                  # cut by a crash
            e = m.chain_add({'op': 'hello', 'job': 'j9'}, force=True)
            lines = list(m.chain_lines())
            self.assertEqual(len(lines), 4, lines)
            self.assertEqual(json.loads(lines[-1])['h'], e['h'])  # its own line, readable
            self.assertEqual(m.chain_head()['h'] if m.chain_on() else e['h'], e['h'])
        finally:
            m.ROOT_STATE = old


if __name__ == '__main__':
    unittest.main(verbosity=2)
