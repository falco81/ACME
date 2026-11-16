#!/usr/bin/env python3
"""Target agents (1.0.116), the hunt of how they work end to end as the pages, the command line
and the console use them - beside test/test_target_agent.py (its real agents, its helpers):

    python3 test/test_target_agent_ui.py

* a service preset (nginx, HAProxy, Tomcat...) on an agent target: its files worked out - the
  preview and the deployment raised a TypeError (the SSH target's staticmethod taken as a
  method);
* the new certificate's wizard with "Key made by the agent" (csr_from): its deployment's
  preview knows the key is made there (the key files "made there", a keystore refused) - and
  what the agent cannot do at all (a line of a shell) is a problem of the preview, not "allows
  all of it";
* What happens of a key made there shows no made-up fingerprint (0000…);
* a passive agent joined, a join code made and not used (Join again… closed): "Ask it now"
  says hello - it answered "not here" for an hour;
* an active agent's policy is asked once it is heard from (it says it only with a job);
* acme --target-agent NAME show / policy as the card: "1 folder" (not "1 folders"), the probes,
  connections, a newer agent, the policy blocking, the keys made there; `allow probe local`
  listed by policy;
* the agents' events for isemon / the SIEM of a target whose name has a space;
* the console offers the agent's menu on a target "Server with acme-agent".

Needs what test_target_agent.py needs (root, setpriv, openssl).
"""
import io
import os
import sys
import time
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_target_agent as T  # noqa: E402  (its folders, its engine, its agents)

E, A, G, S, AT, STORE = T.E, T.A, T.G, T.S, T.AT, T.STORE


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


class FakeH(object):
    def __init__(self, body):
        self._b = body
        self.store = STORE

    def body(self):
        return self._b

    def arg(self, k, default=None):
        return self._b.get(k, default)


def preview(body):
    from acmelib.certs import api_deploys
    return api_deploys._deploys_preview(FakeH(body), {'role': 'fulladmin', 'name': 'tester'})


@unittest.skipUnless(T.CAN, 'needs root, setpriv, openssl')
class Presets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = T.free_port()
        cls.row, cls.ag = T.join_passive(cls(), 'hunt1', cls.port)
        T.www_policy(cls.ag, 'allow probe local')

    @classmethod
    def tearDownClass(cls):
        cls.ag.stop()

    def test_1_a_preset_resolved_previewed_and_deployed(self):
        t, _ctx = T.module(self.row)
        for preset in ('nginx', 'apache', 'haproxy', 'postfix', 'tomcat', 'plex'):
            r = t.resolved(T.Bundle('a'), {'preset': preset}, partial=True)
            self.assertTrue(r['files'], preset)
        got = preview({'target': 'hunt1', 'options': {'preset': 'nginx'},
                       'names': ['www.example.test']})
        self.assertEqual(got['files'][0]['path'], '/etc/nginx/ssl/www.example.test.crt')
        self.assertEqual([i['kind'] for i in got['agent']['items']][:4],
                         ['file', 'file', 'test', 'reload'])
        # the preset's files in folders of the agent's: deployed as the SSH target would
        www = self.ag.www + '/ssl'
        t, _ctx = T.module(self.row, 31)
        said = t.deploy(T.Bundle('a'), {
            'preset': 'nginx', 'test_cmd': '/bin/true',
            'outputs': 'fullchain-pem %s/{name}.crt 0644 root:%s\nkey-pem %s/{name}.key 0640 '
                       'root:%s' % (www, T.USER, www, T.USER)})
        self.assertIn('2 files written', said)
        self.assertTrue(os.path.exists(www + '/www.example.test.crt'))

    def test_2_the_wizard_key_made_there(self):
        body = {'target': 'hunt1', 'csr_from': 'hunt1', 'names': ['www.example.test'],
                'options': {'preset': 'nginx'}}
        got = preview(body)
        self.assertTrue(got['agent']['agent_key'])
        self.assertIn('key', [i['kind'] for i in got['agent']['items']])
        # without it (acme makes the key): the key file a file as any
        got = preview(dict(body, csr_from=''))
        self.assertFalse(got['agent']['agent_key'])
        # a keystore the agent cannot make its key into: a problem of the preview
        got = preview(dict(body, options={'preset': 'tomcat', 'pfx_password': 'secret-pw'}))
        self.assertIn('cannot be written as jks', got['agent'].get('error') or '')
        self.assertTrue(any(p['level'] == 'bad' and 'jks' in p['words']
                            for p in got.get('problems') or []))

    def test_3_a_line_of_a_shell_is_a_problem(self):
        got = preview({'target': 'hunt1', 'names': ['www.example.test'],
                       'options': {'preset': 'kubernetes'}})
        self.assertIn('a line of a shell', got['agent'].get('error') or '')
        self.assertTrue(any(p['level'] == 'bad' and 'shell' in p['words']
                            for p in got.get('problems') or []))

    def test_3b_a_protected_place_said_without_a_line(self):
        # (the agent never writes under /usr/lib, whatever its policy): its words, no
        # "sudo <those words>" to copy - here and in What happens
        got = preview({'target': 'hunt1', 'names': ['www.example.test'],
                       'options': {'preset': 'custom', 'outputs':
                                   'fullchain-pem /usr/lib/x/a.pem 0644 root:root'}})
        it = got['agent']['items'][0]
        self.assertIs(it['ok'], False)
        self.assertEqual(it['allow'], '')
        self.assertIn('gives root', it.get('why') or '')
        from acmelib.certs import plansandbox
        pc = plansandbox.PlanContext.__new__(plansandbox.PlanContext)
        needs = pc.agent_plan_check(G.info(STORE, self.row)['policy'], {
            'files': [{'path': '/usr/lib/x/a.pem', 'mode': 0o644, 'owner': 'root:root'}]})
        self.assertTrue(needs and not needs[0].get('allow'))

    def test_4_ask_it_now_with_a_code_waiting(self):
        G.code_new(STORE, self.row, 'tester')           # Join again… made, closed unused
        st = G.state(STORE, self.row['id'])
        st['policy'] = None
        st['last_seen'] = 0
        G.state_put(STORE, self.row['id'], st)
        got = G.look(STORE, self.row, 'tester')
        self.assertFalse(got.get('said'), got.get('said'))
        self.assertEqual(got['state'], 'answers')
        self.assertTrue(got['policy'])
        self.assertTrue(got['code_until'])              # the code still waits its hour
        self.assertEqual(got['agent_id'], st['agent_id'])

    def test_5_the_command_line_as_the_card(self):
        st = G.state(STORE, self.row['id'])
        st['version'] = '1.0.1'
        st['blocked'] = {'at': time.time(), 'what': 'restart nginx.service',
                         'allow': ['acme-agent allow unit nginx.service restart']}
        G.state_put(STORE, self.row['id'], st)
        try:
            show = self.cli('show')
            pol = self.cli('policy')
        finally:
            G.hello(STORE, self.row)
            st = G.state(STORE, self.row['id'])
            st.pop('blocked', None)
            G.state_put(STORE, self.row['id'], st)
        self.assertIn('1 folder,', show)
        self.assertNotIn('1 folders', show)
        self.assertIn('1 test from there', show)
        self.assertIn('address            127.0.0.1:%d' % self.port, show)
        self.assertIn('newer agent', show)
        self.assertIn('sudo acme-agent allow unit nginx.service restart', show)
        self.assertIn('allow probe local', pol)

    def cli(self, what):
        from acmelib.certs import cli as C
        a = C.Cli.__new__(C.Cli)
        a.store = STORE
        a.json = False
        a.WHO = 'tester'
        buf = io.StringIO()
        with redirect_stdout(buf):
            C.Cli.target_agent(a, ['hunt1', what])
        return buf.getvalue()


class WhatHappensKey(unittest.TestCase):
    def test_no_made_up_fingerprint(self):
        from acmelib.certs import plansandbox
        with open(plansandbox.__file__, encoding='utf-8') as fh:
            src = fh.read()
        self.assertNotIn("'key_fp': '0' * 64", src)
        with open(AT.__file__, encoding='utf-8') as fh:
            src = fh.read()
        self.assertIn("' (its key %s…)' % fp[:16] if fp else ''", src)


@unittest.skipUnless(T.CAN, 'needs root, setpriv, openssl')
class ActivePolicyAsked(unittest.TestCase):
    def setUp(self):
        E.CONFIG['certs_agents_active'] = 1

    def tearDown(self):
        E.CONFIG['certs_agents_active'] = 0
        E.CONFIG['certs_agents_names'] = ''

    def test_asked_once_heard_from(self):
        node = T.Wire(STORE)
        E.CONFIG['certs_agents_names'] = '127.0.0.1:%d' % node.port
        row = T.target('hunt2', mode='active', host='hunt2.example.test')
        code = G.code_new(STORE, row, 'tester')
        ag = T.Agent('hunt2')
        try:
            T.www_policy(ag)
            ag.start_root()
            ag.cli('join', code['code'], '--no-wait')
            ag.start_net()
            for _ in range(100):
                if G.info(STORE, row).get('pending'):
                    break
                time.sleep(0.1)
            G.confirm(STORE, row, G.info(STORE, row)['pending']['fp'], 'tester')
            self.assertTrue(ag.wait('joined', 20), ag.status())
            for _ in range(50):
                if not G.info(STORE, row).get('pending'):
                    break
                time.sleep(0.2)
            self.assertIsNone(G.info(STORE, row)['policy'])
            G.tick(STORE)                               # the leader's round
            for _ in range(150):
                if G.info(STORE, row).get('policy'):
                    break
                time.sleep(0.2)
            info = G.info(STORE, row)
            self.assertTrue(info['policy'], info)
            self.assertEqual(info['policy_summary']['units'], 1)
        finally:
            ag.stop()
            node.stop()


class AgentsPortSetting(unittest.TestCase):
    def test_never_a_port_served_already(self):
        # acme's API there: nginx (every node) or the daemon could not listen - the pages gone
        api = int(E.CONFIG.get('api_port') or 9861)
        for bad in (api, 8443, 18150, 9861):
            with self.assertRaises(E.BadSetting, msg=bad):
                E.check_setting('certs_agents_port', bad)
        self.assertEqual(E.check_setting('certs_agents_port', 8444), 8444)
        E.CONFIG['certs_agents_active'], E.CONFIG['certs_agents_port'] = 1, 8555
        try:
            with self.assertRaises(E.BadSetting):
                E.check_setting('certlogin_port', 8555)
            with self.assertRaises(E.BadSetting):
                E.check_setting('api_port', 8555)
        finally:
            E.CONFIG['certs_agents_active'], E.CONFIG['certs_agents_port'] = 0, 8444


class Events(unittest.TestCase):
    def test_a_name_with_a_space(self):
        from acmelib.certs import monitor as MO
        for words, action in (
                ('the agent of target web two joined acme (ag-1) - vm', 'agent_joined'),
                ('the agent of target web two is heard from again', 'agent_back'),
                ('the agent of target web two was forgotten by x - it is no longer let in',
                 'agent_forgotten'),
                ('the policy of the agent of target web two blocks a deployment: /x - allow it '
                 'on the server (y)', 'agent_policy_blocks')):
            f = MO.event_fields('certificates', words, 'info')
            self.assertEqual((f.get('action'), f.get('target')), (action, 'web two'), words)


class Console(unittest.TestCase):
    def test_the_agents_menu(self):
        from acmelib.certs import console as CO

        class Con(object):
            def __init__(self):
                self.asked, self.acts = [], []

            def choose(self, title, opts, *a, **k):
                self.asked.append((title, [o[0] for o in opts]))
                return 'agent' if len(self.asked) == 1 else 'policy'

            def act(self, *args, **kw):
                self.acts.append(args)

            def _rows(self, *a):
                return []

            def out(self, *a):
                return {}
        con = Con()
        orig = CO._plugin
        CO._plugin = lambda *a, **k: {}
        try:
            CO.fam_do(con, 'target', {'name': 'web1', 'kind': 'agent', 'enabled': 1})
        finally:
            CO._plugin = orig
        self.assertIn('agent', con.asked[0][1])
        self.assertEqual(con.acts, [('--target-agent', 'web1', 'policy')])


if __name__ == '__main__':
    unittest.main(verbosity=2)
