#!/usr/bin/env python3
"""Bug hunt R run t1: the portal's team workspace (acmelib/certs/portal_teams.py,
web/assets/portal-teams.js).

    python3 test/test_hunt_rt1_portal.py

- A team whose limits no longer allow its agents (agents false, or target_kinds without its
  kind): a member with target.manage still made a one-time join code for the team's agent
  target, and confirmed an agent asking to join - the team's enrollment code was refused then.
  Both are refused now, in words naming the team (refusing an agent stays possible).
- In Czech, a device's module ("Server with acme-agent") stayed in English on its card and in
  its dialog - now in the page's language, as the module picker says it.
- A device's settings showed a choice as its raw value ("passive") - now in the module's words.
- The portal's limits editor (Sub-teams & limits → Limits) saved the approval rule without what
  it does not show: `self` and the `outside` envelope set by an administrator were dropped by
  any save there, and every request of an "outside" team waited for approval. Kept now.

The page parts: a real daemon in a folder of its own (test/test_certs_core.py's way), the pages
from a copy of web/ through php -S, in Chromium (test/hunt_rt1_portal_page.js) when node, php
and Playwright are here.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_teams_portal as W        # noqa: E402  (the workspace in this process, its helpers)
import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


class AgentLimits(unittest.TestCase):
    def test_join_code_and_confirm_follow_the_limits(self):
        fx = W.fixture('Device manager')
        ag = fx['ag']
        # allowed: as before
        self.assertEqual(W.status('rp', 'POST', 'agent_code', {'id': ag}), 200)
        # the administrators take the agents away: no join code, no confirmation
        W.T.save_team(W.STORE, {'old_name': 'Web', 'name': 'Web', 'policy': {'agents': False}},
                      'x')
        st, said = W.refusal('rp', 'POST', 'agent_code', {'id': ag})
        self.assertEqual(st, 403, said)
        self.assertIn('Web', said)
        st, said = W.refusal('rp', 'POST', 'agent_confirm', {'id': ag, 'fp': 'x' * 64})
        self.assertEqual(st, 403, said)
        # ...nor where its modules leave the agents out
        W.T.save_team(W.STORE, {'old_name': 'Web', 'name': 'Web',
                                'policy': {'target_kinds': ['ssh']}}, 'x')
        self.assertEqual(W.status('rp', 'POST', 'agent_code', {'id': ag}), 403)
        # refusing one that asks stays possible (409: nothing waits here)
        self.assertEqual(W.status('rp', 'POST', 'agent_refuse', {'id': ag}), 409)
        # allowed again: as before
        W.T.save_team(W.STORE, {'old_name': 'Web', 'name': 'Web',
                                'policy': {'target_kinds': ['ssh', 'agent']}}, 'x')
        self.assertEqual(W.status('rp', 'POST', 'agent_code', {'id': ag}), 200)


class Pages(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 50,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self',
            'mail_mode': 'off', 'certs_agents_active': 1}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        cls.must('POST', '/api/users', {'action': 'add', 'name': 'rtowner', 'role': 'readonly',
                                        'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/teams/save', {
            'name': 'Top', 'kind': 'unit',
            'members': [{'who': 'local:rtowner', 'roles': ['Team owner']}]})
        cls.approval = {'mode': 'outside', 'approvers': 'team', 'count': 1, 'self': True,
                        'outside': {'suffixes': ['ok.example.test'], 'max_days': 30}}
        cls.must('POST', '/api/teams/save', {'name': 'Sub', 'parent': 'Top',
                                             'policy': {'approval': cls.approval,
                                                        'max_days': 60}})
        cls.must('POST', '/api/targets/save', {
            'name': 'srv-agent', 'kind': 'agent', 'owner': 'Top',
            'config': {'mode': 'passive', 'host': 'srv.example.test'}})

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def sub_policy(self):
        got = self.must('GET', '/api/teams')
        rows = got.get('teams') or got.get('rows') or []
        return [t for t in rows if t['name'] == 'Sub'][0].get('policy') or {}

    def test_the_page(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        probe = subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                               cwd=ROOT)
        if probe.returncode != 0:
            self.skipTest('no playwright for node here')
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        seen = {}
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            for lang in ('cs', 'en'):
                got = subprocess.run([node, os.path.join(HERE, 'hunt_rt1_portal_page.js'),
                                      'http://127.0.0.1:%d' % port, 'rtowner', self.pw, lang,
                                      '390'], capture_output=True, text=True, timeout=240,
                                     cwd=ROOT)
                self.assertEqual(got.returncode, 0, got.stderr[-2000:])
                seen[lang] = json.loads(got.stdout.strip().splitlines()[-1])
                # the limits saved unchanged: the approval's envelope and `self` kept
                pol = self.sub_policy()
                self.assertTrue(seen[lang].get('saved'), seen[lang])
                self.assertEqual(pol.get('approval', {}).get('outside'),
                                 self.approval['outside'], (lang, pol))
                self.assertIs(pol['approval'].get('self'), True, (lang, pol))
                self.assertEqual(pol['approval'].get('mode'), 'outside')
                self.assertEqual(pol.get('max_days'), 60)
        finally:
            php.terminate()
            php.wait(10)
        for lang, one in seen.items():
            self.assertNotIn('error', one, one.get('error'))
            self.assertEqual(one['errors'], [], lang)
        cs, en = seen['cs'], seen['en']
        self.assertEqual(en['card'], 'Server with acme-agent')
        self.assertEqual(en['dialog']['kind'], 'Server with acme-agent')
        # in Czech: the module in Czech, on its card and in its dialog
        self.assertTrue(cs['card'] and cs['card'] != 'Server with acme-agent', cs)
        self.assertEqual(cs['card'], cs['dialog']['kind'], cs)
        # the choice in the module's words, not its value
        rows = ' | '.join(en['dialog']['rows'])
        self.assertIn('acme connects to the agent', rows)
        self.assertNotIn('passive', rows)
        self.assertNotIn('passive', ' | '.join(cs['dialog']['rows']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
