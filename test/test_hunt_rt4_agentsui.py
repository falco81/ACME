#!/usr/bin/env python3
"""Hunt R t4 (1.0.126) - the admin pages of target agents (agents.js, policybuilder.js):

    python3 test/test_hunt_rt4_agentsui.py

* "Save as this agent's design" in the policy designer: the page sent the builder's state as
  `state`, a word of every body the API reads as text - every save from the page (and from the
  portal's team workspace) was refused with "state is a piece of text here". It is sent as
  `design_state` now: the body read as the daemon reads it (ApiHandler.body), then saved;
* the pages in a browser (test/hunt_rt4_agentsui_page.js, node with playwright; skipped
  without): the Windows designer's nav with "From discovery" (Folders gone, the services twice),
  a design's text whose test has a word with "=", the save, the card's policy of a Windows
  agent (store, IIS, roles, AD CS, discovery - it said "Nothing is allowed yet"), the blocked
  deployment's lines on Windows without sudo.

Needs what test_target_agent.py needs for its targets (its folders, its engine).
"""
import io
import json
import os
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_target_agent as T  # noqa: E402  (its folders, its engine, its targets)

E, STORE = T.E, T.STORE
CS_EXTRA = os.environ.get('ACME_TEST_CS_EXTRA', '')


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


class Wire(object):
    """A request as the daemon's handler reads it: its body parsed by ApiHandler.body."""
    def __init__(self, role, body):
        raw = json.dumps(body).encode('utf-8')
        self.headers = {'Content-Length': str(len(raw))}
        self.rfile = io.BytesIO(raw)
        self.role, self.store = role, STORE

    def body(self):
        return E.ApiHandler.body(self)

    def me(self, level='readonly'):
        return {'role': self.role, 'name': 'rt4-' + self.role}

    def arg(self, k, default=None):
        return None if k != 'id' else default


class DesignSave(unittest.TestCase):
    def test_saved_from_the_page(self):
        row = T.target('rt4design', mode='passive', host='127.0.0.1', port=T.free_port())
        text = T.AG.POLICY_HEAD + 'allow file /etc/nginx/ssl owner=root:root mode=0644\n'
        state = {'files': [{'dir': '/etc/nginx/ssl', 'owner': 'root', 'group': 'root',
                            'mode': 420}], 'tests': [['nginx', '-t']]}
        save = E.ROUTES[('POST', '/api/agents/design')]
        # what the page sent before: refused before the route is reached
        with self.assertRaises(E.ApiError) as e:
            save(Wire('fulladmin', {'id': row['id'], 'text': text, 'state': state}))
        self.assertIn('state is a piece of text here', str(e.exception))
        # what it sends now
        got = save(Wire('fulladmin', {'id': row['id'], 'text': text, 'design_state': state,
                                      'title': 'nginx', 'note': ''}))
        d = got['design']
        self.assertEqual((d['n'], d['title']), (1, 'nginx'))
        self.assertEqual(d['state']['files'][0]['dir'], '/etc/nginx/ssl')
        self.assertEqual(d['state']['tests'], [['nginx', '-t']])
        # a bad state still refused
        with self.assertRaises((E.ApiError, ValueError)):
            save(Wire('fulladmin', {'id': row['id'], 'text': text,
                                    'design_state': {'files': 'x'}}))
        # and the page sends it so
        with open(os.path.join(os.path.dirname(HERE), 'web', 'assets', 'policybuilder.js'),
                  encoding='utf-8') as fh:
            src = fh.read()
        self.assertIn('design_state: S,', src)
        self.assertNotIn('text: fileText(R), state: S,', src)


class Pages(unittest.TestCase):
    def test_pages(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        root = os.path.dirname(HERE)
        args = [node, os.path.join(HERE, 'hunt_rt4_agentsui_page.js'), os.path.join(root, 'web')]
        if CS_EXTRA:
            args.append(CS_EXTRA)
        got = subprocess.run(args, capture_output=True, text=True, timeout=600)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        bad = [k for k, v in (out.get('checks') or {}).items() if not v]
        if not CS_EXTRA:
            # the Czech words of this hunt not merged yet: those checks are of the English
            bad = [k for k in bad if not k.startswith('cs_') or k in ('cs_win_nav',
                                                                      'cs_save_sent')]
        self.assertFalse(bad or out.get('error') or out.get('errors'),
                         json.dumps({'failed': bad, 'error': out.get('error'),
                                     'errors': out.get('errors')}) + got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
