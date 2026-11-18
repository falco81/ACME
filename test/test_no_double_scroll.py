#!/usr/bin/env python3
"""Nowhere two vertical scrollbars, one inside the other (1.0.128).

    python3 test/test_no_double_scroll.py
    python3 test/test_no_double_scroll.py --serve     # the daemon and the pages kept running
    NDS_WIDTHS=1400,390 python3 test/test_no_double_scroll.py

Settings -> Owners and teams -> Roles showed the roles' matrix in a box with a scrollbar of its
own inside the pane, which scrolls too: two scrollbars side by side. The rule now: content
flows with the page, so the page has one scrollbar; a dialog has at most one scrolling area.

A real daemon (test/test_certs_core.py's way) with long lists - many roles, teams, members,
certificates, targets, events - and php -S; test/no_double_scroll_page.js opens every top tab,
every Settings pane (Owners and teams with each of its views and the team's tabs), the main
add/edit dialogs and the portal's views at 2000x1100, 1400, 768 and 390 px and finds every box
with a vertical scrollbar inside another scrolling area. Only ALLOW may scroll on its own:
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
sys.path.insert(0, ROOT)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)

WIDTHS = os.environ.get('NDS_WIDTHS', '2000x1100,1400,768,390')

# What may scroll on its own inside a scrolling page, and why.
ALLOW = [
    # Settings' side rail: a sticky pane beside the pane's body, two panes side by side
    # (thin, its own colours; shut, no scrollbar at all)
    '#ctl-nav',
    # the organisation's tree of teams: the same - a sticky pane beside the team's page,
    # its rows drawn as they come into view (ROW_H in teams.js)
    '.tmx-tree-s',
    # popovers and dropdowns: above the page, gone on a click elsewhere
    '.ctl-found', '.t-suggest', '.cols-menu', '.acct-panel', '.tm-cpick-panel', '.pw-switch-p',
    '.dpk-pop', '.hl-panel',
    # fixed-height viewers of a log or of code: a window onto text, not content of the page
    '.joblines', 'pre.lines', '.ct-log', '.fw-pre', '.tx-pre', '.mon-pre', '.clk-pre',
    '.cv-pem-t', '.cv-raw', '.pb-pre', '.ag-code pre', '.rp-pkt-tree', '.rb-keybox pre', '.ag-design-diff',
    'textarea',
]


class Pages(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.seed()

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def seed(cls):
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 100,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self',
            'portal_cert_max': 1000, 'portal_cert_keys': 1, 'mail_mode': 'off',
            'certs_agents_active': 1}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        caps = ['cert.view', 'cert.renew', 'deploy.view', 'deploy.run', 'target.view',
                'team.view', 'team.activity']
        for i in range(14):
            cls.must('POST', '/api/roles/save', {
                'name': 'Custom role %02d' % i, 'description': 'a role of the test %d' % i,
                'caps': caps[:2 + i % 6]})
        people = ['p%02d' % i for i in range(45)] + ['bigboss', 'tsolo']
        for name in people:
            cls.must('POST', '/api/users', {'action': 'add', 'name': name, 'role': 'readonly',
                                            'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/teams/save', {'name': 'Company', 'kind': 'unit',
                                             'description': 'the whole company'})
        for u in range(6):
            cls.must('POST', '/api/teams/save', {'name': 'Unit %d' % u, 'kind': 'unit',
                                                 'parent': 'Company'})
            for t in range(6):
                cls.must('POST', '/api/teams/save', {
                    'name': 'Team %d.%d' % (u, t), 'parent': 'Unit %d' % u,
                    'description': 'a team of the test',
                    'members': [{'who': 'local:p%02d' % ((u * 6 + t) % 45), 'roles': ['Viewer']}]})
        members = [{'who': 'local:' + p, 'roles': ['Viewer', 'Requester']} for p in people[:45]]
        members.append({'who': 'local:bigboss', 'roles': ['Team manager', 'Team owner',
                                                          'Approver', 'Device manager']})
        cls.must('POST', '/api/teams/save', {
            'name': 'Big team', 'parent': 'Unit 0', 'description': 'the team with everything',
            'contact_mail': 'big@example.test', 'members': members,
            'policy': {'target_kinds': ['fake', 'agent'], 'max_days': 90,
                       'suffixes': ['example.test']}})
        for i in range(70):
            cls.must('POST', '/api/certs/save', {
                'name': 'host%02d' % i, 'names': ['host%02d.example.test' % i], 'issuer': 'self',
                'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'Big team'})
        cls.must('POST', '/api/certs/save', {
            'name': 'solo-one', 'names': ['solo-one.example.test'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'local:tsolo'})
        out = os.path.join(cls.tmp, 'out')
        for i in range(30):
            cls.must('POST', '/api/targets/save', {
                'name': 'box%02d' % i, 'kind': 'fake', 'owner': 'Big team',
                'config': {'dir': out, 'host': 'box%02d.example.test' % i}})

    @classmethod
    def pages(cls):
        web = os.path.join(cls.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web, ignore=shutil.ignore_patterns('assets'))
        # the assets as they are in the tree (edited while --serve runs)
        os.symlink(os.path.join(ROOT, 'web', 'assets'), os.path.join(web, 'assets'))
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(cls.tmp, 'run') + '/'))
        port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='8'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 20
        while time.time() < end:
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=5)
                break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.3)
        return php, 'http://127.0.0.1:%d' % port

    def drive(self, base, what, user=''):
        node = shutil.which('node')
        got = subprocess.run([node, os.path.join(HERE, 'no_double_scroll_page.js'), base, self.pw,
                              what, WIDTHS, json.dumps(ALLOW), user],
                             capture_output=True, text=True, cwd=ROOT, timeout=900)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        return [json.loads(x) for x in got.stdout.splitlines() if x.startswith('{')][-1]

    def test_nowhere_two_scrollbars(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        try:
            seen = {w: self.drive(base, w, u) for w, u in
                    (('admin', ''), ('portal', 'bigboss'), ('solo', 'tsolo'))}
        finally:
            php.terminate()
            php.wait(10)
        found = []
        for what, s in seen.items():
            self.assertEqual(s['errors'], [], what)
            found += ['%s %s: %s (%d of %d px) inside %s' % (f['size'], f['where'], f['el'], f['h'],
                                                             f['sh'], f['outer'])
                      for f in s['found']]
        steps = sum(len(s['steps']) for s in seen.values())
        # the tour really went everywhere: tabs, panes, the teams' views, dialogs, the portal
        self.assertGreater(steps, 100, seen['admin']['steps'][:20])
        joined = '\n'.join(sum((s['steps'] for s in seen.values()), []))
        for want in ('settings teams / Roles', 'settings teams / Organisation / Big team / members',
                     'tab certs: a certificate', 'portal certs', 'portal solo'):
            self.assertIn(want, joined)
        self.assertEqual(found, [], '\n' + '\n'.join(found))


if __name__ == '__main__':
    if '--serve' in sys.argv:
        Pages.setUpClass()
        try:
            p, b = Pages.pages()
            print('admin  %s/admin/index.php  tester / %s' % (b, Pages.pw), flush=True)
            print('portal %s/  bigboss, tsolo' % b, flush=True)
            p.wait()
        finally:
            Pages.tearDownClass()
    else:
        unittest.main(verbosity=2)
