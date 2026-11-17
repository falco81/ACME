#!/usr/bin/env python3
"""Enterprise teams, phase B1 (1.0.125): the administration's Settings → Owners and teams.

    python3 test/test_teams_admin_ui.py
    python3 test/test_teams_admin_ui.py --serve      # the same daemon and pages, kept running

The pane redrawn as an organisation: the tree of teams on the left (search, fold, kind icons,
counts, + Team / + Unit under the one chosen, Move to…), the team's page on the right (Overview,
Members, Limits, Devices, Certificates, Activity), the roles' capability matrix, the access check
and the teams made from directory groups - in Chromium (test/teams_admin_ui_page.js) against a
real daemon, php -S and a directory that is not there (test/mockldap.py):

- no error on the page; a team made, a member added through the directory search, limits set,
  a custom role's capability switched in the matrix, the access check of a nested person, the
  dry run of teams from groups;
- a read-only account sees all of it without a single control that changes something;
- 1400 / 1024 / 768 / 390 px: nothing wider than the window; on a phone the tree is a drawer;
- an installation with a flat list of teams (no tree, no roles) still draws and the owner select
  and tag picker other panes use are still there.

ACME_SHOTS=DIR keeps screenshots of every width in English and Czech; ACME_EXTRA_CS=FILE (flat
{"English": "Česky"}) is added to the Czech texts of the pages under test.
"""
import json
import os
import re
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
import mockldap                      # noqa: E402

BASE = 'DC=corpnet,DC=loc'
DAY = 86400


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


# The organisation: (name, kind, parent, description, contact mail)
TREE = [
    ('Group HQ', 'unit', None, 'the whole company', 'pki@example.com'),
    ('Europe', 'unit', 'Group HQ', 'every European site', ''),
    ('Prague', 'unit', 'Europe', 'headquarters and the data centre', 'prague-it@example.com'),
    ('Web', 'team', 'Prague', 'public web servers and their load balancers', 'web@example.com'),
    ('Mail', 'team', 'Prague', 'Exchange and the mail gateways', 'mail@example.com'),
    ('Network', 'team', 'Prague', 'switches, firewalls, VPN', ''),
    ('Databases', 'team', 'Prague', '', ''),
    ('Brno', 'unit', 'Europe', 'development centre', ''),
    ('Dev', 'team', 'Brno', 'build servers and test environments', ''),
    ('QA', 'team', 'Brno', '', ''),
    ('Vienna', 'unit', 'Europe', '', ''),
    ('Web AT', 'team', 'Vienna', '', ''),
    ('Ops AT', 'team', 'Vienna', '', ''),
    ('Americas', 'unit', 'Group HQ', '', ''),
    ('New York', 'unit', 'Americas', '', ''),
    ('Trading', 'team', 'New York', 'the trading floor', ''),
    ('Web US', 'team', 'New York', '', ''),
    ('Toronto', 'unit', 'Americas', '', ''),
    ('Support', 'team', 'Toronto', '', ''),
    ('Asia', 'unit', 'Group HQ', '', ''),
    ('Tokyo', 'unit', 'Asia', '', ''),
    ('Factory', 'team', 'Tokyo', 'the plant floor and its PLCs', ''),
    ('IoT', 'team', 'Tokyo', '', ''),
    ('Singapore', 'unit', 'Asia', '', ''),
    ('Payments', 'team', 'Singapore', '', ''),
    ('Suppliers', 'team', None, 'outside companies working for us', 'suppliers@example.com'),
    ('SupplierX', 'team', 'Suppliers', '', ''),
    ('Security', 'team', None, 'the security office', 'soc@example.com'),
    ('Jan Novak', 'person', None, '', 'jnovak@example.com'),
]
MEMBERS = {
    'Group HQ': [{'who': 'group:Helpdesk', 'roles': ['Viewer']}],
    'Europe': [{'who': 'jnovak', 'roles': ['Team manager'], 'note': 'regional lead'}],
    'Prague': [{'who': 'edvorak', 'roles': ['Certificate manager', 'Approver'],
                'until': 'SOON', 'note': 'covering for the summer'}],
    'Web': [{'who': 'local:tester', 'rights': ['view', 'request', 'manage']},
            {'who': 'group:ISE Admins', 'roles': ['Deployer', 'Night shift']},
            {'who': 'pkolar', 'roles': ['Requester']}],
    'Suppliers': [{'who': 'group:CERT_USERS', 'roles': ['Requester']}],
    'SupplierX': [{'who': 'group:CERT_SUPPLIER_X', 'roles': ['Renewer']}],
    'Security': [{'who': 'local:viewer', 'roles': ['Approver']}],
    'Jan Novak': [{'who': 'jnovak', 'rights': ['view', 'request']}],
}
POLICY = {
    'Group HQ': {'suffixes': ['example.com'], 'max_days': 397},
    'Europe': {'key_download': False, 'max_certs': 500},
    'Prague': {'approval': {'mode': 'outside', 'approvers': 'team_or_parent', 'count': 1,
                            'self': False, 'outside': {'suffixes': ['int.example.com'],
                                                       'max_days': 90}},
               'approve_actions': ['revoke']},
    'Web': {'issuers': ['self'], 'target_kinds': ['fake', 'ssh'], 'max_days': 90,
            'free_form': False},
    'Suppliers': {'approval': {'mode': 'always', 'approvers': 'team', 'count': 2},
                  'agents': False},
}


class Pages(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        for cn in ('PKI-Web', 'PKI-Mail', 'PKI-VPN', 'PKI-Factory'):
            mockldap.GROUPS['CN=%s,OU=Groups,%s' % (cn, BASE)] = {
                'cn': [cn], 'objectClass': ['top', 'group'], 'description': ['%s certificates' % cn[4:]],
                'member': ['CN=Jan Novak,OU=People,' + BASE]}
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_cert': 1, 'portal_directory': 'corp'}})
        cls.seed()

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)
        cls.ldap_stop.set()

    @classmethod
    def must(cls, method, path, body=None, args=None):
        st, got = cls.call(method, path, body, cls.admin, args)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def seed(cls):
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        cls.must('POST', '/api/roles/save', {'name': 'Night shift', 'description':
                                             'renews and deploys at night',
                                             'caps': ['cert.view', 'cert.renew', 'deploy.view',
                                                      'deploy.run']})
        cls.must('POST', '/api/roles/save', {'name': 'Auditor', 'description': 'reads everything',
                                             'caps': ['cert.view', 'deploy.view', 'target.view',
                                                      'team.view', 'team.activity']})
        soon = time.strftime('%Y-%m-%d', time.localtime(time.time() + 12 * DAY))
        for name, kind, parent, desc, mail in TREE:
            members = []
            for m in MEMBERS.get(name, []):
                m = dict(m)
                if m.get('until') == 'SOON':
                    m['until'] = soon
                members.append(m)
            cls.must('POST', '/api/teams/save', {
                'name': name, 'kind': kind, 'parent': parent, 'description': desc,
                'contact_mail': mail, 'members': members, 'policy': POLICY.get(name) or {}})
        cls.cert_ids = {}
        n = 0
        for team, count in (('Web', 6), ('Mail', 3), ('Network', 2), ('Prague', 1),
                            ('Trading', 2), ('SupplierX', 2), ('Security', 1)):
            for i in range(count):
                n += 1
                name = '%s-%d' % (team.lower().replace(' ', ''), i + 1)
                cls.cert_ids[name] = cls.must('POST', '/api/certs/save', {
                    'name': name, 'names': ['%s.example.com' % name], 'issuer': 'self',
                    'key_type': 'ec-256', 'auto_renew': 0, 'owner': team})['id']
        for name, owner in (('web-lb1', 'Web'), ('web-lb2', 'Web'), ('mx1', 'Mail'),
                            ('fw-core', 'Network'), ('spare-box', None)):
            cls.must('POST', '/api/targets/save', {'name': name, 'kind': 'fake',
                                                   'config': {'dir': '/tmp'}, 'owner': owner})
        # a few certificates as they are found in a real installation: running out, failed,
        # waiting for an approval
        now = time.time()
        cls.sql([("UPDATE certs SET state = 'ok', not_after = ? WHERE name IN ('web-1', 'web-2', "
                  "'mail-1')", (now + 9 * DAY,)),
                 ("UPDATE certs SET state = 'ok', not_after = ? WHERE name IN ('web-3', 'web-4', "
                  "'trading-1', 'network-1', 'mail-2')", (now + 200 * DAY,)),
                 ("UPDATE certs SET state = 'failed', last_error = 'the CA said no' WHERE name IN "
                  "('web-5', 'network-2')", ()),
                 ("UPDATE certs SET state = 'pending-approval' WHERE name IN ('web-6', "
                  "'supplierx-1')", ())])

    @classmethod
    def sql(cls, stmts):
        code = ('import sys, json; sys.path.insert(0, %r); import acme; acme.load_config(); '
                'st = acme.Storage(acme.open_db())\n'
                'for q, a in %r:\n    st.db.run(q, tuple(a))\nprint(1)\n' % (ROOT, stmts))
        got = subprocess.run([sys.executable, '-c', code], env=cls.env, capture_output=True,
                             text=True, timeout=180)
        if got.returncode:
            raise RuntimeError(got.stderr[-3000:])

    @classmethod
    def pages(cls):
        """php -S on a copy of web/ (the API relayed to this daemon): (process, base url)."""
        web = os.path.join(cls.tmp, 'web')
        if not os.path.isdir(web):
            shutil.copytree(os.path.join(ROOT, 'web'), web,
                            ignore=shutil.ignore_patterns('assets'))
            # the pages' assets as they are in the tree (edited while --serve runs)
            os.symlink(os.path.join(ROOT, 'web', 'assets'), os.path.join(web, 'assets'))
            api_php = os.path.join(web, 'acme-api.php')
            with open(api_php, encoding='utf-8') as f:
                text = f.read()
            with open(api_php, 'w', encoding='utf-8') as f:
                f.write(text.replace('/run/acme/', os.path.join(cls.tmp, 'run') + '/'))
            extra = os.environ.get('ACME_EXTRA_CS')
            if extra and os.path.isfile(extra):
                cs_path = os.path.join(web, 'lang', 'cs.json')
                with open(cs_path, encoding='utf-8') as f:
                    cs = json.load(f)
                with open(extra, encoding='utf-8') as f:
                    more = json.load(f)
                for i, (en, cz) in enumerate(sorted(more.items())):
                    part = 'patterns' if re.search(r'\{\d+\}', en) else 'strings'
                    cs[part]['b1_%04d' % i] = {'source': en, 'text': cz}
                with open(cs_path, 'w', encoding='utf-8') as f:
                    json.dump(cs, f, ensure_ascii=False)
        port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='6'),
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

    def test_api_seeded(self):
        got = self.must('GET', '/api/teams')
        self.assertEqual(len(got['tree']), len(TREE))
        self.assertIn('Night shift', [r['name'] for r in got['roles']])

    def test_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        try:
            got = subprocess.run([node, os.path.join(HERE, 'teams_admin_ui_page.js'), base,
                                  self.pw, os.environ.get('ACME_SHOTS', '')],
                                 capture_output=True, text=True, timeout=900, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [], seen['errors'])
        self.check_seen(seen)

    def check_seen(self, seen):
        # the tree: every team, kind icons, counts; the search keeps the ancestors
        self.assertEqual(seen['treeRows'], len(TREE), seen)
        self.assertEqual(seen['searchShown'], ['Group HQ', 'Europe', 'Prague', 'Web'], seen)
        self.assertEqual(seen['searchHit'], ['Web'], seen)
        # the team's page
        self.assertEqual(seen['crumbs'], ['Group HQ', 'Europe', 'Prague', 'Web'], seen)
        self.assertEqual(seen['tiles']['certs'], '6', seen)
        self.assertEqual(seen['tiles']['failing'], '1', seen)
        self.assertEqual(seen['tiles']['waiting'], '1', seen)
        self.assertEqual(seen['tiles']['devices'], '2', seen)
        self.assertEqual(seen['tabs'], ['overview', 'members', 'limits', 'devices', 'certs',
                                        'activity'], seen)
        # a team made under the chosen one, a member added through the directory
        self.assertTrue(seen['made'], seen)
        made = self.must('GET', '/api/teams')
        t = {x['name']: x for x in made['teams']}
        self.assertEqual(t['Web Shop']['parent'], 'Web', seen)
        self.assertEqual([m['who'] for m in t['Web Shop']['members']], ['jnovak@corpnet.loc'],
                         seen)
        self.assertEqual(t['Web Shop']['members'][0].get('roles'), ['Requester', 'Deployer'],
                         seen)
        # limits saved
        self.assertEqual(t['Web Shop']['policy'].get('max_days'), 30, seen)
        self.assertEqual(t['Web Shop']['policy'].get('approval', {}).get('mode'), 'always',
                         seen)
        self.assertEqual(seen['inheritedHint'], True, seen)
        # moved to another parent through the picker
        self.assertEqual(t['QA']['parent'], 'Dev', seen)
        # the matrix: built-in read only, a custom role's cap switched
        roles = {r['name']: r for r in made['roles']}
        self.assertIn('target.view', roles['Night shift']['caps'], seen)
        self.assertEqual(seen['builtinBoxes'], 0, seen)
        # the access check: nested through two groups
        self.assertEqual(sorted(seen['access']), ['SupplierX', 'Suppliers'], seen)
        self.assertTrue(seen['accessWhy'], seen)
        # from directory groups: a dry run lists them, nothing is made
        self.assertEqual(sorted(seen['dryRun']), ['PKI-Factory', 'PKI-Mail', 'PKI-VPN',
                                                  'PKI-Web'], seen)
        self.assertNotIn('PKI-Web', t)
        # activity
        self.assertGreater(seen['activity'], 0, seen)
        # read only: everything to see, nothing to change
        self.assertEqual(seen['roTreeRows'], len(TREE) + 1, seen)
        self.assertEqual(seen['roWrites'], [], seen)
        # widths: nothing wider than the window; the phone's drawer
        for w, over in seen['overflow'].items():
            self.assertEqual(over, [], (w, over))
        self.assertTrue(seen['drawer'], seen)
        # the tags still there; the pickers other panes use
        self.assertTrue(seen['tagsTab'], seen)
        self.assertEqual(seen['exports'], ['fillFilters', 'load', 'ownerChip', 'ownerPicker',
                                           'tagChip', 'tagOf', 'tagPicker', 'teamOf'], seen)


class Source(unittest.TestCase):
    def test_relay_knows_the_new_routes(self):
        page = read('web/admin/index.php')
        self.assertRegex(page, r'teams\|tags\|reqprofiles\|agents\|roles\|dir\)')

    def test_exports_kept(self):
        js = read('web/assets/teams.js')
        for name in ('ownerPicker', 'tagPicker', 'tagChip', 'ownerChip', 'fillFilters', 'teamOf',
                     'tagOf'):
            self.assertIn('%s: %s' % (name, name), js)


def serve():
    """--serve: the daemon, the directory and the pages, seeded, until Ctrl+C."""
    Pages.setUpClass()
    php, base = Pages.pages()
    print('%s/admin/index.php  password %s  (tester full, viewer read-only, certer cert admin)'
          % (base, Pages.pw), flush=True)
    with open(os.path.join(Pages.tmp, 'url'), 'w') as f:
        f.write(base)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        php.terminate()
        Pages.tearDownClass()


if __name__ == '__main__':
    if '--serve' in sys.argv:
        serve()
    else:
        unittest.main(verbosity=2)
