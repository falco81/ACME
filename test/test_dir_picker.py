#!/usr/bin/env python3
"""Pick from the directory (1.0.128): beside every box that holds a name of the directory.

    python3 test/test_dir_picker.py
    ACME_SHOTS=DIR python3 test/test_dir_picker.py      # screenshots kept in DIR

"Wherever the pages work with the directory - groups, people - it can be asked directly and
picked from." One control (core.js dirPickButton) shared by the administration and the portal: a
small search button beside the box, a popover asking the directory as one types (the
administration's /api/dir/search, the portal's dir-search), what is picked put into the box
in the form the box already takes - a group's DN as one more line of a setting's list, a
person's login, a team member's group:NAME. Typed by hand works as before, wildcards too.

A real daemon (test/test_certs_core.py's way), php -S on a copy of web/, test/mockldap.py as
the directory, test/dir_picker_page.js (node + Playwright) driving the pages:

- the settings' groups (the administrators' four roles, the portal's groups): the button
  beside each, groups picked go in as DNs, picked again come out, the box's separator kept;
- the directory's "Try a sign-in" and "Look a name up", the certificate look-up for a person,
  the teams' access check: a person's login, an account switched off said so;
- Teams from directory groups: groups picked beside the filter, the preview of only those,
  of those and the filter, and of the filter alone as before (the API too);
- the portal's member dialog of a team manager: a person (their UPN), a group (group:NAME);
- 390 / 768 / 1400 px: the popover on the screen, outside the popup, no new scrollbar;
- Czech; a read-only account sees no button; the directory gone: the picker says so and the
  boxes still take what is typed.
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
import mockldap                      # noqa: E402

BASE = 'DC=corpnet,DC=loc'
PKI = ('PKI-Web', 'PKI-Mail', 'PKI-VPN', 'PKI-Factory')


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


def node_ok():
    node = shutil.which('node')
    return bool(node and shutil.which('php') and not subprocess.run(
        [node, '-e', 'require("playwright")'], capture_output=True, cwd=ROOT).returncode)


class DirPicker(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    seen = {}

    @classmethod
    def setUpClass(cls):
        for cn in PKI:
            mockldap.GROUPS['CN=%s,OU=Groups,%s' % (cn, BASE)] = {
                'cn': [cn], 'objectClass': ['top', 'group'],
                'description': ['%s certificates' % cn[4:]],
                'member': ['CN=Jan Novak,OU=People,' + BASE]}
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.php = None
        # before there is a directory: both searches say so
        cls.before = {
            'admin': cls.call('GET', '/api/dir/search', None, cls.admin,
                              {'q': 'pki', 'kind': 'group'}),
            'from_groups': cls.call('POST', '/api/teams/from_groups',
                                    {'filter': 'CN=PKI-*', 'dry_run': True}, cls.admin)}
        cls.must('POST', '/api/users', {'action': 'add', 'name': 'tmgr', 'role': 'readonly',
                                        'password': cls.pw, 'must_change': 0})
        cls.dir_id = cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})['id']
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 100,
            'portal_directory': 'corp', 'admin_directory': 'corp', 'portal_who': 'groups',
            'portal_groups': 'CN=CERT_USERS,OU=Groups,' + BASE, 'mail_mode': 'off'}})
        cls.must('POST', '/api/teams/save', {'name': 'Web', 'description': 'web servers',
                                             'members': [{'who': 'local:tmgr',
                                                          'roles': ['Team manager']}]})
        cls.must('POST', '/api/teams/save', {'name': 'Suppliers', 'members': [
            {'who': 'group:CERT_SUPPLIER_X', 'roles': ['Requester']}]})
        cls.wait_dir(True)

    @classmethod
    def tearDownClass(cls):
        if cls.php is not None:
            cls.php.terminate()
            cls.php.wait(10)
        TCC.CertsCore.tearDownClass.__func__(cls)
        cls.ldap_stop.set()

    @classmethod
    def must(cls, method, path, body=None, args=None):
        st, got = cls.call(method, path, body, cls.admin, args)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def wait_dir(cls, there):
        end = time.time() + 30
        while time.time() < end:
            st, _got = cls.call('GET', '/api/dir/search', None, cls.admin,
                                {'q': 'pki', 'kind': 'group'})
            if (st == 200) == there:
                return
            time.sleep(0.3)
        raise RuntimeError('the directory is %s yet' % ('not there' if there else 'still there'))

    @classmethod
    def pages(cls):
        if cls.php is not None:
            return cls.base
        web = os.path.join(cls.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web, ignore=shutil.ignore_patterns('assets'))
        os.symlink(os.path.join(ROOT, 'web', 'assets'), os.path.join(web, 'assets'))
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(cls.tmp, 'run') + '/'))
        port = TCC.free_port()
        cls.php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
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
        cls.base = 'http://127.0.0.1:%d' % port
        return cls.base

    def run_page(self, mode):
        got = subprocess.run(['node', os.path.join(HERE, 'dir_picker_page.js'), self.pages(),
                              self.pw, mode, os.environ.get('ACME_SHOTS', '')],
                             capture_output=True, text=True, timeout=900, cwd=ROOT)
        self.assertEqual(got.returncode, 0, got.stderr[-3000:])
        lines = [x for x in got.stdout.splitlines() if x.startswith('{')]
        self.assertTrue(lines, got.stdout[-2000:] + got.stderr[-2000:])
        seen = json.loads(lines[-1])
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [], seen['errors'])
        return seen

    # ---- the API ------------------------------------------------------------------------
    def test_1_no_directory_said(self):
        st, got = self.before['admin']
        self.assertEqual(st, 404, got)
        self.assertIn('no directory is set up', got.get('error', ''))
        st, got = self.before['from_groups']
        self.assertEqual(st, 404, got)

    def test_2_from_groups_picked(self):
        dn = lambda cn: 'CN=%s,OU=Groups,%s' % (cn, BASE)       # noqa: E731
        # the filter alone: as before
        got = self.must('POST', '/api/teams/from_groups', {'filter': 'CN=PKI-*', 'dry_run': True})
        self.assertEqual(sorted(g['cn'] for g in got['groups']), sorted(PKI))
        self.assertEqual(got['filter'], 'PKI-*')
        # picked alone (by DN, by cn), the filter left empty
        got = self.must('POST', '/api/teams/from_groups', {
            'filter': '', 'groups': [dn('PKI-Web'), 'CERT_USERS', dn('Nope')], 'dry_run': True})
        self.assertEqual(sorted(g['cn'] for g in got['groups']), ['CERT_USERS', 'PKI-Web'])
        self.assertEqual(got['missing'], [dn('Nope')])
        self.assertEqual(got['picked'], 3)
        # both, one group in both only once
        got = self.must('POST', '/api/teams/from_groups', {
            'filter': 'CN=PKI-V*', 'groups': [dn('PKI-Web'), dn('PKI-VPN')], 'dry_run': True})
        self.assertEqual(sorted(g['cn'] for g in got['groups']), ['PKI-VPN', 'PKI-Web'])
        # nothing at all, or not a list: refused as before
        st, got = self.call('POST', '/api/teams/from_groups', {'filter': '', 'dry_run': True},
                            self.admin)
        self.assertEqual(st, 400, got)
        st, got = self.call('POST', '/api/teams/from_groups',
                            {'filter': '', 'groups': 'PKI-Web', 'dry_run': True}, self.admin)
        self.assertEqual(st, 400, got)
        st, got = self.call('POST', '/api/teams/from_groups',
                            {'filter': '', 'groups': ['g%d' % i for i in range(201)],
                             'dry_run': True}, self.admin)
        self.assertEqual(st, 400, got)
        # a certificate administrator: the preview only, as before
        certer = self.login('certer')
        st, got = self.call('POST', '/api/teams/from_groups',
                            {'groups': [dn('PKI-Web')], 'dry_run': True}, certer)
        self.assertEqual(st, 200, got)
        st, got = self.call('POST', '/api/teams/from_groups', {'groups': [dn('PKI-Web')]},
                            certer)
        self.assertEqual(st, 403, got)
        # the read-only account may not search
        viewer = self.login('viewer')
        st, got = self.call('GET', '/api/dir/search', None, viewer, {'q': 'pki', 'kind': 'group'})
        self.assertEqual(st, 403, got)

    # ---- the pages ----------------------------------------------------------------------
    @unittest.skipUnless(node_ok(), 'no node, php or playwright here')
    def test_3_admin_pages(self):
        s = self.run_page('admin')
        dn = lambda cn: 'CN=%s,OU=Groups,%s' % (cn, BASE)       # noqa: E731
        # the settings' groups: a button beside each box
        self.assertEqual(s['settingButtons'], [['admin_group_full', True],
                                               ['admin_group_cert', True],
                                               ['admin_group_readonly', True],
                                               ['admin_group_portal', True]], s)
        self.assertEqual(s['typedKept'], 'CN=Typed By Hand,OU=X,DC=corpnet,DC=loc')
        self.assertEqual(sorted(i['v'] for i in s['groupItems']), sorted(dn(c) for c in PKI))
        self.assertTrue(all(i['dn'] for i in s['groupItems']), s['groupItems'])
        # picked: one more line each, picked again it comes out; the typed line stays
        self.assertEqual(s['afterTwo'], '\n'.join(['CN=Typed By Hand,OU=X,DC=corpnet,DC=loc',
                                                   dn('PKI-Web'), dn('PKI-Mail')]))
        self.assertEqual(s['afterToggle'], '\n'.join(['CN=Typed By Hand,OU=X,DC=corpnet,DC=loc',
                                                      dn('PKI-Web')]))
        self.assertEqual(s['multiCount'], '2 of these in the box')
        self.assertTrue(s['escapeKeepsPage'])
        self.assertEqual(s['semiList'], 'CN=One,DC=corpnet,DC=loc; CN=Two,DC=corpnet,DC=loc; '
                         + dn('PKI-VPN'))
        # people: their login, their state
        self.assertIn('jnovak@corpnet.loc', [i['v'] for i in s['userItems']])
        self.assertEqual(s['tryName'], 'jnovak@corpnet.loc')
        gone = [i for i in s['goneItems'] if i['v'] == 'gone@corpnet.cz']
        self.assertEqual(gone[0]['state'], 'switched off', s['goneItems'])
        self.assertEqual(s['lookName'], 'gone@corpnet.cz')
        self.assertTrue(s['certLookupButton'])
        # the portal's groups: the new button beside the old "Find and pick"
        self.assertTrue(s['portalGroupsButton'])
        self.assertTrue(s['portalGroupsOld'])
        self.assertEqual(s['portalGroups'], 'CN=CERT_USERS,OU=Groups,%s\n%s'
                         % (BASE, dn('CERT_SUPPLIER_X')))
        # the access check: a person picked, checked at once
        self.assertEqual(s['accessWho'], 'nested@corpnet.cz')
        self.assertEqual(sorted(s['accessTeams']), ['Suppliers'])
        # Teams from directory groups
        self.assertEqual(sorted(s['fgChips']), [dn('PKI-Factory'), dn('PKI-Web')])
        self.assertEqual(s['fgFilterKept'], 'CN=PKI-*')
        self.assertEqual(s['fgPickedOnly'], ['PKI-Factory', 'PKI-Web'])
        self.assertEqual(s['fgBoth'], ['PKI-Factory', 'PKI-VPN', 'PKI-Web'])
        self.assertEqual(s['fgTyped'], sorted(PKI))
        # widths: on the screen, outside the popup, no new scrollbar, a small list
        for w in ('w1400', 'w768', 'w390'):
            one = s[w]
            self.assertTrue(one['besideFilter'], (w, one))
            self.assertTrue(one['fit']['inside'], (w, one))
            self.assertFalse(one['fit']['pageWide'], (w, one))
            self.assertTrue(one['fit']['outsideModal'], (w, one))
            self.assertLessEqual(one['fit']['listMax'], 240, (w, one))
            self.assertTrue(one['modalSame'], (w, one))
            self.assertTrue(one['scrollersSame'], (w, one))
            self.assertTrue(one['modalStillOpen'], (w, one))
        self.assertTrue(s['fit1400']['inside'], s['fit1400'])
        # Czech
        self.assertEqual(s['csTitle'], 'Vybrat skupiny z adresáře')
        self.assertEqual(s['csPlaceholder'], 'Část názvu skupiny')
        self.assertEqual(s['csSaid'], 'Napište aspoň dvě písmena.')
        self.assertEqual(s['csCount'], '1 z nich je v poli')
        self.assertIn('vloží do pole', s['csHint'])
        # read only: no button
        self.assertEqual(s['roPeople'], 0)
        self.assertEqual(s['roTeams'], 0)

    @unittest.skipUnless(node_ok(), 'no node, php or playwright here')
    def test_4_portal_page(self):
        s = self.run_page('portal')
        for w in ('p1400', 'p390'):
            one = s[w]
            self.assertTrue(one['beside'], (w, one))
            self.assertEqual(one['typed'], 'local:someone')
            self.assertTrue(one['fit']['inside'], (w, one))
            self.assertFalse(one['fit']['pageWide'], (w, one))
            self.assertIn('jnovak@corpnet.loc', [i['v'] for i in one['userItems']])
            self.assertEqual(one['pickedUser'], 'jnovak@corpnet.loc')
            self.assertIn('group:CERT_USERS', [i['v'] for i in one['groupItems']])
            self.assertEqual(one['pickedGroup'], 'group:CERT_USERS')

    @unittest.skipUnless(node_ok(), 'no node, php or playwright here')
    def test_5_no_directory_page(self):
        def corp(on):
            self.must('POST', '/api/directories', {'action': 'save', 'directory': {
                'id': self.dir_id, 'name': 'corp', 'hosts': '127.0.0.1', 'port': self.ldap_port,
                'tls': 'none', 'verify': 0, 'base': BASE,
                'bind_dn': 'CN=isemon,OU=Service,' + BASE, 'enabled': 1 if on else 0}})
            self.wait_dir(on)
        # switched off: the settings still name it, there is no directory to search
        corp(False)
        try:
            s = self.run_page('nodir')
        finally:
            corp(True)
        self.assertEqual(s['noDirSaid'], 'No directory is set up to search - type the name by '
                                         'hand.')
        self.assertTrue(s['noDirBad'])
        self.assertEqual(s['noDirTyped'], 'CN=PKI-*,OU=Typed')
        self.assertIn('Není nastaven žádný adresář', s['noDirSaidCs'])


class Source(unittest.TestCase):
    """The control and where it is used, without a browser."""

    def test_one_control_in_core(self):
        core = read('web/assets/core.js')
        self.assertIn('function dirPickButton(input, opts)', core)
        # the administration's search and the portal's - never another route
        self.assertIn("api('dir/search&q='", core)
        self.assertIn("api('dir-search&kind='", core)

    def test_used_beside_each_box(self):
        admin = read('web/assets/admin.js')
        for k in ('portal_groups', 'admin_group_full', 'admin_group_cert', 'admin_group_readonly',
                  'admin_group_portal'):
            self.assertRegex(admin, r'DIRPICK_SETTINGS = \{[^}]*%s' % k)
        for box in ("id: 'ag-try-pick'", "id: 'clk-pick'", "pickId: 'dir-look-pick'"):
            self.assertIn(box, admin)
        teams = read('web/assets/teams.js')
        self.assertIn("id: 'tmx-ac-pick'", teams)
        self.assertIn("id: 'tmx-fg-pick'", teams)
        self.assertIn("id: 'pw-mem-pick'", read('web/assets/portal-teams.js'))

    def test_portal_route_relayed(self):
        page = read('web/index.php')
        self.assertIn("'dir-search' => ['q', 'kind']", page)

    def test_czech(self):
        cs = json.loads(read('web/lang/cs.json'))
        have = {v['source']: v['text'] for part in ('strings', 'patterns')
                for v in cs[part].values()}
        for en in ('Pick from the directory', 'Pick groups from the directory',
                   'Type at least two letters.', '{0} of these in the box',
                   'No directory is set up to search - type the name by hand.',
                   'Or pick groups from the directory with the search button beside the filter.'):
            self.assertTrue(have.get(en), en)
        self.assertIn('{0} of these in the box',
                      {v['source'] for v in cs['patterns'].values()})


if __name__ == '__main__':
    unittest.main(verbosity=2)
