#!/usr/bin/env python3
"""The rebuilt portal (1.0.125, phase B2): the team workspace in Chromium.

    python3 test/test_teams_portal_ui.py
    TP_SERVE=3600 python3 test/test_teams_portal_ui.py      # the pages served for an hour
    TP_CS_EXTRA=a.json:b.json ...                             # Czech words not in cs.json yet

A real daemon in a folder of its own (test/test_certs_core.py's way), the pages from a copy of
web/ through php -S, driven by test/teams_portal_ui_page.js (node + Playwright):

- a tree Europe > Prague > Web > WebDev; people in Web with the built-in roles, an approver of
  Prague (the level above), a team manager, a person in no team;
- per role: a Viewer sees no action button; a Requester asks for a certificate; a Renewer
  renews; a Device manager adds a device with the module's own fields and tests it; an
  Approver approves in "Waiting for you" (a two-level rule: the team's lead, then Prague);
  a Team manager adds a member and a sub-team with limits;
- a person in no team: the old "Your certificates" (its table, its dialog);
- no error in the console, nothing wider than the page at 390 px, no English left in Czech;
- screenshots in English and Czech at 1400, 1024, 768 and 390 px (TP_SHOTS=folder).
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

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)

PEOPLE = {'tviewer': 'Viewer', 'treq': 'Requester', 'trenew': 'Renewer',
          'tdev': 'Device manager', 'tlead': 'Approver', 'tmgr': 'Team manager',
          'towner': 'Team owner'}


def merged_lang(web):
    """cs.json with the Czech of TP_CS_EXTRA (flat {"English": "Česky"} files) added - the
    words of a phase not merged into web/lang/cs.json yet."""
    extra = [p for p in os.environ.get('TP_CS_EXTRA', '').split(':') if p and os.path.isfile(p)]
    if not extra:
        return
    path = os.path.join(web, 'lang', 'cs.json')
    with open(path, encoding='utf-8') as f:
        pack = json.load(f)
    have = {v['source'] for part in ('strings', 'patterns') for v in pack[part].values()}
    n = 0
    for p in extra:
        with open(p, encoding='utf-8') as f:
            words = json.load(f)
        for en, cs in words.items():
            if en in have or not cs:
                continue
            n += 1
            part = 'patterns' if '{0}' in en else 'strings'
            pack[part]['x%s%05d' % (part[0], n)] = {'source': en, 'text': cs}
            have.add(en)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(pack, f, ensure_ascii=False)


class TeamsPortalUi(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.php = None
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 100,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self',
            'portal_cert_max': 1000, 'portal_cert_keys': 1, 'mail_mode': 'off',
            'certs_agents_active': 1}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        for name in list(PEOPLE) + ['tboss', 'tsolo']:
            cls.must('POST', '/api/users', {'action': 'add', 'name': name, 'role': 'readonly',
                                            'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/teams/save', {'name': 'Europe', 'kind': 'unit',
                                             'description': 'the European offices'})
        cls.must('POST', '/api/teams/save', {
            'name': 'Prague', 'kind': 'unit', 'parent': 'Europe',
            'description': 'the Prague office',
            'members': [{'who': 'local:tboss', 'roles': ['Approver']}]})
        cls.must('POST', '/api/teams/save', {
            'name': 'Web', 'parent': 'Prague', 'description': 'public web servers',
            'contact_mail': 'web@example.test',
            'members': [{'who': 'local:' + n, 'roles': [r]} for n, r in PEOPLE.items()],
            'policy': {'target_kinds': ['fake', 'agent', 'agent_windows'], 'max_days': 90,
                       'suffixes': ['example.test'],
                       'approval': {'mode': 'always', 'approvers': 'both', 'count': 1}}})
        cls.must('POST', '/api/teams/save', {'name': 'WebDev', 'parent': 'Web',
                                             'description': 'the developers\' servers'})
        cls.ids = {}
        for i, name in enumerate(['shop', 'api', 'mail', 'intranet']):
            got = cls.must('POST', '/api/certs/save', {
                'name': name, 'names': ['%s.example.test' % name, 'www.%s.example.test' % name],
                'issuer': 'self', 'key_type': 'ec-256', 'auto_renew': 1, 'owner': 'Web'})
            cls.ids[name] = got['id']
            cls.issue(got['id'])
        for i in range(56):
            cls.must('POST', '/api/certs/save', {
                'name': 'host%02d' % i, 'names': ['host%02d.example.test' % i], 'issuer': 'self',
                'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'WebDev' if i % 3 else 'Web'})
        # one that runs out soon: a source of 12 days
        cls.must('POST', '/api/sources/save', {'name': 'short', 'kind': 'selfsigned',
                                               'config': {'days': 12}})
        got = cls.must('POST', '/api/certs/save', {
            'name': 'legacy-intranet', 'names': ['legacy.example.test'], 'issuer': 'short',
            'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'Web'})
        cls.issue(got['id'])
        got = cls.must('POST', '/api/certs/save', {
            'name': 'solo-one', 'names': ['solo-one.example.test'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'local:tsolo'})
        cls.issue(got['id'])
        cls.out = os.path.join(cls.tmp, 'out')
        cls.must('POST', '/api/targets/save', {
            'name': 'web-lb1', 'kind': 'fake', 'owner': 'Web',
            'config': {'dir': cls.out, 'password': 's3cret', 'host': 'lb1.example.test'}})
        cls.must('POST', '/api/targets/save', {
            'name': 'dev-box', 'kind': 'fake', 'owner': 'WebDev',
            'config': {'dir': cls.out, 'password': 'wrong'}})

    @classmethod
    def issue(cls, cid):
        st, got = cls.call('POST', '/api/certs/renew', {'id': cid, 'force': True}, cls.admin)
        if st == 409:                  # issued by itself already (auto_renew)
            end = time.time() + 60
            while time.time() < end:
                c = cls.must('GET', '/api/certs/one?id=%d' % cid)
                c = c.get('cert', c)
                if c.get('not_after') or c.get('state') == 'failed':
                    return
                time.sleep(0.4)
            return
        if st != 200:
            raise RuntimeError('renew %s: %s %s' % (cid, st, got))
        job = got['job_id']
        end = time.time() + 120
        while time.time() < end:
            j = cls.must('GET', '/api/certs/job?id=%d' % job)['job']
            if j['state'] not in ('queued', 'running'):
                return
            time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        if cls.php is not None:
            cls.php.terminate()
            cls.php.wait(10)
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def serve(cls):
        web = os.path.join(cls.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        merged_lang(web)
        if os.environ.get('TP_LIVE'):
            # working on the pages: the assets as they are written (index.php copied again by hand)
            shutil.rmtree(os.path.join(web, 'assets'))
            os.symlink(os.path.join(ROOT, 'web', 'assets'), os.path.join(web, 'assets'))
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(cls.tmp, 'run') + '/'))
        port = TCC.free_port()
        cls.php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 20
        while time.time() < end:
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/' % port, timeout=5)
                break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.3)
        return 'http://127.0.0.1:%d' % port

    def page(self, base, flow, lang='en', width=1400, extra=None):
        node = shutil.which('node')
        args = [node, os.path.join(HERE, 'teams_portal_ui_page.js'), base, flow, self.pw, lang,
                str(width), os.environ.get('TP_SHOTS', '')] + list(extra or [])
        got = subprocess.run(args, capture_output=True, text=True, timeout=400, cwd=ROOT,
                             env=dict(os.environ, TP_OUT=self.out))
        lines = [x for x in (got.stdout or '').splitlines() if x.startswith('{')]
        self.assertTrue(lines, (got.stdout or '')[-3000:] + got.stderr[-3000:])
        out = json.loads(lines[-1])
        self.assertNotIn('error', out, out.get('error'))
        self.assertEqual(out.get('errors'), [], out)
        return out

    def test_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode != 0:
            self.skipTest('no playwright for node here')
        base = self.serve()
        # ---- the roles, one flow each (English, a desktop) -----------------------------------
        got = self.page(base, 'viewer')
        self.assertTrue(got['nav']['certs'] and got['nav']['devices'], got)
        self.assertFalse(got['nav']['members'], got)
        self.assertEqual(got['actions'], [], got)            # no button that changes anything
        self.assertFalse(got['askShown'], got)
        self.assertGreaterEqual(got['total'], 60, got)       # Web and WebDev, paged
        self.assertLessEqual(got['rowsShown'], 50, got)

        got = self.page(base, 'requester')
        self.assertTrue(got['asked'], got)
        self.assertEqual(got['team'], 'Web', got)            # the team's, not their own
        self.assertTrue(got['mine'], got)
        self.assertIn('waits', got['said'].lower() + ' ' + got.get('state', ''), got)

        got = self.page(base, 'renewer')
        self.assertTrue(got['renewed'], got)

        got = self.page(base, 'devman')
        self.assertTrue(got['added'], got)
        self.assertTrue(got['tested'], got)
        self.assertTrue(got['deployAdded'] and got['deployed'], got)
        self.assertTrue(os.path.isfile(os.path.join(self.out, 'b2-shop.pem')))
        st, rows = self.call('GET', '/api/targets', None, self.admin)
        mine = [t for t in rows.get('rows', rows.get('targets', [])) if t.get('name') == 'b2-new']
        self.assertTrue(mine and mine[0].get('owner') == 'Web', mine)

        got = self.page(base, 'approver')          # the team's lead: the first of two levels
        self.assertTrue(got['approved'], got)
        self.assertIn('parent', got['needed'], got)
        got = self.page(base, 'boss')              # Prague: the level above - issued
        self.assertTrue(got['approved'], got)

        got = self.page(base, 'manager')
        self.assertTrue(got['memberAdded'], got)
        self.assertTrue(got['teamMade'], got)
        st, teams = self.call('GET', '/api/teams', None, self.admin)
        sub = [t for t in teams['teams'] if t['name'] == 'WebOps']
        self.assertTrue(sub and sub[0]['parent'] == 'Web', sub)
        self.assertEqual((sub[0].get('policy') or {}).get('max_days'), 30, sub)

        # ---- a person in no team: as before --------------------------------------------------
        got = self.page(base, 'solo')
        self.assertTrue(got['oldTable'], got)
        self.assertEqual(got['cols'], 5, got)
        self.assertTrue(got['dialog'], got)
        self.assertFalse(got['workspace'], got)

        # ---- a request waiting (the inbox, its timeline in the screenshots) ----------------
        st, got = self.call('POST', '/api/portal/login', {'name': 'treq', 'password': self.pw})
        self.assertEqual(st, 200, got)
        st, got = self.call('POST', '/api/portal/cert_request', {
            'names': ['b2-waits.example.test'], 'issuer': 'self', 'team': 'Web'}, got['token'])
        self.assertEqual(st, 200, got)
        # ---- every width, both languages: nothing wider than the page, no English in Czech ----
        for lang in ('en', 'cs'):
            for width in (1400, 1024, 768, 390):
                got = self.page(base, 'tour', lang, width)
                self.assertLessEqual(got['wide'], 0, (lang, width, got))
                if lang == 'cs' and os.environ.get('TP_CS_EXTRA'):
                    self.assertEqual(got['english'], [], (width, got['english']))


if __name__ == '__main__':
    if os.environ.get('TP_SERVE'):
        TeamsPortalUi.setUpClass()
        print(TeamsPortalUi.serve(), TeamsPortalUi.pw, flush=True)
        try:
            time.sleep(int(os.environ['TP_SERVE']))
        finally:
            TeamsPortalUi.tearDownClass()
    else:
        unittest.main(verbosity=2)
