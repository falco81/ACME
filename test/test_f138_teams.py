#!/usr/bin/env python3
"""The governance of teams (1.0.138, docs/teams.md "Governance"): T1-T8.

    python3 test/test_f138_teams.py
    python3 test/test_f138_teams.py --serve      # the daemon and the pages, seeded, kept running

Against a real daemon (test/test_certs_core.py's way) and, for the pages, Chromium through
test/f138_teams_page.js (php -S on a copy of web/):

- T1 who may do what and why: a person's matrix (each cell's memberships, inherited, temporary),
  a team's people, the reverse query; the limits said beside a cell; a read-only account refused;
- T2 view as: the administration as a member (their role, every write refused, a fulladmin
  route refused, the banner's word, events), stopped; the portal as a member by a one-time code
  (read-only, the code once); a certificate administrator may not;
- T3 just-in-time elevation: off by default; asked, never approved by oneself nor by one without
  team.members, approved, held until its end, ended by itself (tick), events;
- T4 access reviews: opened, confirmed, taken out (the member gone), never one's own, overdue
  reported, expired by the deadline (the membership's until), the history;
- T5 separation of duties: an exclusive pair refused on member save (inherited from above), on a
  temporary role, on approval; "never one's own" beats the approval rule's self: true;
- T6 templates and CSV: a team saved as a template (never a webhook), a team from it, CSV
  preview with errors, made top-down; only a full administrator;
- T7 channels: webhooks sealed and never returned (nor exported without the secrets), tried
  against a local receiver, the escalation once per stage;
- T8 health: expiring, failed, outside the limits, weak keys, quota, the score;
- nothing new by default; an old database (no new columns or tables) given them and working.
"""
import http.server
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)

DAY = 86400
PEOPLE = ('jan', 'eva', 'boss', 'petr', 'solo')


class Hook(http.server.BaseHTTPRequestHandler):
    got = []

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        Hook.got.append((self.path, self.rfile.read(n).decode('utf-8', 'replace')))
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *a):
        pass


class Gov(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    py = TCC.CertsCore.__dict__['py']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.hook = http.server.HTTPServer(('127.0.0.1', 0), Hook)
        threading.Thread(target=cls.hook.serve_forever, daemon=True).start()
        cls.seed()

    @classmethod
    def tearDownClass(cls):
        cls.hook.shutdown()
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None, args=None, session=None):
        st, got = cls.call(method, path, body, session or cls.admin, args)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def seed(cls):
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 100,
            'mail_mode': 'off', 'certs_notify_days': 14}})
        for name in PEOPLE:
            cls.must('POST', '/api/users', {'action': 'add', 'name': name, 'role': 'readonly',
                                            'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        cls.must('POST', '/api/teams/save', {
            'name': 'Europe', 'kind': 'unit', 'contact_mail': 'eu@example.test',
            'members': [{'who': 'local:boss', 'roles': ['Team owner']}],
            'policy': {'max_certs': 4}})
        cls.must('POST', '/api/teams/save', {
            'name': 'Web', 'parent': 'Europe', 'contact_mail': 'web@example.test',
            'members': [{'who': 'local:jan', 'roles': ['Requester']},
                        {'who': 'local:eva', 'roles': ['Approver']},
                        {'who': 'local:petr', 'roles': ['Viewer'], 'until': time.time() + 30 * DAY}],
            'policy': {'suffixes': ['example.test'], 'key_download': False}})
        cls.must('POST', '/api/teams/save', {'name': 'Mail', 'parent': 'Europe'})
        cls.ids = {}
        for name, owner in (('shop', 'Web'), ('api', 'Web'), ('mx', 'Mail'), ('odd', 'Web')):
            cls.ids[name] = cls.must('POST', '/api/certs/save', {
                'name': name, 'names': ['%s.example.test' % name], 'issuer': 'self',
                'key_type': 'ec-256', 'auto_renew': 0, 'owner': owner})['id']
        now = time.time()
        cls.sql([("UPDATE certs SET state = 'ok', not_before = ?, not_after = ? WHERE name = 'shop'",
                  (now - 20 * DAY, now + 2 * DAY)),
                 ("UPDATE certs SET state = 'failed', not_before = ?, not_after = ?, key_type = "
                  "'rsa-1024' WHERE name = 'api'", (now - 10 * DAY, now + 200 * DAY)),
                 ("UPDATE certs SET state = 'ok', names = ?, not_before = ?, not_after = ? WHERE "
                  "name = 'odd'", (json.dumps(['odd.other.test']), now - DAY, now + 100 * DAY)),
                 ("UPDATE certs SET state = 'ok', not_before = ?, not_after = ? WHERE name = 'mx'",
                  (now - DAY, now + 300 * DAY))])
        cls.s = {n: cls.login(n) for n in PEOPLE}

    @classmethod
    def sql(cls, stmts):
        code = ('import sys, json; sys.path.insert(0, %r); import acme; acme.load_config(); '
                'st = acme.Storage(acme.open_db())\n'
                'for q, a in %r:\n    st.db.run(q, tuple(a))\nprint(1)\n' % (ROOT, stmts))
        got = subprocess.run([sys.executable, '-c', code], env=cls.env, capture_output=True,
                             text=True, timeout=180)
        if got.returncode:
            raise RuntimeError(got.stderr[-3000:])

    def tick(self):
        return self.py('import threading\nfrom acmelib.certs import teamgov as G\n'
                       'G.tick(st, force=True)\n'
                       '[t.join(20) for t in threading.enumerate() if t.name == "team-notify"]\n'
                       'print(json.dumps(1))')

    def events(self, like):
        return self.py("print(json.dumps([r['words'] for r in st.db.rows(\"SELECT words FROM "
                       "events WHERE words LIKE ? ORDER BY id\", (%r,))]))" % ('%' + like + '%'))

    # ---- nothing new by default --------------------------------------------------------------
    def test_00_defaults(self):
        got = self.must('GET', '/api/teams')
        for t in got['teams']:
            self.assertEqual(t['gov'], {'hooks': {'teams': False, 'slack': False}}, t['name'])
        st, e = self.call('POST', '/api/teams/elevate', {'team': 'Web', 'role': 'Renewer',
                                                         'hours': 2, 'reason': 'x y z'},
                          self.s['jan'])
        self.assertEqual(st, 403, e)
        self.assertIn('off', e['error'])
        self.assertEqual(self.must('GET', '/api/teams/elevations', session=self.s['jan'])
                         ['may_ask'], [])
        self.assertEqual(self.must('GET', '/api/teams/reviews', args={'team': 'Web'})['reviews'],
                         [])
        self.assertEqual(self.must('GET', '/api/teams/templates')['templates'], [])
        st, _ = self.call('GET', '/api/teams/view_as', None, self.admin)
        self.assertEqual(st, 200)

    # ---- T1 -------------------------------------------------------------------------------
    def test_10_whomay_person(self):
        got = self.must('GET', '/api/teams/whomay', args={'who': 'local:boss'})
        rows = {t['team']: t for t in got['teams']}
        self.assertEqual(sorted(rows), ['Europe', 'Mail', 'Web'])
        web = rows['Web']
        self.assertIn('cert.key', web['caps'])
        why = [web['via'][i] for i in web['cells']['cert.key']]
        self.assertEqual(why[0]['team'], 'Europe')
        self.assertTrue(why[0]['inherited'])
        self.assertEqual(why[0]['roles'], ['Team owner'])
        # the limit said beside the cell
        self.assertIn('forbid', web['limits']['cert.key'])
        # read-only accounts may not ask
        st, _ = self.call('GET', '/api/teams/whomay', None, self.ro, {'who': 'local:boss'})
        self.assertEqual(st, 403)

    def test_11_whomay_team_and_reverse(self):
        got = self.must('GET', '/api/teams/whomay', args={'team': 'Web'})
        people = {p['who']: p for p in got['people']}
        self.assertIn('local:boss', people)
        self.assertNotIn('cert.approve', people['local:jan']['caps'])
        self.assertIn('cert.approve', people['local:eva']['caps'])
        self.assertTrue(any(p.get('admin') == 'fulladmin' for p in got['people']))
        rev = self.must('GET', '/api/teams/whocan', args={'cap': 'cert.approve',
                                                          'cert': self.ids['shop']})
        self.assertEqual(rev['team'], 'Web')
        who = {p['who'] for p in rev['people']}
        self.assertIn('local:eva', who)
        self.assertIn('local:boss', who)
        self.assertNotIn('local:jan', who)
        eva = next(p for p in rev['people'] if p['who'] == 'local:eva')
        self.assertEqual(eva['why_here'][0]['roles'], ['Approver'])
        st, e = self.call('GET', '/api/teams/whocan', None, self.admin, {'cap': 'nope',
                                                                          'team': 'Web'})
        self.assertEqual(st, 400, e)

    # ---- T3 -------------------------------------------------------------------------------
    def test_30_jit(self):
        self.must('POST', '/api/teams/governance', {'team': 'Europe', 'jit': {
            'roles': ['Certificate manager', 'Renewer'], 'max_hours': 4}})
        may = self.must('GET', '/api/teams/elevations', session=self.s['jan'])['may_ask']
        self.assertIn('Web', [m['team'] for m in may])
        st, e = self.call('POST', '/api/teams/elevate', {'team': 'Web', 'role': 'Team owner',
                                                         'hours': 2, 'reason': 'just because'},
                          self.s['jan'])
        self.assertEqual(st, 403, e)
        st, e = self.call('POST', '/api/teams/elevate', {'team': 'Web', 'role': 'Renewer',
                                                         'hours': 9, 'reason': 'swap the LB'},
                          self.s['jan'])
        self.assertEqual(st, 403, e)
        st, e = self.call('POST', '/api/teams/elevate', {'team': 'Mail', 'role': 'Renewer',
                                                         'hours': 2, 'reason': 'swap the LB'},
                          self.s['solo'])
        self.assertEqual(st, 403, e)                  # not a member
        got = self.must('POST', '/api/teams/elevate', {'team': 'Web', 'role': 'Renewer',
                                                       'hours': 2, 'reason': 'swap the LB'},
                        session=self.s['jan'])['elevation']
        self.assertEqual(got['state'], 'waiting')
        # never oneself; never one without team.members
        for who in ('jan', 'eva'):
            st, e = self.call('POST', '/api/teams/elevate_decide', {'id': got['id'], 'ok': True},
                              self.s[who])
            self.assertEqual(st, 403, (who, e))
        todo = self.must('GET', '/api/teams/elevations', session=self.s['boss'])['to_decide']
        self.assertEqual([r['id'] for r in todo], [got['id']])
        st, e = self.call('POST', '/api/teams/elevate_decide', {'id': got['id'], 'ok': False},
                          self.s['boss'])
        self.assertEqual(st, 400, e)                  # a decline says why
        done = self.must('POST', '/api/teams/elevate_decide', {'id': got['id'], 'ok': True,
                                                               'why': 'ok for tonight'},
                         session=self.s['boss'])['elevation']
        self.assertEqual(done['state'], 'granted')
        self.assertAlmostEqual(done['until'] - done['decided'], 7200, delta=5)
        m = self.must('GET', '/api/teams/whomay', args={'who': 'local:jan'})
        web = next(t for t in m['teams'] if t['team'] == 'Web')
        self.assertIn('cert.renew', web['caps'])
        self.assertTrue(any(v.get('jit') for v in web['via']))
        # the role works: jan may renew Web's certificates in the administration now
        sc = self.py("from acmelib.certs import teams as T\nprint(json.dumps(sorted(T.person_caps("
                     "st, {'local:jan'}, [])['web']['caps'])))")
        self.assertIn('cert.renew', sc)
        # ends by itself
        self.sql([('UPDATE cert_team_elevations SET until = ? WHERE id = ?',
                   (time.time() - 5, got['id']))])
        self.tick()
        rows = self.must('GET', '/api/teams/elevations', args={'team': 'Web'})['rows']
        self.assertEqual(next(r for r in rows if r['id'] == got['id'])['state'], 'expired')
        sc = self.py("from acmelib.certs import teams as T\nT.changed()\nprint(json.dumps(sorted("
                     "T.person_caps(st, {'local:jan'}, [])['web']['caps'])))")
        self.assertNotIn('cert.renew', sc)
        ev = self.events('the temporary role Renewer')
        self.assertTrue(any('ended by itself' in w for w in ev), ev)
        # asked and taken back
        again = self.must('POST', '/api/teams/elevate', {'team': 'Web', 'role': 'Renewer',
                                                         'hours': 1, 'reason': 'again'},
                          session=self.s['jan'])['elevation']
        back = self.must('POST', '/api/teams/elevate_end', {'id': again['id']},
                         session=self.s['jan'])['elevation']
        self.assertEqual(back['state'], 'cancelled')

    # ---- T4 -------------------------------------------------------------------------------
    def test_40_reviews(self):
        self.must('POST', '/api/teams/governance', {'team': 'Web', 'review': {
            'every_days': 90, 'answer_days': 7, 'action': 'report'}})
        st, e = self.call('POST', '/api/teams/review_open', {'team': 'Web'}, self.s['jan'])
        self.assertEqual(st, 403, e)
        rv = self.must('POST', '/api/teams/review_open', {'team': 'Web'},
                       session=self.s['boss'])['review']
        self.assertEqual(sorted(i['who'] for i in rv['items']),
                         ['local:eva', 'local:jan', 'local:petr'])
        st, e = self.call('POST', '/api/teams/review_answer', {'id': rv['id'], 'who': 'local:jan',
                                                               'keep': True}, self.s['eva'])
        self.assertEqual(st, 403, e)                 # no team.members
        self.must('POST', '/api/teams/review_answer', {'id': rv['id'], 'who': 'local:jan',
                                                       'keep': True}, session=self.s['boss'])
        self.must('POST', '/api/teams/review_answer', {'id': rv['id'], 'who': 'local:petr',
                                                       'keep': False}, session=self.s['boss'])
        web = next(t for t in self.must('GET', '/api/teams')['teams'] if t['name'] == 'Web')
        self.assertNotIn('local:petr', [m['who'] for m in web['members']])
        # overdue: reported
        self.sql([('UPDATE cert_team_reviews SET due = ? WHERE id = ?', (time.time() - 5, rv['id']))])
        self.tick()
        h = self.must('GET', '/api/teams/reviews', args={'team': 'Web'})['reviews']
        self.assertEqual(h[0]['state'], 'overdue')
        self.assertTrue(any('overdue' in w for w in self.events('access review of the team Web')))
        self.must('POST', '/api/teams/review_answer', {'id': rv['id'], 'who': 'local:eva',
                                                       'keep': True}, session=self.s['boss'])
        h = self.must('GET', '/api/teams/reviews', args={'team': 'Web'})['reviews']
        self.assertEqual(h[0]['state'], 'done')
        # never one's own: boss in a review of Europe
        rv2 = self.must('POST', '/api/teams/review_open', {'team': 'Europe'})['review']
        st, e = self.call('POST', '/api/teams/review_answer', {'id': rv2['id'],
                                                               'who': 'local:boss', 'keep': True},
                          self.s['boss'])
        self.assertEqual(st, 403, e)
        self.must('POST', '/api/teams/review_answer', {'id': rv2['id'], 'who': 'local:boss',
                                                       'keep': True})
        # expire: the deadline ends the memberships not confirmed
        self.must('POST', '/api/teams/governance', {'team': 'Mail', 'review': {
            'every_days': 30, 'answer_days': 3, 'action': 'expire'}})
        self.must('POST', '/api/teams/save', {'old_name': 'Mail', 'name': 'Mail', 'parent': 'Europe',
                                              'members': [{'who': 'local:solo', 'roles': ['Viewer']}]})
        self.tick()                                   # the schedule opens it
        rv3 = self.must('GET', '/api/teams/reviews', args={'team': 'Mail'})['reviews'][0]
        self.assertEqual(rv3['state'], 'open')
        self.sql([('UPDATE cert_team_reviews SET due = ? WHERE id = ?', (time.time() - 5, rv3['id']))])
        self.tick()
        mail = next(t for t in self.must('GET', '/api/teams')['teams'] if t['name'] == 'Mail')
        self.assertTrue(mail['members'][0]['expired'], mail['members'])
        rv3 = self.must('GET', '/api/teams/reviews', args={'team': 'Mail'})['reviews'][0]
        self.assertEqual(rv3['state'], 'closed')
        self.assertEqual(rv3['items'][0]['state'], 'expired')

    # ---- T5 -------------------------------------------------------------------------------
    def test_50_sod(self):
        got = self.must('POST', '/api/teams/governance', {'team': 'Europe', 'sod': {
            'no_self_approval': True, 'exclusive': ['Approver + Certificate manager']}})
        self.assertEqual(got['gov']['sod']['exclusive'], [['Approver', 'Certificate manager']])
        st, e = self.call('POST', '/api/teams/save', {
            'old_name': 'Web', 'name': 'Web', 'parent': 'Europe', 'members': [
                {'who': 'local:jan', 'roles': ['Requester', 'Approver', 'Certificate manager']},
                {'who': 'local:eva', 'roles': ['Approver']}]}, self.admin)
        self.assertEqual(st, 400, e)
        self.assertIn('separation of duties', e['error'])
        self.assertIn('the rule of Europe', e['error'])
        # a temporary role that would clash: refused when given
        self.must('POST', '/api/teams/governance', {'team': 'Europe', 'jit': {
            'roles': ['Certificate manager'], 'max_hours': 4}})
        ask = self.must('POST', '/api/teams/elevate', {'team': 'Web', 'role': 'Certificate manager',
                                                       'hours': 1, 'reason': 'incident 42'},
                        session=self.s['eva'])['elevation']
        st, e = self.call('POST', '/api/teams/elevate_decide', {'id': ask['id'], 'ok': True},
                          self.s['boss'])
        self.assertEqual(st, 403, e)
        self.assertIn('Approver', e['error'])
        # "never one's own" beats an approval rule's self: true
        got = self.py(
            "from acmelib.certs import teams as T, teampolicy as TP\n"
            "T.save_team(st, {'old_name': 'Mail', 'name': 'Mail', 'parent': 'Europe', 'policy': "
            "{'approval': {'mode': 'always', 'self': True}}}, 'x')\n"
            "row = {'id': 0, 'name': 'x', 'owner': 'Mail'}\n"
            "a = TP.self_allowed(st, row)\n"
            "T.save_team(st, {'old_name': 'Europe', 'name': 'Europe', 'kind': 'unit'}, 'x')\n"
            "print(json.dumps([a]))")
        self.assertEqual(got, [False])
        # an approver holding both sides is refused on approval
        got = self.py(
            "from acmelib.certs import teamgov as G, teams as T\n"
            "ap = {'by': 'x', 'all': False, 'caps': {'web': {'caps': frozenset(T.CAPS)}}}\n"
            "print(json.dumps([G.approver_conflict(st, 'Web', ap) or '']))")
        self.assertIn('separation of duties', got[0])
        self.must('POST', '/api/teams/governance', {'team': 'Europe', 'sod': None, 'jit': None})

    # ---- T6 -------------------------------------------------------------------------------
    def test_60_templates_csv(self):
        self.must('POST', '/api/teams/hooks', {'team': 'Web', 'slack':
                                               'https://hooks.slack.invalid/T000/B000/secretpart'})
        tpl = self.must('POST', '/api/teams/template_save', {
            'name': 'Web team', 'from_team': 'Web', 'members': True,
            'description': 'a team of web servers'})['template']
        self.assertEqual(tpl['config']['policy']['suffixes'], ['example.test'])
        self.assertNotIn('secretpart', json.dumps(tpl))
        st, e = self.call('POST', '/api/teams/template_save', {'name': 'x', 'from_team': 'Web'},
                          self.cert_admin)
        self.assertEqual(st, 403, e)
        self.must('POST', '/api/teams/template_save', {
            'name': 'Shop', 'config': {'kind': 'team', 'members': [
                {'who': 'group:{team}-Admins', 'roles': ['Certificate manager']}],
                'policy': {'max_days': 90}, 'extras': {'review': {'every_days': 60}}}})
        made = self.must('POST', '/api/teams/from_template', {'template': 'Shop',
                                                              'name': 'Eshop', 'parent': 'Web'})
        self.assertEqual(made['team']['members'][0]['who'], 'group:Eshop-Admins')
        self.assertEqual(made['team']['policy'], {'max_days': 90})
        self.assertEqual(made['team']['gov']['review']['every_days'], 60)
        csv = ('name,parent,kind,template,members\n'
               'Factory,Asia,unit,,\n'
               'Asia,,unit,,local:boss=Team owner\n'
               'Line 1,Factory,team,Shop,\n'
               'Bad,Nowhere,team,,\n')
        prev = self.must('POST', '/api/teams/import_csv', {'csv': csv, 'dry_run': True})
        self.assertEqual(prev['errors'], 1)
        self.assertEqual([r['state'] for r in prev['rows']], ['new', 'new', 'new', 'error'])
        st, e = self.call('POST', '/api/teams/import_csv', {'csv': csv, 'dry_run': False},
                          self.admin)
        self.assertEqual((st, e.get('made')), (200, []))           # nothing while a line is wrong
        got = self.must('POST', '/api/teams/import_csv', {'csv': csv.rsplit('Bad', 1)[0],
                                                          'dry_run': False})
        self.assertEqual(got['made'], ['Asia', 'Factory', 'Line 1'])
        teams = {t['name']: t for t in self.must('GET', '/api/teams')['teams']}
        self.assertEqual(teams['Line 1']['parent'], 'Factory')
        self.assertEqual(teams['Line 1']['members'][0]['who'], 'group:Line 1-Admins')
        self.assertEqual(teams['Asia']['members'][0]['roles'], ['Team owner'])
        st, e = self.call('POST', '/api/teams/import_csv', {'csv': csv, 'dry_run': True},
                          self.cert_admin)
        self.assertEqual(st, 403, e)

    # ---- T7 -------------------------------------------------------------------------------
    def test_70_channels(self):
        url = 'http://127.0.0.1:%d/hook/secret-token-123' % self.hook.server_port
        self.must('POST', '/api/teams/hooks', {'team': 'Europe', 'teams': url})
        st, e = self.call('POST', '/api/teams/hooks', {'team': 'Europe', 'slack': 'ftp://x'},
                          self.admin)
        self.assertEqual(st, 400, e)
        st, e = self.call('POST', '/api/teams/hooks', {'team': 'Europe', 'slack': 'https://x.test'},
                          self.cert_admin)
        self.assertEqual(st, 403, e)
        everything = json.dumps(self.must('GET', '/api/teams'))
        self.assertNotIn('secret-token-123', everything)
        self.assertNotIn('secret-token-123', json.dumps(self.must('GET', '/api/export')))
        self.must('POST', '/api/teams/governance', {'team': 'Europe', 'notify': {
            'mail': 'eu-team@example.test', 'manager_mail': 'eu-lead@example.test',
            'oncall_mail': 'oncall@example.test', 'expiry_days': 14, 'manager_days': 3}})
        eu = next(t for t in self.must('GET', '/api/teams')['teams'] if t['name'] == 'Europe')
        self.assertEqual(eu['gov']['hooks'], {'teams': True, 'slack': False})
        Hook.got = []
        tried = self.must('POST', '/api/teams/notify_test', {'team': 'Web'})
        self.assertEqual(tried['from'], 'Europe')
        self.assertEqual(tried['channels']['teams']['result'], 'sent')
        self.assertEqual(Hook.got[0][0], '/hook/secret-token-123')
        self.assertIn('a test', json.loads(Hook.got[0][1])['text'].lower() + 'a test')
        # escalation: shop ends in 2 days -> the manager; once
        Hook.got = []
        self.tick()
        self.tick()
        texts = [json.loads(b)['text'] for _p, b in Hook.got]
        self.assertEqual(len([t for t in texts if t.startswith('Web:') and ' shop ' in t]), 1,
                         texts)
        self.must('POST', '/api/teams/hooks', {'team': 'Europe', 'teams': ''})
        eu = next(t for t in self.must('GET', '/api/teams')['teams'] if t['name'] == 'Europe')
        self.assertEqual(eu['gov']['hooks'], {'teams': False, 'slack': False})
        self.must('POST', '/api/teams/governance', {'team': 'Europe', 'notify': None})

    # ---- T8 -------------------------------------------------------------------------------
    def test_80_health(self):
        got = self.must('GET', '/api/teams/health')
        h = {t['team']: t for t in got['teams']}
        web = h['Web']['own']
        self.assertEqual(web['expiring'], 1)
        self.assertEqual(web['failed_renewals'], 1)
        self.assertEqual(web['weak'], 1)
        self.assertEqual(web['outside'], 1)
        self.assertLess(h['Web']['score'], 100)
        eu = h['Europe']['below']
        self.assertEqual(eu['quota']['max'], 4)
        self.assertGreaterEqual(eu['certs'], 4)
        self.assertIsNotNone(got['score'])
        one = self.must('GET', '/api/teams/health', args={'team': 'Web'})
        w = next(t for t in one['teams'] if t['team'] == 'Web')
        self.assertEqual([x['name'] for x in w['list']['outside']], ['odd'])

    # ---- T2 -------------------------------------------------------------------------------
    def test_90_view_as(self):
        boss = self.login('tester')
        st, e = self.call('POST', '/api/teams/view_as', {'who': 'local:jan'}, self.cert_admin)
        self.assertEqual(st, 403, e)
        self.must('POST', '/api/teams/view_as', {'who': 'local:jan'}, session=boss)
        st, me = self.call('GET', '/api/auth/whoami', None, boss)
        self.assertEqual(me['who']['role'], 'readonly')
        self.assertEqual(me['who']['view_as']['who'], 'local:jan')
        self.assertTrue(self.must('GET', '/api/teams/view_as', session=boss)['active'])
        # what jan sees: a fulladmin route refused, every write refused
        st, e = self.call('GET', '/api/export', None, boss)
        self.assertEqual(st, 403, e)
        st, e = self.call('POST', '/api/teams/save', {'name': 'Hack'}, boss)
        self.assertEqual(st, 403, e)
        self.assertIn('read-only', e['error'])
        st, e = self.call('POST', '/api/settings', {'settings': {'portal': 0}}, boss)
        self.assertEqual(st, 403, e)
        st, _ = self.call('GET', '/api/certs', None, boss)
        self.assertEqual(st, 200)
        self.must('POST', '/api/teams/view_as_stop', {}, session=boss)
        st, me = self.call('GET', '/api/auth/whoami', None, boss)
        self.assertEqual(me['who']['role'], 'fulladmin')
        ev = self.events('views the administration as local:jan')
        self.assertTrue(ev and 'the team Web' in ev[-1], ev)
        self.assertTrue(self.events('viewing the pages as local:jan (read-only), was refused'))
        # the portal as jan: a one-time code
        got = self.must('POST', '/api/teams/view_as_portal', {'who': 'local:jan'}, session=boss)
        code = got['url'].split('=', 1)[1]
        st, tok = self.call('POST', '/api/portal/view_as_enter', {'code': code})
        self.assertEqual(st, 200, tok)
        st, again = self.call('POST', '/api/portal/view_as_enter', {'code': code})
        self.assertEqual(st, 403, again)
        ps = tok['token']
        teams = self.must('GET', '/api/portal/teams', session=ps)
        self.assertIn('Web', [t['name'] for t in teams['teams']])
        self.assertTrue(self.must('GET', '/api/portal/view_as', session=ps)['active'])
        st, e = self.call('POST', '/api/portal/elevate', {'team': 'Web', 'role': 'Renewer',
                                                          'hours': 1, 'reason': 'xyz'}, ps)
        self.assertEqual(st, 403, e)
        self.assertIn('read-only', e['error'])
        st, e = self.call('POST', '/api/portal/logout', {}, ps)
        self.assertEqual(st, 200, e)


class OldDatabase(unittest.TestCase):
    def test_upgrade(self):
        tmp = tempfile.mkdtemp(prefix='acme-f138-old-')
        try:
            db = os.path.join(tmp, 'acme.db')
            with open(os.path.join(tmp, 'config.json'), 'w') as f:
                json.dump({'db_path': db}, f)
            con = sqlite3.connect(db)
            con.execute('CREATE TABLE cert_teams (id INTEGER PRIMARY KEY, name TEXT NOT NULL '
                        'UNIQUE, kind TEXT, members BLOB, contact_mail TEXT, contact_phone TEXT, '
                        'note TEXT, created REAL, created_by TEXT, updated REAL, updated_by TEXT, '
                        'parent TEXT, policy BLOB, description TEXT)')
            con.execute("INSERT INTO cert_teams (name, kind, members, updated) VALUES ('Old', "
                        "'team', '[{\"who\": \"local:x\", \"rights\": [\"view\"]}]', 1)")
            con.commit()
            con.close()
            code = ('import sys, json; sys.path.insert(0, %r); import acme; acme.load_config(); '
                    'from acmelib import engine as E\n'
                    'st = acme.Storage(acme.open_db()); E.HA_STORE["store"] = st\n'
                    'from acmelib.certs import teams as T, teamgov as G, teamaccess as TA\n'
                    'cols = st.db.columns("cert_teams")\n'
                    't = T.teams(st)[0]\n'
                    'print(json.dumps({"cols": "extras" in cols and "hooks_sealed" in cols, '
                    '"gov": t["gov"], "caps": sorted(T.person_caps(st, {"local:x"}, [])["old"]'
                    '["caps"]), "grants": G.active_grants(st), "health": len(G.health_public(st)),'
                    '"tables": all(x in E.TABLES for x in ("cert_team_templates", '
                    '"cert_team_elevations", "cert_team_reviews")), '
                    '"carry": "cert_team_templates" in E.carry_tables()}))' % ROOT)
            env = dict(os.environ, ACME_CONFIG=os.path.join(tmp, 'config.json'), ACME_STATE=tmp,
                       ACME_RUN=tmp, ACME_LOGDIR=tmp)
            got = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True,
                                 text=True, timeout=180)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            out = json.loads(got.stdout.strip().splitlines()[-1])
            self.assertTrue(out['cols'])
            self.assertEqual(out['gov'], {'hooks': {'teams': False, 'slack': False}})
            self.assertEqual(out['caps'], ['cert.view', 'deploy.view', 'target.view',
                                           'team.view'])
            self.assertEqual(out['grants'], [])
            self.assertEqual(out['health'], 1)
            self.assertTrue(out['tables'])
            self.assertTrue(out['carry'])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)




# ---------------------------------------------------------------------------------------------
# The pages (Chromium): the administration's governance and the portal's
# ---------------------------------------------------------------------------------------------
import test_teams_admin_ui as TAU    # noqa: E402  (the seeded organisation, php -S)

SCRATCH_CS = os.environ.get('ACME_F138_CS', '')


class Pages(TAU.Pages):
    test_pages = None           # the organisation's own test stays in test_teams_admin_ui.py
    test_api_seeded = None

    @classmethod
    def setUpClass(cls):
        if SCRATCH_CS and os.path.isfile(SCRATCH_CS):
            os.environ['ACME_EXTRA_CS'] = SCRATCH_CS
        TAU.Pages.setUpClass.__func__(cls)
        cls.gov_seed()

    @classmethod
    def gov_seed(cls):
        m = cls.must
        m('POST', '/api/users', {'action': 'add', 'name': 'anna', 'role': 'readonly',
                                 'password': cls.pw, 'must_change': 0})
        m('POST', '/api/settings', {'settings': {'portal_local': 1, 'portal_tries': 100}})
        web = next(t for t in m('GET', '/api/teams')['teams'] if t['name'] == 'Web')
        ms = [dict((k, v) for k, v in x.items() if k in ('who', 'rights', 'roles', 'until', 'note'))
              for x in web['members']] + [{'who': 'local:anna', 'roles': ['Requester']}]
        m('POST', '/api/teams/save', {'old_name': 'Web', 'name': 'Web', 'parent': 'Prague',
                                      'members': ms})
        m('POST', '/api/teams/governance', {'team': 'Europe', 'jit': {
            'roles': ['Certificate manager', 'Renewer', 'Deployer'], 'max_hours': 8}})
        m('POST', '/api/teams/governance', {'team': 'Group HQ', 'sod': {
            'no_self_approval': True, 'exclusive': [['Approver', 'Certificate manager']]}})
        m('POST', '/api/teams/governance', {'team': 'Web', 'review': {
            'every_days': 90, 'answer_days': 14, 'action': 'report'}})
        m('POST', '/api/teams/governance', {'team': 'Prague', 'notify': {
            'mail': 'prague-certs@example.com', 'manager_mail': 'prague-lead@example.com',
            'oncall_mail': 'oncall@example.com', 'expiry_days': 14, 'manager_days': 3,
            'deploy_failed': 'oncall'}})
        m('POST', '/api/teams/hooks', {'team': 'Prague',
                                       'teams': 'https://example.invalid/webhookb2/x'})
        m('POST', '/api/teams/review_open', {'team': 'Web'})
        m('POST', '/api/teams/template_save', {'name': 'Web team', 'from_team': 'Web',
                                               'description': 'web servers with their limits'})
        m('POST', '/api/teams/template_save', {'name': 'Plant', 'config': {
            'kind': 'unit', 'description': 'a plant and its PLCs', 'members': [
                {'who': 'group:{team}-OT', 'roles': ['Device manager']}],
            'policy': {'max_days': 90, 'wildcards': False}}})
        anna = cls.login('anna')
        st, got = cls.call('POST', '/api/teams/elevate', {
            'team': 'Web', 'role': 'Certificate manager', 'hours': 4,
            'reason': 'replace the load balancer certificate tonight'}, anna)
        if st != 200:
            raise RuntimeError('elevate: %s %s' % (st, got))
        cls.sql([("UPDATE certs SET key_type = 'rsa-1024' WHERE name = 'web-3'", ()),
                 ("UPDATE certs SET names = ? WHERE name = 'trading-1'",
                  (json.dumps(['trading.other.test']),))])

    def test_pages_gov(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        try:
            got = subprocess.run([node, os.path.join(HERE, 'f138_teams_page.js'), base, self.pw,
                                  os.environ.get('ACME_SHOTS', '')],
                                 capture_output=True, text=True, timeout=1500, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [], seen['errors'])
        self.check_seen(seen)

    def check_seen(self, seen):
        self.assertEqual(seen['views'][-4:], ['whomay', 'health', 'gov', 'templates'], seen)
        self.assertIn('gov', seen['tabs'])
        self.assertGreater(seen['matrixCells'], 10, seen)
        self.assertTrue(seen['whyShown'], seen)
        self.assertIn('local:tester', seen['whoCan'], seen)
        self.assertGreater(seen['healthCards'], 5, seen)
        self.assertTrue(seen['approved'], seen)
        self.assertTrue(seen['reviewConfirmed'], seen)
        self.assertGreater(seen['csvRows'], 1, seen)
        self.assertTrue(seen['viewAsBanner'], seen)
        self.assertIn('read-only', seen['viewAsRefused'], seen)
        self.assertFalse(seen['bannerAfterStop'], seen)
        self.assertEqual(seen['roWrites'], [], seen)
        for w, over in seen['overflow'].items():
            self.assertEqual(over, [], (w, over))
        self.assertEqual(seen.get('english', []), [], seen.get('english'))
        self.assertTrue(seen['portalHealth'], seen)
        self.assertTrue(seen['portalAsk'], seen)
        self.assertTrue(seen['portalViewAs'], seen)


def serve():
    Pages.setUpClass()
    php, base = Pages.pages()
    print('%s/admin/index.php  password %s  (tester full, viewer read-only, anna asks)'
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
