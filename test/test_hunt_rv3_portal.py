#!/usr/bin/env python3
"""Bug hunt v3, the certificate portal and the teams' workspace on it.

    python3 test/test_hunt_rv3_portal.py

A real daemon in a folder of its own (test/test_certs_core.py's way); the pages from a copy of
web/ (with this hunt's Czech merged in) through php -S, in Chromium (node + Playwright), when
they are here.

- An access review answered by two managers at once: each wrote back the list it had read - one
  answer was lost (a member confirmed became pending again), and one member could be taken out
  twice. The answers are now written over the list as it was read, the other read again.
- The review's dialog took a member out of the team at one click on Take out (beside Confirm) -
  Members asks first, and now so does the review; their own membership and one holding more
  than they do were offered Confirm / Take out, each refused once clicked.
- "Open the portal as" a second member in a browser already viewing the portal as another: the
  link was refused as a write - the page stayed on the first member, nothing said.
- ...and behind a load balancer (portal_sso) the balancer's sign-in, asked at every page, was
  refused as a write - and the page cleared the view-as sign-in at once: it never showed.
- The card of a request waiting for its team's approvers said "Waiting for an administrator".
- The page to change the password first asked view-as and was refused (403 in the console).
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

CS_EXTRA = ['/tmp/claude-0/-home-user-ACME/845070b5-9900-5dee-8b93-2de7397138a5/scratchpad/'
            'hunt140/cs_rv3_portal.json']
LB = '10.9.9.9'

NODE = r"""
const { chromium } = require('playwright');
(async () => {
  const [base, pass, flow, width, lang] = process.argv.slice(1);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: Number(width), height: 900}, deviceScaleFactor: 1});
  await ctx.addCookies([{name: 'acme_lang', value: lang || 'en', url: base}]);
  const page = await ctx.newPage();
  const out = {errors: [], bad: []};
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  page.on('response', r => { if (r.status() >= 400) out.bad.push(r.status() + ' ' + r.url()); });
  const pause = ms => page.waitForTimeout(ms);
  const user = {review: 'vmgr', card: 'vmgr', change: 'vchg'}[flow];
  try {
    await page.goto(base + '/');
    await page.fill('#in-name', user);
    await page.fill('#in-pass', pass);
    await page.click('#in-go');
    await page.waitForSelector('#signout', {timeout: 20000});
    await pause(2000);
    if (flow === 'review') {
      await page.evaluate(() => { location.hash = '#access/Web'; });
      await pause(2500);
      await page.locator('.pwg-rv').first().click(); await pause(1200);
      out.rows = await page.$$eval('#pwg-rv-list .pwg-rvi', rs => rs.map(r => ({who: r.dataset.who,
        btns: Array.from(r.querySelectorAll('button')).map(b => (b.disabled ? 'off:' : '') + (b.classList.contains('pwg-rv-keep') ? 'keep' : 'out')),
        text: r.innerText})));
      await page.locator('#pwg-rv-list .pwg-rvi[data-who="local:vreq"] button:not(.pwg-rv-keep)').click();
      await pause(1000);
      out.asked = await page.textContent('#modal-body');
      out.title = await page.textContent('#modal-title');
    } else if (flow === 'card') {
      await page.evaluate(() => { location.hash = '#certs/Web'; });
      await pause(2500);
      await page.locator('#pw-main tbody tr', {hasText: 'v3wait.example.test'}).first().click();
      await pause(1500);
      out.note = await page.$eval('#modal-body .cp-note', n => n.innerText);
    } else if (flow === 'change') {
      out.body = await page.textContent('body');
    }
  } catch (e) { out.error = String(e && e.stack || e); }
  await browser.close();
  console.log(JSON.stringify(out));
})();
"""


class HuntRv3Portal(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    py = TCC.CertsCore.__dict__['py']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.php = None
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 100,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self',
            'portal_cert_max': 1000, 'mail_mode': 'off'}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        for name in ('vmgr', 'vown', 'vreq', 'vview', 'vchg'):
            cls.must('POST', '/api/users', {'action': 'add', 'name': name, 'role': 'readonly',
                                            'password': cls.pw,
                                            'must_change': 1 if name == 'vchg' else 0})
        cls.must('POST', '/api/teams/save', {
            'name': 'Web', 'members': [
                {'who': 'local:vmgr', 'roles': ['Team manager', 'Approver', 'Requester']},
                {'who': 'local:vown', 'roles': ['Team owner']},
                {'who': 'local:vreq', 'roles': ['Requester']},
                {'who': 'local:vview', 'roles': ['Viewer']},
                {'who': 'local:vchg', 'roles': ['Viewer']}],
            'policy': {'suffixes': ['example.test'],
                       'approval': {'mode': 'always', 'approvers': 'team', 'count': 1}}})
        cls.must('POST', '/api/teams/governance', {
            'team': 'Web', 'review': {'every_days': 90, 'answer_days': 14, 'action': 'report'}})

    @classmethod
    def tearDownClass(cls):
        if cls.php is not None:
            cls.php.terminate()
            cls.php.wait(10)
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None, session=None):
        st, got = cls.call(method, path, body, session or cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def portal(cls, name):
        return cls.must('POST', '/api/portal/login', {'name': name, 'password': cls.pw},
                        session='')['token']

    def open_review(self):
        m = self.portal('vmgr')
        st, got = self.call('GET', '/api/portal/reviews', None, m)
        if got.get('open'):
            return got['open'][0]['id']
        return self.must('POST', '/api/portal/review_open', {'team': 'Web'}, m)['review']['id']

    def items(self, rid):
        got = self.must('GET', '/api/teams/reviews?team=Web')
        rv = [r for r in got['reviews'] if r['id'] == rid][0]
        return {i['who']: i['state'] for i in rv['items']}

    # ---- the access review ---------------------------------------------------------------
    def test_01_two_answers_at_once_both_kept(self):
        rid = self.open_review()
        # an answer given while another request had the review read already: its stale copy is
        # what that request writes back
        code = (
            'from acmelib.certs import teamgov as G\n'
            'stale = st.db.row("SELECT * FROM cert_team_reviews WHERE id = ?", (%d,))\n'
            'G.review_answer(st, %d, "local:vview", True, {"all": True, "by": "jan"})\n'
            'real = st.db.row\n'
            'n = [0]\n'
            'def row(sql, args=()):\n'
            '    if sql.startswith("SELECT * FROM cert_team_reviews") and not n[0]:\n'
            '        n[0] = 1\n'
            '        return dict(stale)\n'
            '    return real(sql, args)\n'
            'st.db.row = row\n'
            'G.review_answer(st, %d, "local:vchg", True, {"all": True, "by": "eva"})\n'
            'st.db.row = real\n'
            'try:\n'
            '    G.review_answer(st, %d, "local:vview", False, {"all": True, "by": "eva"})\n'
            '    said = ""\n'
            'except Exception as e:\n'
            '    said = str(e)\n'
            'print(json.dumps(said))\n') % (rid, rid, rid, rid)
        said = self.py(code)
        got = self.items(rid)
        self.assertEqual(got['local:vview'], 'kept', got)        # lost: pending again
        self.assertEqual(got["local:vchg"], "kept", got)
        self.assertIn('confirmed already', said)                 # never answered twice

    def test_02_reviews_say_which_answers_are_theirs(self):
        self.open_review()
        m = self.portal('vmgr')
        got = self.must('GET', '/api/portal/reviews', session=m)['open'][0]
        by = {i['who']: i for i in got['items']}
        self.assertTrue(by['local:vmgr']['me'])
        self.assertFalse(by['local:vreq']['me'])
        self.assertFalse(by['local:vown']['may_out'])            # the owner holds more
        self.assertTrue(by['local:vreq']['may_out'])

    # ---- view as ---------------------------------------------------------------------------
    def view_as(self, who):
        url = self.must('POST', '/api/teams/view_as_portal', {'who': who})['url']
        return url.split('=', 1)[1]

    def test_03_another_members_link_in_a_browser_viewing_as(self):
        st, a = self.call('POST', '/api/portal/view_as_enter', {'code': self.view_as('local:vview')})
        self.assertEqual(st, 200, a)
        st, b = self.call('POST', '/api/portal/view_as_enter', {'code': self.view_as('local:vreq')},
                          a['token'])
        self.assertEqual(st, 200, b)                               # 403 "read-only" before
        self.assertEqual(b['who'], 'local:vreq')
        st, me = self.call('GET', '/api/portal/me', None, b['token'])
        self.assertEqual(me['me']['name'], 'vreq', me)
        st, old = self.call('GET', '/api/portal/me', None, a['token'])
        self.assertIsNone(old.get('me'), old)                     # the first one ended

    def sso(self, name, key, session):
        req = urllib.request.Request('http://127.0.0.1:%d/api/portal/sso' % self.port,
                                     data=json.dumps({'name': name, 'key': key}).encode(),
                                     method='POST')
        req.add_header('X-Acme-Token', self.token)
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Acme-Peer', LB)
        req.add_header('X-Acme-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def test_04_view_as_behind_a_load_balancer(self):
        key = self.must('POST', '/api/portal-sso', {'action': 'key'})['key']
        self.must('POST', '/api/settings', {'settings': {'portal_sso': 1,
                                                         'portal_sso_from': LB + '/32'}})
        try:
            tok = self.must('POST', '/api/portal/view_as_enter',
                            {'code': self.view_as('local:vview')})['token']
            # the administrator who opened it, as the balancer names them
            for name in ('tester', 'CORP\\tester', 'tester@corp.example'):
                st, got = self.sso(name, key, tok)
                self.assertEqual(st, 200, got)                    # 403 read-only before
                self.assertTrue(got.get('same'), got)
            st, me = self.call('GET', '/api/portal/me', None, tok)
            self.assertEqual(me['me']['name'], 'vview', me)
            # somebody else at this browser now: the view-as sign-in ends
            self.sso('somebody', key, tok)
            st, me = self.call('GET', '/api/portal/me', None, tok)
            self.assertIsNone(me.get('me'), me)
        finally:
            self.must('POST', '/api/settings', {'settings': {'portal_sso': 0}})

    # ---- whom a request waits for ---------------------------------------------------------
    def test_05_request_card_says_its_teams_rule(self):
        r = self.portal('vmgr')
        got = self.must('POST', '/api/portal/cert_request', {
            'names': ['v3wait.example.test'], 'team': 'Web', 'issuer': 'self'}, session=r)
        self.assertTrue(got['waits'])
        mine = self.must('GET', '/api/portal/certs', session=r)['rows']
        row = [x for x in mine if x['id'] == got['id']][0]
        self.assertIn("the team Web's rule", row.get('waits_for') or '', row)
        # one of their own, with no team's rule: as before (an administrator's approval)
        got = self.must('POST', '/api/portal/cert_request', {
            'names': ['v3own.example.test'], 'issuer': 'self'}, session=r)
        mine = self.must('GET', '/api/portal/certs', session=r)['rows']
        row = [x for x in mine if x['id'] == got['id']][0]
        self.assertNotIn('waits_for', row)

    # ---- the pages ---------------------------------------------------------------------------
    @classmethod
    def serve(cls):
        web = os.path.join(cls.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(cls.tmp, 'run') + '/'))
        import test_f138_ctxmenu as F
        F.merge_cs(os.path.join(web, 'lang', 'cs.json'), CS_EXTRA)
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

    def page(self, flow, width=1400, lang='en'):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode != 0:
            self.skipTest('no playwright for node here')
        if self.php is None:
            type(self).base = self.serve()
        got = subprocess.run([node, '-e', NODE, '--', self.base, self.pw, flow, str(width), lang],
                             capture_output=True, text=True, timeout=300, cwd=ROOT)
        lines = [x for x in (got.stdout or '').splitlines() if x.startswith('{')]
        self.assertTrue(lines, (got.stdout or '')[-2000:] + (got.stderr or '')[-2000:])
        out = json.loads(lines[-1])
        self.assertNotIn('error', out, out.get('error'))
        self.assertEqual(out['errors'], [], out)
        return out

    def test_06_review_dialog(self):
        self.open_review()
        got = self.page('review', 390, 'cs')
        rows = {r['who']: r for r in got['rows']}
        if rows['local:vreq']['btns'] == []:
            self.skipTest('answered by an earlier test')
        self.assertEqual(rows['local:vmgr']['btns'], [], got)      # their own: no buttons
        self.assertIn('potvrdí vás jiný správce týmu', rows['local:vmgr']['text'], got)
        self.assertIn('off:out', rows['local:vown']['btns'], got)  # the owner holds more
        self.assertIn('vreq už nebude členem týmu Web', got['asked'], got)   # asked first
        self.assertIn('local:vreq', [m['who'] for m in self.must(
            'GET', '/api/teams')['teams'][0]['members']])

    def test_07_request_card_in_czech(self):
        r = self.portal('vmgr')
        st, mine = self.call('GET', '/api/portal/certs', None, r)
        if not any(x['name'] == 'v3wait.example.test' for x in mine.get('rows') or []):
            self.must('POST', '/api/portal/cert_request', {
                'names': ['v3wait.example.test'], 'team': 'Web', 'issuer': 'self'}, session=r)
        got = self.page('card', 390, 'cs')
        self.assertIn('podle pravidla jeho týmu', got['note'], got)
        self.assertIn('schvalovatel týmu Web', got['note'], got)
        self.assertNotIn('správce ho schválí', got['note'], got)

    def test_08_change_the_password_page_asks_nothing_refused(self):
        got = self.page('change', 390, 'en')
        self.assertIn('password', got['body'].lower())
        self.assertEqual([b for b in got['bad'] if 'view-as' in b], [], got)


if __name__ == '__main__':
    unittest.main(verbosity=2)
