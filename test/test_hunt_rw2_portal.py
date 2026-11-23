#!/usr/bin/env python3
"""Bug hunt w2, the certificate portal for ordinary users.

    python3 test/test_hunt_rw2_portal.py

A real daemon in a folder of its own (test/test_certs_core.py's way); the pages from a copy of
web/ (with this hunt's Czech merged in) through php -S, in Chromium (node + Playwright), when
they are here.

- The portal's calendar said acme renews a certificate on the default's day: the page's row it
  was read from has no renew days, no ARI window and no switch - one with renew days of its own
  was shown 25 days early, one switched off with a renewal that never comes.
- A request of a team that wants two approvers, approved by one of them: its row still said
  may_approve - the dialog offered Approve again (refused "approved already"), and the first
  click's toast said "approved" while it waited for another approver.
- A certificate of a team whose limits keep the keys in (key_download false) offered the PFX
  with the key: its password typed, the download was refused.
- "Ask for a certificate" in the team workspace, another team chosen in the form: the names were
  checked against the first team's suffixes (a name of the chosen team refused before it was
  sent), and its limits and its rule were the first team's.
- The teams' actions waiting for an approval (approve_actions: revoke, delete, key, device) had
  no command-line or console form: acme --team-actions, --team-action-approve/-decline.
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

CS_EXTRA = ['/tmp/claude-0/-home-user-ACME/845070b5-9900-5dee-8b93-2de7397138a5/scratchpad/'
            'hunt140/cs_rw2_portal.json']

NODE = r"""
const { chromium } = require('playwright');
(async () => {
  const [base, pass, flow, width, lang, shots] = process.argv.slice(1);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: Number(width), height: 900}, deviceScaleFactor: 1});
  await ctx.addCookies([{name: 'acme_lang', value: lang || 'en', url: base}]);
  const page = await ctx.newPage();
  const out = {errors: [], bad: [], posts: []};
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  page.on('response', r => { if (r.status() >= 400) out.bad.push(r.status() + ' ' + r.url()); });
  page.on('request', r => { if (r.method() === 'POST' && /api=cert-/.test(r.url())) out.posts.push(r.url().replace(/^.*api=/, '') + ' ' + (r.postData() || '')); });
  const pause = ms => page.waitForTimeout(ms);
  const user = {ask: 'wreq', approve: 'wap1'}[flow];
  try {
    await page.goto(base + '/');
    await page.fill('#in-name', user);
    await page.fill('#in-pass', pass);
    await page.click('#in-go');
    await page.waitForSelector('#signout', {timeout: 20000});
    await pause(2000);
    if (flow === 'ask') {
      await page.evaluate(() => { location.hash = '#certs/*'; });
      await pause(2500);
      await page.click('#pw-ask-c');
      await pause(1500);
      out.first = await page.$eval('#cp-team', s => s.value);
      out.other = await page.evaluate(() => {
        const s = document.getElementById('cp-team');
        const o = [...s.options].find(x => !x.selected);
        s.value = o.value;
        s.dispatchEvent(new Event('change'));
        return o.value;
      });
      await pause(800);
      out.limits = await page.$eval('#modal .pw-note', n => n.innerText);
      out.hint = await page.$eval('#modal .says b.mono', n => n.textContent);
      const name = 'w2ask.' + (out.other === 'WTwo' ? 'two' : 'web') + '.example.test';
      await page.fill('#modal textarea.cp-names', name);
      await pause(300);
      out.chips = await page.$$eval('#modal .cp-chips .ct-name.refused', x => x.length);
      if (shots) await page.screenshot({path: shots + '/rw2-ask-' + lang + '-' + width + '.png'});
      await page.locator('#modal button.primary').last().click();
      await pause(2500);
      out.said = await page.evaluate(() => { const s = document.querySelector('#modal .said'); return s ? s.textContent : null; });
    } else if (flow === 'approve') {
      await page.evaluate(() => { location.hash = '#certs/WTwo'; });
      await pause(2500);
      await page.locator('#pw-main tbody tr', {hasText: 'w2dlg.two.example.test'}).first().click();
      await pause(1500);
      await page.locator('#modal button.primary', {hasText: lang === 'cs' ? 'Schválit' : 'Approve'}).click();
      await pause(1500);
      out.toast = await page.evaluate(() => [...document.querySelectorAll('.toast, #toast, .toasts > *')].map(t => t.textContent).join(' | '));
      out.open = await page.evaluate(() => !document.getElementById('modal').hidden);
      await page.locator('#pw-main tbody tr', {hasText: 'w2dlg.two.example.test'}).first().click();
      await pause(1500);
      out.approve = await page.evaluate(() => { const b = [...document.querySelectorAll('#modal button')].find(x => /Approve|Schválit/.test(x.textContent)); return b ? (b.disabled ? 'off' : 'on') : 'none'; });
      out.note = await page.evaluate(() => [...document.querySelectorAll('#modal .cp-note')].map(n => n.innerText).join(' | '));
    }
  } catch (e) { out.error = String(e && e.stack || e); }
  await browser.close();
  console.log(JSON.stringify(out));
})();
"""


class HuntRw2Portal(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    py = TCC.CertsCore.__dict__['py']
    cli = TCC.CertsCore.__dict__['cli']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.php = None
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 100,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self',
            'portal_cert_keys': 1, 'portal_cert_max': 1000, 'mail_mode': 'off'}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 90}})
        for name in ('wreq', 'wown', 'wap1', 'wap2'):
            cls.must('POST', '/api/users', {'action': 'add', 'name': name, 'role': 'readonly',
                                            'password': cls.pw, 'must_change': 0})
        rule1 = {'mode': 'always', 'approvers': 'team', 'count': 1}
        cls.must('POST', '/api/teams/save', {
            'name': 'WWeb', 'members': [
                {'who': 'local:wreq', 'roles': ['Requester']},
                {'who': 'local:wown', 'roles': ['Team owner']},
                {'who': 'local:wap1', 'roles': ['Approver']}],
            'policy': {'suffixes': ['web.example.test'], 'approval': rule1,
                       'approve_actions': ['delete']}})
        cls.must('POST', '/api/teams/save', {
            'name': 'WTwo', 'members': [
                {'who': 'local:wreq', 'roles': ['Requester']},
                {'who': 'local:wap1', 'roles': ['Approver']},
                {'who': 'local:wap2', 'roles': ['Approver']}],
            'policy': {'suffixes': ['two.example.test'],
                       'approval': {'mode': 'always', 'approvers': 'team', 'count': 2}}})

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

    def issued(self, name, team, who='wreq'):
        """A certificate of `team` asked for on the portal, approved by an administrator and
        issued -> its id."""
        st, mine = self.call('GET', '/api/portal/certs', None, self.portal(who))
        have = [r for r in mine.get('rows') or [] if r['cn'] == name]
        if have:
            return have[0]['id']
        got = self.must('POST', '/api/portal/cert_request', {
            'names': [name], 'team': team, 'issuer': 'self'}, session=self.portal(who))
        self.must('POST', '/api/certs/approve', {'id': got['id'], 'ok': 1})
        end = time.time() + 90
        while time.time() < end:
            st, one = self.call('GET', '/api/certs/one?id=%d' % got['id'], None, self.admin)
            if (one.get('cert') or {}).get('not_after'):
                return got['id']
            time.sleep(0.5)
        self.fail('%s was not issued' % name)

    def team_policy(self, team, **changes):
        t = [x for x in self.must('GET', '/api/teams')['teams'] if x['name'] == team][0]
        pol = dict(t['policy'] or {})
        pol.update(changes)
        self.must('POST', '/api/teams/save', {'old_name': team, 'name': team,
                                              'members': t['members'], 'policy': pol})

    # ---- the calendar --------------------------------------------------------------------
    def test_01_calendar_renews_as_the_certificate_says(self):
        cid = self.issued('w2cal.web.example.test', 'WWeb')
        self.py('st.db.update("certs", %d, {"renew_days": 5})\nprint(1)' % cid)
        admin = {e['id']: e for e in self.must('GET', '/api/calendar')['certs']}
        mine = {e['id']: e for e in self.must('GET', '/api/portal/calendar',
                                              session=self.portal('wown'))['certs']}
        self.assertTrue(admin[cid]['renew_at'])
        # the default's day (30 days before the end) before: 25 days early
        self.assertEqual(mine[cid]['renew_at'], admin[cid]['renew_at'])
        self.assertAlmostEqual(mine[cid]['not_after'] - mine[cid]['renew_at'], 5 * 86400,
                               delta=60)
        ics = self.must('GET', '/api/portal/calendar_ics', session=self.portal('wown'))['text']
        day = time.strftime('%Y%m%d', time.localtime(admin[cid]['renew_at']))
        self.assertIn('DTSTART;VALUE=DATE:' + day, ics)
        # switched off: no renewal is planned
        self.py('st.db.update("certs", %d, {"enabled": 0})\nprint(1)' % cid)
        try:
            mine = {e['id']: e for e in self.must('GET', '/api/portal/calendar',
                                                  session=self.portal('wown'))['certs']}
            self.assertIsNone(mine[cid]['renew_at'], mine[cid])
        finally:
            self.py('st.db.update("certs", %d, {"enabled": 1})\nprint(1)' % cid)

    # ---- two approvers -------------------------------------------------------------------
    def two_waiting(self):
        st, mine = self.call('GET', '/api/portal/certs', None, self.portal('wreq'))
        have = [r for r in mine.get('rows') or [] if r['cn'] == 'w2two.two.example.test'
                and r['state'] == 'pending-approval']
        if have:
            return have[0]['id']
        return self.must('POST', '/api/portal/cert_request', {
            'names': ['w2two.two.example.test'], 'team': 'WTwo', 'issuer': 'self'},
            session=self.portal('wreq'))['id']

    def row(self, who, cid):
        rows = self.must('GET', '/api/portal/certs', session=self.portal(who))['rows']
        return [r for r in rows if r['id'] == cid][0]

    def test_02_approved_once_of_two_is_not_offered_again(self):
        cid = self.two_waiting()
        self.assertTrue(self.row('wap1', cid)['may_approve'])
        got = self.must('POST', '/api/portal/cert_approve', {'id': cid, 'ok': 1},
                        session=self.portal('wap1'))
        self.assertTrue(got.get('recorded'), got)
        one = self.row('wap1', cid)
        self.assertFalse(one['may_approve'], one)                  # True before - then a 409
        self.assertIn('approved it already', one['approve_why'])
        self.assertTrue(self.row('wap2', cid)['may_approve'])      # the other approver may
        st, again = self.call('POST', '/api/portal/cert_approve', {'id': cid, 'ok': 1},
                              self.portal('wap1'))
        self.assertEqual(st, 409, again)

    # ---- a team that keeps the keys in ----------------------------------------------------
    def test_03_no_pfx_offered_where_the_team_keeps_keys_in(self):
        cid = self.issued('w2key.web.example.test', 'WWeb')
        self.assertIn('pfx', self.row('wown', cid)['formats'])
        self.team_policy('WWeb', key_download=False)
        try:
            one = self.row('wown', cid)
            self.assertNotIn('pfx', one['formats'])                # offered, then refused
            self.assertIn('fullchain-pem', one['formats'])
            st, got = self.call('POST', '/api/portal/cert_download', {
                'id': cid, 'format': 'pfx', 'password': 'Long-enough-1'}, self.portal('wown'))
            self.assertEqual(st, 403, got)
        finally:
            self.team_policy('WWeb', key_download=True)
        self.assertIn('pfx', self.row('wown', cid)['formats'])

    # ---- the teams' actions on the command line ---------------------------------------------
    def test_04_team_actions_on_the_command_line(self):
        cid = self.issued('w2act.web.example.test', 'WWeb')
        got = self.must('POST', '/api/portal/cert_delete', {'id': cid},
                        session=self.portal('wown'))
        self.assertTrue(got.get('waits'), got)
        aid = got['action']['id']
        out = self.cli('--team-actions', '--json')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        rows = {r['id']: r for r in json.loads(out.stdout)['actions']}
        self.assertEqual(rows[aid]['action'], 'delete')
        self.assertEqual(rows[aid]['what'], 'w2act.web.example.test')
        self.assertTrue(rows[aid]['may_approve'])
        out = self.cli('--team-actions', 'WWeb')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('w2act.web.example.test', out.stdout)
        # declined without a word: refused, nothing done
        out = self.cli('--team-action-decline', aid)
        self.assertNotEqual(out.returncode, 0, out.stdout)
        # approved: deleted, as the portal's approver would have it
        out = self.cli('--team-action-approve', aid, '--why', 'ok by the admin')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('deleted', out.stdout)
        st, one = self.call('GET', '/api/certs/one?id=%d' % cid, None, self.admin)
        self.assertEqual(st, 404, one)
        out = self.cli('--team-action-approve', aid)
        self.assertNotEqual(out.returncode, 0, out.stdout)          # once
        # a read-only account of the administration may not decide
        st, got = self.call('POST', '/api/teams/action_decide', {'id': aid, 'ok': 1}, self.ro)
        self.assertEqual(st, 403, got)
        # the console's line for them
        from acmelib.certs import cli_138

        class Con(object):
            pass
        keys = [x[0] for x in cli_138.gov_menu_items(Con())]
        self.assertIn('a', keys)
        self.assertEqual(len(keys), len(set(keys)))

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
        got = subprocess.run([node, '-e', NODE, '--', self.base, self.pw, flow, str(width), lang,
                              os.environ.get('ACME_TEST_SHOTS', '')],
                             capture_output=True, text=True, timeout=300, cwd=ROOT)
        lines = [x for x in (got.stdout or '').splitlines() if x.startswith('{')]
        self.assertTrue(lines, (got.stdout or '')[-2000:] + (got.stderr or '')[-2000:])
        out = json.loads(lines[-1])
        self.assertNotIn('error', out, out.get('error'))
        self.assertEqual(out['errors'], [], out)
        return out

    def test_05_ask_for_another_team_of_the_form(self):
        for lang, width in (('cs', 390), ('en', 1400)):
            got = self.page('ask', width, lang)
            self.assertNotEqual(got['first'], got['other'], got)
            # the chosen team's limits and names - the first one's before
            self.assertIn(got['other'], got['limits'], got)
            self.assertEqual(got['hint'], 'two.example.test' if got['other'] == 'WTwo'
                             else 'web.example.test', got)
            self.assertEqual(got['chips'], 0, got)                 # its name not refused
            sent = [p for p in got['posts'] if p.startswith('cert-request')]
            self.assertEqual(len(sent), 1, got)                    # none before: refused here
            self.assertIn('"team":"%s"' % got['other'], sent[0])
            self.assertIn('w2ask.', sent[0])

    def test_06_approve_of_two_in_the_dialog(self):
        cid = self.must('POST', '/api/portal/cert_request', {
            'names': ['w2dlg.two.example.test'], 'team': 'WTwo', 'issuer': 'self'},
            session=self.portal('wreq'))['id']
        got = self.page('approve', 390, 'cs')
        self.assertIn('čeká se ještě na', got['toast'], got)       # "approved" before
        self.assertFalse(got['open'], got)
        self.assertEqual(got['approve'], 'off', got)               # offered again before
        self.assertIn('už jste to schválili', got['note'], got)
        self.assertFalse(self.row('wap1', cid)['may_approve'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
