#!/usr/bin/env python3
"""Bug hunt R run t7: request profiles and their approval.

    python3 test/test_hunt_rt7_profiles.py

In one process, as test/test_req_profiles.py (whose helpers it uses):

- A request declined answered "<owner> is told" whatever happened: the person who asked
  had no e-mail address, or mail was switched off - nobody was told. And it named the owner
  (a team), not the person who asked, who is the one a mail goes to. Now it says who is told,
  or why nobody is.
- A waiting request said "You are told by mail when they have" to a person with no e-mail
  address (or with mail switched off): the portal is now told whether a mail goes
  (told_by_mail, of the person signed in and of each waiting request) and says so.
- The portal: a certificate opened from the team workspace's overview left only its row
  behind, and "Ask for a certificate" then offered the free form with no domains and no
  source, and none of the request profiles (node, when it is here).
"""
import json
import os
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_req_profiles as TR       # noqa: E402  (its store, helpers and set-up)
from test_req_profiles import E, P, R, S, STORE, portal, person, base_profile, setup  # noqa: E402

NOMAIL = person('karel', groups=[(TR.WEB_DN, 'WEB_ADMINS')], mail='')
WITHMAIL = person('eva', groups=[(TR.WEB_DN, 'WEB_ADMINS')], mail='eva@corp.test')


class Told(unittest.TestCase):
    def setUp(self):
        setup()
        R.save_profile(STORE, base_profile(name='Waits', teams=[], owner='person', approval=True,
                                           csr=False, tags=[]), 'x')
        R.save_profile(STORE, base_profile(name='Team waits', approval=True, csr=False,
                                           tags=[]), 'x')
        self.told = []
        self._tell = P.tell
        P.tell = lambda store, cid, what, why='': self.told.append((cid, what))

    def tearDown(self):
        P.tell = self._tell
        E.CONFIG['mail_mode'] = 'off'

    def ask(self, who, n, profile='Waits', **more):
        got = portal(who, 'POST', '/api/portal/cert_request',
                     dict({'profile': profile, 'names': ['%s.example.test' % n]}, **more))
        self.assertTrue(got['waits'], got)
        return S.cert_get(STORE, got['id'])

    def decline(self, row):
        return P.approve_request(STORE, row, 'boss', False, 'not now')

    def test_declined_says_who_is_told(self):
        E.CONFIG['mail_mode'] = 'off'
        # no address of theirs: nobody is told (it said "karel is told")
        got = self.decline(self.ask(NOMAIL, 'a'))
        self.assertEqual(got['message'], 'a.example.test declined - karel is not told by mail: '
                                         'no e-mail address of theirs is known')
        self.assertIs(got['told'], False)
        # an address, mail switched off: nobody is told either
        got = self.decline(self.ask(WITHMAIL, 'b'))
        self.assertEqual(got['message'], 'b.example.test declined - eva is not told by mail: '
                                         'sending mail is switched off')
        self.assertIs(got['told'], False)
        # mail on: told - the person who asked, not the team that owns it
        E.CONFIG['mail_mode'] = 'smtp'
        row = self.ask(WITHMAIL, 'c', profile='Team waits', team='Web')
        self.assertEqual(row['owner'], 'Web')
        got = self.decline(row)
        self.assertEqual(got['message'], 'c.example.test declined - eva is told')
        self.assertIs(got['told'], True)
        # the mail is still asked for every time (tell decides, as before)
        self.assertEqual([w for _c, w in self.told], ['declined'] * 3)
        # a request nobody is known to have asked for: nobody
        row = self.ask(WITHMAIL, 'd')
        STORE.db.run('DELETE FROM meta WHERE k = ?', (P.META + str(row['id']),))
        STORE.db.update('certs', row['id'], {'owner': ''})
        got = self.decline(S.cert_get(STORE, row['id']))
        self.assertEqual(got['message'], 'd.example.test declined - nobody is told')

    def test_portal_says_whether_a_mail_goes(self):
        E.CONFIG['mail_mode'] = 'off'
        self.ask(NOMAIL, 'w1')
        mine = portal(NOMAIL, 'GET', '/api/portal/certs')
        self.assertIs(mine['told_by_mail'], False)
        self.assertIs(mine['rows'][0]['told_by_mail'], False)
        self.assertIs(portal(WITHMAIL, 'GET', '/api/portal/certs')['told_by_mail'], False)
        E.CONFIG['mail_mode'] = 'smtp'
        self.assertIs(portal(NOMAIL, 'GET', '/api/portal/certs')['told_by_mail'], False)
        self.assertIs(portal(NOMAIL, 'GET', '/api/portal/certs')['rows'][0]['told_by_mail'],
                      False)
        self.assertIs(portal(WITHMAIL, 'GET', '/api/portal/certs')['told_by_mail'], True)
        self.ask(WITHMAIL, 'w2')
        rows = {r['name']: r for r in portal(WITHMAIL, 'GET', '/api/portal/certs')['rows']}
        self.assertIs(rows['w2.example.test']['told_by_mail'], True)


# What the portal's page says, without a browser: the texts chosen by told_by_mail.
PAGE_JS = r'''
const fs = require('fs'), vm = require('vm');
const src = fs.readFileSync(process.argv[1], 'utf8');
const calls = [];
const sandbox = {console, Promise, JSON, Object, Array, String, Number, Math, Date, setTimeout,
                 clearTimeout};
sandbox.window = sandbox;
sandbox.apiLatest = function (key, what) {
  calls.push(what);
  return Promise.resolve({rows: [{id: 7, name: 'fetched'}], profiles: [{name: 'P1'}, {name: 'P2'}],
                          free_form: true});
};
sandbox.oops = function (e) { calls.push('oops ' + e); };
sandbox.modal = function (title) { calls.push('modal ' + title); };
vm.createContext(sandbox);
vm.runInContext(src, sandbox);
const PC = sandbox.ACME_PORTAL_CERTS;
// a certificate opened from the overview first: only its row is known
try { PC.openRow({id: 3, name: 'opened'}); } catch (e) { /* its dialog needs the page */ }
try { PC.askStart(); } catch (e) { calls.push('threw ' + e); }
setTimeout(function () {
  const d = PC.data() || {};
  console.log(JSON.stringify({calls: calls, profiles: (d.profiles || []).map(p => p.name),
                              rows: (d.rows || []).map(r => r.id)}));
}, 50);
'''


class PortalPage(unittest.TestCase):
    def test_ask_after_a_certificate_opened_from_the_overview(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        got = subprocess.run([node, '-e', PAGE_JS, os.path.join(ROOT, 'web/assets/certs-portal.js')],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        seen = json.loads(got.stdout.strip().splitlines()[-1])
        # the list's answer fetched (it was not: the free form, no domains, no profiles)
        self.assertIn('certs&per=1', seen['calls'], seen)
        self.assertEqual(seen['profiles'], ['P1', 'P2'], seen)
        # the row opened kept beside the fetched ones
        self.assertEqual(sorted(seen['rows']), [3, 7], seen)

    def test_the_texts_follow_told_by_mail(self):
        with open(os.path.join(ROOT, 'web/assets/certs-portal.js'), encoding='utf-8') as f:
            js = f.read()
        for words in ('Look here to see when they have - no mail is sent to you.',
                      'They see what you decide here - no mail is sent to them.',
                      'The person who asked sees why here, on the portal - no mail is sent to them.'):
            self.assertIn(words, js)
        self.assertIn('told_by_mail === false', js)


if __name__ == '__main__':
    unittest.main(verbosity=2)
