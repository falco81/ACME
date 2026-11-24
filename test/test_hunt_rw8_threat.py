#!/usr/bin/env python3
"""Hunt 1.0.144, run w8, area threat: a threat-model review (members of the portal, a team's
certificate administrator against another team, a stolen session cookie, a compromised device,
stored XSS through every field a user sets, the root helper from the web user).

What was found and fixed:

- a stolen session cookie: the account's calendar link (POST /api/calendar/feed_link new) is a
  secret that reads the account's certificates for as long as it may sign in. Made from a
  session whose cookie was taken, it outlived everything the owner does about it: a new
  password (own, on the portal, or set by an administrator) and the second step reset ended
  every sign-in, but the link still answered. It is taken back with them now;
- the access reviews' CSV of a team (teams.js reviewCsv): a member's answer note
  "=HYPERLINK(...)" went into the file as it was - a spreadsheet runs it as a formula; it starts
  with a quote now, as in every other CSV acme writes.

    python3 test/test_hunt_rw8_threat.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_certs_core as TCC  # noqa: E402  (the daemon)


class CalendarLink(TCC.CertsCore):
    """A real daemon: the link made, then each way of taking the account back ends it."""

    # the tests of CertsCore itself are not run again here
    locals().update({k: None for k in dir(TCC.CertsCore) if k.startswith('test')})

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.admin = cls.login('tester')

    def feed(self, tok):
        req = urllib.request.Request('http://127.0.0.1:%d/api/calendar/feed' % self.port)
        req.add_header('X-Acme-Token', self.token)
        req.add_header('X-Acme-Calfeed', tok)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def link(self, who):
        sess = self.login(who)
        st, got = self.call('POST', '/api/calendar/feed_link', {'action': 'new'}, sess)
        self.assertEqual(st, 200, got)
        self.assertEqual(self.feed(got['token']), 200)
        return sess, got['token']

    def test_own_password(self):
        sess, tok = self.link('viewer')
        st, got = self.call('POST', '/api/auth/password', {
            'old': self.pw, 'new': 'Another-Password-8812!', 'again': 'Another-Password-8812!'},
            sess)
        self.assertEqual(st, 200, got)
        self.assertEqual(self.feed(tok), 404)
        # back as it was for the others
        st, got = self.call('POST', '/api/users', {'action': 'password', 'name': 'viewer',
                                                   'password': self.pw, 'must_change': 0},
                            self.admin)
        self.assertEqual(st, 200, got)

    def test_password_set_by_an_administrator(self):
        _sess, tok = self.link('certer')
        st, got = self.call('POST', '/api/users', {'action': 'password', 'name': 'certer',
                                                   'password': self.pw, 'must_change': 0},
                            self.admin)
        self.assertEqual(st, 200, got)
        self.assertEqual(self.feed(tok), 404)
        st, got = self.call('GET', '/api/events', None, self.admin, {'q': 'calendar link'})
        self.assertIn('the calendar link of certer was taken back by tester',
                      json.dumps(got))

    def test_second_step_reset(self):
        _sess, tok = self.link('certer')
        st, got = self.call('POST', '/api/users', {'action': 'mfa_reset', 'name': 'certer'},
                            self.admin)
        self.assertEqual(st, 200, got)
        self.assertEqual(self.feed(tok), 404)

    def test_other_changes_keep_it(self):
        # what does not take the account back leaves the link as it was
        _sess, tok = self.link('certer')
        st, got = self.call('POST', '/api/users', {'action': 'contact', 'name': 'certer',
                                                   'mail': 'certer@example.test'}, self.admin)
        self.assertEqual(st, 200, got)
        self.assertEqual(self.feed(tok), 200)
        # ...and another's new password neither
        st, got = self.call('POST', '/api/users', {'action': 'password', 'name': 'viewer',
                                                   'password': self.pw, 'must_change': 0},
                            self.admin)
        self.assertEqual(st, 200, got)
        self.assertEqual(self.feed(tok), 200)


class PortalPassword(unittest.TestCase):
    def test_portal_password_ends_the_link(self):
        with open(os.path.join(ROOT, 'acmelib/engine/390_the_portal_sign_in.py'),
                  encoding='utf-8') as f:
            src = f.read()
        body = src[src.index("def _portal_password(h):"):src.index("def portal_state(h, s):")]
        self.assertIn("account_calendar_end(h.store, acc['name'], by=acc['name'])", body)


class ReviewCsv(unittest.TestCase):
    """teams.js reviewCsv: its cell quoting, run by node."""

    def test_formula_cells(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        with open(os.path.join(ROOT, 'web/assets/teams.js'), encoding='utf-8') as f:
            js = f.read()
        m = re.search(r'function reviewCsv\(team, list\) \{\n\s*(?:/\*.*?\*/\s*)?(var q = function'
                      r' \(v\) \{.*?\};)', js, re.S)
        self.assertTrue(m, 'reviewCsv q not found')
        cells = ['=HYPERLINK("http://x","y")', '+1+1', '-2+3', '@SUM(A1)', 'ok', '-', '-5',
                 '2026-11-24 10:00', 'a,b', '\tx']
        code = m.group(1) + '\nconsole.log(JSON.stringify(%s.map(q)));' % json.dumps(cells)
        got = subprocess.run([node, '-e', code], capture_output=True, text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr)
        out = json.loads(got.stdout)
        self.assertEqual(out, ['"\'=HYPERLINK(""http://x"",""y"")"', "'+1+1", "'-2+3",
                               "'@SUM(A1)", 'ok', '-', '-5', '2026-11-24 10:00', '"a,b"', "'\tx"])


if __name__ == '__main__':
    unittest.main(verbosity=2)
