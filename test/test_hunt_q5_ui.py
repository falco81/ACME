#!/usr/bin/env python3
"""Bug hunt q5, the pages' last leftovers (1.0.119).

    python3 test/test_hunt_q5_ui.py

- Settings -> Time ("Its time") and the Backups summary ("Next") in the browser's own format -
  now dd-mm-yyyy hh:mm:ss as every other time.
- Message texts saved on a single node: "both nodes send these words now" - said only in HA.
- High security: a rule made an exception left "not allowed" on the settings shown on other
  panes until a reload.
- The caps of the directories' passwords: a directory gone while a change to its cap waited
  threw (saved[k] undefined).
- At 375 px: SSH server's "Root signs in" past its frame (x=411), an account's buttons in
  three lines, a source's window with its words a column a word wide, "default" broken in two.
- acme --renew all said nothing (and ended 0) when every one due waited for its approval;
  --export NAME --format bogus said "needs --out" instead of naming the format.

The command line on a state of its own; the pages through a real daemon
(test/test_certs_core.py's way) and php -S, in Chromium (test/hunt_q5_ui_page.js) when node,
php and Playwright are here.
"""
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


# ---------------------------------------------------------------------------
class TheSources(unittest.TestCase):
    """What the pages are made of, read as text."""

    def test_no_browser_format_in_time_and_backups(self):
        js = read('web/assets/admin.js')
        at = js.index('function drawNtp(')
        ntp = js[at:js.index('\nfunction ', at + 10)]
        self.assertNotIn('toLocaleString', ntp)
        self.assertIn('stamp(dt.getTime() / 1000)', ntp)
        at = js.index('function drawRbTop(')
        top = js[at:js.index('\nfunction ', at + 10)]
        self.assertNotIn('toLocale', top)

    def test_hisec_dress_by_its_rule(self):
        js = read('web/assets/admin.js')
        self.assertIn("if (!r || !hsOn(s.key)) return;", js)
        self.assertIn('hsSettingsAgain();', js)

    def test_phone_css(self):
        css = read('web/assets/acme.css')
        self.assertRegex(css, r'@media \(max-width:560px\)\{\s*\.seg\{flex-wrap:wrap;max-width:100%\}')
        self.assertIn('#us-table td.rowtools { min-width: 9.5em; white-space: nowrap; }', css)
        certs = read('web/assets/certs.css')
        self.assertIn('.ct-plughead-guide{margin-left:62px}', certs)
        self.assertIn('.ct-default-note > .tag{flex:none;white-space:nowrap}', certs)


# ---------------------------------------------------------------------------
class TextsSaved(unittest.TestCase):
    """The toast after a save of message texts: "both nodes" in a pair only."""

    def said(self, ha_mode):
        from acmelib import engine as E
        fn = E._texts_do

        class Store:
            def add_event(self, *a, **k):
                pass

        class H:
            store = Store()

            def body(self):
                return {'action': 'save', 'id': 'verify_mail', 'lang': 'en', 'fields': {}}

            def me(self, *a):
                return {'name': 'q5'}
        was = dict(E.CONFIG)
        saved = E.text_save
        state = E.text_state
        try:
            E.CONFIG['ha_mode'] = ha_mode
            E.text_save = lambda *a, **k: {}
            E.text_state = lambda *a, **k: ({}, None)
            fn.__globals__['text_save'] = E.text_save
            fn.__globals__['text_state'] = E.text_state
            return fn(H())['message']
        finally:
            E.CONFIG.clear()
            E.CONFIG.update(was)
            fn.__globals__['text_save'] = saved
            fn.__globals__['text_state'] = state

    def test_single_node(self):
        self.assertEqual(self.said(''), 'saved')

    def test_pair(self):
        for mode in ('replicated', 'shared'):
            self.assertEqual(self.said(mode), 'saved - both nodes send these words now')


# ---------------------------------------------------------------------------
class CommandLine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-q5ui-')
        with open(os.path.join(cls.tmp, 'config.json'), 'w') as f:
            f.write('{}')
        cls.env = dict(os.environ, ACME_STAY_ROOT='1',
                       ACME_CONFIG=os.path.join(cls.tmp, 'config.json'), ACME_STATE=cls.tmp,
                       ACME_RUN=cls.tmp, ACME_LOGDIR=cls.tmp, NO_COLOR='1',
                       ACME_CONSOLE_FLAG=os.path.join(cls.tmp, 'console-flag'))
        got = cls.run_('--selfsigned', 'q5web', '--names', 'q5.example.test')
        assert got.returncode == 0, got.stdout + got.stderr

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def run_(cls, *args):
        return subprocess.run(ACME + list(args), env=cls.env, capture_output=True, text=True,
                              timeout=120)

    def test_export_bad_format_named(self):
        got = self.run_('--export', 'q5web', '--format', 'bogus')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('--format bogus is not a format of --export', got.stderr + got.stdout)
        self.assertNotIn('needs --out', got.stderr + got.stdout)
        # a format there without --out: as before
        got = self.run_('--export', 'q5web', '--format', 'cert-pem')
        self.assertIn('needs --out', got.stderr + got.stdout)

    def test_renew_all_every_one_waiting(self):
        db = sqlite3.connect(os.path.join(self.tmp, 'acme.db'))
        issuers = [r[0] for r in db.execute("SELECT name FROM cert_issuers WHERE kind = 'acme' "
                                            "ORDER BY id")]
        db.close()
        self.assertTrue(issuers)
        got = self.run_('--cert-add', 'q5wait', '--names', 'wait.example.com',
                        '--issuer', issuers[0])
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        db = sqlite3.connect(os.path.join(self.tmp, 'acme.db'))
        # asked for on the portal, never approved (its state is not pending-approval: due)
        db.execute("UPDATE certs SET created_by = 'portal:q5' WHERE name = 'q5wait'")
        cid = db.execute("SELECT id FROM certs WHERE name = 'q5wait'").fetchone()[0]
        db.execute("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)",
                   ('certs:portal:%d' % cid, json.dumps({'waits': 1})))
        # the self-signed one is not due - kept out all the same
        db.execute("UPDATE certs SET enabled = 0 WHERE name <> 'q5wait'")
        db.commit()
        db.close()
        got = self.run_('--renew', 'all')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('q5wait was never approved', got.stdout)
        self.assertIn('--approve q5wait', got.stdout)
        self.assertIn('nothing renewed: every one due waits for its approval', got.stdout)
        got = self.run_('--renew', 'all', '--json')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        d = json.loads(got.stdout)
        self.assertEqual(d['jobs'], [])
        self.assertEqual([w['cert'] for w in d['waiting']], ['q5wait'])


# ---------------------------------------------------------------------------
class ThePages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            raise unittest.SkipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode != 0:
            raise unittest.SkipTest('no playwright for node here')
        import test_certs_core as TCC
        cls.TCC = TCC
        cls.call = TCC.CertsCore.__dict__['call']
        cls.login = TCC.CertsCore.__dict__['login']
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.TCC.CertsCore.tearDownClass.__func__(cls)

    def test_texts_saved_single_node(self):
        st, got = self.call('POST', '/api/texts', {'action': 'save', 'id': 'verify_mail',
                                                   'lang': 'en', 'fields': {}}, self.admin)
        self.assertEqual(st, 200, got)
        self.assertEqual(got['message'], 'saved')

    def test_the_pages(self):
        TCC = self.TCC
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            got = subprocess.run([shutil.which('node'), os.path.join(HERE, 'hunt_q5_ui_page.js'),
                                  'http://127.0.0.1:%d' % port, 'tester', self.pw],
                                 capture_output=True, text=True, timeout=400, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        # the times: dd-mm-yyyy hh:mm:ss
        self.assertEqual(seen['next'], '18-11-2026 04:15:00', seen)
        self.assertRegex(seen['clock']['shown'], r'^\d\d-\d\d-\d{4} \d\d:\d\d:\d\d$')
        self.assertEqual(seen['clock']['shown'], seen['clock']['want'])
        # high security: the note gone with the exception, without a reload
        h = seen['hisec']
        self.assertTrue(h['before'] and h['lockedBefore'], h)
        self.assertFalse(h['after'] or h['lockedAfter'] or h['freshNote'], h)
        # the caps: no throw, the gone one let go
        self.assertEqual(seen['dp'], {'threw': '', 'keys': ['q5-a'], 'pending': False,
                                      'pendingChanged': True})
        # a phone
        self.assertTrue(seen['seg'], seen)
        for s in seen['seg']:
            self.assertLessEqual(s['most'], s['right'] + 1, seen['seg'])
        self.assertLessEqual(seen['phoneWide'], 375)
        self.assertLess(seen['accountRow'], 100, seen)
        self.assertGreater(seen['plughead'], 150, seen)
        self.assertLess(seen['defaultTag'], 26, seen)
        self.assertEqual(seen['cvPad'], '24px')


if __name__ == '__main__':
    unittest.main(verbosity=2)
