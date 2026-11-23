#!/usr/bin/env python3
"""Bug hunt 1.0.143, run w5, area sign-in: regressions.

    python3 test/test_hunt_rw5_signin.py

- A password set for an account of the directory (Accounts' API, acme --passwd): it was never
  asked - the directory's is - and the API's "to change at sign-in" refused the person every
  page with "change the password first", which a directory account cannot do here. Refused
  now; a mark left from before no longer holds the person up.
- The idle sign-out of the pages counted each tab's own use: a tab left open behind signed out
  the one being worked in. The last use is shared by the tabs of the browser now.
- Who is signed in (Settings - Accounts - Signed in now) had no command line and no place in
  the console: acme --sessions, acme --session-end ID|NAME, Accounts - Who is signed in now.
"""
import collections
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-rw5-signin-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))
os.environ.update({k: v for k, v in ENV.items() if k.startswith('ACME_')})
import acme as E  # noqa: E402
from acmelib import engine as EN  # noqa: E402

STORE = E.Storage(E.open_db())
EN.HA_STORE['store'] = STORE
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
PW = 'Very-long-pass-123'


def run(*args, env=None):
    return subprocess.run(ACME + [str(a) for a in args], env=dict(ENV, **(env or {})),
                          capture_output=True, text=True, timeout=240)


class D(object):
    def __init__(self):
        self.login_fails = collections.defaultdict(list)
        self.login_info = {}
        self.store = STORE
        self.dirs = {}


def handler(body=None, token='', path=''):
    h = E.ApiHandler.__new__(E.ApiHandler)
    h.server = type('S', (), {'daemon': D()})()
    h.headers = {'X-Acme-Session': token} if token else {}
    h.client_address = ('192.0.2.5', 1)
    h._body = dict(body or {})
    h._held = None
    h._failed = False
    h._guard = None
    h.route_path = path
    return h


def call(method, path, body=None, token=''):
    h = handler(body, token, path)
    try:
        return E.ROUTES[(method, path)](h)
    finally:
        h._release()


def account(name, **kw):
    if not STORE.account(name):
        if kw.get('source') == 'directory':
            STORE.add_account(name, kw.get('role', 'readonly'), None, source='directory',
                              dn='CN=%s,OU=People,DC=corp,DC=loc' % name)
        else:
            STORE.add_account(name, kw.get('role', 'readonly'), PW)
    return STORE.account(name)


class DirectoryPassword(unittest.TestCase):
    def setUp(self):
        account('boss', role='fulladmin')
        account('jnovak', source='directory')
        STORE.set_account('jnovak', must_change=0)
        # the directory asked about again in ten minutes, not now (no directory here)
        E.ApiHandler.DIR_CHECKED['jnovak'] = time.time()
        self.boss = STORE.session_new('admin', 'boss', 'fulladmin', '192.0.2.5', 12)

    def test_refused_on_the_pages(self):
        with self.assertRaises(E.ApiError) as e:
            call('POST', '/api/users', {'action': 'password', 'name': 'jnovak',
                                        'password': PW, 'again': PW, 'must_change': 1},
                 self.boss)
        self.assertEqual(e.exception.status, 400)
        self.assertIn("is the directory's", str(e.exception))
        acc = STORE.account('jnovak')
        self.assertFalse(acc.get('pw'))
        self.assertFalse(acc.get('must_change'))
        # an account of acme's own still gets one
        account('local1')
        got = call('POST', '/api/users', {'action': 'password', 'name': 'local1',
                                          'password': PW + 'x', 'again': PW + 'x'}, self.boss)
        self.assertEqual(got['message'], 'the password is set')
        self.assertTrue(STORE.account('local1')['must_change'])

    def test_a_mark_left_holds_nobody_up(self):
        # written before this fix: the person could open nothing
        STORE.set_account('jnovak', must_change=1)
        tok = STORE.session_new('admin', 'jnovak', 'readonly', '192.0.2.5', 12)
        got = call('GET', '/api/auth/whoami', token=tok)
        self.assertFalse(got['who']['must_change'])
        h = handler(token=tok, path='/api/events')
        self.assertEqual(h.me()['name'], 'jnovak')
        # an account of acme's own is still held to it
        account('local2')
        STORE.set_account('local2', must_change=1)
        tok2 = STORE.session_new('admin', 'local2', 'readonly', '192.0.2.5', 12)
        with self.assertRaises(E.ApiError) as e:
            handler(token=tok2, path='/api/events').me()
        self.assertEqual(e.exception.status, 403)

    def test_refused_on_the_command_line(self):
        got = run('--passwd', 'jnovak', env={'ACME_PASSWORD': PW})
        self.assertEqual(got.returncode, 1, got.stdout + got.stderr)
        self.assertIn("is the directory's", got.stderr)
        self.assertFalse(STORE.account('jnovak').get('pw'))
        account('local3')
        got = run('--passwd', 'local3', env={'ACME_PASSWORD': PW + 'y'})
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)


class Sessions(unittest.TestCase):
    def test_list_and_end(self):
        account('anna')
        tok = STORE.session_new('admin', 'anna', 'readonly', '198.51.100.4', 12)
        STORE.session_new('admin', 'anna', 'readonly', '198.51.100.5', 12)
        got = run('--sessions', '--json')
        self.assertEqual(got.returncode, 0, got.stderr)
        rows = [r for r in json.loads(got.stdout)['sessions'] if r['name'] == 'anna']
        self.assertEqual(len(rows), 2)
        self.assertNotIn('token', got.stdout)
        self.assertNotIn(tok, got.stdout)
        words = run('--sessions')
        self.assertIn('198.51.100.4', words.stdout)
        one = [r for r in rows if r['ip'] == '198.51.100.4'][0]
        got = run('--session-end', one['id'])
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIsNone(STORE.session_get(tok, 'admin', 3600))
        self.assertEqual(run('--session-end', one['id']).returncode, 1)
        # every sign-in of a name
        got = run('--session-end', 'ANNA', '--json')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(len(json.loads(got.stdout)['ended']), 1)
        self.assertFalse([r for r in STORE.sessions() if r['name'] == 'anna'])
        ev = STORE.db.rows("SELECT words FROM events WHERE words LIKE '%ended the sign-in of anna%'")
        self.assertTrue(ev)
        self.assertNotIn('Traceback', run('--session-end', 'nobody').stderr)

    def test_console(self):
        from acmelib import engine as EN2

        class C(EN2.Console):
            def __init__(self):
                EN2.Console.__init__(self, EN2.Palette(False))
                self.acts, self.picked, self.items = [], None, None

            def out(self, *args):
                got = run(*(list(args) + ['--json']))
                return json.loads(got.stdout or 'null')

            def act(self, *args, env=None, **kw):
                got = run(*args, env=env)
                self.acts.append((args, got.returncode))
                return got.returncode

            def sub(self, title, items):
                self.items = items

            def pick(self, title, load, cols, act=None, empty='', words=''):
                rows = load()
                for r in rows:
                    for c in cols:
                        c[1](r)
                self.picked = rows
                if rows and act:
                    act(rows[0])
                return rows

            def confirm(self, *a, **k):
                return True

        account('petra')
        tok = STORE.session_new('portal', 'petra', 'portal', '198.51.100.9', 1,
                                {'kind': 'local'})
        con = C()
        con.m_accounts()
        item = [i for i in con.items if 'signed in now' in i[1]]
        self.assertTrue(item, con.items)
        item[0][2]()
        self.assertTrue(con.picked)
        self.assertEqual(con.acts[-1][0][0], '--session-end')
        self.assertEqual(con.acts[-1][1], 0)
        self.assertFalse(STORE.db.row('SELECT id FROM sessions WHERE id = ?',
                                      (con.picked[0]['id'],)))
        del tok


class IdleAcrossTabs(unittest.TestCase):
    """The idle sign-out of admin.js, run in node: two tabs share one browser's storage."""

    def setUp(self):
        with open(os.path.join(ROOT, 'web', 'assets', 'admin.js'), encoding='utf-8') as f:
            src = f.read()
        m = re.search(r"\(function \(\) \{\n  var last = Date\.now\(\), limit = 0.*?\n\}\)\(\);\n",
                      src, re.S)
        self.assertTrue(m, 'the idle sign-out of admin.js not found')
        self.code = m.group(0)
        self.node = subprocess.run(['which', 'node'], capture_output=True, text=True).stdout.strip()
        if not self.node:
            self.skipTest('no node here')

    def test_one_tab_used_keeps_the_other(self):
        script = r"""
const vm = require('vm');
const code = %s;
let now = 1e12;
const store = {};
const localStorage = {getItem: (k) => (k in store ? store[k] : null),
                      setItem: (k, v) => { store[k] = String(v); }};
function tab() {
  const t = {listeners: {}, timers: [], loggedOut: 0};
  const ctx = {
    Date: {now: () => now}, Number, String, Math, localStorage, location: {reload() {}},
    document: {addEventListener: (e, fn) => { t.listeners[e] = fn; }},
    setInterval: (fn) => { t.timers.push(fn); },
    api: (what) => {
      if (what === 'logout') { t.loggedOut++; }
      return {then: (ok) => { if (what === 'whoami') ok({idle_min: 120}); return {catch() {}}; }};
    },
  };
  vm.runInNewContext(code, ctx);
  t.tick = () => t.timers.forEach((f) => f());
  t.use = () => t.listeners.click();
  return t;
}
const a = tab(), b = tab();
const out = {};
// b used every 10 min for three hours, a never touched
for (let i = 0; i < 18; i++) { now += 600000; b.use(); a.tick(); b.tick(); }
out.a_kept = a.loggedOut === 0;
out.b_kept = b.loggedOut === 0;
// then neither is used: signed out after the idle time
now += 121 * 60000; a.tick();
out.a_out = a.loggedOut === 1;
console.log(JSON.stringify(out));
""" % json.dumps(self.code)
        got = subprocess.run([self.node, '-e', script], capture_output=True, text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(json.loads(got.stdout), {'a_kept': True, 'b_kept': True, 'a_out': True})



class PortalIdle(unittest.TestCase):
    """The portal's page signs out after portal_session_min unused, its own refresh of the list
    every minute notwithstanding - any tab of the browser counting as used."""

    def test_said_by_the_daemon(self):
        E.CONFIG['portal_session_min'] = 25
        try:
            got = E.portal_state(handler(), {'name': 'x', 'data': {'kind': 'local'}})
        finally:
            E.CONFIG.pop('portal_session_min', None)
        self.assertEqual(got['idle_min'], 25)

    def test_page(self):
        node = subprocess.run(['which', 'node'], capture_output=True, text=True).stdout.strip()
        if not node:
            self.skipTest('no node here')
        with open(os.path.join(ROOT, 'web', 'assets', 'portal.js'), encoding='utf-8') as f:
            src = f.read()
        m = re.search(r"\nfunction portalIdle\(min\) \{.*?\n\}\n", src, re.S)
        self.assertTrue(m)
        self.assertIn('if (ME && ME.idle_min) portalIdle(ME.idle_min);', src)
        script = r"""
const vm = require('vm');
const code = %s;
let now = 1e12;
const store = {};
const localStorage = {getItem: (k) => (k in store ? store[k] : null),
                      setItem: (k, v) => { store[k] = String(v); }};
function tab() {
  const t = {listeners: {}, timers: [], out: 0, said: {}};
  const ctx = {
    Date: {now: () => now}, Number, String, localStorage, ME: {sso: false},
    sessionStorage: {setItem: (k, v) => { t.said[k] = v; }},
    document: {addEventListener: (e, fn) => { t.listeners[e] = fn; }},
    setInterval: (fn) => { t.timers.push(fn); },
    portalSignOut: () => { t.out++; },
  };
  vm.runInNewContext(code + '\nportalIdle(15);', ctx);
  t.tick = () => t.timers.forEach((f) => f());
  t.use = () => t.listeners.keydown();
  return t;
}
const a = tab(), b = tab();
const out = {};
for (let i = 0; i < 10; i++) { now += 60000; a.tick(); b.tick(); }   // the refresh only
out.kept_while_used = a.out === 0;
for (let i = 0; i < 6; i++) { now += 60000; a.tick(); }
out.out_after_15 = a.out === 1 && a.said['acme-signed-out'] === '1';
now += 1000; b.use();
for (let i = 0; i < 14; i++) { now += 60000; b.tick(); }
out.other_tab_counts = b.out === 0;
console.log(JSON.stringify(out));
""" % json.dumps(m.group(0))
        got = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(json.loads(got.stdout), {'kept_while_used': True, 'out_after_15': True,
                                                  'other_tab_counts': True})


if __name__ == '__main__':
    unittest.main(verbosity=2)
