#!/usr/bin/env python3
"""The right button over the whole application, the acme clipboard, rows picked together, a
command and an API call of an object, and the command palette (1.0.138, docs/context-menu.md).

    python3 test/test_f138_ctxmenu.py
    F138_SHOTS=/some/dir python3 test/test_f138_ctxmenu.py     # and screenshots there
    F138_CS=FILE[,FILE]   {English: Czech} merged into the copy's cs.json (before they are in it)

- The source: the new files loaded on every page that has tables (the administration; the
  portal the menu without the palette), cols.js untouched, the registrations of the pages other
  parts draw kept in ctxmenu-registry.js; nothing is asked of the daemon at load.
- The route (a real daemon as test/test_certs_core.py's): a target cloned "with the same
  credentials" signs in as the original (the fake module answers only to its password) while
  the secret never comes back; a secret typed in wins; the copy is a new one only, of the same
  module, a full administrator's - a certificate administrator and a reader are refused, and the
  event says which secrets were copied, never their value. Saving and the older rows: as before.
- The command the page copies for a target, a DNS set and a certificate, run as the command
  line: it makes the same object.
- The pages (php -S, Chromium via test/f138_ctxmenu_page.js) in English and Czech at 1400 and
  390 px: the menu of a row (role menu, the keyboard, Esc giving the focus back), the browser's
  own menu with Shift and in a box, the column menu while editing the columns, rows picked and a
  bulk action with what will happen and one result, a clone with the same credentials, the acme
  clipboard and Paste as new, a DNS set's and a team's clone, the palette; a reader sees no
  action they may not do; no page error, no English left on the Czech page, no page wider than
  the window.
"""
import json
import os
import re
import shlex
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

SHOTS = os.environ.get('F138_SHOTS', '')
CS_EXTRA = [x for x in os.environ.get('F138_CS', '').split(',') if x]


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


def merge_cs(path, extras):
    """{English: Czech} added to a copy of web/lang/cs.json - a pattern where it has {0}."""
    with open(path, encoding='utf-8') as f:
        pack = json.load(f)
    have = {v['source'] for sect in ('strings', 'patterns', 'rich') for v in pack.get(sect, {}).values()}
    i = 0
    for extra in extras:
        if not os.path.exists(extra):
            continue
        with open(extra, encoding='utf-8') as f:
            more = json.load(f)
        for en, cs in more.items():
            if en in have:
                continue
            i += 1
            sect = 'patterns' if re.search(r'\{\d\}', en) else 'strings'
            pack.setdefault(sect, {})['%s7%04d' % (sect[0], i)] = {'source': en, 'text': cs}
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(pack, f, ensure_ascii=False, indent=1)


def cli_args(text):
    """The words of a command as the page copies it (lines joined, comments left out)."""
    lines = [ln for ln in text.replace('\\\n', ' ').splitlines() if ln.strip() and not ln.lstrip().startswith('#')]
    words = shlex.split(' '.join(lines))
    assert words and words[0] == 'acme', words
    return words[1:]


class Source(unittest.TestCase):
    def test_loaded_on_the_pages(self):
        adm = read('web/admin/index.php')
        for f in ('ctxmenu.css', 'ctxmenu.js', 'ctxmenu-registry.js', 'palette.js'):
            self.assertIn('/assets/%s' % f, adm, f)
        # after the page's own scripts: the registry reads what certs.js lends
        self.assertLess(adm.index('/assets/certs.js'), adm.index('/assets/ctxmenu-registry.js'))
        portal = read('web/index.php')
        self.assertIn("'ctxmenu.css'", portal)
        self.assertIn('/assets/ctxmenu.js', portal)
        self.assertNotIn('palette.js', portal)

    def test_column_menu_untouched_and_honoured(self):
        js = read('web/assets/ctxmenu.js')
        self.assertIn('COLS_EDIT', js)
        self.assertIn('e.shiftKey', js)
        self.assertNotIn('ctxmenu', read('web/assets/cols.js'))

    def test_others_files_not_needed(self):
        """Owners and teams, request profiles, target agents: registered by their classes."""
        reg = read('web/assets/ctxmenu-registry.js')
        for sel in ('#tmx-tree', '.tmx-row', '#tmx-matrix', '.rp-row', '.ag-tile', 'ag-srv-t'):
            self.assertIn(sel, reg, sel)
        for f in ('teams.js', 'agents.js', 'reqprofiles.js', 'policybuilder.js', 'discover.js'):
            self.assertNotIn('ACME_CTX', read('web/assets/' + f), f)

    def test_storage_guarded(self):
        for f in ('ctxmenu.js', 'palette.js'):
            src = read('web/assets/' + f)
            for m in re.finditer(r'localStorage\.\w+\(', src):
                before = src[max(0, m.start() - 400):m.start()]
                self.assertIn('try', before, '%s: %s' % (f, src[m.start():m.start() + 60]))


class Pages(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']
    cli = TCC.CertsCore.__dict__['cli']
    cli_ok = TCC.CertsCore.__dict__['cli_ok']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.out = os.path.join(cls.tmp, 'out')
        os.makedirs(cls.out, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def seed(self):
        if getattr(type(self), '_seeded', False):
            return
        type(self)._seeded = True
        self.ok('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned', 'config': {'days': 40}})
        self.ok('POST', '/api/teams/save', {'name': 'Webteam', 'members': [], 'contact_mail': 'web@example.test',
                                            'policy': {'max_days': 90}})
        self.ok('POST', '/api/targets/save', {'name': 'fake1', 'kind': 'fake', 'tags': ['prod'],
                                              'config': {'dir': self.out, 'password': 's3cret', 'names': ['a', 'b']}})
        self.ok('POST', '/api/targets/save', {'name': 'fake2', 'kind': 'fake', 'config': {'dir': self.out}})
        type(self).cids = []
        for i, n in enumerate(['web', 'mail', 'intranet']):
            type(self).cids.append(self.ok('POST', '/api/certs/save', {
                'name': n, 'names': ['%s.example.test' % n], 'issuer': 'self', 'key_type': 'ec-256',
                'tags': ['prod'], 'owner': 'Webteam' if i == 0 else ''})['id'])
        self.ok('POST', '/api/deploys/save', {'cert_id': self.cids[0], 'target': 'fake1',
                                              'options': {'file': 'web.pem', 'pfx_password': 'pfxpw'}})
        self.ok('POST', '/api/dnssets/save', {'name': 'Company DNS', 'servers': '192.0.2.53\n192.0.2.54',
                                              'protocol': 'udp', 'timeout': 3, 'note': 'ours'})

    def target(self, name):
        got = [r for r in self.ok('GET', '/api/targets')['rows'] if r['name'] == name]
        return got[0] if got else None

    # ---- the route ---------------------------------------------------------------------------
    def test_1_same_credentials(self):
        self.seed()
        src = self.target('fake1')
        body = {'copy_of': src['id'], 'name': 'copy-one', 'kind': 'fake',
                'config': {'dir': self.out, 'password': src['config']['password'], 'names': ['c'], 'mode': 'b'},
                'enabled': True, 'note': 'a copy', 'tags': ['dc2']}
        got = self.ok('POST', '/api/targets/save_copy', body)
        self.assertEqual(got['copied'], ['password'])
        self.assertNotIn('s3cret', json.dumps(got))
        t = self.target('copy-one')
        self.assertEqual(t['config']['names'], ['c'])            # its own settings, not the original's
        self.assertEqual(t['config']['mode'], 'b')
        self.assertEqual(t['tags'], ['dc2'])
        self.assertIn('password', t['secret_set'])
        self.assertNotIn('s3cret', json.dumps(t))
        tested = self.ok('POST', '/api/targets/test', {'id': t['id']})
        self.assertTrue(tested['ok'], tested)                    # signs in as the original does
        # sealed for its own place: the original changed, the copy keeps its own
        self.ok('POST', '/api/targets/save', {'id': src['id'], 'kind': 'fake',
                                              'config': {'dir': self.out, 'password': 'other'}})
        self.assertTrue(self.ok('POST', '/api/targets/test', {'id': t['id']})['ok'])
        self.ok('POST', '/api/targets/save', {'id': src['id'], 'kind': 'fake',
                                              'config': {'dir': self.out, 'password': 's3cret'}})
        # the event says which, never the value
        ev = self.ok('GET', '/api/events', args={'q': 'copy-one', 'limit': 20})
        words = ' '.join(r.get('words', '') for r in ev.get('rows', []))
        self.assertIn('with its credentials (password)', words)
        self.assertNotIn('s3cret', words)

    def test_2_new_secret_wins_and_refusals(self):
        self.seed()
        src = self.target('fake1')
        got = self.ok('POST', '/api/targets/save_copy', {'copy_of': src['id'], 'name': 'copy-two', 'kind': 'fake',
                                                         'config': {'dir': self.out, 'password': 'typed-in'}})
        self.assertEqual(got['copied'], [])
        st, t = self.call('POST', '/api/targets/test', {'id': got['id']}, self.admin)
        self.assertFalse(t.get('ok'), t)                         # the one typed in, not the original's
        cases = [
            ({'copy_of': src['id'], 'name': 'x1', 'kind': 'selfsigned', 'config': {}}, 400, 'same module'),
            ({'copy_of': src['id'], 'id': src['id'], 'name': 'x2', 'kind': 'fake', 'config': {}}, 400, 'new one'),
            ({'copy_of': 999999, 'name': 'x3', 'kind': 'fake', 'config': {'dir': self.out}}, 404, 'no such'),
            ({'name': 'x4', 'kind': 'fake', 'config': {'dir': self.out}}, 400, 'copy_of'),
        ]
        for body, code, words in cases:
            st, r = self.call('POST', '/api/targets/save_copy', body, self.admin)
            self.assertEqual(st, code, (body, r))
            self.assertIn(words, r.get('error', ''), r)
        for who in (self.cert_admin, self.ro):
            st, r = self.call('POST', '/api/targets/save_copy', {'copy_of': src['id'], 'name': 'x5', 'kind': 'fake',
                                                                  'config': {'dir': self.out}}, who)
            self.assertEqual(st, 403, r)
        self.assertIsNone(self.target('x5'))
        # the other families have the route too
        sid = [r for r in self.ok('GET', '/api/sources')['rows'] if r['name'] == 'self'][0]['id']
        self.ok('POST', '/api/sources/save_copy', {'copy_of': sid, 'name': 'self copy', 'kind': 'selfsigned',
                                                   'config': {'days': 30}})

    def test_3_saving_as_before(self):
        """/save, the rows kept from before: what they were (no column, no table made)."""
        self.seed()
        before = self.target('fake2')
        self.ok('POST', '/api/targets/save', {'id': before['id'], 'kind': 'fake', 'note': 'n',
                                              'config': {'dir': self.out}})
        after = self.target('fake2')
        self.assertEqual(after['note'], 'n')
        self.assertEqual(sorted(before.keys()), sorted(after.keys()))
        src = read('acmelib/certs/api_ctxmenu.py')
        self.assertNotIn('CREATE TABLE', src)
        self.assertNotIn('ALTER TABLE', src)

    # ---- the pages -----------------------------------------------------------------------------
    def test_4_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True, cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        self.seed()
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        if CS_EXTRA:
            merge_cs(os.path.join(web, 'lang', 'cs.json'), CS_EXTRA)
        port = TCC.free_port()
        self.assertNotIn(port, (8092, 8443, 5432, 5433))
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
            drv = subprocess.run([node, os.path.join(HERE, 'f138_ctxmenu_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, cwd=ROOT, timeout=1500,
                                 env=dict(os.environ, F138_SHOTS=SHOTS))
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(drv.returncode, 0, drv.stderr[-2000:])
        seen = [json.loads(x) for x in drv.stdout.splitlines() if x.startswith('{')][-1]
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['runs']), 4)
        for one in seen['runs']:
            tag = '%s %s' % (one['lang'], one['w'])
            self.assertEqual(one['menu'], 1, tag)
            self.assertEqual(one['role'], 'menu', tag)
            self.assertGreater(one['items'], 10, tag)
            self.assertTrue(one['copiedCell'], tag)
            self.assertTrue(one['clipCell'], tag)
            self.assertEqual(one['sub'], 1, tag)
            self.assertNotIn('pfxpw', one['json'], tag)
            json.loads(one['json'])
            self.assertEqual((one['kbOpen'], one['kbFocusInMenu'], one['kbMoved'], one['kbClosed'], one['kbBack']),
                             (1, True, True, 0, 'TR'), tag)
            self.assertEqual(one['shiftMenu'], 0, tag)
            self.assertEqual(one['inputMenu'], 0, tag)
            self.assertEqual((one['colsMenu'], one['colsOurs']), (1, 0), tag)
            self.assertEqual(one['picked'], 2, tag)
            self.assertFalse(one['modalAfterPick'], tag)
            self.assertTrue(one['bulkPicked'], tag)
            self.assertIn('ok', one['bulkResult'], tag)
            self.assertEqual(one['pickedAfterEsc'], 0, tag)
            self.assertFalse(one['cloneSecretShown'], tag)
            t = self.target(one['cloneName'])
            self.assertIsNotNone(t, tag)
            self.assertTrue(self.ok('POST', '/api/targets/test', {'id': t['id']})['ok'], tag)
            self.assertIn('--target-add fake1', one['cli'], tag)
            self.assertIn('password=-', one['cli'], tag)
            self.assertNotIn('s3cret', one['cli'] + one['curl'], tag)
            self.assertIn('<fill in>', one['curl'], tag)
            self.assertIn('?api=targets/save', one['curl'], tag)
            self.assertEqual(one['clip']['type'], 'target', tag)
            self.assertNotIn('s3cret', json.dumps(one['clip']), tag)
            self.assertEqual(one['area'], 1, tag)
            self.assertEqual(one['pasteName'], ('Kopie ' if one['lang'] == 'cs' else 'Copy of ') + 'fake2', tag)
            self.assertEqual(one['dnsClone'][1], '192.0.2.53\n192.0.2.54', tag)
            self.assertTrue(one['dnsClone'][0].endswith('Company DNS'), tag)
            self.assertIn('--dns-set-add', one['dnsCli'], tag)
            self.assertEqual(one['teamMenu'], 1, tag)
            self.assertTrue(one['teamClone'].endswith('Webteam'), tag)
            self.assertTrue(one['paletteVerb'] and one['paletteVerb'][0].endswith('intranet'), (tag, one['paletteVerb']))
            self.assertEqual(one['paletteWent'], 'dnssets', tag)
            self.assertEqual(one['paletteClosed'], 0, tag)
            self.assertGreaterEqual(one['recent'], 1, tag)
            self.assertEqual(one['hscroll'], [], tag)
            if one['lang'] == 'cs' and CS_EXTRA:
                self.assertEqual(one['english'], [], tag)
        # the tag of the bulk action is on the two certificates picked
        tagged = [c for c in self.ok('GET', '/api/certs')['rows'] if 'uien1400' in (c.get('tags') or [])]
        self.assertEqual(len(tagged), 2)
        # a reader: no action they may not do
        ro = seen['ro']
        for w in ('Renew now', 'Delete…', 'Edit…', 'Revoke…', 'Clone…'):
            self.assertNotIn(w, ro['items'])
        self.assertIn('Copy', ro['items'])
        for w in ('Edit…', 'Take it away…', 'Clone…'):
            self.assertNotIn(w, ro['targetItems'])
        # the commands the page copied make the same objects on the command line
        dns = cli_args(seen['runs'][0]['dnsCli'])
        dns[dns.index('--dns-set-add') + 1] = 'From the page'
        self.cli_ok(*dns)
        made = [s for s in self.ok('GET', '/api/dnssets')['sets'] if s['name'] == 'From the page'][0]
        self.assertEqual(made['servers'], ['192.0.2.53', '192.0.2.54'])
        self.assertEqual(made['note'], 'ours')
        tg = cli_args(seen['runs'][0]['cli'])
        tg[tg.index('--target-add') + 1] = 'from-page'
        self.cli_ok(*tg, stdin='s3cret\n')
        t = self.target('from-page')
        self.assertEqual(t['config']['names'], ['a', 'b'])
        self.assertTrue(self.ok('POST', '/api/targets/test', {'id': t['id']})['ok'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
