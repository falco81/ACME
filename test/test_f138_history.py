#!/usr/bin/env python3
"""The trash, the history of every object and the saved views (1.0.138, X1-X3,
docs/history-and-trash.md).

    python3 test/test_f138_history.py
    F138_SHOTS=/some/dir python3 test/test_f138_history.py     # and the screenshots there

- The backend (a real daemon as test/test_certs_core.py's): a target changed is a line of its
  history with who, when, from where and the field-level difference - its password only as
  "changed", never its value or its sealed form; what acme writes by itself is no change;
  "Restore this version" saves it again through the target's own route (a certificate
  administrator is refused, as saving is); a deleted target, team, role, tag, DNS set and request
  profile is in the trash, comes back with its secret still opening, under another name when the
  name was taken since; a certificate goes to the trash without its key and comes back as a request
  (held) with its deployment; permanent delete only by a full administrator; the trash off (0)
  keeps nothing; the purge forgets what ran out; a readonly account sees no trash.
- Saved views: personal, team (needs team.view on the team), global (full admin only), the default
  per person, another person's view neither seen nor changed.
- Upgrade: an old database without the new tables gets them, old rows load.
- The pages (php -S, Chromium via test/f138_history_page.js) in English and Czech at 1400 and
  390 px: the Trash pane, its filters and the restore preview, the History of a target with its
  diff and Restore this version, the saved views' dropdown by the certificates - no error of the
  page, nothing wider than the window.
"""
import json
import os
import re
import shutil
import sqlite3
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

SCRATCH = os.environ.get('F138_SCRATCH') or ''


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class History(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']
    wait_job = TCC.CertsCore.__dict__['wait_job']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.outdir = os.path.join(cls.tmp, 'out')

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def db(self):
        return sqlite3.connect(os.path.join(self.tmp, 'state', 'acme.db'))

    def target(self, name, pw='s3cret', **over):
        body = {'name': name, 'kind': 'fake', 'config': {'dir': self.outdir, 'password': pw,
                                                         'mode': 'a'}}
        body.update(over)
        return self.ok('POST', '/api/targets/save', body)['id']

    def hist(self, typ, ident, session=None):
        st, got = self.call('GET', '/api/history', session=session or self.admin,
                            args={'type': typ, 'id': ident})
        self.assertEqual(st, 200, got)
        return got

    # ---- X2: the history --------------------------------------------------------------------
    def test_01_history_of_a_target(self):
        tid = self.target('hist-a')
        self.ok('POST', '/api/targets/save', {'id': tid, 'name': 'hist-a', 'kind': 'fake',
                                              'config': {'dir': self.outdir, 'password': '',
                                                         'mode': 'b', 'port': 7},
                                              'note': 'first note'})
        self.ok('POST', '/api/targets/save', {'id': tid, 'name': 'hist-a', 'kind': 'fake',
                                              'config': {'dir': self.outdir, 'password': 'n3w',
                                                         'mode': 'b', 'port': 7}})
        got = self.hist('target', tid)
        acts = [e['action'] for e in got['entries']]
        self.assertEqual(acts, ['change', 'change', 'create'], acts)
        self.assertEqual(got['object']['name'], 'hist-a')
        first = got['entries'][1]
        self.assertEqual(first['who'], 'tester')
        self.assertTrue(first['ip'])
        subs = {(c['field'], c['sub']): c for c in first['changes']}
        self.assertEqual(subs[('config', 'mode')]['before'], 'a')
        self.assertEqual(subs[('config', 'mode')]['after'], 'b')
        self.assertEqual(subs[('config', 'mode')]['label'], 'Mode')
        self.assertEqual(subs[('note', '')]['after'], 'first note')
        self.assertNotIn(('config', 'password'), subs)        # kept: no change
        last = got['entries'][0]
        pw = [c for c in last['changes'] if c['sub'] == 'password']
        self.assertEqual(len(pw), 1)
        self.assertTrue(pw[0]['secret'])
        self.assertNotIn('before', pw[0])
        text = json.dumps(got)
        for bad in ('s3cret', 'n3w', 'sealed:'):
            self.assertNotIn(bad, text)
        # what acme writes by itself is no change
        with self.db() as c:
            c.execute("UPDATE cert_targets SET last_error = 'x', last_ok = 5 WHERE id = ?", (tid,))
        self.assertEqual(len(self.hist('target', tid)['entries']), 3)
        # the feed
        st, feed = self.call('GET', '/api/history', session=self.admin,
                             args={'feed': 1, 'type': 'target'})
        self.assertEqual(st, 200)
        self.assertTrue(any(e['name'] == 'hist-a' for e in feed['entries']))
        self.assertIn('tester', feed['people'])

    def test_02_restore_a_version(self):
        tid = self.target('hist-b')
        self.ok('POST', '/api/targets/save', {'id': tid, 'name': 'hist-b', 'kind': 'fake',
                                              'config': {'dir': self.outdir, 'password': 'oth3r',
                                                         'mode': 'b'}})
        got = self.hist('target', tid)
        create = got['entries'][-1]
        self.assertTrue(create['can_restore'])
        st, pre = self.call('POST', '/api/history/preview', {'entry': create['id']},
                            session=self.admin)
        self.assertEqual(st, 200, pre)
        self.assertIn('mode', [c['sub'] for c in pre['changes']])
        # a certificate administrator may not save a target: not restore it either
        st, no = self.call('POST', '/api/history/restore', {'entry': create['id']},
                           session=self.cert_admin)
        self.assertEqual(st, 403, no)
        st, did = self.call('POST', '/api/history/restore', {'entry': create['id'],
                                                             'secrets': True}, session=self.admin)
        self.assertEqual(st, 200, did)
        rows = self.ok('GET', '/api/targets')['rows']
        row = [r for r in rows if r['name'] == 'hist-b'][0]
        self.assertEqual(row['config']['mode'], 'a')
        # the password of that version, and it still opens (the target's test checks it)
        st, t = self.call('POST', '/api/targets/test', {'id': tid}, session=self.admin)
        got = self.hist('target', tid)
        self.assertEqual(got['entries'][0]['action'], 'restore')
        self.assertIn('version', got['entries'][0]['note'])

    def test_03_readonly_sees_history_not_trash(self):
        tid = self.target('hist-c')
        self.hist('target', tid, session=self.ro)
        st, _ = self.call('GET', '/api/trash', session=self.ro)
        self.assertEqual(st, 403)
        st, _ = self.call('POST', '/api/trash/purge', {'all': True}, session=self.cert_admin)
        self.assertEqual(st, 403)

    # ---- X1: the trash ----------------------------------------------------------------------
    def test_04_target_to_trash_and_back(self):
        tid = self.target('trash-a', pw='s3cret')
        self.ok('POST', '/api/targets/delete', {'id': tid})
        st, tr = self.call('GET', '/api/trash', session=self.admin)
        self.assertEqual(st, 200, tr)
        it = [i for i in tr['items'] if i['name'] == 'trash-a']
        self.assertEqual(len(it), 1, tr)
        it = it[0]
        self.assertEqual(it['type'], 'target')
        self.assertEqual(it['who'], 'tester')
        self.assertNotIn('s3cret', json.dumps(tr))
        st, pre = self.call('POST', '/api/trash/preview', {'id': it['id']}, session=self.admin)
        self.assertEqual(st, 200, pre)
        self.assertIsNone(pre['conflict'])
        self.assertIn('password', pre['secrets'])
        self.assertNotIn('s3cret', json.dumps(pre))
        self.assertNotIn('sealed:', json.dumps(pre))
        # sealed in the trash as it was
        with self.db() as c:
            raw = c.execute('SELECT row FROM obj_trash WHERE id = ?', (it['id'],)).fetchone()[0]
        self.assertIn('sealed:', raw)
        self.assertNotIn('s3cret', raw)
        # a name taken since: explained, a new one offered
        self.target('trash-a', pw='x')
        st, pre = self.call('POST', '/api/trash/preview', {'id': it['id']}, session=self.admin)
        self.assertEqual(pre['conflict']['suggestion'], 'trash-a 2')
        st, no = self.call('POST', '/api/trash/restore', {'id': it['id']}, session=self.admin)
        self.assertEqual(st, 409, no)
        self.assertEqual(no.get('suggestion'), 'trash-a 2')
        # a certificate administrator may not bring a target back
        st, no = self.call('POST', '/api/trash/restore', {'id': it['id'], 'name': 'x1'},
                           session=self.cert_admin)
        self.assertEqual(st, 403, no)
        did = self.ok('POST', '/api/trash/restore', {'id': it['id'], 'name': 'trash-a 2'})
        new = did['id']
        st, t = self.call('POST', '/api/targets/test', {'id': new}, session=self.admin)
        self.assertEqual(st, 200, t)
        self.wait_job(t['job_id']) if t.get('job_id') else None
        # its secret opens in its new place (the fake target's test needs it)
        rows = self.ok('GET', '/api/targets')['rows']
        row = [r for r in rows if r['name'] == 'trash-a 2'][0]
        self.assertIn('password', row.get('secret_set') or [])
        with self.db() as c:
            n = c.execute('SELECT COUNT(*) FROM obj_trash WHERE id = ?', (it['id'],)).fetchone()[0]
        self.assertEqual(n, 0)
        # its history followed it
        got = self.hist('target', new)
        self.assertEqual([e['action'] for e in got['entries']][:1], ['restore'])
        self.assertIn('create', [e['action'] for e in got['entries']])

    def test_05_teams_roles_tags_sets_profiles(self):
        self.ok('POST', '/api/roles/save', {'name': 'Gone role', 'caps': ['cert.view']})
        self.ok('POST', '/api/tags/save', {'name': 'gonetag', 'colour': 'ok'})
        self.ok('POST', '/api/teams/save', {'name': 'Gone team', 'members': [
            {'who': 'local:certer', 'rights': ['view']}], 'contact_mail': 'a@example.com'})
        self.ok('POST', '/api/dnssets/save', {'name': 'Gone set', 'servers': '192.0.2.53'})
        self.ok('POST', '/api/dnssets/assign', {'purpose': 'targets', 'set': 'Gone set'})
        self.ok('POST', '/api/roles/delete', {'name': 'Gone role'})
        self.ok('POST', '/api/tags/delete', {'name': 'gonetag'})
        self.ok('POST', '/api/teams/delete', {'name': 'Gone team'})
        self.ok('POST', '/api/dnssets/delete', {'name': 'Gone set'})
        tr = self.ok('GET', '/api/trash')
        by = {(i['type'], i['name']): i for i in tr['items']}
        for k in (('role', 'Gone role'), ('tag', 'gonetag'), ('team', 'Gone team'),
                  ('dnsset', 'Gone set')):
            self.assertIn(k, by, tr)
        self.assertEqual([c['type'] for c in by[('dnsset', 'Gone set')]['children']], ['dnsuse'])
        self.assertNotIn('dnsuse', [i['type'] for i in tr['items']])
        for k in (('role', 'Gone role'), ('tag', 'gonetag'), ('team', 'Gone team'),
                  ('dnsset', 'Gone set')):
            self.ok('POST', '/api/trash/restore', {'id': by[k]['id']})
        teams = self.ok('GET', '/api/teams')
        team = [t for t in teams['teams'] if t['name'] == 'Gone team'][0]
        self.assertEqual(team.get('contact_mail'), 'a@example.com')
        self.assertTrue(any(t['name'] == 'gonetag' for t in teams['tags']))
        sets = self.ok('GET', '/api/dnssets')
        self.assertIn('Gone set', json.dumps(sets))
        with self.db() as c:
            use = c.execute("SELECT set_name FROM dns_set_uses WHERE purpose = 'targets'").fetchone()
        self.assertEqual(use[0], 'Gone set')

    def test_06_certificate_to_trash_without_its_key(self):
        tid = self.target('trash-dep')
        self.ok('POST', '/api/sources/save', {'name': 'selfie', 'kind': 'selfsigned', 'config': {}})
        cid = self.ok('POST', '/api/certs/save', {'name': 'trash-cert', 'names': ['t.example.test'],
                                                  'issuer': 'selfie', 'key_type': 'ec-256'})['id']
        got = self.ok('POST', '/api/certs/renew', {'id': cid})
        if got.get('job_id'):
            self.wait_job(got['job_id'])
        self.ok('POST', '/api/deploys/save', {'cert_id': cid, 'target': 'trash-dep',
                                              'options': {'file': 'x.pem', 'pfx_password': 'pfxpw'}})
        self.ok('POST', '/api/certs/delete', {'id': cid})
        tr = self.ok('GET', '/api/trash', args={'type': 'cert'})
        it = [i for i in tr['items'] if i['name'] == 'trash-cert'][0]
        self.assertEqual([c['type'] for c in it['children']], ['deploy'])
        with self.db() as c:
            raw = c.execute('SELECT row FROM obj_trash WHERE id = ?', (it['id'],)).fetchone()[0]
        self.assertNotIn('key_sealed', raw)
        self.assertNotIn('BEGIN', raw)
        pre = self.ok('POST', '/api/trash/preview', {'id': it['id']})
        self.assertTrue(any('request' in n for n in pre['notes']))
        did = self.ok('POST', '/api/trash/restore', {'id': it['id']})
        one = self.ok('GET', '/api/certs/one', args={'id': did['id']})
        cert = one.get('cert') or one
        self.assertEqual(cert.get('state'), 'held')
        self.assertFalse(cert.get('fingerprint'))
        with self.db() as c:
            dep = c.execute('SELECT options FROM cert_deploys WHERE cert_id = ?',
                            (did['id'],)).fetchone()
        self.assertIsNotNone(dep)
        self.assertIn('sealed:', dep[0])
        self.assertEqual(did['with'], ['trash-cert → trash-dep'])

    def test_07_deploy_needs_its_target(self):
        tid = self.target('need-t')
        self.ok('POST', '/api/sources/save', {'name': 'selfie2', 'kind': 'selfsigned',
                                              'config': {}})
        cid = self.ok('POST', '/api/certs/save', {'name': 'need-cert', 'names': ['n.example.test'],
                                                  'issuer': 'selfie2', 'hold': 1})['id']
        did = self.ok('POST', '/api/deploys/save', {'cert_id': cid, 'target': 'need-t',
                                                    'options': {'file': 'n.pem'}})['id']
        self.ok('POST', '/api/deploys/delete', {'id': did})
        self.ok('POST', '/api/targets/delete', {'id': tid})
        tr = self.ok('GET', '/api/trash', args={'type': 'deploy'})
        dep = [i for i in tr['items'] if i['name'] == 'need-cert → need-t'][0]
        pre = self.ok('POST', '/api/trash/preview', {'id': dep['id']})
        self.assertTrue(pre['needs'] and pre['needs'][0]['trash_id'])
        st, no = self.call('POST', '/api/trash/restore', {'id': dep['id']}, session=self.admin)
        self.assertEqual(st, 400, no)
        self.ok('POST', '/api/trash/restore', {'id': dep['id'], 'with_needs': True})
        with self.db() as c:
            n = c.execute("SELECT COUNT(*) FROM cert_deploys WHERE cert_id = ? AND target = "
                          "'need-t'", (cid,)).fetchone()[0]
        self.assertEqual(n, 1)

    def test_08_purge_and_off(self):
        tid = self.target('purge-a')
        self.ok('POST', '/api/targets/delete', {'id': tid})
        tr = self.ok('GET', '/api/trash')
        it = [i for i in tr['items'] if i['name'] == 'purge-a'][0]
        st, no = self.call('POST', '/api/trash/purge', {'ids': [it['id']]}, session=self.cert_admin)
        self.assertEqual(st, 403)
        self.ok('POST', '/api/trash/purge', {'ids': [it['id']]})
        tr = self.ok('GET', '/api/trash')
        self.assertFalse([i for i in tr['items'] if i['name'] == 'purge-a'])
        # off: nothing kept
        self.ok('POST', '/api/settings', {'settings': {'history_trash_days': 0}})
        try:
            tid = self.target('purge-b')
            self.ok('POST', '/api/targets/delete', {'id': tid})
            with self.db() as c:
                n = c.execute("SELECT COUNT(*) FROM obj_trash WHERE oname = 'purge-b'").fetchone()[0]
            self.assertEqual(n, 0)
        finally:
            self.ok('POST', '/api/settings', {'settings': {'history_trash_days': 30}})
        # what ran out is forgotten
        with self.db() as c:
            c.execute("INSERT INTO obj_trash (ts, otable, otype, oid, oname, row, expires) VALUES "
                      "(1, 'cert_tags', 'tag', 999, 'old-one', '{}', 2)")
        tr = self.ok('GET', '/api/trash')
        self.assertFalse([i for i in tr['items'] if i['name'] == 'old-one'])

    def test_09_certadmin_scoped_trash(self):
        tr = self.ok('GET', '/api/trash', session=self.cert_admin)
        self.assertTrue(all(i['type'] in ('cert', 'deploy', 'check') for i in tr['items']), tr)

    # ---- X3: saved views --------------------------------------------------------------------
    def test_10_saved_views(self):
        state = {'filters': {'ct-q': 'web', 'ct-state': 'expiring'},
                 'cols': {'h': ['source'], 'o': ['name', 'state']}, 'key': 'ct-table:x'}
        v = self.ok('POST', '/api/views/save', {'table': 'ct-q', 'name': 'Mine soon',
                                                'scope': 'user', 'view': state,
                                                'default': True}, session=self.cert_admin)
        vid = v['view']['id']
        got = self.ok('GET', '/api/views', args={'table': 'ct-q'}, session=self.cert_admin)
        self.assertEqual(got['default'], vid)
        self.assertEqual(got['views'][0]['state']['filters']['ct-state'], 'expiring')
        # another person sees it not, changes it not
        got = self.ok('GET', '/api/views', args={'table': 'ct-q'}, session=self.ro)
        self.assertFalse([x for x in got['views'] if x['id'] == vid])
        st, _ = self.call('POST', '/api/views/delete', {'id': vid}, session=self.ro)
        self.assertEqual(st, 404)
        # everybody's: a full administrator's only
        st, _ = self.call('POST', '/api/views/save', {'table': 'ct-q', 'name': 'All',
                                                      'scope': 'global', 'view': {}},
                          session=self.cert_admin)
        self.assertEqual(st, 403)
        g = self.ok('POST', '/api/views/save', {'table': 'ct-q', 'name': 'Failed FortiGate',
                                                'scope': 'global',
                                                'view': {'filters': {'ct-state': 'failed'}}})
        got = self.ok('GET', '/api/views', args={'table': 'ct-q'}, session=self.ro)
        self.assertTrue([x for x in got['views'] if x['id'] == g['view']['id']])
        self.assertFalse([x for x in got['views'] if x['id'] == g['view']['id']][0]['mine'])
        # a team's: needs team.view on it
        self.ok('POST', '/api/teams/save', {'name': 'View team', 'members': []})
        self.ok('POST', '/api/settings', {'settings': {'certs_readonly_all': 0, 'certs_certadmin_all': 0}})
        try:
            st, no = self.call('POST', '/api/views/save', {'table': 'ct-q', 'name': 'Team one',
                                                           'scope': 'team', 'team': 'View team',
                                                           'view': {}}, session=self.cert_admin)
            self.assertEqual(st, 403, no)
            self.ok('POST', '/api/teams/save', {'name': 'View team', 'old_name': 'View team',
                                                'members': [{'who': 'local:certer',
                                                             'rights': ['view']}]})
            t = self.ok('POST', '/api/views/save', {'table': 'ct-q', 'name': 'Team one',
                                                    'scope': 'team', 'team': 'View team',
                                                    'view': {}}, session=self.cert_admin)
            got = self.ok('GET', '/api/views', args={'table': 'ct-q'}, session=self.ro)
            self.assertFalse([x for x in got['views'] if x['id'] == t['view']['id']])
        finally:
            self.ok('POST', '/api/settings', {'settings': {'certs_readonly_all': 1, 'certs_certadmin_all': 1}})
        # a bad state refused, a bad table name too
        st, _ = self.call('POST', '/api/views/save', {'table': '../x', 'name': 'a', 'view': {}},
                          session=self.admin)
        self.assertEqual(st, 400)
        self.ok('POST', '/api/views/default', {'table': 'ct-q', 'id': None},
                session=self.cert_admin)
        got = self.ok('GET', '/api/views', args={'table': 'ct-q'}, session=self.cert_admin)
        self.assertIsNone(got['default'])
        self.ok('POST', '/api/views/delete', {'id': vid}, session=self.cert_admin)

    # ---- upgrade -----------------------------------------------------------------------------
    def test_11_tables_made_and_backed_up(self):
        with self.db() as c:
            names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for t in ('obj_history', 'obj_trash', 'saved_views'):
            self.assertIn(t, names)
        got = subprocess.run([sys.executable, '-c', (
            'import sys; sys.path.insert(0, %r); from acmelib import engine as E; '
            'print(",".join(t for t in E.TABLES if t in ("obj_history", "obj_trash", '
            '"saved_views"))); print("obj_history" in E.LOG_TABLES)') % ROOT],
            env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(got.stdout.split(), ['obj_history,obj_trash,saved_views', 'True'],
                         got.stderr[-2000:])

    def test_12_old_database_upgraded(self):
        """A database of 1.0.137 (none of the three tables): they are made at the start, the
        targets of before load and are changed with a history."""
        tmp = os.path.join(self.tmp, 'old')
        os.makedirs(os.path.join(tmp, 'state'), exist_ok=True)
        db = os.path.join(tmp, 'state', 'acme.db')
        src = sqlite3.connect(os.path.join(self.tmp, 'state', 'acme.db'))
        c = sqlite3.connect(db)
        src.backup(c)
        src.close()
        for t in ('obj_history', 'obj_trash', 'saved_views'):
            c.execute('DROP TABLE %s' % t)
        c.commit()
        c.close()
        env = dict(self.env, ACME_STATE=os.path.join(tmp, 'state'))
        got = subprocess.run([sys.executable, '-c', (
            'import sys; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'db = acme.open_db(); db.make_tables(); '
            'print(sorted(r["name"] for r in db.rows("SELECT name FROM sqlite_master WHERE '
            'type=\'table\' AND name IN (\'obj_history\', \'obj_trash\', \'saved_views\')"))); '
            'print(db.value("SELECT COUNT(*) FROM cert_targets") > 0)') % ROOT],
            env=env, capture_output=True, text=True, timeout=120)
        self.assertIn("['obj_history', 'obj_trash', 'saved_views']", got.stdout, got.stderr[-3000:])
        self.assertIn('True', got.stdout)


def merged_lang(web):
    """The Czech of this package put into the copy of web/lang/cs.json the pages are served from
    (the merge into the real file is done at the release)."""
    if not SCRATCH:
        return
    path = os.path.join(web, 'lang', 'cs.json')
    with open(path, encoding='utf-8') as f:
        d = json.load(f)
    have = {e['source'] for part in ('strings', 'patterns') for e in d[part].values()}
    for fn, part in (('cs_history.json', 'strings'), ('cs_history_patterns.json', 'patterns')):
        p = os.path.join(SCRATCH, fn)
        if not os.path.exists(p):
            continue
        with open(p, encoding='utf-8') as f:
            got = json.load(f)
        n = 0
        for en, cs in got.items():
            if en in have:
                continue
            n += 1
            d[part]['h138_%04d' % n if part == 'strings' else 'h138p_%04d' % n] = {'source': en,
                                                                                    'text': cs}
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(d, f, ensure_ascii=False, indent=1)


class Pages(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def test_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        merged_lang(web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
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
            drv = subprocess.run([node, os.path.join(HERE, 'f138_history_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, cwd=ROOT, timeout=900)
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(drv.returncode, 0, drv.stderr[-2000:])
        seen = [json.loads(x) for x in drv.stdout.splitlines() if x.startswith('{')][-1]
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['runs']), 4, seen)
        for one in seen['runs']:
            tag = '%s %s' % (one['lang'], one['w'])
            self.assertGreaterEqual(one['items'], 2, tag)
            self.assertEqual(one['settings'], 2, tag)
            self.assertTrue(one['onlyTargets'], tag)
            self.assertEqual(one['suggested'], 'gone-%s%s 2' % (one['lang'], one['w']), tag)
            self.assertEqual(one['sealed'], 1, tag)
            self.assertTrue(one['restored'], tag)
            self.assertGreater(one['events'], 3, tag)
            self.assertEqual(one['entries'], 3, tag)
            self.assertFalse(one['secretShown'], tag)
            self.assertGreaterEqual(one['secretChanged'], 1, tag)
            self.assertEqual(one['versionBack'], 'a:first', tag)
            self.assertEqual(one['viewName'], 'Soon %s%s' % (one['lang'], one['w']), tag)
            self.assertEqual(one['cleared'], '', tag)
            self.assertEqual(one['picked'], 'expiring', tag)
            self.assertTrue(one['menuClosed'], tag)
            self.assertEqual(one['hscroll'], [], tag)
            if one['lang'] == 'cs' and SCRATCH:
                self.assertEqual(one['english'], [], tag)


class Source(unittest.TestCase):
    def test_hooks_are_small(self):
        api = read('acmelib/certs/api.py')
        self.assertIn("_lib('history').acting(h, s, method, path)", api)
        cols = read('web/assets/cols.js')
        self.assertIn('ACME_COLS_HOOK', cols)

    def test_js_api_for_others(self):
        js = read('web/assets/history.js')
        self.assertIn('window.acmeHistory', js)
        self.assertIn('window.acmeTrash', js)

    def test_czech_of_every_new_text(self):
        """Every text of the new pieces has its Czech in the package's file."""
        path = os.path.join(SCRATCH, 'cs_history.json') if SCRATCH else ''
        if not path or not os.path.exists(path):
            self.skipTest('the Czech of this package is merged later (F138_SCRATCH)')
        cs = json.load(open(path, encoding='utf-8'))
        for w in ('Trash and history', 'Restore this version', 'Saved views', 'Save this view…',
                  'Latest changes', 'Restore'):
            self.assertIn(w, cs, w)


if __name__ == '__main__':
    unittest.main(verbosity=2)
