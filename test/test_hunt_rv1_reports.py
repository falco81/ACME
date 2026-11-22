#!/usr/bin/env python3
"""Hunt v1 (1.0.140), area "reports": the periodic reports and the teams' digests.

    python3 test/test_hunt_rv1_reports.py

- cert_report_runs had a column "rows" - a word MariaDB keeps for itself: the table was never
  made there (CREATE TABLE failed), so no run could be kept on MariaDB.
- A report set for 00:00 came at 07:00 (`hour or 7`).
- A certificate administrator saw the addresses a run went to (the recipients themselves are
  hidden from them), and the runs a report made before its teams were narrowed (every team ->
  Web: the runs of every team, downloadable by the administrator of Web).
- The access report's tile of temporary roles was coloured by the roles of every team.
- A digest that did not go (mail off, the server refused) moved "since" on: what failed in
  between was in no digest.
- The PDF wrote a decomposed letter (c + combining caron) as "c?".
- The console lacked what the page offers: a run's file saved, the runs kept, the days ahead
  and a paused schedule of a report; the teams below, the language and a preview mailed of a
  digest.
"""
import argparse
import json
import os
import re
import sys
import time
import unicodedata
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_f140_reports as F  # noqa: E402  (its own database, its seed)

E, RP, D, T, P, STORE = F.E, F.RP, F.D, F.T, F.P, F.STORE
DAY = 86400


class Units(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ids = F.seed(STORE)
        cls.saved = dict(E.CONFIG)
        E.CONFIG.update(mail_mode='off', mail_from='acme@example.test', mail_lang='en',
                        certs_certadmin_all=1)

    @classmethod
    def tearDownClass(cls):
        E.CONFIG.clear()
        E.CONFIG.update(cls.saved)

    def rep(self, name, kind, teams=(), **more):
        old = RP.get_row(STORE, name)
        b = dict({'name': name, 'kind': kind, 'teams': list(teams), 'formats': ['csv', 'pdf']},
                 **more)
        if old:
            b['id'] = old['id']
        return RP.need(STORE, RP.save(STORE, b, 'test')['id'])

    def test_no_mariadb_reserved_column(self):
        ddl = dict(E.SCHEMA)['cert_report_runs']
        body = ddl.split('(', 1)[1]
        cols = [p.strip().split(' ', 1)[0].lower() for p in body.split(',')]
        for word in ('rows', 'row', 'key', 'keys', 'order', 'group', 'range', 'index', 'read',
                     'release', 'option', 'check', 'desc', 'table', 'over', 'window'):
            self.assertNotIn(word, cols, 'a word MariaDB keeps for itself: %s' % word)
        self.assertIn('row_count', cols)
        self.assertIn('teams', cols)
        r = self.rep('v1-rows', 'inventory', ['Web'])
        run = RP.run(STORE, r, 'test')
        self.assertEqual(run['rows'], 5, 'the rows still counted, under their new column')
        self.assertEqual(RP.runs(STORE, r, 1)[0]['rows'], 5)

    def test_midnight_is_an_hour(self):
        r = self.rep('v1-midnight', 'expiry', schedule={'every': 'weekly', 'day': 1, 'hour': 0})
        self.assertEqual(RP.public(r)['schedule']['hour'], 0)
        mon = time.mktime((2026, 11, 23, 0, 30, 0, 0, 0, -1))          # a Monday, 00:30
        sch = dict(json.loads(r['schedule']), since=mon - 10 * DAY)
        self.assertEqual(RP.due_period(sch, mon)[0], 'w:2026-48', 'due at 00:00, not 07:00')
        since = json.loads(r['schedule'])['since']
        again = self.rep('v1-midnight', 'expiry', note='x')
        self.assertEqual(json.loads(again['schedule'])['since'], since,
                         'a save that keeps the schedule keeps its start')
        self.assertEqual(RP._sched({'every': 'weekly'})['hour'], 7, 'no hour: 07:00')

    def test_certadmin_runs(self):
        ca = {'role': 'certadmin', 'name': 'cm', 'account': {'source': 'local'}}
        full = {'role': 'fulladmin', 'name': 'tester'}
        r = self.rep('v1-narrowed', 'inventory', [], recipients='boss@example.test')
        wide = RP.run(STORE, r, 'test')
        STORE.db.run('UPDATE cert_report_runs SET sent_to = ? WHERE id = ?',
                     ('boss@example.test', wide['id']))
        r = self.rep('v1-narrowed', 'inventory', ['Web'])
        narrow = RP.run(STORE, r, 'test')
        STORE.db.run('UPDATE cert_report_runs SET sent_to = ? WHERE id = ?',
                     ('boss@example.test', narrow['id']))
        E.CONFIG['certs_certadmin_all'] = 0
        t = T.team_get(STORE, 'Web')
        ms = json.loads(t['members']) + [{'who': 'local:cm', 'rights': ['view', 'request',
                                                                       'manage']}]
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'parent': 'Europe',
                            'members': ms}, 'x')
        try:
            self.assertTrue(RP.may_see(STORE, ca, r))
            seen = RP.runs_for(STORE, ca, r)
            self.assertEqual([x['id'] for x in seen], [narrow['id']],
                             'the run of every team is not theirs')
            self.assertNotIn('boss@example.test', json.dumps(seen))
            self.assertEqual(seen[0]['sent_to'], ['…'], 'mailed - to whom is not said')
            self.assertFalse(RP.may_see_run(STORE, ca, r, RP.run_get(STORE, wide['id'])))
            self.assertTrue(RP.may_see_run(STORE, ca, r, RP.run_get(STORE, narrow['id'])))
            self.assertEqual(RP.runs_for(STORE, ca, r, 1)[0]['id'], narrow['id'])
            # a run of before (no teams kept): judged by the report's teams, as before
            STORE.db.run('UPDATE cert_report_runs SET teams = NULL WHERE id = ?', (narrow['id'],))
            self.assertTrue(RP.may_see_run(STORE, ca, r, RP.run_get(STORE, narrow['id'])))
            mine = RP.runs_for(STORE, full, r)
            self.assertEqual(len(mine), 2)
            self.assertIn('boss@example.test', json.dumps(mine), 'a full administrator\'s')
        finally:
            E.CONFIG['certs_certadmin_all'] = 1
            T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'parent': 'Europe',
                                'members': ms[:-1]}, 'x')

    def test_access_tile_scoped(self):
        STORE.db.run("UPDATE cert_team_elevations SET team = 'Quiet' WHERE state = 'granted'")
        try:
            got = RP.build(STORE, self.rep('v1-access', 'access', ['Web']), lang='en')
            tile = [t for t in got['tiles'] if t[0] == 'temporary roles now'][0]
            self.assertEqual((tile[1], tile[2]), (0, 'good'),
                             'a role of another team does not colour it')
        finally:
            STORE.db.run("UPDATE cert_team_elevations SET team = 'Web' WHERE state = 'granted'")

    def test_digest_not_sent_keeps_since(self):
        t = T.team_get(STORE, 'Web')
        STORE.db.run('DELETE FROM meta WHERE k = ?', (D.META_LAST % t['id'],))
        cfg = dict(D.DEFAULTS, on=True)
        first = time.time() - 7 * DAY
        rec = D.send(STORE, t, 'test', cfg, since=first)          # mail is off
        self.assertFalse(rec['ok'])
        self.assertAlmostEqual(D._since(STORE, t, cfg), first, delta=1,
                               msg='the next one covers the time of the one that did not go')
        data = D.collect(STORE, t, cfg, D._since(STORE, t, cfg))
        self.assertEqual([f['cert'] for f in data['failed']], ['api'],
                         'the renewal that failed meanwhile is still told')
        q = T.team_get(STORE, 'Quiet')
        rec = D.send(STORE, q, 'test', cfg, since=first)          # nothing: skipped, ok
        self.assertTrue(rec['skipped'])
        self.assertGreater(D._since(STORE, q, cfg), time.time() - 60)
        STORE.db.run('DELETE FROM meta WHERE k = ?', (D.META_LAST % t['id'],))

    def test_pdf_decomposed_letters(self):
        nfd = unicodedata.normalize('NFD', 'Žluťoučký kůň č')
        self.assertEqual(P.encode(nfd), P.encode('Žluťoučký kůň č'))
        self.assertNotIn(b'?', P.encode(nfd))
        doc = P.Doc(nfd, 'x', 'y')
        doc.table(['a', '#b'], [[nfd, '1'], ['\x00\x1b[31m😀', '2']])
        data = doc.output()
        self.assertTrue(data.startswith(b'%PDF-1.4') and data.rstrip().endswith(b'%%EOF'))
        try:
            import pypdf
            import io
            r = pypdf.PdfReader(io.BytesIO(data), strict=True)
            self.assertIn('Žluťoučký', r.pages[0].extract_text())
        except ImportError:
            pass


class FakeCon(object):
    """The console's calls, kept: what each item would run."""

    def __init__(self, answers, outs=None):
        self.answers = list(answers)
        self.outs = outs or {}
        self.acts = []
        self.forms = []

    def form(self, title, fields, *a, **k):
        self.forms.append([f['key'] for f in fields])
        got = self.answers.pop(0)
        if got is None:
            return None
        vals = {}
        for f in fields:
            vals[f['key']] = str(f.get('value') if f.get('value') is not None else '')
        vals.update(got)
        return vals

    def act(self, *args, **k):
        self.acts.append([str(a) for a in args])
        return 0

    def out(self, *args):
        return self.outs.get(args[0])

    def note(self, *a, **k):
        self.acts.append(['note'])

    @staticmethod
    def _rows(got, *keys):
        return got.get(keys[0]) if isinstance(got, dict) else []


class FakeCli(object):
    calls = []

    def __init__(self, args):
        self.args = args
        self.json = False
        self.store = STORE

    def open(self):
        pass

    def api(self, method, path, body=None, args=None):
        FakeCli.calls.append((method, path, body))
        if path == '/api/teams/digest_save':
            return {'digest': D.clean(STORE, T.team_get(STORE, body['team']), body['digest'])}
        if path == '/api/reports/save':
            return {'report': RP.public(RP.need(STORE, RP.save(STORE, body, 'test')['id']))}
        raise AssertionError(path)

    def done(self, words, got, ok=True):
        return 0


class Console(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        F.seed(STORE)

    def parse(self, argv):
        from acmelib.certs import reports_cli as RC
        p = argparse.ArgumentParser()
        p.add_argument('--json', action='store_true')
        p.add_argument('--yes', action='store_true')
        RC.add_args(p)
        return p.parse_args(argv)

    def run_cli(self, argv):
        """The command the console would run, through the command line's own checks."""
        from acmelib.certs import cli as CLI
        from acmelib.certs import reports_cli as RC
        was = CLI.Cli
        CLI.Cli = FakeCli
        FakeCli.calls[:] = []
        try:
            self.assertEqual(RC.run(self.parse(argv)), 0)
        finally:
            CLI.Cli = was
        return FakeCli.calls

    def test_report_form(self):
        from acmelib.certs import reports_cli as RC
        con = FakeCon([{'name': 'v1-con', 'kind': 'expiry', 'keep': '5', 'days': '14',
                        'off': 'yes'}])
        RC._con_report_form(con, None)
        self.assertIn('keep', con.forms[0])
        args = con.acts[0]
        for opt, v in (('--report-keep', '5'), ('--report-days', '14'), ('--report-off', 'yes')):
            self.assertEqual(args[args.index(opt) + 1], v)
        calls = self.run_cli(args)
        body = calls[0][2]
        self.assertEqual((body['keep'], body['options'], body['enabled']), (5, {'days': 14}, False))
        got = RP.public(RP.need(STORE, 'v1-con'))
        self.assertEqual((got['keep'], got['options']['days'], got['enabled']), (5, 14, False))
        # changed: what it holds is offered back
        con = FakeCon([{}])
        RC._con_report_form(con, got)
        args = con.acts[0]
        self.assertEqual(args[args.index('--report-off') + 1], 'yes')
        self.assertEqual(args[args.index('--report-days') + 1], '14')
        self.run_cli(args)
        RP.delete(STORE, 'v1-con', 'test')

    def test_report_get(self):
        from acmelib.certs import reports_cli as RC
        r = RP.need(STORE, RP.save(STORE, {'name': 'v1-get', 'kind': 'inventory'}, 'test')['id'])
        run = RP.run(STORE, r, 'test')
        con = FakeCon([{'format': 'csv', 'path': '/x/r.csv'}],
                      {'--report-runs': {'runs': RP.runs(STORE, r)}})
        RC._con_report_get(con, RP.public(r))
        self.assertEqual(con.acts[0], ['--report-get', str(run['id']), '--report-format', 'csv',
                                       '--report-out', '/x/r.csv'])
        self.parse(con.acts[0])
        con = FakeCon([], {'--report-runs': {'runs': []}})
        RC._con_report_get(con, RP.public(r))
        self.assertEqual(con.acts, [['note']], 'no run yet: said, nothing run')
        RP.delete(STORE, 'v1-get', 'test')

    def test_digest_form(self):
        from acmelib.certs import reports_cli as RC
        con = FakeCon([{'below': 'no', 'lang': 'cs'}],
                      {'--team-digest': {'digest': D.public(STORE, T.team_get(STORE, 'Web'))}})
        RC._con_digest_form(con, 'Web')
        args = con.acts[0]
        self.assertEqual(args[args.index('--digest-below') + 1], 'no')
        self.assertEqual(args[args.index('--digest-lang') + 1], 'cs')
        calls = self.run_cli(args)
        self.assertEqual((calls[0][2]['digest']['below'], calls[0][2]['digest']['lang']),
                         (False, 'cs'))

    def test_console_items(self):
        with open(os.path.join(F.ROOT, 'acmelib', 'certs', 'reports_cli.py')) as f:
            src = f.read()
        self.assertIn("('get', 'Save a run", src)
        self.assertRegex(src, r"'--team-digest-preview', r\['name'\], '--digest-mail'")
        self.parse(['--team-digest-preview', 'Web', '--digest-mail', 'a@example.test'])
        with open(os.path.join(F.ROOT, 'docs', 'console.md')) as f:
            self.assertTrue(re.search(r'save a run\'s CSV or PDF', f.read()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
