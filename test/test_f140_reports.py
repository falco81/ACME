#!/usr/bin/env python3
"""Features 1.0.140, package "reports": T12 a team's digest by mail, G3 periodic reports.

    python3 test/test_f140_reports.py
    ACME_SHOTS=DIR keeps the pages' screenshots; ACME_F140_CS=FILE (flat {"English": "Česky"})
    is added to the Czech texts of the pages and of the mails under test.

- Units (in this process, its own database): the PDF writer (a valid PDF - read back by pdftotext
  and pypdf where they are here - Czech letters, many pages), the CSV (its mark, formulas
  defused), each kind of report and its scope, the compliance check reused, the schedule (once
  a period, never before it was set), who may see which report, the digest's contents,
  recipients and languages, an empty one skipped, mail switched off (nothing sent, said so),
  the mails through a local SMTP sink (HTML and text, the files attached, sent once however
  often the schedule looks), an older database (no tables, teams without a digest) and the
  configuration's export carrying the definitions.
- Api (a real daemon): the routes and their roles - a reader refused, a certificate
  administrator seeing only the reports of the teams they manage and changing none, the
  digest's routes, the command line (acme --reports ..., --team-digest ...) and the console's
  menu.
- Pages (Chromium, test/f140_reports_page.js): Settings → Reports and a team's Digest tab in
  English and Czech, 1400 and 390 px wide, no error, no page scrolling sideways.
"""
import base64
import email
import json
import os
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-f140-reports-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
_ENV_BEFORE = {k: os.environ.get(k) for k in ('ACME_CONFIG', 'ACME_STATE', 'ACME_RUN',
                                               'ACME_LOGDIR')}
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
import acme  # noqa: E402
from acmelib import engine as E  # noqa: E402
from acmelib import i18n_mail  # noqa: E402
from acmelib.certs import api as A  # noqa: E402,F401
from acmelib.certs import digest as D  # noqa: E402
from acmelib.certs import pdfwriter as P  # noqa: E402
from acmelib.certs import reports as RP  # noqa: E402
from acmelib.certs import teams as T  # noqa: E402
# the daemon's tests start their own processes with their own folders
for _k, _v in _ENV_BEFORE.items():
    if _v is None:
        os.environ.pop(_k, None)
    else:
        os.environ[_k] = _v

STORE = acme.Storage(acme.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DAY = 86400
SCRATCH_CS = os.environ.get('ACME_F140_CS', '')


def extra_cs():
    """The Czech of this package (scratch files, or web/lang/cs.json once merged) put into the
    mails' translation, as the pages' copy gets it."""
    p = i18n_mail.pack('cs')
    if not p or not SCRATCH_CS or not os.path.isfile(SCRATCH_CS):
        return
    with open(SCRATCH_CS, encoding='utf-8') as f:
        more = json.load(f)
    for en, cz in more.items():
        if re.search(r'\{\d+\}', en):
            c = i18n_mail._compile(i18n_mail._fold(en))
            if c:
                c['text'] = i18n_mail._fold(cz)
                p['pats'].append(c)
        else:
            p['exact'][i18n_mail._fold(en)] = cz


extra_cs()


class Sink(socketserver.StreamRequestHandler):
    """A mail relay on 127.0.0.1 that keeps what it is given - never the network."""
    got = []

    def handle(self):
        def w(s):
            self.wfile.write((s + '\r\n').encode())
        w('220 sink ESMTP')
        data, lines, rcpt = False, [], []
        while True:
            ln = self.rfile.readline()
            if not ln:
                return
            s = ln.decode('utf-8', 'replace').rstrip('\r\n')
            if data:
                if s == '.':
                    data = False
                    Sink.got.append((list(rcpt), '\r\n'.join(lines)))
                    lines, rcpt = [], []
                    w('250 kept')
                else:
                    lines.append(s[1:] if s.startswith('..') else s)
                continue
            c = s.split(' ')[0].upper()
            if c == 'EHLO':
                w('250-sink')
                w('250 8BITMIME')
            elif c == 'RCPT':
                rcpt.append(s.split(':', 1)[1].strip().strip('<>'))
                w('250 ok')
            elif c in ('MAIL', 'RSET', 'NOOP'):
                w('250 ok')
            elif c == 'DATA':
                data = True
                w('354 go on')
            elif c == 'QUIT':
                w('221 bye')
                return
            else:
                w('502 no')


def sink_start():
    srv = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Sink)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def openssl_cert(bits, days):
    d = tempfile.mkdtemp(prefix='acme-f140-cert-')
    try:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:%d' % bits, '-nodes',
                        '-keyout', os.path.join(d, 'k.pem'), '-out', os.path.join(d, 'c.pem'),
                        '-days', str(days), '-subj', '/CN=weak.example.test'],
                       check=True, capture_output=True, timeout=60)
        with open(os.path.join(d, 'c.pem')) as f:
            return f.read()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def seed(store):
    for t in ('certs', 'cert_teams', 'cert_reports', 'cert_report_runs', 'cert_jobs',
              'cert_deploys', 'cert_team_elevations', 'cert_team_reviews'):
        store.db.run('DELETE FROM %s' % t)
    store.db.run("DELETE FROM meta WHERE k LIKE 'digest:%' OR k LIKE 'reports:%'")
    if not store.db.row("SELECT id FROM cert_issuers WHERE name = 'self'"):
        store.db.insert('cert_issuers', {'name': 'self', 'kind': 'selfsigned', 'config': '{}',
                                         'enabled': 1})
    for name, mail, lang in (('jan', 'jan@example.test', 'en'), ('eva', 'eva@example.test', 'cs'),
                             ('nomail', '', None)):
        if not store.account(name):
            store.add_account(name, 'readonly', 'Pw-123456789-x!')
        store.set_account(name, mail=mail, prefs=json.dumps({'lang': lang} if lang else {}))
    T.save_team(store, {'name': 'Europe', 'kind': 'unit', 'contact_mail': 'eu@example.test'}, 'x')
    T.save_team(store, {'name': 'Web', 'parent': 'Europe', 'contact_mail': 'web@example.test',
                        'members': [{'who': 'local:jan', 'roles': ['Requester']},
                                    {'who': 'local:eva', 'roles': ['Approver']},
                                    {'who': 'local:nomail', 'roles': ['Viewer']}]}, 'x')
    T.save_team(store, {'name': 'Mail', 'parent': 'Europe'}, 'x')
    T.save_team(store, {'name': 'Quiet', 'contact_mail': 'quiet@example.test'}, 'x')
    now = time.time()
    ids = {}
    for name, owner, left, state, auto in (('shop', 'Web', 3, 'ok', 0), ('api', 'Web', 200, 'failed', 1),
                                           ('mx', 'Mail', 20, 'ok', 1), ('old', 'Web', -2, 'ok', 0),
                                           ('free', '', 10, 'ok', 1), ('gone', 'Web', 5, 'revoked', 0),
                                           ('ask', 'Web', 0, 'pending-approval', 0)):
        cid = A.cert_save(store, {'name': name, 'names': ['%s.example.test' % name], 'issuer': 'self',
                                  'key_type': 'ec-256', 'auto_renew': auto, 'owner': owner}, 'test')
        ids[name] = cid
        store.db.run('UPDATE certs SET state = ?, not_before = ?, not_after = ? WHERE id = ?',
                     (state, now - 30 * DAY if left else None, now + left * DAY if left else None,
                      cid))
    store.db.insert('cert_jobs', {'ts': now - 3600, 'kind': 'renew', 'cert_id': ids['api'],
                                  'state': 'failed', 'ok': 0, 'said': 'the CA said no: rateLimited'})
    store.db.insert('cert_jobs', {'ts': now - 30 * DAY, 'kind': 'renew', 'cert_id': ids['api'],
                                  'state': 'failed', 'ok': 0, 'said': 'long ago'})
    store.db.insert('cert_team_elevations', {'team': 'Web', 'who': 'local:jan', 'role': 'Renewer',
                                             'hours': 4, 'reason': 'the load balancer tonight',
                                             'state': 'waiting', 'asked': now - 600,
                                             'asked_by': 'jan'})
    store.db.insert('cert_team_elevations', {'team': 'Web', 'who': 'local:eva', 'role': 'Deployer',
                                             'hours': 8, 'state': 'granted', 'asked': now - 7200,
                                             'decided': now - 7000, 'until': now + 3600})
    return ids


class Units(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ids = seed(STORE)
        cls.saved = dict(E.CONFIG)
        E.CONFIG.update(mail_mode='off', mail_from='acme@example.test', mail_lang='en',
                        certs_certadmin_all=1)

    @classmethod
    def tearDownClass(cls):
        E.CONFIG.clear()
        E.CONFIG.update(cls.saved)

    def tearDown(self):
        E.CONFIG.update(mail_mode='off', certs_certadmin_all=1)

    def rep(self, kind, teams=(), **more):
        name = 'u-%s-%s' % (kind, '-'.join(teams) or 'all')
        old = RP.get_row(STORE, name)
        b = dict({'name': name, 'kind': kind, 'teams': list(teams), 'formats': ['csv', 'pdf']},
                 **more)
        if old:
            b['id'] = old['id']
        return RP.need(STORE, RP.save(STORE, b, 'test')['id'])

    # ---- the PDF and the CSV ---------------------------------------------------------------
    def test_pdf_valid_czech_many_pages(self):
        doc = P.Doc('Přehled certifikátů – ŽLUŤOUČKÝ kůň', 'acme · ďábel', '22.11.2026')
        doc.tiles([('Certifikátů', '300', 'info'), ('Končí', '3', 'warn')])
        doc.heading('Všechny', 'Řádky podle konce platnosti.')
        doc.table(['Jméno', 'Tým', '#Dní'], [['cert-%03d' % i, 'Tým Ěřů (ťď)', str(i)]
                                             for i in range(300)], {(1, 2): 'bad'})
        data = doc.output(lambda i, n: 'Strana %d z %d' % (i, n), 'patička')
        self.assertTrue(data.startswith(b'%PDF-1.4'))
        self.assertTrue(data.rstrip().endswith(b'%%EOF'))
        xref = int(data.rsplit(b'startxref', 1)[1].split()[0])
        self.assertTrue(data[xref:].startswith(b'xref'), 'startxref points at the xref table')
        path = os.path.join(TMP, 'u.pdf')
        with open(path, 'wb') as f:
            f.write(data)
        if shutil.which('pdftotext'):
            txt = subprocess.run(['pdftotext', '-layout', path, '-'], capture_output=True,
                                 text=True, timeout=60)
            self.assertEqual(txt.returncode, 0, txt.stderr)
            self.assertIn('Přehled certifikátů – ŽLUŤOUČKÝ kůň', txt.stdout)
            self.assertIn('Tým Ěřů (ťď)', txt.stdout)
            self.assertIn('cert-299', txt.stdout)
            pages = re.findall(r'Strana (\d+) z (\d+)', txt.stdout)
            self.assertGreater(len(pages), 3)
            self.assertTrue(all(b == pages[0][1] for _a, b in pages))
            # the table's head again on every page
            self.assertEqual(txt.stdout.count('JMÉNO'), len(pages))
        try:
            import pypdf
        except ImportError:
            return
        r = pypdf.PdfReader(path)
        self.assertGreater(len(r.pages), 3)
        self.assertIn('cert-150', ''.join(p.extract_text() for p in r.pages))

    def test_pdf_text_without_its_glyph(self):
        self.assertEqual(P.encode('a→b ✔'), b'a->b +')
        self.assertEqual(P.encode('Ő'), b'O')                   # no glyph here: its letter
        self.assertEqual(P.encode('日'), b'?')
        self.assertLess(P.width('iiii', 10), P.width('WWWW', 10))
        self.assertTrue(P.fit('a' * 400, 9, 50).endswith('…'))

    def test_csv(self):
        data = {'columns': [('a', 'Name'), ('b', '#Days')],
                'rows': [{'a': '=HYPERLINK("x")', 'b': '-3'}, {'a': 'Žluťoučký, "kůň"', 'b': '-'},
                         {'a': '@sum', 'b': '12'}]}
        raw = RP.render_csv(data)
        self.assertTrue(raw.startswith(b'\xef\xbb\xbf'))
        text = raw[3:].decode('utf-8')
        self.assertEqual(text.splitlines()[0], 'Name,Days')
        self.assertIn('"\'=HYPERLINK(""x"")",-3', text)
        self.assertIn('"Žluťoučký, ""kůň""",-', text)
        self.assertIn("'@sum,12", text)

    # ---- the kinds and their scope -------------------------------------------------------------
    def test_inventory_scope(self):
        whole = RP.build(STORE, self.rep('inventory'), lang='en')
        names = [r['name'] for r in whole['rows']]
        for n in ('shop', 'api', 'mx', 'old', 'free', 'gone'):
            self.assertIn(n, names)
        web = RP.build(STORE, self.rep('inventory', ['Web']), lang='en')
        self.assertEqual(sorted(r['name'] for r in web['rows']),
                         ['api', 'ask', 'gone', 'old', 'shop'])
        eu = RP.build(STORE, self.rep('inventory', ['Europe']), lang='en')
        self.assertIn('mx', [r['name'] for r in eu['rows']], 'the teams below too')
        self.assertNotIn('free', [r['name'] for r in eu['rows']], 'no team: only in every team')
        old = next(r for r in web['rows'] if r['name'] == 'old')
        self.assertEqual(old['state'], 'expired')
        self.assertEqual(old['left'], '-2')
        tiles = {a: b for a, b, _c in whole['tiles']}
        self.assertEqual(tiles['certificates'], len(whole['rows']))
        self.assertGreaterEqual(tiles['failed or expired'], 2)

    def test_expiry(self):
        got = RP.build(STORE, self.rep('expiry', ['Europe'], options={'days': 30}), lang='en')
        self.assertEqual([r['name'] for r in got['rows']], ['old', 'shop', 'mx'])
        self.assertNotIn('gone', [r['name'] for r in got['rows']], 'a revoked one is not due')
        self.assertTrue(got['sections'][0]['rows'])
        self.assertEqual(dict((a, b) for a, b, _c in got['tiles'])['within 7 days'], 1)

    def test_compliance_reuses_the_check(self):
        cid = self.ids['api']
        STORE.db.run('UPDATE certs SET cert_pem = ? WHERE id = ?', (openssl_cert(1024, 30), cid))
        try:
            got = RP.build(STORE, self.rep('compliance', ['Web']), lang='en')
        finally:
            STORE.db.run('UPDATE certs SET cert_pem = NULL WHERE id = ?', (cid,))
        row = next(r for r in got['rows'] if r['name'] == 'api')
        self.assertEqual(row['status'], 'does not comply')
        self.assertIn('RSA key of 1024 bits', row['findings'])

    def test_agents_and_access(self):
        STORE.db.insert('cert_targets', {'name': 'ag-web', 'kind': 'agent', 'config': '{}',
                                         'enabled': 1, 'owner': 'Web'})
        try:
            got = RP.build(STORE, self.rep('agents', ['Web']), lang='en')
            self.assertEqual([r['name'] for r in got['rows']], ['ag-web'])
            self.assertEqual(got['rows'][0]['state'], 'not joined yet')
        finally:
            STORE.db.run("DELETE FROM cert_targets WHERE name = 'ag-web'")
        acc = RP.build(STORE, self.rep('access', ['Europe']), lang='en')
        who = [(r['team'], r['member'], r['kind']) for r in acc['rows']]
        self.assertIn(('Web', 'local:jan', 'local'), who)
        self.assertIn(('Web', 'local:eva', 'temporary role'), who)
        self.assertNotIn('Quiet', [r['team'] for r in acc['rows']])

    def test_czech_words(self):
        got = RP.build(STORE, self.rep('expiry', ['Web']), lang='cs')
        heads = [h for _k, h in got['columns']]
        self.assertIn('Certifikát', heads)
        self.assertEqual(got['lang'], 'cs')
        self.assertRegex(got['rows'][0]['ends'], r'^\d\d\.\d\d\.\d{4}$')

    # ---- a run: kept, pruned, its files ------------------------------------------------------
    def test_run_keeps_and_prunes(self):
        r = self.rep('inventory', ['Web'], keep=2)
        for _ in range(3):
            run = RP.run(STORE, r, 'test')
        runs = RP.runs(STORE, r)
        self.assertEqual(len(runs), 2)
        self.assertEqual(runs[0]['id'], run['id'])
        pdf = base64.b64decode(RP.run_file(STORE, run['id'], 'pdf')['data_b64'])
        self.assertTrue(pdf.startswith(b'%PDF'))
        csv = base64.b64decode(RP.run_file(STORE, run['id'], 'csv')['data_b64']).decode('utf-8-sig')
        self.assertIn('shop', csv)
        self.assertFalse([x for x in RP.runs(STORE, r) if x['files'] and 'data_b64' in x['files'][0]],
                         'a list of runs carries no file')
        with self.assertRaises(ValueError):
            RP.save(STORE, {'name': 'x', 'kind': 'nope', 'formats': ['pdf']}, 'test')
        with self.assertRaises(ValueError):
            RP.save(STORE, {'name': 'x', 'kind': 'inventory', 'teams': ['No such']}, 'test')
        with self.assertRaises(ValueError):
            RP.save(STORE, {'name': 'x', 'kind': 'inventory', 'recipients': 'not-an-address'},
                    'test')

    # ---- the schedule -------------------------------------------------------------------------
    def test_due_period(self):
        mon = time.mktime((2026, 11, 23, 9, 0, 0, 0, 0, -1))           # a Monday, 09:00
        sch = {'every': 'weekly', 'day': 1, 'hour': 7, 'since': mon - 10 * DAY}
        self.assertEqual(RP.due_period(sch, mon)[0], 'w:2026-48')
        self.assertIsNone(RP.due_period(dict(sch, hour=10), mon)[0], 'not before its hour')
        self.assertIsNone(RP.due_period(dict(sch, since=mon - 3600), mon)[0],
                          'set after this week\'s moment: the next week\'s')
        self.assertEqual(RP.due_period({'every': 'monthly', 'day': 1, 'hour': 7,
                                        'since': mon - 40 * DAY}, mon)[0], 'm:2026-11')
        self.assertIsNone(RP.due_period({'every': 'off'}, mon)[0])
        cfg = dict(D.DEFAULTS, on=True, every='daily', hour=8, since=mon - DAY)
        self.assertEqual(D.due_period(cfg, mon), 'd:2026-11-23')
        self.assertIsNone(D.due_period(dict(cfg, on=False), mon))

    # ---- who may see which report ---------------------------------------------------------------
    def test_may_see(self):
        full = {'role': 'fulladmin', 'name': 'tester'}
        ca = {'role': 'certadmin', 'name': 'cm', 'account': {'source': 'local'}}
        ro = {'role': 'readonly', 'name': 'jan', 'account': {'source': 'local'}}
        web, eu, every = self.rep('expiry', ['Web']), self.rep('expiry', ['Europe']), \
            self.rep('expiry')
        self.assertTrue(all(RP.may_see(STORE, full, r) for r in (web, eu, every)))
        self.assertFalse(any(RP.may_see(STORE, ro, r) for r in (web, eu, every)))
        self.assertTrue(RP.may_see(STORE, ca, every), 'certs_certadmin_all on: every one')
        E.CONFIG['certs_certadmin_all'] = 0
        t = T.team_get(STORE, 'Web')
        ms = json.loads(t['members']) + [{'who': 'local:cm', 'rights': ['view', 'request',
                                                                       'manage']}]
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'parent': 'Europe',
                            'members': ms}, 'x')
        try:
            self.assertTrue(RP.may_see(STORE, ca, web))
            self.assertFalse(RP.may_see(STORE, ca, eu), 'Europe holds Mail, not theirs')
            self.assertFalse(RP.may_see(STORE, ca, every))
        finally:
            T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'parent': 'Europe',
                                'members': ms[:-1]}, 'x')

    # ---- the digest ----------------------------------------------------------------------------
    def test_digest_defaults_and_old_teams(self):
        t = T.team_get(STORE, 'Quiet')
        STORE.db.update('cert_teams', t['id'], {'extras': json.dumps({'review': {
            'every_days': 90, 'answer_days': 14, 'action': 'report'}})})
        cfg = D.config(T.team_get(STORE, 'Quiet'))
        self.assertFalse(cfg['on'])
        self.assertEqual((cfg['every'], cfg['days'], cfg['skip_empty']), ('weekly', 30, True))
        D.tick(STORE)
        self.assertIsNone(STORE.get_meta(D.META_LAST % t['id']), 'off: nothing is made')
        got = D.save(STORE, 'Quiet', {'on': True}, 'test')
        self.assertTrue(got['on'])
        self.assertIn('review', json.loads(T.team_get(STORE, 'Quiet')['extras']),
                      'the governance kept beside it')
        with self.assertRaises(ValueError):
            D.save(STORE, 'Web', {'on': True, 'members': ['local:stranger']}, 'test')
        with self.assertRaises(ValueError):
            D.save(STORE, 'Mail', {'on': True, 'contact': True}, 'test')   # no address anywhere
        D.save(STORE, 'Quiet', {'on': False}, 'test')

    def test_digest_contents(self):
        t = T.team_get(STORE, 'Web')
        data = D.collect(STORE, t, dict(D.DEFAULTS), time.time() - 7 * DAY)
        self.assertEqual([e['name'] for e in data['expiring']], ['shop'])
        self.assertEqual([e['name'] for e in data['expired']], ['old'])
        self.assertEqual([f['cert'] for f in data['failed']], ['api'])
        self.assertEqual(data['failed'][0]['times'], 1, 'only since the last digest')
        self.assertEqual([a['name'] for a in data['approvals']], ['ask'])
        self.assertEqual([e['who'] for e in data['elevations']], ['local:jan'])
        self.assertEqual([e['who'] for e in data['roles_now']], ['local:eva'])
        self.assertFalse(data['empty'])
        eu = D.collect(STORE, T.team_get(STORE, 'Europe'), dict(D.DEFAULTS),
                       time.time() - 7 * DAY)
        self.assertIn('mx', [e['name'] for e in eu['expiring']], 'the teams below')
        only = D.collect(STORE, T.team_get(STORE, 'Europe'), dict(D.DEFAULTS, below=False),
                         time.time() - 7 * DAY)
        self.assertTrue(only['empty'])
        subject, page, text, _d = D.build(STORE, t, dict(D.DEFAULTS), 'en', time.time() - 7 * DAY)
        self.assertIn('Web', subject)
        self.assertIn('<html lang="en"', page)
        for w in ('shop', 'old', 'rateLimited', 'Renewer', 'Deployer', '#settings/teams'):
            self.assertIn(w, page)
        self.assertIn('CERTIFICATES ENDING WITHIN 30 DAYS', text)
        self.assertNotIn('<', text.replace('<-', ''))
        # nothing secret: no key, no password, no webhook
        self.assertNotRegex(page, r'(?i)BEGIN [A-Z ]*PRIVATE|password|webhook')
        _s, cs, _t, _d = D.build(STORE, t, dict(D.DEFAULTS), 'cs', time.time() - 7 * DAY)
        self.assertIn('<html lang="cs"', cs)
        self.assertIn('Certifikát', cs)

    def test_digest_recipients_and_languages(self):
        t = T.team_get(STORE, 'Web')
        rec = D.recipients(STORE, t, dict(D.DEFAULTS, members=['local:jan', 'local:eva',
                                                                'local:nomail']))
        self.assertEqual([(r['mail'], r['lang']) for r in rec],
                         [('web@example.test', 'en'), ('jan@example.test', 'en'),
                          ('eva@example.test', 'cs')])
        rec = D.recipients(STORE, t, dict(D.DEFAULTS, contact=False, members=['local:jan'],
                                          lang='cs'))
        self.assertEqual([(r['mail'], r['lang']) for r in rec], [('jan@example.test', 'cs')])
        STORE.set_account('jan', disabled=1)
        try:
            self.assertEqual(D.recipients(STORE, t, dict(D.DEFAULTS, contact=False,
                                                         members=['local:jan'])), [])
        finally:
            STORE.set_account('jan', disabled=0)

    def test_digest_mail_off_and_empty(self):
        t = T.team_get(STORE, 'Web')
        rec = D.send(STORE, t, 'test', dict(D.DEFAULTS))
        self.assertFalse(rec['ok'])
        self.assertIn('switched off', rec['said'])
        ev = STORE.db.value("SELECT words FROM events WHERE words LIKE '%digest of the team Web%' "
                            "ORDER BY id DESC LIMIT 1", (), '')
        self.assertIn('mail is switched off', ev)
        q = T.team_get(STORE, 'Quiet')
        rec = D.send(STORE, q, 'test', dict(D.DEFAULTS))
        self.assertTrue(rec['skipped'], 'nothing needs Quiet: not sent')
        with self.assertRaises(E.ApiError):
            D.send_me(STORE, 'Web', {'name': 'jan'})

    def test_mails_through_a_sink(self):
        srv = sink_start()
        Sink.got[:] = []
        E.CONFIG.update(mail_mode='smtp', smtp_host='127.0.0.1', smtp_port=srv.server_address[1],
                        smtp_security='none', smtp_auth='none', smtp_user='', smtp_timeout_s=5)
        try:
            # the digest: one mail per language, HTML with a plain-text copy
            D.save(STORE, 'Web', {'on': True, 'contact': True, 'members': ['local:jan',
                                                                          'local:eva']}, 'test')
            got = D.send_now(STORE, 'Web', 'test')
            self.assertTrue(got['ok'], got)
            self.assertEqual(len(Sink.got), 2, [r for r, _m in Sink.got])
            to = sorted(sorted(r) for r, _m in Sink.got)
            self.assertEqual(to, [['eva@example.test'], ['jan@example.test', 'web@example.test']])
            msg = email.message_from_string(Sink.got[0][1])
            types = [p.get_content_type() for p in msg.walk()]
            self.assertIn('text/plain', types)
            self.assertIn('text/html', types)
            ev = STORE.db.value("SELECT words FROM events WHERE words LIKE 'the digest of the "
                                "team Web was sent%' ORDER BY id DESC LIMIT 1", (), '')
            self.assertIn('jan@example.test', ev)
            # a preview to one's own address only
            Sink.got[:] = []
            D._ME.clear()
            D.send_me(STORE, 'Web', {'name': 'eva'})
            self.assertEqual([r for r, _m in Sink.got], [['eva@example.test']])
            from email.header import decode_header, make_header
            subj = str(make_header(decode_header(email.message_from_string(Sink.got[0][1])['Subject'])))
            self.assertRegex(subj.lower(), r'preview|náhled')
            # the schedule: due now, sent once however often it looks
            Sink.got[:] = []
            t = T.team_get(STORE, 'Web')
            cfg = D.config(t)
            cfg.update(every='daily', hour=0, since=time.time() - 3 * DAY)
            ex = json.loads(t['extras'])
            ex['digest'] = cfg
            STORE.db.update('cert_teams', t['id'], {'extras': json.dumps(ex)})
            STORE.db.run('DELETE FROM meta WHERE k = ?', (D.META_PERIOD % t['id'],))
            D.tick(STORE)
            D.tick(STORE)
            self.assertEqual(len(Sink.got), 2, 'one period, one sending (two languages)')
            # a report with its files attached
            Sink.got[:] = []
            r = self.rep('expiry', ['Web'], recipients='boss@example.test')
            run = RP.run(STORE, r, 'test', send=True)
            self.assertTrue(run['ok'], run)
            self.assertEqual(run['sent_to'], ['boss@example.test'])
            msg = email.message_from_string(Sink.got[0][1])
            names = sorted(p.get_filename() for p in msg.walk() if p.get_filename())
            self.assertEqual([n.rsplit('.', 1)[1] for n in names], ['csv', 'pdf'])
            pdf = next(p for p in msg.walk() if (p.get_filename() or '').endswith('.pdf'))
            self.assertTrue(pdf.get_payload(decode=True).startswith(b'%PDF'))
            # the reports' schedule: claimed once per period
            Sink.got[:] = []
            STORE.db.update('cert_reports', r['id'], {'schedule': json.dumps({
                'every': 'weekly', 'day': 1, 'hour': 0, 'since': time.time() - 30 * DAY})})
            n = time.time()
            if RP.due_period(RP.need(STORE, r['id'])['schedule'], n)[0]:
                RP._reports_tick(STORE)
                RP._reports_tick(STORE)
                self.assertEqual(len(Sink.got), 1)
        finally:
            D.save(STORE, 'Web', {'on': False}, 'test')
            E.CONFIG.update(mail_mode='off')
            srv.shutdown()
            srv.server_close()

    def test_report_mail_off_says_so(self):
        r = self.rep('inventory', ['Web'], recipients='boss@example.test')
        run = RP.run(STORE, r, 'test', send=True)
        self.assertFalse(run['ok'])
        self.assertIn('switched off', run['said'])
        self.assertTrue(run['files'], 'made and kept all the same')

    # ---- an older database, the configuration's export ------------------------------------------
    def test_upgrade_and_carry(self):
        self.assertIn('cert_reports', E.CERT_CARRY_TABLES)
        self.assertNotIn('cert_report_runs', E.CERT_CARRY_TABLES)
        self.assertIn('cert_report_runs', E.TABLES)
        tmp = tempfile.mkdtemp(prefix='acme-f140-old-')
        try:
            path = os.path.join(tmp, 'old.db')
            import sqlite3
            con = sqlite3.connect(path)
            con.execute('CREATE TABLE cert_teams (id INTEGER PRIMARY KEY, name TEXT NOT NULL '
                        'UNIQUE, kind TEXT, members TEXT, contact_mail TEXT)')
            con.execute("INSERT INTO cert_teams (name, kind, members, contact_mail) VALUES "
                        "('Legacy', 'team', '[]', 'l@example.test')")
            con.commit()
            con.close()
            had = E.CONFIG.get('db_path')
            E.CONFIG['db_path'] = path
            try:
                st = acme.Storage(acme.open_db())
            finally:
                E.CONFIG['db_path'] = had
            self.assertEqual(RP.definitions(st), [])
            t = T.team_get(st, 'Legacy')
            self.assertFalse(D.config(t)['on'])
            RP.tick(st, force=True, wait=True)          # nothing defined: nothing happens
            self.assertEqual(st.db.value('SELECT COUNT(*) FROM cert_report_runs', (), 0), 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.rep('inventory', ['Web'])
        got = E.carry_export(STORE, False)
        rows = got.get('cert_reports') if isinstance(got, dict) else None
        if rows is not None:
            self.assertTrue(any(r.get('name') == 'u-inventory-Web' for r in rows))


# ---------------------------------------------------------------------------------------------
# A real daemon: the routes, their roles, the command line
# ---------------------------------------------------------------------------------------------
import test_certs_core as TCC  # noqa: E402


class Api(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    py = TCC.CertsCore.__dict__['py']
    cli = TCC.CertsCore.__dict__['cli']
    cli_ok = TCC.CertsCore.__dict__['cli_ok']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.seed_api()

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None, args=None, session=None):
        st, got = cls.call(method, path, body, session or cls.admin, args)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def seed_api(cls):
        m = cls.must
        m('POST', '/api/settings', {'settings': {'mail_mode': 'off', 'certs_certadmin_all': 0,
                                                 'certs_readonly_all': 0}})
        for name, role in (('cm', 'certadmin'), ('jan', 'readonly'), ('eva', 'readonly')):
            m('POST', '/api/users', {'action': 'add', 'name': name, 'role': role,
                                     'password': cls.pw, 'must_change': 0,
                                     'mail': '%s@example.test' % name})
        m('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                        'config': {'days': 40}})
        m('POST', '/api/teams/save', {'name': 'Europe', 'kind': 'unit',
                                      'contact_mail': 'eu@example.test'})
        m('POST', '/api/teams/save', {'name': 'Web', 'parent': 'Europe',
                                      'contact_mail': 'web@example.test',
                                      'members': [{'who': 'local:cm', 'roles': ['Certificate manager']},
                                                  {'who': 'local:jan', 'roles': ['Viewer']}]})
        m('POST', '/api/teams/save', {'name': 'Mail', 'parent': 'Europe'})
        now = time.time()
        stmts = []
        for name, owner, left in (('shop', 'Web', 3), ('api', 'Web', 200), ('mx', 'Mail', 20),
                                  ('old', 'Web', -2)):
            m('POST', '/api/certs/save', {'name': name, 'names': ['%s.example.test' % name],
                                          'issuer': 'self', 'key_type': 'ec-256',
                                          'auto_renew': 0, 'owner': owner})
            stmts.append(("UPDATE certs SET state = 'ok', not_before = ?, not_after = ? WHERE "
                          "name = ?", (now - 30 * DAY, now + left * DAY, name)))
        cls.sql(stmts)
        cls.s = {n: cls.login(n) for n in ('cm', 'jan', 'eva')}

    @classmethod
    def sql(cls, stmts):
        code = ('import sys, json; sys.path.insert(0, %r); import acme; acme.load_config(); '
                'st = acme.Storage(acme.open_db())\n'
                'for q, a in %r:\n    st.db.run(q, tuple(a))\nprint(1)\n' % (ROOT, stmts))
        got = subprocess.run([sys.executable, '-c', code], env=cls.env, capture_output=True,
                             text=True, timeout=180)
        if got.returncode:
            raise RuntimeError(got.stderr[-3000:])

    def test_10_nothing_until_defined(self):
        got = self.must('GET', '/api/reports')
        self.assertEqual(got['reports'], [])
        self.assertEqual([k['kind'] for k in got['kinds']],
                         ['inventory', 'expiry', 'compliance', 'agents', 'access'])
        d = self.must('GET', '/api/teams/digest', args={'team': 'Web'})
        self.assertFalse(d['digest']['on'])

    def test_20_roles(self):
        st, _ = self.call('GET', '/api/reports', None, self.s['jan'])
        self.assertEqual(st, 403, 'a reader sees no report')
        st, _ = self.call('POST', '/api/reports/save', {'name': 'x', 'kind': 'inventory'},
                          self.s['cm'])
        self.assertEqual(st, 403, 'a certificate administrator defines none')
        web = self.must('POST', '/api/reports/save', {
            'name': 'Web expiry', 'kind': 'expiry', 'teams': ['Web'], 'formats': ['pdf', 'csv'],
            'recipients': 'boss@example.test', 'schedule': {'every': 'weekly', 'day': 1,
                                                            'hour': 6}})['report']
        eu = self.must('POST', '/api/reports/save', {'name': 'Europe inventory',
                                                      'kind': 'inventory',
                                                      'teams': ['Europe']})['report']
        every = self.must('POST', '/api/reports/save', {'name': 'All access',
                                                         'kind': 'access'})['report']
        seen = [r['name'] for r in self.must('GET', '/api/reports', session=self.s['cm'])['reports']]
        self.assertEqual(seen, ['Web expiry'], 'only the reports of the teams they manage')
        mine = self.must('GET', '/api/reports', session=self.s['cm'])['reports'][0]
        self.assertNotIn('boss@example.test', json.dumps(mine), 'the recipients: a full '
                                                                'administrator\'s')
        for r in (eu, every):
            st, _ = self.call('GET', '/api/reports/one', None, self.s['cm'], {'id': r['id']})
            self.assertEqual(st, 403)
        st, _ = self.call('POST', '/api/reports/run', {'id': web['id']}, self.s['cm'])
        self.assertEqual(st, 403, 'running (and mailing) is a full administrator\'s')
        run = self.must('POST', '/api/reports/run', {'id': web['id'], 'send': True})['run']
        self.assertFalse(run['ok'], 'mail is off: not sent')
        self.assertIn('switched off', run['said'])
        got = self.must('GET', '/api/reports/download', args={'run': run['id'], 'format': 'pdf'},
                        session=self.s['cm'])
        self.assertTrue(base64.b64decode(got['data_b64']).startswith(b'%PDF'))
        self.assertTrue(got['filename'].endswith('.pdf'))
        run2 = self.must('POST', '/api/reports/run', {'id': eu['id']})['run']
        st, _ = self.call('GET', '/api/reports/download', None, self.s['cm'],
                          {'run': run2['id'], 'format': 'pdf'})
        self.assertEqual(st, 403)
        st, _ = self.call('GET', '/api/reports/download', None, self.s['jan'],
                          {'run': run['id'], 'format': 'pdf'})
        self.assertEqual(st, 403)
        pv = self.must('POST', '/api/reports/preview', {'id': web['id']}, session=self.s['cm'])
        self.assertEqual([r[0] for r in pv['preview']['rows']], ['old', 'shop'])
        st, _ = self.call('POST', '/api/reports/preview', {'draft': {'name': 'd',
                                                                     'kind': 'inventory'}},
                          self.s['cm'])
        self.assertEqual(st, 403)
        dr = self.must('POST', '/api/reports/preview', {'draft': {'name': 'd', 'kind': 'agents'}})
        self.assertEqual(dr['preview']['kind'], 'agents')
        st, _ = self.call('POST', '/api/reports/delete', {'id': every['id']}, self.s['cm'])
        self.assertEqual(st, 403)
        self.must('POST', '/api/reports/delete', {'id': every['id']})
        ev = self.py("print(json.dumps([r['words'] for r in st.db.rows(\"SELECT words FROM events "
                     "WHERE words LIKE '%report%' ORDER BY id\")]))")
        self.assertTrue(any('the report Web expiry was made' in w for w in ev), ev)
        self.assertTrue(any('downloaded the report Web expiry' in w for w in ev), ev)
        self.assertTrue(any('the report All access was deleted' in w for w in ev), ev)

    def test_30_digest_routes(self):
        st, _ = self.call('GET', '/api/teams/digest', None, self.s['eva'], {'team': 'Web'})
        self.assertEqual(st, 403, 'not a member, readers see only their teams')
        got = self.must('GET', '/api/teams/digest', args={'team': 'Web'}, session=self.s['jan'])
        self.assertFalse(got['may_change'])
        self.assertEqual(got['members'], [], 'who has an address: a full administrator\'s')
        st, _ = self.call('POST', '/api/teams/digest_save', {'team': 'Web', 'digest': {'on': True}},
                          self.s['cm'])
        self.assertEqual(st, 403)
        saved = self.must('POST', '/api/teams/digest_save', {'team': 'Web', 'digest': {
            'on': True, 'every': 'weekly', 'day': 5, 'hour': 9, 'members': ['local:jan']}})
        self.assertTrue(saved['digest']['on'])
        full = self.must('GET', '/api/teams/digest', args={'team': 'Web'})
        self.assertEqual({m['who']: m['mails'] for m in full['members']},
                         {'local:cm': 1, 'local:jan': 1})
        pv = self.must('POST', '/api/teams/digest_preview', {'team': 'Web', 'lang': 'en'},
                       session=self.s['jan'])['preview']
        self.assertIn('shop', pv['html'])
        self.assertNotIn('@', json.dumps(pv['recipients']), 'a reader sees no address')
        st, got = self.call('POST', '/api/teams/digest_send_me', {'team': 'Web'}, self.s['jan'])
        self.assertEqual(st, 409)
        self.assertIn('mail is switched off', got['error'])
        st, _ = self.call('POST', '/api/teams/digest_send', {'team': 'Web'}, self.s['cm'])
        self.assertEqual(st, 403)

    def test_40_command_line(self):
        out = self.cli_ok('--report-add', 'CLI inventory', '--report-kind', 'inventory',
                          '--report-teams', 'Web', '--report-formats', 'csv,pdf',
                          '--report-every', 'monthly', '--report-day', '1', '--report-hour', '6')
        self.assertIn('monthly, day 1 06:00', out.stdout)
        lst = json.loads(self.cli_ok('--reports', '--json').stdout)
        self.assertIn('CLI inventory', [r['name'] for r in lst['reports']])
        show = self.cli_ok('--report-show', 'CLI inventory')
        self.assertIn('shop', show.stdout)
        folder = os.path.join(self.tmp, 'out', 'cli')
        got = self.cli_ok('--report-run', 'CLI inventory', '--report-out', folder)
        self.assertIn('was made', got.stdout)
        files = sorted(os.listdir(folder))
        self.assertEqual([f.rsplit('.', 1)[1] for f in files], ['csv', 'pdf'])
        runs = json.loads(self.cli_ok('--report-runs', 'CLI inventory', '--json').stdout)['runs']
        path = os.path.join(self.tmp, 'out', 'one.pdf')
        self.cli_ok('--report-get', str(runs[0]['id']), '--report-format', 'pdf',
                    '--report-out', path)
        with open(path, 'rb') as f:
            self.assertTrue(f.read(5) == b'%PDF-')
        self.cli_ok('--report-edit', 'CLI inventory', '--report-name', 'CLI inv',
                    '--report-every', 'off')
        bad = self.cli('--reports', '--report-send')
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn('goes with --report-run', bad.stderr)
        self.cli_ok('--team-digest-set', 'Mail', '--digest', 'off')
        self.cli_ok('--team-digest-set', 'Europe', '--digest', 'on', '--digest-every', 'daily',
                    '--digest-hour', '8')
        shown = self.cli_ok('--team-digest', 'Europe')
        self.assertIn('on, every day at 08:00', shown.stdout)
        html = os.path.join(self.tmp, 'out', 'd.html')
        pv = self.cli_ok('--team-digest-preview', 'Europe', '--digest-lang', 'en',
                         '--report-out', html)
        self.assertIn('Europe', pv.stdout)
        with open(html, encoding='utf-8') as f:
            self.assertIn('<html lang="en"', f.read())
        no = self.cli('--team-digest-send', 'Europe')
        self.assertNotEqual(no.returncode, 0, 'asks first')
        self.cli_ok('--report-del', 'CLI inv', '--yes')
        sys.path.insert(0, ROOT)
        from acmelib.certs import console as C
        self.assertTrue(any(k == 'p' and 'Reports' in w for k, w, _f in C.main_items(object())))


# ---------------------------------------------------------------------------------------------
# The pages (Chromium)
# ---------------------------------------------------------------------------------------------
import test_teams_admin_ui as TAU  # noqa: E402


class Pages(Api):
    test_10_nothing_until_defined = test_20_roles = test_30_digest_routes = None
    test_40_command_line = None

    @classmethod
    def setUpClass(cls):
        if SCRATCH_CS and os.path.isfile(SCRATCH_CS):
            os.environ['ACME_EXTRA_CS'] = SCRATCH_CS
        Api.setUpClass.__func__(cls)
        cls.must('POST', '/api/teams/digest_save', {'team': 'Web', 'digest': {
            'on': True, 'every': 'weekly', 'day': 1, 'hour': 7, 'members': ['local:jan']}})

    pages = classmethod(TAU.Pages.__dict__['pages'].__func__)

    def test_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        try:
            got = subprocess.run([node, os.path.join(HERE, 'f140_reports_page.js'), base, self.pw,
                                  os.environ.get('ACME_SHOTS', '')],
                                 capture_output=True, text=True, timeout=1500, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [], seen['errors'])
        self.assertTrue(seen['emptyKinds'] >= 5, seen)
        self.assertTrue(seen['saved'], seen)
        self.assertGreater(seen['previewRows'], 0, seen)
        self.assertTrue(seen['pdf'], seen)
        self.assertTrue(seen['digestTab'], seen)
        self.assertTrue(seen['digestFrame'], seen)
        self.assertEqual(seen['cmNew'], 0, 'a certificate administrator defines none')
        self.assertEqual(seen['cmCards'], 1, seen)
        for w, over in seen['overflow'].items():
            self.assertEqual(over, [], (w, over))
        if SCRATCH_CS:
            self.assertEqual(seen.get('english', []), [], seen.get('english'))


def serve():
    Pages.setUpClass()
    php, base = Pages.pages()
    print('%s/admin/index.php  password %s  (tester full, cm certificate admin of Web, jan '
          'reader)' % (base, Pages.pw), flush=True)
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
