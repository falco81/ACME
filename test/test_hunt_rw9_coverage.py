#!/usr/bin/env python3
"""Hunt w9 (coverage): code the rest of the tests barely ran, run for what it does.

    python3 test/test_hunt_rw9_coverage.py

Measured with coverage over some 80 test files: these functions were run by none of them (or
by a line or two). Each is run here for its real behaviour - the calendar's windows, feeds and
.ics, the published CRL checked over HTTP, the search box's values, a module cloned with its
credentials, a catalog loaded, the plan sandbox's masks, SCTs read, the periods missed, the
tests run from the command line - and what it got wrong fixed beside it.
"""
import base64
import datetime
import http.server
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-rw9-cov-')
os.makedirs(os.path.join(TMP, 'plugins', 'targets'), exist_ok=True)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
FAKE = r'''
from acmelib.plugins.base import Target, PluginError, field


class ListTarget(Target):
    kind = 'w9list'
    title = 'A target with a list (tests)'
    vendor = 'Test'
    fields = [field('host', 'Host', 'text', required=True),
              field('password', 'Password', 'secret'),
              field('vdom', 'VDOM', 'text'),
              field('product', 'Product', 'catalog', catalog='products')]
    deploy_fields = [field('vdom', 'VDOM', 'text'),
                     field('rule', 'Rule', 'catalog', catalog='rules')]

    def catalog(self, key):
        self.ctx.step('asked for %s with %s' % (key, self.c('vdom') or '-'))
        if self.c('password') != 'kept-s3cret':
            raise PluginError('the password was not the one kept')
        if key == 'products':
            return {'options': [['a', 'Product A'], ['b'], 'junk'], 'sets': {'a': {'vdom': 'x'},
                    'b': 'junk'}, 'pick': 'b'}
        return {'options': [[n, n] for n in (getattr(self, 'hint_names', None) or [])],
                'pick': 'nowhere', 'said': 'rules of %s' % (self.c('vdom') or '-')}

    def deploy(self, bundle, options):
        return 'ok'
'''
with open(os.path.join(TMP, 'plugins', 'targets', 'w9list.py'), 'w') as f:
    f.write(FAKE)
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402  (the routes)
from acmelib.certs import store as S  # noqa: E402
from acmelib.certs import teams as T  # noqa: E402
from acmelib.certs import expirycal as X  # noqa: E402
from acmelib.certs import listsearch as L  # noqa: E402
from acmelib.certs import publish as PUB  # noqa: E402
from acmelib.certs import api_catalog, api_ctxmenu  # noqa: E402

STORE = acme.Storage(acme.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DAY = 86400


class FakeH(object):
    def __init__(self, who='boss', role='fulladmin', body=None, args=None):
        self.store, self._body = STORE, dict(body or {})
        self.who, self.role = who, role
        self.headers, self.args = {}, dict(args or {})

    def me(self, _role='readonly'):
        return {'name': self.who, 'role': self.role,
                'account': {'name': self.who, 'role': self.role, 'source': 'local',
                            'dn': '', 'group_list': ''}}

    def body(self):
        return self._body

    def arg(self, name, default=''):
        return self.args.get(name, default)


def sess(who='boss', role='fulladmin'):
    return FakeH(who, role).me()


def add_cert(name, days_left, **more):
    now = time.time()
    row = {'name': name, 'cn': name + '.example.test',
           'names': json.dumps([name + '.example.test']), 'state': 'ok',
           'not_before': now - 10 * DAY, 'not_after': now + days_left * DAY,
           'auto_renew': 1, 'enabled': 1, 'issuer': 'self', 'renew_days': 30}
    row.update(more)
    return STORE.db.insert('certs', row)


def clean():
    for t in ('certs', 'cert_deploys', 'cert_teams'):
        STORE.db.run('DELETE FROM %s' % t)
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'certs:calfeed%'")
    T.changed()
    if not STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'self'"):
        STORE.db.insert('cert_issuers', {'name': 'self', 'kind': 'selfsigned', 'config': '{}',
                                         'enabled': 1})


# ---------------------------------------------------------------------------
# The expiry calendar
# ---------------------------------------------------------------------------
class Calendar(unittest.TestCase):
    def setUp(self):
        clean()

    def test_window_refusals(self):
        with self.assertRaises(ValueError):
            X.window('2026-13-01', '')
        with self.assertRaises(ValueError):
            X.window('2026-05-02', '2026-05-01')
        with self.assertRaises(ValueError):
            X.window('2026-01-01', '2028-06-01')
        a, b = X.window('2026-05-01', '2026-05-01')
        self.assertAlmostEqual(b - a, DAY, delta=3700)      # one whole day (DST aside)

    def test_week_counts_only_in_the_window(self):
        """The weeks of the window: what ends (or is renewed) outside the window but inside
        the first or last week (partial) is not counted - `acme --calendar` said more ran out
        than it listed."""
        start, end = X.window('2026-05-06', '2026-05-12')        # Wednesday to Tuesday
        mid = X._ts_of_day('2026-05-08') + 12 * 3600
        before = X._ts_of_day('2026-05-05') + 12 * 3600          # the Tuesday before
        after = X._ts_of_day('2026-05-14') + 12 * 3600           # the Thursday after
        e = [{'not_after': mid, 'renew_at': None},
             {'not_after': after, 'renew_at': mid},
             {'not_after': before + 400 * DAY, 'renew_at': before}]
        weeks = X.week_counts(e, start, end)
        self.assertEqual([w['week'] for w in weeks], ['2026-05-04', '2026-05-11'])
        self.assertEqual(sum(w['ends'] for w in weeks), 1, weeks)
        self.assertEqual(sum(w['renews'] for w in weeks), 1, weeks)

    def test_renew_at(self):
        now = time.time()
        row = {'auto_renew': 1, 'enabled': 1, 'issuer': 'self', 'state': 'ok',
               'not_before': now - 60 * DAY, 'not_after': now + 30 * DAY, 'renew_days': 10}
        self.assertAlmostEqual(X.renew_at(row), now + 20 * DAY, delta=5)
        self.assertAlmostEqual(X.renew_at(dict(row, ari=json.dumps({'at': now + DAY}))),
                               now + DAY, delta=5)
        self.assertAlmostEqual(X.renew_at(dict(row, ari=json.dumps({'at': now + 29 * DAY}))),
                               now + 20 * DAY, delta=5)      # an ARI window later: not later
        self.assertAlmostEqual(X.renew_at(dict(row, ari='{"at": "x"}')), now + 20 * DAY, delta=5)
        for no in ({'auto_renew': 0}, {'enabled': 0}, {'issuer': ''}, {'state': 'held'},
                   {'state': 'revoked'}, {'not_after': None}, {'not_after': 'x'}):
            self.assertIsNone(X.renew_at(dict(row, **no)), no)

    def test_admin_rows_filters(self):
        T.team_save(STORE, {'name': 'Web'}, 'boss') if hasattr(T, 'team_save') else None
        a = add_cert('a', 10, owner='Web')
        b = add_cert('b', 20, owner='local:eva', issuer='other')
        add_cert('c', 30, created_by='eva')
        add_cert('gone', -20)                                   # ran out before the window
        add_cert('rev', 15, state='revoked')
        STORE.db.insert('cert_deploys', {'cert_id': b, 'target': 'web1', 'options': '{}'})
        s = sess()
        start, end = X.window('', '')
        names = lambda rows: sorted(r['name'] for r in rows[0])     # noqa: E731
        self.assertEqual(names(X.admin_rows(STORE, s, start, end)), ['a', 'b', 'c'])
        self.assertEqual(names(X.admin_rows(STORE, s, start, end, issuer='other')), ['b'])
        self.assertEqual(names(X.admin_rows(STORE, s, start, end, target='web1')), ['b'])
        eva = sess('eva', 'readonly')
        self.assertEqual(names(X.admin_rows(STORE, eva, start, end, mine=True)), ['b', 'c'])
        got = X.answer(STORE, s, '', '')
        self.assertEqual(got['count'], 3)
        self.assertEqual(sum(w['ends'] for w in got['weeks']), 3)
        self.assertEqual(sum(d['ends'] for d in got['counts'].values()), 3)
        self.assertIn(a, [e['id'] for e in got['certs']])
        worst = {d['worst'] for d in got['counts'].values()}
        self.assertIn('warn', worst)

    def test_feed_link_round_trip(self):
        if not STORE.account('feedy'):
            STORE.add_account('feedy', 'readonly', 'Local-Only-Pw-77!feedy')
        tok = X.feed_new(STORE, 'feedy', 'cs', 'Europe/Prague')
        s, got = X.feed_session(STORE, tok)
        self.assertEqual((s['name'], s['role'], got['lang'], got['tz']),
                         ('feedy', 'readonly', 'cs', 'Europe/Prague'))
        self.assertEqual(X.feed_of(STORE, 'FEEDY')['lang'], 'cs')
        self.assertEqual([f['who'] for f in X.feeds(STORE)], ['feedy'])
        self.assertEqual(X.feed_session(STORE, 'short'), (None, None))
        self.assertEqual(X.feed_session(STORE, 'x' * 43), (None, None))
        tok2 = X.feed_new(STORE, 'feedy', 'xx-bad', 'Not/A/Zone/At/All')  # the old one stops
        self.assertEqual(X.feed_session(STORE, tok), (None, None))
        s, got = X.feed_session(STORE, tok2)
        self.assertEqual((got['lang'], got.get('tz')), ('en', None))
        # the account made again under the same name: somebody else
        STORE.db.run('UPDATE accounts SET created = ? WHERE LOWER(name) = ?',
                     (time.time() + 99, 'feedy'))
        self.assertEqual(X.feed_session(STORE, tok2), (None, None))
        self.assertTrue(X.feed_revoke(STORE, 'feedy', by='boss'))
        self.assertFalse(X.feed_revoke(STORE, 'feedy', by='boss'))
        self.assertIsNone(X.feed_of(STORE, 'feedy'))

    def test_ics_lines_folded_and_escaped(self):
        now = time.time()
        long_name = 'č' * 60 + ';,\\x'
        e = X.entry({'id': 7, 'name': long_name, 'names': ['a.example.test'], 'owner': 'Web',
                     'issuer': 'self', 'state': 'ok', 'not_before': now - DAY,
                     'not_after': now + 40 * DAY, 'auto_renew': 1, 'enabled': 1,
                     'renew_days': 30})
        text = X.ics([e], 'en', 'Site, one', tz='Pacific/Kiritimati')
        self.assertTrue(text.endswith('\r\n'))
        for line in text.split('\r\n'):
            self.assertLessEqual(len(line.encode('utf-8')), 75, line)
        flat = text.replace('\r\n ', '')
        self.assertIn('X-WR-CALNAME:Site\\, one - certificates running out', flat)
        self.assertIn('\\;\\,\\\\x runs out', flat)
        self.assertEqual(flat.count('BEGIN:VEVENT'), 2)
        self.assertEqual(flat.count('BEGIN:VALARM'), 1)
        day = datetime.datetime.fromtimestamp(now + 40 * DAY,
                                              X.zone('Pacific/Kiritimati')).strftime('%Y%m%d')
        self.assertIn('DTSTART;VALUE=DATE:' + day, flat)
        self.assertIsNone(X.zone('../etc/passwd'))
        self.assertEqual(X.zone_name('Nowhere/Land'), '')


class CalendarCli(unittest.TestCase):
    """acme --calendar: the count said is the count listed."""

    def test_count_said_is_count_listed(self):
        tmp = tempfile.mkdtemp(prefix='acme-rw9-cal-')
        with open(os.path.join(tmp, 'config.json'), 'w') as f:
            f.write('{}')
        env = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
        env.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(tmp, 'config.json'),
                   ACME_STATE=tmp, ACME_RUN=tmp, ACME_LOGDIR=tmp, NO_COLOR='1',
                   ACME_CONSOLE_FLAG=os.path.join(tmp, 'console-flag'))
        code = ('import sys, json, time; sys.path.insert(0, %r)\n'
                'import acme\nst = acme.Storage(acme.open_db())\n'
                'import datetime\n'
                'def ts(d): return time.mktime(datetime.date.fromisoformat(d).timetuple()) + 43200\n'
                'for n, d in (("inside", "2026-05-08"), ("after", "2026-05-14")):\n'
                '    st.db.insert("certs", {"name": n, "names": "[]", "state": "ok", '
                '"not_after": ts(d), "not_before": ts(d) - 90 * 86400, "auto_renew": 1, '
                '"enabled": 1, "issuer": "x", "renew_days": 5})\n' % ROOT)
        made = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True,
                              text=True, timeout=120)
        self.assertEqual(made.returncode, 0, made.stderr)
        got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--calendar',
                              '--from', '2026-05-06', '--weeks', '1'], env=env,
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('Certificates running out from 2026-05-06 to 2026-05-12: 1', got.stdout)
        self.assertIn('inside', got.stdout)
        self.assertNotIn('after', got.stdout.split('runs out')[-1])


# ---------------------------------------------------------------------------
# The CRL and certificate published on acme, checked over HTTP
# ---------------------------------------------------------------------------
class PkiServer(object):
    """/pki/ answered as web/pki.php answers it - from publish.serve; `bend` turns answers."""
    bend = {}

    def __init__(self):
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                name = self.path.rsplit('/', 1)[-1]
                b = outer.bend.get(name)
                if b == 404:
                    self.send_error(404)
                    return
                slug, _, ext = name.partition('.')
                try:
                    data, mime, _fn = PUB.serve(STORE, 'crl' if ext.startswith('crl') else 'cert',
                                                slug, 'pem' if ext in ('crl.pem', 'pem') else 'der')
                except LookupError:
                    self.send_error(404)
                    return
                if isinstance(b, tuple):
                    data, mime = b
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        self.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


class Published(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from acmelib.certs import ca
        cls.ca = ca
        cls.srv = PkiServer()
        E.CONFIG.update(pki_publish=1, pki_base_url='http://127.0.0.1:%d/pki/' % cls.srv.port)
        cls.root = ca.ca_create(STORE, 'W9 Root', 'CN=W9 Root', key_type='ec-256', days=400)
        cls.other = ca.ca_create(STORE, 'W9 Other', 'CN=W9 Other', key_type='ec-256', days=400)
        ca.ca_crl(STORE, cls.root)
        ca.ca_crl(STORE, cls.other)

    @classmethod
    def tearDownClass(cls):
        cls.srv.srv.shutdown()
        E.CONFIG.pop('pki_base_url', None)

    def setUp(self):
        PkiServer.bend = {}

    def test_check_right(self):
        got = PUB.check(STORE, self.root)
        self.assertTrue(got['ok'], got['steps'])
        words = ' | '.join(w for _l, w in got['steps'])
        self.assertIn('its signature is the authority', words)
        self.assertIn('what is published is right', words)
        self.assertIn('application/pkix-crl', words)

    def test_check_wrong_answers(self):
        slug = PUB.slug_of(STORE, PUB._row(STORE, self.root))
        oslug = PUB.slug_of(STORE, PUB._row(STORE, self.other))
        other_crl, _m, _f = PUB.serve(STORE, 'crl', oslug)
        other_crt, _m, _f = PUB.serve(STORE, 'cert', oslug)
        PkiServer.bend = {slug + '.crl': (other_crl, 'text/plain'),
                          slug + '.crt': (other_crt, 'application/pkix-cert')}
        got = PUB.check(STORE, self.root)
        self.assertFalse(got['ok'])
        levels = [l for l, _w in got['steps']]
        words = ' | '.join(w for _l, w in got['steps'])
        self.assertIn('warn', levels)                       # the content type
        self.assertIn('is not the authority', words)        # the issuer
        self.assertIn('does not verify', words)             # the signature
        self.assertIn('not the authority\'s', words)        # the certificate
        PkiServer.bend = {slug + '.crl': 404, slug + '.crt': (b'junk', 'text/plain')}
        got = PUB.check(STORE, self.root)
        self.assertFalse(got['ok'])
        words = ' | '.join(w for _l, w in got['steps'])
        self.assertIn('HTTP 404', words)
        self.assertIn('not a certificate', words)

    def test_check_not_published(self):
        PUB.set_published(STORE, self.other, False, 'boss')
        try:
            got = PUB.check(STORE, self.other)
            self.assertFalse(got['ok'])
            self.assertIn('is not published', got['steps'][0][1])
            oslug = PUB.slug_of(STORE, PUB._row(STORE, self.other))
            with self.assertRaises(LookupError):
                PUB.serve(STORE, 'crl', oslug)
        finally:
            PUB.set_published(STORE, self.other, True, 'boss')
        E.CONFIG['pki_publish'] = 0
        try:
            got = PUB.check(STORE, self.root)
            self.assertIn('switched off', got['steps'][0][1])
            self.assertEqual(PUB.index(STORE), [])
        finally:
            E.CONFIG['pki_publish'] = 1
        with self.assertRaises(LookupError):
            PUB.check(STORE, 999999)

    def test_renamed_old_slug_answers(self):
        from acmelib.certs import api_cas
        sub = self.ca.ca_create(STORE, 'W9 Renamed', 'CN=W9 Renamed', key_type='ec-256', days=300)
        before = PUB.slug_of(STORE, PUB._row(STORE, sub))
        got = api_cas.ca_save(STORE, {'id': sub, 'name': 'W9 Renamed Two', 'crl_url': 'own',
                                      'aia_url': 'own'}, 'boss')
        after = PUB.slug_of(STORE, PUB._row(STORE, sub))
        self.assertNotEqual(before, after)
        self.assertTrue(any('/pki/%s.crl' % after in w for w in got['warnings']), got)
        for slug in (before, after):
            data, mime, fn = PUB.serve(STORE, 'cert', slug, 'pem')
            self.assertTrue(data.startswith(b'-----BEGIN CERTIFICATE'))
            self.assertEqual(fn, after + '.pem')
        row = PUB._row(STORE, sub)
        self.assertEqual(row['crl_url'], PUB.urls(STORE, row)['crl'])
        # named back: the first slug is its own again, the second answers still
        api_cas.ca_save(STORE, {'id': sub, 'name': 'W9 Renamed'}, 'boss')
        self.assertEqual(PUB.slug_of(STORE, PUB._row(STORE, sub)), before)
        self.assertEqual(PUB.find(STORE, after)['id'], sub)
        with self.assertRaises(ValueError):
            api_cas.ca_save(STORE, {'id': sub, 'ocsp_url': 'own'}, 'boss')
        got = api_cas.ca_save(STORE, {'id': sub, 'disabled': True}, 'boss')
        self.assertTrue(any('signs nothing now' in w for w in got['warnings']), got)
        got = api_cas.ca_save(STORE, {'id': sub, 'enabled': True}, 'boss')
        self.assertEqual(got['changed'].get('disabled'), [1, 0])
        self.assertEqual(api_cas.ca_save(STORE, {'id': sub}, 'boss')['message'],
                         'nothing was changed')

    def test_rate_per_source(self):
        PUB._RATE_OF.clear()
        PUB._RATE.update(t=time.monotonic(), tokens=PUB.RATE_ALL_PER_S * 2)
        n = 0
        while PUB.allowed('198.51.100.7') and n < 1000:
            n += 1
        self.assertLessEqual(n, PUB.RATE_ONE_BURST + 2)
        self.assertTrue(PUB.allowed('198.51.100.300'))          # not an address: its own bucket
        self.assertFalse(PUB.allowed('198.51.100.8'))           # the same /24
        self.assertTrue(PUB.allowed('203.0.113.1'))             # another source


# ---------------------------------------------------------------------------
# The search box: values offered as one types
# ---------------------------------------------------------------------------
class SearchValues(unittest.TestCase):
    def setUp(self):
        clean()
        add_cert('one', 50, tags=json.dumps(['prod', 'web']), owner='Web')
        add_cert('two', 60, tags=json.dumps(['prod']), owner='Db', state='failed')
        add_cert('three', 70, tags='not json', owner='')

    def test_values(self):
        h = FakeH()
        self.assertEqual([(v['val'], v['n']) for v in L.values(h, 'tag', '')],
                         [('prod', 2), ('web', 1)])
        self.assertEqual([v['val'] for v in L.values(h, 'tag', 'we*')], ['web'])
        self.assertEqual([v['val'] for v in L.values(h, 'state', '')], ['ok', 'failed'])
        self.assertEqual([v['val'] for v in L.values(h, 'renew', 'Y')], ['yes'])
        self.assertEqual(L.values(h, 'note', ''), [])           # not offered
        self.assertEqual(L.values(h, 'nothing', ''), [])
        self.assertEqual([v['val'] for v in L.values(h, 'dns', 'two')], ['two.example.test'])
        self.assertEqual([v['val'] for v in L.values(h, 'owner', 'd')], ['Db', 'Web'][:1])

    def test_where_serial_with_colons(self):
        sql, args = L.where('serial:1F:AB:03')
        self.assertIn('1fab03', ''.join(str(a).lower() for a in args))
        sql, args = L.where('1F:AB')
        self.assertIn('%1fab%', [str(a).lower() for a in args])
        self.assertEqual(L.where(''), ('', []))
        with self.assertRaises(ValueError):
            L.where('(state:ok')


# ---------------------------------------------------------------------------
# A module's list loaded (catalog) and a module cloned with its credentials
# ---------------------------------------------------------------------------
class CatalogAndCopy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        STORE.db.run("DELETE FROM cert_targets WHERE name LIKE 'w9-%'")
        cls.tid = A.family_save(STORE, 'target', {'name': 'w9-list', 'kind': 'w9list', 'config': {
            'host': 'h1', 'password': 'kept-s3cret', 'vdom': 'root'}}, 'boss')

    def test_catalog_with_the_kept_secret(self):
        got = api_catalog.catalog(STORE, 'target', {'id': self.tid, 'field': 'product',
                                                    'config': {'password': '••••••'}})
        self.assertEqual(got['options'], [['a', 'Product A'], ['b', 'b']])
        self.assertEqual(got['sets'], {'a': {'vdom': 'x'}})
        self.assertEqual(got['pick'], 'b')
        self.assertEqual(got['said'], '2')
        self.assertIn('asked for products with root', got['steps'])

    def test_catalog_deploy_field_empty_keeps_the_targets(self):
        got = api_catalog.catalog(STORE, 'target', {'id': self.tid, 'field': 'rule',
                                                    'config': {'vdom': ''},
                                                    'names': ['www.example.test', 7, '']})
        self.assertEqual(got['said'], 'rules of root')
        self.assertEqual(got['options'], [['www.example.test', 'www.example.test']])
        self.assertEqual(got['pick'], '')                       # not one of the options
        got = api_catalog.catalog(STORE, 'target', {'id': self.tid, 'field': 'rule',
                                                    'config': {'vdom': 'dmz'}})
        self.assertEqual(got['said'], 'rules of dmz')

    def test_catalog_refusals(self):
        from acmelib.plugins.base import PluginError
        with self.assertRaises(ValueError):
            api_catalog.catalog(STORE, 'target', {'id': self.tid, 'field': 'host'})
        with self.assertRaises(LookupError):
            api_catalog.catalog(STORE, 'target', {'id': 987654, 'field': 'product'})
        with self.assertRaises(ValueError):
            api_catalog.catalog(STORE, 'target', {'kind': 'no_such_kind', 'field': 'product'})
        with self.assertRaises(PluginError):        # unsaved: no secret kept to fall back on
            api_catalog.catalog(STORE, 'target', {'kind': 'w9list', 'field': 'product',
                                                  'config': {'host': 'h'}})

    def test_save_copy(self):
        got = api_ctxmenu.save_copy(STORE, 'target', {
            'copy_of': self.tid, 'name': 'w9-copy', 'kind': 'w9list',
            'config': {'host': 'h2', 'password': '••••'}}, 'boss')
        self.assertEqual(got['copied'], ['password'])
        row = S.plugin_row(STORE, 'target', got['id'])
        cfg = S.plugin_config('target', row)
        self.assertEqual((cfg['host'], cfg['password']), ('h2', 'kept-s3cret'))
        self.assertNotIn('kept-s3cret', row['config'])          # sealed again, for its place
        got2 = api_ctxmenu.save_copy(STORE, 'target', {
            'copy_of': self.tid, 'name': 'w9-copy2', 'kind': 'w9list',
            'config': {'host': 'h3', 'password': 'own-one'}}, 'boss')
        self.assertEqual(got2['copied'], [])
        self.assertEqual(S.plugin_config('target', S.plugin_row(STORE, 'target', got2['id']))
                         ['password'], 'own-one')
        for bad, err in (({'copy_of': self.tid, 'id': 3, 'name': 'w9-x'}, ValueError),
                         ({'copy_of': 987654, 'name': 'w9-x'}, LookupError),
                         ({'copy_of': self.tid, 'name': 'w9-x', 'kind': 'fortigate'}, ValueError),
                         ('not a dict', ValueError)):
            with self.assertRaises(err, msg=bad):
                api_ctxmenu.save_copy(STORE, 'target', bad, 'boss')



# ---------------------------------------------------------------------------
# Small readers: times, SCTs, an ACME request shown, the plan's DNS, masks
# ---------------------------------------------------------------------------
class Readers(unittest.TestCase):
    def test_epoch(self):
        want = 1767225600.0                                     # 2026-01-01 00:00 UTC
        for v in ('2026-01-01T00:00:00Z', '2026-01-01 00:00:00', 'Jan 01 00:00:00 2026 GMT',
                  '20260101000000Z', '2026-01-01T01:00:00+0100', want, int(want), str(want),
                  datetime.datetime(2026, 1, 1),
                  datetime.datetime(2026, 1, 1, 1, tzinfo=datetime.timezone(
                      datetime.timedelta(hours=1)))):
            self.assertEqual(S.epoch(v), want, v)
        for v in (None, '', 'soon'):
            self.assertIsNone(S.epoch(v))

    def test_sct_list(self):
        from acmelib.certs import certview
        log_id = bytes(range(32))

        def sct(ts_ms, hash_alg=4, sig_alg=3):
            body = bytes([0]) + log_id + struct.pack('>Q', ts_ms) + struct.pack('>H', 0) + \
                bytes([hash_alg, sig_alg]) + struct.pack('>H', 3) + b'sig'
            return struct.pack('>H', len(body)) + body
        lst = sct(1767225600123) + sct(1767225601000, 5, 1) + struct.pack('>H', 4) + b'tiny'
        raw = struct.pack('>H', len(lst)) + lst
        der = b'\x04' + bytes([0x81, len(raw)]) + raw if len(raw) > 127 else \
            b'\x04' + bytes([len(raw)]) + raw
        for given in (raw, der):
            got = certview._sct_list(given)
            self.assertEqual(len(got), 2)                       # the short one passed over
            self.assertEqual(got[0]['ts'], 1767225600)
            self.assertEqual(got[0]['version'], 1)
            self.assertEqual(got[0]['sig'], 'ECDSA SHA-256')
            self.assertEqual(got[1]['sig'], 'RSA SHA-384')
            self.assertEqual(got[0]['log_id_hex'], log_id.hex().upper())
        self.assertEqual(certview._sct_list(b'\x00'), [])

    def test_jws_shown(self):
        from acmelib.certs import plansandbox as PS

        def b64u(o):
            return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip('=')
        n = base64.urlsafe_b64encode(b'\x01' * 256).decode().rstrip('=')
        eab = {'protected': b64u({'alg': 'HS256', 'kid': 'eab-kid', 'url': 'u'}),
               'payload': b64u({'kty': 'RSA'}), 'signature': 'c2ln'}
        body = {'protected': b64u({'alg': 'RS256', 'jwk': {'kty': 'RSA', 'e': 'AQAB', 'n': n},
                                   'nonce': 'n1', 'url': 'https://ca/new-acct'}),
                'payload': b64u({'termsOfServiceAgreed': True, 'externalAccountBinding': eab,
                                 'csr': 'A' * 400}),
                'signature': 'c2lnbmF0dXJl'}
        got = PS.jws_shown(json.dumps(body).encode(), {})
        self.assertIn('2048 bits', got['protected']['jwk']['n'])
        self.assertEqual(got['signature'], '•••• (signature)')
        self.assertEqual(got['payload']['externalAccountBinding']['protected']['kid'], 'eab-kid')
        self.assertIn('HMAC', got['payload']['externalAccountBinding']['signature'])
        self.assertIn('CSR', got['payload']['csr'])
        post_as_get = dict(body, payload='')
        self.assertEqual(PS.jws_shown(post_as_get, {})['payload'], '')
        for bad in (b'not json', {'protected': 'x'}, {'protected': '!!', 'payload': '',
                                                       'signature': ''}):
            self.assertIsNone(PS.jws_shown(bad, {}))

    def test_mask_text_base64(self):
        from acmelib.certs import plansandbox as PS
        key_pem = '-----BEGIN PRIVATE KEY-----\n' + 'A' * 200 + '\n-----END PRIVATE KEY-----\n'
        crt_pem = '-----BEGIN CERTIFICATE-----\n' + 'B' * 200 + '\n-----END CERTIFICATE-----\n'
        b = lambda x: base64.b64encode(x if isinstance(x, bytes) else x.encode()).decode()  # noqa
        got = PS.mask_text('k=' + b(key_pem), {})
        self.assertIn('private key, PEM, base64', got)
        self.assertNotIn(b(key_pem)[:40], got)
        self.assertIn('certificate PEM, base64', PS.mask_text(b(crt_pem), {}))
        self.assertIn('binary, base64', PS.mask_text(b(os.urandom(120)), {}))
        plain = b('just some words that are long enough to be a run of base64 ' * 3)
        self.assertEqual(PS.mask_text(plain, {}), plain)        # words, not a secret
        self.assertEqual(PS.mask_text('x PLANSECRET1 y', {'PLANSECRET1': 'password'}),
                         'x •••• (password) y')

    def test_dns_answer(self):
        from acmelib.certs import plansandbox as PS
        from acmelib.plugins.challenges import _dns as D
        m = D.Message(7, 0x0100)
        m.question = [('_acme-challenge.www.example.co.uk', 16, D.CLASS_IN),
                      ('example.co.uk', 6, D.CLASS_IN), ('www.example.co.uk', 6, D.CLASS_IN),
                      ('example.co.uk', 2, D.CLASS_IN), ('www.example.co.uk', 1, D.CLASS_IN),
                      ('www.example.co.uk', 28, D.CLASS_IN), ('www.example.co.uk', 15, D.CLASS_IN)]
        got = D.parse(PS.dns_answer(D, m.to_wire(), {}))
        self.assertEqual(got.id, 7)
        self.assertTrue(got.flags & 0x8000)
        kinds = [(D.norm(x.name), x.rtype) for x in got.answer]
        self.assertIn(('_acme-challenge.www.example.co.uk', 16), kinds)
        self.assertIn(('example.co.uk', 6), kinds)
        self.assertIn(('www.example.co.uk', 1), kinds)
        self.assertIn(('www.example.co.uk', 28), kinds)
        self.assertEqual(len([k for k in kinds if k[1] == 2]), 2)
        self.assertEqual(len(got.authority), 2)                 # below the apex; no MX


# ---------------------------------------------------------------------------
# Periods missed while acme was down, the report's certificates
# ---------------------------------------------------------------------------
class Periods(unittest.TestCase):
    def ts(self, y, m, d, h=0):
        return time.mktime(datetime.datetime(y, m, d, h, 30).timetuple())

    def test_digest_missed(self):
        from acmelib.certs import digest as DG
        daily = {'on': True, 'every': 'daily', 'hour': 8, 'since': self.ts(2026, 5, 1)}
        self.assertEqual(DG.missed_period(daily, self.ts(2026, 5, 6, 7)), 'd:2026-05-05')
        self.assertIsNone(DG.missed_period(dict(daily, since=self.ts(2026, 5, 5, 9)),
                                           self.ts(2026, 5, 6, 7)))
        self.assertIsNone(DG.missed_period(dict(daily, on=False), self.ts(2026, 5, 6, 7)))
        weekly = {'on': True, 'every': 'weekly', 'day': 3, 'hour': 6, 'since': self.ts(2026, 4, 1)}
        # Monday 2026-05-11: last week's Wednesday was missed
        self.assertEqual(DG.missed_period(weekly, self.ts(2026, 5, 11, 1)), 'w:2026-19')
        self.assertEqual(DG.due_period(weekly, self.ts(2026, 5, 13, 7)), 'w:2026-20')
        self.assertIsNone(DG.due_period(weekly, self.ts(2026, 5, 13, 5)))

    def test_reports_missed(self):
        from acmelib.certs import reports as RP
        m = {'every': 'monthly', 'day': 31, 'hour': 0, 'since': self.ts(2026, 1, 1)}
        key, at = RP.missed_period(m, self.ts(2026, 3, 2, 5))
        self.assertEqual(key, 'm:2026-02')
        self.assertEqual(datetime.datetime.fromtimestamp(at).day, 28)
        self.assertEqual(RP.missed_period(dict(m, every='off'))[0], None)
        key, _at = RP.missed_period(m, self.ts(2026, 1, 15))         # December: before `since`
        self.assertIsNone(key)
        w = {'every': 'weekly', 'day': 9, 'hour': 23, 'since': self.ts(2025, 12, 1)}
        key, at = RP.missed_period(w, self.ts(2026, 1, 5, 1))        # Monday of ISO week 2
        self.assertEqual(key, 'w:2026-01')
        self.assertEqual(datetime.datetime.fromtimestamp(at).isoweekday(), 7)
        self.assertTrue(RP._made('w:2026-02', 'w:2026-01'))
        self.assertFalse(RP._made('m:2026-02', 'w:2026-01'))

    def test_renewer_report(self):
        from acmelib.certs import renewer
        clean()
        add_cert('soon', 5)
        add_cert('soon-revoked', 6, state='revoked')
        add_cert('soon-off', 7, enabled=0)
        add_cert('later', 90)
        STORE.db.insert('cert_jobs', {'kind': 'renew', 'ok': 1, 'ts': time.time(), 'state': 'done'})
        STORE.db.insert('cert_jobs', {'kind': 'deploy', 'ok': 0, 'ts': time.time(), 'state': 'failed'})
        title, lines = renewer.report(STORE, time.time() - 60, 'en')[0]
        self.assertEqual(title, 'Certificates')
        self.assertTrue(lines[0].startswith('4 certificate(s): 3 ok, 1 revoked'), lines)
        self.assertIn('renew: 1 done', lines)
        self.assertIn('deploy: 1 failed', lines)
        ends = [x for x in lines if x.startswith('ends ')]
        # what is revoked or switched off ends without anything to do about it
        self.assertEqual([x.split(': ', 1)[1] for x in ends], ['soon'], lines)
        title, lines = renewer.report(STORE, time.time() - 60, 'cs')[0]
        self.assertEqual(title, 'Certifikáty')
        self.assertTrue(lines[0].startswith('4 certifikáty: v pořádku 3, odvolané 1'), lines)
        self.assertIn('nasazení: selhalo 1', lines)
        self.assertTrue(any(x.startswith('končí ') and x.endswith(': soon') for x in lines))



# ---------------------------------------------------------------------------
# A Windows agent's policy: what each deployment needs
# ---------------------------------------------------------------------------
class WindowsNeeds(unittest.TestCase):
    def test_deploy_needs(self):
        from acmelib.certs import agent_policy as P
        clean()
        STORE.db.run("DELETE FROM cert_targets WHERE name = 'w9-win'")
        A.family_save(STORE, 'target', {'name': 'w9-win', 'kind': 'agent_windows',
                                        'config': {'host': 'win1.example.test'}}, 'boss')
        cid = add_cert('winc', 60, state='new')
        opts = {'store': True, 'rdp': True, 'post_ps': ['Write-Host $thumb'],
                'iis': ['Default Web Site | www.example.test | 443',
                        'default web site | b.example.test | 443', 'Other | | 8443'],
                'outputs': ['pfx C:/certs/{name}.pfx'], 'reload_cmd': ['Restart-Service W3SVC'],
                'test_cmd': ['C:\\scripts\\t.ps1']}
        STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'w9-win', 'enabled': 1,
                                         'options': json.dumps(opts)})
        row = S.plugin_row(STORE, 'target', 'w9-win')
        got = P.deploy_needs(STORE, row)
        self.assertEqual(len(got), 1)
        self.assertNotIn('error', got[0])
        items = got[0]['items']
        kinds = [i['kind'] for i in items]
        self.assertEqual(kinds.count('iis'), 2)                 # one site said once
        allow = [i['allow'] for i in items]
        for want in ('acme-agent allow store', 'acme-agent allow rdp',
                     'acme-agent allow iis "Default Web Site"', 'acme-agent allow iis Other',
                     'acme-agent allow file C:\\certs', 'acme-agent allow service W3SVC restart'):
            self.assertIn(want, allow)
        h = [i for i in items if i['kind'] == 'hash']
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]['interp'], 'powershell')
        self.assertTrue(any(i['kind'] == 'script' and i['step'] == 'test' for i in items))
        pol = P.builder(STORE, row)
        self.assertEqual(pol['platform'], 'windows')
        self.assertEqual(pol['needs'][0]['items'], items)


# ---------------------------------------------------------------------------
# A secret found in clear, sealed for its place at its first use; teams' pairs
# ---------------------------------------------------------------------------
class SealedAndPairs(unittest.TestCase):
    def test_secret_in_clear_sealed(self):
        if not E.seal_bound():
            self.skipTest('secrets not bound to their place here')
        STORE.db.run("DELETE FROM cert_targets WHERE name = 'w9-clear'")
        tid = STORE.db.insert('cert_targets', {'name': 'w9-clear', 'kind': 'w9list', 'config':
                                               json.dumps({'host': 'h', 'password': 'in-clear'}),
                                               'enabled': 1})
        row = S.plugin_row(STORE, 'target', tid)
        self.assertEqual(S.plugin_config('target', row)['password'], 'in-clear')
        kept = json.loads(STORE.db.value('SELECT config FROM cert_targets WHERE id = ?', (tid,)))
        self.assertTrue(kept['password'].startswith('sealed:'), kept)
        self.assertEqual(kept['host'], 'h')
        row = S.plugin_row(STORE, 'target', tid)
        self.assertEqual(S.plugin_config('target', row)['password'], 'in-clear')

    def test_clean_pairs(self):
        self.assertIsNone(T.clean_pairs(None))
        self.assertEqual(T.clean_pairs(''), {})
        self.assertEqual(T.clean_pairs('{"LE": ["web", "dns"]}'), {'LE': ['web', 'dns']})
        self.assertEqual(T.clean_pairs({' LE ': None}), {'LE': []})
        for bad in ('{nope', [1], {'': []}, {'a\x01': []}, {'LE': [], 'le': []},
                    {'x' * 191: []}):
            with self.assertRaises(ValueError, msg=bad):
                T.clean_pairs(bad)
        with self.assertRaises(ValueError):
            T.clean_pairs({'s%d' % i: [] for i in range(T.PAIRS_MOST + 1)})


# ---------------------------------------------------------------------------
# The console's Find: each kind opens what it is
# ---------------------------------------------------------------------------
class ConsoleFind(unittest.TestCase):
    def test_find_opens_each_kind(self):
        from acmelib.certs import console_ui as CU
        acted = []

        class Con(object):
            def ask_one(self, *a):
                return ' www '

            def out(self, *args):
                self.asked = args
                return {'groups': {
                    'cert': [{'name': 'c1'}], 'target': [{'name': 't1'}],
                    'agent': [{'name': 'a1'}], 'source': [{'name': 's1'}],
                    'validation': [{'name': 'v1'}], 'test': [{'name': 'k1'}],
                    'ca': [{'name': 'ca1'}], 'deploy': [{'name': 'c1 → t1', 'cert': 'c1'}],
                    'team': [{'name': 'Web'}], 'account': [{'name': 'eva', '_x': 1}]}}

            def act(self, *args):
                acted.append(args)

            def details(self, title, d):
                acted.append(('details', title, sorted(d)))

            def pick(self, title, load, cols, do, empty):
                self.title = title
                for r in load():
                    for _n, fn, _w, _s in cols:
                        fn(r)
                    do(r)
        con = Con()
        CU.find(con)
        self.assertEqual(con.asked, ('--find', 'www'))
        self.assertEqual(con.title, 'Found: www')
        self.assertEqual(acted, [
            ('--cert', 'c1'), ('--target-show', 't1'), ('--target-show', 'a1'),
            ('--source-show', 's1'), ('--validation-show', 'v1'), ('--check-show', 'k1'),
            ('--ca-show', 'ca1'), ('--deploys', 'c1'), ('--team-show', 'Web'),
            ('details', 'account', ['name'])])

        class Empty(Con):
            def ask_one(self, *a):
                return '  '
        CU.find(Empty())                                        # nothing asked
        self.assertEqual(len(acted), 10)


# ---------------------------------------------------------------------------
# The command line: --check-run, --find
# ---------------------------------------------------------------------------
class CommandLine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-rw9-cli-')
        with open(os.path.join(cls.tmp, 'config.json'), 'w') as f:
            f.write('{}')
        env = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
        env.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(cls.tmp, 'config.json'),
                   ACME_STATE=cls.tmp, ACME_RUN=cls.tmp, ACME_LOGDIR=cls.tmp, NO_COLOR='1',
                   ACME_CONSOLE_FLAG=os.path.join(cls.tmp, 'console-flag'))
        cls.env = env
        for args in (('--selfsigned', 'one', '--names', 'one.example.test'),
                     ('--selfsigned', 'two', '--names', 'two.example.test'),
                     ('--check-add', 'closed', '--kind', 'tls', '--set', 'host=127.0.0.1',
                      '--set', 'port=1'),
                     ('--check-attach', 'one', 'closed'), ('--check-attach', 'two', 'closed')):
            got = cls.acme(*args)
            assert got.returncode == 0, (args, got.stdout, got.stderr)

    @classmethod
    def acme(cls, *args):
        got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(args),
                             env=cls.env, capture_output=True, text=True, timeout=120, input='')
        assert 'Traceback' not in got.stderr + got.stdout, got.stderr
        return got

    def test_check_run(self):
        got = self.acme('--check-run', 'all', '--json')
        self.assertEqual(got.returncode, 1, got.stderr)
        res = json.loads(got.stdout)
        self.assertEqual(len(res['results']), 2)
        self.assertEqual({r['state'] for r in res['results']}, {'unreachable'})
        self.assertEqual(res['report'], '')
        got = self.acme('--check-run', 'cert:two')
        self.assertEqual(got.returncode, 1)
        self.assertIn('[fail]', got.stdout)
        self.assertEqual(got.stdout.count('cannot be reached'), 1)
        got = self.acme('--check-run', 'test:closed', '--json')
        self.assertEqual(len(json.loads(got.stdout)['results']), 2)
        got = self.acme('--check-run', 'test:nothing')
        self.assertEqual(got.returncode, 1)
        self.assertIn('there is no test to run', got.stderr)
        got = self.acme('--check-run', 'everything')
        self.assertIn('--check-run ID, cert:NAME, test:NAME or all', got.stderr)
        got = self.acme('--check-run', 'all', '--sms-to', '+420777000111')
        self.assertEqual(got.returncode, 1)
        self.assertIn('sending SMS is switched off', got.stderr)
        got = self.acme('--check-run', 'all', '--report-to', 'alerts')
        self.assertIn('no address to send the report to', got.stderr)

    def test_find(self):
        got = self.acme('--find', 'two.example')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('two', got.stdout)
        got = self.acme('--find', 'nothing-like-it-anywhere')
        self.assertEqual(got.returncode, 1)
        self.assertIn('nothing found', got.stdout)
        got = self.acme('--find', 'one', '--json')
        self.assertIn('cert', json.loads(got.stdout)['groups'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
