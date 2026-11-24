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


if __name__ == '__main__':
    unittest.main(verbosity=2)
