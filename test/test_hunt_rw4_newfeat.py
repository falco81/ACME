#!/usr/bin/env python3
"""Hunt w4 (1.0.143), area "newfeat": the 1.0.140 features again.

    python3 test/test_hunt_rw4_newfeat.py

- Reports and the team digest: a certificate that ran out hours ago had 0 days left (int()
  rounded towards nought) - the expiry report counted it "within 7 days", not "expired", the
  inventory counted it "ending within 30 days" as well as "failed or expired", and the digest
  said "0 days" instead of "ended".
- Expiry calendar: the .ics file (and the subscription) put each event on the day of the
  server's time zone; the page draws the browser's - a certificate the page showed on the 1st
  was on the 2nd in the file of a browser elsewhere. The file and a link now take the browser's
  zone (tz).
"""
import datetime
import json
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_f140_ui as U  # noqa: E402  (its store, H and call)

from acmelib import engine as E  # noqa: E402
from acmelib.certs import digest as D  # noqa: E402
from acmelib.certs import expirycal as EC  # noqa: E402
from acmelib.certs import reports as RP  # noqa: E402
from acmelib.certs import teams as T  # noqa: E402

STORE = U.STORE
DAY = 86400


def _cert(name, not_after, owner='W4', state='ok'):
    STORE.db.run('DELETE FROM certs WHERE name = ?', (name,))
    STORE.db.insert('certs', {'name': name, 'names': json.dumps([name + '.example.test']),
                              'issuer': 'self', 'state': state, 'owner': owner,
                              'not_before': not_after - 90 * DAY, 'not_after': not_after,
                              'auto_renew': 0, 'enabled': 1, 'key_type': 'ec-256'})
    return STORE.db.row('SELECT id FROM certs WHERE name = ?', (name,))['id']


class Left(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        U.setup()
        STORE.db.run('DELETE FROM certs')
        STORE.db.run('DELETE FROM cert_reports')
        if not T.team_get(STORE, 'W4'):
            T.save_team(STORE, {'name': 'W4', 'contact_mail': 'w4@example.test'}, 'test')
        now = time.time()
        _cert('w4-gone-hours', now - 5 * 3600)          # ran out 5 hours ago
        _cert('w4-soon', now + 3 * DAY + 3600)

    def rep(self, name, kind):
        old = RP.get_row(STORE, name)
        b = {'name': name, 'kind': kind, 'teams': ['W4'], 'formats': ['csv']}
        if old:
            b['id'] = old['id']
        return RP.need(STORE, RP.save(STORE, b, 'test')['id'])

    def test_expiry_counts_expired_hours_ago(self):
        d = RP.build(STORE, self.rep('w4-exp', 'expiry'), 'en')
        tiles = {a: b for a, b, _c in d['tiles']}
        self.assertEqual(tiles['expired'], 1, d['tiles'])
        self.assertEqual(tiles['within 7 days'], 1, d['tiles'])
        row = [r for r in d['rows'] if r['name'] == 'w4-gone-hours'][0]
        self.assertEqual(row['left'], '-1')
        # the CSV says the same as the preview
        csv = RP.render_csv(d).decode('utf-8-sig')
        self.assertIn('w4-gone-hours', csv)
        pv = RP.preview(d)
        keys = [c['key'] for c in pv['columns']]
        got = [r for r in pv['rows'] if r[keys.index('name')] == 'w4-gone-hours'][0]
        self.assertEqual(got[keys.index('left')], '-1')

    def test_inventory_not_ending_and_expired_twice(self):
        d = RP.build(STORE, self.rep('w4-inv', 'inventory'), 'en')
        tiles = {a: b for a, b, _c in d['tiles']}
        self.assertEqual(tiles['failed or expired'], 1, d['tiles'])
        self.assertEqual(tiles['ending within 30 days'], 1, d['tiles'])

    def test_digest_says_ended(self):
        t = T.team_get(STORE, 'W4')
        cfg = dict(D.config(t), on=True, contact=True)
        data = D.collect(STORE, t, cfg, time.time() - 7 * DAY)
        gone = [e for e in data['expired'] if e['name'] == 'w4-gone-hours'][0]
        self.assertLess(gone['left'], 0)
        _s, _html, text, _d = D.build(STORE, t, cfg, 'en', time.time() - 7 * DAY)
        line = [ln for ln in text.splitlines() if ln.startswith('- w4-gone-hours')][0]
        self.assertTrue(line.endswith('ended'), line)
        self.assertNotIn('0 days', line)


class IcsZone(unittest.TestCase):
    # 2026-12-01 23:30 UTC: the 2nd in Prague, the 1st in New York
    AT = datetime.datetime(2026, 12, 1, 23, 30, tzinfo=datetime.timezone.utc).timestamp()

    def entries(self):
        return [{'id': 7, 'name': 'w4', 'names': ['w4.example.test'], 'owner': '', 'issuer': '',
                 'not_after': self.AT, 'renew_at': None}]

    def test_days_in_the_zone_asked(self):
        pr = EC.ics(self.entries(), 'en', 'acme', 'Europe/Prague')
        ny = EC.ics(self.entries(), 'en', 'acme', 'America/New_York')
        self.assertIn('DTSTART;VALUE=DATE:20261202', pr)
        self.assertIn('DTEND;VALUE=DATE:20261203', pr)
        self.assertIn('DTSTART;VALUE=DATE:20261201', ny)
        # none, or one this system does not know: the server's own, as before
        own = datetime.date.fromtimestamp(self.AT).strftime('%Y%m%d')
        for tz in (None, '', 'Mars/Olympus', '../../etc/passwd', 'x' * 200):
            self.assertIn('DTSTART;VALUE=DATE:' + own, EC.ics(self.entries(), 'en', 'acme', tz))

    def test_route_and_link_keep_the_zone(self):
        U.setup()
        STORE.db.run('DELETE FROM certs')
        U.cert('w4z', 0, not_after=self.AT)
        got = U.call('GET', '/api/calendar/ics', args={'from': '2026-11-20', 'to': '2026-12-10',
                                                       'tz': 'Asia/Tokyo'})
        self.assertIn('DTSTART;VALUE=DATE:20261202', got['text'])
        got = U.call('GET', '/api/calendar/ics', args={'from': '2026-11-20', 'to': '2026-12-10',
                                                       'tz': 'America/Los_Angeles'})
        self.assertIn('DTSTART;VALUE=DATE:20261201', got['text'])
        if not STORE.account('boss'):
            STORE.add_account('boss', 'fulladmin', 'Local-Only-Pw-77!x')
        made = U.call('POST', '/api/calendar/feed_link', {'action': 'new', 'lang': 'en',
                                                          'tz': 'America/New_York'})
        h = STORE.get_meta(EC.META_FEED_OF + 'boss')
        self.assertEqual(json.loads(STORE.get_meta(EC.META_FEED + h))['tz'], 'America/New_York')
        EC.FEED_CACHE['at'].clear()
        fh = U.H()
        fh.headers = {'X-Acme-Calfeed': made['token']}
        text = E.ROUTES[('GET', '/api/calendar/feed')](fh)['text']
        self.assertIn('DTSTART;VALUE=DATE:20261201', text)
        # a zone this system does not know is not kept
        U.call('POST', '/api/calendar/feed_link', {'action': 'new', 'tz': 'No/Such_Zone'})
        h = STORE.get_meta(EC.META_FEED_OF + 'boss')
        self.assertNotIn('tz', json.loads(STORE.get_meta(EC.META_FEED + h)))

    def test_pages_send_the_zone(self):
        with open(os.path.join(ROOT, 'web/assets/calendar.js'), encoding='utf-8') as f:
            js = f.read()
        self.assertIn("resolvedOptions().timeZone", js)
        self.assertIn("{action: 'new', lang: lang(), tz: tzName()}", js)
        self.assertIn("lang: lang(), tz: tzName()}", js)
        self.assertIn("'&tz=' + encodeURIComponent(tzName())", js)
        with open(os.path.join(ROOT, 'web/index.php'), encoding='utf-8') as f:
            self.assertIn("calendar_ics' . $team_query(['lang', 'tz'])", f.read())


if __name__ == '__main__':
    unittest.main(verbosity=2)
