#!/usr/bin/env python3
"""Hunt v3 (1.0.141), area "integr": mail, the teams' digests and the reports' mails, alerts.

    python3 test/test_hunt_rv3_integr.py

- The digest's preview (a draft too) named the accounts a group or a member chosen stands for
  to a reader of the team - only whoever may set the digest sees who they are; the digest's
  last "sent to a@x" too.
- A report's run (and its last word) can hold a mail server's answer naming a recipient - a
  certificate administrator, who never sees recipients, sees it with the addresses masked.
- GET /api/teams/whocan?cert= answered 404 for a certificate that does not exist and 403 for
  one the session may not see - now the same 403 for both.
- A team's digest whose moment fell while acme was down, acme started again only in the next
  period: it is sent once after the start (as the reports' missed period), once on one node.
"""
import json
import os
import sys
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_f140_reports as F  # noqa: E402  (its own database, its seed)

from acmelib.certs import api_reports as AR  # noqa: E402
from acmelib.certs import api_teamgov as AG  # noqa: E402

E, RP, D, T, STORE = F.E, F.RP, F.D, F.T, F.STORE
DAY = 86400


def at(*ymdh):
    y, m, d, h = ymdh
    return time.mktime((y, m, d, h, 0, 0, 0, 0, -1))


class H:
    def __init__(self, args=None, body=None):
        self.store = STORE
        self._a = args or {}
        self._b = body or {}

    def arg(self, k):
        return self._a.get(k)

    def body(self):
        return self._b


def call(fn, s, args=None, body=None):
    """(status, answer) as the route's wrapper makes them."""
    try:
        return 200, fn(H(args, body), s)
    except E.ApiError as e:
        return e.status, str(e)
    except LookupError as e:
        return 404, str(e)


FULL = {'role': 'fulladmin', 'name': 'admin'}
JAN = {'role': 'readonly', 'name': 'jan'}
CM = {'role': 'certadmin', 'name': 'cm'}


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ids = F.seed(STORE)
        cls.saved = dict(E.CONFIG)
        E.CONFIG.update(mail_mode='off', mail_from='acme@example.test', mail_lang='en',
                        certs_certadmin_all=0, certs_readonly_all=0)
        if not STORE.account('cm'):
            STORE.add_account('cm', 'certadmin', 'Pw-123456789-x!')
        T.save_team(STORE, {'name': 'Web', 'old_name': 'Web', 'parent': 'Europe',
                            'contact_mail': 'web@example.test',
                            'members': [{'who': 'local:jan', 'roles': ['Requester']},
                                        {'who': 'local:eva', 'roles': ['Approver']},
                                        {'who': 'local:cm', 'roles': ['Certificate manager']}]},
                    'x')

    @classmethod
    def tearDownClass(cls):
        E.CONFIG.clear()
        E.CONFIG.update(cls.saved)


class DigestPreview(Base):
    def test_reader_sees_no_names(self):
        draft = {'on': True, 'members': ['local:eva', 'local:jan'], 'contact': True}
        st, got = call(AR._digest_preview, JAN, body={'team': 'Web', 'digest': draft,
                                                      'lang': 'en'})
        self.assertEqual(st, 200, got)
        rec = got['preview']['recipients']
        self.assertEqual(len(rec), 3)
        blob = json.dumps(rec)
        self.assertNotIn('eva', blob)
        self.assertNotIn('jan', blob)
        self.assertNotIn('@', blob)
        self.assertEqual(sorted(r['who'] for r in rec), ['contact', 'member', 'member'])
        st, got = call(AR._digest_preview, FULL, body={'team': 'Web', 'digest': draft,
                                                       'lang': 'en'})
        self.assertEqual(sorted(r['who'] for r in got['preview']['recipients']),
                         ['contact', 'eva', 'jan'], 'who may set it sees them')

    def test_last_said_masked_for_reader(self):
        t = T.team_get(STORE, 'Web')
        STORE.set_meta(D.META_LAST % t['id'], json.dumps({
            'at': time.time(), 'ok': True, 'said': 'sent to web@example.test, eva@example.test',
            'items': 2, 'to_count': 2}))
        try:
            st, got = call(AR._digest, JAN, args={'team': 'Web'})
            self.assertEqual(st, 200, got)
            self.assertNotIn('@', got['digest']['last']['said'])
            st, got = call(AR._digest, FULL, args={'team': 'Web'})
            self.assertIn('eva@example.test', got['digest']['last']['said'])
        finally:
            STORE.set_meta(D.META_LAST % t['id'], '')


class ReportSaid(Base):
    def test_certadmin_sees_no_address_in_said(self):
        r = RP.need(STORE, RP.save(STORE, {'name': 'said-mask', 'kind': 'inventory',
                                           'teams': ['Web'], 'formats': ['csv'],
                                           'recipients': 'boss@example.test'}, 'test')['id'])
        bad = "550 5.1.1 <boss@example.test>: Recipient address rejected"
        with mock.patch.object(RP, 'send_files', lambda *a, **k: (False, bad)):
            E.CONFIG['mail_mode'] = 'smtp'
            try:
                RP.run(STORE, r, 'test', send=True)
            finally:
                E.CONFIG['mail_mode'] = 'off'
        mine = [x for x in RP.runs_for(STORE, CM, r)]
        self.assertTrue(mine, 'the certificate administrator of Web sees the run')
        self.assertNotIn('boss@', mine[0]['said'])
        self.assertIn('Recipient address rejected', mine[0]['said'])
        self.assertIn('boss@example.test', RP.runs_for(STORE, FULL, r)[0]['said'])
        st, got = call(AR._report_one, CM, args={'id': r['id']})
        self.assertEqual(st, 200, got)
        self.assertNotIn('boss@', got['report']['last_said'])
        self.assertNotIn('boss@', json.dumps(got['runs']))
        st, got = call(AR._reports, CM)
        mine = [x for x in got['reports'] if x['name'] == 'said-mask'][0]
        self.assertNotIn('boss@', json.dumps(mine))
        st, got = call(AR._report_one, FULL, args={'id': r['id']})
        self.assertIn('boss@example.test', got['report']['last_said'])


class WhoCan(Base):
    def test_same_answer_missing_and_unseen(self):
        st1, w1 = call(AG._whocan, CM, args={'cap': 'cert.view', 'cert': 'mx'})       # Mail's
        st2, w2 = call(AG._whocan, CM, args={'cap': 'cert.view', 'cert': 'no-such-cert'})
        st3, w3 = call(AG._whocan, CM, args={'cap': 'cert.view', 'cert': 'free'})     # no team
        self.assertEqual((st1, w1), (403, 'not a certificate you may see'))
        self.assertEqual((st2, w2), (st1, w1))
        self.assertEqual((st3, w3), (st1, w1))
        st, got = call(AG._whocan, CM, args={'cap': 'cert.view', 'cert': 'shop'})
        self.assertEqual(st, 200, got)
        st, _ = call(AG._whocan, FULL, args={'cap': 'cert.view', 'cert': 'no-such-cert'})
        self.assertEqual(st, 404, 'who sees every certificate is told it is not there')


class MissedDigest(Base):
    def cfg(self, **kw):
        t = T.team_get(STORE, 'Quiet')
        ex = D._extras(t)
        ex['digest'] = dict(D.DEFAULTS, on=True, contact=True, skip_empty=False, **kw)
        STORE.db.update('cert_teams', t['id'], {'extras': json.dumps(ex)})
        T.changed()
        STORE.set_meta(D.META_PERIOD % t['id'], '')
        STORE.set_meta(D.META_LAST % t['id'], '')
        return T.team_get(STORE, 'Quiet')

    def sends(self, now, times=2):
        got = []
        with mock.patch.object(D, '_now', lambda: now), \
                mock.patch.object(D, 'send', lambda store, t, by, cfg=None, period='', **k:
                                  got.append((t['name'], period))):
            for _ in range(times):
                D.tick(STORE, now)
        return [g for g in got if g[0] == 'Quiet']

    def test_units(self):
        mon = at(2026, 11, 23, 5)                       # a Monday 05:00, before 07:00
        cfg = dict(D.DEFAULTS, on=True, day=1, hour=7, since=mon - 30 * DAY)
        self.assertIsNone(D.due_period(cfg, mon))
        self.assertEqual(D.missed_period(cfg, mon), 'w:2026-47')
        self.assertIsNone(D.missed_period(dict(cfg, since=mon - 3 * DAY), mon))
        self.assertIsNone(D.missed_period(dict(cfg, on=False), mon))
        daily = dict(cfg, every='daily')
        self.assertEqual(D.missed_period(daily, mon), 'd:2026-11-22')
        self.assertEqual(D.missed_period(daily, at(2027, 1, 1, 3)), 'd:2026-12-31')

    def test_weekly_missed_sent_once(self):
        mon = at(2026, 11, 23, 5)
        self.cfg(every='weekly', day=1, hour=7, since=mon - 30 * DAY)
        self.assertEqual(self.sends(mon), [('Quiet', 'w:2026-47')], 'once, not twice')
        self.assertEqual(self.sends(mon + 3600), [], 'not again')
        self.assertEqual(self.sends(at(2026, 11, 23, 8)), [('Quiet', 'w:2026-48')],
                         'this week\'s at its moment')
        self.assertEqual(self.sends(at(2026, 11, 24, 8)), [])

    def test_made_not_again_and_not_before_set(self):
        mon = at(2026, 11, 23, 5)
        t = self.cfg(every='weekly', day=1, hour=7, since=mon - 30 * DAY)
        STORE.set_meta(D.META_PERIOD % t['id'], 'w:2026-47')
        self.assertEqual(self.sends(mon), [], 'last week\'s went')
        self.cfg(every='weekly', day=1, hour=7, since=mon - 2 * DAY)
        self.assertEqual(self.sends(mon), [], 'set after that moment: nothing missed')

    def test_not_on_a_node_that_does_not_lead(self):
        mon = at(2026, 11, 23, 5)
        self.cfg(every='daily', hour=7, since=mon - 30 * DAY)
        with mock.patch.object(E, 'claim_once', lambda *a: False):
            self.assertEqual(self.sends(mon), [])
        self.assertEqual(self.sends(mon), [('Quiet', 'd:2026-11-22')])


if __name__ == '__main__':
    unittest.main(verbosity=2)
