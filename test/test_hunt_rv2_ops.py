#!/usr/bin/env python3
"""Hunt v2 (1.0.141), area "ops": the scheduler, HA, upgrade/downgrade.

    python3 test/test_hunt_rv2_ops.py

- A weekly or monthly report whose moment fell while the daemon was down, the daemon started
  again only in the next week (month) before that one's moment: the report of the period missed
  was never made. It is made once now after the start - not twice, not on a node that does not
  lead (claim_once), and not when it was set only after that moment.
- Going back below 1.0.140 with agents whose policy guards what they deploy (allow issuer, allow
  names, require key local): the older acme sends neither the CAs nor the PKCS#12's password the
  agent checks with - every such deployment would be refused. Refused with the agents named.
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

E, RP, STORE = F.E, F.RP, F.STORE
DAY = 86400


def at(*ymdh):
    y, m, d, h = ymdh
    return time.mktime((y, m, d, h, 0, 0, 0, 0, -1))


class MissedReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        F.seed(STORE)
        cls.saved = dict(E.CONFIG)
        E.CONFIG.update(mail_mode='off', mail_from='acme@example.test', mail_lang='en')

    @classmethod
    def tearDownClass(cls):
        E.CONFIG.clear()
        E.CONFIG.update(cls.saved)

    def rep(self, name, sched):
        old = RP.get_row(STORE, name)
        b = {'name': name, 'kind': 'inventory', 'formats': ['csv']}
        if old:
            b['id'] = old['id']
        r = RP.need(STORE, RP.save(STORE, b, 'test')['id'])
        STORE.db.update('cert_reports', r['id'], {'schedule': json.dumps(sched)})
        STORE.set_meta('reports:period:%d' % r['id'], '')
        return RP.need(STORE, r['id'])

    def ticks(self, r, now, times=2):
        with mock.patch.object(RP, '_now', lambda: now):
            for _ in range(times):
                RP._reports_tick(STORE)
        return len(RP.runs(STORE, r))

    def test_missed_period_units(self):
        mon = at(2026, 11, 23, 5)                       # a Monday 05:00, before 07:00
        sch = {'every': 'weekly', 'day': 1, 'hour': 7, 'since': mon - 30 * DAY}
        self.assertEqual(RP.due_period(sch, mon), (None, None), 'this week\'s not yet')
        self.assertEqual(RP.missed_period(sch, mon)[0], 'w:2026-47')
        self.assertEqual(RP.missed_period(sch, mon)[1], at(2026, 11, 16, 7))
        self.assertEqual(RP.missed_period(dict(sch, since=mon - 3 * DAY), mon), (None, None),
                         'set after the last week\'s moment: nothing missed')
        self.assertEqual(RP.missed_period({'every': 'off'}, mon), (None, None))
        jan = at(2027, 1, 4, 5)                         # a Monday of the year's first week
        self.assertEqual(RP.missed_period(dict(sch, since=0), jan)[0], 'w:2026-53')
        m = {'every': 'monthly', 'day': 3, 'hour': 7, 'since': 1}
        self.assertEqual(RP.missed_period(m, at(2027, 1, 2, 9)),
                         ('m:2026-12', at(2026, 12, 3, 7)), 'over the year\'s end')
        self.assertTrue(RP._made('w:2026-48', 'w:2026-47'))
        self.assertTrue(RP._made('w:2026-47', 'w:2026-47'))
        self.assertFalse(RP._made('w:2026-46', 'w:2026-47'))
        self.assertFalse(RP._made('', 'w:2026-47'))
        self.assertFalse(RP._made('m:2026-12', 'w:2026-47'))

    def test_weekly_missed_once(self):
        r = self.rep('rv2-weekly', {'every': 'weekly', 'day': 1, 'hour': 7,
                                    'since': at(2026, 11, 1, 0)})
        # it ran in week 46 (Monday 9 November); the daemon was down on Monday 16 November
        self.assertEqual(self.ticks(r, at(2026, 11, 9, 8)), 1)
        self.assertEqual(self.ticks(r, at(2026, 11, 15, 12)), 1, 'nothing more in week 46')
        # started again on Monday 23 November at 05:00, before this week's moment: made once
        self.assertEqual(self.ticks(r, at(2026, 11, 23, 5)), 2, 'the missed week 47, once')
        self.assertEqual(self.ticks(r, at(2026, 11, 23, 6)), 2, 'not again')
        # this week's moment: the week's own report, once
        self.assertEqual(self.ticks(r, at(2026, 11, 23, 8)), 3)
        self.assertEqual(self.ticks(r, at(2026, 11, 29, 8)), 3)
        self.assertEqual(self.ticks(r, at(2026, 11, 30, 5)), 3, 'week 48 made: nothing missed')

    def test_down_through_both_moments(self):
        r = self.rep('rv2-both', {'every': 'weekly', 'day': 1, 'hour': 7,
                                  'since': at(2026, 11, 1, 0)})
        self.assertEqual(self.ticks(r, at(2026, 11, 2, 8)), 1)
        # down from week 45 to after week 48's moment: this week's report alone, once
        self.assertEqual(self.ticks(r, at(2026, 11, 24, 8)), 2)
        self.assertEqual(STORE.get_meta('reports:period:%d' % r['id']), 'w:2026-48')

    def test_monthly_missed(self):
        r = self.rep('rv2-monthly', {'every': 'monthly', 'day': 28, 'hour': 23,
                                     'since': at(2026, 9, 1, 0)})
        self.assertEqual(self.ticks(r, at(2026, 9, 29, 8)), 1)
        # down on 28 October, up on 2 November
        self.assertEqual(self.ticks(r, at(2026, 11, 2, 8)), 2)
        self.assertEqual(STORE.get_meta('reports:period:%d' % r['id']), 'm:2026-10')
        self.assertEqual(self.ticks(r, at(2026, 11, 20, 8)), 2)

    def test_new_report_makes_nothing_missed(self):
        r = self.rep('rv2-new', {'every': 'weekly', 'day': 1, 'hour': 7,
                                 'since': at(2026, 11, 20, 0)})
        self.assertEqual(self.ticks(r, at(2026, 11, 23, 5)), 0)

    def test_disabled_and_follower(self):
        r = self.rep('rv2-follower', {'every': 'weekly', 'day': 1, 'hour': 7,
                                      'since': at(2026, 11, 1, 0)})
        STORE.db.update('cert_reports', r['id'], {'enabled': 0})
        self.assertEqual(self.ticks(r, at(2026, 11, 23, 5)), 0, 'switched off')
        STORE.db.update('cert_reports', r['id'], {'enabled': 1})
        # a node that does not lead claims nothing
        with mock.patch.object(E, 'claim_once', lambda *a: False):
            self.assertEqual(self.ticks(r, at(2026, 11, 23, 5)), 0)
        self.assertEqual(self.ticks(r, at(2026, 11, 23, 5)), 1)


class DowngradeGuard(unittest.TestCase):
    def test_guarded_agents_stop_going_below_140(self):
        from acmelib.certs import agents as AG
        STORE.db.query("DELETE FROM cert_targets WHERE name LIKE 'rv2-%'")
        self.assertEqual(E.downgrade_guarded_agents(STORE), [])
        STORE.db.insert('cert_targets', {'name': 'rv2-plain', 'kind': 'agent', 'enabled': 1})
        STORE.db.insert('cert_targets', {'name': 'rv2-guarded', 'kind': 'agent', 'enabled': 1})
        tids = {r['name']: r['id'] for r in AG.rows(STORE)}
        AG.state_put(STORE, tids['rv2-plain'], {'policy': {'files': ['/etc/ssl']}})
        AG.state_put(STORE, tids['rv2-guarded'], {'policy': {'files': ['/etc/ssl'],
                                                             'key_local': True}})
        self.assertEqual(E.downgrade_guarded_agents(STORE), ['rv2-guarded'])
        for v in ('1.0.139', '1.0.137'):
            got = [w for w in E.downgrade_new_use(STORE, v) if 'guard what it' in w]
            self.assertEqual(len(got), 1, v)
            self.assertIn('rv2-guarded', got[0])
            self.assertNotIn('rv2-plain', got[0])
        self.assertTrue(any('rv2-guarded' in w for w in E.downgrade_why_not(STORE, '1.0.139')))
        self.assertEqual(E.downgrade_new_use(STORE, '1.0.140'), [])
        AG.state_put(STORE, tids['rv2-guarded'], {'policy': {'files': ['/etc/ssl']}})
        self.assertEqual(E.downgrade_new_use(STORE, '1.0.139'), [], 'the lines taken out')
        STORE.db.query("DELETE FROM cert_targets WHERE name LIKE 'rv2-%'")


if __name__ == '__main__':
    unittest.main(verbosity=1)
