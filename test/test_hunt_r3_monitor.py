#!/usr/bin/env python3
"""Hunt R run 3, monitoring: the report's days, the disk alert of the inodes, the counts.

    python3 test/test_hunt_r3_monitor.py

- The report's "Events by day" (report_build) are the calendar's days: a month with the
  clocks put back (Europe/Prague, October) showed 25.10. twice and lost 31.10., and the
  events after the change went into the day before.
- A file system out of inodes is "bad" from 95 % as one out of room, and the alert says so
  (it was "warn" and said "40 % full").
- The counts of the certificates and deployments by state (Prometheus acme_certs,
  acme_cert_deploys, SNMP) add rows without a state to those 'new' - not the last read over
  the other.
- prometheus.yml on Settings → Monitoring puts an IPv6 address in brackets.
"""
import json
import os
import re
import sys
import tempfile
import time
import unittest

os.environ['TZ'] = 'Europe/Prague'
time.tzset()

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix='acme-hunt-r3-monitor-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
ME = E.node_name()


def local(*parts):
    return time.mktime(tuple(parts) + (0,) * (6 - len(parts)) + (0, 0, -1))


class ReportDays(unittest.TestCase):
    def setUp(self):
        self.was = E.CONFIG.get('report_every')
        STORE.db.run('DELETE FROM events')

    def tearDown(self):
        E.CONFIG['report_every'] = self.was
        STORE.db.run('DELETE FROM events')

    def event(self, ts, level='info'):
        STORE.db.run("INSERT INTO events (ts, kind, level, words, node, who) VALUES "
                     "(?, 'settings', ?, 'something', ?, 'test')", (ts, level, ME))

    def bars(self, since, until):
        _subj, page, _text = E.report_build(STORE, since, until, 'en')
        days = re.findall(r'margin-top:3px">([0-9.]+)</div>', page)
        counts = [int(x) for x in re.findall(
            r'<div style="font-size:10px;color:#6b7280">(\d+)</div>', page)]
        return days, counts

    def test_october_with_the_clocks_back(self):
        E.CONFIG['report_every'] = 'monthly'
        since, until, pid = E.report_period(local(2026, 11, 3, 10))
        self.assertEqual(pid, 'monthly:2026-10-01')
        self.event(local(2026, 10, 31, 0, 30))           # after the change, just past midnight
        self.event(local(2026, 10, 25, 23, 30), 'warn')  # the day of the change, late
        self.event(local(2026, 10, 1, 0, 5))
        days, counts = self.bars(since, until)
        self.assertEqual(days, ['%02d.10.' % d for d in range(1, 32)])
        self.assertEqual(counts[30], 1)                   # 31.10.
        self.assertEqual(counts[29], 0)                   # not 30.10.
        self.assertEqual(counts[24], 1)                   # 25.10.
        self.assertEqual(counts[0], 1)
        self.assertEqual(sum(counts), 3)

    def test_march_with_the_clocks_forward(self):
        E.CONFIG['report_every'] = 'weekly'
        since, until = local(2026, 3, 23), local(2026, 3, 30)  # Mar 29: clocks forward
        self.event(local(2026, 3, 29, 23, 30))
        days, counts = self.bars(since, until)
        self.assertEqual(days, ['%02d.03.' % d for d in range(23, 30)])
        self.assertEqual(counts[-1], 1)

    def test_an_ordinary_week(self):
        since, until = local(2026, 6, 1), local(2026, 6, 8)
        self.event(local(2026, 6, 3, 12))
        days, counts = self.bars(since, until)
        self.assertEqual(len(days), 7)
        self.assertEqual(counts, [0, 0, 1, 0, 0, 0, 0])

    def test_the_period_going_on(self):
        since = local(2026, 6, 1)
        self.event(local(2026, 6, 3, 9))
        days, counts = self.bars(since, local(2026, 6, 3, 10))   # "so far": 2 days and 10 h
        self.assertEqual(days, ['01.06.', '02.06.', '03.06.'])
        self.assertEqual(counts, [0, 0, 1])


class DiskInodes(unittest.TestCase):
    def setUp(self):
        self.was = E.CONFIG.get('alerts_disk_pct')
        E.CONFIG['alerts_disk_pct'] = 90

    def tearDown(self):
        E.CONFIG['alerts_disk_pct'] = self.was
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'host:health:%'")

    def disk(self, pct, inodes):
        STORE.set_meta('host:health:' + ME, json.dumps({'at': time.time(), 'disks': [
            {'path': '/var', 'pct': pct, 'inodes': inodes, 'free': 10 ** 10,
             'total': 2 * 10 ** 10}]}))
        return E.alert_problems(STORE).get('disk:%s:/var' % ME)

    def test_out_of_inodes(self):
        p = self.disk(40.0, 99.0)
        self.assertEqual(p['level'], 'bad')
        self.assertIn('Inodes 99.0 % used', p['said'])
        cs = E.alert_problems(STORE, 'cs')['disk:%s:/var' % ME]
        self.assertIn('Inody zaplněny z 99.0 %', cs['said'])

    def test_as_before(self):
        p = self.disk(96.0, 10.0)
        self.assertEqual(p['level'], 'bad')
        self.assertEqual(p['said'], '96.0 % full - 9.3 GB free.')
        self.assertEqual(self.disk(91.0, 10.0)['level'], 'warn')
        self.assertEqual(self.disk(40.0, 91.0)['level'], 'warn')
        self.assertIsNone(self.disk(40.0, 10.0))


class Counts(unittest.TestCase):
    def test_no_state_and_new_add_up(self):
        from acmelib.certs import monitor as MO

        class Db(object):
            def rows(self, sql, args=()):
                return [{'state': None, 'n': 2}, {'state': 'new', 'n': 3}, {'state': 'ok', 'n': 4}]

        class St(object):
            db = Db()
        c = MO.counts(St())
        self.assertEqual(c['new'], 5)
        self.assertEqual(c['ok'], 4)


class PrometheusYml(unittest.TestCase):
    def test_ipv6_in_brackets(self):
        with open(os.path.join(ROOT, 'web', 'assets', 'admin.js'), encoding='utf-8') as fh:
            js = fh.read()
        i = js.index('function drawMonitor()')
        part = js[i:js.index('\nfunction ', i + 10)]
        self.assertIn("'[' + a + ']'", part)
        self.assertNotIn("(n.address || n.name) + ':443'", part)


if __name__ == '__main__':
    unittest.main()
