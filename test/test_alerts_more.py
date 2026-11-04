#!/usr/bin/env python3
"""Alerts for what the nodes already saw (as otp 1.0.242), and the quiet rows (1.0.234).

    python3 test/test_alerts_more.py     (or python3 -m unittest test.test_alerts_more)

Each new alert raised from what a node wrote in its health row (or the database holds) and
gone once that is over, each with its own switch; the opt-in ones off by default. What is
said as it happens comes from the events - and the very first look, with no event at all
yet, no longer leaves it at 0 for ever (nothing was ever said). The 'quiet' row is each
node's own, and a test alert from the node that does not send writes nothing back.
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix='acme-alerts-more-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
ME = E.node_name()


def health(**kw):
    row = {'at': time.time()}
    row.update(kw)
    STORE.set_meta('host:health:' + ME, json.dumps(row))


def keys():
    return set(E.alert_problems(STORE))


class TestNew(unittest.TestCase):
    def setUp(self):
        for k in list(E.CONFIG):
            if k.startswith('alerts_'):
                E.CONFIG[k] = E.DEFAULTS.get(k)
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'host:%' OR k LIKE 'acme:state:%' OR "
                     "k LIKE 'mailq:%' OR k LIKE 'alerts:%'")
        health()

    def test_defaults(self):
        on = ('alerts_shipping', 'alerts_snmp', 'alerts_acme', 'alerts_upgrade', 'alerts_trial',
              'alerts_dbguard', 'alerts_mailq', 'alerts_split', 'alerts_clock')
        off = ('alerts_repl_behind_mb', 'alerts_selinux', 'alerts_hisec', 'alerts_sso')
        self.assertEqual([E.DEFAULTS[k] for k in on], [1] * len(on))
        self.assertEqual([E.DEFAULTS[k] for k in off], [0] * len(off))
        for k in on + off:
            self.assertIn(k, E.PANES['alerts'])
            self.assertIn(k, E.NAMES)
            self.assertIn(k, E.SAYS)

    def test_logs_not_shipped(self):
        health(isemon={'on': True, 'trouble': {'isemon.example:6514': 'refused'}, 'dropped': 12})
        k = 'ship:isemon:' + ME
        al = E.alert_problems(STORE)
        self.assertIn(k, al)
        self.assertIn('12 lines dropped', al[k]['said'])
        E.CONFIG['alerts_shipping'] = 0
        self.assertNotIn(k, keys())
        E.CONFIG['alerts_shipping'] = 1
        health(isemon={'on': True, 'trouble': {}})
        self.assertNotIn(k, keys())

    def test_snmp(self):
        E.CONFIG['snmp'] = 1
        try:
            health(snmp={'listening': False, 'error': 'the port 161 is taken'})
            self.assertIn('snmp:' + ME, keys())
            health(snmp={'listening': True, 'trap_error': 'nms: refused'})
            self.assertIn('snmp:trap:' + ME, keys())
            health(snmp={'listening': True})
            self.assertFalse([k for k in keys() if k.startswith('snmp')])
        finally:
            E.CONFIG['snmp'] = 0

    def test_the_ca_did_not_renew(self):
        E.CONFIG['acme'] = 1
        try:
            STORE.set_meta('acme:state:' + ME, json.dumps({'ok': False, 'failed_at': time.time(),
                                                            'said': 'the CA said no'}))
            al = E.alert_problems(STORE)
            self.assertIn('acme:' + ME, al)
            self.assertEqual(al['acme:' + ME]['said'], 'the CA said no')
            STORE.set_meta('acme:state:' + ME, json.dumps({'ok': True}))
            self.assertNotIn('acme:' + ME, keys())
        finally:
            E.CONFIG['acme'] = 0

    def test_key_and_name_clash(self):
        health(key_lost=True, name_clash='two machines call themselves %s' % ME)
        al = E.alert_problems(STORE)
        self.assertEqual(al['key:' + ME]['level'], 'bad')
        self.assertIn('sealed secrets', al['key:' + ME]['title'])
        self.assertIn('clash:' + ME, al)
        self.assertIn('zapečetěná', E.alert_problems(STORE, 'cs')['key:' + ME]['title'])

    def test_updates_failed(self):
        STORE.set_meta('host:osup:plan', json.dumps({'state': 'failed', 'ended': time.time(),
                                                      'failed_on': ME}))
        STORE.set_meta('host:osup:check:' + ME, json.dumps({'state': 'failed', 'at': time.time(),
                                                             'error': 'no repository'}))
        got = keys()
        self.assertIn('osup:failed', got)
        self.assertIn('osup:check:' + ME, got)

    def test_internal_certificates(self):
        E.CONFIG['alerts_cert_days'] = 14
        STORE.set_meta('dbtls:server:' + ME, json.dumps({'cert_end': time.time() + 3 * 86400}))
        STORE.set_meta('hatls:node:' + ME, json.dumps({'cert_end': time.time() + 300 * 86400}))
        got = E.alert_problems(STORE)
        self.assertEqual(got['cert:pg:' + ME]['level'], 'bad')
        self.assertNotIn('cert:link:' + ME, got)
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'dbtls:%' OR k LIKE 'hatls:%'")

    def test_dbguard_refused(self):
        health(dbguard_refused=[{'what': 'fw:conf', 'why': 'it is not signed', 'at': time.time()}])
        al = E.alert_problems(STORE)
        self.assertIn('fw:conf (it is not signed)', al['dbguard:' + ME]['said'])
        E.CONFIG['alerts_dbguard'] = 0
        self.assertNotIn('dbguard:' + ME, keys())

    def test_mails_that_do_not_go(self):
        STORE.set_meta('mailq:1', json.dumps({'state': 'failed', 'kind': 'code', 'created': time.time(),
                                               'said': '550 no such user'}))
        STORE.set_meta('mailq:2', json.dumps({'state': 'failed', 'kind': 'alert', 'created': time.time()}))
        al = E.alert_problems(STORE)
        self.assertIn('mailq', al)
        self.assertIn('1 mail', al['mailq']['title'])

    def test_opt_in_ones_off(self):
        got = keys()
        self.assertFalse([k for k in got if k.startswith(('selinux:', 'hisec', 'repl:behind'))])

    def test_selinux_when_switched_on(self):
        E.CONFIG['alerts_selinux'] = 1
        had = getattr(E, 'selinux_problems', None)
        try:
            # Ported by another part: asked only when there.
            E.__dict__['selinux_problems'] = lambda store, n: ['SELinux refused 2 things', 'ready for enforcing']
            al = E.alert_problems(STORE)
            self.assertEqual(al['selinux:' + ME]['said'], 'SELinux refused 2 things')
        finally:
            if had is None:
                E.__dict__.pop('selinux_problems', None)
            else:
                E.__dict__['selinux_problems'] = had


class TestEvents(unittest.TestCase):
    def setUp(self):
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'alerts:%'")
        STORE.db.run('DELETE FROM events')
        E.CONFIG['alerts'] = 0           # nothing mailed - what would be said is counted

    def test_first_look_with_no_event(self):
        got = E.alerts_evaluate(STORE)
        st = json.loads(STORE.get_meta('alerts:state'))
        self.assertIn('event_id', st)
        self.assertEqual(st['event_id'], 0)
        self.assertEqual(got['events'], 0)
        # What comes later is said - it was never, with no event at the first look.
        STORE.add_event('settings', 'the firewall and access went back to what they were before '
                                    '(not kept in 5 min)', 'warn')
        STORE.add_event('settings', 'somebody saved the settings')
        self.assertEqual(E.alerts_evaluate(STORE)['events'], 1)
        self.assertEqual(E.alerts_evaluate(STORE)['events'], 0)       # said once
        E.CONFIG['alerts_trial'] = 0
        STORE.add_event('settings', 'the change of the SSH server went back on n1', 'warn')
        self.assertEqual(E.alerts_evaluate(STORE)['events'], 0)
        E.CONFIG['alerts_trial'] = 1


class TestQuiet(unittest.TestCase):
    def test_each_node_its_own_row(self):
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'alerts:quiet%'")
        STORE.set_meta('alerts:quiet:other', json.dumps({'why': 'other in maintenance',
                                                         'until': time.time() + 300}))
        self.assertGreater(E.alerts_quiet_until(STORE), time.time())
        self.assertIn('other in maintenance', E.alerts_quiet(STORE, [ME]))
        self.assertIsNone(STORE.get_meta('alerts:quiet'))

    def test_a_test_from_the_other_node_writes_nothing_back(self):
        STORE.db.run("DELETE FROM meta WHERE k = 'alerts:state'")
        was = E.alerts_lead
        E.__dict__['alerts_lead'] = lambda store: False
        try:
            def boom(*a, **kw):
                raise E.MailError('nobody to send to')
            had = E.mail_deliver
            E.__dict__['mail_deliver'] = boom
            try:
                E.alert_send(STORE, {'Subject': 'test'}, ['a@example.cz'], 'test', [])
            finally:
                E.__dict__['mail_deliver'] = had
            self.assertIsNone(STORE.get_meta('alerts:state'))
        finally:
            E.__dict__['alerts_lead'] = was


class TestReportDue(unittest.TestCase):
    def test_a_missed_day_goes_later_in_its_period(self):
        from datetime import datetime
        E.CONFIG.update(report_every='weekly', report_day=3, report_at='07:30')
        wed_early = time.mktime(datetime(2026, 11, 4, 6, 0).timetuple())    # a Wednesday
        wed_late = time.mktime(datetime(2026, 11, 4, 8, 0).timetuple())
        fri = time.mktime(datetime(2026, 11, 6, 3, 0).timetuple())
        tue = time.mktime(datetime(2026, 11, 3, 9, 0).timetuple())
        self.assertEqual([E.report_due(t) for t in (wed_early, wed_late, fri, tue)],
                         [False, True, True, False])
        # One period: the same mark whichever day of it.
        self.assertEqual(E.report_period(wed_late)[2], E.report_period(fri)[2])
        E.CONFIG.update(report_every='monthly')
        self.assertTrue(E.report_due(time.mktime(datetime(2026, 11, 9, 3, 0).timetuple())))
        self.assertFalse(E.report_due(time.mktime(datetime(2026, 11, 1, 3, 0).timetuple())))
        E.CONFIG.update(report_every=E.DEFAULTS['report_every'], report_day=E.DEFAULTS['report_day'])


class TestTrialEvents(unittest.TestCase):
    def test_network_going_back_said(self):
        with open(os.path.join(ROOT, 'acmelib/engine/305_changes_that_could_cut.py')) as f:
            src = f.read()
        self.assertIn('went back to the network it had before', src)
        rule = [r for r in E.ALERT_EVENTS if r[0] == 'alerts_trial'][0]
        self.assertIn('went back to the network it had before', rule[2])


if __name__ == '__main__':
    unittest.main()
