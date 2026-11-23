#!/usr/bin/env python3
"""Hunt w2 (1.0.143), area "ops": operations under stress - a restart and a leader change in the
middle of the work, split brain, backups.

    python3 test/test_hunt_rw2_ops.py

- The agents' update rollout: acme stopped (or the leader changed) while a ring was being
  updated - the ring's job was marked failed at the start (or its node was gone), but the
  rollout stayed "canary"/"rest" for good: the renewer's tick moves only a rollout that waits,
  Continue refuses one that is not waiting, a new one is refused while one is under way. The
  tick now goes on with the ring, without updating again the agents done before (each agent's
  result is kept as it comes); a ring whose job still runs, here or on a node alive, is left.
- The scheduled backup to the destinations: acme stopped in the middle of it (a restart, an
  upgrade at night) - the day's claim, kept in the database, said it was done and the day's (a
  week's) backup was never made. Made again after the start, once; not when it ended.
- A scheduled report (weekly, monthly): acme stopped in the middle of its run (or the leader
  that took the period is gone) - the period's claim said it was made and the report was lost
  until the next period. Made again once after the start (by one node), not when it was made.
- Split brain: on the node that does not lead, the previews and plans of 1.0.138-1.0.140 (a
  version's and a deleted object's preview, a report's and a digest's preview, a profile's dry
  run, the readiness check, the run plan, the take-over's preview) were refused as changes.

Never port 8092 nor PostgreSQL: temporary folders only (test_f138_fleet's database).
"""
import json
import os
import sys
import threading
import time
import unittest
from datetime import datetime
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_f138_fleet as F  # noqa: E402  (its own database, its agents)

E, G, FL, STORE, jobs = F.E, F.G, F.FL, F.STORE, F.jobs


class RolloutLeft(unittest.TestCase):
    """A ring of the update rollout that no job runs any more goes on at the next tick."""

    def setUp(self):
        self.rows = [F.target('w2ring%d' % i, text=F.NGINX + 'allow self-update\n',
                              version='1.0.130') for i in range(3)]
        self.updated = []
        self.block = None
        self.keep = (G.update_candidates, G.update_agent, G.package, jobs.submit)

        def cand(store):
            return [{'id': r['id'], 'name': r['name'], 'mode': 'passive', 'platform': 'linux',
                     'version': G.state(store, r['id']).get('version'), 'offered': '1.0.138',
                     'ok': True, 'why': ''} for r in self.rows
                    if G.state(store, r['id']).get('version') != '1.0.138']

        def upd(store, row, by):
            if self.block is not None and row['name'] == self.block[0]:
                self.block[1].wait(30)                  # acme "stops" here
                raise RuntimeError('acme stopped')
            self.updated.append(row['name'])
            st = G.state(store, row['id'])
            st.update(version='1.0.138', last_seen=time.time())
            G.state_put(store, row['id'], st)
            return {'ok': True}
        G.update_candidates, G.update_agent = cand, upd
        G.package = lambda build=True: {'version': '1.0.138', 'signed': True}
        STORE.db.run("DELETE FROM meta WHERE k = 'fleet:rollout'")
        self.g = FL.group_save(STORE, {'name': 'W2 canary %s' % self.id()[-8:], 'canary': True,
                                       'members': [self.rows[0]['id'], self.rows[1]['id']]},
                               'tester')

    def tearDown(self):
        for b in (self.block, getattr(self, 'gone', None)):
            if b is not None:
                b[1].set()
        G.update_candidates, G.update_agent, G.package, jobs.submit = self.keep
        time.sleep(0.3)
        FL.group_delete(STORE, self.g['id'], 'tester')
        STORE.db.run("DELETE FROM meta WHERE k = 'fleet:rollout'")
        for r in self.rows:
            STORE.db.run('DELETE FROM cert_targets WHERE id = ?', (r['id'],))
            STORE.db.run('DELETE FROM meta WHERE k = ?', (G.M_T(r['id']),))

    def wait(self, cond, what, secs=20):
        end = time.time() + secs
        while time.time() < end:
            r = FL.rollout_view(STORE)
            if cond(r or {}):
                return r
            time.sleep(0.1)
        self.fail('%s: %s' % (what, FL.rollout_view(STORE)))

    def test_ring_left_by_a_restart_goes_on(self):
        # w2ring1 is being updated when acme stops: w2ring0 was updated before it
        self.block = ('w2ring1', threading.Event())
        FL.rollout_start(STORE, {'canary': self.g['id'], 'wait': 0}, 'tester')
        r = self.wait(lambda r: str(self.rows[0]['id']) in (r.get('results') or {}),
                      'the first agent updated')
        jid = r['job_canary']
        # what the start of the daemon does with the job of the process gone (jobs.recover)
        STORE.db.update('cert_jobs', jid, {'state': 'failed', 'ok': 0,
                                           'said': 'acme stopped while it ran'})
        with jobs._LOCK:
            jobs.RUNNING.pop(jid, None)
        self.assertEqual(FL.rollout_view(STORE)['phase'], 'canary')
        self.gone, self.block = self.block, None        # its thread is gone with the process
        FL.tick(STORE)
        r = self.wait(lambda r: r.get('phase') == 'waiting', 'the canary ring ended')
        self.assertNotEqual(r['job_canary'], jid)
        self.assertEqual(self.updated, ['w2ring0', 'w2ring1'])      # w2ring0 not again
        self.assertTrue(all(v['ok'] for v in r['results'].values()), r['results'])
        evs = [e['words'] for e in STORE.db.rows(
            "SELECT words FROM events WHERE words LIKE '%left unfinished%'")]
        self.assertTrue(evs)
        FL.tick(STORE)                                   # the rest, as before
        r = self.wait(lambda r: r.get('phase') == 'done', 'the rollout done')
        self.assertEqual(sorted(self.updated), ['w2ring0', 'w2ring1', 'w2ring2'])

    def test_ring_of_a_node_gone(self):
        FL.rollout_start(STORE, {'canary': self.g['id'], 'wait': 0}, 'tester')
        self.wait(lambda r: r.get('phase') == 'waiting', 'the canary ring ended')
        # the rest was being updated by the other node (the leader then), which is gone
        r = FL._meta(STORE, FL.M_ROLLOUT, {})
        jid = STORE.db.insert('cert_jobs', {'ts': time.time() - 60, 'kind': 'action',
                                            'node': 'w2-other', 'state': 'running',
                                            'steps': '[]', 'by_who': 'tester'})
        r.update(phase='rest', job_rest=jid, ring_at=time.time() - 60)
        FL._put(STORE, FL.M_ROLLOUT, r)
        with mock.patch.object(jobs, '_node_alive', lambda store, name: name != 'w2-other'):
            FL.tick(STORE)
        r = self.wait(lambda r: r.get('phase') == 'done', 'the rollout done')
        self.assertEqual(sorted(self.updated), ['w2ring0', 'w2ring1', 'w2ring2'])
        got = STORE.db.row('SELECT state, said FROM cert_jobs WHERE id = ?', (jid,))
        self.assertEqual((got['state'], got['said']), ('failed', 'its node is gone'))

    def test_ring_still_running_is_left_alone(self):
        self.block = ('w2ring1', threading.Event())
        FL.rollout_start(STORE, {'canary': self.g['id'], 'wait': 0}, 'tester')
        r = self.wait(lambda r: str(self.rows[0]['id']) in (r.get('results') or {}),
                      'the first agent updated')
        FL.tick(STORE)                                   # its job runs: nothing started again
        self.assertEqual(FL.rollout_view(STORE)['job_canary'], r['job_canary'])
        self.assertEqual(self.updated, ['w2ring0'])
        # ...nor by the other node while it is alive
        with mock.patch.object(E, 'node_name', lambda: 'w2-leader'), \
                mock.patch.object(jobs, '_node_alive', lambda store, name: True):
            FL.tick(STORE)
        self.assertEqual(FL.rollout_view(STORE)['job_canary'], r['job_canary'])
        self.assertEqual(STORE.db.value('SELECT state FROM cert_jobs WHERE id = ?',
                                        (r['job_canary'],)), 'running')

    def test_ring_run_by_the_command_line_is_left_alone(self):
        # acme --fleet-rollout start: the ring runs in the command line's process
        FL.rollout_start(STORE, {'canary': self.g['id'], 'wait': 0}, 'tester')
        self.wait(lambda r: r.get('phase') == 'waiting', 'the canary ring ended')
        r = FL._meta(STORE, FL.M_ROLLOUT, {})
        jid = STORE.db.insert('cert_jobs', {'ts': time.time(), 'kind': 'action',
                                            'node': E.node_name(), 'state': 'running',
                                            'steps': '[]', 'by_who': 'tester'})
        r.update(phase='rest', job_rest=jid, ring_at=time.time())
        FL._put(STORE, FL.M_ROLLOUT, r)
        mark = jobs._cli_mark_write(jid)
        try:
            FL.tick(STORE)
            self.assertEqual(FL.rollout_view(STORE)['job_rest'], jid)
            self.assertEqual(sorted(self.updated), ['w2ring0', 'w2ring1'])
        finally:
            jobs._cli_mark_drop(mark)
        FL.tick(STORE)                                   # that process gone: it goes on
        self.wait(lambda r: r.get('phase') == 'done', 'the rollout done')
        self.assertEqual(sorted(self.updated), ['w2ring0', 'w2ring1', 'w2ring2'])

    def test_ring_end_not_written_over_by_its_job_number(self):
        # a ring over at once (one quick agent): its end and the job's number both kept
        def quick(store, kind, fn, **kw):
            ident = jobs.new_job(store, kind, by=kw.get('by'), said=kw.get('said'))
            done = threading.Event()

            def go():
                fn(ident)
                done.set()
            threading.Thread(target=go, daemon=True).start()
            done.wait(1.5)
            return ident.id
        jobs.submit = quick
        FL.group_save(STORE, {'id': self.g['id'], 'members': [self.rows[0]['id']]}, 'tester')
        FL.rollout_start(STORE, {'canary': self.g['id'], 'wait': 30}, 'tester')
        r = self.wait(lambda r: r.get('phase') == 'waiting', 'the canary ring ended')
        self.assertTrue(r.get('job_canary'))
        self.assertEqual(self.updated, ['w2ring0'])


class FakeDaemon(object):
    def __init__(self):
        self.store = STORE


class ScheduledBackupLeft(unittest.TestCase):
    """The day's scheduled backup that acme stopped in the middle of is made after the start."""

    def setUp(self):
        self.saved = dict(E.CONFIG)
        E.CONFIG.update(rbackup=1, rbackup_at='00:00', rbackup_every='daily', ha_mode='')
        self.dest = E.rb_save(STORE, {'kind': 'folder', 'name': 'w2 nas',
                                      'path': os.path.join(F.TMP, 'w2-nas'), 'enabled': 1},
                              'tester')
        self.today = datetime.now().strftime('%Y-%m-%d')
        self.started = []
        self.keep = E.rb_job_start
        E.rb_job_start = lambda store, by, only=None: self.started.append(by)
        for k in ('rbackup_day:' + E.node_name(), E.node_key('rbackup', 'runs')):
            STORE.db.run('DELETE FROM meta WHERE k = ?', (k,))

    def tearDown(self):
        E.rb_job_start = self.keep
        E.rb_delete(STORE, self.dest['id'], 'tester')
        E.CONFIG.clear()
        E.CONFIG.update(self.saved)

    def test_left_by_a_restart_is_made(self):
        d = FakeDaemon()
        E.rb_tick(d)                                     # the day's: claimed and started
        self.assertEqual(self.started, ['acme (scheduled)'])
        E.rb_tick(d)
        self.assertEqual(len(self.started), 1)
        # acme stopped before it ended (no line in the history); a new process starts
        d = FakeDaemon()
        E.rb_tick(d)
        self.assertEqual(self.started, ['acme (scheduled)'] * 2)
        E.rb_tick(d)                                     # once
        self.assertEqual(len(self.started), 2)

    def test_ended_is_not_made_again(self):
        E.rb_tick(FakeDaemon())
        E.rb_history_add(STORE, {'at': time.time(), 'by': 'acme (scheduled)',
                                 'node': E.node_name(), 'targets': [], 'ok': True})
        d = FakeDaemon()
        E.rb_tick(d)                                     # restarted after it ended
        E.rb_tick(d)
        self.assertEqual(self.started, ['acme (scheduled)'])
        # a backup of yesterday's or one by hand does not count for the day
        STORE.db.run('DELETE FROM meta WHERE k = ?', (E.node_key('rbackup', 'runs'),))
        E.rb_history_add(STORE, {'at': time.time() - 2 * 86400, 'by': 'acme (scheduled)',
                                 'node': E.node_name(), 'targets': [], 'ok': True})
        E.rb_history_add(STORE, {'at': time.time(), 'by': 'tester',
                                 'node': E.node_name(), 'targets': [], 'ok': True})
        E.rb_tick(FakeDaemon())
        self.assertEqual(len(self.started), 2)


class ReportLeftUnmade(unittest.TestCase):
    """A scheduled report whose run acme stopped in the middle of is made after the start."""

    @classmethod
    def setUpClass(cls):
        from acmelib.certs import reports as RP
        cls.RP = RP
        cls.saved = dict(E.CONFIG)
        E.CONFIG.update(mail_mode='off')

    @classmethod
    def tearDownClass(cls):
        E.CONFIG.clear()
        E.CONFIG.update(cls.saved)

    def setUp(self):
        RP = self.RP
        old = RP.get_row(STORE, 'w2-weekly')
        b = {'name': 'w2-weekly', 'kind': 'inventory', 'formats': ['csv']}
        if old:
            b['id'] = old['id']
        self.r = RP.need(STORE, RP.save(STORE, b, 'test')['id'])
        STORE.db.update('cert_reports', self.r['id'], {'schedule': json.dumps(
            {'every': 'weekly', 'day': 1, 'hour': 7, 'since': self.mon - 30 * 86400})})
        for k in ('period', 'claim', 'again'):
            STORE.db.run('DELETE FROM meta WHERE k = ?', ('reports:%s:%d' % (k, self.r['id']),))
        STORE.db.run('DELETE FROM cert_report_runs WHERE report_id = ?', (self.r['id'],))
        self.r = self.RP.need(STORE, self.r['id'])

    mon = time.mktime((2026, 11, 23, 8, 0, 0, 0, 0, -1))       # a Monday 08:00, past 07:00

    def ticks(self, times=2):
        with mock.patch.object(self.RP, '_now', lambda: self.mon):
            for _ in range(times):
                self.RP._reports_tick(STORE)
        return len(self.RP.runs(STORE, self.r))

    def test_stopped_in_the_middle_is_made_once(self):
        RP = self.RP
        # the week's run: claimed, then acme stopped before it was kept
        with mock.patch.object(RP, 'run', side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self.ticks(1)
        self.assertEqual(STORE.get_meta('reports:period:%d' % self.r['id']), 'w:2026-48')
        self.assertEqual(self.ticks(), 0, 'the same process: it is not taken for gone')
        with mock.patch.object(RP, '_STARTED', time.time() + 1):    # a new process
            self.assertEqual(self.ticks(), 1, 'made once after the start')
            self.assertEqual(self.ticks(), 1, 'not again')

    def test_made_is_not_made_again(self):
        self.assertEqual(self.ticks(), 1)
        with mock.patch.object(self.RP, '_STARTED', time.time() + 1):
            self.assertEqual(self.ticks(), 1)

    def test_other_node_gone(self):
        STORE.set_meta('reports:period:%d' % self.r['id'], 'w:2026-48')
        STORE.set_meta('reports:claim:%d' % self.r['id'], json.dumps(
            {'key': 'w:2026-48', 'at': time.time() - 60, 'node': 'w2-other'}))
        with mock.patch.object(jobs, '_node_alive', lambda store, n: False):
            self.assertEqual(self.ticks(), 0, 'a minute ago: it may still be at it')
        STORE.set_meta('reports:claim:%d' % self.r['id'], json.dumps(
            {'key': 'w:2026-48', 'at': time.time() - 7200, 'node': 'w2-other'}))
        with mock.patch.object(jobs, '_node_alive', lambda store, n: True):
            self.assertEqual(self.ticks(), 0, 'its node alive')
        with mock.patch.object(jobs, '_node_alive', lambda store, n: False):
            self.assertEqual(self.ticks(), 1, 'its node gone: made here, once')
        # a claim of before 1.0.143 (who took it not kept): as before, nothing
        STORE.db.run('DELETE FROM cert_report_runs WHERE report_id = ?', (self.r['id'],))
        STORE.db.run('DELETE FROM meta WHERE k = ?', ('reports:again:%d' % self.r['id'],))
        STORE.db.run('DELETE FROM meta WHERE k = ?', ('reports:claim:%d' % self.r['id'],))
        with mock.patch.object(self.RP, '_STARTED', time.time() + 1):
            self.assertEqual(self.ticks(), 0)


class SplitReads(unittest.TestCase):
    """What only reads goes on on the frozen node of a split; changes do not."""
    READS = ('/api/history/preview', '/api/trash/preview', '/api/reports/preview',
             '/api/teams/digest_preview', '/api/reqprofiles/dryrun',
             '/api/reqprofiles/template_preview', '/api/certs/plan', '/api/certs/check',
             '/api/certs/run_plan', '/api/fleet/takeover_preview')

    def test_reads_go_on_changes_do_not(self):
        with mock.patch.object(E, 'split_frozen', lambda: True):
            for p in self.READS:
                self.assertIn(('POST', p), E.ROUTES, p)
                self.assertEqual(E.split_refuses('POST', p), '', p)
            for p in ('/api/history/restore', '/api/trash/restore', '/api/reports/run',
                      '/api/reports/save', '/api/teams/digest_send_me', '/api/fleet/takeover',
                      '/api/certs/save'):
                self.assertIn('cannot reach each other', E.split_refuses('POST', p), p)


if __name__ == '__main__':
    unittest.main(verbosity=2)
