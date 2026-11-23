#!/usr/bin/env python3
"""Hunt r6, the scheduler: the daemon's loop, its sparing log and the certificates' jobs.

    python3 test/test_hunt_r6_scheduler.py

- log_sparing: a clock stepped back (NTP) silenced every line of a kind until it caught up.
- Job.cancelled / step: measured on the wall clock - stepped back, a stop asked from the other
  node (or the pages through meta) was not looked at for as long.
- jobs.submit: a job the pool refused stayed "queued", its certificate busy until a restart.
- Daemon.changed: a mark of another node not read yet was written over and taken as read - its
  settings never loaded here.
"""
import concurrent.futures
import os
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-r6sched-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)

from acmelib.certs import jobs as J  # noqa: E402


def fake_time(wall, mono):
    t = types.SimpleNamespace(**{k: getattr(time, k) for k in dir(time) if not k.startswith('_')})
    t.time = lambda: wall[0]
    t.monotonic = lambda: mono[0]
    return t


class SparingLog(unittest.TestCase):
    def test_clock_stepped_back(self):
        g = E.log_sparing.__globals__
        said = []
        wall = [1800000000.0]
        old_log, old_time = g['log'], g['time']
        g['log'] = lambda w, level='info': said.append(w)
        g['time'] = fake_time(wall, [0.0])
        try:
            E.log_sparing('r6-step', 'one', every=600)
            E.log_sparing('r6-step', 'quiet', every=600)
            wall[0] -= 86400                        # NTP stepped the clock back a day
            E.log_sparing('r6-step', 'after the step', every=600)
            E.log_sparing('r6-step', 'quiet again', every=600)
        finally:
            g['log'], g['time'] = old_log, old_time
        self.assertEqual(len(said), 2)
        self.assertTrue(said[1].startswith('after the step'))
        self.assertNotIn('-', said[1].split('last')[-1])


class Jobs(unittest.TestCase):
    def tearDown(self):
        J.time = time

    def test_stop_seen_after_a_step_back(self):
        wall, mono = [time.time()], [1000.0]
        J.time = fake_time(wall, mono)
        j = J.new_job(STORE, 'renew')
        try:
            self.assertFalse(j.cancelled())
            wall[0] -= 3600                         # the clock stepped back an hour
            STORE.set_meta(J.STOP_PREFIX + str(j.id), '1')
            wall[0] += 10
            mono[0] += 10
            self.assertTrue(j.cancelled())
        finally:
            with J._LOCK:
                J.RUNNING.pop(j.id, None)

    def test_refused_by_the_pool(self):
        cid = STORE.db.insert('certs', {'name': 'r6-pool', 'state': 'new', 'enabled': 1})
        dead = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        dead.shutdown()
        want = max(1, min(32, int(E.CONFIG.get('certs_parallel') or 4)))
        was = dict(J._POOL)
        J._POOL.update(pool=dead, size=want)
        try:
            with self.assertRaises(RuntimeError):
                J.submit(STORE, 'renew', lambda job: True, cert_id=cid)
        finally:
            J._POOL.clear()
            J._POOL.update(was)
        row = STORE.db.row('SELECT state FROM cert_jobs WHERE cert_id = ?', (cid,))
        self.assertEqual(row['state'], 'failed')
        self.assertFalse(J.cert_busy(STORE, cid))
        self.assertNotIn(cid, J.BUSY_CERTS)
        # ...and the next one runs
        ident = J.submit(STORE, 'renew', lambda job: True, cert_id=cid)
        for _ in range(100):
            if STORE.db.value('SELECT state FROM cert_jobs WHERE id = ?', (ident,)) == 'ok':
                break
            time.sleep(0.05)
        self.assertEqual(STORE.db.value('SELECT state FROM cert_jobs WHERE id = ?', (ident,)), 'ok')


class Changed(unittest.TestCase):
    def test_other_mark_not_taken_as_read(self):
        d = E.Daemon(STORE, serve=False)
        STORE.set_meta('conf_serial', '%.6f:acme2' % time.time())    # saved on another node
        d.changed('directories')
        self.assertNotEqual(STORE.get_meta('conf_serial', '0'), d.conf_serial)  # the loop reloads

    def test_own_change_taken_as_read(self):
        d = E.Daemon(STORE, serve=False)
        d.reload_all()
        d.changed('directories')
        self.assertEqual(STORE.get_meta('conf_serial', '0'), d.conf_serial)


if __name__ == '__main__':
    unittest.main(verbosity=1)
