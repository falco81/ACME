#!/usr/bin/env python3
"""The certificate manager's jobs are a log (1.0.58):

    python3 test/test_jobs_log.py

Forgotten with the events older than N days - a queued or running one never; a copy put back
without its logs keeps the finished jobs here and drops the queued ones (they named the
certificates of the data replaced).
"""
import gzip
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-jobslog-')
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


def job(state, ts):
    STORE.db.insert('cert_jobs', {'ts': ts, 'kind': 'renew', 'cert_id': 1, 'state': state,
                                  'ok': 0, 'steps': '[]'})


class JobsLog(unittest.TestCase):
    def setUp(self):
        STORE.db.run('DELETE FROM cert_jobs')

    def states(self):
        return sorted(r['state'] for r in STORE.db.rows('SELECT state FROM cert_jobs'))

    def test_a_log(self):
        self.assertIn('cert_jobs', E.LOG_TABLES)

    def test_prune_keeps_live_ones(self):
        old = time.time() - 40 * 86400
        for st in ('done', 'failed', 'queued', 'running'):
            job(st, old)
        job('done', time.time())
        gone = E.db_prune(STORE, 30)
        self.assertEqual(gone['cert_jobs'], 2)
        self.assertEqual(self.states(), ['done', 'queued', 'running'])

    def test_put_back_without_logs(self):
        job('done', time.time())
        job('queued', time.time())
        src = os.path.join(TMP, 'copy.json.gz')
        with gzip.open(src, 'wt', encoding='utf-8') as f:
            f.write(json.dumps({'acme': '1'}) + '\n')
            f.write(json.dumps({'table': 'cert_jobs'}) + '\n')
            f.write(json.dumps({'id': 99, 'ts': 1, 'kind': 'renew', 'state': 'done'}) + '\n')
        E._load_tables(STORE.db, src, False, None, gzip)
        self.assertEqual(self.states(), ['done'])       # the copy's not taken, the queued dropped
        E._load_tables(STORE.db, src, True, None, gzip)
        self.assertEqual([r['id'] for r in STORE.db.rows('SELECT id FROM cert_jobs')], [99])


if __name__ == '__main__':
    unittest.main(verbosity=1)
