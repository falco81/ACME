#!/usr/bin/env python3
"""Hunt w10 (regressions of 1.0.144) - a backup no longer holds the daemon's database.

    python3 test/test_hunt_rw10_regress.py

1.0.144 made every copy of the database one moment (Db.snapshot, dump_tables): its read
transaction ran on the daemon's own connection, under that connection's lock, for the whole
copy - every page, job and tick of the daemon (all on that connection) waited until the backup
ended (a minute of a large log). The snapshot is read on a connection of its own now.
"""
import os
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
TMP = tempfile.mkdtemp(prefix='acme-rw10-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import store as S  # noqa: E402,F401  (its tables)


class BackupDoesNotHoldTheDaemon(unittest.TestCase):
    n = 0

    def db(self):
        BackupDoesNotHoldTheDaemon.n += 1
        db = E.Db('sqlite', path=os.path.join(TMP, 'db%d.sqlite' % self.n))
        E.Storage(db)
        db.lanes_on = True              # as in the daemon
        db.insert('certs', {'name': 'web', 'names': '["a.example"]', 'version': 1,
                            'serial': 'S1', 'state': 'ok'})
        return db

    def waited_during_copy(self, db):
        """How long a statement of another thread (a page, a job) waited while the copy was
        reading its tables - asked right after the copy read `certs`."""
        real, got = E.Db.rows, {}

        def rows(this, sql, args=()):
            out = real(this, sql, args)
            if 'FROM certs WHERE' in sql and 'wait' not in got:
                got['wait'] = None

                def other():
                    t = time.monotonic()
                    db.value('SELECT COUNT(*) FROM certs')
                    got['wait'] = time.monotonic() - t
                th = threading.Thread(target=other)
                th.start()
                th.join(4)              # the copy goes on after at most this
                got['thread'] = th
            return out
        E.Db.rows = rows
        try:
            E.dump_tables(db, os.path.join(TMP, 'copy-%d.json.gz' % self.n))
        finally:
            E.Db.rows = real
        got['thread'].join(10)
        return got['wait']

    def test_other_statements_go_on_during_a_copy(self):
        db = self.db()
        wait = self.waited_during_copy(db)
        self.assertIsNotNone(wait)
        self.assertLess(wait, 2, 'a statement of the daemon waited for the whole backup')
        # the daemon's connection is out of any transaction, and writes
        self.assertFalse(db.in_tx)
        db.run("UPDATE certs SET note = 'after' WHERE name = 'web'")
        self.assertEqual(db.value("SELECT note FROM certs WHERE name = 'web'"), 'after')
        db.close()

    def test_the_test_sees_the_old_way(self):
        """Without a connection of its own (as 1.0.144 read it, and still where a second one
        cannot be made): the other statement waits for the copy - what the test above sees."""
        db = self.db()
        real = E.Db._snapshot_conn
        E.Db._snapshot_conn = lambda self: None
        try:
            wait = self.waited_during_copy(db)
        finally:
            E.Db._snapshot_conn = real
        self.assertTrue(wait is None or wait >= 3.5)
        db.close()

    def test_no_connection_of_its_own_is_left_open(self):
        db = self.db()
        made = []
        real = E.Db._snapshot_conn

        def conn(this):
            got = real(this)
            made.append(got)
            return got
        E.Db._snapshot_conn = conn
        try:
            E.dump_tables(db, os.path.join(TMP, 'copy-x.json.gz'))
        finally:
            E.Db._snapshot_conn = real
        self.assertEqual(len(made), 1)
        self.assertIsNotNone(made[0])
        self.assertTrue(all(lane.conn is None for lane in made[0]._lanes.values()))
        db.close()

    def test_inside_a_transaction_reads_its_own(self):
        """A copy asked inside the thread's own transaction reads what it wrote (as before)."""
        db = self.db()
        path = os.path.join(TMP, 'copy-tx.json.gz')
        with db.transaction():
            db.run("UPDATE certs SET serial = 'S9' WHERE name = 'web'")
            E.dump_tables(db, path)
        import gzip
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            self.assertIn('"S9"', f.read())
        db.close()


if __name__ == '__main__':
    unittest.main()
