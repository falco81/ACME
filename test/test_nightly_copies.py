"""The nightly copy of the database (1.0.39).

The dumps acme makes every night are called acme-ENGINE-STAMP-WHY; the names
taken were only otp's (otp-, opt-), so they were never listed, never counted
on the card The database on Overview (yellow: "last copy 3 days ago" beside
a dump of last night), never kept to "Copies kept" and could not be
downloaded. And the card's popup now says why it is the colour it is.

    python3 test/test_nightly_copies.py
"""
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-nightly-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def clear_dumps():
    if E.DUMP_DIR.is_dir():
        for f in E.DUMP_DIR.iterdir():
            f.unlink()


class TestNightlyDumps(unittest.TestCase):
    def setUp(self):
        clear_dumps()
        E.CONFIG['backup_daily'] = 1
        E.CONFIG['backup_keep'] = 14

    def test_a_dump_is_listed_and_counted(self):
        E.make_dump(STORE, 'daily')
        got = E.kept_dumps(STORE.db.engine)
        self.assertEqual(len(got), 1, got)
        self.assertTrue(got[0]['name'].startswith('acme-'))
        st = E.nightly_state(STORE)
        self.assertTrue(st['fresh'], st)
        self.assertEqual(st['why'], '')
        self.assertEqual(st['last_name'], got[0]['name'])

    def test_kept_to_copies_kept(self):
        E.CONFIG['backup_keep'] = 2
        for _ in range(4):
            E.make_dump(STORE, 'daily')
            time.sleep(1.05)                    # one name a second
        names = [x['name'] for x in E.kept_dumps(STORE.db.engine)]
        self.assertEqual(len(names), 2, names)

    def test_downloadable(self):
        E.make_dump(STORE, 'daily')
        name = E.kept_dumps(STORE.db.engine)[0]['name']
        self.assertTrue(E._kept_path(name, 'dump').is_file())


class TestWhyNotGreen(unittest.TestCase):
    def setUp(self):
        clear_dumps()
        for f in (E.BACKUP_DIR.iterdir() if E.BACKUP_DIR.is_dir() else []):
            f.unlink()
        E.CONFIG['backup_daily'] = 1
        E.CONFIG['ha_mode'] = ''
        STORE.db.run("DELETE FROM events WHERE kind = 'backups'")

    def old_dump(self, days):
        E.make_dump(STORE, 'daily')
        f = [p for p in E.DUMP_DIR.iterdir() if p.name.startswith('acme-')][0]
        t = time.time() - days * 86400
        for p in E.DUMP_DIR.iterdir():
            os.utime(str(p), (t, t))
        return f

    def test_none_yet(self):
        STORE.set_meta('backup_day', '')
        st = E.nightly_state(STORE)
        self.assertEqual(st['why'], 'none')
        self.assertTrue(st['next'] and st['next'] > time.time())

    def test_off(self):
        self.old_dump(3)
        E.CONFIG['backup_daily'] = 0
        st = E.nightly_state(STORE)
        self.assertEqual(st['why'], 'off')
        self.assertIsNone(st['next'])

    def test_late(self):
        self.old_dump(3)
        st = E.nightly_state(STORE)
        self.assertEqual(st['why'], 'late')
        self.assertFalse(st['fresh'])

    def test_failed_said_how(self):
        self.old_dump(3)
        STORE.add_event('backups', 'the daily dump failed: pg_dump: server version mismatch', 'bad')
        st = E.nightly_state(STORE)
        self.assertEqual(st['why'], 'failed')
        self.assertIn('server version mismatch', st['failed']['words'])

    def test_a_failure_before_the_last_copy_is_old_news(self):
        STORE.add_event('backups', 'the daily dump failed: once', 'bad')
        time.sleep(0.05)
        E.make_dump(STORE, 'daily')
        st = E.nightly_state(STORE)
        self.assertEqual(st['why'], '')
        self.assertIsNone(st['failed'])

    def test_other_node_on_one_database(self):
        self.old_dump(3)
        E.CONFIG['ha_mode'] = 'shared'
        try:
            STORE.set_meta('backup_day', time.strftime('%Y-%m-%d'))
            st = E.nightly_state(STORE)
            self.assertEqual(st['why'], 'other_node')
            self.assertTrue(st['shared'])
        finally:
            E.CONFIG['ha_mode'] = ''


if __name__ == '__main__':
    unittest.main()
