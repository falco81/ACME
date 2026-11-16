#!/usr/bin/env python3
"""This machine's database shown as a database server (db_local_card, 1.0.115).

    python3 test/test_db_local_card.py        (as root, with PostgreSQL 16 installed)

One acme node on a PostgreSQL 16 of its own (initdb into a folder of its own, its own port -
the clusters on 5432/5433 are not touched), on 127.0.0.1, no agent:

* Off (the default): GET /api/db-agent is what it was - no `local`, the same keys; nothing is
  written for it (no row 'dblocal:node:...').
* On: the node looks at its own database server by itself and writes its row; GET
  /api/db-agent says `local` - this node's tile: the engine and its version, running and since
  when, TLS, the connections, the data's disk, the RAM, the processors, the load, the uptime -
  and never the database's password. "Look now" (POST look) answers with the row. A row of a
  node not in the cluster is not shown. /api/ha and /api/dbtls have the same keys on and off.
* Off again: no `local`, and this node's row taken away.
* MariaDB on this machine: the same tile (its version, TLS, since when, the connections).
"""
import json
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from test_ha import Node, wait_for  # noqa: E402
from test_external_db import (PgServer, MyServer, can_run, can_run_my, quietly,  # noqa: E402
                              set_up_or_clean)

DB_PW = 'Local-Card-Pw-4711'
BEFORE_KEYS = {'ok', 'db_admin', 'node', 'servers', 'applies', 'where', 'ha_mode', 'addresses'}


@unittest.skipUnless(can_run(), 'needs root, PostgreSQL 16 (initdb), runuser and psql')
class LocalCard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        set_up_or_clean(cls, cls._set_up)

    @classmethod
    def _set_up(cls):
        cls.db = PgServer('local')
        cls.db.sql("CREATE ROLE acme LOGIN PASSWORD '%s'" % DB_PW)
        cls.db.sql('CREATE DATABASE acme OWNER acme')
        cls.n = Node('n0', db={'db_engine': 'postgres', 'db_host': '127.0.0.1',
                               'db_port': cls.db.port, 'db_name': 'acme', 'db_user': 'acme',
                               'db_password': DB_PW})
        cls.n.env.update(ACME_DBLOCAL_EVERY='2')
        cls.n.add_account()
        cls.n.start()

    @classmethod
    def tearDownClass(cls):
        quietly(*[getattr(cls, x).cleanup for x in ('n',) if getattr(cls, x, None)],
                *[getattr(cls, x).cleanup for x in ('db',) if getattr(cls, x, None)])

    def rows(self):
        return self.db.sql("SELECT k FROM meta WHERE k LIKE 'dblocal:node:%'", db='acme')

    def setting(self, on):
        self.n.ok('POST', '/api/settings', {'settings': {'db_local_card': bool(on)}})

    def test_1_off_as_before(self):
        v = self.n.ok('GET', '/api/db-agent')
        self.assertEqual(set(v), BEFORE_KEYS)
        self.assertEqual(v['where']['kind'], 'here')
        self.assertEqual(v['servers'], [])
        time.sleep(5)
        self.assertEqual(self.rows(), '')
        got = self.n.ok('POST', '/api/db-agent', {'action': 'look'})
        self.assertIsNone(got['row'])
        self.assertNotIn('local', got['view'])
        self.assertEqual(self.rows(), '')

    def test_2_on_the_tile(self):
        ha0 = set(self.n.ok('GET', '/api/ha'))
        tls0 = set(self.n.ok('GET', '/api/dbtls'))
        self.setting(True)
        try:
            v = wait_for(lambda: (self.n.ok('GET', '/api/db-agent').get('local') or None), 30, 1,
                         'the row of this machine\'s database server')
            self.assertIsInstance(v, list)
            self.assertEqual(len(v), 1, v)
            s = v[0]
            self.assertTrue(s['me'])
            self.assertEqual(s['node'], 'n0')
            self.assertEqual(s['kind'], 'db')
            self.assertEqual(s['engine'], 'postgres')
            self.assertEqual((s['host'], s['port']), ('127.0.0.1', self.db.port))
            self.assertFalse(s['stale'])
            f = s['facts']
            self.assertTrue(f['running'])
            self.assertTrue(str(f['version']).startswith('16'), f)
            self.assertIs(f['ssl'], False)
            self.assertGreaterEqual(f['connections'], 1)
            self.assertGreater(f['started'], time.time() - 86400)
            for k in ('cpus', 'ram', 'avail', 'load', 'uptime'):
                self.assertTrue(f.get(k), k)
            self.assertGreater(f['disk']['total'], 0)
            view = self.n.ok('GET', '/api/db-agent')
            self.assertNotIn(DB_PW, json.dumps(view))
            self.assertEqual(set(view), BEFORE_KEYS | {'local'})
            # no agent: nothing of it said as a database server of an agent
            self.assertEqual(view['servers'], [])
            self.assertNotIn('dbservers', self.n.ok('GET', '/api/ha'))
            self.assertEqual(set(self.n.ok('GET', '/api/ha')), ha0)
            self.assertEqual(set(self.n.ok('GET', '/api/dbtls')), tls0)
            # Look now
            got = self.n.ok('POST', '/api/db-agent', {'action': 'look'})
            self.assertEqual(got['row']['node'], 'n0')
            self.assertEqual(len(got['view']['local']), 1)
            # a node that is not of this cluster: its row not shown
            self.db.sql("INSERT INTO meta (k, v) VALUES ('dblocal:node:gone', '%s')"
                        % json.dumps({'at': time.time(), 'host': 'localhost', 'port': 5432,
                                      'engine': 'postgres', 'facts': {}}), db='acme')
            self.assertEqual([x['node'] for x in self.n.ok('GET', '/api/db-agent')['local']],
                             ['n0'])
            self.db.sql("DELETE FROM meta WHERE k = 'dblocal:node:gone'", db='acme')
            # A setting waiting for a restart: said, and the restart offered only where the
            # server's own settings may restart it (here no postgresql service: not)
            self.db.sql('ALTER SYSTEM SET max_connections = 123')
            self.db.sql('SELECT pg_reload_conf()')
            r = wait_for(lambda: self.n.ok('GET', '/api/db-agent')['local'][0].get('restart'),
                         20, 1, 'the restart waited for')
            self.assertIn('max_connections', r['waiting'])
            self.assertFalse(r['may'])
            self.db.sql('ALTER SYSTEM RESET max_connections')
            self.db.sql('SELECT pg_reload_conf()')
        finally:
            self.setting(False)

    def test_3_off_again(self):
        self.setting(True)
        wait_for(lambda: self.rows(), 30, 1, 'the row written')
        self.setting(False)
        self.assertNotIn('local', self.n.ok('GET', '/api/db-agent'))
        wait_for(lambda: self.rows() == '', 30, 1, 'the row taken away')



@unittest.skipUnless(can_run_my(), 'needs root and MariaDB (mariadb-install-db, mariadbd)')
class LocalCardMariaDb(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        set_up_or_clean(cls, cls._set_up)

    @classmethod
    def _set_up(cls):
        cls.db = MyServer('localmy')
        cls.db.sql("CREATE DATABASE acme CHARACTER SET utf8mb4; CREATE USER 'acme'@'127.0.0.1' "
                   "IDENTIFIED BY '%s'; GRANT ALL ON acme.* TO 'acme'@'127.0.0.1'" % DB_PW)
        cls.n = Node('m0', db={'db_engine': 'mariadb', 'db_host': '127.0.0.1',
                               'db_port': cls.db.port, 'db_name': 'acme', 'db_user': 'acme',
                               'db_password': DB_PW})
        cls.n.env.update(ACME_DBLOCAL_EVERY='2')
        cls.n.add_account()
        cls.n.start()

    @classmethod
    def tearDownClass(cls):
        quietly(*[getattr(cls, x).cleanup for x in ('n',) if getattr(cls, x, None)],
                *[getattr(cls, x).cleanup for x in ('db',) if getattr(cls, x, None)])

    def test_tile(self):
        self.assertNotIn('local', self.n.ok('GET', '/api/db-agent'))
        self.n.ok('POST', '/api/settings', {'settings': {'db_local_card': True}})
        try:
            v = wait_for(lambda: (self.n.ok('GET', '/api/db-agent').get('local') or None), 30, 1,
                         'the row of this machine\'s MariaDB')
            s = v[0]
            self.assertEqual((s['engine'], s['me'], s['port']), ('mariadb', True, self.db.port))
            f = s['facts']
            self.assertTrue(f['running'], f)
            self.assertIn('MariaDB', f['version'])
            self.assertIn(f['ssl'], (True, False))
            self.assertGreaterEqual(f['connections'], 1)
            self.assertGreater(f['started'], time.time() - 86400)
            self.assertNotIn('restart', s)
            self.assertNotIn(DB_PW, json.dumps(v))
        finally:
            self.n.ok('POST', '/api/settings', {'settings': {'db_local_card': False}})


if __name__ == '__main__':
    unittest.main(verbosity=2)
