#!/usr/bin/env python3
"""HA edge cases (1.0.58):

    python3 test/test_ha_edges.py

The subscription's host read back as acme last set it (subconninfo is the superuser's alone);
the preferred node taken for down only when its own /healthz says so (not a TCP connection to
443); a signed row deleted with its signatures; acme 1.0.42's password policy taken over by
the lead alone in a replicated cluster.
"""
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-haedges-')
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
N = sys.modules['acmelib.engine'].__dict__


class Resp(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Edges(unittest.TestCase):
    def test_sub_host_as_acme_set_it(self):
        E.CONFIG['ha_slot'] = 1
        p = mock.patch.dict(N, {'ha_sub_here': lambda db, n: 'acme_from_2'})
        p.start()
        self.addCleanup(p.stop)
        real = STORE.db.run

        def fake(sql, *a, **k):
            if 'ALTER SUBSCRIPTION' in str(getattr(sql, 'sql', sql)) or 'log_' in str(sql):
                return 0
            return real(sql, *a, **k)
        with mock.patch.object(STORE.db, 'run', side_effect=fake):
            E.sub_connection_set(STORE, 'acme_from_2', "host=10.0.0.12 port=5432 dbname=acme "
                                 "user=acme password='x y'")
        sub = 'acme_from_2'
        row = json.loads(STORE.get_meta('ha:subhost:' + E.node_name()))
        self.assertEqual(row['host'], '10.0.0.12')
        self.assertNotIn('password', json.dumps(row))
        if row['sub'] == sub:
            self.assertEqual(E._sub_host(STORE), '10.0.0.12')
        STORE.set_meta('ha:subhost:' + E.node_name(), json.dumps({'sub': 'other', 'host': '1.2.3.4'}))
        self.assertEqual(E._sub_host(STORE), '')        # another subscription's: not known

    def test_peer_health(self):
        with mock.patch('urllib.request.urlopen', return_value=Resp(200, b'ok acme2\n')):
            self.assertEqual(E.split_peer_says('192.0.2.2'), 'up')
        err = urllib.error.HTTPError('u', 503, 'x', {}, io.BytesIO(b'down: the database does not open\n'))
        with mock.patch('urllib.request.urlopen', side_effect=err):
            self.assertEqual(E.split_peer_says('192.0.2.2'), 'down')
        err = urllib.error.HTTPError('u', 503, 'x', {}, io.BytesIO(b'maintenance acme2\n'))
        with mock.patch('urllib.request.urlopen', side_effect=err):
            self.assertEqual(E.split_peer_says('192.0.2.2'), '')    # maintenance is not "down"
        err = urllib.error.HTTPError('u', 403, 'x', {}, io.BytesIO(b'forbidden'))
        with mock.patch('urllib.request.urlopen', side_effect=err):
            self.assertEqual(E.split_peer_says('192.0.2.2'), '')
        with mock.patch('urllib.request.urlopen', side_effect=OSError('refused')):
            self.assertEqual(E.split_peer_says('192.0.2.2'), '')

    def test_meta_drop_with_signatures(self):
        k = 'host:rootkey:again:' + E.node_name()
        self.assertTrue(E.dbguard_meta_signed(k))
        STORE.set_meta(k, '1')
        head = 'sig:m:%s:' % E._dbguard_hash(k)
        STORE.set_meta(head + 'acme2', 'x')             # the other node's signature too
        E.meta_drop(STORE, k)
        self.assertIsNone(STORE.get_meta(k))
        self.assertEqual([r for r in E._dbguard_head_rows(STORE.db, head) if r['k'].startswith(head)], [])

    def test_policy_taken_over_by_the_lead_alone(self):
        STORE.db.run("DELETE FROM meta WHERE k IN ('host:pwpolicy:conf', 'pwpolicy:migrated:2')")
        saved = E.CONFIG.get('ha_mode')
        E.CONFIG['ha_mode'] = 'replicated'
        try:
            with mock.patch.dict(N, {'ha_lead': lambda st: False}):
                self.assertFalse(E.pwp_migrate(STORE))
                self.assertIsNone(STORE.get_meta('pwpolicy:migrated:2'))
            with mock.patch.dict(N, {'ha_lead': lambda st: True}):
                E.pwp_migrate(STORE)
                self.assertTrue(STORE.get_meta('pwpolicy:migrated:2'))
        finally:
            E.CONFIG['ha_mode'] = saved


if __name__ == '__main__':
    unittest.main(verbosity=1)
