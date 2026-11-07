#!/usr/bin/env python3
"""The daemon's own connection to its PostgreSQL and the link between the databases (1.0.57):

    python3 test/test_dbtls_auto.py

One certificate for both: the link renews it while it is on, Settings → The database does not at
the same time; a connection the rescue moved back to no TLS goes encrypted again by itself once
that works, and not when it was switched off by hand.
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-dbtls-')
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


class D:
    store = STORE


class Auto(unittest.TestCase):
    def setUp(self):
        self.saved = {k: E.CONFIG.get(k) for k in ('db_engine', 'db_host', 'ha_mode', 'ha_tls', 'db_tls',
                                                    'db_tls_ca')}
        E.CONFIG.update(db_engine='postgres', db_host='127.0.0.1', ha_mode='replicated',
                        ha_tls='verify-full', db_tls='', db_tls_ca='')
        self.real = (E.dbtls_probe, E.dbtls_switch, E.dbtls_publish, E._dbtls_server_cert)
        self.probe_ok, self.switched, self.made = True, [], []
        E.dbtls_probe = lambda mode, ca: {'ok': self.probe_ok, 'said': 'x'}
        E.dbtls_switch = lambda d, m, c, by: self.switched.append((m, c, by))
        E.dbtls_publish = lambda d, force=False: None
        E._dbtls_server_cert = lambda st, by: self.made.append(by)
        for k in ('dbtls:rescued:', 'dbtls:server:', 'hatls:want', 'hatls:node:'):
            STORE.db.run("DELETE FROM meta WHERE k LIKE ?", (k + '%',))

    def tearDown(self):
        E.dbtls_probe, E.dbtls_switch, E.dbtls_publish, E._dbtls_server_cert = self.real
        E.CONFIG.update(self.saved)

    def test_back_to_tls_by_itself(self):
        k = 'dbtls:rescued:' + E.node_name()
        STORE.set_meta(k, json.dumps({'at': time.time() - 700, 'was': 'verify-full',
                                      'ca': '/x/ca.pem', 'why': 'certificate verify failed'}))
        self.probe_ok = False
        E._dbtls_again(D)
        self.assertEqual(self.switched, [])             # still does not go: kept, tried again
        self.assertTrue(STORE.get_meta(k))
        E._dbtls_again(D)
        self.assertEqual(self.switched, [])             # not again within 10 minutes
        r = json.loads(STORE.get_meta(k))
        r['tried'] = time.time() - 700
        STORE.set_meta(k, json.dumps(r))
        self.probe_ok = True
        E._dbtls_again(D)
        self.assertEqual(self.switched, [('verify-full', '/x/ca.pem', 'acme (it works with TLS again)')])

    def test_not_when_set_by_hand_since(self):
        k = 'dbtls:rescued:' + E.node_name()
        STORE.set_meta(k, json.dumps({'at': time.time() - 700, 'was': 'verify-full', 'ca': ''}))
        E.CONFIG['db_tls'] = 'require'                  # chosen in the wizard since
        E._dbtls_again(D)
        self.assertEqual(self.switched, [])
        self.assertFalse(STORE.get_meta(k))

    def test_link_renews_it_alone(self):
        STORE.set_meta('dbtls:server:' + E.node_name(), json.dumps(
            {'cert_end': time.time() + 86400, 'at': 0, 'names': ['x']}))   # old, kept from before
        E.DBTLS_WORK['renew'] = None
        E.dbtls_tick(D)
        time.sleep(0.2)
        self.assertEqual(self.made, [])                 # the link is on: it renews it
        E.CONFIG['ha_tls'] = ''                          # the link off: this one renews it
        E.dbtls_tick(D)
        time.sleep(0.2)
        self.assertEqual(self.made, ['acme (renewed)'])

    def test_rescue_kept_for_after_a_restart(self):
        src = open(os.path.join(ROOT, 'acmelib/engine/325_something_asked_of_every.py')).read()
        self.assertIn("set_meta('dbtls:rescued:' + node_name()", src)
        self.assertIn("_meta_obj(store, 'dbtls:rescued:' + node_name())", src)


if __name__ == '__main__':
    unittest.main(verbosity=1)
