#!/usr/bin/env python3
"""The hunt of 1.0.48, round 1 (security, the cluster, the pages) - each checked.

    python3 test/test_hunt_b1.py
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-huntb1-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


def engine(prefix):
    d = os.path.join(ROOT, 'acmelib', 'engine')
    return read('acmelib', 'engine', [n for n in os.listdir(d) if n.startswith(prefix + '_')][0])


class Cluster(unittest.TestCase):
    def setUp(self):
        self.store = E.Storage(E.open_db())

    def test_a_failed_rebuild_marked_from_the_command_line_too(self):
        src = engine('195')
        self.assertIn("store = Storage(local)", src)

    def test_the_upgrade_waits_for_a_node_stepped_aside(self):
        self.assertIn("beat_out = isinstance(n.get('maintenance'), dict)", engine('205'))

    def test_a_restart_waits_for_a_node_in_service(self):
        self.assertIn("n['maintenance'].get('on')", engine('300'))

    def test_the_lease_read_again_before_a_scan(self):
        self.assertIn("now_lead = leader(self.store)", read('acmelib', 'certs', 'renewer.py'))

    def test_the_other_not_known_yet_is_alive(self):
        E.LEAD_FAR.clear()
        with mock.patch.dict(E.CONFIG, {'ha_mode': 'replicated'}):
            E.LEAD_FAR_LOCK.acquire()
            try:
                self.assertTrue(E._alive_far('peer'))
            finally:
                E.LEAD_FAR_LOCK.release()

    def test_a_node_called_day_claims_no_shared_key(self):
        with mock.patch.dict(E.CONFIG, {'ha_mode': 'replicated'}), \
                mock.patch.object(E, 'node_name', return_value='day'), \
                mock.patch.object(E, 'ha_lead', return_value=False):
            self.assertFalse(E.claim_once(self.store, 'osup:check:day', '2026-11-05'))
            self.assertTrue(E.claim_once(self.store, 'rbackup_day:day', '2026-11-05-x'))

    def test_a_rename_carries_the_days_and_takes_the_old_asks(self):
        src = engine('245')
        self.assertIn("for k in ('backup_day:', 'rbackup_day:'):", src)
        self.assertIn("'%' + NODE_KEY_SEP + old[:63]", src)


if __name__ == '__main__':
    unittest.main()
