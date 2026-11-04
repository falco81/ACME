#!/usr/bin/env python3
"""Settings -> High security: what is in effect on every node (1.0.41).

    python3 test/test_hisec_nodes.py

This node as it is now; the others from their heartbeats - one not heard from lately,
or of a version that does not say it, said so.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-hsn-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402


class Nodes(unittest.TestCase):
    def test_this_node_as_it_is(self):
        with mock.patch.dict(E.CONFIG, {'high_security': 1}):
            now = E.hisec_node_now()
        self.assertTrue(now['high_security'])
        self.assertIn('db_guard', now)
        self.assertIn('guard_key', now)

    def test_in_the_heartbeat(self):
        self.assertIn("'hisec_now': hisec_node_now()",
                      open(os.path.join(ROOT, 'acmelib/engine/190_two_servers_both_answering.py')).read())

    def test_the_others_from_their_beats(self):
        me = E.node_name()
        beats = [{'name': me, 'me': True, 'alive': True},
                 {'name': 'peer-new', 'alive': True, 'age': 3, 'version': '1.0.41', 'db_guard': True,
                  'hisec_now': {'high_security': True, 'db_guard': True, 'guard_key': True,
                                'refused': 2}},
                 {'name': 'peer-old', 'alive': True, 'age': 5, 'version': '1.0.39',
                  'db_guard': False},
                 {'name': 'peer-gone', 'alive': False, 'age': 900, 'version': '1.0.41',
                  'hisec_now': {'high_security': False, 'db_guard': False}}]
        with mock.patch.object(E, 'ha_nodes', return_value=beats):
            got = {n['name']: n for n in E.hisec_nodes(None)}
        self.assertEqual(list(got)[0], me)
        self.assertTrue(got[me]['me'] and got[me]['known'] and got[me]['alive'])
        self.assertEqual(sum(1 for n in got.values() if n['name'] == me), 1)
        self.assertTrue(got['peer-new']['high_security'])
        self.assertEqual(got['peer-new']['refused'], 2)
        self.assertFalse(got['peer-old']['known'])
        self.assertIsNone(got['peer-old']['high_security'])
        self.assertFalse(got['peer-gone']['alive'])


if __name__ == '__main__':
    unittest.main()
