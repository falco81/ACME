"""Re-addressing a node of an HA pair: otp 1.0.262's fixes carried into acme 1.0.56
(fix 4, R3-1, R3-5).

    python3 test/test_readdress_tell.py
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-readdress-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "nodea", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
import acmelib.engine as N  # noqa: E402  the engine's one namespace, where names are looked up

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def _del(k):
    STORE.db.run('DELETE FROM meta WHERE k = ?', (k,))


class TestAddrKey(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(N._addr_key('FD99:0:0:0:0:0:0:1'), 'fd99::1')
        self.assertEqual(N._addr_key('[fd99::1]'), 'fd99::1')
        self.assertEqual(N._addr_key(' NodeA.Example.cz '), 'nodea.example.cz')
        self.assertNotEqual(N._addr_key('10.0.0.1'), N._addr_key('10.0.0.12'))
        self.assertEqual(N._addr_key(None), '')


class TestOneAddress(unittest.TestCase):
    """Fix 4: 10.0.0.1 is not "in" 10.0.0.12."""

    def setUp(self):
        self.cfg = mock.patch.dict(N.CONFIG, {'ha_mode': 'replicated', 'ha_address': '10.0.0.12',
                                              'ha_peer': '10.0.0.2', 'ha_slot': 1})
        self.cfg.start()

    def tearDown(self):
        self.cfg.stop()

    def _run(self, **kw):
        with mock.patch.object(N, '_readdress_hba', return_value='pg_hba.conf changed'), \
                mock.patch.object(N, 'write_file_settings'), \
                mock.patch.object(N, 'once_peer_forget'), \
                mock.patch.object(N, 'hatls_check_soon'), \
                mock.patch.object(N, 'ha_sub_here', return_value='acme_from_2'), \
                mock.patch.object(STORE.db, 'value', return_value=None):
            return N.ha_readdress(STORE, tell=False, **kw)

    def test_prefix_of_the_other_is_taken(self):
        got = self._run(peer='10.0.0.1')
        self.assertIn('ha_peer = 10.0.0.1 (was 10.0.0.2)', got['done'])

    def test_the_same_address_refused(self):
        with self.assertRaises(ValueError) as e:
            self._run(peer='10.0.0.12')
        self.assertIn('cannot have one address', str(e.exception))
        N.CONFIG['ha_address'] = 'FD99:0:0:0:0:0:0:1'
        with self.assertRaises(ValueError):
            self._run(peer='fd99::1')

    def test_unchanged_in_another_form(self):
        N.CONFIG['ha_peer'] = 'FD99:0:0:0:0:0:0:2'
        with mock.patch.object(N, '_sub_host', return_value=''):
            got = self._run(peer='fd99::2')
        self.assertEqual(got['done'], [])


class FakeDaemon:
    store = STORE


class TestKeepDropsOld(unittest.TestCase):
    """R3-1: Keep asks the other node to drop the old line only for a new address it was told."""

    def setUp(self):
        _del('readdress:dropold:nodea')
        _del('net:keep:nodea')

    def _keep(self, **job):
        job.setdefault('id', 'j1')
        STORE.set_meta('net:keep:nodea', json.dumps({'id': job['id'], 'by': 'admin'}))
        with mock.patch.object(N, 'node_name', return_value='nodea'):
            N.net_trial_tick(FakeDaemon(), dict(state='trial', trial_until=time.time() + 60, **job))
        return STORE.get_meta('readdress:dropold:nodea')

    def test_new_address_told(self):
        got = self._keep(keep_old=True, told=True,
                         want={'old_ip': '10.0.0.1', 'new_ip': '10.0.0.3', 'ip_changed': True})
        self.assertEqual(json.loads(got)['old'], '10.0.0.1')

    def test_gateway_only(self):
        self.assertIsNone(self._keep(keep_old=True, told=False, want={
            'old_ip': '10.0.0.1', 'new_ip': '10.0.0.1', 'ip_changed': False}))

    def test_not_told(self):
        self.assertIsNone(self._keep(keep_old=True, want={
            'old_ip': '10.0.0.1', 'new_ip': '10.0.0.3', 'ip_changed': True}))

    def test_old_row_with_one_address_drops_nothing(self):
        _del('readdress:dropold:done:nodea')
        STORE.set_meta('readdress:dropold:nodeb', json.dumps(
            {'id': 'x1', 'from': 'nodeb', 'old': '10.0.0.2', 'new': '10.0.0.2'}))
        try:
            with mock.patch.object(N, 'node_name', return_value='nodea'), \
                    mock.patch.object(N, '_readdress_hba') as hba:
                N.readdress_dropold_tick(STORE)
            hba.assert_not_called()
            self.assertEqual(STORE.get_meta('readdress:dropold:done:nodea'), 'x1')
        finally:
            _del('readdress:dropold:nodeb')


class TestTellAgain(unittest.TestCase):
    """R3-5: a failed tell after going back is kept and tried again until it succeeds."""

    K = 'readdress:tell:nodea'

    def setUp(self):
        _del(self.K)
        _del('net:job:nodea')
        N.READDRESS_TELL_TRIED['at'] = None
        self.cfg = mock.patch.dict(N.CONFIG, {'ha_mode': 'replicated', 'ha_address': '10.0.0.1',
                                              'ha_peer': '10.0.0.2'})
        self.cfg.start()
        self.nn = mock.patch.object(N, 'node_name', return_value='nodea')
        self.nn.start()

    def tearDown(self):
        self.nn.stop()
        self.cfg.stop()
        _del(self.K)
        _del('net:job:nodea')

    def test_kept_only_while_going_back(self):
        N._readdress_tell_keep(STORE, '10.0.0.2', '10.0.0.1', 'x', False, True)
        self.assertIsNone(STORE.get_meta(self.K))
        STORE.set_meta('net:job:nodea', json.dumps({'state': 'running', 'rollback': True,
                                                     'moved': time.time()}))
        N._readdress_tell_keep(STORE, '10.0.0.2', '10.0.0.1', 'x', False, True)
        self.assertEqual(json.loads(STORE.get_meta(self.K))['mine'], '10.0.0.1')
        N._readdress_tell_keep(STORE, '10.0.0.2', '10.0.0.1', 'x', False, False)
        self.assertIsNone(STORE.get_meta(self.K))

    def test_tried_again_until_told(self):
        STORE.set_meta(self.K, json.dumps({'peer': '10.0.0.2', 'mine': '10.0.0.1', 'by': 'x'}))
        fail = ([], ['could not be reached'])
        with mock.patch.object(N, 'readdress_tell', return_value=fail) as tell:
            N.readdress_tell_again(STORE)
            N.readdress_tell_again(STORE)          # within the minute: not again
            self.assertEqual(tell.call_count, 1)
        self.assertTrue(STORE.get_meta(self.K))
        N.READDRESS_TELL_TRIED['at'] = None
        with mock.patch.object(N, 'readdress_tell', return_value=(['told'], [])) as tell:
            N.readdress_tell_again(STORE)
        tell.assert_called_once_with('10.0.0.2', '10.0.0.1', 'x', False)
        self.assertIsNone(STORE.get_meta(self.K))

    def test_not_while_the_job_runs(self):
        STORE.set_meta(self.K, json.dumps({'peer': '10.0.0.2', 'mine': '10.0.0.1'}))
        STORE.set_meta('net:job:nodea', json.dumps({'state': 'rebooting', 'moved': time.time()}))
        with mock.patch.object(N, 'readdress_tell') as tell:
            N.readdress_tell_again(STORE)
        tell.assert_not_called()

    def test_dropped_once_ha_address_moved_on(self):
        STORE.set_meta(self.K, json.dumps({'peer': '10.0.0.2', 'mine': '10.0.0.1'}))
        N.CONFIG['ha_address'] = '10.0.0.5'
        with mock.patch.object(N, 'readdress_tell') as tell:
            N.readdress_tell_again(STORE)
        tell.assert_not_called()
        self.assertIsNone(STORE.get_meta(self.K))


if __name__ == '__main__':
    unittest.main()
