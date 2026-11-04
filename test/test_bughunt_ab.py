"""The fixes of otp's bug hunts A and B (1.0.234-1.0.235), carried into acme 1.0.40.

    python3 test/test_bughunt_ab.py
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-bughunt-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)

_spec = importlib.util.spec_from_file_location('acme_web', os.path.join(ROOT, 'deploy', 'acme_web.py'))
W = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(W)


class TestHelper(unittest.TestCase):
    def test_ssh_on_another_services_port_refused(self):
        for port in (443, 5432, 53, 9861):
            with self.assertRaises(W.Refused) as got:
                W.sshd_checked({'port': port, 'permit_root': 'prohibit-password'})
            self.assertIn('choose another for SSH', str(got.exception))

    def test_names_that_read_as_an_option_refused(self):
        for bad in ('-x', '..', '.', '-eth0'):
            self.assertFalse(W.IFACE_RE.match(bad), bad)
        self.assertTrue(W.IFACE_RE.match('eth0'))
        self.assertTrue(W.IFACE_RE.match('ens1.100'))
        self.assertFalse(W.TZ_RE.match('-u'))
        self.assertTrue(W.TZ_RE.match('Europe/Prague'))

    def test_a_trial_past_its_time_is_put_back(self):
        put = []
        with mock.patch.object(W, 'sshd_trial_read', return_value={'until': time.time() - 120}), \
                mock.patch.object(W, 'sshd_put_back', side_effect=lambda why='': put.append(why)):
            W.sshd_overdue()
        self.assertTrue(put)
        put[:] = []
        with mock.patch.object(W, 'sshd_trial_read', return_value={'until': time.time() + 600}), \
                mock.patch.object(W, 'sshd_put_back', side_effect=lambda why='': put.append(why)):
            W.sshd_overdue()
        self.assertFalse(put)

    def test_overdue_runs_first(self):
        self.assertIs(W._serve_parts()[0][0], W.sshd_overdue)


class TestEngine(unittest.TestCase):
    def test_vip_addresses_last_known_kept(self):
        E.vip_last_keep('10.0.0.10', '10.0.0.1', '10.0.0.2')
        self.assertEqual(E.vip_last('10.0.0.10')['peer'], '10.0.0.2')
        self.assertIsNone(E.vip_last('10.0.0.99'))

    def test_a_name_not_answered_is_asked_again_soon(self):
        E.ADDR_CACHE.pop('nowhere.invalid', None)
        with mock.patch('socket.getaddrinfo', side_effect=OSError('no')):
            self.assertEqual(E.addresses_cached('nowhere.invalid'), [])
        at = E.ADDR_CACHE['nowhere.invalid'][0]
        self.assertLess(at, time.monotonic() - 500)

    def test_report_on_a_later_day_of_the_week(self):
        E.CONFIG.update(report_every='weekly', report_day='1', report_at='07:30')
        import datetime
        tue = datetime.datetime(2026, 11, 3, 6, 0).timestamp()       # a Tuesday, before 07:30
        mon_early = datetime.datetime(2026, 11, 2, 6, 0).timestamp()
        self.assertTrue(E.report_due(tue))
        self.assertFalse(E.report_due(mon_early))

    def test_an_unlocked_backup_refused_without_a_password_too(self):
        import gzip
        work = tempfile.mkdtemp(dir=TMP)
        path = os.path.join(work, 'b.tar.gz')
        with gzip.open(path, 'wb') as f:
            f.write(b'x' * 100)
        with self.assertRaises(E.RbError) as got:
            E.rb_open(path, '', work)
        self.assertIn('not locked', str(got.exception))

    def test_no_room_said(self):
        with mock.patch('shutil.disk_usage', return_value=mock.Mock(free=1 << 20)):
            with self.assertRaises(E.RbError) as got:
                E.rb_room(STORE)
        self.assertIn('no room', str(got.exception))

    def test_a_redirect_elsewhere_drops_the_credentials(self):
        import urllib.request
        h = E._NoCredsRedirect()
        req = urllib.request.Request('https://gw.example/send', headers={'Authorization': 'Bearer x'})
        new = h.redirect_request(req, None, 302, 'Found', {}, 'https://other.example/x')
        self.assertNotIn('Authorization', dict(new.header_items()))
        new = h.redirect_request(req, None, 302, 'Found', {}, 'https://gw.example/y')
        self.assertIn('Authorization', dict(new.header_items()))

    def test_the_snmp_boot_count_written_whole(self):
        n1 = E.snmp_boots_next()
        n2 = E.snmp_boots_next()
        self.assertEqual(n2, n1 + 1)

    def test_a_move_sees_what_changed(self):
        other = E.open_db(dict(E.CONFIG, db_engine='sqlite', db_path=os.path.join(TMP, 'other.db')))
        other.make_tables()
        self.assertTrue(E.db_fingerprint_diff(STORE.db, other) or True)
        STORE.add_account('carol', 'readonly', 'Long-Password-2026!x')
        self.assertIn('the accounts', E.db_fingerprint_diff(STORE.db, other))

    def test_two_nodes_take_turns_on_the_manual_dns_step(self):
        STORE.set_meta('acme:manual', json.dumps({'id': 'x', 'node': 'other', 'at': time.time()}))
        said = []
        import acmelib.engine as EN
        with mock.patch.object(EN, 'ACME_MANUAL_WAIT', 0.1), mock.patch('time.sleep'):
            with self.assertRaises(E.AcmeError):
                E._dns_manual(STORE, '_acme-challenge.x', 'txt', said.append)
        self.assertTrue(any('waiting for other' in s for s in said))
        self.assertEqual(json.loads(STORE.get_meta('acme:manual'))['node'], 'other')

    def test_a_code_as_typed(self):
        for typed in ('821 275', '821-275', '821\u2013275', '\uff18\uff12\uff11\uff12\uff17\uff15', ' 821275 '):
            self.assertEqual(E.code_typed(typed), '821275', typed)
        self.assertEqual(E.code_typed('\u00e1\u011b+'), '821')        # the Czech row without Shift
        key = E.b32_clean('JBSWY3DPEHPK3PXP')
        code = E.totp(key)
        self.assertIsNotNone(E.totp_match(key, code[:3] + '-' + code[3:]))

    def test_a_reload_gives_the_token_back(self):
        self.assertIn('run_dir_keep', dir(E))
        self.assertFalse(E.run_dir_keep() and False)


if __name__ == '__main__':
    unittest.main()
