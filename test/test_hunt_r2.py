#!/usr/bin/env python3
"""The bugs and holes found in the hunt of 1.0.44, round 2 - each one shut, checked here.

    python3 test/test_hunt_r2.py
"""
import gzip
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-hunt2-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'none'))
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402
from acmelib.certs import renewer as R  # noqa: E402
from acmelib.certs import dnsserver as DS  # noqa: E402
from acmelib.certs import api_checks as AC  # noqa: E402
from acmelib.plugins.targets import _common as TC  # noqa: E402
from acmelib.plugins.targets import ssh as TSSH  # noqa: E402


class Backups(unittest.TestCase):
    def good(self, **kw):
        return dict({'id': 'a1', 'kind': 'sftp', 'host': 'backup.example.cz', 'port': 22,
                     'user': 'acme', 'path': '/srv/acme'}, **kw)

    def test_runtime_checked(self):
        E.rb_runtime_checked(self.good())
        E.rb_runtime_checked({'kind': 'folder', 'path': '/mnt/backup'})
        for bad in (dict(user='-oProxyCommand=id'), dict(host='-oProxyCommand=id'),
                    dict(path='/srv/x!id'), dict(path='/srv/$(id)'), dict(kind='smb', path='a;b'),
                    dict(user='a b'), dict(host='a b'), dict(kind='nope'),
                    dict(path='/srv/x\nput y')):
            with self.assertRaises(E.RbError, msg=bad):
                E.rb_runtime_checked(self.good(**bad))

    def test_saved_refuses_bang(self):
        with self.assertRaises(ValueError):
            E.rb_checked({'kind': 'smb', 'host': 'nas', 'share': 'b', 'path': 'x!id'})

    def test_transport_checks_first(self):
        with self.assertRaises(E.RbError):
            E.rb_transport(self.good(user='-oProxyCommand=id'))

    def test_ssh_ends_its_options(self):
        t = E.RbSsh.__new__(E.RbSsh)
        t.t, t.opts, t.dest = self.good(), ['-oBatchMode=yes'], 'acme@backup.example.cz'
        said = []
        t._run = lambda argv, what, **k: said.append(argv)
        t._ssh('true')
        self.assertEqual(said[0][said[0].index('--') + 1], 'acme@backup.example.cz')

    def test_guarded(self):
        self.assertIn('rbackup:targets', E.DBGUARD_META_EXACT)
        for k in ('rbackup', 'rbackup_password', 'acme_dns_tsig_secret', 'acme_ca'):
            self.assertIn(k, E.DBGUARD_SETTINGS)


class Deployments(unittest.TestCase):
    def test_service_is_a_name(self):
        self.assertEqual(TC.service_of('', 'web'), 'web')
        self.assertEqual(TC.service_of('ns/web-tls', 'x'), 'ns/web-tls')
        for bad in ('web; id>/tmp/pwn #', '-x', '$(id)', 'a b', '/etc', 'a`id`', 'a|b'):
            with self.assertRaises(TC.PluginError, msg=bad):
                TC.service_of(bad, 'x')

    def test_preset_with_a_bad_service_refused(self):
        class B(object):
            name, names, not_before, serial, alt = 'web.example.cz', ['web.example.cz'], 0, '', None
        t = TSSH.SshTarget.__new__(TSSH.SshTarget) if hasattr(TSSH, 'SshTarget') else None
        if t is None:
            cls = [c for c in vars(TSSH).values() if isinstance(c, type) and
                   hasattr(c, 'resolved') and c.__module__ == TSSH.__name__][0]
            t = cls.__new__(cls)
        t.c = lambda k: 'h'
        t.ctx = mock.MagicMock()
        with self.assertRaises(TC.PluginError):
            t.resolved(B(), {'preset': 'docker', 'service': 'web; id>/tmp/pwn #'}, partial=True)

    def test_renew_window_short_lived(self):
        t = time.time()
        row = {'renew_days': 30}
        self.assertAlmostEqual(R.renew_window(row, t + 6 * 86400, t), 2 * 86400, delta=1)
        self.assertEqual(R.renew_window(row, t + 90 * 86400, t), 30 * 86400)
        self.assertEqual(R.renew_window(row, t + 90 * 86400, None), 30 * 86400)
        fresh = {'auto_renew': 1, 'issuer': 'le', 'state': 'ok', 'cert_pem': 'x',
                 'not_before': t - 60, 'not_after': t + 6 * 86400 - 60}
        self.assertEqual(R.main_due(fresh, t), '')
        fresh['not_after'] = t + 86400
        fresh['not_before'] = t - 5 * 86400
        self.assertTrue(R.main_due(fresh, t))

    def test_stop_and_deploying_handled(self):
        import inspect
        from acmelib.certs import deployer, jobs
        src = inspect.getsource(deployer)
        self.assertIn("'stopped before it was done'", src)
        self.assertIn("state = 'deploying'", inspect.getsource(jobs.stop))
        self.assertIn("state = 'renewing'", inspect.getsource(jobs.stop))
        self.assertIn("cert_deploys SET state = 'failed'", inspect.getsource(jobs.recover))


class Checks(unittest.TestCase):
    def test_scoped_sees_only_its_own(self):
        rows = [{'id': 1, 'cert_id': 10}, {'id': 2, 'cert_id': 20}]
        h = mock.MagicMock()
        with mock.patch.object(AC.T, 'unscoped', return_value=False), \
                mock.patch.object(AC.S, 'cert_get', side_effect=lambda st, cid: {'owner': cid}), \
                mock.patch.object(AC.T, 'cert_may', side_effect=lambda st, s, row, r:
                                  row.get('owner') == 10):
            self.assertEqual([r['id'] for r in AC._seen(h, {}, rows)], [1])
        with mock.patch.object(AC.T, 'unscoped', return_value=True):
            self.assertEqual(AC._seen(h, {}, rows), rows)

    def test_crl_pem_needs_certadmin(self):
        import inspect
        from acmelib.certs import api
        self.assertIn("'crl', 'crl-pem', 'crl-der', 'bundle'", inspect.getsource(api))

    def test_crl_held_when_split(self):
        from acmelib.certs import ca
        from acmelib.certs.pki import PkiError
        with mock.patch.object(ca, '_E') as e:
            e.return_value.split_issue_refused.return_value = 'the cluster is split'
            with self.assertRaises(PkiError):
                ca.ca_crl(None, 1)


class DnsTcp(unittest.TestCase):
    def test_a_trickle_ends(self):
        a, b = socket.socketpair()
        try:
            a.sendall(b'\x00')
            t0 = time.monotonic()
            cls = [c for c in vars(DS).values() if isinstance(c, type) and hasattr(c, '_read')][0]
            try:
                got = cls._read(b, 2, time.monotonic() + 0.5)
            except OSError:                             # the timeout: the connection ends
                got = None
            self.assertIsNone(got)
            self.assertLess(time.monotonic() - t0, 3)
        finally:
            a.close()
            b.close()

    def test_per_peer_cap(self):
        self.assertLess(DS.TCP_PER_PEER, DS.TCP_MAX_CONN)


class SshGate(unittest.TestCase):
    def setUp(self):
        self.store = E.Storage(E.open_db())
        self.store.db.run("DELETE FROM meta WHERE k LIKE 'sshfail:%'")
        E.SSHOTP_FAILS.clear()

    def test_unknown_name_no_row(self):
        with mock.patch.object(E, 'sshotp_get', return_value=None):
            ok, said = E.sshotp_check(self.store, 'scanner1', '123456')
        self.assertFalse(ok)
        self.assertFalse(self.store.db.rows("SELECT k FROM meta WHERE k LIKE 'sshfail:%'"))
        self.assertTrue(E.SSHOTP_FAILS.get('scanner1'))

    def test_memory_capped(self):
        now = time.time()
        with mock.patch.object(E, 'SSHOTP_FAILS_MOST', 10):
            for i in range(50):
                E._sshotp_fail_mem('n%d' % i, now)
            self.assertLessEqual(len(E.SSHOTP_FAILS), 10)

    def test_tidied(self):
        k = E.node_key('sshfail', 'old')
        self.store.set_meta(k, json.dumps([time.time() - 10 * 86400]))
        k2 = E.node_key('sshfail', 'new')
        self.store.set_meta(k2, json.dumps([time.time()]))
        E.sshotp_fails_tidy(self.store)
        self.assertIsNone(self.store.get_meta(k))
        self.assertTrue(self.store.get_meta(k2))


class Restore(unittest.TestCase):
    def test_copy_capped(self):
        src = io.BytesIO(b'x' * (3 << 20))
        with self.assertRaises(ValueError):
            E._copy_capped(src, io.BytesIO(), 1 << 20)
        self.assertEqual(E._copy_capped(io.BytesIO(b'abc'), io.BytesIO(), 10), 3)

    def test_long_line_refused(self):
        p = os.path.join(TMP, 'bomb.json.gz')
        with gzip.open(p, 'wb') as f:
            f.write(b'{"acme": "1"}\n' + b'x' * (2 << 20))
        with gzip.open(p, 'rt') as f:
            f.readline()
            with self.assertRaises(ValueError):
                list(E._lines_capped(f, 1 << 20))
        with gzip.open(p, 'rb') as f:
            self.assertEqual(len(list(E._lines_capped(f, 4 << 20))), 2)


class Mail(unittest.TestCase):
    def test_sign_in_not_in_the_debugging(self):
        import inspect
        src = inspect.getsource(E.send_mail) if hasattr(E, 'send_mail') else ''
        body = src or open(os.path.join(ROOT, 'acmelib', 'engine',
                                        [n for n in os.listdir(os.path.join(ROOT, 'acmelib',
                                                                            'engine'))
                                         if n.startswith('150_')][0])).read()
        self.assertIn('conn.set_debuglevel(0)', body)
        self.assertIn('conn.set_debuglevel(said_dl)', body)

    def test_sms_spool_not_for_everyone(self):
        d = tempfile.mkdtemp(dir=TMP)
        with mock.patch.dict(E.CONFIG, {'sms_mode': 'spool', 'sms_spool_dir': d}):
            try:
                E.sms_send('+420603123456', 'code 123456')
            except Exception:                           # noqa: BLE001
                fn = [n for n in dir(E) if n.startswith('sms_') and 'send' in n]
                self.skipTest('no sms_send here: %s' % fn)
        names = os.listdir(d)
        self.assertEqual(len(names), 1)
        self.assertEqual(os.stat(os.path.join(d, names[0])).st_mode & 0o777, 0o660)


class Clocks(unittest.TestCase):
    def test_back_offs_are_monotonic(self):
        import inspect
        eng = os.path.join(ROOT, 'acmelib', 'engine')
        src = ''.join(open(os.path.join(eng, n)).read() for n in sorted(os.listdir(eng))
                      if n[:4] in ('035_', '080_', '085_', '195_', '197_', '265_'))
        for bad in ('time.time() < lane.down_until', 'time.time() < lane.failed_until',
                    "ONCE_PEER['down_until'] > time.time()", "time.time() - ACME_WORK['at']"):
            self.assertNotIn(bad, src)
        self.assertIn('time.monotonic() - self.last_scan', inspect.getsource(R))

    def test_siem_stamped_when_it_happened(self):
        cls = E.Siem
        obj = cls.__new__(cls)
        obj.host = lambda: 'h'
        with mock.patch.dict(E.CONFIG, {'siem_format': 'syslog'}):
            line = cls.frame(obj, 'event', 6, {}, 'x', at=946684800.0)
        self.assertIn('2000-01-01', line)


class Alerts(unittest.TestCase):
    def test_kinds_and_late_rows(self):
        import inspect
        src = inspect.getsource(E.alerts_evaluate)
        self.assertIn('kind IN (%s)', src)
        self.assertIn("event_seen", src)


class KvRows(unittest.TestCase):
    def test_underscore_not_a_wildcard(self):
        from acmelib.certs import names
        store = E.Storage(E.open_db())
        kv = names.KV_PREFIX
        store.set_meta(kv + 'target:dc-1:arn', 'keep')
        store.set_meta(kv + 'target:dc_1:arn', 'move')
        names._kv(store, 'target', 'dc_1', 'dc_2')
        self.assertEqual(store.get_meta(kv + 'target:dc-1:arn'), 'keep')
        self.assertEqual(store.get_meta(kv + 'target:dc_2:arn'), 'move')


if __name__ == '__main__':
    unittest.main()
