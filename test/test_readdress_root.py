#!/usr/bin/env python3
"""Re-addressing a node of an HA pair, the root helper's side (1.0.56): a short host name the
machine has kept, secondary IPv4 addresses kept, going back not refused for its gateway, and the
other node's pg_hba line not dropped when its address did not change.

    python3 test/test_readdress_root.py
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-readdress-')
os.environ.update(ACME_STATE=TMP, ACME_RUN=TMP, ACME_LOGDIR=TMP,
                  ACME_NET_SNAP_DIR=os.path.join(TMP, 'root-only'))
sys.path.insert(0, ROOT)

spec = importlib.util.spec_from_file_location('acme_web_rd', os.path.join(ROOT, 'deploy',
                                                                           'acme_web.py'))
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)

BASE = {'con': 'x', 'ipv4': {'addr': '192.0.2.10/24'}}


class ShortHostName(unittest.TestCase):
    def test_static_hostname(self):
        with mock.patch.object(W, 'run', return_value='Node1.\n'):
            self.assertEqual(W.net_static_hostname(), 'node1')

    def test_static_hostname_fallback(self):
        # hostnamectl says nothing, or fails: the kernel's name (fix 9)
        fake = mock.Mock(nodename='Node2.')
        for got in (mock.Mock(return_value=''), mock.Mock(side_effect=W.Refused('no'))):
            with mock.patch.object(W, 'run', got), mock.patch.object(W.os, 'uname',
                                                                    return_value=fake):
                self.assertEqual(W.net_static_hostname(), 'node2')

    def test_kept_short_name_taken(self):
        with mock.patch.object(W, 'net_static_hostname', return_value='nodea'):
            self.assertEqual(W.net_checked(dict(BASE, hostname='nodea'))['hostname'], 'nodea')
            self.assertEqual(W.net_checked(dict(BASE, hostname='NodeA.'))['hostname'], 'nodea')
            with self.assertRaises(W.Refused):
                W.net_checked(dict(BASE, hostname='nodeb'))
            self.assertEqual(W.net_checked(dict(BASE, hostname='nodeb', rollback=True))
                             ['hostname'], 'nodeb')
            self.assertEqual(W.net_checked(dict(BASE, hostname='b.example.cz'))['hostname'],
                             'b.example.cz')

    def test_unknown_name_refuses_short(self):
        with mock.patch.object(W, 'net_static_hostname', return_value=''):
            with self.assertRaises(W.Refused):
                W.net_checked(dict(BASE, hostname='nodea'))


class Secondaries(unittest.TestCase):
    def test_kept(self):
        before = {'ipv4.method': 'manual',
                  'ipv4.addresses': '192.0.2.1/24, 198.51.100.5/24, 203.0.113.7/28'}
        self.assertEqual(W.net_addrs4_after(before, '192.0.2.3/24'),
                         ['192.0.2.3/24', '198.51.100.5/24', '203.0.113.7/28'])

    def test_secondary_made_primary(self):
        before = {'ipv4.method': 'manual', 'ipv4.addresses': '192.0.2.1/24,198.51.100.5/24'}
        self.assertEqual(W.net_addrs4_after(before, '198.51.100.5/24'), ['198.51.100.5/24'])

    def test_dhcp_or_one(self):
        self.assertEqual(W.net_addrs4_after({'ipv4.method': 'auto',
                                             'ipv4.addresses': '192.0.2.1/24,10.0.0.1/8'},
                                            '192.0.2.3/24'), ['192.0.2.3/24'])
        self.assertEqual(W.net_addrs4_after({'ipv4.method': 'manual',
                                             'ipv4.addresses': '192.0.2.1/24'},
                                            '192.0.2.3/24'), ['192.0.2.3/24'])
        self.assertEqual(W.net_addrs4_after({}, '192.0.2.3/24'), ['192.0.2.3/24'])

    def test_nmcli_given_all(self):
        n = W.net_checked(dict(BASE, ipv4={'addr': '192.0.2.3/24'}, ipv6={'mode': 'keep'}))
        calls = []
        fields = {'ipv4.method': 'manual', 'ipv4.addresses': '192.0.2.1/24, 198.51.100.5/24'}

        def run(cmd, what, ok=(0,)):
            calls.append(cmd)
            return 'x\n' if cmd[-2:] == ['connection', 'show'] else ''
        with mock.patch.object(W, 'run', run), \
                mock.patch.object(W.shutil, 'which', return_value='/bin/nmcli'), \
                mock.patch.object(W, 'nm_fields', return_value=fields), \
                mock.patch.object(W, '_net_apply_rest', return_value={'said': []}):
            W.net_apply(n)
        mod = [c for c in calls if 'modify' in c][0]
        self.assertEqual(mod[mod.index('ipv4.addresses') + 1], '192.0.2.3/24,198.51.100.5/24')


class RollbackGateway(unittest.TestCase):
    def test_gateway_outside(self):
        r = dict(BASE, ipv4={'addr': '192.0.2.10/32', 'gw': '192.0.2.1'})
        with self.assertRaises(W.Refused):
            W.net_checked(r)
        self.assertEqual(W.net_checked(dict(r, rollback=True))['gw4'], '192.0.2.1')
        with self.assertRaises(W.Refused):        # still one IPv4 address
            W.net_checked(dict(r, rollback=True, ipv4={'addr': '192.0.2.10/32', 'gw': '::1'}))


class PeerSameAddress(unittest.TestCase):
    HBA = ('local all all peer\n'
           'host    acme    acme    10.99.0.1/32    scram-sha-256\n')

    def peer(self, **r):
        put = []
        with mock.patch.object(W, 'pg_sql', return_value='0'), \
                mock.patch.object(W, 'pg_path_checked', return_value=__file__), \
                mock.patch.object(W, 'pg_file_read', return_value=self.HBA), \
                mock.patch.object(W, 'pg_file_copy'), \
                mock.patch.object(W.os, 'lstat', return_value=os.stat(__file__)), \
                mock.patch.object(W, 'pg_file_put', lambda p, t, *a: put.append(t)):
            got = W.pgtls_peer(dict({'db': 'acme', 'user': 'acme', 'port': 5432}, **r))
        return got, put

    def test_drop_old_same(self):
        for extra in ({'drop_old': True}, {}, {'keep_old': True}):
            got, put = self.peer(peer='10.99.0.1', old_peer='10.99.0.1', **extra)
            self.assertEqual(put, [], extra)
            self.assertIn('already', got['said'])

    def test_drop_old_moved(self):
        hba = self.HBA + 'host    acme    acme    10.99.0.3/32    scram-sha-256\n'
        with mock.patch.object(self, 'HBA', hba):
            got, put = self.peer(peer='10.99.0.3', old_peer='10.99.0.1', drop_old=True)
        self.assertEqual(len(put), 1)
        self.assertNotIn('10.99.0.1/32', put[0])
        self.assertIn('10.99.0.3/32', put[0])


if __name__ == '__main__':
    unittest.main()
