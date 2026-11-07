#!/usr/bin/env python3
"""A node of an HA pair re-addressed - the daemon's network check and job (1.0.56, otp
1.0.261/262's READDRESS report).

    python3 test/test_readdress_net.py      (or python3 -m unittest test.test_readdress_net)

In one process, SQLite; the root helper, the other node and keepalived played by the test:
the old IPv6 address of the node's own certificate swapped (by a key, as openssl prints it);
net_check carrying old_ip6, going back never refused for its gateway, an IPv6 change taking
away the replication address refused; net_others_held (heard but out of service, on trial;
a dead node never holds); the job: maintenance before the other node is told, told only when
replication is on the address changed, snmp_bind moved for an old IPv6 address and saved
only once root took the network, the settings put back when the job stops half way (root
refused, the service restarted, no restart in an hour); going back after a trial waiting
while nobody else serves.
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-readdress-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

ENG = sys.modules['acmelib.engine'].__dict__
STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DAEMON = E.Daemon(STORE, serve=False)
ME = E.node_name()


def now_row(ip4='10.99.0.1/24', ip6=None, host='acme1.example.cz', ha_address=''):
    conf = {'ipv4_method': 'manual', 'ipv4_addresses': [ip4], 'ipv4_gateway': '10.99.0.254',
            'ipv4_dns': ['10.99.0.254']}
    if ip6:
        conf.update(ipv6_method='manual', ipv6_addresses=[ip6], ipv6_gateway='fd99::fe')
    else:
        conf['ipv6_method'] = 'disabled'
    return {'at': time.time(), 'boot': 1.0, 'ha_address': ha_address,
            'data': {'nm': True, 'con': 'eth', 'devices': [{'con': 'eth', 'dev': 'eth0'}],
                     'hostname': host, 'conf': conf}}


def want(ip4='10.99.0.3/24', gw='10.99.0.254', ip6=None, host='acme1.example.cz'):
    w = {'con': 'eth', 'ipv4': {'addr': ip4, 'gw': gw, 'dns': ['10.99.0.254']},
         'hostname': host, 'ipv6': {'on': False}}
    if ip6:
        w['ipv6'] = {'on': True, 'mode': 'manual', 'addr': ip6, 'gw': 'fd99::fe'}
    return w


class Base(unittest.TestCase):
    KEYS = ('ha_mode', 'ha_address', 'ha_peer', 'snmp_bind', 'db_host', 'mail_helo')

    def setUp(self):
        with open(os.path.join(TMP, 'config.json')) as f:
            self.file_text = f.read()
        self.cfg = {k: E.CONFIG.get(k) for k in self.KEYS}
        self.fcfg = {k: E.FILE_CONFIG.get(k) for k in self.KEYS if k in E.FILE_CONFIG}
        self.patched = {}
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'net:%' OR k LIKE 'node:%' OR "
                     "k LIKE 'maint:%' OR k LIKE 'web:tls:%'")
        STORE.set_meta('net:now:' + ME, json.dumps(now_row()))

    def tearDown(self):
        with open(os.path.join(TMP, 'config.json'), 'w') as f:
            f.write(self.file_text)
        for k, v in self.patched.items():
            ENG[k] = v
        E.CONFIG.update(self.cfg)
        for k in self.KEYS:
            if k in self.fcfg:
                E.FILE_CONFIG[k] = self.fcfg[k]
            else:
                E.FILE_CONFIG.pop(k, None)
        E.net_before_drop()

    def file(self, **kv):
        E.write_file_settings(kv)
        E.CONFIG.update(kv)
        E.FILE_CONFIG.update(kv)

    def patch(self, name, fn):
        self.patched.setdefault(name, ENG[name])
        ENG[name] = fn

    def other(self, alive=True, maint=False, aside=False):
        STORE.set_meta('node:acme2', json.dumps({'at': time.time() - (0 if alive else 3600),
                                                 'maintenance': aside}))
        if maint:
            STORE.set_meta('maint:acme2', json.dumps({'on': True, 'why': 'by hand'}))


class CertNames(Base):
    def test_key(self):
        self.assertEqual(E._cert_name_key('FD99:0:0:0:0:0:0:1'), 'fd99::1')
        self.assertEqual(E._cert_name_key('[fd99::1]'), 'fd99::1')
        self.assertEqual(E._cert_name_key('Acme1.Example.CZ'), 'acme1.example.cz')
        self.assertEqual(E._cert_names_swap(['FD99:0:0:0:0:0:0:1', 'a', '10.0.0.1'],
                                            {'fd99::1': 'fd99::3', '10.0.0.1': ''}),
                         ['fd99::3', 'a'])

    def test_cert_again_swaps_old_ipv6(self):
        key, crt = E.make_selfsigned('acme1.example.cz', ['10.99.0.1', 'fd99::1'], 30, 'ec')
        got = E.cert_bundle(crt, key)
        E.tls_save(STORE, ME, {'cert': got['cert'], 'info': got['info']}, 'test')
        STORE.set_meta('net:now:' + ME, json.dumps(now_row(ip6='fd99::1/64')))
        w = E.net_check(STORE, ME, want(ip6='fd99::3/64'))
        self.assertEqual(w['old_ip6'], ['fd99::1'])
        said = E.net_cert_again(STORE, w, 'test')
        self.assertIn('made again', said)
        names = [E._cert_name_key(n) for n in E.cert_info(E.tls_profile(STORE, ME)['cert'])['san']]
        self.assertIn('10.99.0.3', names)
        self.assertIn('fd99::3', names)
        self.assertNotIn('fd99::1', names)
        self.assertNotIn('10.99.0.1', names)


class Check(Base):
    def test_rollback_gateway(self):
        bad = want(ip4='10.99.0.3/24', gw='192.0.2.1')
        with self.assertRaises(ValueError):
            E.net_check(STORE, ME, bad)
        self.assertEqual(E.net_check(STORE, ME, bad, rollback=True)['ipv4']['gw'], '192.0.2.1')
        junk = want(ip4='10.99.0.3/24', gw='nonsense')
        with self.assertRaises(ValueError):
            E.net_check(STORE, ME, junk)
        self.assertEqual(E.net_check(STORE, ME, junk, rollback=True)['ipv4']['gw'], '')
        w6 = want(ip6='fd99::3/64')
        w6['ipv6']['gw'] = '10.0.0.1'
        with self.assertRaises(ValueError):
            E.net_check(STORE, ME, w6)
        self.assertEqual(E.net_check(STORE, ME, w6, rollback=True)['ipv6']['gw'], '')

    def test_replication_ipv6_kept(self):
        STORE.set_meta('net:now:' + ME, json.dumps(now_row(ip6='fd99::1/64')))
        E.CONFIG.update(ha_mode='replicated', ha_address='fd99:0::1', ha_peer='fd99::2')
        with self.assertRaises(ValueError) as e:
            E.net_check(STORE, ME, want(ip6='fd99::3/64'))
        self.assertIn('replicate over', str(e.exception))
        with self.assertRaises(ValueError):
            E.net_check(STORE, ME, want())                  # IPv6 off
        E.net_check(STORE, ME, want(ip6='fd99::1/64'))      # kept: fine
        E.net_check(STORE, ME, want(ip6='fd99::3/64'), rollback=True)
        E.CONFIG.update(ha_address='10.99.0.1')
        E.net_check(STORE, ME, want(ip6='fd99::3/64'))

    def test_plan_tells_only_on_old(self):
        E.CONFIG.update(ha_mode='replicated', ha_address='', ha_peer='10.99.0.2')
        self.assertTrue(any('told' in p for p in E.net_check(STORE, ME, want())['plan']))
        E.CONFIG.update(ha_address='10.98.0.1')
        self.assertFalse(any('told' in p for p in E.net_check(STORE, ME, want())['plan']))
        self.assertTrue(E.net_ha_on_old('10.99.0.1', '10.99.0.1'))
        self.assertFalse(E.net_ha_on_old('10.99.0.1', '10.99.0.12'))


class Held(Base):
    def test_held(self):
        E.CONFIG.update(ha_mode='replicated', ha_address='', ha_peer='10.99.0.2')
        self.assertEqual(E.net_others_held(STORE, ME), [])
        self.other(alive=True)
        self.assertEqual(E.net_others_held(STORE, ME), [])
        self.other(alive=True, aside=True)
        self.assertEqual(len(E.net_others_held(STORE, ME)), 1)
        self.other(alive=True, maint=True)
        self.assertEqual(len(E.net_others_held(STORE, ME)), 1)
        with self.assertRaises(ValueError) as e:
            E.net_ask(STORE, ME, want(), 'test')
        self.assertIn('out of service', str(e.exception))
        E.net_ask(STORE, ME, want(), 'test', rollback=True)          # never refused
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'net:want:%'")
        self.other(alive=False, maint=True)                          # dead: never holds
        self.assertEqual(E.net_others_held(STORE, ME), [])
        STORE.db.run("DELETE FROM meta WHERE k = 'maint:acme2'")
        self.other(alive=True)
        STORE.set_meta('net:job:acme2', json.dumps({'state': 'trial', 'moved': time.time(),
                                                    'trial_until': time.time() + 60}))
        self.assertIn('on trial', E.net_others_held(STORE, ME)[0])
        E.CONFIG.update(ha_mode='')
        self.assertEqual(E.net_others_held(STORE, ME), [])


class Job(Base):
    def run_job(self, w, root):
        order = []
        self.patch('net_root', root)
        self.patch('maintenance_set', lambda s, on, why, by: order.append(('maint', on)))
        self.patch('maintenance_row', lambda s, name=None: {'on': False})
        self.patch('ha_readdress', lambda s, **kw: (order.append(('tell', kw.get('mine'))),
                                                    {'message': 'ok', 'left': [], 'done': []})[1])
        self.patch('vip_conf', lambda s: {'on': False})
        ask = {'id': 'j' + str(time.time()), 'want': w, 'by': 'test'}
        STORE.set_meta('readdress:ask', json.dumps({'from': ME, 'done': time.time() + 5,
                                                    'at': time.time() + 5}))
        E.net_job_run(DAEMON, ask)
        return order, E._meta_obj(STORE, 'net:job:' + ME)

    def refused(self, data, wait=60):
        raise ValueError('the root helper said no')

    def test_order_and_put_back(self):
        self.file(ha_mode='replicated', ha_address='10.99.0.1', ha_peer='10.99.0.2',
                  db_host='10.99.0.1')
        E.CONFIG.update(snmp_bind='10.99.0.1')
        w = E.net_check(STORE, ME, want())
        order, job = self.run_job(w, self.refused)
        self.assertEqual(job['state'], 'failed')
        self.assertEqual(order[0], ('maint', True))                 # before the other is told
        self.assertEqual(order[1], ('tell', '10.99.0.3'))
        self.assertEqual(order[2], ('tell', '10.99.0.1'))           # told back
        self.assertEqual(str(E.CONFIG.get('snmp_bind')), '10.99.0.1')   # never saved
        self.assertEqual(E._net_file_now()['db_host'], '10.99.0.1')   # put back
        self.assertFalse(os.path.exists(os.path.join(TMP, E.NET_BEFORE_FILE)))

    def test_secondary_not_told_and_bind_after_root(self):
        self.file(ha_mode='replicated', ha_address='10.98.0.1', ha_peer='10.98.0.2')
        E.CONFIG.update(snmp_bind='fd99:0::1')
        STORE.set_meta('net:now:' + ME, json.dumps(now_row(ip6='fd99::1/64')))
        w = E.net_check(STORE, ME, want(ip6='fd99::3/64'))
        seen = {}

        def root(data, wait=60):
            seen['bind'] = E.CONFIG.get('snmp_bind')
            return {'said': ['set'], 'before': {}}
        order, job = self.run_job(w, root)
        self.assertNotIn('tell', [o[0] for o in order])
        self.assertEqual(seen['bind'], 'fd99:0::1')                 # not before root took it
        self.assertEqual(E.CONFIG.get('snmp_bind'), 'fd99::3')
        self.assertEqual(job['state'], 'rebooting')
        self.assertEqual(E._net_file_now()['ha_address'], '10.98.0.1')

    def test_stalled_put_back(self):
        E.CONFIG.update(ha_mode='', mail_helo='acme1.example.cz')
        job = {'id': 'st1', 'want': {}, 'state': 'running', 'steps': []}
        E.net_before_keep(STORE, job)
        DAEMON.save_settings({'mail_helo': 'other.example.cz'}, by='t', node=ME)
        E.net_job_stalled(DAEMON, job, 'test')
        self.assertEqual(E.CONFIG.get('mail_helo'), 'acme1.example.cz')
        st = os.stat(os.path.join(TMP, E.NET_BEFORE_FILE)) if os.path.exists(
            os.path.join(TMP, E.NET_BEFORE_FILE)) else None
        self.assertIsNone(st)

    def test_before_file_private(self):
        E.net_before_keep(STORE, {'id': 'x'})
        self.assertEqual(os.stat(os.path.join(TMP, E.NET_BEFORE_FILE)).st_mode & 0o777, 0o600)


class BackWait(Base):
    def test_waits(self):
        E.CONFIG.update(ha_mode='replicated')
        job = {'id': 't1', 'state': 'trial', 'trial_until': time.time() - 5, 'trial_min': 2,
               'steps': []}
        self.other(alive=True, maint=True)
        self.assertTrue(E.net_back_wait(STORE, job))
        self.assertIn('waits', E._meta_obj(STORE, 'net:job:' + ME)['steps'][-1]['what'])
        STORE.set_meta('net:keep:' + ME, json.dumps({'id': 't1', 'by': 'x'}))
        self.assertFalse(E.net_back_wait(STORE, job))             # Keep never held
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'net:keep:%'")
        STORE.db.run("DELETE FROM meta WHERE k = 'maint:acme2'")
        self.assertFalse(E.net_back_wait(STORE, job))             # the other serves
        self.other(alive=False)
        self.assertTrue(E.net_back_wait(STORE, job))              # nobody answers
        job['trial_until'] = time.time() - E.NET_BACK_WAIT_S - 5
        self.assertFalse(E.net_back_wait(STORE, job))             # not for ever
        job['trial_until'] = time.time() + 60
        self.assertFalse(E.net_back_wait(STORE, job))             # not out of time
        E.CONFIG.update(ha_mode='')
        job['trial_until'] = time.time() - 5
        self.assertFalse(E.net_back_wait(STORE, job))


if __name__ == '__main__':
    unittest.main()
