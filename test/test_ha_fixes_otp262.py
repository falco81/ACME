#!/usr/bin/env python3
"""The HA fixes ported from otp 1.0.261/1.0.262 (re-addressing a node, 1.0.56).

    python3 test/test_ha_fixes_otp262.py

In one process, SQLite, the other node played by its rows: nginx's certificate folder from
ACME_VIP_CERT_DIR; a planned change said as warn, not bad (ha_planned_away, ha_watch_tick);
the preferred node re-addressed counts as unable; the alerts quiet while a node changes its
network; the keepalived peer from the other node's published ha_address (one shared
database); the VIP address's family; the cluster's authority made by ha_lead alone; the
preferred node not changed while apart; the link's TLS failed only waiting for the peer;
--ha-forget's rows; the directory's failover and the other node's clock; upgrade:online
looked at by one node.
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-otp262-')
CERTS = os.path.join(TMP, 'certs')
os.makedirs(CERTS)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'),
                  ACME_VIP_CERT_DIR=CERTS, ACME_HA_CA=os.path.join(TMP, 'ha-ca.pem'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DAEMON = E.Daemon(STORE, serve=False)


def beat(name, age=0, address='127.0.0.1'):
    STORE.set_meta('node:' + name, json.dumps({'at': time.time() - age, 'address': address,
                                              'version': E.__version__}))


def reset(**conf):
    E.CONFIG.update(ha_mode='replicated', ha_peer='192.0.2.2', ha_slot=1, node_name='acme1',
                    ha_address='', split_mode='off', split_prefer='')
    E.CONFIG.update(conf)
    E.MAINT_CACHE['at'] = 0
    E.SPLIT.update(peer_err='', apart_since=0.0, role='serve', why='')
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'node:%' OR k LIKE 'net:%' OR k LIKE 'power:%' "
                 "OR k LIKE 'maint:%' OR k LIKE 'upgrade:%' OR k LIKE 'alerts:quiet%' OR "
                 "k LIKE 'split:%' OR k LIKE 'clock:%'")
    STORE.db.run("DELETE FROM events")
    beat('acme1')
    beat('acme2')


def net_job(name, state='running', age=5):
    STORE.set_meta('net:job:' + name, json.dumps({'state': state, 'at': time.time() - age,
                                                  'moved': time.time() - age}))


class Patched:
    """E.name = value for the block, put back after."""
    def __init__(self, **kw):
        self.kw, self.was = kw, {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.was[k] = getattr(E, k)
            setattr(E, k, v)

    def __exit__(self, *a):
        for k, v in self.was.items():
            setattr(E, k, v)


def events():
    return STORE.db.rows("SELECT level, words FROM events WHERE kind = 'ha' ORDER BY ts")


# ---------------------------------------------------------------------------
class NginxCertDir(unittest.TestCase):
    """Problem 4 / fix 10: the folder root writes into, read by web_drift and web_state."""

    def test_files_from_the_env(self):
        self.assertEqual(E.NGINX_CERT_FILES['node'], os.path.join(CERTS, 'acme.pem'))
        self.assertEqual(E.NGINX_CERT_FILES['vip'], os.path.join(CERTS, 'acme-vip.pem'))

    def test_drift_and_state_read_them(self):
        key, crt = E.make_selfsigned('node.example.test', [], 30, 'ec')
        with open(E.NGINX_CERT_FILES['node'], 'w') as f:
            f.write(crt)
        self.assertEqual(E.web_drift({'tls': {'node': {'cert': crt}}}), '')
        key2, crt2 = E.make_selfsigned('other.example.test', [], 30, 'ec')
        self.assertIn('holds another certificate', E.web_drift({'tls': {'node': {'cert': crt2}}}))
        asked = []
        with Patched(cert_now=lambda p: asked.append(p) or None):
            E.web_state(STORE)
        self.assertEqual(asked[:2], [E.NGINX_CERT_FILES['node'], E.NGINX_CERT_FILES['vip']])


class PlannedAway(unittest.TestCase):
    """Problem 2: a re-addressing or a restart asked for - warn, 'expected while ...'."""

    def setUp(self):
        reset()
        E.HA_SEEN.clear()

    def test_planned(self):
        self.assertEqual(E.ha_planned_away(STORE), {})
        net_job('acme2')
        self.assertEqual(E.ha_planned_away(STORE), {'acme2': 'acme2 is changing its network'})
        net_job('acme2', state='done')
        self.assertEqual(E.ha_planned_away(STORE), {})
        net_job('acme2', age=E.NET_JOB_LIVE_S + 10)         # stalled: no longer
        self.assertEqual(E.ha_planned_away(STORE), {})
        net_job('acme1')                                      # this node's own: not "other"
        self.assertEqual(E.ha_planned_away(STORE), {})
        STORE.set_meta('power:plan', json.dumps({'id': 'p1', 'at': time.time()}))
        STORE.set_meta('power:node:acme2', json.dumps({'id': 'p1', 'state': 'going',
                                                       'moved': time.time()}))
        self.assertEqual(E.ha_planned_away(STORE), {'acme2': 'acme2 is restarting'})

    def test_watch_says_warn(self):
        E.CONFIG['ha_mode'] = 'replicated'
        rs = {'incoming': [{'name': 'acme_from_2', 'running': True, 'enabled': True}],
              'outgoing': []}
        with Patched(ha_repl_state=lambda store: rs, vip_conf=lambda store: {'on': False}):
            E.ha_watch_tick(STORE)                          # the first look: nothing said
            net_job('acme2')
            beat('acme2', age=600)
            rs['incoming'][0]['running'] = False
            E.ha_watch_tick(STORE)
            got = events()
            self.assertEqual([r['level'] for r in got], ['warn', 'warn'], got)
            self.assertIn('expected: acme2 is changing its network', got[0]['words'])
            self.assertIn('expected while acme2 is changing its network', got[1]['words'])
            # Nothing planned: bad, as before.
            STORE.db.run("DELETE FROM events")
            STORE.db.run("DELETE FROM meta WHERE k = 'net:job:acme2'")
            beat('acme2')
            rs['incoming'][0]['running'] = True
            E.ha_watch_tick(STORE)
            STORE.db.run("DELETE FROM events")
            beat('acme2', age=600)
            rs['incoming'][0]['running'] = False
            E.ha_watch_tick(STORE)
            self.assertEqual([r['level'] for r in events()], ['bad', 'bad'])

    def test_maintenance_asked_is_warn(self):
        vip = {'on': True, 'address': '192.0.2.50/24'}
        was = dict(E.VIP_HEALTH)
        try:
            with Patched(vip_conf=lambda store: vip, vip_here=lambda a: False):
                E.VIP_HEALTH.update(ok=True, why='')
                E.ha_watch_tick(STORE)
                E.VIP_HEALTH.update(ok=False, why='in maintenance')
                E.ha_watch_tick(STORE)
                E.VIP_HEALTH.update(ok=True, why='')
                E.ha_watch_tick(STORE)
                E.VIP_HEALTH.update(ok=False, why='its pages do not answer')
                E.ha_watch_tick(STORE)
        finally:
            E.VIP_HEALTH.clear()
            E.VIP_HEALTH.update(was)
        got = [(r['level'], r['words']) for r in events() if 'healthy' in r['words']]
        self.assertEqual([x[0] for x in got], ['warn', 'info', 'bad'], got)


class SplitPreferredReaddressed(unittest.TestCase):
    """Fix 1: the preferred node being re-addressed is known not to serve."""

    def test_unable(self):
        reset(split_mode='priority', ha_slot=2, split_prefer='acme2')
        self.assertEqual(E.split_preferred_unable(STORE, time.time()), '')
        net_job('acme2', state='rebooting')
        self.assertIn('changing its network', E.split_preferred_unable(STORE, time.time()))
        net_job('acme2', state='done')
        STORE.set_meta('power:plan', json.dumps({'id': 'p1', 'at': time.time()}))
        STORE.set_meta('power:node:acme2', json.dumps({'id': 'p1', 'state': 'going',
                                                       'moved': time.time()}))
        self.assertIn('restarting', E.split_preferred_unable(STORE, time.time()))
        reset()


class SplitPreferWhileApart(unittest.TestCase):
    """H/O: split_prefer changed while apart is refused; the same one sent again is not."""

    def call(self, body):
        h = E.CliApiHandler(DAEMON, 'tester', body, {}, '/api/split')
        try:
            E.ROUTES[('POST', '/api/split')](h)
            return 200
        except E.ApiError as e:
            return e.status

    def test_refused_apart(self):
        reset(split_mode='priority', split_prefer='acme1')
        try:
            E.SPLIT['apart_since'] = time.time() - 60
            self.assertTrue(E.split_apart())
            self.assertEqual(self.call({'action': 'save', 'conf': {
                'split_mode': 'priority', 'split_prefer': 'acme2'}}), 409)
            self.assertEqual(self.call({'action': 'save', 'conf': {
                'split_mode': 'priority', 'split_prefer': 'acme1'}}), 200)
            E.SPLIT['apart_since'] = 0.0
            self.assertEqual(self.call({'action': 'save', 'conf': {
                'split_mode': 'priority', 'split_prefer': 'acme2'}}), 200)
        finally:
            for k in ('split_mode', 'split_prefer'):
                STORE.drop_setting(k)
            E.load_config()
            reset()


class AlertsQuiet(unittest.TestCase):
    """Fix 8: a net job of any node quiets the alerts."""

    def test_net_job(self):
        reset()
        self.assertEqual(E.alerts_quiet(STORE, ['acme1', 'acme2']), '')
        net_job('acme1')
        self.assertIn('acme1 changing its network', E.alerts_quiet(STORE, ['acme1', 'acme2']))
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'alerts:quiet%' OR k LIKE 'net:%'")
        STORE.set_meta('power:plan', json.dumps({'id': 'p1', 'at': time.time() - 7200}))
        STORE.set_meta('power:node:acme2', json.dumps({'id': 'p1', 'state': 'going',
                                                       'moved': time.time()}))
        self.assertIn('acme2 is restarting', E.alerts_quiet(STORE, ['acme1', 'acme2']))
        reset()


class VipPeer(unittest.TestCase):
    """C/M: one shared database - the other node's published ha_address; F: the family."""
    VIP = {'on': True, 'address': '192.0.2.50/24', 'fqdn': ''}

    def desired(self):
        with Patched(vip_conf=lambda store: self.VIP, vip_auth=lambda: 'secret12'):
            return E.web_desired(STORE)['vip']

    def publish(self, name, ha_address, age=0, live4=()):
        STORE.set_meta('net:now:' + name, json.dumps({
            'at': time.time() - age, 'ha_address': ha_address,
            'data': {'live': {'addrs4': [{'addr': a, 'dev': 'eth0'} for a in live4],
                              'addrs6': []}}}))

    def tearDown(self):
        try:
            os.unlink(str(E.VIP_LAST_FILE))
        except OSError:
            pass
        reset(ha_mode='')

    def test_shared_published(self):
        reset(ha_mode='shared', ha_peer='192.0.2.2', ha_address='192.0.2.1')
        self.assertEqual(self.desired()['peer'], '192.0.2.2')
        self.publish('acme2', '192.0.2.4')
        self.assertEqual(self.desired()['peer'], '192.0.2.4')
        self.publish('acme2', '192.0.2.4', age=E.VIP_PUBLISHED_S + 60)     # old: ha_peer
        self.assertEqual(self.desired()['peer'], '192.0.2.2')
        self.publish('acme2', 'fd00::4')                                    # another family
        self.assertEqual(self.desired()['peer'], '192.0.2.2')
        self.publish('acme2', '')                                           # none published
        self.assertEqual(self.desired()['peer'], '192.0.2.2')

    def test_replicated_unchanged(self):
        reset(ha_mode='replicated', ha_peer='192.0.2.2', ha_address='192.0.2.1')
        self.publish('acme2', '192.0.2.4')
        self.assertEqual(self.desired()['peer'], '192.0.2.2')

    def test_family(self):
        reset(ha_mode='replicated', ha_peer='fd00::2', ha_address='fd00::1')
        self.publish('acme2', 'fd00::2', live4=['10.9.9.9/8', '192.0.2.12/24'])
        with Patched(local_addresses=lambda: {'127.0.0.1', 'fd00::1', '10.0.0.5', '192.0.2.11',
                                              '192.0.2.50'}):
            v = self.desired()
        self.assertTrue(v['on'])
        self.assertEqual((v['own'], v['peer']), ('192.0.2.11', '192.0.2.12'))
        # Nothing of the family on the other side: the VIP waits, never a mismatched pair -
        # and a pair of the other family remembered is not taken.
        os.unlink(str(E.VIP_LAST_FILE))
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'net:%'")
        with open(str(E.VIP_LAST_FILE), 'w') as f:
            json.dump({'address': '192.0.2.50/24', 'own': 'fd00::1', 'peer': 'fd00::2'}, f)
        with Patched(local_addresses=lambda: {'192.0.2.11'}):
            self.assertEqual(self.desired(), {'on': False})


class ClusterAuthority(unittest.TestCase):
    """G: in a replicated pair only ha_lead makes (or rolls) the authority."""

    def test_only_lead(self):
        reset(ha_mode='replicated')
        made, cas = [], {'cas': []}
        stubs = dict(hatls_ca_make=lambda store, by: made.append(by) or cas.update(cas=[{'end': 0}]),
                     hatls_ca=lambda store: cas, hatls_issue=lambda store, n: ('k', 'c'),
                     hatls_trust=lambda ca: '', hatls_names=lambda *a: ['x'],
                     _dbtls_helper=lambda *a, **k: {'ok': True, 'cert_end': 1})
        with Patched(ha_lead=lambda store: True, **stubs):
            E._dbtls_server_cert(STORE, 't')
        self.assertEqual(made, ['t'])
        made.clear()
        cas['cas'] = [{'cert': 'c', 'end': time.time() + 86400}]          # a roll due
        with Patched(ha_lead=lambda store: False, **stubs):
            E._dbtls_server_cert(STORE, 't')
        self.assertEqual(made, [])
        seen = []

        def comes_over(store):
            seen.append(1)
            return {'cas': [{'cert': 'c', 'end': 0}]} if len(seen) > 2 else {'cas': []}
        with Patched(ha_lead=lambda store: False, **dict(stubs, hatls_ca=comes_over)):
            E._dbtls_server_cert(STORE, 't')
        self.assertEqual(made, [])
        self.assertGreater(len(seen), 2)


class LinkWaitsAgain(unittest.TestCase):
    """I: 'failed' at step 'link', nothing wrong here: back to the link."""

    def test_back_to_link(self):
        reset(ha_tls='', ha_tls_ca='')
        now = time.time()
        put = []
        st = {'for': 1, 'step': 'failed', 'failed_step': 'link', 'at': now - 60,
              'link_since': now - 1000, 'error': 'x'}
        with open(str(E.HA_CA_FILE), 'w') as f:
            f.write('CA\n')
        with Patched(hatls_want=lambda store: {'at': 1}, hatls_peer_name=lambda store: 'acme2',
                     hatls_state=lambda store, name=None: dict(st) if name is None else
                     {'step': 'server', 'at': now - 600},
                     hatls_ca=lambda store: {'cas': [{'cert': 'CA', 'end': now + 1e8}]},
                     hatls_trust=lambda ca: 'CA', hatls_needs=lambda store: [],
                     hatls_own_cert=lambda store: (now + 1e8, ()),
                     hatls_put=lambda store, s: put.append(dict(s))):
            E.hatls_check(STORE)
        self.assertEqual(len(put), 1)
        self.assertEqual(put[0]['step'], 'link')
        self.assertGreaterEqual(put[0]['link_since'], now)


class Forget(unittest.TestCase):
    """J: maint:/upgrade:node: rows go only with a node that no longer answers."""

    def test_rows(self):
        reset()
        for k in ('maint:acme2', 'upgrade:node:acme2'):
            STORE.set_meta(k, json.dumps({'on': True}))
        E.ha_forget(STORE, 'acme2')
        self.assertIsNotNone(STORE.get_meta('maint:acme2'))
        self.assertIsNotNone(STORE.get_meta('upgrade:node:acme2'))
        beat('acme2', age=3600)
        E.ha_forget(STORE, 'acme2')
        self.assertIsNone(STORE.get_meta('maint:acme2'))
        self.assertIsNone(STORE.get_meta('upgrade:node:acme2'))
        reset()


class ClockDirectory(unittest.TestCase):
    """K: stepped aside for the directory only toward a peer whose clock is good."""

    def test_peer_clock(self):
        peer = {'fresh': True, 'role': 'serve', 'dir_ok': True, 'ref': 0.5}
        dec = lambda p: E.clock_decide('guard', 0.1, 20, False, False, True, p)[0]  # noqa: E731
        self.assertEqual(dec(peer), 'aside')
        self.assertEqual(dec(dict(peer, ref=-45.0)), 'serve')
        self.assertEqual(dec(dict(peer, ref=None)), 'aside')              # not measured


class OnlineLook(unittest.TestCase):
    """L: in a replicated pair one node looks."""

    def test_lead_only(self):
        reset(upgrade_check=1)
        looked = []

        class D:
            store = STORE
        try:
            with Patched(online_url=lambda: 'https://example.test/', ha_lead=lambda s: False,
                         online_look=lambda store, by='': looked.append(1)):
                E.ONLINE_WORK.update(at=0.0, busy=False)
                E.online_tick(D())
                time.sleep(0.2)
                self.assertEqual(looked, [])
            with Patched(online_url=lambda: 'https://example.test/', ha_lead=lambda s: True,
                         online_look=lambda store, by='': looked.append(1)):
                E.ONLINE_WORK.update(at=0.0, busy=False)
                E.online_tick(D())
                time.sleep(0.3)
                self.assertEqual(looked, [1])
        finally:
            E.CONFIG['upgrade_check'] = 0


if __name__ == '__main__':
    unittest.main()
