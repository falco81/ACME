#!/usr/bin/env python3
"""Bug hunt 1.0.143, run w5, the machine acme runs on (network, time, power) - each checked:

- the time servers: an IPv6 address with a scope id (fe80::1%eth0) as a server, or a network
  with one (fe80::%eth0/64) among those allowed to ask, was saved by the daemon - the root
  helper refuses it, so every node failed to set its time servers, again every ten minutes;
- a node's network: a search domain root refuses (corp_ad.local, a..b) or an IPv6 address,
  gateway or DNS server with a scope id passed the daemon's check - the change was planned,
  the other node told, the node's certificate made again, and root refused it half way;
  going back leaves such a search domain out instead (never refused);
- the page's Power off had no command line and no place in the console: now
  acme --power-off-nodes NODE,NODE|all (asked first, --yes) and the console's
  *Switch a machine off* (The pages' certificates, updates, restarts, tests).

Nothing of this machine is touched: the root helper is only asked to check, and the power-off
is only asked for in a state of the test's own (no daemon runs it).

    python3 test/test_hunt_rw5_host.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-rw5host-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'),
           NO_COLOR='1', ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'),
           ACME_VIP_NO_SERVICES='1')
os.environ.update({k: v for k, v in ENV.items() if k.startswith('ACME_')})
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'deploy'))

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
import acme_web as W  # noqa: E402

ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.load_config()
ME = E.node_name()
assert ME == 'acme1', ME


def run(*args):
    return subprocess.run(ACME + [str(a) for a in args], env=ENV, capture_output=True,
                          text=True, timeout=240, stdin=subprocess.DEVNULL)


# ---------------------------------------------------------------------------------------------
class A_Time(unittest.TestCase):
    def root_takes(self, c):
        W.ntp_checked(dict(c, peers=[]))

    def test_scoped_server_refused_here_as_root_refuses_it(self):
        b = {'manage': True, 'servers': [{'host': 'fe80::1%eth0'}]}
        with self.assertRaises(W.Refused):
            W.ntp_checked(b)
        with self.assertRaises(ValueError):
            E.ntp_checked(b)
        with self.assertRaises(ValueError):
            E.ntp_checked({'manage': True, 'servers': [{'host': 'ntp.example.cz'}],
                           'allow': 'fe80::%eth0/64'})

    def test_plain_ones_still_taken_and_root_takes_them(self):
        c = E.ntp_checked({'manage': True, 'servers': [{'host': '2001:db8::123'},
                                                       {'host': '192.0.2.1'},
                                                       {'host': 'NTP.Example.cz.'}],
                           'allow': '10.1.2.3/8, 2001:db8::/32'})
        self.assertEqual([x['host'] for x in c['servers']],
                         ['2001:db8::123', '192.0.2.1', 'ntp.example.cz'])
        self.assertEqual(c['allow'], ['10.0.0.0/8', '2001:db8::/32'])
        self.root_takes(c)


# ---------------------------------------------------------------------------------------------
def now_row():
    return {'at': time.time(), 'boot': 1.0,
            'data': {'nm': True, 'con': 'eth', 'devices': [{'con': 'eth', 'dev': 'eth0'}],
                     'hostname': 'acme1.example.cz',
                     'conf': {'ipv4_method': 'manual', 'ipv4_addresses': ['10.99.0.1/24'],
                              'ipv4_gateway': '10.99.0.254', 'ipv4_dns': ['10.99.0.254'],
                              'ipv6_method': 'disabled'}}}


def want(search=None, v6=None):
    w = {'con': 'eth', 'ipv4': {'addr': '10.99.0.3/24', 'gw': '10.99.0.254',
                                'dns': ['10.99.0.254'], 'search': search or []},
         'hostname': 'acme1.example.cz', 'ipv6': {'on': False}}
    if v6:
        w['ipv6'] = dict({'on': True, 'mode': 'manual', 'addr': 'fd99::3/64', 'gw': 'fd99::fe',
                          'dns': []}, **v6)
    return w


def root_request(w):
    """What the job asks of root (295), from what net_check made of it."""
    return {'do': 'apply', 'con': w['con'], 'ipv4': w['ipv4'],
            'ipv6': {'mode': w['ipv6']['mode'] if w['ipv6']['on'] else 'off',
                     'addr': w['ipv6']['addr'], 'gw': w['ipv6']['gw'], 'dns': w['ipv6']['dns']},
            'hostname': w['hostname'], 'old': [w['old_ip']], 'old_hostname': w['old_hostname'],
            'reboot_in': 8}


class B_Network(unittest.TestCase):
    def setUp(self):
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'net:%'")
        STORE.set_meta('net:now:' + ME, json.dumps(now_row()))

    def test_search_domain_root_refuses_is_refused_up_front(self):
        for bad in ('corp_ad.local', 'a..b.cz', '-x.example.cz'):
            with self.assertRaises(W.Refused):
                W.net_checked(root_request(E.net_check(STORE, ME, want(['example.cz']))) |
                              {'ipv4': dict(want()['ipv4'], search=[bad])})
            with self.assertRaises(ValueError) as e:
                E.net_check(STORE, ME, want(['example.cz', bad]))
            self.assertIn('search domain', str(e.exception))
            # going back is never refused: the bad one left out
            got = E.net_check(STORE, ME, want(['example.cz', bad]), rollback=True)
            self.assertEqual(got['ipv4']['search'], ['example.cz'])
        got = E.net_check(STORE, ME, want(['Example.cz', 'corp.example.cz']))
        W.net_checked(root_request(got))            # root takes what the daemon passed

    def test_scoped_ipv6_refused_up_front(self):
        for v6 in ({'addr': 'fd99::3%eth0/64'}, {'gw': 'fe80::1%eth0'},
                   {'dns': ['fe80::53%eth0']}):
            with self.assertRaises(ValueError, msg=v6):
                E.net_check(STORE, ME, want(v6=v6))
        got = E.net_check(STORE, ME, want(v6={'gw': 'fe80::1', 'dns': ['fd99::53']}))
        W.net_checked(root_request(got))
        # going back: a scoped DNS server left out, not refused
        got = E.net_check(STORE, ME, want(v6={'dns': ['fe80::53%eth0', 'fd99::53']}),
                          rollback=True)
        self.assertEqual(got['ipv6']['dns'], ['fd99::53'])


# ---------------------------------------------------------------------------------------------
class C_PowerOff(unittest.TestCase):
    def setUp(self):
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'power:%'")

    def plan(self):
        got = run('--restarts', '--json')
        self.assertEqual(got.returncode, 0, got.stderr)
        return json.loads(got.stdout).get('plan') or {}

    def test_cli(self):
        got = run('--help')
        self.assertIn('--power-off-nodes', got.stdout)
        got = run('--power-off-nodes', 'nope', '--yes')
        self.assertEqual(got.returncode, 1)
        self.assertIn('there is no node nope', got.stderr)
        got = run('--power-off-nodes', ME)          # no terminal, no --yes: nothing asked
        self.assertEqual(got.returncode, 1)
        self.assertIn('switched off', got.stderr)
        self.assertIn('again with --yes', got.stderr)
        self.assertEqual(self.plan(), {})
        got = run('--power-off-nodes', 'all', '--yes')
        self.assertEqual(got.returncode, 0, got.stderr)
        p = self.plan()
        self.assertEqual((p['how'], p['targets'], p['order']), ('poweroff', [ME], 'one'))
        got = run('--power-off-nodes', ME, '--yes')
        self.assertEqual(got.returncode, 1)
        self.assertIn('under way already', got.stderr)
        self.assertNotIn('Traceback', got.stderr)
        got = run('--power-off-nodes', '')
        self.assertIn('needs a value', got.stderr)

    def test_documented(self):
        for doc in ('operations.md', 'network-and-power.md', 'console.md'):
            with open(os.path.join(ROOT, 'docs', doc), encoding='utf-8') as f:
                text = f.read()
            self.assertIn('power-off-nodes' if doc != 'console.md' else 'switched off', text,
                          doc)

    def test_console(self):
        class C(E.Console):
            def __init__(self, chooses, confirms):
                E.Console.__init__(self, E.Palette(False))
                self.chooses, self.confirms, self.acts, self.items = chooses, confirms, [], None
                self.said = []

            def out(self, *args):
                got = run(*(list(args) + ['--json']))
                return json.loads(got.stdout or 'null')

            def act(self, *args, **kw):
                got = run(*args)
                self.acts.append((args, got.returncode, got.stdout + got.stderr))
                return got.returncode

            def sub(self, title, items):
                self.items = items

            def choose(self, title, options, words='', cur=0):
                want_ = self.chooses.pop(0)
                assert want_ in [o[0] for o in options], (want_, options)
                return want_

            def confirm(self, title, words, *a, **k):
                self.said.append(words)
                return self.confirms.pop(0)

        con = C([ME], [False])
        con.m_ops()
        item = [x for x in con.items if 'off' in x[1].lower()]
        self.assertEqual(len(item), 1, con.items)
        keys = [x[0] for x in con.items]
        self.assertEqual(len(keys), len(set(keys)))
        item[0][2]()
        self.assertEqual(con.acts, [])                  # cancelled: nothing asked
        self.assertIn('stays off', con.said[-1])
        self.assertEqual(self.plan(), {})
        con = C([ME], [True])
        con.m_ops()
        [x for x in con.items if 'off' in x[1].lower()][0][2]()
        self.assertEqual(con.acts[-1][0], ('--power-off-nodes', ME, '--yes'))
        self.assertEqual(con.acts[-1][1], 0, con.acts)
        self.assertEqual(self.plan().get('how'), 'poweroff')


if __name__ == '__main__':
    unittest.main()
