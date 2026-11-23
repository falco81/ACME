#!/usr/bin/env python3
"""Hunt w3 (1.0.143), domain validation: what the earlier rounds missed.

    python3 test/test_hunt_rw3_valid.py

No root, no internet: acme's own DNS server (acmelib/certs/dnsserver.py) on a
high port of 127.0.0.1 stands for the customer's DNS; nothing else is asked.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix='acme-hunt-w3-valid-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "testnode", "upgrade_check": 0}')
os.environ.setdefault('ACME_CONFIG', os.path.join(TMP, 'config.json'))
os.environ.setdefault('ACME_STATE', TMP)
os.environ.setdefault('ACME_RUN', TMP)
os.environ.setdefault('ACME_LOGDIR', TMP)
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import test_challenges as TC                                                   # noqa: E402
from acmelib.certs.dnsserver import DnsServer                                  # noqa: E402
from acmelib.plugins.challenges import dns_persist as DP                       # noqa: E402

LE_PROD = 'https://acme-v02.api.letsencrypt.org/acme/acct/111'
GOOD = 'letsencrypt.org; accounturi=%s; policy=wildcard' % LE_PROD

STATIC = '\n'.join([
    'ns1 A 127.0.0.1',
    # the customer's record a CNAME to one place every domain points at
    '_validation-persist.example.com. CNAME persist.acme.example.net.',
    'persist TXT "%s"' % GOOD,
    # a chain of two, and one to a name that has nothing
    '_validation-persist.two.example.com. CNAME hop.acme.example.net.',
    'hop CNAME persist.acme.example.net.',
    '_validation-persist.empty.example.com. CNAME nothing.acme.example.net.',
    '_validation-persist.plain.example.com. TXT "%s"' % GOOD,
    'xn--pklad-zsa96e.example.com. A 192.0.2.7',
])


class DnsWorld(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = TC.MemStore()
        cls.port = TC.free_port()
        cfg = TC.server_config(cls.port, dns_static=STATIC,
                               dns_ns_names='ns1.acme.example.net',
                               dns_ns_addresses='127.0.0.1')
        cls.srv = DnsServer(cls.store, cfg)
        st = cls.srv.start()
        assert st['ok'], st

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()

    def server(self):
        return '127.0.0.1:%d' % self.port


class PersistThroughCname(DnsWorld):
    """dns-persist-01: _validation-persist.NAME a CNAME (to one record kept for many
    domains) - the CA follows it, as for any TXT look-up; acme read the zone's own name
    servers without recursion, got the CNAME only, and said the record was missing."""

    def module(self):
        m = DP.DnsPersist({'domains': ['example.com']}, TC.FakeCtx())
        m.resolvers = lambda: [self.server()]
        m.auth_port = self.port
        return m

    def test_followed(self):
        m = self.module()
        self.assertEqual(m.txt('_validation-persist.example.com'), [GOOD])
        self.assertEqual(m.txt('_validation-persist.two.example.com'), [GOOD])
        ok, words, _rr = m.check_name('www.example.com', ['letsencrypt.org'], LE_PROD)
        self.assertTrue(ok, words)

    def test_cname_to_nothing_is_missing(self):
        self.assertEqual(self.module().txt('_validation-persist.empty.example.com'), [])

    def test_plain_record_as_before(self):
        self.assertEqual(self.module().txt('_validation-persist.plain.example.com'), [GOOD])
        self.assertEqual(self.module().txt('_validation-persist.none.example.com'), [])


class DnsSetTestIdn(DnsWorld):
    """Settings → DNS, "Look a name up": a name with Czech letters was refused ("which
    name?") - it is asked in its IDNA form, as DNS carries it."""

    def test_idn_name_asked(self):
        from acmelib.certs import dnssets as N
        got = N.test(None, {'servers': self.server(), 'qname': 'příklad.example.com',
                            'qtype': 'A'})
        self.assertTrue(got['ok'], got)
        self.assertEqual(got['qname'], 'xn--pklad-zsa96e.example.com')
        self.assertEqual([a['value'] for a in got['answers']], ['192.0.2.7'])

    def test_ascii_as_before(self):
        from acmelib.certs import dnssets as N
        got = N.test(None, {'servers': self.server(), 'qname': 'XN--PKLAD-ZSA96E.example.com.',
                            'qtype': 'A'})
        self.assertEqual(got['qname'], 'xn--pklad-zsa96e.example.com')
        with self.assertRaises(ValueError):
            N.test(None, {'servers': self.server(), 'qname': 'a b.example.com'})


class AcmeDnsAccountKeys(unittest.TestCase):
    """acme-dns "Accounts by name": a key written with capitals, a dot at the end or Czech
    letters (as "Register accounts" kept it) was not found for the order's name."""

    def account(self, accounts, name):
        from acmelib.plugins.challenges import acme_dns
        m = acme_dns.AcmeDns({'url': 'https://auth.example', 'accounts': json.dumps(accounts)},
                             TC.FakeCtx())
        return m.account(name)

    def test_written_otherwise(self):
        a = {'username': 'u', 'subdomain': 's'}
        self.assertEqual(self.account({'Example.COM.': a}, 'example.com'), a)
        self.assertEqual(self.account({'příklad.cz': a}, 'xn--pklad-zsa96e.cz'), a)
        self.assertEqual(self.account({'*.Example.com': a}, 'example.com'), a)

    def test_exact_first_and_missing_said(self):
        from acmelib.plugins.base import PluginError
        a, b = {'username': 'a', 'subdomain': 'a'}, {'username': 'b', 'subdomain': 'b'}
        self.assertEqual(self.account({'Example.com': b, 'example.com': a}, 'example.com'), a)
        with self.assertRaises(PluginError):
            self.account({'other.com': a}, 'example.com')


ROOT = os.path.dirname(HERE)
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
CTMP = tempfile.mkdtemp(prefix='acme-hunt-w3-valid-cli-')
with open(os.path.join(CTMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(CTMP, 'config.json'), ACME_STATE=CTMP,
           ACME_RUN=CTMP, ACME_LOGDIR=CTMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(CTMP, 'console-flag'))


def run(*args):
    return subprocess.run(ACME + [str(a) for a in args], env=ENV, capture_output=True,
                          text=True, timeout=180)


def sets():
    got = run('--dns-sets', '--json')
    assert got.returncode == 0, got.stdout + got.stderr
    return {s['name']: s for s in json.loads(got.stdout)['sets']}, json.loads(got.stdout)


class Con(object):
    """The console as its menus see it (as test_hunt_rv1_parity's): what a person answers
    given in order, each command run for real."""
    def __init__(self, chooses=(), forms=(), pick=0):
        self.chooses, self.forms, self.pick_at = list(chooses), list(forms), pick
        self.acts, self.subs = [], []

    def out(self, *args):
        got = run(*(list(args) + ['--json']))
        return json.loads(got.stdout or 'null')

    def act(self, *args, **kw):
        got = run(*args)
        self.acts.append((args, got.returncode, got.stdout + got.stderr))
        return got.returncode

    def sub(self, title, items):
        self.subs.append((title, items))

    def pick(self, title, load, cols, act=None, empty='', words=''):
        rows = load()
        for c in cols:
            for r in rows:
                c[1](r)
        if act and rows:
            act(rows[self.pick_at] if isinstance(self.pick_at, int) else
                [r for r in rows if r.get('name') == self.pick_at][0])
        return rows

    def choose(self, title, options, words='', cur=0):
        want = self.chooses.pop(0)
        assert want is None or want in [o[0] for o in options], (want, options)
        return want

    def form(self, title, fields, words='', check=None, ok='OK'):
        for f in fields:
            if f.get('when'):
                f['when']({'protocol': 'udp'})
        vals = {f['key']: str(f.get('value') or '') if f.get('kind') != 'choice' else
                (f.get('value') or f['options'][0][0]) for f in fields}
        vals.update(self.forms.pop(0))
        return vals

    def confirm(self, *a, **k):
        return True


class DnsSetsInTheConsole(unittest.TestCase):
    """Settings → DNS on the pages adds, changes, deletes, tries and assigns sets; the
    console only listed them."""

    def test_menu_add_try_change_assign_delete(self):
        from acmelib.certs import console as C
        con = Con()
        C.dns_sets(con)
        _t, items = con.subs[-1]
        self.assertEqual(len({k for k, _w, _f in items}), len(items))
        con = Con(forms=[{'name': 'Lab', 'servers': '127.0.0.1:5353, 127.0.0.2',
                          'note': 'the lab'}])
        C.dns_set_pick(con)                         # the first row: + add a set
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        have, _all = sets()
        self.assertEqual(have['Lab']['servers'], ['127.0.0.1:5353', '127.0.0.2'])
        self.assertEqual(have['Lab']['note'], 'the lab')
        con = Con(chooses=['edit'], forms=[{'name': 'Lab2', 'servers': '127.0.0.3',
                                           'note': ''}], pick='Lab')
        C.dns_set_pick(con)
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        have, _all = sets()
        self.assertNotIn('Lab', have)
        self.assertEqual(have['Lab2']['servers'], ['127.0.0.3'])
        self.assertEqual(have['Lab2']['note'], '')          # taken away, as on the page
        con = Con(chooses=['test'], forms=[{'qname': 'example.invalid', 'qtype': 'A'}],
                  pick='Lab2')
        C.dns_set_pick(con)
        self.assertEqual(con.acts[-1][0][:3], ('--dns-set-test', 'Lab2', 'example.invalid'))
        con = Con(chooses=['validation', 'Lab2'])
        C.dns_assign(con)
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        _h, got = sets()
        self.assertEqual({p['key']: p['set'] for p in got['purposes']}['validation'], 'Lab2')
        con = Con(chooses=['del'], pick='Lab2')
        C.dns_set_pick(con)
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        have, got = sets()
        self.assertNotIn('Lab2', have)
        self.assertNotEqual({p['key']: p['set'] for p in got['purposes']}['validation'], 'Lab2')

    def test_built_in_sets_offer_what_they_may(self):
        from acmelib.certs import console as C
        seen = []

        class Seen(Con):
            def choose(self, title, options, words='', cur=0):
                seen.append((title, [o[0] for o in options]))
                return None
        C.dns_set_pick(Seen(pick="The system's"))
        C.dns_set_pick(Seen(pick='Public'))
        self.assertEqual(seen[0][1], ['test'])
        self.assertEqual(seen[1][1], ['test', 'edit'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
