#!/usr/bin/env python3
"""Bug hunt v4, area infra (acme's own CA, local users).

    python3 test/test_hunt_rv4_infra.py

- an authority's certificate put on hold (acme --ca-revoke ... --reason certificateHold) could
  never be released: ca.ca_unrevoke() was there and nothing called it, though own-ca.md says a
  hold can be released - now /api/cas/unrevoke (full administrator), acme --ca-unrevoke CA
  SERIAL, the console's "Release a certificate on hold" and the page's "Release the hold";
- the page's "Name and shell" of a local user had no command line: acme --local-user set NAME
  --local-full-name / --local-shell (and the console's "Its full name and shell");
- acme's own DNS server: a TTL past 32 bits in dns_static was answered cut to its low 32 bits
  (99999999999 -> 1215752191), one past 2^31-1 as it was (resolvers take it as 0) - now said
  among its problems and not served; dns_ttl kept to 2^31-1.
"""
import json
import os
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-rv4infra-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))


def run(*args):
    got = subprocess.run(ACME + list(args), env=ENV, capture_output=True, text=True, timeout=120,
                         input='')
    assert 'Traceback' not in got.stderr + got.stdout, got.stderr
    return got


def ok(*args):
    got = run(*args)
    assert got.returncode == 0, got.stdout + got.stderr
    return got


def crl_serials():
    out = os.path.join(TMP, 'root.crl')
    ok('--ca-crl', 'Root', '--out', out)
    got = subprocess.run(['openssl', 'crl', '-in', out, '-noout', '-text'], capture_output=True,
                         text=True, check=True).stdout
    return [ln.split(':', 1)[1].strip() for ln in got.splitlines()
            if 'Serial Number:' in ln]


class CaHoldReleased(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ok('--ca-create', 'Root', '--subject', 'CN=Root')
        cls.serials = []
        for n in ('a', 'b'):
            key, csr = os.path.join(TMP, n + '.key'), os.path.join(TMP, n + '.csr')
            subprocess.run(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:P-256', '-nodes', '-keyout', key, '-subj',
                            '/CN=%s.example.com' % n, '-out', csr], check=True,
                           capture_output=True)
            pem = os.path.join(TMP, n + '.pem')
            ok('--ca-sign', 'Root', '--csr', csr, '--out', pem)
            cls.serials.append(subprocess.run(['openssl', 'x509', '-in', pem, '-noout', '-serial'],
                                              capture_output=True, text=True, check=True)
                               .stdout.strip().split('=', 1)[1])

    def state(self, serial):
        issued = json.loads(ok('--ca-show', 'Root', '--json').stdout)['issued']
        return [i for i in issued if i['serial'] == serial][0]

    def test_hold_released(self):
        s = self.serials[0]
        ok('--ca-revoke', 'Root', s, '--reason', 'certificateHold', '--yes')
        self.assertEqual(self.state(s)['reason'], 'certificateHold')
        self.assertIn(s, crl_serials())
        got = ok('--ca-unrevoke', 'Root', s)
        self.assertIn('released', got.stdout)
        self.assertFalse(self.state(s)['revoked'])
        self.assertNotIn(s, crl_serials())

    def test_other_reason_not_taken_back(self):
        s = self.serials[1]
        ok('--ca-revoke', 'Root', s, '--reason', 'keyCompromise', '--yes')
        got = run('--ca-unrevoke', 'Root', s)
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('only a certificate on hold', got.stderr + got.stdout)
        self.assertTrue(self.state(s)['revoked'])
        self.assertNotEqual(run('--ca-unrevoke', 'Root', 'not-a-serial').returncode, 0)

    def test_every_way_has_it(self):
        self.assertIn('--ca-unrevoke', ok('--help').stdout)
        with open(os.path.join(ROOT, 'docs', 'command-line.md'), encoding='utf-8') as f:
            self.assertIn('acme --ca-unrevoke CA SERIAL', f.read())
        with open(os.path.join(ROOT, 'acmelib', 'certs', 'api_cas.py'), encoding='utf-8') as f:
            self.assertIn("@A.api('POST', '/api/cas/unrevoke', 'fulladmin')", f.read())
        with open(os.path.join(ROOT, 'acmelib', 'certs', 'console.py'), encoding='utf-8') as f:
            self.assertIn("con.act('--ca-unrevoke', name, serial)", f.read())
        with open(os.path.join(ROOT, 'web', 'assets', 'certs.js'), encoding='utf-8') as f:
            js = f.read()
        self.assertIn("capi('cas/unrevoke'", js)
        self.assertIn("r.reason === 'certificateHold'", js)


class LocalUserSet(unittest.TestCase):
    """acme --local-user set: asked of the nodes as the page's "Name and shell" asks."""

    @classmethod
    def setUpClass(cls):
        os.environ.update(ACME_CONFIG=ENV['ACME_CONFIG'], ACME_STATE=TMP, ACME_RUN=TMP,
                          ACME_LOGDIR=TMP)
        sys.path.insert(0, ROOT)
        import acme  # noqa: F401
        from acmelib import engine as E
        cls.E = E

    def cli(self, *argv):
        E = self.E
        asked = []
        args = E.build_parser().parse_args(list(argv))
        view = {'nodes': [{'name': 'acme1', 'pending': 0, 'said': [
            {'name': 'jnovak', 'ok': True, 'said': 'jnovak changed'}]}]}
        with mock.patch.object(E, 'cli_store', lambda: object()), \
                mock.patch.object(E, 'host_nodes', lambda store: ['acme1']), \
                mock.patch.object(E, 'cli_who', lambda: 'root (command line)'), \
                mock.patch.object(E, 'osu_view', lambda store: view), \
                mock.patch.object(E, 'osu_ask', lambda store, nodes, do, by, **f:
                                  asked.append((do, f)) or list(nodes)):
            rc = E.cli_osusers(args, E.Palette(False))
        return rc, asked

    def test_set_name_and_shell(self):
        rc, asked = self.cli('--local-user', 'set', 'jnovak', '--local-full-name', 'Jan Novák',
                             '--local-shell', '/bin/zsh')
        self.assertEqual(rc, 0)
        self.assertEqual(asked[-1], ('set', {'name': 'jnovak', 'gecos': 'Jan Novák',
                                             'shell': '/bin/zsh'}))
        rc, asked = self.cli('--local-user', 'set', 'jnovak', '--local-shell', '/bin/bash')
        self.assertEqual(asked[-1], ('set', {'name': 'jnovak', 'shell': '/bin/bash'}))

    def test_set_needs_something(self):
        rc, asked = self.cli('--local-user', 'set', 'jnovak')
        self.assertEqual(rc, 2)
        self.assertEqual(asked, [])


class DnsTtl(unittest.TestCase):
    def test_ttl_out_of_range(self):
        sys.path.insert(0, os.path.join(ROOT, 'test'))
        sys.path.insert(0, ROOT)
        import test_challenges as T
        from acmelib.certs.dnsserver import DnsServer
        from acmelib.plugins.challenges import _dns as D
        st = T.MemStore()
        srv = DnsServer(st, T.server_config(0, dns_static='www A 192.0.2.5 99999999999\n'
                                                          'w2 A 192.0.2.6 3000000000\n'
                                                          'w3 A 192.0.2.7 2147483647\n'
                                                          'w4 A 192.0.2.8'))
        got = {}
        for n in ('www', 'w2', 'w3', 'w4'):
            m = D.parse(srv.answer(D.make_query(n + '.' + T.ZONE, 1).to_wire()))
            got[n] = [r.ttl for r in m.answer]
        self.assertEqual(got['www'], [])
        self.assertEqual(got['w2'], [])
        self.assertEqual(got['w3'], [2147483647])
        self.assertTrue(got['w4'])
        self.assertEqual(len([p for p in srv.records().problems if 'TTL' in p]), 2)
        srv = DnsServer(st, T.server_config(0, dns_static='', dns_ttl=99999999999))
        self.assertEqual(srv.records().ttl, 2147483647)


if __name__ == '__main__':
    unittest.main(verbosity=2)
