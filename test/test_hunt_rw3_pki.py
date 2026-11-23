#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hunt w3, area pki (acme as a CA, SCEP, AD CS, chains): what was found and fixed.

  - an authority with an IPv6 name constraint (IP:fd00::/8) signed no IPv6 name at all and
    could have no intermediate with one: a ValueError (Python's ip_network does not read the
    IPv6 mask form openssl writes)
  - an imported authority with an IP name constraint (kept as 10.0.0.0/8, as its certificate
    reads) could not be renewed, nor have an intermediate: openssl "bad ip address"
  - SCEP: GetCACert answering a PKCS#7 with no certificate in it was an IndexError
  - AD CS over RPC: an AIA address (chain completion) answering an empty PKCS#7 or a cut
    certificate was an IndexError / DerError after the CA had issued - the certificate lost
  - "Request for a CA elsewhere" (docs/own-ca.md) had no way in: no route, no button, no
    command line, no console item - POST /api/cas/request, the button, `acme --ca-request`,
    the console's item; the console also installs the answer and puts a certificate on hold
  - docs/own-ca.md said every certificate gets must-staple (only when the profile asks)

Every certificate is checked with openssl verify.

    python3 test/test_hunt_rw3_pki.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-rw3pki-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = dict(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
           ACME_LOGDIR=TMP)
os.environ.update(ENV)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import acme as E                                            # noqa: E402
from acmelib.certs import api as API, ca as CA, pki         # noqa: E402,F401
from acmelib.certs.cli import _Daemon                       # noqa: E402
from acmelib.certs.pki import PkiError                      # noqa: E402
from acmelib.plugins.base import PluginError                # noqa: E402
from acmelib.plugins.issuers import _scep_pkcs7 as p7       # noqa: E402
from acmelib.plugins.issuers import ms_adcs_rpc as RPC      # noqa: E402
from acmelib.plugins.issuers.scep import ScepIssuer         # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
DAEMON = _Daemon(STORE)
CLI_ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
CLI_ENV.update(ENV, ACME_STAY_ROOT='1', NO_COLOR='1',
               ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))


def call(method, path, body=None):
    return E.cli_api(DAEMON, 'tester', method, path, body=body)


def run(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + [str(a) for a in args],
                          env=CLI_ENV, capture_output=True, text=True, input='', timeout=180)


def csr_for(*names, kt='ec-256'):
    return pki.make_csr(pki.make_key(kt), list(names))[0]


def verify(leaf, chain, crls=None):
    """openssl verify of `leaf` through `chain` (its last one the root)."""
    d = tempfile.mkdtemp(prefix='acme-rw3v-')
    try:
        def w(n, t):
            with open(os.path.join(d, n), 'w') as f:
                f.write(t)
            return os.path.join(d, n)
        args = ['openssl', 'verify', '-x509_strict', '-CAfile', w('root.pem', chain[-1])]
        if chain[:-1]:
            args += ['-untrusted', w('mid.pem', ''.join(chain[:-1]))]
        if crls:
            args += ['-crl_check', '-CRLfile', w('crl.pem', ''.join(crls))]   # the leaf's
        r = subprocess.run(args + [w('leaf.pem', leaf)], capture_output=True, text=True)
        return r.returncode == 0, r.stdout + r.stderr
    finally:
        shutil.rmtree(d, ignore_errors=True)


def x509_text(pem):
    return subprocess.run(['openssl', 'x509', '-noout', '-text'], input=pem, text=True,
                          capture_output=True).stdout


class NameConstraintsIp(unittest.TestCase):
    def test_ipv6_constraint(self):
        root = CA.ca_create(STORE, 'V6 Root', 'W3 V6 Root', key_type='ec-256',
                            name_constraints=['corp.example', 'IP:fd00::/8', 'IP:10.0.0.0/8'])
        text = x509_text(CA.ca_get(STORE, root)['cert_pem'])
        self.assertIn('IP:FD00:0:0:0:0:0:0:0/FF00:0:0:0:0:0:0:0', text)
        leaf, chain = CA.ca_sign(STORE, root, csr_for('fd00::5', 'a.corp.example'), 30)
        ok, said = verify(leaf, chain)
        self.assertTrue(ok, said)
        with self.assertRaises(PkiError) as e:
            CA.ca_sign(STORE, root, csr_for('fe80::1'), 30)
        self.assertIn('outside', str(e.exception))
        # an intermediate with a narrower IPv6 constraint; one wider refused
        sub = CA.ca_create(STORE, 'V6 Sub', 'W3 V6 Sub', key_type='ec-256', parent_id=root,
                           name_constraints=['IP:fd00:1::/32', 'sub.corp.example'])
        with self.assertRaises(PkiError):
            CA.ca_create(STORE, 'V6 Wide', 'W3 V6 Wide', key_type='ec-256', parent_id=root,
                         name_constraints=['IP:fc00::/7'])
        leaf, chain = CA.ca_sign(STORE, sub, csr_for('fd00:1::9', 'x.sub.corp.example'), 30)
        ok, said = verify(leaf, chain)
        self.assertTrue(ok, said)
        with self.assertRaises(PkiError):
            CA.ca_sign(STORE, sub, csr_for('fd00:2::9'), 30)
        # renewed under its parent with the constraints it has (normalised once more)
        CA.ca_renew(STORE, sub)
        leaf, chain = CA.ca_sign(STORE, sub, csr_for('fd00:1::a'), 30)
        self.assertTrue(verify(leaf, chain)[0])
        self.assertEqual(CA.nc_normalize(['permitted;IP:fd00::/ff00::']),
                         ['permitted;IP:fd00::/ff00::'])

    def test_imported_with_ip_prefix(self):
        made = CA.ca_create(STORE, 'Elsewhere Made', 'W3 Imported Root', key_type='ec-256',
                            path_len=1, name_constraints=['corp.example', 'IP:10.0.0.0/8',
                                                          'IP:fd00::/8'])
        g = CA.ca_get(STORE, made)
        key = CA._key(CA._row(STORE, made))
        imp = CA.ca_import(STORE, 'W3 Imported', g['cert_pem'], key)
        self.assertIn('permitted;IP:10.0.0.0/8', CA.ca_get(STORE, imp)['name_constraints'])
        sub = CA.ca_create(STORE, 'W3 Imported Sub', 'W3 Imported Sub', key_type='ec-256',
                           parent_id=imp)
        self.assertIn('IP:10.0.0.0/255.0.0.0', x509_text(CA.ca_get(STORE, sub)['cert_pem']))
        leaf, chain = CA.ca_sign(STORE, sub, csr_for('10.1.2.3', 'w.corp.example'), 30)
        ok, said = verify(leaf, chain)
        self.assertTrue(ok, said)
        out = CA.ca_renew(STORE, imp)
        self.assertEqual(out['how'], 'self')
        text = x509_text(out['cert_pem'])
        self.assertIn('IP:10.0.0.0/255.0.0.0', text)
        self.assertIn('IP:FD00:0:0:0:0:0:0:0/FF00:0:0:0:0:0:0:0', text)
        ok, said = verify(leaf, [chain[0], out['cert_pem']])      # signed before: still good
        self.assertTrue(ok, said)


class Scep(unittest.TestCase):
    def test_get_ca_cert_without_certificates(self):
        class Ctx(object):
            def step(self, *a):
                pass
        for ctype in ('application/x-x509-ca-ra-cert', 'application/x-x509-ca-cert'):
            s = ScepIssuer({'url': 'http://scep.example/scep'}, Ctx())
            s._get = lambda *a, **k: (200, {'content-type': ctype}, p7.build_degenerate([]))
            with self.assertRaises(PluginError) as e:
                s.ca_certs()
            self.assertIn('no certificate', str(e.exception))


class RpcChainFromAia(unittest.TestCase):
    def test_aia_answers(self):
        root = CA.ca_create(STORE, 'Aia Root', 'W3 Aia Root', key_type='ec-256',
                            aia_url='http://pki.example/root.crt')
        sub = CA.ca_create(STORE, 'Aia Sub', 'W3 Aia Sub', key_type='ec-256', parent_id=root,
                           aia_url='http://pki.example/sub.crt')
        CA.ca_edit(STORE, sub, {'aia_url': 'http://pki.example/sub.crt'})
        leaf, chain = CA.ca_sign(STORE, sub, csr_for('aia.example'), 30)
        said = []

        class Ctx(object):
            def __init__(self, answer):
                self.answer = answer

            def http(self, method, url, body, headers, timeout):
                return self.answer(url)

            def step(self, words, level='info'):
                said.append(words)
        good = {'http://pki.example/sub.crt': pki.pem_to_der(chain[0]),
                'http://pki.example/root.crt': pki.pem_to_der(chain[1])}
        for answer in (lambda u: (200, {}, p7.build_degenerate([])),
                       lambda u: (200, {}, b'\x30\x03\x02\x01\x01')):
            got = RPC.MsAdcsRpcIssuer({}, Ctx(answer))._chain_elsewhere(pki.pem_to_der(leaf))
            self.assertEqual(got, [])
            self.assertTrue(any('does not read as a certificate' in w for w in said))
        got = RPC.MsAdcsRpcIssuer({}, Ctx(lambda u: (200, {}, good[u])))._chain_elsewhere(
            pki.pem_to_der(leaf))
        self.assertEqual([p7.pem(d) for d in got], chain)
        # a degenerate PKCS#7 of the issuer, as AD CS serves its .crt at times
        deg = {'http://pki.example/sub.crt': p7.build_degenerate([pki.pem_to_der(chain[0])]),
               'http://pki.example/root.crt': good['http://pki.example/root.crt']}
        got = RPC.MsAdcsRpcIssuer({}, Ctx(lambda u: (200, {}, deg[u])))._chain_elsewhere(
            pki.pem_to_der(leaf))
        self.assertEqual(len(got), 2)


def outside_ca(d):
    """A CA elsewhere (AD CS in spirit): openssl x509 -req with the SubCA extensions."""
    def sh(*a):
        subprocess.run(list(a), check=True, capture_output=True, cwd=d)
    sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out',
       'root.pem', '-days', '3650', '-subj', '/CN=W3 Corporate Root', '-addext',
       'keyUsage = critical, keyCertSign, cRLSign')
    with open(os.path.join(d, 'ext.cnf'), 'w') as f:
        f.write('[v3]\nbasicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, '
                'keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n'
                'authorityKeyIdentifier = keyid:always\n')

    def sign(csr_pem):
        with open(os.path.join(d, 'req.csr'), 'w') as f:
            f.write(csr_pem)
        sh('openssl', 'x509', '-req', '-in', 'req.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
           '-CAcreateserial', '-days', '1000', '-extfile', 'ext.cnf', '-extensions', 'v3',
           '-out', 'out.pem')
        with open(os.path.join(d, 'out.pem')) as f:
            return f.read()
    with open(os.path.join(d, 'root.pem')) as f:
        return f.read(), sign


class RequestForACaElsewhere(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='acme-rw3out-')
        self.root, self.sign = outside_ca(self.d)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def finish(self, ident, csr, names=('w.corp.example',)):
        self.assertIn('CA:TRUE', subprocess.run(['openssl', 'req', '-noout', '-text'], input=csr,
                                                text=True, capture_output=True).stdout)
        call('POST', '/api/cas/install_cert', {'id': ident, 'cert_pem': self.sign(csr),
                                               'chain_pem': self.root})
        leaf, chain = CA.ca_sign(STORE, ident, csr_for(*names), 30)
        ok, said = verify(leaf, chain, [CA.ca_get(STORE, ident)['crl_pem']])
        self.assertTrue(ok, said)
        self.assertEqual(pki.cert_info(chain[-1])['subject_dn'], 'CN=W3 Corporate Root')
        return leaf

    def test_api(self):
        got = call('POST', '/api/cas/request', {
            'name': 'W3 Sub API', 'subject': {'CN': 'W3 Sub API', 'O': 'Example'},
            'key_type': 'ec-256', 'path_len': 0, 'name_constraints': ['corp.example']})
        self.assertTrue(got['pending'])
        self.assertIn('BEGIN CERTIFICATE REQUEST', got['csr_pem'])
        row = CA.ca_get(STORE, got['id'])
        self.assertTrue(row['pending'])
        self.assertEqual(row['csr_pem'], got['csr_pem'])
        self.assertEqual(row['name_constraints'], ['permitted;DNS:corp.example'])
        self.assertTrue(row['key_set'])
        with self.assertRaises(PkiError):            # it signs nothing yet
            CA.ca_sign(STORE, got['id'], csr_for('w.corp.example'), 30)
        self.finish(got['id'], got['csr_pem'])
        with self.assertRaises(PkiError):            # its own check: the name constraints
            CA.ca_sign(STORE, got['id'], csr_for('w.other.example'), 30)
        # a subject without CN refused, an unknown key type refused
        with self.assertRaises((Exception, SystemExit)):
            call('POST', '/api/cas/request', {'name': 'W3 No CN', 'subject': {'O': 'x'}})
        with self.assertRaises((Exception, SystemExit)):
            call('POST', '/api/cas/request', {'name': 'W3 Bad', 'subject': {'CN': 'x'},
                                              'key_type': 'dsa-1024'})

    def test_command_line_and_console(self):
        out = os.path.join(self.d, 'sub.csr')
        got = run('--ca-request', 'W3 Sub Cli', '--subject', 'CN=W3 Sub Cli,O=Example',
                  '--key-type', 'ec-256', '--set', 'path_len=0', '--out', out)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('--ca-install-cert', got.stdout)
        with open(out) as f:
            csr = f.read()
        ident = CA.ca_get(STORE, 'W3 Sub Cli')['id']
        self.assertEqual(CA.ca_get(STORE, ident)['csr_pem'], csr)
        with open(os.path.join(self.d, 'answer.pem'), 'w') as f:
            f.write(self.sign(csr) + self.root)
        got = run('--ca-install-cert', 'W3 Sub Cli', os.path.join(self.d, 'answer.pem'))
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        leaf, chain = CA.ca_sign(STORE, ident, csr_for('cli.example'), 30)
        ok, said = verify(leaf, chain)
        self.assertTrue(ok, said)
        # --json; printed; --days refused (the CA above gives them)
        got = run('--ca-request', 'W3 Sub Json', '--subject', 'CN=W3 Sub Json', '--json')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('CERTIFICATE REQUEST', json.loads(got.stdout)['csr_pem'])
        got = run('--ca-request', 'W3 Sub Print')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('-----BEGIN CERTIFICATE REQUEST-----', got.stdout)
        got = run('--ca-request', 'W3 Sub Days', '--set', 'days=30')
        self.assertNotEqual(got.returncode, 0)
        self.assertRaises(PkiError, CA.ca_get, STORE, 'W3 Sub Days')
        # the console: the request, then the answer installed from the authority's menu
        from acmelib.certs import console as C
        out2 = os.path.join(self.d, 'console.csr')
        con = Con(forms=[{'name': 'W3 Sub Console', 'subject': 'CN=W3 Sub Console',
                          'key_type': 'ec-256', 'out': out2}])
        C.ca_request(con)
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        self.assertEqual(con.acts[-1][0][0], '--ca-request')
        with open(out2) as f:
            csr = f.read()
        with open(os.path.join(self.d, 'answer2.pem'), 'w') as f:
            f.write(self.sign(csr))
        con = Con(chooses=['install'], asks=[os.path.join(self.d, 'answer2.pem')])
        C.ca_do(con, {'name': 'W3 Sub Console'})
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        self.assertFalse(CA.ca_get(STORE, 'W3 Sub Console')['pending'])
        leaf, chain = CA.ca_sign(STORE, 'W3 Sub Console', csr_for('con.example'), 30)
        self.assertEqual(len(chain), 1)         # installed without its chain: the root is known
        ok, said = verify(leaf, chain + [self.root])
        self.assertTrue(ok, said)
        # the console lists the request among the new ones
        con = Con()
        C.cas(con)
        self.assertIn('+ a request for a CA elsewhere', [r['name'] for r in con.rows])

    def test_console_puts_on_hold(self):
        from acmelib.certs import console as C
        ident = CA.ca_create(STORE, 'W3 Hold', 'W3 Hold', key_type='ec-256')
        leaf, chain = CA.ca_sign(STORE, ident, csr_for('hold.example'), 30)
        serial = pki.cert_info(leaf)['serial']
        con = Con(chooses=['revoke'], forms=[{'serial': serial, 'reason': 'certificateHold'}])
        C.ca_do(con, {'name': 'W3 Hold'})
        self.assertEqual(con.acts[-1][1], 0, con.acts[-1])
        self.assertIn('released again', con.confirmed[-1])
        crl = CA.ca_get(STORE, ident)['crl_pem']
        self.assertFalse(verify(leaf, chain, [crl])[0])
        con = Con(chooses=['unrevoke'], asks=[serial])
        C.ca_do(con, {'name': 'W3 Hold'})
        self.assertTrue(verify(leaf, chain, [CA.ca_get(STORE, ident)['crl_pem']])[0])


class Con(object):
    """The console as its menus see it; the answers given in order."""
    def __init__(self, chooses=(), asks=(), forms=()):
        self.chooses, self.asks, self.forms = list(chooses), list(asks), list(forms)
        self.acts, self.confirmed, self.rows = [], [], []

    def out(self, *args):
        got = run(*(list(args) + ['--json']))
        try:
            return json.loads(got.stdout or 'null')
        except ValueError:
            return None

    _rows = staticmethod(lambda got, *keys: next(
        (got[k] for k in keys if isinstance(got, dict) and isinstance(got.get(k), list)), []))

    def act(self, *args, **kw):
        got = run(*args)
        self.acts.append((args, got.returncode, got.stdout + got.stderr))
        return got.returncode

    def pick(self, title, load, cols, act=None, empty='', words=''):
        self.rows = load()
        for c in cols:
            for r in self.rows:
                c[1](r)

    def choose(self, title, options, words='', cur=0):
        want = self.chooses.pop(0)
        assert want in [o[0] for o in options], (want, options)
        return want

    def ask_one(self, *a, **k):
        return self.asks.pop(0)

    def form(self, title, fields, words='', check=None, ok='OK'):
        vals = {}
        for f in fields:
            v = f.get('value')
            if f.get('kind') == 'choice' and v not in [o[0] for o in f['options']]:
                v = f['options'][0][0]
            vals[f['key']] = str(v if v is not None else '')
        vals.update(self.forms.pop(0))
        for f in fields:
            if f.get('kind') == 'choice':
                assert vals[f['key']] in [o[0] for o in f['options']], (f['key'], vals)
        return vals

    def confirm(self, title, words, *a, **k):
        self.confirmed.append(words)
        return True

    def note(self, *a, **k):
        pass


class PagesAndDocs(unittest.TestCase):
    def read(self, *p):
        with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
            return f.read()

    def test_button_and_route(self):
        ui = self.read('web', 'admin', 'certs-ui.php')
        self.assertIn('id="ca-request"', ui)
        js = self.read('web', 'assets', 'certs.js')
        self.assertIn("capi('cas/request'", js)
        self.assertIn("on('ca-request'", js)
        self.assertIn("'Show the request'", self.read('web', 'assets', 'cas.js'))
        subprocess.run(['node', '--check', os.path.join(ROOT, 'web', 'assets', 'certs.js')],
                       check=True) if shutil.which('node') else None
        subprocess.run(['node', '--check', os.path.join(ROOT, 'web', 'assets', 'cas.js')],
                       check=True) if shutil.which('node') else None

    def test_docs(self):
        self.assertIn('--ca-request', self.read('docs', 'command-line.md'))
        own = self.read('docs', 'own-ca.md')
        self.assertIn('/api/cas/request', own)
        self.assertNotRegex(own, r'TLS Feature `status_request` with \*must staple\*\.')
        self.assertIn('a request for a CA elsewhere', self.read('docs', 'console.md'))

    def test_must_staple_only_when_asked(self):
        ident = CA.ca_create(STORE, 'W3 Staple', 'W3 Staple', key_type='ec-256')
        leaf, _c = CA.ca_sign(STORE, ident, csr_for('st.example'), 30)
        self.assertNotIn('TLS Feature', x509_text(leaf))
        leaf, _c = CA.ca_sign(STORE, ident, csr_for('st.example'), 30, {'must_staple': True})
        self.assertTrue(re.search(r'TLS Feature:\s*\n\s*status_request', x509_text(leaf)))


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
