#!/usr/bin/env python3
"""1.0.140 (agentkey): the agent checks WHAT it deploys (A1) and where the keys of its
certificates are made (B7) - docs/target-agent.md "What the agent deploys", "Where keys are made".

* the policy's lines `allow issuer sha256=HEX`, `allow names ...`, `require key local`: read,
  written back, reported, the hash of a policy without them as before; `acme-agent allow issuer
  CA.pem`, `allow names`, `require key local|any`; on Windows (its fake) and in the Kubernetes
  agent the same words;
* the agent's own check (guard_check): the chain verified by openssl (the job's chain only what
  a path is built from), a cross-signed copy of an allowed CA, every name, the key one it made,
  a PKCS#12 opened with the password sealed to it, a DER certificate, a keystore it cannot read;
* acme's side: the lines carried (clean_policy), a deployment checked before it is sent (and
  said in What happens and the needs card), args.guard only to an agent that knows it, the
  builder's facts (the CAs acme knows, the names deployed there), its state kept, fleet
  templates with the lines;
* LIVE (a real agent, both sides, joined passive as test_f138_agentsec does): a certificate of
  another CA refused, a foreign name refused, acme's key refused with require key local, the
  allowed ones deployed (PEM, the PFX with acme's key, the key the agent made); nothing written
  when refused, the refusal in its audit log; old policy files work unchanged;
* B7: where keys are made (counts, which could switch, why not), Switch at the next renewal (the
  sweep makes it when the renewal comes) and now, take back, permissions (the role, the team);
* the routes, the command line, the console; the page (test/f140_agentkey_page.js).

    python3 test/test_f140_agentkey.py
"""
import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_target_agent as T  # noqa: E402

E, G, S, STORE, AG = T.E, T.G, T.S, T.STORE, T.AG
from acmelib.certs import agent_deployguard as DG, agent_keyplace as K  # noqa: E402
from acmelib.certs import api as A, agent_policy as P  # noqa: E402
from acmelib.plugins import base  # noqa: E402

PKI = {}


def need_account():
    import pwd
    if not T.CAN:
        return
    try:
        pwd.getpwnam(T.USER)
    except KeyError:
        subprocess.run(['useradd', '--system', '--no-create-home', '--shell',
                        '/usr/sbin/nologin', T.USER], capture_output=True)


def ossl(*args):
    return subprocess.run(['openssl'] + list(args), capture_output=True, check=True).stdout


def make_pki():
    """A root, an intermediate, a leaf of it; another CA (evil) and a leaf of it; a leaf of the
    test CA (test_target_agent's) for a foreign name."""
    if PKI:
        return PKI
    d = tempfile.mkdtemp(prefix='acme-f140-pki-')
    j = lambda n: os.path.join(d, n)        # noqa: E731
    ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes']
    with open(j('ca.ext'), 'w') as fh:
        fh.write('basicConstraints=critical,CA:TRUE\n')
    ossl('req', '-x509', *ec, '-keyout', j('root.key'), '-out', j('root.crt'), '-days', '30',
         '-subj', '/CN=F140 Root', '-addext', 'basicConstraints=critical,CA:TRUE')
    ossl('req', *ec, '-keyout', j('int.key'), '-out', j('int.csr'), '-subj', '/CN=F140 Int')
    ossl('x509', '-req', '-in', j('int.csr'), '-CA', j('root.crt'), '-CAkey', j('root.key'),
         '-CAcreateserial', '-days', '20', '-out', j('int.crt'), '-extfile', j('ca.ext'))
    for leaf, ca, names in (('leaf', 'int', 'DNS:www.example.test,DNS:api.example.test'),
                            ('evil', 'eroot', 'DNS:www.example.test')):
        if ca == 'eroot' and not os.path.exists(j('eroot.crt')):
            ossl('req', '-x509', *ec, '-keyout', j('eroot.key'), '-out', j('eroot.crt'), '-days',
                 '30', '-subj', '/CN=F140 Root', '-addext', 'basicConstraints=critical,CA:TRUE')
        with open(j(leaf + '.ext'), 'w') as fh:
            fh.write('subjectAltName=%s\n' % names)
        ossl('req', *ec, '-keyout', j(leaf + '.key'), '-out', j(leaf + '.csr'), '-subj',
             '/CN=www.example.test')
        ossl('x509', '-req', '-in', j(leaf + '.csr'), '-CA', j(ca + '.crt'), '-CAkey',
             j(ca + '.key'), '-CAcreateserial', '-days', '10', '-out', j(leaf + '.crt'),
             '-extfile', j(leaf + '.ext'))
    ossl('pkcs12', '-export', '-inkey', j('leaf.key'), '-in', j('leaf.crt'), '-certfile',
         j('int.crt'), '-passout', 'pass:pw', '-out', j('leaf.p12'))
    PKI.update(d=d, j=j, r=lambda n: open(j(n)).read())
    return PKI


def fp(pem):
    return AG.fp_of_pem(pem)


class Wire(object):
    def __init__(self, role, body=None, args=None, name=None):
        raw = json.dumps(body or {}).encode('utf-8')
        self.headers = {'Content-Length': str(len(raw))}
        self.rfile = io.BytesIO(raw)
        self.role, self.store = role, STORE
        self.args = args or {}
        self.name = name or 'f140-' + role

    def body(self):
        return E.ApiHandler.body(self)

    def me(self, level='readonly'):
        return {'role': self.role, 'name': self.name}

    def arg(self, k, default=None):
        return self.args.get(k, default)


def route(method, path, role, body=None, args=None):
    return E.ROUTES[(method, path)](Wire(role, body, args))


def setUpModule():
    T.setUpModule()


def tearDownModule():
    for a in list(T.Agent.ALL):
        a.stop()
    for w in list(T.Wire.ALL):
        w.stop()
    shutil.rmtree(T.TMP, ignore_errors=True)
    if PKI.get('d'):
        shutil.rmtree(PKI['d'], ignore_errors=True)


# ---- the policy's lines ---------------------------------------------------------------------------
class PolicyLines(unittest.TestCase):
    def test_lines_read_written_reported(self):
        m = AG
        h = 'ab' * 32
        text = ('allow file /srv/ssl owner=root:root mode=0644\nallow issuer sha256=%s\n'
                'allow names *.example.com www.example.net\nallow names api.example.org\n'
                'require key local\n' % h.upper())
        p = m.parse_policy(text)
        self.assertEqual(p['problems'], [])
        self.assertEqual(p['issuers'], [h])
        self.assertEqual(p['names'], ['*.example.com', 'www.example.net', 'api.example.org'])
        self.assertTrue(p['key_local'])
        self.assertEqual(m.policy_lines(p)[-3:], [
            'allow issuer sha256=' + h, 'allow names *.example.com www.example.net '
            'api.example.org', 'require key local'])
        # read back the same
        again = m.parse_policy('\n'.join(m.policy_lines(p)))
        self.assertEqual(m.policy_canon(again), m.policy_canon(p))
        rep = m.policy_report(p, 'x')
        self.assertEqual(rep['issuers'], [h])
        self.assertTrue(rep['key_local'])
        self.assertIn('deploy-guard', m.FEATURES)
        self.assertEqual(m.guard_words(p), '1 issuer, 3 names, own key')
        for bad in ('allow issuer', 'allow issuer sha256=12', 'allow issuer foo=%s' % h,
                    'allow names', 'allow names *.com', 'allow names a..b', 'require key',
                    'require key remote', 'require names local'):
            self.assertTrue(m.parse_policy(bad)['problems'], bad)
        # names without issuers: a warning of policy check
        got = m.policy_check('allow names www.example.com\n')
        self.assertFalse(got['errors'])
        self.assertEqual([w['code'] for w in got['warnings']], ['names-alone'])
        self.assertFalse(m.policy_check('allow names a.example.com\nallow issuer sha256=%s\n'
                                        % h)['warnings'])

    def test_old_policy_unchanged(self):
        """A policy without the lines: the hash, the report and the lines as before 1.0.140."""
        m = AG
        text = ('allow file /srv/ssl owner=root:nginx mode=0640\nallow unit nginx reload\n'
                'allow test -- /usr/sbin/nginx -t\nallow probe local\nlimit files 30\n')
        p = m.parse_policy(text)
        self.assertNotIn('issuers', p)
        self.assertNotIn('key_local', p)
        canon = json.loads(m.policy_canon(p))
        self.assertEqual(sorted(canon), ['connect', 'files', 'from', 'limits', 'probe_local',
                                         'script_hashes', 'scripts', 'self_update', 'tests',
                                         'units'])
        rep = m.policy_report(p, 'x')
        for k in ('issuers', 'names', 'key_local'):
            self.assertNotIn(k, rep)
        self.assertFalse(m.guard_on(p))
        self.assertEqual(m.guard_check(p, [('/x', b'whatever', '', None)]), '')
        self.assertFalse(DG.guard_of(G.clean_policy(rep)))
        self.assertNotIn('issuers', G.clean_policy(rep))

    def test_agent_cli(self):
        """acme-agent allow issuer CA.pem | sha256=, allow names (added to, taken from), require
        key local | any, policy show."""
        if not T.CAN:
            self.skipTest('needs root and openssl')
        k = make_pki()
        ag = T.Agent('f140cli')
        try:
            ag.policy('allow file %s owner=root:root mode=0644' % (ag.www + '/ssl'))
            got = ag.cli('allow', 'issuer', k['j']('root.crt'))
            self.assertIn('allowed: allow issuer sha256=%s' % fp(k['r']('root.crt')), got.stdout)
            ag.cli('allow', 'issuer', 'sha256=' + 'cd' * 32)
            ag.cli('allow', 'names', '*.example.test', 'www.example.net')
            got = ag.cli('allow', 'names', 'api.example.org', 'www.example.net')
            self.assertIn('allowed: names *.example.test www.example.net api.example.org',
                          got.stdout)
            ag.cli('deny', 'names', 'www.example.net')
            ag.cli('require', 'key', 'local')
            text = T.read(ag.d + '/etc/policy')
            self.assertIn('allow names *.example.test api.example.org\n', text)
            self.assertIn('require key local\n', text)
            self.assertEqual(text.count('allow issuer'), 2)
            show = ag.cli('policy', 'show', '--json').stdout
            rep = json.loads(show)
            self.assertEqual(rep['names'], ['*.example.test', 'api.example.org'])
            self.assertTrue(rep['key_local'])
            ag.cli('require', 'key', 'any')
            ag.cli('deny', 'issuer', 'sha256=' + 'cd' * 32)
            text = T.read(ag.d + '/etc/policy')
            self.assertNotIn('require key', text)
            self.assertEqual(text.count('allow issuer'), 1)
            bad = ag.cli('allow', 'names', '*.com', ok=False)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn('top-level', bad.stderr)
            self.assertEqual(ag.cli('require', 'key', 'maybe', ok=False).returncode != 0, True)
            # its audit log: each change of the policy
            self.assertIn('allow issuer sha256=', T.read(ag.d + '/rs/audit.log'))
        finally:
            ag.stop()

    def test_windows_words(self):
        """The Windows agent (its fake on Linux): the same lines, read and written."""
        script = r"""
import importlib.util, json, os, sys, tempfile
TMP = tempfile.mkdtemp(prefix='acme-f140w-')
os.environ.update(ACME_AGENT_FAKE_WINDOWS='1', ACME_AGENT_FAKE_ROOT=os.path.join(TMP, 'fake'))
os.makedirs(os.environ['ACME_AGENT_FAKE_ROOT'])
for k in ('ACME_AGENT_ETC', 'ACME_AGENT_STATE', 'ACME_AGENT_ROOT_STATE', 'ACME_AGENT_RUN'):
    os.environ.pop(k, None)
spec = importlib.util.spec_from_file_location('agw', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
p = m.parse_policy('allow store\nallow issuer sha256=' + 'ab' * 32 + '\nallow names www.example.test\nrequire key local\n')
crt = open(sys.argv[2]).read()
ok = m.guard_check(m.parse_policy('allow names *.example.test'), [('C:\\certs\\a.crt', crt.encode(), '', None)], top=TMP)
try:
    m.guard_check(m.parse_policy('allow names x.example.org'), [('C:\\certs\\a.crt', crt.encode(), '', None)], top=TMP)
    bad = ''
except m.Refused as e:
    bad = str(e)
print(json.dumps({'windows': m.WINDOWS, 'problems': p['problems'], 'lines': m.policy_lines(p),
                  'warn': [w['code'] for w in m.policy_check('allow names x.example.test')['warnings']],
                  'ok': ok, 'bad': bad}))
"""
        if not shutil.which('openssl'):
            self.skipTest('needs openssl')
        k = make_pki()
        got = subprocess.run([sys.executable, '-c', script, T.AGENT, k['j']('leaf.crt')],
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        out = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertTrue(out['windows'])
        self.assertIn('every name is one the policy allows', out['ok'])
        self.assertIn('(allow names)', out['bad'])
        self.assertIn('C:\\certs\\a.crt', out['bad'])
        self.assertEqual(out['problems'], [])
        self.assertEqual(out['lines'], ['allow store', 'allow issuer sha256=' + 'ab' * 32,
                                        'allow names www.example.test', 'require key local'])
        self.assertEqual(out['warn'], ['names-alone'])

    def test_k8s_words(self):
        """The Kubernetes agent: allow issuer and allow names; require key local refused (it
        makes no key)."""
        script = r"""
import importlib.util, json, os, sys
sys.path.insert(0, os.path.dirname(sys.argv[1]))
spec = importlib.util.spec_from_file_location('k8s', os.path.join(os.path.dirname(sys.argv[1]), 'k8s', 'acme_k8s_agent.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
kp = m.parse('allow secret web/tls\nallow issuer sha256=' + 'ab' * 32 + '\nallow names *.example.test\nrequire key local\n')
old = m.parse('allow secret web/tls\n')
print(json.dumps({'problems': kp['problems'], 'lines': m.lines(kp), 'pol': {k: m.as_agent(kp).get(k) for k in ('issuers', 'names')},
                  'old_canon': m.canon(old), 'new_canon': m.canon(kp)}))
"""
        got = subprocess.run([sys.executable, '-c', script, T.AGENT], capture_output=True,
                             text=True, timeout=120, env=dict(os.environ, ACME_AGENT_ETC='/nonexistent',
                                                              ACME_AGENT_STATE='/nonexistent'))
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        out = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertEqual(len(out['problems']), 1)
        self.assertIn('makes no key', out['problems'][0])
        self.assertIn('allow issuer sha256=' + 'ab' * 32, out['lines'])
        self.assertEqual(out['pol']['names'], ['*.example.test'])
        self.assertNotIn('issuers', out['old_canon'])          # its hash as before
        self.assertIn('issuers', out['new_canon'])


# ---- the agent's own check -------------------------------------------------------------------------
@unittest.skipUnless(shutil.which('openssl'), 'needs openssl')
class GuardCheck(unittest.TestCase):
    def setUp(self):
        self.k = make_pki()
        self.top = tempfile.mkdtemp(prefix='acme-f140-g-')

    def tearDown(self):
        shutil.rmtree(self.top, ignore_errors=True)

    def chk(self, pol_text, mats, pool=(), own=None):
        return AG.guard_check(AG.parse_policy(pol_text), mats, pool, own, top=self.top)

    def test_issuer(self):
        r = self.k['r']
        full = (r('leaf.crt') + r('int.crt')).encode()
        root, inter = fp(r('root.crt')), fp(r('int.crt'))
        # the root allowed, the job's chain without it: from the pool (what acme sends)
        self.assertIn('chains to a CA', self.chk('allow issuer sha256=%s' % root,
                                                 [('/x/a.crt', full, '', None)], [r('root.crt')]))
        with self.assertRaises(AG.Refused) as e:
            self.chk('allow issuer sha256=%s' % root, [('/x/a.crt', full, '', None)])
        self.assertIn('the job holds none of the CAs', str(e.exception))
        # the intermediate allowed
        self.chk('allow issuer sha256=%s' % inter, [('/x/a.crt', full, '', None)])
        # another CA, with the same name as the root: its signature does not hold
        with self.assertRaises(AG.Refused) as e:
            self.chk('allow issuer sha256=%s' % root, [('/x/e.crt', r('evil.crt').encode(), '',
                                                        None)], [r('eroot.crt'), r('root.crt'),
                                                                 r('int.crt')])
        self.assertIn('(allow issuer)', str(e.exception))
        self.assertIn('/x/e.crt', str(e.exception))
        # a chain that says the evil root is the allowed one's: only its fingerprint counts
        with self.assertRaises(AG.Refused):
            self.chk('allow issuer sha256=%s' % root, [('/x/e.crt', (r('evil.crt') +
                                                                     r('eroot.crt')).encode(),
                                                        '', None)])
        # the stage folder is left empty
        self.assertEqual([x for x in os.listdir(self.top)], [])

    def test_names(self):
        r = self.k['r']
        full = (r('leaf.crt') + r('int.crt')).encode()
        self.chk('allow names *.example.test', [('/x/a.crt', full, '', None)])
        self.chk('allow names www.example.test api.example.test', [('/x/a.crt', full, '', None)])
        with self.assertRaises(AG.Refused) as e:
            self.chk('allow names www.example.test', [('/x/a.crt', full, '', None)])
        self.assertIn('holds the name api.example.test', str(e.exception))
        self.assertTrue(AG.name_allowed(['*.example.test'], 'WWW.Example.Test.'))
        self.assertFalse(AG.name_allowed(['*.example.test'], 'example.test'))
        self.assertFalse(AG.name_allowed(['*.example.test'], 'a.b.example.test'))
        self.assertTrue(AG.name_allowed(['*.example.test'], '*.example.test'))
        self.assertFalse(AG.name_allowed(['www.example.test'], '*.example.test'))
        self.assertTrue(AG.name_allowed(['192.0.2.1'], '192.0.2.1'))

    def test_key_local(self):
        r = self.k['r']
        own = [AG.spki_fp(r('leaf.key'))]
        full = (r('leaf.crt') + r('int.crt')).encode()
        self.chk('require key local', [('/x/a.crt', full, '', None),
                                       ('/x/a.key', r('leaf.key').encode(), 'key-pem', None)],
                 own=own)
        with self.assertRaises(AG.Refused) as e:
            self.chk('require key local', [('/x/a.key', r('leaf.key').encode(), 'key-pem', None)],
                     own=[])
        self.assertIn('(require key local)', str(e.exception))
        with self.assertRaises(AG.Refused) as e:
            self.chk('require key local', [('/x/a.crt', full, '', None)], own=[])
        self.assertIn('not for a key this agent made', str(e.exception))

    def test_formats(self):
        r = self.k['r']
        inter = fp(r('int.crt'))
        p12 = open(self.k['j']('leaf.p12'), 'rb').read()
        self.chk('allow issuer sha256=%s' % inter, [('/x/a.pfx', p12, 'pfx', 'pw')])
        with self.assertRaises(AG.Refused) as e:
            self.chk('allow issuer sha256=%s' % inter, [('/x/a.pfx', p12, 'pfx', 'nope')])
        self.assertIn('a PKCS#12 it cannot open', str(e.exception))
        # its key is not the agent's: refused with require key local
        with self.assertRaises(AG.Refused):
            self.chk('require key local', [('/x/a.pfx', p12, 'pfx', 'pw')], own=[])
        der = ossl('x509', '-outform', 'DER', '-in', self.k['j']('leaf.crt'))
        self.chk('allow issuer sha256=%s' % inter, [('/x/a.der', der, 'der', None)],
                 [r('int.crt')])
        with self.assertRaises(AG.Refused) as e:
            self.chk('allow names www.example.test', [('/x/a.jks', b'\xfe\xed\xfe\xed', 'jks', None)])
        self.assertIn('a Java keystore', str(e.exception))
        # a key file alone (no certificate) with only issuer: nothing to judge, allowed
        self.chk('allow issuer sha256=%s' % inter, [('/x/a.key', r('leaf.key').encode(),
                                                     'key-pem', None)])


# ---- acme's side ------------------------------------------------------------------------------------
class AcmeSide(unittest.TestCase):
    def test_clean_policy_part(self):
        got = G.clean_policy({'issuers': ['AB' * 32, 'x', 7], 'names': ['*.example.com', 'bad name',
                                                                        5], 'key_local': True})
        self.assertEqual(got['issuers'], ['ab' * 32])
        self.assertEqual(got['names'], ['*.example.com'])
        self.assertTrue(got['key_local'])
        got = G.clean_policy({'key_local': 'yes'})
        self.assertNotIn('key_local', got)
        self.assertEqual(DG.summary({'issuers': ['ab' * 32], 'names': ['a.example', 'b.example'],
                                     'key_local': True})['words'], '1 issuer, 2 names, own key')
        self.assertIsNone(DG.summary({'files': []}))

    def test_check_and_needs(self):
        k = make_pki()
        r = k['r']

        class B(object):
            cert_pem = r('leaf.crt')
            chain_pems = [r('int.crt')]
            names = ['www.example.test', 'api.example.test']
        pol = {'issuers': [fp(r('int.crt'))], 'names': ['*.example.test'], 'key_local': True}
        probs = DG.check(STORE, pol, B(), True, 'web9')
        self.assertEqual(probs, [])
        probs = DG.check(STORE, pol, B(), False, 'web9')
        self.assertEqual(len(probs), 1)
        self.assertIn('not sent: the policy of the agent on web9 refuses it (require key local)',
                      probs[0])
        pol2 = {'names': ['www.example.test']}
        probs = DG.check(STORE, pol2, B(), False, 'web9')
        self.assertIn('(allow names)', probs[0])
        self.assertIn('api.example.test', probs[0])
        items = DG.needs_items(dict(pol, names=['www.example.test']), B(), False, STORE, 'web9')
        self.assertEqual([i['label'] for i in items], ['the issuer', 'the names', 'the key'])
        self.assertEqual([i['ok'] for i in items], [True, False, False])
        self.assertTrue(all(i['kind'] == 'guard' and i['allow'] == '' for i in items))

        # not issued yet: the names it asks for
        class Sample(object):
            cert_pem = ''
            chain_pems = []
            names = ['www.example.test', 'other.example.org']
        items = DG.needs_items({'names': ['*.example.test']}, Sample(), False, STORE, 'web9')
        self.assertFalse(items[0]['ok'])
        self.assertIn('other.example.org', items[0]['why'])
        self.assertEqual(DG.needs_items({'files': []}, B(), False, STORE, 'web9'), [])

    def test_loosened_is_widened(self):
        """A7: a guard line taken away, a CA or a name more - the policy widened."""
        from acmelib.certs import agent_guard as AGD
        was = {'issuers': ['ab' * 32], 'names': ['a.example.test'], 'key_local': True}
        self.assertEqual(DG.loosened(was, dict(was)), [])
        self.assertEqual(DG.loosened(None, {}), [])
        got = DG.loosened(was, {'issuers': ['ab' * 32, 'cd' * 32], 'names': []})
        self.assertEqual(len(got), 3)
        self.assertIn('a CA more', got[0])
        self.assertIn('any name', got[1])
        self.assertIn('require key local taken away', got[2])
        base = AGD._base_of({'policy': {'hash': 'h', 'issuers': ['ab' * 32]}})
        self.assertEqual(base['guard']['issuers'], ['ab' * 32])
        self.assertNotIn('guard', AGD._base_of({'policy': {'hash': 'h'}}))
        self.assertTrue(AGD._wider(base, {'hash': 'i'}))
        self.assertEqual(AGD._wider(AGD._base_of({'policy': {'hash': 'h'}}),
                                    {'hash': 'i', 'issuers': ['ab' * 32]}), [])

    def test_builder_state_and_design(self):
        st = P.clean_state({'issuers': ['ab' * 32], 'names': ['a.example.test'],
                            'key_local': True, 'files': []})
        self.assertEqual(st['issuers'], ['ab' * 32])
        with self.assertRaises(ValueError):
            P.clean_state({'key_local': 'yes'})
        m = G.agent_mod()
        lines = P._canon_lines(m, {'issuers': ['ab' * 32], 'names': ['a.example.test'],
                                   'key_local': True})
        self.assertEqual(lines, ['allow issuer sha256=' + 'ab' * 32,
                                 'allow names a.example.test', 'require key local'])
        c = P.compare('allow names a.example.test\n', {'hash': 'x', 'files': []}, m)
        self.assertEqual(c['state'], 'differs')
        self.assertEqual(c['added'], ['allow names a.example.test'])

    def test_fleet_template_holds_them(self):
        from acmelib.certs import fleet as FL
        text = ('allow file /srv/app/tls owner=root:app mode=0640\nallow issuer sha256=%s\n'
                'allow names *.example.test\nrequire key local\n' % ('ab' * 32))
        t = FL.template_save(STORE, {'title': 'f140 guarded', 'platform': 'linux', 'text': text},
                             'tester')
        self.assertIn('require key local', t['lines'])
        self.assertTrue(t['state'].get('key_local'))
        self.assertEqual(t['state'].get('names'), ['*.example.test'])
        self.assertIn('allow names *.example.test', FL.lines_of_state('linux', t['state']))
        FL.template_delete(STORE, t['ref'], 'tester')


# ---- the page's core (policybuilder.js), as node runs it ---------------------------------------------
@unittest.skipUnless(shutil.which('node'), 'needs node')
class BuilderCore(unittest.TestCase):
    def test_lines(self):
        js = r"""
const C = require(process.argv[1]);
C.setFacts({protected: [], parts: [], own: [], verbs: ['reload'], shells: [], config_ok: [], head: '# h\n',
  discover_kinds: [], limits: {files: 20, size: 1048576, files_most: 200, size_most: 67108864}});
const s = C.empty();
s.issuers = ['AB'.repeat(32), 'xyz'];
s.names = ['*.Example.test', 'www.example.net', '', '*.com'];
s.key_local = true;
const R = C.check(s);
const back = C.fromPolicy({issuers: ['ab'.repeat(32)], names: ['a.example'], key_local: true, files: [], units: {}, tests: [], scripts: [], script_hashes: [], from: [], connect: []});
const old = C.check(C.empty());
console.log(JSON.stringify({lines: R.lines, bad: R.counts.bad, warn: R.counts.warn, allow: C.allowLines(R),
  back: [back.issuers, back.names, back.key_local], oldLines: old.lines, oldKeys: Object.keys(C.empty()).sort()}));
"""
        got = subprocess.run(['node', '-e', js, os.path.join(T.ROOT, 'web', 'assets',
                                                             'policybuilder.js')],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr)
        out = json.loads(got.stdout)
        self.assertEqual(out['lines'], ['allow issuer sha256=' + 'ab' * 32,
                                        'allow names *.example.test www.example.net',
                                        'require key local'])
        self.assertEqual(out['bad'], 2)                      # xyz, *.com
        self.assertEqual(out['warn'], 0)
        self.assertIn('sudo acme-agent require key local', out['allow'])
        self.assertEqual(out['back'], [['ab' * 32], ['a.example'], True])
        self.assertEqual(out['oldLines'], [])
        self.assertNotIn('issuers', out['oldKeys'])
        # the same lines as the agent writes them
        p = AG.parse_policy('\n'.join(out['lines']))
        self.assertEqual(AG.policy_lines(p), out['lines'])


# ---- LIVE: a real agent ----------------------------------------------------------------------------
@unittest.skipUnless(T.CAN, 'needs root, setpriv and openssl')
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_account()
        cls.k = make_pki()
        cls.port = T.free_port()
        cls.row, cls.ag = T.join_passive(cls(), 'f140web', cls.port)
        cls.ca_fp = fp(T.read(os.path.join(T.TMP, 'ca.crt')))

    @classmethod
    def tearDownClass(cls):
        cls.ag.stop()

    def policy(self, *more):
        T.www_policy(self.ag, *more)
        G.hello(STORE, self.row)

    def deploy(self, bundle, **o):
        t, ctx = T.module(S.plugin_row(STORE, 'target', 'f140web'), 140)
        return t.deploy(bundle, T.opts(self.ag, **o)), ctx

    def raw(self, bundle, **o):
        """The job sent as acme would build it - acme's own check left out (as a stolen acme
        would): only the agent decides."""
        was = DG.check
        DG.check = lambda *a, **k: []
        try:
            return self.deploy(bundle, **o)
        finally:
            DG.check = was

    def files(self):
        out = {}
        for n in ('site.crt', 'site.key', 'site.pfx'):
            p = os.path.join(self.ag.www, 'ssl', n)
            out[n] = open(p, 'rb').read() if os.path.exists(p) else None
        return out

    def test_1_without_lines_as_before(self):
        self.policy()
        sent = []
        was = G.call

        def spy(store, r, op, args=None, *a, **kw):
            sent.append((op, dict(args or {})))
            return was(store, r, op, args, *a, **kw)
        G.call = spy
        try:
            said, ctx = self.deploy(T.Bundle('a'))
        finally:
            G.call = was
        self.assertIn('written', said)
        dep = [a for op, a in sent if op == 'deploy'][0]
        self.assertNotIn('guard', dep)
        self.assertFalse([s for s in ctx.steps if 'checks what it deploys' in str(s)])
        info = G.info(STORE, self.row)
        self.assertIn('deploy-guard', G.state(STORE, self.row['id'])['features'])
        self.assertFalse(DG.guard_of(info['policy']))

    def test_2_allowed_deployed(self):
        self.policy('allow issuer sha256=%s' % self.ca_fp, 'allow names www.example.test')
        info = G.info(STORE, self.row)
        self.assertEqual(info['policy']['issuers'], [self.ca_fp])
        sent = []
        was = G.call

        def spy(store, r, op, args=None, *a, **kw):
            sent.append((op, dict(args or {})))
            return was(store, r, op, args, *a, **kw)
        G.call = spy
        try:
            said, ctx = self.deploy(T.Bundle('b'))
        finally:
            G.call = was
        self.assertIn('3 files written', said)
        steps = ' '.join(str(s) for s in ctx.steps)
        self.assertIn('checked by the policy here (1 issuer, 1 name)', steps)
        self.assertIn('acme checked this certificate against it before sending', steps)
        dep = [a for op, a in sent if op == 'deploy'][0]
        self.assertIn('guard', dep)
        self.assertIn('pass_sealed', dep['guard'])        # the PFX (acme's key) looked into there
        self.assertNotIn('secret-pw', json.dumps(dep))
        self.assertEqual(self.files()['site.key'], T.Bundle('b').key_pem.encode())

    def test_3_wrong_issuer_refused(self):
        self.policy('allow issuer sha256=%s' % self.ca_fp)
        T.www_policy(self.ag, 'allow issuer sha256=%s' % self.ca_fp)
        r = self.k['r']

        class Evil(T.Bundle):
            def __init__(self):
                T.Bundle.__init__(self, 'a')
                self.cert_pem, self.key_pem = r('evil.crt'), r('evil.key')
                self.chain_pems = [r('eroot.crt')]
                self.fullchain_pem = self.cert_pem + r('eroot.crt')
                self.crt_file, self.key_file = self_k('evil.crt'), self_k('evil.key')
        self_k = self.k['j']
        before = self.files()
        # acme itself says no, before anything is sent
        with self.assertRaises(base.PluginError) as e:
            self.deploy(Evil())
        self.assertIn('not sent: the policy of the agent on f140web refuses it (allow issuer)',
                      str(e.exception))
        # sent all the same (a stolen acme): the agent refuses, writes nothing, notes it
        with self.assertRaises(base.PluginError) as e:
            self.raw(Evil())
        self.assertIn('refused by the policy of this machine (allow issuer): the certificate '
                      'www.example.test', str(e.exception))
        self.assertEqual(self.files(), before)
        audit = T.read(self.ag.d + '/rs/audit.log')
        self.assertIn('allow issuer', audit)

    def test_4_foreign_name_refused(self):
        T.www_policy(self.ag, 'allow issuer sha256=%s' % self.ca_fp, 'allow names web.example.test')
        G.hello(STORE, self.row)
        before = self.files()
        with self.assertRaises(base.PluginError) as e:
            self.deploy(T.Bundle('a'))
        self.assertIn('(allow names)', str(e.exception))
        with self.assertRaises(base.PluginError) as e:
            self.raw(T.Bundle('a'))
        self.assertIn('refused by the policy of this machine (allow names): the certificate '
                      'www.example.test', str(e.exception))
        self.assertIn('holds the name www.example.test', str(e.exception))
        self.assertEqual(self.files(), before)

    def test_5_acme_key_refused_own_key_deployed(self):
        T.www_policy(self.ag, 'require key local')
        G.hello(STORE, self.row)
        before = self.files()
        with self.assertRaises(base.PluginError) as e:
            self.deploy(T.Bundle('a'))
        self.assertIn('(require key local)', str(e.exception))
        with self.assertRaises(base.PluginError) as e:
            self.raw(T.Bundle('a'))
        self.assertIn('refused by the policy of this machine (require key local)',
                      str(e.exception))
        self.assertEqual(self.files(), before)
        # the key the agent made: deployed (its PFX built there with its own key)
        o = T.opts(self.ag)
        t, ctx = T.module(S.plugin_row(STORE, 'target', 'f140web'), 141)
        csr = t.device_csr(T.req_for(o))
        crt = T.sign_csr_test(csr)
        t, ctx = T.module(S.plugin_row(STORE, 'target', 'f140web'), 141)
        said = t.deploy(T.KeylessBundle(crt), o)
        self.assertIn('3 files written', said)
        self.assertEqual(T.spki(T.read(os.path.join(self.ag.www, 'ssl', 'site.key'))),
                         T.spki(crt))
        self.assertIn('every key is one this agent made', ' '.join(str(s) for s in ctx.steps))

    def test_6_old_agent_gets_no_guard_args(self):
        """An agent that does not say deploy-guard (an older one): nothing new is sent to it."""
        T.www_policy(self.ag, 'allow issuer sha256=%s' % self.ca_fp)
        G.hello(STORE, self.row)
        st = G.state(STORE, self.row['id'])
        st['features'] = ['audit-chain', 'cmdkey', 'enckey']
        G.state_put(STORE, self.row['id'], st)
        sent = []
        was = G.call

        def spy(store, r, op, args=None, *a, **kw):
            sent.append((op, dict(args or {})))
            if op == 'deploy':
                return {'ok': True, 'said': 'x', 'unchanged': True, 'files': []}
            return was(store, r, op, args, *a, **kw)
        G.call = spy
        try:
            self.deploy(T.Bundle('a'))
        finally:
            G.call = was
            G.hello(STORE, self.row)
        dep = [a for op, a in sent if op == 'deploy'][0]
        self.assertNotIn('guard', dep)

    def test_7_what_happens(self):
        """What happens (the run plan) of a deployment the guard refuses: said before it runs."""
        from acmelib.certs import ca as CA, runplan
        T.www_policy(self.ag, 'allow names web.example.test')
        G.hello(STORE, self.row)
        ca_id = CA.ca_create(STORE, 'F140 Plan Root', {'CN': 'F140 Plan Root'}, key_type='ec-256',
                             by='tester')
        STORE.db.insert('cert_issuers', {'name': 'own-f140', 'kind': 'internal_ca',
                                         'config': json.dumps({'ca': ca_id, 'days': 60}),
                                         'state': '{}', 'enabled': 1, 'created': time.time()})
        cid = A.cert_save(STORE, {'name': 'f140-plan', 'names': ['www.example.test'],
                                  'issuer': 'own-f140', 'key_type': 'ec-256'}, 'tester', full=True)
        cid = cid[0] if isinstance(cid, tuple) else cid
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'f140web', 'options': T.opts(self.ag)},
                      'tester')
        row = S.cert_get(STORE, cid)
        deps = STORE.db.rows('SELECT * FROM cert_deploys WHERE cert_id = ?', (cid,))
        plan = runplan.plan(STORE, row, deps, full=True)
        text = json.dumps(plan)
        self.assertIn('allow names', text)
        self.assertIn('www.example.test', text)
        # the needs card of its deployment
        t, ctx = T.module(S.plugin_row(STORE, 'target', 'f140web'), deps[0]['id'])
        from acmelib.certs import api_deploys
        b = api_deploys._bundle(row, {}, type(t))
        n = t.needs(b, T.opts(self.ag, outputs='fullchain-pem %s/ssl/p.crt 0644 root:%s\nkey-pem '
                                '%s/ssl/p.key 0640 root:%s' % (self.ag.www, T.USER, self.ag.www,
                                                               T.USER)))
        g = [i for i in n['items'] if i['kind'] == 'guard']
        self.assertEqual(len(g), 1)
        self.assertFalse(g[0]['ok'])
        # the CAs acme knows: its own authority there
        cas = DG.known_cas(STORE)
        self.assertTrue([c for c in cas if c['title'] == 'F140 Plan Root' and
                         c['kind'] == 'authority'])
        facts = P.builder(STORE, S.plugin_row(STORE, 'target', 'f140web'))['guard']
        self.assertIn('www.example.test', facts['names'])
        self.assertNotIn('pem', facts['cas'][0])
        # the command line: --agent-guard says the deployment and why
        out, rc = cli('--agent-guard', 'f140web')
        self.assertEqual(rc, 1)
        self.assertIn('f140-plan', out)
        self.assertIn('allow names web.example.test', out)
        T.www_policy(self.ag)
        G.hello(STORE, self.row)


# ---- B7: where keys are made ---------------------------------------------------------------------
def cli(*argv):
    from acmelib.certs import cli as C
    p = argparse.ArgumentParser()
    C.add_args(p)
    p.add_argument('--yes', action='store_true')
    p.add_argument('--json', action='store_true')
    a = p.parse_args(list(argv))
    c = C.Cli.__new__(C.Cli)
    c.E, c.args, c.store, c.json = E, a, STORE, bool(a.json)
    c.pal = E.Palette(False)
    c.files = {}
    c.WHO = 'command line'
    from acmelib.certs import api_agentkeys
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        try:
            rc = api_agentkeys.cli(c)
        except SystemExit as e:
            print(e)
            rc = 2
    return out.getvalue(), rc


class KeyPlace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from acmelib.certs import ca as CA
        cls.tgt = T.target('f140keys', mode='passive', host='127.0.0.1', port=T.free_port())
        G.state_put(STORE, cls.tgt['id'], {'agent_id': 'ag-00f1400000000001', 'cert_fp': 'a' * 64,
                                           'last_seen': time.time(), 'features': ['deploy-guard'],
                                           'policy': {'hash': 'b' * 64, 'files': [],
                                                      'key_local': True}})
        cls.other = T.target('f140other', mode='passive', host='127.0.0.1', port=T.free_port())
        ca_id = CA.ca_create(STORE, 'F140 Keys Root', {'CN': 'F140 Keys Root'}, key_type='ec-256',
                             by='tester')
        STORE.db.insert('cert_issuers', {'name': 'own-f140k', 'kind': 'internal_ca',
                                         'config': json.dumps({'ca': ca_id, 'days': 60}),
                                         'state': '{}', 'enabled': 1, 'created': time.time()})
        ids = {}
        for n, how in (('k-agent', 'agent'), ('k-acme', 'acme'), ('k-two', 'two'),
                       ('k-twin', 'twin'), ('k-acme2', 'acme')):
            b = {'name': n, 'names': ['%s.example.test' % n], 'issuer': 'own-f140k',
                 'key_type': 'ec-256'}
            if how == 'agent':
                b['csr_from'] = 'f140keys'
            if how == 'twin':
                b['key_type_alt'] = 'rsa-2048'
            cid = A.cert_save(STORE, b, 'tester', full=True)
            cid = cid[0] if isinstance(cid, tuple) else cid
            ids[n] = cid
            if how != 'agent':
                A.deploy_save(STORE, {'cert_id': cid, 'target': 'f140keys', 'options': {
                    'outputs': 'fullchain-pem /srv/x/%s.crt 0644\nkey-pem /srv/x/%s.key 0600'
                               % (n, n)}}, 'tester')
            if how == 'two':
                A.deploy_save(STORE, {'cert_id': cid, 'target': 'f140other', 'options': {
                    'outputs': 'fullchain-pem /srv/y/%s.crt 0644' % n}}, 'tester')
        cls.ids = ids

    def view(self, s=None):
        got = K.overview(STORE, s)
        return [t for t in got['targets'] if t['name'] == 'f140keys'][0]

    def test_1_overview(self):
        v = self.view()
        by = {c['name']: c for c in v['certs']}
        self.assertEqual(by['k-agent']['key'], 'agent')
        self.assertEqual(by['k-acme']['key'], 'acme')
        self.assertTrue(by['k-acme']['switchable'])
        self.assertFalse(by['k-two']['switchable'])
        self.assertIn('f140other', by['k-two']['why'])
        self.assertFalse(by['k-twin']['switchable'])
        self.assertIn('twin', by['k-twin']['why'])
        self.assertTrue(v['key_local'])
        self.assertTrue(by['k-acme']['refused'])           # require key local beside it
        self.assertEqual(v['counts']['agent'], 1)
        self.assertEqual(v['counts']['acme'], 4)
        self.assertEqual(v['counts']['switchable'], 2)
        tc = K.target_counts(STORE, self.tgt)
        self.assertEqual(sorted(tc['switch_ids']), sorted([self.ids['k-acme'], self.ids['k-acme2']]))
        # the route: a read-only session sees it; a session scoped to no team sees none of them
        got = route('GET', '/api/agents/keyplace', 'readonly')
        self.assertTrue([t for t in got['targets'] if t['name'] == 'f140keys'])

    def test_2_switch_next_then_sweep(self):
        cid = self.ids['k-acme2']
        # issued, 20 days left (its renewal in about 10 days with 30 renew days... after 60 below)
        STORE.db.run('UPDATE certs SET cert_pem = ?, not_after = ?, not_before = ?, state = ?, '
                     'auto_renew = 1, renew_days = 5 WHERE id = ?',
                     (T.read(T.CERTS['a'][0]), time.time() + 86400 * 20,
                      time.time() - 86400 * 60, 'ok', cid))
        got = K.switch(STORE, [cid, self.ids['k-two']], 'next', 'tester')
        self.assertEqual([x['name'] for x in got['done']], ['k-acme2'])
        self.assertEqual(got['refused'][0]['name'], 'k-two')
        self.assertTrue(K.pending(STORE, cid))
        self.assertFalse(S.cert_get(STORE, cid).get('csr_from'))      # nothing changed yet
        self.assertEqual(K.sweep(STORE), [])                          # not due yet
        self.assertTrue(K.pending(STORE, cid))
        v = self.view()
        self.assertTrue([c for c in v['certs'] if c['id'] == cid][0]['pending'])
        # a day before its renewal comes: switched
        self.assertEqual(K.sweep(STORE, now=time.time() + 86400 * 14.5), ['k-acme2'])
        row = S.cert_get(STORE, cid)
        self.assertEqual(row['csr_from'], 'f140keys')
        self.assertEqual(row['state'], 'due')
        self.assertFalse(K.pending(STORE, cid))

    def test_3_switch_now_cancel_permissions(self):
        cid = self.ids['k-acme']
        # a read-only session: the route refuses
        with self.assertRaises(E.ApiError):
            route('POST', '/api/agents/keyplace/switch', 'readonly', {'ids': [cid], 'when': 'now'})
        with self.assertRaises((E.ApiError, ValueError)):
            route('POST', '/api/agents/keyplace/switch', 'certadmin', {'ids': 'x'})
        # a session whose team holds no right on it: refused, said
        from acmelib.certs import teams
        was = teams.cert_may
        teams.cert_may = lambda store, s, row, right: right == 'view'
        try:
            got = K.switch(STORE, [cid], 'now', 'scoped', s={'role': 'certadmin', 'name': 'x'})
        finally:
            teams.cert_may = was
        self.assertEqual(got['done'], [])
        self.assertIn('may not change', got['refused'][0]['why'])
        # next, then taken back
        got = route('POST', '/api/agents/keyplace/switch', 'certadmin', {'ids': [cid],
                                                                          'when': 'next'})
        self.assertEqual(got['done'][0]['when'], 'next')
        got = route('POST', '/api/agents/keyplace/cancel', 'certadmin', {'ids': [cid]})
        self.assertEqual(got['cancelled'][0]['id'], cid)
        self.assertFalse(K.pending(STORE, cid))
        # now: switched at once, a renewal started
        started = []
        was = A.start_renew
        A.start_renew = lambda store, ref, force, by: started.append(ref) or 'job-f140'
        try:
            got = route('POST', '/api/agents/keyplace/switch', 'certadmin', {'ids': [cid],
                                                                              'when': 'now'})
        finally:
            A.start_renew = was
        self.assertEqual(got['done'][0]['job_id'], 'job-f140')
        self.assertEqual(started, [cid])
        self.assertEqual(S.cert_get(STORE, cid)['csr_from'], 'f140keys')

    def test_4_cli_and_console(self):
        out, rc = cli('--agent-keys', 'f140keys')
        self.assertEqual(rc, 0)
        self.assertIn('f140keys - the key made on the server', out)
        self.assertIn('k-two', out)
        out, rc = cli('--agent-keys', '--json')
        got = json.loads(out)
        self.assertTrue([t for t in got['targets'] if t['name'] == 'f140keys'])
        out, rc = cli('--agent-cas', '--json')
        self.assertTrue([c for c in json.loads(out) if c['title'] == 'F140 Keys Root'])
        out, rc = cli('--agent-keys-switch', 'k-twin', '--yes')
        self.assertEqual(rc, 1)
        self.assertIn('not switched', out)
        out, rc = cli('--agent-keys-cancel', 'k-acme', '--json')
        self.assertEqual(rc, 0)
        out, rc = cli('--agent-guard', 'f140keys')
        self.assertIn('own key', out)
        with open(os.path.join(T.ROOT, 'acmelib', 'certs', 'console.py')) as fh:
            src = fh.read()
        self.assertIn("lambda: agent_keys(con)", src)
        self.assertIn("con.act('--agent-keys-switch'", src)
        self.assertIn("con.act('--agent-guard', name)", src)
        self.assertIn("con.act('--agent-cas')", src)

    def test_5_deployguard_route(self):
        got = route('GET', '/api/agents/deployguard', 'readonly', args={'id': self.tgt['id']})
        self.assertEqual(got['guard']['words'], 'own key')
        self.assertEqual(got['lines'], ['require key local'])
        self.assertTrue(got['supported'])
        deps = {d['cert']: d for d in got['deployments']}
        self.assertFalse(deps['k-twin']['ok'])
        self.assertIn('(require key local)', deps['k-twin']['problems'][0])


class Pages(unittest.TestCase):
    def test_page(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        args = [node, os.path.join(HERE, 'f140_agentkey_page.js'), os.path.join(T.ROOT, 'web')]
        extra = os.environ.get('ACME_TEST_CS_EXTRA')
        args.append(extra if extra and os.path.exists(extra) else '')
        if os.environ.get('ACME_TEST_SHOTS'):
            args.append(os.environ['ACME_TEST_SHOTS'])
        got = subprocess.run(args, capture_output=True, text=True, timeout=900)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        bad = [k for k, v in (out.get('checks') or {}).items() if not v]
        self.assertTrue(out.get('ok'), json.dumps({'failed': bad, 'error': out.get('error'),
                                                   'errors': out.get('errors')})
                        + got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
