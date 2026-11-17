#!/usr/bin/env python3
"""A Microsoft CA (AD CS) through acme-agent (1.0.125, docs/ms-adcs-agent.md): the source
ms_adcs_agent, the Windows agent's op `adcs`, its policy (allow adcs, allow adcs-read).

    python3 test/test_ms_adcs_agent.py

The agent's side runs as on Windows with its facade faked (ACME_AGENT_FAKE_WINDOWS=1) and
PowerShell faked (wincert.powershell - the one place it runs): a CA in memory that issues
(signed by a test CA with openssl), holds a request for a certificate manager, denies. acme's
side is the source module with a Context whose agent_call hands the job to the agent's root
side (Root.op_adcs) and takes the answer as acme takes it (agents.clean_result).

Tried: issued; pending, then retrieved once approved; denied in words; a template and a CA the
policy does not allow (refused with the line that allows it, nothing asked of the CA); the
Linux agent refuses; a certificate for another key refused; the CAs and templates listed (form
and policy builder, adcs-read); the policy's lines (several templates, *, one line a CA, the
CLI allow / deny); What happens; no secret anywhere.
"""
import base64
import importlib.util
import io
import json
import os
import contextlib
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AGENT_DIR = os.path.join(ROOT, 'deploy', 'agent')
TMP = tempfile.mkdtemp(prefix='acme-adcsag-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "n1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib.certs import agents as G  # noqa: E402
from acmelib.plugins import base  # noqa: E402
from acmelib.plugins.base import CertRequest, PluginError  # noqa: E402
from acmelib.plugins.issuers import ms_adcs_agent as MA  # noqa: E402

FAKE_ROOT = os.path.join(TMP, 'fakewin')
CA = 'ca01.example.test\\Example Issuing CA'
CA2 = 'ca02.example.test\\Other CA'


def openssl(*args, data=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True,
                          check=True).stdout


def load(name, windows):
    d = os.path.join(TMP, name)
    for k, sub in (('ACME_AGENT_ETC', 'etc'), ('ACME_AGENT_STATE', 'st'),
                   ('ACME_AGENT_ROOT_STATE', 'rs'), ('ACME_AGENT_RUN', 'run')):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
        os.environ[k] = os.path.join(d, sub)
    if windows:
        os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
        os.environ['ACME_AGENT_FAKE_ROOT'] = FAKE_ROOT
    try:
        spec = importlib.util.spec_from_file_location(name, os.path.join(AGENT_DIR,
                                                                         'acme_agent.py'))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)
    return m


AG = load('acme_agent_adcs_win', True)
LX = load('acme_agent_adcs_linux', False)
W = AG._wincert()


def j(n):
    return os.path.join(TMP, n)


openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
        '-keyout', j('root.key'), '-out', j('root.crt'), '-days', '30', '-subj',
        '/CN=Example Root')
openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout',
        j('ica.key'), '-out', j('ica.csr'), '-subj', '/CN=Example Issuing CA')
with open(j('ca.ext'), 'w') as f:
    f.write('basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
openssl('x509', '-req', '-in', j('ica.csr'), '-CA', j('root.crt'), '-CAkey', j('root.key'),
        '-CAcreateserial', '-days', '20', '-out', j('ica.crt'), '-extfile', j('ca.ext'))


def der_of(pem_file):
    return openssl('x509', '-in', pem_file, '-outform', 'DER')


def sign(csr_pem):
    """The test CA's certificate for a CSR (DER)."""
    with open(j('req.csr'), 'w') as fh:
        fh.write(csr_pem)
    with open(j('leaf.ext'), 'w') as fh:
        fh.write('subjectAltName=DNS:www.example.test\n')
    openssl('x509', '-req', '-in', j('req.csr'), '-CA', j('ica.crt'), '-CAkey', j('ica.key'),
            '-CAcreateserial', '-days', '10', '-out', j('leaf.crt'), '-extfile', j('leaf.ext'))
    return der_of(j('leaf.crt'))


def p7_chain(leaf_der):
    from acmelib.plugins.issuers import _scep_pkcs7 as p7
    return p7.build_degenerate([leaf_der, der_of(j('ica.crt')), der_of(j('root.crt'))])


def new_req(names=('www.example.test',), extra_san=''):
    key = openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256').decode()
    with open(j('k.pem'), 'w') as fh:
        fh.write(key)
    san = ','.join('DNS:%s' % n for n in names) + extra_san
    csr = openssl('req', '-new', '-key', j('k.pem'), '-subj', '/CN=%s' % names[0], '-addext',
                  'subjectAltName=%s' % san).decode()
    csr_der = openssl('req', '-outform', 'DER', data=csr.encode())
    return CertRequest(names=list(names), sans=list(names), key_type='ec-256', key_pem=key,
                       csr_pem=csr, csr_der=csr_der, subject={}, profile={}, cert_id=7)


# ---- PowerShell, faked: a CA in memory ------------------------------------------------------------
class FakeCA(object):
    """ADCS_PS answered as the CA would: WebServer issues, Approve waits for a certificate
    manager, Denied is denied (the computer account may not enroll)."""
    def __init__(self):
        self.calls = []
        self.reqs = {}
        self.next_id = 100
        self.wrong_key = False
        self.templates = [('WebServer', 'Web Server'), ('Approve', 'Approve Me'),
                          ('Denied', 'Denied Template'), ('Other', 'Other')]

    def __call__(self, script, env, timeout=300):
        assert script == W.ADCS_PS, 'a script that is not the fixed one'
        path = env['ACME_WIN_IN']
        assert os.path.dirname(path) == os.path.join(AG.ROOT_STATE, 'stage'), path
        with open(path) as fh:
            v = json.load(fh)
        self.calls.append(v)
        act = v['action']
        out = {'action': act}
        if act == 'cas':
            out['cas'] = [{'config': CA, 'name': 'Example Issuing CA',
                           'server': 'ca01.example.test'},
                          {'config': CA2, 'name': 'Other CA', 'server': 'ca02.example.test'}]
        elif act == 'templates':
            out['templates'] = [{'name': n, 'display': d} for n, d in self.templates]
        elif act == 'submit':
            rid = self.next_id
            self.next_id += 1
            tpl = v['attrib'].split('\n')[0].split(':', 1)[1]
            self.reqs[rid] = {'csr': v['csr'], 'template': tpl, 'state': 'pending'
                              if tpl == 'Approve' else 'denied' if tpl == 'Denied' else 'issued'}
            out.update(self._answer(rid))
        elif act == 'retrieve':
            out.update(self._answer(int(v['req_id'])))
        return 0, 'something PowerShell said\nACME ' + json.dumps(out) + '\n'

    def _answer(self, rid):
        r = self.reqs.get(rid)
        if r is None:
            return {'error': 'The parameter is incorrect.', 'code': '0x80070057'}
        if r['state'] == 'pending':
            return {'disposition': 5, 'req_id': rid, 'status': '0x00000000',
                    'message': 'Taken Under Submission'}
        if r['state'] == 'denied':
            return {'disposition': 2, 'req_id': rid, 'status': '0x80094012',
                    'message': 'Denied by Policy Module'}
        csr = r['csr']
        if self.wrong_key:
            csr = new_req().csr_pem
        leaf = sign(csr)
        return {'disposition': 3, 'req_id': rid, 'status': '0x00000000',
                'message': 'Issued', 'cert': base64.b64encode(leaf).decode(),
                'chain': base64.b64encode(p7_chain(leaf)).decode()}


POLICY = 'allow adcs "%s" template=WebServer,Approve,Denied\n' % CA


class Ctx(base.Context):
    """acme's Context of a source, its agent_call handed to the agent's root side."""
    def __init__(self, agent_mod):
        self.mod = agent_mod
        self.steps, self.kv, self.jobs = [], {}, []
        self.node = 'test'
        self.settings = {}

    def step(self, words, level='info'):
        self.steps.append((level, words))

    def debug(self, words):
        pass

    def cancelled(self):
        return False

    def kv_get(self, key, default=None):
        return self.kv.get(key, default)

    def kv_keys(self, prefix=''):
        return {k: v for k, v in self.kv.items() if k.startswith(prefix)}

    def kv_set(self, key, value, ttl_s=None):
        if value is None:
            self.kv.pop(key, None)
        else:
            self.kv[key] = value

    def seal(self, text, bind):
        return 'sealed:' + base64.b64encode(text.encode()).decode()

    def unseal(self, value, bind):
        return base64.b64decode(value[7:]).decode()

    def agent_call(self, op, args=None, timeout=900, target=None):
        self.jobs.append((op, dict(args or {}), target))
        m = self.mod
        root = m.Root()
        try:
            out = getattr(root, 'op_' + op)(dict(args or {}), {}, {})
            out.setdefault('ok', True)
        except m.Refused as e:
            out = {'ok': False, 'said': str(e)[:600], 'needs': e.needs[:40], 'refused': True}
        return G.clean_result(json.loads(json.dumps(out)))


def source(ctx, **cfg):
    c = {'agent': 'win1', 'ca': CA, 'template': 'WebServer', 'key_kinds': 'any',
         'timeout': 60}
    c.update(cfg)
    return MA.MsAdcsAgentIssuer(c, ctx)


class Base(unittest.TestCase):
    def setUp(self):
        self.ca = FakeCA()
        self._ps, W.powershell = W.powershell, self.ca
        self.pol_text = POLICY
        self._pl = AG.policy_load
        AG.policy_load = lambda: (AG.parse_policy(self.pol_text), 'h', self.pol_text)
        self.ctx = Ctx(AG)

    def tearDown(self):
        W.powershell = self._ps
        AG.policy_load = self._pl
        st = os.path.join(AG.ROOT_STATE, 'stage')
        self.assertEqual(os.listdir(st) if os.path.isdir(st) else [], [],
                         'the stage folder keeps nothing')


class Issue(Base):
    def test_issued(self):
        req = new_req()
        got = source(self.ctx).issue(req)
        self.assertIn('BEGIN CERTIFICATE', got.cert_pem)
        self.assertEqual(len(got.chain_pems), 2)          # the intermediate, then the root
        self.assertEqual(got.info['req_id'], '100')
        sub = self.ca.calls[-1]
        self.assertEqual(sub['action'], 'submit')
        self.assertEqual(sub['ca'], CA)
        self.assertEqual(sub['attrib'], 'CertificateTemplate:WebServer')
        self.assertEqual(sub['csr'], req.csr_pem)
        self.assertEqual(set(sub), {'action', 'ca', 'csr', 'attrib'})
        self.assertEqual(self.ctx.jobs[0][0], 'adcs')
        self.assertEqual(self.ctx.jobs[0][2], 'win1')
        self.assertEqual(self.ctx.kv, {})
        words = ' '.join(w for _l, w in self.ctx.steps)
        self.assertIn('the certificate came: request 100', words)

    def test_san_attribute_of_the_csr_names(self):
        req = new_req(('www.example.test', 'api.example.test'))
        source(self.ctx, san_attr=True).issue(req)
        self.assertEqual(self.ca.calls[-1]['attrib'], 'CertificateTemplate:WebServer\n'
                         'SAN:dns=www.example.test&dns=api.example.test')

    def test_upn_in_csr_refused(self):
        req = new_req(extra_san=',otherName:1.3.6.1.4.1.311.20.2.3;UTF8:admin@example.test')
        with self.assertRaises(PluginError) as e:
            source(self.ctx).issue(req)
        self.assertIn('no Windows sign-in name', str(e.exception))
        self.assertEqual(self.ca.calls, [])

    def test_per_certificate_template(self):
        req = new_req()
        req.profile = {'template': 'Approve'}
        with self.assertRaises(PluginError):
            source(self.ctx).issue(req)
        self.assertEqual(self.ca.calls[-1]['attrib'], 'CertificateTemplate:Approve')

    def test_pending_then_retrieved(self):
        req = new_req()
        src = source(self.ctx, template='Approve')
        with self.assertRaises(PluginError) as e:
            src.issue(req)
        self.assertTrue(e.exception.retry)
        self.assertIn('holds the request 100 for a certificate manager', str(e.exception))
        slot = [k for k in self.ctx.kv if k.startswith('ms_adcs_agent-pending:')]
        self.assertEqual(len(slot), 1)
        # the next try, still waiting: no new request filed
        req2 = new_req()
        with self.assertRaises(PluginError):
            src.issue(req2)
        self.assertEqual([c['action'] for c in self.ca.calls], ['submit', 'retrieve'])
        self.assertEqual(self.ca.calls[-1]['req_id'], 100)
        # approved: the held request's certificate, with the held key
        self.ca.reqs[100]['state'] = 'issued'
        got = source(self.ctx, template='Approve').issue(new_req())
        self.assertEqual(got.info['req_id'], '100')
        self.assertEqual(got.key_pem, req.key_pem)
        self.assertEqual([k for k in self.ctx.kv if k.startswith('ms_adcs_agent-pending:')],
                         [])
        self.assertEqual(len(self.ca.reqs), 1)

    def test_denied(self):
        with self.assertRaises(PluginError) as e:
            source(self.ctx, template='Denied').issue(new_req())
        w = str(e.exception)
        self.assertFalse(e.exception.retry)
        self.assertIn('denied the request 100', w)
        self.assertIn('may not enroll for this template', w)
        self.assertIn('Denied by Policy Module', w)
        self.assertEqual(self.ctx.kv, {})

    def test_denied_after_pending_lets_go(self):
        src = source(self.ctx, template='Approve')
        with self.assertRaises(PluginError):
            src.issue(new_req())
        self.ca.reqs[100]['state'] = 'denied'
        with self.assertRaises(PluginError) as e:
            src.issue(new_req())
        self.assertIn('denied', str(e.exception))
        self.assertEqual(self.ctx.kv, {})

    def test_template_not_allowed(self):
        with self.assertRaises(PluginError) as e:
            source(self.ctx, template='Other').issue(new_req())
        w = str(e.exception)
        self.assertFalse(e.exception.retry)
        self.assertIn('not allowed by the policy of this machine', w)
        self.assertIn('acme-agent allow adcs "%s" template=WebServer,Approve,Denied,Other' % CA,
                      w)
        self.assertEqual(self.ca.calls, [])

    def test_ca_not_allowed(self):
        with self.assertRaises(PluginError) as e:
            source(self.ctx, ca=CA2).issue(new_req())
        self.assertIn('acme-agent allow adcs "%s" template=WebServer' % CA2, str(e.exception))
        self.assertEqual(self.ca.calls, [])

    def test_any_template(self):
        self.pol_text = 'allow adcs "%s" template=*\n' % CA
        got = source(self.ctx, template='Other').issue(new_req())
        self.assertIn('BEGIN CERTIFICATE', got.cert_pem)

    def test_nothing_allowed_no_line(self):
        self.pol_text = ''
        with self.assertRaises(PluginError) as e:
            source(self.ctx).issue(new_req())
        self.assertIn('allow adcs', str(e.exception))

    def test_key_mismatch_refused(self):
        self.ca.wrong_key = True
        with self.assertRaises(PluginError) as e:
            source(self.ctx).issue(new_req())
        self.assertIn('for another key', str(e.exception))
        self.assertFalse(e.exception.retry)

    def test_bad_values_never_reach_the_ca(self):
        for cfg in ({'ca': 'ca01\\x" -attrib "SAN:upn=admin'}, {'template': 'Web"Server'},
                    {'ca': '-config'}):
            with self.assertRaises(PluginError):
                source(self.ctx, **cfg).issue(new_req())
        # straight to the agent: refused there too
        for args in ({'action': 'submit', 'ca': 'x', 'template': 'WebServer', 'csr': 'x'},
                     {'action': 'submit', 'ca': CA, 'template': 'WebServer', 'csr': 'nope'},
                     {'action': 'retrieve', 'ca': CA, 'template': 'WebServer', 'req_id': '1 2'},
                     {'action': 'run', 'ca': CA}):
            got = self.ctx.agent_call('adcs', args)
            self.assertFalse(got['ok'], args)
        self.assertEqual(self.ca.calls, [])


class Linux(unittest.TestCase):
    def test_linux_agent_refuses(self):
        ctx = Ctx(LX)
        with self.assertRaises(PluginError) as e:
            source(ctx).issue(new_req())
        self.assertIn('only by acme-agent on Windows', str(e.exception))
        self.assertIn('adcs', LX.ROOT_OPS)
        pol = LX.parse_policy('allow adcs "%s" template=WebServer\n' % CA)
        self.assertTrue(pol['problems'])
        self.assertNotIn('adcs', pol)


class Lists(Base):
    def test_templates_marked(self):
        got = source(self.ctx).catalog('templates')
        opts = dict((o[0], o[1]) for o in got['options'])
        self.assertEqual(opts['WebServer'], 'WebServer (Web Server)')
        self.assertIn('not allowed by the agent\'s policy', opts['Other'])
        self.assertEqual(self.ca.calls[-1], {'action': 'templates', 'ca': CA})

    def test_cas_only_allowed_without_adcs_read(self):
        got = source(self.ctx).catalog('cas')
        self.assertEqual([o[0] for o in got['options']], [CA])
        self.pol_text = POLICY + 'allow adcs-read\n'
        got = source(self.ctx).catalog('cas')
        self.assertEqual([o[0] for o in got['options']], [CA, CA2])
        self.assertIn('not allowed', got['options'][1][1])

    def test_listing_needs_the_policy(self):
        self.pol_text = ''
        with self.assertRaises(PluginError) as e:
            source(self.ctx).catalog('cas')
        self.assertIn('acme-agent allow adcs-read', str(e.exception))
        with self.assertRaises(PluginError) as e:
            source(self.ctx, ca=CA2).catalog('templates')
        self.assertIn('acme-agent allow adcs-read', str(e.exception))
        self.pol_text = 'allow adcs-read\n'
        got = source(self.ctx, ca=CA2).catalog('templates')
        self.assertEqual(len(got['options']), 4)
        self.assertEqual(self.ca.calls[-1], {'action': 'templates', 'ca': CA2})

    def test_test_button(self):
        words = source(self.ctx).test()
        self.assertIn('4 templates', words)
        self.assertIn('WebServer is offered', words)
        with self.assertRaises(PluginError):
            source(self.ctx, template='Nope').test()

    def test_agent_cli(self):
        os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = AG.main(['adcs', 'cas', '--json'])
            self.assertEqual(rc, 0)
            got = json.loads(out.getvalue())
            self.assertEqual([c['config'] for c in got['cas']], [CA, CA2])
            self.assertEqual([t['name'] for t in got['cas'][0]['templates']],
                             ['WebServer', 'Approve', 'Denied', 'Other'])
            self.assertEqual(got['cas'][0]['allowed'], ['WebServer', 'Approve', 'Denied'])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = AG.main(['adcs', 'templates', '--config', CA])
            self.assertIn('WebServer', out.getvalue())
            self.assertIn('Web Server', out.getvalue())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                AG.main(['adcs', 'cas'])
            self.assertIn('acme-agent allow adcs "%s" template=' % CA, out.getvalue())
        finally:
            os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)
        with self.assertRaises(SystemExit):
            LX.main(['adcs', 'cas'])


class Policy(unittest.TestCase):
    def test_lines(self):
        pol = AG.parse_policy('allow adcs "%s" template=WebServer,WebServer2\n'
                              'allow adcs "%s" template=Extra,webserver\n'
                              'allow adcs \'%s\' template=*\n'
                              'allow adcs-read\n' % (CA, CA, CA2))
        self.assertEqual(pol['problems'], [])
        self.assertEqual(pol['adcs'], [{'ca': CA, 'templates': ['WebServer', 'WebServer2',
                                                                 'Extra']},
                                       {'ca': CA2, 'templates': ['*']}])
        self.assertTrue(pol['adcs_read'])
        lines = AG.policy_lines(pol)
        self.assertIn('allow adcs "%s" template=WebServer,WebServer2,Extra' % CA, lines)
        self.assertIn('allow adcs "%s" template=*' % CA2, lines)
        self.assertIn('allow adcs-read', lines)
        again = AG.parse_policy('\n'.join(lines))
        self.assertEqual(again['adcs'], pol['adcs'])
        self.assertNotEqual(AG.policy_canon(pol), AG.policy_canon(AG.parse_policy('')))
        rep = AG.policy_report(pol, 'h')
        self.assertEqual(G.clean_policy(rep)['adcs'], pol['adcs'])
        self.assertTrue(G.clean_policy(rep)['adcs_read'])

    def test_bad_lines(self):
        for line in ('allow adcs "%s"' % CA, 'allow adcs "%s" template=' % CA,
                     'allow adcs nobackslash template=X', 'allow adcs "%s" template=*,X' % CA,
                     'allow adcs "%s" template=a"b' % CA, 'allow adcs "%s" templates=X' % CA,
                     'allow adcs-read now'):
            pol = AG.parse_policy(line)
            self.assertTrue(pol['problems'], line)
            self.assertFalse(pol.get('adcs'), line)

    def test_cli_allow_deny(self):
        os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
        try:
            if os.path.exists(AG.POLICY):
                os.unlink(AG.POLICY)
            with contextlib.redirect_stdout(io.StringIO()):
                AG.main(['allow', 'adcs', CA, 'template=WebServer'])
                AG.main(['allow', 'adcs', CA, 'template=WebServer2,WebServer'])
                AG.main(['allow', 'adcs-read'])
            with open(AG.POLICY) as fh:
                text = fh.read()
            lines = [x for x in text.splitlines() if x.startswith('allow')]
            self.assertEqual(lines, ['allow adcs "%s" template=WebServer,WebServer2' % CA,
                                     'allow adcs-read'])
            with contextlib.redirect_stdout(io.StringIO()):
                AG.main(['deny', 'adcs', CA, 'template=WebServer'])
            with open(AG.POLICY) as fh:
                self.assertIn('allow adcs "%s" template=WebServer2\n' % CA, fh.read())
            with contextlib.redirect_stdout(io.StringIO()):
                AG.main(['deny', 'adcs', CA])
                AG.main(['deny', 'adcs-read'])
            with open(AG.POLICY) as fh:
                self.assertFalse([x for x in fh.read().splitlines()
                                  if x.startswith('allow adcs')])
        finally:
            os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)

    def test_needs_alike_on_both_sides(self):
        pol = AG.parse_policy(POLICY)
        wc = G.wincert_mod()
        self.assertEqual(wc.adcs_needs(pol, {'action': 'submit', 'ca': CA,
                                             'template': 'WebServer'}), [])
        n = wc.adcs_needs(pol, {'action': 'submit', 'ca': CA.upper(), 'template': 'webserver'})
        self.assertEqual(n, [])
        n = wc.adcs_needs(pol, {'action': 'submit', 'ca': CA, 'template': 'X'})
        self.assertEqual(n[0]['kind'], 'adcs')


class WhatHappens(unittest.TestCase):
    def run_plan(self, policy):
        from acmelib.certs import runplan as R
        from acmelib.plugins import base as B
        B.REGISTRY.reload()
        cls = B.REGISTRY.get('issuer', 'ms_adcs_agent')
        cfg = {'agent': 'win1', 'ca': CA, 'template': 'WebServer', 'key_kinds': 'any',
               'timeout': 120, 'san_attr': False}
        sec = R.Secrets()
        scfg, marks = sec.stand_ins(R._fields_of(cls), cfg)
        r = {'id': 'r1', 'family': 'issuer', 'kind': 'ms_adcs_agent', 'name': 'corp-ca',
             'seconds': 30, 'op': 'issue', 'config': scfg, 'marks': marks,
             'answers': R.answers_of('ms_adcs_agent', scfg, first=False, family='issuer'),
             'ssh_answers': [], 'names': ['www.example.test'], 'pinned': [],
             'agent': {'mode': 'passive', 'state': 'answers', 'host': 'win1.example.test',
                       'port': 8446, 'via': '', 'platform': 'windows',
                       'policy': G.clean_policy(AG.policy_report(AG.parse_policy(policy), 'h'))
                       if policy is not None else None}}
        got, err = R.record({'runs': [r], 'settings': {},
                             'cert': {'names': ['www.example.test'], 'key_type': 'ec-256'}},
                            timeout=120)
        self.assertEqual(err, '')
        run = got['r1']
        self.assertFalse(run.get('error'), run.get('error'))
        steps = R.steps_of(run['events'])
        return run['events'], steps

    def test_steps(self):
        evs, steps = self.run_plan(POLICY)
        words = [s.get('words') for s in steps]
        self.assertIn('Sends a signed job (adcs submit) to the agent of win1', words)
        cmd = [s for s in steps if str(s.get('words', '')).startswith('The agent runs certreq '
                                                                      '-submit')]
        self.assertEqual(len(cmd), 1, words)
        self.assertIn(CA, cmd[0]['words'])
        self.assertIn('WebServer', cmd[0]['words'])
        self.assertEqual(cmd[0]['policy']['ok'], True)
        pairs = dict((p[0], p[1]) for p in cmd[0]['detail']['pairs'])
        self.assertEqual(pairs['As'], 'certreq -submit -config "%s" -attrib '
                                      '"CertificateTemplate:WebServer" request.csr' % CA)
        self.assertIn('The agent\'s policy allows this CA and template', words)
        self.assertIn('the certificate came', json.dumps(evs))
        self.assertNotIn('PRIVATE KEY', json.dumps(evs) + json.dumps(steps))

    def test_steps_refused_by_policy(self):
        _evs, steps = self.run_plan('allow adcs "%s" template=Other\n' % CA)
        cmd = [s for s in steps if s.get('policy')][0]
        self.assertIs(cmd['policy']['ok'], False)
        self.assertEqual(cmd['policy']['allow'],
                         'acme-agent allow adcs "%s" template=Other,WebServer' % CA)
        _evs, steps = self.run_plan(None)
        self.assertTrue([s for s in steps if 'has not said its policy' in
                         str(s.get('words'))])


class NoSecrets(unittest.TestCase):
    def test_no_secret_fields(self):
        self.assertFalse([f for f in MA.MsAdcsAgentIssuer.fields
                          if f.get('type') in ('secret', 'pem', 'sshkey') or f.get('secret')])
        keys = {f['key'] for f in MA.MsAdcsAgentIssuer.fields}
        self.assertEqual(keys, {'agent', 'ca', 'template', 'key_kinds', 'san_attr', 'timeout'})

    def test_job_holds_no_key(self):
        ctx = Ctx(AG)
        ca = FakeCA()
        old, W.powershell = W.powershell, ca
        pl = AG.policy_load
        AG.policy_load = lambda: (AG.parse_policy(POLICY), 'h', POLICY)
        try:
            req = new_req()
            source(ctx).issue(req)
        finally:
            W.powershell = old
            AG.policy_load = pl
        sent = json.dumps(ctx.jobs) + json.dumps(ca.calls)
        self.assertNotIn('PRIVATE KEY', sent)
        self.assertNotIn(req.key_pem.strip().splitlines()[1], sent)


# ---- acme's side with a database: the API, the CLI, the policy builder, the form's choices ------
_STORE = []


def store():
    if not _STORE:
        import acmelib.engine as E
        from acmelib.certs import store as S
        st = E.Storage(E.open_db())
        E.sealing_key(make=True)
        S.registry()
        _STORE.append(st)
    return _STORE[0]


class FromAcme(unittest.TestCase):
    """The lists through acme (GET /api/agents/adcs, acme --target-agent NAME adcs-templates,
    the policy builder), the agent answered by the same faked Windows agent."""
    @classmethod
    def setUpClass(cls):
        from acmelib.certs import api as A, store as S
        st = store()
        cls.st = st
        if not S.plugin_row(st, 'target', 'win1'):
            A.family_save(st, 'target', {'name': 'win1', 'kind': 'agent_windows', 'config': {
                'mode': 'passive', 'host': 'win1.example.test'}, 'enabled': 1}, 'tester')
            A.family_save(st, 'target', {'name': 'lin1', 'kind': 'agent', 'config': {
                'mode': 'passive', 'host': 'lin1.example.test'}, 'enabled': 1}, 'tester')
            A.family_save(st, 'issuer', {'name': 'corp-ca', 'kind': 'ms_adcs_agent', 'config': {
                'agent': 'win1', 'ca': CA, 'template': 'WebServer'}, 'enabled': 1}, 'tester')

    def setUp(self):
        self.ca = FakeCA()
        self._ps, W.powershell = W.powershell, self.ca
        self.pol_text = POLICY + 'allow adcs-read\n'
        self._pl = AG.policy_load
        AG.policy_load = lambda: (AG.parse_policy(self.pol_text), 'h', self.pol_text)
        self._call = G.call
        ctx = Ctx(AG)
        G.call = lambda store_, row, op, args=None, timeout=900, step=None: \
            ctx.agent_call(op, args, timeout)

    def tearDown(self):
        W.powershell = self._ps
        AG.policy_load = self._pl
        G.call = self._call

    def test_api_route(self):
        from acmelib.certs import api_agents

        class H(object):
            store = self.st

            def __init__(self, q):
                self.q = q

            def arg(self, k):
                return self.q.get(k)
        got = api_agents._adcs(H({'target': 'win1'}), {})
        self.assertEqual([c['config'] for c in got['cas']], [CA, CA2])
        self.assertEqual([t['name'] for t in got['cas'][0]['templates']],
                         ['WebServer', 'Approve', 'Denied', 'Other'])
        self.assertTrue(got['cas'][0]['templates'][0]['allowed'])
        self.assertFalse(got['cas'][1]['templates'][0]['allowed'])
        self.assertEqual(got['cas'][0]['allowed'], ['WebServer', 'Approve', 'Denied'])
        got = api_agents._adcs(H({'target': 'win1', 'ca': CA2}), {})
        self.assertEqual(len(got['cas']), 1)
        with self.assertRaises(PluginError):
            api_agents._adcs(H({'target': 'lin1'}), {})
        self.pol_text = ''
        got = api_agents._adcs(H({'target': 'win1'}), {})
        self.assertEqual(got['cas'], [])
        self.assertEqual(got['needs'][0]['allow'], 'acme-agent allow adcs-read')

    def test_route_is_read_only_for_certificate_administrators(self):
        with open(os.path.join(ROOT, 'acmelib', 'certs', 'api_agents.py')) as fh:
            src = fh.read()
        self.assertIn("@A.api('GET', '/api/agents/adcs', 'certadmin')", src)

    def test_cli(self):
        from acmelib.certs import cli as C
        c = C.Cli.__new__(C.Cli) if hasattr(C, 'Cli') else None
        if c is None:
            self.skipTest('no Cli class')
        c.store = self.st
        c.json = True
        got = []
        c.out = lambda x: got.append(x)
        from acmelib.certs import agents as GG
        rc = c.target_agent_adcs(GG.target_row(self.st, 'win1'), [])
        self.assertEqual(rc, 0)
        self.assertEqual([x['config'] for x in got[0]['cas']], [CA, CA2])
        c.json = False
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            c.target_agent_adcs(GG.target_row(self.st, 'win1'), [])
        self.assertIn('-> acme-agent allow adcs "%s" template=WebServer,Approve,Denied,Other' % CA,
                      out.getvalue())

    def test_builder(self):
        from acmelib.certs import agent_policy as P, agents as GG
        row = GG.target_row(self.st, 'win1')
        b = P.builder(self.st, row)
        tpl = [t for t in b['templates'] if t['key'] == 'adcs']
        self.assertEqual(len(tpl), 1)
        self.assertEqual(tpl[0]['adcs'][0]['templates'], ['WebServer'])
        src = [n for n in b['needs'] if n.get('source') == 'corp-ca']
        self.assertEqual(src[0]['items'], [{'kind': 'adcs', 'ca': CA, 'template': 'WebServer',
                                            'allow': 'acme-agent allow adcs "%s" '
                                                     'template=WebServer' % CA}])
        self.assertEqual(P.clean_state({'adcs': [{'ca': CA, 'templates': ['*']}],
                                        'adcs_read': True})['adcs_read'], True)
        lin = P.builder(self.st, GG.target_row(self.st, 'lin1'))
        self.assertFalse([t for t in lin['templates'] if t['key'] == 'adcs'])

    def test_form_choices(self):
        from acmelib.certs import api as A
        self.assertEqual(A.options_for(self.st, 'agent_windows_targets'), [['win1', 'win1']])

    def test_builder_core_as_the_agent(self):
        """The builder's own check (node) writes the lines the agent writes."""
        import shutil as sh
        if not sh.which('node'):
            self.skipTest('no node')
        text = ('allow adcs "%s" template=WebServer,Two\nallow adcs "%s" template=webserver,X\n'
                'allow adcs "%s" template=*\nallow adcs-read\n' % (CA, CA, CA2))
        want = AG.policy_lines(AG.parse_policy(text))
        js = ("var C = require(%s); C.setFacts({platform: 'windows', roles: [], verbs: "
              "['restart'], limits: {files: 20, size: 1048576, files_most: 200, size_most: "
              "67108864}}); var s = C.empty(); s.adcs = %s; s.adcs_read = true; "
              "console.log(JSON.stringify(C.check(s).lines));") % (
            json.dumps(os.path.join(ROOT, 'web', 'assets', 'policybuilder.js')),
            json.dumps([{'ca': CA, 'templates': ['WebServer', 'Two']},
                        {'ca': CA, 'templates': ['webserver', 'X']},
                        {'ca': CA2, 'templates': ['*']}]))
        got = json.loads(subprocess.run(['node', '-e', js], capture_output=True, check=True,
                                        text=True).stdout)
        self.assertEqual(got, want)


if __name__ == '__main__':
    unittest.main()
