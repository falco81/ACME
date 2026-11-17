#!/usr/bin/env python3
"""The Windows deployment of acme-agent (1.0.120, docs/target-agent.md "Windows: the machine
store, IIS, Remote Desktop"): Part B.

    python3 test/test_agent_windows_deploy.py

The agent's side (deploy/agent/acme_agent_wincert.py, the hooks in acme_agent.py) with the
Windows facade faked (ACME_AGENT_FAKE_WINDOWS=1) and PowerShell faked (wincert.powershell - the
one place it runs): the certificate imported into the machine store from a PKCS#12 sealed to
the agent (its password sealed too, the PKCS#12 staged in root's stage folder and gone after),
IIS bindings made or changed, the Remote Desktop listener; the same certificate again changes
nothing; a failing test puts the bindings, the listener, the store and the files back; a binding
failing half way is undone; the certificates it imported before removed beyond keep (never one
it did not import); the key made by the agent imported (the PKCS#12 made by root); the policy's
allow store / iis / rdp - refused whole with the lines that allow it, before anything runs; a
Linux job as it was (no `win`: nothing of this loaded or asked).

acme's side (acmelib/plugins/targets/agent_windows.py): the Windows command lines read as the
agent's operations, the job built for a Windows server (files without owner or mode, the
store's PKCS#12 never written as a file, `win`), what the policy lacks, What happens, the
policy builder's Windows templates.
"""
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AGENT_DIR = os.path.join(ROOT, 'deploy', 'agent')
TMP = tempfile.mkdtemp(prefix='acme-winb-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "n1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
import acmelib.engine as E  # noqa: E402
from acmelib.certs import agents as G  # noqa: E402
from acmelib.plugins import base  # noqa: E402
from acmelib.plugins.targets import agent_windows as AW  # noqa: E402



def _have_win():
    try:
        with open(os.path.join(AGENT_DIR, 'acme_agent_win.py')) as fh:
            return '\ndef install(' in fh.read()
    except OSError:
        return False


HAVE_WIN = _have_win()
AID = 'ag-0123456789abcdef'
FAKE_ROOT = os.path.join(TMP, 'fakewin')         # C:\\x is FAKE_ROOT/C/x (acme_agent_win.FakeWin)


def openssl(*args, data=None, env=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True, check=True,
                          env=env).stdout


def load(name, windows):
    old = os.environ.get('ACME_AGENT_FAKE_WINDOWS')
    d = os.path.join(TMP, name)
    for k, sub in (('ACME_AGENT_ETC', 'etc'), ('ACME_AGENT_STATE', 'st'),
                   ('ACME_AGENT_ROOT_STATE', 'rs'), ('ACME_AGENT_RUN', 'run')):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
        os.environ[k] = os.path.join(d, sub)
    if windows and HAVE_WIN:
        os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
        os.environ['ACME_AGENT_FAKE_ROOT'] = FAKE_ROOT
    else:
        os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)
    try:
        spec = importlib.util.spec_from_file_location(name, os.path.join(AGENT_DIR,
                                                                         'acme_agent.py'))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        if old is None:
            os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)
        else:
            os.environ['ACME_AGENT_FAKE_WINDOWS'] = old
    if windows and not HAVE_WIN:
        m.WINDOWS = True                # acme_agent_win.py not there yet: the store part alone
    return m


AG = load('acme_agent_winb', True)
LX = load('acme_agent_winb_linux', False)
W = AG._wincert()
PRIV = bytes(range(1, 33))
ENC_PUB = base64.b64encode(E.x25519_public(PRIV)).decode()


def seal(label, data):
    return G.seal(ENC_PUB, AID, label, data)


# ---- certificates ---------------------------------------------------------------------------
CERTS = {}


def _certs():
    j = lambda n: os.path.join(TMP, n)  # noqa: E731
    openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', j('ca.key'), '-out', j('ca.crt'), '-days', '30', '-subj', '/CN=Test CA')
    with open(j('ext'), 'w') as fh:
        fh.write('subjectAltName=DNS:www.example.test\n')
    for leaf in ('a', 'b', 'c'):
        openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-keyout', j(leaf + '.key'), '-out', j(leaf + '.csr'), '-subj',
                '/CN=www.example.test')
        openssl('x509', '-req', '-in', j(leaf + '.csr'), '-CA', j('ca.crt'), '-CAkey',
                j('ca.key'), '-CAcreateserial', '-days', '10', '-out', j(leaf + '.crt'),
                '-extfile', j('ext'))
        with open(j(leaf + '.crt')) as fh:
            crt = fh.read()
        with open(j(leaf + '.key')) as fh:
            key = fh.read()
        CERTS[leaf] = {'crt': crt, 'key': key, 'crt_file': j(leaf + '.crt'),
                       'key_file': j(leaf + '.key'), 'thumb': W.thumb_of(crt)}
    with open(j('ca.crt')) as fh:
        CERTS['ca'] = fh.read()


def pfx_of(leaf, pw):
    c = CERTS[leaf]
    return openssl('pkcs12', '-export', '-inkey', c['key_file'], '-in', c['crt_file'],
                   '-passout', 'pass:' + pw, '-name', 'acme-test')


# ---- PowerShell, faked: a Windows server's store, IIS and listener in memory -------------------
class FakePS(object):
    SCRIPTS = None

    def __init__(self):
        self.store = {'F' * 40: {'friendly': 'not acme\'s', 'key': True}}
        self.sites = {'Default Web Site': {}}
        self.rdp = 'E' * 40
        self.calls = []
        self.fail = {}
        self.bind_fail_at = None

    def __call__(self, script, env, timeout=300):
        fixed = {W.PS_STATE: 'state', W.PS_IMPORT: 'import', W.PS_BIND: 'bind',
                 W.PS_UNBIND: 'unbind', W.PS_REMOVE: 'remove'}
        assert script in fixed, 'a script that is not one of the fixed ones'
        name = fixed[script]
        path = env['ACME_WIN_IN']
        stage = os.path.join(AG.ROOT_STATE, 'stage')
        assert os.path.dirname(path) == stage, path
        with open(path) as fh:
            j = json.load(fh)
        self.calls.append((name, j))
        out = []

        def say(o):
            out.append('ACME ' + json.dumps(o))
        if name in self.fail:
            return 1, 'ACME-ERROR %s' % self.fail[name]
        if name == 'state':
            iis = []
            for w in j['iis']:
                site = self.sites.get(w['site'])
                b = (site or {}).get((w['host'], w['port']))
                iis.append({'site': w['site'], 'host': w['host'], 'port': w['port'],
                            'ip': w['ip'], 'site_there': site is not None,
                            'binding': b is not None, 'thumb': (b or {}).get('thumb', '')})
            say({'present': j['thumb'] in self.store, 'iis': iis,
                 'rdp': self.rdp if j['rdp'] else ''})
        elif name == 'import':
            assert os.path.dirname(j['pfx']) == stage and os.path.exists(j['pfx'])
            had = j['thumb'] in self.store
            if not had:
                e = dict(os.environ, ACME_PFX_PASSWORD=env.get('ACME_PFX_PASSWORD', ''))
                try:
                    pem = openssl('pkcs12', '-in', j['pfx'], '-nokeys', '-passin',
                                  'env:ACME_PFX_PASSWORD', env=e).decode()
                    keys = openssl('pkcs12', '-in', j['pfx'], '-nocerts', '-nodes', '-passin',
                                   'env:ACME_PFX_PASSWORD', env=e).decode()
                except subprocess.CalledProcessError as x:
                    return 1, 'ACME-ERROR the PKCS#12 does not open: %s' % x.stderr[-100:]
                if W.thumb_of(pem) != j['thumb']:
                    return 1, 'ACME-ERROR the PKCS#12 holds another certificate'
                self.store[j['thumb']] = {'friendly': j['friendly'], 'key': 'PRIVATE KEY' in keys,
                                          'exportable': j['exportable']}
            say({'imported': not had, 'thumb': j['thumb']})
        elif name == 'bind':
            for n, w in enumerate(j['iis']):
                site = self.sites.get(w['site'])
                if site is None:
                    return 1, '\n'.join(out + ['ACME-ERROR there is no IIS site ' + w['site']])
                b = site.get((w['host'], w['port']))
                created = b is None
                if created:
                    b = site[(w['host'], w['port'])] = {'ip': w['ip'], 'thumb': ''}
                say({'step': 'iis', 'site': w['site'], 'host': w['host'], 'port': w['port'],
                     'ip': w['ip'], 'old': '' if created else b['thumb'], 'created': created})
                if self.bind_fail_at == n:
                    return 1, '\n'.join(out + ['ACME-ERROR A specified logon session does not '
                                               'exist'])
                b['thumb'] = j['thumb']
                say({'step': 'iis-done', 'site': w['site'], 'host': w['host'],
                     'port': w['port']})
            if j['rdp']:
                say({'step': 'rdp', 'old': self.rdp})
                self.rdp = j['thumb']
                say({'step': 'rdp-done'})
        elif name == 'unbind':
            for w in j['iis']:
                site = self.sites[w['site']]
                if w['created']:
                    site.pop((w['host'], w['port']), None)
                else:
                    site[(w['host'], w['port'])]['thumb'] = w['old']
                say({'step': 'iis', 'site': w['site']})
            if j['rdp_back']:
                self.rdp = j['rdp_old']
        elif name == 'remove':
            used = {b['thumb'] for s in self.sites.values() for b in s.values()} | {self.rdp}
            for t in j['thumbs']:
                if t not in self.store:
                    say({'thumb': t, 'was': 'gone'})
                elif t in used:
                    say({'thumb': t, 'was': 'inuse'})
                else:
                    del self.store[t]
                    say({'thumb': t, 'was': 'removed'})
        return 0, '\n'.join(out)

    def names(self):
        return [c[0] for c in self.calls]


class Root(object):
    def conf(self):
        return {'agent_id': AID}

    def enc_key(self):
        return PRIV


POLICY_ALL = 'allow store\nallow iis "Default Web Site"\nallow rdp\n'


def policy(text):
    pol = AG.parse_policy(text)
    if not HAVE_WIN:                    # the Windows entries are read by acme_agent_win.py
        for line in text.splitlines():
            if line == 'allow store':
                pol['store'] = True
            elif line == 'allow rdp':
                pol['rdp'] = True
            elif line.startswith('allow iis '):
                pol.setdefault('iis', []).append(line[10:].strip('"'))
        pol['problems'] = []
    return pol


def job(leaf='a', iis=True, rdp=True, keep=1, slot='dep-7', extra=None):
    pw = 'pw-' + leaf
    args = {'files': [{'path': '', 'format': 'p12-legacy',
                       'sealed': seal('win store', pfx_of(leaf, pw))}],
            'stale': [], 'pre': [], 'test': [], 'reload': [], 'post': [], 'script': None,
            'env': {}, 'backup': 'none', 'backup_keep': 0, 'skip_same': True, 'pending': False,
            'win': {'store': {'pfx_index': 0, 'password_sealed': seal('win store password',
                                                                     pw.encode()),
                              'cert_pem': CERTS[leaf]['crt'] + CERTS['ca'],
                              'friendly': 'acme-www.example.test-%s' % leaf,
                              'exportable': False, 'keep': keep, 'slot': slot},
                    'iis': [{'site': 'Default Web Site', 'host': 'www.example.test',
                             'port': 443, 'ip': '*'}] if iis else [],
                    'rdp': rdp}}
    args.update(extra or {})
    return args


class AgentSide(unittest.TestCase):
    def setUp(self):
        self.ps = FakePS()
        self._ps, W.powershell = W.powershell, self.ps
        self._pl = AG.policy_load
        self.pol_text = POLICY_ALL
        AG.policy_load = lambda: (policy(self.pol_text), 'h', self.pol_text)
        for fn in ('store.json',):
            p = os.path.join(AG.ROOT_STATE, fn)
            if os.path.exists(p):
                os.unlink(p)

    def tearDown(self):
        W.powershell = self._ps
        AG.policy_load = self._pl

    def deploy(self, args, fail_test=False):
        d = AG.Deploy(Root(), args, {})
        if fail_test:
            def run_op(op, env, what, warn=False):
                d.step('%s: failed' % what, 'bad')
                return False, 'exit 1'
            d.run_op = run_op
        return d.run()

    def stage_empty(self):
        st = os.path.join(AG.ROOT_STATE, 'stage')
        self.assertEqual(os.listdir(st) if os.path.isdir(st) else [], [])

    def test_1_import_bindings_rdp_then_the_same(self):
        got = self.deploy(job('a'))
        self.assertTrue(got['ok'], got)
        t = CERTS['a']['thumb']
        self.assertIn(t, self.ps.store)
        self.assertTrue(self.ps.store[t]['key'])
        self.assertFalse(self.ps.store[t]['exportable'])
        self.assertEqual(self.ps.store[t]['friendly'], 'acme-www.example.test-a')
        self.assertEqual(self.ps.sites['Default Web Site'][('www.example.test', 443)]['thumb'], t)
        self.assertEqual(self.ps.rdp, t)
        self.assertEqual(self.ps.names(), ['state', 'import', 'bind'])
        self.assertIn('IIS Default Web Site www.example.test:443', got['said'])
        self.assertIn('Remote Desktop', got['said'])
        words = '\n'.join(s[1] for s in got['steps'])
        self.assertIn('imported into the machine store', words)
        self.assertIn('a new https binding', words)
        self.assertIn('the Remote Desktop listener uses it (was EEEEEEEEEEEE…)', words)
        self.stage_empty()
        self.assertEqual([x['thumb'] for x in W.records_load(AG)['dep-7']], [t])
        # the same again: nothing imported, nothing bound
        self.ps.calls = []
        got = self.deploy(job('a'))
        self.assertTrue(got['ok'] and got.get('unchanged'), got)
        self.assertEqual(self.ps.names(), ['state'])

    def test_2_a_failing_test_puts_everything_back(self):
        site = self.ps.sites['Default Web Site']
        site[('www.example.test', 443)] = {'ip': '*', 'thumb': 'D' * 40}
        self.ps.store['D' * 40] = {'friendly': 'the one before', 'key': True}
        args = job('b', extra={'test': [{'argv': ['C:\\scripts\\probe.exe']}]})
        local = None
        if HAVE_WIN:
            self.pol_text = POLICY_ALL + 'allow test -- C:\\scripts\\probe.exe\n' \
                'allow file C:\\certs\n'
            # a file written beside the store: the one there before is back too
            local = os.path.join(FAKE_ROOT, 'C', 'certs', 'www.crt')
            os.makedirs(os.path.dirname(local), exist_ok=True)
            with open(local, 'w') as fh:
                fh.write('the one before\n')
            args['files'].insert(0, {'path': 'C:\\certs\\www.crt', 'format': 'fullchain-pem',
                                     'data': base64.b64encode(CERTS['b']['crt'].encode())
                                     .decode()})
            args['win']['store']['pfx_index'] = 1
        else:
            args['test'] = [{'argv': ['/bin/false']}]
            self.pol_text = POLICY_ALL + 'allow test -- /bin/false\n'
        got = self.deploy(args, fail_test=True)
        self.assertFalse(got['ok'], got)
        self.assertTrue(got.get('rolled_back'))
        self.assertEqual(site[('www.example.test', 443)]['thumb'], 'D' * 40)
        self.assertEqual(self.ps.rdp, 'E' * 40)
        self.assertNotIn(CERTS['b']['thumb'], self.ps.store)
        self.assertIn('D' * 40, self.ps.store)
        self.assertEqual(self.ps.names(), ['state', 'import', 'bind', 'unbind', 'remove'])
        words = '\n'.join(s[1] for s in got['steps'])
        if local:
            with open(local) as fh:
                self.assertEqual(fh.read(), 'the one before\n')
            self.assertIn('wrote C:\\certs\\www.crt', words)
            self.assertIn('the previous files are back', words)
        self.assertIn('the bindings are back as they were', words)
        self.assertIn('out of the machine store again', words)
        self.stage_empty()
        self.assertNotIn('dep-7', W.records_load(AG))

    def test_3_a_binding_failing_half_way(self):
        self.ps.sites['Intranet'] = {}
        self.pol_text = 'allow store\nallow iis *\n'
        args = job('c', rdp=False)
        args['win']['iis'].append({'site': 'Intranet', 'host': '', 'port': 8443, 'ip': '*'})
        self.ps.bind_fail_at = 1
        got = self.deploy(args)
        self.assertFalse(got['ok'], got)
        self.assertIn('A specified logon session does not exist', got['said'])
        self.assertEqual(self.ps.sites['Intranet'], {})          # the binding made: gone
        self.assertEqual(self.ps.sites['Default Web Site'], {})
        self.assertNotIn(CERTS['c']['thumb'], self.ps.store)
        unbind = [j for n, j in self.ps.calls if n == 'unbind'][0]
        self.assertEqual([b['site'] for b in unbind['iis']], ['Intranet', 'Default Web Site'])

    def test_4_keep_removes_only_its_own(self):
        self.assertTrue(self.deploy(job('a', iis=False, rdp=False, keep=0))['ok'])
        self.assertTrue(self.deploy(job('b', iis=False, rdp=False, keep=0))['ok'])
        self.assertNotIn(CERTS['a']['thumb'], self.ps.store)    # imported by it: removed
        self.assertIn(CERTS['b']['thumb'], self.ps.store)
        self.assertIn('F' * 40, self.ps.store)                  # never its own: never touched
        self.assertEqual([x['thumb'] for x in W.records_load(AG)['dep-7']],
                         [CERTS['b']['thumb']])
        # one still bound is kept
        self.ps.sites['Default Web Site'][('x', 443)] = {'ip': '*', 'thumb': CERTS['b']['thumb']}
        got = self.deploy(job('c', iis=False, rdp=False, keep=0))
        self.assertIn(CERTS['b']['thumb'], self.ps.store)
        self.assertIn('still bound: kept', '\n'.join(s[1] for s in got['steps']))
        self.assertEqual(len(W.records_load(AG)['dep-7']), 2)

    def test_5_policy_refused_whole_with_needs(self):
        self.pol_text = ''
        with self.assertRaises(AG.Refused) as cm:
            self.deploy(job('a'))
        allow = [n['allow'] for n in cm.exception.needs]
        self.assertEqual(allow, ['acme-agent allow store',
                                 'acme-agent allow iis "Default Web Site"',
                                 'acme-agent allow rdp'])
        self.assertEqual(self.ps.calls, [])
        self.pol_text = 'allow store\nallow iis Other\n'
        with self.assertRaises(AG.Refused) as cm:
            self.deploy(job('a', rdp=False))
        self.assertEqual([n['allow'] for n in cm.exception.needs],
                         ['acme-agent allow iis "Default Web Site"'])
        self.pol_text = 'allow store\nallow iis *\n'
        self.assertTrue(self.deploy(job('a', rdp=False))['ok'])
        # a shape refused: a binding without a store, a file without a path not the store's
        bad = job('a')
        bad['win']['store'] = None
        bad['files'] = []
        with self.assertRaises(AG.Refused):
            AG.plan_check(policy(POLICY_ALL), bad)
        bad = job('a')
        bad['win']['store']['pfx_index'] = None
        with self.assertRaises(AG.Refused):
            AG.plan_check(policy(POLICY_ALL), bad)

    def test_6_the_key_made_by_the_agent(self):
        slot = 'dep-9'
        pending, _cur = AG.key_paths(slot)
        with open(pending, 'w') as fh:
            fh.write(CERTS['a']['key'])
        args = job('a', iis=False, rdp=False, slot=slot)
        args['files'] = []
        args['win']['store'].update(pfx_index=None, password_sealed=None)
        args['agent_key'] = {'slot': slot, 'cert_pem': CERTS['a']['crt']}
        got = self.deploy(args)
        self.assertTrue(got['ok'], got)
        self.assertTrue(self.ps.store[CERTS['a']['thumb']]['key'])
        self.assertFalse(os.path.exists(pending))               # the key in use now
        self.stage_empty()
        # a certificate not of its key
        with open(pending, 'w') as fh:
            fh.write(CERTS['b']['key'])
        args = job('a', iis=False, rdp=False, slot=slot)
        args['files'] = []
        args['win']['store'].update(pfx_index=None)
        args['agent_key'] = {'slot': slot, 'cert_pem': CERTS['c']['crt']}
        args['win']['store']['cert_pem'] = CERTS['c']['crt']
        with self.assertRaises(AG.Refused):
            self.deploy(args)

    def test_7_the_check_changes_nothing(self):
        r = AG.Root.__new__(AG.Root)
        self.ps.sites = {}
        args = job('a')
        for k in ('sealed',):
            args['files'][0].pop(k)
        got = r.op_check(args, {}, {})
        self.assertFalse(got['ok'])
        said = {f['path']: f for f in got['files']}
        self.assertTrue(said['IIS Default Web Site www.example.test:443']['bad'])
        self.assertIn('is imported', said['the machine store (LocalMachine\\My)']['said'])
        self.assertEqual(self.ps.names(), ['state'])
        self.pol_text = ''
        got = r.op_check(job('a'), {}, {})
        self.assertTrue(got['refused'])
        self.assertIn('acme-agent allow store', [n['allow'] for n in got['needs']])

    def test_8_a_store_failing_puts_the_files_back(self):
        self.ps.fail['import'] = 'Access is denied'
        got = self.deploy(job('a'))
        self.assertFalse(got['ok'])
        self.assertIn('Access is denied', got['said'])
        self.assertEqual(self.ps.names(), ['state', 'import'])
        self.stage_empty()


class LinuxUnchanged(unittest.TestCase):
    def test_a_job_without_win(self):
        pol = LX.parse_policy('allow file /etc/ssl/acme\n')
        args = {'files': [{'path': '/etc/ssl/acme/a.pem', 'mode': 0o644}], 'test': [],
                'reload': [], 'pre': [], 'post': [], 'script': None}
        plan = LX.plan_check(pol, dict(args))
        self.assertNotIn('win', plan)
        self.assertEqual(sorted(plan), ['files', 'post', 'pre', 'reload', 'script', 'stale',
                                        'test'])
        self.assertEqual(LX.PLATFORM if hasattr(LX, 'PLATFORM') else 'linux', 'linux')

    def test_a_win_job_refused_on_linux(self):
        ps = FakePS()
        old, W.powershell = W.powershell, ps
        old_pl = LX.policy_load
        LX.policy_load = lambda: (policy(POLICY_ALL) if not HAVE_WIN else
                                  dict(LX.parse_policy(''), store=True, rdp=True,
                                       iis=['Default Web Site']), 'h', '')
        try:
            with self.assertRaises(LX.Refused) as cm:
                LX.Deploy(Root(), job('a'), {}).run()
            self.assertIn('does not run on Windows', str(cm.exception))
            self.assertEqual(ps.calls, [])
        finally:
            W.powershell = old
            LX.policy_load = old_pl


# ---- acme's side -------------------------------------------------------------------------------
class Ctx(object):
    target_name = 'win1'
    deploy_id = 12

    def __init__(self, policy=None):
        self.steps = []
        self.sealed = []
        self.kv = {}
        self._policy = policy

    def step(self, words, level='info'):
        self.steps.append((level, words))

    def debug(self, *_a):
        pass

    def agent_seal(self, label, data):
        self.sealed.append(label)
        return {'sealed': label}

    def agent_info(self):
        return {'state': 'answers', 'policy': self._policy, 'id': 3}

    def agent_plan_check(self, pol, part):
        part = dict(part)
        part.pop('platform', None)
        full = {'files': [], 'stale': [], 'pre': [], 'test': [], 'reload': [], 'post': [],
                'script': None}
        full.update(part)
        m = G.agent_mod_windows()
        p = m.parse_policy('')
        p.update({k: v for k, v in pol.items() if k in p or k in ('store', 'iis', 'rdp')})
        try:
            m.plan_check(p, full)
        except m.Refused as e:
            return e.needs or [{'kind': 'other', 'what': str(e), 'allow': ''}]
        return []

    def kv_get(self, k):
        return self.kv.get(k)

    def kv_set(self, k, v):
        self.kv[k] = v


class Bundle(base.Bundle):
    def __init__(self, leaf='a'):
        c = CERTS[leaf]
        self.cert_pem, self.key_pem = c['crt'], c['key']
        self.chain_pems = [CERTS['ca']]
        self.name = 'www.example.test'
        self.names = ['www.example.test']
        self.fingerprint = hashlib.sha256(c['crt'].encode()).hexdigest()
        self.not_before = time.time()
        self.not_after = time.time() + 86400 * 10
        self.serial = 'abcdef0123'
        self.key_type = 'ec-256'
        self.alt = None
        self.version = 1

    def as_format(self, fmt, password=None, alias=None):
        if fmt == 'fullchain-pem':
            return (self.cert_pem + CERTS['ca']).encode()
        if fmt == 'cert-pem':
            return self.cert_pem.encode()
        if fmt == 'key-pem':
            return self.key_pem.encode()
        if fmt in ('pfx', 'p12', 'p12-legacy'):
            return b'PFX:' + (password or '').encode()
        raise ValueError(fmt)


def target(ctx=None):
    t = AW.AgentWindowsTarget({'mode': 'passive', 'host': 'win1.example.test'}, ctx or Ctx())
    t.agent_key_of = lambda bundle: False
    t.unchanged = lambda *a, **k: False
    t.pending = lambda: False
    return t


class AcmeSide(unittest.TestCase):
    def test_cmd_ops_of_windows(self):
        self.assertEqual(AW.cmd_ops('Restart-Service W3SVC'), [{'unit': 'W3SVC',
                                                                'verb': 'restart'}])
        self.assertEqual(AW.cmd_ops('Restart-Service -Name W3SVC -Force'),
                         [{'unit': 'W3SVC', 'verb': 'restart'}])
        self.assertEqual(AW.cmd_ops('Restart-Service W3SVC,WAS'),
                         [{'unit': 'W3SVC', 'verb': 'restart'}, {'unit': 'WAS', 'verb': 'restart'}])
        self.assertEqual(AW.cmd_ops('Start-Service "MSSQL$SQLEXPRESS"'.replace('$', '_')),
                         [{'unit': 'MSSQL_SQLEXPRESS', 'verb': 'start'}])
        self.assertEqual(AW.cmd_ops('iisreset'), [{'argv': ['iisreset']}])
        self.assertEqual(AW.cmd_ops('C:/scripts/after.ps1 -Site "Default Web Site"'),
                         [{'script': 'C:\\scripts\\after.ps1', 'args': ['-Site',
                                                                       'Default Web Site']}])
        for bad, word in (('net stop W3SVC', 'Restart-Service W3SVC'),
                          ('iisreset | Out-Null', 'put the rest into such a script'),
                          ('Restart-Service W3SVC; iisreset', 'shell'),
                          ('powershell -File C:\\x.ps1', 'shell'),
                          ('C:\\x\\y.bat', 'PowerShell script'),
                          ('Restart-Service -Bogus W3SVC', 'not one the agent does'),
                          ('Get-Service $x', 'shell')):
            with self.assertRaises(base.PluginError) as cm:
                AW.cmd_ops(bad)
            self.assertIn(word, str(cm.exception), bad)
        self.assertEqual(AW.op_words({'unit': 'W3SVC', 'verb': 'restart'}),
                         'Restart-Service W3SVC')
        self.assertEqual(AW.allow_of({'unit': 'W3SVC', 'verb': 'restart'}),
                         'acme-agent allow service W3SVC restart')
        self.assertEqual(AW.allow_of({'script': 'C:\\Program Files\\x.ps1'}),
                         'acme-agent allow script "C:\\Program Files\\x.ps1"')

    def test_the_job_built(self):
        ctx = Ctx()
        t = target(ctx)
        opts = {'iis': 'Default Web Site | www.example.test | 443\nIntranet | | 8443 | 10.0.0.5',
                'rdp': True, 'outputs': 'fullchain-pem C:/certs/{name}.crt\nkey-pem '
                'C:/certs/{name}.key', 'reload_cmd': 'Restart-Service W3SVC', 'keep': 2,
                'exportable': False}
        b = Bundle('a')
        r = t.resolved(b, opts)
        args = t.plan(b, opts, r, t.render(b, r))
        paths = [f['path'] for f in args['files']]
        self.assertEqual(paths, ['C:\\certs\\www.example.test.crt',
                                 'C:\\certs\\www.example.test.key', ''])
        for f in args['files']:
            self.assertNotIn('owner', f)
            self.assertNotIn('mode', f)
        self.assertEqual(args['reload'], [{'unit': 'W3SVC', 'verb': 'restart'}])
        w = args['win']
        self.assertEqual(w['store']['pfx_index'], 2)
        self.assertEqual(W.thumb_of(w['store']['cert_pem']), CERTS['a']['thumb'])
        self.assertEqual(w['store']['keep'], 2)
        self.assertEqual(w['store']['slot'], 'dep-12')
        self.assertTrue(w['store']['legacy'])
        self.assertEqual(w['iis'], [
            {'site': 'Default Web Site', 'host': 'www.example.test', 'port': 443, 'ip': '*'},
            {'site': 'Intranet', 'host': '', 'port': 8443, 'ip': '10.0.0.5'}])
        self.assertTrue(w['rdp'])
        self.assertIn('win store', ctx.sealed)
        self.assertIn('win store password', ctx.sealed)
        self.assertIn('file C:\\certs\\www.example.test.key', ctx.sealed)
        # the agent reads it as it is (its own plan_check)
        pol = policy(POLICY_ALL + 'allow iis Intranet\n')
        a2 = json.loads(json.dumps(args))
        if not HAVE_WIN:                # Windows paths are read by acme_agent_win.py
            a2['files'] = a2['files'][2:]
            a2['win']['store']['pfx_index'] = 0
            a2['reload'] = []
        else:
            pol = policy(POLICY_ALL + 'allow iis Intranet\nallow file C:\\certs\n'
                         'allow service W3SVC restart\n')
        plan = AG.plan_check(pol, a2)
        self.assertEqual(len(a2['files']), len(plan['files']))
        self.assertEqual(plan['win']['store']['from'], 'stage')
        self.assertEqual(t.served_places(opts), [('127.0.0.1', 443), ('127.0.0.1', 8443)])
        self.assertEqual(t.served_places({'rdp': True}), [])
        # no store: the job puts none there; an owner on a Windows file refused
        args = t.plan(b, {'store': False, 'outputs': 'pfx C:/certs/a.pfx'},
                      t.resolved(b, {'store': False, 'outputs': 'pfx C:/certs/a.pfx'}), [b'x'])
        self.assertIsNone(args['win']['store'])
        with self.assertRaises(base.PluginError):
            t.resolved(b, {'outputs': 'pfx C:/certs/a.pfx 0600 root:root'})
        with self.assertRaises(base.PluginError):
            t.resolved(b, {'outputs': 'pfx /etc/ssl/a.pfx'})

    def test_needs_of_the_policy(self):
        t = target(Ctx({'files': [], 'units': {}, 'tests': [], 'scripts': [],
                        'script_hashes': [], 'store': True, 'iis': ['Default Web Site']}))
        got = t.needs(Bundle('a'), {'iis': 'Default Web Site | www.example.test\nShop | shop',
                                    'rdp': True, 'reload_cmd': 'Restart-Service W3SVC'})
        by = {(i['kind'], i['what'].split()[0]): i for i in got['items']}
        self.assertTrue(by[('store', 'Cert:\\LocalMachine\\My')]['ok'])
        self.assertTrue(by[('iis', 'Default')]['ok'])
        self.assertFalse(by[('iis', 'Shop')]['ok'])
        self.assertEqual(by[('iis', 'Shop')]['allow'], 'acme-agent allow iis Shop')
        self.assertFalse(by[('rdp', 'the')]['ok'])
        self.assertEqual(by[('rdp', 'the')]['allow'], 'acme-agent allow rdp')
        rl = [i for i in got['items'] if i['kind'] == 'reload'][0]
        self.assertFalse(rl['ok'])
        self.assertIn('allow service w3svc restart', rl['allow'].lower())
        self.assertIn('restart', rl['allow'])
        self.assertEqual(AW.win_needs({'iis': ['*']}, {'iis': [{'site': 'X'}]}), [])

    def test_what_happens_lines(self):
        from acmelib.certs import runplan
        ev = {'op': 'deploy', 'target': 'win1', 'mode': 'passive', 'host': 'w', 'port': 8446,
              'platform': 'windows', 'policy_known': True, 'items': [
                  {'what': 'store', 'exportable': False, 'keep': 1, 'agent_key': False,
                   'friendly': 'acme-x', 'ok': True, 'allow': ''},
                  {'what': 'iis', 'site': 'Default Web Site', 'host': 'www.example.test',
                   'port': 443, 'ip': '*', 'ok': False, 'allow': 'acme-agent allow iis '
                                                                 '"Default Web Site"'},
                  {'what': 'rdp', 'ok': True, 'allow': ''},
                  {'what': 'file', 'windows': True, 'path': 'C:\\certs\\a.crt',
                   'format': 'fullchain-pem', 'ok': True, 'allow': ''},
                  {'what': 'reload', 'op': {'unit': 'W3SVC', 'verb': 'restart'}, 'ok': True,
                   'allow': ''}]}
        steps = runplan._agent_steps(ev)
        words = [s['words'] for s in steps]
        self.assertIn('The agent imports the certificate into the machine store '
                      '(Cert:\\LocalMachine\\My)', words)
        self.assertIn('The agent binds it to the IIS site Default Web Site (https '
                      'www.example.test:443)', words)
        self.assertIn('The agent gives the Remote Desktop listener the certificate', words)
        self.assertIn('The agent writes C:\\certs\\a.crt', words)
        self.assertIn('The agent restarts Restart-Service W3SVC', words)
        iis = [s for s in steps if s['words'].startswith('The agent binds')][0]
        self.assertEqual(iis['policy'], {'ok': False, 'allow': 'acme-agent allow iis '
                                                               '"Default Web Site"',
                                         'windows': True})
        self.assertTrue(any(s.get('kind') == 'stop' for s in steps))

    def test_what_happens_order_password_format(self):
        """1.0.123: the steps in the agent's own order, the password of a PKCS#12/JKS and its
        alias, the store's PKCS#12 format, the password of the Central Certificate Store, and
        the files written again when Skip files that are the same is off."""
        from acmelib.certs import runplan
        ev = {'op': 'deploy', 'target': 'win1', 'mode': 'passive', 'host': 'w', 'port': 8446,
              'platform': 'windows', 'policy_known': True, 'skip_same': False,
              'meta': {'password': 'generate', 'alias': 'a1', 'pfx_format': 'p12-legacy',
                       'ccs_password': True},
              'items': [
                  {'what': 'role', 'role': 'ccs', 'o': {'ccs_path': 'D:\\c'}, 'ok': True,
                   'allow': ''},
                  {'what': 'post', 'op': {'argv': ['C:/x/post.exe']}, 'ok': True, 'allow': ''},
                  {'what': 'key_read', 'account': 'NT SERVICE\\X', 'ok': True, 'allow': ''},
                  {'what': 'reload', 'op': {'unit': 'W3SVC', 'verb': 'restart'}, 'ok': True,
                   'allow': ''},
                  {'what': 'store', 'exportable': False, 'keep': 1, 'agent_key': False,
                   'friendly': 'acme-x', 'ok': True, 'allow': ''},
                  {'what': 'file', 'windows': True, 'path': 'C:\\certs\\a.pfx',
                   'format': 'pfx', 'sealed': True, 'ok': True, 'allow': ''},
                  {'what': 'pre', 'op': {'argv': ['C:/x/pre.exe']}, 'ok': True, 'allow': ''}]}
        steps = runplan._agent_steps(ev)
        words = [s['words'] for s in steps if 'policy' in s]
        order = ['Before the files', 'The agent writes', 'The agent imports', 'The agent restarts',
                 'The agent gives', 'The agent sets the Windows role', 'After it']
        self.assertEqual([next(o for o in order if w.startswith(o)) for w in words], order)
        text = json.dumps(steps)
        self.assertIn('protected by a password acme made, kept sealed with the deployment', text)
        self.assertIn('legacy (3DES, SHA-1)', text)
        self.assertIn('the PFX files protected by the password of the store', text)
        self.assertIn('every file is written again even when it is the same', text)
        ev['skip_same'] = True
        ev['meta'] = {'password': 'fixed', 'alias': 'a1'}
        ev['items'] = [{'what': 'file', 'path': '/etc/a.jks', 'format': 'jks', 'mode': 384,
                        'ok': True, 'allow': ''}]
        ev['platform'] = 'linux'
        text = json.dumps(runplan._agent_steps(ev), ensure_ascii=False)
        self.assertIn('protected by the password of the deployment · its alias a1', text)
        self.assertIn('a file the same (SHA-256, owner, mode) is left alone', text)

    def test_what_happens_records_the_job(self):
        """The sandbox of What happens (plansandbox.PlanContext.agent_call) writes down the store,
        each binding, the listener and the files of a Windows job, each judged by the policy."""
        from acmelib.certs import plansandbox as PS
        pol = {'files': [], 'units': {}, 'tests': [], 'scripts': [], 'script_hashes': [],
               'store': True, 'iis': ['*']}
        ctx = PS.PlanContext({'target_name': 'win1', 'deploy_id': 12,
                              'agent': {'policy': pol, 'platform': 'windows', 'mode': 'active'}},
                             'target:win1', None)
        t = AW.AgentWindowsTarget({'mode': 'active'}, ctx)
        t.agent_key_of = lambda bundle: False
        t.unchanged = lambda *a, **k: False
        t.pending = lambda: False
        t._written = lambda options, paths=None: []
        opts = {'iis': 'Default Web Site | www.example.test', 'rdp': True,
                'outputs': 'fullchain-pem C:/certs/a.crt'}
        b = Bundle('a')
        r = t.resolved(b, opts)
        args = t.plan(b, opts, r, t.render(b, r))
        PS.RECORDING[0] = []
        try:
            ctx.agent_call('deploy', args)
            ev = [e for e in PS.RECORDING[0] if e.get('kind') == 'agent-job'][0]
        finally:
            PS.RECORDING[0] = None
        self.assertEqual(ev['platform'], 'windows')
        what = [(i['what'], i['ok']) for i in ev['items']]
        self.assertEqual(what[:3], [('store', True), ('iis', True), ('rdp', False)])
        self.assertEqual([i['path'] for i in ev['items'] if i['what'] == 'file'],
                         ['C:\\certs\\a.crt'])            # the store's PKCS#12 is no file
        rdp = [i for i in ev['items'] if i['what'] == 'rdp'][0]
        self.assertEqual(rdp['allow'], 'acme-agent allow rdp')

    def test_builder_templates_and_needs(self):
        from acmelib.certs import agent_policy as P
        tpl = {t['key']: t for t in P.templates_windows()}
        for key in ('iis', 'iis-all', 'rdp', 'store', 'folder', 'service'):
            self.assertIn(key, tpl)
            self.assertEqual(tpl[key]['platform'], 'windows')
        self.assertEqual(tpl['iis']['iis'], ['Default Web Site'])
        self.assertTrue(tpl['iis']['store'])
        self.assertTrue(tpl['rdp']['rdp'])
        self.assertEqual(tpl['folder']['files'], [{'dir': 'C:\\certs', 'readers': []}])
        self.assertEqual(tpl['service']['units'], {'myservice': ['restart']})
        # 1.0.120 parity: the agent does what windows_ssh does - Exchange and every role too
        self.assertEqual(tpl['exchange']['roles'], {'exchange': []})
        self.assertEqual(tpl['ccs']['roles'], {'ccs': ['\\\\fileserver\\ccs']})
        # what a deployment needs, as items of the builder
        items = []
        t = target()
        opts = {'iis': 'Default Web Site | www.example.test\nShop | shop', 'rdp': True,
                'outputs': 'fullchain-pem C:/certs/x/a.crt', 'reload_cmd': 'Restart-Service W3SVC'}
        b = Bundle('a')
        r = t.resolved(b, opts)
        P._win_needs(items, t, t.plan(b, opts, r, [b'' for _ in r['files']], sealed=False),
                     opts)
        kinds = [(i['kind'], i.get('site') or i.get('path') or i.get('unit') or '') for i in items]
        self.assertEqual(kinds, [('store', ''), ('iis', 'Default Web Site'), ('iis', 'Shop'),
                                 ('rdp', ''), ('file', 'C:\\certs\\x\\a.crt'),
                                 ('unit', 'W3SVC'), ('probe', '')])
        self.assertEqual(items[4]['dir'], 'C:\\certs\\x')
        self.assertEqual(items[5]['allow'], 'acme-agent allow service W3SVC restart')


# ---- the policy builder's core for a Windows agent (web/assets/policybuilder.js, node) ----------
BUILDER = os.path.join(ROOT, 'web', 'assets', 'policybuilder.js')
NODE = shutil.which('node')
BUILD_JS = r"""
const C = require(process.argv[1]);
const inp = JSON.parse(require('fs').readFileSync(0, 'utf8'));
C.setFacts(inp.facts);
console.log(JSON.stringify(inp.states.map(function (x) {
  var s = C.fromSaved(x.state || {});
  (x.templates || []).forEach(function (t) { C.addTemplate(s, t); });
  (x.needs || []).forEach(function (it) { C.addNeed(s, it); });
  var R = C.check(s), codes = [];
  ['files', 'units', 'tests', 'scripts', 'hashes', 'from', 'probe', 'connect', 'iis'].forEach(function (k) {
    R[k].forEach(function (v) { v.msgs.forEach(function (m) { codes.push([m.level, m.code, m.words]); }); }); });
  return {text: C.fileText(R), lines: R.lines, once: C.oneShot(R), allow: C.allowLines(R), codes: codes,
          covers: (x.covers || []).map(function (it) { return C.covers(s, R, it); })};
})));
"""


def win_facts():
    m = G.agent_mod_windows()
    f = dict(m.policy_facts())
    if f.get('platform') != 'windows':          # acme_agent_win.py not there yet
        f.update(platform='windows', verbs=['restart', 'try-restart', 'start'],
                 protected=['C:\\Windows', 'C:\\Program Files', 'C:\\Users\\*\\AppData'],
                 own=['C:\\ProgramData\\acme-agent'], parts=['.ssh'],
                 shells=['cmd', 'powershell', 'pwsh'], exec_ext=['.exe', '.ps1'],
                 head='# C:\\ProgramData\\acme-agent\\etc\\policy\n')
    return f


def builder_out(states):
    got = subprocess.run([NODE, '-e', BUILD_JS, BUILDER], input=json.dumps(
        {'facts': win_facts(), 'states': states}), capture_output=True, text=True, timeout=60,
        check=True)
    return json.loads(got.stdout)


@unittest.skipUnless(NODE, 'needs node')
class BuilderWindows(unittest.TestCase):
    def test_windows_policy_text(self):
        from acmelib.certs import agent_policy as P
        tpl = {t['key']: t for t in P.templates_windows()}
        got = builder_out([
            {'state': {'files': [{'dir': 'c:/certs/', 'readers': ['IIS_IUSRS', 'NT SERVICE\\W3SVC']},
                                 {'dir': 'C:\\Windows\\System32\\x', 'readers': []},
                                 {'dir': 'C:\\Users\\bob\\AppData\\x', 'readers': []},
                                 {'dir': '\\\\server\\share', 'readers': []},
                                 {'dir': 'C:\\a:stream', 'readers': []}],
                       'units': [{'name': 'W3SVC', 'verbs': ['restart', 'start']},
                                 {'name': 'bad name', 'verbs': ['restart']},
                                 {'name': 'X', 'verbs': ['reload']}],
                       'tests': [['iisreset', '/status'], ['C:\\x\\a.bat']],
                       'scripts': [{'path': 'C:\\scripts\\after.ps1', 'sha256': 'a' * 64},
                                   {'path': 'C:\\scripts\\pin.ps1', 'sha256': ''}],
                       'store': True, 'iis': ['Default Web Site', 'Shop'], 'rdp': True},
             'covers': [{'kind': 'store'}, {'kind': 'iis', 'site': 'default web site'},
                        {'kind': 'iis', 'site': 'Other'},
                        {'kind': 'file', 'path': 'C:\\certs\\www\\a.crt'},
                        {'kind': 'file', 'path': 'C:\\other\\a.crt'},
                        {'kind': 'file', 'path': 'C:\\certs\\x.ps1'},
                        {'kind': 'unit', 'unit': 'w3svc', 'verb': 'restart'}]},
            {'templates': [tpl['iis'], tpl['rdp'], tpl['service']],
             'needs': [{'kind': 'iis', 'site': 'Shop'},
                       {'kind': 'file', 'path': 'D:\\certs\\a.pem', 'dir': 'D:\\certs'}]}])
        one, two = got
        self.assertEqual(one['lines'], [
            'allow file C:\\certs readers="IIS_IUSRS,NT SERVICE\\W3SVC"',
            'allow service w3svc restart,start',
            'allow test -- iisreset /status',
            'allow script C:\\scripts\\after.ps1 sha256=' + 'a' * 64,
            'allow store', 'allow iis "Default Web Site"', 'allow iis Shop', 'allow rdp'])
        bad = [c for c in one['codes'] if c[0] == 'bad']
        self.assertEqual(len(bad), 7, bad)          # 4 folders, 2 services, the .bat
        self.assertTrue(one['once'].startswith("@'\n"))
        self.assertIn("\n'@ | acme-agent policy apply -\nacme-agent allow script "
                      "C:\\scripts\\pin.ps1", one['once'])
        self.assertIn('acme-agent allow file C:\\certs --readers "IIS_IUSRS,NT SERVICE\\W3SVC"',
                      one['allow'])
        self.assertIn('acme-agent allow iis "Default Web Site"', one['allow'])
        self.assertFalse(any(x.startswith('sudo') for x in one['allow']))
        self.assertEqual(one['covers'][:5], ['yes', 'yes', 'no', 'yes', 'no'])
        self.assertIn('runs or loads as a program', one['covers'][5])
        self.assertEqual(one['covers'][6], 'yes')
        self.assertEqual(two['lines'], [
            'allow file C:\\certs\\myservice readers="NT SERVICE\\myservice"',
            'allow file D:\\certs', 'allow service myservice restart', 'allow probe local',
            'allow store', 'allow iis "Default Web Site"', 'allow iis Shop', 'allow rdp'])
        if HAVE_WIN:
            # the agent reads the very file the builder writes, and writes it back the same
            m = G.agent_mod_windows()
            for x in got:
                chk = m.policy_check(x['text'])
                self.assertEqual([e for e in chk['errors']], [], x['text'])
                self.assertEqual(m.policy_lines(m.parse_policy(x['text'])), x['lines'])


if __name__ == '__main__':
    _certs()
    unittest.main(verbosity=2)
else:
    _certs()
