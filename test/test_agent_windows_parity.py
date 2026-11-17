#!/usr/bin/env python3
"""The Windows agent does what the OpenSSH target does (1.0.120, docs/target-agent.md "Windows:
what the OpenSSH target does, the agent does").

    python3 test/test_agent_windows_parity.py

* the parity table (PARITY, below) as data, checked against windows_ssh's own fields: every
  deploy field of windows_ssh has its counterpart in agent_windows (or a reason), every
  behaviour its place;
* one logic: the role scripts are _win_roles' templates rendered twice - windows_ssh's text
  is what it was before the templates (test/win_roles_before.json, but for the fixes found
  against Microsoft's documentation, each named here), the agent's copy
  (deploy/agent/acme_agent_winroles.py) is what tools/gen_agent_winroles.py makes, and the
  agent's script with a job's values put in is windows_ssh's text, line by line;
* each role through the agent (PowerShell faked): refused by the policy with the line that
  allows it, then allowed - the JSON the script gets, a password only in the environment; a
  role failing is said, the others run, the deployment fails, the old certificates are kept;
* the policy entries (allow role, allow key-read) - Windows only: a Linux policy's hash is
  as it was; What happens says the roles.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_agent_windows_deploy as D  # noqa: E402  (its fake Windows, certificates, agent)
from test_agent_windows_deploy import AG, LX, W, CERTS  # noqa: E402

ROOT = D.ROOT
from acmelib.plugins.targets import _win_roles as WR  # noqa: E402
from acmelib.plugins.targets import windows_ssh as WS  # noqa: E402
from acmelib.plugins.targets import agent_windows as AW  # noqa: E402
import win_roles_matrix as MX  # noqa: E402

GEN = os.path.join(ROOT, 'tools', 'gen_agent_winroles.py')

# ---- the parity table -------------------------------------------------------------------------
# (windows_ssh, agent_windows, how the agent does it - the policy entry, a difference and why)
PARITY = [
    ('iis', 'iis', 'allow iis SITE', 'SNI by host name, IP, port; a missing https binding made'),
    ('rdp', 'rdp', 'allow rdp', 'Win32_TSGeneralSetting; NETWORK SERVICE (S-1-5-20) read on the '
                                'key - _win_roles.RDP_KEY_READ, the same lines'),
    ('exchange', 'exchange', 'allow role exchange', 'run as the Exchange role with those '
                                                   'services (after the restarts)'),
    ('pfx_format', 'pfx_format', 'allow store', '3DES or AES-256 PKCS#12 into the store'),
    ('exportable', 'exportable', 'allow store', 'Import-PfxCertificate -Exportable'),
    ('post_ps', 'post_ps', 'allow script-hash HASH', 'after the import and the bindings, with '
                                                     '$thumb, $store, $cert'),
    ('keep', 'keep', 'allow store', 'only certificates this agent imported (store.json) are '
                                    'removed - never one of another tool; never one still used '
                                    '(_win_roles.USED, the same lines)'),
    ('outputs', 'outputs', 'allow file C:\\FOLDER', 'any format; {name} {cn} {service} {date}'),
    ('pfx_password_mode', 'pfx_password_mode', '-', 'the password of the files'),
    ('pfx_password', 'pfx_password', '-', 'sealed to the agent'),
    ('jks_alias', 'jks_alias', '-', ''),
    ('service', 'service', '-', '{service}, ACME_SERVICE'),
    ('skip_same', 'skip_same', '-', 'by SHA-256 (the agent compares)'),
    ('backup', 'backup', '-', ''),
    ('backup_format', 'backup_format', '-', ''),
    ('backup_keep', 'backup_keep', '-', ''),
    ('script_mode', 'script_mode', 'allow script-hash / allow script PATH',
     'uploaded (written here) or one on the server'),
    ('script_path', 'script_path', 'allow script C:\\x.ps1', 'pinned by SHA-256'),
    ('script_args', 'script_args', '-', ''),
    ('script_interp', 'script_interp', '-', 'powershell'),
    ('script_body', 'script_body', 'allow script-hash HASH', ''),
    ('key_read', 'key_read', 'allow key-read ACCOUNT', 'before the roles; failing stops them'),
    ('verify', 'verify', 'allow probe local', 'through the agent'),
    ('verify_sni', 'verify_sni', '-', ''),
] + [('role_' + k, 'role_' + k, 'allow role %s%s' % (k, {'ccs': ' path=FOLDER',
                                                          'wac': ' [msi=FILE]'}.get(k, '')),
      'the same PowerShell, its own fields: values in $o') for k, _l, _t, _n in WR.ROLES]
# behaviours that are no field
BEHAVIOURS = [
    ('the import into LocalMachine\\My, friendly name acme-<name>-<date>-<serial>',
     'win.store.friendly = object_name()'),
    ('Test the connection lists the roles of the server', 'check with win.detect - '
     '_win_roles.DETECT, the same lines'),
    ('the test of a deployment: are the roles installed, their PowerShell shown',
     'dry_run: check (a role not installed: bad) + roles_scripts()'),
    ('What happens (preview): the roles\' script and problems', 'preview(): got["roles"]'),
    ('LDAPS checked on 636 after', 'served_places(): 127.0.0.1:636 (allow probe local)'),
    ('a role failing: said, the others run, the deployment fails, old certificates kept',
     'WinJob.run_roles()'),
    ('read on the key failing stops the roles', 'WinJob.run_roles()'),
]
# the fields of the target itself (not of a deployment): ssh's sign-in has no counterpart -
# the agent joins acme instead (that is the point of it)
TARGET_ONLY = {'user': 'no sign-in: the agent joined acme', 'auth': 'no sign-in',
               'key': 'no sign-in', 'password': 'no sign-in',
               'hostkey': 'the agent\'s own key, pinned at the join (its fingerprint)',
               'trust_first': 'the join code / the fingerprint confirmed in acme',
               'tmp_dir': 'root\'s stage folder of the agent (C:\\ProgramData\\acme-agent\\'
                          'root\\stage), never a shared temporary folder'}


def _ssh_target_fields():
    return [f['key'] for f in WS.WindowsSshTarget.fields]


class ParityTable(unittest.TestCase):
    def test_every_deploy_field_has_its_counterpart(self):
        ssh = [f['key'] for f in WS.WindowsSshTarget.deploy_fields]
        agent = {f['key']: f for f in AW.AgentWindowsTarget.deploy_fields}
        rows = {r[0]: r for r in PARITY}
        roles_own = {f['key'] for f in WR.role_fields() if f.get('show_if')}
        for k in ssh:
            if k in roles_own:
                role = [x for x in agent[k]['show_if'] if x.startswith('role_')][0]
                self.assertIn(role, rows, k)
                continue
            self.assertIn(k, rows, '%s of windows_ssh is not in the parity table' % k)
            self.assertIn(rows[k][1], agent, '%s has no field in agent_windows' % k)
        # the same fields: the same type, the same default, the same choices
        for k in ssh:
            f = [x for x in WS.WindowsSshTarget.deploy_fields if x['key'] == k][0]
            g = agent[k]
            self.assertEqual((f['type'], f.get('default'), f.get('options'), f.get('show_if')),
                             (g['type'], g.get('default'), g.get('options'), g.get('show_if')),
                             k)
        for r in PARITY:
            self.assertTrue(r[2], r)

    def test_target_fields(self):
        agent = {f['key'] for f in AW.AgentWindowsTarget.fields}
        for k in _ssh_target_fields():
            self.assertTrue(k in agent or k in TARGET_ONLY,
                            '%s of windows_ssh: no counterpart and no reason' % k)

    def test_the_docs_hold_the_table(self):
        with open(os.path.join(ROOT, 'docs', 'target-agent.md'), encoding='utf-8') as fh:
            doc = fh.read()
        self.assertIn('Windows: what the OpenSSH target does, the agent does', doc)
        for r in PARITY:
            if r[0].startswith('role_'):
                self.assertIn('`allow role %s' % r[0][5:], doc)
        self.assertIn('allow key-read', doc)


# ---- one logic, two renderings ----------------------------------------------------------------
# what windows_ssh's role scripts changed after Microsoft's documentation was read (and why) -
# the text of win_roles_before.json is the same but for these roles
FIXED = {
    # about_WSMan_Provider: a listener's CertificateThumbprint is set with New-Item only - an
    # existing listener changed with Set-WSManInstance (Set-WSManInstance, Example 1)
    'winrm': 'Set-WSManInstance -ResourceURI winrm/config/Listener',
    # "Update the Administration Mode certificate": -SubjectName or -Thumbprint, not both;
    # NETWORK SERVICE must read the key (given by thumbprint - acme keeps older ones of the
    # same subject, which Set-WACCertificateAcl -SubjectName may pick)
    'wac': "if ($cmd.Parameters.ContainsKey('Thumbprint')) { $a = @{ Thumbprint = $thumb } }",
}


def inline(lines, params):
    """The agent's text with a job's values put in: what windows_ssh's text is for the same
    values (if ($o.x) {..} else {..} decided, foreach ($it in @($o.x)) unrolled, ($o.x) as a
    literal) - braces matched as PowerShell reads them."""
    out = []
    i = 0
    n = len(lines)

    def block(start):
        """lines[start] opens a block (if ... {, } else {): -> the index of the line that
        closes it (}, or } else {)"""
        depth = 1
        for j in range(start + 1, n):
            if lines[j] == '} else {' and depth == 1:
                return j
            depth += _braces(lines[j])
            if depth == 0:
                return j
        raise AssertionError('unclosed: %r' % lines[start])
    while i < n:
        line = lines[i]
        m = re.match(r'^if \(\$o\.(\w+)\) \{$', line)
        f = re.match(r'^foreach \(\$it in @\(\$o\.(\w+)\)\) \{$', line)
        sec = re.match(r'^(\$\w+) = New-Object System\.Security\.SecureString$', line)
        if m:
            end = block(i)
            then = lines[i + 1:end]
            other = []
            stop = end
            if lines[end] == '} else {':
                stop = block(end)
                other = lines[end + 1:stop]
            out += inline(then if params.get(m.group(1)) else other, params)
            i = stop + 1
            continue
        if f:
            end = block(i)
            body = lines[i + 1:end]
            for x in params.get(f.group(1)) or []:
                out += inline([b.replace('([string]$it)', WR.ps_str(x)) for b in body], params)
            i = end + 1
            continue
        if sec and i + 1 < n and lines[i + 1].startswith('if ([string]$env:'):
            env = re.search(r'\$env:(\w+)', lines[i + 1]).group(1)
            key = {'ACME_PFX_PASSWORD': 'pfx_pw', 'ACME_CCS_PASSWORD': 'ccs_pw'}[env]
            out.append(WR._secure(sec.group(1), params.get(key)))
            i += 2
            continue
        line = re.sub(r'\(\[string\]\$o\.(\w+)\)', lambda mm: WR.ps_str(
            params.get(mm.group(1)) or ''), line)
        line = re.sub(r'\(\[int\]\$o\.(\w+)\)', lambda mm: '%d' % int(
            params.get(mm.group(1)) or 0), line)
        line = re.sub(r'@\(\$o\.(\w+)\)', lambda mm: '@(%s)' % ', '.join(
            WR.ps_str(x) for x in params.get(mm.group(1)) or []), line)
        out.append(line)
        i += 1
    return out


def _braces(line):
    """{ minus } of a line, quotes skipped."""
    d, i, q = 0, 0, None
    while i < len(line):
        c = line[i]
        if q:
            if c == q:
                if i + 1 < len(line) and line[i + 1] == q:
                    i += 2
                    continue
                q = None
            elif c == '`' and q == '"':
                i += 1
        elif c in '\'"':
            q = c
        elif c == '{':
            d += 1
        elif c == '}':
            d -= 1
        i += 1
    return d


class OneLogic(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(HERE, 'win_roles_before.json'), encoding='utf-8') as fh:
            self.before = json.load(fh)

    def test_generated_in_sync(self):
        got = subprocess.run([sys.executable, GEN, '--check'], capture_output=True, text=True)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(AG._winroles().SCRIPTS, WR.agent_scripts())
        self.assertEqual({k: dict(v) for k, v in AG._winroles().SCHEMA.items()},
                         {k: dict(v) for k, v in WR.SCHEMA.items()})
        self.assertEqual([r[0] for r in AG._winroles().ROLES], [r[0] for r in WR.ROLES])

    def test_ssh_text_as_before_but_the_fixes(self):
        changed = set()
        for name, key, opts, env in MX.cases(WR):
            new = '\n'.join(WR.role_script(key, opts, env))
            if new != self.before[name]:
                changed.add(key)
                self.assertIn(key, FIXED, '%s: windows_ssh\'s script changed' % name)
                self.assertIn(FIXED[key], new)
        self.assertEqual(changed, set(FIXED))
        self.assertEqual('\n'.join(WR.key_read_script(["DOM\\o'neil", 'NT Service\\X'])),
                         self.before['__key_read'])
        self.assertEqual('\n'.join(WR.cleanup_script('acme-www-', 2)), self.before['__cleanup'])
        self.assertEqual('\n'.join(WR.DETECT), self.before['__detect'])
        for k, code in WR.HELPERS:
            if k != 'Grant-KeyRead':                    # the well-known SIDs (below)
                self.assertEqual(code, self.before['__helper_' + k], k)
        gk = dict(WR.HELPERS)['Grant-KeyRead']
        self.assertIn("'NT AUTHORITY\\NETWORK SERVICE' = 'S-1-5-20'", gk)

    def test_the_agents_script_is_the_ssh_text(self):
        """The agent's body with the values put in == windows_ssh's body, every case."""
        n = 0
        for name, key, opts, env in MX.cases(WR):
            params = WR.role_params(key, opts, env)
            agent = WR.render(WR.TEMPLATES[key], None, 'agent')
            self.assertEqual(inline(agent, params), WR.role_script(key, opts, env), name)
            # nothing of a job in the agent's text: only $o
            self.assertNotIn("'www.example.test'", '\n'.join(agent))
            n += 1
        self.assertGreater(n, 150)
        ka = WR.render(WR.KEY_READ_TEMPLATE, None, 'agent')
        self.assertEqual(inline(ka, {'accounts': ["a'b", 'c']}),
                         WR.key_read_script(["a'b", 'c']))
        # the agent's whole script: its head + the helpers + that body
        for key in [r[0] for r in WR.ROLES]:
            body = WR.render(WR.TEMPLATES[key], None, 'agent')
            self.assertEqual(AG._winroles().SCRIPTS[key],
                             '\n'.join(WR.head_agent('\n'.join(body)) + body))
            self.assertEqual(D_balanced(AG._winroles().SCRIPTS[key]), '', key)

    def test_schema_takes_what_role_params_makes(self):
        for name, key, opts, env in MX.cases(WR):
            try:
                p = WR.role_params(key, opts, env)
            except Exception:                           # noqa: BLE001
                continue
            if WR.check_options(opts, env['names']):
                continue                    # acme refuses it before anything is sent
            if opts.get('rds_broker') == MX.VALUES['rds_broker']:
                # not a host name (a quote): windows_ssh quotes it, the agent refuses it
                with self.assertRaises(AG.Refused):
                    W.role_values(AG, key, {k: v for k, v in p.items() if k not in WR.SECRETS
                                            and WR.SCHEMA[key].get(k, ('agent',))[0] !=
                                            'agent'})
                continue
            o = {k: v for k, v in p.items() if k not in WR.SECRETS and
                 WR.SCHEMA[key].get(k, ('agent',))[0] != 'agent'}
            got = W.role_values(AG, key, o)
            self.assertEqual(got, o, name)
        with self.assertRaises(AG.Refused):
            W.role_values(AG, 'sql', {'sql_instance': 'a;b'})
        with self.assertRaises(AG.Refused):
            W.role_values(AG, 'rds', {'pfx': 'C:\\x.pfx'})          # the agent's own
        with self.assertRaises(AG.Refused):
            W.role_values(AG, 'ccs', {'ccs_pw': 'x'})               # never a password
        with self.assertRaises(AG.Refused):
            W.role_values(AG, 'nope', {})

    def test_ssh_import_rdp_and_iis_fixed(self):
        b = FakeB()
        sc = WS.WindowsSshTarget.script(WS.WindowsSshTarget.__new__(WS.WindowsSshTarget), b,
                                        {'rdp': True, 'iis': 'Default Web Site | a.test'},
                                        'C:/x.pfx', 'pw')
        self.assertIn("icacls.exe $kp /grant '*S-1-5-20:R'", sc)
        self.assertIn('RSACryptoServiceProvider', sc)
        self.assertNotIn("'NETWORK SERVICE:R'", sc)
        self.assertIn("try { $b.AddSslCertificate($thumb, 'My') } catch { "
                      "$b.RemoveSslCertificate(); $b.AddSslCertificate($thumb, 'My') }", sc)
        self.assertIn(WR.RDP_KEY_READ[0], W.PS_BIND)            # the agent: the same lines
        self.assertIn(WR.USED[-1], W.PS_REMOVE)


def D_balanced(ps):
    sys.path.insert(0, HERE)
    import test_targets_windows_roles as TR
    return TR.balanced(ps)


class FakeB(object):
    name = 'www.example.test'
    names = ['www.example.test']
    not_before = 1793491200
    serial = '0a1b2c3d'

    def __init__(self):
        self.cert_pem = CERTS['a']['crt']


# ---- the roles through the agent --------------------------------------------------------------
class RolesPS(D.FakePS):
    """FakePS of test_agent_windows_deploy and the roles: a role script answers its STEP lines
    (or fails as told); what it was given kept."""

    def __init__(self):
        D.FakePS.__init__(self)
        self.roles = []
        self.role_fail = {}
        self.found = {}

    def __call__(self, script, env, timeout=300):
        if not script.startswith(W.ROLE_PRELUDE):
            return D.FakePS.__call__(self, script, env, timeout)
        body = script[len(W.ROLE_PRELUDE):-len(W.ROLE_END)]
        S = AG._winroles().SCRIPTS
        key = [k for k, v in S.items() if v == body]
        with open(env['ACME_WIN_IN']) as fh:
            j = json.load(fh)
        if not key:
            # the PowerShell after: the fixed head and acme's lines
            assert body.startswith(W.POST_PS_HEAD), body[:80]
            self.roles.append(('post_ps', j, body[len(W.POST_PS_HEAD):]))
            if 'post_ps' in self.role_fail:
                return 1, 'ERROR: %s' % self.role_fail['post_ps']
            return 0, 'STEP ok it ran'
        key = key[0]
        pfx = None
        for k in ('pfx', 'ccs_pfx'):
            p = (j.get('o') or {}).get(k)
            if p:
                assert os.path.dirname(p) == os.path.join(AG.ROOT_STATE, 'stage'), p
                with open(p, 'rb') as fh:
                    pfx = (k, fh.read())
        self.roles.append((key, j, {k: env.get(k) for k in ('ACME_PFX_PASSWORD',
                                                            'ACME_CCS_PASSWORD')}, pfx))
        if key == 'detect':
            return 0, ''.join('ROLE %s %s %s\n' % (k, 'yes' if v[0] else 'no', v[1])
                              for k, v in self.found.items())
        if key in self.role_fail:
            return 1, 'STEP info about to fail\nERROR: %s' % self.role_fail[key]
        return 0, 'STEP ok %s worked' % key

    def role_names(self):
        return [r[0] for r in self.roles]


def roles_job(leaf='a', roles=(), key_read=(), post_ps=None, ccs=None):
    args = D.job(leaf, iis=False, rdp=False)
    w = args['win']
    w['prefix'] = 'acme-www.example.test-'
    w['roles'] = [{'key': k, 'o': o} for k, o in roles]
    w['key_read'] = list(key_read)
    if post_ps:
        w['post_ps'] = post_ps
    if ccs is not None:
        w['ccs'] = ccs
    return args


def o_of(key, **opts):
    p = WR.role_params(key, dict({'role_' + key: True}, **opts),
                       {'names': ['www.example.test', 'example.test']})
    return {k: v for k, v in p.items() if k not in WR.SECRETS and
            WR.SCHEMA[key].get(k, ('agent',))[0] != 'agent'}


class AgentRoles(unittest.TestCase):
    def setUp(self):
        self.ps = RolesPS()
        self._ps, W.powershell = W.powershell, self.ps
        self._pl = AG.policy_load
        self.pol_text = 'allow store\n'
        AG.policy_load = lambda: (D.policy(self.pol_text), 'h', self.pol_text)
        p = os.path.join(AG.ROOT_STATE, 'store.json')
        if os.path.exists(p):
            os.unlink(p)

    def tearDown(self):
        W.powershell = self._ps
        AG.policy_load = self._pl

    def deploy(self, args):
        return AG.Deploy(D.Root(), args, {}).run()

    def test_each_role_refused_then_allowed(self):
        for key, _l, title, need in WR.ROLES:
            extra = {'ccs': {'ccs_path': '\\\\fs\\ccs'}, 'sharepoint': {
                'sp_url': 'https://sp.example.test'}, 'wac': {'wac_msi': 'C:\\i\\wac.msi'}}.get(
                    key, {})
            o = o_of(key, **extra)
            ccs = {'sealed': D.seal('win ccs', D.pfx_of('a', 'cc')),
                   'password_sealed': D.seal('win ccs password', b'cc')} if key == 'ccs' else None
            self.pol_text = 'allow store\n'
            self.ps.roles = []
            with self.assertRaises(AG.Refused) as cm:
                self.deploy(roles_job(roles=[(key, o)], ccs=ccs))
            line = {'ccs': 'acme-agent allow role ccs path=\\\\fs\\ccs',
                    'wac': 'acme-agent allow role wac msi=C:\\i\\wac.msi'}.get(
                        key, 'acme-agent allow role %s' % key)
            self.assertEqual([n['allow'] for n in cm.exception.needs], [line], key)
            self.assertEqual(self.ps.roles, [])                     # nothing ran
            self.pol_text = 'allow store\n' + line[len('acme-agent '):] + '\n'
            self.ps.store.pop(CERTS['a']['thumb'], None)
            got = self.deploy(roles_job(roles=[(key, o)], ccs=ccs))
            self.assertTrue(got['ok'], (key, got))
            self.assertEqual(self.ps.role_names(), [key])
            _k, j, env, pfx = self.ps.roles[0]
            self.assertEqual(j['thumb'], CERTS['a']['thumb'])
            self.assertEqual(j['prefix'], 'acme-www.example.test-')
            self.assertEqual({k: v for k, v in j['o'].items() if k not in ('pfx', 'ccs_pfx')},
                             o, key)
            if need == 'pfx':
                self.assertEqual(pfx[0], 'pfx')
                D.openssl('pkcs12', '-in', '/dev/stdin', '-nokeys', '-passin',
                          'pass:' + env['ACME_PFX_PASSWORD'], data=pfx[1])
            elif key == 'ccs':
                self.assertEqual(env['ACME_CCS_PASSWORD'], 'cc')
                D.openssl('pkcs12', '-in', '/dev/stdin', '-nokeys', '-passin', 'pass:cc',
                          data=pfx[1])
            else:
                self.assertIsNone(pfx)
                self.assertIsNone(env['ACME_PFX_PASSWORD'])
            words = '\n'.join(s[1] for s in got['steps'])
            self.assertIn('%s: done' % title, words)
            self.assertIn('%s worked' % key, words)
            self.assertIn(title, got['said'])
            D.AgentSide.stage_empty(self)

    def test_a_role_failing_the_others_run_nothing_put_back(self):
        self.pol_text = 'allow store\nallow role rdgw\nallow role sstp\nallow role sql\n'
        self.ps.store['D' * 40] = {'friendly': 'old', 'key': True}
        self.ps.role_fail = {'rdgw': 'RD Gateway: the service TSGateway is not on this server'}
        got = self.deploy(roles_job(roles=[('sstp', o_of('sstp')), ('rdgw', o_of('rdgw')),
                                           ('sql', o_of('sql'))]))
        self.assertFalse(got['ok'])
        self.assertFalse(got.get('rolled_back'))
        self.assertEqual(got['said'], 'RD Gateway failed (SQL Server, SSTP VPN done); the old '
                                      'certificates are kept')
        self.assertEqual(self.ps.role_names(), ['rdgw', 'sql', 'sstp'])     # the role order
        self.assertIn(CERTS['a']['thumb'], self.ps.store)                    # stays: in use
        self.assertNotIn('remove', self.ps.names())                          # nothing removed
        words = [s[1] for s in got['steps']]
        self.assertIn('about to fail', words)
        self.assertIn('RD Gateway failed: RD Gateway: the service TSGateway is not on this '
                      'server', words)
        self.assertIn('roles on the server: RD Gateway, SQL Server, SSTP VPN', words)
        # remembered as imported by this agent: a later deployment removes it beyond keep
        self.assertEqual([x['thumb'] for x in W.records_load(AG)['dep-7']],
                         [CERTS['a']['thumb']])

    def test_key_read_first_and_failing_stops(self):
        self.pol_text = 'allow store\nallow role sql\nallow key-read "NT SERVICE\\Foo"\n'
        with self.assertRaises(AG.Refused) as cm:
            self.deploy(roles_job(roles=[('sql', o_of('sql'))], key_read=['nobody']))
        self.assertEqual([n['allow'] for n in cm.exception.needs],
                         ['acme-agent allow key-read nobody'])
        got = self.deploy(roles_job(roles=[('sql', o_of('sql'))],
                                    key_read=['NT SERVICE\\Foo']))
        self.assertTrue(got['ok'], got)
        self.assertEqual(self.ps.role_names(), ['key_read', 'sql'])
        self.assertEqual(self.ps.roles[0][1]['o'], {'accounts': ['NT SERVICE\\Foo']})
        self.ps.roles = []
        self.ps.role_fail = {'key_read': 'the account NT SERVICE\\Foo is not known here'}
        self.ps.store.pop(CERTS['a']['thumb'], None)
        got = self.deploy(roles_job(roles=[('sql', o_of('sql'))],
                                    key_read=['NT SERVICE\\Foo']))
        self.assertFalse(got['ok'])
        self.assertIn('read on the key could not be given', got['said'])
        self.assertEqual(self.ps.role_names(), ['key_read'])

    def test_post_ps_by_its_hash_and_failing_puts_back(self):
        body = 'Write-Output $thumb\nRestart-Service W3SVC'
        h = hashlib.sha256(body.encode()).hexdigest()
        with self.assertRaises(AG.Refused) as cm:
            self.deploy(roles_job(post_ps=body))
        self.assertEqual([n['allow'] for n in cm.exception.needs],
                         ['acme-agent allow script-hash %s' % h])
        self.pol_text = 'allow store\nallow script-hash %s\n' % h
        got = self.deploy(roles_job(post_ps=body))
        self.assertTrue(got['ok'], got)
        self.assertEqual(self.ps.roles[0][0], 'post_ps')
        self.assertEqual(self.ps.roles[0][2], body)
        self.assertEqual(self.ps.roles[0][1], {'thumb': CERTS['a']['thumb']})
        # failing: as a failing test - the store and the files back
        self.ps.role_fail = {'post_ps': 'boom'}
        got = self.deploy(roles_job('b', post_ps=body))
        self.assertFalse(got['ok'])
        self.assertTrue(got['rolled_back'])
        self.assertIn('the PowerShell after the import failed: boom', got['said'])
        self.assertNotIn(CERTS['b']['thumb'], self.ps.store)

    def test_check_detects_roles(self):
        self.ps.found = {'sql': (True, 'MSSQLSERVER'), 'adfs': (False, '')}
        pol = D.policy('allow store\nallow role sql\nallow role adfs\n')
        plan = AG.plan_check(pol, roles_job(roles=[('sql', o_of('sql')),
                                                   ('adfs', o_of('adfs'))]))
        out = W.dry_check(AG, plan['win'])
        role = {x['role']: x for x in out if x.get('role')}
        self.assertFalse(role['sql'].get('bad'))
        self.assertTrue(role['adfs']['bad'])
        self.assertEqual(role['adfs']['said'], 'is not installed on this server')
        plan = AG.plan_check(pol, {'files': [], 'win': {'store': None, 'iis': [], 'rdp': False,
                                                        'detect': True}})
        out = W.dry_check(AG, plan['win'])
        self.assertEqual(out[0]['roles'], {'sql': [True, 'MSSQLSERVER'], 'adfs': [False, '']})
        self.assertEqual(out[0]['said'], 'SQL Server (MSSQLSERVER)')

    def test_job_refused_shapes(self):
        pol = D.policy('allow store\nallow role sql\n')
        for bad in ([{'key': 'sql', 'o': {'sql_instance': 'x', 'evil': 1}}],
                    [{'key': 'sql', 'o': {'sql_instance': "a'b"}}],
                    [{'key': 'sql', 'o': {}}, {'key': 'sql', 'o': {}}], 'x'):
            args = roles_job()
            args['win']['roles'] = bad
            with self.assertRaises(AG.Refused):
                AG.plan_check(pol, args)
        args = roles_job(roles=[('sql', o_of('sql'))])
        args['win']['store'] = None
        args['files'] = []
        with self.assertRaises(AG.Refused):
            AG.plan_check(pol, args)


class PolicyEntries(unittest.TestCase):
    def test_windows_entries(self):
        pol = AG.parse_policy('allow role adfs\nallow role ccs path=\\\\fs\\ccs\n'
                              'allow role wac msi=C:\\i\\wac.msi\n'
                              'allow key-read "NT SERVICE\\Foo"\nallow role ccs\n'
                              'allow role ccs path=C:\\Windows\\x\nallow role nope\n'
                              'allow role adfs path=C:\\x\n')
        self.assertEqual(pol['roles'], {'adfs': [], 'ccs': ['\\\\fs\\ccs'],
                                        'wac': ['C:\\i\\wac.msi']})
        self.assertEqual(pol['key_read'], ['NT SERVICE\\Foo'])
        self.assertEqual(len(pol['problems']), 4, pol['problems'])
        self.assertEqual(AG.policy_lines(pol)[-4:], [
            'allow role adfs', 'allow role ccs path=\\\\fs\\ccs',
            'allow role wac msi=C:\\i\\wac.msi', 'allow key-read "NT SERVICE\\Foo"'])
        again = AG.parse_policy('\n'.join(AG.policy_lines(pol)))
        self.assertEqual(again['roles'], pol['roles'])
        rep = AG.policy_report(pol, 'h')
        self.assertEqual(rep['roles'], pol['roles'])
        self.assertEqual(rep['roles_known'], [r[0] for r in WR.ROLES])
        self.assertIn('roles', AG.policy_facts())

    def test_linux_policy_hash_as_before(self):
        text = 'allow file /etc/ssl/x owner=root:root mode=0640\nallow unit nginx.service ' \
               'reload\nallow probe local\n'
        pol = LX.parse_policy(text)
        keep = {k: pol[k] for k in ('files', 'units', 'tests', 'scripts', 'script_hashes',
                                    'from', 'self_update', 'connect', 'limits')}
        keep['probe_local'] = True
        self.assertEqual(LX.policy_canon(pol), json.dumps(keep, sort_keys=True,
                                                          separators=(',', ':')))
        self.assertNotIn('roles_known', LX.policy_report(pol, 'h'))
        self.assertTrue(LX.parse_policy('allow role adfs\n')['problems'])     # not on Linux
        self.assertNotIn('roles', LX.policy_facts())


# ---- acme's side ------------------------------------------------------------------------------
class AcmeSide(unittest.TestCase):
    OPTS = {'role_sql': True, 'sql_instance': 'SQLEXPRESS', 'role_ccs': True,
            'ccs_path': 'D:\\CCS', 'ccs_password': 'sesame', 'key_read': 'NT SERVICE\\Foo',
            'exchange': 'IIS; smtp', 'post_ps': 'Write-Output $thumb', 'role_ldaps': True}

    def test_plan_carries_the_roles(self):
        t = D.target()
        b = D.Bundle('a')
        r = t.resolved(b, dict(self.OPTS))
        args = t.plan(b, self.OPTS, r, t.render(b, r))
        w = args['win']
        self.assertEqual([x['key'] for x in w['roles']], ['sql', 'ldaps', 'ccs', 'exchange'])
        sql = w['roles'][0]['o']
        self.assertEqual(sql, {'sql_instance': 'SQLEXPRESS', 'sql_fe_set': False,
                               'sql_fe_on': False, 'sql_restart': True})
        self.assertEqual(w['roles'][3]['o']['ex_services'], ['IIS', 'SMTP'])
        self.assertEqual(w['roles'][2]['o']['ccs_files'], ['www.example.test.pfx'])
        self.assertNotIn('ccs_pw', json.dumps(w['roles']))
        self.assertNotIn('sesame', json.dumps(args))                 # sealed only
        self.assertEqual(w['key_read'], ['NT SERVICE\\Foo'])
        self.assertEqual(w['post_ps'], 'Write-Output $thumb')
        self.assertTrue(w['ccs']['sealed'] and w['ccs']['password_sealed'])
        # the agent takes the job as acme makes it
        pol = D.policy('allow store\nallow role sql\nallow role ldaps\nallow role exchange\n'
                       'allow role ccs path=D:\\CCS\nallow key-read "NT SERVICE\\Foo"\n'
                       'allow script-hash %s\nallow probe local\n' % hashlib.sha256(
                           b'Write-Output $thumb').hexdigest())
        plan = AG.plan_check(pol, json.loads(json.dumps(args)))
        self.assertEqual([x['key'] for x in plan['win']['roles']],
                         ['sql', 'ldaps', 'ccs', 'exchange'])
        self.assertEqual(t.served_places(self.OPTS), [('127.0.0.1', 636)])

    def test_needs_and_preview(self):
        t = D.target()
        pol = AG.policy_report(D.policy('allow store\nallow role sql\n'), 'h')
        t.ctx.agent_info = lambda: {'policy': pol, 'state': 'joined'}
        got = t.preview(D.Bundle('a'), dict(self.OPTS))
        items = {(i['kind'], i['what']): i for i in got['agent']['items']}
        self.assertTrue(items[('role', 'SQL Server')]['ok'])
        self.assertFalse(items[('role', 'LDAPS')]['ok'])
        self.assertEqual(items[('role', 'LDAPS')]['allow'], 'acme-agent allow role ldaps')
        self.assertEqual(items[('role', 'IIS Central Certificate Store (D:\\CCS)')]['allow'],
                         'acme-agent allow role ccs path=D:\\CCS')
        self.assertEqual(items[('key-read', 'NT SERVICE\\Foo')]['allow'],
                         'acme-agent allow key-read "NT SERVICE\\Foo"')
        self.assertIn('acme-agent allow script-hash', items[('script', 'sha256 %s…' % hashlib.sha256(
            b'Write-Output $thumb').hexdigest()[:16])]['allow'])
        self.assertEqual([x['key'] for x in got['roles']['on']],
                         ['sql', 'ldaps', 'ccs', 'exchange'])
        self.assertIn('# --- SQL Server ---', got['roles']['script'])
        self.assertIn('"sql_instance": "SQLEXPRESS"', got['roles']['script'])
        self.assertIn('$inst = ([string]$o.sql_instance)', got['roles']['script'])
        self.assertTrue(any('after the import' in p['words'] for p in got['problems']))

    def test_old_agent_gets_no_roles(self):
        t = D.target()
        pol = LX.policy_report(D.policy('allow store\n'), 'h')      # no roles_known
        t.ctx.agent_info = lambda: {'policy': pol, 'state': 'joined'}
        with self.assertRaises(D.base.PluginError) as cm:
            t.deploy(D.Bundle('a'), {'role_sql': True})
        self.assertIn('knows no Windows role', str(cm.exception))

    def test_test_lists_roles(self):
        t = D.target()
        calls = []

        def call(op, args, timeout=0):
            calls.append((op, args))
            if op == 'hello':
                return {'ok': True, 'version': '1.0.120', 'host': 'w1', 'platform': 'windows',
                        'policy': AG.policy_report(D.policy('allow store\nallow role sql\n'),
                                                   'h')}
            return {'ok': True, 'files': [{'path': 'the roles on this server', 'roles': {
                'sql': [True, 'MSSQLSERVER'], 'adfs': [True, '']}}]}
        t._call = call
        words = t.test()
        self.assertIn('roles sql', words)
        self.assertIn('roles on this server: AD FS, SQL Server (MSSQLSERVER)', words)
        self.assertEqual(calls[1][1]['win']['detect'], True)

    def test_what_happens_says_the_roles(self):
        from acmelib.certs import runplan as RP
        ev = {'op': 'deploy', 'platform': 'windows', 'policy_known': True, 'target': 'w1',
              'items': [{'what': 'store', 'ok': True, 'allow': ''},
                        {'what': 'role', 'role': 'sql', 'o': {'sql_instance': 'X'},
                         'ok': False, 'allow': 'acme-agent allow role sql'},
                        {'what': 'key_read', 'account': 'NT SERVICE\\Foo', 'ok': True,
                         'allow': ''},
                        {'what': 'post_ps', 'sha256': 'ab' * 32, 'ok': True, 'allow': ''}]}
        steps = RP._agent_job_steps(ev) if hasattr(RP, '_agent_job_steps') else None
        if steps is None:
            steps = [RP._agent_win_step(i) for i in ev['items']]
        words = json.dumps(steps)
        self.assertIn('The agent sets the Windows role SQL Server', words)
        self.assertIn('sql_instance=\\"X\\"', words)
        self.assertIn('The agent gives NT SERVICE\\\\Foo read on the private key', words)
        self.assertIn('The agent runs the PowerShell after the import', words)

    def test_builder_needs_and_lines(self):
        from acmelib.certs import agent_policy as P
        t = D.target()
        b = D.Bundle('a')
        r = t.resolved(b, dict(self.OPTS))
        items = []
        P._win_needs(items, t, t.plan(b, self.OPTS, r, [b'' for _ in r['files']],
                                      sealed=False), self.OPTS)
        kinds = [(i['kind'], i.get('role') or i.get('account') or '') for i in items
                 if i['kind'] in ('role', 'key-read', 'hash')]
        self.assertEqual(kinds, [('role', 'sql'), ('role', 'ldaps'), ('role', 'ccs'),
                                 ('role', 'exchange'), ('key-read', 'NT SERVICE\\Foo'),
                                 ('hash', '')])
        if not D.NODE:
            return
        tpl = {x['key']: x for x in P.templates_windows()}
        got = D.builder_out([{'templates': [tpl['adfs'], tpl['ccs']],
                              'needs': [i for i in items if i['kind'] in ('role', 'key-read')],
                              'covers': [{'kind': 'role', 'role': 'ccs', 'extra': 'D:\\CCS'},
                                         {'kind': 'role', 'role': 'ccs', 'extra': 'E:\\x'},
                                         {'kind': 'key-read', 'account': 'nt service\\foo'}]}])
        lines = got[0]['lines']
        self.assertIn('allow role adfs', lines)
        self.assertIn('allow role ccs path=\\\\fileserver\\ccs', lines)
        self.assertIn('allow role ccs path=D:\\CCS', lines)
        self.assertIn('allow key-read "NT SERVICE\\Foo"', lines)
        self.assertEqual(got[0]['covers'], ['yes', 'no', 'yes'])
        self.assertIn('acme-agent allow role sql', got[0]['allow'])
        # the agent reads the builder's file and writes it back the same
        m = D.G.agent_mod_windows()
        self.assertEqual(m.policy_lines(m.parse_policy(got[0]['text'])), lines)
        self.assertEqual(m.policy_check(got[0]['text'])['errors'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
