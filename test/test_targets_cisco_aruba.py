#!/usr/bin/env python3
"""The Cisco and HPE Aruba targets of 1.0.95, without a network and without a device.

    python3 test/test_targets_cisco_aruba.py

  cisco_iosxe            ''  17.3  17.12   SSH: SCP to bootflash:, crypto pki import pkcs12,
                                           ip http secure-trustpoint (PKCS#12 kind by version)
  cisco_wlc9800          ''  17.3  17.12   the same, and the webauth parameter map
  cisco_nxos             ''                NX-API JSON-RPC + SCP, nxapi certificate trustpoint
  cisco_catalyst_center  ''                Intent API certificate / certificate-p12
  cisco_fmc              7.7               PKCS12 Cert Enrollment + managecertificates
  aruba_aoscx            ''                REST: TA profiles, PUT certificates, association
  aruba_clearpass        ''                OAuth2, trust list, PUT server-cert from a URL
  aruba_central          ''                token refresh, POST / PUT non_msp certificate

The fake Context, SSH session and certificates are those of test_targets.py: every request and
command is recorded and answered as the vendor documents it, and the tests look at what was
asked - paths, bodies, commands - at versions refused before anything changes, and at errors.
"""
import base64
import json
import os
import re
import sys
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh  # noqa: E402
from test_targets_more import parts_of  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import cisco_iosxe as IX  # noqa: E402
from acmelib.plugins.targets import cisco_nxos as NX  # noqa: E402

GUIDES = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')
NEW = {'cisco_iosxe': ['', '17.3', '17.12'], 'cisco_wlc9800': ['', '17.3', '17.12'],
       'cisco_nxos': [''], 'cisco_catalyst_center': [''], 'aruba_aoscx': [''],
       'aruba_clearpass': [''], 'aruba_central': ['']}


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def make(kind, version, cfg, ctx):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', kind, version)
    assert cls.module_version == version, (kind, cls.module_version, version)
    return cls(cfg, ctx)


class Recording(FakeBundle):
    """A FakeBundle that says which formats were asked of it."""
    def __init__(self, *a, **k):
        FakeBundle.__init__(self, *a, **k)
        self.asked = []

    def as_format(self, fmt, password=None, alias=None):
        self.asked.append(fmt)
        return FakeBundle.as_format(self, fmt, password, alias)


class Registered(unittest.TestCase):
    def test_versions_labels_fields(self):
        reg = Registry(extra_dirs=[]).reload()
        self.assertEqual(reg.broken, [])
        for kind, vers in NEW.items():
            got = reg.versions_of('target', kind)
            self.assertEqual(sorted(got), sorted(vers), kind)
            self.assertIs(reg.get('target', kind), got[''], 'the plain one is the default')
            for v, cls in got.items():
                self.assertTrue(cls.description and cls.title and cls.vendor, kind)
                self.assertEqual(cls.fields, got[''].fields, 'saved settings fit every version')
                self.assertEqual(cls.deploy_fields, got[''].deploy_fields)
                if v:
                    self.assertIn(cls.version_label, cls.description)
                else:
                    self.assertIn(cls.version_label, ('', 'any version (detects it)'))
        labels = {k: c.version_label for k, c in reg.versions_of('target', 'cisco_iosxe').items()}
        self.assertEqual(labels, {'': 'any version (detects it)', '17.3': 'IOS XE 17.3 - 17.11',
                                  '17.12': 'IOS XE 17.12 - 26.1'})
        fmc = reg.versions_of('target', 'cisco_fmc')
        self.assertEqual(sorted(fmc), ['', '7.7'])
        self.assertIs(reg.get('target', 'cisco_fmc'), fmc[''], 'the existing one stays default')
        self.assertEqual(fmc['7.7'].fields, fmc[''].fields)
        self.assertEqual(fmc['7.7'].version_label, 'FMC 7.7 - 10.0')
        for kind in ('cisco_asa', 'cisco_ise', 'cisco_ftd_fdm'):
            self.assertEqual(sorted(reg.versions_of('target', kind)), [''],
                             '%s: its calls are the same in every version the guide covers'
                             % kind)

    def test_version_for(self):
        self.assertEqual(IX.RANGES.version_for((17, 9, 4))[0], '17.3')
        self.assertEqual(IX.RANGES.version_for((17, 11, 99))[0], '17.3')
        self.assertEqual(IX.RANGES.version_for((17, 12, 1))[0], '17.12')
        self.assertEqual(IX.RANGES.version_for((26, 1, 1))[0], '17.12')
        self.assertEqual(IX.RANGES.version_for((16, 12, 4)), ('', ''))
        self.assertEqual(IX.parse_iosxe('Cisco IOS XE Software, Version 17.09.04a\n'), (17, 9, 4))
        self.assertEqual(IX.parse_iosxe('Cisco IOS XE Software, Version 17.12.01\n'),
                         (17, 12, 1))
        self.assertEqual(NX.parse_nxos('10.2(3)F'), (10, 2, 3))
        self.assertIsNone(IX.parse_iosxe('nothing'))


class Guides(unittest.TestCase):
    def test_every_new_module_and_version_has_both(self):
        want = dict(NEW)
        want['cisco_fmc'] = ['7.7']
        for kind, vers in want.items():
            for v in vers:
                for suffix in ('.md', '.cs.md'):
                    p = os.path.join(GUIDES, '%s%s%s' % (kind, '@' + v if v else '', suffix))
                    with open(p, encoding='utf-8') as f:
                        md = f.read()
                    self.assertTrue(md.startswith('# '), p)
                    self.assertIn('```', md, p)
                    self.assertIn('| ', md, p)
                    self.assertIn('Vyplnění v acme' if suffix == '.cs.md' else 'Fill in acme',
                                  md, p)
                    if suffix == '.cs.md':
                        self.assertTrue(re.search('[ěščřžýáíéůú]', md), p)


# ---------------------------------------------------------------------------
# IOS XE and the 9800
# ---------------------------------------------------------------------------
def iosxe_ssh(version='17.09.04a', tps=(), http_tp='', import_out='', webauth=''):
    """A switch that answers as IOS XE does."""
    state = {'tps': list(tps), 'http': http_tp}

    def running(cmd, inp):
        out = ''.join('crypto pki trustpoint %s\n' % t for t in state['tps'])
        if state['http']:
            out += 'ip http secure-trustpoint %s\n' % state['http']
        return 0, out, ''

    def shell(cmd, inp):
        m = re.search(r'crypto pki import (\S+) pkcs12', inp)
        if m:
            if import_out:
                return 0, import_out, ''
            state['tps'] += [m.group(1)]
            return 0, '% Importing pkcs12...\nCRYPTO_PKI: Imported PKCS12 file successfully.\n', ''
        m = re.search(r'ip http secure-trustpoint (\S+)', inp)
        if m:
            state['http'] = m.group(1)
        for t in re.findall(r'no crypto pki trustpoint (\S+)', inp):
            state['tps'].remove(t)
        return 0, 'Enter configuration commands, one per line.\n', ''

    ssh = FakeSsh([
        (r'^show version', (0, 'Cisco IOS XE Software, Version %s\nCisco IOS Software '
                               '[Dublin], Catalyst L3 Switch Software\n' % version, '')),
        (r'^show running-config \| include', running),
        (r'^show running-config \| section parameter-map', (0, webauth, '')),
        (r'^show crypto pki certificates', (0, 'Certificate\n  Status: Available\n', '')),
        (r'^delete /force', (0, '', '')),
        (r'^write memory', (0, 'Building configuration...\n[OK]\n', '')),
        (r'^\n', shell),
    ])
    ssh.state = state
    return ssh


CFG = {'host': 'sw01.example.test', 'user': 'acme', 'auth': 'password', 'password': 'pw'}


class IosXe(unittest.TestCase):
    def deploy(self, version, sw, **opts):
        b = Recording()
        ssh = iosxe_ssh(sw, **opts.pop('ssh', {}))
        ctx = FakeCtx(ssh=ssh)
        got = make(opts.pop('kind', 'cisco_iosxe'), version, CFG, ctx).deploy(
            b, dict({'keep': 1}, **opts))
        return b, ssh, ctx, got

    def scripts(self, ssh):
        return [inp for cmd, inp in ssh.runs if cmd == '']

    def test_plain_before_1712_sends_legacy(self):
        b, ssh, ctx, got = self.deploy('', '17.09.04a')
        name = C.object_name(b, {}, maxlen=60)
        self.assertIn('p12-legacy', b.asked)
        self.assertEqual(ssh.puts[0][0], 'bootflash:%s.pfx' % name)
        self.assertEqual(ssh.vias, ['scp'])
        self.assertTrue(ssh.conns[0]['scp_legacy'], 'IOS XE speaks the old SCP protocol')
        imp, bind = self.scripts(ssh)[:2]
        self.assertTrue(imp.startswith('configure terminal\ncrypto pki import %s pkcs12 '
                                       'bootflash:%s.pfx password ' % (name, name)))
        self.assertTrue(imp.endswith('end\nexit\n'))
        self.assertEqual(bind, 'configure terminal\nip http secure-trustpoint %s\n'
                               'no ip http secure-server\nip http secure-server\nend\nexit\n'
                         % name)
        cmds = [c for c, _i in ssh.runs if c]
        self.assertIn('show crypto pki certificates %s' % name, cmds)
        self.assertIn('delete /force bootflash:%s.pfx' % name, cmds)
        self.assertEqual(cmds[-1] if cmds[-1] == 'write memory' else 'write memory',
                         'write memory')
        self.assertIn('write memory', cmds)
        self.assertIn('imported', got)
        # the one-time password never in a step
        pw = re.search(r'password (\S+)', imp).group(1)
        self.assertFalse([w for _l, w in ctx.steps if pw in w])

    def test_plain_1712_sends_aes(self):
        b, ssh, ctx, got = self.deploy('', '17.12.01')
        self.assertIn('pfx', b.asked)
        self.assertNotIn('p12-legacy', b.asked)

    def test_versions_send_their_own(self):
        b, ssh, ctx, got = self.deploy('17.3', '17.06.05')
        self.assertIn('p12-legacy', b.asked)
        b, ssh, ctx, got = self.deploy('17.12', '26.01.01')
        self.assertIn('pfx', b.asked)

    def test_another_version_refused_before_any_change(self):
        for version, sw, fit in (('17.3', '17.15.03', 'IOS XE 17.12 - 26.1'),
                                 ('17.12', '17.09.04a', 'IOS XE 17.3 - 17.11'),
                                 ('17.12', '16.12.04', 'any version (detects it)')):
            ssh = iosxe_ssh(sw)
            with self.assertRaises(PluginError) as e:
                make('cisco_iosxe', version, CFG, FakeCtx(ssh=ssh)).deploy(FakeBundle(), {})
            self.assertFalse(e.exception.retry)
            self.assertIn('"%s"' % fit, str(e.exception))
            self.assertEqual(ssh.puts, [])
            self.assertEqual(self.scripts(ssh), [], 'nothing configured')

    def test_try(self):
        ctx = FakeCtx(ssh=iosxe_ssh('17.15.03', tps=['TP-self-signed-1']))
        self.assertIn('IOS XE 17.15.3; 1 trustpoint', make('cisco_iosxe', '', CFG, ctx).test())
        with self.assertRaises(PluginError):
            make('cisco_iosxe', '17.3', CFG, FakeCtx(ssh=iosxe_ssh('17.15.03'))).test()

    def test_import_refused_said_and_file_deleted(self):
        ssh = iosxe_ssh('17.12.04', import_out='% Error: PKCS12 import failed (Bad HMAC)\n')
        with self.assertRaises(PluginError) as e:
            make('cisco_iosxe', '', CFG, FakeCtx(ssh=ssh)).deploy(FakeBundle(), {})
        self.assertIn('Bad HMAC', str(e.exception))
        self.assertTrue([c for c, _i in ssh.runs if c.startswith('delete /force')])
        self.assertFalse([i for c, i in ssh.runs if c == '' and 'secure-trustpoint' in i])

    def test_older_removed_same_is_noop(self):
        prefix = C.name_prefix(FakeBundle(), {}, maxlen=60)
        old = prefix + '20250101-aaaaaaaa'
        b, ssh, ctx, got = self.deploy('', '17.12.04', keep=0,
                                       ssh={'tps': [old, old + '-rrr1'], 'http_tp': old})
        last = self.scripts(ssh)[-1]
        self.assertIn('no crypto pki trustpoint %s-rrr1\nyes\n' % old, last)
        self.assertIn('no crypto pki trustpoint %s\nyes\n' % old, last)
        self.assertIn('crypto key zeroize ec %s\nyes\n' % old, last)
        self.assertTrue([w for _l, w in ctx.steps if 'removed the older trustpoint' in w])
        # the same again: nothing
        again = make('cisco_iosxe', '', CFG, ctx).deploy(b, {'keep': 0})
        self.assertIn('unchanged', again)

    def test_wlc_webauth(self):
        b, ssh, ctx, got = self.deploy('', '17.12.03', kind='cisco_wlc9800', webauth=True,
                                       webauth_host='guest.example.test')
        name = C.object_name(b, {}, maxlen=60)
        self.assertIn('configure terminal\nparameter-map type webauth global\ntrustpoint %s\n'
                      'exit\nno ip http server\nip http server\nend\nexit\n' % name,
                      self.scripts(ssh))
        t = make('cisco_wlc9800', '', CFG, FakeCtx())
        self.assertEqual(t.served_places({'webauth': True, 'webauth_host': 'guest.example.test'}),
                         [('sw01.example.test', 443), ('guest.example.test', 443)])

    def test_wlc_versions(self):
        b, ssh, ctx, got = self.deploy('17.3', '17.09.05', kind='cisco_wlc9800')
        self.assertIn('p12-legacy', b.asked)
        with self.assertRaises(PluginError):
            self.deploy('17.3', '17.12.05', kind='cisco_wlc9800')

    def test_wlc_keeps_the_portal_trustpoint(self):
        prefix = C.name_prefix(FakeBundle(), {}, maxlen=60)
        old = prefix + '20250101-aaaaaaaa'
        b, ssh, ctx, got = self.deploy('', '17.12.03', kind='cisco_wlc9800', keep=0, ssh={
            'tps': [old], 'webauth': 'parameter-map type webauth global\n trustpoint %s\n' % old})
        self.assertFalse([i for c, i in ssh.runs if c == '' and 'no crypto pki' in (i or '')])
        self.assertTrue([w for lv, w in ctx.steps if lv == 'warn' and 'still in use' in w])


# ---------------------------------------------------------------------------
# NX-OS
# ---------------------------------------------------------------------------
def nxapi(version='10.6(1)', tps=(), fail=None, cut=False):
    state = {'tps': list(tps), 'batches': []}

    def ans(call):
        batch = json.loads(call['body'])
        cmds = [x['params']['cmd'] for x in batch]
        state['batches'].append(cmds)
        if cut and any(c.startswith('nxapi certificate') for c in cmds):
            raise ConnectionResetError('the connection was reset')
        out = []
        for x in batch:
            c = x['params']['cmd']
            if fail and fail in c:
                out.append({'jsonrpc': '2.0', 'error': {'code': -32602, 'message':
                            'Invalid params', 'data': {'msg': '% Invalid PKCS12 password'}},
                            'id': x['id']})
                continue
            if c == 'show version':
                r = {'body': {'nxos_ver_str': version, 'host_name': 'n9k01'}}
            elif c.startswith('show running-config'):
                r = {'msg': ''.join('crypto ca trustpoint %s\n' % t for t in state['tps'])}
            else:
                m = re.match(r'crypto ca import (\S+) pkcs12', c)
                if m:
                    state['tps'].append(m.group(1))
                r = None
            out.append({'jsonrpc': '2.0', 'result': r, 'id': x['id']})
        return 200, out[0] if len(out) == 1 else out
    return state, ans


NXCFG = {'host': 'n9k01.example.test', 'user': 'acme', 'password': 'pw'}


class Nxos(unittest.TestCase):
    def test_deploy(self):
        prefix = C.name_prefix(FakeBundle(), {}, maxlen=60)
        old = prefix + '20250101-aaaaaaaa'
        state, ans = nxapi(tps=[old])
        ctx = FakeCtx([('POST', r'/ins$', ans)])
        b = FakeBundle()
        make('cisco_nxos', '', NXCFG, ctx).deploy(b, {'keep': 0})
        name = C.object_name(b, {}, maxlen=60)
        c = ctx.calls[0]
        self.assertEqual(c['headers']['Content-Type'], 'application/json-rpc')
        self.assertEqual(c['headers']['Authorization'],
                         'Basic ' + base64.b64encode(b'acme:pw').decode())
        self.assertEqual(ctx._ssh.puts[0][0], 'bootflash:%s.pfx' % name)
        self.assertEqual(ctx._ssh.conns[0]['port'], 22)
        self.assertTrue(ctx._ssh.conns[0]['scp_legacy'])
        b_ = state['batches']
        imp = [x for x in b_ if any(c.startswith('crypto ca import') for c in x)][0]
        self.assertEqual(imp[:3], ['configure terminal', 'crypto ca trustpoint %s' % name,
                                   'exit'])
        self.assertTrue(imp[3].startswith('crypto ca import %s pkcs12 bootflash:%s.pfx '
                                          % (name, name)))
        self.assertIn(['delete bootflash:%s.pfx no-prompt' % name], b_)
        self.assertIn(['copy running-config startup-config'], b_)
        self.assertIn(['configure terminal', 'nxapi certificate trustpoint %s' % name], b_)
        rm = b_[-1]
        self.assertEqual(rm[-1], 'no crypto ca trustpoint %s' % old,
                         'the older one goes after NX-API has left it')
        self.assertLess(b_.index(['configure terminal', 'nxapi certificate trustpoint %s' % name]),
                        len(b_) - 1)

    def test_old_nxos_refused(self):
        state, ans = nxapi(version='10.2(2)F')
        ctx = FakeCtx([('POST', r'/ins$', ans)])
        with self.assertRaises(PluginError) as e:
            make('cisco_nxos', '', NXCFG, ctx).deploy(FakeBundle(), {})
        self.assertIn('10.2(3)F', str(e.exception))
        self.assertEqual(ctx._ssh.puts, [])

    def test_import_error_hides_the_password(self):
        state, ans = nxapi(fail='crypto ca import')
        ctx = FakeCtx([('POST', r'/ins$', ans)])
        with self.assertRaises(PluginError) as e:
            make('cisco_nxos', '', NXCFG, ctx).deploy(FakeBundle(), {})
        self.assertIn('Invalid PKCS12 password', str(e.exception))
        self.assertTrue([x for x in state['batches'] if x[0].startswith('delete bootflash:')])

    def test_restart_cut_off_is_a_warning(self):
        state, ans = nxapi(cut=True)
        ctx = FakeCtx([('POST', r'/ins$', ans)])
        got = make('cisco_nxos', '', NXCFG, ctx).deploy(FakeBundle(), {})
        self.assertIn('NX-API', got)
        self.assertTrue([w for lv, w in ctx.steps if lv == 'warn' and 'restarted' in w])

    def test_try(self):
        state, ans = nxapi()
        self.assertIn('NX-OS 10.6(1)', make('cisco_nxos', '', NXCFG,
                                            FakeCtx([('POST', r'/ins$', ans)])).test())


# ---------------------------------------------------------------------------
# Catalyst Center
# ---------------------------------------------------------------------------
class CatalystCenter(unittest.TestCase):
    def routes(self, task):
        return [('POST', r'/dna/system/api/v1/auth/token$', (200, {'Token': 'TOK'})),
                ('POST', r'/dna/intent/api/v1/certificate', (202, {'response': {
                    'taskId': 't-1', 'url': '/api/v1/task/t-1'}, 'version': '1.0'})),
                ('GET', r'/dna/intent/api/v1/task/t-1$', task)]

    def test_pem(self):
        ctx = FakeCtx(self.routes((200, {'response': {'isError': False, 'progress': 'done',
                                                      'endTime': 1}})))
        t = make('cisco_catalyst_center', '', {'host': 'cc.test', 'user': 'acme',
                                               'password': 'pw'}, ctx)
        b = FakeBundle()
        t.deploy(b, {})
        tok = ctx.calls[0]
        self.assertEqual(tok['headers']['Authorization'],
                         'Basic ' + base64.b64encode(b'acme:pw').decode())
        up = ctx.find('POST', r'/certificate\?')[0]
        self.assertEqual(up['path'], '/dna/intent/api/v1/certificate')
        self.assertEqual(up['query'], {'listOfUsers': ['server']})
        self.assertEqual(up['headers']['X-Auth-Token'], 'TOK')
        parts = parts_of(up)
        self.assertEqual(parts['certFileUpload'][1].decode(), b.fullchain_pem)
        self.assertEqual(parts['pkFileUpload'][1].decode(), b.key_pem)
        self.assertEqual(len(ctx.find('GET', r'/task/t-1')), 1)
        self.assertIn('unchanged', t.deploy(b, {}))
        self.assertEqual(t.served_places({}), [('cc.test', 443)])
        self.assertEqual(t.served_places({'used_for': 'ipsec'}), [])

    def test_p12_and_dr(self):
        ctx = FakeCtx(self.routes((200, {'response': {'endTime': 1}})))
        make('cisco_catalyst_center', '', {'host': 'cc.test', 'user': 'a', 'password': 'p'},
             ctx).deploy(FakeBundle(), {'format': 'pkcs12', 'used_for': 'server,ipsec'})
        up = ctx.find('POST', r'/certificate-p12\?')[0]
        self.assertEqual(up['query']['listOfUsers'], ['server,ipsec'])
        self.assertTrue(up['query']['p12Password'][0])
        self.assertIn('p12FileUpload', parts_of(up))

    def test_refused_by_the_task(self):
        ctx = FakeCtx(self.routes((200, {'response': {'isError': True,
                                                      'failureReason': 'chain order'}})))
        with self.assertRaises(PluginError) as e:
            make('cisco_catalyst_center', '', {'host': 'cc.test', 'user': 'a', 'password': 'p'},
                 ctx).deploy(FakeBundle(), {})
        self.assertIn('chain order', str(e.exception))

    def test_restart_cuts_the_task_off(self):
        ctx = FakeCtx(self.routes((503, 'restarting')))
        t = make('cisco_catalyst_center', '', {'host': 'cc.test', 'user': 'a', 'password': 'p'},
                 ctx)
        t.deploy(FakeBundle(), {})
        self.assertTrue([w for lv, w in ctx.steps if 'cannot be read any more' in w])

    def test_bad_sign_in(self):
        ctx = FakeCtx([('POST', r'/auth/token$', (401, {'error': 'Unauthorized'}))])
        with self.assertRaises(PluginError) as e:
            make('cisco_catalyst_center', '', {'host': 'cc.test', 'user': 'a',
                                               'password': 'p'}, ctx).test()
        self.assertFalse(e.exception.retry)


# ---------------------------------------------------------------------------
# FMC 7.7
# ---------------------------------------------------------------------------
D = '/api/fmc_config/v1/domain/dom1'


def fmc_routes(version='7.7.0 (build 91)', enrollments=(), devcerts=()):
    return [
        ('POST', r'/generatetoken$', (204, '', {'X-auth-access-token': 'TKN',
                                               'DOMAIN_UUID': 'dom1'})),
        ('GET', r'/info/serverversion$', (200, {'items': [{'serverVersion': version}]})),
        ('GET', D + r'/object/certenrollments\?', (200, {'items': list(enrollments),
                                                         'paging': {'count': len(enrollments)}})),
        ('POST', D + r'/object/certenrollments$', (201, {'id': 'enr-new', 'name': 'RAVPN-acme'})),
        ('PUT', D + r'/object/certenrollments/enr-1$', (200, {'id': 'enr-1',
                                                              'name': 'RAVPN-acme'})),
        ('GET', D + r'/devices/devicerecords\?', (200, {'items': [{'id': 'dev-1', 'name': 'ftd-1'}],
                                                        'paging': {'count': 1}})),
        ('GET', D + r'/devices/certificates\?', (200, {'items': list(devcerts)})),
        ('POST', D + r'/devices/operational/managecertificates$', (202, {'id': 'task-1'})),
        ('GET', D + r'/object/internalcertificates\?', (200, {'items': [],
                                                              'paging': {'count': 0}})),
        ('POST', D + r'/object/internalcertificates$', (201, {'id': 'ic-1'})),
    ]


FMCCFG = {'host': 'fmc.test', 'user': 'api', 'password': 'pw'}


class Fmc77(unittest.TestCase):
    def test_new_enrollment_enrolled(self):
        ctx = FakeCtx(fmc_routes())
        make('cisco_fmc', '7.7', FMCCFG, ctx).deploy(FakeBundle(), {
            'enrollment': 'RAVPN-acme', 'enroll_devices': 'ftd-1', 'internal': False})
        body = ctx.json(ctx.find('POST', r'/object/certenrollments$')[0])
        self.assertEqual((body['type'], body['name'], body['enrollmentType']),
                         ('CertEnrollment', 'RAVPN-acme', 'PKCS12'))
        self.assertTrue(base64.b64decode(body['pkcs12Content']['base64Certificate']))
        self.assertTrue(body['pkcs12Content']['passPhrase'])
        self.assertEqual(body['validationUsage'], {'ipsecClient': True, 'sslServer': True})
        q = ctx.find('GET', r'/devices/certificates\?')[0]['query']
        self.assertEqual(q['filter'], ['deviceId:dev-1'])
        mc = ctx.json(ctx.find('POST', r'/managecertificates$')[0])
        self.assertEqual(mc, {'action': 'ENROLL', 'deviceCertificates': [{
            'deviceId': 'dev-1', 'certificates': [{'certificate': {'id': 'enr-new'}}]}]})
        self.assertFalse(ctx.find('POST', r'/internalcertificates$'), 'internal off')
        self.assertTrue(all(c['headers'].get('X-auth-access-token') == 'TKN'
                            for c in ctx.calls[1:]))

    def test_renewal_replaces_and_re_enrols(self):
        ctx = FakeCtx(fmc_routes(enrollments=[{'id': 'enr-1', 'name': 'RAVPN-acme',
                                               'enrollmentType': 'PKCS12'}],
                                 devcerts=[{'id': 'enr-1', 'name': 'RAVPN-acme'}]))
        make('cisco_fmc', '7.7', FMCCFG, ctx).deploy(FakeBundle(), {
            'enrollment': 'RAVPN-acme', 'enroll_devices': 'ftd-1'})
        put = ctx.json(ctx.find('PUT', r'/certenrollments/enr-1$')[0])
        self.assertEqual(put['id'], 'enr-1')
        self.assertEqual(ctx.json(ctx.find('POST', r'/managecertificates$')[0])['action'],
                         'RE_ENROLL')
        self.assertEqual(len(ctx.find('POST', r'/internalcertificates$')), 1,
                         'the Internal Certificate too, as the plain version')

    def test_older_fmc_refused_before_any_change(self):
        ctx = FakeCtx(fmc_routes(version='7.6.1 (build 26)'))
        with self.assertRaises(PluginError) as e:
            make('cisco_fmc', '7.7', FMCCFG, ctx).deploy(FakeBundle(), {
                'enrollment': 'RAVPN-acme', 'enroll_devices': 'ftd-1'})
        self.assertIn('runs FMC 7.6.1', str(e.exception))
        self.assertEqual({c['method'] for c in ctx.calls[1:]}, {'GET'})

    def test_unknown_device_and_wrong_type(self):
        ctx = FakeCtx(fmc_routes())
        with self.assertRaises(PluginError):
            make('cisco_fmc', '7.7', FMCCFG, ctx).deploy(FakeBundle(), {
                'enrollment': 'RAVPN-acme', 'enroll_devices': 'ftd-9', 'internal': False})
        ctx = FakeCtx(fmc_routes(enrollments=[{'id': 'enr-1', 'name': 'RAVPN-acme',
                                               'enrollmentType': 'SCEP'}]))
        with self.assertRaises(PluginError) as e:
            make('cisco_fmc', '7.7', FMCCFG, ctx).deploy(FakeBundle(), {
                'enrollment': 'RAVPN-acme', 'internal': False})
        self.assertIn('SCEP', str(e.exception))

    def test_try_says_the_version(self):
        self.assertIn('FMC 7.7.0', make('cisco_fmc', '7.7', FMCCFG,
                                        FakeCtx(fmc_routes())).test())


# ---------------------------------------------------------------------------
# AOS-CX
# ---------------------------------------------------------------------------
def cx_routes(certs=None, assoc=None, status='as_configured', tas=None, cut=False):
    certs = dict(certs or {})
    st = {'assoc': dict(assoc or {})}

    def patch(call):
        if cut:
            raise ConnectionResetError('reset')
        st['assoc'] = json.loads(call['body'])['certificate_association']
        return 200, ''

    def system(call):
        a = call['query'].get('attributes', [''])[0]
        if 'certificate_association_status' in a:
            return 200, {'certificate_association_status': {
                k: {'associated_cert_name': v, 'status_reason': status}
                for k, v in st['assoc'].items()}}
        if 'certificate_association' in a:
            return 200, {'certificate_association': st['assoc']}
        return 200, {'platform_name': '6300', 'software_version': 'FL.10.16.1010',
                     'hostname': 'sw01'}
    return [
        ('POST', r'/rest/latest/login\?', (200, '', {'Set-Cookie': 'id=SESSION; Path=/; Secure',
                                                     'x-csrf-token': 'CSRF'})),
        ('POST', r'/rest/latest/logout$', (200, '')),
        ('GET', r'/rest/latest/certificates$', (200, certs)),
        ('GET', r'/rest/latest/system/pki_ta_profiles$', (200, dict(tas or {}))),
        ('POST', r'/rest/latest/system/pki_ta_profiles$', (201, '')),
        ('PUT', r'/rest/latest/certificates/', (200, '')),
        ('GET', r'/rest/latest/system\?', system),
        ('PATCH', r'/rest/latest/system$', patch),
        ('PUT', r'/rest/latest/fullconfigs/startup-config\?', (200, '')),
        ('DELETE', r'/rest/latest/certificates/', (204, '')),
    ]


CXCFG = {'host': 'sw01.test', 'user': 'acme', 'password': 'p&w'}


class AosCx(unittest.TestCase):
    def test_deploy(self):
        prefix = C.name_prefix(FakeBundle(), {}, maxlen=32, serial_len=6)
        old = prefix + '20250101-aaaaaa'
        ctx = FakeCtx(cx_routes(certs={old: '/rest/v10.16/certificates/' + old,
                                       'local-cert': '/x'},
                                assoc={'https-server': old, 'syslog-client': 'local-cert'}))
        b = FakeBundle()
        make('aruba_aoscx', '', CXCFG, ctx).deploy(b, {'keep': 0})
        name = C.object_name(b, {}, maxlen=32, serial_len=6)
        self.assertLessEqual(len(name), 32)
        login = ctx.calls[0]
        self.assertEqual(login['query'], {'username': ['acme'], 'password': ['p&w']})
        self.assertEqual(ctx.calls[1]['headers']['Cookie'], 'id=SESSION')
        ta = ctx.json(ctx.find('POST', r'/pki_ta_profiles$')[0])
        self.assertEqual(ta, {'name': 'acme-ca-%s' % C.chain_id(b.chain_pems[0]),
                              'certificate': b.chain_pems[0],
                              'revocation_check_mode': 'disabled'})
        put = ctx.find('PUT', r'/certificates/')[0]
        self.assertEqual(put['path'], '/rest/latest/certificates/%s' % name)
        self.assertEqual(ctx.json(put), {'certificate': b.key_pem + b.fullchain_pem})
        self.assertEqual(put['headers']['X-CSRF-TOKEN'], 'CSRF')
        self.assertEqual(ctx.json(ctx.find('PATCH', r'/system$')[0]), {
            'certificate_association': {'https-server': name, 'syslog-client': 'local-cert'}})
        sv = ctx.find('PUT', r'/startup-config')[0]
        self.assertEqual(sv['query'], {'from': ['/rest/latest/fullconfigs/running-config']})
        self.assertEqual([c['path'] for c in ctx.find('DELETE', '')],
                         ['/rest/latest/certificates/%s' % old])
        self.assertEqual(len(ctx.find('POST', r'/login\?')), 2,
                         'signed in again after the HTTPS server took the new one')
        self.assertTrue(ctx.find('POST', r'/logout$'))
        self.assertFalse([w for _l, w in ctx.steps if 'p&w' in w])

    def test_not_taken_is_an_error(self):
        ctx = FakeCtx(cx_routes(status='configured_cert_invalid'))
        with self.assertRaises(PluginError) as e:
            make('aruba_aoscx', '', CXCFG, ctx).deploy(FakeBundle(), {})
        self.assertIn('configured_cert_invalid', str(e.exception))

    def test_cut_session_after_https_server(self):
        ctx = FakeCtx(cx_routes(cut=True))
        make('aruba_aoscx', '', CXCFG, ctx).deploy(FakeBundle(), {'save': False})
        self.assertFalse(ctx.find('PUT', r'/startup-config'))

    def test_bad_application(self):
        with self.assertRaises(PluginError):
            make('aruba_aoscx', '', CXCFG, FakeCtx(cx_routes())).deploy(
                FakeBundle(), {'applications': 'webui'})

    def test_try(self):
        got = make('aruba_aoscx', '', CXCFG, FakeCtx(cx_routes(certs={'local-cert': '/x'}))).test()
        self.assertIn('AOS-CX FL.10.16.1010; 1 certificate', got)


# ---------------------------------------------------------------------------
# ClearPass
# ---------------------------------------------------------------------------
CPCFG = {'host': 'cppm.test', 'client_id': 'acme', 'client_secret': 'SEC', 'server': 'cppm01',
         'stage_host': 'files.test', 'stage_auth': 'password', 'stage_password': 'x',
         'stage_dir': '/var/www/drop/', 'stage_url': 'https://files.test/drop'}


def cp_routes(trust=(201, {'id': 7})):
    return [
        ('POST', r'/api/oauth$', (200, {'access_token': 'AT', 'expires_in': 28800})),
        ('GET', r'/api/cluster/server$', (200, {'_embedded': {'items': [
            {'server_uuid': 'uuid-1', 'name': 'cppm01', 'fqdn': 'cppm01.test'}]}})),
        ('POST', r'/api/cert-trust-list$', trust),
        ('PUT', r'/api/server-cert/name/uuid-1/', (200, {'subject': 'CN=cppm01',
                                                        'expiry_date': '2027-02-01'})),
    ]


class ClearPass(unittest.TestCase):
    def test_deploy(self):
        ctx = FakeCtx(cp_routes())
        b = FakeBundle()
        make('aruba_clearpass', '', CPCFG, ctx).deploy(b, {'services': 'HTTPS(RSA)\nRadSec'})
        self.assertEqual(ctx.json(ctx.calls[0]), {'grant_type': 'client_credentials',
                                                  'client_id': 'acme', 'client_secret': 'SEC'})
        tl = ctx.json(ctx.find('POST', r'/cert-trust-list$')[0])
        self.assertEqual(tl, {'cert_file': b.chain_pems[0], 'enabled': True,
                              'cert_usage': ['EAP', 'Others']})
        path, data, mode = ctx._ssh.puts[0]
        self.assertTrue(re.match(r'^/var/www/drop/acme-[0-9a-f]{32}\.p12$', path), path)
        self.assertEqual(mode, 0o644)
        puts = ctx.find('PUT', r'/server-cert/')
        self.assertEqual([c['path'] for c in puts],
                         ['/api/server-cert/name/uuid-1/HTTPS%28RSA%29',
                          '/api/server-cert/name/uuid-1/RadSec'])
        body = ctx.json(puts[0])
        self.assertEqual(body['pkcs12_file_url'],
                         'https://files.test/drop/' + path.rsplit('/', 1)[1])
        self.assertTrue(body['pkcs12_passphrase'])
        self.assertTrue(all(c['headers']['Authorization'] == 'Bearer AT' for c in ctx.calls[1:]))
        self.assertEqual(ctx._ssh.runs[-1][0], "rm -f %s" % path, 'the staged file deleted')
        t = make('aruba_clearpass', '', CPCFG, FakeCtx())
        self.assertEqual(t.served_places({'services': 'HTTPS(RSA)\nRadSec'}),
                         [('cppm.test', 443), ('cppm.test', 2083)])

    def test_staged_file_deleted_when_refused(self):
        routes = cp_routes(trust=(400, {'detail': 'already exists'}))
        routes[3] = ('PUT', r'/server-cert/', (422, {'detail': 'chain not trusted'}))
        ctx = FakeCtx(routes)
        with self.assertRaises(PluginError) as e:
            make('aruba_clearpass', '', CPCFG, ctx).deploy(FakeBundle(), {})
        self.assertIn('chain not trusted', str(e.exception))
        self.assertTrue(ctx._ssh.runs and ctx._ssh.runs[-1][0].startswith('rm -f '))

    def test_unknowns(self):
        with self.assertRaises(PluginError):
            make('aruba_clearpass', '', CPCFG, FakeCtx(cp_routes())).deploy(
                FakeBundle(), {'services': 'Database'})
        with self.assertRaises(PluginError) as e:
            make('aruba_clearpass', '', dict(CPCFG, server='cppm09'),
                 FakeCtx(cp_routes())).test()
        self.assertIn('cppm01', str(e.exception))


# ---------------------------------------------------------------------------
# Central
# ---------------------------------------------------------------------------
CCFG = {'gateway': 'https://apigw.test', 'client_id': 'cid', 'client_secret': 'cs',
        'refresh_token': 'R0'}


def central_routes(items=()):
    n = {'i': 0}

    def token(call):
        n['i'] += 1
        return 200, {'access_token': 'A%d' % n['i'], 'refresh_token': 'R%d' % n['i'],
                     'expires_in': 7200}
    return [('POST', r'/oauth2/token\?', token),
            ('GET', r'/configuration/v1/certificates\?', (200, {'items': list(items),
                                                                'total': len(items)})),
            ('POST', r'/configuration/v1/certificates$', (201, {'cert_name': 'captive',
                                                                'expire_date': '2027-01-01'})),
            ('PUT', r'/configuration/v1/non_msp/certificate$', (200, {}))]


class Central(unittest.TestCase):
    def test_upload_then_replace(self):
        ctx = FakeCtx(central_routes())
        b = FakeBundle()
        make('aruba_central', '', CCFG, ctx).deploy(b, {'cert_name': 'captive'})
        tok = ctx.calls[0]
        self.assertEqual(tok['query'], {'client_id': ['cid'], 'client_secret': ['cs'],
                                        'grant_type': ['refresh_token'], 'refresh_token': ['R0']})
        q = ctx.find('GET', r'/certificates\?')[0]['query']
        self.assertEqual(q, {'limit': ['20'], 'offset': ['0'], 'q': ['captive']})
        body = ctx.json(ctx.find('POST', r'/certificates$')[0])
        self.assertEqual((body['cert_name'], body['cert_type'], body['cert_format']),
                         ('captive', 'SERVER_CERT', 'PKCS12'))
        self.assertTrue(base64.b64decode(body['passphrase']))
        self.assertTrue(base64.b64decode(body['cert_data']))
        self.assertEqual(ctx.find('POST', r'/certificates$')[0]['headers']['Authorization'],
                         'Bearer A1')
        # the next run: the certificate is there - replaced under its name, and the token
        # refreshed with the refresh token Central gave last (the old one is used up)
        ctx.routes = central_routes(items=[{'cert_name': 'captive', 'cert_type': 'SERVER_CERT'}])
        ctx.calls = []
        kept = ctx.kv[[k for k in ctx.kv if k.startswith('central-tokens:')][0]]
        kept['until'] = 0
        make('aruba_central', '', CCFG, ctx).deploy(FakeBundle('b'), {'cert_name': 'captive'})
        self.assertEqual(ctx.calls[0]['query']['refresh_token'], ['R1'])
        self.assertEqual(ctx.json(ctx.find('PUT', r'/non_msp/certificate$')[0])['cert_name'],
                         'captive')
        self.assertFalse(ctx.find('POST', r'/certificates$'))

    def test_refused_refresh_said(self):
        ctx = FakeCtx([('POST', r'/oauth2/token\?', (401, {'error': 'invalid_grant'}))])
        with self.assertRaises(PluginError) as e:
            make('aruba_central', '', CCFG, ctx).test()
        self.assertIn('refresh token', str(e.exception))
        self.assertNotIn('cs', urllib.parse.unquote(str(e.exception)).split('(')[0])

    def test_another_type_refused(self):
        ctx = FakeCtx(central_routes(items=[{'cert_name': 'captive', 'cert_type': 'CA_CERT'}]))
        with self.assertRaises(PluginError):
            make('aruba_central', '', CCFG, ctx).deploy(FakeBundle(), {'cert_name': 'captive'})
        self.assertFalse(ctx.find('PUT', ''))


if __name__ == '__main__':
    unittest.main(verbosity=1)
