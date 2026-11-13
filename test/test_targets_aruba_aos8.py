#!/usr/bin/env python3
"""ArubaOS 8 targets, without a network and without a device.

    python3 test/test_targets_aruba_aos8.py

  aruba_aos8   ''             SSH shell: copy tftp:/scp: from a staging server to flash,
                              crypto pki-import pfx ServerCert, web-server profile switch-cert
                              / captive-portal-cert, write memory, no crypto-local pki (old)
  aruba_iap    ''  8.3  8.7   8.7+: crypto pki-import from a URL, wlan cert-assignment-profile,
                              commit apply; 8.3 - 8.6: copy tftp ... uiserver / cpserver

The fake Context, SSH session and certificates are those of test_targets.py: every command is
recorded and answered as the CLI Bank documents it (see the module for what is unverified),
and the tests look at the lines sent, the staging server's files, versions refused before
anything changes, and errors.
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import aruba_aos8 as A  # noqa: E402

GUIDES = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')
NEW = {'aruba_aos8': [''], 'aruba_iap': ['', '8.3', '8.7']}


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
    def __init__(self, *a, **k):
        FakeBundle.__init__(self, *a, **k)
        self.asked = []

    def as_format(self, fmt, password=None, alias=None):
        self.asked.append(fmt)
        if fmt == 'key-pem-enc':
            return ('ENCRYPTED KEY with %s\n' % password).encode()
        return FakeBundle.as_format(self, fmt, password, alias)


class WithIntermediate(Recording):
    """A chain of an intermediate (any non-self-signed certificate) and the root."""
    def __init__(self, *a, **k):
        Recording.__init__(self, *a, **k)
        self.chain_pems = [T.read(T.CERTS['b'][0])] + self.chain_pems


def aos_ssh(version='8.10.0.7', certs=None, said=None):
    """A controller answering as ArubaOS 8 does; `said` {regex: answer} for the lines given."""
    st = {'ServerCert': dict(certs or {}), 'IntermediateCA': {}, 'TrustedCA': {}, 'flash': [],
          'switch': '', 'captive': ''}

    def table(kind):
        out = ('Certificate Name   Original Filename   Reference Count   Expired\n'
               '----------------   -----------------   ---------------   -------\n')
        for n, refs in st[kind].items():
            out += '%s   %s.pfx   %d   No\n' % (n, n, refs)
        return out

    def shell(cmd, inp):
        for rx, ans in (said or {}).items():
            if re.search(rx, inp):
                return 0, ans, ''
        out = ''
        if 'show version' in inp:
            out += ('Aruba Operating System Software.\nArubaOS (MODEL: Aruba7210), Version %s\n'
                    % version)
        m = re.search(r'show crypto-local pki (\S+)', inp)
        if m:
            out += table(m.group(1))
        for f in re.findall(r'^copy (?:tftp|scp): .* flash: (\S+)$', inp, re.M):
            st['flash'].append(f)
            out += 'File transferred successfully\n'
        for fmt, kind, name, f in re.findall(r'crypto pki-import (\S+) (\S+) (\S+) (\S+)', inp):
            st[kind][name] = 0
            out += 'Certificate is uploaded. It can be used in the configuration now.\n'
        for f in re.findall(r'^delete filename (\S+)$', inp, re.M):
            st['flash'].remove(f)
        m = re.search(r'^switch-cert (\S+)$', inp, re.M)
        if m:
            if st['switch'] in st['ServerCert']:
                st['ServerCert'][st['switch']] -= 1
            st['switch'] = m.group(1)
            st['ServerCert'][m.group(1)] = st['ServerCert'].get(m.group(1), 0) + 1
        m = re.search(r'^captive-portal-cert (\S+)$', inp, re.M)
        if m:
            st['captive'] = m.group(1)
        for n in re.findall(r'^no crypto-local pki ServerCert (\S+)$', inp, re.M):
            st['ServerCert'].pop(n, None)
        return 0, out, ''

    ssh = FakeSsh([(r'^test -d', (0, 'writable\n', '')), (r'^rm -f', (0, '', '')),
                   (r'^\n', shell)])
    ssh.state = st
    return ssh


CFG = {'host': 'mcr01.example.test', 'user': 'acme', 'auth': 'password', 'password': 'pw',
       'stage_host': 'stage.example.test', 'stage_addr': '192.0.2.10', 'stage_dir': '/srv/tftp',
       'stage_user': 'acme', 'stage_auth': 'password', 'stage_password': 'stagepw'}


def shells(ssh):
    return [inp for cmd, inp in ssh.runs if cmd == '']


class Registered(unittest.TestCase):
    def test_versions_labels_fields(self):
        reg = Registry(extra_dirs=[]).reload()
        self.assertEqual(reg.broken, [])
        for kind, vers in NEW.items():
            got = reg.versions_of('target', kind)
            self.assertEqual(sorted(got), sorted(vers), kind)
            self.assertIs(reg.get('target', kind), got[''])
            for v, cls in got.items():
                self.assertTrue(cls.description and cls.title and cls.vendor)
                self.assertEqual(cls.fields, got[''].fields)
                self.assertEqual(cls.deploy_fields, got[''].deploy_fields)
                if v:
                    self.assertIn(cls.version_label, cls.description)
                else:
                    self.assertEqual(cls.version_label, 'any version (detects it)')
        labels = {k: c.version_label for k, c in reg.versions_of('target', 'aruba_iap').items()}
        self.assertEqual(labels, {'': 'any version (detects it)', '8.3': 'Instant 8.3 - 8.6',
                                  '8.7': 'Instant 8.7 - 8.13'})

    def test_parsers(self):
        self.assertEqual(A.parse_aos('ArubaOS (MODEL: Aruba7030), Version 8.10.0.7 LSR'),
                         (8, 10, 0, 7))
        self.assertEqual(A.parse_aos('ArubaOS (MODEL: 515), Version 8.6.0.4'), (8, 6, 0, 4))
        self.assertIsNone(A.parse_aos('Cisco IOS XE Software, Version 17.12.01'))
        self.assertEqual(A.parse_certs('Name  File  Reference Count  Expired\n'
                                       '----  ----  ---  ---\nmcr-1  m.pfx  2  No\n'),
                         {'mcr-1': 2})
        self.assertEqual(A.IAP_RANGES.version_for((8, 6, 0, 4))[0], '8.3')
        self.assertEqual(A.IAP_RANGES.version_for((8, 7, 0, 0))[0], '8.7')
        self.assertEqual(A.IAP_RANGES.version_for((8, 13, 1, 0))[0], '8.7')
        pw = A.one_time_password()
        self.assertTrue(pw.isalnum() and len(pw) == 20)


class Guides(unittest.TestCase):
    def test_every_module_and_version_has_both(self):
        for kind, vers in NEW.items():
            for v in vers:
                for suffix in ('.md', '.cs.md'):
                    p = os.path.join(GUIDES, '%s%s%s' % (kind, '@' + v if v else '', suffix))
                    with open(p, encoding='utf-8') as f:
                        md = f.read()
                    self.assertTrue(md.startswith('# '), p)
                    self.assertIn('```', md, p)
                    self.assertIn('Vyplnění v acme' if suffix == '.cs.md' else 'Fill in acme',
                                  md, p)
                    self.assertIn('neověřen' if suffix == '.cs.md' else 'nverified', md, p)


# ---------------------------------------------------------------------------
class Aos8(unittest.TestCase):
    def deploy(self, cfg=None, bundle=None, ssh=None, **opts):
        b = bundle or Recording()
        ssh = ssh or aos_ssh()
        ctx = FakeCtx(ssh=ssh)
        got = make('aruba_aos8', '', dict(CFG, **(cfg or {})), ctx).deploy(
            b, dict({'keep': 1}, **opts))
        return b, ssh, ctx, got

    def test_tftp_import_switch_cert_save(self):
        b, ssh, ctx, got = self.deploy()
        name = C.object_name(b, {}, maxlen=31)
        self.assertLessEqual(len(name), 31)
        f = 'acme-%s.pfx' % C.short_serial(b, 8)
        ca = 'acme-ca-%s' % C.chain_id(b.chain_pems[0])
        self.assertIn('p12-legacy', b.asked)
        # the staging server: the root CA and the PKCS#12, written and removed
        self.assertEqual([p for p, _d, _m in ssh.puts],
                         ['/srv/tftp/%s.pem' % ca, '/srv/tftp/%s' % f])
        self.assertEqual(ssh.puts[1][2], 0o644, 'TFTP reads as nobody')
        self.assertEqual(ssh.conns[1]['host'], 'stage.example.test')
        rms = [c for c, _i in ssh.runs if c.startswith('rm -f')]
        self.assertEqual(rms, ['rm -f -- /srv/tftp/%s.pem' % ca, 'rm -f -- /srv/tftp/%s' % f])
        sh = shells(ssh)
        self.assertTrue(all(s.startswith('no paging\n') and s.endswith('exit\n') for s in sh))
        self.assertIn('no paging\ncopy tftp: 192.0.2.10 %s flash: %s\nexit\n' % (f, f), sh)
        self.assertIn('no paging\ncrypto pki-import pem TrustedCA %s %s.pem\nexit\n' % (ca, ca),
                      sh)
        imp = [s for s in sh if 'pki-import pfx' in s][0]
        pw = re.search(r'crypto pki-import pfx ServerCert %s %s (\w+)\n' % (name, f), imp).group(1)
        self.assertIn('no paging\nconfigure terminal\nweb-server profile\nno switch-cert\n'
                      'switch-cert %s\nexit\nexit\nexit\n' % name, sh)
        self.assertIn('no paging\nwrite memory\nexit\n', sh)
        self.assertIn('no paging\ndelete filename %s.pem\ndelete filename %s\nexit\n' % (ca, f),
                      sh)
        self.assertEqual(ssh.state['flash'], [])
        self.assertEqual(ssh.state['switch'], name)
        self.assertFalse([w for _l, w in ctx.steps if pw in w], 'no password in a step')
        self.assertIn('imported %s' % name, got)
        # the same again: nothing
        again = make('aruba_aos8', '', CFG, ctx).deploy(b, {'keep': 1})
        self.assertIn('unchanged', again)

    def test_intermediate_and_ca_once(self):
        b = WithIntermediate()
        mid = 'acme-ca-%s' % C.chain_id(b.chain_pems[0])
        b, ssh, ctx, got = self.deploy(bundle=b)
        sh = '\n'.join(shells(ssh))
        self.assertIn('crypto pki-import pem IntermediateCA %s %s.pem' % (mid, mid), sh)
        self.assertIn('crypto pki-import pem TrustedCA', sh)
        # another certificate of the same CA: the CAs are there already
        ctx2 = FakeCtx(ssh=ssh)
        n0 = len(ssh.puts)
        make('aruba_aos8', '', CFG, ctx2).deploy(WithIntermediate('b'), {'force': True,
                                                                         'keep': 1})
        self.assertEqual(len(ssh.puts) - n0, 1, 'only the PKCS#12 this time')

    def test_scp_conductor_node_captive_portal(self):
        b, ssh, ctx, got = self.deploy(cfg={'transfer': 'scp', 'config_node': '/md/branch'},
                                       captive_portal=True, captive_host='cp.example.test',
                                       import_chain=False)
        name = C.object_name(b, {}, maxlen=31)
        f = 'acme-%s.pfx' % C.short_serial(b, 8)
        sh = shells(ssh)
        self.assertIn('no paging\ncopy scp: 192.0.2.10 acme /srv/tftp/%s flash: %s\nstagepw\n'
                      'exit\n' % (f, f), sh)
        self.assertEqual(ssh.puts[0][2], 0o600)
        self.assertIn('no paging\ncd /md/branch\nconfigure terminal\n'
                      'crypto-local pki ServerCert %s %s\nweb-server profile\nno switch-cert\n'
                      'switch-cert %s\nno captive-portal-cert\ncaptive-portal-cert %s\nexit\n'
                      'exit\nexit\n' % (name, f, name, name), sh)
        self.assertIn('no paging\ncd /md/branch\nwrite memory\nexit\n', sh)
        self.assertFalse([s for s in sh if 'TrustedCA' in s])
        t = make('aruba_aos8', '', CFG, FakeCtx())
        self.assertEqual(t.served_places({'captive_portal': True,
                                          'captive_host': 'cp.example.test'}),
                         [('mcr01.example.test', 4343), ('cp.example.test', 443)])
        self.assertEqual(t.served_places({'web_admin': False}), [])

    def test_scp_needs_a_password(self):
        with self.assertRaises(PluginError) as e:
            self.deploy(cfg={'transfer': 'scp', 'stage_auth': 'key'})
        self.assertIn('password', str(e.exception))

    def test_enable_password_and_hidden(self):
        b, ssh, ctx, got = self.deploy(cfg={'enable_password': 'en4ble'}, import_chain=False)
        self.assertTrue(all(s.startswith('enable\nen4ble\nno paging\n') for s in shells(ssh)))

    def test_old_removed_used_kept(self):
        prefix = C.name_prefix(FakeBundle(), {}, maxlen=31)
        old1, old2 = prefix + '20250101-aaaaaaaa', prefix + '20250201-bbbbbbbb'
        ssh = aos_ssh(certs={old1: 0, old2: 0, 'other-cert': 0})
        b, ssh, ctx, got = self.deploy(ssh=ssh, keep=0)
        sh = shells(ssh)
        for o in (old1, old2):
            self.assertIn('no paging\nconfigure terminal\nno crypto-local pki ServerCert %s\n'
                          'exit\nwrite memory\nexit\n' % o, sh)
        self.assertIn('other-cert', ssh.state['ServerCert'])
        # one still referenced stays
        ssh = aos_ssh(certs={old1: 2})
        b, ssh, ctx, got = self.deploy(ssh=ssh, keep=0)
        self.assertIn(old1, ssh.state['ServerCert'])
        self.assertTrue([w for lv, w in ctx.steps if lv == 'warn' and 'still referenced' in w])

    def test_import_refused_files_gone_nothing_switched(self):
        ssh = aos_ssh(said={r'pki-import pfx': 'Error: Certificate import failed\n'})
        with self.assertRaises(PluginError) as e:
            self.deploy(ssh=ssh, import_chain=False)
        self.assertIn('Certificate import failed', str(e.exception))
        self.assertTrue([c for c, _i in ssh.runs if c.startswith('rm -f')])
        self.assertFalse([s for s in shells(ssh) if 'switch-cert' in s])
        self.assertNotIn(re.search(r'ServerCert \S+ \S+ (\w+)', '\n'.join(shells(ssh))).group(1),
                         str(e.exception))

    def test_aos6_and_aos10_refused_before_any_change(self):
        for v in ('6.5.4.20', '10.7.1.0'):
            ssh = aos_ssh(version=v)
            with self.assertRaises(PluginError) as e:
                self.deploy(ssh=ssh)
            self.assertFalse(e.exception.retry)
            self.assertEqual(ssh.puts, [])
            self.assertFalse([s for s in shells(ssh) if 'pki-import' in s or 'copy' in s])
        self.assertIn('aruba_central', str(e.exception))

    def test_try(self):
        ctx = FakeCtx(ssh=aos_ssh(certs={'mcr-2026': 1}))
        said = make('aruba_aos8', '', CFG, ctx).test()
        self.assertIn('ArubaOS 8.10.0.7; 1 server certificate', said)
        self.assertIn('/srv/tftp is writable', said)
        ssh = aos_ssh(said={r'show version': 'Cisco IOS XE Software, Version 17.12.01\n'})
        with self.assertRaises(PluginError):
            make('aruba_aos8', '', CFG, FakeCtx(ssh=ssh)).test()
        ssh = aos_ssh()
        ssh.answers.insert(0, (r'^test -d', (1, '', '')))
        with self.assertRaises(PluginError) as e:
            make('aruba_aos8', '', CFG, FakeCtx(ssh=ssh)).test()
        self.assertIn('not writable', str(e.exception))


# ---------------------------------------------------------------------------
def iap_ssh(version='8.10.0.6', said=None):
    st = {'assigned': {}, 'imported': [], 'commit': 0, 'copies': []}

    def shell(cmd, inp):
        for rx, ans in (said or {}).items():
            if re.search(rx, inp):
                return 0, ans, ''
        out = ''
        if 'show version' in inp:
            out += 'ArubaOS (MODEL: 515), Version %s\n' % version
        m = re.search(r'crypto pki-import format \S+ cert-type ServerCert url \S+ certname (\S+)',
                      inp)
        if m:
            st['imported'].append(m.group(1))
        for app, name in re.findall(r'pki-cert-assign application (\S+) cert-type ServerCert '
                                    r'certname (\S+)', inp):
            st['assigned'][app] = name
        if 'commit apply' in inp:
            st['commit'] += 1
        if 'show cert assignment' in inp:
            out += ''.join('%s  ServerCert  %s\n' % kv for kv in st['assigned'].items())
        st['copies'] += re.findall(r'^copy tftp .*$', inp, re.M)
        return 0, out, ''

    ssh = FakeSsh([(r'^test -d', (0, 'writable\n', '')), (r'^rm -f', (0, '', '')),
                   (r'^\n', shell)])
    ssh.state = st
    return ssh


ICFG = dict(CFG, host='iap.example.test', user='admin')


class Iap(unittest.TestCase):
    def deploy(self, version='', sw='8.10.0.6', cfg=None, **opts):
        b = Recording()
        ssh = iap_ssh(sw)
        ctx = FakeCtx(ssh=ssh)
        got = make('aruba_iap', version, dict(ICFG, **(cfg or {})), ctx).deploy(b, opts)
        return b, ssh, ctx, got

    def test_87_import_assign_commit(self):
        b, ssh, ctx, got = self.deploy(captive_portal=True)
        name = C.object_name(b, {}, maxlen=31)
        f = 'acme-%s.pfx' % C.short_serial(b, 8)
        self.assertIn('p12-legacy', b.asked)
        self.assertEqual(ssh.puts[0][0], '/srv/tftp/%s' % f)
        sh = shells(ssh)
        imp = [s for s in sh if 'pki-import' in s][0]
        m = re.match(r'no paging\ncrypto pki-import format pfx cert-type ServerCert url '
                     r'tftp://192\.0\.2\.10/%s certname %s psk (\w+)\nexit\n$'
                     % (re.escape(f), re.escape(name)), imp)
        self.assertTrue(m, imp)
        self.assertIn('no paging\nconfigure terminal\nwlan cert-assignment-profile\n'
                      'pki-cert-assign application ui cert-type ServerCert certname %s\n'
                      'pki-cert-assign application captive-portal cert-type ServerCert '
                      'certname %s\nexit\nexit\ncommit apply\nexit\n' % (name, name), sh)
        self.assertEqual(ssh.state['commit'], 1)
        self.assertTrue([c for c, _i in ssh.runs if c == 'rm -f -- /srv/tftp/%s' % f])
        self.assertFalse([w for _l, w in ctx.steps if m.group(1) in w])
        self.assertIn('assigned to ui, captive-portal', got)

    def test_87_url_and_command_fields(self):
        b, ssh, ctx, got = self.deploy(
            '8.7', '8.12.0.1',
            cfg={'stage_url': 'ftp://u:p@{addr}/{dir}/{file}',
                 'import_command': 'crypto pki-import {format} ServerCert {url} {name} {psk}'})
        imp = [s for s in shells(ssh) if 'pki-import' in s][0]
        self.assertIn('crypto pki-import pfx ServerCert ftp://u:p@192.0.2.10/srv/tftp/acme-', imp)

    def test_83_copy_tftp(self):
        for version in ('', '8.3'):
            b, ssh, ctx, got = self.deploy(version, '8.6.0.4', captive_portal=True)
            f = 'acme-%s.pem' % C.short_serial(b, 8)
            self.assertIn('key-pem-enc', b.asked)
            data = ssh.puts[0][1]
            pw = re.search(rb'ENCRYPTED KEY with (\w+)', data).group(1).decode()
            self.assertIn(b'BEGIN CERTIFICATE', data)
            self.assertEqual(ssh.state['copies'],
                             ['copy tftp 192.0.2.10 %s uiserver cert %s format pem' % (f, pw),
                              'copy tftp 192.0.2.10 %s cpserver cert %s format pem' % (f, pw)])
            self.assertFalse([s for s in shells(ssh) if 'cert-assignment' in s])
            self.assertFalse([w for _l, w in ctx.steps if pw in w])

    def test_versions_refused_before_any_change(self):
        for version, sw, fit in (('8.3', '8.10.0.6', 'Instant 8.7 - 8.13'),
                                 ('8.7', '8.6.0.4', 'Instant 8.3 - 8.6'),
                                 ('', '10.7.0.0', None)):
            ssh = iap_ssh(sw)
            with self.assertRaises(PluginError) as e:
                make('aruba_iap', version, ICFG, FakeCtx(ssh=ssh)).deploy(FakeBundle(), {})
            self.assertFalse(e.exception.retry)
            if fit:
                self.assertIn('"%s"' % fit, str(e.exception))
            else:
                self.assertIn('aruba_central', str(e.exception))
            self.assertEqual(ssh.puts, [])

    def test_nothing_chosen_and_import_error(self):
        with self.assertRaises(PluginError):
            self.deploy(web_admin=False)
        ssh = iap_ssh(said={r'pki-import': '% Invalid input detected at \'^\' marker.\n'})
        with self.assertRaises(PluginError) as e:
            make('aruba_iap', '', ICFG, FakeCtx(ssh=ssh)).deploy(FakeBundle(), {})
        self.assertIn('Invalid input', str(e.exception))
        self.assertTrue([c for c, _i in ssh.runs if c.startswith('rm -f')])
        self.assertFalse([s for s in shells(ssh) if 'commit apply' in s])

    def test_try(self):
        said = make('aruba_iap', '', ICFG, FakeCtx(ssh=iap_ssh('8.6.0.4'))).test()
        self.assertIn('Instant 8.6.0.4 (copy tftp)', said)
        said = make('aruba_iap', '', ICFG, FakeCtx(ssh=iap_ssh('8.11.2.1'))).test()
        self.assertIn('cert-assignment-profile', said)
        with self.assertRaises(PluginError):
            make('aruba_iap', '8.3', ICFG, FakeCtx(ssh=iap_ssh('8.11.2.1'))).test()


if __name__ == '__main__':
    unittest.main()
