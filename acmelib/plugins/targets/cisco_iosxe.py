# -*- coding: utf-8 -*-
"""
Cisco IOS XE (Catalyst switches, ISR/ASR/Catalyst 8000 routers) over SSH: the certificate,
its key and chain copied as PKCS#12 to bootflash: with SCP, imported into a new trustpoint
(`crypto pki import <tp> pkcs12`), the HTTPS server (WebUI, RESTCONF, NETCONF over HTTPS)
pointed at it and restarted, the configuration saved, the file and older acme trustpoints
removed.

    scp (legacy SCP protocol)  <file>  user@host:bootflash:<tp>.pfx    (ip scp server enable)
    exec   show version                                                the IOS XE version
    exec   show running-config | include ^crypto pki trustpoint|^ip http secure-trustpoint
    shell  configure terminal
             crypto pki import <tp> pkcs12 bootflash:<tp>.pfx password <one-time password>
           end
    exec   show crypto pki certificates <tp>                           it is there
    exec   delete /force bootflash:<tp>.pfx
    shell  configure terminal
             ip http secure-trustpoint <tp>
             no ip http secure-server
             ip http secure-server
           end
    exec   write memory
    shell  configure terminal / no crypto pki trustpoint <old> + yes /
           crypto key zeroize <rsa|ec> <old> + yes / end                older acme ones

Versions (1.0.95), by the PKCS#12 IOS XE takes - the one thing that differs in the
documents for this job (TN 213917, CSCvz41428: no SHA-256 MAC before 17.12.1):

  ''        any version - reads `show version`, sends 3DES/SHA-1 PKCS#12 before 17.12, AES after
  '17.3'    IOS XE 17.3 - 17.11      PKCS#12 3DES, SHA-1 MAC (openssl -legacy -macalg sha1)
  '17.12'   IOS XE 17.12 - 26.1      PKCS#12 AES-256, SHA-256 MAC

Sources (the vendor guide navody/certifikaty/cisco/ios-xe-nx-os.md and what it cites):
    https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-cert-enroll-pki-0.html
    https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/213917-generate-csr-for-third-party-certificate.html
    https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1715/b_1715_programmability_cg/restconf_protocol.html
    https://github.com/YangModels/yang/blob/main/vendor/cisco/xe/17181/Cisco-IOS-XE-http.yang

Less certain:
    - the configuration commands go to an SSH shell session as lines on its input (no
      terminal), as Ansible's network_cli sends them; IOS XE takes one command on an exec
      channel only, so a shell is the way to configuration mode without an interactive
      terminal - checked against no device;
    - the RESTCONF RPC Cisco-IOS-XE-rpc:crypto pki/import of the guide is derived from the
      YANG model, and restarting the HTTPS server over RESTCONF cuts RESTCONF itself (the
      guide says to do it over SSH) - hence SSH for all of it;
    - `delete /force`, the yes asked by `no crypto pki trustpoint` and `crypto key zeroize`
      are the usual IOS XE words, not quoted by the guide; the clean-up warns, never fails;
    - from 17.9.1 the guide says a trustpoint wants a password (type-6 encryption) - not
      needed for an imported PKCS#12 as far as the documents say.
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import (
    Base, PluginError, field, as_bool, text, object_name, name_prefix, ours, prune,
    random_password, ssh_fields, ssh_conn, verify_fields, keep_field, put_scp, as_int, family_of)
from acmelib.plugins.targets._cisco_aruba import Ranges, VersionCheck

# IOS says what it did not take with a "%" line
BAD = re.compile(r'^\s*(%\s*(?:Invalid|Incomplete|Ambiguous|Unknown|Error|Bad|Failed|.*\bfail'
                 r'|.*\bnot\b|.*denied|.*unable).*)$', re.I | re.M)
OK_WORDS = re.compile(r'success', re.I)

RANGES = Ranges((('17.3', 'IOS XE 17.3 - 17.11', (17, 3, 0), (17, 11, 999)),
                 ('17.12', 'IOS XE 17.12 - 26.1', (17, 12, 0), None)))


def parse_iosxe(out):
    """`show version` -> (major, minor, rebuild), None when it does not say IOS XE's."""
    m = re.search(r'IOS[ -]XE Software.*?Version\s+0*(\d+)\.0*(\d+)\.0*(\d+)', text(out),
                  re.I | re.S)
    if not m:
        m = re.search(r'Cisco IOS Software.*?Version\s+0*(\d+)\.0*(\d+)\.0*(\d+)', text(out),
                      re.I | re.S)
    return tuple(int(x) for x in m.groups()) if m else None


def key_kind(bundle):
    """'rsa' or 'ec' - the key of the certificate (for `crypto key zeroize`)."""
    return 'ec' if family_of(bundle) == 'ec' else 'rsa'


class CiscoIosXeTarget(VersionCheck, Base):
    kind = 'cisco_iosxe'
    title = 'Cisco IOS XE (switches, routers)'
    vendor = 'Cisco'
    module_version = ''
    version_label = 'any version (detects it)'
    description = ('Copies the certificate as PKCS#12 to bootflash: over SCP, imports it into '
                   'a new trustpoint, points the HTTPS server (WebUI, RESTCONF) at it and '
                   'restarts it, saves the configuration and removes the older acme '
                   'trustpoints - over SSH. Any IOS XE 17.3 - 26.1: the PKCS#12 kind is taken '
                   'from the version the device says.')
    doc = 'targets.md'
    discovery = False
    sw_name = 'IOS XE'
    ranges = RANGES
    sw_checked_to = (26, 1)
    p12_kind = None                 # 'p12-legacy' | 'pfx'; None: by the version said
    fields = ssh_fields(sudo=False, user_default='acme', howto='generic',
                        try_command='show version') + [
        field('file_system', 'File system', 'text', default='bootflash:', advanced=True,
              help='where the PKCS#12 is copied for the import (bootflash: or flash:)'),
        field('https_port', 'HTTPS port', 'number', default=443, advanced=True,
              help='the port of the WebUI (ip http secure-port), for the test of what is '
                   'served'),
    ]
    deploy_fields = [
        field('web_admin', 'HTTPS server (WebUI, RESTCONF)', 'bool', default=True,
              help='ip http secure-trustpoint, then the HTTPS server restarted (WebUI and '
                   'RESTCONF sessions are cut for a moment; traffic is not)'),
        field('save', 'Save the configuration (write memory)', 'bool', default=True),
        keep_field(1),
    ] + verify_fields()
    served_wait = (6, 5)

    # -- SSH --------------------------------------------------------------------------------
    def conn(self):
        c = ssh_conn(self)
        c['scp_legacy'] = True          # the IOS XE SCP server speaks the old protocol only
        return c

    def ssh(self):
        return self.ctx.ssh(self.conn())

    def exec_(self, s, cmd, what=None, check=True):
        rc, out, err = s.run(cmd, timeout=120, check=False)
        out = text(out) + text(err)
        if check:
            self.check(out, what or cmd)
        return out

    def config(self, s, cmds, what, hide=None, check=True):
        """Lines in configuration mode, over the input of an SSH shell session."""
        script = '\n'.join(['configure terminal'] + list(cmds) + ['end', 'exit']) + '\n'
        rc, out, err = s.run('', input=script, timeout=300, check=False)
        out = text(out) + text(err)
        if hide:
            out = out.replace(hide, '…')
        if check:
            self.check(out, what)
        return out

    def check(self, out, what):
        m = BAD.search(out)
        if m:
            raise PluginError('%s: the device said "%s"' % (what, m.group(1).strip()[:200]),
                              detail=out[-4000:], retry=False)

    def fs(self):
        f = text(self.c('file_system') or 'bootflash:').strip()
        return f if f.endswith(':') or f.endswith('/') else f + ':'

    # -- reading ----------------------------------------------------------------------------
    def sw_version(self):
        if '_ver' not in self.__dict__:
            self._ver = None
            try:
                with self.ssh() as s:
                    self._ver = parse_iosxe(self.exec_(s, 'show version', check=False))
            except PluginError as e:
                self.ctx.debug('the version cannot be read: %s' % e)
        return self._ver

    def running(self, s):
        """(trustpoints, the trustpoint of the HTTPS server)."""
        out = self.exec_(s, 'show running-config | include ^crypto pki trustpoint|'
                            '^ip http secure-trustpoint', what='reading the trustpoints')
        tps = re.findall(r'^crypto pki trustpoint (\S+)', out, re.M)
        m = re.search(r'^ip http secure-trustpoint (\S+)', out, re.M)
        return tps, (m.group(1) if m else '')

    def test(self):
        with self.ssh() as s:
            out = self.exec_(s, 'show version', what='signing in', check=False)
            ver = parse_iosxe(out)
            if ver is None:
                raise PluginError('the answer is not the show version of IOS XE: %s'
                                  % out.strip()[:200], retry=False)
            self._ver = ver
            self.check_version(ver)
            tps, cur = self.running(s)
        return 'signed in to %s: IOS XE %s; %d trustpoint%s, the HTTPS server uses %s' % (
            self.c('host'), '.'.join(map(str, ver)), len(tps), '' if len(tps) == 1 else 's',
            cur or 'its own')

    def served_places(self, options):
        if not self.c('host') or not as_bool((options or {}).get('web_admin', True), True):
            return []
        return [(self.c('host'), as_int(self.c('https_port', 443), 443))]

    # -- the work ---------------------------------------------------------------------------
    def pkcs12_kind(self, ver):
        if self.p12_kind:
            return self.p12_kind
        if ver is None:
            self.ctx.step('the IOS XE version cannot be read - PKCS#12 with 3DES and a SHA-1 '
                          'MAC is sent (what every 17.x takes)', 'warn')
            return 'p12-legacy'
        return 'pfx' if tuple(ver) >= (17, 12, 0) else 'p12-legacy'

    def binds(self, options, name):
        """[(words, configuration lines)] pointing the services asked at `name`."""
        out = []
        if as_bool(self.opt(options, 'web_admin', True), True):
            out.append(('the HTTPS server', ['ip http secure-trustpoint %s' % name,
                                             'no ip http secure-server',
                                             'ip http secure-server']))
        return out

    def bound(self, s, options):
        """The trustpoints the services use now (kept by the clean-up)."""
        return set([self.running(s)[1]])

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=60)
        prefix = name_prefix(bundle, options, maxlen=60)
        with self.ssh() as s:
            ver = parse_iosxe(self.exec_(s, 'show version', check=False))
            self._ver = ver
            tps, cur = self.running(s)
            if self.unchanged(bundle, options, present=lambda: name in tps):
                return self.same(bundle, 'in the trustpoint %s' % name)
            self.check_version(ver)
            did = []
            if name not in tps:
                kind = self.pkcs12_kind(ver)
                pw = random_password(20)
                path = '%s%s.pfx' % (self.fs(), name)
                put_scp(s, bundle.as_format(kind, password=pw, alias=name), path)
                self.ctx.step('copied the PKCS#12 to %s (%s)' % (
                    path, '3DES, SHA-1 MAC' if kind == 'p12-legacy' else 'AES-256'))
                try:
                    self.config(s, ['crypto pki import %s pkcs12 %s password %s'
                                    % (name, path, pw)], 'importing %s' % name, hide=pw)
                    shown = self.exec_(s, 'show crypto pki certificates %s' % name,
                                       what='reading the trustpoint %s' % name, check=False)
                    if not re.search(r'Certificate', shown):
                        raise PluginError('the trustpoint %s holds no certificate after the '
                                          'import' % name, detail=shown[-2000:], retry=False)
                finally:
                    try:
                        self.exec_(s, 'delete /force %s' % path, what='deleting the PKCS#12')
                    except PluginError as e:
                        self.ctx.step('the file %s stays: %s' % (path, e), 'warn')
                self.ctx.step('imported into the new trustpoint %s' % name, 'ok')
                did.append('imported %s' % name)
            else:
                self.ctx.step('the trustpoint %s is there already' % name)
            for words, cmds in self.binds(options, name):
                self.mark_pending(bundle)
                self.config(s, cmds, 'pointing %s at %s' % (words, name))
                self.ctx.step('%s uses %s' % (words, name), 'ok')
                did.append(words)
            if as_bool(self.opt(options, 'save', True), True):
                out = self.exec_(s, 'write memory', what='write memory')
                self.ctx.step('write memory%s' % (' - [OK]' if '[OK]' in out else ''), 'ok')
            self.done_pending()
            self.cleanup(s, bundle, options, prefix, name, tps)
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def cleanup(self, s, bundle, options, prefix, current, tps):
        keep = self.keep(options)
        if keep < 0:
            return
        gone = prune([t for t in tps if ours(t, prefix)], prefix, keep, current)
        if not gone:
            return
        try:
            used = self.bound(s, options)
        except PluginError as e:
            self.ctx.step('the older trustpoints stay - what uses them cannot be read: %s' % e,
                          'warn')
            return
        kk = key_kind(bundle)
        for old in gone:
            if old in used:
                self.ctx.step('the older trustpoint %s stays: it is still in use' % old, 'warn')
                continue
            chain = [t for t in tps if re.match(re.escape(old) + r'-rrr\d+$', t)]
            cmds = []
            for t in chain + [old]:
                cmds += ['no crypto pki trustpoint %s' % t, 'yes']
            cmds += ['crypto key zeroize %s %s' % (kk, old), 'yes']
            # the "yes" lines answer the questions IOS asks; where it asks none they are
            # refused words - so the result is read from the configuration, not the answer
            try:
                self.config(s, cmds, 'removing the trustpoint %s' % old, check=False)
                left = self.running(s)[0]
            except PluginError as e:
                self.ctx.step('the older trustpoint %s may stay: %s' % (old, e), 'warn')
                continue
            if old in left:
                self.ctx.step('the older trustpoint %s stays: IOS XE did not remove it' % old,
                              'warn')
            else:
                self.ctx.step('removed the older trustpoint %s' % old)


_SAME = (' Copies it to bootflash: over SCP, imports it into a new trustpoint, points the '
         'HTTPS server at it, saves and removes older acme trustpoints. Refused on a device '
         'that says another IOS XE.')


class CiscoIosXe173Target(CiscoIosXeTarget):
    """IOS XE before 17.12.1: no PKCS#12 with a SHA-256 MAC (CSCvz41428)."""
    module_version, version_label, sw_min, sw_max = RANGES.ranges[0]
    description = ('IOS XE 17.3 - 17.11: the PKCS#12 is made the old way (3DES, SHA-1 MAC) - '
                   'these versions refuse a SHA-256 MAC (CSCvz41428).' + _SAME)
    p12_kind = 'p12-legacy'


class CiscoIosXe1712Target(CiscoIosXeTarget):
    """IOS XE 17.12.1 and later (17.15, 17.18, 26.1): a standard AES PKCS#12."""
    module_version, version_label, sw_min, sw_max = RANGES.ranges[1]
    description = ('IOS XE 17.12 - 26.1 (17.12, 17.15, 17.18, 26.x): the PKCS#12 is AES-256 '
                   'with a SHA-256 MAC.' + _SAME)
    p12_kind = 'pfx'
