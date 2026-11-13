# -*- coding: utf-8 -*-
"""
Cisco Secure Firewall ASA through its HTTP Interface for Automation (the CLI
over HTTPS - Cisco's replacement of the ASA REST API, which is no longer
developed): the certificate, its key and chain imported as PKCS#12 into a new
trustpoint, the `ssl trust-point` lines switched to it, older acme
trustpoints nothing names removed, `write memory`.

    HTTP basic + User-Agent: ASDM (or a string allowed by http server basic-auth-client)
    GET  /admin/exec/<command, spaces as +>[/<command>...]      one or more commands
    POST /admin/config      the commands one a line in the body
      crypto ca trustpoint <tp>
      exit
      crypto ca import <tp> pkcs12 <passphrase> nointeractive
      <the PKCS#12, base64>
      quit
    POST /admin/config      ssl trust-point <tp> [<interface> | domain <name>] ...
    GET  /admin/exec/show+running-config+crypto+ca+trustpoint    the trustpoints
    GET  /admin/exec/show+running-config+ssl+trust-point          what uses them
    POST /admin/config      no crypto ca trustpoint <old> noconfirm
    GET  /admin/exec/write+memory

The HTTP status says only that the request arrived: 200 comes with a failed command
too, so every answer is read for the device's words (ERROR:, INFO: ... completed
successfully, Config OK).

Checked against (the user's collection of the vendor's documents,
api-docs/cisco_asa/notes.md), quoting:
    https://www.cisco.com/c/en/us/td/docs/security/asa/misc/http-interface/asa-http-interface.html
    https://www.cisco.com/c/en/us/td/docs/security/asa/api/qsg-asa-api.html
    https://www.cisco.com/c/en/us/td/docs/security/asa/compatibility/asamatrx.html
    https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/crypto-a-to-crypto-ir-commands.html
    https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S/so-st-commands.html
    https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/T-Z/asa-command-ref-T-Z/w-z-commands.html
    https://www.cisco.com/c/en/us/support/docs/security/vpn-client-tools/220282-install-and-renew-certificates-on-asa-ma.html

Less certain:
    - whether `crypto ca import ... pkcs12` needs the trustpoint made first is not said;
      acme makes it first, as the TechNote does (`crypto ca trustpoint`, `exit`);
    - which PKCS#12 encryption every ASA version takes (3DES is sent by default);
    - `write memory` and `show running-config ...` over /admin/exec are derived from the
      URL format, no example of them is in the document;
    - the answers are text only: the trustpoints are read from `show running-config`
      lines, and a failure is recognised by ERROR / % Invalid / "not" completed words;
    - the trustpoints used elsewhere (IPsec, tunnel groups) are not looked at: acme removes
      an older acme trustpoint only when no `ssl trust-point` names it - keep it (keep -1)
      when it is used for IKEv2/IPsec too;
    - whether removing a trustpoint removes its key pair is not said; failover replication
      is not checked; in multiple context mode the context is the one signed in to.
"""
from __future__ import annotations

import base64
import re
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, text, lines, object_name, name_prefix, ours, prune,
    random_password, http_fields, tls_fields, verify_fields, keep_field)

BAD = re.compile(r'^\s*((?:ERROR:|% ?Invalid|% ?Incomplete|% ?Ambiguous|% ?Unknown|.*failed).*)$',
                 re.I | re.M)


def b64_lines(data):
    s = base64.b64encode(data).decode()
    return [s[i:i + 64] for i in range(0, len(s), 64)]


class CiscoAsaTarget(HttpTarget):
    kind = 'cisco_asa'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Cisco Secure Firewall ASA (HTTP interface)'
    vendor = 'Cisco'
    description = ('Imports the certificate into the ASA as PKCS#12 in a new trustpoint through '
                   'its HTTP Interface for Automation, points ssl trust-point at it, removes the '
                   'older one and saves the configuration.')
    doc = 'targets.md'
    fields = http_fields(443, 'asa.example.local') + [
        field('user', 'User', 'text', required=True,
              help='a privilege 15 user (aaa authentication http console LOCAL)'),
        field('password', 'Password', 'secret', required=True),
        field('user_agent', 'User-Agent', 'text', default='ASDM', advanced=True,
              help='the ASA takes basic authentication only from allowed User-Agent strings '
                   '(http server basic-auth-client); ASDM is allowed by default'),
    ] + tls_fields()
    deploy_fields = [
        field('trust_points', 'ssl trust-point', 'list', placeholder='outside',
              help='one a line: an interface name (nameif), "outside vpnlb-ip", "domain '
                   'vpn.example.com", or "-" for the fallback of every interface; empty: only '
                   'where an older acme trustpoint of this certificate is named'),
        field('pkcs12_kind', 'PKCS#12 kind', 'select', default='p12-legacy', advanced=True,
              options=[['p12-legacy', '3DES (older ASA)'], ['pfx', 'AES-256']]),
        field('save', 'Save the configuration (write memory)', 'bool', default=True),
        keep_field(1),
    ] + verify_fields()

    def auth_headers(self):
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode(),
                'User-Agent': text(self.c('user_agent') or 'ASDM')}

    # -- the CLI over HTTP ------------------------------------------------------------------
    def exec_(self, *cmds, what=None):
        path = '/admin/exec/' + '/'.join(urllib.parse.quote_plus(c) for c in cmds)
        st, hd, d = self.req('GET', path, headers={'Accept': 'text/plain'},
                             what=what or cmds[0])
        return text(d)

    def conf_t(self, cmds, what, hide=None):
        body = '\n'.join(cmds) + '\n'
        try:
            st, hd, d = self.req('POST', '/admin/config', body.encode(),
                                 {'Content-Type': 'text/plain', 'Accept': 'text/plain'},
                                 what=what)
        except PluginError as e:
            raise PluginError(str(e), detail=None if hide else e.detail, retry=e.retry)
        out = text(d)
        if hide:
            out = out.replace(hide, '…')
        self.check(out, what)
        return out

    def check(self, out, what):
        m = BAD.search(out)
        if m:
            raise PluginError('%s: the ASA said "%s"' % (what, m.group(0).strip()[:200]),
                              detail=out[:4000], retry=False)

    def trustpoints(self):
        out = self.exec_('show running-config crypto ca trustpoint', what='listing trustpoints')
        return re.findall(r'^crypto ca trustpoint (\S+)', out, re.M)

    def ssl_lines(self):
        """[(trustpoint, the rest of the line)] of `ssl trust-point`."""
        out = self.exec_('show running-config ssl trust-point', what='reading ssl trust-point')
        got = []
        for m in re.finditer(r'^ssl trust-point (\S+)(?: (.*))?$', out, re.M):
            got.append((m.group(1), (m.group(2) or '').strip()))
        return got

    # -- read-only --------------------------------------------------------------------------
    def test(self):
        out = self.exec_('show version', what='signing in')
        if 'Adaptive Security Appliance' not in out and 'Software Version' not in out and \
                'Version' not in out:
            raise PluginError('the answer is not the ASA\'s show version: %s'
                              % out.strip()[:200], retry=False)
        first = next((ln.strip() for ln in out.splitlines() if 'Version' in ln), '')
        n = len(self.trustpoints())
        return 'signed in to %s: %s; %d trustpoint%s' % (self.c('host'), first[:120], n,
                                                       '' if n == 1 else 's')

    # -- the work ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=128)
        prefix = name_prefix(bundle, options, maxlen=128)
        tps = self.trustpoints()
        if self.unchanged(bundle, options, present=lambda: name in tps):
            return self.same(bundle, 'in the trustpoint %s' % name)
        did = []
        if name not in tps:
            pw = random_password(20)
            p12 = bundle.as_format(self.opt(options, 'pkcs12_kind', 'p12-legacy'), password=pw,
                                   alias=name)
            try:
                out = self.conf_t(['crypto ca trustpoint %s' % name, 'exit',
                                   'crypto ca import %s pkcs12 %s nointeractive' % (name, pw)] +
                                  b64_lines(p12) + ['quit'],
                                  'importing into the trustpoint %s' % name, hide=pw)
                if not re.search(r'Import PKCS12 operation completed successfully', out, re.I):
                    raise PluginError('the ASA did not say the PKCS#12 import completed: %s'
                                      % out.strip()[-300:], retry=False)
            except Exception:
                # the trustpoint made for it goes again (1.0.88: left empty, the next try saw it
                # there, imported nothing and bound ssl to a trustpoint with no certificate)
                try:
                    self.conf_t(['no crypto ca trustpoint %s noconfirm' % name],
                                'taking away the empty trustpoint %s' % name)
                except Exception:                       # noqa: BLE001
                    pass
                raise
            self.ctx.step('imported into the new trustpoint %s' % name, 'ok')
            did.append('imported %s' % name)
        else:
            self.ctx.step('the trustpoint %s is there already' % name)
        binds = self.ssl_lines()
        want = []
        for ln in lines(options.get('trust_points')):
            want.append('' if ln == '-' else ln)
        for tp, rest in binds:
            if ours(tp, prefix) and tp != name and rest not in want:
                want.append(rest)
        cmds = []
        for rest in want:
            if (name, rest) not in binds:
                cmds.append(('ssl trust-point %s %s' % (name, rest)).strip())
            for tp, r in binds:
                if r == rest and tp != name and ours(tp, prefix):
                    cmds.append(('no ssl trust-point %s %s' % (tp, r)).strip())
        if cmds:
            self.conf_t(cmds, 'switching ssl trust-point to %s' % name)
            for rest in want:
                # what it named before, said (1.0.98): the decision What happens shows
                was = [tp for tp, r in binds if r == rest and tp != name]
                self.ctx.step('ssl trust-point %s %s%s' % (
                    name, rest or '(every interface)', ' (before: %s)' % ', '.join(was)
                    if was else ''), 'ok')
            did.append('ssl trust-point: %s' % ', '.join(r or 'fallback' for r in want))
        elif not want:
            self.ctx.step('no ssl trust-point names this certificate (the first time: give the '
                          'interfaces in "ssl trust-point")', 'warn')
        else:
            self.ctx.step('ssl trust-point names %s already' % name)
        self.cleanup(prefix, name, self.keep(options), tps)
        if as_bool(self.opt(options, 'save', True), True):
            out = self.exec_('write memory', what='write memory')
            self.check(out, 'write memory')
            self.ctx.step('write memory', 'ok')
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def cleanup(self, prefix, current, keep, tps):
        if keep < 0:
            return
        gone = prune([t for t in tps if ours(t, prefix)], prefix, keep, current)
        if not gone:
            return
        try:
            used = set(tp for tp, _r in self.ssl_lines())
        except PluginError as e:
            self.ctx.step('the older trustpoints stay - ssl trust-point cannot be read: %s' % e,
                          'warn')
            return
        for old in gone:
            if old in used:
                self.ctx.step('the older trustpoint %s stays: ssl trust-point names it' % old,
                              'warn')
                continue
            try:
                self.conf_t(['no crypto ca trustpoint %s noconfirm' % old],
                            'removing the trustpoint %s' % old)
                self.ctx.step('removed the older trustpoint %s' % old)
            except PluginError as e:
                self.ctx.step('the older trustpoint %s stays: %s' % (old, e), 'warn')
