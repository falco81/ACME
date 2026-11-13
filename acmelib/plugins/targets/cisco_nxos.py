# -*- coding: utf-8 -*-
"""
Cisco NX-OS (Nexus 9000) - the HTTPS certificate of NX-API: the certificate, its key and
chain copied as PKCS#12 to bootflash: with SCP, imported into a new trustpoint through
NX-API (JSON-RPC), NX-API pointed at the trustpoint, the file and older acme trustpoints
(not the one NX-API uses) removed, the configuration saved.

    scp (legacy SCP protocol)  <file>  user@host:bootflash:<tp>.pfx      (feature scp-server)
    POST /ins  (application/json-rpc, HTTP basic)   [{"jsonrpc": "2.0", "method": "cli" |
               "cli_ascii", "params": {"cmd": ..., "version": 1}, "id": n}, ...]
      show version                                     nxos_ver_str: the NX-OS version
      show running-config | include "crypto ca trustpoint"     the trustpoints
      configure terminal ; crypto ca trustpoint <tp> ; exit ;
      crypto ca import <tp> pkcs12 bootflash:<tp>.pfx <one-time password>
      delete bootflash:<tp>.pfx no-prompt
      configure terminal ; nxapi certificate trustpoint <tp>    (NX-API restarts: the
                                                                answer may never come)
      show nxapi                                       the trustpoint NX-API uses stays
      configure terminal ; crypto ca trustpoint <old> ; delete certificate force ;
      delete ca-certificate ; exit ; no crypto ca trustpoint <old>    older acme ones
      copy running-config startup-config               last

One version: `nxapi certificate trustpoint` is there from NX-OS 10.2(3)F; the guide (NX-OS
10.2 - 10.6) has no other difference for this job. An older NX-OS is refused (its way -
`nxapi certificate httpscrt/httpskey` files of 8 kB at most - is not this module's).

Sources (the vendor guide navody/certifikaty/cisco/ios-xe-nx-os.md and what it cites):
    https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/configuration/security/cisco-nexus-9000-series-nx-os-security-configuration-guide-release-106x/m-configuring-pki.html
    https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/programmability/cisco-nexus-9000-series-nx-os-programmability-guide-106x/m-nx-api-cli.html

Less certain:
    - the answer of the JSON-RPC batch (a list of {"result" | "error", "id"}; a single
      command: one object) and the key nxos_ver_str of `show version` are NX-API's usual
      ones, not quoted by the guide;
    - `nxapi certificate` lines are not in the running configuration (the guide): after a
      `reload ascii` the trustpoint may have to be set again - a deployment with "force" does;
    - removing an older trustpoint (delete certificate force, delete ca-certificate, no crypto
      ca trustpoint) is NX-OS's usual way, not quoted; the clean-up warns, never fails;
    - that `show nxapi` names the trustpoint in use is not quoted either: a trustpoint it
      names is kept, and when it names none (and NX-API was not pointed at the new one in
      this run) no older one is removed (1.0.96).
"""
from __future__ import annotations

import base64
import re

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, text, object_name, name_prefix, ours,
    prune, random_password, http_fields, tls_fields, verify_fields, keep_field, put_scp)


def parse_nxos(v):
    """'10.6(1)' / '10.2(3)F' -> (10, 6, 1), None when not one."""
    m = re.search(r'(\d+)\.(\d+)\((\d+)\)', text(v))
    return tuple(int(x) for x in m.groups()) if m else None


def nx_words(ver):
    return '%d.%d(%d)' % tuple(ver[:3])


class CiscoNxosTarget(HttpTarget):
    kind = 'cisco_nxos'
    title = 'Cisco NX-OS (Nexus, NX-API)'
    vendor = 'Cisco'
    description = ('Copies the certificate as PKCS#12 to the Nexus\'s bootflash: over SCP, '
                   'imports it into a new trustpoint through NX-API, makes NX-API serve it '
                   '(nxapi certificate trustpoint), saves and removes the older acme '
                   'trustpoints. NX-OS 10.2(3)F - 10.6.')
    doc = 'targets.md'
    discovery = False
    min_version = (10, 2, 3)
    fields = http_fields(443, 'n9k01.example.local') + [
        field('user', 'User', 'text', required=True, default='acme',
              help='a user with the role network-admin, or a role of its own that may run '
                   'crypto, nxapi certificate, copy and configure terminal'),
        field('password', 'Password', 'secret', required=True),
        field('ssh_port', 'SSH port (SCP)', 'number', default=22,
              help='the PKCS#12 is copied with SCP (feature scp-server) by the same user'),
        field('hostkey', 'Host key', 'text', advanced=True,
              placeholder='n9k01.example.local ssh-rsa AAAA…',
              help='a known_hosts line; empty with "trust the first" takes the one seen first'),
        field('trust_first', 'Trust the first host key seen', 'bool', default=True,
              advanced=True),
    ] + tls_fields()
    deploy_fields = [
        field('nxapi', 'NX-API HTTPS', 'bool', default=True,
              help='nxapi certificate trustpoint: NX-API (nginx) restarts, its sessions are '
                   'cut'),
        field('save', 'Save the configuration (copy running-config startup-config)', 'bool',
              default=True),
        keep_field(1),
    ] + verify_fields()
    served_wait = (6, 5)

    def auth_headers(self):
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()}

    def conn(self):
        return {'host': self.c('host'), 'port': as_int(self.c('ssh_port', 22), 22),
                'user': self.c('user'), 'password': self.c('password'), 'key': None,
                'key_pass': None, 'hostkey': self.c('hostkey') or None,
                'hostkey_field': 'hostkey',
                'trust_first': as_bool(self.c('trust_first', True), True),
                'timeout': as_int(self.c('timeout', 30), 30), 'via': '',
                'scp_legacy': True}

    # -- NX-API -----------------------------------------------------------------------------
    def rpc(self, cmds, what, ascii=False, hide=None):
        """The commands in one JSON-RPC batch -> [result]; an error of any is raised."""
        body = [{'jsonrpc': '2.0', 'method': 'cli_ascii' if ascii else 'cli',
                 'params': {'cmd': c, 'version': 1}, 'id': i + 1} for i, c in enumerate(cmds)]
        try:
            st, hd, d = self.req('POST', '/ins', body, {'Content-Type': 'application/json-rpc'},
                                 what=what)
        except PluginError as e:
            raise PluginError(str(e).replace(hide, '…') if hide else str(e),
                              detail=None if hide else e.detail, retry=e.retry)
        items = d if isinstance(d, list) else [d]
        out = []
        for it in items:
            if not isinstance(it, dict):
                continue
            if it.get('error'):
                err = it['error']
                msg = text((err.get('data') or {}).get('msg') if isinstance(err, dict) and
                           isinstance(err.get('data'), dict) else '') or \
                    text(err.get('message') if isinstance(err, dict) else err)
                if hide:
                    msg = msg.replace(hide, '…')
                raise PluginError('%s: NX-OS said "%s"' % (what, msg.strip()[:200]),
                                  detail=None if hide else text(it)[:4000], retry=False)
            out.append(it.get('result'))
        return out

    def version(self):
        r = self.rpc(['show version'], 'reading the version')
        body = (r[0] or {}).get('body') if r and isinstance(r[0], dict) else {}
        body = body if isinstance(body, dict) else {}
        said = body.get('nxos_ver_str') or body.get('kickstart_ver_str') or \
            body.get('sys_ver_str') or ''
        return parse_nxos(said), text(said), body

    def check_version(self, ver, said):
        if ver is None:
            self.ctx.step('the NX-OS version cannot be read - nxapi certificate trustpoint '
                          '(10.2(3)F and later) is used', 'warn')
            return
        if ver < self.min_version:
            raise PluginError('this Nexus runs NX-OS %s - `nxapi certificate trustpoint` is '
                              'there from 10.2(3)F; upgrade it, or put the certificate there '
                              'by hand (nxapi certificate httpscrt / httpskey)' % said,
                              retry=False)
        if ver[:2] > (10, 6):
            self.ctx.step('NX-OS %s is newer than the documents this module was checked '
                          'against (10.6)' % said, 'warn')

    def trustpoints(self):
        r = self.rpc(['show running-config | include "crypto ca trustpoint"'],
                     'reading the trustpoints', ascii=True)
        out = text((r[0] or {}).get('msg') if r and isinstance(r[0], dict) else '')
        return re.findall(r'^\s*crypto ca trustpoint (\S+)', out, re.M)

    # -- read-only --------------------------------------------------------------------------
    def test(self):
        ver, said, body = self.version()
        self.check_version(ver, said)
        n = len(self.trustpoints())
        return 'signed in to %s (%s): NX-OS %s; %d trustpoint%s' % (
            self.c('host'), body.get('chassis_id') or body.get('host_name') or 'Nexus',
            said or '?', n, '' if n == 1 else 's')

    def served_places(self, options):
        if not self.c('host') or not as_bool((options or {}).get('nxapi', True), True):
            return []
        return [(self.c('host'), as_int(self.c('port', 443), 443))]

    # -- the work ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=60)
        prefix = name_prefix(bundle, options, maxlen=60)
        tps = self.trustpoints()
        if self.unchanged(bundle, options, present=lambda: name in tps):
            return self.same(bundle, 'in the trustpoint %s' % name)
        ver, said, _b = self.version()
        self.check_version(ver, said)
        did = []
        if name not in tps:
            pw = random_password(20)
            path = 'bootflash:%s.pfx' % name
            with self.ctx.ssh(self.conn()) as s:
                put_scp(s, bundle.as_format('pfx', password=pw, alias=name), path)
            self.ctx.step('copied the PKCS#12 to %s' % path)
            try:
                self.rpc(['configure terminal', 'crypto ca trustpoint %s' % name, 'exit',
                          'crypto ca import %s pkcs12 %s %s' % (name, path, pw)],
                         'importing %s' % name, hide=pw)
            finally:
                try:
                    self.rpc(['delete %s no-prompt' % path], 'deleting the PKCS#12')
                except PluginError as e:
                    self.ctx.step('the file %s stays: %s' % (path, e), 'warn')
            self.ctx.step('imported into the new trustpoint %s' % name, 'ok')
            did.append('imported %s' % name)
        else:
            self.ctx.step('the trustpoint %s is there already' % name)
        switched = False
        if as_bool(self.opt(options, 'nxapi', True), True):
            # NX-API restarts with the new certificate and the answer may be cut off
            self.mark_pending(bundle)
            try:
                self.rpc(['configure terminal', 'nxapi certificate trustpoint %s' % name],
                         'pointing NX-API at %s' % name)
                self.ctx.step('NX-API uses %s (it restarts)' % name, 'ok')
                switched = True
            except PluginError as e:
                if 'NX-OS said' in str(e):
                    raise
                self.ctx.step('NX-API restarted before it answered (%s) - the test of what is '
                              'served says whether it took %s' % (e, name), 'warn')
            self.done_pending()
            did.append('NX-API')
        # after the switch: the older trustpoint is the one NX-API served until now (one the
        # restart keeps from answering stays until the next deployment)
        self.cleanup(prefix, name, self.keep(options), tps, switched)
        # saved last (1.0.96): before, the startup configuration had the import but not the
        # trustpoint of NX-API nor the removal of the older ones
        if as_bool(self.opt(options, 'save', True), True):
            self.rpc(['copy running-config startup-config'], 'saving the configuration')
            self.ctx.step('copy running-config startup-config', 'ok')
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def nxapi_uses(self, tps):
        """The trustpoints `show nxapi` names (the `nxapi certificate` lines are not in the
        running configuration); None when it cannot be read."""
        try:
            r = self.rpc(['show nxapi'], 'reading the NX-API settings', ascii=True)
        except PluginError as e:
            self.ctx.debug('show nxapi: %s' % e)
            return None
        out = text((r[0] or {}).get('msg') if r and isinstance(r[0], dict) else '')
        return {t for t in tps if re.search(r'(?<![\w.-])%s(?![\w.-])' % re.escape(t), out)}

    def cleanup(self, prefix, current, keep, tps, switched=False):
        if keep < 0:
            return
        gone = prune([t for t in tps if ours(t, prefix)], prefix, keep, current)
        if not gone:
            return
        # never the trustpoint NX-API serves (1.0.96): with "Point NX-API at it" off, or the
        # switch cut off by the restart, that is an older acme one - removing it took HTTPS
        # of NX-API away
        used = self.nxapi_uses(tps)
        if used is None or (not used and not switched):
            self.ctx.step('the older trustpoints stay - which one NX-API uses cannot be read '
                          '(show nxapi)', 'warn')
            return
        for old in [t for t in gone if t in used]:
            self.ctx.step('the older trustpoint %s stays: NX-API uses it' % old, 'warn')
        for old in [t for t in gone if t not in used]:
            try:
                self.rpc(['configure terminal', 'crypto ca trustpoint %s' % old,
                          'delete certificate force', 'delete ca-certificate', 'exit',
                          'no crypto ca trustpoint %s' % old],
                         'removing the trustpoint %s' % old)
                self.ctx.step('removed the older trustpoint %s' % old)
            except PluginError as e:
                self.ctx.step('the older trustpoint %s stays: %s' % (old, e), 'warn')
