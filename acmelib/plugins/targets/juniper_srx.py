# -*- coding: utf-8 -*-
"""
Juniper SRX (Junos OS) through its REST API (the XML RPCs over HTTPS): the
certificate and its key written to the device as files, loaded into the PKI
under a new certificate id, the services asked switched to that id in one
committed change, the older acme ids removed, the files emptied.

    https://<srx>:3443, HTTP basic on every request (set system services rest https ...)
    POST /rpc?stop-on-error=1   the RPCs as XML in the body:
      <file-put><filename>/var/tmp/<id>.crt</filename><permission>0600</permission>
        <encoding>base64</encoding><delete-if-exist/><file-contents>...</file-contents></file-put>
      <load-pki-local-certificate><certificate-id>, <filename>, <key>
      <lock-configuration/>
      <load-configuration action="set" format="text"><configuration-set>
        set system services web-management https pki-local-certificate <id>
        set services ssl termination profile <p> server-certificate <id> ...
      </configuration-set></load-configuration>
      <commit-configuration><log>...</log></commit-configuration>
      <unlock-configuration/>
      <clear-pki-local-certificate><certificate-id>  and  <clear-pki-key-pair><certificate-id>
    GET  /rpc/get-pki-local-certificate        the local certificates (their identifiers)
    GET  /rpc/get-software-information         for the test

Checked against (the user's collection of the vendor's documents,
api-docs/juniper_srx/notes.md and the Junos YANG RPC models beside it,
junos-es-rpc-request / -clear / -security / -file-mgd @2023-01-01.yang), quoting:
    https://www.juniper.net/documentation/us/en/software/junos/rest-api/topics/task/rest-api-submitting-post-request.html
    https://www.juniper.net/documentation/us/en/software/junos/rest-api/topics/task/rest-api-submitting-get-request.html
    https://www.juniper.net/documentation/us/en/software/junos/rest-api/topics/task/rest-api-configuring.html
    https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/request-security-pki-ca-certificate-load-high-end.html
    https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-pki-local-certificate-security.html
    https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/clear-security-pki-local-certificate-id.html
    https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/https-edit-system.html
    https://juniper.net/documentation/us/en/software/junos/application-identification/authentication-firewall/topics/ref/statement/server-certificate-edit-services-ssl-termination-profile.html
    https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/security-edit-certificate.html
    https://www.juniper.net/documentation/us/en/software/junos/automation-scripting/topics/example/junos-script-automation-op-script-exporting-files.html
    https://www.juniper.net/documentation/us/en/software/junos/junos-xml-protocol/topics/task/junos-xml-protocol-configuration-data-uploading-stream.html
    https://www.juniper.net/documentation/us/en/software/junos/junos-xml-protocol/topics/ref/tag/junos-xml-protocol-commit-configuration.html
    https://github.com/Juniper/yang/tree/master/23.4/23.4R1/native/conf-and-rpcs/junos-es/rpc/models

Less certain:
    - file-put is documented for op scripts and NETCONF; that the REST API runs it is only
      what the REST page says of "any Junos OS rpc command";
    - there is no file-delete in the documents: after loading, acme writes the two files
      again with nothing in them (file-put delete-if-exist), so no key stays in /var/tmp;
    - the certificate file holds the certificate and then the chain (the PKI page: "The
      server certificate must appear before the chained certificates in the combined file");
      whether J-Web sends the chain from it is not found (choose "only the certificate");
    - loading over an existing id is not documented: each renewal is a new id (32 characters
      at most, no ".", "/", "%" or space);
    - the error words of the PKI RPCs are not documented: an <xnm:error> or <error-message>
      in the answer fails the step;
    - when the commit fails, the candidate configuration may still hold acme's lines
      (rollback 0 in the CLI);
    - removing an id still named in the configuration is not documented: acme removes only
      older acme ids beyond "keep", after the switch was committed; an IKE policy keeps a list,
      so the older acme id is deleted from it;
    - chassis cluster / multinode HA (a second node's PKI) is not looked at.
"""
from __future__ import annotations

import base64
import hashlib
import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, text, lines, label_of, stamp, short_serial, ours,
    prune, http_fields, tls_fields, verify_fields, keep_field)

TMPDIR = '/var/tmp'


def srx_id(bundle, options):
    """acme-<label>-<YYYYMMDD>-<serial>, 32 characters at most, no '.' (Junos ids)."""
    tail = '-%s-%s' % (stamp(bundle), short_serial(bundle, 6))
    room = 32 - len('acme-') - len(tail)
    lab = re.sub(r'[^a-z0-9_-]', '-', label_of(bundle, options, 200)).strip('-') or 'cert'
    if len(lab) > room:
        lab = lab[:room - 5].rstrip('-_') + '-' + hashlib.sha1(lab.encode()).hexdigest()[:4]
    return 'acme-%s%s' % (lab, tail)


def srx_prefix(bundle, options):
    n = srx_id(bundle, options)
    return n[:-(len(stamp(bundle)) + 6 + 1)]


def strip_ns(root):
    for el in root.iter():
        if isinstance(el.tag, str) and '}' in el.tag:
            el.tag = el.tag.split('}', 1)[1]
    return root


def errors_of(raw):
    """The error messages in a Junos XML answer (one RPC or a multipart of several)."""
    s = text(raw)
    out = []
    for m in re.finditer(r'<(?:\w+:)?error\b[^>]*>(.*?)</(?:\w+:)?error>', s, re.S):
        msg = re.search(r'<(?:\w+:)?message>(.*?)</(?:\w+:)?message>', m.group(1), re.S) or \
            re.search(r'<error-message>(.*?)</error-message>', m.group(1), re.S)
        out.append(re.sub(r'\s+', ' ', (msg.group(1) if msg else
                                        re.sub(r'<[^>]+>', ' ', m.group(1)))).strip())
    for m in re.finditer(r'<error-message>(.*?)</error-message>', s, re.S):
        w = re.sub(r'\s+', ' ', m.group(1)).strip()
        if w not in out:
            out.append(w)
    return [w for w in out if w]


class JuniperSrxTarget(HttpTarget):
    kind = 'juniper_srx'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Juniper SRX (Junos REST API)'
    vendor = 'Juniper Networks'
    description = ('Loads the certificate into the Junos PKI of an SRX under a new id through the '
                   'REST API, switches web management, SSL profiles or IKE policies to it in one '
                   'commit and removes the older one.')
    doc = 'targets.md'
    fields = http_fields(3443, 'srx.example.local') + [
        field('user', 'User', 'text', required=True,
              help='a login class with maintenance, security and configure rights'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('web_management', 'J-Web / web management (HTTPS)', 'bool', default=True,
              help='set system services web-management https pki-local-certificate'),
        field('rest_api', 'The REST API itself', 'bool', default=False,
              help='set system services rest https server-certificate - the API acme speaks to'),
        field('ssl_termination', 'SSL termination profiles', 'list', placeholder='tls-in',
              help='one a line: services ssl termination profile <name> server-certificate'),
        field('ssl_proxy', 'SSL proxy profiles', 'list', placeholder='rev-proxy',
              help='one a line: services ssl proxy profile <name> server-certificate'),
        field('ike_policies', 'IKE policies', 'list', placeholder='ike-pol-1',
              help='one a line: security ike policy <name> certificate local-certificate (the '
                   'older acme id is deleted from it)'),
        field('cert_file', 'The certificate file holds', 'select', default='fullchain',
              advanced=True, options=[['fullchain', 'the certificate and its chain'],
                                      ['cert', 'only the certificate']]),
        keep_field(1),
    ] + verify_fields()

    def auth_headers(self):
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()}

    # -- RPCs -------------------------------------------------------------------------------
    def rpc(self, xml, what, hide=None):
        try:
            st, hd, d = self.req('POST', '/rpc?stop-on-error=1', xml.encode(),
                                 {'Content-Type': 'application/xml',
                                  'Accept': 'application/xml'}, what=what)
        except PluginError as e:
            raise PluginError(str(e), detail=None if hide else e.detail, retry=e.retry)
        raw = text(d)
        errs = errors_of(raw)
        if errs:
            raise PluginError('%s: Junos said %s' % (what, '; '.join(errs)[:300]),
                              detail=None if hide else raw[:4000], retry=False)
        return raw

    def get(self, rpc, what):
        st, hd, d = self.req('GET', '/rpc/%s' % rpc, headers={'Accept': 'application/xml'},
                             what=what)
        raw = text(d)
        errs = errors_of(raw)
        if errs:
            raise PluginError('%s: Junos said %s' % (what, '; '.join(errs)[:300]),
                              detail=raw[:4000], retry=False)
        try:
            return strip_ns(ET.fromstring(re.sub(r'^\s*<\?xml[^>]*\?>', '', raw.strip()) or
                                          '<x/>'))
        except ET.ParseError:
            return strip_ns(ET.fromstring('<x>%s</x>' % re.sub(r'<\?xml[^>]*\?>', '', raw)))

    def local_ids(self):
        root = self.get('get-pki-local-certificate', 'listing the local certificates')
        out = []
        for el in root.iter('identifier'):
            if el.text and el.text.strip() not in out:
                out.append(el.text.strip())
        return out

    def put_file(self, path, data, what, hide=True):
        return self.rpc('<file-put><filename>%s</filename><permission>0600</permission>'
                        '<encoding>base64</encoding><delete-if-exist/>'
                        '<file-contents>%s</file-contents></file-put>'
                        % (escape(path), base64.b64encode(data).decode()), what, hide=hide)

    # -- read-only --------------------------------------------------------------------------
    def test(self):
        root = self.get('get-software-information', 'signing in')
        host = root.findtext('.//host-name') or self.c('host')
        ver = root.findtext('.//junos-version') or root.findtext('.//package-information/comment')
        ids = self.local_ids()
        return 'signed in to %s (Junos %s); %d local certificate%s' % (
            host, ver or '?', len(ids), '' if len(ids) == 1 else 's')

    # -- the work ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        cid = srx_id(bundle, options)
        prefix = srx_prefix(bundle, options)
        ids = self.local_ids()
        if self.unchanged(bundle, options, present=lambda: cid in ids):
            return self.same(bundle, 'as %s' % cid)
        did = []
        if cid not in ids:
            crt, key = '%s/%s.crt' % (TMPDIR, cid), '%s/%s.key' % (TMPDIR, cid)
            pem = bundle.as_format('fullchain-pem' if self.opt(options, 'cert_file') !=
                                   'cert' else 'cert-pem')
            try:
                self.put_file(crt, pem, 'writing %s' % crt)
                self.put_file(key, bundle.as_format('key-pem'), 'writing %s' % key)
                self.ctx.step('wrote %s and %s' % (crt, key))
                self.rpc('<load-pki-local-certificate><certificate-id>%s</certificate-id>'
                         '<filename>%s</filename><key>%s</key></load-pki-local-certificate>'
                         % (escape(cid), escape(crt), escape(key)),
                         'loading %s into the PKI' % cid)
            finally:
                for p in (key, crt):
                    try:
                        self.put_file(p, b'\n', 'emptying %s' % p)
                    except PluginError as e:
                        self.ctx.step('%s could not be emptied: %s' % (p, e), 'warn')
            self.ctx.step('loaded the local certificate %s' % cid, 'ok')
            did.append('loaded %s' % cid)
        else:
            self.ctx.step('the local certificate %s is there already' % cid)
        sets = []
        if as_bool(self.opt(options, 'web_management', True), True):
            sets.append('set system services web-management https pki-local-certificate %s' % cid)
        if as_bool(self.opt(options, 'rest_api', False)):
            sets.append('set system services rest https server-certificate %s' % cid)
        for p in lines(options.get('ssl_termination')):
            sets.append('set services ssl termination profile %s server-certificate %s'
                        % (self.word(p), cid))
        for p in lines(options.get('ssl_proxy')):
            sets.append('set services ssl proxy profile %s server-certificate %s'
                        % (self.word(p), cid))
        olds = [i for i in ids if ours(i, prefix) and i != cid]
        for p in lines(options.get('ike_policies')):
            sets.append('set security ike policy %s certificate local-certificate %s'
                        % (self.word(p), cid))
            for o in olds:
                sets.append('delete security ike policy %s certificate local-certificate %s'
                            % (self.word(p), o))
        if sets:
            self.commit(sets, cid)
            did.append('committed %d line%s' % (len(sets), '' if len(sets) == 1 else 's'))
        else:
            self.ctx.step('nothing is switched to %s (no service asked)' % cid, 'warn')
        self.cleanup(prefix, cid, self.keep(options), ids)
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % cid

    @staticmethod
    def word(s):
        s = text(s).strip()
        if not re.match(r'^[A-Za-z0-9_.:-]{1,64}$', s):
            raise PluginError('"%s" is not a Junos name' % s, retry=False)
        return s

    def commit(self, sets, cid):
        body = ('<lock-configuration/>'
                '<load-configuration action="set" format="text"><configuration-set>%s'
                '</configuration-set></load-configuration>'
                '<commit-configuration><log>%s</log></commit-configuration>'
                '<unlock-configuration/>' % (escape('\n'.join(sets)),
                                             escape('acme: %s' % cid)))
        try:
            self.rpc(body, 'committing the switch to %s' % cid)
        except PluginError as e:
            try:
                self.rpc('<unlock-configuration/>', 'unlocking the configuration')
            except PluginError:
                pass
            raise PluginError('%s (the candidate configuration may hold acme\'s lines: '
                              '"rollback 0" in the CLI)' % e, detail=e.detail, retry=False)
        for s in sets:
            self.ctx.step(s, 'ok')

    def cleanup(self, prefix, current, keep, ids):
        if keep < 0:
            return
        for old in prune([i for i in ids if ours(i, prefix)], prefix, keep, current):
            try:
                self.rpc('<clear-pki-local-certificate><certificate-id>%s</certificate-id>'
                         '</clear-pki-local-certificate>' % escape(old),
                         'removing the local certificate %s' % old)
                self.rpc('<clear-pki-key-pair><certificate-id>%s</certificate-id>'
                         '</clear-pki-key-pair>' % escape(old),
                         'removing the key pair %s' % old)
                self.ctx.step('removed the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')
