# -*- coding: utf-8 -*-
"""
FortiWeb (REST API v2.0): the certificate imported as a local certificate
under a dated name, its intermediates as an intermediate CA group, the
server policies asked for pointed at both, older acme certificates no policy
uses deleted.

    Authorization: base64({"username", "password"[, "vdom"]})   (with every request)
    GET    /api/v2.0/system/status.systemstatus                     (Test)
    GET    /api/v2.0/cmdb/system/certificate.local[?mkey=<name>]    there already? the older
    POST   /api/v2.0/system/certificate.local.json_cert
           {"name", "type": "certificate", "status": "ok", "flag": 0, "is-hsm": "no",
            "passwd": "", "private-key", "certificate"}
    POST   /api/v2.0/system/certificate.intermediateca   multipart: type=localPC, uploadedFile
    POST   /api/v2.0/cmdb/system/certificate.intermediate-certificate-group  {"data": {"name"}}
    POST   /api/v2.0/cmdb/system/certificate.intermediate-certificate-group/members?mkey=<group>
           {"data": {"name": <intermediate CA>}}
    GET    /api/v2.0/cmdb/server-policy/policy[?mkey=<policy>]     the policies (the list)
    PUT    /api/v2.0/cmdb/server-policy/policy?mkey=<policy>
           {"data": <the policy as read, "certificate" and "intermediate-certificate-group" set>}
    DELETE /api/v2.0/cmdb/system/certificate.local?mkey=<name>

Checked against (the user's collection of the vendor's documents, api-docs/fortinet/):
    fortiweb.md (and notes.md) - quotes from Fortinet's official Ansible collection
      https://github.com/fortinet-ansible-dev/ansible-galaxy-fortiweb-collection
      (plugins/httpapi/fwebos.py; plugins/modules/fwebos_certificate_local_import_certificate.py,
      fwebos_server_policy.py, fwebos_certificate_intermediate_ca*.py) and Fortinet's
      Technical Tips
      https://community.fortinet.com/t5/FortiWeb/Technical-Tip-How-to-upload-the-local-certificate-to-FortiWeb/ta-p/342766
      https://community.fortinet.com/fortiweb-40/technical-tip-how-to-update-server-policy-certificate-via-rest-api-226216
      https://community.fortinet.com/fortiweb-40/technical-tip-how-to-generate-api-authorization-token-for-fortiweb-228191

Less certain (the reference is on fndn.fortinet.net, behind a sign-in):
    - the name an intermediate CA gets when uploaded (taken from the file's name, as the
      Technical Tip's local certificate is) and the body of a group member ({"name"}) - the
      Ansible module's parameters, not a quoted request; Chain "a group of mine" or "none"
      leaves this out;
    - the shape of the answers (lists under "results"; an "errcode" below 0 an error, -3
      "not there", as the Ansible module reads it);
    - that a change in the cmdb takes effect at once (no save call was found).
"""
from __future__ import annotations

import base64
import json
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, text, object_name, name_prefix, ours, prune,
    http_fields, tls_fields, verify_fields, keep_field, chain_list, chain_id, multipart)

API = '/api/v2.0'


def q(s):
    return urllib.parse.quote(text(s), safe='')


def results(d):
    """The objects of an answer: "results" a list, or one object."""
    r = d.get('results') if isinstance(d, dict) else None
    if isinstance(r, list):
        return [x for x in r if isinstance(x, dict)]
    if isinstance(r, dict) and not ('errcode' in r and len(r) <= 2):
        return [r]
    return []


def errcode(d):
    r = d.get('results') if isinstance(d, dict) else None
    try:
        return int((r or {}).get('errcode')) if isinstance(r, dict) else 0
    except (TypeError, ValueError):
        return 0


class FortiWebTarget(HttpTarget):
    kind = 'fortiweb'
    discovery = False       # nothing to find: FortiWeb lists no VDOMs through the calls acme makes
    title = 'FortiWeb'
    vendor = 'Fortinet'
    description = ('Imports the certificate into FortiWeb as a local certificate, with its '
                   'intermediates as a group, and points server policies at it; deletes older '
                   'ones acme put there.')
    doc = 'targets.md'
    fields = http_fields(443, 'fortiweb.example.local') + [
        field('user', 'User', 'text', required=True, default='admin',
              help='an administrator: FortiWeb has no API tokens of its own'),
        field('password', 'Password', 'secret', required=True),
        field('vdom', 'VDOM', 'text', placeholder='root',
              help='empty on a FortiWeb without administrative domains'),
    ] + tls_fields()
    deploy_fields = [
        field('policy', 'Server policy', 'catalog', catalog='policies', autoload=False,
              help='the server policy (HTTPS) to use the certificate; picked from the list or '
                   'typed'),
        field('policies', 'More server policies', 'list', placeholder='www-policy',
              help='one a line: more server policies'),
        field('chain', 'Intermediates', 'select', default='group',
              options=[['group', 'uploaded by acme as a group acme-chain-…'],
                       ['existing', 'a group of mine (below)'],
                       ['none', 'none: the policy keeps its own']]),
        field('intermediate_group', 'Intermediate CA group', 'text',
              show_if={'chain': ['existing']},
              help='the intermediate certificate group the policies are to use'),
        keep_field(1),
    ] + verify_fields()
    actions = [{'key': 'look', 'label': 'List the server policies',
                'help': 'Lists the server policies and the certificates they use - it changes '
                        'nothing.',
                'changes': False}]

    def auth_headers(self):
        cred = {'username': text(self.c('user')), 'password': text(self.c('password'))}
        if text(self.c('vdom')).strip():
            cred['vdom'] = text(self.c('vdom')).strip()
        return {'Authorization': base64.b64encode(json.dumps(cred).encode()).decode()}

    def api(self, method, path, body=None, ok=None, what=None, headers=None):
        st, hd, d = self.req(method, API + path, body, headers, ok=ok, what=what)
        d = d if isinstance(d, (dict, list)) else {}
        code = errcode(d)
        if code < 0 and code != -3:
            raise PluginError('%s: FortiWeb said error %d' % (what or path, code),
                              detail=text(d)[:4000])
        return st, d

    def local_certs(self):
        st, d = self.api('GET', '/cmdb/system/certificate.local',
                         what='listing the local certificates')
        return [text(x.get('name') or x.get('mkey')) for x in results(d)
                if x.get('name') or x.get('mkey')]

    def has_cert(self, name):
        st, d = self.api('GET', '/cmdb/system/certificate.local?mkey=%s' % q(name),
                         ok=range(200, 600), what='looking for %s' % name)
        if st != 200 or errcode(d) < 0:
            return False
        return any(text(x.get('name') or x.get('mkey')) == name for x in results(d))

    def policies(self):
        st, d = self.api('GET', '/cmdb/server-policy/policy', what='listing the server policies')
        return results(d)

    def test(self):
        st, d = self.api('GET', '/system/status.systemstatus', what='signing in')
        r = (results(d) or [{}])[0]
        n = len(self.local_certs())
        return 'signed in to FortiWeb %s%s; %d local certificate%s' % (
            self.c('host'), ', %s' % r['version'] if r.get('version') else '',
            n, '' if n == 1 else 's')

    def catalog(self, key):
        if key != 'policies':
            raise PluginError('there is no list called %s here' % key, retry=False)
        opts = [[text(p.get('name')), '%s%s' % (p.get('name'), ' (%s)' % p['certificate']
                                                if p.get('certificate') else '')]
                for p in self.policies() if p.get('name')]
        return {'options': opts, 'sets': {}, 'said': '%d server policies' % len(opts)}

    def action(self, key):
        if key != 'look':
            return HttpTarget.action(self, key)
        pols = self.policies()
        for p in pols:
            self.ctx.step('%s: %s%s' % (p.get('name'), p.get('certificate') or '-',
                                        '; intermediates %s' % p['intermediate-certificate-group']
                                        if p.get('intermediate-certificate-group') else ''))
        return '%d server polic%s' % (len(pols), 'y' if len(pols) == 1 else 'ies')

    def chain_group(self, bundle, options):
        """The intermediate CA group the policies get, or None to leave theirs."""
        mode = text(options.get('chain') or 'group')
        if mode == 'none':
            return None
        if mode == 'existing':
            g = text(options.get('intermediate_group')).strip()
            if not g:
                raise PluginError('Intermediates "a group of mine" needs the group\'s name',
                                  retry=False)
            return g
        chain = chain_list(bundle)
        if not chain:
            return None
        group = 'acme-chain-%s' % chain_id(''.join(chain))
        st, d = self.api('GET', '/cmdb/system/certificate.intermediate-certificate-group'
                         '?mkey=%s' % q(group), ok=range(200, 600),
                         what='looking for the group %s' % group)
        if st == 200 and errcode(d) == 0 and results(d):
            return group
        names = []
        for pem in chain:
            n = 'acme-ca-%s' % chain_id(pem)
            body, ctype = multipart([('type', 'localPC'),
                                     ('uploadedFile', (n + '.crt', pem.encode(),
                                                       'application/x-x509-ca-cert'))])
            try:
                self.api('POST', '/system/certificate.intermediateca', body,
                         headers={'Content-Type': ctype},
                         what='uploading the intermediate CA %s' % n)
            except PluginError as e:
                if 'exist' not in text(e).lower() and 'duplicat' not in text(e).lower():
                    raise
            names.append(n)
        self.api('POST', '/cmdb/system/certificate.intermediate-certificate-group',
                 {'data': {'name': group}}, what='making the intermediate group %s' % group)
        for n in names:
            self.api('POST', '/cmdb/system/certificate.intermediate-certificate-group/members'
                     '?mkey=%s' % q(group), {'data': {'name': n}},
                     what='putting %s into %s' % (n, group))
        self.ctx.step('made the intermediate CA group %s (%s)' % (group, ', '.join(names)), 'ok')
        return group

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=63)
        prefix = name_prefix(bundle, options, maxlen=63)
        there = self.has_cert(name)
        if self.unchanged(bundle, options, present=lambda: there):
            return self.same(bundle, 'as %s' % name)
        did = []
        if not there:
            self.api('POST', '/system/certificate.local.json_cert', {
                'name': name, 'type': 'certificate', 'status': 'ok', 'flag': 0,
                'is-hsm': 'no', 'passwd': '',
                'private-key': text(bundle.as_format('key-pem')).strip(),
                'certificate': text(bundle.as_format('cert-pem')).strip()},
                what='importing %s' % name)
            self.ctx.step('imported the local certificate %s' % name, 'ok')
            did.append('imported %s' % name)
        else:
            self.ctx.step('the local certificate %s is there already' % name)
        refs = []
        one = text(options.get('policy')).strip()
        if one:
            refs.append(one)
        refs += [r for r in lines(options.get('policies')) if r not in refs]
        group = self.chain_group(bundle, options) if refs else None
        for ref in refs:
            st, d = self.api('GET', '/cmdb/server-policy/policy?mkey=%s' % q(ref),
                             ok=range(200, 600), what='reading the server policy %s' % ref)
            got = results(d) if st == 200 else []
            if not got or errcode(d) == -3:
                if st not in (200, 404) and errcode(d) != -3:
                    raise PluginError('reading the server policy %s: FortiWeb said %d' % (
                        ref, st), detail=text(d)[:4000])
                raise PluginError('FortiWeb has no server policy "%s"' % ref, retry=False)
            pol = dict(got[0])
            want = dict(pol, certificate=name)
            if group:
                want['intermediate-certificate-group'] = group
            if want == pol:
                self.ctx.step('the server policy %s uses %s already' % (ref, name))
                continue
            self.api('PUT', '/cmdb/server-policy/policy?mkey=%s' % q(ref), {'data': want},
                     what='pointing the server policy %s at %s' % (ref, name))
            self.ctx.step('the server policy %s uses %s' % (ref, name), 'ok')
            did.append(ref)
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            gone = prune([n for n in self.local_certs() if ours(n, prefix)], prefix, keep,
                         current)
            used = set(text(p.get('certificate')) for p in self.policies()) if gone else set()
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        for old in gone:
            if old in used:
                self.ctx.step('the older %s stays: a server policy still uses it' % old, 'warn')
                continue
            try:
                self.api('DELETE', '/cmdb/system/certificate.local?mkey=%s' % q(old),
                         what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')
