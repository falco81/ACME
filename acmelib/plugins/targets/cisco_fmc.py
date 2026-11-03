# -*- coding: utf-8 -*-
"""
Cisco Secure Firewall Management Center (FMC REST API): the certificate
and its key imported as a new Internal Certificate object - changing one in
place is not reliable - the decryption rules (Decrypt - Known Key) of the
policies asked for switched from the older acme object to it, the changes
deployed to the devices, older acme objects no rule uses deleted.

    POST /api/fmc_platform/v1/auth/generatetoken   (HTTP basic, empty body) -> headers
         X-auth-access-token, DOMAIN_UUID; then X-auth-access-token: <token>
    GET  /api/fmc_config/v1/domain/<d>/object/internalcertificates?limit=1000&offset=N
    POST /api/fmc_config/v1/domain/<d>/object/internalcertificates
         {"name", "type": "InternalCertificate", "cert", "privateKey"}
    GET  /api/fmc_config/v1/domain/<d>/policy/decryptionpolicies              (the list)
    GET  /api/fmc_config/v1/domain/<d>/policy/decryptionpolicies/<p>/decryptionpolicyrules
         ?expanded=true&limit=1000
    PUT  /api/fmc_config/v1/domain/<d>/policy/decryptionpolicies/<p>/decryptionpolicyrules/<r>
         the rule as read, each reference {"id": <older acme object>} made the new one's
    GET  /api/fmc_config/v1/domain/<d>/deployment/deployabledevices?expanded=true
    POST /api/fmc_config/v1/domain/<d>/deployment/deploymentrequests
         {"type": "DeploymentRequest", "ignoreWarning": true, "deviceList": [ids]}
    DELETE /api/fmc_config/v1/domain/<d>/object/internalcertificates/<id>

Checked against (the user's collection of the vendor's documents, api-docs/cisco_fmc/notes.md):
    https://www.cisco.com/c/en/us/td/docs/security/firepower/760/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_760.html
    https://www.cisco.com/c/en/us/td/docs/security/firepower/760/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_760/Connecting_With_A_Client.html
    https://www.cisco.com/c/en/us/td/docs/security/firepower/760/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_760/Objects_In_The_REST_API.html
    https://www.cisco.com/c/en/us/td/docs/security/firepower/760/api/REST/secure_firewall_management_center_rest_api_quick_start_guide_760.pdf
    https://www.cisco.com/c/en/us/support/docs/security/firepower-management-center/215918-how-to-generate-authentication-token-for.html
    https://github.com/CiscoDevNet/terraform-provider-fmc (gen/definitions/internal_certificate.yaml,
      internal/provider/model_fmc_internal_certificate.go, gen/definitions/device_deploy.yaml)
    https://docs.manage.security.cisco.com/cdfmc/c_known_key_decryption.html

Less certain (the OpenAPI specification is only on the FMC itself, /api/api-explorer):
    - the body of an Internal Certificate is from Cisco's Terraform provider (FMC 7.4 and
      later); whether "cert" may hold the chain is not said - only the certificate is sent;
    - the field of a decryption rule that names the certificate is not documented: acme
      looks through each rule for a reference {"id": <an older acme object>} wherever it
      is and puts the new object's id and name there;
    - the shape of deployabledevices (a device's id taken from "device"."id", or "id");
    - logging out is not documented (the token lives 30 minutes).
"""
from __future__ import annotations

import base64
import copy
import json
import urllib.parse

from acmelib.plugins.base import Plugin
from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, as_int, text, object_name, name_prefix,
    ours, prune, http_fields, tls_fields, verify_fields, keep_field)


def q(s):
    return urllib.parse.quote(text(s), safe='')


def swap(node, old_ids, new):
    """Every reference {"id": <one of old_ids>, ...} in a rule made the new object's.
    -> how many were changed."""
    n = 0
    if isinstance(node, dict):
        if text(node.get('id')) in old_ids:
            node['id'] = new['id']
            if 'name' in node:
                node['name'] = new['name']
            n += 1
        for k, v in node.items():
            if k not in ('links', 'metadata'):
                n += swap(v, old_ids, new)
    elif isinstance(node, list):
        for v in node:
            n += swap(v, old_ids, new)
    return n


def refers(node, ids):
    s = json.dumps(node)
    return any('"%s"' % i in s for i in ids)


class CiscoFmcTarget(HttpTarget):
    kind = 'cisco_fmc'
    title = 'Cisco Secure Firewall Management Center (FMC)'
    vendor = 'Cisco'
    description = ('Imports the certificate into FMC as a new Internal Certificate, switches '
                   'the decryption rules from the older one to it, deploys the change and '
                   'deletes the older object.')
    doc = 'targets.md'
    fields = http_fields(443, 'fmc.example.local') + [
        field('user', 'User', 'text', required=True, default='api-acme',
              help='an account for the API only: the same account signed in to the web '
                   'interface is signed out'),
        field('password', 'Password', 'secret', required=True),
        field('domain_uuid', 'Domain UUID', 'text', advanced=True,
              help='empty: the domain the sign-in answers with (DOMAIN_UUID)'),
    ] + tls_fields()
    deploy_fields = [
        field('decryption_policy', 'Decryption policy', 'catalog', catalog='policies',
              autoload=False,
              help='the policy whose rules (Decrypt - Known Key) use the older acme object; '
                   'their references are switched to the new one'),
        field('decryption_policies', 'More decryption policies', 'list',
              placeholder='Inbound decryption', help='one a line: names or IDs'),
        field('deploy', 'Deploy to the devices', 'bool', default=True,
              help='after the change, a deployment request for the devices with changes'),
        field('devices', 'Only these devices', 'list', placeholder='ftd-1',
              help='one a line: device names; empty: every device with changes to deploy'),
        keep_field(1),
    ] + verify_fields()
    actions = [{'key': 'look', 'label': 'List the internal certificates',
                'help': 'Lists the Internal Certificate objects and the decryption policies - '
                        'it changes nothing.',
                'changes': False}]

    token = None
    domain = None
    signin_domain = ''

    # -- the session ------------------------------------------------------------------------
    def auth_headers(self):
        return {'X-auth-access-token': self.token} if self.token else {}

    def login(self):
        if self.token:
            return
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        try:
            st, hd, d = self.req('POST', '/api/fmc_platform/v1/auth/generatetoken', b'',
                                 {'Authorization': 'Basic ' +
                                  base64.b64encode(raw.encode()).decode()},
                                 auth=False, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry=False)
        tok = hd.get('x-auth-access-token')
        if not tok:
            raise PluginError('the FMC gave no token (X-auth-access-token)', retry=False)
        self.token = text(tok)
        self.signin_domain = text(hd.get('domain_uuid')).strip()
        self.domain = text(self.c('domain_uuid')).strip() or self.signin_domain
        if not self.domain:
            raise PluginError('the FMC gave no DOMAIN_UUID: set the Domain UUID', retry=False)

    # -- discovery (1.0.29): the form filled in from the FMC --------------------------------
    discover_keys = ['host', 'port', 'user', 'password', 'verify_tls']

    def discover_setup(self):
        """Read-only: the sign-in (generatetoken, as test()) answers with the DOMAIN_UUID of
        the user - offered for the Domain UUID, empty (the same: the one of the sign-in)
        first. The FMC's other domains are not listed here - another one is typed."""
        out = Plugin.discover_setup(self)
        self.login()
        dom = self.signin_domain
        if dom:
            out['facts'].append(['Domain of the sign-in', dom])
            self.offer(out, 'domain_uuid', [['', 'Empty: the domain the sign-in answers with'],
                                            [dom, dom]], pick='')
        return out

    def api(self, method, path, body=None, ok=None, what=None):
        self.login()
        st, hd, d = self.req(method, '/api/fmc_config/v1/domain/%s%s' % (self.domain, path),
                             body, ok=ok, what=what)
        return st, (d if isinstance(d, dict) else {})

    def paged(self, path, what):
        out, offset = [], 0
        while offset < 50000:
            sep = '&' if '?' in path else '?'
            st, d = self.api('GET', '%s%soffset=%d&limit=1000' % (path, sep, offset), what=what)
            got = [x for x in d.get('items') or [] if isinstance(x, dict)]
            out += got
            total = as_int((d.get('paging') or {}).get('count'), len(out))
            offset += len(got)
            if not got or offset >= total:
                break
        return out

    def internal(self):
        return self.paged('/object/internalcertificates', 'listing the internal certificates')

    def policies(self):
        return self.paged('/policy/decryptionpolicies', 'listing the decryption policies')

    def policy_id(self, ref, pols):
        for p in pols:
            if ref in (text(p.get('id')), text(p.get('name'))):
                return text(p.get('id')), text(p.get('name'))
        raise PluginError('the FMC has no decryption policy "%s"' % ref, retry=False)

    def rules(self, pid):
        return self.paged('/policy/decryptionpolicies/%s/decryptionpolicyrules?expanded=true'
                          % q(pid), 'reading the rules of %s' % pid)

    # -- read-only things -------------------------------------------------------------------
    def test(self):
        n = len(self.internal())
        return 'signed in to the FMC %s (domain %s); %d internal certificate%s' % (
            self.c('host'), self.domain, n, '' if n == 1 else 's')

    def catalog(self, key):
        if key != 'policies':
            raise PluginError('there is no list called %s here' % key, retry=False)
        opts = [[text(p.get('name')), text(p.get('name'))] for p in self.policies()
                if p.get('name')]
        return {'options': opts, 'sets': {}, 'said': '%d decryption policies' % len(opts)}

    def action(self, key):
        if key != 'look':
            return HttpTarget.action(self, key)
        certs = self.internal()
        for c in certs:
            self.ctx.step('internal certificate %s (%s)' % (c.get('name'), c.get('id')))
        for p in self.policies():
            self.ctx.step('decryption policy %s (%s)' % (p.get('name'), p.get('id')))
        return '%d internal certificate%s' % (len(certs), '' if len(certs) == 1 else 's')

    # -- the work ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=63)
        prefix = name_prefix(bundle, options, maxlen=63)
        certs = self.internal()
        byname = {text(c.get('name')): c for c in certs}
        if self.unchanged(bundle, options, present=lambda: name in byname):
            return self.same(bundle, 'as %s' % name)
        did = []
        cur = byname.get(name)
        if cur is None:
            st, cur = self.api('POST', '/object/internalcertificates', {
                'name': name, 'type': 'InternalCertificate',
                'cert': text(bundle.as_format('cert-pem')),
                'privateKey': text(bundle.as_format('key-pem'))},
                what='importing %s' % name)
            if not cur.get('id'):
                raise PluginError('the FMC gave no id for %s' % name, detail=text(cur)[:4000])
            self.ctx.step('imported the internal certificate %s (%s)' % (name, cur['id']), 'ok')
            did.append('imported %s' % name)
        else:
            self.ctx.step('the internal certificate %s is there already' % name)
        new = {'id': text(cur.get('id')), 'name': name}
        old_ids = set(text(c.get('id')) for n, c in byname.items()
                      if ours(n, prefix) and n != name and c.get('id'))
        refs = []
        one = text(options.get('decryption_policy')).strip()
        if one:
            refs.append(one)
        refs += [r for r in lines(options.get('decryption_policies')) if r not in refs]
        changed = 0
        if refs:
            pols = self.policies()
            for ref in refs:
                pid, pname = self.policy_id(ref, pols)
                n = 0
                for r in self.rules(pid):
                    rule = copy.deepcopy(r)
                    if not old_ids or not swap(rule, old_ids, new):
                        continue
                    for k in ('links', 'metadata'):
                        rule.pop(k, None)
                    self.api('PUT', '/policy/decryptionpolicies/%s/decryptionpolicyrules/%s'
                             % (q(pid), q(r.get('id'))), rule,
                             what='switching the rule %s of %s' % (r.get('name'), pname))
                    self.ctx.step('the rule %s of %s uses %s' % (r.get('name'), pname, name),
                                  'ok')
                    n += 1
                if not n:
                    self.ctx.step('no rule of %s used an older acme object of this certificate '
                                  '(the first time: pick %s in its rules once)' % (pname, name),
                                  'warn')
                changed += n
                did.append('%s: %d rule%s' % (pname, n, '' if n == 1 else 's'))
        if changed and as_bool(self.opt(options, 'deploy', True), True):
            self.deploy_devices(options, did)
        self.cleanup(prefix, name, self.keep(options), certs)
        self.remember(bundle, options, id=new['id'])
        return ', '.join(did) or 'already %s' % name

    def deploy_devices(self, options, did):
        st, d = self.api('GET', '/deployment/deployabledevices?expanded=true',
                         what='listing the devices with changes')
        want = set(lines(options.get('devices')))
        ids, names = [], []
        for it in d.get('items') or []:
            if not isinstance(it, dict):
                continue
            dev = it.get('device') if isinstance(it.get('device'), dict) else it
            nm = text(dev.get('name') or it.get('name'))
            if want and nm not in want:
                continue
            if dev.get('id'):
                ids.append(text(dev['id']))
                names.append(nm)
        if not ids:
            self.ctx.step('no device has changes to deploy%s' % (
                ' among ' + ', '.join(sorted(want)) if want else ''), 'warn')
            return
        self.api('POST', '/deployment/deploymentrequests', {
            'type': 'DeploymentRequest', 'ignoreWarning': True, 'deviceList': ids,
            'deploymentNote': 'acme: a renewed certificate'},
            what='asking for the deployment')
        self.ctx.step('deployment asked for %s' % ', '.join(names), 'ok')
        did.append('deployed to %s' % ', '.join(names))

    def cleanup(self, prefix, current, keep, certs):
        if keep < 0:
            return
        byname = {text(c.get('name')): c for c in certs}
        gone = prune([n for n in byname if ours(n, prefix)], prefix, keep, current)
        if not gone:
            return
        try:
            ids = {text(byname[n].get('id')): n for n in gone}
            used = set()
            for p in self.policies():
                for r in self.rules(text(p.get('id'))):
                    for i in ids:
                        if refers(r, [i]):
                            used.add(i)
        except PluginError as e:
            self.ctx.step('the older certificates stay - the rules cannot be read: %s' % e,
                          'warn')
            return
        for i, old in ids.items():
            if i in used:
                self.ctx.step('the older %s stays: a decryption rule still uses it' % old, 'warn')
                continue
            try:
                self.api('DELETE', '/object/internalcertificates/%s' % q(i),
                         what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')
