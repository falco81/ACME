# -*- coding: utf-8 -*-
"""
Cisco Secure Firewall Threat Defense managed locally by its Device Manager
(FDM REST API): the certificate and its key uploaded as a new Internal
Certificate, the intermediates as External CA Certificates (added once), the
management web interface (and, when asked, remote access VPN) switched to it,
the change deployed, older acme objects nothing uses deleted.

    POST /api/fdm/latest/fdm/token   {"grant_type": "password", "username", "password"}
         -> access_token; then Authorization: Bearer <token>
    GET  /api/fdm/latest/object/internalcertificates?offset=N&limit=10   (10 a page at most)
    POST /api/fdm/latest/object/internalcertificates
         {"type": "internalcertificate", "name", "certType": "UPLOAD", "cert", "privateKey"}
    GET  /api/fdm/latest/object/externalcacertificates?offset=N&limit=10
    POST /api/fdm/latest/object/externalcacertificates  {"type": "externalcacertificate",
         "name": "acme-ca-<id>", "cert"}
    GET  /api/fdm/latest/devicesettings/default/webuicertificates           (the one object)
    PUT  /api/fdm/latest/devicesettings/default/webuicertificates/<id>
         the whole object, "certificate": {id, name, type, version} of the new one,
         "trustChain": [the External CA Certificates]
    GET  /api/fdm/latest/ravpns ; PUT /api/fdm/latest/ravpns/<id>   (vpnGatewaySettings
         .serverCertificate), when asked
    POST /api/fdm/latest/operational/deploy ; GET .../operational/deploy/<id> until DEPLOYED
    DELETE /api/fdm/latest/object/internalcertificates/<id>      (older acme ones, unused)

FTD managed by an FMC is not this: use the cisco_fmc target.

Checked against (the user's collection of the vendor's documents,
api-docs/cisco_ftd_fdm/notes.md), quoting:
    https://developer.cisco.com/docs/ftd-api-reference/latest/
    https://pubhub.devnetcloud.com/media/ftd-api-reference-v6-ftd-v7-2-/docs/ (introduction/auth,
      introduction/deploy_config, resources/Certificate/*, resources/WebUICertificate/*,
      resources/Deployment/add_deployment, models/internal_certificate, models/web_ui_certificate,
      models/ra_vpn, models/vpn_gateway_settings, models/external_ca_certificate,
      models/deployment_status)
    https://www.cisco.com/c/en/us/td/docs/security/firepower/ftd-api/guide/ftd-rest-api/ftd-rest-api-intro.html
    https://www.cisco.com/c/en/us/td/docs/security/firepower/ftd-api/guide/ftd-rest-api/ftd-api-deployment.html
    https://www.cisco.com/c/en/us/td/docs/security/firepower/ftd-api/guide/ftd-rest-api/auth-ftd-rest-api.html

Less certain (the OpenAPI specification is only on the device, /apispec/ngfw.json; the public
reference is v6, FTD 7.2):
    - the shape of a list answer ("items", paged with offset/limit) is not quoted in the
      notes; acme reads "items" and pages until a page is short;
    - "trustChain" entries "must contain the certificate string itself, the subject name, and
      the issuer name": acme sends the External CA Certificate objects whole, as FDM gave them;
    - whether "cert" of an Internal Certificate may hold the chain: not found - only the
      certificate is sent; the chain goes as External CA Certificates;
    - the vpnGatewaySettings of a RaVpn object changed in place and the whole object PUT back
      is derived from the model, not from an example;
    - the states of a deployment other than QUEUED and DEPLOYED are not listed: acme waits
      while the state is neither DEPLOYED nor one that says FAIL/ERROR, up to a time limit;
    - what DELETE answers for an object still in use is not documented; acme deletes only the
      older acme objects neither the web interface nor a RA VPN names;
    - after the web interface is switched, the management interface shows the new
      certificate (put its CA in "CA certificate" or the check may refuse it);
    - logging out (revoking the token) is not documented; the token lives 30 minutes.
"""
from __future__ import annotations

import time
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, text, object_name, name_prefix,
    ours, prune, chain_list, chain_id, http_fields, tls_fields, verify_fields, keep_field)

API = '/api/fdm/latest'


def q(s):
    return urllib.parse.quote(text(s), safe='')


def ref_of(obj):
    return {'id': obj.get('id'), 'name': obj.get('name'), 'type': obj.get('type'),
            'version': obj.get('version')}


def bare(obj):
    return {k: v for k, v in (obj or {}).items() if k != 'links'}


class CiscoFtdFdmTarget(HttpTarget):
    kind = 'cisco_ftd_fdm'
    title = 'Cisco Secure Firewall Threat Defense (FDM)'
    vendor = 'Cisco'
    description = ('Uploads the certificate to an FTD managed by its Device Manager as a new '
                   'internal certificate, switches the management web interface (and RA VPN) '
                   'to it, deploys the change and deletes the older one.')
    doc = 'targets.md'
    fields = http_fields(443, 'ftd.example.local') + [
        field('user', 'User', 'text', required=True, default='admin',
              help='the admin account of the device (FDM takes the API only from it)'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('web_ui', 'The management web interface', 'bool', default=True,
              help='FDM\'s own HTTPS (web interface and API) uses the certificate'),
        field('ravpn', 'Remote access VPN', 'bool', default=False,
              help='the server certificate of the RA VPN gateway settings'),
        field('fdm_deploy', 'Deploy the change', 'bool', default=True,
              help='nothing is active on the device before a deployment'),
        field('deploy_wait', 'Wait for the deployment (s)', 'number', default=900, advanced=True),
        keep_field(1),
    ] + verify_fields()

    token = None

    # -- the session ------------------------------------------------------------------------
    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.token} if self.token else {}

    def login(self):
        if self.token:
            return
        try:
            st, hd, d = self.req('POST', API + '/fdm/token', {
                'grant_type': 'password', 'username': self.c('user') or '',
                'password': self.c('password') or ''}, auth=False, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry=False)
        tok = d.get('access_token') if isinstance(d, dict) else None
        if not tok:
            raise PluginError('FDM gave no access_token', retry=False)
        self.token = text(tok)

    def api(self, method, path, body=None, ok=None, what=None):
        self.login()
        st, hd, d = self.req(method, API + path, body, ok=ok, what=what)
        return st, (d if isinstance(d, dict) else {})

    def paged(self, path, what):
        out, offset = [], 0
        while offset < 20000:
            sep = '&' if '?' in path else '?'
            st, d = self.api('GET', '%s%soffset=%d&limit=10' % (path, sep, offset), what=what)
            got = [x for x in d.get('items') or [] if isinstance(x, dict)]
            out += got
            offset += len(got)
            if len(got) < 10:
                break
        return out

    def internal(self):
        return self.paged('/object/internalcertificates', 'listing the internal certificates')

    def webui(self):
        st, d = self.api('GET', '/devicesettings/default/webuicertificates',
                         what='reading the web interface certificate')
        items = [x for x in d.get('items') or [] if isinstance(x, dict)]
        if not items:
            raise PluginError('FDM shows no web interface certificate setting', retry=False)
        return items[0]

    def ravpns(self):
        return self.paged('/ravpns', 'reading the remote access VPN')

    # -- read-only --------------------------------------------------------------------------
    def test(self):
        n = len(self.internal())
        w = self.webui()
        return 'signed in to FDM %s; %d internal certificate%s, the web interface uses %s' % (
            self.c('host'), n, '' if n == 1 else 's',
            (w.get('certificate') or {}).get('name') or '?')

    # -- the work ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=128)
        prefix = name_prefix(bundle, options, maxlen=128)
        certs = self.internal()
        byname = {text(c.get('name')): c for c in certs}
        if self.unchanged(bundle, options, present=lambda: name in byname):
            return self.same(bundle, 'as %s' % name)
        did, changed = [], False
        cur = byname.get(name)
        if cur is None:
            st, cur = self.api('POST', '/object/internalcertificates', {
                'type': 'internalcertificate', 'name': name, 'certType': 'UPLOAD',
                'cert': text(bundle.as_format('cert-pem')),
                'privateKey': text(bundle.as_format('key-pem'))},
                what='uploading %s' % name)
            if not cur.get('id'):
                raise PluginError('FDM gave no id for %s' % name, detail=text(cur)[:4000])
            self.ctx.step('uploaded the internal certificate %s' % name, 'ok')
            did.append('uploaded %s' % name)
            changed = True
        else:
            self.ctx.step('the internal certificate %s is there already' % name)
        old_ids = set(text(c.get('id')) for n, c in byname.items()
                      if ours(n, prefix) and n != name and c.get('id'))
        if as_bool(self.opt(options, 'web_ui', True), True):
            chain = self.chain(bundle)
            w = self.webui()
            if text((w.get('certificate') or {}).get('id')) == text(cur.get('id')):
                self.ctx.step('the web interface uses %s already' % name)
            else:
                body = bare(w)
                body['certificate'] = ref_of(cur)
                body['trustChain'] = chain
                self.api('PUT', '/devicesettings/default/webuicertificates/%s' % q(w.get('id')),
                         body, what='switching the web interface to %s' % name)
                self.ctx.step('the web interface uses %s' % name, 'ok')
                did.append('web interface')
                changed = True
        if as_bool(self.opt(options, 'ravpn', False)):
            vpns = self.ravpns()
            if not vpns:
                self.ctx.step('there is no remote access VPN on the device', 'warn')
            for v in vpns:
                gw = v.get('vpnGatewaySettings')
                if not isinstance(gw, dict):
                    self.ctx.step('the RA VPN %s has no gateway settings' % v.get('name'), 'warn')
                    continue
                if text((gw.get('serverCertificate') or {}).get('id')) == text(cur.get('id')):
                    self.ctx.step('the RA VPN %s uses %s already' % (v.get('name'), name))
                    continue
                body = bare(v)
                body['vpnGatewaySettings'] = dict(gw, serverCertificate=ref_of(cur))
                self.api('PUT', '/ravpns/%s' % q(v.get('id')), body,
                         what='switching the RA VPN %s to %s' % (v.get('name'), name))
                self.ctx.step('the RA VPN %s uses %s' % (v.get('name'), name), 'ok')
                did.append('RA VPN %s' % v.get('name'))
                changed = True
        deploy_on = as_bool(self.opt(options, 'fdm_deploy', True), True)
        if changed and deploy_on:
            self.deploy_now(options)
            did.append('deployed')
        elif changed:
            self.ctx.step('not deployed: the change is pending in FDM until a deployment',
                          'warn')
        gone = self.cleanup(prefix, name, self.keep(options), certs, old_ids)
        if gone and deploy_on:
            self.deploy_now(options)
        self.remember(bundle, options, id=text(cur.get('id')))
        return ', '.join(did) or 'already %s' % name

    def chain(self, bundle):
        """The intermediates as External CA Certificates: acme-ca-<id>, added once."""
        pems = chain_list(bundle)
        if not pems:
            return []
        have = {text(c.get('name')): c for c in self.paged(
            '/object/externalcacertificates', 'listing the external CA certificates')}
        out = []
        for pem in pems:
            n = 'acme-ca-%s' % chain_id(pem)
            obj = have.get(n)
            if obj is None:
                st, obj = self.api('POST', '/object/externalcacertificates', {
                    'type': 'externalcacertificate', 'name': n, 'cert': text(pem)},
                    what='adding the CA certificate %s' % n)
                self.ctx.step('added the CA certificate %s' % n, 'ok')
            out.append(bare(obj))
        return out

    def deploy_now(self, options):
        st, d = self.api('POST', '/operational/deploy', {},
                         what='asking for a deployment')
        did = text(d.get('id'))
        if not did:
            raise PluginError('FDM gave no id for the deployment', detail=text(d)[:4000])
        self.ctx.step('deployment %s asked for' % did)
        sleep = getattr(self, '_sleep', time.sleep)
        until = time.time() + max(30, as_int(self.opt(options, 'deploy_wait', 900), 900))
        state = text(d.get('state'))
        while True:
            if state == 'DEPLOYED':
                self.ctx.step('deployed (%s)' % (d.get('statusMessage') or state), 'ok')
                return
            if 'FAIL' in state.upper() or 'ERROR' in state.upper():
                raise PluginError('the deployment %s ended %s: %s' % (
                    did, state, d.get('statusMessage') or d.get('statusMessages') or ''),
                    detail=text(d)[:4000])
            if time.time() > until or self.ctx.cancelled():
                raise PluginError('the deployment %s is still %s - see the Device Manager'
                                  % (did, state or '?'))
            sleep(5)
            st, d = self.api('GET', '/operational/deploy/%s' % q(did),
                             what='reading the deployment %s' % did)
            state = text(d.get('state'))

    def cleanup(self, prefix, current, keep, certs, old_ids):
        if keep < 0 or not old_ids:
            return []
        byname = {text(c.get('name')): c for c in certs}
        names = prune([n for n in byname if ours(n, prefix)], prefix, keep, current)
        if not names:
            return []
        try:
            used = set([text((self.webui().get('certificate') or {}).get('id'))])
            for v in self.ravpns():
                used.add(text(((v.get('vpnGatewaySettings') or {}).get('serverCertificate')
                               or {}).get('id')))
        except PluginError as e:
            self.ctx.step('the older certificates stay - what uses them cannot be read: %s' % e,
                          'warn')
            return []
        gone = []
        for old in names:
            c = byname[old]
            if text(c.get('id')) in used:
                self.ctx.step('the older %s stays: it is still in use' % old, 'warn')
                continue
            try:
                self.api('DELETE', '/object/internalcertificates/%s' % q(c.get('id')),
                         what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
                gone.append(old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')
        return gone
