# -*- coding: utf-8 -*-
"""
Azure Application Gateway: the certificate added to the gateway's
sslCertificates (a PKCS#12 with its chain, base64) under a dated name - or
under one fixed name, replaced in place - or pointed at a Key Vault secret
without a version; the HTTPS listeners switched to it, older acme
certificates no listener uses taken out, all in one PUT of the whole gateway
(the API has no call for one certificate), then waited for.

    https://management.azure.com (Azure Resource Manager), api-version=2026-03-01,
    a token of Microsoft Entra for an app registration (scope .../.default)
    GET   .../providers/Microsoft.Network/applicationGateways/<gw>   the whole gateway
    PUT   .../providers/Microsoft.Network/applicationGateways/<gw>   the same, with
          properties.sslCertificates[] {"name", "properties": {"data": base64 PFX, "password"}}
          or {"name", "properties": {"keyVaultSecretId": "https://<kv>/secrets/<name>/"}}
          and properties.httpListeners[] / listeners[] .properties.sslCertificate.id
          (long-running: GET again until provisioningState is no longer Updating)
    PATCH .../applicationGateways/<gw>  {"tags"}    (Key Vault: a change makes the gateway
          look for a new version at once)
    (... = /subscriptions/<id>/resourceGroups/<group>)

Checked against (the user's collection of the vendor's documents, api-docs/azure_appgw/:
notes.md, applicationGateway.json - the OpenAPI of Microsoft.Network 2026-03-01 -
and example-ApplicationGatewayCreate.json), quoting:
    https://github.com/Azure/azure-rest-api-specs/blob/main/specification/network/resource-manager/Microsoft.Network/Network/stable/2026-03-01/applicationGateway.json
    https://github.com/Azure/azure-rest-api-specs/blob/main/specification/network/resource-manager/Microsoft.Network/Network/stable/2026-03-01/examples/ApplicationGatewayCreate.json
    https://learn.microsoft.com/en-us/azure/application-gateway/key-vault-certs
    https://learn.microsoft.com/en-us/azure/application-gateway/renew-certificates
    https://learn.microsoft.com/en-us/azure/application-gateway/ssl-overview
    https://learn.microsoft.com/en-us/rest/api/azure/
    https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow

Less certain:
    - the gateway read with GET is PUT back whole, with its read-only properties in it (what
      the PowerShell of renew-certificates does: Get-AzApplicationGateway, then
      Set-AzApplicationGateway); certificates already there go back without "data";
    - what PUT answers when a certificate still named by a listener is taken out is not
      documented: acme takes out only older acme ones no listener (HTTP or TLS) names;
    - the values of provisioningState (common.json is not in the collection): acme waits
      while it is "Updating" and fails on "Failed";
    - the format of publicCertData is not described, so "the same certificate is there"
      means the dated name is there (or, in place, what acme remembers);
    - EC keys are not said to be supported (PFXImportCertStore); the PKCS#12 is 3DES unless
      AES is chosen;
    - Key Vault: the secret is put there by the azure_keyvault target (run it first); the
      gateway needs a managed identity allowed to read it; tags changed with PATCH should make
      it look at once ("Any change ... Resource Tags"), else within four hours.
"""
from __future__ import annotations

import base64
import re
import time
import urllib.parse

from acmelib.plugins.targets._common import (
    PluginError, field, lines, as_bool, as_int, label_of, object_name, name_prefix, ours, prune, text,
    verify_fields, keep_field, random_password, fp_of, SEG_PATTERN)
from acmelib.plugins.base import Plugin
from acmelib.plugins.targets._cloud import (
    CloudTarget, cloud_fields, entra_token, arm_list, arm_groups)

API = '2026-03-01'
ARM = {'public': 'https://management.azure.com',
       'china': 'https://management.chinacloudapi.cn',
       'usgov': 'https://management.usgovcloudapi.net'}
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$')


class AzureAppGwTarget(CloudTarget):
    kind = 'azure_appgw'
    title = 'Azure Application Gateway'
    vendor = 'Microsoft'
    description = ('Puts the certificate on an Azure Application Gateway (a PKCS#12 upload or a '
                   'Key Vault secret), switches its HTTPS listeners to it and takes the older '
                   'one out.')
    doc = 'targets.md'
    fields = [
        field('subscription_id', 'Subscription ID', 'text', required=True),
        field('resource_group', 'Resource group', 'text', required=True,
              help='the resource group of the application gateways'),
        field('tenant_id', 'Tenant (directory) ID', 'text', required=True),
        field('client_id', 'Client (application) ID', 'text', required=True,
              help='An app registration with the role "Network Contributor" on the gateway '
                   '(and, with Key Vault, Managed Identity Operator on its identity).'),
        field('client_secret', 'Client secret', 'secret', required=True),
        field('cloud', 'Cloud', 'select', default='public', advanced=True,
              options=[['public', 'Azure'], ['china', 'Azure China (21Vianet)'],
                       ['usgov', 'Azure US Government']]),
    ] + cloud_fields()
    deploy_fields = [
        field('gateway', 'Application gateway', 'text', pattern=SEG_PATTERN, required=True, placeholder='agw-www',
              help='the name of the application gateway'),
        field('listener', 'Listener', 'catalog', pattern=SEG_PATTERN, catalog='listeners', autoload=False,
              help='an HTTPS (or TLS) listener of the gateway to use the certificate; picked '
                   'from the list or typed'),
        field('listeners', 'More listeners', 'list', pattern=SEG_PATTERN, placeholder='https-www',
              help='one a line; with none given, the listeners that use an older acme '
                   'certificate of this one are switched'),
        field('source', 'The certificate goes', 'select', default='upload',
              options=[['upload', 'uploaded (PKCS#12 with its chain)'],
                       ['keyvault', 'from Key Vault (a secret without a version)']]),
        field('key_vault_secret_id', 'Key Vault secret ID', 'text',
              placeholder='https://kv-firma.vault.azure.net/secrets/acme-www-example-com/',
              show_if={'source': ['keyvault']},
              help='without a version: the gateway takes each new version by itself'),
        field('cert_name', 'Name on the gateway', 'text', placeholder='www-example-com',
              help='empty: a new dated name each time (acme-<name>-<date>-<serial>); set: that '
                   'one certificate, its content replaced in place'),
        field('pfx_kind', 'PKCS#12 kind', 'select', default='p12-legacy', advanced=True,
              options=[['p12-legacy', '3DES'], ['pfx', 'AES-256']]),
        field('gw_wait', 'Wait for the gateway (s)', 'number', default=1800, advanced=True),
        keep_field(1),
    ] + verify_fields()

    def arm(self):
        return ARM.get(self.c('cloud', 'public'), ARM['public'])

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % entra_token(self, self.arm() + '/.default')}

    def gw_path(self, gw):
        return '/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/' \
            'applicationGateways/%s' % (
                urllib.parse.quote(text(self.c('subscription_id')).strip(), safe=''),
                urllib.parse.quote(text(self.c('resource_group')).strip(), safe=''),
                urllib.parse.quote(text(gw).strip(), safe=''))

    def api(self, method, path, body=None, ok=None, what=None):
        st, hd, d = self.req(method, '%s%s?api-version=%s' % (self.arm(), path, API), body,
                             ok=ok, what=what)
        return st, (d if isinstance(d, dict) else {})

    def gateway(self, name):
        if not text(name).strip():
            raise PluginError('no application gateway is set', retry=False)
        st, d = self.api('GET', self.gw_path(name), ok=(200, 404),
                         what='reading the application gateway %s' % name)
        if st == 404:
            raise PluginError('there is no application gateway "%s" in the resource group %s'
                              % (name, self.c('resource_group')), retry=False)
        return d

    # -- read-only --------------------------------------------------------------------------
    def test(self):
        st, d = self.api('GET', '/subscriptions/%s/resourceGroups/%s/providers/'
                         'Microsoft.Network/applicationGateways' % (
                             urllib.parse.quote(text(self.c('subscription_id')).strip(),
                                                safe=''),
                             urllib.parse.quote(text(self.c('resource_group')).strip(),
                                                safe='')),
                         what='signing in')
        names = [text(g.get('name')) for g in d.get('value') or []]
        return 'signed in to Azure; %d application gateway%s in %s%s' % (
            len(names), '' if len(names) == 1 else 's', self.c('resource_group'),
            (': ' + ', '.join(names[:10])) if names else '')

    def catalog(self, key):
        if key != 'listeners':
            raise PluginError('there is no list called %s here' % key, retry=False)
        g = self.gateway(self.c('gateway'))
        p = g.get('properties') or {}
        opts = []
        for kind in ('httpListeners', 'listeners'):
            for li in p.get(kind) or []:
                lp = li.get('properties') or {}
                if text(lp.get('protocol')).lower() not in ('https', 'tls'):
                    continue
                cert = text((lp.get('sslCertificate') or {}).get('id')).rsplit('/', 1)[-1]
                host = lp.get('hostName') or ', '.join(lp.get('hostNames') or []) or '*'
                opts.append([text(li.get('name')), '%s (%s, %s)' % (li.get('name'), host,
                                                                     cert or 'no certificate')])
        return {'options': opts, 'sets': {}, 'said': '%d listeners' % len(opts)}

    # -- discovery (1.0.29): the form filled in from the subscription ------------------------
    discover_keys = ['subscription_id', 'tenant_id', 'client_id', 'client_secret', 'cloud']

    def discover_setup(self):
        """Read-only: the application gateways of the subscription (GET /subscriptions/<s>/
        providers/Microsoft.Network/applicationGateways) - the resource groups holding them
        offered as the resource group."""
        out = Plugin.discover_setup(self)
        sub = text(self.c('subscription_id')).strip()
        if not sub:
            raise PluginError('set the Subscription ID first', retry=False)
        gws = arm_list(self, '%s/subscriptions/%s/providers/Microsoft.Network/'
                       'applicationGateways?api-version=%s' % (
                           self.arm(), urllib.parse.quote(sub, safe=''), API),
                       'listing the application gateways')
        out['facts'].append(['Application gateways in the subscription', str(len(gws))])
        groups = arm_groups(gws)
        if groups:
            self.offer(out, 'resource_group', [
                [g, '%s (%s)' % (g, ', '.join(sorted(n for n in groups[g] if n)[:5]))]
                for g in sorted(groups, key=str.lower)])
        else:
            out['notes'].append('the subscription has no application gateway this app '
                                'registration can see')
        return out

    # -- the work ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        gwname = text(options.get('gateway')).strip()
        g = self.gateway(gwname)
        p = g.setdefault('properties', {})
        certs = p.setdefault('sslCertificates', [])
        byname = {text(c.get('name')): c for c in certs}
        kv = self.opt(options, 'source', 'upload') == 'keyvault'
        fixed = text(options.get('cert_name')).strip()
        if fixed and not NAME_RE.match(fixed):
            raise PluginError('"%s" is not a name for the gateway (letters, digits, _ . -)'
                              % fixed, retry=False)
        prefix = name_prefix(bundle, options, maxlen=80)
        if kv:
            name = fixed or ('acme-' + label_of(bundle, options, 70))
        else:
            name = fixed or object_name(bundle, options, maxlen=80)
        if not kv and self.unchanged(bundle, options, present=lambda: name in byname):
            return self.same(bundle, 'as %s' % name)
        did, change = [], False
        gid = text(g.get('id')) or (self.gw_path(gwname))
        if kv:
            sid = text(options.get('key_vault_secret_id')).strip()
            if not re.match(r'^https://[^/]+/secrets/[^/]+/?$', sid):
                raise PluginError('the Key Vault secret ID is to be https://<vault>/secrets/<name>/ '
                                  '(without a version, so the gateway takes each new one)',
                                  retry=False)
            if not (g.get('identity') or {}).get('type'):
                raise PluginError('the gateway %s has no managed identity: it reads Key Vault '
                                  'through one (give it a user-assigned identity first)' % gwname,
                                  retry=False)
            cur = byname.get(name)
            if cur is None or text((cur.get('properties') or {}).get('keyVaultSecretId')) != sid:
                entry = {'name': name, 'properties': {'keyVaultSecretId': sid}}
                if cur is None:
                    certs.append(entry)
                else:
                    certs[certs.index(cur)] = entry
                self.ctx.step('the certificate %s of the gateway points at %s' % (name, sid), 'ok')
                did.append('%s -> Key Vault' % name)
                change = True
        else:
            pw = random_password()
            pfx = bundle.as_format(self.opt(options, 'pfx_kind', 'p12-legacy'), password=pw,
                                   alias=name)
            entry = {'name': name, 'properties': {'data': base64.b64encode(pfx).decode(),
                                                  'password': pw}}
            if name in byname:
                certs[certs.index(byname[name])] = entry
                self.ctx.step('the certificate %s is replaced in place' % name)
            else:
                certs.append(entry)
            did.append('uploaded %s' % name)
            change = True
        new_id = '%s/sslCertificates/%s' % (gid, name)
        old = set(n for n in byname if ours(n, prefix) and n != name)
        want = []
        one = text(options.get('listener')).strip()
        if one:
            want.append(one)
        want += [x for x in lines(options.get('listeners')) if x not in want]
        found = set()
        for kind in ('httpListeners', 'listeners'):
            for li in p.get(kind) or []:
                lp = li.setdefault('properties', {})
                ln = text(li.get('name'))
                cur = text((lp.get('sslCertificate') or {}).get('id')).rsplit('/', 1)[-1]
                if ln in want:
                    found.add(ln)
                elif cur not in old:
                    continue
                if cur == name:
                    continue
                lp['sslCertificate'] = {'id': new_id}
                self.ctx.step('the listener %s uses %s%s' % (
                    ln, name, ' (before: %s)' % cur if cur else ''), 'ok')
                did.append(ln)
                change = True
        missing = [x for x in want if x not in found]
        if missing:
            raise PluginError('the gateway %s has no listener %s' % (gwname, ', '.join(missing)),
                              retry=False)
        if not want and not any(text(((li.get('properties') or {}).get('sslCertificate') or {})
                                     .get('id')).rsplit('/', 1)[-1] == name
                                for k in ('httpListeners', 'listeners')
                                for li in p.get(k) or []):
            self.ctx.step('no listener uses %s (the first time: give the listeners, or pick it '
                          'in the portal once)' % name, 'warn')
        gone = self.drop_old(p, prefix, name, self.keep(options)) if not fixed else []
        if gone:
            change = True
        if change:
            body = {k: v for k, v in g.items() if k not in ('etag',)}
            self.api('PUT', self.gw_path(gwname), body,
                     what='writing the application gateway %s' % gwname)
            self.ctx.step('the gateway %s is being updated' % gwname)
            self.wait(gwname, options)
            for n in gone:
                self.ctx.step('took the older %s out' % n)
        if kv:
            tags = dict(g.get('tags') or {})
            fp16 = fp_of(bundle)[:16]
            if not change and tags.get('acme-certificate') == fp16 and \
                    not as_bool(options.get('force')):
                self.remember(bundle, options)
                return self.same(bundle, 'behind %s' % name)
            tags['acme-certificate'] = fp16
            tags['acme-deployed'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            self.api('PATCH', self.gw_path(gwname), {'tags': tags},
                     what='tagging the gateway %s' % gwname)
            self.ctx.step('tagged the gateway (acme-certificate %s): it looks for the new '
                          'version in Key Vault now' % fp16, 'ok')
            did.append('tagged')
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def drop_old(self, p, prefix, current, keep):
        if keep < 0:
            return []
        certs = p.get('sslCertificates') or []
        used = set()
        for kind in ('httpListeners', 'listeners'):
            for li in p.get(kind) or []:
                used.add(text(((li.get('properties') or {}).get('sslCertificate') or {})
                              .get('id')).rsplit('/', 1)[-1])
        names = [text(c.get('name')) for c in certs]
        gone = []
        for old in prune([n for n in names if ours(n, prefix)], prefix, keep, current):
            if old in used:
                self.ctx.step('the older %s stays: a listener still uses it' % old, 'warn')
                continue
            gone.append(old)
        p['sslCertificates'] = [c for c in certs if text(c.get('name')) not in gone]
        return gone

    def wait(self, gwname, options):
        sleep = getattr(self, '_sleep', time.sleep)
        until = time.time() + max(60, as_int(self.opt(options, 'gw_wait', 1800), 1800))
        while True:
            g = self.gateway(gwname)
            state = text((g.get('properties') or {}).get('provisioningState'))
            if state == 'Succeeded':
                self.ctx.step('the gateway %s is updated' % gwname, 'ok')
                return
            if state in ('Failed', 'Canceled'):
                raise PluginError('the update of the gateway %s ended %s' % (gwname, state),
                                  retry=False)
            if time.time() > until or self.ctx.cancelled():
                raise PluginError('the gateway %s is still %s - see the portal'
                                  % (gwname, state or '?'))
            sleep(15)
