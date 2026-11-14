# -*- coding: utf-8 -*-
"""
Azure App Service: the certificate uploaded (PKCS#12) as a certificate of the
resource group under a dated name, the custom hostnames of the app bound to
it (SNI SSL), older acme ones deleted when nothing is bound to them.

    https://management.azure.com (Azure Resource Manager), api-version=2023-12-01,
    a token of Microsoft Entra for an app registration (scope .../.default)
    GET    .../providers/Microsoft.Web/sites/<app>                  location, serverFarmId
    GET    .../providers/Microsoft.Web/sites/<app>/hostNameBindings  its hostnames
    GET    .../providers/Microsoft.Web/certificates/<name>          there already?
    PUT    .../providers/Microsoft.Web/certificates/<name>
           {"location", "properties": {"pfxBlob": base64, "password", "serverFarmId"}}
    PUT    .../providers/Microsoft.Web/sites/<app>/hostNameBindings/<host>
           {"properties": {"sslState": "SniEnabled", "thumbprint"}}
    GET    .../providers/Microsoft.Web/certificates                 the older ones
    DELETE .../providers/Microsoft.Web/certificates/<name>
    (... = /subscriptions/<id>/resourceGroups/<group>)

Sources (Microsoft's official REST API specification):
    https://github.com/Azure/azure-rest-api-specs/blob/main/specification/web/resource-manager/Microsoft.Web/AppService/stable/2023-12-01/Certificates.json
    https://github.com/Azure/azure-rest-api-specs/blob/main/specification/web/resource-manager/Microsoft.Web/AppService/stable/2023-12-01/WebApps.json
"""
from __future__ import annotations

import base64
import urllib.parse

from acmelib.plugins.targets._common import (
    PluginError, field, lines, object_name, name_prefix, prune, text, verify_fields,
    keep_field, random_password, sha1_thumb, covers, SEG_PATTERN)
from acmelib.plugins.base import Plugin
from acmelib.plugins.targets._cloud import (
    CloudTarget, cloud_fields, entra_token, arm_list, arm_groups)

API = '2023-12-01'
ARM = {'public': 'https://management.azure.com',
       'china': 'https://management.chinacloudapi.cn',
       'usgov': 'https://management.usgovcloudapi.net'}


class AzureAppServiceTarget(CloudTarget):
    kind = 'azure_appservice'
    title = 'Azure App Service'
    vendor = 'Microsoft'
    description = ('Uploads the certificate to Azure App Service and binds the custom '
                   'hostnames of a web app to it (SNI SSL); deletes the older ones.')
    doc = 'targets.md'
    fields = [
        field('subscription_id', 'Subscription ID', 'text', required=True),
        field('resource_group', 'Resource group', 'text', required=True,
              help='the resource group of the web apps (their certificates are kept there)'),
        field('tenant_id', 'Tenant (directory) ID', 'text', required=True),
        field('client_id', 'Client (application) ID', 'text', required=True,
              help='An app registration with the role "Website Contributor" on the web apps '
                   'and "Web Plan Contributor" on their App Service plan (or Contributor on '
                   'the resource group).'),
        field('client_secret', 'Client secret', 'secret', required=True),
        field('cloud', 'Cloud', 'select', default='public', advanced=True,
              options=[['public', 'Azure'], ['china', 'Azure China (21Vianet)'],
                       ['usgov', 'Azure US Government']]),
    ] + cloud_fields()
    deploy_fields = [
        field('site', 'Web app', 'text', pattern=SEG_PATTERN, required=True, placeholder='app-www',
              help='the name of the App Service web app'),
        field('hostnames', 'Hostnames', 'list', pattern=SEG_PATTERN, placeholder='www.example.com',
              help='one a line: the custom hostnames of the app to bind; empty: each of them '
                   'the certificate covers'),
        field('pfx_format', 'PKCS#12 kind', 'select', default='p12-legacy', advanced=True,
              options=[['p12-legacy', '3DES (as App Service documents it)'],
                       ['pfx', 'AES-256']]),
        keep_field(1),
    ] + verify_fields()

    def arm(self):
        return ARM.get(self.c('cloud', 'public'), ARM['public'])

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % entra_token(self, self.arm() + '/.default')}

    def rg(self):
        return '%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web' % (
            self.arm(), urllib.parse.quote(text(self.c('subscription_id')).strip(), safe=''),
            urllib.parse.quote(text(self.c('resource_group')).strip(), safe=''))

    def api(self, method, path, body=None, ok=None, what=None):
        sep = '&' if '?' in path else '?'
        st, hd, d = self.req(method, '%s%s%sapi-version=%s' % (self.rg(), path, sep, API), body,
                             ok=ok, what=what)
        return st, (d if isinstance(d, dict) else {})

    def site(self, name):
        st, d = self.api('GET', '/sites/%s' % urllib.parse.quote(name, safe=''), ok=(200, 404),
                         what='reading the web app %s' % name)
        if st == 404:
            raise PluginError('there is no web app "%s" in the resource group %s' % (
                name, self.c('resource_group')), retry=False)
        return d

    def bindings(self, name):
        st, d = self.api('GET', '/sites/%s/hostNameBindings' % urllib.parse.quote(name, safe=''),
                         what='reading the hostnames of %s' % name)
        out = []
        for b in d.get('value') or []:
            host = text(b.get('name')).split('/')[-1]
            out.append((host, b.get('properties') or {}))
        return out

    def test(self):
        st, d = self.api('GET', '/certificates', what='signing in')
        n = len(d.get('value') or [])
        return 'signed in to Azure; %d App Service certificate%s in %s' % (
            n, '' if n == 1 else 's', self.c('resource_group'))

    # -- discovery (1.0.29): the form filled in from the subscription ------------------------
    discover_keys = ['subscription_id', 'tenant_id', 'client_id', 'client_secret', 'cloud']

    def discover_setup(self):
        """Read-only: the App Service certificates of the subscription (GET /subscriptions/<s>/
        providers/Microsoft.Web/certificates) - the resource groups holding them offered as
        the resource group. A group with no certificate yet is typed by hand."""
        out = Plugin.discover_setup(self)
        sub = text(self.c('subscription_id')).strip()
        if not sub:
            raise PluginError('set the Subscription ID first', retry=False)
        certs = arm_list(self, '%s/subscriptions/%s/providers/Microsoft.Web/certificates'
                         '?api-version=%s' % (self.arm(), urllib.parse.quote(sub, safe=''), API),
                         'listing the App Service certificates')
        out['facts'].append(['App Service certificates in the subscription', str(len(certs))])
        groups = arm_groups(certs)
        if groups:
            self.offer(out, 'resource_group', [[g, '%s (%d)' % (g, len(groups[g]))]
                                               for g in sorted(groups, key=str.lower)])
        out['notes'].append('only the resource groups that hold App Service certificates are '
                            'listed - another one is typed by hand')
        return out

    def deploy(self, bundle, options):
        options = options or {}
        app = text(options.get('site')).strip()
        if not app:
            raise PluginError('no web app is set', retry=False)
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        thumb = sha1_thumb(bundle)
        st, cur = self.api('GET', '/certificates/%s' % name, ok=(200, 404),
                           what='looking for %s' % name)
        there = st == 200
        if self.unchanged(bundle, options, present=lambda: there):
            return self.same(bundle, 'as %s' % name)
        site = self.site(app)
        did = []
        if there:
            self.ctx.step('%s is in App Service already' % name)
        else:
            pw = random_password()
            pfx = bundle.as_format(options.get('pfx_format') or 'p12-legacy', password=pw,
                                   alias=name)
            st, cur = self.api('PUT', '/certificates/%s' % name, {
                'location': site.get('location'),
                'properties': {'pfxBlob': base64.b64encode(pfx).decode(), 'password': pw,
                               'serverFarmId': (site.get('properties') or {}).get(
                                   'serverFarmId')}},
                what='uploading %s' % name)
            self.ctx.step('uploaded %s' % name, 'ok')
            did.append('uploaded %s' % name)
        thumb = text((cur.get('properties') or {}).get('thumbprint') or thumb).upper()
        binds = self.bindings(app)
        have = [h for h, _p in binds]
        want = lines(options.get('hostnames'))
        if want:
            missing = [h for h in want if h.lower() not in [x.lower() for x in have]]
            if missing:
                raise PluginError('the web app %s has no hostname %s (add it there first)'
                                  % (app, ', '.join(missing)), retry=False)
        else:
            want = [h for h in have if covers(bundle.names, h) and
                    not h.lower().endswith('.azurewebsites.net')]
            if not want:
                raise PluginError('the certificate covers none of the custom hostnames of %s '
                                  '(%s)' % (app, ', '.join(have) or 'none'), retry=False)
        props = {h.lower(): p for h, p in binds}
        for h in want:
            p = props.get(h.lower()) or {}
            if text(p.get('thumbprint')).upper() == thumb and p.get('sslState') == 'SniEnabled':
                self.ctx.step('%s is bound to %s already' % (h, name))
                continue
            self.api('PUT', '/sites/%s/hostNameBindings/%s' % (
                urllib.parse.quote(app, safe=''), urllib.parse.quote(h, safe='')),
                {'properties': {'sslState': 'SniEnabled', 'thumbprint': thumb}},
                what='binding %s' % h)
            self.ctx.step('%s uses %s (SNI SSL)%s' % (h, name, ' - before: the certificate %s'
                                                     % text(p['thumbprint']).upper()
                                                     if p.get('thumbprint') else ''), 'ok')
            did.append(h)
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            st, d = self.api('GET', '/certificates', what='listing the certificates')
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        names = [text(c.get('name')) for c in d.get('value') or []]
        for old in prune(names, prefix, keep, current):
            try:
                self.api('DELETE', '/certificates/%s' % old, what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays (still bound?): %s' % (old, e), 'warn')
