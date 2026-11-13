# -*- coding: utf-8 -*-
"""
HPE Aruba Networking Central (Classic Central, API Gateway) - a server certificate in
Central's certificate store, which AOS 10 gateways and APs (and Instant APs, CX switches
managed by Central) use where a profile names it: the captive portal, 802.1X termination,
the gateway's WebUI. acme keeps one name: the first time the certificate is uploaded, then
replaced under the same name, so the profiles that name it keep naming it and Central pushes
it to the devices.

    POST /oauth2/token?client_id=&client_secret=&grant_type=refresh_token&refresh_token=
         -> access_token, refresh_token (the new one kept: an old one is used up)
    GET  /configuration/v1/certificates?limit=20&offset=0&q=<name>     is it there?
    POST /configuration/v1/certificates      {"cert_name", "cert_type": "SERVER_CERT",
                                              "cert_format": "PKCS12", "passphrase": base64,
                                              "cert_data": base64 of the PKCS#12}
    PUT  /configuration/v1/non_msp/certificate    the same body: replaces the one of that name

One module: the Classic Central API the guide was checked by (pycentral's token refresh, the
API reference's certificate calls). New Central (HPE GreenLake) has no certificate store
API in the official index - not this module. AOS 8 Mobility Conductors are not Central's:
the guide found no documented API that uploads a certificate file to them.

Sources (the vendor guide navody/certifikaty/aruba/aos8-aos10-central.md and what it cites):
    https://developer.arubanetworks.com/central/reference/apicertificatesupload_certificate.md
    https://developer.arubanetworks.com/central/reference/apicertificatesupdate_certificate_for_non_msp_customer.md
    https://developer.arubanetworks.com/central/reference/apicertificatesget_certificates.md
    https://github.com/aruba/pycentral/blob/master/pycentral/base.py

Less certain: the shape of the list's answer (its items: cert_name, expire_date, checksums);
an MSP account's update call (msp_update_certificate) is not used - an MSP customer is said
in words; the gateway's restart of the service is not in the documents.
"""
from __future__ import annotations

import base64
import json
import time
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, text, random_password, tls_fields)

# the two the guide names; the others are on Central's REST API page
GATEWAYS = [['https://apigw-prod2.central.arubanetworks.com', 'US-2'],
            ['https://eu-apigw.central.arubanetworks.com', 'EU-1']]


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else text(data).encode()).decode()


class ArubaCentralTarget(HttpTarget):
    kind = 'aruba_central'
    title = 'HPE Aruba Networking Central (AOS 10)'
    vendor = 'HPE Aruba Networking'
    description = ('Uploads the certificate (PKCS#12) into the certificate store of Aruba '
                   'Central and replaces it there under the same name at each renewal, so '
                   'the profiles of AOS 10 gateways and APs that name it get it. Classic '
                   'Central API Gateway.')
    doc = 'targets.md'
    discovery = False
    fields = [
        field('gateway', 'API gateway', 'text', required=True,
              default='https://apigw-prod2.central.arubanetworks.com',
              help='the API gateway of your Central cluster (Organization → Platform '
                   'Integration → REST API shows it): %s' % ', '.join(
                       '%s %s' % (w, u) for u, w in GATEWAYS)),
        field('client_id', 'Client ID', 'text', required=True),
        field('client_secret', 'Client secret', 'secret', required=True),
        field('refresh_token', 'Refresh token', 'secret', required=True,
              help='of a token made for the API client; acme keeps the new one each refresh '
                   'gives (a refresh token is used up) - put a new one here when acme says it '
                   'is refused'),
    ] + tls_fields()
    deploy_fields = [
        field('cert_name', 'Name in Central', 'text', required=True, placeholder='captive-portal',
              help='the name the profiles use; the first deployment uploads it, the next ones '
                   'replace it under this name'),
    ]

    token = None

    def base_url(self):
        return text(self.c('gateway')).strip().rstrip('/')

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.token} if self.token else {}

    def tokens_key(self):
        return 'central-tokens:%s:%s' % (self.base_url(), self.c('client_id'))

    def kept(self):
        try:
            v = self.ctx.kv_get(self.tokens_key())
        except Exception:                               # noqa: BLE001
            v = None
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except ValueError:
                v = None
        return v if isinstance(v, dict) else {}

    def login(self):
        if self.token:
            return
        k = self.kept()
        if k.get('access') and float(k.get('until') or 0) > time.time() + 60 and \
                k.get('from') == self.c('refresh_token'):
            self.token = text(k['access'])
            return
        refresh = k.get('refresh') if k.get('from') == self.c('refresh_token') else None
        refresh = refresh or self.c('refresh_token') or ''
        qs = urllib.parse.urlencode({'client_id': self.c('client_id') or '',
                                     'client_secret': self.c('client_secret') or '',
                                     'grant_type': 'refresh_token', 'refresh_token': refresh})
        try:
            st, hd, d = self.req('POST', '/oauth2/token?' + qs, b'', auth=False,
                                 what='refreshing the token')
        except PluginError as e:
            raise PluginError('Central refused the token refresh - make a new token for the '
                              'API client and put its refresh token into the target (%s)'
                              % str(e).split(' - ')[0], retry=False)
        d = d if isinstance(d, dict) else {}
        if not d.get('access_token'):
            raise PluginError('Central gave no access_token', retry=False)
        self.token = text(d['access_token'])
        try:
            self.ctx.kv_set(self.tokens_key(), {
                'access': self.token, 'refresh': text(d.get('refresh_token') or refresh),
                'until': time.time() + float(d.get('expires_in') or 7200),
                'from': self.c('refresh_token')})
        except Exception as e:                          # noqa: BLE001
            self.ctx.step('the new refresh token cannot be kept: %s - the next run needs a '
                          'new one' % e, 'warn')

    def api(self, method, path, body=None, ok=None, what=None):
        self.login()
        st, hd, d = self.req(method, path, body, ok=ok, what=what)
        return st, d

    def find(self, name):
        st, d = self.api('GET', '/configuration/v1/certificates?' + urllib.parse.urlencode(
            {'limit': 20, 'offset': 0, 'q': name}), what='looking for %s' % name)
        items = d.get('items') if isinstance(d, dict) else d
        for it in items or []:
            if isinstance(it, dict) and text(it.get('cert_name')) == name:
                return it
        return None

    def test(self):
        st, d = self.api('GET', '/configuration/v1/certificates?limit=20&offset=0',
                         what='listing the certificates')
        items = d.get('items') if isinstance(d, dict) else d
        n = (d.get('total') if isinstance(d, dict) else None) or len(items or [])
        return 'signed in to Central (%s); %s certificate%s in its store' % (
            self.base_url(), n, '' if n == 1 else 's')

    def deploy(self, bundle, options):
        options = options or {}
        name = text(options.get('cert_name')).strip()
        if not name:
            raise PluginError('give the name the certificate has in Central', retry=False)
        if self.unchanged(bundle, options):
            return self.same(bundle, 'as %s in Central' % name)
        there = self.find(name)
        if there is not None and text(there.get('cert_type')) not in ('', 'SERVER_CERT'):
            raise PluginError('%s in Central is a %s, not a server certificate' % (
                name, there.get('cert_type')), retry=False)
        # what is there now, said (1.0.98): the decision What happens shows
        self.ctx.step('%s is in Central%s - it is replaced under that name' % (
            name, ' (until %s)' % there['expire_date'] if there.get('expire_date') else '')
            if there is not None else '%s is not in Central yet - it is uploaded' % name)
        pw = random_password(20)
        body = {'cert_name': name, 'cert_type': 'SERVER_CERT', 'cert_format': 'PKCS12',
                'passphrase': b64(pw),
                'cert_data': b64(bundle.as_format('pfx', password=pw, alias=name))}
        if there is None:
            st, d = self.api('POST', '/configuration/v1/certificates', body,
                             what='uploading %s' % name)
            words = 'uploaded %s' % name
        else:
            st, d = self.api('PUT', '/configuration/v1/non_msp/certificate', body,
                             what='replacing %s' % name)
            words = 'replaced %s' % name
        d = d if isinstance(d, dict) else {}
        self.ctx.step('%s into Central%s' % (words, ' (until %s)' % d['expire_date']
                                              if d.get('expire_date') else ''), 'ok')
        self.ctx.step('Central pushes it to the devices whose profiles name %s' % name)
        self.remember(bundle, options)
        return words
