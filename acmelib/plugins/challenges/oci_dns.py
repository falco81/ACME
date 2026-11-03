# -*- coding: utf-8 -*-
"""DNS-01 at Oracle Cloud Infrastructure DNS, its REST API (20180115) with
OCI's request signatures (draft-cavage HTTP signatures, rsa-sha256), the
RSA signature made by the openssl program:

    GET   https://dns.{region}.oci.oraclecloud.com/20180115/zones?compartmentId=..&zoneType=PRIMARY
    GET   .../zones/{zone}/records/{fqdn}?rtype=TXT          {items: [{domain, rtype, rdata, ttl}]}
    PATCH .../zones/{zone}/records/{fqdn}/TXT   {items: [{operation: ADD|REMOVE, domain, rtype, rdata, ttl}]}

The signing string is the headers "date (request-target) host" - for a body
also "content-length content-type x-content-sha256" (base64 SHA-256 of the
body) - each "name: value" on a line of its own; Authorization: Signature
version="1",headers="...",keyId="TENANCY/USER/FINGERPRINT",algorithm=
"rsa-sha256",signature="base64". PATCH adds or removes one value of the
RRset, so other orders' values stay; REMOVE names the rdata as OCI keeps it.

Sources: https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm
(the signature and its published test key and signatures - the test checks
both) and https://docs.oracle.com/en-us/iaas/api/#/en/dns/20180115/ (the DNS
API) - not reachable from where this was written; the vectors are those of
Oracle's oci-go-sdk (common/http_signer_test.go), the DNS calls as lego's
providers/dns/oraclecloud (the SDK) makes them. The user's API key is a PEM
RSA key without a passphrase.
"""
from __future__ import annotations

import base64
import email.utils
import hashlib
import json
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, api, openssl_sign,
                                                unquote_txt)
from acmelib.plugins.challenges._records import RecordApiDns

VERSION = '20180115'


def signing_string(method, url, headers):
    """(signing string, header names) for OCI: headers a dict holding date,
    host and, for a body, content-length, content-type and x-content-sha256."""
    u = urllib.parse.urlsplit(url)
    target = u.path + (('?' + u.query) if u.query else '')
    low = {k.lower(): str(v) for k, v in headers.items()}
    low['(request-target)'] = '%s %s' % (method.lower(), target)
    low.setdefault('host', u.netloc)
    names = ['date', '(request-target)', 'host']
    if method.upper() in ('POST', 'PUT', 'PATCH'):
        names += ['content-length', 'content-type', 'x-content-sha256']
    return '\n'.join('%s: %s' % (n, low[n]) for n in names), names


def sign_headers(ctx, method, url, body, key_id, key_pem, date=None):
    """The headers to send, Authorization made with the key (openssl)."""
    h = {'date': date or email.utils.formatdate(usegmt=True),
         'host': urllib.parse.urlsplit(url).netloc}
    if method.upper() in ('POST', 'PUT', 'PATCH'):
        body = body or b''
        h['content-type'] = 'application/json'
        h['content-length'] = str(len(body))
        h['x-content-sha256'] = base64.b64encode(hashlib.sha256(body).digest()).decode()
    sts, names = signing_string(method, url, h)
    sig = base64.b64encode(openssl_sign(ctx, key_pem, sts.encode('utf-8'))).decode()
    h['authorization'] = ('Signature version="1",headers="%s",keyId="%s",algorithm="rsa-sha256",'
                          'signature="%s"' % (' '.join(names), key_id, sig))
    return h


class OciDns(RecordApiDns):
    kind = 'oci_dns'
    discover_keys = ['tenancy', 'user', 'fingerprint', 'key', 'region', 'api']   # the signing
    title = 'Oracle Cloud (OCI) DNS'
    vendor = 'Oracle Cloud'
    who = 'OCI DNS'
    min_ttl = 30
    description = 'TXT records in a public zone of Oracle Cloud Infrastructure DNS, with a ' \
                  'user\'s API signing key.'
    fields = [
        field('tenancy', 'Tenancy OCID', 'text', required=True,
              placeholder='ocid1.tenancy.oc1..aaaa...'),
        field('user', 'User OCID', 'text', required=True, placeholder='ocid1.user.oc1..aaaa...',
              help='Identity → Users → a user for acme → API keys → Add API key: the private key '
                   'below, its fingerprint shown there. A policy such as "Allow group acme-dns to '
                   'manage dns in compartment X".'),
        field('fingerprint', 'Key fingerprint', 'text', required=True,
              placeholder='20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34'),
        field('key', 'API private key', 'pem', secret=True, required=True,
              help='The PEM private key of that API key (RSA, without a passphrase).'),
        field('region', 'Region', 'text', required=True, placeholder='eu-frankfurt-1'),
        field('compartment', 'Compartment OCID', 'text', default='',
              help='Where the zones are; empty: the tenancy (the root compartment).'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone of the compartment the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=30, advanced=True),
        field('api', 'API address', 'text', default='', advanced=True,
              help='Empty: https://dns.<region>.oci.oraclecloud.com'),
    ] + PROPAGATION_FIELDS

    def _base(self):
        b = str(self.c('api', '') or '').rstrip('/')
        return (b or 'https://dns.%s.oci.oraclecloud.com' % str(self.c('region', '')).strip()) + \
            '/' + VERSION

    def _call(self, method, path, body=None, missing_ok=False):
        url = self._base() + path
        data = json.dumps(body).encode() if body is not None else None
        key_id = '%s/%s/%s' % (self.c('tenancy', ''), self.c('user', ''),
                               self.c('fingerprint', ''))
        h = sign_headers(self.ctx, method, url, data, key_id, self.c('key', ''))
        st, got = api(self.ctx, method, url, headers=h, raw_body=data, who='OCI DNS',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def zone_names(self):
        comp = str(self.c('compartment', '') or self.c('tenancy', ''))
        got = self._call('GET', '/zones?' + urllib.parse.urlencode(
            {'compartmentId': comp, 'zoneType': 'PRIMARY', 'limit': 100})) or []
        return [z.get('name') for z in got if isinstance(z, dict)]

    def _path(self, zone, fqdn):
        return '/zones/%s/records/%s' % (urllib.parse.quote(zone), urllib.parse.quote(fqdn))

    def txt_records(self, zone, fqdn):
        got = self._call('GET', self._path(zone, fqdn) + '?rtype=TXT', missing_ok=True) or {}
        return [(r.get('rdata'), r.get('rdata')) for r in got.get('items') or []
                if str(r.get('rtype')).upper() == 'TXT' and D.norm(r.get('domain') or '') == fqdn]

    def create_txt(self, zone, fqdn, value):
        self._call('PATCH', self._path(zone, fqdn) + '/TXT', {'items': [
            {'operation': 'ADD', 'domain': fqdn, 'rtype': 'TXT', 'rdata': value,
             'ttl': self.ttl()}]})
        return None

    def delete_txt(self, zone, fqdn, record_id, value):
        rdata = record_id if unquote_txt(record_id) == value else value
        self._call('PATCH', self._path(zone, fqdn) + '/TXT', {'items': [
            {'operation': 'REMOVE', 'domain': fqdn, 'rtype': 'TXT', 'rdata': rdata}]})

    def test(self):
        if not str(self.c('region', '') or '').strip():
            raise PluginError('no region is set', retry=False)
        return RecordApiDns.test(self)
