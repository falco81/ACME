# -*- coding: utf-8 -*-
"""DNS-01 through Google Cloud DNS - a service account's key (JSON), the
access token got with a JWT signed RS256 by the openssl program."""
from __future__ import annotations

import base64
import json
import os
import shutil
import tempfile
import time
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, DnsChallenge, api, rmw_lock

SCOPE = 'https://www.googleapis.com/auth/ndev.clouddns.readwrite'
BASE = 'https://dns.googleapis.com/dns/v1'


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def make_jwt(ctx, sa, now=None, scope=SCOPE):
    """The signed assertion for Google's token endpoint."""
    now = int(time.time() if now is None else now)
    head = {'alg': 'RS256', 'typ': 'JWT'}
    if sa.get('private_key_id'):
        head['kid'] = sa['private_key_id']
    claims = {'iss': sa['client_email'], 'scope': scope,
              'aud': sa.get('token_uri') or 'https://oauth2.googleapis.com/token',
              'iat': now, 'exp': now + 3600}
    signing = (b64url(json.dumps(head, separators=(',', ':')).encode()) + '.' +
               b64url(json.dumps(claims, separators=(',', ':')).encode()))
    work = tempfile.mkdtemp(prefix='acme-gcp-')
    try:
        os.chmod(work, 0o700)
        kf = os.path.join(work, 'key.pem')
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(sa['private_key'])
        sig = ctx.openssl(['dgst', '-sha256', '-sign', kf], data=signing.encode())
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if not sig:
        raise PluginError('openssl did not sign the token request')
    return signing + '.' + b64url(sig)


class GoogleCloudDns(DnsChallenge):
    kind = 'gcloud_dns'
    title = 'Google Cloud DNS'
    vendor = 'Google'
    description = 'TXT records in a Cloud DNS managed zone, with a service account\'s key.'
    fields = [
        field('service_account', 'Service account key (JSON)', 'secret', required=True,
              help='IAM → Service accounts → Keys → Add key → JSON, pasted whole. The account '
                   'needs the role "DNS Administrator" (dns.admin) on the project.'),
        field('project', 'Project ID', 'text', default='',
              help='Empty: the project of the service account.'),
        field('managed_zone', 'Managed zone', 'text', default='',
              help='Its name in Cloud DNS (not the domain). Empty: found by the domain.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    _token = None
    _token_until = 0.0

    def _sa(self):
        try:
            sa = json.loads(self.c('service_account', '') or '{}')
        except ValueError:
            raise PluginError('the service account key is not JSON', retry=False)
        for k in ('client_email', 'private_key'):
            if not sa.get(k):
                raise PluginError('the service account key has no %s' % k, retry=False)
        return sa

    def _project(self):
        return self.c('project', '') or self._sa().get('project_id') or ''

    def token(self):
        if self._token and time.time() < self._token_until - 60:
            return self._token
        sa = self._sa()
        body = urllib.parse.urlencode({
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': make_jwt(self.ctx, sa)}).encode()
        _st, got = api(self.ctx, 'POST', sa.get('token_uri') or 'https://oauth2.googleapis.com/token',
                       raw_body=body, headers={'Content-Type': 'application/x-www-form-urlencoded'},
                       who='Google')
        if not got or not got.get('access_token'):
            raise PluginError('Google gave no token', retry=False)
        self._token = got['access_token']
        self._token_until = time.time() + float(got.get('expires_in') or 3000)
        return self._token

    def _call(self, method, path, body=None):
        return api(self.ctx, method, '%s/projects/%s%s' % (
            BASE, urllib.parse.quote(self._project()), path), body,
            {'Authorization': 'Bearer ' + self.token()}, who='Google Cloud DNS')[1]

    def _managed_zone(self, fqdn):
        if self.c('managed_zone'):
            return self.c('managed_zone')
        best = None
        got = self._call('GET', '/managedZones') or {}
        for z in got.get('managedZones') or []:
            dom = D.norm(z.get('dnsName'))
            if D.in_zone(fqdn, dom) and (best is None or len(dom) > len(best[0])) and \
                    z.get('visibility', 'public') == 'public':
                best = (dom, z.get('name'))
        if not best:
            raise PluginError('Cloud DNS has no public zone for %s in %s' % (
                fqdn, self._project()), retry=False)
        return best[1]

    def _rrset(self, mz, fqdn):
        got = self._call('GET', '/managedZones/%s/rrsets?name=%s.&type=TXT' % (
            urllib.parse.quote(mz), urllib.parse.quote(D.norm(fqdn)))) or {}
        for rs in got.get('rrsets') or []:
            if D.norm(rs.get('name')) == D.norm(fqdn) and rs.get('type') == 'TXT':
                return rs
        return None

    def _replace(self, mz, fqdn, old, values):
        change = {'additions': [], 'deletions': []}
        if old:
            change['deletions'].append(old)
        if values:
            change['additions'].append({'name': D.norm(fqdn) + '.', 'type': 'TXT',
                                        'ttl': self.ttl(), 'rrdatas': values})
        self._call('POST', '/managedZones/%s/changes' % urllib.parse.quote(mz), change)

    def add_txt(self, fqdn, value):
        mz = self._managed_zone(fqdn)
        one = '"%s"' % value
        # the RRset is replaced whole: one writer at a time
        with rmw_lock(('gcloud', self._project(), mz)):
            old = self._rrset(mz, fqdn)
            have = list((old or {}).get('rrdatas') or [])
            if one not in have:
                self._replace(mz, fqdn, old, have + [one])
        return {'managed_zone': mz}

    def del_txt(self, fqdn, value, handle):
        mz = (handle or {}).get('managed_zone') or self._managed_zone(fqdn)
        one = '"%s"' % value
        with rmw_lock(('gcloud', self._project(), mz)):
            old = self._rrset(mz, fqdn)
            have = list((old or {}).get('rrdatas') or [])
            if one in have:
                self._replace(mz, fqdn, old, [v for v in have if v != one])

    def test(self):
        got = self._call('GET', '/managedZones') or {}
        zs = ['%s (%s)' % (z.get('dnsName'), z.get('name')) for z in got.get('managedZones') or []]
        return 'signed in as %s; %d zone(s) in %s: %s' % (
            self._sa()['client_email'], len(zs), self._project(), ', '.join(zs[:20]))
