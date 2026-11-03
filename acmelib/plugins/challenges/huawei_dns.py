# -*- coding: utf-8 -*-
"""DNS-01 in a public zone of Huawei Cloud DNS, through its API v2 (1.0.26):

    GET    https://dns.{region}.myhuaweicloud.com/v2/zones?type=public&limit=500[&marker=..]
                                       {zones: [{id, name: "example.com."}], links: {next}}
    GET    .../v2/zones/{zone_id}/recordsets?type=TXT&name=_acme-challenge.www.example.com.
           &search_mode=equal          {recordsets: [{id, name, type, ttl, records, status}]}
    POST   .../v2/zones/{zone_id}/recordsets   {name, type: TXT, ttl, records: ["\\"<value>\\""]}
    PUT    .../v2/zones/{zone_id}/recordsets/{recordset_id}  {name, type, ttl, records}
    DELETE .../v2/zones/{zone_id}/recordsets/{recordset_id}

A zone has one record set a name and type, holding every value: acme adds
its value (in double quotes, as Huawei Cloud writes a TXT value) to the set -
or makes the set - and on cleanup writes the set back without it (PUT), or
deletes the set when ours was its last value; one change at a time on this
node. A change answers 202 and the set is PENDING_* for a moment: a change
refused with DNS.0314 ("not in a steady state") is read again and tried
again after 2, 4, 8, 16 s; DNS.0312 ("name already exists") on making the set
reads it again and adds to it.

Every request is signed with the access key (AK/SK, SDK-HMAC-SHA256):

    CanonicalRequest = METHOD \\n CanonicalURI (ending in "/") \\n CanonicalQueryString (sorted,
                       %20 for a space) \\n CanonicalHeaders (lowercase:trimmed\\n, sorted) \\n
                       SignedHeaders \\n HexEncode(SHA256(body))
    StringToSign     = "SDK-HMAC-SHA256" \\n X-Sdk-Date \\n HexEncode(SHA256(CanonicalRequest))
    Authorization: SDK-HMAC-SHA256 Access=<AK>, SignedHeaders=<..>, Signature=HexEncode(HMAC-SHA256(SK, StringToSign))

with X-Sdk-Date (YYYYMMDDTHHMMSSZ, UTC - this machine's clock within 15
minutes) and Host signed, Content-Type too when there is a body, and
X-Project-Id / X-Security-Token (a temporary AK/SK) when set.

Sources (the user's collection of Huawei Cloud's documentation,
api-docs/huawei_dns/notes.md, quoting): the API overview
https://support.huaweicloud.com/intl/en-us/api-dns/dns_api_10000.html, Making
an API Request https://support.huaweicloud.com/intl/en-us/api-dns/en-us_topic_0037134406.html
(X-Sdk-Date, Host, X-Project-Id), Authentication
https://support.huaweicloud.com/intl/en-us/api-dns/dns_api_30003.html (AK/SK,
X-Security-Token, the 15 minutes), the AK/SK signing algorithm
https://support.huaweicloud.com/intl/en-us/devg-apisign/api-sign-algorithm-001.html
and its example api-sign-algorithm-002.html, ListPublicZones
https://support.huaweicloud.com/intl/en-us/api-dns/dns_api_62003.html,
CreateRecordSet, ListRecordSetsByZone, UpdateRecordSet, DeleteRecordSet
(https://support.huaweicloud.com/intl/en-us/api-dns/CreateRecordSet.html and
the pages beside it), the error codes
https://support.huaweicloud.com/intl/en-us/api-dns/ErrorCode.html, the TXT
rules https://support.huaweicloud.com/intl/en-us/usermanual-dns/dns_usermanual_0601.html
("Text record values must be enclosed in double quotation marks"), and the
official Go SDK https://github.com/huaweicloud/huaweicloud-sdk-go-v3
(services/dns/v2/dns_meta.go - the paths and methods; region/region.go -
https://dns.{region}.myhuaweicloud.com).

Less certain (the documentation leaves it open): no TXT example is in the API
reference (the quotes are from the console's rules); that PUT with the rest
of the values is the way to take one away (records "replaces" the set - read
from the field's description); how path segments and query values beyond
the unreserved characters are escaped for signing (acme's are only letters,
digits, "-", "_", "." and "~"); which record set is taken when several hold
the name (a v2.1 resolution line) - the first listed; no rate limit and no
lowest TTL beyond "1 to 2147483647" are documented (300 is used when not set).
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _common as C
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, rmw_lock,
                                                unquote_txt)
from acmelib.plugins.challenges._records import SoftZones, zone_field

ALGO = 'SDK-HMAC-SHA256'
STEADY_WAITS = (2, 4, 8, 16)    # DNS.0314: the record set is still PENDING_*


def _enc(s):
    return urllib.parse.quote(str(s), safe='-_.~')


def canonical(method, url, headers, body):
    """(CanonicalRequest, SignedHeaders) as Huawei Cloud's signing algorithm writes them."""
    u = urllib.parse.urlsplit(url)
    path = '/'.join(_enc(urllib.parse.unquote(p)) for p in (u.path or '/').split('/'))
    if not path.endswith('/'):
        path += '/'
    pairs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    query = '&'.join('%s=%s' % (_enc(k), _enc(v)) for k, v in sorted(pairs))
    hs = {k.lower().strip(): ' '.join(str(v).split()) for k, v in headers.items()}
    names = sorted(hs)
    canon_h = ''.join('%s:%s\n' % (n, hs[n]) for n in names)
    signed = ';'.join(names)
    payload = hashlib.sha256(body or b'').hexdigest()
    return '\n'.join([method.upper(), path, query, canon_h, signed, payload]), signed


def sign(method, url, headers, body, ak, sk, sdk_date=None):
    """The headers to send: those given (all of them signed) with Host, X-Sdk-Date and
    Authorization."""
    out = dict(headers or {})
    low = {k.lower() for k in out}
    if 'host' not in low:
        out['Host'] = urllib.parse.urlsplit(url).netloc
    if 'x-sdk-date' not in low:
        out['X-Sdk-Date'] = sdk_date or datetime.datetime.now(
            datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    date = next(v for k, v in out.items() if k.lower() == 'x-sdk-date')
    creq, signed = canonical(method, url, out, body)
    sts = '\n'.join([ALGO, date, hashlib.sha256(creq.encode('utf-8')).hexdigest()])
    sig = hmac.new(str(sk).encode('utf-8'), sts.encode('utf-8'), hashlib.sha256).hexdigest()
    out['Authorization'] = '%s Access=%s, SignedHeaders=%s, Signature=%s' % (ALGO, ak, signed,
                                                                             sig)
    return out


def quoted(value):
    return '"%s"' % value


class HuaweiDns(SoftZones, ApiDns):
    kind = 'huawei_dns'
    title = 'Huawei Cloud DNS'
    vendor = 'Huawei Cloud'
    who = 'Huawei Cloud DNS'
    min_ttl = 1                     # "1 to 2147483647"
    description = 'TXT records in a public zone of Huawei Cloud DNS, with an access key (AK/SK).'
    fields = [
        field('access_key', 'Access key ID (AK)', 'text', required=True,
              help='An access key of an IAM user allowed to read the zones and change their '
                   'record sets (best one for acme alone).'),
        field('secret_key', 'Secret access key (SK)', 'secret', required=True),
        field('region', 'Region', 'text', required=True, placeholder='ap-southeast-1',
              help='The region whose DNS endpoint acme asks, as Huawei Cloud names it '
                   '(ap-southeast-1, cn-north-4, tr-west-1, …): https://dns.{region}.myhuaweicloud.com.'),
        zone_field(['access_key', 'secret_key', 'region']),
        field('project_id', 'Project ID', 'text', default='', advanced=True,
              help='Sent as X-Project-Id - only where Huawei Cloud asks for it (several '
                   'projects in a region, Dedicated Cloud).'),
        field('security_token', 'Security token', 'secret', default='', advanced=True,
              help='Only for a temporary AK/SK: sent as X-Security-Token.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True),
        field('api', 'API address', 'text', default='', advanced=True,
              placeholder='https://dns.ap-southeast-1.myhuaweicloud.com',
              help='Empty: https://dns.{region}.myhuaweicloud.com.'),
    ] + PROPAGATION_FIELDS

    def _base(self):
        given = str(self.c('api') or '').strip().rstrip('/')
        if given:
            return given
        region = str(self.c('region') or '').strip().lower()
        if not region or not all(c.isalnum() or c == '-' for c in region):
            raise PluginError('the Huawei Cloud region is not set (ap-southeast-1, say)',
                              retry=False)
        return 'https://dns.%s.myhuaweicloud.com' % region

    def _call(self, method, path, body=None, missing_ok=False):
        url = self._base() + path
        raw = None
        h = {}
        if body is not None:
            raw = json.dumps(body).encode()
            h['Content-Type'] = 'application/json'
        if self.c('project_id'):
            h['X-Project-Id'] = str(self.c('project_id'))
        if self.c('security_token'):
            h['X-Security-Token'] = str(self.c('security_token'))
        h = sign(method, url, h, raw, str(self.c('access_key', '')), str(self.c('secret_key', '')))
        st, got = api(self.ctx, method, url, None, h, who='Huawei Cloud DNS', raw_body=raw,
                      ok=tuple(range(200, 600)))
        if st == 404 and missing_ok:
            return None
        if st not in (200, 201, 202, 204):
            g = got if isinstance(got, dict) else {}
            code = str(g.get('code') or g.get('error_code') or '')
            said = ('%s %s' % (code, g.get('message') or g.get('error_msg') or '')).strip()
            words = 'Huawei Cloud DNS said %s: %s' % (st, said or 'nothing more')
            if st in (401, 403):
                words += ' - the access key is wrong or may not do this'
            raise PluginError(words, detail=said or str(got), retry=st >= 500 or st == 429)
        return got

    # -- zones ------------------------------------------------------------------------------
    def _zone_ids(self, name=None):
        out, marker = {}, None
        for _page in range(50):
            q = [('type', 'public'), ('limit', '500')]
            if name:
                q += [('name', D.norm(name) + '.'), ('search_mode', 'equal')]
            if marker:
                q.append(('marker', marker))
            got = self._call('GET', '/v2/zones?' + urllib.parse.urlencode(q)) or {}
            rows = [z for z in got.get('zones') or [] if isinstance(z, dict) and z.get('id')]
            out.update({D.norm(z.get('name')): z['id'] for z in rows if z.get('name')})
            nxt = (got.get('links') or {}).get('next')
            marker = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(nxt).query)).get(
                'marker') if nxt else None
            if not rows or not marker:
                break
        return out

    def zone_names(self):
        return list(self._zone_ids())

    def _zid(self, zone):
        if not hasattr(self, '_ids'):
            self._ids = {}
        z = D.norm(zone)
        if z not in self._ids:
            zid = self._zone_ids(z).get(z)
            if not zid:
                raise PluginError('Huawei Cloud DNS has no public zone %s that this key may '
                                  'see' % z, retry=False)
            self._ids[z] = zid
        return self._ids[z]

    def _set(self, zid, fqdn):
        """The TXT record set at fqdn ({id, ttl, records}), or None."""
        q = urllib.parse.urlencode([('type', 'TXT'), ('name', D.norm(fqdn) + '.'),
                                    ('search_mode', 'equal'), ('limit', '500')])
        got = self._call('GET', '/v2/zones/%s/recordsets?%s' % (zid, q)) or {}
        for rs in got.get('recordsets') or []:
            if isinstance(rs, dict) and str(rs.get('type')).upper() == 'TXT' and \
                    D.norm(rs.get('name')) == D.norm(fqdn):
                return rs
        return None

    def _steady(self, fn, what):
        """fn() - again after a while when the set is not in a steady state (DNS.0314)."""
        for wait in STEADY_WAITS + (None,):
            try:
                return fn()
            except PluginError as e:
                if wait is None or 'DNS.0314' not in '%s %s' % (e, e.detail or ''):
                    raise
                self.ctx.step('Huawei Cloud DNS: %s is still being changed - again in %d s' %
                              (what, wait))
                C.SLEEP(wait)

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        zid = self._zid(zone)

        def once():
            rs = self._set(zid, fqdn)
            if rs is None:
                try:
                    self._call('POST', '/v2/zones/%s/recordsets' % zid, {
                        'name': D.norm(fqdn) + '.', 'type': 'TXT', 'ttl': self.ttl(),
                        'records': [quoted(value)]})
                    return
                except PluginError as e:
                    if not any(c in '%s %s' % (e, e.detail or '') for c in ('DNS.0312',
                                                                         'DNS.0335')):
                        raise
                    rs = self._set(zid, fqdn)
                    if rs is None:
                        raise
            have = [str(v) for v in rs.get('records') or []]
            if value in [unquote_txt(v) for v in have]:
                return
            self._call('PUT', '/v2/zones/%s/recordsets/%s' % (zid, rs['id']), {
                'name': D.norm(fqdn) + '.', 'type': 'TXT', 'ttl': rs.get('ttl') or self.ttl(),
                'records': have + [quoted(value)]})
        with rmw_lock('huawei_dns|%s' % zid):
            self._steady(once, fqdn)
        return {'zone': zone, 'zid': zid}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        zid = h.get('zid') or self._zid(zone)

        def once():
            rs = self._set(zid, fqdn)
            if rs is None:
                return
            have = [str(v) for v in rs.get('records') or []]
            left = [v for v in have if unquote_txt(v) != value]
            if len(left) == len(have):
                return                                  # gone already
            path = '/v2/zones/%s/recordsets/%s' % (zid, rs['id'])
            if left:
                self._call('PUT', path, {'name': D.norm(fqdn) + '.', 'type': 'TXT',
                                         'ttl': rs.get('ttl') or self.ttl(), 'records': left})
            else:
                self._call('DELETE', path, missing_ok=True)
        with rmw_lock('huawei_dns|%s' % zid):
            self._steady(once, fqdn)

    def test(self):
        z = D.norm(self.c('zone', ''))
        if z:
            self._zid(z)
            return 'Huawei Cloud DNS: the key sees the public zone %s' % z
        return ApiDns.test(self)
