# -*- coding: utf-8 -*-
"""DNS-01 through Amazon Route 53 - its REST API signed with AWS Signature
Version 4, written here with hashlib/hmac."""
from __future__ import annotations

import datetime
import hashlib
import hmac
import urllib.parse
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, DnsChallenge, rmw_lock

NS = '{https://route53.amazonaws.com/doc/2013-04-01/}'
VERSION = '2013-04-01'


# ---------------------------------------------------------------------------
# Signature Version 4
# ---------------------------------------------------------------------------
def _q(s, safe='-_.~'):
    return urllib.parse.quote(s, safe=safe)


def signing_key(secret, date, region, service):
    k = hmac.new(('AWS4' + secret).encode(), date.encode(), hashlib.sha256).digest()
    for part in (region, service, 'aws4_request'):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    return k


def canonical_request(method, url, headers, body):
    """(canonical request, signed headers) - the request as SigV4 writes it."""
    u = urllib.parse.urlsplit(url)
    path = _q(urllib.parse.unquote(u.path or '/'), safe='/-_.~')
    pairs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    query = '&'.join('%s=%s' % (_q(k), _q(v)) for k, v in sorted(pairs))
    hs = {}
    for k, v in headers.items():
        hs.setdefault(k.lower().strip(), []).append(' '.join(str(v).split()))
    names = sorted(hs)
    canon_h = ''.join('%s:%s\n' % (n, ','.join(hs[n])) for n in names)
    signed = ';'.join(names)
    payload = hashlib.sha256(body or b'').hexdigest()
    return '\n'.join([method.upper(), path, query, canon_h, signed, payload]), signed


def sigv4(method, url, headers, body, access_key, secret_key, region, service, amz_date=None,
          session_token=None):
    """The headers to send: those given, with x-amz-date, host and
    Authorization (and x-amz-security-token for temporary credentials)."""
    out = dict(headers or {})
    low = {k.lower() for k in out}
    for k, v in out.items():
        if k.lower() == 'x-amz-date' and amz_date is None:
            amz_date = str(v)
    if amz_date is None:
        amz_date = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    if 'x-amz-date' not in low:
        out['X-Amz-Date'] = amz_date
    if 'host' not in low:
        out['Host'] = urllib.parse.urlsplit(url).netloc
    if session_token and 'x-amz-security-token' not in low:
        out['X-Amz-Security-Token'] = session_token
    creq, signed = canonical_request(method, url, out, body)
    scope = '%s/%s/%s/aws4_request' % (amz_date[:8], region, service)
    sts = '\n'.join(['AWS4-HMAC-SHA256', amz_date, scope,
                     hashlib.sha256(creq.encode()).hexdigest()])
    sig = hmac.new(signing_key(secret_key, amz_date[:8], region, service), sts.encode(),
                   hashlib.sha256).hexdigest()
    out['Authorization'] = 'AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s' % (
        access_key, scope, signed, sig)
    return out


# ---------------------------------------------------------------------------
class Route53(DnsChallenge):
    kind = 'route53'
    api_provider = True             # its zones are asked of its API (guide)
    title = 'Amazon Route 53'
    vendor = 'Amazon'
    description = 'TXT records in a Route 53 hosted zone, with an IAM access key.'
    fields = [
        field('access_key_id', 'Access key ID', 'text', required=True, placeholder='AKIA...',
              help='An IAM user with route53:ListHostedZonesByName, ListResourceRecordSets, '
                   'ChangeResourceRecordSets (and GetChange) on the zones.'),
        field('secret_access_key', 'Secret access key', 'secret', required=True),
        field('session_token', 'Session token', 'secret', advanced=True,
              help='Only for temporary credentials (STS).'),
        field('hosted_zone_id', 'Hosted zone ID', 'text', default='', placeholder='Z0123456789ABC',
              help='Empty: found by the name (a public zone first).'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('partition', 'Partition', 'select', default='aws', advanced=True,
              options=[['aws', 'AWS (route53.amazonaws.com, us-east-1)'],
                       ['aws-cn', 'AWS China (route53.amazonaws.com.cn, cn-northwest-1)'],
                       ['aws-us-gov', 'AWS GovCloud (route53.us-gov.amazonaws.com, us-gov-west-1)']]),
        field('wait_insync', 'Wait for INSYNC', 'bool', default=True, advanced=True,
              help='Wait until Route 53 says the change is on all its servers before '
                   'looking at DNS.'),
    ] + PROPAGATION_FIELDS

    ENDPOINTS = {'aws': ('https://route53.amazonaws.com', 'us-east-1'),
                 'aws-cn': ('https://route53.amazonaws.com.cn', 'cn-northwest-1'),
                 'aws-us-gov': ('https://route53.us-gov.amazonaws.com', 'us-gov-west-1')}

    def _call(self, method, path, body=None, missing_ok=False):
        base, region = self.ENDPOINTS.get(self.c('partition', 'aws'), self.ENDPOINTS['aws'])
        url = base + path
        h = {'Content-Type': 'application/xml'} if body else {}
        h = sigv4(method, url, h, body or b'', str(self.c('access_key_id', '')),
                  str(self.c('secret_access_key', '')), region, 'route53',
                  session_token=self.c('session_token') or None)
        try:
            st, _rh, got = self.ctx.http(method, url, body=body, headers=h, timeout=30)
        except Exception as e:                          # noqa: BLE001
            raise PluginError('Route 53 did not answer: %s' % e)
        if st == 404 and missing_ok:
            return None
        if st >= 300:
            msg = ''
            try:
                x = ET.fromstring(got)
                msg = ' '.join(t.text or '' for t in x.iter() if t.tag.endswith('Message'))
            except ET.ParseError:
                msg = (got or b'')[:300].decode('utf-8', 'replace')
            raise PluginError('Route 53 said %s: %s' % (st, msg.strip()), detail=got,
                              retry=st >= 500 or 'PriorRequestNotComplete' in msg or
                              'Throttling' in msg)
        return ET.fromstring(got) if got else None

    def _zone(self, fqdn):
        if self.c('hosted_zone_id'):
            zid = str(self.c('hosted_zone_id')).split('/')[-1]
            return zid, D.norm(self.c('zone', '')) or None
        labels = D.norm(fqdn).split('.')
        for i in range(len(labels) - 1):
            cand = '.'.join(labels[i:])
            x = self._call('GET', '/%s/hostedzonesbyname?dnsname=%s&maxitems=10' % (
                VERSION, urllib.parse.quote(cand)))
            found = []
            for hz in x.iter(NS + 'HostedZone'):
                if D.norm(hz.findtext(NS + 'Name')) == cand:
                    private = (hz.findtext('%sConfig/%sPrivateZone' % (NS, NS)) or '') == 'true'
                    found.append((private, hz.findtext(NS + 'Id').split('/')[-1]))
            if found:
                return sorted(found)[0][1], cand
        raise PluginError('Route 53 has no hosted zone for %s that this key may see' % fqdn,
                          retry=False)

    def zone_hint(self, fqdn):
        try:
            return self._zone(fqdn)[1]
        except PluginError:
            return None

    def _values(self, zid, fqdn):
        x = self._call('GET', '/%s/hostedzone/%s/rrset?name=%s.&type=TXT&maxitems=1' % (
            VERSION, zid, urllib.parse.quote(D.norm(fqdn))))
        for rs in x.iter(NS + 'ResourceRecordSet'):
            if D.norm(rs.findtext(NS + 'Name')) == D.norm(fqdn) and rs.findtext(NS + 'Type') == 'TXT':
                return int(rs.findtext(NS + 'TTL') or self.ttl()), [
                    v.text for v in rs.iter(NS + 'Value')]
        return self.ttl(), []

    def _change(self, zid, action, fqdn, ttl, values):
        recs = ''.join('<ResourceRecord><Value>%s</Value></ResourceRecord>' % escape(v)
                       for v in values)
        body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/%s/">'
                '<ChangeBatch><Comment>acme DNS-01</Comment><Changes><Change>'
                '<Action>%s</Action><ResourceRecordSet><Name>%s.</Name><Type>TXT</Type>'
                '<TTL>%d</TTL><ResourceRecords>%s</ResourceRecords></ResourceRecordSet>'
                '</Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>'
                % (VERSION, action, escape(D.norm(fqdn)), ttl, recs)).encode()
        x = self._call('POST', '/%s/hostedzone/%s/rrset' % (VERSION, zid), body)
        cid = x.findtext('%sChangeInfo/%sId' % (NS, NS)) if x is not None else None
        return cid.split('/')[-1] if cid else None

    def add_txt(self, fqdn, value):
        zid, _z = self._zone(fqdn)
        one = '"%s"' % value
        cid = None
        # the RRset is read and written whole: one writer at a time (two orders side by
        # side - a wildcard and its domain, two certificates - keep each other's value)
        with rmw_lock('route53:' + str(zid)):
            ttl, have = self._values(zid, fqdn)
            if one not in have:
                cid = self._change(zid, 'UPSERT', fqdn, ttl if have else self.ttl(),
                                   have + [one])
        return {'zone_id': zid, 'change': cid}

    def ready(self, name, handle):
        h = (handle or {}).get('h')
        cid = h.get('change') if isinstance(h, dict) else None
        if cid and self.flag('wait_insync') and not self._said.get('insync:' + cid):
            x = self._call('GET', '/%s/change/%s' % (VERSION, cid))
            st = x.findtext('%sChangeInfo/%sStatus' % (NS, NS)) if x is not None else ''
            if st != 'INSYNC':
                self.say_once('r53:' + cid, 'Route 53 says the change is %s' % st)
                return False
            self._said['insync:' + cid] = True
        return DnsChallenge.ready(self, name, handle)

    def del_txt(self, fqdn, value, handle):
        zid = (handle or {}).get('zone_id') or self._zone(fqdn)[0]
        one = '"%s"' % value
        with rmw_lock('route53:' + str(zid)):
            ttl, have = self._values(zid, fqdn)
            if one not in have:
                return
            left = [v for v in have if v != one]
            if left:
                self._change(zid, 'UPSERT', fqdn, ttl, left)
            else:
                self._change(zid, 'DELETE', fqdn, ttl, have)

    def test(self):
        if self.c('hosted_zone_id'):
            x = self._call('GET', '/%s/hostedzone/%s' % (VERSION, self._zone('x')[0]))
            return 'the key sees the hosted zone %s' % x.findtext(
                '%sHostedZone/%sName' % (NS, NS))
        x = self._call('GET', '/%s/hostedzone?maxitems=20' % VERSION)
        names = [D.norm(hz.findtext(NS + 'Name')) for hz in x.iter(NS + 'HostedZone')]
        return 'the key sees %d hosted zone(s): %s' % (len(names), ', '.join(names) or 'none')

