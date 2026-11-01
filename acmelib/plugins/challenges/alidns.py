# -*- coding: utf-8 -*-
"""DNS-01 at Alibaba Cloud DNS (Aliyun DNS), through its RPC API, version
2015-01-09, signed with signature version 1.0 (HMAC-SHA1) written here:

    GET https://alidns.aliyuncs.com/?Action=...&<common parameters>&Signature=...

    DescribeDomains       PageNumber, PageSize                       Domains.Domain[].DomainName
    DescribeDomainRecords DomainName, RRKeyWord, TypeKeyWord=TXT     DomainRecords.Record[]: RecordId, RR, Type, Value
    AddDomainRecord       DomainName, RR, Type=TXT, Value, TTL       RecordId
    DeleteDomainRecord    RecordId

Common parameters: Format=JSON, Version, AccessKeyId, SignatureMethod=
HMAC-SHA1, SignatureVersion=1.0, SignatureNonce, Timestamp (UTC,
YYYY-MM-DDThh:mm:ssZ). StringToSign = "GET&%2F&" + percent(the parameters
sorted, each percent-encoded, joined key=value&...), percent-encoding as RFC
3986 (A-Z a-z 0-9 - _ . ~ kept, the rest %XX upper case); the key is the
AccessKey secret + "&"; Signature = base64(HMAC-SHA1).

Sources: https://www.alibabacloud.com/help/en/sdk/product-overview/rpc-mechanism
(the signature, with its worked example - the test checks it), and
https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-dir-parsing-records
(the actions). Neither was reachable from where this was written; they are as
remembered and as acme.sh's dnsapi/dns_ali.sh and Posh-ACME's Aliyun plugin
call them. The free edition of Alibaba Cloud DNS takes no TTL under 600.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import urllib.parse
import uuid

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns, rel_name

API = 'https://alidns.aliyuncs.com'
VERSION = '2015-01-09'


def pct(s):
    return urllib.parse.quote(str(s), safe='-_.~')


def rpc_signature(params, secret, method='GET'):
    """Signature version 1.0 of the parameters (without Signature)."""
    canon = '&'.join('%s=%s' % (pct(k), pct(v)) for k, v in sorted(params.items()))
    sts = '%s&%s&%s' % (method, pct('/'), pct(canon))
    return base64.b64encode(hmac.new((secret + '&').encode('utf-8'), sts.encode('utf-8'),
                                     hashlib.sha1).digest()).decode()


def signed_query(action, args, key_id, secret, timestamp=None, nonce=None, version=VERSION):
    p = {'Action': action, 'Format': 'JSON', 'Version': version, 'AccessKeyId': key_id,
         'SignatureMethod': 'HMAC-SHA1', 'SignatureVersion': '1.0',
         'SignatureNonce': nonce or str(uuid.uuid4()),
         'Timestamp': timestamp or datetime.datetime.now(datetime.timezone.utc).strftime(
             '%Y-%m-%dT%H:%M:%SZ')}
    p.update({k: str(v) for k, v in (args or {}).items()})
    p['Signature'] = rpc_signature(p, secret)
    return '&'.join('%s=%s' % (pct(k), pct(v)) for k, v in sorted(p.items()))


class AliDns(RecordApiDns):
    kind = 'alidns'
    title = 'Alibaba Cloud DNS'
    vendor = 'Alibaba Cloud'
    who = 'Alibaba Cloud DNS'
    min_ttl = 600
    description = 'TXT records in a domain at Alibaba Cloud DNS (Aliyun), with a RAM AccessKey.'
    fields = [
        field('key_id', 'AccessKey ID', 'text', required=True,
              help='RAM console → Users → a user for acme → AccessKey: create one. Give the '
                   'user the policy AliyunDNSFullAccess (or a policy with alidns:DescribeDomains, '
                   'DescribeDomainRecords, AddDomainRecord and DeleteDomainRecord).'),
        field('secret', 'AccessKey secret', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=600, advanced=True,
              help='The free edition takes 600 or more; paid editions less.'),
        field('api', 'API address', 'text', default=API, advanced=True,
              help='The endpoint of the region, e.g. https://alidns.ap-southeast-1.aliyuncs.com.'),
    ] + PROPAGATION_FIELDS

    def _call(self, action, **args):
        q = signed_query(action, args, str(self.c('key_id', '')), str(self.c('secret', '')))
        _st, got = api(self.ctx, 'GET', '%s/?%s' % (str(self.c('api', API)).rstrip('/'), q),
                       who='Alibaba Cloud DNS')
        if isinstance(got, dict) and got.get('Code') and not got.get('RequestId'):
            raise PluginError('Alibaba Cloud DNS said %s: %s' % (got.get('Code'),
                                                                 got.get('Message')), detail=got)
        return got or {}

    def zone_names(self):
        out, page = [], 1
        while page < 50:
            got = self._call('DescribeDomains', PageNumber=page, PageSize=100)
            doms = (got.get('Domains') or {}).get('Domain') or []
            out += [d.get('DomainName') for d in doms]
            if len(out) >= int(got.get('TotalCount') or 0) or not doms:
                break
            page += 1
        return out

    def txt_records(self, zone, fqdn):
        rr = rel_name(fqdn, zone)
        got = self._call('DescribeDomainRecords', DomainName=zone, RRKeyWord=rr,
                         TypeKeyWord='TXT', PageSize=100)
        return [(r.get('RecordId'), r.get('Value')) for r in
                (got.get('DomainRecords') or {}).get('Record') or []
                if r.get('RR') == rr and str(r.get('Type')).upper() == 'TXT']

    def create_txt(self, zone, fqdn, value):
        try:
            return self._call('AddDomainRecord', DomainName=zone, RR=rel_name(fqdn, zone),
                              Type='TXT', Value=value, TTL=self.ttl()).get('RecordId')
        except PluginError as e:
            if 'DomainRecordDuplicate' in str(e):
                return None
            raise

    def delete_txt(self, zone, fqdn, record_id, value):
        try:
            self._call('DeleteDomainRecord', RecordId=record_id)
        except PluginError as e:
            if 'DomainRecordNotBelongToUser' not in str(e) and 'NotExist' not in str(e):
                raise
