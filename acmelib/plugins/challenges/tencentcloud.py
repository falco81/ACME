# -*- coding: utf-8 -*-
"""DNS-01 at Tencent Cloud DNSPod, through API 3.0 (version 2021-03-23),
signed with TC3-HMAC-SHA256 written here:

    POST https://dnspod.tencentcloudapi.com/   X-TC-Action, X-TC-Version, X-TC-Timestamp,
         Authorization: TC3-HMAC-SHA256 Credential=ID/DATE/dnspod/tc3_request,
                        SignedHeaders=content-type;host, Signature=...

    DescribeDomainList   {Offset, Limit}                                     Response.DomainList[].Name
    DescribeRecordList   {Domain, Subdomain, RecordType: "TXT"}               Response.RecordList[]: RecordId, Name, Type, Value
    CreateRecord         {Domain, SubDomain, RecordType, RecordLine, Value, TTL}   Response.RecordId
    DeleteRecord         {Domain, RecordId}

CanonicalRequest = POST \\n / \\n \\n content-type:...\\nhost:...\\n \\n
content-type;host \\n hex(sha256(body)); StringToSign = TC3-HMAC-SHA256 \\n
timestamp \\n DATE/dnspod/tc3_request \\n hex(sha256(CanonicalRequest)); the
key HMAC("TC3" + secret, DATE) -> service -> "tc3_request". Errors come as
Response.Error {Code, Message} with status 200; DescribeRecordList answers
ResourceNotFound.NoDataOfRecord when there is none.

Sources: https://www.tencentcloud.com/document/api/1157/49029 (Signature v3)
and https://www.tencentcloud.com/document/product/1157/49025 (DNSPod
records) - not reachable from where this was written; the signature is as
documented (the test checks the hashed canonical request of Tencent's own
worked example), the calls as lego's providers/dns/tencentcloud (the SDK)
and Posh-ACME's TencentDNS make them. RecordLine "默认" is the default line.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import time

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, http_call, said_error
from acmelib.plugins.challenges._records import RecordApiDns, rel_name

HOST = 'dnspod.tencentcloudapi.com'
VERSION = '2021-03-23'


def tc3_headers(secret_id, secret_key, service, host, action, version, payload, timestamp=None,
                region=None, content_type='application/json; charset=utf-8'):
    """The headers of a TC3-HMAC-SHA256 signed POST (payload: bytes)."""
    ts = int(time.time() if timestamp is None else timestamp)
    date = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%d')
    creq = '\n'.join(['POST', '/', '', 'content-type:%s\nhost:%s\n' % (content_type, host),
                      'content-type;host', hashlib.sha256(payload).hexdigest()])
    scope = '%s/%s/tc3_request' % (date, service)
    sts = '\n'.join(['TC3-HMAC-SHA256', str(ts), scope,
                     hashlib.sha256(creq.encode('utf-8')).hexdigest()])

    def h(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
    k = h(h(h(('TC3' + secret_key).encode('utf-8'), date), service), 'tc3_request')
    sig = hmac.new(k, sts.encode('utf-8'), hashlib.sha256).hexdigest()
    out = {'Authorization': 'TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host, '
                            'Signature=%s' % (secret_id, scope, sig),
           'Content-Type': content_type, 'Host': host, 'X-TC-Action': action,
           'X-TC-Timestamp': str(ts), 'X-TC-Version': version}
    if region:
        out['X-TC-Region'] = region
    return out, creq


class TencentCloud(RecordApiDns):
    kind = 'tencentcloud'
    title = 'Tencent Cloud DNSPod'
    vendor = 'Tencent Cloud'
    who = 'DNSPod'
    min_ttl = 600
    description = 'TXT records in a domain at Tencent Cloud DNSPod, with an API key (SecretId).'
    fields = [
        field('secret_id', 'SecretId', 'text', required=True,
              help='Tencent Cloud console → CAM → Users → a user for acme → API keys. Give the '
                   'user the policy QcloudDNSPodFullAccess (or one with DescribeDomainList, '
                   'DescribeRecordList, CreateRecord and DeleteRecord).'),
        field('secret_key', 'SecretKey', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=600, advanced=True,
              help='The free plan takes 600 or more.'),
        field('host', 'API host', 'text', default=HOST, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, action, body, missing=()):
        host = str(self.c('host', HOST) or HOST)
        payload = json.dumps(body, ensure_ascii=False).encode('utf-8')
        h, _cr = tc3_headers(str(self.c('secret_id', '')), str(self.c('secret_key', '')),
                             'dnspod', host, action, VERSION, payload)
        h['User-Agent'] = 'acme-challenge'
        st, _rh, got = http_call(self.ctx, 'POST', 'https://%s/' % host, payload, h, who='DNSPod')
        try:
            ans = json.loads(got.decode('utf-8')).get('Response') or {}
        except (ValueError, UnicodeDecodeError, AttributeError):
            raise said_error('DNSPod', st, None, got)
        err = ans.get('Error')
        if err:
            if err.get('Code') in missing:
                return {}
            words = 'DNSPod said %s: %s' % (err.get('Code'), err.get('Message'))
            if str(err.get('Code', '')).startswith('AuthFailure'):
                words += ' - the SecretId/SecretKey are wrong, or this machine\'s clock is'
            raise PluginError(words, detail=ans, retry=str(err.get('Code', '')).startswith(
                ('RequestLimitExceeded', 'InternalError')))
        return ans

    def zone_names(self):
        out, off = [], 0
        while off < 5000:
            got = self._call('DescribeDomainList', {'Offset': off, 'Limit': 100},
                             missing=('ResourceNotFound.NoDataOfDomain',))
            names = [d.get('Name') for d in got.get('DomainList') or []]
            out += names
            if len(names) < 100:
                break
            off += 100
        return out

    def txt_records(self, zone, fqdn):
        sub = rel_name(fqdn, zone)
        got = self._call('DescribeRecordList', {'Domain': zone, 'Subdomain': sub,
                                                'RecordType': 'TXT', 'Limit': 100},
                         missing=('ResourceNotFound.NoDataOfRecord',))
        return [(r.get('RecordId'), r.get('Value')) for r in got.get('RecordList') or []
                if r.get('Name') == sub and str(r.get('Type')).upper() == 'TXT']

    def create_txt(self, zone, fqdn, value):
        return self._call('CreateRecord', {'Domain': zone, 'SubDomain': rel_name(fqdn, zone),
                                           'RecordType': 'TXT', 'RecordLine': '默认',
                                           'Value': value, 'TTL': self.ttl()}).get('RecordId')

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DeleteRecord', {'Domain': zone, 'RecordId': int(record_id)},
                   missing=('ResourceNotFound.NoDataOfRecord', 'InvalidParameter.RecordIdInvalid'))
