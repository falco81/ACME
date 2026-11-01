#!/usr/bin/env python3
"""The validation modules added with acme 1.1, each against a fake of its API.

    python3 test/test_dns_providers_more.py

No internet. As test_dns_providers.py: ctx.http answered by an in-memory
fake of each provider that keeps TXT records the way that provider does and
checks each request (address, method, signature or credentials, body); each
DNS module put through the same run (the longest zone found, two values at
one name, cleanup taking only its own away, a second cleanup quiet, test()
changing nothing, a 429 waited out). The signatures are checked against the
vendors' own worked examples where they publish them:

    Alibaba Cloud RPC v1   the DescribeRegions example of its signature page
    Tencent Cloud TC3      the hashed canonical request of its CVM example
    Oracle Cloud (OCI)     the test key and both signatures of its signing page
                           (as in Oracle's oci-go-sdk, common/http_signer_test.go)
    Akamai EdgeGrid        Akamai's test cases (AkamaiOPEN-edgegrid-python)

The HTTP-01 upload modules: FTP against a small FTP server written here on
socketserver (FTPS is not tried: it would need a TLS server - the same code
with ftplib.FTP_TLS); SFTP against the SSH fake of test_challenges.py; S3,
Azure Blob and WebDAV against fakes of their HTTP APIs.
"""
import base64
import datetime
import email.utils
import hashlib
import hmac
import json
import os
import socket
import socketserver
import sys
import threading
import unittest
import urllib.parse
import xml.etree.ElementTree as ET
import xmlrpc.client

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_challenges import FakeCtx, SshWorld, plugin  # noqa: E402
from test_dns_providers import NAME, SLEPT, ZONES, Base, Fake, form, module, q  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402


def j(body):
    return json.loads(body) if body else {}


# ---------------------------------------------------------------------------
# Central Europe
# ---------------------------------------------------------------------------
class SubregFake(Fake):
    """PHP-SOAP as Subreg answers it: maps of {key, value} items."""
    def enc(self, v):
        if isinstance(v, dict):
            return '<value>%s</value>' % ''.join(
                '<item><key>%s</key>%s</item>' % (k, self.enc(x)) for k, x in v.items())
        if isinstance(v, list):
            return '<value SOAP-ENC:arrayType="ns2:Map[%d]">%s</value>' % (len(v), ''.join(
                '<item>%s</item>' % self.enc(x)[7:-8] for x in v))
        return '<value>%s</value>' % v

    def answer(self, cmd, m):
        ret = self.enc(m)[7:-8]
        return ('<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.'
                'org/soap/envelope/" xmlns:ns1="http://soap.subreg.cz/soap" xmlns:SOAP-ENC='
                '"http://schemas.xmlsoap.org/soap/encoding/"><SOAP-ENV:Body><ns1:%sResponse>'
                '<return>%s</return></ns1:%sResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>'
                % (cmd, ret, cmd))

    def handle(self, method, url, body, h):
        self.t.assertEqual((method, url), ('POST', 'https://soap.subreg.cz/cmd.php'))
        x = ET.fromstring(body)
        call = [e for e in x.iter() if e.tag.startswith('{http://soap.subreg.cz/soap}')][0]
        cmd = call.tag.split('}')[1]
        self.t.assertEqual(h['SOAPAction'], 'http://soap.subreg.cz/soap#' + cmd)
        data = call.find('data')

        def t(path):
            return (data.findtext(path) or '').strip()
        if cmd == 'Login':
            if (t('login'), t('password')) != ('me', 'pw'):
                return 200, self.answer(cmd, {'status': 'error', 'error': {
                    'errormsg': 'Invalid login', 'errorcode': {'major': 500, 'minor': 101}}})
            return 200, self.answer(cmd, {'status': 'ok', 'data': {'ssid': 'S1'}})
        self.t.assertEqual(t('ssid'), 'S1')
        if cmd == 'Domains_List':
            return 200, self.answer(cmd, {'status': 'ok', 'data': {
                'domains': [{'name': z, 'expire': '2030-01-01'} for z in ZONES], 'count': 3}})
        zone = t('domain')
        if cmd == 'Get_DNS_Zone':
            if zone not in ZONES:
                return 200, self.answer(cmd, {'status': 'error', 'error': {
                    'errormsg': 'Domain not found', 'errorcode': {'major': 500, 'minor': 1}}})
            return 200, self.answer(cmd, {'status': 'ok', 'data': {'domain': zone, 'records': [
                {'id': r['id'], 'name': self.rel(zone, r['name']), 'type': 'TXT',
                 'content': r['value'], 'prio': 0, 'ttl': 120}
                for r in self.recs if r['zone'] == zone]}})
        if cmd == 'Add_DNS_Record':
            self.t.assertEqual(t('record/type'), 'TXT')
            rid = self.add(zone, self.full(zone, t('record/name')), t('record/content'))
            return 200, self.answer(cmd, {'status': 'ok', 'data': {'record_id': rid}})
        if cmd == 'Delete_DNS_Record':
            self.drop(lambda r: str(r['id']) == t('record/id'))
            return 200, self.answer(cmd, {'status': 'ok', 'data': {}})


class LoopiaFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(url, 'https://api.loopia.se/RPCSERV')
        args, meth = xmlrpc.client.loads(body)
        self.t.assertEqual(args[:2], ('lu@loopiaapi', 'lp'))
        args = args[2:]

        def ok(v):
            return 200, xmlrpc.client.dumps((v,), methodresponse=True)
        if meth == 'getDomains':
            return ok([{'domain': z, 'paid': 1} for z in ZONES])
        zone, sub = args[0], args[1]
        name = self.full(zone, sub if sub != '@' else '')
        if meth == 'getZoneRecords':
            return ok([{'type': 'TXT', 'ttl': 300, 'priority': 0, 'rdata': r['value'],
                        'record_id': r['id']} for r in self.recs if r['name'] == name])
        if meth in ('addSubdomain', 'removeSubdomain'):
            self.subs = getattr(self, 'subs', []) + [(meth, sub)]
            return ok('OK')
        if meth == 'addZoneRecord':
            self.t.assertGreaterEqual(args[2]['ttl'], 300)
            self.add(zone, name, args[2]['rdata'])
            return ok('OK')
        if meth == 'removeZoneRecord':
            self.drop(lambda r: r['id'] == args[2])
            return ok('OK')


class SimplyFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Basic ' + base64.b64encode(b'S1:k').decode())
        base = 'https://api.simply.com/2/my/products/'
        self.t.assertTrue(url.startswith(base), url)
        p = url[len(base):].strip('/').split('/')
        if p == ['']:
            return 200, {'products': [{'object': z.upper(), 'domain': {'name': z, 'name_idn': z}}
                                      for z in ZONES]}
        zone = p[0].lower()
        if method == 'GET':
            return 200, {'records': [{'record_id': r['id'], 'name': self.rel(zone, r['name']) or
                                      '@', 'type': 'TXT', 'data': r['value'], 'ttl': 120}
                                     for r in self.recs if r['zone'] == zone]}
        if method == 'POST':
            b = j(body)
            return 200, {'record': {'id': self.add(zone, self.full(zone, b['name']), b['data'])}}
        if method == 'DELETE':
            self.drop(lambda r: str(r['id']) == p[3])
            return 200, {'status': 200}


class HostingDeFake(Fake):
    def handle(self, method, url, body, h):
        b = j(body)
        self.t.assertEqual(b.pop('authToken'), 'hk')
        cmd = url.rsplit('/', 1)[1]
        ok = {'status': 'success', 'errors': [], 'response': {}}
        if cmd == 'zoneConfigsFind':
            v = b['filter']['value']
            ok['response'] = {'data': [{'id': 'Z' + z, 'name': z, 'status': 'active'}
                                       for z in ZONES if v in ('*', z)]}
        elif cmd == 'recordsFind':
            f = {x['field']: x['value'] for x in b['filter']['subFilter']}
            ok['response'] = {'data': [{'id': r['id'], 'name': r['name'], 'type': 'TXT',
                                        'content': '"%s"' % r['value']} for r in self.recs
                                       if 'Z' + r['zone'] == f['zoneConfigId'] and
                                       r['name'] == f['recordName']]}
        elif cmd == 'zoneUpdate':
            zone = b['zoneConfig']['name']
            for r in b['recordsToAdd'] or []:
                self.t.assertFalse(r['content'].startswith('"'))
                self.add(zone, r['name'], r['content'])
            for r in b['recordsToDelete'] or []:
                self.t.assertTrue(r['content'].startswith('"'))
                self.drop(lambda x: x['name'] == r['name'] and '"%s"' % x['value'] == r['content'])
        return 200, ok


class IdFake(Fake):
    """A REST API with zones by id: /prefix/{zone id}/... - written per provider."""
    def zid(self, zone):
        return ZONES.index(zone) + 1

    def zone(self, zid):
        return ZONES[int(zid) - 1]


class DomeneshopFake(IdFake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Basic ' + base64.b64encode(b'dt:ds').decode())
        u = urllib.parse.urlsplit(url)
        p = u.path[len('/v0/'):].split('/')
        if p == ['domains']:
            return 200, [{'id': self.zid(z), 'domain': z} for z in ZONES]
        zone = self.zone(p[1])
        if method == 'GET':
            host = q(url)['host']
            return 200, [{'id': r['id'], 'host': self.rel(zone, r['name']) or '@', 'type': 'TXT',
                          'data': r['value'], 'ttl': 60} for r in self.recs
                         if r['zone'] == zone and (self.rel(zone, r['name']) or '@') == host]
        if method == 'POST':
            b = j(body)
            return 201, {'id': self.add(zone, self.full(zone, b['host']), b['data'])}
        if method == 'DELETE':
            return (204, b'') if self.drop(lambda r: str(r['id']) == p[3]) else (404, {})


class GlesysFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Basic ' + base64.b64encode(b'CL1:gk').decode())
        b = j(body)
        cmd = url.split('/domain/')[1]
        resp = {'status': {'code': 200}}
        if cmd == 'list':
            resp['domains'] = [{'domainname': z} for z in ZONES]
        elif cmd == 'listrecords':
            z = b['domainname']
            resp['records'] = [{'recordid': r['id'], 'domainname': z, 'host': self.rel(z, r['name'])
                                or '@', 'type': 'TXT', 'data': r['value'], 'ttl': 60}
                               for r in self.recs if r['zone'] == z]
        elif cmd == 'addrecord':
            z = b['domainname']
            resp['record'] = {'recordid': self.add(z, self.full(z, b['host']), b['data'])}
        elif cmd == 'deleterecord':
            self.drop(lambda r: r['id'] == b['recordid'])
        return 200, {'response': resp}


class MythicFake(Fake):
    def handle(self, method, url, body, h):
        if url == 'https://auth.mythic-beasts.com/login':
            self.t.assertEqual(h['Authorization'], 'Basic ' + base64.b64encode(b'kid:ks').decode())
            self.t.assertEqual(form(body), {'grant_type': 'client_credentials'})
            return 200, {'access_token': 'AT', 'expires_in': 300, 'token_type': 'bearer'}
        self.t.assertEqual(h['Authorization'], 'Bearer AT')
        u = urllib.parse.urlsplit(url)
        p = [urllib.parse.unquote(x) for x in u.path[len('/dns/v2/'):].split('/')]
        if p == ['zones']:
            return 200, {'zones': ZONES}
        zone, host = p[1], p[3]
        name = self.full(zone, '' if host == '@' else host)
        if method == 'GET':
            return 200, {'records': [{'host': host, 'type': 'TXT', 'data': r['value'], 'ttl': 60}
                                     for r in self.recs if r['name'] == name]}
        if method == 'POST':
            for r in j(body)['records']:
                self.add(zone, name, r['data'])
            return 200, {'records_added': 1}
        if method == 'DELETE':
            return 200, {'records_removed': self.drop(
                lambda r: r['name'] == name and r['value'] == q(url)['data'])}


class InfomaniakFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Bearer it')
        u = urllib.parse.urlsplit(url)
        p = u.path[len('/2/zones/'):].split('/')
        zone = p[0]
        if p[1:] == ['exists']:
            return 200, {'result': 'success', 'data': zone in ZONES}
        if method == 'GET':
            return 200, {'result': 'success', 'data': [
                {'id': r['id'], 'source': self.rel(zone, r['name']) or '.', 'source_idn': r['name'],
                 'type': 'TXT', 'target': '"%s"' % r['value'], 'ttl': 300}
                for r in self.recs if r['zone'] == zone]}
        if method == 'POST':
            b = j(body)
            self.t.assertTrue(b['target'].startswith('"'))
            return 200, {'result': 'success', 'data': {'id': self.add(
                zone, self.full(zone, '' if b['source'] == '.' else b['source']),
                b['target'].strip('"'))}}
        if method == 'DELETE':
            self.drop(lambda r: str(r['id']) == p[2])
            return 200, {'result': 'success', 'data': True}


# ---------------------------------------------------------------------------
# Signed APIs
# ---------------------------------------------------------------------------
class AliFake(Fake):
    def handle(self, method, url, body, h):
        from acmelib.plugins.challenges.alidns import rpc_signature
        p = q(url)
        sig = p.pop('Signature')
        self.t.assertEqual(sig, rpc_signature(p, 'as'), 'signed as Alibaba Cloud checks it')
        self.t.assertEqual((p['AccessKeyId'], p['Version'], p['SignatureMethod']),
                           ('ak', '2015-01-09', 'HMAC-SHA1'))
        a = p['Action']
        if a == 'DescribeDomains':
            return 200, {'RequestId': 'r', 'TotalCount': 3, 'Domains': {'Domain': [
                {'DomainName': z} for z in ZONES]}}
        if a == 'DescribeDomainRecords':
            z = p['DomainName']
            return 200, {'RequestId': 'r', 'DomainRecords': {'Record': [
                {'RecordId': str(r['id']), 'RR': self.rel(z, r['name']) or '@', 'Type': 'TXT',
                 'Value': r['value']} for r in self.recs if r['zone'] == z and
                (self.rel(z, r['name']) or '@') == p['RRKeyWord']]}}
        if a == 'AddDomainRecord':
            self.t.assertGreaterEqual(int(p['TTL']), 600)
            z = p['DomainName']
            return 200, {'RequestId': 'r', 'RecordId': str(self.add(z, self.full(
                z, p['RR']), p['Value']))}
        if a == 'DeleteDomainRecord':
            if not self.drop(lambda r: str(r['id']) == p['RecordId']):
                return 400, {'Code': 'DomainRecordNotBelongToUser', 'Message': 'no'}
            return 200, {'RequestId': 'r', 'RecordId': p['RecordId']}


class TencentFake(Fake):
    def handle(self, method, url, body, h):
        from acmelib.plugins.challenges.tencentcloud import tc3_headers
        want, _ = tc3_headers('sid', 'skey', 'dnspod', 'dnspod.tencentcloudapi.com',
                              h['X-TC-Action'], '2021-03-23', body, int(h['X-TC-Timestamp']))
        self.t.assertEqual(h['Authorization'], want['Authorization'])
        b, a = j(body), h['X-TC-Action']

        def ok(d):
            d['RequestId'] = 'r'
            return 200, {'Response': d}
        if a == 'DescribeDomainList':
            return ok({'DomainList': [{'Name': z} for z in ZONES]})
        z = b['Domain']
        if a == 'DescribeRecordList':
            got = [{'RecordId': r['id'], 'Name': self.rel(z, r['name']) or '@', 'Type': 'TXT',
                    'Value': r['value']} for r in self.recs if r['zone'] == z and
                   (self.rel(z, r['name']) or '@') == b['Subdomain']]
            if not got:
                return ok({'Error': {'Code': 'ResourceNotFound.NoDataOfRecord', 'Message': '-'}})
            return ok({'RecordList': got})
        if a == 'CreateRecord':
            self.t.assertEqual(b['RecordLine'], '默认')
            return ok({'RecordId': self.add(z, self.full(z, b['SubDomain']), b['Value'])})
        if a == 'DeleteRecord':
            self.drop(lambda r: r['id'] == b['RecordId'])
            return ok({})


class OciFake(Fake):
    def handle(self, method, url, body, h):
        auth = h['authorization']
        self.t.assertIn('keyId="ocid1.tenancy.t/ocid1.user.u/aa:bb"', auth)
        self.t.assertIn('algorithm="rsa-sha256"', auth)
        if method == 'PATCH':
            self.t.assertIn('headers="date (request-target) host content-length content-type '
                            'x-content-sha256"', auth)
            self.t.assertEqual(h['x-content-sha256'],
                               base64.b64encode(hashlib.sha256(body).digest()).decode())
        u = urllib.parse.urlsplit(url)
        self.t.assertEqual(u.netloc, 'dns.eu-frankfurt-1.oci.oraclecloud.com')
        p = [urllib.parse.unquote(x) for x in u.path[len('/20180115/'):].split('/')]
        if p == ['zones']:
            self.t.assertEqual(q(url)['compartmentId'], 'ocid1.tenancy.t')
            return 200, [{'name': z, 'id': 'ocid1.dns-zone.' + z} for z in ZONES]
        zone, fqdn = p[1], p[3]
        if method == 'GET':
            return 200, {'items': [{'domain': r['name'], 'rtype': 'TXT',
                                    'rdata': '"%s"' % r['value'], 'ttl': 30}
                                   for r in self.recs if r['name'] == fqdn]}
        for it in j(body)['items']:
            if it['operation'] == 'ADD':
                self.add(zone, it['domain'], it['rdata'])
            else:
                self.drop(lambda r: r['name'] == it['domain'] and '"%s"' % r['value'] == it['rdata'])
        return 200, {'items': []}


class AkamaiFake(Fake):
    def handle(self, method, url, body, h):
        from acmelib.plugins.challenges.akamai_edgedns import edgegrid
        a = h['Authorization']
        parts = dict(x.split('=', 1) for x in a.split(' ', 1)[1].split(';'))
        want, _ = edgegrid(method, url, body, 'ct', 'cs', 'at', parts['timestamp'], parts['nonce'])
        self.t.assertEqual(a, want)
        u = urllib.parse.urlsplit(url)
        self.t.assertEqual(u.netloc, 'akab-x.luna.akamaiapis.net')
        p = [urllib.parse.unquote(x) for x in u.path[len('/config-dns/v2/'):].split('/')]
        if p == ['zones']:
            return 200, {'zones': [{'zone': z} for z in ZONES]}
        zone, fqdn = p[1], p[3]
        have = ['"%s"' % r['value'] for r in self.recs if r['name'] == fqdn]
        if method == 'GET':
            return (200, {'name': fqdn, 'type': 'TXT', 'ttl': 60, 'rdata': have}) if have else \
                (404, {'title': 'Not Found'})
        if method == 'POST' and have:
            return 409, {'title': 'exists'}
        if method == 'PUT' and not have:
            return 404, {'title': 'Not Found'}
        self.drop(lambda r: r['name'] == fqdn)
        if method in ('POST', 'PUT'):
            for v in j(body)['rdata']:
                self.add(zone, fqdn, v.strip('"'))
        return 200 if method != 'DELETE' else 204, b''


class DmeFake(IdFake):
    def handle(self, method, url, body, h):
        d = h['x-dnsme-requestDate']
        self.t.assertEqual(h['x-dnsme-hmac'],
                           hmac.new(b'dsec', d.encode(), hashlib.sha1).hexdigest())
        self.t.assertEqual(h['x-dnsme-apiKey'], 'dkey')
        u = urllib.parse.urlsplit(url)
        p = u.path[len('/V2.0/dns/managed/'):].strip('/').split('/')
        if p == ['']:
            return 200, {'data': [{'id': self.zid(z), 'name': z} for z in ZONES]}
        zone = self.zone(p[0])
        if method == 'GET':
            n = q(url).get('recordName', '')
            return 200, {'data': [{'id': r['id'], 'name': self.rel(zone, r['name']), 'type': 'TXT',
                                   'value': '"%s"' % r['value']} for r in self.recs
                                  if r['zone'] == zone and self.rel(zone, r['name']) == n]}
        if method == 'POST':
            b = j(body)
            return 201, {'id': self.add(zone, self.full(zone, b['name']), b['value'].strip('"'))}
        if method == 'DELETE':
            return (200, b'') if self.drop(lambda r: str(r['id']) == p[2]) else (404, {})


# ---------------------------------------------------------------------------
# REST APIs with tokens
# ---------------------------------------------------------------------------
class GcoreFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'APIKey gk')
        u = urllib.parse.urlsplit(url)
        p = [urllib.parse.unquote(x) for x in u.path[len('/dns/v2/'):].split('/')]
        if p == ['zones']:
            return 200, {'zones': [{'name': z} for z in ZONES], 'total_amount': 3}
        zone, fqdn = p[1], p[2]
        have = [r['value'] for r in self.recs if r['name'] == fqdn]
        if method == 'GET':
            return (200, {'name': fqdn, 'type': 'TXT', 'ttl': 120, 'resource_records': [
                {'content': [v], 'id': i} for i, v in enumerate(have)]}) if have else \
                (404, {'error': 'record is not found'})
        if method == 'POST' and have:
            return 400, {'error': 'rrset is already exists'}
        self.drop(lambda r: r['name'] == fqdn)
        if method in ('POST', 'PUT'):
            for rr in j(body)['resource_records']:
                for v in rr['content']:
                    self.add(zone, fqdn, v)
        return 200, {}


class NetlifyFake(IdFake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Bearer nt')
        p = urllib.parse.urlsplit(url).path[len('/api/v1/'):].split('/')
        if p == ['dns_zones']:
            return 200, [{'id': 'z%d' % self.zid(z), 'name': z} for z in ZONES]
        zone = self.zone(p[1][1:])
        if method == 'GET':
            return 200, [{'id': str(r['id']), 'hostname': r['name'], 'type': 'TXT',
                          'value': r['value']} for r in self.recs if r['zone'] == zone]
        if method == 'POST':
            b = j(body)
            return 201, {'id': str(self.add(zone, b['hostname'], b['value']))}
        if method == 'DELETE':
            return (204, b'') if self.drop(lambda r: str(r['id']) == p[3]) else (404, {})


class VercelFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Bearer vt')
        self.t.assertEqual(q(url).get('teamId'), 'team_1')
        p = urllib.parse.urlsplit(url).path.split('/')[1:]
        if p == ['v5', 'domains']:
            return 200, {'domains': [{'name': z} for z in ZONES]}
        zone = p[2]
        if method == 'GET':
            self.t.assertEqual(p[0], 'v4')
            return 200, {'records': [{'id': 'rec_%d' % r['id'], 'name': self.rel(zone, r['name']),
                                      'type': 'TXT', 'value': r['value']}
                                     for r in self.recs if r['zone'] == zone]}
        if method == 'POST':
            b = j(body)
            return 200, {'uid': 'rec_%d' % self.add(zone, self.full(zone, b['name']), b['value'])}
        if method == 'DELETE':
            return (200, {}) if self.drop(lambda r: 'rec_%d' % r['id'] == p[4]) else (404, {})


class NameComFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Basic ' + base64.b64encode(b'nu:nt').decode())
        p = urllib.parse.urlsplit(url).path[len('/v4/'):].split('/')
        if p == ['domains']:
            return 200, {'domains': [{'domainName': z} for z in ZONES]}
        zone = p[1]
        if method == 'GET':
            return 200, {'records': [{'id': r['id'], 'domainName': zone, 'host': self.rel(
                zone, r['name']), 'fqdn': r['name'] + '.', 'type': 'TXT', 'answer': r['value'],
                'ttl': 300} for r in self.recs if r['zone'] == zone]}
        if method == 'POST':
            b = j(body)
            self.t.assertGreaterEqual(b['ttl'], 300)
            return 200, {'id': self.add(zone, self.full(zone, b['host']), b['answer'])}
        if method == 'DELETE':
            return (200, {}) if self.drop(lambda r: str(r['id']) == p[3]) else (404, {})


class NameSiloFake(Fake):
    def handle(self, method, url, body, h):
        p = q(url)
        self.t.assertEqual((p['key'], p['type'], p['version']), ('nk', 'json', '1'))
        op = urllib.parse.urlsplit(url).path.rsplit('/', 1)[1]

        def ok(**more):
            r = {'code': 300, 'detail': 'success'}
            r.update(more)
            return 200, {'request': {'operation': op}, 'reply': r}
        if op == 'listDomains':
            return ok(domains={'domain': ZONES})
        z = p['domain']
        if op == 'dnsListRecords':
            return ok(resource_record=[{'record_id': 'x%d' % r['id'], 'type': 'TXT',
                                        'host': r['name'], 'value': r['value'], 'ttl': 3600}
                                       for r in self.recs if r['zone'] == z])
        if op == 'dnsAddRecord':
            self.t.assertGreaterEqual(int(p['rrttl']), 3600)
            return ok(record_id='x%d' % self.add(z, self.full(z, p['rrhost']), p['rrvalue']))
        if op == 'dnsDeleteRecord':
            self.drop(lambda r: 'x%d' % r['id'] == p['rrid'])
            return ok()


class DynuFake(IdFake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['API-Key'], 'dk')
        p = urllib.parse.urlsplit(url).path[len('/v2/'):].split('/')
        if p == ['dns']:
            return 200, {'statusCode': 200, 'domains': [{'id': self.zid(z), 'name': z}
                                                        for z in ZONES]}
        zone = self.zone(p[1])
        if method == 'GET':
            return 200, {'dnsRecords': [{'id': r['id'], 'nodeName': self.rel(zone, r['name']),
                                         'hostname': r['name'], 'recordType': 'TXT',
                                         'textData': r['value']} for r in self.recs
                                        if r['zone'] == zone]}
        if method == 'POST':
            b = j(body)
            return 200, {'id': self.add(zone, self.full(zone, b['nodeName']), b['textData'])}
        if method == 'DELETE':
            return (200, {}) if self.drop(lambda r: str(r['id']) == p[3]) else (404, {})


class NjallaFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Njalla nj')
        b = j(body)
        m, p = b['method'], b['params']
        if m == 'list-domains':
            return 200, {'result': {'domains': [{'name': z} for z in ZONES]}}
        z = p['domain']
        if m == 'list-records':
            return 200, {'result': {'records': [{'id': r['id'], 'name': self.rel(z, r['name']) or
                                                 '@', 'type': 'TXT', 'content': r['value']}
                                                for r in self.recs if r['zone'] == z]}}
        if m == 'add-record':
            return 200, {'result': {'id': self.add(z, self.full(z, p['name']), p['content'])}}
        if m == 'remove-record':
            if not self.drop(lambda r: r['id'] == p['id']):
                return 200, {'error': {'code': 404, 'message': 'no such record'}}
            return 200, {'result': {}}


class DreamhostFake(Fake):
    def handle(self, method, url, body, h):
        p = q(url)
        self.t.assertEqual((p['key'], p['format']), ('dh', 'json'))
        cmd = p['cmd']
        if cmd == 'dns-list_records':
            return 200, {'result': 'success', 'data': [
                {'record': r['name'], 'zone': r['zone'], 'type': 'TXT', 'value': r['value'],
                 'editable': '1'} for r in self.recs] + [
                {'record': z, 'zone': z, 'type': 'A', 'value': '192.0.2.1', 'editable': '1'}
                for z in ZONES]}
        name, value = p['record'], p['value']
        zone = max((z for z in ZONES if name.endswith(z)), key=len)
        if cmd == 'dns-add_record':
            if any(r['name'] == name and r['value'] == value for r in self.recs):
                return 200, {'result': 'error', 'data': 'record_already_exists_not_editable'}
            self.add(zone, name, value)
            return 200, {'result': 'success', 'data': 'record_added'}
        if cmd == 'dns-remove_record':
            if not self.drop(lambda r: r['name'] == name and r['value'] == value):
                return 200, {'result': 'error', 'data': 'no_such_record'}
            return 200, {'result': 'success', 'data': 'record_removed'}


class TestMoreProviders(Base):
    def test_subreg(self):
        self.run_module('subreg', SubregFake(self), login='me', password='pw')

    def test_subreg_says_why_login_failed(self):
        f = SubregFake(self)
        f.throttled = True
        m, _ = module('subreg', f, login='me', password='wrong')
        with self.assertRaises(PluginError) as e:
            m.test()
        self.assertIn('Invalid login', str(e.exception))
        self.assertIn('500.101', str(e.exception))

    def test_loopia(self):
        f = LoopiaFake(self)
        self.run_module('loopia', f, user='lu@loopiaapi', password='lp')
        self.assertIn(('addSubdomain', '_acme-challenge.www'), f.subs)
        self.assertNotIn(('removeSubdomain', '_acme-challenge.www'), f.subs,
                         'another value is still there: the subdomain stays')

    def test_simply(self):
        self.run_module('simply', SimplyFake(self), account='S1', key='k')

    def test_hostingde(self):
        self.run_module('hostingde', HostingDeFake(self), token='hk')

    def test_domeneshop(self):
        self.run_module('domeneshop', DomeneshopFake(self), token='dt', secret='ds')

    def test_glesys(self):
        self.run_module('glesys', GlesysFake(self), project='CL1', key='gk')

    def test_mythic_beasts(self):
        self.run_module('mythic_beasts', MythicFake(self), key_id='kid', secret='ks')

    def test_infomaniak(self):
        f = InfomaniakFake(self)
        self.run_module('infomaniak', f, token='it', zone='')
        m, _ = module('infomaniak', f, token='it', zone='example.com')
        self.assertIn('example.com', m.test())

    def test_alidns(self):
        self.run_module('alidns', AliFake(self), key_id='ak', secret='as')

    def test_tencentcloud(self):
        self.run_module('tencentcloud', TencentFake(self), secret_id='sid', secret_key='skey')

    def test_oci_dns(self):
        self.run_module('oci_dns', OciFake(self), tenancy='ocid1.tenancy.t', user='ocid1.user.u',
                        fingerprint='aa:bb', key=OCI_KEY, region='eu-frankfurt-1')

    def test_akamai_edgedns(self):
        self.run_module('akamai_edgedns', AkamaiFake(self), host='akab-x.luna.akamaiapis.net',
                        client_token='ct', client_secret='cs', access_token='at')

    def test_dnsmadeeasy(self):
        self.run_module('dnsmadeeasy', DmeFake(self), key='dkey', secret='dsec')

    def test_gcore(self):
        self.run_module('gcore', GcoreFake(self), token='gk')

    def test_netlify(self):
        self.run_module('netlify', NetlifyFake(self), token='nt')

    def test_vercel(self):
        self.run_module('vercel', VercelFake(self), token='vt', team='team_1')

    def test_namecom(self):
        self.run_module('namecom', NameComFake(self), user='nu', token='nt')

    def test_namesilo(self):
        self.run_module('namesilo', NameSiloFake(self), key='nk')

    def test_dynu(self):
        self.run_module('dynu', DynuFake(self), key='dk')

    def test_njalla(self):
        self.run_module('njalla', NjallaFake(self), token='nj')

    def test_dreamhost(self):
        self.run_module('dreamhost', DreamhostFake(self), key='dh')


# ---------------------------------------------------------------------------
# Modules that cannot go through the common run
# ---------------------------------------------------------------------------
class CzechiaFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['AuthorizationToken'], 'cz')
        zone = urllib.parse.urlsplit(url).path.split('/')[3]
        self.t.assertTrue(url.endswith('/TXT'))
        b = j(body)
        self.t.assertEqual(b['publishZone'], 1)
        name = self.full(zone, '' if b['hostName'] == '@' else b['hostName'])
        if method == 'POST':
            if any(r['name'] == name and r['value'] == b['text'] for r in self.recs):
                return 400, {'status': 400, 'title': 'Record already exists'}
            self.add(zone, name, b['text'])
            return 200, {}
        if not self.drop(lambda r: r['name'] == name and r['value'] == b['text']):
            return 404, {'status': 404, 'title': 'Record not found'}
        return 200, {}


class DuckFake(Fake):
    def handle(self, method, url, body, h):
        p = q(url)
        self.t.assertEqual((p['token'], p['verbose']), ('dt', 'true'))
        if p['domains'] != 'myhome':
            return 200, 'KO'
        name = 'myhome.duckdns.org'
        self.drop(lambda r: r['name'] == name)
        if p.get('clear') != 'true':
            self.add('duckdns.org', name, p['txt'])
        return 200, 'OK\n\n%s\nUPDATED' % p.get('txt', '')


class TestOwnWays(unittest.TestCase):
    def test_czechia_by_value(self):
        f = CzechiaFake(self)
        m, ctx = module('czechia', f, token='cz', zone='example.com')
        f.add('example.com', NAME, 'someone-elses')
        h1 = m.present('www.example.com', 't', 'k', 'one')
        m.present('*.www.example.com', 't', 'k', 'two')
        m.present('www.example.com', 't', 'k', 'one')               # "already exists": fine
        self.assertEqual(f.values(), ['one', 'someone-elses', 'two'])
        m.cleanup('www.example.com', h1)
        m.cleanup('www.example.com', h1)                            # gone: quiet
        self.assertEqual(f.values(), ['someone-elses', 'two'])
        n = len(f.calls)
        self.assertIn('dry run', m.test())
        self.assertEqual(len(f.calls), n, 'test() asks nothing that could change a record')

    def test_duckdns_one_value_at_a_time(self):
        f = DuckFake(self)
        f.throttled = True
        m, ctx = module('duckdns', f, token='dt', domains='myhome')
        self.assertFalse(plugin('duckdns').parallel)
        h = m.present('myhome.duckdns.org', 't', 'k', 'one')
        self.assertEqual(f.values('myhome.duckdns.org'), ['one'])
        with self.assertRaises(PluginError) as e:                   # a second value: later
            m.present('*.myhome.duckdns.org', 't', 'k', 'two')
        self.assertIn('one value a name', str(e.exception))
        self.assertTrue(e.exception.retry)
        m.cleanup('myhome.duckdns.org', h)
        self.assertEqual(f.values('myhome.duckdns.org'), [])
        m.present('*.myhome.duckdns.org', 't', 'k', 'two')          # now it may
        self.assertEqual(f.values('myhome.duckdns.org'), ['two'])
        with self.assertRaises(PluginError) as e:
            module('duckdns', f, token='dt', domains='other')[0].present(
                'other.duckdns.org', 't', 'k', 'x')
        self.assertIn('KO', str(e.exception))

    def test_hostingde_without_records_find(self):
        f = HostingDeFake(self)
        f.throttled = True
        real = f.handle

        def no_find(method, url, body, h):
            if url.endswith('/recordsFind'):
                return 200, {'status': 'error', 'errors': [{'code': 10101, 'text': 'denied'}]}
            return real(method, url, body, h)
        f.handle = no_find
        m, _ = module('hostingde', f, token='hk')
        h = m.present('www.example.com', 't', 'k', 'one')
        self.assertEqual(f.values(), ['one'])
        m.cleanup('www.example.com', h)
        self.assertEqual(f.values(), [])


# ---------------------------------------------------------------------------
# The signatures against the vendors' own examples
# ---------------------------------------------------------------------------
OCI_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----
"""


class TestSignatures(unittest.TestCase):
    def test_alibaba_rpc_v1_example(self):
        # Alibaba Cloud's signature page: DescribeRegions, AccessKey testid / testsecret
        from acmelib.plugins.challenges.alidns import rpc_signature, signed_query
        p = {'AccessKeyId': 'testid', 'Action': 'DescribeRegions', 'Format': 'XML',
             'SignatureMethod': 'HMAC-SHA1', 'SignatureNonce': '3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf',
             'SignatureVersion': '1.0', 'Timestamp': '2016-02-23T12:46:24Z',
             'Version': '2014-05-26'}
        self.assertEqual(rpc_signature(p, 'testsecret'), 'OLeaidS1JvxuMvnyHOwuJ+uX5qY=')
        got = signed_query('DescribeRegions', {'Format': 'XML'}, 'testid', 'testsecret',
                           timestamp='2016-02-23T12:46:24Z',
                           nonce='3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf', version='2014-05-26')
        self.assertIn('Signature=OLeaidS1JvxuMvnyHOwuJ%2BuX5qY%3D', got)
        self.assertIn('Timestamp=2016-02-23T12%3A46%3A24Z', got)

    def test_tencent_tc3_example(self):
        # Tencent Cloud's Signature v3 page: CVM DescribeInstances at 1551113065
        from acmelib.plugins.challenges.tencentcloud import tc3_headers
        payload = ('{"Limit": 1, "Filters": [{"Values": ["\\u672a\\u547d\\u540d"], '
                   '"Name": "instance-name"}]}').encode()
        h, creq = tc3_headers('AKIDEXAMPLE', 'SECRETEXAMPLE', 'cvm', 'cvm.tencentcloudapi.com',
                              'DescribeInstances', '2017-03-12', payload, 1551113065)
        self.assertEqual(hashlib.sha256(creq.encode()).hexdigest(),
                         '5ffe6a04c0664d6b969fab9a13bdab201d63ee709638e2749d62a09ca18d7031')
        self.assertTrue(h['Authorization'].startswith(
            'TC3-HMAC-SHA256 Credential=AKIDEXAMPLE/2019-02-25/cvm/tc3_request, '
            'SignedHeaders=content-type;host, Signature='))
        # the key chain, by hand
        k = hmac.new(b'TC3SECRETEXAMPLE', b'2019-02-25', hashlib.sha256).digest()
        k = hmac.new(hmac.new(k, b'cvm', hashlib.sha256).digest(), b'tc3_request',
                     hashlib.sha256).digest()
        sts = 'TC3-HMAC-SHA256\n1551113065\n2019-02-25/cvm/tc3_request\n' + \
            '5ffe6a04c0664d6b969fab9a13bdab201d63ee709638e2749d62a09ca18d7031'
        self.assertTrue(h['Authorization'].endswith(
            hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()))

    def test_oci_published_signatures(self):
        from acmelib.plugins.challenges.oci_dns import sign_headers, signing_string
        from acmelib.plugins.challenges._common import openssl_sign
        ctx = FakeCtx()
        url = ('https://iaas.us-phoenix-1.oraclecloud.com/20160918/instances'
               '?availabilityDomain=Pjwf%3A%20PHX-AD-1&compartmentId=ocid1.compartment.oc1..'
               'aaaaaaaam3we6vgnherjq5q2idnccdflvjsnog7mlr6rtdb25gilchfeyjxa&displayName='
               'TeamXInstances&volumeId=ocid1.volume.oc1.phx.abyhqljrgvttnlx73nmrwfaux7kcvzfs3s'
               '66izvxf2h4lgvyndsdsnoiwr5q')
        date = 'Thu, 05 Jan 2014 21:31:40 GMT'
        s, _ = signing_string('GET', url, {'date': date})
        self.assertEqual(base64.b64encode(openssl_sign(ctx, OCI_KEY, s.encode())).decode(),
                         'GBas7grhyrhSKHP6AVIj/h5/Vp8bd/peM79H9Wv8kjoaCivujVXlpbKLjMPeDUhxkFIW'
                         'tTtLBj3sUzaFj34XE6YZAHc9r2DmE4pMwOAy/kiITcZxa1oHPOeRheC0jP2dqbTll8fmT'
                         'ZVwKZOKHYPtrLJIJQHJjNvxFWeHQjMaR7M=')
        body = ('{\n    "compartmentId": "ocid1.compartment.oc1..aaaaaaaam3we6vgnherjq5q2idnccdfl'
                'vjsnog7mlr6rtdb25gilchfeyjxa",\n    "instanceId": "ocid1.instance.oc1.phx.abuw4lj'
                'rlsfiqw6vzzxb43vyypt4pkodawglp3wqxjqofakrwvou52gb6s5a",\n    "volumeId": "ocid1.'
                'volume.oc1.phx.abyhqljrgvttnlx73nmrwfaux7kcvzfs3s66izvxf2h4lgvyndsdsnoiwr5q"\n}'
                ).encode()
        h = sign_headers(ctx, 'POST', 'https://iaas.us-phoenix-1.oraclecloud.com/20160918/'
                         'volumeAttachments', body,
                         'ocid1.tenancy.oc1..aaaaaaaaba3pv6wkcr4jqae5f15p2b2m2yt2j6rx32uzr4h25vqs'
                         'tifsfdsq/ocid1.user.oc1..aaaaaaaat5nvwcna5j6aqzjcaty5eqbb6qt2jvpkanghtg'
                         'daqedqw3rynjq/20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34',
                         OCI_KEY, date=date)
        self.assertEqual(h['content-length'], '316')
        self.assertEqual(h['x-content-sha256'], 'V9Z20UJTvkvpJ50flBzKE32+6m2zJjweHpDMX/U4Uy0=')
        self.assertIn('signature="Mje8vIDPlwIHmD/cTDwRxE7HaAvBg16JnVcsuqaNRim23fFPgQfLoOOxae6Wq'
                      'Kb1uPjYEl0qIdazWaBy/Ml8DRhqlocMwoSXv0fbukP8J5N80LCmzT/FFBvIvTB91XuXI3hYf'
                      'P9Zt1l7S6ieVadHUfqBedWH0itrtPJBgKmrWso="', h['authorization'])
        self.assertIn('headers="date (request-target) host content-length content-type '
                      'x-content-sha256"', h['authorization'])

    def test_akamai_edgegrid_cases(self):
        from acmelib.plugins.challenges.akamai_edgedns import edgegrid
        base = 'https://akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net'
        cases = [('GET', '/', None, 'tL+y4hxyHxgWVD30X3pWnGKHcPzmrIF+LThiAOhMxYU='),
                 ('GET', '/testapi/v1/t1?p1=1&p2=2', None,
                  'hKDH1UlnQySSHjvIcZpDMbQHihTQ0XyVAKZaApabdeA='),
                 ('POST', '/testapi/v1/t3', b'datadatadatadatadatadatadatadata',
                  'hXm4iCxtpN22m4cbZb4lVLW5rhX8Ca82vCFqXzSTPe4='),
                 ('POST', '/testapi/v1/t6', b'', '1gEDxeQGD5GovIkJJGcBaKnZ+VaPtrc4qBUHixjsPCQ=')]
        for method, path, body, sig in cases:
            got, _ = edgegrid(method, base + path, body, 'akab-client-token-xxx-xxxxxxxxxxxxxxxx',
                              'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=',
                              'akab-access-token-xxx-xxxxxxxxxxxxxxxx', '20140321T19:34:21+0000',
                              'nonce-xx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', max_body=2048)
            self.assertEqual(got, 'EG1-HMAC-SHA256 client_token=akab-client-token-xxx-xxxxxxxxxx'
                                  'xxxxxx;access_token=akab-access-token-xxx-xxxxxxxxxxxxxxxx;'
                                  'timestamp=20140321T19:34:21+0000;nonce=nonce-xx-xxxx-xxxx-'
                                  'xxxx-xxxxxxxxxxxx;signature=' + sig, path)

    def test_dnsmadeeasy_hmac(self):
        from acmelib.plugins.challenges.dnsmadeeasy import dme_headers
        h = dme_headers('k', 'secret', 'Sat, 12 Feb 2011 20:59:04 GMT')
        self.assertEqual(h['x-dnsme-hmac'], hmac.new(
            b'secret', b'Sat, 12 Feb 2011 20:59:04 GMT', hashlib.sha1).hexdigest())

    def test_azure_shared_key_string(self):
        from acmelib.plugins.challenges.http_azure_blob import shared_key, string_to_sign
        h = {'x-ms-date': 'Fri, 26 Jun 2015 23:39:12 GMT', 'x-ms-version': '2015-02-21',
             'x-ms-blob-type': 'BlockBlob', 'Content-Length': '0', 'Content-Type': 'text/plain'}
        sts = string_to_sign('PUT', 'https://myaccount.blob.core.windows.net/mycontainer/'
                             'a/b.txt?comp=metadata&Timeout=20', h, 'myaccount')
        self.assertEqual(sts, 'PUT\n\n\n\n\ntext/plain\n\n\n\n\n\n\n'
                              'x-ms-blob-type:BlockBlob\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\n'
                              'x-ms-version:2015-02-21\n'
                              '/myaccount/mycontainer/a/b.txt\ncomp:metadata\ntimeout:20')
        key = base64.b64encode(b'k' * 64).decode()
        self.assertEqual(shared_key('PUT', 'https://myaccount.blob.core.windows.net/mycontainer/'
                                    'a/b.txt?comp=metadata&Timeout=20', h, 'myaccount', key),
                         'SharedKey myaccount:' + base64.b64encode(hmac.new(
                             b'k' * 64, sts.encode(), hashlib.sha256).digest()).decode())

    def test_s3_sigv4_aws_example(self):
        # AWS's documented GET Object example (sig-v4-header-based-auth.html)
        from acmelib.plugins.challenges.route53 import sigv4
        h = sigv4('GET', 'https://examplebucket.s3.amazonaws.com/test.txt',
                  {'Range': 'bytes=0-9', 'x-amz-content-sha256': hashlib.sha256(b'').hexdigest()},
                  b'', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                  'us-east-1', 's3', amz_date='20130524T000000Z')
        self.assertEqual(h['Authorization'],
                         'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/'
                         'aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, '
                         'Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41')


# ---------------------------------------------------------------------------
# HTTP-01 uploads
# ---------------------------------------------------------------------------
class FtpHandler(socketserver.StreamRequestHandler):
    """Just enough FTP (RFC 959) for ftplib: USER PASS TYPE PASV STOR RETR
    DELE MKD CWD QUIT - the files in server.files."""
    def say(self, line):
        self.wfile.write((line + '\r\n').encode())

    def handle(self):
        srv = self.server
        self.say('220 fake ftp')
        user, authed, cwd = None, False, '/'
        data_sock = None
        while True:
            line = self.rfile.readline().decode().rstrip('\r\n')
            if not line:
                return
            cmd, _, arg = line.partition(' ')
            cmd = cmd.upper()
            srv.log.append((cmd, arg))
            if cmd == 'USER':
                user = arg
                self.say('331 password')
            elif cmd == 'PASS':
                authed = (user, arg) == ('fu', 'fp')
                self.say('230 in' if authed else '530 Login incorrect.')
            elif not authed:
                self.say('530 not logged in')
            elif cmd == 'TYPE':
                self.say('200 ok')
            elif cmd == 'PASV':
                data_sock = socket.socket()
                data_sock.bind(('127.0.0.1', 0))
                data_sock.listen(1)
                port = data_sock.getsockname()[1]
                self.say('227 Entering Passive Mode (127,0,0,1,%d,%d)' % (port // 256, port % 256))
            elif cmd in ('STOR', 'RETR'):
                path = arg if arg.startswith('/') else cwd.rstrip('/') + '/' + arg
                if cmd == 'STOR' and os.path.dirname(path) not in srv.dirs:
                    self.say('553 no such folder')
                    continue
                if cmd == 'RETR' and path not in srv.files:
                    self.say('550 no such file')
                    continue
                self.say('150 here')
                c, _a = data_sock.accept()
                if cmd == 'STOR':
                    buf = b''
                    while True:
                        b = c.recv(4096)
                        if not b:
                            break
                        buf += b
                    srv.files[path] = buf
                else:
                    c.sendall(srv.files[path])
                c.close()
                data_sock.close()
                self.say('226 done')
            elif cmd == 'DELE':
                if srv.files.pop(arg, None) is None:
                    self.say('550 no such file')
                else:
                    self.say('250 deleted')
            elif cmd == 'MKD':
                if arg in srv.dirs:
                    self.say('550 exists')
                else:
                    srv.dirs.add(arg)
                    self.say('257 "%s" made' % arg)
            elif cmd == 'CWD':
                if arg in srv.dirs:
                    cwd = arg
                    self.say('250 ok')
                else:
                    self.say('550 no such folder')
            elif cmd == 'QUIT':
                self.say('221 bye')
                return
            else:
                self.say('502 not here')


class FtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        socketserver.ThreadingTCPServer.__init__(self, ('127.0.0.1', 0), FtpHandler)
        self.files, self.dirs, self.log = {}, {'/', '/www'}, []


class WebFake(object):
    """A web site serving what was uploaded (for ready()), and the upload API."""
    def __init__(self, t):
        self.t, self.files, self.calls = t, {}, []

    def site(self, url):
        u = urllib.parse.urlsplit(url)
        if u.scheme == 'http' and u.netloc == 'www.example.com':
            key = u.path.lstrip('/')
            return (200, self.files[key]) if key in self.files else (404, b'not found')
        return None


class S3Fake(WebFake):
    def __call__(self, method, url, body, h):
        self.calls.append((method, url))
        got = self.site(url)
        if got:
            return got[0], {}, got[1]
        from acmelib.plugins.challenges.route53 import sigv4
        want = sigv4(method, url, {k: v for k, v in h.items()
                                   if k.lower() not in ('authorization', 'user-agent')},
                     body or b'', 'AK', 'SK', 'eu-central-1', 's3')
        self.t.assertEqual(h['Authorization'], want['Authorization'])
        self.t.assertEqual(h['x-amz-content-sha256'], hashlib.sha256(body or b'').hexdigest())
        u = urllib.parse.urlsplit(url)
        self.t.assertEqual(u.netloc, 'site-bucket.s3.eu-central-1.amazonaws.com')
        key = u.path.lstrip('/')
        if method == 'HEAD':
            return 200, {}, b''
        if method == 'PUT':
            self.files[key] = body
            return 200, {}, b''
        if method == 'GET':
            return (200, {}, self.files[key]) if key in self.files else (404, {}, b'<Error/>')
        if method == 'DELETE':
            self.files.pop(key, None)
            return 204, {}, b''


class AzureFake(WebFake):
    def __call__(self, method, url, body, h):
        self.calls.append((method, url))
        got = self.site(url)
        if got:
            return got[0], {}, got[1]
        from acmelib.plugins.challenges.http_azure_blob import shared_key
        self.t.assertEqual(h['Authorization'], shared_key(
            method, url, {k: v for k, v in h.items() if k not in ('Authorization', 'User-Agent')},
            'mysite', base64.b64encode(b'azkey').decode()))
        u = urllib.parse.urlsplit(url)
        self.t.assertEqual(u.netloc, 'mysite.blob.core.windows.net')
        self.t.assertTrue(u.path.startswith('/$web'))
        key = u.path[len('/$web/'):]
        if method == 'GET' and q(url).get('restype') == 'container':
            return 200, {}, b''
        if method == 'PUT':
            self.t.assertEqual(h['x-ms-blob-type'], 'BlockBlob')
            self.files[key] = body
            return 201, {}, b''
        if method == 'GET':
            return (200, {}, self.files[key]) if key in self.files else (404, {}, b'')
        if method == 'DELETE':
            return (202, {}, b'') if self.files.pop(key, None) is not None else (404, {}, b'')


class DavFake(WebFake):
    def __init__(self, t):
        WebFake.__init__(self, t)
        self.dirs = set()

    def __call__(self, method, url, body, h):
        self.calls.append((method, url))
        got = self.site(url)
        if got:
            return got[0], {}, got[1]
        self.t.assertEqual(h['Authorization'], 'Basic ' + base64.b64encode(b'du:dp').decode())
        base = 'https://dav.example.com/www/'
        self.t.assertTrue(url.startswith(base), url)
        key = url[len(base):]
        if method == 'PROPFIND':
            return 207, {}, b'<multistatus/>'
        if method == 'MKCOL':
            if key in self.dirs:
                return 405, {}, b''
            self.dirs.add(key)
            return 201, {}, b''
        if method == 'PUT':
            self.t.assertIn('.well-known/acme-challenge/', self.dirs)
            self.files[key] = body
            return 201, {}, b''
        if method == 'GET':
            return (200, {}, self.files[key]) if key in self.files else (404, {}, b'')
        if method == 'DELETE':
            return (204, {}, b'') if self.files.pop(key, None) is not None else (404, {}, b'')


class TestUploads(unittest.TestCase):
    def run_upload(self, kind, fake, **cfg):
        ctx = FakeCtx(http=fake)
        m = plugin(kind)(cfg, ctx)
        self.assertEqual(plugin(kind).types, ('http-01',))
        h = m.present('www.example.com', 'tok-1', 'tok-1.ka', '')
        self.assertTrue(m.ready('www.example.com', h), ctx.steps)
        self.assertIn(h['key'], fake.files)
        m.cleanup('www.example.com', h)
        self.assertNotIn(h['key'], fake.files)
        m.cleanup('www.example.com', h)                             # gone already: quiet
        self.assertIn('probe', m.test())
        self.assertEqual(fake.files, {}, 'the probe of test() is taken away')
        with self.assertRaises(PluginError):
            m.present('*.example.com', 't', 'k', '')
        g = m.guide('*.example.com')
        self.assertFalse(g['ok'])
        return m, h

    def test_s3(self):
        f = S3Fake(self)
        m, h = self.run_upload('http_s3', f, bucket='site-bucket', region='eu-central-1',
                               access_key_id='AK', secret_access_key='SK')
        self.assertEqual(h['key'], '.well-known/acme-challenge/tok-1')
        self.assertIn('the key sees the bucket', m.access())

    def test_s3_folder_and_path_style(self):
        m = plugin('http_s3')({'bucket': 'b', 'region': 'us-east-1', 'folder': '/site/',
                               'endpoint': 'https://minio.example.net', 'path_style': True},
                              FakeCtx())
        self.assertEqual(m._url(m.key_of('t')),
                         'https://minio.example.net/b/site/.well-known/acme-challenge/t')
        self.assertEqual(plugin('http_s3')({'bucket': 'b', 'folder': '../x'}, FakeCtx()).key_of(
            't'), 'x/.well-known/acme-challenge/t', 'never above the bucket\'s root')

    def test_azure_blob(self):
        self.run_upload('http_azure_blob', AzureFake(self), account='mysite', auth='key',
                        key=base64.b64encode(b'azkey').decode())

    def test_azure_blob_sas(self):
        m = plugin('http_azure_blob')({'account': 'mysite', 'sas': '?sv=2022&sig=abc'},
                                      FakeCtx())
        self.assertEqual(m._url('k'), 'https://mysite.blob.core.windows.net/$web/k?sv=2022&sig=abc')

    def test_webdav(self):
        f = DavFake(self)
        self.run_upload('http_webdav', f, url='https://dav.example.com/www', user='du',
                        password='dp')
        self.assertTrue(any(c[0] == 'MKCOL' for c in f.calls))

    def test_ftp_against_a_small_server(self):
        srv = FtpServer()
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]
            web = WebFake(self)

            def http(method, url, body, h):
                u = urllib.parse.urlsplit(url)
                path = '/www' + u.path
                if path in srv.files:
                    return 200, {}, srv.files[path]
                return 404, {}, b''
            ctx = FakeCtx(http=http)
            m = plugin('http_ftp')({'protocol': 'ftp', 'host': '127.0.0.1:%d' % port,
                                    'ftp_user': 'fu', 'ftp_password': 'fp', 'folder': '/www'},
                                   ctx)
            h = m.present('www.example.com', 'tok-2', 'tok-2.ka', '')
            self.assertEqual(srv.files['/www/.well-known/acme-challenge/tok-2'], b'tok-2.ka')
            self.assertIn('/www/.well-known/acme-challenge', srv.dirs)
            self.assertTrue(m.ready('www.example.com', h))
            m.cleanup('www.example.com', h)
            self.assertEqual(srv.files, {})
            m.cleanup('www.example.com', h)                         # 550: gone already
            self.assertIn('read back', m.test())
            self.assertIn('the folder /www is there', m.access())
            bad = plugin('http_ftp')({'protocol': 'ftp', 'host': '127.0.0.1:%d' % port,
                                      'ftp_user': 'fu', 'ftp_password': 'no'}, ctx)
            with self.assertRaises(PluginError) as e:
                bad.access()
            self.assertIn('did not let fu in', str(e.exception))
            del web
        finally:
            srv.shutdown()
            srv.server_close()

    def test_sftp_through_ssh(self):
        world = SshWorld()

        def http(method, url, body, h):
            path = '/srv/www' + urllib.parse.urlsplit(url).path
            got = world.files.get('web.example.net', {}).get(path)
            return (200, {}, got) if got is not None else (404, {}, b'')
        ctx = FakeCtx(http=http, ssh=world)
        m = plugin('http_ftp')({'protocol': 'sftp', 'host': 'web.example.net', 'user': 'site',
                                'auth': 'password', 'password': 'x', 'trust_first': True,
                                'folder': '/srv/www'}, ctx)
        h = m.present('www.example.com', 'tok-3', 'tok-3.ka', '')
        self.assertEqual(world.files['web.example.net']['/srv/www/.well-known/acme-challenge/'
                                                        'tok-3'], b'tok-3.ka')
        self.assertEqual(world.conns[-1]['user'], 'site')
        self.assertTrue(m.ready('www.example.com', h))
        m.cleanup('www.example.com', h)
        self.assertNotIn('/srv/www/.well-known/acme-challenge/tok-3',
                         world.files['web.example.net'])


class TestDescribed(unittest.TestCase):
    DNS = ('subreg', 'czechia', 'loopia', 'simply', 'hostingde', 'domeneshop', 'glesys',
           'mythic_beasts', 'infomaniak', 'alidns', 'tencentcloud', 'oci_dns', 'akamai_edgedns',
           'dnsmadeeasy', 'gcore', 'netlify', 'vercel', 'namecom', 'namesilo', 'dynu', 'njalla',
           'dreamhost', 'duckdns')
    HTTP = ('http_ftp', 'http_s3', 'http_azure_blob', 'http_webdav')

    def test_every_new_module_described(self):
        for kind in self.DNS + self.HTTP:
            cls = plugin(kind)
            d = cls.describe()
            self.assertEqual(cls.types, ('dns-01',) if kind in self.DNS else ('http-01',), kind)
            self.assertTrue(d['title'] and d['description'], kind)
            secrets = [f for f in d['fields'] if f['type'] == 'secret' or f.get('secret')]
            self.assertTrue(secrets, kind)
            keys = [f['key'] for f in d['fields']]
            self.assertEqual(len(keys), len(set(keys)), kind)
            if kind in self.DNS:
                self.assertIn('zone', keys, kind)
            self.assertTrue((cls.__doc__ or sys.modules[cls.__module__].__doc__ or '').strip(),
                            kind)
            self.assertIn('Source', sys.modules[cls.__module__].__doc__, kind)

    def test_guide_says_access_without_changing(self):
        f = DynuFake(self)
        f.throttled = True
        m, _ = module('dynu', f, key='dk', zone='example.com')
        m.guide_timeout = 0.2
        m.resolvers = lambda: ['127.0.0.1:9']
        g = m.guide('www.example.com')
        self.assertEqual(g['steps'][0]['key'], 'access')
        self.assertTrue(g['steps'][0]['done'])
        self.assertEqual(f.changes, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
