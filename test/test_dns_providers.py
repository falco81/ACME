#!/usr/bin/env python3
"""The DNS provider API modules (DNS-01), each against a fake of its API.

    python3 test/test_dns_providers.py

No internet: ctx.http is answered by an in-memory fake of each provider that
keeps TXT records the way that provider does (one record a value, or an
RRset written whole) and checks that each request is what the provider
wants - the address, the method, the signature or the credentials, the body.
For every module: the zone found (the longest of the zones the account has),
two values at one name (example.com and *.example.com at once) both kept,
cleanup taking only its own away, a second cleanup quiet, test() changing
nothing, and a 429 with Retry-After waited out.
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_challenges import FakeCtx, plugin  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.challenges import _common as C  # noqa: E402

ZONES = ['example.com', 'dev.example.com', 'other.org']
NAME = '_acme-challenge.www.example.com'
# a 429 is waited out without waiting. One list however this file is imported: as
# test.test_dns_providers by unittest and as test_dns_providers by the files that
# build on it (test_dns_providers_more / _new) - two copies of the module, one _common
SLEPT = C.__dict__.setdefault('_TEST_SLEPT', [])
C.SLEEP = SLEPT.append


def q(url):
    return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query,
                                                      keep_blank_values=True).items()}


def form(body):
    return {k: v[0] for k, v in urllib.parse.parse_qs((body or b'').decode(),
                                                      keep_blank_values=True).items()}


class Fake(object):
    """An API: handle(method, url, body, headers) -> (status, data) - data a
    dict/list (JSON), bytes or str. The first request answers 429 once."""
    def __init__(self, test):
        self.t = test
        self.recs = []                       # {'id', 'zone', 'name' (fqdn), 'value', 'ttl'}
        self.next_id = 100
        self.calls = []
        self.throttled = False
        self.changes = 0

    def add(self, zone, name, value, ttl=60):
        self.next_id += 1
        self.recs.append({'id': self.next_id, 'zone': zone, 'name': name.lower().rstrip('.'),
                          'value': value, 'ttl': ttl})
        self.changes += 1
        return self.next_id

    def values(self, name=NAME):
        return sorted(r['value'] for r in self.recs if r['name'] == name)

    def drop(self, pred):
        before = len(self.recs)
        self.recs = [r for r in self.recs if not pred(r)]
        self.changes += before - len(self.recs)
        return before - len(self.recs)

    def __call__(self, method, url, body, headers):
        self.calls.append((method, url, body, headers))
        if not self.throttled:
            self.throttled = True
            return 429, {'Retry-After': '2'}, b'{"detail": "slow down"}'
        st, data = self.handle(method, url, body, headers)
        if isinstance(data, (dict, list)):
            data = json.dumps(data).encode()
        elif isinstance(data, str):
            data = data.encode()
        return st, {}, data or b''

    def rel(self, zone, name):
        name = name.lower().rstrip('.')
        return '' if name == zone else name[:-len(zone) - 1]

    def full(self, zone, rel):
        return zone if rel in ('', '@') else '%s.%s' % (rel, zone)


def module(kind, fake, **cfg):
    cfg.setdefault('propagation', 'none')
    cfg.setdefault('follow_cname', False)
    ctx = FakeCtx(http=fake)
    return plugin(kind)(cfg, ctx), ctx


class Base(unittest.TestCase):
    """What every module is put through."""
    def run_module(self, kind, fake, quoted=False, **cfg):
        del SLEPT[:]
        m, ctx = module(kind, fake, **cfg)
        # the zone: the longest of the account's zones the name is in
        self.assertEqual(m.zone_for('_acme-challenge.a.dev.example.com'), 'dev.example.com')
        self.assertEqual(m.zone_for(NAME), 'example.com')
        self.assertTrue(SLEPT and SLEPT[0] == 2.0, 'a 429 is waited out as Retry-After says')
        self.assertTrue(any('429' in w for _l, w in ctx.steps))
        fake.add('example.com', NAME, 'someone-elses')
        h1 = m.present('www.example.com', 't', 'k', 'one')
        h2 = m.present('*.www.example.com', 't', 'k', 'two')
        self.assertEqual(fake.values(), ['one', 'someone-elses', 'two'])
        again = m.present('www.example.com', 't', 'k', 'one')       # put in again: no copy
        self.assertEqual(fake.values(), ['one', 'someone-elses', 'two'])
        m.cleanup('www.example.com', h1)
        self.assertEqual(fake.values(), ['someone-elses', 'two'])
        m.cleanup('www.example.com', again)                          # gone already: quiet
        m.cleanup('www.example.com', h1)
        m.cleanup('*.www.example.com', h2)
        self.assertEqual(fake.values(), ['someone-elses'])
        n = fake.changes
        m2, _ = module(kind, fake, **cfg)
        words = m2.test()
        self.assertEqual(fake.changes, n, 'test() changes nothing')
        self.assertTrue(words)
        return m


# ---------------------------------------------------------------------------
class DesecFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Token tok')
        base = 'https://desec.io/api/v1/domains/'
        self.t.assertTrue(url.startswith(base), url)
        path = url[len(base):].strip('/').split('/')
        if method == 'GET' and path == ['']:
            return 200, [{'name': z, 'minimum_ttl': 3600} for z in ZONES]
        zone = path[0]
        if method == 'GET' and len(path) == 1:
            return (200, {'name': zone, 'minimum_ttl': 3600}) if zone in ZONES else (404, {})
        if method == 'GET' and path[1] == 'rrsets':
            name = self.full(zone, urllib.parse.unquote(path[2]))
            vals = ['"%s"' % r['value'] for r in self.recs if r['name'] == name]
            return (200, {'records': vals, 'ttl': 3600}) if vals else (404, {'detail': 'nope'})
        if method == 'PATCH':
            self.t.assertEqual(path[1:], ['rrsets'])
            for rs in json.loads(body):
                self.t.assertEqual(rs['type'], 'TXT')
                self.t.assertGreaterEqual(rs['ttl'], 3600)
                name = self.full(zone, rs['subname'])
                self.drop(lambda r: r['name'] == name)
                for v in rs['records']:
                    self.t.assertTrue(v.startswith('"'))
                    self.add(zone, name, v.strip('"'))
            return 200, []
        return 404, {}


class GandiFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Bearer pat')
        base = 'https://api.gandi.net/v5/livedns/domains'
        if url == base:
            return 200, [{'fqdn': z} for z in ZONES]
        _, zone, _r, rel, typ = url[len(base):].split('/')
        self.t.assertEqual(typ, 'TXT')
        name = self.full(zone, urllib.parse.unquote(rel))
        if method == 'GET':
            vals = ['"%s"' % r['value'] for r in self.recs if r['name'] == name]
            return (200, {'rrset_values': vals, 'rrset_ttl': 300}) if vals else (404, {})
        self.drop(lambda r: r['name'] == name)
        if method == 'PUT':
            b = json.loads(body)
            self.t.assertGreaterEqual(b['rrset_ttl'], 300)
            for v in b['rrset_values']:
                self.add(zone, name, v.strip('"'))
        return 201, {}


class LinodeFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Bearer lt')
        u = urllib.parse.urlsplit(url)
        self.t.assertEqual(u.netloc, 'api.linode.com')
        p = u.path[len('/v4/'):].split('/')
        if p == ['domains']:
            return 200, {'data': [{'id': i + 1, 'domain': z} for i, z in enumerate(ZONES)],
                         'page': 1, 'pages': 1}
        zone = ZONES[int(p[1]) - 1]
        if method == 'GET':
            return 200, {'data': [{'id': r['id'], 'type': 'TXT', 'name': self.rel(zone, r['name']),
                                   'target': r['value']} for r in self.recs if r['zone'] == zone],
                         'pages': 1}
        if method == 'POST':
            b = json.loads(body)
            self.t.assertEqual((b['type'], b['ttl_sec']), ('TXT', 300))
            return 200, {'id': self.add(zone, self.full(zone, b['name']), b['target'])}
        if method == 'DELETE':
            return (200, {}) if self.drop(lambda r: str(r['id']) == p[3]) else (404, {})


class VultrFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Bearer vk')
        p = urllib.parse.urlsplit(url).path[len('/v2/'):].split('/')
        if p == ['domains']:
            return 200, {'domains': [{'domain': z} for z in ZONES], 'meta': {'links': {'next': ''}}}
        zone = p[1]
        if method == 'GET':
            return 200, {'records': [{'id': str(r['id']), 'type': 'TXT', 'name': self.rel(
                zone, r['name']), 'data': '"%s"' % r['value']} for r in self.recs
                if r['zone'] == zone], 'meta': {'links': {'next': ''}}}
        if method == 'POST':
            b = json.loads(body)
            self.t.assertTrue(b['data'].startswith('"'))
            rid = self.add(zone, self.full(zone, b['name']), b['data'].strip('"'))
            return 201, {'record': {'id': str(rid)}}
        if method == 'DELETE':
            return (204, b'') if self.drop(lambda r: str(r['id']) == p[3]) else (404, {})


class PorkbunFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(method, 'POST')
        b = json.loads(body)
        self.t.assertEqual((b['apikey'], b['secretapikey']), ('pk1', 'sk1'))
        p = url[len('https://api.porkbun.com/api/json/v3/'):].split('/')
        if p == ['ping']:
            return 200, {'status': 'SUCCESS', 'yourIp': '203.0.113.5'}
        if p == ['domain', 'listAll']:
            return 200, {'status': 'SUCCESS', 'domains': [{'domain': z} for z in ZONES]}
        if p[:2] == ['dns', 'retrieveByNameType']:
            zone, sub = p[2], p[4] if len(p) > 4 else ''
            name = self.full(zone, sub)
            return 200, {'status': 'SUCCESS', 'records': [
                {'id': str(r['id']), 'name': name, 'content': r['value']}
                for r in self.recs if r['name'] == name]}
        if p[:2] == ['dns', 'create']:
            self.t.assertGreaterEqual(int(b['ttl']), 600)
            return 200, {'status': 'SUCCESS', 'id': self.add(p[2], self.full(p[2], b['name']),
                                                            b['content'])}
        if p[:2] == ['dns', 'delete']:
            if self.drop(lambda r: str(r['id']) == p[3]):
                return 200, {'status': 'SUCCESS'}
            return 400, {'status': 'ERROR', 'message': 'Invalid record ID.'}


class NamecheapFake(Fake):
    NS = 'http://api.namecheap.com/xml.response'

    def __init__(self, t):
        Fake.__init__(self, t)
        self.other = [('@', 'A', '192.0.2.1', '10', '1800'), ('@', 'MX', 'mx.example.com.', '5',
                                                              '1800')]

    def ok(self, inner):
        return 200, '<?xml version="1.0"?><ApiResponse Status="OK" xmlns="%s"><Errors/>' \
                    '<CommandResponse>%s</CommandResponse></ApiResponse>' % (self.NS, inner)

    def handle(self, method, url, body, h):
        p = q(url) if method == 'GET' else form(body)
        self.t.assertEqual((p['ApiUser'], p['ApiKey'], p['ClientIp']), ('u', 'key', '198.51.100.7'))
        cmd = p['Command']
        if cmd == 'namecheap.domains.getList':
            return self.ok('<DomainGetListResult>%s</DomainGetListResult><Paging><TotalItems>%d'
                           '</TotalItems></Paging>' % (''.join('<Domain Name="%s"/>' % z
                                                               for z in ZONES), len(ZONES)))
        zone = '%s.%s' % (p['SLD'], p['TLD'])
        if cmd == 'namecheap.domains.dns.getHosts':
            hosts = ''.join('<host HostId="1" Name="%s" Type="%s" Address="%s" MXPref="%s" '
                            'TTL="%s"/>' % o for o in self.other)
            hosts += ''.join('<host HostId="%d" Name="%s" Type="TXT" Address="%s" MXPref="10" '
                             'TTL="60"/>' % (r['id'], self.rel(zone, r['name']) or '@', r['value'])
                             for r in self.recs if r['zone'] == zone)
            return self.ok('<DomainDNSGetHostsResult Domain="%s" EmailType="MX" '
                           'IsUsingOurDNS="true">%s</DomainDNSGetHostsResult>' % (zone, hosts))
        if cmd == 'namecheap.domains.dns.setHosts':
            self.t.assertEqual(method, 'POST')
            self.t.assertEqual(p.get('EmailType'), 'MX')
            n, others, txt = 1, [], []
            while 'HostName%d' % n in p:
                row = (p['HostName%d' % n], p['RecordType%d' % n], p['Address%d' % n],
                       p['MXPref%d' % n], p['TTL%d' % n])
                (txt if row[1] == 'TXT' else others).append(row)
                n += 1
            self.t.assertEqual(others, self.other, 'every other record is written back as it was')
            self.drop(lambda r: r['zone'] == zone)
            for row in txt:
                self.add(zone, self.full(zone, row[0]), row[2])
            return self.ok('<DomainDNSSetHostsResult Domain="%s" IsSuccess="true"/>' % zone)


class GodaddyFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'sso-key K:S')
        u = urllib.parse.urlsplit(url)
        p = u.path[len('/v1/'):].split('/')
        if p == ['domains']:
            self.t.assertEqual(q(url)['statuses'], 'ACTIVE')
            return 200, [{'domain': z} for z in ZONES]
        zone, typ, rel = p[1], p[3], urllib.parse.unquote(p[4])
        self.t.assertEqual(typ, 'TXT')
        name = self.full(zone, rel)
        if method == 'GET':
            return 200, [{'data': r['value'], 'ttl': 600, 'name': rel, 'type': 'TXT'}
                         for r in self.recs if r['name'] == name]
        if method == 'DELETE' and not self.values(name):
            return 404, {'code': 'NOT_FOUND'}
        self.drop(lambda r: r['name'] == name)
        if method == 'PUT':
            for rec in json.loads(body):
                self.t.assertGreaterEqual(rec['ttl'], 600)
                self.add(zone, name, rec['data'])
        return 200, b''


class DnsimpleFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Bearer dt')
        u = urllib.parse.urlsplit(url)
        p = u.path[len('/v2/'):].split('/')
        if p == ['whoami']:
            return 200, {'data': {'account': {'id': 1010}, 'user': None}}
        self.t.assertEqual(p[0], '1010')
        if p[1:] == ['zones']:
            return 200, {'data': [{'name': z} for z in ZONES], 'pagination': {'total_pages': 1}}
        zone = p[2]
        if method == 'GET':
            name = self.full(zone, q(url).get('name', ''))
            return 200, {'data': [{'id': r['id'], 'name': self.rel(zone, r['name']),
                                   'content': '"%s"' % r['value']} for r in self.recs
                                  if r['name'] == name]}
        if method == 'POST':
            b = json.loads(body)
            return 201, {'data': {'id': self.add(zone, self.full(zone, b['name']), b['content'])}}
        if method == 'DELETE':
            return (204, b'') if self.drop(lambda r: str(r['id']) == p[4]) else (404, {})


class Ns1Fake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['X-NSONE-Key'], 'nk')
        p = urllib.parse.urlsplit(url).path[len('/v1/'):].split('/')
        if p == ['zones']:
            return 200, [{'zone': z} for z in ZONES]
        zone, name = p[1], p[2]
        have = [r for r in self.recs if r['name'] == name]
        if method == 'GET':
            return (200, {'answers': [{'answer': [r['value']]} for r in have], 'ttl': 60}) \
                if have else (404, {'message': 'record not found'})
        if method == 'PUT' and have:
            return 400, {'message': 'record already exists'}
        if method == 'POST' and not have:
            return 404, {'message': 'record not found'}
        if method == 'DELETE':
            return (200, {}) if self.drop(lambda r: r['name'] == name) else (404, {})
        b = json.loads(body)
        if method == 'PUT':
            self.t.assertEqual((b['zone'], b['domain'], b['type']), (zone, name, 'TXT'))
        self.drop(lambda r: r['name'] == name)
        for a in b['answers']:
            self.add(zone, name, a['answer'][0])
        return 200, {}


class BunnyFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['AccessKey'], 'bk')
        p = urllib.parse.urlsplit(url).path.strip('/').split('/')
        if p == ['dnszone']:
            return 200, {'Items': [{'Id': i + 1, 'Domain': z} for i, z in enumerate(ZONES)],
                         'HasMoreItems': False}
        zone = ZONES[int(p[1]) - 1]
        if method == 'GET':
            return 200, {'Records': [{'Id': r['id'], 'Type': 3, 'Name': self.rel(zone, r['name']),
                                      'Value': r['value']} for r in self.recs
                                     if r['zone'] == zone] + [{'Id': 1, 'Type': 0, 'Name': '',
                                                               'Value': '192.0.2.1'}]}
        if method == 'PUT':
            b = json.loads(body)
            self.t.assertEqual(b['Type'], 3)
            return 201, {'Id': self.add(zone, self.full(zone, b['Name']), b['Value'])}
        if method == 'DELETE':
            return (204, b'') if self.drop(lambda r: str(r['id']) == p[3]) else (404, {})


class CloudnsFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(method, 'POST')
        p = form(body)
        self.t.assertEqual((p['sub-auth-id'], p['auth-password']), ('77', 'cp'))
        what = url.rsplit('/', 1)[1]
        if what == 'login.json':
            return 200, {'status': 'Success', 'statusDescription': 'Success login.'}
        if what == 'list-zones.json':
            return 200, [{'name': z, 'type': 'master'} for z in ZONES]
        zone = p['domain-name']
        if what == 'records.json':
            name = self.full(zone, p['host'])
            got = {str(r['id']): {'id': str(r['id']), 'host': p['host'], 'type': 'TXT',
                                  'record': r['value']} for r in self.recs if r['name'] == name}
            return 200, got or []
        if what == 'add-record.json':
            self.t.assertEqual(p['ttl'], '60')
            rid = self.add(zone, self.full(zone, p['host']), p['record'])
            return 200, {'status': 'Success', 'data': {'id': rid}}
        if what == 'delete-record.json':
            if self.drop(lambda r: str(r['id']) == p['record-id']):
                return 200, {'status': 'Success'}
            return 200, {'status': 'Failed', 'statusDescription': 'Invalid record-id param.'}


class InwxFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual((method, url), ('POST', 'https://api.domrobot.com/jsonrpc/'))
        b = json.loads(body)
        m, p = b['method'], b['params']
        if m == 'account.login':
            self.t.assertEqual((p['user'], p['pass']), ('iu', 'ip'))
            self.session = True
            return 200, {'code': 1000, 'resData': {'tfa': '0'}}
        self.t.assertTrue(getattr(self, 'session', False))
        if m == 'account.logout':
            return 200, {'code': 1500}
        if m == 'nameserver.list':
            return 200, {'code': 1000, 'resData': {'count': 3, 'domains': [{'domain': z}
                                                                         for z in ZONES]}}
        if m == 'nameserver.info':
            return 200, {'code': 1000, 'resData': {'record': [
                {'id': r['id'], 'name': r['name'], 'type': 'TXT', 'content': r['value']}
                for r in self.recs if r['name'] == p['name']]}}
        if m == 'nameserver.createRecord':
            self.t.assertGreaterEqual(p['ttl'], 300)
            return 200, {'code': 1000, 'resData': {'id': self.add(p['domain'], p['name'],
                                                                  p['content'])}}
        if m == 'nameserver.deleteRecord':
            if self.drop(lambda r: r['id'] == p['id']):
                return 200, {'code': 1000}
            return 200, {'code': 2303, 'msg': 'Object does not exist'}

    def __call__(self, method, url, body, headers):
        st, rh, data = Fake.__call__(self, method, url, body, headers)
        if st == 200 and b'"tfa"' in data:
            rh = {'Set-Cookie': 'domrobot=S3SS; path=/; secure'}
        elif st == 200:
            self.t.assertEqual(headers.get('Cookie'), 'domrobot=S3SS')
        return st, rh, data


class TransipFake(Fake):
    def __init__(self, t, pub):
        Fake.__init__(self, t)
        self.pub = pub

    def handle(self, method, url, body, h):
        p = urllib.parse.urlsplit(url).path[len('/v6/'):].split('/')
        if p == ['auth']:
            b = json.loads(body)
            self.t.assertEqual((b['login'], b['expiration_time']), ('tl', '30 minutes'))
            work = tempfile.mkdtemp()
            try:
                with open(os.path.join(work, 'pub'), 'wb') as f:
                    f.write(self.pub)
                with open(os.path.join(work, 'sig'), 'wb') as f:
                    f.write(base64.b64decode(h['Signature']))
                ok = subprocess.run(['openssl', 'dgst', '-sha512', '-verify',
                                     os.path.join(work, 'pub'), '-signature',
                                     os.path.join(work, 'sig')], input=body, capture_output=True)
            finally:
                shutil.rmtree(work)
            self.t.assertIn(b'Verified OK', ok.stdout, 'the sign-in is signed RSA-SHA512')
            return 201, {'token': 'JWT1'}
        self.t.assertEqual(h['Authorization'], 'Bearer JWT1')
        if p == ['domains']:
            return 200, {'domains': [{'name': z} for z in ZONES]}
        zone = p[1]
        if method == 'GET':
            return 200, {'dnsEntries': [{'name': self.rel(zone, r['name']) or '@', 'expire': 60,
                                         'type': 'TXT', 'content': r['value']}
                                        for r in self.recs if r['zone'] == zone]}
        e = json.loads(body)['dnsEntry']
        name = self.full(zone, e['name'])
        if method == 'POST':
            self.t.assertIn(e['expire'], (60, 300, 3600, 86400))
            self.add(zone, name, e['content'])
            return 201, b''
        if method == 'DELETE':
            return (204, b'') if self.drop(lambda r: r['name'] == name and
                                           r['value'] == e['content']) else (404, {})


class NetcupFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(url, 'https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON')
        b = json.loads(body)
        a, p = b['action'], b['param']
        if a == 'login':
            self.t.assertEqual((p['customernumber'], p['apikey'], p['apipassword']),
                               ('4711', 'nk', 'np'))
            return 200, {'status': 'success', 'statuscode': 2000,
                         'responsedata': {'apisessionid': 'SID'}}
        self.t.assertEqual(p['apisessionid'], 'SID')
        if a == 'logout':
            return 200, {'status': 'success', 'statuscode': 2000}
        zone = p.get('domainname')
        if a == 'infoDnsZone':
            if zone in ZONES:
                return 200, {'status': 'success', 'statuscode': 2000,
                             'responsedata': {'name': zone, 'ttl': '86400'}}
            return 200, {'status': 'error', 'statuscode': 5028, 'shortmessage': 'no zone'}
        if a == 'infoDnsRecords':
            recs = [{'id': str(r['id']), 'hostname': self.rel(zone, r['name']) or '@',
                     'type': 'TXT', 'destination': r['value'], 'deleterecord': False}
                    for r in self.recs if r['zone'] == zone]
            if not recs:
                return 200, {'status': 'error', 'statuscode': 5029, 'shortmessage': 'no records'}
            return 200, {'status': 'success', 'statuscode': 2000,
                         'responsedata': {'dnsrecords': recs}}
        if a == 'updateDnsRecords':
            for r in p['dnsrecordset']['dnsrecords']:
                if r.get('deleterecord'):
                    self.drop(lambda x: str(x['id']) == r['id'])
                else:
                    self.t.assertNotIn('id', r)
                    self.add(zone, self.full(zone, r['hostname']), r['destination'])
            return 200, {'status': 'success', 'statuscode': 2000, 'responsedata': {}}


class IonosFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['X-API-Key'], 'pre.sec')
        p = urllib.parse.urlsplit(url).path[len('/dns/v1/'):].split('/')
        if p == ['zones']:
            return 200, [{'id': 'z%d' % i, 'name': z, 'type': 'NATIVE'} for i, z in enumerate(ZONES)]
        zone = ZONES[int(p[1][1:])]
        if method == 'GET':
            name = q(url)['recordName']
            self.t.assertEqual(q(url)['recordType'], 'TXT')
            return 200, {'name': zone, 'records': [{'id': str(r['id']), 'name': r['name'],
                                                    'type': 'TXT', 'content': '"%s"' % r['value']}
                                                   for r in self.recs if r['name'] == name]}
        if method == 'POST':
            (b,) = json.loads(body)
            return 201, [{'id': str(self.add(zone, b['name'], b['content']))}]
        if method == 'DELETE':
            return (200, b'') if self.drop(lambda r: str(r['id']) == p[3]) else (404, {})


class ScalewayFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['X-Auth-Token'], 'sk')
        p = urllib.parse.urlsplit(url).path[len('/domain/v2beta1/'):].split('/')
        if p == ['dns-zones']:
            return 200, {'dns_zones': [{'domain': 'example.com', 'subdomain': ''},
                                       {'domain': 'example.com', 'subdomain': 'dev'},
                                       {'domain': 'other.org', 'subdomain': ''}], 'total_count': 3}
        zone = p[1]
        if method == 'GET':
            name = self.full(zone, q(url).get('name', ''))
            return 200, {'records': [{'id': 'r%d' % r['id'], 'name': self.rel(zone, r['name']),
                                      'type': 'TXT', 'data': '"%s"' % r['value']}
                                     for r in self.recs if r['name'] == name]}
        if method == 'PATCH':
            for ch in json.loads(body)['changes']:
                if 'add' in ch:
                    for rec in ch['add']['records']:
                        self.t.assertTrue(rec['data'].startswith('"'))
                        self.add(zone, self.full(zone, rec['name']), rec['data'].strip('"'))
                else:
                    if not self.drop(lambda r: 'r%d' % r['id'] == ch['delete']['id']):
                        return 404, {'message': 'record not found'}
            return 200, {'records': []}


class ExoscaleFake(Fake):
    def handle(self, method, url, body, h):
        u = urllib.parse.urlsplit(url)
        self.t.assertEqual(u.netloc, 'api-ch-gva-2.exoscale.com')
        auth = dict(x.split('=', 1) for x in h['Authorization'][len('EXO2-HMAC-SHA256 '):]
                    .split(','))
        msg = '\n'.join(['%s %s' % (method, u.path), (body or b'').decode(), '', '',
                         auth['expires']])
        want = base64.b64encode(hmac.new(b'es', msg.encode(), hashlib.sha256).digest()).decode()
        self.t.assertEqual((auth['credential'], auth['signature']), ('EXOk', want))
        p = u.path[len('/v2/'):].split('/')
        if p == ['dns-domain']:
            return 200, {'dns-domains': [{'id': 'd%d' % i, 'unicode-name': z}
                                         for i, z in enumerate(ZONES)]}
        zone = ZONES[int(p[1][1:])]
        if method == 'GET':
            return 200, {'dns-domain-records': [{'id': 'r%d' % r['id'], 'type': 'TXT',
                                                 'name': self.rel(zone, r['name']),
                                                 'content': '"%s"' % r['value']}
                                                for r in self.recs if r['zone'] == zone]}
        if method == 'POST':
            b = json.loads(body)
            self.add(zone, self.full(zone, b['name']), b['content'])
            return 200, {'id': 'op1', 'state': 'success'}
        if method == 'DELETE':
            return (200, {'state': 'success'}) if self.drop(
                lambda r: 'r%d' % r['id'] == p[3]) else (404, {'message': 'not found'})


class InfobloxFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Basic ' + base64.b64encode(b'ib:ipw').decode())
        u = urllib.parse.urlsplit(url)
        self.t.assertEqual(u.netloc, 'gm.example.local')
        p = u.path[len('/wapi/v2.10/'):]
        if p == 'zone_auth':
            self.t.assertEqual(q(url)['view'], 'internal')
            return 200, [{'_ref': 'zone_auth/x:%s/internal' % z, 'fqdn': z} for z in ZONES]
        if p == 'record:txt' and method == 'GET':
            return 200, [{'_ref': 'record:txt/R%d:%s/internal' % (r['id'], r['name']),
                          'name': r['name'], 'text': r['value']} for r in self.recs
                         if r['name'] == q(url)['name']]
        if p == 'record:txt' and method == 'POST':
            b = json.loads(body)
            self.t.assertEqual((b['view'], b['use_ttl']), ('internal', True))
            rid = self.add('?', b['name'], b['text'])
            return 201, 'record:txt/R%d:%s/internal' % (rid, b['name'])
        if method == 'DELETE':
            rid = p.split('/')[1].split(':')[0][1:]
            return (200, '"%s"' % p) if self.drop(lambda r: str(r['id']) == rid) else \
                (404, {'Error': 'AdmConDataNotFoundError', 'text': 'not found'})


class TechnitiumFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual(method, 'POST')
        p = form(body)
        self.t.assertEqual(p['token'], 'tt')
        path = urllib.parse.urlsplit(url).path
        if path == '/api/zones/list':
            return 200, {'status': 'ok', 'response': {'zones': [{'name': z, 'type': 'Primary'}
                                                                for z in ZONES]}}
        if path == '/api/zones/records/get':
            return 200, {'status': 'ok', 'response': {'records': [
                {'name': r['name'], 'type': 'TXT', 'ttl': 60, 'rData': {'text': r['value']}}
                for r in self.recs if r['name'] == p['domain']]}}
        self.t.assertEqual(p['type'], 'TXT')
        if path == '/api/zones/records/add':
            self.add(p['zone'], p['domain'], p['text'])
            return 200, {'status': 'ok', 'response': {}}
        if path == '/api/zones/records/delete':
            if self.drop(lambda r: r['name'] == p['domain'] and r['value'] == p['text']):
                return 200, {'status': 'ok'}
            return 200, {'status': 'error', 'errorMessage': 'no such record'}


class WedosFake(Fake):
    def handle(self, method, url, body, h):
        self.t.assertEqual((method, url), ('POST', 'https://api.wedos.com/wapi/json'))
        r = json.loads(form(body)['request'])['request']
        from acmelib.plugins.challenges.wedos import wedos_auth
        self.t.assertEqual(r['user'], 'me@example.cz')
        self.t.assertEqual(r['auth'], wedos_auth('me@example.cz', 'wp'))
        cmd, d = r['command'], r.get('data') or {}

        def ok(data=None):
            return 200, {'response': {'code': 1000, 'result': 'OK', 'data': data or {}}}
        if cmd == 'ping':
            return ok()
        if cmd == 'dns-domains-list':
            # as WAPI: 50 a page unless asked; a secondary and a disabled one among them
            every = [{'name': 'zz%03d.example.net' % i, 'type': 'primary', 'status': 'active'}
                     for i in range(getattr(self, 'filler', 0))] + \
                [{'name': 'sec.example.com', 'type': 'secondary', 'status': 'active'},
                 {'name': 'off.example.com', 'type': 'primary', 'status': 'disabled'}] + \
                [{'name': z, 'type': 'primary', 'status': 'active'} for z in ZONES]
            per = int(d.get('page_limit') or 50)
            page = int(d.get('page') or 1)
            return ok({'domain': every[(page - 1) * per:page * per], 'total': len(every),
                       'page': page, 'page_limit': per})
        if cmd == 'dns-rows-list':
            rows = [{'ID': str(x['id']), 'name': self.rel(d['domain'], x['name']),
                     'ttl': '300', 'rdtype': 'TXT', 'rdata': x['value']}
                    for x in self.recs if x['zone'] == d['domain']]
            if getattr(self, 'numbered', False):        # the docs' template: row1, row2...
                return ok({'row%d' % (i + 1): r for i, r in enumerate(rows)})
            return ok({'row': rows})
        if cmd == 'dns-row-add':
            self.t.assertGreaterEqual(d['ttl'], 300)
            self.t.assertNotIn('auth_comment', d)       # the parameter is author_comment
            self.t.assertIn('author_comment', d)
            self.add(d['domain'], self.full(d['domain'], d['name']), d['rdata'])
            self.commits = getattr(self, 'commits', 0) - 1
            return ok()
        if cmd == 'dns-row-delete':
            self.drop(lambda x: str(x['id']) == str(d['row_id']))
            self.commits = getattr(self, 'commits', 0) - 1
            return ok()
        if cmd == 'dns-domain-commit':
            self.t.assertIn(d['name'], ZONES)
            self.commits = 0
            return ok()


class WebsupportFake(Fake):
    """Websupport v1 and Active24 v2 alike: signed HMAC-SHA1."""
    def __init__(self, t, host, v2=False):
        Fake.__init__(self, t)
        self.host, self.v2 = host, v2

    def handle(self, method, url, body, h):
        u = urllib.parse.urlsplit(url)
        self.t.assertEqual(u.netloc, self.host)
        key, sig = base64.b64decode(h['Authorization'][6:]).decode().split(':')
        # v2 (Active24): the Date in RFC 3339, as lego's v2 client sends it; v1 basic ISO 8601
        ts = int(datetime.datetime.strptime(h['Date'], '%Y-%m-%dT%H:%M:%SZ' if self.v2 else
                                            '%Y%m%dT%H%M%SZ').replace(
            tzinfo=datetime.timezone.utc).timestamp())
        want = hmac.new(b'wsec', ('%s %s %d' % (method, u.path, ts)).encode(),
                        hashlib.sha1).hexdigest()
        self.t.assertEqual((key, sig), ('wkey', want))
        p = u.path.strip('/').split('/')
        if self.v2:
            if p == ['v2', 'check']:
                return 200, {'verified': True}
            if p[:4] == ['v1', 'user', 'self', 'zone']:
                # one domain's service (acme.sh's lookup): other.org is not in the list
                return (200, {'id': 777, 'name': p[4]}) if p[4] == 'other.org' else (404, {})
            if len(p) == 5 and p[3:] == ['dns', 'zone']:
                return 200, {'name': ZONES[int(p[2]) - 500] if int(p[2]) != 777 else 'other.org',
                             'dnssecSigning': 'inactive'}
            if p == ['v1', 'user', 'self', 'service']:
                return 200, {'items': [{'id': 500 + i, 'serviceName': 'domain', 'name': z}
                                       for i, z in enumerate(ZONES) if z != 'other.org'] + [
                    {'id': 9, 'serviceName': 'hosting', 'name': 'x'}]}
            zone = 'other.org' if int(p[2]) == 777 else ZONES[int(p[2]) - 500]
            recs = 'data'
            rid_at = 5
        else:
            if p == ['v1', 'user', 'self', 'zone']:
                return 200, {'items': [{'name': z} for z in ZONES]}
            zone = p[4]
            recs = 'items'
            rid_at = 6
        if method == 'GET':
            got = [{'id': r['id'], 'type': 'TXT', 'name': self.rel(zone, r['name']) or '@',
                    'content': r['value']} for r in self.recs if r['zone'] == zone]
            if self.v2:
                f = q(url)
                self.t.assertEqual(f['filters[type][]'], 'TXT')
                got = [r for r in got if r['name'] == f['filters[name]']]
            return 200, {recs: got}
        if method == 'POST':
            b = json.loads(body)
            rid = self.add(zone, self.full(zone, b['name']), b['content'])
            # v2: 204 and no body, as its OpenAPI description says
            return (204, None) if self.v2 else (201, {'status': 'success', 'item': {'id': rid}})
        if method == 'DELETE':
            return (200, {'status': 'success'}) if self.drop(
                lambda r: str(r['id']) == p[rid_at]) else (404, {'message': 'not found'})


class Active24ComFake(Fake):
    """api.active24.com: a Bearer token, records by their hashId."""
    def handle(self, method, url, body, h):
        u = urllib.parse.urlsplit(url)
        self.t.assertEqual(u.netloc, 'api.active24.com')
        self.t.assertEqual(h['Authorization'], 'Bearer a24tok')
        p = u.path.strip('/').split('/')
        if p == ['dns', 'domains', 'v1']:
            return 200, ZONES
        zone = p[1]
        if method == 'GET' and p[2:] == ['records', 'v1']:
            return 200, [{'hashId': 'h%d' % r['id'], 'type': 'TXT', 'ttl': r['ttl'],
                          'name': self.rel(zone, r['name']) or '@', 'text': r['value']}
                         for r in self.recs if r['zone'] == zone] + [
                {'hashId': 'hA', 'type': 'A', 'name': 'www', 'ip': '192.0.2.1', 'ttl': 300}]
        if method == 'POST' and p[2:] == ['txt', 'v1']:
            b = json.loads(body)
            self.t.assertEqual(set(b), {'name', 'text', 'ttl'})
            self.add(zone, self.full(zone, b['name']), b['text'], b['ttl'])
            return 204, None
        if method == 'DELETE' and p[3] == 'v1':
            return (204, None) if self.drop(lambda r: 'h%d' % r['id'] == p[2]) else \
                (400, {'message': 'DNS_RECORD_TO_DELETE_NOT_FOUND'})
        return 404, {}


# ---------------------------------------------------------------------------
class TestProviders(Base):
    def test_desec(self):
        m = self.run_module('desec', DesecFake(self), token='tok', settle=0)
        self.assertEqual(m.ttl(), 3600, 'deSEC takes no TTL under 3600')

    def test_desec_settles(self):
        f = DesecFake(self)
        f.throttled = True
        m, _ = module('desec', f, token='tok', settle=60)
        h = m.present('www.example.com', 't', 'k', 'v')
        self.assertFalse(m.ready('www.example.com', h), 'seen, then 60 s more for anycast')

    def test_gandi(self):
        self.run_module('gandi', GandiFake(self), token='pat')

    def test_linode(self):
        self.run_module('linode', LinodeFake(self), token='lt')

    def test_vultr(self):
        self.run_module('vultr', VultrFake(self), token='vk')

    def test_porkbun(self):
        self.run_module('porkbun', PorkbunFake(self), api_key='pk1', secret_key='sk1')

    def test_namecheap_keeps_every_other_record(self):
        self.run_module('namecheap', NamecheapFake(self), api_user='u', api_key='key',
                        client_ip='198.51.100.7')

    def test_namecheap_refuses_without_consent_and_explains_ip(self):
        f = NamecheapFake(self)
        f.throttled = True
        m, _ = module('namecheap', f, api_user='u', api_key='key', client_ip='198.51.100.7',
                      rewrite_ok=False, zone='example.com')
        with self.assertRaises(PluginError):
            m.present('www.example.com', 't', 'k', 'v')
        self.assertEqual(f.changes, 0)
        f.handle = lambda *a: (200, '<ApiResponse Status="ERROR" xmlns="%s"><Errors><Error '
                                    'Number="1011150">Invalid request IP: 198.51.100.7</Error>'
                                    '</Errors></ApiResponse>' % f.NS)
        with self.assertRaises(PluginError) as e:
            module('namecheap', f, api_user='u', api_key='key', client_ip='198.51.100.7')[0].test()
        self.assertIn('whitelist', str(e.exception))

    def test_godaddy(self):
        self.run_module('godaddy', GodaddyFake(self), api_key='K', api_secret='S')

    def test_dnsimple(self):
        self.run_module('dnsimple', DnsimpleFake(self), token='dt')

    def test_ns1(self):
        self.run_module('ns1', Ns1Fake(self), api_key='nk')

    def test_bunny(self):
        self.run_module('bunny', BunnyFake(self), api_key='bk')

    def test_cloudns(self):
        self.run_module('cloudns', CloudnsFake(self), auth_id='77', auth_password='cp')

    def test_inwx(self):
        self.run_module('inwx', InwxFake(self), username='iu', password='ip')

    def test_inwx_2fa(self):
        from acmelib.plugins.challenges.inwx import totp
        # RFC 6238's test key, SHA-1, at 59 s: 94287082 (8 digits) -> 287082
        key = base64.b32encode(b'12345678901234567890').decode()
        self.assertEqual(totp(key, now=59, digits=8), '94287082')
        f = InwxFake(self)
        f.throttled = True
        seen = []

        def login(method, url, body, h):
            b = json.loads(body)
            seen.append(b['method'])
            if b['method'] == 'account.login':
                return 200, {'code': 1000, 'resData': {'tfa': 'GOOGLE-AUTH'}}
            if b['method'] == 'account.unlock':
                self.assertEqual(b['params']['tan'], totp(key))
                return 200, {'code': 1000}
            return 200, {'code': 1000, 'resData': {'domains': [], 'count': 0}}
        f.handle = login
        with self.assertRaises(PluginError) as e:
            module('inwx', f, username='iu', password='ip')[0].test()
        self.assertIn('two factors', str(e.exception))
        module('inwx', f, username='iu', password='ip', tfa_secret=key)[0].test()
        self.assertIn('account.unlock', seen)

    def test_transip_signed_with_the_key(self):
        work = tempfile.mkdtemp()
        try:
            kf = os.path.join(work, 'k.pem')
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                            'rsa_keygen_bits:2048', '-out', kf], check=True, capture_output=True)
            pub = subprocess.run(['openssl', 'pkey', '-in', kf, '-pubout'], check=True,
                                 capture_output=True).stdout
            with open(kf) as f:
                pem = f.read()
        finally:
            shutil.rmtree(work)
        self.run_module('transip', TransipFake(self, pub), login='tl', private_key=pem)

    def test_netcup(self):
        self.run_module('netcup', NetcupFake(self), customer='4711', api_key='nk',
                        api_password='np')

    def test_ionos(self):
        self.run_module('ionos', IonosFake(self), prefix='pre', secret='sec')

    def test_scaleway(self):
        self.run_module('scaleway', ScalewayFake(self), secret_key='sk')

    def test_exoscale_signature(self):
        self.run_module('exoscale', ExoscaleFake(self), api_key='EXOk', api_secret='es')
        from acmelib.plugins.challenges.exoscale import exo2_auth
        # a fixed request: the lines signed are exactly these
        msg = 'GET /v2/dns-domain\n\n\n\n1700000600'
        sig = base64.b64encode(hmac.new(b's', msg.encode(), hashlib.sha256).digest()).decode()
        self.assertEqual(exo2_auth('K', 's', 'GET', 'https://api-ch-gva-2.exoscale.com/v2/'
                                   'dns-domain', b'', 1700000600),
                         'EXO2-HMAC-SHA256 credential=K,expires=1700000600,signature=' + sig)

    def test_infoblox(self):
        self.run_module('infoblox', InfobloxFake(self), url='https://gm.example.local',
                        username='ib', password='ipw', view='internal')

    def test_technitium(self):
        self.run_module('technitium', TechnitiumFake(self), url='http://dns.local:5380',
                        token='tt')

    def test_wedos(self):
        f = WedosFake(self)
        self.run_module('wedos', f, login='me@example.cz', wapi_password='wp')
        self.assertEqual(f.commits, 0, 'every change is committed')

    def test_wedos_pages_numbered_rows_and_secondary(self):
        """1.0.21: every page of the domains (a 600-domain account), only primary active
        ones, the rows as row1, row2... too."""
        f = WedosFake(self)
        f.filler, f.numbered = 600, True
        self.run_module('wedos', f, login='me@example.cz', wapi_password='wp')
        m, _ = module('wedos', f, login='me@example.cz', wapi_password='wp')
        zones = m.zone_names()
        self.assertIn('zz599.example.net', zones)
        self.assertIn('example.com', zones)
        self.assertNotIn('sec.example.com', zones)
        self.assertNotIn('off.example.com', zones)

    def test_wedos_refused_sign_in_holds_wapi(self):
        """A refused sign-in (2051...): WAPI is not asked again for a while - more wrong
        requests would block the address (1.0.21)."""
        from acmelib.plugins import limits
        from acmelib.plugins.base import PluginError
        f = WedosFake(self)
        calls = []

        def refuse(method, url, body, h):
            calls.append(1)
            return 200, {'response': {'code': 2051, 'result': 'Access not allowed from this IP'}}
        f.handle = refuse
        m, _ = module('wedos', f, login='me@example.cz', wapi_password='wp')
        try:
            with self.assertRaises(PluginError):
                m._call('ping')
            with self.assertRaises(PluginError) as e:
                m._call('ping')
            self.assertEqual(len(calls), 1, 'not asked again while held')
            self.assertIn('not asked again', str(e.exception))
        finally:
            limits.forget()

    def test_wedos_record_there_already(self):
        """2316 (this record already exists) is the record being there."""
        f = WedosFake(self)
        orig = f.handle

        def there(method, url, body, h):
            r = json.loads(form(body)['request'])['request']
            if r['command'] == 'dns-row-add':
                return 200, {'response': {'code': 2316, 'result': 'Record already exists'}}
            return orig(method, url, body, h)
        f.handle = there
        m, _ = module('wedos', f, login='me@example.cz', wapi_password='wp')
        m.add_txt('_acme-challenge.www.example.com', 'v1')

    def test_wedos_auth_hour_in_prague(self):
        from acmelib.plugins.challenges import wedos as W
        # 2026-07-01 10:30 UTC is 12:30 in Prague (CEST); 2026-01-15 10:30 UTC is 11:30 (CET)
        summer = datetime.datetime(2026, 7, 1, 10, 30, tzinfo=datetime.timezone.utc).timestamp()
        winter = datetime.datetime(2026, 1, 15, 10, 30, tzinfo=datetime.timezone.utc).timestamp()
        self.assertEqual((W.prague_hour(summer), W.prague_hour(winter)), ('12', '11'))
        inner = hashlib.sha1(b'wp').hexdigest()
        self.assertEqual(W.wedos_auth('me@example.cz', 'wp', summer),
                         hashlib.sha1(('me@example.cz' + inner + '12').encode()).hexdigest())

    def test_websupport(self):
        self.run_module('websupport', WebsupportFake(self, 'rest.websupport.sk'),
                        api_key='wkey', api_secret='wsec')
        from acmelib.plugins.challenges.websupport import ws_headers
        h = ws_headers('k', 's', 'GET', '/v1/user/self?x=1', now=1700000000)
        self.assertEqual(h['Date'], '20231114T221320Z')
        sig = hmac.new(b's', b'GET /v1/user/self 1700000000', hashlib.sha1).hexdigest()
        self.assertEqual(h['Authorization'], 'Basic ' + base64.b64encode(
            ('k:' + sig).encode()).decode())

    def test_active24(self):
        f = WebsupportFake(self, 'rest.active24.cz', v2=True)
        m = self.run_module('active24', f, api_key='wkey', api_secret='wsec')
        # a domain not in the list of services, set as the domain: asked for itself
        # (/v1/user/self/zone/...)
        mo, _ = module('active24', f, api_key='wkey', api_secret='wsec', zone='other.org')
        h = mo.present('www.other.org', 't', 'k', 'v9')
        self.assertEqual(f.values('_acme-challenge.www.other.org'), ['v9'])
        mo.cleanup('www.other.org', h)
        self.assertEqual(f.values('_acme-challenge.www.other.org'), [])
        self.assertIn('/v2/check', ' '.join(c[1] for c in f.calls))
        # a service ID alone: its zone read from /v2/service/{id}/dns/zone
        m2, _ = module('active24', f, api_key='wkey', api_secret='wsec', service_id='501')
        self.assertEqual(m2.zone_for(NAME.replace('www.example.com', 'www.dev.example.com')),
                         'dev.example.com')

    def test_active24_com(self):
        self.run_module('active24', Active24ComFake(self), platform='com', token='a24tok')


class TestHeNet(unittest.TestCase):
    def test_one_value_a_name(self):
        state = {}

        def he(method, url, body, h):
            self.assertEqual((method, url), ('POST', 'https://dyn.dns.he.net/nic/update'))
            p = form(body)
            if p['password'] != 'K1':
                return 200, {}, b'badauth'
            old = state.get(p['hostname'])
            state[p['hostname']] = p['txt']
            return 200, {}, ('nochg ' if old == p['txt'] else 'good ').encode() + p['txt'].encode()
        m, ctx = module('he_net', he, keys=NAME + ' K1', zone='example.com')
        self.assertFalse(plugin('he_net').parallel)
        h = m.present('www.example.com', 't', 'k', 'one')
        self.assertEqual(state[NAME], 'one')
        with self.assertRaises(PluginError) as e:          # a second value at that name: later
            m.present('*.www.example.com', 't', 'k', 'two')
        self.assertTrue(e.exception.retry)
        m.cleanup('www.example.com', h)
        self.assertEqual(state[NAME], 'acme-idle')
        h2 = m.present('*.www.example.com', 't', 'k', 'two')
        self.assertEqual(state[NAME], 'two')
        m.cleanup('www.example.com', h)                     # the old one again: left alone
        self.assertEqual(state[NAME], 'two')
        m.cleanup('*.www.example.com', h2)
        with self.assertRaises(PluginError) as e:
            module('he_net', he, keys=NAME + ' WRONG', zone='example.com')[0].present(
                'www.example.com', 't', 'k', 'x')
        self.assertIn('key is wrong', str(e.exception))
        with self.assertRaises(PluginError):
            module('he_net', he, keys='_acme-challenge.other.org K1')[0].present(
                'www.example.com', 't', 'k', 'x')


class TestShared(unittest.TestCase):
    def test_429_gives_up_in_words(self):
        calls = []

        def busy(method, url, body, h):
            calls.append(url)
            return 429, {'Retry-After': '120'}, b'{"detail": "Request was throttled."}'
        del SLEPT[:]
        m, _ = module('desec', busy, token='tok')
        with self.assertRaises(PluginError) as e:
            m.test()
        self.assertEqual(len(calls), C.RETRIES_429 + 1)
        self.assertEqual(SLEPT, [C.WAIT_429_MAX] * C.RETRIES_429)
        self.assertIn('429', str(e.exception))
        self.assertTrue(e.exception.retry)

    def test_retry_after_date(self):
        self.assertEqual(C.retry_after({'Retry-After': 'Wed, 21 Oct 2015 07:28:30 GMT'},
                                       now=1445412500.0), 10.0)
        self.assertEqual(C.retry_after({}), 5.0)

    def test_no_zone_said(self):
        f = DesecFake(unittest.TestCase())
        f.throttled = True
        m, _ = module('desec', f, token='tok')
        with self.assertRaises(PluginError) as e:
            m.present('www.example.net', 't', 'k', 'v')
        self.assertIn('no zone for _acme-challenge.www.example.net', str(e.exception))

    def test_every_new_module_described(self):
        for kind in ('desec', 'gandi', 'linode', 'vultr', 'porkbun', 'namecheap', 'godaddy',
                     'dnsimple', 'ns1', 'bunny', 'cloudns', 'inwx', 'transip', 'netcup', 'ionos',
                     'scaleway', 'exoscale', 'infoblox', 'technitium', 'he_net', 'wedos',
                     'active24', 'websupport'):
            d = plugin(kind).describe()
            self.assertEqual(tuple(d['types'] if 'types' in d else plugin(kind).types), ('dns-01',))
            secrets = [f for f in d['fields'] if f['type'] == 'secret' or f.get('secret')]
            self.assertTrue(secrets, kind)
            for f in d['fields']:
                if f.get('required'):
                    self.assertNotEqual(f['type'], 'bool', (kind, f['key']))
            self.assertTrue(any(f['key'] == 'zone' for f in d['fields']), kind)


if __name__ == '__main__':
    unittest.main(verbosity=2)
