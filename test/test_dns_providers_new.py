#!/usr/bin/env python3
"""The validation modules added with acme 1.0.22, each against a fake of its API.

    python3 test/test_dns_providers_new.py

No internet. As test_dns_providers.py: ctx.http answered by an in-memory
fake of each provider that keeps TXT records the way that provider does
(an RRset written whole, or one record a value) and checks each request -
the address, the method, the credentials or signature, the body - against
what the provider's own SDK or API description sends (named in each
module's docstring and in docs/validation.md). Each DNS module is put
through the same run (the longest zone found, two values at one name,
cleanup taking only its own away, a second cleanup quiet, test() changing
nothing, a 429 waited out).
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import unittest
import urllib.parse
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_challenges import plugin  # noqa: E402
from test_dns_providers import NAME, SLEPT, ZONES, Base, Fake, form, module, q  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402

NEW = ('hostinger', 'constellix', 'ultradns', 'mailinabox', 'efficientip', 'openprovider',
       'easydns', 'plesk', 'rackspace')


def j(body):
    return json.loads(body) if body else {}


def basic_of(h):
    return base64.b64decode(h['Authorization'].split(' ', 1)[1]).decode()


class RRsetFake(Fake):
    """A provider keeping one RRset a name: the values of a name read and written whole."""
    def rrset(self, name):
        return [r['value'] for r in self.recs if r['name'] == name]

    def put_rrset(self, zone, name, values, ttl=60):
        self.drop(lambda r: r['name'] == name)
        for v in values:
            self.add(zone, name, v, ttl)


# ---------------------------------------------------------------------------
class HostingerFake(RRsetFake):
    BASE = 'https://developers.hostinger.com'

    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Bearer htok')
        self.t.assertTrue(url.startswith(self.BASE), url)
        path = url[len(self.BASE):]
        if path == '/api/domains/v1/portfolio':
            return 200, [{'id': i, 'domain': z, 'type': 'domain', 'status': 'active'}
                         for i, z in enumerate(ZONES)]
        self.t.assertTrue(path.startswith('/api/dns/v1/zones/'), path)
        zone = urllib.parse.unquote(path.split('/')[-1])
        if zone not in ZONES:
            return 404, {'message': 'not found'}
        if method == 'GET':
            names = sorted({r['name'] for r in self.recs if r['zone'] == zone})
            return 200, [{'name': self.rel(zone, n) or '@', 'type': 'TXT', 'ttl': 300,
                          'records': [{'content': v, 'is_disabled': False}
                                      for v in self.rrset(n)]} for n in names]
        b = j(body)
        if method == 'PUT':
            for rs in b['zone']:
                self.t.assertEqual(rs['type'], 'TXT')
                name = self.full(zone, rs['name'])
                vals = [r['content'] for r in rs['records']]
                if b['overwrite'] is False:
                    self.t.assertGreaterEqual(rs['ttl'], 60)
                    vals = self.rrset(name) + vals
                self.put_rrset(zone, name, vals)
            return 200, {}
        if method == 'DELETE':
            for f in b['filters']:
                self.t.assertEqual(f['type'], 'TXT')
                name = self.full(zone, f['name'])
                self.drop(lambda r: r['name'] == name)
            return 200, {}


class ConstellixFake(RRsetFake):
    BASE = 'https://api.dns.constellix.com/v1/domains'

    def __init__(self, t):
        RRsetFake.__init__(self, t)
        self.ids = {}                                   # name -> record id

    def handle(self, method, url, body, h):
        key, mac, ms = h['x-cns-security-token'].split(':')
        want = base64.b64encode(hmac.new(b'csec', ms.encode(), hashlib.sha1).digest()).decode()
        self.t.assertEqual((key, mac), ('ckey', want))
        self.t.assertEqual(len(ms), 13)                 # milliseconds
        self.t.assertTrue(url.startswith(self.BASE), url)
        p = url[len(self.BASE):].strip('/').split('/')
        if p == ['']:
            return 200, [{'id': 70 + i, 'name': z} for i, z in enumerate(ZONES)]
        zone = ZONES[int(p[0]) - 70]
        self.t.assertEqual(p[1:3], ['records', 'txt'])
        if method == 'GET':
            out = []
            for name in sorted({r['name'] for r in self.recs if r['zone'] == zone}):
                rid = self.ids.setdefault(name, 900 + len(self.ids))
                out.append({'id': rid, 'name': self.rel(zone, name), 'ttl': 60, 'type': 'TXT',
                            'roundRobin': [{'value': '"%s"' % v, 'disableFlag': False}
                                           for v in self.rrset(name)]})
            return 200, out
        if method == 'DELETE':
            name = [n for n, i in self.ids.items() if str(i) == p[3]][0]
            self.drop(lambda r: r['name'] == name)
            return 200, {'success': 'deleted'}
        b = j(body)
        name = self.full(zone, b['name'])
        vals = []
        for v in b['roundRobin']:
            self.t.assertTrue(v['value'].startswith('"') and v['value'].endswith('"'), v)
            vals.append(v['value'][1:-1])
        if method == 'POST':
            self.t.assertEqual(self.rrset(name), [], 'POST on a name that has a record')
            self.put_rrset(zone, name, vals)
            return 201, [{'id': self.ids.setdefault(name, 900 + len(self.ids))}]
        if method == 'PUT':
            self.t.assertEqual(str(self.ids[name]), p[3])
            self.put_rrset(zone, name, vals)
            return 200, {'success': 'updated'}


class UltraFake(RRsetFake):
    BASE = 'https://api.ultradns.com'

    def __init__(self, t):
        RRsetFake.__init__(self, t)
        self.logins = 0
        self.expire_next = False

    def handle(self, method, url, body, h):
        self.t.assertTrue(url.startswith(self.BASE), url)
        u = urllib.parse.urlsplit(url)
        if u.path == '/v1/authorization/token':
            f = form(body)
            self.t.assertEqual(f, {'grant_type': 'password', 'username': 'uu', 'password': 'up'})
            self.logins += 1
            return 200, {'accessToken': 'AT%d' % self.logins, 'refreshToken': 'RT',
                         'expiresIn': '3600', 'tokenType': 'Bearer'}
        if self.expire_next:
            self.expire_next = False
            return 401, [{'errorCode': 60001, 'errorMessage': 'invalid_grant:token not valid'}]
        self.t.assertEqual(h['Authorization'], 'Bearer AT%d' % self.logins)
        if u.path == '/v3/zones':
            qs = q(url)
            self.t.assertEqual(qs['limit'], '1000')
            if qs.get('cursor') == 'PAGE2':
                return 200, {'zones': [{'properties': {'name': 'other.org.'}}],
                             'cursorInfo': {'previous': 'X'}}
            return 200, {'zones': [{'properties': {'name': z + '.'}} for z in ZONES[:2]],
                         'cursorInfo': {'next': 'PAGE2'}}
        p = u.path.split('/')
        self.t.assertEqual(p[1:3], ['v1', 'zones'])
        zone, typ, owner = p[3], p[5], urllib.parse.unquote(p[6])
        self.t.assertEqual(typ, 'TXT')
        self.t.assertTrue(owner.endswith('.'), 'the owner is written absolute')
        name = owner.rstrip('.')
        have = self.rrset(name)
        if method == 'GET':
            if not have:
                return 404, [{'errorCode': 70002, 'errorMessage': 'Data not found.'}]
            return 200, {'zoneName': zone + '.', 'rrSets': [
                {'ownerName': owner, 'rrtype': 'TXT (16)', 'ttl': 300, 'rdata': have}]}
        if method == 'DELETE':
            self.drop(lambda r: r['name'] == name)
            return 204, b''
        b = j(body)
        if method == 'POST':
            if have:
                return 400, [{'errorCode': 2111, 'errorMessage': 'Resource Record exists'}]
            self.put_rrset(zone, name, b['rdata'])
            return 201, {'message': 'Successful'}
        if method == 'PUT':
            self.put_rrset(zone, name, b['rdata'])
            return 200, {'message': 'Successful'}


class MiabFake(Fake):
    BASE = 'https://box.example.com/admin'

    def handle(self, method, url, body, h):
        self.t.assertEqual(basic_of(h), 'admin@example.com:mp')
        self.t.assertTrue(url.startswith(self.BASE), url)
        path = url[len(self.BASE):]
        if path == '/dns/zones':
            return 200, ZONES
        p = path.split('/')
        self.t.assertEqual(p[1:3], ['dns', 'custom'])
        self.t.assertEqual(p[4], 'TXT')
        name = urllib.parse.unquote(p[3])
        zone = max((z for z in ZONES if name == z or name.endswith('.' + z)), key=len)
        if method == 'GET':
            return 200, [{'qname': r['name'], 'rtype': 'TXT', 'value': r['value'],
                          'sort-order': {}, 'zone': zone} for r in self.recs
                         if r['name'] == name]
        self.t.assertEqual(h['Content-Type'], 'text/plain')
        value = body.decode('ascii')
        if method == 'POST':
            self.add(zone, name, value)
            return 200, 'updated DNS: %s' % zone
        if method == 'DELETE':
            self.t.assertTrue(value, 'a DELETE without a value removes every value')
            self.drop(lambda r: r['name'] == name and r['value'] == value)
            return 200, 'updated DNS: %s' % zone


class SdsFake(Fake):
    BASE = 'https://sds.example.local/api/v2.0'

    def where(self, url):
        w = q(url).get('where', '')
        out = {}
        for part in w.split(' AND '):
            k, v = part.split('=', 1)
            self.t.assertTrue(v.startswith("'") and v.endswith("'"), part)
            out[k] = v[1:-1].replace("''", "'")
        return out

    def handle(self, method, url, body, h):
        self.t.assertEqual(basic_of(h), 'sdsuser:sp')
        self.t.assertTrue(url.startswith(self.BASE), url)
        path = urllib.parse.urlsplit(url).path[len('/api/v2.0'):]
        if path == '/dns/zone/list':
            self.t.assertEqual(self.where(url), {'server_name': 'smart.local'})
            return 200, {'success': True, 'data': [
                {'zone_id': str(i), 'zone_name': z, 'zone_type': 'master',
                 'zone_is_reverse': '0', 'server_name': 'smart.local'}
                for i, z in enumerate(ZONES)] + [
                {'zone_name': '1.168.192.in-addr.arpa', 'zone_is_reverse': '1'}]}
        if path == '/dns/rr/list':
            w = self.where(url)
            self.t.assertEqual((w['rr_type'], w['server_name']), ('TXT', 'smart.local'))
            rows = [{'rr_id': str(r['id']), 'rr_full_name': r['name'], 'rr_type': 'TXT',
                     'rr_value1': r['value'], 'server_name': 'smart.local'}
                    for r in self.recs if r['name'] == w['rr_full_name']]
            return (200, {'success': True, 'data': rows}) if rows else (204, b'')
        if path == '/dns/rr/add':
            b = j(body)
            self.t.assertEqual((b['server_name'], b['rr_type']), ('smart.local', 'TXT'))
            zone = max((z for z in ZONES if b['rr_name'].endswith('.' + z)), key=len)
            rid = self.add(zone, b['rr_name'], b['rr_value1'], b['rr_ttl'])
            return 201, {'success': True, 'data': [{'rr_id': str(rid)}]}
        if path == '/dns/rr/delete':
            self.t.assertEqual(method, 'DELETE')
            rid = q(url)['rr_id']
            if not self.drop(lambda r: str(r['id']) == rid):
                return 400, {'success': False, 'messages': [{'message': 'not found'}]}
            return 200, {'success': True, 'data': [{'rr_id': rid}]}


class OpenproviderFake(Fake):
    BASE = 'https://api.openprovider.eu/v1beta'

    def __init__(self, t):
        Fake.__init__(self, t)
        self.logins = 0

    def handle(self, method, url, body, h):
        self.t.assertTrue(url.startswith(self.BASE), url)
        path = urllib.parse.urlsplit(url).path[len('/v1beta'):]
        if path == '/auth/login':
            self.t.assertEqual(j(body), {'username': 'opu', 'password': 'opp'})
            self.logins += 1
            return 200, {'code': 0, 'data': {'token': 'OT%d' % self.logins, 'reseller_id': 9}}
        self.t.assertEqual(h['Authorization'], 'Bearer OT%d' % self.logins)
        qs = q(url)
        if path == '/dns/zones':
            if qs['offset'] == '0':
                return 200, {'code': 0, 'data': {'results': [{'id': 1, 'name': ZONES[0]},
                                                             {'id': 2, 'name': ZONES[1]}],
                                                 'total': 3}}
            return 200, {'code': 0, 'data': {'results': [{'id': 3, 'name': ZONES[2]}],
                                             'total': 3}}
        p = path.split('/')
        zone = p[3]
        if method == 'GET':
            self.t.assertEqual((p[4:], qs['type']), (['records'], 'TXT'))
            rows = [{'name': r['name'], 'type': 'TXT', 'value': r['value'], 'ttl': r['ttl']}
                    for r in self.recs if r['zone'] == zone]
            return 200, {'code': 0, 'data': {'results': rows, 'total': len(rows)}}
        self.t.assertEqual(method, 'PUT')
        b = j(body)
        self.t.assertEqual((b['name'], b['provider']), (zone, 'openprovider'))
        for r in b['records'].get('add') or []:
            self.t.assertFalse(r['name'].endswith(zone), 'written relative')
            self.add(zone, self.full(zone, r['name']), r['value'], r['ttl'])
        for r in b['records'].get('remove') or []:
            self.t.assertFalse(r['name'].endswith(zone), 'written relative')
            name = self.full(zone, r['name'])
            self.drop(lambda x: x['name'] == name and x['value'] == r['value'])
        return 200, {'code': 0, 'data': {'success': True}}


class EasyFake(Fake):
    BASE = 'https://rest.easydns.net'

    def handle(self, method, url, body, h):
        self.t.assertEqual(basic_of(h), 'etok:ekey')
        u = urllib.parse.urlsplit(url)
        self.t.assertEqual(u.scheme + '://' + u.netloc, self.BASE)
        self.t.assertEqual(q(url), {'format': 'json'})
        p = u.path.strip('/').split('/')
        if p[:2] == ['domains', 'list']:
            return 200, {'data': [{'id': 1, 'name': z} for z in ZONES]}
        if method == 'GET':
            self.t.assertEqual(p[:3], ['zones', 'records', 'all'])
            zone = p[3]
            return 200, {'msg': 'OK', 'status': 200, 'data': [
                {'id': str(r['id']), 'domain': zone, 'host': self.rel(zone, r['name']) or '@',
                 'ttl': str(r['ttl']), 'prio': '0', 'type': 'TXT', 'rdata': r['value']}
                for r in self.recs if r['zone'] == zone]}
        if method == 'PUT':
            self.t.assertEqual(p[:3] + p[4:], ['zones', 'records', 'add', 'TXT'])
            b = j(body)
            self.t.assertEqual((b['domain'], b['type']), (p[3], 'TXT'))
            self.t.assertTrue(300 <= b['ttl'] <= 86400)
            rid = self.add(p[3], self.full(p[3], b['host']), b['rdata'], b['ttl'])
            return 201, {'msg': 'OK', 'status': 201, 'data': {'id': str(rid)}}
        if method == 'DELETE':
            self.t.assertEqual(p[:2], ['zones', 'records'])
            if not self.drop(lambda r: str(r['id']) == p[3]):
                return 404, {'error': {'code': 404, 'message': 'No such record'}}
            return 200, {'msg': 'OK', 'status': 200}


class PleskFake(Fake):
    URL = 'https://plesk.example.com:8443/enterprise/control/agent.php'

    def reply(self, op, cmd, inner):
        return 200, ('<?xml version="1.0" encoding="UTF-8"?><packet version="1.6.9.1"><%s><%s>%s'
                     '</%s></%s></packet>' % (op, cmd, inner, cmd, op))

    def handle(self, method, url, body, h):
        self.t.assertEqual((method, url), ('POST', self.URL))
        self.t.assertEqual(h['Content-Type'], 'text/xml')
        if h.get('KEY'):
            self.t.assertEqual(h['KEY'], 'sk-1')
        else:
            self.t.assertEqual((h['HTTP_AUTH_LOGIN'], h['HTTP_AUTH_PASSWD']), ('admin', 'pp'))
        x = ET.fromstring(body)
        op = x[0]
        cmd = op[0]
        if op.tag == 'site':
            self.t.assertEqual(cmd.tag, 'get')
            self.t.assertIsNotNone(cmd.find('dataset/gen_info'))
            want = cmd.findtext('filter/name')
            out = ''.join('<result><status>ok</status><id>%d</id><data><gen_info><name>%s</name>'
                          '<ascii-name>%s</ascii-name></gen_info></data></result>'
                          % (20 + i, z, z) for i, z in enumerate(ZONES)
                          if want in (None, z))
            if want and not out:
                out = ('<result><status>error</status><errcode>1013</errcode><errtext>Site does '
                       'not exist</errtext></result>')
            return self.reply('site', 'get', out)
        self.t.assertEqual(op.tag, 'dns')
        if cmd.tag == 'get_rec':
            zone = ZONES[int(cmd.findtext('filter/site-id')) - 20]
            return self.reply('dns', 'get_rec', ''.join(
                '<result><status>ok</status><id>%d</id><data><site-id>1</site-id><type>TXT</type>'
                '<host>%s.</host><value>%s</value><opt></opt></data></result>'
                % (r['id'], r['name'], r['value']) for r in self.recs if r['zone'] == zone))
        if cmd.tag == 'add_rec':
            zone = ZONES[int(cmd.findtext('site-id')) - 20]
            self.t.assertEqual(cmd.findtext('type'), 'TXT')
            host = cmd.findtext('host') or ''
            self.t.assertFalse(host.endswith(zone), 'written relative')
            rid = self.add(zone, self.full(zone, host), cmd.findtext('value'))
            return self.reply('dns', 'add_rec', '<result><status>ok</status><id>%d</id></result>'
                              % rid)
        if cmd.tag == 'del_rec':
            rid = cmd.findtext('filter/id')
            if not self.drop(lambda r: str(r['id']) == rid):
                return self.reply('dns', 'del_rec', '<result><status>error</status><errcode>1013'
                                  '</errcode><errtext>Record does not exist</errtext></result>')
            return self.reply('dns', 'del_rec', '<result><status>ok</status><id>%s</id></result>'
                              % rid)


class RackspaceFake(Fake):
    ID = 'https://identity.api.rackspacecloud.com/v2.0/tokens'
    DNS = 'https://dns.api.rackspacecloud.com/v1.0/123456'

    def __init__(self, t):
        Fake.__init__(self, t)
        self.jobs = {}
        self.logins = 0

    def job(self, response=None, error=None):
        jid = 'job-%d' % (len(self.jobs) + 1)
        done = {'status': 'ERROR', 'error': error} if error else {
            'status': 'COMPLETED', 'response': response or {}}
        self.jobs[jid] = [{'status': 'RUNNING', 'callbackUrl': self.DNS + '/status/' + jid,
                           'jobId': jid}, dict(done, callbackUrl=self.DNS + '/status/' + jid)]
        return 202, {'status': 'INITIALIZED', 'callbackUrl': self.DNS + '/status/' + jid,
                     'jobId': jid}

    def handle(self, method, url, body, h):
        if url == self.ID:
            self.t.assertEqual(j(body), {'auth': {'RAX-KSKEY:apiKeyCredentials': {
                'username': 'rsu', 'apiKey': 'rsk'}}})
            self.logins += 1
            return 200, {'access': {
                'token': {'id': 'RT%d' % self.logins, 'expires': '2099-01-01T00:00:00.000Z',
                          'tenant': {'id': '123456', 'name': '123456'}},
                'serviceCatalog': [
                    {'name': 'cloudServersOpenStack', 'type': 'compute',
                     'endpoints': [{'publicURL': 'https://x.example/v2'}]},
                    {'name': 'cloudDNS', 'type': 'rax:dns',
                     'endpoints': [{'publicURL': self.DNS, 'tenantId': '123456'}]}]}}
        self.t.assertEqual(h['X-Auth-Token'], 'RT%d' % self.logins)
        self.t.assertTrue(url.startswith(self.DNS), url)
        u = urllib.parse.urlsplit(url)
        p = u.path[len('/v1.0/123456/'):].split('/')
        qs = q(url)
        if p[0] == 'status':
            self.t.assertEqual(qs, {'showDetails': 'true'})
            return 200, self.jobs[p[1]].pop(0)
        if p == ['domains']:
            if 'name' in qs:
                return 200, {'domains': [{'id': 50 + ZONES.index(qs['name']),
                                          'name': qs['name']}] if qs['name'] in ZONES else [],
                             'totalEntries': 1}
            off = int(qs['offset'])
            rows = [{'id': 50 + i, 'name': z} for i, z in enumerate(ZONES)][off:off + 2]
            return 200, {'domains': rows, 'totalEntries': len(ZONES)}
        zone = ZONES[int(p[1]) - 50]
        if method == 'GET':
            self.t.assertEqual(qs['type'], 'TXT')
            return 200, {'records': [{'id': 'TXT-%d' % r['id'], 'name': r['name'],
                                      'type': 'TXT', 'data': r['value'], 'ttl': r['ttl']}
                                     for r in self.recs if r['zone'] == zone and
                                     r['name'] == qs['name']]}
        if method == 'POST':
            (rec,) = j(body)['records']
            self.t.assertGreaterEqual(rec['ttl'], 300)
            rid = self.add(zone, rec['name'], rec['data'], rec['ttl'])
            return self.job({'records': [{'id': 'TXT-%d' % rid, 'name': rec['name']}]})
        if method == 'DELETE':
            rid = p[3].split('-')[1]
            if not self.drop(lambda r: str(r['id']) == rid):
                return 404, {'code': 404, 'message': 'Not found'}
            return self.job()


# ---------------------------------------------------------------------------
class TestNewProviders(Base):
    def test_hostinger(self):
        self.run_module('hostinger', HostingerFake(self), token='htok')

    def test_hostinger_domain_not_in_portfolio(self):
        f = HostingerFake(self)
        f.throttled = True
        real = f.handle

        def only_one(method, url, body, h):
            if url.endswith('/portfolio'):
                return 200, [{'domain': 'example.com'}]
            return real(method, url, body, h)
        f.handle = only_one
        m, _ = module('hostinger', f, token='htok')
        self.assertEqual(m.zone_for('_acme-challenge.x.other.org'), 'other.org')

    def test_constellix(self):
        self.run_module('constellix', ConstellixFake(self), api_key='ckey', secret_key='csec')

    def test_constellix_token(self):
        from acmelib.plugins.challenges.constellix import cns_token
        mac = base64.b64encode(hmac.new(b's', b'1700000000123', hashlib.sha1).digest()).decode()
        self.assertEqual(cns_token('k', 's', 1700000000123), 'k:%s:1700000000123' % mac)

    def test_ultradns(self):
        f = UltraFake(self)
        self.run_module('ultradns', f, user='uu', password='up')
        self.assertEqual(f.logins, 2, 'one sign-in per run (the module of test() is new)')

    def test_ultradns_signs_in_again_on_401(self):
        f = UltraFake(self)
        f.throttled = True
        m, _ = module('ultradns', f, user='uu', password='up', zone='example.com')
        m.present('www.example.com', 't', 'k', 'v1')
        f.expire_next = True
        m.present('www.example.com', 't', 'k', 'v2')
        self.assertEqual((f.values(), f.logins), (['v1', 'v2'], 2))

    def test_mailinabox(self):
        self.run_module('mailinabox', MiabFake(self), host='box.example.com',
                        user='admin@example.com', password='mp')

    def test_mailinabox_address_forms(self):
        for host in ('https://box.example.com', 'https://box.example.com/admin/',
                     'box.example.com/'):
            m, _ = module('mailinabox', MiabFake(self), host=host, user='a', password='b')
            self.assertEqual(m._base(), 'https://box.example.com/admin')

    def test_efficientip(self):
        self.run_module('efficientip', SdsFake(self), host='sds.example.local', user='sdsuser',
                        password='sp', server='smart.local')

    def test_efficientip_where_quoted(self):
        from acmelib.plugins.challenges.efficientip import _sql
        self.assertEqual(_sql("a'b"), "'a''b'")

    def test_openprovider(self):
        f = OpenproviderFake(self)
        self.run_module('openprovider', f, user='opu', password='opp')
        self.assertEqual(f.logins, 2)

    def test_easydns(self):
        del SLEPT[:]
        f = EasyFake(self)
        m, ctx = module('easydns', f, token='etok', key='ekey', zone='example.com')
        self.assertEqual(m.zone_for(NAME), 'example.com')
        f.add('example.com', NAME, 'someone-elses')
        h1 = m.present('www.example.com', 't', 'k', 'one')
        h2 = m.present('*.www.example.com', 't', 'k', 'two')
        m.present('www.example.com', 't', 'k', 'one')
        self.assertEqual(f.values(), ['one', 'someone-elses', 'two'])
        self.assertTrue(SLEPT and SLEPT[0] == 2.0)
        m.cleanup('www.example.com', h1)
        m.cleanup('www.example.com', h1)
        m.cleanup('*.www.example.com', h2)
        self.assertEqual(f.values(), ['someone-elses'])
        self.assertEqual([r['ttl'] for r in f.recs], [60])
        n = f.changes
        self.assertIn('the domain example.com has 1 record', m.test())
        m2, _ = module('easydns', f, token='etok', key='ekey', user='me')
        self.assertIn('signed in as me', m2.test())
        m3, _ = module('easydns', f, token='etok', key='ekey')
        with self.assertRaises(PluginError):
            m3.test()
        self.assertEqual(f.changes, n)

    def test_easydns_sandbox(self):
        f = EasyFake(self)
        f.BASE = 'https://sandbox.rest.easydns.net'
        f.throttled = True
        m, _ = module('easydns', f, token='etok', key='ekey', zone='example.com',
                      endpoint='sandbox', ttl=30)
        m.present('www.example.com', 't', 'k', 'sb')
        self.assertEqual([r['ttl'] for r in f.recs], [300], 'raised to what easyDNS takes')

    def test_plesk(self):
        self.run_module('plesk', PleskFake(self), host='plesk.example.com', user='admin',
                        password='pp')

    def test_plesk_secret_key_and_address(self):
        f = PleskFake(self)
        f.throttled = True
        m, _ = module('plesk', f, host='https://plesk.example.com', auth='key',
                      secret_key='sk-1', zone='example.com')
        m.present('www.example.com', 't', 'k', 'kv')
        self.assertEqual(f.values(), ['kv'])
        for host, url in (('plesk.example.com:8880', 'https://plesk.example.com:8880'),
                          ('http://10.0.0.5:8880/', 'http://10.0.0.5:8880')):
            m, _ = module('plesk', f, host=host, user='a', password='b')
            self.assertEqual(m._url(), url + '/enterprise/control/agent.php')
        m, _ = module('plesk', f, host='plesk.example.com', user='admin', password='pp',
                      zone='example.net')
        with self.assertRaises(PluginError) as e:
            m.present('www.example.net', 't', 'k', 'x')
        self.assertIn('Site does not exist', str(e.exception))

    def test_rackspace(self):
        f = RackspaceFake(self)
        self.run_module('rackspace', f, user='rsu', api_key='rsk')
        self.assertEqual(f.logins, 2)
        self.assertTrue(all(not v for v in f.jobs.values()), 'every job followed to its end')

    def test_rackspace_job_error_said(self):
        f = RackspaceFake(self)
        f.throttled = True
        real = f.handle

        def refuse(method, url, body, h):
            if method == 'POST' and url.endswith('/records'):
                return f.job(error={'failedItems': {'faults': [
                    {'code': 400, 'details': 'Record is a duplicate of another record.'}]}})
            return real(method, url, body, h)
        f.handle = refuse
        m, _ = module('rackspace', f, user='rsu', api_key='rsk', zone='example.com')
        with self.assertRaises(PluginError) as e:
            m.present('www.example.com', 't', 'k', 'v')
        self.assertIn('duplicate of another record', str(e.exception))


class TestNewDescribed(unittest.TestCase):
    def test_every_new_module_described(self):
        for kind in NEW:
            cls = plugin(kind)
            d = cls.describe()
            self.assertEqual(cls.types, ('dns-01',), kind)
            self.assertTrue(d['title'] and d['description'], kind)
            self.assertTrue([f for f in d['fields'] if f['type'] == 'secret'], kind)
            keys = [f['key'] for f in d['fields']]
            self.assertEqual(len(keys), len(set(keys)), kind)
            self.assertIn('zone', keys, kind)
            self.assertIn('Sources', sys.modules[cls.__module__].__doc__, kind)
            self.assertIn('https://', sys.modules[cls.__module__].__doc__, kind)

    def test_every_word_has_czech(self):
        from acmelib.plugins.base import Registry
        with open(os.path.join(os.path.dirname(HERE), 'web', 'lang', 'cs.json'),
                  encoding='utf-8') as fh:
            cs = json.load(fh)
        sources = {v['source'] for v in cs['strings'].values()}
        reg = Registry(extra_dirs=[]).reload()

        def words_of(d):
            out = [d['title'], d['description']]
            for f in d['fields']:
                out += [f['label'], f.get('help', '')]
                out += [o[1] for o in f.get('options') or []]
            return [w for w in out if w]
        missing = sorted({w for k in NEW for w in words_of(reg.get('challenge', k).describe())
                          if w not in sources})
        self.assertEqual(missing, [], 'web/lang/cs.json lacks these')

    def test_documented(self):
        with open(os.path.join(os.path.dirname(HERE), 'docs', 'validation.md'),
                  encoding='utf-8') as fh:
            doc = fh.read()
        for kind in NEW:
            self.assertIn('(`%s`)' % kind, doc, kind)
            self.assertIn('| `%s` |' % kind, doc, kind)


if __name__ == '__main__':
    unittest.main(verbosity=2)
