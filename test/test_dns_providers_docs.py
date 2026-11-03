#!/usr/bin/env python3
"""The validation modules of 1.0.26 written from the vendors' own documentation
(the user's collection, named in each module's docstring and in
docs/validation.md): cPanel, Joker.com, Netim, Huawei Cloud DNS, DirectAdmin.

    python3 test/test_dns_providers_docs.py

No internet. As test_dns_providers.py: ctx.http is answered by an in-memory
fake of each provider that keeps TXT records the way that provider does (a
zone file with line indexes and a serial, a whole zone written back, one
record a value, an RRset written whole) and checks each request against what
the documentation says - the address, the method, the credentials or the
signature, the body. Each module goes through the same run (the longest zone
found, two values at one name, cleanup taking only its own away, a second
cleanup quiet, test() changing nothing, a 429 waited out), and then through
what is its own.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import unittest
import urllib.parse
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_challenges import plugin  # noqa: E402
from test_dns_providers import NAME, SLEPT, ZONES, Base, Fake, form, module, q  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.challenges import _dns as D  # noqa: E402

DOCS = ('cpanel', 'joker', 'netim', 'huawei_dns', 'directadmin')


def j(body):
    return json.loads(body) if body else {}


def b64(s):
    return base64.b64encode(s.encode()).decode()


# ---------------------------------------------------------------------------
class CpanelFake(Fake):
    BASE = 'https://cpanel.example.com:2083/execute/'

    def __init__(self, t):
        Fake.__init__(self, t)
        self.serial = {z: 2026110300 for z in ZONES}
        self.bump_once = False                  # someone else changes the zone first

    def ok(self, data):
        return 200, {'apiversion': 3, 'module': 'DNS', 'func': 'x',
                     'result': {'status': 1, 'errors': None, 'data': data}}

    def no(self, words):
        return 200, {'apiversion': 3, 'result': {'status': 0, 'errors': [words], 'data': None}}

    def lines(self, zone):
        return [r for r in self.recs if r['zone'] == zone]

    def handle(self, method, url, body, h):
        self.t.assertEqual(method, 'GET')
        self.t.assertEqual(h['Authorization'], 'cpanel cpu:ctok')
        self.t.assertTrue(url.startswith(self.BASE), url)
        u = urllib.parse.urlsplit(url)
        func = u.path[len('/execute/'):]
        qs = urllib.parse.parse_qs(u.query)
        if func == 'DomainInfo/list_domains':
            return self.ok({'main_domain': 'example.com', 'addon_domains': ['other.org'],
                            'parked_domains': [], 'sub_domains': ['dev.example.com',
                                                                  'www.example.com']})
        zone = qs['zone'][0]
        if zone not in ZONES:
            return self.no('You do not have a zone named “%s”.' % zone)
        if func == 'DNS/parse_zone':
            soa = ['ns1.example.com.', 'hostmaster.example.com.', str(self.serial[zone]),
                   '3600', '1800', '1209600', '86400']
            out = [{'type': 'comment', 'line_index': 0, 'text_b64': b64('; cPanel zone')},
                   {'type': 'record', 'line_index': 1, 'dname_b64': b64(zone + '.'),
                    'record_type': 'SOA', 'ttl': 86400, 'data_b64': [b64(x) for x in soa]},
                   {'type': 'record', 'line_index': 2, 'dname_b64': b64('www'),
                    'record_type': 'TXT', 'ttl': 300, 'data_b64': [b64('two'), b64('parts')]}]
            for i, r in enumerate(self.lines(zone)):
                rel = self.rel(zone, r['name'])
                owner = rel if i % 2 else r['name'] + '.'       # relative and whole, both
                out.append({'type': 'record', 'line_index': 3 + i, 'dname_b64': b64(owner),
                            'record_type': 'TXT', 'ttl': r['ttl'],
                            'data_b64': [b64(r['value'])]})
            return self.ok(out)
        self.t.assertEqual(func, 'DNS/mass_edit_zone')
        if self.bump_once:
            self.bump_once = False
            self.serial[zone] += 1
        if int(qs['serial'][0]) != self.serial[zone]:
            return self.no('The given serial number (%s) does not match the DNS zone’s '
                           'serial number (%d).' % (qs['serial'][0], self.serial[zone]))
        mine = self.lines(zone)
        gone = {mine[int(i) - 3]['id'] for i in qs.get('remove', [])}
        self.t.assertTrue(all(int(i) >= 3 for i in qs.get('remove', [])), 'only TXT lines')
        self.drop(lambda r: r['id'] in gone)
        for a in qs.get('add', []):
            rec = json.loads(a)
            self.t.assertEqual(rec['record_type'], 'TXT')
            self.t.assertFalse(rec['dname'].endswith('.'), 'written relative')
            (value,) = rec['data']
            self.add(zone, self.full(zone, rec['dname']), value, rec['ttl'])
        self.serial[zone] += 1
        return self.ok({'new_serial': self.serial[zone]})


class JokerFake(Fake):
    BASE = 'https://dmapi.joker.com/request/'
    KEPT = ['# made by hand', '@ A 0 192.0.2.1 86400', 'www CNAME 0 example.com. 86400',
            '$dyndns=no']

    def __init__(self, t):
        Fake.__init__(self, t)
        self.sid = None
        self.logins = 0
        self.puts = 0

    def say(self, head, body=''):
        return 200, '\n'.join(head) + '\n\n' + body

    def zone_text(self, zone):
        return '\n'.join(self.KEPT + ['%s TXT 0 "%s" %d' % (self.rel(zone, r['name']) or '@',
                                                            r['value'], r['ttl'])
                                      for r in self.recs if r['zone'] == zone]) + '\n'

    def handle(self, method, url, body, h):
        self.t.assertEqual(method, 'POST')
        self.t.assertTrue(url.startswith(self.BASE), url)
        name = url[len(self.BASE):]
        f = form(body)
        if name == 'login':
            self.t.assertEqual(f, {'api-key': 'jkey'})
            self.logins += 1
            self.sid = 'SID%d' % self.logins
            return self.say(['Auth-SID: %s' % self.sid, 'UID: 4711', 'Tracking-Id: 1'],
                            'com\nnet\norg\n')
        if f.get('auth-sid') != self.sid:
            return self.say(['Status-Code: 2200', 'Status-Text: Authorization error',
                             'Error: Authorization error', 'Result: NACK'])
        if name == 'dns-zone-list':
            return self.say(['Status-Code: 0'], '\n'.join(ZONES) + '\n')
        zone = f['domain']
        if zone not in ZONES:
            return self.say(['Status-Code: 2303', 'Error: Object does not exist'])
        if name == 'dns-zone-get':
            return self.say(['Status-Code: 0', 'Status-Text: OK'], self.zone_text(zone))
        self.t.assertEqual(name, 'dns-zone-put')
        lines = [ln for ln in f['zone'].split('\n') if ln.strip()]
        self.t.assertEqual([ln for ln in lines if ' TXT ' not in ln], self.KEPT,
                           'every other line written back as it was read')
        self.puts += 1
        self.drop(lambda r: r['zone'] == zone)
        for ln in lines:
            if ' TXT ' in ln:
                label, typ, pri, target, ttl = ln.split()
                self.t.assertEqual((typ, pri), ('TXT', '0'))
                self.t.assertTrue(target.startswith('"') and target.endswith('"'), ln)
                self.add(zone, self.full(zone, label), target[1:-1], int(ttl))
        return self.say(['Status-Code: 0', 'Status-Text: OK', 'Proc-ID: 42'])


class NetimFake(Fake):
    BASE = 'https://rest.netim.com/1.0'

    def __init__(self, t):
        Fake.__init__(self, t)
        self.open = set()
        self.opened = 0
        self.ops = {}

    def op(self, done):
        n = 1000 + len(self.ops)
        self.ops[n] = 'Done' if done else 'Pending'
        return {'ID_OPE': n, 'STATUS': self.ops[n], 'MESSAGE': '', 'TYPE': 'domainZone',
                'DATE': '2026-11-03'}

    def handle(self, method, url, body, h):
        self.t.assertTrue(url.startswith(self.BASE), url)
        path = url[len(self.BASE):]
        if path == '/session/' and method == 'POST':
            self.t.assertEqual(base64.b64decode(h['Authorization'].split(' ', 1)[1]).decode(),
                               'NET1234:npw')
            self.t.assertEqual(h['Content-Type'], 'application/json')
            self.opened += 1
            tok = 'nt%d' % self.opened
            self.open.add(tok)
            return 200, {'access_token': tok}
        tok = h['Authorization'].split(' ', 1)[1]
        self.t.assertTrue(h['Authorization'].startswith('Bearer '))
        if tok not in self.open:
            return 401, {'message': 'Unauthorized'}
        if path == '/session/':
            self.t.assertEqual(method, 'DELETE')
            self.open.discard(tok)
            return 200, ''
        if path == '/domains/*':
            return 200, [{'domain': z, 'dateCreate': '2020-01-01',
                          'dateExpiration': '2030-01-01'} for z in ZONES]
        if path.startswith('/operation/'):
            n = int(path.split('/')[-1])
            self.ops[n] = 'Done'
            return 200, {'ID_OPE': n, 'STATUS': 'Done'}
        self.t.assertTrue(path.startswith('/domain/') and path.endswith('/zone/'), path)
        zone = urllib.parse.unquote(path.split('/')[2])
        if zone not in ZONES:
            return 400, {'message': 'Domain not found'}
        if method == 'GET':
            rows = [{'hostname': '', 'type': 'A', 'value': '192.0.2.1', 'options': {}}]
            rows += [{'hostname': self.rel(zone, r['name']), 'type': 'TXT', 'value': r['value'],
                      'options': {'ttl': r['ttl']}} for r in self.recs if r['zone'] == zone]
            return 200, rows
        b = j(body)
        self.t.assertEqual(b['type'], 'TXT')
        self.t.assertFalse(b['subdomain'].endswith(zone), 'relative')
        name = self.full(zone, b['subdomain'])
        if method == 'POST':
            self.t.assertEqual(set(b), {'subdomain', 'type', 'value', 'options'})
            self.add(zone, name, b['value'], b['options']['ttl'])
            return 200, self.op(done=len(self.ops) % 2 == 1)
        self.t.assertEqual(method, 'DELETE')
        self.t.assertEqual(set(b), {'subdomain', 'type', 'value'})
        if not self.drop(lambda r: r['name'] == name and r['value'] == b['value']):
            return 400, {'message': 'Record not found'}
        return 200, self.op(done=True)


def huawei_canonical(method, url, headers, signed, body):
    """The signing algorithm again, written apart from the module's."""
    u = urllib.parse.urlsplit(url)
    path = u.path if u.path.endswith('/') else u.path + '/'
    qs = sorted(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    query = '&'.join('%s=%s' % (urllib.parse.quote(k, safe='~'), urllib.parse.quote(v, safe='~'))
                     for k, v in qs)
    low = {k.lower(): str(v).strip() for k, v in headers.items()}
    names = signed.split(';')
    ch = ''.join('%s:%s\n' % (n, low[n]) for n in names)
    return '\n'.join([method, path, query, ch, signed, hashlib.sha256(body or b'').hexdigest()])


class HuaweiFake(Fake):
    BASE = 'https://dns.ap-southeast-1.myhuaweicloud.com'

    def __init__(self, t):
        Fake.__init__(self, t)
        self.unsteady = 0                       # so many changes answered DNS.0314
        self.ids = {}

    def check_sign(self, method, url, body, h):
        auth = h['Authorization']
        self.t.assertTrue(auth.startswith('SDK-HMAC-SHA256 Access=hak, SignedHeaders='), auth)
        signed = auth.split('SignedHeaders=')[1].split(',')[0]
        sig = auth.split('Signature=')[1]
        for must in ('host', 'x-sdk-date'):
            self.t.assertIn(must, signed.split(';'))
        if body:
            self.t.assertIn('content-type', signed.split(';'))
        self.t.assertEqual(h['Host'], 'dns.ap-southeast-1.myhuaweicloud.com')
        self.t.assertRegex(h['X-Sdk-Date'], r'^\d{8}T\d{6}Z$')
        creq = huawei_canonical(method, url, h, signed, body)
        sts = 'SDK-HMAC-SHA256\n%s\n%s' % (h['X-Sdk-Date'],
                                            hashlib.sha256(creq.encode()).hexdigest())
        self.t.assertEqual(sig, hmac.new(b'hsk', sts.encode(), hashlib.sha256).hexdigest())

    def rrset(self, name):
        return [r['value'] for r in self.recs if r['name'] == name]

    def handle(self, method, url, body, h):
        self.check_sign(method, url, body, h)
        self.t.assertTrue(url.startswith(self.BASE), url)
        u = urllib.parse.urlsplit(url)
        p = u.path.strip('/').split('/')
        qs = q(url)
        if p == ['v2', 'zones']:
            self.t.assertEqual(qs['type'], 'public')
            rows = [{'id': 'z%d' % i, 'name': z + '.'} for i, z in enumerate(ZONES)]
            if 'name' in qs:
                self.t.assertEqual(qs['search_mode'], 'equal')
                rows = [r for r in rows if r['name'] == qs['name']]
                return 200, {'zones': rows, 'links': {}, 'metadata': {'total_count': len(rows)}}
            start = [r['id'] for r in rows].index(qs['marker']) + 1 if 'marker' in qs else 0
            page = rows[start:start + 2]
            links = {'self': url}
            if start + 2 < len(rows):
                links['next'] = self.BASE + '/v2/zones?type=public&limit=500&marker=' + \
                    page[-1]['id']
            return 200, {'zones': page, 'links': links, 'metadata': {'total_count': len(rows)}}
        zone = ZONES[int(p[2][1:])]
        self.t.assertEqual(p[3], 'recordsets')
        if method == 'GET':
            self.t.assertEqual((qs['type'], qs['search_mode']), ('TXT', 'equal'))
            name = qs['name'].rstrip('.')
            vals = self.rrset(name) if D.in_zone(name, zone) else []
            sets = [{'id': self.ids.setdefault(name, 'rs-%d' % len(self.ids)), 'name': name + '.',
                     'type': 'TXT', 'ttl': 300, 'status': 'ACTIVE',
                     'records': ['"%s"' % v for v in vals]}] if vals else []
            return 200, {'recordsets': sets, 'links': {}, 'metadata': {'total_count': len(sets)}}
        if self.unsteady:
            self.unsteady -= 1
            return 400, {'code': 'DNS.0314', 'message': 'The record set is not in a steady state.'}
        if method == 'DELETE':
            name = [n for n, i in self.ids.items() if i == p[4]][0]
            self.drop(lambda r: r['name'] == name)
            return 202, {'id': p[4], 'status': 'PENDING_DELETE'}
        b = j(body)
        self.t.assertEqual(b['type'], 'TXT')
        self.t.assertTrue(b['name'].endswith(zone + '.'), 'whole, with its final dot')
        name = b['name'].rstrip('.')
        vals = []
        for v in b['records']:
            self.t.assertTrue(v.startswith('"') and v.endswith('"'), v)
            vals.append(v[1:-1])
        if method == 'POST':
            if self.rrset(name):
                return 400, {'code': 'DNS.0312', 'message': 'This record set name already exists.'}
            for v in vals:
                self.add(zone, name, v, b['ttl'])
            return 202, {'id': self.ids.setdefault(name, 'rs-%d' % len(self.ids)),
                         'status': 'PENDING_CREATE'}
        self.t.assertEqual(method, 'PUT')
        self.t.assertEqual(self.ids[name], p[4])
        self.drop(lambda r: r['name'] == name)
        for v in vals:
            self.add(zone, name, v, b['ttl'])
        return 202, {'id': p[4], 'status': 'PENDING_UPDATE'}


class DirectAdminFake(Fake):
    BASE = 'https://da.example.com:2222/'

    def __init__(self, t):
        Fake.__init__(self, t)
        self.forgetful = False                  # a delete that takes nothing away

    def handle(self, method, url, body, h):
        self.t.assertEqual(base64.b64decode(h['Authorization'].split(' ', 1)[1]).decode(),
                           'dau:dakey')
        self.t.assertTrue(url.startswith(self.BASE), url)
        u = urllib.parse.urlsplit(url)
        cmd = u.path.strip('/')
        if cmd == 'CMD_API_SHOW_DOMAINS':
            return 200, urllib.parse.urlencode([('list[]', z) for z in ZONES])
        self.t.assertEqual(cmd, 'CMD_API_DNS_CONTROL')
        f = form(body) if method == 'POST' else q(url)
        zone = f['domain']
        if zone not in ZONES:
            return 200, 'error=1&text=Cannot%20View%20Dns%20Record&details=No%20such%20domain'
        if method == 'GET':
            self.t.assertEqual(f.get('urlencoded'), 'yes')
            txt = [(self.rel(zone, r['name']) if i % 2 else r['name'] + '.', '"%s"' % r['value'])
                   for i, r in enumerate(r for r in self.recs if r['zone'] == zone)]
            return 200, '\n'.join([
                'A=%s' % urllib.parse.urlencode([(zone + '.', '192.0.2.1'), ('ftp', '192.0.2.1')]),
                'NS=%s' % urllib.parse.urlencode([('ns1.example.net.', zone + '.')]),
                'MX=mail=10', 'CNAME=', 'PTR=',
                'TXT=%s' % urllib.parse.urlencode([(zone + '.', '"v=spf1 a mx ?all"')] + txt),
                'AAAA=', 'SRV=']) + '\n'
        self.t.assertEqual(method, 'POST')
        if f['action'] == 'add':
            self.t.assertEqual(f['type'], 'TXT')
            self.t.assertFalse(f['name'].endswith('.'), 'written relative')
            self.add(zone, self.full(zone, f['name']), f['value'])
            return 200, 'error=0&text=Record%20Added&details='
        self.t.assertEqual(f['action'], 'select')
        self.t.assertEqual(list(f), ['domain', 'action', 'txtrecs0'])
        inner = dict(urllib.parse.parse_qsl(f['txtrecs0']))
        n = inner['name']
        name = D.norm(n) if n.endswith('.') else self.full(zone, n)
        self.t.assertTrue(inner['value'].startswith('"'), 'the value as it was listed')
        if not self.forgetful:
            self.drop(lambda r: r['name'] == name and '"%s"' % r['value'] == inner['value'])
        return 200, 'error=0&text=Records%20Deleted&details='


# ---------------------------------------------------------------------------
class TestDocProviders(Base):
    def test_cpanel(self):
        self.run_module('cpanel', CpanelFake(self), host='cpanel.example.com', user='cpu',
                        token='ctok')

    def test_cpanel_serial_moved_on(self):
        f = CpanelFake(self)
        f.throttled = True
        m, ctx = module('cpanel', f, host='https://cpanel.example.com', user='cpu', token='ctok',
                        zone='example.com')
        f.bump_once = True
        m.present('www.example.com', 't', 'k', 'one')
        self.assertEqual(f.values(), ['one'])
        self.assertTrue(any('read again' in w for _l, w in ctx.steps))
        self.assertIn('the zone example.com', m.test())

    def test_cpanel_zone_is_a_zone_it_reads(self):
        f = CpanelFake(self)
        f.throttled = True
        m, _ = module('cpanel', f, host='cpanel.example.com', user='cpu', token='ctok')
        # www.example.com is a subdomain of the account, not a zone of its own
        self.assertEqual(m.zone_for('_acme-challenge.www.example.com'), 'example.com')

    def test_joker(self):
        f = JokerFake(self)
        self.run_module('joker', f, api_key='jkey')
        self.assertEqual(f.logins, 2, 'one sign-in per run (the module of test() is new)')

    def test_joker_signs_in_again(self):
        f = JokerFake(self)
        f.throttled = True
        m, _ = module('joker', f, api_key='jkey', zone='example.com')
        m.present('www.example.com', 't', 'k', 'v1')
        f.sid = 'expired'
        m.present('www.example.com', 't', 'k', 'v2')
        self.assertEqual((f.values(), f.logins), (['v1', 'v2'], 2))

    def test_joker_empty_zone_not_written(self):
        f = JokerFake(self)
        f.throttled = True
        f.KEPT = []
        m, _ = module('joker', f, api_key='jkey', zone='example.com')
        with self.assertRaises(PluginError) as e:
            m.present('www.example.com', 't', 'k', 'v1')
        self.assertIn('read empty', str(e.exception))
        self.assertEqual(f.puts, 0)

    def test_joker_password_and_ote(self):
        f = JokerFake(self)
        f.throttled = True
        f.BASE = 'https://dmapi.ote.joker.com/request/'
        real = f.handle

        def by_password(method, url, body, h):
            if url.endswith('/login'):
                self.assertEqual(form(body), {'username': 'ju', 'password': 'jp'})
                body = b'api-key=jkey'
            return real(method, url, body, h)
        f.handle = by_password
        m, _ = module('joker', f, auth='password', user='ju', password='jp', endpoint='ote',
                      zone='other.org', ttl=60)
        m.present('x.other.org', 't', 'k', 'o1')
        self.assertEqual([r['ttl'] for r in f.recs], [300], 'raised to what Joker takes')

    def test_netim(self):
        f = NetimFake(self)
        self.run_module('netim', f, reseller='NET1234', password='npw')
        self.assertEqual(f.open, set(), 'every session closed')
        self.assertTrue(all(s == 'Done' for s in f.ops.values()), 'every operation followed')
        self.assertIn(5, SLEPT, 'a Pending operation asked again after a while')

    def test_netim_failed_operation(self):
        f = NetimFake(self)
        f.throttled = True
        real = f.handle

        def fail(method, url, body, h):
            if method == 'POST' and url.endswith('/zone/'):
                return 200, {'ID_OPE': 7, 'STATUS': 'Failed', 'MESSAGE': 'Invalid value'}
            return real(method, url, body, h)
        f.handle = fail
        m, _ = module('netim', f, reseller='NET1234', password='npw', zone='example.com')
        with self.assertRaises(PluginError) as e:
            m.present('www.example.com', 't', 'k', 'v')
        self.assertIn('Invalid value', str(e.exception))
        self.assertEqual(f.open, set())

    def test_huawei_dns(self):
        self.run_module('huawei_dns', HuaweiFake(self), access_key='hak', secret_key='hsk',
                        region='ap-southeast-1')

    def test_huawei_not_steady_waited(self):
        del SLEPT[:]
        f = HuaweiFake(self)
        f.throttled = True
        m, ctx = module('huawei_dns', f, access_key='hak', secret_key='hsk',
                        region='ap-southeast-1', zone='example.com', project_id='p1',
                        security_token='st')
        real = f.check_sign

        def also(method, url, body, h):
            self.assertEqual((h['X-Project-Id'], h['X-Security-Token']), ('p1', 'st'))
            real(method, url, body, h)
        f.check_sign = also
        m.present('www.example.com', 't', 'k', 'one')
        f.unsteady = 2
        m.present('*.www.example.com', 't', 'k', 'two')
        self.assertEqual(f.values(), ['one', 'two'])
        self.assertEqual(SLEPT, [2, 4])

    def test_huawei_canonical_request(self):
        from acmelib.plugins.challenges.huawei_dns import canonical, sign
        h = sign('GET', 'https://dns.x.myhuaweicloud.com/v2/zones?type=public&limit=10', {},
                 None, 'AK', 'SK', sdk_date='20240416T095341Z')
        creq, signed = canonical('GET', 'https://dns.x.myhuaweicloud.com/v2/zones?type=public'
                                 '&limit=10', {k: v for k, v in h.items()
                                               if k != 'Authorization'}, None)
        self.assertEqual(signed, 'host;x-sdk-date')
        self.assertEqual(creq.split('\n')[:3], ['GET', '/v2/zones/', 'limit=10&type=public'])
        sts = 'SDK-HMAC-SHA256\n20240416T095341Z\n' + hashlib.sha256(creq.encode()).hexdigest()
        self.assertEqual(h['Authorization'], 'SDK-HMAC-SHA256 Access=AK, SignedHeaders='
                         'host;x-sdk-date, Signature=' +
                         hmac.new(b'SK', sts.encode(), hashlib.sha256).hexdigest())

    def test_directadmin(self):
        self.run_module('directadmin', DirectAdminFake(self), host='da.example.com', user='dau',
                        password='dakey')

    def test_directadmin_delete_not_done_said(self):
        f = DirectAdminFake(self)
        f.throttled = True
        m, _ = module('directadmin', f, host='https://da.example.com', user='dau',
                      password='dakey', zone='example.com')
        h = m.present('www.example.com', 't', 'k', 'v')
        f.forgetful = True
        with self.assertRaises(PluginError) as e:
            m.cleanup('www.example.com', h)
        self.assertIn('by hand', str(e.exception))
        m, _ = module('directadmin', f, host='da.example.com', user='dau', password='dakey',
                      zone='example.net')
        with self.assertRaises(PluginError) as e:
            m.present('www.example.net', 't', 'k', 'x')
        self.assertIn('No such domain', str(e.exception))


class TestSoftZones(unittest.TestCase):
    """Zone discovery that never stops a run: the list refused, the SOA is asked."""

    def test_list_refused_soa_asked(self):
        f = JokerFake(self)
        f.throttled = True
        real = f.handle

        def no_list(method, url, body, h):
            if url.endswith('/dns-zone-list'):
                return 200, 'Status-Code: 2400\nError: Access denied\n\n'
            return real(method, url, body, h)
        f.handle = no_list
        m, ctx = module('joker', f, api_key='jkey')
        with mock.patch.object(D, 'find_zone', return_value='example.com') as fz:
            self.assertEqual(m.zone_for(NAME), 'example.com')
        self.assertTrue(fz.called)
        self.assertTrue(any('found by its SOA' in w for _l, w in ctx.steps))

    def test_zone_set_wins_and_catalog(self):
        for kind, fake, cfg in (
                ('cpanel', CpanelFake, {'host': 'cpanel.example.com', 'user': 'cpu',
                                        'token': 'ctok'}),
                ('joker', JokerFake, {'api_key': 'jkey'}),
                ('netim', NetimFake, {'reseller': 'NET1234', 'password': 'npw'}),
                ('huawei_dns', HuaweiFake, {'access_key': 'hak', 'secret_key': 'hsk',
                                            'region': 'ap-southeast-1'}),
                ('directadmin', DirectAdminFake, {'host': 'da.example.com', 'user': 'dau',
                                                  'password': 'dakey'})):
            f = fake(self)
            f.throttled = True
            m, _ = module(kind, f, zone='other.org', **cfg)
            self.assertEqual(m.zone_for('_acme-challenge.x.other.org'), 'other.org', kind)
            got = m.catalog('zones')
            self.assertTrue({'example.com', 'other.org'} <= {o[0] for o in got['options']}, kind)
            self.assertEqual(f.changes, 0, kind)


class TestDocDescribed(unittest.TestCase):
    def test_every_module_described(self):
        for kind in DOCS:
            cls = plugin(kind)
            d = cls.describe()
            self.assertEqual(cls.types, ('dns-01',), kind)
            self.assertTrue(d['title'] and d['description'], kind)
            self.assertTrue([f for f in d['fields'] if f['type'] == 'secret'], kind)
            keys = [f['key'] for f in d['fields']]
            self.assertEqual(len(keys), len(set(keys)), kind)
            zone = [f for f in d['fields'] if f['key'] == 'zone'][0]
            self.assertEqual((zone['type'], zone['catalog']), ('catalog', 'zones'), kind)
            doc = sys.modules[cls.__module__].__doc__
            for must in ('Sources', 'api-docs/', 'https://', 'Less certain'):
                self.assertIn(must, doc, (kind, must))

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
                out += [f['label'], f.get('help', ''), f.get('placeholder', '')
                        if ' ' in f.get('placeholder', '') else '']
                out += [o[1] for o in f.get('options') or []]
            return [w for w in out if w]
        missing = sorted({w for k in DOCS for w in words_of(reg.get('challenge', k).describe())
                          if w not in sources})
        self.assertEqual(missing, [], 'web/lang/cs.json lacks these')

    def test_every_message_has_czech(self):
        """The errors and steps the modules say (and the SoftZones helper), in cs.json:
        a sentence among the strings, one with %s / %d among the patterns ({0}, {1}…)."""
        import ast
        import re
        from test_ssls import _english_of_module
        with open(os.path.join(os.path.dirname(HERE), 'web', 'lang', 'cs.json'),
                  encoding='utf-8') as fh:
            cs = json.load(fh)
        known = {v['source'] for v in cs['strings'].values() if v.get('text')}
        pats = {v['source'] for v in cs['patterns'].values() if v.get('text')}
        missing = []
        for kind in DOCS + ('_records',):
            path = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'challenges',
                                kind + '.py')
            strings, patterns = _english_of_module(path)

            def add(node):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    s = node.value
                    if len(re.findall(r'[A-Za-z]{2,}', s)) < 2:
                        return
                    if '%' in s:
                        n = [0]

                        def slot(_m):
                            n[0] += 1
                            return '{%d}' % (n[0] - 1)
                        patterns.add(re.sub(r'%[sd]', slot, s))
                    else:
                        strings.add(s)
                elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                    add(node.left)
                elif isinstance(node, ast.IfExp):
                    add(node.body)
                    add(node.orelse)
            with open(path, encoding='utf-8') as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'step' and node.args:
                        add(node.args[0])
                    elif node.func.attr == 'say_once' and len(node.args) > 1:
                        add(node.args[1])
            missing += sorted('%s: %s' % (kind, s) for s in strings
                              if s not in known and ' ' in s)   # not a host name or a URL
            missing += sorted('%s: PATTERN %s' % (kind, p) for p in patterns
                              if p not in pats and ' ' in p)
        self.assertEqual(missing, [], '\n'.join(missing))

    def test_documented(self):
        with open(os.path.join(os.path.dirname(HERE), 'docs', 'validation.md'),
                  encoding='utf-8') as fh:
            doc = fh.read()
        for kind in DOCS:
            self.assertIn('(`%s`)' % kind, doc, kind)
            self.assertIn('| `%s` |' % kind, doc, kind)
        for kind in ('bluecat', 'dynadot'):
            self.assertIn(kind, doc.lower())


if __name__ == '__main__':
    unittest.main(verbosity=2)
