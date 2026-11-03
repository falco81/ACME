#!/usr/bin/env python3
"""The validation modules of 1.0.27 written from the vendors' own documentation
(the user's collection, api-docs/<vendor>/, named in each module's docstring
and in docs/validation.md): Forpsi F-DNS, ISPConfig, HestiaCP, Virtualmin,
froxlor and Windows DNS over SSH - and what the same collection changed in the
modules already there (Hetzner, GoDaddy v3, PowerDNS EXTEND/PRUNE, Gandi
PATCH, Azure DNS etags, Cloudflare's quoted content, OVH's TTL, NS1, Porkbun,
Google Cloud DNS, Akamai).

    python3 test/test_dns_providers_panels.py

No internet. As test_dns_providers.py: ctx.http (or the SSH session) is
answered by an in-memory fake of each API that keeps TXT records the way that
API does and checks each request against what its documentation says. Each
new module goes through the same run (the longest zone found, two values at
one name, cleanup taking only its own away, a second cleanup quiet, test()
changing nothing, a 429 waited out), then through what is its own.
"""
import base64
import json
import os
import re
import sys
import unittest
import urllib.parse
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_challenges import FakeCtx, Router, plugin  # noqa: E402
from test_dns_providers import NAME, SLEPT, ZONES, Base, Fake, form, module, q  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.challenges import _dns as D  # noqa: E402

NEW = ('forpsi', 'ispconfig', 'hestiacp', 'virtualmin', 'froxlor', 'windows_dns')
CHANGED = ('hetzner', 'godaddy', 'powerdns', 'gandi', 'azure_dns', 'cloudflare', 'ovh', 'ns1',
           'porkbun', 'gcloud_dns', 'akamai_edgedns', 'ssh_dns')


def j(body):
    return json.loads(body) if body else {}


def basic_of(h):
    return base64.b64decode(h['Authorization'].split(' ', 1)[1]).decode()


# ---------------------------------------------------------------------------
# Forpsi F-DNS (api-docs/forpsi/openapi.json)
# ---------------------------------------------------------------------------
class ForpsiFake(Fake):
    BASE = 'https://api.forpsi.com/dnsaas/v1'

    def page(self, items, key, url):
        qs = q(url)
        skip, limit = int(qs.get('skip', 0)), int(qs.get('limit', 100))
        self.t.assertTrue(1 <= limit <= 1000, 'limit 1 to 1000')
        part = items[skip:skip + limit]
        nxt = None
        if skip + limit < len(items):
            nxt = '%s?skip=%d&limit=%d' % (url.split('?')[0], skip + limit, limit)
        return 200, {key: part, 'total_count': len(items), 'next_page': nxt}

    def handle(self, method, url, body, h):
        self.t.assertTrue(url.startswith(self.BASE), url)
        if h.get('token') != 'ftok':
            return 401, {'msg': 'Invalid token'}
        self.t.assertNotIn('Authorization', h)
        path = urllib.parse.urlsplit(url).path[len('/dnsaas/v1'):]
        if path in ('', '/'):
            return 200, {'service_renew_date': '2027-01-01', 'domains_allowed': 500,
                         'domains_used': len(ZONES)}
        if path == '/domains':
            return self.page([{'name': z} for z in ZONES], 'domains', url)
        bits = path.split('/')
        zone = bits[2]
        if zone not in ZONES:
            return 404, {'msg': 'Not found'}
        if len(bits) == 4 and method == 'GET':
            rows = [{'id': 1, 'name': '', 'type': 'A', 'data': '192.0.2.1', 'ttl': 3600}]
            rows += [{'id': r['id'], 'name': self.rel(zone, r['name']), 'type': 'TXT',
                      'data': r['value'], 'ttl': r['ttl']} for r in self.recs
                     if r['zone'] == zone]
            return self.page(rows, 'dnsrecords', url)
        if len(bits) == 4 and method == 'POST':
            b = j(body)
            self.t.assertEqual(set(b), {'name', 'type', 'data', 'ttl'})
            self.t.assertEqual(b['type'], 'TXT')
            self.t.assertFalse(b['name'].endswith(zone), 'relative')
            self.t.assertTrue(60 <= b['ttl'] <= 86400)
            self.t.assertLessEqual(len(b['data']), 255)
            rid = self.add(zone, self.full(zone, b['name']), b['data'], b['ttl'])
            return 200, dict(b, id=rid)
        self.t.assertEqual((len(bits), method), (5, 'DELETE'))
        if not self.drop(lambda r: str(r['id']) == bits[4]):
            return 404, {'msg': 'Not found (e.g. domain or DNS record does not exist)'}
        return 200, {'msg': 'OK'}


# ---------------------------------------------------------------------------
# ISPConfig Remote API, JSON (api-docs/ispconfig/notes.md)
# ---------------------------------------------------------------------------
class IspConfigFake(Fake):
    URL = 'https://panel.example.com:8080/remote/json.php?'

    def __init__(self, t):
        Fake.__init__(self, t)
        self.sessions, self.opened = set(), 0
        self.ids = {z: i + 11 for i, z in enumerate(ZONES)}

    def ok(self, response):
        return 200, {'code': 'ok', 'message': '', 'response': response}

    def fault(self, words):
        return 200, {'code': 'remote_fault', 'message': words, 'response': False}

    def handle(self, method, url, body, h):
        self.t.assertEqual(method, 'POST')
        self.t.assertTrue(url.startswith(self.URL), url)
        self.t.assertEqual(h['Content-Type'], 'application/json')
        fn, b = url[len(self.URL):], j(body)
        if fn == 'login':
            if (b.get('username'), b.get('password')) != ('acme', 'ipw'):
                return self.fault('The login failed. Username or password wrong.')
            self.opened += 1
            sid = 'sid%d' % self.opened
            self.sessions.add(sid)
            return self.ok(sid)
        if b.get('session_id') not in self.sessions:
            return self.fault('The Session is expired or does not exist.')
        if fn == 'logout':
            self.sessions.discard(b['session_id'])
            return self.ok(True)
        if fn == 'dns_zone_get':
            pid = b['primary_id']
            zs = [{'id': self.ids[z], 'server_id': 1, 'origin': z + '.'} for z in ZONES]
            if pid == -1:
                return self.ok(zs)
            self.t.assertIsInstance(pid, dict)
            return self.ok([x for x in zs if x['origin'] == pid.get('origin')])
        if fn == 'dns_rr_get_all_by_zone':
            zone = [z for z, i in self.ids.items() if i == b['zone_id']][0]
            rows = [{'id': 1, 'zone': b['zone_id'], 'name': zone + '.', 'type': 'A',
                     'data': '192.0.2.1', 'ttl': 3600}]
            rows += [{'id': r['id'], 'zone': b['zone_id'], 'name': self.rel(zone, r['name']),
                      'type': 'txt', 'data': r['value'], 'ttl': r['ttl']}
                     for r in self.recs if r['zone'] == zone]
            return self.ok(rows)
        if fn == 'dns_txt_add':
            p = b['params']
            self.t.assertEqual((b['client_id'], b['update_serial']), (0, True))
            self.t.assertEqual((p['type'], p['active'], p['server_id']), ('txt', 'y', 1))
            zone = [z for z, i in self.ids.items() if i == p['zone']][0]
            self.t.assertFalse(p['name'].endswith('.'), 'relative - the origin is appended')
            self.t.assertGreaterEqual(int(p['ttl']), 60)
            self.t.assertFalse(p['data'].startswith('"'), 'the template adds the quotes')
            return self.ok(self.add(zone, self.full(zone, p['name']), p['data'], int(p['ttl'])))
        if fn == 'dns_txt_delete':
            self.t.assertTrue(b['update_serial'])
            return self.ok(self.drop(lambda r: r['id'] == b['primary_id']))
        return 200, {'code': 'invalid_method', 'message': 'no such method', 'response': False}


# ---------------------------------------------------------------------------
# HestiaCP API (api-docs/hestiacp/notes.md)
# ---------------------------------------------------------------------------
class HestiaFake(Fake):
    URL = 'https://hestia.example.com:8083/api/'

    def handle(self, method, url, body, h):
        self.t.assertEqual((method, url), ('POST', self.URL))
        f = form(body)
        if f.get('hash') != 'AK0123456789:SK0123456789':
            return 401, 'Error: authentication failed'
        cmd, rc = f['cmd'], f['returncode']
        self.t.assertEqual(f['arg1'], 'alice')
        if cmd == 'v-list-dns-domains':
            self.t.assertEqual((rc, f['arg2']), ('no', 'json'))
            return 200, {z: {'IP': '192.0.2.1', 'TTL': '14400'} for z in ZONES}
        zone = f['arg2']
        if zone not in ZONES:
            if rc == 'yes':
                return 200, '3'
            return 400, "Error: dns domain %s doesn't exist" % zone
        if cmd == 'v-list-dns-records':
            self.t.assertEqual((rc, f['arg3']), ('no', 'json'))
            rows = {'1': {'RECORD': '@', 'TYPE': 'A', 'VALUE': '192.0.2.1', 'ID': '1',
                          'TTL': '14400'}}
            for r in self.recs:
                if r['zone'] == zone:
                    rows[str(r['id'])] = {'RECORD': self.rel(zone, r['name']), 'TYPE': 'TXT',
                                          'VALUE': '"%s"' % r['value'], 'ID': str(r['id']),
                                          'TTL': str(r['ttl'])}
            return 200, rows
        self.t.assertEqual(rc, 'yes')
        if cmd == 'v-add-dns-record':
            self.t.assertEqual(f['arg4'], 'TXT')
            self.t.assertFalse(f['arg3'].endswith(zone), 'relative to the zone')
            self.t.assertFalse(f['arg5'].startswith('"'))
            if 'arg9' in f:
                self.t.assertEqual((f['arg6'], f['arg7'], f['arg8']), ('', '', 'yes'))
            self.add(zone, self.full(zone, f['arg3']), f['arg5'], int(f.get('arg9') or 14400))
            return 200, '0'
        self.t.assertEqual(cmd, 'v-delete-dns-record')
        return 200, '0' if self.drop(lambda r: str(r['id']) == f['arg3']) else '3'


# ---------------------------------------------------------------------------
# Virtualmin remote.cgi (api-docs/virtualmin/notes.md)
# ---------------------------------------------------------------------------
class VirtualminFake(Fake):
    URL = 'https://vm.example.com:10000/virtual-server/remote.cgi'

    def __init__(self, t):
        Fake.__init__(self, t)
        self.removed = []

    def out(self, text, status=0):
        return 200, '%s\nExit status: %d\n' % (text, status)

    def handle(self, method, url, body, h):
        self.t.assertEqual((method, url), ('POST', self.URL))
        if basic_of(h) != 'root:vpw':
            return 401, 'Unauthorized'
        pairs = urllib.parse.parse_qsl(body.decode(), keep_blank_values=True)
        f = dict(pairs)
        prog = f.pop('program')
        if prog == 'list-domains':
            self.t.assertEqual(f, {'with-feature': 'dns', 'name-only': ''})
            return self.out('\n'.join(ZONES))
        zone = f['domain']
        if zone not in ZONES:
            return 200, 'ERROR: No domain with name %s exists\n' % zone
        if prog == 'get-dns':
            self.t.assertEqual((f['type'], f['multiline']), ('TXT', ''))
            lines = ['%s.\n    Type: TXT\n    Value: v=spf1 -all' % zone]
            lines += ['%s.\n    Type: TXT\n    TTL: %d\n    Value: %s' % (r['name'], r['ttl'],
                                                                         r['value'])
                      for r in self.recs if r['zone'] == zone]
            return self.out('\n'.join(lines))
        self.t.assertEqual(prog, 'modify-dns')
        if 'add-record-with-ttl' in f:
            name, typ, ttl, value = f['add-record-with-ttl'].split(' ')
            self.t.assertTrue(name.endswith('.'), 'whole, with the final dot')
            self.t.assertEqual(typ, 'TXT')
            name = D.norm(name)
            if D.in_zone(name, zone) and value not in [r['value'] for r in self.recs
                                                       if r['name'] == name]:
                self.add(zone, name, value, int(ttl))
            # a clash or a name outside the zone is only a line, not an error
            return self.out('Adding records..\n.. done')
        spec = f['remove-record'].split(' ')
        self.t.assertEqual(len(spec), 3, 'remove-record always with the value')
        name, typ, value = spec
        self.removed.append(spec)
        self.drop(lambda r: r['name'] == D.norm(name) and r['value'] == value)
        return self.out('Removing records..\n.. done')


# ---------------------------------------------------------------------------
# froxlor API (api-docs/froxlor/notes.md)
# ---------------------------------------------------------------------------
class FroxlorFake(Fake):
    URL = 'https://froxlor.example.com/api.php'

    def __init__(self, t, customer=False):
        Fake.__init__(self, t)
        self.customer = customer

    def handle(self, method, url, body, h):
        self.t.assertEqual((method, url), ('POST', self.URL))
        self.t.assertEqual(h['Content-Type'], 'application/json')
        if basic_of(h) != 'fk:fs':
            return 403, {'message': 'Invalid authorization credentials'}
        b = j(body)
        cmd, p = b['command'], b.get('params') or {}
        if cmd == 'Domains.listing':
            if self.customer:
                return 403, {'message': 'You cannot access this resource'}
            rows = [{'id': i + 1, 'domain': z, 'parentdomainid': '0', 'isbinddomain': '1'}
                    for i, z in enumerate(ZONES)]
            rows.append({'id': 9, 'domain': 'www.example.com', 'parentdomainid': '1',
                         'isbinddomain': '1'})
            rows.append({'id': 10, 'domain': 'nodns.example.com', 'parentdomainid': '0',
                         'isbinddomain': '0'})
            return 200, {'data': {'count': len(rows), 'list': rows}}
        if cmd == 'SubDomains.listing':
            rows = [{'id': i + 1, 'domain': z, 'parentdomainid': 0} for i, z in enumerate(ZONES)]
            return 200, {'data': {'count': len(rows), 'list': rows}}
        zone = p.get('domainname')
        if zone not in ZONES:
            return 406, {'message': 'DNS zones can only be generated for the main domain'}
        if cmd == 'DomainZones.listing':
            rows = [{'id': r['id'], 'domain_id': 1, 'record': self.rel(zone, r['name']),
                     'type': 'TXT', 'prio': 0, 'content': r['value'], 'ttl': r['ttl']}
                    for r in self.recs if r['zone'] == zone]
            return 200, {'data': {'count': len(rows), 'list': rows}}
        if cmd == 'DomainZones.add':
            self.t.assertEqual(p['type'], 'TXT')
            self.t.assertLessEqual(len(p['record']), 63)
            self.t.assertFalse(p['record'].endswith(zone))
            self.t.assertFalse(p['content'].startswith('"'))
            self.add(zone, self.full(zone, p['record']), p['content'], p['ttl'])
            return 200, {'data': ['$TTL 18000', '@ IN SOA ns.example.com. ...']}
        self.t.assertEqual(cmd, 'DomainZones.delete')
        if not self.drop(lambda r: r['id'] == p['entry_id']):
            return 304, b''
        return 200, {'data': True}


# ---------------------------------------------------------------------------
class TestPanels(Base):
    def test_forpsi(self):
        f = ForpsiFake(self)
        # the module's own globals (a Registry reload elsewhere imports it anew)
        with mock.patch.dict(plugin('forpsi')._pages.__globals__, {'PAGE': 2}):
            self.run_module('forpsi', f, token='ftok')
        self.assertTrue(any('skip=2' in c[1] for c in f.calls), 'every page read')

    def test_forpsi_ttl_and_words(self):
        f = ForpsiFake(self)
        f.throttled = True
        m, _ = module('forpsi', f, token='ftok', zone='example.com', ttl=10)
        m.present('www.example.com', 't', 'k', 'v1')
        self.assertEqual([r['ttl'] for r in f.recs], [60], 'raised to what F-DNS takes')
        self.assertIn('the domain example.com has', m.test())
        d = plugin('forpsi').describe()
        self.assertIn('no API', d['description'])
        m, _ = module('forpsi', f, token='bad')
        with self.assertRaises(PluginError) as e:
            m.test()
        self.assertIn('Invalid token', str(e.exception))

    def test_ispconfig(self):
        f = IspConfigFake(self)
        self.run_module('ispconfig', f, url='panel.example.com', user='acme', password='ipw')
        self.assertEqual(f.sessions, set(), 'every session closed')

    def test_ispconfig_refusal_said(self):
        f = IspConfigFake(self)
        f.throttled = True
        m, _ = module('ispconfig', f, url='https://panel.example.com:8080', user='acme',
                      password='wrong', zone='example.com')
        with self.assertRaises(PluginError) as e:
            m.present('www.example.com', 't', 'k', 'v')
        self.assertIn('Username or password wrong', str(e.exception))
        self.assertFalse(e.exception.retry)

    def test_hestiacp(self):
        self.run_module('hestiacp', HestiaFake(self), host='hestia.example.com', user='alice',
                        access_key='AK0123456789', secret_key='SK0123456789')

    def test_hestiacp_ttl_and_exit_codes(self):
        f = HestiaFake(self)
        f.throttled = True
        m, _ = module('hestiacp', f, host='https://hestia.example.com:8083', user='alice',
                      access_key='AK0123456789', secret_key='SK0123456789', zone='example.com',
                      ttl=120)
        m.present('www.example.com', 't', 'k', 'v1')
        self.assertEqual([r['ttl'] for r in f.recs], [120])
        m, _ = module('hestiacp', f, host='hestia.example.com', user='alice',
                      access_key='AK0123456789', secret_key='SK0123456789', zone='example.net')
        with self.assertRaises(PluginError) as e:
            m.present('www.example.net', 't', 'k', 'x')
        self.assertIn("doesn't exist", str(e.exception))
        self.assertEqual(f.recs[0]['value'], 'v1', 'nothing else changed')

    def test_virtualmin(self):
        f = VirtualminFake(self)
        self.run_module('virtualmin', f, host='vm.example.com', user='root', password='vpw')
        self.assertTrue(f.removed and all(len(s) == 3 for s in f.removed))

    def test_virtualmin_not_added_said(self):
        f = VirtualminFake(self)
        f.throttled = True
        m, _ = module('virtualmin', f, host='vm.example.com', user='root', password='vpw')
        # a name outside the virtual server's zone: Virtualmin only prints a line
        m._zones['_acme-challenge.x.other.org'] = 'example.com'
        with self.assertRaises(PluginError) as e:
            m.add_txt('_acme-challenge.x.other.org', 'Fz3kQ9-token')
        self.assertIn('did not add', str(e.exception))
        self.assertEqual(f.recs, [])

    def test_froxlor(self):
        self.run_module('froxlor', FroxlorFake(self), url='froxlor.example.com', api_key='fk',
                        api_secret='fs')

    def test_froxlor_customer_key_and_words(self):
        f = FroxlorFake(self, customer=True)
        f.throttled = True
        m, _ = module('froxlor', f, url='https://froxlor.example.com/', api_key='fk',
                      api_secret='fs')
        self.assertEqual(m.zone_for(NAME), 'example.com', 'SubDomains.listing for a customer')
        m, _ = module('froxlor', f, url='froxlor.example.com', api_key='fk', api_secret='no')
        with self.assertRaises(PluginError) as e:
            m.test()
        self.assertIn('Invalid authorization credentials', str(e.exception))
        f2 = FroxlorFake(self)
        f2.throttled = True
        m, _ = module('froxlor', f2, url='froxlor.example.com', api_key='fk', api_secret='fs')
        self.assertNotIn('nodns.example.com', m.zone_names())
        self.assertNotIn('www.example.com', m.zone_names())


# ---------------------------------------------------------------------------
# Windows DNS over SSH
# ---------------------------------------------------------------------------
class TestWindowsDns(unittest.TestCase):
    def world(self):
        from test_ssh_dns import World
        held = []

        def ps(core, inp, sudo):
            if 'Get-DnsServerZone' in core:
                return 0, 'example.com\nexample.net\n', ''
            m = re.search(r"-DescriptiveText '([^']*)'", core)
            if 'Add-DnsServerResourceRecord' in core and m and m.group(1) not in held:
                held.append(m.group(1))
            m = re.search(r"-RecordData '([^']*)'", core)
            if 'Remove-DnsServerResourceRecord' in core and m and m.group(1) in held:
                held.remove(m.group(1))
            return 0, '', ''
        return World([(r'^powershell ', ps)]), held

    def module(self, w, **cfg):
        from test_ssh_dns import Ctx
        base = {'host': 'dc1.example.com', 'user': 'acme', 'key': 'K', 'propagation': 'none',
                'follow_cname': False, 'zone': 'example.com'}
        base.update(cfg)
        return plugin('windows_dns')(base, Ctx(w))

    def test_add_and_remove_only_ours(self):
        w, held = self.world()
        m = self.module(w, computer='dns1')
        h1 = m.present('www.example.com', 't', 'k', 'one')
        m.present('*.www.example.com', 't', 'k', 'two')
        self.assertEqual(held, ['one', 'two'])
        m.cleanup('www.example.com', h1)
        self.assertEqual(held, ['two'])
        for c in w.commands:
            self.assertTrue(c.startswith('powershell -NoProfile -NonInteractive -Command "'), c)
            self.assertNotIn('sudo', c)
            if 'Remove-DnsServerResourceRecord' in c:
                self.assertIn("-RecordData 'one'", c, 'never without -RecordData')
                self.assertIn('-Force', c)
            if 'Get-DnsServerResourceRecord' in c:
                self.assertIn('-Node', c)
            self.assertIn("-ComputerName 'dns1'", c)
        self.assertIn("-Name '_acme-challenge.www' -Txt -DescriptiveText 'one'", w.commands[0])

    def test_test_lists_zones_and_changes_nothing(self):
        w, held = self.world()
        said = self.module(w).test()
        self.assertIn('example.com', said)
        self.assertEqual(held, [])
        self.assertTrue(all('Get-DnsServerZone' in c for c in w.commands))

    def test_unsafe_value_refused(self):
        w, _ = self.world()
        with self.assertRaises(PluginError):
            self.module(w).present('www.example.com', 't', 'k', "x'; Remove-Item C:\\ #")
        self.assertEqual(w.commands, [])

    def test_ssh_dns_powershell_the_same(self):
        from acmelib.plugins.challenges.ssh_dns import ps_txt
        rm = ps_txt('del', 'example.com', '_acme-challenge', 'v', 60)
        self.assertIn("Remove-DnsServerResourceRecord -ZoneName 'example.com' -RRType Txt "
                      "-Name '_acme-challenge' -RecordData 'v' -Force", rm)
        self.assertNotIn('| Remove-DnsServerResourceRecord', rm, 'not piped without RecordData')

    def test_form(self):
        d = plugin('windows_dns').describe()
        keys = [f['key'] for f in d['fields']]
        self.assertNotIn('flavour', keys)
        self.assertNotIn('sudo', keys)
        key = [f for f in d['fields'] if f['type'] == 'sshkey'][0]
        self.assertEqual(key['howto'], 'windows')
        self.assertEqual(d['actions'], [])


# ---------------------------------------------------------------------------
# What the collection changed in the modules already there
# ---------------------------------------------------------------------------
class TestHetzner(unittest.TestCase):
    API = 'https://api.hetzner.cloud/v1'

    def fake(self, ttl=None, values=(), locked=0, running=False):
        st = {'values': list(values), 'ttl': ttl, 'bodies': [], 'locked': locked, 'polls': 0}
        r = Router()
        r.on('GET', self.API + '/zones?name=example.com',
             lambda u, b, h: {'zones': [{'id': 7, 'name': 'example.com'}]})
        r.on('GET', self.API + '/zones?name=', lambda u, b, h: {'zones': []})

        def get(u, b, h):
            if not st['values']:
                return 404, {'error': {'code': 'not_found'}}
            return {'rrset': {'ttl': st['ttl'], 'records': [{'value': v} for v in st['values']]}}

        def post(u, b, h):
            if st['locked']:
                st['locked'] -= 1
                return 423, {'error': {'code': 'locked', 'message': 'locked'}}
            body = json.loads(b)
            st['bodies'].append((u.rsplit('/', 1)[1], body))
            vals = [x['value'] for x in body['records']]
            if u.endswith('add_records'):
                if 'ttl' in body and st['values'] and st['ttl'] is not None:
                    return 422, {'error': {'code': 'invalid_input'}}
                st['values'] += vals
                st['ttl'] = body.get('ttl', st['ttl'])
            else:
                st['values'] = [v for v in st['values'] if v not in vals]
            return 201, {'action': {'id': 99, 'status': 'running' if running else 'success'}}

        def action(u, b, h):
            st['polls'] += 1
            return {'action': {'id': 99, 'status': 'success'}}
        r.on('GET', self.API + '/zones/7/rrsets/', get)
        r.on('POST', self.API + '/zones/7/rrsets/', post)
        r.on('GET', self.API + '/zones/actions/99', action)
        return r, st

    def test_ttl_only_for_a_new_rrset_and_only_ours_away(self):
        r, st = self.fake(ttl=3600, values=['"someone"'])
        m = plugin('hetzner')({'token': 'T', 'propagation': 'none'}, FakeCtx(http=r))
        h = m.present('www.example.com', 't', 'k', 'v1')
        self.assertNotIn('ttl', st['bodies'][0][1], 'the RRset there keeps its TTL')
        m.present('www.example.com', 't', 'k', 'v1')
        self.assertEqual(len(st['bodies']), 1, 'there already: nothing sent')
        m.cleanup('www.example.com', h)
        self.assertEqual(st['values'], ['"someone"'])
        self.assertEqual(st['bodies'][-1], ('remove_records', {'records': [{'value': '"v1"'}]}))
        m.cleanup('www.example.com', h)
        self.assertEqual(len(st['bodies']), 2, 'gone already: nothing sent')
        r, st = self.fake()
        plugin('hetzner')({'token': 'T', 'propagation': 'none', 'ttl': 10},
                          FakeCtx(http=r)).present('www.example.com', 't', 'k', 'v')
        self.assertEqual(st['bodies'][0][1]['ttl'], 60, 'at least 60')

    def test_action_waited_and_locked_tried_again(self):
        del SLEPT[:]
        r, st = self.fake(locked=1, running=True)
        ctx = FakeCtx(http=r)
        plugin('hetzner')({'token': 'T', 'propagation': 'none'}, ctx).present(
            'www.example.com', 't', 'k', 'v')
        self.assertEqual(st['values'], ['"v"'])
        self.assertEqual(st['polls'], 1)
        self.assertTrue(any('423' in w for _l, w in ctx.steps))

    def test_old_dns_console_refused_in_words(self):
        m = plugin('hetzner')({'token': 'T', 'api': 'dns', 'propagation': 'none'},
                              FakeCtx(http=Router()))
        with self.assertRaises(PluginError) as e:
            m.present('www.example.com', 't', 'k', 'v')
        self.assertIn('May 2026', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertNotIn('api', [f['key'] for f in plugin('hetzner').describe()['fields']])


class GodaddyV3Fake(Fake):
    BASE = 'https://api.godaddy.com/v3/domains'

    def handle(self, method, url, body, h):
        self.t.assertEqual(h['Authorization'], 'Bearer gpat')
        self.t.assertTrue(url.startswith(self.BASE), url)
        u = urllib.parse.urlsplit(url)
        p = u.path[len('/v3/domains/'):].split('/')
        if p == ['domain-names']:
            qs = q(url)
            self.t.assertEqual(qs['statuses'], 'ACTIVE')
            items = [{'domain': z, 'status': 'ACTIVE'} for z in ZONES]
            if 'pageToken' not in qs:
                return 200, {'items': items[:2], 'links': [
                    {'rel': 'next', 'href': '/v3/domains/domain-names?statuses=ACTIVE&'
                                            'pageSize=200&pageToken=t2'}]}
            return 200, {'items': items[2:], 'links': [{'rel': 'self', 'href': url}]}
        zone = p[1]
        if method == 'GET':
            qs = q(url)
            self.t.assertEqual(qs['type'], 'TXT')
            rows = [{'recordId': 'rec_%d' % r['id'], 'name': self.rel(zone, r['name']) or '@',
                     'type': 'TXT', 'data': r['value'], 'ttl': r['ttl']}
                    for r in self.recs if r['zone'] == zone]
            rows = [x for x in rows if x['name'] == qs['name']]
            return 200, {'items': rows, 'links': [{'rel': 'self', 'href': url}]}
        if method == 'POST':
            b = j(body)
            self.t.assertEqual(set(b), {'type', 'name', 'data', 'ttl'})
            self.t.assertTrue(600 <= b['ttl'] <= 86400)
            self.t.assertFalse(b['name'].endswith(zone))
            rid = self.add(zone, self.full(zone, b['name']), b['data'], b['ttl'])
            return 201, dict(b, recordId='rec_%d' % rid)
        self.t.assertEqual(method, 'DELETE')
        rid = p[3]
        if not self.drop(lambda r: 'rec_%d' % r['id'] == rid):
            return 404, {'code': 'NOT_FOUND', 'message': 'record not found'}
        return 204, b''


class TestGodaddy(Base):
    def test_v3_with_a_personal_access_token(self):
        f = GodaddyV3Fake(self)
        self.run_module('godaddy', f, pat='gpat')
        self.assertTrue(any('pageToken=t2' in c[1] for c in f.calls), 'every page')
        self.assertFalse(any('/v1/' in c[1] for c in f.calls))

    def test_v1_kept_for_a_key_saved_before(self):
        from test_dns_providers import GodaddyFake
        f = GodaddyFake(self)
        f.throttled = True
        m, _ = module('godaddy', f, api_key='K', api_secret='S', zone='example.com')
        m.present('www.example.com', 't', 'k', 'g1')
        self.assertEqual(f.values(), ['g1'])
        self.assertTrue(all('/v1/' in c[1] for c in f.calls))
        f = GodaddyFake(self)
        f.throttled = True
        m, ctx = module('godaddy', f, api='v3', api_key='K', api_secret='S', zone='example.com')
        m.present('www.example.com', 't', 'k', 'g2')     # saved again with the form's default
        self.assertEqual(f.values(), ['g2'])
        self.assertTrue(any('v1 is used' in w for _l, w in ctx.steps))
        m, _ = module('godaddy', GodaddyV3Fake(self), api='v3', zone='example.com')
        with self.assertRaises(PluginError) as e:
            m.present('www.example.com', 't', 'k', 'g1')
        self.assertIn('personal access token', str(e.exception))


class TestPowerDns(unittest.TestCase):
    BASE = 'http://pdns:8081/api/v1/servers/localhost'

    def fake(self, version):
        st = {'records': [{'content': '"other"', 'disabled': False}], 'ttl': 900, 'patches': []}
        r = Router()
        r.on('GET', self.BASE + '/zones/example.com..?', lambda u, b, h: {'rrsets': [
            {'name': '_acme-challenge.example.com.', 'type': 'TXT', 'ttl': st['ttl'],
             'records': list(st['records'])}] if st['records'] else []})
        r.on('GET', self.BASE + '/zones', lambda u, b, h: [
            {'name': 'example.com.', 'id': 'example.com..'}])

        def patch(u, b, h):
            self.assertIn('/zones/example.com..', u, 'the id the server lists')
            rs = json.loads(b)['rrsets'][0]
            st['patches'].append(rs)
            ct = rs['changetype']
            if ct == 'EXTEND':
                st['records'] += rs['records']
            elif ct == 'PRUNE':
                st['records'] = [x for x in st['records']
                                 if x['content'] != rs['records'][0]['content']]
            elif ct == 'REPLACE':
                st['records'], st['ttl'] = rs['records'], rs['ttl']
            else:
                st['records'] = []
            return 204, b''
        r.on('PATCH', self.BASE + '/zones/', patch)
        r.on('GET', self.BASE, lambda u, b, h: {'daemon_type': 'authoritative',
                                                'version': version})
        return r, st

    def run_one(self, version):
        r, st = self.fake(version)
        m = plugin('powerdns')({'url': 'http://pdns:8081', 'api_key': 'k', 'propagation': 'none'},
                               FakeCtx(http=r))
        h = m.present('example.com', 't', 'k', 'one')
        m.cleanup('example.com', h)
        self.assertEqual([x['content'] for x in st['records']], ['"other"'])
        self.assertEqual(st['ttl'], 900, 'the RRset keeps its TTL')
        return [p['changetype'] for p in st['patches']], st

    def test_extend_prune_from_4_9_12_and_5_0_2(self):
        for v in ('4.9.12', '5.0.2', '5.1.0', '4.9.13-beta'):
            got, st = self.run_one(v)
            self.assertEqual(got, ['EXTEND', 'PRUNE'], v)
            self.assertEqual(st['patches'][1]['records'], [{'content': '"one"'}])
            self.assertNotIn('ttl', st['patches'][1], 'no TTL with PRUNE')
        for v in ('4.9.11', '4.8.4', '5.0.1', 'master'):
            self.assertEqual(self.run_one(v)[0], ['REPLACE', 'REPLACE'], v)

    def test_version_gate(self):
        from acmelib.plugins.challenges.powerdns import extend_prune
        self.assertTrue(extend_prune('4.9.12'))
        self.assertFalse(extend_prune('4.10.0'))
        self.assertFalse(extend_prune(None))


class TestOthersChanged(unittest.TestCase):
    def test_gandi_patch_never_put(self):
        from test_dns_providers import GandiFake
        f = GandiFake(self)
        f.throttled = True
        m, _ = module('gandi', f, token='pat', zone='example.com')
        f.add('example.com', NAME, 'theirs')
        h = m.present('www.example.com', 't', 'k', 'g1')
        m.cleanup('www.example.com', h)
        self.assertEqual(f.values(), ['theirs'])
        self.assertNotIn('PUT', [c[0] for c in f.calls])
        self.assertNotIn('DELETE', [c[0] for c in f.calls])
        h = m.present('x.example.com', 't', 'k', 'g2')          # a new RRset: POST
        self.assertIn('POST', [c[0] for c in f.calls])

    def test_azure_etag_and_ttl_kept(self):
        st = {'etag': 'e1', 'values': [['theirs']], 'ttl': 3600, 'puts': [], 'stale': 1}
        mg = 'https://management.azure.com'
        zid = '/subscriptions/S/resourceGroups/rg/providers/Microsoft.Network/dnsZones/example.com'
        r = Router()
        r.on('POST', 'https://login.microsoftonline.com/T/oauth2/v2.0/token',
             lambda u, b, h: {'access_token': 'AT', 'expires_in': 3600})
        r.on('GET', mg + '/subscriptions/S/resourceGroups/rg/providers/Microsoft.Network/'
                         'dnsZones?', lambda u, b, h: {'value': [{'name': 'example.com',
                                                                  'id': zid}]})
        r.on('GET', mg + zid + '/TXT/', lambda u, b, h: {
            'etag': st['etag'], 'properties': {'TTL': st['ttl'], 'metadata': {'k': 'v'},
                                               'TXTRecords': [{'value': v}
                                                              for v in st['values']]}})

        def put(u, b, h):
            if st['stale']:
                st['stale'] -= 1
                st['etag'] = 'e2'
                return 412, {'error': {'code': 'PreconditionFailed', 'message': 'etag'}}
            self.assertEqual(h.get('If-Match'), st['etag'])
            p = json.loads(b)['properties']
            st['puts'].append(p)
            st['values'] = [x['value'] for x in p['TXTRecords']]
            return {}
        r.on('PUT', mg + zid + '/TXT/', put)
        ctx = FakeCtx(http=r)
        m = plugin('azure_dns')({'tenant_id': 'T', 'client_id': 'C', 'client_secret': 'X',
                                 'subscription_id': 'S', 'resource_group': 'rg',
                                 'propagation': 'none'}, ctx)
        h = m.present('www.example.com', 't', 'k', 'az')
        self.assertEqual(st['values'], [['theirs'], ['az']])
        self.assertEqual((st['puts'][0]['TTL'], st['puts'][0]['metadata']), (3600, {'k': 'v'}))
        self.assertTrue(any('changed meanwhile' in w for _l, w in ctx.steps))
        m.cleanup('www.example.com', h)
        self.assertEqual(st['values'], [['theirs']])

    def test_cloudflare_quoted_content_cleaned_up_without_an_id(self):
        cf = 'https://api.cloudflare.com/client/v4'
        recs = {'R1': '"theirs"', 'R2': '"cfv"'}
        r = Router()
        r.on('GET', cf + '/zones?name=example.com', lambda u, b, h: {
            'success': True, 'result': [{'id': 'Z1', 'name': 'example.com'}]})
        r.on('GET', cf + '/zones?name=', lambda u, b, h: {'success': True, 'result': []})
        r.on('GET', cf + '/zones/Z1/dns_records?', lambda u, b, h: {'success': True, 'result': [
            {'id': k, 'type': 'TXT', 'name': '_acme-challenge.www.example.com', 'content': v}
            for k, v in recs.items()]})
        r.on('DELETE', cf + '/zones/Z1/dns_records/', lambda u, b, h: (
            recs.pop(u.rsplit('/', 1)[1], None), {'success': True, 'result': {}})[1])
        m = plugin('cloudflare')({'token': 'tok', 'propagation': 'none'}, FakeCtx(http=r))
        m.cleanup('www.example.com', {'fqdn': '_acme-challenge.www.example.com', 'txt': 'cfv'})
        self.assertEqual(recs, {'R1': '"theirs"'})

    def test_ovh_ttl_zero_or_sixty(self):
        m = plugin('ovh')({'app_key': 'a', 'app_secret': 's', 'consumer_key': 'c', 'ttl': 30},
                          FakeCtx())
        self.assertEqual(m.ttl(), 60)
        m = plugin('ovh')({'app_key': 'a', 'app_secret': 's', 'consumer_key': 'c', 'ttl': 300},
                          FakeCtx())
        self.assertEqual(m.ttl(), 300)

    def test_ns1_other_answers_kept_whole(self):
        st = {'answers': [{'id': 'a1', 'answer': ['theirs'], 'meta': {'note': 'x'}}]}
        r = Router()
        base = 'https://api.nsone.net/v1/zones'
        r.on('GET', base + '/example.com/', lambda u, b, h: {'answers': st['answers'],
                                                             'ttl': 300})

        def post(u, b, h):
            st['answers'] = json.loads(b)['answers']
            return {}
        r.on('POST', base + '/example.com/', post)
        m = plugin('ns1')({'api_key': 'nk', 'zone': 'example.com', 'propagation': 'none'},
                          FakeCtx(http=r))
        h = m.present('www.example.com', 't', 'k', 'n1')
        self.assertEqual(st['answers'][0], {'id': 'a1', 'answer': ['theirs'],
                                            'meta': {'note': 'x'}})
        m.cleanup('www.example.com', h)
        self.assertEqual(st['answers'], [{'id': 'a1', 'answer': ['theirs'],
                                          'meta': {'note': 'x'}}])

    def test_ns1_zone_pages(self):
        from acmelib.plugins.challenges.ns1 import next_link
        nxt = 'https://api.nsone.net/v1/zones?after=x'
        self.assertEqual(next_link({'Link': '<%s>; rel="next"' % nxt}), nxt)
        self.assertIsNone(next_link({'Link': '<https://x/a>; rel="prev"'}))
        self.assertIsNone(next_link({}))

    def test_porkbun_duplicate_adopted(self):
        r = Router()
        api = 'https://api.porkbun.com/api/json/v3'
        r.on('POST', api + '/domain/listAll', lambda u, b, h: {
            'status': 'SUCCESS', 'domains': [{'domain': 'example.com'}]})
        r.on('POST', api + '/dns/retrieveByNameType/', lambda u, b, h: {
            'status': 'SUCCESS', 'records': []})
        r.on('POST', api + '/dns/create/', lambda u, b, h: (400, {
            'status': 'ERROR', 'code': 'DUPLICATE_RECORD', 'existingId': '555',
            'message': 'A record with this exact name, type and content already exists'}))
        m = plugin('porkbun')({'api_key': 'pk1', 'secret_key': 'sk1', 'propagation': 'none'},
                              FakeCtx(http=r))
        self.assertEqual(m.add_txt('_acme-challenge.www.example.com', 'p1')['id'], '555')

    def test_gcloud_pages_and_ttl_kept(self):
        st = {'changes': []}
        r = Router()
        base = 'https://dns.googleapis.com/dns/v1/projects/p1'
        r.on('POST', 'https://oauth2.googleapis.com/token', lambda u, b, h: {
            'access_token': 'GT', 'expires_in': 3600})
        r.on('GET', base + '/managedZones?pageToken=n2', lambda u, b, h: {'managedZones': [
            {'name': 'ex', 'dnsName': 'example.com.', 'visibility': 'public'}]})
        r.on('GET', base + '/managedZones/ex/rrsets', lambda u, b, h: {'rrsets': [
            {'name': '_acme-challenge.www.example.com.', 'type': 'TXT', 'ttl': 1800,
             'rrdatas': ['"theirs"']}]})
        r.on('GET', base + '/managedZones', lambda u, b, h: {'managedZones': [
            {'name': 'other', 'dnsName': 'other.org.', 'visibility': 'public'}],
            'nextPageToken': 'n2'})
        r.on('POST', base + '/managedZones/ex/changes', lambda u, b, h: (
            st['changes'].append(json.loads(b)) or {'id': '1', 'status': 'pending'}))
        m = plugin('gcloud_dns')({'service_account': json.dumps({
            'client_email': 'a@p1.iam.gserviceaccount.com', 'private_key': 'K',
            'project_id': 'p1'}), 'propagation': 'none'}, FakeCtx(http=r))
        with mock.patch.dict(type(m)._sign_in.__globals__, {'make_jwt': lambda *a, **k: 'J'}):
            m.present('www.example.com', 't', 'k', 'gv')
        add = st['changes'][0]['additions'][0]
        self.assertEqual((add['ttl'], add['rrdatas']), (1800, ['"theirs"', '"gv"']))
        self.assertEqual(st['changes'][0]['deletions'][0]['rrdatas'], ['"theirs"'])

    def test_akamai_zone_types_in_capitals(self):
        import inspect
        from acmelib.plugins.challenges.akamai_edgedns import AkamaiEdgeDns
        self.assertIn('types=PRIMARY', inspect.getsource(AkamaiEdgeDns.zone_names))


# ---------------------------------------------------------------------------
class TestDescribed(unittest.TestCase):
    def test_every_new_module_described(self):
        for kind in NEW:
            cls = plugin(kind)
            d = cls.describe()
            self.assertEqual(cls.types, ('dns-01',), kind)
            self.assertTrue(d['title'] and d['description'], kind)
            self.assertTrue([f for f in d['fields'] if f['type'] in ('secret', 'sshkey')], kind)
            keys = [f['key'] for f in d['fields']]
            self.assertEqual(len(keys), len(set(keys)), kind)
            if kind != 'windows_dns':
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
        sources = {v['source'] for v in cs['strings'].values() if v.get('text')}
        reg = Registry(extra_dirs=[]).reload()

        def words_of(d):
            out = [d['title'], d['description']]
            for f in d['fields']:
                out += [f['label'], f.get('help', ''), f.get('placeholder', '')
                        if ' ' in f.get('placeholder', '') else '']
                out += [o[1] for o in f.get('options') or []]
            return [w for w in out if w]
        missing = sorted({w for k in NEW + ('godaddy', 'hetzner')       # the forms that changed
                          for w in words_of(reg.get('challenge', k).describe())
                          if w not in sources})
        self.assertEqual(missing, [], 'web/lang/cs.json lacks these')

    def test_every_message_has_czech(self):
        """What the new modules say (form, errors, steps, answers): a sentence among the
        strings, one with %s / %d among the patterns ({0}, {1}…)."""
        import ast
        from test_ssls import _english_of_module
        with open(os.path.join(os.path.dirname(HERE), 'web', 'lang', 'cs.json'),
                  encoding='utf-8') as fh:
            cs = json.load(fh)
        known = {v['source'] for v in cs['strings'].values() if v.get('text')}
        pats = {v['source'] for v in cs['patterns'].values() if v.get('text')}
        missing = []
        for kind in NEW + CHANGED:
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
                              if s not in known and ' ' in s and kind in NEW)
            missing += sorted('%s: PATTERN %s' % (kind, p) for p in patterns
                              if p not in pats and ' ' in p and kind in NEW)
        self.assertEqual(missing, [], '\n'.join(missing))

    def test_documented(self):
        with open(os.path.join(os.path.dirname(HERE), 'docs', 'validation.md'),
                  encoding='utf-8') as fh:
            doc = fh.read()
        for kind in NEW:
            self.assertIn('(`%s`)' % kind, doc, kind)
            self.assertIn('| `%s` |' % kind, doc, kind)
        self.assertIn('ordinary Forpsi DNS', doc)
        self.assertIn('checked against the collection of 2026-11-03', doc)


if __name__ == '__main__':
    unittest.main(verbosity=2)
