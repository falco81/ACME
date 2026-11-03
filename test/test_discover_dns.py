#!/usr/bin/env python3
"""Discovery of the DNS validations - "Find the settings from the account" (1.0.29).

    python3 test/test_discover_dns.py

Each DNS module that can read its account offers what it found: the zones, and the
fields a zone lives in (a hosted-zone id, a resource group, a managed zone, a server,
a view, an endpoint). Every answer here comes from a fake of the provider's API, and
every request a discovery makes is a read (GET, or the sign-in's token POST).
"""
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-discover-dns-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
from acmelib.certs import api_discover  # noqa: E402
from acmelib.certs import store as S  # noqa: E402
from acmelib.plugins.challenges._common import DnsChallenge  # noqa: E402
from test_challenges import FakeCtx, Router, plugin  # noqa: E402

PROTECTED = {'active24': ['platform', 'api_key', 'api_secret', 'token', 'api'],
             'wedos': ['login', 'wapi_password'], 'czechia': ['token', 'api'],
             'webglobe': ['login', 'auth', 'api_token', 'password', 'endpoint', 'api'],
             'websupport': ['api_key', 'api_secret', 'api'],
             'subreg': ['login', 'password', 'api']}
NOTHING = ('script', 'manual', 'acme_dns', 'dns_builtin', 'dns_persist', 'rfc2136', 'he_net',
           'duckdns', 'easydns', 'infomaniak', 'netcup', 'ssh_dns', 'windows_dns',
           'http_local', 'http_ssh', 'http_ftp', 'http_s3', 'http_webdav', 'http_azure_blob')


class Reads(Router):
    """A Router that writes down every request: discovery only reads."""
    def __init__(self, token_posts=()):
        Router.__init__(self)
        self.calls = []
        self.token_posts = tuple(token_posts)

    def __call__(self, method, url, body, headers):
        self.calls.append((method, url))
        return Router.__call__(self, method, url, body, headers)

    def only_reads(self, t):
        for m, u in self.calls:
            t.assertTrue(m == 'GET' or (m == 'POST' and u.startswith(self.token_posts)),
                         'discovery wrote: %s %s' % (m, u))


def found(kind, http, **cfg):
    m = plugin(kind)(cfg, FakeCtx(http=http))
    got = m.discover_setup()
    clean = api_discover._clean(type(m), got)
    # every key offered is a field of the module, none a secret
    for k in list(got['sets']) + list(got['choices']):
        assert k in clean['sets'] or k in clean['choices'], (kind, k)
    for c in got['choices'].values():
        for more in c['sets'].values():
            assert set(more) <= {f['key'] for f in type(m).fields}, (kind, more)
            assert not set(more) & S.secret_fields(type(m)), (kind, more)
    return got


def values(choice):
    return [o[0] for o in choice['options']]


class TestOffered(unittest.TestCase):
    def test_which_offer_and_what_they_ask(self):
        want = {'cloudflare': ['token', 'api'], 'digitalocean': ['token'],
                'hetzner': ['token'],
                'ovh': ['endpoint', 'app_key', 'app_secret', 'consumer_key'],
                'powerdns': ['url', 'api_key', 'verify_tls'],
                'route53': ['access_key_id', 'secret_access_key', 'session_token', 'partition'],
                'azure_dns': ['tenant_id', 'client_id', 'client_secret', 'subscription_id',
                              'cloud'],
                'gcloud_dns': ['service_account', 'project'],
                'efficientip': ['host', 'user', 'password', 'verify_tls', 'ca_pem'],
                'infoblox': ['url', 'wapi_version', 'username', 'password', 'verify_tls',
                             'ca_pem'],
                'cloudns': ['user_kind', 'auth_id', 'auth_password'],
                'ionos': ['prefix', 'secret'], 'rackspace': ['user', 'api_key', 'identity'],
                'oci_dns': ['tenancy', 'user', 'fingerprint', 'key', 'region', 'api'],
                'namecheap': ['api_user', 'api_key', 'client_ip', 'user_name', 'endpoint']}
        for kind, keys in want.items():
            d = plugin(kind).describe()
            self.assertEqual(d['discover'], {'keys': keys}, kind)

    def test_nothing_to_find_no_button(self):
        for kind in NOTHING:
            self.assertIsNone(S.plugin_class('challenge', kind).describe()['discover'], kind)

    def test_protected_modules_as_they_were(self):
        for kind, keys in PROTECTED.items():
            cls = plugin(kind)
            self.assertTrue(cls.discover_offered(), kind)
            self.assertEqual(cls.discover_keys_of(), keys, kind)
            self.assertIs(cls.discover_setup, DnsChallenge.discover_setup, kind)


class TestCloudflare(unittest.TestCase):
    CF = 'https://api.cloudflare.com/client/v4'

    def test_zone_ids_and_the_account(self):
        r = Reads()
        page1 = [{'id': 'Z%02d' % i, 'name': 'z%02d.example' % i, 'status': 'active',
                  'account': {'id': 'A1', 'name': 'Firma'}} for i in range(50)]
        page2 = [{'id': 'ZB', 'name': 'b.example.com', 'status': 'pending',
                  'account': {'id': 'A2', 'name': 'Druha'}}]
        r.on('GET', self.CF + '/zones?per_page=50&page=1', lambda u, b, h: {
            'success': True, 'result': page1})
        r.on('GET', self.CF + '/zones?per_page=50&page=2', lambda u, b, h: {
            'success': True, 'result': page2})
        got = found('cloudflare', r, token='tok')
        c = got['choices']['zone_id']
        self.assertEqual(c['options'][0], ['', 'Empty: found by the name.'])
        self.assertIn(['ZB', 'b.example.com (pending)'], c['options'])
        self.assertEqual(len(c['options']), 52)
        self.assertEqual(c['pick'], '')
        self.assertIn(['Account', 'Firma (A1)'], got['facts'])
        self.assertIn(['Account', 'Druha (A2)'], got['facts'])
        self.assertIn(['Zones the account sees', '51'], got['facts'])
        r.only_reads(self)
        got = found('cloudflare', r, token='tok', zone_id='ZB')
        self.assertEqual(got['choices']['zone_id']['pick'], 'ZB')

    def test_refused_said(self):
        r = Reads().on('GET', self.CF + '/zones', lambda u, b, h: (403, {
            'success': False, 'errors': [{'code': 9109, 'message': 'Invalid access token'}]}))
        got = found('cloudflare', r, token='bad')
        self.assertEqual(got['choices'], {})
        self.assertIn('Invalid access token', ' '.join(got['notes']))


class TestDigitalOcean(unittest.TestCase):
    def test_domains_of_every_page(self):
        r = Reads()
        base = 'https://api.digitalocean.com/v2/domains?per_page=200&page='
        r.on('GET', base + '1', lambda u, b, h: {
            'domains': [{'name': 'example.com'}],
            'links': {'pages': {'next': base + '2'}}})
        r.on('GET', base + '2', lambda u, b, h: {'domains': [{'name': 'other.org'}],
                                                  'links': {}})
        got = found('digitalocean', r, token='T')
        self.assertEqual(values(got['choices']['zone']), ['', 'example.com', 'other.org'])
        r.only_reads(self)


class TestHetzner(unittest.TestCase):
    def test_primary_zones_paged(self):
        r = Reads()
        api = 'https://api.hetzner.cloud/v1/zones?page='
        r.on('GET', api + '1&', lambda u, b, h: {
            'zones': [{'id': 1, 'name': 'example.com', 'mode': 'primary'},
                      {'id': 2, 'name': 'sec.example', 'mode': 'secondary'}],
            'meta': {'pagination': {'page': 1, 'next_page': 2}}})
        r.on('GET', api + '2&', lambda u, b, h: {
            'zones': [{'id': 3, 'name': 'other.org', 'mode': 'primary'}],
            'meta': {'pagination': {'page': 2, 'next_page': None}}})
        got = found('hetzner', r, token='T')
        self.assertEqual(values(got['choices']['zone']), ['', 'example.com', 'other.org'])
        self.assertIn('1 secondary zone(s)', ' '.join(got['notes']))
        r.only_reads(self)


class TestOvh(unittest.TestCase):
    def test_zones(self):
        r = Reads().on('GET', 'https://eu.api.ovh.com/1.0/domain/zone', lambda u, b, h: [
            'example.com', 'other.org'])
        got = found('ovh', r, app_key='a', app_secret='s', consumer_key='c')
        self.assertEqual(values(got['choices']['zone']), ['', 'example.com', 'other.org'])
        self.assertNotIn('endpoint', got['choices'])
        r.only_reads(self)

    def test_keys_of_another_endpoint(self):
        r = Reads()
        r.on('GET', 'https://eu.api.ovh.com/1.0/domain/zone', lambda u, b, h: (
            403, {'message': 'This application key is invalid'}))
        r.on('GET', 'https://ca.api.ovh.com/1.0/domain/zone', lambda u, b, h: ['example.ca'])
        r.on('GET', 'https://api.us.ovhcloud.com/1.0/domain/zone', lambda u, b, h: (
            403, {'message': 'This application key is invalid'}))
        got = found('ovh', r, endpoint='ovh-eu', app_key='a', app_secret='s',
                    consumer_key='c')
        self.assertEqual(got['choices']['endpoint']['options'], [['ovh-ca', 'OVH Canada']])
        self.assertEqual(got['choices']['endpoint']['pick'], 'ovh-ca')
        self.assertEqual(values(got['choices']['zone']), ['', 'example.ca'])
        self.assertIn('application key is invalid', ' '.join(got['notes']))
        r.only_reads(self)


class TestPowerDns(unittest.TestCase):
    URL = 'http://pdns:8081/api/v1'

    def router(self, servers):
        r = Reads()
        r.on('GET', self.URL + '/servers/localhost/zones', lambda u, b, h: [
            {'id': 'example.com.', 'name': 'example.com.'}])
        r.on('GET', self.URL + '/servers/ns1/zones', lambda u, b, h: [
            {'id': 'other.org.', 'name': 'other.org.'}])
        r.on('GET', self.URL + '/servers', lambda u, b, h: servers)
        return r

    def test_server_and_zones(self):
        r = self.router([{'id': 'localhost', 'daemon_type': 'authoritative',
                          'version': '4.9.12'}])
        got = found('powerdns', r, url='http://pdns:8081', api_key='k')
        self.assertEqual(got['choices']['server_id']['options'],
                         [['localhost', 'localhost (PowerDNS 4.9.12)']])
        self.assertEqual(got['choices']['server_id']['pick'], 'localhost')
        self.assertEqual(values(got['choices']['zone']), ['', 'example.com'])
        self.assertIn(['Version', 'PowerDNS 4.9.12'], got['facts'])
        self.assertEqual(got['notes'], [])
        r.only_reads(self)

    def test_another_server_id_listed_and_old_version_said(self):
        r = self.router([{'id': 'ns1', 'daemon_type': 'authoritative', 'version': '4.8.3'},
                         {'id': 'rec', 'daemon_type': 'recursor', 'version': '5.0'}])
        got = found('powerdns', r, url='http://pdns:8081', api_key='k')
        self.assertEqual(values(got['choices']['server_id']), ['ns1'])
        self.assertEqual(values(got['choices']['zone']), ['', 'other.org'])
        self.assertIn('older than 4.9.12', ' '.join(got['notes']))


class TestRoute53(unittest.TestCase):
    NS = 'https://route53.amazonaws.com/doc/2013-04-01/'

    def test_public_hosted_zones_paged(self):
        r = Reads()

        def zones(u, b, h):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query)
            if 'marker' not in q:
                body = ('<HostedZone><Id>/hostedzone/ZPUB</Id><Name>example.com.</Name>'
                        '<Config><PrivateZone>false</PrivateZone></Config></HostedZone>'
                        '<HostedZone><Id>/hostedzone/ZPRIV</Id><Name>example.com.</Name>'
                        '<Config><PrivateZone>true</PrivateZone></Config></HostedZone>')
                more = '<IsTruncated>true</IsTruncated><NextMarker>Z2</NextMarker>'
            else:
                self.assertEqual(q['marker'], ['Z2'])
                body = ('<HostedZone><Id>/hostedzone/Z2</Id><Name>other.org.</Name>'
                        '<Config><PrivateZone>false</PrivateZone></Config></HostedZone>')
                more = '<IsTruncated>false</IsTruncated>'
            return ('<ListHostedZonesResponse xmlns="%s"><HostedZones>%s</HostedZones>%s'
                    '<MaxItems>100</MaxItems></ListHostedZonesResponse>' % (
                        self.NS, body, more)).encode()
        r.on('GET', 'https://route53.amazonaws.com/2013-04-01/hostedzone?', zones)
        got = found('route53', r, access_key_id='AKID', secret_access_key='S',
                    hosted_zone_id='/hostedzone/Z2')
        c = got['choices']['hosted_zone_id']
        self.assertEqual(c['options'], [
            ['', 'Empty: found by the name (a public zone first).'],
            ['ZPUB', 'example.com (ZPUB)'], ['Z2', 'other.org (Z2)']])
        self.assertEqual(c['pick'], 'Z2')
        self.assertIn('1 private zone(s)', ' '.join(got['notes']))
        r.only_reads(self)


class TestAzure(unittest.TestCase):
    MG = 'https://management.azure.com'

    def test_zones_with_their_resource_groups(self):
        r = Reads(token_posts=('https://login.microsoftonline.com/',))
        r.on('POST', 'https://login.microsoftonline.com/T/oauth2/v2.0/token', lambda u, b, h: {
            'access_token': 'AT', 'expires_in': 3600})
        zid = '/subscriptions/S/resourceGroups/%s/providers/Microsoft.Network/dnsZones/%s'
        r.on('GET', self.MG + '/subscriptions/S/providers/Microsoft.Network/dnsZones?',
             lambda u, b, h: {'value': [
                 {'name': 'example.com', 'id': zid % ('rg-web', 'example.com')},
                 {'name': 'twice.org', 'id': zid % ('rg-a', 'twice.org')}],
                 'nextLink': self.MG + '/next-page'})
        r.on('GET', self.MG + '/next-page', lambda u, b, h: {'value': [
            {'name': 'twice.org', 'id': zid.replace('resourceGroups', 'resourcegroups') % (
                'rg-b', 'twice.org')}]})
        got = found('azure_dns', r, tenant_id='T', client_id='C', client_secret='X',
                    subscription_id='S', resource_group='RG-WEB')
        z = got['choices']['zone']
        self.assertEqual(values(z), ['', 'example.com', 'twice.org'])
        self.assertEqual(z['sets'], {'example.com': {'resource_group': 'rg-web'}})
        g = got['choices']['resource_group']
        self.assertEqual(values(g), ['', 'rg-a', 'rg-b', 'rg-web'])
        self.assertEqual(g['pick'], 'rg-web')
        self.assertIn(['Zones the account sees', '3'], got['facts'])
        r.only_reads(self)


class TestGoogleCloud(unittest.TestCase):
    def test_public_managed_zones_of_the_project(self):
        r = Reads().on('GET', 'https://dns.googleapis.com/dns/v1/projects/p1/managedZones',
                       lambda u, b, h: {'managedZones': [
                           {'name': 'web', 'dnsName': 'example.com.', 'visibility': 'public'},
                           {'name': 'inner', 'dnsName': 'corp.example.', 'visibility':
                            'private'}]})
        sa = json.dumps({'client_email': 'acme@p1.iam.gserviceaccount.com',
                         'private_key': 'x', 'project_id': 'p1'})
        m = plugin('gcloud_dns')({'service_account': sa}, FakeCtx(http=r))
        m._token, m._token_until = 'AT', time.time() + 3600
        got = m.discover_setup()
        c = got['choices']['managed_zone']
        self.assertEqual(c['options'], [['', 'Empty: found by the domain'],
                                        ['web', 'example.com (web)']])
        self.assertIn(['Project', 'p1'], got['facts'])
        self.assertIn(['Service account', 'acme@p1.iam.gserviceaccount.com'], got['facts'])
        self.assertIn('1 private zone(s)', ' '.join(got['notes']))
        r.only_reads(self)

    def test_a_key_that_is_not_json(self):
        got = plugin('gcloud_dns')({'service_account': 'nope'}, FakeCtx(http=Reads())) \
            .discover_setup()
        self.assertIn('not JSON', ' '.join(got['notes']))


class TestEfficientIp(unittest.TestCase):
    def test_server_view_and_zones(self):
        r = Reads().on('GET', 'https://sds/api/v2.0/dns/zone/list', lambda u, b, h: {
            'success': True, 'data': [
                {'zone_name': 'example.com', 'server_name': 'smart.local', 'view_name': 'ext'},
                {'zone_name': 'corp.local', 'server_name': 'smart.local', 'view_name': 'int'},
                {'zone_name': '1.168.192.in-addr.arpa', 'server_name': 'smart.local',
                 'view_name': 'int', 'zone_is_reverse': '1'}]})
        got = found('efficientip', r, host='sds', user='u', password='p')
        self.assertEqual(got['choices']['server']['options'], [['smart.local', 'smart.local']])
        self.assertEqual(got['choices']['server']['pick'], 'smart.local')
        self.assertEqual(values(got['choices']['view']), ['', 'ext', 'int'])
        z = got['choices']['zone']
        self.assertEqual(values(z), ['', 'corp.local', 'example.com'])
        self.assertEqual(z['sets']['example.com'], {'view': 'ext'})
        r.only_reads(self)


class TestInfoblox(unittest.TestCase):
    def test_views_and_zones(self):
        base = 'https://gm/wapi/v2.10'
        r = Reads()
        r.on('GET', base + '/zone_auth?view=default', lambda u, b, h: [
            {'_ref': 'zone_auth/x', 'fqdn': 'example.com'}])
        r.on('GET', base + '/view?', lambda u, b, h: [
            {'_ref': 'view/a', 'name': 'default'}, {'_ref': 'view/b', 'name': 'external'}])
        got = found('infoblox', r, url='https://gm', username='u', password='p')
        self.assertEqual(values(got['choices']['view']), ['default', 'external'])
        self.assertEqual(got['choices']['view']['pick'], 'default')
        self.assertEqual(values(got['choices']['zone']), ['', 'example.com'])
        self.assertIn('view default', ' '.join(got['notes']))
        r.only_reads(self)


class TestDnsimple(unittest.TestCase):
    def test_the_account_of_the_token(self):
        api = 'https://api.dnsimple.com/v2'
        r = Reads()
        r.on('GET', api + '/whoami', lambda u, b, h: {'data': {
            'account': {'id': 1010, 'email': 'it@example.com'}, 'user': None}})
        r.on('GET', api + '/1010/zones', lambda u, b, h: {
            'data': [{'name': 'example.com'}], 'pagination': {'total_pages': 1}})
        got = found('dnsimple', r, token='T')
        self.assertEqual(values(got['choices']['zone']), ['', 'example.com'])
        self.assertIn(['Account', 'it@example.com (1010)'], got['facts'])
        r.only_reads(self)


if __name__ == '__main__':
    unittest.main()
