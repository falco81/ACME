#!/usr/bin/env python3
"""Discovery - "Find the settings from the account" (1.0.29).

    python3 test/test_discover.py

A module's form asks only the sign-in; the module reads the rest from its
account (Plugin.discover_setup) and the form is offered it. Read-only: nothing
is ordered, changed or saved, and every field stays settable by hand.
"""
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-discover-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
# a DNS module of the test's own (the command line asks it in a process of its own)
os.makedirs(os.path.join(TMP, 'plugins', 'challenges'))
with open(os.path.join(TMP, 'plugins', 'challenges', 'discotest.py'), 'w') as f:
    f.write('''from acmelib.plugins.base import field
from acmelib.plugins.challenges._common import ApiDns


class DiscoTest(ApiDns):
    kind = 'discotest'
    title = 'Disco test'
    fields = [field('token', 'Token', 'secret', required=True), field('zone', 'Zone'),
              field('ttl', 'TTL', 'number', default=300)]

    def zone_names(self):
        return ['only.example.com']

    def discover_setup(self):
        out = ApiDns.discover_setup(self)
        out['sets']['ttl'] = 600
        return out

    def test(self):
        return 'the token works'
''')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import api_discover, runtime  # noqa: E402,F401  (the routes)
from acmelib.certs import store as S  # noqa: E402
from acmelib.plugins.base import Plugin, PluginError, field  # noqa: E402
from acmelib.plugins.challenges._common import ApiDns  # noqa: E402
from acmelib.plugins.issuers.sslmarket import SslmarketIssuer, SslmarketAcmeIssuer  # noqa: E402
from test_sslmarket import BASE, TOKEN, Ctx, FakeApi  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DOTS = '•' * 8

CONTACTS = {'owner_name': 'Firma s.r.o.', 'owner_street': 'Dlouhá 5', 'owner_city': 'Brno',
            'owner_zip': '60200', 'owner_country': 'cz', 'owner_tel': '+420.555',
            'tech_title': 'Ing.', 'tech_firstname': 'Petr', 'tech_lastname': 'Malý',
            'tech_email': 'petr@firma.cz', 'tech_tel': '+420.556',
            'invoice_name': 'Firma s.r.o.', 'invoice_ic': '12345678', 'invoice_dic': 'CZ12345678'}


class FakeH(object):
    def __init__(self, role, body=None):
        self.store, self.role, self._body = STORE, role, body or {}

    def me(self, _role):
        return {'name': 'someone', 'role': self.role}

    def body(self):
        return self._body


class TestDescribed(unittest.TestCase):
    def test_offered_and_asks_only_the_sign_in(self):
        d = SslmarketIssuer.describe()
        self.assertEqual(d['discover'], {'keys': ['api', 'api_url', 'token']})
        wd = S.plugin_class('challenge', 'wedos').describe()
        self.assertEqual(wd['discover']['keys'], ['login', 'wapi_password'])
        # a module that finds nothing has no button; SSH DNS keeps its own discovery
        self.assertIsNone(S.plugin_class('challenge', 'manual').describe()['discover'])
        self.assertIsNone(S.plugin_class('challenge', 'ssh_dns').describe()['discover'])

    def test_no_order_or_owner_field_is_asked(self):
        """The popup never asks what discovery is there to find."""
        reg = S.registry()
        for fam in ('issuer', 'challenge', 'target'):
            for kind, cls in reg.all(fam).items():
                keys = cls.discover_keys_of() if cls.discover_offered() else []
                for k in keys:
                    self.assertFalse(re.search(r'^(owner|contact|invoice|product|order)_?', k),
                                     '%s %s asks %s' % (fam, kind, k))


class TestSslmarket(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi(None)
        self.ctx = Ctx(self.api)

    def test_owner_and_contact_from_the_last_order(self):
        self.api.add_order(100, ['old.example.cz'], '2020-01-01 00:00:00')
        o = self.api.add_order(205, ['www.firma.cz', 'firma.cz'], '2099-01-01 00:00:00',
                               product='DIGICERT_SECURE_SITE')
        o['contacts'] = CONTACTS
        got = SslmarketIssuer({'token': TOKEN}, self.ctx).discover_setup()
        s = got['sets']
        self.assertEqual(s['owner_name'], 'Firma s.r.o.')
        self.assertEqual(s['owner_country'], 'CZ')
        self.assertEqual((s['contact_first'], s['contact_last'], s['contact_email']),
                         ('Petr', 'Malý', 'petr@firma.cz'))
        self.assertEqual(s['contact_title'], 'Ing.')
        self.assertEqual(s['invoice_ic'], '12345678')
        self.assertEqual(s['dcv'], 'DNS')
        prods = [x[0] for x in got['choices']['product']['options']]
        self.assertEqual(prods, ['RAPIDSSL_STANDARD', 'DIGICERT_SECURE_SITE'])
        orders = got['choices']['order_id']
        self.assertEqual(orders['pick'], '', 'an order to reuse is never picked by itself')
        self.assertEqual([x[0] for x in orders['options']], ['', '205'], 'only one that runs')
        # read-only: nothing but GETs
        self.assertEqual({c[0] for c in self.api.calls}, {'GET'})

    def test_no_order_the_organisation(self):
        got = SslmarketIssuer({'token': TOKEN}, self.ctx).discover_setup()
        self.assertEqual(got['sets']['owner_name'], 'Example s.r.o.')
        self.assertEqual(got['sets']['contact_email'], 'j@x.cz')
        self.assertNotIn('order_id', got['choices'])

    def test_the_value_set_stays_picked(self):
        got = SslmarketIssuer({'token': TOKEN, 'product': 'DIGICERT_SECURE_SITE'},
                              self.ctx).discover_setup()
        self.assertEqual(got['choices']['product']['pick'], 'DIGICERT_SECURE_SITE')

    def test_a_wrong_key_said(self):
        with self.assertRaises(PluginError) as e:
            SslmarketIssuer({'token': 'wrong'}, self.ctx).discover_setup()
        self.assertIn('refuses the API key', str(e.exception))

    def test_acme_keys(self):
        self.api.acmes.append({'acme_id': 3, 'name': 'web', 'status': 'active',
                               'product_code': 'DIGICERT_ACME_DV',
                               'certificate_validity_days': 90, 'organization_id': None,
                               'acme_directory_url': 'https://x/dir', 'inserted': '2026-01-01'})
        got = SslmarketAcmeIssuer({'token': TOKEN}, self.ctx).discover_setup()
        c = got['choices']['acme_name']
        self.assertEqual(c['pick'], 'web', 'the only key')
        self.assertEqual(c['sets']['web'], {'acme_product': 'DIGICERT_ACME_DV',
                                            'validity_days': 90})
        self.assertIn(['12', 'Example s.r.o.'], got['choices']['organization_id']['options'])


class ZonesDns(ApiDns):
    kind = 'zones_test'
    title = 'Zones'
    fields = [field('token', 'Token', 'secret', required=True), field('zone', 'Zone')]

    def zone_names(self):
        if self.c('token') != 'ok':
            raise PluginError('the token is refused')
        return ['b.example.com', 'a.example.com']


class TestDnsZones(unittest.TestCase):
    def test_zones_offered_empty_first(self):
        self.assertTrue(ZonesDns.discover_offered())
        got = ZonesDns({'token': 'ok'}, None).discover_setup()
        z = got['choices']['zone']
        self.assertEqual([x[0] for x in z['options']], ['', 'a.example.com', 'b.example.com'])
        self.assertEqual(z['pick'], '')
        got = ZonesDns({'token': 'ok', 'zone': 'b.example.com'}, None).discover_setup()
        self.assertEqual(got['choices']['zone']['pick'], 'b.example.com')

    def test_refused_said_as_a_note(self):
        got = ZonesDns({'token': 'no'}, None).discover_setup()
        self.assertIn('refused', ' '.join(got['notes']))


class TwoWays(Plugin):
    kind = 'two_ways'
    fields = [field('auth', 'Auth', 'select', default='token', options=[['token', 'T'], ['pw', 'P']]),
              field('token', 'Token', 'secret', show_if={'auth': ['token']}),
              field('password', 'Password', 'secret', show_if={'auth': ['pw']}),
              field('pick', 'Pick', 'catalog', catalog='pick', depends=['token', 'password'])]

    def catalog(self, which):
        return {'options': [['a', 'A']]}


class TestDepends(unittest.TestCase):
    def test_a_hidden_depend_is_not_needed(self):
        got = TwoWays({'auth': 'token', 'token': 't'}, None).discover_setup()
        self.assertIn('pick', got['choices'])
        got = TwoWays({'auth': 'pw'}, None).discover_setup()
        self.assertNotIn('pick', got['choices'])
        self.assertTrue(got['notes'])


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.id = A.family_save(STORE, 'issuer', {
            'name': 'sslm-disc', 'kind': 'sslmarket', 'config': {
                'token': TOKEN, 'product': 'RAPIDSSL_STANDARD', 'owner_name': 'x',
                'owner_street': 'x', 'owner_city': 'x', 'owner_zip': '1', 'owner_country': 'CZ',
                'owner_tel': '+420.1', 'contact_first': 'x', 'contact_last': 'x',
                'contact_email': 'x@example.cz', 'contact_tel': '+420.1'}}, 'tester')
        cls.api = FakeApi(None)
        o = cls.api.add_order(300, ['www.firma.cz'], '2099-01-01 00:00:00')
        o['contacts'] = CONTACTS
        cls._http = runtime.RunContext.http
        fake = cls.api

        def http(self, method, url, *a, **kw):
            if url.startswith(BASE):
                return fake(method, url, *a, **kw)
            return cls._http(self, method, url, *a, **kw)
        runtime.RunContext.http = http

    @classmethod
    def tearDownClass(cls):
        runtime.RunContext.http = cls._http

    def call(self, role, body):
        return E.ROUTES[('POST', '/api/sources/discover')](FakeH(role, body))

    def test_kept_token_used_nothing_saved(self):
        before = S.plugin_config('issuer', S.plugin_row(STORE, 'issuer', self.id))
        got = self.call('certadmin', {'id': self.id, 'config': {'token': DOTS}})
        self.assertTrue(got['worked'], got)
        self.assertEqual(got['found']['sets']['owner_city'], 'Brno')
        self.assertIn('product', got['found']['choices'])
        self.assertTrue(got['job_id'])
        after = S.plugin_config('issuer', S.plugin_row(STORE, 'issuer', self.id))
        self.assertEqual(before, after, 'nothing saved')
        json.dumps(got)

    def test_secrets_never_sent_back(self):
        got = self.call('fulladmin', {'id': self.id, 'config': {'token': DOTS}})
        self.assertNotIn('token', got['found']['sets'])
        self.assertNotIn(TOKEN, json.dumps(got))

    def test_another_address_with_the_kept_key_refused(self):
        with self.assertRaises(E.ApiError) as e:
            self.call('certadmin', {'id': self.id, 'config': {
                'token': DOTS, 'api': 'custom', 'api_url': 'https://collector.example.net'}})
        self.assertEqual(e.exception.status, 403)

    def test_a_module_without_discovery(self):
        with self.assertRaises(ValueError):
            self.call('fulladmin', {'kind': 'manual', 'config': {}})

    def test_failure_said_in_words(self):
        got = self.call('fulladmin', {'kind': 'sslmarket', 'config': {'token': 'bad'}})
        self.assertTrue(got['ok'], 'answered')
        self.assertFalse(got['worked'])
        self.assertIn('set by hand', got['said'])


class TestCli(unittest.TestCase):
    def cli(self, *args):
        import subprocess
        got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(args),
                             env=dict(os.environ), capture_output=True, text=True, timeout=120)
        self.assertEqual(got.returncode, 0, got.stdout[-1500:] + got.stderr[-1500:])
        return got

    def test_shown_then_filled(self):
        A.family_save(STORE, 'challenge', {'name': 'disco', 'kind': 'discotest',
                                           'config': {'token': 'tok-kept'}}, 'tester')
        got = json.loads(self.cli('--validation-discover', 'disco', '--json').stdout)
        self.assertEqual(got['would_fill'], {'ttl': 600}, 'a zone is never picked by itself')
        out = self.cli('--validation-discover', 'disco').stdout
        self.assertIn('only.example.com', out)
        self.assertIn('--fill', out)
        row = S.plugin_row(STORE, 'challenge', 'disco')
        self.assertNotIn('zone', S.plugin_config('challenge', row), 'nothing saved without --fill')
        self.cli('--validation-discover', 'disco', '--fill')
        cfg = S.plugin_config('challenge', S.plugin_row(STORE, 'challenge', 'disco'))
        self.assertEqual(cfg['ttl'], 600)
        self.assertNotIn('zone', cfg)
        self.assertEqual(cfg['token'], 'tok-kept', 'the secret kept')
        out = self.cli('--validation-discover', 'disco', '--fill').stdout
        self.assertIn('nothing to fill in', out)


class TestPage(unittest.TestCase):
    def test_loaded_and_drawn(self):
        with open(os.path.join(ROOT, 'web', 'admin', 'index.php'), encoding='utf-8') as f:
            self.assertIn('/assets/discover.js?v=', f.read())
        with open(os.path.join(ROOT, 'web', 'assets', 'certs.js'), encoding='utf-8') as f:
            src = f.read()
        self.assertIn('window.ACME_DISCOVER({form: form', src)

    def test_every_word_has_czech(self):
        with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
            cs = json.load(f)
        known = {v['source'] for v in cs['strings'].values()}
        with open(os.path.join(ROOT, 'web', 'assets', 'discover.js'), encoding='utf-8') as f:
            src = f.read()
        words = set(re.findall(r"(?:el|cmdButton|tr_|toast|data|modal)\([^'\n]*?'([A-Z\u2013][^']{2,})'", src))
        words |= set(re.findall(r"words: '([^']+)'", src))
        words |= {'Field', 'Now in the form', 'From the account'}
        words -= {'Close'}
        missing = sorted(w for w in words if w not in known)
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
