#!/usr/bin/env python3
"""A certificate's own settings of its source and validations (1.0.24, profile.over).

    python3 test/test_cert_over.py

Add a certificate → Settings: each setting a certificate may set itself is shown
with the source's (or validation's) value, and "Own" gives it a value for this
certificate only. Checked here: which fields may be set (never a secret, where or
as whom a module signs in, nor a command, a path or sudo), how the values are
checked when saved, and that the module is built with them - the renewal, the
plan, the check of what fits - while the source stays as it is for the others.
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-cert-over-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import store as S, compat, runplan  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def keys(family, kind):
    return [f['key'] for f in S.over_fields(S.plugin_class(family, kind))]


class Fields(unittest.TestCase):
    def test_what_a_certificate_may_set(self):
        adcs = keys('issuer', 'ms_adcs')
        self.assertIn('template', adcs)
        self.assertIn('key_kinds', adcs)
        for k in ('url', 'user', 'password', 'auth', 'domain', 'client_key', 'ca_pem'):
            self.assertNotIn(k, adcs)
        acme = keys('issuer', 'acme')
        for k in ('directory_url', 'account_key', 'contacts', 'profile', 'eab_hmac'):
            self.assertNotIn(k, acme)
        self.assertIn('zone', keys('challenge', 'wedos'))
        self.assertNotIn('login', keys('challenge', 'wedos'))
        self.assertNotIn('wapi_password', keys('challenge', 'wedos'))
        # never what runs or is written where: a full administrator's alone
        self.assertEqual([k for k in keys('challenge', 'script') if k in ('path', 'env', 'style')], [])
        ssh = keys('challenge', 'http_ssh')
        for k in ('webroot', 'sudo', 'command_after', 'hosts', 'nginx_conf'):
            self.assertNotIn(k, ssh)
        for k in keys('challenge', 'ssh_dns'):
            self.assertFalse(S.OVER_NEVER.search(k), k)
        for fam in ('issuer', 'challenge'):
            for cls in S.registry().all()[fam].values():
                for f in S.over_fields(cls):
                    self.assertNotEqual(f.get('type'), 'secret', (cls.kind, f['key']))
                    self.assertFalse(f.get('secret'), (cls.kind, f['key']))

    def test_described_for_the_page(self):
        d = A.plugins_view(STORE)
        one = [x for x in d['issuer'] if x['kind'] == 'ms_adcs'][0]
        self.assertIn('template', one['cert_fields'])
        self.assertNotIn('password', one['cert_fields'])


class Saved(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.family_save(STORE, 'issuer', {'name': 'Win CA', 'kind': 'ms_adcs', 'config': {
            'url': 'https://ca01.example.local', 'template': 'WebServer', 'auth': 'basic',
            'user': 'svc', 'password': 'Pw-1', 'key_kinds': 'rsa'}}, 'tester')
        A.family_save(STORE, 'challenge', {'name': 'wedos-x', 'kind': 'wedos', 'config': {
            'login': 'me@example.cz', 'wapi_password': 'WPw-2', 'zone': 'example.cz'}}, 'tester')

    def save(self, over, name='web01.example.local', **more):
        b = {'name': name, 'names': [name], 'issuer': 'Win CA', 'key_type': 'rsa-2048',
             'profile': {'over': over}}
        b.update(more)
        return A.cert_save(STORE, b, 'tester')

    def test_kept_checked_and_used(self):
        got = self.save({'source': {'template': 'WebServerV3', 'key_kinds': 'any'}})
        cid = got['id'] if isinstance(got, dict) else got
        row = S.cert_need(STORE, cid)
        prof = json.loads(row['profile'])
        self.assertEqual(prof['over'], {'source': {'template': 'WebServerV3', 'key_kinds': 'any'}})
        # the module is made with them; the source itself is as it was
        irow = S.plugin_row(STORE, 'issuer', 'Win CA')
        inst = S.plugin_instance(STORE, 'issuer', irow, None, S.cert_over(row, 'issuer'))
        self.assertEqual(inst.c('template'), 'WebServerV3')
        self.assertEqual(inst.c('user'), 'svc')
        self.assertEqual(S.plugin_config('issuer', irow)['template'], 'WebServer')
        # what fits follows them: an EC key with key_kinds rsa at the source, any here
        def key_problems(over):
            return [p for p in compat.check(STORE, ['web02.example.local'], 'Win CA',
                                            key_type='ec-256', profile={'over': over})
                    if p.get('step') == 'key']
        self.assertTrue(key_problems({}))
        self.assertFalse(key_problems({'source': {'key_kinds': 'any'}}))
        # the plan shows the template it will ask for
        p = runplan.plan(STORE, row, [])
        self.assertIn('WebServerV3', json.dumps(p))

    def test_refused(self):
        for over, words in (({'source': {'password': 'x'}}, 'cannot set'),
                            ({'source': {'url': 'https://evil.example'}}, 'cannot set'),
                            ({'source': {'key_kinds': 'dsa'}}, 'one of'),
                            ({'source': 'x'}, 'object'),
                            ({'validation': {'nope': {'zone': 'x'}}}, 'no validation')):
            with self.assertRaises(ValueError) as e:
                self.save(over, name='bad.example.local')
            self.assertIn(words, str(e.exception))

    def test_a_validation_it_does_not_use_is_dropped(self):
        got = self.save({'validation': {'wedos-x': {'zone': 'other.cz'}}}, name='v1.example.local')
        cid = got['id'] if isinstance(got, dict) else got
        self.assertNotIn('over', json.loads(S.cert_need(STORE, cid)['profile']))
        with self.assertRaises(ValueError):
            A.cert_save(STORE, {'id': cid, 'challenge': 'wedos-x', 'profile': {
                'over': {'validation': {'wedos-x': {'wapi_password': 'x'}}}}}, 'tester')
        A.cert_save(STORE, {'id': cid, 'challenge': 'wedos-x', 'profile': {
            'over': {'validation': {'wedos-x': {'zone': 'other.cz', 'ttl': '120'}}}}}, 'tester')
        row = S.cert_need(STORE, cid)
        self.assertEqual(S.cert_over(row, 'challenge', 'wedos-x'), {'zone': 'other.cz', 'ttl': 120})
        crow = S.plugin_row(STORE, 'challenge', 'wedos-x')
        inst = S.plugin_instance(STORE, 'challenge', crow, None,
                                 S.cert_over(row, 'challenge', 'wedos-x'))
        self.assertEqual(inst.c('zone'), 'other.cz')
        self.assertEqual(inst.c('wapi_password'), 'WPw-2')

    def test_config_over_only_its_fields(self):
        cls = S.plugin_class('issuer', 'ms_adcs')
        got = S.config_over(cls, {'url': 'a', 'template': 'T'}, {'url': 'b', 'template': 'U'})
        self.assertEqual(got, {'url': 'a', 'template': 'U'})
        self.assertEqual(S.cert_over({'profile': '{}'}, 'issuer'), {})
        self.assertEqual(S.cert_over({'profile': 'not json'}, 'challenge', 'x'), {})


if __name__ == '__main__':
    try:
        unittest.main(verbosity=1)
    except PluginError:
        raise
