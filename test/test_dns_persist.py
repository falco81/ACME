#!/usr/bin/env python3
"""dns-persist-01 (acmelib/plugins/challenges/dns_persist.py): the record set
once at _validation-persist.DOMAIN, read and judged as a CA would, the guide,
the fallback while a CA does not offer it, and a whole order against a mock
ACME CA that offers it.

    python3 -m unittest test/test_dns_persist.py -v
    python3 test/test_dns_persist.py

No network: DNS answers come from a dict, the CA is test_issuers.MockAcme.
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix='acme-persist-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "testnode", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from acmelib.plugins.base import CertRequest, Context, PluginError, Registry  # noqa: E402
from acmelib.plugins.challenges import dns_persist as DP                      # noqa: E402
from acmelib.plugins.issuers.acme import AcmeIssuer                           # noqa: E402

import test_issuers as TI                                                     # noqa: E402

LE_PROD = 'https://acme-v02.api.letsencrypt.org/acme/acct/111'
LE_STAGE = 'https://acme-staging-v02.api.letsencrypt.org/acme/acct/222'
NOW = 1800000000


# ---------------------------------------------------------------------------
# Stand-ins
# ---------------------------------------------------------------------------
class FakeSource(object):
    """What ctx.acme_sources() gives: an issuer with persist_info()."""
    def __init__(self, preset, account, directory=None, staging=False):
        self.info = {'preset': preset, 'title': {'letsencrypt': "Let's Encrypt",
                                                 'letsencrypt-staging': "Let's Encrypt (staging)"
                                                 }.get(preset, preset),
                     'directory': directory or {
                         'letsencrypt': 'https://acme-v02.api.letsencrypt.org/directory',
                         'letsencrypt-staging':
                             'https://acme-staging-v02.api.letsencrypt.org/directory'}.get(
                                 preset, 'https://ca.example/dir'),
                     'account': account, 'error': '', 'staging': staging}
        self.registered = False
        self.probed = []

    def persist_info(self, register=False):
        out = dict(self.info)
        if not out['account'] and register:
            self.registered = True
            out['account'] = 'https://ca.example/acct/new'
            self.info['account'] = out['account']
        return out

    def persist_probe(self, name):
        self.probed.append(name)
        return {'types': ['dns-01', 'dns-persist-01', 'http-01'],
                'issuer_domains': ['letsencrypt.org']}


class FakeFallback(object):
    kind = 'fake'
    types = ('dns-01',)

    def guide(self, name):
        return {'steps': [{'key': 'txt', 'what': 'fallback step for %s' % name, 'where': '',
                           'record': None, 'done': True, 'said': '', 'fix': '',
                           'blocking': False}], 'ok': True}


class Ctx(Context):
    def __init__(self, sources=None, fallbacks=None):
        self.steps, self.kv = [], {}
        self.node = 'test'
        self.settings = {}
        self._sources = sources or []
        self._fallbacks = fallbacks or {}

    def step(self, words, level='info'):
        self.steps.append((level, words))

    def kv_get(self, key, default=None):
        return self.kv.get(key, default)

    def kv_set(self, key, value, ttl_s=None):
        assert len(key) <= 120
        self.kv[key] = json.loads(json.dumps(value))

    def acme_sources(self, names=None):
        return [(n, s) for n, s in self._sources if not names or n in names]

    def validation(self, name):
        return self._fallbacks.get(name)


def module(dns, cfg=None, sources=None, fallbacks=None):
    ctx = Ctx(sources, fallbacks)
    m = DP.DnsPersist(dict(cfg or {}), ctx)
    m.txt = lambda rr: list(dns.get(rr, []))
    return m


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------
class TestRecord(unittest.TestCase):
    def test_make(self):
        self.assertEqual(DP.make_value('letsencrypt.org', LE_PROD),
                         'letsencrypt.org; accounturi=%s; policy=wildcard' % LE_PROD)
        self.assertEqual(DP.make_value('LetsEncrypt.org.', LE_PROD, wildcard=False,
                                       persist_until=1893456000),
                         'letsencrypt.org; accounturi=%s; persistUntil=1893456000' % LE_PROD)

    def test_parse(self):
        p = DP.parse_value(' LetsEncrypt.ORG ;AccountURI=%s ;  Policy=Wildcard;' % LE_PROD)
        self.assertEqual(p['error'], '')
        self.assertEqual(p['issuer'], 'letsencrypt.org')
        self.assertEqual(p['params'], {'accounturi': LE_PROD, 'policy': 'Wildcard'})
        self.assertIn('not a domain', DP.parse_value('accounturi=x')['error'])
        self.assertIn('no issuer', DP.parse_value('; accounturi=x')['error'])
        self.assertIn('tag=value', DP.parse_value('letsencrypt.org; accounturi')['error'])
        self.assertIn('twice', DP.parse_value('letsencrypt.org; a=1; A=2')['error'])
        self.assertIn('space', DP.parse_value('letsencrypt.org; accounturi=a b')['error'])
        self.assertIn('empty', DP.parse_value('letsencrypt.org;; accounturi=x')['error'])

    def test_judge_several_values(self):
        values = ['v=spf1 -all',
                  'letsencrypt.org; accounturi=%s; policy=wildcard' % LE_STAGE,
                  'letsencrypt.org; accounturi=%s; policy=wildcard' % LE_PROD,
                  'other-ca.example; accounturi=https://other/acct/1']
        self.assertTrue(DP.judge(values, ['letsencrypt.org'], LE_PROD, True, NOW)[0])
        self.assertTrue(DP.judge(values, ['letsencrypt.org'], LE_STAGE, True, NOW)[0])
        ok, probs, _w = DP.judge(values, ['letsencrypt.org'], LE_PROD + '9', False, NOW)
        self.assertFalse(ok)
        self.assertEqual(probs[0][0], 'account')
        self.assertIn(LE_PROD + '9', probs[0][1])

    def test_judge_problems(self):
        j = lambda vals, need=False: DP.judge(vals, ['letsencrypt.org'], LE_PROD, need, NOW)
        self.assertEqual(j([])[1][0][0], 'missing')
        self.assertEqual(j(['other.example; accounturi=%s' % LE_PROD])[1][0][0], 'issuer')
        self.assertIn('other.example', j(['other.example; accounturi=x'])[1][0][1])
        self.assertEqual(j(['letsencrypt.org accounturi=%s' % LE_PROD])[1][0][0], 'syntax')
        self.assertEqual(j(['letsencrypt.org; policy=wildcard'])[1][0][0], 'account')
        # policy: needed for a wildcard or a name under the record's domain only
        self.assertTrue(j(['letsencrypt.org; accounturi=%s' % LE_PROD])[0])
        self.assertEqual(j(['letsencrypt.org; accounturi=%s' % LE_PROD], True)[1][0][0], 'policy')
        self.assertEqual(j(['letsencrypt.org; accounturi=%s; policy=other' % LE_PROD],
                           True)[1][0][0], 'policy')
        # persistUntil: past, soon, not a number; unknown parameters ignored
        self.assertEqual(j(['letsencrypt.org; accounturi=%s; persistUntil=%d'
                            % (LE_PROD, NOW - 1)])[1][0][0], 'expired')
        ok, _p, warns = j(['letsencrypt.org; accounturi=%s; persistuntil=%d; foo=bar'
                           % (LE_PROD, NOW + 86400)])
        self.assertTrue(ok)
        self.assertIn('runs out', warns[0])
        self.assertEqual(j(['letsencrypt.org; accounturi=%s; persistUntil=soon' % LE_PROD]
                           )[1][0][0], 'syntax')

    def test_until(self):
        self.assertIsNone(DP.until_ts(''))
        self.assertEqual(DP.until_ts('1893456000'), 1893456000)
        self.assertEqual(DP.until_ts('2030-01-01'), 1893456000)
        with self.assertRaises(PluginError):
            DP.until_ts('next year')


# ---------------------------------------------------------------------------
# Where it is looked for
# ---------------------------------------------------------------------------
class TestPlaces(unittest.TestCase):
    def test_the_name_itself_only(self):
        """The CA looks the record up at the name itself (Let's Encrypt staging refused
        pokus.example.com with only example.com's record, 1.0.30)."""
        m = module({}, {'each_name': True})
        bare, wild, places = m.places('*.shop.example.co.uk')
        self.assertEqual((bare, wild), ('shop.example.co.uk', True))
        self.assertEqual(places, [('_validation-persist.shop.example.co.uk', True)])
        self.assertEqual(m.places('www.example.com')[2],
                         [('_validation-persist.www.example.com', False)])

    def test_each_name_off_the_draft(self):
        """"A record at each name" off: the draft - the domain's record (policy=wildcard)
        covers the names under it, looked for from the name up to the domain."""
        m = module({}, {'each_name': False})
        self.assertEqual(m.places('*.shop.example.co.uk')[2],
                         [('_validation-persist.shop.example.co.uk', True),
                          ('_validation-persist.example.co.uk', True)])
        self.assertEqual(m.places('www.example.com')[2],
                         [('_validation-persist.www.example.com', False),
                          ('_validation-persist.example.com', True)])
        d = module({}, {'each_name': False, 'domains': ['dept.example.com', 'example.com']})
        self.assertEqual(d.base_of('a.dept.example.com'), 'dept.example.com')
        self.assertEqual(d.base_of('www.example.com'), 'example.com')
        dns = {'_validation-persist.example.com': [DP.make_value('letsencrypt.org', LE_PROD)]}
        off = module(dns, {'each_name': False})
        for n in ('www.example.com', 'a.b.example.com', '*.example.com'):
            self.assertTrue(off.check_name(n, ['letsencrypt.org'], LE_PROD)[0], n)
        self.assertFalse(module(dns, {'each_name': True}).check_name('www.example.com', ['letsencrypt.org'],
                                                LE_PROD)[0], 'on: its own')
        self.assertTrue(module(dns).check_name('www.example.com', ['letsencrypt.org'],
                                               LE_PROD)[0], 'off by default: the draft')

    def test_domain_set_and_policy_off(self):
        m = module({}, {'each_name': True, 'domains': ['dept.example.com', 'example.com']})
        self.assertEqual(m.base_of('a.dept.example.com'), 'a.dept.example.com')
        self.assertEqual(m.base_of('www.example.com'), 'www.example.com')
        off = module({}, {'wildcard': False})
        self.assertEqual(off.places('www.example.com')[2],
                         [('_validation-persist.www.example.com', False)])
        ok, words, _rr = off.check_name('*.example.com', ['letsencrypt.org'], LE_PROD)
        self.assertFalse(ok)
        self.assertIn('policy=wildcard', words)

    def test_check_name(self):
        dns = {'_validation-persist.example.com': [
            DP.make_value('letsencrypt.org', LE_PROD)]}
        m = module(dns, {'each_name': True})
        for n in ('example.com', '*.example.com'):
            self.assertTrue(m.check_name(n, ['letsencrypt.org'], LE_PROD)[0], n)
        for n in ('www.example.com', 'a.b.example.com'):
            ok, words, rr = m.check_name(n, ['letsencrypt.org'], LE_PROD)
            self.assertFalse(ok, 'a record of the domain does not prove %s' % n)
            self.assertEqual(rr, '_validation-persist.' + n)
        ok, words, rr = m.check_name('example.com', ['letsencrypt.org'], LE_STAGE)
        self.assertFalse(ok)
        self.assertEqual(rr, '_validation-persist.example.com')
        self.assertIn('not this one', words)
        # a record at the name itself without policy proves the name, not a name under it
        dns2 = {'_validation-persist.www.example.com': [
            DP.make_value('letsencrypt.org', LE_PROD, wildcard=False)],
            '_validation-persist.example.com': [
            DP.make_value('letsencrypt.org', LE_PROD, wildcard=False)]}
        m2 = module(dns2, {'each_name': True})
        self.assertTrue(m2.check_name('www.example.com', ['letsencrypt.org'], LE_PROD)[0])
        ok, words, _rr = m2.check_name('*.example.com', ['letsencrypt.org'], LE_PROD)
        self.assertFalse(ok)
        self.assertIn('policy=wildcard', words)
        ok, words, _rr = module({}, {'each_name': True}).check_name('x.example.org', ['letsencrypt.org'], LE_PROD)
        self.assertIn('_validation-persist.x.example.org: there is no TXT record', words)


# ---------------------------------------------------------------------------
# The guide, the page, the actions
# ---------------------------------------------------------------------------
class TestGuide(unittest.TestCase):
    def sources(self, stage_account=LE_STAGE):
        return [('LetsEncrypt', FakeSource('letsencrypt', LE_PROD)),
                ('LetsEncrypt staging', FakeSource('letsencrypt-staging', stage_account,
                                                   staging=True))]

    def test_records_for_each_source(self):
        dns = {'_validation-persist.example.com': [DP.make_value('letsencrypt.org', LE_PROD)]}
        m = module(dns, {'fallback': 'web'}, self.sources(), {'web': FakeFallback()})
        g = m.guide('*.example.com')
        recs = [s for s in g['steps'] if s['key'] == 'persist-record']
        self.assertEqual(len(recs), 2)
        self.assertEqual({r['record']['name'] for r in recs}, {'_validation-persist.example.com'})
        self.assertEqual(sorted(r['record']['value'] for r in recs), sorted(
            [DP.make_value('letsencrypt.org', LE_PROD), DP.make_value('letsencrypt.org',
                                                                      LE_STAGE)]))
        self.assertEqual([r['done'] for r in recs], [True, False])
        # a fallback: what is missing does not block; the fallback's own steps follow
        self.assertTrue(g['ok'])
        self.assertTrue(any(s['what'].startswith('fallback step') for s in g['steps']))
        self.assertTrue(any('not known yet whether' in s['said'] for s in g['steps']
                            if s['key'] == 'persist-ca'))

    def test_no_fallback_blocks(self):
        m = module({}, {}, self.sources())
        g = m.guide('www.example.com')
        self.assertFalse(g['ok'])
        self.assertTrue(any(s['key'] == 'fallback' and s['blocking'] for s in g['steps']))
        self.assertTrue(all(s['blocking'] for s in g['steps'] if s['key'] == 'persist-record'))

    def test_one_source_of_the_certificate(self):
        m = module({}, {'fallback': 'web'}, self.sources(), {'web': FakeFallback()})
        m.persist_source = 'LetsEncrypt staging'
        recs = [s for s in m.guide('example.com')['steps'] if s['key'] == 'persist-record']
        self.assertEqual(len(recs), 1)
        self.assertIn(LE_STAGE, recs[0]['record']['value'])

    def test_no_account_yet_and_record_action(self):
        src = self.sources(stage_account=None)
        m = module({}, {'fallback': 'web', 'domains': ['example.com'],
                        'persist_until': '2030-01-01'}, src, {'web': FakeFallback()})
        steps = m.guide('example.com')['steps']
        acct = [s for s in steps if s['key'] == 'persist-account']
        self.assertEqual(len(acct), 1)
        self.assertIn('Make the record', acct[0]['fix'])
        said = m.action('record')
        self.assertTrue(src[1][1].registered)
        self.assertIn('accounturi=https://ca.example/acct/new; policy=wildcard; '
                      'persistUntil=1893456000', said)

    def test_overview_and_test(self):
        dns = {'_validation-persist.example.com': [DP.make_value('letsencrypt.org', LE_PROD)]}
        m = module(dns, {'domains': ['example.com']}, self.sources())
        got = m.overview()
        self.assertEqual([r['ok'] for r in got['records']], [True, False])
        self.assertEqual(len(got['cas']), 2)
        with self.assertRaises(PluginError) as cm:          # no fallback: the test fails
            m.test()
        self.assertIn(LE_STAGE, str(cm.exception))
        dns['_validation-persist.example.com'].append(DP.make_value('letsencrypt.org',
                                                                    LE_STAGE))
        self.assertIn('the record is right', m.test())

    def test_look_now_only_at_staging(self):
        src = self.sources()
        m = module({}, {'domains': ['example.com']}, src)
        said = m.action('look')
        self.assertEqual(src[0][1].probed, [])
        self.assertEqual(src[1][1].probed, ['example.com'])
        self.assertIn('not asked', said)
        self.assertTrue(m.offered_now(src[1][1].info['directory']))
        self.assertIn("offered by Let's Encrypt (staging) since", said)

    def test_compat_words(self):
        self.assertEqual(DP.DnsPersist.place_problem('acme-dns-persist-01', 'x', {}, {}), '')
        self.assertIn('only with an ACME source',
                      DP.DnsPersist.place_problem('txt-any', 'x', {}, {}))
        self.assertIn('HTTP-01', DP.DnsPersist.place_problem('acme-http-01', 'x', {}, {}))
        reg = Registry(extra_dirs=[]).reload()
        self.assertIn('acme-dns-persist-01',
                      reg.get('issuer', 'acme').proofs_for({'directory': 'letsencrypt'}))
        self.assertEqual(reg.get('challenge', 'dns_persist').proofs_for({}),
                         ['acme-dns-persist-01'])
        self.assertNotIn('acme-dns-persist-01', reg.get('issuer', 'digicert').proofs_for({}))

    def test_czech(self):
        """Every string of its form and its actions is in web/lang/cs.json."""
        with open(os.path.join(os.path.dirname(HERE), 'web', 'lang', 'cs.json'),
                  encoding='utf-8') as f:
            got = json.load(f)
        cs = {v['source'] for v in got['strings'].values() if v.get('text')}
        pats = {v['source'] for v in got['patterns'].values() if v.get('text')}
        d = Registry(extra_dirs=[]).reload().get('challenge', 'dns_persist').describe()
        want = [d['title'], d['description']] + [x for fl in d['fields'] for x in (
            [fl['label'], fl.get('help')] + [o[1] for o in fl.get('options') or []])] + [
            x for a in d['actions'] for x in (a['label'], a['help'])]
        self.assertEqual([s for s in want if s and s not in cs], [])
        self.assertIn('the CA does not offer dns-persist-01 yet - used {0}', pats)


# ---------------------------------------------------------------------------
# At an order
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# The record written through another validation (1.0.21)
# ---------------------------------------------------------------------------
from acmelib.plugins.challenges._common import DnsChallenge                   # noqa: E402

WRITES = []


class FakeWriter(DnsChallenge):
    """A DNS validation that writes TXT records into the `dns` dict the module reads."""
    kind = 'fakedns'
    title = 'A DNS that writes'

    def __init__(self, dns, config=None, ctx=None):
        DnsChallenge.__init__(self, dict(config or {}), ctx or Ctx())
        self.dns = dns

    def add_txt(self, fqdn, value):
        WRITES.append(('add', fqdn, value))
        vals = self.dns.setdefault(fqdn, [])
        if value not in vals:
            vals.append(value)
        return {'id': 'r%d' % len(WRITES)}

    def del_txt(self, fqdn, value, handle):
        WRITES.append(('del', fqdn, value, (handle or {}).get('id')))
        vals = self.dns.get(fqdn, [])
        if value in vals:
            vals.remove(value)


class TestWriteRecords(unittest.TestCase):
    RR = '_validation-persist.example.com'

    def setUp(self):
        WRITES[:] = []

    def make(self, dns, cfg=None, account=LE_PROD):
        src = FakeSource('letsencrypt', account)
        cfg = dict({'domains': 'example.com', 'writer': 'wr', 'fallback': 'web'}, **(cfg or {}))
        m = module(dns, cfg, [('LE', src)], {'wr': FakeWriter(dns), 'web': FakeFallback()})
        return m, src

    def test_writer_options(self):
        self.assertTrue(DP.can_write(FakeWriter))
        reg = Registry(extra_dirs=[]).reload()
        for kind in ('webglobe', 'active24', 'cloudflare', 'ssh_dns', 'route53'):
            self.assertTrue(DP.can_write(reg.get('challenge', kind)), kind)
        for kind in ('dns_builtin', 'manual', 'dns_persist', 'http_local', 'acme_dns',
                     'duckdns'):
            self.assertFalse(DP.can_write(reg.get('challenge', kind)), kind)

    def test_write_check_and_again(self):
        foreign = 'pki.goog; accounturi=https://pki.goog/acct/9'
        dns = {self.RR: [foreign]}
        m, _src = self.make(dns)
        rows = m.check_records()
        self.assertEqual([(r['domain'], r['state']) for r in rows], [('example.com', 'missing')])
        self.assertEqual(WRITES, [], 'a check changes nothing')
        words = m.action('write_records')
        self.assertIn('1 written', words)
        want = DP.make_value('letsencrypt.org', LE_PROD)
        self.assertEqual(dns[self.RR], [foreign, want])
        kept = m.written()
        self.assertEqual([(k['name'], k['value'], k['via']) for k in kept],
                         [(self.RR, want, 'wr')])
        self.assertEqual(kept[0]['handle'], {'id': 'r1'})
        self.assertEqual([(r['state'], r['written']) for r in m.check_records()],
                         [('present', True)])
        # again: nothing written twice
        self.assertIn('0 written, 1 there already', m.action('write_records'))
        self.assertEqual(len([w for w in WRITES if w[0] == 'add']), 1)

    def test_different_value_and_the_account_changed(self):
        old = DP.make_value('letsencrypt.org', 'https://acme-v02.api.letsencrypt.org/acme/acct/1')
        by_hand = DP.make_value('letsencrypt.org', 'https://acme-v02.api.letsencrypt.org/acme/'
                                                   'acct/77')
        dns = {self.RR: [old, by_hand]}
        m, _src = self.make(dns)
        # acme wrote `old` before, with the account it had then
        m.ctx.kv_set(DP.WRITTEN_KEY, [{'domain': 'example.com', 'name': self.RR, 'value': old,
                                       'account': 'x', 'source': 'LE', 'via': 'wr',
                                       'directory': 'https://acme-v02.api.letsencrypt.org/'
                                                    'directory', 'handle': {'id': 'old'},
                                       'at': 1}])
        self.assertEqual(m.check_records()[0]['state'], 'different')
        m.action('write_records')
        want = DP.make_value('letsencrypt.org', LE_PROD)
        self.assertEqual(sorted(dns[self.RR]), sorted([by_hand, want]),
                         'acme\'s old value replaced, the one set by hand left alone')
        self.assertIn(('del', self.RR, old, 'old'), WRITES)
        self.assertEqual([k['value'] for k in m.written()], [want])

    def test_take_away_only_what_acme_wrote(self):
        by_hand = DP.make_value('letsencrypt.org', 'https://acme-v02.api.letsencrypt.org/acme/'
                                                   'acct/77')
        dns = {self.RR: [by_hand]}
        m, _src = self.make(dns)
        m.action('write_records')
        self.assertEqual(len(dns[self.RR]), 2)
        self.assertEqual(m.action('remove_records'), '1 record(s) taken away')
        self.assertEqual(dns[self.RR], [by_hand])
        self.assertEqual(m.written(), [])
        self.assertIn('nothing to take away', m.action('remove_records'))

    def test_no_writer(self):
        m, _src = self.make({}, {'writer': ''})
        with self.assertRaises(PluginError) as e:
            m.action('write_records')
        self.assertIn('Write the record through', str(e.exception))
        m, _src = self.make({}, {'writer': 'nope'})
        with self.assertRaises(PluginError) as e:
            m.action('write_records')
        self.assertIn('not there or switched off', str(e.exception))

    def test_written_at_an_order_when_missing(self):
        dns = {}
        m, _src = self.make(dns, {'each_name': True})
        m.wait_visible = lambda shown, issuers, acct, seconds=0: m.check_name(shown, issuers,
                                                                              acct)
        ch = {'type': 'dns-persist-01', 'url': 'https://x/chal/1',
              'issuer-domain-names': ['letsencrypt.org']}
        how, got = m.persist_choose('www.example.com', False, {'dns-persist-01': ch}, LE_PROD,
                                    TestChoose.DIR, "Let's Encrypt")
        self.assertEqual((how, got), ('persist', ch))
        www = '_validation-persist.www.example.com'
        self.assertEqual(dns[www], [DP.make_value('letsencrypt.org', LE_PROD)],
                         'at the name itself (1.0.30)')
        # the same name again in the order: not written again; another name: its own
        m.persist_choose('www.example.com', False, {'dns-persist-01': ch}, LE_PROD,
                         TestChoose.DIR, "Let's Encrypt")
        self.assertEqual(len([w for w in WRITES if w[0] == 'add']), 1)
        m.persist_choose('example.com', True, {'dns-persist-01': ch}, LE_PROD, TestChoose.DIR,
                         "Let's Encrypt")
        self.assertEqual(len([w for w in WRITES if w[0] == 'add']), 2)
        self.assertIn(self.RR, dns)

    def test_not_written_at_an_order_when_switched_off(self):
        dns = {}
        m, _src = self.make(dns, {'write_missing': False})
        how, _got = m.persist_choose('www.example.com', False, {'dns-01': {}}, LE_PROD,
                                     TestChoose.DIR, "Let's Encrypt")
        self.assertEqual(how, 'fallback')
        self.assertEqual(WRITES, [])
        # on: written while the CA does not offer it yet, ready for the day it does
        m, _src = self.make(dns, {'each_name': True})
        m.persist_choose('www.example.com', False, {'dns-01': {}}, LE_PROD, TestChoose.DIR,
                         "Let's Encrypt")
        self.assertEqual(dns['_validation-persist.www.example.com'],
                         [DP.make_value('letsencrypt.org', LE_PROD)])


class TestChoose(unittest.TestCase):
    DIR = 'https://acme-v02.api.letsencrypt.org/directory'

    def test_not_offered_uses_fallback(self):
        fb = FakeFallback()
        m = module({}, {'fallback': 'web'}, [], {'web': fb})
        how, got = m.persist_choose('example.com', False, {'dns-01': {}, 'http-01': {}},
                                    LE_PROD, self.DIR, "Let's Encrypt")
        self.assertEqual(how, 'fallback')
        self.assertIs(got, fb)
        self.assertIn(('warn', 'the CA does not offer dns-persist-01 yet - used web'),
                      m.ctx.steps)
        st = m.ca_state(self.DIR)
        self.assertTrue(st['looked'])
        self.assertFalse(st.get('offered_since'))
        self.assertIn("not offered by Let's Encrypt yet - last looked", m.offer_words(
            st, "Let's Encrypt"))

    def test_not_offered_no_fallback(self):
        m = module({}, {})
        with self.assertRaises(PluginError) as cm:
            m.persist_choose('example.com', False, {'dns-01': {}}, LE_PROD, self.DIR, 'LE')
        self.assertIn('does not offer dns-persist-01 yet', str(cm.exception))

    def test_offered_and_right(self):
        dns = {'_validation-persist.example.com': [DP.make_value('letsencrypt.org', LE_PROD)]}
        m = module(dns, {'fallback': 'web'}, [], {'web': FakeFallback()})
        ch = {'type': 'dns-persist-01', 'url': 'https://x/chal/1',
              'issuer-domain-names': ['letsencrypt.org']}
        how, got = m.persist_choose('example.com', True, {'dns-persist-01': ch}, LE_PROD,
                                    self.DIR, "Let's Encrypt")
        self.assertEqual((how, got), ('persist', ch))
        self.assertTrue(m.offered_now(self.DIR))
        self.assertTrue(any('the first time' in w for _l, w in m.ctx.steps))
        self.assertIn("offered by Let's Encrypt since", m.offer_words(m.ca_state(self.DIR),
                                                                       "Let's Encrypt"))

    def test_offered_but_wrong(self):
        dns = {'_validation-persist.example.com': ['other.example; accounturi=x']}
        ch = {'type': 'dns-persist-01', 'url': 'u', 'issuer-domain-names': ['letsencrypt.org']}
        fb = FakeFallback()
        m = module(dns, {'fallback': 'web', 'each_name': True}, [], {'web': fb})
        how, got = m.persist_choose('www.example.com', False, {'dns-persist-01': ch,
                                                               'dns-01': {}}, LE_PROD,
                                    self.DIR, 'LE')
        self.assertEqual(how, 'fallback')
        self.assertTrue(any('the record to set' in w and LE_PROD in w for _l, w in m.ctx.steps))
        m2 = module(dns, {'each_name': True})
        with self.assertRaises(PluginError) as cm:
            m2.persist_choose('www.example.com', False, {'dns-persist-01': ch}, LE_PROD,
                              self.DIR, 'LE')
        self.assertIn('_validation-persist.www.example.com. TXT "letsencrypt.org; accounturi=%s'
                      % LE_PROD, str(cm.exception))


class PersistAcme(TI.MockAcme):
    """The mock CA, offering dns-persist-01 (issuer-domain-names ca.example) when asked."""
    def __init__(self, offer=True):
        self.offer = offer
        self.persist_dns = {}
        TI.MockAcme.__init__(self)

    def _handler(self):
        H = TI.MockAcme._handler(self)
        app = self

        class P(H):
            def new_order(self, kid, payload):
                before = set(app.authz)
                out = H.new_order(self, kid, payload)
                if app.offer:
                    for aid in set(app.authz) - before:
                        cid = app.nid()
                        app.chals[cid] = {'type': 'dns-persist-01', 'status': 'pending',
                                          'url': app.base + '/chal/' + cid, 'authz': aid,
                                          'issuer-domain-names': ['ca.example']}
                        app.authz[aid]['challenges'].append(app.chals[cid])
                return out

            def respond(self, cid, jwk):
                ch = app.chals[cid]
                if ch['type'] != 'dns-persist-01':
                    return H.respond(self, cid, jwk)
                kid = [k for k, a in app.accounts.items() if a['jwk'] == jwk][0]
                az = app.authz[ch['authz']]
                name = az['identifier']['value']
                # as Let's Encrypt (staging, 1.0.30): the record at the name itself only
                rr = DP.PREFIX + name
                ok = DP.judge(app.persist_dns.get(rr, []), ch['issuer-domain-names'], kid,
                              bool(az.get('wildcard')))[0]
                app.seen.append(('persist-answer', name))
                ch['status'] = az['status'] = 'valid' if ok else 'invalid'
                for o in app.orders.values():
                    if all(app.authz[u.rsplit('/', 1)[1]]['status'] == 'valid'
                           for u in o['authorizations']) and o['status'] == 'pending':
                        o['status'] = 'ready'
                self.send(200, ch, headers=self.common())
        return P


class TestAcmeOrder(unittest.TestCase):
    def run_order(self, offer, set_record=True):
        ca = PersistAcme(offer=offer)
        self.addCleanup(ca.close)
        ictx = TI.FakeContext()
        iss = AcmeIssuer({'directory': 'custom', 'directory_url': ca.base + '/dir',
                          'contacts': ['pki@example.com'], 'poll_every': 0.2, 'wait_ready': 10,
                          'wait_valid': 10, 'wait_order': 10}, ictx)
        fb = TI.FakeChallenge(('dns-01',), ca.board)
        ictx2 = Ctx(fallbacks={'dns': fb})
        mod = DP.DnsPersist({'fallback': 'dns', 'issuer_domain': 'ca.example'}, ictx2)
        mod.txt = lambda rr: list(ca.persist_dns.get(rr, []))
        if set_record:
            # the account first (as "Make the record" does), then the record set once
            info = iss.persist_info(register=True)
            self.assertTrue(info['account'].startswith(ca.base + '/acct/'))
            for n in ('example.com', 'www.example.com'):
                ca.persist_dns['_validation-persist.' + n] = [
                    DP.make_value('ca.example', info['account'])]
        names = ['www.example.com', '*.example.com']
        key, csr_pem, csr_der = TI.make_key_csr(names)
        got = iss.issue(CertRequest(names=names, key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                                    challenges={n: mod for n in names}))
        self.assertIn('BEGIN CERTIFICATE', got.cert_pem)
        return ca, fb, mod, ictx

    def test_used_when_offered(self):
        ca, fb, mod, ictx = self.run_order(True)
        self.assertEqual(fb.log, [])                        # nothing put in place
        self.assertEqual(sorted(n for k, n in ca.seen if k == 'persist-answer'),
                         ['example.com', 'www.example.com'])
        posted = [p for path, p in ca.seen if isinstance(path, str) and path.startswith('/chal/')]
        self.assertEqual(len(posted), 2)
        self.assertTrue(mod.offered_now(ca.base + '/dir'))
        self.assertTrue(any('dns-persist-01' in w for _l, w in ictx.steps))

    def test_fallback_when_not_offered(self):
        ca, fb, mod, _ictx = self.run_order(False, set_record=False)
        self.assertEqual(sorted(n for k, n in fb.log if k == 'present'),
                         ['example.com', 'www.example.com'])
        self.assertIn(('warn', 'the CA does not offer dns-persist-01 yet - used dns'),
                      mod.ctx.steps)
        self.assertFalse(mod.offered_now(ca.base + '/dir'))
        self.assertTrue(mod.ca_state(ca.base + '/dir').get('looked'))

    def test_fallback_when_record_missing(self):
        ca, fb, mod, _ictx = self.run_order(True, set_record=False)
        self.assertTrue(fb.log)
        self.assertTrue(any('the CA offers dns-persist-01, but' in w for _l, w in mod.ctx.steps))


# ---------------------------------------------------------------------------
# In the daemon: the sources and the fallback through RunContext, the route
# ---------------------------------------------------------------------------
class TestEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import acme as E
        from acmelib.certs import api  # noqa: F401  (the routes, api_readiness among them)
        from acmelib.certs import cli, store as S
        cls.E, cls.S = E, S
        cls.store = E.Storage(E.open_db())
        S.registry()
        cls.ca = PersistAcme(offer=False)
        cls.add('cert_issuers', 'LE', 'acme', {
            'directory': 'custom', 'directory_url': cls.ca.base + '/dir',
            'contacts': ['pki@example.com'], 'poll_every': 0.2})
        cls.add('cert_issuers', 'dc', 'digicert', {})
        cls.add('cert_challenges', 'web', 'http_local', {})
        cls.add('cert_challenges', 'persist', 'dns_persist', {
            'fallback': 'web', 'domains': ['example.com'], 'issuer_domain': 'ca.example',
            'resolvers': ['127.0.0.1:9']})
        cls.d = cli._Daemon(cls.store)

    @classmethod
    def tearDownClass(cls):
        cls.ca.close()

    @classmethod
    def add(cls, table, name, kind, cfg):
        S = cls.S
        family = {'cert_issuers': 'issuer', 'cert_challenges': 'challenge'}[table]
        ident = cls.store.db.insert(table, {'name': name, 'kind': kind, 'config': '{}',
                                            'enabled': 1, 'created': time.time(),
                                            'updated': time.time()})
        sealed = S.config_seal(cfg, {}, '%s:%s' % (table, ident),
                               S.secret_fields(S.plugin_class(family, kind)))
        cls.store.db.update(table, ident, {'config': json.dumps(sealed)})

    def call(self, method, path, body=None):
        return self.E.cli_api(self.d, 'command line', method, path, body=body)

    def test_route_context_and_compat(self):
        from acmelib.certs import compat, runtime
        got = self.call('POST', '/api/validations/persist', {'name': 'persist'})['persist']
        self.assertEqual([r['source'] for r in got['records']], ['LE'])
        self.assertIsNone(got['records'][0]['account'])
        self.assertIn('no ACME account', got['records'][0]['said'])
        got = self.call('POST', '/api/validations/persist', {'name': 'persist',
                                                             'register': True})['persist']
        acct = got['records'][0]['account']
        self.assertTrue(acct.startswith(self.ca.base + '/acct/'))
        self.assertEqual(got['records'][0]['record'], {
            'name': '_validation-persist.example.com', 'type': 'TXT', 'ttl': None,
            'value': 'ca.example; accounturi=%s; policy=wildcard' % acct})
        self.assertIs(got['records'][0]['ok'], False)        # nothing answers DNS here
        self.assertIn('could not be looked up', got['records'][0]['said'])
        # the module's Context gives the sources and the fallback
        ctx = runtime.RunContext(self.store, scope='challenge:persist')
        self.assertEqual([n for n, _i in ctx.acme_sources()], ['LE'])
        self.assertEqual(ctx.validation('web').kind, 'http_local')
        self.assertIsNone(ctx.validation('nope'))
        # compat: an ACME source takes it, another one is told in words
        self.assertEqual(compat.check(self.store, ['*.example.com'], 'LE', 'persist'), [])
        probs = compat.check(self.store, ['www.example.com'], 'dc', 'persist')
        self.assertEqual(len(probs), 1)
        self.assertIn('dns-persist-01 works only with an ACME source', probs[0]['what'])
        with self.assertRaises(SystemExit):
            self.call('POST', '/api/validations/persist', {'name': 'web'})

    def test_with_the_command_line(self):
        import subprocess
        env = dict(os.environ, NO_COLOR='1', ACME_STAY_ROOT='1')

        def acme(*args):
            return subprocess.run([sys.executable, os.path.join(os.path.dirname(HERE),
                                                                'acme.py')] + list(args),
                                  env=env, capture_output=True, text=True, timeout=180)
        got = acme('--validation-action', 'persist', 'record')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('_validation-persist.example.com. TXT "ca.example; accounturi=%s/acct/'
                      % self.ca.base, got.stdout)
        got = acme('--validation-show', 'persist')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('the record to set once (dns-persist-01)', got.stdout)
        self.assertIn('_validation-persist.example.com. TXT "ca.example; accounturi=', got.stdout)
        self.assertIn('not known yet whether', got.stdout)

    def test_written_then_deleted_with_its_records(self):
        from acmelib.plugins import base as B
        dns = {}
        B.REGISTRY.found['challenge']['fakedns'] = FakeWriter
        FakeWriter.__init__.__defaults__ = (None, None)
        real_init = FakeWriter.__init__

        def init(self, config=None, ctx=None):
            real_init(self, dns, config, ctx)
        txt = DP.DnsPersist.txt
        FakeWriter.__init__ = init
        DP.DnsPersist.txt = lambda self, rr: list(dns.get(rr, []))
        try:
            self.add('cert_challenges', 'wr', 'fakedns', {})
            self.add('cert_challenges', 'gone', 'dns_persist', {
                'fallback': 'web', 'domains': ['example.org'], 'issuer_domain': 'ca.example',
                'writer': 'wr'})
            row = self.S.plugin_row(self.store, 'challenge', 'gone')
            pub = self.S.plugin_public(self.store, 'challenge', row)
            self.assertNotIn('remove_records', [a['key'] for a in pub['actions']])
            self.assertIn('write_records', [a['key'] for a in pub['actions']])
            got = self.call('POST', '/api/validations/action', {'name': 'gone',
                                                                'action': 'write_records'})
            self.assertTrue(got['ok'], got)
            rr = '_validation-persist.example.org'
            self.assertEqual(len(dns[rr]), 1)
            dns[rr].append('ca.example; accounturi=https://elsewhere/acct/5')     # by hand
            pub = self.S.plugin_public(self.store, 'challenge', row)
            self.assertEqual(pub['persist_written'], 1)
            self.assertIn('remove_records', [a['key'] for a in pub['actions']])
            got = self.call('POST', '/api/validations/delete', {'id': row['id'], 'cleanup': 1})
            self.assertTrue(got.get('job_id'))
            self.assertEqual(dns[rr], ['ca.example; accounturi=https://elsewhere/acct/5'])
            self.assertIsNone(self.S.plugin_row(self.store, 'challenge', 'gone'))
            ev = [str(e) for e in self.store.db.rows(
                "SELECT * FROM events ORDER BY id DESC LIMIT 10")]
            self.assertTrue(any('Take the records away' in str(e) for e in ev), ev)
        finally:
            FakeWriter.__init__ = real_init
            DP.DnsPersist.txt = txt
            B.REGISTRY.found['challenge'].pop('fakedns', None)

    def test_readiness_names_the_source(self):
        from acmelib.certs import readiness
        readiness.forget()
        got = readiness.plan(self.store, ['www.example.com'], issuer='LE', challenge='persist',
                             timeout=20, suggestions='none')
        steps = got['groups'][0]['guide']['steps']
        keys = [s['key'] for s in steps]
        self.assertIn('fallback', keys)
        self.assertTrue(any(k in keys for k in ('persist-record', 'persist-account')))


class AskedAtTheSource(unittest.TestCase):
    """1.0.22: a record just written is read from the zone's own name servers - a
    resolver's "no such record", kept from a look before it was written, is not it."""

    def test_authoritative_first(self):
        from acmelib.plugins.challenges import _dns as DD
        m = DP.DnsPersist({'domains': ['example.com']}, None)
        m.resolvers = lambda: ['192.0.2.1']
        saved = (DD.find_zone, DD.zone_servers, DD.txt_at, DD.ask_any)
        try:
            DD.find_zone = lambda rr, res, timeout=3.0, rd=True: 'example.com'
            DD.zone_servers = lambda z, res, timeout=3.0: [('ns1.example.com', ['192.0.2.53'])]
            DD.txt_at = lambda a, rr, port=53, timeout=3.0, rd=False: ['fresh']

            def cached_nothing(*a, **k):
                raise AssertionError('the resolvers are not asked while a name server answers')
            DD.ask_any = cached_nothing
            self.assertEqual(m.txt('_validation-persist.example.com'), ['fresh'])
        finally:
            DD.find_zone, DD.zone_servers, DD.txt_at, DD.ask_any = saved


if __name__ == '__main__':
    unittest.main()
