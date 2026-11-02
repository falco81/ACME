#!/usr/bin/env python3
"""Import from a source (acmelib/certs/onlineimport.py) and a private key added
later - against the fake servers of the sources' own tests.

    python3 test/test_online_import.py

- SSLS.cz (test_ssls.FakeSapi): the account's certificates listed (myCerts), each
  marked when acme has it already (by the id kept, by the order acme made, by its
  serial); the picked ones imported in a job - bound to the source with their SSLS
  ID, no key; the key added later (a wrong one refused); a deployment that needs the
  key refused in words until then, one that needs only the certificate done; a
  renewal reissues that very SSLS ID (quickReissue of it, whatever "Certificate to
  reuse" says) with a new key acme holds from then on;
- SSLmarket (test_sslmarket.FakeApi): the order list, a download, a reissue of the
  imported order;
- acme's own authority: what it signed and acme does not keep, imported;
- DigiCert, Vault, Google CA Service, GlobalSign Atlas, EJBCA, FreeIPA: their list
  and fetch calls against canned answers of their documented shapes;
- who may: a scoped certificate administrator imports only for a team they may
  ask for, and adds a key only to a certificate they manage.
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
TMP = tempfile.mkdtemp(prefix='acme-onlineimport-')
os.makedirs(os.path.join(TMP, 'plugins', 'targets'), exist_ok=True)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
with open(os.path.join(TMP, 'plugins', 'targets', 'oi_test_targets.py'), 'w') as f:
    f.write('''
from acmelib.plugins.base import Target


class CertOnly(Target):
    kind = 'oi_certonly'
    title = 'Only the certificate (tests)'

    def deploy(self, bundle, options):
        bundle.as_format('fullchain-pem')
        return 'the certificate put in place'


class NeedsKey(Target):
    kind = 'oi_needskey'
    title = 'Certificate and key (tests)'

    def deploy(self, bundle, options):
        bundle.as_format('combined-pem')
        return 'the certificate and its key put in place'
''')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402  (the routes)
from acmelib.certs import onlineimport as OI, jobs, deployer, runtime, pki  # noqa: E402
from acmelib.certs import store as S, teams as T, ca as CA  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.issuers import ssls as SS  # noqa: E402
from acmelib.plugins.issuers.digicert import DigicertIssuer  # noqa: E402
from acmelib.plugins.issuers.vault_pki import VaultPkiIssuer  # noqa: E402
from acmelib.plugins.issuers.google_cas import GoogleCasIssuer  # noqa: E402
from acmelib.plugins.issuers.globalsign_atlas import GlobalSignAtlasIssuer  # noqa: E402
from acmelib.plugins.issuers.ejbca import EjbcaIssuer  # noqa: E402
from acmelib.plugins.issuers.freeipa import FreeIpaIssuer  # noqa: E402
from acmelib.plugins.issuers import _scep_pkcs7 as p7  # noqa: E402
import test_ssls as TS  # noqa: E402
import test_sslmarket as TM  # noqa: E402
from test_issuers import TestCA, make_key_csr  # noqa: E402
from test_issuers_more import CannedContext, Base as MoreBase, hdr  # noqa: E402

STORE = acme.Storage(acme.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DAY = 86400
FAKE = {}                       # host -> fn(method, url, body, headers, ...)


def fake_http(self, method, url, body=None, headers=None, timeout=30, verify=True, ca_pem=None,
              client_cert=None, proxy=True, idempotent=None, retries=None):
    """Every request of a module in a job goes to the fake of its host."""
    if isinstance(body, str):
        body = body.encode('utf-8')
    host = urllib.parse.urlsplit(url).netloc
    if host not in FAKE:
        raise AssertionError('no other address is asked: %s' % url)
    return FAKE[host](method, url, body, headers, timeout, verify, ca_pem, client_cert, proxy)


class FakeH(object):
    """A request of the administration pages."""
    def __init__(self, who='boss', role='fulladmin', body=None, args=None):
        self.store, self._body, self.args = STORE, dict(body or {}), dict(args or {})
        self.who, self.role = who, role
        self.headers = {}

    def me(self, _role='readonly'):
        return {'name': self.who, 'role': self.role,
                'account': {'name': self.who, 'role': self.role, 'source': 'local', 'dn': '',
                            'group_list': ''}}

    def session(self, kind):
        return self.me()

    def body(self):
        return self._body

    def arg(self, name, default=''):
        return self.args.get(name, default)

    def num(self, name, default, lo=0, hi=10 ** 9):
        return default


def call(method, path, body=None, args=None, **who):
    return E.ROUTES[(method, path)](FakeH(body=body, args=args, **who))


def wait_job(jid, most=60):
    end = time.time() + most
    while time.time() < end:
        r = STORE.db.row('SELECT state, ok, said FROM cert_jobs WHERE id = ?', (jid,))
        if r and r['state'] not in ('queued', 'running'):
            return r
        time.sleep(0.05)
    raise AssertionError('the job %s did not end' % jid)


def source(name, kind, conf):
    cls = S.plugin_class('issuer', kind)
    STORE.db.run('DELETE FROM cert_issuers WHERE name = ?', (name,))
    iid = STORE.db.insert('cert_issuers', {'name': name, 'kind': kind, 'config': '{}',
                                           'enabled': 1, 'created': time.time()})
    cfg = S.config_seal(conf, {}, 'cert_issuers:%d' % iid, S.secret_fields(cls))
    STORE.db.update('cert_issuers', iid, {'config': json.dumps(cfg)})
    return iid


def target(name, kind):
    STORE.db.run('DELETE FROM cert_targets WHERE name = ?', (name,))
    return STORE.db.insert('cert_targets', {'name': name, 'kind': kind, 'config': '{}',
                                            'enabled': 1, 'created': time.time()})


def clean():
    for t in ('certs', 'cert_versions', 'cert_jobs', 'cert_deploys', 'cert_teams'):
        STORE.db.run('DELETE FROM %s' % t)
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'certs:kv:%' OR k LIKE 'certs:onlineimport:%'")
    E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1, certs_notify_mail='')


# ---------------------------------------------------------------------------
# SSLS.cz, end to end
# ---------------------------------------------------------------------------
SSLS_CONF = dict(TS.CONF, dcv='email', approver='admin')


class TestSsls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = TestCA(cn='Fake USERTrust Root')
        cls.ca = TestCA(cn='Fake Sectigo DV CA', parent=cls.root)
        cls._http = runtime.RunContext.http
        runtime.RunContext.http = fake_http
        # the class the registry made (it loads the modules afresh), on a clock of its own
        cls.cls = S.plugin_class('issuer', 'ssls')
        cls.mod = sys.modules[cls.cls.__module__]
        cls._now = cls.mod._now
        cls.clock = [time.time()]
        cls.mod._now = lambda: cls.clock[0]
        cls._init = cls.cls.__init__

        def init(self, config, ctx):
            cls._init(self, config, ctx)
            self._sleep = lambda s: cls.clock.__setitem__(0, cls.clock[0] + s)
        cls.cls.__init__ = init

    @classmethod
    def tearDownClass(cls):
        runtime.RunContext.http = cls._http
        cls.mod._now = cls._now
        cls.cls.__init__ = cls._init
        cls.ca.close()
        cls.root.close()

    def setUp(self):
        clean()
        self.sapi = TS.FakeSapi(self.ca, self.root, {}, {})
        FAKE['api.ssls.cz'] = self.sapi
        source('SSLS', 'ssls', SSLS_CONF)

    def bought(self, names, status='A', product='positivemd', days=100):
        """A certificate bought at www.ssls.cz, not by acme: (SSLS ID, its key)."""
        key, csr_pem, csr_der = make_key_csr(list(names), 'ec')
        cid = str(self.sapi.next_cert)
        self.sapi.next_cert += 1
        now = time.time()
        self.sapi.certs[cid] = {
            'product': product, 'names': list(names), 'csr': csr_pem, 'method': 'email',
            'status': status, 'polls': 0, 'period': '2', 'orderType': 'new',
            'params': {'dcv': {'email': 'admin@%s' % SS._base(names[0])}},
            'NVB': int(now - DAY), 'NVA': int(now + days * DAY), 'SNVB': int(now - DAY),
            'SNVA': int(now + 600 * DAY), 'sub_end': now + 600 * DAY, 'reissues': 0,
            'cert': self.ca.sign_csr(csr_der, list(names)) if status in ('A', 'R') else None,
            'auth': {}}
        self.sapi.used_csrs.add(csr_pem)
        self.sapi.approved.add(cid)         # its e-mail DCV is clicked whenever asked
        return cid, key

    def run_import(self, refs, **more):
        items = [dict({'ref': r, 'owner': '', 'tags': ['imported'], 'auto_renew': 1}, **more)
                 for r in refs]
        jid = call('POST', '/api/certs/online_import', {'source': 'SSLS', 'items': items})['job_id']
        wait_job(jid)
        return call('GET', '/api/certs/online_import_result', args={'job': jid})['result']

    def test_list_import_key_deploy_renew(self):
        a, key_a = self.bought(['www.example.cz', 'example.cz'])
        b, _key_b = self.bought(['shop.example.cz'])
        p, _ = self.bought(['waiting.example.cz'], status='P')
        sources = call('GET', '/api/certs/online_sources')['sources']
        self.assertIn('SSLS', [x['name'] for x in sources])
        self.assertEqual([x['kind'] for x in sources if x['name'] == 'SSLS'], ['ssls'])
        got = call('POST', '/api/certs/online_list', {'source': 'SSLS'})
        by = {x['ref']: x for x in got['items']}
        self.assertEqual(set(by), {a, b, p})
        self.assertEqual(by[a]['names'], ['www.example.cz', 'example.cz'])
        self.assertEqual(by[a]['renewable'], 'reissue')
        self.assertTrue(by[a]['importable'])
        self.assertFalse(by[p]['importable'])            # still being validated
        self.assertIn('being validated', by[p]['note'])
        self.assertGreater(by[a]['paid_until'], by[a]['not_after'])
        self.assertEqual(got['importable'], 2)
        listed = len(self.sapi.calls)
        self.assertEqual(self.sapi.names(), ['myCerts'])  # only read
        # -- imported: bound to the source with its SSLS ID, no key
        res = self.run_import([a, b, p])
        st = {r['ref']: r['state'] for r in res['results']}
        self.assertEqual(st, {a: 'imported', b: 'imported', p: 'failed'})
        self.assertNotIn('newOrder', self.sapi.names())
        self.assertNotIn('quickReissue', self.sapi.names())
        self.assertGreater(len(self.sapi.calls), listed)
        row = STORE.db.row('SELECT * FROM certs WHERE issuer_ref = ?', (a,))
        self.assertEqual(row['issuer'], 'SSLS')
        self.assertEqual(row['source'], 'import')
        self.assertEqual(json.loads(row['names']), ['www.example.cz', 'example.cz'])
        self.assertFalse(row['key_sealed'])
        self.assertTrue(row['chain_pem'].count('BEGIN CERTIFICATE') >= 1)
        self.assertEqual(json.loads(row['tags']), ['imported'])
        self.assertEqual(row['auto_renew'], 1)
        # -- listed again: both are in acme now; importing again skips them
        again = {x['ref']: x for x in call('POST', '/api/certs/online_list',
                                           {'source': 'SSLS'})['items']}
        self.assertEqual(again[a]['in_acme']['id'], row['id'])
        self.assertFalse(again[a]['importable'])
        res = self.run_import([a])
        self.assertEqual(res['results'][0]['state'], 'skipped')
        # -- deployments: the certificate alone goes, one that needs the key is refused
        target('plain', 'oi_certonly')
        target('withkey', 'oi_needskey')
        d1 = STORE.db.insert('cert_deploys', {'cert_id': row['id'], 'target': 'plain',
                                              'options': '{}', 'enabled': 1})
        d2 = STORE.db.insert('cert_deploys', {'cert_id': row['id'], 'target': 'withkey',
                                              'options': '{}', 'enabled': 1})

        def deploy(dep_id):
            cert = S.cert_need(STORE, row['id'])
            dep = STORE.db.row('SELECT * FROM cert_deploys WHERE id = ?', (dep_id,))
            out = {}
            jobs.run_now(STORE, 'deploy', lambda job: out.setdefault(
                'r', deployer.deploy_one(STORE, job, cert, dep)))
            return out['r']
        self.assertTrue(deploy(d1)[0])
        ok, why = deploy(d2)
        self.assertFalse(ok)
        self.assertIn('acme does not hold the private key', why)
        self.assertIn('Add its private key', why)
        # -- the key added: a wrong one refused, the right one kept sealed
        wrong, _c, _d = make_key_csr(['www.example.cz'], 'ec')
        with self.assertRaises(ValueError) as e:
            call('POST', '/api/certs/add_key', {'id': row['id'], 'key_pem': wrong})
        self.assertIn('does not belong', str(e.exception))
        with self.assertRaises(ValueError) as e:
            call('POST', '/api/certs/add_key', {'id': row['id'], 'key_pem':
                 '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMG\n-----END PRIVATE KEY-----'})
        self.assertIn('cannot be read', str(e.exception))
        got = call('POST', '/api/certs/add_key', {'id': row['id'], 'key_pem': key_a})
        self.assertTrue(got['added']['main'])
        row = S.cert_need(STORE, row['id'])
        self.assertTrue(row['key_sealed'])
        self.assertEqual(pki.key_info(S.cert_key(row))['pub_sha256'],
                         pki.key_info(key_a)['pub_sha256'])
        v = STORE.db.row('SELECT key_sealed FROM cert_versions WHERE cert_id = ? AND version = ?',
                         (row['id'], row['version']))
        self.assertEqual(v['key_sealed'], row['key_sealed'])
        with self.assertRaises(ValueError):
            call('POST', '/api/certs/add_key', {'id': row['id'], 'key_pem': key_a})
        self.assertTrue(deploy(d2)[0])
        # -- renewed: that very SSLS ID reissued, whatever "Certificate to reuse" says
        cfg = dict(SSLS_CONF, cert_reuse=b)
        source('SSLS', 'ssls', cfg)
        self.sapi.calls[:] = []
        j = jobs.run_now(STORE, 'renew', lambda job: __import__(
            'acmelib.certs.renewer', fromlist=['x']).renew_cert(STORE, job, row['id'], True,
                                                                'test'), cert_id=row['id'])
        self.assertTrue(j.ok, j.steps[-5:])
        reissued = self.sapi.of('quickReissue')
        self.assertEqual([x['certID'] for x in reissued], [a])
        self.assertNotIn('newOrder', self.sapi.names())
        after = S.cert_need(STORE, row['id'])
        self.assertEqual(after['issuer_ref'], a)
        self.assertGreater(after['version'], row['version'])
        new_key = S.cert_key(after)
        self.assertTrue(new_key)
        self.assertNotEqual(pki.key_info(new_key)['pub_sha256'], pki.key_info(key_a)['pub_sha256'])
        self.assertTrue(pki.key_matches(after['cert_pem'], new_key))
        self.assertTrue(any('the source\'s own certificate %s is renewed' % a in w
                            for _t, _l, w in j.steps))
        # no secret in the steps or the events
        self.assertNotIn(TS.TOKEN, json.dumps(j.steps))
        self.assertNotIn(TS.TOKEN, json.dumps(STORE.db.rows('SELECT * FROM events')))

    def test_known_by_acme_order_and_serial(self):
        a, _ = self.bought(['a.example.cz'])
        b, _ = self.bought(['b.example.cz'])
        mine = STORE.db.insert('certs', {'name': 'ordered-here', 'names': '["a.example.cz"]',
                                         'issuer': 'SSLS', 'state': 'ok', 'version': 0})
        ctx = runtime.RunContext(STORE, None, scope='issuer:SSLS')
        ctx.kv_set('ssls-order:%d:ec' % mine, json.dumps({'cert_id': a}))
        # b: imported once by a file, under another name - known by its serial
        leaf = self.sapi.certs[b]['cert']
        other = STORE.db.insert('certs', {'name': 'from-a-file', 'names': '["b.example.cz"]',
                                          'issuer': '', 'state': 'ok', 'version': 0})
        S.save_version(STORE, other, leaf, [], None, 'import', 'test')
        items = {x['ref']: x for x in OI.listing(STORE, 'SSLS')['items']}
        self.assertEqual(items[a]['in_acme']['by'], 'ordered by acme')
        self.assertEqual(items[a]['in_acme']['name'], 'ordered-here')
        # myCerts says no serial: b is found by it once fetched, and not imported twice
        self.assertIsNone(items[b]['in_acme'])
        res = self.run_import([a, b])
        st = {r['ref']: (r['state'], r['why']) for r in res['results']}
        self.assertEqual(st[a], ('skipped', 'acme has it already: ordered-here'))
        self.assertEqual(st[b], ('skipped', 'acme has it already: from-a-file'))
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM certs'), 2)

    def test_scoped_certadmin(self):
        a, key_a = self.bought(['team.example.cz'])
        E.CONFIG.update(certs_certadmin_all=0)
        T.save_team(STORE, {'name': 'Web', 'members': ['local:jana=request']}, 'x')
        T.save_team(STORE, {'name': 'Ops'}, 'x')
        item = {'ref': a, 'owner': 'Ops', 'auto_renew': 1}
        with self.assertRaises(E.ApiError) as e:
            call('POST', '/api/certs/online_import', {'source': 'SSLS', 'items': [item]},
                 who='jana', role='certadmin')
        self.assertEqual(e.exception.status, 403)
        with self.assertRaises(E.ApiError):
            call('POST', '/api/certs/online_import', {'source': 'SSLS', 'items': [
                dict(item, owner='')]}, who='jana', role='certadmin')
        with self.assertRaises(E.ApiError) as e:
            call('POST', '/api/certs/online_list', {'source': 'SSLS'}, who='v', role='readonly')
        self.assertEqual(e.exception.status, 403)
        jid = call('POST', '/api/certs/online_import', {'source': 'SSLS', 'items': [
            dict(item, owner='Web')]}, who='jana', role='certadmin')['job_id']
        self.assertTrue(wait_job(jid)['ok'])
        row = STORE.db.row('SELECT * FROM certs WHERE issuer_ref = ?', (a,))
        self.assertEqual(row['owner'], 'Web')
        # the key: only with manage on its team - jana may only ask
        with self.assertRaises(E.ApiError) as e:
            call('POST', '/api/certs/add_key', {'id': row['id'], 'key_pem': key_a},
                 who='jana', role='certadmin')
        self.assertEqual(e.exception.status, 403)
        T.save_team(STORE, {'name': 'Web', 'old_name': 'Web',
                            'members': ['local:jana=manage']}, 'x')
        call('POST', '/api/certs/add_key', {'id': row['id'], 'key_pem': key_a},
             who='jana', role='certadmin')
        self.assertTrue(S.cert_need(STORE, row['id'])['key_sealed'])

    def test_a_changed_source_forgets_the_ref(self):
        a, _ = self.bought(['x.example.cz'])
        self.run_import([a])
        row = STORE.db.row('SELECT * FROM certs WHERE issuer_ref = ?', (a,))
        source('Other', 'selfsigned', {})
        A.cert_save(STORE, {'id': row['id'], 'issuer': 'Other'}, 'test')
        self.assertFalse(S.cert_need(STORE, row['id']).get('issuer_ref'))


# ---------------------------------------------------------------------------
# acme's own authority
# ---------------------------------------------------------------------------
class TestOwnCa(unittest.TestCase):
    def setUp(self):
        clean()
        STORE.db.run('DELETE FROM cert_ca_issued')
        STORE.db.run('DELETE FROM cert_cas')
        self.ca_id = CA.ca_create(STORE, 'Test Root', 'Test Root', 'ec-256', 365)
        source('Own', 'internal_ca', {'ca': self.ca_id})

    def test_signed_elsewhere_imported(self):
        key, csr, _der = make_key_csr(['dev.example.test'], 'ec')
        pem, _chain = CA.ca_sign(STORE, self.ca_id, csr, 30, by='a CSR signed by hand')
        # one signed before 1.0.21: its certificate was not kept
        k2, csr2, _d2 = make_key_csr(['old.example.test'], 'ec')
        old, _c = CA.ca_sign(STORE, self.ca_id, csr2, 30)
        STORE.db.run('UPDATE cert_ca_issued SET cert_pem = NULL WHERE serial = ?',
                     (pki.cert_info(old)['serial'],))
        items = {x['cn']: x for x in OI.listing(STORE, 'Own')['items']}
        self.assertTrue(items['dev.example.test']['importable'])
        self.assertEqual(items['dev.example.test']['renewable'], 'issue')
        self.assertFalse(items['old.example.test']['importable'])
        self.assertIn('did not keep', items['old.example.test']['note'])
        ref = items['dev.example.test']['ref']
        j = jobs.run_now(STORE, 'online-import', lambda job: OI.run_import(
            STORE, job, S.plugin_row(STORE, 'issuer', 'Own'),
            OI.clean_picks(STORE, [{'ref': ref}]), 'test'))
        self.assertTrue(j.ok, j.steps)
        row = STORE.db.row('SELECT * FROM certs WHERE issuer_ref = ?', (ref,))
        self.assertEqual(row['cert_pem'].strip(), pem.strip())
        self.assertIn('Test Root', row['chain_pem'] and pki.cert_info(
            S.chain_list(row['chain_pem'])[0])['subject_dn'])
        self.assertEqual(row['auto_renew'], 0)
        items = {x['cn']: x for x in OI.listing(STORE, 'Own')['items']}
        self.assertEqual(items['dev.example.test']['in_acme']['id'], row['id'])


# ---------------------------------------------------------------------------
# SSLmarket
# ---------------------------------------------------------------------------
class TestSslmarket(TM.Base):
    def test_orders_listed_fetched_and_reissued(self):
        key, csr, _der = make_key_csr(['www.example.cz', 'example.cz'], 'ec')
        o = self.api.add_order(900, ['www.example.cz', 'example.cz'],
                               time.strftime('%Y-%m-%d', time.gmtime(time.time() + 300 * DAY)),
                               csr=csr, serial='AB01')
        o['published'] = time.strftime('%Y-%m-%d')
        self.api.add_order(901, ['new.example.cz'], '2099-01-01', state='Waiting for validation')
        iss = self.issuer(dcv='Email')
        items = {x['ref']: x for x in iss.list_existing()}
        self.assertEqual(items['900']['names'], ['www.example.cz', 'example.cz'])
        self.assertTrue(items['900']['downloadable'])
        self.assertEqual(items['900']['renewable'], 'reissue')
        self.assertFalse(items['901']['downloadable'])
        got = iss.fetch_existing('900')
        self.assertTrue(pki.key_matches(got['cert_pem'], key))
        self.assertEqual(got['ref'], '900')
        self.assertEqual([c[1] for c in self.api.calls if c[0] != 'GET'], [])   # only read
        # renewed with its order as the ref: that one is reissued, not "Order to reuse"
        iss = self.issuer(dcv='Email', order_id='901')
        req = self.req(['www.example.cz', 'example.cz'])
        req.ref = '900'
        out = iss.issue(req)
        self.assertIn(('POST', '/certificate/order_id/{ORDER_ID}/reissue',
                       '/certificate/order_id/900/reissue'),
                      [c[:3] for c in self.api.calls])
        self.assertEqual(out.info['ref'], '900')


# ---------------------------------------------------------------------------
# The others, against canned answers of their documented shapes
# ---------------------------------------------------------------------------
class TestOthers(MoreBase):
    def leaf(self, names, serial=None):
        key, _csr, der = make_key_csr(list(names), 'ec')
        return self.sign(der, list(names), serial=serial), key

    def test_digicert(self):
        leaf, _k = self.leaf(['www.example.test'])
        seen = []

        def handler(method, url, body, headers, cc):
            self.assertEqual(hdr(headers, 'X-DC-DEVKEY'), 'DEVKEY')
            u = urllib.parse.urlsplit(url)
            seen.append((method, u.path, u.query))
            p = u.path[len('/services/v2'):]
            if p == '/order/certificate' and method == 'GET':
                q = dict(urllib.parse.parse_qsl(u.query))
                self.assertEqual(q['limit'], '1000')
                return 200, {}, {'orders': [
                    {'id': 1234, 'status': 'issued', 'certificate': {
                        'common_name': 'www.example.test', 'dns_names': ['www.example.test',
                                                                         'example.test'],
                        'valid_till': '2027-01-01', 'serial_number': '0A1B'},
                     'order_valid_till': '2028-06-01',
                     'product': {'name_id': 'ssl_basic', 'name': 'Basic OV'}},
                    {'id': 1235, 'status': 'pending', 'certificate': {'common_name': 'x.test'},
                     'product': {'name_id': 'ssl_basic'}}],
                    'page': {'total': 2, 'limit': 1000, 'offset': 0}}
            if p == '/certificate/download/order/1234/format/pem_all':
                return 200, {}, leaf + self.ca.pem + self.root.pem
            return 404, {}, {'errors': [{'message': 'no %s' % p}]}
        d = DigicertIssuer({'api_key': 'DEVKEY'}, CannedContext(handler))
        items = {x['ref']: x for x in d.list_existing()}
        self.assertEqual(items['1234']['names'], ['www.example.test', 'example.test'])
        self.assertEqual(items['1234']['renewable'], 'reissue')
        self.assertTrue(items['1234']['paid_until'] > items['1234']['not_after'])
        self.assertFalse(items['1235']['downloadable'])
        got = d.fetch_existing('1234')
        self.assertEqual(got['cert_pem'].strip(), leaf.strip())
        self.assertEqual([p7.Cert(c).subject_cn for c in got['chain_pems']],
                         ['More Issuing CA', 'More Root X1'])
        self.assertTrue(all(m == 'GET' for m, _p, _q in seen))

    def test_vault(self):
        leaf, _k = self.leaf(['app.example.test'])

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            self.assertEqual(method, 'GET')
            if u.path == '/v1/pki/certs':
                self.assertEqual(u.query, 'list=true')
                self.assertEqual(hdr(headers, 'X-Vault-Token'), 'tok')
                return 200, {}, {'data': {'keys': ['17:aa', '01:02']}}
            if u.path == '/v1/pki/cert/17:aa':
                return 200, {}, {'data': {'certificate': leaf}}
            if u.path == '/v1/pki/cert/01:02':
                return 200, {}, {'data': {'certificate': self.ca.pem}}
            if u.path == '/v1/pki/cert/ca_chain':
                return 200, {}, {'data': {'ca_chain': self.ca.pem + self.root.pem}}
            return 404, {}, {'errors': []}
        v = VaultPkiIssuer({'url': 'https://vault:8200', 'role': 'web', 'token': 'tok'},
                           CannedContext(handler))
        items = v.list_existing()
        self.assertEqual([x['ref'] for x in items], ['17:aa'])       # the CA left out
        self.assertEqual(items[0]['cn'], 'app.example.test')
        got = v.fetch_existing('17:aa')
        self.assertEqual(got['cert_pem'].strip(), leaf.strip())
        self.assertEqual(len(got['chain_pems']), 2)

    def test_google_cas(self):
        leaf, _k = self.leaf(['svc.example.test'])
        pool = 'projects/p1/locations/eu/caPools/tls'
        name = pool + '/certificates/c1'

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            if u.netloc == 'oauth2.googleapis.com':
                return 200, {}, {'access_token': 'ya29.T', 'expires_in': 3600}
            self.assertEqual(method, 'GET')
            if u.path == '/v1/' + pool + '/certificates':
                q = dict(urllib.parse.parse_qsl(u.query))
                if not q.get('pageToken'):
                    return 200, {}, {'certificates': [{'name': name, 'pemCertificate': leaf,
                                                       'pemCertificateChain': [self.ca.pem]}],
                                     'nextPageToken': 'N2'}
                return 200, {}, {'certificates': [{'name': pool + '/certificates/c2',
                                                   'pemCertificate': leaf,
                                                   'revocationDetails': {'revocationState':
                                                                         'KEY_COMPROMISE'}}]}
            if u.path == '/v1/' + name:
                return 200, {}, {'name': name, 'pemCertificate': leaf,
                                 'pemCertificateChain': [self.ca.pem, self.root.pem]}
            return 404, {}, {}
        w = __import__('acmelib.plugins.issuers._source_common', fromlist=['x']).Work()
        kf = w.path('sa.pem')
        __import__('test_issuers').openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt',
                                            'rsa_keygen_bits:2048', '-out', kf])
        sa = {'client_email': 'a@p1.iam.gserviceaccount.com', 'private_key': __import__('test_issuers').rd(kf),
              'project_id': 'p1'}
        w.close()
        ctx = CannedContext(handler)
        g = GoogleCasIssuer({'service_account': json.dumps(sa), 'location': 'eu', 'pool': 'tls'},
                            ctx)
        items = {x['ref']: x for x in g.list_existing()}
        self.assertTrue(items[name]['downloadable'])
        self.assertFalse(items[pool + '/certificates/c2']['downloadable'])
        got = g.fetch_existing(name)
        self.assertEqual(got['cert_pem'].strip(), leaf.strip())
        self.assertTrue(any(k.startswith('gcas-cert:') for k in ctx.kv))   # it can be revoked
        with self.assertRaises(PluginError):
            g.fetch_existing('projects/other/locations/eu/caPools/x/certificates/c1')

    def test_globalsign_atlas(self):
        leaf, _k = self.leaf(['atlas.example.test'], serial=0x1A2B)

        def handler(method, url, body, headers, cc):
            p = urllib.parse.urlsplit(url).path[3:]
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
            if p == '/login':
                return 200, {}, {'access_token': 'TOK'}
            self.assertEqual(method, 'GET')
            if p == '/stats/issued':
                self.assertEqual(set(q), {'page', 'per_page', 'from', 'to'})
                return 200, {'Total-Count': '1'}, [{'serial_number': '1A2B',
                                                    'not_before': 1, 'not_after': 2}]
            if p == '/certificates/1A2B':
                return 200, {}, {'certificate': leaf, 'status': 'ISSUED'}
            if p == '/trustchain':
                return 200, {}, [self.ca.pem, self.root.pem]
            return 404, {}, {}
        g = GlobalSignAtlasIssuer({'api_key': 'K', 'api_secret': 'S', 'client_cert': 'C',
                                   'client_key': 'K'}, CannedContext(handler))
        items = g.list_existing()
        self.assertEqual(items[0]['ref'], '1A2B')
        self.assertEqual(items[0]['cn'], 'atlas.example.test')
        self.assertEqual(g.fetch_existing('1A2B')['cert_pem'].strip(), leaf.strip())

    def test_ejbca(self):
        import base64
        leaf, _k = self.leaf(['ej.example.test'], serial=0x3C)
        bodies = []

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            if u.path.endswith('/v1/certificate/search'):
                b = json.loads(body)
                bodies.append(b)
                self.assertEqual(b['criteria'][0], {'property': 'CA', 'value': 'IssuingCA',
                                                    'operation': 'EQUAL'})
                return 200, {}, {'certificates': [{
                    'certificate': base64.b64encode(p7.cert_der(leaf)).decode(),
                    'serial_number': '3C', 'certificate_profile': 'SERVER'}],
                    'more_results': False}
            if '/v1/ca/' in u.path and u.path.endswith('/certificate/download'):
                return 200, {}, self.ca.pem + self.root.pem
            return 404, {}, {}
        e = EjbcaIssuer({'url': 'https://ejbca.example.test', 'client_cert': 'C', 'client_key': 'K',
                         'ca_name': 'IssuingCA'}, CannedContext(handler))
        items = e.list_existing()
        self.assertEqual(items[0]['ref'], '3C')
        self.assertEqual(bodies[0]['criteria'][1], {'property': 'STATUS', 'value': 'CERT_ACTIVE',
                                                    'operation': 'EQUAL'})
        got = e.fetch_existing('3C')
        self.assertEqual(bodies[-1]['criteria'][1]['property'], 'SERIAL_NUMBER')
        self.assertEqual(got['cert_pem'].strip(), leaf.strip())
        self.assertEqual(len(got['chain_pems']), 2)

    def test_freeipa(self):
        import base64
        leaf, _k = self.leaf(['ipa-host.example.test'], serial=77)
        der = base64.b64encode(p7.cert_der(leaf)).decode()

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            if u.path == '/ipa/session/login_password':
                return 200, {'Set-Cookie': 'ipa_session=abc; path=/ipa'}, b''
            b = json.loads(body)
            if b['method'] == 'cert_find/1':
                self.assertEqual(b['params'][1]['status'], 'VALID')
                self.assertTrue(b['params'][1]['all'])
                return 200, {}, {'result': {'result': [{'serial_number': 77, 'certificate': der,
                                                        'status': 'VALID'}],
                                            'count': 1, 'truncated': False}, 'error': None}
            if b['method'] == 'cert_show/1':
                self.assertEqual(b['params'][0], ['77'])
                self.assertTrue(b['params'][1]['chain'])
                return 200, {}, {'result': {'result': {'certificate': der,
                                                       'certificate_chain': [der]}},
                                 'error': None}
            return 200, {}, {'error': {'message': 'no'}}
        ipa = FreeIpaIssuer({'url': 'https://ipa.example.test', 'user': 'u', 'password': 'p',
                             'realm': 'EXAMPLE.TEST'}, CannedContext(handler))
        items = ipa.list_existing()
        self.assertEqual(items[0]['ref'], '77')
        self.assertEqual(items[0]['cn'], 'ipa-host.example.test')
        self.assertEqual(ipa.fetch_existing('77')['cert_pem'].strip(), leaf.strip())


class TestWithoutTheCapability(unittest.TestCase):
    def test_only_the_sources_that_list(self):
        clean()
        source('LE', 'acme', {'directory': 'https://acme-v02.api.letsencrypt.org/directory'})
        names = [x['name'] for x in OI.sources(STORE)]
        self.assertNotIn('LE', names)
        with self.assertRaises(ValueError):
            OI.listing(STORE, 'LE')
        from acmelib.plugins.issuers.acme import AcmeIssuer
        self.assertFalse(AcmeIssuer.describe()['lists_existing'])

    def test_picks_checked(self):
        with self.assertRaises(ValueError):
            OI.clean_picks(STORE, [])
        with self.assertRaises(ValueError):
            OI.clean_picks(STORE, [{'ref': '1', 'challenge': 'no such one'}])
        got = OI.clean_picks(STORE, [{'ref': '1', 'auto_renew': True}, {'ref': '1'}])
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]['auto_renew'], 1)


if __name__ == '__main__':
    unittest.main()
