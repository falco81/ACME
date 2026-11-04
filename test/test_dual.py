#!/usr/bin/env python3
"""Dual certificates: the same names twice, ECDSA and RSA (docs/certificates.md,
"Dual certificates (ECDSA + RSA)").

    python3 test/test_dual.py            (or python3 -m unittest test.test_dual)

In this process, no network: the renewer issues against the mock ACME server of
test_issuers.py (a second order finds the names proved already, as Let's
Encrypt does) and against an authority of acme's own; one variant due alone, the
twin failing and tried again; the bundle and the export of each; the SSH
target's @variant outputs and its nginx / HAProxy presets writing both; F5 with
two cert-key-chain entries (canned answers); the TLS check asking for each
variant of a local server that holds both; a backup opening the twin's key.
With ACME_TEST_PEBBLE=/path/to/pebble also a real dual order from pebble.
"""
import base64
import gzip
import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-dual-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "testnode", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import acme as E  # noqa: E402
from acmelib.certs import api, ca as CA, deployer, jobs, pki, renewer, store as S  # noqa: E402
from acmelib.plugins import base  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
import test_issuers as TI  # noqa: E402
import test_targets as TT  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
E.CONFIG['certs_precheck'] = 0
S.registry()


# ---------------------------------------------------------------------------
# The pieces: a validation that answers the mock CA, an ACME CA that reuses
# authorizations, a source whose RSA certificate can be made to fail
# ---------------------------------------------------------------------------
class BoardChallenge(base.Challenge):
    kind = 'dualboard'
    title = 'The mock CA\'s board (tests)'
    types = ('http-01', 'dns-01')
    BOARD = {'dns': {}, 'http': {}}
    LOG = []

    def present(self, name, token, key_authorization, txt_value):
        BoardChallenge.LOG.append(('present', name))
        self.BOARD['http'][token] = key_authorization
        self.BOARD['dns'].setdefault(name, []).append(txt_value)
        return {'token': token, 'txt': txt_value}

    def cleanup(self, name, handle):
        BoardChallenge.LOG.append(('cleanup', name))
        self.BOARD['http'].pop(handle['token'], None)
        try:
            self.BOARD['dns'].get(name, []).remove(handle['txt'])
        except ValueError:
            pass


class ReuseAcme(TI.MockAcme):
    """The mock ACME server, a valid authorization of the account used again in
    the next order of the same name (no second validation), as Let's Encrypt does."""
    def __init__(self, *a, **kw):
        self.reused = []
        TI.MockAcme.__init__(self, *a, **kw)

    def _handler(self):
        H = TI.MockAcme._handler(self)
        app = self

        def new_order(h, kid, payload):
            oid = app.nid()
            azs, fresh = [], 0
            for ident in payload['identifiers']:
                wild = ident['value'].startswith('*.')
                value = ident['value'][2:] if wild else ident['value']
                old = [a for a, az in app.authz.items() if az['status'] == 'valid' and
                       az['identifier']['value'] == value and az['wildcard'] == wild and
                       az.get('kid') == kid]
                if old:
                    app.reused.append(ident['value'])
                    azs.append(app.base + '/authz/' + old[0])
                    continue
                fresh += 1
                aid = app.nid()
                chs = []
                for t in (('dns-01',) if wild else ('http-01', 'dns-01')):
                    cid = app.nid()
                    app.chals[cid] = {'type': t, 'url': app.base + '/chal/' + cid,
                                      'status': 'pending', 'token': TI.b64u(os.urandom(16)),
                                      'authz': aid}
                    chs.append(app.chals[cid])
                app.authz[aid] = {'status': 'pending', 'kid': kid,
                                  'identifier': {'type': ident['type'], 'value': value},
                                  'challenges': chs, 'wildcard': wild,
                                  'expires': '2030-01-01T00:00:00Z'}
                azs.append(app.base + '/authz/' + aid)
            app.orders[oid] = {'status': 'ready' if not fresh else 'pending',
                               'identifiers': payload['identifiers'], 'authorizations': azs,
                               'finalize': app.base + '/fin/' + oid,
                               'profile': payload.get('profile'),
                               'replaces': payload.get('replaces')}
            h.send(201, app.orders[oid], headers=h.common() + [('Location',
                                                               app.base + '/o/' + oid)])
        H.new_order = new_order
        return H


class HalfCa(base.Issuer):
    """Signs itself (self-signed); its RSA ones fail while `fail_rsa`."""
    kind = 'dualhalf'
    title = 'Half a CA (tests)'
    dual = True
    fail_rsa = True
    asked = []

    def issue(self, req):
        HalfCa.asked.append(req.key_type)
        if req.key_type.startswith('rsa') and HalfCa.fail_rsa:
            raise base.PluginError('no RSA today')
        cert = pki.self_signed(req.key_pem, req.names, days=90)
        return base.Issued(cert, [])


class PaidCa(HalfCa):
    kind = 'dualpaid'
    dual = False
    dual_field = 'dual_order'
    fields = [base.dual_order_field()]


class OneCertTarget(base.Target):
    kind = 'dualone'
    title = 'One certificate at a time (tests)'
    GOT = []

    def deploy(self, bundle, options):
        OneCertTarget.GOT.append((bundle.key_type, getattr(bundle, 'alt', None)))
        return 'took %s' % bundle.key_type


for fam, cls in (('challenge', BoardChallenge), ('issuer', HalfCa), ('issuer', PaidCa),
                 ('target', OneCertTarget)):
    base.REGISTRY.found[fam][cls.kind] = cls


def add(table, name, kind, config):
    return STORE.db.insert(table, {'name': name, 'kind': kind, 'config': json.dumps(config),
                                   'state': '{}', 'enabled': 1, 'created': time.time()})


def cert(name, names, issuer, key_type='ec-256', alt='rsa-2048', challenge=''):
    return STORE.db.insert('certs', {
        'name': name, 'names': json.dumps(names), 'cn': names[0], 'issuer': issuer,
        'challenge': challenge, 'challenge_map': '{}', 'key_type': key_type,
        'key_type_alt': alt, 'auto_renew': 1, 'state': 'new', 'enabled': 1, 'version': 0,
        'fails': 0, 'ari': '{}', 'profile': '{}', 'created': time.time()})


def renew(cid, only=None, force=False):
    return jobs.run_now(STORE, 'renew', renewer.renew_job(cid, force, 'test', only), cert_id=cid,
                        by='test')


def words(job):
    return '\n'.join(s[2] for s in job.steps)


CA_ID = CA.ca_create(STORE, 'Dual Root', {'CN': 'Dual Root'}, key_type='ec-256', by='t')
add('cert_issuers', 'own', 'internal_ca', {'ca': CA_ID, 'days': 60})
add('cert_issuers', 'half', 'dualhalf', {})


def own_dual(name='both.example'):
    """A dual certificate from acme's own authority, issued."""
    cid = cert(name, [name, 'www.' + name], 'own')
    job = renew(cid)
    assert job.ok, words(job)
    return cid


# ---------------------------------------------------------------------------
class DualAcme(unittest.TestCase):
    """A real dual issue from the mock ACME server, through the renewer."""
    @classmethod
    def setUpClass(cls):
        cls.ca = ReuseAcme()
        cls.ca.board = BoardChallenge.BOARD
        add('cert_issuers', 'mock', 'acme', {
            'directory': 'custom', 'directory_url': cls.ca.base + '/dir',
            'contacts': ['pki@example.com'], 'poll_every': 0.2, 'wait_ready': 10,
            'wait_valid': 10, 'wait_order': 10})
        add('cert_challenges', 'board', 'dualboard', {})

    @classmethod
    def tearDownClass(cls):
        cls.ca.close()

    def test_both_issued_second_order_reuses_the_names(self):
        BoardChallenge.LOG[:] = []
        names = ['www.dual.test', 'dual.test']
        cid = cert('dual', names, 'mock', challenge='board')
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        row = S.cert_get(STORE, cid)
        self.assertEqual(row['state'], 'ok')
        self.assertEqual(pki.cert_info(row['cert_pem'])['key_type'], 'ec-256')
        self.assertEqual(pki.cert_info(row['alt_cert_pem'])['key_type'], 'rsa-2048')
        self.assertEqual(sorted(pki.cert_info(row['alt_cert_pem'])['names']), sorted(names))
        self.assertEqual(row['alt_state'], 'ok')
        self.assertTrue(pki.key_matches(row['alt_cert_pem'], S.cert_key(row, 'alt')))
        self.assertTrue(pki.key_matches(row['cert_pem'], S.cert_key(row)))
        # two orders; the second found both names proved: nothing put in place twice,
        # every proof taken away once
        orders = [o for o in self.ca.orders.values() if
                  sorted(i['value'] for i in o['identifiers']) == sorted(names)]
        self.assertEqual(len(orders), 2)
        self.assertEqual(orders[0]['authorizations'], orders[1]['authorizations'])
        self.assertEqual(sorted(self.ca.reused), sorted(names))
        self.assertEqual(sorted(n for w, n in BoardChallenge.LOG if w == 'present'), sorted(names))
        self.assertEqual(sorted(n for w, n in BoardChallenge.LOG if w == 'cleanup'), sorted(names))
        self.assertEqual(self.ca.board['http'], {})
        self.assertIn('every name is proved already', words(job))
        self.assertIn('dual: ec-256 and rsa-2048', words(job))
        # the versions: one of each, numbered in one sequence; the ARI id of each
        vs = STORE.db.rows('SELECT version, variant FROM cert_versions WHERE cert_id = ? '
                           'ORDER BY version', (cid,))
        self.assertEqual([(v['version'], v['variant'] or '') for v in vs], [(1, ''), (2, 'alt')])
        self.assertEqual((row['version'], row['alt_version']), (1, 2))
        self.assertTrue(S.jload(row['alt_ari'], {}).get('id'))
        self.assertNotEqual(S.jload(row['alt_ari'])['id'], S.jload(row['ari'])['id'])
        self.assertEqual(S.generation(row), 2)
        # renewed: the main order replaces the main one, the twin's its own (ARI)
        old_main, old_alt = row['cert_pem'], row['alt_cert_pem']
        job = renew(cid, force=True)
        self.assertTrue(job.ok, words(job))
        last = list(self.ca.orders.values())[-2:]
        self.assertEqual([o['replaces'] for o in last],
                         [TI.ac.ari_id(old_main), TI.ac.ari_id(old_alt)])


class DualOwnCa(unittest.TestCase):
    def test_internal_ca_dual(self):
        cid = own_dual('own.example')
        row = S.cert_get(STORE, cid)
        self.assertEqual(S.key_family(pki.cert_info(row['cert_pem'])['key_type']), 'ec')
        self.assertEqual(S.key_family(pki.cert_info(row['alt_cert_pem'])['key_type']), 'rsa')
        issued = STORE.db.rows('SELECT serial FROM cert_ca_issued WHERE cert_id = ?', (cid,))
        self.assertEqual(len(issued), 2)                  # both on the authority's list

    def test_rsa_main_ec_twin(self):
        cid = cert('rsamain.example', ['rsamain.example'], 'own', 'rsa-2048', 'ec-384')
        self.assertTrue(renew(cid).ok)
        row = S.cert_get(STORE, cid)
        self.assertEqual(pki.cert_info(row['cert_pem'])['key_type'], 'rsa-2048')
        self.assertEqual(pki.cert_info(row['alt_cert_pem'])['key_type'], 'ec-384')
        b = S.bundle_of(row)
        self.assertEqual(b.variant('ec').key_type, 'ec-384')
        self.assertIs(b.variant('rsa'), b)

    def test_save_checks_the_twin(self):
        cid = api.cert_save(STORE, {'name': 'saved', 'names': ['saved.example'],
                                    'key_type': 'ec-256', 'key_type_alt': 'rsa-3072',
                                    'issuer': 'own'}, 't')
        self.assertEqual(S.cert_get(STORE, cid)['key_type_alt'], 'rsa-3072')
        with self.assertRaises(ValueError):
            api.cert_save(STORE, {'id': cid, 'key_type_alt': 'ec-384'}, 't')   # same kind
        with self.assertRaises(ValueError):
            api.cert_save(STORE, {'id': cid, 'key_type_alt': 'dsa'}, 't')
        api.cert_save(STORE, {'id': cid, 'key_type_alt': 'none'}, 't')
        self.assertEqual(S.cert_get(STORE, cid)['key_type_alt'], '')

    def test_twin_changed_is_issued_again(self):
        cid = own_dual('change.example')
        api.cert_save(STORE, {'id': cid, 'key_type_alt': 'rsa-3072'}, 't')
        row = S.cert_get(STORE, cid)
        self.assertIsNone(row['alt_cert_pem'])
        self.assertIn('has not been issued yet', renewer.due_why(row))
        self.assertEqual(renewer.main_due(row), '')
        self.assertTrue(renew(cid, only='alt').ok)
        self.assertEqual(pki.cert_info(S.cert_get(STORE, cid)['alt_cert_pem'])['key_type'],
                         'rsa-3072')

    def test_paid_source_gives_no_twin_unless_allowed(self):
        add('cert_issuers', 'paid', 'dualpaid', {})
        HalfCa.fail_rsa = False
        try:
            cid = cert('paid.example', ['paid.example'], 'paid')
            job = renew(cid)
            self.assertTrue(job.ok)
            self.assertIn('gives no twin', words(job))
            self.assertIsNone(S.cert_get(STORE, cid)['alt_cert_pem'])
            STORE.db.run("UPDATE cert_issuers SET config = ? WHERE name = 'paid'",
                         (json.dumps({'dual_order': True}),))
            self.assertTrue(renew(cid).ok)
            self.assertTrue(S.cert_get(STORE, cid)['alt_cert_pem'])
        finally:
            HalfCa.fail_rsa = True
        d = PaidCa.describe()
        self.assertTrue(d['dual'])
        self.assertEqual(d['dual_field'], 'dual_order')


class DualDueAndFailing(unittest.TestCase):
    def test_only_the_twin_due(self):
        cid = own_dual('due.example')
        row = S.cert_get(STORE, cid)
        self.assertEqual(renewer.due_why(row), '')
        t = time.time()
        STORE.db.update('certs', cid, {'alt_not_after': t + 86400, 'alt_not_before': t - 89 * 86400})
        row = S.cert_get(STORE, cid)
        self.assertEqual(renewer.main_due(row), '')
        self.assertIn('the twin (rsa-2048) ends in', renewer.alt_due(row))
        # the scan starts a job for the twin alone
        seen = []
        orig = renewer.jobs.submit
        renewer.jobs.submit = lambda store, kind, fn, **kw: seen.append((kind, fn, kw)) or 1
        try:
            renewer.scan(STORE)
        finally:
            renewer.jobs.submit = orig
        mine = [x for x in seen if x[2].get('cert_id') == cid]
        self.assertEqual(len(mine), 1)
        self.assertIn('the twin', mine[0][2]['said'])
        main_v, alt_v = row['version'], row['alt_version']
        job = jobs.run_now(STORE, 'renew', mine[0][1], cert_id=cid, by='test')
        self.assertTrue(job.ok, words(job))
        row2 = S.cert_get(STORE, cid)
        self.assertEqual(row2['version'], main_v)                 # the main one untouched
        self.assertEqual(row2['cert_pem'], row['cert_pem'])
        self.assertGreater(row2['alt_version'], alt_v)
        self.assertGreater(row2['alt_not_after'], t + 86400 * 30)
        # the main one due: both renewed
        STORE.db.update('certs', cid, {'not_after': t + 86400, 'not_before': t - 89 * 86400})
        self.assertIn('ends in', renewer.main_due(S.cert_get(STORE, cid)))
        self.assertTrue(renew(cid).ok)
        row3 = S.cert_get(STORE, cid)
        self.assertGreater(row3['version'], row2['alt_version'])
        self.assertGreater(row3['alt_version'], row3['version'])
        # ARI per variant: the twin's window passed
        STORE.db.update('certs', cid, {'alt_ari': json.dumps({'at': t - 10, 'id': 'x'})})
        self.assertIn('renewal window', renewer.alt_due(S.cert_get(STORE, cid)))

    def test_twin_fails_main_counts(self):
        HalfCa.fail_rsa = True
        cid = cert('half.example', ['half.example'], 'half')
        job = renew(cid)
        self.assertFalse(job.ok)                        # said: the twin failed
        self.assertIn('the twin (rsa-2048) failed: no RSA today', job.said)
        row = S.cert_get(STORE, cid)
        self.assertEqual(row['state'], 'ok')            # the main one counts
        self.assertEqual(row['version'], 1)
        self.assertTrue(row['cert_pem'])
        self.assertEqual(row['alt_state'], 'failed')
        self.assertEqual(row['alt_fails'], 1)
        self.assertGreater(row['alt_next_try'], time.time() + 200)
        self.assertEqual(renewer.due_why(row), '')      # waiting
        STORE.db.update('certs', cid, {'alt_next_try': time.time() - 1})
        self.assertIn('failed last time; the wait is over',
                      renewer.alt_due(S.cert_get(STORE, cid)))
        # again failing: the wait doubles, the main one still untouched
        self.assertFalse(renew(cid, only='alt').ok)
        row = S.cert_get(STORE, cid)
        self.assertEqual((row['alt_fails'], row['state'], row['version']), (2, 'ok', 1))
        HalfCa.fail_rsa = False
        try:
            self.assertTrue(renew(cid, only='alt').ok)
        finally:
            HalfCa.fail_rsa = True
        row = S.cert_get(STORE, cid)
        self.assertEqual((row['alt_state'], row['alt_fails'], row['version']), ('ok', 0, 1))
        self.assertTrue(row['alt_cert_pem'])


class DualBundleExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cid = own_dual('export.example')
        cls.row = S.cert_get(STORE, cls.cid)

    def test_bundle(self):
        b = S.bundle_of(self.row)
        self.assertEqual(b.family, 'ec')
        self.assertEqual(b.alt.family, 'rsa')
        self.assertIs(b.variant('main'), b)
        self.assertIs(b.variant('alt'), b.alt)
        self.assertIs(b.variant('rsa'), b.alt)
        self.assertIs(b.variant('ecdsa'), b)
        self.assertEqual(b.as_format('cert-pem@rsa'), b.alt.as_format('cert-pem'))
        self.assertIn(b'RSA PRIVATE KEY', b.as_format('key-rsa@alt'))
        self.assertTrue(pki.key_matches(b.alt.cert_pem, b.alt.key_pem))
        self.assertIsNone(b.alt.alt)
        with self.assertRaises(pki.PkiError):
            S.bundle_of(self.row, variant='main').variant('alt')
        # a version of the twin
        v = S.version_row(STORE, self.cid, self.row['alt_version'])
        self.assertEqual(v['variant'], 'alt')
        self.assertEqual(S.bundle_of(self.row, v).fingerprint, b.alt.fingerprint)

    def test_export(self):
        s = {'role': 'fulladmin', 'name': 't'}
        got = api.cert_export(STORE, {'id': self.cid, 'format': 'cert-pem', 'variant': 'alt'}, s)
        self.assertEqual(got['variant'], 'alt')
        self.assertTrue(got['filename'].endswith('.rsa.crt'), got['filename'])
        self.assertEqual(base64.b64decode(got['data_b64']).decode(), self.row['alt_cert_pem'])
        got = api.cert_export(STORE, {'id': self.cid, 'format': 'key-pem', 'variant': 'rsa'}, s)
        self.assertTrue(pki.key_matches(self.row['alt_cert_pem'],
                                        base64.b64decode(got['data_b64']).decode()))
        got = api.cert_export(STORE, {'id': self.cid, 'format': 'cert-pem'}, s)
        self.assertEqual(got['variant'], 'main')
        self.assertEqual(base64.b64decode(got['data_b64']).decode(), self.row['cert_pem'])
        got = api.cert_export(STORE, {'id': self.cid, 'format': 'cert-pem',
                                      'version': self.row['alt_version']}, s)
        self.assertEqual(got['variant'], 'alt')
        with self.assertRaises(ValueError):
            api.cert_export(STORE, {'id': self.cid, 'format': 'cert-pem', 'variant': 'x'}, s)

    def test_view(self):
        got = api.cert_one(STORE, self.cid)
        v = got['cert']['variants']
        self.assertEqual([x['variant'] for x in v], ['main', 'alt'])
        self.assertEqual([x['family'] for x in v], ['ec', 'rsa'])
        self.assertEqual(v[1]['fingerprint'], self.row['alt_fingerprint'])
        self.assertTrue(v[1]['not_after'])
        self.assertNotIn('alt_key_sealed', got['cert'])
        self.assertTrue(got['cert']['has_alt_key'])
        self.assertEqual({x['variant'] for x in got['versions']}, {'', 'alt'})

    def test_deploy_picks_a_variant_for_one_cert_targets(self):
        b = S.bundle_of(self.row)
        self.assertIs(deployer.pick_variant(b, {}, OneCertTarget), b.alt)     # auto: RSA
        self.assertIs(deployer.pick_variant(b, {'variant': 'main'}, OneCertTarget), b)
        self.assertIs(deployer.pick_variant(b, {'variant': 'ec'}, OneCertTarget), b)
        from acmelib.plugins.targets.ssh import SshTarget
        self.assertIs(deployer.pick_variant(b, {}, SshTarget), b)              # both
        add('cert_targets', 'one', 'dualone', {})
        STORE.db.insert('cert_deploys', {'cert_id': self.cid, 'target': 'one', 'options': '{}',
                                         'enabled': 1, 'state': 'new', 'fails': 0,
                                         'created': time.time()})
        OneCertTarget.GOT[:] = []
        job = jobs.run_now(STORE, 'deploy', deployer.deploy_job(self.cid), cert_id=self.cid)
        self.assertTrue(job.ok, words(job))
        self.assertEqual(OneCertTarget.GOT, [('rsa-2048', None)])
        d = STORE.db.row('SELECT * FROM cert_deploys WHERE cert_id = ?', (self.cid,))
        self.assertEqual(d['deployed_version'], S.generation(self.row))
        # a target of one certificate is offered the choice; one of both is not
        self.assertIn('variant', [f['key'] for f in OneCertTarget.describe()['deploy_fields']])
        self.assertNotIn('variant', [f['key'] for f in SshTarget.describe()['deploy_fields']])


# ---------------------------------------------------------------------------
class DualTargets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TT.setUpModule()
        cls.cid = own_dual('targets.example')
        cls.b = S.bundle_of(S.cert_get(STORE, cls.cid))
        cls.single = S.bundle_of(S.cert_get(STORE, cls.cid), variant='main')

    @classmethod
    def tearDownClass(cls):
        TT.tearDownModule()

    def test_outputs_with_variants(self):
        outs = C.parse_outputs('fullchain-pem@rsa /x/a.rsa.crt\nkey-pem@ecdsa /x/a.ec.key\n'
                               'cert-pem@main /x/a.crt\nkey-pem@alt /x/a.alt.key')
        self.assertEqual([o['variant'] for o in outs], ['rsa', 'ec', '', 'alt'])
        self.assertEqual(outs[1]['mode'], 0o600)
        with self.assertRaises(base.PluginError):
            C.parse_outputs('cert-pem@dsa /x/a')
        ctx = TT.FakeCtx()
        pairs = C.outputs_for(ctx, self.b, outs)
        self.assertEqual([b.family for _o, b in pairs], ['rsa', 'ec', 'ec', 'rsa'])
        pairs = C.outputs_for(ctx, self.single, outs)            # not dual: the twin left out
        self.assertEqual([o['path'] for o, _b in pairs], ['/x/a.ec.key', '/x/a.crt'])
        self.assertTrue(any('left out' in w for _l, w in ctx.steps))

    def test_ssh_presets_write_both(self):
        t = TT.make('ssh', {'host': 'srv'}, TT.FakeCtx())
        r = t.resolved(self.b, {'preset': 'nginx'})
        self.assertEqual([f['path'] for f in r['files']], [
            '/etc/nginx/ssl/targets.example.crt', '/etc/nginx/ssl/targets.example.key',
            '/etc/nginx/ssl/targets.example.rsa.crt', '/etc/nginx/ssl/targets.example.rsa.key'])
        datas = t.render(self.b, r)
        self.assertEqual(datas[2], self.b.alt.fullchain_pem.encode())
        self.assertEqual(datas[3], self.b.alt.key_pem.encode())
        # the page fills the preset's own lines in: still both
        from acmelib.plugins.targets import ssh as mod
        r = t.resolved(self.b, {'preset': 'nginx', 'outputs': '\n'.join(
            mod.PRESETS['nginx']['outputs'])})
        self.assertEqual(len(r['files']), 4)
        r = t.resolved(self.b, {'preset': 'haproxy'})
        self.assertEqual([f['path'] for f in r['files']], [
            '/etc/haproxy/certs/targets.example.ecdsa.pem',
            '/etc/haproxy/certs/targets.example.rsa.pem'])
        datas = t.render(self.b, r)
        self.assertTrue(datas[0].startswith(self.b.key_pem.encode()))
        self.assertTrue(datas[1].startswith(self.b.alt.key_pem.encode()))
        for key in ('apache', 'postfix'):
            self.assertEqual(len(t.resolved(self.b, {'preset': key})['files']),
                             len(mod.PRESETS[key]['outputs']) + 2, key)
        # not dual: as before
        self.assertEqual(len(t.resolved(self.single, {'preset': 'nginx'})['files']), 2)
        self.assertEqual(len(t.resolved(self.single, {'preset': 'haproxy'})['files']), 1)

    def test_ssh_deploy_writes_each(self):
        d = tempfile.mkdtemp(dir=TMP)
        ctx = TT.FakeCtx(ssh=TT.FakeSsh(local=True))
        t = TT.make('ssh', {'host': 'srv', 'tmp_dir': d}, ctx)
        opts = {'outputs': 'fullchain-pem %s/s.crt\nkey-pem %s/s.key\nfullchain-pem@rsa %s/s.rsa.crt'
                           '\nkey-pem@rsa %s/s.rsa.key' % (d, d, d, d),
                'test_cmd': 'true', 'reload_cmd': 'true'}
        self.assertIn('4 files written', t.deploy(self.b, opts))
        self.assertEqual(TT.read(d + '/s.rsa.crt'), self.b.alt.fullchain_pem)
        self.assertEqual(TT.read(d + '/s.crt'), self.b.fullchain_pem)
        self.assertTrue(t.deploy(self.b, opts).startswith('unchanged'))
        # only the twin new: written again
        other = S.bundle_of(S.cert_get(STORE, own_dual('other.example')))
        mixed = S.bundle_of(S.cert_get(STORE, self.cid))
        mixed.alt = other.alt
        self.assertIn('4 files written', t.deploy(mixed, opts))

    def test_stale_files_taken_away(self):
        """Single -> dual -> single: the files acme wrote before and not now go, put
        back when the test fails; a file acme did not write stays."""
        d = tempfile.mkdtemp(dir=TMP)
        ctx = TT.FakeCtx(ssh=TT.FakeSsh(local=True))
        ctx.deploy_id = 41
        t = TT.make('ssh', {'host': 'srv', 'tmp_dir': d}, ctx)
        opts = {'outputs': 'fullchain-pem %s/s.crt\nkey-pem %s/s.key\n'
                           'fullchain-pem@rsa %s/s.rsa.crt\nkey-pem@rsa %s/s.rsa.key'
                           % (d, d, d, d), 'test_cmd': 'true', 'reload_cmd': 'true'}
        with open(d + '/mine.pem', 'w') as f:
            f.write('not acme\'s')
        t.deploy(self.single, opts)                     # the RSA lines left out
        self.assertFalse(os.path.exists(d + '/s.rsa.crt'))
        t.deploy(self.b, opts)
        self.assertEqual(TT.read(d + '/s.rsa.key'), self.b.alt.key_pem)
        # back to one: the test fails - the twin's files are back where they were
        with self.assertRaises(base.PluginError):
            t.deploy(self.single, dict(opts, test_cmd='false'))
        self.assertEqual(TT.read(d + '/s.rsa.key'), self.b.alt.key_pem)
        t.deploy(self.single, opts)
        self.assertFalse(os.path.exists(d + '/s.rsa.crt'))
        self.assertFalse(os.path.exists(d + '/s.rsa.key'))
        self.assertFalse([f for f in os.listdir(d) if 'acme-stale' in f])
        self.assertTrue(os.path.exists(d + '/s.crt'))
        self.assertEqual(TT.read(d + '/mine.pem'), 'not acme\'s')
        # another deployment of the same certificate on the same host keeps its own
        ctx.deploy_id = 42
        self.assertEqual(t._written(opts), [])

    def test_haproxy_single_to_dual_removes_the_old_pem(self):
        ssh = TT.FakeSsh()
        ctx = TT.FakeCtx(ssh=ssh)
        ctx.deploy_id = 7
        t = TT.make('ssh', {'host': 'srv'}, ctx)
        t.deploy(self.single, {'preset': 'haproxy'})
        old = '/etc/haproxy/certs/targets.example.pem'
        self.assertEqual(t._written({}), [old])
        self.assertFalse(any('acme-stale' in c for c, _i in ssh.runs))
        t.deploy(self.b, {'preset': 'haproxy'})
        aside = [c for c, _i in ssh.runs if 'acme-stale' in c and 'for p in' in c]
        self.assertEqual(len(aside), 1)
        self.assertIn(old, aside[0])
        self.assertNotIn('ecdsa.pem', aside[0])
        self.assertEqual(sorted(t._written({})), [
            '/etc/haproxy/certs/targets.example.ecdsa.pem',
            '/etc/haproxy/certs/targets.example.rsa.pem'])
        # nginx: dual -> single takes the twin's pair away
        ssh.runs[:] = []
        t.deploy(self.b, {'preset': 'nginx'})
        ssh.runs[:] = []
        t.deploy(self.single, {'preset': 'nginx'})
        aside = [c for c, _i in ssh.runs if 'acme-stale' in c and 'for p in' in c][0]
        self.assertIn('/etc/nginx/ssl/targets.example.rsa.crt', aside)
        self.assertIn('/etc/nginx/ssl/targets.example.rsa.key', aside)
        self.assertNotIn('targets.example.crt ', aside + ' ')

    def test_f5_two_entries(self):
        routes = TT.F5Test().routes()
        ctx = TT.FakeCtx(routes)
        t = TT.make('f5', {'host': 'bigip', 'user': 'acme', 'password': 'pw'}, ctx)
        t.deploy(self.b, {'profiles': 'www_ssl', 'keep': 1})
        name = C.object_name(self.b, {})
        tname = C.object_name(self.b.alt, t.twin_options(self.b, {}))
        self.assertTrue(tname.startswith('acme-targets.example-rsa-'), tname)
        inst = [ctx.json(c)['name'] for c in ctx.find('POST', r'/sys/crypto/(cert|key)$')]
        for n in (name, tname):
            self.assertIn('/Common/' + n, inst)
        ups = {c['path'].rsplit('/', 1)[1]: c['body'] for c in ctx.find('POST', 'uploads/')}
        self.assertEqual(ups[tname + '.crt'], self.b.alt.cert_pem.encode())
        chains = ctx.json(ctx.find('PATCH', 'client-ssl')[0])['certKeyChain']
        by = {e['name']: e for e in chains}
        self.assertEqual(by['default']['cert'], '/Common/' + name)
        self.assertEqual(by['acme-rsa']['cert'], '/Common/' + tname)
        self.assertEqual(by['acme-rsa']['key'], '/Common/' + tname)
        self.assertTrue(by['acme-rsa']['chain'].startswith('/Common/acme-chain-'))
        self.assertEqual(by['rsa']['cert'], '/Common/rsa.crt')    # the profile's other kept
        # again with the twin's entry there: it is found by its name, not added twice
        ctx2 = TT.FakeCtx(routes)
        prof = {'name': 'www_ssl', 'certKeyChain': chains}
        ctx2.routes = [r for r in routes if 'client-ssl' not in r[1]] + [
            ('GET', r'/mgmt/tm/ltm/profile/client-ssl/~Common~www_ssl', (200, prof)),
            ('PATCH', r'/mgmt/tm/ltm/profile/client-ssl/~Common~www_ssl', (200, {}))]
        t2 = TT.make('f5', {'host': 'bigip', 'user': 'acme', 'password': 'pw'}, ctx2)
        t2.deploy(self.b, {'profiles': 'www_ssl', 'keep': 1, 'force': True})
        self.assertFalse(ctx2.find('PATCH', 'client-ssl'))          # unchanged

    def test_payloads(self):
        ctx = TT.FakeCtx([('GET', r'/secrets/', (404, {})), ('POST', r'/secrets$', (201, {}))])
        TT.make('kubernetes', {'host': 'https://k8s', 'token': 't'}, ctx).deploy(self.b, {})
        data = ctx.json(ctx.find('POST', '/secrets$')[0])['data']
        self.assertEqual(base64.b64decode(data['tls-rsa.crt']).decode(), self.b.alt.fullchain_pem)
        self.assertEqual(base64.b64decode(data['tls.crt']).decode(), self.b.fullchain_pem)
        ctx = TT.FakeCtx([('GET', r'/v1/secret/data/', (404, {})),
                          ('POST', r'/v1/secret/data/', (200, {'data': {'version': 1}}))])
        TT.make('vault', {'host': 'https://v', 'token': 't'}, ctx).deploy(self.b, {})
        data = ctx.json(ctx.find('POST', '/v1/secret/data/')[0])['data']
        self.assertEqual(data['alt_certificate'], self.b.alt.cert_pem)
        self.assertEqual(data['alt_key_type'], 'rsa-2048')
        self.assertIn('alt_private_key', data)
        ctx = TT.FakeCtx([('POST', r'hook', (200, {}))])
        TT.make('webhook', {'url': 'https://h/hook'}, ctx).deploy(self.b, {})
        body = ctx.json(ctx.find('POST', 'hook')[0])
        self.assertEqual(body['alt']['fingerprint'], C.fp_of(self.b.alt))
        self.assertNotIn('key_pem', body['alt'])                   # no keys: none of either

    def test_appliance_puts_the_twin(self):
        put = []

        class Ctx(TT.FakeCtx):
            def pages_where(self):
                return {'node': 'n1', 'nodes': ['n1'], 'cluster': False, 'vip': {'on': False}}

            def pages_get(self, where):
                return put[-1] if put else None

            def pages_put(self, where, cert_pem, key_pem, chain_pems=None, how='', alt=None):
                put.append({'fingerprint': hashlib.sha256(C.pem_to_der(cert_pem)).hexdigest(),
                            'alt_fingerprint': hashlib.sha256(C.pem_to_der(alt[0])).hexdigest()
                            if alt else ''})
                return {'cn': 'x', 'verify': ''}
        t = TT.make('appliance', {}, Ctx())
        t.deploy(self.b, {'where': 'this'})
        self.assertEqual(put[0]['alt_fingerprint'], C.fp_of(self.b.alt))
        self.assertTrue(t.verify(self.b, {'where': 'this'}))
        self.assertIn('already', t.deploy(self.b, {'where': 'this'}))
        put[-1]['alt_fingerprint'] = 'f' * 64                        # another twin there
        self.assertFalse(t.verify(self.b, {'where': 'this'}))
        self.assertIn('on the pages', t.deploy(self.b, {'where': 'this'}))


class DualVerify(unittest.TestCase):
    """The TLS check asks for each variant of a server that holds both."""
    @classmethod
    def setUpClass(cls):
        cls.cid = own_dual('verify.example')
        cls.b = S.bundle_of(S.cert_get(STORE, cls.cid))
        cls.d = tempfile.mkdtemp(dir=TMP)
        files = []
        for i, one in enumerate(cls.b.variants()):
            c, k = os.path.join(cls.d, '%d.crt' % i), os.path.join(cls.d, '%d.key' % i)
            with open(c, 'w') as f:
                f.write(one.fullchain_pem)
            with open(k, 'w') as f:
                f.write(one.key_pem)
            files.append((c, k))
        cls.both = cls.serve(files)
        cls.ec_only = cls.serve(files[:1])

    @staticmethod
    def serve(files):
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        for c, k in files:
            sctx.load_cert_chain(c, k)          # one of each kind: OpenSSL keeps both
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        sock.listen(8)

        def loop():
            while True:
                try:
                    conn, _ = sock.accept()
                except OSError:
                    return
                try:
                    with sctx.wrap_socket(conn, server_side=True) as t:
                        t.recv(1)
                except (ssl.SSLError, OSError):
                    pass
        threading.Thread(target=loop, daemon=True).start()
        return sock

    @classmethod
    def tearDownClass(cls):
        cls.both.close()
        cls.ec_only.close()

    def hp(self, sock):
        return '127.0.0.1:%d' % sock.getsockname()[1]

    def test_each_variant_served(self):
        port = self.both.getsockname()[1]
        self.assertEqual(C.served_fingerprint('127.0.0.1', port, only='ec'), C.fp_of(self.b))
        self.assertEqual(C.served_fingerprint('127.0.0.1', port, only='rsa'),
                         C.fp_of(self.b.alt))
        ctx = TT.FakeCtx()
        self.assertTrue(C.check_served(ctx, self.b, self.hp(self.both), tries=1))
        said = ' '.join(w for _l, w in ctx.steps)
        self.assertIn('serves the new EC certificate', said)
        self.assertIn('serves the new RSA certificate', said)

    def test_twin_not_served(self):
        ctx = TT.FakeCtx()
        self.assertFalse(C.check_served(ctx, self.b, self.hp(self.ec_only), tries=1))
        self.assertIn('does not serve the RSA certificate', ' '.join(w for _l, w in ctx.steps))
        # a target given one of the two (not dual) checks that one as before
        ctx = TT.FakeCtx()
        single = S.bundle_of(S.cert_get(STORE, self.cid), variant='main')
        self.assertTrue(C.check_served(ctx, single, self.hp(self.ec_only), tries=1))

    def test_through_a_target(self):
        t = TT.make('ssh', {'host': '127.0.0.1'}, TT.FakeCtx())
        self.assertTrue(t.verify(self.b, {'verify': self.hp(self.both)}))


class DualBackup(unittest.TestCase):
    def test_backup_opens_the_twins_key(self):
        cid = own_dual('backup.example')
        path = os.path.join(TMP, 'copy.json.gz')
        with open(path, 'wb') as f:
            E.dump_tables(STORE.db, f)
        got = E.copy_read_through(path, E.sealing_key(), child=True, sample=100000)
        self.assertEqual(got['opened'], got['tried'], got)
        with gzip.open(path, 'rt') as f:
            text = f.read()
        self.assertIn('alt_key_sealed', text)
        self.assertIn(('certs', 'alt_key_sealed'), E.sealed_columns())
        row = S.cert_get(STORE, cid)
        self.assertEqual(E.seal_bind('certs', row, 'alt_key_sealed'),
                         S.key_place(cid, row['alt_version'], 'alt'))
        v = S.version_row(STORE, cid, row['alt_version'])
        self.assertEqual(E.seal_bind('cert_versions', v, 'key_sealed'),
                         S.key_place(cid, row['alt_version'], 'alt'))
        self.assertIsNotNone(E.unseal_secret(v['key_sealed'], E.seal_bind('cert_versions', v,
                                                                           'key_sealed')))
        out = E.carry_export(STORE, True)
        mine = [r for r in out.get('certs', []) if r['id'] == cid][0]
        self.assertIn('PRIVATE KEY', mine.get('alt_key_sealed') or '')


# ---------------------------------------------------------------------------
@unittest.skipUnless(os.environ.get('ACME_TEST_PEBBLE'),
                     'set ACME_TEST_PEBBLE=/path/to/pebble for a dual order from pebble')
class DualPebble(unittest.TestCase):
    def test_dual_order(self):
        exe = os.environ['ACME_TEST_PEBBLE']
        d = tempfile.mkdtemp(prefix='acme-pebble-dual-')
        ca = TI.TestCA('Pebble TLS Root')
        try:
            k = os.path.join(d, 'tls.key')
            TI.openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-out', k])
            csr = TI.openssl(['req', '-new', '-key', k, '-subj', '/CN=localhost',
                              '-outform', 'DER'])
            TI.wr(os.path.join(d, 'tls.crt'), ca.sign_csr(csr, ['localhost', '127.0.0.1']))
            s = socket.socket()
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
            s.close()
            board = {'dns': {}, 'http': {}}

            class H(TI.Quiet):
                def do_GET(self):
                    tok = self.path.rsplit('/', 1)[-1]
                    if tok in board['http']:
                        self.send(200, board['http'][tok], 'application/octet-stream')
                    else:
                        self.send(404)
            web = TI.Server(H)
            conf = {'pebble': {'listenAddress': '127.0.0.1:%d' % port,
                               'managementListenAddress': '127.0.0.1:0',
                               'certificate': os.path.join(d, 'tls.crt'), 'privateKey': k,
                               'httpPort': web.port, 'tlsPort': 5001, 'ocspResponderURL': '',
                               'externalAccountBindingRequired': False}}
            TI.wr(os.path.join(d, 'p.json'), json.dumps(conf))
            env = dict(os.environ, PEBBLE_VA_NOSLEEP='1', PEBBLE_WFE_NONCEREJECT='0',
                       PEBBLE_AUTHZREUSE='100')
            logf = open(os.path.join(d, 'log'), 'w')
            proc = subprocess.Popen([exe, '-config', os.path.join(d, 'p.json')], env=env,
                                    stdout=logf, stderr=subprocess.STDOUT)
            try:
                for _ in range(50):
                    try:
                        socket.create_connection(('127.0.0.1', port), 0.2).close()
                        break
                    except OSError:
                        time.sleep(0.1)
                ctx = TI.FakeContext()
                iss = TI.AcmeIssuer({'directory': 'custom',
                                     'directory_url': 'https://localhost:%d/dir' % port,
                                     'ca_pem': ca.pem, 'contacts': ['pki@example.com'],
                                     'poll_every': 0.5, 'wait_ready': 5, 'wait_valid': 60,
                                     'wait_order': 60}, ctx)
                self.assertTrue(iss.can_dual())
                names = ['localhost']
                ch = TI.FakeChallenge(('http-01',), board)
                got = {}
                for kind in ('ec', 'rsa'):
                    key, csr_pem, csr_der = TI.make_key_csr(names, kind)
                    got[kind] = iss.issue(base.CertRequest(
                        names=names, key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                        challenges={'localhost': ch}))
                    self.assertTrue(pki.key_matches(got[kind].cert_pem, key))
                self.assertEqual(pki.cert_info(got['ec'].cert_pem)['key_type'], 'ec-256')
                self.assertEqual(pki.cert_info(got['rsa'].cert_pem)['key_type'], 'rsa-2048')
                # the second order: the authorization reused, nothing presented again
                self.assertEqual([x for x in ch.log if x[0] == 'present'], [('present',
                                                                           'localhost')])
                self.assertEqual([x for x in ch.log if x[0] == 'cleanup'], [('cleanup',
                                                                           'localhost')])
                self.assertTrue(any('every name is proved already' in w for _l, w in ctx.steps))
            finally:
                proc.terminate()
                proc.wait()
                logf.close()
                web.close()
        finally:
            ca.close()
            shutil.rmtree(d, ignore_errors=True)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
