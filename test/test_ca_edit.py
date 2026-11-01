#!/usr/bin/env python3
"""An authority of acme's own changed after it was made (docs/own-ca.md,
"Changing an authority"): its settings edited, renamed with what refers to it,
its certificate renewed with the same key.

    python3 test/test_ca_edit.py

No root, no daemon: the engine's own Storage on SQLite in a folder of its
own, the routes asked as the command line asks them (engine cli_api), the
command line itself run for --ca-edit / --ca-renew / --ca-versions, and
openssl to verify what comes out.

- POST /api/cas/save: days, CRL days (the CRL made anew, its life the new
  one), URLs (in what is signed from then on), note, default EKU; a name that
  is not safe refused; events written;
- a rename: the source that signs with it (internal_ca "ca"), the default
  authority, its /pki/ address (a new slug, the OLD one still answering - a
  certificate signed before carries it), acme's own addresses following;
- POST /api/cas/renew of a root: the same key, subject and key identifier, a
  new serial and validity; a certificate signed BEFORE verifies against the
  NEW root; the CRL made anew and signed by it; /pki/ serves the new one; the
  versions list both;
- of an intermediate under one of acme's own: signed by its parent again, the
  chains of the authorities under it made anew, a leaf verifies;
- of one under a CA elsewhere: a request with the same key, the answer
  installed (POST /api/cas/install_cert), a new version;
- switched off: it signs nothing, its CRL is still made and published, what
  relies on it is listed;
- a backup carries the versions (and every sealed key still opens).
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-caedit-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = dict(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
           ACME_LOGDIR=TMP)
os.environ.update(ENV)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import api as API, ca as CA, pki, publish  # noqa: E402,F401
from acmelib.certs.cli import _Daemon  # noqa: E402
from acmelib.certs.pki import PkiError  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
DAEMON = _Daemon(STORE)


def call(method, path, body=None, args=None):
    return E.cli_api(DAEMON, 'tester', method, path, body=body, args=args)


def make_ca(name, parent=None, **kw):
    body = {'name': name, 'subject': {'CN': name, 'O': 'Test', 'C': 'CZ'}, 'key_type': 'ec-256',
            'days': kw.pop('days', 3650)}
    if parent:
        body['parent_id'] = parent
    body.update(kw)
    return int(call('POST', '/api/cas/create', body)['id'])


def leaf(ca_id, names=('www.test.example',), **kw):
    key = pki.make_key('ec-256')
    csr, _der = pki.make_csr(key, list(names))
    return CA.ca_sign(STORE, ca_id, csr, kw.pop('days', 0), kw.pop('profile', None))


def verify(root_pem, leaf_pem, untrusted=()):
    d = tempfile.mkdtemp(prefix='acme-verify-')
    try:
        with open(os.path.join(d, 'root.pem'), 'w') as f:
            f.write(root_pem)
        with open(os.path.join(d, 'leaf.pem'), 'w') as f:
            f.write(leaf_pem)
        args = ['openssl', 'verify', '-CAfile', os.path.join(d, 'root.pem')]
        if untrusted:
            with open(os.path.join(d, 'mid.pem'), 'w') as f:
                f.write(''.join(untrusted))
            args += ['-untrusted', os.path.join(d, 'mid.pem')]
        got = subprocess.run(args + [os.path.join(d, 'leaf.pem')], capture_output=True,
                             text=True)
        return got.returncode == 0, got.stdout + got.stderr
    finally:
        shutil.rmtree(d, ignore_errors=True)


def row(ca_id):
    return CA._row(STORE, ca_id)


def events(words):
    return [r for r in STORE.db.rows('SELECT words, level FROM events ORDER BY id')
            if words in (r['words'] or '')]


def served(what, slug):
    got = call('GET', '/api/pki/%s' % what, args={'ca': slug})
    return base64.b64decode(got['data_b64'])


class EditFields(unittest.TestCase):
    def test_edit_fields(self):
        ident = make_ca('Edit Root')
        got = call('POST', '/api/cas/save', {'id': ident, 'days_default': 90, 'crl_days': 3,
                                             'note': 'for the lab',
                                             'ocsp_url': 'http://ocsp.test.example/',
                                             'eku': ['clientAuth']})
        self.assertEqual(set(got['changed']), {'days_default', 'crl_days', 'note', 'ocsp_url',
                                               'eku'})
        self.assertTrue(any('from now on' in w for w in got['warnings']), got['warnings'])
        r = row(ident)
        self.assertEqual((r['days_default'], r['crl_days'], r['note']), (90, 3, 'for the lab'))
        crl = pki.crl_info(r['crl_pem'])
        self.assertAlmostEqual(crl['next_update'] - crl['this_update'], 3 * 86400, delta=120)
        cert, _chain = leaf(ident)
        i = pki.cert_info(cert)
        self.assertAlmostEqual(i['not_after'] - time.time(), 90 * 86400, delta=7200)
        self.assertEqual(i['eku'], ['clientAuth'])
        self.assertIn('http://ocsp.test.example/', i['ocsp'])
        # Nothing asked: nothing changed.
        self.assertEqual(call('POST', '/api/cas/save', {'id': ident, 'note': 'for the lab'})
                         ['changed'], {})
        with self.assertRaises(SystemExit):
            call('POST', '/api/cas/save', {'id': ident, 'name': "Bob's (CA)"})
        with self.assertRaises(SystemExit):
            call('POST', '/api/cas/save', {'id': ident, 'crl_url': 'ftp://x'})
        with self.assertRaises(SystemExit):
            call('POST', '/api/cas/save', {'id': ident, 'crl_days': 0})
        self.assertTrue(events('authority Edit Root edited by tester'))
        self.assertEqual(row(ident)['note'], 'for the lab')

    def test_rename_with_references(self):
        ident = make_ca('Old Name CA')
        old_slug = publish.slug_of(STORE, row(ident))
        r0 = row(ident)
        self.assertTrue(r0['crl_url'].endswith('/%s.crl' % old_slug), r0['crl_url'])
        before, _chain = leaf(ident, ['old.test.example'])
        STORE.db.insert('cert_issuers', {'name': 'Own CA source', 'kind': 'internal_ca',
                                         'config': json.dumps({'ca': 'Old Name CA', 'days': 30}),
                                         'enabled': 1, 'created': time.time()})
        call('POST', '/api/cas/default', {'id': ident})
        got = call('POST', '/api/cas/save', {'id': ident, 'name': 'New Name CA'})
        self.assertEqual(got['name'], 'New Name CA')
        r = row(ident)
        self.assertEqual(r['name'], 'New Name CA')
        cfg = json.loads(STORE.db.value("SELECT config FROM cert_issuers WHERE name = "
                                        "'Own CA source'"))
        self.assertEqual(cfg['ca'], 'New Name CA')
        self.assertEqual(STORE.get_meta('certs:default_ca'), str(ident))
        new_slug = publish.slug_of(STORE, r)
        self.assertNotEqual(new_slug, old_slug)
        self.assertEqual(new_slug, 'new-name-ca')
        # acme's own addresses follow the new name, for what it signs from now on ...
        self.assertTrue(r['crl_url'].endswith('/new-name-ca.crl'), r['crl_url'])
        self.assertTrue(r['aia_url'].endswith('/new-name-ca.crt'), r['aia_url'])
        self.assertTrue(any('answer still' in w for w in got['warnings']), got['warnings'])
        # ... and what was signed before still finds its CRL and its issuer.
        old_cdp = pki.cert_info(before)['crl'][0]
        self.assertTrue(old_cdp.endswith('/%s.crl' % old_slug))
        for slug in (old_slug, new_slug):
            crl = served('crl', slug)
            self.assertEqual(pki.crl_info(crl)['issuer_dn'], r['subject_dn'])
            self.assertEqual(pki.cert_info(served('cert', slug))['sha256'], r['fingerprint'])
        self.assertIn(old_slug, [a for a in publish.aliases_of(r)])
        # The source signs with it still, by its new name.
        cert, _c = leaf(cfg['ca'], ['new.test.example'])
        self.assertTrue(pki.cert_info(cert)['crl'][0].endswith('/new-name-ca.crl'))
        self.assertTrue(events('name Old Name CA -> New Name CA'))
        # Another authority cannot take the old address (nor the name).
        other = make_ca('Old Name CA')
        self.assertNotEqual(publish.slug_of(STORE, row(other)), old_slug)
        with self.assertRaises(SystemExit):
            call('POST', '/api/cas/save', {'id': other, 'name': 'New Name CA'})


class Renew(unittest.TestCase):
    def test_renew_root(self):
        ident = make_ca('Renew Root', days=400)
        cert_before, _c = leaf(ident, ['before.test.example'], days=200)
        old = row(ident)
        oi = pki.cert_info(old['cert_pem'])
        crl_no = int(old['crl_number'])
        got = call('POST', '/api/cas/renew', {'id': ident, 'days': 4000})
        self.assertFalse(got['pending'])
        self.assertTrue(got['root'])
        self.assertTrue(any('before the old one ends' in w for w in got['warnings']))
        new = row(ident)
        ni = pki.cert_info(new['cert_pem'])
        self.assertEqual(ni['pub_sha256'], oi['pub_sha256'])
        self.assertEqual(ni['ski'], oi['ski'])
        self.assertEqual(ni['subject_der'], oi['subject_der'])
        self.assertTrue(ni['self_signed'])
        self.assertNotEqual(ni['serial'], oi['serial'])
        self.assertGreater(ni['not_after'], oi['not_after'] + 3000 * 86400)
        self.assertEqual(ni['key_usage'], oi['key_usage'])
        self.assertTrue(ni['is_ca'])
        ok, said = verify(new['cert_pem'], cert_before)
        self.assertTrue(ok, said)
        ok, said = verify(old['cert_pem'], cert_before)
        self.assertTrue(ok, said)
        # The CRL made anew, signed by the key of both.
        self.assertGreater(int(new['crl_number']), crl_no)
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, 'ca.pem'), 'w') as f:
                f.write(new['cert_pem'])
            with open(os.path.join(d, 'crl.pem'), 'w') as f:
                f.write(new['crl_pem'])
            subprocess.run(['openssl', 'crl', '-in', os.path.join(d, 'crl.pem'), '-CAfile',
                            os.path.join(d, 'ca.pem'), '-noout'], check=True,
                           capture_output=True)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        slug = publish.slug_of(STORE, new)
        self.assertEqual(pki.cert_info(served('cert', slug))['sha256'], ni['sha256'])
        vers = call('GET', '/api/cas/versions', args={'id': ident})['rows']
        self.assertEqual([v['version'] for v in vers], [2, 1])
        self.assertTrue(vers[0]['current'] and not vers[1]['current'])
        self.assertEqual(vers[1]['fingerprint'], oi['sha256'])
        self.assertEqual(vers[0]['fingerprint'], ni['sha256'])
        # A new path length and name constraints, when asked.
        call('POST', '/api/cas/renew', {'id': ident, 'path_len': 2,
                                        'name_constraints': ['test.example']})
        ri = pki.cert_info(row(ident)['cert_pem'])
        self.assertEqual(ri['path_len'], 2)
        self.assertEqual(ri['name_constraints'].get('permitted'), ['DNS:test.example'])
        self.assertEqual(ri['ski'], oi['ski'])
        self.assertTrue(events('authority Renew Root renewed with the same key'))
        with self.assertRaises(PkiError):           # outside its constraints now
            leaf(ident, ['www.other.example'])

    def test_renew_intermediate(self):
        root = make_ca('Chain Root', path_len=2)
        mid = make_ca('Chain Mid', parent=root, days=1000, path_len=1)
        sub = make_ca('Chain Sub', parent=mid, days=900, path_len=0)
        cert, chain = leaf(sub, ['deep.test.example'])
        old_mid = row(mid)
        issued = STORE.db.value('SELECT COUNT(*) FROM cert_ca_issued WHERE ca_id = ?', (root,))
        got = call('POST', '/api/cas/renew', {'id': mid, 'days': 500})
        self.assertFalse(got['root'])
        self.assertIn('Chain Sub', got['children'])
        new_mid = row(mid)
        a, b = pki.cert_info(old_mid['cert_pem']), pki.cert_info(new_mid['cert_pem'])
        self.assertNotEqual(a['serial'], b['serial'])
        self.assertEqual((a['ski'], a['aki'], a['subject_der'], a['path_len']),
                         (b['ski'], b['aki'], b['subject_der'], b['path_len']))
        self.assertEqual(new_mid['chain_pem'], row(root)['cert_pem'])
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_ca_issued WHERE ca_id = ?',
                                        (root,)), issued + 1)
        # The authority under it carries the new one in its chain.
        s = row(sub)
        self.assertEqual(pki.certs_in(s['chain_pem'])[0], pki.certs_in(new_mid['cert_pem'])[0])
        ok, said = verify(row(root)['cert_pem'], cert, [s['cert_pem'], new_mid['cert_pem']])
        self.assertTrue(ok, said)
        # The root renewed: every chain below made anew, all down.
        got = call('POST', '/api/cas/renew', {'id': root})
        self.assertEqual(set(got['children']), {'Chain Mid', 'Chain Sub'})
        self.assertEqual(pki.certs_in(row(sub)['chain_pem'])[1], row(root)['cert_pem'])
        ok, said = verify(row(root)['cert_pem'], cert, pki.certs_in(row(sub)['chain_pem'])[:1]
                          + [row(sub)['cert_pem']])
        self.assertTrue(ok, said)
        # A path length the parent does not allow is refused.
        with self.assertRaises(SystemExit):
            call('POST', '/api/cas/renew', {'id': sub, 'path_len': 3})

    def test_renew_under_a_ca_elsewhere(self):
        d = tempfile.mkdtemp(prefix='acme-outside-')
        try:
            def sh(*a):
                subprocess.run(list(a), check=True, capture_output=True, cwd=d)
            sh('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
               'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'root.key', '-out',
               'root.pem', '-days', '3650', '-subj', '/CN=Outside Root')
            with open(os.path.join(d, 'ext.cnf'), 'w') as f:
                f.write('[v3]\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, '
                        'keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n'
                        'authorityKeyIdentifier = keyid:always\n')

            def sign(csr_pem, days):
                with open(os.path.join(d, 'req.csr'), 'w') as f:
                    f.write(csr_pem)
                sh('openssl', 'x509', '-req', '-in', 'req.csr', '-CA', 'root.pem', '-CAkey',
                   'root.key', '-CAcreateserial', '-days', str(days), '-extfile', 'ext.cnf',
                   '-extensions', 'v3', '-out', 'out.pem')
                with open(os.path.join(d, 'out.pem')) as f:
                    return f.read()
            with open(os.path.join(d, 'root.pem')) as f:
                outside = f.read()
            ident, csr = CA.ca_csr(STORE, 'Outside Mid', {'CN': 'Outside Mid', 'O': 'Test'},
                                   key_type='ec-256')
            call('POST', '/api/cas/install_cert', {'id': ident, 'cert_pem': sign(csr, 100),
                                                   'chain_pem': outside})
            first = row(ident)
            cert, _c = leaf(ident, ['far.test.example'])
            got = call('POST', '/api/cas/renew', {'id': ident})
            self.assertTrue(got['pending'])
            self.assertIn('CERTIFICATE REQUEST', got['csr_pem'])
            self.assertEqual(pki.csr_info(got['csr_pem'])['pub_sha256'],
                             pki.cert_info(first['cert_pem'])['pub_sha256'])
            self.assertEqual(CA.ca_export(STORE, ident, 'csr')['data'].decode(), got['csr_pem'])
            self.assertEqual(row(ident)['fingerprint'], first['fingerprint'])   # not yet
            call('POST', '/api/cas/install_cert', {'id': ident,
                                                   'cert_pem': sign(got['csr_pem'], 400)})
            now = row(ident)
            self.assertNotEqual(now['fingerprint'], first['fingerprint'])
            self.assertGreater(now['not_after'], first['not_after'])
            self.assertEqual(now['chain_pem'], first['chain_pem'])
            self.assertFalse(CA.ca_get(STORE, ident)['renew_csr_pem'])
            self.assertEqual(len(CA.ca_versions(STORE, ident)), 2)
            ok, said = verify(outside, cert, [now['cert_pem']])
            self.assertTrue(ok, said)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class SwitchedOff(unittest.TestCase):
    def test_disabled_signs_nothing_but_publishes(self):
        ident = make_ca('Off CA')
        STORE.db.insert('cert_issuers', {'name': 'Off source', 'kind': 'internal_ca',
                                         'config': json.dumps({'ca': str(ident)}),
                                         'enabled': 1, 'created': time.time()})
        STORE.db.insert('certs', {'name': 'off-web', 'issuer': 'Off source',
                                  'names': json.dumps(['off.test.example']),
                                  'key_type': 'ec-256', 'created': time.time(), 'version': 0})
        dep = call('GET', '/api/cas/dependents', args={'id': ident})
        self.assertEqual((dep['sources'], dep['certs']), (['Off source'], ['off-web']))
        got = call('POST', '/api/cas/save', {'id': ident, 'disabled': True})
        self.assertTrue(any('Off source' in w and 'off-web' in w for w in got['warnings']),
                        got['warnings'])
        self.assertTrue([e for e in events('Off CA signs nothing now') if e['level'] == 'warn'])
        with self.assertRaises(PkiError):
            leaf(ident)
        number = int(row(ident)['crl_number'])
        crl = served('crl', publish.slug_of(STORE, row(ident)))
        self.assertEqual(pki.crl_info(crl)['issuer_dn'], row(ident)['subject_dn'])
        CA.ca_crl(STORE, ident)
        self.assertEqual(int(row(ident)['crl_number']), number + 1)
        # The leader's refresh keeps its CRL fresh too.
        STORE.db.run('UPDATE cert_cas SET crl_pem = ? WHERE id = ?', ('', ident))
        self.assertIn('Off CA', publish.refresh(STORE))
        call('POST', '/api/cas/save', {'id': ident, 'disabled': False})
        leaf(ident)


class Backups(unittest.TestCase):
    def test_backup_carries_versions(self):
        ident = make_ca('Backup Root')
        call('POST', '/api/cas/renew', {'id': ident, 'days': 5000})
        want = STORE.db.value('SELECT COUNT(*) FROM cert_ca_versions')
        self.assertGreaterEqual(want, 2)
        path = os.path.join(TMP, 'copy.json.gz')
        with open(path, 'wb') as f:
            E.dump_tables(STORE.db, f)
        got = E.copy_read_through(path, E.sealing_key(), child=True)
        self.assertEqual(got['counts'].get('cert_ca_versions'), want, got['counts'])
        self.assertEqual(got['opened'], got['tried'], got)
        self.assertIn('cert_ca_versions', E.TABLES)


class CommandLine(unittest.TestCase):
    def cli(self, *args):
        env = dict(os.environ, ACME_STAY_ROOT='1', NO_COLOR='1', **ENV)
        got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(args),
                             env=env, capture_output=True, text=True, input='', timeout=180)
        self.assertEqual(got.returncode, 0, '%s: %s %s' % (args, got.stdout[-2000:],
                                                           got.stderr[-2000:]))
        return got.stdout

    def test_cli(self):
        ident = make_ca('Cli CA', days=300)
        out = self.cli('--ca-edit', 'Cli CA', '--set', 'note=from the command line', '--set',
                       'days_default=60')
        self.assertIn('days_default', out)
        self.assertEqual(row(ident)['note'], 'from the command line')
        self.assertEqual(row(ident)['days_default'], 60)
        self.cli('--ca-renew', 'Cli CA', '--days', '900', '--path-len', '1')
        i = pki.cert_info(row(ident)['cert_pem'])
        self.assertEqual(i['path_len'], 1)
        self.assertGreater(i['not_after'], time.time() + 800 * 86400)
        out = self.cli('--ca-versions', 'Cli CA')
        self.assertIn('renewed', out)
        got = json.loads(self.cli('--ca-versions', 'Cli CA', '--json'))
        self.assertEqual(len(got['rows']), 2)
        self.cli('--ca-edit', 'Cli CA', '--set', 'name=Cli CA renamed')
        self.assertEqual(row(ident)['name'], 'Cli CA renamed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
