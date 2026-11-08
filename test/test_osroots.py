"""The system's trusted roots (1.0.59, as otp 1.0.265).

    python3 test/test_osroots.py

- reading a certificate, in the daemon and in the root helper alike (the same words): what is
  refused (a private key, PKCS#7, not an authority, a key that may not sign certificates, not
  base64, too large) and what is only said (ran out, SHA-1, a short RSA key, an intermediate
  without its root); a chain; DER; the limits;
- the set wanted: the newest v of every node's row wins, v counted above every v seen; added,
  taken away by a fingerprint's prefix; signed by the database guard; an event for each change;
- each node: its root helper asked (list / sync) and its own row written; the status words;
- the root helper (deploy/acme_web.py) against a folder and a tool of the test's: the whole set
  put in, the tool run only when anything changed, the files of others never touched, a link
  never followed, a folder that is a link or not root's refused, the answer to osroots.ask;
- the pages: the relay passes /api/osroots both ways, the card is in Certificates and TLS,
  acme-web.path starts the helper for osroots.ask; who may read and who may change;
- the command line: --os-roots, --os-roots-add FILE (read before the service's account takes
  over), --os-roots-remove FP.
"""
import base64
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-osroots-')
os.makedirs(os.path.join(TMP, 'web'), exist_ok=True)
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_NET_SNAP_DIR=os.path.join(TMP, 'root-only'))
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
import acmelib.engine as ENG  # noqa: E402  (the namespace the engine's functions see)

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def helper():
    spec = importlib.util.spec_from_file_location('acme_web_osr', os.path.join(ROOT, 'deploy', 'acme_web.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


W = helper()
CERTS = os.path.join(TMP, 'certs')
os.makedirs(CERTS)

CA_EXT = 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'


def text(path):
    with open(path) as f:
        return f.read()


def _ossl(*args):
    got = subprocess.run(['openssl'] + list(args), capture_output=True, text=True)
    if got.returncode != 0:
        raise RuntimeError(got.stderr)
    return got.stdout


def mk(name, cn, issuer=None, ext=CA_EXT, key='ec', md='sha256'):
    """A certificate made by openssl: self-signed, or signed by `issuer` (a name made before).
    ext None: a version 1 certificate - no extensions at all."""
    k, csr, crt = (os.path.join(CERTS, name + x) for x in ('.key', '.csr', '.pem'))
    if key == 'ec':
        _ossl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
              '-keyout', k, '-subj', '/O=Test/CN=' + cn, '-out', csr)
    else:
        _ossl('req', '-new', '-newkey', 'rsa:%d' % key, '-nodes', '-keyout', k,
              '-subj', '/O=Test/CN=' + cn, '-out', csr)
    args = ['x509', '-req', '-in', csr, '-days', '3650', '-out', crt, '-' + md]
    if issuer:
        args += ['-CA', os.path.join(CERTS, issuer + '.pem'), '-CAkey', os.path.join(CERTS, issuer + '.key'),
                 '-CAcreateserial']
    else:
        args += ['-signkey', k]
    if ext is not None:
        e = os.path.join(CERTS, name + '.ext')
        with open(e, 'w') as f:
            f.write(ext)
        args += ['-extfile', e]
    _ossl(*args)
    with open(crt) as f:
        return f.read()


ROOT_CA = mk('root', 'Example Corp Root CA')
INTER = mk('inter', 'Example Corp Issuing CA 1', 'root')
LEAF = mk('leaf', 'ldap.example.local', 'inter', ext='basicConstraints=CA:FALSE\nsubjectAltName=DNS:ldap.example.local\n')
NOBC = mk('nobc', 'No Constraints', ext=None)
NOSIGN = mk('nosign', 'No Sign CA', ext='basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\n')
OTHER = mk('other', 'Lab LDAPS CA')
SHA1 = mk('sha1', 'Old Issuing CA', 'root', md='sha1')
SHORT = mk('short', 'Short Key CA', key=1024)
KEY_TEXT = text(os.path.join(CERTS, 'root.key'))


def der_of(pem):
    return base64.b64decode(''.join(pem.strip().splitlines()[1:-1]))


def fp_of(pem):
    import hashlib
    return hashlib.sha256(der_of(pem)).hexdigest()


def clear_set():
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'oscerts:%'")
    E.OSR_FACTS.clear()


class TestReading(unittest.TestCase):
    """What a certificate is - the daemon and the root helper say the same."""

    def facts(self, pem):
        (p, d), = E.osr_blocks(pem)
        f = E.osr_facts(p, d)
        (p2, d2), = W.osroots_blocks(pem)
        g = W.osroots_facts(p2, d2)
        for k in ('fp', 'cn', 'subject', 'issuer', 'kind', 'key', 'refused', 'warn', 'not_after'):
            self.assertEqual(f[k], g[k], k)
        return f

    def test_a_root_is_taken(self):
        f = self.facts(ROOT_CA)
        self.assertEqual((f['kind'], f['cn'], f['refused'], f['warn']), ('root', 'Example Corp Root CA', [], []))
        self.assertEqual(f['fp'], fp_of(ROOT_CA))
        self.assertTrue(f['key'].startswith('EC '))

    def test_an_intermediate(self):
        f = self.facts(INTER)
        self.assertEqual(f['kind'], 'intermediate')
        self.assertIn('CN=Example Corp Root CA', f['issuer'])
        self.assertEqual(f['refused'], [])

    def test_not_an_authority_refused(self):
        self.assertEqual(self.facts(LEAF)['refused'], [
            "it is not a certificate authority (CA:FALSE) - a server's own certificate does not go here"])
        self.assertIn('no basicConstraints CA:TRUE', self.facts(NOBC)['refused'][0])
        self.assertEqual(self.facts(NOSIGN)['refused'],
                         ['its key usage does not let it sign certificates (no keyCertSign)'])

    def test_warnings(self):
        self.assertIn('the system\'s crypto policy (DEFAULT) refuses it', ' '.join(self.facts(SHA1)['warn']))
        f = self.facts(SHORT)
        self.assertEqual(f['key'], 'RSA 1024')
        self.assertIn('its key has 1024 bits', ' '.join(f['warn']))
        self.assertEqual(f['refused'], [])

    def test_ran_out_said(self):
        try:
            import datetime
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import NameOID
        except ImportError:
            self.skipTest('cryptography is not installed')
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Old Root')])
        now = datetime.datetime.now(datetime.timezone.utc)
        c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
             .serial_number(1).not_valid_before(now - datetime.timedelta(days=400))
             .not_valid_after(now - datetime.timedelta(days=10))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
             .sign(key, hashes.SHA256()))
        f = self.facts(c.public_bytes(serialization.Encoding.PEM).decode())
        self.assertTrue(f['warn'][0].startswith('it ran out on '), f['warn'])
        self.assertEqual(f['refused'], [])

    def test_whole_text_refused(self):
        for bad in (ROOT_CA + KEY_TEXT, '-----BEGIN PKCS7-----\nMAA=\n-----END PKCS7-----\n',
                    '-----BEGIN TRUSTED CERTIFICATE-----\nMAA=\n-----END TRUSTED CERTIFICATE-----\n',
                    '-----BEGIN ENCRYPTED PRIVATE KEY-----\nMAA=\n-----END ENCRYPTED PRIVATE KEY-----\n'):
            with self.assertRaises(ValueError) as e:
                E.osr_blocks(bad)
            self.assertIn('no private key', str(e.exception))
            with self.assertRaises(W.Refused) as e2:
                W.osroots_blocks(bad)
            self.assertEqual(str(e.exception), str(e2.exception))

    def test_not_base64_empty_too_large(self):
        for text, words in (('-----BEGIN CERTIFICATE-----\nnot*base64\n-----END CERTIFICATE-----', 'no certificate'),
                            ('-----BEGIN CERTIFICATE-----\nAB=C\n-----END CERTIFICATE-----', 'not base64'),
                            ('', 'no certificate in it'), ('hello', 'no certificate in it'),
                            ('-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----' %
                             base64.b64encode(b'0' * 13000).decode(), 'a few kB at most')):
            with self.assertRaises(ValueError) as e:
                E.osr_blocks(text)
            self.assertIn(words, str(e.exception))
            with self.assertRaises(W.Refused) as e2:
                W.osroots_blocks(text)
            self.assertEqual(str(e.exception), str(e2.exception))
        with self.assertRaises(ValueError):
            E.osr_read_text('   ')
        with self.assertRaises(ValueError) as e:
            E.osr_read_text('x' * (E.OSR_MAX * E.OSR_PEM_MAX + 1))
        self.assertIn('far more than 50', str(e.exception))

    def test_der_read_as_pem(self):
        text = E.osr_text(der_of(ROOT_CA))
        self.assertIn('-----BEGIN CERTIFICATE-----', text)
        self.assertEqual(E.osr_read_text(text)[0]['fp'], fp_of(ROOT_CA))
        with self.assertRaises(ValueError):
            E.osr_text(b'\x30\x03\x01\x02\x03')
        with self.assertRaises(ValueError):
            E.osr_text(b'just some text')


class TestTheSet(unittest.TestCase):
    def setUp(self):
        clear_set()

    def test_chain_and_lone_intermediate(self):
        got = E.osr_check(STORE, INTER + ROOT_CA)
        self.assertEqual([f['kind'] for f in got], ['intermediate', 'root'])
        self.assertFalse(any('without its root' in w for f in got for w in f['warn']))
        got = E.osr_check(STORE, INTER)
        self.assertIn('an intermediate without its root here', got[0]['warn'][-1])

    def test_add_check_remove(self):
        r = E.osr_add(STORE, INTER + ROOT_CA + LEAF, 'admin')
        self.assertEqual(sorted(a['cn'] for a in r['added']), ['Example Corp Issuing CA 1', 'Example Corp Root CA'])
        self.assertEqual(r['refused'][0]['cn'], 'ldap.example.local')
        w = E.osr_want(STORE)
        self.assertEqual(len(w['certs']), 2)
        self.assertEqual(w['node'], E.node_name())
        ev = STORE.db.rows("SELECT * FROM events ORDER BY id DESC LIMIT 1")[0]
        self.assertIn("the system's trusted roots of every node", str(dict(ev)))
        # The intermediate's root is in the set now: nothing said of it.
        self.assertTrue(E.osr_check(STORE, INTER)[0]['already'])
        self.assertFalse(any('without its root' in x for x in E.osr_check(STORE, SHA1)[0]['warn']))
        with self.assertRaises(ValueError) as e:
            E.osr_add(STORE, ROOT_CA, 'admin')
        self.assertIn('there already', str(e.exception))
        with self.assertRaises(ValueError) as e:
            E.osr_add(STORE, LEAF, 'admin')
        self.assertIn("a server's own certificate does not go here", str(e.exception))
        for fp, words in (('abc', '12 characters'), ('0' * 16, 'no certificate with that')):
            with self.assertRaises(ValueError) as e:
                E.osr_remove(STORE, fp, 'admin')
            self.assertIn(words, str(e.exception))
        E.osr_remove(STORE, fp_of(INTER)[:12].upper(), 'admin')
        self.assertEqual([c['cn'] for c in E.osr_want(STORE)['certs']], ['Example Corp Root CA'])

    def test_ambiguous_prefix(self):
        certs = [{'pem': ROOT_CA, 'fp': 'ab' * 6 + '1' * 52, 'cn': 'a'}, {'pem': ROOT_CA, 'fp': 'ab' * 6 + '2' * 52, 'cn': 'b'}]
        with self.assertRaises(ValueError) as e:
            E.osr_find(certs, 'ab' * 6)
        self.assertIn('more than one', str(e.exception))

    def test_at_most_fifty(self):
        certs = [{'pem': OTHER, 'fp': '%064x' % i, 'cn': 'x', 'kind': 'root'} for i in range(E.OSR_MAX)]
        STORE.set_meta('oscerts:want:' + E.node_name(), json.dumps({'v': 1, 'certs': certs}))
        with self.assertRaises(ValueError) as e:
            E.osr_add(STORE, ROOT_CA, 'admin')
        self.assertIn('50 certificates at most', str(e.exception))
        many = ''.join([ROOT_CA] * (E.OSR_MAX + 1))
        with self.assertRaises(ValueError) as e:
            E.osr_read_text(many)
        self.assertIn('51 certificates in it', str(e.exception))

    def test_newest_v_wins(self):
        a = {'v': 100, 'certs': [{'pem': ROOT_CA, 'fp': fp_of(ROOT_CA), 'cn': 'r'}], 'by': 'a', 'at': 1}
        b = {'v': 200, 'certs': [], 'by': 'b', 'at': 2}
        STORE.set_meta('oscerts:want:nodea', json.dumps(a))
        STORE.set_meta('oscerts:want:nodeb', json.dumps(b))
        w = E.osr_want(STORE)
        self.assertEqual((w['v'], w['node'], w['certs']), (200, 'nodeb', []))
        # A tie goes by the row's name; a row of another shape is passed over.
        STORE.set_meta('oscerts:want:nodec', json.dumps(dict(a, v=200)))
        STORE.set_meta('oscerts:want:noded', '[1, 2]')
        self.assertEqual(E.osr_want(STORE)['node'], 'nodec')
        # A clock far ahead on another node: this node's next set still counts above it.
        far = 10 ** 15
        STORE.set_meta('oscerts:want:nodeb', json.dumps(dict(b, v=far)))
        E.osr_add(STORE, OTHER, 'admin')
        w = E.osr_want(STORE)
        self.assertEqual((w['v'], w['node']), (far + 1, E.node_name()))
        # The set's hash does not hang on the order.
        x, y = {'fp': '1' * 64}, {'fp': '2' * 64}
        self.assertEqual(E.osr_hash([x, y]), E.osr_hash([y, x]))

    def test_signed_by_the_guard(self):
        self.assertTrue(E.dbguard_meta_kept('oscerts:want:node1'))
        self.assertFalse(E.dbguard_meta_kept('oscerts:node:node1'))
        with mock.patch.dict(E.CONFIG, {'db_guard': 1}):
            E.osr_add(STORE, ROOT_CA, 'admin')
            self.assertIsNotNone(E.osr_want(STORE))
            # Written past acme: not its word, as if it were not there.
            STORE.db.run("UPDATE meta SET v = ? WHERE k = ?", (json.dumps({'v': 5, 'certs': []}),
                                                                'oscerts:want:' + E.node_name()))
            self.assertIsNone(E.osr_want(STORE))


class TestEachNode(unittest.TestCase):
    def setUp(self):
        clear_set()
        E.OSR.update(busy=False, done_hash=None, done_at=0.0, fail_hash=None, fail_at=0.0, again_seen=None)

    def test_run_writes_the_row_and_status(self):
        E.osr_add(STORE, ROOT_CA, 'admin')
        want = E.osr_want(STORE)
        answer = {'said': ['added acme-%s.crt' % fp_of(ROOT_CA)[:16], 'update-ca-certificates run'], 'refused': [],
                  'ours': [{'fp': fp_of(ROOT_CA), 'file': 'acme-x.crt', 'in_bundle': True}], 'others': [],
                  'system': {'count': 123}, 'flavour': 'debian', 'dir': '/usr/local/share/ca-certificates',
                  'tool': 'update-ca-certificates', 'tool_there': True}
        with mock.patch.object(ENG, 'root_ask', return_value=answer) as ra:
            E.osroots_run(STORE, want)
        self.assertEqual(ra.call_args[0][2]['do'], 'sync')
        self.assertEqual(ra.call_args[0][2]['certs'], [ROOT_CA])
        row = json.loads(STORE.get_meta('oscerts:node:' + E.node_name()))
        self.assertTrue(row['ok'])
        self.assertNotIn('BEGIN CERTIFICATE', json.dumps(row))       # no PEMs in a node's row
        v = E.osr_view(STORE)
        me = [n for n in v['nodes'] if n['me']][0]
        self.assertEqual((me['status'], me['system']['count']), ('applied', 123))
        self.assertTrue(v['certs'][0]['on'][E.node_name()])
        self.assertFalse(E.OSR['busy'])

    def test_failed_and_waiting(self):
        E.osr_add(STORE, ROOT_CA, 'admin')
        want = E.osr_want(STORE)
        with mock.patch.object(ENG, 'root_ask', side_effect=ValueError('the root helper of this node did not answer')):
            E.osroots_run(STORE, want)
        st, why = E.osr_node_status(want, json.loads(STORE.get_meta('oscerts:node:' + E.node_name())), True)
        self.assertEqual((st, why), ('failed', 'the root helper of this node did not answer'))
        self.assertEqual(E.OSR['fail_hash'], want['hash'])
        self.assertEqual(E.osr_node_status(want, {}, False), ('waiting', 'not answering'))
        self.assertEqual(E.osr_node_status(want, {}, True), ('waiting', ''))
        late = dict(want, at=time.time() - 600)
        self.assertIn('acme-web.path running there', E.osr_node_status(late, {}, True)[1])
        self.assertEqual(E.osr_node_status(None, {}, True), ('none', ''))
        self.assertEqual(E.osr_node_status(want, {'at': 1, 'hash': want['hash'], 'ok': True,
                                                  'refused': [{'cn': 'x', 'why': 'y'}]}, True), ('failed', 'x - y'))

    def test_nothing_ever_wanted_only_lists(self):
        with mock.patch.object(ENG, 'root_ask', return_value={'said': [], 'ours': [], 'others': []}) as ra:
            E.osroots_run(STORE, None)
        self.assertEqual(ra.call_args[0][2], {'do': 'list'})
        self.assertEqual(E.osr_view(STORE)['nodes'][0]['status'], 'none')

    def test_tick_when_due(self):
        started = []
        with mock.patch.object(E.threading, 'Thread', side_effect=lambda **k: SimpleNamespace(
                start=lambda: started.append(k['args']))):
            daemon = SimpleNamespace(store=STORE)
            E.osroots_tick(daemon)                  # at the start: due
            self.assertEqual(len(started), 1)
            E.OSR.update(busy=False, done_at=time.time(), done_hash=None)
            E.osroots_tick(daemon)                  # nothing new
            self.assertEqual(len(started), 1)
            E.osr_add(STORE, ROOT_CA, 'admin')      # a new set: due
            E.osroots_tick(daemon)
            self.assertEqual(len(started), 2)
            E.OSR['busy'] = True                    # one at a time
            E.osr_again(STORE, 'admin')
            E.osroots_tick(daemon)
            self.assertEqual(len(started), 2)
            E.OSR['busy'] = False
            E.OSR['done_hash'] = E.osr_want(STORE)['hash']
            E.osroots_tick(daemon)                  # read again, asked
            self.assertEqual(len(started), 3)

    def test_python_trust(self):
        t = E.osr_python_trust()
        self.assertIn('system', t)
        with mock.patch.dict(os.environ, {'SSL_CERT_FILE': '', 'SSL_CERT_DIR': ''}), \
                mock.patch.object(E.ssl, 'get_default_verify_paths', return_value=SimpleNamespace(
                    cafile='/nowhere/cert.pem', capath='/nowhere/certs')), \
                mock.patch.object(ENG, 'OSR_SYSTEM_BUNDLES', (os.path.join(CERTS, 'root.pem'),)):
            E.osr_python_fix()
            self.assertEqual(os.environ.get('SSL_CERT_FILE'), os.path.join(CERTS, 'root.pem'))
        with mock.patch.dict(os.environ, {'SSL_CERT_FILE': '/given.pem'}):
            E.osr_python_fix()
            self.assertEqual(os.environ['SSL_CERT_FILE'], '/given.pem')


class TestRootHelper(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='osr-', dir=TMP)
        self.dir = os.path.join(self.d, 'local')
        os.makedirs(self.dir, 0o755)
        os.chmod(self.dir, 0o755)
        self.bundle = os.path.join(self.d, 'bundle.crt')
        self.count = os.path.join(self.d, 'runs')
        tool = os.path.join(self.d, 'update-ca-test')
        with open(tool, 'w') as f:
            f.write('#!/bin/sh\necho x >> %s\n[ -f %s/fail ] && { echo "it broke" >&2; exit 3; }\n'
                    'cat %s/base.pem > %s; find %s -maxdepth 2 -name "*.crt" -type f -exec cat {} + >> %s\n'
                    % (self.count, self.d, self.d, self.bundle, self.dir, self.bundle))
        os.chmod(tool, 0o755)
        with open(os.path.join(self.d, 'base.pem'), 'w') as f:
            f.write(SHA1)                           # the distribution's own list: one
        self.env = mock.patch.dict(os.environ, {'ACME_OSROOTS_FLAVOUR': 'debian', 'ACME_OSROOTS_DIR': self.dir,
                                                'ACME_OSROOTS_BUNDLE': self.bundle,
                                                'ACME_OSROOTS_EXTRACT': tool,
                                                'ACME_OSROOTS_PKG': 'echo ca-certificates-20260816'})
        self.env.start()
        # Somebody else's: a file, a link to a file outside, something that is no certificate.
        with open(os.path.join(self.dir, 'lab-ldaps-ca.crt'), 'w') as f:
            f.write(OTHER)
        self.outside = os.path.join(self.d, 'outside.txt')
        with open(self.outside, 'w') as f:
            f.write('not to be touched\n')
        os.symlink(self.outside, os.path.join(self.dir, 'linked.crt'))
        with open(os.path.join(self.dir, 'README'), 'w') as f:
            f.write('hello\n')
        self.before = self.snapshot()

    def tearDown(self):
        self.env.stop()
        shutil.rmtree(self.d, True)

    def snapshot(self):
        out = {}
        for n in ('lab-ldaps-ca.crt', 'README'):
            p = os.path.join(self.dir, n)
            st = os.lstat(p)
            out[n] = (text(p), st.st_mtime_ns, st.st_ino)
        out['linked.crt'] = os.readlink(os.path.join(self.dir, 'linked.crt'))
        out['outside'] = text(self.outside)
        return out

    def runs(self):
        try:
            return len(text(self.count).split())
        except OSError:
            return 0

    def ours(self):
        return sorted(n for n in os.listdir(self.dir) if n.startswith('acme-'))

    def test_sync_whole_set_idempotent(self):
        w = W.osroots_where()
        said, refused = W.osroots_sync(w, [ROOT_CA, INTER, LEAF])
        name_r, name_i = 'acme-%s.crt' % fp_of(ROOT_CA)[:16], 'acme-%s.crt' % fp_of(INTER)[:16]
        self.assertEqual(self.ours(), sorted([name_r, name_i]))
        self.assertEqual(refused[0]['cn'], 'ldap.example.local')
        self.assertIn("a server's own certificate does not go here", refused[0]['why'])
        self.assertEqual(said[-1], '%s run' % w['tool'][0])
        self.assertEqual(self.runs(), 1)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.dir, name_r)).st_mode), 0o644)
        # Again the same: nothing written, the tool not run.
        said, _r = W.osroots_sync(w, [ROOT_CA, INTER])
        self.assertEqual((said, self.runs()), ([], 1))
        # Asked to: the tool runs anyway.
        said, _r = W.osroots_sync(w, [ROOT_CA, INTER], force=True)
        self.assertEqual(self.runs(), 2)
        # One taken away: only its file.
        said, _r = W.osroots_sync(w, [ROOT_CA])
        self.assertEqual(said, ['removed ' + name_i, '%s run' % w['tool'][0]])
        self.assertEqual(self.ours(), [name_r])
        W.osroots_sync(w, [])
        self.assertEqual(self.ours(), [])
        self.assertEqual(self.snapshot(), self.before)       # the others' as they were

    def test_read_ours_others_and_bundle(self):
        w = W.osroots_where()
        W.osroots_sync(w, [ROOT_CA])
        got = W.osroots_read(w)
        self.assertEqual(len(got['ours']), 1)
        self.assertTrue(got['ours'][0]['in_bundle'])
        self.assertEqual(got['system']['count'], 3)          # base + the others' + ours
        self.assertEqual(got['system']['package'], 'ca-certificates-20260816')
        others = {o['file']: o for o in got['others']}
        self.assertEqual(others['lab-ldaps-ca.crt']['certs'][0]['cn'], 'Lab LDAPS CA')
        self.assertEqual(others['linked.crt']['link'], self.outside)
        self.assertEqual(others['README']['certs'], [])
        self.assertEqual((got['flavour'], got['dir']), ('debian', self.dir))
        # A file of ours changed by somebody: not in the bundle any more, put back at the next sync.
        p = os.path.join(self.dir, got['ours'][0]['file'])
        with open(p, 'w') as f:
            f.write(INTER)
        said, _r = W.osroots_sync(w, [ROOT_CA])
        self.assertEqual(text(p), W.osroots_blocks(ROOT_CA)[0][0])
        self.assertTrue(said[0].startswith('added '))

    def test_a_link_in_our_place_is_never_followed(self):
        w = W.osroots_where()
        name = os.path.join(self.dir, 'acme-%s.crt' % fp_of(ROOT_CA)[:16])
        os.symlink(self.outside, name)
        W.osroots_sync(w, [ROOT_CA])
        self.assertFalse(os.path.islink(name))
        self.assertEqual(text(self.outside), 'not to be touched\n')
        # Ours as a link and no longer wanted: the link goes, not what it leads to.
        os.unlink(name)
        os.symlink(self.outside, name)
        W.osroots_sync(w, [])
        self.assertFalse(os.path.lexists(name))
        self.assertTrue(os.path.exists(self.outside))
        self.assertIsNone(W._osroots_read(os.path.join(self.dir, 'linked.crt')))

    def test_folder_refused(self):
        w = W.osroots_where()
        os.chmod(self.dir, 0o777)
        with self.assertRaises(W.Refused) as e:
            W.osroots_sync(w, [ROOT_CA])
        self.assertIn("is not root's alone", str(e.exception))
        os.chmod(self.dir, 0o755)
        real = self.dir + '-real'
        os.rename(self.dir, real)
        os.symlink(real, self.dir)
        with self.assertRaises(W.Refused) as e:
            W.osroots_sync(w, [ROOT_CA])
        self.assertIn('not a folder (a link?)', str(e.exception))
        self.assertFalse([n for n in os.listdir(real) if n.startswith('acme-')])

    def test_folder_made_only_when_needed(self):
        shutil.rmtree(self.dir)
        w = W.osroots_where()
        self.assertEqual(W.osroots_sync(w, []), ([], []))
        self.assertFalse(os.path.exists(self.dir))
        W.osroots_sync(w, [ROOT_CA])
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o755)

    def test_tool_failing_and_missing(self):
        w = W.osroots_where()
        open(os.path.join(self.d, 'fail'), 'w').close()
        with self.assertRaises(W.Refused) as e:
            W.osroots_sync(w, [ROOT_CA])
        self.assertIn('ended with 3: it broke', str(e.exception))
        w['tool'] = ['no-such-tool-here']
        with self.assertRaises(W.Refused) as e:
            W.osroots_sync(w, [ROOT_CA], force=True)
        self.assertIn('no-such-tool-here is not on this machine', str(e.exception))

    def test_request_checked(self):
        w = W.osroots_where()
        for certs, words in (('x', 'a list of 50 at most'), ([ROOT_CA] * 51, 'a list of 50 at most'),
                             ([ROOT_CA + INTER], 'one certificate in each'), ([5], 'PEM text'),
                             ([KEY_TEXT], 'no private key')):
            with self.assertRaises(W.Refused) as e:
                W.osroots_sync(w, certs)
            self.assertIn(words, str(e.exception))
        self.assertEqual(self.ours(), [])
        with self.assertRaises(W.Refused):
            W.osroots_do({'do': 'rm -rf'})
        with mock.patch.dict(os.environ, {'ACME_OSROOTS_FLAVOUR': 'rhel'}):
            r = W.osroots_where()
            self.assertEqual((r['ext'], r['flavour']), ('.pem', 'rhel'))
            W.osroots_sync(r, [ROOT_CA])
            self.assertIn('acme-%s.pem' % fp_of(ROOT_CA)[:16], os.listdir(self.dir))

    def test_the_ask_answered(self):
        with open(os.path.join(TMP, 'web', 'osroots.ask'), 'w') as f:
            f.write(json.dumps({'id': 'abc123', 'do': 'sync', 'certs': [ROOT_CA]}))
        W.FD[0] = None
        W.osroots_part()
        got = json.loads(text(os.path.join(TMP, 'web', 'osroots.json')))
        self.assertTrue(got['ok'], got)
        self.assertEqual(got['id'], 'abc123')
        self.assertEqual(len(got['data']['ours']), 1)
        self.assertFalse(os.path.exists(os.path.join(TMP, 'web', 'osroots.ask')))
        # An ask that is a link: taken away, never read through.
        os.symlink(self.outside, os.path.join(TMP, 'web', 'osroots.ask'))
        W.osroots_part()
        self.assertFalse(os.path.lexists(os.path.join(TMP, 'web', 'osroots.ask')))
        self.assertEqual(text(self.outside), 'not to be touched\n')
        # Something not asked: said no.
        with open(os.path.join(TMP, 'web', 'osroots.ask'), 'w') as f:
            f.write(json.dumps({'id': 'x1', 'do': 'check', 'text': LEAF}))
        W.osroots_part()
        got = json.loads(text(os.path.join(TMP, 'web', 'osroots.json')))
        self.assertTrue(got['data']['certs'][0]['refused'])
        self.assertIn((W.osroots_part, "the system's trusted roots"), W._serve_parts())


class FakeH(object):
    def __init__(self, role, body=None):
        self.store, self.role, self._body = STORE, role, body or {}

    def me(self, role='readonly'):
        if E.ROLE_RANK.get(self.role, 0) < E.ROLE_RANK[role] or not E.ROLE_RANK.get(self.role):
            raise E.ApiError(403, 'no')
        return {'name': 'someone', 'role': self.role}

    def body(self):
        return self._body


class TestApiAndPages(unittest.TestCase):
    def read(self, *p):
        with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
            return f.read()

    def setUp(self):
        clear_set()

    def call(self, method, role, body=None):
        return E.ROUTES[(method, '/api/osroots')](FakeH(role, body))

    def test_who_may(self):
        for role in ('readonly', 'certadmin', 'fulladmin'):
            self.assertIn('certs', self.call('GET', role))
        with self.assertRaises(E.ApiError):
            self.call('GET', 'portal')
        for role in ('readonly', 'certadmin'):
            with self.assertRaises(E.ApiError) as e:
                self.call('POST', role, {'action': 'add', 'text': ROOT_CA})
            self.assertEqual(e.exception.status, 403)
        self.assertIsNone(E.osr_want(STORE))
        got = self.call('POST', 'fulladmin', {'action': 'check', 'text': ROOT_CA + LEAF})
        self.assertEqual([bool(c['refused']) for c in got['certs']], [False, True])
        self.assertNotIn('pem', got['certs'][0])
        self.assertIn('added 1', self.call('POST', 'fulladmin', {'action': 'add', 'text': ROOT_CA})['message'])
        v = self.call('GET', 'readonly')
        self.assertEqual((len(v['certs']), v['max'], v['cluster']), (1, 50, False))
        self.call('POST', 'fulladmin', {'action': 'refresh'})
        self.assertTrue(STORE.get_meta('oscerts:again:' + E.node_name()))
        self.call('POST', 'fulladmin', {'action': 'remove', 'fp': fp_of(ROOT_CA)})
        self.assertEqual(E.osr_want(STORE)['certs'], [])
        with self.assertRaises(E.ApiError) as e:
            self.call('POST', 'fulladmin', {'action': 'nuke'})
        self.assertEqual(e.exception.status, 400)

    def test_relay_card_unit_docs(self):
        php = self.read('web', 'admin', 'index.php')
        self.assertEqual(len(re.findall(r"'osroots' => '/api/osroots'", php)), 2)
        pane = php[php.index('id="pane-web"'):php.index('id="pane-fw"')]
        self.assertLess(pane.index('id="web-push-card"'), pane.index('id="osr-card"'))
        self.assertIn('<div class="card full" id="osr-card">', pane)
        js = self.read('web', 'assets', 'admin.js')
        for piece in ('function osrLoad(', 'function drawOsRoots(', 'function osrAdd(', 'function osrRemove(',
                      "api('osroots', {action: 'check', text: text})", 'osrLoad();', 'osrTick();',
                      "'pw-grid osr-grid'", 'netFacts(['):
            self.assertIn(piece, js)
        block = js[js.index('var OSR = {'):js.index('function osrRemove(')]
        self.assertFalse(re.search(r'(?<!as )\botp\b', block))
        self.assertIn('PathExists=/var/lib/acme/web/osroots.ask', self.read('deploy', 'acme-web.path'))
        self.assertIn('[docs/trusted-roots.md](docs/trusted-roots.md)', self.read('README.md'))
        doc = self.read('docs', 'trusted-roots.md')
        for piece in ('acme --os-roots', '--os-roots-add', '--os-roots-remove', 'update-ca-trust',
                      'update-ca-certificates', 'oscerts:want:'):
            self.assertIn(piece, doc)

    def test_every_text_has_its_czech(self):
        """The texts of the card, with their Czech, handed over beside the change."""
        scratch = os.environ.get('ACME_OSROOTS_CS')
        if not scratch or not os.path.exists(scratch):
            self.skipTest('ACME_OSROOTS_CS not given')
        cs = json.loads(text(scratch))
        rich = scratch.replace('.json', '-rich.json')
        if os.path.exists(rich):
            cs.update(json.loads(text(rich)))
        js = self.read('web', 'assets', 'admin.js')
        block = js[js.index('var OSR = {'):js.index('/* The VIP address lives on the High availability pane')]
        missing = []
        for m in re.finditer(r"(?:el\([^,]+, '[^']*', |cmdButton\(|iconButton\('[a-z]+', |words: |confirmThen\(|explain\(add, |toast\()'((?:[^'\\]|\\.)+)'", block):
            w = m.group(1).replace("\\'", "'").strip()
            if block[m.end():m.end() + 4].lstrip().startswith('+'):
                if any(k.startswith(w) and '{0}' in k for k in cs):
                    continue
            if w and not re.match(r'^[\W\d]*$', w) and w not in cs:
                missing.append(w)
        self.assertEqual(missing, [])


class TestCommandLine(unittest.TestCase):
    def setUp(self):
        clear_set()

    def test_options(self):
        p = E.build_parser()
        a = p.parse_args(['--os-roots-add', '/root/company-root.pem', '--yes'])
        self.assertEqual((a.os_roots_add, a.yes), ('/root/company-root.pem', True))
        self.assertTrue(p.parse_args(['--os-roots']).os_roots)
        self.assertEqual(p.parse_args(['--os-roots-remove', '6433b38639c3f329']).os_roots_remove, '6433b38639c3f329')

    def test_file_read_before_the_service_takes_over(self):
        d = tempfile.mkdtemp(prefix='root-only-')
        f = os.path.join(d, 'company-root.pem')
        with open(f, 'w') as x:
            x.write(ROOT_CA)
        args = SimpleNamespace(os_roots_add=f)
        with mock.patch.object(ENG, 'service_ids', return_value=(65534, 65534)), \
                mock.patch.object(os, 'geteuid', return_value=0):
            E.cli_stage_files(args)
        self.assertNotEqual(args.os_roots_add, f)
        self.assertTrue(args.os_roots_add.startswith(str(E.STATE_DIR)))
        self.assertEqual(text(args.os_roots_add), ROOT_CA)
        self.assertEqual(os.stat(args.os_roots_add).st_uid, 65534)

    def test_add_list_remove(self):
        f = os.path.join(CERTS, 'chain-for-cli.pem')
        with open(f, 'w') as x:
            x.write(INTER + ROOT_CA)
        pal = E.Palette(False)
        base = dict(os_roots=False, os_roots_add=None, os_roots_remove=None, json=False, yes=True)
        with mock.patch('sys.stdout', new_callable=__import__('io').StringIO) as out:
            self.assertEqual(E.cli_os_roots(SimpleNamespace(**dict(base, os_roots_add=f)), pal, STORE), 0)
            self.assertEqual(len(E.osr_want(STORE)['certs']), 2)
            E.cli_os_roots(SimpleNamespace(**dict(base, os_roots=True)), pal, STORE)
            E.cli_os_roots(SimpleNamespace(**dict(base, os_roots_remove=fp_of(INTER)[:16])), pal, STORE)
        text = out.getvalue()
        self.assertIn('Example Corp Root CA', text)
        self.assertIn('acme\'s additions (2 of 50 at most)', text)
        self.assertEqual(len(E.osr_want(STORE)['certs']), 1)
        with open(f, 'wb') as x:
            x.write(der_of(ROOT_CA))
        with self.assertRaises(SystemExit) as e, mock.patch('sys.stdout'):
            E.cli_os_roots(SimpleNamespace(**dict(base, os_roots_add=f)), pal, STORE)
        self.assertIn('nothing to add', str(e.exception))


if __name__ == '__main__':
    unittest.main()
