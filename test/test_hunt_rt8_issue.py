#!/usr/bin/env python3
"""Hunt t8 (issuance): two jobs proving one shared CA authorization put the same TXT
record into acme's own DNS server; the first to finish must not take away the other's.

    python3 test/test_hunt_rt8_issue.py
"""
import os
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix='acme-hunt-t8-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "testnode", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)


class _Job(object):
    def __init__(self, ident):
        self.id = ident

    def step(self, *a, **k):
        pass

    def cancelled(self):
        return False


class TestSharedTxt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import acme as E
        from acmelib.certs import runtime
        cls.R = runtime
        cls.store = E.Storage(E.open_db())

    def rows(self, name):
        return self.store.db.rows('SELECT owner, value FROM dns_records WHERE name = ?', (name,))

    def test_one_job_leaves_the_others_record(self):
        name = '_acme-challenge.shared.example'
        a = self.R.RunContext(self.store, _Job(101), scope='challenge:own')
        b = self.R.RunContext(self.store, _Job(102), scope='challenge:own')
        a.dns_put(name, 'TXT', 'same-key-authz-digest')
        b.dns_put(name, 'TXT', 'same-key-authz-digest')
        a.dns_drop(name, 'TXT', 'same-key-authz-digest')      # job A done
        left = self.rows(name)
        self.assertEqual([r['owner'] for r in left], ['job:102'])
        b.tidy()
        self.assertEqual(self.rows(name), [])

    def test_a_record_of_no_job_of_ours_still_dropped(self):
        # a leftover put by another context (an earlier run) - taken away as before
        name = '_acme-challenge.left.example'
        self.R.RunContext(self.store, _Job(201), scope='challenge:own').dns_put(name, 'TXT', 'v')
        self.R.RunContext(self.store, _Job(202), scope='challenge:own').dns_drop(name, 'TXT', 'v')
        self.assertEqual(self.rows(name), [])

    def test_no_value_drops_all(self):
        name = '_acme-challenge.all.example'
        a = self.R.RunContext(self.store, _Job(301), scope='challenge:own')
        a.dns_put(name, 'TXT', 'x')
        a.dns_put(name, 'TXT', 'y')
        a.dns_drop(name, 'TXT')
        self.assertEqual(self.rows(name), [])

    def test_a_shared_http_token_stays_for_the_other_job(self):
        from acmelib.certs.runtime import CHAL_PREFIX
        tok = 'sharedtoken12345'
        a = self.R.RunContext(self.store, _Job(401), scope='challenge:web')
        b = self.R.RunContext(self.store, _Job(402), scope='challenge:web')
        a.http_token_put(tok, tok + '.thumb')
        b.http_token_put(tok, tok + '.thumb')
        a.tidy()
        self.assertIsNotNone(self.store.get_meta(CHAL_PREFIX + tok))
        b.tidy()
        self.assertIsNone(self.store.get_meta(CHAL_PREFIX + tok))

    def test_a_token_dropped_by_another_context_still_goes(self):
        from acmelib.certs.runtime import CHAL_PREFIX
        tok = 'lefttoken1234567'
        self.R.RunContext(self.store, _Job(501), scope='challenge:web').http_token_put(tok, 'x')
        self.R.RunContext(self.store, _Job(502), scope='challenge:web').http_token_drop(tok)
        self.assertIsNone(self.store.get_meta(CHAL_PREFIX + tok))


def _pem_chain():
    """leaf <- Int <- 'Root X' cross-signed by 'Old Root' (the long, default chain) and
    leaf <- Int (whose issuer is Root X: the short, alternate chain)."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def nm(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def make(subject, key, issuer, ikey, ca=True):
        now = datetime.datetime.now(datetime.timezone.utc)
        b = (x509.CertificateBuilder().subject_name(nm(subject)).issuer_name(nm(issuer))
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=30))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        return b.sign(ikey, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

    old, rx, it, lf = (ec.generate_private_key(ec.SECP256R1()) for _ in range(4))
    cross = make('Root X', rx, 'Old Root', old)
    inter = make('Int CA', it, 'Root X', rx)
    leaf = make('www.example.com', lf, 'Int CA', it, ca=False)
    return leaf + inter + cross, leaf + inter


class TestPreferredChain(unittest.TestCase):
    def pick(self, preferred):
        from acmelib.plugins.issuers import _acme_client as ac
        long_, short = _pem_chain()

        class Fake(object):
            said = []

            def post(self, url, payload, accept=None):
                if url.endswith('/alt'):
                    return 200, {}, short.encode()
                return 200, {'link': '<https://ca.example/cert/1/alt>;rel="alternate"'}, \
                    long_.encode()

            def say(self, w, level='info'):
                self.said.append(w)

        text, where = ac.AcmeClient.download_chain(Fake(), 'https://ca.example/cert/1', preferred)
        return text, where, long_, short

    def test_the_chain_ending_at_the_root_named_wins(self):
        # the default chain carries Root X too (cross-signed by Old Root): it was taken
        text, where, _l, short = self.pick('Root X')
        self.assertEqual(text, short)
        self.assertTrue(where.endswith('/alt'))

    def test_the_cross_signing_root_still_picks_the_long_chain(self):
        text, where, long_, _s = self.pick('Old Root')
        self.assertEqual((text, where), (long_, 'https://ca.example/cert/1'))

    def test_an_intermediate_named_still_matches(self):
        text, _w, long_, _s = self.pick('Int CA')
        self.assertEqual(text, long_)             # the first chain carrying it, as before


if __name__ == '__main__':
    unittest.main()
