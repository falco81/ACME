#!/usr/bin/env python3
"""Hunt v4 (1.0.142), area "regress": a review of what changed since 1.0.139.

    python3 test/test_hunt_rv4_regress.py

- The deploy guard (1.0.140, A1): known_cas() read and parsed the chains of up to 5000
  certificates (every one of them loaded first) for each call - and a deployment to an agent
  whose policy says `allow issuer` calls it twice, What happens once more, the page's guard of a
  target once for each of its up to 200 deployments: minutes on a big installation. A CA's text
  is read once now, and only the newest 5000 certificates are asked of the database.
- Where keys are made (1.0.140, B7): a switch waiting for the renewal (agentkeys:switch:<id>) is
  a certificate's row in meta - it went with neither the certificate's deletion (a certificate
  given the same number later was switched by its sweep) nor its export, import or trash.
"""
import os
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-hunt-rv4-regress-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
_ENV_BEFORE = {k: os.environ.get(k) for k in ('ACME_CONFIG', 'ACME_STATE', 'ACME_RUN',
                                               'ACME_LOGDIR')}
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402,F401
from acmelib.certs import agent_deployguard as DG  # noqa: E402
from acmelib.certs import agent_keyplace as K  # noqa: E402
from acmelib.certs import pki  # noqa: E402
from acmelib.certs import store as S  # noqa: E402
for _k, _v in _ENV_BEFORE.items():
    if _v is None:
        os.environ.pop(_k, None)
    else:
        os.environ[_k] = _v

STORE = acme.Storage(acme.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def _ca_pem(cn):
    import subprocess
    d = tempfile.mkdtemp(dir=TMP)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                    'ec_paramgen_curve:P-256', '-nodes', '-keyout', os.path.join(d, 'k'),
                    '-out', os.path.join(d, 'c'), '-days', '30', '-subj', '/CN=' + cn,
                    '-addext', 'basicConstraints=critical,CA:TRUE'], check=True,
                   capture_output=True)
    with open(os.path.join(d, 'c')) as fh:
        return fh.read()


class KnownCasOnce(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = _ca_pem('Rv4 Root') + _ca_pem('Rv4 Other')
        for i in range(60):
            STORE.db.insert('certs', {'name': 'rv4-cas-%d' % i, 'names': '["rv4-%d.test"]' % i,
                                      'issuer': 'rv4src', 'chain_pem': cls.chain})

    def test_each_ca_read_once(self):
        getattr(DG, '_INFO', {}).clear()
        real = pki.cert_info
        calls = []

        def counted(pem):
            calls.append(1)
            return real(pem)
        with mock.patch.object(pki, 'cert_info', counted):
            first = DG.known_cas(STORE)
            n1 = len(calls)
            again = DG.known_cas(STORE)
            DG.known_cas(STORE)
        titles = {c['title'] for c in first}
        self.assertIn('Rv4 Root', titles)
        self.assertIn('Rv4 Other', titles)
        self.assertEqual([c['fp'] for c in first], [c['fp'] for c in again])
        mine = [c for c in again if c['title'] == 'Rv4 Root'][0]
        self.assertGreaterEqual(mine['certs'], 60)
        # two CAs in 60 chains: read twice (once each), not 120 times - and not again after
        self.assertLessEqual(n1, 4)
        self.assertEqual(len(calls), n1)

    def test_newest_asked_only(self):
        seen = []
        real = STORE.db.rows

        def rows(sql, args=()):
            seen.append(sql)
            return real(sql, args)
        with mock.patch.object(STORE.db, 'rows', rows):
            DG.known_cas(STORE)
        q = [x for x in seen if 'chain_pem FROM certs' in x]
        self.assertTrue(q)
        self.assertIn('LIMIT %d' % DG.CERTS_SCAN, q[0])


class KeySwitchGoesWithTheCert(unittest.TestCase):
    def _cert(self, name):
        return STORE.db.insert('certs', {'name': name, 'names': '["%s.test"]' % name})

    def test_out_in_drop(self):
        cid = self._cert('rv4-switch')
        STORE.set_meta(K.M_SWITCH % cid, '{"at": 1, "by": "admin", "target": "web1"}')
        self.assertTrue(K.pending(STORE, cid))
        got = S.cert_meta_out(STORE, cid)
        self.assertIn('keyswitch', got)
        # imported under another number: the switch is that certificate's
        other = self._cert('rv4-switch-imported')
        S.cert_meta_in(STORE, other, got)
        self.assertEqual((K.pending(STORE, other) or {}).get('target'), 'web1')
        # the certificate deleted: its switch goes with it
        S.cert_meta_drop(STORE, cid)
        self.assertIsNone(K.pending(STORE, cid))

    def test_delete_takes_it(self):
        cid = self._cert('rv4-switch-del')
        STORE.set_meta(K.M_SWITCH % cid, '{"at": 1, "by": "admin", "target": "web1"}')
        A.cert_drop(STORE, S.cert_get(STORE, cid), 'test')
        self.assertIsNone(STORE.get_meta(K.M_SWITCH % cid))

    def test_same_key_as_the_sweep(self):
        self.assertEqual(S.CERT_META['keyswitch'], K.M_SWITCH)


if __name__ == '__main__':
    unittest.main(verbosity=2)
