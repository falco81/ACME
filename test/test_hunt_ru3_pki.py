#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hunt u3, area pki (acme's own authorities): what was found and fixed.

  - an intermediate revoked by the authority above it (in that authority's CRL) went on
    signing: every certificate it signed was refused by a client checking the CRLs
  - a root renewed for fewer days than the intermediates under it: what they signed was
    given dates past the end of the root (a chain no client takes then)

    python3 test/test_hunt_ru3_pki.py
"""
import os
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_pki as T                                        # noqa: E402  (MemStore, keys)
from acmelib.certs import ca as CA                          # noqa: E402
from acmelib.certs import pki                               # noqa: E402
from acmelib.certs.pki import PkiError                      # noqa: E402


def verify(tmp, leaf, chain, crls=None, at=None):
    """openssl verify of the leaf through `chain` (its last one the root), CRLs checked."""
    tmp.w('leaf.pem', leaf)
    args = ['openssl', 'verify', '-CAfile', tmp.w('root.pem', chain[-1])]
    if chain[:-1]:
        args += ['-untrusted', tmp.w('mid.pem', ''.join(chain[:-1]))]
    if crls:
        args += ['-crl_check_all', '-CRLfile', tmp.w('crls.pem', ''.join(crls))]
    if at:
        args += ['-attime', str(int(at))]
    r = subprocess.run(args + [os.path.join(tmp.d, 'leaf.pem')], capture_output=True, text=True)
    return r.returncode == 0, r.stdout + r.stderr


class OwnCa(T.Tmp, unittest.TestCase):
    def setUp(self):
        T.Tmp.setUp(self)
        self.store = T.MemStore()
        self.root = CA.ca_create(self.store, 'Root', 'U3 Root', key_type='ec-256', days=3650,
                                 path_len=2)
        self.sub = CA.ca_create(self.store, 'Sub', 'U3 Sub', key_type='ec-256', days=1825,
                                parent_id=self.root, path_len=1)

    def csr(self, name='a.example'):
        return pki.make_csr(T.key(), [name])[0]

    def test_revoked_intermediate_signs_nothing(self):
        leaf, chain = CA.ca_sign(self.store, self.sub, self.csr(), 30)
        sub = CA.ca_get(self.store, self.sub)
        under = CA.ca_create(self.store, 'Under', 'U3 Under', key_type='ec-256',
                             parent_id=self.sub)
        root_crl = CA.ca_revoke(self.store, self.root, pki.cert_info(sub['cert_pem'])['serial'],
                                'keyCompromise')
        # openssl: what it signed is refused once the root's CRL says so
        ok, words = verify(self, leaf, chain, [root_crl, CA.ca_crl(self.store, self.sub)])
        self.assertFalse(ok)
        self.assertIn('revoked', words)
        # ... so it signs nothing more, nor does the authority under it, nor a new one under it
        for ca_id in (self.sub, under):
            with self.assertRaises(PkiError) as e:
                CA.ca_sign(self.store, ca_id, self.csr('b.example'), 30)
            self.assertIn('revoked', str(e.exception))
        with self.assertRaises(PkiError):
            CA.ca_create(self.store, 'Under2', 'U3 Under 2', parent_id=self.sub)
        # its CRL is still made (what it signed before is checked against it)
        self.assertTrue(CA.ca_crl(self.store, self.sub))
        # renewed by the root (a new certificate, not revoked): it signs again
        CA.ca_renew(self.store, self.sub)
        leaf2, chain2 = CA.ca_sign(self.store, self.sub, self.csr('c.example'), 30)
        ok, words = verify(self, leaf2, chain2, [CA.ca_crl(self.store, self.root),
                                                 CA.ca_crl(self.store, self.sub)])
        self.assertTrue(ok, words)
        # a hold is released: it signs again too
        other = CA.ca_create(self.store, 'Held', 'U3 Held', key_type='ec-256', parent_id=self.root)
        serial = pki.cert_info(CA.ca_get(self.store, other)['cert_pem'])['serial']
        CA.ca_revoke(self.store, self.root, serial, 'certificateHold')
        with self.assertRaises(PkiError):
            CA.ca_sign(self.store, other, self.csr(), 30)
        CA.ca_unrevoke(self.store, self.root, serial)
        self.assertTrue(CA.ca_sign(self.store, other, self.csr(), 30)[0])

    def test_dates_not_past_the_root(self):
        CA.ca_renew(self.store, self.root, days=20)            # shorter than Sub (5 years)
        root_end = CA.ca_get(self.store, self.root)['not_after']
        self.assertGreater(CA.ca_get(self.store, self.sub)['not_after'], root_end)
        leaf, chain = CA.ca_sign(self.store, self.sub, self.csr(), 90)
        end = pki.cert_info(leaf)['not_after']
        self.assertLessEqual(end, root_end)
        ok, words = verify(self, leaf, chain, at=end - 60)     # the whole chain valid to its end
        self.assertTrue(ok, words)
        # an intermediate made under Sub ends with the root too
        under = CA.ca_create(self.store, 'Under', 'U3 Under', parent_id=self.sub, days=900)
        self.assertLessEqual(CA.ca_get(self.store, under)['not_after'], root_end)
        # what is not cut stays as asked
        leaf, _ = CA.ca_sign(self.store, self.sub, self.csr(), 5)
        self.assertAlmostEqual(pki.cert_info(leaf)['not_after'], time.time() + 5 * 86400,
                               delta=120)

    def test_crl_days_on_create(self):
        """crl_days on create: 1 to 365, as an edit allows."""
        from acmelib.certs.pki import PkiError
        for bad in (0, 366, 'x'):
            with self.assertRaises(PkiError):
                CA.ca_create(self.store, 'Bad%s' % bad, 'U3 Bad', key_type='ec-256',
                             crl_days=bad)
        cid = CA.ca_create(self.store, 'Fine', 'U3 Fine', key_type='ec-256', crl_days=30)
        self.assertEqual(self.store.db.value('SELECT crl_days FROM cert_cas WHERE id = ?',
                                             (cid,)), 30)

    def test_root_above_ran_out(self):
        self.store.db.run('UPDATE cert_cas SET not_after = ? WHERE id = ?',
                          (int(time.time()) - 10, self.root))
        with self.assertRaises(PkiError) as e:
            CA.ca_sign(self.store, self.sub, self.csr(), 30)
        self.assertIn('ran out', str(e.exception))


if __name__ == '__main__':
    unittest.main()
