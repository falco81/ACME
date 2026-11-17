# -*- coding: utf-8 -*-
"""Hunt R, run 5, area vendors: regression tests."""
from __future__ import annotations

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, make  # noqa: E402


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


class AwsAcmRemoveDualTest(unittest.TestCase):
    """remove() of one half of a dual (RSA + EC) certificate deletes that half's ARN, not
    the one kept by the name alone (the half imported first)."""
    RSA = 'arn:aws:acm:eu-central-1:123456789012:certificate/rsa'
    EC = 'arn:aws:acm:eu-central-1:123456789012:certificate/ec'

    def setUp(self):
        self.deleted = []
        self.algo = {self.RSA: 'RSA_2048', self.EC: 'EC_prime256v1'}

        def acm(call):
            target = call['headers']['X-Amz-Target'].split('.')[1]
            body = json.loads(call['body'])
            if target == 'DeleteCertificate':
                self.deleted.append(body['CertificateArn'])
                return 200, {}
            if target == 'DescribeCertificate':
                return 200, {'Certificate': {'Serial': '01',
                                             'KeyAlgorithm': self.algo[body['CertificateArn']]}}
            return 400, {'__type': 'x#Nope'}
        self.ctx = FakeCtx([('POST', r'amazonaws\.com/$', acm)])
        self.t = make('aws_acm', {'access_key_id': 'AK', 'secret_access_key': 'SK',
                                  'region': 'eu-central-1'}, self.ctx)
        self.key = self.t.kv_arn(FakeBundle(), {})
        # as deploy keeps them: the RSA half first (also by the name alone), then the EC one
        self.ctx.kv[self.key] = self.RSA
        self.ctx.kv[self.key + ':RSA_2048'] = self.RSA
        self.ctx.kv[self.key + ':EC_prime256v1'] = self.EC

    def bundle(self, kt):
        b = FakeBundle()
        b.key_type = kt
        return b

    def test_ec_half_deletes_its_own_arn(self):
        self.t.remove(self.bundle('ec-256'), {})
        self.assertEqual(self.deleted, [self.EC])
        self.assertEqual(self.ctx.kv[self.key], self.RSA)       # the RSA half's stays
        self.assertFalse(self.ctx.kv[self.key + ':EC_prime256v1'])

    def test_rsa_half(self):
        self.t.remove(self.bundle('rsa-2048'), {})
        self.assertEqual(self.deleted, [self.RSA])
        self.assertFalse(self.ctx.kv[self.key])
        self.assertEqual(self.ctx.kv[self.key + ':EC_prime256v1'], self.EC)

    def test_kept_by_name_only_of_another_key_type_not_deleted(self):
        # kept before 1.0.88 by the name alone, and it is the RSA half's
        del self.ctx.kv[self.key + ':EC_prime256v1']
        del self.ctx.kv[self.key + ':RSA_2048']
        self.t.remove(self.bundle('ec-256'), {})
        self.assertEqual(self.deleted, [])
        self.t.remove(self.bundle('rsa-2048'), {})
        self.assertEqual(self.deleted, [self.RSA])

    def test_given_arn(self):
        self.t.remove(self.bundle('ec-256'), {'certificate_arn': self.RSA})
        self.assertEqual(self.deleted, [self.RSA])


if __name__ == '__main__':
    unittest.main()
