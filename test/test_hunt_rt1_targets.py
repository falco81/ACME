#!/usr/bin/env python3
"""Hunt R, run t1, area "targets": the bugs found and fixed, each kept fixed.

    python3 test/test_hunt_rt1_targets.py

- _common.Base.keep(): a "Previous versions to keep" left empty (the page sends null for an
  emptied number box) was read as 2, not as the field's own default - Plesk's -1 ("keep all")
  deleted the older certificates of the repository, MikroTik's 1 kept two.
- api_deploys: the preview and the test (dry run) of a deployment to a target that holds one
  certificate at a time were handed the RSA one of a dual certificate whatever the
  deployment's "Which certificate (when it is dual)" said - deploy_one() hands over the one
  it says (an ECDSA one tested as RSA, the test passed and the deployment then failed).
- Settings → Certificates, "Test the servers after each deployment": its help said a failed
  test makes the deployment a warning, not a failure - since 1.0.77 it fails the deployment
  on its target (checks.after_deploy, deployer.run_deploys, docs/targets.md).
"""
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


class KeepEmptyTest(unittest.TestCase):
    def test_empty_keep_is_the_fields_default(self):
        t = make('plesk', {'host': 'p', 'user': 'a', 'password': 'b'}, FakeCtx())
        self.assertEqual(t.keep({'keep': None}), -1)
        self.assertEqual(t.keep({'keep': ''}), -1)
        self.assertEqual(t.keep({}), -1)
        self.assertEqual(t.keep({'keep': 3}), 3)
        self.assertEqual(t.keep({'keep': '0'}), 0)
        m = make('mikrotik', {'host': 'r', 'user': 'a', 'password': 'b'}, FakeCtx())
        self.assertEqual(m.keep({'keep': None}), 1)
        self.assertEqual(m.keep({'keep': '2'}), 2)

    def test_plesk_with_keep_emptied_deletes_nothing(self):
        b = FakeBundle()
        from acmelib.plugins.targets._common import name_prefix
        old = name_prefix(b, {}) + '20200101-00000001'
        older = name_prefix(b, {}) + '20190101-00000002'
        oldest = name_prefix(b, {}) + '20180101-00000003'
        names = ''.join('<certificate><name>%s</name></certificate>' % n
                        for n in (old, older, oldest))
        pool = ('<packet><certificate><get-pool><result><status>ok</status><certificates>%s'
                '</certificates></result></get-pool></certificate></packet>' % names)
        ok = lambda cmd: ('<packet><certificate><%s><result><status>ok</status></result></%s>'  # noqa
                          '</certificate></packet>' % (cmd, cmd))

        def answer(call):
            body = call['body'].decode()
            if '<get-pool>' in body:
                return 200, pool
            if '<install>' in body:
                return 200, ok('install')
            if '<remove>' in body:
                return 200, ok('remove')
            raise AssertionError(body)
        ctx = FakeCtx([('POST', r'agent\.php', answer)])
        t = make('plesk', {'host': 'p', 'user': 'a', 'password': 'b'}, ctx)
        t.deploy(b, {'repository': 'admin', 'keep': None})
        removes = [c for c in ctx.calls if b'<remove>' in c['body']]
        self.assertEqual(removes, [], 'keep emptied is "keep all" (-1) on Plesk')


class DualVariantPreviewTest(unittest.TestCase):
    def test_bundle_follows_the_deployments_variant(self):
        from acmelib.certs import api_deploys as AD
        from acmelib.certs import store as S
        from acmelib.plugins.base import PluginError

        class Twin(object):
            def __init__(self, family, alt=None):
                self.family, self.alt, self.key_type = family, alt, family + '-x'

            def variants(self):
                return [self] + ([self.alt] if self.alt is not None else [])

            def variant(self, v):
                for b in self.variants():
                    if b.family == v or (v == 'alt' and b is self.alt) or \
                            (v == 'main' and b is self):
                        return b
                raise ValueError('no %s' % v)
        rsa = Twin('rsa')
        whole = Twin('ec', rsa)
        old = S.bundle_of
        S.bundle_of = lambda cert: whole
        try:
            class One(object):
                dual = False

            class Both(object):
                dual = True
            cert = {'cert_pem': 'x'}
            self.assertIs(AD._bundle(cert, {}, One), rsa)                 # auto: the RSA one
            self.assertIs(AD._bundle(cert, {}, One, opts={'variant': 'ec'}), whole)
            self.assertIs(AD._bundle(cert, {}, One, opts={'variant': 'main'}), whole)
            self.assertIs(AD._bundle(cert, {}, One, opts={'variant': 'alt'}), rsa)
            self.assertIs(AD._bundle(cert, {}, Both, opts={'variant': 'rsa'}), whole)
            # a variant the certificate has not: the preview shows the default one, the test
            # fails as the deployment would
            self.assertIs(AD._bundle(cert, {}, One, opts={'variant': 'ed'}), rsa)
            with self.assertRaises(PluginError):
                AD._bundle(cert, {}, One, opts={'variant': 'ed'}, strict=True)
        finally:
            S.bundle_of = old

    def test_preview_and_dry_run_pass_the_options(self):
        with open(os.path.join(os.path.dirname(HERE), 'acmelib', 'certs',
                               'api_deploys.py'), encoding='utf-8') as fh:
            src = fh.read()
        self.assertIn('_bundle(cert, b, cls, h.store, opts)', src)
        self.assertIn('_bundle(cert, b, cls, opts=opts, strict=True)', src)


class AfterDeployHelpTest(unittest.TestCase):
    def test_the_help_says_a_failed_test_fails_it(self):
        with open(os.path.join(os.path.dirname(HERE), 'acmelib', 'engine',
                               '900_certificates.py'), encoding='utf-8') as fh:
            src = fh.read()
        self.assertNotIn('makes the deployment a warning, not a failure', src)
        self.assertIn('A failed test fails the deployment on its target', src)


if __name__ == '__main__':
    unittest.main()
