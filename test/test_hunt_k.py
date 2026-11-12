#!/usr/bin/env python3
"""Hunt K (1.0.95): the guard against writes to the database covers the uploaded modules, a
configuration put in signs only what it wrote, the second step and a directory's authorities
are signed where written; a slot is given up only for a choice that stands; a person's choice
of when a test runs (and a test taken off) stays; a test acme made that cannot reach the server
does not fail the deployment; the setup guides of a configuration file are checked.

    python3 test/test_hunt_k.py
"""
import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
TMP = tempfile.mkdtemp(prefix='acme-huntk-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api_push as P, checks as C, custom_modules as CM, guides as G  # noqa: E402
from acmelib.certs import store as S  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def tearDownModule():
    E.CONFIG['db_guard'] = 0
    shutil.rmtree(TMP, ignore_errors=True)


class Guard(unittest.TestCase):
    def setUp(self):
        E.CONFIG['db_guard'] = 1

    def tearDown(self):
        E.CONFIG['db_guard'] = 0

    def test_1_a_module_written_past_acme_is_not_run(self):
        E.dbguard_adopt(STORE)
        code = b'from acmelib.plugins.base import Target\nclass Evil(Target):\n    kind = "evilk"\n'
        STORE.db.upsert('meta', 'k', {'k': 'module-file:targets/evilk.py', 'v': json.dumps(
            {'text': base64.b64encode(code).decode(), 'sha256': hashlib.sha256(code).hexdigest(),
             'bytes': len(code), 'family': 'target'})})
        self.assertTrue(E.dbguard_meta_kept('module-file:targets/evilk.py'))
        self.assertTrue(E.dbguard_meta_kept('module-files:sig'))
        self.assertEqual(CM.uploaded(STORE), {})
        # one put in on the page is signed, and read
        STORE.set_meta('module-file:targets/fine.py', json.dumps({'sha256': 'x', 'family': 'target'}))
        self.assertIn('targets/fine.py', CM.uploaded(STORE))
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'module-file:%'")

    def test_2_second_step_kept_signed(self):
        STORE.set_meta(E.mfa_key('alice'), json.dumps({'kind': 'app', 'secret': 'x', 'step': 0}))
        self.assertTrue(E.mfa_update(STORE, 'alice', {'kind': 'app', 'secret': 'x', 'step': 7}))
        self.assertEqual((E.mfa_get(STORE, 'alice') or {}).get('step'), 7)

    def test_3_directory_authorities_signed(self):
        STORE.directory_save({'name': 'corpk', 'hosts': 'dc1.example.com', 'base': 'dc=example,dc=com',
                              'bind_dn': 'cn=x', 'bind_pw': 'pw', 'tls': 'ldaps'}, 'alice')
        one = STORE.directory('corpk')
        STORE.directory_set_ca(one['id'], '', 'clear')
        self.assertTrue(E.dbguard_directory_ok(STORE.db, 'corpk'))

    def test_4_import_signs_only_what_it_wrote(self):
        STORE.db.upsert('meta', 'k', {'k': 'fw:conf', 'v': json.dumps({'forged': True})})
        self.assertIsNone(STORE.get_meta('fw:conf'))
        E.config_import(STORE, E.Daemon(STORE, serve=False), {'guides': {
            'guide:target:f5@:en': json.dumps({'md': '# x'})}}, 'tester')
        E.CONFIG['db_guard'] = 1            # read again from config.json by the import
        self.assertIsNone(STORE.get_meta('fw:conf'))
        STORE.db.run("DELETE FROM meta WHERE k = 'fw:conf'")


class Guides(unittest.TestCase):
    def test_5_configuration_file_rows_checked(self):
        good = json.dumps({'md': '# ok', 'at': 1, 'by': 'x'})
        self.assertIsNotNone(G.check_key('guide:target:f5@:en', good))
        for k, v in (('guide:nope:f5@:en', good), ('guide:target:f5@:de', good),
                     ('guide:target:f5@:en', 'not json'), ('guide:target:f5@:en', '{"md": ""}'),
                     ('guide:target:f5@:en', json.dumps({'md': 'x' * (G.MAX_MD + 1)}))):
            self.assertIsNone(G.check_key(k, v), k + v[:20])
        # a file replacing all takes away the ones it does not have
        STORE.set_meta('guide:target:f5@:cs', good)
        E.config_import(STORE, E.Daemon(STORE, serve=False),
                        {'guides': {'guide:target:f5@:en': good}}, 'tester', replace=True)
        self.assertIsNone(STORE.get_meta('guide:target:f5@:cs'))
        self.assertTrue(STORE.get_meta('guide:target:f5@:en'))


def _cert(name, names):
    return STORE.db.insert('certs', {'name': name, 'names': json.dumps(names), 'state': 'ok',
                                     'enabled': 1})


class Slots(unittest.TestCase):
    def test_6_slot_kept_when_the_choice_is_refused(self):
        STORE.db.insert('cert_targets', {'name': 'appk', 'kind': 'acme_push', 'config': '{}',
                                         'enabled': 1})
        a = _cert('Ak', ['web.example.test'])
        b = _cert('Bk', ['other.example.test'])
        d = STORE.db.insert('cert_deploys', {'cert_id': a, 'target': 'appk', 'enabled': 1,
                                             'options': json.dumps({'slots': 'web\napi'}),
                                             'state': 'ok'})
        slot = {'id': 'web', 'names': ['web.example.test'], 'installable': True}

        def disc(store, body):
            row = S.plugin_row(store, 'target', 'appk')
            s = dict(slot, covered_by=P.covered_by(store, row, slot),
                     fits=P.fits(P.certs_pool(store), slot))
            return {'target': 'appk', 'slots': [s]}
        was = P.discover
        P.discover = disc
        try:
            got = P.adopt_each(STORE, {'name': 'appk', 'each': {'web': {'how': 'existing',
                                                                        'cert_id': b}}}, 'tester')
        finally:
            P.discover = was
        self.assertEqual(len(got['left']), 1)
        opts = json.loads(STORE.db.row('SELECT options FROM cert_deploys WHERE id = ?', (d,))['options'])
        self.assertEqual(opts['slots'], 'web\napi')


class ServedTests(unittest.TestCase):
    def test_7_choices_stay(self):
        STORE.db.insert('cert_targets', {'name': 'tk', 'kind': 'local', 'config': '{}', 'enabled': 1})
        cid = _cert('Ck', ['tk.example.test'])
        STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'tk', 'enabled': 1,
                                         'options': '{}', 'state': 'ok'})
        name = C.for_target(STORE, cid, 'tk', 'tester', 'tls', 'tk.example.test', 443)
        chk = STORE.db.row('SELECT * FROM cert_checks WHERE cert_id = ? AND test = ?', (cid, name))
        C.after(STORE, chk['id'], C.AFTER_NONE, 'person')
        C.for_target(STORE, cid, 'tk', 'tester', 'tls', 'tk.example.test', 443)
        self.assertEqual(STORE.db.row('SELECT after_target FROM cert_checks WHERE id = ?',
                                      (chk['id'],))['after_target'], C.AFTER_NONE)
        # taken off by a person: not attached again
        self.assertTrue(C.auto_made(STORE, name))
        C.detach(STORE, chk['id'])
        # by acme itself (a save of the deployment): left off
        C.for_target(STORE, cid, 'tk', 'tester', 'tls', 'tk.example.test', 443, auto=True)
        self.assertIsNone(STORE.db.row('SELECT id FROM cert_checks WHERE cert_id = ? AND test = ?',
                                       (cid, name)))
        # asked for by a person (verify=...): attached again (1.0.96)
        C.for_target(STORE, cid, 'tk', 'tester', 'tls', 'tk.example.test', 443)
        self.assertIsNotNone(STORE.db.row('SELECT id FROM cert_checks WHERE cert_id = ? AND test = ?',
                                          (cid, name)))
        # a '-' left by the deployment going away is tied again when it comes back (1.0.96)
        chk2 = STORE.db.row('SELECT * FROM cert_checks WHERE cert_id = ? AND test = ?', (cid, name))
        STORE.db.update('cert_checks', chk2['id'], {'after_target': C.AFTER_NONE})
        C.for_target(STORE, cid, 'tk', 'tester', 'tls', 'tk.example.test', 443, auto=True)
        self.assertEqual(STORE.db.row('SELECT after_target FROM cert_checks WHERE id = ?',
                                      (chk2['id'],))['after_target'], 'tk')

    def test_8_unreachable_made_test_does_not_fail(self):
        STORE.db.insert('cert_targets', {'name': 'uk', 'kind': 'local', 'config': '{}', 'enabled': 1})
        cid = _cert('Uk', ['uk.example.test'])
        STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'uk', 'enabled': 1,
                                         'options': '{}', 'state': 'ok'})
        C.for_target(STORE, cid, 'uk', 'tester', 'tls', 'uk.example.test', 443)
        was_probe, was_tries = C.probe, C.AFTER_DEPLOY_TRIES
        C.probe = lambda store, chk: {'state': 'unreachable', 'ok': False, 'said': 'no route',
                                      'detail': {}}
        C.AFTER_DEPLOY_TRIES = (0,)

        class Job:
            stop = None

            def check(self):
                pass

            def step(self, *a, **k):
                pass
        failed = {}
        try:
            C.after_deploy(STORE, Job(), cid, {'uk'}, failed)
        finally:
            C.probe, C.AFTER_DEPLOY_TRIES = was_probe, was_tries
        self.assertEqual(failed, {})


if __name__ == '__main__':
    unittest.main(verbosity=2)
