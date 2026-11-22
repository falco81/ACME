#!/usr/bin/env python3
"""Hunt 1.0.140 round v1, area "ui": the global search, the expiry calendar's subscription,
profiles from a template - the bugs found and fixed (test/test_f140_ui.py's store and helpers).

    python3 test/test_hunt_rv1_ui.py
"""
import json
import os
import re
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_f140_ui as F  # noqa: E402

from acmelib import engine as E  # noqa: E402
from acmelib.certs import expirycal as EC  # noqa: E402
from acmelib.certs import reqprofiles_more as RM  # noqa: E402
from acmelib.certs import reqprofiles_templates as RT  # noqa: E402

STORE = F.STORE
call, status, cert = F.call, F.status, F.cert


def names(q, **kw):
    got = call('GET', '/api/search', args={'q': q}, **kw)['groups']
    return {k: [r['name'] for r in v] for k, v in got.items()}


class Search(unittest.TestCase):
    def setUp(self):
        F.setup()

    def test_exact_name_not_crowded_out(self):
        """A certificate called exactly what was typed was missing when more than 24 others
        holding the words sorted before it by name (the SQL LIMIT came before the ranking)."""
        for i in range(40):
            cert('a-web-%02d' % i, 30, owner='Web')
        cert('web', 30, owner='Web')
        got = names('web')['cert']
        self.assertEqual(got[0], 'web')
        self.assertEqual(len(got), 8)

    def test_scoped_targets_not_crowded_out(self):
        """A member kept to their team found none of their own targets when other teams' targets
        holding the words came first (the team filter ran after the SQL LIMIT)."""
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        for i in range(60):
            STORE.db.insert('cert_targets', {'name': 'srv-%02d' % i, 'kind': 'fake', 'enabled': 1,
                                             'config': '{}', 'owner': 'Approvers'})
        STORE.db.insert('cert_targets', {'name': 'srv-mine', 'kind': 'fake', 'enabled': 1,
                                         'config': '{}', 'owner': 'Web'})
        STORE.db.insert('cert_targets', {'name': 'srv-shared', 'kind': 'fake', 'enabled': 1,
                                         'config': '{}'})
        got = names('srv', who='mgr', role='certadmin').get('target', [])
        self.assertIn('srv-mine', got)
        self.assertIn('srv-shared', got)
        self.assertFalse([n for n in got if re.match(r'srv-\d', n)])
        # a full administrator: every one, as before
        self.assertEqual(len(names('srv')['target']), 8)

    def test_odd_queries(self):
        cert('per%cent_x', 30, owner='Web')
        cert('perXcentYx', 30, owner='Web')
        self.assertEqual(names('per%cent_')['cert'], ['per%cent_x'])
        for q in ("' OR 1=1 --", '!!', '\\', '"; DROP TABLE certs; --', 'ž' * 100):
            self.assertEqual(status('GET', '/api/search', args={'q': q}), 200, q)
        self.assertTrue(STORE.db.rows('SELECT id FROM certs'))


def _h(tok, cls=F.H):
    h = cls(who='-')
    h.headers = {'X-Acme-Calfeed': tok}
    return h


class Feed(unittest.TestCase):
    def setUp(self):
        F.setup()
        F.cert('alpha', 5, owner='Web')

    def tearDown(self):
        for n in ('calperson', 'dirperson'):
            if STORE.account(n):
                STORE.drop_account(n)

    def test_a_new_account_of_the_same_name_gets_nothing(self):
        """The link of a deleted account came back to life when an account of the same name
        was made again (somebody else) - with that one's rights."""
        STORE.add_account('calperson', 'certadmin', 'Local-Only-Pw-77!x')
        tok = call('POST', '/api/calendar/feed_link', {'action': 'new'}, who='calperson',
                   role='certadmin')['token']
        self.assertIsNotNone(EC.feed_session(STORE, tok)[0])
        STORE.drop_account('calperson')
        self.assertIsNone(EC.feed_session(STORE, tok)[0])
        time.sleep(0.01)
        STORE.add_account('calperson', 'fulladmin', 'Local-Only-Pw-77!x')
        self.assertIsNone(EC.feed_session(STORE, tok)[0])
        with self.assertRaises(E.ApiError) as e:
            E.ROUTES[('GET', '/api/calendar/feed')](_h(tok))
        self.assertEqual(e.exception.status, 404)
        # a link the new account makes itself works
        tok2 = call('POST', '/api/calendar/feed_link', {'action': 'new'}, who='calperson',
                    role='fulladmin')['token']
        self.assertIn('alpha', E.ROUTES[('GET', '/api/calendar/feed')](_h(tok2))['text'])

    def test_a_link_from_before_still_works(self):
        """A link kept without the account's mark (made by an earlier build): as before."""
        STORE.add_account('calperson', 'certadmin', 'Local-Only-Pw-77!x')
        tok = EC.feed_new(STORE, 'calperson')
        h = EC._hash(tok)
        got = json.loads(STORE.get_meta(EC.META_FEED + h))
        STORE.set_meta(EC.META_FEED + h, json.dumps({'who': got['who'], 'made': got['made'],
                                                     'lang': 'en'}))
        self.assertIsNotNone(EC.feed_session(STORE, tok)[0])

    def test_directory_account_asked_again(self):
        """A directory account taken out of the directory (or of every group that gives it a
        role) kept its feed: the account row stays until it signs in again. The feed asks the
        directory as a sign-in does (directory_recheck)."""
        STORE.add_account('dirperson', 'certadmin', None, source='directory',
                          dn='CN=dirperson,DC=x')
        tok = EC.feed_new(STORE, 'dirperson')
        asked = []

        class Gone(F.H):
            def directory_recheck(self, acc):
                asked.append(acc['name'])
                raise E.ApiError(401, 'that account may no longer sign in')

        class Demoted(F.H):
            def directory_recheck(self, acc):
                return dict(acc, role='portal')

        class Same(F.H):
            def directory_recheck(self, acc):
                return acc
        EC.FEED_CACHE['at'].clear()
        for cls in (Gone, Demoted):
            with self.assertRaises(E.ApiError) as e:
                E.ROUTES[('GET', '/api/calendar/feed')](_h(tok, cls))
            self.assertEqual(e.exception.status, 404)
        self.assertEqual(asked, ['dirperson'])
        self.assertIn('BEGIN:VCALENDAR', E.ROUTES[('GET', '/api/calendar/feed')](
            _h(tok, Same))['text'])
        # the same name given to somebody else in the directory (another DN): nothing
        STORE.set_account('dirperson', dn='CN=dirperson,OU=other,DC=x')
        self.assertIsNone(EC.feed_session(STORE, tok)[0])


class Templates(unittest.TestCase):
    def setUp(self):
        F.setup()

    def tearDown(self):
        STORE.set_meta(RM.META_RULES, '{}')

    def test_fallback_key_keeps_the_shortest_rsa(self):
        """None of the template's key types signed by the source: the one taken instead was
        the source's first - an RSA 2048 key under a company rule of RSA 3072 at least, while
        the source also signs EC P-256."""
        real = RT._issuers(STORE)
        own = [dict(i) for i in real if i['name'] == 'own'][0]
        own['key_types'] = ['rsa-2048', 'ec-256']
        RM.save_rules(STORE, {'min_rsa': 3072}, 'x')
        old = RT._issuers
        RT._issuers = lambda store: [own]
        try:
            got = RT.build(STORE, 'vpn', issuer='own', suffixes=['example.test'])
        finally:
            RT._issuers = old
        self.assertEqual(got['body']['key_types'], ['ec-256'])
        self.assertEqual(got['body']['key_default'], 'ec-256')
        self.assertNotIn('min_rsa', [f['rule'] for f in got['findings'] if f['level'] == 'bad'])


class Deploy(unittest.TestCase):
    def test_calendar_token_not_in_the_error_log(self):
        """nginx writes a request it limits (429) to the error log with its whole line - the
        secret of the link with it."""
        conf = F.read('deploy/nginx-acme.conf')
        block = conf[conf.index('location = /calendar.ics'):]
        block = block[:block.index('}')]
        self.assertIn('limit_req_log_level info;', block)
        inst = F.read('install.sh')
        block = inst[inst.index("location = /calendar.ics {"):]
        block = block[:block.index('}')]
        self.assertIn('limit_req_log_level info;', block)


if __name__ == '__main__':
    unittest.main(verbosity=2)
