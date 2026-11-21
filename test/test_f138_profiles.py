#!/usr/bin/env python3
"""Request profiles 1.0.138 (docs/request-profiles.md): versions, a base profile, the
compliance check, a dry run and a profile that ends.

    python3 test/test_f138_profiles.py

In one process, as test/test_req_profiles.py (its daemon-less store and helpers):
- P1 every saved change a version (who, when, what changed), none for a save that changes
  nothing, the first change of a profile older than versions writes it as it was as version 1,
  the diff of any two, a restore as a new version, a certificate stamped with the version it
  was asked for from, the versions carried in the configuration's export;
- P2 a base: what is inherited follows the base, what is overridden stays, no circle, a change
  of the base that would break a profile based on it refused, deleting a base refused or
  (detach) its profiles made to stand alone;
- P3 the CA/B Forum's schedule (dates and days), a public source against it, a private one
  not, the company's rules, a SHA-1 / short key certificate, the report "on date X";
- P4 the dry run: subject, names, EKU, key, validity, approval, owner - nothing written;
- P5 a profile that ends: not offered on the portal, the impact preview, its certificate moved
  to the successor at its renewal, undone;
- the rights: a certificate administrator (not full) is refused every change, a read-only
  account reads; old data (a profile with no versions and no base) works as before.
"""
import datetime
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_req_profiles as TRP  # noqa: E402  (its store, FakeH, setup, helpers)

from acmelib import engine as E  # noqa: E402
from acmelib.certs import reqprofiles as R, reqprofiles_more as RM, store as S  # noqa: E402

STORE = TRP.STORE
call, status, portal, portal_status = TRP.call, TRP.status, TRP.portal, TRP.portal_status
EVA = TRP.EVA


def setup():
    TRP.setup()
    STORE.db.run('DELETE FROM cert_req_profile_versions')
    STORE.set_meta(RM.META_RULES, '{}')


def prof(**more):
    return TRP.base_profile(**more)


class Versions(unittest.TestCase):
    def setUp(self):
        setup()

    def test_versions_diff_restore(self):
        call('POST', '/api/reqprofiles/save', prof())
        v = call('GET', '/api/reqprofiles/versions', args={'name': 'Web servers'}, role='readonly')
        self.assertEqual([x['version'] for x in v['versions']], [1])
        self.assertEqual(v['versions'][0]['why'], 'added')
        self.assertEqual(v['versions'][0]['by'], 'boss')
        # a save that changes nothing: no version
        call('POST', '/api/reqprofiles/save', dict(prof(), old_name='Web servers'))
        self.assertEqual(RM.current(STORE, 'Web servers'), 1)
        call('POST', '/api/reqprofiles/save', dict(prof(days=60, suffixes=['example.test',
                                                                          'more.test']),
                                                   old_name='Web servers'))
        v = call('GET', '/api/reqprofiles/versions', args={'name': 'Web servers'})
        self.assertEqual(v['current'], 2)
        self.assertEqual(sorted(v['versions'][0]['changes']), ['days', 'suffixes'])
        d = call('GET', '/api/reqprofiles/diff', args={'name': 'Web servers', 'a': '1', 'b': '2'})
        ch = {c['key']: c for c in d['changes']}
        self.assertEqual((ch['days']['a'], ch['days']['b']), (90, 60))
        self.assertEqual(ch['suffixes']['added'], ['more.test'])
        self.assertTrue([r for r in d['rows'] if r['key'] == 'issuer'][0]['same'])
        # restored: version 3, as version 1 said
        self.assertEqual(status(call, 'POST', '/api/reqprofiles/restore',
                                {'name': 'Web servers', 'version': 1}, role='certadmin'), 403)
        call('POST', '/api/reqprofiles/restore', {'name': 'Web servers', 'version': 1})
        self.assertEqual(R.config_of(R.profile_get(STORE, 'Web servers'))['days'], 90)
        v = call('GET', '/api/reqprofiles/versions', args={'name': 'Web servers'})
        self.assertEqual((v['current'], v['versions'][0]['why']), (3, 'restored from version 1'))
        self.assertEqual(status(call, 'POST', '/api/reqprofiles/restore',
                                {'name': 'Web servers', 'version': 9}), 404)
        # renamed: the versions follow
        call('POST', '/api/reqprofiles/save', dict(prof(name='Web'), old_name='Web servers'))
        self.assertEqual(RM.current(STORE, 'Web'), 4)
        # deleted: they go
        call('POST', '/api/reqprofiles/delete', {'name': 'Web'})
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_req_profile_versions'), 0)

    def test_old_profile_first_change(self):
        """A profile of before 1.0.138 (no versions): version 1 shown as it is, not written;
        its first change writes it as it was (1), then the change (2)."""
        R.save_profile(STORE, prof(), 'x')
        STORE.db.run('DELETE FROM cert_req_profile_versions')
        v = RM.versions(STORE, 'Web servers')
        self.assertEqual([x['version'] for x in v['versions']], [1])
        self.assertTrue(v['versions'][0]['unsaved'])
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_req_profile_versions'), 0)
        R.save_profile(STORE, dict(prof(max_names=2), old_name='Web servers'), 'y')
        v = RM.versions(STORE, 'Web servers')
        self.assertEqual([(x['version'], x['changes']) for x in v['versions']],
                         [(2, ['max_names']), (1, [])])
        self.assertEqual(v['versions'][1]['why'], 'as it was before versions were kept')

    def test_cert_stamped_with_version(self):
        R.save_profile(STORE, prof(), 'x')
        R.save_profile(STORE, dict(prof(days=80), old_name='Web servers'), 'x')
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'names': ['v.example.test'], 'team': 'Web'})
        TRP.wait_cert(got['id'])
        one = [c for c in portal(EVA, 'GET', '/api/portal/certs')['rows'] if c['id'] == got['id']][0]
        self.assertEqual((one['req_profile'], one['req_profile_version']), ('Web servers', 2))
        v = RM.versions(STORE, 'Web servers')
        self.assertEqual(v['versions'][0]['certs'], 1)

    def test_carried(self):
        self.assertIn('cert_req_profile_versions', E.carry_tables())
        R.save_profile(STORE, prof(), 'x')
        out = E.carry_export(STORE, False)
        self.assertEqual(len(out['cert_req_profile_versions']), 1)
        # put in again: matched by its uid, not doubled
        said = __import__('collections').Counter()
        E.carry_import(STORE, {'cert_req_profile_versions': out['cert_req_profile_versions']},
                       'x', False, said)
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_req_profile_versions'), 1)


class Inheritance(unittest.TestCase):
    def setUp(self):
        setup()
        R.save_profile(STORE, prof(name='Company web'), 'x')

    def child(self, **more):
        b = {'name': 'Shop', 'base': 'Company web', 'suffixes': ['shop.test'], 'teams': [],
             'inherit': [g for g, _k in R.INHERIT_GROUPS if g not in ('suffixes', 'teams')]}
        b.update(more)
        return call('POST', '/api/reqprofiles/save', b)['profile']

    def test_inherits_and_follows(self):
        got = self.child()
        self.assertEqual((got['base'], got['suffixes'], got['issuer'], got['days'], got['teams']),
                         ('Company web', ['shop.test'], 'own', 90, []))
        self.assertEqual(got['subject']['O'], {'mode': 'fixed', 'value': 'Example s.r.o.'})
        own = R.own_of(R.raw_rows(STORE)[[r['name'] for r in R.raw_rows(STORE)].index('Shop')])
        self.assertNotIn('days', own)               # kept: only what it overrides
        # the base changed: the child follows, what it overrides stays
        R.save_profile(STORE, dict(prof(name='Company web', days=45, suffixes=['corp.test']),
                                   old_name='Company web'), 'x')
        c = R.config_of(R.profile_get(STORE, 'Shop'))
        self.assertEqual((c['days'], c['suffixes']), (45, ['shop.test']))
        listed = {p['name']: p for p in call('GET', '/api/reqprofiles')['profiles']}
        self.assertEqual(listed['Company web']['children'], ['Shop'])
        # the portal asks with the child as it works
        R.save_profile(STORE, dict(prof(name='Company web', teams=[], owner='person'),
                                   old_name='Company web'), 'x')
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Shop', 'names': ['a.shop.test']})
        self.assertEqual(json.loads(S.cert_get(STORE, got['id'])['profile'])['days'], 90)
        self.assertEqual(portal_status(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Shop', 'names': ['a.example.test']}), 403)
        # renamed base: the child follows
        R.save_profile(STORE, dict(prof(name='Corp web', teams=[], owner='person'),
                                   old_name='Company web'), 'x')
        self.assertEqual(R.profile_get(STORE, 'Shop') and
                         R.own_of(R.profile_get(STORE, 'Shop'))['base'], 'Corp web')

    def test_no_circle_and_breaking_base(self):
        self.child()
        with self.assertRaises(ValueError) as e:
            R.save_profile(STORE, dict(prof(name='Company web', base='Shop', inherit=['days']),
                                       old_name='Company web'), 'x')
        self.assertIn('circle', str(e.exception))
        with self.assertRaises(ValueError):
            self.child(base='Shop', name='Shop', old_name='Shop')
        # the child overrides: the person sends a CSR (no key made here); the base moves to a
        # self-signed source, which signs no CSR - refused, naming the child
        self.child(old_name='Shop', make_key=False, csr=True,
                   inherit=[g for g, _k in R.INHERIT_GROUPS
                            if g not in ('suffixes', 'teams', 'make_key', 'csr', 'pfx')])
        with self.assertRaises(ValueError) as e:
            R.save_profile(STORE, dict(prof(name='Company web', issuer='self', csr=False,
                                            subject={}, days=None, key_types=['ec-256'],
                                            key_default='ec-256'),
                                       old_name='Company web'), 'x')
        self.assertIn('the profile Shop is based on it and would not fit', str(e.exception))
        self.assertEqual(R.config_of(R.profile_get(STORE, 'Company web'))['issuer'], 'own')

    def test_delete_base(self):
        self.child()
        self.assertEqual(status(call, 'POST', '/api/reqprofiles/delete', {'name': 'Company web'}),
                         409)
        call('POST', '/api/reqprofiles/delete', {'name': 'Company web', 'detach': True})
        c = R.profile_get(STORE, 'Shop')
        cfg = R.config_of(c)
        self.assertEqual((cfg.get('base'), cfg['days'], cfg['issuer']), (None, 90, 'own'))
        self.assertEqual(R.problems(STORE, cfg, c), [])
        self.assertEqual(RM.versions(STORE, 'Shop')['versions'][0]['why'],
                         'its base Company web was deleted: it stands alone')

    def test_base_gone_by_hand(self):
        """A base gone some other way (an import): said, and not offered."""
        self.child()
        STORE.db.run("DELETE FROM cert_req_profiles WHERE name = 'Company web'")
        r = R.profile_get(STORE, 'Shop')
        self.assertIn('its base profile Company web is gone', R.problems(STORE, R.config_of(r), r))
        self.assertNotIn('Shop', [p['name'] for p in portal(EVA, 'GET', '/api/portal/certs')
                                  ['profiles']])


class Compliance(unittest.TestCase):
    def setUp(self):
        setup()

    def test_schedule(self):
        d = datetime.date
        self.assertEqual(RM.limit_on(d(2026, 3, 14)), 398)
        self.assertEqual(RM.limit_on(d(2026, 3, 15)), 200)
        self.assertEqual(RM.limit_on(d(2027, 3, 15)), 100)
        self.assertEqual(RM.limit_on(d(2029, 3, 14)), 100)
        self.assertEqual(RM.limit_on(d(2029, 3, 15)), 47)

    def test_public_and_private(self):
        today = d0 = datetime.date(2026, 11, 21)
        cfg = {'days': 150, 'renew_days': 60, 'key_types': ['ec-256', 'rsa-2048']}
        fs = RM.lint_settings(STORE, cfg, today, True)
        days = [f for f in fs if f['rule'] == 'cabf_days'][0]
        self.assertEqual((days['level'], days['from']), ('bad', '2027-03-15'))
        rd = [f for f in fs if f['rule'] == 'renew_days'][0]
        self.assertEqual(rd['from'], '2029-03-15')
        self.assertEqual(RM._status(fs, d0, d0), 'ok')
        self.assertEqual(RM._status(fs, d0, datetime.date(2027, 4, 1)), 'ends')
        self.assertEqual(RM.lint_settings(STORE, dict(cfg, days=300), today, True)[0]['from'], '')
        # a private CA: no CA/B Forum rule
        self.assertEqual([f for f in RM.lint_settings(STORE, cfg, today, False)], [])

    def test_rules_and_report(self):
        R.save_profile(STORE, prof(wildcards=True, approval=False), 'x')
        self.assertEqual(status(call, 'POST', '/api/reqprofiles/rules', {'max_days': 60},
                                role='certadmin'), 403)
        call('POST', '/api/reqprofiles/rules', {'max_days': 60, 'min_rsa': 3072,
                                                'wildcards_approval': True, 'no_pfx': True})
        rep = call('GET', '/api/reqprofiles/compliance', args={'at': '2030-01-01'}, role='readonly')
        p = rep['profiles'][0]
        self.assertFalse(p['public'])
        self.assertEqual(p['status'], 'bad')
        self.assertEqual(sorted({f['rule'] for f in p['findings']}),
                         ['rule_max_days', 'rule_min_rsa', 'rule_pfx', 'rule_wildcards'])
        self.assertEqual(rep['at'], '2030-01-01')
        self.assertEqual(rep['limit_at'], 47)
        self.assertEqual(status(call, 'GET', '/api/reqprofiles/compliance', args={'at': 'nope'}),
                         400)
        # rules off: it complies
        call('POST', '/api/reqprofiles/rules', {})
        rep = call('GET', '/api/reqprofiles/compliance')
        self.assertEqual(rep['profiles'][0]['status'], 'ok')

    def test_certificate_lint(self):
        from acmelib.certs import pki
        R.save_profile(STORE, prof(), 'x')
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'names': ['c.example.test'], 'team': 'Web'})
        row = TRP.wait_cert(got['id'])
        rl = RM.rules(STORE)
        self.assertEqual(RM.lint_cert(STORE, row, {}, False, datetime.date.today(), rl), [])
        # as if it were public and valid 300 days: refused now
        info = pki.cert_info(row['cert_pem'])
        fake = dict(row)
        orig = pki.cert_info
        try:
            pki.cert_info = lambda _p: dict(info, not_after=info['not_before'] + 300 * 86400,
                                            sig_alg='sha1WithRSAEncryption', key_type='rsa-1024',
                                            key_bits=1024)
            fs = RM.lint_cert(STORE, fake, {'days': 300}, True, datetime.date.today(), rl)
        finally:
            pki.cert_info = orig
        rules_ = {f['rule'] for f in fs}
        self.assertTrue({'sha1', 'key', 'cabf_days', 'cabf_renew'} <= rules_, rules_)


class DryRun(unittest.TestCase):
    def setUp(self):
        setup()
        R.save_profile(STORE, prof(), 'x')

    def test_dryrun(self):
        n = STORE.db.value('SELECT COUNT(*) FROM certs')
        ev = STORE.db.value('SELECT COUNT(*) FROM events')
        got = call('POST', '/api/reqprofiles/dryrun', {
            'profile': 'Web servers', 'names': ['d.example.test', 'e.example.test'],
            'team': 'Web', 'subject': {'OU': 'Ops'}, 'key_type': 'rsa-2048'}, role='readonly')
        self.assertTrue(got['fits'], got['refused'])
        self.assertEqual(got['subject'], [['CN', 'd.example.test'], ['O', 'Example s.r.o.'],
                                          ['OU', 'Ops'], ['C', 'CZ']])
        self.assertEqual((got['sans'], got['eku'], got['key']['type'], got['validity']['days'],
                          got['owner']['name'], got['approval']['waits'], got['version']),
                         (['d.example.test', 'e.example.test'], ['serverAuth'], 'rsa-2048', 90,
                          'Web', False, 1))
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM certs'), n)
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM events'), ev)
        bad = call('POST', '/api/reqprofiles/dryrun', {
            'profile': 'Web servers', 'names': ['x.other.test'], 'team': 'Approvers'})
        self.assertFalse(bad['fits'])
        self.assertTrue(any('not under the domains' in w for w in bad['refused']))
        self.assertTrue(any('Approvers may not ask' in w for w in bad['refused']))
        R.save_profile(STORE, dict(prof(approval=True), old_name='Web servers'), 'x')
        w = call('POST', '/api/reqprofiles/dryrun', {'profile': 'Web servers',
                                                     'names': ['d.example.test'], 'team': 'Web'})
        self.assertTrue(w['approval']['waits'])
        self.assertIn('Web', w['approval']['approver'])
        self.assertEqual(status(call, 'POST', '/api/reqprofiles/dryrun', {'profile': 'Nope'}), 404)


class Ending(unittest.TestCase):
    def setUp(self):
        setup()
        R.save_profile(STORE, prof(), 'x')
        R.save_profile(STORE, prof(name='Web 2026', days=45, renew_days=15, tags=[],
                                   suffixes=['example.test'], key_types=['ec-256'],
                                   key_default='ec-256'), 'x')

    def test_ends_moves_and_undo(self):
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'names': ['m.example.test'], 'team': 'Web',
            'key_type': 'rsa-2048'})
        TRP.wait_cert(got['id'])
        self.assertEqual(status(call, 'POST', '/api/reqprofiles/ends',
                                {'name': 'Web servers', 'successor': 'Web 2026'},
                                role='certadmin'), 403)
        for bad in ({'successor': 'Web servers'}, {'successor': 'Nope'}, {}):
            self.assertEqual(status(call, 'POST', '/api/reqprofiles/ends',
                                    dict({'name': 'Web servers'}, **bad)), 400, bad)
        call('POST', '/api/reqprofiles/ends', {'name': 'Web servers', 'successor': 'Web 2026',
                                               'note': 'shorter validity'})
        seen = {p['name'] for p in portal(EVA, 'GET', '/api/portal/certs')['profiles']}
        self.assertEqual(seen, {'Web 2026'})
        self.assertEqual(portal_status(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'names': ['n.example.test'], 'team': 'Web'}), 404)
        # the successor cannot be deleted, nor end itself onto it
        self.assertEqual(status(call, 'POST', '/api/reqprofiles/delete', {'name': 'Web 2026'}),
                         400)
        self.assertEqual(status(call, 'POST', '/api/reqprofiles/ends',
                                {'name': 'Web 2026', 'successor': 'Web servers'}), 400)
        # an account that sees only its teams' certificates does not see them
        E.CONFIG['certs_certadmin_all'] = 0
        try:
            self.assertEqual(status(call, 'GET', '/api/reqprofiles/impact',
                                    args={'name': 'Web servers'}, role='certadmin'), 403)
            rep = call('GET', '/api/reqprofiles/compliance', role='certadmin')
            self.assertEqual((rep['certs'], rep['certs_hidden']), ([], True))
        finally:
            E.CONFIG['certs_certadmin_all'] = 1
        imp = call('GET', '/api/reqprofiles/impact', args={'name': 'Web servers'}, role='readonly')
        self.assertEqual((imp['successor'], imp['moves'], imp['stays']), ('Web 2026', 1, 0))
        fields = {c['field'] for c in imp['certs'][0]['changes']}
        self.assertTrue({'key_type', 'days', 'renew_days'} <= fields, fields)
        self.assertEqual(RM.versions(STORE, 'Web servers')['versions'][0]['why'],
                         'ends: its successor is Web 2026')
        # renewed: it moves
        row = S.cert_get(STORE, got['id'])
        moved = RM.migrate_on_renew(STORE, None, row)
        self.assertIsNotNone(moved)
        self.assertEqual((moved['key_type'], json.loads(moved['profile'])['days'],
                          moved['renew_days']), ('ec-256', 45, 15))
        from acmelib.certs import portal as P
        a = P.asker(STORE, got['id'])
        self.assertEqual((a['profile'], a['moved_from']['profile']), ('Web 2026', 'Web servers'))
        self.assertIsNone(RM.migrate_on_renew(STORE, None, S.cert_get(STORE, got['id'])))
        # undone: offered again
        call('POST', '/api/reqprofiles/ends', {'name': 'Web servers', 'undo': True})
        seen = {p['name'] for p in portal(EVA, 'GET', '/api/portal/certs')['profiles']}
        self.assertEqual(seen, {'Web 2026', 'Web servers'})

    def test_renewal_job_moves_it(self):
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'names': ['r.example.test'], 'team': 'Web',
            'key_type': 'ec-256'})
        TRP.wait_cert(got['id'])
        RM.set_ends(STORE, 'Web servers', 'Web 2026', '', 'x')
        from acmelib.certs import api as A
        A.start_renew(STORE, got['id'], True, 'test')
        row = TRP.wait_cert(got['id'], 2)
        from acmelib.certs import pki
        info = pki.cert_info(row['cert_pem'])
        self.assertLessEqual(round((info['not_after'] - info['not_before']) / 86400), 46)

    def test_cannot_move(self):
        R.save_profile(STORE, dict(prof(name='Web 2026', suffixes=['other.test'], days=45),
                                   old_name='Web 2026'), 'x')
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'names': ['s.example.test'], 'team': 'Web'})
        TRP.wait_cert(got['id'])
        RM.set_ends(STORE, 'Web servers', 'Web 2026', '', 'x')
        imp = RM.impact(STORE, 'Web servers')
        self.assertEqual((imp['moves'], imp['stays']), (0, 1))
        self.assertIn('names the successor does not give', imp['certs'][0]['why'])
        self.assertIsNone(RM.migrate_on_renew(STORE, None, S.cert_get(STORE, got['id'])))


class OldData(unittest.TestCase):
    def test_profile_saved_before(self):
        """A row as 1.0.137 wrote it (config without base, inherit, ends): listed, offered,
        asked from, as before."""
        setup()
        cfg = R.build_cfg(STORE, prof(teams=[], owner='person'))
        STORE.db.insert('cert_req_profiles', {'name': 'Legacy', 'description': '', 'enabled': 1,
                                              'config': json.dumps(cfg), 'created': 1.0,
                                              'created_by': 'old', 'updated': 1.0,
                                              'updated_by': 'old'})
        p = call('GET', '/api/reqprofiles')['profiles'][0]
        self.assertEqual((p['base'], p['inherit'], p['children'], p['ends'], p['version'],
                          p['problems']), ('', [], [], None, 1, []))
        got = portal(EVA, 'POST', '/api/portal/cert_request', {'profile': 'Legacy',
                                                               'names': ['l.example.test']})
        self.assertTrue(got['id'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
