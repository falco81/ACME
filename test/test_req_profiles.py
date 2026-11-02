#!/usr/bin/env python3
"""Request profiles (Settings → Request profiles, docs/request-profiles.md).

    python3 test/test_req_profiles.py      (or python3 -m unittest test.test_req_profiles)

In one process, as test/test_teams.py: the catalog (every value checked against
its own catalog, what does not fit refused), who may use a profile (its teams,
their right request), a certificate asked for from one (names outside its domains
refused, its fixed subject put in, issued at once or waiting for approval, its
owner and tags), a CSR decoded and checked item by item, a certificate issued for
a CSR by an authority of acme's own - no key kept, renewed with the same CSR,
no PFX and no key out - a new CSR sent for it, and the portal's old free form
working as before.
"""
import base64
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-reqprof-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402  (the routes)
from acmelib.certs import teams as T, jobs, renewer, pki, ca as CA  # noqa: E402
from acmelib.certs import reqprofiles as R, portal as P, store as S  # noqa: E402

STORE = acme.Storage(acme.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
BASE = 'DC=corpnet,DC=loc'
WEB_DN = 'CN=WEB_ADMINS,OU=Groups,' + BASE


class FakeH(object):
    """A request of the administration pages (or, `portal`, of the portal) - test_teams.py's."""
    def __init__(self, who='boss', role='fulladmin', body=None, args=None, portal=None):
        self.store, self._body, self.args = STORE, dict(body or {}), dict(args or {})
        self.who, self.role, self.portal = who, role, portal
        self.headers = {}

    def me(self, _role='readonly'):
        return {'name': self.who, 'role': self.role,
                'account': {'name': self.who, 'role': self.role, 'source': 'local',
                            'dn': '', 'group_list': ''}}

    def session(self, kind):
        return self.portal if kind == 'portal' else self.me()

    def body(self):
        return self._body

    def arg(self, name, default=''):
        return self.args.get(name, default)


def clean():
    for t in ('certs', 'cert_teams', 'cert_tags', 'cert_versions', 'cert_jobs', 'cert_deploys',
              'cert_req_profiles'):
        STORE.db.run('DELETE FROM %s' % t)
    E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1, certs_notify_mail='',
                    portal=1, portal_cert=1, portal_local=1)
    for n in ('marta', 'mgr'):
        if not STORE.account(n):
            STORE.add_account(n, 'readonly', 'Local-Only-Pw-77!x')
    if not STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'self'"):
        STORE.db.insert('cert_issuers', {'name': 'self', 'kind': 'selfsigned', 'config': '{}',
                                         'enabled': 1})


def call(method, path, body=None, **who):
    return E.ROUTES[(method, path)](FakeH(body=body, **who))


def status(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return 200
    except E.ApiError as e:
        return e.status
    except (LookupError,):
        return 404
    except ValueError:
        return 400


def person(name, local=False, groups=(), mail=''):
    data = {'kind': 'local' if local else 'directory', 'mail': mail, 'about': {'upn': mail},
            'cert_groups': [list(g) for g in groups], 'cert_groups_at': time.time(),
            'dn': 'CN=%s,%s' % (name, BASE),
            'dir_checked': time.time()}     # just signed in: the directory not asked again yet
    return {'name': name, 'data': data, 'kind': 'portal'}


def portal(s, method, path, body=None):
    return E.ROUTES[(method, path)](FakeH(portal=s, body=body))


def portal_status(s, method, path, body=None):
    return status(E.ROUTES[(method, path)], FakeH(portal=s, body=body))


def wait_cert(cid, version=1, secs=90):
    end = time.time() + secs
    while time.time() < end:
        row = S.cert_get(STORE, cid)
        if int(row.get('version') or 0) >= version and not jobs.cert_busy(STORE, cid):
            return row
        if row.get('state') == 'failed' and not jobs.cert_busy(STORE, cid):
            raise AssertionError('it failed: %s' % row.get('last_error'))
        time.sleep(0.2)
    raise AssertionError('not issued in time: %s' % S.cert_get(STORE, cid).get('state'))


OWN = {}


def setup():
    clean()
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'certs:portal:%'")
    E.CONFIG.update(portal_cert_suffixes='', portal_cert_issuers='', portal_cert_auto=0,
                    portal_cert_keys=0, portal_cert_max=50, mail_mode='off')
    if not OWN:
        OWN['ca'] = int(CA.ca_create(STORE, 'Profiles CA', {'CN': 'Profiles CA'},
                                     key_type='ec-256'))
    if not STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'own'"):
        STORE.db.insert('cert_issuers', {'name': 'own', 'kind': 'internal_ca',
                                         'config': json.dumps({'ca': OWN['ca']}),
                                         'enabled': 1})
    T.save_team(STORE, {'name': 'Web', 'members': ['group:WEB_ADMINS=request',
                                                   'local:marta=view',
                                                   'local:mgr=manage']}, 'x')
    T.save_team(STORE, {'name': 'Approvers', 'members': ['local:boss2=approve']}, 'x')
    T.save_tag(STORE, {'name': 'web', 'colour': 'info'}, 'x')


def base_profile(**more):
    b = {'name': 'Web servers', 'description': 'TLS for the web servers', 'issuer': 'own',
         'suffixes': ['example.test'], 'wildcards': False, 'max_names': 3, 'make_key': True,
         'csr': True, 'key_types': ['ec-256', 'rsa-2048'], 'key_default': 'ec-256',
         'subject': {'O': {'mode': 'fixed', 'value': 'Example s.r.o.'},
                     'OU': {'mode': 'person', 'value': 'IT'},
                     'C': {'mode': 'fixed', 'value': 'CZ'}},
         'auto_renew': True, 'renew_days': 20, 'days': 90, 'eku': ['serverAuth'],
         'approval': False, 'owner': 'team', 'tags': ['web'], 'teams': ['Web'], 'pfx': True}
    b.update(more)
    return b


EVA = person('eva', groups=[(WEB_DN, 'WEB_ADMINS')], mail='eva@corp.test')


class Catalog(unittest.TestCase):
    def setUp(self):
        setup()

    def test_crud_and_checks(self):
        got = call('POST', '/api/reqprofiles/save', base_profile())['profile']
        self.assertEqual((got['issuer'], got['challenge'], got['suffixes'], got['days']),
                         ('own', '', ['example.test'], 90))
        self.assertEqual(got['subject']['O'], {'mode': 'fixed', 'value': 'Example s.r.o.'})
        self.assertEqual(got['subject']['L'], {'mode': 'off', 'value': ''})
        listed = call('GET', '/api/reqprofiles', role='readonly')
        self.assertEqual([p['name'] for p in listed['profiles']], ['Web servers'])
        self.assertIn('own', [i['name'] for i in listed['options']['issuers']])
        self.assertFalse(listed['can_change'])
        # only a full administrator changes them
        self.assertEqual(status(call, 'POST', '/api/reqprofiles/save', base_profile(name='X'),
                                role='certadmin'), 403)
        # what does not fit is refused, in words
        for bad, words in (({'csr': True, 'issuer': 'self'}, 'signs only a key acme makes'),
                           ({'make_key': False, 'csr': False}, 'either acme makes the key'),
                           ({'teams': ['Nobody']}, 'no owner or team Nobody'),
                           ({'tags': ['nope']}, 'no tag nope'),
                           ({'owner': 'fixed', 'owner_team': ''}, 'choose the team'),
                           ({'suffixes': []}, 'under which domains'),
                           ({'key_types': []}, 'at least one key type'),
                           ({'subject': {'C': {'mode': 'fixed', 'value': 'Czech'}}}, 'two letters'),
                           ({'issuer': 'nothing'}, 'choose the source')):
            with self.assertRaises((ValueError, E.ApiError)) as e:
                R.save_profile(STORE, base_profile(name='Bad', **bad), 'x')
            self.assertIn(words, str(e.exception), bad)
        # renamed: an owner and a tag renamed - the profile follows
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Webteam'}, 'x')
        T.save_tag(STORE, {'old_name': 'web', 'name': 'www'}, 'x')
        p = R.config_of(R.profile_get(STORE, 'Web servers'))
        self.assertEqual((p['teams'], p['tags']), (['Webteam'], ['www']))
        got = call('POST', '/api/reqprofiles/save', dict(base_profile(teams=['Webteam'],
                                                                      tags=[]),
                                                         old_name='Web servers', name='Web'))
        self.assertEqual(got['profile']['name'], 'Web')
        call('POST', '/api/reqprofiles/delete', {'name': 'Web'})
        self.assertEqual(R.rows(STORE), [])


class Portal(unittest.TestCase):
    def setUp(self):
        setup()
        R.save_profile(STORE, base_profile(), 'x')
        R.save_profile(STORE, base_profile(name='Anybody', teams=[], owner='person',
                                           approval=True, csr=False, auto_renew=False,
                                           tags=[]), 'x')
        R.save_profile(STORE, base_profile(name='Off', teams=[], owner='person'), 'x')
        STORE.db.run("UPDATE cert_req_profiles SET enabled = 0 WHERE name = 'Off'")

    def test_who_may_use(self):
        seen = {p['name'] for p in portal(EVA, 'GET', '/api/portal/certs')['profiles']}
        self.assertEqual(seen, {'Web servers', 'Anybody'})
        marta = person('marta', local=True)              # view only on Web: not for requests
        self.assertEqual({p['name'] for p in portal(marta, 'GET', '/api/portal/certs')
                          ['profiles']}, {'Anybody'})
        got = portal(EVA, 'GET', '/api/portal/certs')
        self.assertFalse(got['free_form'])               # no old form set up
        web = [p for p in got['profiles'] if p['name'] == 'Web servers'][0]
        self.assertEqual(web['owner_choices'], ['Web'])
        self.assertEqual(portal_status(marta, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'names': ['a.example.test'], 'team': 'Web'}), 404)

    def test_request_from_a_profile(self):
        r = {'profile': 'Web servers', 'names': ['app.example.test'], 'team': 'Web',
             'subject': {'OU': 'Ops', 'O': 'Not taken'}, 'key_type': 'rsa-2048'}
        for bad, code in (({'names': ['app.other.test']}, 403),
                          ({'names': ['*.example.test']}, 403),
                          ({'names': ['a.example.test', 'b.example.test', 'c.example.test',
                                      'd.example.test']}, 400),
                          ({'key_type': 'ed25519'}, 400),
                          ({'team': ''}, 403),
                          ({'team': 'Approvers'}, 403)):
            self.assertEqual(portal_status(EVA, 'POST', '/api/portal/cert_request',
                                           dict(r, **bad)), code, bad)
        got = portal(EVA, 'POST', '/api/portal/cert_request', r)
        self.assertFalse(got['waits'])
        row = wait_cert(got['id'])
        prof = json.loads(row['profile'])
        self.assertEqual(prof['subject'], {'O': 'Example s.r.o.', 'OU': 'Ops', 'C': 'CZ'})
        self.assertEqual((row['owner'], json.loads(row['tags']), row['renew_days'],
                          row['auto_renew'], row['key_type']),
                         ('Web', ['portal', 'web'], 20, 1, 'rsa-2048'))
        info = pki.cert_info(row['cert_pem'])
        self.assertEqual(info['subject'].get('O'), 'Example s.r.o.')
        self.assertTrue(row['key_sealed'])
        one = [c for c in portal(EVA, 'GET', '/api/portal/certs')['rows']
               if c['id'] == got['id']][0]
        self.assertIn('pfx', one['formats'])
        self.assertEqual(one['req_profile'], 'Web servers')

    def test_renamed_profile_keeps_what_was_asked(self):
        """A profile renamed: what was asked for from it says the new name, counts in
        it, and a new CSR for it is checked against it still (1.0.19)."""
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'names': ['ren.example.test'], 'team': 'Web'})
        wait_cert(got['id'])
        R.save_profile(STORE, base_profile(name='Web TLS', old_name='Web servers'), 'x')
        self.assertEqual(P.asker(STORE, got['id']).get('profile'), 'Web TLS')
        used = {p['name']: p['used'] for p in R.profiles(STORE)}
        self.assertEqual(used.get('Web TLS'), 1)
        one = [c for c in portal(EVA, 'GET', '/api/portal/certs')['rows']
               if c['id'] == got['id']][0]
        self.assertEqual(one['req_profile'], 'Web TLS')
        self.assertIn('pfx', one['formats'])
        # what a CA said of a twin that failed is not shown there, as last_error is not
        STORE.db.update('certs', got['id'], {'alt_error': 'https://ca.internal:8443/ said no'})
        one = P.public_row(STORE, S.cert_get(STORE, got['id']), 'me')
        self.assertNotIn('alt_error', one)
        self.assertNotIn('ca.internal', json.dumps(one))
        # deleted, who asked for it goes too - not handed to a certificate of the same id
        call('POST', '/api/certs/delete', {'id': got['id']})
        self.assertIsNone(STORE.get_meta(P.META + str(got['id'])))

    def test_waits_for_approval(self):
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Anybody', 'names': ['w.example.test']})
        self.assertTrue(got['waits'])
        row = S.cert_get(STORE, got['id'])
        self.assertEqual((row['state'], row['auto_renew'], row['owner']),
                         (P.WAITING, 0, 'eva'))
        # a CSR to a profile that takes none: refused
        key = pki.make_key('ec-256')
        csr = pki.make_csr(key, ['x.example.test'])[0]
        self.assertEqual(portal_status(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Anybody', 'csr': csr}), 400)
        P.approve_request(STORE, row, 'boss', True, '')
        wait_cert(got['id'])
        self.assertEqual(S.cert_get(STORE, got['id'])['auto_renew'], 0)   # as the profile says

    def test_old_free_form_still_works(self):
        E.CONFIG.update(portal_cert_suffixes='example.test', portal_cert_issuers='self',
                        portal_cert_auto=0)
        got = portal(EVA, 'GET', '/api/portal/certs')
        self.assertTrue(got['free_form'] and got['may_request'])
        got = portal(EVA, 'POST', '/api/portal/cert_request', {'names': ['old.example.test'],
                                                                'issuer': 'self'})
        self.assertEqual(S.cert_get(STORE, got['id'])['state'], P.WAITING)


class Csr(unittest.TestCase):
    def setUp(self):
        setup()
        R.save_profile(STORE, base_profile(make_key=False, pfx=False), 'x')

    def csr(self, names, kt='ec-256', subject=None):
        key = pki.make_key(kt)
        return key, pki.make_csr(key, names, subject=subject)[0]

    def test_decode_and_checks(self):
        _k, csr = self.csr(['www.example.test', 'bad.other.test'],
                           subject={'CN': 'www.example.test', 'O': 'Someone', 'L': 'Brno'})
        got = portal(EVA, 'POST', '/api/portal/csr_decode', {'profile': 'Web servers',
                                                              'csr': csr})
        self.assertFalse(got['fits'])
        self.assertTrue(got['csr']['sig_ok'])
        self.assertEqual((got['csr']['key_type'], got['csr']['key_bits']), ('ec-256', 256))
        byname = {c.get('name'): c['ok'] for c in got['checks'] if c['what'] == 'name'}
        self.assertEqual(byname, {'www.example.test': True, 'bad.other.test': False})
        subj = {x['field']: (x['csr'], x['cert'], x['how']) for x in got['subject']}
        self.assertEqual(subj['O'], ('Someone', 'Example s.r.o.', 'fixed'))
        self.assertEqual(subj['L'], ('Brno', '', 'off'))
        self.assertEqual(subj['OU'], ('', 'IT', 'person'))           # the default
        # a DER file, uploaded
        der = pki.pem_to_der(self.csr(['a.example.test'], 'ed25519')[1])
        got = portal(EVA, 'POST', '/api/portal/csr_decode', {
            'profile': 'Web servers', 'csr_b64': base64.b64encode(der).decode()})
        self.assertEqual([c['ok'] for c in got['checks'] if c['what'] == 'key'], [False])
        self.assertEqual(portal_status(EVA, 'POST', '/api/portal/csr_decode', {
            'profile': 'Web servers', 'csr': 'not a CSR'}), 400)
        # a profile they may not use: nothing said about it
        self.assertEqual(portal_status(person('marta', local=True), 'POST',
                                       '/api/portal/csr_decode',
                                       {'profile': 'Web servers', 'csr': csr}), 404)

    def test_issued_for_a_csr_and_renewed_with_it(self):
        key, csr = self.csr(['api.example.test', 'api2.example.test'], 'ec-384',
                            subject={'O': 'Whatever', 'OU': 'Dev'})
        # this profile takes only a CSR
        self.assertEqual(portal_status(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'names': ['api.example.test'], 'team': 'Web'}), 400)
        self.assertEqual(portal_status(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'csr': csr, 'team': 'Web'}), 400)   # ec-384: not allowed
        R.save_profile(STORE, base_profile(make_key=False, pfx=False,
                                           key_types=['ec-256', 'ec-384'],
                                           old_name='Web servers'), 'x')
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'csr': csr, 'team': 'Web'})
        row = wait_cert(got['id'])
        self.assertFalse(row['key_sealed'])
        self.assertEqual(row['key_type'], 'ec-384')
        info = pki.cert_info(row['cert_pem'])
        self.assertEqual(info['pub_sha256'], pki.key_info(key)['pub_sha256'])
        self.assertEqual((info['subject'].get('O'), info['subject'].get('OU'),
                          info['subject'].get('CN')), ('Example s.r.o.', 'Dev',
                                                       'api.example.test'))
        self.assertEqual(sorted(info['names']), ['api.example.test', 'api2.example.test'])
        self.assertTrue(S.cert_public(row)['from_csr'])
        # renewed: the same CSR, the same key
        jobs.run_now(STORE, 'renew', renewer.renew_job(row['id'], True, 'test'),
                     cert_id=row['id'])
        row2 = S.cert_get(STORE, row['id'])
        self.assertEqual(row2['version'], 2)
        self.assertEqual(pki.cert_info(row2['cert_pem'])['pub_sha256'], info['pub_sha256'])
        self.assertNotEqual(row2['serial'], row['serial'])
        # no PFX, no key out
        one = [c for c in portal(EVA, 'GET', '/api/portal/certs')['rows']
               if c['id'] == row['id']][0]
        self.assertNotIn('pfx', one['formats'])
        self.assertTrue(one['from_csr'])
        E.CONFIG['portal_cert_keys'] = 1
        self.assertEqual(portal_status(EVA, 'POST', '/api/portal/cert_download', {
            'id': row['id'], 'format': 'pfx', 'password': 'Long-enough-1'}), 400)
        with self.assertRaises(ValueError) as e:
            A.cert_export(STORE, {'id': row['id'], 'format': 'key-pem'},
                          {'name': 'boss', 'role': 'fulladmin'})
        self.assertIn('never had its key', str(e.exception))
        self.assertTrue(portal(EVA, 'POST', '/api/portal/cert_download', {
            'id': row['id'], 'format': 'fullchain-pem'})['data_b64'])
        # a new CSR (a new key): only with the right manage, then issued again
        key2, csr2 = self.csr(['api.example.test'])
        self.assertEqual(portal_status(EVA, 'POST', '/api/portal/cert_csr', {
            'id': row['id'], 'csr': csr2}), 403)
        mgr = person('mgr', local=True)
        portal(mgr, 'POST', '/api/portal/cert_csr', {'id': row['id'], 'csr': csr2})
        row3 = wait_cert(row['id'], 3)
        self.assertEqual(pki.cert_info(row3['cert_pem'])['pub_sha256'],
                         pki.key_info(key2)['pub_sha256'])
        self.assertEqual((row3['key_type'], json.loads(row3['names'])),
                         ('ec-256', ['api.example.test']))
        # revoked and "a new one at once": refused before anything is revoked - a new
        # one needs a new CSR (1.0.19)
        self.assertEqual(portal_status(mgr, 'POST', '/api/portal/cert_revoke', {
            'id': row['id'], 'reason': 'superseded', 'renew': 1}), 400)
        row4 = S.cert_get(STORE, row['id'])
        self.assertEqual((row4['state'], row4['version']), (row3['state'], 3))


if __name__ == '__main__':
    unittest.main(verbosity=2)
