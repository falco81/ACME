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
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
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

    def test_asked_at_once_from_a_profile(self):
        # Hunt N round 1 (1.0.102): two asks at once got a 500 and a Traceback - the name the
        # other took meanwhile is taken next, as the portal's free form does
        import threading
        got, bad = [], []
        gate = threading.Barrier(6)

        def one():
            gate.wait()
            try:
                got.append(portal(EVA, 'POST', '/api/portal/cert_request', {
                    'profile': 'Anybody', 'names': ['race.example.test']})['name'])
            except Exception as e:                      # noqa: BLE001
                bad.append(repr(e))
        ts = [threading.Thread(target=one) for _ in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        self.assertEqual(bad, [])
        self.assertEqual(len(set(got)), 6)
        # ...and for certain: the name looked free, then was taken before the insert
        real_row = STORE.db.row
        seen = []

        def row(sql, args=()):
            if sql.startswith('SELECT id FROM certs WHERE name') and not seen:
                seen.append(args)
                return None
            return real_row(sql, args)
        STORE.db.row = row
        try:
            one_more = portal(EVA, 'POST', '/api/portal/cert_request', {
                'profile': 'Anybody', 'names': ['race.example.test']})
        finally:
            STORE.db.row = real_row
        self.assertEqual(seen, [('race.example.test',)])
        self.assertNotIn(one_more['name'], got)
        self.assertTrue(one_more['name'].startswith('race.example.test-'))

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

    def test_crafted_csrs_refused(self):
        """1.0.102: two extensionRequests (acme read the last, a CA the first), names of a kind
        no profile gives, a CA asked for, extended key usages the profile does not give."""
        sys.path.insert(0, HERE)
        import csr_craft as C
        key = pki.make_key('ec-256')
        dual = C.two_ext_requests(key, [C.UPN_SAN, C.SMARTCARD_EKU],
                                  ['subjectAltName=DNS:www.example.test'])
        for path in ('/api/portal/csr_decode', '/api/portal/cert_request'):
            self.assertEqual(portal_status(EVA, 'POST', path, {
                'profile': 'Web servers', 'csr': dual, 'team': 'Web'}), 400, path)
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM certs'), 0)

        def checks(csr, profile='Web servers'):
            got = portal(EVA, 'POST', '/api/portal/csr_decode', {'profile': profile, 'csr': csr})
            return got['fits'], {c['what']: c['ok'] for c in got['checks']
                                 if c['what'] in ('refused', 'eku')}
        dns = 'subjectAltName=DNS:www.example.test'
        # a UPN beside the DNS name: refused even by acme's own CA, which writes the names itself
        self.assertEqual(checks(C.csr(key, 'www.example.test',
                                      dns + ',otherName:1.3.6.1.4.1.311.20.2.3;UTF8:a@corp.test')),
                         (False, {'refused': False}))
        self.assertEqual(checks(C.csr(key, 'www.example.test', dns + ',RID:1.2.3.4')),
                         (False, {'refused': False}))
        self.assertEqual(checks(C.csr(key, 'www.example.test', dns,
                                      'basicConstraints=critical,CA:TRUE')),
                         (False, {'refused': False}))
        # its EKU: not written by acme's own CA (said), refused for a source taking it as it is
        self.assertEqual(checks(C.csr(key, 'www.example.test', dns, C.SMARTCARD_EKU)),
                         (True, {'eku': None}))
        self.assertEqual(checks(C.csr(key, 'www.example.test', dns,
                                      'extendedKeyUsage=serverAuth')), (True, {}))
        STORE.db.run("DELETE FROM cert_issuers WHERE name = 'corp-adcs'")
        STORE.db.insert('cert_issuers', {'name': 'corp-adcs', 'kind': 'ms_adcs', 'enabled': 1,
                                         'config': json.dumps({
                                             'url': 'https://ca.corp.test/certsrv',
                                             'template': 'WebServer', 'username': 'u',
                                             'password': 'p'})})
        R.save_profile(STORE, base_profile(name='AD', issuer='corp-adcs', make_key=False,
                                           pfx=False, subject={}), 'x')
        fits, got = checks(C.csr(key, 'www.example.test', dns, C.SMARTCARD_EKU), 'AD')
        self.assertEqual((fits, got), (False, {'eku': False}))
        self.assertEqual(checks(C.csr(key, 'www.example.test', dns), 'AD'), (True, {}))
        # the words of a refused name say which kinds are read
        got = portal(EVA, 'POST', '/api/portal/csr_decode', {'profile': 'Web servers', 'csr': C.csr(
            key, 'www.example.test', dns + ',RID:1.2.3.4')})
        said = [c['said'] for c in got['checks'] if c['what'] == 'refused'][0]
        self.assertIn('DNS names, IP addresses, e-mail addresses and URIs', said)

    def test_ms_ext_req_refused_and_kept_one_renews(self):
        """1.0.102: a CSR with msExtReq (AD CS reads its names, acme did not) is refused when it
        comes in; one kept from before still renews."""
        sys.path.insert(0, HERE)
        import csr_craft as C
        key = pki.make_key('ec-256')
        ms = C.msext_csr(key, 'www.example.test')
        for path in ('/api/portal/csr_decode', '/api/portal/cert_request'):
            self.assertEqual(portal_status(EVA, 'POST', path, {
                'profile': 'Web servers', 'csr': ms, 'team': 'Web'}), 400, path)
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM certs'), 0)
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'csr': C.csr(key, 'www.example.test',
                                                   'subjectAltName=DNS:www.example.test'),
            'team': 'Web'})
        row = wait_cert(got['id'])
        STORE.db.update('certs', row['id'], {'csr_given': ms})      # as kept before 1.0.102
        jobs.run_now(STORE, 'renew', renewer.renew_job(row['id'], True, 'test'),
                     cert_id=row['id'])
        row2 = S.cert_get(STORE, row['id'])
        self.assertEqual(row2['version'], 2, row2.get('last_error'))
        self.assertEqual(pki.cert_info(row2['cert_pem'])['pub_sha256'],
                         pki.key_info(key)['pub_sha256'])

    def test_windows_csr_taken_and_renewed(self):
        """1.0.102: a CSR of Windows certreq / ConfigMgr repeats the enrollment name-value pair
        attribute (1.3.6.1.4.1.311.13.2.1) - taken, issued, and renewed with it."""
        sys.path.insert(0, HERE)
        import csr_craft as C
        key = pki.make_key('ec-256')
        csr = C.windows_csr(key)
        got = portal(EVA, 'POST', '/api/portal/csr_decode', {'profile': 'Web servers',
                                                              'csr': csr})
        self.assertTrue(got['fits'], got['checks'])
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'csr': csr, 'team': 'Web'})
        row = wait_cert(got['id'])
        self.assertEqual(pki.cert_info(row['cert_pem'])['pub_sha256'],
                         pki.key_info(key)['pub_sha256'])
        jobs.run_now(STORE, 'renew', renewer.renew_job(row['id'], True, 'test'),
                     cert_id=row['id'])
        row2 = S.cert_get(STORE, row['id'])
        self.assertEqual(row2['version'], 2)
        self.assertEqual(pki.cert_info(row2['cert_pem'])['pub_sha256'],
                         pki.key_info(key)['pub_sha256'])

    def test_a_new_csr_with_its_profile_gone_is_refused(self):
        """1.0.106: with the request profile deleted, a new CSR was compared by its DNS names
        only - an e-mail or URI name, any extended key usage and any subject went to the
        source unchecked."""
        T.save_team(STORE, {'name': 'Web', 'old_name': 'Web', 'members': [
            'group:WEB_ADMINS=request', 'local:mgr=manage']}, 'x')
        _k, csr = self.csr(['gone.example.test'])
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'csr': csr, 'team': 'Web'})
        row = wait_cert(got['id'])
        R.delete_profile(STORE, 'Web servers', 'x')
        mgr = person('mgr', local=True)
        _k2, csr2 = self.csr(['gone.example.test'])
        h = FakeH(portal=mgr, body={'id': row['id'], 'csr': csr2})
        with self.assertRaises(E.ApiError) as e:
            E.ROUTES[('POST', '/api/portal/cert_csr')](h)
        self.assertEqual(e.exception.status, 409)
        self.assertIn('its request profile is gone', str(e.exception))
        self.assertEqual(S.cert_get(STORE, row['id'])['csr_given'].strip(), csr.strip())

    def test_a_new_csr_with_other_names_is_approved_again(self):
        """1.0.106: put back to waiting by a new CSR with other names, the approval it had
        before does not count - it is approved again before an issue."""
        R.save_profile(STORE, base_profile(make_key=False, pfx=False, approval=True,
                                           old_name='Web servers'), 'x')
        T.save_team(STORE, {'name': 'Web', 'old_name': 'Web', 'members': [
            'group:WEB_ADMINS=request', 'local:mgr=manage', 'local:appr=approve']}, 'x')
        _k, csr = self.csr(['again.example.test'])
        cid = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'csr': csr, 'team': 'Web'})['id']
        self.assertTrue(P.asker(STORE, cid)['waits'])
        self.assertIn('approve it first', S.unapproved_why(STORE, S.cert_get(STORE, cid)))
        P.mark_approved(STORE, cid, 'x')
        STORE.db.update('certs', cid, {'state': 'failed'})     # approved; its issue failed
        self.assertEqual(S.unapproved_why(STORE, S.cert_get(STORE, cid)), '')
        _k2, csr2 = self.csr(['again2.example.test'])
        got = portal(person('mgr', local=True), 'POST', '/api/portal/cert_csr',
                     {'id': cid, 'csr': csr2})
        self.assertTrue(got['waits'])
        self.assertNotIn('approved', P.asker(STORE, cid))
        STORE.db.update('certs', cid, {'state': 'failed'})     # out of the wait, not approved
        self.assertIn('never approved', S.unapproved_why(STORE, S.cert_get(STORE, cid)))

    def test_a_new_csr_with_other_names_waits_in_one_write(self):
        """1.0.106 (final review): the state put back to waiting, its sender noted and the
        approval taken back were three writes - the meta not written, it waited still marked
        approved (or its names changed with nothing of it noted). Now one transaction: the meta
        not written, nothing of the new CSR is kept."""
        R.save_profile(STORE, base_profile(make_key=False, pfx=False, approval=True,
                                           old_name='Web servers'), 'x')
        T.save_team(STORE, {'name': 'Web', 'old_name': 'Web', 'members': [
            'group:WEB_ADMINS=request', 'local:mgr=manage', 'local:appr=approve']}, 'x')
        _k, csr = self.csr(['one.example.test'])
        cid = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'csr': csr, 'team': 'Web'})['id']
        P.mark_approved(STORE, cid, 'x')
        STORE.db.update('certs', cid, {'state': 'failed'})     # approved; its issue failed
        before = S.cert_get(STORE, cid)
        _k2, csr2 = self.csr(['one2.example.test'])
        real = P.asker_change
        writes = []

        def broken(store, cid_, change):
            writes.append(cid_)
            raise E.ApiError(409, 'changed meanwhile')
        P.asker_change = broken
        try:
            self.assertEqual(portal_status(person('mgr', local=True), 'POST',
                                           '/api/portal/cert_csr', {'id': cid, 'csr': csr2}), 409)
        finally:
            P.asker_change = real
        self.assertEqual(writes, [cid])                     # one write of the meta only
        row = S.cert_get(STORE, cid)
        self.assertEqual((row['state'], row['csr_given'], row['names']),
                         (before['state'], before['csr_given'], before['names']))
        self.assertEqual(P.asker(STORE, cid)['approved']['by'], 'x')
        # written: waiting, its sender noted, not approved - together
        got = portal(person('mgr', local=True), 'POST', '/api/portal/cert_csr',
                     {'id': cid, 'csr': csr2})
        self.assertTrue(got['waits'])
        a = P.asker(STORE, cid)
        self.assertNotIn('approved', a)
        self.assertTrue(a['waits'])
        self.assertIn('local:mgr', P.askers_of(STORE, cid))
        self.assertEqual(S.cert_get(STORE, cid)['state'], 'pending-approval')

    def test_a_new_csr_makes_its_sender_one_who_asked(self):
        """1.0.102: a member who may manage sent his own CSR with other names for another's
        request (put back to waiting) and approved it himself; and a CSR refused because a job
        works on the certificate was kept all the same."""
        R.save_profile(STORE, base_profile(make_key=False, pfx=False, approval=True,
                                           old_name='Web servers'), 'x')
        T.save_team(STORE, {'name': 'Web', 'old_name': 'Web', 'members': [
            'group:WEB_ADMINS=request', 'local:marta=view', 'local:mgr=manage',
            'local:appr=approve']}, 'x')
        _k, csr = self.csr(['www.example.test'])
        got = portal(EVA, 'POST', '/api/portal/cert_request', {
            'profile': 'Web servers', 'csr': csr, 'team': 'Web'})
        cid = got['id']
        self.assertTrue(got['waits'])
        STORE.db.update('certs', cid, {'state': 'failed'})     # approved before; its issue failed
        P.mark_approved(STORE, cid, 'x')
        if not STORE.account('appr'):
            STORE.add_account('appr', 'readonly', 'Local-Only-Pw-77!x')
        mgr, appr = person('mgr', local=True), person('appr', local=True)
        # a job on it: refused, and nothing of the new CSR kept
        jid = STORE.db.insert('cert_jobs', {'ts': time.time(), 'kind': 'renew', 'cert_id': cid,
                                            'state': 'running', 'ok': 0})
        _k2, csr2 = self.csr(['api.example.test'])
        self.assertEqual(portal_status(mgr, 'POST', '/api/portal/cert_csr',
                                       {'id': cid, 'csr': csr2}), 409)
        row = S.cert_get(STORE, cid)
        self.assertEqual((row['csr_given'].strip(), json.loads(row['names'])),
                         (csr.strip(), ['www.example.test']))
        STORE.db.run('DELETE FROM cert_jobs WHERE id = ?', (jid,))
        got = portal(mgr, 'POST', '/api/portal/cert_csr', {'id': cid, 'csr': csr2})
        self.assertTrue(got['waits'])
        self.assertIn('local:mgr', P.askers_of(STORE, cid))
        self.assertEqual(P.asker(STORE, cid)['who'], 'eva')       # the one who asked stays
        self.assertEqual(portal_status(mgr, 'POST', '/api/portal/cert_approve',
                                       {'id': cid, 'ok': 1}), 403)
        mine = [c for c in portal(mgr, 'GET', '/api/portal/certs')['rows'] if c['id'] == cid]
        self.assertTrue(mine[0]['asked_by_me'])
        # nor on the administration's pages, as mgr
        st = status(E.ROUTES[('POST', '/api/certs/approve')],
                    FakeH(who='mgr', role='fulladmin', body={'id': cid, 'ok': 1}))
        self.assertEqual(st, 403)
        self.assertEqual(S.cert_get(STORE, cid)['state'], P.WAITING)
        self.assertEqual(portal_status(appr, 'POST', '/api/portal/cert_approve',
                                       {'id': cid, 'ok': 1}), 200)


if __name__ == '__main__':
    unittest.main(verbosity=2)
