#!/usr/bin/env python3
"""Signing in with Windows - Kerberos SSO (1.0.99, as otp 1.0.274), the administration and the
certificate portal each by its own switches.

    python3 test/test_kerberos.py      (or python3 -m unittest test.test_kerberos)

A real MIT Kerberos realm of its own (krb5-kdc on a free port, made in a folder of its own -
the kit's testing/kdc.sh, inside the test): the people of test/mockldap.py's directory, the web
service's names in one keytab, a name that is in no keytab, and two names sharing one key. The
browser's "Authorization: Negotiate" token made with the system's GSS-API from a person's ticket
cache, as a browser on Linux makes it. A real daemon in a folder of its own (test/test_certs_core.py's
way), the directory of test/mockldap.py, and the pages through php -S for the relay (401 Negotiate,
403 for every refusal, 404 while off, the cookie).

Skipped as a whole where krb5kdc, kadmin.local or libgssapi_krb5 are not there.
"""
import base64
import ctypes
import ctypes.util
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)
import mockldap                      # noqa: E402

BASE = 'DC=corpnet,DC=loc'
REALM = 'CORPNET.LOC'
HOST = 'acme.corpnet.loc'
PEOPLE = ('jnovak', 'edvorak', 'falco', 'marta', 'nested', 'nogroups', 'ghost', 'pkolar', 'gone',
          'tester', 'outsider')
ADMINS = 'CN=ISE Admins,OU=Groups,' + BASE
WATCHERS = 'CN=ISE Watchers,OU=Groups,' + BASE
CERT_USERS = 'CN=CERT_USERS,OU=Groups,' + BASE


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _have_kerberos():
    if not all(shutil.which(x) for x in ('krb5kdc', 'kdb5_util', 'kadmin.local', 'kinit')):
        return False
    try:
        ctypes.CDLL(ctypes.util.find_library('gssapi_krb5') or 'libgssapi_krb5.so.2')
    except OSError:
        return False
    return True


# The kit's krbtok.py: a browser's token for HTTP@<host> from one person's ticket cache - run in a
# process of its own, KRB5_CONFIG and KRB5CCNAME being the library's environment.
TOKEN_PY = r'''
import base64, ctypes, ctypes.util, sys
class Buf(ctypes.Structure):
    _fields_ = [('length', ctypes.c_size_t), ('value', ctypes.c_void_p)]
class Oid(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('elements', ctypes.c_void_p)]
def oid(raw):
    b = ctypes.create_string_buffer(raw, len(raw))
    o = Oid(len(raw), ctypes.cast(b, ctypes.c_void_p)); o._keep = b
    return o
host, mech = sys.argv[1], sys.argv[2]
lib = ctypes.CDLL(ctypes.util.find_library('gssapi_krb5') or 'libgssapi_krb5.so.2')
P, U, V = ctypes.POINTER, ctypes.c_uint32, ctypes.c_void_p
lib.gss_import_name.argtypes = [P(U), P(Buf), P(Oid), P(V)]
lib.gss_init_sec_context.argtypes = [P(U), V, P(V), V, P(Oid), U, U, V, P(Buf), P(P(Oid)), P(Buf), P(U), P(U)]
m = U(); nb = ('HTTP@' + host).encode()
nbuf = Buf(len(nb), ctypes.cast(ctypes.c_char_p(nb), V)); name = V()
hb = oid(bytes.fromhex('2a864886f71201020104'))
if lib.gss_import_name(ctypes.byref(m), ctypes.byref(nbuf), ctypes.byref(hb), ctypes.byref(name)):
    raise SystemExit('import_name failed')
mo = oid(bytes.fromhex('2b0601050502' if mech == 'spnego' else '2a864886f712010202'))
ctx, out = V(), Buf()
r = lib.gss_init_sec_context(ctypes.byref(m), None, ctypes.byref(ctx), name, ctypes.byref(mo), 0, 0,
                             None, None, None, ctypes.byref(out), None, None)
if r not in (0, 1):
    raise SystemExit('init_sec_context: %#x/%d' % (r, m.value))
print(base64.b64encode(ctypes.string_at(out.value, out.length)).decode())
'''


def der(tag, body):
    n = len(body)
    if n < 128:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + body


NTLM_NEGOTIATE = b'NTLMSSP\x00\x01\x00\x00\x00\x97\x82\x08\xe2' + b'\x00' * 16


def ntlm_in_spnego():
    """A NegTokenInit offering NTLM (1.3.6.1.4.1.311.2.2.10) with NTLM's first message inside -
    what Windows sends when it has no ticket for the name."""
    ntlm_oid = der(0x06, bytes.fromhex('2b06010401823702020a'))
    init = der(0x30, der(0xa0, der(0x30, ntlm_oid)) + der(0xa2, der(0x04, NTLM_NEGOTIATE)))
    return der(0x60, der(0x06, bytes.fromhex('2b0601050502')) + der(0xa0, init))


@unittest.skipUnless(_have_kerberos(), 'no MIT Kerberos (krb5kdc, kadmin.local, libgssapi_krb5) here')
class Kerberos(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.ok
    py = TCC.CertsCore.py

    # ---- the realm ------------------------------------------------------------------------
    @classmethod
    def kdc_up(cls):
        d = cls.kdc = tempfile.mkdtemp(prefix='acme-kdc-')
        port = free_port()
        with open(os.path.join(d, 'krb5.conf'), 'w') as f:
            f.write('[libdefaults]\n  default_realm = %s\n  dns_lookup_kdc = false\n'
                    '  dns_lookup_realm = false\n  rdns = false\n  udp_preference_limit = 1\n'
                    '[realms]\n  %s = {\n    kdc = 127.0.0.1:%d\n  }\n' % (REALM, REALM, port))
        with open(os.path.join(d, 'kdc.conf'), 'w') as f:
            f.write('[kdcdefaults]\n  kdc_ports = %d\n  kdc_tcp_ports = %d\n[realms]\n  %s = {\n'
                    '    database_name = %s/principal\n    key_stash_file = %s/stash\n'
                    '    acl_file = %s/kadm5.acl\n    supported_enctypes = '
                    'aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n  }\n'
                    % (port, port, REALM, d, d, d))
        cls.kenv = dict(os.environ, KRB5_CONFIG=os.path.join(d, 'krb5.conf'),
                        KRB5_KDC_PROFILE=os.path.join(d, 'kdc.conf'))
        cls.kenv.pop('KRB5CCNAME', None)

        def run(*argv, inp=None):
            got = subprocess.run(list(argv), env=cls.kenv, input=inp, capture_output=True,
                                 text=True, timeout=60)
            if got.returncode:
                raise RuntimeError('%s: %s' % (' '.join(argv), got.stderr[-500:]))
            return got.stdout
        run('kdb5_util', 'create', '-s', '-r', REALM, '-P', base64.b64encode(os.urandom(18)).decode())

        def q(cmd):
            return run('kadmin.local', '-r', REALM, '-q', cmd)
        for p in ('HTTP/%s' % HOST, 'HTTP/node2.corpnet.loc', 'HTTP/other.corpnet.loc'):
            q('addprinc -randkey %s' % p)
        # Two names of one key (one service account with two SPNs): the salt of the realm only.
        pw = base64.b64encode(os.urandom(12)).decode()
        for p in ('HTTP/svc1.corpnet.loc', 'HTTP/svc2.corpnet.loc'):
            run('kadmin.local', '-r', REALM, '-q',
                'addprinc -e aes256-cts-hmac-sha1-96:onlyrealm -pw %s %s' % (pw, p))
        q('ktadd -k %s/http.keytab HTTP/%s HTTP/node2.corpnet.loc' % (d, HOST))
        q('ktadd -norandkey -k %s/svc1.keytab HTTP/svc1.corpnet.loc' % d)
        for p in PEOPLE:
            q('addprinc -randkey %s' % p)
            q('ktadd -k %s/%s.keytab %s' % (d, p, p))
        cls.kdc_proc = subprocess.Popen(['krb5kdc', '-n', '-r', REALM], env=cls.kenv,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        for p in PEOPLE:
            env = dict(cls.kenv, KRB5CCNAME='FILE:%s/%s.cc' % (d, p))
            for _ in range(20):
                got = subprocess.run(['kinit', '-k', '-t', '%s/%s.keytab' % (d, p), p], env=env,
                                     capture_output=True, text=True, timeout=30)
                if not got.returncode:
                    break
                time.sleep(0.3)
            else:
                raise RuntimeError('kinit %s: %s' % (p, got.stderr))
        with open(os.path.join(d, 'tok.py'), 'w') as f:
            f.write(TOKEN_PY)

    @classmethod
    def ticket(cls, person, host=HOST, mech='spnego'):
        env = dict(cls.kenv, KRB5CCNAME='FILE:%s/%s.cc' % (cls.kdc, person))
        got = subprocess.run([sys.executable, '-I', os.path.join(cls.kdc, 'tok.py'), host, mech],
                             env=env, capture_output=True, text=True, timeout=30)
        if got.returncode:
            raise RuntimeError('a token of %s for %s: %s' % (person, host, got.stderr))
        return got.stdout.strip()

    @classmethod
    def keytab_b64(cls, name):
        with open(os.path.join(cls.kdc, name), 'rb') as f:
            return base64.b64encode(f.read()).decode()

    # ---- the daemon -------------------------------------------------------------------------
    @classmethod
    def setUpClass(cls):
        cls.kdc_up()
        os.environ['KRB5_CONFIG'] = os.path.join(cls.kdc, 'krb5.conf')     # the daemon's too
        # The directory as a domain controller has it for these people: their account state
        # readable (userAccountControl), marta in the group of the portal. Put back afterwards.
        cls.ldap_was = json.dumps([mockldap.PEOPLE, mockldap.GROUPS])
        for dn, one in mockldap.PEOPLE.items():
            if (one.get('sAMAccountName') or [''])[0] in ('jnovak', 'edvorak', 'nogroups'):
                one['userAccountControl'] = ['512']
        members = mockldap.GROUPS[CERT_USERS]['member']
        if 'CN=Marta Mobilni,OU=People,' + BASE not in members:
            members.append('CN=Marta Mobilni,OU=People,' + BASE)
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.spool = os.path.join(cls.tmp, 'sms')
        os.makedirs(cls.spool, exist_ok=True)
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        cls.must('POST', '/api/settings', {'settings': {
            'admin_directory': 'corp', 'admin_group_full': ADMINS, 'admin_group_readonly': WATCHERS,
            'portal': 1, 'portal_directory': 'corp', 'portal_who': 'groups',
            'portal_groups': CERT_USERS, 'portal_tries': 50, 'login_tries': 50,
            'sms_mode': 'spool', 'sms_spool_dir': cls.spool}})

    @classmethod
    def tearDownClass(cls):
        try:
            TCC.CertsCore.tearDownClass.__func__(cls)
        finally:
            cls.ldap_stop.set()
            people, groups = json.loads(cls.ldap_was)
            mockldap.PEOPLE.clear()
            mockldap.PEOPLE.update(people)
            mockldap.GROUPS.clear()
            mockldap.GROUPS.update(groups)
            proc = getattr(cls, 'kdc_proc', None)
            if proc is not None:
                proc.terminate()
                proc.wait(10)
            shutil.rmtree(cls.kdc, ignore_errors=True)
            os.environ.pop('KRB5_CONFIG', None)

    @classmethod
    def must(cls, method, path, body=None, session=None):
        st, got = cls.call(method, path, body, session or cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def setUp(self):
        self.call('POST', '/api/lockouts', {'action': 'clear_all'}, self.admin)

    def settings(self, session=None, portal=None, **kv):
        req = urllib.request.Request('http://127.0.0.1:%d/api/settings' % self.port,
                                     data=json.dumps({'settings': kv}).encode(), method='POST')
        req.add_header('X-Acme-Token', self.token)
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Acme-Session', session or self.admin)
        if portal:
            req.add_header('X-Acme-Portal-Session', portal)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def krb(self, part, header, session=None):
        path = '/api/auth/kerberos' if part == 'admin' else '/api/portal/kerberos'
        return self.call('POST', path, {'header': header} if header is not None else {}, session)

    def neg(self, person, host=HOST, mech='spnego'):
        return 'Negotiate ' + self.ticket(person, host, mech)

    def events(self, text):
        got = self.ok('GET', '/api/events', args={'q': text})
        return [e.get('words') or '' for e in got.get('events') or got.get('rows') or []]

    def put_keytab(self, name='http.keytab'):
        st, got = self.call('POST', '/api/kerberos', {'action': 'put', 'data': self.keytab_b64(name),
                                                      'name': name}, self.admin)
        self.assertEqual(st, 200, got)
        return got

    def keytab_file(self):
        return os.path.join(self.tmp, 'state', 'kerberos', 'http.keytab')

    def forget_rcache(self):
        """This node's own replay cache (the library's) gone - as on the other node of a cluster,
        which shares only the database."""
        for f in os.listdir(os.path.dirname(self.keytab_file())):
            if 'rcache' in f:
                os.unlink(os.path.join(os.path.dirname(self.keytab_file()), f))

    # -------------------------------------------------------------------------------------
    def test_01_off_by_default(self):
        self.assertEqual(self.py(
            'print(json.dumps([E.DEFAULTS[k] for k in ("admin_krb", "admin_krb_auto", '
            '"admin_password_off", "portal_krb", "portal_krb_auto", "portal_password_off", '
            '"alerts_kerberos")]))'), [0, 0, 0, 0, 0, 0, 0])
        for part in ('admin', 'portal'):
            st, got = self.krb(part, None)
            self.assertEqual(st, 404, got)
            st, got = self.krb(part, self.neg('jnovak'))
            self.assertEqual(st, 404, got)
        st, h = self.call('GET', '/api/health')
        self.assertEqual(h['kerberos'], {'on': False, 'auto': False, 'only': False})
        st, info = self.call('GET', '/api/portal/info')
        self.assertFalse(info['kerberos']['on'])
        # The switches are signed rows (db_guard), "only Windows" refused on from a password.
        st, got = self.settings(admin_password_off=1)
        self.assertEqual(st, 400, got)
        self.assertIn('only from a sign-in made with Windows', got['error'])

    def test_02_the_keytab(self):
        st, got = self.call('POST', '/api/kerberos', {'action': 'put', 'data': base64.b64encode(
            b'not a keytab at all').decode()}, self.admin)
        self.assertEqual(st, 400, got)
        st, got = self.call('POST', '/api/kerberos', {'action': 'put', 'data': 'x'}, self.ro)
        self.assertEqual(st, 403, got)
        got = self.put_keytab()
        princ = sorted({e['principal'] for e in got['view']['keytab']['entries']})
        self.assertEqual(princ, ['HTTP/%s@%s' % (HOST, REALM), 'HTTP/node2.corpnet.loc@%s' % REALM])
        self.assertNotIn('key', json.dumps(got['view']['keytab']).replace('keytab', ''))
        # Kept sealed and signed, never in the clear in the database.
        raw = self.py('print(json.dumps(st.db.value("SELECT v FROM meta WHERE k = %r", ())))'
                      % 'krb:keytab')
        self.assertIn('sealed:2:', raw)
        self.assertNotIn(self.keytab_b64('http.keytab')[:40], raw)
        self.assertTrue(self.py('print(json.dumps(bool(st.db.value("SELECT 1 FROM meta WHERE k LIKE '
                                '%r", ()))))' % 'sig:m:%'))
        # Written out by the node itself, 0600.
        with open(os.path.join(self.kdc, 'http.keytab'), 'rb') as f:
            want = f.read()
        for _ in range(60):
            if os.path.exists(self.keytab_file()):
                break
            time.sleep(0.5)
        with open(self.keytab_file(), 'rb') as f:
            self.assertEqual(f.read(), want)
        self.assertEqual(os.stat(self.keytab_file()).st_mode & 0o777, 0o600)
        # The card: the names, the realm from the base DN, this node.
        v = self.ok('GET', '/api/kerberos', session=self.ro)
        self.assertEqual(v['parts']['admin']['realm'], REALM)
        self.assertEqual(v['parts']['admin']['realm_from'], 'directory')
        self.assertTrue(v['lib']['there'])
        self.assertEqual(len(v['nodes']), 1)
        self.assertTrue(v['nodes'][0]['written'] and v['nodes'][0]['lib'])

    def test_03_admin_on_portal_off(self):
        self.put_keytab()
        st, got = self.settings(admin_krb=1)
        self.assertEqual(st, 200, got)
        st, h = self.call('GET', '/api/health')
        self.assertEqual(h['kerberos'], {'on': True, 'auto': False, 'only': False})
        # No ticket: 401 (the page answers it with Negotiate).
        st, got = self.krb('admin', None)
        self.assertEqual(st, 401, got)
        # The right person: their role, a session that says how it was opened.
        st, got = self.krb('admin', self.neg('jnovak'))
        self.assertEqual(st, 200, got)
        self.assertEqual(got['who'], {'name': 'jnovak', 'role': 'fulladmin'})
        st, me = self.call('GET', '/api/auth/whoami', None, got['token'])
        self.assertEqual(me['who']['how'], 'Kerberos')
        self.assertEqual(me['who']['role'], 'fulladmin')
        st, got = self.krb('admin', self.neg('edvorak'))
        self.assertEqual((st, got.get('who', {}).get('role')), (200, 'readonly'), got)
        # The portal's endpoint stays off: its own switch.
        st, got = self.krb('portal', self.neg('falco'))
        self.assertEqual(st, 404, got)
        self.assertTrue(any('jnovak signed in from' in w and 'Windows (Kerberos' in w
                            for w in self.events('with Windows')))

    def test_04_refused(self):
        self.put_keytab()
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
        cases = [
            ('nogroups', 'none of the groups'),          # known, no role
            ('falco', 'none of the groups'),             # a portal person, no role here
            ('ghost', 'nobody called ghost'),            # not in the directory
            ('pkolar', 'locked'),                        # locked out in AD
            ('gone', 'disabled'),                        # switched off in AD
            ('tester', 'account of this server'),        # a local account of the same name
        ]
        for person, why in cases:
            st, got = self.krb('admin', self.neg(person))
            self.assertEqual(st, 401, (person, got))
            self.assertNotIn('token', got)
            self.assertIn(why, got.get('error', ''), person)
        # A ticket for a name that is not in the keytab.
        st, got = self.krb('admin', self.neg('jnovak', 'other.corpnet.loc'))
        self.assertEqual(st, 401, got)
        self.assertIn('not found in keytab', got['error'])
        # NTLM: bare (in Negotiate and as its own scheme), inside SPNEGO; garbage; 20 kB.
        for header, why in (('Negotiate ' + base64.b64encode(NTLM_NEGOTIATE).decode(), 'NTLM'),
                            ('NTLM ' + base64.b64encode(NTLM_NEGOTIATE).decode(), 'NTLM'),
                            ('Negotiate ' + base64.b64encode(ntlm_in_spnego()).decode(), 'NTLM'),
                            ('Negotiate ' + base64.b64encode(os.urandom(300)).decode(), 'not taken'),
                            ('Negotiate %%%%-not-base64', 'not base64'),
                            ('Negotiate ' + base64.b64encode(os.urandom(15000)).decode(), 'not taken')):
            st, got = self.krb('admin', header)
            self.assertEqual(st, 401, (header[:30], got))
            self.assertIn(why, got.get('error', ''))
        # Another realm only is taken.
        self.must('POST', '/api/settings', {'settings': {'admin_krb_realm': 'example.com'}})
        st, got = self.krb('admin', self.neg('jnovak'))
        self.assertEqual(st, 401, got)
        self.assertIn('only EXAMPLE.COM signs in here', got['error'])
        self.must('POST', '/api/settings', {'settings': {'admin_krb_realm': ''}})
        # Every refusal in Events, never a token in them.
        words = self.events('with Windows (Kerberos) was refused')
        self.assertTrue(len(words) >= 10, words)
        self.assertFalse(any('YII' in w or 'TlRMTVNT' in w for w in words))

    def test_05_once_in_the_cluster(self):
        self.put_keytab()
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
        header = self.neg('jnovak')
        st, got = self.krb('admin', header)
        self.assertEqual(st, 200, got)
        # The same token again on the same node: the library's replay cache.
        st, got = self.krb('admin', header)
        self.assertEqual(st, 401, got)
        self.assertIn('replay', got['error'].lower())
        # ...and on "the other node", which shares only the database: the cluster's table.
        self.forget_rcache()
        st, got = self.krb('admin', header)
        self.assertEqual(st, 401, got)
        self.assertIn('used already', got['error'])
        # A token the other node took (its row, in the shared database): refused here.
        header = self.neg('jnovak')
        raw = base64.b64decode(header.split()[1])
        self.py('st.db.run("INSERT INTO meta (k, v) VALUES (?, ?)", (%r, json.dumps([time.time()])));'
                ' print("1")' % ('krbonce:%s@@node2' % hashlib.sha256(raw).hexdigest()))
        st, got = self.krb('admin', header)
        self.assertEqual(st, 401, got)
        self.assertIn('used already', got['error'])

    def test_06_one_key_for_two_names(self):
        """The keytab of svc1 alone takes a ticket for svc2: one account's key serves every SPN."""
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
        self.put_keytab('svc1.keytab')
        try:
            st, got = self.krb('admin', self.neg('jnovak', 'svc2.corpnet.loc'))
            self.assertEqual(st, 200, got)
            st, got = self.krb('admin', self.neg('jnovak', 'svc2.corpnet.loc', 'krb5'))
            self.assertEqual(st, 200, got)     # bare Kerberos, not wrapped in SPNEGO
        finally:
            self.put_keytab()

    def test_07_second_step_after_it(self):
        self.put_keytab()
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 1, 'admin_2fa': 1}})
        try:
            st, got = self.krb('admin', self.neg('jnovak'))
            self.assertEqual(st, 200, got)
            self.assertEqual(got['mfa'], 'enrol')
            self.assertEqual(got['who']['role'], '')
            st, me = self.call('GET', '/api/auth/whoami', None, got['token'])
            self.assertEqual(me['who']['mfa'], 'enrol')
            st, x = self.call('GET', '/api/status', None, got['token'])
            self.assertEqual(st, 401, x)
        finally:
            self.must('POST', '/api/settings', {'settings': {'admin_2fa': 0}})

    def test_08_only_windows_admin(self):
        self.put_keytab()
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
        st, got = self.krb('admin', self.neg('jnovak'))
        self.assertEqual(st, 200, got)
        kerb = got['token']
        # From a password sign-in: refused; from the Kerberos one: switched on.
        st, got = self.settings(admin_password_off=1)
        self.assertEqual(st, 400, got)
        st, got = self.settings(session=kerb, admin_password_off=1)
        self.assertEqual(st, 200, got)
        try:
            st, h = self.call('GET', '/api/health')
            self.assertTrue(h['kerberos']['only'])
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            self.assertEqual(st, 403, got)
            self.assertIn('only Windows', got['error'])
            st, got = self.call('POST', '/api/auth/password', {'old': self.pw, 'new': 'An-0ther-Pass!',
                                                               'again': 'An-0ther-Pass!'}, self.admin)
            self.assertEqual(st, 403, got)
            st, got = self.call('POST', '/api/users', {'action': 'add', 'name': 'newone',
                                                       'role': 'readonly', 'password': 'Xx-123456789!'},
                                self.admin)
            self.assertEqual(st, 403, got)
            st, me = self.call('GET', '/api/auth/whoami', None, kerb)
            self.assertTrue(me['who']['password_off'])
            # Not from the command line, nor from a file; switched off there it is.
            cli = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--set',
                                  'portal_password_off=1'], env=self.env, capture_output=True,
                                 text=True, timeout=120)
            self.assertNotEqual(cli.returncode, 0, cli.stdout)
            # Kerberos off brings the passwords back - the way back without root.
            st, got = self.settings(session=kerb, admin_krb=0)
            self.assertEqual(st, 200, got)
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            self.assertEqual(st, 200, got)
            self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            self.assertEqual(st, 403, got)
        finally:
            # Root's way back: acme --set admin_password_off=0.
            cli = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--set',
                                  'admin_password_off=0'], env=self.env, capture_output=True,
                                 text=True, timeout=120)
            self.assertEqual(cli.returncode, 0, cli.stdout + cli.stderr)
        for _ in range(40):                 # the daemon reads the settings again within seconds
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            if st == 200:
                break
            time.sleep(0.5)
        self.assertEqual(st, 200, got)
        type(self).admin = got['token']

    def test_09_portal_on_admin_off(self):
        self.put_keytab()
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 0, 'portal_krb': 1}})
        try:
            st, got = self.krb('admin', self.neg('jnovak'))
            self.assertEqual(st, 404, got)
            st, info = self.call('GET', '/api/portal/info')
            self.assertEqual(info['kerberos'], {'on': True, 'auto': False, 'only': False})
            st, h = self.call('GET', '/api/health')
            self.assertFalse(h['kerberos']['on'])
            st, got = self.krb('portal', None)
            self.assertEqual(st, 401, got)
            # In the portal's groups: in; a nested member too.
            st, got = self.krb('portal', self.neg('falco'))
            self.assertEqual(st, 200, got)
            st, me = self.call('GET', '/api/portal/me', None, got['token'])
            self.assertEqual(st, 200, me)
            self.assertEqual(me['me']['name'], 'falco@corpnet.cz')
            st, got = self.krb('portal', self.neg('nested'))
            self.assertEqual(st, 200, got)
            # A full administrator of the administration, in none of the portal's groups: out.
            for person, why in (('jnovak', 'none of the groups'), ('gone', 'disabled'),
                                ('ghost', 'no such account'), ('tester', 'account of this server')):
                st, got = self.krb('portal', self.neg(person))
                self.assertEqual(st, 401, (person, got))
                self.assertIn(why, got['error'], person)
            # Both on: each part by its own rules - falco is no administrator, jnovak no portal user.
            self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
            st, got = self.krb('admin', self.neg('falco'))
            self.assertEqual(st, 401, got)
            st, got = self.krb('admin', self.neg('jnovak'))
            self.assertEqual(st, 200, got)
            st, got = self.krb('portal', self.neg('jnovak'))
            self.assertEqual(st, 401, got)
            # Try my browser's ticket: who it would be, for each part, nobody signed in. (A read-only
            # account may: it changes nothing. Signed in again - the second step switched on in
            # test_07 ended the other sign-ins.)
            type(self).ro = self.login('viewer')
            st, t = self.call('POST', '/api/kerberos/try', {'part': 'portal',
                                                            'header': self.neg('falco')}, self.ro)
            self.assertEqual((st, t['ok'], t.get('name')), (200, True, 'falco@corpnet.cz'), t)
            st, t = self.call('POST', '/api/kerberos/try', {'part': 'admin',
                                                            'header': self.neg('falco')}, self.ro)
            self.assertEqual((st, t['ok']), (200, False), t)
            st, t = self.call('POST', '/api/kerberos/try', {'part': 'admin',
                                                            'header': self.neg('edvorak')}, self.ro)
            self.assertEqual((t['ok'], t['role']), (True, 'readonly'), t)
            # Neither: both 404.
            self.must('POST', '/api/settings', {'settings': {'admin_krb': 0, 'portal_krb': 0}})
            for part in ('admin', 'portal'):
                st, got = self.krb(part, self.neg('jnovak'))
                self.assertEqual(st, 404, got)
        finally:
            self.must('POST', '/api/settings', {'settings': {'admin_krb': 0, 'portal_krb': 0}})

    def test_10_portal_code_after_it(self):
        self.put_keytab()
        self.must('POST', '/api/settings', {'settings': {'portal_krb': 1, 'portal_code': 'sms'}})
        try:
            st, got = self.krb('portal', self.neg('marta'))
            self.assertEqual(st, 200, got)
            self.assertEqual(got['gate']['kind'], 'sms')
            st, me = self.call('GET', '/api/portal/me', None, got['token'])
            # The code first, as after a password: the sign-in waits for it, nothing more.
            self.assertEqual(set(me['me']), {'name', 'gate'}, me)
            st, x = self.call('GET', '/api/portal/certs', None, got['token'])
            self.assertEqual(st, 401, x)
        finally:
            self.must('POST', '/api/settings', {'settings': {'portal_code': 'off', 'portal_krb': 0}})

    def test_11_only_windows_portal(self):
        self.put_keytab()
        self.must('POST', '/api/settings', {'settings': {'portal_krb': 1}})
        st, got = self.krb('portal', self.neg('falco'))
        self.assertEqual(st, 200, got)
        ptok = got['token']
        st, got = self.settings(portal_password_off=1)
        self.assertEqual(st, 400, got)
        st, got = self.settings(portal=ptok, portal_password_off=1)
        self.assertEqual(st, 200, got)
        try:
            st, info = self.call('GET', '/api/portal/info')
            self.assertTrue(info['kerberos']['only'])
            st, got = self.call('POST', '/api/portal/login', {'name': 'falco',
                                                              'password': 'falco-password-1'})
            self.assertEqual(st, 403, got)
            # The administration keeps its passwords: its own switch.
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            self.assertEqual(st, 200, got)
            self.must('POST', '/api/settings', {'settings': {'portal_krb': 0}})
            st, got = self.call('POST', '/api/portal/login', {'name': 'falco',
                                                              'password': 'falco-password-1'})
            self.assertEqual(st, 200, got)
        finally:
            self.must('POST', '/api/settings', {'settings': {'portal_password_off': 0,
                                                             'portal_krb': 0}})

    def test_12_through_the_pages(self):
        """web/admin/index.php and web/index.php through php -S: 404 while off, 401 Negotiate
        without a ticket, 403 for every refusal (never a second 401), the cookie on success."""
        if not shutil.which('php'):
            self.skipTest('no php here')
        self.put_keytab()
        web = tempfile.mkdtemp(prefix='acme-krb-web-')
        shutil.rmtree(web)
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        with open(os.path.join(web, 'router.php'), 'w') as f:
            f.write("<?php\n$p = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);\n"
                    "if ($p === '/' || $p === '/index.php') { chdir(__DIR__); require __DIR__ . '/index.php'; return true; }\n"
                    "if ($p === '/admin/') { chdir(__DIR__ . '/admin'); require __DIR__ . '/admin/index.php'; return true; }\n"
                    "return false;\n")
        port = free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port, 'router.php'], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='2'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def post(path, auth=None):
            req = urllib.request.Request('http://127.0.0.1:%d%s' % (port, path), data=b'{}',
                                         method='POST')
            req.add_header('Content-Type', 'application/json')
            if auth is not None:
                req.add_header('Authorization', auth)
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return r.status, dict(r.headers), r.headers.get_all('Set-Cookie') or [], \
                        json.loads(r.read().decode() or '{}')
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers), e.headers.get_all('Set-Cookie') or [], \
                    json.loads(e.read().decode() or '{}')

        def page(path):
            with urllib.request.urlopen('http://127.0.0.1:%d%s' % (port, path), timeout=60) as r:
                return r.read().decode('utf-8', 'replace')
        try:
            for _ in range(50):
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/nothing' % port, timeout=2)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.1)
            self.must('POST', '/api/settings', {'settings': {'admin_krb': 0, 'portal_krb': 0}})
            for path in ('/admin/?api=kerberos-login', '/?api=kerberos-login'):
                st, hd, _, got = post(path)
                self.assertEqual(st, 404, (path, got))
                self.assertNotIn('WWW-Authenticate', hd)
            self.assertNotIn('id="krb-box"', page('/admin/'))
            self.assertNotIn('id="krb-box"', page('/'))
            # The administration on, the portal off.
            self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
            self.assertIn('id="krb-box"', page('/admin/'))
            self.assertNotIn('id="krb-box"', page('/'))
            st, hd, _, got = post('/admin/?api=kerberos-login')
            self.assertEqual((st, hd.get('WWW-Authenticate')), (401, 'Negotiate'), got)
            self.assertEqual(got.get('code'), 'no_ticket')
            st, hd, cookies, got = post('/admin/?api=kerberos-login', self.neg('jnovak'))
            self.assertEqual(st, 200, got)
            self.assertNotIn('token', got)
            self.assertTrue(any(c.startswith('acme_session=') and 'HttpOnly' in c and
                                'SameSite=Strict' in c for c in cookies), cookies)
            for auth in (self.neg('nogroups'), 'NTLM ' + base64.b64encode(NTLM_NEGOTIATE).decode(),
                         'Negotiate ' + base64.b64encode(ntlm_in_spnego()).decode(),
                         'Negotiate ' + 'A' * 20000, 'Basic dXNlcjpwYXNz'):
                st, hd, cookies, got = post('/admin/?api=kerberos-login', auth)
                self.assertEqual(st, 403, (auth[:20], got))
                self.assertNotIn('WWW-Authenticate', hd)
                self.assertFalse(any(c.startswith('acme_session=') and 'expires' not in c.lower()
                                     for c in cookies))
            st, hd, _, got = post('/?api=kerberos-login', self.neg('falco'))
            self.assertEqual(st, 404, got)
            # The portal on too, by itself on open; "only Windows" there: no password field.
            self.must('POST', '/api/settings', {'settings': {'portal_krb': 1, 'portal_krb_auto': 1}})
            p = page('/')
            self.assertIn('data-part="portal" data-auto="1"', p)
            self.assertIn('id="in-pass"', p)
            st, hd, cookies, got = post('/?api=kerberos-login', self.neg('falco'))
            self.assertEqual(st, 200, got)
            self.assertTrue(any(c.startswith('acme_portal=') for c in cookies), cookies)
            ptok = [c for c in cookies if c.startswith('acme_portal=')][0].split(';')[0].split('=', 1)[1]
            st, got = self.settings(portal=ptok, portal_password_off=1)
            self.assertEqual(st, 200, got)
            p = page('/')
            self.assertNotIn('id="in-pass"', p)
            self.assertIn('data-only="1"', p)
            self.assertIn('id="in-pass"', page('/admin/'))      # the administration keeps it
        finally:
            self.must('POST', '/api/settings', {'settings': {'portal_password_off': 0,
                                                             'portal_krb': 0, 'portal_krb_auto': 0,
                                                             'admin_krb': 0}})
            php.terminate()
            php.wait(10)
            shutil.rmtree(web, ignore_errors=True)

    def test_13_the_command_line_export_and_taken_away(self):
        acme = [sys.executable, os.path.join(ROOT, 'acme.py')]
        got = subprocess.run(acme + ['--kerberos-keytab', os.path.join(self.kdc, 'svc1.keytab'),
                                     '--json'], env=self.env, capture_output=True, text=True,
                             timeout=120)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(json.loads(got.stdout)['entries'][0]['principal'],
                         'HTTP/svc1.corpnet.loc@%s' % REALM)
        got = subprocess.run(acme + ['--kerberos'], env=self.env, capture_output=True, text=True,
                             timeout=120)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('HTTP/svc1.corpnet.loc@%s' % REALM, got.stdout)
        self.assertIn('realm %s' % REALM, got.stdout)
        # The daemon writes the new one out by itself.
        with open(os.path.join(self.kdc, 'svc1.keytab'), 'rb') as f:
            want = f.read()
        for _ in range(80):
            try:
                with open(self.keytab_file(), 'rb') as f:
                    if f.read() == want:
                        break
            except OSError:
                pass
            time.sleep(0.5)
        else:
            self.fail('the keytab put in from the command line was not written out')
        # The configuration with the secrets carries it; without them, only what it holds.
        kt = self.py('print(json.dumps(E.config_export(st, True)["kerberos"]))')
        self.assertEqual(base64.b64decode(kt['keytab']), want)
        whole = self.ok('GET', '/api/export', args={'secrets': '1'})
        bare = self.ok('GET', '/api/export')['config']
        self.assertNotIn('keytab', bare['kerberos'])
        self.assertEqual(bare['kerberos']['entries'][0]['principal'], 'HTTP/svc1.corpnet.loc@%s' % REALM)
        # Taken away: from the database and from the node.
        got = subprocess.run(acme + ['--kerberos-keytab-off', '--yes'], env=self.env,
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        for _ in range(80):
            if not os.path.exists(self.keytab_file()):
                break
            time.sleep(0.5)
        self.assertFalse(os.path.exists(self.keytab_file()))
        v = self.ok('GET', '/api/kerberos')
        self.assertIsNone(v['keytab'])
        # Put back from the exported file: the keytab comes with it.
        st, got = self.call('POST', '/api/import', {'config': whole['bundle'],
                                                    'passphrase': whole['passphrase']}, self.admin)
        self.assertEqual(st, 200, got)
        v = self.ok('GET', '/api/kerberos')
        self.assertEqual(v['keytab']['entries'][0]['principal'], 'HTTP/svc1.corpnet.loc@%s' % REALM)
        self.put_keytab()


if __name__ == '__main__':
    unittest.main()
