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


KRB5_OID = bytes.fromhex('2a864886f712010202')
MSKRB5_OID = bytes.fromhex('2a864882f712010202')      # 1.2.840.48018.1.2.2
SPNEGO_OID = bytes.fromhex('2b0601050502')
REFUSED = 'Windows sign-in refused: '


def spnego(inner, mechs):
    """A NegTokenInit offering `mechs`, `inner` as its mechToken (None: none)."""
    init = der(0x30, der(0xa0, der(0x30, b''.join(der(0x06, m) for m in mechs)))
               + (der(0xa2, der(0x04, inner)) if inner is not None else b''))
    return der(0x60, der(0x06, SPNEGO_OID) + der(0xa0, init))


def b64neg(raw):
    return 'Negotiate ' + base64.b64encode(raw).decode()


def keytab_records(raw):
    """[(principal, enctype, record bytes)] of a keytab - the test's own reading, to make mixed
    ones of: a weak key and another service's name beside the web service's AES keys."""
    out, i = [], 2
    while i + 4 <= len(raw):
        size = int.from_bytes(raw[i:i + 4], 'big', signed=True)
        i += 4
        if size <= 0:
            break
        rec = raw[i:i + size]
        j, count = 2, int.from_bytes(rec[0:2], 'big')
        n = int.from_bytes(rec[j:j + 2], 'big')
        realm = rec[j + 2:j + 2 + n].decode()
        j += 2 + n
        comps = []
        for _ in range(count):
            n = int.from_bytes(rec[j:j + 2], 'big')
            comps.append(rec[j + 2:j + 2 + n].decode())
            j += 2 + n
        j += 4 + 4 + 1
        enc_at = j
        out.append(('/'.join(comps) + '@' + realm, int.from_bytes(rec[j:j + 2], 'big'), rec,
                    enc_at))
        i += size
    return out


def keytab_of(recs):
    return b'\x05\x02' + b''.join(len(r).to_bytes(4, 'big') + r for r in recs)


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

    def events(self, text, session=None):
        got = self.ok('GET', '/api/events', args={'q': text}, session=session)
        return [e.get('words') or '' for e in got.get('events') or got.get('rows') or []]

    def put_keytab(self, name='http.keytab'):
        st, got = self.call('POST', '/api/kerberos', {'action': 'put', 'data': self.keytab_b64(name),
                                                      'name': name}, self.admin)
        self.assertEqual(st, 200, got)
        return got

    def keytab_file(self):
        return os.path.join(self.tmp, 'state', 'kerberos', 'http.keytab')

    def refused(self, part, header, kind, why=None, session=None):
        """A sign-in refused: the caller told only the kind, the reason in Events."""
        st, got = self.krb(part, header, session)
        self.assertEqual(st, 401, got)
        self.assertNotIn('token', got)
        self.assertEqual(got.get('error'), REFUSED + kind, got)
        if why:
            self.assertTrue(any(why in w for w in self.events(why)), why)
        return got

    def restart_daemon(self):
        """The daemon stopped and started again (an upgrade, a failover): the time it was
        started; the caller asks from the first moment it answers."""
        d = type(self).daemon
        d.terminate()
        d.wait(30)
        if d.stdout:
            d.stdout.close()
        old = self.token
        t0 = time.time()
        type(self).daemon = subprocess.Popen([sys.executable, os.path.join(ROOT, 'acme.py'),
                                              '--daemon'], env=self.env, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.STDOUT, cwd=self.tmp)
        return t0, old

    def new_token(self, old):
        tok = ''
        for _ in range(200):
            try:
                with open(os.path.join(self.tmp, 'run', 'api-token')) as f:
                    tok = f.read().strip()
                if tok and tok != old:
                    break
            except OSError:
                pass
            time.sleep(0.02)
        type(self).token = tok or old

    def back_to_passwords(self, part='admin'):
        """Root's way back (acme --set <part>_password_off=0), and the test's sign-ins anew."""
        cli = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--set',
                              '%s_password_off=0' % part], env=self.env, capture_output=True,
                             text=True, timeout=120)
        self.assertEqual(cli.returncode, 0, cli.stdout + cli.stderr)
        for _ in range(40):                 # the daemon reads the settings again within seconds
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            if st == 200:
                break
            time.sleep(0.5)
        self.assertEqual(st, 200, got)
        type(self).admin = got['token']
        type(self).ro = self.login('viewer')

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
        # The caller is told the kind only ("Windows sign-in refused: not allowed"); the reason
        # is in Events, for the administrators.
        cases = [
            ('nogroups', 'none of the groups'),          # known, no role
            ('falco', 'none of the groups'),             # a portal person, no role here
            ('ghost', 'nobody called ghost'),            # not in the directory
            ('pkolar', 'locked'),                        # locked out in AD
            ('gone', 'disabled'),                        # switched off in AD
            ('tester', 'account of this server'),        # a local account of the same name
        ]
        for person, why in cases:
            self.refused('admin', self.neg(person), 'not allowed', why)
        # A ticket for a name that is not in the keytab.
        got = self.refused('admin', self.neg('jnovak', 'other.corpnet.loc'), 'ticket not accepted',
                           'not found in keytab')
        self.assertNotIn('keytab', got['error'])
        # NTLM: bare (in Negotiate and as its own scheme), inside SPNEGO - and a password typed
        # into the browser's own dialog (Basic): no Kerberos ticket at all (1.0.100: a category
        # of its own, so the page tells a computer outside the domain from a refusal).
        for header, why in (('Negotiate ' + base64.b64encode(NTLM_NEGOTIATE).decode(), 'NTLM'),
                            ('NTLM ' + base64.b64encode(NTLM_NEGOTIATE).decode(), 'NTLM'),
                            ('Negotiate ' + base64.b64encode(ntlm_in_spnego()).decode(), 'NTLM'),
                            ('Basic dXNlcjpwYXNz', 'no Negotiate ticket')):
            self.refused('admin', header, 'no Kerberos ticket', why)
        # Garbage, 20 kB: a ticket not accepted.
        for header, why in (('Negotiate ' + base64.b64encode(os.urandom(300)).decode(),
                             'not a Kerberos request that can be read'),
                            ('Negotiate %%%%-not-base64', 'not base64'),
                            ('Negotiate ' + base64.b64encode(os.urandom(15000)).decode(),
                             'not a Kerberos request that can be read')):
            self.refused('admin', header, 'ticket not accepted', why)
        # Another realm only is taken - and the card warns of a realm the directory is not of.
        self.must('POST', '/api/settings', {'settings': {'admin_krb_realm': 'example.com'}})
        self.refused('admin', self.neg('jnovak'), 'not allowed', 'only EXAMPLE.COM signs in here')
        v = self.ok('GET', '/api/kerberos')
        self.assertIn('not the domain of the directory', v['parts']['admin']['realm_warn'])
        self.must('POST', '/api/settings', {'settings': {'admin_krb_realm': ''}})
        v = self.ok('GET', '/api/kerberos')
        self.assertEqual(v['parts']['admin']['realm_warn'], '')
        # The realm as the ticket says it, compared exactly (realms are case-sensitive).
        self.assertEqual(self.py('print(json.dumps(E.krb_split("jnovak@corpnet.loc")))'),
                         ['jnovak', 'corpnet.loc'])
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
        self.refused('admin', header, 'replay', 'was used already')
        # A token the other node took (its row, in the shared database): refused here. The row
        # is the AP-REQ's authenticator, whatever wrapped it.
        header = self.neg('jnovak')
        key = self.py('import base64; print(json.dumps(E.krb_ap_req_key(base64.b64decode(%r))))'
                      % header.split()[1])
        self.py('st.db.run("INSERT INTO meta (k, v) VALUES (?, ?)", (%r, json.dumps([time.time()])));'
                ' print("1")' % ('krbonce:%s@@node2' % key))
        self.refused('admin', header, 'replay')

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
            # The password sign-ins open before are ended with it (test_16).
            st, got = self.call('GET', '/api/auth/whoami', None, self.admin)
            self.assertNotEqual((got.get('who') or {}).get('name'), 'tester', got)
            st, got = self.call('POST', '/api/auth/password', {'old': self.pw, 'new': 'An-0ther-Pass!',
                                                               'again': 'An-0ther-Pass!'}, kerb)
            self.assertEqual(st, 403, got)
            st, got = self.call('POST', '/api/users', {'action': 'add', 'name': 'newone',
                                                       'role': 'readonly', 'password': 'Xx-123456789!'},
                                kerb)
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
            type(self).admin = got['token']
            self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            self.assertEqual(st, 403, got)
        finally:
            # Root's way back: acme --set admin_password_off=0.
            self.back_to_passwords()

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
                self.refused('portal', self.neg(person), 'not allowed', why)
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
        """Switched on by an administrator of the directory with their own portal sign-in made
        with Windows - somebody else's portal sign-in in that browser is no proof."""
        self.put_keytab()
        # Anybody of the directory on the portal: jnovak, an administrator, may sign in there too.
        self.must('POST', '/api/settings', {'settings': {'portal_krb': 1, 'admin_krb': 1,
                                                         'portal_who': 'anyone'}})
        st, got = self.krb('portal', self.neg('falco'))
        self.assertEqual(st, 200, got)
        ptok = got['token']
        st, got = self.krb('portal', self.neg('jnovak'))
        self.assertEqual(st, 200, got)
        mine = got['token']
        st, got = self.krb('admin', self.neg('jnovak'))
        self.assertEqual(st, 200, got)
        kerb = got['token']
        st, got = self.call('POST', '/api/portal/login', {'name': 'falco',
                                                          'password': 'falco-password-1'})
        self.assertEqual(st, 200, got)
        falco_pw = got['token']
        st, got = self.settings(portal_password_off=1)
        self.assertEqual(st, 400, got)
        # tester (an account of this server) with falco's portal sign-in; jnovak with falco's.
        st, got = self.settings(portal=ptok, portal_password_off=1)
        self.assertEqual(st, 400, got)
        st, got = self.settings(session=kerb, portal=ptok, portal_password_off=1)
        self.assertEqual(st, 400, got)
        self.assertIn('same person', got['error'])
        st, got = self.settings(session=kerb, portal=mine, portal_password_off=1)
        self.assertEqual(st, 200, got)
        try:
            st, info = self.call('GET', '/api/portal/info')
            self.assertTrue(info['kerberos']['only'])
            # The portal's password sign-in open before is ended; the ones made with Windows stay.
            st, me = self.call('GET', '/api/portal/me', None, falco_pw)
            self.assertIsNone(me.get('me'), me)
            st, me = self.call('GET', '/api/portal/me', None, ptok)
            self.assertEqual(me['me']['name'], 'falco@corpnet.cz')
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
                                                             'portal_krb': 0, 'admin_krb': 0,
                                                             'portal_who': 'groups'}})

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
            no_ticket = ('NTLM ' + base64.b64encode(NTLM_NEGOTIATE).decode(),
                         'Negotiate ' + base64.b64encode(ntlm_in_spnego()).decode(),
                         'Basic dXNlcjpwYXNz')
            for auth in (self.neg('nogroups'), 'Negotiate ' + 'A' * 20000) + no_ticket:
                st, hd, cookies, got = post('/admin/?api=kerberos-login', auth)
                self.assertEqual(st, 403, (auth[:20], got))
                # No Kerberos ticket at all (NTLM, Basic) is said as such to the page (1.0.100);
                # a refusal of a real ticket, or garbage, is not.
                self.assertEqual(got.get('code'), 'no_ticket' if auth in no_ticket else None,
                                 (auth[:20], got))
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
            # "Only Windows" on the portal by jnovak, an administrator signed in to the portal
            # with Windows too (anybody of the directory may use it, for this).
            self.must('POST', '/api/settings', {'settings': {'portal_who': 'anyone'}})
            st, hd, cookies, got = post('/?api=kerberos-login', self.neg('jnovak'))
            self.assertEqual(st, 200, got)
            ptok = [c for c in cookies if c.startswith('acme_portal=')][0].split(';')[0].split('=', 1)[1]
            st, got = self.krb('admin', self.neg('jnovak'))
            self.assertEqual(st, 200, got)
            st, got = self.settings(session=got['token'], portal=ptok, portal_password_off=1)
            self.assertEqual(st, 200, got)
            p = page('/')
            self.assertNotIn('id="in-pass"', p)
            self.assertIn('data-only="1"', p)
            self.assertIn('id="in-pass"', page('/admin/'))      # the administration keeps it
        finally:
            self.must('POST', '/api/settings', {'settings': {'portal_password_off': 0,
                                                             'portal_krb': 0, 'portal_krb_auto': 0,
                                                             'admin_krb': 0, 'portal_who': 'groups'}})
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

    # ---- the findings of the review (1.0.99) ------------------------------------------------
    def test_14_replay_wrapped_again(self):
        """Finding 1: the cluster's key is the AP-REQ's authenticator - the same request sent
        bare, or in SPNEGO with another list of mechanisms, is the same request on the other
        node (which has only the database)."""
        self.put_keytab()
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
        try:
            inner = base64.b64decode(self.ticket('jnovak', mech='krb5'))
            keys = self.py('import base64; print(json.dumps([E.krb_ap_req_key(base64.b64decode(x)) '
                           'for x in %r]))' % [base64.b64encode(t).decode() for t in (
                               inner, spnego(inner, [KRB5_OID]),
                               spnego(inner, [KRB5_OID, MSKRB5_OID]),
                               spnego(inner, [MSKRB5_OID, KRB5_OID]))])
            self.assertEqual(len(set(keys)), 1, keys)
            st, got = self.krb('admin', b64neg(spnego(inner, [KRB5_OID])))
            self.assertEqual(st, 200, got)
            for again in (inner, spnego(inner, [KRB5_OID, MSKRB5_OID]),
                          spnego(inner, [MSKRB5_OID, KRB5_OID])):
                self.forget_rcache()            # "the other node"
                self.refused('admin', b64neg(again), 'replay')
            # A token that cannot be taken apart is refused before the library is asked.
            self.refused('admin', b64neg(spnego(None, [KRB5_OID])), 'ticket not accepted',
                         'no mechToken')
            # Windows' own form (Microsoft's OID first, the standard inner token): still taken.
            st, got = self.krb('admin', b64neg(spnego(base64.b64decode(
                self.ticket('jnovak', mech='krb5')), [MSKRB5_OID, KRB5_OID])))
            self.assertEqual(st, 200, got)
        finally:
            self.must('POST', '/api/settings', {'settings': {'admin_krb': 0}})

    def test_15_only_windows_from_the_first_moment(self):
        """Finding 2: "only Windows" in effect from the daemon's first answer after a start -
        the keytab's presence read before it serves anybody."""
        self.put_keytab()
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
        st, got = self.krb('admin', self.neg('jnovak'))
        kerb = got['token']
        st, got = self.settings(session=kerb, admin_password_off=1)
        self.assertEqual(st, 200, got)
        try:
            t0, old = self.restart_daemon()
            while time.time() - t0 < 60:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/api/health' % self.port, timeout=2)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.05)
            self.new_token(old)
            seen, first = [], None
            while not seen or time.time() - seen[0][0] < 7:     # past the old window (~6 s)
                st, h = self.call('GET', '/api/health')
                if first is None:
                    first = h.get('kerberos')
                st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
                seen.append((time.time(), st))
            # No password at all with Windows the only way in: tried by itself (1.0.100).
            self.assertEqual(first, {'on': True, 'auto': True, 'only': True})
            self.assertTrue(len(seen) > 5, seen)
            self.assertEqual({x[1] for x in seen}, {403}, seen)
        finally:
            self.back_to_passwords()
            self.must('POST', '/api/settings', {'settings': {'admin_krb': 0}})

    def test_16_only_windows_ends_password_sign_ins(self):
        """Finding 3: switched on, the part's sign-ins made with a password end - the one who
        switched it on (signed in with Windows) and the others made with Windows stay."""
        self.put_keytab()
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
        st, got = self.krb('admin', self.neg('jnovak'))
        kerb = got['token']
        st, got = self.krb('admin', self.neg('edvorak'))
        other_kerb = got['token']
        pw1, pw2 = self.admin, self.login('viewer')
        try:
            st, got = self.settings(session=kerb, admin_password_off=1)
            self.assertEqual(st, 200, got)
            for tok in (pw1, pw2):
                st, got = self.call('GET', '/api/status', None, tok)
                self.assertEqual(st, 401, got)
            for tok in (kerb, other_kerb):
                st, got = self.call('GET', '/api/status', None, tok)
                self.assertEqual(st, 200, got)
            self.assertTrue(any('only Windows now' in w
                                for w in self.events('only Windows now', session=kerb)))
        finally:
            self.back_to_passwords()
            self.must('POST', '/api/settings', {'settings': {'admin_krb': 0}})

    def test_17_kerberos_off_ends_its_sign_ins(self):
        """Finding 4: Kerberos switched off, or the keytab taken away, ends the sign-ins made
        with it - but the one of whoever did it; the portal's GET /api/portal/me too."""
        self.put_keytab()
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
        st, got = self.krb('admin', self.neg('jnovak'))
        mine = got['token']
        st, got = self.krb('admin', self.neg('edvorak'))
        theirs = got['token']
        st, got = self.settings(session=mine, admin_krb=0)
        self.assertEqual(st, 200, got)
        st, got = self.call('GET', '/api/status', None, mine)
        self.assertEqual(st, 200, got)                  # whoever switched it off stays
        st, got = self.call('GET', '/api/status', None, theirs)
        self.assertEqual(st, 401, got)
        # The keytab taken away (by a password sign-in): every sign-in made with Windows ends.
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 1}})
        st, got = self.krb('admin', self.neg('edvorak'))
        theirs = got['token']
        self.must('POST', '/api/kerberos', {'action': 'drop'})
        for tok in (mine, theirs):
            st, got = self.call('GET', '/api/status', None, tok)
            self.assertEqual(st, 401, got)
        st, got = self.call('GET', '/api/status', None, self.admin)
        self.assertEqual(st, 200, got)
        # Ended at the next request even where nothing ended it (a node whose settings came
        # from elsewhere): a sign-in made with Windows, Kerberos off under it.
        self.put_keytab()
        st, got = self.krb('admin', self.neg('edvorak'))
        theirs = got['token']
        self.py('st.save_setting("admin_krb", 0, "root"); '
                'st.set_meta("conf_serial", "%.6f:elsewhere" % time.time()); print(1)')
        for _ in range(40):
            st, got = self.call('GET', '/api/status', None, theirs)
            if st == 401:
                break
            time.sleep(0.5)
        self.assertEqual(st, 401, got)
        # The portal: GET /api/portal/me as portal_me.
        self.must('POST', '/api/settings', {'settings': {'portal_krb': 1}})
        try:
            st, got = self.krb('portal', self.neg('falco'))
            ptok = got['token']
            st, me = self.call('GET', '/api/portal/me', None, ptok)
            self.assertEqual(me['me']['name'], 'falco@corpnet.cz')
            self.must('POST', '/api/settings', {'settings': {'portal_krb': 0}})
            st, me = self.call('GET', '/api/portal/me', None, ptok)
            self.assertIsNone(me.get('me'), me)
            st, x = self.call('GET', '/api/portal/certs', None, ptok)
            self.assertEqual(st, 401, x)
        finally:
            self.must('POST', '/api/settings', {'settings': {'portal_krb': 0, 'admin_krb': 0}})

    def test_18_split_lets_the_portal_sign_in(self):
        """Finding 5: the portal's sign-in with Windows is free while the nodes are apart, as its
        password sign-in (test/test_split.py asks the dispatcher too)."""
        got = self.py('print(json.dumps([E.split_free_path(p) for p in ("/api/portal/kerberos", '
                      '"/api/portal/login", "/api/auth/kerberos")]))')
        self.assertEqual(got, [True, True, True])

    def test_19_import_checks_the_keytab_first(self):
        """Finding 6: a configuration whose keytab would be refused changes nothing at all."""
        self.put_keytab()
        bare = self.ok('GET', '/api/export')['config']
        sets = dict(bare.get('settings') or {})
        was = self.py('print(json.dumps(E.CONFIG.get("site_name")))')
        sets['site_name'] = 'CHANGED-BY-IMPORT'
        with open(os.path.join(self.kdc, 'http.keytab'), 'rb') as f:
            recs = keytab_records(f.read())
        weak = []
        for _p, _enc, rec, at in recs:
            weak.append(rec[:at] + (23).to_bytes(2, 'big') + rec[at + 2:])
        for keytab, why in ((self.keytab_b64('jnovak.keytab'), 'no key of a web service'),
                            (base64.b64encode(keytab_of(weak)).decode(), 'only weak ones')):
            conf = dict(bare, settings=sets, kerberos={'keytab': keytab, 'name': 'x'})
            st, got = self.call('POST', '/api/import', {'config': conf}, self.admin)
            self.assertEqual(st, 400, got)
            self.assertIn(why, got['error'])
            self.assertNotIn('imported before it stopped', got['error'])
            self.assertEqual(self.py('print(json.dumps(E.CONFIG.get("site_name")))'), was)
            v = self.ok('GET', '/api/kerberos')
            self.assertEqual(sorted({e['principal'] for e in v['keytab']['entries']}),
                             ['HTTP/%s@%s' % (HOST, REALM), 'HTTP/node2.corpnet.loc@%s' % REALM])

    def test_20_keytab_keeps_aes_of_http_only(self):
        """Finding 7: of a keytab with RC4 and another service's keys beside the web service's AES
        ones, only those are kept and written out; what was left out is said, on the card too."""
        with open(os.path.join(self.kdc, 'http.keytab'), 'rb') as f:
            good = f.read()
        recs = keytab_records(good)
        with open(os.path.join(self.kdc, 'jnovak.keytab'), 'rb') as f:
            person = keytab_records(f.read())
        _p, _enc, rec, at = recs[0]
        rc4 = rec[:at] + (23).to_bytes(2, 'big') + rec[at + 2:]
        host = rec.replace(b'\x00\x04HTTP', b'\x00\x04host', 1)
        mixed = keytab_of([r for _p, _e, r, _a in recs] + [rc4, host, person[0][2]])
        st, got = self.call('POST', '/api/kerberos', {'action': 'put', 'name': 'mixed.keytab',
                                                      'data': base64.b64encode(mixed).decode()},
                            self.admin)
        self.assertEqual(st, 200, got)
        self.assertIn('left out', got['message'])
        kept = got['view']['keytab']['entries']
        self.assertTrue(all(e['principal'].startswith('HTTP/') and not e['weak'] for e in kept))
        self.assertEqual(len(kept), len(recs))
        dropped = got['view']['keytab']['dropped']
        whys = sorted((d['principal'].split('/')[0].split('@')[0], d['why']) for d in dropped)
        self.assertEqual(whys, [('HTTP', 'a weak key (RC4 or DES)'),
                                ('host', 'not a web service (HTTP/)'),
                                ('jnovak', 'not a web service (HTTP/)')])
        self.assertEqual(self.ok('GET', '/api/kerberos')['keytab']['dropped'], dropped)
        for _ in range(60):
            try:
                with open(self.keytab_file(), 'rb') as f:
                    out = f.read()
                if out == good:
                    break
            except OSError:
                pass
            time.sleep(0.5)
        self.assertEqual(out, good)                     # the AES keys of HTTP/, nothing else
        self.assertTrue(any('left out' in w and 'rc4-hmac' in w
                            for w in self.events('left out')))
        # Nothing left: refused, the keytab before kept.
        st, got = self.call('POST', '/api/kerberos', {'action': 'put', 'name': 'weak.keytab',
                                                      'data': base64.b64encode(keytab_of(
                                                          [rc4, host])).decode()}, self.admin)
        self.assertEqual(st, 400, got)
        self.assertEqual(len(self.ok('GET', '/api/kerberos')['keytab']['entries']), len(recs))
        self.put_keytab()

    def test_21_the_person_of_the_realm(self):
        """Finding 8: the entry found must be of the ticket's realm - a same-named account of
        another domain under a forest-wide base is not that person."""
        self.put_keytab()
        old_dn = 'CN=Outsider,OU=People,' + BASE
        new_dn = 'CN=Outsider,OU=People,DC=child,' + BASE
        entry = mockldap.PEOPLE.pop(old_dn)
        entry = dict(entry, memberOf=[ADMINS, CERT_USERS])
        mockldap.PEOPLE[new_dn] = entry
        mockldap.GROUPS[ADMINS]['member'].append(new_dn)
        mockldap.GROUPS[CERT_USERS]['member'].append(new_dn)
        self.must('POST', '/api/settings', {'settings': {'admin_krb': 1, 'portal_krb': 1}})
        try:
            self.refused('admin', self.neg('outsider'), 'not allowed', 'not of the realm')
            self.refused('portal', self.neg('outsider'), 'not allowed', 'not of the realm')
            st, t = self.call('POST', '/api/kerberos/try', {'part': 'admin',
                                                            'header': self.neg('outsider')},
                              self.admin)
            self.assertEqual((st, t['ok']), (200, False), t)
            self.assertIn('DC=child', t['said'])
            # The people of the realm's own domain still sign in.
            st, got = self.krb('admin', self.neg('jnovak'))
            self.assertEqual(st, 200, got)
        finally:
            mockldap.GROUPS[ADMINS]['member'].remove(new_dn)
            mockldap.GROUPS[CERT_USERS]['member'].remove(new_dn)
            mockldap.PEOPLE.pop(new_dn)
            entry['memberOf'] = []
            mockldap.PEOPLE[old_dn] = entry
            self.must('POST', '/api/settings', {'settings': {'admin_krb': 0, 'portal_krb': 0}})

    def test_22_the_rest(self):
        """The review's remarks: nginx's header room, the page's and the daemon's caps alike."""
        with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as f:
            self.assertIn('large_client_header_buffers 4 64k;', f.read())
        with open(os.path.join(ROOT, 'install.sh')) as f:
            text = f.read()
        self.assertIn("large_client_header_buffers 4 64k;', 1)", text)
        self.assertIn('32k;', text)                      # acme's own of before, raised
        with open(os.path.join(ROOT, 'web', 'acme-api.php')) as f:
            php = f.read()
        caps = self.py('print(json.dumps([E.KRB_HEADER_MAX, E.KRB_TOKEN_MAX]))')
        self.assertIn('strlen($auth) > %d' % caps[0], php)
        # The largest ticket taken fits in the header, and the header in one buffer of nginx's.
        self.assertLessEqual(len('Negotiate ') + 4 * ((caps[1] + 2) // 3), caps[0])
        self.assertLessEqual(len('Authorization: ') + caps[0], 64 * 1024)
        sys.path.insert(0, os.path.join(ROOT, 'deploy'))
        try:
            import acme_web
        finally:
            sys.path.pop(0)
        main = ('server {\n    listen 443 ssl;\n    client_max_body_size 8m;\n'
                '    large_client_header_buffers 4 32k;\n}\n')
        self.assertIn('4 64k;', acme_web.krb_buffers_into(main))
        self.assertNotIn('32k', acme_web.krb_buffers_into(main))


if __name__ == '__main__':
    unittest.main()
