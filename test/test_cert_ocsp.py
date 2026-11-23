#!/usr/bin/env python3
"""The certificate sign-in checked by OCSP and by CRLs read from the directory (1.0.105, as isemon
1.10.348's kit ocsp-ldap-kit).

    python3 test/test_cert_ocsp.py      (or python3 -m unittest test.test_cert_ocsp)

The kit's test PKI (testing/pki_ocsp.sh, inside the test): Corp Root CA and Corp Issuing CA (the
issuing one issued through `openssl ca`, so the root's responder knows it), two real `openssl
ocsp` responders, a forged one (its own key), the http CRLs, and the people of the kit's table:

    alice  good                      bob  revoked (both)          dan  responder dead
    eve    no AIA                    hal  revoked in the CRL only ida  unknown to the responder
    gina   CDP only in the directory (ldap:///...CN=CDP,CN=Public Key Services,...)

test/mockldap.py serves the CDP object, its certificateRevocationList as bytes. A responder is
waited for by its log ("waiting for OCSP client connections") - never probed with a bare TCP
connect, which holds it (it answers one connection at a time) until it times out.

Skipped as a whole where openssl is not there.
"""
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import threading
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)
import mockldap                      # noqa: E402

BASE = 'DC=corpnet,DC=loc'
FULL = 'CN=CERT_SUPPLIER_X,OU=Groups,' + BASE
WATCH = 'CN=CERT_USERS,OU=Groups,' + BASE
REFUSED = 'Certificate sign-in refused: '
CDP_DN = ('CN=Corp Issuing CA,CN=pki,CN=CDP,CN=Public Key Services,CN=Services,'
          'CN=Configuration,' + BASE)
LDAPCDP = ('ldap:///CN=Corp%20Issuing%20CA,CN=pki,CN=CDP,CN=Public%20Key%20Services,CN=Services,'
           'CN=Configuration,DC=corpnet,DC=loc?certificateRevocationList?base?'
           'objectClass=cRLDistributionPoint')

# The kit's testing/pki_ocsp.sh DIR PORT, adapted: the directory's DN is mockldap's domain, alice
# is nested@corpnet.cz (an account of the directory, a full administrator) so she signs in, and a
# forged responder certificate (the same name, its own key) is made beside the real ones.
PKI_SH = r'''#!/bin/bash
set -e
D=$(readlink -f "$1")
P=$2
U="http://127.0.0.1:$P"
LDAPCDP='@LDAPCDP@'
LDAPDER=$(python3 -I -c '
import sys
def tl(t, b):
    n = len(b)
    h = bytes([n]) if n < 128 else (bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 255]))
    return bytes([t]) + h + b
u = sys.argv[1].encode()
print(tl(0x30, tl(0x30, tl(0xa0, tl(0xa0, tl(0x86, u))))).hex().upper())' "$LDAPCDP")
mkdir -p "$D"
cd "$D"
cat > ca.cnf <<EOF
[ca]
default_ca = issuing
[issuing]
dir = $D/db
database = \$dir/index.txt
new_certs_dir = \$dir/new
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $D/issuing.pem
private_key = $D/issuing.key
default_md = sha256
default_days = 365
default_crl_days = 7
policy = anything
copy_extensions = none
unique_subject = no
[rootca]
dir = $D/rootdb
database = \$dir/index.txt
new_certs_dir = \$dir/new
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $D/root.pem
private_key = $D/root.key
default_md = sha256
default_days = 1825
default_crl_days = 30
policy = anything
copy_extensions = none
unique_subject = no
[anything]
commonName = supplied
[root_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[issuing_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:$U/root.crl
authorityInfoAccess = OCSP;URI:http://127.0.0.1:$((P+1))/
[signer]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = OCSPSigning
1.3.6.1.5.5.7.48.1.5 = ASN1:NULL
[person]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:$U/issuing.crl
authorityInfoAccess = OCSP;URI:http://127.0.0.1:$((P+2))/
[person_dead]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:$U/issuing.crl
authorityInfoAccess = OCSP;URI:http://127.0.0.1:$((P+3))/
[person_noaia]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:$U/issuing.crl
[person_ldap]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = DER:$LDAPDER
EOF
mkdir -p db/new rootdb/new www
: > db/index.txt; : > rootdb/index.txt
echo 1000 > db/serial; echo 1000 > db/crlnumber; echo 5000 > rootdb/serial; echo 5000 > rootdb/crlnumber
export UPN=x
openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 \
  -subj "/DC=loc/DC=corpnet/CN=Corp Root CA" -config ca.cnf -extensions root_ext 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout issuing.key -out issuing.csr \
  -subj "/DC=loc/DC=corpnet/CN=Corp Issuing CA" 2>/dev/null
openssl ca -batch -config ca.cnf -name rootca -extensions issuing_ext -in issuing.csr \
  -out issuing.pem -notext >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout ocsp-r.key -out ocsp-r.csr -subj "/CN=Corp Root OCSP" 2>/dev/null
openssl ca -batch -config ca.cnf -name rootca -extensions signer -in ocsp-r.csr -out ocsp-r.pem \
  -notext >/dev/null 2>&1
cat issuing.pem root.pem > cas.pem
openssl req -newkey rsa:2048 -nodes -keyout ocsp-i.key -out ocsp-i.csr -subj "/CN=Corp Issuing OCSP" 2>/dev/null
openssl ca -batch -config ca.cnf -extensions signer -in ocsp-i.csr -out ocsp-i.pem -notext >/dev/null 2>&1
# A forger's responder: the same name, a key and a certificate of its own.
openssl req -x509 -newkey rsa:2048 -nodes -keyout forged.key -out forged.pem -days 30 \
  -subj "/CN=Corp Issuing OCSP" -addext extendedKeyUsage=OCSPSigning 2>/dev/null
person() {   # name upn extensions
  export UPN=$2
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null
  openssl ca -batch -config ca.cnf -extensions "$3" -in "$1.csr" -out "$1.pem" -notext >/dev/null 2>&1
}
person alice nested@corpnet.cz person
person bob bob@corp.example person
person dan dan@corp.example person_dead
person eve eve@corp.example person_noaia
person gina gina@corp.example person_ldap
person hal hal@corp.example person
openssl ca -config ca.cnf -revoke bob.pem -crl_reason keyCompromise >/dev/null 2>&1
cp db/index.txt ocsp-index.txt            # what the responder knows: hal good, ida not at all
person ida ida@corp.example person
openssl ca -config ca.cnf -revoke hal.pem >/dev/null 2>&1
openssl ca -config ca.cnf -gencrl -out issuing.crl.pem >/dev/null 2>&1
openssl crl -in issuing.crl.pem -outform DER -out www/issuing.crl
openssl crl -in issuing.crl.pem -outform DER -out issuing.crl.der
openssl ca -config ca.cnf -name rootca -gencrl -out root.crl.pem >/dev/null 2>&1
openssl crl -in root.crl.pem -outform DER -out www/root.crl
rm -f ./*.csr
'''


def free_base(n=8):
    """A port with the n after it free too (the kit's PORT, PORT+1 ...)."""
    for _ in range(50):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        p = s.getsockname()[1]
        s.close()
        if p + n > 65000:
            continue
        ok = True
        for q in range(p, p + n):
            t = socket.socket()
            try:
                t.bind(('127.0.0.1', q))
            except OSError:
                ok = False
            finally:
                t.close()
        if ok:
            return p
    raise RuntimeError('no free ports')


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


@unittest.skipUnless(shutil.which('openssl'), 'no openssl here')
class CertOcsp(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.ok
    py = TCC.CertsCore.py
    cli = TCC.CertsCore.cli

    # ---- the PKI, the responders, the directory ---------------------------------------------
    @classmethod
    def responder(cls, name, port, index, signer, key, ca):
        log = os.path.join(cls.pki, '%s.log' % name)
        fh = open(log, 'w')
        p = subprocess.Popen(['openssl', 'ocsp', '-port', str(port), '-index', index,
                              '-rsigner', signer, '-rkey', key, '-CA', ca, '-ndays', '1'],
                             cwd=cls.pki, stdout=fh, stderr=subprocess.STDOUT)
        fh.close()
        for _ in range(200):
            with open(log) as f:
                if 'waiting for OCSP client connections' in f.read():
                    break
            if p.poll() is not None:
                raise RuntimeError('openssl ocsp %s ended: %s' % (name, open(log).read()))
            time.sleep(0.05)
        else:
            raise RuntimeError('openssl ocsp %s did not start' % name)
        cls.procs[name] = p
        return p

    @classmethod
    def issuing_up(cls):
        return cls.responder('issuing', cls.P + 2, 'ocsp-index.txt', 'ocsp-i.pem', 'ocsp-i.key',
                             'issuing.pem')

    @classmethod
    def asked_of(cls, name):
        with open(os.path.join(cls.pki, '%s.log' % name)) as f:
            return f.read().count('Received request')

    @classmethod
    def setUpClass(cls):
        cls.pki = tempfile.mkdtemp(prefix='acme-ocsp-pki-')
        cls.P = P = free_base()
        with open(os.path.join(cls.pki, 'pki.sh'), 'w') as f:
            f.write(PKI_SH.replace('@LDAPCDP@', LDAPCDP))
        got = subprocess.run(['bash', os.path.join(cls.pki, 'pki.sh'), cls.pki, str(P)],
                             capture_output=True, text=True, timeout=300)
        if got.returncode:
            raise RuntimeError('pki_ocsp.sh: %s' % got.stderr[-2000:])
        www = os.path.join(cls.pki, 'www')

        class H(_Quiet):
            def __init__(self, *a, **kw):
                http.server.SimpleHTTPRequestHandler.__init__(self, *a, directory=www, **kw)
        cls.www = http.server.ThreadingHTTPServer(('127.0.0.1', P), H)
        threading.Thread(target=cls.www.serve_forever, daemon=True).start()
        cls.procs = {}
        cls.responder('root', P + 1, 'rootdb/index.txt', 'ocsp-r.pem', 'ocsp-r.key', 'root.pem')
        cls.issuing_up()
        # P+3: dan's responder - nobody there.
        cls.responder('forged', P + 4, 'ocsp-index.txt', 'forged.pem', 'forged.key', 'issuing.pem')
        # P+5: "a responder of its own" for every certificate and authority, as an AD CS Online
        # Responder with a revocation configuration of each authority: openssl's answers what
        # its -CA issued, so the question goes to the issuing one, and to the root's when that
        # one does not know the certificate's issuer.
        lock = threading.Lock()

        class Own(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
                with lock:
                    out = b''
                    for port in (P + 2, P + 1):
                        req = urllib.request.Request('http://127.0.0.1:%d/' % port, data=body,
                                                     headers={'Content-Type':
                                                              'application/ocsp-request'})
                        with urllib.request.urlopen(req, timeout=10) as r:
                            out = r.read()
                        said = subprocess.run(['openssl', 'ocsp', '-respin', '/dev/stdin',
                                               '-resp_text', '-noverify'], input=out,
                                              capture_output=True, timeout=30)
                        if b'Cert Status: unknown' not in said.stdout:
                            break
                self.send_response(200)
                self.send_header('Content-Type', 'application/ocsp-response')
                self.send_header('Content-Length', str(len(out)))
                self.end_headers()
                self.wfile.write(out)
        cls.own = http.server.ThreadingHTTPServer(('127.0.0.1', P + 5), Own)
        threading.Thread(target=cls.own.serve_forever, daemon=True).start()
        # The directory: mockldap's people, and the CDP object of AD CS with its CRL as bytes.
        with open(os.path.join(cls.pki, 'issuing.crl.der'), 'rb') as f:
            crl = f.read()
        mockldap.CONFIG_OBJECTS[CDP_DN] = {
            'objectClass': ['top', 'cRLDistributionPoint'], 'cn': ['Corp Issuing CA'],
            'certificateRevocationList': [crl], 'deltaRevocationList': [b'\x00']}
        # ...and the same attribute where no CDP is: never read.
        mockldap.CONFIG_OBJECTS['CN=Decoy,CN=Users,' + BASE] = {
            'objectClass': ['top', 'cRLDistributionPoint'], 'certificateRevocationList': [crl]}
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        os.environ['ACME_CDP_LOOPBACK_OK'] = '1'
        try:
            TCC.CertsCore.setUpClass.__func__(cls)
        finally:
            os.environ.pop('ACME_CDP_LOOPBACK_OK', None)
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        cls.must('POST', '/api/settings', {'settings': {
            'admin_directory': 'corp', 'admin_group_full': FULL, 'admin_group_readonly': WATCH,
            'login_tries': 50, 'admin_certlogin_match': 'compat'}})
        with open(os.path.join(cls.pki, 'cas.pem'), 'rb') as f:
            import base64
            cls.must('POST', '/api/certlogin', {'action': 'put', 'name': 'cas.pem',
                                                'data': base64.b64encode(f.read()).decode()})

    @classmethod
    def tearDownClass(cls):
        try:
            TCC.CertsCore.tearDownClass.__func__(cls)
        finally:
            cls.ldap_stop.set()
            mockldap.CONFIG_OBJECTS.clear()
            for p in cls.procs.values():
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(10)
                    except subprocess.TimeoutExpired:
                        p.kill()
            cls.www.shutdown()
            cls.own.shutdown()
            shutil.rmtree(cls.pki, ignore_errors=True)

    @classmethod
    def must(cls, method, path, body=None, session=None):
        st, got = cls.call(method, path, body, session or cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def setUp(self):
        self.call('POST', '/api/lockouts', {'action': 'clear_all'}, self.admin)

    # ---- helpers ----------------------------------------------------------------------------
    def pem(self, name):
        with open(os.path.join(self.pki, name + '.pem')) as f:
            return f.read()

    def on(self, **kv):
        self.must('POST', '/api/settings', {'settings': kv})

    def settings(self, **kv):
        return self.call('POST', '/api/settings', {'settings': kv}, self.admin)

    def sign(self, name):
        import secrets
        return self.call('POST', '/api/auth/cert', {'cert': self.pem(name),
                                                    'once': secrets.token_hex(16)})

    def events(self, text):
        got = self.ok('GET', '/api/events', args={'q': text})
        return [e.get('words') or '' for e in got.get('events') or got.get('rows') or []]

    def refused(self, name, kind, why=None):
        st, got = self.sign(name)
        self.assertIn(st, (401, 503), (name, got))
        self.assertNotIn('token', got)
        self.assertEqual(got.get('error'), REFUSED + kind, (name, got))
        # The person is told little: nothing of the responder, the certificate or the CRL.
        self.assertNotRegex(json.dumps(got), r'CN=|corpnet|OCSP|http://|serial|127\.0')
        if why:
            self.assertTrue(any(why in w for w in self.events(why)), (name, why))
        return got

    def engine(self, body, **kv):
        """Code run with the engine against the kit's PKI: `P` its folder, go(name, mode='off',
        crl=True, url='', ldap=None) 'OK ' + how each was checked, or the kind refused (WHY[name]
        the words)."""
        head = ('import os, subprocess\nos.environ["ACME_CDP_LOOPBACK_OK"] = "1"\n'
                'P = %r\nPORT = %d\nWHY = {}\n'
                'def go(n, mode="off", crl=True, url="", ldap=None):\n'
                '    try:\n'
                '        f = E.cl_check(open(os.path.join(P, n + ".pem")).read(), '
                'os.path.join(P, "cas.pem"), crl=crl, ocsp=mode, ocsp_url=url, ldap=ldap)\n'
                '        return "OK " + "+".join(f["revocation"])\n'
                '    except E.CertRefused as e:\n'
                '        WHY[n] = e.why\n'
                '        return e.kind\n' % (self.pki, self.P))
        return self.py(head + body % kv)

    def ask(self, act, key=''):
        x = self.must('POST', '/api/certlogin', {'action': 'ocsp_' + act, 'url': key})
        self.assertTrue(x['id'] and x['nodes'], x)
        for _ in range(120):
            got = self.must('POST', '/api/certlogin', {'action': 'result', 'id': x['id']})['nodes']
            if all(got.get(n) for n in x['nodes']):
                return x, got
            time.sleep(0.5)
        self.fail('no answer to %s: %s' % (act, got))

    def answers(self):
        return self.must('GET', '/api/certlogin', session=self.ro)['ocsp_answers']

    # ---- the tests --------------------------------------------------------------------------
    def test_01_off_by_default_and_the_settings(self):
        self.assertEqual(self.py(
            'print(json.dumps([E.DEFAULTS[p + k] for p in ("admin", "portal") for k in '
            '("_certlogin_ocsp", "_certlogin_ocsp_url", "_certlogin_crl_ldap")]))'),
            ['off', '', 0, 'off', '', 0])
        # The responder's address: the same guards as a CRL's, on save.
        for bad in ('http://169.254.169.254/latest', 'https://pki.corp.example/ocsp',
                    'http://user:password@pki.corp.example/ocsp', 'ldap:///CN=x',
                    'http://metadata.google.internal/x', 'http://[fe80::1]/'):
            st, got = self.settings(admin_certlogin_ocsp_url=bad)
            self.assertEqual(st, 400, (bad, got))
            self.assertIn('admin_certlogin_ocsp_url', got.get('error', ''))
        st, got = self.settings(admin_certlogin_ocsp='sometimes')
        self.assertEqual(st, 400, got)
        st, got = self.settings(portal_certlogin_crl_ldap=2)
        self.assertEqual(st, 400, got)
        # Loopback: refused wherever ACME_CDP_LOOPBACK_OK is not set (the tests' alone).
        got = self.py('import os\nos.environ.pop("ACME_CDP_LOOPBACK_OK", None)\nout = []\n'
                      'for u in ("http://127.0.0.1:8080/", "http://pki.corp.example/ocsp"):\n'
                      '    try:\n'
                      '        E.check_setting("admin_certlogin_ocsp_url", u); out.append("ok")\n'
                      '    except E.BadSetting as e:\n'
                      '        out.append(str(e))\n'
                      'print(json.dumps(out))')
        self.assertIn('admin_certlogin_ocsp_url', got[0])
        self.assertEqual(got[1], 'ok')
        st, got = self.settings(admin_certlogin_ocsp_url='http://pki.corp.example/ocsp',
                                admin_certlogin_ocsp='first', admin_certlogin_crl_ldap=1)
        self.assertEqual(st, 200, got)
        try:
            v = self.must('GET', '/api/certlogin', session=self.ro)
            p = v['parts']['admin']
            self.assertEqual((p['ocsp'], p['ocsp_url'], p['ocsp_url_ok'], p['crl_ldap']),
                             ('first', 'http://pki.corp.example/ocsp', True, True))
            self.assertEqual((v['parts']['portal']['ocsp'], v['parts']['portal']['crl_ldap']),
                             ('off', False))
            # Signed settings (db_guard), in a pane, with a name and words of help.
            got = self.py('print(json.dumps([[k in E.DBGUARD_SETTINGS for k in ks], '
                          '[k in E.PANES["admincert"] + E.PANES["portalcert"] for k in ks], '
                          '[bool(E.NAMES.get(k)) and bool(E.SAYS.get(k)) for k in ks], '
                          'E.ONLY_WHEN["admin_certlogin_ocsp_url"]]))'.replace(
                              'ks', '[p + k for p in ("admin_", "portal_") for k in '
                              '("certlogin_ocsp", "certlogin_ocsp_url", "certlogin_crl_ldap")]'))
            self.assertTrue(all(got[0]) and all(got[1]) and all(got[2]), got)
            self.assertEqual(got[3], ['admin_certlogin_ocsp', 'off-not'])
        finally:
            self.on(admin_certlogin_ocsp_url='', admin_certlogin_ocsp='off',
                    admin_certlogin_crl_ldap=0)

    def test_02_the_people_by_mode(self):
        """The kit's table: each person in each mode."""
        got = self.engine('''
out = {}
for who in ("alice", "bob", "dan", "eve", "hal", "ida"):
    for mode in ("off", "first", "only", "both"):
        E.CL_OCSP_CACHE.clear()
        out[who + ":" + mode] = go(who, mode)
out["why"] = WHY
print(json.dumps(out))
''')
        want = {
            'alice': ['OK crl', 'OK ocsp+ocsp', 'OK ocsp+ocsp', 'OK ocsp+crl+ocsp+crl'],
            'bob': ['revoked', 'revoked', 'revoked', 'revoked'],
            'dan': ['OK crl', 'OK crl+ocsp', 'unavailable', 'unavailable'],
            'eve': ['OK crl', 'OK crl+ocsp', 'unavailable', 'OK crl+ocsp+crl'],
            'hal': ['revoked', 'OK ocsp+ocsp', 'OK ocsp+ocsp', 'revoked'],
            'ida': ['OK crl', 'certificate', 'certificate', 'certificate']}
        for who, modes in want.items():
            self.assertEqual([got['%s:%s' % (who, m)] for m in ('off', 'first', 'only', 'both')],
                             modes, who)
        self.assertIn('unknown', got['why']['ida'])

    def test_03_off_as_before(self):
        """off: no responder asked, -crl_check_all once - the CRLs as before; CRLs off and OCSP
        first: no answer, no sign-in."""
        before = self.asked_of('issuing')
        got = self.engine('''
E.CL_OCSP_CACHE.clear()
print(json.dumps([go("alice"), go("hal"), go("eve", crl=False), len(E.CL_OCSP_CACHE),
                  go("dan", "first", crl=False), go("eve", "first", crl=False), WHY]))
''')
        self.assertEqual(got[:4], ['OK crl', 'revoked', 'OK ', 0])
        self.assertEqual(got[4:6], ['unavailable', 'unavailable'])
        self.assertIn('CRLs are off', got[6]['eve'])
        self.assertEqual(self.asked_of('issuing'), before)

    def test_04_forged_and_a_responder_of_its_own(self):
        own, forged = 'http://127.0.0.1:%d/' % (self.P + 5), 'http://127.0.0.1:%d/' % (self.P + 4)
        got = self.engine('''
E.CL_OCSP_CACHE.clear()
out = [go("alice", "only", url=%(forged)r), go("alice", "first", url=%(forged)r)]
E.CL_OCSP_CACHE.clear()
out += [go("eve", "only", url=%(own)r), go("dan", "only", url=%(own)r), go("bob", "only", url=%(own)r)]
out.append(sorted({c["url"] for c in E.CL_OCSP_CACHE.values()}))
out.append(WHY)
print(json.dumps(out))
''', forged=forged, own=own)
        # Signed by a key of the forger's: no answer - only refused, first by the CRL.
        self.assertEqual(got[0], 'unavailable')
        self.assertIn('signature is not good by the authorities put in', got[6]['alice'])
        self.assertEqual(got[1], 'OK crl+crl')
        # A responder of its own for everybody: eve (no AIA) and dan (a dead one) asked there.
        self.assertEqual(got[2:5], ['OK ocsp+ocsp', 'OK ocsp+ocsp', 'revoked'])
        self.assertEqual(got[5], [own])

    def test_05_the_cache(self):
        """Ten minutes (or the next update), a minute after a failure, the last good answer
        kept until its next update while the responder is stopped - on a fake clock."""
        pid = self.procs['issuing'].pid
        try:
            got = self.engine('''
import signal
real = time.time
clock = [0]
E.time.time = lambda: real() + clock[0]
def log():
    return open(os.path.join(P, "issuing.log")).read().count("Received request")
E.CL_OCSP_CACHE.clear()
go("bob", "first")
out = {"now": E.cl_ocsp_now()}
E.CL_OCSP_CACHE.clear()
out.update(a1=go("alice", "only"), n1=log())
out["a2"] = go("alice", "only"); out["n2"] = log()                 # kept: not asked
clock[0] = 601
out["a3"] = go("alice", "only"); out["n3"] = log()                 # ten minutes: asked again
os.kill(%(pid)d, signal.SIGTERM)
time.sleep(1)
clock[0] = 1300
out["a4"] = go("alice", "only")                                     # stopped: the last good one
key = [k for k, c in E.CL_OCSP_CACHE.items() if c["subject"] == "CN=alice"][0]
out["kept"] = {k: E.CL_OCSP_CACHE[key][k] for k in ("status", "err")}
out["t1"] = E.CL_OCSP_CACHE[key]["tried"]
clock[0] = 1330
out["a5"] = go("alice", "only")
out["t2"] = E.CL_OCSP_CACHE[key]["tried"]                           # not asked within a minute
clock[0] = 1400
out["a6"] = go("alice", "only")
out["t3"] = E.CL_OCSP_CACHE[key]["tried"]
clock[0] = E.CL_OCSP_CACHE[key]["next"] - real() + 5                # its next update passed
out["a7"] = go("alice", "only")
out["dead"] = E.CL_OCSP_CACHE[key]["status"]
out["why"] = WHY
print(json.dumps(out))
''', pid=pid)
        finally:
            try:
                self.procs['issuing'].wait(10)
            except subprocess.TimeoutExpired:
                self.procs['issuing'].kill()
            self.issuing_up()
        self.assertEqual([got[k] for k in ('a1', 'a2', 'a3')], ['OK ocsp+ocsp'] * 3)
        self.assertEqual(got['n1'], got['n2'])
        self.assertEqual(got['n3'], got['n2'] + 1)
        self.assertEqual(got['a4'], 'OK ocsp+ocsp')
        self.assertEqual(got['kept']['status'], 'good')
        self.assertTrue(got['kept']['err'])
        self.assertEqual(got['a5'], 'OK ocsp+ocsp')
        self.assertEqual(got['t1'], got['t2'])
        self.assertGreater(got['t3'], got['t2'])
        self.assertEqual(got['a7'], 'unavailable')
        self.assertEqual(got['dead'], '')
        self.assertTrue(got['now'] and all(set(c) == set(
            ('key', 'url', 'subject', 'serial', 'issuer', 'status', 'at', 'this', 'next', 'err',
             'err_at', 'revoked_at', 'reason', 'responder', 'size')) for c in got['now']), got['now'])
        self.assertNotIn('BEGIN CERTIFICATE', json.dumps(got['now']))
        bob = [c for c in got['now'] if c['subject'] == 'CN=bob'][0]
        self.assertEqual((bob['status'], bob['reason']), ('revoked', 'keyCompromise'))
        self.assertEqual(bob['responder'], 'CN=Corp Issuing OCSP')
        # 200 at most: one more answer past them and the cache starts again.
        got = self.engine('''
for i in range(200):
    E.CL_OCSP_CACHE["x%%d" %% i] = {"key": "x%%d" %% i, "url": "u", "status": ""}
go("alice", "only")
print(json.dumps(len(E.CL_OCSP_CACHE)))
''')
        self.assertLessEqual(got, 200)

    def test_06_crls_from_the_directory(self):
        """gina names her CRL in the directory only: refused while it is off; read with the
        directory's own connection while on - base scope, its CDP object, its CRL attribute."""
        mockldap.ASKED.clear()
        got = self.engine('''
st_ = st
d = E.Daemon(st_, serve=False)
d.reload_directories()
off = E.cl_ldap_for(d, st_, "admin")
E.CONFIG["admin_certlogin_crl_ldap"] = 1
rd = E.cl_ldap_for(d, st_, "admin")
E.CL_CRL_CACHE.clear()
out = [off is None, go("gina"), go("gina", ldap=rd), go("gina", "first", ldap=rd),
       sorted(E.CL_CRL_CACHE), [c.get("via") for c in E.cl_crls_now()]]
try:
    rd("ldap:///CN=Decoy,CN=Users,DC=corpnet,DC=loc?certificateRevocationList?base")
    out.append("read")
except ValueError as e:
    out.append(str(e))
out.append(E.cl_ldap_name(%(url)r))
out.append(WHY)
print(json.dumps(out))
''', url=LDAPCDP)
        self.assertTrue(got[0])
        self.assertEqual(got[1], 'certificate')
        self.assertIn('names no CRL over http', got[8]['gina'])
        self.assertEqual(got[2:4], ['OK crl', 'OK crl+ocsp'])
        self.assertIn(LDAPCDP, got[4])
        self.assertIn('ldap', got[5])
        self.assertIn('not a CDP object', got[6])
        self.assertEqual(got[7], 'Corp Issuing CA')
        # What the directory was asked: the CDP object alone, base scope, its CRL attribute.
        cdp = [a for a in mockldap.ASKED if 'CN=CDP' in a[0]]
        self.assertTrue(cdp, mockldap.ASKED)
        self.assertTrue(all(a == (CDP_DN, 0, ['certificateRevocationList']) for a in cdp), cdp)
        self.assertFalse([a for a in mockldap.ASKED if 'Decoy' in a[0]])
        # The parser's guard: only CDP objects of the configuration, base scope, CRL attributes.
        got = self.py('print(json.dumps([E.cl_ldap_cdp(u) for u in %r]))' % ([
            LDAPCDP, LDAPCDP.replace('certificateRevocationList', 'deltaRevocationList;binary'),
            LDAPCDP.replace('certificateRevocationList', 'userPassword'),
            LDAPCDP.replace('certificateRevocationList', 'unicodePwd'),
            LDAPCDP.replace('?base?', '?sub?'),
            'ldap:///CN=Administrator,CN=Users,DC=corpnet,DC=loc?certificateRevocationList?base',
            'ldap://evil.example/CN=x,CN=CDP,CN=Public%20Key%20Services,CN=Services,'
            'CN=Configuration,DC=corpnet,DC=loc?certificateRevocationList?base',
            'http://127.0.0.1/x.crl'],))
        self.assertEqual(got[0], [CDP_DN, 'certificateRevocationList'])
        self.assertEqual(got[1], [CDP_DN, 'deltaRevocationList'])
        self.assertEqual(got[2:6], [None] * 4)
        # A host in the address is taken as text only: the DN is read with acme's connection.
        self.assertEqual(got[6][1], 'certificateRevocationList')
        self.assertIsNone(got[7])

    def test_07_the_card_the_asks_and_the_person(self):
        self.on(admin_certlogin=1, admin_certlogin_ocsp='first', admin_certlogin_crl_ldap=1)
        try:
            self.ask('clear')
            st, got = self.sign('alice')
            self.assertEqual(st, 200, got)
            self.assertEqual(got['who']['name'], 'nested')
            # The person is told little; the reason goes to Events.
            self.refused('bob', 'revoked', 'the OCSP responder says (keyCompromise')
            self.refused('ida', 'certificate not accepted', 'does not know the certificate')
            self.on(admin_certlogin_ocsp='only')
            self.refused('dan', 'not available just now', 'gave no answer')
            self.refused('eve', 'not available just now', 'names no OCSP responder')
            self.on(admin_certlogin_ocsp='first')
            # gina: her CRL read from the directory, then not one of the directory's people.
            self.refused('gina', 'not allowed')
            v = self.must('GET', '/api/certlogin', session=self.ro)
            self.assertNotIn('BEGIN CERTIFICATE', json.dumps(v))
            rows = {c['subject']: c for c in v['ocsp_answers']}
            for who in ('CN=alice', 'CN=bob', 'CN=ida', 'CN=dan'):
                self.assertIn(who, rows)
            self.assertEqual(rows['CN=bob']['status'], 'revoked')
            self.assertEqual(rows['CN=ida']['status'], 'unknown')
            self.assertEqual(rows['CN=dan']['status'], '')
            self.assertTrue(rows['CN=dan']['err'])
            self.assertTrue(any('Corp Issuing CA' in r['subject'] and 'Corp Root CA' in r['issuer']
                                for r in v['ocsp_answers']))
            self.assertEqual([n['node'] for n in rows['CN=alice']['nodes']], ['testnode'])
            ldap_rows = [c for c in v['crls'] if c['via'] == 'ldap']
            self.assertEqual([(c['url'], c['name'], c['ok']) for c in ldap_rows],
                             [(LDAPCDP, 'Corp Issuing CA', True)])
            # The node's state: facts only, never a certificate or a CRL.
            for _ in range(40):
                state = self.py('print(json.dumps(E.cl_node_state(st, "testnode")))')
                if state.get('ocsp'):
                    break
                time.sleep(0.5)
            self.assertTrue(state.get('ocsp'), state)
            self.assertNotRegex(json.dumps(state), r'BEGIN (CERTIFICATE|X509 CRL)|_pem|_ipem')
            # Only a full administrator; a key not kept is 404.
            for who in (self.login('viewer'), self.login('certer')):
                for act in ('ocsp_fetch', 'ocsp_clear'):
                    st, got = self.call('POST', '/api/certlogin', {'action': act}, who)
                    self.assertEqual(st, 403, got)
            st, got = self.call('POST', '/api/certlogin', {'action': 'ocsp_fetch',
                                                           'url': 'http://x/|CN=y|01'}, self.admin)
            self.assertEqual(st, 404, got)
            # Ask again: every responder; dan's does not answer.
            x, got = self.ask('fetch')
            ans = got['testnode']
            self.assertFalse(ans['ok'])
            bad = [r for r in ans['crls'] if not r['ok']]
            self.assertEqual({r['url'] for r in bad}, {'http://127.0.0.1:%d/' % (self.P + 3)})
            self.assertTrue(any(r['status'] == 'revoked' for r in ans['crls']))
            self.assertTrue(any('asked every OCSP responder' in w
                                for w in self.events('asked every OCSP responder')))
            # One row cleared, then all (each written to Events).
            key = rows['CN=alice']['key']
            x, got = self.ask('clear', key)
            self.assertEqual([r['key'] for r in got['testnode']['crls']], [key])
            self.assertNotIn(key, [r['key'] for r in self.answers()])
            self.assertTrue(any('cleared an OCSP answer' in w
                                for w in self.events('cleared an OCSP answer')))
            self.ask('clear')
            self.assertEqual(self.answers(), [])
            self.assertTrue(any('cleared the OCSP answers' in w
                                for w in self.events('cleared the OCSP answers')))
            st, got = self.sign('alice')
            self.assertEqual(st, 200, got)
        finally:
            self.on(admin_certlogin=0, admin_certlogin_ocsp='off', admin_certlogin_crl_ldap=0)

    def test_08_the_command_line(self):
        self.on(admin_certlogin=1, admin_certlogin_ocsp='first')
        try:
            self.assertEqual(self.sign('alice')[0], 200)
            self.refused('bob', 'revoked')
            for _ in range(60):          # the daemon says its answers within 15 s (cl_tick)
                got = self.cli('--cert-login-ocsp')
                if 'CN=bob' in got.stdout:
                    break
                time.sleep(1)
            self.assertEqual(got.returncode, 0, got.stderr)
            self.assertIn('OCSP for the administration: first', got.stdout)
            self.assertIn('CN=bob  REVOKED', got.stdout)
            self.assertIn('signed by CN=Corp Issuing OCSP', got.stdout)
            v = json.loads(self.cli('--cert-login-ocsp', '--json').stdout)
            self.assertEqual(v['ocsp']['admin'], 'first')
            self.assertTrue(any(a['subject'] == 'CN=alice' and a['status'] == 'good'
                                for a in v['answers']), v)
            self.assertNotIn('BEGIN CERTIFICATE', json.dumps(v))
            got = self.cli('--cert-login-ocsp-fetch')
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
            self.assertIn('testnode', got.stdout)
            self.assertIn('answered', got.stdout)
            got = self.cli('--cert-login-ocsp-fetch', 'http://x/|CN=y|01')
            self.assertNotEqual(got.returncode, 0)
            self.assertIn('no OCSP answer of that', got.stderr)
            got = self.cli('--cert-login-ocsp-clear')
            self.assertNotEqual(got.returncode, 0)                 # asks; --yes
            got = self.cli('--cert-login-ocsp-clear', '--yes')
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
            self.assertIn('cleared', got.stdout)
            got = self.cli('--set', 'admin_certlogin_ocsp=both')
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
            got = self.cli('--set', 'admin_certlogin_ocsp_url=https://x.example/')
            self.assertNotEqual(got.returncode, 0)
        finally:
            self.on(admin_certlogin=0, admin_certlogin_ocsp='off')


# ---- hunt O (1.0.106): what a security review of the revocation checks found -----------------------
HUNT_O = r"""
import datetime, hashlib, http.server, json, os, sys, threading, time
os.environ['ACME_CDP_LOOPBACK_OK'] = '1'
sys.path.insert(0, sys.argv[2])
from acmelib import engine as E
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

P = sys.argv[1]
NOW = datetime.datetime.now(datetime.timezone.utc)
D = datetime.timedelta
SRV = http.server.ThreadingHTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler)
PORT = SRV.server_address[1]
U = 'http://127.0.0.1:%d' % PORT
FILES, HITS, OCSP = {}, {}, {}


def key():
    return ec.generate_private_key(ec.SECP256R1())


def name(cn, dc=True):
    return x509.Name(([x509.NameAttribute(NameOID.DOMAIN_COMPONENT, 'loc')] if dc else []) +
                     [x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subj, pub, iss, ikey, ca=False, days=(-1, 300), aki=None, ocsp_path='ocsp', cdp='i.crl',
         fresh=None, eku=None):
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(iss).public_key(pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(NOW + D(days=days[0])).not_valid_after(NOW + D(days=days[1]))
         .add_extension(x509.BasicConstraints(ca, None), True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), False))
    if aki is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(aki), False)
    if ca:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False,
                                          False), True)
    else:
        b = (b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False,
                                           False), True)
             .add_extension(x509.ExtendedKeyUsage(eku or [ExtendedKeyUsageOID.CLIENT_AUTH]), False)
             .add_extension(x509.SubjectAlternativeName([x509.OtherName(
                 x509.ObjectIdentifier('1.3.6.1.4.1.311.20.2.3'),
                 b'\x0c' + bytes([len(subj.rfc4514_string().split('=')[-1] + '@corp.example')]) +
                 (subj.rfc4514_string().split('=')[-1] + '@corp.example').encode())]), False))
    if cdp:
        b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            [x509.UniformResourceIdentifier('%s/%s' % (U, cdp))], None, None, None)]), False)
    if fresh:
        b = b.add_extension(x509.FreshestCRL([x509.DistributionPoint(
            [x509.UniformResourceIdentifier('%s/%s' % (U, fresh))], None, None, None)]), False)
    if ocsp_path:
        b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier('%s/%s' % (U, ocsp_path)))]), False)
    return b.sign(ikey, hashes.SHA256())


def pem(*cs):
    return ''.join(c.public_bytes(serialization.Encoding.PEM).decode() for c in cs)


def crl(ca, k, number, revoked=(), delta_base=None, fresh=None):
    b = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
         .last_update(NOW - D(minutes=5)).next_update(NOW + D(days=1))
         .add_extension(x509.CRLNumber(number), False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(k.public_key()), False))
    if delta_base is not None:
        b = b.add_extension(x509.DeltaCRLIndicator(delta_base), True)
    if fresh:
        b = b.add_extension(x509.FreshestCRL([x509.DistributionPoint(
            [x509.UniformResourceIdentifier('%s/%s' % (U, fresh))], None, None, None)]), False)
    for c in revoked:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(
            c.serial_number).revocation_date(NOW - D(minutes=1)).build())
    return b.sign(k, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


rk = key()
root = cert(name('Corp Root CA'), rk.public_key(), name('Corp Root CA'), rk, ca=True, cdp=None,
            ocsp_path=None)
k1 = key()
ca1 = cert(name('Corp Issuing CA'), k1.public_key(), root.subject, rk, ca=True,
           aki=rk.public_key(), cdp='root.crl', ocsp_path='ocsp-root')
alice = cert(name('alice', False), key().public_key(), ca1.subject, k1, aki=k1.public_key())
bob = cert(name('bob', False), key().public_key(), ca1.subject, k1, aki=k1.public_key())
# the issuing authority renewed with a new key (AD CS keeps its name): the old one put in first
k2 = key()
ca2 = cert(name('Corp Issuing CA'), k2.public_key(), root.subject, rk, ca=True,
           aki=rk.public_key(), cdp='root.crl', ocsp_path='ocsp-root')
carol = cert(name('carol', False), key().public_key(), ca2.subject, k2, aki=k2.public_key(),
             cdp='i2.crl')
dora = cert(name('dora', False), key().public_key(), ca2.subject, k2, aki=k2.public_key(),
            cdp='i2.crl')
# ...and the old one run out (renewed long ago): never of the new one's chain
k0 = key()
ca0 = cert(name('Corp Issuing CA'), k0.public_key(), root.subject, rk, ca=True,
           aki=rk.public_key(), days=(-900, -10), cdp='root.crl', ocsp_path='ocsp-root')
# the delta's people
dk = key()
cad = cert(name('Corp Delta CA'), dk.public_key(), root.subject, rk, ca=True,
           aki=rk.public_key(), cdp='root.crl', ocsp_path=None)
eric = cert(name('eric', False), key().public_key(), cad.subject, dk, aki=dk.public_key(),
            cdp='d.crl', fresh='d-delta.crl', ocsp_path=None)
for n, v in (('cas.pem', pem(ca1, root)), ('cas-renewed.pem', pem(ca0, ca1, ca2, root)),
             ('cas-delta.pem', pem(cad, root))):
    with open(os.path.join(P, n), 'w') as fh:
        fh.write(v)
FILES['root.crl'] = crl(root, rk, 1)
FILES['i.crl'] = crl(ca1, k1, 1, [bob])
FILES['i2.crl'] = crl(ca2, k2, 1, [carol])
KEYS = {}
for c, k, rv in ((ca1, k1, {bob.serial_number}), (ca2, k2, {carol.serial_number}),
                 (root, rk, set())):
    # the issuer key hash: SHA-1 of its public key's bits (an EC point, uncompressed)
    raw = c.public_key().public_bytes(serialization.Encoding.X962,
                                      serialization.PublicFormat.UncompressedPoint)
    KEYS[hashlib.sha1(raw).digest()] = (c, k, rv)
MODE = {'how': 'real', 'asked': []}
forger = key()
forged = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(
    NameOID.COMMON_NAME, 'Response verify OK')])).issuer_name(x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, 'Response verify OK')])).public_key(forger.public_key())
    .serial_number(1).not_valid_before(NOW - D(days=1)).not_valid_after(NOW + D(days=30))
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False)
    .sign(forger, hashes.SHA256()))


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        name = self.path.lstrip('/')
        HITS[name] = HITS.get(name, 0) + 1
        if name == 'slow.crl':
            time.sleep(1.5)
        body = FILES.get(name)
        if body is None:
            self.send_response(500)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        req = ocsp.load_der_ocsp_request(self.rfile.read(int(self.headers.get('Content-Length') or 0)))
        c, k, rv = KEYS[req.issuer_key_hash]
        MODE['asked'].append((req.serial_number, c.serial_number))
        st = ocsp.OCSPCertStatus.REVOKED if req.serial_number in rv else ocsp.OCSPCertStatus.GOOD
        this, nxt = NOW - D(minutes=1), NOW + D(hours=1)
        if MODE['how'] == 'stale':
            this, nxt = NOW - D(days=365), None
        elif MODE['how'] == 'fresh-no-next':
            nxt = None
        elif MODE['how'] == 'expired':
            this, nxt = NOW - D(hours=2), NOW - D(hours=1)
        b = ocsp.OCSPResponseBuilder().add_response_by_hash(
            req.issuer_name_hash, req.issuer_key_hash, req.serial_number, req.hash_algorithm,
            ocsp.OCSPCertStatus.GOOD if MODE['how'] == 'forged' else st, this, nxt,
            NOW if st == ocsp.OCSPCertStatus.REVOKED and MODE['how'] != 'forged' else None, None)
        if MODE['how'] == 'forged':
            resp = b.responder_id(ocsp.OCSPResponderEncoding.NAME, forged).certificates(
                [forged]).sign(forger, hashes.SHA256())
        else:
            resp = b.responder_id(ocsp.OCSPResponderEncoding.HASH, c).sign(k, hashes.SHA256())
        body = resp.public_bytes(serialization.Encoding.DER)
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


SRV.RequestHandlerClass = H
SRV.daemon_threads = True
threading.Thread(target=SRV.serve_forever, daemon=True).start()
OUT = {}


def go(c, cas='cas.pem', mode='off', crl=True):
    E.CL_OCSP_CACHE.clear()
    E.CL_CRL_CACHE.clear()
    try:
        f = E.cl_check(pem(c), os.path.join(P, cas), crl=crl, ocsp=mode)
        return 'OK ' + '+'.join(f['revocation'])
    except E.CertRefused as e:
        OUT.setdefault('why', {})['%s-%s' % (c.subject.rfc4514_string(), mode)] = e.why
        return e.kind


# 1. a forged answer from a responder named "Response verify OK"
MODE['how'] = 'forged'
OUT['forged'] = {m: go(bob, mode=m) for m in ('first', 'only', 'both')}
OUT['forged_alice_only'] = go(alice, mode='only')
OUT['forged_why'] = dict(OUT.get('why') or {})
MODE['how'] = 'real'
OUT['real'] = {m: [go(alice, mode=m), go(bob, mode=m)] for m in ('first', 'only', 'both')}
# 2b. renewed with the SAME key (AD CS): the old one, run out, put in first - the one valid now
ca1old = cert(name('Corp Issuing CA'), k1.public_key(), root.subject, rk, ca=True,
              aki=rk.public_key(), days=(-900, -10), cdp='root.crl', ocsp_path='ocsp-root')
with open(os.path.join(P, 'cas-samekey.pem'), 'w') as fh:
    fh.write(pem(ca1old, ca1, root))
OUT['samekey_chain'] = [c['sha256'] for c in E.cl_chain(
    E.cl_facts(pem(alice)), E.cl_ca_facts(os.path.join(P, 'cas-samekey.pem')))]
OUT['samekey_want'] = [E.cl_facts(pem(ca1))['sha256'], E.cl_facts(pem(root))['sha256']]
OUT['samekey'] = {m: go(alice, 'cas-samekey.pem', m) for m in ('off', 'first', 'only')}
OUT['samekey_bob'] = go(bob, 'cas-samekey.pem', 'first')
# 2. the authority renewed with a new key: its issuer by key
cas = E.cl_ca_facts(os.path.join(P, 'cas-renewed.pem'))
fc = E.cl_facts(pem(carol))
OUT['chain'] = [c['sha256'] for c in E.cl_chain(fc, cas)]
OUT['want_chain'] = [E.cl_facts(pem(ca2))['sha256'], E.cl_facts(pem(root))['sha256']]
MODE['asked'] = []
OUT['renewed'] = {m: [go(carol, 'cas-renewed.pem', m), go(dora, 'cas-renewed.pem', m)]
                  for m in ('off', 'first', 'only', 'both')}
OUT['renewed_asked_of'] = sorted(set(str(s) for _x, s in MODE['asked']))
OUT['renewed_want'] = sorted({str(ca2.serial_number), str(root.serial_number)})
E.CL_OCSP_CACHE.clear()
try:
    E.cl_ocsp_ask('%s/ocsp' % U, fc, pem(carol), pem(ca2), os.path.join(P, 'cas-renewed.pem'))
except E.CertRefused:
    pass
OUT['key_has_hash'] = any(E.cl_pem_key_hash(pem(ca2)) in k for k in E.CL_OCSP_CACHE)
# 3. a delta CRL of a base newer than the one held
fd = E.cl_facts(pem(eric))
FILES['d.crl'] = crl(cad, dk, 10, fresh='d-delta.crl')
FILES['d-delta.crl'] = crl(cad, dk, 12, [eric], delta_base=10)
OUT['delta_same'] = go(eric, 'cas-delta.pem')
FILES['d-delta.crl'] = crl(cad, dk, 12, [eric], delta_base=11)
OUT['delta_newer'] = go(eric, 'cas-delta.pem')
OUT['delta_newer_first'] = go(eric, 'cas-delta.pem', 'first')
E.CL_CRL_CACHE.clear()
FILES['d.crl'] = crl(cad, dk, 10, fresh='d-delta.crl')
E.cl_crl_fetch('%s/d.crl' % U)                                 # #10 held...
FILES['d.crl'] = crl(cad, dk, 11, fresh='d-delta.crl')        # ...#11 published since
try:
    E.cl_check(pem(eric), os.path.join(P, 'cas-delta.pem'), crl=True, ocsp='off')
    OUT['delta_refetched'] = 'OK'
except E.CertRefused as e:
    OUT['delta_refetched'] = e.kind
OUT['delta_refetched_num'] = E.CL_CRL_CACHE['%s/d.crl' % U].get('num')
FILES['d-delta.crl'] = crl(cad, dk, 12, [], delta_base=11)
OUT['delta_clean'] = go(eric, 'cas-delta.pem')
# 4. an answer without next update
fa = E.cl_facts(pem(alice))
for how in ('stale', 'fresh-no-next', 'expired'):
    MODE['how'] = how
    E.CL_OCSP_CACHE.clear()
    try:
        OUT[how] = E.cl_ocsp_ask('%s/ocsp' % U, fa, pem(alice), pem(ca1),
                                 os.path.join(P, 'cas.pem'))['status']
    except E.CertRefused as e:
        OUT[how] = e.kind
        OUT[how + '_why'] = e.why
MODE['how'] = 'real'
# 5. a CRL that failed: not fetched again within a minute; one fetch at a time
E.CL_CRL_CACHE.clear()
url = '%s/none.crl' % U
for _ in range(3):
    try:
        E.cl_crl_fetch(url)
    except E.CertRefused:
        pass
OUT['failed_hits'] = HITS.get('none.crl')
real = time.time
E.time.time = lambda: real() + 61
try:
    E.cl_crl_fetch(url)
except E.CertRefused:
    pass
E.time.time = real
OUT['failed_hits_later'] = HITS.get('none.crl')
FILES['slow.crl'] = FILES['i.crl']
got = []
ts = [threading.Thread(target=lambda: got.append(E.cl_crl_fetch('%s/slow.crl' % U)['num']))
      for _ in range(3)]
[t.start() for t in ts]
[t.join() for t in ts]
OUT['slow'] = [HITS.get('slow.crl'), got]
print(json.dumps(OUT, default=str))
"""


@unittest.skipUnless(shutil.which('openssl'), 'no openssl here')
class HuntO(unittest.TestCase):
    """The revocation checks of the sign-in with a certificate, as the review of 1.0.106 found
    them: a forged OCSP answer, the issuer by key, a delta of a newer base, an old answer without
    next update, a CRL that failed fetched at every sign-in. Run with the engine in a process of
    its own (the cryptography package makes its PKI and answers)."""

    @classmethod
    def setUpClass(cls):
        try:
            import cryptography                        # noqa: F401
        except ImportError:
            raise unittest.SkipTest('no cryptography package here')
        cls.tmp = tempfile.mkdtemp(prefix='acme-hunt-o-')
        with open(os.path.join(cls.tmp, 'config.json'), 'w') as fh:
            fh.write('{}')
        script = os.path.join(cls.tmp, 'run.py')
        with open(script, 'w') as fh:
            fh.write(HUNT_O)
        env = dict(os.environ, ACME_CONFIG=os.path.join(cls.tmp, 'config.json'),
                   ACME_STATE=cls.tmp, ACME_RUN=cls.tmp, ACME_LOGDIR=cls.tmp)
        got = subprocess.run([sys.executable, script, cls.tmp, ROOT], capture_output=True,
                             text=True, timeout=600, env=env, cwd=cls.tmp)
        if got.returncode:
            raise RuntimeError(got.stdout[-2000:] + got.stderr[-4000:])
        cls.got = json.loads(got.stdout.strip().splitlines()[-1])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_1_forged_answer_refused(self):
        g = self.got
        self.assertEqual(g['forged'], {'first': 'revoked', 'only': 'unavailable',
                                       'both': 'unavailable'}, g.get('why'))
        self.assertEqual(g['forged_alice_only'], 'unavailable')
        self.assertIn('signature is not good', g['forged_why']['CN=bob-only'])
        self.assertEqual(g['real'], {'first': ['OK ocsp+ocsp', 'revoked'],
                                     'only': ['OK ocsp+ocsp', 'revoked'],
                                     'both': ['OK ocsp+crl+ocsp+crl', 'revoked']})

    def test_2_issuer_by_key(self):
        g = self.got
        self.assertEqual(g['chain'], g['want_chain'])
        for m in ('off', 'first', 'only', 'both'):
            self.assertEqual(g['renewed'][m][0], 'revoked', (m, g.get('why')))
            self.assertTrue(g['renewed'][m][1].startswith('OK'), (m, g['renewed'], g.get('why')))
        self.assertEqual(g['renewed_asked_of'], g['renewed_want'])
        self.assertTrue(g['key_has_hash'])

    def test_3_delta_of_a_newer_base(self):
        g = self.got
        self.assertEqual(g['delta_same'], 'revoked')
        self.assertEqual(g['delta_newer'], 'unavailable')
        self.assertEqual(g['delta_newer_first'], 'unavailable')
        self.assertEqual((g['delta_refetched'], g['delta_refetched_num']), ('revoked', 11))
        self.assertEqual(g['delta_clean'], 'OK crl')

    def test_4_answer_without_next_update(self):
        self.assertEqual(self.got['stale'], 'unavailable')
        self.assertEqual(self.got['fresh-no-next'], 'good')
        # openssl's "<file>: WARNING: Status times invalid." read as such (1.0.106)
        self.assertEqual(self.got['expired'], 'unavailable')
        self.assertIn('out of date', self.got['expired_why'])

    def test_7_renewed_with_the_same_key(self):
        """AD CS renewal with the same key, the old certificate (run out) first: the chain and
        the OCSP checks take the one valid now - nobody was signed in with OCSP on (1.0.106)."""
        g = self.got
        self.assertEqual(g['samekey_chain'], g['samekey_want'])
        self.assertEqual(g['samekey']['off'], 'OK crl')
        self.assertTrue(g['samekey']['first'].startswith('OK ocsp'), g['samekey'])
        self.assertTrue(g['samekey']['only'].startswith('OK ocsp'), g['samekey'])
        self.assertEqual(g['samekey_bob'], 'revoked')

    def test_5_crl_failed_and_together(self):
        g = self.got
        self.assertEqual(g['failed_hits'], 1)
        self.assertEqual(g['failed_hits_later'], 2)
        self.assertEqual(g['slow'], [1, [1, 1, 1]])

    def test_6_asks_of_every_node_queued(self):
        """Clear of one CRL, then of another, within a node's tick: both done on the other
        nodes (the second replaced the first, 1.0.106), each answered for its own page."""
        env = dict(os.environ, ACME_CONFIG=os.path.join(self.tmp, 'config.json'),
                   ACME_STATE=self.tmp, ACME_RUN=self.tmp, ACME_LOGDIR=self.tmp)
        code = r"""
import json, sys, time
sys.path.insert(0, %r)
import acme
from acmelib import engine as E
store = E.Storage(E.open_db())
E.HA_STORE['store'] = store
done = []
@E.node_ask_kind('t_hunt')
def _t(daemon, args):
    done.append(args['url'])
    return {'ok': True, 'url': args['url']}
class D(object):
    pass
d = D(); d.store = store; d.serving = False           # asked on another node's pages
a = E.node_ask(d, 't_hunt', {'url': 'A'}, 't')
b = E.node_ask(d, 't_hunt', {'url': 'B'}, 't')
for i in range(12):
    E.node_ask(d, 't_hunt2', {'n': i}, 't')
row = json.loads(store.get_meta('ask:want:t_hunt2'))
d.serving = True
E.node_ask_tick(d)                                     # this node's loop: both, once each
E.node_ask_tick(d)
for _ in range(100):
    if len(done) >= 2:
        break
    time.sleep(0.05)
time.sleep(0.3)
me = E.node_name()
ra = E.node_ask_results(store, 't_hunt', a['id']).get(me)
rb = E.node_ask_results(store, 't_hunt', b['id']).get(me)
print(json.dumps([sorted(done), (ra or {}).get('url'), (rb or {}).get('url'),
                  len(row['queue']), row['args']]))
""" % ROOT
        got = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                             timeout=120, env=env, cwd=self.tmp)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        done, ra, rb, queued, last = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertEqual(done, ['A', 'B'])
        self.assertEqual((ra, rb), ('A', 'B'))
        self.assertEqual(queued, 7)                     # NODE_ASK_QUEUE - 1 kept before the latest
        self.assertEqual(last, {'n': 11})

    def test_5_addresses(self):
        env = dict(os.environ, ACME_CONFIG=os.path.join(self.tmp, 'config.json'),
                   ACME_STATE=self.tmp, ACME_RUN=self.tmp, ACME_LOGDIR=self.tmp)
        env.pop('ACME_CDP_LOOPBACK_OK', None)
        code = ('import json, sys\nsys.path.insert(0, %r)\nfrom acmelib import engine as E\n'
                'ips = ["168.63.129.16", "192.0.0.192", "2002:a9fe:a9fe::1", "2002:7f00:1::1",'
                ' "2001:0:a9fe:a9fe::5", "64:ff9b::a9fe:a9fe", "2002:a00:1::1", "10.0.0.5"]\n'
                'dn = "ldap:///CN=X,CN=pki,CN=CDP,CN=Public Key Services,CN=Services,'
                'CN=Configuration,%%s?certificateRevocationList?base"\n'
                'print(json.dumps([[bool(E.cl_addr_no(i)) for i in ips], '
                '[bool(E.cl_ldap_cdp(dn %% t)) for t in ("DC=corp,DC=loc", "DC=corp,OU=x,DC=loc",'
                ' "DC=corp,DC=loc,CN=Users", "DC=loc")]]))' % ROOT)
        got = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                             timeout=120, env=env, cwd=self.tmp)
        self.assertEqual(got.returncode, 0, got.stderr)
        ips, dns = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertEqual(ips, [True] * 6 + [False, False])
        self.assertEqual(dns, [True, False, False, True])



class HuntO2(unittest.TestCase):
    """The second review of 1.0.106: the asks of every node done in order, the latest of a
    switch only; the issuer of one renewed with the same key; NAT64's addresses."""

    def run_code(self, code):
        tmp = tempfile.mkdtemp(prefix='acme-hunt-o2-')
        self.addCleanup(shutil.rmtree, tmp, True)
        with open(os.path.join(tmp, 'config.json'), 'w') as fh:
            fh.write('{}')
        env = dict(os.environ, ACME_CONFIG=os.path.join(tmp, 'config.json'),
                   ACME_STATE=tmp, ACME_RUN=tmp, ACME_LOGDIR=tmp)
        env.pop('ACME_CDP_LOOPBACK_OK', None)
        got = subprocess.run([sys.executable, '-c', 'import sys\nsys.path.insert(0, %r)\n' % ROOT
                              + code], capture_output=True, text=True, timeout=120, env=env,
                             cwd=tmp)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        return json.loads(got.stdout.strip().splitlines()[-1])

    def test_1_asks_in_order_latest_of_a_switch(self):
        got = self.run_code(r"""
import json, random, threading, time
import acme
from acmelib import engine as E
store = E.Storage(E.open_db())
E.HA_STORE['store'] = store
E.host_alive = lambda st: {E.node_name(): True}
ran, busy, overlap = [], [0], [0]
lock = threading.Lock()


def slow(name):
    def fn(daemon, args):
        with lock:
            busy[0] += 1
            overlap[0] = max(overlap[0], busy[0])
        time.sleep(random.uniform(0, 0.15))
        ran.append((name, args['n']))
        with lock:
            busy[0] -= 1
        return {'ok': True}
    return fn


E.node_ask_kind('t_switch')(slow('switch'))
E.node_ask_kind('t_test')(slow('test'))
E.NODE_ASK_LATEST['t_switch'] = lambda a: str(a.get('phase') or '')
class D(object):
    pass
d = D(); d.store = store; d.serving = False           # asked on another node's pages
ids = [E.node_ask(d, 't_switch', {'n': i, 'phase': 'connect'}, 't')['id'] for i in range(3)]
E.node_ask(d, 't_switch', {'n': 9, 'phase': 'server'}, 't')
for i in range(4):
    E.node_ask(d, 't_test', {'n': i}, 't')
d.serving = True
E.node_ask_tick(d)
E.node_ask_tick(d)
for _ in range(200):
    if len(ran) >= 6:
        break
    time.sleep(0.05)
time.sleep(0.3)
me = E.node_name()
skipped = [(E.node_ask_results(store, 't_switch', i).get(me) or {}).get('skipped') for i in ids]
# a restart: what this node answered is not done again; of those asked before it began only
# the latest (a test trap sent again for each)
E.NODE_ASK['done'].clear()
n_before = len(ran)
E.node_ask_tick(d)
time.sleep(0.5)
again = len(ran) - n_before
E.NODE_ASK['done'].clear()
store.set_meta('ask:got:t_test:' + me, '{}')
E.NODE_ASK_BEGAN = time.time() + 1
E.node_ask_tick(d)
time.sleep(0.8)
print(json.dumps([[x for x in ran[:n_before] if x[0] == 'switch'],
                  [x[1] for x in ran[:n_before] if x[0] == 'test'], overlap[0] <= 2,
                  skipped, again, ran[n_before:]]))
""")
        switch, tests, overlap_ok, skipped, again, after = got
        self.assertEqual(switch, [['switch', 2], ['switch', 9]])     # the latest of a phase
        self.assertEqual(tests, [0, 1, 2, 3])                          # every one, in order
        self.assertTrue(overlap_ok)                                    # one at a time a kind
        self.assertEqual(skipped, [True, True, None])
        self.assertEqual(again, 0)
        self.assertEqual(after, [['test', 3]])

    def test_1b_two_nodes_ask_at_once(self):
        """Final review of 1.0.106: the ask's row was read and written whole under a lock of
        this process's only - another node writing its ask between the two lost it, never done
        anywhere. Now a compare-and-swap: both kept."""
        got = self.run_code(r"""
import json, threading
import acme
from acmelib import engine as E
store = E.Storage(E.open_db())
E.HA_STORE['store'] = store
E.node_ask_kind('t_two')(lambda daemon, args: {'ok': True})
class D(object):
    pass
d = D(); d.store = store; d.serving = False
real = store.db.value
other = []

def value(sql, *a, **k):
    got = real(sql, *a, **k)
    if 'FROM meta' in sql and a and a[0] == ('ask:want:t_two',) and not other:
        # the other node writes its ask between this one's read and write
        other.append({'id': 'othernode', 'args': {'n': 'other'}, 'at': __import__('time').time(),
                      'by': 'o'})
        E._node_ask_want_put(store, 't_two', other[0])
    return got
store.db.value = value
mine = E.node_ask(d, 't_two', {'n': 'mine'}, 't')['id']
store.db.value = real
row = json.loads(store.get_meta('ask:want:t_two'))
first = [row['id']] + [w['id'] for w in row['queue']]
# many at once, each as if on a node of its own (no lock of this process's between them)
class NoLock(object):
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
E.NODE_ASK_LOCK = NoLock()
ids, errs = [], []
def one(i):
    try:
        ids.append(E.node_ask(d, 't_many', {'n': i}, 't')['id'])
    except Exception as e:
        errs.append(repr(e))
ts = [threading.Thread(target=one, args=(i,)) for i in range(6)]
for t in ts:
    t.start()
for t in ts:
    t.join()
row = json.loads(store.get_meta('ask:want:t_many'))
kept = [row['id']] + [w['id'] for w in row['queue']]
print(json.dumps([first, mine, sorted(ids) == sorted(kept), errs]))
""")
        first, mine, all_kept, errs = got
        self.assertEqual(sorted(first), sorted([mine, 'othernode']))
        self.assertEqual(first[0], mine)                # the latest written last
        self.assertTrue(all_kept)
        self.assertEqual(errs, [])

    def test_2_issuer_renewed_with_the_same_key(self):
        got = self.run_code(r"""
import json, time
from acmelib import engine as E
now = time.time()
def ca(sha, nb, na):
    return {'sha256': sha, 'subject': 'CN=I', 'issuer': 'CN=R', 'ski': 'AA',
            'not_before_t': nb, 'not_after_t': na, 'pem': ''}
E.cl_signed_by = lambda c, p: p['sha256'] != 'other'
c = {'sha256': 'leaf', 'subject': 'CN=u', 'issuer': 'CN=I', 'aki': 'AA'}
old, new, newer = ca('old', now - 900 * 86400, now - 86400), ca('new', now - 86400, now + 9e7), \
    ca('newer', now - 3600, now + 9e8)
print(json.dumps([E.cl_issuer_of(c, [old, new])['sha256'],
                  E.cl_issuer_of(c, [old, newer, new])['sha256'],
                  E.cl_issuer_of(c, [old, ca('other', 0, now + 9e7)])['sha256'],
                  E.cl_issuer_of(c, [ca('other', 0, now + 9e7)]) is None]))
""")
        self.assertEqual(got, ['new', 'newer', 'old', False])

    def test_3_nat64(self):
        got = self.run_code(r"""
import json
from acmelib import engine as E
ips = ['64:ff9b::808:808', '64:ff9b::a00:5', '64:ff9b::a9fe:a9fe', '64:ff9b::7f00:1',
       '64:ff9b:1::808:808', '64:ff9b::e000:1']
print(json.dumps([E.cl_addr_no(i) for i in ips]))
""")
        self.assertEqual(got[:2], ['', ''])
        self.assertTrue(all(got[2:]), got)
        self.assertIn('carried in an IPv6 address', got[2])
        self.assertEqual(got[4], 'reserved')


if __name__ == '__main__':
    unittest.main(verbosity=2)
