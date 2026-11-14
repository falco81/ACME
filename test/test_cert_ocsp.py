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
import signal
import socket
import subprocess
import sys
import tempfile
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
        d = cls.pki
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
        pki, lock = cls.pki, threading.Lock()

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
        got = self.py('print(json.dumps([E.cl_ldap_cdp(u) for u in %r]))' % [
            LDAPCDP, LDAPCDP.replace('certificateRevocationList', 'deltaRevocationList;binary'),
            LDAPCDP.replace('certificateRevocationList', 'userPassword'),
            LDAPCDP.replace('certificateRevocationList', 'unicodePwd'),
            LDAPCDP.replace('?base?', '?sub?'),
            'ldap:///CN=Administrator,CN=Users,DC=corpnet,DC=loc?certificateRevocationList?base',
            'ldap://evil.example/CN=x,CN=CDP,CN=Public%20Key%20Services,CN=Services,'
            'CN=Configuration,DC=corpnet,DC=loc?certificateRevocationList?base',
            'http://127.0.0.1/x.crl'])
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
