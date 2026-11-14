#!/usr/bin/env python3
"""Signing in with a certificate - a smart card, a YubiKey (1.0.100, as otp 1.0.275), the
administration and the certificate portal each by its own switches.

    python3 test/test_cert_login.py      (or python3 -m unittest test.test_cert_login)

A PKI of its own as AD CS makes it (the kit's testing/pki.sh, inside the test): a root, an issuing
authority, its CRL served over http on a port of its own, and people's certificates for every case
the sign-in has to tell apart - right, a full admin, no SID, another account's SID, revoked, run
out, Server Authentication only, no UPN, no group, switched off in AD, not in AD, another
authority, a CRL at an address that does not answer. The people of test/mockldap.py's directory
(their objectSid added), a real daemon in a folder of its own (test/test_certs_core.py's way), the
pages through php -S as nginx hands them the certificate (the relay: the nonce, the cookie, back
to 443), and - where nginx and php-fpm are here - a real nginx on the certificate's own port with
the servers the root helper writes (the authorities' names sent, 443 asking nobody, nothing but the
sign-in served, an expired certificate's 495 to the page).

Skipped as a whole where openssl is not there.
"""
import base64
import http.server
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)
import mockldap                      # noqa: E402

BASE = 'DC=corpnet,DC=loc'
HOST = 'acme.corpnet.loc'
FULL = 'CN=CERT_SUPPLIER_X,OU=Groups,' + BASE        # nested is in it: a full admin
WATCH = 'CN=CERT_USERS,OU=Groups,' + BASE            # falco: read only (nested too, below)
SIDS = {'falco': 'S-1-5-21-1111-2222-3333-1105', 'nested': 'S-1-5-21-1111-2222-3333-1106',
        'outsider': 'S-1-5-21-1111-2222-3333-1200', 'gone': 'S-1-5-21-1111-2222-3333-1201'}
REFUSED = 'Certificate sign-in refused: '

# The kit's testing/pki.sh: an AD CS of its own with openssl - its CDP at @CRL@ (served by the
# test), the one that does not answer at @NOCRL@.
PKI_SH = r'''#!/bin/bash
set -e
D=$1
cd "$D"
SID_FALCO=S-1-5-21-1111-2222-3333-1105
SID_NESTED=S-1-5-21-1111-2222-3333-1106
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
crlDistributionPoints = URI:@ROOTCRL@
[nc_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
crlDistributionPoints = URI:@ROOTCRL@
nameConstraints = critical,permitted;email:partner.example,permitted;DNS:partner.example
[person_fresh]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:@CRL@
freshestCRL = URI:@DELTA@
1.3.6.1.4.1.311.25.2 = ASN1:SEQUENCE:sidext
[person_sansid]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN},otherName:1.3.6.1.4.1.311.25.2.1;OCTETSTRING:\${ENV::SID}
crlDistributionPoints = URI:@CRL@
[person_sanurl]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = @san_url
crlDistributionPoints = URI:@CRL@
1.3.6.1.4.1.311.25.2 = ASN1:SEQUENCE:sidext
[san_url]
otherName.1 = 1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
URI.1 = tag:microsoft.com,2022-09-14:sid:$SID_NESTED
[person_5upn]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:falco@corpnet.cz,otherName:1.3.6.1.4.1.311.20.2.3;UTF8:falco@corpnet.cz,otherName:1.3.6.1.4.1.311.20.2.3;UTF8:falco@corpnet.cz,otherName:1.3.6.1.4.1.311.20.2.3;UTF8:falco@corpnet.cz,otherName:1.3.6.1.4.1.311.20.2.3;UTF8:nested@corpnet.cz
crlDistributionPoints = URI:@CRL@
[person]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN},email:\${ENV::UPN}
crlDistributionPoints = URI:@CRL@
1.3.6.1.4.1.311.25.2 = ASN1:SEQUENCE:sidext
[person_nosid]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:@CRL@
[person_nocdp]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:@NOCRL@
1.3.6.1.4.1.311.25.2 = ASN1:SEQUENCE:sidext
[person_srv]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:@CRL@
[person_noupn]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = email:noupn@corpnet.cz
crlDistributionPoints = URI:@CRL@
[server]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:acme.corpnet.loc,DNS:node2.corpnet.loc,DNS:localhost,IP:127.0.0.1
[sidext]
gn = IMPLICIT:0C,SEQUENCE:othername
[othername]
oid = OID:1.3.6.1.4.1.311.25.2.1
val = EXPLICIT:0,OCTETSTRING:\${ENV::SID}
EOF
mkdir -p db/new
: > db/index.txt
echo 1000 > db/serial
echo 1000 > db/crlnumber
export UPN=x SID=S-1-0-0
openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 \
  -subj "/DC=loc/DC=corpnet/CN=Corpnet Root CA" -config ca.cnf -extensions root_ext 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout issuing.key -out issuing.csr \
  -subj "/DC=loc/DC=corpnet/CN=Corpnet Issuing CA" 2>/dev/null
openssl x509 -req -in issuing.csr -CA root.pem -CAkey root.key -CAcreateserial -out issuing.pem \
  -days 1825 -extfile ca.cnf -extensions issuing_ext 2>/dev/null
cat issuing.pem root.pem > cas.pem
person() {
  local n=$1
  export UPN=$2 SID=$3
  openssl req -newkey rsa:2048 -nodes -keyout "$n.key" -out "$n.csr" -subj "/CN=$n" 2>/dev/null
  if [ -n "$5" ]; then
    openssl ca -batch -config ca.cnf -extensions "$4" -in "$n.csr" -out "$n.pem" -notext \
      -startdate "$5" -enddate "$6" >/dev/null 2>&1
  else
    openssl ca -batch -config ca.cnf -extensions "$4" -in "$n.csr" -out "$n.pem" -notext >/dev/null 2>&1
  fi
}
person falco falco@corpnet.cz $SID_FALCO person
person nested nested@corpnet.cz $SID_NESTED person
person falco-nosid falco@corpnet.cz - person_nosid
person falco-sid2 falco@corpnet.cz $SID_NESTED person
person falco-rev falco@corpnet.cz $SID_FALCO person
person falco-old falco@corpnet.cz $SID_FALCO person 20200101000000Z 20210101000000Z
person falco-srv falco@corpnet.cz $SID_FALCO person_srv
person falco-nocdp falco@corpnet.cz $SID_FALCO person_nocdp
person noupn - - person_noupn
person outsider outsider@corpnet.cz S-1-5-21-1111-2222-3333-1200 person
person gone gone@corpnet.cz S-1-5-21-1111-2222-3333-1201 person
person ghost ghost@corpnet.cz S-1-5-21-1111-2222-3333-1202 person
person web - - server
openssl ca -config ca.cnf -revoke falco-rev.pem >/dev/null 2>&1
openssl ca -config ca.cnf -gencrl -out issuing.crl.pem >/dev/null 2>&1
mkdir -p www
openssl crl -in issuing.crl.pem -outform DER -out www/issuing.crl
openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.pem -days 3650 \
  -subj "/CN=Somebody Else CA" -config ca.cnf -extensions root_ext 2>/dev/null
export UPN=falco@corpnet.cz SID=$SID_FALCO
openssl req -newkey rsa:2048 -nodes -keyout stranger.key -out stranger.csr -subj "/CN=stranger" 2>/dev/null
openssl x509 -req -in stranger.csr -CA other.pem -CAkey other.key -CAcreateserial -out stranger.pem \
  -days 365 -extfile ca.cnf -extensions person 2>/dev/null
openssl x509 -in issuing.pem -outform DER -out issuing.der
openssl crl2pkcs7 -nocrl -certfile cas.pem -out cas.p7b
# The security review's cases (1.0.100): every UPN looked at, the SID of the SAN, a delta CRL,
# the root's CRL (an issuing authority revoked by it), name constraints.
cat >> ca.cnf <<EOF
[person_sub]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:@SUBCRL@
EOF
person five falco@corpnet.cz - person_5upn
person esc1 nested@corpnet.cz $SID_NESTED person_sansid
person falco-sansid falco@corpnet.cz $SID_FALCO person_sansid
person falco-sanurl falco@corpnet.cz $SID_FALCO person_sanurl
person falco-sansid2 falco@corpnet.cz $SID_NESTED person_sansid
person fresh falco@corpnet.cz $SID_FALCO person_fresh
person lost falco@corpnet.cz $SID_FALCO person
openssl ca -config ca.cnf -gencrl -out issuing.crl.pem >/dev/null 2>&1
openssl crl -in issuing.crl.pem -outform DER -out www/issuing.crl
mkcnf() { # file folder certificate key
  cat > "$1" <<EOF
[ca]
default_ca = c
[c]
dir = $D/$2
database = \$dir/index.txt
new_certs_dir = \$dir/new
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $D/$3
private_key = $D/$4
default_md = sha256
default_days = 365
default_crl_days = 30
policy = anything
copy_extensions = none
unique_subject = no
[anything]
commonName = supplied
EOF
  mkdir -p "$2/new"; : > "$2/index.txt"; echo 2000 > "$2/serial"; echo 2000 > "$2/crlnumber"
}
mkcnf root.cnf rdb root.pem root.key
# An issuing authority of the root's that the root revokes, and a person of it.
openssl req -newkey rsa:2048 -nodes -keyout sub.key -out sub.csr -subj "/DC=loc/DC=corpnet/CN=Corpnet Old CA" 2>/dev/null
openssl x509 -req -in sub.csr -CA root.pem -CAkey root.key -CAcreateserial -out sub.pem \
  -days 1000 -extfile ca.cnf -extensions issuing_ext 2>/dev/null
mkcnf sub.cnf sdb sub.pem sub.key
openssl req -newkey rsa:2048 -nodes -keyout subling.key -out subling.csr -subj "/CN=subling" 2>/dev/null
openssl ca -batch -config sub.cnf -extfile ca.cnf -extensions person_sub -in subling.csr -out subling.pem -notext >/dev/null 2>&1
openssl ca -config sub.cnf -gencrl -out sub.crl.pem >/dev/null 2>&1
openssl crl -in sub.crl.pem -outform DER -out www/sub.crl
openssl ca -config root.cnf -revoke sub.pem >/dev/null 2>&1
openssl ca -config root.cnf -gencrl -out root.crl.pem >/dev/null 2>&1
openssl crl -in root.crl.pem -outform DER -out www/root.crl
cat issuing.pem root.pem sub.pem > cas-sub.pem
# A partner's authority constrained to partner.example, a person of it with a corpnet UPN
# (openssl itself does not look at the UPN), and one within.
openssl req -newkey rsa:2048 -nodes -keyout nc.key -out nc.csr -subj "/CN=Partner NC CA" 2>/dev/null
openssl x509 -req -in nc.csr -CA root.pem -CAkey root.key -CAcreateserial -out nc.pem -days 1000 \
  -extfile ca.cnf -extensions nc_ext 2>/dev/null
for p in ncp:nested@corpnet.cz ncok:anna@partner.example; do
  export UPN=${p#*:}
  openssl req -newkey rsa:2048 -nodes -keyout ${p%%:*}.key -out ${p%%:*}.csr -subj "/CN=${p%%:*}" 2>/dev/null
  openssl x509 -req -in ${p%%:*}.csr -CA nc.pem -CAkey nc.key -CAcreateserial -out ${p%%:*}.pem \
    -days 100 -extfile ca.cnf -extensions person_nosid 2>/dev/null
done
cat issuing.pem root.pem nc.pem > cas-nc.pem
# The delta CRL of the issuing authority (Freshest CRL of "fresh"): nothing new in it yet.
BASE=$(openssl crl -in issuing.crl.pem -noout -crlnumber | cut -d= -f2)
( cat ca.cnf; printf '[delta_ext]\n2.5.29.27 = critical,ASN1:INTEGER:%s\n' "$BASE" ) > delta.cnf
openssl ca -config delta.cnf -gencrl -crlexts delta_ext -crldays 1 -out delta.crl.pem >/dev/null 2>&1
openssl crl -in delta.crl.pem -outform DER -out www/issuing-delta.crl
cat web.pem issuing.pem > web-chain.pem
mkdir -p otherdir && cp other.pem otherdir/ && openssl rehash otherdir >/dev/null 2>&1 || true
'''


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def sid_bytes(text):
    p = text.split('-')
    subs = [int(x) for x in p[3:]]
    return bytes([int(p[1]), len(subs)]) + int(p[2]).to_bytes(6, 'big') + \
        b''.join(x.to_bytes(4, 'little') for x in subs)


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


@unittest.skipUnless(shutil.which('openssl'), 'no openssl here')
class CertLogin(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.ok
    py = TCC.CertsCore.py
    cli = TCC.CertsCore.cli

    @classmethod
    def pki_up(cls):
        d = cls.pki = tempfile.mkdtemp(prefix='acme-pki-')
        cls.crl_port, nocrl = free_port(), free_port()
        here = 'http://127.0.0.1:%d/' % cls.crl_port
        script = PKI_SH.replace('@CRL@', here + 'issuing.crl') \
            .replace('@NOCRL@', 'http://127.0.0.1:%d/nowhere.crl' % nocrl) \
            .replace('@ROOTCRL@', here + 'root.crl').replace('@SUBCRL@', here + 'sub.crl') \
            .replace('@DELTA@', here + 'issuing-delta.crl')
        with open(os.path.join(d, 'pki.sh'), 'w') as f:
            f.write(script)
        got = subprocess.run(['bash', os.path.join(d, 'pki.sh'), d], capture_output=True,
                             text=True, timeout=300)
        if got.returncode:
            raise RuntimeError('pki.sh: %s' % got.stderr[-2000:])
        www = os.path.join(d, 'www')

        class H(_Quiet):
            def __init__(self, *a, **kw):
                http.server.SimpleHTTPRequestHandler.__init__(self, *a, directory=www, **kw)
        cls.crl_srv = http.server.ThreadingHTTPServer(('127.0.0.1', cls.crl_port), H)
        threading.Thread(target=cls.crl_srv.serve_forever, daemon=True).start()

    @classmethod
    def setUpClass(cls):
        cls.pki_up()
        cls.ldap_was = {dn: dict(v) for dn, v in mockldap.PEOPLE.items()}
        cls.groups_was = json.dumps(mockldap.GROUPS)
        for dn, one in mockldap.PEOPLE.items():
            sam = (one.get('sAMAccountName') or [''])[0]
            if sam in SIDS:
                one['objectSid'] = [sid_bytes(SIDS[sam])]
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        # The system's roots, as openssl finds them by default, hold "Somebody Else CA": the
        # sign-in must trust only the authorities put in (openssl verify -no-CApath).
        os.environ['SSL_CERT_DIR'] = os.path.join(cls.pki, 'otherdir')
        # The CRLs are served on this machine: loopback is no address a CDP may have otherwise.
        os.environ['ACME_CDP_LOOPBACK_OK'] = '1'
        try:
            TCC.CertsCore.setUpClass.__func__(cls)
        finally:
            os.environ.pop('SSL_CERT_DIR', None)
            os.environ.pop('ACME_CDP_LOOPBACK_OK', None)
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        cls.must('POST', '/api/settings', {'settings': {
            'admin_directory': 'corp', 'admin_group_full': FULL, 'admin_group_readonly': WATCH,
            'portal': 1, 'portal_directory': 'corp', 'portal_who': 'groups',
            'portal_groups': WATCH, 'portal_tries': 50, 'login_tries': 50}})

    @classmethod
    def tearDownClass(cls):
        try:
            TCC.CertsCore.tearDownClass.__func__(cls)
        finally:
            cls.ldap_stop.set()
            mockldap.PEOPLE.clear()
            mockldap.PEOPLE.update(cls.ldap_was)
            mockldap.GROUPS.clear()
            mockldap.GROUPS.update(json.loads(cls.groups_was))
            cls.crl_srv.shutdown()
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

    def b64(self, name):
        with open(os.path.join(self.pki, name), 'rb') as f:
            return base64.b64encode(f.read()).decode()

    def put(self, name='cas.pem', session=None):
        return self.call('POST', '/api/certlogin', {'action': 'put', 'data': self.b64(name),
                                                    'name': name}, session or self.admin)

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

    def sign(self, part, name, session=None):
        path = '/api/auth/cert' if part == 'admin' else '/api/portal/cert'
        # The page's nonce, as acme-api.php hands it on (once only - the daemon keeps it).
        return self.call('POST', path, {'cert': self.pem(name) if name else '',
                                        'once': secrets.token_hex(16)}, session)

    def events(self, text):
        got = self.ok('GET', '/api/events', args={'q': text})
        return [e.get('words') or '' for e in got.get('events') or got.get('rows') or []]

    def refused(self, part, name, kind, why=None):
        st, got = self.sign(part, name)
        self.assertIn(st, (401, 503), (name, got))
        self.assertNotIn('token', got)
        self.assertEqual(got.get('error'), REFUSED + kind, (name, got))
        # Nothing of the certificate, the directory or the authorities to the caller.
        self.assertFalse(re.search(r'CN=|corpnet|S-1-5|http://|serial', json.dumps(got)), got)
        if why:
            self.assertTrue(any(why in w for w in self.events(why)), (name, why))
        return got

    def on(self, **kv):
        self.must('POST', '/api/settings', {'settings': kv})

    def serving(self, port=8443, path='/api/health'):
        """Something answering on the certificate's port, as nginx does once root wrote its
        server - until then the sign-in pages offer no button (hunt M round 3). The daemon
        asks the port at most every 5 s: waited for until it says so."""
        lsn = socket.socket()
        lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsn.bind(('127.0.0.1', port))
        lsn.listen(8)
        for _ in range(30):
            st, h = self.call('GET', path)
            if (h.get('certlogin') or {}).get('ready') or not (h.get('certlogin') or {}).get('on'):
                break
            time.sleep(0.5)
        return lsn

    def not_serving(self):
        """Until the daemon's last look at the port (at most 5 s old) says nothing answers."""
        for _ in range(30):
            st, h = self.call('GET', '/api/health')
            if not (h.get('certlogin') or {}).get('ready'):
                return
            time.sleep(0.5)

    def back_to_passwords(self, part='admin'):
        cli = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--set',
                              '%s_password_off=0' % part], env=self.env, capture_output=True,
                             text=True, timeout=120)
        self.assertEqual(cli.returncode, 0, cli.stdout + cli.stderr)
        for _ in range(40):
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            if st == 200:
                break
            time.sleep(0.5)
        self.assertEqual(st, 200, got)
        type(self).admin = got['token']
        type(self).ro = self.login('viewer')

    def ca_file(self):
        return os.path.join(self.tmp, 'state', 'certlogin', 'cas.pem')

    # ---- off --------------------------------------------------------------------------------
    def test_01_off_by_default(self):
        self.assertEqual(self.py(
            'print(json.dumps([E.DEFAULTS[k] for k in ("admin_certlogin", "portal_certlogin", '
            '"admin_certlogin_crl", "admin_certlogin_match", "certlogin_port", '
            '"alerts_certlogin")]))'), [0, 0, 1, 'strong', 8443, 0])
        for part in ('admin', 'portal'):
            st, got = self.sign(part, 'nested')
            self.assertEqual(st, 404, got)
        st, h = self.call('GET', '/api/health')
        self.assertEqual(h['certlogin'], {'on': False, 'ready': False, 'auto': False, 'only': False,
                                          'port': 0})
        self.assertEqual({k: h['signin'][k] for k in ('password', 'windows', 'certificate', 'order')},
                         {'password': True, 'windows': 'off', 'certificate': 'off', 'order': []})
        st, info = self.call('GET', '/api/portal/info')
        self.assertFalse(info['certlogin']['on'])
        # No port: nothing asked of root, no opening in the firewall.
        self.assertEqual(self.py('print(json.dumps(E.certlogin_desired(st)))'), None)
        self.assertEqual(self.py('print(json.dumps(E.cl_firewall(st, E.node_name())))'), [])
        # "No password at all" not from a password sign-in.
        st, got = self.settings(admin_password_off=1)
        self.assertEqual(st, 400, got)
        self.assertIn('with a certificate', got['error'])

    def test_02_the_authorities(self):
        # A person's certificate is refused, and so is anything else; a read-only one may not.
        st, got = self.put('falco.pem')
        self.assertEqual(st, 400, got)
        self.assertIn('not an authority', got['error'])
        st, got = self.call('POST', '/api/certlogin', {'action': 'put', 'data': base64.b64encode(
            b'not a certificate').decode()}, self.admin)
        self.assertEqual(st, 400, got)
        st, got = self.put('cas.pem', self.ro)
        self.assertEqual(st, 403, got)
        # DER of the issuing one; then the PKCS#7 of both (the issuing one there already).
        st, got = self.put('issuing.der')
        self.assertEqual(st, 200, got)
        self.assertEqual([c['subject'] for c in got['added']],
                         ['CN=Corpnet Issuing CA,DC=corpnet,DC=loc'])
        st, got = self.put('cas.p7b')
        self.assertEqual(st, 200, got)
        self.assertEqual([c['subject'] for c in got['added']], ['CN=Corpnet Root CA,DC=corpnet,DC=loc'])
        v = got['view']
        self.assertEqual(len(v['cas']), 2)
        self.assertTrue(all(len(c['sha256']) == 64 and c['not_after'] for c in v['cas']))
        # Kept signed (db_guard), written out by the node itself, 0600, as the database has them.
        self.assertTrue(self.py('print(json.dumps(E.dbguard_meta_kept("certlogin:cas")))'))
        for _ in range(60):
            if os.path.exists(self.ca_file()):
                break
            time.sleep(0.5)
        self.assertEqual(os.stat(self.ca_file()).st_mode & 0o777, 0o600)
        with open(self.ca_file()) as f:
            self.assertEqual(f.read().count('BEGIN CERTIFICATE'), 2)
        # Taken away one by one, and put back.
        sha = [c['sha256'] for c in v['cas'] if 'Root' in c['subject']][0]
        st, got = self.call('POST', '/api/certlogin', {'action': 'drop', 'sha256': sha[:16]},
                            self.admin)
        self.assertEqual((st, len(got['view']['cas'])), (200, 1), got)
        st, got = self.put('cas.pem')
        self.assertEqual(len(got['view']['cas']), 2)
        self.assertTrue(any('put in the authorities of the sign-in with a certificate' in w
                            for w in self.events('authorities of the sign-in')))

    def test_03_the_port(self):
        for port in (443, 80, 22, 9861, 1812, self.port):
            st, got = self.settings(certlogin_port=port)
            self.assertEqual(st, 400, (port, got))
        st, got = self.settings(certlogin_port=8443)
        self.assertEqual(st, 200, got)
        self.put()
        self.on(admin_certlogin=1)
        try:
            want = self.py('print(json.dumps(E.certlogin_desired(st)))')
            self.assertEqual((want['port'], want['admin'], want['portal']), (8443, True, False))
            self.assertEqual(want['cas'].count('BEGIN CERTIFICATE'), 2)
            rules = self.py('print(json.dumps(E.cl_firewall(st, E.node_name())))')
            self.assertEqual(rules[0]['key'], 'certlogin')
            self.assertTrue(all(r['port'] == '8443' and r['proto'] == 'tcp' for r in rules[0]['rules']))
            # Nothing answers on the port (nginx not given it yet): no button, no port - the
            # browser was sent to "connection refused" (hunt M round 3)
            self.not_serving()
            st, h = self.call('GET', '/api/health')
            self.assertEqual(h['certlogin'], {'on': True, 'ready': False, 'auto': False,
                                              'only': False, 'port': 0})
            self.assertEqual(h['signin']['certificate'], 'button')
            lsn = self.serving()
            try:
                st, h = self.call('GET', '/api/health')
                self.assertEqual(h['certlogin'], {'on': True, 'ready': True, 'auto': False,
                                                  'only': False, 'port': 8443})
            finally:
                lsn.close()
        finally:
            self.on(admin_certlogin=0)
        # Off again: root is asked to take the port away ({port: 0}).
        self.assertEqual(self.py('print(json.dumps(E.certlogin_desired(st)))'), {'port': 0})

    def test_04_signed_in(self):
        self.put()
        self.on(admin_certlogin=1)
        try:
            st, got = self.sign('admin', 'nested')
            self.assertEqual(st, 200, got)
            self.assertEqual(got['who'], {'name': 'nested', 'role': 'fulladmin'})
            st, me = self.call('GET', '/api/auth/whoami', None, got['token'])
            self.assertEqual((me['who']['how'], me['who']['role']), ('certificate', 'fulladmin'))
            st, got = self.sign('admin', 'falco')
            self.assertEqual((st, got.get('who', {}).get('role')), (200, 'readonly'), got)
            # The portal's endpoint stays off: its own switch.
            st, got = self.sign('portal', 'falco')
            self.assertEqual(st, 404, got)
            self.assertTrue(any('nested signed in from' in w and 'with a certificate' in w
                                for w in self.events('with a certificate')))
            # The CRL fetched and kept, on the card.
            v = self.ok('GET', '/api/certlogin', session=self.ro)
            self.assertTrue(any(c['ok'] and c['next'] for c in v['crls']), v['crls'])
        finally:
            self.on(admin_certlogin=0)

    def test_05_refused(self):
        self.put()
        self.on(admin_certlogin=1)
        try:
            cases = [('falco-rev', 'revoked', 'certificate revoked'),
                     ('falco-old', 'run out', 'certificate has expired'),
                     ('falco-srv', 'certificate not accepted', 'not for signing in'),
                     ('noupn', 'certificate not accepted', 'names no user'),
                     ('outsider', 'not allowed', 'none of the groups'),
                     ('gone', 'not allowed', 'disabled'),
                     ('ghost', 'not allowed', 'nobody has that UPN'),
                     ('stranger', 'certificate not accepted', 'unable to get local issuer'),
                     ('falco-nocdp', 'not available just now', 'could not be had'),
                     ('falco-sid2', 'not allowed', 'is not the one of falco'),
                     ('issuing', 'certificate not accepted', 'certificate of an authority')]
            for name, kind, why in cases:
                self.refused('admin', name, kind, why)
            st, got = self.call('POST', '/api/auth/cert', {}, None)
            self.assertEqual(got.get('error'), REFUSED + 'certificate not accepted', got)
            st, got = self.call('POST', '/api/auth/cert', {'cert': 'x' * 20000}, None)
            self.assertEqual(got.get('error'), REFUSED + 'certificate not accepted', got)
            # nginx's own refusal (an expired one, 495), said as nginx said it.
            st, got = self.call('POST', '/api/auth/cert', {'failed': 'FAILED:certificate has expired',
                                                           'once': secrets.token_hex(16)})
            self.assertEqual(got.get('error'), REFUSED + 'run out', got)
            words = self.events('a sign-in with a certificate was refused')
            self.assertTrue(len(words) >= 10, words)
            self.assertFalse(any('BEGIN CERTIFICATE' in w or 'MII' in w for w in words))
        finally:
            self.on(admin_certlogin=0)

    def test_06_how_matched(self):
        self.put()
        self.on(admin_certlogin=1, admin_certlogin_match='compat')
        try:
            # compat (an opt-down): no SID - taken; another's SID - refused.
            self.assertEqual(self.sign('admin', 'falco-nosid')[0], 200)
            self.refused('admin', 'falco-sid2', 'not allowed')
            self.on(admin_certlogin_match='strong')
            self.refused('admin', 'falco-nosid', 'not allowed', 'is strong')
            self.assertEqual(self.sign('admin', 'falco')[0], 200)
            self.on(admin_certlogin_match='upn')
            self.assertEqual(self.sign('admin', 'falco-sid2')[0], 200)
            self.assertEqual(self.sign('admin', 'falco-nosid')[0], 200)
            # Revocation off: the revoked one signs in (the card says so).
            self.on(admin_certlogin_match='compat', admin_certlogin_crl=0)
            self.assertEqual(self.sign('admin', 'falco-rev')[0], 200)
            self.assertEqual(self.sign('admin', 'falco-nocdp')[0], 200)
            self.on(admin_certlogin_crl=1)
            self.refused('admin', 'falco-rev', 'revoked')
        finally:
            self.on(admin_certlogin=0, admin_certlogin_match='strong', admin_certlogin_crl=1)

    def test_07_second_step(self):
        self.put()
        self.on(admin_certlogin=1, admin_2fa=1)
        try:
            st, got = self.sign('admin', 'nested')
            self.assertEqual(st, 200, got)
            self.assertEqual((got['mfa'], got['who']['role']), ('enrol', ''))
            st, x = self.call('GET', '/api/status', None, got['token'])
            self.assertEqual(st, 401, x)
        finally:
            self.on(admin_certlogin=0, admin_2fa=0)

    def test_08_no_password_at_all(self):
        self.put()
        self.on(admin_certlogin=1)
        st, got = self.sign('admin', 'nested')
        self.assertEqual(st, 200, got)
        card = got['token']
        try:
            st, got = self.settings(admin_password_off=1)
            self.assertEqual(st, 400, got)
            st, got = self.settings(session=card, admin_password_off=1)
            self.assertEqual(st, 200, got)
            st, h = self.call('GET', '/api/health')
            self.assertTrue(h['certlogin']['only'])
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            self.assertEqual(st, 403, got)
            self.assertIn('only a certificate', got['error'])
            st, got = self.call('GET', '/api/auth/whoami', None, self.admin)
            self.assertNotEqual((got.get('who') or {}).get('name'), 'tester', got)
            st, me = self.call('GET', '/api/auth/whoami', None, card)
            self.assertTrue(me['who']['password_off'])
            # The certificates switched off bring the passwords back, and end their sign-ins
            # but the switcher's.
            st, other = self.sign('admin', 'falco')
            self.assertEqual(st, 200, other)
            st, got = self.settings(session=card, admin_certlogin=0)
            self.assertEqual(st, 200, got)
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            self.assertEqual(st, 200, got)
            type(self).admin = got['token']
            st, x = self.call('GET', '/api/auth/whoami', None, other['token'])
            self.assertFalse(x.get('who'), x)
            st, x = self.call('GET', '/api/auth/whoami', None, card)
            self.assertEqual(x['who']['name'], 'nested', x)
        finally:
            self.back_to_passwords()
            self.on(admin_certlogin=0)

    def test_09_the_portal_by_itself(self):
        self.put()
        self.on(admin_certlogin=0, portal_certlogin=1)
        try:
            st, got = self.sign('admin', 'nested')
            self.assertEqual(st, 404, got)
            st, got = self.sign('portal', 'falco')
            self.assertEqual(st, 200, got)
            self.assertEqual(got['how'], 'certificate')
            self.assertEqual(got['name'], 'falco@corpnet.cz')
            st, me = self.call('GET', '/api/portal/me', None, got['token'])
            self.assertEqual(me['me']['name'], 'falco@corpnet.cz', me)
            # Who may sign in decides: outsider is in no group of the portal.
            self.refused('portal', 'outsider', 'not allowed', 'in none of the groups')
            self.refused('portal', 'falco-rev', 'revoked')
            st, h = self.call('GET', '/api/health')
            self.assertFalse(h['certlogin']['on'])
            lsn = self.serving(path='/api/portal/info')
            try:
                st, info = self.call('GET', '/api/portal/info')
            finally:
                lsn.close()
            self.assertEqual(info['certlogin'], {'on': True, 'ready': True, 'auto': False,
                                                 'only': False, 'port': 8443})
            want = self.py('print(json.dumps(E.certlogin_desired(st)))')
            self.assertEqual((want['admin'], want['portal']), (False, True))
        finally:
            self.on(portal_certlogin=0)

    def test_10_try_my_certificate(self):
        self.put()
        self.on(admin_certlogin=0)
        st, got = self.call('POST', '/api/certlogin/try', {'cert': self.pem('nested'), 'part': 'admin'}, None)
        self.assertEqual(st, 401, got)
        got = self.ok('POST', '/api/certlogin/try', {'cert': self.pem('nested'), 'part': 'admin',
                                                     'once': secrets.token_hex(16)},
                      session=self.ro)
        self.assertEqual((got['ok'], got['name'], got['role'], got['on']),
                         (True, 'nested', 'fulladmin', False))
        st, got2 = self.call('POST', '/api/certlogin/try', {'cert': self.pem('outsider'),
                                                            'part': 'portal',
                                                            'once': secrets.token_hex(16)}, self.ro)
        self.assertFalse(got2['ok'])
        self.assertIn('none of the groups', got2['said'])
        # Nobody signed in by it; the card reads it back (its own only).
        v = self.ok('GET', '/api/certlogin', args={'tried': got['id']}, session=self.ro)
        self.assertEqual(v['tried']['name'], 'nested')
        v = self.ok('GET', '/api/certlogin', args={'tried': got['id']}, session=self.admin)
        self.assertNotIn('tried', v)

    def test_11_cli_and_configuration(self):
        got = self.cli('--cert-login-ca', os.path.join(self.pki, 'falco.pem'))
        self.assertNotEqual(got.returncode, 0)
        got = self.cli('--cert-login-ca', os.path.join(self.pki, 'cas.pem'), '--json')
        self.assertEqual(got.returncode, 0, got.stderr)
        got = self.cli('--cert-login')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('Corpnet Issuing CA', got.stdout)
        self.assertIn('8443', got.stdout)
        v = json.loads(self.cli('--cert-login', '--json').stdout)
        self.assertEqual(len(v['cas']), 2)
        # "No password at all" never from the command line.
        got = self.cli('--set', 'admin_password_off=1')
        self.assertNotEqual(got.returncode, 0)
        # Exported with the configuration; a configuration without them takes nothing away
        # unless it replaces.
        conf = self.py('print(json.dumps(E.config_export(st, False).get("certlogin")))')
        self.assertEqual(len(conf['cas']), 2)
        self.assertTrue(all('BEGIN CERTIFICATE' in c['pem'] for c in conf['cas']))
        sha = v['cas'][0]['sha256']
        got = self.cli('--cert-login-ca-off', sha[:16], '--yes')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(len(json.loads(self.cli('--cert-login', '--json').stdout)['cas']), 1)
        self.put()

    def test_12_through_the_pages(self):
        """web/admin/index.php and web/index.php through php -S, as nginx hands them the
        certificate on the port (ACME_CERT_*): the nonce, the cookie, back to 443."""
        if not shutil.which('php'):
            self.skipTest('no php here')
        self.put()
        web = tempfile.mkdtemp(prefix='acme-cert-web-')
        shutil.rmtree(web)
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        # The router plays nginx: X-Test-Port: 1 makes the request one of the certificate's port,
        # X-Test-Cert its certificate (escaped as $ssl_client_escaped_cert), X-Test-Fail 495.
        with open(os.path.join(web, 'router.php'), 'w') as f:
            f.write("<?php\n$p = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);\n"
                    "$_SERVER['HTTPS'] = 'on';\n"
                    "if (($_SERVER['HTTP_X_TEST_PORT'] ?? '') === '1') { $_SERVER['ACME_CERT_PORT'] = '1';"
                    " $_SERVER['ACME_CERT_PART'] = $p === '/' ? 'portal' : 'admin';"
                    " $_SERVER['ACME_CERT_PEM'] = (string) ($_SERVER['HTTP_X_TEST_CERT'] ?? '');"
                    " $_SERVER['ACME_CERT_VERIFY'] = (string) ($_SERVER['HTTP_X_TEST_VERIFY'] ?? 'NONE');"
                    " if (($_SERVER['HTTP_X_TEST_FAIL'] ?? '') === '1') { $_SERVER['ACME_CERT_FAIL'] = '1'; } }\n"
                    "if ($p === '/' || $p === '/index.php') { chdir(__DIR__); require __DIR__ . '/index.php'; return true; }\n"
                    "if ($p === '/admin/') { chdir(__DIR__ . '/admin'); require __DIR__ . '/admin/index.php'; return true; }\n"
                    "return false;\n")
        port = free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port, 'router.php'], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='2'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None
        opener = urllib.request.build_opener(NoRedirect)

        def go(path, method='GET', body=None, cookies=(), headers=None):
            req = urllib.request.Request('http://127.0.0.1:%d%s' % (port, path),
                                         data=json.dumps(body).encode() if body is not None else None,
                                         method=method)
            req.add_header('Host', HOST + (':8443' if (headers or {}).get('X-Test-Port') else ''))
            if body is not None:
                req.add_header('Content-Type', 'application/json')
            if cookies:
                req.add_header('Cookie', '; '.join(cookies))
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            try:
                with opener.open(req, timeout=60) as r:
                    return r.status, r.headers, r.read().decode('utf-8', 'replace')
            except urllib.error.HTTPError as e:
                return e.code, e.headers, e.read().decode('utf-8', 'replace')

        def jar(headers):
            return [c.split(';')[0] for c in headers.get_all('Set-Cookie') or []
                    if c.split(';')[0].split('=', 1)[1]]

        def bound(headers, part):
            name = '__Host-acme_certn_%s=' % part
            return [c for c in jar(headers) if c.startswith(name)][0]

        def port_get(path, n, cert, cookies, fail=False):
            hd = {'X-Test-Port': '1', 'X-Test-Cert': urllib.parse.quote(self.pem(cert)) if cert else ''}
            if fail:
                hd.update({'X-Test-Fail': '1', 'X-Test-Verify': 'FAILED:certificate has expired'})
            return go(path % n, cookies=cookies, headers=hd)

        try:
            for _ in range(50):
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/nothing' % port, timeout=2)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.1)
            # Off: no button, no nonce.
            self.on(admin_certlogin=0, portal_certlogin=0)
            st, hd, body = go('/admin/')
            self.assertNotIn('id="cert-box"', body)
            st, hd, body = go('/admin/?api=cert-nonce', 'POST', {})
            self.assertEqual(st, 404, body)
            # On: the button; the nonce in an HttpOnly SameSite=Strict cookie of the page's path.
            self.on(admin_certlogin=1)
            st, hd, body = go('/admin/')
            self.assertIn('id="cert-box"', body)
            self.assertIn('id="in-pass"', body)
            self.assertNotIn('id="cert-box"', go('/')[2])
            st, hd, body = go('/admin/?api=cert-nonce', 'POST', {})
            self.assertEqual(st, 200, body)
            url = json.loads(body)['url']
            self.assertTrue(url.startswith('https://%s:8443/admin/?api=cert-login&n=' % HOST), url)
            # The nonce bound to a random value of its own in a __Host- cookie of this browser
            # (path /, no Domain: no sibling name can plant one) - never the nonce itself.
            raw = [c for c in hd.get_all('Set-Cookie') if c.startswith('__Host-acme_certn_admin=')][0]
            for want in ('HttpOnly', 'SameSite=Strict', 'secure', 'path=/;', 'Max-Age=300'):
                self.assertIn(want.lower(), raw.lower() + ';')
            self.assertNotIn('domain=', raw.lower())
            n = url.split('n=', 1)[1]
            cookie = bound(hd, 'admin')
            self.assertNotIn(n.split('.')[0], cookie)
            # On 443 the sign-in itself is no endpoint at all.
            self.assertEqual(go('/admin/?api=cert-login&n=' + n)[0], 404)
            # No nonce, a wrong one, another browser's cookie: refused, the daemon not asked.
            for path, cookies in (('/admin/?api=cert-login&n=%s', []),
                                  ('/admin/?api=cert-login&n=%s', ['__Host-acme_certn_admin=' + 'a' * 32]),
                                  ('/admin/?api=cert-login&n=%s', ['acme_certn_admin=' + n]),
                                  ('/admin/?api=cert-login&n=%s', [cookie[:-4] + 'ffff'])):
                st, hd, _ = port_get(path, n, 'nested', cookies)
                self.assertEqual(st, 303)
                self.assertEqual(hd['Location'], 'https://%s/admin/?certsaid=nonce' % HOST)
                self.assertFalse(any(c.startswith('__Host-acme_session=') for c in jar(hd)))
            # The right one: signed in, the cookie (no port in it), back on 443.
            st, hd, _ = port_get('/admin/?api=cert-login&n=%s', n, 'nested', [cookie])
            self.assertEqual((st, hd['Location']), (303, 'https://%s/admin/' % HOST))
            sess = [c for c in jar(hd) if c.startswith('__Host-acme_session=')]
            self.assertEqual(len(sess), 1, hd.get_all('Set-Cookie'))
            raw = [c for c in hd.get_all('Set-Cookie') if c.startswith('__Host-acme_session=')][0]
            self.assertIn('HttpOnly', raw)
            self.assertIn('SameSite=Strict', raw)
            self.assertNotIn('8443', raw)
            # __Host- over https (1.0.101): Secure, Path=/, no Domain.
            self.assertIn('secure', raw.lower())
            self.assertIn('path=/;', raw.lower() + ';')
            self.assertNotIn('domain', raw.lower())
            st, me = self.call('GET', '/api/auth/whoami', None, sess[0].split('=', 1)[1])
            self.assertEqual((me['who']['name'], me['who']['how']), ('nested', 'certificate'))
            # The nonce once only: the cookie went with it - and sent again with the cookie kept
            # (another tab, a replay), the daemon refuses it: it keeps the nonce (review F7).
            self.assertIn('__Host-acme_certn_admin=;', ' '.join(hd.get_all('Set-Cookie')).replace('=deleted;', '=;'))
            st, hd, _ = port_get('/admin/?api=cert-login&n=%s', n, 'nested', [cookie])
            self.assertEqual(hd['Location'], 'https://%s/admin/?certsaid=certificate' % HOST)
            self.assertFalse(any(c.startswith('__Host-acme_session=') for c in jar(hd)))
            self.assertTrue(any('used already' in w for w in self.events('used already')))
            # A nonce of another browser (an attacker's, the cookie planted): its MAC is bound to
            # that browser's own value - refused.
            st, hd2, body = go('/admin/?api=cert-nonce', 'POST', {})
            n_other = json.loads(body)['url'].split('n=', 1)[1]
            st, hd, body = go('/admin/?api=cert-nonce', 'POST', {})
            st, hd, _ = port_get('/admin/?api=cert-login&n=%s', n_other, 'falco', [bound(hd, 'admin')])
            self.assertEqual(hd['Location'], 'https://%s/admin/?certsaid=nonce' % HOST)
            # Refused: back to 443 with the kind only.
            for cert, kind, fail in (('falco-rev', 'revoked', False), ('outsider', 'allowed', False),
                                     ('stranger', 'certificate', False), (None, 'certificate', False),
                                     ('falco-old', 'expired', True)):
                st, hd, body = go('/admin/?api=cert-nonce', 'POST', {})
                n = json.loads(body)['url'].split('n=', 1)[1]
                st, hd, _ = port_get('/admin/?api=cert-login&n=%s', n, cert, [bound(hd, 'admin')], fail)
                self.assertEqual(hd['Location'], 'https://%s/admin/?certsaid=%s' % (HOST, kind), cert)
                self.assertFalse(any(c.startswith('__Host-acme_session=') for c in jar(hd)))
            # The port serves the sign-in only, even with the page's other names asked.
            for q in ('/admin/', '/admin/?api=settings', '/admin/?api=whoami&n=' + n):
                st, hd, body = go(q, headers={'X-Test-Port': '1'})
                self.assertEqual(st, 404, q)
            # The portal by itself (its own nonce, its own cookie, its own part).
            self.on(portal_certlogin=1)
            st, hd, body = go('/?api=cert-nonce', 'POST', {})
            url = json.loads(body)['url']
            self.assertTrue(url.startswith('https://%s:8443/?api=cert-login&n=' % HOST), url)
            n = url.split('n=', 1)[1]
            # The portal's nonce with the admin's cookie: no portal's.
            st, hd, _ = port_get('/?api=cert-login&n=%s', n, 'falco',
                                 [bound(hd, 'portal').replace('_portal=', '_admin=')])
            self.assertEqual(hd['Location'], 'https://%s/?certsaid=nonce' % HOST)
            st, hd, body = go('/?api=cert-nonce', 'POST', {})
            n = json.loads(body)['url'].split('n=', 1)[1]
            st, hd, _ = port_get('/?api=cert-login&n=%s', n, 'falco', [bound(hd, 'portal')])
            self.assertEqual(hd['Location'], 'https://%s/' % HOST)
            self.assertTrue(any(c.startswith('__Host-acme_portal=') for c in jar(hd)))
            # Try my certificate: from the card (signed in), through the port, back to the card.
            st, hd, body = go('/admin/?api=cert-try-nonce', 'POST', {'part': 'portal'},
                              cookies=['__Host-acme_session=' + self.ro])
            self.assertEqual(st, 200, body)
            url = json.loads(body)['url']
            self.assertIn('api=cert-try&n=', url)
            self.assertTrue(url.endswith('&part=portal'))
            n = url.split('n=', 1)[1].split('&')[0]
            st, hd, _ = go('/admin/?api=cert-try&n=%s&part=portal' % n, cookies=[
                bound(hd, 'admin'), '__Host-acme_session=' + self.ro], headers={
                'X-Test-Port': '1', 'X-Test-Cert': urllib.parse.quote(self.pem('falco'))})
            m = re.match(r'^https://%s/admin/\?certtried=([0-9a-f]{24})#settings/portal$' % re.escape(HOST),
                         hd['Location'])
            self.assertTrue(m, hd['Location'])
            v = self.ok('GET', '/api/certlogin', args={'tried': m.group(1)}, session=self.ro)
            self.assertEqual((v['tried']['ok'], v['tried']['name']), (True, 'falco@corpnet.cz'))
            self.assertFalse(any(c.startswith('__Host-acme_session=') for c in jar(hd)))
            # "No password at all": no password field, the button only.
            st, got = self.sign('admin', 'nested')
            st, got = self.settings(session=got['token'], admin_password_off=1)
            self.assertEqual(st, 200, got)
            try:
                body = go('/admin/')[2]
                self.assertNotIn('id="in-pass"', body)
                self.assertIn('id="cert-go"', body)
            finally:
                self.back_to_passwords()
        finally:
            self.on(admin_certlogin=0, portal_certlogin=0)
            php.terminate()
            php.wait(10)
            shutil.rmtree(web, ignore_errors=True)

    def test_13_real_nginx(self):
        """A real nginx on the certificate's port, with the servers the root helper writes, and
        php-fpm with the pages: the authorities' names sent, 443 asking nobody, nothing but the
        sign-in served, an expired certificate (nginx's 495) to the page, signed in."""
        fpm = shutil.which('php-fpm') or next((p for p in ('/usr/sbin/php-fpm8.3', '/usr/sbin/php-fpm8.2',
                                                           '/usr/sbin/php-fpm') if os.path.exists(p)), None)
        if not shutil.which('nginx') or not fpm:
            self.skipTest('no nginx or php-fpm here')
        self.put()
        self.on(admin_certlogin=1, portal_certlogin=1, certlogin_port=8443)
        d = tempfile.mkdtemp(prefix='acme-cert-nginx-')
        procs = []
        try:
            web = os.path.join(d, 'www')
            shutil.copytree(os.path.join(ROOT, 'web'), web)
            api_php = os.path.join(web, 'acme-api.php')
            with open(api_php, encoding='utf-8') as f:
                text = f.read()
            with open(api_php, 'w', encoding='utf-8') as f:
                f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
            sock = os.path.join(d, 'fpm.sock')
            with open(os.path.join(d, 'fpm.conf'), 'w') as f:
                f.write('[global]\nerror_log = %s/fpm.log\n[www]\nlisten = %s\npm = static\n'
                        'pm.max_children = 3\nclear_env = no\nuser = root\ngroup = root\nlisten.mode = 0666\n'
                        % (d, sock))
            procs.append(subprocess.Popen([fpm, '-F', '-R', '-y', os.path.join(d, 'fpm.conf')],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            # The root helper's own functions, as root would run them: acme.conf of the package
            # (its 443 server, the names and certificate of this test), then the port's servers.
            spec = importlib.util.spec_from_file_location('acme_web_t', os.path.join(ROOT, 'deploy', 'acme_web.py'))
            W = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(W)
            W.CERTLOGIN_CA = os.path.join(d, 'certlogin-ca.pem')
            with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as f:
                main = f.read()
            main = main.replace('acme.example.local', HOST) \
                .replace('/etc/nginx/certs/acme.pem', os.path.join(self.pki, 'web-chain.pem')) \
                .replace('/etc/nginx/certs/acme.key', os.path.join(self.pki, 'web.key')) \
                .replace('unix:/run/php-fpm/acme.sock', 'unix:' + sock) \
                .replace('/var/www/acme', web).replace('/var/log/nginx/', d + '/')
            want = self.py('print(json.dumps(E.certlogin_desired(st)))')
            c = W.certlogin_checked(want)
            cert_conf = re.sub(r'include\s+fastcgi_params;', 'include /etc/nginx/fastcgi_params;',
                               W.certlogin_text(main, None, c))
            main = re.sub(r'include\s+fastcgi_params;', 'include /etc/nginx/fastcgi_params;', main)
            with open(W.CERTLOGIN_CA, 'w') as f:
                f.write(c['cas'])
            if not socket.has_ipv6 or not self._v6():
                cert_conf = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', cert_conf)
                main = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', main)
            p443, p80 = free_port(), free_port()
            main = re.sub(r'listen(\s+)443 ', r'listen\g<1>%d ' % p443, main)
            main = re.sub(r'listen(\s+)\[::\]:443 ', r'listen\g<1>[::]:%d ' % p443, main)
            main = re.sub(r'listen(\s+)80;', r'listen\g<1>%d;' % p80, main)
            main = re.sub(r'listen(\s+)\[::\]:80;', r'listen\g<1>[::]:%d;' % p80, main)
            with open(os.path.join(d, 'nginx.conf'), 'w') as f:
                f.write('pid %s/nginx.pid;\nerror_log %s/error.log;\nevents {}\nhttp {\n'
                        'include /etc/nginx/mime.types;\naccess_log %s/access.log;\n'
                        'client_body_temp_path %s;\nfastcgi_temp_path %s;\nproxy_temp_path %s;\n'
                        'scgi_temp_path %s;\nuwsgi_temp_path %s;\n%s\n%s\n}\n'
                        % (d, d, d, d, d, d, d, d, main, cert_conf))
            t = subprocess.run(['nginx', '-t', '-p', d, '-c', os.path.join(d, 'nginx.conf')],
                               capture_output=True, text=True)
            self.assertEqual(t.returncode, 0, t.stderr + cert_conf)
            procs.append(subprocess.Popen(['nginx', '-p', d, '-c', os.path.join(d, 'nginx.conf'),
                                           '-g', 'daemon off;'], stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL))
            for _ in range(50):
                if os.path.exists(sock) and self._open(8443):
                    break
                time.sleep(0.2)
            self.assertIn('ssl_verify_client      optional_no_ca', cert_conf)
            self.assertNotIn('ssl_verify_client', main)
            # The authorities' names sent on the port; 443 asks nobody.
            sc = subprocess.run(['openssl', 's_client', '-connect', '127.0.0.1:8443', '-servername', HOST],
                                input='', capture_output=True, text=True, timeout=30)
            self.assertIn('Acceptable client certificate CA names', sc.stdout)
            self.assertIn('Corpnet Issuing CA', sc.stdout)
            sc = subprocess.run(['openssl', 's_client', '-connect', '127.0.0.1:%d' % p443, '-servername', HOST],
                                input='', capture_output=True, text=True, timeout=30)
            self.assertIn('No client certificate CA names sent', sc.stdout)

            def ask(port, path, cert=None, cookies=(), method='GET', body=None):
                ctx = ssl.create_default_context(cafile=os.path.join(self.pki, 'root.pem'))
                ctx.check_hostname = False
                if cert:
                    ctx.load_cert_chain(os.path.join(self.pki, cert + '.pem'), os.path.join(self.pki, cert + '.key'))
                import http.client
                conn = http.client.HTTPSConnection('127.0.0.1', port, context=ctx, timeout=60)
                hd = {'Host': HOST + ('' if port == p443 else ':%d' % port)}
                if cookies:
                    hd['Cookie'] = '; '.join(cookies)
                if body is not None:
                    hd['Content-Type'] = 'application/json'
                    hd['Sec-Fetch-Site'] = 'same-origin'
                conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=hd)
                r = conn.getresponse()
                out = (r.status, r.getheaders(), r.read().decode('utf-8', 'replace'))
                conn.close()
                return out

            def hget(headers, name):
                return [v for k, v in headers if k.lower() == name.lower()]

            def nonce(page='/admin/'):
                st, hd, body = ask(p443, page + '?api=cert-nonce', method='POST', body={})
                self.assertEqual(st, 200, body)
                url = json.loads(body)['url']
                # The path on the port, and the __Host- cookie that binds its nonce to this browser.
                return url.split(':8443', 1)[1], [c.split(';')[0] for c in hget(hd, 'Set-Cookie')
                                                  if c.startswith('__Host-acme_certn_')][0]
            # Nothing but the sign-in on the port.
            for path in ('/', '/admin/', '/admin/?api=settings', '/assets/core.js', '/healthz',
                         '/admin/?api=cert-login&n=1&api=settings', '/index.php', '/pki/'):
                st, hd, body = ask(8443, path, 'nested')
                self.assertEqual(st, 404, path)
            # Signed in, back on 443.
            path, n = nonce()
            st, hd, body = ask(8443, path, 'nested', [n])
            self.assertEqual((st, hget(hd, 'Location')), (303, ['https://%s/admin/' % HOST]), body)
            sess = [c.split(';')[0] for c in hget(hd, 'Set-Cookie') if c.startswith('__Host-acme_session=')]
            self.assertEqual(len(sess), 1)
            st, hd, body = ask(p443, '/admin/', cookies=sess)
            self.assertIn('id="signout"', body)
            # No certificate at all: refused, said.
            path, n = nonce()
            st, hd, body = ask(8443, path, None, [n])
            self.assertEqual(hget(hd, 'Location'), ['https://%s/admin/?certsaid=certificate' % HOST])
            # Expired: nginx refuses it itself (495) - the page says why.
            path, n = nonce()
            st, hd, body = ask(8443, path, 'falco-old', [n])
            self.assertEqual(hget(hd, 'Location'), ['https://%s/admin/?certsaid=expired' % HOST])
            # Another authority's (nginx lets it through with optional_no_ca; acme refuses it).
            path, n = nonce()
            st, hd, body = ask(8443, path, 'stranger', [n])
            self.assertEqual(hget(hd, 'Location'), ['https://%s/admin/?certsaid=certificate' % HOST])
            # The portal on the same port.
            path, n = nonce('/')
            st, hd, body = ask(8443, path, 'falco', [n])
            self.assertEqual(hget(hd, 'Location'), ['https://%s/' % HOST], body)
            self.assertTrue(any(c.startswith('__Host-acme_portal=') for c in hget(hd, 'Set-Cookie')))
        finally:
            for p in procs:
                p.terminate()
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    p.kill()
            self.on(admin_certlogin=0, portal_certlogin=0)
            shutil.rmtree(d, ignore_errors=True)

    # ---- the security review of 1.0.100 (F1-F8) ------------------------------------------------
    def engine(self, body, **kv):
        """Code run with the engine against the test's PKI (its CRLs served): `P` the PKI's
        folder, go(name, cas='cas', crl=True) 'ok' or the kind refused (and `why` its words),
        ca(...) openssl ca of the issuing authority, pub(src, dst) a CRL put at its CDP,
        later() the CRLs kept as if CL_CRL_FRESH_S had gone by."""
        head = ('import os, subprocess\nP = %r\nWHY = {}\n'
                'def go(n, cas="cas", crl=True):\n'
                '    try:\n'
                '        E.cl_check(open(os.path.join(P, n + ".pem")).read(), os.path.join(P, cas + ".pem"), crl=crl)\n'
                '        return "ok"\n'
                '    except E.CertRefused as e:\n'
                '        WHY[n] = e.why\n'
                '        return e.kind\n'
                'def ca(*a, cnf="ca.cnf"):\n'
                '    subprocess.run(["openssl", "ca", "-config", cnf] + list(a), cwd=P, check=True,\n'
                '                   capture_output=True, env=dict(os.environ, UPN="x", SID="x"))\n'
                'def pub(src, dst):\n'
                '    subprocess.run(["openssl", "crl", "-in", src, "-outform", "DER", "-out", dst], cwd=P, check=True)\n'
                'def later():\n'
                '    for c in E.CL_CRL_CACHE.values():\n'
                '        c["at"] -= E.CL_CRL_FRESH_S + 1\n' % self.pki)
        return self.py(head + body % kv)

    def test_20_sid_only_from_its_extension(self):
        """F1: the SID of the SAN (an otherName 1.3.6.1.4.1.311.25.2.1, or the URL form) is the
        requester's word - never strong; one that is not the extension's or the account's is
        refused."""
        self.put()
        self.on(admin_certlogin=1)
        try:
            self.assertEqual(self.py('print(json.dumps(E.cl_match("admin")))'), 'strong')
            # ESC1: nested's UPN and nested's SID - in the SAN only.
            self.refused('admin', 'esc1', 'not allowed', 'no SID extension')
            self.refused('admin', 'falco-sansid', 'not allowed', 'not taken for it')
            # The URL form against the extension: refused whatever the matching.
            self.refused('admin', 'falco-sanurl', 'certificate not accepted', 'not the one of its SID extension')
            self.assertEqual(self.sign('admin', 'falco')[0], 200)
            self.on(admin_certlogin_match='compat')
            # compat: taken by its UPN (as one without a SID), but a SAN SID of another account
            # is refused.
            self.assertEqual(self.sign('admin', 'falco-sansid')[0], 200)
            self.refused('admin', 'falco-sansid2', 'not allowed', 'in the Subject Alternative Name')
            self.refused('admin', 'falco-sanurl', 'certificate not accepted')
            v = self.ok('GET', '/api/certlogin')
            self.assertIn('Not strong', v['parts']['admin']['match_warn'])
        finally:
            self.on(admin_certlogin=0, admin_certlogin_match='strong')
        v = self.ok('GET', '/api/certlogin')
        self.assertEqual(v['parts']['admin']['match_warn'], '')

    def test_21_every_upn(self):
        """F6: all the UPNs before anything is cut: four of falco and a fifth of nested."""
        self.put()
        self.on(admin_certlogin=1)
        try:
            self.refused('admin', 'five', 'certificate not accepted', 'more than one user')
        finally:
            self.on(admin_certlogin=0)

    def test_22_revocation_within_ten_minutes(self):
        """F3: the CRL kept CL_CRL_FRESH_S (ten minutes) at most - a revocation the authority
        publishes is seen within it; the delta CRL (Freshest CRL) fetched and applied; one named
        and not to be had, no sign-in; the CDP down - the last good CRL until its next update."""
        got = self.engine('''
out = {"cap": E.CL_CRL_FRESH_S}
out["lost1"] = go("lost")
ca("-revoke", "lost.pem")
ca("-gencrl", "-out", "issuing.crl.pem")
pub("issuing.crl.pem", "www/issuing.crl")
out["lost2"] = go("lost")
later()
out["lost3"] = go("lost")
# The delta: the base CRL at its CDP as it is, the revocation in the delta only.
out["fresh1"] = go("fresh")
ca("-revoke", "fresh.pem")
base = subprocess.run(["openssl", "crl", "-in", "issuing.crl.pem", "-noout", "-crlnumber"], cwd=P,
                      capture_output=True, text=True).stdout.strip().split("=")[1]
with open(os.path.join(P, "delta.cnf"), "w") as f:
    f.write(open(os.path.join(P, "ca.cnf")).read() + "[delta_ext]\\n2.5.29.27 = critical,ASN1:INTEGER:%%s\\n" %% base)
ca("-gencrl", "-crlexts", "delta_ext", "-crldays", "1", "-out", "delta.crl.pem", cnf="delta.cnf")
pub("delta.crl.pem", "www/issuing-delta.crl")
later()
out["fresh2"] = go("fresh")
# The delta not to be had: no sign-in (fail closed).
os.rename(os.path.join(P, "www/issuing-delta.crl"), os.path.join(P, "www/delta-away.crl"))
E.CL_CRL_CACHE.clear()
out["nodelta"] = go("fresh")
os.rename(os.path.join(P, "www/delta-away.crl"), os.path.join(P, "www/issuing-delta.crl"))
# The CDP down: the last good CRL until its next update, then nothing.
E.CL_CRL_CACHE.clear()
out["falco1"] = go("falco")
os.rename(os.path.join(P, "www/issuing.crl"), os.path.join(P, "www/base-away.crl"))
later()
out["falco2"] = go("falco")
for c in E.CL_CRL_CACHE.values():
    c["next"] = time.time() - 1
out["falco3"] = go("falco")
os.rename(os.path.join(P, "www/base-away.crl"), os.path.join(P, "www/issuing.crl"))
out["why"] = WHY
print(json.dumps(out))
''')
        self.assertLessEqual(got['cap'], 600)
        self.assertEqual([got[k] for k in ('lost1', 'lost2', 'lost3')], ['ok', 'ok', 'revoked'])
        self.assertEqual([got[k] for k in ('fresh1', 'fresh2', 'nodelta')], ['ok', 'revoked', 'unavailable'])
        self.assertEqual([got[k] for k in ('falco1', 'falco2', 'falco3')], ['ok', 'ok', 'unavailable'])

    def test_23_the_authorities_revocation(self):
        """F4: every certificate of the chain checked against its CRL (-crl_check_all): an issuing
        authority its root revoked signs nobody in; the root, its own anchor, needs none."""
        got = self.engine('''
print(json.dumps([go("subling", "cas-sub"), go("subling", "cas-sub", False), go("falco"), WHY]))
''')
        self.assertEqual(got[:3], ['certificate', 'ok', 'ok'])
        self.assertIn('revoked (an authority above it)', got[3]['subling'])

    def test_24_where_a_crl_is_fetched_from(self):
        """F5: every address of a CDP's name checked as it is fetched (no loopback, link-local,
        metadata, multicast, unspecified - private addresses are AD CS's own), no redirect
        followed, the size and the time limited."""
        got = self.engine('''
import http.server, threading
os.environ.pop("ACME_CDP_LOOPBACK_OK", None)
static = {u: E.cl_cdp_ok(u) for u in (
    "http://pki.corp.example/x.crl", "http://10.1.2.3/x.crl", "http://192.168.1.1/x.crl",
    "http://[fd12::1]/x.crl", "https://pki.corp.example/x.crl", "ldap:///CN=x", "http://u:p@pki/x.crl",
    "http://169.254.169.254/latest", "http://metadata.google.internal/x", "http://[fe80::1]/x",
    "http://0.0.0.0/x", "http://224.0.0.1/x", "http://127.0.0.1/x", "http://[::1]/x",
    "http://[::ffff:169.254.169.254]/x", "http://100.100.100.200/x")}
def get(u):
    try:
        E.cl_http_get(u)
        return "ok"
    except ValueError as e:
        return str(e)
fetched = {u: get(u) for u in ("http://localhost:%(port)d/issuing.crl", "http://2852039166/x.crl",
                               "http://0251.0376.0251.0376/x.crl", "http://127.1:%(port)d/issuing.crl")}
os.environ["ACME_CDP_LOOPBACK_OK"] = "1"
class R(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.end_headers()
srv = http.server.HTTPServer(("127.0.0.1", 0), R)
threading.Thread(target=srv.serve_forever, daemon=True).start()
fetched["redirect"] = get("http://127.0.0.1:%%d/x.crl" %% srv.server_address[1])
fetched["good"] = get("http://127.0.0.1:%(port)d/issuing.crl")
E.CL_CRL_MOST = 100
fetched["big"] = get("http://127.0.0.1:%(port)d/issuing.crl")
print(json.dumps([static, fetched]))
''', port=self.crl_port)
        static, fetched = got
        for u in ('http://pki.corp.example/x.crl', 'http://10.1.2.3/x.crl', 'http://192.168.1.1/x.crl',
                  'http://[fd12::1]/x.crl'):
            self.assertTrue(static[u], u)
        for u, ok in static.items():
            if u not in ('http://pki.corp.example/x.crl', 'http://10.1.2.3/x.crl',
                         'http://192.168.1.1/x.crl', 'http://[fd12::1]/x.crl'):
                self.assertFalse(ok, u)
        for u, words in fetched.items():
            if u == 'good':
                self.assertEqual(words, 'ok')
            elif u == 'redirect':
                self.assertIn('not followed', words)
            elif u == 'big':
                self.assertIn('larger than', words)
            else:
                self.assertRegex(words, r'\((loopback|link-local|a cloud.s metadata service)\) - no CRL', u)

    def test_25_name_constraints(self):
        """F8: openssl does not apply an authority's name constraints to the UPN - acme does
        (rfc822Name, dNSName): a partner's authority for partner.example signs in nobody of
        corpnet."""
        got = self.engine('''
v = subprocess.run(["openssl", "verify", "-no-CApath", "-no-CAstore", "-CAfile", os.path.join(P, "cas-nc.pem"),
                    os.path.join(P, "ncp.pem")], capture_output=True, text=True).stdout
print(json.dumps([go("ncp", "cas-nc", False), go("ncok", "cas-nc", False), WHY, v]))
''')
        self.assertEqual(got[:2], ['certificate', 'ok'])
        self.assertIn('outside the names the authority CN=Partner NC CA may issue for', got[2]['ncp'])
        self.assertIn(': OK', got[3])                    # what openssl alone says

    def test_26_sessions_end_with_their_rule(self):
        """F8: an authority taken away ends the sign-ins made with its certificates; revocation
        switched on, the matching made stricter, end those of that part - the doer's kept."""
        self.put()
        self.on(admin_certlogin=1, admin_certlogin_match='compat', admin_certlogin_crl=0)
        try:
            st, card = self.sign('admin', 'nested')
            self.assertEqual(st, 200, card)
            st, other = self.sign('admin', 'falco')
            self.assertEqual(st, 200, other)
            st, got = self.settings(session=card['token'], admin_certlogin_match='strong')
            self.assertEqual(st, 200, got)
            self.assertFalse(self.call('GET', '/api/auth/whoami', None, other['token'])[1].get('who'))
            self.assertEqual(self.call('GET', '/api/auth/whoami', None, card['token'])[1]['who']['name'],
                             'nested')
            self.assertTrue(any('made with a certificate ended' in w and 'more strictly' in w
                                for w in self.events('more strictly')))
            st, other = self.sign('admin', 'falco')
            self.on(admin_certlogin_crl=1)
            self.assertFalse(self.call('GET', '/api/auth/whoami', None, other['token'])[1].get('who'))
            # Made looser: nothing ends.
            st, other = self.sign('admin', 'falco')
            self.on(admin_certlogin_match='upn')
            self.assertTrue(self.call('GET', '/api/auth/whoami', None, other['token'])[1].get('who'))
            # The root taken away (the issuing one stays): its sign-ins end.
            v = self.ok('GET', '/api/certlogin')
            root = [c['sha256'] for c in v['cas'] if 'Root' in c['subject']][0]
            st, got = self.call('POST', '/api/certlogin', {'action': 'drop', 'sha256': root}, self.admin)
            self.assertEqual(st, 200, got)
            self.assertFalse(self.call('GET', '/api/auth/whoami', None, other['token'])[1].get('who'))
            self.assertTrue(any('was taken away' in w for w in self.events('was taken away')))
        finally:
            self.put()
            self.on(admin_certlogin=0, admin_certlogin_match='strong', admin_certlogin_crl=1)

    def test_27_the_nonce_once(self):
        """F7: the page's nonce once in the whole cluster - kept by the daemon, not only by the
        browser's cookie going."""
        self.put()
        self.on(admin_certlogin=1)
        try:
            once = secrets.token_hex(16)
            st, got = self.call('POST', '/api/auth/cert', {'cert': self.pem('nested'), 'once': once})
            self.assertEqual(st, 200, got)
            st, got = self.call('POST', '/api/auth/cert', {'cert': self.pem('nested'), 'once': once})
            self.assertEqual((st, got.get('error')), (401, REFUSED + 'certificate not accepted'), got)
            st, got = self.call('POST', '/api/auth/cert', {'cert': self.pem('nested')})
            self.assertEqual((st, got.get('error')), (401, REFUSED + 'certificate not accepted'), got)
            words = self.events('nonce of the page')
            self.assertTrue(any('used already' in w for w in words), words)
            self.assertTrue(any('no nonce of the page' in w for w in words), words)
        finally:
            self.on(admin_certlogin=0)

    def test_28_an_nginx_not_acmes(self):
        """F8: the port taken by a process named nginx that is not the system's (its pid file
        names another master): refused like any other program; the system's own is not."""
        d = tempfile.mkdtemp(prefix='acme-nginx-name-')
        os.symlink(sys.executable, os.path.join(d, 'nginx'))
        with open(os.path.join(d, 'listen.py'), 'w') as f:
            f.write('import socket, time\ns = socket.socket()\ns.bind(("127.0.0.1", 0))\ns.listen(1)\n'
                    'print(s.getsockname()[1], flush=True)\ntime.sleep(120)\n')
        proc = subprocess.Popen([os.path.join(d, 'nginx'), os.path.join(d, 'listen.py')],
                                stdout=subprocess.PIPE, text=True)
        try:
            port = int(proc.stdout.readline())
            pidfile = os.path.join(d, 'nginx.pid')
            with open(pidfile, 'w') as f:
                f.write('%d\n' % proc.pid)
            got = self.py('E.CL_NGINX_PID_FILES[:] = [%r]\na = E.cl_port_busy(%d)\n'
                          'E.CL_NGINX_PID_FILES[:] = [%r]\nb = E.cl_port_busy(%d)\n'
                          'print(json.dumps([a, b]))' % (pidfile + '.none', port, pidfile, port))
            self.assertIn('nginx that is not acme', got[0])
            self.assertEqual(got[1], '')
            spec = importlib.util.spec_from_file_location('acme_web_n', os.path.join(ROOT, 'deploy', 'acme_web.py'))
            W = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(W)
            W.NGINX_PID_FILES = [pidfile + '.none']
            self.assertIn('not the system', W.certlogin_busy(port, 'testnode'))
            W.NGINX_PID_FILES = [pidfile]
            self.assertEqual(W.certlogin_busy(port, 'testnode'), '')
        finally:
            proc.kill()
            proc.wait(10)
            proc.stdout.close()
            shutil.rmtree(d, ignore_errors=True)

    @staticmethod
    def _v6():
        try:
            s = socket.socket(socket.AF_INET6)
            s.close()
            return True
        except OSError:
            return False

    @staticmethod
    def _open(port):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                return True
        except OSError:
            return False

    def test_15_port_taken_by_another_program(self):
        """A port something else listens on (a WAF's agent, another web server): refused at the
        save with the program named, said per node on the card, and the root helper gives nginx
        nothing for it."""
        self.put()
        busy = socket.socket()
        busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        busy.bind(('0.0.0.0', 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        with open('/proc/self/comm') as f:
            me = f.read().strip()
        try:
            st, got = self.settings(certlogin_port=port, admin_certlogin=1)
            self.assertEqual(st, 400, got)
            self.assertIn('port %d is used by %s' % (port, me), got['error'])
            self.assertIn('choose another port', got['error'])
            # Switching a part on with the port taken: the same.
            self.on(certlogin_port=8443)
            words = self.py('print(json.dumps(E.cl_port_busy(%d)))' % port)
            self.assertIn(me, words)
            self.assertEqual(self.py('print(json.dumps(E.cl_port_busy(%d)))' % free_port()), '')
            # The root helper, as root runs it: nothing written, said why.
            spec = importlib.util.spec_from_file_location('acme_web_b', os.path.join(ROOT, 'deploy', 'acme_web.py'))
            W = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(W)
            self.assertIn(me, W.certlogin_busy(port, 'testnode'))
            self.assertEqual(W.certlogin_busy(free_port(), 'testnode'), '')
            self.assertIn((me, os.getpid()), W.certlogin_port_users(port))
        finally:
            busy.close()
            self.on(admin_certlogin=0, certlogin_port=8443)

    def test_16_by_itself_when_the_page_opens(self):
        """admin_certlogin_auto / portal_certlogin_auto (1.0.100): off by default, each part's
        own, said to the page only while the certificate is offered at all."""
        self.assertEqual(self.py('print(json.dumps([E.DEFAULTS["admin_certlogin_auto"], '
                                 'E.DEFAULTS["portal_certlogin_auto"]]))'), [0, 0])
        self.put()
        self.on(admin_certlogin_auto=1)
        try:
            st, h = self.call('GET', '/api/health')
            self.assertFalse(h['certlogin']['auto'], 'not while the certificate is off')
            self.on(admin_certlogin=1)
            # gone to by itself only while something answers on the port (hunt M round 3)
            self.not_serving()
            st, h = self.call('GET', '/api/health')
            self.assertEqual(h['certlogin'], {'on': True, 'ready': False, 'auto': False,
                                              'only': False, 'port': 0})
            lsn = self.serving()
            try:
                st, h = self.call('GET', '/api/health')
            finally:
                lsn.close()
            self.assertEqual(h['certlogin'], {'on': True, 'ready': True, 'auto': True, 'only': False,
                                              'port': 8443})
            self.assertEqual({k: h['signin'][k] for k in ('password', 'windows', 'certificate', 'order')},
                             {'password': True, 'windows': 'off', 'certificate': 'auto',
                              'order': ['certificate']})
            st, info = self.call('GET', '/api/portal/info')
            self.assertFalse(info['certlogin']['auto'], 'the portal has its own switch')
            self.on(portal_certlogin=1)
            st, info = self.call('GET', '/api/portal/info')
            self.assertEqual(info['signin']['certificate'], 'button')
            self.on(portal_certlogin_auto=1)
            st, info = self.call('GET', '/api/portal/info')
            self.assertEqual(info['signin']['certificate'], 'auto')
            v = self.ok('GET', '/api/certlogin')
            self.assertTrue(v['parts']['admin']['auto'])
            self.assertEqual(v['parts']['portal']['signin']['order'], ['certificate'])
        finally:
            self.on(admin_certlogin=0, admin_certlogin_auto=0, portal_certlogin=0,
                    portal_certlogin_auto=0)

    def test_14_kerberos_untouched(self):
        """The shared code: a Kerberos sign-in's session and its words as before."""
        self.assertEqual(self.py('print(json.dumps(E.sso_only_said("admin")))'),
                         'only Windows: these pages take no password - sign in with Windows')
        self.assertTrue(self.py('print(json.dumps("Kerberos" in E.SSO_HOWS and "certificate" in E.SSO_HOWS))'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
