#!/usr/bin/env python3
"""The tests of what a server serves, protocol by protocol (1.0.32).

    python3 test/test_checks_protocols.py

For each module a small server of the test's own on 127.0.0.1 speaks the
protocol's plain start (SMTP, IMAP, POP3, FTP, LDAP, RDP, PostgreSQL, MySQL,
XMPP, TDS) and then TLS with a self-signed certificate made here: the module
must give back that very certificate, refuse it with verify=True, and say in
words what went wrong when the server does not go on to TLS. Nothing is
reached but 127.0.0.1.
"""
import datetime
import hashlib
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-checks-protocols-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.checks import (ftp, imap, implicit, ldap, mssql, mysql,  # noqa: E402
                                    pop3, postgres, rdp, smtp, tls, xmpp)



def self_signed():
    """A self-signed certificate for localhost, made with openssl (as the other tests)."""
    import subprocess
    cp, kp = os.path.join(TMP, 'cert.pem'), os.path.join(TMP, 'key.pem')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                    'ec_paramgen_curve:P-256', '-nodes', '-keyout', kp, '-out', cp, '-days', '30',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                   check=True, capture_output=True)
    der = subprocess.run(['openssl', 'x509', '-in', cp, '-outform', 'DER'], check=True,
                         capture_output=True).stdout
    return der, cp, kp


CERT_DER, CERT_PEM, KEY_PEM = self_signed()
SHA = hashlib.sha256(CERT_DER).hexdigest()
SERVER_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
SERVER_CTX.load_cert_chain(CERT_PEM, KEY_PEM)


# ---------------------------------------------------------------------------
# A server of the test's own: the plain start (a function), then TLS
# ---------------------------------------------------------------------------
class Lines(object):
    def __init__(self, conn):
        self.conn, self.buf = conn, b''

    def line(self):
        while b'\n' not in self.buf:
            got = self.conn.recv(4096)
            if not got:
                raise EOFError
            self.buf += got
        raw, _, self.buf = self.buf.partition(b'\n')
        return raw.rstrip(b'\r').decode()

    def send(self, *lines):
        self.conn.sendall(b''.join(x.encode() + b'\r\n' for x in lines))


def exact(conn, n):
    out = b''
    while len(out) < n:
        got = conn.recv(n - len(out))
        if not got:
            raise EOFError
        out += got
    return out


class Fake(object):
    """Accepts connections on 127.0.0.1 until stopped; start(conn) speaks the plain
    start and says True for TLS to follow (or does the TLS itself and says None)."""
    def __init__(self, start):
        self.start, self.seen = start, []
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            conn.settimeout(10)
            try:
                if self.start(conn, self) is True:
                    s = SERVER_CTX.wrap_socket(conn, server_side=True)
                    try:
                        s.recv(1)
                    except (OSError, ssl.SSLError):
                        pass
                    s.close()
            except (OSError, ssl.SSLError, EOFError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self.stop = True
        self.sock.close()


def implicit_start(conn, fake):
    return True


class Base(unittest.TestCase):
    def serve(self, start):
        f = Fake(start)
        self.addCleanup(f.close)
        return f

    def module(self, cls, **config):
        config.setdefault('timeout', 5)
        return cls(config, None)

    def works(self, cls, start, said=None, **config):
        """The certificate comes back with verify=False, verify=True refuses it."""
        f = self.serve(start)
        m = self.module(cls, **config)
        out = m.served('127.0.0.1', f.port, 'localhost', verify=False)
        self.assertEqual(hashlib.sha256(out['chain'][0]).hexdigest(), SHA)
        self.assertTrue(out['tls'].startswith('TLS'))
        self.assertTrue(out['cipher'])
        if said is not None:
            self.assertIn(said, out.get('said', ''))
        with self.assertRaises(ssl.SSLCertVerificationError):
            m.served('127.0.0.1', f.port, 'localhost', verify=True)
        return f, out

    def says(self, cls, start, *words, **config):
        f = self.serve(start)
        with self.assertRaises(PluginError) as e:
            self.module(cls, **config).served('127.0.0.1', f.port, 'localhost', verify=False)
        for w in words:
            self.assertIn(w, str(e.exception))
        return f, str(e.exception)


# ---------------------------------------------------------------------------
# The modules as modules
# ---------------------------------------------------------------------------
KINDS = {'tls', 'https', 'smtp', 'smtps', 'imap', 'imaps', 'pop3', 'pop3s', 'ftp', 'ftps',
         'ldap', 'ldaps', 'rdp', 'postgres', 'mysql', 'xmpp', 'mqtts', 'sips', 'dot', 'mssql'}
PORTS = {'smtp': 25, 'smtps': 465, 'imap': 143, 'imaps': 993, 'pop3': 110, 'pop3s': 995,
         'ftp': 21, 'ftps': 990, 'ldap': 389, 'ldaps': 636, 'rdp': 3389, 'postgres': 5432,
         'mysql': 3306, 'xmpp': 5222, 'mqtts': 8883, 'sips': 5061, 'dot': 853, 'mssql': 1433}
STARTTLS = {'smtp', 'imap', 'pop3', 'ftp', 'ldap', 'rdp', 'postgres', 'mysql', 'xmpp', 'mssql'}


class TestRegistry(unittest.TestCase):
    def test_all_found_and_described(self):
        r = Registry()
        r.reload()
        self.assertEqual([b for b in r.broken if 'checks' in b[0]], [])
        found = r.found['check']
        self.assertTrue(KINDS <= set(found), KINDS - set(found))
        for kind in KINDS - {'tls', 'https'}:
            cls = found[kind]
            d = cls.describe()
            self.assertEqual(cls.default_port, PORTS[kind], kind)
            self.assertEqual(d['starttls'], kind in STARTTLS, kind)
            self.assertTrue(cls.title and cls.protocol and cls.description, kind)
            port = [x for x in cls.fields if x['key'] == 'port'][0]
            self.assertEqual(port['default'], PORTS[kind], kind)
            self.assertTrue({'host', 'port', 'sni', 'timeout'} <=
                            {x['key'] for x in cls.fields}, kind)
        self.assertIn('domain', [x['key'] for x in found['xmpp'].fields])


class TestImplicit(Base):
    def test_each(self):
        for cls in (smtp.SmtpsCheck, imap.ImapsCheck, pop3.Pop3sCheck, ftp.FtpsCheck,
                    ldap.LdapsCheck, implicit.MqttsCheck, implicit.SipsCheck,
                    implicit.DotCheck):
            with self.subTest(cls.kind):
                self.assertTrue(issubclass(cls, tls.TlsCheck))
                self.works(cls, implicit_start)

    def test_closed_port(self):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        for cls in (smtp.SmtpCheck, ldap.LdapCheck, rdp.RdpCheck, postgres.PostgresCheck,
                    mssql.MssqlCheck, implicit.DotCheck):
            with self.subTest(cls.kind):
                with self.assertRaises(PluginError) as e:
                    self.module(cls).served('127.0.0.1', port, 'localhost', verify=False)
                self.assertIn('127.0.0.1:%d cannot be reached' % port, str(e.exception))

    def test_not_tls_at_all(self):
        def plain(conn, fake):
            conn.sendall(b'220 not TLS here\r\n')
            conn.recv(4096)
        self.says(implicit.MqttsCheck, plain, 'the TLS handshake failed')


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------
def smtp_server(offer=True, starttls_code='220'):
    def start(conn, fake):
        l = Lines(conn)
        l.send('220-mx.example.test ESMTP', '220 says hello in two lines')
        ehlo = l.line()
        fake.seen.append(ehlo)
        caps = ['250-mx.example.test greets you', '250-SIZE 52428800', '250-8BITMIME']
        if offer:
            caps.append('250-STARTTLS')
        caps.append('250 SMTPUTF8')
        l.send(*caps)
        cmd = l.line()
        fake.seen.append(cmd)
        if cmd != 'STARTTLS':
            l.send('502 no')
            return False
        l.send('%s 2.0.0 Ready to start TLS' % starttls_code)
        return starttls_code == '220'
    return start


class TestSmtp(Base):
    def test_starttls(self):
        f, out = self.works(smtp.SmtpCheck, smtp_server(), said='220-mx.example.test ESMTP')
        self.assertEqual(f.seen[:2], ['EHLO acme-check.localhost', 'STARTTLS'])

    def test_no_starttls(self):
        _, words = self.says(smtp.SmtpCheck, smtp_server(offer=False),
                             'the server does not offer STARTTLS (it said: 250-SIZE')
        self.assertNotIn('greets you', words)

    def test_refused(self):
        self.says(smtp.SmtpCheck, smtp_server(starttls_code='454'),
                  'refused STARTTLS', '454')

    def test_injected_bytes_refused(self):
        def start(conn, fake):
            l = Lines(conn)
            l.send('220 mx')
            l.line()
            l.send('250-mx', '250 STARTTLS')
            l.line()
            conn.sendall(b'220 go\r\n250 injected\r\n')
            return False
        self.says(smtp.SmtpCheck, start, 'more before TLS')

    def test_not_smtp(self):
        def start(conn, fake):
            conn.sendall(b'SSH-2.0-OpenSSH_9.6\r\n')
        self.says(smtp.SmtpCheck, start, 'does not speak SMTP', 'SSH-2.0')


# ---------------------------------------------------------------------------
# IMAP, POP3, FTP
# ---------------------------------------------------------------------------
def imap_server(offer=True):
    def start(conn, fake):
        l = Lines(conn)
        l.send('* OK [CAPABILITY IMAP4rev1] Dovecot ready.')
        fake.seen.append(l.line())
        l.send('* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ %s'
               'LOGINDISABLED' % ('STARTTLS ' if offer else ''), 'a1 OK Pre-login capabilities')
        cmd = l.line()
        fake.seen.append(cmd)
        if cmd != 'a2 STARTTLS':
            l.send('a2 BAD no')
            return False
        l.send('a2 OK Begin TLS negotiation now.')
        return True
    return start


def pop3_server(offer=True):
    def start(conn, fake):
        l = Lines(conn)
        l.send('+OK Dovecot ready.')
        fake.seen.append(l.line())
        if not offer:
            l.send('-ERR Unknown command.')
            return False
        l.send('+OK Begin TLS negotiation now.')
        return True
    return start


def ftp_server(offer=True):
    def start(conn, fake):
        l = Lines(conn)
        l.send('220-Welcome to the FTP server', '   of the example', '220 ProFTPD ready')
        fake.seen.append(l.line())
        if not offer:
            l.send('500 AUTH not understood')
            return False
        l.send('234 AUTH TLS successful')
        return True
    return start


class TestMail(Base):
    def test_imap(self):
        f, _ = self.works(imap.ImapCheck, imap_server(), said='Dovecot ready')
        self.assertEqual(f.seen[:2], ['a1 CAPABILITY', 'a2 STARTTLS'])

    def test_imap_no_starttls(self):
        self.says(imap.ImapCheck, imap_server(False),
                  'the server does not offer STARTTLS (it said: * CAPABILITY IMAP4rev1')

    def test_imap_preauth(self):
        def start(conn, fake):
            conn.sendall(b'* PREAUTH ready\r\n')
            conn.recv(100)
        self.says(imap.ImapCheck, start, 'PREAUTH')

    def test_pop3(self):
        f, _ = self.works(pop3.Pop3Check, pop3_server(), said='+OK Dovecot')
        self.assertEqual(f.seen[0], 'STLS')

    def test_pop3_no_stls(self):
        self.says(pop3.Pop3Check, pop3_server(False),
                  'does not offer STLS (it said: -ERR Unknown command.)')

    def test_ftp(self):
        f, _ = self.works(ftp.FtpCheck, ftp_server(), said='220-Welcome')
        self.assertEqual(f.seen[0], 'AUTH TLS')

    def test_ftp_no_auth_tls(self):
        self.says(ftp.FtpCheck, ftp_server(False),
                  'does not offer AUTH TLS (it said: 500 AUTH not understood)')


# ---------------------------------------------------------------------------
# LDAP
# ---------------------------------------------------------------------------
LDAP_REQUEST = bytes.fromhex('301d02010177188016') + b'1.3.6.1.4.1.1466.20037'


def ldap_response(code, diag=b'', name=True):
    op = b'\x0a\x01' + bytes([code]) + b'\x04\x00' + b'\x04' + bytes([len(diag)]) + diag
    if name:
        op += b'\x8a\x16' + b'1.3.6.1.4.1.1466.20037'
    body = b'\x02\x01\x01' + b'\x78' + bytes([len(op)]) + op
    return b'\x30' + bytes([len(body)]) + body


def ldap_server(code=0, diag=b''):
    def start(conn, fake):
        fake.seen.append(exact(conn, len(LDAP_REQUEST)))
        conn.sendall(ldap_response(code, diag))
        return code == 0
    return start


class TestLdap(Base):
    def test_request_bytes(self):
        self.assertEqual(ldap.request(1), LDAP_REQUEST)

    def test_starttls(self):
        f, _ = self.works(ldap.LdapCheck, ldap_server())
        self.assertEqual(f.seen[0], LDAP_REQUEST)

    def test_long_length_form(self):
        def start(conn, fake):
            exact(conn, len(LDAP_REQUEST))
            r = ldap_response(0)
            conn.sendall(b'\x30\x84' + struct.pack('>I', r[1]) + r[2:])
            return True
        self.works(ldap.LdapCheck, start)

    def test_refused(self):
        self.says(ldap.LdapCheck, ldap_server(52, b'no certificate'),
                  'refused StartTLS', 'unavailable (52)', 'no certificate')
        self.says(ldap.LdapCheck, ldap_server(2), 'protocolError (2)')


# ---------------------------------------------------------------------------
# RDP
# ---------------------------------------------------------------------------
RDP_REQUEST = bytes.fromhex('030000130ee00000000000010008000b000000')


def rdp_confirm(neg):
    x224 = bytes([6 + len(neg), 0xD0, 0, 0, 0, 0, 0]) + neg
    return struct.pack('>BBH', 3, 0, 4 + len(x224)) + x224


def rdp_server(neg, tls_after):
    def start(conn, fake):
        fake.seen.append(exact(conn, 19))
        conn.sendall(rdp_confirm(neg))
        return tls_after
    return start


class TestRdp(Base):
    def test_request_bytes(self):
        self.assertEqual(rdp.connection_request(), RDP_REQUEST)

    def test_tls(self):
        for proto in (1, 2, 8):
            with self.subTest(proto):
                f, _ = self.works(rdp.RdpCheck,
                                  rdp_server(struct.pack('<BBHI', 2, 0, 8, proto), True))
                self.assertEqual(f.seen[0], RDP_REQUEST)

    def test_failure(self):
        self.says(rdp.RdpCheck, rdp_server(struct.pack('<BBHI', 3, 0, 8, 2), False),
                  'refused TLS', 'SSL_NOT_ALLOWED_BY_SERVER')
        self.says(rdp.RdpCheck, rdp_server(struct.pack('<BBHI', 3, 0, 8, 5), False),
                  'HYBRID_REQUIRED_BY_SERVER')

    def test_standard_security(self):
        self.says(rdp.RdpCheck, rdp_server(b'', False), 'standard RDP security',
                  'no certificate')
        self.says(rdp.RdpCheck, rdp_server(struct.pack('<BBHI', 2, 0, 8, 0), False),
                  'standard RDP security')


# ---------------------------------------------------------------------------
# PostgreSQL, MySQL
# ---------------------------------------------------------------------------
def pg_server(answer):
    def start(conn, fake):
        fake.seen.append(exact(conn, 8))
        conn.sendall(answer)
        return answer == b'S'
    return start


def mysql_greeting(caps):
    p = (b'\x0a' + b'8.4.3-MySQL\0' + struct.pack('<I', 42) + b'abcdefgh' + b'\0' +
         struct.pack('<H', caps & 0xFFFF) + bytes([255]) + struct.pack('<H', 2) +
         struct.pack('<H', caps >> 16) + bytes([21]) + b'\0' * 10 + b'ijklmnopqrst\0' +
         b'caching_sha2_password\0')
    return struct.pack('<I', len(p))[:3] + b'\x00' + p


def mysql_server(caps):
    def start(conn, fake):
        conn.sendall(mysql_greeting(caps))
        if not caps & mysql.CLIENT_SSL:
            conn.recv(10)
            return False
        fake.seen.append(exact(conn, 36))
        return True
    return start


ALL_CAPS = 0xDFFFFFFF


class TestDatabases(Base):
    def test_postgres(self):
        f, _ = self.works(postgres.PostgresCheck, pg_server(b'S'))
        self.assertEqual(f.seen[0], bytes.fromhex('0000000804d2162f'))

    def test_postgres_off(self):
        self.says(postgres.PostgresCheck, pg_server(b'N'), 'SSL is off')

    def test_mysql(self):
        f, out = self.works(mysql.MysqlCheck, mysql_server(ALL_CAPS), said='8.4.3-MySQL')
        req = f.seen[0]
        self.assertEqual(req[:4], b'\x20\x00\x00\x01')          # 32 bytes, sequence 1
        caps, most, charset = struct.unpack('<IIB', req[4:13])
        self.assertTrue(caps & mysql.CLIENT_SSL and caps & mysql.CLIENT_PROTOCOL_41)
        self.assertEqual(charset, 45)
        self.assertEqual(req[13:], b'\0' * 23)

    def test_mysql_no_ssl(self):
        self.says(mysql.MysqlCheck, mysql_server(ALL_CAPS & ~mysql.CLIENT_SSL),
                  'does not offer TLS', 'CLIENT_SSL')

    def test_mysql_error(self):
        def start(conn, fake):
            msg = b"\xff\x6a\x04Host '10.0.0.9' is not allowed to connect to this MySQL server"
            conn.sendall(struct.pack('<I', len(msg))[:3] + b'\x00' + msg)
        self.says(mysql.MysqlCheck, start, 'error 1130', 'is not allowed')


# ---------------------------------------------------------------------------
# XMPP
# ---------------------------------------------------------------------------
def xmpp_server(offer=True):
    def start(conn, fake):
        buf = b''
        while b'version=' not in buf or not buf.endswith(b'>'):
            buf += conn.recv(4096)
        fake.seen.append(buf)
        tls = (b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>"
               if offer else b'')
        conn.sendall(b"<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                     b"xmlns:stream='http://etherx.jabber.org/streams' id='x1' "
                     b"from='chat.example.test' version='1.0' xml:lang='en'>")
        conn.sendall(b'<stream:features>' + tls + b"<mechanisms xmlns='urn:ietf:params:xml:"
                     b"ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms>"
                     b'</stream:features>')
        if not offer:
            conn.recv(100)
            return False
        got = b''
        while b'/>' not in got:
            got += conn.recv(4096)
        fake.seen.append(got)
        conn.sendall(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        return True
    return start


class TestXmpp(Base):
    def test_starttls(self):
        f, _ = self.works(xmpp.XmppCheck, xmpp_server(), said="from='chat.example.test'",
                          domain='chat.example.test')
        self.assertIn(b"to='chat.example.test'", f.seen[0])
        self.assertIn(b"xmlns:stream='http://etherx.jabber.org/streams'", f.seen[0])
        self.assertEqual(f.seen[1], b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")

    def test_domain_from_sni(self):
        f, _ = self.works(xmpp.XmppCheck, xmpp_server())
        self.assertIn(b"to='localhost'", f.seen[0])

    def test_no_starttls(self):
        self.says(xmpp.XmppCheck, xmpp_server(False),
                  'the server does not offer STARTTLS (it said: <stream:features>')

    def test_stream_error(self):
        def start(conn, fake):
            conn.recv(4096)
            conn.sendall(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams'>"
                         b"<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-"
                         b"streams'/></stream:error></stream:stream>")
        self.says(xmpp.XmppCheck, start, 'ended the stream: host-unknown')


# ---------------------------------------------------------------------------
# Microsoft SQL Server: TLS inside TDS PRELOGIN packets
# ---------------------------------------------------------------------------
def tds_read(conn):
    typ, body = None, b''
    while True:
        head = exact(conn, 8)
        typ = head[0] if typ is None else typ
        body += exact(conn, struct.unpack('>H', head[2:4])[0] - 8)
        if head[1] & 1:
            return typ, body


def tds_send(conn, typ, body):
    for i in range(0, len(body), 1000):            # small packets: records split across
        part = body[i:i + 1000]
        last = i + 1000 >= len(body)
        conn.sendall(struct.pack('>BBHHBB', typ, 1 if last else 0, 8 + len(part), 0, 1, 0)
                     + part)


def tds_server(encryption=mssql.ENCRYPT_ON):
    def start(conn, fake):
        typ, body = tds_read(conn)
        fake.seen.append((typ, mssql.options(body)))
        tds_send(conn, 0x04, mssql_answer(encryption))
        if encryption == mssql.ENCRYPT_NOT_SUP:
            conn.recv(10)
            return False
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = SERVER_CTX.wrap_bio(inc, out, server_side=True)
        for _ in range(10):
            typ, body = tds_read(conn)
            fake.seen.append(typ)
            inc.write(body)
            try:
                obj.do_handshake()
                done = True
            except ssl.SSLWantReadError:
                done = False
            flight = out.read()
            if flight:
                tds_send(conn, 0x12, flight)
            if done:
                break
        conn.recv(10)
        return None
    return start


def mssql_answer(encryption):
    opts = [(0, struct.pack('>BBHH', 16, 0, 4175, 0)), (1, bytes([encryption])),
            (2, b'\0'), (4, b'\0')]
    at, head, data = len(opts) * 5 + 1, b'', b''
    for tok, v in opts:
        head += struct.pack('>BHH', tok, at + len(data), len(v))
        data += v
    return head + b'\xff' + data


class TestMssql(Base):
    def test_prelogin(self):
        body = mssql.prelogin_body()
        o = mssql.options(body)
        self.assertEqual(o[mssql.ENCRYPTION], b'\x01')
        self.assertEqual(len(o[mssql.VERSION]), 6)
        msg, pid = mssql.packets(0x12, body)
        self.assertEqual(msg[:2], b'\x12\x01')
        self.assertEqual(struct.unpack('>H', msg[2:4])[0], 8 + len(body))

    def test_tls_in_tds(self):
        f, out = self.works(mssql.MssqlCheck, tds_server(), said='SQL Server 16.0.4175')
        self.assertEqual(f.seen[0][0], 0x12)
        self.assertTrue(all(x == 0x12 for x in f.seen[1:] if isinstance(x, int)))

    def test_not_supported(self):
        self.says(mssql.MssqlCheck, tds_server(mssql.ENCRYPT_NOT_SUP),
                  'does not do encryption')


class TestTalkSaysWhatIsSent(Base):
    """What happens shows what a test says before TLS (talk(), 1.0.37): that is what
    served() really sends - each module against its server here, every send recorded."""
    def recorded(self, cls, start, **config):
        from acmelib.plugins.checks import _tls as T, _wire as W
        sent = []
        was_line, was_send = T.Lines.send, W.send

        def line_send(lines, text):
            sent.append(('line', text))
            return was_line(lines, text)

        def raw_send(sock, data, what='the server'):
            sent.append(('raw', bytes(data).hex()))
            return was_send(sock, data, what)
        T.Lines.send, W.send = line_send, raw_send
        try:
            f = self.serve(start)
            m = self.module(cls, **config)
            m.served('127.0.0.1', f.port, 'localhost', verify=False)
        finally:
            T.Lines.send, W.send = was_line, was_send
        said = []
        for t in m.talk('127.0.0.1', 'localhost'):
            if t.get('send') is not None:
                said.append(t['send'])
            elif t.get('send_hex'):
                said.append(t['send_hex'])
        return [x[1] for x in sent], said

    def test_each(self):
        cases = [(smtp.SmtpCheck, smtp_server(), {}), (imap.ImapCheck, imap_server(), {}),
                 (pop3.Pop3Check, pop3_server(), {}), (ftp.FtpCheck, ftp_server(), {}),
                 (ldap.LdapCheck, ldap_server(), {}),
                 (rdp.RdpCheck, rdp_server(struct.pack('<BBHI', 2, 0, 8, 1), True), {}),
                 (postgres.PostgresCheck, pg_server(b'S'), {}),
                 (xmpp.XmppCheck, xmpp_server(), {'domain': 'chat.example.test'}),
                 (mssql.MssqlCheck, tds_server(), {})]
        for cls, start, config in cases:
            with self.subTest(cls.kind):
                sent, said = self.recorded(cls, start, **config)
                if cls.kind == 'mssql':
                    sent = sent[:1]         # then the TLS handshake carried inside TDS
                if cls.kind == 'xmpp':
                    sent = [bytes.fromhex(x).decode() for x in sent]
                self.assertEqual(sent, said)

    def test_mysql_said_as_sent(self):
        """MySQL's SSLRequest carries what the server offers: the words say so, the
        bytes are those for a server that offers everything."""
        sent, said = self.recorded(mysql.MysqlCheck, mysql_server(0xFFFFFFFF))
        self.assertEqual(sent, said)


if __name__ == '__main__':
    unittest.main(verbosity=2)
