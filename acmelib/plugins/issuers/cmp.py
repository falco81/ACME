# -*- coding: utf-8 -*-
"""
Certificates by CMP - the Certificate Management Protocol (RFC 4210, updated
by RFC 9480 "CMP Updates" and RFC 9483 "Lightweight CMP Profile"; HTTP
transfer RFC 6712 / 9811): EJBCA, Nokia NetGuard, Siemens, Insta Certifier,
PrimeKey, Keyfactor and the industrial (IEC 62443) world.

The CMP messages are made, protected, checked and polled by the openssl
program (`openssl cmp`, OpenSSL 3.0 and later -
https://docs.openssl.org/3.0/man1/openssl-cmp/): ir (initialization
request), cr (certification request) or p10cr (the PKCS#10 request as it is),
answered by ip/cp, confirmed by certConf/pkiConf (or implicitConfirm), a
"waiting" answer polled (pollReq) until -total_timeout; rr (revocation
request) for a revocation; genm (general message) for "Try it". Protected
with a shared secret (PBM, password-based MAC: -ref and -secret) or a
signature (a client certificate and key: -cert and -key).

openssl talks plain HTTP to a relay of this module on 127.0.0.1 only; the
relay sends each message on with ctx.http (application/pkixcmp) - through
the proxy of Settings → Proxy, checked against the TLS settings here - and
hands back the answer. The secret and the keys are given to openssl in files
(0600, in a directory of their own), never on its command line.

UNCERTAIN: CMP servers differ in what they want in the header (recipient,
sender, the senderKID): the recipient DN and the reference are settings, and
the extra options a server needs are said in docs/sources.md (CMP). Each
message goes on a connection of its own (ctx.http): a server that keeps a
transaction only while one connection stays open (OpenSSL's own mock server
does) needs "Implicit confirmation" (no certConf). A request
the CA holds longer than the wait is not taken up again at the next try (the
transaction lives in openssl): it is asked again.
"""
from __future__ import annotations

import http.server
import re
import shutil
import subprocess
import threading

from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _source_common as sc

DN_RE = re.compile(r'^(/|(/[A-Za-z][A-Za-z0-9.]*=[^/\s][^/]*)+)\Z')


class _Relay(object):
    """An HTTP server on 127.0.0.1 that sends what openssl posts to the CMP
    server with ctx.http, for one run of openssl."""
    def __init__(self, ctx, url, verify, ca_pem, client_cert):
        relay = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.0'

            def log_message(self, *a):
                pass

            def do_POST(self):                      # noqa: N802
                n = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(n) if n else b''
                fwd = {'Content-Type': 'application/pkixcmp', 'Accept': 'application/pkixcmp'}
                if (self.headers.get('Connection') or '').lower() == 'keep-alive':
                    # openssl keeps one transaction on one connection: said on to servers
                    # that look at it (ctx.http itself may still close it after each answer)
                    fwd['Connection'] = 'keep-alive'
                try:
                    status, h, data = sc.http(ctx, 'POST', url, body, fwd,
                                              who='the CMP server', verify=verify,
                                              ca_pem=ca_pem, client_cert=client_cert)
                except PluginError as e:
                    relay.error = e
                    status, h, data = 502, {}, b''
                relay.statuses.append(status)
                if status != 200:
                    relay.answers.append(data[:2000])
                self.send_response(status)
                self.send_header('Content-Type', h.get('content-type') or 'application/pkixcmp')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(data)

        self.error = None
        self.statuses = []
        self.answers = []
        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class CmpIssuer(Issuer):
    kind = 'cmp'
    discovery = False               # CMP (RFC 4210) has no reading of profiles or settings
    dual = True                     # where the CA's profile takes both kinds of key
    title = 'CMP (RFC 4210 / 9480)'
    description = ('Certificates by the Certificate Management Protocol (CMPv2, RFC 4210 and '
                   '9480; the Lightweight CMP Profile): EJBCA, Nokia, Siemens, Insta and other '
                   'CAs, with a shared secret or a signing certificate - spoken by openssl cmp.')
    vendor = 'Standards'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    fields = [
        field('url', 'CMP server', 'text', required=True,
              placeholder='https://ca.example.local/ejbca/publicweb/cmp/acme',
              help='The CMP endpoint (HTTP transfer): EJBCA .../ejbca/publicweb/cmp/ALIAS; '
                   'Lightweight CMP .../.well-known/cmp[/p/LABEL].'),
        field('command', 'Request', 'select', default='cr',
              options=[['ir', 'ir - initialization request (the first certificate)'],
                       ['cr', 'cr - certification request'],
                       ['p10cr', 'p10cr - the PKCS#10 request as it is']],
              help='What the CA expects: ir for an entity it does not know yet, cr otherwise; '
                   'p10cr where the CA wants the CSR itself.'),
        field('auth', 'Protection', 'select', default='secret',
              options=[['secret', 'Shared secret (PBM: reference and password)'],
                       ['signature', 'Signature (a client certificate and its key)']]),
        field('reference', 'Reference (senderKID)', 'text', show_if={'auth': ['secret']},
              placeholder='acme01',
              help='The name the secret belongs to at the CA (EJBCA: the end entity\'s name, '
                   'or what its alias wants).'),
        field('secret', 'Shared secret', 'secret', show_if={'auth': ['secret']},
              help='The password the CA gave for the reference (EJBCA: the enrollment code).'),
        field('client_cert', 'Signing certificate', 'pem', show_if={'auth': ['signature']},
              help='The certificate acme signs the messages with, its chain after it.'),
        field('client_key', 'Signing certificate\'s key', 'pem', secret=True,
              show_if={'auth': ['signature']}),
        field('recipient', 'CA name (recipient)', 'text', placeholder='/C=CZ/O=Example/CN=Issuing CA',
              help='The CA\'s name, as /C=../O=../CN=.. Empty: "/" (a null name, as many servers '
                   'accept) or the subject of the CA certificate below.'),
        field('trusted', 'CA certificate (answers)', 'pem',
              help='The certificate(s) the CA\'s signed answers are checked against, and the '
                   'new certificate. Needed with signature protection; with a shared secret the '
                   'answers are checked by the secret.'),
        field('profile', 'Certificate profile', 'text', advanced=True, placeholder='tls-server',
              help='Sent as the certProfile of the header (RFC 9480 / Lightweight CMP), where '
                   'the CA chooses by it. Needs openssl 3.3 or later.'),
        field('implicit_confirm', 'Implicit confirmation', 'bool', default=False, advanced=True,
              help='Ask the CA not to wait for certConf (where it allows it) - also for servers '
                   'that keep a transaction only on one open connection.'),
        field('unprotected_errors', 'Take unprotected error answers', 'bool', default=True,
              advanced=True,
              help='Many CAs answer an error without protection; on, its words are shown.'),
        field('ca_pem', 'CA certificate of the server\'s TLS', 'pem', advanced=True,
              help='For HTTPS with a private CA.'),
        field('verify', 'Check the server\'s TLS certificate', 'bool', default=True, advanced=True),
        field('wait', 'Wait for the certificate (s)', 'number', default=120, advanced=True,
              help='How long a CA that answers "waiting" is polled.'),
    ]

    def _url(self):
        url = str(self.c('url') or '').strip()
        if not re.match(r'^https?://[^\s/]+\S*\Z', url):
            raise PluginError('set the CMP server (http:// or https://)', retry=False)
        return url

    def _recipient(self):
        r = str(self.c('recipient') or '').strip()
        if r and not DN_RE.match(r):
            raise PluginError('the CA name is written /C=CZ/O=Example/CN=Name', retry=False)
        if not r and self.c('trusted'):
            return None                             # the subject of -trusted / -srvcert
        return r or '/'

    def _common(self, w):
        """The arguments of every message: protection, recipient, trust."""
        args = []
        auth = self.c('auth') or 'secret'
        if auth == 'secret':
            if not self.c('reference') or not self.c('secret'):
                raise PluginError('set the reference and the shared secret', retry=False)
            ref = str(self.c('reference'))
            if not re.match(r'^[\x21-\x7e][\x20-\x7e]{0,127}\Z', ref):
                raise PluginError('the reference may hold printable ASCII only', retry=False)
            args += ['-ref', ref, '-secret', 'file:' + w.file('secret.txt',
                                                              str(self.c('secret')) + '\n')]
        else:
            if not self.c('client_cert') or not self.c('client_key'):
                raise PluginError('set the signing certificate and its key', retry=False)
            args += ['-cert', w.file('signer.pem', self.c('client_cert')),
                     '-key', w.file('signer.key', self.c('client_key'))]
        rcpt = self._recipient()
        if rcpt:
            args += ['-recipient', rcpt]
        trusted = self.c('trusted')
        if trusted:
            if not sc.certs_of(trusted):
                raise PluginError('the CA certificate (answers) is not a certificate', retry=False)
            tf = w.file('trusted.pem', trusted)
            args += ['-trusted', tf, '-out_trusted', tf]
        elif auth == 'signature':
            raise PluginError('with signature protection, set the CA certificate the answers '
                              'are checked against', retry=False)
        if sc.as_bool(self.c('unprotected_errors'), True):
            args += ['-unprotected_errors']
        prof = str(self.c('profile') or '').strip()
        if prof:
            if not re.match(r'^[A-Za-z0-9._-]{1,64}\Z', prof):
                raise PluginError('the certificate profile may hold letters, digits and . _ -',
                                  retry=False)
            if not self._openssl_at_least(3, 3):
                raise PluginError('a certificate profile needs openssl 3.3 or later (openssl cmp '
                                  '-profile); this one has none - leave it empty', retry=False)
            args += ['-profile', prof]
        return args

    def _openssl_at_least(self, major, minor):
        m = re.search(rb'OpenSSL (\d+)\.(\d+)', sc.run_openssl(self.ctx, ['version']))
        return bool(m) and (int(m.group(1)), int(m.group(2))) >= (major, minor)

    def run(self, args, timeout):
        """openssl cmp with `args`, its messages through the relay."""
        runner = getattr(self.ctx, 'run_local', None)
        if callable(runner):
            # a context that runs local programs itself (What happens: recorded, not run) -
            # the relay is not opened; what openssl would send through it is said
            full = ['openssl', 'cmp', '-server', '127.0.0.1:RELAY/cmp', '-no_proxy',
                    '127.0.0.1', '-msg_timeout', str(max(10, int(timeout))), '-total_timeout',
                    str(max(20, int(timeout) + 10))] + list(args)
            cmd = args[args.index('-cmd') + 1] if '-cmd' in args else '?'
            sc.say(self.ctx, 'openssl cmp sends its messages (%s, then certConf unless implicit '
                   'confirmation; pollReq while the CA waits) to acme\'s relay on 127.0.0.1, '
                   'which posts each to %s with acme\'s connection (Content-Type: '
                   'application/pkixcmp) and hands back the answer' % (cmd, self._url()))
            rc, out, err = runner(full, timeout=int(timeout) + 30)
            if rc != 0:
                raise PluginError('openssl cmp: %s' % ((out or b'') + (err or b'')).decode(
                    'utf-8', 'replace').strip()[-300:])
            return out or b''
        # CMP protects the messages itself: the TLS under it needs no client certificate.
        relay = _Relay(self.ctx, self._url(), sc.as_bool(self.c('verify'), True),
                       self.c('ca_pem') or None, None)
        try:
            full = ['cmp', '-server', '127.0.0.1:%d/cmp' % relay.port, '-no_proxy', '127.0.0.1',
                    '-msg_timeout', str(max(10, int(timeout))), '-total_timeout',
                    str(max(20, int(timeout) + 10))] + list(args)
            try:
                return self._openssl(full, int(timeout) + 30)
            except PluginError as e:
                if relay.error:
                    raise relay.error
                bad = [s for s in relay.statuses if s != 200]
                if bad:
                    said = relay.answers[-1].decode('utf-8', 'replace') if relay.answers else ''
                    raise PluginError('the CMP server answered %d%s' % (
                        bad[-1], (': ' + sc.said_of(None, said)) if said.strip() else ''),
                        detail=str(e), retry=bad[-1] >= 500)
                raise PluginError('the CMP exchange failed: %s' % self._words(e), detail=e.detail
                                  or str(e), retry=False)
        finally:
            relay.close()

    @staticmethod
    def _openssl(args, timeout):
        """openssl cmp run here, not by ctx.openssl: it says what went wrong on its
        standard output, which is wanted in the words. No shell; the secrets are
        in files named by the arguments."""
        exe = shutil.which('openssl')
        if not exe:
            raise PluginError('openssl is not on this machine', retry=False)
        try:
            got = subprocess.run([exe] + [str(a) for a in args], capture_output=True,
                                 timeout=timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise PluginError('openssl cmp took more than %d s' % timeout)
        text = (got.stdout + b'\n' + got.stderr).decode('utf-8', 'replace')
        if got.returncode != 0:
            raise PluginError('openssl cmp: %s' % text.strip()[-300:], detail=text[-4000:])
        return got.stdout

    @staticmethod
    def _words(e):
        text = str(getattr(e, 'detail', '') or e)
        found = re.findall(r'CMP (?:error|info|warning): ([^\n]+)', text)
        bits = [f.strip() for f in found if 'section' not in f and 'saving to file' not in f]
        m = re.findall(r'(?:statusString|status string|PKIStatus|failInfo)[^\n]*', text)
        bits += [x.strip() for x in m]
        return '; '.join(dict.fromkeys(bits))[:400] or str(e)[:300]

    # -- trying it -----------------------------------------------------------------------
    def test(self):
        self._url()
        with sc.Work('acme-cmp-') as w:
            self.run(['-cmd', 'genm'] + self._common(w), 30)
        return 'the CMP server answers a general message (genm), protected as set'

    # -- a certificate -------------------------------------------------------------------
    def issue(self, req):
        if not req.key_pem or not (req.csr_der or req.csr_pem):
            raise PluginError('there is no request (CSR and key) for CMP', retry=False)
        cmd = self.c('command') or 'cr'
        if cmd not in ('ir', 'cr', 'p10cr'):
            raise PluginError('an unknown CMP request: %s' % cmd, retry=False)
        with sc.Work('acme-cmp-') as w:
            args = ['-cmd', cmd] + self._common(w)
            csr = w.file('req.pem', sc.csr_pem(req))
            args += ['-csr', csr]
            if cmd != 'p10cr':
                args += ['-newkey', w.file('new.key', req.key_pem)]
            if req.days and cmd != 'p10cr':
                args += ['-days', str(int(req.days))]
            if sc.as_bool(self.c('implicit_confirm')):
                args += ['-implicit_confirm']
            args += ['-certout', w.path('cert.pem'), '-chainout', w.path('chain.pem'),
                     '-extracertsout', w.path('extra.pem'), '-cacertsout', w.path('cacerts.pem')]
            sc.say(self.ctx, '%s to the CMP server %s' % (cmd, self._url()))
            self.run(args, sc.num(self.c('wait'), 120))
            certs = sc.certs_of(w.read('cert.pem'))
            chain = []
            for f in ('chain.pem', 'extra.pem', 'cacerts.pem'):
                for c in sc.certs_of(w.read(f)):
                    if c not in chain and c not in certs:
                        chain.append(c)
            if self.c('trusted'):
                chain += [c for c in sc.certs_of(self.c('trusted')) if c not in chain]
        if not certs:
            raise PluginError('the CMP server sent no certificate')
        return sc.finish(self.ctx, req, certs, chain, info={'cmp': self._url()},
                         who='the CMP server')

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        code = sc.reason_code(reason)
        with sc.Work('acme-cmp-') as w:
            args = ['-cmd', 'rr'] + self._common(w) + ['-oldcert', w.file('old.pem', cert_pem),
                                                       '-revreason', str(code)]
            self.run(args, 60)
        return 'the CMP server accepted the revocation of serial %s' % sc.serial_hex(cert_pem)

