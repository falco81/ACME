# -*- coding: utf-8 -*-
"""
Certificates from a Microsoft CA (Active Directory Certificate Services)
through its Web Enrollment pages (/certsrv): the request posted to
certfnsh.asp with the template, the certificate fetched from certnew.cer and
the chain from certnew.p7b. A request the CA holds for a certificate manager
(pending) is fetched at a later try. Signed in with NTLM (v2, pure Python),
Basic, or a client certificate. See docs/ms-adcs.md.

NTLM signs in a TCP connection, not a request: it needs the same connection
for its three messages, which ctx.http (one connection a request) cannot
keep. This module therefore holds its own connections (http.client) for
NTLM and client certificates; Basic goes through ctx.http as usual.
"""
from __future__ import annotations

import base64
import hashlib
import html
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import tempfile
import time
import urllib.parse

from acmelib.plugins.base import Issuer, Issued, PluginError, field
from acmelib.plugins.issuers import _ntlm
from acmelib.plugins.issuers import _scep_pkcs7 as der

# What the CA's error codes mean (certsrv's "The error code is 0x...").
ADCS_ERRORS = {
    '0x80094800': 'the CA does not offer this template (CA → Certificate Templates → New → '
                  'Certificate Template to Issue), or it is the display name - give the template '
                  'name (without spaces)',
    '0x80094801': 'the request has no template - set the template',
    '0x80094012': 'the user may not enroll for this template (template → Security: Read and Enroll)',
    '0x80094005': 'the CA refused the request\'s names (the template builds the subject from '
                  'Active Directory: set it to "Supply in the request")',
    '0x80094004': 'the template needs a subject (e-mail, DNS name) the user\'s AD account does '
                  'not have - set the template to "Supply in the request"',
    '0x80094006': 'the CA refused the request\'s key (too small, of a kind the template does not take)',
    '0x80094009': 'the request has a key smaller than the template wants',
    '0x8009480f': 'the template needs a DNS name in Active Directory the user does not have',
    '0x80094811': 'the template needs a key the request does not have (key size, provider)',
    '0x80070005': 'access is denied (the user\'s rights on the CA: Request Certificates)',
    '0x80094011': 'the CA needs a certificate manager to approve the request',
    '0x800b0110': 'the certificate is not for that purpose',
}


class AdcsHttp(object):
    """HTTP(S) to the CA on connections kept open, signing in by NTLM, Basic
    or a client certificate."""
    def __init__(self, ctx, base, auth, user='', password='', domain='', ca_pem=None,
                 verify=True, client_cert=None, client_key=None, timeout=60):
        u = urllib.parse.urlsplit(base)
        self.ctx = ctx
        self.scheme = u.scheme
        self.host = u.hostname
        self.port = u.port or (443 if u.scheme == 'https' else 80)
        self.prefix = u.path.rstrip('/')
        self.auth = auth
        self.user = user
        self.password = password
        self.domain = domain
        self.ca_pem = ca_pem
        self.verify = verify
        self.client_cert = client_cert
        self.client_key = client_key
        self.timeout = timeout
        self.conn = None
        self.authed = False
        self.work = None

    def url(self, path):
        return '%s://%s:%d%s%s' % (self.scheme, self.host, self.port, self.prefix, path)

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:                       # noqa: BLE001
                pass
        self.conn = None
        if self.work:
            shutil.rmtree(self.work, ignore_errors=True)
            self.work = None

    def _ssl(self):
        sc = ssl.create_default_context()
        if self.ca_pem:
            sc.load_verify_locations(cadata=self.ca_pem)
        if not self.verify:
            sc.check_hostname = False
            sc.verify_mode = ssl.CERT_NONE
        if self.auth == 'cert':
            if not self.client_cert or not self.client_key:
                raise PluginError('set the client certificate and its key', retry=False)
            self.work = self.work or tempfile.mkdtemp(prefix='acme-adcs-')
            os.chmod(self.work, 0o700)
            c, k = os.path.join(self.work, 'c.pem'), os.path.join(self.work, 'k.pem')
            for p, data in ((c, self.client_cert), (k, self.client_key)):
                fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'w') as f:
                    f.write(data)
            try:
                sc.load_cert_chain(c, k)
            except (ssl.SSLError, OSError) as e:
                raise PluginError('the client certificate and key do not go together: %s' % e,
                                  retry=False)
        return sc

    def _connect(self):
        if self.conn is None:
            if self.scheme == 'https':
                self.conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout,
                                                        context=self._ssl())
            else:
                self.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            self.authed = False
        return self.conn

    def _send(self, method, path, body, headers):
        for attempt in (1, 2):
            conn = self._connect()
            try:
                conn.request(method, self.prefix + path, body=body, headers=headers)
                r = conn.getresponse()
                data = r.read()
                hdrs = {}
                for k, v in r.getheaders():
                    k = k.lower()
                    hdrs[k] = hdrs[k] + ', ' + v if k in hdrs else v
                if (hdrs.get('connection') or '').lower() == 'close':
                    self.close()
                return r.status, hdrs, data
            except (http.client.HTTPException, ConnectionError) as e:
                self.close()
                if attempt == 2:
                    raise PluginError('the CA\'s web server broke off: %s' % e)
            except ssl.SSLCertVerificationError as e:
                self.close()
                raise PluginError('the CA\'s TLS certificate is not trusted (%s) - add its CA '
                                  'certificate under More, or switch off the check' % e.verify_message,
                                  retry=False)
            except (OSError, socket.timeout) as e:
                self.close()
                raise PluginError('the CA\'s web server does not answer (%s:%d): %s'
                                  % (self.host, self.port, e))

    def server_cert(self):
        try:
            sock = self.conn.sock
            return sock.getpeercert(binary_form=True) if sock and self.scheme == 'https' else None
        except Exception:                           # noqa: BLE001
            return None

    def request(self, method, path, body=None, headers=None):
        h = {'User-Agent': 'Mozilla/5.0 (acme certificate manager)', 'Accept': '*/*'}
        h.update(headers or {})
        if body is not None:
            h['Content-Length'] = str(len(body))
        if self.auth == 'basic':
            tok = base64.b64encode(('%s%s:%s' % ((self.domain + '\\') if self.domain else '',
                                                 self.user, self.password)).encode('utf-8')).decode()
            h['Authorization'] = 'Basic ' + tok
            try:
                status, hdrs, data = self.ctx.http(method, self.url(path), body, h, self.timeout,
                                                   self.verify, self.ca_pem)
            except PluginError:
                raise
            except Exception as e:                  # noqa: BLE001
                raise PluginError('the CA\'s web server does not answer: %s' % e)
            hdrs = {str(k).lower(): v for k, v in (hdrs or {}).items()}
        else:
            status, hdrs, data = self._send(method, path, body, h)
            if status == 401 and self.auth == 'ntlm':
                status, hdrs, data = self._ntlm(method, path, body, h, hdrs)
        if status == 401:
            raise PluginError('the CA does not let the user in (401) - check the user, the password '
                              'and the domain, and that IIS offers %s for /certsrv' % {
                                  'ntlm': 'Windows authentication (NTLM)', 'basic': 'Basic authentication',
                                  'cert': 'client certificates'}.get(self.auth, self.auth),
                              retry=False)
        if status == 403:
            raise PluginError('the CA\'s web server refuses (403) - with client certificates: IIS '
                              'must map the certificate to a user (SSL Settings: Require)', retry=False)
        return status, hdrs, data

    def _ntlm(self, method, path, body, h, hdrs):
        offered = hdrs.get('www-authenticate') or ''
        scheme = 'NTLM' if _ntlm.header_token(offered, 'NTLM') is not None else (
            'Negotiate' if _ntlm.header_token(offered, 'Negotiate') is not None else None)
        if not scheme:
            raise PluginError('the CA\'s web server offers no NTLM (it says %s) - choose another '
                              'way of signing in' % (offered or 'nothing'), retry=False)
        neg = _ntlm.negotiate_message()
        h1 = dict(h, Authorization='%s %s' % (scheme, base64.b64encode(neg).decode()))
        status, hdrs, data = self._send(method, path, body, h1)
        tok = _ntlm.header_token(hdrs.get('www-authenticate'), scheme)
        if status != 401 or not tok:
            if status == 401:
                raise PluginError('the CA\'s web server did not answer the NTLM negotiation '
                                  '(Kerberos only? "Negotiate:Kerberos" in IIS)', retry=False)
            return status, hdrs, data
        user, domain = self.user, (self.domain or None)
        if '\\' in user:
            domain, user = user.split('\\', 1)
        elif '@' in user and not domain:
            domain = ''             # user@domain: the name as it is, no domain
        auth = _ntlm.authenticate_message(neg, tok, user, self.password, domain,
                                          workstation='ACME', server_cert_der=self.server_cert())
        h2 = dict(h, Authorization='%s %s' % (scheme, base64.b64encode(auth).decode()))
        status, hdrs, data = self._send(method, path, body, h2)
        if status != 401:
            self.authed = True
        return status, hdrs, data


class MsAdcsIssuer(Issuer):
    kind = 'ms_adcs'
    dual = True                     # where the template takes both kinds of key (its Cryptography tab)
    title = 'Microsoft AD CS (Web Enrollment)'
    description = ('Certificates from a Microsoft CA through its Web Enrollment pages '
                   '(/certsrv), with a template; signed in with NTLM, Basic or a client '
                   'certificate. Requests waiting for approval are fetched later.')
    vendor = 'Microsoft'
    doc = 'docs/ms-adcs.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    fields = [
        field('url', 'Web Enrollment address', 'text', required=True,
              placeholder='https://ca01.example.local/certsrv',
              help='The CA\'s IIS with Web Enrollment (/certsrv is added when missing).'),
        field('template', 'Template', 'text', required=True, placeholder='WebServer',
              help='The template\'s name (not its display name): WebServer, or a copy of it.'),
        field('auth', 'Signing in', 'select', default='ntlm',
              options=[['ntlm', 'Windows (NTLM)'], ['basic', 'Basic (over HTTPS)'],
                       ['cert', 'Client certificate']]),
        field('user', 'User', 'text', placeholder='svc-acme', show_if={'auth': ['ntlm', 'basic']},
              help='An account with Enroll on the template: user, DOMAIN\\user or user@domain.'),
        field('password', 'Password', 'secret', show_if={'auth': ['ntlm', 'basic']}),
        field('domain', 'Domain', 'text', placeholder='EXAMPLE', show_if={'auth': ['ntlm', 'basic']},
              help='The NetBIOS name of the domain (empty: the one the server says).'),
        field('client_cert', 'Client certificate', 'pem', show_if={'auth': ['cert']}),
        field('client_key', 'Client certificate\'s key', 'secret', show_if={'auth': ['cert']}),
        field('ca_pem', 'CA certificate of the web server', 'pem', advanced=True,
              help='Your internal root, for the TLS of the CA\'s IIS.'),
        field('verify', 'Check the web server\'s TLS certificate', 'bool', default=True, advanced=True),
        field('attributes', 'More attributes', 'list', advanced=True, placeholder='SAN:dns=www.example.com',
              help='Lines added to CertAttrib (e.g. SAN:..., where the CA takes them).'),
        field('wait_pending', 'Wait for approval (s)', 'number', default=0, advanced=True,
              help='How long to wait for a pending request within a try; it is fetched again '
                   'at later tries anyway.'),
    ]

    def _base(self):
        url = str(self.c('url') or '').strip().rstrip('/')
        if not url:
            raise PluginError('set the address of Web Enrollment', retry=False)
        if not re.match(r'^https?://', url):
            url = 'https://' + url
        if not url.lower().endswith('/certsrv'):
            url += '/certsrv'
        return url

    def _http(self):
        url = self._base()
        if url.startswith('http://'):
            self._say('the CA is asked over plain HTTP - the password and the certificate travel '
                      'unencrypted', 'warn')
        verify = self.c('verify')
        verify = True if verify in (None, '') else bool(verify) and str(verify).lower() not in ('0', 'false', 'no')
        auth = self.c('auth') or 'ntlm'
        if auth in ('ntlm', 'basic') and not self.c('user'):
            raise PluginError('set the user that signs in to the CA', retry=False)
        return AdcsHttp(self.ctx, url, auth, str(self.c('user') or ''),
                        str(self.c('password') or ''), str(self.c('domain') or ''),
                        self.c('ca_pem') or None, verify, self.c('client_cert'),
                        self.c('client_key'))

    def _say(self, words, level='info'):
        try:
            self.ctx.step(words, level)
        except Exception:                           # noqa: BLE001
            pass

    def _slot(self, req):
        spki = der.csr_spki(req.csr_der)
        return 'ms_adcs-pending:%s:%s' % (hashlib.sha256(self._base().encode()).hexdigest()[:16],
                                          hashlib.sha256(spki).hexdigest()[:32])

    # -- trying it -------------------------------------------------------------------
    def test(self):
        h = self._http()
        try:
            status, _hd, data = h.request('GET', '/')
            if status >= 400:
                raise PluginError('the CA\'s Web Enrollment answers %d' % status)
            text = data.decode('utf-8', 'replace')
            if 'certsrv' not in text.lower() and 'certificate services' not in text.lower():
                raise PluginError('%s does not look like AD CS Web Enrollment' % self._base(),
                                  detail=text[:300])
            chain = self._ca_chain(h)
            cn = der.Cert(chain[0]).subject_cn if chain else '?'
            return 'Web Enrollment answers, signed in; the CA is %s' % cn
        finally:
            h.close()

    def _ca_chain(self, h):
        status, _hd, data = h.request('GET', '/certnew.p7b?ReqID=CACert&Renewal=-1&Enc=b64')
        if status != 200:
            return []
        try:
            return [der.pem(d) for d in der.certs_from_pkcs7(data)]
        except (der.DerError, ValueError, IndexError):
            return []

    # -- a certificate ---------------------------------------------------------------
    def issue(self, req):
        if not req.csr_pem:
            raise PluginError('there is no request (CSR) to send to the CA', retry=False)
        template = str((req.profile or {}).get('template') or self.c('template') or '').strip()
        if not template:
            raise PluginError('set the template', retry=False)
        slot = self._slot(req)
        h = self._http()
        try:
            held = self.ctx.kv_get(slot)
            if isinstance(held, str):
                try:
                    held = json.loads(held)
                except ValueError:
                    held = None
            if isinstance(held, dict) and held.get('req_id'):
                self._say('the request %s waits at the CA since %s - asked for again' % (
                    held['req_id'], time.strftime('%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0))))
                req_id = str(held['req_id'])
            else:
                req_id = self._submit(h, req, template)
                if not req_id.startswith('ok:'):
                    self.ctx.kv_set(slot, json.dumps({'req_id': req_id, 'at': time.time(),
                                                      'template': template}), ttl_s=90 * 86400)
            if req_id.startswith('ok:'):
                req_id = req_id[3:]
            else:
                self._wait(h, req_id)
            out = self._fetch(h, req_id, req)
            self.ctx.kv_set(slot, None)
            return out
        finally:
            h.close()

    def _submit(self, h, req, template):
        attrs = ['CertificateTemplate:%s' % template]
        attrs += [str(a).strip() for a in (self.c('attributes') or []) if str(a).strip()]
        form = urllib.parse.urlencode({
            'Mode': 'newreq', 'CertRequest': req.csr_pem.strip(),
            'CertAttrib': '\r\n'.join(attrs), 'FriendlyType': 'Saved-Request Certificate',
            'TargetStoreFlags': '0', 'SaveCert': 'yes'}).encode('ascii')
        self._say('the request goes to %s (template %s)' % (self._base(), template))
        status, _hd, data = h.request('POST', '/certfnsh.asp', form,
                                      {'Content-Type': 'application/x-www-form-urlencoded'})
        text = data.decode('utf-8', 'replace')
        if status >= 400:
            raise PluginError('the CA\'s Web Enrollment answered %d' % status, detail=text[:1000])
        m = re.search(r'certnew\.cer\?ReqID=(\d+)', text, re.I)
        if m:
            self._say('the CA issued the certificate (request %s)' % m.group(1), 'ok')
            return 'ok:' + m.group(1)
        rid = re.search(r'Request\s+Id\s+is\s*(?:<[^>]*>\s*)*(\d+)', text, re.I) or \
            re.search(r'ReqID=(\d+)', text, re.I)
        if re.search(r'pending|has been received|was submitted', text, re.I) and rid:
            self._say('the CA holds the request %s for a certificate manager to approve' % rid.group(1), 'warn')
            return rid.group(1)
        raise self._refusal(text, rid.group(1) if rid else None)

    def _refusal(self, text, rid=None):
        code = re.search(r'(0x[0-9a-fA-F]{8})', text)
        disp = re.search(r'disposition message is\s*"?([^"<\r\n]+)', text, re.I)
        said = re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', disp.group(1) if disp else '')))\
            .strip()
        words = ADCS_ERRORS.get(code.group(1).lower()) if code else None
        if not words and re.search(r'denied', text, re.I):
            words = 'the CA denied the request'
        if not words:
            words = 'the CA did not issue the certificate'
        bits = [words]
        if said:
            bits.append('it says: %s' % said[:200])
        if code:
            bits.append(code.group(1))
        if rid:
            bits.append('request %s' % rid)
        return PluginError(' - '.join(bits), detail=re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', text))[:2000],
                           retry=False)

    def _wait(self, h, req_id):
        end = time.time() + float(self.c('wait_pending') or 0)
        while True:
            st = self._state(h, req_id)
            if st == 'issued':
                return
            if time.time() >= end:
                raise PluginError('the CA holds the request %s for a certificate manager to approve '
                                  '(Certification Authority → Pending Requests → Issue); acme asks '
                                  'for it again at the next try' % req_id, retry=True)
            if self.ctx.cancelled():
                raise PluginError('stopped', retry=False)
            time.sleep(min(30, max(1, end - time.time())))

    def _state(self, h, req_id):
        status, hd, data = h.request('GET', '/certnew.cer?ReqID=%s&Enc=b64' % req_id)
        if status == 200 and b'BEGIN CERTIFICATE' in data:
            self._cert_cache = (req_id, data)
            return 'issued'
        text = data.decode('utf-8', 'replace')
        if re.search(r'denied|revoked|0x8009', text, re.I) and not re.search(r'pending', text, re.I):
            raise self._refusal(text, req_id)
        return 'pending'

    def _fetch(self, h, req_id, req):
        cached = getattr(self, '_cert_cache', None)
        if cached and cached[0] == req_id:
            data = cached[1]
        else:
            status, _hd, data = h.request('GET', '/certnew.cer?ReqID=%s&Enc=b64' % req_id)
            if status != 200 or b'BEGIN CERTIFICATE' not in data:
                raise self._refusal(data.decode('utf-8', 'replace'), req_id)
        blocks = der.pem_blocks(data, 'CERTIFICATE')
        if not blocks:
            raise PluginError('the CA sent no certificate for request %s' % req_id)
        leaf = blocks[0][1]
        cert = der.Cert(leaf)
        if req.csr_der and cert.spki_der != der.csr_spki(req.csr_der):
            raise PluginError('the certificate of request %s is for another key than this request '
                              '(an old pending request?) - it is not used' % req_id, retry=False)
        chain = []
        status, _hd, p7 = h.request('GET', '/certnew.p7b?ReqID=%s&Enc=b64' % req_id)
        if status == 200:
            try:
                chain = [d for d in der.certs_from_pkcs7(p7) if d != leaf]
            except (der.DerError, ValueError, IndexError):
                chain = []
        if not chain:
            chain = [der.cert_der(c) for c in self._ca_chain(h)]
        chain = der.order_chain(leaf, chain)
        self._say('the certificate came: request %s, serial %x, until %s, from %s' % (
            req_id, cert.serial, time.strftime('%Y-%m-%d', time.gmtime(cert.not_after)),
            cert.issuer_cn or '?'), 'ok')
        return Issued(der.pem(leaf), [der.pem(c) for c in chain],
                      info={'req_id': req_id, 'ca': self._base()})

