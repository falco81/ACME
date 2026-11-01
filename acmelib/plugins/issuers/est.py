# -*- coding: utf-8 -*-
"""
Certificates by EST - Enrollment over Secure Transport (RFC 7030): Cisco,
EJBCA, Keyfactor, DigiCert TLM, Entrust, Nexus, Microsoft-free Windows PKIs,
GlobalSign, the open-source estserver of Cisco (libest) and others.

From the standard (https://www.rfc-editor.org/rfc/rfc7030, sections 3.2.2,
4.1, 4.2 and 4.2.3), what is spoken here:

* https://<server>/.well-known/est[/<label>]/<operation> - the label for a
  server that hosts several CAs (EJBCA: the alias).
* GET cacerts: the CA certificates, a certs-only CMC Simple PKI Response
  (PKCS#7 degenerate SignedData), application/pkcs7-mime, base64 (4.1.3).
* POST simpleenroll / simplereenroll: the PKCS#10 request (base64 of its
  DER, application/pkcs10, 4.2.1); the answer is the certificate as a
  certs-only PKCS#7, base64 (4.2.3). 202 Accepted with Retry-After: the
  request is held (manual approval) - the same request is sent again later.
* GET csrattrs: the attributes the CA wants in the request (4.5) - only asked
  by "Try it".
* The client signs in with HTTP Basic (3.2.3) or a TLS client certificate
  (3.3.2), or both; the server's TLS certificate is checked against the
  "explicit trust anchor" (the CA certificate given) or the system's.

simplereenroll (a renewal) is asked for only when the setting says so: a
server takes it with the client certificate of the certificate being renewed,
which acme does not hold here - most servers renew as well with simpleenroll.

UNCERTAIN: the server-side key generation (serverkeygen, 4.4) and full CMC
(4.3) are not spoken. See docs/sources.md (EST).
"""
from __future__ import annotations

import base64
import re
import time

from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _source_common as sc
from acmelib.plugins.issuers import _scep_pkcs7 as p7


class EstIssuer(Issuer):
    kind = 'est'
    title = 'EST (RFC 7030)'
    description = ('Certificates from a CA that speaks EST (Enrollment over Secure Transport, '
                   'RFC 7030): Cisco, EJBCA, Keyfactor, Entrust, GlobalSign and others, signed '
                   'in with a password or a client certificate. Requests the CA holds are '
                   'asked for again.')
    vendor = 'Standards'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    fields = [
        field('url', 'EST server', 'text', required=True,
              placeholder='https://est.example.local',
              help='The server\'s address; /.well-known/est is added when the path does not '
                   'have it already.'),
        field('label', 'CA label', 'text', placeholder='tls-servers',
              help='The label of the CA on a server that hosts several (EJBCA: the EST alias). '
                   'Empty: the server\'s default CA.'),
        field('auth', 'Signing in', 'select', default='basic',
              options=[['basic', 'User and password (HTTP Basic)'],
                       ['cert', 'Client certificate'],
                       ['both', 'Client certificate and password'],
                       ['none', 'Nothing (the server lets anybody enroll)']]),
        field('user', 'User', 'text', show_if={'auth': ['basic', 'both']}),
        field('password', 'Password', 'secret', show_if={'auth': ['basic', 'both']}),
        field('client_cert', 'Client certificate', 'pem', show_if={'auth': ['cert', 'both']},
              help='The certificate acme signs in to the EST server with (PEM, with its chain).'),
        field('client_key', 'Client certificate\'s key', 'pem', secret=True,
              show_if={'auth': ['cert', 'both']}),
        field('ca_pem', 'CA certificate of the server (trust anchor)', 'pem',
              help='The root the EST server\'s TLS certificate is checked against (RFC 7030 '
                   'explicit trust anchor). Empty: the system\'s roots.'),
        field('verify', 'Check the server\'s TLS certificate', 'bool', default=True, advanced=True),
        field('reenroll', 'Renewals by simplereenroll', 'bool', default=False, advanced=True,
              help='Off: every certificate is asked for with simpleenroll. On: a renewal goes '
                   'to simplereenroll (servers that want it, with a client certificate that '
                   'may renew).'),
        field('wait_pending', 'Wait for approval (s)', 'number', default=60, advanced=True,
              help='How long a try waits for a request the CA holds (202); it is asked for '
                   'again at later tries anyway.'),
    ]

    # -- talking to it -------------------------------------------------------------------
    def base(self):
        url = str(self.c('url') or '').strip().rstrip('/')
        if not re.match(r'^https?://[^\s/]+', url):
            raise PluginError('set the EST server (https://...)', retry=False)
        if '/.well-known/est' not in url:
            url += '/.well-known/est'
        label = str(self.c('label') or '').strip().strip('/')
        if label:
            if not re.match(r'^[A-Za-z0-9._~-]+\Z', label):
                raise PluginError('the CA label may hold letters, digits and . _ ~ - only',
                                  retry=False)
            url += '/' + label
        return url

    def _client(self):
        auth = self.c('auth') or 'basic'
        headers, cert = {}, None
        if auth in ('basic', 'both'):
            if not self.c('user'):
                raise PluginError('set the user that signs in to the EST server', retry=False)
            tok = base64.b64encode(('%s:%s' % (self.c('user'), self.c('password') or ''))
                                   .encode('utf-8')).decode('ascii')
            headers['Authorization'] = 'Basic ' + tok
        if auth in ('cert', 'both'):
            if not self.c('client_cert') or not self.c('client_key'):
                raise PluginError('set the client certificate and its key', retry=False)
            cert = (self.c('client_cert'), self.c('client_key'))
        return headers, cert

    def call(self, method, op, body=None, ctype=None):
        url = self.base() + '/' + op
        if url.startswith('http://'):
            sc.say(self.ctx, 'EST over plain HTTP - RFC 7030 wants TLS; the password travels '
                             'unencrypted', 'warn')
        headers, cert = self._client()
        headers['Accept'] = '*/*'
        if ctype:
            headers['Content-Type'] = ctype
            headers['Content-Transfer-Encoding'] = 'base64'
        status, h, data = sc.http(self.ctx, method, url, body, headers, who='the EST server',
                                  verify=sc.as_bool(self.c('verify'), True),
                                  ca_pem=self.c('ca_pem') or None, client_cert=cert)
        if status == 401:
            raise PluginError('the EST server does not let acme in (401) - check the user and '
                              'password, or the client certificate', retry=False)
        return status, h, data

    def cacerts(self):
        status, _h, data = self.call('GET', 'cacerts')
        if status != 200:
            raise sc.refusal('the EST server (cacerts)', status, sc.parse_json(data), data,
                             'check the address and the CA label')
        certs = sc.certs_of(data)
        if not certs:
            raise PluginError('the EST server\'s cacerts holds no certificate', detail=data[:500])
        return certs

    # -- trying it -----------------------------------------------------------------------
    def test(self):
        certs = self.cacerts()
        cas = [p7.Cert(c) for c in certs]
        words = 'the EST server answers: CA %s' % ', '.join(c.subject_cn or '?' for c in cas)
        try:
            status, _h, data = self.call('GET', 'csrattrs')
            if status == 200 and data.strip():
                words += '; it asks for attributes in the request (csrattrs)'
        except PluginError:
            pass
        return words

    # -- a certificate -------------------------------------------------------------------
    def issue(self, req):
        slot = sc.pending_slot('est', self.base(), req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        op = 'simplereenroll' if (req.previous and sc.as_bool(self.c('reenroll'))) else 'simpleenroll'
        if held:
            op = held.get('op') or op
            sc.say(self.ctx, 'the request held by the EST server since %s is sent again' %
                   time.strftime('%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0)))
        body = base64.encodebytes(sc.csr_der(r))
        end = time.time() + sc.num(self.c('wait_pending'), 60)
        while True:
            sc.say(self.ctx, '%s to %s' % (op, self.base()))
            status, h, data = self.call('POST', op, body, 'application/pkcs10')
            if status == 200:
                break
            if status == 202:
                if not held:
                    held = sc.pending_put(self.ctx, slot, r, {'op': op, 'csr_pem': sc.csr_pem(r),
                                                              'id': op})
                wait = sc.retry_after(h, 30)
                if time.time() + wait > end or self.ctx.cancelled():
                    raise PluginError('the EST server holds the request (202) for someone to '
                                      'approve - acme asks for it again at the next try')
                sc.say(self.ctx, 'the EST server holds the request (202) - asked again in %d s'
                       % wait)
                time.sleep(wait)
                continue
            if held:
                sc.pending_drop(self.ctx, slot)
            raise sc.refusal('the EST server (%s)' % op, status, sc.parse_json(data), data,
                             'the user may not enroll here, or the request is not what the '
                             'CA takes')
        certs = sc.certs_of(data)
        if not certs:
            raise PluginError('the EST server\'s answer holds no certificate', detail=data[:500])
        chain = []
        try:
            chain = self.cacerts()
        except PluginError as e:
            sc.say(self.ctx, 'the CA certificates could not be fetched for the chain: %s' % e,
                   'warn')
        out = sc.finish(self.ctx, r, certs, chain, info={'est': self.base()},
                        key_pem=r.key_pem if held else None, who='the EST server')
        if held:
            sc.pending_drop(self.ctx, slot)
        return out
