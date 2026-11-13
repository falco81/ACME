# -*- coding: utf-8 -*-
"""
Lenovo XClarity Administrator (LXCA 3.x, 4.x) - the server certificate of the management
server (its web interface and REST API, and the certificate LXCA shows its managed devices)
for a key LXCA makes itself ("the device makes the key", docs/certificates.md "Key made by the
device"). Lenovo: POST /serverCertificate takes only a certificate that "must have been created
from the certificate signing request" of LXCA - no key can be imported. So acme asks LXCA for a
new key and CSR at every issue and renewal (device_csr) and, right after the issue, uploads the
certificate signed for it (deploy, with no key).

    POST /certificateSigningRequest   {CommonName, Country, StateProvince, StateLocality,
                                       Organization, OrganizationUnit,
                                       subjectAlternativeNames: {generalNames: [
                                           {type: "dNSName" | "iPAddress", name}]}}
                                       -> {response: [{path}], result: "success"}
    GET  /certificateSigningRequest?path=<path>       -> the CSR (PEM)
    POST /trustedCertificates   {certificate: PEM}    the root and each intermediate, before
                                                      the upload (Lenovo: else the managed
                                                      devices turn untrusted)
    POST /serverCertificate/tmp  multipart "uploadedfile": the certificate, the intermediates
                                 and the root, PEM     -> FQXHMSE0134I, response.jobPath
    GET  /serverCertificate                           (Test: the certificate served, read only)

Signed in with HTTP Basic (Lenovo's REST examples). Once the certificate is uploaded, LXCA 4.0
and later restart the web server and end every session (3.x kept them); when the CA is new to
LXCA it starts a job handing the CA out to its managed devices (jobPath) - the job's result is
said, not waited for. The calls are the same in LXCA 3.x and 4.x: one version of the module.

Sources:
    https://pubs.lenovo.com/lxca/certificates_server_deploytolxca      (the steps, Key Usage,
        EKU server and client authentication, the restart of the web server from 4.0)
    https://pubs.lenovo.com/lxca/certificates_server_installexternallysigned  (the whole chain,
        the root and intermediates in the trust store first)
    https://pubs.lenovo.com/lxca/certificates_workwith   (RSA 2048 / SHA-256, RSA 3072 /
        SHA-384; no ECDSA, no RSA-PSS for the server certificate)
    https://pubs.lenovo.com/lxca_scripting/rest_api_certificatesigningrequest_post, ..._get,
        rest_api_servercertificate_tmp_post, rest_api_trustedcertificates_post
    https://pubs.lenovo.com/lxca/roles_create             (lxc-security-admin)

Less certain (not tried on an LXCA; Lenovo's pages could not be read again here - taken from
the vendor guide written from them): the SAN type of an IP address ("iPAddress", as Lenovo's
example writes it - the list of types writes "ipAddress"); the CSR's GET answering the PEM
itself (a JSON holding it is read too); the key LXCA makes (by its cryptographic mode - RSA
2048 or, NIST strict, 3072: no choice is sent); a CA certificate already in the trust store
answered with an error (words of "already"/"exists" taken as done).
"""
from __future__ import annotations

import ipaddress
import json
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, http_fields, tls_fields, verify_fields,
    text, multipart, split_hostport, served_fingerprint, fp_of)
from acmelib.plugins.targets._x509 import split_chain
from acmelib.plugins.targets.lenovo_xcc import find_csr

CSR = '/certificateSigningRequest'
TRUST = '/trustedCertificates'
UPLOAD = '/serverCertificate/tmp'
SERVER = '/serverCertificate'


def is_ip(name):
    try:
        ipaddress.ip_address(text(name).strip('[]'))
        return True
    except ValueError:
        return False


class LenovoLxcaTarget(HttpTarget):
    kind = 'lenovo_lxca'
    discovery = False
    title = 'Lenovo XClarity Administrator'
    vendor = 'Lenovo'
    description = ('The server certificate of a Lenovo XClarity Administrator (LXCA 3.x, 4.x: '
                   'web interface, REST API, the certificate its managed devices see) for a '
                   'key LXCA makes itself: at every issue and renewal acme asks it for a new '
                   'key and CSR over its REST API, puts the CA certificates in its trust store '
                   'and uploads the certificate signed for it.')
    doc = 'targets.md'
    module_version = ''
    version_label = 'LXCA 3.x - 4.x'
    device_key = True
    device_key_types = ('rsa-2048', 'rsa-3072')

    fields = http_fields(443, 'lxca.example.local') + [
        field('user', 'User', 'text', required=True, placeholder='svc-cert',
              help='an LXCA account in the role group LXC-SECURITY-ADMIN (or a custom role '
                   'made from lxc-security-admin)'),
        field('password', 'Password', 'secret', required=True),
        field('csr_country', 'Country (C)', 'text', required=True, placeholder='CZ',
              help='two letters - LXCA asks for it in every CSR; the certificate\'s own '
                   'subject (its profile) wins'),
        field('csr_state', 'State or region (ST)', 'text', required=True, placeholder='Praha'),
        field('csr_city', 'City (L)', 'text', required=True, placeholder='Praha'),
        field('csr_org', 'Organization (O)', 'text', required=True, placeholder='Example s.r.o.'),
        field('csr_ou', 'Unit (OU)', 'text', placeholder='IT'),
    ] + tls_fields()
    deploy_fields = [
        field('trust_ca', 'Add the CA certificates to the trust store', 'bool', default=True,
              help='the root and the intermediates added to LXCA\'s Trusted Certificates '
                   'before the upload, as Lenovo asks (else the managed devices may turn '
                   'untrusted)'),
        field('root_pem', 'Root CA certificate', 'pem',
              help='the root the chain ends in, when the chain does not carry it (an ACME CA '
                   'sends none) - LXCA wants the whole chain, root included'),
    ] + verify_fields()

    # LXCA 4.0+ restarts its web server after the upload (every session ends)
    served_wait = (20, 15)

    def auth_headers(self):
        import base64
        tok = base64.b64encode(('%s:%s' % (self.c('user') or '', self.c('password') or ''))
                               .encode()).decode()
        return {'Authorization': 'Basic ' + tok}

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []

    def served_now(self, bundle):
        try:
            host, port = split_hostport('%s:%s' % (self.c('host'), self.c('port') or 443))
            return served_fingerprint(host, port, None) == fp_of(bundle)
        except (OSError, ValueError):
            return False

    # -- the CSR LXCA makes --------------------------------------------------------------
    def _payload(self, req):
        names = [text(n).strip() for n in (req.names or []) if text(n).strip()]
        subj = dict(req.subject or {})
        if not names:
            raise PluginError('the certificate has no name for the CSR', retry=False)
        if req.key_type not in self.device_key_types:
            raise PluginError('LXCA makes RSA keys only (%s, by its cryptographic mode) - '
                              'choose one of those key types for the certificate'
                              % ', '.join(self.device_key_types), retry=False)
        body = {'CommonName': text(subj.get('CN') or names[0]).strip()}
        miss = []
        for key, sk, ck, label in (('Country', 'C', 'csr_country', 'Country'),
                                   ('StateProvince', 'ST', 'csr_state', 'State'),
                                   ('StateLocality', 'L', 'csr_city', 'City'),
                                   ('Organization', 'O', 'csr_org', 'Organization'),
                                   ('OrganizationUnit', 'OU', 'csr_ou', None)):
            v = text(subj.get(sk) or self.c(ck) or '').strip()
            if v:
                body[key] = v
            elif label:
                miss.append(label)
        if miss:
            raise PluginError('LXCA asks for %s in every CSR - fill them in on the target'
                              % ', '.join(miss), retry=False)
        body['subjectAlternativeNames'] = {'generalNames': [
            {'type': 'iPAddress' if is_ip(n) else 'dNSName', 'name': n.strip('[]')}
            for n in names]}
        return body, names

    def device_csr(self, req):
        body, names = self._payload(req)
        st, hd, d = self.req('POST', CSR, body, what='asking LXCA for a new key and CSR',
                             timeout=180)
        path = ''
        if isinstance(d, dict):
            resp = d.get('response')
            if isinstance(resp, list) and resp and isinstance(resp[0], dict):
                path = text(resp[0].get('path'))
            elif isinstance(resp, dict):
                path = text(resp.get('path'))
            if text(d.get('result')).lower() not in ('', 'success'):
                raise PluginError('LXCA did not make the CSR: %s' % text(
                    json.dumps(d.get('messages')) if d.get('messages') else d.get('result')),
                    detail=text(json.dumps(d))[:4000])
        csr = find_csr(d)       # an LXCA that answers with the CSR itself
        if not csr:
            q = '?path=' + urllib.parse.quote(path, safe='') if path else ''
            st, hd, got = self.req('GET', CSR + q, headers={'Accept': '*/*'},
                                   what='downloading the CSR')
            csr = find_csr(got)
            if not csr:
                raise PluginError('LXCA gave no CSR to download',
                                  detail=text(json.dumps(got) if isinstance(got, (dict, list))
                                              else got)[:4000])
        self.ctx.step('LXCA made a new key and a CSR for %s' % ', '.join(names), 'ok')
        return csr

    # -- the certificate uploaded ----------------------------------------------------------
    def _trust(self, pem, what):
        try:
            self.req('POST', TRUST, {'certificate': pem.strip() + '\n'},
                     what='adding the %s to the trust store' % what)
            self.ctx.step('added the %s to LXCA\'s trusted certificates' % what, 'ok')
        except PluginError as e:
            low = str(e).lower()
            if ('said 400' in low or 'said 409' in low) and \
                    any(w in low for w in ('already', 'exist', 'duplicate')):
                self.ctx.step('the %s is in LXCA\'s trust store already' % what, 'ok')
                return
            raise

    def deploy(self, bundle, options):
        options = options or {}
        if getattr(bundle, 'key_pem', None):
            raise PluginError('LXCA takes only a certificate for a key it made itself - let the '
                              'device make the key (the certificate → Key: "Key made by the '
                              'device")', retry=False)
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by LXCA')
        inter, root = split_chain(bundle, text(options.get('root_pem')))
        if not root:
            self.ctx.step('no root CA certificate - the chain ends in an intermediate; LXCA '
                          'wants the root too (give it in the deployment\'s options)', 'warn')
        if as_bool(self.opt(options, 'trust_ca', True), True):
            if root:
                self._trust(root, 'root CA certificate')
            for i, pem in enumerate(inter):
                self._trust(pem, 'intermediate CA certificate%s' % (
                    ' %d' % (i + 1) if len(inter) > 1 else ''))
        chain = [text(bundle.cert_pem).strip()] + [p.strip() for p in inter] + \
            ([root.strip()] if root else [])
        data = ('\n'.join(chain) + '\n').encode()
        body, ctype = multipart([('uploadedfile', ('cert_chain.pem', data,
                                                   'application/octet-stream'))])
        st, hd, d = self.req('POST', UPLOAD, body, headers={'Content-Type': ctype},
                             what='uploading the server certificate', timeout=180)
        job = ''
        if isinstance(d, dict):
            if text(d.get('result')).lower() not in ('', 'success'):
                raise PluginError('LXCA did not take the certificate: %s' % text(
                    json.dumps(d.get('messages')) if d.get('messages') else d.get('result')),
                    detail=text(json.dumps(d))[:4000], retry=False)
            r = d.get('response')
            if isinstance(r, list) and r and isinstance(r[0], dict):
                r = r[0]
            if isinstance(r, dict):
                job = text(r.get('jobPath'))
        self.ctx.step('LXCA took the server certificate - its web server restarts (LXCA 4.0 '
                      'and later end every session)', 'ok')
        if job:
            self.ctx.step('LXCA hands the new CA to its managed devices (job %s) - look at '
                          'Jobs if a device turns untrusted' % job, 'info')
        self.remember(bundle, options)
        return 'uploaded the server certificate for LXCA\'s own key%s' % (
            ' (CA job %s)' % job if job else '')

    def test(self):
        st, hd, d = self.req('GET', SERVER, headers={'Accept': '*/*'},
                             what='reading the server certificate')
        has = 'BEGIN CERTIFICATE' in text(d if not isinstance(d, (dict, list))
                                           else json.dumps(d))
        return 'signed in to %s; LXCA %s its server certificate' % (
            self.c('host'), 'gave' if has else 'answered, without')
