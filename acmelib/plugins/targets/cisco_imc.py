# -*- coding: utf-8 -*-
"""
Cisco IMC (standalone UCS C-Series): the HTTPS certificate of the IMC put in as an
"External Certificate" with its key, through the IMC XML API, then activated.

    POST /nuova  <aaaLogin inName= inPassword=/>                       -> outCookie
    POST /nuova  <configResolveDn dn="sys/cert-mgmt/curr-cert"/>        (Try: read only)
    POST /nuova  <configConfMo dn="sys/cert-mgmt/external-cert-upload">
                   <uploadExternalCertificate adminAction="content-cert-upload" certificateContent=PEM/>
    POST /nuova  <configConfMo dn="sys/cert-mgmt/external-pvt-key-upload">
                   <uploadExternalPrivateKey adminAction="content-cert-upload" certificateContent=PEM/>
    POST /nuova  <configConfMo dn="sys/cert-mgmt">
                   <certificateManagement adminAction="activate-external-cert"/>
    POST /nuova  <aaaLogout inCookie=/>

Sources (2026-11): Cisco IMC XML API Programmer's Guide 6.0, "Examples of Common Tasks"
(External Certificate: the DNs, classes and adminAction values above), Cisco IMC CLI
Configuration Guide 6.0 "Managing Certificates and Server Security" (upload-paste-external-
certificate, upload-paste-external-private-key, activate-external-certificate; "Admin
privileges for all certificate tasks"; activation drops HTTPS/SSH sessions and restarts the
IMC), the official imcsdk (mometa UploadExternalCertificate, UploadExternalPrivateKey,
CertificateManagement, CurrentCertificate). A "server certificate" upload takes only a
certificate for a CSR the IMC made - an external one is the way for a key made elsewhere.

The same objects in Cisco IMC 4.x (M5/M6) and 6.0 (M7, M8) - one module. External keys:
RSA 2048 / 4096 (8192 on M5 and later), files up to 8 KB. Not used: Redfish with a key in
CertificateString (Cisco shows it for KMIP only, not for HTTPS).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.sax.saxutils import quoteattr

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, http_fields, tls_fields, verify_fields,
    text, served_fingerprint, fp_of, split_hostport, family_of,
    join_hostport)

MAX_FILE = 8192


def attr(v):
    """An XML attribute value that keeps a PEM's line ends (a raw newline in an
    attribute is read back as a space)."""
    return quoteattr(text(v), {'\n': '&#10;', '\r': '&#13;', '\t': '&#9;'})


class CiscoImcTarget(HttpTarget):
    kind = 'cisco_imc'
    discovery = False
    title = 'Cisco IMC (UCS C-Series, standalone)'
    vendor = 'Cisco'
    description = ('Puts the HTTPS certificate and its key into a standalone Cisco IMC (UCS '
                   'C-Series M5 - M8, IMC 4.x - 6.0) as an External Certificate through the IMC '
                   'XML API and activates it - the IMC restarts its web and SSH services, the '
                   'server keeps running. RSA keys only.')
    doc = 'targets.md'
    fields = http_fields(443, 'cimc.example.local') + [
        field('user', 'User', 'text', required=True, default='svc-cert',
              help='an IMC user with the role admin (every certificate task needs it)'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('with_chain', 'Send the chain with the certificate', 'bool', default=False,
              help='the External Certificate holds the certificate and the intermediates '
                   '(off: the certificate alone)'),
    ] + verify_fields()

    cookie = None

    # -- the XML API -------------------------------------------------------------------
    def xml(self, body, what, check=True):
        st, hd, raw = self.req('POST', '/nuova', body, what=what, timeout=120,
                               headers={'Content-Type': 'application/x-www-form-urlencoded',
                                        'Accept': 'text/xml'})
        s = text(raw).strip()
        try:
            root = ET.fromstring(s.encode('utf-8'))
        except ET.ParseError:
            raise PluginError('%s: the IMC did not answer in XML: %s' % (what, s[:200]),
                              detail=s[:4000])
        code = text(root.get('errorCode')).strip()
        if check and code and code != '0':
            raise PluginError('%s: the IMC said error %s - %s' % (
                what, code, text(root.get('errorDescr')).strip() or '?'),
                detail=s[:4000], retry=False)
        return root

    def login(self):
        root = self.xml('<aaaLogin inName=%s inPassword=%s/>' % (
            attr(self.c('user')), attr(self.c('password') or '')), 'signing in', check=False)
        code = text(root.get('errorCode')).strip()
        if code and code != '0':
            raise PluginError('signing in: the IMC said error %s - %s' % (
                code, text(root.get('errorDescr')).strip() or '?'), retry=False)
        self.cookie = text(root.get('outCookie')).strip()
        if not self.cookie:
            raise PluginError('the IMC gave no session cookie on signing in', retry=False)

    def logout(self):
        if self.cookie:
            try:
                self.xml('<aaaLogout cookie=%s inCookie=%s/>' % (attr(self.cookie),
                                                                  attr(self.cookie)),
                         'signing out', check=False)
            except PluginError:
                pass
        self.cookie = None

    def conf(self, dn, inner, what):
        return self.xml('<configConfMo cookie=%s inHierarchical="false" dn=%s><inConfig>%s'
                        '</inConfig></configConfMo>' % (attr(self.cookie), attr(dn), inner), what)

    # -- the work ----------------------------------------------------------------------
    def served_now(self, bundle):
        try:
            host, port = split_hostport(join_hostport(self.c('host'), self.c('port') or 443))
            return served_fingerprint(host, port, None) == fp_of(bundle)
        except (OSError, ValueError):
            return False

    def test(self):
        self.login()
        try:
            root = self.xml('<configResolveDn cookie=%s inHierarchical="false" '
                            'dn="sys/cert-mgmt/curr-cert"/>' % attr(self.cookie),
                            'reading the current certificate')
            cur = root.find('.//currentCertificate')
            got = dict(cur.attrib) if cur is not None else {}
            return 'signed in to %s: the IMC serves %s, valid to %s' % (
                self.c('host'), got.get('commonName') or got.get('subject') or '?',
                got.get('validTo') or '?')
        finally:
            self.logout()

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the IMC')
        if family_of(bundle) not in ('rsa', ''):
            raise PluginError('the IMC takes RSA keys only for an External Certificate (2048 '
                              'or 4096 bits) - choose an RSA key type', retry=False)
        try:
            key = text(bundle.as_format('key-rsa'))
        except Exception as e:                          # noqa: BLE001
            raise PluginError('the key cannot be written as an RSA key: %s' % e, retry=False)
        if 'BEGIN RSA PRIVATE KEY' not in key:
            raise PluginError('the IMC takes RSA keys only for an External Certificate - choose '
                              'an RSA key type', retry=False)
        cert = text(bundle.as_format('fullchain-pem' if as_bool(
            self.opt(options, 'with_chain', False)) else 'cert-pem'))
        for what, v in (('certificate', cert), ('key', key)):
            if len(v.encode()) > MAX_FILE:
                raise PluginError('the %s is %d bytes - the IMC takes 8 KB at most'
                                  % (what, len(v.encode())), retry=False)
        self.login()
        activated = False
        try:
            self.conf('sys/cert-mgmt/external-cert-upload',
                      '<uploadExternalCertificate dn="sys/cert-mgmt/external-cert-upload" '
                      'adminAction="content-cert-upload" certificateContent=%s/>' % attr(cert),
                      'uploading the external certificate')
            self.ctx.step('the IMC took the external certificate', 'ok')
            self.conf('sys/cert-mgmt/external-pvt-key-upload',
                      '<uploadExternalPrivateKey dn="sys/cert-mgmt/external-pvt-key-upload" '
                      'adminAction="content-cert-upload" certificateContent=%s/>' % attr(key),
                      'uploading the external private key')
            self.ctx.step('the IMC took the external private key', 'ok')
            self.conf('sys/cert-mgmt', '<certificateManagement dn="sys/cert-mgmt" '
                      'adminAction="activate-external-cert"/>',
                      'activating the external certificate')
            activated = True
            self.ctx.step('the external certificate is activated - the IMC restarts its web '
                          'and SSH services (a few minutes)', 'ok')
        finally:
            if activated:
                self.cookie = None      # the sessions are gone with the activation
            self.logout()
        self.remember(bundle, options)
        return 'activated the external certificate, the IMC restarts its services'

    served_wait = (30, 15)          # the activation restarts the IMC's services

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []

    def verify(self, bundle, options):
        options = dict(options or {})
        if not options.get('verify'):
            options['verify'] = join_hostport(self.c('host'), as_int(self.c('port', 443), 443))
        options.setdefault('verify_tries', 30)
        options.setdefault('verify_wait', 15)
        return HttpTarget.verify(self, bundle, options)
