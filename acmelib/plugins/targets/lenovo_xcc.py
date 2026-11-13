# -*- coding: utf-8 -*-
"""
Lenovo XClarity Controller (XCC3, XCC2, XCC) - the HTTPS certificate of the controller for a
key the controller makes itself ("the device makes the key", docs/certificates.md "Key made
by the device"). Lenovo documents that the XCC imports only a certificate signed from a CSR
made on the same XCC: no key of acme's can go there, so acme asks the XCC for a new key and
CSR at every issue and renewal (device_csr) and, right after the issue, puts the signed
certificate back (deploy, with no key).

    GET    /redfish/v1/                               -> Links.Sessions, CertificateService
    POST   <Sessions>  {UserName, Password}          -> X-Auth-Token, Location
    GET    /redfish/v1/Managers -> Members[0] -> NetworkProtocol
    GET    <CertificateService>                       -> Actions (GenerateCSR, ReplaceCertificate)
    POST   <CertificateService>/Actions/CertificateService.GenerateCSR
           {CertificateCollection: {"@odata.id": <NetworkProtocol>/HTTPS/Certificates},
            CommonName, AlternativeNames, Country, State, City, Organization,
            OrganizationalUnit, Email,
            KeyPairAlgorithm "TPM_ALG_ECDH" + KeyCurveId "TPM_ECC_NIST_P256|P384" |
            KeyPairAlgorithm "TPM_ALG_RSA" + KeyBitLength 2048|3072|4096   (XCC3 only)}
                                                      -> {CSRString}
    GET    <NetworkProtocol>/HTTPS/Certificates       -> Members[0] (the certificate's URI)
    POST   <CertificateService>/Actions/CertificateService.ReplaceCertificate
           {CertificateUri: {"@odata.id": ...}, CertificateType: "PEM",
            CertificateString: the certificate (+ the intermediates when asked)}
    DELETE <Location>                                  (signing out)

The version `xcc2` (XCC and XCC2, ThinkSystem V1-V3): no key type is sent - those make an RSA
key of their own -, and a firmware without the standard GenerateCSR gets Lenovo's OEM
service instead:

    POST <Manager>/Oem/Lenovo/Security/Actions/LenovoSecurityService.GenerateCSR
         {Title, Target, RequiredCertificateData: {Service: "Server", CountryName,
          StateOrProvinceName, LocalityName, OrganizationName, HostName},
          OptionalCertificateData: {OrganizationalUnitName, EmailAddress}}
    POST <Manager>/Oem/Lenovo/Security/Actions/LenovoSecurityService.DownloadCSR
         {Title: "DownloadCSR", Service: "Server", Format: "PEM"}         -> the CSR
    POST <Manager>/Oem/Lenovo/Security/Actions/LenovoSecurityService.ImportCertificate
         {Title: "ImportCertificate", Service: "Server", ImportCertificateType: "CSR",
          SignedCertificates: [the DER bytes]}

The XCC serves the new certificate within about 15 minutes, without a restart (Lenovo's XCC3
user guide, "SSL certificate handling"); the tests after the deployment wait that long.

Sources:
    https://pubs.lenovo.com/xcc3-restapi/certmgt_resource_certificateservice
    https://pubs.lenovo.com/xcc3-restapi/certmgt_generate_csr_post
    https://pubs.lenovo.com/xcc3-restapi/certmgt_replace_certificate_post
    https://pubs.lenovo.com/xcc-restapi/certificate_management
    https://pubs.lenovo.com/xcc3/nn1ia_c_sslcertificatehandling   (only a CSR of the same XCC,
        about 15 minutes until it is served)
    https://pubs.lenovo.com/xcc3/dw1lm_r_rolescommand             (the role: custom:nsc)
    https://github.com/lenovo/python-redfish-lenovo  (lenovo_ssl_certificate_generate_csr.py,
        lenovo_ssl_certificate_import.py: the key parameters, CertificateType PEM, the OEM way)

Less certain (not tried on a device): the KeyPairAlgorithm / KeyCurveId / KeyBitLength values
(from Lenovo's script and the DMTF schema - Lenovo's page lists KeyBitLength as a string; an
integer is sent, as the schema says); CertificateType "PEM" (Lenovo's script uses it, its
page does not say); whether the intermediates may follow the certificate (off by default);
the OEM answer's field holding the CSR (looked for anywhere in it) and the shape of
SignedCertificates (the DER as a list of byte values, as the script reads it); which key the
XCC / XCC2 make without a choice (RSA 2048 is assumed).
"""
from __future__ import annotations

import json

from acmelib.plugins.targets._common import (
    PluginError, field, as_bool, http_fields, tls_fields, verify_fields, text, pem_blocks,
    pem_to_der, chain_list)
from acmelib.plugins.targets.redfish import RedfishTarget

# acme's key type -> what GenerateCSR is asked for (XCC3)
KEY_PARAMS = {
    'ec-256': {'KeyPairAlgorithm': 'TPM_ALG_ECDH', 'KeyCurveId': 'TPM_ECC_NIST_P256'},
    'ec-384': {'KeyPairAlgorithm': 'TPM_ALG_ECDH', 'KeyCurveId': 'TPM_ECC_NIST_P384'},
    'rsa-2048': {'KeyPairAlgorithm': 'TPM_ALG_RSA', 'KeyBitLength': 2048},
    'rsa-3072': {'KeyPairAlgorithm': 'TPM_ALG_RSA', 'KeyBitLength': 3072},
    'rsa-4096': {'KeyPairAlgorithm': 'TPM_ALG_RSA', 'KeyBitLength': 4096},
}
GENERATE = '#CertificateService.GenerateCSR'
REPLACE = '#CertificateService.ReplaceCertificate'
OEM = '/Oem/Lenovo/Security/Actions/LenovoSecurityService.'


def find_csr(data):
    """The CSR in an answer, wherever it is: a PEM string, or a list of the DER's bytes."""
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode('ascii', 'replace')
    if isinstance(data, str):
        return data if 'CERTIFICATE REQUEST-----' in data else ''
    if isinstance(data, dict):
        for k in ('CSRString', 'CSR', 'Csr', 'csr'):
            got = find_csr(data.get(k))
            if got:
                return got
        for v in data.values():
            got = find_csr(v)
            if got:
                return got
    if isinstance(data, list):
        if data and all(isinstance(x, int) and 0 <= x < 256 for x in data):
            import base64
            b64 = base64.b64encode(bytes(data)).decode()
            return '-----BEGIN CERTIFICATE REQUEST-----\n%s\n-----END CERTIFICATE REQUEST-----\n' \
                % '\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64))
        for v in data:
            got = find_csr(v)
            if got:
                return got
    return ''


class LenovoXccTarget(RedfishTarget):
    kind = 'lenovo_xcc'
    discovery = False
    title = 'Lenovo XClarity Controller (XCC, XCC2, XCC3)'
    vendor = 'Lenovo'
    description = ('The HTTPS certificate of a Lenovo XClarity Controller (web, Redfish, LDAP '
                   'client) for a key the XCC makes itself: at every issue and renewal acme '
                   'asks it for a new key and CSR over Redfish, and imports the certificate '
                   'signed for it.')
    doc = 'targets.md'
    module_version = ''
    version_label = 'XCC3 (ThinkSystem V4) - the key type chosen'
    # the device makes the key (docs/writing-a-module.md "The device makes the key")
    device_key = True
    device_key_types = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
    # the key type sent with GenerateCSR; Lenovo's OEM security service where the standard
    # GenerateCSR is not there (older XCC / XCC2 firmware)
    send_key_type = True
    oem_fallback = False

    fields = http_fields(443, 'xcc.example.local') + [
        field('user', 'User', 'text', required=True, placeholder='svccert',
              help='an XCC account with the privilege "Configuration - Networking and BMC '
                   'Security" (nsc) - a role of its own with only that'),
        field('password', 'Password', 'secret', required=True),
        field('csr_country', 'Country (C)', 'text', required=True, placeholder='CZ',
              help='two letters - the XCC asks for it in every CSR; the certificate\'s own '
                   'subject (its profile) wins'),
        field('csr_state', 'State or region (ST)', 'text', required=True, placeholder='Praha'),
        field('csr_city', 'City (L)', 'text', required=True, placeholder='Praha'),
        field('csr_org', 'Organization (O)', 'text', required=True, placeholder='Example s.r.o.'),
        field('csr_ou', 'Unit (OU)', 'text', placeholder='IT'),
        field('csr_email', 'E-mail in the CSR', 'text', advanced=True),
        field('basic_auth', 'Basic authentication instead of a session', 'bool', default=False,
              advanced=True, help='for a controller whose sessions do not work'),
    ] + tls_fields()
    deploy_fields = [
        field('send_chain', 'Send the intermediates too', 'bool', default=False,
              help='off: the certificate alone, as Lenovo\'s examples import it; on: the '
                   'certificate followed by its intermediate CA certificates'),
        field('certificate_uri', 'Certificate URI', 'text', advanced=True,
              placeholder='/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1',
              help='empty: the first HTTPS certificate of the first manager'),
    ] + verify_fields()

    # the XCC serves a new certificate within about 15 minutes, without a restart
    served_wait = (32, 30)

    # -- the CSR the XCC makes ----------------------------------------------------------
    def _cs(self, root):
        return (root.get('CertificateService') or {}).get('@odata.id') or \
            '/redfish/v1/CertificateService'

    def _actions(self, cs):
        """The CertificateService's actions ({} when it lists none, or cannot be read)."""
        try:
            svc = self.get(cs, what='reading the certificate service')
        except PluginError as e:
            if '(404)' in str(e):
                return None                 # no standard certificate service at all
            raise
        acts = svc.get('Actions')
        return acts if isinstance(acts, dict) else {}

    def _collection(self, options):
        uri = text((options or {}).get('certificate_uri')).strip()
        if uri:
            return uri.rstrip('/').rsplit('/', 1)[0]
        m = self.get(self.manager(), what='reading the manager')
        np = (m.get('NetworkProtocol') or {}).get('@odata.id')
        if not np:
            raise PluginError('the manager has no NetworkProtocol: give the Certificate URI',
                              retry=False)
        return np.rstrip('/') + '/HTTPS/Certificates'

    def _subject(self, req):
        subj = dict(getattr(req, 'subject', None) or {})
        names = list(getattr(req, 'names', None) or [])
        out = {'CommonName': text(subj.get('CN') or (names[0] if names else '')).strip()}
        for key, sk, ck in (('Country', 'C', 'csr_country'), ('State', 'ST', 'csr_state'),
                            ('City', 'L', 'csr_city'), ('Organization', 'O', 'csr_org'),
                            ('OrganizationalUnit', 'OU', 'csr_ou'),
                            ('Email', 'emailAddress', 'csr_email')):
            v = text(subj.get(sk) or self.c(ck) or '').strip()
            if v:
                out[key] = v
        if not out['CommonName']:
            raise PluginError('the certificate has no name for the CSR', retry=False)
        miss = [k for k in ('Country', 'State', 'City', 'Organization') if not out.get(k)]
        if miss:
            raise PluginError('the XCC asks for %s in every CSR - fill them in on the target'
                              % ', '.join(miss), retry=False)
        return out

    def _key_params(self, key_type):
        if not self.send_key_type:
            return {}
        got = KEY_PARAMS.get(text(key_type))
        if not got or key_type not in self.device_key_types:
            raise PluginError('the XCC makes %s keys - %s cannot be asked of it' % (
                ', '.join(self.device_key_types), key_type), retry=False)
        return dict(got)

    def device_csr(self, req):
        names = list(req.names)
        subj = self._subject(req)
        if not self.send_key_type and req.key_type not in self.device_key_types:
            raise PluginError('this XCC makes %s keys only - choose that key type for the '
                              'certificate' % ', '.join(self.device_key_types), retry=False)
        keyp = self._key_params(req.key_type)
        root = self.login()
        try:
            cs = self._cs(root)
            acts = self._actions(cs)
            if acts is not None and (not acts or GENERATE in acts):
                act = (acts or {}).get(GENERATE) or {}
                target = text(act.get('target')) or cs + '/Actions/CertificateService.GenerateCSR'
                coll = self._collection(req.options)
                body = dict(subj, CertificateCollection={'@odata.id': coll},
                            AlternativeNames=names)
                body.update(keyp)
                st, hd, d = self.req('POST', target, body, what='asking the XCC for a new key '
                                     'and CSR', timeout=180)
                csr = find_csr(d)
                if not csr:
                    raise PluginError('the XCC answered GenerateCSR without a CSR',
                                      detail=text(json.dumps(d) if isinstance(d, (dict, list))
                                                  else d)[:4000])
                self.ctx.step('the XCC made a new key%s and a CSR for %s (%s)' % (
                    ' (%s)' % req.key_type if keyp else '', ', '.join(names), coll), 'ok')
                return csr
            if not self.oem_fallback:
                raise PluginError('the XCC offers no CertificateService.GenerateCSR - an XCC or '
                                  'XCC2 with older firmware: choose the version "xcc2" of this '
                                  'target (Lenovo\'s own security service)', retry=False)
            return self._oem_csr(req, subj)
        finally:
            self.logout()

    def _oem_csr(self, req, subj):
        names = list(req.names)
        if len(names) > 1:
            raise PluginError('this XCC makes its CSR through Lenovo\'s own service, which takes '
                              'one host name - give the certificate one name (it has %s)'
                              % ', '.join(names), retry=False)
        # its CSR has no SAN - its one name is HostName (the CN): the certificate's name, not
        # another CN of the profile, which acme's check of the CSR would refuse only after the
        # XCC made its key (1.0.96, as hpe_ilo_devkey)
        host = text(names[0]).strip() if names else subj['CommonName']
        base = self.manager().rstrip('/') + OEM
        need = {'Service': 'Server', 'CountryName': subj['Country'],
                'StateOrProvinceName': subj['State'], 'LocalityName': subj['City'],
                'OrganizationName': subj['Organization'], 'HostName': host}
        more = {}
        if subj.get('OrganizationalUnit'):
            more['OrganizationalUnitName'] = subj['OrganizationalUnit']
        if subj.get('Email'):
            more['EmailAddress'] = subj['Email']
        self.req('POST', base + 'GenerateCSR', {
            'Title': 'GenerateCSR', 'Target': base + 'GenerateCSR',
            'RequiredCertificateData': need, 'OptionalCertificateData': more},
            what='asking the XCC for a new key and CSR (Lenovo OEM)', timeout=180)
        st, hd, d = self.req('POST', base + 'DownloadCSR', {
            'Title': 'DownloadCSR', 'Service': 'Server', 'Format': 'PEM'},
            what='downloading the CSR (Lenovo OEM)')
        csr = find_csr(d)
        if not csr:
            raise PluginError('the XCC gave no CSR to download',
                              detail=text(json.dumps(d) if isinstance(d, (dict, list))
                                          else d)[:4000])
        self.ctx.step('the XCC made a new key and a CSR for %s (Lenovo OEM)' % names[0], 'ok')
        return csr

    # -- the certificate put back -----------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        if getattr(bundle, 'key_pem', None):
            raise PluginError('the XCC takes only a certificate for a key it made itself - let '
                              'its device make the key (the certificate → Key: "Key made by '
                              'the device")', retry=False)
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the XCC')
        pem = text(bundle.cert_pem).strip() + '\n'
        if as_bool(options.get('send_chain')):
            pem += ''.join(p.strip() + '\n' for p in chain_list(bundle))
        root = self.login()
        try:
            cs = self._cs(root)
            acts = self._actions(cs)
            if acts is not None and (not acts or REPLACE in acts):
                uri = self.cert_uri(options)
                if isinstance(uri, tuple):
                    coll = uri[1]
                    self.req('POST', coll, {'CertificateString': pem, 'CertificateType': 'PEM'},
                             what='importing the certificate to %s' % coll, timeout=120)
                    did = coll
                else:
                    act = (acts or {}).get(REPLACE) or {}
                    target = text(act.get('target')) or \
                        cs + '/Actions/CertificateService.ReplaceCertificate'
                    self.req('POST', target, {
                        'CertificateUri': {'@odata.id': uri}, 'CertificateType': 'PEM',
                        'CertificateString': pem}, what='importing the certificate (%s)' % uri,
                        timeout=120)
                    did = uri
            elif self.oem_fallback:
                base = self.manager().rstrip('/') + OEM
                der = pem_to_der(pem_blocks(bundle.cert_pem)[0])
                self.req('POST', base + 'ImportCertificate', {
                    'Title': 'ImportCertificate', 'Service': 'Server',
                    'ImportCertificateType': 'CSR', 'SignedCertificates': list(der)},
                    what='importing the certificate (Lenovo OEM)', timeout=120)
                did = 'Lenovo OEM'
            else:
                raise PluginError('the XCC offers no CertificateService.ReplaceCertificate - '
                                  'choose the version "xcc2" of this target', retry=False)
        finally:
            self.logout()
        self.ctx.step('the XCC took the certificate (%s) - it serves it within about 15 '
                      'minutes, without a restart' % did, 'ok')
        self.remember(bundle, options)
        return 'imported the HTTPS certificate for the XCC\'s own key (%s)' % did

    def test(self):
        root = self.login()
        try:
            m = self.get(self.manager(), what='reading the manager')
            acts = self._actions(self._cs(root))
            if acts is None or (acts and GENERATE not in acts):
                way = 'Lenovo\'s own security service (no standard GenerateCSR)' \
                    if self.oem_fallback else 'NO standard GenerateCSR - choose the version ' \
                    '"xcc2" of this target'
            else:
                way = 'the CSR through CertificateService.GenerateCSR'
            return 'signed in to %s: %s %s, firmware %s, Redfish %s; %s' % (
                self.c('host'), m.get('Manufacturer', root.get('Vendor', '')),
                m.get('Model', m.get('Name', '?')), m.get('FirmwareVersion', '?'),
                root.get('RedfishVersion', '?'), way)
        finally:
            self.logout()


class LenovoXcc2Target(LenovoXccTarget):
    module_version = 'xcc2'
    version_label = 'XCC and XCC2 (ThinkSystem V1-V3) - RSA 2048, Lenovo OEM on older firmware'
    device_key_types = ('rsa-2048',)
    send_key_type = False
    oem_fallback = True
