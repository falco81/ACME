# -*- coding: utf-8 -*-
"""
HPE iLO 5 / 6 / 7: a version of the Redfish target (kind `redfish`, 1.0.95) that puts
acme's key and certificate on the iLO the way HPE documents it - the OEM resource
HpeHttpsCert, not the DMTF CertificateService.ReplaceCertificate of the plain module.

    POST   /redfish/v1/SessionService/Sessions  {UserName, Password}   -> X-Auth-Token
    GET    /redfish/v1/Managers -> Members[0]                          FirmwareVersion "iLO 6 v1.62"
    GET    <Manager>/SecurityService/                                  SecurityState, Links.HttpsCert
    GET    <Manager>/SecurityService/HttpsCert/                        KeyType, Actions
    PATCH  <HttpsCert> {"KeyType": "RSA" | "ECDSA"}                    (only when it says another)
    POST   Actions["#HpeHttpsCert.ImportCertificate"].target
           {"Certificate": certificate PEM + private key PEM}         -> the iLO resets itself

Why a version of its own: HPE's documents (the iLO security service supplement of the
Redfish documentation, iLO 5 "SSL certificate" of ilo-rest-api-docs, iLO 6 1.74 / iLO 7
1.23 resource definitions) give the certificate of iLO's web server and API only through
HpeHttpsCert: ImportCertificate takes a certificate for iLO's own CSR or - the "sideload"
- a certificate followed by its private key (iLO 5 2.78 and later, iLO 6 1.30 and later,
iLO 7). The DMTF NetworkProtocol/HTTPS/Certificates collection exists only from iLO 7
1.19 and HPE does not describe a ReplaceCertificate of it; iLO 6 lists no such action -
the plain module refuses there.

What is the same from iLO 5 2.78 to iLO 7 1.25 (so one version, not three): the action,
its body, the reset after it. What differs is checked, not sent differently:

  KeyType     iLO 6 1.70+ and iLO 7 1.17+ have it (RSA / ECDSA); it must match the key,
              else 400 ImportCertificateFailed - patched first when it says another.
              iLO 5 has none: nothing patched.
  RSA key     iLO 6 takes it only in the security state Production, iLO 7 only in
              SecureStandard - refused before anything is changed in another state.
  firmware    iLO 5 older than 2.78, iLO 6 older than 1.30, iLO 4 and anything not an
              iLO are refused before anything is changed.

Uncertain (the guide's own "unverified" list): iLO 5 2.78's sideload is documented as
"through iLOrest", which posts this very action; whether iLO 5 refuses an RSA key in a
security state other than Production is not said (not checked here); whether the
intermediates may follow the certificate in "Certificate" is not said - acme sends the
certificate and the key only, as HPE's example does (a client must know the
intermediate CA).
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import (
    PluginError, as_bool, text, verify_fields, pem_to_der)
from acmelib.plugins.targets.redfish import RedfishTarget

# generation: (the oldest firmware that takes a key, the newest the documents were read for)
ILO_FIRMWARE = {5: ((2, 78), (3, 99)), 6: ((1, 30), (1, 79)), 7: ((1, 0), (1, 25))}
# the security state an RSA key is taken in (iLO 5: not documented, not checked)
RSA_STATE = {6: 'Production', 7: 'SecureStandard'}

_OID_RSA = bytes.fromhex('2a864886f70d010101')          # rsaEncryption
_OID_EC = bytes.fromhex('2a8648ce3d0201')               # id-ecPublicKey


def key_family(bundle):
    """'RSA' | 'ECDSA' | '' - the kind of the certificate's key, from its public key (a
    PKCS#8 key PEM does not say it in its header)."""
    try:
        der = pem_to_der(bundle.cert_pem)
    except Exception:                                   # noqa: BLE001
        return ''
    if _OID_EC in der:
        return 'ECDSA'
    if _OID_RSA in der:
        return 'RSA'
    return ''


def ilo_version(*words):
    """(generation, (major, minor)) from what the manager says - "iLO 5 v2.78",
    "iLO 7 v1.12.00" -, None when it is not an iLO's."""
    for w in words:
        m = re.search(r'\biLO\s*(\d+)\b(?:\s*v?(\d+)\.(\d+))?', text(w), re.I)
        if m:
            gen = int(m.group(1))
            fw = (int(m.group(2)), int(m.group(3))) if m.group(2) else None
            return gen, fw
    return None


def fw_words(fw):
    return '%d.%02d' % fw if fw else '?'


class RedfishIloTarget(RedfishTarget):
    """HPE iLO 5 (2.78+), iLO 6 (1.30+), iLO 7: HpeHttpsCert.ImportCertificate with the key."""
    module_version = 'ilo'
    version_label = 'HPE iLO 5 (2.78+), iLO 6 (1.30+), iLO 7'
    description = ('HPE iLO 5 (2.78+), iLO 6 (1.30+), iLO 7: puts the certificate and its '
                   'private key on the iLO through HPE\'s HpeHttpsCert.ImportCertificate '
                   '(the key type set to match first), after which the iLO resets itself '
                   '(1-3 minutes, the server is not touched). Refused on another controller '
                   'or older firmware before anything is changed.')
    deploy_fields = verify_fields()

    def manager_info(self):
        """(manager URI, its JSON, (generation, firmware)) - refused when not an iLO it
        is for."""
        uri = self.manager()
        m = self.get(uri, what='reading the manager')
        oem = ((m.get('Oem') or {}).get('Hpe') or {})
        cur = (((oem.get('Firmware') or {}).get('Current') or {}).get('VersionString'))
        ver = ilo_version(m.get('FirmwareVersion'), cur, m.get('Model'))
        if ver is None:
            raise PluginError(
                'this controller is not an HPE iLO (%s %s) - the module version "%s" is for '
                'HPE iLO only; choose the plain Redfish version of the target' % (
                    m.get('Model', '?'), m.get('FirmwareVersion', '?'), self.version_label),
                retry=False)
        gen, fw = ver
        if gen not in ILO_FIRMWARE:
            raise PluginError(
                'this is an iLO %d - the module version "%s" is for iLO 5, 6 and 7' % (
                    gen, self.version_label), retry=False)
        low, checked = ILO_FIRMWARE[gen]
        if fw is None:
            self.ctx.step('the iLO %d firmware version cannot be read - going on' % gen, 'warn')
        elif fw < low:
            raise PluginError(
                'this iLO %d runs firmware %s - it takes a private key from %s on; update '
                'the iLO firmware' % (gen, fw_words(fw), fw_words(low)), retry=False)
        elif fw > checked:
            self.ctx.step('iLO %d firmware %s is newer than the documents this version was '
                          'checked against (%s)' % (gen, fw_words(fw), fw_words(checked)),
                          'warn')
        return uri, m, ver

    def https_cert(self, mgr):
        """(the HttpsCert URI, the security state or None)."""
        sec_uri = mgr.rstrip('/') + '/SecurityService/'
        state, uri = None, None
        try:
            sec = self.get(sec_uri, what='reading the security service')
            state = text(sec.get('SecurityState')) or None
            uri = (((sec.get('Links') or {}).get('HttpsCert')) or {}).get('@odata.id')
        except PluginError as e:
            self.ctx.debug('the security service cannot be read: %s' % e)
        return uri or sec_uri + 'HttpsCert/', state

    def test(self):
        root = self.login()
        try:
            uri, m, (gen, fw) = self.manager_info()
            hc, state = self.https_cert(uri)
            cur = self.get(hc, what='reading the HTTPS certificate')
            x = cur.get('X509CertificateInformation') or {}
            return 'signed in to %s: iLO %d firmware %s, security state %s, certificate %s ' \
                   'until %s, Redfish %s' % (
                       self.c('host'), gen, fw_words(fw), state or '?',
                       x.get('Subject', '?'), x.get('ValidNotAfter', '?'),
                       root.get('RedfishVersion', '?'))
        finally:
            self.logout()

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the iLO')
        fam = key_family(bundle)
        self.login()
        reset = False
        try:
            mgr, m, (gen, fw) = self.manager_info()
            hc_uri, state = self.https_cert(mgr)
            need = RSA_STATE.get(gen)
            if fam == 'RSA' and need and state and state != need:
                raise PluginError(
                    'this iLO %d is in the security state %s - it takes an RSA key only in %s; '
                    'use an ECDSA key type for this certificate' % (gen, state, need),
                    retry=False)
            hc = self.get(hc_uri, what='reading the HTTPS certificate')
            act = ((hc.get('Actions') or {}).get('#HpeHttpsCert.ImportCertificate') or {})
            target = text(act.get('target')) or \
                hc_uri.rstrip('/') + '/Actions/HpeHttpsCert.ImportCertificate'
            if 'KeyType' in hc and fam and text(hc.get('KeyType')).upper() != fam:
                self.req('PATCH', hc_uri, {'KeyType': fam},
                         what='setting the key type to %s' % fam)
                self.ctx.step('key type of the iLO certificate set to %s' % fam, 'ok')
            pem = text(bundle.as_format('cert-pem')).strip() + '\n' + \
                text(bundle.as_format('key-pem')).strip() + '\n'
            self.req('POST', target, {'Certificate': pem}, timeout=120,
                     what='importing the certificate and key')
            reset = True
            self.ctx.step('imported the certificate with its key - the iLO resets (1-3 '
                          'minutes, the server is not touched)', 'ok')
        finally:
            if reset:
                self.session_uri = None          # gone with the reset
            self.logout()
        self.remember(bundle, options)
        return 'imported the HTTPS certificate with its key, the iLO resets'

    @staticmethod
    def served_wait(options):
        """The iLO resets after every import: a few minutes."""
        return (20, 15)

    def verify(self, bundle, options):
        options = dict(options or {}, reset=True)
        return RedfishTarget.verify(self, bundle, options)
