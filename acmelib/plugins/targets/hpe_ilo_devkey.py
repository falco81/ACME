# -*- coding: utf-8 -*-
"""
HPE iLO 5 / 6 / 7 - the HTTPS certificate of the iLO for a key the iLO makes itself ("the
device makes the key", docs/certificates.md "Key made by the device"): HPE's own way,
"Generate CSR and Import an SSL Certificate" - the private key never leaves the iLO.

Why beside redfish@ilo (which puts acme's key on the iLO, the "sideload"): the sideload is
there only from iLO 5 2.78 and iLO 6 1.30 on, iLO 6 takes an RSA key that way only in the
security state Production and iLO 7 only in SecureStandard; an iLO in HighSecurity, FIPS or
CNSA, an older firmware, or a policy that a management controller's key must not leave it
are served by this one: the iLO makes the key in every state and firmware.

    POST   /redfish/v1/SessionService/Sessions  {UserName, Password}   -> X-Auth-Token
    GET    /redfish/v1/Managers -> Members[0]                          "iLO 6 v1.62"
    GET    <Manager>/SecurityService/                                  SecurityState, Links.HttpsCert
    GET    <Manager>/SecurityService/HttpsCert/      KeyType, Actions, CertificateSigningRequest
    PATCH  <HttpsCert> {"KeyType": "RSA" | "ECDSA"}  (iLO 6 1.70+ / iLO 7 1.17+, when another)
    POST   Actions["#HpeHttpsCert.GenerateCSR"].target
           {OrgName, OrgUnit, CommonName, Country, State, City, IncludeIP}
                                                     -> "GeneratingCertificate" (minutes)
    GET    <HttpsCert>  until CertificateSigningRequest is a new one     (up to ~10 minutes)
    POST   Actions["#HpeHttpsCert.ImportCertificate"].target  {"Certificate": the PEM}
                                                     -> the iLO resets itself (1-3 minutes)

What the iLO puts into its CSR: the common name, and its own IP addresses when IncludeIP
(there is no parameter for other alternative names). So a certificate here has one DNS name
- the iLO's name - and, when it has IP addresses too, they must be the iLO's own: IncludeIP
is sent then. Key: KeyType says RSA or ECDSA (ECDSA = P-384) where the iLO has it; without
it the iLO makes RSA in Production and ECDSA P-384 in HighSecurity, FIPS, CNSA and SuiteB.

Sources (2026-11): the iLO security service supplement of HPE's Redfish documentation
(GenerateCSR, the CSR read back, ImportCertificate, the reset, the security states and the
key made in them, LoginPriv + iLOConfigPriv); iLO 6 1.74 and iLO 7 1.25 resource
definitions (HpeHttpsCert, KeyType from iLO 6 1.70 / iLO 7 1.17); python-ilorest-library
examples generate_csr.py / import_ssl.py (actions read from HttpsCert, the wait for the CSR).

Uncertain: the RSA size the iLO makes (2048 taken - acme warns when the CSR says another);
whether the iLO adds its short host name to the CSR (acme's check of the CSR says it then);
whether the intermediates may follow the certificate on import (the certificate alone is
sent, as HPE's example does); iLO 4 (HpHttpsCert) is not in the documents read - refused.
"""
from __future__ import annotations

import ipaddress
import time

from acmelib.plugins.targets._common import (
    PluginError, field, as_bool, as_int, text, pem_blocks, verify_fields, http_fields)
from acmelib.plugins.targets.redfish import RedfishTarget
from acmelib.plugins.targets.redfish_ilo import RedfishIloTarget, ilo_version, fw_words

GENERATE = '#HpeHttpsCert.GenerateCSR'
IMPORT = '#HpeHttpsCert.ImportCertificate'
# the security states in which an iLO without KeyType makes ECDSA P-384 keys
ECDSA_STATES = ('HighSecurity', 'FIPS', 'CNSA', 'SuiteB')
KEY_TYPE = {'rsa-2048': 'RSA', 'ec-384': 'ECDSA'}


def _is_ip(name):
    try:
        ipaddress.ip_address(text(name).strip())
        return True
    except ValueError:
        return False


class HpeIloDeviceKeyTarget(RedfishIloTarget):
    kind = 'hpe_ilo_devkey'
    discovery = False
    title = 'HPE iLO 5 / 6 / 7 - key made by the iLO'
    vendor = 'HPE'
    module_version = ''
    version_label = 'iLO 5, iLO 6, iLO 7 (any firmware)'
    description = ('The HTTPS certificate of an HPE iLO 5, 6 or 7 for a key the iLO makes '
                   'itself: at every issue acme asks the iLO for a new key and CSR over Redfish '
                   '(HpeHttpsCert.GenerateCSR, a few minutes) and imports the signed '
                   'certificate, after which the iLO resets (1-3 minutes, the server is not '
                   'touched). For any firmware and security state (HighSecurity, FIPS, CNSA) - '
                   'the key never leaves the iLO.')
    doc = 'targets.md'
    device_key = True
    device_key_types = ('rsa-2048', 'ec-384')

    fields = http_fields(443, 'ilo.example.local') + [
        field('user', 'User', 'text', required=True, placeholder='svc-cert',
              help='an iLO account with the privileges Login and Configure iLO Settings only'),
        field('password', 'Password', 'secret', required=True),
        field('csr_country', 'Country (C)', 'text', required=True, placeholder='CZ',
              help='two letters - the iLO asks for it in every CSR; the certificate\'s own '
                   'subject (its profile) wins'),
        field('csr_state', 'State or region (ST)', 'text', required=True, placeholder='Praha'),
        field('csr_city', 'City (L)', 'text', required=True, placeholder='Praha'),
        field('csr_org', 'Organization (O)', 'text', required=True, placeholder='Example s.r.o.'),
        field('csr_ou', 'Unit (OU)', 'text', required=True, placeholder='IT'),
        field('csr_wait', 'Wait for the CSR at most (s)', 'number', default=900, advanced=True,
              help='the iLO makes its key and CSR in up to about 10 minutes'),
    ] + [f for f in RedfishTarget.fields if f['key'] not in ('host', 'port', 'user', 'password')]
    deploy_fields = verify_fields()

    _sleep = staticmethod(time.sleep)

    def manager_info(self):
        """(manager URI, its JSON, (generation, firmware)) - refused when not an iLO 5-7."""
        uri = self.manager()
        m = self.get(uri, what='reading the manager')
        oem = ((m.get('Oem') or {}).get('Hpe') or {})
        cur = (((oem.get('Firmware') or {}).get('Current') or {}).get('VersionString'))
        ver = ilo_version(m.get('FirmwareVersion'), cur, m.get('Model'))
        if ver is None:
            raise PluginError('this controller is not an HPE iLO (%s %s) - this target is for '
                              'iLO 5, 6 and 7' % (m.get('Model', '?'),
                                                  m.get('FirmwareVersion', '?')), retry=False)
        if ver[0] not in (5, 6, 7):
            raise PluginError('this is an iLO %d - this target is for iLO 5, 6 and 7' % ver[0],
                              retry=False)
        return uri, m, ver

    # -- the CSR the iLO makes ----------------------------------------------------------
    def _subject(self, req):
        subj = dict(getattr(req, 'subject', None) or {})
        out = {}
        for key, sk, ck in (('OrgName', 'O', 'csr_org'), ('OrgUnit', 'OU', 'csr_ou'),
                            ('Country', 'C', 'csr_country'), ('State', 'ST', 'csr_state'),
                            ('City', 'L', 'csr_city')):
            v = text(subj.get(sk) or self.c(ck) or '').strip()
            if v:
                out[key] = v
        miss = [k for k in ('OrgName', 'OrgUnit', 'Country', 'State', 'City') if not out.get(k)]
        if miss:
            raise PluginError('the iLO asks for %s in every CSR - fill them in on the target'
                              % ', '.join(miss), retry=False)
        return out

    def _names(self, req):
        """(the common name, IncludeIP) - refused when the iLO cannot make them."""
        names = list(req.names)
        dns = [n for n in names if not _is_ip(n)]
        ips = [n for n in names if _is_ip(n)]
        if len(dns) != 1:
            raise PluginError('the iLO puts one host name into its CSR (the common name) and, '
                              'when asked, its own IP addresses - give the certificate the iLO\'s '
                              'name and nothing else but its addresses (it has %s)'
                              % ', '.join(names), retry=False)
        cn = text((req.subject or {}).get('CN') or dns[0]).strip()
        if cn.lower().rstrip('.') != dns[0].lower().rstrip('.'):
            cn = dns[0]
        return cn, bool(ips)

    def _key_type(self, hc_uri, hc, state, kt):
        """Make the iLO make the key type asked: KeyType patched where it has it; refused in
        words where its security state decides."""
        want = KEY_TYPE.get(text(kt))
        if not want:
            raise PluginError('the iLO makes RSA 2048 or ECDSA P-384 keys - %s cannot be asked '
                              'of it' % kt, retry=False)
        if 'KeyType' in hc:
            if text(hc.get('KeyType')).upper() != want:
                self.req('PATCH', hc_uri, {'KeyType': want},
                         what='setting the key type to %s' % want)
                self.ctx.step('key type of the iLO certificate set to %s' % want, 'ok')
            return
        makes = 'ECDSA' if text(state) in ECDSA_STATES else 'RSA'
        if makes != want:
            raise PluginError('this iLO (security state %s, no KeyType) makes %s keys only - '
                              'choose the key type %s for this certificate' % (
                                  state or 'Production', makes,
                                  'ec-384' if makes == 'ECDSA' else 'rsa-2048'), retry=False)

    def device_csr(self, req):
        cn, include_ip = self._names(req)
        body = self._subject(req)
        if text(req.key_type) not in self.device_key_types:
            raise PluginError('the iLO makes RSA 2048 or ECDSA P-384 keys - %s cannot be asked '
                              'of it' % req.key_type, retry=False)
        body.update(CommonName=cn, IncludeIP=include_ip)
        seconds = as_int(self.c('csr_wait', 900), 900)
        self.login()
        try:
            mgr, m, (gen, fw) = self.manager_info()
            hc_uri, state = self.https_cert(mgr)
            hc = self.get(hc_uri, what='reading the HTTPS certificate')
            self._key_type(hc_uri, hc, state, req.key_type)
            before = text(hc.get('CertificateSigningRequest')).strip()
            act = ((hc.get('Actions') or {}).get(GENERATE) or {})
            target = text(act.get('target')) or \
                hc_uri.rstrip('/') + '/Actions/HpeHttpsCert.GenerateCSR'
            self.req('POST', target, body, timeout=120,
                     what='asking the iLO for a new key and CSR')
            self.ctx.step('the iLO %d (firmware %s) makes a new %s key and a CSR for %s%s - '
                          'it takes a few minutes' % (gen, fw_words(fw), req.key_type, cn,
                                                      ' and its IP addresses' if include_ip
                                                      else ''), 'info')
            csr = self._wait_csr(hc_uri, before, seconds)
            self.ctx.step('the iLO made its CSR', 'ok')
            return csr
        finally:
            self.logout()

    def _wait_csr(self, hc_uri, before, seconds):
        # counted by the waits made, not the clock: the same under a stand-in sleep
        waited, step = 0, 15
        while True:
            try:
                hc = self.get(hc_uri, what='reading the CSR')
                csr = text(hc.get('CertificateSigningRequest')).strip()
                if 'CERTIFICATE REQUEST-----' in csr and csr != before:
                    return csr + '\n'
            except PluginError as e:
                if not getattr(e, 'retry', True):
                    raise
                self.ctx.debug('the CSR cannot be read now: %s' % e)
            if waited >= seconds or self.ctx.cancelled():
                raise PluginError('the iLO made no new CSR in %d s - it may still be making it: '
                                  'try again later (a new request does not start another while '
                                  'it is busy)' % seconds)
            self._sleep(step)
            waited += step

    # -- the certificate put back -----------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        if getattr(bundle, 'key_pem', None):
            raise PluginError('this target takes only a certificate for a key the iLO made '
                              'itself - let the device make the key (the certificate → Key: '
                              '"Key made by the device"); for a key of acme\'s use the target '
                              'Server management (Redfish), version HPE iLO', retry=False)
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the iLO')
        pem = pem_blocks(bundle.cert_pem)[0].strip() + '\n'
        self.login()
        reset = False
        try:
            mgr, m, (gen, fw) = self.manager_info()
            hc_uri, state = self.https_cert(mgr)
            hc = self.get(hc_uri, what='reading the HTTPS certificate')
            x = hc.get('X509CertificateInformation') or {}
            self.ctx.step('the iLO %d (firmware %s) serves %s until %s - replaced' % (
                gen, fw_words(fw), x.get('Subject') or '?', x.get('ValidNotAfter') or '?'))
            act = ((hc.get('Actions') or {}).get(IMPORT) or {})
            target = text(act.get('target')) or \
                hc_uri.rstrip('/') + '/Actions/HpeHttpsCert.ImportCertificate'
            self.req('POST', target, {'Certificate': pem}, timeout=120,
                     what='importing the certificate')
            reset = True
            self.ctx.step('the iLO took the certificate for its own key - it resets (1-3 '
                          'minutes, the server is not touched)', 'ok')
        finally:
            if reset:
                self.session_uri = None          # gone with the reset
            self.logout()
        self.remember(bundle, options)
        return 'imported the HTTPS certificate for the iLO\'s own key, the iLO resets'

    def test(self):
        root = self.login()
        try:
            uri, m, (gen, fw) = self.manager_info()
            hc_uri, state = self.https_cert(uri)
            hc = self.get(hc_uri, what='reading the HTTPS certificate')
            x = hc.get('X509CertificateInformation') or {}
            acts = hc.get('Actions') or {}
            way = 'GenerateCSR and ImportCertificate offered' \
                if GENERATE in acts and IMPORT in acts else \
                'the actions not listed (taken as there)'
            if 'KeyType' in hc:
                keys = 'key type %s (RSA or ECDSA P-384 chosen per certificate)' % hc['KeyType']
            else:
                keys = 'makes %s keys' % ('ECDSA P-384' if text(state) in ECDSA_STATES
                                          else 'RSA')
            return 'signed in to %s: iLO %d firmware %s, security state %s, %s; %s; ' \
                   'certificate %s until %s, Redfish %s' % (
                       self.c('host'), gen, fw_words(fw), state or '?', keys, way,
                       x.get('Subject', '?'), x.get('ValidNotAfter', '?'),
                       root.get('RedfishVersion', '?'))
        finally:
            self.logout()
