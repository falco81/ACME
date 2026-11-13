# -*- coding: utf-8 -*-
"""
HPE Synergy Composer (HPE OneView for Synergy) and HPE OneView: certificates for a key the
device makes itself ("the device makes the key", docs/certificates.md "Key made by the
device") - the appliance's own HTTPS certificate made from its CSR, and the HTTPS
certificate of an enclosure's management module (the bay of a frame's Frame Link Module,
or a c7000's Onboard Administrator), which OneView offers through a CSR only.

The module hpe_oneview imports a key of acme's (PKCS#12) for the appliance; this one is for
an administrator who wants the key to stay on the appliance, and for the enclosures, which
take no key at all. At every issue and renewal acme asks for a new key and CSR, has the CSR
signed and puts the certificate back right away.

    GET    /rest/version                                   -> currentVersion (X-API-Version)
    POST   /rest/login-sessions {userName, password, authLoginDomain, loginMsgAck}
                                                           -> sessionID ("Auth" header)
  the appliance (Composer / OneView):
    POST   /rest/certificates/https/certificaterequest
           {type: CertificateSigningRequestV2, country, state, locality, organization,
            organizationalUnit, commonName, alternativeName: "a,b,10.0.0.20", email,
            cnsaCertRequested: true for RSA 3072}          -> {base64Data: the CSR} (or a task,
                                                              then GET of the same URI)
    GET    /rest/certificates/ca/<alias>, POST /rest/certificates/ca   (the intermediates)
    PUT    /rest/certificates/https/certificaterequest {type: CertificateDataV2, base64Data}
                                                           -> a task; web services reload
  an enclosure's management module (bay N):
    GET    /rest/enclosures?filter="name='<name>'"         -> members[0].uri
    POST   <enclosure>/https/certificaterequest?bayNumber=N
           {type: CertificateDtoV2, organization, organizationalUnit, locality, state,
            country, commonName}                           -> a task or the CSR
    GET    <enclosure>/https/certificaterequest?bayNumber=N   -> {base64Data: the CSR}
    PUT    <enclosure>/https/certificaterequest?bayNumber=N {type: CertificateDataV2,
            base64Data}                                     -> a task
    GET    /rest/tasks/<id>                                -> taskState
    DELETE /rest/login-sessions                            (signing out)

Sources (the OneView API reference is not machine-readable - HPE's own libraries): the
POSH-HPEOneView 10.00 module (New-OVApplianceCsr, Install-OVApplianceCertificate: the URI,
CertificateSigningRequestV2 / CertificateDataV2, cnsaCertRequested; "only RSA certificates
are supported for the appliance certificate"; RSA 2048 by default, 3072 for CNSA),
oneview-python servers/enclosures.py (generate_csr / get_csr / import_certificate: the URI,
bayNumber, CertificateDtoV2), endpoints-support.md (both URIs for API 2800 - 9200, OneView
9.x - 11.x and Synergy Composer alike): one module, the X-API-Version the appliance takes
(at most 9200).

Uncertain (the vendor guide's own list): whether the appliance's POST answers with the CSR
or with a task (both handled: the CSR read back after the task); the enclosure CSR call is
documented by the SDK for an Onboard Administrator - that it does the same for a Synergy
frame's Frame Link Module is HPE's API reference's word, not checked on a frame; the
enclosure's CSR body has no alternative names (one name, the common name); which key a
Frame Link Module makes (RSA 2048 taken - acme warns when the CSR says another); the least
role (Infrastructure administrator, unscoped).
"""
from __future__ import annotations

import ipaddress
import urllib.parse

from acmelib.plugins.targets._common import (
    PluginError, field, as_bool, as_int, verify_fields, text, chain_list, chain_id,
    pem_blocks)
from acmelib.plugins.targets.hpe_oneview import HpeOneViewTarget

APPLIANCE_CSR = '/rest/certificates/https/certificaterequest'
# the subject fields: (body key, profile key, target field, longest the appliance takes)
SUBJECT = (('country', 'C', 'csr_country', 128), ('state', 'ST', 'csr_state', 128),
           ('locality', 'L', 'csr_city', 128), ('organization', 'O', 'csr_org', 64),
           ('organizationalUnit', 'OU', 'csr_ou', 64))


def _is_ip(name):
    try:
        ipaddress.ip_address(text(name).strip())
        return True
    except ValueError:
        return False


def find_csr(d):
    """The CSR in an answer (base64Data, or anywhere in it), '' when none."""
    if isinstance(d, str):
        return d if 'CERTIFICATE REQUEST-----' in d else ''
    if isinstance(d, dict):
        for k in ('base64Data', 'csr', 'CSR'):
            got = find_csr(d.get(k))
            if got:
                return got
        for v in d.values():
            got = find_csr(v)
            if got:
                return got
    if isinstance(d, list):
        for v in d:
            got = find_csr(v)
            if got:
                return got
    return ''


class HpeSynergyTarget(HpeOneViewTarget):
    kind = 'hpe_synergy'
    discovery = False
    title = 'HPE Synergy Composer / OneView - key made by the device'
    vendor = 'HPE'
    module_version = ''
    version_label = 'OneView for Synergy 9.x - 11.x (detects the API)'
    description = ('HPE Synergy Composer (OneView for Synergy 9.x - 11.x) and HPE OneView: '
                   'the appliance\'s HTTPS certificate, or that of an enclosure\'s management '
                   'module (a Synergy frame\'s Frame Link Module bay, a c7000\'s Onboard '
                   'Administrator), for a key the device makes - at every issue acme asks for a '
                   'new key and CSR over the REST API and imports the signed certificate. The '
                   'appliance makes RSA 2048 (3072 for CNSA) and reloads its web services.')
    doc = 'targets.md'
    # the device makes the key (docs/writing-a-module.md "The device makes the key")
    device_key = True
    device_key_types = ('rsa-2048', 'rsa-3072')

    fields = list(HpeOneViewTarget.fields) + [
        field('csr_country', 'Country (C)', 'text', required=True, placeholder='CZ',
              help='two letters - every CSR has it; the certificate\'s own subject (its '
                   'profile) wins'),
        field('csr_state', 'State or region (ST)', 'text', required=True, placeholder='Praha'),
        field('csr_city', 'City (L)', 'text', required=True, placeholder='Praha'),
        field('csr_org', 'Organization (O)', 'text', required=True, placeholder='Example s.r.o.'),
        field('csr_ou', 'Unit (OU)', 'text', placeholder='IT'),
        field('csr_email', 'E-mail in the CSR', 'text', advanced=True,
              help='the appliance\'s CSR only'),
    ]
    deploy_fields = [
        field('part', 'Certificate of', 'select', default='appliance',
              options=[['appliance', 'the appliance (Composer / OneView)'],
                       ['enclosure', 'an enclosure\'s management module (frame / OA bay)']],
              help='each certificate deployed here is for one of them'),
        field('enclosure', 'Enclosure', 'text', placeholder='Frame1',
              show_if={'part': ['enclosure']},
              help='its name in OneView, or its URI (/rest/enclosures/…)'),
        field('bay', 'Bay', 'number', default=1, show_if={'part': ['enclosure']},
              help='the bay of the Frame Link Module / Onboard Administrator (1 or 2)'),
        field('import_chain', 'Put the intermediates into the trust store', 'bool',
              default=True, show_if={'part': ['appliance']},
              help='POST /rest/certificates/ca - HPE wants the issuing CA there before the '
                   'appliance certificate'),
        field('task_wait', 'Wait for the tasks (s)', 'number', default=300, advanced=True),
    ] + verify_fields()

    # -- what is asked of which part ----------------------------------------------------
    @staticmethod
    def part(options):
        return 'enclosure' if text((options or {}).get('part')).strip() == 'enclosure' \
            else 'appliance'

    def subject(self, req, longest=True, enclosure=False):
        subj = dict(getattr(req, 'subject', None) or {})
        names = list(getattr(req, 'names', None) or [])
        cn = text(subj.get('CN') or (names[0] if names else '')).strip()
        if enclosure and names:
            # an enclosure's CSR has no SAN: its one name is the common name - the
            # certificate's name, not another CN of the profile, which acme's check of the CSR
            # would refuse only after the bay made its key (1.0.96)
            cn = text(names[0]).strip()
        if not cn:
            raise PluginError('the certificate has no name for the CSR', retry=False)
        out = {}
        for key, sk, ck, most in SUBJECT:
            v = text(subj.get(sk) or self.c(ck) or '').strip()
            if v:
                if len(v) > most:
                    raise PluginError('%s "%s" is longer than the %d characters the appliance '
                                      'takes' % (key, v, most), retry=False)
                out[key] = v
        miss = [k for k in ('country', 'state', 'locality', 'organization') if not out.get(k)]
        if miss:
            raise PluginError('OneView asks for %s in every CSR - fill them in on the target'
                              % ', '.join(miss), retry=False)
        if len(out['country']) != 2:
            raise PluginError('the country must be two letters (it is "%s")' % out['country'],
                              retry=False)
        out['commonName'] = cn
        return out

    def enclosure_uri(self, options):
        given = text((options or {}).get('enclosure')).strip()
        if not given:
            raise PluginError('the deployment names no enclosure - give its name in OneView '
                              '(or its URI)', retry=False)
        if given.startswith('/rest/enclosures/'):
            return given.rstrip('/')
        st, hd, d = self.req('GET', '/rest/enclosures?filter=%s' % urllib.parse.quote(
            "name='%s'" % given.replace("'", ''), safe=''), what='looking for the enclosure %s'
            % given)
        mem = [m for m in ((d or {}).get('members') or []) if isinstance(m, dict)] \
            if isinstance(d, dict) else []
        mem = [m for m in mem if text(m.get('name')) == given] or mem
        if not mem or not text(mem[0].get('uri')):
            raise PluginError('OneView has no enclosure named %s' % given, retry=False)
        e = mem[0]
        self.ctx.debug('enclosure %s: %s %s' % (given, e.get('enclosureType') or
                                                e.get('enclosureModel') or '?', e.get('uri')))
        return text(e['uri']).rstrip('/')

    def bay(self, options):
        # an enclosure has two management bays: a Synergy frame's Frame Link Modules, a
        # c7000's Onboard Administrators (1.0.96: 1 to 8 was taken, "a number from 1" said)
        b = as_int((options or {}).get('bay'), 1) or 1
        if b not in (1, 2):
            raise PluginError('the bay is 1 or 2 - the Frame Link Module / Onboard '
                              'Administrator bay (it is %s)' % b, retry=False)
        return b

    def seconds(self, options):
        return as_int(self.opt(options or {}, 'task_wait', 300), 300)

    # -- the CSR ------------------------------------------------------------------------
    def device_csr(self, req):
        options = getattr(req, 'options', None) or {}
        names = list(req.names)
        kt = text(req.key_type)
        if kt not in self.device_key_types:
            raise PluginError('the appliance makes RSA 2048 (or RSA 3072 for CNSA) keys - %s '
                              'cannot be asked of it' % kt, retry=False)
        enclosure = self.part(options) == 'enclosure'
        if enclosure and kt != 'rsa-2048':
            # its CSR body has no key size: the bay makes RSA 2048 - refused before it drops
            # its pending key (1.0.96)
            raise PluginError('an enclosure\'s management module makes RSA 2048 keys only - '
                              'choose rsa-2048 for the certificate (it asks for %s)' % kt,
                              retry=False)
        subj = self.subject(req, enclosure=enclosure)
        if enclosure:
            if len(names) > 1:
                raise PluginError('an enclosure\'s CSR has one name, its common name - give the '
                                  'certificate one name (it has %s)' % ', '.join(names),
                                  retry=False)
            if _is_ip(names[0]):
                raise PluginError('the common name of an enclosure\'s CSR is a host name - '
                                  'give the certificate the module\'s DNS name', retry=False)
            self.bay(options)                   # said before signing in
            return self._enclosure_csr(req, subj, options)
        return self._appliance_csr(req, subj, options)

    def _read_csr(self, uri, what):
        st, hd, d = self.req('GET', uri, what=what)
        return find_csr(d)

    def _appliance_csr(self, req, subj, options):
        body = {'type': 'CertificateSigningRequestV2'}
        body.update(subj)
        body['alternativeName'] = ','.join(req.names)
        email = text((req.subject or {}).get('emailAddress') or self.c('csr_email')).strip()
        if email:
            body['email'] = email
        body['cnsaCertRequested'] = req.key_type == 'rsa-3072'
        self.login()
        try:
            st, hd, d = self.req('POST', APPLIANCE_CSR, body, timeout=180,
                                 what='asking the appliance for a new key and CSR')
            csr = find_csr(d)
            if not csr:
                self.wait_task(self.task_of(hd, d), 'making the CSR', self.seconds(options))
                csr = self._read_csr(APPLIANCE_CSR, 'reading the CSR')
            if not csr:
                raise PluginError('the appliance made no CSR to read',
                                  detail=text(d)[:4000])
            self.ctx.step('the appliance made a new %s key and a CSR for %s' % (
                req.key_type, ', '.join(req.names)), 'ok')
            return csr
        finally:
            self.logout()

    def _enclosure_csr(self, req, subj, options):
        body = {'type': 'CertificateDtoV2'}
        body.update(subj)
        bay = self.bay(options)
        self.login()
        try:
            enc = self.enclosure_uri(options)
            uri = '%s/https/certificaterequest?bayNumber=%d' % (enc, bay)
            st, hd, d = self.req('POST', uri, body, timeout=180,
                                 what='asking bay %d of the enclosure for a new key and CSR' % bay)
            csr = find_csr(d)
            if not csr:
                self.wait_task(self.task_of(hd, d), 'making the CSR of bay %d' % bay,
                               self.seconds(options))
                csr = self._read_csr(uri, 'reading the CSR of bay %d' % bay)
            if not csr:
                raise PluginError('bay %d of the enclosure made no CSR to read' % bay,
                                  detail=text(d)[:4000])
            self.ctx.step('bay %d of %s made a new key and a CSR for %s' % (
                bay, enc, req.names[0]), 'ok')
            return csr
        finally:
            self.logout()

    # -- the certificate put back ---------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        if getattr(bundle, 'key_pem', None):
            raise PluginError('this target takes only a certificate for a key the appliance or '
                              'the enclosure made itself - let the device make the key (the '
                              'certificate → Key: "Key made by the device"); for a key of '
                              'acme\'s use the target HPE OneView / Synergy Composer',
                              retry=False)
        enclosure = self.part(options) == 'enclosure'
        if not enclosure and not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the appliance')
        seconds = self.seconds(options)
        leaf = pem_blocks(bundle.cert_pem)[0].strip() + '\n'
        did = []
        self.login()
        try:
            if enclosure:
                bay = self.bay(options)
                enc = self.enclosure_uri(options)
                uri = '%s/https/certificaterequest?bayNumber=%d' % (enc, bay)
                st, hd, d = self.req('PUT', uri, {'type': 'CertificateDataV2',
                                                  'base64Data': leaf}, timeout=180,
                                     what='importing the certificate of bay %d' % bay)
                self.wait_task(self.task_of(hd, d), 'the import into bay %d' % bay, seconds)
                self.ctx.step('bay %d of %s took the certificate' % (bay, enc), 'ok')
                did.append('imported the certificate of bay %d of %s' % (bay, enc))
            else:
                if as_bool(self.opt(options, 'import_chain', True), True):
                    for pem in chain_list(bundle):
                        try:
                            if self.put_ca(pem, seconds):
                                did.append('CA %s' % chain_id(pem))
                        except PluginError as e:
                            if getattr(e, 'retry', True) is False and '(403)' in str(e):
                                raise
                            self.ctx.step('the intermediate CA is not in the trust store: %s'
                                          % e, 'warn')
                st, hd, d = self.req('PUT', APPLIANCE_CSR, {'type': 'CertificateDataV2',
                                                            'base64Data': leaf},
                                     timeout=180, what='importing the appliance certificate')
                self.ctx.step('the appliance took the certificate for its own key - it reloads '
                              'its web services', 'ok')
                done = self.wait_task(self.task_of(hd, d), 'the certificate import', seconds,
                                      relogin=True)
                if done:
                    self.ctx.step('the import task completed (the SSO certificate goes to the '
                                  'managed iLOs and frames too)', 'ok')
                did.insert(0, 'imported the appliance certificate for its own key')
        finally:
            self.logout()
        self.remember(bundle, options)
        return ', '.join(did)

    def test(self):
        self.login()
        try:
            st, hd, d = self.req('GET', '/rest/certificates/https',
                                 what='reading the appliance certificate')
            d = d if isinstance(d, dict) else {}
            st, hd, e = self.req('GET', '/rest/enclosures?start=0&count=16',
                                 what='listing the enclosures')
            encs = [text(m.get('name')) for m in ((e or {}).get('members') or [])
                    if isinstance(m, dict)] if isinstance(e, dict) else []
            return 'signed in to %s (API %d): appliance certificate %s, until %s; enclosures: ' \
                   '%s' % (self.c('host'), self.api_version(),
                           d.get('commonName') or d.get('subject') or '?',
                           d.get('expiresOn') or d.get('validUntil') or '?',
                           ', '.join(encs) or 'none listed')
        finally:
            self.logout()

    def served_places(self, options):
        if self.part(options) == 'enclosure':
            return []           # the module's own address is not OneView's: "verify" says it
        return HpeOneViewTarget.served_places(self, options)

    def verify(self, bundle, options):
        if self.part(options) == 'enclosure' and not (options or {}).get('verify'):
            return None
        return HpeOneViewTarget.verify(self, bundle, options)
