# -*- coding: utf-8 -*-
"""
Dell OpenManage Enterprise (OME 3.x, 4.x) - the HTTPS certificate of the appliance (its web
interface and REST API) for a key the appliance makes itself ("the device makes the key",
docs/certificates.md "Key made by the device"). Dell's user guide: "Generate the CSR only from
within the OpenManage Enterprise appliance" - no key can be imported, the certificate uploaded
must be the one signed for the appliance's last CSR. So acme asks OME for a new key and CSR at
every issue and renewal (device_csr) and, right after the issue, uploads the certificate signed
for it (deploy, with no key).

    POST   /api/SessionService/Sessions  {UserName, Password, SessionType: "API"}
                                                -> X-Auth-Token (header), {Id}
    GET    /api/ApplicationService/Info         -> {Version: "4.6.0", ...}
    POST   /api/ApplicationService/Actions/ApplicationService.GenerateCSR
           {DistinguishedName, DepartmentName, BusinessName, Locality, State, Country,
            Email, San: "name1,name2,..."}     -> {CertificateData: the CSR}
    POST   /api/ApplicationService/Actions/ApplicationService.UploadCertChain   (OME 3.10+)
           the certificate and its intermediates, PEM, application/octet-stream
    POST   /api/ApplicationService/Actions/ApplicationService.UploadCertificate (before 3.10)
           the certificate alone, PEM, application/octet-stream
    DELETE /api/SessionService/Sessions('<Id>')                               (signing out)

Once the certificate is uploaded OME restarts its web server and "cannot be accessed for a
few seconds" (Dell's Ansible module) - no restart of the appliance.

Versions of the module: the calls are the same in OME 3.x and 4.x but for the upload of a chain,
which came with OME 3.10 (Dell's Ansible module refuses upload_cert_chain on an older one):

  ''      any version - reads it (ApplicationService/Info): the chain on 3.10 and later, the
          certificate alone before
  '3.10'  OME 3.10 - 4.x: the chain (UploadCertChain)
  '3.0'   OME 3.0 - 3.9: the certificate alone (UploadCertificate)

A version refuses an appliance that says another version, before anything is asked of it.

Sources:
    https://www.dell.com/support/manuals/en-us/dell-openmanage-enterprise/ome_4_6_online_help_user_guide/
        (Security certificates; Generate and download a certificate signing request; Assign a
        web server certificate to an appliance - SHA-256/384/512, no wildcard, chain of 10 at
        most, EKU Server Authentication; Details of user privileges - Appliance Management)
    https://github.com/dell/dellemc-openmanage-ansible-modules  plugins/modules/
        ome_application_certificate.py (the URIs, the CSR payload, the octet-stream upload,
        upload_cert_chain from 3.10), plugins/module_utils/ome.py (the session: SessionType
        API, X-Auth-Token, Id, DELETE SessionService/Sessions('Id')), module_utils/utils.py
        (get_ome_version: GET ApplicationService/Info -> Version)

Less certain (not tried on an appliance; Dell's OME REST API reference could not be read): the
key OME makes (RSA 2048 assumed - Dell documents no key choice); up to four names in San
(Dell's Ansible documentation); whether OME before 3.10 takes San at all (acme's check of the
CSR says so in words when a name is missing).
"""
from __future__ import annotations

import re
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, http_fields, tls_fields, verify_fields,
    text, chain_list, pem_blocks, split_hostport, join_hostport, served_fingerprint, fp_of)

API = '/api'
GEN = API + '/ApplicationService/Actions/ApplicationService.GenerateCSR'
UP_CHAIN = API + '/ApplicationService/Actions/ApplicationService.UploadCertChain'
UP_CERT = API + '/ApplicationService/Actions/ApplicationService.UploadCertificate'
INFO = API + '/ApplicationService/Info'
SESSIONS = API + '/SessionService/Sessions'
MAX_SAN = 4                 # Dell: primary, secondary, tertiary and quaternary
CHAIN_FROM = (3, 10, 0)


def parse_version(s):
    """'4.6.0.123' -> (4, 6, 0); None when it is not a version."""
    got = re.findall(r'\d+', text(s))
    if not got:
        return None
    nums = [int(x) for x in got[:3]]
    return tuple(nums + [0] * (3 - len(nums)))


def words(ver):
    return '.'.join(str(x) for x in ver)


# the module versions and the OME versions each is for (first, last; None: open)
RANGES = (('3.0', 'OpenManage Enterprise 3.0 - 3.9', (3, 0, 0), (3, 9, 999)),
          ('3.10', 'OpenManage Enterprise 3.10 - 4.x', (3, 10, 0), None))


def version_for(ver):
    for mv, label, lo, hi in RANGES:
        if ver >= lo and (hi is None or ver <= hi):
            return mv, label
    return '', ''


class DellOmeTarget(HttpTarget):
    kind = 'dell_ome'
    discovery = False
    title = 'Dell OpenManage Enterprise'
    vendor = 'Dell'
    description = ('The HTTPS certificate of a Dell OpenManage Enterprise appliance (web '
                   'interface and REST API) for a key OME makes itself: at every issue and '
                   'renewal acme asks it for a new key and CSR over its REST API and uploads '
                   'the certificate signed for it. Any OME 3.x or 4.x: the version is read - '
                   'the chain is uploaded on 3.10 and later, the certificate alone before.')
    doc = 'targets.md'
    module_version = ''
    version_label = 'any version (detects it)'
    device_key = True
    device_key_types = ('rsa-2048',)
    ome_min = None          # the versioned ones: the OME versions they are for
    ome_max = None
    chain_upload = None     # None: by the version read; True / False: that way

    fields = http_fields(443, 'ome.example.local') + [
        field('user', 'User', 'text', required=True, placeholder='svc-cert',
              help='an OME account with the privilege "Appliance Management" (a custom role '
                   'of OME 4.x with only that) or the role Administrator'),
        field('password', 'Password', 'secret', required=True),
        field('csr_country', 'Country (C)', 'text', required=True, placeholder='CZ',
              help='two letters - OME asks for it in every CSR; the certificate\'s own '
                   'subject (its profile) wins'),
        field('csr_state', 'State or region (ST)', 'text', required=True, placeholder='Praha'),
        field('csr_city', 'City (L)', 'text', required=True, placeholder='Praha'),
        field('csr_org', 'Business name (O)', 'text', required=True,
              placeholder='Example s.r.o.'),
        field('csr_ou', 'Department name (OU)', 'text', required=True, placeholder='IT'),
        field('csr_email', 'E-mail in the CSR', 'text', required=True,
              placeholder='admin@example.com'),
    ] + tls_fields()
    deploy_fields = [
        field('send_chain', 'Upload the chain', 'bool', default=True,
              help='on: the certificate and its intermediates (OME 3.10 and later; the '
                   'certificate alone on an older one); off: the certificate alone'),
        field('root_pem', 'Root CA certificate', 'pem', advanced=True,
              help='added at the end of the chain uploaded - for a CA whose chain does not '
                   'carry its root (Dell advises the whole chain, root included)'),
    ] + verify_fields()

    # OME restarts its web server after the upload - a few seconds, a minute at most
    served_wait = (12, 10)

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []

    def served_now(self, bundle):
        try:
            host, port = split_hostport(join_hostport(self.c('host'), self.c('port') or 443))
            return served_fingerprint(host, port, None) == fp_of(bundle)
        except (OSError, ValueError):
            return False

    # -- the session ---------------------------------------------------------------------
    token = None
    session_id = None

    def auth_headers(self):
        return {'X-Auth-Token': self.token} if self.token else {}

    def login(self):
        st, hd, d = self.req('POST', SESSIONS, {
            'UserName': self.c('user'), 'Password': self.c('password'), 'SessionType': 'API'},
            auth=False, what='signing in to OME')
        self.token = hd.get('x-auth-token')
        if not self.token:
            raise PluginError('OME gave no session (X-Auth-Token) on signing in')
        self.session_id = text((d or {}).get('Id')) if isinstance(d, dict) else ''

    def logout(self):
        if not self.token:
            return
        try:
            if self.session_id:
                self.req('DELETE', "%s('%s')" % (SESSIONS, urllib.parse.quote(
                    self.session_id, safe='-')), what='signing out')
        except PluginError as e:
            self.ctx.debug('signing out of OME: %s' % e)
        finally:
            self.token = None
            self.session_id = None

    # -- the version -----------------------------------------------------------------------
    def ome_version(self):
        """(major, minor, patch) OME says, or None when it cannot be read."""
        try:
            st, hd, d = self.req('GET', INFO, what='reading the OME version')
        except PluginError as e:
            if '(401)' in str(e) or '(403)' in str(e):
                raise
            return None
        return parse_version(d.get('Version')) if isinstance(d, dict) else None

    def range_words(self):
        if self.ome_min is None:
            return 'any OME'
        return self.version_label

    def check_version(self):
        """-> the version read (or None); a version of the module on an OME it is not for is
        refused before anything is asked of it."""
        ver = self.ome_version()
        if self.ome_min is None:
            return ver
        if ver is None:
            self.ctx.step('the OME version cannot be read - the calls of %s are used'
                          % self.range_words(), 'warn')
            return ver
        if ver < self.ome_min or (self.ome_max is not None and ver > self.ome_max):
            fit = version_for(ver)[1] or DellOmeTarget.version_label
            raise PluginError('this appliance runs OpenManage Enterprise %s - the module '
                              'version "%s" is for %s; choose the version "%s" of the target'
                              % (words(ver), self.version_label, self.range_words(), fit),
                              retry=False)
        return ver

    def uploads_chain(self, ver):
        if self.chain_upload is not None:
            return self.chain_upload
        return ver is None or ver >= CHAIN_FROM

    # -- the CSR OME makes ---------------------------------------------------------------
    def _payload(self, req):
        names = [text(n).strip() for n in (req.names or []) if text(n).strip()]
        subj = dict(req.subject or {})
        if not names:
            raise PluginError('the certificate has no name for the CSR', retry=False)
        wild = [n for n in names if n.startswith('*')]
        if wild:
            raise PluginError('OpenManage Enterprise takes no wildcard certificate (%s) - give '
                              'the appliance\'s own names' % ', '.join(wild), retry=False)
        if len(names) > MAX_SAN:
            raise PluginError('OpenManage Enterprise puts at most %d names in its CSR - the '
                              'certificate has %d (%s)' % (MAX_SAN, len(names),
                                                           ', '.join(names)), retry=False)
        if req.key_type not in self.device_key_types:
            raise PluginError('OpenManage Enterprise makes %s keys only - choose that key type '
                              'for the certificate' % ', '.join(self.device_key_types),
                              retry=False)
        body = {'DistinguishedName': text(subj.get('CN') or names[0]).strip()}
        miss = []
        for key, sk, ck, label in (('DepartmentName', 'OU', 'csr_ou', 'Department name'),
                                   ('BusinessName', 'O', 'csr_org', 'Business name'),
                                   ('Locality', 'L', 'csr_city', 'City'),
                                   ('State', 'ST', 'csr_state', 'State'),
                                   ('Country', 'C', 'csr_country', 'Country'),
                                   ('Email', 'emailAddress', 'csr_email', 'E-mail')):
            v = text(subj.get(sk) or self.c(ck) or '').strip()
            if not v:
                miss.append(label)
            body[key] = v
        if miss:
            raise PluginError('OpenManage Enterprise asks for %s in every CSR - fill them in '
                              'on the target' % ', '.join(miss), retry=False)
        body['San'] = ','.join(names)
        return body, names

    def device_csr(self, req):
        body, names = self._payload(req)
        self.login()
        try:
            self.check_version()
            st, hd, d = self.req('POST', GEN, body, what='asking OME for a new key and CSR',
                                 timeout=180)
        finally:
            self.logout()
        csr = text(d.get('CertificateData')) if isinstance(d, dict) else text(d)
        if 'CERTIFICATE REQUEST-----' not in csr:
            raise PluginError('OME answered GenerateCSR without a CSR', detail=text(d)[:4000])
        self.ctx.step('OME made a new key and a CSR for %s' % ', '.join(names), 'ok')
        return csr

    # -- the certificate uploaded ----------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        if getattr(bundle, 'key_pem', None):
            raise PluginError('OpenManage Enterprise takes only a certificate for a key it made '
                              'itself - let the device make the key (the certificate → Key: '
                              '"Key made by the device")', retry=False)
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by OME')
        self.login()
        try:
            ver = self.check_version()
            chain = as_bool(self.opt(options, 'send_chain', True), True) and \
                self.uploads_chain(ver)
            pem = text(bundle.cert_pem).strip() + '\n'
            if chain:
                blocks = chain_list(bundle)
                root = pem_blocks(text(options.get('root_pem')))
                if root and root[0].strip() not in [b.strip() for b in blocks]:
                    blocks.append(root[0])
                pem += ''.join(b.strip() + '\n' for b in blocks)
            path = UP_CHAIN if chain else UP_CERT
            self.req('POST', path, pem.encode(), headers={
                'Content-Type': 'application/octet-stream',
                'Accept': 'application/octet-stream'},
                what='uploading the certificate%s' % (' chain' if chain else ''), timeout=120)
        finally:
            self.logout()
        how = 'the certificate and its chain' if chain else 'the certificate'
        self.ctx.step('OME took %s - its web server restarts, a few seconds' % how, 'ok')
        self.remember(bundle, options)
        return 'uploaded %s for OME\'s own key%s' % (
            how, ' (OME %s)' % words(ver) if ver else '')

    def test(self):
        self.login()
        try:
            ver = self.ome_version()
        finally:
            self.logout()
        if ver is None:
            return 'signed in to %s; the OME version cannot be read' % self.c('host')
        fit = version_for(ver)[1] or 'no version of this module'
        out = 'signed in to %s: OpenManage Enterprise %s (%s); the %s is uploaded' % (
            self.c('host'), words(ver), fit,
            'chain' if self.uploads_chain(ver) else 'certificate alone')
        if self.ome_min is not None and (ver < self.ome_min or (
                self.ome_max is not None and ver > self.ome_max)):
            out += ' - NOT the version this module version is for (%s)' % self.range_words()
        return out


class DellOme30Target(DellOmeTarget):
    description = ('OpenManage Enterprise 3.0 - 3.9: the key and CSR made by OME, the '
                   'certificate uploaded alone (UploadCertificate - no chain upload before '
                   '3.10). Refuses an appliance on another version.')
    module_version, version_label, ome_min, ome_max = RANGES[0]
    chain_upload = False


class DellOme310Target(DellOmeTarget):
    description = ('OpenManage Enterprise 3.10 - 4.x: the key and CSR made by OME, the '
                   'certificate and its intermediates uploaded (UploadCertChain). Refuses an '
                   'appliance on another version.')
    module_version, version_label, ome_min, ome_max = RANGES[1]
    chain_upload = None     # the option says: the chain, or the certificate alone
