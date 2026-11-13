# -*- coding: utf-8 -*-
"""
VMware Cloud Foundation - the TLS certificate of one VCF component (vCenter, NSX Manager,
SDDC Manager, the Aria / VCF management components...) replaced through VCF's own
certificate management, for a key VCF makes itself ("the device makes the key",
docs/certificates.md "Key made by the device"). Neither SDDC Manager (VCF 5.2) nor VCF
Operations fleet management (VCF 9.x) takes a private key made elsewhere - they install only
a certificate signed for a CSR they made ("leaf certificate doesn't match any CSR stored in the
locker"). So acme has VCF make a new key and CSR for the component at every issue and renewal
(device_csr), and right after the issue has it install the certificate signed for it (deploy,
with no key). VCF then applies it on the component and restarts what needs restarting.
(The kind sddc_manager only adds CA certificates to SDDC Manager's trust store.)

The plain version - SDDC Manager API v1 (VCF 5.2; still there in VCF 9.0 - 9.1.1):

    POST /v1/tokens {username, password}                              -> {accessToken} (Bearer)
    GET  /v1/sddc-managers                                            the version (Try)
    GET  /v1/domains                                                  the domain by name or id
    PUT  /v1/domains/{id}/csrs {csrGenerationSpec: {country, state, locality, organization,
             organizationUnit, email?, keySize "2048|3072|4096", keyAlgorithm "RSA"},
             resources: [{fqdn, type, sans: [every name]}]}           -> 202 Task
    GET  /v1/tasks/{id}                                               until SUCCESSFUL
    GET  /v1/domains/{id}/csrs                                        -> elements[] the CSR of
                                                                         the resource (PEM)
    PUT  /v1/domains/{id}/resource-certificates/validations
             [{resourceFqdn, resourceCertificate, caCertificate (root),
               certificateChain (intermediates + root)}]              -> {validationId}
    GET  /v1/domains/{id}/resource-certificates/validations/{validationId}   until COMPLETED
    PUT  /v1/domains/{id}/resource-certificates  (the same list)      -> 202 Task, until SUCCESSFUL

The version 9.1 - VCF Operations fleet management API (VCF 9.1 - 9.1.1):

    POST /suite-api/api/auth/token/acquire {username, password, authSource?}  -> {token}
         (then "Authorization: OpsToken <token>")
    GET  /suite-api/api/versions/current                              {major, minor} - 9.1 or later
    POST /suite-api/api/fleet-management/certificate-management/certificates/query
             ?page=0&pageSize=100 {applianceFqdn, category: "TLS_CERT"}
                                                                      -> vcfCertificateModels[]
    POST .../certificate-management/csrs {certificateId, generateCsrSpec: {commonName,
             organization, orgUnit, locality, state, country, email?, keyAlgorithm "RSA",
             keySize "KEY_2048|KEY_3072|KEY_4096", subjectAltNames: {dns: [], ip: []}}}
                                                                      -> WorkflowRequest
    GET  /suite-api/api/workflows/requests/{requestId}                until COMPLETED
    GET  .../certificate-management/csrs?certificateId=<id>          -> certificateSignatureInfo[].csr
    PUT  .../certificate-management/certificates/{certificateId}
             {caType: "EXTERNAL_CA", certificateChain: leaf + intermediates + root}
                                                                      -> WorkflowRequest, until done
    POST /suite-api/api/auth/token/release                            (signing out)

Sources (2026-11): the vendor guide navody/certifikaty/vmware/vcf-sddc-manager.md and what it
cites - VMware Cloud Foundation API 5.2.2 "Certificates" (/v1/domains/{id}/csrs, /certificates,
/resource-certificates and their validations), POST /v1/tokens, GET /v1/tasks/{id}; SDDC
Manager API 9.1.1 "Certificates"; VCF Operations API "Fleet Certificate Management" (9.1.1),
"Auth - Acquire Token", "Workflow Request"; techdocs "Generate Certificate Signing Requests in
VCF", "Replace a Certificate with an External CA-Signed Certificate" (9.1) and "Install
Third-Party CA-Signed Certificates Using Server Certificate and CA Files" (5.2): RSA 2048 /
3072 / 4096 only, the FQDN in the SAN (9.1 checks strictly), the chain leaf → intermediate →
root, an expired certificate cannot be replaced.

UNVERIFIED (no VCF to try it on; from the API references through the guide): the answer
holding the CSR is looked for anywhere in /v1/domains/{id}/csrs (csrEncodedContent is
expected) next to its resource's FQDN; the validation's words (executionStatus COMPLETED,
resultStatus SUCCEEDED); the "OpsToken" prefix of VCF Operations; keySize "KEY_3072" /
"KEY_4096" (the reference shows KEY_2048); certificateId being the certificateResourceKey of the
query; the workflow states (COMPLETED / FAILED). The roles: an SDDC Manager ADMIN (the
role matrix is not published, VIEWER is read-only), a VCF Operations Administrator (the
privilege of fleet certificate management is not named).
"""
from __future__ import annotations

import ipaddress
import json
import time

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_int, http_fields, tls_fields, text, chain_list)
from acmelib.plugins.targets._x509 import is_root
from acmelib.plugins.targets import _vmware as V
from acmelib.plugins.targets.lenovo_xcc import find_csr

TYPES = [['VCENTER', 'vCenter'], ['NSXT_MANAGER', 'NSX Manager (NSX-T)'],
         ['NSX_MANAGER', 'NSX Manager'], ['SDDC_MANAGER', 'SDDC Manager'],
         ['VRSLCM', 'Aria Suite Lifecycle (VRSLCM)'], ['VROPS', 'Aria Operations (VROPS)'],
         ['VRLI', 'Aria Operations for Logs (VRLI)'], ['VRA', 'Aria Automation (VRA)'],
         ['NSX_ALB', 'NSX Advanced Load Balancer'], ['VXRAIL_MANAGER', 'VxRail Manager'],
         ['ESXI', 'ESX host']]
FLEET = '/suite-api/api/fleet-management/certificate-management'
DONE = ('SUCCESSFUL', 'SUCCEEDED', 'COMPLETED', 'COMPLETED_WITH_SUCCESS')
FAILED = ('FAILED', 'CANCELLED', 'COMPLETED_WITH_FAILURE', 'ERROR', 'ABORTED')


def _is_ip(v):
    try:
        ipaddress.ip_address(text(v).strip('[]'))
        return True
    except ValueError:
        return False


def _status(d, *keys):
    if not isinstance(d, dict):
        return ''
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v.upper()
    return ''


class VcfComponentTarget(HttpTarget):
    kind = 'vcf_component'
    discovery = False
    title = 'VMware Cloud Foundation component (SDDC Manager / VCF Operations CSR)'
    vendor = 'VMware'
    description = ('The certificate of one VCF component (vCenter, NSX Manager, SDDC Manager, '
                   'Aria / VCF management) through VCF\'s certificate management, for a key VCF '
                   'makes itself: at every issue and renewal acme has SDDC Manager make a new '
                   'key and CSR for the component and installs the certificate signed for it. '
                   'VCF 5.2 - 9.1.1 (SDDC Manager API); the version 9.1 uses VCF Operations.')
    doc = 'targets.md'
    module_version = ''
    version_label = 'VCF 5.2 - 9.1.1 (SDDC Manager API)'
    device_key = True
    device_key_types = ('rsa-2048', 'rsa-3072', 'rsa-4096')
    api = 'sddc'

    fields = http_fields(443, 'sddc-manager.example.local') + [
        field('user', 'User', 'text', required=True, placeholder='svc-vcf-certs@corp.local',
              help='SDDC Manager: an ADMIN (or OPERATOR); VCF Operations (version 9.1): an '
                   'Administrator'),
        field('password', 'Password', 'secret', required=True),
        field('auth_source', 'Authentication source', 'text', advanced=True,
              help='VCF Operations only (version 9.1): the source the user is from, e.g. the '
                   'name of its VCF Identity Broker or LDAP source; empty: a local user'),
        field('resource_fqdn', 'Component FQDN', 'text', placeholder='vc01.example.local',
              help='the FQDN VCF knows the component by; empty: the first name of the '
                   'certificate'),
        field('resource_type', 'Component type', 'select', default='VCENTER', options=TYPES,
              help='SDDC Manager\'s resource type'),
        field('domain', 'Workload domain', 'text', placeholder='sddcm-mgmt-domain',
              help='SDDC Manager: the domain (name or ID) the component is in; empty: the only '
                   'domain'),
        field('certificate_id', 'Certificate ID', 'text', advanced=True,
              help='VCF Operations only: the certificate\'s ID in Fleet management → '
                   'Certificates; empty: found by the component\'s FQDN'),
        field('csr_country', 'Country (C)', 'text', required=True, placeholder='CZ',
              help='two letters - VCF asks for it in every CSR; the certificate\'s own subject '
                   '(its profile) wins'),
        field('csr_state', 'State or region (ST)', 'text', required=True, placeholder='Praha',
              help='the full name, not an abbreviation'),
        field('csr_city', 'City (L)', 'text', required=True, placeholder='Praha'),
        field('csr_org', 'Organization (O)', 'text', required=True, placeholder='Example s.r.o.'),
        field('csr_ou', 'Unit (OU)', 'text', required=True, placeholder='IT'),
        field('csr_email', 'E-mail in the CSR', 'text', advanced=True),
        field('task_minutes', 'Wait for VCF\'s tasks (minutes)', 'number', default=60,
              advanced=True, help='replacing a vCenter\'s certificate restarts its services'),
    ] + tls_fields()
    deploy_fields = [
        field('root_pem', 'Root CA certificate', 'pem',
              help='the root the chain ends in (VCF wants the whole chain to the root - ISRG '
                   'Root X1 for Let\'s Encrypt); empty: the last certificate of the chain when '
                   'it is a root'),
    ]

    # VCF installs the certificate and restarts the component's services before its task
    # ends; a vCenter takes a few more minutes to serve again
    served_wait = (10, 30)
    token = None

    def served_places(self, options):
        fq = text(self.c('resource_fqdn')).strip()
        return [(fq, 443)] if fq else []

    # -- signing in ------------------------------------------------------------------------
    def auth_headers(self):
        if not self.token:
            return {}
        return {'Authorization': ('OpsToken %s' if self.api == 'ops' else 'Bearer %s')
                % self.token}

    def login(self):
        if self.api == 'ops':
            body = {'username': text(self.c('user')), 'password': text(self.c('password'))}
            if text(self.c('auth_source')).strip():
                body['authSource'] = text(self.c('auth_source')).strip()
            path, key = '/suite-api/api/auth/token/acquire', 'token'
        else:
            body = {'username': text(self.c('user')), 'password': text(self.c('password'))}
            path, key = '/v1/tokens', 'accessToken'
        try:
            st, hd, d = self.req('POST', path, body, auth=False, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail,
                              retry=not any(x in str(e) for x in ('(401)', '(403)', 'said 400')))
        tok = text(d.get(key) if isinstance(d, dict) else '')
        if not tok:
            raise PluginError('%s gave no token on signing in' % self.who(), retry=False)
        self.token = tok

    def logout(self):
        if self.api == 'ops' and self.token:
            try:
                self.req('POST', '/suite-api/api/auth/token/release', what='signing out')
            except PluginError as e:
                self.ctx.debug('signing out: %s' % e)
        self.token = None

    def who(self):
        return 'VCF Operations' if self.api == 'ops' else 'SDDC Manager'

    # -- waiting -----------------------------------------------------------------------------
    def _tries(self):
        return max(1, as_int(self.c('task_minutes', 60), 60) * 6)

    def wait_task(self, hd, d, what):
        """An SDDC Manager task (202: its id in the body or the Location) until it ends."""
        tid = text(d.get('id') if isinstance(d, dict) else '') or \
            text((hd or {}).get('location')).rstrip('/').rsplit('/', 1)[-1]
        if not tid:
            if _status(d, 'status') in DONE:
                return d
            raise PluginError('SDDC Manager started %s but said no task' % what,
                              detail=text(json.dumps(d) if isinstance(d, (dict, list)) else d))
        return V.wait_task(
            self, lambda: self.req('GET', '/v1/tasks/%s' % tid, what='asking about %s' % what)[2],
            lambda x: _status(x, 'status') in DONE,
            lambda x: _status(x, 'status') in FAILED,
            tries=self._tries(), every=10.0, what=what)

    def wait_request(self, d, what):
        """A VCF Operations workflow request until it ends."""
        rid = text(d.get('requestId') or d.get('id') if isinstance(d, dict) else '')
        if not rid:
            raise PluginError('VCF Operations started %s but said no request' % what,
                              detail=text(json.dumps(d) if isinstance(d, (dict, list)) else d))
        return V.wait_task(
            self, lambda: self.req('GET', '/suite-api/api/workflows/requests/%s' % rid,
                                   what='asking about %s' % what)[2],
            lambda x: _status(x, 'state', 'status') in DONE,
            lambda x: _status(x, 'state', 'status') in FAILED,
            tries=self._tries(), every=10.0, what=what)

    # -- what the CSR is for -----------------------------------------------------------------
    def fqdn(self, req=None):
        fq = text(self.c('resource_fqdn')).strip().rstrip('.')
        if not fq and req is not None and req.names:
            fq = text(req.names[0])
        if not fq:
            raise PluginError('give the component\'s FQDN on the target', retry=False)
        return fq

    def subject(self, req):
        subj = dict(getattr(req, 'subject', None) or {})
        out = {}
        for k, sk, ck in (('country', 'C', 'csr_country'), ('state', 'ST', 'csr_state'),
                          ('locality', 'L', 'csr_city'), ('organization', 'O', 'csr_org'),
                          ('organizationUnit', 'OU', 'csr_ou'),
                          ('email', 'emailAddress', 'csr_email')):
            v = text(subj.get(sk) or self.c(ck) or '').strip()
            if v:
                out[k] = v
        miss = [k for k in ('country', 'state', 'locality', 'organization', 'organizationUnit')
                if not out.get(k)]
        if miss:
            raise PluginError('VCF asks for %s in every CSR - fill them in on the target'
                              % ', '.join(miss), retry=False)
        return out

    def check_request(self, req):
        if req.key_type not in self.device_key_types:
            raise PluginError('VCF makes RSA keys only (2048, 3072, 4096) - %s cannot be asked '
                              'of it' % req.key_type, retry=False)
        bad = [n for n in req.names if '*' in n]
        if bad:
            raise PluginError('VCF does not take wildcard names for a component (%s)'
                              % ', '.join(bad), retry=False)
        fq = self.fqdn(req)
        if fq.lower() not in [text(n).lower() for n in req.names]:
            raise PluginError('the component\'s FQDN %s is not one of the certificate\'s names '
                              '(%s) - VCF wants it in the SAN' % (fq, ', '.join(req.names)),
                              retry=False)
        return fq

    def domain_id(self):
        st, hd, d = self.req('GET', '/v1/domains', what='reading the workload domains')
        doms = (d.get('elements') if isinstance(d, dict) else d) or []
        want = text(self.c('domain')).strip()
        if want:
            for x in doms:
                if want in (text(x.get('id')), text(x.get('name'))):
                    return text(x.get('id'))
            raise PluginError('SDDC Manager has no workload domain %s (it has %s)' % (
                want, ', '.join(text(x.get('name')) for x in doms) or 'none'), retry=False)
        if len(doms) == 1:
            return text(doms[0].get('id'))
        raise PluginError('give the workload domain on the target (SDDC Manager has %s)' % (
            ', '.join(text(x.get('name')) for x in doms) or 'none'), retry=False)

    # -- the CSR VCF makes -------------------------------------------------------------------
    def device_csr(self, req):
        fq = self.check_request(req)
        subj = self.subject(req)
        self.login()
        try:
            if self.api == 'ops':
                return self._ops_csr(req, fq, subj)
            return self._sddc_csr(req, fq, subj)
        finally:
            self.logout()

    def _sddc_csr(self, req, fq, subj):
        dom = self.domain_id()
        rtype = text(self.c('resource_type') or 'VCENTER')
        spec = dict(subj, keySize=req.key_type.split('-')[1], keyAlgorithm='RSA')
        st, hd, d = self.req('PUT', '/v1/domains/%s/csrs' % dom, {
            'csrGenerationSpec': spec,
            'resources': [{'fqdn': fq, 'type': rtype, 'sans': list(req.names)}]},
            what='asking SDDC Manager for a new key and CSR')
        self.wait_task(hd, d, 'making the CSR')
        st, hd, d = self.req('GET', '/v1/domains/%s/csrs' % dom, what='reading the CSR')
        csr = ''
        for x in (d.get('elements') if isinstance(d, dict) else d) or []:
            res = x.get('resource') if isinstance(x, dict) else None
            names = [text((res or {}).get('fqdn')), text(x.get('fqdn') if isinstance(x, dict)
                                                         else '')]
            if fq.lower() in [n.lower() for n in names]:
                csr = find_csr(x)
                break
        if not csr:
            raise PluginError('SDDC Manager made the CSR but lists none for %s' % fq,
                              detail=text(json.dumps(d) if isinstance(d, (dict, list)) else d)[:4000])
        self.ctx.step('SDDC Manager made a new %s key and a CSR for %s (%s)' % (
            req.key_type, fq, rtype), 'ok')
        return csr

    def _ops_version(self):
        try:
            st, hd, d = self.req('GET', '/suite-api/api/versions/current',
                                 what='reading the version')
        except PluginError as e:
            self.ctx.debug('the version cannot be read: %s' % e)
            return None
        if isinstance(d, dict) and d.get('major') is not None:
            return (as_int(d.get('major')), as_int(d.get('minor')))
        return V.parse_version(text(d.get('releaseName') if isinstance(d, dict) else ''))

    def _ops_check_version(self):
        v = self._ops_version()
        if v is not None and tuple(v[:2]) < (9, 1):
            raise PluginError('VCF Operations %s has no fleet certificate management API - '
                              'choose the plain version of this target (SDDC Manager API)'
                              % V.version_words(v), retry=False)
        return v

    def _cert_id(self, fq):
        given = text(self.c('certificate_id')).strip()
        if given:
            return given
        st, hd, d = self.req('POST', FLEET + '/certificates/query?page=0&pageSize=100',
                             {'applianceFqdn': fq, 'category': 'TLS_CERT'},
                             what='looking for the certificate of %s' % fq)
        rows = [x for x in ((d or {}).get('vcfCertificateModels') or []) if isinstance(x, dict)
                and fq.lower() in (text(x.get('applianceFqdn')).lower(),
                                   text(x.get('issuedTo')).lower())]
        ids = []
        for x in rows:
            cid = text(x.get('certificateResourceKey') or x.get('certificateId') or x.get('id'))
            if cid and cid not in ids:
                ids.append(cid)
        if not ids:
            raise PluginError('VCF Operations lists no TLS certificate of %s - give the '
                              'component\'s FQDN as VCF knows it, or the Certificate ID' % fq,
                              retry=False)
        if len(ids) > 1:
            raise PluginError('VCF Operations lists %d TLS certificates of %s (%s) - give the '
                              'Certificate ID on the target' % (len(ids), fq, ', '.join(ids)),
                              retry=False)
        return ids[0]

    def _ops_csr(self, req, fq, subj):
        self._ops_check_version()
        cid = self._cert_id(fq)
        spec = {'commonName': text((req.subject or {}).get('CN') or fq),
                'organization': subj['organization'], 'orgUnit': subj['organizationUnit'],
                'locality': subj['locality'], 'state': subj['state'],
                'country': subj['country'],
                'keyAlgorithm': 'RSA', 'keySize': 'KEY_%s' % req.key_type.split('-')[1],
                'subjectAltNames': {'dns': [n for n in req.names if not _is_ip(n)],
                                    'ip': [n for n in req.names if _is_ip(n)]}}
        if subj.get('email'):
            spec['email'] = subj['email']
        st, hd, d = self.req('POST', FLEET + '/csrs', {'certificateId': cid,
                                                       'generateCsrSpec': spec},
                             what='asking VCF Operations for a new key and CSR')
        self.wait_request(d, 'making the CSR')
        st, hd, d = self.req('GET', FLEET + '/csrs?certificateId=%s' % cid,
                             what='reading the CSR')
        infos = (d.get('certificateSignatureInfo') if isinstance(d, dict) else None) or d
        csr = find_csr(infos)
        if not csr:
            raise PluginError('VCF Operations made the CSR but gives none for %s' % cid,
                              detail=text(json.dumps(d) if isinstance(d, (dict, list)) else d)[:4000])
        self.ctx.step('VCF Operations made a new %s key and a CSR for %s (certificate %s)' % (
            req.key_type, fq, cid), 'ok')
        return csr

    # -- the certificate installed -------------------------------------------------------
    def chain(self, bundle, options):
        inter = [p.strip() + '\n' for p in chain_list(bundle) if not is_root(p)]
        root = V.root_of(bundle, (options or {}).get('root_pem'))
        if not root:
            raise PluginError('VCF wants the chain up to the root: paste the root CA '
                              'certificate in the deployment\'s options', retry=False)
        return inter, root.strip() + '\n'

    def deploy(self, bundle, options):
        options = options or {}
        if getattr(bundle, 'key_pem', None):
            raise PluginError('VCF takes only a certificate for a key it made itself - let its '
                              'device make the key (the certificate → Key: "Key made by the '
                              'device")', retry=False)
        fq = self.fqdn(None) if text(self.c('resource_fqdn')).strip() else \
            text((getattr(bundle, 'names', None) or [''])[0])
        leaf = text(bundle.cert_pem).strip() + '\n'
        inter, root = self.chain(bundle, options)
        self.login()
        try:
            if self.api == 'ops':
                did = self._ops_install(fq, leaf, inter, root)
            else:
                did = self._sddc_install(fq, leaf, inter, root)
        finally:
            self.logout()
        self.remember(bundle, options)
        return did

    def _sddc_install(self, fq, leaf, inter, root):
        dom = self.domain_id()
        body = [{'resourceFqdn': fq, 'resourceCertificate': leaf, 'caCertificate': root,
                 'certificateChain': ''.join(inter) + root}]
        base = '/v1/domains/%s/resource-certificates' % dom
        st, hd, d = self.req('PUT', base + '/validations', body,
                             what='having SDDC Manager validate the certificate')
        vid = text(d.get('validationId') if isinstance(d, dict) else '')
        if vid:
            def failed(x):
                return _status(x, 'resultStatus') in FAILED + ('FAILURE',)
            got = V.wait_task(
                self, lambda: self.req('GET', base + '/validations/%s' % vid,
                                       what='asking about the validation')[2],
                lambda x: _status(x, 'executionStatus') in DONE and not failed(x),
                failed, tries=60, every=5.0, what='the validation of the certificate')
            self.ctx.step('SDDC Manager validated the certificate for %s (%s)' % (
                fq, _status(got, 'resultStatus') or 'done'), 'ok')
        st, hd, d = self.req('PUT', base, body, what='having SDDC Manager install the '
                             'certificate')
        self.ctx.step('SDDC Manager installs the certificate on %s - it restarts the '
                      'component\'s services' % fq, 'info')
        started = time.time()
        self.wait_task(hd, d, 'installing the certificate on %s' % fq)
        self.ctx.step('SDDC Manager installed the certificate on %s (%d s)' % (
            fq, int(time.time() - started)), 'ok')
        return 'installed the certificate for VCF\'s own key on %s' % fq

    def _ops_install(self, fq, leaf, inter, root):
        self._ops_check_version()
        cid = self._cert_id(fq)
        st, hd, d = self.req('PUT', FLEET + '/certificates/%s' % cid, {
            'caType': 'EXTERNAL_CA', 'certificateChain': leaf + ''.join(inter) + root},
            what='having VCF Operations replace the certificate')
        self.wait_request(d, 'replacing the certificate of %s' % fq)
        self.ctx.step('VCF Operations replaced the certificate of %s (certificate %s)' % (
            fq, cid), 'ok')
        return 'replaced the certificate for VCF\'s own key on %s' % fq

    # -- Try ------------------------------------------------------------------------------
    def test(self):
        self.login()
        try:
            if self.api == 'ops':
                v = self._ops_check_version()
                fq = text(self.c('resource_fqdn')).strip()
                more = '; the certificate of %s: %s' % (fq, self._cert_id(fq)) if fq else ''
                return 'signed in to VCF Operations %s (%s)%s' % (
                    self.c('host'), V.version_words(v) if v else 'version not read', more)
            st, hd, d = self.req('GET', '/v1/sddc-managers', what='reading SDDC Manager')
            els = (d.get('elements') if isinstance(d, dict) else None) or [{}]
            ver = text(els[0].get('version'))
            dom = self.domain_id()
            return 'signed in to SDDC Manager %s (%s); workload domain %s' % (
                self.c('host'), ver or 'version not read', dom)
        finally:
            self.logout()


class VcfOperationsComponentTarget(VcfComponentTarget):
    module_version = '9.1'
    version_label = 'VCF 9.1 - 9.1.1 (VCF Operations fleet management API)'
    description = ('VCF 9.1 and 9.1.1: the certificate of one VCF component through VCF '
                   'Operations → Fleet management → Certificates, for a key VCF makes itself '
                   '- a new key and CSR at every issue and renewal, the certificate signed for '
                   'it put back with its chain ("Replace with imported certificate"). Refuses '
                   'VCF Operations older than 9.1.')
    api = 'ops'
