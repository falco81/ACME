# -*- coding: utf-8 -*-
"""
VMware vSphere Supervisor (vSphere with Tanzu / VKS) - the certificate of its Kubernetes API
endpoint (the virtual IP's nginx, what "kubectl vsphere login" and the VCF Consumption CLI see)
or of its default NSX ingress, with acme's key, through vCenter's vSphere Automation API:

    POST  /api/session (basic) -> the session ; DELETE /api/session
    vCenter 9.1 and later:
    GET   /api/vcenter/namespace-management/supervisors/<supervisor>/certificates
    PATCH /api/vcenter/namespace-management/supervisors/<supervisor>/certificates
          {"endpoint": "KUBERNETES_API_SERVER" | "DEFAULT_NSX_INGRESS",
           "tls_endpoint_certificate": leaf + intermediates + root, "tls_endpoint_private_key"}
    vCenter 9.0 (deprecated in 9.1):
    GET   /api/vcenter/namespace-management/clusters/<cluster>
    PATCH /api/vcenter/namespace-management/clusters/<cluster>
          {"tls_endpoint_certificate", "tls_endpoint_private_key"}       (the key: API 9.0+)

Before 9.0 the API takes only a certificate for a CSR the Supervisor made: no key made
elsewhere - refused. Hence, besides the plain one:

  ''      any version - reads vCenter's version (VI JSON API "about", no sign-in) and uses the
          calls of it; not known: the 9.1 calls, the 9.0 ones when vCenter does not have them
  '9.0'   vCenter 9.0          PATCH .../clusters/<cluster>
  '9.1'   vCenter 9.1 - 9.1.x  PATCH .../supervisors/<supervisor>/certificates

Sources: navody/certifikaty/vmware/vsan-supervisor.md (2026-11) - VCF 9.0 / 9.1 "Replace the
VIP Certificate to Securely Connect to the Supervisor API Endpoint", vSphere Automation API
Supervisors Certificates (GET / PATCH, Namespaces.Manage; System.Read to read), Namespace
Management Clusters PATCH (tls_endpoint_certificate deprecated in 9.1), KB 89324.
Less certain (said in the guide): the endpoint names KUBERNETES_API_SERVER and
DEFAULT_NSX_INGRESS (taken from the CSR types: the EndpointType page was not read) - a choice
in the form; the Supervisor's id is typed (domain-c8 ...: vSphere Client, or GET
/api/vcenter/namespace-management/supervisors/summaries).
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, text, tls_fields, verify_fields, http_fields,
    join_hostport)
from acmelib.plugins.targets.vcenter import VCenterTarget
from acmelib.plugins.targets import _vmware as V

NM = '/api/vcenter/namespace-management'

RANGES = (('9.0', 'vCenter 9.0', (9, 0, 0), (9, 0, 999)),
          ('9.1', 'vCenter 9.1 and later 9.x', (9, 1, 0), None))


def version_for(ver):
    for mv, label, lo, hi in RANGES:
        if ver >= lo and (hi is None or ver <= hi):
            return mv, label
    return '', ''


def q(s):
    return urllib.parse.quote(text(s), safe='')


class SupervisorTarget(VCenterTarget):
    kind = 'vsphere_supervisor'
    module_version = ''
    version_label = 'any version (detects it)'
    title = 'VMware vSphere Supervisor (API endpoint)'
    vendor = 'VMware'
    discovery = False
    description = ('vCenter 9.0 - 9.1: replaces the certificate of a Supervisor\'s Kubernetes '
                   'API endpoint (or its default NSX ingress) with acme\'s key through '
                   'vCenter\'s API; the calls of the vCenter version it reads (9.1: '
                   'supervisors/<id>/certificates, 9.0: clusters/<id>).')
    doc = 'targets.md'
    fields = http_fields(443, 'vcenter.example.local') + [
        field('user', 'User', 'text', required=True, placeholder='svc-wcp-cert@vsphere.local',
              help='a vCenter user with Namespaces.Manage (Modify cluster-wide configuration)'),
        field('password', 'Password', 'secret', required=True),
        field('supervisor', 'Supervisor', 'text', required=True, placeholder='domain-c8',
              help='the Supervisor\'s id (vCenter 9.1) or its cluster\'s id (vCenter 9.0)'),
        field('endpoint_host', 'API endpoint', 'text', placeholder='supervisor.example.local',
              help='the Supervisor\'s FQDN or virtual IP: where acme checks the API '
                   'endpoint\'s certificate (443); the NSX ingress\'s is not checked there'),
    ] + tls_fields()
    deploy_fields = [
        field('endpoint', 'Which certificate', 'select', default='KUBERNETES_API_SERVER',
              options=[['KUBERNETES_API_SERVER', 'the Kubernetes API endpoint (virtual IP)'],
                       ['DEFAULT_NSX_INGRESS', 'the default NSX ingress (vCenter 9.1)']]),
        field('root_pem', 'Root CA certificate', 'pem',
              help='the root, last in the chain (an identity provider needs the whole chain); '
                   'empty: the chain as it is'),
    ] + verify_fields()

    api_gen = None              # '9.0' | '9.1' | None: by the version vCenter says
    vc_min = None
    vc_max = None
    vc_checked_to = (9, 1)

    def vc_version(self):
        if '_ver' not in self.__dict__:
            self._ver = V.parse_version(V.vi_about(self).get('version'))
        return self._ver

    def range_words(self):
        for mv, label, lo, hi in RANGES:
            if mv == self.module_version:
                return label
        return 'vCenter 9.0 and later'

    def generation(self):
        """'9.0' or '9.1' - the calls to make; refused before anything changes when this
        version of the module is not for the vCenter there."""
        ver = self.vc_version()
        if ver is not None and ver < (9, 0, 0):
            raise PluginError(
                'this vCenter runs %s - before 9.0 the Supervisor\'s API takes only a '
                'certificate for a CSR it made (no key made elsewhere): replace it in the '
                'vSphere Client (Supervisor > Configure > Certificates)'
                % V.version_words(ver), retry=False)
        if self.vc_min is not None:
            if ver is None:
                self.ctx.step('the vCenter version cannot be read - the calls of %s are used'
                              % self.range_words(), 'warn')
            elif ver < self.vc_min or (self.vc_max is not None and ver > self.vc_max):
                fit = version_for(ver)[1] or SupervisorTarget.version_label
                raise PluginError(
                    'this vCenter runs %s - the module version "%s" is for %s; choose the '
                    'version "%s" of the target' % (V.version_words(ver), self.version_label,
                                                    self.range_words(), fit), retry=False)
        if ver is not None and ver[:2] > self.vc_checked_to:
            self.ctx.step('vCenter %s is newer than the documents this module was checked '
                          'against (9.1)' % V.version_words(ver), 'warn')
        if self.api_gen:
            return self.api_gen
        if ver is None:
            return None
        return '9.0' if ver < (9, 1, 0) else '9.1'

    def paths(self, gen):
        sup = q(text(self.c('supervisor')).strip())
        if gen == '9.0':
            return '%s/clusters/%s' % (NM, sup), '%s/clusters/%s' % (NM, sup)
        return '%s/supervisors/%s/certificates' % (NM, sup), \
            '%s/supervisors/%s/certificates' % (NM, sup)

    def read(self, gen):
        """(the generation that answered, its answer) - an unknown version: 9.1's calls, 9.0's
        when vCenter does not know them."""
        for g in ([gen] if gen else ['9.1', '9.0']):
            get, _patch = self.paths(g)
            st, hd, d = self.req('GET', get, ok=(200, 404), what='reading the Supervisor')
            if st == 200:
                return g, d
        raise PluginError('vCenter has no Supervisor "%s"' % self.c('supervisor'), retry=False)

    def test(self):
        gen = self.generation()
        self.login()
        try:
            g, d = self.read(gen)
            ver = self.vc_version()
            return 'signed in to vCenter %s%s; the Supervisor %s answers (%s calls)' % (
                self.c('host'), ' %s' % V.version_words(ver) if ver else '',
                self.c('supervisor'), 'supervisors' if g == '9.1' else 'clusters')
        finally:
            self.logout()

    def chain(self, bundle, options):
        root = V.root_of(bundle, options.get('root_pem'))
        pems = [text(bundle.as_format('cert-pem'))] + V.intermediates(bundle) + \
            ([root] if root else [])
        return ''.join(p.strip() + '\n' for p in pems)

    def deploy(self, bundle, options):
        options = options or {}
        endpoint = text(options.get('endpoint') or 'KUBERNETES_API_SERVER')
        gen = self.generation()
        self.login()
        try:
            g, cur = self.read(gen)
            if g == '9.0' and endpoint != 'KUBERNETES_API_SERVER':
                raise PluginError('vCenter 9.0 takes only the API endpoint\'s certificate with '
                                  'a key (clusters/<id>); the NSX ingress needs vCenter 9.1',
                                  retry=False)
            if self.unchanged(bundle, options, present=lambda: V.has_cert(cur, bundle)):
                return self.same(bundle, 'on the Supervisor')
            # the decisions said (What happens): which calls, what is there now
            ver = self.vc_version()
            self.ctx.step('vCenter %s: the %s calls; the Supervisor %s holds %s' % (
                V.version_words(ver) if ver else '(its version not read)',
                'supervisors/<id>/certificates' if g == '9.1' else 'clusters/<id>',
                self.c('supervisor'), 'this certificate already - it is put there again'
                if V.has_cert(cur, bundle) else 'another certificate - it is replaced'))
            _get, patch = self.paths(g)
            body = {'tls_endpoint_certificate': self.chain(bundle, options),
                    'tls_endpoint_private_key': text(bundle.as_format('key-pem'))}
            if g == '9.1':
                body = dict({'endpoint': endpoint}, **body)
            self.req('PATCH', patch, body, what='replacing the certificate of the Supervisor',
                     timeout=300)
            self.ctx.step('the Supervisor %s took the certificate (%s)' % (
                self.c('supervisor'), endpoint if g == '9.1' else 'API endpoint'), 'ok')
        finally:
            self.logout()
        self.remember(bundle, options)
        return 'Supervisor %s: %s certificate replaced' % (self.c('supervisor'), endpoint)

    served_wait = (6, 10)

    @staticmethod
    def ingress(options):
        return text((options or {}).get('endpoint')) == 'DEFAULT_NSX_INGRESS'

    def served_places(self, options):
        # the API endpoint serves its own certificate, not the NSX ingress's (1.0.96: the
        # ingress deployment was tested there and failed) - no test made for the ingress
        h = text(self.c('endpoint_host')).strip()
        return [(h, 443)] if h and not self.ingress(options) else []

    def verify(self, bundle, options):
        options = dict(options or {})
        h = text(self.c('endpoint_host')).strip()
        if not options.get('verify') and h and not self.ingress(options):
            options['verify'] = join_hostport(h, 443)
        options.setdefault('verify_tries', 6)
        options.setdefault('verify_wait', 10)
        return HttpTarget.verify(self, bundle, options)


_SAME = (' Replaces the certificate of the Supervisor\'s API endpoint with acme\'s key through '
         'vCenter\'s API. Refused on a vCenter that says another version.')


class Supervisor90Target(SupervisorTarget):
    """vCenter 9.0: PATCH namespace-management/clusters/<cluster> with the key (API 9.0)."""
    module_version, version_label, vc_min, vc_max = RANGES[0]
    api_gen = '9.0'
    description = ('vCenter 9.0: PATCH namespace-management/clusters/<cluster> '
                   '(tls_endpoint_certificate and tls_endpoint_private_key).' + _SAME)


class Supervisor91Target(SupervisorTarget):
    """vCenter 9.1 and later: PATCH namespace-management/supervisors/<id>/certificates."""
    module_version, version_label, vc_min, vc_max = RANGES[1]
    api_gen = '9.1'
    description = ('vCenter 9.1 and later 9.x: PATCH namespace-management/supervisors/<id>/'
                   'certificates (the API endpoint or the default NSX ingress).' + _SAME)
