# -*- coding: utf-8 -*-
"""
NetApp ONTAP (REST API, HTTP basic sign-in): the certificate installed as a server
certificate of the cluster (its admin SVM) or of a data SVM, made the one its web services
(System Manager, REST API) use, older acme ones deleted afterwards.

    GET    /api/cluster?fields=version                       the ONTAP version
    POST   /api/security/certificates?return_timeout=120     {"name", "type": "server",
           "public_certificate", "private_key", "intermediate_certificates": [...],
           "svm": {"name"} (a data SVM only)}
    GET    /api/security/certificates?name=<n>&fields=uuid,name,svm
    PATCH  /api/cluster/web            {"certificate": {"uuid"}}    9.10.1 and later
    PATCH  /api/svm/svms/<uuid>/web    {"certificate": {"uuid"}}    9.10.1 and later
    PATCH  /api/cluster                {"certificate": {"uuid"}}    before 9.10 (deprecated
    PATCH  /api/svm/svms/<uuid>        {"certificate": {"uuid"}}     since, still working)
    DELETE /api/security/certificates/<uuid>                         the old ones, last
    GET    /api/cluster/jobs/<uuid>                                  a 202's job, waited for

Versions of the module (what differs for this job is where the certificate is bound):

  ''      any version - reads the version (GET /api/cluster) and binds where it takes it
  '9.6'   ONTAP 9.6 - 9.9: the "certificate" field of /api/cluster and /api/svm/svms/<uuid>
  '9.10'  ONTAP 9.10.1 - 9.19: /api/cluster/web and /api/svm/svms/<uuid>/web

Sources (the vendor guide navody/certifikaty/storage-hci/netapp-ontap.md, 2026-11, citing):
    https://docs.netapp.com/us-en/ontap-restapi/ontap/security_certificates_endpoint_overview.html
    https://docs.netapp.com/us-en/ontap-restapi/ontap/post-security-certificates.html
    https://docs.netapp.com/us-en/ontap-restapi/ontap/cluster_web_endpoint_overview.html
    https://docs.netapp.com/us-en/ontap-restapi/ontap/patch-cluster-web.html
    https://docs.netapp.com/us-en/ontap-restapi/ontap/patch-svm-svms-web.html
    https://docs.netapp.com/us-en/ontap-restapi/ontap/patch-cluster.html
    https://docs.netapp.com/us-en/ontap-restapi/ontap/patch-svm-svms-.html
    https://docs.netapp.com/us-en/ontap/authentication/install-server-certificate-cluster-svm-ssl-server-task.html

Less certain: GET /api/cluster's "version" (generation, major, minor) is from the general
REST reference, not the guide; the least REST role (rest-role on /api/cluster/web and
/api/svm/svms/*/web) is not proven by NetApp - the guide suggests the admin role when it is
refused; the name length of a certificate is not documented (acme keeps it to 63); ONTAP
restarts its web services after the PATCH, so the answer to it may be cut - acme then reads
/api/cluster/web to see what it holds.
"""
from __future__ import annotations

import base64
import time
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, text, http_fields, tls_fields, verify_fields, keep_field,
    object_name, name_prefix, prune, chain_list, as_int)

RANGES = (('9.6', 'ONTAP 9.6 - 9.9', (9, 6, 0), (9, 9, 999)),
          ('9.10', 'ONTAP 9.10.1 - 9.19', (9, 10, 0), None))


def ontap_words(ver):
    return '.'.join(str(x) for x in ver)


def version_for(ver):
    for mv, label, lo, hi in RANGES:
        if ver >= lo and (hi is None or ver <= hi):
            return mv, label
    return '', ''


def q(s):
    return urllib.parse.quote(text(s), safe='')


class NetAppOntapTarget(HttpTarget):
    kind = 'netapp_ontap'
    title = 'NetApp ONTAP (REST API)'
    vendor = 'NetApp'
    module_version = ''
    version_label = 'any version (detects it)'
    description = ('Installs the certificate as a server certificate of an ONTAP cluster or '
                   'SVM through the REST API, makes its web services (System Manager, REST '
                   'API) use it and deletes older ones acme put there. Any ONTAP 9.6 and '
                   'later: where it is bound is taken from the version the cluster says.')
    doc = 'targets.md'
    discovery = False       # nothing to find: the sign-in, and an SVM typed
    fields = http_fields(443, 'cluster1.example.local') + [
        field('user', 'User', 'text', required=True, default='svc_cert',
              help='a cluster account (admin SVM) with the http application'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('svm', 'SVM', 'text',
              help='empty: the cluster\'s own web services (the admin SVM); a data SVM\'s '
                   'name: its web services'),
        field('job_timeout', 'Wait for a job (s)', 'number', default=120, advanced=True),
        keep_field(1),
    ] + verify_fields()

    web_api = None              # True: /…/web (9.10.1+); False: the certificate field; None: by version
    ontap_min = None
    ontap_max = None
    checked_to = (9, 19)

    _sleep = staticmethod(time.sleep)

    def auth_headers(self):
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()}

    def http_error(self, status, parsed, raw, method, path, what=None):
        if isinstance(parsed, dict) and isinstance(parsed.get('error'), dict):
            e = parsed['error']
            parsed = {'message': '%s%s' % (e.get('message') or '', ' (code %s)' % e['code']
                                           if e.get('code') else '')}
        return HttpTarget.http_error(self, status, parsed, raw, method, path, what)

    # -- the version -------------------------------------------------------------------
    def ontap_version(self):
        if '_ver' not in self.__dict__:
            ver, full = None, ''
            try:
                st, hd, d = self.req('GET', '/api/cluster?fields=version,name',
                                     what='reading the ONTAP version')
                v = (d or {}).get('version') or {}
                full = text(v.get('full'))
                if v.get('generation') is not None:
                    ver = (as_int(v.get('generation')), as_int(v.get('major')),
                           as_int(v.get('minor')))
            except PluginError as e:
                if getattr(e, 'retry', True) is False and 'let acme in' in str(e):
                    raise
                self.ctx.debug('the ONTAP version cannot be read: %s' % e)
            self._ver, self._full = ver, full
        return self._ver

    def range_words(self):
        if self.ontap_min is None:
            return 'any ONTAP'
        return self.version_label

    def check_version(self):
        if self.ontap_min is None:
            return
        ver = self.ontap_version()
        if ver is None:
            self.ctx.step('the ONTAP version cannot be read - the calls of %s are used'
                          % self.version_label, 'warn')
            return
        if ver < self.ontap_min or (self.ontap_max is not None and ver > self.ontap_max):
            fit = version_for(ver)[1] or NetAppOntapTarget.version_label
            raise PluginError(
                'this cluster runs ONTAP %s - the module version "%s" is for %s; choose the '
                'version "%s" of the target' % (ontap_words(ver), self.version_label,
                                                self.range_words(), fit), retry=False)
        if ver[:2] > tuple(self.checked_to):
            self.ctx.step('ONTAP %s is newer than the documents this module version was '
                          'checked against (%s)' % (ontap_words(ver),
                                                    ontap_words(self.checked_to)), 'warn')

    def uses_web(self):
        if self.web_api is not None:
            return self.web_api
        ver = self.ontap_version()
        return True if ver is None else ver >= (9, 10, 0)

    def test(self):
        st, hd, d = self.req('GET', '/api/cluster?fields=version,name', what='signing in')
        v = (d or {}).get('version') or {}
        self._full = text(v.get('full'))
        if v.get('generation') is not None:
            self._ver = (as_int(v.get('generation')), as_int(v.get('major')),
                         as_int(v.get('minor')))
        self.check_version()
        return 'signed in to %s, %s' % ((d or {}).get('name') or self.c('host'),
                                       self._full or 'ONTAP ?')

    # -- the calls ---------------------------------------------------------------------
    def wait_job(self, d, what, options):
        """A 202's job waited for: success, or its message as an error."""
        job = (d or {}).get('job') if isinstance(d, dict) else None
        uuid = text((job or {}).get('uuid'))
        if not uuid:
            return
        end = time.time() + as_int(self.opt(options, 'job_timeout', 120), 120)
        while True:
            st, hd, j = self.req('GET', '/api/cluster/jobs/%s?fields=state,message' % q(uuid),
                                 what='asking for the job of %s' % what)
            state = text((j or {}).get('state')).lower()
            if state == 'success':
                return
            if state == 'failure':
                raise PluginError('%s: the job failed - %s' % (what, (j or {}).get('message')),
                                  detail=text(j)[:4000])
            if self.ctx.cancelled() or time.time() > end:
                raise PluginError('%s: the job %s has not finished' % (what, uuid))
            self._sleep(3)

    def svm_uuid(self, svm):
        st, hd, d = self.req('GET', '/api/svm/svms?name=%s&fields=uuid,name' % q(svm),
                             what='finding the SVM %s' % svm)
        recs = (d or {}).get('records') or []
        if not recs:
            raise PluginError('the cluster has no SVM named "%s"' % svm, retry=False)
        return text(recs[0].get('uuid'))

    def certs(self, svm, name=None):
        qs = 'type=server&fields=uuid,name,svm,serial_number,expiry_time'
        qs += '&name=%s' % q(name) if name else ''
        qs += '&svm.name=%s' % q(svm) if svm else '&scope=cluster'
        st, hd, d = self.req('GET', '/api/security/certificates?' + qs,
                             what='listing the certificates')
        return [r for r in (d or {}).get('records') or [] if isinstance(r, dict)]

    def bound(self, svm, svm_id):
        """The uuid of the certificate the web services use now ('' when not said)."""
        try:
            if self.uses_web():
                p = '/api/svm/svms/%s/web' % q(svm_id) if svm else '/api/cluster/web'
            else:
                p = '/api/svm/svms/%s' % q(svm_id) if svm else '/api/cluster'
            st, hd, d = self.req('GET', p + '?fields=certificate', what='reading the binding')
            return text(((d or {}).get('certificate') or {}).get('uuid'))
        except PluginError as e:
            self.ctx.debug('the binding cannot be read: %s' % e)
            return ''

    def bind(self, uuid, svm, svm_id, options):
        web = self.uses_web()
        if web:
            p = '/api/svm/svms/%s/web' % q(svm_id) if svm else '/api/cluster/web'
        else:
            p = '/api/svm/svms/%s' % q(svm_id) if svm else '/api/cluster'
        what = 'binding the certificate to %s' % (('SVM %s' % svm) if svm else 'the cluster')
        try:
            st, hd, d = self.req('PATCH', p, {'certificate': {'uuid': uuid}}, what=what)
            self.wait_job(d, what, options)
        except PluginError as e:
            if 'cannot be reached' not in str(e):
                raise
            # ONTAP restarts its web services: the answer may be cut off
            self.ctx.step('the connection dropped while ONTAP restarts its web services - '
                          'reading what is bound', 'warn')
            self._sleep(10)
            if self.bound(svm, svm_id) != uuid:
                raise
        self.ctx.step('%s web services use it (%s)' % (('SVM %s' % svm) if svm else 'the cluster',
                                                        p), 'ok')

    def deploy(self, bundle, options):
        options = options or {}
        svm = text(options.get('svm')).strip()
        name = object_name(bundle, options, maxlen=63)
        prefix = name_prefix(bundle, options, maxlen=63)
        self.check_version()
        svm_id = self.svm_uuid(svm) if svm else ''
        have = self.certs(svm, name)
        uuid = text(have[0].get('uuid')) if have else ''
        if uuid and self.unchanged(bundle, options,
                                   present=lambda: self.bound(svm, svm_id) == uuid):
            return self.same(bundle, 'as %s' % name)
        if not uuid:
            body = {'name': name, 'type': 'server',
                    'public_certificate': text(bundle.as_format('cert-pem')),
                    'private_key': text(bundle.as_format('key-pem')),
                    'intermediate_certificates': chain_list(bundle)}
            if not body['intermediate_certificates']:
                del body['intermediate_certificates']
            if svm:
                body['svm'] = {'name': svm}
            try:
                st, hd, d = self.req('POST', '/api/security/certificates?return_timeout=120',
                                     body, what='installing %s' % name)
            except PluginError as e:
                raise PluginError(str(e), retry=e.retry)        # no key in the detail
            self.wait_job(d, 'installing %s' % name, options)
            have = self.certs(svm, name)
            if not have:
                raise PluginError('ONTAP took %s but does not list it' % name)
            uuid = text(have[0].get('uuid'))
            self.ctx.step('installed %s' % name, 'ok')
        else:
            self.ctx.step('%s is there already' % name)
        self.bind(uuid, svm, svm_id, options)
        self.cleanup(svm, prefix, name, self.keep(options))
        self.remember(bundle, options)
        return 'installed %s, bound to %s' % (name, ('SVM %s' % svm) if svm else 'the cluster')

    def cleanup(self, svm, prefix, current, keep):
        if keep < 0:
            return
        try:
            recs = self.certs(svm)
        except PluginError as e:
            self.ctx.step('the old certificates cannot be listed: %s' % e, 'warn')
            return
        by_name = {text(r.get('name')): text(r.get('uuid')) for r in recs}
        for old in prune(list(by_name), prefix, keep, current):
            try:
                self.req('DELETE', '/api/security/certificates/%s' % q(by_name[old]),
                         what='deleting %s' % old)
                self.ctx.step('deleted the old %s' % old)
            except PluginError as e:
                self.ctx.step('the old %s stays: %s' % (old, e), 'warn')

    served_wait = (6, 10)       # the web services restart after the binding

    def served_places(self, options):
        if text((options or {}).get('svm')).strip() or not self.c('host'):
            return []           # an SVM serves on its own management LIF
        return [(self.c('host'), as_int(self.c('port', 443), 443))]


_SAME = (' Installs the certificate (POST /api/security/certificates), binds it, deletes older '
         'ones acme put there. Refused on a cluster that says another version.')


class NetAppOntap96Target(NetAppOntapTarget):
    """ONTAP 9.6 - 9.9: no /web endpoints - the certificate field of the cluster and SVM."""
    module_version, version_label, ontap_min, ontap_max = RANGES[0]
    description = ('ONTAP 9.6 - 9.9: bound through the certificate field of PATCH /api/cluster '
                   'or /api/svm/svms/<uuid>.' + _SAME)
    web_api = False


class NetAppOntap910Target(NetAppOntapTarget):
    """ONTAP 9.10.1 - 9.19: /api/cluster/web and /api/svm/svms/<uuid>/web."""
    module_version, version_label, ontap_min, ontap_max = RANGES[1]
    description = ('ONTAP 9.10.1 - 9.19: bound through PATCH /api/cluster/web or '
                   '/api/svm/svms/<uuid>/web; ONTAP restarts its web services.' + _SAME)
    web_api = True
