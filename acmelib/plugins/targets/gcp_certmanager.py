# -*- coding: utf-8 -*-
"""
Google Cloud Certificate Manager: a self-managed certificate made once and
on each renewal updated in place (PATCH ...?updateMask=selfManaged), so the
certificate maps and load balancers pointing at it take the new one.

    POST  https://certificatemanager.googleapis.com/v1/projects/<p>/locations/<l>/certificates
          ?certificateId=<id>  {"selfManaged": {"pemCertificate", "pemPrivateKey"}}
    PATCH .../certificates/<id>?updateMask=selfManaged   (the same body)
    GET   .../certificates/<id> -> pemCertificate (output only)
    GET   https://certificatemanager.googleapis.com/v1/<operation name>  until done

The token: a service account's key, a JWT signed RS256 by the openssl program
(challenges/gcloud_dns.py), scope cloud-platform.

Sources:
    https://cloud.google.com/certificate-manager/docs/reference/certificate-manager/rest/v1/projects.locations.certificates
    https://cloud.google.com/certificate-manager/docs/certificates#update-certificate
    https://cloud.google.com/certificate-manager/docs/reference/certificate-manager/rest/v1/projects.locations.operations/get
Uncertain: whether the PATCH of a certificate attached to a map is taken
by every load balancer at once - Google's page says it is.
"""
from __future__ import annotations

import re
import time
import urllib.parse

from acmelib.plugins.targets._common import (
    PluginError, field, label_of, pem_blocks, text, verify_fields, as_bool)
from acmelib.plugins.targets._cloud import (
    CloudTarget, cloud_fields, google_token, service_account)

BASE = 'https://certificatemanager.googleapis.com/v1'


def cm_id(bundle, options):
    raw = text((options or {}).get('certificate_id')).strip()
    if raw:
        if not re.match(r'^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$', raw):
            raise PluginError('"%s" is not a certificate ID (a-z, 0-9 and -, starting with a '
                              'letter, at most 63)' % raw, retry=False)
        return raw
    s = ('acme-' + re.sub(r'[^a-z0-9-]+', '-', label_of(bundle, options, 50))).strip('-')
    return s[:63].rstrip('-')


class GcpCertManagerTarget(CloudTarget):
    kind = 'gcp_certmanager'
    title = 'Google Cloud Certificate Manager'
    vendor = 'Google'
    description = ('Uploads the certificate to Certificate Manager as a self-managed one and '
                   'updates it in place on each renewal, for the load balancers using it.')
    doc = 'targets.md'
    fields = [
        field('service_account', 'Service account key (JSON)', 'secret', required=True,
              multiline=True,
              help='IAM → Service accounts → Keys → Add key → JSON, pasted whole. The account '
                   'needs the role "Certificate Manager Editor" '
                   '(roles/certificatemanager.editor) on the project.'),
        field('project', 'Project ID', 'text', default='',
              help='Empty: the project of the service account.'),
        field('location', 'Location', 'text', default='global',
              help='global for global external load balancers; a region (europe-west3) for '
                   'regional ones'),
    ] + cloud_fields()
    deploy_fields = [
        field('certificate_id', 'Certificate ID', 'text', placeholder='www-example-com',
              help='a-z, 0-9 and -; empty: acme-<the certificate\'s name>'),
        field('description', 'Description', 'text', advanced=True,
              default='kept by acme'),
    ] + verify_fields()

    _now = None
    _sleep = staticmethod(time.sleep)

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % google_token(self)}

    def parent(self):
        proj = text(self.c('project')).strip() or service_account(self).get('project_id', '')
        if not proj:
            raise PluginError('no project: set the Project ID', retry=False)
        loc = text(self.c('location') or 'global').strip()
        return '%s/projects/%s/locations/%s' % (BASE, urllib.parse.quote(proj, safe=''),
                                                urllib.parse.quote(loc, safe=''))

    def test(self):
        st, hd, d = self.req('GET', self.parent() + '/certificates?pageSize=100',
                             what='listing the certificates')
        n = len((d or {}).get('certificates') or []) if isinstance(d, dict) else 0
        return 'signed in to Certificate Manager (%s), %d certificate%s' % (
            self.parent().split('/projects/')[1], n, '' if n == 1 else 's')

    def wait(self, op, what):
        """An operation waited for (two minutes at most)."""
        for _ in range(60):
            if not isinstance(op, dict) or op.get('done'):
                break
            self._sleep(2)
            st, hd, op = self.req('GET', '%s/%s' % (BASE, op.get('name')), what=what)
        if not isinstance(op, dict) or not op.get('done'):
            raise PluginError('%s: Google has not finished after two minutes' % what)
        if op.get('error'):
            raise PluginError('%s: %s' % (what, text(op['error'].get('message') or op['error'])),
                              detail=text(op), retry=False)
        return op

    def deploy(self, bundle, options):
        options = options or {}
        cid = cm_id(bundle, options)
        url = '%s/certificates/%s' % (self.parent(), cid)
        st, hd, d = self.req('GET', url, ok=(200, 404), what='reading %s' % cid)
        exists = st == 200
        if exists and not as_bool(options.get('force')):
            have = pem_blocks((d or {}).get('pemCertificate') if isinstance(d, dict) else '')
            if have and have[0].strip() == text(bundle.cert_pem).strip():
                self.remember(bundle, options)
                return self.same(bundle, 'in %s' % cid)
        body = {'selfManaged': {'pemCertificate': text(bundle.as_format('fullchain-pem')),
                                'pemPrivateKey': text(bundle.as_format('key-pem'))}}
        if exists:
            st, hd, op = self.req('PATCH', url + '?updateMask=selfManaged', body,
                                  what='updating %s' % cid)
            how = 'updated'
        else:
            body['description'] = self.opt(options, 'description', 'kept by acme')
            body['labels'] = {'managed-by': 'acme'}
            st, hd, op = self.req('POST', '%s/certificates?certificateId=%s' % (
                self.parent(), urllib.parse.quote(cid)), body, what='making %s' % cid)
            how = 'made'
        self.wait(op, '%s %s' % ('updating' if exists else 'making', cid))
        self.ctx.step('%s the certificate %s' % (how, cid), 'ok')
        self.remember(bundle, options)
        return '%s %s in Certificate Manager' % (how, cid)
