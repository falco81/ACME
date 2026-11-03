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
Checked against api-docs/gcp_certmanager/notes.md and
certificatemanager-v1-discovery.json: PATCH in place is for the same SANs
("make sure that the SANs in the new certificate exactly match"); with other
names acme still updates it (what the API does then is not said) and warns.
"""
from __future__ import annotations

import re
import time
import urllib.parse

from acmelib.plugins.targets._common import (
    PluginError, field, label_of, pem_blocks, text, verify_fields, as_bool)
from acmelib.plugins.base import Plugin
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

    # -- discovery (1.0.29): the form filled in from the project ------------------------------
    discover_keys = ['service_account', 'project']

    def discover_setup(self):
        """Read-only: the locations of Certificate Manager the project sees
        (projects.locations.list, GET v1/projects/<p>/locations) offered as the location,
        global first; the project of the service account shown."""
        out = Plugin.discover_setup(self)
        sa = service_account(self)
        proj = text(self.c('project')).strip() or text(sa.get('project_id')).strip()
        if not proj:
            raise PluginError('no project: set the Project ID', retry=False)
        out['facts'].append(['Project', proj])
        if sa.get('client_email'):
            out['facts'].append(['Service account', text(sa['client_email'])])
        locs, tok = [], ''
        for _ in range(20):
            st, hd, d = self.req('GET', '%s/projects/%s/locations?pageSize=500%s' % (
                BASE, urllib.parse.quote(proj, safe=''),
                '&pageToken=' + urllib.parse.quote(tok, safe='') if tok else ''),
                what='listing the locations')
            d = d if isinstance(d, dict) else {}
            locs += [x for x in d.get('locations') or [] if isinstance(x, dict)]
            tok = text(d.get('nextPageToken'))
            if not tok:
                break
        opts = []
        for x in locs:
            lid = text(x.get('locationId') or text(x.get('name')).rsplit('/', 1)[-1]).strip()
            if lid and lid not in [o[0] for o in opts]:
                shown = text(x.get('displayName')).strip()
                opts.append([lid, '%s (%s)' % (lid, shown) if shown and shown != lid else lid])
        opts.sort(key=lambda o: (o[0] != 'global', o[0]))
        self.offer(out, 'location', opts, pick='global')
        return out

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
            had = sorted(text(n).lower() for n in
                         ((d if isinstance(d, dict) else {}).get('sanDnsnames') or []))
            now = sorted(text(n).lower() for n in (bundle.names or []))
            if had and had != now:
                # "make sure that the SANs in the new certificate exactly match the SANs
                # in the existing certificate" (Google's page on updating one)
                self.ctx.step('the names differ from those of %s (%s, now %s): Google asks '
                              'for the same names when a certificate is updated in place - '
                              'check the certificate map entries' % (cid, ', '.join(had),
                                                                     ', '.join(now)), 'warn')
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
