# -*- coding: utf-8 -*-
"""
Certificates from Google Cloud Certificate Authority Service (CA Service,
"privateca"): acme's request issued from a CA pool, with a service account's
key (the JWT of challenges/gcloud_dns.py, signed RS256 by openssl).

From the API's discovery document
(https://privateca.googleapis.com/$discovery/rest?version=v1, read 2026-11;
the same as https://cloud.google.com/certificate-authority-service/docs/
reference/rest):

* POST https://privateca.googleapis.com/v1/projects/<p>/locations/<l>/caPools/
  <pool>/certificates?certificateId=<id>[&issuingCertificateAuthorityId=<ca>]
  with {pemCsr, lifetime: "<seconds>s", certificateTemplate, labels}
  -> a Certificate {name, pemCertificate, pemCertificateChain [...]}.
* POST .../certificates/<id>:revoke {reason, requestId}.
* GET .../caPools/<pool> and POST .../caPools/<pool>:fetchCaCerts for "Try it".
* Scope https://www.googleapis.com/auth/cloud-platform; the service account
  needs roles/privateca.certificateRequester (and certificateManager to revoke).

The certificate's id at Google is kept in the module's state by the
certificate's fingerprint, for revocation.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.challenges.gcloud_dns import make_jwt
from acmelib.plugins.issuers import _source_common as sc

SCOPE = 'https://www.googleapis.com/auth/cloud-platform'
BASE = 'https://privateca.googleapis.com/v1'
REASONS = {0: 'REVOCATION_REASON_UNSPECIFIED', 1: 'KEY_COMPROMISE',
           2: 'CERTIFICATE_AUTHORITY_COMPROMISE', 3: 'AFFILIATION_CHANGED', 4: 'SUPERSEDED',
           5: 'CESSATION_OF_OPERATION', 6: 'CERTIFICATE_HOLD', 9: 'PRIVILEGE_WITHDRAWN',
           10: 'ATTRIBUTE_AUTHORITY_COMPROMISE'}
ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,63}\Z')


class GoogleCasIssuer(Issuer):
    kind = 'google_cas'
    dual = True
    title = 'Google Cloud CA Service'
    description = ('Certificates from a CA pool of Google Cloud Certificate Authority Service '
                   '(private CAs), signed in with a service account\'s key. Revocation included.')
    vendor = 'Google'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    choose_days = True
    fields = [
        field('service_account', 'Service account key (JSON)', 'secret', multiline=True,
              required=True,
              help='IAM → Service accounts → Keys → Add key → JSON, pasted whole. The account '
                   'needs "CA Service Certificate Requester" on the pool (and "Certificate '
                   'Manager" to revoke).'),
        field('project', 'Project ID', 'text', help='Empty: the project of the service account.'),
        field('location', 'Location', 'text', required=True, placeholder='europe-west3'),
        field('pool', 'CA pool', 'text', required=True, placeholder='tls-pool'),
        field('ca_id', 'CA in the pool', 'text', advanced=True,
              help='A CA of the pool to issue (issuingCertificateAuthorityId). Empty: Google '
                   'chooses one.'),
        field('template', 'Certificate template', 'text', advanced=True,
              placeholder='projects/P/locations/L/certificateTemplates/T',
              help='A certificate template\'s full name. A certificate\'s profile "template" wins.'),
        field('days', 'Validity (days)', 'number', default=90,
              help='A certificate\'s own days win; the pool\'s policy may cap it.'),
    ]

    _token = None
    _token_until = 0.0

    def _sa(self):
        try:
            sa = json.loads(self.c('service_account') or '{}')
        except ValueError:
            raise PluginError('the service account key is not JSON', retry=False)
        for k in ('client_email', 'private_key'):
            if not sa.get(k):
                raise PluginError('the service account key has no %s' % k, retry=False)
        return sa

    def _pool_path(self):
        project = str(self.c('project') or self._sa().get('project_id') or '').strip()
        loc, pool = str(self.c('location') or '').strip(), str(self.c('pool') or '').strip()
        for what, v in (('project', project), ('location', loc), ('CA pool', pool)):
            if not re.match(r'^[a-z0-9][a-z0-9.:_-]{0,127}\Z', v, re.I):
                raise PluginError('set the %s' % what, retry=False)
        return 'projects/%s/locations/%s/caPools/%s' % (project, loc, pool)

    def token(self):
        if limits.sharing(self.ctx):
            # one token for every run with these settings, for its lifetime (limits.py)
            return limits.session(limits.key_of(self, 'token'), self._sign_in)
        if self._token and time.time() < self._token_until - 60:
            return self._token
        self._token, life = self._sign_in()
        self._token_until = time.time() + life
        return self._token

    def _sign_in(self):
        sa = self._sa()
        body = urllib.parse.urlencode({'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                                       'assertion': make_jwt(self.ctx, sa, scope=SCOPE)})
        status, _h, data = sc.http(self.ctx, 'POST', sa.get('token_uri') or
                                   'https://oauth2.googleapis.com/token', body,
                                   {'Content-Type': 'application/x-www-form-urlencoded'},
                                   who='Google')
        got = sc.parse_json(data) or {}
        if status != 200 or not got.get('access_token'):
            raise sc.refusal('Google (token)', status, got, data,
                             'the service account key is wrong or disabled')
        return got['access_token'], float(got.get('expires_in') or 3000)

    def _call(self, method, path, body=None, what='CA Service'):
        status, _h, data = sc.http(self.ctx, method, BASE + '/' + path, body,
                                   {'Authorization': 'Bearer ' + self.token()}, who='CA Service')
        parsed = sc.parse_json(data)
        if status not in (200, 201):
            raise sc.refusal(what, status, parsed, data,
                             'the service account lacks the CA Service role on the pool')
        return parsed or {}

    def test(self):
        pool = self._call('GET', self._pool_path(), what='CA Service (pool)')
        cas = self._call('POST', self._pool_path() + ':fetchCaCerts', {}, what='CA Service (CA '
                                                                               'certificates)')
        n = len(cas.get('caCerts') or [])
        return 'CA Service answers: the pool %s (%s tier), %d CA chain(s)' % (
            pool.get('name', '').split('/')[-1] or '?', pool.get('tier') or '?', n)

    def issue(self, req):
        days = int(req.days or sc.num(self.c('days'), 90) or 90)
        cid = 'acme-%s-%s' % (time.strftime('%Y%m%d%H%M%S', time.gmtime()),
                              sc.b64u(os.urandom(6)).lower().replace('_', '0').replace('-', '1'))
        q = {'certificateId': cid}
        ca = str(self.c('ca_id') or '').strip()
        if ca:
            if not ID_RE.match(ca):
                raise PluginError('the CA in the pool is its id', retry=False)
            q['issuingCertificateAuthorityId'] = ca
        body = {'pemCsr': sc.csr_pem(req), 'lifetime': '%ds' % (days * 86400),
                'labels': {'issued-by': 'acme'}}
        tpl = str((req.profile or {}).get('template') or self.c('template') or '').strip()
        if tpl:
            body['certificateTemplate'] = tpl
        sc.say(self.ctx, 'the request goes to CA Service: %s (%d days)' % (self._pool_path(), days))
        got = self._call('POST', '%s/certificates?%s' % (self._pool_path(),
                                                         urllib.parse.urlencode(q)), body,
                         what='CA Service (create)')
        certs = sc.certs_of(got.get('pemCertificate'))
        chain = sc.certs_of(got.get('pemCertificateChain') or [])
        out = sc.finish(self.ctx, req, certs, chain, who='CA Service',
                        info={'gcas_name': got.get('name')})
        if got.get('name'):
            self.ctx.kv_set('gcas-cert:%s' % sc.fingerprint(out.cert_pem)[:40], got['name'],
                            ttl_s=800 * 86400)
        return out

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        name = self.ctx.kv_get('gcas-cert:%s' % sc.fingerprint(cert_pem)[:40])
        if not name or not re.match(r'^projects/[A-Za-z0-9._:/-]+\Z', str(name)):
            raise PluginError('acme does not know this certificate\'s name at CA Service - revoke '
                              'it in the console (CA Service → the pool → Certificates)',
                              retry=False)
        self._call('POST', '%s:revoke' % name, {'reason': REASONS.get(sc.reason_code(reason),
                                                                      REASONS[0])},
                   what='CA Service (revoke)')
        return 'CA Service revoked %s' % name.split('/')[-1]
