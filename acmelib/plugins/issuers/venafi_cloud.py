# -*- coding: utf-8 -*-
"""
Certificates from CyberArk Certificate Manager, SaaS - Venafi as a Service /
Venafi Control Plane / TLS Protect Cloud - through its REST API: acme's
request (CSR) for an application and its issuing template, the certificate
fetched when the template's CA has issued it, a certificate of the account
renewed in its place; the application's certificates listed for Certificates →
Import from a source.

What the API is, and from where: Venafi's (now CyberArk's) own client of it,
github.com/Venafi/vcert (pkg/venafi/cloud/connector.go, cloud.go, search.go,
pkg/util/utils.go; README-CLI-CLOUD.md), read 2026-11, and the service's OpenAPI
definitions on https://developer.venafi.com/tlsprotectcloud/reference/ (its
"servers", certificaterequests_create, certificates_getcontentsbyid):

* https://api.venafi.cloud (US), api.eu.venafi.cloud, api.au.venafi.cloud,
  api.uk.venafi.cloud, api.sg.venafi.cloud, api.ca.venafi.cloud; the API key in
  the header tppl-api-key.
* GET v1/useraccounts -> {user {username...}, company {name...}} (Try it).
* GET outagedetection/v1/applications/name/{APP} -> {id,
  certificateIssuingTemplateAliasIdMap {alias: template id}}.
* POST outagedetection/v1/certificaterequests {certificateSigningRequest (PEM),
  applicationId, certificateIssuingTemplateId, isVaaSGenerated false (the one
  field the OpenAPI definition requires), apiClientInformation {type, identifier},
  validityPeriod ("P<days>D"), existingCertificateId and renewType
  USER_PROVIDED_CSR (a renewal: "Required when renewing a certificate i.e.
  renewType is set to USER_PROVIDED_CSR")} -> {certificateRequests [{id, status...}]}.
* GET outagedetection/v1/certificaterequests/{id} -> {status (ISSUED, FAILED,
  other: waiting), certificateIds [...], applicationId,
  certificateIssuingTemplateId, errorInformation {message}}.
* GET outagedetection/v1/certificates/{id} -> {id, certificateRequestId...}.
* GET outagedetection/v1/certificates/{id}/contents?chainOrder=EE_FIRST&format=PEM
  -> the certificate and its chain (PEM); 409 while the CA has not signed it.
* POST outagedetection/v1/certificatesearch {expression {operator AND, operands
  [{field appstackIds, operator MATCH, value APP-ID}, {field validityEnd,
  operator GTE, value RFC3339}]}, paging {pageNumber, pageSize}} ->
  {count, certificates [{id, subjectCN [..], subjectAlternativeNamesByType
  {dNSName [..], iPAddress [..]}, serialNumber, fingerprint, validityStart,
  validityEnd, certificateRequestId}]} (Import from a source).

Revocation goes through the service's GraphQL API in vcert, not REST: it is not
offered here (revoke in the web interface).
"""
from __future__ import annotations

import calendar
import re
import time
import urllib.parse

from acmelib.plugins.base import Issuer, Plugin, PluginError, field
from acmelib.plugins.issuers import _source_common as sc

REGIONS = {'us': 'https://api.venafi.cloud', 'eu': 'https://api.eu.venafi.cloud',
           'au': 'https://api.au.venafi.cloud', 'uk': 'https://api.uk.venafi.cloud',
           'sg': 'https://api.sg.venafi.cloud', 'ca': 'https://api.ca.venafi.cloud'}
BASE = 'outagedetection/v1/'


def _epoch(v):
    try:
        return calendar.timegm(time.strptime(str(v or '')[:19], '%Y-%m-%dT%H:%M:%S'))
    except (TypeError, ValueError):
        return None


class VenafiCloudIssuer(Issuer):
    kind = 'venafi_cloud'
    title = 'CyberArk Certificate Manager SaaS (Venafi Cloud)'
    description = ('Certificates from CyberArk Certificate Manager, SaaS (Venafi as a Service, '
                   'TLS Protect Cloud) through its REST API: acme\'s request for an application '
                   'and issuing template, fetched when issued, renewed in place. Lists the '
                   'application\'s certificates for importing.')
    vendor = 'CyberArk (Venafi)'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    choose_days = True
    lists_existing = True           # certificatesearch + contents: Import from a source
    key_types = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
    fields = [
        field('region', 'Region', 'select', default='us',
              options=[['us', 'US (api.venafi.cloud)'], ['eu', 'EU (api.eu.venafi.cloud)'],
                       ['au', 'AU (api.au.venafi.cloud)'], ['uk', 'UK (api.uk.venafi.cloud)'],
                       ['sg', 'SG (api.sg.venafi.cloud)'], ['ca', 'CA (api.ca.venafi.cloud)'],
                       ['custom', 'Another address']]),
        field('api_url', 'API address', 'text', show_if={'region': ['custom']},
              placeholder='https://api.venafi.cloud'),
        field('api_key', 'API key', 'secret', required=True,
              help='The web interface → your name → Preferences → API Keys. Sent as the header '
                   'tppl-api-key.'),
        field('application', 'Application', 'text', required=True, placeholder='Storefront',
              help='The name of the application the certificates belong to (you must be among '
                   'its owners).'),
        field('template', 'Issuing template', 'catalog', catalog='templates',
              depends=['api_key', 'application'],
              help='Load the list (the application\'s issuing templates, by their API alias - '
                   'nothing changes) and pick the one that issues the certificates.'),
        field('template_typed', 'Issuing template typed (API alias)', 'text', advanced=True,
              placeholder='Default',
              help='Only where the list cannot be loaded here: the API alias, used instead of '
                   'Issuing template.'),
        field('days', 'Validity (days)', 'number', default=0,
              help='0: as the issuing template says. A certificate\'s own days win.'),
        field('renew_in_place', 'Renew the same certificate', 'bool', default=True,
              advanced=True,
              help='A renewal (and a certificate imported from the service) is asked for as a '
                   'renewal of it (existingCertificateId), so the service keeps its history.'),
        field('wait', 'Wait for the certificate (s)', 'number', default=180, advanced=True,
              help='Longer (a CA that takes its time): acme asks again at the next try.'),
        field('poll_every', 'Ask again every (s)', 'number', default=5, advanced=True),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self._sleep = time.sleep
        self._app = None

    # -- the API ---------------------------------------------------------------------------
    def _base(self):
        r = self.c('region') or 'us'
        url = str(self.c('api_url') or '').strip().rstrip('/') if r == 'custom' else \
            REGIONS.get(r)
        if not url or not re.match(r'^https://[^\s/]+\Z', url):
            raise PluginError('set the API address (https://api.venafi.cloud)', retry=False)
        return url + '/'

    def _raw(self, method, path, body=None):
        key = str(self.c('api_key') or '').strip()
        if not key:
            raise PluginError('set the API key', retry=False)
        return sc.http(self.ctx, method, self._base() + path, body,
                       {'tppl-api-key': key, 'Accept': 'application/json' if body is not None
                        else '*/*'}, who='CyberArk Certificate Manager')

    def call(self, method, path, body=None, what='', ok=(200, 201, 202)):
        status, _h, data = self._raw(method, path, body)
        got = sc.parse_json(data)
        if status not in ok:
            raise sc.refusal('CyberArk Certificate Manager (%s)' % (what or path), status, got,
                             data, 'the API key is wrong or may not do this')
        return got if got is not None else {}

    def application(self):
        """(application id, {template alias: template id}) of the application set."""
        if self._app is None:
            name = str(self.c('application') or '').strip()
            if not name:
                raise PluginError('set the application', retry=False)
            got = self.call('GET', BASE + 'applications/name/%s' % urllib.parse.quote(name, ''),
                            what='the application %s' % name)
            if not got.get('id'):
                raise PluginError('there is no application "%s"' % name, retry=False)
            self._app = (str(got['id']), dict(got.get('certificateIssuingTemplateAliasIdMap')
                                              or {}))
        return self._app

    def template_id(self):
        alias = str(self.c('template_typed') or '').strip() or str(self.c('template') or '').strip()
        if not alias:
            raise PluginError('set the issuing template', retry=False)
        app, cits = self.application()
        if alias not in cits:
            raise PluginError('the application %s has no issuing template "%s" (it has: %s)' % (
                self.c('application'), alias, ', '.join(sorted(cits)) or 'none'), retry=False)
        return app, cits[alias]

    # -- the form's list -------------------------------------------------------------------------
    def catalog(self, key):
        if key != 'templates':
            raise PluginError('there is no list called %s here' % key, retry=False)
        _app, cits = self.application()
        opts = [[a, a] for a in sorted(cits, key=str.lower)]
        return {'options': opts, 'said': '%d issuing templates' % len(opts)}

    # -- the certificate ---------------------------------------------------------------------------
    def _previous(self, req):
        """The certificate id a renewal renews, or None."""
        if getattr(req, 'ref', None):
            return str(req.ref)
        if not sc.as_bool(self.c('renew_in_place'), True) or not getattr(req, 'cert_id', None):
            return None
        return self.ctx.kv_get('venafi-cloud-cert:%s' % req.cert_id)

    def request_body(self, req):
        days = int(req.days or sc.num(self.c('days'), 0) or 0)
        prev = self._previous(req)
        body = {'certificateSigningRequest': sc.csr_pem(req).strip(), 'isVaaSGenerated': False,
                'apiClientInformation': {'type': 'acme', 'identifier': ''}}
        if prev:
            # vcert RenewCertificate: the application and template of the request that made it
            cert = self.call('GET', BASE + 'certificates/%s' % self._safe(prev),
                             what='the certificate %s' % prev)
            rid = cert.get('certificateRequestId')
            old = self.call('GET', BASE + 'certificaterequests/%s' % self._safe(rid),
                            what='its request') if rid else {}
            app, tpl = old.get('applicationId'), old.get('certificateIssuingTemplateId')
            if not app or not tpl:
                app, tpl = self.template_id()
            body.update(existingCertificateId=prev, renewType='USER_PROVIDED_CSR',
                        applicationId=app, certificateIssuingTemplateId=tpl)
        else:
            app, tpl = self.template_id()
            body.update(applicationId=app, certificateIssuingTemplateId=tpl)
        if days:
            body['validityPeriod'] = 'P%dD' % days
        return body

    @staticmethod
    def _safe(v):
        v = str(v or '').strip()
        if not re.match(r'^[0-9A-Za-z-]{1,64}\Z', v):
            raise PluginError('"%s" is not an id of the service' % v, retry=False)
        return v

    def issue(self, req):
        if not req.names:
            raise PluginError('the certificate has no names', retry=False)
        slot = sc.pending_slot('venafi-cloud', self._base(), req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        if held:
            rid = held['id']
            sc.say(self.ctx, 'the request %s waits at the service - asked for again' % rid)
        else:
            body = self.request_body(req)
            got = self.call('POST', BASE + 'certificaterequests', body, what='the request')
            reqs = got.get('certificateRequests') or []
            rid = str((reqs[0] if reqs and isinstance(reqs[0], dict) else {}).get('id') or '')
            self._safe(rid)
            if body.get('existingCertificateId'):
                sc.say(self.ctx, 'the service took the renewal of %s: request %s' % (
                    body['existingCertificateId'], rid), 'ok')
            else:
                sc.say(self.ctx, 'the service took the request: %s' % rid, 'ok')
            held = sc.pending_put(self.ctx, slot, req, {'id': rid, 'csr_pem': sc.csr_pem(req)},
                                  ttl_days=30)
            r = req
        cid, certs = self._await(rid, slot)
        out = sc.finish(self.ctx, r, certs, who='the service',
                        key_pem=r.key_pem if r is not req else None,
                        info={'certificate_id': cid, 'request_id': rid, 'ref': cid})
        sc.pending_drop(self.ctx, slot)
        if getattr(req, 'cert_id', None):
            self.ctx.kv_set('venafi-cloud-cert:%s' % req.cert_id, cid, ttl_s=5 * 366 * 86400)
        return out

    def contents(self, cid):
        """The certificates (DER) of `cid`, or None while the CA has not signed it."""
        status, _h, data = self._raw('GET', BASE + 'certificates/%s/contents?chainOrder=EE_FIRST'
                                     '&format=PEM' % self._safe(cid))
        if status == 409:
            return None
        if status != 200:
            raise sc.refusal('CyberArk Certificate Manager (the certificate %s)' % cid, status,
                             sc.parse_json(data), data)
        return sc.certs_of(data)

    def _await(self, rid, slot):
        end = time.time() + sc.num(self.c('wait'), 180)
        every = max(1.0, sc.num(self.c('poll_every'), 5))
        while True:
            st = self.call('GET', BASE + 'certificaterequests/%s' % self._safe(rid),
                           what='the request %s' % rid)
            status = str(st.get('status') or '').upper()
            if status == 'FAILED':
                sc.pending_drop(self.ctx, slot)
                err = st.get('errorInformation') if isinstance(st.get('errorInformation'),
                                                                dict) else {}
                raise PluginError('the service did not issue (request %s): %s' % (
                    rid, err.get('message') or 'FAILED'), retry=False)
            if status == 'ISSUED' and st.get('certificateIds'):
                cid = str(st['certificateIds'][0])
                certs = self.contents(cid)
                if certs:
                    return cid, certs
            if time.time() >= end or self.ctx.cancelled():
                raise PluginError('the service has not issued yet (request %s: %s) - acme asks '
                                  'again at the next try' % (rid, status or 'waiting'))
            self._sleep(every)

    def test(self):
        me = self.call('GET', 'v1/useraccounts', what='the API key')
        user = (me.get('user') or {}) if isinstance(me.get('user'), dict) else {}
        comp = (me.get('company') or {}) if isinstance(me.get('company'), dict) else {}
        words = 'the service answers: the API key is %s\'s of %s' % (
            user.get('username') or '?', comp.get('name') or '?')
        if str(self.c('application') or '').strip():
            _app, cits = self.application()
            words += '; the application %s has %d issuing template(s)' % (
                self.c('application'), len(cits))
        return words

    # -- the certificates of the application (Certificates → Import from a source) -------------
    def list_existing(self):
        """The application's certificates still valid (certificatesearch) - read only."""
        operands = [{'field': 'validityEnd', 'operator': 'GTE',
                     'value': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}]
        if str(self.c('application') or '').strip():
            app, _cits = self.application()
            operands.insert(0, {'field': 'appstackIds', 'operator': 'MATCH', 'value': app})
        mine = {}
        try:
            for k, v in self.ctx.kv_keys('venafi-cloud-cert:').items():
                cid = k.split(':', 1)[1]
                if cid.isdigit() and v:
                    mine[str(v)] = int(cid)
        except (AttributeError, NotImplementedError):
            pass
        out, page, per = [], 0, 50
        while page < 200:
            got = self.call('POST', BASE + 'certificatesearch', {
                'expression': {'operator': 'AND', 'operands': operands},
                'paging': {'pageNumber': page, 'pageSize': per}}, what='the certificates')
            items = [x for x in (got.get('certificates') or []) if isinstance(x, dict)]
            for c in items:
                cid = str(c.get('id') or '')
                if not cid:
                    continue
                cns = c.get('subjectCN') or []
                cn = str(cns[0] if isinstance(cns, list) and cns else cns or '')
                sans = c.get('subjectAlternativeNamesByType') or {}
                names = [cn] + [str(n) for n in (sans.get('dNSName') or []) +
                                (sans.get('iPAddress') or [])]
                names = [n for i, n in enumerate(names) if n and n not in names[:i]]
                out.append({'ref': cid, 'cn': cn or (names[0] if names else ''), 'names': names,
                            'product': str(self.c('application') or ''), 'status': 'issued',
                            'not_before': _epoch(c.get('validityStart')),
                            'not_after': _epoch(c.get('validityEnd')),
                            'serial': str(c.get('serialNumber') or '').upper(),
                            'downloadable': True, 'renewable': 'reissue', 'note': '',
                            'acme_cert_id': mine.get(cid)})
            page += 1
            if len(items) < per:
                break
        return out

    def fetch_existing(self, ref):
        cid = self._safe(ref)
        certs = self.contents(cid)
        if not certs:
            raise PluginError('the service has no certificate %s to give yet' % cid, retry=False)
        return sc.existing(certs, who='the service', ref=cid)

    # -- discovery (1.0.29): the form filled in from the account -------------------------------
    discover_keys = ['region', 'api_url', 'api_key']

    def discover_setup(self):
        """Read-only: the applications the API key may use that have issuing templates
        (GET outagedetection/v1/applications?issuingTemplateAssigned=true), each with its
        templates - one template set with the application - and the templates of the
        application set or found."""
        out = {'sets': {}, 'choices': {}, 'facts': [], 'notes': []}
        got = self.call('GET', BASE + 'applications?issuingTemplateAssigned=true',
                        what='the applications')
        apps = [a for a in got.get('applications') or [] if isinstance(a, dict) and a.get('name')]
        out['facts'].append(['Applications', str(len(apps))])
        maps, sets = {}, {}
        for a in apps:
            cits = dict(a.get('certificateIssuingTemplateAliasIdMap') or {})
            maps[str(a['name'])] = (str(a.get('id') or ''), cits)
            if len(cits) == 1:
                sets[str(a['name'])] = {'template': next(iter(cits))}
        self.offer(out, 'application', [[n, '%s (%d template(s))' % (n, len(maps[n][1]))]
                                        for n in sorted(maps, key=str.lower)], sets)
        app = str(self.c('application') or '').strip() or \
            (out['choices'].get('application') or {}).get('pick') or ''
        if app in maps:
            self._app = maps[app]
        if app:
            with sc.assumed(self, {'application': app}):
                sc.merge_found(out, Plugin.discover_setup(self))
        else:
            out['notes'].append('Issuing template: pick the application, then ask again')
        self._app = None
        return out
