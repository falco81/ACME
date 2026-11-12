# -*- coding: utf-8 -*-
"""
VMware Cloud Director 10.5.1 - 10.6.x - the certificate of the cells' HTTP endpoint (portals,
API, console proxy on 443) through the OpenAPI: put into the Certificates Library, then each
cell's access endpoints pointed at it, a cell at a time; older acme items nothing uses deleted.

    POST /cloudapi/1.0.0/sessions/provider       (basic, user@System) -> the token in the header
                                                 X-VMWARE-VCLOUD-ACCESS-TOKEN (Bearer)
    GET  /cloudapi/1.0.0/ssl/certificateLibrary?page=1&pageSize=128&filter=alias==<alias>
    POST /cloudapi/1.0.0/ssl/certificateLibrary  {"alias", "description", "certificate" (leaf +
                                                 intermediates), "privateKey" (PKCS#8, PEM)}
    GET  /cloudapi/1.0.0/cells?page=1&pageSize=128
    GET|PUT /cloudapi/1.0.0/cells/<cellUrn>      {"status": "MAINTENANCE" | "ACTIVE"} (when asked)
    GET|PUT /cloudapi/1.0.0/cells/<cellUrn>/accessEndpoints    the whole object back, only
                                                 apiSslCertRef changed -> 202, a task
    GET  <the task in Location>                  until it is "success"
    GET  /cloudapi/1.0.0/ssl/certificateLibrary/<id>/consumers ; DELETE .../<id>

From 10.5.1 the cells read their certificate from the Certificates Library and in 10.6
"cell-management-tool certificates" is gone: the library and accessEndpoints (API 38.1+) are
the way, the same in 10.5.1 - 10.6.1 (one module; the API version sent is a field).

Sources: navody/certifikaty/vmware/site-recovery-replication-vcd.md (2026-11) - VCD 10.6
"Certificate Management in the VMware Cloud Director Appliance", "Change the Certificates of a
Cell", "Import Certificates to the Certificates Library" (Certificate Library: Manage), VCD
OpenAPI 39.1 Certificate Library, Cell (accessEndpoints, apiSslCertRef and jmxSslCertRef both
required), sessions/provider.
Less certain (said in the guide): the token header's name and the Bearer use (from the VCD API
Programming Guide, not the reference page) - acme takes the token from either header it is in;
the rights needed for accessEndpoints (a System Administrator); the cell's PUT with its status.
"""
from __future__ import annotations

import base64
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, text, object_name, name_prefix, prune,
    http_fields, tls_fields, verify_fields, keep_field, as_int)
from acmelib.plugins.targets import _vmware as V

API = '/cloudapi/1.0.0'
LIB = API + '/ssl/certificateLibrary'


def q(s):
    return urllib.parse.quote(text(s), safe='')


class VcdTarget(HttpTarget):
    kind = 'vcd'
    title = 'VMware Cloud Director (cell certificate)'
    vendor = 'VMware'
    discovery = False
    description = ('Cloud Director 10.5.1 - 10.6: imports the certificate into the Certificates '
                   'Library and points each cell\'s HTTP endpoint (portals, API, console proxy) '
                   'at it, a cell at a time (in maintenance when asked); deletes older acme '
                   'items nothing uses.')
    doc = 'targets.md'
    fields = http_fields(443, 'vcd.example.local') + [
        field('user', 'User', 'text', required=True, placeholder='svc-cert@System',
              help='a provider (System organisation) user; "@System" is added when missing'),
        field('password', 'Password', 'secret', required=True),
        field('api_version', 'API version', 'text', default='39.0', advanced=True,
              help='sent in Accept (application/json;version=...): 39.0 for 10.6, 38.1 for '
                   '10.5.1'),
    ] + tls_fields()
    deploy_fields = [
        field('cells', 'Cells', 'list', placeholder='vcd-cell1',
              help='one a line: the names (or urn:vcloud:cell:... ids) of the cells; empty: '
                   'every cell'),
        field('maintenance', 'Each cell in maintenance while it changes', 'bool', default=False,
              help='quiesced first and active again after (recommended behind a load '
                   'balancer: no session is cut)'),
        keep_field(1),
    ] + verify_fields()

    token = None

    def accept(self):
        return 'application/json;version=%s' % (text(self.c('api_version')).strip() or '39.0')

    def auth_headers(self):
        h = {'Accept': self.accept()}
        if self.token:
            h['Authorization'] = 'Bearer %s' % self.token
        return h

    def login(self):
        user = text(self.c('user')).strip()
        if '@' not in user:
            user += '@System'
        raw = '%s:%s' % (user, self.c('password') or '')
        try:
            st, hd, d = self.req('POST', API + '/sessions/provider', auth=False, headers={
                'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode(),
                'Accept': self.accept()}, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail,
                              retry=not any(x in str(e) for x in ('(401)', '(403)')))
        tok = text(hd.get('x-vmware-vcloud-access-token')).strip()
        if not tok:
            raise PluginError('Cloud Director gave no X-VMWARE-VCLOUD-ACCESS-TOKEN on signing in',
                              retry=False)
        self.token = tok

    def page(self, path, what):
        out = []
        for n in range(1, 50):
            sep = '&' if '?' in path else '?'
            st, hd, d = self.req('GET', '%s%spage=%d&pageSize=128' % (path, sep, n), what=what)
            d = d if isinstance(d, dict) else {}
            out += [x for x in d.get('values') or [] if isinstance(x, dict)]
            if n >= as_int(d.get('pageCount', 1), 1):
                break
        return out

    def test(self):
        self.login()
        cells = self.page(API + '/cells', 'listing the cells')
        return 'signed in to Cloud Director %s; cells: %s' % (
            self.c('host'), ', '.join(text(c.get('name') or c.get('id')) for c in cells) or 'none')

    def find(self, alias):
        got = self.page('%s?filter=%s' % (LIB, q('alias==%s' % alias)),
                        'looking for %s in the library' % alias)
        got = [x for x in got if text(x.get('alias')) == alias]
        return got[0] if got else None

    def wait(self, hd, what):
        loc = text(hd.get('location')).strip()
        if not loc:
            return
        V.wait_task(self, lambda: self.req('GET', loc, what='reading the task of %s' % what)[2],
                    done=lambda t: text((t or {}).get('status') if isinstance(t, dict)
                                        else '').lower() == 'success',
                    failed=lambda t: text((t or {}).get('status') if isinstance(t, dict)
                                          else '').lower() in ('error', 'aborted', 'canceled'),
                    tries=60, every=5.0, what=what)

    def set_status(self, cell, status):
        urn = text(cell.get('id'))
        st, hd, obj = self.req('GET', '%s/cells/%s' % (API, q(urn)), what='reading the cell')
        obj = dict(obj if isinstance(obj, dict) else {}, status=status)
        st, hd, d = self.req('PUT', '%s/cells/%s' % (API, q(urn)), obj,
                             what='putting the cell %s %s' % (cell.get('name') or urn,
                                                              status.lower()))
        self.wait(hd, 'the cell going %s' % status.lower())

    def chosen(self, options):
        cells = self.page(API + '/cells', 'listing the cells')
        want = lines(options.get('cells'))
        if not want:
            if not cells:
                raise PluginError('Cloud Director lists no cell', retry=False)
            return cells
        out = []
        for w in want:
            got = [c for c in cells if w in (text(c.get('name')), text(c.get('id')))]
            if not got:
                raise PluginError('Cloud Director has no cell "%s"' % w, retry=False)
            out.append(got[0])
        return out

    def deploy(self, bundle, options):
        options = options or {}
        alias = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        self.login()
        item = self.find(alias)
        cells = self.chosen(options)
        if self.unchanged(bundle, options, present=lambda: item is not None):
            return self.same(bundle, 'as %s' % alias)
        if item is None:
            st, hd, item = self.req('POST', LIB, {
                'alias': alias, 'description': 'acme %s' % bundle.name,
                'certificate': text(bundle.as_format('fullchain-pem')),
                'privateKey': text(bundle.as_format('key-pem'))},
                what='importing %s into the Certificates Library' % alias)
            item = item if isinstance(item, dict) and item.get('id') else self.find(alias)
            if not item:
                raise PluginError('the library does not list %s after the import' % alias)
            self.ctx.step('imported %s into the Certificates Library' % alias, 'ok')
        else:
            self.ctx.step('%s is in the Certificates Library already' % alias)
        ref = {'id': text(item.get('id')), 'name': alias}
        did = []
        for cell in cells:
            urn, name = text(cell.get('id')), text(cell.get('name') or cell.get('id'))
            path = '%s/cells/%s/accessEndpoints' % (API, q(urn))
            st, hd, ep = self.req('GET', path, what='reading the endpoints of %s' % name)
            ep = ep if isinstance(ep, dict) else {}
            if text((ep.get('apiSslCertRef') or {}).get('id')) == ref['id']:
                self.ctx.step('%s uses %s already' % (name, alias))
                continue
            maint = as_bool(self.opt(options, 'maintenance', False))
            if maint:
                self.set_status(cell, 'MAINTENANCE')
                self.ctx.step('%s is in maintenance' % name)
            try:
                ep['apiSslCertRef'] = ref
                st, hd, d = self.req('PUT', path, ep, what='pointing %s at %s' % (name, alias))
                self.wait(hd, 'the endpoints of %s' % name)
                self.ctx.step('%s serves %s (its connections restarted)' % (name, alias), 'ok')
                did.append(name)
            finally:
                if maint:
                    self.set_status(cell, 'ACTIVE')
                    self.ctx.step('%s is active again' % name)
        self.cleanup(prefix, alias, self.keep(options))
        self.remember(bundle, options)
        return '%s: %s' % (alias, ', '.join(did) or 'every cell had it already')

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            items = {text(x.get('alias')): x for x in self.page(LIB, 'listing the library')}
        except PluginError as e:
            self.ctx.step('the library cannot be listed: %s' % e, 'warn')
            return
        for old in prune(list(items), prefix, keep, current):
            iid = text(items[old].get('id'))
            try:
                st, hd, d = self.req('GET', '%s/%s/consumers?page=1&pageSize=25' % (LIB, q(iid)),
                                     what='asking what uses %s' % old)
                if as_int((d or {}).get('resultTotal', 0) if isinstance(d, dict) else 0, 0):
                    self.ctx.step('the older %s stays: something still uses it' % old, 'warn')
                    continue
                self.req('DELETE', '%s/%s' % (LIB, q(iid)), what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')

    served_wait = (6, 10)

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []
