# -*- coding: utf-8 -*-
"""
VMware Aria Suite Lifecycle 8.18 - the certificate imported into its Locker, then put on the
Aria products it manages (Aria Operations, Aria Automation / Orchestrator, Aria Operations for
Logs, Workspace ONE Access) by Suite Lifecycle's own "Replace Certificate" - which also makes
the other products trust it again and takes a snapshot when set to.

    Authorization: Basic admin@local (or a Certificate Administrator)
    GET    /lcm/locker/api/v2/certificates                    the Locker (there already?)
    POST   /lcm/locker/api/v2/certificates/import  {"alias", "certificateChain" (leaf,
           intermediates, root), "privateKey", "passphrase"}      CertificateImportRequestDTO
    POST   /lcm/lcops/api/v2/environments/<env>/products/<product>/certificates/<vmid>/pre-validate
    PUT    /lcm/lcops/api/v2/environments/<env>/products/<product>/certificates/<vmid>
                                                             -> a request (its requestId)
    GET    /lcm/request/api/v2/requests/<requestId>           until it is COMPLETED (or FAILED)
    DELETE /lcm/locker/api/v2/certificates/<vmid>             older acme ones (refused while used)

Aria Operations' own web certificate (Admin UI only), Operations for Logs (its UI only) and
Workspace ONE Access have no API of their own to take a certificate: through Suite Lifecycle is
the documented way. The Suite Lifecycle appliance's own certificate is two files and an nginx
restart (/opt/vmware/vlcm/cert/server.crt, server.key; "systemctl restart nginx") - the SSH
target does that, see the guide.

Sources: navody/certifikaty/vmware/aria-vcf-operations.md (2026-11) - Aria Suite Lifecycle 8.18
"Manage certificates" (Locker: a certificate expiring within 15 days is refused), "Create and
assign a Certificate Administrator role", REST API Operations Index (Locker Certificates
Controller, Deployments Controller, Request Controller), data structure
CertificateImportRequestDTO; KB 408525, KB 411526 (an expired certificate cannot be replaced
through Lifecycle).
Less certain (said in the guide): the bodies of PUT .../certificates/<vmid> and pre-validate
(sent empty, as the guide's calls do); the product ids (vrops, vra, vrli, vidm, ...: from
Suite Lifecycle's own environment details); the field names of a request's state (state /
status, values COMPLETED / FAILED); basic authentication with admin@local.
"""
from __future__ import annotations

import base64
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, as_int, text, object_name, name_prefix,
    prune, http_fields, tls_fields, verify_fields, keep_field)
from acmelib.plugins.targets import _vmware as V

LOCKER = '/lcm/locker/api/v2/certificates'


def q(s):
    return urllib.parse.quote(text(s), safe='')


def _list(d):
    """The certificates of a Locker answer: a list, or a page of one."""
    if isinstance(d, list):
        return [x for x in d if isinstance(x, dict)]
    if isinstance(d, dict):
        for k in ('certificates', 'content', 'results', 'items', 'elements'):
            if isinstance(d.get(k), list):
                return [x for x in d[k] if isinstance(x, dict)]
    return []


def _state(d):
    if not isinstance(d, dict):
        return ''
    return text(d.get('state') or d.get('status') or d.get('requestState') or '').upper()


class AriaLifecycleTarget(HttpTarget):
    kind = 'aria_lifecycle'
    title = 'VMware Aria Suite Lifecycle (product certificates)'
    vendor = 'VMware'
    discovery = False
    description = ('Aria Suite Lifecycle 8.18: imports the certificate into the Locker and runs '
                   '"Replace Certificate" on the Aria products listed (Operations, Automation, '
                   'Operations for Logs, Workspace ONE Access), waiting for each request; '
                   'deletes older acme certificates from the Locker.')
    doc = 'targets.md'
    fields = http_fields(443, 'lcm.example.local') + [
        field('user', 'User', 'text', required=True, default='admin@local',
              help='admin@local, or a user with only the role Certificate Administrator'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('products', 'Products', 'list', placeholder='<environment id> vrops',
              help='one a line: the environment id and the product id (vrops, vra, vrli, vidm '
                   '...) as Suite Lifecycle names them; empty: only into the Locker'),
        field('root_pem', 'Root CA certificate', 'pem', advanced=True,
              help='the root, after the intermediates (Suite Lifecycle wants the whole chain); '
                   'empty: the chain as it is'),
        field('prevalidate', 'Pre-validate first', 'bool', default=True, advanced=True),
        field('wait_minutes', 'Wait for each request (minutes)', 'number', default=60,
              advanced=True, help='0: start the request and go on'),
        keep_field(1),
    ] + verify_fields()

    def auth_headers(self):
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()}

    def locker(self):
        st, hd, d = self.req('GET', LOCKER, what='listing the Locker')
        return _list(d)

    def test(self):
        n = len(self.locker())
        return 'signed in to Aria Suite Lifecycle %s; %d certificate%s in the Locker' % (
            self.c('host'), n, '' if n == 1 else 's')

    @staticmethod
    def products(options):
        out = []
        for line in lines(options.get('products')):
            parts = line.replace(',', ' ').replace('/', ' ').split()
            if len(parts) != 2:
                raise PluginError('the product line "%s" is "<environment id> <product id>"'
                                  % line, retry=False)
            out.append((parts[0], parts[1]))
        return out

    def chain(self, bundle, options):
        root = V.root_of(bundle, options.get('root_pem'))
        pems = [text(bundle.as_format('cert-pem'))] + V.intermediates(bundle) + \
            ([root] if root else [])
        return ''.join(p.strip() + '\n' for p in pems)

    def deploy(self, bundle, options):
        options = options or {}
        prods = self.products(options)
        alias = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        have = self.locker()
        mine = [c for c in have if text(c.get('alias')) == alias]
        if self.unchanged(bundle, options, present=lambda: bool(mine)):
            return self.same(bundle, 'as %s' % alias)
        if not mine:
            self.req('POST', LOCKER + '/import', {
                'alias': alias, 'certificateChain': self.chain(bundle, options),
                'privateKey': text(bundle.as_format('key-pem')), 'passphrase': ''},
                what='importing %s into the Locker' % alias)
            self.ctx.step('imported %s into the Locker' % alias, 'ok')
            mine = [c for c in self.locker() if text(c.get('alias')) == alias]
        else:
            self.ctx.step('%s is in the Locker already' % alias)
        vmid = text((mine[0] if mine else {}).get('vmid'))
        if not vmid:
            raise PluginError('the Locker does not list %s after the import' % alias,
                              retry=True)
        did = ['Locker %s' % alias]
        for env, prod in prods:
            base = '/lcm/lcops/api/v2/environments/%s/products/%s/certificates/%s' % (
                q(env), q(prod), q(vmid))
            if as_bool(self.opt(options, 'prevalidate', True), True):
                self.req('POST', base + '/pre-validate', {},
                         what='pre-validating %s for %s' % (alias, prod))
                self.ctx.step('%s: the pre-validation passed' % prod, 'ok')
            st, hd, d = self.req('PUT', base, {}, what='replacing the certificate of %s' % prod)
            rid = text((d or {}).get('requestId') if isinstance(d, dict) else '')
            self.ctx.step('%s: Replace Certificate started%s' % (
                prod, ' (request %s)' % rid if rid else ''), 'ok')
            wait = as_int(self.opt(options, 'wait_minutes', 60), 60)
            if rid and wait > 0:
                V.wait_task(self, lambda: self.req('GET', '/lcm/request/api/v2/requests/%s'
                                                   % q(rid), what='reading the request')[2],
                            done=lambda r: _state(r) in ('COMPLETED', 'SUCCESS', 'SUCCEEDED'),
                            failed=lambda r: _state(r) in ('FAILED', 'ERROR', 'CANCELLED'),
                            tries=max(1, wait * 2), every=30.0,
                            what='the request %s (%s)' % (rid, prod))
                self.ctx.step('%s uses %s' % (prod, alias), 'ok')
            did.append(prod)
        self.cleanup(prefix, alias, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did)

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            byname = {text(c.get('alias')): c for c in self.locker()}
        except PluginError as e:
            self.ctx.step('the Locker cannot be listed: %s' % e, 'warn')
            return
        for old in prune(list(byname), prefix, keep, current):
            try:
                self.req('DELETE', '%s/%s' % (LOCKER, q(byname[old].get('vmid'))),
                         what='deleting %s from the Locker' % old)
                self.ctx.step('deleted the older %s from the Locker' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays in the Locker (still used?): %s' % (old, e),
                              'warn')
