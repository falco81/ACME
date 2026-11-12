# -*- coding: utf-8 -*-
"""
VMware NSX Manager - its own HTTPS certificate (the UI and API of the manager nodes, the
cluster's virtual IP) through the NSX Manager API (MP API), NSX 4.2 - 9.1. The "nsx" target
is another thing: the load balancer's virtual servers (Policy API, service certificates).

    https://<nsx-manager>, HTTP basic authentication
    GET  /api/v1/trust-management/certificates                    the certificates there
    POST /api/v1/trust-management/certificates?action=import      {"display_name",
          "pem_encoded" (leaf, intermediates, root), "private_key"} -> {"results": [{"id"}]}
    GET  /api/v1/trust-management/certificates/<id>?action=validate&usage=SERVER -> {"status"}
    POST /api/v1/trust-management/certificates/<id>?action=apply_certificate&service_type=API
          &node_id=<node uuid>                                     each node chosen
    POST /api/v1/trust-management/certificates/<id>?action=apply_certificate
          &service_type=MGMT_CLUSTER                               the cluster's virtual IP
    DELETE /api/v1/trust-management/certificates/<id>              older acme ones nothing uses
                                                                   (their "used_by" empty)

The same calls in NSX 4.2.x and 9.0 / 9.1 (one module): from 4.2 the nodes' API certificate
and the VIP's are one and the same by default - both can be given the new one here. A node's
HTTPS restarts when the certificate is applied (tens of seconds): acme asks again a few times.

Sources: navody/certifikaty/vmware/nsx.md (2026-11) - NSX 4.2 "Replace Certificates Through
API", API reference AddCertificate / ImportCertificate / ValidateCertificate / ApplyCertificate
(4.2, 9.0.2), KB 421552, KB 414001, KB 416689 (Service Certificate = No for the platform: the
MP import is not a service certificate), KB 400892 (the private key with it).
Rights: Enterprise Admin; Security Admin (security_engineer) has full access to System >
Certificates in the RBAC matrix, but the guide says "admin privileges" for applying - try it.
Less certain: the node ids are typed (System > Appliances > View Details, or "get cluster
status" in the NSX CLI); used_by as the sign of a certificate in use.
"""
from __future__ import annotations

import base64
import time
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, text, object_name, name_prefix, ours, prune,
    http_fields, tls_fields, verify_fields, keep_field, as_int)
from acmelib.plugins.targets import _vmware as V

TM = '/api/v1/trust-management/certificates'


def q(s):
    return urllib.parse.quote(text(s), safe='')


class NsxManagerTarget(HttpTarget):
    kind = 'nsx_manager'
    title = 'VMware NSX Manager (its own certificate)'
    vendor = 'VMware'
    discovery = False
    description = ('NSX 4.2 - 9.1: imports the certificate into NSX Manager (trust management, '
                   'not a service certificate), validates it and applies it to the API of the '
                   'manager nodes and/or the cluster\'s virtual IP; deletes older acme ones '
                   'nothing uses.')
    doc = 'targets.md'
    fields = http_fields(443, 'nsx-mgr01.example.local') + [
        field('user', 'User', 'text', required=True, default='admin',
              help='Enterprise Admin, or Security Admin (security_engineer)'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('vip', 'The cluster\'s virtual IP (MGMT_CLUSTER)', 'bool', default=True,
              help='apply_certificate service_type=MGMT_CLUSTER - a virtual IP must be set'),
        field('node_ids', 'Manager nodes (API)', 'list',
              placeholder='a1b2c3d4-0000-0000-0000-000000000001',
              help='one a line: the UUIDs of the manager nodes whose own API/UI takes it '
                   '(System > Appliances > View Details, or "get cluster status")'),
        field('root_pem', 'Root CA certificate', 'pem', advanced=True,
              help='the root, put after the intermediates (NSX wants leaf, intermediates, root); '
                   'empty: the chain as it is'),
        keep_field(1),
    ] + verify_fields()

    def auth_headers(self):
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()}

    def api(self, method, path, body=None, ok=None, what=None, timeout=None):
        st, hd, d = self.req(method, path, body, ok=ok, what=what, timeout=timeout)
        return st, (d if isinstance(d, dict) else {})

    def certs(self):
        out, cursor = [], None
        for _i in range(100):
            st, d = self.api('GET', TM + ('?cursor=%s' % q(cursor) if cursor else ''),
                             what='listing the certificates')
            out += [x for x in d.get('results') or [] if isinstance(x, dict)]
            cursor = d.get('cursor')
            if not cursor:
                break
        return out

    def test(self):
        cs = self.certs()
        return 'signed in to NSX Manager %s; %d certificate%s' % (
            self.c('host'), len(cs), '' if len(cs) == 1 else 's')

    def pem_chain(self, bundle, options):
        root = V.root_of(bundle, options.get('root_pem'))
        pems = [text(bundle.as_format('cert-pem'))] + V.intermediates(bundle) + \
            ([root] if root else [])
        # no empty lines, leaf - intermediates - root (KB 414001)
        return ''.join(p.strip() + '\n' for p in pems)

    def apply(self, cid, service, node=None):
        p = '%s/%s?action=apply_certificate&service_type=%s' % (TM, q(cid), service)
        if node:
            p += '&node_id=%s' % q(node)
        what = 'applying it to %s' % ('the node %s' % node if node else 'the virtual IP')
        sleep = getattr(self, '_sleep', time.sleep)
        for i in range(4):
            try:
                self.api('POST', p, what=what, timeout=120)
                return
            except PluginError as e:
                # the node's HTTPS restarting after the one before: asked again a little later
                if 'cannot be reached' not in str(e) and 'said 503' not in str(e) or i == 3:
                    raise
                self.ctx.step('NSX Manager is restarting its web service - asking again', 'info')
                sleep(15)

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        nodes = lines(options.get('node_ids'))
        vip = as_bool(self.opt(options, 'vip', True), True)
        if not nodes and not vip:
            raise PluginError('nothing to apply it to: tick the virtual IP or give the manager '
                              'nodes', retry=False)
        have = self.certs()
        mine = [c for c in have if text(c.get('display_name')) == name]
        if self.unchanged(bundle, options, present=lambda: bool(mine)):
            return self.same(bundle, 'as %s' % name)
        if mine:
            cid = text(mine[0].get('id'))
            self.ctx.step('the certificate %s is in NSX already' % name)
        else:
            st, d = self.api('POST', TM + '?action=import', {
                'display_name': name, 'pem_encoded': self.pem_chain(bundle, options),
                'private_key': text(bundle.as_format('key-pem'))}, what='importing %s' % name)
            res = d.get('results') or []
            cid = text(res[0].get('id')) if res and isinstance(res[0], dict) else ''
            if not cid:
                raise PluginError('NSX gave no id for the imported certificate', detail=text(d))
            self.ctx.step('imported %s (%s)' % (name, cid), 'ok')
        st, d = self.api('GET', '%s/%s?action=validate&usage=SERVER' % (TM, q(cid)),
                         what='validating %s' % name)
        if text(d.get('status')).upper() != 'OK':
            raise PluginError('NSX does not take %s as a server certificate: %s' % (
                name, d.get('error_message') or d.get('status') or '?'), detail=text(d),
                retry=False)
        self.ctx.step('NSX validated it (usage SERVER)', 'ok')
        did = []
        for n in nodes:
            self.apply(cid, 'API', n)
            self.ctx.step('the node %s serves it' % n, 'ok')
            did.append('node %s' % n)
        if vip:
            self.apply(cid, 'MGMT_CLUSTER')
            self.ctx.step('the virtual IP serves it', 'ok')
            did.append('virtual IP')
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options)
        return '%s applied to %s' % (name, ', '.join(did))

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            listed = self.certs()
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        byname = {text(c.get('display_name')): c for c in listed
                  if ours(text(c.get('display_name')), prefix)}
        for old in prune(list(byname), prefix, keep, current):
            c = byname[old]
            if c.get('used_by'):
                self.ctx.step('the older %s stays: NSX still uses it' % old, 'warn')
                continue
            try:
                self.api('DELETE', '%s/%s' % (TM, q(c.get('id'))), what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')

    served_wait = (8, 10)

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []
