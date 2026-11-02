# -*- coding: utf-8 -*-
"""
DigitalOcean Load Balancer: the certificate uploaded as a "custom" certificate
under a dated name, the HTTPS forwarding rules of the load balancers asked for
pointed at it, older acme ones deleted.

    https://api.digitalocean.com, Authorization: Bearer <personal access token>
    GET    /v2/certificates?name=NAME                 there already?
    POST   /v2/certificates  {"name", "type": "custom", "private_key",
                              "leaf_certificate", "certificate_chain"}
    GET    /v2/load_balancers/<id>  |  /v2/load_balancers?page=N&per_page=200
    PUT    /v2/load_balancers/<id>   the load balancer as it is (what godo's
                                     LoadBalancer.AsRequest() sends), the
                                     rules' certificate_id changed
    GET    /v2/certificates?page=N&per_page=200       the older ones
    DELETE /v2/certificates/<id>

Sources (DigitalOcean's official Go library, which doctl is made of):
    https://github.com/digitalocean/godo/blob/main/certificates.go
    https://github.com/digitalocean/godo/blob/main/load_balancers.go   (AsRequest, ForwardingRule)
    https://github.com/digitalocean/godo/blob/main/godo.go             (base URL, paging)
"""
from __future__ import annotations

import re
import urllib.parse

from acmelib.plugins.targets._common import (
    PluginError, field, lines, as_int, object_name, name_prefix, prune, text,
    verify_fields, keep_field)
from acmelib.plugins.targets._cloud import CloudTarget, cloud_fields

API = 'https://api.digitalocean.com'
HTTPS = ('https', 'http2', 'http3')
# What LoadBalancer.AsRequest() of godo copies into an update (region as its slug).
REQUEST_KEYS = ('name', 'algorithm', 'size', 'size_unit', 'type', 'forwarding_rules',
                'droplet_ids', 'tag', 'redirect_http_to_https', 'enable_proxy_protocol',
                'enable_backend_keepalive', 'vpc_uuid', 'subnet_uuid',
                'disable_lets_encrypt_dns_records', 'project_id', 'http_idle_timeout_seconds',
                'target_load_balancer_ids', 'network', 'network_stack', 'tls_cipher_policy',
                'health_check', 'sticky_sessions', 'firewall', 'domains', 'glb_settings')


def as_request(lb):
    out = {k: lb[k] for k in REQUEST_KEYS if k in lb and lb[k] not in (None, '', [])}
    reg = lb.get('region')
    if isinstance(reg, dict) and reg.get('slug'):
        out['region'] = reg['slug']
    elif isinstance(reg, str) and reg:
        out['region'] = reg
    return out


class DigitalOceanLbTarget(CloudTarget):
    kind = 'digitalocean_lb'
    title = 'DigitalOcean Load Balancer'
    vendor = 'DigitalOcean'
    description = ('Uploads the certificate to DigitalOcean and puts it on the HTTPS '
                   'forwarding rules of the load balancers in place of the older one.')
    doc = 'targets.md'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='DigitalOcean → API → Personal access tokens: a token with the scopes '
                   'certificate (create, read, delete) and load_balancer (read, update)'),
    ] + cloud_fields()
    deploy_fields = [
        field('load_balancers', 'Load balancers', 'list', placeholder='lb-www',
              help='one a line: the name or ID of each load balancer; "List the load '
                   'balancers" shows them'),
        field('ports', 'Entry ports', 'list', placeholder='443',
              help='one a line: the HTTPS forwarding rules (by their entry port) to use the '
                   'certificate; empty: every HTTPS rule that is not TLS passthrough'),
        keep_field(1),
    ] + verify_fields()
    actions = [{'key': 'look', 'label': 'List the load balancers',
                'help': 'Lists the load balancers and their HTTPS forwarding rules, with the '
                        'certificates each uses - it changes nothing.',
                'changes': False}]

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.c('token')}

    def api(self, method, path, body=None, ok=None, what=None):
        st, hd, d = self.req(method, API + path, body, ok=ok, what=what)
        return st, (d if isinstance(d, dict) else {})

    def test(self):
        st, d = self.api('GET', '/v2/load_balancers?per_page=200', what='signing in')
        n = len(d.get('load_balancers') or [])
        return 'signed in to DigitalOcean; %d load balancer%s' % (n, '' if n == 1 else 's')

    def paged(self, path, key):
        out, page = [], 1
        while page and page < 50:
            st, d = self.api('GET', '%s?page=%d&per_page=200' % (path, page),
                             what='listing %s' % key.replace('_', ' '))
            out += [x for x in d.get(key) or [] if isinstance(x, dict)]
            nxt = (((d.get('links') or {}).get('pages') or {}).get('next'))
            page = page + 1 if nxt else 0
        return out

    def by_name(self, name):
        st, d = self.api('GET', '/v2/certificates?name=%s' % urllib.parse.quote(name),
                         what='looking for %s' % name)
        got = [c for c in d.get('certificates') or [] if c.get('name') == name]
        return got[0] if got else None

    def lb(self, ref):
        ref = text(ref).strip()
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-', ref):
            st, d = self.api('GET', '/v2/load_balancers/%s' % ref, ok=(200, 404),
                             what='reading the load balancer %s' % ref)
            if st == 200 and d.get('load_balancer'):
                return d['load_balancer']
        got = [x for x in self.paged('/v2/load_balancers', 'load_balancers')
               if x.get('name') == ref or x.get('id') == ref]
        if not got:
            raise PluginError('there is no load balancer "%s" in this account' % ref,
                              retry=False)
        return got[0]

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=63)
        prefix = name_prefix(bundle, options, maxlen=63)
        cur = self.by_name(name)
        if self.unchanged(bundle, options, present=lambda: cur is not None):
            return self.same(bundle, 'as %s' % name)
        did = []
        if cur is not None:
            self.ctx.step('%s is at DigitalOcean already (%s)' % (name, cur.get('id')))
        else:
            st, d = self.api('POST', '/v2/certificates', {
                'name': name, 'type': 'custom',
                'private_key': text(bundle.as_format('key-pem')),
                'leaf_certificate': text(bundle.as_format('cert-pem')),
                'certificate_chain': text(bundle.as_format('chain-pem'))},
                what='uploading %s' % name)
            cur = d.get('certificate') or {}
            if not cur.get('id'):
                raise PluginError('DigitalOcean gave no id for %s' % name, detail=text(d))
            self.ctx.step('uploaded %s (%s)' % (name, cur['id']), 'ok')
            did.append('uploaded %s' % name)
        new_id = cur['id']
        lbs = lines(options.get('load_balancers'))
        ports = set(as_int(p, -1) for p in lines(options.get('ports')))
        for ref in lbs:
            lb = self.lb(ref)
            rules, changed, used = [], [], 0
            for r in lb.get('forwarding_rules') or []:
                r = dict(r)
                port = as_int(r.get('entry_port'), 0)
                if text(r.get('entry_protocol')) in HTTPS and not r.get('tls_passthrough') \
                        and (not ports or port in ports):
                    used += 1
                    if r.get('certificate_id') != new_id:
                        r['certificate_id'] = new_id        # one certificate a rule
                        changed.append(port)
                rules.append(r)
            if not used:
                raise PluginError('the load balancer %s has no HTTPS forwarding rule%s' % (
                    lb.get('name'), ' on %s' % ', '.join(map(str, sorted(ports)))
                    if ports else ''), retry=False)
            if not changed:
                self.ctx.step('%s uses %s already' % (lb.get('name'), name))
                continue
            body = as_request(lb)
            body['forwarding_rules'] = rules
            self.api('PUT', '/v2/load_balancers/%s' % lb['id'], body,
                     what='updating the load balancer %s' % lb.get('name'))
            for port in changed:
                self.ctx.step('%s:%d uses %s' % (lb.get('name'), port, name), 'ok')
                did.append('%s:%d' % (lb.get('name'), port))
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options, id=new_id)
        return ', '.join(did) or 'already %s' % name

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            certs = self.paged('/v2/certificates', 'certificates')
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        byname = {text(c.get('name')): c for c in certs}
        for old in prune(list(byname), prefix, keep, current):
            try:
                self.api('DELETE', '/v2/certificates/%s' % byname[old]['id'],
                         what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays (still used?): %s' % (old, e), 'warn')

    def action(self, key):
        if key != 'look':
            return CloudTarget.action(self, key)
        certs = {c['id']: c.get('name') for c in self.paged('/v2/certificates', 'certificates')}
        lbs = self.paged('/v2/load_balancers', 'load_balancers')
        for lb in lbs:
            https = ['%s → %s' % (r.get('entry_port'), certs.get(r.get('certificate_id'),
                                                              r.get('certificate_id')) or '-')
                     for r in lb.get('forwarding_rules') or []
                     if text(r.get('entry_protocol')) in HTTPS and not r.get('tls_passthrough')]
            self.ctx.step('%s (ID %s): %s' % (lb.get('name'), lb.get('id'),
                                              '; '.join(https) or 'no HTTPS rule'))
        return '%d load balancer%s' % (len(lbs), '' if len(lbs) == 1 else 's')
