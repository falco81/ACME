# -*- coding: utf-8 -*-
"""
Hetzner Cloud Load Balancer: the certificate uploaded to the project (type
"uploaded") under a dated name, the HTTPS services of the load balancers
asked for pointed at it in place of the older acme one, older ones deleted.

    https://api.hetzner.cloud/v1, Authorization: Bearer <API token of the project>
    GET    /certificates?name=NAME                    there already?
    POST   /certificates  {"name", "type": "uploaded", "certificate", "private_key", "labels"}
    GET    /load_balancers/<id>  |  /load_balancers?name=NAME
    POST   /load_balancers/<id>/actions/update_service
                          {"listen_port", "http": {"certificates": [ids]}}
    GET    /load_balancers/actions/<id>               until "success" (or "error")
    GET    /certificates?page=N&per_page=50           the older ones
    DELETE /certificates/<id>

Sources (Hetzner's official Go library, which the hcloud CLI is made of):
    https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/certificate.go
    https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/schema/certificate.go
    https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/load_balancer.go
    https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/schema/load_balancer.go
    https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/action.go
    https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/client.go   (Bearer, paging)
"""
from __future__ import annotations

import time
import urllib.parse

from acmelib.plugins.targets._common import (
    ours,
    PluginError, field, lines, as_bool, as_int, object_name, name_prefix, prune, text,
    verify_fields, keep_field)
from acmelib.plugins.targets._cloud import CloudTarget, cloud_fields

API = 'https://api.hetzner.cloud/v1'


class HetznerLbTarget(CloudTarget):
    kind = 'hetzner_lb'
    discovery = False       # nothing to find: its only field is the sign-in
    title = 'Hetzner Cloud Load Balancer'
    vendor = 'Hetzner'
    description = ('Uploads the certificate to a Hetzner Cloud project and puts it on the '
                   'HTTPS services of its load balancers in place of the older one.')
    doc = 'targets.md'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='Hetzner Console → the project → Security → API tokens: a token with '
                   'Read & Write'),
    ] + cloud_fields()
    deploy_fields = [
        field('load_balancers', 'Load balancers', 'list', placeholder='lb-www',
              help='one a line: the name or ID of each load balancer; "List the load '
                   'balancers" shows them'),
        field('ports', 'Listen ports', 'list', placeholder='443',
              help='one a line: the HTTPS services (by their listen port) to use the '
                   'certificate; empty: every HTTPS service of the load balancer'),
        field('replace_all', 'Replace every certificate of the service', 'bool', default=False,
              help='off: only the older acme one of this certificate is replaced, others stay '
                   '(a service holds several, chosen by SNI); on: the service holds this one '
                   'only'),
        keep_field(1),
    ] + verify_fields()
    actions = [{'key': 'look', 'label': 'List the load balancers',
                'help': 'Lists the load balancers of the project and their HTTPS services, '
                        'with the certificates each uses - it changes nothing.',
                'changes': False}]

    _sleep = staticmethod(time.sleep)

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.c('token')}

    def api(self, method, path, body=None, ok=None, what=None):
        st, hd, d = self.req(method, API + path, body, ok=ok, what=what)
        return st, (d if isinstance(d, (dict, list)) else {})

    def test(self):
        st, d = self.api('GET', '/load_balancers?per_page=50', what='signing in')
        n = len(d.get('load_balancers') or [])
        return 'signed in to the Hetzner Cloud project; %d load balancer%s' % (
            n, '' if n == 1 else 's')

    # -- what is there ----------------------------------------------------------------------
    def paged(self, path, key):
        out, page = [], 1
        while page and page < 100:
            sep = '&' if '?' in path else '?'
            st, d = self.api('GET', '%s%spage=%d&per_page=50' % (path, sep, page),
                             what='listing %s' % key.replace('_', ' '))
            out += [x for x in d.get(key) or [] if isinstance(x, dict)]
            page = as_int((((d.get('meta') or {}).get('pagination') or {}).get('next_page')),
                          0)
        return out

    def by_name(self, name):
        st, d = self.api('GET', '/certificates?name=%s' % urllib.parse.quote(name),
                         what='looking for %s' % name)
        got = [c for c in d.get('certificates') or [] if c.get('name') == name]
        return got[0] if got else None

    def lb(self, ref):
        ref = text(ref).strip()
        if ref.isdigit():
            st, d = self.api('GET', '/load_balancers/%s' % ref, ok=(200, 404),
                             what='reading the load balancer %s' % ref)
            if st == 200 and d.get('load_balancer'):
                return d['load_balancer']
        st, d = self.api('GET', '/load_balancers?name=%s' % urllib.parse.quote(ref),
                         what='looking for the load balancer %s' % ref)
        got = [x for x in d.get('load_balancers') or [] if x.get('name') == ref]
        if not got:
            raise PluginError('there is no load balancer "%s" in this project' % ref,
                              retry=False)
        return got[0]

    def wait(self, action, what):
        a = action or {}
        end = time.time() + 120
        while text(a.get('status')) == 'running':
            if self.ctx.cancelled() or time.time() > end:
                raise PluginError('%s has not finished in 120 s' % what)
            self._sleep(2)
            st, d = self.api('GET', '/load_balancers/actions/%s' % a.get('id'),
                             what='asking how %s goes' % what)
            a = d.get('action') or {}
        if text(a.get('status')) == 'error':
            err = a.get('error') or {}
            raise PluginError('%s failed: %s' % (what, err.get('message') or err.get('code')
                                                 or 'error'), detail=text(a))

    # -- the work ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=63)
        prefix = name_prefix(bundle, options, maxlen=63)
        cur = self.by_name(name)
        lbs = lines(options.get('load_balancers'))
        if self.unchanged(bundle, options, present=lambda: cur is not None):
            return self.same(bundle, 'as %s' % name)
        did = []
        if cur is not None:
            # (a name is unique in a project: the one there is this very certificate)
            self.ctx.step('%s is in the project already (%s)' % (name, cur.get('id')))
        else:
            st, d = self.api('POST', '/certificates', {
                'name': name, 'type': 'uploaded',
                'certificate': text(bundle.as_format('fullchain-pem')),
                'private_key': text(bundle.as_format('key-pem')),
                'labels': {'managed-by': 'acme'}}, what='uploading %s' % name)
            cur = d.get('certificate') or {}
            if not cur.get('id'):
                raise PluginError('Hetzner gave no id for %s' % name, detail=text(d))
            self.ctx.step('uploaded %s (%s)' % (name, cur['id']), 'ok')
            did.append('uploaded %s' % name)
        new_id = cur['id']
        mine = set()
        if lbs:
            mine = set(c['id'] for c in self.paged('/certificates', 'certificates')
                       if ours(c.get('name'), prefix) and c.get('id') != new_id)
        ports = set(as_int(p, -1) for p in lines(options.get('ports')))
        for ref in lbs:
            lb = self.lb(ref)
            used = 0
            for svc in lb.get('services') or []:
                if text(svc.get('protocol')) != 'https':
                    continue
                port = as_int(svc.get('listen_port'), 0)
                if ports and port not in ports:
                    continue
                used += 1
                have = list((svc.get('http') or {}).get('certificates') or [])
                want = [] if as_bool(options.get('replace_all')) else \
                    [c for c in have if c not in mine and c != new_id]
                want.append(new_id)
                if have == want:
                    self.ctx.step('%s:%d uses %s already' % (lb.get('name'), port, name))
                    continue
                st, d = self.api('POST', '/load_balancers/%s/actions/update_service' % lb['id'],
                                 {'listen_port': port, 'http': {'certificates': want}},
                                 what='updating %s:%d' % (lb.get('name'), port))
                self.wait(d.get('action'), 'updating %s:%d' % (lb.get('name'), port))
                self.ctx.step('%s:%d uses %s' % (lb.get('name'), port, name), 'ok')
                did.append('%s:%d' % (lb.get('name'), port))
            if not used:
                raise PluginError('the load balancer %s has no HTTPS service%s' % (
                    lb.get('name'), ' on %s' % ', '.join(map(str, sorted(ports)))
                    if ports else ''), retry=False)
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options, id=new_id)
        return ', '.join(did) or 'already %s' % name

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            certs = self.paged('/certificates', 'certificates')
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        byname = {text(c.get('name')): c for c in certs}
        for old in prune(list(byname), prefix, keep, current):
            c = byname[old]
            if c.get('used_by'):
                self.ctx.step('the older %s stays: a load balancer still uses it' % old, 'warn')
                continue
            try:
                self.api('DELETE', '/certificates/%s' % c['id'], what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')

    def action(self, key):
        if key != 'look':
            return CloudTarget.action(self, key)
        certs = {c['id']: c.get('name') for c in self.paged('/certificates', 'certificates')}
        lbs = self.paged('/load_balancers', 'load_balancers')
        for lb in lbs:
            https = ['%s → %s' % (s.get('listen_port'), ', '.join(
                text(certs.get(i, i)) for i in (s.get('http') or {}).get('certificates') or [])
                or '-') for s in lb.get('services') or [] if s.get('protocol') == 'https']
            self.ctx.step('%s (ID %s): %s' % (lb.get('name'), lb.get('id'),
                                              '; '.join(https) or 'no HTTPS service'))
        return '%d load balancer%s' % (len(lbs), '' if len(lbs) == 1 else 's')
