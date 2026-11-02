# -*- coding: utf-8 -*-
"""
bunny.net CDN: the certificate put on the custom hostnames of a pull zone
(its own certificate instead of bunny's free one).

    https://api.bunny.net, header AccessKey: <the account's API key>
    GET  /pullzone/<id>                 the pull zone and its Hostnames
    GET  /pullzone?search=NAME          a pull zone found by its name ({"Items": [...]})
    POST /pullzone/<id>/addCertificate  {"Hostname", "Certificate": base64(full chain PEM),
                                         "CertificateKey": base64(key PEM)}

bunny keeps one certificate a hostname: a new one takes the place of the one
before, nothing is left to clean up.

Source (bunny.net's official Terraform provider):
    https://github.com/BunnyWay/terraform-provider-bunnynet/blob/main/internal/api/pullzone_hostname.go
    https://github.com/BunnyWay/terraform-provider-bunnynet/blob/main/internal/api/pullzone.go
    https://github.com/BunnyWay/terraform-provider-bunnynet/blob/main/internal/api/client.go
"""
from __future__ import annotations

import base64
import urllib.parse

from acmelib.plugins.targets._common import (
    PluginError, field, lines, text, verify_fields, covers)
from acmelib.plugins.targets._cloud import CloudTarget, cloud_fields

API = 'https://api.bunny.net'


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


class BunnyTarget(CloudTarget):
    kind = 'bunny'
    title = 'bunny.net CDN (pull zone hostnames)'
    vendor = 'bunny.net'
    description = ('Puts the certificate on the custom hostnames of a bunny.net pull zone '
                   'through the bunny.net API.')
    doc = 'targets.md'
    fields = [
        field('api_key', 'API key', 'secret', required=True,
              help='bunny.net dashboard → Account settings → API key'),
    ] + cloud_fields()
    deploy_fields = [
        field('pull_zone', 'Pull zone', 'text', required=True, placeholder='www-example',
              help='its name or ID; "List the pull zones" shows them'),
        field('hostnames', 'Hostnames', 'list', placeholder='cdn.example.com',
              help='one a line: the custom hostnames of the pull zone to get the '
                   'certificate; empty: each of them the certificate covers'),
    ] + verify_fields()
    actions = [{'key': 'look', 'label': 'List the pull zones',
                'help': 'Lists the pull zones and their hostnames, with whether each has a '
                        'certificate - it changes nothing.',
                'changes': False}]

    def auth_headers(self):
        return {'AccessKey': self.c('api_key') or ''}

    def api(self, method, path, body=None, ok=None, what=None):
        st, hd, d = self.req(method, API + path, body, ok=ok, what=what)
        return st, d

    def test(self):
        st, d = self.api('GET', '/pullzone?search=', what='signing in')
        items = (d.get('Items') if isinstance(d, dict) else d) or []
        return 'signed in to bunny.net; %d pull zone%s' % (len(items),
                                                           '' if len(items) == 1 else 's')

    def zone(self, ref):
        ref = text(ref).strip()
        if not ref:
            raise PluginError('no pull zone is set', retry=False)
        if ref.isdigit():
            st, d = self.api('GET', '/pullzone/%s' % ref, ok=(200, 404),
                             what='reading the pull zone %s' % ref)
            if st == 200 and isinstance(d, dict):
                return d
        st, d = self.api('GET', '/pullzone?search=%s' % urllib.parse.quote(ref),
                         what='looking for the pull zone %s' % ref)
        items = (d.get('Items') if isinstance(d, dict) else d) or []
        got = [z for z in items if isinstance(z, dict) and text(z.get('Name')) == ref]
        if not got:
            raise PluginError('there is no pull zone "%s" in this account' % ref, retry=False)
        return got[0]

    def deploy(self, bundle, options):
        options = options or {}
        if self.unchanged(bundle, options):
            return self.same(bundle, 'on the pull zone')
        z = self.zone(options.get('pull_zone'))
        zid = z.get('Id')
        custom = [h for h in z.get('Hostnames') or []
                  if isinstance(h, dict) and not h.get('IsSystemHostname')]
        have = [text(h.get('Value')) for h in custom]
        want = lines(options.get('hostnames'))
        if want:
            missing = [h for h in want if h.lower() not in [x.lower() for x in have]]
            if missing:
                raise PluginError('the pull zone %s has no hostname %s (add it there first)'
                                  % (z.get('Name'), ', '.join(missing)), retry=False)
        else:
            want = [h for h in have if covers(bundle.names, h)]
            if not want:
                raise PluginError('the certificate covers none of the hostnames of the pull '
                                  'zone %s (%s)' % (z.get('Name'), ', '.join(have) or 'none'),
                                  retry=False)
        cert = b64(bundle.as_format('fullchain-pem'))
        key = b64(bundle.as_format('key-pem'))
        for h in want:
            self.api('POST', '/pullzone/%s/addCertificate' % zid,
                     {'Hostname': h, 'Certificate': cert, 'CertificateKey': key},
                     what='putting the certificate on %s' % h)
            self.ctx.step('%s has the certificate' % h, 'ok')
        self.remember(bundle, options)
        return 'pull zone %s: %s' % (z.get('Name'), ', '.join(want))

    def action(self, key):
        if key != 'look':
            return CloudTarget.action(self, key)
        st, d = self.api('GET', '/pullzone?search=', what='listing the pull zones')
        items = (d.get('Items') if isinstance(d, dict) else d) or []
        for z in items:
            hosts = ['%s%s' % (h.get('Value'), ' (certificate)' if h.get('HasCertificate')
                               else '') for h in z.get('Hostnames') or []
                     if isinstance(h, dict) and not h.get('IsSystemHostname')]
            self.ctx.step('%s (ID %s): %s' % (z.get('Name'), z.get('Id'),
                                              ', '.join(hosts) or 'no custom hostname'))
        return '%d pull zone%s' % (len(items), '' if len(items) == 1 else 's')
