# -*- coding: utf-8 -*-
"""
Infoblox NIOS (Grid Manager, WAPI): the certificate, its chain and its key uploaded as
the HTTPS certificate of each Grid member asked for (the Grid Manager / WAPI of the Grid
Master, a Grid Master Candidate, a member's DoT/DoH and HTTPS) - or as its Captive Portal
certificate - through WAPI's fileop. NIOS replaces the member's certificate and restarts
its web server (the administrators are signed out); nothing is left to delete.

    https://<grid-master>/wapi/v<version>/   HTTP basic on every request
    GET  grid                                                  signing in (test)
    POST fileop?_function=uploadinit  {"filename"}         -> {"token", "url"}
    POST <url>   multipart: file = one PEM: the certificate, the chain, the key (unencrypted)
    POST fileop?_function=uploadcertificate
         {"certificate_usage": "ADMIN" | "CAPTIVE_PORTAL", "member": "<fqdn>", "token"}  -> {}

The url uploadinit gives may name the Grid Master by an address acme does not reach (NAT):
its path is sent to the address of the target, as Infoblox-PS's ibx-sdk does.

Checked against the vendor guide of 2026-11 (infoblox.md: "Managing Certificates",
"Uploading HTTPS Certificates", "Uploading CA Certificates" and "About Admin Groups" of
NIOS 9.0 / 8.6, the on-box WAPI 2.13.7 reference of fileop as published by a NIOS
installation, and the source of Infoblox-PS ibx-sdk 0.8.1 - upload_certificate()). The
calls are the same in NIOS 8.6, 9.0 and 9.1; WAPI is versioned apart from NIOS and keeps
its older versions, so one WAPI version (2.11, ibx-sdk's default) serves them all.

Less certain (the guide's "unverified" points):
    - which limited-access admin group may upload a member's HTTPS certificate (the guide
      advises a superuser group allowed only the API);
    - the multipart part's name "file" (the curl samples and ibx-sdk);
    - what NIOS does to an HA pair's two nodes and to a Grid Master Candidate after a
      promotion - list every member that should serve it;
    - that only the web server restarts (DNS/DHCP untouched): the documents say only that
      the administrator is signed out.
"""
from __future__ import annotations

import base64
import re
import time
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, text, multipart,
    http_fields, tls_fields, verify_fields)

USAGES = ('ADMIN', 'CAPTIVE_PORTAL')


class InfobloxTarget(HttpTarget):
    kind = 'infoblox'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Infoblox NIOS (WAPI)'
    vendor = 'Infoblox'
    description = ('Uploads the certificate with its chain and key as the HTTPS certificate '
                   '(Grid Manager, WAPI, DoT/DoH) or the Captive Portal certificate of Grid '
                   'members through WAPI (fileop uploadcertificate). NIOS 8.6, 9.0 and 9.1.')
    doc = 'targets.md'
    fields = http_fields(443, 'gm.example.local') + [
        field('user', 'User', 'text', required=True, default='svc-cert',
              help='an admin of a group allowed the API (API - WAPI/PAPI only)'),
        field('password', 'Password', 'secret', required=True),
        field('wapi_version', 'WAPI version', 'text', default='2.11', advanced=True,
              help='2.11 is in NIOS 8.6 - 9.1; a newer one (2.13.7 on NIOS 9.0) works too'),
    ] + tls_fields()
    deploy_fields = [
        field('members', 'Grid members', 'list', required=True,
              placeholder='gm.example.local\ngmc.example.local',
              help='one a line: the members\' host names as the Grid knows them; the Grid '
                   'Master last (its WAPI restarts with the new certificate)'),
        field('usage', 'Use it as', 'select', default='ADMIN',
              options=[['ADMIN', 'the HTTPS certificate (Grid Manager, WAPI, DoT/DoH)'],
                       ['CAPTIVE_PORTAL', 'the Captive Portal certificate']]),
    ] + verify_fields()

    # The web server of a member restarts after its upload; the Grid Master's WAPI with it.
    served_wait = (10, 6)
    _sleep = staticmethod(time.sleep)

    def auth_headers(self):
        raw = '%s:%s' % (text(self.c('user')), text(self.c('password')))
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()}

    def wapi(self):
        v = text(self.c('wapi_version') or '2.11').strip().lstrip('vV') or '2.11'
        return '/wapi/v%s' % v

    def call(self, function, body, what):
        st, hd, d = self.req('POST', '%s/fileop?_function=%s' % (self.wapi(), function), body,
                             what=what)
        return d if isinstance(d, dict) else {}

    def again(self, fn, what):
        """fn() - asked again for a minute when the Grid Master cannot be reached: its web
        server restarts after its own certificate was uploaded."""
        for i in range(7):
            try:
                return fn()
            except PluginError as e:
                if 'cannot be reached' not in str(e) or i == 6:
                    raise
                self.ctx.step('the Grid Master does not answer (its web server restarts?) - '
                              'asked again in 10 s: %s' % what)
                self._sleep(10)

    def test(self):
        st, hd, d = self.req('GET', '%s/grid' % self.wapi(), what='signing in')
        grid = d[0] if isinstance(d, list) and d else {}
        ref = text(grid.get('_ref') if isinstance(grid, dict) else '')
        return 'signed in to %s (WAPI %s)%s' % (self.c('host'), self.wapi().split('/v')[-1],
                                               ', grid %s' % ref.split(':')[-1] if ref else '')

    def served_places(self, options):
        options = options or {}
        if (options.get('usage') or 'ADMIN') != 'ADMIN':
            return []
        return [(m, 443) for m in lines(options.get('members'))]

    def upload_url(self, url):
        """The url of uploadinit, sent to the address of the target (the Grid Master may
        name itself by an address acme does not reach)."""
        u = urllib.parse.urlsplit(text(url))
        if not u.path:
            raise PluginError('the Grid Master gave no upload address', detail=text(url))
        return self.base_url() + u.path + ('?' + u.query if u.query else '')

    def deploy(self, bundle, options):
        options = options or {}
        members = lines(options.get('members'))
        if not members:
            raise PluginError('no Grid member is given', retry=False)
        usage = text(options.get('usage') or 'ADMIN').upper()
        if usage not in USAGES:
            raise PluginError('"%s" is not a use acme knows (%s)' % (usage, ', '.join(USAGES)),
                              retry=False)
        if self.unchanged(bundle, options):
            return self.same(bundle, 'on %s' % ', '.join(members))
        # one PEM: the certificate, the chain, the key - unencrypted (NIOS takes no password)
        pem = bundle.as_format('fullchain-pem') + b'\n' + bundle.as_format('key-pem')
        fname = 'acme-%s.pem' % (re.sub(r'[^0-9A-Za-z]', '', text(getattr(bundle, 'serial', '')))[-16:]
                                  or 'cert')
        did = []
        for m in members:
            init = self.again(lambda: self.call('uploadinit', {'filename': fname},
                                                'starting the upload for %s' % m),
                              'starting the upload for %s' % m)
            tok, url = text(init.get('token')), text(init.get('url'))
            if not tok or not url:
                raise PluginError('the Grid Master gave no upload token / address',
                                  detail=text(init)[:2000])
            body, ctype = multipart([('file', (fname, pem, 'application/x-pem-file'))])
            self.req('POST', self.upload_url(url), body, {'Content-Type': ctype},
                     what='uploading the certificate for %s' % m)
            self.call('uploadcertificate', {'certificate_usage': usage, 'member': m,
                                            'token': tok},
                      'making it the %s certificate of %s' % (usage, m))
            self.ctx.step('%s has the new %s certificate (its web server restarts, the '
                          'administrators are signed out)' % (m, usage), 'ok')
            did.append(m)
        self.remember(bundle, options)
        return '%s certificate of %s' % (usage, ', '.join(did))
