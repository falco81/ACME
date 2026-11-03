# -*- coding: utf-8 -*-
"""
Virtualmin (Remote API, remote.cgi): the certificate, its key and chain
installed into a virtual server with install-cert - its files replaced in
place, the web server and the other services using that certificate
updated, Virtualmin's own Let's Encrypt renewal turned off for it.

    POST https://<host>:10000/virtual-server/remote.cgi   HTTP basic (the master administrator)
         program=install-cert&domain=<d>&cert=<PEM>&key=<PEM>&ca=<chain PEM>
         - each PEM with TABs where its new lines are: remote.cgi splits a value at new
           lines into several arguments, install-cert turns TABs back into new lines
         program=list-certs&domain=<d>&cert=      the domain's certificate (to compare)
         program=list-domains&name-only=          the virtual servers (test, the list)
    the answer is text ending in "Exit status: <n>" (0 = it worked)

Checked against (the user's collection of the vendor's documents,
api-docs/virtualmin/notes.md, with virtualmin-gpl's remote.cgi, install-cert.pl,
list-certs.pl and list-domains.pl), quoting:
    https://www.virtualmin.com/docs/development/remote-api/
    https://www.virtualmin.com/docs/development/api-programs/install-cert/
    https://www.virtualmin.com/docs/development/api-programs/list-domains/
    https://www.virtualmin.com/docs/development/api-programs/enable-feature/
    https://github.com/virtualmin/virtualmin-gpl/blob/master/install-cert.pl

Less certain:
    - the JSON answer of remote.cgi is not described, so the plain text answer and its
      "Exit status:" line are read;
    - what list-certs --cert prints is not quoted: acme takes the first PEM certificate in it
      to tell whether the same one is there (otherwise it remembers what it installed);
    - install-cert does not turn SSL on: a virtual server without the SSL feature gets it with
      enable-feature --ssl first only when "Turn SSL on" is set (the order is not described);
    - a server sharing another one's certificate (ssl_same) is refused by install-cert.
"""
from __future__ import annotations

import base64
import hashlib
import re

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, text, lines, form, pem_blocks, pem_to_der, fp_of,
    chain_list, http_fields, tls_fields, verify_fields)


def tabs(pem):
    return text(pem).strip().replace('\r', '').replace('\n', '\t')


def fp_text(out):
    blocks = [b for b in pem_blocks(out) if 'CERTIFICATE' in b.split('\n', 1)[0]]
    if not blocks:
        return ''
    try:
        return hashlib.sha256(pem_to_der(blocks[0])).hexdigest()
    except Exception:                                   # noqa: BLE001
        return ''


class VirtualminTarget(HttpTarget):
    kind = 'virtualmin'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Virtualmin (Remote API)'
    vendor = 'Virtualmin'
    description = ('Installs the certificate into Virtualmin virtual servers through the Remote '
                   'API (install-cert); Virtualmin updates the web server and other services.')
    doc = 'targets.md'
    fields = http_fields(10000, 'server.example.com') + [
        field('user', 'User', 'text', required=True, default='root',
              help='the master administrator of Webmin (the Remote API takes no other)'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('domain', 'Virtual server', 'catalog', catalog='domains', autoload=False,
              help='its domain name (picked from the list or typed)'),
        field('domains', 'More virtual servers', 'list', placeholder='shop.example.com',
              help='one a line'),
        field('enable_ssl', 'Turn SSL on where it is off', 'bool', default=False,
              help='enable-feature --ssl before installing, for a virtual server without SSL'),
    ] + verify_fields()

    def auth_headers(self):
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()}

    def run(self, program, args, what, check=True):
        body = form(dict([('program', program)] + list(args)))
        st, hd, d = self.req('POST', '/virtual-server/remote.cgi', body,
                             {'Content-Type': 'application/x-www-form-urlencoded',
                              'Accept': 'text/plain'}, what=what)
        out = text(d)
        m = re.search(r'Exit status:\s*(\d+)', out)
        rc = int(m.group(1)) if m else None
        if check and rc != 0:
            words = re.sub(r'\s+', ' ', out.split('Exit status:')[0]).strip()
            if out.strip().startswith('ERROR'):
                words = out.strip()
            raise PluginError('%s: Virtualmin said %s' % (
                what, (words[:300] or 'nothing') + ('' if rc is None else ' (exit %d)' % rc)),
                detail=out[:4000], retry=False)
        return rc, out

    def domain_list(self):
        rc, out = self.run('list-domains', [('name-only', '')], 'listing the virtual servers')
        return [ln.strip() for ln in out.split('Exit status:')[0].splitlines() if ln.strip()]

    def test(self):
        doms = self.domain_list()
        return 'signed in to Virtualmin %s; %d virtual server%s' % (
            self.c('host'), len(doms), '' if len(doms) == 1 else 's')

    def catalog(self, key):
        if key != 'domains':
            raise PluginError('there is no list called %s here' % key, retry=False)
        doms = self.domain_list()
        return {'options': [[d, d] for d in doms], 'sets': {},
                'said': '%d virtual servers' % len(doms)}

    def deploy(self, bundle, options):
        options = options or {}
        want = []
        one = text(options.get('domain')).strip()
        if one:
            want.append(one)
        want += [x for x in lines(options.get('domains')) if x not in want]
        if not want:
            raise PluginError('no virtual server is set', retry=False)
        fp = fp_of(bundle)
        did, same = [], []
        for dom in want:
            if not options.get('force'):
                try:
                    rc, out = self.run('list-certs', [('domain', dom), ('cert', '')],
                                       'reading the certificate of %s' % dom, check=False)
                except PluginError:
                    rc, out = None, ''
                if rc == 0 and fp_text(out) == fp:
                    self.ctx.step('%s has this certificate already' % dom)
                    same.append(dom)
                    continue
            if as_bool(self.opt(options, 'enable_ssl', False)):
                rc, out = self.run('enable-feature', [('domain', dom), ('ssl', '')],
                                   'turning SSL on for %s' % dom, check=False)
                if rc == 0:
                    self.ctx.step('%s: SSL turned on' % dom)
            args = [('domain', dom), ('cert', tabs(bundle.as_format('cert-pem'))),
                    ('key', tabs(bundle.as_format('key-pem')))]
            chain = ''.join(chain_list(bundle))
            if chain:
                args.append(('ca', tabs(chain)))
            try:
                self.run('install-cert', args, 'installing the certificate of %s' % dom)
            except PluginError as e:
                raise PluginError(str(e), retry=False)          # no key in the detail
            self.ctx.step('%s: certificate installed' % dom, 'ok')
            did.append(dom)
        self.remember(bundle, options)
        if not did:
            return self.same(bundle, 'on %s' % ', '.join(same))
        return 'installed on %s' % ', '.join(did)
