# -*- coding: utf-8 -*-
"""
HestiaCP over SSH: the certificate, its key and chain written to a private
folder on the server and given to Hestia's own commands - v-add-web-domain-ssl
the first time, v-change-web-domain-sslcert at a renewal - for each web domain
asked; the folder removed afterwards. Hestia restarts the web server itself.

    mktemp -d                                   a folder of the SSH user (0700)
    <dir>/<domain>.crt, <domain>.key, <domain>.ca   the certificate, key, chain (issuer first)
    v-list-users json                           for the test
    v-list-web-domain <user> <domain> json      SSL, LETSENCRYPT, SSL_HOME of the domain
    v-list-web-domain-ssl <user> <domain> json  the certificate there now (CRT)
    v-change-web-domain-sslcert <user> <domain> <dir> yes      SSL on already
    v-add-web-domain-ssl <user> <domain> <dir> <ssl_home> yes   SSL off
    v-delete-web-domain-ssl <user> <domain> no  first, when Hestia's Let's Encrypt is on for
                                                it (else its cron puts its own back)
    rm -rf <dir>

Why not Hestia's REST API (/api/): its SSL commands take only a folder on the server,
and the only way to write one through the API is an undocumented pseudo-command
(v-make-tmp-file) that leaves the key in /tmp - so the documented commands are run
over SSH instead.

Checked against (the user's collection of the vendor's documents,
api-docs/hestiacp/notes.md, with hestiacp's bin/v-add-web-domain-ssl,
v-change-web-domain-sslcert, v-delete-web-domain-ssl, v-list-web-domain-ssl,
v-update-letsencrypt-ssl and func/domain.sh), quoting:
    https://hestiacp.com/docs/reference/cli.html
    https://hestiacp.com/docs/server-administration/rest-api.html
    https://github.com/hestiacp/hestiacp/blob/main/docs/docs/reference/cli.md
    https://github.com/hestiacp/hestiacp/blob/main/web/api/index.php

Less certain:
    - the commands' folder (/usr/local/hestia/bin) is taken from $HESTIA (/usr/local/hestia,
      the folder the documents name for the API's data) and $BIN of the scripts; set another
      under "Hestia's commands";
    - the keys of v-list-web-domain's JSON (SSL, LETSENCRYPT, SSL_HOME) are the names of the
      domain's settings in the scripts, the JSON itself is not quoted;
    - v-delete-web-domain-ssl (needed once when Hestia's Let's Encrypt was on) also turns
      "force SSL" off - acme says so in the job;
    - each change keeps a copy of the previous certificate and key in the domain's private/
      folder (v-change-web-domain-sslcert does that itself).
"""
from __future__ import annotations

import hashlib
import json
import re

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, text, lines, quote, pem_blocks, pem_to_der,
    fp_of, chain_list, ssh_fields, verify_fields)


def fp_text(pem):
    blocks = [b for b in pem_blocks(pem) if 'CERTIFICATE' in b.split('\n', 1)[0]]
    if not blocks:
        return ''
    try:
        return hashlib.sha256(pem_to_der(blocks[0])).hexdigest()
    except Exception:                                   # noqa: BLE001
        return ''


def parse_json(out):
    s = text(out).strip()
    try:
        return json.loads(s)
    except ValueError:
        return {}


class HestiaCpTarget(SshMixin, Base):
    kind = 'hestiacp'
    discovery = False       # nothing to find: a server over SSH
    title = 'HestiaCP (SSH)'
    vendor = 'HestiaCP'
    description = ('Installs the certificate on HestiaCP web domains over SSH with Hestia\'s own '
                   'commands (v-add-web-domain-ssl / v-change-web-domain-sslcert).')
    doc = 'targets.md'
    fields = ssh_fields(sudo=True, user_default='root',
                        try_command='id -un; ls /usr/local/hestia/bin/v-list-users') + [
        field('hestia_bin', 'Hestia\'s commands', 'text', default='/usr/local/hestia/bin',
              advanced=True),
    ]
    deploy_fields = [
        field('hestia_user', 'Hestia user', 'text', required=True, default='admin',
              help='the user the web domains belong to'),
        field('web_domains', 'Web domains', 'list', required=True, placeholder='example.com',
              help='one a line: the web domains of that user'),
        field('restart', 'Restart the web server', 'bool', default=True),
    ] + verify_fields()

    def cmd(self, name, *args):
        b = text(self.c('hestia_bin') or '/usr/local/hestia/bin').rstrip('/')
        if not re.match(r'^/[A-Za-z0-9_./-]+$', b):
            raise PluginError('"%s" is not a folder' % b, retry=False)
        return ' '.join([quote('%s/%s' % (b, name))] + [quote(text(a)) for a in args])

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.sh(s, self.cmd('v-list-users', 'json'), what='signing in')
        users = parse_json(out)
        n = len(users) if isinstance(users, dict) else 0
        return 'signed in to %s: Hestia answers, %d user%s' % (self.c('host'), n,
                                                              '' if n == 1 else 's')

    def deploy(self, bundle, options):
        options = options or {}
        user = text(options.get('hestia_user')).strip()
        doms = lines(options.get('web_domains'))
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_.-]*$', user):
            raise PluginError('"%s" is not a Hestia user' % user, retry=False)
        if not doms:
            raise PluginError('no web domain is set', retry=False)
        restart = 'yes' if as_bool(self.opt(options, 'restart', True), True) else 'no'
        fp = fp_of(bundle)
        did, same = [], []
        with self.ssh() as s:
            for dom in doms:
                if not re.match(r'^[A-Za-z0-9*][A-Za-z0-9_.-]*$', dom):
                    raise PluginError('"%s" is not a domain' % dom, retry=False)
                rc, out, err = self.sh(s, self.cmd('v-list-web-domain', user, dom, 'json'),
                                       what='reading the web domain %s' % dom)
                info = parse_json(out)
                d = info.get(dom) if isinstance(info.get(dom), dict) else \
                    next((v for v in info.values() if isinstance(v, dict)), {})
                ssl_on = text(d.get('SSL')).lower() == 'yes'
                le_on = text(d.get('LETSENCRYPT')).lower() == 'yes'
                if ssl_on and not le_on and not options.get('force'):
                    rc, out, err = self.sh(s, self.cmd('v-list-web-domain-ssl', user, dom,
                                                       'json'), check=False)
                    got = parse_json(out)
                    crt = ''
                    for v in (got.values() if isinstance(got, dict) else []):
                        if isinstance(v, dict):
                            crt = text(v.get('CRT')).replace('\\n', '\n')
                    if fp_text(crt) == fp:
                        self.ctx.step('%s has this certificate already' % dom)
                        same.append(dom)
                        continue
                folder = self.folder(s)
                try:
                    s.put(bundle.as_format('cert-pem'), '%s/%s.crt' % (folder, dom), 0o600)
                    s.put(bundle.as_format('key-pem'), '%s/%s.key' % (folder, dom), 0o600)
                    chain = ''.join(chain_list(bundle))
                    if chain:
                        s.put(chain.encode(), '%s/%s.ca' % (folder, dom), 0o600)
                    dropped = False
                    if ssl_on and le_on:
                        dropped = True
                        self.sh(s, self.cmd('v-delete-web-domain-ssl', user, dom, 'no'),
                                what='turning Hestia\'s Let\'s Encrypt off for %s' % dom)
                        self.ctx.step('%s: Hestia\'s own Let\'s Encrypt is off for it (and so is '
                                      '"force SSL" - turn it on again in Hestia if it was)' % dom,
                                      'warn')
                        ssl_on = False
                    if ssl_on:
                        self.sh(s, self.cmd('v-change-web-domain-sslcert', user, dom, folder,
                                            restart), what='changing the certificate of %s' % dom)
                    else:
                        home = text(d.get('SSL_HOME')) or 'same'
                        try:
                            self.sh(s, self.cmd('v-add-web-domain-ssl', user, dom, folder, home,
                                                restart), what='turning SSL on for %s' % dom)
                        except PluginError as e:
                            if dropped:
                                # said plainly (1.0.51): Hestia's own certificate was taken off
                                # first - the domain is left with no SSL at all
                                raise PluginError('%s now has NO SSL: Hestia\'s own Let\'s '
                                                  'Encrypt was turned off for it and the new '
                                                  'certificate was refused (%s) - turn Let\'s '
                                                  'Encrypt on again in Hestia, or deploy again'
                                                  % (dom, e), retry=False)
                            raise
                finally:
                    s.run('rm -rf %s' % quote(folder), check=False)
                self.ctx.step('%s: certificate installed%s' % (
                    dom, '' if restart == 'yes' else ' (the web server is not restarted)'), 'ok')
                did.append(dom)
        self.remember(bundle, options)
        if not did:
            return self.same(bundle, 'on %s' % ', '.join(same))
        return 'installed on %s' % ', '.join(did)

    def folder(self, s):
        rc, out, err = s.run('umask 077; mktemp -d', check=False)
        f = text(out).strip().splitlines()[-1] if text(out).strip() else ''
        if rc != 0 or not re.match(r'^/[A-Za-z0-9_./-]+$', f):
            raise PluginError('no private folder could be made on the server (mktemp -d): %s'
                              % (text(err).strip() or f)[-200:])
        return f
