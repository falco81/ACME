# -*- coding: utf-8 -*-
"""
OPNsense: the certificate imported through its API (System → Trust), the
intermediates as CAs; the web GUI pointed at it over SSH when asked.

Checked against api-docs/opnsense/notes.md and the models trust-Cert.xml /
trust-Ca.xml: /api/trust/cert/add with "action": "import" (one certificate
in crt_payload, the intermediates as CAs first); /api/trust/cert/set/<uuid>
replaces one in place, its refid kept - with "action": "import" sent, or
OPNsense "reissues" it with its own CA; a certificate in use cannot be
deleted ("Item in use by"). So Force on a name there already replaces it in
place (it deleted and added it before, which fails for one in use), and
"Replace in place" puts each renewal into the older acme certificate, for
services pointed at it by hand (the web GUI's certificate is not in the API:
set over SSH, as before).
"""
from __future__ import annotations

import base64
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, SshMixin, PluginError, field, as_bool, object_name, name_prefix, prune,
    http_fields, tls_fields, verify_fields, keep_field, chain_list, chain_id, ssh_fields,
    ssh_conn, text, ours)

GUI_PHP = r'''<?php
require_once("config.inc");
require_once("util.inc");
global $config;
$descr = base64_decode('%(descr)s');
$ref = null;
foreach (($config['cert'] ?? []) as $c) { if (($c['descr'] ?? '') === $descr) { $ref = $c['refid']; } }
if ($ref === null) { echo "NOTFOUND\n"; exit(2); }
if (($config['system']['webgui']['ssl-certref'] ?? '') !== $ref) {
    $config['system']['webgui']['ssl-certref'] = $ref;
    write_config('acme: web GUI certificate ' . $descr);
    echo "CHANGED $ref\n";
} else { echo "SAME $ref\n"; }
'''


class OPNsenseTarget(SshMixin, HttpTarget):
    kind = 'opnsense'
    title = 'OPNsense'
    vendor = 'Deciso'
    description = ('Imports the certificate through the OPNsense API (System → Trust); '
                   'can make the web GUI use it (over SSH).')
    doc = 'targets.md'
    fields = http_fields(443, 'opnsense.example.local') + [
        field('api_key', 'API key', 'text', required=True),
        field('api_secret', 'API secret', 'secret', required=True),
    ] + tls_fields() + ssh_fields(sudo=False, prefix='ssh_', advanced=True, howto='opnsense')
    deploy_fields = [
        field('webgui', 'Web GUI certificate', 'bool', default=False,
              help='needs the SSH sign-in of the target (root)'),
        field('in_place', 'Replace in place', 'bool', default=False, advanced=True,
              help='the older certificate acme put there gets the new one (trust/cert/set), '
                   'so the services you pointed at it in OPNsense keep it; they read it '
                   'again when restarted'),
        keep_field(2),
    ] + verify_fields()

    def auth_headers(self):
        tok = base64.b64encode(('%s:%s' % (self.c('api_key'), self.c('api_secret')))
                               .encode()).decode()
        return {'Authorization': 'Basic ' + tok}

    def test(self):
        st, hd, d = self.req('GET', '/api/core/firmware/info', ok=(200, 404),
                             what='signing in')
        ver = d.get('product_version') if isinstance(d, dict) else None
        st, hd, d = self.req('GET', '/api/trust/cert/search', what='reading the certificates')
        return 'signed in to %s%s, %s certificates' % (
            self.c('host'), ', OPNsense %s' % ver if ver else '',
            (d or {}).get('total', len((d or {}).get('rows') or [])))

    def search(self, kind, phrase):
        st, hd, d = self.req('GET', '/api/trust/%s/search?%s' % (kind, urllib.parse.urlencode(
            {'searchPhrase': phrase, 'rowCount': -1})), what='searching')
        return [r for r in (d or {}).get('rows') or [] if isinstance(r, dict)]

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        rows = self.search('cert', prefix)
        have = {r.get('descr'): r for r in rows}
        if self.unchanged(bundle, options, present=lambda: name in have):
            return self.same(bundle, 'as %s' % name)
        did = []
        for pem in chain_list(bundle):
            ca = 'acme-ca-%s' % chain_id(pem)
            if not any(r.get('descr') == ca for r in self.search('ca', ca)):
                self.req('POST', '/api/trust/ca/add', {'ca': {
                    'action': 'existing', 'descr': ca, 'crt_payload': pem}},
                    what='adding the CA %s' % ca)
                self.ctx.step('added the intermediate %s' % ca)
        replaced = False
        if name not in have or as_bool(options.get('force')):
            cert = {'action': 'import', 'descr': name,
                    'crt_payload': text(bundle.as_format('cert-pem')),
                    'prv_payload': text(bundle.as_format('key-pem'))}
            # set/<uuid> with "action": "import" replaces it in place (its refid, and so
            # every service pointing at it, stays) - the one of this name (Force), or
            # with "Replace in place" the newest older one acme put there
            older = sorted((n for n in have if ours(n, prefix) and n != name), reverse=True)
            row = have.get(name) or (have[older[0]] if older and as_bool(
                options.get('in_place')) else None)
            if row:
                st, hd, d = self.req('POST', '/api/trust/cert/set/%s' % row['uuid'],
                                     {'cert': cert}, what='replacing %s' % row.get('descr'))
                how = 'replaced %s in place' % name if row.get('descr') == name else \
                    'replaced %s in place, now %s' % (row.get('descr'), name)
                replaced = True
            else:
                st, hd, d = self.req('POST', '/api/trust/cert/add', {'cert': cert},
                                     what='importing %s' % name)
                how = 'imported %s' % name
            if isinstance(d, dict) and d.get('result') not in (None, 'saved'):
                raise PluginError('OPNsense did not take the certificate: %s'
                                  % (d.get('validations') or d), detail=str(d), retry=False)
            self.ctx.step(how, 'ok')
            did.append(how)
        if as_bool(options.get('webgui')):
            did.append(self.webgui(name, restart=replaced))
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def webgui(self, name, restart=False):
        if not self.c('ssh_user'):
            raise PluginError('the web GUI is set over SSH: fill in the SSH sign-in of the '
                              'target', retry=False)
        php = GUI_PHP % {'descr': base64.b64encode(name.encode()).decode()}
        with self.ctx.ssh(ssh_conn(self, 'ssh_')) as s:
            rc, out, err = s.run('/usr/local/bin/php', input=php, timeout=120, check=False)
            out = text(out)
            if rc != 0 or not (out.startswith('CHANGED') or out.startswith('SAME')):
                raise PluginError('setting the web GUI certificate failed: %s'
                                  % (out.strip() or text(err).strip())[-200:])
            if out.startswith('CHANGED') or restart:
                # a certificate replaced in place is read again only on a restart
                s.run('configctl webgui restart', timeout=120, check=False)
        self.ctx.step('the web GUI uses %s' % name, 'ok')
        return 'web GUI'

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        rows = {r.get('descr'): r for r in self.search('cert', prefix)}
        for old in prune(rows, prefix, keep, current):
            try:
                self.req('POST', '/api/trust/cert/del/%s' % rows[old]['uuid'], {},
                         what='deleting %s' % old)
                self.ctx.step('deleted the old %s' % old)
            except PluginError as e:
                self.ctx.step('the old %s stays (still used?): %s' % (old, e), 'warn')
