# -*- coding: utf-8 -*-
"""
ISPConfig 3 (Remote API, JSON transport): the certificate, its key and chain
written into a website's SSL settings with ssl_action=save - at every
renewal - SSL turned on and the panel's own Let's Encrypt off for it. The
server's ISPConfig cron writes the files and reloads the web server a minute
or so later.

    POST https://<panel>:8080/remote/json.php?login  {"username", "password"}
         -> {"code": "ok", "response": <session id>}
    POST .../json.php?sites_web_domain_get     {"session_id", "primary_id": {"domain": <site>}}
    POST .../json.php?sites_web_domain_update  {"session_id", "client_id", "primary_id": <id>,
         "params": {"ssl": "y", "ssl_letsencrypt": "n", "ssl_cert", "ssl_key", "ssl_bundle",
                    "ssl_action": "save"}}
    POST .../json.php?logout                   {"session_id"}
    (an answer is {"code": "ok" | "remote_fault" | ..., "message", "response"})

Checked against (the user's collection of the vendor's documents,
api-docs/ispconfig/notes.md - from the official ISPConfig 3.3.2p1 package:
remoting_client/API-docs, remoting_client/examples, interface/web/remote/json.php,
interface/lib/classes/json_handler.inc.php, remoting.inc.php, remoting_lib.inc.php,
sites/form/web_vhost_domain.tform.php, server/plugins-available/apache2_plugin.inc.php),
quoting:
    https://www.ispconfig.org/downloads/ISPConfig-3-stable.tar.gz
    https://www.ispconfig.org/documentation/

Less certain:
    - ssl_key is not in the API reference of sites_web_domain_update (it is in the form and
      the server plugin writes it);
    - the meaning of client_id at an update is not described (the example sends 0);
    - the work is done by the server's cron, and its outcome is not given back through the
      API - "Check what is served" after a minute or two tells;
    - the nginx plugin was not read in detail (the same ssl_action branches are there);
    - an encrypted key is refused by the server (acme's never is).
"""
from __future__ import annotations

import hashlib

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_int, text, lines, pem_blocks, pem_to_der, fp_of, norm_fp,
    chain_list, http_fields, tls_fields, verify_fields)

VHOSTS = ('vhost', 'vhostsubdomain', 'vhostalias')


def fp_text(pem):
    blocks = [b for b in pem_blocks(pem) if 'CERTIFICATE' in b.split('\n', 1)[0]]
    if not blocks:
        return ''
    try:
        return hashlib.sha256(pem_to_der(blocks[0])).hexdigest()
    except Exception:                                   # noqa: BLE001
        return ''


class IspConfigTarget(HttpTarget):
    kind = 'ispconfig'
    title = 'ISPConfig (Remote API)'
    vendor = 'ISPConfig'
    description = ('Writes the certificate into the SSL settings of ISPConfig websites through '
                   'the Remote API (ssl_action save); the server\'s cron puts it in place.')
    doc = 'targets.md'
    fields = http_fields(8080, 'panel.example.com') + [
        field('user', 'Remote user', 'text', required=True,
              help='a remote user (System → Remote Users) with "Sites Domain functions"'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('website', 'Website', 'catalog', catalog='websites', autoload=False,
              help='the domain of the website (picked from the list or typed)'),
        field('websites', 'More websites', 'list', placeholder='shop.example.com',
              help='one a line: their domains'),
        field('client_id', 'Client ID for the update', 'number', default=0, advanced=True,
              help='as in ISPConfig\'s example: 0'),
    ] + verify_fields()

    sid = None

    # -- the Remote API ---------------------------------------------------------------------
    def call(self, method, params, what=None, auth=True):
        if auth:
            self.login()
            params = dict(params, session_id=self.sid)
        st, hd, d = self.req('POST', '/remote/json.php?%s' % method, params,
                             what=what or method)
        if not isinstance(d, dict):
            raise PluginError('%s: ISPConfig gave no JSON (is the Remote API on, and the address '
                              'the panel\'s?)' % (what or method), detail=text(d)[:4000])
        if d.get('code') != 'ok':
            raise PluginError('%s: ISPConfig said %s - %s' % (
                what or method, d.get('code'), text(d.get('message'))[:300]),
                detail=text(d)[:4000],
                retry=d.get('code') not in ('remote_fault', 'invalid_method', 'invalid_data'))
        return d.get('response')

    def login(self):
        if self.sid:
            return
        try:
            r = self.call('login', {'username': self.c('user') or '',
                                    'password': self.c('password') or ''},
                          what='signing in', auth=False)
        except PluginError as e:
            raise PluginError(str(e), retry=False)
        if not r:
            raise PluginError('ISPConfig gave no session', retry=False)
        self.sid = text(r)

    def logout(self):
        if not self.sid:
            return
        try:
            self.call('logout', {}, what='signing out')
        except PluginError:
            pass
        self.sid = None

    def sites(self, flt):
        r = self.call('sites_web_domain_get', {'primary_id': flt},
                      what='reading the website %s' % (flt.get('domain') if
                                                       isinstance(flt, dict) else flt))
        if isinstance(r, dict):
            r = [r] if r.get('domain_id') or r.get('domain') else list(r.values())
        return [x for x in r or [] if isinstance(x, dict)]

    # -- read-only --------------------------------------------------------------------------
    def test(self):
        try:
            n = len(self.sites({'#LIMIT#': 1000}))
        finally:
            self.logout()
        return 'signed in to ISPConfig %s; %d website%s seen' % (self.c('host'), n,
                                                                '' if n == 1 else 's')

    def catalog(self, key):
        if key != 'websites':
            raise PluginError('there is no list called %s here' % key, retry=False)
        try:
            got = self.sites({'#LIMIT#': 1000})
        finally:
            self.logout()
        opts = []
        for s in got:
            if s.get('type') in VHOSTS and s.get('domain'):
                opts.append([text(s['domain']), '%s%s' % (
                    s['domain'], ' (SSL)' if s.get('ssl') == 'y' else '')])
        return {'options': sorted(opts), 'sets': {}, 'said': '%d websites' % len(opts)}

    # -- the work ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        want = []
        one = text(options.get('website')).strip()
        if one:
            want.append(one)
        want += [x for x in lines(options.get('websites')) if x not in want]
        if not want:
            raise PluginError('no website is set', retry=False)
        fp = fp_of(bundle)
        force = options.get('force')
        did, same = [], []
        try:
            for dom in want:
                recs = [r for r in self.sites({'domain': dom}) if r.get('type') in VHOSTS]
                if not recs:
                    raise PluginError('ISPConfig has no website "%s"' % dom, retry=False)
                rec = recs[0]
                if not force and rec.get('ssl') == 'y' and \
                        norm_fp(fp_text(rec.get('ssl_cert'))) == fp and \
                        rec.get('ssl_letsencrypt') != 'y':
                    self.ctx.step('%s has this certificate already' % dom)
                    same.append(dom)
                    continue
                if rec.get('ssl_letsencrypt') == 'y':
                    self.ctx.step('%s: the panel\'s own Let\'s Encrypt is turned off for it' % dom,
                                  'warn')
                params = {'ssl': 'y', 'ssl_letsencrypt': 'n',
                          'ssl_cert': text(bundle.as_format('cert-pem')),
                          'ssl_key': text(bundle.as_format('key-pem')),
                          'ssl_bundle': ''.join(chain_list(bundle)),
                          'ssl_action': 'save'}
                self.call('sites_web_domain_update', {
                    'client_id': as_int(self.opt(options, 'client_id', 0), 0),
                    'primary_id': as_int(rec.get('domain_id'), 0), 'params': params},
                    what='writing the certificate of %s' % dom)
                self.ctx.step('%s: certificate saved (the server\'s cron puts it in place)' % dom,
                              'ok')
                did.append(dom)
        finally:
            self.logout()
        self.remember(bundle, options)
        if not did:
            return self.same(bundle, 'on %s' % ', '.join(same))
        return 'saved on %s' % ', '.join(did)
