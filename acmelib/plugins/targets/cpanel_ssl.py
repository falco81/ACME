# -*- coding: utf-8 -*-
"""
cPanel / WHM: the certificate, its key and CA bundle installed on the
websites (virtual hosts) of a cPanel account through UAPI SSL::install_ssl -
or, as root or a reseller, on any account's domain through WHM API 1
installssl. cPanel replaces the certificate of the virtual host and restarts
Apache itself; older certificates acme installed and no site uses any more
are deleted from the account's SSL storage (UAPI).

    cPanel (port 2083), Authorization: cpanel <user>:<API token>
    GET  /execute/SSL/installed_hosts         the sites, their domains and certificate text
    POST /execute/SSL/install_ssl             domain, cert, key, cabundle (form, URI-encoded)
         -> result.status 1, result.data.cert_id
    GET  /execute/SSL/list_certs              the account's SSL storage (domain_is_configured)
    GET  /execute/SSL/delete_cert?id=<id>
    WHM (port 2087), Authorization: whm <user>:<API token>
    GET  /json-api/fetch_ssl_vhosts?api.version=1      the virtual hosts and their certificates
    GET  /json-api/installssl?api.version=1&domain=&crt=&key=&cab=
         -> metadata.result 1, data.status 1

Checked against (the user's collection of the vendor's documents, api-docs/cpanel_ssl/ and
api-docs/cpanel/notes.md for the sign-in):
    notes.md - quotes from
      https://api.docs.cpanel.net/specifications/cpanel.openapi/ssl-certificate-management/ssl-install_ssl
      https://api.docs.cpanel.net/specifications/cpanel.openapi/ssl-certificate-management/ssl-delete_cert
      https://api.docs.cpanel.net/specifications/cpanel.openapi/cpanel-account-ssl-management/ssl-installed_hosts
      https://api.docs.cpanel.net/specifications/cpanel.openapi/cpanel-account-ssl-management/ssl-list_certs
      https://api.docs.cpanel.net/guides/quickstart-development-guide/tutorial-call-uapis-ssl-install-ssl-function-in-custom-code/
      https://api.docs.cpanel.net/specifications/whm.openapi/cpanel-account-settings/ssl-installssl
      https://api.docs.cpanel.net/cpanel/tokens, https://api.docs.cpanel.net/whm/tokens
    cpanel-uapi-ssl.openapi.json - the UAPI specification's /SSL/* (cPanel 11.138.0.10)
    whm-api1-ssl-install.openapi.json - WHM API 1 /installssl, /fetch_ssl_vhosts

Less certain:
    - WHM installssl is documented as a GET with the certificate in the address; a long
      chain may make the address too long (Send the CA bundle off: WHM picks the bundle);
    - WHM tells no certificate text of a virtual host: "the same one is there" is judged by
      its not_after and its key's modulus / ECDSA point, read with fetch_ssl_vhosts;
    - SSL storage is pruned only of certificates acme installed itself (remembered by
      their cert_id) that no site uses (domain_is_configured 0); their keys stay.
"""
from __future__ import annotations

import hashlib
import json
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, as_int, text, tls_fields,
    verify_fields, keep_field, covers, pem_blocks, pem_to_der, form)


def fp_pem(pem):
    try:
        return hashlib.sha256(pem_to_der(pem)).hexdigest()
    except PluginError:
        return ''


class CpanelSslTarget(HttpTarget):
    kind = 'cpanel_ssl'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'cPanel / WHM (SSL install)'
    vendor = 'cPanel'
    description = ('Installs the certificate, key and CA bundle on the websites of a cPanel '
                   'account (UAPI SSL::install_ssl) or, through WHM, on any account\'s domain '
                   '(installssl).')
    doc = 'targets.md'
    fields = [
        field('host', 'Address', 'text', required=True, placeholder='server.example.com',
              help='the cPanel or WHM server'),
        field('api', 'Through', 'select', default='uapi',
              options=[['uapi', 'cPanel (UAPI) - the account\'s own sites'],
                       ['whm', 'WHM API 1 - root or a reseller, any account']]),
        field('port', 'HTTPS port', 'number', placeholder='2083',
              help='empty: 2083 for cPanel, 2087 for WHM'),
        field('user', 'User', 'text', required=True,
              help='the cPanel account (UAPI), or root / the reseller (WHM)'),
        field('token', 'API token', 'secret', required=True,
              help='cPanel → Security → Manage API Tokens (WHM: Development → Manage API '
                   'Tokens)'),
    ] + tls_fields()
    deploy_fields = [
        field('domain', 'Domain', 'catalog', catalog='domains', autoload=False,
              help='the website (its main domain) to install on; empty (UAPI): every site of '
                   'the account the certificate covers'),
        field('domains', 'More domains', 'list', placeholder='shop.example.com',
              help='one a line: more websites'),
        field('send_chain', 'Send the CA bundle', 'bool', default=True, advanced=True,
              help='off: cPanel works the bundle out itself'),
        keep_field(1),
    ] + verify_fields()
    actions = [{'key': 'look', 'label': 'List the websites',
                'help': 'Lists the websites (virtual hosts) and the certificate each has - it '
                        'changes nothing.',
                'changes': False}]

    def whm(self):
        return self.c('api', 'uapi') == 'whm'

    def base_url(self):
        host = text(self.c('host')).strip().rstrip('/')
        if host.startswith(('http://', 'https://')):
            return host
        port = as_int(self.c('port'), 0) or (2087 if self.whm() else 2083)
        if ':' in host and not host.startswith('['):
            host = '[%s]' % host
        return 'https://%s:%d' % (host, port)

    def auth_headers(self):
        return {'Authorization': '%s %s:%s' % ('whm' if self.whm() else 'cpanel',
                                               self.c('user') or '', self.c('token') or '')}

    # -- the two APIs -----------------------------------------------------------------------
    def uapi(self, func, params=None, post=False, what=None):
        path = '/execute/SSL/%s' % func
        if post:
            st, hd, d = self.req('POST', path, form(params or {}),
                                 {'Content-Type': 'application/x-www-form-urlencoded'},
                                 what=what or func)
        else:
            qs = ('?' + urllib.parse.urlencode(params)) if params else ''
            st, hd, d = self.req('GET', path + qs, what=what or func)
        r = (d.get('result') if isinstance(d, dict) else None) or (d if isinstance(d, dict)
                                                                  else {})
        if as_int(r.get('status'), 0) != 1:
            errs = r.get('errors') or []
            raise PluginError('%s: cPanel said %s' % (what or func, '; '.join(map(text, errs))
                                                      if isinstance(errs, list) else errs
                                                      or 'it failed'),
                              detail=text(d)[:4000], retry=False)
        return r.get('data')

    def whmapi(self, func, params=None, what=None):
        p = {'api.version': '1'}
        p.update(params or {})
        st, hd, d = self.req('GET', '/json-api/%s?%s' % (func, urllib.parse.urlencode(p)),
                             what=what or func)
        d = d if isinstance(d, dict) else {}
        meta = d.get('metadata') or {}
        if as_int(meta.get('result'), 0) != 1:
            raise PluginError('%s: WHM said %s' % (what or func, meta.get('reason') or 'it failed'),
                              detail=text(d)[:4000], retry=False)
        return d.get('data') or {}

    def hosts(self):
        """[{servername, domains, cert_fp | None, crt}] - the websites with SSL."""
        out = []
        if self.whm():
            for v in (self.whmapi('fetch_ssl_vhosts', what='listing the virtual hosts')
                      .get('vhosts') or []):
                if isinstance(v, dict):
                    out.append({'servername': text(v.get('servername')),
                                'domains': [text(x) for x in v.get('domains') or []],
                                'fp': None, 'crt': v.get('crt') or {}})
        else:
            for h in self.uapi('installed_hosts', what='listing the websites') or []:
                if isinstance(h, dict):
                    out.append({'servername': text(h.get('servername')),
                                'domains': [text(x) for x in h.get('domains') or []],
                                'fp': fp_pem(h.get('certificate_text') or ''),
                                'crt': h.get('certificate') or {}})
        return out

    def test(self):
        hs = self.hosts()
        return 'signed in to %s as %s (%s); %d website%s with SSL' % (
            self.c('host'), self.c('user'), 'WHM' if self.whm() else 'cPanel', len(hs),
            '' if len(hs) == 1 else 's')

    def catalog(self, key):
        if key != 'domains':
            raise PluginError('there is no list called %s here' % key, retry=False)
        opts = []
        for h in self.hosts():
            if h['servername']:
                opts.append([h['servername'], '%s%s' % (h['servername'], ' (%s)' % ', '.join(
                    d for d in h['domains'] if d != h['servername'])[:120]
                    if len(h['domains']) > 1 else '')])
        return {'options': opts, 'sets': {}, 'said': '%d websites' % len(opts)}

    def action(self, key):
        if key != 'look':
            return HttpTarget.action(self, key)
        hs = self.hosts()
        for h in hs:
            c = h['crt']
            self.ctx.step('%s: %s, until %s' % (h['servername'], c.get('subject.commonName') or
                                                 '?', c.get('not_after') or '?'))
        return '%d website%s' % (len(hs), '' if len(hs) == 1 else 's')

    # -- the work ---------------------------------------------------------------------------
    def same_there(self, h, bundle):
        if h.get('fp'):
            return h['fp'] == fp_pem(bundle.cert_pem)
        c = h.get('crt') or {}
        try:
            return int(c.get('not_after') or 0) == int(float(bundle.not_after)) and \
                bool(c.get('modulus') or c.get('ecdsa_public'))
        except (TypeError, ValueError):
            return False

    def deploy(self, bundle, options):
        options = options or {}
        hs = self.hosts()
        want = []
        one = text(options.get('domain')).strip()
        if one:
            want.append(one)
        want += [d for d in lines(options.get('domains')) if d not in want]
        if not want:
            want = [h['servername'] for h in hs if h['servername'] and
                    covers(bundle.names, h['servername'])]
            if not want:
                raise PluginError('no website of the account is covered by the certificate: '
                                  'set the domain', retry=False)
        byname = {}
        for h in hs:
            for n in [h['servername']] + h['domains']:
                byname.setdefault(n, h)

        def present():
            return all(n in byname and self.same_there(byname[n], bundle) for n in want)
        if self.unchanged(bundle, options, present=present):
            return self.same(bundle, 'on %s' % ', '.join(want))
        cert = text(bundle.as_format('cert-pem'))
        key = text(bundle.as_format('key-pem'))
        chain = ''.join(pem_blocks(bundle.as_format('chain-pem'))) \
            if as_bool(self.opt(options, 'send_chain', True), True) else ''
        did, ids = [], []
        for dom in want:
            if dom in byname and self.same_there(byname[dom], bundle) and \
                    not as_bool(options.get('force')):
                self.ctx.step('%s has this certificate already' % dom)
                continue
            if self.whm():
                p = {'domain': dom, 'crt': cert, 'key': key}
                if chain:
                    p['cab'] = chain
                data = self.whmapi('installssl', p, what='installing on %s' % dom)
                if as_int(data.get('status'), 1) != 1:
                    raise PluginError('installing on %s: WHM said %s' % (
                        dom, data.get('statusmsg') or data.get('message') or 'it failed'),
                        detail=text(data)[:4000], retry=False)
                said = data.get('message') or data.get('statusmsg') or ''
            else:
                p = {'domain': dom, 'cert': cert, 'key': key}
                if chain:
                    p['cabundle'] = chain
                data = self.uapi('install_ssl', p, post=True, what='installing on %s' % dom) or {}
                if data.get('cert_id'):
                    ids.append(text(data['cert_id']))
                said = data.get('message') or data.get('statusmsg') or ''
            self.ctx.step('installed on %s%s' % (dom, (': ' + text(said).splitlines()[0])
                                                 if said else ''), 'ok')
            for w in (data.get('warning_domains') or []) if isinstance(data, dict) else []:
                self.ctx.step('%s: the certificate does not cover %s' % (dom, w), 'warn')
            did.append(dom)
        mine = self.mine(options) + [i for i in ids if i not in self.mine(options)]
        if not self.whm():
            mine = self.cleanup(mine, ids, self.keep(options))
        self.remember(bundle, options, ids=mine[-50:])
        return 'installed on %s' % ', '.join(did) if did else 'already on %s' % ', '.join(want)

    def mine(self, options):
        """The cert_ids acme installed for this deployment before, oldest first."""
        try:
            v = self.ctx.kv_get(self.state_key(options))
        except Exception:                               # noqa: BLE001
            v = None
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except ValueError:
                v = None
        return [text(i) for i in (v or {}).get('ids') or []] if isinstance(v, dict) else []

    def cleanup(self, mine, now, keep):
        """Delete from SSL storage the older ones acme installed that no site uses."""
        if keep < 0 or not mine:
            return mine
        try:
            stored = {text(c.get('id')): c for c in self.uapi('list_certs',
                                                               what='listing SSL storage') or []
                      if isinstance(c, dict)}
        except PluginError as e:
            self.ctx.step('the SSL storage cannot be listed: %s' % e, 'warn')
            return mine
        older = [i for i in mine if i not in now and i in stored]
        gone = older[:max(0, len(older) - keep)]
        left = [i for i in mine if i in stored or i in now]
        for i in gone:
            if as_int(stored[i].get('domain_is_configured'), 1):
                self.ctx.step('the older %s stays: a site still uses it' % i, 'warn')
                continue
            try:
                self.uapi('delete_cert', {'id': i}, what='deleting %s' % i)
                self.ctx.step('deleted the older certificate %s from SSL storage' % i)
                left.remove(i)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (i, e), 'warn')
        return left
