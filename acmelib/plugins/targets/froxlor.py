# -*- coding: utf-8 -*-
"""
froxlor (its API, api.php): the certificate, its key and chain set as a
domain's SSL certificate - Certificates.add the first time, then
Certificates.update in place - for each domain asked. froxlor's cron
writes the web server's configuration afterwards (REBUILD_VHOST).

    POST https://<panel>/api.php   Content-Type: application/json,
         Authorization: Basic <API key>:<API secret>
         {"command": "Certificates.get", "params": {"domainname"}}  -> 200, or 412 (none yet)
         {"command": "Certificates.add" | "Certificates.update", "params": {"domainname",
          "ssl_cert_file", "ssl_key_file", "ssl_cert_chainfile"}}  (PEM text, not files)
         {"command": "Froxlor.listFunctions"}                       for the test
    an error: HTTP 4xx with {"message"} (the guide says status_message; the code says message)

Checked against (the user's collection of the vendor's documents,
api-docs/froxlor/notes.md, with froxlor 2.3.16's api.php, lib/Froxlor/Api/FroxlorRPC.php,
Response.php, Commands/Certificates.php, Commands/Domains.php), quoting:
    https://docs.froxlor.org/latest/api-guide/
    https://docs.froxlor.org/latest/api-guide/commands/certificates.html
    https://github.com/Froxlor/Froxlor/releases/tag/2.3.16

Less certain:
    - the guide names the domain of Certificates.add "id", the code reads "domainid": acme
      sends only "domainname";
    - how ssl_ca_file and ssl_cert_chainfile differ in the web server's configuration was not
      read: the intermediates go in ssl_cert_chainfile;
    - a domain with froxlor's own Let's Encrypt is refused (sslcertificateisletsencryptmanaged):
      turn it off for the domain in froxlor;
    - the change takes effect when froxlor's cron runs; when that is cannot be told or asked
      through the API.
"""
from __future__ import annotations

import base64
import hashlib

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, text, lines, pem_blocks, pem_to_der, fp_of, norm_fp,
    chain_list, tls_fields, verify_fields)


def fp_text(pem):
    blocks = [b for b in pem_blocks(pem) if 'CERTIFICATE' in b.split('\n', 1)[0]]
    if not blocks:
        return ''
    try:
        return hashlib.sha256(pem_to_der(blocks[0])).hexdigest()
    except Exception:                                   # noqa: BLE001
        return ''


class FroxlorTarget(HttpTarget):
    kind = 'froxlor'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'froxlor (API)'
    vendor = 'froxlor'
    description = ('Sets the certificate of froxlor domains through its API (Certificates.add / '
                   'update); froxlor\'s cron puts it in place.')
    doc = 'targets.md'
    fields = [
        field('url', 'Panel address', 'text', required=True,
              placeholder='https://froxlor.example.com',
              help='where froxlor is; api.php is called there'),
        field('api_key', 'API key', 'secret', required=True),
        field('api_secret', 'API secret', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('domains', 'Domains', 'list', required=True, placeholder='www.example.com',
              help='one a line: the froxlor domains (as named there) to get the certificate'),
    ] + verify_fields()

    def base_url(self):
        u = text(self.c('url')).strip().rstrip('/')
        if not u.startswith(('http://', 'https://')):
            u = 'https://' + u
        return u[:-len('/api.php')] if u.endswith('/api.php') else u

    def auth_headers(self):
        raw = '%s:%s' % (self.c('api_key') or '', self.c('api_secret') or '')
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()}

    def http_error(self, status, parsed, raw, method, path, what=None):
        msg = ''
        if isinstance(parsed, dict):
            msg = text(parsed.get('message') or parsed.get('status_message') or '')
        if status in (401, 403):
            return '%s: froxlor does not let acme in (%d)%s' % (
                what or 'signing in', status, (' - ' + msg) if msg else '')
        return '%s: froxlor said %d%s' % (what or method, status, (' - ' + msg) if msg else '')

    def call(self, command, params=None, ok=None, what=None):
        body = {'command': command}
        if params:
            body['params'] = params
        st, hd, d = self.req('POST', '/api.php', body, ok=range(100, 600), what=what or command)
        if st not in (ok or range(200, 300)):
            # froxlor answers a refused value with 406 (and none yet with 412)
            raise PluginError(self.http_error(st, d, b'', 'POST', '/api.php', what or command),
                              detail=text(d)[:4000] if isinstance(d, dict) else None,
                              retry=st not in (400, 401, 403, 404, 405, 406, 409, 412, 422))
        return st, (d if isinstance(d, dict) else {})

    def test(self):
        try:
            st, d = self.call('Froxlor.listFunctions', what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry=False)
        data = d.get('data')
        n = len(data.get('list') or []) if isinstance(data, dict) else \
            (len(data) if isinstance(data, list) else 0)
        return 'signed in to froxlor %s; %d API functions allowed' % (self.base_url(), n)

    def deploy(self, bundle, options):
        options = options or {}
        doms = lines(options.get('domains'))
        if not doms:
            raise PluginError('no domain is set', retry=False)
        fp = fp_of(bundle)
        did, same = [], []
        for dom in doms:
            st, d = self.call('Certificates.get', {'domainname': dom}, ok=(200, 412),
                              what='reading the certificate of %s' % dom)
            data = d.get('data') if isinstance(d.get('data'), dict) else {}
            if st == 200 and not options.get('force') and \
                    norm_fp(fp_text(data.get('ssl_cert_file'))) == fp:
                self.ctx.step('%s has this certificate already' % dom)
                same.append(dom)
                continue
            cmd = 'Certificates.update' if st == 200 else 'Certificates.add'
            self.call(cmd, {
                'domainname': dom,
                'ssl_cert_file': text(bundle.as_format('cert-pem')),
                'ssl_key_file': text(bundle.as_format('key-pem')),
                'ssl_cert_chainfile': ''.join(chain_list(bundle))},
                what='%s the certificate of %s' % ('replacing' if st == 200 else 'adding', dom))
            self.ctx.step('%s: certificate %s (froxlor\'s cron puts it in place)' % (
                dom, 'replaced' if st == 200 else 'added'), 'ok')
            did.append(dom)
        self.remember(bundle, options)
        if not did:
            return self.same(bundle, 'on %s' % ', '.join(same))
        return 'set on %s' % ', '.join(did)
