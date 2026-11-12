# -*- coding: utf-8 -*-
"""
A10 Networks Thunder / vThunder (ACOS) through aXAPI v3: the certificate,
its key and the intermediates imported as SSL files under dated names, the
client-SSL templates asked for pointed at them, the configuration written,
older acme files deleted.

    POST /axapi/v3/auth   {"credentials": {"username", "password"}}
                          -> {"authresponse": {"signature"}}; then Authorization: A10 <signature>
    POST /axapi/v3/active-partition/<p>  {"active-partition": {"curr_part_name", "shared"}}
    GET  /axapi/v3/file/ssl-cert/oper    the SSL certificate files there
    POST /axapi/v3/file/ssl-cert   multipart: "json" {"ssl-cert": {"file", "action": "import",
                                   "certificate-type": "pem", "file-handle"}} + "file"
    POST /axapi/v3/file/ssl-key    multipart: "json" {"ssl-key": {"file", "action": "import",
                                   "file-handle"}} + "file"
    POST /axapi/v3/slb/template/client-ssl/<t>/certificate
                                   {"certificate": {"cert", "key", "chain-cert"}}
    POST /axapi/v3/write/memory    {"memory": {}}
    POST /axapi/v3/pki/delete      {"delete": {"cert-name"}} / {"delete": {"private-key"}}
    POST /axapi/v3/logoff

Sources (A10's official Ansible collection, made from the aXAPI schema):
    https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/module_utils/auth.py
    https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/module_utils/client.py
    https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/module_utils/axapi_client.py
    https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/modules/a10_file_ssl_cert.py
    https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/modules/a10_file_ssl_key.py
    https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/modules/a10_slb_template_client_ssl_certificate.py
    https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/modules/a10_write_memory.py
    https://github.com/a10networks/a10-acos-axapi/blob/master/plugins/modules/a10_pki_delete.py

Checked against api-docs/a10/notes.md and the aXAPI schemas of ACOS 5.2.1 and
7.0.3 there (slb-template-client-ssl, slb-template-client-ssl-certificate,
file-ssl-cert, file-ssl-key, pki-delete, write-memory): a template's
certificate-list is a list keyed by "cert", so a POST of the new entry adds
it beside the older one - which acme then takes out (DELETE
.../client-ssl/<t>/certificate/<older>, only acme's own; a refusal is said,
not an error), so the older files can be deleted.
Less certain: the DELETE of one entry follows the schema's element URI and
the general Delete Object of aXAPI - no example of it was found; A10's forum
says an entry still in use cannot be removed from a template.
"""
from __future__ import annotations

import json
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, object_name, name_prefix, prune,
    http_fields, tls_fields, verify_fields, keep_field, chain_list, chain_id, text, multipart,
    ours)


class A10Target(HttpTarget):
    kind = 'a10'
    discovery = False       # nothing to find: ACOS lists no partitions through the calls acme makes
    title = 'A10 Thunder (ACOS aXAPI)'
    vendor = 'A10 Networks'
    description = ('Imports the certificate, key and chain through aXAPI v3 under new names, '
                   'points client-SSL templates at them, writes the configuration and '
                   'deletes the older files.')
    doc = 'targets.md'
    fields = http_fields(443, 'thunder.example.local') + [
        field('user', 'User', 'text', required=True, default='admin'),
        field('password', 'Password', 'secret', required=True),
        field('partition', 'Partition', 'text', default='shared',
              help='the partition of the templates and files; shared: the shared one'),
    ] + tls_fields()
    deploy_fields = [
        field('templates', 'Client-SSL templates', 'list', placeholder='tpl-www-clientssl',
              help='one a line: the client-SSL templates to use the certificate'),
        field('write_memory', 'Write the configuration', 'bool', default=True,
              help='write memory after the change, so it survives a reboot'),
        keep_field(1),
    ] + verify_fields()

    signature = None

    def auth_headers(self):
        return {'Authorization': 'A10 %s' % self.signature} if self.signature else {}

    def call(self, method, path, body=None, ok=None, what=None, headers=None):
        st, hd, d = self.req(method, path, body, headers, ok=ok, what=what)
        if isinstance(d, dict) and text((d.get('response') or {}).get('status')) == 'fail':
            err = (d['response'].get('err') or {})
            raise PluginError('%s: ACOS said %s' % (what or path, err.get('msg') or
                                                    err.get('code') or 'fail'), detail=text(d))
        return st, (d if isinstance(d, dict) else {})

    def login(self):
        st, d = self.call('POST', '/axapi/v3/auth', {'credentials': {
            'username': self.c('user') or '', 'password': self.c('password') or ''}},
            what='signing in')
        sig = (d.get('authresponse') or {}).get('signature')
        if not sig:
            raise PluginError('ACOS gave no signature on signing in', detail=text(d),
                              retry=False)
        self.signature = text(sig)
        part = text(self.c('partition') or 'shared').strip() or 'shared'
        if part != 'shared':
            self.call('POST', '/axapi/v3/active-partition/%s' % urllib.parse.quote(part),
                      {'active-partition': {'curr_part_name': part, 'shared': 'false'}},
                      what='switching to the partition %s' % part)

    def logout(self):
        if self.signature:
            try:
                self.req('POST', '/axapi/v3/logoff', ok=range(0, 600))
            except PluginError:
                pass
            self.signature = None

    def test(self):
        self.login()
        try:
            st, d = self.call('GET', '/axapi/v3/version/oper', what='reading the version')
            oper = ((d.get('version') or {}).get('oper') or {})
            return 'signed in to %s, ACOS %s; %d SSL certificate files' % (
                self.c('host'), oper.get('sw-version', '?'), len(self.files()))
        finally:
            self.logout()

    def files(self, kind='ssl-cert'):
        st, d = self.call('GET', '/axapi/v3/file/%s/oper' % kind, what='listing the SSL files')
        oper = ((d.get(kind) or {}).get('oper') or {})
        out = []
        for f in oper.get('file-list') or []:
            if isinstance(f, dict) and f.get('file'):
                out.append(text(f['file']))
        return out

    def upload(self, kind, name, data, extra=None):
        obj = {'file': name, 'action': 'import', 'file-handle': name}
        obj.update(extra or {})
        body, ctype = multipart([
            ('json', ('blob', json.dumps({kind: obj}).encode(), 'application/json')),
            ('file', (name, data, 'application/octet-stream'))])
        self.call('POST', '/axapi/v3/file/%s' % kind, body, headers={'Content-Type': ctype},
                  what='importing the %s %s' % ('key' if kind == 'ssl-key' else 'certificate',
                                                name))

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        self.login()
        try:
            have = self.files()
            # its key too (1.0.88: the certificate went up, its key failed, and every later try
            # saw the certificate there and imported neither - templates pointed at no key)
            try:
                keys = self.files('ssl-key')
            except PluginError:
                keys = None
            key_there = keys is None or name in keys
            if self.unchanged(bundle, options, present=lambda: name in have and key_there):
                return self.same(bundle, 'as %s' % name)
            did = []
            if name not in have or not key_there or as_bool(options.get('force')):
                self.upload('ssl-cert', name, bundle.as_format('cert-pem'),
                            {'certificate-type': 'pem'})
                self.upload('ssl-key', name, bundle.as_format('key-pem'))
                self.ctx.step('imported the certificate and key %s' % name, 'ok')
                did.append('imported %s' % name)
            chain = None
            for _pem in chain_list(bundle)[:1]:         # the issuing CA: ACOS sends one chain file
                # named by the whole chain (1.0.88: by its first only, a changed rest was not sent)
                chain = 'acme-ca-%s' % chain_id(''.join(chain_list(bundle)))
                if chain not in have:
                    pems = ''.join(chain_list(bundle))
                    self.upload('ssl-cert', chain, pems.encode(), {'certificate-type': 'pem'})
                    self.ctx.step('imported the chain %s' % chain)
            for t in lines(options.get('templates')):
                cert = {'cert': name, 'key': name}
                if chain:
                    cert['chain-cert'] = chain
                self.call('POST', '/axapi/v3/slb/template/client-ssl/%s/certificate'
                          % urllib.parse.quote(t, safe=''), {'certificate': cert},
                          what='pointing the template %s at %s' % (t, name))
                self.ctx.step('the client-SSL template %s uses %s' % (t, name), 'ok')
                self.drop_older(t, prefix, name)
                did.append(t)
            if as_bool(self.opt(options, 'write_memory', True), True):
                self.call('POST', '/axapi/v3/write/memory', {'memory': {}},
                          what='writing the configuration')
                self.ctx.step('wrote the configuration (write memory)')
            self.cleanup(prefix, name, self.keep(options))
            self.remember(bundle, options)
            return ', '.join(did) or 'already %s' % name
        finally:
            self.logout()

    def drop_older(self, tpl, prefix, current):
        """The template's certificate-list is a list keyed by "cert" (the schema's
        /slb/template/client-ssl/{name}/certificate/{cert}): the POST above adds the
        new entry beside the older one, which is taken out here (DELETE of that entry)
        - only entries acme made for this certificate; a refusal is only said."""
        q = urllib.parse.quote(tpl, safe='')
        try:
            st, d = self.call('GET', '/axapi/v3/slb/template/client-ssl/%s' % q,
                              what='reading the template %s' % tpl)
        except PluginError as e:
            self.ctx.step('the template %s cannot be read: %s' % (tpl, e), 'warn')
            return
        entries = ((d.get('client-ssl') or {}).get('certificate-list') or [])
        for e in entries:
            old = text((e or {}).get('cert')) if isinstance(e, dict) else ''
            if not old or old == current or not ours(old, prefix):
                continue
            try:
                self.call('DELETE', '/axapi/v3/slb/template/client-ssl/%s/certificate/%s'
                          % (q, urllib.parse.quote(old, safe='')),
                          what='taking %s out of the template %s' % (old, tpl))
                self.ctx.step('took the older %s out of the template %s' % (old, tpl))
            except PluginError as err:
                self.ctx.step('the older %s stays in the template %s: %s' % (old, tpl, err),
                              'warn')

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            names = self.files()
        except PluginError as e:
            self.ctx.step('the older files cannot be listed: %s' % e, 'warn')
            return
        for old in prune(names, prefix, keep, current):
            try:
                self.call('POST', '/axapi/v3/pki/delete', {'delete': {'cert-name': old}},
                          what='deleting the certificate %s' % old)
                self.call('POST', '/axapi/v3/pki/delete', {'delete': {'private-key': old}},
                          what='deleting the key %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays (still used?): %s' % (old, e), 'warn')
