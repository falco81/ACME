# -*- coding: utf-8 -*-
"""
Plesk (XML API): the certificate, its key and CA certificate installed into
a certificate repository - a subscription's or the server's - under a dated
name. Plesk's XML API documents no way to assign a certificate to a website:
that is done by hand in Plesk (Websites & Domains → SSL/TLS Certificates, or
`plesk bin subscription -u <domain> -certificate-name <name>`). acme only puts
the new one in the repository and says so; older ones are removed only when
"Previous versions to keep" says so (-1, keep all, by default), since Plesk
does not tell whether one is still assigned.

    POST https://<host>:8443/enterprise/control/agent.php   Content-Type: text/xml
         HTTP_AUTH_LOGIN / HTTP_AUTH_PASSWD, or KEY: <secret key>
    <packet><certificate><get-pool><filter><domain-name>D</domain-name></filter></get-pool>
                                                    (or <get-pool><admin/></get-pool>)
         -> <get-pool><result><status>ok</status><certificates><certificate><name/>...
    <packet><certificate><install><name>N</name><webspace>D</webspace> (or <admin/>)
         <content><csr/><pvt>KEY</pvt><cert>CERT</cert><ca>CHAIN</ca></content></install>
    <packet><certificate><remove><filter><name>N</name></filter><webspace>D</webspace>
         (or <admin/>)</remove>

Checked against (the user's collection of the vendor's documents, api-docs/plesk/):
    notes.md - quotes from
      https://docs.plesk.com/en-US/obsidian/api-rpc/about-xml-api/xml-api-packets/a-sample-packet.50169/
      https://docs.plesk.com/en-US/obsidian/api-rpc/about-xml-api/reference/managing-ssltls-certificates.34871/
      https://docs.plesk.com/en-US/obsidian/api-rpc/about-xml-api/reference/managing-ssltls-certificates/installing-certificates.34877/
      https://docs.plesk.com/en-US/obsidian/api-rpc/about-xml-api/reference/managing-ssltls-certificates/deleting-certificates.34882/
      https://docs.plesk.com/en-US/obsidian/api-rpc/about-xml-api/reference/managing-ssltls-certificates/retrieving-list-of-certificates.68395/
      https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/subscription-subscriptions.37768/
      https://github.com/plesk/api-php-lib (src/Api/Client.php: the headers)
    xsd-1.6.9.1/certificate_input.xsd, certificate_output.xsd (the order of the elements)

Less certain:
    - assigning the certificate to a website: not in the XML API documents (only the CLI's
      -certificate-name), so it is not done - assign it by hand;
    - <csr> is required by the schema; acme has none to give and sends it empty;
    - whether Plesk refuses to remove a certificate still assigned (not documented): keep
      older ones (-1) unless you know they are no longer assigned.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, text, object_name, name_prefix, ours, prune, http_fields,
    tls_fields, verify_fields, keep_field, chain_list)


def packet(op, cmd, items):
    """<packet><op><cmd>items</cmd></op></packet>; items: (tag, text | list | None) pairs."""
    root = ET.Element('packet')
    c = ET.SubElement(ET.SubElement(root, op), cmd)

    def put(parent, pairs):
        for tag, v in pairs:
            e = ET.SubElement(parent, tag)
            if isinstance(v, list):
                put(e, v)
            elif v is not None:
                e.text = text(v)
    put(c, items)
    return b'<?xml version="1.0" encoding="UTF-8"?>' + ET.tostring(root)


class PleskTarget(HttpTarget):
    kind = 'plesk'
    title = 'Plesk (certificate repository)'
    vendor = 'Plesk'
    description = ('Installs the certificate into a Plesk certificate repository (of a '
                   'subscription or the server) through the XML API; it is assigned to the '
                   'website in Plesk by hand.')
    doc = 'targets.md'
    fields = http_fields(8443, 'plesk.example.com') + [
        field('auth', 'Sign in with', 'select', default='password',
              options=[['password', 'login and password'], ['key', 'a secret key']]),
        field('user', 'Login', 'text', default='admin', show_if={'auth': ['password']},
              help='the administrator or a reseller (the certificate operator is theirs)'),
        field('password', 'Password', 'secret', show_if={'auth': ['password']}),
        field('secret_key', 'Secret key', 'secret', show_if={'auth': ['key']},
              help='a secret key of the XML API made for acme'),
    ] + tls_fields()
    deploy_fields = [
        field('repository', 'Repository', 'select', default='webspace',
              options=[['webspace', 'the subscription\'s (below)'],
                       ['admin', 'the server\'s (Tools & Settings)']]),
        field('subscription', 'Subscription', 'text', placeholder='example.com',
              show_if={'repository': ['webspace']},
              help='the subscription (its domain) whose repository gets the certificate'),
        keep_field(-1),
    ] + verify_fields()

    def auth_headers(self):
        if self.c('auth', 'password') == 'key':
            return {'KEY': text(self.c('secret_key'))}
        return {'HTTP_AUTH_LOGIN': text(self.c('user')),
                'HTTP_AUTH_PASSWD': text(self.c('password'))}

    def call(self, cmd, items, what):
        body = packet('certificate', cmd, items)
        st, hd, raw = self.req('POST', '/enterprise/control/agent.php', body,
                               {'Content-Type': 'text/xml', 'Accept': 'text/xml'}, what=what)
        try:
            root = ET.fromstring(raw if isinstance(raw, bytes) else text(raw).encode())
        except ET.ParseError:
            raise PluginError('%s: Plesk did not answer in XML' % what, detail=text(raw)[:4000])
        sys_err = root.find('./system')
        if sys_err is not None:
            raise PluginError('%s: Plesk said %s' % (what, (sys_err.findtext('errtext') or
                                                            'an error').strip()),
                              detail=text(raw)[:4000], retry=False)
        res = root.findall('./certificate/%s/result' % cmd)
        for r in res:
            if (r.findtext('status') or '').strip() != 'ok':
                raise PluginError('%s: Plesk said %s' % (
                    what, (r.findtext('errtext') or r.findtext('errcode') or 'error').strip()),
                    detail=text(raw)[:4000], retry=False)
        return res

    def where(self, options):
        if text(options.get('repository') or 'webspace') == 'admin':
            return ('admin', None)
        sub = text(options.get('subscription')).strip()
        if not sub:
            raise PluginError('no subscription is set (or choose the server\'s repository)',
                              retry=False)
        return ('webspace', sub)

    def pool(self, options):
        tag, sub = self.where(options)
        items = [('admin', None)] if tag == 'admin' else \
            [('filter', [('domain-name', sub)])]
        res = self.call('get-pool', items, 'listing the certificates of the repository')
        return [text(n.text).strip() for r in res for n in r.findall('./certificates/'
                                                                     'certificate/name')
                if n.text]

    def test(self):
        res = self.call('get-pool', [('admin', None)], 'listing the server\'s certificates')
        n = sum(len(r.findall('./certificates/certificate')) for r in res)
        return 'signed in to Plesk %s; %d certificate%s in the server\'s repository' % (
            self.c('host'), n, '' if n == 1 else 's')

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=63)
        prefix = name_prefix(bundle, options, maxlen=63)
        tag, sub = self.where(options)
        have = self.pool(options)
        if self.unchanged(bundle, options, present=lambda: name in have):
            return self.same(bundle, 'as %s' % name)
        place = 'the server\'s repository' if tag == 'admin' else 'the repository of %s' % sub
        if name not in have:
            content = [('csr', ''), ('pvt', text(bundle.as_format('key-pem')).strip()),
                       ('cert', text(bundle.as_format('cert-pem')).strip())]
            chain = ''.join(chain_list(bundle)).strip()
            if chain:
                content.append(('ca', chain))
            self.call('install', [('name', name), (tag, sub), ('content', content)],
                      'installing %s' % name)
            self.ctx.step('installed %s into %s' % (name, place), 'ok')
        else:
            self.ctx.step('%s is in %s already' % (name, place))
        self.ctx.step('Plesk\'s XML API does not assign a certificate to a website: choose %s '
                      'for the site in Plesk (Websites & Domains → SSL/TLS Certificates)' % name,
                      'warn')
        keep = self.keep(options)
        if keep >= 0:
            for old in prune([n for n in have if ours(n, prefix)], prefix, keep, name):
                try:
                    self.call('remove', [('filter', [('name', old)]), (tag, sub)],
                              'removing %s' % old)
                    self.ctx.step('removed the older %s' % old)
                except PluginError as e:
                    self.ctx.step('the older %s stays: %s' % (old, e), 'warn')
        self.remember(bundle, options)
        return 'installed %s into %s - assign it to the website in Plesk' % (name, place)
