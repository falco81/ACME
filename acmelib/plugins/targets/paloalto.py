# -*- coding: utf-8 -*-
"""
Palo Alto Networks PAN-OS over the XML API: the key pair imported (PKCS#12)
under a dated name, the intermediates as certificates, SSL/TLS service
profiles pointed at it, older ones deleted, committed and the job waited for.
"""
from __future__ import annotations

import time
import urllib.parse
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, as_int, object_name, name_prefix, prune,
    http_fields, tls_fields, verify_fields, keep_field, chain_list, chain_id, random_password,
    multipart, form, text)


def xstr(s):
    """A name inside an xpath predicate: [@name='x']"""
    s = text(s)
    if "'" in s:
        raise PluginError('a name with a quote is not allowed: %s' % s, retry=False)
    return "'%s'" % s


class PaloAltoTarget(HttpTarget):
    kind = 'paloalto'
    title = 'Palo Alto Networks (PAN-OS)'
    vendor = 'Palo Alto Networks'
    description = ('Imports the certificate and key through the PAN-OS XML API, points '
                   'SSL/TLS service profiles at it, deletes older ones and commits.')
    doc = 'targets.md'
    fields = http_fields(443, 'pa.example.local') + [
        field('auth', 'Sign in with', 'select', default='key',
              options=[['key', 'an API key'], ['password', 'user and password']]),
        field('api_key', 'API key', 'secret', show_if={'auth': ['key']}),
        field('user', 'User', 'text', show_if={'auth': ['password']}),
        field('password', 'Password', 'secret', show_if={'auth': ['password']}),
        field('vsys', 'Virtual system', 'text', advanced=True,
              help='empty: shared (Device → Certificates, shared)'),
    ] + tls_fields()
    deploy_fields = [
        field('profiles', 'SSL/TLS service profiles', 'list',
              help='one a line: the profiles (GlobalProtect, admin GUI, …) to use it'),
        field('commit', 'Commit', 'select', default='admin',
              options=[['admin', 'commit acme\'s own changes only'],
                       ['all', 'commit everything pending'], ['no', 'do not commit']]),
        field('pfx_format', 'PKCS#12 kind', 'select', default='p12-legacy', advanced=True,
              options=[['p12-legacy', '3DES (any PAN-OS)'], ['pfx', 'AES-256']]),
        field('commit_timeout', 'Wait for the commit (s)', 'number', default=600,
              advanced=True),
        keep_field(2),
    ] + verify_fields()

    _sleep = staticmethod(time.sleep)
    key = None

    def auth_headers(self):
        return {'X-PAN-KEY': self.key} if self.key else {}

    def call(self, params, files=None, what=None, timeout=None):
        """POST /api/ -> the <result> element (or the response). Errors in words."""
        if files:
            q = urllib.parse.urlencode(params)
            body, ctype = multipart(files)
            st, hd, raw = self.req('POST', '/api/?' + q, body, {'Content-Type': ctype},
                                   what=what, timeout=timeout)
        else:
            st, hd, raw = self.req('POST', '/api/', form(params),
                                   {'Content-Type': 'application/x-www-form-urlencoded'},
                                   what=what, timeout=timeout)
        try:
            root = ET.fromstring(raw if isinstance(raw, bytes) else str(raw).encode())
        except ET.ParseError:
            raise PluginError('%s: not an answer of PAN-OS' % (what or params.get('type')),
                              detail=text(raw)[:2000])
        if root.get('status') != 'success':
            msg = ' '.join(t.strip() for t in root.itertext() if t.strip())
            raise PluginError('%s: PAN-OS said %s' % (what or params.get('type'), msg[:300]),
                              detail=text(raw)[:4000],
                              retry=root.get('code') not in ('400', '403', '13'))
        return root

    def login(self):
        if (self.c('auth') or 'key') == 'key':
            self.key = self.c('api_key')
            if not self.key:
                raise PluginError('no API key is set', retry=False)
            return
        root = self.call({'type': 'keygen', 'user': self.c('user'),
                          'password': self.c('password')}, what='signing in')
        k = root.findtext('.//key')
        if not k:
            raise PluginError('PAN-OS gave no API key')
        self.key = k

    def base_xpath(self):
        vsys = (self.c('vsys') or '').strip()
        if vsys:
            return "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name=%s]" \
                % xstr(vsys)
        return '/config/shared'

    def test(self):
        self.login()
        root = self.call({'type': 'version'}, what='reading the version')
        return 'signed in to %s, %s PAN-OS %s' % (
            root.findtext('.//hostname') or self.c('host'), root.findtext('.//model') or '',
            root.findtext('.//sw-version') or '?')

    def exists(self, name):
        root = self.call({'type': 'config', 'action': 'get', 'xpath': '%s/certificate/entry'
                          '[@name=%s]' % (self.base_xpath(), xstr(name))})
        return root.find('.//entry') is not None

    def import_params(self, **p):
        vsys = (self.c('vsys') or '').strip()
        if vsys:
            p['vsys'] = vsys
        p['type'] = 'import'
        return p

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=63)
        prefix = name_prefix(bundle, options, maxlen=63)
        base = self.base_xpath()
        self.login()
        if self.unchanged(bundle, options, present=lambda: self.exists(name)):
            return self.same(bundle, 'as %s' % name)
        did = []
        if not self.exists(name) or as_bool(options.get('force')):
            pw = random_password()
            data = bundle.as_format(options.get('pfx_format') or 'p12-legacy', password=pw,
                                    alias=name)
            self.call(self.import_params(category='keypair', **{
                'certificate-name': name, 'format': 'pkcs12', 'passphrase': pw}),
                files=[('file', (name + '.p12', data, 'application/x-pkcs12'))],
                what='importing %s' % name)
            self.ctx.step('imported %s' % name, 'ok')
            did.append('imported %s' % name)
        for pem in chain_list(bundle):
            ca = 'acme-ca-%s' % chain_id(pem)
            if not self.exists(ca):
                self.call(self.import_params(category='certificate', **{
                    'certificate-name': ca, 'format': 'pem'}),
                    files=[('file', (ca + '.pem', pem.encode(), 'application/x-pem-file'))],
                    what='importing %s' % ca)
                self.ctx.step('imported the intermediate %s' % ca)
        for p in lines(options.get('profiles')):
            self.call({'type': 'config', 'action': 'set',
                       'xpath': '%s/ssl-tls-service-profile/entry[@name=%s]' % (base, xstr(p)),
                       'element': '<certificate>%s</certificate>' % escape(name)},
                      what='setting the profile %s' % p)
            self.ctx.step('profile %s uses %s' % (p, name), 'ok')
            did.append('profile %s' % p)
        self.cleanup(base, prefix, name, self.keep(options))
        how = options.get('commit') or 'admin'
        if how != 'no':
            did.append(self.commit(how, as_int(options.get('commit_timeout', 600), 600)))
        self.remember(bundle, options)
        return ', '.join(did)

    def cleanup(self, base, prefix, current, keep):
        if keep < 0:
            return
        root = self.call({'type': 'config', 'action': 'get', 'xpath': base + '/certificate'})
        names = [e.get('name') for e in root.iter('entry') if e.get('name')]
        for old in prune(names, prefix, keep, current):
            try:
                self.call({'type': 'config', 'action': 'delete',
                           'xpath': '%s/certificate/entry[@name=%s]' % (base, xstr(old))},
                          what='deleting %s' % old)
                self.ctx.step('deleted the old %s' % old)
            except PluginError as e:
                self.ctx.step('the old %s stays (still used?): %s' % (old, e), 'warn')

    def commit(self, how, wait):
        if how == 'admin' and (self.c('auth') == 'password') and self.c('user'):
            cmd = ('<commit><partial><admin><member>%s</member></admin></partial></commit>'
                   % escape(self.c('user')))
        else:
            cmd = '<commit></commit>'
        root = self.call({'type': 'commit', 'cmd': cmd}, what='committing')
        job = root.findtext('.//job')
        if not job:
            self.ctx.step('nothing to commit')
            return 'nothing to commit'
        self.ctx.step('commit job %s started' % job)
        end = time.time() + wait
        while True:
            r = self.call({'type': 'op', 'cmd': '<show><jobs><id>%s</id></jobs></show>'
                           % escape(job)}, what='asking for the commit')
            status = r.findtext('.//job/status')
            if status == 'FIN':
                result = r.findtext('.//job/result')
                if result != 'OK':
                    details = ' '.join(t.strip() for t in r.find('.//job').itertext()
                                       if t.strip())[-300:]
                    raise PluginError('the commit failed: %s' % details)
                self.ctx.step('committed (job %s)' % job, 'ok')
                return 'committed'
            if self.ctx.cancelled() or time.time() > end:
                raise PluginError('the commit (job %s) has not finished in %ds' % (job, wait))
            self._sleep(5)
