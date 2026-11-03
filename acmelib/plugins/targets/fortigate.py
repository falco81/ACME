# -*- coding: utf-8 -*-
"""
FortiGate (FortiOS REST API with an API token): the certificate imported
under a dated name, then used for the admin GUI, SSL VPN, SSL/SSH inspection
profiles and virtual IPs as asked; older acme ones deleted.

Checked against api-docs/fortigate/notes.md (Fortinet's Ansible modules and
admin guide): a virtual IP's ssl-certificate is a string up to FortiOS 7.4.1
and a list of {"name"} from 7.4.2, an SSL/SSH profile's server-cert a list
from 7.0.0 - the form is taken from the version the FortiGate says
(monitor/system/status), the other one tried when the version is not known
or the first is refused.
"""
from __future__ import annotations

import base64
import re
import urllib.parse

from acmelib.plugins.base import Plugin
from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, object_name, name_prefix, prune,
    http_fields, tls_fields, verify_fields, keep_field, chain_list, random_password, text)


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


class FortiGateTarget(HttpTarget):
    kind = 'fortigate'
    title = 'FortiGate'
    vendor = 'Fortinet'
    description = ('Imports the certificate through the FortiOS REST API and uses it for the '
                   'admin GUI, SSL VPN, inspection profiles and virtual IPs; deletes older '
                   'ones acme put there.')
    doc = 'targets.md'
    fields = http_fields(443, 'fw.example.local') + [
        field('token', 'API token', 'secret', required=True,
              help='System → Administrators → REST API Admin'),
        field('vdom', 'VDOM', 'text', default='root',
              help='empty on a FortiGate without VDOMs'),
    ] + tls_fields()
    deploy_fields = [
        field('admin', 'Admin GUI certificate', 'bool', default=False,
              help='system global admin-server-cert'),
        field('sslvpn', 'SSL VPN certificate', 'bool', default=False,
              help='vpn ssl settings servercert'),
        field('ssl_ssh_profiles', 'SSL/SSH inspection profiles', 'list',
              help='firewall ssl-ssh-profile names (server certificate of inbound inspection)'),
        field('vips', 'Virtual IPs', 'list', help='firewall vip names (ssl-certificate)'),
        field('vdom', 'VDOM', 'text', advanced=True, help='empty: the target\'s'),
        field('scope', 'Import into', 'select', default='global', advanced=True,
              options=[['global', 'global (every VDOM, the admin GUI)'], ['vdom', 'the VDOM']]),
        field('import_as', 'Import as', 'select', default='pkcs12', advanced=True,
              options=[['pkcs12', 'PKCS#12'], ['regular', 'certificate + key (PEM)']]),
        field('import_chain', 'Import the intermediates as CA certificates', 'bool',
              default=True, advanced=True),
        keep_field(2),
    ] + verify_fields()

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.c('token')}

    def vdom(self, options=None):
        return ((options or {}).get('vdom') or self.c('vdom') or '').strip()

    def path(self, p, vdom=None, **q):
        if vdom:
            q['vdom'] = vdom
        if q:
            p += ('&' if '?' in p else '?') + urllib.parse.urlencode(q)
        return p

    def api(self, method, p, body=None, ok=None, what=None, vdom=None, **q):
        st, hd, d = self.req(method, self.path(p, vdom, **q), body, ok=ok, what=what)
        if isinstance(d, dict) and st < 300 and d.get('status') == 'error':
            raise PluginError('%s: FortiOS said error %s' % (what or p, d.get('error', '?')),
                              detail=str(d))
        return st, d

    def test(self):
        st, d = self.api('GET', '/api/v2/monitor/system/status', what='signing in',
                         vdom=self.vdom())
        r = d.get('results') or {}
        return 'signed in to %s (%s), FortiOS %s' % (
            r.get('hostname', self.c('host')), r.get('model_name', d.get('serial', '?')),
            d.get('version', '?'))

    # -- discovery (1.0.29): the form filled in from the FortiGate --------------------------
    discover_keys = ['host', 'port', 'token', 'verify_tls']

    def discover_setup(self):
        """Read-only: monitor/system/status asked without a VDOM - the VDOM FortiOS answers
        in (the "vdom" of its answer) offered, its version, model and name shown. FortiOS
        lists its VDOMs only through calls acme does not make: another one is typed."""
        out = Plugin.discover_setup(self)
        st, d = self.api('GET', '/api/v2/monitor/system/status', what='signing in')
        r = d.get('results') or {}
        for label, v in (('FortiOS', d.get('version')), ('Model', r.get('model_name')),
                         ('Host name', r.get('hostname')), ('Serial number', d.get('serial'))):
            if text(v).strip():
                out['facts'].append([label, text(v).strip()])
        v = text(d.get('vdom')).strip()
        if v:
            self.offer(out, 'vdom', [['', 'Empty: a FortiGate without VDOMs'], [v, v]], pick=v)
            out['notes'].append('FortiOS says only the VDOM the token answers in - another '
                                'VDOM is typed by hand')
        return out

    def fos_version(self, vdom):
        """(major, minor, patch) of FortiOS, None when it cannot be read."""
        if '_fos' not in self.__dict__:
            ver = None
            try:
                st, d = self.api('GET', '/api/v2/monitor/system/status', vdom=vdom)
                m = re.match(r'^v?(\d+)\.(\d+)\.(\d+)', text(d.get('version')))
                if m:
                    ver = tuple(int(x) for x in m.groups())
            except PluginError as e:
                self.ctx.debug('the FortiOS version cannot be read: %s' % e)
            self._fos = ver
        return self._fos

    def list_first(self, since, vdom, default):
        """Whether a reference field is a [{name}] list on this FortiOS (since `since`)."""
        ver = self.fos_version(vdom)
        return default if ver is None else ver >= since

    def exists(self, name, vdom):
        st, d = self.api('GET', '/api/v2/cmdb/vpn.certificate/local/%s'
                         % urllib.parse.quote(name, safe=''), ok=(200, 404), vdom=vdom)
        return st == 200 and bool(d.get('results'))

    def set_ref(self, p, key, name, vdom, list_first, what):
        """Point an object at the certificate - as a string or a [{name}] list,
        whichever this FortiOS version takes."""
        forms = [[{'name': name}], name]
        if not list_first:
            forms.reverse()
        err = None
        for value in forms:
            try:
                self.api('PUT', p, {key: value}, vdom=vdom, what=what)
                return
            except PluginError as e:
                err = e
                if getattr(e, 'retry', True) is False and 'not found' in str(e):
                    raise
        raise err

    def deploy(self, bundle, options):
        options = options or {}
        vdom = self.vdom(options)
        name = object_name(bundle, options, maxlen=35, serial_len=6)
        prefix = name_prefix(bundle, options, maxlen=35, serial_len=6)
        scope = options.get('scope') or 'global'
        if self.unchanged(bundle, options, present=lambda: self.exists(name, vdom)):
            return self.same(bundle, 'as %s' % name)
        did = []
        if self.exists(name, vdom) and not as_bool(options.get('force')):
            self.ctx.step('%s is there already' % name)
        else:
            if (options.get('import_as') or 'pkcs12') == 'pkcs12':
                pw = random_password()
                body = {'type': 'pkcs12', 'certname': name, 'password': pw, 'scope': scope,
                        'file_content': b64(bundle.as_format('p12-legacy', password=pw,
                                                             alias=name))}
            else:
                body = {'type': 'regular', 'certname': name, 'scope': scope, 'password': '',
                        'file_content': b64(bundle.as_format('cert-pem')),
                        'key_file_content': b64(bundle.as_format('key-pem'))}
            self.api('POST', '/api/v2/monitor/vpn-certificate/local/import', body,
                     vdom=vdom if scope == 'vdom' else None, what='importing %s' % name)
            self.ctx.step('imported %s' % name, 'ok')
            did.append('imported %s' % name)
            if as_bool(self.opt(options, 'import_chain', True), True):
                for pem in chain_list(bundle):
                    try:
                        self.api('POST', '/api/v2/monitor/vpn-certificate/ca/import',
                                 {'import_method': 'file', 'scope': 'global',
                                  'file_content': b64(pem)}, what='importing a CA certificate')
                    except PluginError as e:
                        self.ctx.debug('CA certificate not imported (there already?): %s' % e)
        if as_bool(options.get('admin')):
            self.api('PUT', '/api/v2/cmdb/system/global', {'admin-server-cert': name},
                     what='setting the admin certificate')
            self.ctx.step('admin GUI uses %s' % name, 'ok')
            did.append('admin GUI')
        if as_bool(options.get('sslvpn')):
            self.api('PUT', '/api/v2/cmdb/vpn.ssl/settings', {'servercert': name}, vdom=vdom,
                     what='setting the SSL VPN certificate')
            self.ctx.step('SSL VPN uses %s' % name, 'ok')
            did.append('SSL VPN')
        for p in lines(options.get('ssl_ssh_profiles')):
            self.set_ref('/api/v2/cmdb/firewall/ssl-ssh-profile/%s' % urllib.parse.quote(p, safe=''),
                         'server-cert', name, vdom, self.list_first((7, 0, 0), vdom, True),
                         'setting profile %s' % p)
            self.ctx.step('profile %s uses %s' % (p, name), 'ok')
            did.append('profile %s' % p)
        for v in lines(options.get('vips')):
            self.set_ref('/api/v2/cmdb/firewall/vip/%s' % urllib.parse.quote(v, safe=''),
                         'ssl-certificate', name, vdom, self.list_first((7, 4, 2), vdom, False),
                         'setting VIP %s' % v)
            self.ctx.step('VIP %s uses %s' % (v, name), 'ok')
            did.append('VIP %s' % v)
        self.cleanup(prefix, name, vdom, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def cleanup(self, prefix, current, vdom, keep):
        if keep < 0:
            return
        try:
            st, d = self.api('GET', '/api/v2/cmdb/vpn.certificate/local', vdom=vdom,
                             format='name')
        except PluginError as e:
            self.ctx.step('the old certificates cannot be listed: %s' % e, 'warn')
            return
        names = [r.get('name', '') for r in d.get('results') or []]
        for old in prune(names, prefix, keep, current):
            try:
                self.api('DELETE', '/api/v2/cmdb/vpn.certificate/local/%s'
                         % urllib.parse.quote(old, safe=''), vdom=vdom,
                         what='deleting %s' % old)
                self.ctx.step('deleted the old %s' % old)
            except PluginError as e:
                self.ctx.step('the old %s stays (still used?): %s' % (old, e), 'warn')
