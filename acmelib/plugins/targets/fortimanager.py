# -*- coding: utf-8 -*-
"""
FortiManager / FortiAnalyzer (JSON-RPC with an API token): the certificate added as a
local certificate of the system under a dated name (its key encrypted with a one-time
password, as the CLI takes it), the intermediates as CA certificates, the HTTPS
certificate of the GUI and the JSON-RPC API (admin setting admin_server_cert) pointed at
it, older acme certificates deleted.

    POST /jsonrpc  {"id", "method", "params": [{"url", "data"}]}
         Authorization: Bearer <token>  (FMG/FAZ 7.2.2 and later; from 7.4.7 / 7.6.2 the
         header only - never ?access_token=)
         -> {"result": [{"status": {"code": 0, "message": "OK"}, "data": ...}]}
    get    /cli/global/system/admin/setting                    signing in; admin_server_cert
    get    /cli/global/system/certificate/local[/<name>]       there already? older ones
    add    /cli/global/system/certificate/local   {"name", "comment", "password",
                                                   "private-key", "certificate"}
    add    /cli/global/system/certificate/ca      {"name", "ca"}       (the intermediates)
    set    /cli/global/system/admin/setting       {"admin_server_cert"}
    delete /cli/global/system/certificate/local/<name>

Checked against the vendor guide of 2026-11 (fortinet.md: FortiManager CLI reference
7.6.3 / 7.6.7 - "config system certificate local", "config system admin setting"
admin_server_cert, "config system admin user" user_type api / rpc-permit; KB 276351 (API
tokens), KB 231395 / 189844; Fortinet's Ansible collection fortinet.fortimanager -
fmgr_system_certificate_local, fmgr_system_certificate_ca, fmgr_system_admin_setting).
The calls are the same on FortiManager and FortiAnalyzer 7.2.2 - 7.6 (the GUI moved the
setting from Admin Settings to Settings in 7.4 - not the API).

Less certain (the guide's "unverified" points):
    - the JSON-RPC body of "add /cli/global/system/certificate/local" (an unofficial
      how-to; its fields are the official CLI's and Ansible's) and the url of the admin
      setting (from the CLI);
    - the CA certificate's field "ca" (Ansible's fmgr_system_certificate_ca) - a CA that
      is refused (there already) is said and skipped;
    - "delete" of an older local certificate (the standard JSON-RPC method; one still in
      use is refused by FortiManager and kept);
    - the least admin profile that may write these (the KB uses Super_User);
    - whether the web server restarts (sessions signed out) - not documented.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, text, as_bool, as_int, object_name, name_prefix, ours,
    prune, chain_list, chain_id, random_password, fp_of, http_fields, tls_fields,
    verify_fields, keep_field)

LOCAL = '/cli/global/system/certificate/local'
CA = '/cli/global/system/certificate/ca'
SETTING = '/cli/global/system/admin/setting'
NOT_THERE = (-3,)           # "Object does not exist"


class FortiManagerTarget(HttpTarget):
    kind = 'fortimanager'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'FortiManager / FortiAnalyzer'
    vendor = 'Fortinet'
    description = ('Adds the certificate as a local certificate of a FortiManager or '
                   'FortiAnalyzer through JSON-RPC, makes it the HTTPS certificate of the GUI '
                   'and the API (admin_server_cert) and deletes older ones. FortiManager / '
                   'FortiAnalyzer 7.2.2 - 7.6 (API token).')
    doc = 'targets.md'
    fields = http_fields(443, 'fmg.example.local') + [
        field('token', 'API token', 'secret', required=True,
              help='execute api-user generate-key <user> (a user of type api, rpc-permit '
                   'read-write)'),
    ] + tls_fields()
    deploy_fields = [
        field('admin_gui', 'HTTPS certificate of the GUI and API', 'bool', default=True,
              help='config system admin setting / set admin_server_cert'),
        field('import_chain', 'Add the intermediates as CA certificates', 'bool', default=True,
              advanced=True),
        keep_field(2),
    ] + verify_fields()

    served_wait = (6, 5)
    _id = 0

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % text(self.c('token'))}

    def rpc(self, method, url, data=None, what=None, missing_ok=False):
        """One JSON-RPC request -> (code, data). A code other than 0 is a PluginError
        (missing_ok: -3, "Object does not exist", comes back as it is)."""
        self._id += 1
        p = {'url': url}
        if data is not None:
            p['data'] = data
        st, hd, d = self.req('POST', '/jsonrpc', {'id': self._id, 'method': method,
                                                  'params': [p]}, what=what or url)
        res = (d or {}).get('result') if isinstance(d, dict) else None
        res = res[0] if isinstance(res, list) and res else (res if isinstance(res, dict) else {})
        status = res.get('status') or {}
        code = as_int(status.get('code'), -1) if isinstance(status, dict) else -1
        if code == 0 or (missing_ok and code in NOT_THERE):
            return code, res.get('data')
        msg = text(status.get('message') if isinstance(status, dict) else '') or 'no answer'
        raise PluginError('%s: FortiManager said %s (%s)' % (what or url, msg, code),
                          detail=text(d)[:4000],
                          retry=code not in (-11, -6, -3, -2, -10, -20, -22))

    def test(self):
        code, d = self.rpc('get', SETTING, what='signing in')
        cur = text(d.get('admin_server_cert') if isinstance(d, dict) else '')
        return 'signed in to %s; the GUI uses %s' % (self.c('host'), cur or '?')

    def served_places(self, options):
        if not as_bool(self.opt(options, 'admin_gui', True), True):
            return []
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []

    def exists(self, name):
        code, d = self.rpc('get', '%s/%s' % (LOCAL, urllib.parse.quote(name, safe='')),
                           what='looking for %s' % name, missing_ok=True)
        return code == 0

    def names(self):
        code, d = self.rpc('get', LOCAL, what='listing the local certificates')
        return [text(x.get('name')) for x in (d if isinstance(d, list) else [])
                if isinstance(x, dict) and x.get('name')]

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=35, serial_len=6)
        prefix = name_prefix(bundle, options, maxlen=35, serial_len=6)
        there = self.exists(name)
        if self.unchanged(bundle, options, present=lambda: there):
            return self.same(bundle, 'as %s' % name)
        did = []
        if there:
            self.ctx.step('%s is there already' % name)
        else:
            pw = random_password(20)
            self.rpc('add', LOCAL, {
                'name': name, 'comment': 'acme %s' % fp_of(bundle)[:16], 'password': pw,
                'private-key': text(bundle.as_format('key-pem-enc', password=pw)),
                'certificate': text(bundle.as_format('cert-pem'))},
                what='adding %s' % name)
            self.ctx.step('added the local certificate %s' % name, 'ok')
            did.append('added %s' % name)
        if as_bool(self.opt(options, 'import_chain', True), True):
            for pem in chain_list(bundle):
                ca = 'acme-ca-%s' % chain_id(pem)
                try:
                    self.rpc('add', CA, {'name': ca, 'ca': pem}, what='adding the CA %s' % ca)
                    self.ctx.step('added the intermediate %s' % ca)
                except PluginError as e:
                    self.ctx.step('the CA %s is not added (there already?): %s' % (ca, e))
        current_gui = None
        if as_bool(self.opt(options, 'admin_gui', True), True):
            self.rpc('set', SETTING, {'admin_server_cert': name},
                     what='making %s the HTTPS certificate' % name)
            self.ctx.step('the GUI and the API use %s' % name, 'ok')
            did.append('GUI')
            current_gui = name
        self.cleanup(prefix, name, self.keep(options), current_gui)
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def cleanup(self, prefix, current, keep, gui):
        if keep < 0:
            return
        try:
            names = [n for n in self.names() if ours(n, prefix)]
            if gui is None:
                code, d = self.rpc('get', SETTING, what='reading the admin setting')
                gui = text(d.get('admin_server_cert') if isinstance(d, dict) else '')
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        for old in prune(names, prefix, keep, current):
            if old == gui:
                self.ctx.step('the older %s stays: the GUI still uses it' % old, 'warn')
                continue
            try:
                self.rpc('delete', '%s/%s' % (LOCAL, urllib.parse.quote(old, safe='')),
                         what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays (still used?): %s' % (old, e), 'warn')
