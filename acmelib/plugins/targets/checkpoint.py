# -*- coding: utf-8 -*-
"""
Check Point (Security Management / Multi-Domain, Management API): the
certificate imported as a server certificate (PKCS#12, base64) under a dated
name - or into one object kept in place - the HTTPS Inspection rules asked
for pointed at it, the portals of a gateway given it, the session published,
the policy installed, older acme objects no longer used deleted; signed out.

    POST /web_api/[<v>/]login        {"user", "password"} | {"api-key"} [+ "domain"]
                                     -> {"sid"}; then the header X-chkp-sid: <sid>
    POST /web_api/show-server-certificate    {"name"}            there already? (404: no)
    POST /web_api/add-server-certificate     {"name", "base64-certificate" (p12),
                                              "base64-password", "comments"}
    POST /web_api/set-server-certificate     {"name", "base64-certificate", "base64-password"}
    POST /web_api/set-https-rule     {"layer", "uid" | "name" | "rule-number", "certificate"}
    POST /web_api/set-simple-gateway | set-simple-cluster   {"name",
            "platform-portal-settings" | "usercheck-portal-settings":
                {"certificate-settings": {"base64-certificate", "base64-password"}},
            "identity-awareness-settings": {"browser-based-authentication-settings":
                {"browser-based-authentication-portal-settings": {"certificate-settings"}}},
            "vpn-settings": {"saml-portal-settings": {"certificate-settings"}}}
    POST /web_api/show-server-certificates   {"limit", "offset"}  the older ones
    POST /web_api/where-used         {"name"} -> "used-directly": {"total"}
    POST /web_api/delete-server-certificate  {"name"}
    POST /web_api/publish            {} -> {"task-id"};  show-task {"task-id"} until done
    POST /web_api/install-policy     {"policy-package", "access": true, "targets"} -> task
    POST /web_api/discard            (when something failed before publishing)
    POST /web_api/logout

Checked against (the user's collection of the vendor's documents, api-docs/checkpoint/):
    notes.md - quotes from
      https://sc1.checkpoint.com/documents/latest/APIs/index.html
      https://sc1.checkpoint.com/documents/latest/APIs/data/v2.2/introduction.html
      https://sc1.checkpoint.com/documents/latest/APIs/data/v2.2/api_versions.html
      https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_ThreatPrevention_AdminGuide/Topics-SECMG/HTTPS-Inspection.htm
      https://github.com/CheckPointSW/terraform-provider-checkpoint (set-server-certificate on update)
    mgmt-api-v2.2-apis.json - https://sc1.checkpoint.com/documents/latest/APIs/data/v2.2/dynamic/apis.json
      (the request fields and required fields of every command above, the task statuses
      "in progress" / "succeeded" / "succeeded with warnings" / "partially succeeded" /
      "failed", the WhereUsedReportReply)

Less certain:
    - whether a change of a portal's certificate-settings needs install-policy (the
      documents do not say; acme installs when a policy package is set);
    - that HTTPS Inspection goes with the Access Control policy ("access": true) - the
      admin guide says only "After creating the rules, install the Access Control Policy";
    - what delete-server-certificate answers for an object still in use (where-used is
      asked first, and one in use is not deleted);
    - which PKCS#12 encryption the Management server takes: 3DES (p12-legacy) by default,
      AES (pfx) as an option;
    - the shape of the rules in show-https-rulebase (sections holding "rulebase" lists)
      is read loosely for the list to pick from.
"""
from __future__ import annotations

import base64
import re
import time

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, as_int, text, object_name, name_prefix,
    ours, prune, http_fields, tls_fields, verify_fields, keep_field, random_password, fp_of)

UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
PORTALS = (
    ('portal_platform', 'the Gaia platform portal', ('platform-portal-settings',)),
    ('portal_usercheck', 'the UserCheck portal', ('usercheck-portal-settings',)),
    ('portal_captive', 'the Identity Awareness captive portal',
     ('identity-awareness-settings', 'browser-based-authentication-settings',
      'browser-based-authentication-portal-settings')),
    ('portal_saml', 'the SAML portal of the VPN', ('vpn-settings', 'saml-portal-settings')),
)


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


def rules_of(rulebase):
    """Every rule of a show-https-rulebase answer: sections hold rules of their own."""
    out = []
    for r in rulebase or []:
        if not isinstance(r, dict):
            continue
        if isinstance(r.get('rulebase'), list):
            out += rules_of(r['rulebase'])
        elif r.get('uid') and (r.get('rule-number') is not None or
                               text(r.get('type')).endswith('rule')):
            out.append(r)
    return out


class CheckPointTarget(HttpTarget):
    kind = 'checkpoint'
    title = 'Check Point (Management API)'
    vendor = 'Check Point'
    description = ('Imports the certificate as a server certificate through the Check Point '
                   'Management API, points HTTPS Inspection rules and gateway portals at it, '
                   'publishes and installs the policy.')
    doc = 'targets.md'
    fields = http_fields(443, 'mgmt.example.local') + [
        field('auth', 'Sign in with', 'select', default='password',
              options=[['password', 'a user and password'], ['api_key', 'an API key']]),
        field('user', 'User', 'text', default='admin', show_if={'auth': ['password']}),
        field('password', 'Password', 'secret', show_if={'auth': ['password']}),
        field('api_key', 'API key', 'secret', show_if={'auth': ['api_key']},
              help='SmartConsole → the administrator → Authentication method: API key'),
        field('domain', 'Domain', 'text', advanced=True,
              help='Multi-Domain Server: the domain (name or UID) to sign in to; empty: the '
                   'default one'),
        field('api_version', 'API version', 'text', advanced=True, placeholder='v1.9',
              help='empty: the newest the server has; v1.6 (R80.40) or later is needed'),
    ] + tls_fields()
    deploy_fields = [
        field('object', 'Server certificate object', 'text', placeholder='www-example-com',
              help='empty: a new object of a dated name each time, the rules pointed at it and '
                   'the older one deleted; a name: that one object, its certificate replaced '
                   'in place (set-server-certificate), made when it is not there'),
        field('https_rule', 'HTTPS Inspection rule', 'catalog', catalog='https_rules',
              autoload=False,
              help='the inbound rule to use the certificate (its Certificate column); picked '
                   'from the list, the layer below is filled in'),
        field('https_rules', 'More HTTPS Inspection rules', 'list', placeholder='Inbound www',
              help='one a line: the name, UID or number of each rule, in the layer below'),
        field('https_layer', 'HTTPS Inspection layer', 'text', placeholder='Default Layer',
              help='the layer that holds the rules (show-https-layers lists them)'),
        field('gateway', 'Gateway or cluster (portals)', 'catalog', catalog='gateways',
              autoload=False,
              help='the gateway object whose portals get the certificate; empty: none'),
        field('gateway_type', 'It is', 'select', default='simple-gateway',
              options=[['simple-gateway', 'a gateway'], ['simple-cluster', 'a cluster']]),
        field('portal_platform', 'Gaia platform portal', 'bool', default=False),
        field('portal_usercheck', 'UserCheck portal', 'bool', default=False),
        field('portal_captive', 'Identity Awareness captive portal', 'bool', default=False),
        field('portal_saml', 'SAML portal of the VPN', 'bool', default=False,
              help='API v2.1 (R82.10) or later'),
        field('policy_package', 'Install the policy package', 'catalog', catalog='packages',
              autoload=False,
              help='after publishing, the Access Control policy of this package is installed; '
                   'empty: only published (install it yourself)'),
        field('install_targets', 'Install on', 'list', placeholder='gw-cluster-1',
              help='one a line: the gateways to install on; empty: the package\'s targets'),
        field('p12_format', 'PKCS#12 encryption', 'select', default='p12-legacy',
              advanced=True,
              options=[['p12-legacy', '3DES (works with every version)'],
                       ['pfx', 'AES-256 (newer versions)']]),
        field('task_timeout', 'Wait for publish and install (s)', 'number', default=900,
              advanced=True),
        keep_field(1),
    ] + verify_fields()
    actions = [{'key': 'look', 'label': 'List the server certificates',
                'help': 'Signs in read-only and lists the server certificates, the HTTPS '
                        'Inspection layers and the gateways - it changes nothing.',
                'changes': False}]

    _sleep = staticmethod(time.sleep)
    sid = None

    # -- the session ------------------------------------------------------------------------
    def auth_headers(self):
        return {'X-chkp-sid': self.sid} if self.sid else {}

    def cmd_path(self, cmd):
        v = text(self.c('api_version')).strip().strip('/')
        return '/web_api/%s%s' % (v + '/' if v else '', cmd)

    def call(self, cmd, body=None, ok=None, what=None):
        st, hd, d = self.req('POST', self.cmd_path(cmd), body if body is not None else {},
                             ok=ok, what=what or cmd)
        return st, (d if isinstance(d, dict) else {})

    def http_error(self, status, parsed, raw, method, path, what=None):
        if isinstance(parsed, dict) and (parsed.get('message') or parsed.get('errors')):
            said = [text(parsed.get('message'))] if parsed.get('message') else []
            for k in ('errors', 'blocking-errors', 'warnings'):
                for e in parsed.get(k) or []:
                    said.append(text(e.get('message') if isinstance(e, dict) else e))
            head = ('not allowed (%d)' % status if status in (401, 403)
                    else 'the Management server said %d' % status)
            return '%s: %s - %s' % (what or path, head, '; '.join(w for w in said if w)[:600])
        return HttpTarget.http_error(self, status, parsed, raw, method, path, what)

    def login(self, read_only=False):
        body = {}
        if self.c('auth', 'password') == 'api_key':
            body['api-key'] = self.c('api_key') or ''
        else:
            body.update({'user': self.c('user') or '', 'password': self.c('password') or ''})
        if text(self.c('domain')).strip():
            body['domain'] = text(self.c('domain')).strip()
        if read_only:
            body['read-only'] = True
        else:
            body.update({'session-name': 'acme', 'session-description':
                         'acme puts a certificate in place'})
        try:
            st, d = self.call('login', body, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry=False)
        if not d.get('sid'):
            raise PluginError('the Management server gave no session (sid)', retry=False)
        self.sid = text(d['sid'])

    def logout(self, discard=False):
        if not self.sid:
            return
        if discard:
            try:
                self.call('discard', what='discarding the unpublished changes')
                self.ctx.step('discarded the changes of the session (nothing was published)',
                              'warn')
            except PluginError:
                pass
        try:
            self.call('logout', ok=range(0, 600))
        except PluginError:
            pass
        self.sid = None

    def wait_task(self, task, what, timeout):
        end = time.time() + timeout
        while True:
            st, d = self.call('show-task', {'task-id': task}, what='asking how %s goes' % what)
            tasks = [t for t in d.get('tasks') or [] if isinstance(t, dict)]
            status = text(tasks[0].get('status')).lower() if tasks else ''
            if status and status != 'in progress':
                if status in ('succeeded', 'succeeded with warnings'):
                    self.ctx.step('%s: %s' % (what, status), 'ok')
                    return status
                det = tasks[0].get('task-details') or tasks[0].get('progress-description') or ''
                raise PluginError('%s: %s' % (what, status), detail=text(det)[:4000])
            if self.ctx.cancelled() or time.time() > end:
                raise PluginError('%s has not finished in %d s' % (what, timeout))
            self._sleep(3)

    # -- what is there ----------------------------------------------------------------------
    def exists(self, name):
        st, d = self.call('show-server-certificate', {'name': name}, ok=(200, 404),
                          what='looking for %s' % name)
        return st == 200

    def paged(self, cmd, body=None, key='objects'):
        out, offset = [], 0
        while offset < 20000:
            b = dict(body or {})
            b.update({'limit': 500, 'offset': offset})
            st, d = self.call(cmd, b, what='listing (%s)' % cmd)
            got = [o for o in d.get(key) or [] if isinstance(o, dict)]
            out += got
            total = as_int(d.get('total'), 0)
            offset += len(got)
            if not got or offset >= total:
                break
        return out

    def server_certs(self):
        return [text(o.get('name')) for o in self.paged('show-server-certificates')
                if o.get('name')]

    def used(self, name):
        st, d = self.call('where-used', {'name': name}, what='asking where %s is used' % name)
        return as_int((d.get('used-directly') or {}).get('total'), 0)

    # -- the lists the deployment's form picks from (read-only) ------------------------------
    def catalog(self, key):
        if key not in ('https_rules', 'gateways', 'packages'):
            raise PluginError('there is no list called %s here' % key, retry=False)
        self.login(read_only=True)
        try:
            opts, sets = [], {}
            if key == 'https_rules':
                for layer in self.paged('show-https-layers', key='https-layers') or []:
                    lname = text(layer.get('name'))
                    st, d = self.call('show-https-rulebase', {'name': lname, 'limit': 500},
                                      what='reading the layer %s' % lname)
                    for r in rules_of(d.get('rulebase')):
                        uid = text(r.get('uid'))
                        opts.append([uid, '%s: %s%s' % (lname, r.get('name') or uid,
                                                        ' (#%s)' % r['rule-number']
                                                        if r.get('rule-number') else '')])
                        sets[uid] = {'https_layer': lname}
            elif key == 'gateways':
                for cmd, kind in (('show-simple-gateways', 'simple-gateway'),
                                  ('show-simple-clusters', 'simple-cluster')):
                    try:
                        objs = self.paged(cmd)
                    except PluginError as e:
                        self.ctx.step('%s: %s' % (cmd, e), 'warn')
                        continue
                    for o in objs:
                        n = text(o.get('name'))
                        if n:
                            opts.append([n, '%s (%s)' % (n, 'cluster' if kind == 'simple-cluster'
                                                         else 'gateway')])
                            sets[n] = {'gateway_type': kind}
            else:
                for o in self.paged('show-packages', key='packages'):
                    if o.get('name'):
                        opts.append([text(o['name']), text(o['name'])])
            return {'options': opts, 'sets': sets, 'said': '%d' % len(opts)}
        finally:
            self.logout()

    def test(self):
        self.login(read_only=True)
        try:
            st, d = self.call('show-api-versions', what='reading the API version')
            n = len(self.paged('show-server-certificates'))
            return 'signed in to %s, Management API %s; %d server certificate%s' % (
                self.c('host'), d.get('current-version') or '?', n, '' if n == 1 else 's')
        finally:
            self.logout()

    def action(self, key):
        if key != 'look':
            return HttpTarget.action(self, key)
        self.login(read_only=True)
        try:
            names = self.server_certs()
            for n in names:
                self.ctx.step('server certificate %s%s' % (n, ' (acme)' if n.startswith('acme-')
                                                             else ''))
            try:
                for layer in self.paged('show-https-layers', key='https-layers'):
                    self.ctx.step('HTTPS Inspection layer %s' % layer.get('name'))
            except PluginError as e:
                self.ctx.step('the HTTPS Inspection layers cannot be listed: %s' % e, 'warn')
            for cmd in ('show-simple-gateways', 'show-simple-clusters'):
                try:
                    for o in self.paged(cmd):
                        self.ctx.step('%s %s' % ('cluster' if 'cluster' in cmd else 'gateway',
                                                 o.get('name')))
                except PluginError as e:
                    self.ctx.step('%s: %s' % (cmd, e), 'warn')
            return '%d server certificate%s' % (len(names), '' if len(names) == 1 else 's')
        finally:
            self.logout()

    # -- the work ---------------------------------------------------------------------------
    def p12(self, bundle, options):
        pw = random_password(20)
        fmt = text(self.opt(options, 'p12_format', 'p12-legacy'))
        if fmt not in ('p12-legacy', 'pfx', 'p12'):
            fmt = 'p12-legacy'
        return b64(bundle.as_format(fmt, password=pw)), b64(pw)

    def rule_refs(self, options):
        refs = []
        one = text(options.get('https_rule')).strip()
        if one:
            refs.append(one)
        refs += [r for r in lines(options.get('https_rules')) if r not in refs]
        return refs

    def deploy(self, bundle, options):
        options = options or {}
        fixed = text(options.get('object')).strip()
        name = fixed or object_name(bundle, options, maxlen=63)
        prefix = name_prefix(bundle, options, maxlen=63)
        rules = self.rule_refs(options)
        layer = text(options.get('https_layer')).strip()
        if rules and not layer:
            raise PluginError('HTTPS Inspection rules are given but no layer: set the HTTPS '
                              'Inspection layer', retry=False)
        gw = text(options.get('gateway')).strip()
        portals = [p for p in PORTALS if as_bool(options.get(p[0]))]
        if portals and not gw:
            raise PluginError('portals are chosen but no gateway: set the gateway or cluster',
                              retry=False)
        self.login()
        published = False
        try:
            there = self.exists(name)
            if self.unchanged(bundle, options, present=lambda: there):
                published = True
                return self.same(bundle, 'as %s' % name)
            did = []
            cert64, pw64 = self.p12(bundle, options)
            if there and fixed:
                self.call('set-server-certificate', {'name': name, 'base64-certificate': cert64,
                                                     'base64-password': pw64},
                          what='replacing the certificate of %s' % name)
                self.ctx.step('replaced the certificate of the object %s in place' % name, 'ok')
                did.append('replaced %s' % name)
            elif not there:
                self.call('add-server-certificate', {
                    'name': name, 'base64-certificate': cert64, 'base64-password': pw64,
                    'comments': 'acme %s' % fp_of(bundle)[:16]},
                    what='importing %s' % name)
                self.ctx.step('imported the server certificate %s' % name, 'ok')
                did.append('imported %s' % name)
            else:
                self.ctx.step('the server certificate %s is there already' % name)
            for ref in rules:
                body = {'layer': layer, 'certificate': name}
                if UUID_RE.match(ref):
                    body['uid'] = ref
                elif ref.isdigit():
                    body['rule-number'] = int(ref)
                else:
                    body['name'] = ref
                self.call('set-https-rule', body,
                          what='pointing the HTTPS Inspection rule %s at %s' % (ref, name))
                self.ctx.step('the HTTPS Inspection rule %s uses %s' % (ref, name), 'ok')
                did.append('rule %s' % ref)
            if portals:
                kind = text(options.get('gateway_type') or 'simple-gateway')
                if kind not in ('simple-gateway', 'simple-cluster'):
                    kind = 'simple-gateway'
                body = {'name': gw}
                for _k, words, path in portals:
                    p12, pw = self.p12(bundle, options)
                    node = body
                    for part in path:
                        node = node.setdefault(part, {})
                    node['certificate-settings'] = {'base64-certificate': p12,
                                                    'base64-password': pw}
                self.call('set-%s' % kind, body,
                          what='giving the portals of %s the certificate' % gw)
                self.ctx.step('%s: %s use the certificate' % (
                    gw, ', '.join(w for _k, w, _p in portals)), 'ok')
                did.append('%s portals' % gw)
            if not fixed:
                self.cleanup(prefix, name, self.keep(options))
            timeout = float(as_int(self.opt(options, 'task_timeout', 900), 900))
            st, d = self.call('publish', what='publishing')
            published = True
            if d.get('task-id'):
                self.wait_task(d['task-id'], 'publishing', timeout)
            self.ctx.step('published the session', 'ok')
            pkg = text(options.get('policy_package')).strip()
            if pkg:
                body = {'policy-package': pkg, 'access': True, 'threat-prevention': False}
                tg = lines(options.get('install_targets'))
                if tg:
                    body['targets'] = tg
                st, d = self.call('install-policy', body,
                                  what='installing the policy %s' % pkg)
                if d.get('task-id'):
                    self.wait_task(d['task-id'], 'installing the policy %s' % pkg, timeout)
                did.append('policy %s installed' % pkg)
            else:
                self.ctx.step('published, the policy is not installed here (no policy package '
                              'is set): install it from SmartConsole', 'warn')
            self.remember(bundle, options)
            return ', '.join(did) or 'already %s' % name
        finally:
            self.logout(discard=not published)

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            names = [n for n in self.server_certs() if ours(n, prefix)]
        except PluginError as e:
            self.ctx.step('the older server certificates cannot be listed: %s' % e, 'warn')
            return
        for old in prune(names, prefix, keep, current):
            try:
                n = self.used(old)
                if n:
                    self.ctx.step('the older %s stays: it is still used (%d)' % (old, n), 'warn')
                    continue
                self.call('delete-server-certificate', {'name': old},
                          what='deleting the older %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')
