# -*- coding: utf-8 -*-
"""
Cisco Catalyst Center (formerly DNA Center) - its system certificate (Controller: the GUI,
the northbound Intent API, PnP, telemetry) and/or the Disaster Recovery one, replaced
through the Intent API; Catalyst Center restarts its web services and signs everybody out.

    POST /dna/system/api/v1/auth/token        (HTTP basic) -> {"Token": ...}; then X-Auth-Token
    POST /dna/intent/api/v1/certificate?listOfUsers=server[,ipsec]
         multipart: certFileUpload (the certificate, then its chain, in order), pkFileUpload
    POST /dna/intent/api/v1/certificate-p12?listOfUsers=...&p12Password=...
         multipart: p12FileUpload                             (PKCS#12, when asked)
         -> {"response": {"taskId", "url"}}
    GET  /dna/intent/api/v1/task/<taskId>     -> {"response": {"isError", "progress",
                                                 "failureReason", "endTime"}}  (while it answers)

One module for Catalyst Center 2.3.7.x, 3.1.x and 3.3.x: the guide finds the same two
calls in all (Cisco's SDK dnacentersdk 3.1.6.0 authentication_management.import_certificate /
import_certificate_p12, the Ansible modules authentication_import_certificate[_p12] from
2.3.7.6 on). Catalyst Center has no call that lists the system certificate, so the same
certificate deployed again is known by what acme remembers.

Sources (the vendor guide navody/certifikaty/cisco/catalyst-center.md and what it cites):
    https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-3-x/admin-guide/cisco-catalyst-center-admin-guide-3-3-x/manage-certificates/c_certificate_support.html
    https://developer.cisco.com/docs/dna-center/#!import-certificate
    https://github.com/cisco-en-programmability/dnacentersdk/blob/master/dnacentersdk/api/v3_1_6_0/authentication_management.py

Less certain: the shape of the import's answer and of the task (the usual Intent API ones -
the guide could not check them for this call); whether a key without a password needs
pkPassword (acme sends the key unencrypted and no pkPassword); whether the REST API bundle
must be enabled on 3.x (Platform > Manage > Bundles on 2.3.x).
"""
from __future__ import annotations

import base64
import time
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_int, text, random_password, http_fields, tls_fields,
    verify_fields, multipart)

USERS = [['server', 'Controller (the system certificate: GUI, API, PnP)'],
         ['ipsec', 'Disaster Recovery (ipsec)'],
         ['server,ipsec', 'both']]


class CiscoCatalystCenterTarget(HttpTarget):
    kind = 'cisco_catalyst_center'
    title = 'Cisco Catalyst Center (DNA Center)'
    vendor = 'Cisco'
    description = ('Replaces the system certificate of Catalyst Center (the GUI, Intent API, '
                   'PnP, telemetry) and/or its Disaster Recovery certificate through the '
                   'Intent API; it restarts its web services and signs everybody out. '
                   'Catalyst Center 2.3.7, 3.1 and 3.3.')
    doc = 'targets.md'
    discovery = False
    fields = http_fields(443, 'catalyst.example.local') + [
        field('user', 'User', 'text', required=True, default='acme',
              help='a user with SUPER-ADMIN-ROLE, or a role of its own with System '
                   'Management and the APIs'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('used_for', 'Used for', 'select', default='server', options=USERS),
        field('format', 'Upload as', 'select', default='pem', advanced=True,
              options=[['pem', 'PEM chain + key'], ['pkcs12', 'PKCS#12']]),
        field('task_wait', 'Wait for the import (s)', 'number', default=300, advanced=True,
              help='Catalyst Center restarts its services after the import; acme follows the '
                   'task while it answers'),
    ] + verify_fields()
    served_wait = (20, 15)

    token = None

    def auth_headers(self):
        return {'X-Auth-Token': self.token} if self.token else {}

    def login(self):
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        try:
            st, hd, d = self.req('POST', '/dna/system/api/v1/auth/token', b'',
                                 {'Authorization': 'Basic ' +
                                  base64.b64encode(raw.encode()).decode()},
                                 auth=False, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry=False)
        tok = d.get('Token') if isinstance(d, dict) else None
        if not tok:
            raise PluginError('Catalyst Center gave no token', retry=False)
        self.token = text(tok)

    def test(self):
        self.login()
        return 'signed in to Catalyst Center %s' % self.c('host')

    def served_places(self, options):
        if not self.c('host') or 'server' not in text((options or {}).get('used_for')
                                                      or 'server'):
            return []
        return [(self.c('host'), as_int(self.c('port', 443), 443))]

    def deploy(self, bundle, options):
        options = options or {}
        users = text(self.opt(options, 'used_for', 'server')) or 'server'
        if users not in [u for u, _w in USERS]:
            raise PluginError('"%s" is not what the certificate can be used for (server, '
                              'ipsec)' % users, retry=False)
        if self.unchanged(bundle, options):
            return self.same(bundle, 'the certificate of Catalyst Center')
        self.login()
        q = {'listOfUsers': users}
        if self.opt(options, 'format', 'pem') == 'pkcs12':
            pw = random_password(20)
            q['p12Password'] = pw
            body, ctype = multipart([('p12FileUpload', ('acme.p12', bundle.as_format(
                'pfx', password=pw), 'application/x-pkcs12'))])
            path = '/dna/intent/api/v1/certificate-p12'
        else:
            # the certificate first, then the CAs in the order of the chain (the guide)
            body, ctype = multipart([
                ('certFileUpload', ('acme-chain.pem', bundle.as_format('fullchain-pem'),
                                    'application/x-pem-file')),
                ('pkFileUpload', ('acme.key', bundle.as_format('key-pem'),
                                  'application/x-pem-file'))])
            path = '/dna/intent/api/v1/certificate'
        st, hd, d = self.req('POST', path + '?' + urllib.parse.urlencode(q), body,
                             {'Content-Type': ctype}, what='importing the certificate',
                             timeout=180)
        r = (d.get('response') if isinstance(d, dict) else None) or {}
        task = text(r.get('taskId')) if isinstance(r, dict) else ''
        self.ctx.step('Catalyst Center took the certificate for %s%s' % (
            users, ' (task %s)' % task if task else ''), 'ok')
        if task:
            self.follow(task, as_int(self.opt(options, 'task_wait', 300), 300))
        self.ctx.step('Catalyst Center restarts its web services and signs everybody out '
                      '(about 2 minutes)', 'warn')
        self.remember(bundle, options)
        return 'the %s certificate of Catalyst Center replaced' % users

    def follow(self, task, wait):
        sleep = getattr(self, '_sleep', time.sleep)
        until = time.time() + max(10, wait)
        while True:
            try:
                st, hd, d = self.req('GET', '/dna/intent/api/v1/task/%s'
                                     % urllib.parse.quote(task, safe=''),
                                     what='reading the task %s' % task)
            except PluginError as e:
                # its services restart after an import: the session ends with them
                self.ctx.step('the task %s cannot be read any more (%s) - Catalyst Center '
                              'restarts' % (task, e), 'warn')
                return
            r = (d.get('response') if isinstance(d, dict) else None) or {}
            if r.get('isError') in (True, 'true'):
                raise PluginError('Catalyst Center refused the certificate: %s' % (
                    r.get('failureReason') or r.get('progress') or '?'), detail=text(d)[:4000],
                    retry=False)
            if r.get('endTime'):
                self.ctx.step('the import is done: %s' % (r.get('progress') or 'ok'), 'ok')
                return
            if time.time() > until or self.ctx.cancelled():
                self.ctx.step('the task %s is still running: %s' % (task, r.get('progress')
                                                                   or '?'), 'warn')
                return
            sleep(5)
