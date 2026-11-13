# -*- coding: utf-8 -*-
"""
HPE OneView (the VM appliance) and HPE Synergy Composer (OneView for Synergy): the
appliance's HTTPS certificate (web GUI, REST API, HPE SSO into the iLOs) replaced with
acme's key and certificate as PKCS#12, the intermediates put into its trust store first.

    GET    /rest/version                                   -> currentVersion (X-API-Version)
    POST   /rest/login-sessions {userName, password, authLoginDomain, loginMsgAck}
                                                           -> sessionID ("Auth" header)
    GET    /rest/certificates/ca/<alias>                   (an intermediate there already?)
    POST   /rest/certificates/ca  CertificateAuthorityInfoCollection   -> a task
    PUT    /rest/certificates/https/pkcs12?uploadfilename=acme.pfx
           multipart "file", headers Password + uploadfilename          -> a task
    GET    /rest/tasks/<id>                                -> taskState
    DELETE /rest/login-sessions                            (signing out)

Sources: HPE's own libraries (the OneView API reference is not machine-readable): the
POSH-HPEOneView 10.00 module (Install-OVApplianceCertificate / Upload-File: the PKCS#12
URI, PUT, the multipart field "file", the Password header; Add-OVApplianceTrustedCertificate:
the CA body), oneview-python (login, the API versions - 9200 = 11.50, 6600 = 9.00),
oneview-ansible-collection. The same /rest/certificates calls in OneView 9.x, 10.x and
11.x and on a Synergy Composer (endpoints-support.md lists no change): one module, the
X-API-Version the appliance says it takes (at most 9200, the newest read).

Facts from the documents: only RSA certificates for the appliance ("Currently, only RSA
certificates are supported for the appliance certificate") - an ECDSA one is refused
before anything is changed; the import is a task, after which the appliance reloads its
web services (sessions are cut, the VM is not restarted) and deploys its new SSO
certificate to the managed iLOs/OAs; the intermediate CA should be in the trust store
before (Infrastructure administrator).
Uncertain: the least role for the appliance certificate (taken: Infrastructure
administrator, unscoped); the headers of the PKCS#12 upload come from the PowerShell
module, not from the API reference.
"""
from __future__ import annotations

import time
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, http_fields, tls_fields, verify_fields,
    text, multipart, random_password, chain_list, chain_id, served_fingerprint, fp_of,
    split_hostport, join_hostport)
from acmelib.plugins.targets.redfish_ilo import key_family

API_NEWEST = 9200           # OneView 11.50 - the newest the documents were read for
API_OLDEST = 6600           # OneView 9.00
TASK_DONE = ('Completed', 'Warning', 'Error', 'Terminated', 'Killed')


class HpeOneViewTarget(HttpTarget):
    kind = 'hpe_oneview'
    discovery = False           # nothing to find: its fields are the sign-in
    title = 'HPE OneView / Synergy Composer'
    vendor = 'HPE'
    module_version = ''
    version_label = 'any version (detects it)'
    description = ('HPE OneView 9.x - 11.x and HPE Synergy Composer (OneView for Synergy): '
                   'imports the certificate with its key (PKCS#12) as the appliance\'s HTTPS '
                   'certificate through the REST API, the intermediates into its trust store '
                   'first. RSA keys only. The appliance reloads its web services.')
    doc = 'targets.md'
    fields = http_fields(443, 'oneview.example.local') + [
        field('user', 'User', 'text', required=True, default='svc-acme'),
        field('password', 'Password', 'secret', required=True),
        field('login_domain', 'Login domain', 'text', default='LOCAL',
              help='LOCAL, or the name of the directory (LDAP / AD) login domain'),
        field('api_version', 'API version', 'number', advanced=True,
              help='X-API-Version sent; empty: what the appliance says it takes (at most '
                   '9200)'),
    ] + tls_fields()
    deploy_fields = [
        field('import_chain', 'Put the intermediates into the trust store', 'bool',
              default=True, help='POST /rest/certificates/ca - HPE wants the issuing CA '
                                 'there before the appliance certificate'),
        field('task_wait', 'Wait for the import task (s)', 'number', default=300,
              advanced=True),
    ] + verify_fields()

    _sleep = staticmethod(time.sleep)
    session = None
    _api = None

    # -- the API ------------------------------------------------------------------------
    def api_version(self):
        if self._api is None:
            given = as_int(self.c('api_version'), 0)
            if given:
                self._api = given
            else:
                st, hd, d = self.req('GET', '/rest/version', auth=False,
                                     what='reading the API version')
                cur = as_int((d or {}).get('currentVersion') if isinstance(d, dict) else 0, 0)
                if not cur:
                    raise PluginError('the appliance did not say its API version '
                                      '(GET /rest/version) - is this HPE OneView?')
                if cur < API_OLDEST:
                    self.ctx.step('the appliance takes API %d - older than OneView 9.00 (%d), '
                                  'which this module was checked against' % (cur, API_OLDEST),
                                  'warn')
                self._api = min(cur, API_NEWEST)
        return self._api

    def auth_headers(self):
        h = {'X-API-Version': str(self.api_version())}
        if self.session:
            h['Auth'] = self.session
        return h

    def login(self):
        self.api_version()
        try:
            st, hd, d = self.req('POST', '/rest/login-sessions', {
                'userName': self.c('user'), 'password': self.c('password') or '',
                'authLoginDomain': self.c('login_domain') or 'LOCAL', 'loginMsgAck': True},
                what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry='(401)' not in str(e))
        self.session = (d or {}).get('sessionID') if isinstance(d, dict) else None
        if not self.session:
            raise PluginError('the appliance gave no sessionID on signing in')

    def logout(self):
        if self.session:
            try:
                self.req('DELETE', '/rest/login-sessions', ok=range(0, 600))
            except PluginError:
                pass
        self.session = None

    def task_of(self, hd, d):
        """The task URI an asynchronous call answered with, None when it said none."""
        loc = text((hd or {}).get('location'))
        if '/rest/tasks/' in loc:
            return loc[loc.index('/rest/tasks/'):]
        if isinstance(d, dict):
            u = text(d.get('uri'))
            if u.startswith('/rest/tasks/'):
                return u
        return None

    def wait_task(self, uri, what, seconds, relogin=False):
        """Wait for a task. True: completed; raises when it failed; None: its end could not
        be read (the appliance reloading its web services) - the test of what is served
        then tells."""
        if not uri:
            return None
        # counted by the waits made, not the clock: the same under a stand-in sleep
        waited, step = 0, 5
        tried_login = False
        while True:
            try:
                st, hd, d = self.req('GET', uri, what='reading the task of %s' % what)
                state = text((d or {}).get('taskState')) if isinstance(d, dict) else ''
                if not state:
                    return None
                if state in TASK_DONE:
                    errs = '; '.join(text(e.get('message')) for e in (d.get('taskErrors') or [])
                                     if isinstance(e, dict) and e.get('message'))
                    if state == 'Completed':
                        return True
                    if state == 'Warning':
                        self.ctx.step('%s ended with a warning: %s' % (what, errs or '?'), 'warn')
                        return True
                    raise PluginError('%s: the task ended %s - %s' % (what, state, errs or '?'),
                                      detail=text(d)[:4000], retry=False)
            except PluginError as e:
                if not getattr(e, 'retry', True) and 'task ended' in str(e):
                    raise
                # the import cut the sessions: sign in again once, then keep asking
                if relogin and not tried_login and '(401)' in str(e):
                    tried_login = True
                    try:
                        self.session = None
                        self.login()
                    except PluginError as e2:
                        self.ctx.debug('signing in again: %s' % e2)
                else:
                    self.ctx.debug('the task cannot be read now: %s' % e)
            if waited >= seconds or self.ctx.cancelled():
                self.ctx.step('the end of %s could not be read in time - the test of what '
                              'is served tells' % what, 'warn')
                return None
            self._sleep(step)
            waited += step

    # -- the work -----------------------------------------------------------------------
    def test(self):
        self.login()
        try:
            st, hd, d = self.req('GET', '/rest/certificates/https',
                                 what='reading the appliance certificate')
            d = d if isinstance(d, dict) else {}
            return 'signed in to %s (API %d): appliance certificate %s, until %s' % (
                self.c('host'), self.api_version(),
                d.get('commonName') or d.get('subject') or '?',
                d.get('expiresOn') or d.get('validUntil') or '?')
        finally:
            self.logout()

    def served_now(self, bundle):
        try:
            host, port = split_hostport(join_hostport(self.c('host'), self.c('port') or 443))
            return served_fingerprint(host, port, None) == fp_of(bundle)
        except (OSError, ValueError):
            return False

    def put_ca(self, pem, seconds):
        alias = 'acme-%s' % chain_id(pem)
        st, hd, d = self.req('GET', '/rest/certificates/ca/%s' % urllib.parse.quote(alias, safe=''),
                             ok=(200, 404), what='looking for the CA %s' % alias)
        if st == 200:
            self.ctx.step('the CA %s is in the trust store already' % alias)
            return False
        st, hd, d = self.req('POST', '/rest/certificates/ca', {
            'type': 'CertificateAuthorityInfoCollection',
            'members': [{'type': 'CertificateAuthorityInfo',
                         'certificateDetails': {'type': 'CertificateDetailV2',
                                                'aliasName': alias, 'base64Data': pem}}]},
            what='adding the CA %s to the trust store' % alias)
        self.wait_task(self.task_of(hd, d), 'adding the CA %s' % alias, min(seconds, 120))
        self.ctx.step('the CA %s added to the trust store' % alias, 'ok')
        return True

    def deploy(self, bundle, options):
        options = options or {}
        if key_family(bundle) == 'ECDSA':
            raise PluginError('HPE OneView takes only an RSA certificate for the appliance - '
                              'choose an RSA key type for this certificate', retry=False)
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the appliance')
        seconds = as_int(self.opt(options, 'task_wait', 300), 300)
        self.login()
        did = []
        try:
            if as_bool(self.opt(options, 'import_chain', True), True):
                for pem in chain_list(bundle):
                    try:
                        if self.put_ca(pem, seconds):
                            did.append('CA %s' % chain_id(pem))
                    except PluginError as e:
                        if getattr(e, 'retry', True) is False and '(403)' in str(e):
                            raise
                        self.ctx.step('the intermediate CA is not in the trust store: %s' % e,
                                      'warn')
            pw = random_password()
            body, ctype = multipart([('file', ('acme.pfx', bundle.as_format('pfx', password=pw,
                                                                            alias='acme'),
                                               'application/octet-stream'))])
            st, hd, d = self.req('PUT', '/rest/certificates/https/pkcs12?uploadfilename=acme.pfx',
                                 body, headers={'Content-Type': ctype, 'Password': pw,
                                                'uploadfilename': 'acme.pfx'},
                                 timeout=180, what='importing the appliance certificate')
            self.ctx.step('the appliance certificate imported (PKCS#12) - the appliance '
                          'reloads its web services', 'ok')
            done = self.wait_task(self.task_of(hd, d), 'the certificate import', seconds,
                                  relogin=True)
            if done:
                self.ctx.step('the import task completed (the SSO certificate goes to the '
                              'managed iLOs too)', 'ok')
            did.insert(0, 'imported the appliance certificate')
        finally:
            self.logout()
        self.remember(bundle, options)
        return ', '.join(did)

    @staticmethod
    def served_wait(options):
        """The appliance reloads its web services after the import: a minute or two."""
        return (12, 10)

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []

    def verify(self, bundle, options):
        options = dict(options or {})
        if not options.get('verify'):
            options['verify'] = join_hostport(self.c('host'), as_int(self.c('port', 443), 443))
        options.setdefault('verify_tries', 12)
        options.setdefault('verify_wait', 10)
        return HttpTarget.verify(self, bundle, options)
