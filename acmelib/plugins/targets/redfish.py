# -*- coding: utf-8 -*-
"""
Server management controllers through Redfish - Dell iDRAC9, HPE iLO 5/6,
Lenovo XClarity Controller, Supermicro and AMI MegaRAC BMCs: the HTTPS
certificate of the controller replaced with the standard action
CertificateService.ReplaceCertificate (key and chain in one PEM string),
the controller restarted where it needs it.

    GET    /redfish/v1/                               -> Links.Sessions, CertificateService
    POST   <Sessions>  {UserName, Password}          -> X-Auth-Token, Location
    GET    /redfish/v1/Managers -> Members[0] -> NetworkProtocol
    GET    <NetworkProtocol>/HTTPS/Certificates      -> Members[0] (the certificate's URI)
    POST   <CertificateService>/Actions/CertificateService.ReplaceCertificate
           {CertificateString: key + full chain, CertificateType: "PEMchain" | "PEM",
            CertificateUri: {"@odata.id": ...}}
    POST   <Manager>/Actions/Manager.Reset {"ResetType": "GracefulRestart"}  (when asked)
    DELETE <Location>                                  (signing out)

Sources:
    https://www.dmtf.org/sites/default/files/standards/documents/DSP2046_2023.3.html
        (CertificateService.ReplaceCertificate, Certificate.v1_x CertificateType)
    https://www.dmtf.org/sites/default/files/standards/documents/DSP0266_1.20.0.html  (sessions)
    https://github.com/acmesh-official/acme.sh/blob/master/deploy/redfish.sh
Uncertain: which controllers take a private key this way. acme.sh's hook
reports it for AMI MegaRAC (ASUS, Lenovo, Supermicro) and says iDRAC9 5.x and
iLO 5 2.42+ "should" work; HPE iLO generally wants its own CSR, older iDRACs
want racadm sslkeyupload. Choose an RSA 2048 key type for these.
Checked against api-docs/redfish/notes.md and the DMTF schemas there
(CertificateService.v1_2_2, CertificateCollection, Certificate.v1_11_0): the
action is posted to the target the CertificateService gives for it; an empty
HTTPS certificate collection ("insertable") gets a POST of the certificate
instead of a replace of a made-up member; a service that lists its actions
without ReplaceCertificate (HPE iLO 6) is said in words. Dell's own way for
iDRAC (OEM UploadSSLKey + ImportSSLCertificate, then a reset - "Until the
iDRAC is reset, the old certificate will remain active") is not used; Lenovo
XCC2 takes "PEM" only.
"""
from __future__ import annotations

import base64
import re

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, http_fields, tls_fields, verify_fields,
    text, served_fingerprint, fp_of)


class RedfishTarget(HttpTarget):
    kind = 'redfish'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Server management (Redfish: iDRAC, iLO, XCC, BMC)'
    vendor = 'Redfish (Dell, HPE, Lenovo, Supermicro)'
    description = ('Replaces the HTTPS certificate of a server\'s management controller through '
                   'the standard Redfish CertificateService, then restarts the controller '
                   'when asked.')
    doc = 'targets.md'
    fields = http_fields(443, 'idrac.example.local') + [
        field('user', 'User', 'text', required=True, default='root'),
        field('password', 'Password', 'secret', required=True),
        field('basic_auth', 'Basic authentication instead of a session', 'bool', default=False,
              advanced=True, help='for a controller whose sessions do not work'),
    ] + tls_fields()
    deploy_fields = [
        field('cert_type', 'Send as', 'select', default='PEMchain',
              options=[['PEMchain', 'key + certificate + chain (PEMchain)'],
                       ['PEM', 'key + certificate (PEM)']],
              help='PEM for a controller that refuses PEMchain'),
        field('certificate_uri', 'Certificate URI', 'text', advanced=True,
              placeholder='/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol/HTTPS/'
                          'Certificates/SecurityCertificate.1',
              help='empty: the first HTTPS certificate of the first manager'),
        field('reset', 'Restart the controller afterwards', 'bool', default=False,
              help='Manager.Reset GracefulRestart - some controllers serve the new certificate '
                   'only after it (iDRAC); the server itself is not touched'),
    ] + verify_fields()

    token = None
    session_uri = None

    def auth_headers(self):
        h = {'OData-Version': '4.0'}
        if as_bool(self.c('basic_auth')):
            h['Authorization'] = 'Basic ' + base64.b64encode(
                ('%s:%s' % (self.c('user'), self.c('password') or '')).encode()).decode()
        elif self.token:
            h['X-Auth-Token'] = self.token
        return h

    def get(self, path, what=None):
        st, hd, d = self.req('GET', path, what=what)
        if not isinstance(d, dict):
            raise PluginError('%s: the controller did not answer with JSON' % (what or path))
        return d

    def login(self):
        root = self.get('/redfish/v1/', what='reading the service root')
        if as_bool(self.c('basic_auth')):
            return root
        sess = ((root.get('Links') or {}).get('Sessions') or {}).get('@odata.id') or \
            '/redfish/v1/SessionService/Sessions'
        try:
            st, hd, d = self.req('POST', sess, {'UserName': self.c('user'),
                                                'Password': self.c('password') or ''},
                                 auth=False, headers={'OData-Version': '4.0'},
                                 what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry='(401)' not in str(e))
        self.token = hd.get('x-auth-token')
        self.session_uri = hd.get('location')
        if not self.token:
            raise PluginError('the controller gave no X-Auth-Token on signing in')
        return root

    def logout(self):
        if self.session_uri:
            try:
                self.req('DELETE', self.session_uri, ok=range(0, 600))
            except PluginError:
                pass
        self.token = self.session_uri = None

    def manager(self):
        ms = self.get('/redfish/v1/Managers', what='listing the managers')
        mem = ms.get('Members') or []
        if not mem:
            raise PluginError('the controller lists no manager', retry=False)
        return mem[0]['@odata.id']

    def cert_uri(self, options):
        uri = text((options or {}).get('certificate_uri')).strip()
        if uri:
            return uri
        m = self.get(self.manager(), what='reading the manager')
        np = (m.get('NetworkProtocol') or {}).get('@odata.id')
        if not np:
            raise PluginError('the manager has no NetworkProtocol: give the Certificate URI',
                              retry=False)
        try:
            coll = self.get(np + '/HTTPS/Certificates', what='listing the HTTPS certificates')
        except PluginError as e:
            # 1.0.96: an HPE iLO has no standard HTTPS certificate collection - say which
            # version of the target it needs, not only "not found"
            fw = '%s %s' % (text(m.get('FirmwareVersion')), text(m.get('Model')))
            if '(404)' in str(e) and re.search(r'\bilo', fw, re.I):
                raise PluginError(
                    'the controller has no HTTPS certificate collection (404) (HPE iLO: '
                    'choose the module version for HPE iLO - iLO takes a certificate with its '
                    'key through its own HpeHttpsCert)',
                    detail='%s\n%s' % (e, e.detail or ''), retry=False)
            raise
        mem = coll.get('Members') or []
        if mem:
            return mem[0]['@odata.id']
        return None, np + '/HTTPS/Certificates'     # none yet: a POST to the collection

    def replace_target(self, cs):
        """The ReplaceCertificate action's target the CertificateService gives
        (Actions."#CertificateService.ReplaceCertificate".target), the usual path
        when it does not say; None when it lists actions without that one."""
        default = cs + '/Actions/CertificateService.ReplaceCertificate'
        try:
            svc = self.get(cs, what='reading the certificate service')
        except PluginError:
            return default
        acts = svc.get('Actions')
        if not isinstance(acts, dict) or not acts:
            return default
        act = acts.get('#CertificateService.ReplaceCertificate')
        if not isinstance(act, dict):
            return None
        return text(act.get('target')) or default

    def served_now(self, bundle):
        # 1.0.96: the host and the port apart - "2001:db8::1:443" read back by
        # split_hostport is another address (an IPv6 host was never asked)
        host = text(self.c('host')).strip().strip('[]')
        try:
            same = served_fingerprint(host, as_int(self.c('port') or 443, 443),
                                      None) == fp_of(bundle)
        except (OSError, ValueError) as e:
            self.ctx.step('what %s serves cannot be read (%s) - the certificate is put there'
                          % (host, e))
            return False
        # the decision said (What happens): the same one served - nothing to do; another -
        # put there
        self.ctx.step('%s serves this certificate already' % host if same else
                      '%s serves another certificate - this one is put there' % host)
        return same

    def test(self):
        root = self.login()
        try:
            m = self.get(self.manager(), what='reading the manager')
            return 'signed in to %s: %s %s, firmware %s, Redfish %s' % (
                self.c('host'), m.get('Manufacturer', root.get('Vendor', '')),
                m.get('Model', m.get('Name', '?')), m.get('FirmwareVersion', '?'),
                root.get('RedfishVersion', '?'))
        finally:
            self.logout()

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the controller')
        typ = self.opt(options, 'cert_type', 'PEMchain')
        pem = text(bundle.as_format('key-pem')) + text(
            bundle.as_format('fullchain-pem' if typ == 'PEMchain' else 'cert-pem'))
        root = self.login()
        try:
            cs = (root.get('CertificateService') or {}).get('@odata.id') or \
                '/redfish/v1/CertificateService'
            uri = self.cert_uri(options)
            if isinstance(uri, tuple):
                # an empty collection: "insertable", a POST of the certificate to it
                coll = uri[1]
                self.req('POST', coll, {'CertificateString': pem, 'CertificateType': typ},
                         what='adding the certificate to %s' % coll, timeout=120)
                self.ctx.step('added the HTTPS certificate to %s' % coll, 'ok')
                did = 'added the HTTPS certificate (%s)' % coll
            else:
                target = self.replace_target(cs)
                if not target:
                    raise PluginError(
                        'the controller offers no CertificateService.ReplaceCertificate '
                        '(HPE iLO: choose the module version for HPE iLO - iLO takes a '
                        'certificate with its key through its own HpeHttpsCert)', retry=False)
                self.req('POST', target, {
                    'CertificateString': pem, 'CertificateType': typ,
                    'CertificateUri': {'@odata.id': uri}}, what='replacing %s' % uri,
                    timeout=120)
                self.ctx.step('replaced %s' % uri, 'ok')
                did = 'replaced the HTTPS certificate (%s)' % uri
            if as_bool(options.get('reset')):
                mgr = self.manager()
                self.req('POST', mgr + '/Actions/Manager.Reset', {'ResetType': 'GracefulRestart'},
                         what='restarting the controller')
                self.ctx.step('the controller restarts (a minute or few)', 'ok')
                did += ', the controller restarts'
                self.session_uri = None             # gone with the restart
        finally:
            self.logout()
        self.remember(bundle, options)
        return did

    @staticmethod
    def served_wait(options):
        """A reset of the controller takes minutes; without one the certificate is served
        at once (1.0.95: every deployment waited up to five minutes)."""
        return (20, 15) if as_bool((options or {}).get('reset')) else None

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []

    def verify(self, bundle, options):
        options = dict(options or {})
        if not options.get('verify'):
            # 1.0.96: an IPv6 address in brackets, so split_hostport reads it back whole
            host = text(self.c('host')).strip().strip('[]')
            options['verify'] = '%s:%d' % ('[%s]' % host if ':' in host else host,
                                           as_int(self.c('port', 443), 443))
        if as_bool(options.get('reset')):
            options.setdefault('verify_tries', 20)
            options.setdefault('verify_wait', 15)
        return HttpTarget.verify(self, bundle, options)
