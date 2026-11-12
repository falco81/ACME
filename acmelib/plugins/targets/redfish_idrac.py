# -*- coding: utf-8 -*-
"""
Dell iDRAC9 6.00.02 and later, iDRAC10: a version of the Redfish target (kind
"redfish", 1.0.94) that puts acme's key and certificate on the iDRAC Dell's own
way - the OEM DelliDRACCardService - instead of the standard ReplaceCertificate.

    GET  /redfish/v1/  -> Sessions;  POST <Sessions> {UserName, Password}  (as the plain one)
    GET  /redfish/v1/Managers -> Members[0]     FirmwareVersion: iDRAC9 3.x - 7.x, iDRAC10 1.x
    GET  <Manager>/Oem/Dell/DelliDRACCardService            (its Actions: UploadSSLKey there?)
    POST <Manager>/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.UploadSSLKey
         {"SSLKeyString": key PEM}                           - the key first,
    POST <Manager>/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.ImportSSLCertificate
         {"CertificateType": "Server", "SSLCertificateFile": certificate PEM}   - then the certificate
    POST <Manager>/Actions/Manager.Reset {"ResetType": "GracefulRestart"}  (only when asked)

Why a version of its own: Dell documents ReplaceCertificate for a certificate of
a CSR the iDRAC made itself (CertificateType "PEM", the certificate alone); a key
of one's own goes through UploadSSLKey + ImportSSLCertificate "Server", from
iDRAC9 6.00.02.00 (racadm sslkeyupload -t 1 + sslcertupload -t 1 alike). The
plain module sends the key inside ReplaceCertificate's CertificateString - the
DMTF way, not one Dell documents for the iDRAC.

From iDRAC9 6.00.02 and on iDRAC10 the iDRAC restarts only its web server after
the import (no reset of the iDRAC; older firmware needed racreset) - the server
and its OS are not touched. iDRAC9 and iDRAC10 take the same calls, hence one
version for both; the firmware the iDRAC says is checked first and an older one
(or not an iDRAC) refused before anything is changed.

Sources (Dell): RACADM CLI Guides iDRAC9 7.xx and iDRAC10 1.xx (sslkeyupload,
sslcertupload), the InfoHub "Methods to manage web server certificates on
iDRAC", dell/iDRAC-Redfish-Scripting ExportImportSSLCertificateREDFISH.py, the
Ansible module dellemc.openmanage.idrac_certificates (import with ssl_key, FW
6.00.02+); rights: Login + Configure iDRAC.
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import PluginError, as_bool, text
from acmelib.plugins.targets.redfish import RedfishTarget

OEM = '/Oem/Dell/DelliDRACCardService'


def fw_tuple(v):
    """'7.10.70.00' -> (7, 10, 70, 0); None when it is not a firmware version."""
    m = re.match(r'^\s*(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?', text(v))
    return tuple(int(x or 0) for x in m.groups()) if m else None


def generation(fw):
    """'iDRAC9' / 'iDRAC10' / '' from the firmware version: iDRAC10 counts from 1.x,
    iDRAC9 from 3.x (iDRAC8 is 2.x)."""
    if fw is None:
        return ''
    if fw[0] == 1:
        return 'iDRAC10'
    if fw[0] >= 3:
        return 'iDRAC9'
    return ''


class IdracOemTarget(RedfishTarget):
    module_version = '6.00.02'
    version_label = 'Dell iDRAC9 6.00.02+ / iDRAC10 (Dell OEM)'
    description = ('Dell iDRAC9 6.00.02+ / iDRAC10 (Dell OEM): uploads the key and imports the '
                   'certificate through Dell\'s DelliDRACCardService (UploadSSLKey, then '
                   'ImportSSLCertificate "Server"), as Dell documents for a key made elsewhere; '
                   'the iDRAC restarts its web server by itself (the server is not touched). '
                   'Refused on another controller or older firmware.')
    idrac9_min = (6, 0, 2, 0)
    checked_to = {'iDRAC9': (7, 20), 'iDRAC10': (1, 30)}

    def manager_info(self):
        mgr = self.manager()
        return mgr, self.get(mgr, what='reading the manager')

    def check_idrac(self, mgr, m):
        """Not an iDRAC, or a firmware older than 6.00.02: refused before anything is changed.
        The firmware not read: said, and gone on (the OEM service is asked for its actions)."""
        dell = 'iDRAC' in mgr or 'Dell' in (m.get('Oem') or {}) or \
            'dell' in text(m.get('Manufacturer')).lower()
        if not dell:
            raise PluginError('this controller is not a Dell iDRAC (%s) - use the plain '
                              'version of the target' % text(m.get('Model') or mgr),
                              retry=False)
        fw = fw_tuple(m.get('FirmwareVersion'))
        gen = generation(fw)
        if fw is None:
            self.ctx.step('the iDRAC firmware version cannot be read - the Dell OEM calls are '
                          'tried', 'warn')
            return ''
        words = text(m.get('FirmwareVersion')).strip()
        if not gen or (gen == 'iDRAC9' and fw < self.idrac9_min):
            raise PluginError('this iDRAC runs firmware %s - the module version "%s" needs '
                              'iDRAC9 6.00.02 or later or iDRAC10 (an older one takes a key of '
                              'its own only after a reset: use the plain version of the target '
                              'with "Restart the controller", or update the firmware)'
                              % (words, self.version_label), retry=False)
        if fw[:2] > self.checked_to[gen]:
            self.ctx.step('%s firmware %s is newer than the documents this module version was '
                          'checked against' % (gen, words), 'warn')
        return '%s %s' % (gen, words)

    def test(self):
        self.login()
        try:
            mgr, m = self.manager_info()
            said = self.check_idrac(mgr, m)
            return 'signed in to %s: %s, firmware %s%s' % (
                self.c('host'), m.get('Model', m.get('Name', '?')),
                m.get('FirmwareVersion', '?'), (' (%s)' % said.split()[0]) if said else '')
        finally:
            self.logout()

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the iDRAC')
        typ = self.opt(options, 'cert_type', 'PEMchain')
        cert = text(bundle.as_format('fullchain-pem' if typ == 'PEMchain' else 'cert-pem'))
        self.login()
        try:
            mgr, m = self.manager_info()
            said = self.check_idrac(mgr, m)
            svc = mgr + OEM
            acts = {}
            try:
                acts = self.get(svc, what='reading DelliDRACCardService').get('Actions') or {}
            except PluginError as e:
                self.ctx.debug('DelliDRACCardService not read: %s' % e)
            if acts and '#DelliDRACCardService.UploadSSLKey' not in acts:
                raise PluginError('this iDRAC offers no DelliDRACCardService.UploadSSLKey (it '
                                  'came with iDRAC9 6.00.02) - update the firmware, or use the '
                                  'plain version of the target', retry=False)
            self.req('POST', svc + '/Actions/DelliDRACCardService.UploadSSLKey',
                     {'SSLKeyString': text(bundle.as_format('key-pem'))},
                     what='uploading the key', timeout=120)
            self.ctx.step('uploaded the key', 'ok')
            self.req('POST', svc + '/Actions/DelliDRACCardService.ImportSSLCertificate',
                     {'CertificateType': 'Server', 'SSLCertificateFile': cert},
                     what='importing the certificate', timeout=120)
            self.ctx.step('imported the certificate - the iDRAC restarts its web server', 'ok')
            did = 'imported the key and certificate%s' % ((' (%s)' % said) if said else '')
            if as_bool(options.get('reset')):
                self.req('POST', mgr + '/Actions/Manager.Reset',
                         {'ResetType': 'GracefulRestart'}, what='restarting the iDRAC')
                self.ctx.step('the iDRAC restarts (a few minutes)', 'ok')
                did += ', the iDRAC restarts'
            self.session_uri = None         # the web server restarts: the session is gone
        finally:
            self.logout()
        self.remember(bundle, options)
        return did

    @staticmethod
    def served_wait(options):
        """The web server restarts by itself after the import (tens of seconds); a reset of
        the iDRAC takes minutes."""
        return (20, 15) if as_bool((options or {}).get('reset')) else (8, 10)
