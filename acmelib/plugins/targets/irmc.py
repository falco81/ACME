# -*- coding: utf-8 -*-
"""
Fujitsu / Fsas Technologies iRMC (PRIMERGY, PRIMEQUEST 4000): the HTTPS certificate of
the iRMC put in with iRMC Remote Scripting (SCCI), then the iRMC reset so it serves it.

    POST /config  (HTTP Basic)  <CMDSEQ> of SCCI commands, OC="E002" (SET):
         OE="1981"  ConfBMCSslPrivateKey     the key - PKCS#1 ("BEGIN RSA PRIVATE KEY")
         OE="1982"  ConfBMCSslCertificate    the certificate
         OE="1983"  ConfBMCSslCaCertificate  the CA certificate (optional)
         key and certificate always together, in one sequence
    POST /config  OC="E001" (GET) OE="1982"                     (Try: read, change nothing)
    POST /rest/v1/Oem/iRMC/Reset            -> 202              (the reset, as Fsas' role does)
      or POST /redfish/v1/Managers/iRMC/Actions/Manager.Reset {"ResetType": "GracefulRestart"}

Sources (2026-11): the official Ansible collection fsas.primergy 3.1.0 (formerly
fujitsu.primergy; github.com/fujitsu/ansible-irmc-integration) - module irmc_certificate
(the SCCI codes 0x1981-0x1983, "If you update the certificate with set, you must restart
the iRMC", "Private keys created with openssl 3.x cannot be registered" - PKCS#1 needed),
role irmc_set_certificate (POST /rest/v1/Oem/iRMC/Reset expecting 202, then waiting for
GET /redfish/v1/Managers/iRMC, up to 600 s); iRMC S6 Configuration and Maintenance 2.x,
chapter 4 (Load from File, then "Reboot the iRMC"; files up to 4 KB, RSA).

The same calls on iRMC S4 (FW 9.04+), S5 (FW 1.25+) and S6 (PRIMERGY M5 - M8, PRIMEQUEST
4000) - hence one module, no versions. Not used: the Redfish OEM FTSCertificates /
FsasCertificates actions (from a mirror of the Terraform provider only), the standard
CertificateService (not documented for iRMC). Known: on some M8 machines the SCCI SET
fails until an iRMC firmware fix (Fsas' known issue) - said in words.
"""
from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, http_fields, tls_fields, verify_fields,
    text, served_fingerprint, fp_of, family_of)

KEY_OE, CERT_OE, CA_OE = '1981', '1982', '1983'
MAX_FILE = 4096            # the iRMC takes files up to 4 KB (Configuration and Maintenance)


def scci_set(oe, value):
    # CDATA: a PEM has no "]]>", and nothing in it is read as markup.
    return ('<CMD Context="SCCI" OC="E002" OE="%s" OI="0" CA="-1" Type="SET">'
            '<DATA Type="xsd::string"><![CDATA[%s]]></DATA><STATUS>0</STATUS></CMD>'
            % (oe, value))


def scci_get(oe):
    return ('<CMD Context="SCCI" OC="E001" OE="%s" OI="0" CA="-1" Type="GET">'
            '<STATUS>0</STATUS></CMD>' % oe)


def scci_seq(cmds):
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><CMDSEQ>%s</CMDSEQ>'
            % ''.join(cmds))


def scci_result(raw):
    """(errors in words, {OE: value}) of an SCCI answer: a STATUS other than 0 is an error,
    with the MESSAGE / ERROR text of it."""
    s = text(raw).strip()
    try:
        root = ET.fromstring(s.encode('utf-8'))
    except ET.ParseError:
        return ['the iRMC did not answer in SCCI XML: %s' % re.sub(r'\s+', ' ', s)[:200]], {}
    errors, values = [], {}
    cmds = [root] if root.tag.upper() == 'CMD' else list(root.iter('CMD'))
    for cmd in cmds:
        st = None
        for tag in ('STATUS', 'Status'):
            el = cmd.find(tag)
            if el is not None and text(el.text).strip():
                st = text(el.text).strip()
                break
            # 1.0.96: <Status><Value>N</Value><Message/></Status> inside a CMD - the code is
            # in Value, the element itself has no text (read as "no status" before)
            if el is not None and status_value(el) is not None:
                st = status_value(el)
                break
        words = ' '.join(text(e.text).strip() for e in cmd.iter()
                         if e.tag.upper() in ('MESSAGE', 'ERROR', 'ERRORMSG')
                         and text(e.text).strip())
        oe = text(cmd.get('OE')).strip()
        if st not in (None, '0'):
            errors.append('SCCI %s: status %s%s' % (oe or '?', st,
                                                     (' - ' + words) if words else ''))
        for tag in ('DATA', 'VALUE'):
            el = cmd.find(tag)
            if el is not None and text(el.text).strip():
                values[oe] = text(el.text).strip()
    # a sequence-level status (some firmware answers <Status> under the root only)
    if not cmds:
        for el in root.iter():
            if el.tag.upper() != 'STATUS':
                continue
            # 1.0.96: the root <Status><Value>N</Value><Severity/><Message/></Status> (the
            # answer to a whole sequence) - a Value other than 0 is an error, worded with
            # its Message / Error; the Value was not read before, so a refusal passed as done
            st = status_value(el)
            if st is None:
                st = text(el.text).strip()
            if st in ('', '0'):
                continue
            words = ' '.join(text(e.text).strip() for e in el.iter()
                             if e.tag.upper() in ('MESSAGE', 'ERROR', 'ERRORMSG')
                             and text(e.text).strip())
            errors.append('SCCI status %s%s' % (st, (' - ' + words) if words else ''))
    return errors, values


def status_value(el):
    """The code of a <Status><Value>N</Value>...</Status> element (None: no Value in it)."""
    for v in el:
        if v.tag.upper() == 'VALUE' and text(v.text).strip():
            return text(v.text).strip()
    return None


class IrmcTarget(HttpTarget):
    kind = 'irmc'
    discovery = False           # nothing to find: its fields are the sign-in
    title = 'Fujitsu iRMC (PRIMERGY, PRIMEQUEST 4000)'
    vendor = 'Fujitsu / Fsas Technologies'
    description = ('Puts the HTTPS certificate of an iRMC S4, S5 or S6 (PRIMERGY M2 - M8, '
                   'PRIMEQUEST 4000) in with iRMC Remote Scripting (SCCI ConfBMCSslPrivateKey '
                   '/ ConfBMCSslCertificate / ConfBMCSslCaCertificate), then resets the iRMC so '
                   'it serves it - the server itself keeps running. Every iRMC generation '
                   'takes the same calls. RSA keys only.')
    doc = 'targets.md'
    fields = http_fields(443, 'irmc.example.local') + [
        field('user', 'User', 'text', required=True, default='svc-cert',
              help='an iRMC user with "Configure iRMC Settings" and the LAN channel privilege '
                   'Administrator'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('send_ca', 'Send the intermediate as the CA certificate', 'bool', default=True,
              help='ConfBMCSslCaCertificate (SCCI 0x1983) - the CA certificate of the iRMC'),
        field('reset', 'Reset the iRMC afterwards', 'select', default='rest',
              options=[['rest', 'iRMC REST: /rest/v1/Oem/iRMC/Reset (as Fsas\' Ansible role)'],
                       ['redfish', 'Redfish: Manager.Reset GracefulRestart'],
                       ['none', 'no reset (the old certificate is served until one)']],
              help='the iRMC serves the new certificate only after a reset; the server and its '
                   'operating system are not touched'),
    ] + verify_fields()

    def auth_headers(self):
        return {'Authorization': 'Basic ' + base64.b64encode(
            ('%s:%s' % (self.c('user'), self.c('password') or '')).encode()).decode()}

    def scci(self, cmds, what):
        st, hd, d = self.req('POST', '/config', scci_seq(cmds), what=what, timeout=120,
                             headers={'Content-Type': 'application/x-www-form-urlencoded'})
        errors, values = scci_result(d if isinstance(d, (bytes, str)) else text(d))
        if errors:
            hint = ''
            if any('Type="SET"' in c for c in cmds):
                # Fsas' known issue: "On some M8 generation devices, this module fails when
                # command is set to set due to an iRMC issue."
                hint = (' (on some PRIMERGY M8 machines the SCCI certificate SET fails until '
                        'an iRMC firmware fix - use the iRMC web interface there)')
            raise PluginError('%s: the iRMC refused it - %s%s' % (what, '; '.join(errors), hint),
                              detail=text(d)[:4000], retry=False)
        return values

    def served_now(self, bundle):
        try:
            # 1.0.96: the host and the port apart - "2001:db8::1:443" read back by
            # split_hostport is another address (an IPv6 host was never asked)
            host = text(self.c('host')).strip().strip('[]')
            return served_fingerprint(host, as_int(self.c('port') or 443, 443),
                                      None) == fp_of(bundle)
        except (OSError, ValueError):
            return False

    def test(self):
        values = self.scci([scci_get(CERT_OE)], 'reading the iRMC certificate (SCCI)')
        cur = values.get(CERT_OE, '')
        return 'signed in to %s: SCCI answered, the certificate there is %s' % (
            self.c('host'), 'read (%d characters)' % len(cur) if cur else 'not said')

    def key_pkcs1(self, bundle):
        if family_of(bundle) not in ('rsa', ''):
            raise PluginError('the iRMC takes RSA keys only - choose an RSA key type for this '
                              'certificate', retry=False)
        try:
            key = text(bundle.as_format('key-rsa'))
        except Exception as e:                          # noqa: BLE001
            raise PluginError('the key cannot be written as PKCS#1 (RSA): %s' % e, retry=False)
        if 'BEGIN RSA PRIVATE KEY' not in key:
            raise PluginError('the iRMC takes RSA keys only (PKCS#1, "BEGIN RSA PRIVATE KEY")',
                              retry=False)
        return key

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the iRMC')
        key = self.key_pkcs1(bundle)
        cert = text(bundle.as_format('cert-pem'))
        cmds = [scci_set(KEY_OE, key), scci_set(CERT_OE, cert)]
        ca = ''
        if as_bool(self.opt(options, 'send_ca', True), True):
            ca = text(bundle.as_format('chain-pem')).strip()
            if ca:
                cmds.append(scci_set(CA_OE, ca + '\n'))
        for what, v in (('key', key), ('certificate', cert), ('CA certificate', ca)):
            if len(v.encode()) > MAX_FILE:
                raise PluginError('the %s is %d bytes - the iRMC takes files of 4 KB at most%s'
                                  % (what, len(v.encode()),
                                     ' (turn off "Send the intermediate as the CA certificate")'
                                     if what == 'CA certificate' else ''), retry=False)
        self.scci(cmds, 'putting the certificate in (SCCI)')
        self.ctx.step('the iRMC took the key and the certificate%s' % (
            ' and the CA certificate' if ca else ''), 'ok')
        did = 'certificate put in'
        how = self.opt(options, 'reset', 'rest')
        if how == 'rest':
            self.req('POST', '/rest/v1/Oem/iRMC/Reset', '', ok=(200, 202, 204),
                     headers={'Content-Type': 'application/json'}, what='resetting the iRMC')
        elif how == 'redfish':
            self.req('POST', '/redfish/v1/Managers/iRMC/Actions/Manager.Reset',
                     {'ResetType': 'GracefulRestart'}, ok=(200, 202, 204),
                     what='resetting the iRMC')
        if how in ('rest', 'redfish'):
            self.ctx.step('the iRMC resets (a few minutes; the server keeps running)', 'ok')
            did += ', the iRMC resets'
        else:
            self.ctx.step('no reset asked: the iRMC serves the new certificate after its next '
                          'reset', 'warn')
        self.remember(bundle, options)
        return did

    @staticmethod
    def served_wait(options):
        """The reset takes minutes (Fsas' role waits up to 600 s)."""
        return (40, 15) if ((options or {}).get('reset') or 'rest') != 'none' else None

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('port', 443), 443))] if self.c('host') else []
