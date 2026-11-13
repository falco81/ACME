# -*- coding: utf-8 -*-
"""
Cisco Unified Communications Manager (CUCM 14 and 15, every SU) - the certificate of one
unit of one node (tomcat: the web, AXL, UDS, SAML SP; CallManager: SIP/SCCP TLS; or their
-ECDSA twins) for a key CUCM makes itself ("the device makes the key", docs/certificates.md
"Key made by the device"). Cisco Unified OS Administration takes no private key for these
units: the key is made on CUCM by Generate CSR, and the certificate signed for it is uploaded.
So acme asks CUCM for a new key and CSR at every issue and renewal (device_csr), and right
after the issue puts the signed certificate back (deploy, with no key) - over the platform
CLI (SSH, an OS platform account of privilege level 1):

    show version active                                   (Try: read only)
    set csr gen <unit>                                    a new key and CSR of the unit
    show csr own <unit>/<unit>.csr                        the CSR (PEM) printed
    show cert list trust                                  the CA certificates there already
    set cert import trust <unit>-trust                    each CA of the chain not there yet
        <the CA certificate pasted, an empty line>          ("Paste the Certificate and Hit Enter")
    set cert import own <unit> <unit>-trust/<ca file>     the certificate, for the CSR's key
        <the certificate pasted, an empty line>
    show cert own <unit>/<unit>.pem                       the serial checked
    utils service restart Cisco Tomcat | Cisco Tftp       (tomcat; CallManager: Cisco CallManager,
                                                          Cisco CTIManager - when asked)

The CLI makes the CSR with CUCM's own names: the node's FQDN as the common name, and the
names CUCM adds (its domain, an alternate host name set with `set web-security`) - it takes
no names from acme. acme reads the names in the CSR and says them when they are not exactly
the certificate's names (which the check after device_csr needs). A multi-server (SAN)
certificate is uploaded only in the OS Administration GUI from 14SU2 on: one node a target.

Sources (2026-11, the vendor guide navody/certifikaty/cisco/cucm.md and the pages it cites):
    Administration Guide for Cisco Unified CM 15 - Manage Certificates (Generate CSR, Upload,
        the services to restart: Table 5)
    Security Guide for Cisco Unified CM 15 - Certificates (multi-server SAN from the publisher
        and in the GUI only from 14SU2, no wildcard, at most 4096 bits; 15SU5: the CN of a CSR
        cannot be edited)
    CLI Reference Guide 15 - Set commands (set csr gen, set cert import own|trust, set account
        name, privilege level 1), Show commands (show csr list, show cert list|own),
        Utils commands (utils service restart)
    Cisco TechNote 200753 "Configure CA Signed Certificate via CLI in Cisco VOS" (set csr gen
        tomcat -> "Successfully Generated CSR for tomcat", show csr own tomcat/tomcat.csr,
        set cert import trust ... and set cert import own tomcat tomcat-trust/<ca>.pem with the
        certificate pasted at "Paste the Certificate and Hit Enter")

UNVERIFIED (no CUCM to try it on): that the CLI reads its commands from the input of an SSH
session without a terminal (as the AOS and IOS modules send theirs) - CUCM's CLI starts
slowly, the time limits are long; that `set csr gen` asks nothing on 14 / 15 (no overwrite
question; it overwrites the CSR of the same unit, Admin Guide); the file name CUCM gives a CA
certificate in <unit>-trust (its common name, spaces as "_", is assumed - the listing is read
and the name looked for in it, a field takes it when that fails); the words CUCM answers with
(errors are looked for, success is checked by the serial `show cert own` prints); the key
CUCM makes for each unit (RSA 2048 for tomcat / CallManager, EC for the -ECDSA ones is
assumed - the key in the CSR is read and checked). Cisco's UC Certificate Management REST API
(/platformcom/api/v1/certmgr, CUCM 14 and later) was not built on: its request bodies for
making a CSR and uploading a certificate could not be read (developer.cisco.com).
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import (
    Base, PluginError, field, as_bool, ssh_fields, verify_fields, text, pem_blocks, ssh_conn,
    chain_list)
from acmelib.plugins.targets._x509 import is_root

UNITS = ('tomcat', 'tomcat-ECDSA', 'CallManager', 'CallManager-ECDSA')
# the services Cisco's Admin Guide 15 (Table 5) has restarted after a new certificate
RESTART = {
    'tomcat': ['Cisco Tomcat', 'Cisco Tftp'],
    'tomcat-ECDSA': ['Cisco Tomcat', 'Cisco Tftp'],
    'CallManager': ['Cisco CallManager', 'Cisco CTIManager'],
    'CallManager-ECDSA': ['Cisco CallManager', 'Cisco CTIManager'],
}
# what CUCM's CLI says when a command did not do its work
BAD = re.compile(r'^\s*(.*(?:Executed command unsuccessfully|Invalid command|[Ii]nvalid '
                 r'(?:certificate|unit|input|argument)|Error(?:\s|:)|ERROR|not permitted|'
                 r'[Pp]ermission denied|[Uu]nable to|[Ff]ailed to|not found|Syntax error).*)$',
                 re.M)
CSR_RE = re.compile(r'-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----.*?'
                    r'-----END (?:NEW )?CERTIFICATE REQUEST-----', re.S)
VERSION_RE = re.compile(r'Active Master Version:\s*(\S+)')
FILE_RE = re.compile(r'^\s*([A-Za-z-]+-trust)/([^\s:]+\.(?:pem|der|cer|crt))\s*:?(.*)$', re.M)


def file_stem(cn):
    """The name CUCM is assumed to give a CA certificate in a trust store: its common name,
    what is not a letter, digit, '.', '-' or '_' made '_'."""
    return re.sub(r'[^A-Za-z0-9._-]', '_', text(cn).strip())


def _flat(s):
    return re.sub(r'[^a-z0-9]', '', text(s).lower())


def pasted(pem):
    """A certificate as typed at "Paste the Certificate and Hit Enter": its lines, an empty
    line after."""
    return '\n'.join(x.rstrip() for x in text(pem).strip().splitlines()) + '\n\n'


class CucmTarget(Base):
    kind = 'cucm'
    discovery = False
    title = 'Cisco Unified Communications Manager (CUCM)'
    vendor = 'Cisco'
    description = ('CUCM 14 and 15 (every SU), one node: the certificate of a unit (tomcat '
                   'for the web, AXL and UDS, or CallManager) for a key CUCM makes itself - at '
                   'every issue and renewal acme has the platform CLI over SSH make a new key '
                   'and CSR (set csr gen), imports the certificate signed for it with its CA '
                   'certificates (set cert import) and restarts the unit\'s services.')
    doc = 'targets.md'
    module_version = ''
    version_label = 'CUCM 14 and 15, every SU (platform CLI over SSH)'
    # the device makes the key (docs/writing-a-module.md "The device makes the key"); CUCM's
    # CLI makes RSA 2048 for tomcat / CallManager and an EC key for the -ECDSA units
    device_key = True
    device_key_types = ('rsa-2048', 'ec-256', 'ec-384')

    fields = ssh_fields(sudo=False, user_default='svc-cert', howto='generic',
                        try_command='show version active') + [
        field('unit', 'Certificate', 'select', default='tomcat',
              options=[['tomcat', 'tomcat (web, AXL, UDS, SAML SP) - RSA'],
                       ['tomcat-ECDSA', 'tomcat-ECDSA - EC'],
                       ['CallManager', 'CallManager (SIP / SCCP TLS) - RSA'],
                       ['CallManager-ECDSA', 'CallManager-ECDSA - EC']],
              help='one unit a target; a CallManager restart registers the node\'s phones '
                   'again'),
        field('cli_timeout', 'Time for a CLI command (s)', 'number', default=600,
              advanced=True, help='CUCM\'s CLI starts slowly; a service restart takes minutes'),
    ]
    deploy_fields = [
        field('restart', 'Restart the services', 'bool', default=True,
              help='tomcat: Cisco Tomcat and Cisco Tftp; CallManager: Cisco CallManager and '
                   'Cisco CTIManager (phones register again) - off: restart them yourself, '
                   'CUCM keeps serving the old certificate until then'),
        field('root_pem', 'Root CA certificate', 'pem',
              help='the root the chain ends in, imported to <unit>-trust with the '
                   'intermediates (ISRG Root X1 for Let\'s Encrypt); empty: the last '
                   'certificate of the chain when it is a root'),
        field('ca_file', 'CA file in the trust store', 'text', advanced=True,
              placeholder='tomcat-trust/Example_Issuing_CA.pem',
              help='the CA certificate "set cert import own" names; empty: the issuer of '
                   'the certificate as found in "show cert list trust"'),
    ] + verify_fields(8443)

    @staticmethod
    def served_wait(options):
        # Cisco Tomcat comes back in minutes after its restart
        return (20, 30) if as_bool((options or {}).get('restart', True), True) else None

    def served_places(self, options):
        if not self.c('host') or not self.unit().startswith('tomcat'):
            return []
        return [(self.c('host'), 8443)]

    # -- the CLI --------------------------------------------------------------------------
    def unit(self):
        u = text(self.c('unit') or 'tomcat').strip()
        if u not in UNITS:
            raise PluginError('%s is not a certificate unit acme handles (%s)' % (
                u, ', '.join(UNITS)), retry=False)
        return u

    def ssh(self):
        return self.ctx.ssh(ssh_conn(self))

    def cli(self, s, lines, what, check=True):
        """Lines typed into CUCM's CLI over the input of one SSH session, `exit` after."""
        script = ''.join(x if x.endswith('\n') else x + '\n' for x in lines) + 'exit\n'
        try:
            limit = int(self.c('cli_timeout', 600) or 600)
        except (TypeError, ValueError):
            limit = 600
        rc, out, err = s.run('', input=script, timeout=max(60, limit), check=False)
        out = text(out) + text(err)
        if check:
            m = BAD.search(out)
            if m:
                raise PluginError('%s: CUCM said "%s"' % (what, m.group(1).strip()[:200]),
                                  detail=out[-4000:], retry=False)
        return out

    def version(self, s):
        m = VERSION_RE.search(self.cli(s, ['show version active'], 'show version active',
                                       check=False))
        return m.group(1) if m else ''

    # -- the CSR CUCM makes --------------------------------------------------------------
    def device_csr(self, req):
        from acmelib.certs import pki
        unit = self.unit()
        ec = unit.endswith('-ECDSA')
        if ec != text(req.key_type).startswith('ec-'):
            raise PluginError('CUCM makes %s keys for %s - choose %s for the certificate, or '
                              'the unit %s' % ('EC' if ec else 'RSA', unit,
                                               'ec-256 / ec-384' if ec else 'rsa-2048',
                                               unit.replace('-ECDSA', '') if ec
                                               else unit + '-ECDSA'), retry=False)
        if any('*' in n for n in req.names):
            raise PluginError('CUCM takes no wildcard certificate (Cisco\'s Security Guide)',
                              retry=False)
        with self.ssh() as s:
            out = self.cli(s, ['set csr gen %s' % unit, 'show csr own %s/%s.csr' % (unit, unit)],
                           'making the CSR (set csr gen %s)' % unit)
        m = CSR_RE.search(out)
        if not m:
            raise PluginError('CUCM printed no CSR after "set csr gen %s"' % unit,
                              detail=out[-4000:])
        csr = m.group(0).replace('NEW CERTIFICATE REQUEST', 'CERTIFICATE REQUEST')
        csr = '\n'.join(x.strip() for x in csr.splitlines() if x.strip()) + '\n'
        info = pki.csr_info(csr)
        if info['key_type'] != req.key_type:
            raise PluginError('CUCM made a %s key for %s, the certificate asks for %s - choose '
                              '%s for the certificate' % (info['key_type'], unit, req.key_type,
                                                          info['key_type']), retry=False)
        got = [v for t, v in info.get('san') or [] if t in ('DNS', 'IP')] or [info['cn']]
        want = [text(n).lower().rstrip('.') for n in req.names]
        have = [text(n).lower().rstrip('.') for n in got]
        if sorted(set(want)) != sorted(set(have)):
            raise PluginError('CUCM puts %s into its CSR for %s (its CLI takes no names) - give '
                              'the certificate exactly these names (the certificate has %s)'
                              % (', '.join(got), unit, ', '.join(req.names)), retry=False)
        self.ctx.step('CUCM made a new %s key and a CSR for %s (%s)' % (
            info['key_type'], ', '.join(got), unit), 'ok')
        return csr

    # -- the certificate put back -----------------------------------------------------
    def _cas(self, bundle, options):
        chain = [p for p in chain_list(bundle)]
        root = pem_blocks(text(options.get('root_pem')))
        out = [p for p in chain if not is_root(p)]
        roots = [p for p in chain if is_root(p)] or root[:1]
        return out + roots[:1]

    def _ca_file(self, unit, listing, issuer_cn, options):
        given = text(options.get('ca_file')).strip()
        if given:
            if not re.match(r'^[A-Za-z-]+-trust/[A-Za-z0-9._()-]+$', given):
                raise PluginError('the CA file is <unit>-trust/<file>.pem - %r is not' % given,
                                  retry=False)
            return given
        want = _flat(file_stem(issuer_cn))
        for store, name, _rest in FILE_RE.findall(listing):
            if store == unit + '-trust' and _flat(name.rsplit('.', 1)[0]) == want:
                return '%s/%s' % (store, name)
        return '%s-trust/%s.pem' % (unit, file_stem(issuer_cn))

    def deploy(self, bundle, options):
        from acmelib.certs import pki
        options = options or {}
        if getattr(bundle, 'key_pem', None):
            raise PluginError('CUCM takes only a certificate for a key it made itself - let its '
                              'device make the key (the certificate → Key: "Key made by the '
                              'device")', retry=False)
        unit = self.unit()
        leaf = text(bundle.cert_pem).strip() + '\n'
        info = pki.cert_info(leaf)
        cas = self._cas(bundle, options)
        if not cas:
            raise PluginError('no CA certificate to import into %s-trust: paste the root CA '
                              'certificate in the deployment\'s options' % unit, retry=False)
        issuer = text((info.get('issuer') or {}).get('CN'))
        with self.ssh() as s:
            listing = self.cli(s, ['show cert list trust'], 'reading %s-trust' % unit,
                               check=False)
            new = []
            for ca in cas:
                cn = text((pki.cert_info(ca).get('subject') or {}).get('CN'))
                there = any(st == unit + '-trust' and
                            _flat(nm.rsplit('.', 1)[0]) == _flat(file_stem(cn))
                            for st, nm, _r in FILE_RE.findall(listing))
                if there:
                    self.ctx.step('%s is in %s-trust already' % (cn, unit))
                else:
                    new.append((cn, ca))
            if new:
                lines = []
                for cn, ca in new:
                    lines += ['set cert import trust %s-trust' % unit, pasted(ca)]
                lines.append('show cert list trust')
                listing = self.cli(s, lines, 'importing the CA certificates into %s-trust'
                                   % unit)
                self.ctx.step('imported %s into %s-trust' % (
                    ', '.join(cn for cn, _ca in new), unit), 'ok')
            ca_file = self._ca_file(unit, listing, issuer, options)
            out = self.cli(s, ['set cert import own %s %s' % (unit, ca_file), pasted(leaf),
                               'show cert own %s/%s.pem' % (unit, unit)],
                           'importing the certificate (set cert import own %s)' % unit)
            serial = _flat(info.get('serial')).lstrip('0')
            if serial and serial not in _flat(out):
                self.ctx.step('"show cert own %s/%s.pem" does not show the new serial - look '
                              'at the certificate in Cisco Unified OS Administration'
                              % (unit, unit), 'warn')
            else:
                self.ctx.step('CUCM took the certificate for %s (%s)' % (unit, ca_file), 'ok')
            if as_bool(options.get('restart', True), True):
                for svc in RESTART[unit]:
                    self.cli(s, ['utils service restart %s' % svc], 'restarting %s' % svc)
                    self.ctx.step('restarted %s' % svc, 'ok')
                if unit.startswith('CallManager'):
                    self.ctx.step('in mixed mode the CTL file needs an update now: utils ctl '
                                  'update CTLFile', 'warn')
            else:
                self.ctx.step('restart %s yourself - CUCM serves the old certificate until '
                              'then' % ' and '.join(RESTART[unit]), 'warn')
        self.remember(bundle, options)
        return 'imported the %s certificate for CUCM\'s own key%s' % (
            unit, ', services restarted' if as_bool(options.get('restart', True), True) else '')

    def test(self):
        unit = self.unit()
        with self.ssh() as s:
            ver = self.version(s)
            own = self.cli(s, ['show cert list own'], 'show cert list own', check=False)
        if not ver:
            raise PluginError('signed in, but "show version active" told no version - is this '
                              'CUCM\'s platform CLI (an OS administrator account)?',
                              detail=own[-2000:], retry=False)
        major = re.match(r'(\d+)', ver)
        note = '' if major and int(major.group(1)) >= 14 else \
            ' - acme\'s module is for CUCM 14 and 15'
        has = '%s/%s.pem' % (unit, unit) in own
        return 'signed in to %s: CUCM %s%s; %s %s' % (
            self.c('host'), ver, note, unit, 'is there' if has else
            'is not in "show cert list own"')
