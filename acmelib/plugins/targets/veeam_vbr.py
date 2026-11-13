# -*- coding: utf-8 -*-
"""
Veeam Backup & Replication (Windows): the backup server certificate - the TLS certificate
the components, agents, plug-ins and consoles trust the backup server by; in v13 also the
one of its web UI and REST API (443, 9419) - replaced through Veeam's PowerShell module,
signed in to the server over OpenSSH:

    Import-PfxCertificate ... Cert:\\LocalMachine\\My        (a one-time PKCS#12)
    $c = Get-VBRBackupServerCertificate -FromStore | Where-Object Thumbprint -eq <thumb>
    Add-VBRBackupServerCertificate -Certificate $c [-Force]   (-Force exists from v13 only)
    netsh http add sslcert ipport=0.0.0.0:9419 certhash=<thumb>
          appid={284175c4-aa3e-4c6f-a2dd-5a4c80552eb9}       (12.x: the REST API's binding)

Sources (the vendor guide navody/certifikaty/veeam/vbr-server.md, 2026-11, citing):
    https://helpcenter.veeam.com/docs/vbr/userguide/backup_server_certificate.html?ver=13
    https://helpcenter.veeam.com/docs/vbr/userguide/tls_internal_ca.html?ver=13
    https://helpcenter.veeam.com/docs/vbr/powershell/add-vbrbackupservercertificate.html
    https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrbackupservercertificate.html
    https://helpcenter.veeam.com/archive/backup/120/powershell/add-vbrbackupservercertificate.html
    https://helpcenter.veeam.com/archive/backup/120/vbr_rest/tls_certificate.html
    https://www.veeam.com/kb4687

Versions of the module (what differs for this job):

  ''      any version - tells v13 from 12.x by the cmdlet (Add-VBRBackupServerCertificate has
          -Force from v13 on) and does what that one needs
  '12.3'  VBR 12.3: Add-VBRBackupServerCertificate without -Force; the REST API (9419) is an
          http.sys binding of its own, moved to the new certificate with netsh
  '13'    VBR 13.0 - 13.1: -Force; the web UI and REST API use the backup server certificate
          by themselves (no netsh)

Veeam takes only a certificate of an internal CA made from the Subordinate CA template:
Basic Constraints CA with path length 0, RSA 2048+ in a legacy CSP (Key Type Exchange), the
subject the server's FQDN, FQDN and NetBIOS name in the SAN - not one of a public CA, not
ECC, not CNG. acme says so, before anything is changed, of a certificate that is not such.

Less certain (the guide's own unverified points): whether Add-VBRBackupServerCertificate
restarts the backup service itself ("requires the restart of the backup service" - the
deployment can restart the services named); the service name (VeeamBackupSvc); the
property names of the certificate object (Thumbprint is read); whether v13 on Windows
needs no netsh binding; Get-VBRBackupServerInfo (only words) is not in the guide.
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import (
    PluginError, field, lines, as_bool, sha1_thumb, verify_fields, family_of, pem_to_der)
from acmelib.plugins.targets._veeam import VeeamPsTarget, ps_str, keep_field

REST_APPID = '{284175c4-aa3e-4c6f-a2dd-5a4c80552eb9}'

# The module versions and the VBR generations each is for - for the words said when the
# server runs another one.
RANGES = (('12.3', 'VBR 12.3', 12), ('13', 'VBR 13.0 - 13.1', 13))


def version_for(gen):
    for mv, label, g in RANGES:
        if g == gen:
            return mv, label
    return '', ''


def _der_len(der, i):
    n = der[i]
    if n < 0x80:
        return n, i + 1
    k = n & 0x7f
    return int.from_bytes(der[i + 1:i + 1 + k], 'big'), i + 1 + k


def basic_constraints(pem):
    """(cA, pathLen) of a certificate's Basic Constraints, None when it has none - read from
    the DER by the extension's OID (2.5.29.19), no library needed."""
    der = pem_to_der(pem)
    oid = b'\x06\x03\x55\x1d\x13'
    at = der.find(oid)
    if at < 0:
        return None
    i = at + len(oid)
    if der[i] == 0x01:                      # critical BOOLEAN
        i += 3
    if der[i] != 0x04:                      # extnValue OCTET STRING
        return None
    _n, i = _der_len(der, i + 1)
    if der[i] != 0x30:
        return None
    n, i = _der_len(der, i + 1)
    end, ca, plen = i + n, False, None
    while i < end:
        tag = der[i]
        ln, j = _der_len(der, i + 1)
        if tag == 0x01:
            ca = der[j] != 0
        elif tag == 0x02:
            plen = int.from_bytes(der[j:j + ln], 'big')
        i = j + ln
    return ca, plen


class VeeamVbrTarget(VeeamPsTarget):
    kind = 'veeam_vbr'
    discovery = False
    title = 'Veeam Backup & Replication (backup server certificate)'
    module_version = ''
    version_label = 'any version (detects it)'
    description = ('Replaces the backup server certificate of Veeam Backup & Replication on '
                   'Windows through its PowerShell module over SSH (also the web UI and REST '
                   'API certificate of v13). Any version: v13 or 12.3 is told from the cmdlet, '
                   'and the 12.3 REST API binding moved too.')
    deploy_fields = [
        field('restart_services', 'Restart these services', 'list', advanced=False,
              placeholder='VeeamBackupSvc',
              help='after the certificate is set, one service name a line (Restart-Service): '
                   'Veeam says the backup service must restart - every running job is '
                   'stopped, so empty keeps it for your maintenance window; the Veeam AHV '
                   'Service too when the Nutanix AHV plug-in is used'),
        field('rest_binding', 'Move the REST API binding (12.3, port 9419)', 'bool',
              default=True, advanced=True,
              help='VBR 12.x: netsh http sslcert on 0.0.0.0:9419 to the new certificate'),
        field('allow_leaf', 'Deploy a certificate that is not a CA one', 'bool',
              default=False, advanced=True,
              help='Veeam takes only a certificate with Basic Constraints CA (path length 0); '
                   'acme refuses another one unless this is on'),
        keep_field(1),
    ] + verify_fields(443)

    generation = None               # 12 / 13: what a version sends; None - detected
    checked_to = 13                 # the newest VBR in the documents it was checked by

    def range_words(self):
        return self.version_label if self.generation else 'any VBR'

    def test(self):
        with self.ssh() as s:
            who = self.admin_check(s)
            info = self.server_info(s)
        self.check_version(info)
        return 'signed in as %s; Veeam Backup & Replication %s, backup server certificate %s' % (
            who, info.get('build') or ('v%s' % info['gen'] if info.get('gen') else '?'),
            (info.get('current') or '?')[:12])

    def server_info(self, s):
        """{'gen': 12 | 13 | None, 'build', 'current'} - read, nothing changed."""
        rc, out, err = self.ps(s, '\n'.join([
            self.module_line(),
            "$cmd = Get-Command Add-VBRBackupServerCertificate -ErrorAction Stop",
            "Write-Output ('FORCE ' + $cmd.Parameters.ContainsKey('Force'))",
            "try { $i = Get-VBRBackupServerInfo -ErrorAction Stop; Write-Output ('BUILD ' + "
            "$i.Build) } catch { }",
            "try { $cur = Get-VBRBackupServerCertificate -ErrorAction Stop; Write-Output "
            "('CURRENT ' + $cur.Thumbprint) } catch { }",
        ]), 'reading Veeam Backup & Replication', timeout=self.timeout_s())
        force = (self.said(out, 'FORCE') or [''])[-1].lower()
        build = (self.said(out, 'BUILD') or [''])[-1]
        gen = None
        m = re.match(r'^(\d+)\.', build)
        if m:
            gen = int(m.group(1))
        elif force in ('true', 'false'):
            gen = 13 if force == 'true' else 12
        cur = (self.said(out, 'CURRENT') or [''])[-1].upper()
        return {'gen': gen, 'build': build, 'current': cur, 'force': force == 'true'}

    def check_version(self, info):
        """A version of the module on a VBR it is not for: refused, before anything is changed
        (its cmdlet would be called wrong). Not known: said, and gone on."""
        gen = info.get('gen')
        if not self.generation:
            return
        if gen is None:
            self.ctx.step('the version of Veeam Backup & Replication cannot be read - the '
                          'calls of %s are used' % self.version_label, 'warn')
            return
        if gen != self.generation and not (gen > self.checked_to and self.generation ==
                                           self.checked_to):
            fit = version_for(gen)[1] or VeeamVbrTarget.version_label
            raise PluginError(
                'this server runs Veeam Backup & Replication %s - the module version "%s" is '
                'for %s; choose the version "%s" of the target' % (
                    info.get('build') or 'v%d' % gen, self.version_label, self.range_words(),
                    fit), retry=False)
        if gen > self.checked_to:
            self.ctx.step('Veeam Backup & Replication %s is newer than the documents this '
                          'module version was checked against (%d)' % (
                              info.get('build') or gen, self.checked_to), 'warn')

    def check_certificate(self, bundle, options):
        if as_bool(options.get('allow_leaf')):
            return
        bc = basic_constraints(bundle.cert_pem)
        why = []
        if not bc or not bc[0]:
            why.append('it has no Basic Constraints CA (Veeam: Subject Type = CA, path '
                       'length 0 - a certificate from a template made from Subordinate '
                       'Certification Authority)')
        elif bc[1] not in (0, None):
            why.append('its path length is %s, Veeam wants 0' % bc[1])
        fam = family_of(bundle)
        if fam and fam != 'rsa':
            why.append('its key is %s - Veeam takes RSA (2048 or more) only' % fam.upper())
        if why:
            raise PluginError('Veeam Backup & Replication would refuse this certificate: %s. '
                              'Issue it from an internal CA as Veeam asks (see the setup '
                              'guide), or turn on "Deploy a certificate that is not a CA one"'
                              % '; '.join(why), retry=False)

    def deploy(self, bundle, options):
        options = options or {}
        self.check_certificate(bundle, options)
        # 1.0.96: the service names refused before signing in - a bad one was found only
        # after the PKCS#12 (the key) had been uploaded, and it stayed on the server
        services = lines(options.get('restart_services'))
        for svc in services:
            if not re.match(r'^[A-Za-z0-9_.$ -]{1,80}$', svc):
                raise PluginError('"%s" is not a service name' % svc, retry=False)
        thumb = sha1_thumb(bundle)
        with self.ssh() as s:
            info = self.server_info(s)
            if self.unchanged(bundle, options, present=lambda: info.get('current') == thumb):
                return self.same(bundle, 'as the backup server certificate')
            self.check_version(info)
            gen = self.generation or info.get('gen')
            if gen is None:
                gen = 13 if info.get('force') else 12
                self.ctx.step('the version cannot be read: the calls of VBR %s are used' % gen,
                              'warn')
            pfx, pw = self.upload_pfx(s, bundle, options)
            try:
                out = self.set_certificate(s, bundle, options, gen, pfx, pw, services)
            except BaseException:
                # 1.0.96: the PKCS#12 removed on every path that did not run the script to
                # its Remove-Item (a refusal, a lost session, a failing step)
                try:
                    self.drop_file(s, pfx)
                except Exception:                       # noqa: BLE001
                    pass
                raise
            self.steps_of(out)
        if not services:
            self.ctx.step('restart the backup service (it stops running jobs) and the consoles '
                          'in a maintenance window - Veeam needs it for the new certificate',
                          'warn')
        self.remember(bundle, options)
        return 'backup server certificate %s set (VBR %s)' % (thumb[:12], gen)

    def set_certificate(self, s, bundle, options, gen, pfx, pw, services):
        """The script that imports the PKCS#12 (and removes it), sets the backup server
        certificate, moves the 12.x REST binding and restarts the services. -> its output"""
        sc = [self.module_line()] + self.import_lines(bundle, options, pfx, pw) + [
            "$c = Get-VBRBackupServerCertificate -FromStore | Where-Object { "
            "$_.Thumbprint -eq $thumb } | Select-Object -First 1",
            "if (-not $c) { throw ('Get-VBRBackupServerCertificate -FromStore does not offer '"
            " + $thumb + ' - it lists only certificates with their private key that Veeam "
            "can use') }",
            "$prev = ''; try { $prev = (Get-VBRBackupServerCertificate).Thumbprint } catch { }",
            "Add-VBRBackupServerCertificate -Certificate $c%s | Out-Null"
            % (' -Force' if gen >= 13 else ''),
            "Write-Output 'STEP ok the backup server certificate is set'",
            "Write-Output ('SET ' + $thumb)",
        ]
        if gen < 13 and as_bool(self.opt(options, 'rest_binding', True), True):
            # 1.0.96: the binding there before (its hash and application ID - read by
            # their shape, netsh words are in the language of Windows) is put back when
            # the add fails: 9419 was left with no certificate, the REST API down
            sc += [
                "$was = (netsh http show sslcert ipport=0.0.0.0:9419) -join ' '",
                "$oldhash = ''; if ($was -match '\\b([0-9a-fA-F]{40})\\b') "
                "{ $oldhash = $Matches[1] }",
                "$oldapp = '%s'; if ($was -match '(\\{[0-9a-fA-F-]{36}\\})') "
                "{ $oldapp = $Matches[1] }" % REST_APPID,
                "netsh http delete sslcert ipport=0.0.0.0:9419 | Out-Null",
                "$r = netsh http add sslcert ipport=0.0.0.0:9419 certhash=$thumb "
                "appid='%s' certstorename=MY" % REST_APPID,
                "if ($LASTEXITCODE -ne 0) { $back = ''; if ($oldhash) { netsh http add "
                "sslcert ipport=0.0.0.0:9419 certhash=$oldhash appid=$oldapp "
                "certstorename=MY | Out-Null; if ($LASTEXITCODE -eq 0) { $back = "
                "' - the previous binding of 0.0.0.0:9419 is back' } else { $back = "
                "' - the previous binding of 0.0.0.0:9419 could not be put back' } }; "
                "throw ('netsh http add sslcert said: ' + ($r -join ' ') + $back) }",
                "Write-Output 'STEP ok the REST API (0.0.0.0:9419) uses it'",
            ]
        sc += ["$used = @($thumb, $prev)"] + self.cleanup_lines(bundle, options)
        for svc in services:
            sc += ["Restart-Service -Name %s -Force" % ps_str(svc),
                   "Write-Output ('STEP ok restarted ' + %s)" % ps_str(svc)]
        rc, out, err = self.ps(s, '\n'.join(sc), 'setting the backup server certificate',
                               timeout=self.timeout_s())
        return out

    @staticmethod
    def served_wait(options):
        # the backup service starts its services delayed: up to ten minutes (KB4687)
        return (20, 30) if lines((options or {}).get('restart_services')) else None

    def served_places(self, options):
        h = self.c('host')
        if not h:
            return []
        if self.generation == 13:
            return [(h, 443)]
        # 12.x has no web UI; its REST API (9419) follows when the binding is moved - and
        # v13's 9419 serves the backup server certificate too
        return [(h, 9419)] if as_bool(self.opt(options, 'rest_binding', True), True) else []


_SAME = (' Imports the certificate into LocalMachine\\My over SSH, makes it the backup server '
         'certificate (Add-VBRBackupServerCertificate) and removes older ones acme put there. '
         'Refused on a server that says another version.')


class VeeamVbr123Target(VeeamVbrTarget):
    """VBR 12.3: no -Force; the REST API's http.sys binding on 9419 moved with netsh."""
    module_version, version_label, generation = RANGES[0]
    description = ('VBR 12.3: Add-VBRBackupServerCertificate without -Force, and the REST '
                   'API binding on port 9419 moved with netsh.' + _SAME)


class VeeamVbr13Target(VeeamVbrTarget):
    """VBR 13.0 - 13.1: -Force; web UI and REST API follow the backup server certificate."""
    module_version, version_label, generation = RANGES[1]
    description = ('VBR 13.0 - 13.1: Add-VBRBackupServerCertificate -Force; the web UI and '
                   'REST API (443, 9419) use the backup server certificate by themselves.'
                   + _SAME)

