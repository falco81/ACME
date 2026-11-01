# -*- coding: utf-8 -*-
"""
Windows over OpenSSH: the PFX imported into LocalMachine\\My, bound to IIS
sites, the RDP listener and Exchange as asked; old ones taken away. Besides,
when asked: the certificate written as files (any formats, any places) and a
PowerShell script run after them (uploaded each time, or one already there).
"""
from __future__ import annotations

import base64
import secrets

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, lines, as_bool, as_int, object_name, name_prefix,
    ssh_fields, verify_fields, keep_field, sha1_thumb, random_password, text, put_scp,
    label_of, stamp, parse_outputs, outputs_for, alt_of, family_of, PFX_FORMATS)
from acmelib.plugins.targets import _script as SC

INTERPS = ('powershell',)


def ps_str(s):
    """A PowerShell single-quoted string."""
    return "'" + text(s).replace("'", "''") + "'"


def encoded(script):
    return base64.b64encode(script.encode('utf-16-le')).decode('ascii')


class WindowsSshTarget(SshMixin, Base):
    kind = 'windows_ssh'
    title = 'Windows server (OpenSSH + PowerShell)'
    vendor = 'Microsoft'
    description = ('Imports the certificate into the machine store, binds it to IIS sites, '
                   'the Remote Desktop listener and Exchange as asked, and removes the '
                   'old ones.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=False, user_default='Administrator', howto='windows',
                        try_command='whoami') + [
        field('tmp_dir', 'Folder for uploads', 'text', default='C:/Windows/Temp', advanced=True),
        field('timeout', 'Timeout (s)', 'number', default=60, advanced=True),
    ] + SC.script_fields(INTERPS, deploy=False, default='powershell')
    deploy_fields = [
        field('iis', 'IIS bindings', 'list',
              placeholder='Default Web Site | www.example.com | 443',
              help='site | host name | port [| ip], one a line. A host name makes an SNI '
                   'binding; none binds the port for all names. Missing https bindings '
                   'are made.'),
        field('rdp', 'Remote Desktop listener', 'bool', default=False),
        field('exchange', 'Exchange services', 'text', advanced=True, placeholder='IIS,SMTP',
              help='Enable-ExchangeCertificate -Services …; empty: not Exchange'),
        field('pfx_format', 'PKCS#12 kind', 'select', default='p12-legacy', advanced=True,
              options=[['p12-legacy', '3DES (any Windows)'],
                       ['pfx', 'AES-256 (Windows Server 2019 and later)']]),
        field('exportable', 'Key exportable', 'bool', default=False, advanced=True),
        field('post_ps', 'PowerShell after', 'list', advanced=True,
              help='lines run last; $thumb is the new thumbprint'),
        keep_field(1),
        field('outputs', 'Files', 'list', ui='files', advanced=True,
              placeholder='pfx C:/certs/{name}.pfx\nfullchain-pem C:/nginx/conf/{name}.crt',
              help='besides the machine store, when asked: one a line, format path - the '
                   'same formats as on Linux (cert-pem, fullchain-pem, key-pem, pfx, '
                   'p12-legacy, jks...); {name} {cn} {service} {date} in paths'),
    ] + SC.password_fields() + [
        field('service', 'Service name', 'text', advanced=True,
              help='{service} in the paths, ACME_SERVICE for the script'),
    ] + SC.script_fields(INTERPS, default='powershell') + verify_fields()
    files_ui = SC.files_ui('windows', INTERPS, SC.layouts('C:/certs/{name}', 'windows'),
                           owners=False)

    _did = []

    def run_ps(self, s, script, what='PowerShell', check=True, timeout=300):
        full = ("$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n"
                "try {\n%s\n} catch { Write-Output ('ERROR: ' + $_.Exception.Message); "
                "exit 1 }\n" % script)
        cmd = ('powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass '
               '-EncodedCommand ' + encoded(full))
        rc, out, err = s.run(cmd, timeout=timeout, check=False)
        out, err = text(out), text(err)
        if check and rc != 0:
            said = [x[7:] for x in out.splitlines() if x.startswith('ERROR: ')]
            raise PluginError('%s failed: %s' % (what, (said[-1] if said else
                                                        (err.strip() or out.strip())[-300:])),
                              detail=out + err)
        return rc, out, err

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.run_ps(s, (
                "$os = (Get-CimInstance Win32_OperatingSystem).Caption\n"
                "$adm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]"
                "::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\n"
                "Write-Output (\"$env:USERNAME|$os|$($PSVersionTable.PSVersion)|$adm\")"),
                'signing in')
        last = [x for x in out.splitlines() if '|' in x][-1:] or ['?|?|?|?']
        user, os_, psv, adm = (last[0].split('|') + ['?'] * 4)[:4]
        if adm.strip().lower() != 'true':
            raise PluginError('signed in as %s, but not as an administrator (elevated)' % user,
                              retry=False)
        return 'signed in as %s on %s, PowerShell %s' % (user, os_, psv)

    def script(self, bundle, options, pfx_path, password):
        thumb = sha1_thumb(bundle)
        fname = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        keep = as_int(options.get('keep', 1), 1)
        flags = '-Exportable' if as_bool(options.get('exportable')) else ''
        sc = [
            "$thumb = %s" % ps_str(thumb),
            "$pw = ConvertTo-SecureString -String %s -AsPlainText -Force" % ps_str(password),
            "$store = 'Cert:\\LocalMachine\\My'",
            "if (-not (Test-Path (Join-Path $store $thumb))) {",
            "  Import-PfxCertificate -FilePath %s -CertStoreLocation $store -Password $pw %s "
            "| Out-Null" % (ps_str(pfx_path), flags),
            "}",
            "Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue" % ps_str(pfx_path),
            "$cert = Get-Item (Join-Path $store $thumb)",
            "$cert.FriendlyName = %s" % ps_str(fname),
            "Write-Output \"IMPORTED $thumb\"",
        ]
        iis = []
        for n, line in enumerate(lines(options.get('iis')), 1):
            parts = [p.strip() for p in line.split('|')]
            if not parts[0]:
                raise PluginError('IIS line %d has no site' % n, retry=False)
            site = parts[0]
            host = parts[1] if len(parts) > 1 else ''
            port = as_int(parts[2], 443) if len(parts) > 2 and parts[2] else 443
            ip = parts[3] if len(parts) > 3 and parts[3] else '*'
            iis.append((site, host, port, ip))
        if iis:
            sc.append("Import-Module WebAdministration")
            for site, host, port, ip in iis:
                sni = 1 if host else 0
                sc += [
                    "$b = Get-WebBinding -Name %s -Protocol https -Port %d -HostHeader %s "
                    "| Select-Object -First 1" % (ps_str(site), port, ps_str(host)),
                    "if (-not $b) { New-WebBinding -Name %s -Protocol https -Port %d "
                    "-HostHeader %s -IPAddress %s -SslFlags %d; "
                    "$b = Get-WebBinding -Name %s -Protocol https -Port %d -HostHeader %s "
                    "| Select-Object -First 1 }" % (ps_str(site), port, ps_str(host), ps_str(ip),
                                                    sni, ps_str(site), port, ps_str(host)),
                    "$b.AddSslCertificate($thumb, 'My')",
                    "Write-Output ('IIS ' + %s)" % ps_str('%s %s:%d' % (site, host or ip, port)),
                ]
        if as_bool(options.get('rdp')):
            sc += [
                "$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]"
                "::GetRSAPrivateKey($cert)",
                "if ($rsa -and $rsa.Key) { $kf = $rsa.Key.UniqueName; foreach ($d in "
                "@(\"$env:ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\", "
                "\"$env:ProgramData\\Microsoft\\Crypto\\Keys\")) { $p = Join-Path $d $kf; "
                "if (Test-Path $p) { icacls $p /grant 'NETWORK SERVICE:R' | Out-Null } } }",
                "$ts = Get-CimInstance -Namespace root/cimv2/TerminalServices "
                "-ClassName Win32_TSGeneralSetting -Filter \"TerminalName='RDP-tcp'\"",
                "Set-CimInstance -InputObject $ts -Property @{SSLCertificateSHA1Hash=$thumb}",
                "Write-Output 'RDP'",
            ]
        ex = (options.get('exchange') or '').strip()
        if ex:
            services = ','.join(x.strip() for x in ex.replace(';', ',').split(',') if x.strip())
            sc += [
                "if (-not (Get-Command Enable-ExchangeCertificate -ErrorAction SilentlyContinue))"
                " { Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn }",
                "Enable-ExchangeCertificate -Thumbprint $thumb -Services %s -Force "
                "-Confirm:$false" % ps_str(services),
                "Write-Output 'EXCHANGE'",
            ]
        for line in lines(options.get('post_ps')):
            sc.append(line)
        if keep >= 0:
            sc += [
                "$used = @()",
                "if (Get-Module -ListAvailable WebAdministration) { Import-Module WebAdministration;"
                " $used += (Get-ChildItem IIS:\\SslBindings -ErrorAction SilentlyContinue | "
                "ForEach-Object { $_.Thumbprint }) }",
                "$old = Get-ChildItem $store | Where-Object { $_.FriendlyName -like %s -and "
                "$_.Thumbprint -ne $thumb } | Sort-Object NotBefore -Descending | "
                "Select-Object -Skip %d" % (ps_str(prefix + '*'), keep),
                "foreach ($o in $old) { if ($used -contains $o.Thumbprint) { Write-Output "
                "('INUSE ' + $o.Thumbprint) } else { Remove-Item -LiteralPath $o.PSPath; "
                "Write-Output ('REMOVED ' + $o.Thumbprint) } }",
            ]
        return '\n'.join(sc)

    # -- files and the script after them ------------------------------------------------
    def _vars(self, bundle, options):
        alt = alt_of(bundle)
        name = label_of(bundle, options)
        return {'name': name, 'date': stamp(bundle),
                'cn': label_of(bundle, {'object_name': (list(bundle.names or [name]))[0]}),
                'service': (options or {}).get('service') or name,
                'alt': family_of(alt) if alt is not None else 'alt'}

    def _files(self, bundle, options, vars):
        return outputs_for(self.ctx, bundle, parse_outputs(options.get('outputs'), vars))

    def _render(self, pairs, options, vars):
        pw = SC.password_of(options)
        out = []
        for o, b in pairs:
            if o['format'] == 'jks' and (not pw or len(pw) < 6):
                raise PluginError('a jks keystore needs a password of 6 characters or more',
                                  retry=False)
            data = b.as_format(o['format'], password=pw if o['format'] in PFX_FORMATS else None,
                               alias=options.get('jks_alias') or vars['name'])
            out.append(data.encode() if isinstance(data, str) else data)
        return out

    def _tmp(self):
        return (self.c('tmp_dir') or 'C:/Windows/Temp').rstrip('/\\')

    def _write_files(self, s, pairs, datas):
        """Each uploaded, then moved into place, the one there kept as .acme-prev.
        -> the paths that were there before."""
        token = secrets.token_hex(6)
        tmps = []
        for i, data in enumerate(datas):
            tmps.append('%s/acme-%s-%d.part' % (self._tmp(), token, i))
            put_scp(s, data, tmps[-1])
        sc = ["$had = @()"]
        for (o, _b), tmp in zip(pairs, tmps):
            p = ps_str(o['path'])
            sc += ["New-Item -ItemType Directory -Force -Path (Split-Path -Parent %s) | Out-Null" % p,
                   "if (Test-Path -LiteralPath %s) { Copy-Item -LiteralPath %s -Destination %s "
                   "-Force; Write-Output ('HAD ' + %s) }" % (p, p, ps_str(o['path'] + '.acme-prev'), p),
                   "Move-Item -LiteralPath %s -Destination %s -Force" % (ps_str(tmp), p)]
        rc, out, err = self.run_ps(s, '\n'.join(sc), 'writing the files', check=False)
        had = [x[4:].strip() for x in out.splitlines() if x.startswith('HAD ')]
        if rc != 0:
            self._put_back(s, pairs, had)
            self.run_ps(s, '; '.join("Remove-Item -LiteralPath %s -Force -ErrorAction "
                                     "SilentlyContinue" % ps_str(t) for t in tmps),
                        'cleaning up', check=False)
            said = [x[7:] for x in out.splitlines() if x.startswith('ERROR: ')]
            raise PluginError('the files could not be written, the previous ones are back: %s'
                              % (said[-1] if said else (err.strip() or out.strip())[-300:]))
        self.ctx.step('wrote %s' % ', '.join(o['path'] for o, _b in pairs), 'ok')
        return had

    def _put_back(self, s, pairs, had):
        sc = []
        for o, _b in pairs:
            p = ps_str(o['path'])
            if o['path'] in had:
                sc.append("Copy-Item -LiteralPath %s -Destination %s -Force"
                          % (ps_str(o['path'] + '.acme-prev'), p))
            else:
                sc.append("Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue" % p)
        if sc:
            rc, out, err = self.run_ps(s, '\n'.join(sc), 'putting the files back', check=False)
            self.ctx.step('the previous files are back' if rc == 0 else
                          'putting the previous files back failed: %s' % (err or out)[-200:],
                          'warn' if rc == 0 else 'bad')

    def _drop_previous(self, s, pairs):
        self.run_ps(s, '; '.join("Remove-Item -LiteralPath %s -Force -ErrorAction "
                                 "SilentlyContinue" % ps_str(o['path'] + '.acme-prev')
                                 for o, _b in pairs), 'cleaning up', check=False)

    def _after(self, s, bundle, options, vars, pairs):
        """The files written and the script run after them; a failing script puts
        the previous files back. -> words for the result, or ''."""
        sc = SC.script_of(self, options, vars, INTERPS)
        if not pairs and not sc:
            return ''
        datas = self._render(pairs, options, vars)
        had = self._write_files(s, pairs, datas) if pairs else []
        if sc:
            env = SC.env_for(self, bundle, pairs, vars, SC.password_of(options),
                             extra={'ACME_THUMBPRINT': sha1_thumb(bundle)})
            rc, out, err = SC.run_windows(self, s, sc, env, self._tmp())
            said = SC.tell(self, sc, rc, out, err)
            if rc != 0:
                if pairs:
                    self._put_back(s, pairs, had)
                raise PluginError('%s failed (exit %s)%s%s' % (
                    SC._what(sc), rc, ', the previous files are back' if pairs else '',
                    (': ' + said.splitlines()[-1][-200:]) if said else ''), retry=False)
        if pairs:
            self._drop_previous(s, pairs)
        return ', '.join(x for x in ('%d file%s' % (len(pairs), '' if len(pairs) == 1 else 's')
                                     if pairs else '', 'the script ran' if sc else '') if x)

    def preview(self, bundle, options):
        options = dict(options or {})
        problems = []
        vars = self._vars(bundle, options)
        try:
            pairs = self._files(bundle, options, vars)
        except PluginError as e:
            problems.append({'level': 'bad', 'words': str(e)})
            pairs = []
        got = SC.preview(self, bundle, options, pairs, vars, problems, owners=False,
                         interps=INTERPS, windows=True)
        got['env']['ACME_THUMBPRINT'] = sha1_thumb(bundle) if getattr(bundle, 'cert_pem', '') \
            else ''
        got['problems'] = [p for p in got['problems'] if p['words'] != 'no files are written']
        return got

    def dry_run(self, bundle, options, run_script=True):
        """Signed in; the files made into a temporary folder; the script run with
        ACME_DRY_RUN=1; the folder deleted. The machine store and the bindings are
        not touched."""
        options = dict(options or {})
        vars = self._vars(bundle, options)
        pairs = self._files(bundle, options, vars)
        sc = SC.script_of(self, options, vars, INTERPS)
        datas = self._render(pairs, options, vars)
        with self.ssh() as s:
            tdir = '%s/acme-test-%s' % (self._tmp(), secrets.token_hex(6))
            self.run_ps(s, "New-Item -ItemType Directory -Force -Path %s | Out-Null" % ps_str(tdir),
                        'signing in')
            self.ctx.step('signed in on %s' % self.c('host'), 'ok')
            try:
                moved = []
                for i, ((o, b), data) in enumerate(zip(pairs, datas)):
                    p = '%s/%d-%s' % (tdir, i + 1, o['path'].replace('\\', '/').split('/')[-1])
                    put_scp(s, data, p)
                    moved.append((dict(o, path=p), b))
                    self.ctx.step('%s: %s, %d B - into the temporary folder' % (
                        o['path'], o['format'], len(data)))
                self.ctx.step('the machine store and the bindings are not touched on a test')
                if sc and run_script:
                    env = SC.env_for(self, bundle, moved, vars, SC.password_of(options),
                                     dry_run=True, extra={'ACME_THUMBPRINT': sha1_thumb(bundle),
                                                          'ACME_TEST_DIR': tdir})
                    rc, out, err = SC.run_windows(self, s, sc, env, self._tmp())
                    SC.tell(self, sc, rc, out, err, dry_run=True)
                    if rc != 0:
                        raise PluginError('%s failed on the test (exit %s)' % (SC._what(sc), rc),
                                          retry=False)
            finally:
                self.run_ps(s, "Remove-Item -LiteralPath %s -Recurse -Force -ErrorAction "
                            "SilentlyContinue" % ps_str(tdir), 'cleaning up', check=False)
                self.ctx.step('the temporary folder is gone')
        return 'the test passed: %d file%s%s' % (len(pairs), '' if len(pairs) == 1 else 's',
                                                 ', the script ran with ACME_DRY_RUN=1'
                                                 if sc and run_script else '')

    def deploy(self, bundle, options):
        options = options or {}
        thumb = sha1_thumb(bundle)
        vars = self._vars(bundle, options)
        pairs = self._files(bundle, options, vars)
        SC.script_of(self, options, vars, INTERPS)      # refused before anything is done
        with self.ssh() as s:
            if self.unchanged(bundle, options, present=lambda: 'YES' in self.run_ps(
                    s, "if (Test-Path 'Cert:\\LocalMachine\\My\\%s') { 'YES' } else { 'NO' }"
                    % thumb, check=False)[1]):
                return self.same(bundle, 'in the machine store')
            password = random_password()
            fmt = options.get('pfx_format') or 'p12-legacy'
            data = bundle.as_format(fmt, password=password, alias=object_name(bundle, options))
            path = '%s/acme-%s.pfx' % ((self.c('tmp_dir') or 'C:/Windows/Temp').rstrip('/\\'),
                                       secrets.token_hex(6))
            put_scp(s, data, path)
            rc, out, err = self.run_ps(s, self.script(bundle, options, path, password),
                                       'importing the certificate')
            self._said(out)
            after = self._after(s, bundle, options, vars, pairs)
        did = ['imported %s' % thumb[:12]] + self._did
        if after:
            did.append(after)
        self.remember(bundle, options)
        return ', '.join(did)

    def _said(self, out):
        did = []
        for line in out.splitlines():
            if line.startswith('IIS '):
                did.append('IIS %s' % line[4:])
                self.ctx.step('bound to IIS %s' % line[4:], 'ok')
            elif line == 'RDP':
                did.append('RDP')
                self.ctx.step('Remote Desktop listener uses it', 'ok')
            elif line == 'EXCHANGE':
                did.append('Exchange')
                self.ctx.step('Exchange uses it', 'ok')
            elif line.startswith('REMOVED '):
                self.ctx.step('removed the old %s' % line[8:])
            elif line.startswith('INUSE '):
                self.ctx.step('the old %s is still bound: kept' % line[6:], 'warn')
        self._did = did
