# -*- coding: utf-8 -*-
"""
Omnissa (VMware) Horizon 8 Connection Server - its Machine Identity certificate (the TLS
certificate of the server, HTML Access and the Blast Secure Gateway), through Windows over
OpenSSH and PowerShell, as the Horizon documents do it by hand:

    Import-PfxCertificate -CertStoreLocation Cert:\\LocalMachine\\My -Exportable
                                     (the key must be exportable - "No qualifying certificates
                                      in keystore" otherwise)
    Import-Certificate -CertStoreLocation Cert:\\LocalMachine\\CA      each intermediate
    the friendly name "vdm" taken off the certificate that had it, given to the new one
                                     (only one certificate may have it)
    Restart-Service wsbroker         (Omnissa Horizon Connection Server; it interrupts
                                      provisioning and Blast sessions)
    older acme certificates beyond "keep" removed from the store, never the one in use

The same for Horizon 8 2212 - 2609 (one module). Each Connection Server of a pod has its own
Machine Identity: one target each, deployed one after another.

Sources: navody/certifikaty/vmware/horizon-uag.md (2026-11) - Horizon 8 Installation and
Upgrade: Configure Horizon Connection Server to Use a New TLS Certificate, Import a Signed
Server Certificate into a Windows Certificate Store, Modify the Certificate Friendly Name,
Import a Root Certificate and Intermediate Certificates into a Windows Certificate Store;
Microsoft's PKI module (Import-PfxCertificate, Import-Certificate).
Why not the Horizon Server REST API (POST /rest/config/v2/connection-servers/action/
import-certificate): it cannot restart the service, which the Horizon documents ask for.
Less certain: the service's name "wsbroker" (its display name since the rebranding is
"Omnissa Horizon Connection Server"; both are looked for); the EC friendly name "vdm.ec" (from
Horizon 2312) - asked for in the form, "vdm" by default.
"""
from __future__ import annotations

import secrets

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, as_int, ssh_fields, verify_fields, keep_field,
    sha1_thumb, random_password, text, put_scp, object_name, chain_list, join_hostport)
from acmelib.plugins.targets import _win_roles as WR


def ps_str(s):
    return WR.ps_str(s)


class HorizonConnectionServerTarget(SshMixin, Base):
    kind = 'horizon_cs'
    title = 'Omnissa Horizon Connection Server'
    vendor = 'Omnissa'
    discovery = False
    description = ('Horizon 8 (2212 - 2609): imports the certificate into the Connection '
                   'Server\'s machine store with an exportable key, moves the friendly name '
                   '"vdm" to it and restarts the Connection Server service - over OpenSSH and '
                   'PowerShell.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=False, user_default='Administrator', howto='windows',
                        try_command='whoami') + [
        field('tmp_dir', 'Folder for uploads', 'text', default='C:/Windows/Temp', advanced=True),
        field('timeout', 'Timeout (s)', 'number', default=60, advanced=True),
    ]
    deploy_fields = [
        field('friendly_name', 'Friendly name', 'select', default='vdm',
              options=[['vdm', 'vdm (Machine Identity)'],
                       ['vdm.ec', 'vdm.ec (an ECDSA Machine Identity, Horizon 2312 and later)']],
              help='the name Horizon finds its certificate by; only one certificate may have it'),
        field('restart', 'Restart the Connection Server service', 'bool', default=True,
              help='Horizon takes the certificate when its service starts; the restart '
                   'interrupts provisioning and Blast sessions'),
        field('intermediates', 'Intermediates into the machine\'s CA store', 'bool',
              default=True, advanced=True),
        keep_field(1),
    ] + verify_fields()

    _roles_tmp = WR.RolesMixin._roles_tmp
    roles_ps = WR.RolesMixin.roles_ps

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.roles_ps(s, (
                "$adm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]"
                "::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\n"
                "$svc = Get-Service -Name wsbroker -ErrorAction SilentlyContinue\n"
                "if (-not $svc) { $svc = Get-Service -DisplayName '*Horizon Connection Server*' "
                "-ErrorAction SilentlyContinue | Select-Object -First 1 }\n"
                "$v = Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { $_.FriendlyName -eq "
                "'vdm' } | Select-Object -First 1\n"
                "Write-Output (\"HZ|$env:USERNAME|$adm|$($svc.Name)|$($svc.Status)|"
                "$($v.Subject)|$($v.NotAfter)\")"), 'signing in')
        last = [x for x in out.splitlines() if x.startswith('HZ|')][-1:] or ['HZ|?|?|||||']
        _hz, user, adm, svc, status, subj, until = (last[0].split('|') + [''] * 7)[:7]
        if adm.strip().lower() != 'true':
            raise PluginError('signed in as %s, but not as an administrator (elevated)' % user,
                              retry=False)
        if not svc:
            raise PluginError('there is no Horizon Connection Server service on %s'
                              % self.c('host'), retry=False)
        return 'signed in as %s; %s is %s; "vdm": %s%s' % (
            user, svc, status or '?', subj or 'none', ', valid to %s' % until if until else '')

    def script(self, bundle, options, pfx, password, cer_paths):
        thumb = sha1_thumb(bundle)
        fname = text(options.get('friendly_name') or 'vdm')
        if fname not in ('vdm', 'vdm.ec'):
            raise PluginError('the friendly name is vdm or vdm.ec, not %s' % fname, retry=False)
        name = object_name(bundle, options)
        keep = as_int(options.get('keep', 1), 1)
        sc = [
            "$thumb = %s" % ps_str(thumb),
            "$store = 'Cert:\\LocalMachine\\My'",
            "$pw = ConvertTo-SecureString -String %s -AsPlainText -Force" % ps_str(password),
            "if (-not (Test-Path (Join-Path $store $thumb))) {",
            "  Import-PfxCertificate -FilePath %s -CertStoreLocation $store -Password $pw "
            "-Exportable | Out-Null" % ps_str(pfx),
            "  Write-Output 'STEP ok imported into LocalMachine\\My with an exportable key'",
            "}",
            "Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue" % ps_str(pfx),
        ]
        for p in cer_paths:
            sc += ["Import-Certificate -FilePath %s -CertStoreLocation Cert:\\LocalMachine\\CA "
                   "| Out-Null" % ps_str(p),
                   "Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue" % ps_str(p)]
        if cer_paths:
            sc.append("Write-Output 'STEP info the intermediates are in LocalMachine\\CA'")
        sc += [
            # the friendly name moved: the old one gets acme's name for it, so it can be
            # recognised and removed later - only acme's ones (dated names) are ever removed
            "foreach ($o in (Get-ChildItem $store | Where-Object { $_.FriendlyName -eq %s -and "
            "$_.Thumbprint -ne $thumb })) { $o.FriendlyName = ('acme-was-' + %s + '-' + "
            "$o.Thumbprint.Substring(0,8)); Write-Output ('STEP info %s taken off ' + "
            "$o.Thumbprint) }" % (ps_str(fname), ps_str(fname), fname),
            "$cert = Get-Item (Join-Path $store $thumb)",
            "if (-not $cert.HasPrivateKey) { throw 'the certificate has no private key in the "
            "store' }",
            "$cert.FriendlyName = %s" % ps_str(fname),
            "Write-Output ('STEP ok the friendly name %s is on ' + $thumb)" % fname,
            "Set-Content -LiteralPath (Join-Path $env:ProgramData 'acme-horizon-%s.txt') -Value "
            "%s -ErrorAction SilentlyContinue" % (fname, ps_str(name)),
        ]
        if keep >= 0:
            sc += [
                # acme's earlier ones only - the thumbprints acme imported here (kept by acme);
                # one acme did not import (renamed acme-was-... above) is never removed
                "$mine = @(%s)" % ', '.join(ps_str(t) for t in self.known() if t != thumb),
                "$old = Get-ChildItem $store | Where-Object { $_.Thumbprint -ne $thumb -and "
                "$_.FriendlyName -ne %s -and ($mine -contains $_.Thumbprint) } | "
                "Sort-Object NotBefore -Descending | Select-Object -Skip %d" % (ps_str(fname),
                                                                                keep),
                "foreach ($o in $old) { Remove-Item -LiteralPath $o.PSPath; Write-Output "
                "('REMOVED ' + $o.Thumbprint) }",
            ]
        return '\n'.join(sc)

    def restart_script(self):
        return '\n'.join([
            "$svc = Get-Service -Name wsbroker -ErrorAction SilentlyContinue",
            "if (-not $svc) { $svc = Get-Service -DisplayName '*Horizon Connection Server*' "
            "-ErrorAction SilentlyContinue | Select-Object -First 1 }",
            "if (-not $svc) { throw 'there is no Horizon Connection Server service' }",
            "Restart-Service -InputObject $svc -Force",
            "$svc.WaitForStatus('Running', [TimeSpan]::FromMinutes(5))",
            "Write-Output ('STEP ok restarted ' + $svc.DisplayName)",
        ])

    def _kv_key(self):
        return 'horizon-thumbs:%s' % self.ident()

    def known(self):
        try:
            v = self.ctx.kv_get(self._kv_key())
        except Exception:                               # noqa: BLE001
            v = None
        return [text(x) for x in v] if isinstance(v, list) else []

    def _remember_thumb(self, thumb):
        have = [t for t in self.known() if t != thumb] + [thumb]
        try:
            self.ctx.kv_set(self._kv_key(), have[-10:])
        except Exception:                               # noqa: BLE001
            pass

    def _steps(self, out):
        removed = []
        for line in text(out).splitlines():
            line = line.strip()
            if line.startswith('STEP '):
                parts = line.split(' ', 2)
                if len(parts) == 3 and parts[1] in ('ok', 'info', 'warn', 'bad'):
                    self.ctx.step(parts[2], parts[1])
            elif line.startswith('REMOVED '):
                removed.append(line[8:])
                self.ctx.step('removed the older %s' % line[8:])
        return removed

    def drop_staged(self, s, paths):
        """The files put for the import taken away; a warning when they cannot be."""
        sc = '\n'.join("Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue"
                       % ps_str(p) for p in paths)
        try:
            if hasattr(self.ctx, 'tidying'):
                with self.ctx.tidying():
                    self.roles_ps(s, sc, 'cleaning up', check=False)
            else:
                self.roles_ps(s, sc, 'cleaning up', check=False)
        except PluginError as e:
            self.ctx.step('%s may stay: %s' % (', '.join(paths), e), 'warn')

    def deploy(self, bundle, options):
        options = options or {}
        thumb = sha1_thumb(bundle)
        fname = text(options.get('friendly_name') or 'vdm')
        with self.ssh() as s:
            if self.unchanged(bundle, options, present=lambda: 'YES' in self.roles_ps(
                    s, "$c = Get-Item -LiteralPath 'Cert:\\LocalMachine\\My\\%s' -ErrorAction "
                       "SilentlyContinue; if ($c -and $c.FriendlyName -eq %s) { 'YES' } else "
                       "{ 'NO' }" % (thumb, ps_str(fname)), 'looking', check=False)[1]):
                return self.same(bundle, 'as "%s" on the Connection Server' % fname)
            password = random_password()
            tmp = self._roles_tmp()
            pfx = '%s/acme-hz-%s.pfx' % (tmp, secrets.token_hex(6))
            cers = []
            staged = [pfx]
            try:
                put_scp(s, bundle.as_format('p12-legacy', password=password,
                                            alias=object_name(bundle, options)), pfx)
                if as_bool(self.opt(options, 'intermediates', True), True):
                    for pem in chain_list(bundle):
                        p = '%s/acme-hz-%s.cer' % (tmp, secrets.token_hex(6))
                        staged.append(p)
                        put_scp(s, pem.encode() if isinstance(pem, str) else pem, p)
                        cers.append(p)
                self.mark_pending(bundle)
                rc, out, err = self.roles_ps(s, self.script(bundle, options, pfx, password,
                                                            cers),
                                             'importing the certificate')
            finally:
                # every path (1.0.96, as _veeam does): a refused upload or import left the
                # PKCS#12 - the key - in the temporary folder
                self.drop_staged(s, staged)
            self._remember_thumb(thumb)
            self._steps(out)
            restarted = False
            if as_bool(self.opt(options, 'restart', True), True):
                rc, out, err = self.roles_ps(s, self.restart_script(),
                                             'restarting the Connection Server', timeout=600)
                self._steps(out)
                restarted = True
            else:
                self.ctx.step('the Connection Server service was not restarted - Horizon uses '
                              'the certificate from its next start', 'warn')
        self.remember(bundle, options)
        self.done_pending()
        return '"%s" is %s%s' % (fname, thumb[:12], ', the service restarted' if restarted else '')

    served_wait = (10, 12)

    def served_places(self, options):
        return [(self.c('host'), 443)] if self.c('host') else []

    def verify(self, bundle, options):
        options = dict(options or {})
        if not options.get('verify') and self.c('host'):
            options['verify'] = join_hostport(self.c('host'), 443)
        options.setdefault('verify_tries', 10)
        options.setdefault('verify_wait', 12)
        return Base.verify(self, bundle, options)
