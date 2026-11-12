# -*- coding: utf-8 -*-
"""
VMware Aria Automation / Automation Orchestrator 8.18 - the ingress certificate (the UI and API
on 443) set with vracli over SSH as root, then the services deployed again:

    the PEM written to /root/acme-ingress-<random>.pem (0600): the RSA private key, the
    certificate, the intermediates, the root - each block on lines of its own (KB 325876,
    KB 423843)
    vracli certificate ingress --validate stdin --parse < the file   checked first, nothing changed
    vracli certificate ingress --set <the file>
    /opt/scripts/deploy.sh             every node of a cluster, the services redeployed: the
                                       product is away for tens of minutes
    the file removed

    vracli certificate ingress --list   (the one there now - "the same" without a change)

A cluster: one node is enough, deploy.sh applies it to all. Behind a load balancer the
certificate must name every node and the load balancer's FQDN; no wildcard (KB 325876).
Managed by Aria Suite Lifecycle: use the aria_lifecycle target instead - it makes the other
products trust the new certificate. VCF Automation 9.x is managed by VCF Operations (fleet
management), which takes only certificates for CSRs it made - not this module.

Sources: navody/certifikaty/vmware/aria-vcf-operations.md (2026-11) - KB 325876, KB 423843,
KB 424434, KB 423661, KB 384243, KB 424674. Less certain (said in the guide): the techdocs
page of 8.18 for vracli was not read; "--sha256 <hash>" is asked for by 8.18.x when the PEM's
blocks are not on lines of their own (acme writes them so - if it is asked all the same, acme
stops and says it).
"""
from __future__ import annotations

import secrets

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, ssh_fields, verify_fields, text, family_of)
from acmelib.plugins.targets import _vmware as V


class AriaAutomationTarget(SshMixin, Base):
    kind = 'aria_automation'
    title = 'VMware Aria Automation / Orchestrator (vracli)'
    vendor = 'VMware'
    discovery = False
    description = ('Aria Automation and Automation Orchestrator 8.18: sets the ingress '
                   'certificate with "vracli certificate ingress --set" over SSH (validated '
                   'first) and runs /opt/scripts/deploy.sh - the services are redeployed.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=False, user_default='root', try_command='vracli version') + [
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('root_pem', 'Root CA certificate', 'pem',
              help='the root, last in the PEM (KB 325876: key, certificate, intermediates, '
                   'root); empty: the chain as it is'),
        field('deploy', 'Run /opt/scripts/deploy.sh', 'bool', default=True,
              help='the certificate is used once the services are deployed again (tens of '
                   'minutes away); off: run it yourself in a maintenance window'),
        field('deploy_timeout', 'Wait for deploy.sh (minutes)', 'number', default=90,
              advanced=True),
    ] + verify_fields()

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.sh(s, 'vracli version 2>/dev/null || true; id -un',
                                   what='signing in')
            rc2, cur, err2 = self.sh(s, 'vracli certificate ingress --list', check=False)
        o = [x for x in out.strip().splitlines() if x.strip()]
        has = 'BEGIN CERTIFICATE' in cur
        return 'signed in as %s; %s; an ingress certificate is %s' % (
            (o[-1:] or ['?'])[0], (o[:1] or ['vracli ?'])[0], 'set' if has else 'not readable')

    def pem(self, bundle, options):
        if family_of(bundle) not in ('rsa', ''):
            raise PluginError('Aria Automation takes an RSA key for its ingress certificate: '
                              'choose an RSA key for this certificate', retry=False)
        root = V.root_of(bundle, options.get('root_pem'))
        blocks = [text(bundle.as_format('key-rsa')), text(bundle.as_format('cert-pem'))] + \
            list(V.intermediates(bundle)) + ([root] if root else [])
        return ''.join(b.strip() + '\n' for b in blocks).encode()

    def deploy(self, bundle, options):
        options = options or {}
        data = self.pem(bundle, options)
        path = '/root/acme-ingress-%s.pem' % secrets.token_hex(6)
        with self.ssh() as s:
            if not self.pending():
                rc, cur, err = self.sh(s, 'vracli certificate ingress --list', check=False)
                # served already (whoever set it): nothing to redeploy - unless forced
                if not as_bool(options.get('force')) and rc == 0 and V.has_cert(cur, bundle):
                    self.remember(bundle, options)
                    return self.same(bundle, 'the ingress certificate')
            s.put(data, path, mode=0o600)
            try:
                rc, out, err = self.sh(s, 'vracli certificate ingress --validate stdin --parse '
                                          '< %s' % path, check=False, timeout=300)
                if rc != 0:
                    raise PluginError('vracli does not take the certificate: %s' % (
                        text(err).strip() or text(out).strip())[-300:], retry=False,
                        detail=text(out) + text(err))
                self.ctx.step('vracli validated the certificate', 'ok')
                self.mark_pending(bundle)
                rc, out, err = self.sh(s, 'vracli certificate ingress --set %s' % path,
                                       check=False, timeout=600)
                said = text(out) + text(err)
                if rc != 0 or '--sha256' in said:
                    raise PluginError('vracli did not set the certificate%s: %s' % (
                        ' (it asks for --sha256: the PEM\'s blocks are not as it wants them - '
                        'KB 423843)' if '--sha256' in said else '', said.strip()[-300:]),
                        retry=False, detail=said)
                self.ctx.step('vracli set the ingress certificate', 'ok')
            finally:
                self.sh(s, 'rm -f %s' % path, check=False)
            if as_bool(self.opt(options, 'deploy', True), True):
                mins = int(float(self.opt(options, 'deploy_timeout', 90) or 90))
                self.ctx.step('running /opt/scripts/deploy.sh - the services are redeployed, '
                              'tens of minutes')
                rc, out, err = self.sh(s, '/opt/scripts/deploy.sh', check=False,
                                       timeout=max(10, mins) * 60)
                if rc != 0:
                    raise PluginError('/opt/scripts/deploy.sh failed (exit %s): %s' % (
                        rc, (text(err).strip() or text(out).strip())[-300:]),
                        detail=text(out) + text(err))
                self.ctx.step('deploy.sh finished: the services use the new certificate', 'ok')
            else:
                self.ctx.step('deploy.sh was not run - the certificate is used once you run it',
                              'warn')
        self.remember(bundle, options)
        self.done_pending()
        return 'ingress certificate set on %s%s' % (
            self.c('host'), ', services deployed' if as_bool(self.opt(options, 'deploy', True),
                                                              True) else '')

    served_wait = (20, 30)

    def served_places(self, options):
        return [(self.c('host'), 443)] if self.c('host') else []
