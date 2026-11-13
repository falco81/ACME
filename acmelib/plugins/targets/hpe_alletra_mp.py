# -*- coding: utf-8 -*-
"""
HPE Alletra 9000 (OS 9.x) and HPE Alletra Storage MP B10000 (OS 10.x) - and the 3PAR /
Primera arrays whose CLI they carry on: the certificate of the "unified-server" service
(WSAPI, the UI / SSMC connection, CIM, the CLI's TLS) for a key the array makes itself ("the
device makes the key", docs/certificates.md "Key made by the device"). The CLI of these
arrays makes the key and a CSR (createcert -csr) and imports the certificate signed for it
(importcert); a private key of acme's cannot be imported there.

    SSH  CLI%  showversion                                    (Try, read only)
    SSH  CLI%  showcert -service unified-server               (Try, read only)
    SSH  CLI%  createcert unified-server -csr -keysize 2048|3072|4096 -C CZ -ST "…" -L "…"
               -O "…" -OU "…" -CN alletra01.example.local
               -SAN "DNS:alletra01.example.local,IP:10.0.0.60"           -> the CSR (PEM)
    SSH  CLI%  importcert unified-server -ca stdin -f   < the intermediates (when asked)
    SSH  CLI%  importcert unified-server -f stdin       < the certificate
               -> the services of unified-server restart (WSAPI / UI away for a moment)

The CSR changes nothing on the array ("no certificates are modified and no services are
restarted" - the 3PAR CLI reference on -csr); the import restarts the management services
(not the host I/O).

Sources (2026-11): the vendor guide (navody hpe/alletra-nimble.md, part 2, wholly marked
"unverified" - HPE's CLI reference and WSAPI guide on support.hpe.com were not readable),
the HPE 3PAR Command Line Interface Reference (createcert / importcert / showcert / the
unified-server service, as carried on by Primera and Alletra 9000 / MP), HPE Community
threads showing createcert unified-server -csr with -C -ST -L -O -OU -CN -SAN and importcert
unified-server [-ca] <file>.

NOT checked on an array (said in the guide and the report): the exact createcert options on
OS 9.x / 10.x (the 3PAR form is used; the guide's "-subj" form is not); "stdin" as the file
of importcert over SSH (the CLI over SSH reads no file of acme's machine - the certificate is
fed on standard input); -f on both commands; the RSA sizes offered (2048 - 4096); the role
(super, domain all). A device that answers otherwise fails with the CLI's own words.
"""
from __future__ import annotations

import ipaddress
import re

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, as_int, ssh_fields, verify_fields, text,
    pem_blocks, chain_list, served_fingerprint, fp_of)

SERVICE = 'unified-server'
KEY_SIZE = {'rsa-2048': 2048, 'rsa-3072': 3072, 'rsa-4096': 4096}
# what goes between the double quotes of a CLI argument (the CLI is Tcl: no quote, bracket,
# brace, dollar or backslash may reach it)
VALUE_RE = re.compile(r'^[^"\[\]{}$\\\r\n]{1,128}\Z')
NAME_RE = re.compile(r'^[A-Za-z0-9.*:-]{1,253}\Z')
ERROR_RE = re.compile(r'^\s*(Error|ERROR|error)\b.*$|^.*(Invalid|invalid|not valid|Usage:).*$',
                      re.M)
CSR_RE = re.compile(r'-----BEGIN (NEW )?CERTIFICATE REQUEST-----.+?-----END (NEW )?CERTIFICATE '
                    r'REQUEST-----', re.S)


def _is_ip(name):
    try:
        ipaddress.ip_address(text(name).strip())
        return True
    except ValueError:
        return False


def quoted(v, what):
    v = text(v).strip()
    if not VALUE_RE.match(v):
        raise PluginError('the %s "%s" cannot be given to the array\'s CLI (no quotes, '
                          'brackets, braces, $ or \\)' % (what, v), retry=False)
    return '"%s"' % v


class HpeAlletraMpTarget(SshMixin, Base):
    kind = 'hpe_alletra_mp'
    discovery = False
    title = 'HPE Alletra 9000 / Alletra Storage MP B10000 - key made by the array'
    vendor = 'HPE'
    module_version = ''
    version_label = 'Alletra 9000 (OS 9.x), Alletra MP B10000 (OS 10.x), Primera / 3PAR CLI'
    description = ('The certificate of the unified-server service (WSAPI, UI / SSMC, CIM) of an '
                   'HPE Alletra 9000 or Alletra Storage MP B10000 for a key the array makes: at '
                   'every issue acme runs createcert -csr in the array\'s CLI over SSH and '
                   'imports the signed certificate (importcert). RSA keys. The management '
                   'services restart; host I/O is not touched.')
    doc = 'targets.md'
    device_key = True
    device_key_types = ('rsa-2048', 'rsa-3072', 'rsa-4096')

    fields = ssh_fields(sudo=False, user_default='svc-cert', howto='generic',
                        try_command='showcert -service unified-server') + [
        field('csr_country', 'Country (C)', 'text', required=True, placeholder='CZ',
              help='two letters; the certificate\'s own subject (its profile) wins'),
        field('csr_state', 'State or region (ST)', 'text', required=True, placeholder='Praha'),
        field('csr_city', 'City (L)', 'text', required=True, placeholder='Praha'),
        field('csr_org', 'Organization (O)', 'text', required=True, placeholder='Example s.r.o.'),
        field('csr_ou', 'Unit (OU)', 'text', placeholder='IT'),
        field('https_port', 'HTTPS port of WSAPI / UI', 'number', default=443, advanced=True),
    ]
    deploy_fields = [
        field('import_chain', 'Import the intermediates first', 'bool', default=True,
              help='importcert unified-server -ca: the array keeps the CA certificates of its '
                   'service certificate'),
    ] + verify_fields()

    # the management services restart after an import: a minute or two
    served_wait = (12, 10)

    def cli(self, s, cmd, what, data=None, timeout=300):
        rc, out, err = s.run(cmd, input=data, timeout=timeout, check=False)
        out, err = text(out), text(err)
        bad = ERROR_RE.search(err) or (None if CSR_RE.search(out) else ERROR_RE.search(out))
        if rc != 0 or bad:
            said = bad.group(0).strip() if bad else (err.strip() or out.strip())[-300:]
            raise PluginError('%s: the array\'s CLI said %s' % (what, said or 'exit %s' % rc),
                              detail='CLI%% %s\n%s\n%s' % (cmd, out, err), retry=False)
        return out

    def served_now(self, bundle):
        try:
            return served_fingerprint(self.c('host'), as_int(self.c('https_port', 443), 443),
                                      None) == fp_of(bundle)
        except (OSError, ValueError):
            return False

    # -- the CSR the array makes --------------------------------------------------------
    def command(self, req):
        """The createcert command for the certificate - refused in words before the array
        is reached."""
        kt = text(req.key_type)
        if kt not in KEY_SIZE:
            raise PluginError('the array makes RSA keys (2048, 3072 or 4096 bits) - %s cannot '
                              'be asked of it' % kt, retry=False)
        names = [text(n).strip() for n in req.names]
        for n in names:
            if not NAME_RE.match(n):
                raise PluginError('the name %s cannot be given to the array\'s CLI' % n,
                                  retry=False)
        subj = dict(req.subject or {})
        cn = text(subj.get('CN') or names[0]).strip()
        parts = ['createcert', SERVICE, '-csr', '-keysize', str(KEY_SIZE[kt])]
        for opt, sk, ck, need in (('-C', 'C', 'csr_country', True),
                                  ('-ST', 'ST', 'csr_state', True),
                                  ('-L', 'L', 'csr_city', True),
                                  ('-O', 'O', 'csr_org', True),
                                  ('-OU', 'OU', 'csr_ou', False)):
            v = text(subj.get(sk) or self.c(ck) or '').strip()
            if not v:
                if need:
                    raise PluginError('fill in %s on the target - the CSR carries it' % {
                        '-C': 'Country', '-ST': 'State', '-L': 'City',
                        '-O': 'Organization'}[opt], retry=False)
                continue
            if opt == '-C' and len(v) != 2:
                raise PluginError('the country must be two letters (it is "%s")' % v,
                                  retry=False)
            parts += [opt, quoted(v, opt[1:])]
        parts += ['-CN', quoted(cn, 'common name')]
        parts += ['-SAN', '"%s"' % ','.join(('IP:%s' if _is_ip(n) else 'DNS:%s') % n
                                            for n in names)]
        return ' '.join(parts)

    def device_csr(self, req):
        cmd = self.command(req)
        with self.ssh() as s:
            out = self.cli(s, cmd, 'asking the array for a new key and CSR', timeout=300)
        m = CSR_RE.search(out)
        if not m:
            raise PluginError('the array printed no CSR for createcert -csr', detail=out[-4000:])
        self.ctx.step('the array made a new %s key and a CSR for %s (unified-server)' % (
            req.key_type, ', '.join(req.names)), 'ok')
        return m.group(0).strip() + '\n'

    # -- the certificate put back -----------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        if getattr(bundle, 'key_pem', None):
            raise PluginError('the array takes only a certificate for a key it made itself - '
                              'let its device make the key (the certificate → Key: "Key made '
                              'by the device")', retry=False)
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by WSAPI / UI')
        leaf = pem_blocks(bundle.cert_pem)[0].strip() + '\n'
        chain = ''.join(p.strip() + '\n' for p in chain_list(bundle))
        did = []
        with self.ssh() as s:
            if chain and as_bool(self.opt(options, 'import_chain', True), True):
                self.cli(s, 'importcert %s -ca stdin -f' % SERVICE,
                         'importing the intermediates', data=chain + '\n')
                self.ctx.step('the intermediates imported for unified-server', 'ok')
                did.append('the intermediates')
            self.cli(s, 'importcert %s -f stdin' % SERVICE, 'importing the certificate',
                     data=leaf + '\n')
        self.ctx.step('the array took the certificate for its own key - the unified-server '
                      'services (WSAPI, UI, CIM) restart', 'ok')
        self.remember(bundle, options)
        return 'imported the unified-server certificate for the array\'s own key' + (
            ' and %s' % ', '.join(did) if did else '')

    def test(self):
        with self.ssh() as s:
            ver = self.cli(s, 'showversion', 'reading the version', timeout=60)
            cert = self.cli(s, 'showcert -service %s' % SERVICE, 'reading the certificate',
                            timeout=60)
        rel = re.search(r'Release version\s+(\S+)', ver)
        first = [ln.strip() for ln in cert.splitlines() if ln.strip()][:3]
        return 'signed in to %s: release %s; %s' % (
            self.c('host'), rel.group(1) if rel else '?', ' / '.join(first) or
            'showcert answered')

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('https_port', 443), 443))] \
            if self.c('host') else []
