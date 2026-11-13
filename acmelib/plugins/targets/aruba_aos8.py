# -*- coding: utf-8 -*-
"""
HPE Aruba Networking ArubaOS 8 over SSH: Mobility Conductor / Mobility Controllers (kind
`aruba_aos8`) and Instant AP clusters (kind `aruba_iap`, a CLI of its own).

AOS 8 takes a certificate file only from its own flash (controllers) or from a URL / TFTP
server it fetches itself (Instant): its REST API documents no call that uploads one, and no
command reads a certificate from the terminal. So acme puts the file on a **staging server**
- a Linux server it reaches over SSH, whose folder is served to the device by TFTP (or, for
a controller, read with the device's own `copy scp:`) - has the device fetch it, imports it,
and deletes it at once from both places (one of them is the private key).

Controllers (`aruba_aos8`), every AOS 8.x (8.6 - 8.13: the same commands):

    stage  put <dir>/acme-<serial>.pfx                         over SSH, removed afterwards
    shell  show version                                         ArubaOS 8.x, else refused
    shell  show crypto-local pki ServerCert|IntermediateCA|TrustedCA
    shell  copy tftp: <stage> acme-<serial>.pfx flash: acme-<serial>.pfx
             (or copy scp: <stage> <user> <dir>/acme-<serial>.pfx flash: ... + its password)
           crypto pki-import pfx ServerCert <name> acme-<serial>.pfx <one-time password>
           (the chain: crypto pki-import pem IntermediateCA|TrustedCA acme-ca-<id> <file>)
    shell  [cd <config node>]
           configure terminal
             [crypto-local pki ServerCert <name> <file>]        on a Conductor's config node
             web-server profile
               no switch-cert / switch-cert <name>              WebUI (restarts the web server)
               no captive-portal-cert / captive-portal-cert <name>     optional
           write memory
    shell  delete filename <file>                               the flash copies
    shell  configure terminal / no crypto-local pki ServerCert <old> / write memory

Instant AP (`aruba_iap`), by the version (`show version`):

  ''      any version (detects it)
  '8.3'   Instant 8.3 - 8.6:   copy tftp <stage> <file> uiserver|cpserver cert <pw> format pem
  '8.7'   Instant 8.7 - 8.13:  crypto pki-import ... ServerCert <url> ... + wlan
          cert-assignment-profile / pki-cert-assign application ui|captive-portal ... +
          commit apply  (from Instant 8.7.0.0 a certificate takes effect only when assigned)

Sources (the vendor guide navody/certifikaty/aruba/aos8-aos10-central.md and the official
pages found for this module - the HPE techdocs CLI Bank):
    https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/aos8/cry-pki-imp.htm
    https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/aos8/crypt_lcl_pki.htm
    https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/aos8/web-srvr-pro.htm
    https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/aos8/copy.htm
    https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/crypto-pki-import.htm
    https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/wlan%20cert-assignment-profile.htm
    https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/instant/copy.htm
    https://arubanetworking.hpe.com/techdocs/Instant_8.x_WebHelp/Content/instant-ug/authentication/upload-cert.htm

UNVERIFIED (no device; the pages above were read through search excerpts, not in full - the
techdocs host could not be opened from where this was written):
    - the lines go to an SSH shell session on its input, no terminal (as Ansible's
      network_cli does); `no paging` first; the password `copy scp:` asks is answered by the
      next line; `enable` + its password only when an enable password is set;
    - `copy tftp:` / `copy scp:` and `crypto pki-import pfx ServerCert <name> <file> <pw>` are
      the CLI Bank's syntax; that the PKCS#12 may carry the chain and the controller serves
      it is not said - hence the chain is also imported as IntermediateCA / TrustedCA;
    - `crypto-local pki ServerCert <name> <file>` on a Conductor's config node, and
      `no switch-cert` before `switch-cert` (the CLI Bank's example) - a standalone
      controller needs no config node;
    - `delete filename <file>`, the layout of `show crypto-local pki ...` (name, original
      file, reference count) are the usual AOS words, not quoted by the pages read;
    - Instant 8.7+: the keyword form of `crypto pki-import` (format / cert-type / url /
      certname / psk) and the URL schemes the AP fetches from (the CLI Bank's example is
      FTP) - the command is a field (Import command) so it can be corrected without a new
      acme; `commit apply` after the assignment; older Instant certificates are not
      removed by acme;
    - Instant 8.3 - 8.6: `copy tftp ... uiserver|cpserver cert <pw> format pem` (the CLI
      Bank / user guide's words; older Instant said ui / cp).
"""
from __future__ import annotations

import posixpath
import re
import secrets
import string

from acmelib.plugins.targets._common import (
    Base, PluginError, field, as_bool, as_int, text, object_name, name_prefix, ours, prune,
    short_serial, chain_id, ssh_fields, ssh_conn, verify_fields, keep_field, quote)
from acmelib.plugins.targets._cisco_aruba import Ranges, VersionCheck, words
from acmelib.plugins.targets._x509 import split_chain

# What AOS says when it did not take a line: "% Invalid input detected at '^' marker.",
# "Error: ...", "... failed", "server certificate "x" not found in path /md"
BAD = re.compile(r'^\s*(%\s*(?:Invalid|Incomplete|Ambiguous|Unknown).*'
                 r'|(?:Error|ERROR|Failed|Fail|Cannot|Unable)\b.*'
                 r'|.*\b(?:error|failed|not found|denied|unacceptable|not allowed)\b.*)$',
                 re.I | re.M)

CHECKED_TO = (8, 13)


def parse_aos(out):
    """`show version` -> (8, 10, 0, 7), None when it is not ArubaOS's."""
    m = re.search(r'ArubaOS.*?Version\s+(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?', text(out),
                  re.I | re.S)
    if not m:
        return None
    return tuple(int(x) for x in m.groups() if x is not None)


def parse_certs(out):
    """`show crypto-local pki <type>` -> {name: reference count} (the table's rows:
    name, original file name, reference count, expired)."""
    got = {}
    for line in text(out).splitlines():
        m = re.match(r'^\s*(\S+)\s+(\S+)\s+(\d+)\b', line)
        if m and not m.group(1).startswith('-'):
            got[m.group(1)] = int(m.group(3))
    return got


def one_time_password(n=20):
    # letters and digits only: AOS refuses quotes, ; < > | and the like in a passphrase
    abc = string.ascii_letters + string.digits
    return ''.join(secrets.choice(abc) for _ in range(n))


def stage_fields(device='controller', url=False, transfer=False):
    """The staging server: a Linux server acme writes the file to over SSH, the device
    fetches it from (TFTP, or the controller's own copy scp:)."""
    out = []
    if transfer:
        out.append(field(
            'transfer', 'The %s fetches the file with' % device, 'select', default='tftp',
            options=[['tftp', 'TFTP from the staging server'],
                     ['scp', 'SCP from the staging server (copy scp:, with its password)']],
            help='AOS 8 takes a certificate only from its flash: acme writes the file to '
                 'the staging server and has the %s copy it from there' % device))
    out += [
        field('stage_host', 'Staging server', 'text', required=True,
              placeholder='tftp.example.local',
              help='a Linux server acme signs in to over SSH and writes the file to (it is '
                   'deleted right after the %s fetched it)' % device),
        field('stage_addr', 'Its address for the %s' % device, 'text',
              placeholder='192.0.2.10',
              help='the address the %s reaches the staging server at; empty: the one above'
                   % device),
        field('stage_dir', 'Folder on the staging server', 'text', default='/srv/tftp',
              help='the TFTP server\'s root (TFTP) or any folder the user may write to (SCP)'),
    ]
    out += ssh_fields(sudo=False, prefix='stage_', user_default='acme', howto='linux',
                      try_command='id -un; uname -n')
    if url:
        out.append(field(
            'stage_url', 'URL the AP fetches it from', 'text',
            default='tftp://{addr}/{file}', advanced=True,
            placeholder='ftp://user:password@{addr}/certs/{file}',
            help='Instant 8.7 and later: {addr} the address above, {file} the file name, '
                 '{dir} the folder'))
    return out


class _Aos8(Base):
    """What the controller and the Instant AP share: one SSH shell session a step, the
    staging server."""
    vendor = 'HPE Aruba Networking'
    doc = 'targets.md'
    discovery = False
    served_wait = (8, 5)

    # -- the device ---------------------------------------------------------------------
    def ssh(self):
        return self.ctx.ssh(ssh_conn(self))

    def cli(self, s, cmds, what, hide=(), check=True):
        """Lines over the input of an SSH shell session (AOS takes configuration commands
        only in a session; one session a step keeps each answer to itself)."""
        head = []
        if self.c('enable_password'):
            head += ['enable', text(self.c('enable_password'))]
        script = '\n'.join(head + ['no paging'] + list(cmds) + ['exit']) + '\n'
        rc, out, err = s.run('', input=script, timeout=300, check=False)
        out = text(out) + text(err)
        for h in [self.c('enable_password')] + list(hide or ()):
            if h:
                out = out.replace(text(h), '…')
        if check:
            m = BAD.search(out)
            if m:
                raise PluginError('%s: the device said "%s"' % (what, m.group(1).strip()[:200]),
                                  detail=out[-4000:], retry=False)
        return out

    def version_of(self, s):
        return parse_aos(self.cli(s, ['show version'], 'show version', check=False))

    # -- the staging server ------------------------------------------------------------
    def stage_conn(self):
        c = ssh_conn(self, prefix='stage_')
        c['host'] = text(self.c('stage_host')).strip()
        return c

    def stage_addr(self):
        return text(self.c('stage_addr') or self.c('stage_host')).strip()

    def stage_dir(self):
        return text(self.c('stage_dir') or '/srv/tftp').strip().rstrip('/') or '/'

    def stage_path(self, name):
        return posixpath.join(self.stage_dir(), name)

    def staged(self):
        if not text(self.c('stage_host')).strip():
            raise PluginError('the staging server is not set: AOS 8 fetches the certificate '
                              'file from it', retry=False)
        return self.ctx.ssh(self.stage_conn())

    def stage_put(self, st, name, data, world=False):
        # a TFTP server reads as nobody: the file is readable by all for the seconds it is
        # there; SCP signs in as the staging user, so it stays the user's own
        st.put(data, self.stage_path(name), 0o644 if world else 0o600)

    def stage_drop(self, st, names):
        if not names:
            return
        try:
            st.run('rm -f -- %s' % ' '.join(quote(self.stage_path(n)) for n in names),
                   check=False)
            self.ctx.step('deleted %s from the staging server' % ', '.join(names))
        except Exception as e:                          # noqa: BLE001
            self.ctx.step('%s may stay on the staging server: %s' % (', '.join(names), e),
                          'warn')

    def stage_test(self):
        with self.staged() as st:
            rc, out, err = st.run('test -d %s && test -w %s && echo writable'
                                  % (quote(self.stage_dir()), quote(self.stage_dir())),
                                  check=False)
        if 'writable' not in text(out):
            raise PluginError('the folder %s on the staging server %s is not there or not '
                              'writable for %s' % (self.stage_dir(), self.c('stage_host'),
                                                   self.c('stage_user')), retry=False)
        return 'the staging folder %s is writable' % self.stage_dir()

    def served_places(self, options):
        if not self.c('host'):
            return []
        o = options or {}
        out = []
        if as_bool(self.opt(o, 'web_admin', True), True):
            out.append((self.c('host'), as_int(self.c('https_port', 4343), 4343)))
        cp = text(o.get('captive_host')).strip()
        if cp and as_bool(self.opt(o, 'captive_portal', False), False):
            out.append((cp, 443))
        return out


# ---------------------------------------------------------------------------
# Mobility Conductor / Mobility Controller
# ---------------------------------------------------------------------------
class ArubaAos8Target(_Aos8):
    kind = 'aruba_aos8'
    title = 'HPE Aruba Networking ArubaOS 8 (Mobility Conductor, controllers)'
    module_version = ''
    version_label = 'any version (detects it)'
    description = ('ArubaOS 8.6 - 8.13 Mobility Conductor or Mobility Controller over SSH: '
                   'the certificate as PKCS#12 put on a staging server, copied by the '
                   'controller to its flash (copy tftp: / copy scp:), imported as a '
                   'ServerCert (crypto pki-import pfx) with its chain, set as the WebUI '
                   'certificate (web-server profile, switch-cert) and optionally the captive '
                   'portal one, saved (write memory); older acme certificates removed. The '
                   'same commands in every AOS 8.x; AOS 6 and AOS 10 are refused.')
    fields = ssh_fields(sudo=False, user_default='acme', howto='generic',
                        try_command='show version') + [
        field('enable_password', 'Enable password', 'secret', advanced=True,
              help='only when the account lands in the non-privileged mode (">"): acme sends '
                   'enable and this password first'),
        field('config_node', 'Configuration node', 'text', advanced=True,
              placeholder='/md/branch or /mm/mynode',
              help='a Mobility Conductor: the node whose web-server profile is changed (cd '
                   '<node>; crypto-local pki there too); empty for a standalone controller'),
        field('https_port', 'WebUI port', 'number', default=4343, advanced=True,
              help='for the test of what is served'),
        field('p12_kind', 'PKCS#12 encryption', 'select', default='legacy', advanced=True,
              options=[['legacy', '3DES with a SHA-1 MAC (what every AOS 8 reads)'],
                       ['aes', 'AES-256 with a SHA-256 MAC']]),
    ] + stage_fields('controller', transfer=True)
    deploy_fields = [
        field('web_admin', 'WebUI management certificate (switch-cert)', 'bool', default=True,
              help='web-server profile, switch-cert: the web server restarts - WebUI and REST '
                   'API sessions on 4343 are cut for a moment'),
        field('captive_portal', 'Captive portal certificate (captive-portal-cert)', 'bool',
              default=False,
              help='web-server profile, captive-portal-cert: new guest sign-ins get it'),
        field('captive_host', 'Captive portal name', 'text', placeholder='captive.example.com',
              show_if={'captive_portal': [True, 'true', '1']},
              help='for the test of what is served on 443; empty: not tested'),
        field('import_chain', 'Import the chain (IntermediateCA, TrustedCA)', 'bool',
              default=True,
              help='each CA of the chain as acme-ca-<id>, once (kept for the next ones)'),
        field('save', 'Save the configuration (write memory)', 'bool', default=True),
        keep_field(1),
    ] + verify_fields(4343)
    default_verify_port = 4343

    def node(self):
        return text(self.c('config_node')).strip()

    def check_aos(self, ver):
        if ver is None:
            self.ctx.step('the ArubaOS version cannot be read - going on as with AOS 8', 'warn')
            return
        if ver[0] != 8:
            raise PluginError(
                'this device runs ArubaOS %s - the target is for AOS 8 (%s); %s' % (
                    words(ver, 4), 'AOS 10 is configured in Central: use the target '
                    'aruba_central' if ver[0] >= 10 else 'AOS 6 has other web-server commands',
                    'nothing was changed'), retry=False)
        if ver[:2] > CHECKED_TO:
            self.ctx.step('ArubaOS %s is newer than the documents this module was checked '
                          'against (8.13)' % words(ver, 4), 'warn')

    def certs(self, s, kind='ServerCert'):
        return parse_certs(self.cli(s, ['show crypto-local pki %s' % kind],
                                    'reading the %s certificates' % kind, check=False))

    def test(self):
        with self.ssh() as s:
            out = self.cli(s, ['show version'], 'signing in', check=False)
            ver = parse_aos(out)
            if ver is None:
                raise PluginError('the answer is not the show version of ArubaOS: %s'
                                  % out.strip()[-200:], retry=False)
            self.check_aos(ver)
            certs = self.certs(s)
        said = 'signed in to %s: ArubaOS %s; %d server certificate%s' % (
            self.c('host'), words(ver, 4), len(certs), '' if len(certs) == 1 else 's')
        return '%s; %s' % (said, self.stage_test())

    # -- the work -------------------------------------------------------------------------
    def fetch_lines(self, fname):
        """The lines that copy fname from the staging server to flash (and what to hide)."""
        if text(self.c('transfer') or 'tftp') == 'scp':
            if text(self.c('stage_auth') or 'key') != 'password' or not self.c('stage_password'):
                raise PluginError('copy scp: signs in to the staging server with a password: '
                                  'set "Sign in with" of the staging server to a password',
                                  retry=False)
            pw = text(self.c('stage_password'))
            return ['copy scp: %s %s %s flash: %s' % (
                self.stage_addr(), self.c('stage_user'), self.stage_path(fname), fname),
                pw], [pw]
        return ['copy tftp: %s %s flash: %s' % (self.stage_addr(), fname, fname)], []

    def bring(self, s, st, fname, data, import_line, what, hide=()):
        """Staging server -> flash -> imported. The staged file is gone afterwards."""
        world = text(self.c('transfer') or 'tftp') != 'scp'
        self.stage_put(st, fname, data, world=world)
        try:
            lines, secret = self.fetch_lines(fname)
            self.cli(s, lines, 'copying %s to flash' % fname, hide=secret)
            self.ctx.step('the controller copied %s to its flash' % fname)
            self.cli(s, [import_line], what, hide=hide)
        finally:
            self.stage_drop(st, [fname])

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=31)
        prefix = name_prefix(bundle, options, maxlen=31)
        fname = 'acme-%s.pfx' % short_serial(bundle, 8)       # AOS: 31 characters at most
        node = self.node()
        flash = []
        with self.ssh() as s:
            ver = self.version_of(s)
            self.check_aos(ver)
            have = self.certs(s)
            if self.unchanged(bundle, options, present=lambda: name in have):
                return self.same(bundle, 'the ServerCert %s' % name)
            did = []
            cas = []
            with self.staged() as st:
                if as_bool(self.opt(options, 'import_chain', True), True):
                    cas = self.chain(s, st, bundle, flash)
                if name not in have:
                    pw = one_time_password()
                    kind = 'p12-legacy' if text(self.c('p12_kind') or 'legacy') == 'legacy' \
                        else 'pfx'
                    flash.append(fname)
                    self.bring(s, st, fname, bundle.as_format(kind, password=pw, alias=name),
                               'crypto pki-import pfx ServerCert %s %s %s' % (name, fname, pw),
                               'importing %s' % name, hide=[pw])
                    if name not in self.certs(s):
                        raise PluginError('the ServerCert %s is not there after the import'
                                          % name, retry=False)
                    self.ctx.step('imported the ServerCert %s' % name, 'ok')
                    did.append('imported %s' % name)
                else:
                    self.ctx.step('the ServerCert %s is there already' % name)
            try:
                cmds = self.config_lines(options, name, fname, cas)
                if cmds:
                    self.mark_pending(bundle)
                    self.cli(s, cmds, 'setting the web-server profile')
                    self.ctx.step('web-server profile%s: %s' % (
                        ' at %s' % node if node else '', self.said(options, name)), 'ok')
                    did.append(self.said(options, name))
                if as_bool(self.opt(options, 'save', True), True):
                    self.cli(s, (['cd %s' % node] if node else []) + ['write memory'],
                             'write memory')
                    self.ctx.step('write memory', 'ok')
                self.done_pending()
            finally:
                self.drop_flash(s, flash)
            self.cleanup(s, options, prefix, name)
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def chain(self, s, st, bundle, flash):
        """The CAs of the chain, each once as acme-ca-<id> -> [(type, name, file)]."""
        mids, root = split_chain(bundle)
        out = []
        have = {'IntermediateCA': self.certs(s, 'IntermediateCA'),
                'TrustedCA': self.certs(s, 'TrustedCA') if root else {}}
        for typ, pem in [('IntermediateCA', p) for p in mids] + \
                ([('TrustedCA', root)] if root else []):
            cid = chain_id(pem)
            cname, cfile = 'acme-ca-%s' % cid, 'acme-ca-%s.pem' % cid
            out.append((typ, cname, cfile))
            if cname in have[typ]:
                continue
            flash.append(cfile)
            self.bring(s, st, cfile, pem.encode('ascii'),
                       'crypto pki-import pem %s %s %s' % (typ, cname, cfile),
                       'importing the %s %s' % (typ, cname))
            self.ctx.step('imported the %s %s' % (typ, cname))
        return out

    def said(self, options, name):
        w = []
        if as_bool(self.opt(options, 'web_admin', True), True):
            w.append('switch-cert %s' % name)
        if as_bool(self.opt(options, 'captive_portal', False), False):
            w.append('captive-portal-cert %s' % name)
        return ', '.join(w)

    def config_lines(self, options, name, fname, cas):
        node = self.node()
        web = as_bool(self.opt(options, 'web_admin', True), True)
        cp = as_bool(self.opt(options, 'captive_portal', False), False)
        if not (web or cp or node):
            return []
        out = (['cd %s' % node] if node else []) + ['configure terminal']
        if node:
            # a Conductor: the certificate imported on it is made known to the node
            out += ['crypto-local pki %s %s %s' % (t, n, f) for t, n, f in cas]
            out.append('crypto-local pki ServerCert %s %s' % (name, fname))
        if web or cp:
            out.append('web-server profile')
            if web:
                out += ['no switch-cert', 'switch-cert %s' % name]
            if cp:
                out += ['no captive-portal-cert', 'captive-portal-cert %s' % name]
            out.append('exit')
        out.append('exit')
        return out

    def drop_flash(self, s, files):
        if not files:
            return
        try:
            self.cli(s, ['delete filename %s' % f for f in files], 'deleting from flash')
            self.ctx.step('deleted %s from flash' % ', '.join(files))
        except PluginError as e:
            self.ctx.step('%s may stay on flash: %s' % (', '.join(files), e), 'warn')

    def cleanup(self, s, options, prefix, current):
        keep = self.keep(options)
        if keep < 0:
            return
        try:
            have = self.certs(s)
        except PluginError as e:
            self.ctx.step('the older certificates stay - the list cannot be read: %s' % e,
                          'warn')
            return
        gone = prune([n for n in have if ours(n, prefix)], prefix, keep, current)
        node = self.node()
        for old in gone:
            if have.get(old):
                self.ctx.step('the older ServerCert %s stays: still referenced %d time(s)'
                              % (old, have[old]), 'warn')
                continue
            try:
                self.cli(s, (['cd %s' % node] if node else []) + [
                    'configure terminal', 'no crypto-local pki ServerCert %s' % old, 'exit',
                    'write memory'], 'removing %s' % old)
            except PluginError as e:
                self.ctx.step('the older ServerCert %s may stay: %s' % (old, e), 'warn')
                continue
            self.ctx.step('removed the older ServerCert %s' % old)


# ---------------------------------------------------------------------------
# Instant AP (the virtual controller of a cluster)
# ---------------------------------------------------------------------------
IAP_RANGES = Ranges((('8.3', 'Instant 8.3 - 8.6', (8, 3, 0), (8, 6, 999)),
                     ('8.7', 'Instant 8.7 - 8.13', (8, 7, 0), None)))

IAP_IMPORT = ('crypto pki-import format {format} cert-type ServerCert url {url} '
              'certname {name} psk {psk}')


class ArubaIapTarget(VersionCheck, _Aos8):
    kind = 'aruba_iap'
    title = 'HPE Aruba Networking Instant AP (AOS 8)'
    module_version = ''
    version_label = 'any version (detects it)'
    description = ('Instant AP 8.3 - 8.13 cluster (the virtual controller) over SSH: the '
                   'certificate put on a staging server and fetched by the AP - Instant 8.7 '
                   'and later: crypto pki-import as a ServerCert, assigned to the WebUI and '
                   'optionally the captive portal (wlan cert-assignment-profile), commit '
                   'apply; Instant 8.3 - 8.6: copy tftp ... uiserver / cpserver. The way is '
                   'chosen by the version show version says.')
    sw_name = 'Instant'
    ranges = IAP_RANGES
    sw_checked_to = CHECKED_TO
    way = None                      # '8.3' | '8.7'; None: by the version said
    fields = ssh_fields(sudo=False, user_default='admin', howto='generic',
                        try_command='show version') + [
        field('https_port', 'WebUI port', 'number', default=4343, advanced=True,
              help='for the test of what is served'),
        field('import_command', 'Import command (Instant 8.7 and later)', 'text',
              default=IAP_IMPORT, advanced=True,
              help='{format} {url} {name} {psk} filled in - change it only when your Instant '
                   'says another syntax'),
    ] + stage_fields('AP', url=True)
    deploy_fields = [
        field('web_admin', 'WebUI certificate', 'bool', default=True,
              help='the WebUI of the virtual controller on 4343 (its web server restarts)'),
        field('captive_portal', 'Captive portal certificate', 'bool', default=False),
        field('captive_host', 'Captive portal name', 'text', placeholder='captive.example.com',
              show_if={'captive_portal': [True, 'true', '1']},
              help='for the test of what is served on 443; empty: not tested'),
    ] + verify_fields(4343)
    default_verify_port = 4343

    def sw_version(self):
        if '_ver' not in self.__dict__:
            self._ver = None
            try:
                with self.ssh() as s:
                    self._ver = self.version_of(s)
            except PluginError as e:
                self.ctx.debug('the version cannot be read: %s' % e)
        return self._ver

    def check_iap(self, ver):
        if ver is not None and ver[0] >= 10:
            raise PluginError('this AP runs AOS %s - AOS 10 APs are configured in Central: '
                              'use the target aruba_central' % words(ver, 4), retry=False)
        self.check_version(ver)

    def way_for(self, ver):
        if self.way:
            return self.way
        if ver is None:
            self.ctx.step('the Instant version cannot be read - the way of Instant 8.7 and '
                          'later is used', 'warn')
            return '8.7'
        if tuple(ver) < (8, 3, 0):
            self.ctx.step('Instant %s is older than the documents (8.3) - the copy tftp way '
                          'is used' % words(ver, 4), 'warn')
        return '8.7' if tuple(ver) >= (8, 7, 0) else '8.3'

    def test(self):
        with self.ssh() as s:
            out = self.cli(s, ['show version'], 'signing in', check=False)
            ver = parse_aos(out)
            if ver is None:
                raise PluginError('the answer is not the show version of Instant: %s'
                                  % out.strip()[-200:], retry=False)
            self._ver = ver
            self.check_iap(ver)
        return 'signed in to %s: Instant %s (%s); %s' % (
            self.c('host'), words(ver, 4), 'cert-assignment-profile'
            if self.way_for(ver) == '8.7' else 'copy tftp', self.stage_test())

    def url(self, fname):
        t = text(self.c('stage_url') or 'tftp://{addr}/{file}')
        return t.replace('{addr}', self.stage_addr()).replace('{file}', fname) \
            .replace('{dir}', self.stage_dir().strip('/'))

    def deploy(self, bundle, options):
        options = options or {}
        if self.unchanged(bundle, options):
            return self.same(bundle, 'on the AP')
        name = object_name(bundle, options, maxlen=31)
        web = as_bool(self.opt(options, 'web_admin', True), True)
        cp = as_bool(self.opt(options, 'captive_portal', False), False)
        if not (web or cp):
            raise PluginError('neither the WebUI nor the captive portal is chosen', retry=False)
        pw = one_time_password()
        with self.ssh() as s:
            ver = self.version_of(s)
            self._ver = ver
            self.check_iap(ver)
            way = self.way_for(ver)
            with self.staged() as st:
                if way == '8.7':
                    did = self.deploy_87(s, st, bundle, name, pw, web, cp)
                else:
                    did = self.deploy_83(s, st, bundle, name, pw, web, cp)
        self.remember(bundle, options)
        return did

    def deploy_87(self, s, st, bundle, name, pw, web, cp):
        fname = 'acme-%s.pfx' % short_serial(bundle, 8)
        url = self.url(fname)
        self.stage_put(st, fname, bundle.as_format('p12-legacy', password=pw, alias=name),
                       world=True)
        try:
            cmd = text(self.c('import_command') or IAP_IMPORT)
            line = cmd.replace('{format}', 'pfx').replace('{url}', url) \
                .replace('{name}', name).replace('{psk}', pw)
            self.cli(s, [line], 'importing %s' % name, hide=[pw, url])
            self.ctx.step('imported the ServerCert %s' % name, 'ok')
        finally:
            self.stage_drop(st, [fname])
        apps = (['ui'] if web else []) + (['captive-portal'] if cp else [])
        self.mark_pending(bundle)
        self.cli(s, ['configure terminal', 'wlan cert-assignment-profile'] +
                 ['pki-cert-assign application %s cert-type ServerCert certname %s' % (a, name)
                  for a in apps] + ['exit', 'exit', 'commit apply'],
                 'assigning %s' % name)
        self.done_pending()
        shown = self.cli(s, ['show cert assignment'], 'show cert assignment', check=False)
        if name not in shown:
            self.ctx.step('show cert assignment does not name %s - check it on the AP' % name,
                          'warn')
        self.ctx.step('assigned %s to %s, commit apply' % (name, ', '.join(apps)), 'ok')
        return 'imported %s, assigned to %s' % (name, ', '.join(apps))

    def deploy_83(self, s, st, bundle, name, pw, web, cp):
        fname = 'acme-%s.pem' % short_serial(bundle, 8)
        # PEM: the key encrypted with the one-time password, the certificate, the chain
        data = bundle.as_format('key-pem-enc', password=pw) + \
            bundle.as_format('fullchain-pem')
        self.stage_put(st, fname, data, world=True)
        self.mark_pending(bundle)
        try:
            for on, verb, what in ((web, 'uiserver', 'the WebUI'),
                                   (cp, 'cpserver', 'the captive portal')):
                if on:
                    self.cli(s, ['copy tftp %s %s %s cert %s format pem'
                                 % (self.stage_addr(), fname, verb, pw)],
                             'loading the certificate of %s' % what, hide=[pw])
                    self.ctx.step('%s has the new certificate (copy tftp ... %s)'
                                  % (what, verb), 'ok')
        finally:
            self.stage_drop(st, [fname])
        self.done_pending()
        return 'loaded for %s' % ', '.join(w for on, w in ((web, 'the WebUI'),
                                                           (cp, 'the captive portal')) if on)


_SAME = (' Refused on an AP that says another Instant version, before anything is changed.')


class ArubaIap83Target(ArubaIapTarget):
    """Instant before 8.7: copy tftp ... uiserver / cpserver - no assignment profile."""
    module_version, version_label, sw_min, sw_max = IAP_RANGES.ranges[0]
    description = ('Instant 8.3 - 8.6: the AP fetches a PEM (key, certificate, chain) from the '
                   'staging server\'s TFTP with copy tftp ... uiserver cert (WebUI) / cpserver '
                   'cert (captive portal) ... format pem.' + _SAME)
    way = '8.3'


class ArubaIap87Target(ArubaIapTarget):
    """Instant 8.7.0.0 and later: imported, then assigned (wlan cert-assignment-profile)."""
    module_version, version_label, sw_min, sw_max = IAP_RANGES.ranges[1]
    description = ('Instant 8.7 - 8.13: crypto pki-import of a PKCS#12 ServerCert from a URL '
                   'on the staging server, pki-cert-assign to ui / captive-portal in wlan '
                   'cert-assignment-profile, commit apply.' + _SAME)
    way = '8.7'
