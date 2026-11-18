# -*- coding: utf-8 -*-
"""
FortiGate (FortiOS REST API with an API token): the certificate imported
under a dated name, then used for the admin GUI, SSL VPN, SSL/SSH inspection
profiles and virtual IPs as asked; older acme ones deleted.

Versions of the module (1.0.94), by the FortiOS REST API documents (Fortinet's
Ansible collection 2.6.0 - every CMDB attribute with the FortiOS versions it is
in, 6.0.0 to 8.0.0 -, schemas read from a FortiGate on 7.4.8, the official 6.0.4
reference, the 7.6 monitor API). What acme uses is the same everywhere but two
reference fields:

  firewall ssl-ssh-profile server-cert   a name up to 6.4; a list of {"name"} from 7.0.0
                                         (its "name" member is in the data from v7.0.0)
  firewall vip ssl-certificate           a name up to 7.4.1; a list of {"name"} from 7.4.2
                                         ("ssl-certificate" v6.0.0-v7.4.1, the list -
                                         Ansible's ssl-certificate-dict - v7.4.2-)

monitor/vpn-certificate/local/import, ca/import, cmdb vpn.certificate/local,
system global admin-server-cert and vpn ssl settings servercert are alike in
6.0 - 8.0. SSL VPN tunnel mode is gone from 7.6.3 (tunnel-ip-pools, dtls-tunnel
... end at v7.6.2), web mode is "Agentless VPN" since, its servercert kept - so
no version of its own. Hence three versions, besides the plain one:

  ''        any version - reads it (monitor/system/status), the other shape tried
            when it is not known or the first is refused (as before 1.0.94)
  '6.0'     FortiOS 6.0 - 6.4      profile: a name     VIP: a name
  '7.0'     FortiOS 7.0 - 7.4.1    profile: a list     VIP: a name
  '7.4.2'   FortiOS 7.4.2 - 8.0    profile: a list     VIP: a list

A version sends its shapes and no other; the FortiOS version the box says is
checked first, one outside the range refused before anything is changed.

Replace in place (1.0.128, every version; over SSH since 1.0.129): a deployment may instead
update a local certificate the FortiGate has already - chosen from "Find on the device" (cmdb
vpn.certificate/local, with_meta for its count of uses; Fortinet factory ones left out) or
typed. Its name stays, so every policy, VIP, ZTNA rule or user-auth setting bound to it keeps
it; nothing is re-pointed but what the deployment lists.

The REST API cannot do it: a PUT of cmdb vpn.certificate/local/<name> with "certificate" is
turned by FortiOS into CLI lines, and the PEM over several lines breaks them ("value parse
error before '-----BEGIN CERTIFICATE-----'", error -651; FortiOS 7.4.13 build 2933). So the
FortiOS CLI over SSH, as an administrator does it (the target's optional SSH sign-in):

    [config global | config vdom / edit <vdom>]      (VDOMs on: by the certificate's range)
    config vpn certificate local
      edit "<name>"
        set password "<one-time>"                     (the key encrypted PKCS#8; refused: plain)
        set private-key "<PEM>"
        set certificate "<the leaf, PEM>"
      abort    - first, to see FortiOS take the lines; then the same with next / end

Its answer is read for errors ("Command fail", "-651", "duplicated", "not a valid"...); then
the certificate is read back (REST, else CLI show) - its fingerprint must be the new one.
FortiOS refuses a local certificate identical to another ("This local certificate is
duplicated"): an unused copy acme made (acme-...) is deleted first, any other stops it before
anything changes. A name not on the box fails first too; cleanup never takes the replaced
one; the intermediates go in as CA certificates through REST, as for a new one.
"""
from __future__ import annotations

import base64
import re
import urllib.parse

from acmelib.plugins.base import Plugin
from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, object_name, name_prefix, prune,
    http_fields, tls_fields, verify_fields, keep_field, chain_list, random_password, text, ours, SEG_PATTERN,
    pem_to_der, fp_of, norm_fp, family_of, ssh_fields, ssh_conn)


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


def fos_words(ver):
    return '.'.join(str(x) for x in ver)


# The module versions and the FortiOS versions each is for (first, last; None: open) -
# for the words said when the box runs another one.
RANGES = (('6.0', 'FortiOS 6.0 - 6.4', (6, 0, 0), (6, 4, 999)),
          ('7.0', 'FortiOS 7.0 - 7.4.1', (7, 0, 0), (7, 4, 1)),
          ('7.4.2', 'FortiOS 7.4.2 - 8.0', (7, 4, 2), None))


def version_for(ver):
    """The module version made for FortiOS `ver` ((major, minor, patch)): (module_version,
    its label), ('', '') when none is (older than 6.0)."""
    for mv, label, lo, hi in RANGES:
        if ver >= lo and (hi is None or ver <= hi):
            return mv, label
    return '', ''


# The SSH sign-in (1.0.129): only "Replace an existing certificate in place" uses it - FortiOS
# takes a new certificate and key for an existing local certificate in its CLI only.
SSH_ONLY = 'only for "Replace an existing certificate in place" - empty: not used'
SSH_LABELS = {
    'ssh_port': ('SSH port', None),
    'ssh_user': ('SSH user (replace in place)',
                 'an administrator who may change VPN certificates (vpngrp read-write; a '
                 'certificate in the global range: scope global) - ' + SSH_ONLY),
    'ssh_auth': ('SSH: sign in with', None),
    'ssh_key': ('The SSH key (replace in place)', None),
    'ssh_password': ('SSH password', SSH_ONLY),
    'ssh_hostkey': ('SSH host key', None),
    'ssh_trust_first': ('Trust the first SSH host key seen', None),
}


def fgt_ssh_fields():
    out = ssh_fields(sudo=False, prefix='ssh_', user_default='', howto='generic',
                     try_command='get system status', via=False)
    for f in out:
        label, help_ = SSH_LABELS.get(f.get('key'), (None, None))
        if label:
            f['label'] = label
        if help_:
            f['help'] = help_
        if f.get('key') == 'ssh_port':
            f['advanced'] = True
    return out


# What the FortiOS CLI says when it does not take a line - read in its answer (1.0.129)
CLI_BAD = re.compile(r'(command fail|return code\s*-?\d+|duplicated|not a valid|parse error|'
                     r'node_check_object fail|unknown action|entry not found|not found|'
                     r'permission denied|access denied|invalid|not allowed|cannot|'
                     r'new entry .* added)', re.I)
B64_LINE = re.compile(r'^[A-Za-z0-9+/=]{12,}$')


def scrub_lines(lines_, hide=()):
    """FortiOS's lines with nothing of a PEM or a password in them: a line cut where a
    PEM begins, a base64 line dropped, a password replaced."""
    out = []
    for ln in lines_:
        ln = text(ln)
        for h in hide or ():
            if h:
                ln = ln.replace(text(h), '\u2026')
        cut = re.search(r'-----(BEGIN|END) ', ln)
        if cut:
            ln = ln[:cut.start()].rstrip() + ' \u2026'
        st = ln.strip().strip('"\'')
        if not st or B64_LINE.match(st):
            continue
        out.append(ln.rstrip()[:200])
    return out


def cli_errors(out, hide=()):
    """The lines of a FortiOS CLI answer that say it refused something (scrubbed)."""
    return [ln.strip() for ln in scrub_lines(text(out).splitlines(), hide)
            if CLI_BAD.search(ln)]


def trim_answer(raw):
    """A FortiOS REST answer fit to be kept in a job's steps: its cli_error lines with no PEM
    in them, no certificate or key; anything else of it scrubbed line by line."""
    import json as _json
    d = raw
    if not isinstance(d, (dict, list)):
        try:
            d = _json.loads(text(raw))
        except ValueError:
            return '\n'.join(scrub_lines(text(raw).splitlines()))[:2000]
    if isinstance(d, dict):
        d = dict(d)
        for k in ('certificate', 'private-key', 'password', 'results'):
            d.pop(k, None)
        if isinstance(d.get('cli_error'), list):
            d['cli_error'] = [x for x in scrub_lines(d['cli_error']) if CLI_BAD.search(x)]
        for k, v in list(d.items()):
            if isinstance(v, str) and ('-----BEGIN' in v or '\n' in v):
                d[k] = ' / '.join(scrub_lines(v.splitlines()))
    out = _json.dumps(d, default=str, ensure_ascii=False)
    if '-----BEGIN' in out:
        out = out[:out.index('-----BEGIN')] + '\u2026'
    return out[:3000]


def cli_quote(v):
    return '"%s"' % text(v).replace('\\', '\\\\').replace('"', '\\"')


class FortiGateTarget(HttpTarget):
    kind = 'fortigate'
    title = 'FortiGate'
    vendor = 'Fortinet'
    module_version = ''
    version_label = 'any version (detects it)'
    description = ('Imports the certificate through the FortiOS REST API and uses it for the '
                   'admin GUI, SSL VPN, inspection profiles and virtual IPs; deletes older '
                   'ones acme put there. Any FortiOS: the shapes of the profile and VIP '
                   'certificate fields are taken from the version the FortiGate says. Or '
                   'replaces a certificate the FortiGate has in place (its name and uses kept).')
    doc = 'targets.md'
    fields = http_fields(443, 'fw.example.local') + [
        field('token', 'API token', 'secret', required=True,
              help='System → Administrators → REST API Admin'),
        field('vdom', 'VDOM', 'text', default='root',
              help='empty on a FortiGate without VDOMs'),
    ] + tls_fields() + fgt_ssh_fields()
    deploy_fields = [
        # Replace in place (1.0.128): the certificate the FortiGate has already - its name,
        # and everything that uses it (policies, VIPs, ZTNA, user auth...) kept
        field('mode', 'Certificate on the FortiGate', 'select', default='new',
              options=[['new', 'a new one each time (acme-<name>-<date>), the uses below '
                                'switched to it'],
                       ['replace', 'Replace an existing certificate in place']],
              help='Replace in place: the certificate keeps its name and everything bound '
                   'to it keeps using it - nothing is re-pointed; it goes over SSH (the '
                   'FortiOS CLI): the target needs its SSH sign-in'),
        field('replace_name', 'The certificate on the FortiGate', 'catalog',
              catalog='local_certs', autoload=False, pattern=SEG_PATTERN,
              load_label='Find on the device', show_if={'mode': ['replace']},
              help='a local certificate (System → Certificates) - found on the device or '
                   'typed by hand; its certificate and key are replaced, its name stays'),
        field('admin', 'Admin GUI certificate', 'bool', default=False,
              help='system global admin-server-cert'),
        field('sslvpn', 'SSL VPN certificate', 'bool', default=False,
              help='vpn ssl settings servercert'),
        field('ssl_ssh_profiles', 'SSL/SSH inspection profiles', 'list', pattern=SEG_PATTERN,
              help='firewall ssl-ssh-profile names (server certificate of inbound inspection)'),
        field('vips', 'Virtual IPs', 'list', pattern=SEG_PATTERN, help='firewall vip names (ssl-certificate)'),
        field('vdom', 'VDOM', 'text', advanced=True, help='empty: the target\'s'),
        field('scope', 'Import into', 'select', default='global', advanced=True,
              options=[['global', 'global (every VDOM, the admin GUI)'], ['vdom', 'the VDOM']]),
        field('import_as', 'Import as', 'select', default='pkcs12', advanced=True,
              options=[['pkcs12', 'PKCS#12'], ['regular', 'certificate + key (PEM)']]),
        field('import_chain', 'Import the intermediates as CA certificates', 'bool',
              default=True, advanced=True),
        keep_field(2),
    ] + verify_fields()

    # What a version of the module sends (1.0.94): True - a list of {"name"}; False - a
    # name; None - by the version the FortiGate says, the other shape tried after.
    profile_cert_list = None        # firewall ssl-ssh-profile server-cert
    vip_cert_list = None            # firewall vip ssl-certificate
    fos_min = None                  # the FortiOS versions it is for (None: any)
    fos_max = None
    fos_checked_to = (8, 0)         # the newest FortiOS in the documents it was checked by

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.c('token')}

    def vdom(self, options=None):
        return ((options or {}).get('vdom') or self.c('vdom') or '').strip()

    def path(self, p, vdom=None, **q):
        if vdom:
            q['vdom'] = vdom
        if q:
            p += ('&' if '?' in p else '?') + urllib.parse.urlencode(q)
        return p

    def api(self, method, p, body=None, ok=None, what=None, vdom=None, **q):
        st, hd, d = self.req(method, self.path(p, vdom, **q), body, ok=ok, what=what)
        if isinstance(d, dict) and st < 300 and d.get('status') == 'error':
            raise PluginError('%s: FortiOS said error %s' % (what or p, d.get('error', '?')),
                              detail=trim_answer(d))
        return st, d

    # An answer of FortiOS kept in a job's steps (1.0.129): its error lines, never a PEM -
    # its cli_error had said back every line of the certificate sent
    def req(self, *a, **k):
        try:
            return HttpTarget.req(self, *a, **k)
        except PluginError as e:
            if e.detail:
                e.detail = trim_answer(e.detail)
            raise

    def http_error(self, status, parsed, raw, method, path, what=None):
        if isinstance(parsed, dict) and isinstance(parsed.get('cli_error'), list):
            parsed = dict(parsed, cli_error=[x for x in scrub_lines(parsed['cli_error'])
                                             if CLI_BAD.search(x)])
        return HttpTarget.http_error(self, status, parsed, trim_answer(raw).encode(), method,
                                     path, what)

    def test(self):
        st, d = self.api('GET', '/api/v2/monitor/system/status', what='signing in',
                         vdom=self.vdom())
        r = d.get('results') or {}
        self._fos = self.parse_version(d.get('version'))
        self.check_version()
        said = 'signed in to %s (%s), FortiOS %s' % (
            r.get('hostname', self.c('host')), r.get('model_name', d.get('serial', '?')),
            d.get('version', '?'))
        if self.ssh_ready():
            # the SSH sign-in of "replace in place" (1.0.129), tried as well: a harmless
            # get system status
            with self.fgt_ssh() as s:
                st_ = self.cli_status(s)
            said += '; over SSH as %s: %s' % (self.ssh_user(), st_['words'])
        return said

    @staticmethod
    def parse_version(v):
        m = re.match(r'^v?(\d+)\.(\d+)\.(\d+)', text(v).strip())
        return tuple(int(x) for x in m.groups()) if m else None

    def range_words(self):
        if self.fos_min is None:
            return 'any FortiOS'
        lo = fos_words(self.fos_min[:2] if self.fos_min[2] == 0 else self.fos_min)
        if self.fos_max is None:
            return 'FortiOS %s and later' % lo
        hi = self.fos_max[:2] if self.fos_max[2] >= 999 else self.fos_max
        return 'FortiOS %s - %s' % (lo, fos_words(hi))

    def check_version(self, vdom=None):
        """A version of the module on a FortiOS it is not for: refused, before anything is
        changed (its shapes would be wrong). Not known: said, and gone on."""
        if self.fos_min is None:
            return
        ver = self.fos_version(vdom if vdom is not None else self.vdom())
        if ver is None:
            self.ctx.step('the FortiOS version cannot be read - the shapes of %s are used'
                          % self.range_words(), 'warn')
            return
        if ver < self.fos_min or (self.fos_max is not None and ver > self.fos_max):
            fit = version_for(ver)[1] or FortiGateTarget.version_label
            raise PluginError(
                'this FortiGate runs FortiOS %s - the module version "%s" is for %s; choose '
                'the version "%s" of the target' % (fos_words(ver), self.version_label,
                                                    self.range_words(), fit),
                retry=False)
        if ver[:2] > tuple(self.fos_checked_to):
            self.ctx.step('FortiOS %s is newer than the documents this module version was '
                          'checked against (%s)' % (fos_words(ver),
                                                    fos_words(self.fos_checked_to)), 'warn')

    # -- discovery (1.0.29): the form filled in from the FortiGate --------------------------
    discover_keys = ['host', 'port', 'token', 'verify_tls']

    def discover_setup(self):
        """Read-only: monitor/system/status asked without a VDOM - the VDOM FortiOS answers
        in (the "vdom" of its answer) offered, its version, model and name shown. FortiOS
        lists its VDOMs only through calls acme does not make: another one is typed."""
        out = Plugin.discover_setup(self)
        st, d = self.api('GET', '/api/v2/monitor/system/status', what='signing in')
        r = d.get('results') or {}
        for label, v in (('FortiOS', d.get('version')), ('Model', r.get('model_name')),
                         ('Host name', r.get('hostname')), ('Serial number', d.get('serial'))):
            if text(v).strip():
                out['facts'].append([label, text(v).strip()])
        ver = self.parse_version(d.get('version'))
        if ver is not None and version_for(ver)[0]:
            out['facts'].append(['Module version for it', version_for(ver)[1]])
        v = text(d.get('vdom')).strip()
        if v:
            self.offer(out, 'vdom', [['', 'Empty: a FortiGate without VDOMs'], [v, v]], pick=v)
            out['notes'].append('FortiOS says only the VDOM the token answers in - another '
                                'VDOM is typed by hand')
        return out

    def fos_version(self, vdom):
        """(major, minor, patch) of FortiOS, None when it cannot be read."""
        if '_fos' not in self.__dict__:
            ver = None
            try:
                st, d = self.api('GET', '/api/v2/monitor/system/status', vdom=vdom)
                ver = self.parse_version(d.get('version'))
            except PluginError as e:
                self.ctx.debug('the FortiOS version cannot be read: %s' % e)
            self._fos = ver
        return self._fos

    def list_first(self, since, vdom, default):
        """Whether a reference field is a [{name}] list on this FortiOS (since `since`)."""
        ver = self.fos_version(vdom)
        return default if ver is None else ver >= since

    def form(self, fixed, since, vdom, default):
        """(a list?, the other shape tried after?) - a version's own, or detected."""
        if fixed is not None:
            return fixed, False
        return self.list_first(since, vdom, default), True

    def exists(self, name, vdom):
        st, d = self.api('GET', '/api/v2/cmdb/vpn.certificate/local/%s'
                         % urllib.parse.quote(name, safe=''), ok=(200, 404), vdom=vdom)
        return st == 200 and bool(d.get('results'))

    def set_ref(self, p, key, name, vdom, list_first, what, prefix=None, fallback=True):
        """Point an object at the certificate - as a string or a [{name}] list,
        whichever this FortiOS version takes (fallback=False: only the one asked)."""
        listed = [{'name': name}]
        if prefix and (fallback or list_first):
            # The list as it is, ours in it replaced (1.0.51): a profile's other server
            # certificates, a VIP's ECDSA beside the RSA one, were dropped by the PUT.
            try:
                st, d = self.api('GET', p, vdom=vdom, what=what)
                r = (d or {}).get('results') if isinstance(d, dict) else None
                r = r[0] if isinstance(r, list) and r else (r if isinstance(r, dict) else {})
                cur = r.get(key) if isinstance(r, dict) else None
                if isinstance(cur, list):
                    keep = [{'name': text(c.get('name'))} for c in cur if isinstance(c, dict)
                            and c.get('name') and not ours(c.get('name'), prefix)
                            and c.get('name') != name]
                    listed = keep + [{'name': name}]
            except PluginError:
                pass
        forms = [listed, name]
        if not list_first:
            forms.reverse()
        if not fallback:
            forms = forms[:1]
        err = None
        for value in forms:
            try:
                self.api('PUT', p, {key: value}, vdom=vdom, what=what)
                return
            except PluginError as e:
                err = e
                if getattr(e, 'retry', True) is False and 'not found' in str(e):
                    raise
        raise err

    def deploy(self, bundle, options):
        options = options or {}
        vdom = self.vdom(options)
        if self.mode_of(options) == 'replace':
            return self.deploy_replace(bundle, options, vdom)
        name = object_name(bundle, options, maxlen=35, serial_len=6)
        prefix = name_prefix(bundle, options, maxlen=35, serial_len=6)
        scope = options.get('scope') or 'global'
        if self.unchanged(bundle, options, present=lambda: self.exists(name, vdom)):
            return self.same(bundle, 'as %s' % name)
        self.check_version(vdom)
        ver = self.fos_version(vdom)
        if ver is not None:
            self.ctx.step('FortiOS %s' % fos_words(ver))
        did = []
        if self.exists(name, vdom) and not as_bool(options.get('force')):
            self.ctx.step('%s is there already' % name)
        else:
            if (options.get('import_as') or 'pkcs12') == 'pkcs12':
                pw = random_password()
                body = {'type': 'pkcs12', 'certname': name, 'password': pw, 'scope': scope,
                        'file_content': b64(bundle.as_format('p12-legacy', password=pw,
                                                             alias=name))}
            else:
                body = {'type': 'regular', 'certname': name, 'scope': scope, 'password': '',
                        'file_content': b64(bundle.as_format('cert-pem')),
                        'key_file_content': b64(bundle.as_format('key-pem'))}
            self.api('POST', '/api/v2/monitor/vpn-certificate/local/import', body,
                     vdom=vdom if scope == 'vdom' else None, what='importing %s' % name)
            self.ctx.step('imported %s' % name, 'ok')
            did.append('imported %s' % name)
            self.import_cas(bundle, options)
        self.point_at(name, prefix, vdom, options, did)
        self.cleanup(prefix, name, vdom, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    # -- replace in place (1.0.128; over SSH, the FortiOS CLI, since 1.0.129) ----------------
    # The name and every reference to it stay; nothing is imported under a new name. The REST
    # API is used to list, read back and check only - its PUT of "certificate" breaks on the
    # PEM (FortiOS 7.4.13: "value parse error", -651), so the lines go to the CLI over SSH.
    def state_key(self, options):
        o = dict(options or {})
        if self.mode_of(o) != 'replace':
            # a deployment saved before (or with the mode as it was): its key as before, so
            # opening and saving its form does not deploy it again
            o.pop('mode', None)
            o.pop('replace_name', None)
        return HttpTarget.state_key(self, o)

    @staticmethod
    def mode_of(options):
        return 'replace' if text((options or {}).get('mode')).strip().lower() == 'replace' \
            else 'new'

    @staticmethod
    def factory(name, row=None):
        """A certificate FortiOS came with (Fortinet_Factory, Fortinet_SSL...): not replaced."""
        src = text((row or {}).get('source')).strip().lower()
        return src == 'factory' or text(name).startswith('Fortinet_')

    def local_row(self, name, vdom):
        """The local certificate `name` as cmdb has it ({} when there is none)."""
        st, d = self.api('GET', '/api/v2/cmdb/vpn.certificate/local/%s'
                         % urllib.parse.quote(name, safe=''), ok=(200, 404), vdom=vdom,
                         what='reading the certificate %s' % name, with_meta=1)
        if st != 200 or not isinstance(d, dict):
            return {}
        r = d.get('results')
        r = r[0] if isinstance(r, list) and r else r
        return r if isinstance(r, dict) and text(r.get('name') or name) == name else {}

    @staticmethod
    def pem_facts(pem):
        """What a certificate PEM says: {cn, names, not_after, issuer, key, fp}, {} unread."""
        pem = text(pem).strip()
        if '-----BEGIN CERTIFICATE-----' not in pem:
            return {}
        try:
            from acmelib.certs import pki
            i = pki.cert_info(pem)
        except Exception:                               # noqa: BLE001
            return {}
        iss = i.get('issuer') or {}
        return {'cn': text(i.get('cn')), 'names': [text(n).lower() for n in i.get('names') or []],
                'not_after': i.get('not_after'), 'key': text(i.get('key_type')),
                'issuer': text(iss.get('CN') or iss.get('O') or i.get('issuer_dn') or ''),
                'fp': norm_fp(i.get('sha256'))}

    @staticmethod
    def day(epoch):
        try:
            import time as _t
            return _t.strftime('%Y-%m-%d', _t.gmtime(int(epoch)))
        except (TypeError, ValueError, OverflowError):
            return '?'

    def holds(self, name, vdom, bundle):
        """Whether the certificate `name` on the device is this very one (unknown: there)."""
        row = self.local_row(name, vdom)
        if not row:
            return False
        got = self.pem_facts(row.get('certificate')).get('fp')
        return not got or got == norm_fp(fp_of(bundle))

    def deploy_replace(self, bundle, options, vdom):
        name = text(options.get('replace_name')).strip()
        if not name:
            raise PluginError('replace in place: no certificate on the FortiGate is chosen - '
                              'find it on the device or type its name', retry=False)
        if self.factory(name):
            raise PluginError('%s is a Fortinet factory certificate - it is not replaced; '
                              'choose a certificate of your own' % name, retry=False)
        prefix = name_prefix(bundle, options, maxlen=35, serial_len=6)
        if self.unchanged(bundle, options, present=lambda: self.holds(name, vdom, bundle)):
            return self.same(bundle, 'in %s' % name)
        self.check_version(vdom)
        ver = self.fos_version(vdom)
        if ver is not None:
            self.ctx.step('FortiOS %s' % fos_words(ver))
        row = self.local_row(name, vdom)
        if not row:
            raise PluginError('there is no local certificate %s on the FortiGate%s - nothing '
                              'was changed (Find on the device lists them; the name is '
                              'case-sensitive)' % (name, (' (VDOM %s)' % vdom) if vdom else ''),
                              retry=False)
        if self.factory(name, row):
            raise PluginError('%s is a Fortinet factory certificate - it is not replaced; '
                              'choose a certificate of your own' % name, retry=False)
        if not self.ssh_ready():
            raise PluginError(
                'replace in place goes over SSH and the target has no SSH sign-in: FortiOS '
                'takes a new certificate and key for an existing local certificate only in '
                'its CLI (config vpn certificate local / edit / set private-key / set '
                'certificate) - its REST API turns the PEM into broken CLI lines (error -651). '
                'Fill in the target\'s SSH user and its key or password (an administrator who '
                'may change VPN certificates) - nothing was changed', retry=False)
        old = self.pem_facts(row.get('certificate'))
        uses = row.get('q_ref')
        now = []
        if old:
            now.append('now %s, valid to %s' % (old.get('cn') or '?',
                                                self.day(old.get('not_after'))))
        if text(uses).strip().isdigit():
            now.append('used %s times' % uses if text(uses).strip() != '1' else 'used once')
        self.ctx.step('replacing the certificate %s in place: the same name, everything that '
                      'uses it keeps using it%s' % (name, (' (%s)' % '; '.join(now))
                                                    if now else ''))
        new_fp = norm_fp(fp_of(bundle))
        did = []
        if old.get('fp') and old['fp'] == new_fp:
            # the very certificate there already: nothing to send (FortiOS would call it a
            # duplicate of itself)
            self.ctx.step('%s holds this certificate already - it is in place' % name, 'ok')
        else:
            drop = self.duplicates(name, vdom, new_fp)
            with self.fgt_ssh() as s:
                status = self.cli_status(s)
                self.ctx.step('signed in over SSH as %s: %s - the certificate is replaced in '
                              'the FortiOS CLI (its REST API cannot)'
                              % (self.ssh_user(), status['words']), 'ok')
                scope, where = self.scope_of(row, self.vdoms_on(status), vdom)
                new_fam = family_of(bundle)
                old_fam = 'ec' if old.get('key', '').startswith('ec') else (
                    'rsa' if old.get('key', '').startswith('rsa') else old.get('key', ''))
                if old_fam and new_fam and old_fam != new_fam:
                    self.ctx.step('the key type changes from %s to %s - what uses %s keeps it '
                                  '(a VIP that holds an RSA and an ECDSA certificate side by '
                                  'side may need a look)' % (old_fam.upper(), new_fam.upper(),
                                                             name))
                for n in drop:
                    self.drop_copy(n, vdom)
                self.cli_replace(s, bundle, name, scope, where, vdom, row)
                self.check_in_place(s, name, scope, where, vdom, new_fp)
            self.ctx.step('%s replaced in place - its name and every use of it kept' % name,
                          'ok')
            did.append('%s replaced in place' % name)
            self.import_cas(bundle, options)
        self.point_at(name, prefix, vdom, options, did)
        self.cleanup(prefix, name, vdom, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did) or 'already in place in %s' % name

    # -- duplicates: FortiOS refuses a local certificate identical to another (1.0.129) -----
    def duplicates(self, name, vdom, new_fp):
        """The other local certificates that are this very one, looked at before anything
        changes: an unused copy acme made (acme-...) is to be deleted first (its names
        returned); a used one, or one acme did not make, stops the deployment here."""
        try:
            st, d = self.api('GET', '/api/v2/cmdb/vpn.certificate/local', vdom=vdom,
                             with_meta=1, what='listing the local certificates')
        except PluginError as e:
            self.ctx.step('the local certificates cannot be listed to look for a copy of this '
                          'one (%s) - FortiOS says so itself if there is one' % e, 'warn')
            return []
        same = []
        for r in (d.get('results') if isinstance(d, dict) else None) or []:
            if not isinstance(r, dict):
                continue
            n = text(r.get('name'))
            if not n or n == name:
                continue
            if self.pem_facts(r.get('certificate')).get('fp') == new_fp:
                same.append(r)
        if not same:
            self.ctx.step('no other local certificate on the FortiGate is this one (FortiOS '
                          'refuses a duplicate)')
            return []
        drop = []
        for r in same:
            n = text(r.get('name'))
            refs = text(r.get('q_ref')).strip()
            if self.factory(n, r) or not n.startswith('acme-'):
                raise PluginError(
                    'the FortiGate has this very certificate already as %s, which acme did not '
                    'make - FortiOS refuses a local certificate identical to another one ("This '
                    'local certificate is duplicated"), so %s cannot take it. Nothing was '
                    'changed: delete %s on the FortiGate (System → Certificates) if nothing '
                    'uses it, or point what uses it at %s first' % (n, name, n, name),
                    retry=False)
            if refs not in ('', '0'):
                raise PluginError(
                    'the FortiGate has this very certificate already as %s, an earlier import '
                    'of acme that is used (%s×) - FortiOS refuses a local certificate identical '
                    'to another one, so %s cannot take it. Nothing was changed: point what uses '
                    '%s at %s (or tick it in this deployment: admin GUI, SSL VPN, profiles, '
                    'VIPs), delete %s, then deploy again' % (n, refs, name, n, name, n),
                    retry=False)
            self.ctx.step('%s is this very certificate already - an unused copy acme imported '
                          'earlier; it is deleted first (FortiOS refuses two identical local '
                          'certificates)' % n)
            drop.append(n)
        return drop

    def drop_copy(self, n, vdom):
        try:
            self.api('DELETE', '/api/v2/cmdb/vpn.certificate/local/%s'
                     % urllib.parse.quote(n, safe=''), vdom=vdom, what='deleting %s' % n)
        except PluginError as e:
            raise PluginError('%s, an unused copy of this very certificate, cannot be deleted '
                              '(%s) - nothing else was changed; delete it on the FortiGate, then '
                              'deploy again' % (n, e), detail=e.detail, retry=False)
        self.ctx.step('deleted %s, the unused copy of this certificate' % n, 'ok')

    # -- the SSH sign-in and the FortiOS CLI (1.0.129) ---------------------------------------
    def ssh_user(self):
        return text(self.c('ssh_user')).strip()

    def ssh_ready(self):
        """Whether the target has an SSH sign-in: a user, and its key or password."""
        if not self.ssh_user():
            return False
        if text(self.c('ssh_auth') or 'key') == 'password':
            return bool(self.c('ssh_password'))
        return bool(self.c('ssh_key'))

    def ssh_host(self):
        h = text(self.c('host')).strip()
        if '://' in h:
            h = urllib.parse.urlsplit(h).hostname or h
        elif h.count(':') == 1:
            h = h.split(':', 1)[0]
        return h.strip('[]')

    def fgt_ssh(self):
        conn = ssh_conn(self, prefix='ssh_')
        conn['host'] = self.ssh_host()
        return self.ctx.ssh(conn)

    def cli(self, s, script):
        """Lines given to the FortiOS CLI over SSH (a shell session) -> what it answered."""
        rc, out, err = s.run('', input=script, timeout=180, check=False)
        return text(out) + '\n' + text(err)

    def cli_status(self, s):
        """get system status - harmless: {'version', 'vdoms' (None: not said), 'words'}."""
        out = self.cli(s, 'get system status\n')
        m = re.search(r'^\s*Version:\s*(.*?)\s*$', out, re.M)
        if not m:
            bad = cli_errors(out)
            words = ('signed in over SSH as %s, but "get system status" was not answered as '
                     'FortiOS answers it - is it the FortiGate\'s CLI?' % self.ssh_user())
            if bad:
                words = ('signed in over SSH as %s, but "get system status" was not answered '
                         'as FortiOS answers it (%s) - is it the FortiGate\'s CLI?'
                         % (self.ssh_user(), '; '.join(bad[:3])))
            raise PluginError(words, detail='\n'.join(scrub_lines(out.splitlines()[-20:])),
                              retry=False)
        v = re.search(r'v(\d+\.\d+\.\d+)', m.group(1))
        vd = re.search(r'^\s*Virtual domain configuration:\s*(\S+)', out, re.M | re.I)
        vdoms = None if not vd else vd.group(1).lower() not in ('disable', 'disabled',
                                                                 'no-vdom')
        host = re.search(r'^\s*Hostname:\s*(\S+)', out, re.M)
        words = 'FortiOS %s' % (v.group(1) if v else m.group(1)[:60])
        if host:
            words += ' on %s' % host.group(1)
        if vdoms is not None:
            words += ', VDOMs %s' % ('on (%s)' % vd.group(1) if vdoms else 'off')
        return {'version': v.group(1) if v else '', 'vdoms': vdoms, 'words': words}

    def vdoms_on(self, status):
        if status.get('vdoms') is not None:
            return status['vdoms']
        try:
            st, d = self.api('GET', '/api/v2/cmdb/system/global', what='reading the VDOM mode')
            r = (d or {}).get('results') if isinstance(d, dict) else None
            r = r[0] if isinstance(r, list) and r else r
            if isinstance(r, dict):
                if text(r.get('vdom-mode')).strip():
                    return text(r.get('vdom-mode')).strip() != 'no-vdom'
                if text(r.get('vdom-admin')).strip():
                    return text(r.get('vdom-admin')).strip() == 'enable'
        except PluginError as e:
            self.ctx.debug('the VDOM mode cannot be read: %s' % e)
        self.ctx.step('whether VDOMs are on cannot be read - the CLI lines go without config '
                      'global / config vdom', 'warn')
        return False

    @staticmethod
    def scope_of(row, vdoms, vdom):
        """('', '') no VDOMs; ('global', '') a certificate of the global range on a box with
        VDOMs; ('vdom', <vdom>) one of a VDOM's."""
        if not vdoms:
            return '', ''
        if text((row or {}).get('range')).strip().lower() == 'vdom':
            return 'vdom', vdom or 'root'
        return 'global', ''

    @staticmethod
    def in_scope(scope, where, lines_):
        if scope == 'global':
            return ['config global'] + lines_ + ['end']
        if scope == 'vdom':
            return ['config vdom', 'edit %s' % cli_quote(where)] + lines_ + ['end']
        return lines_

    def cert_script(self, scope, where, name, pw, key, cert, commit):
        """The CLI lines that put `key` and `cert` into the local certificate `name`: ended
        with abort (taken, nothing saved) or with next / end (saved)."""
        body = ['config vpn certificate local', 'edit %s' % cli_quote(name)]
        if pw:
            body.append('set password %s' % cli_quote(pw))
        body += ['set private-key %s' % cli_quote(text(key).strip()),
                 'set certificate %s' % cli_quote(text(cert).strip())]
        body += ['next', 'end'] if commit else ['abort']
        return '\n'.join(self.in_scope(scope, where, body)) + '\n'

    def cli_replace(self, s, bundle, name, scope, where, vdom, row):
        """The certificate and key of `name` replaced in the CLI: the lines first ended with
        abort - FortiOS checks each, nothing is saved -, the key encrypted with a one-time
        password (as FortiOS keeps it), as plain PEM when that is refused; then, taken, the
        same lines saved. Refused: said, the old certificate read back to say it is as it was."""
        cert = text(bundle.as_format('cert-pem')).strip()
        pw = random_password()
        forms = []
        try:
            forms.append((pw, text(bundle.as_format('key-pem-enc', password=pw)).strip()))
        except Exception as e:                          # noqa: BLE001
            self.ctx.debug('the key cannot be encrypted here: %s' % e)
        forms.append(('', text(bundle.as_format('key-pem')).strip()))
        hide = [pw]
        bad, use = [], None
        where_words = {'global': ', in config global', 'vdom': ', in config vdom, edit %s'
                       % where}.get(scope, '')
        for i, (p, key) in enumerate(forms):
            self.ctx.step('the new key and certificate given to the CLI for %s (%s%s), ended '
                          'with abort - FortiOS checks the lines, nothing is saved yet'
                          % (name, 'the key encrypted with a one-time password' if p else
                             'the key as plain PEM', where_words))
            bad = cli_errors(self.cli(s, self.cert_script(scope, where, name, p, key, cert,
                                                          False)), hide)
            if not bad:
                use = (p, key)
                break
            if i + 1 < len(forms) and p and not re.search(
                    r'duplicated|new entry|not found|permission|access denied|unknown action',
                    ' '.join(bad), re.I):
                self.ctx.step('FortiOS did not take the encrypted key (%s) - trying the key as '
                              'plain PEM' % '; '.join(bad[:2]), 'warn')
                continue
            break
        if use is None:
            self.refused(name, vdom, row, bad, 'nothing was saved: acme ended its lines with '
                                               'abort')
        self.ctx.step('FortiOS took the lines - given again and saved (next, end)')
        bad = cli_errors(self.cli(s, self.cert_script(scope, where, name, use[0], use[1], cert,
                                                      True)), hide)
        if bad:
            self.refused(name, vdom, row, bad, '')

    def refused(self, name, vdom, row, bad, how):
        words = 'FortiOS refused to replace %s in place: %s' % (name, '; '.join(bad[:4]) or '?')
        if any(re.search(r'new entry', b, re.I) for b in bad):
            words += ' (the name is not in the scope it was asked in)'
        try:
            now = self.local_row(name, vdom)
            same = text(now.get('certificate')).strip() == text(row.get('certificate')).strip()
        except PluginError:
            now, same = {}, None
        if now and same:
            words += ' - %s is untouched (the old certificate, nothing deleted)' % name
        elif now:
            words += ' - check %s on the FortiGate' % name
        if how:
            words += '; %s' % how
        raise PluginError(words, detail='\n'.join(bad), retry=False)

    def check_in_place(self, s, name, scope, where, vdom, new_fp):
        """The certificate `name` read back - through REST, else the CLI's show: its
        fingerprint must be the new one."""
        got = ''
        try:
            got = self.pem_facts(self.local_row(name, vdom).get('certificate')).get('fp') or ''
        except PluginError as e:
            self.ctx.debug('%s cannot be read back over REST: %s' % (name, e))
        if not got:
            out = self.cli(s, '\n'.join(self.in_scope(scope, where, [
                'show vpn certificate local %s' % cli_quote(name)])) + '\n')
            m = re.search(r'set certificate "(-----BEGIN CERTIFICATE-----.*?-----END '
                          r'CERTIFICATE-----)', out.replace('\r', ''), re.S)
            got = self.pem_facts(m.group(1)).get('fp') if m else ''
        if not got:
            raise PluginError('FortiOS took the lines, yet the certificate %s cannot be read '
                              'back to check it - look at it on the FortiGate' % name,
                              retry=False)
        if got != new_fp:
            raise PluginError('FortiOS took the lines, yet %s still holds another certificate '
                              '- it may not replace a certificate of this kind in place (a '
                              'factory or CA-made one?)' % name, retry=False)
        self.ctx.step('checked: %s holds the new certificate now (SHA-256 %s…)'
                      % (name, new_fp[:16]), 'ok')

    def import_cas(self, bundle, options):
        """The intermediates as CA certificates. One there already is said once, quietly:
        FortiOS answers the import of a CA certificate it holds with 500 and error -328
        (the CA list read then to make sure, once; unreadable: taken as there)."""
        if not as_bool(self.opt(options, 'import_chain', True), True):
            return
        there, have = 0, False
        for pem in chain_list(bundle):
            try:
                self.api('POST', '/api/v2/monitor/vpn-certificate/ca/import',
                         {'import_method': 'file', 'scope': 'global',
                          'file_content': b64(pem)}, what='importing a CA certificate')
            except PluginError as e:
                if self.dup(e):
                    if have is False:
                        have = self.cas_there()
                    der = self.der_of(pem)
                    if have is None or not der or der in have:
                        there += 1
                        continue
                self.ctx.step('the CA certificate is not imported (there already?): %s' % e)
        if there:
            self.ctx.step('the intermediate CA certificate%s on the FortiGate already' % (
                ' is' if there == 1 else 's are'))

    @staticmethod
    def der_of(pem):
        try:
            return pem_to_der(pem)
        except Exception:                               # noqa: BLE001
            return b''

    @staticmethod
    def dup(e):
        """FortiOS error -328 on a CA import: that certificate is there already."""
        for s in (getattr(e, 'detail', None), str(e)):
            if re.search(r'(?<![\d])-328(?!\d)', text(s)):
                return True
        return False

    def cas_there(self):
        """The CA certificates the FortiGate holds (a set of DER), None when unread."""
        try:
            st, d = self.api('GET', '/api/v2/cmdb/vpn.certificate/ca', format='name|ca')
        except PluginError as e:
            self.ctx.debug('the CA certificates cannot be listed: %s' % e)
            return None
        out = set()
        for r in (d.get('results') if isinstance(d, dict) else None) or []:
            der = self.der_of(text((r or {}).get('ca')))
            if der:
                out.add(der)
        return out

    def point_at(self, name, prefix, vdom, options, did):
        """The admin GUI, SSL VPN, profiles and VIPs listed: pointed at `name`."""
        if as_bool(options.get('admin')):
            self.api('PUT', '/api/v2/cmdb/system/global', {'admin-server-cert': name},
                     what='setting the admin certificate')
            self.ctx.step('admin GUI uses %s' % name, 'ok')
            did.append('admin GUI')
        if as_bool(options.get('sslvpn')):
            self.api('PUT', '/api/v2/cmdb/vpn.ssl/settings', {'servercert': name}, vdom=vdom,
                     what='setting the SSL VPN certificate')
            self.ctx.step('SSL VPN uses %s' % name, 'ok')
            did.append('SSL VPN')
        for p in lines(options.get('ssl_ssh_profiles')):
            first, fallback = self.form(self.profile_cert_list, (7, 0, 0), vdom, True)
            self.set_ref('/api/v2/cmdb/firewall/ssl-ssh-profile/%s' % urllib.parse.quote(p, safe=''),
                         'server-cert', name, vdom, first, 'setting profile %s' % p, prefix,
                         fallback)
            self.ctx.step('profile %s uses %s' % (p, name), 'ok')
            did.append('profile %s' % p)
        for v in lines(options.get('vips')):
            first, fallback = self.form(self.vip_cert_list, (7, 4, 2), vdom, False)
            self.set_ref('/api/v2/cmdb/firewall/vip/%s' % urllib.parse.quote(v, safe=''),
                         'ssl-certificate', name, vdom, first, 'setting VIP %s' % v, prefix,
                         fallback)
            self.ctx.step('VIP %s uses %s' % (v, name), 'ok')
            did.append('VIP %s' % v)

    # -- Find on the device: the local certificates, for "replace in place" ------------------
    hint_names = None               # the deployed certificate's names (api_catalog, the page)

    def catalog(self, key):
        if key != 'local_certs':
            raise PluginError('there is no list called %s here' % key, retry=False)
        vdom = self.vdom()
        try:
            st, d = self.api('GET', '/api/v2/cmdb/vpn.certificate/local', vdom=vdom,
                             with_meta=1, what='listing the local certificates')
        except PluginError as e:
            m = re.search(r'\((\d{3})\)|said (\d{3})', str(e))
            code = (m.group(1) or m.group(2)) if m else ''
            if code in ('401', '403'):
                why = ('the token may not read the certificates (%s) - its admin profile '
                       'needs VPN (vpngrp) read, and the acme server among its trusted hosts'
                       % code)
            elif code == '404':
                why = 'the VDOM %s is not there (404)' % (vdom or '?')
            else:
                why = str(e)
            raise PluginError('the certificates cannot be listed: %s - type the name of the '
                              'certificate instead' % why, detail=e.detail, retry=False)
        rows = (d.get('results') if isinstance(d, dict) else None) or []
        want = [text(n).lower().rstrip('.') for n in (self.hint_names or []) if text(n).strip()]
        opts, factory, best = [], 0, None
        for r in rows:
            if not isinstance(r, dict) or not text(r.get('name')).strip():
                continue
            name = text(r.get('name'))
            if self.factory(name, r):
                factory += 1
                continue
            f = self.pem_facts(r.get('certificate'))
            bits = []
            if f.get('cn'):
                bits.append('CN %s' % f['cn'])
            if f.get('not_after'):
                bits.append('→ %s' % self.day(f['not_after']))
            if f.get('issuer'):
                bits.append(f['issuer'])
            if text(r.get('range')).strip():
                bits.append(text(r.get('range')).strip())
            if r.get('q_ref') not in (None, ''):
                bits.append('%s×' % r.get('q_ref'))
            score = 0
            if want and f:
                if f.get('cn', '').lower() in want:
                    score = 2
                elif set(f.get('names') or []) & set(want):
                    score = 1
            if score and (best is None or (score, f.get('not_after') or 0) > best[0]):
                best = ((score, f.get('not_after') or 0), name)
            opts.append([name, ' · '.join([name] + bits), score])
        opts.sort(key=lambda o: (-o[2], o[0].lower()))
        pick = best[1] if best else ''
        out = [[o[0], ('★ ' if o[0] == pick else '') + o[1]] for o in opts]
        said = '%d certificate%s found on the FortiGate' % (len(out), '' if len(out) == 1
                                                             else 's')
        if factory:
            said += '; %d Fortinet factory one%s left out (not replaced)' % (
                factory, '' if factory == 1 else 's')
        if pick:
            said += '; ★ %s has the names of this certificate' % pick
        return {'options': out, 'sets': {}, 'said': said, 'pick': pick}

    def cleanup(self, prefix, current, vdom, keep):
        if keep < 0:
            return
        try:
            st, d = self.api('GET', '/api/v2/cmdb/vpn.certificate/local', vdom=vdom,
                             format='name')
        except PluginError as e:
            self.ctx.step('the old certificates cannot be listed: %s' % e, 'warn')
            return
        names = [r.get('name', '') for r in d.get('results') or []]
        for old in prune(names, prefix, keep, current):
            try:
                self.api('DELETE', '/api/v2/cmdb/vpn.certificate/local/%s'
                         % urllib.parse.quote(old, safe=''), vdom=vdom,
                         what='deleting %s' % old)
                self.ctx.step('deleted the old %s' % old)
            except PluginError as e:
                self.ctx.step('the old %s stays (still used?): %s' % (old, e), 'warn')


# -- the versions (1.0.94) ------------------------------------------------------------------
_SAME = (' Imports the certificate (monitor/vpn-certificate/local/import), uses it for the '
         'admin GUI (system global admin-server-cert), SSL VPN (vpn ssl settings '
         'servercert), inspection profiles and virtual IPs, deletes older ones acme put '
         'there - or replaces a certificate the FortiGate has in place (its name and uses '
         'kept). Refused on a FortiGate that says another FortiOS.')


class FortiGate60Target(FortiGateTarget):
    """FortiOS 6.0 - 6.4: an inspection profile's server-cert and a VIP's ssl-certificate
    are names (the server-cert list's "name" member is in the data from 7.0.0 only)."""
    module_version, version_label, fos_min, fos_max = RANGES[0]
    description = ('FortiOS 6.0 - 6.4: an inspection profile\'s server-cert and a virtual '
                   'IP\'s ssl-certificate are set as a name.' + _SAME)
    profile_cert_list = False
    vip_cert_list = False


class FortiGate70Target(FortiGateTarget):
    """FortiOS 7.0 - 7.4.1: server-cert a list of {name}, ssl-certificate still a name."""
    module_version, version_label, fos_min, fos_max = RANGES[1]
    description = ('FortiOS 7.0 - 7.4.1: an inspection profile\'s server-cert is a list of '
                   'certificates (others in it kept), a virtual IP\'s ssl-certificate a '
                   'name.' + _SAME)
    profile_cert_list = True
    vip_cert_list = False


class FortiGate742Target(FortiGateTarget):
    """FortiOS 7.4.2 - 8.0: both lists of {name}. SSL VPN web mode is "Agentless VPN"
    from 7.6.3 (tunnel mode gone) - vpn ssl settings servercert is the same."""
    module_version, version_label, fos_min, fos_max = RANGES[2]
    description = ('FortiOS 7.4.2 - 8.0 (7.4.x, 7.6.x, 8.0): an inspection profile\'s '
                   'server-cert and a virtual IP\'s ssl-certificate are lists of '
                   'certificates (others in them kept); "SSL VPN" is the Agentless VPN of '
                   '7.6.3 and later.' + _SAME)
    profile_cert_list = True
    vip_cert_list = True
