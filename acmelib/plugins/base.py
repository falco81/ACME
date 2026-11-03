# -*- coding: utf-8 -*-
"""
The contract every module of acme keeps - an issuer, a challenge (a way of
proving a name to a CA) or a target (a place a certificate is put).

A module is one Python file in one of

    acmelib/plugins/issuers/      where certificates come from
    acmelib/plugins/challenges/   how a name is proved (DNS-01, HTTP-01)
    acmelib/plugins/targets/      where certificates go
    /etc/acme/plugins/<the same three>/    your own, kept across upgrades

holding one or more subclasses of Issuer, Challenge or Target with a `kind`
of their own. Nothing else has to be told: the registry finds them, the pages
draw their forms from `fields`, the command line and the console list them.

A module never touches the database, the sealing key or the network settings
itself: everything it may use comes through the Context it is handed.
"""
from __future__ import annotations

import base64
import importlib.util
import os
import re
import sys
import threading
import time
import traceback


# ---------------------------------------------------------------------------
# The fields of a form
# ---------------------------------------------------------------------------
# What a module needs set is described, not drawn: the pages, the command line
# and the console make the form out of this.
#
#   {'key': 'host', 'label': 'Address', 'type': 'text', 'required': True,
#    'default': '', 'placeholder': 'bigip.example.local', 'help': 'words...',
#    'options': [['value', 'Words'], ...],          # for 'select'
#    'show_if': {'auth': ['password']},             # shown only when another field holds one of these
#    'advanced': False}                             # folded away under "More"
#
# type: text | secret | number | bool | select | textarea | pem | list | hostport
#   secret    sealed in the database, never sent back in clear: a full administrator is
#             shown eight dots and its last two characters, anybody else eight dots; saved
#             as "" or as those dots, the one kept stays. multiline=True: a key, JSON, lines
#   pem       a certificate or a key pasted or read from a file; secret=True: a private
#             key - kept and shown as a secret (the last two of its body, not of -----END)
#   list      several values, one a line (names, addresses, commands)
#   sshkey    the SSH key acme signs in with, drawn as isemon's key card: Make a key
#             (ed25519; key_type='rsa4096' for something old), Use my own (pasted or a
#             file, its passphrase asked and checked), Download it, Forget it, Try
#             reaching it, How to set it up. Give it secret=True: the value kept is the
#             private key, sealed; beside it, not secret, <key>.sshkey holds the public
#             half and the fingerprint (acmelib/certs/api_sshkeys.py). Options:
#             pass_key='key_pass' (where a passphrase of a key brought is kept),
#             auth_key='auth' (the select saying key or password), ssh_prefix='ssh_',
#             try_command='id -un; uname -n', howto='linux' | 'windows' | 'mikrotik' |
#             'pfsense' | 'opnsense' | 'generic' (the module's sshkey_howto otherwise)
#   catalog   a choice from a list the module fetches live (a CA's products): the page's
#             "Load the list" asks the module's catalog(<catalog>) with the form as it
#             is (saved or not, a kept secret used) and gets {'options': [[value, words]],
#             'sets': {value: {other_key: value}} (picked: those fields filled in), 'said'};
#             read-only (acmelib/certs/api_catalog.py, web/assets/catalog.js). Options:
#             catalog='products', depends=['token'] (what the list needs set first).
#             In a target's deploy_fields too: the target's catalog() is asked with its
#             settings and the deployment's options over them (the virtual servers to
#             bind); autoload=False there keeps the form from asking by itself.
#             Elsewhere (command line, console) it is a text field holding the value.
FIELD_TYPES = ('text', 'secret', 'number', 'bool', 'select', 'textarea', 'pem', 'list',
               'hostport', 'sshkey', 'catalog')


def field(key, label, type='text', **more):
    """One field of a form - see above."""
    if type not in FIELD_TYPES:
        raise ValueError('a field of an unknown type: %s' % type)
    out = {'key': key, 'label': label, 'type': type}
    out.update(more)
    return out


class PluginError(Exception):
    """Said to the person as it is: what failed, in words they can act on.
    `detail` is the longer story (a server's answer), kept in the job's steps."""
    def __init__(self, words, detail=None, retry=True):
        Exception.__init__(self, words)
        self.detail = detail
        self.retry = retry          # False: trying again unchanged will not help


# ---------------------------------------------------------------------------
# What a module is handed
# ---------------------------------------------------------------------------
class Context(object):
    """Everything a module may use, given by acmelib.certs (the real one is
    acmelib.certs.runtime.RunContext). A module calls only these.

        ctx.step(words, level='info')       a line in the job's log ('info' | 'ok' | 'warn' | 'bad')
        ctx.debug(words)                    a line only when debugging
        ctx.http(method, url, body=None, headers=None, timeout=30, verify=True,
                 ca_pem=None, client_cert=None, proxy=True) -> (status, headers, bytes)
                                            HTTPS through the proxy of Settings → Proxy when asked
        ctx.ssh(conn) -> SshSession         an SSH connection (see SshSession below)
        ctx.openssl(args, data=None, timeout=60) -> bytes     the openssl program
        ctx.kv_get(key) / ctx.kv_set(key, value, ttl_s=None)  a little state of the module's own,
                                            in the database (both nodes of a cluster see it)
        ctx.kv_keys(prefix='') -> {key: value}  every one of them whose key starts with prefix
        ctx.dns_put(name, type, value, ttl=60) / ctx.dns_drop(name, type, value)
                                            a record in acme's own DNS server
        ctx.http_token_put(token, key_authorization) / ctx.http_token_drop(token)
                                            an answer on this server's /.well-known/acme-challenge/
        ctx.http_file_put(host, path, content, ttl_s) / ctx.http_file_drop(host, path)
                                            a file this server answers for http://host/path, path
                                            under /.well-known/pki-validation/ (a commercial CA's
                                            DCV file, kept for days)
        ctx.cancelled() -> bool             the job was stopped: give up at the next step
        ctx.node                            this node's name
        ctx.settings                        the settings (read only)

    What a challenge's guide() and dry_run() may ask about acme itself (each
    has an answer that says "cannot tell" here, so an older Context works):
        ctx.dns_server_info() -> {'on', 'zones', 'ns', 'glue': {ns: [addresses]},
                                  'answering': [addresses], 'port'}
                                            acme's own DNS server as its settings say
        ctx.own_addresses() -> {'vip': address or None, 'nodes': [addresses]}
        ctx.port_open(proto, port) -> True | False | None
                                            does acme's firewall let it in from anywhere
        ctx.http_probe() -> (token, key_authorization) or None
                                            a probe acme answers on its own port 80

    What a validation that stands on another module may ask (dns_persist.py:
    the ACME account a record names, the validation used while a CA does not
    offer dns-persist-01) - [] / None here:
        ctx.acme_sources(names=None) -> [(name, Issuer instance)]
                                            the ACME sources (each with a Context of its
                                            own): their account, without the network
                                            unless asked (AcmeIssuer.persist_info)
        ctx.validation(name) -> Challenge instance or None
                                            another validation, as the renewer makes it
        ctx.names_using() -> [names]        the names of the certificates this validation
                                            proves (its own scope 'challenge:NAME')

    For a target that is acme itself (targets/appliance.py) - the certificate
    of its own pages, as Settings → Certificates and TLS keeps it:
        ctx.pages_where() -> {'node', 'nodes': [...], 'cluster', 'vip': {'on', 'fqdn'}}
        ctx.pages_get(where) -> {'fingerprint', 'cn', 'not_after', 'how'} or None
        ctx.pages_put(where, cert_pem, key_pem, chain_pems, how) -> {'cn', 'not_after', ...}
                                            where: a node's name or 'vip'; every node puts
                                            its own in place within seconds

    For a target that is another application of ours (targets/acme_push.py):
        ctx.push_identity() -> {'seed', 'public', 'id', 'text'}
                                            acme's own Ed25519 key it signs acme push with
        ctx.push_pin(url, pin=None) -> {'app_id', 'enc_key', 'how', ...} or None
                                            the application at url, as paired (pin=: kept)
    """
    node = ''
    settings = {}

    def step(self, words, level='info'):
        raise NotImplementedError

    def debug(self, words):
        pass

    def cancelled(self):
        return False

    # -- what guide() and dry_run() may ask (None / empty: cannot tell here) ------------
    def dns_server_info(self):
        from acmelib.certs import dnsserver
        return dnsserver.server_info(getattr(self, 'store', None), self.settings or {})

    def own_addresses(self):
        return {'vip': None, 'nodes': []}

    def port_open(self, proto, port):
        return None

    def http_probe(self):
        return None

    def acme_sources(self, names=None):
        return []

    def validation(self, name):
        return None

    def names_using(self):
        return []


class SshSession(object):
    """What ctx.ssh(conn) gives, `conn` being
    {'host', 'port', 'user', 'password', 'key', 'key_pass', 'hostkey', 'timeout'}
    (the host key as a known_hosts line; with none, the first one seen is
    taken and kept when the target says trust_first).

        s.run(command, input=None, timeout=120, check=True) -> (rc, stdout, stderr)
        s.put(data: bytes, remote_path, mode=0o600, owner=None)   written whole, then moved into place
        s.get(remote_path) -> bytes
        s.close()
    Used as `with ctx.ssh(conn) as s:`."""
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        pass


# ---------------------------------------------------------------------------
# What travels between them
# ---------------------------------------------------------------------------
class CertRequest(object):
    """What an issuer is asked for.

        names        ['www.example.com', 'example.com', '*.example.com', '192.0.2.10']
                     the first is the common name
        key_type     'ec-256' | 'ec-384' | 'rsa-2048' | 'rsa-3072' | 'rsa-4096'
        key_pem      the private key (PEM, PKCS#8), made by acme before it asks
        csr_pem      the request, signed with that key (subject and names in it)
        csr_der      the same, DER
        subject      {'CN': .., 'O': .., 'OU': .., 'C': .., 'ST': .., 'L': .., 'emailAddress': ..}
        days         the validity asked for, where the issuer lets it be chosen (None: its own)
        profile      {'eku': ['serverAuth', 'clientAuth'], 'must_staple': False,
                      'acme_profile': 'shortlived', 'template': 'WebServer', ...}
        sans         every subjectAltName of the request, typed where not DNS/IP:
                     names + ['email:it@example.com', 'uri:https://example.com/x'] (the
                     DNS names and addresses are `names`, the ones proved); [] = names
        challenges   {name: Challenge instance} - for each name, how it is proved
        previous     the certificate being renewed (PEM) or None (ARI 'replaces')
        cert_id      the certificate's id in acme
        ref          the source's own id of this certificate (its order, its certificate
                     ID) where acme keeps one - a certificate imported from the source
                     (Import from a source): the order a renewal reissues. None: the
                     source finds its order as it always did (its settings, its state)
    """
    def __init__(self, **kw):
        self.names = []
        self.key_type = 'ec-256'
        self.key_pem = ''
        self.csr_pem = ''
        self.csr_der = b''
        self.subject = {}
        self.days = None
        self.profile = {}
        self.challenges = {}
        self.sans = []
        self.previous = None
        self.cert_id = None
        self.ref = None
        self.__dict__.update(kw)


class Issued(object):
    """What an issuer gives back: the certificate, the chain above it (each PEM,
    nearest first), and - only where the issuer made the key itself - the key."""
    def __init__(self, cert_pem, chain_pems=None, key_pem=None, info=None):
        self.cert_pem = cert_pem
        self.chain_pems = list(chain_pems or [])
        self.key_pem = key_pem
        self.info = dict(info or {})    # e.g. {'order_url': .., 'ari_id': ..}


class Bundle(object):
    """A certificate as a target gets it, in every shape it may want.

        name, names, serial, fingerprint (SHA-256, hex), not_before, not_after (epoch)
        cert_pem, key_pem, chain_pems, fullchain_pem
        b.as_format(fmt, password=None, alias=None) -> bytes, fmt one of
            'cert-pem' 'cert-der' 'key-pem' (PKCS#8) 'key-rsa' (PKCS#1) 'key-der'
            'chain-pem' 'fullchain-pem' 'combined-pem' (key + fullchain) 'p7b'
            'pfx' / 'p12' (PKCS#12, AES) 'p12-legacy' (3DES/RC2, for old devices) 'jks'
    A dual certificate (the same names with two kinds of key):
        b.alt                 the twin, a Bundle of its own, or None
        b.variant(v)          'main' | 'alt' | 'ec' | 'rsa' -> that one (PluginError: none)
        b.as_format('fullchain-pem@rsa')   a format of one of them
    The real one is acmelib.certs.bundle.CertBundle."""
    FORMATS = ('cert-pem', 'cert-der', 'key-pem', 'key-rsa', 'key-der', 'chain-pem',
               'fullchain-pem', 'combined-pem', 'p7b', 'pfx', 'p12', 'p12-legacy', 'jks')
    alt = None


# ---------------------------------------------------------------------------
# What proves a name: the words an issuer and a validation agree in
# ---------------------------------------------------------------------------
# An issuer says which of these prove a name to it (Issuer.proofs_for), a
# validation which of them it can put in place (Challenge.proofs_for); a name
# is proved where the two meet - wildcards only by a DNS one, IP addresses only
# by an HTTP one (acmelib/certs/compat.py decides it, for every page alike).
PROOFS = {
    'acme-dns-01': 'the ACME TXT record at _acme-challenge.NAME',
    'acme-http-01': 'the ACME file http://NAME/.well-known/acme-challenge/TOKEN',
    'acme-dns-persist-01': 'the persistent ACME TXT record at _validation-persist.DOMAIN, set '
                           'once (dns-persist-01, draft-ietf-acme-dns-persist)',
    'txt-any': 'a TXT record at any name with any value (a commercial CA\'s DCV)',
    'cname-any': 'a CNAME record at any name pointing anywhere (a commercial CA\'s DCV)',
    'http-file-any': 'a file at any path under http://NAME/.well-known/ (a commercial CA\'s DCV)',
    'email': 'an e-mail to the domain that a person approves - no validation module',
}
DNS_PROOFS = ('acme-dns-01', 'acme-dns-persist-01', 'txt-any', 'cname-any')
HTTP_PROOFS = ('acme-http-01', 'http-file-any')
# The kinds of place(): what each puts where.
PLACE_KINDS = {'txt': 'txt-any', 'cname': 'cname-any', 'file': 'http-file-any'}


# ---------------------------------------------------------------------------
# The three kinds of module
# ---------------------------------------------------------------------------
# The fields discovery asks by themselves (Plugin.discover_keys_of): how one signs in.
_SIGN_IN = re.compile(r'^(api|api_url|url|base_url|endpoint|host|hostport|server|address|port|'
                      r'region|tenant|tenant_id|client|client_id|user|username|login|account|'
                      r'account_id|customer|customer_id|reseller|realm|subscription|project|'
                      r'project_id|platform|auth|token|key|key_id|secret|password|keys|'
                      r'environment|sandbox|test_mode|insecure|verify_tls|service_account)$|'
                      r'^(api|ssh|auth|client|access|secret|account|tenant)_|'
                      r'_(key|secret|token|password|pass|user|login|url|endpoint)$')


class Plugin(object):
    family = ''             # 'issuer' | 'challenge' | 'target'
    kind = ''               # unique within the family: 'acme', 'f5', 'cloudflare'
    title = ''              # 'F5 BIG-IP'
    # The name a new one is offered with on the page (store.NAME_RE: letters,
    # digits, spaces and . _ @ + -). Empty: made from the title, made safe.
    default_name = ''
    description = ''        # a sentence or two for the page
    vendor = ''             # grouping on the page: 'Linux', 'F5', 'Fortinet', 'Public CA'
    fields = []             # the form of its settings
    doc = ''                # docs/<file>.md, said on the page as "read more"
    # How its SSH key (a field of the type sshkey) is put on the machine, said in
    # "How to set it up on ..." of the key card: 'linux' | 'windows' | 'mikrotik' |
    # 'pfsense' | 'opnsense' | 'generic', or {'title', 'steps': [{'title', 'html',
    # 'code'}], 'note'} of its own ({pub} {user} {from} {host} are filled in).
    sshkey_howto = ''
    # Things it can do besides its work, offered as buttons on the page, in the
    # console and as `acme --validation-action NAME KEY` (and --source-action,
    # --target-action): [{'key': 'prepare', 'label': 'Prepare the hosts',
    # 'help': '...', 'confirm': 'words asked first' (optional), 'changes': True}]
    # Each is run by action(key) in a job of its own, its steps written down.
    actions = []

    # Discovery (1.0.29) - "Find the settings from the account": a popup asks only what
    # signing in takes (discover_keys - None: found by discover_keys_of(), the secrets,
    # the addresses and the names to sign in with, and what shows them), the module asks
    # its server for the rest - read-only, nothing ordered, nothing saved - and the form
    # is offered what it found; every field stays settable by hand. discovery: True / False
    # to say so; None: offered where discover_setup() can find something (a module of
    # its own one, a list to choose from - a catalog field -, a DNS module's zones).
    # (Not `discover`: SSH DNS has a discover() of its own - what runs on the server.)
    discovery = None
    discover_keys = None

    def __init__(self, config, ctx):
        self.config = dict(config or {})
        self.ctx = ctx

    def c(self, key, default=None):
        """A setting of this module, the field's default where it is not set."""
        v = self.config.get(key)
        if v in (None, ''):
            for f in self.fields:
                if f['key'] == key:
                    return f.get('default', default)
            return default
        return v

    def test(self):
        """Try it - reach the server, sign in - without changing anything.
        Returns words to show; raises PluginError when it does not work."""
        return 'nothing to try for %s' % self.title

    # -- discovery ----------------------------------------------------------------------
    def discover_setup(self):
        """What the account says of the settings, for the form (read-only, as test()):
        {'sets': {key: value} (found: offered ticked), 'choices': {key: {'options':
        [[value, words]], 'sets': {value: {key: value}} (picked, those fields too),
        'pick': value}}, 'facts': [[words, value]] (shown only), 'notes': [words]}.
        Here: each list of the form (a catalog field) whose fields it needs are set.
        A module that knows more starts from Plugin.discover_setup(self) and adds."""
        out = {'sets': {}, 'choices': {}, 'facts': [], 'notes': []}
        cat = getattr(self, 'catalog', None)
        if not callable(cat):
            return out
        for f in self.fields or []:
            if f.get('type') != 'catalog' or not f.get('key'):
                continue
            key = f['key']
            # what it needs and is shown now (a field hidden by show_if - the other way
            # of signing in - is not needed)
            need = [d for d in f.get('depends') or [] if self.c(d) in (None, '') and
                    self._shown(d)]
            if need:
                labels = [str(next((x.get('label') for x in self.fields
                                    if x.get('key') == d), d)) for d in need]
                out['notes'].append('%s: set %s first, then ask again' % (
                    f.get('label') or key, ', '.join(labels)))
                continue
            try:
                got = cat(f.get('catalog') or key) or {}
            except PluginError as e:
                out['notes'].append('%s: %s' % (f.get('label') or key, e))
                continue
            except NotImplementedError:
                continue
            self.offer(out, key, got.get('options') or [], got.get('sets') or {})
        return out

    def _shown(self, key):
        """Whether a field is shown with the settings as they are (its show_if)."""
        f = next((x for x in self.fields or [] if x.get('key') == key), None)
        cond = (f or {}).get('show_if') or {}
        for k, want in cond.items():
            want = want if isinstance(want, (list, tuple)) else [want]
            have = self.c(k)
            if not any(str(w).lower() == str('' if have is None else have).lower() or
                       (isinstance(w, bool) and bool(have) == w) for w in want):
                return False
        return True

    def offer(self, out, key, options, sets=None, pick=None):
        """A choice put into discover_setup()'s answer: the value set now stays picked,
        else `pick`, else the only one there is."""
        opts = []
        for o in options or []:
            if isinstance(o, (list, tuple)) and o:
                opts.append([str(o[0]), str(o[1] if len(o) > 1 else o[0])])
            elif isinstance(o, str) and o:
                opts.append([o, o])
        if not opts:
            return
        now = self.config.get(key)
        vals = [o[0] for o in opts]
        if now not in (None, '') and str(now) in vals:
            pick = str(now)
        elif pick is None or str(pick) not in vals:
            pick = vals[0] if len(vals) == 1 else ''
        out['choices'][key] = {'options': opts, 'pick': str(pick),
                               'sets': {str(k): dict(v) for k, v in (sets or {}).items()
                                        if isinstance(v, dict)}}

    @classmethod
    def discover_keys_of(cls):
        """The fields the discovery popup asks: discover_keys, else the module's
        secrets, addresses and names to sign in with, with what shows them."""
        fields = [f for f in cls.fields or [] if f.get('key')]
        by = {f['key']: f for f in fields}
        if cls.discover_keys is not None:
            want = [k for k in cls.discover_keys if k in by]
        else:
            want = [f['key'] for f in fields if f.get('type') != 'catalog' and (
                f.get('type') in ('secret', 'sshkey') or f.get('secret') or
                _SIGN_IN.search(f['key']))]
        seen, i = list(want), 0
        while i < len(seen):                # what shows them, and what that needs
            for d in (by.get(seen[i], {}).get('show_if') or {}):
                if d in by and d not in seen:
                    seen.append(d)
            i += 1
        return [f['key'] for f in fields if f['key'] in seen]

    @classmethod
    def discover_offered(cls):
        """Whether the form offers discovery (describe()'s 'discover')."""
        if cls.discovery is not None:
            return bool(cls.discovery) and bool(cls.discover_keys_of())
        if not cls.discover_keys_of():
            return False
        if cls.discover_setup not in GENERIC_DISCOVERY:
            return True                     # a module that finds things of its own
        return callable(getattr(cls, 'catalog', None)) and \
            any(f.get('type') == 'catalog' for f in cls.fields or [])

    def action(self, key):
        """Do one of `actions` (by its key). Returns words to show; raises
        PluginError when it does not work. ctx.step() tells how it goes."""
        raise PluginError('%s can do nothing called "%s"' % (self.title or self.kind, key),
                          retry=False)

    @classmethod
    def describe(cls):
        return {'family': cls.family, 'kind': cls.kind, 'title': cls.title or cls.kind,
                'default_name': cls.default_name,
                'description': cls.description, 'vendor': cls.vendor,
                'fields': list(cls.fields), 'doc': cls.doc,
                'actions': [dict(a) for a in (cls.actions or [])],
                'discover': ({'keys': cls.discover_keys_of()} if cls.discover_offered()
                             else None),
                'sshkey_howto': cls.sshkey_howto,
                'module': getattr(cls, '_module_file', '')}


# discover_setup()s that find only what any module of a family would (lists, zones)
GENERIC_DISCOVERY = {Plugin.discover_setup}


class Issuer(Plugin):
    """Where a certificate comes from.

    What a certificate of this source may be (acmelib/certs/compat.py checks it
    everywhere - the pages, the API, the command line, the portal, the renewer):

        needs_challenge / needs_challenge_for(config)   each name proved by a validation
        challenge_types   ACME: the challenge types it takes ('dns-01', 'http-01')
        dcv / dcv_field   a commercial CA's domain validation: {method: {'proof': one of
                          PROOFS, 'words': ..., 'record': 'the shape, e.g. TXT at NAME'}},
                          the method chosen by the setting `dcv_field`; 'email' (proof
                          None) needs no validation at all
        proofs_for(config) -> [proofs]   any one of them proves a name (see PROOFS)
        wildcards, ip_names              names of those kinds are taken
        key_types / key_types_for(config) the key types it signs (None: all of them)
        public_names / public_for(config) a publicly trusted CA: only fully qualified
                          names under a public suffix (no "intranet", no .local)
        dual / dual_field                a twin of another key type (below)"""
    family = 'issuer'
    needs_challenge = False         # True: each name has to be proved (ACME)
    challenge_types = ()            # ('dns-01', 'http-01', 'tls-alpn-01') it can use
    makes_key = False               # True: the issuer makes the key (rare); else acme does
    wildcards = True
    ip_names = False
    choose_days = False             # the validity can be asked for
    dcv = {}                        # {method: {'proof', 'words', 'record'}} - a commercial CA
    dcv_field = ''                  # the setting that chooses the method of `dcv`
    dcv_default = ''                # the method when the setting is empty
    key_types = None                # None: every key type acme makes
    public_names = False            # True: a publicly trusted CA (CA/B Forum rules on names)
    # The subjectAltNames it puts in: 'dns', 'ip', 'email', 'uri' (None: all four for a
    # source of your own, DNS and IP for a public CA); cn_free: the common name may be
    # other than every SAN (None: only where it is not a public CA - CA/B Forum: the CN
    # is one of the SANs, 64 characters at most).
    san_types = None
    cn_free = None
    # A dual certificate (docs/certificates.md): the same names issued twice in one
    # job, the main key type and a twin of another kind (ECDSA beside RSA) - two
    # keys, two CSRs, two issue() calls. True: this source can give the twin. A
    # source where the second one costs (a paid order) says False and names a bool
    # setting in `dual_field` that allows it; dual_for() is what counts.
    dual = False
    dual_field = ''
    # What each certificate of this source may set for itself, kept in its profile and
    # asked in Add a certificate → Profile: [{'key' (the profile's key, e.g. 'template'),
    # 'label', 'help', 'placeholder', 'field' + 'catalog' (the field of its form of the type
    # catalog whose list it picks from - catalog() gives it; it can always be typed too)}].
    per_cert = []

    @classmethod
    def dual_for(cls, config):
        """Whether a source of this kind, with these settings, gives a twin."""
        if cls.dual_field:
            v = (config or {}).get(cls.dual_field)
            return v is True or str(v).strip().lower() in ('1', 'true', 'yes', 'on')
        return bool(cls.dual)

    def can_dual(self):
        return type(self).dual_for(self.config)

    # -- what a certificate of it may be (acmelib/certs/compat.py) -------------------------
    @classmethod
    def dcv_method(cls, config):
        """The DCV method chosen in these settings ('' where the source has none)."""
        if not cls.dcv:
            return ''
        m = str((config or {}).get(cls.dcv_field) or '').strip() if cls.dcv_field else ''
        if m not in cls.dcv:
            m = cls.dcv_default if cls.dcv_default in cls.dcv else sorted(cls.dcv)[0]
        return m

    @classmethod
    def proofs_for(cls, config):
        """The proofs (PROOFS) any one of which proves a name to this source;
        [] where none is needed (an authority of its own, DCV by e-mail)."""
        if cls.dcv:
            p = (cls.dcv.get(cls.dcv_method(config)) or {}).get('proof')
            return [p] if p else []
        if not cls.needs_challenge:
            return []
        return ['acme-' + t for t in (cls.challenge_types or ()) if 'acme-' + t in PROOFS]

    @classmethod
    def needs_challenge_for(cls, config):
        if cls.dcv:
            return bool(cls.proofs_for(config))
        return bool(cls.needs_challenge)

    @classmethod
    def dcv_where(cls, config, name, proof):
        """Where this source wants `proof` for `name` - the record's name (DNS) or
        the file's path (HTTP) - so a validation can say whether it can put it
        there. A commercial CA says it (its _dnsauth label, its file)."""
        bare = str(name or '').lower().rstrip('.')
        bare = bare[2:] if bare.startswith('*.') else bare
        if proof == 'acme-dns-01':
            return '_acme-challenge.' + bare
        if proof == 'acme-dns-persist-01':
            return '_validation-persist.' + bare
        if proof == 'acme-http-01':
            return '/.well-known/acme-challenge/'
        if proof == 'http-file-any':
            return '/.well-known/pki-validation/'
        return bare

    @classmethod
    def key_types_for(cls, config):
        """The key types this source signs (None: all of them)."""
        return list(cls.key_types) if cls.key_types is not None else None

    @classmethod
    def public_for(cls, config):
        """Whether the source is a publicly trusted CA with these settings."""
        return bool(cls.public_names)

    @classmethod
    def san_types_for(cls, config):
        if cls.san_types is not None:
            return list(cls.san_types)
        return ['dns', 'ip'] if cls.public_for(config) else ['dns', 'ip', 'email', 'uri']

    @classmethod
    def cn_free_for(cls, config):
        if cls.cn_free is not None:
            return bool(cls.cn_free)
        return not cls.public_for(config)

    @classmethod
    def describe(cls):
        d = Plugin.describe.__func__(cls)
        d['dual'] = bool(cls.dual) or bool(cls.dual_field)
        d['dual_field'] = cls.dual_field
        d['dcv'] = {k: dict(v) for k, v in (cls.dcv or {}).items()}
        d['dcv_field'] = cls.dcv_field
        d['key_types'] = list(cls.key_types) if cls.key_types is not None else None
        d['public_names'] = bool(cls.public_names)
        d['san_types'] = cls.san_types_for({})
        d['cn_free'] = cls.cn_free_for({})
        for k in ('wildcards', 'ip_names', 'choose_days', 'makes_key'):
            d.setdefault(k, bool(getattr(cls, k, False)))
        d.setdefault('needs_challenge', bool(cls.needs_challenge))
        d.setdefault('challenge_types', list(cls.challenge_types or ()))
        d['lists_existing'] = bool(cls.lists_existing)
        d['per_cert'] = [dict(x) for x in (cls.per_cert or [])]
        return d

    def issue(self, req):
        """-> Issued. Raise PluginError when it does not."""
        raise NotImplementedError

    # -- the certificates the account has already (Certificates → Import from a source) --
    # A source whose API lists the account's certificates sets lists_existing and
    # gives both of these. Both only READ - nothing is ordered, reissued or changed.
    lists_existing = False

    def list_existing(self):
        """Every certificate the account has at the source: a list of
        {'ref'          the source's own id of it (order id, certificate ID, serial) -
                        what fetch_existing() takes and a renewal reissues (req.ref)
         'cn', 'names', 'product', 'status' (words), 'not_before', 'not_after' (epoch),
         'paid_until'   the end of the order or subscription (epoch), where there is one
         'serial'       hex, where known (acme matches the certificates it has by it)
         'downloadable' bool: fetch_existing() can give the certificate now
         'renewable'    'reissue' (a free reissue of that order) | 'order' (only a new,
                        paid order) | 'issue' (a new certificate from the source, no
                        order: a private CA) | 'none'
         'note'         words, e.g. why it cannot be imported
         'acme_cert_id' the certificate of acme this one is, where the module knows}"""
        raise PluginError('%s cannot list the certificates of its account' % self.title,
                          retry=False)

    def fetch_existing(self, ref):
        """The certificate `ref` of list_existing(): {'cert_pem', 'chain_pems' (nearest
        first), 'ref' (the id to keep, when it is another one), 'acme_cert_id' (where the
        module knows acme has it)}. Never a key."""
        raise PluginError('%s cannot hand out the certificates of its account' % self.title,
                          retry=False)

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        raise PluginError('%s cannot revoke a certificate' % self.title, retry=False)

    def renewal_window(self, cert_pem):
        """(start, end) in epoch seconds, as the issuer suggests it (ACME ARI,
        RFC 9773), or None: acme decides by its own days before the end."""
        return None


# ---------------------------------------------------------------------------
# What a challenge tells a person: guide() and dry_run()
# ---------------------------------------------------------------------------
# Both give {'steps': [step, ...], 'ok': True | False | None}, a step being
#
#   {'key': 'cname',                    what kind of step (the same for every module that has it)
#    'what': 'words: what must be in place',
#    'where': 'your DNS at firma.cz' | 'acme' | 'the web server 10.0.0.5',
#    'record': {'name', 'type', 'value', 'ttl'} or None,   the exact record to create
#    'done': True | False | None,       None: acme cannot tell from here
#    'said': 'what was found',
#    'fix': 'what to do' ('' when done),
#    'blocking': bool}                  False: worth saying, but no reason not to ask the CA
#
# 'ok' is False when a step blocks, True when no step blocks and at least one
# was checked, None when nothing could be checked. The words are plain English,
# fixed sentences with the names at their edges (web/lang/*.json translates them).
def guide_step(key, what, where='', record=None, done=None, said='', fix='', blocking=None):
    if record is not None:
        record = {'name': str(record.get('name') or ''), 'type': str(record.get('type') or ''),
                  'value': str(record.get('value') or ''),
                  'ttl': record.get('ttl')}
    return {'key': str(key), 'what': str(what), 'where': str(where or ''), 'record': record,
            'done': done if done in (True, False) else None, 'said': str(said or ''),
            'fix': '' if done is True else str(fix or ''),
            'blocking': bool(done is False) if blocking is None else bool(blocking and
                                                                          done is False)}


def guide_of(steps):
    """{'steps', 'ok'} of a list of steps (see above)."""
    steps = [s for s in steps or [] if s]
    if any(s.get('blocking') for s in steps):
        ok = False
    elif any(s.get('done') is True for s in steps):
        ok = True
    else:
        ok = None
    return {'steps': steps, 'ok': ok}


def _b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


class Challenge(Plugin):
    """How a name is proved to a CA: an ACME challenge (present / ready /
    cleanup), and - where the module can put any record or file in place - a
    commercial CA's domain validation (DCV) through place / placed_ready /
    unplace:

        proofs_for(config) -> [PROOFS]       what it can put in place
        place_problem(proof, where, config, settings) -> '' or words: why it
                                             cannot put `proof` at `where` (a record's
                                             name, a file's path) - read-only, no network
        place(kind, name, where, content) -> handle
            kind 'txt'   a TXT record at the name `where` holding `content`
                 'cname' a CNAME record at `where` pointing at `content`
                 'file'  the file `where` (a path under /.well-known/) holding
                         `content`, served for http://name/
        placed_ready(handle) -> bool         it can be seen from outside
        unplace(handle)                      taken away again (quiet when gone)
    A module that cannot raises NotImplementedError from place(): acme then
    calls the pairing incompatible, before anything is ordered."""
    family = 'challenge'
    types = ()                      # ('dns-01',) or ('http-01',)
    proofs = ()                     # PROOFS it can put in place besides its ACME types
    parallel = True                 # several at once (False: one name at a time)
    dry_wait = 120                  # seconds dry_run() waits for ready() at most
    dry_every = 2.0                 # and how often it asks

    # -- what it can put in place (acmelib/certs/compat.py) ---------------------------------
    @classmethod
    def proofs_for(cls, config):
        out = ['acme-' + t for t in (cls.types or ()) if 'acme-' + t in PROOFS]
        return out + [p for p in (cls.proofs or ()) if p not in out]

    @classmethod
    def place_problem(cls, proof, where, config, settings):
        """'' when `proof` can be put at `where` (a record's name, a file's path),
        else the reason in words. Read-only and quick: no network."""
        if proof not in cls.proofs_for(config):
            return '%s cannot put %s in place' % (cls.title or cls.kind, PROOFS.get(proof, proof))
        return ''

    def place(self, kind, name, where, content):
        raise NotImplementedError('%s cannot put a %s in place' % (self.title or self.kind, kind))

    def placed_ready(self, handle):
        return True

    def unplace(self, handle):
        pass

    @classmethod
    def describe(cls):
        d = Plugin.describe.__func__(cls)
        d['types'] = list(cls.types or ())
        d['proofs'] = cls.proofs_for({})
        return d

    # -- what a person is told ---------------------------------------------------------
    def guide(self, name):
        """What must be in place for `name` to be proved this way: steps (see
        guide_step), each checked live where it can be without changing
        anything (DNS asked, an API read, a probe acme answers fetched).
        A module says what it knows; this one only says it cannot tell."""
        return guide_of([guide_step(
            'try', 'A dry run shows whether this validation works for the name',
            where='acme', done=None,
            said='this validation cannot tell what it needs before it is tried',
            fix='Run a dry run: acme puts a test record in place, looks for it from outside '
                'and takes it away again', blocking=False)])

    def dry_run(self, name, wait=None):
        """The validation tried for real, without a CA: a random test value put
        in place by present(), waited for with ready() (at most `wait`
        seconds, dry_wait), looked for from outside (seen_outside()) and taken
        away by cleanup() - always. Each step said through ctx.step as it goes."""
        import hashlib
        steps = []

        def say(st):
            steps.append(st)
            lvl = 'ok' if st['done'] is True else ('bad' if st['blocking'] else
                                                   'warn' if st['done'] is False else 'info')
            # a line each (each translated by itself on the pages)
            self.ctx.step(st['what'], lvl)
            if st['said']:
                self.ctx.step(st['said'], 'info')
            if st['fix'] and st['done'] is False:
                self.ctx.step(st['fix'], lvl)

        if wait is None:
            try:
                wait = float((self.ctx.settings or {}).get('certs_dry_run_s') or self.dry_wait)
            except (TypeError, ValueError):
                wait = self.dry_wait
        token = _b64u(os.urandom(24))
        ka = token + '.' + _b64u(os.urandom(24))
        txt = _b64u(hashlib.sha256(ka.encode('ascii')).digest())
        self.ctx.step('Dry run for %s: a test value is put in place, looked for and taken away '
                      'again - no CA is asked' % name)
        handle, placed = None, False
        try:
            try:
                handle = self.present(name, token, ka, txt)
                placed = True
                say(guide_step('present', 'The test value is put in place', where='acme',
                               done=True, said=self.dry_said(name, handle)))
            except PluginError as e:
                say(guide_step('present', 'The test value is put in place', where='acme',
                               done=False, said=str(e),
                               fix='Correct the validation\'s settings, then try again'))
                return guide_of(steps)
            end = time.time() + max(1.0, float(wait))
            seen, err = False, ''
            while True:
                if self.ctx.cancelled():
                    err = 'the job was stopped'
                    break
                try:
                    seen = bool(self.ready(name, handle))
                except PluginError as e:
                    err = str(e)
                    break
                except Exception as e:                  # noqa: BLE001
                    self.ctx.debug('ready(%s): %s' % (name, e))
                    seen = False
                if seen or time.time() >= end:
                    break
                time.sleep(min(self.dry_every, max(0.1, end - time.time())))
            say(guide_step('ready', 'The test value can be seen where the CA will look',
                           where='acme', done=seen,
                           said=err or ('seen' if seen else 'not seen after %d s' % int(wait)),
                           fix='See the steps above: the record or file is not where the CA '
                               'looks for it'))
            for st in self.seen_outside(name, handle) or []:
                say(st)
            return guide_of(steps)
        finally:
            if placed:
                try:
                    self.cleanup(name, handle)
                    self.ctx.step('The test value is taken away again', 'ok')
                except Exception as e:                  # noqa: BLE001
                    say(guide_step('cleanup', 'The test value is taken away again', where='acme',
                                   done=False, said=str(e), blocking=False,
                                   fix='Take it away by hand'))

    def dry_said(self, name, handle):
        """Words for where dry_run() put the test value (a module says it better)."""
        return ''

    def seen_outside(self, name, handle):
        """Steps: the test value of dry_run() looked for from outside (the
        zone's name servers and public resolvers, plain HTTP). [] here."""
        return []

    def present(self, name, token, key_authorization, txt_value):
        """Put the proof in place: for dns-01 the TXT record `txt_value` at
        _acme-challenge.<name> (wildcards without the *.), for http-01 the
        file /.well-known/acme-challenge/<token> holding key_authorization.
        Returns a handle for cleanup (any JSON-able value)."""
        raise NotImplementedError

    def ready(self, name, handle):
        """True once the proof can be seen from outside (DNS propagated, the
        file reachable). acme asks again until it is, or the wait runs out."""
        return True

    def cleanup(self, name, handle):
        """Take the proof away again. Must not raise for what is gone already."""
        pass

    def zone_of(self, name):
        """The zone a record for `name` goes in, where the module knows it."""
        return None


def dual_order_field(key='dual_order'):
    """The switch of a source whose second certificate is a second (paid) order."""
    return field(key, 'Allow a second (paid) order for a dual certificate', 'bool',
                 default=False, advanced=True,
                 help='A dual certificate (ECDSA and RSA of the same names) is two orders '
                      'here, each paid for. Off: a twin is not ordered from this source.')


# The deploy option of a target that serves one certificate at a time, added to its
# deployment's form by itself (Target.describe): which of a dual certificate's two
# it gets. 'auto' is the RSA one where there is one - what every client can use.
VARIANT_FIELD = {
    'key': 'variant', 'label': 'Which certificate (when it is dual)', 'type': 'select',
    'default': 'auto',
    'options': [['auto', 'RSA where there is one (works with every client)'],
                ['main', 'the main one (its own key type)'],
                ['alt', 'the twin'], ['rsa', 'the RSA one'], ['ec', 'the ECDSA one']],
    'advanced': True, 'dual_only': True,
    'help': 'This target holds one certificate at a time: of a dual certificate (ECDSA and '
            'RSA of the same names) it gets the one chosen here. Nothing changes for a '
            'certificate that is not dual.'}


class Target(Plugin):
    """Where a certificate is put, and what is told to take it."""
    family = 'target'
    # The options of one certificate on this target (a deployment): paths,
    # formats, the profile it goes into, the commands after.
    deploy_fields = []
    # True: deploy() is handed a dual certificate whole (bundle.alt the twin, None
    # when it is not dual) and puts both in place - nginx, Apache, HAProxy, F5,
    # acme's own pages... False: the target holds one at a time, and is handed the
    # one its deployment's 'variant' option says (VARIANT_FIELD), bundle.alt None.
    dual = False

    def deploy(self, bundle, options):
        """Put `bundle` in place as `options` say and make the service take
        it. Returns words for the job's log. Raise PluginError when it fails."""
        raise NotImplementedError

    def verify(self, bundle, options):
        """Is the new certificate what is served now? True / False / None (cannot tell)."""
        return None

    def remove(self, bundle, options):
        """Take an old certificate away from the device, where that makes sense."""
        pass

    @classmethod
    def describe(cls):
        d = Plugin.describe.__func__(cls)
        d['deploy_fields'] = list(cls.deploy_fields)
        if not cls.dual and not any(f.get('key') == 'variant' for f in cls.deploy_fields):
            d['deploy_fields'].append(dict(VARIANT_FIELD))
        d['dual'] = bool(cls.dual)
        # A target that writes the certificate as files (ssh, windows_ssh, local): what
        # the page's files designer needs - formats in words, quick layouts, the
        # variables of the script after them (targets/_script.py files_ui()).
        if getattr(cls, 'files_ui', None):
            d['files_ui'] = cls.files_ui
        return d


FAMILIES = {'issuer': Issuer, 'challenge': Challenge, 'target': Target}
FOLDERS = {'issuer': 'issuers', 'challenge': 'challenges', 'target': 'targets'}


# ---------------------------------------------------------------------------
# Finding them
# ---------------------------------------------------------------------------
class Registry(object):
    """Every module there is, found once and found again on reload()."""
    def __init__(self, extra_dirs=None):
        self.lock = threading.Lock()
        self.found = {f: {} for f in FAMILIES}
        self.broken = []                # [(file, words)] - shown on the page
        here = os.path.dirname(os.path.abspath(__file__))
        self.dirs = [here] + list(extra_dirs or [])

    def reload(self):
        found = {f: {} for f in FAMILIES}
        broken = []
        for root in self.dirs:
            for family, folder in FOLDERS.items():
                d = os.path.join(root, folder)
                if not os.path.isdir(d):
                    continue
                for fn in sorted(os.listdir(d)):
                    if not fn.endswith('.py') or fn.startswith(('_', '.')):
                        continue
                    path = os.path.join(d, fn)
                    try:
                        mod = self._load(root, folder, fn, path)
                    except Exception as e:              # noqa: BLE001
                        broken.append((path, '%s: %s' % (type(e).__name__, e),
                                       traceback.format_exc()))
                        continue
                    for obj in vars(mod).values():
                        if isinstance(obj, type) and issubclass(obj, FAMILIES[family]) and \
                                obj is not FAMILIES[family] and obj.kind and \
                                obj.__module__ == mod.__name__:
                            obj._module_file = path
                            found[family][obj.kind] = obj   # a later folder wins: yours
        with self.lock:
            self.found, self.broken = found, broken
        return self

    def _load(self, root, folder, fn, path):
        if root == self.dirs[0]:
            name = 'acmelib.plugins.%s.%s' % (folder, fn[:-3])
        else:
            name = 'acme_local_plugins.%s.%s' % (folder, fn[:-3])
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod

    def get(self, family, kind):
        with self.lock:
            cls = self.found.get(family, {}).get(kind)
        if not cls:
            raise PluginError('there is no %s module "%s" (Settings → About lists them)'
                              % (family, kind), retry=False)
        return cls

    def all(self, family=None):
        with self.lock:
            if family:
                return dict(self.found.get(family, {}))
            return {f: dict(v) for f, v in self.found.items()}

    def describe(self):
        return {f: sorted((c.describe() for c in v.values()),
                          key=lambda d: (d['vendor'], d['title']))
                for f, v in self.all().items()}


REGISTRY = Registry(extra_dirs=[os.environ.get('ACME_PLUGINS', '/etc/acme/plugins')])


def b64(data):
    return base64.b64encode(data).decode('ascii')
