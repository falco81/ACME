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
FIELD_TYPES = ('text', 'secret', 'number', 'bool', 'select', 'textarea', 'pem', 'list',
               'hostport', 'sshkey')


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
        ctx.dns_put(name, type, value, ttl=60) / ctx.dns_drop(name, type, value)
                                            a record in acme's own DNS server
        ctx.http_token_put(token, key_authorization) / ctx.http_token_drop(token)
                                            an answer on this server's /.well-known/acme-challenge/
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

    For a target that is acme itself (targets/appliance.py) - the certificate
    of its own pages, as Settings → Certificates and TLS keeps it:
        ctx.pages_where() -> {'node', 'nodes': [...], 'cluster', 'vip': {'on', 'fqdn'}}
        ctx.pages_get(where) -> {'fingerprint', 'cn', 'not_after', 'how'} or None
        ctx.pages_put(where, cert_pem, key_pem, chain_pems, how) -> {'cn', 'not_after', ...}
                                            where: a node's name or 'vip'; every node puts
                                            its own in place within seconds
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
        challenges   {name: Challenge instance} - for each name, how it is proved
        previous     the certificate being renewed (PEM) or None (ARI 'replaces')
        cert_id      the certificate's id in acme
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
        self.previous = None
        self.cert_id = None
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
# The three kinds of module
# ---------------------------------------------------------------------------
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
                'sshkey_howto': cls.sshkey_howto,
                'module': getattr(cls, '_module_file', '')}


class Issuer(Plugin):
    """Where a certificate comes from."""
    family = 'issuer'
    needs_challenge = False         # True: each name has to be proved (ACME)
    challenge_types = ()            # ('dns-01', 'http-01', 'tls-alpn-01') it can use
    makes_key = False               # True: the issuer makes the key (rare); else acme does
    wildcards = True
    ip_names = False
    choose_days = False             # the validity can be asked for
    # A dual certificate (docs/certificates.md): the same names issued twice in one
    # job, the main key type and a twin of another kind (ECDSA beside RSA) - two
    # keys, two CSRs, two issue() calls. True: this source can give the twin. A
    # source where the second one costs (a paid order) says False and names a bool
    # setting in `dual_field` that allows it; dual_for() is what counts.
    dual = False
    dual_field = ''

    @classmethod
    def dual_for(cls, config):
        """Whether a source of this kind, with these settings, gives a twin."""
        if cls.dual_field:
            v = (config or {}).get(cls.dual_field)
            return v is True or str(v).strip().lower() in ('1', 'true', 'yes', 'on')
        return bool(cls.dual)

    def can_dual(self):
        return type(self).dual_for(self.config)

    @classmethod
    def describe(cls):
        d = Plugin.describe.__func__(cls)
        d['dual'] = bool(cls.dual) or bool(cls.dual_field)
        d['dual_field'] = cls.dual_field
        return d

    def issue(self, req):
        """-> Issued. Raise PluginError when it does not."""
        raise NotImplementedError

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
    """How a name is proved to an ACME CA."""
    family = 'challenge'
    types = ()                      # ('dns-01',) or ('http-01',)
    parallel = True                 # several at once (False: one name at a time)
    dry_wait = 120                  # seconds dry_run() waits for ready() at most
    dry_every = 2.0                 # and how often it asks

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
