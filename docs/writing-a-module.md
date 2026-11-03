# Writing a target module

A target module teaches acme a new place to put certificates - a load
balancer, a firewall, an appliance with an API or an SSH shell. It is one
Python file. acme finds it by itself: no registration, no restart of the web
pages; the form for it is drawn from what it declares.

## Where it goes

```
/etc/acme/plugins/targets/<something>.py
```

Files there are kept across upgrades. A module with the same `kind` as a
built-in one replaces it. Files starting with `_` are not modules (use them
for your own helpers). After adding or changing one, restart the daemon
(`systemctl restart acme`) so the registry looks again; *Settings → About*
lists the modules found, and a file that does not load is listed there with
its error while the rest keep working.

Only the Python standard library is there - no `pip install`. Everything that
reaches out goes through the **Context** acme hands the module (`self.ctx`):

| | |
|---|---|
| `ctx.http(method, url, body=None, headers=None, timeout=30, verify=True, ca_pem=None, client_cert=None, proxy=True)` | → `(status, headers, body_bytes)`, header names lower case |
| `ctx.ssh(conn)` | an SSH session: `s.run(cmd, input=None, timeout=120, check=True)` → `(rc, out, err)`, `s.put(data, path, mode=0o600, owner=None)`, `s.get(path)`; use as `with ctx.ssh(conn) as s:` |
| `ctx.step(words, level)` | a line in the job (`info`, `ok`, `warn`, `bad`) |
| `ctx.debug(words)` | a line only when debugging |
| `ctx.kv_get(key)` / `ctx.kv_set(key, value)` | a little state of the module's own, shared by the cluster |
| `ctx.cancelled()` | the job was stopped: give up |

A module never opens sockets, files or the database itself (the TLS check of
`_common.served_der` is the one exception, and it only reads).

## The contract

Subclass `acmelib.plugins.base.Target` (or, easier, one of the helpers below)
and set:

- `kind` - short, unique, lower case: stored in the database, do not rename it later;
- `title`, `vendor`, `description` - for the page (modules are grouped by vendor);
- `fields` - **the target's form**: how acme reaches and signs in to the
  device. Types: `text secret number bool select textarea pem list hostport sshkey`;
  `secret` values are sealed and never sent back in clear (a full administrator
  sees eight dots and the last two characters, anybody else dots; the dots
  saved back keep the one set) - `multiline=True` for a key or lines, and a
  `pem` field with `secret=True` (a private key) is kept the same way. Options:
  `required`, `default`, `placeholder`, `help`, `options` (select),
  `show_if` (`{'auth': ['password']}`), `advanced` (folded under *More*).
  `sshkey` is the SSH key acme signs in with, drawn as isemon's key card (Make a
  key, Use my own, Download it, Forget it, Try reaching it, How to set it up):
  give it `secret=True`; the module reads the private key from it as from any
  secret (`self.c('key')`), and a passphrase of a key brought in the field named
  by `pass_key` (`key_pass`). Optional: `auth_key` (the select saying key or
  password), `ssh_prefix` (`ssh_` when the module's SSH fields have one),
  `try_command` (what *Try reaching it* runs once signed in - it must change
  nothing; `id -un; uname -n` when not said), `key_type='rsa4096'`, and `howto`
  - `linux windows mikrotik pfsense opnsense generic` - or the class attribute
  `sshkey_howto`, which may also be a guide of its own: `{'title', 'note',
  'steps': [{'title', 'html', 'code'}]}` with `{pub} {user} {from} {host}
  {file} {line}` filled in. `ssh_fields()` of `targets/_common.py` and
  `challenges/_common.py` give it already;
- `deploy_fields` - **one deployment's form**: what to do with *this*
  certificate there (profiles, listeners, paths, commands). A field of the
  type `catalog` here (`catalog='virtual_servers', autoload=False`) is a list
  picked from, with a value always typed instead: *Load the list* asks the
  module's `catalog(key)` - read-only - with the target's settings and the
  deployment's options over them (`self.c('a_deploy_key')`), so a
  deployment's key must not be a target's too;

and implement:

- `test(self)` → words. Sign in and read something harmless (a version).
  **Change nothing.**
- `deploy(self, bundle, options)` → a short line for the job. Put the
  certificate in place and make the service use it. Raise `PluginError` with
  words a person can act on (`detail=` for the device's full answer,
  `retry=False` when trying again unchanged cannot help - wrong password,
  missing profile).
- `verify(self, bundle, options)` → `True` / `False` / `None` - optional; the
  helpers below do it from a `verify` host:port list.
- `remove(self, bundle, options)` - optional: take a certificate away.

Optionally, `actions` - **things it can do besides its work**, each a button
on its row, an item in the console and `acme --target-action NAME KEY`:

```python
actions = [{'key': 'prepare', 'label': 'Prepare the device',
            'help': 'What it does, in a sentence.',
            'confirm': 'Asked first (optional)?', 'changes': True}]

def action(self, key):          # -> words; raise PluginError when it fails
    ...
```

Each runs in a job of its own (`ctx.step` writes its steps); `changes: True`
(the default) makes it a full administrator's. Issuers and challenges take
`actions` the same way (`http_ssh` has `prepare`).

`self.c('key')` reads a target field (its default when unset); `options` is
a plain dict of the deployment fields, plus `options['force']` when the
person asked to deploy again regardless.

`bundle` is the certificate: `name`, `names`, `serial`, `fingerprint`
(SHA-256 hex), `not_before`, `not_after`, `cert_pem`, `key_pem`, `chain_pems`,
`fullchain_pem`, and `bundle.as_format(fmt, password=None, alias=None)` →
bytes for `cert-pem cert-der key-pem key-rsa key-der chain-pem fullchain-pem
combined-pem p7b pfx p12 p12-legacy jks`.

## Be a good module

- **Idempotent**: the same fingerprint again must not change anything
  (unless `force`). Look on the device, or remember what you did.
- **New names, not overwrites**: name objects `acme-<name>-<date>-<serial>`,
  point the service at the new one, *then* delete old ones beyond a *keep*
  count - never one still in use. A failed deployment then leaves the old
  certificate working.
- **Steps**: one `ctx.step()` per thing done on the device; the job is what
  someone reads at 3 a.m.
- **No secrets in words**: never put a password or key into a step or an error.
- **Kind to the service** (1.0.21): go through `ctx.http` - it keeps two requests
  at once and four a second per host, waits out a 429 / 503 / "too many attempts"
  and asks an idempotent call again (`idempotent=True` for a POST that may be
  repeated). Sign in through `acmelib.plugins.limits.session(limits.key_of(self,
  'token'), login)` where `login()` returns `(token, seconds it lives)`: the token is
  shared by every run with the same settings, a refused sign-in is not repeated for
  a minute; after a 401 call `limits.session_drop(key, token)` and sign in once more.
  A list of zones or domains: `limits.shared(limits.key_of(self, 'zones'), fn)`.
  Under a test's stand-in ctx (`limits.sharing(ctx)` false) nothing is shared.

## The helpers: `acmelib.plugins.targets._common`

| | |
|---|---|
| `HttpTarget` | a `Target` with `self.req(method, path, body, headers, ok=, what=)` → `(status, headers, data)` over `ctx.http`: JSON in and out, the target's TLS check / CA / proxy / timeout fields applied, a non-2xx status turned into a `PluginError` in words. Override `auth_headers()` and, if needed, `base_url()`. |
| `Base` | the same without HTTP: `unchanged(bundle, options, present=)`, `remember(bundle, options)`, `same(bundle, words)`, `keep(options)`, `opt(options, key)`, and `verify()` from the `verify` field |
| `SshMixin` | `self.ssh()` from `ssh_fields()`, `self.sh(s, script)` - through sudo when the target says so |
| `http_fields(port, placeholder)`, `tls_fields()`, `ssh_fields(sudo=)`, `verify_fields()`, `keep_field(n)` | the usual fields |
| `object_name(bundle, options, maxlen=)`, `name_prefix(…)`, `prune(names, prefix, keep, current)` | dated names and which old ones to delete |
| `ours(name, prefix)`, `covers(names, host)` | is a name one of those dated ones (not a twin's that only starts the same); does a certificate's name (a wildcard too) cover a hostname |
| `chain_list(bundle)`, `chain_id(pem)` | the intermediates one by one, a stable short id each |
| `check_served(ctx, bundle, hostports, sni)`, `served_fingerprint(host, port, sni)` | the TLS handshake check |
| `parse_outputs(lines, vars)` | the `format path [mode] [owner]` lines of the ssh module |
| `multipart(parts)`, `form(dict)`, `lines(v)`, `as_bool(v)`, `text(v)` | small things |

They are acme's own and may grow; what is listed here stays.

## A complete example

A load balancer with a REST API: `GET /api/v1/system/version`,
`GET|POST /api/v1/certificates`, `PATCH /api/v1/listeners/<name>`, a bearer
token.

```python
# -*- coding: utf-8 -*-
"""
ExampleNet LB-9000: certificates through its REST API.

    /etc/acme/plugins/targets/examplelb.py
"""
from acmelib.plugins.base import field, PluginError
from acmelib.plugins.targets._common import (
    HttpTarget, http_fields, tls_fields, verify_fields, keep_field,
    object_name, name_prefix, prune, lines, text)


class ExampleLb(HttpTarget):
    kind = 'examplelb'                      # unique; the same as a built-in replaces it
    title = 'ExampleNet LB-9000'
    vendor = 'ExampleNet'
    description = 'Uploads the certificate through the LB-9000 REST API and binds it.'
    doc = 'targets.md'

    # How acme signs in - the target's form (secrets are sealed).
    fields = http_fields(8443, 'lb.example.local') + [
        field('token', 'API token', 'secret', required=True),
    ] + tls_fields()

    # What one certificate does there - the deployment's form.
    deploy_fields = [
        field('listeners', 'Listeners', 'list', placeholder='https-main',
              help='one a line: the listeners that serve this certificate'),
        keep_field(2),
    ] + verify_fields()

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.c('token')}

    def test(self):
        st, hd, d = self.req('GET', '/api/v1/system/version', what='signing in')
        return 'signed in to %s, firmware %s' % (self.c('host'), d.get('version', '?'))

    def deploy(self, bundle, options):
        name = object_name(bundle, options)           # acme-www.example.com-20261101-0a1b2c3d
        prefix = name_prefix(bundle, options)          # acme-www.example.com-
        st, hd, d = self.req('GET', '/api/v1/certificates/%s' % name, ok=(200, 404))
        if self.unchanged(bundle, options, present=lambda: st == 200):
            return self.same(bundle, 'as %s' % name)
        if st == 404:
            self.req('POST', '/api/v1/certificates', {
                'name': name,
                'certificate': text(bundle.as_format('fullchain-pem')),
                'key': text(bundle.as_format('key-pem')),
            }, what='uploading %s' % name)
            self.ctx.step('uploaded %s' % name, 'ok')
        for li in lines(options.get('listeners')):
            self.req('PATCH', '/api/v1/listeners/%s' % li, {'certificate': name},
                     what='binding %s' % li)
            self.ctx.step('%s uses %s' % (li, name), 'ok')
        st, hd, d = self.req('GET', '/api/v1/certificates')
        for old in prune([c['name'] for c in d.get('items', [])], prefix,
                         self.keep(options), name):
            try:
                self.req('DELETE', '/api/v1/certificates/%s' % old)
                self.ctx.step('deleted the old %s' % old)
            except PluginError as e:
                self.ctx.step('the old %s stays: %s' % (old, e), 'warn')
        self.remember(bundle, options)
        return 'uploaded %s, bound to %s' % (name, ', '.join(lines(options.get('listeners')))
                                             or 'nothing')
```

That is all: save it as `/etc/acme/plugins/targets/examplelb.py`, reload the
modules, and *ExampleNet LB-9000* is in the list of targets with an address,
port, token and TLS fields; each deployment to it asks for listeners, how many
previous versions to keep, and where to check what is served.

## Over SSH instead

For a device with a shell and no API, use `SshMixin` and `ssh_fields()`:

```python
from acmelib.plugins.targets._common import (
    Base, SshMixin, ssh_fields, verify_fields, object_name, quote)


class ExampleSsh(SshMixin, Base):
    kind = 'examplessh'
    title = 'ExampleNet SG (SSH)'
    vendor = 'ExampleNet'
    description = 'Copies the certificate over SSH and runs the import command.'
    fields = ssh_fields(sudo=False, user_default='admin')
    deploy_fields = verify_fields()

    def test(self):
        with self.ssh() as s:
            rc, out, err = s.run('show version', check=False)
        return 'signed in: %s' % out.strip().splitlines()[0]

    def deploy(self, bundle, options):
        if self.unchanged(bundle, options):
            return self.same(bundle)
        name = object_name(bundle, options)
        with self.ssh() as s:
            s.put(bundle.as_format('pfx', password='x'), '/tmp/%s.p12' % name)
            self.sh(s, 'cert-import --name %s --file /tmp/%s.p12 --password x && rm -f /tmp/%s.p12'
                    % (quote(name), name, name), what='the import')
        self.remember(bundle, options)
        return 'imported %s' % name
```

## A source that lists its account's certificates

Sources (`acmelib/plugins/issuers/`, base class `Issuer`) whose API can list
the certificates of the account offer them to *Certificates → Import from a
source* (acmelib/certs/onlineimport.py). Set `lists_existing = True` and give
both, each only reading - never ordering, reissuing or changing anything:

```python
lists_existing = True

def list_existing(self):        # -> [ {...}, ... ]
    return [{'ref': '1234567890',           # the source's own id: order id, certificate ID, serial
             'cn': 'www.example.cz', 'names': ['www.example.cz', 'example.cz'],
             'product': 'PositiveSSL', 'status': 'issued and active',
             'not_before': 1767225600, 'not_after': 1784505600,   # epoch
             'paid_until': 1830297600,      # the end of the order/subscription, or None
             'serial': '0A1B…',             # hex where known: acme matches its own by it
             'downloadable': True,          # fetch_existing() can give it now
             'renewable': 'reissue',        # 'reissue' | 'order' (only a new, paid one) |
                                            # 'issue' (a private CA) | 'none'
             'note': '',                    # words: why it cannot be imported, say
             'acme_cert_id': None}]         # acme's certificate it is, where the module knows

def fetch_existing(self, ref):  # -> the certificate, never a key
    return {'cert_pem': leaf, 'chain_pems': [intermediate, root], 'ref': ref,
            'acme_cert_id': None}
```

`ctx.kv_keys(prefix)` gives the module's own state by key prefix - how
`ssls`, `sslmarket` and `digicert` find the orders acme made for its
certificates (`acme_cert_id`). `acmelib.plugins.issuers._source_common.existing(certs_der,
chain_der, who, ref)` picks the certificate among those an API sent and puts
its chain in order.

The `ref` is kept with the imported certificate (`certs.issuer_ref`) and
handed to `issue()` at every renewal as `req.ref`: renew *that* order (it wins
over a setting like "Certificate to reuse"), and say in `Issued.info['ref']`
the id actually used - a new order's - so acme keeps it for the next time.

## A test of a server

A test (`acmelib/plugins/checks/`, base class `Check`; your own in
`/etc/acme/plugins/checks/` or uploaded on Settings → Modules) knows one protocol:
it connects, does the protocol's own start (STARTTLS, a negotiation), does TLS
and gives back the chain the server sent. Comparing it with the certificate is
not its job - `acmelib/certs/checks.py` does that the same way for every test.

```python
from acmelib.plugins.base import Check, PluginError, field
from acmelib.plugins.checks import _tls


class SieveCheck(Check):
    kind = 'sieve'
    title = 'ManageSieve (STARTTLS)'
    protocol = 'ManageSieve'
    default_port = 4190
    starttls = True
    description = 'A ManageSieve server: STARTTLS on port 4190.'
    fields = _tls.fields(4190)        # + [field(...)] of its own, before TLS's settings

    def served(self, host, port, sni, verify=True):
        t = float(self.c('timeout', 15) or 15)
        sock = _tls.connect(host, port, t)          # through an SSH server too, by itself
        lines = _tls.Lines(sock, 'the ManageSieve server')
        while not lines.line().startswith('OK'):
            pass
        lines.send('STARTTLS')
        if not lines.line().startswith('OK'):
            raise PluginError('the server refused STARTTLS')
        return _tls.tls(sock, sni, verify, t)       # {'chain': [DER...], 'tls', 'cipher'}
```

Rules: use `_tls.connect()` (it honours the address family, the source address
and an SSH relay) and `_tls.tls()` or `_tls.context()` / `_tls.result()` (they
honour the TLS versions, ciphers and ALPN set in the test); with `verify=True`
let `ssl.SSLCertVerificationError` out - acme asks again with `verify=False` to
see the chain all the same; say every failure in words (`PluginError`) with what
the server said. `_tls.fields(port, more)` gives the settings every test has;
put your own in `more`. A test only reads: never log in, never send mail.

## Versions, overrides and the page Modules

**Where modules come from**, in this order - a later one wins: shipped with acme
(`acmelib/plugins/`), your own on the disk of a node (`ACME_PLUGINS`,
`/etc/acme/plugins/<issuers|challenges|targets>/`), and uploaded on Settings →
**Modules** (kept in the database; each node writes them into
`/var/lib/acme/plugins-uploaded/` itself and loads them).

**Versions** - one kind, several implementations (the API generations of a
device): give each class a `module_version`; the plain one is `''`.

```python
from acmelib.plugins.targets.netscaler import NetScalerTarget

class NetScaler14(NetScalerTarget):
    module_version = '14.1'
    version_label = 'NITRO of ADC 14.1'
    default_version = True        # a new one, and one that says none, takes this
```

Each source, validation or target chooses its version in its form (the cards
under *Settings of the module*); it is kept in its settings as `_version`. A
version that is no longer there (its file taken away) is said on the page in
red, and the default version is used meanwhile. Secrets of every version are
sealed whichever is used.

**Overrides** - a class of your own with the kind *and* version of one that is
there replaces it: `class NetScalerMine(NetScalerTarget)` with no
`module_version` replaces the plain shipped NetScaler. The page tags it
*override*; one with a version of its own is tagged *uploaded* or *own module*
and adds that version. A module shipped with no versions can get two of your
own: they sit beside the plain one, and `default_version` chooses.

**Settings → Modules** (certificate administrators read it, full administrators
act): every module with where it comes from, its versions and how many use
each; *Download* gives the source of any of them (a shipped one to start an
override from), *Make one of your own* a file that subclasses it, *Upload a
module* takes a `.py` file - checked first in a process of its own (it must
load and hold a module of that family; what it would add or replace is shown)
and only then kept. An uploaded module is in every copy of the database and on
both nodes of a cluster by itself; files of your own on the disk are kept in
the database too (`custom-modules:<node>` in `meta`), compared between the
nodes (a warning when they differ) and written back with
`acme --plugins-sync NODE` (root) - after a copy was put back on a new machine,
say. A full backup (Settings → Backups) has them in `plugins/` as well.

**Marks** - *tested*, *works*, *problem* - say how far a version of a module
is checked. A full administrator sets them on the page (or
`acme --module-mark target/netscaler@14.1 works --note "ADC 14.1-25"`); they
are kept with the sha256 of the file, so a mark on a file changed since says
so. A release ships its own in `acmelib/plugins/verified.json`
(`"target/netscaler@": {"state": "works", "note": "...", "since": "1.0.32"}`);
`acme --module-marks-export` prints the marks set on an installation in that
shape, to put into the file before a release.

## Filled in from the account (discovery)

*Find the settings from the account* (web/assets/discover.js, POST
/api/<sources|validations|targets>/discover, `acme --source-discover`) asks
only the sign-in and lets the module read the rest. `Plugin.discover_setup()`
does it, read-only like `test()`:

```python
discover_keys = ['api', 'token']         # what the popup asks (None: the secrets,
                                         # addresses and users, with what shows them)

def discover_setup(self):
    out = Plugin.discover_setup(self)    # the lists of its catalog fields (DNS: the zones)
    prods = self._api_products()
    self.offer(out, 'product', [[p['code'], p['title']] for p in prods])
    out['sets']['contact_email'] = self._account()['email']    # offered ticked when empty
    out['facts'].append(['Products', str(len(prods))])          # shown only
    out['notes'].append('...')                                  # said in words
    return out
```

Keys are the module's own fields, never secrets. A choice keeps the value set
now picked; `pick=''` with an option `''` (said in words) where empty means
something, and for anything that costs or binds (an order to reuse). Nothing
is written, ordered or changed - only listing and reading calls the vendor
documents. `discovery = False` takes the button away from a module that has
nothing to find; it is offered by itself where `discover_setup()` is the
module's own, where a field is of type `catalog`, or for a DNS module with a
`zone` field and its own `zone_names()`.

## Trying it without a device

`test/test_targets.py` has a fake `Context` (`FakeCtx`: canned answers per
method and URL, every request recorded), a fake SSH session and a fake
certificate made with openssl. Copy one of its test classes, point it at
your module:

```python
from acmelib.plugins.base import Registry
reg = Registry(extra_dirs=['/etc/acme/plugins']).reload()
print(reg.broken)                     # [] when every module loads
cls = reg.get('target', 'examplelb')
ctx = FakeCtx([('GET', r'/version$', (200, {'version': '9.1'}))])
print(cls({'host': 'lb', 'token': 't'}, ctx).test())
```

and check the requests in `ctx.calls` are what the device's API documents.
