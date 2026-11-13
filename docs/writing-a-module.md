# Writing a target module

A target module teaches acme a new place to put certificates - a load
balancer, a firewall, an appliance with an API or an SSH shell. It is one
Python file. acme finds it by itself: no registration, no restart of the web
pages; the form for it is drawn from what it declares.

## Where it goes

```
/etc/acme/plugins/targets/<something>.py
```

The folders are `issuers/` (sources), `challenges/` (validations),
`targets/` and `checks/` (tests). Files there are kept across upgrades. A
module with the same `kind` (and version) as a built-in one replaces it - see
*Where modules come from, and which one wins* below. Files starting with `_`
are not modules (use them for your own helpers). `/etc/acme/plugins/README`
says the same in short, and `/etc/acme/plugins/examples/` holds working
examples (`*.py.example`, not loaded): a new target, another version of a
shipped target, an override, a new test, a version of a validation and of a
source - each says the name to copy it to. install.sh writes both again at
every install; your own files are never touched. After adding or changing one, restart the daemon
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
  A `list` with `options_from` (`'tests'`, `'targets'`, `'cas'`…) is chosen from
  what is defined: drawn as a table of the chosen ones (each taken off or moved
  up by its own button) with an *Add* button under it offering the rest -
  `add_words` names that button (`'Add a test'`); the module gets the names
  chosen, in that order. Not `required`, it can be saved empty and filled later.
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
| `Base` | the same without HTTP: `unchanged(bundle, options, present=)`, `remember(bundle, options)`, `same(bundle, words)`, `keep(options)`, `opt(options, key)`; `served_places(options)` and `served_wait` say where it serves and how long it restarts - a test of it is attached with a new deployment (1.0.93) |
| `SshMixin` | `self.ssh()` from `ssh_fields()`, `self.sh(s, script)` - through sudo when the target says so |
| `http_fields(port, placeholder)`, `tls_fields()`, `ssh_fields(sudo=)`, `verify_fields()`, `keep_field(n)` | the usual fields |
| `object_name(bundle, options, maxlen=)`, `name_prefix(…)`, `prune(names, prefix, keep, current)` | dated names and which old ones to delete |
| `ours(name, prefix)`, `covers(names, host)` | is a name one of those dated ones (not a twin's that only starts the same); does a certificate's name (a wildcard too) cover a hostname |
| `chain_list(bundle)`, `chain_id(pem)` | the intermediates one by one, a stable short id each |
| `check_served(ctx, bundle, hostports, sni)`, `served_fingerprint(host, port, sni)` | the TLS handshake check |
| `parse_outputs(lines, vars)` | the `format path [mode] [owner]` lines of the ssh module |
| `multipart(parts)`, `form(dict)`, `lines(v)`, `as_bool(v)`, `text(v)` | small things |

They are acme's own and may grow; what is listed here stays.

**`served_places(options)`** (1.0.93) returns `[(host, port)]`: where the deployment with
these options serves the certificate - each becomes a test (Certificates → Tests) attached
with a new deployment and run after it (`acmelib/certs/checks.py` `served_tests`, through
`for_target`). Return `[]` where the address the module knows does not serve this certificate
(vSphere Supervisor's NSX ingress: its API endpoint serves another). Two things may be added
(1.0.96), both left out by every module before - their places mean what they meant:

- a third item, the key the test asks for: `(host, port, 'rsa')` or `(host, port, 'ecdsa')`
  - where one port serves an RSA and an ECDSA certificate and picks by what the client offers
  (CUCM's Cisco Tomcat: `tomcat` and `tomcat-ECDSA` on 8443). The test is made with *Key
  asked for* set so (TLS 1.2 with ciphers of that key only, `checks/_tls.py`); without it the
  test takes whichever the server picks and may get the other unit's certificate;
- the host `self.CERT_NAME` (`'{name}'`): the certificate's first name - for a module that
  deploys to the name taken from the certificate when its field is empty (`vcf_component`
  without *Component FQDN*); the test is made with no host and connects to that name.

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

## The device makes the key

Some devices take only a certificate for a key they made themselves (Lenovo XClarity
Controller, Dell OpenManage Enterprise, Cisco CUCM, Unisphere for PowerMax, SDDC Manager,
HPE Synergy, Fujitsu MMB...): they make a key and a CSR through their API or CLI and import
the certificate signed for it. A target module for such a device says so and asks it for the
CSR; acme then never holds the key, and does the rest - the issue (any source that signs a
CSR: an ACME CA, an authority of acme's own, a commercial CA), renewal, ARI, retries,
notices, events, What happens - as for any certificate.

```python
class ExampleBmc(HttpTarget):
    kind = 'examplebmc'
    ...
    device_key = True                                   # default False
    device_key_types = ('ec-256', 'rsa-2048')           # optional: the form offers only these

    def device_csr(self, req):          # -> the CSR, PEM ("CERTIFICATE REQUEST")
        st, hd, d = self.req('POST', '/api/csr', {
            'common_name': req.subject.get('CN') or req.names[0],
            'alt_names': req.names,                     # every name, and only these
            'organization': req.subject.get('O') or self.c('org'),
            'key': {'ec-256': 'P256', 'rsa-2048': 'RSA2048'}[req.key_type],
            'slot': req.options.get('slot', 'https'),   # the deployment's own options
        }, what='asking the device for a new key and CSR')
        self.ctx.step('the device made a new %s key and a CSR' % req.key_type, 'ok')
        return d['csr']

    def deploy(self, bundle, options):  # bundle.key_pem is None: the certificate (+ chain) only
        self.req('POST', '/api/certificate', {'certificate': bundle.cert_pem,
                                              'chain': ''.join(bundle.chain_pems)},
                 what='importing the certificate')
        return 'imported the certificate for the device\'s own key'
```

`req` is a `CertRequest` with `names` (DNS names and IP addresses; the first the usual common
name), `sans` (with the `email:` / `uri:` ones of the profile), `subject` (`{'CN', 'O', 'OU',
'C', 'ST', 'L', 'emailAddress'}` as the certificate's profile says - `CN` always there),
`key_type` (`ec-256 ec-384 rsa-2048 rsa-3072 rsa-4096`), `options` (the deployment's options
of this certificate on this target, opened as `deploy()` gets them), `name` and `cert_id` (the
certificate in acme), `target` (the target's name). The context is the target's (`self.ctx`,
the same kv state as `deploy()`); `self.c()` reads the target's settings.

What acme does with it (acmelib/certs/devicekey.py):

- A certificate says where its key is made: `certs.csr_from` = the target's name (the form's
  *Key made by the device*, `acme --cert-add NAME --names ... --csr-from TARGET`). Its
  deployment to that target is made with it.
- **At every issue and renewal** `device_csr()` is called - a **new** key each time (never the
  one before: there is no "keep the key"). acme checks the CSR: signed by its key, **every name
  of the certificate in it and no other** (DNS/IP subjectAltNames, or the common name when it
  has none); for an ACME source the common name must be one of the names. The subject of the
  certificate is the profile's where the source sets it (acme's authority does). The
  certificate issued is checked to be for the CSR's key (`pub_sha256`).
- **Right after the issue**, in the same job, the deployment runs: `deploy(bundle, options)`
  with `bundle.key_pem` `None` - put the certificate (and the chain, where the device takes it)
  in place for the key it made a moment ago. When the deployments are held (*Deploy now*), the
  device keeps its old certificate, and the next issue asks it for a new key and CSR.
- Such a certificate goes to **that target only**, has no twin (`key_type_alt`), no
  `reuse_key`, no key to export; and a `device_key` target takes **no other certificate** -
  `deploy_save` refuses both in words.

Rules for the module:

- Raise `PluginError` in words a person can act on - a missing privilege, a key type the
  device cannot make (`retry=False`), a name it will not put into its CSR.
- Give every name the device can take; a device that takes only one host name must say so
  (refuse more than one name in `device_csr()` - the check after it would refuse the CSR
  anyway, less clearly).
- Do not import anything in `device_csr()`: making the CSR is all. A device that drops its
  pending key when asked for a CSR a second time is fine - acme asks once per issue (an issue
  not finished, a request a source holds, uses the CSR it got again) and deploys right after.
- Make the key type asked (`req.key_type`, one of `device_key_types`): a CSR with another key,
  or a weak one (RSA under 2048 bits), is refused.
- `deploy()` must work with no key; refuse a bundle that has one (`bundle.key_pem` set) with
  words saying to let the device make the key - it cannot use acme's.
- `served_wait` / `served_places` as for any target (a device that switches to the new
  certificate after minutes says how long).
- What happens records `device_csr()` in its sandbox like any other call: what the module
  sends is shown, and the sandbox answers with a CSR for the names (a throwaway key).

The reference module is `acmelib/plugins/targets/lenovo_xcc.py` (Redfish `GenerateCSR` and
`ReplaceCertificate`, a version for Lenovo's OEM service); its tests
`test/test_targets_lenovo_xcc.py` check the exact calls against a fake Redfish, and
`test/test_device_key.py` the whole flow with a fake device.

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


**What happens** runs a source, validation or target in a sandbox that reaches
nothing and writes down what it does: through the Context (`ctx.http`,
`ctx.ssh`, `ctx.run_local`, files) every call whole; and what a module does on
its own - `http.client` / `urllib` requests whole, `ftplib` commands and
uploads, UDP datagrams to the byte, a TCP connection's address (what is said
on it cannot be told). Secrets are stand-ins there and left out of what is
shown. Use the Context where you can: its calls are what the plan shows best.

**What happens** shows a test from its settings - it only reads, nothing is
recorded. A test that speaks a protocol before TLS says what it sends in
`talk(self, host, sni)`: a list of `{'send': 'EHLO …'}` (a line of text),
`{'send_hex': bytes.hex(), 'what': 'SSLRequest'}` (bytes) and `{'wait': 'the
greeting 220'}`, in order; built from the same functions `served()` sends with,
so the two cannot part (test/test_checks_protocols.py holds each shipped one to
it). A test that starts with TLS returns `[]` (the default).
## Versions, overrides and the page Modules

### Where modules come from, and which one wins

acme loads modules from three places, in this order - **a later one wins**:

| | where | kept |
|---|---|---|
| 1. shipped | `acmelib/plugins/` of the installation | the package |
| 2. your own on the disk | `/etc/acme/plugins/<issuers\|challenges\|targets\|checks>/` (`ACME_PLUGINS`) | the disk of each node; listed (with their text) in the database |
| 3. uploaded | Settings → **Modules** → *Upload* | the database (`meta` `module-file:<folder>/<file>`); each node writes them into `/var/lib/acme/plugins-uploaded/` itself (`ACME_STATE`) and loads them |

Within one folder the files are read by name. A module is its **kind and its
version** (`kind`, `module_version`):

* **another version** - a `module_version` its kind does not have yet - is
  added beside the others; each source, validation, target or test chooses in
  its form which one it uses, nothing changes until one does;
* **the same kind and version** as one loaded before **replaces it** - an
  override: a file in `/etc/acme/plugins` replaces the shipped one, an upload
  replaces both. The page tags it *override* and still lists the shipped
  original under it (*replaced - not used*, its code to download); taken away,
  the shipped one is used again - it is never deleted;
* a kind no module has is a module of its own.

A form that names no version takes the **default version**: the one chosen
on Settings → Modules → the module → *Make it the default* (kept in the
database, `meta` `module-default:<family>/<kind>` - both nodes, every backup;
*As the code says* takes it away), else the one with `default_version = True`
(yours before the shipped ones), else the plain one (`''`), else the first by
name. The page says first how many name no version - they follow it.
`POST /api/modules/default {family, kind, version | null}` does the same.

*Upload it* needs no version typed: a file says its own (`module_version`);
the version typed is only for *Start from a template*. Once checked, the file is
named by its kind and version (`netscaler_14_1.py`, `netscaler_override.py`) -
the same version uploaded again replaces it - unless a name was typed.

**Kept, in a cluster and in backups.** An uploaded module is in the database:
on both nodes of a cluster by itself (each writes it within ~20 s), in every
copy and backup of the database, back with it after a restore - nothing to do
by hand. A file in `/etc/acme/plugins` is on the disk of the node it was put
on, and only there: it is **never run from the database**. acme keeps a list
of these files with their text in the database (`meta` `custom-modules:<node>`,
written by each node when its page Modules is opened, at every copy of the
database and every backup it makes), and the page warns when the nodes do
not have the same files. Root writes one node's files into this node's folder
with

```bash
acme --plugins-sync NODE
```

(`--plugins-sync NODE --remove`: files here that NODE does not have go too),
then `systemctl restart acme`. That is how a second node gets them - after it
joins a cluster, after either node is set up again. A full backup (Settings →
Backups) has the `.py` files of `/etc/acme/plugins` in `plugins/` and puts them
back there on the machine it is restored on; the README and `examples/` are not
in it (install.sh writes them). In a cluster, prefer uploading: one place, both
nodes, every backup.

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
each; *Download this code* gives the source of any of them. A shipped module
you replaced is still listed, under your replacement, as *shipped original -
replaced, not used* - its own *Download this code* gives the shipped code, not
yours; it is used again once your replacement is taken away. *Make one of your
own* has two ways: *another version beside it* (named - its version and label;
as many as you need) and *replace the shipped one*. Each *Download a start*
asks first: *only a start* (a few lines that subclass the module and change
what you write - it follows the module when acme is updated) or *the whole code
of a version* - any of them, the shipped original too - its class already
saying the version you named (`module_version`, `version_label`,
`default_version = False`; for a replacement the shipped version). Another
module of the same file (`tls.py` holds `tls` and `https`) is imported from
where it is, not defined again, so the copy adds or replaces only the one
asked for. `GET /api/modules/source?family=&kind=&version=&has_version=1
&copy=1&as_version=&as_label=[&override=1][&original=1]` does the same from a
script. *Upload a module* takes a `.py` file - checked first in a process of its own (it must
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

## A setup guide for the other side

Every module - each version of it, an override, one of your own - has a **setup guide**: Markdown
saying how to set up the device, service, DNS provider or CA for acme (its account and least
rights, the commands, what goes into acme's fields). Forms, target and test windows and the page
*Modules* show it read-only in a window over almost the whole page (button *Setup guide*); a full
administrator writes it over on the page *Modules* (*Edit the guide*). Put commands in a fenced
block (```` ```sh ````, ```` ```text ````): the guide shown gives each block a *Copy* button, and a
click on `code` in the text copies it.

Where the text comes from - the first that has one, for the language asked, then English:

1. **written on the page** - kept in the database (`meta guide:<family>:<kind>@<version>:<lang>`),
   so on both nodes of a cluster, in every backup and in the configuration file
   (`config export` / `import`, key `guides`); *Back to the default* takes it away again;
2. **the module itself** - a class attribute `guide` / `guide_cs` (Markdown), or a file beside a
   module of your own: `mine.py` → `mine.md` and `mine.cs.md`;
3. **shipped with acme** - `acmelib/plugins/guides/<folder>/<kind>@<version>[.cs].md`, then
   `<kind>[.cs].md` (one text for every version with the same steps);
4. **made from the module** - its title, description and fields as a table.

```python
class Mine(LocalTarget):
    kind = 'mine'
    title = 'Mine'
    guide = """# Mine - setup for acme

1. Make an account `acme` with the right to import certificates.
2. Fill in acme: *Address*, *User*, *Password*.
"""
```

The editor has a **Visual** mode (edited like a document, no Markdown needed), **Markdown**, side
by side and a preview. Its assistant puts parts of a guide in (an outline with the module's
fields filled in, steps, commands, a warning, a tip, a table) and starts from another text:
acme's own text of the version, the other language, another version of the module. HTML pasted
in (from a web page or a document) is turned into Markdown. Links may be `https://`, `http://`,
`mailto:` or `#` only; nothing of the text runs as HTML.

    GET  /api/modules/guide?family=target&kind=fortigate&version=7.4.2&lang=cs
    POST /api/modules/guide {family, kind, version, lang, md}   (md '' gives it back)
    GET  /api/modules/guides                                    (the ones written on the page)

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
