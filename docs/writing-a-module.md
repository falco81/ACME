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
  certificate there (profiles, listeners, paths, commands);

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
