# The command line of the certificate manager

What the pages can do, the command line can do too. Each of these options runs
the same API route the pages use, in this process, as `command line` (a full
administrator), so the checks, the events and the words are the same.
Renewals, deployments, tests and a module's actions run here and now, and
their steps are printed as they come. `--json` answers JSON instead of tables
(every option below). `--no-color` turns colour off.

`acme --help` lists every option, including the engine's own; the certificate
manager's are in the groups **CERTIFICATES**, **CERTIFICATES: SOURCES,
VALIDATIONS AND TARGETS**, **CERTIFICATES: DEPLOYMENTS**, **CERTIFICATES:
AUTHORITIES OF ACME'S OWN** and **CERTIFICATES: ACME'S OWN DNS SERVER**.

The exit code is 0 when things went well and 1 when a job, a test or an
action failed, so these options can be used from scripts. Something that
deletes or revokes asks first on a terminal; `--yes` says yes ahead (a script
without a terminal needs it).

## Settings of a module: `--set KEY=VALUE`

Sources, validations, targets and deployments are modules (`acme --plugins`),
each with its own settings - `acme --plugin KIND` lists them: the key, the
type, whether it is needed, the default, when it is shown, and its help. The
same `--set` the engine's settings use gives them, again for each one, and
each is checked against the module's own fields before anything is saved:

| | |
|---|---|
| `KEY=VALUE` | text, a number (`number`), on/off (`bool`: yes/no, on/off, 1/0), one of the choices (`select` - a wrong one is refused with the list) |
| `KEY=a,b,c` | a list (one a line on the pages); with a line break in VALUE, one a line |
| `KEY+=VALUE` / `KEY-=VALUE` | one more in a list / one taken out of it |
| `KEY=-` | a **secret** (a password, a token, a key's passphrase): asked for on the terminal (twice), or one line of stdin, or `ACME_VALUE_KEY` from the environment. A secret written out on the command line is refused: `ps` and the shell's history would keep it. It is never shown again in clear: eight dots and its last two characters |
| `KEY=@env` | from `ACME_VALUE_KEY` (what the console passes) |
| `KEY=@file:PATH` | the contents of a file - a PEM, a private key |
| `KEY=` | empty; for a secret: keep the one that is set |

A needed field (and one only needed when another says so - `show_if`) is
asked for when it is missing. Changing one (`--source-edit`, ...) keeps every
other setting as it is.

## Certificates

| | |
|---|---|
| `acme --certs [--search TEXT]` | every certificate: state, days left, end, issuer, deployments, names |
| `acme --cert NAME` | one certificate: its details, versions, deployments and last jobs |
| `acme --cert-add NAME --names a.example.com,b.example.com [--issuer X] [--challenge Y] [--key-type ec-256] [--set ...]` | a certificate to keep, renewed by itself. Without `--issuer`: the default source (**LetsEncrypt**), and for an ACME CA without `--challenge` the default validation (**This server HTTP-01**). The renewer issues it at its next look, or `--renew NAME` issues it now |
| `acme --cert-edit NAME [--names ...] [--issuer X] [--challenge Y] [--key-type T] [--name NEW] [--note TEXT] [--enabled on\|off] [--set ...]` | change it. `--set` takes `auto_renew`, `renew_days` (0: the setting's), `reuse_key`, `tags` (`tags+=x`), `owner`, `note`, `enabled`, `challenge_map.NAME=VALIDATION` (empty: taken out), `profile.KEY` (`profile.eku=serverAuth,clientAuth`, `profile.must_staple=yes`, `profile.days=90`, `profile.acme_profile=shortlived`, `profile.subject.O=Example`) |
| `acme --cert-del NAME [--yes]` | delete it with its versions and deployments (the devices keep what they have) |
| `acme --renew NAME` | renew it now, due or not |
| `acme --renew all [--force]` | every certificate that is due. With `--force`, every one acme can renew |
| `acme --deploy NAME` | run every enabled deployment of it now (forced: put in place even when unchanged) |
| `acme --revoke NAME [--reason R] [--yes]` | revoke it where it was issued. Reasons: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn` |
| `acme --csr NAME [--out FILE] [--force]` | a request (CSR) for an authority acme does not speak to: printed (or written to FILE). The key waits in acme. `--force`: a new request (a new key) |
| `acme --csr-answer NAME FILE` | the certificate that authority sent back for it: kept as a new version, then deployed |
| `acme --import FILE [--name N] [--password]` | a certificate from a file: PEM, DER, PFX/P12, P7B, JKS, or a ZIP of them. `--password` asks for the file's password (or reads `ACME_FILE_PASSWORD`, or one line of stdin) |
| `acme --export NAME --format F --out FILE [--password]` | the certificate into a file (`--out -` writes it to stdout). Formats: `cert-pem`, `cert-der`, `chain-pem`, `fullchain-pem`, `p7b`, `key-pem`, `key-rsa`, `key-der`, `combined-pem`, `pfx`, `p12`, `p12-legacy`, `jks`. PFX, P12 and JKS need `--password`. The file is written with mode 0600 |
| `acme --selfsigned NAME --names a,b [--key-type T] [--days N]` | a self-signed certificate, made now. A `self-signed` source is made the first time it is needed |
| `acme --jobs [--limit N]` | the jobs, newest first |
| `acme --job ID` | one job and every step. While it runs, it is followed until it ends (Ctrl-C leaves it running). The exit code is 0 when the job went well |
| `acme --job-stop ID` | stop a job that runs (on either node) |
| `acme --acme-contact MAIL [--force]` | the contact e-mail of the ACME sources that have none (with `--force`: of every one). The CA mails about expiry and policy changes there; certificates are issued without one too |
| `acme --status` | includes the certificates, which node renews them, and the DNS server |

## Sources, validations, targets

The same options for each of the three: **source** (where certificates come
from, `cert_issuers`), **validation** (how names are proved, `cert_challenges`),
**target** (where certificates go, `cert_targets`).

| | |
|---|---|
| `acme --sources` · `--validations` · `--targets` | the list; `*` marks the default (what a new certificate takes; for targets: offered first for a new deployment) |
| `acme --source-default NAME` · `--validation-default NAME` · `--target-default NAME` | make it the default of its list (`none`: no default). A switched-off one is refused; deleting the default leaves none; renaming it keeps it the default. Written to the events |
| `acme --source-show NAME` | one: every setting (a secret: eight dots and its last two characters), what uses it, its last test, its actions, whether it is the default. `--target-show` also lists the target's deployments; `--validation-show` of HTTP-01 answered here (`http_local`) also says how it works on this installation: the URL the CA fetches, the nodes and the VIP address that answer it, port 80 in their firewall, and every name that uses it with what it resolves to (✔ one of acme's addresses, ✘ elsewhere) |
| `acme --validation-check NAME HOST` | HTTP-01 answered here: a probe token put in place and fetched at `http://HOST/.well-known/acme-challenge/` from this node, step by step (exit code 0 when it answers). Behind NAT, a router that does not loop back to its own public address (hairpin NAT) fails here although the CA from outside is answered |
| `acme --check-names N1,N2,... [--issuer X] [--challenge Y]` | before a certificate: its names grouped by DNS zone, each name's validation chosen as the renewer would (the default when none is said), each step of what it needs checked now ✔ / ✘ / ? with where it is set, what to do and the exact record to create, and which other validations would do. Read-only; exit code 0 when nothing blocks; `--json` the plan ([validation.md](validation.md#before-the-first-certificate-what-acme-checks-and-tells-you)) |
| `acme --cert-check NAME` | the same for a certificate acme keeps (its names, source, validation and `challenge_map`) |
| `acme --dry-run NAME\|N1,N2 [--challenge Y]` | the validation tried for real without a CA: a test record or file put in place, waited for (`certs_dry_run_s`), looked for from outside (the zone's name servers, public resolvers; HTTP by the name and by each address) and taken away. A job (kind `dry-run`), followed; exit code 0 when it worked |
| `acme --source-add NAME --kind KIND --set KEY=VALUE ...` | a new one of that module (`acme --plugins`) |
| `acme --source-edit NAME [--set ...] [--name NEW] [--note TEXT] [--enabled on\|off] [--kind KIND]` | change it; what is not said stays. Another `--kind` starts its settings from nothing. A new name is carried into the certificates and deployments that use it |
| `acme --source-del NAME [--yes]` | delete one nothing uses |
| `acme --source-test NAME [--set ...]` | try it (reach the server, sign in, change nothing); `--set` tries it with those settings over its own, saving nothing. For a target: `acme --target-test NAME` |
| `acme --source-action NAME ACTION` | one of the things its module can do besides its work (`acme --plugin KIND` lists them) - e.g. `acme --validation-action web prepare` writes the nginx server block for HTTP-01 on every web server of an `http_ssh` validation |
| `acme --plugins` | the modules: issuers, challenges, targets, their actions, and those that did not load |
| `acme --plugin KIND` | one module: its description, every field (`--set` takes), a target's deployment options, its actions. `source/KIND`, `validation/KIND` or `target/KIND` where two families have the kind |

(`--validation-...` and `--target-...` are the same as `--source-...`.)

## Deployments

| | |
|---|---|
| `acme --deploys [CERT]` | every deployment (of one certificate): its target, state, the version there, options (secrets as `(set)`), the last error |
| `acme --deploy-add CERT TARGET [--set KEY=VALUE ...] [--enabled off]` | put CERT on TARGET from now on, with the target module's deployment options (`acme --plugin KIND`) |
| `acme --deploy-edit ID [--set ...] [--enabled on\|off] [--note TEXT]` | change one; its options not said stay |
| `acme --deploy-del ID [--yes]` | take one away (the device keeps what it has) |
| `acme --deploy-run ID` | run that one now (forced) |

## Authorities of acme's own

| | |
|---|---|
| `acme --cas` | the authorities, each under the one that signed it |
| `acme --ca-show CA` | one authority, where it is published on acme (the URLs, the last CRL, its next update) and what it signed (`--limit`) |
| `acme --ca-create NAME --subject "CN=Example Root CA,O=Example" [--key-type ec-384] [--days 3650] [--set ...]` | a new root authority. `--set crl_days=7 crl_url=... aia_url=... ocsp_url=... path_len=0 name_constraints=example.com` |
| `acme --ca-sub NAME --parent CA [--subject ...] [--key-type ec-256] [--days 1825] [--set ...]` | a new intermediate, signed by CA |
| `acme --ca-import FILE [--key FILE] [--name N] [--password]` | an authority from a file (PEM or PFX with its key, or the key in a file of its own; its password in `ACME_KEY_PASSWORD`) |
| `acme --ca-revoke CA SERIAL [--reason R] [--yes]` | revoke what it signed; in its next CRL |
| `acme --ca-crl CA [--out FILE]` | a new CRL, printed (or written) |
| `acme --ca-export CA --what FORMAT --out FILE [--password]` | `cert`, `cert-der`, `chain`, `crl`, `crl-der`, `p7b`, `bundle`, `csr`, `key`, `p12` (the key and the P12 into a file only, mode 0600; a P12 asks for its password) |
| `acme --ca-sign CA --csr FILE [--days N] [--set eku=serverAuth,clientAuth] [--out FILE]` | a certificate for a CSR from elsewhere |
| `acme --ca-del CA [--yes]` | delete an authority no source signs with (when it was the default, there is none then) |
| `acme --ca-default CA` | make it the default authority: offered first for a new own-CA source and for signing a CSR (`none`: no default). One that cannot sign (no certificate yet, no key, switched off, run out) is refused |
| `acme --ca-publish CA on\|off` | its CRL and certificate published on acme at `/pki/` (port 80, every node and the VIP address), or not ([own-ca.md](own-ca.md#publishing-on-acme)) |
| `acme --ca-pki-urls CA` | acme's own `/pki/` addresses put into what it signs from now on (CRL and CA certificate); what it signed before keeps its addresses |
| `acme --ca-pki-check CA` | its published CRL and certificate fetched over HTTP from here and checked with openssl (the issuer, the signature, nextUpdate in the future); exit code 0 when right |

## acme's own DNS server

| | |
|---|---|
| `acme --dns-records` | its zone, whether it listens, the queries asked here, every record |
| `acme --dns-add NAME TYPE VALUE [--ttl S] [--note TEXT]` | a record of your own (`@`: the zone itself). Types: A, AAAA, TXT, CNAME, MX, NS, CAA, SRV, PTR |
| `acme --dns-del ID` · `acme --dns-del NAME [TYPE [VALUE]] [--yes]` | take records away (more than one: `--yes`) |

## Examples

```
acme --sources
acme --acme-contact pki@example.com
acme --cert-add www --names www.example.com,example.com          # Let's Encrypt, HTTP-01 here
acme --cert-add wild --names '*.example.com' --challenge "acme's DNS server"
acme --renew www
acme --target-add web1 --kind ssh --set host=192.0.2.21 --set user=acme --set key=@file:/root/id_ed25519 --set trust_first=yes
acme --plugin ssh                                                  # what a deployment to it takes
acme --deploy-add www web1 --set "outputs=fullchain-pem /etc/nginx/tls/www.pem" --set "reload_cmd=systemctl reload nginx"
acme --deploy-run 1
acme --validation-add web --kind http_ssh --set hosts=web1.example.com,web2.example.com --set auth=password --set password=-
acme --validation-action web prepare
acme --target-add pages --kind appliance && acme --deploy-add www pages --set where=auto
acme --export www --format pfx --out /root/www.pfx --password
acme --import /root/old-portal.pfx --name portal --password
acme --ca-create "Example Root" --subject "CN=Example Root CA,O=Example"
acme --ca-sub "Example Issuing" --parent "Example Root" --set crl_url=http://pki.example.com/issuing.crl
acme --job 42
acme --certs --json | jq '.rows[] | select(.days_left < 14) | .name'
```

The console (`acme --console`) has the same things under **Certificates**, at
the top of its main menu - its forms are drawn from the same module fields.
