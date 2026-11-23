# The command line of the certificate manager

What the pages can do, the command line can do too. Each of these options runs
the same API route the pages use, in this process, as `command line` (a full
administrator), so the checks, the events and the words are the same.
Renewals, deployments, tests and a module's actions run here and now, and
their steps are printed as they come. `--json` answers JSON instead of tables
(every option below). `--no-color` turns colour off.

The pages copy the command that makes an object - the right button on its row, *Copy ▸ As a
CLI command* ([context-menu.md](context-menu.md)) - with every secret as `KEY=-`.

`acme --help` lists every option, including the engine's own; the certificate
manager's are in the groups **CERTIFICATES**, **CERTIFICATES: SOURCES,
VALIDATIONS AND TARGETS**, **CERTIFICATES: DEPLOYMENTS**, **CERTIFICATES:
AUTHORITIES OF ACME'S OWN**, **CERTIFICATES: ACME'S OWN DNS SERVER**, **DNS SETS**,
**OWNERS AND TAGS**, **CERTIFICATES: SEARCH, THE EXPIRY CALENDAR, PROFILES FROM A
TEMPLATE**, **TARGET AGENTS: WHAT THEY DEPLOY, WHERE THEIR KEYS ARE MADE**, **REPORTS AND
DIGESTS** and **HISTORY AND TRASH, REQUEST PROFILES, THE AGENT FLEET, THE GOVERNANCE OF
TEAMS**.

The exit code is 0 when things went well and 1 when a job, a test or an
action failed, so these options can be used from scripts. Something that
deletes or revokes asks first on a terminal; `--yes` says yes ahead (a script
without a terminal needs it).

One thing is asked at a time (1.0.79): `--set` beside another option (`acme
--local-policy --set ...`, `acme --certs --set ...`) is refused - it was
dropped without a word. An option that names something given an empty value
(`--cert-del ""`) is refused with that said, and an option that only goes
with another one, given alone (`--hosts x`, `--limit 40`), says so in one
line instead of printing the whole help. Beside an option that does not read it
(`--selfsigned X --owner T`, `--ca-create X --parent CA`, `--tag-add T
--description ..`, `--team-add T --caps ..`), `--owner`, `--parent`, `--description`,
`--caps`, `--strip`, `--members`, `--policy` and the other team options are refused
with the options they go with, nothing done (1.0.127); so is `--set` beside
`--selfsigned`, `--import`, `--check-names`, `--cert-check`, `--dry-run`. A thing that is not there is said
before anything is asked (`--team-del`, `--tag-del`, `--dns-set-del`,
`--ssh-token-del`, `--downgrade FILE`).

`--api METHOD PATH BODY` takes no secret written out in BODY: a field any
module or directory keeps sealed (`bind_pw`, `eab_hmac`, `service_account`,
`sas`, ...) is refused there - the body then comes through stdin (`--api POST
PATH -`). Routes that hand a file to a browser (`/api/db/download`) are not
run through it: `acme --backup` makes a copy and says where.

Root's SSH keys (1.0.108) have no option of their own: `acme --api GET
/api/sshkeys` lists them as *Settings → SSH keys* does, and a change of them
through `--api POST /api/sshkeys` is refused as it is on the pages - root
changes `/root/.ssh/authorized_keys` on the server itself. A normal user's keys
are changed the same way as on the pages (`{"action": "uk_make", "user":
"falco", "scope": "all"}`; a body with a private key through stdin). See
[SSH keys](ssh-keys.md).

The private half of an SSH key (`--target-key NAME private`, and the same for
validations and tests) is written with `--out FILE` (0600) or printed with
`--out -` - not to the screen unasked.

`--status --json` and `--check --json` say `"ok"` as their exit code does.

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

A server a secret is sent to (the mail server of `smtp_password`, the proxy of
`proxy_password`, ...) is changed together with the secret, in the same
command: `acme --set smtp_port=2525 --set smtp_password=-`. The console asks
for the secret in the same window.

A needed field (and one only needed when another says so - `show_if`) is
asked for when it is missing. Changing one (`--source-edit`, ...) keeps every
other setting as it is.

## Certificates

| | |
|---|---|
| `acme --certs [--search TEXT] [--owner TEAM] [--issuer SOURCE]` | every certificate: state, days left, end, issuer, deployments, names; `--owner`, `--issuer` only those of that team, from that source (the list's filters) |
| `acme --cert NAME` | one certificate: its details, versions, deployments and last jobs |
| `acme --cert-add NAME --names a.example.com,b.example.com [--issuer X] [--challenge Y] [--key-type ec-256] [--key-type-alt rsa-2048] [--csr-from TARGET] [--set ...]` | a certificate to keep, renewed by itself. Without `--issuer`: the default source (**LetsEncrypt**), and for an ACME CA without `--challenge` the default validation (**This server HTTP-01**). The renewer issues it at its next look, or `--renew NAME` issues it now |
| `acme --cert-edit NAME [--names ...] [--issuer X] [--challenge Y] [--key-type T] [--key-type-alt T\|none] [--csr-from TARGET\|none] [--name NEW] [--note TEXT] [--enabled on\|off] [--set ...]` | change it. `--set` takes `auto_renew`, `renew_days` (0: the setting's), `reuse_key`, `tags` (`tags+=x`), `owner`, `note`, `enabled`, `challenge_map.NAME=VALIDATION` (empty: taken out), `profile.KEY` (`profile.eku=serverAuth,clientAuth`, `profile.must_staple=yes`, `profile.days=90`, `profile.acme_profile=shortlived`, `profile.subject.O=Example`) |
| `acme --cert-del NAME [--yes]` | delete it with its versions and deployments (the devices keep what they have) |
| `acme --cert-del NAME --revoke-first [--reason R] [--yes]` | revoke it where it was issued (reason `cessationOfOperation` when not said), then delete it - in one job, followed. A revocation that fails deletes nothing: the certificate is kept as "revocation failed" (`--cert-keep NAME`, or `--cert-del` again) |
| `acme --cert-keep NAME` | keep a certificate whose revocation (to delete it) failed: back to valid (or expired), renewed by itself again |
| `acme --approve NAME [--why TEXT]` | approve a certificate asked for on the portal: it is issued now (the job followed), the person who asked is told. Not one you asked for yourself |
| `acme --decline NAME --why TEXT` | decline one asked for on the portal; `--why` is required - the person who asked is told it |
| `acme --renew NAME` | renew it now, due or not |
| `acme --renew all [--force]` | every certificate that is due. With `--force`, every one acme can renew |
| `acme --deploy NAME` | run every enabled deployment of it now (forced: put in place even when unchanged); a hold (`--deploy-hold`) ends |
| `acme --deploy-hold NAME on\|off` | on: a new certificate of it is issued and kept, not deployed until `--deploy NAME`; off: deployed by itself again |
| `acme --revoke NAME [--reason R] [--reissue] [--yes]` | revoke it where it was issued. Reasons: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn`. Refused, as on the pages, for one acme cannot revoke (imported, from before a move of its source, self-signed, being revoked now). `--reissue`: a new one issued at once in its place (a new key, whatever "keep the key" says), deployed where the revoked one is |
| `acme --csr NAME [--out FILE] [--force]` | a request (CSR) for an authority acme does not speak to: printed (or written to FILE). The key waits in acme. `--force`: a new request (a new key) |
| `acme --csr-answer NAME FILE [--force]` | the certificate that authority sent back for it: kept as a new version, then deployed. One that lacks a name of the certificate is refused (`--force` takes it anyway) |
| `acme --import FILE [--name N \| --into CERT] [--password] [--owner TEAM] [--note TEXT]` | a certificate from a file: PEM, DER, PFX/P12, P7B, JKS, or a ZIP of them; `--owner`, `--note` of the new one (not with `--into`); `--into CERT` makes it a new version of a certificate kept here (its names, deployments and tests stay). `--password` asks for the file's password (or reads `ACME_FILE_PASSWORD`, or one line of stdin) |
| `acme --export NAME --format F --out FILE [--password] [--variant main\|alt]` | the certificate into a file (`--out -` writes it to stdout); of a dual certificate (`--key-type-alt`: a twin of the same names with another key type) `--variant alt` exports its twin. Formats: `cert-pem`, `cert-der`, `chain-pem`, `fullchain-pem`, `p7b`, `key-pem`, `key-rsa`, `key-der`, `combined-pem`, `pfx`, `p12`, `p12-legacy`, `jks`. PFX, P12 and JKS need `--password`. The file is written with mode 0600 |
| `acme --selfsigned NAME --names a,b [--key-type T] [--days N]` | a self-signed certificate, made now. A `self-signed` source is made the first time it is needed |
| `acme --run-plan NAME` | *What happens* of the page: everything a renewal of it would do, step by step - the key and the request, the source (each call to the CA), each name's validation, each deployment (the files, the commands, the calls), the tests, who is told and when it comes again - worked out without doing any of it (nothing is changed or contacted; the modules are recorded in a process that can reach nothing). Steps marked *Only the first time* / *Only at later renewals*, *the answer decides* where the device or the CA decides what follows (1.0.141) |
| `acme --inspect FILE\|- [--password]` | *Show a certificate* of the page: what a file holds - certificates, a chain and how it links, a CSR, a CRL, keys (what they are and which certificate each belongs to, never the key), PFX/P12, P7B, JKS, a ZIP of them. Nothing is kept or contacted. `--password` asks for the file's password (or `ACME_FILE_PASSWORD`; an encrypted key's own in `ACME_KEY_PASSWORD`); exit 1 when it stays locked (1.0.141) |
| `acme --jobs [--limit N]` | the jobs, newest first |
| `acme --job ID` | one job and every step. While it runs, it is followed until it ends (Ctrl-C leaves it running). The exit code is 0 when the job went well |
| `acme --job-stop ID` | stop a job that runs (on either node) |
| `acme --acme-contact MAIL [--force]` | the contact e-mail of the ACME sources that have none (with `--force`: of every one). The CA mails about expiry and policy changes there; certificates are issued without one too |
| `acme --status` | includes the certificates, which node renews them, and the DNS server |
| `acme --hand` | what waits for a person on every node (To be done by hand) with its id, and Done lately |
| `acme --hand-done ID@NODE` | a step that cannot be checked written down as done |
| `acme --hand-clear` | Done lately emptied - what is still to be done stays |

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
| `acme --target-key NAME make\|show\|public\|own FILE\|private\|forget\|try` | the SSH key a target signs in with, as the key card of the page (isemon's): `make [ed25519\|rsa4096]` a new pair made here (the private half sealed, never shown), `show` its fingerprint and public half, `public` / `private` the half as a file (`--out`; the private one written into Events), `own FILE` a private key of your own (its passphrase from `ACME_KEY_PASSWORD`, checked), `forget` (`--yes`), `try` a sign-in that changes nothing, step by step. `--validation-key` the same for a validation over SSH |
| `acme --source-discover NAME [--set ...] [--fill]` | find its settings from the account (read-only): the module signs in and reads what its API tells - lists to choose from (products, organisations, zones, partitions…), contacts, ids - shown beside what is set. `--fill` saves the found values into the settings that are empty (a list: the value picked, if any); nothing set is replaced. `-` with `--kind KIND --set ...`: for one not saved yet (nothing can be filled then). A module that finds nothing says so; `acme --plugin KIND` says whether it has it and what it asks |
| `acme --source-action NAME ACTION` | one of the things its module can do besides its work (`acme --plugin KIND` lists them) - e.g. `acme --validation-action web prepare` writes the nginx server block for HTTP-01 on every web server of an `http_ssh` validation |
| `acme --plugins` | the modules: issuers, challenges, targets, where each comes from (shipped, your own, an *OVERRIDE*), its versions (`*` the default), its actions, and those that did not load; then the modules of your own on this node and whether the other nodes have the same |
| `acme --plugins-sync NODE [--remove] [--yes]` | write the modules of your own that NODE keeps in the database into this node's `ACME_PLUGINS` folder (root) - after a copy was put back, or to make a second node the same; `--remove` also takes away files NODE does not have. Uploaded modules need none of this |
| `acme --module-mark family/kind[@version] tested\|works\|problem\|none [--note TEXT]` | mark how far a version of a module is checked (a full administrator's; shown on Settings → Modules and beside the module) |
| `acme --tests` · `--check-add NAME --kind KIND --set ...` · `--check-edit` · `--check-show` · `--check-del` · `--check-test` | the tests of what the servers serve, defined as targets are ([checks.md](checks.md)); `--check-key` the SSH key of a connector |
| `acme --check-attach CERT TEST...` · `--check-detach ID` | attach tests to a certificate, take one off |
| `acme --checks [CERT]` | the tests attached to the certificates (to one): each with its last result |
| `acme --check-run ID\|cert:NAME\|test:NAME\|all` | run attached tests now, each result said; exit code 1 when one fails. A test switched off (on Tests or for its certificate) or of a certificate switched off is run only when named by its ID (1.0.77) |
| `... --report-to ADDR[,ADDR]\|alerts` · `--sms-to NUM[,NUM]` | with `--check-run`: the report of them by mail (`alerts`: to the alerts' addresses) and / or one line by SMS, as *Run the tests…* of the page (1.0.77) |
| `acme --check-after ID any\|-\|TARGET[,TARGET]` | after which deployments an attached test runs: any, none (`-`, by its schedule only), or these targets of its certificate (1.0.77) |
| `acme --check-switch ID on\|off` | an attached test switched off (or on) for its certificate only (1.0.77) |
| `acme --module-marks-export` | the marks set here as `acmelib/plugins/verified.json` takes them - what a release ships as checked |
| `acme --plugin KIND` | one module: its description, every field (`--set` takes), a target's deployment options, its actions. `source/KIND`, `validation/KIND` or `target/KIND` where two families have the kind |

(`--validation-...`, `--target-...` and `--check-...` are the same as `--source-...`; a target
is tried with `--target-test`.)

**The agent of a target** "Server with acme-agent" ([target-agent.md](target-agent.md)):
`acme --target-agent NAME show|system|code|confirm FP|look|policy|renew|update|forget|design
show|text|forget|discover [cached] [--kind K,K]|adcs-templates [HOST\CA]`; `acme --target-agent
waiting`; the company enrollment codes `acme --target-agent enroll new [--title TEXT] [--mode
passive|active] [--port N] [--days N] [--most N] [--auto-confirm] [--owner TEAM]`, `enroll list`,
`enroll revoke ID`; `acme --target-agent all update`.

## Deployments

| | |
|---|---|
| `acme --deploys [CERT]` | every deployment (of one certificate): its target, state, the version there, options (secrets as `(set)`), the last error |
| `acme --deploy-add CERT TARGET [--set KEY=VALUE ...] [--enabled off]` | put CERT on TARGET from now on, with the target module's deployment options (`acme --plugin KIND`) |
| `acme --deploy-edit ID [--set ...] [--enabled on\|off] [--note TEXT]` | change one; its options not said stay |
| `acme --deploy-del ID [--yes]` | take one away (the device keeps what it has) |
| `acme --deploy-run ID` | run that one now (forced) |
| `acme --deploy-preview ID [--set KEY=VALUE ...]` | what it would write - each file with its path, format, mode, owner, size and whether it holds the key - the script after them and the `ACME_*` variables it is given (a password as dots), with what is wrong; worked out by the target's module, nothing sent. `--set`: with these options over its own, nothing saved (the form of the page as it is typed). Exit 1 when a problem would stop it (1.0.141) |
| `acme --deploy-dry-run ID [--set KEY=VALUE ...]` | the page's test of a deployment: signed in, the files made and written into a temporary folder on the target (not their places), the script run there with `ACME_DRY_RUN=1`, the folder deleted - nothing is reloaded or restarted. The steps said, exit 1 when it failed (a certificate administrator may test only the script and commands saved) (1.0.141) |

## Target agents: what they deploy, where their keys are made (1.0.140)

As Settings → Target agents and the policy builder ([target-agent.md](target-agent.md) *What the
agent deploys*, *Where keys are made*):

| | |
|---|---|
| `acme --agent-guard TARGET [--json]` | what the agent of TARGET checks of what it deploys (`allow issuer`, `allow names`, `require key local` of its policy, as it last said it), whether the agent knows these lines, and each deployment there judged by them as acme judges it before sending (exit code 1 when one would be refused) |
| `acme --agent-cas [TARGET] [--json]` | the CAs acme knows - its own authorities, every CA in its certificates' chains - with their SHA-256: what `acme-agent allow issuer sha256=HEX` names (TARGET: the ones of its certificates first) |
| `acme --agent-keys [TARGET] [--json]` | for each target with an agent: the certificates deployed there with the key made on the server, with acme's key, which could switch and why the others cannot, those waiting for their next renewal; `require key local` of its policy |
| `acme --agent-keys-switch CERT... [--now] [--yes]` | "Switch to a key made on the server": each certificate's key made by the agent of the one target it is deployed to - from its next renewal on (a day before it is due), or `--now`: switched and renewed now. Each one that cannot is said; exit code 1 then |
| `acme --agent-keys-cancel CERT...` | a switch waiting for the next renewal taken back |

On the server, as root (the agent's own command line): `acme-agent allow issuer CA.pem` (or
`sha256=HEX`), `acme-agent allow names NAME...` (added to the names allowed; `deny names NAME`
takes them away), `acme-agent require key local` (`require key any` takes it away).

## Authorities of acme's own

| | |
|---|---|
| `acme --cas` | the authorities, each under the one that signed it |
| `acme --ca-show CA` | one authority, where it is published on acme (the URLs, the last CRL, its next update) and what it signed (`--limit`) |
| `acme --ca-create NAME --subject "CN=Example Root CA,O=Example" [--key-type ec-384] [--days 3650] [--set ...]` | a new root authority. `--set crl_days=7 crl_url=... aia_url=... ocsp_url=... path_len=0 name_constraints=example.com` |
| `acme --ca-sub NAME --parent CA [--subject ...] [--key-type ec-256] [--days 1825] [--set ...]` | a new intermediate, signed by CA |
| `acme --ca-import FILE [--key FILE] [--name N] [--password]` | an authority from a file (PEM or PFX with its key, or the key in a file of its own; its password in `ACME_KEY_PASSWORD`) |
| `acme --ca-revoke CA SERIAL [--reason R] [--yes]` | revoke what it signed; its CRL is made anew at once with it. Reasons: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold` (`privilegeWithdrawn` is refused: openssl cannot put it into a CRL) |
| `acme --ca-unrevoke CA SERIAL` | release a certificate it put on hold (`--ca-revoke ... --reason certificateHold`): valid again, its CRL made anew without it. Any other reason cannot be taken back |
| `acme --ca-crl CA [--out FILE]` | a new CRL, printed (or written) |
| `acme --ca-export CA --what FORMAT --out FILE [--password]` | `cert`, `cert-der`, `chain`, `crl`, `crl-der`, `p7b`, `bundle`, `csr`, `key`, `p12` (the key and the P12 into a file only, mode 0600; a P12 asks for its password) |
| `acme --ca-sign CA --csr FILE [--days N] [--set eku=serverAuth,clientAuth] [--out FILE]` | a certificate for a CSR from elsewhere |
| `acme --ca-del CA [--yes]` | delete an authority no source signs with (when it was the default, there is none then) |
| `acme --ca-default CA` | make it the default authority: offered first for a new own-CA source and for signing a CSR (`none`: no default). One that cannot sign (no certificate yet, no key, switched off, run out) is refused |
| `acme --ca-publish CA on\|off` | its CRL and certificate published on acme at `/pki/` (port 80, every node and the VIP address), or not ([own-ca.md](own-ca.md#publishing-on-acme)) |
| `acme --ca-pki-urls CA` | acme's own `/pki/` addresses put into what it signs from now on (CRL and CA certificate); what it signed before keeps its addresses |
| `acme --ca-pki-check CA` | its published CRL and certificate fetched over HTTP from here and checked with openssl (the issuer, the signature, nextUpdate in the future); exit code 0 when right |
| `acme --ca-edit CA --set KEY=VALUE …` | change what is not inside its certificate: `name`, `days_default`, `crl_days`, `crl_url` / `aia_url` (`own`: acme's own) / `ocsp_url` (for what it signs from now on), `note`, `disabled=yes\|no`, `eku` ([own-ca.md](own-ca.md#changing-an-authority)) |
| `acme --ca-renew CA [--days N] [--path-len N\|none] [--name-constraints LIST\|none]` | its certificate made again with the same key and subject; what it signed stays valid. Under a CA elsewhere: prints the request |
| `acme --ca-install-cert CA FILE` | the certificate a CA elsewhere signed for it (its first, or a renewal's answer) |
| `acme --ca-versions CA` | every certificate it has had: serial, dates, SHA-256, path length |

## acme's own DNS server

| | |
|---|---|
| `acme --dns-records` | its zone, whether it listens, the queries asked here, every record |
| `acme --dns-add NAME TYPE VALUE [--ttl S] [--note TEXT]` | a record of your own (`@`: the zone itself). Types: A, AAAA, TXT, CNAME, MX, NS, CAA, SRV, PTR |
| `acme --dns-del ID` · `acme --dns-del NAME [TYPE [VALUE]] [--yes]` | take records away (more than one: `--yes`) |

## DNS sets (Settings → DNS)

Which DNS servers each function of acme asks - [dns-sets.md](dns-sets.md).

| | |
|---|---|
| `acme --dns-sets` | every set ("The system's" first), and the set each function asks and why |
| `acme --dns-set-add NAME --servers ADDR,ADDR [--protocol udp\|tcp\|dot] [--tls-name NAME] [--dns-timeout S] [--note TEXT]` | a new set (ADDR: `192.0.2.53`, `192.0.2.53:5353`, `[2001:db8::53]:53`) |
| `acme --dns-set-edit NAME [--servers ...] [--name NEW] ...` | change one; the functions that ask it follow a new name |
| `acme --dns-set-del NAME [--yes]` | delete one; the functions it was chosen for go back to their default |
| `acme --dns-set-test NAME QNAME [TYPE]` | a name looked up through a set: every server, what it said, how long it took; exit code 0 when one answered |
| `acme --dns-assign FUNCTION SET` | `validation`, `public`, `apis`, `targets`, `acme` or `mail` asks SET (`default`: its default) |

## Owners, teams and tags (Settings → Owners and teams)

Who certificates belong to, what their members may do, and the tags - [teams.md](teams.md).

| | |
|---|---|
| `acme --teams [--json]` | the owners with their members and rights, the tags, and what certificates say that is not defined |
| `acme --team-add NAME [--team-kind team\|person] [--members 'local:jan=manage,group:Web=view+request'] [--contact-mail ADDR] [--note TEXT]` | a new owner (a member without `=rights`: view+request) |
| `acme --team-edit NAME [--name NEW] [--members ...] [--contact-mail ...]` | change one; renamed, its certificates follow; `--note ''` / `--description ''` take them away |
| `acme --team-edit NAME --members '[{"who": "CN=PKI,OU=Groups,DC=example,DC=com", "roles": ["Viewer"], "until": "2026-12-31 18:00", "note": "..."}, "group:Web"]'` | the members as a JSON list (anything starting with `[`): what the simple form cannot say - a DN, a role with `+` or `,` in its name, a member's note, an end at an exact time (`until`: an epoch, `YYYY-MM-DD` the end of that day, `YYYY-MM-DD HH:MM`); a word alone is a `who` with view+request (docs/teams.md) |
| `acme --team-show NAME [--json]` | one owner whole: its members with their roles, ends and notes, its limits (`--teams` cuts those columns at 48 characters) |
| `acme --team-del NAME [--reassign OTHER\|-] [--yes]` | delete one; owning certificates only with `--reassign` |
| `acme --tag-add TAG [--colour dim\|info\|ok\|warn\|crit\|violet] [--note TEXT]` · `acme --tag-del TAG [--strip]` | the tags of the catalog |
| `acme --teams-adopt` | owners and tags made from what certificates say now |
| `acme --team-add NAME [--parent TEAM] [--team-kind unit] [--description TEXT] [--policy JSON]` · `acme --team-edit NAME [--parent TEAM\|-] [--policy '{}'] [--members 'group:Web=Requester+Deployer,local:jan=manage@2026-12-31']` | enterprise teams (1.0.125): the tree, the team's limits, members with roles and an end |
| `acme --team-del NAME --parent TEAM\|- [--yes]` | delete one with teams below it: they move under TEAM (`-` the top level) |
| `acme --roles [--json]` · `acme --role-add NAME --caps cert.view,cert.renew [--description TEXT]` · `acme --role-del NAME [--strip] [--yes]` | the roles and their capabilities; a role of your own |
| `acme --team-access WHO [--json]` | what a person (`local:NAME`, a user of the directory) may in which team, why, and the limits in force |
| `acme --team-activity NAME [--below] [--limit N] [--json]` | what happened in the team, newest first (`--below`: the teams below it too) |
| `acme --teams-from-groups FILTER [--member-role ROLE] [--parent TEAM] [--team-kind team\|unit] [--yes]` | a team of each directory group whose name fits (`PKI-*`), the group its member as ROLE (Viewer): shown first, made with `--yes`; `--group DN\|NAME` (again for more) adds groups picked from the directory, `FILTER` `-` takes only those |
| `acme --target-add NAME --kind KIND ... --owner TEAM` · `acme --target-edit NAME --owner TEAM\|-` | a team's device (`-`: acme's own again) |
| `acme --target-agent enroll new --owner TEAM [...]` | a team's enrollment code: the servers enrolling with it become that team's targets |

## Reports and digests (1.0.140)

Settings → Reports and a team's Digest ([reports.md](reports.md),
[teams.md](teams.md#the-digest-by-mail-t12-10140)); each with `--json`:

| | |
|---|---|
| `acme --reports` | the reports defined: kind, scope, formats, schedule, recipients, the last run |
| `acme --report-show NAME [--report-lang cs\|en]` | one: its settings, what it says now (its tiles and first rows), its runs |
| `acme --report-add NAME --report-kind inventory\|expiry\|compliance\|agents\|access [--report-teams T1,T2\|-] [--report-formats csv,pdf] [--report-every off\|weekly\|monthly --report-day N --report-hour H] [--report-recipients A,B\|-] [--report-lang cs\|en\|-] [--report-keep N] [--report-days N] [--report-off yes\|no]` | a new report (`--report-days`: the expiry outlook's days ahead) |
| `acme --report-edit NAME [the same] [--report-name NEW]` | change one |
| `acme --report-del NAME [--yes]` | delete it and its runs |
| `acme --report-run NAME [--report-send] [--report-out DIR]` | made now and kept; `--report-send` mails it to its recipients; `--report-out` saves its files there |
| `acme --report-runs NAME` | its runs kept |
| `acme --report-get RUN --report-format csv\|pdf --report-out FILE\|-` | a run's file (`-`: standard output) |
| `acme --team-digest TEAM` | the team's digest: on or off, when, to whom, the last one |
| `acme --team-digest-set TEAM [--digest on\|off] [--digest-every weekly\|daily] [--digest-day 1-7] [--digest-hour H] [--digest-days N] [--digest-contact yes\|no] [--digest-members W1,W2\|-] [--digest-skip-empty yes\|no] [--digest-below yes\|no] [--digest-lang cs\|en\|-]` | set it |
| `acme --team-digest-preview TEAM [--digest-lang cs\|en] [--report-out FILE.html] [--digest-mail ADDR]` | what it says now (its text; the HTML into a file; a preview mailed to ADDR) - nothing else sent |
| `acme --team-digest-send TEAM [--yes]` | to its recipients now |

## Search, the expiry calendar, profiles from a template (1.0.140)

What Ctrl+K finds, when certificates run out ([expiry-calendar.md](expiry-calendar.md)) and request
profiles from a template ([request-profiles.md](request-profiles.md) "From a template"):

| | |
|---|---|
| `acme --find TEXT [--limit N] [--json]` | certificates by name, SAN or serial, deployments, targets, agents, sources, authorities, validations, tests, request profiles, teams, accounts and the events of the last 30 days (`--limit` of each kind, 20 at most); exit 1 when nothing is found |
| `acme --calendar [--from YYYY-MM-DD] [--weeks N] [--team TEAM] [--issuer SOURCE] [--target TARGET] [--json]` | what runs out and what acme renews, week by week (13 weeks), then each certificate |
| `acme --calendar-ics FILE\|- [--lang cs] [the same filters]` | the same as an iCalendar file (104 weeks) |
| `acme --calendar-feeds [--json]` · `acme --calendar-feed-revoke WHO\|all [--yes]` | who has a link to subscribe to their calendar; take one (or all) back |
| `acme --profile-templates [--json]` | the templates of request profiles: what each sets, whether it complies, the sources that fit |
| `acme --profile-from-template ID --name NAME --names DOMAIN,DOMAIN [--issuer SOURCE] [--challenge VALIDATION] [--note DESCRIPTION] [--json]` | a new request profile from the template ID (`web`, `mail`, `vpn`, `internal`, `wildcard`, `codesign`); a name taken is refused |

`--from`, `--weeks`, `--team`, `--target` go only with `--calendar` and `--calendar-ics`, `--lang`
only with `--calendar-ics`; beside another option they are refused, nothing done.

## History and trash, request profiles, the agent fleet, the governance of teams (1.0.138)

What 1.0.138 added to the pages has its options too (since 1.0.140, `acmelib/certs/cli_138.py`)
- each runs the page's own route as `command line`, a full administrator; `--json` answers
JSON. What deletes, restores or changes many asks first (`--yes`).

**History and trash** ([history-and-trash.md](history-and-trash.md)):

| | |
|---|---|
| `acme --history [--limit N]` | the latest changes of everything: the entry, when, what, its name, created / changed / deleted, by whom, the fields |
| `acme --history TYPE NAME` | one object's history, field by field (TYPE: `cert`, `target`, `source`, `validation`, `test`, `deploy`, `check`, `profile`, `team`, `role`, `tag`, `dnsset`, `dnsrecord`) |
| `acme --history-restore ENTRY [--yes]` | that version saved again by its own route - what changes is said first |
| `acme --trash` | what was deleted and can be restored (30 days), with what went with it |
| `acme --trash-restore ID [--name NEW]` | brought back, with what went with it (under another name when its name is taken) |
| `acme --trash-purge ID\|all [--yes]` | gone for good |

Since 1.0.140 what `--team-*`, `--tag-*`, `--role-*` and `--dns-set-*` change is in the history
and what they delete in the trash, as on the pages (they were left out), and `acme --api GET
/api/history`, `/api/trash` answer (*the pages have no ...* before).

**Request profiles** ([request-profiles.md](request-profiles.md)) - made on the command line
from a template (above) or `acme --api POST /api/reqprofiles/save -` with the body on stdin:

| | |
|---|---|
| `acme --profiles` | every request profile: on the portal, its source, its base, its version, whether it ends (and its successor), how many certificates were asked for from it, what is wrong |
| `acme --profile-show NAME` | one whole |
| `acme --profile-versions NAME` | its versions: who, when, what changed and why, the certificates asked for from each |
| `acme --profile-diff NAME A [B]` | two versions field by field (B left out: as it is now) |
| `acme --profile-restore NAME N [--yes]` | as version N said - saved as a new version |
| `acme --profile-compliance [YYYY-MM-DD]` | every profile and certificate against the CA/Browser Forum's schedule and the company's rules (on a day to come); exit 1 when one does not comply |
| `acme --profile-dry-run NAME --names D,D` | what it would issue - the subject, names, key, usages, validity, source, whether it waits - or each reason it would refuse; nothing is issued; exit 1 when refused |
| `acme --profile-end NAME SUCCESSOR [--note TEXT] [--yes]` | it ends: the certificates asked for from it said first (moves or stays), they take the successor's settings at their next renewal; `acme --profile-end NAME -`: it no longer ends |
| `acme --profile-del NAME [--yes]` | deleted (to the trash); what was asked for from it stays |

**The agent fleet** ([agent-fleet.md](agent-fleet.md)):

| | |
|---|---|
| `acme --fleet` | every agent: kind, version, health and why, its groups, its template and drift; the groups; the update rollout; how many certificates found are not managed |
| `acme --fleet-unmanaged` | the certificates found on the servers acme does not manage, the most urgent first |
| `acme --fleet-takeover TARGET SERVICE [--issuer SOURCE] [--yes]` | take one over: what is made and the policy lines it needs said first, then the certificate and its deployment made (`acme --renew NAME` issues it) |
| `acme --fleet-templates` | the policy templates, built in and your own |
| `acme --fleet-assign TEMPLATE\|- AGENT...` | the template these agents follow (`-`: none of their own) |
| `acme --fleet-drift [AGENT...]` | each agent's policy against its template: the lines missing on the server, those there besides; exit 1 when one differs |
| `acme --fleet-group-save NAME [--fleet-members A,B\|-] [--fleet-template REF\|-] [--fleet-canary yes\|no]` · `acme --fleet-group-del NAME` | a group made, changed, deleted |
| `acme --fleet-ask AGENT...\|all` · `acme --fleet-update AGENT...\|all` | asked now / updated, a job followed here |
| `acme --fleet-rollout plan [GROUP]` · `start [GROUP] [--rollout-wait MIN] [--yes]` · `continue` · `stop` · `forget` | an update in rings: the canary ring first - GROUP, or as on the page the group marked the canary ring, or (none marked, or GROUP `-`) 5 % of the agents - then the rest after the wait |

**Watching an agent** ([target-agent.md](target-agent.md)) - beside `--target-agent NAME`:
`watch` (the audit chain, anomalies, what it serves, its keys and their age), `watch-set
audit=on|off anomaly=on|off health=on|off rotate=on|off rotate_days=N`, `audit-verify` (exit 1
when the chain does not agree), `ack audit|anomaly`, `rotate [command|seal|both] [--yes]`,
`served` (exit 1 when a service still serves the old certificate); `acme --target-agent all keys`
(every key's age) and `acme --target-agent all keys-rotate [--yes]` (a new command key).

**The governance of teams** ([teams.md](teams.md) "Governance"):

| | |
|---|---|
| `acme --team-health [TEAM]` | every team's health (running out, expired, failed renewals and deployments, outside its limits, weak keys) and one score |
| `acme --team-gov TEAM` | its access reviews, temporary roles, separation of duties, channels - its own and those in force from above |
| `acme --team-gov-set TEAM JSON\|-` | changed: `{"review": {"every_days": 90, "answer_days": 14, "action": "report"}, "jit": {"roles": ["Requester"], "max_hours": 8}, "sod": {"no_self_approval": true, "exclusive": [["Requester", "Approver"]]}, "notify": {"mail": "web@example.com", "oncall_mail": "..."}}` - a key `null`: off; the members already holding both sides of a pair are said |
| `acme --team-notify-test TEAM` | every channel tried now; exit 1 when one failed |
| `acme --who-may WHO` · `acme --who-may team:NAME` | a person against every capability in every team, each with why (role, right, inherited, temporary, until when) - or a team's people |
| `acme --who-can CAP TEAM\|cert:NAME` | who may CAP (`cert.key`, `cert.renew`...) there, and why |
| `acme --elevations [TEAM]` · `--elevation-approve ID [--why TEXT]` · `--elevation-decline ID --why TEXT` · `--elevation-end ID` | the requests for a temporary role (the command line never asks for one) |
| `acme --reviews [TEAM]` · `--review-open TEAM` · `--review-answer ID WHO keep\|out [--note TEXT]` | access reviews |
| `acme --team-templates` · `--team-template-save TEAM NAME [--template-members]` · `--team-from-template TEMPLATE NAME [--parent TEAM]` · `--team-template-del NAME [--yes]` | the templates of teams: a team saved as one (its kind, limits, contact addresses and governance, never a secret; `--template-members`: its members too), a team made from one, one deleted (the teams made from it stay) |
| `acme --teams-import-csv FILE\|- [--yes]` | teams from a CSV file: each row said first (new, there already, wrong), then made |

A team's webhooks are kept sealed: `acme --api POST /api/teams/hooks -` with the body on stdin.
*View as* is a sign-in of the pages and the saved views are the pages' lists - neither has a
command line.

## Signing in with Windows - Kerberos (1.0.99)

The engine's own options (group **WHAT THE PAGES DO, HERE TOO**), as the card on *Settings →
Accounts* and *Settings → The enrolment pages* ([kerberos-sso.md](kerberos-sso.md)):

| | |
|---|---|
| `--kerberos` | each part (the administration, the portal) on or off, its realm and where it comes from, its directory, by itself or a button, "no password at all", the sign-in page (a password, Windows and a certificate - a button, at once or off); the keytab's principals, key versions and kinds of key (never a key); the names the pages are opened by with their SPN; each node - heard from, the keytab written out, the Kerberos library there (`--json` too) |
| `--kerberos-keytab FILE` | put in the keytab of the service account (as `ktpass` made it) - for both parts; every node writes it out itself within seconds |
| `--kerberos-keytab-off` | take it away (asks; `--yes`) |
| `--set admin_krb=1`, `--set portal_krb=1` | each part's switch; `admin_krb_auto`, `admin_krb_realm`, `portal_krb_auto`, `portal_krb_realm` the same way |
| `--set admin_password_off=0`, `--set portal_password_off=0` | root's way back from "no password at all" (one switch of Windows and the certificate). Switching it **on** is refused here: only somebody signed in with Windows or a certificate to that part switches it on, on the pages |

## Signing in with a certificate - a smart card, a YubiKey (1.0.100)

As the card on *Settings → Accounts* and *Settings → The enrolment pages*
([certificate-sign-in.md](certificate-sign-in.md)):

| | |
|---|---|
| `--cert-login` | each part on or off, its directory, how a certificate is matched, revocation, "no password at all", the sign-in page (a password, Windows and a certificate - a button, at once or off); the port; the authorities (subject, issuer, valid to, SHA-256); the CRLs fetched; each node - heard from, the authorities written out, nginx listening on the port (`--json` too) |
| `--cert-login-ca FILE` | put in authorities (the issuing one and its root; PEM, DER or `.p7b`) - a person's certificate is refused; every node writes them out itself |
| `--cert-login-ca-off SHA256` | take one away, by its SHA-256 or the first 12 characters of it or more (asks; `--yes`) |
| `--cert-login-crl` | the CRLs, as the card's table: each address, base or delta, its issuer, number, this and next update, the revoked entries, size, the signature (checked by openssl against the authorities put in), each node's fetch and last error; those the authorities name and not fetched yet too (`--json`) |
| `--cert-login-crl-fetch [URL]` | Fetch now: every CRL (or the one at URL) fetched again on every node, each itself - each node's answer waited for (a minute at most); exit 1 when one could not be fetched. A failed fetch loosens nothing: the last good CRL until its next update |
| `--cert-login-crl-clear [URL]` | Clear: every node forgets its CRLs (all of them: asks; `--yes`) or the one at URL - the next sign-in fetches them again |
| `--cert-login-ocsp` | the OCSP answers each node keeps, as the card's table *Online status (OCSP)*: the certificate, its issuer and serial, the status (good, revoked with its time and reason, unknown, no answer, run out, the last answer kept), the responder and who signed its answer, this and next update, the last error, each node's (`--json`: `{ocsp: {admin, portal}, answers}`) |
| `--cert-login-ocsp-fetch [KEY]` | Ask again: every responder (or the one answer of KEY, as `--json` says it) asked again on every node, each itself - each node's answer waited for (a minute at most); exit 1 when one did not answer. A failed asking loosens nothing: the last good answer until its next update |
| `--cert-login-ocsp-clear [KEY]` | Clear: every node forgets its OCSP answers (all of them: asks; `--yes`) or the one of KEY - the next sign-in asks again |
| `--set admin_certlogin=1`, `--set portal_certlogin=1` | each part's switch; `certlogin_port`, `admin_certlogin_match`, `admin_certlogin_crl`, `portal_certlogin_match`, `portal_certlogin_crl` the same way; how revocation is checked besides the CRL (1.0.105): `admin_certlogin_ocsp` (off, first, only, both), `admin_certlogin_ocsp_url` (an http address, the guards of a CRL's), `admin_certlogin_crl_ldap` (0/1), and the portal's `portal_...` |
| `--set admin_password_off=0`, `--set portal_password_off=0` | the way back from "no password at all - only Windows or a certificate"; switched **on** only from the pages, by somebody signed in with Windows or a certificate |

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
