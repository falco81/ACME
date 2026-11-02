# Proving names: the challenges

An ACME CA (Let's Encrypt) issues a certificate only for names acme proves it
controls - by **DNS-01** (a TXT record at `_acme-challenge.NAME`) or **HTTP-01**
(a file at `http://NAME/.well-known/acme-challenge/TOKEN`). A challenge
(Settings → Validations, `cert_challenges`) says how; a certificate may use a
different challenge per name (`challenge_map`).

acme itself never has to be reachable from the internet: for DNS-01 the
records go to a DNS server (acme's own - only its port 53 - or somebody
else's); for HTTP-01 the files go over SSH to the web servers the names
already point at.

Wildcards (`*.example.com`) can only be proved by DNS-01.

## The modules

| Kind | What it does | Needs |
|---|---|---|
| `dns_builtin` | TXT records in **acme's own DNS server** ([dns-server.md](dns-server.md)) | a zone delegated to acme; `_acme-challenge.NAME CNAME NAME.<zone>` once per name |
| `rfc2136` | **dynamic UPDATE with TSIG** (hmac-sha256/-512/-384/-224/-sha1/-md5) to BIND, Knot, PowerDNS, Windows DNS; zone found by SOA | the primary's address; a key allowed to change TXT |
| `cloudflare` | Cloudflare API | an API token (Zone:DNS:Edit, Zone:Read) |
| `powerdns` | PowerDNS Authoritative HTTP API | API URL and key |
| `route53` | Amazon Route 53 (SigV4 signed here) | access key with ListHostedZonesByName, ListResourceRecordSets, ChangeResourceRecordSets, GetChange |
| `azure_dns` | Azure DNS (OAuth2 client credentials) | an app registration with DNS Zone Contributor |
| `gcloud_dns` | Google Cloud DNS (service account JWT, RS256 by openssl) | a service account key (JSON) with dns.admin |
| `hetzner` | Hetzner Console/Cloud API zones, or the old dns.hetzner.com | API token |
| `digitalocean` | DigitalOcean Domains | personal access token |
| `ovh` | OVHcloud API | application key/secret, consumer key on /domain/zone/* |
| `desec` | [deSEC.io](https://desec.io) (dedyn.io names too); TTL raised to the domain's minimum (3600); waits 60 s more after both name servers have it (anycast) | an API token (a token policy limiting it to TXT at `_acme-challenge` is best) |
| `gandi` | Gandi LiveDNS v5 | a personal access token ("Manage domain name technical configurations") or an older API key |
| `linode` | Linode / Akamai Cloud Domains (API v4) | a personal access token, Domains Read/Write |
| `vultr` | Vultr DNS (API v2) | an API key, acme's address under Access Control |
| `porkbun` | Porkbun (API v3) | API key + secret, *API Access* on for each domain |
| `namecheap` | Namecheap XML API - **setHosts rewrites every record of the domain** (read-modify-write, see below) | API user + key, acme's public IP whitelisted |
| `godaddy` | GoDaddy Domains API v1 | API key + secret (production API only for qualifying accounts) |
| `dnsimple` | DNSimple API v2 | an account access token (a user token: the account ID too) |
| `ns1` | NS1 / IBM NS1 Connect | an API key with View and Manage zones |
| `bunny` | bunny.net DNS | the account's API key |
| `cloudns` | ClouDNS | an API user or sub-user (auth-id / sub-auth-id + password), acme's address allowed |
| `inwx` | INWX JSON-RPC (DomRobot); two-factor accounts by their TOTP secret | user + password (+ 2FA secret) |
| `transip` | TransIP API v6, the sign-in signed RSA-SHA512 by openssl | login + the key pair's private key |
| `netcup` | netcup CCP DNS API | customer number, API key, API password |
| `ionos` | IONOS Hosting DNS API | an API key (public prefix + secret) |
| `scaleway` | Scaleway Domains and DNS (v2beta1) | an API secret key with DomainsDNS access |
| `exoscale` | Exoscale DNS (API v2, EXO2-HMAC-SHA256 signed here) | API key + secret, a role with the DNS operations |
| `infoblox` | Infoblox NIOS WAPI | an admin with API access and rights on the zones; the Grid Master's CA |
| `technitium` | Technitium DNS Server HTTP API | an API token of a user with Modify on the zones |
| `he_net` | dns.he.net dynamic TXT update - **one value per name**, record made by hand | a dynamic key per record |
| `wedos` | WEDOS WAPI (JSON) | WAPI login + WAPI password, acme's IP allowed in WAPI |
| `active24` | Active24 REST API v2 (Websupport-group signing) | API key + secret |
| `websupport` | Websupport.sk / .cz REST API v1 (HMAC-SHA1 signed) | API key + secret |
| `subreg` | Subreg.cz / Gransy SOAP API (envelope written by hand) | API login + password, acme's IP allowed |
| `czechia` | CZECHIA.COM (ZONER) REST API; zone by SOA - no read call, so a dry run is the test | the account's API token |
| `loopia` | LoopiaAPI (XML-RPC); slow name servers | API user + password with the zone functions |
| `simply` | Simply.com (UnoEuro) API v2 | account number + API key (or a bearer key) |
| `hostingde` | hosting.de / http.net JSON API (zoneUpdate) | an API key with DNS rights |
| `domeneshop` | Domeneshop API v0 | API token + secret |
| `glesys` | GleSYS API (domain/*) | project (CL…) + API key |
| `mythic_beasts` | Mythic Beasts DNS API v2 (OAuth2 client credentials) | API key ID + secret |
| `infomaniak` | Infomaniak API v2 (zones) | an API token |
| `alidns` | Alibaba Cloud DNS (RPC, signature v1 HMAC-SHA1 here); TTL ≥ 600 on the free edition | RAM AccessKey with the alidns record actions |
| `tencentcloud` | Tencent Cloud DNSPod API 3.0 (TC3-HMAC-SHA256 here); TTL ≥ 600 on the free plan | CAM SecretId + SecretKey |
| `oci_dns` | Oracle Cloud Infrastructure DNS (OCI request signing, RSA by openssl) | tenancy, user, fingerprint, the API private key, region |
| `akamai_edgedns` | Akamai Edge DNS Zone Management v2 (EdgeGrid signed here) | an API client with DNS Zone Record Management READ-WRITE |
| `dnsmadeeasy` | DNS Made Easy V2.0 (HMAC-SHA1 of the date) | API key + secret |
| `gcore` | Gcore Managed DNS v2 (RRsets) | a permanent API token |
| `netlify` | Netlify DNS | a personal access token |
| `vercel` | Vercel DNS | an access token (+ team ID) |
| `namecom` | Name.com API v4; TTL ≥ 300 | user name + API token |
| `namesilo` | NameSilo API; TTL ≥ 3600, slow name servers | an API key |
| `dynu` | Dynu API v2 | an API key |
| `njalla` | Njalla JSON-RPC API | an API token |
| `dreamhost` | DreamHost DNS API | an API key with the dns-* functions |
| `duckdns` | Duck DNS - **one TXT value per name** (proved one after another) | the account's token; your own names by CNAME to a duckdns.org name |
| `webglobe` | Webglobe API (JWT sign-in; staging selectable); `txt-any` and `cname-any` for a commercial CA's DCV | login + an API key that allows acme's IP address |
| `acme_dns` | an [acme-dns](https://github.com/joohoi/acme-dns) server | account(s); `_acme-challenge.NAME CNAME <fulldomain>` once |
| `ssh_dns` | commands on the DNS server itself over SSH, straight into its zones: BIND (`nsupdate -l`, `nsupdate -k`, or the zone file + `rndc reload`), PowerDNS (`pdnsutil` or its HTTP API there), Knot (`knotc` transaction), NSD (zone file + `nsd-control reload`), dnsmasq (`txt-record`), Unbound (`local_data`), Windows DNS (PowerShell via OpenSSH), or your own commands; **Find out what runs there** reads the server (read-only) and fills the form in | an SSH account there (sudo optional) |
| `script` | a program on this machine (`present`/`cleanup`, dehydrated- or lego-style), `ACME_*` variables | the program |
| `dns_persist` | **dns-persist-01**: one TXT record at `_validation-persist.DOMAIN`, set once, names the ACME account - no record per order, wildcards and subdomains with `policy=wildcard`; a fallback validation while the CA does not offer it ([below](#a-record-set-once-dns-persist-01-dns_persist)) | an ACME source; the record put in your DNS once |
| `manual` | shows the record to put in by hand; waits until the zone's name servers have it (or until it is confirmed) | someone there |
| `http_local` | HTTP-01 answered by acme's own nginx on port 80 | the name pointing at acme, port 80 open |
| `http_ssh` | HTTP-01: the token file written over SSH on **every** web server the name points at | an SSH account on each, the nginx block below |
| `http_ftp` | HTTP-01: the token file uploaded over **FTPS, FTP or SFTP** into a web hosting's web root | the hosting's FTP or SFTP account |
| `http_s3` | HTTP-01: the token file uploaded to an **S3 or S3-compatible bucket** (SigV4) behind a static site or CDN | a key with PutObject, GetObject, DeleteObject |
| `http_azure_blob` | HTTP-01: the token file uploaded to **Azure Blob Storage** (`$web` static website or a container behind a CDN) | a SAS token or the account key |
| `http_webdav` | HTTP-01: the token file uploaded over **WebDAV** (PUT, MKCOL, DELETE) | a WebDAV user on the web root |

### Waiting for DNS

Every DNS-01 module (except `dns_builtin`, which asks acme's own server) waits
before the CA is told to look:

1. **Where the record goes.** `_acme-challenge.NAME` is looked up first; if it
   is a CNAME (a delegation to another zone - to acme-dns, to a zone at a
   provider with an API) the record is written where the CNAME ends, as the CA
   will follow it ("Follow a CNAME", on by default).
2. **The zone** comes from the provider (its zone list) or from the SOA.
3. **Seen by** (`propagation`): by default every name server of the zone (its NS
   records) is asked straight, without recursion, until each has the value - so
   no resolver caches "not there" in the meantime. `auth+public` then also
   asks public resolvers (Settings → DNS, *The public view*: the set "Public",
   1.1.1.1, 8.8.8.8, 9.9.9.9 - [dns-sets.md](dns-sets.md)); `resolvers` asks only the
   resolvers set; `none` asks nothing. When the name servers cannot be reached
   from acme (an outbound firewall), the resolvers are asked instead, and the
   job says so.
4. **Delay**: at least that many seconds after the record is put in.

The ACME issuer decides how long it waits in all (its own setting); the job
log says, server by server, what has been seen.

### Several orders at once

Every module adds its value next to values already at the name and takes only
its own away again, so `example.com` and `*.example.com` (one TXT name, two
values), or two renewals at once, do not take each other's records away.
(acme-dns keeps only the newest two values per account: give a certificate
with more names one account per name - the `accounts` field.)

## A record set once: dns-persist-01 (`dns_persist`)

[draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/)
(announced by Let's Encrypt in February 2026, planned for production in 2026;
offered by Google Trust Services - issuer domain `pki.goog` - since September 2026)
proves a domain with **one TXT record that stays**: it names the CA and the
ACME account allowed to issue, and nothing changes in DNS at an order - no
token, no DNS credentials in acme. At an order the authorization offers a
challenge of the type `dns-persist-01` carrying `issuer-domain-names`; acme
checks the record and answers the challenge with `{}`; the CA looks the record
up itself.

```
_validation-persist.example.com.  TXT  "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567; policy=wildcard"
```

| Part | Meaning |
|---|---|
| `letsencrypt.org` | the CA's issuer domain name - one of the challenge's `issuer-domain-names` (Let's Encrypt and its staging: `letsencrypt.org`) |
| `accounturi=` | the URL of the ACME account (required) - acme shows it, the account made where there is none yet |
| `policy=wildcard` | optional: the record also covers `*.example.com` and every name under the domain (`www.example.com`, `a.b.example.com`) |
| `persistUntil=` | optional: a Unix time after which the CA no longer takes the record |

The syntax is that of a CAA issuer value (RFC 8659): the domain name first,
then `; tag=value` parameters (tags without regard to case, unknown ones
ignored, no spaces inside a value). **Several TXT records may stand at the
name** - one for each account: Let's Encrypt and its staging have different
account URLs, so a source of each needs its own record, and other TXT records
there stay.

**Settings** of the validation: *Domains with the record* (where the record
stands; empty: each name's registered domain), *Cover subdomains and
wildcards* (`policy=wildcard`, on by default; off: a record at each name
itself and no wildcard), *Valid until* (`persistUntil`, a day or a Unix
time), *Fallback validation*, and under More the sources the record is for
(empty: every ACME source) and the CA's issuer domain name (empty:
`letsencrypt.org` for Let's Encrypt; for another CA what its challenge says).

**What to set**: the validation's page (Certificates → Validation → the
validation) shows the exact record for each ACME source, with a copy button
for the name, the type and the value; *Make the record* makes the ACME account
at the CA where the source has none yet (as the first order would). The
readiness guide of a certificate (the wizard, *Check*, the precheck before the
CA is asked) shows the record for the certificate's own source. On the
command line: `acme --validation-show NAME` prints it, `acme --validation-action
NAME record` makes the accounts and prints it.

**The check** (Test, the guide) looks the record up through Settings → DNS
(*Validation checks*, or the validation's own resolvers) at the name itself,
then at each domain above it up to the record's domain - a record above the
name counts only with `policy=wildcard` - and says exactly what is wrong: no
record, a record of another CA, a record that cannot be read (syntax), another
account URI, `policy=wildcard` missing for a wildcard or a name under the
domain, `persistUntil` run out (and when it runs out within 30 days).

**At an order**, for each authorization:

1. The CA offers `dns-persist-01` and the record is right: acme answers the
   challenge (`POST {}`), puts nothing in place, waits for nothing.
2. The CA offers it, the record is not right: the fallback proves the name and
   the job says what is wrong and the record to set (without a fallback the
   order fails with that).
3. The CA does not offer it (Let's Encrypt in production until it launches):
   the fallback validation proves the name, the job says *the CA does not
   offer dns-persist-01 yet - used FALLBACK*. Once the CA offers it, acme
   switches by itself - nothing to change.

When a CA was **first seen offering it** is kept in the validation's state,
per CA (its directory URL), and shown on its page: *offered by Let's Encrypt
since 2026-…*, or *not offered by Let's Encrypt yet - last looked …*. The real
orders are the probe; no order is made only to look - except *Look now
(staging)*, which orders at a **staging** CA only (nothing is issued, its
authorizations are deactivated again).

It works only with an ACME source that takes it (the `acme` module): any other
source - a commercial CA's DCV, AD CS - is told so when the validation is
chosen (it does not fit). An IP address cannot be proved by it.

### acme writes the record itself (1.0.21)

*Write the record through* picks one of the DNS validations acme already has
that writes TXT records which stay - Active24, Webglobe, Cloudflare, Route 53,
SSH DNS, RFC 2136… (a list of the validations, never typed; acme's own DNS
server, Duck DNS, acme-dns and the manual ones are not offered: their records
do not stay or are not in your zone). Empty: the record is set by hand, as
before. Its credentials stay in that validation and are never shown here.

| On the validation's page | What it does |
|---|---|
| *Check the records* | for each domain and ACME source: the record is **there**, **missing**, or holds **another value** (a record of this CA naming another account - the account changed, `policy` or `persistUntil` differ); *written by acme through …* where acme wrote it. Read-only. |
| *Write the records to DNS* | through that validation's `add_txt`: only what is missing or not right. A value acme wrote before (the account changed) is replaced - the new one written first, the old one taken away; **a record acme did not write is never touched**. A value written within the last hour and not seen in DNS yet is not written again. What was written - domain, name, value, the validation it went through, its handle - is kept in the validation's state. |
| *Take the records away* | asks first (in the page); removes exactly what acme wrote, through the validation that wrote it. |

*Domains with the record* empty: the domains of the certificates that use the
validation. Writing and taking away run as jobs (Certificates → Jobs, step by
step) and are said in the events; they need a full administrator (they change
your DNS) - checking is for a certificate administrator too. Both are
idempotent (looked up first), so on a replicated pair either node may run
them; what acme wrote is in the replicated database.

*Write it by itself when missing* (on by default, used only with a validation
chosen above): at an order, before a name's authorization is answered, a
missing or wrong record of this CA and account is written first (once per
order and domain); while the CA offers dns-persist-01 acme then waits up to
90 s for it to be seen, else the fallback proves the name this time. While the
CA does not offer it yet, the record is written all the same - ready for the
day it does. *What happens* (the run plan) shows the look-up and the write
through that validation.

**Deleting the validation** (*Take it away*) asks in a popup with *Also remove
its records from DNS* - ticked when acme wrote some: they are taken away
first, in a job, and if that fails nothing is deleted. On the command line:
`acme --validation-action NAME check_records | write_records | remove_records`.

## Before the first certificate: what acme checks and tells you

Every validation says, for one name, **what must be in place, where** - and
checks each piece now, without changing anything. That is its *guide*
(`Challenge.guide(name)` in `acmelib/plugins/base.py`). A *dry run*
(`Challenge.dry_run(name)`) then tries it for real, with no CA asked: a random
test value goes in through the module's own `present()`, acme waits for it
with `ready()` (at most `certs_dry_run_s`, 120 s), looks for it from outside,
and takes it away again with `cleanup()` - whatever happened.

A step of a guide has its words (`what`), where it is set (`where`: *your
DNS at firma.cz*, *acme*, *the web server 10.0.0.5*, *the DNS of example.net
(the parent zone)*), the exact record to create (`record`: name, type, value,
TTL), whether it is in place (`done`: yes, no, or *cannot tell from here*),
what was found (`said`) and what to do (`fix`). A step that is not in place
but is no reason not to ask the CA (a public resolver that still caches an
old answer) is marked as not blocking.

What each kind checks:

| Kind | The guide (read-only) | The dry run looks |
|---|---|---|
| `dns_builtin` | acme's DNS server answers for its zone; the zone is delegated to it (`NS` records in the parent zone, and glue `A`/`AAAA` for name servers inside the zone) reaching the addresses acme answers on (`dns_expose`: the VIP, the nodes, or both); `_acme-challenge.NAME. CNAME NAME.<zone>.` (or the fixed label) in the name's own DNS - asked of that zone's own name servers, so no cached "not there" fools it; the firewall lets UDP and TCP 53 in | the CNAME leads the CA to the test value; every name server of acme's zone answers it; public resolvers see it |
| `http_local` | a wildcard refused (DNS-01 only); `A`/`AAAA` of the name are acme's (the VIP or a node - or one of *Addresses in front of acme*, for a NAT or a proxy); TCP 80 let in by the firewall; a probe acme answers on port 80 fetched from each of its addresses (Host: NAME) and by the name | the test file at `http://NAME/` and at each of acme's addresses with `Host: NAME` |
| `http_ssh` | a wildcard refused; the name points at the web servers (or at *Load balancer in front*); acme signs in to each over SSH; each answers HTTP on the check port | the test file at `http://NAME/` and at each web server's address with `Host: NAME` |
| `http_ftp`, `http_s3`, `http_azure_blob`, `http_webdav` | a wildcard refused; signing in and the folder (read only); the name has an address and answers HTTP | the test file at `http://NAME/` (and at *Address the folder is served at*) |
| a DNS provider's API (`desec`, `wedos`, `cloudflare`, `route53`, ... every `ApiDns` and the other API modules) | the credentials work (the module's `test()`); `_acme-challenge.NAME`'s CNAME followed - the TXT record goes where it ends, and that zone must be at the provider; the provider holds the zone (else: add it there, or point `_acme-challenge.NAME` by CNAME into a zone that is); the internet asks that zone (no subzone delegated elsewhere, name servers there); how long acme waits (the TTL - deSEC: its minimum, 3600 s, and 60 s more for its anycast) | every name server of the zone answers the test value; public resolvers see it |
| `rfc2136` | the primary answers DNS; the zone is found; a trial UPDATE that changes nothing (a prerequisite only) is accepted with the key | as above |
| `acme_dns` | the server's `/health`; `_acme-challenge.NAME. CNAME <fulldomain>.` | as above |
| `manual` | the zone; while an order waits, the exact TXT record and whether every name server has it | as above |
| `script`, `ssh_dns` | the program / the SSH account (`test()`), the zone - and that only a dry run can tell | as above |

A module of your own gets a guide that says "a dry run tells" and the dry
run itself without writing anything: `dry_run()` uses its `present()`,
`ready()` and `cleanup()`. A DNS-01 module based on `DnsChallenge` (or an
HTTP-01 one on `HttpChallenge`) gets the outside checks too.

**Names from several domains.** One certificate may hold names of different
zones, each proved its own way (`challenge_map`). `acmelib/certs/readiness.py`
groups the names by the zone they are in (by its SOA; where DNS says nothing,
by the registrable domain, `co.uk` and `com.au` known), chooses each name's
validation exactly as the renewer does, and puts the guides together. For
every group it also says which validations would do: a DNS provider that
holds the zone (asked of its API, kept two minutes), acme's own DNS server,
HTTP-01 here when the names point at acme, HTTP-01 on the web servers when
they point there. A wildcard is DNS-01 only.

    acme --check-names firma.cz,www.firma.cz,*.firma.cz,firma.sk --challenge "acme's DNS server"
    acme --cert-check web          # a certificate acme keeps
    acme --dry-run web             # its validations tried for real (a job, followed)
    acme --dry-run shop.firma.co.uk --challenge "This server (HTTP-01)"

`--check-names` prints a group a domain, each step ✔ / ✘ / ?, under a ✘ what
to do and the exact record; exit code 0 when nothing blocks. `--json` gives
the plan as it is. A dry run is a job of its own (kind `dry-run`) in
Certificates → Jobs, its steps live.

Before the **first** certificate of a certificate (and after a renewal that
failed on its validation) the renewer runs the same check by itself, and
does not ask the CA while something blocks - [certificates.md](certificates.md#before-the-first-certificate-what-acme-checks-and-tells-you).

## What fits: a source and a validation

Not every validation can prove a name to every source. acme decides it in one
place, `acmelib/certs/compat.py`, and the same answer is given everywhere: the
wizard of a new certificate (and its edit) offers only what fits and greys
the rest with the reason, `POST /api/certs/save` refuses with 400 and the
words, `acme --cert-add` / `--cert-edit` and the portal's request refuse the
same way, the readiness plan shows it as a blocking step, and the renewer
fails in words instead of letting the CA refuse. `POST /api/certs/compat
{names, issuer, challenge, challenge_map, key_type, key_type_alt, profile}`
says it for the pages: `{fits, problems, source, names, validations, key_types,
twin}`.

**The vocabulary** (`base.PROOFS`). A source says which proofs prove a name to
it (`Issuer.proofs_for(config)`); a validation which it can put in place
(`Challenge.proofs_for(config)`, and `place_problem()` for a given record
name or path):

| Proof | What | Asked by |
|---|---|---|
| `acme-dns-01` | the ACME TXT record at `_acme-challenge.NAME` | ACME |
| `acme-http-01` | the ACME file `/.well-known/acme-challenge/TOKEN` | ACME |
| `txt-any` | a TXT record at any name, any value | DigiCert `dns-txt-token`, Sectigo/SSLmarket DNS |
| `cname-any` | a CNAME at any name, to anywhere | DigiCert `dns-cname-token`, Sectigo CNAME |
| `http-file-any` | a file at any path under `/.well-known/` | DigiCert `http-token`, Sectigo FILE |
| `email` | an e-mail a person approves | DigiCert/Sectigo e-mail DCV: no validation at all |

**What each validation can put in place:**

| Validation | Proofs |
|---|---|
| every DNS provider's API (`ApiDns`, `RecordApiDns`, `route53`, `azure_dns`, `gcloud_dns`, `hetzner`, `ovh`, `powerdns`, ...), `script`, `ssh_dns` | `acme-dns-01`, `txt-any` |
| `cloudflare`, `desec`, `rfc2136`, `manual` | `acme-dns-01`, `txt-any`, `cname-any` (their APIs write CNAMEs; `manual` says the record) |
| `dns_builtin` (acme's own DNS server) | `acme-dns-01`; `txt-any` / `cname-any` **only for names inside acme's own zones** (delegated to it) - a commercial CA's `_dnsauth.NAME` sits in your DNS, where acme's server cannot write |
| `acme_dns`, `duckdns` | `acme-dns-01` only (one TXT value at their own name) |
| `http_local` | `acme-http-01`, `http-file-any` (under `/.well-known/pki-validation/`: nginx sends that path to `acme.php` too, the file kept 30 days in acme's database) |
| `http_ssh` | `acme-http-01`, `http-file-any` when its folder ends in `/.well-known/acme-challenge` (the file goes beside it; *Prepare the hosts* serves `/.well-known/pki-validation/` too) |
| `http_ftp`, `http_s3`, `http_azure_blob`, `http_webdav` | `acme-http-01`, `http-file-any` (uploaded under the same folder) |

**The other rules:**

* a **wildcard** only by a DNS proof (`acme-dns-01`, `txt-any`, `cname-any`);
  an **IP address** only by an HTTP one, and only from a source that takes
  addresses (`ip_names`; Let's Encrypt only in its `shortlived` profile -
  letsencrypt.org/docs/profiles);
* a **publicly trusted CA** (ACME presets, DigiCert, SSLmarket, GlobalSign)
  takes only fully qualified names under a public suffix: no single label
  (`intranet`, `a`), nothing under `.local`, `.internal`, `.lan`,
  `.home.arpa`, `.localhost`, `.test`, `.invalid`, `.example`, `.corp`,
  `.home`, ... and no private address. An authority of your own, self-signed,
  AD CS, SCEP, EST, an ACME server of your own (*Another ACME server*) take
  any;
* the **common name** of a public CA is one of the names (at most 64
  characters); e-mail and URI subjectAltNames only from a source that puts
  them in (your own authority, self-signed, AD CS...);
* the **key type** one the source signs (`Issuer.key_types_for`: SCEP RSA
  only; AD CS as its template's *Key types the template takes*; a public CA no
  Ed25519); the **twin** of a dual certificate only from a source that gives
  one.

A module of your own declares it the same way: an issuer `dcv` / `dcv_field`
(its DCV methods and the proof each needs), `public_names`, `key_types`,
`san_types`, `cn_free`; a challenge `proofs` and `place()` / `placed_ready()` /
`unplace()` (base.py says how). A module that says nothing keeps its ACME
types (`types`) and is refused for anything else.

## DNS providers with an API

What every one of them does the same way:

* **The zone** is the one set (*Zone* / *Domain*), else the longest of the
  zones the credentials may see that the name is in (`www.dev.example.com`
  goes to `dev.example.com` when the account has both). netcup and
  dns.he.net cannot list zones: netcup is asked name by name, dns.he.net
  goes by the SOA.
* **Several values at one name**: our value is added next to the ones there,
  and cleanup removes only ours. Where the API keeps a whole RRset (deSEC,
  Gandi, GoDaddy, NS1, Namecheap) it is read, changed and written back, one
  change at a time on this node. Removing a value that is gone already is
  not an error.
* **Kind to the provider** (1.0.21, for every module, source and target -
  `acmelib/plugins/limits.py`): **one sign-in per validation and its
  settings** - the token (Webglobe's JWT, an OAuth token of Azure / Google /
  Mythic Beasts, a TransIP token, a netcup or INWX session) is kept for its
  lifetime and shared by every job and check with the same settings, one
  sign-in at a time; a 401 signs in once more. A refused sign-in is not tried
  again for a minute (a wrong key is not hammered into a lock-out). The list
  of zones / domains and the Test of a validation are **asked once** for a
  little while (45 s / 30 s) - a readiness check of six certificates on one
  Webglobe validation signs in once, and *Check again* right after asks
  nothing again. **Every host** gets two requests at once and four a second
  at most, whatever runs in parallel (renewals, `certs_parallel`, readiness);
  loopback is not limited. A `429`, a `503` or a refusal saying *Too Many
  Attempts* / *rate limit* is **waited out** - as long as its `Retry-After`
  says (seconds or a date), else 2, 4, 8 s with a little jitter - and an
  idempotent call (GET, PUT, DELETE) is asked again at most twice; the host
  is then left alone for that long by every job (a longer wait: *not asked
  again before HH:MM*), and the job says so in words. Let's Encrypt's
  documented limits - 10 new accounts and 300 new orders in 3 hours - are
  kept before asking.
* **Test** signs in and lists the zones (or reads the zone set) - it never
  changes a record.
* **Seen**: as every DNS-01 module, by the zone's own name servers (above).

Where acme knows an API less well than it would like, the module's own
docstring (`acmelib/plugins/challenges/<kind>.py`) says which part, and so
does this page.

### deSEC (`desec`)

desec.io → *Token management* → **+**. Best with a *token policy*: write
access to type `TXT` at subname `_acme-challenge` (and the names below it)
only, and the addresses acme calls from. A `dedyn.io` name is a domain of the
account like any other. deSEC takes no TTL under the domain's *minimum TTL*
(3600 s for most accounts): a lower one is raised. Its name servers are
anycast: once both have the record acme waits *Wait after it is seen* (60 s)
more, so the CA's other vantage points see it too. The API is
`https://desec.io/api/v1/domains/{domain}/rrsets/` (`Authorization: Token`),
the same acme uses for its own certificates (Settings → ACME → deSEC).

```
token: (the token)      zone: example.dedyn.io (or empty)
```

### Gandi (`gandi`)

admin.gandi.net → *Organizations* → yours → *Sharing* → *Personal Access
Tokens* → *Create a token*: the domains acme may change, permission **Manage
domain name technical configurations**. An older API key works too (*Signs in
with: an API key*). LiveDNS v5; TTL at least 300.

### Linode (`linode`)

cloud.linode.com → your name → *API Tokens* → *Create a Personal Access
Token*: **Domains: Read/Write**, everything else *No Access*.

### Vultr (`vultr`)

my.vultr.com → *Account* → *API* → *Enable API*. Under *Access Control* add
the address acme reaches the internet from - Vultr refuses the key from any
other. Vultr keeps TXT values in quotes; acme sends them so.

### Porkbun (`porkbun`)

porkbun.com → *Account* → *API Access* → *Create API Key* (key `pk1_…`,
secret `sk1_…`). Then for **each domain**: *Domain Management* → the domain →
*Details* → *API Access* **on** - without it Porkbun says the domain is not
opted in. TTL at least 600.

### Namecheap (`namecheap`)

*Profile* → *Tools* → *Business & Dev Tools* → *Namecheap API Access* → on
(Namecheap grants it only to accounts that meet its terms), and **whitelist
the public IPv4 address** acme calls from (the proxy's, through a proxy) - set
the same address as *Client IP*. The domain has to use Namecheap's own DNS
(*BasicDNS* / *PremiumDNS*).

> **setHosts replaces ALL records of the domain.** Namecheap has no call that
> adds or removes one record. acme reads every record (getHosts), adds or
> removes its one TXT value and writes them all back with the domain's
> *EmailType*, one change at a time on this node. A record someone changes by
> hand in that same second can be lost, and a record getHosts does not show
> would be dropped: look at a domain with unusual records once after the first
> certificate. *Allow rewriting every record* (on) is that consent; off, acme
> refuses to change the domain.

### GoDaddy (`godaddy`)

developer.godaddy.com → *API Keys* → *Create New API Key*, environment
**Production** (OTE is GoDaddy's test copy, *Endpoint*). Since 2024 GoDaddy
answers its production API only for accounts with enough domains (or a
Discount Domain Club plan): others get `403 ACCESS_DENIED`. TTL at least 600.

### DNSimple (`dnsimple`)

dnsimple.com → the account → *Account* → *Access tokens* → *New access
token* (an account token). A user token sees several accounts: set the
*Account ID*.

### NS1 (`ns1`)

The NS1 portal → *Account settings* → *Users & teams* → *API keys* → *Add
key*: DNS **View zones** and **Manage zones**, limited to the zones acme may
change. NS1 makes a record with PUT and changes it with POST; acme does both.

### bunny.net (`bunny`)

dash.bunny.net → *Account settings* → *API key*. bunny.net has no key limited
to DNS: this key can do everything in the account.

### ClouDNS (`cloudns`)

cloudns.net → *API & Resellers* → *API users*: a **sub-user** limited to the
zones acme may change (sub-auth-id) is best, the main API user (auth-id)
works. Allow the address acme calls from there. ClouDNS knows only some TTLs
(60, 300, 900, 1800, 3600, …): another is raised to the next.

### INWX (`inwx`)

Best an extra user for acme (*Account* → *Account access*) with DNS rights and
**no two-factor sign-in**. For an account with 2FA give its **two-factor
secret** - the base32 key shown when 2FA was set up, not a 6-digit code - acme
makes the code (TOTP) from it for each sign-in. `api.ote.domrobot.com` is
INWX's test system. TTL at least 300.

### TransIP (`transip`)

Control panel → *Account* → *API* → *Key pairs* → *Generate*: the private key
is shown once - paste it whole. Either switch *Accept only from whitelisted IP
addresses* off (then leave *The key pair is not limited to whitelisted
addresses* on), or whitelist acme's address. acme signs the sign-in
(`POST /v6/auth`, header `Signature`) with that key by the openssl program
(RSA-SHA512); the token it gets lives 30 minutes. TransIP knows the TTLs 60,
300, 3600 and 86400.

### netcup (`netcup`)

Customer Control Panel → *Master Data* → *API*: create an **API key** and an
**API password**; the customer number is your login number. netcup has no
call that lists zones: without *Domain* acme asks `infoDnsZone` for the name
and each name above it. netcup's name servers take a while (5-15 minutes is
usual): leave the propagation check on.

### IONOS (`ionos`)

developer.hosting.ionos.com → *API keys* → *Create*: the **public prefix**
and the **secret** (acme sends `prefix.secret` in `X-API-Key`). This is the
Hosting DNS API for IONOS domains; IONOS Cloud (DCD) DNS is a different API.

### Scaleway (`scaleway`)

console.scaleway.com → *IAM* → an application with a policy giving
**DomainsDNSFullAccess** (or the read and write DNS permission sets) on the
project of the zone → *API keys* → *Generate*: the **secret key** is what
acme needs. A zone that is a subdomain (`dev.example.com`) is found as such.

### Exoscale (`exoscale`)

portal.exoscale.com → *IAM* → *API keys* → *Add*, with a role allowing the DNS
operations (`list-dns-domains`, `list-dns-domain-records`,
`create-dns-domain-record`, `delete-dns-domain-record`). Every request is
signed EXO2-HMAC-SHA256 here - the scheme of Exoscale's own SDKs (method and
path, body, signed query values, headers, expiry, HMAC-SHA256, base64); acme
signs no query arguments.

### Infoblox (`infoblox`)

An admin group with **API** access and read-write permission on the zones
(or on TXT records in them), a user of its own for acme. *Grid Master* is its
address (or the VIP), *WAPI version* what the grid speaks (`2.10` and later
have everything acme uses). The Grid Master's certificate is usually made by
the organisation's own CA: paste that CA under *CA of the Grid Master's
certificate* rather than switching the check off. *DNS view* is `default`
unless your grid uses views.

### Technitium (`technitium`)

The web console → your user → *Create API Token* (or *Administration* →
*Sessions* → *Create Token*) for a user with **Modify** on the zones
(*Administration* → *Permissions*). *Server address* is the console's,
`http://HOST:5380` or `https://HOST:53443`.

### Hurricane Electric (`he_net`)

dns.he.net has no API besides its dynamic update, so:

1. make the TXT record `_acme-challenge.NAME` by hand in dns.he.net (any
   value), with **Enable entry for dynamic dns** ticked;
2. generate its key (the arrows button beside the record) - **one key per
   record**;
3. put a line `_acme-challenge.NAME KEY` per record under *Records and their
   keys* (a line with only a key is used for every name not listed).

Its limits: the record holds **one value** - it is replaced, never added to.
`example.com` and `*.example.com` in one certificate need two values at one
name at once, which dns.he.net cannot hold: acme proves such names one after
the other (the module is not parallel) and refuses a second value while the
first is in use (it is tried again later). Cleanup cannot delete the record:
it is set to *Value when idle* (`acme-idle`). *Test* cannot try a key without
changing the record: it only checks, at HE's name servers, that each record
listed is there.

### WEDOS (`wedos`)

Customer administration → *Customer* → **WAPI interface**: order WAPI (it is
free), set a **WAPI password** (its own, not the account's), choose the
**JSON** protocol, and **allow the IP address** acme calls from - WEDOS
refuses every other. *Login* is the e-mail you sign in with. Each call is
signed `sha1(login + sha1(WAPI password) + hour)`, the hour being the hour
now in Europe/Prague: this machine's clock has to be right (NTP). After each
change acme commits the domain (`dns-domain-commit`); WEDOS's name servers
then take a few minutes. TTL at least 300.

### Active24 (`active24`)

The Active24 administration → your name → *Security and login* → *API
access* → generate an access: the identifier is *API key*, the secret *API
secret*. Requests are signed as Websupport signs them (below), against
`https://rest.active24.cz` - records under `/v2/service/{id}/dns/record`.
**Less certain**: Active24 moved its customers onto the Websupport platform
in 2023-2024; the calls are written as its v2 documentation describes them,
but the list of services (which id is which domain, `/v1/user/self/service`)
is the part acme is least sure of - when the domain is not found, set its
*Service ID* (the number in the address of the domain's page in the
administration) and the list is not asked.

### Websupport (`websupport`)

admin.websupport.sk (or .cz) → your name → *Security and login* → *API
access* → *Generate new access*. Every request is signed: HMAC-SHA1 with the
secret over `METHOD PATH UNIXTIME` (the path without its query), hex, sent as
basic authentication `KEY:SIGNATURE` with a `Date` header of that time
(`YYYYmmddTHHMMSSZ`) - this machine's clock has to be right. acme uses REST
API v1 (`/v1/user/self/zone/{domain}/record`); Websupport has a v2 beside it
(the one Active24 uses), and *API address* can be pointed elsewhere should
v1 go away.

### Modules added in acme 1.1: what was checked, and how

The DNS and upload modules below were written from each vendor's API
documentation (named in each section and in the module's docstring) - but
the vendors' pages could not be fetched from where they were written, so
every call was compared with what lego, acme.sh, Posh-ACME or the vendor's
own SDK send. The signatures are tested against the vendors' **published
worked examples** where there are any (Alibaba Cloud, Tencent Cloud, Oracle
Cloud, Akamai EdgeGrid, AWS SigV4; `test/test_dns_providers_more.py`).
Where a part is less certain, the section says so; a dry run (Settings →
Validations → *Dry run*) tries it for real without asking a CA.

### Subreg.cz (`subreg`)

Subreg administration → *Settings* → **API**: an API user (or the account
itself) and the **IP address** acme calls from allowed. Gransy runs the same
system: set its address under *API address*. The SOAP calls are `Login`,
`Domains_List`, `Get_DNS_Zone`, `Add_DNS_Record`, `Delete_DNS_Record`
(https://soap.subreg.cz/manual/), sent as a hand-written envelope
(`SOAPAction: http://soap.subreg.cz/soap#COMMAND`). Each value is a record of
its own; cleanup deletes only the records holding ours. A domain in Subreg's
DNS that is not registered there is found by asking `Get_DNS_Zone` name by
name. **Less certain**: whether `Get_DNS_Zone` gives names relative to the
domain - both forms are read.

```
login: (API login)      password: (API password)      zone: example.cz (or empty)
```

### CZECHIA.COM / ZONER (`czechia`)

The CZECHIA.COM administration → **API**: the authorization token.
`POST`/`DELETE https://api.czechia.com/api/DNS/{zone}/TXT` with
`{hostName, text, ttl, publishZone: 1}` (header `AuthorizationToken`) - a value
is added and removed by itself (https://api.czechia.com/swagger/). The API
has no call acme knows that only reads: the zone is found by its SOA (or
set), *Test* cannot try the token, and **a dry run is the real test**.

### Webglobe (`webglobe`)

Webglobe administration (webglobe.cz / .sk) → **My account → API keys**: a
new key for the login acme signs in as, with the **public IP address** (or
network) acme calls from allowed - Webglobe refuses a key from every other
address, and a key with none. The key is shown once: paste it as *API key*;
*Login* is the e-mail of that login. Best a **sub-account** (*Users*) given
only the domains acme needs, with a key of its own.

acme signs in (`POST /auth/login {login, token}` → a JWT, kept for the run,
signed in once more on a 401), finds the domain (`GET /domains`, the longest
one the name is in; one not listed is asked for by name, `GET
/domains/{name}`), writes one TXT record (`POST /{domainId}/dns {name, type,
data, ttl}`) and keeps its id; cleanup deletes that id only (`DELETE
/{domainId}/dns/{id}`), and only while it still is a TXT record holding acme's
value at that name. *API*: production `https://api.webglobe.com` or staging
`https://api.staging.core.webglobe.com` (or *API address*).

**Two-factor sign-in**: an account with SMS, OTP or e-mail codes cannot sign
in with its password from a machine (codes 1034, 24, 1382): use an API key.
The remember-me sign-in (`/auth/remember-me`) needs a code once by hand, and
acme does not use it.

Source: the Webglobe API's OpenAPI description ("Webglobe API" 1.0; a copy in
`test/fixtures/webglobe-openapi.yaml`). **Less certain**: the list of domains
is described loosely (a map keyed by the domain's ID; it is read every way it
may come, else set *Domain* or *Domain ID*); whether TXT data is sent bare
(acme does so) and a CNAME's target with its final dot (acme does so);
whether an API key signs in past two-factor sign-in (the description says the
key replaces the password); the lowest TTL Webglobe takes (300 is used).

```
login: you@example.cz      API key: (the key)      domain: example.cz (or empty)
```

### Other Central-European providers

Forpsi, Zoner (other than CZECHIA.COM), Vshosting, Blueboard and Thinline
publish no DNS API acme could find: use their name servers' delegation of
`_acme-challenge` by CNAME to a zone acme can write (acme's own DNS server,
deSEC, ...), or RFC 2136 where they offer it. WEDOS, Active24, Websupport,
Subreg (and Gransy) and CZECHIA.COM have modules of their own.

### Loopia (`loopia`)

Customer zone → *Account settings* → **LoopiaAPI** → create an API user
(`name@loopiaapi`) with `getDomains`, `getZoneRecords`, `addSubdomain`,
`addZoneRecord`, `removeZoneRecord`, `removeSubdomain`. XML-RPC at
`https://api.loopia.se/RPCSERV` (`api.loopia.rs` for Serbia;
https://www.loopia.com/api/). TTL at least 300. Loopia's name servers may
take many minutes to have a record - keep *Wait until it is seen* at the
zone's name servers. The subdomain `_acme-challenge...` acme made is removed
again once no record is left in it.

### Simply.com (`simply`)

Control panel → *Account* → **API**: the account number (S123456) and the API
key - sent as basic authentication; a newer key alone is sent as a bearer
token (leave *Account number* empty). API v2
(https://www.simply.com/en/docs/api/), records under
`/my/products/{domain}/dns/records/`.

### hosting.de / http.net (`hostingde`)

hosting.de → *Profile* → **API keys**: a key with the DNS rights (list
zones, list records, edit zones). http.net: *API address*
`https://partner.http.net/api/dns/v1/json`. Calls `zoneConfigsFind`,
`recordsFind`, `zoneUpdate` (`recordsToAdd` / `recordsToDelete`;
https://www.hosting.de/api/#dns). **Less certain**: `recordsFind` and its
filter fields, and listing every zone with the filter value `*` in *Test*
(set the zone and *Test* asks only for it); should `recordsFind` be refused,
a value is added and deleted by its content without looking first.

### Domeneshop (`domeneshop`)

domene.shop → *My page* → **API** (https://api.domeneshop.no/docs/): a token
and a secret (basic authentication). TTL at least 60.

### GleSYS (`glesys`)

GleSYS Cloud → the project → **API keys**: a key allowed `domain` list,
listrecords, addrecord, deleterecord, and acme's address (*Allowed hosts*).
*Project* is its name (CL12345). https://github.com/GleSYS/API/wiki/API-Documentation.
**Less certain**: the field names of the `list` and `listrecords` answers.

### Mythic Beasts (`mythic_beasts`)

Control panel → **API keys** → a key with DNS API access to the zone (it can
be limited to TXT records at `_acme-challenge`). acme gets a token from
`https://auth.mythic-beasts.com/login` (client credentials) and uses DNS API
v2 (https://www.mythic-beasts.com/support/api/dnsv2); a value is removed by
`DELETE ...?data=VALUE`.

### Infomaniak (`infomaniak`)

manager.infomaniak.com → *Developer* → **API tokens**: a token with the
domain/DNS scopes. API v2: `/2/zones/{zone}/records`
(https://developer.infomaniak.com/docs/api). The API lists products, not
zones: the zone is found by asking `/2/zones/{name}/exists` name by name -
set the zone to have *Test* check it. TTL at least 300.

### Alibaba Cloud DNS (`alidns`)

RAM console → **Users** → a user for acme → *AccessKey*; the policy
`AliyunDNSFullAccess` or one allowing `alidns:DescribeDomains`,
`DescribeDomainRecords`, `AddDomainRecord`, `DeleteDomainRecord`. RPC API
2015-01-09 at `https://alidns.aliyuncs.com` (a region's endpoint under *API
address*), signed with signature version 1.0 (HMAC-SHA1;
https://www.alibabacloud.com/help/en/sdk/product-overview/rpc-mechanism -
the test checks the signature page's own example). The free edition takes
no TTL under **600**.

### Tencent Cloud DNSPod (`tencentcloud`)

Tencent Cloud console → **CAM** → a user → *API keys* (SecretId +
SecretKey); policy `QcloudDNSPodFullAccess` or the four actions
`DescribeDomainList`, `DescribeRecordList`, `CreateRecord`, `DeleteRecord`.
API 3.0 (version 2021-03-23) at `dnspod.tencentcloudapi.com`, signed
TC3-HMAC-SHA256 (https://www.tencentcloud.com/document/api/1157/49029) - the
test checks the hashed canonical request of Tencent's own worked example.
The record line is the default (`默认`); the free plan takes no TTL under
**600**. This machine's clock must be right.

### Oracle Cloud Infrastructure DNS (`oci_dns`)

Identity → **Users** → a user (in a group with *manage dns* in the
compartment) → **API keys** → *Add API key*: paste the private key (PEM RSA,
no passphrase) into acme and copy the fingerprint, the user's and the
tenancy's OCIDs. *Region* as `eu-frankfurt-1`; *Compartment* where the
public zones are (empty: the tenancy). Every request is signed as OCI wants
(https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm;
the test checks Oracle's published test key and both its signatures); the
value is added and removed with `PATCH .../records/{name}/TXT` (`ADD` /
`REMOVE`), so other values stay.

### Akamai Edge DNS (`akamai_edgedns`)

Control Center → *Identity and access* → **API clients** → a client with
*DNS—Zone Record Management* READ-WRITE: its host, client token, client
secret and access token (the `.edgerc` section). EdgeGrid signing
(https://techdocs.akamai.com/developer/docs/authenticate-with-edgegrid -
checked against Akamai's own test cases); Zone Management API v2, the RRset
read, our value added and written back. Primary zones only.

### DNS Made Easy (`dnsmadeeasy`)

Control panel → *Account Information* → the API key and secret key. Each
request carries `x-dnsme-requestDate` and its HMAC-SHA1 (this machine's
clock must be right; https://api-docs.dnsmadeeasy.com/). The sandbox: *API
address* `https://api.sandbox.dnsmadeeasy.com/V2.0`.

### Gcore DNS (`gcore`)

Gcore portal → *Profile* → **API tokens** → a permanent token (a role that
may edit DNS). API v2 RRsets at `https://api.gcore.com/dns/v2/zones/{zone}/{name}/TXT`
(https://api.gcore.com/docs/dns), read, changed, written back. **Less
certain**: the zone list (`GET /v2/zones`); without it the zone is asked
name by name.

### Netlify DNS (`netlify`)

app.netlify.com → *User settings* → *Applications* → **Personal access
tokens**. https://open-api.netlify.com/ (`dns_zones`, `dns_records`).

### Vercel DNS (`vercel`)

vercel.com → *Account settings* → **Tokens** (scoped to the team that holds
the domains), and the team's ID for a team's domains. **Less certain**: the
versions of the two lists (`/v5/domains`, `/v4/domains/{domain}/records`);
records are added and deleted through `/v2/domains/{domain}/records`
(https://vercel.com/docs/rest-api).

### Name.com (`namecom`)

name.com → *Account settings* → *Security* → **API access**: turn it on, make
a production token. API v4 with basic authentication (user name + token;
https://www.name.com/api-docs/). TTL at least 300. **Less certain**: Name.com
has announced a newer API; when v4 goes, its address goes under *API
address*.

### NameSilo (`namesilo`)

namesilo.com → *Account* → **API Manager**: generate a key (best limited to
acme's address). https://www.namesilo.com/api-reference. NameSilo takes no
TTL under **3600** and its name servers often need **15 minutes** or more:
acme waits for them (keep *Wait until it is seen* on the zone's name
servers), and the CA is not asked before.

### Dynu (`dynu`)

dynu.com → *Control Panel* → **API Credentials**: the API key (header
`API-Key`; https://www.dynu.com/Support/API).

### Njalla (`njalla`)

njal.la → *Settings* → **API access** → *Add token* (best limited to acme's
address). JSON-RPC at `https://njal.la/api/1/` (https://njal.la/api/).

### DreamHost (`dreamhost`)

panel.dreamhost.com → *Advanced* → **API** → a key with *All dns functions*
(https://help.dreamhost.com/hc/en-us/articles/217555707-DNS-API-commands). A
value is added and removed by itself; DreamHost sets the TTL.

### Duck DNS (`duckdns`)

duckdns.org → signed in: the **token** at the top; *Duck DNS names* lists
the account's names acme may use (`myhome` or `myhome.duckdns.org`). Duck DNS
keeps **one TXT value per name** and answers it for every name under it:
`myhome.duckdns.org` and `*.myhome.duckdns.org` in one certificate are
proved one after the other (the module is not parallel; a second value is
refused while the first is in use and tried again). A name of your own is
proved through it by a CNAME: `_acme-challenge.www.example.com. CNAME
myhome.duckdns.org.` (one Duck DNS name per name proved at a time). *Test*
cannot try the token without changing the value. https://www.duckdns.org/spec.jsp

### Not added

* Selectel, Reg.ru, Yandex, Timeweb and the other Russian providers: left
  out on purpose (sanctions).
* Microsoft DNS over WinRM: WS-Management needs NTLM (or Kerberos) on one
  kept-open connection and, by default, the SOAP body sealed by NTLM -
  ctx.http keeps no connection between requests. Windows DNS is reached
  over OpenSSH by `ssh_dns` (its PowerShell flavour) or by RFC 2136.
* PowerDNS-Admin: it fronts a PowerDNS server whose own API `powerdns`
  speaks; PowerDNS-Admin's own API keys were not added.
* Joker, Variomedia, UltraDNS, Constellix, Rackspace, EasyDNS, Hostinger,
  One.com: not this time (Joker's and One.com's APIs rewrite whole zones or
  are not documented; the rest maybe later).
* TLS-ALPN-01: acme's nginx answers port 443 for its own pages; answering
  `acme-tls/1` with a validation certificate for other names would need a
  TLS front acme does not have (and the name pointing at acme, as
  `http_local` does already). DNS-01 or HTTP-01 instead.

## HTTP-01 on web servers over SSH (`http_ssh`)

acme never takes connections from the internet. The names point at your web
servers (several behind DNS round-robin or a load balancer); for each
validation acme

1. connects over SSH to **every** host listed (`host` or `host:port`; key or
   password; host keys pinned as `known_hosts` lines - `ssh-keyscan -t ed25519 HOST`),
2. writes `/var/www/acme-challenge/.well-known/acme-challenge/<token>` (the
   folder is made if missing; with sudo: written to `/tmp`, then `sudo -n install`),
   runs the optional *command after*,
3. fails - and takes the file off the hosts that got it - unless **all** hosts
   succeeded (the CA may ask any of them),
4. before the CA is asked, fetches `http://<each host's address>/.well-known/acme-challenge/<token>`
   with `Host: NAME` (or `http://NAME/...`, or nothing) and compares,
5. afterwards removes the file from every host.

**Test** writes a probe file on each host, reads it back over SSH, fetches it
over HTTP from that host, and removes it.

The SSH account needs only to write that folder. Without sudo:

```
useradd -r -m -s /bin/sh acme
install -d -o acme -g acme -m 0755 /var/www/acme-challenge/.well-known/acme-challenge
# the public key acme shows: into ~acme/.ssh/authorized_keys, best with
# restrict,from="<acme's address>" ssh-ed25519 AAAA...
```

With sudo, a sudoers line for exactly that:

```
acme ALL=(root) NOPASSWD: /usr/bin/mkdir -p /var/www/acme-challenge/.well-known/acme-challenge, \
     /usr/bin/install -m 644 /tmp/.acme-* /var/www/acme-challenge/.well-known/acme-challenge/*, \
     /usr/bin/rm -f /var/www/acme-challenge/.well-known/acme-challenge/*
```

### nginx on those web servers

A server on port 80 that serves only the challenge files, from that folder, and
sends everything else to HTTPS (or 404s it). `default_server`, so it also
answers when asked by address with any `Host` (acme's check and the CA alike):

```nginx
# /etc/nginx/conf.d/acme-challenge.conf
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # HTTP-01: files acme writes over SSH, nothing else
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme-challenge;
        default_type text/plain;
        try_files $uri =404;
        autoindex off;
        access_log /var/log/nginx/acme-challenge.log;
    }

    # everything else: to HTTPS (or: return 404;)
    location / {
        return 301 https://$host$request_uri;
    }
}
```

**Prepare the hosts** (the action `prepare` of an `http_ssh` validation: the
button on its row, `acme --validation-action NAME prepare`, or the console)
does this on every web server: it finds nginx, makes the webroot (owned by
the SSH account when it writes without sudo), writes the block above to
`/etc/nginx/conf.d/acme-challenge.conf` (*nginx file*, `nginx_conf`; with an
`alias` to the webroot), checks it with `nginx -t` - putting back what was
there when the check fails - and reloads nginx; then it runs the probe of
*Test*. It needs root there, or `sudo` without a password for `sh`. Where
another block is the default server of port 80 already, name the names in
*Names that block answers for* (`prepare_names`); *That block listens on
IPv6 too* and *Everything else to HTTPS* (else 404) are under *More*. Run
again, it changes nothing that is in place.

**Check before the CA is asked** - *at other addresses* (`check: at`): the
token is fetched at each address of *Check at* (`check_at`: an IP or name,
`:port`, or `https://` for TLS) instead of each web server's own address -
a load balancer, the public IP, a NAT in front. The URL keeps the
certificate's name and only the connection goes to the address, so Host and
the TLS SNI are the name's and a redirect (to HTTPS) is followed as the CA
follows it. *Name for Test* (`check_name`) is the name Test sends then (and
the Host of Test in *each machine*).

**nginx answering port 80 already** (your sites, a certbot redirect to
HTTPS): *How "Prepare" sets nginx up* (`prepare_how`):

* **by itself** (`auto`, the default) - with nothing else on port 80, acme's
  own server block; with *Names acme's own block answers for* filled in and no
  other block answering those names, its own block for them only (not the
  default server); otherwise one line,
  `include /etc/nginx/snippets/acme-challenge.conf;  # acme`, goes at the top
  of every port-80 server block. Nothing else in them changes. The snippet
  starts with `rewrite ^(/\.well-known/acme-challenge/.*)$ $1 break;` - at the
  server level nginx runs rewrite, return and if in order, so a `return 301`
  or certbot's `if ($host = …) { return 301 …; }` would answer first; `break`
  ends that for these paths only and the snippet's `location ^~` (with
  `root`) serves the file. Each file is checked unchanged since it was read,
  copied to `/var/backups/acme-nginx/DATE/` (outside nginx's folders, where a
  `sites-enabled/*` would load a copy), written in place (owner and mode
  kept), `nginx -t` - every file put back when it fails - and nginx reloaded.
  A block with a location for `/.well-known/acme-challenge/` of its own is
  left as it is (said in the job).
* **I put it in myself** (`manual`) - acme changes nothing: *Download the
  nginx config* gives the snippet and the line; *Prepare the hosts* then only
  checks every port-80 block includes it, and runs the probe.
* **always its own server block** (`own`) - as before.

**Set nginx up by itself** (`auto_prepare`, off by default) does the same
before *Test* and before every validation, once a job: nothing is written and
nginx is not reloaded while the block is in place as it should be. A web
server where it fails fails the validation before any token is written.
**Open port 80 in their firewall** (`prepare_firewall`, off by default) adds
port 80/tcp to firewalld (`--add-service=http`, permanent) or ufw when it is
closed there; another firewall is said in the job, not changed. An SSH that
works while HTTP says *No route to host* is that firewall (firewalld rejects
so) - the check says so.

With a server block of your own on port 80 already, put just the `location
^~ /.well-known/acme-challenge/ { root /var/www/acme-challenge; ... }` into it
(before any redirect). Apache: `Alias /.well-known/acme-challenge/
/var/www/acme-challenge/.well-known/acme-challenge/` with `Require all granted`.

Behind a load balancer: let `/.well-known/acme-challenge/` through on port 80
to every pool member (no redirect to HTTPS before it - a redirect to HTTPS is
followed by the CA, but only to port 443 of the same name).

## HTTP-01 by uploading the file (`http_ftp`, `http_s3`, `http_azure_blob`, `http_webdav`)

For a site acme cannot sign in to with a shell: a web hosting with an FTP
account, a static site in a bucket, a CDN in front of storage. Each
validation acme uploads `.well-known/acme-challenge/TOKEN` under the folder
set, fetches `http://NAME/.well-known/acme-challenge/TOKEN` as the CA will
(*Check before the CA is asked*: by the name, by *Address the folder is
served at* - the bucket's own website address - or not at all) and takes
the file away afterwards. *Test* uploads a probe, reads it back where it can
and takes it away. The guide checks the sign-in and the folder (read only),
that the name has an address and answers HTTP; only a dry run shows that the
folder set is the one the site serves. Wildcards: DNS-01 only.

### FTP, FTPS, SFTP (`http_ftp`)

*Protocol*: **FTPS** (explicit TLS, `AUTH TLS`, the data channel protected
too - RFC 4217) wherever the hosting has it; plain FTP sends the password in
the clear. *Web root of the site* as the FTP account sees it: often `/www`,
`/public_html`, `/httpdocs`, `/web` or `/www/example.com`. FTP goes straight
from this machine (passive mode), not through the HTTP proxy. **SFTP** goes
through acme's SSH: an SSH key or password, the host key pinned as for
`http_ssh`; the file is put with scp and removed with `rm` - an SFTP-only
account (no shell) cannot run `rm`, so the file is emptied instead (an empty
file is harmless) and the job says so. Wherever the account has a shell,
`http_ssh` is the better choice.

```
protocol: ftps   host: ftp.example.com   ftp_user: example.com   folder: /www
```

### S3 and S3-compatible buckets (`http_s3`)

An IAM user (or the service's key) allowed `s3:PutObject`, `s3:GetObject`
and `s3:DeleteObject` on `BUCKET/FOLDER.well-known/acme-challenge/*`
(`s3:ListBucket` too for the guide's check). Signed SigV4 (the code that
signs Route 53, checked against AWS's documented S3 example). For MinIO,
Ceph, Wasabi, Backblaze B2, Cloudflare R2 (*Region* `auto`), Hetzner, OVH,
Exoscale: their address under *Endpoint*, *Path style* for those that want
`endpoint/bucket/key`. The file must be readable by the CA: a bucket policy
for `.well-known/acme-challenge/*` (or *ACL of the file* `public-read` where
ACLs are on), and a CloudFront or other CDN in front must pass
`/.well-known/acme-challenge/*` through to the bucket over HTTP (no cache, or
a short one). https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html

```json
{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
 "Resource": "arn:aws:s3:::www-example-com/.well-known/acme-challenge/*"}
```

### Azure Blob Storage (`http_azure_blob`)

A static website's container is `$web`. Sign in with a **SAS token** (the
container's, or the account's: service Blob, resource Object, permissions
Read, Write, Create, Delete - the part after `?`) or the **account key**
(Shared Key, signed here as
https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
says; Microsoft publishes no full worked example to test it against, so the
test checks the string to sign rule by rule). Behind Azure Front Door or
CDN: let `/.well-known/acme-challenge/*` through without caching.

### WebDAV (`http_webdav`)

*WebDAV address of the web root*: the WebDAV URL of the folder the site is
served from (a hosting's WebDAV access, Nextcloud, Apache `mod_dav`, IIS).
`MKCOL` makes `.well-known/acme-challenge/` (405 - already there - is fine),
then `PUT` and `DELETE` (RFC 4918). Basic authentication: use HTTPS.

## DNS-01 over SSH (`ssh_dns`)

acme signs in to the DNS server itself over SSH and writes the TXT record
straight into the zone there - no API, no TSIG key over the network. Every
setting is a field of its own and can be set by hand; **Find out what runs
there** (the button under the form, or `acme --validation-action NAME discover`)
reads what the server is and fills them in.

| How (`flavour`) | Server | What acme runs there | Needs |
|---|---|---|---|
| `nsupdate_local` | BIND | `nsupdate -l` (`-k` the session key when *Session key file* is set) | the zone with `update-policy local;`; the account reads the session key (group `bind`/`named`) or sudo |
| `nsupdate_key` | BIND | `nsupdate -k KEYFILE`, sent to *Server nsupdate sends to* (127.0.0.1) | a TSIG key file there, granted in `update-policy`/`allow-update` |
| `bind_file` | BIND (static zone) | the zone file edited (below), `named-checkzone`, `rndc reload ZONE`; a zone with a journal: `rndc freeze` before, `rndc thaw` after | *Zone files*; write access to the file and its directory (or sudo) |
| `pdnsutil` *(PowerDNS default)* | PowerDNS | `pdnsutil list-zone` (read), `add-record` / `replace-rrset` (the other TXT values at the name kept) / `delete-rrset`, `increase-serial`, `rectify-zone` | the account may run pdnsutil (it reads the backend: usually sudo) |
| `pdns_api` | PowerDNS | `curl` on that machine to its HTTP API on localhost: GET the RRset, PATCH `REPLACE`/`DELETE`, PUT `rectify` for a DNSSEC zone; the API key goes to curl on its input (`-K -`), never on a command line | `api=yes`, `webserver=yes`, the API key |
| `knot` | Knot DNS | `knotc zone-read`, then `zone-begin` / `zone-set` or `zone-unset` / `zone-commit` (`zone-abort` on any error) | access to knotd's control socket (group `knot` or sudo) |
| `nsd` | NSD | the zone file edited, `nsd-checkzone`, `nsd-control reload ZONE` | *Zone files*; `nsd-control` set up (`nsd-control-setup` or a unix socket) |
| `dnsmasq` | dnsmasq | `txt-record=NAME,"VALUE"` lines in a file of acme's own (`/etc/dnsmasq.d/acme-challenge.conf`), `dnsmasq --test`, then *Restart command* | dnsmasq reading that directory (`conf-dir=/etc/dnsmasq.d/,*.conf`) |
| `unbound` | Unbound | `unbound-control local_data 'NAME TTL IN TXT "VALUE"'`; taken away by `local_data_remove NAME` and the other records at that name put back - in memory, no restart | remote-control enabled; only useful where Unbound is the server asked (an internal CA) |
| `powershell` | Windows DNS | `Add-DnsServerResourceRecord` / `Remove-DnsServerResourceRecord` (OpenSSH for Windows) | the account in DnsAdmins; *Zone* as DNS Manager shows it |
| `custom` | anything | your *Command to add* / *to take away* / *to try* | |

Every name and value is checked (letters, digits, `_ . - *`) and every word is
shell-quoted; paths must be absolute plain paths, and the command fields (rndc,
the restart) words without `; | & $ \` > <`. With **Through sudo** each tool
runs as `sudo -n TOOL ...` (a sudoers line can name exactly it); where a file is
edited (`bind_file`, `nsd`, `dnsmasq`) the whole script runs as `sudo -n sh -s`.
The tools are looked for in `/usr/sbin`, `/sbin` and `/usr/local/sbin` too.

**Which zone.** *Zone* when it is set (and the name is in it); else the longest
of *Zones there* (and of *Zone files*) the name is in; else the zone found by
its SOA. dnsmasq and Unbound need none: the record is put at its name. Writing
is idempotent: a value already there is not added again, and taking it away
takes only acme's value - other TXT records at the same name stay.

**The zone file editor** (`bind_file`, `nsd`). acme reads the file, adds the
line `_acme-challenge.NAME. TTL IN TXT "VALUE" ; acme-challenge` at its end (or
takes exactly that line away - a line without the mark is never touched) and
raises the SOA serial: *as it is written* - a date `YYYYMMDDnn` stays one (today's
`00`, or the old one + 1), any other number + 1; or always the date, the Unix time,
+ 1. A file it cannot read whole is refused, with "use a dynamic zone (nsupdate)
instead": `$INCLUDE`, no SOA or more than one, a parenthesis or a quote that
does not end, not a text file (a raw or map zone). The new file is put in place
by one script there (`sh -s`, the content in a quoted here-document):

1. the file must still be what was read (its SHA-256) - else nothing is written;
2. a copy is kept beside it as `.FILE.acme-bak`, the new one written to
   `.FILE.acme-new` (owner and mode kept);
3. `named-checkzone ZONE .FILE.acme-new` (`nsd-checkzone`) - refused: the new
   one removed, nothing changed;
4. moved into place, `rndc reload ZONE` (`nsd-control reload ZONE`) - failed:
   the copy put back and reloaded again.

Nothing but acme's own two files is ever removed. A BIND zone with a journal
(`FILE.jnl`: it is dynamic) is frozen first (`rndc freeze`) and thawed after
(`rndc thaw`, which reloads it), also when something failed - or refused when
*Freeze a dynamic zone* is off. dnsmasq's file is acme's own: the same script,
`dnsmasq --test` once it is in place (the whole configuration), then the restart.
dnsmasq reads `txt-record` only when it starts - a SIGHUP does **not** reload it
- so it is restarted (`systemctl restart dnsmasq`; its cache is lost).

**Test** changes nothing: nsupdate there (and the key readable), the zone files
read and checked (`named-checkzone`/`nsd-checkzone` on the file as it is, the
serial said), `rndc status` / `nsd-control status`, `pdnsutil list-all-zones`,
the API's zone list, `knotc zone-status`, `dnsmasq --test`, `unbound-control
list_local_zones` - each zone set must be there. `nsupdate -l` cannot be tried
without changing the zone: the **dry run** (any flavour) puts a random test TXT
record in, waits until the zone's name servers answer it, and takes it away.

### Find out what runs there

Read-only, always: each command is checked against a fixed list of read-only
commands before it is sent (anything else is refused before it leaves acme),
runs under `timeout 10` where `timeout` is there, and a tool that is missing or
fails is only said. Nothing is written, reloaded or restarted. What needs root
is tried as the account first, then with `sudo -n` when that works. The
commands (`PATH` with the sbin directories before each):

```
uname -s; id -u; id -un; id -G
for c in named named-checkconf named-checkzone rndc nsupdate pdnsutil pdns_server pdns_control knotc knotd nsd nsd-checkconf nsd-checkzone nsd-control dnsmasq unbound unbound-control systemctl pgrep sudo timeout sha256sum curl powershell; do command -v "$c"; done
sudo -n true                                            # not as root
systemctl is-active named bind9 pdns knot nsd dnsmasq unbound
pgrep -l -x 'named|pdns_server|knotd|nsd|nsd: main|dnsmasq|unbound'
# BIND
named -v
named-checkconf -p [NAMED_CONF]                         # zones, views, update-policy, allow-update, keys (their secrets are never kept)
ls -lnd -- ZONEFILE ZONEFILE.jnl ZONEDIR ... /run/named/session.key /var/run/named/session.key
grep -sH -E '^[[:space:]]*key[[:space:]]' -- /etc/bind/*.key /etc/bind/keys/*.key /etc/named/*.key /etc/named*.key /var/named/*.key /var/lib/bind/*.key /usr/local/etc/namedb/*.key
# PowerDNS
pdns_server --version
grep -hsE '^[[:space:]]*(api|webserver|webserver-address|webserver-port|launch)[[:space:]]*=' /etc/powerdns/pdns.conf /etc/pdns/pdns.conf /etc/powerdns/pdns.d/*.conf   # never api-key
pdnsutil [--config-dir=DIR] list-all-zones
pdnsutil [--config-dir=DIR] show-zone ZONE              # DNSSEC, primary or secondary (20 zones at most)
# Knot
knotc [-c CONF] [-s SOCKET] -V | zone-status | conf-read zone.domain
# NSD
nsd -v
nsd-checkconf -o zones|-o zonesdir /etc/nsd/nsd.conf
nsd-checkconf -z ZONE -o zonefile|-o request-xfr /etc/nsd/nsd.conf
ls -lnd -- ZONEFILE ZONEDIR ...
# dnsmasq
dnsmasq --version
grep -hsE '^[[:space:]]*(conf-dir|conf-file|auth-zone|auth-server|local|domain|txt-record|port)=' /etc/dnsmasq.conf /etc/dnsmasq.d/*.conf
ls -lnd -- /etc/dnsmasq.d
# Unbound
unbound -V
unbound-control [-c CONF] list_local_zones
# Windows (when uname does not answer)
powershell -NoProfile -NonInteractive -Command "Get-DnsServerZone | ForEach-Object { ... }"
```

It answers which server runs there (and its version), the way it suggests,
each zone with its file, whether it is dynamic and how acme would write it
(a secondary: "written on its primary"), the keys found (names and files), whether
sudo works and is needed, and what is in the way. The page fills in the fields
it found: an empty field (or one at its default) at once, a field set otherwise
only when you tick it in the list it shows; *Use only this one* puts a zone into
*Zone*. Nothing is saved until **Save**; when it cannot find anything (no SSH,
no server it knows) it says why, and every field stays to be set by hand. When
several servers run there, the one with zones acme can write is suggested, the
other named (another validation can use it).

### Setting it up by hand

**BIND, nsupdate -l** (the simplest: no key to manage):

```
zone "example.com" {
    type primary;
    file "/var/lib/bind/db.example.com";      # a directory named may write (the journal)
    update-policy local;                      # = grant local-ddns zonesub any;
};
```

named makes `/run/named/session.key` (`session-keyfile` moves it - then set
*Session key file*). The SSH account reads it: `usermod -aG bind acme` (Debian;
`named` on RHEL), or *Through sudo* with
`acme ALL=(root) NOPASSWD: /usr/bin/nsupdate`. To allow only TXT records:
`update-policy { grant local-ddns zonesub TXT; };`.

**BIND, a key of its own** (`nsupdate_key`):

```
tsig-keygen -a hmac-sha256 acme-key > /etc/bind/acme.key   # chgrp bind, chmod 640
include "/etc/bind/acme.key";
zone "example.com" { type primary; file "..."; update-policy { grant acme-key zonesub TXT; }; };
```

**BIND, a static zone** (`bind_file`): *Zone files* `example.com
/etc/bind/db.example.com`; the account may write the file and its directory and
run `rndc` (group `bind`), or *Through sudo* with `acme ALL=(root) NOPASSWD:
/bin/sh -s, /usr/bin/cat, /usr/bin/test, /usr/sbin/rndc` (a shell as root - prefer
the group).
Secondaries get the change by NOTIFY, as the serial is raised.

**PowerDNS** (`pdnsutil`): `acme ALL=(root) NOPASSWD: /usr/bin/pdnsutil` (or the
account in the group that reads the backend). The HTTP API instead
(`pdns_api`): in `pdns.conf` `api=yes`, `api-key=...`, `webserver=yes`,
`webserver-address=127.0.0.1`, `webserver-port=8081`; curl on the server.

**Knot DNS** (`knot`): the account in the group `knot` (it may use
`/run/knot/knot.sock`), or `acme ALL=(root) NOPASSWD: /usr/sbin/knotc`. A change
made by knotc goes to Knot's journal (the `database: storage` directory must
exist) and back into the zone file as `zonefile-sync` says; a signed zone
(`dnssec-signing: on`) is signed again by Knot. An ACL is needed only for RFC 2136
(`rfc2136`), not here:
`acl: [{id: acme, key: acme-key, action: update, update-type: [TXT]}]`.

**NSD** (`nsd`): `nsd-control-setup` once (or `control-interface: /run/nsd/nsd.ctl`),
*Zone files* as `nsd-checkconf -z ZONE -o zonefile` says (relative to
`zonesdir`); sudo for the zone files, as for BIND.

**dnsmasq** (`dnsmasq`): `conf-dir=/etc/dnsmasq.d/,*.conf` in `dnsmasq.conf`
(Debian reads the directory by itself); sudo for the file and the restart.

**Unbound** (`unbound`): `remote-control: control-enable: yes` (`unbound-control-setup`),
and the account allowed to use it (sudo). Unbound is a resolver: a public CA asks
the zone's authoritative servers, never it.

**Windows DNS**: OpenSSH Server on the DNS server (or a machine with the
DnsServer RSAT module, `-ComputerName`); the account in DnsAdmins. The zone
must be set as DNS Manager shows it.

**Your own commands**: `{fqdn} {relative} {zone} {value} {ttl} {name}` are
put in shell-quoted, e.g. a zone file included by the real one:

```
add:  printf '%s 60 IN TXT "%s"\n' {fqdn}. {value} >> /var/named/acme-challenge.inc && rndc reload {zone}
del:  sed -i /{value}/d /var/named/acme-challenge.inc && rndc reload {zone}
```
(the zone's SOA serial must change for secondaries: prefer a flavour above).

## RFC 2136 (`rfc2136`)

BIND:

```
tsig-keygen -a hmac-sha256 acme-key > /etc/bind/acme-key.conf    # include it in named.conf
zone "example.com" {
    type primary; file "...";
    update-policy { grant acme-key zonesub TXT; };   # TXT records only, anywhere in the zone
};
```

Knot: `acl: [{id: acme, key: acme-key, action: update, update-type: [TXT]}]`.
PowerDNS: `dnsupdate=yes`, the key in `tsigkeys`, `TSIG-ALLOW-DNSUPDATE` metadata
on the zone. Windows DNS signs updates only with GSS-TSIG (Kerberos), which acme
does not speak: use `ssh_dns` with PowerShell, or set the zone to "Nonsecure and
secure" dynamic updates, restrict it to acme's address, and leave the key empty.

**Test** sends an UPDATE whose only content is the prerequisite "the zone's
SOA exists" - the key, the zone and the server's permission are tried and
nothing is changed.

## A script (`script`)

```
#!/bin/sh
# /etc/acme/hooks/dns.sh present|cleanup RECORD VALUE
case "$1" in
  present) my-dns-cli add  "$2" TXT "$3" ;;
  cleanup) my-dns-cli del  "$2" TXT "$3" ;;
esac
```

The environment holds `ACME_ACTION ACME_NAME ACME_RECORD ACME_CHALLENGE_NAME
ACME_TXT ACME_TOKEN ACME_ZONE ACME_TTL` and the variables set on the challenge;
nothing of acme's own environment. Exit 0 or the order fails with the script's
last words.
