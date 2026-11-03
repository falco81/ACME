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
| `hetzner` | Hetzner Console/Cloud API zones (`api.hetzner.cloud`, RRset actions `add_records` / `remove_records`, each action waited for); the old dns.hetzner.com was switched off in May 2026 | a project's API token |
| `digitalocean` | DigitalOcean Domains | personal access token |
| `ovh` | OVHcloud API | application key/secret, consumer key on /domain/zone/* |
| `desec` | [deSEC.io](https://desec.io) (dedyn.io names too); TTL raised to the domain's minimum (3600); waits 60 s more after both name servers have it (anycast) | an API token (a token policy limiting it to TXT at `_acme-challenge` is best) |
| `gandi` | Gandi LiveDNS v5 | a personal access token ("Manage domain name technical configurations") or an older API key |
| `linode` | Linode / Akamai Cloud Domains (API v4) | a personal access token, Domains Read/Write |
| `vultr` | Vultr DNS (API v2) | an API key, acme's address under Access Control |
| `porkbun` | Porkbun (API v3) | API key + secret, *API Access* on for each domain |
| `namecheap` | Namecheap XML API - **setHosts rewrites every record of the domain** (read-modify-write, see below) | API user + key, acme's public IP whitelisted |
| `godaddy` | GoDaddy Domains API v3 (one record a value, deleted by its `recordId`); v1 with the older key + secret selectable | a personal access token (domains.domain:read, domains.dns:update); the account must be eligible |
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
| `active24` | Active24 REST API v2 (Websupport-group signing), or the Active24 API (api.active24.com) | API key + secret, or a token |
| `websupport` | Websupport.sk / .cz REST API v1 (HMAC-SHA1 signed) | API key + secret |
| `subreg` | Subreg.cz / Gransy SOAP API (envelope written by hand) | API login + password, acme's IP allowed |
| `czechia` | CZECHIA.COM (ZONER) REST API; zone by SOA (or set), read by GET /api/DNS/{zone} | the account's API token (an ACME token is enough) |
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
| `hostinger` | Hostinger API (DNS zone, RRsets written with overwrite false / true) | an API token (hPanel → Account → API) |
| `constellix` | Constellix DNS API v1 (HMAC-SHA1 security token) | API key + secret key |
| `ultradns` | UltraDNS (Vercara) REST API, OAuth2 password sign-in | an UltraDNS user allowed to change the zones' records |
| `mailinabox` | a Mail-in-a-Box server's control panel API (`/admin/dns/custom`) | an administrator's e-mail + password (without two-factor sign-in) |
| `efficientip` | EfficientIP SOLIDserver REST API v2.0 (`/dns/rr/*`) | a user allowed the DNS services; the DNS server (or SMART) name |
| `openprovider` | Openprovider REST API (`/v1beta/dns/zones`) | an API user + password |
| `easydns` | easyDNS REST API; zone by SOA (or set); TTL 300-86400 | API token + API key |
| `plesk` | Plesk XML API (`dns` add_rec / get_rec / del_rec) | a login + password or an XML API secret key |
| `rackspace` | Rackspace Cloud DNS v1.0 (asynchronous jobs followed); TTL ≥ 300 | user name + API key |
| `cpanel` | cPanel UAPI (`DNS::parse_zone` / `DNS::mass_edit_zone` with the SOA serial, removed by `line_index`) | the cPanel user + an API token |
| `joker` | Joker.com DMAPI - **`dns-zone-put` rewrites the whole zone** (read, our line added or taken away, written back); TTL ≥ 300 | a DMAPI API key (or user + password) |
| `netim` | Netim REST API 1.0 (asynchronous operations followed; deleted by subdomain + type + value) | reseller ID + API (DAS) password |
| `huawei_dns` | Huawei Cloud DNS v2 (one record set a name; AK/SK SDK-HMAC-SHA256 signed here); the region's endpoint | an IAM access key (AK/SK) + region |
| `directadmin` | DirectAdmin legacy API `CMD_API_DNS_CONTROL` (deleted by name + value, read back) | the user + a login key |
| `forpsi` | Forpsi **F-DNS** (the paid DNS-as-a-service) REST API, one record a value; **ordinary Forpsi DNS has no API** | an F-DNS API token (admin.forpsi.com) |
| `ispconfig` | ISPConfig 3 Remote API (JSON): `dns_txt_add` / `dns_txt_delete` by id, the serial raised; applied by the panel's cron | a remote user with the DNS zone and DNS txt functions |
| `hestiacp` | HestiaCP API: `v-add-dns-record`, `v-delete-dns-record` by ID (found by its value) | an access key + secret of the user (or an admin's), acme's IP allowed |
| `virtualmin` | Virtualmin Remote API (`remote.cgi`): `modify-dns` add / `--remove-record` **always with the value**, read back | the master administrator's password |
| `froxlor` | froxlor API: `DomainZones.add` / `DomainZones.delete` by entry id (found by its value); applied by froxlor's cron | an API key + secret, the external API enabled |
| `windows_dns` | Windows Server DNS: PowerShell `Add-DnsServerResourceRecord` / `Remove-DnsServerResourceRecord -RecordData` over OpenSSH for Windows | an account allowed to change the zone (DnsAdmins), OpenSSH Server |
| `acme_dns` | an [acme-dns](https://github.com/joohoi/acme-dns) server | account(s); `_acme-challenge.NAME CNAME <fulldomain>` once |
| `ssh_dns` | commands on the DNS server itself over SSH, straight into its zones: BIND (`nsupdate -l`, `nsupdate -k`, or the zone file + `rndc reload`), PowerDNS (`pdnsutil` or its HTTP API there), Knot (`knotc` transaction), NSD (zone file + `nsd-control reload`), dnsmasq (`txt-record`), Unbound (`local_data`), Windows DNS (PowerShell via OpenSSH), or your own commands; **Find out what runs there** reads the server (read-only) and fills the form in | an SSH account there (sudo optional) |
| `script` | a program on this machine (`present`/`cleanup`, dehydrated- or lego-style), `ACME_*` variables | the program |
| `dns_persist` | **dns-persist-01**: one TXT record at `_validation-persist.NAME` of each name, set once, names the ACME account - no record per order, the wildcard `*.NAME` with `policy=wildcard`; a fallback validation while the CA does not offer it ([below](#a-record-set-once-dns-persist-01-dns_persist)) | an ACME source; the record put in your DNS once |
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
| `policy=wildcard` | optional: the record also covers `*.example.com`. **Not the names under the domain**: the CA looks each name's record up at that name - `www.example.com` needs `_validation-persist.www.example.com` (the draft says they are covered; Let's Encrypt's Boulder looks up only `_validation-persist.<the name>` - staging refused a name under the domain with only the domain's record: *NXDOMAIN looking up TXT for _validation-persist.www.example.com*). The switch *A record at each name (Let's Encrypt today)*, off by default, writes and checks a record at each name when on - turn it on for Let's Encrypt as it is now; off, the domain's record covers the names under it, as the draft says |
| `persistUntil=` | optional: a Unix time after which the CA no longer takes the record |

The syntax is that of a CAA issuer value (RFC 8659): the domain name first,
then `; tag=value` parameters (tags without regard to case, unknown ones
ignored, no spaces inside a value). **Several TXT records may stand at the
name** - one for each account: Let's Encrypt and its staging have different
account URLs, so a source of each needs its own record, and other TXT records
there stay.

**Settings** of the validation: *Names with the record* (on: names that get
the record besides those of the certificates; off: the domains whose record
covers the names under them), *Cover subdomains and wildcards*
(`policy=wildcard`, on by default), *A record at each name (Let's Encrypt
today)* (off by default; on: every name its own record, as Let's Encrypt looks
it up only at the name - turn it off again once the CA covers the names under a
domain with the domain's record - *Take the records away* then removes what acme
wrote, *Write the records to DNS* writes the domain's again), *Valid until* (`persistUntil`, a day or a Unix
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
  goes to `dev.example.com` when the account has both). netcup, dns.he.net
  and easyDNS cannot list zones: netcup is asked name by name, dns.he.net
  and easyDNS go by the SOA.
* **Several values at one name**: our value is added next to the ones there,
  and cleanup removes only ours. Where the API keeps a whole RRset (deSEC,
  GoDaddy's older v1, NS1, Namecheap, Huawei Cloud DNS - Joker.com even the
  whole zone) it is read, changed and written back, one
  change at a time on this node (Azure DNS with the etag read, so a change
  made elsewhere meanwhile is not lost); where the API adds or takes away
  single values of an RRset (Gandi's PATCH, Hetzner's actions, PowerDNS's
  EXTEND / PRUNE from 4.9.12 / 5.0.2) only ours is sent. Removing a value
  that is gone already is not an error.
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
with: an API key*). LiveDNS v5; TTL at least 300. Since 1.0.27 our value is
added and taken away with `PATCH` (`add_rrset_values` / `remove_rrset_values`),
so the RRset is never written whole; a new RRset is made with `POST`.

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

developer.godaddy.com → *Personal Access Token*: the scopes
`domains.domain:read` and `domains.dns:update` (since 1.0.27 acme speaks the
Domains API **v3**: one record a value, deleted by its `recordId` - the other
values at the name are never written). The older *API Keys* (`sso-key`) do not
work with v3; *API: Domains API v1* keeps them (the values at the name read,
ours added or taken away, written back), and a validation saved with a key and
no token goes on using v1. OTE is GoDaddy's test copy (*Endpoint*). GoDaddy
answers its domain management only for eligible accounts ("Account holds at
least one domain, OR is on a plan that grants management access"): others get
`403` with a `code` saying why. TTL at least 600.

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

Checked again in 1.0.22 against lego's `providers/dns/internal/active24`
(the v2 client its `active24` and `websupport` providers share, written to
https://rest.active24.cz/v2/docs): the same record calls, filters and
service list - but its `Date` header is RFC 3339 (`2025-01-31T12:00:00Z`),
which acme now sends for Active24 too (it sent the basic form
`20250131T120000Z` of API v1 before). Websupport (`websupport`, API v1)
keeps the basic form.

Checked in 1.0.24 against Active24's own descriptions of both its APIs:

* **REST API v2** - `https://rest.active24.cz/v2/docs/openapi.json` (OpenAPI 3,
  "Rest API 2.0.0"): `/v2/check` (*Test* asks it: signed in?),
  `/v2/service/{service}/dns/zone` (the zone's name - with a *Service ID*
  alone the domain is read from it, not guessed from its SOA),
  `/v2/service/{service}/dns/record` with `filters[name]` and
  `filters[type][]`, POST of `{type, name, content, ttl}` answered 204 with
  no body, DELETE `/v2/service/{service}/dns/record/{record}`; basicAuth.
  A domain set under *Domain* but missing from the list of services is asked
  for itself, `/v1/user/self/zone/{domain}` (its `id`), as acme.sh's
  `dns_active24.sh` does; neither /v1 lookup is in the v2 description.
* **Active24 API** - `https://api.active24.com/v2/api-docs` (Swagger 2.0,
  "Active24 REST API Documentation"), *API* set to *Active24 API -
  api.active24.com*, with its token (`Authorization: Bearer`):
  `GET /dns/domains/v1` (the domains), `GET /dns/{domain}/records/v1`,
  `POST /dns/{domain}/txt/v1` `{name, text, ttl}`, `DELETE
  /dns/{domain}/{hashId}/v1` (400 `DNS_RECORD_TO_DELETE_NOT_FOUND`: gone
  already). The description names only `name` and `ttl` of a listed record;
  `hashId`, `type` and `text` are read as Posh-ACME's Active24 plugin
  (github.com/rmbolger/Posh-ACME, `Plugins/Active24.ps1`) reads them.

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

The CZECHIA.COM administration → your account → **REST API token**. Of its two
kinds (napoveda.czechia.com, *Aktivace REST API*) an **ACME** token - only the
TXT records of DNS, usable from any address - is enough; a full-access one
works only from the addresses allowed there.

Checked in 1.0.24 against the API's own description,
`https://api.czechia.com/swagger/v1/swagger.json` ("Zoner REST API
Documentation" v1, OpenAPI 3.0.1), header `authorizationToken`:

* `GET /api/DNS/{zone}` - the zone, its `txtRecords` (`hostName`, `text`,
  `ttl`): read before a value is added (one already there is not added again)
  and before one is taken away; *Test* reads it when the domain is set.
* `POST` / `DELETE /api/DNS/{zone}/TXT` with `{hostName, text, ttl,
  publishZone: 1}` - a value added and removed by itself; `publishZone: 1`
  puts the change on the DNS servers at once. A TTL is **120 to 172800** s
  (acme sent 60 and up before).
* `GET /api/Domains` - the domains of the account: *Test* lists them when no
  domain is set. An ACME token may not list them: the zone is then found by
  its SOA, as always, and *Test* says to set the domain.

A token that may not read the zone either: each value is added and removed as
asked, as before (an "already exists" taken for done).

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

### Modules added in acme 1.0.22: what was checked, and how

The vendors' documentation sites could not be fetched from where these
were written (only GitHub could be reached), so every call below was taken
from the **vendor's own SDK, API description or official integration on
GitHub** - named with the files read - and compared with lego's provider of
the same name where there is one. The reference each vendor publishes is
named too (not fetched). `test/test_dns_providers_new.py` puts each module
through a fake of its API built from those sources. A dry run (Settings →
Validations → *Dry run*) tries a module for real without asking a CA.

### Hetzner (`hetzner`), checked again

Hetzner DNS moved into the Hetzner Console / Cloud API in 2025; the module
already speaks it (*API* = Hetzner Console / Cloud API, the default) and
keeps the old DNS Console (`dns.hetzner.com`) selectable. Checked in 1.0.22
against Hetzner's official Python SDK (https://github.com/hetznercloud/hcloud-python:
`hcloud/zones/client.py` - `GET /zones?name=`, `POST
/zones/{id_or_name}/rrsets/{name}/{type}/actions/add_records` and
`.../remove_records` with `{records: [{value}], ttl}`; `hcloud/exp/zone.py` -
TXT values in quotes), whose reference is
https://docs.hetzner.cloud/reference/cloud#zone-rrset-actions-add-records-to-an-rrset:
unchanged, nothing to fix.

Checked again in 1.0.27 against the collection of 2026-11-03
(`api-docs/hetzner/`): Hetzner switched the old DNS Console and its API off on
2026-05-27 ("The DNS console and API was removed"), so the choice of it is gone
- a validation still set to it is refused in words. An `add_records` sends a
TTL only for a new RRset ("If set, and the RRSet being updated already has a
TTL, the values must be the same"); every write's action is waited for until
`success` (or its error said); a `423 locked` is tried again; cleanup reads the
RRset and removes only our value, and nothing when it is gone.

### Hostinger (`hostinger`)

hPanel → *Account* → **API** → *New token* (best with an expiry). acme
reads the domains (`GET /api/domains/v1/portfolio`), reads the zone (`GET
/api/dns/v1/zones/{domain}`), adds its value (`PUT /api/dns/v1/zones/{domain}`
with `overwrite: false` - added to the RRset), and on cleanup writes the
RRset back without it (`overwrite: true`) or deletes it (`DELETE` with
`filters: [{name, type}]`) when ours was its last value. A domain whose DNS
is at Hostinger but not in the portfolio is asked for by name.

Verified against: https://github.com/hostinger/api-python-sdk -
`docs/DNSZoneApi.md` (get_dns_records_v1, update_dns_records_v1,
delete_dns_records_v1), `docs/DomainsPortfolioApi.md` (get_domain_list_v1),
`docs/DNSV1ZoneUpdateRequest.md`, `docs/DNSV1ZoneDestroyRequest.md`,
`hostinger_api/configuration.py` (https://developers.hostinger.com); the
reference https://developers.hostinger.com/#tag/dns-zone; lego
`providers/dns/hostinger`.

```
token: (the API token)      domain: example.com (or empty)
```

### Constellix (`constellix`)

The Constellix account's **API keys**: the API key and its secret key.
Every request carries `x-cns-security-token: KEY:HMAC:TIME` (TIME in
milliseconds, HMAC the base64 HMAC-SHA1 of it with the secret - this
machine's clock must be right). A Constellix TXT record holds every value
of its name (`roundRobin`, each in quotes): acme adds its value to it
(`PUT .../records/txt/{id}`, or `POST .../records/txt` for a new name) and
writes it back without its value on cleanup (or `DELETE`s it when ours was
the last).

Verified against: https://github.com/Constellix/constellix-go-client
(`client/client.go` - `https://api.dns.constellix.com/`, `getToken()`;
`models/model_txt.go`) and https://github.com/Constellix/terraform-provider-constellix
(`constellix/resource_constellix_txt_record.go`,
`datasource_constellix_domain.go`, `datasource_constellix_txt_record.go` -
`v1/domains`, `v1/domains/{id}/records/txt` with POST, GET, PUT, DELETE);
the reference https://api-docs.constellix.com; lego `providers/dns/constellix`.

### UltraDNS (`ultradns`)

An UltraDNS user (best one for acme alone) allowed to change the zones'
records. acme signs in (`POST /v1/authorization/token`,
`grant_type=password`), keeps the Bearer token for its lifetime (a 401 or
error 60001 signs in again), lists the zones (`GET /v3/zones`, page by
cursor), and reads, changes and writes back the TXT RRset
(`/v1/zones/{zone}/rrsets/TXT/{owner.}` - POST to make it, PUT to write it,
DELETE when ours was its last value). lego's provider writes and deletes
the RRset whole; acme keeps other values.

Verified against: https://github.com/ultradns/python_rest_api_client
(`src/ultra_rest_client/connection.py` - auth(), _refresh(), errorCode
60001; `ultra_rest_client.py` - get_zones_v3, get_rrsets_by_type_owner,
create_rrset, edit_rrset, delete_rrset) and https://github.com/ultradns/ultradns-go-sdk
(`pkg/zone`, `pkg/rrset`, `pkg/helper` - the JSON fields, cursorInfo); the
reference https://ultra-portalstatic.ultradns.com/static/docs/REST-API_User_Guide.pdf;
lego `providers/dns/ultradns`.

### Mail-in-a-Box (`mailinabox`)

The box's address (`box.example.com`), an administrator's e-mail and
password (basic authentication). An administrator with two-factor sign-in
cannot be used (the session key of `/admin/login` lives two days at most):
make one for acme without it. `GET /admin/dns/zones`, `GET
/admin/dns/custom/{qname}/TXT`, `POST` (adds a value next to the others) and
`DELETE` (removes that one value) with the value as the body; the box then
writes its zones and reloads nsd, and keeps the TTL itself.

Verified against: https://github.com/mail-in-a-box/mailinabox
(`api/mailinabox.yml` - /dns/zones, /dns/custom/{qname}/{rtype};
`management/daemon.py` - dns_zones(), dns_get_records(), dns_set_record();
`management/auth.py` - the session's two days), rendered at
https://mailinabox.email/api-docs.html; lego `providers/dns/mailinabox`.

### EfficientIP SOLIDserver (`efficientip`)

The management appliance's address, a user whose group may use the DNS
services on the zones, and *DNS server* - the server (or SMART architecture)
the zones are on, as SOLIDserver names it (*DNS view* when the zones are in
one). REST API v2.0, basic authentication: `GET /api/v2.0/dns/zone/list`
and `/dns/rr/list` with a `where` clause (`rr_full_name='…' AND
rr_type='TXT' AND server_name='…'`), `POST /dns/rr/add` (`rr_name`,
`rr_type`, `rr_value1`, `rr_ttl`, `server_name`, `view_name`), `DELETE
/dns/rr/delete?rr_id=`. Each value is a record of its own. A private CA:
paste it under *CA certificate*.

Verified against: https://github.com/EfficientIP-Labs/solidserver-go-client
(`sdsclient/api/openapi.yaml` - the servers `https://{host}:{port}/api/v2.0`,
BasicAuth, dns_rr_add_input, the where clause; `sdsclient/docs/DnsAPI.md`,
`DataInnerDnsRrData.md`, `DataInnerDnsZoneData.md`,
`DataInnerDnsRrAddSuccess.md`); lego `providers/dns/efficientip` (the older
`/rest/dns_rr_*` names of the same services). **Less certain**: what the
list answers when nothing matches (an empty list or 204 - both read as
nothing).

### Openprovider (`openprovider`)

An Openprovider user with API access (best its own, limited to acme's
address). acme signs in (`POST /v1beta/auth/login` → a Bearer token, kept
six hours, a 401 signs in again), lists the zones (`GET /v1beta/dns/zones`),
reads the TXT records (`GET /v1beta/dns/zones/{zone}/records?type=TXT`) and
adds or removes its own (`PUT /v1beta/dns/zones/{zone}` with `records: {add:
[…]}` / `{remove: […]}`, the name relative to the zone). *DNS*: Openprovider
DNS or Premium DNS (Sectigo) - the zone's `provider`.

Verified against: https://github.com/openprovider/rest-client-php
(`src/Auth/Api/AuthApi.php`, `src/Dns/Api/ZoneServiceApi.php`,
`src/Dns/Api/ZoneRecordServiceApi.php`, the models `ZoneUpdateZoneRequest`,
`ZoneRecordUpdates`, `ZoneRecord`, `RecordRecordInfo`,
`src/Base/Configuration.php` - https://api.openprovider.eu) and
https://github.com/openprovider/Openprovider-WHMCS-domains
(`OpenProvider/API/ApiHelper.php` - removeDnsRecord(), updateDnsRecords(),
the zone's provider; `Controllers/System/DnsController.php` - names listed
whole, written relative). No lego provider to compare. **Less certain**:
the token's lifetime, the lowest TTL (600 is used), whether `type=TXT` is
honoured by the list (filtered again here).

### easyDNS (`easydns`)

The API token and API key of the easyDNS control panel (basic
authentication; `?format=json` on every call). `GET
/zones/records/all/{domain}`, `PUT /zones/records/add/{domain}/TXT` (`{domain,
host, ttl, prio, type, rdata}`), `DELETE /zones/records/{domain}/{id}`. The API
lists domains only by user name, so the domain is the one set or found by
its SOA; *User name* lets *Test* read the list (`GET /domains/list/{user}`).
TTL 300 to 86400. *API*: the sandbox `sandbox.rest.easydns.net`.

Verified against: https://github.com/easydns/easydns-mcp (easyDNS's own:
`docs/API-REFERENCE.md`, `src/auth.ts`, `src/client.ts`,
`src/tools/dns-records-list.ts`, `dns-record-add.ts`, `dns-record-delete.ts`,
`domain-list.ts`); the reference https://docs.sandbox.rest.easydns.net; lego
`providers/dns/easydns`.

### Plesk (`plesk`)

The Plesk server (port 8443 when none is given), signed in with a login and
password (`HTTP_AUTH_LOGIN` / `HTTP_AUTH_PASSWD`) or an XML API secret key
(`KEY`). `POST /enterprise/control/agent.php` with XML packets: `site get`
(by name; with an empty filter, every site) for the domain's id, `dns
get_rec` by `site-id`, `dns add_rec` (`site-id`, `type` TXT, `host`
relative, `value`), `dns del_rec` by `id`. Each value is a record of its
own.

Verified against: https://github.com/plesk/api-php-lib (`src/Api/Client.php`
- agent.php on 8443, the headers, the packet; `src/Api/Operator/Dns.php`,
`Site.php`, `Operator.php`, `SecretKey.php`; `src/Api/Struct/Dns/Info.php`;
`tests/DnsTest.php`); the reference
https://docs.plesk.com/en-US/obsidian/api-rpc/about-xml-api/reference.28784/;
lego `providers/dns/plesk`.

### Rackspace Cloud DNS (`rackspace`)

A Rackspace Cloud user allowed to change DNS and its API key. acme signs in
at `https://identity.api.rackspacecloud.com/v2.0/tokens`
(`RAX-KSKEY:apiKeyCredentials`), takes the `rax:dns` endpoint from the
service catalog, lists the domains (`GET /domains`), reads the TXT records
(`GET /domains/{id}/records?type=TXT&name=`), adds its value (`POST
/domains/{id}/records`) and deletes only its own (`DELETE
/domains/{id}/records/{id}`). Changes are asynchronous: acme follows the
`callbackUrl` (`?showDetails=true`) until the job is COMPLETED, or says its
ERROR. TTL at least 300.

Verified against: https://github.com/pycontribs/pyrax (Rackspace's SDK,
first published as rackspace/pyrax: `pyrax/identity/rax_identity.py`,
`pyrax/base_identity.py`, `pyrax/clouddns.py` - list, search_records,
add_records, delete_record, _async_call; `pyrax/fakes.py` - the rax:dns
endpoint); the reference https://developer.rackspace.com/docs/cloud-dns/v1/;
lego `providers/dns/rackspace`.

### Modules added in acme 1.0.26: from the vendors' own documentation

These five were written from the official documentation the user collected
from the vendors' sites (`api-docs/<vendor>/notes.md` - verbatim quotes, each
with its URL - and the machine-readable files beside it), and from nothing
else: no lego, no acme.sh. Where the documentation leaves something open,
the module's docstring and the section below say **Less certain** and what
acme does about it. `test/test_dns_providers_docs.py` puts each through a
fake of its API built from those files.

All five find the zone the same way (`_records.SoftZones`): the zone set
(*Zone* is a list to load and pick from - *Load the list* reads the
provider's zones - or typed by hand), else the longest of the zones listed;
when the list cannot be read, or has none for the name, the zone comes from
its SOA and the job says so - the list never stops a run.

### cPanel (`cpanel`)

The cPanel server (port 2083 when none is given), the cPanel user and an API
token (cPanel → Security → Manage API Tokens; `Authorization: cpanel
user:TOKEN`). `GET /execute/DomainInfo/list_domains` for the domains,
`/execute/DNS/parse_zone?zone=` for the zone (owner and content base64, each
line with its `line_index`), `/execute/DNS/mass_edit_zone?zone=&serial=` with
`add={"dname","ttl","record_type":"TXT","data":[value]}` or
`remove=<line_index>` - only the TXT lines at the name holding our value.
The serial must be the zone's current one: acme reads, then writes with the
serial just read, one change at a time on this node, and a refused change
is read again and tried again (three times at most). The zone is the
longest of the account's domains that `parse_zone` reads as a zone (a
subdomain is mostly inside its parent's zone).

Checked against: `api-docs/cpanel/cpanel-uapi-dns-domaininfo.openapi.json`
(cPanel's UAPI OpenAPI 11.138.0.10 - `/DNS/parse_zone`, `/DNS/mass_edit_zone`,
`/DomainInfo/list_domains`, `ResponseRR`, `ResponseBase`, the result envelope)
and `api-docs/cpanel/notes.md`:
https://api.docs.cpanel.net/specifications/cpanel.openapi/dns/dns-parse_zone,
https://api.docs.cpanel.net/specifications/cpanel.openapi/dns/dns-mass_edit_zone,
https://api.docs.cpanel.net/specifications/cpanel.openapi/domain-information/domaininfo-list_domains,
https://api.docs.cpanel.net/cpanel/tokens, https://api.docs.cpanel.net/cpanel/introduction.
**Less certain**: the serial is read from the SOA record of `parse_zone`
(its third field - the documentation only says "the current serial number
in the DNS zone's SOA record"); each item of a TXT record's `data_b64` is
taken for one of its strings; the error words of a serial that moved on are
not documented (any refusal is read again); `dname` is written relative, as
in the documentation's examples; no lowest TTL is documented (300 is used).

```
host: cpanel.example.com      user: alice      token: (the API token)      zone: (empty, or picked)
```

### Joker.com (`joker`)

A DMAPI API key (Joker.com → My Profile → Manage Joker.com API access keys;
"modifications only" is enough) or the account's user name and password;
OT&E (`dmapi.ote.joker.com`) selectable. `POST /request/login` gives the
Auth-SID (kept and shared; a refused request signs in once more and is asked
again, as DMAPI tells), `dns-zone-list` the zones, `dns-zone-get` the zone,
`dns-zone-put` writes it - **replacing the whole zone**. So acme reads the
zone, adds one line (`_acme-challenge.www TXT 0 "<value>" 300`) or takes
away only the TXT lines at that label holding our value, and writes it back
with every other line exactly as read, one change of a zone at a time on
this node; then it reads the zone again to see the change. A zone read empty
is never written. TTL at least 300.

`svc.joker.com/nic/replace` (Joker's own Let's Encrypt helper, with the
domain's Dynamic DNS credentials) is **not** used: it "will replace all TXT
records for the specified label", so a second order's value at the same name
(`example.com` and `*.example.com`) would be taken away.

Checked against: `api-docs/joker/DMAPI-ext.txt`
(https://dmapi.joker.com/docs/DMAPI-ext.txt - Basics and the reply format,
login, dns-zone-list, dns-zone-get, dns-zone-put and its record format) and
`api-docs/joker/notes.md`: https://joker.com/faq/books/reseller-documentation-en/page/basics,
.../page/account-and-handling, .../page/modify-zonedata,
.../page/what-is-an-ote-system,
https://joker.com/faq/books/jokercom-faq-en/page/lets-encrypt-ssl-certificates.
**Less certain**: no real `dns-zone-get` answer is published (it is read as
header lines, an empty line, the zone in the `dns-zone-put` format); whether
the default records left out without `include-defaults=1` stay when the zone
is written back without them; which refusals are "authorization failures"
(any refused request signs in once more); the session's life (an hour without
requests by default - kept 30 minutes); the lowest TTL (300 in DMAPI-ext.txt,
60 on the modify-zonedata page - 300 is used); whether DMAPI's zone calls are
open to accounts that are not resellers.

```
auth: key      api_key: (the DMAPI key)      zone: (empty, or picked)
```

### Netim (`netim`)

A Netim reseller account: its ID and the API password (the DAS password of
*API – DAS – OTE*, not the account's own); OT&E selectable (plain HTTP, as
Netim gives its address). `POST /1.0/session/` (basic authentication) gives
the session, `GET /domains/*` the domains, `GET /domain/{domain}/zone/` the
records; `POST` to the same path `{subdomain, type: TXT, value, options:
{ttl}}` adds one, `DELETE` `{subdomain, type, value}` deletes exactly that
record - other values at the name stay. A change answers an operation:
*Pending* is followed at `GET /operation/{ID_OPE}` until *Done* (or its
*Failed* / *Cancelled* message is said). Netim allows 10 sessions at once:
acme opens one for each piece of work and closes it (`DELETE /session/`).

Checked against: `api-docs/netim/api-secured.wsdl` (SOAP API 2.0 -
`sessionOpen`, `queryDomainList`, `queryZoneList`, `domainZoneCreate`,
`domainZoneDelete`, `queryOpe`, `StructQueryZoneList`) and
`api-docs/netim/notes.md`: https://support.netim.com/en/docs/api-rest-1-0/get-started,
.../sessions-management/open-session, .../close-session,
.../domain-names/get-domains-list,
.../domain-names/domain-services/get-dns-records-list, .../create-dns-zone,
.../delete-domain-dns-zone, .../api-objects/structoptionszone,
.../structoperationresponse, .../operation-management/get-operation-information,
https://support.netim.com/en/docs/resellers/manage-my-reseller-account/sessions-management,
and Netim's official client https://github.com/netim-com/netim-apirest-client-for-python
(`APIRest.py` - the DELETE with its JSON body). **Less certain**: no real JSON
answer is published - a listed record is read by `hostname` or `host` (the
REST page and the WSDL differ), relative or whole; `subdomain` is written
relative (as the example `www`); how a TXT value is quoted (written as it is;
the value deleted is the one listed); the TTL's unit and limits (3600 is
used); a status other than the four documented ones is taken as done, and the
job says so.

```
reseller: NETIM1234      password: (the DAS password)      zone: (empty, or picked)
```

### Huawei Cloud DNS (`huawei_dns`)

An IAM user's access key (AK/SK) allowed to read the zones and change their
record sets, and the region (`https://dns.{region}.myhuaweicloud.com`);
*Project ID* (`X-Project-Id`) and a temporary key's *Security token*
(`X-Security-Token`) where needed. Every request is signed
**SDK-HMAC-SHA256** as Huawei Cloud's signing algorithm says (the canonical
request with the URI ending in `/`, sorted query and headers, `X-Sdk-Date`
and `Host` signed; the signature the HMAC-SHA256 of the string to sign with
the SK) - this machine's clock within 15 minutes. `GET /v2/zones?type=public`
(page by `marker`), `GET /v2/zones/{id}/recordsets?type=TXT&name=<fqdn.>&search_mode=equal`,
`POST` to make the TXT record set, `PUT .../recordsets/{id}` to write it with
our value added (in double quotes) or taken away, `DELETE` when ours was its
last value - one record set a name, read, changed and written back one change
at a time on this node. A set still `PENDING_*` (`DNS.0314`) is tried again
after 2, 4, 8, 16 s; `DNS.0312` on making it reads it and adds to it.

Checked against `api-docs/huawei_dns/notes.md`:
https://support.huaweicloud.com/intl/en-us/api-dns/dns_api_10000.html,
https://support.huaweicloud.com/intl/en-us/api-dns/en-us_topic_0037134406.html,
https://support.huaweicloud.com/intl/en-us/api-dns/dns_api_30003.html,
https://support.huaweicloud.com/intl/en-us/devg-apisign/api-sign-algorithm-001.html
(and its example api-sign-algorithm-002.html),
https://support.huaweicloud.com/intl/en-us/api-dns/dns_api_62003.html,
https://support.huaweicloud.com/intl/en-us/api-dns/CreateRecordSet.html,
ListRecordSetsByZone.html, UpdateRecordSet.html, DeleteRecordSet.html,
https://support.huaweicloud.com/intl/en-us/api-dns/ErrorCode.html,
https://support.huaweicloud.com/intl/en-us/usermanual-dns/dns_usermanual_0601.html,
and the official Go SDK https://github.com/huaweicloud/huaweicloud-sdk-go-v3
(`services/dns/v2/dns_meta.go`, `services/dns/v2/region/region.go`).
**Less certain**: the API reference has no TXT example (the quotes are the
console's rule); taking one value away by `PUT` with the rest is read from
the field's description; path and query escaping beyond the unreserved
characters (acme's are only those); which set is taken when a v2.1 resolution
line makes several at a name (the first); no rate limit and no lowest TTL
beyond "1 to 2147483647" (300 is used).

```
access_key: (AK)      secret_key: (SK)      region: ap-southeast-1      zone: (empty, or picked)
```

### DirectAdmin (`directadmin`)

The DirectAdmin server (port 2222 when none is given), the user and a login
key made for acme (basic authentication; `admin|user` for an admin acting for
a user). The new API (`/api/...`) has no DNS calls, so the legacy one is used:
`CMD_API_SHOW_DOMAINS` (`list[]=`), `CMD_API_DNS_CONTROL?domain=&urlencoded=yes`
(the TXT line, values in quotes), `action=add&type=TXT&name=&value=`, and
`action=select&txtrecs0=<"name=..&value=..">` - that one record away by its
name and value, as listed. Every change is read back: a record not there
after the add, or still there after the delete, is said in the job and never
taken for done. No TTL is sent (the zone's own).

Checked against `api-docs/directadmin/notes.md`:
https://docs.directadmin.com/developer/api/,
https://docs.directadmin.com/developer/api/legacy-api.html,
https://docs.directadmin.com/changelog/version-1.24.2.html,
https://docs.directadmin.com/changelog/version-1.26.4.html,
https://docs.directadmin.com/changelog/version-1.28.2.html,
https://docs.directadmin.com/changelog/version-1.31.0.html,
https://docs.directadmin.com/changelog/version-1.53.1.html, and
`api-docs/directadmin_ssl/directadmin-swagger.json` (no DNS paths).
**Less certain**: `CMD_API_DNS_CONTROL` is described only in the changelog,
with no TXT example - `type=TXT` and `txtrecs0` follow the pattern
documented for the other types (`arecs0`, `nsrecs0`, … and the "txtrecs"
section); whether a TXT value goes with its quotes (added without, deleted
as listed); the shape of an error answer (`error=1&text=&details=`, as the
other legacy calls).

```
host: server.example.com      user: alice      password: (the login key)      zone: (empty, or picked)
```

### Modules added in acme 1.0.27: from the vendors' own documentation

Six more, written the same way as those of 1.0.26: only from the official
documentation the user collected (`api-docs/<vendor>/notes.md`, verbatim
quotes each with its URL, and the files beside it), nothing else; what it
leaves open is **Less certain** in the module's docstring and here, and notes
marked "odvozeno" (derived) or "neoficiální" (unofficial) were taken only with
such a mark. `test/test_dns_providers_panels.py` puts each through a fake of
its API built from those files. The five with an API find the zone as the
1.0.26 ones do (`_records.SoftZones`: the zone set - a list to load and pick
from, or typed - else the longest listed, else its SOA).

### Forpsi F-DNS (`forpsi`)

Only **F-DNS**, Forpsi's paid DNS-as-a-service (DNSaaS, from 500 domains), has
an API; **ordinary Forpsi DNS** - the free DNS hosting with a domain or a web
hosting - has none (its web administration and a CSV import only). For a
domain there, point `_acme-challenge.NAME` by a CNAME to a zone acme can write
(acme's own DNS, acme-dns, a provider with an API) and use that validation.

The F-DNS token (admin.forpsi.com, with DNSaaS active) goes in the header
`token:`. `GET https://api.forpsi.com/dnsaas/v1/domains` (page by `skip` /
`limit`, up to 1000) for the domains, `GET .../domains/{domain}/records` for
the records (no filter by name or type: read page by page and ours picked
out), `POST` the same `{name, type: TXT, data, ttl}` - the record with its
`id` comes back - and `DELETE .../records/{id}`: only ours goes. TTL 60 to
86400, no publish step. *Test* reads `GET /` (domains used / allowed) and the
domains.

Checked against `api-docs/forpsi/openapi.json` (OpenAPI 3.1.0 from
https://api.forpsi.com/dnsaas/v1/docs/) and `api-docs/forpsi/notes.md`:
https://www.forpsi.com/ForpsiCZ/media/Forpsi/Documents/tc-files/ICZ_podminky_DNS.pdf
(art. IV - the API only for the business service), https://www.forpsi.com/f-dns/,
https://support.forpsi.com/kb/a4408/importing-dns-records.aspx (TTL range).
**Less certain**: whether `name` is relative (the specification's example is
`subdomain`: written relative, read relative or whole); the apex (`@` written);
whether TXT `data` goes with quotes (sent as it is, compared without them);
error answers beyond `{"msg": "Invalid token"}`; how soon the name servers
have a change.

```
token: (the F-DNS token)      zone: (empty, or picked)
```

### ISPConfig (`ispconfig`)

A remote user of the panel (*System → Remote Users*) with the function groups
**DNS zone functions** and **DNS txt functions**, acme's address among its
allowed ones, and the Remote API allowed in the security settings. acme
speaks the JSON transport: `POST https://PANEL:8080/remote/json.php?FUNCTION`
with the PHP function's parameters by name, the answer `{code: "ok", message,
response}`. `login` gives the session (closed with `logout` at the end of each
piece of work), `dns_zone_get` with `{origin: "example.com."}` the zone's `id`
and `server_id` (with `-1` every zone - the form's list),
`dns_rr_get_all_by_zone` the records, `dns_txt_add` (`update_serial: true`, so
the SOA serial is raised and the secondaries take it) adds ours and answers
its id, `dns_txt_delete` deletes exactly that id - other values at the name
stay. The name is relative (the BIND template appends the origin), the value
without quotes (the template adds them), TTL at least 60. ISPConfig applies a
change through its server cron (about a minute): acme waits until the zone's
name servers have it.

Checked against `api-docs/ispconfig/notes.md` - the official ISPConfig 3.3.2p1
package (https://www.ispconfig.org/downloads/ISPConfig-3-stable.tar.gz):
`remoting_client/API-docs` (login, dns_txt_add, dns_txt_delete,
dns_rr_get_all_by_zone, dns_zone_get_by_user), `remoting_client/examples`
(rest_example.php, dns_txt_add.php, dns_txt_delete.php),
`interface/lib/classes/json_handler.inc.php`, `remoting.inc.php`,
`remoting_lib.inc.php`, `remote.d/dns.inc.php`, `dns_txt.tform.php`,
`server/conf/bind_pri.domain.master`. **Less certain**: which `client_id`
`dns_txt_add` wants (the example has 1, its meaning is not documented - 0 is
sent unless *Client ID* is set); `dns_zone_get` by an origin filter or `-1` is
documented for `getDataRecord` as a whole; whether an origin is stored with
the final dot (both are asked); the example's `stamp` / `serial` params (sent
as it sends them); the highest TTL.

```
url: panel.example.com:8080      user: acme      password: (the remote user's)      zone: (empty, or picked)
```

### HestiaCP (`hestiacp`)

An access key of the user who owns the DNS domains (or an administrator's;
`v-add-access-key` or the panel) allowed `v-list-dns-domains`,
`v-list-dns-records`, `v-add-dns-record` and `v-delete-dns-record`, and acme's
address in the API's allowed addresses. Each call is a form POSTed to
`https://SERVER:8083/api/` (`hash=ACCESS:SECRET`, `cmd`, `arg1`...):
`v-list-dns-domains USER json`, `v-list-dns-records USER DOMAIN json`,
`v-add-dns-record USER DOMAIN RECORD TXT VALUE` (with `'' '' yes TTL` after it
when a TTL is set) and `v-delete-dns-record USER DOMAIN ID` - with
`returncode=yes`, the answer is the exit code, said in words when it is not 0
(`E_NOTEXIST`, `E_FORBIDEN`, ...). `v-add-dns-record` gives no ID back, so the
records at the name are listed and ours found by its value; cleanup deletes
only those IDs (`E_NOTEXIST` there is a record gone already). The name is
relative, the value without quotes ("will be striped of quotes"); each
command raises the serial, rewrites the zone and reloads the DNS server
itself.

Checked against `api-docs/hestiacp/notes.md`:
https://hestiacp.com/docs/server-administration/rest-api.html,
https://hestiacp.com/docs/reference/api.html,
https://hestiacp.com/docs/reference/cli.html,
https://github.com/hestiacp/hestiacp-api-examples and the source of
`web/api/index.php`, `bin/v-add-dns-record`, `bin/v-delete-dns-record`,
`bin/v-list-dns-records`. **Less certain**: the JSON of `v-list-dns-domains`
(its keys taken for the domains); how empty arguments 6 and 7 are taken when a
TTL is sent; no TTL limits are documented (empty: the zone's); the HTTP status
of a failed command with `returncode=no` (any other than 200/204 is said).

```
host: server.example.com      user: alice      access_key: (the key ID)      secret_key: (its secret)
```

### Virtualmin (`virtualmin`)

The master administrator (the Remote API is open to it only), by HTTP basic
authentication, `POST https://SERVER:10000/virtual-server/remote.cgi` with
`program=` and the program's options as parameters (`name=value` is
`--name value`, an empty value the bare option); the answer ends with `Exit
status: N`, and anything but 0 (or `ERROR:`) is said. `list-domains
--with-feature dns --name-only` for the zones (the virtual servers with DNS),
`modify-dns --domain Z --add-record-with-ttl "NAME. TXT TTL VALUE"` to add, and
`modify-dns --domain Z --remove-record "NAME. TXT VALUE"` - **always with the
value**: without it Virtualmin deletes every record of that name and type.
The name is written whole with its final dot. `modify-dns` does not refuse a
record that clashes or lies outside the domain (it only prints a line), so
the zone's TXT records are read again after each change (`get-dns --type TXT
--multiline`) and a change that did not happen is said. modify-dns raises the
serial and reloads BIND itself. A sub-server may keep its records in its
parent's zone: set *Virtual server* then.

Checked against `api-docs/virtualmin/notes.md`:
https://www.virtualmin.com/docs/development/remote-api/,
https://www.virtualmin.com/docs/development/api-programs/modify-dns/,
.../get-dns/, .../list-domains/ and the source of virtualmin-gpl (`remote.cgi`,
`modify-dns.pl`, `feature-dns.pl`). **Less certain**: get-dns's output is not
documented beyond its options (acme only looks for our value in it, as a word
of its own); the JSON form (`json=1`) is not documented and not used; whether a
TXT value is stored with quotes (sent without); no lowest TTL (60 is sent);
the Remote API has no token or address limit of its own.

```
host: server.example.com      user: root      password: (the master administrator's)      zone: (empty, or picked)
```

### froxlor (`froxlor`)

An API key and its secret (froxlor → your name → *API keys*; *Settings → System
settings → Enable external API usage* on), by HTTP basic authentication; every
call is `POST https://FROXLOR/api.php` with `{"command": ..., "params": ...}`.
`Domains.listing` (an admin's key) or `SubDomains.listing` (a customer's) for
the domains - a zone is a main domain (`parentdomainid` 0) with DNS on;
`DomainZones.listing {domainname}` for its entries, `DomainZones.add
{domainname, record, type: TXT, content, ttl}` to add, `DomainZones.delete
{domainname, entry_id}` to delete exactly ours (a `304` there is an entry gone
already). `add` answers the zone file, not the new id, so ours is found by its
record + type + content. The record is relative (at most 63 characters), the
value without quotes. froxlor writes the zone through its cron (`REBUILD_DNS`),
so acme waits until every name server has the record.

froxlor's documentation and code differ, and the code is taken: an error's
words are in `message` (the guide says `status_message` - both are read), and
`Certificates.add` takes `domainid` where the guide says `id` (DomainZones
take `domainname`, used here).

Checked against `api-docs/froxlor/notes.md`: https://docs.froxlor.org/latest/api-guide/,
https://docs.froxlor.org/latest/api-guide/commands/domainzones.html and froxlor
2.3.16's source (`FroxlorRPC.php`, `Response.php`, `Commands/DomainZones.php`,
`Dns.php`, `doc/example/list_functions.php`). **Less certain**: the fields of
a Domains / SubDomains listing entry (`parentdomainid`, `isbinddomain` read
where present); no lowest TTL (0 or less becomes 18000 - 60 is sent); how long
until the cron writes the zone.

```
url: froxlor.example.com      api_key: (the key)      api_secret: (its secret)      zone: (empty, or picked)
```

### Windows DNS (`windows_dns`)

Windows Server DNS has no REST API; acme signs in over **OpenSSH for Windows**
(the DNS server itself, or a machine with the DNS Server Tools and *DNS server
for the cmdlets* set) and runs the DnsServer cmdlets in PowerShell - the
PowerShell flavour of `ssh_dns` as a validation of its own:
`Add-DnsServerResourceRecord -ZoneName Z -Name N -Txt -DescriptiveText VALUE
-TimeToLive ...` only when `Get-DnsServerResourceRecord -ZoneName Z -Name N
-RRType Txt -Node` does not hold the value, and `Remove-DnsServerResourceRecord
-ZoneName Z -RRType Txt -Name N -RecordData VALUE -Force` only when it does -
**never without `-RecordData`** ("If you do not specify RecordData, the cmdlet
deletes all records that match RRtype and Name") and with `-Force` (else it
waits for a confirmation). `-Node` keeps the names below `N` out. The name is
relative to the zone. Windows raises the serial itself; an AD-integrated zone
reaches the other domain controllers by replication - acme waits for every
name server. *Test* runs `Get-DnsServerZone`. The account must be allowed to
change the zone (DnsAdmins); the SSH key card says where its public half goes.

Checked against `api-docs/windows_dns/notes.md`:
https://learn.microsoft.com/en-us/powershell/module/dnsserver/add-dnsserverresourcerecord,
.../remove-dnsserverresourcerecord, .../get-dnsserverresourcerecord,
.../get-dnsserverzone, https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/37eea101-00b8-4958-99eb-de8cda4b8417,
https://learn.microsoft.com/en-us/windows-server/networking/dns/dynamic-update.
**Less certain**: `-RecordData` for a TXT record is documented only by an A
record's example (the text is given as written); the property
`RecordData.DescriptiveText` of a listed record is the WMI class's, not in the
cmdlet's page; no lowest TTL (60 is used); how long AD replication takes.

```
host: dc1.example.com:22      user: acme      key: (made here)      zone: example.com
```

### Re-checked in 1.0.27: checked against the collection of 2026-11-03

The modules below were compared with the same collection, call by call. What
the documentation showed differently was changed; the rest is confirmed as it
was.

* **Cloudflare** (`api-docs/cloudflare/`, openapi-dns-zones.json): confirmed -
  each value its own record, deleted by `id`; `name` is the whole name; TTL 60
  to 86400 or 1. *Changed*: a listed TXT `content` comes back in quotes
  ("Cloudflare will automatically add double quotes"), so a cleanup without
  the record's id (and the lookup after an identical-record refusal) compares
  it unquoted - before, such a record was left behind.
* **Route 53** (`service-2.json`): confirmed - the RRset written whole (UPSERT,
  DELETE with exactly the values read), values in quotes, a public zone chosen
  over a private one, `GetChange` until `INSYNC`, `PriorRequestNotComplete` /
  `Throttling` tried again.
* **Azure DNS** (`dns-2018-05-01.json`): *changed* - the record set is written
  back with `If-Match: <etag>` (`If-None-Match: *` for a new one), keeping its
  TTL and metadata, and read again when the etag no longer matches; confirmed:
  relative names, one unquoted string an item.
* **Google Cloud DNS** (`dns-v1-discovery.json`): confirmed - `changes.create`
  with the RRset as read in `deletions`, FQDN with the dot, quoted values,
  public zones only. *Changed*: `managedZones.list` is followed by
  `nextPageToken`; the RRset keeps its TTL when ours is added or taken away.
* **DigitalOcean** (`openapi-domains/`): confirmed - relative name on create,
  the FQDN as the list's filter, deleted by id, TTL at least 30.
* **OVHcloud** (`domain-zone-dns.json`): confirmed - `$1$` signature, the
  target unquoted, `POST .../refresh` after each change, the id-0 bug (the
  record then found by its target). *Changed*: a TTL is 0 or at least 60 (as
  OVH's Terraform provider checks).
* **Hetzner** (`cloud-dns-zones-rrsets.json`): see *Hetzner, checked again*
  above - the old API removed (2026-05), the TTL only for a new RRset, actions
  waited for, `423` tried again.
* **Gandi** (`livedns-reference-extract.txt`): *changed* to `PATCH`
  `add_rrset_values` / `remove_rrset_values` (POST for a new RRset); confirmed:
  quoted values, TTL at least 300. The new `verification` endpoint only adds,
  so it is not used.
* **GoDaddy** (`domains-v3.json`): *changed* to v3 with a personal access token
  (one record a value, deleted by `recordId`, TTL 600 to 86400, pages followed);
  v1 with the key and secret kept selectable, and used by validations saved
  with them.
* **Porkbun** (`openapi-dns.json`): confirmed - all POST with the keys in the
  body, *API Access* per domain, TTL at least 600, deleted by id. *Changed*: a
  `DUPLICATE_RECORD` refusal's `existingId` is taken as ours.
* **Infoblox** (WAPI, `notes.md`): confirmed - one `record:txt` a value with
  its `_ref`, FQDN without the dot, unquoted text, `_max_results` given.
  `restartservices` is not called: the documentation does not say a TXT
  record needs it, and it would also apply other administrators' pending
  changes.
* **PowerDNS** (`authoritative-api-openapi.yaml`): *changed* - `EXTEND` /
  `PRUNE` (only our record added / taken away) from 4.9.12 and 5.0.2 (the
  version read from `/servers/{id}`), REPLACE with the rest, its TTL kept, on
  older ones; the zone addressed by the `id` the server lists. Confirmed:
  quoted content, `Accept: application/json`.
* **NS1** (`notes.md`, the reference behind a bot check): confirmed - PUT
  creates, POST changes, FQDN `domain`, unquoted answers. *Changed*: the other
  answers are written back exactly as read (their `id` and `meta` kept), the
  zone list follows its `Link` header.
* **Akamai Edge DNS** (`edge-dns-v2-openapi.json`): confirmed - EdgeGrid
  (body hashed for POST only), FQDN names, quoted rdata, the record set read
  and written whole. *Changed*: the zone list asks `types=PRIMARY` in
  capitals, as the specification's enum.
* **RFC 2136** (RFC 2136, 8945, 1035): confirmed - "Delete An RR From An RRset"
  (CLASS NONE, TTL 0, exactly our RDATA), never CLASS ANY; TSIG last in the
  additional section, fudge 300; the trial update of *Test* has only a
  prerequisite.
* **cPanel, DirectAdmin, Joker.com, Netim, Huawei Cloud DNS** (1.0.26): the
  collection is the same for them - confirmed as described above, their
  Less certain points still open.
* **`ssh_dns`'s PowerShell flavour** now runs the same commands as
  `windows_dns` (`-Node`, `-RecordData`, `-Force`); before, a record was
  removed by piping `Get-DnsServerResourceRecord` without `-Node` into
  `Remove-DnsServerResourceRecord`.


### Not added

* Selectel, Reg.ru, Yandex, Timeweb and the other Russian providers: left
  out on purpose (sanctions).
* Microsoft DNS over WinRM: WS-Management needs NTLM (or Kerberos) on one
  kept-open connection and, by default, the SOAP body sealed by NTLM -
  ctx.http keeps no connection between requests. Windows DNS is reached
  over OpenSSH by `windows_dns` (1.0.27) or `ssh_dns` (its PowerShell
  flavour) - RFC 2136 only to a zone that takes unsigned updates, as Windows
  signs updates with GSS-TSIG (Kerberos) only.
* PowerDNS-Admin: it fronts a PowerDNS server whose own API `powerdns`
  speaks; PowerDNS-Admin's own API keys were not added.
* Variomedia, One.com: not this time (One.com's API is not documented).
* Dynadot (looked at again in 1.0.26): its API3 `set_dns2` rewrites every
  record unless `add_dns_to_current_setting=1` and cannot remove a single
  record; the DNS calls of its new REST API sit behind a script-only page and
  are not in the collected documentation (`api-docs/dynadot/notes.md`) - left
  out until they are copied from https://www.dynadot.com/domain/api-document.
* BlueCat Address Manager (looked at again in 1.0.26): the RESTful v2 API's
  sessions, zones and `resourceRecords` (a TXT record is a resource of its
  own, deleted by its id) are documented, but the body of a quick deployment
  (`POST /api/v2/zones/{id}/deployments`) and the `TXTRecord` schema (TTL,
  quotes) are only in the OpenAPI document each Address Manager serves itself
  (`/api/openapi.json`), not in the public guide (`api-docs/bluecat/notes.md`).
  Without the deployment the record never reaches the DNS servers, so it is
  left out until that document is at hand.
* Looked at in 1.0.22 and left out because no vendor SDK, API description
  or official integration with the DNS calls could be read where the
  modules were written (only GitHub could be reached; lego or acme.sh alone
  is not enough to confirm an endpoint): Nicmanager, Zonomi, NameBright,
  ArvanCloud (its official Terraform provider covers only its cloud
  servers), ISPConfig, Forpsi (no public DNS API - both came in 1.0.27, from
  the vendors' own documentation: ISPConfig's Remote API, Forpsi's F-DNS).
  Volcengine does have an
  official SDK, but its request signing was more than that round could test
  against published examples - maybe later. (Netim, DirectAdmin, cPanel,
  Joker.com and Huawei Cloud DNS came in 1.0.26, from the vendors' own
  documentation - above.)
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
| `powershell` | Windows DNS | `Add-DnsServerResourceRecord` when the name (`Get-DnsServerResourceRecord -Node`) lacks the value / `Remove-DnsServerResourceRecord -RecordData VALUE -Force` - never without `-RecordData`, which would take every TXT record of the name (OpenSSH for Windows; also the validation `windows_dns` of its own) | the account in DnsAdmins; *Zone* as DNS Manager shows it |
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
