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
| `acme_dns` | an [acme-dns](https://github.com/joohoi/acme-dns) server | account(s); `_acme-challenge.NAME CNAME <fulldomain>` once |
| `ssh_dns` | commands on the DNS server over SSH: `nsupdate -l`, `nsupdate -k`, PowerShell `Add-DnsServerResourceRecord` (Windows DNS via OpenSSH), or your own (edit a zone file + `rndc reload`) | an SSH account there (sudo optional) |
| `script` | a program on this machine (`present`/`cleanup`, dehydrated- or lego-style), `ACME_*` variables | the program |
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
* **Throttling**: a `429 Too Many Requests` is waited out as long as its
  `Retry-After` says (at most 60 s, three times) and the job says so; then
  it fails with "try again later".
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

* **BIND on that machine**: `nsupdate -l` uses BIND's local session key; the
  zone needs `update-policy local;` (or `{ grant local-ddns zonesub any; };`).
  The SSH user must read `/run/named/session.key` (group bind/named) or use sudo.
* **A TSIG key file there**: `nsupdate -k /etc/bind/acme.key`, sent to the
  server set (127.0.0.1 by default).
* **Windows DNS**: OpenSSH Server on the DNS server (or a machine with the
  DnsServer RSAT module, `-ComputerName`); the account in DnsAdmins. The zone
  must be set as DNS Manager shows it.
* **Your own commands**: `{fqdn} {relative} {zone} {value} {ttl} {name}` are
  put in shell-quoted, e.g. a zone file included by the real one:

  ```
  add:  printf '%s 60 IN TXT "%s"\n' {fqdn}. {value} >> /var/named/acme-challenge.inc && rndc reload {zone}
  del:  sed -i /{value}/d /var/named/acme-challenge.inc && rndc reload {zone}
  ```
  (the zone's SOA serial must change for secondaries: prefer `nsupdate -l`).

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
