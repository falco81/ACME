# Changes in acme

Newest first. Each version's section is what the pages show before an
upgrade (and, going back, what is given up), so it says what changed for
the people who run acme - one `## X.Y.Z - date` heading per version.

## 1.0.34 - not released

- Import of a dual certificate (RSA and ECDSA of the same names): a file
  holding both halves with their keys is imported as the certificate and its
  twin at once; the other half imported into a certificate later is kept as its
  twin (the same names, the other key type - guessed, or *Kept as* in the
  window, `"as": "alt"` on the API), not as its next version, which put the
  first half away.
- Settings → Certificates and TLS → *Download* of a dual certificate asks which:
  the main one, the second one beside it, or both in one PEM - it gave the main
  one only, so the second could not be had.

- Tests: a server sending the other half of a dual certificate acme keeps only
  one half of (the same names, ECDSA where acme has the RSA one) is said as
  that - "serves the ECDSA twin of this certificate ... import it as its twin,
  or set Key asked for" - not as a stranger's certificate. A test's new *Key
  asked for* (whichever, RSA, ECDSA): TLS 1.2 with ciphers of that key only, so
  a dual server sends that one.

- Modules → a module → *Download a start* asks first: only a start (a few
  lines that take the module as it is) or the whole code of a version - the
  shipped one, any of yours, or the shipped original under a replacement - its
  class already saying the version and label you named (or, for a replacement,
  the shipped version): change a line and upload it. A file of two modules
  (tls.py: tls and https) copies only the one asked for. The upload window has
  *Start from the whole code of* too.
- A shipped module replaced: its original stays listed under your replacement
  - "shipped original - replaced, not used", its own *Download this code* (the
  shipped code, not yours). Every row says *Download this code*; the
  replacement's upload button is *Upload a new replacement*; the card says what
  is in use instead of what.
- A long popup opens at its top: a box far down (the version of a module of
  your own) is not focused, so the window does not open scrolled to it.

- A name box just opened is not red yet ("it needs a name" said before anything
  was typed - a new authority, say): said once something is typed or the box is
  left; the main button is off meanwhile, as before.
- A test's window is called "Test mail-smtp" in Czech (it stayed "The test
  mail-smtp": a name with a hyphen in it). "No tag." in Czech in a form's tags.

## 1.0.33 - 2026-11-03

- Settings → Accounts: an account's role is changed in its own column - beside
  the buttons the row ran past its card. About: a node's name apart from its tag.

- A module's tags (own, uploaded, override, version, marks) look one way
  everywhere - the same height, corners and letters, apart by a gap - and in the
  "Add a …" tiles they sit in a row of their own at the bottom left.

- Import of a PEM with its key locked: the password is asked for above what was
  read (it said "no private key in the file", and asked nothing); typed in the
  file's password box, the file is read again; the key's password works for a
  key inside the file too. A key in a file of its own, dropped beside it, is
  said as "its key: …", not "no key". A wrong password says so, not "give its
  password". The read notes in Czech.
- Modules → a module: making one of your own said as two ways - another version
  beside it (named: as many as needed, each with its version and label) or the
  shipped one replaced - each "Download a start" and "Upload it". A file of your
  own starts from the shipped module, never from another uploaded one. An
  uploaded version: "Upload a new file" replaces it. The window is drawn again
  after an upload, a mark or a file taken away (it showed what was there
  before). The upload window: its parts apart. The list: every module's icon
  in one column under its heading, a stripe (your own, the row under the
  pointer) beside it, not over it.

- Import of a certificate did nothing: the Import button broke on a box of
  its window (the owner) it could not see. It imports again.
- Tests on a server over SSH: can be saved with no test chosen yet; the tests
  it runs are a table with "Add a test" under it, as a certificate's
  deployments are, not ticks.
- A certificate's Tests: a table as its Deployments - test, state, where, last
  run - its buttons under it on the left; what the server served opens from
  the row.
- Tests: switched on and off right in the list, as targets are.
- HTTPS test: "Ask over HTTP too" says that it brings the method, path, Host
  header and other headers.

- Settings → Modules: its icon in the rail; the pane as tall as the window, only
  its list scrolls (there were two scroll bars); no lede said twice. A
  module's window: its sections apart as in every other window.

## 1.0.32 - 2026-11-03

- **Tests of what the servers serve**: Certificates → **Tests** defines
  them as targets are defined - a module, its settings, *Test* - and the
  certificate's window attaches them as it deploys (*Attach a test*). A test
  connects as a client of its protocol would and compares the chain it is sent
  with the certificate: the version deployed (or an old one - the renewal did
  not reach the server - or another certificate), the names, the chain, how
  long it runs, trust here; HTTPS also asks over HTTP with its own Host header,
  path and status expected. Modules: HTTPS, TLS on any port, SMTP (STARTTLS) and
  SMTPS, IMAP / IMAPS, POP3 / POP3S, FTP (AUTH TLS) / FTPS, LDAP (StartTLS) /
  LDAPS, RDP, PostgreSQL, MySQL / MariaDB, Microsoft SQL Server (TLS in TDS),
  XMPP, MQTT, SIP and DNS over TLS - and a **connector** that signs in over SSH
  to a Linux server (the key card of an SSH target) and runs the tests chosen
  for it from there (`ssh -W`). Every setting can be set: the address connected
  to (an IP), the SNI, the name looked for, the certificate expected, TLS
  versions, ciphers, ALPN, the address family and source. Run after the
  certificate's deployments, by themselves (Settings → Renewal and notices:
  *Test the servers by themselves*, every 360 min), or now; a test that starts
  failing is an event, a mail and an SMS (Settings → Message texts: *A test of
  a server failed* / *works again*). *What happens* shows them as a phase of
  their own, one test at a time or side by side. Command line: `--tests`,
  `--check-add` … `--check-attach CERT TEST`, `--checks`, `--check-run`.
  Tests are modules as any: overridden, versioned, uploaded (docs/checks.md,
  docs/writing-a-module.md).
- **Settings → Modules** (was a tab of its own).

- **The page Modules**: every module sources, validations and targets are
  made of - shipped, your own on the disk of a node, uploaded on the page -
  with where it comes from, its versions, how many use each and its marks;
  tiles to filter by origin, the families as chips, a search box as every
  other. *Download* gives the source of any module (a shipped one to start an
  override from); *Make one of your own* a file that subclasses it; *Upload a
  module* takes a `.py` file, checks it in a process of its own and shows
  what it would add or replace before it is kept. Uploading, marking and
  taking away are a full administrator's, written to the events.
- **Versions of a module**: several classes of one kind, each with its
  `module_version` (an API version of a device); each source, validation or
  target chooses its version in its form (cards under *Settings of the
  module*), kept as `_version`; the default by `default_version`. A version
  that is gone is said in red and the default one used meanwhile. Works for
  overrides too - a shipped module without versions can get two of your own.
- **Overrides said**: a module of your own with the kind and version of a
  shipped one replaces it - tagged *override* (orange) wherever the module is
  drawn: its form, the lists, the module picker; one of your own *own module*
  or *uploaded* (violet), a version in blue.
- **Marks**: *tested* (cyan), *works* (green), *problem* (red) on a version of
  a module - set by a full administrator (also `acme --module-mark`), kept
  with the file's sha256 (a file changed since is said), and shipped with a
  release in `acmelib/plugins/verified.json` (outlined, with a shield);
  `acme --module-marks-export` writes the marks of an installation in that
  shape.
- **Modules of your own are backed up**: uploaded ones live in the database -
  in every copy and on both nodes, each node writing them into its own folder;
  the files on the disk (`/etc/acme/plugins`) are kept in the database too,
  in every copy (they were only in a full backup), compared between the nodes
  (the page warns when they differ) and written back by `acme --plugins-sync
  NODE`.

## 1.0.31 - 2026-11-03

- **NetScaler (Citrix ADC): a certkey not there yet is added.** NITRO says
  "not there" as HTTP 599 with an errorcode - `1540 Certificate does not
  exist` for `GET sslcertkey/NAME`, `258 No such resource` - where acme looked
  for 404 only, so the first deployment stopped at *reading acme-NAME: the
  device said 599 - Certificate does not exist* before anything was
  uploaded. Those two codes are read as "not there" for the certkey, its CA
  certkeys and the SSL virtual servers; any other 599 is still an error. A
  copy of the module put in /etc/acme/plugins/targets/ to get round it can be
  deleted after the upgrade (it would go on overriding the one shipped).

## 1.0.30 - 2026-11-03

- **dns-persist-01: a record at each name - a switch.** Let's Encrypt looks the
  record up only at the name it validates (Boulder, va/dns_persist.go:
  `_validation-persist.<the name>`, no look at the domains above): staging
  refused pokus.example.com - *NXDOMAIN looking up TXT for
  _validation-persist.pokus.example.com* - although
  _validation-persist.example.com with policy=wildcard was there, which the
  draft says covers every name under the domain. The new switch **A record at
  each name (Let's Encrypt today)**, off by default - turn it on for Let's
  Encrypt as it is now: each name of a certificate gets, and is checked for,
  its own `_validation-persist.NAME`
  (`policy=wildcard` covers that name and `*.NAME`); *Write the records to DNS*
  and an order write the missing ones through the chosen validation; the
  readiness check says a name without its record is not ready. Off (the
  default): the draft's way - one record of the domain covers the names under
  it, as before. "Domains with the record" is *Names with the
  record*.

## 1.0.29 - 2026-11-03

- Find the settings from the account: a failure is said in its own words
  (it showed "HTTP 200"), with every step of the job; SSLmarket orders that
  cannot be read are a note, the rest is still found.
- Finding the settings from the account on the command line and in the
  console too: `acme --source-discover NAME` (`--validation-discover`,
  `--target-discover`; `-` with `--kind` and `--set` for one not saved) shows
  what the account says beside what is set; `--fill` saves it into the
  settings left empty - nothing set is replaced, a list is chosen with
  `--set`. The console offers it in the menu of each module that has it, and
  `acme --plugin KIND` says what it asks.

## 1.0.28 - 2026-11-03

- **Find the settings from the account** (discovery): over the form of a
  source, a validation or a target, a button opens a popup that asks only the
  sign-in (an API key, a user and password, the address). acme asks the
  account's API - read-only: nothing is ordered, changed or saved - and offers
  what it found beside what the form says: values the form has none of are
  ticked, values it has otherwise are not, lists are a choice. "Fill in the
  ticked ones" puts them into the form; Save keeps them. Every field stays
  settable by hand. SSLmarket takes the product list, the orders and - from
  the last order (or the account's organisation) - the owner, contact, invoice
  data and DCV method; SSLmarket ACME its ACME keys, products and
  organisations. Other sources: their organisations, profiles, products,
  templates, CAs, mounts and roles, the account's contacts, orders to reuse
  (never picked by themselves). DNS validations: the zones the account sees,
  and zone ids, resource groups, servers and views where a module has them
  (Cloudflare, Route 53, Azure, Google Cloud, OVH, PowerDNS, Hetzner,
  DigitalOcean, Infoblox, EfficientIP...). Targets: FortiGate VDOM, F5
  partitions, PAN-OS vsys, Check Point API version and domain, FMC domain,
  Avi version, Azure resource groups, Google Cloud locations, Cloudflare
  zones, Vault KV mounts, Nutanix clusters. Modules with nothing to find show
  no button.

- **Six new DNS-01 validations**, written from the vendors' own documentation:
  Forpsi F-DNS (the paid DNS-as-a-service only - ordinary Forpsi DNS has no
  API), ISPConfig, HestiaCP, Virtualmin, froxlor and Windows DNS (PowerShell
  over OpenSSH, Remove-DnsServerResourceRecord always with -RecordData; the
  Windows flavour of the DNS server over SSH now does the same).
- **Twenty validations re-checked** against the same documentation: Hetzner
  drops the old DNS Console API (switched off in May 2026) and waits for its
  actions; GoDaddy speaks Domains API v3 with a personal access token (v1 kept
  for settings that have a key and secret); PowerDNS uses EXTEND/PRUNE from
  4.9.12 / 5.0.2; Gandi adds and removes values with PATCH; Azure DNS writes
  with the record set's etag; Cloudflare compares TXT values unquoted (a value
  could be left behind); OVH, NS1, Porkbun, Google Cloud DNS and Akamai got
  smaller fixes.
- Active24 and Websupport send the signature's time as X-Date as well (REST API
  v2 asks for it; Date stays); Active24's old API (api.active24.com) is marked
  as the old platform, no longer working. WEDOS lists only the TXT records of
  the name (row_name, rdtype - the whole zone again on an older WAPI, never
  after a refused sign-in) and gives our TXT the TTL a TXT of that name has
  already, as records of one name and type share one there.

- **New sources**, written from the vendors' own API documents: SSL.com (SWS
  API), The SSL Store (REST API) and GlobalSign MSSL (GCC SOAP API). Each
  rekeys or reissues inside an order already bought, places a new paid order
  only with "Allow new orders (paid)", has the certificate's validation put the
  documented record or file in place, downloads with the chain, revokes and
  lists the account's orders for *Import from a source*.
- Sources re-checked against the same documents: ZeroSSL orders annual
  certificates as 200 days and downloads as JSON; Venafi Cloud's EU region is
  api.eu.venafi.cloud and renewals say USER_PROVIDED_CSR; Venafi TPP sends
  Base64 and TypeName as documented; Keyfactor sends IP SANs as "ip" and its
  own revocation codes; GlobalSign Atlas lists certificates 30 days at a time.

- **Targets re-checked against the vendors' own API documents** (16 changed,
  15 confirmed): Kemp keeps a virtual service's other certificates (CertFile is
  the whole list) and stays under 30 calls in 3 s; AWS ACM refuses a renewal of
  another key type in words; Azure Key Vault can keep the certificate as
  PKCS#12 (for Application Gateway); Sophos reads its certificate list from the
  tar the XML API answers with and sets a WAF rule's HTTPSCertificate;
  OPNsense and pfSense replace in place on Force (OPNsense optionally at every
  renewal), pfSense keeps old ones still used by OpenVPN, IPsec or the captive
  portal; A10 takes its older certificate out of a client-SSL template;
  FortiGate picks a VIP's certificate field by FortiOS version (a list from
  7.4.2); Redfish posts to the action target the controller gives and says
  when a controller (HPE iLO 6) cannot take a key; vCenter takes AlreadyExists
  as served already; PAN-OS partial commits as documented; Google Certificate
  Manager warns when an in-place update changes the names.

- **Nine more targets**, written from the vendors' own API documents
  (docs/targets.md names the files and what stays less certain): Cisco FTD
  managed by its Device Manager, Cisco ASA (HTTP Interface for Automation -
  answers read for errors, as the ASA says 200 regardless), Juniper SRX (Junos
  REST API, one commit), Azure Application Gateway (PKCS#12 or a Key Vault
  secret without a version, listeners switched), ISPConfig, HestiaCP (its
  documented commands over SSH), Virtualmin, froxlor and Proxmox Backup Server.
  Not added, and why: Cisco Catalyst 9800, WatchGuard, SonicWall, Meraki,
  pfSense's API.

## 1.0.27 - 2026-11-03

- **New sources**, written only from the vendors' own API documentation
  (docs/sources.md names the files): Sectigo Certificate Manager (Admin API:
  domains validated by CNAME, TXT, HTTP file or e-mail - the record put in place
  by the certificate's validation, domains validated already skipped - a
  certificate profile from a list, collected, renewed or replaced, revoked),
  Certum (SOAP partner API: reissued inside an order, a new order only with
  "Allow new orders (paid)", TXT/CNAME at the domain or `_certum.`, or the file
  certum.txt), GoGetSSL (API v1: reissue, or a paid order when allowed; its API
  cannot revoke - an action asks to cancel the order) and Namecheap SSL (a
  bought certificate activated or reissued, a new one bought only when allowed,
  CNAME or HTTP validation). All four can *Import from a source*.
- AWS Private CA: the template is a list of the 18 end-entity templates AWS
  documents (still typeable, per certificate too). EJBCA: the CA, end entity
  profile and certificate profile are lists (the profile lists likely need
  EJBCA Enterprise; a typed name always works), and an enrollment waiting for
  approval is said as such. DigiCert downloads the certificate by its id, as
  documented. Entrust Certificate Services is not added: its public
  certificates ended on 8 September 2025.

- **Nine new targets**, written from the vendors' own API documents
  (docs/targets.md names the files and what stays less certain): Check Point
  (Management API: a server certificate as PKCS#12, HTTPS Inspection rules and
  gateway portals, publish and install-policy), VMware NSX load balancer (a new
  certificate, the virtual servers' client SSL binding switched, the old one
  deleted), Barracuda WAF (a new certificate, the services' SSL security),
  FortiWeb, FortiADC, Cisco Secure Firewall Management Center (a new Internal
  Certificate, decryption rules switched, deployed), cPanel / WHM
  (SSL::install_ssl / installssl), DirectAdmin and Plesk (into its certificate
  repository; assigned to the site by hand).
- **A deployment's form picks from a list the target fetches** (virtual
  servers, services, rules, policies) - and a value can always be typed.

- **Five new DNS-01 validations**, each written only from the vendor's own
  documentation (docs/validation.md names the files): cPanel (UAPI
  DNS::parse_zone / DNS::mass_edit_zone with the zone's serial, only our record
  removed by its line), Joker.com (DMAPI: the zone read, our line added or taken
  away, every other line untouched), Netim (REST 1.0: the exact record deleted
  by subdomain, type and value; asynchronous operations followed until done),
  Huawei Cloud DNS (record sets, AK/SK signing) and DirectAdmin
  (CMD_API_DNS_CONTROL, deleted by name and value, every change read back).
  Their zone can be loaded as a list or typed; when the list cannot be read, it
  is found by its SOA. What the documentation leaves open is listed as "Less
  certain". BlueCat and Dynadot are left out for now (their deploy call / REST
  DNS calls are not in their public documentation).

## 1.0.26 - 2026-11-02

- **Check again checks again**, and says so: in *Add a certificate* it gave back
  the answer of a moment ago, and the zones found were kept two minutes (a
  delegation just set right still showed as it was); now everything is asked
  anew, and beside the buttons a quiet line says when it was checked, how long
  ago, how long it took and how it came out.

- **A deployment taken off from its row**: beside its Edit, a button that asks
  once in a popup and takes it off (what is on the target stays there).

- **Add only adds, and issues nothing**: the certificate waits as *added, not
  issued* until *Issue now* is pressed in its window (the look right after the
  save issued it at once before).
- **A job's window, opened again**: the certificate's window has *Its running
  job* / *Its last job*, and *Last job* in the list of certificates opens it - a
  job closed while it ran was nowhere to be found.

- **Escape closes a popup at the first press**, everywhere: a help shown by the
  pointer resting on a card or a button took the first Escape, and the popup
  needed a second.

- **A certificate's own web root** (or folder, container, bucket) of an HTTP-01
  validation - *Add a certificate → Settings* - set by a full administrator
  only, as on the module itself; a certificate administrator does not see it,
  and saving the certificate keeps it as it was set. Commands, scripts and sudo
  stay the module's alone.

## 1.0.25 - 2026-11-02

- **Lists loaded from the CA, in the source's form and for each certificate in
  *Add a certificate → Settings*** (one can always be typed): the roles of a
  Vault PKI mount (LIST roles), the certificate profiles of FreeIPA
  (certprofile_find) and the certificate templates of Google CA Service
  (certificateTemplates.list).

- The directory's groups (Settings → Administrators and the teams' members):
  *narrow this list* reads `name:`, `dn~`, `about:` with its funnel too, and the
  box stays as it is while the list under it is drawn again.

- **A search box's fields open only when asked**: by the funnel at the right
  of the box (beside the clearing cross, in its colour) or Ctrl+Space - never by
  themselves, when a popup opens or something is typed; once open they follow
  what is typed. Over a word already typed, a field picked is put after it.

## 1.0.24 - 2026-11-02

- **CZECHIA.COM (ZONER)** checked against its own swagger.json: the zone is read
  (GET /api/DNS/{zone}) before a value is added or taken away, *Test* reads it
  (or lists the domains) instead of saying only a dry run can tell, and the
  TTL is at least 120 s, as the API takes (60 was sent).

- **Active24: both of its APIs**, checked against Active24's own descriptions -
  the REST API v2 (rest.active24.cz: *Test* asks /v2/check, a Service ID alone
  gives its domain by /v2/service/{id}/dns/zone, a domain missing from the
  list of services is asked for itself) and the Active24 API (api.active24.com,
  with a token - chosen under *API*).

- **Tags: sixteen colours**, ten more (teal, cyan, indigo, pink, rose, orange,
  amber, lime, brown, slate), picked from the tag itself shown in each colour.

- **Every search box reads `field:value` and offers as one types**, as Events
  and the outgoing mail did (and otp does): Certificates (`state:failed`,
  `dns:*.example.cz`, `-tag:test`, `source:"Let's Encrypt"`, `renew:no` -
  read by the daemon, the values offered counted over the certificates one may
  see), Sources, Validation and Targets (name, kind, state, use, and every
  setting of their modules as a field: `zone:example.cz`, `product:alpiro*`),
  the records of acme's DNS server, the modules to pick from, Import from a
  source and what an authority signed. `field:a,b`, `-field:x`, `field~part`,
  `*`, `>`/`<`, ranges, `(a OR b)` and NOT as everywhere; what does not read is
  said under the box. Sources and Validation have the search box beside *Add*,
  as Targets.

- **Each certificate its own settings of its source and validations** - no
  second source for each template, product or zone. *Add a certificate* has
  the step *Settings*: every setting of the chosen source and of the
  validations its names use, with what they use, and *Own* to give this
  certificate a value of its own (an AD CS template loaded from the CA, an
  SSLS.cz product, a DNS zone, a TTL...). It follows what is chosen, and the
  renewal, *What happens* and the check of what fits use it. Secrets, where
  and as whom a module signs in, and anything that runs a command or writes a
  file stay the module's (a full administrator's).

- **New sources**, each written from its vendor's own API client (the files
  are named in docs/sources.md): ZeroSSL (REST API, not ACME - CNAME, file or
  e-mail validation, revocation), CyberArk Certificate Manager Self-Hosted
  (Venafi TPP - a policy folder, renewed in place), CyberArk Certificate
  Manager SaaS (Venafi Cloud - an application and its issuing template),
  Keyfactor Command (CSR enrollment with a template and CA, Basic or OAuth)
  and Cloudflare Origin CA (for servers behind Cloudflare). All five can
  *Import from a source*; their forms load the vendor's lists (folders,
  templates, CAs, zones).
- **New validations (DNS-01)**: Hostinger, Constellix, UltraDNS (Vercara),
  Mail-in-a-Box, EfficientIP SOLIDserver, Openprovider, easyDNS, Plesk (XML
  API) and Rackspace Cloud DNS - each from the vendor's own SDK or API
  description, listed in docs/validation.md. acme adds its value beside any
  others and removes only its own; Test changes nothing.
- **New targets**, each checked against the vendor's own code, SDK, Ansible
  collection, Terraform provider or REST specification (docs/targets.md):
  Kong Gateway (SNIs repointed, dual certificates), Nginx Proxy Manager
  (proxy, redirection and 404 hosts), VMware Avi / NSX ALB (virtual services
  or the portal, dual certificates), A10 Thunder (client-SSL templates, write
  memory), Hetzner Cloud and DigitalOcean load balancers (with *List the load
  balancers*), Azure App Service (SNI bindings), bunny.net pull-zone
  hostnames, Fastly TLS (replaced in place, its activations kept) and Nutanix
  (the cluster certificate through Prism Central v4, the cluster picked from
  a list).
- A header an API sends twice (two Set-Cookie) is kept whole.
- Active24: the signed requests of its REST API v2 carry the date as RFC 3339.
  Hetzner was checked against the new Hetzner Cloud DNS API (already used).

- **Microsoft AD CS: the templates loaded from the CA.** *Template* is picked
  from the list the CA offers the user (its Web Enrollment page
  *certrqxt.asp*, read only) - in the source's form, and for each certificate
  in *Add a certificate → Settings*. One not listed (a schema 3 template) can
  still be typed: *Type it yourself…*.
- **Every list a module loads can also be typed** (*Type it yourself…*): a
  product of SSLS.cz, a server type, a template.
- Saving the wizard no longer drops a Vault role or a template set by the API: they are
  the source's settings of the certificate now (*Settings*).
- **Import from a source: each certificate set up like a new one.** After the
  import the wizard of *Add a certificate* opens for it (for several: *Set it
  up* at each, or *Set up each one*): validation, key, renewal, profile,
  deployments - everything the source supports, as for a certificate added
  there. It starts from what the certificate says (its subject, key usages
  and must-staple are kept as its profile); saving keeps the certificate in
  use as it is and makes its next renewal so. Until set up it is marked *to set
  up* in the list.

## 1.0.23 - 2026-11-02

- An upgrade added no column declared last before a table's own rule (UNIQUE):
  the certificate an own authority signs (cert_ca_issued) was not kept.
- **Import from a source** (Certificates, beside *Import*): the certificates
  your account already has at SSLS.cz, SSLmarket, DigiCert CertCentral, Vault,
  EJBCA, FreeIPA, Google CA Service, GlobalSign Atlas or an authority of acme's
  own are listed (only asked - nothing is ordered or changed there), each with
  its names, product, state, validity, what is paid and its id there, *already
  in acme* marked; the ones ticked are imported in one job with an owner, tags,
  a validation and *Renew by itself*, and the popup says what was imported,
  skipped or failed and why. Each stays bound to its source with its own id
  there: a renewal reissues that very SSLS ID or order (free while it runs; a
  new order only with *Allow new orders (paid)*) - no *Certificate to reuse*
  needed. ACME sources cannot list what they issued (docs/certificates.md).
- **Add its private key** in a certificate's window, for one acme holds no key
  of (imported from a source, or from a file without it): pasted PEM or a
  .key/.pem/.pfx/.p12 file, checked to belong to the certificate, then kept
  sealed (a dual certificate's twin too). Until then a deployment that needs the
  key is refused in those words; one that needs only the certificate works. The
  first renewal of an imported certificate makes a new key, held by acme.
- **The clocks of the nodes** (Settings → Time, the card of otp): a node whose
  clock is off refuses right codes of the second step and keeps the VIP
  address. Chosen there: *As until now* (the default - nothing of it runs),
  *Measure and warn* (each node asks the time servers itself over SNTP and
  measures the other node's clock through its database; alerts), or *Step
  aside when not well* (the node whose clock is off steps aside - no lead, no
  DNS answers, the VIP address and /healthz go to the other node - only while
  the other is well, never both). Switches: the codes, the heartbeats and the
  lead's lease, the pauses after wrong tries by the corrected time; step aside
  when the directory cannot be reached. docs/clock-guard.md.
- **When the nodes lose each other**, as otp 1.0.224-1.0.227: the report
  waits for the other node's rows to come over (10 min at most) and counts
  only this time apart, each thing once; with *Only the preferred node* the
  other node goes on when the preferred node's database refuses (PostgreSQL
  shutting down or starting up, or refusing while its machine answers), is
  in maintenance, or stepped aside for its clock; a node that steps aside is
  silent at once; and the question before a code, held off after the other
  database did not answer, is asked every 2 s again - in every mode.
- **A target switched on and off right in its list** (a switch in Targets; off
  asks first when certificates are deployed there). Its deployments are kept;
  on the Certificates list a certificate says "N target(s) off", and in its
  dialog the deployment says "target switched off" - nothing is put there until
  it is on again.
- A switch drawn on was taken as an edit of the person's: a live redraw of a list
  put it back on after it was turned off (the target's switch, and any switch
  whose value changed meanwhile).
- **Show a certificate** (Certificates, beside *Import* - for everybody, read-only
  too): drop any file or paste its text - PEM with any number of blocks, DER,
  PKCS#7 (.p7b/.p7c), PFX/P12 (modern and legacy, a Java PKCS12 keystore too),
  JKS and JCEKS keystores, a CSR, a CRL, a private or public key, base64 without
  its lines, a ZIP of them - and see everything in it in the largest popup. On
  top the chain as a rail, leaf to root: each certificate a station, the
  signature of each link checked, the root in this server's trust store or not,
  a missing issuer said; a keystore's entries by alias. Below, the one picked in
  cards over the whole width: subject and issuer by each part, validity with a
  bar, key, serial (hex and decimal), fingerprints, names, key usage and EKU,
  basic and name constraints, policies (DV/OV/EV), CRL and OCSP addresses, key
  ids, CT SCTs, must-staple, any other extension as its OID and bytes, the PEM
  to copy or download. A locked file asks for its password in the popup (a
  wrong one is said); a JKS shows its certificates even without one. A private
  key is only described - its type, whether it was encrypted, which certificate
  it fits - never sent back. Nothing is kept and nothing changes.
- **Sign a CSR** (Authorities): the request is read as soon as it is pasted or
  read from a file and shown beside the form - its subject, names, key, whether
  it is signed by its own key, the extensions it asks for - with what the
  certificate will get (the issuer, from and until with the authority's end,
  names, key usage, what it is used for). The signed certificate is shown in
  the same viewer with its chain, with *Copy* and *Download*; a CSR in DER (read
  from a file) is signed too.

- What happens with several deployments: a junction - the plan's line branches
  into a track to each deployment's station (its target, module, host, how
  many steps, whether it holds the key); the one picked is shown below over the
  whole width, "All of them" lays them out side by side. On a phone nothing of
  the plan runs wider than the screen any more.

- What happens: a PowerShell command sent as `-EncodedCommand` is shown as the
  script it runs, readable (a password written into it as dots); the encoded
  command as sent stays below, folded.

- The root helper (acme-web.service) writes in the journal each of its parts
  that takes 3 s or more (`journalctl -u acme-web.service`) - a page that waits
  on one of them shows which one held it up.

- Delete with revoke: the certificate stays in the list as "being revoked, then
  deleted" until its CA has it, and only then goes; a revocation that fails
  leaves it "revocation failed" with the reason - nothing deleted, not renewed
  or deployed by itself - with *Delete* (again, with or without revoking) and
  *Keep it* in its dialog.

## 1.0.22 - 2026-11-02

- Settings → SSH server: an error of one read ("the root helper of this node
  did not answer in 60 s", e.g. while the node was being upgraded) no longer
  stays on the node's card after the reads that worked since; a change that
  failed still stays said until one works.
- DNS-PERSIST-01: *Test* says what is still to do as numbered steps (make the
  account, write the record through the chosen validation, choose a fallback)
  and fails only when a certificate would fail - not for an account to be made
  at the first order or a CA not looked at yet.
- DNS-PERSIST-01: a record is read from the zone's own name servers first - a
  record just written read as "not in DNS yet" for up to an hour while the
  resolvers kept the "no such record" of the look before it.
- Each action of a module (a validation's, a source's, a target's) has its own
  icon in the lists - make the record, look, check, write, take away, products,
  discover… - instead of the same gear for every one.

## 1.0.21 - 2026-11-02

- An authority of acme's own keeps every certificate it signs (also a CSR
  signed by hand), so it can be imported later.

- WEDOS (WAPI) as its documentation says: the record's comment sent as
  `author_comment` (was `auth_comment`), every page of the domains (50 a page
  before - an account with more did not find its domain), only primary, active
  domains written to, 2316 ("already exists") taken as done, the rows read in
  either shape, and a refused sign-in holds every call to WAPI for 5 minutes -
  more wrong requests block the address at WEDOS.
- **acme never runs into the limits of the services it talks to**: a
  validation signs in **once** for all the certificates it covers - "What to
  set up" of a Webglobe validation with six certificates signed in six times
  and Webglobe answered *Too Many Attempts*. Sign-in tokens (Webglobe, Azure,
  Google, TransIP, Mythic Beasts, netcup, INWX) are kept for their lifetime per
  validation and settings, a refused sign-in is not tried again for a minute,
  lists of zones and a validation's test are shared for a little while (*Check
  again* right after asks nothing again). Every remote host gets at most two
  requests at once and four a second, from every job together; a `429`, `503`
  or *Too Many Attempts* is waited out (Retry-After, else a growing wait) and
  asked again only where that is safe, the host left alone meanwhile - and the
  job says so. Let's Encrypt's limits for new accounts and orders are kept.
- **Readiness lists are compact**: "6 certificates · 4 ready · 2 need
  attention" on top, what needs attention open and first, what is ready one row
  each (a click opens it), several ready ones folded into one row - in a
  validation's "What to set up", a certificate's *Check* and *Dry run* and the
  wizard. A check opened again within half a minute is not asked again.
- **dns-persist-01 writes its record itself**: *Write the record through*
  picks one of your DNS validations (Active24, Webglobe, Cloudflare, SSH
  DNS…); *Check the records* says per domain whether it is there, missing or
  another value, *Write the records to DNS* writes only what is missing (only
  acme's own older value is replaced, other records are left alone), *Take the
  records away* removes exactly what acme wrote. With *Write it by itself when
  missing* an order writes a missing record first; *What happens* shows it.
  Taking the validation away asks in a popup, with *Also remove its records
  from DNS*.
- *Take it away* in a validation's (source's, target's) own popup asks first -
  it deleted at once.
- A new deployment whose Save is refused (a field missing, a right missing) is
  no longer left behind: every failed Save added another one to the certificate.
- Saving a deployment (or a source, validation, target) no longer asks for a
  required field of a part switched off - "Folder of the store is needed" with
  the IIS Central Certificate Store role off on a Windows server.
- **Delete asks in a popup and revokes first**: *Revoke it first* is ticked
  (with the reason, "no longer used"); the certificate is revoked at its CA and
  then deleted, in one job - a revocation that fails deletes nothing. Where it
  cannot be revoked (not issued, revoked already, self-signed, no source) the
  popup says so. *Revoke* alone stays its own button.
- **SSLS.cz** (`ssls`, docs/ssls.md): a new source for the certificates SSLS.cz
  sells (AlpiroSSL, Sectigo, PositiveSSL, Certum, GeoTrust, DigiCert…) through
  its API SAPI v2. The product is picked from the list SSLS.cz gives (*Load the
  list* in the form - nothing is ordered); DCV by DNS (a CNAME, Certum a TXT) or
  FILE is put in place by the certificate's own validation and taken away
  after, DCV by e-mail needs no validation (the approver address picked from
  those SSLS.cz offers). Renewals are free reissues (`quickReissue`) while the
  subscription runs; a new order is a purchase and is made only with *Allow new
  orders (paid)* on (off by default). *Try it* checks the token and the allowed
  IP address and shows the credit. A form field can now be a list the module
  loads live (the type `catalog`).

## 1.0.20 - 2026-11-02

- *What happens*: a certificate says, step by step, everything a renewal of it
  does - the key and the request (made new or kept, the CSR sent in), every
  call to its source (the ACME protocol in order with its signed payloads, an
  authority of acme's own with the extensions it signs, any other source as
  its module calls it), how each name is proved (the record or file, the
  provider's API calls, the DNS questions, the wait, the cleanup), and for
  each deployment how acme connects (host, port, user, key or password, the
  host key pinned or not, TLS checked or not) and every call with its method,
  address and body, every file with its path, mode and size, every command,
  the check after it - what only the first time does marked, and who is told.
  A button in an opened certificate, and on the last step of Add a
  certificate - from what is set there, nothing saved. It is worked
  out by running each module's own code in a process that can reach nothing
  and change nothing: no device, DNS server or CA is contacted, no file is
  written; passwords, keys and tokens are never shown.

## 1.0.19 - 2026-11-02

- *Wrong codes before it has to be sent again* (Settings → Codes by e-mail and
  SMS) was never asked: a code of the second step sent by mail or SMS could be
  tried any number of times while it was good. It is gone after that many wrong
  tries, and another has to be sent.
- A CA certificate pasted for isemon, for syslog or for another ACME CA lost its
  line breaks in a box of one line - and was then refused when it was used; the
  records of acme's own DNS server could be given only one. These are boxes of
  several lines now.
- An account's role in Settings → Accounts waits for Save in the bar at the
  bottom, as every other change there - it was given the moment the list changed.
- Settings → Time and Upgrades no longer scroll sideways on a phone; a list
  narrower than its words there (the nodes of Upgrades) scrolls in its own box
  rather than laying one cell's tags over the next; a long message (an error
  with a path in it) or address breaks inside its box instead of running off it.
- In Czech: what a screen reader is told of a setting whose help has a name or
  an address in it, the words of *Give the disk back*, of the Teltonika check,
  of restarting PostgreSQL, of stopping a system update and *on the VIP address
  only* (DNS server) are translated.
- SSH DNS: the server nsupdate sends to is checked (one host and a port);
  Microsoft AD CS: more attributes saved as text are read line by line.
- Route 53, PowerDNS, Azure DNS and Google Cloud DNS validations write the TXT
  values at a name as a whole: two jobs at once (two certificates, or a
  certificate and a dry run) could each write over the other's value, and one
  validation failed. They now write one after another.
- A certificate administrator who changed a saved source's, validation's or
  target's settings (the API address, the host) and tried them (Test, *Try
  reaching it*, *Find out what runs there*) had them tried with the API key,
  password or TSIG kept for it - which could so be sent elsewhere. Settings not
  saved are tried with the kept secrets by a full administrator only (tried as
  saved, or with the secrets typed in again, as before).
- With debug on, the steps of a job showed each address a module asked in
  full - with the token of Duck DNS or the API key of DreamHost in it. The
  secrets in an address are shown as dots.
- Behind a NAT with a split DNS (the web server 192.168.43.17 inside, the name
  published with the public address), the check before the CA is asked held
  an HTTP-01 certificate back: here the name resolved to the private address.
  Where the validation's resolvers give private addresses only, the public view
  (Settings → DNS) is asked as well, and its answer - what the CA sees -
  counts; with the public address set, a name the internet sees elsewhere is
  no longer taken as right because it resolves to the server here.
- A commercial CA's DCV records (DigiCert, SSLmarket) put in place before an
  error other than a refusal (a broken connection, say) are taken away again.

- A backup put back that was made while a job ran no longer leaves its
  certificate busy for hours: those jobs come back marked failed.
- The key on the enrolment pages is also given to the person who asked for the
  certificate in a request profile that offers it (for a team).
- The commands a deployment runs on the target (before, test, reload, after,
  the script on the machine) are changed only by a full administrator, as the
  script written here already was; a certificate administrator keeps them.
- Running one deployment while another job works on the certificate waits for
  that job and then runs it (the other job's result was given before).
- Delete in a certificate's dialog goes once; its finished jobs go with it.
- A local folder target no longer writes its files again every time when the
  paths name the folder.
- A scoped account sees the members and addresses of its own teams only.
- The key of a certificate (a PFX) is given on the enrolment pages only to its
  owner, a member of its team who may manage it, or an administrator who sees
  all - no longer to a member who may only see it.
- A person of the directory signed in on the enrolment pages is asked about
  again every ten minutes: switched off there or no longer in the groups that
  let them in, and the sign-in ends.
- An account of the enrolment pages only could not give its second step there
  with *acme's own accounts* (portal_local) switched off - it was told it had
  none to give, and the sign-in page reloaded for good.
- A new password set for an account (Accounts, `acme --passwd`, a configuration
  read back), or its second step reset, now ends its sign-ins on the enrolment
  pages too - not only in the administration.
- A request waiting for approval, or declined, can no longer be switched to
  *renewed by itself* (on the portal or in the administration): the renewer then
  issued it, past the approval or the decline. The switch is not shown for a
  declined one.
- A certificate owned by a team is seen on the portal by the team's members
  only: a directory group or a person with the same name as the team saw it
  too - and could download its key where the PFX is offered.
- Wrong passwords of acme's own accounts on the enrolment pages count while the
  directory cannot be reached (they were given back with the 503, so guessing
  had no limit); a name typed there is cut at 190 characters, as in the
  administration.
- A request profile renamed keeps what was asked for from it (its count, the
  profile shown, a new CSR checked against it); a certificate deleted takes who
  asked for it on the portal with it.
- *Revoke* with *a new one at once* is refused, before anything is revoked, for
  a certificate issued for a CSR sent in (it needs a new CSR); the portal no
  longer shows what a CA said of a failed twin.
- A certificate administrator or read-only account kept to its teams could act
  on another team's certificate by giving its number written differently
  (" 5", 5.0), and take over another team's deployment by saving it with a
  certificate of its own; the Overview showed it every team's numbers and named
  the others' certificates in its alerts, and the list of jobs left its own out
  where they were past the first page of everybody's.
- *Renew now* (and revoking, deploying a new deployment at once) opens the job's
  log over the certificate again: the certificate drawn afresh took the log's
  place, and the log was lost.
- A revoked certificate switched off and on again (*In use*) no longer comes
  back as valid, nor a request waiting for approval (or declined) as one to
  issue - the renewer then issued it, past the approval.
- *Save and deploy now* pressed again after the deployment was refused (not
  issued yet) saves the same deployment again instead of adding a second one;
  the same in the wizard when a deployment of a new certificate is refused.
- The alias asked for in *Export* of a Java keystore is the alias in the file
  (it was always the certificate's name).
- Hints left in English on a Czech page: the name boxes of the wizard, the
  import, a self-signed certificate and a CSR, the secret boxes of the modules
  and the PKCS#12 password, *choose one…* of a new deployment, *default* of a
  file's mode, a script's arguments, a tag's meaning.
- A configuration read back into an installation that has certificates or
  authorities of its own keeps each deployment with its certificate (and what an
  authority signed, an authority's parent): a certificate given another number
  here left its deployments on whichever certificate had its number - another
  certificate was deployed there.
- A backup tried (*Try it*, after every backup, weekly) is no longer "not good"
  because a job, a sign-in or a code used once was written while its copy was
  made.
- Two nodes apart: a node stepped aside (or held back with *Renewals only on the
  preferred node*) no longer signs with acme's own authorities when a hold is
  released, a CRL is made by hand, an authority is renewed or one is made under
  another; and what only reads - the progress of a job, a copy downloaded, the
  wizard's choices, a preview, a check of the database - goes on on the node
  whose changes wait, and is not in the report as a change done on both.
- The preferred node renamed stays the preferred node; one that is not a node of
  the cluster can no longer be saved (`acme --set`, a configuration read back) -
  with *priority* both nodes then stepped aside while apart.
- *Stop* of a job left running by a node of the cluster that is gone (or was
  renamed) marks it stopped: it was asked of that node for ever, and the
  certificate stayed busy for two hours.
- `acme --job`, `--cert`, `--ca-show` and the others with a number beyond 64
  bits say there is none (a traceback on SQLite); `acme --events --limit` below 1
  is refused (every event, or the database's error).

## 1.0.18 - 2026-11-02

- *Renew now* asks first, in the administration and on the enrolment pages:
  what it does (a new certificate now, the one in use stays valid), from
  where, its key, and that it is put in place again.
- Running a deployment while a job works on the certificate gives that job to
  watch instead of an error.
- **Request profiles** (Settings → Request profiles, docs/request-profiles.md):
  kinds of certificates people may ask for on the enrolment pages with the
  source, the validation, the domains (wildcards, how many names), the key or
  their own CSR, the subject (each field not used, fixed or filled by the
  person), renewal, validity, usage, approval, owner, tags, who may use it and
  the PFX set beforehand - the person gives only the names. Each is picked from
  the catalogs and checked as it is saved. With none defined the portal asks as
  before.
- **A CSR sent in is decoded and shown first** on the portal - its subject, its
  names, key, signature (valid or not), usages - with every check against the
  profile and what the certificate will say beside what the CSR says; only a
  CSR that fits is asked for. Such a certificate holds no key: the CSR is kept
  and used again at every renewal (same key); *Send a new CSR* changes the key.
  A PFX or a deployment that needs the key is refused in words.

## 1.0.17 - 2026-11-02

- **Popups are wider on a wide screen**: every popup grows with the window -
  about two thirds to three quarters of it on a big screen (a certificate's
  details 1480 px at 2000 px), never the whole of it; below 1400 px as before,
  on a phone the whole width.

## 1.0.16 - 2026-11-02

- **A team's rights work on the enrolment pages**, not only in the
  administration: *manage* gives *Renew now*, renewed by itself on/off and
  *Revoke* in the certificate's dialog; *approve* (or *manage*) gives *Approve*
  and *Decline* of the team's waiting requests. The dialog says what the person
  may (*You may*), the list says *team X* for a team's certificate.
- *Ask for a certificate* is shown dimmed, with the reason, to whoever may ask
  for a team while the enrolment pages do not say yet which names and sources
  may be asked for (before: missing). Owners and teams says so too.

## 1.0.15 - 2026-11-02

- The enrolment pages no longer go blank while *Certificates on the portal* is
  off: they say that certificates are not offered yet and where the
  administrator switches them on. Settings → Owners and teams says the same
  (the members would see nothing there), with a button to the setting.

## 1.0.14 - 2026-11-02

- **A role for the enrolment pages only** ("enrolment pages only"): an account
  that never gets into the administration, signs in on the enrolment pages and
  sees and asks for what its teams give it (Owners and teams). For acme's own
  accounts (Accounts → role) and from the directory (*Group of
  enrolment-only accounts*, picked with *Find the groups*). Settings → The
  enrolment pages → *Accounts of the role Enrolment pages only may sign in*
  (on). Its first password - and any later one - is changed on the enrolment
  pages.
- **Split brain protection** for a cluster of two, as otp's: what each node
  does when it cannot reach the other (step aside, an arbiter, the preferred
  node, renewals only there, half the tries, frozen changes, the report of
  what was done apart). Default: as until now, nothing runs.
- **Validation over SSH straight on the DNS server** (BIND, PowerDNS, Knot,
  NSD, dnsmasq, Unbound, Windows): *Find what runs there* only reads, and
  fills in the server, the zones, the keys - every field stays editable.
- A certificate's details are first, with *Change*: what can be changed without
  a new certificate is said, the wizard marks the steps that make one.

## 1.0.13 - 2026-11-01

- The line on a target's form saying where files, script and roles are set is
  as quiet as the help under a field (small, dimmed), not a bright paragraph.

## 1.0.12 - 2026-11-01

- The form of an SSH, Windows or local target says where its files, their
  format, the script after them and (Windows) the roles of the server are set:
  in each certificate's deployment ("Deploy it on a target").

## 1.0.11 - 2026-11-01

- The self-signed and the CSR dialogs pick the owner and the tags from Settings
  → Owners and teams too (a certificate administrator limited to their teams
  makes certificates there as well).

## 1.0.10 - 2026-11-01

- **Deployment designer** (SSH, Windows, this machine): the files on the target
  by quick layouts or rows - format in plain words, path with {name} {cn}
  {service} {date} {alt}, mode, owner; the PKCS#12/keystore password none, set,
  or made by acme (24 characters, sealed, the same across renewals); after the
  files a script already on the machine, or written here - uploaded on every
  deployment, run with ACME_* variables (ACME_FILE_KEY_PEM, ACME_PASSWORD,
  ACME_NAMES ...), then deleted; the previous files put back when it fails. A
  live preview of the real paths and the variables, and a dry run
  (ACME_DRY_RUN=1, files into a temporary folder). Only a full administrator
  changes a script.
- **Windows roles**: RDS (Connection Broker), RD Gateway, AD FS, Web Application
  Proxy, SQL Server, LDAPS, WinRM HTTPS, SSTP VPN, IIS Central Certificate Store,
  IIS FTP, Exchange (every service), Skype for Business, SharePoint SE (beta),
  Windows Admin Center; read on the key for accounts; Test says which roles a
  server has; the PowerShell shown before it runs.
- **Owners and teams, a tag catalog, rights**: owners and teams with members
  (acme's accounts, directory users and groups) and rights (view, request,
  manage, approve); tags with a colour; nothing typed as free text any more.
  Full administrators always see and do everything; certificate administrators
  and read-only accounts see everything unless that is switched off (then only
  their teams'). Expiry and failure mails also to the team's address.
- **A certificate's details edited without a new certificate** (owner, tags,
  note, renewal, reuse of the key, name, on/off); after changed names or key
  "renew now, or at the next renewal?".
- **The certificate portal**: acme's own accounts may sign in (with their
  second factor); administrators see every certificate, others what is theirs
  or their team's.
- **Certificates from acme**: the card as in ai, every change through the save
  bar.
- **Backups**: modules of your own (/etc/acme/plugins) in them; a cluster's
  backup put back says the exact steps to make it two again; a test proves a
  backup on a clean installation is the installation it came from.
- **Czech everywhere**: every message of the daemon shown in the pages.

## 1.0.9 - 2026-11-01

- **Columns of a list no longer jump** when it is drawn again - a switch in a
  row, the auto refresh, "2 min ago" become "3 min ago": the widths it had
  first are kept (as shares, so a window made wider or narrower still fits);
  a long word that does not fit is laid out once more before the page is
  painted. A layout set by hand (the columns editor) comes first.
- **Add and issue now** shows the job already issuing a new certificate (the
  look starts it as soon as it is saved) instead of "a job is working"; the
  popup closes whatever the issuing says. "Renew now" on a certificate being
  worked on shows that job too.
- HTTP-01 over SSH guide: a CNAME to the name that has the public address is
  suggested, or a redirect of /.well-known/acme-challenge/ from another web
  server; a name acme's own block adds by itself is not a thing to set up.

## 1.0.8 - 2026-11-01

- **acme-dns: Register an account** from the validation's form - one, or one a
  name into "Accounts by name" (an acme-dns account keeps two TXT values), with
  the CNAMEs to put into your DNS; nothing saved until Save.
- SSLmarket: the DCV records of an order that waited across the upgrade to
  1.0.5 are taken away too.
- Tests: the HA and database move suites run against real PostgreSQL and
  MariaDB again; the SSLmarket suite runs all its tests.

## 1.0.7 - 2026-11-01

- **The QR code of the second factor is right again.** 1.0.6 drew it wrong:
  a helper of acme push had the name of the QR code's own (the engine's parts
  share one namespace), so an authenticator app could not read a new QR code.
  Every name is defined once now, and the engine's lint and a test say so.
- A second `db_trouble` (the words for an unreachable PostgreSQL when joining
  a cluster) renamed `ha_db_trouble` - it had taken the place of the one that
  tells a database error.
- docs/acme-push-protocol.md: **additive only** - every existing way of
  managing certificates in an application stays as it is; acme push is off by
  default and only one more way in.

## 1.0.6 - 2026-11-01

- **acme push - certificates for our other applications** (otp, isemon,
  zigmon and acme itself): a target that pairs with the application once
  (a one-time code shown there, Settings → Certificates and TLS →
  "Certificates from acme"), then installs each certificate and its renewals
  with signed requests, the private key sealed to the application.
  **Discover** reads the application's certificate slots (each node, the VIP
  address, zigmon's front server and broker) and makes the certificates and
  deployments for those not covered. The receiving side is in the engine;
  docs/acme-push-protocol.md is the specification for the other projects.
- HTTP-01 over SSH **behind NAT**: the guide never suggests a private address
  (the public one, from a name it knows); "Public addresses (NAT, load
  balancer)"; port 80 checked with the name; a name nginx does not answer said
  as such; the name validated added to acme's own block.
- Settings → DNS: **Public is built in** - always there, changed, never deleted.

## 1.0.5 - 2026-11-01

- **HTTP-01 on web servers over SSH where nginx answers port 80 already**:
  "Prepare the hosts" puts one line, `include
  /etc/nginx/snippets/acme-challenge.conf;`, at the top of each port-80 server
  block - nothing else in them changes (a certbot redirect to HTTPS goes on as
  before). Every file is checked unchanged since it was read, copied to
  /var/backups/acme-nginx/, and put back when nginx -t fails. With names
  given and no block answering them, acme's own block listens for those
  names only (not the default server). "I put it in myself": "Download the
  nginx config" gives the file and the line, and Prepare only checks.
- "Set nginx up by itself" (before Test and every validation) and "Open port
  80 in their firewall" (firewalld, ufw); a port 80 closed by the firewall is
  said as such ("No route to host" while SSH works).
- The check before the CA is asked can be made **at other addresses** - a load
  balancer, the public IP, NAT; https:// too - with the certificate's name as
  Host and SNI; "Name for Test".
- **Try reaching it fills in the host keys** of the form (every form with an SSH
  key); a different key pinned already is shown with a warning and "Replace
  with the key seen", never replaced by itself. Kept by Save.
- **Webglobe**: DNS-01 validation (login + API key; only the record it made is
  taken away) and a target uploading your own certificate to a hosted domain.
- The nginx config for HTTP-01 printed by `acme --validation-action NAME
  nginx_files`.
- Settings → DNS: a function's set waits for Save on the bar (Put back undoes
  it); Test of a set opens over its form and gives the form back as it was.
- High security: a refused exception switch turns back instead of an error.

## 1.0.4 - 2026-11-01

- **Renewal by itself switched on and off** from the list of certificates and
  from a certificate - nothing is revoked, it stays valid and deployed.
- **Revoking**: a dual certificate's both keys (ECDSA and RSA) are revoked, the
  dialog says so; "Issue a new one at once" gives a new certificate with a new
  key in the same job, deployed where the revoked one was. A revoked one has
  "Issue a new one". The old "Switch renewal off" switch did nothing - gone.
- **dns-persist-01**: one TXT record at `_validation-persist.DOMAIN`, set once,
  for any certificate of the domain (subdomains and wildcards with
  `policy=wildcard`). acme writes the exact record for each ACME account,
  checks it, and uses it as soon as the CA offers it (Google Trust Services
  does; Let's Encrypt has announced it) - a fallback validation until then.
- **What fits together is checked before the CA is asked**: names, source,
  validation, key type and twin, in one place - the wizard greys out what does
  not fit and says why; a public CA refuses single labels, .local/.test and
  private addresses.
- **SAN editor**: typed SANs (DNS, IP, e-mail, URI), the CN apart with "CN is
  also a SAN", many pasted at once.
- **DigiCert, GeoTrust, Thawte, RapidSSL** products, with domain validation by
  TXT, CNAME, HTTP file or e-mail placed by the validation; SSLmarket uses the
  same.
- **Settings → DNS**: named sets of DNS servers (UDP, TCP, DNS over TLS) given
  to validation, public checks, APIs, targets, ACME and mail; the system's by
  default.
- **Own authorities edited** without removing them: settings, the name (the old
  /pki/ addresses still served), the certificate renewed with the same key, its
  history. A switched-off authority still publishes its CRL.
- Name constraints written as "permitted DNS:…" are read too.
- SSLmarket reworked after its API description, and SSLmarket ACME.
- The authorities' tree drawn with joined lines; "until" of a CRL translated.

## 1.0.3 - 2026-11-01

- **The pages after an upgrade are the new ones**: they said otp's version
  (1.0.209) for every acme release, so browsers kept core.js and admin.js from
  before - the default buttons without their star, errors of old scripts on
  new pages after F5. Every script and stylesheet is keyed by its own file now,
  and a release keeps the pages' version equal to acme's.
- acme's own DNS server answering on the VIP only: the validation's Test and
  its wait ask the VIP, not 127.0.0.1 where the server does not listen then.
- The SQLite file's setting is on The database pane, not under every pane; a
  test keeps every setting on a pane of its own.
- A button after words on the same line keeps its gap ("… is there" [every
  step]).

## 1.0.2 - 2026-11-01

- **Validation that tells you what to do, and tests itself.** For every name of
  a certificate acme says what has to be in place and where - the exact CNAME,
  NS or TXT record with Copy buttons, where an HTTP-01 name must point - and
  checks it live. "Dry run" puts a real test record or file in place, sees it
  from outside and takes it away, without asking the CA. Names are grouped by
  domain, with a validation suggested for each (a certificate may span many
  domains, each proved its own way). Before a first certificate - and after a
  failed validation - the CA is not asked while something is missing.
- **More sources**: EST, CMPv2, HashiCorp Vault PKI, EJBCA, step-ca, AWS Private
  CA, Google CAS, FreeIPA, GlobalSign Atlas, DigiCert CertCentral, SSLmarket.cz;
  Actalis, Certum, Sectigo and DigiCert (EAB) among the ACME CAs. A paid order
  is never placed without "Allow new orders (paid)".
- **More validations** (deSEC, WEDOS, Active24, Websupport, Subreg/Gransy,
  CZECHIA.COM and some 45 more DNS providers), HTTP-01 by FTP/FTPS/SFTP, S3,
  Azure Blob and WebDAV.
- **More targets**: AWS ACM, Azure Key Vault, Google Certificate Manager,
  Cloudflare, vCenter, ESXi, Redfish (iDRAC, iLO, XCC), Sophos, Kemp, Cisco
  ISE, HAProxy (runtime API), Traefik, Caddy, NGINX Unit, Zimbra, TrueNAS,
  Docker Swarm, strongSwan, FRITZ!Box, UniFi OS.
- **Dual certificates**: ECDSA and RSA under one certificate, renewed in one
  job (the second ACME order needs no second validation) and deployed together
  where the target serves both (nginx, Apache, HAProxy, Postfix, F5, acme's own
  pages...), the variant chosen for the others.
- **acme's DNS server**: answers on the VIP address, the nodes, or both (and
  from the address it was asked at); the firewall lets it in by itself when it
  is switched on.
- **CRLs on acme**: every authority of acme's own publishes its CRL and its
  certificate over HTTP at /pki/ on every node and the VIP, refreshed by
  itself; new authorities put those URLs in what they sign.
- **The SSH key card of isemon** wherever acme signs in over SSH: make a key
  here, use your own, download, forget, try reaching it, how to set it up.
- **The database move wizard**: target, connection, checks, what happens, the
  move live, done - SQLite, MariaDB and PostgreSQL in every direction; not on a
  node of a cluster.
- A default in every list (sources, validations, targets, authorities); the
  lists are current without reloading; names made safe everywhere (the
  defaults of 1.0.0/1.0.1 are renamed with every reference to them).
- The overview as in otp: the certificates' tiles first, then the server's,
  each opening what it counts.
- Fixed: backups checked "not good" after an upgrade from the pages and with
  keys of authorities (the backups themselves were whole); the configuration's
  export left the authorities' and certificates' keys out; the encrypted link
  between the databases could not be switched on (otp's version floor).

## 1.0.1 - 2026-11-01

- **High availability: joining does everything by itself, on both sides.**
  - The node a bundle is made for is let through the firewall of the first
    node at once (for a day, until it has joined; a firewall change on trial
    never takes it back), and the joining node opens its own firewall to the
    first one before it reaches the database or copies anything - acme's own
    chain (ACME-IN) and firewalld alike, each opening checked and said
    truthfully ("does NOT let ..." with the command, when it did not work).
  - The bundle made on the pages prepares PostgreSQL on the first node as
    `acme --ha-setup` does: it listens on the node's address, the joining
    node is in pg_hba.conf, PostgreSQL is restarted - each step shown.
  - A node's PostgreSQL lets in its own address too: the replicated join
    stopped half way on "no pg_hba.conf entry for host <own address>".
  - Every failure of a join is named with its fix: connection refused (not
    listening there), timed out / no route (a firewall), pg_hba, password,
    name. "Check from here" tries it before joining. A half-done join is said
    to be one, and running it again finishes it cleanly.
  - Shared mode writes `ha_mode` on both nodes (they ran as two single
    servers on one database).
  - `--ha-status` and the page saw the outgoing replication as missing while
    both directions ran (the slots were looked for under otp's names); the
    cluster counted as unhealthy for /healthz?check=all and the alerts.
  - The Make the bundle and Join a cluster popups redrawn: a drop zone and
    what the bundle holds, the passphrase checked as typed, live steps.
- **Secrets as otp shows them, everywhere**: a stored password is dots and
  its last two characters to a full administrator, dots only to everybody
  else, and only dots while it is typed - the certificate manager's sources,
  validations, targets and deployments included. The SSH keys of validations
  and the acme-dns accounts are sealed now; the configuration export carries
  module secrets only when it is locked with a password.
- **Czech everywhere**: every tab, settings pane, popup and module form of
  the certificate manager, the job steps and the errors.
- No browser dialogs: the contact e-mail of the ACME sources is asked in
  acme's own popup.
- As in otp: "The enrolment pages" keeps its name; the balancer's health
  check offers "+ DNS server listening" (`/healthz?check=dns`) where otp
  offered RADIUS; the certificate manager's retention is on The database.

## 1.0.0 - 2026-11-01

The first version of **acme**: certificates kept, renewed and put in place by
themselves.

acme is built on the engine of **otp 1.0.209** (the one-time password server):
its platform - settings, the database (SQLite, MariaDB, PostgreSQL), sealed
secrets, the two-node cluster with its VIP address, mail and SMS, backups, the
firewall, the network, time, upgrades, the API, the command line and the
console - taken over, renamed `otp` → `acme` everywhere, and the single
`otp.py` split into a package. RADIUS, the tokens and the enrolment of otp
are not part of acme.

- **The certificate manager** (`acmelib/certs`): certificates kept with every
  version they had, renewed before they run out (or when the CA says so, ARI),
  deployed to every place they are used, one node at a time in a cluster, every
  step of every job written down.
- **Issuers**: ACME (Let's Encrypt and any ACME CA), acme's own certificate
  authorities (root and intermediate, CRLs), self-signed, Microsoft AD CS,
  SCEP.
- **Challenges**: DNS-01 with acme's own DNS server (UDP and TCP 53), RFC 2136,
  and the APIs of Cloudflare, Route 53, Azure, Google Cloud, Hetzner, OVH,
  DigitalOcean, PowerDNS and others; HTTP-01 here (nginx → `acme.php` on
  port 80) or on another web server over SSH.
- **Targets**: Linux and Windows over SSH, F5, NetScaler, MikroTik, FortiGate,
  Palo Alto, pfSense, OPNsense, Proxmox, Synology, Kubernetes, Vault, a
  webhook, and more - and your own modules in `/etc/acme/plugins/`.
- **The layout**: `acme.py` (the launcher) and `acmelib/` (the engine in
  numbered parts, the certificate manager, the modules, colorama carried
  along).
- **Python 3.14 and PHP 8.3** from the start: install.sh installs or requires
  `python3.14` (AppStream on EL, the deadsnakes PPA on Ubuntu) and PHP-FPM
  8.3, and refuses an older Python unless `--python PATH` says otherwise.
- **The installed tree**: `/usr/local/lib/acme/versions/X.Y.Z-STAMP/`, compiled,
  with `current` switched to a new one in a single step on an upgrade and the
  one before kept as `previous` (`acme_upgrade.py --previous` puts it back).
- **Releases**: `tools/release.py` builds `release/acme-X.Y.Z.tar.gz` - the
  tree with a MANIFEST of SHA-256 sums signed with Ed25519 by acme's own release
  key (`deploy/release-keys/acme-release-1.pub`; otp's key is not trusted) -
  keeps the last ten, and writes `release/index.json` and `release/LATEST`,
  which the servers read for new versions (`upgrade_url`).
