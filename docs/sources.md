# More certificate sources: EST, CMP, Vault, EJBCA, step-ca, cloud CAs, CA APIs

Sources → Add offers, beside ACME (`acme-issuers.md`), acme's own CAs
(`own-ca.md`), Microsoft AD CS (`ms-adcs.md`), SCEP (`scep.md`), SSLmarket
(`sslmarket.md`) and SSLS.cz (`ssls.md`), these modules. Each takes the request (CSR) acme makes for
the certificate - **the private key never leaves acme** - and gives back the
certificate with its chain, ordered and checked against the key. *Try it*
(Sources → Test) only reads: it signs in and looks at the CA, it orders nothing.

| Module | Kind | Signing in | Waits for approval | Revokes |
|---|---|---|---|---|
| [EST (RFC 7030)](#est-rfc-7030) | `est` | HTTP Basic and/or client certificate | yes (202 Retry-After, kept for the next try) | - (EST has none) |
| [CMP (RFC 4210 / 9480)](#cmp-rfc-4210--9480) | `cmp` | shared secret (PBM) or signature | polled within the try | yes (rr) |
| [HashiCorp Vault PKI](#hashicorp-vault-pki) | `vault_pki` | token or AppRole | - | yes |
| [EJBCA REST](#ejbca-rest) | `ejbca` | administrator's client certificate | - | yes |
| [step-ca (JWK provisioner)](#step-ca-jwk-provisioner) | `step_ca` | one-time token signed with the provisioner key | - | yes |
| [AWS Private CA](#aws-private-ca) | `aws_pca` | IAM access key (SigV4) | yes (kept for the next try) | yes |
| [Google Cloud CA Service](#google-cloud-ca-service) | `google_cas` | service account key | - | yes |
| [FreeIPA / Red Hat IdM](#freeipa--red-hat-idm) | `freeipa` | user and password | - | yes |
| [GlobalSign Atlas](#globalsign-atlas-hvca) | `globalsign_atlas` | mTLS + API key and secret | yes (kept for the next try) | yes |
| [DigiCert CertCentral](#digicert-certcentral-api) (DigiCert, GeoTrust, Thawte, RapidSSL) | `digicert` | API key | yes (DCV, OV/EV: kept) | yes |
| [ZeroSSL (REST API)](#zerossl-rest-api) | `zerossl` | API key | yes (DCV: kept) | yes |
| [CyberArk Certificate Manager Self-Hosted (Venafi TPP)](#cyberark-certificate-manager-self-hosted-venafi-tpp) | `venafi_tpp` | user and password (OAuth) or access token | yes (kept for the next try) | yes |
| [CyberArk Certificate Manager SaaS (Venafi Cloud)](#cyberark-certificate-manager-saas-venafi-cloud) | `venafi_cloud` | API key | yes (kept for the next try) | - (GraphQL only) |
| [Keyfactor Command](#keyfactor-command) | `keyfactor_command` | HTTP Basic or OAuth client | - (an approval is said) | yes |
| [Cloudflare Origin CA](#cloudflare-origin-ca) | `cloudflare_origin_ca` | API token or Origin CA Key | - | yes |

A request a CA keeps waiting is remembered in the module's state together
with its key (sealed): the next try asks for it again instead of making a new
one, and the certificate comes with the key it was asked for.

Not here, and why: **Sectigo Certificate Manager** and **HARICA**, **Actalis**,
**Certum**, **SwissSign** speak ACME with EAB - they are presets (or *Another
ACME server*) of the `acme` source. **Azure Key Vault** makes the key itself
and is a store more than a CA (its CSR-and-merge flow is the other way round).
**Keyfactor Command** and **CyberArk Certificate Manager (Venafi)** are here
since 1.0.23, from their vendors' own clients (below). Still not here, because
no API description by the vendor itself could be read where these modules were
written (the vendors' sites were out of reach, and no client of theirs is
public): **Sectigo Certificate Manager's REST API** (its SDK and Terraform
provider are not public; SCM's ACME with EAB is the `acme` source),
**GoGetSSL** (its PHP SDK on Packagist is a third party's), **Entrust
Certificate Services** (only Ansible's community modules speak it; Entrust's
public certificates moved to Sectigo), **Certum's** partner API and
**Namecheap's** SSL API (no client of theirs). Without a source we can check,
no endpoint is guessed.

---

## EST (RFC 7030)

What it is: Enrollment over Secure Transport - an HTTPS protocol for asking a
CA for certificates, spoken by Cisco ISE/IOS, EJBCA, Keyfactor, Entrust,
GlobalSign, Nexus, DigiCert TLM and the libest server.

What acme does: `GET cacerts` (the CA chain), `POST simpleenroll` with the CSR
(base64 DER, `application/pkcs10`), the answer a certs-only PKCS#7 (base64).
`202 Accepted` + `Retry-After`: the CA holds the request; acme waits *Wait for
approval*, then asks with the same request at the next try. A renewal can go
to `simplereenroll` (switch *Renewals by simplereenroll* on where the server
wants it). Source: RFC 7030, sections 3.2, 4.1, 4.2
(https://www.rfc-editor.org/rfc/rfc7030).

Where to get credentials: the EST server's administrator - a user and
password (or one-time password) for HTTP Basic, or a client certificate the
server knows. EJBCA: an EST alias (System Configuration → EST), the URL
`https://ca/.well-known/est/<alias>/`.

Example:

| Field | Value |
|---|---|
| EST server | `https://est.example.local` |
| CA label | `tls-servers` |
| Signing in | User and password |
| CA certificate of the server | the root of the server's TLS certificate |

Not spoken: server-side key generation (`serverkeygen`) and full CMC.

## CMP (RFC 4210 / 9480)

What it is: the Certificate Management Protocol (CMPv2), updated by RFC 9480,
profiled by RFC 9483 (Lightweight CMP) - EJBCA, Nokia NetGuard, Siemens,
Insta Certifier, industrial PKIs (IEC 62443).

What acme does: runs `openssl cmp` (OpenSSL 3.0+,
https://docs.openssl.org/3.0/man1/openssl-cmp/) for `ir`, `cr` or `p10cr`
(and `rr` to revoke, `genm` for *Try it*). openssl speaks to a relay of the
module on 127.0.0.1 only; the relay sends each message with acme's HTTP client
(`application/pkixcmp`, through Settings → Proxy, with the TLS settings of the
source). The secret and keys go to openssl in files (0600), never on its
command line. A *waiting* answer is polled by openssl for *Wait for the
certificate*.

Where to get credentials: from the CA - a reference (senderKID) and a shared
secret (EJBCA: a CMP alias in RA mode with *HMAC* authentication, the end
entity's name and enrollment code), or a signing certificate the CA trusts.
The CA's name for *recipient* (`/C=CZ/O=Example/CN=Issuing CA`), and its
certificate for checking signed answers.

Example (EJBCA, RA mode, HMAC):

| Field | Value |
|---|---|
| CMP server | `https://ejbca.example.local/ejbca/publicweb/cmp/acme` |
| Request | cr |
| Protection | Shared secret |
| Reference / Shared secret | `acme01` / the alias's HMAC secret |
| CA name | `/CN=Issuing CA/O=Example/C=CZ` |

Uncertain: servers differ in what they want in the header. A *certificate
profile* (certProfile) needs OpenSSL 3.3+. Each message travels on its own
connection: a server that keeps a transaction only on one open connection
(OpenSSL's mock server does) needs *Implicit confirmation*. A request still
waiting when the try ends is asked again from the start at the next try.

## HashiCorp Vault PKI

What it is: the PKI secrets engine of HashiCorp Vault (and OpenBao).

What acme does: `POST /v1/<mount>/sign/<role>` (or
`/v1/<mount>/issuer/<ref>/sign/<role>`) with the CSR, the common name,
`alt_names`, `ip_sans`, `ttl`; the answer's `certificate`, `ca_chain`.
`POST /v1/<mount>/revoke` with the serial. *Try it*: `auth/token/lookup-self`
and `<mount>/cert/ca_chain`. Source:
https://developer.hashicorp.com/vault/api-docs/secret/pki and
https://developer.hashicorp.com/vault/api-docs/auth/approle.
*Role* (in the form, and for each certificate in *Add a certificate →
Settings*) loads the mount's roles: `LIST /v1/<mount>/roles` (sent as
`GET ...?list=true`) → `data.keys` - "List roles" of the same API reference
(checked in 1.0.25 in hashicorp/web-unified-docs,
`content/vault/v1.20.x/content/api-docs/secret/pki/index.mdx`); the token needs
`list` on that path, and a role can always be typed.

Where to get credentials: a token whose policy allows

```hcl
path "pki_int/sign/web-servers" { capabilities = ["update"] }
path "pki_int/revoke"           { capabilities = ["update"] }
```

or an AppRole with that policy (`vault read auth/approle/role/acme/role-id`,
`vault write -f auth/approle/role/acme/secret-id`).

Example: Vault address `https://vault.example.local:8200`, mount `pki_int`,
role `web-servers`, AppRole. The role's rules (allowed domains, max TTL, key
types) decide what is signed; a certificate's own *days* become the `ttl`.

## EJBCA REST

What it is: EJBCA's (Keyfactor, Community or Enterprise) REST certificate
management interface.

What acme does: `POST /ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll`
with the CSR, the certificate profile, end entity profile, CA, end entity name
and enrollment code; revocation by
`PUT …/v1/certificate/<issuer DN>/<serial>/revoke?reason=…`. *Try it*:
`/v1/certificate/status` and `/v1/ca`. Source: EJBCA's OpenAPI
(github.com/Keyfactor/ejbca-ce, `modules/ejbca-rest-api/resources/openapi.json`;
https://docs.keyfactor.com/ejbca/latest/ejbca-rest-interface).

Where to get credentials: switch the interface on (System Configuration →
Protocol Configuration → REST Certificate Management), issue an administrator
certificate (a role with the CA, the profiles and *RA functionality* rights),
give it here with its key.

Example: address `https://ejbca.example.local`, CA `IssuingCA`, certificate
profile `SERVER`, end entity profile `TLS_SERVERS`, end entity name `{cn}`.
Uncertain: an enrollment that needs approval is answered with an error in the
versions read; it is said as it comes.

## step-ca (JWK provisioner)

What it is: Smallstep's step-ca by its own API, for names ACME cannot prove.
(step-ca with an ACME provisioner: the `acme` source, *Another ACME server*.)

What acme does: `POST /1.0/sign` with the CSR and a one-time token - a JWT
signed with the provisioner's key (ES256 for the default P-256 key): `iss` the
provisioner, `aud` `https://<ca>/1.0/sign`, `sub` the first name, `sans` all
names, 5 minutes, `jti` once, `sha` the root's fingerprint, header `kid`.
`POST /1.0/revoke` (passive) the same way. Source: step-ca's source
(github.com/smallstep/certificates: `api/sign.go`, `api/revoke.go`,
`authority/provisioner/jwk.go`) and
https://smallstep.com/docs/step-ca/provisioners/#jwk.

Where to get credentials: a JWK provisioner (`step ca provisioner add acme-jwk
--type JWK --create`) and its private key, decrypted:

```sh
step ca provisioner list | jq -r '.[] | select(.name=="acme-jwk") | .encryptedKey' \
  | step crypto jwe decrypt        # asks the provisioner's password, prints the JWK
```

Paste that JWK (or a PEM key) as *Provisioner key*, and step-ca's
`root_ca.crt` as *Root certificate*.

## AWS Private CA

What it is: AWS Private Certificate Authority (ACM PCA).

What acme does: `IssueCertificate` (the CSR, the CA's signing algorithm, the
validity in days, a template ARN where set), then `GetCertificate` until it is
ready (`RequestInProgressException`: asked again, at the next try if need be);
`RevokeCertificate` with the serial. Signed with AWS Signature Version 4.
Source: the API model (github.com/boto/botocore,
`botocore/data/acm-pca/2017-08-22/service-2.json`) and
https://docs.aws.amazon.com/privateca/latest/APIReference/.

Where to get credentials: an IAM user (or role's temporary keys) with

```json
{"Effect": "Allow", "Action": ["acm-pca:IssueCertificate", "acm-pca:GetCertificate",
 "acm-pca:DescribeCertificateAuthority", "acm-pca:RevokeCertificate"],
 "Resource": "arn:aws:acm-pca:eu-central-1:123456789012:certificate-authority/…"}
```

Example: CA ARN as the console shows it, validity 90 days. AWS charges per
certificate issued by a private CA - that is the CA owner's agreement with
AWS, there is no order to buy here.

## Google Cloud CA Service

What it is: Google Cloud Certificate Authority Service (`privateca`).

What acme does: `POST …/caPools/<pool>/certificates?certificateId=…` with
the CSR and `lifetime`; `…/certificates/<id>:revoke`. The certificate's
Google name is kept by its fingerprint for the revocation. *Try it*: the pool
and `:fetchCaCerts`. Source: the discovery document
(https://privateca.googleapis.com/$discovery/rest?version=v1) and
https://cloud.google.com/certificate-authority-service/docs/reference/rest.

Where to get credentials: a service account with *CA Service Certificate
Requester* on the pool (*CA Service Certificate Manager* to revoke), its key
as JSON (IAM → Service accounts → Keys → Add key).

Example: project `p1`, location `europe-west3`, pool `tls-pool`.

*Certificate template* (in the form, and for each certificate in *Add a
certificate → Settings*) loads the templates of the location: `GET
v1/projects/<p>/locations/<l>/certificateTemplates` page by page
(`pageToken`) → `certificateTemplates[].name` / `description` - the API's
discovery document (googleapis/google-api-go-client,
`privateca/v1/privateca-api.json`, checked in 1.0.25). A template can always be
typed.

## FreeIPA / Red Hat IdM

What it is: the CA (Dogtag) of FreeIPA / Red Hat Identity Management.

What acme does: signs in (`/ipa/session/login_password`), then the JSON-RPC
`cert_request` for the principal `SERVICE/first-name@REALM` with the profile
(`caIPAserviceCert`), adding the service when missing; `cert_revoke`. Source:
FreeIPA's source (github.com/freeipa/freeipa: `ipaserver/rpcserver.py`,
`ipaserver/plugins/cert.py`) and
https://freeipa.readthedocs.io/en/latest/api/basic_usage.html.

Where to get credentials: a user with the role *Certificate Administrators*
(or a role with *Request Certificate* and the CA ACL of the profile). The
host of the name must be in IPA; other names of the certificate must be
managed by that service (IPA's rules). The CA certificate is `/etc/ipa/ca.crt`.

Example: server `https://ipa.example.local`, realm `EXAMPLE.LOCAL`, service
`HTTP`. No wildcards (IPA issues for principals).

*Profile* (in the form, and for each certificate in *Add a certificate →
Settings*) loads IPA's certificate profiles: `certprofile_find/1` → `result[]`
with `cn` (the profile id) and `description` (freeipa,
`ipaserver/plugins/certprofile.py`, checked in 1.0.25). A profile can always be
typed.

## GlobalSign Atlas (HVCA)

What it is: GlobalSign's Atlas platform, through its HVCA API.

What acme does: `POST /login` (API key and secret, over the account's mTLS
certificate), `POST /certificates` with the subject, SANs and the CSR as
`public_key` (answer: the serial in `Location`), `GET /certificates/<serial>`
until it is there, `GET /trustchain`; `PATCH /certificates/<serial>` to
revoke. Source: GlobalSign's own client (github.com/globalsign/hvclient) and
GlobalSign's API documentation
(https://www.globalsign.com/en/resources/apis/api-documentation/globalsign_atlas_certificate_management_api.html).

Where to get credentials: the Atlas portal → API credentials: an API key and
secret and the mTLS certificate (with its key). The names must be verified
domains of the account (Atlas → Domains). *More of the subject* adds what the
account's validation policy wants (`organization=…`, `country=CZ`).

Uncertain: Atlas's answer for an unverified domain (it is said as it comes).

## DigiCert CertCentral (API)

What it is: DigiCert's CertCentral Services API v2 - the certificates of
**DigiCert, GeoTrust, Thawte and RapidSSL**, all DigiCert's brands, all
ordered through CertCentral.

**ACME or the API?** CertCentral also speaks ACME with EAB: the `acme` source,
preset *DigiCert (EAB - CertCentral, SSLmarket)*. Prefer it where it does the
job - it is **fully automatic** (no orders, no random values: each name proved
by DNS-01 or HTTP-01, renewed in the CA's own window), for DV and for OV/EV of
an organization validated already in the account. Take this module where ACME
cannot: an **OV/EV order of a chosen organization**, **multi-year plans**
(one order, the certificate reissued inside it for free as each one ends), a
brand's product chosen by name, **DCV by e-mail**. Thawte is also sold by
SSLmarket - see [sslmarket.md](sslmarket.md) (its own module, `sslmarket`).

### The brands and their products (`name_id`)

| Brand | Product | `name_id` | Validation | Wildcards |
|---|---|---|---|---|
| DigiCert | Basic OV | `ssl_basic` | OV | also |
| DigiCert | Basic EV | `ssl_ev_basic` | EV | no |
| DigiCert | Secure Site OV | `ssl_securesite_flex` | OV | also |
| DigiCert | Secure Site EV | `ssl_ev_securesite_flex` | EV | no |
| DigiCert | Secure Site Pro OV / EV | `ssl_securesite_pro` / `ssl_ev_securesite_pro` | OV / EV | also / no |
| DigiCert | Encryption Everywhere DV | `ssl_dv_ee` | DV | also |
| GeoTrust | TrueBusiness ID OV / EV | `ssl_geotrust_truebizid` / `ssl_ev_geotrust_truebizid` | OV / EV | also / no |
| GeoTrust | Standard DV | `ssl_dv_geotrust` | DV | no |
| GeoTrust | QuickSSL Premium DV | `ssl_dv_geotrust_flex` | DV | also |
| GeoTrust | Wildcard DV / Cloud DV | `wildcard_dv_geotrust` / `cloud_dv_geotrust` | DV | only / also |
| Thawte | SSL Webserver OV / EV | `ssl_thawte_webserver` / `ssl_ev_thawte_webserver` | OV / EV | also / no |
| Thawte | SSL123 DV | `ssl_dv_thawte` | DV | also |
| RapidSSL | Standard DV | `ssl_dv_rapidssl` | DV | no |
| RapidSSL | Wildcard DV | `wildcard_dv_rapidssl` | DV | only |

Another product: *Another product (its name_id)*. The action **List the
products** shows what the account may order. A product that takes no wildcard
refuses one before anything is ordered; an OV/EV product needs the
*Organization ID* (the action **List the organizations**) for a new order.

### Money

A certificate is **reissued inside an order paid already** (free) - the one
in *Order to reuse*, or the one acme made last for the certificate. A **new
order is a purchase** and is made only when *Allow new orders (paid)* is on;
otherwise the job stops with words saying so and nothing is bought. When the
order's validity ends (within a week), the new order is a **renewal order**
of it (`renewal_of_order_id`) - again only with *Allow new orders (paid)*.

### The domain validation (DCV) and which validations can do it

DigiCert checks each domain its own way; the certificate's validation puts
the record or file in place through the placement API every validation module
keeps (`place` / `placed_ready` / `unplace` in `acmelib/plugins/base.py`;
`acmelib/plugins/issuers/_dcv.py`), DigiCert is asked to look at once
(`check-dcv`), and the records are taken away once it is issued. A pairing
that cannot work is refused before anything is ordered - on the page, in the
API, on the command line and by the renewer ([validation.md](validation.md#what-fits-a-source-and-a-validation)).

| *Domain validation (DCV)* | DigiCert's method | What is put in place | Validations that can |
|---|---|---|---|
| DNS TXT record | `dns-txt-token` | TXT at `_dnsauth.DOMAIN` (or the domain itself: *Label*) holding the random value | every DNS provider's API (`desec`, `cloudflare`, `route53`, `wedos`, ... all `ApiDns`), `rfc2136`, `manual`, `script`, `ssh_dns`; acme's own DNS server only for names inside its own zones; **not** `acme_dns`, `duckdns` |
| DNS CNAME record | `dns-cname-token` | CNAME `_dnsauth.DOMAIN` → `RANDOM.dcv.digicert.com` (or `RANDOM.DOMAIN` → `dcv.digicert.com`: *Shape*) | `desec`, `cloudflare`, `rfc2136`, `manual` (and acme's own DNS server inside its zones) |
| HTTP file | `http-token` | `http://DOMAIN/.well-known/pki-validation/fileauth.txt` holding the random value | `http_local` (this server answers it, kept for 30 days), `http_ssh` (written beside the tokens; *Prepare the hosts* serves it), `http_ftp`, `http_s3`, `http_azure_blob`, `http_webdav`. Not for wildcards |
| E-mail | `email` | nothing: DigiCert mails the domain's admin addresses, a person approves | no validation needed |

**Domains validated already** in the account (their DCV still valid, `GET
/domain`) get no record (*Skip domains validated already*). An order that
waits (OV/EV validation, a DCV not seen yet) is **kept across runs**: the next
try asks for it again, never orders twice, puts back what went away with the
last job and asks DigiCert to look again.

Endpoints (each a setting under More): `POST /order/certificate/{name_id}`,
`POST /order/certificate/{order}/reissue`, `GET /order/certificate/{order}`,
`PUT …/dcv-random-value`, `PUT …/check-dcv`, `GET /domain`,
`GET /organization`, `GET /product`,
`GET /certificate/download/order/{order}/format/pem_all`,
`PUT /certificate/{id}/revoke`, `GET /user/me`; header `X-DC-DEVKEY`.
Sources: DigiCert's developer pages (https://dev.digicert.com - not readable
from where this was written), cross-checked against code that speaks the API:
github.com/sapcc/go-certcentral (paths), github.com/lexiconn-internet-services/digicert
(the product `name_id`s), github.com/metorial/metorial
`integrations/digicert/docs/API_RESEARCH.md` (bodies, answers, DCV endpoints),
github.com/grindsa/acme2certifier `docs/digicert.md`. `test/test_digicert.py`
lists every path the module may call (a contract test).

Where to get credentials: CertCentral → Automation → API Keys. Check a
product's `name_id` (Settings → Product settings, or *List the products*) and
an organization's id before the first paid order.

Uncertain: the shape of the answers between products, the reissue states, the
TXT label (`_dnsauth` or the domain itself - a setting), the CNAME's shape (a
setting), whether `GET /domain` filters by name (all are read, at most 1000),
`renewal_of_order_id` on a renewal order.

## ZeroSSL (REST API)

What it is: ZeroSSL's REST API (not its ACME server: that one is the `acme`
source's preset *ZeroSSL*). Take this module for what ACME does not do there:
the certificates in the account's dashboard (and Import from a source), 1-year
certificates where the plan sells them, DCV by e-mail.

What acme does: `POST /certificates` with the names (`certificate_domains`),
the CSR, `certificate_validity_days` (90 or 365) and `strict_domains=1`; the
DCV record or file ZeroSSL answers with (`validation.other_methods`) is put in
place by the certificate's validation, as for DigiCert; then
`POST /certificates/{id}/challenges` (`CNAME_CSR_HASH`, `HTTP_CSR_HASH` or
`EMAIL` with the approver addresses), `GET /certificates/{id}` until `issued`,
`GET /certificates/{id}/download/return` (the certificate and `ca_bundle.crt`).
A certificate still waiting is kept for the next try - nothing asked for twice.
`POST /certificates/{id}/revoke?reason=…` revokes it. *Try it*:
`GET /certificates?limit=1`. Import from a source: `GET /certificates` page by
page, each one's `download/return`.

| *Domain validation (DCV)* | Method | What is put in place | Validations that can |
|---|---|---|---|
| DNS CNAME record | `CNAME_CSR_HASH` | CNAME `cname_validation_p1` (`_HASH.NAME`) → `cname_validation_p2` | the DNS validations that write CNAMEs (`desec`, `cloudflare`, `rfc2136`, `manual`, acme's own DNS server inside its zones) |
| HTTP file | `HTTP_CSR_HASH` | `http://NAME/.well-known/pki-validation/HASH.txt` holding the lines ZeroSSL gives | the HTTP validations (`http_local`, `http_ssh`, `http_ftp`, `http_s3`, …). Not for wildcards |
| E-mail | `EMAIL` | nothing: ZeroSSL mails the approver address (*Approver mailbox*) | no validation needed |

The API key: since August 2026 in the header `Authorization: ApiKey KEY`; an
older account that still wants the parameter `access_key` chooses *How the API
key is sent*. ZeroSSL answers 200 even to an error - `{"success": false,
"error": {code, type}}` is said in words; the key never goes into a step.

Verified against (ZeroSSL's documentation, https://zerossl.com/documentation/api/,
could not be read from where this was written): ZeroSSL's own Go client - Caddy
is ZeroSSL's project -
https://raw.githubusercontent.com/caddyserver/zerossl/master/endpoints.go,
https://raw.githubusercontent.com/caddyserver/zerossl/master/client.go,
https://raw.githubusercontent.com/caddyserver/zerossl/master/models.go,
https://raw.githubusercontent.com/caddyserver/zerossl/master/zerossl.go
(github.com/caddyserver/zerossl).

Where to get credentials: the ZeroSSL dashboard → Developer → the API access
key. Uncertain: what `replacement_for_certificate` does to an account (not
sent); `HTTPS_CSR_HASH` is not offered.

## CyberArk Certificate Manager Self-Hosted (Venafi TPP)

What it is: the Venafi Trust Protection Platform, now *CyberArk Certificate
Manager, Self-Hosted*, through its WebSDK.

What acme does: signs in with `POST /vedauth/authorize/oauth` (`client_id`
`vcert-sdk`, scope `certificate:manage,revoke` - both settings) or uses an
access token made in the platform; `POST /vedsdk/certificates/request` with the
CSR into the policy folder (`PolicyDN` `\VED\Policy\…`, the SANs, an optional
`CADN`), then `POST /vedsdk/certificates/retrieve` until the certificate is
there (with its chain). A renewal - and a certificate imported from the platform
(its DN is its id) - goes to `POST /vedsdk/certificates/renew` of that object
(*Renew the same certificate object*). `POST /vedsdk/certificates/revoke` by the
SHA-1 thumbprint. *Try it*: `GET /vedsdk/Identity/Self`. The form's list of
folders: `POST /vedsdk/config/findobjectsofclass` (Class `Policy`) - a token
without the *configuration* scope cannot read it; type the folder in *Policy
folder typed* then. Import from a source:
`GET /vedsdk/certificates/?ParentDNRecursive=…&limit=…&offset=…&ValidToGreater=…`.

Verified against Venafi's own client, vcert:
https://raw.githubusercontent.com/Venafi/vcert/master/pkg/venafi/tpp/tpp.go,
https://raw.githubusercontent.com/Venafi/vcert/master/pkg/venafi/tpp/connector.go,
https://raw.githubusercontent.com/Venafi/vcert/master/pkg/venafi/tpp/search.go,
https://raw.githubusercontent.com/Venafi/vcert/master/pkg/certificate/certificate.go,
https://raw.githubusercontent.com/Venafi/vcert/master/README-CLI-PLATFORM.md
(github.com/Venafi/vcert).

Where to get credentials: a user with *WebSDK access* and the right to request
certificates in the folder; the API integration *VCert* (`vcert-sdk`) with the
scope `certificate:manage,revoke` (Platform → API → Integrations).

## CyberArk Certificate Manager SaaS (Venafi Cloud)

What it is: Venafi as a Service / TLS Protect Cloud, now *CyberArk Certificate
Manager, SaaS*.

What acme does: `GET /outagedetection/v1/applications/name/{application}` (its
id and its issuing templates by API alias), `POST
/outagedetection/v1/certificaterequests` with the CSR, the application, the
template and `validityPeriod` (`P<days>D`, when set), `GET
/outagedetection/v1/certificaterequests/{id}` until `ISSUED`, then `GET
/outagedetection/v1/certificates/{id}/contents?chainOrder=EE_FIRST&format=PEM`.
A renewal - and an imported certificate - is a request with
`existingCertificateId` and the application and template of the request that
made it (`GET /outagedetection/v1/certificates/{id}`). *Try it*: `GET
/v1/useraccounts`. Import from a source: `POST
/outagedetection/v1/certificatesearch` (the application, `validityEnd` ≥ now,
50 a page). Regions: `api.venafi.cloud` (US), `api.venafi.eu`,
`api.au.venafi.cloud`, `api.uk.venafi.cloud`, `api.sg.venafi.cloud`,
`api.ca.venafi.cloud`; the key in the header `tppl-api-key`. Revocation goes
through the service's GraphQL API in vcert, so it is not offered here.

Verified against vcert:
https://raw.githubusercontent.com/Venafi/vcert/master/pkg/venafi/cloud/connector.go,
https://raw.githubusercontent.com/Venafi/vcert/master/pkg/venafi/cloud/cloud.go,
https://raw.githubusercontent.com/Venafi/vcert/master/pkg/venafi/cloud/search.go,
https://raw.githubusercontent.com/Venafi/vcert/master/pkg/util/utils.go,
https://raw.githubusercontent.com/Venafi/vcert/master/README-CLI-CLOUD.md.

Where to get credentials: the web interface → your name → Preferences → API
Keys; an application you own with an issuing template assigned (its API alias).

## Keyfactor Command

What it is: Keyfactor Command (its REST API, `/KeyfactorAPI`). Keyfactor's
EJBCA is the `ejbca` source.

What acme does: `POST /KeyfactorAPI/Enrollment/CSR` (header
`x-certificateformat: PEM`) with the CSR, the template, the CA, the SANs and
`IncludeChain` - the certificate and its chain come in the answer; a template
that needs an approval leaves the request waiting in Command, and acme says so.
`POST /KeyfactorAPI/Certificates/Revoke` by the certificate's Keyfactor id
(kept, or found by its thumbprint with `GET /KeyfactorAPI/Certificates?
pq.queryString=Thumbprint -eq "…"`). The form's lists and *Try it*: `GET
/KeyfactorAPI/Enrollment/CSR/Context/My` (the templates and their CAs the user
may enroll with). Import from a source: `GET /KeyfactorAPI/Certificates`
(`pq.pageReturned`, `pq.returnLimit`, `pq.includeExpired=false`, an optional
query of your own) and `POST /KeyfactorAPI/Certificates/Download` (P7B). Every
request carries `x-keyfactor-api-version: 1` and `x-keyfactor-requested-with:
APIClient`. Signing in: HTTP Basic (`DOMAIN\user`) or an OAuth client's token
(client credentials at the identity provider's token address).

Verified against Keyfactor's own clients:
https://raw.githubusercontent.com/Keyfactor/keyfactor-go-client-sdk/main/README.md,
https://raw.githubusercontent.com/Keyfactor/keyfactor-go-client-sdk/main/docs/EnrollmentApi.md,
https://raw.githubusercontent.com/Keyfactor/keyfactor-go-client-sdk/main/docs/CertificateApi.md,
https://raw.githubusercontent.com/Keyfactor/keyfactor-go-client-sdk/main/docs/ModelsEnrollmentCSREnrollmentRequest.md,
https://raw.githubusercontent.com/Keyfactor/keyfactor-go-client-sdk/main/docs/ModelsPkcs10CertificateResponse.md,
https://raw.githubusercontent.com/Keyfactor/keyfactor-go-client-sdk/main/docs/CoreModelsEnrollmentEnrollmentTemplate.md,
https://raw.githubusercontent.com/Keyfactor/keyfactor-go-client-sdk/main/docs/ModelsCertificateDownloadRequest.md,
https://raw.githubusercontent.com/Keyfactor/keyfactor-go-client-sdk/main/docs/ModelsRevokeCertificateRequest.md,
https://raw.githubusercontent.com/Keyfactor/keyfactor-go-client-sdk/main/docs/ModelsCertificateRetrievalResponse.md
(github.com/Keyfactor/keyfactor-go-client-sdk, generated from Command's
OpenAPI), https://raw.githubusercontent.com/Keyfactor/keyfactor-go-client/main/v3/api/certificate.go
and `certificate_models.go` (the headers, the download, the revocation), and
https://raw.githubusercontent.com/Keyfactor/keyfactor-auth-client-go/main/auth_providers/auth_core.go,
`auth_basic.go`, `auth_oauth.go` (the API path, Basic and OAuth).

Where to get credentials: a Command user (or an OAuth client of the identity
provider Command trusts) with *Certificate Enrollment: Enroll CSR* and, to
revoke and import, *Certificates: Read / Revoke* on the certificates.

## Cloudflare Origin CA

What it is: Cloudflare's Origin CA - certificates for the server behind
Cloudflare's proxy, trusted by Cloudflare's edge only (not by browsers; the
source is not a public CA in the wizard). Free, issued at once, up to 15 years.

What acme does: `POST /client/v4/certificates` with the CSR, the hostnames,
`request_type` (`origin-ecc` for an EC key, `origin-rsa` for RSA - a setting)
and `requested_validity` (7, 30, 90, 365, 730, 1095 or 5475 days); the root
of the Origin CA (`origin_ca_ecc_root.pem` / `origin_ca_rsa_root.pem` at
developers.cloudflare.com) is put above it. `DELETE
/client/v4/certificates/{id}` revokes it. *Try it*: `GET
/client/v4/user/tokens/verify` (an API token). The form's list of zones: `GET
/client/v4/zones`. Import from a source: `GET
/client/v4/certificates?zone_id=…` (Cloudflare lists them zone by zone) and
`GET /client/v4/certificates/{id}`. Signing in: an API token (`Bearer`, Zone →
SSL and Certificates → Edit) or the Origin CA Key (`X-Auth-User-Service-Key`).

Verified against Cloudflare's own Go client:
https://raw.githubusercontent.com/cloudflare/cloudflare-go/v0/origin_ca.go,
https://raw.githubusercontent.com/cloudflare/cloudflare-go/v0/consts.go,
https://raw.githubusercontent.com/cloudflare/cloudflare-go/v0/cloudflare.go,
https://raw.githubusercontent.com/cloudflare/cloudflare-go/v0/api_token.go,
https://raw.githubusercontent.com/cloudflare/cloudflare-go/v0/zone.go,
https://raw.githubusercontent.com/cloudflare/cloudflare-go/v0/pagination.go,
https://raw.githubusercontent.com/cloudflare/cloudflare-go/main/origin_ca_certificates/origincacertificate.go,
https://raw.githubusercontent.com/cloudflare/cloudflare-go/main/shared/shared.go
(`request_type`), https://raw.githubusercontent.com/cloudflare/cloudflare-go/main/ssl/certificatepack.go
(`requested_validity`) (github.com/cloudflare/cloudflare-go).

Where to get credentials: My Profile → API Tokens → Create Token (Zone → SSL
and Certificates → Edit; Zone → Zone → Read for the list of zones), or My
Profile → API Tokens → Origin CA Key. The names must be in zones of the account.

`test/test_sources_vendors.py` lists, for each of these five, every path the
module may call as the vendor's client has it (a contract test).
