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
| [Sectigo Certificate Manager](#sectigo-certificate-manager-admin-api) | `sectigo_scm` | OAuth 2.0 client, or login and password | yes (DCV, approval: kept) | yes |
| [Certum (partner API)](#certum-partner-api) | `certum` | partner login and password (SOAP) | yes (DCV: kept) | yes |
| [GoGetSSL (reseller API)](#gogetssl-reseller-api) | `gogetssl` | user and API password | yes (DCV: kept) | - (cancel only) |
| [Namecheap SSL (API)](#namecheap-ssl-api) | `namecheap_ssl` | API user, API key, client IP | yes (DCV: kept) | replaced ones only |

A request a CA keeps waiting is remembered in the module's state together
with its key (sealed): the next try asks for it again instead of making a new
one, and the certificate comes with the key it was asked for.

Not here, and why: **HARICA**, **Actalis**, **SwissSign** speak ACME with EAB -
they are presets (or *Another ACME server*) of the `acme` source (so do Sectigo
Certificate Manager and Certum, which have modules of their own here too, since
1.0.27, for what their APIs do beyond ACME). **Azure Key Vault** makes the key
itself and is a store more than a CA (its CSR-and-merge flow is the other way
round). **Entrust Certificate Services** (ECS): Entrust's public certificates are
no longer issued through it - "ECS for public trust certificate issuance and
management is scheduled for end-of-life on September 8, 2025", "As of September 8,
2025, all former Entrust customers now receive support through Sectigo's
specialized teams" (https://www.sectigo.com/entrust-migration); the former
Entrust customers are in Sectigo Certificate Manager (`sectigo_scm` below), and
whether ECS still serves anything else could not be found - so no module is
written for an API on its way out. The four modules of 1.0.27 (`sectigo_scm`,
`certum`, `gogetssl`, `namecheap_ssl`) were written from the vendors' own API
descriptions, collected from their sites (the files named in each section);
what those leave open is said there as *Less certain* - nothing is guessed.

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

Checked again in 1.0.27 against api-docs `vault/notes.md` (the PKI page's v2.x
source, `last_modified: 2026-10-12`) and `vault/vault-client-go-openapi.json`
(Vault 1.15): `sign` and `issuer/<ref>/sign` with `csr`, `common_name`,
`alt_names` and `ip_sans` comma-separated, `ttl`, `format`,
`exclude_cn_from_sans`, `remove_roots_from_chain`; `revoke` by `serial_number`
(colon hex); `LIST` sent as `GET ?list=true`, an empty list answered `404
{"errors":[]}` (taken as empty); `cert/<serial>` and `cert/ca_chain` read without
a token ("unauthenticated endpoints"); `X-Vault-Token`, `X-Vault-Namespace`; 200
and 204 both success. Nothing differed - nothing changed.

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

*CA*, *End entity profile* and *Certificate profile* are lists (1.0.27), each
also typeable: `GET /v1/ca` (the CAs), `GET /v2/endentity/profiles/authorized`
(`end_entitie_profiles[].name` - spelt so in the OpenAPI: the end entity
profiles the administrator may use) and `GET /v2/endentity/profile/{name}`
(`available_certificate_profiles` of the end entity profile set) - EJBCA's
`openapi.json` (api-docs `ejbca/openapi.json`, from Keyfactor/ejbca-ce) and the
7.10.0.1 release notes. **The two `/v2/endentity/` calls are likely EJBCA
Enterprise only** (Keyfactor's REST documentation marks the `/endentity/`
resource "Enterprise", and EJBCA Community's source has no such resource): on
Community *Load the list* says so and **a typed name always works**. There is no
call that lists every certificate profile without an end entity profile. A
certificate's own profile (*Add a certificate → Settings*) picks from the same
list. An enrollment that waits for an administrator's approval is answered `202`
(the REST documentation's status codes): since 1.0.27 it is said as that, and
asked again at the next try (how the answer names the request is not
documented).

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

*Template* (in the form, and for each certificate in *Add a certificate →
Settings*) is a list (1.0.27): the 18 end-entity templates AWS documents -
`EndEntityCertificate/V1` (AWS's default), `EndEntityClientAuthCertificate/V1`,
`EndEntityServerAuthCertificate/V1` and their `_CSRPassthrough`,
`_APIPassthrough`, `_APICSRPassthrough` and `Blank…` variants,
`arn:aws:acm-pca:::template/NAME/V1` - quoted from
https://docs.aws.amazon.com/privateca/latest/userguide/template-varieties.html
(api-docs `aws_pca/notes.md`). AWS has no call that lists templates (none in
`service-2.json`), so *Load the list* asks nothing; another ARN (GovCloud's) can
always be typed. An APIPassthrough template takes `ApiPassthrough` values, which
acme does not send. Checked again in 1.0.27 against `aws_pca/service-2.json`
(botocore 2017-08-22), `paginators-1.json`, `waiters-2.json` and the notes'
quotes of API_IssueCertificate / API_GetCertificate / API_RevokeCertificate:
`Csr` base64 of the PEM, `Validity {Value, Type: DAYS}`, `IdempotencyToken` at
most 36 characters, `RequestInProgressException` while the certificate is made
(the waiter `CertificateIssued`), the serial colon-separated hex as AWS's example
- all as the module did. Import from a source is not offered: the API cannot list
the certificates a CA issued (only an audit report into S3).

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

Checked again in 1.0.27 against api-docs `google_cas/privateca-v1-discovery.json`
(revision 20261021) and `google_cas/notes.md`: `certificates.create` (`POST
v1/{parent}/certificates`, `certificateId`, `issuingCertificateAuthorityId`),
`certificates.revoke` (`{reason}` of its enum), `certificates.get`,
`certificates.list` (`pageSize`, `pageToken`; always newest first),
`caPools.get` / `:fetchCaCerts`, `certificateTemplates.list` (per location), the
scope `cloud-platform` - as the module did; nothing changed.

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
`GET /certificate/{certificate}/download/format/pem_all`,
`PUT /certificate/{id}/revoke`, `GET /user/me`; header `X-DC-DEVKEY`.
Sources: DigiCert's developer pages (https://dev.digicert.com - not readable
from where this was written), cross-checked against code that speaks the API:
github.com/sapcc/go-certcentral (paths), github.com/lexiconn-internet-services/digicert
(the product `name_id`s), github.com/metorial/metorial
`integrations/digicert/docs/API_RESEARCH.md` (bodies, answers, DCV endpoints),
github.com/grindsa/acme2certifier `docs/digicert.md`. `test/test_digicert.py`
lists every path the module may call (a contract test).

Checked again in 1.0.27 against api-docs `digicert/notes.md` (dev.digicert.com,
read by the user: authentication, List orders, Download certificate by format,
Reissue certificate, glossary, rate limits, errors): the base URLs (US and
Europe), `X-DC-DEVKEY`, `GET /order/certificate` with `offset` / `limit` (1000;
at most 5000) and `page.total`, the order states, the reissue body
(`common_name`, `dns_names`, `csr`, `signature_hash`, `server_platform`) and its
answer without `certificate_id`, 429 waited out. One difference fixed: the
certificate is now downloaded by **its certificate ID** - `GET
/certificate/{certificate_id}/download/format/pem_all` ("Download certificate by
format", the order's `certificate.id`) - as the documentation has it; the order's
path (`/certificate/download/order/{order}/format/pem_all`) stays only where the
certificate ID is not known. The order of `pem_all` is not documented: acme puts
the chain in order itself.

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

## Sectigo Certificate Manager (Admin API)

What it is: Sectigo Certificate Manager (SCM, formerly cert-manager.com) - the
enterprise account of Sectigo (and, since September 2025, of the former Entrust
public-certificate customers) - through its **Admin API** (`/api/ssl/v2`,
`/api/dcv/v2`). SCM's ACME with EAB stays the `acme` source's preset; take this
module for the account's certificate profiles, terms and custom fields, DCV by
e-mail, and the account's certificates seen and imported.

What acme does: for each domain of the certificate `POST
/api/dcv/v2/validation/status {domain}` - a domain `Validated` already gets no
record; the others are validated by the chosen method, the record or file put in
place by the certificate's validation (as for DigiCert); then `POST
/api/ssl/v2/enroll {orgId, certType, term, csr, subjAltNames, dcvMode,
customFields, comments, externalRequester}` → `sslId`, `GET /api/ssl/v2/{sslId}`
until `Issued`, `GET /api/ssl/v2/collect/{sslId}?format=x509` (the certificate
with its chain, PEM). A renewal of a certificate acme made (or imported, or the
one in *Certificate to reuse*) is `POST /api/ssl/v2/renewById/{sslId} {csr,
dcvMode}` (a new ID) or - *A renewal: replaces it* - `POST
/api/ssl/v2/replace/{sslId} {csr, reason, commonName, subjectAlternativeNames}`
(the same ID); other names than that certificate's are a new enrollment.
Revocation: `POST /api/ssl/v2/revoke/{id} {reasonCode, reason}` (by
`revoke/serial/{serialNumber}` where the ID is not known). *Try it* and the list
*Certificate profile*: `GET /api/ssl/v2/types?organizationId=` (`id`, `name`,
`terms`). Import from a source: `GET /api/ssl/v2?size=200&position=N`
(`X-Total-Count`). Signing in: OAuth 2.0 client credentials at
`https://auth.sso.sectigo.com/auth/realms/apiclients/protocol/openid-connect/token`
(a setting), the API at `https://admin.{enterprise|hard|eu}.sectigo.com`; or the
headers `login`, `password`, `customerUri` at `https://cert-manager.com`.

| *Domain validation (DCV)* | SCM's call | What is put in place | Validations that can |
|---|---|---|---|
| DNS CNAME record | `start/domain/cname` → `submit/domain/cname` | CNAME `host` → `point` | the DNS validations that write CNAMEs (`desec`, `cloudflare`, `rfc2136`, `manual`, acme's own DNS server inside its zones) |
| DNS TXT record | `submit/domain/txt` (no start) | TXT at `host` holding `point` | every DNS validation that writes TXT records |
| HTTP file | `start/domain/http` → `submit/domain/http` | `url` (under `/.well-known/pki-validation/`) holding `firstLine` and `secondLine` | the HTTP validations. Not for wildcards |
| E-mail | `start/domain/email` → `submit/domain/email {domain, email}` | nothing: SCM mails the address picked from those it offers (*Approver mailbox*) | no validation needed |

Verified against Sectigo's own API reference - the OpenAPI definitions embedded
in https://scm.devx.sectigo.com/reference/*.md and
https://enroll.scm.devx.sectigo.com/reference/*.md, collected as api-docs
`sectigo/scm-admin-api.openapi.json`, `sectigo/scm-rest-enrollment-api.openapi.json`
and `sectigo/openapi-admin-fragments/*.json` (`enroll-ssl-certificate.json`,
`collect-ssl-certificate.json`, `get-ssl-certificate-details.json`,
`get-ssl-certificates-list.json`, `get-ssl-cert-types.json`,
`renew-ssl-certificate-by-id.json`, `replace-ssl-certificate-by-id.json`,
`revokessl-certificate-by-id.json`, `revoke-ssl-certificate-by-serial-number.json`,
`get-dcv-status.json`, `start-cname-dcv.json`, `submit-cname-dcv.json`,
`submit-txt-dcv.json`, `start-http-dcv.json`, `submit-http-dcv.json`,
`start-email-dcv.json`, `submit-email-dcv.json`, `createaccesstoken.json`), and
https://scm.devx.sectigo.com/docs/authentication.md,
https://scm.devx.sectigo.com/docs/base-url-explanation.md (api-docs
`sectigo/notes.md`). The REST Enrollment API (`/api/v1/certificates`) is not
used: it cannot list certificates or profiles.

Where to get credentials: SCM → an API client (OAuth 2.0 client ID and secret),
or an administrator allowed the API and the account's customer URI; the
organization's ID; domains delegated to that organization.

*Less certain* (the reference does not say): the exact shape of `host` and `point`
(a host ending in the domain is used as it is, a bare label gets the domain
added); whether `subjAltNames` should hold the common name too (the other names
are sent); whether `collect` answers 404 while the certificate is not issued (the
status is read first); the serial's format for `revoke/serial` (hex); whether a
replaced certificate's ID reads `Replaced` (after a replace the certificate is
collected until it is the one of the new key); the term when none is set (the
shortest of the profile's `terms`). No sandbox of SCM was found.

## Certum (partner API)

What it is: Certum (Asseco Data Systems) through its **SOAP partner API**
(PartnerApi) - the one that takes a CSR. Certum's ACME with EAB is the `acme`
source's preset; Certum's REST CertManager API (`api.certmanager.certum.pl`, v0_2)
only orders *ACME products* (it hands out EAB keys) and is not used.

What acme does: a certificate is **reissued inside an order bought already**
(free, within the product's validity) - the one in *Order to reuse*, the one it
was imported from, or the one acme made last: `getOrderByOrderID` (its serial),
`reissueCertificate {serialNumber, hashAlgorithm, CSR, SANApprover, SANEntries
(only when the names changed)}`. A **new order is a purchase** (`quickOrder
{SANApprover, orderParameters {CSR, customer, language, productCode, userAgent,
hashAlgorithm}, organizationInfo, requestorInfo, SANEntries}`) and is made only
when *Allow new orders (paid)* is on. The answer's `SANVerification` (one `code`
for every domain) becomes the records below, put in place by the certificate's
validation; `performSanVerification {code}`, then `getOrderState` until
`ENROLLED` and `getCertificate` (`certificateDetails/X509Cert`,
`caBundle/X509Cert`). A request still waiting is kept for the next try (and
`getSanVerificationState` says which domain is not verified yet, and why).
`revokeCertificate {revocationReason, serialNumber}`. *Try it* and the list
*Product of a new order*: `getProductList` (type `ISSUE`). Import from a source:
`getOrdersByDateRange` (the orders of *Orders listed (days back)*, 100 a page).
SOAP 1.1 document/literal, namespace `http://webservice.api.muc.unizeto.pl/`,
`requestHeader/authToken {userName, password}`, `responseHeader/successCode` 0.

| *Domain validation (DCV)* | `approverMethod` | What is put in place | Validations that can |
|---|---|---|---|
| DNS TXT at `_certum.` | `DNS_TXT_PREFIX` (the default) | TXT `_certum.DOMAIN` holding the code | every DNS validation that writes TXT records |
| DNS TXT at the domain | `DNS_TXT` | TXT at the domain holding the code | the same |
| DNS CNAME at `_certum.` | `DNS_CNAME_PREFIX` | CNAME `_certum.DOMAIN` → `CODE.certum.pl` | the DNS validations that write CNAMEs |
| DNS CNAME at the domain | `DNS_CNAME` | CNAME DOMAIN → `CODE.certum.pl` | the same |
| HTTP file | `FILE` | `http://NAME/.well-known/pki-validation/certum.txt` holding `CODE-certum.pl` | the HTTP validations. Not for wildcards |

Verified against Certum's own documents: the WSDL
https://gs.test.certum.pl/service/PartnerApi.wsdl (api-docs
`certum/PartnerApi-test.wsdl`: every element, its order and type), the *API -
User Guide EN 5.19* (https://repository.certum.pl/API/EN/API%20-%20User%20Guide%20EN%205.19.pdf,
api-docs `certum/API-User-Guide-EN-5.19.pdf`: 4.2.3 the DCV records, 5.1 - 5.6 the
calls, the error codes) and https://support.certum.eu/en/domain-verification-methods/
(the file's name), quoted in api-docs `certum/notes.md`; the REST API's
`certum/certum-certmanager-rest-openapi-v0_2.json` was read to rule it out.

Where to get credentials: a Certum partner account (https://partnerregistration.certum.pl/)
with the API on, its login and password, the product codes it may order and the
**IP addresses acme calls from** (at most three, static). *Customer* is the end
customer's ID - not the partner login (error 1023).

*Less certain*: the production endpoint `https://gs.certum.pl/service/PartnerApi`
(from the address of its WSDL, which is behind the IP allow list - a setting);
whether the TXT record holds the code without a suffix (the guide: "place the code
in the TXT record"); the file's name `certum.txt` (from the support page - the API
does not answer it); the date-time format of `getOrdersByDateRange` (the WSDL says
`xs:dateTime`, the guide `YYYY-MM-DD`); whether a reissue keeps the order ID (the
one answered is used). A renewal order (`renewCertificate`, a product of type
`RENEWAL`) is not made: when an order cannot be reissued any more, a new order is
(only with *Allow new orders (paid)*).

## GoGetSSL (reseller API)

What it is: GoGetSSL, the reseller (Sectigo, DigiCert, GoGetSSL brands), through
its **API v1** (`https://my.gogetssl.com/api/`).

What acme does: signs in (`POST /auth {user, pass}` → `key`, sent as `auth_key`;
it lives 365 days, kept for 30). A certificate is **reissued inside an order
bought already** (free) - *Order to reuse*, the one it was imported from, or the
one acme made last: `POST /orders/ssl/reissue/{order_id} {csr, dcv_method,
dns_names, approver_email(s)}`. A **new order is a purchase** (`POST
/orders/add_ssl_order {product_id, period, csr, server_count, dcv_method,
dns_names, admin_*, tech_*, ...}`), made only when *Allow new orders (paid)* is on;
*More fields of a new order* adds what an OV/EV order wants (`org_*`,
`webserver_type`...). The DCV data of the answer (`approver_method` and each
`san[].validation`) is put in place by the certificate's validation, GoGetSSL is
asked to look again once (`POST /orders/ssl/revalidate/{order_id} {domain}` - at
most once in 300 s), then `GET /orders/status/{order_id}` until `active`: the
certificate is `crt_code`, its CA's `ca_code`. *Try it*: `GET /account/balance`.
The list *Product of a new order*: `GET /products/ssl`. Import from a source: `GET
/orders/ssl/all?limit=100&offset=N`, each active order read (`orders/status`).
**No revocation** - the API has none; the action *Cancel the order to reuse*
asks for `POST /orders/cancel_ssl_order {order_id, reason}` (reviewed by GoGetSSL
in 2 - 48 hours, refunded within 30 days). Errors come as HTTP 200 with `{"error":
true, "message", "description"}`, said in words without the password or key.

| *Domain validation (DCV)* | `dcv_method` | What is put in place | Validations that can |
|---|---|---|---|
| DNS CNAME record | `dns` | the `record` "NAME CNAME TARGET" (`_HASH.NAME` → `...comodoca.com`) | the DNS validations that write CNAMEs |
| HTTP file | `http` | `link` (`/.well-known/pki-validation/HASH.txt`) holding `content` | the HTTP validations. Not for wildcards |
| E-mail | `email` | nothing: the CA mails `approver_email` (*Approver mailbox*@ the domain) | no validation needed |

Verified against GoGetSSL's own documentation, published as Postman collections:
https://doc-v1.gogetssl.com (https://documenter.getpostman.com/view/5593375/T1LHFp7m,
api-docs `gogetssl/gogetssl-api-v1.postman_collection.json`: auth,
getSslProducts, addSSLOrder, reissueSSLOrder, getOrderStatus, revalidate,
getAllSSLOrders, cancelOrder, getAccountBalance) and https://doc-v2.gogetssl.com
(`gogetssl/gogetssl-api-v2.postman_collection.json`), quoted in api-docs
`gogetssl/notes.md`. The PHP SDK on Packagist is a third party's and was not
used.

Where to get credentials: the GoGetSSL client area → Reseller Modules → API
settings: the API password (not the account's); the login is the client area's.

*Less certain*: whether `ca_code` holds the whole chain (what it holds is put in
order); the largest `limit` of `orders/ssl/all` (100 a page is asked); `test=Y`,
seen in examples without a description, is not sent. API v2 (`Authorization: GGS
CODE:PASSWORD`, `dns-txt`) is not used: the name of its TXT (and CNAME) record is
not documented. HTTPS file validation (`https`) is not offered: the validations
put files for `http://`. No sandbox was found (real orders can be cancelled within
30 days for a refund).

## Namecheap SSL (API)

What it is: the SSL certificates sold by Namecheap (Sectigo's), through the
Namecheap API (`namecheap.ssl.*`, XML).

What acme does: a certificate bought already (*Certificate to reuse*, the one it
was imported from, or the one acme had last) is **activated** when it is new
(`namecheap.ssl.activate`) or **reissued** when it is active
(`namecheap.ssl.reissue`, free) - with the CSR, `AdminEmailAddress` and the DCV
method. A **new certificate is a purchase** (`namecheap.ssl.create {Years, Type,
SANStoADD}`) and is bought only when *Allow new orders (paid)* is on. The CNAME or
file of the activation's answer (`DNSDCValidation/DNS {HostName, Target}`,
`HttpDCValidation/DNS {FileName, FileContent}`) is put in place by the
certificate's validation, `namecheap.ssl.resendApproverEmail` asks the CA to look
again ("retries HTTP/DNS validation"), then `namecheap.ssl.getInfo
{Returncertificate, Returntype Individual}` until `active`: the certificate and
its `CaCertificates`. A reissue makes a child certificate - acme follows the
parent's `ReplacedBy` until it gets the one of its key. `namecheap.ssl.getList`
(100 a page) for *Try it* and Import from a source; `namecheap.ssl.revokecertificate
{CertificateID, CertificateType}` revokes - Namecheap documents it for
certificates **replaced by a reissue**. Every call carries `ApiUser`, `ApiKey`,
`UserName`, `ClientIp` (POST, URL-encoded), production or sandbox. The list *Type
of a new certificate* is the fixed list of `create`'s Type values (PositiveSSL,
EssentialSSL, InstantSSL, InstantSSL Pro, PremiumSSL, EV SSL, the Wildcard and
Multi Domain ones, Unified Communications) - no call lists them.

| *Domain validation (DCV)* | Sent | What is put in place | Validations that can |
|---|---|---|---|
| DNS CNAME record | `DNSDCValidation=true`; multi-domain: `CNAMECSRHASH` for each name | CNAME `HostName` → `Target` (`_HASH.NAME` → `...comodoca.com`) | the DNS validations that write CNAMEs |
| HTTP file | `HTTPDCValidation=true`; multi-domain: `HTTPCSRHASH` | `http://NAME/.well-known/pki-validation/FileName` holding `FileContent` | the HTTP validations. Not for wildcards |
| E-mail | `ApproverEmail` (*Approver mailbox*@ the domain) | nothing: the CA mails it | no validation needed |

Note the spelling: `activate` and `reissue` take `CNAMECSRHASH` / `HTTPCSRHASH`;
`editDCVMethod` would take `CNAME_CSR_HASH` / `HTTP_CSR_HASH` - acme does not call
`editDCVMethod` (the retry is `resendApproverEmail`). Namecheap's DNS DCV is a
CNAME only - there is no TXT.

Verified against Namecheap's own pages (namecheap.com refuses scripts; read from
their 2025 copies in the Wayback Machine, quoted in api-docs `namecheap/notes.md`):
https://www.namecheap.com/support/api/intro/,
https://www.namecheap.com/support/api/global-parameters/,
https://www.namecheap.com/support/api/error-codes/,
https://www.namecheap.com/support/api/methods/ssl/create/,
https://www.namecheap.com/support/api/methods/ssl/activate/,
https://www.namecheap.com/support/api/methods/ssl/get-info/,
https://www.namecheap.com/support/api/methods/ssl/reissue/,
https://www.namecheap.com/support/api/methods/ssl/get-list/,
https://www.namecheap.com/support/api/methods/ssl/revokecertificate/,
https://www.namecheap.com/support/api/methods/ssl/resend-approver-email/,
https://www.namecheap.com/support/api/methods/ssl/editdcvmethod/.

Where to get credentials: Profile → Tools → Namecheap API Access: switch it on
(the account must meet Namecheap's requirements), the API key, and **whitelist
the IPv4 address acme calls from** (*Client IP*).

*Less certain*: whether the ID a reissue answers is the child's (acme follows
`ReplacedBy`); whether a multi-domain activation wants `ApproverEmail=CNAMECSRHASH`
beside `DNSApproverEmails` (sent so); whether `FileContent`'s words belong on one
line in the file (written as answered); revoking a certificate that was not
replaced (said as Namecheap answers); whether the live pages changed since the 2025
copies. A renewal purchase (`namecheap.ssl.renew`) is not made - a new certificate
is (only with *Allow new orders (paid)*).

`test/test_sources_resellers.py` lists, for each of these four, every call the
module may make as its vendor documents it (a contract test), and checks the
lists of AWS Private CA and EJBCA.

`test/test_sources_vendors.py` lists, for each of these five, every path the
module may call as the vendor's client has it (a contract test).
