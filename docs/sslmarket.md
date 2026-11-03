# Commercial certificates from SSLmarket (DigiCert, GeoTrust, Thawte, RapidSSL, Sectigo)

SSLmarket - the Czech reseller run by ZONER a.s., one platform behind
SSLmarket.cz, .sk, .com, .de, .at, .ch, .hu and .co.uk - has a REST API for
ordering certificates and for ACME keys. acme speaks it with two sources
(Sources → Add):

| Source | What it does | Renewals |
|---|---|---|
| **SSLmarket.cz (DigiCert, Sectigo, GeoTrust…)** (`sslmarket`) | orders a certificate (paid - only when allowed), reissues it inside the order (free), puts SSLmarket's DCV string in place by the certificate's validation, downloads the certificate | a free reissue while the order runs |
| **SSLmarket ACME (DigiCert, EAB made through the API)** (`sslmarket_acme`) | makes an ACME key at SSLmarket through the API (directory URL + EAB), then orders every certificate by ACME, each name proved by DNS-01 / HTTP-01 like Let's Encrypt | fully automatic, ACME (ARI) - no order, no DCV of SSLmarket's |

In both, the key and the CSR are made by acme. The DCV records and the ACME
proofs are put in place by the certificate's own validation module - acme's DNS
server, deSEC, Cloudflare, HTTP over SSH… - as for any other source.

## The API

SSLmarket's OpenAPI 3.0 specification (*SSLmarket's API for ordering
certificates*, kept in `test/fixtures/sslmarket-openapi.json`; the tests check
every call of these sources against it):

* server `https://www.sslmarket.cz/api` (the other shops: `https://www.sslmarket.<tld>/api`),
* the account's key in the header **`X-Auth-Token`**,
* JSON; 2XX on success, 4XX with `{"message": "…"}` - said in the job as it is
  (*SSLmarket refused the order (400): …*). 401/403: the key; 429/5XX are tried
  again later, any other 4XX is not (it would not help).

Also: <https://www.sslmarket.com/ssl/sslmarket-api-for-ordering-certificates>,
<https://www.sslmarket.cz/api/swagger-ui/>,
<https://www.sslmarket.com/ssl/manual-work-with-api-using-the-postman-tool>.

| Call | Used for |
|---|---|
| `GET /product/list` | *Load the products*, *Try it* (product_code, title, validate_type, max_years, SANs) |
| `GET /order/list` | *List the orders*; finding a new order (see below) |
| `POST /order/certificate/{PRODUCT_CODE}` | a new order (paid) |
| `GET /order/order_id/{ID}` | the order: state, expired, certificate_serial_number, reissue_pending, dv_auth_method, dv_auth_content, has_child / child_id |
| `PUT /order/order_id/{ID}` | the request and DCV method put into an order bought but not issued yet |
| `POST /certificate/order_id/{ID}/reissue` | the free reissue with the new CSR |
| `PUT /certificate/order_id/{ID}/cancel-reissue` | a reissue running already (not acme's) is cancelled before acme's; also an action |
| `PUT /certificate/order_id/{ID}/resend` | *Send the DCV e-mail again* |
| `PUT /certificate/order_id/{ID}/revoke` | revocation - **DigiCert Client Premium (Class 1 and 2) only**, says the specification |
| `GET /certificate/order_id/{ID}/format/{pem_server, pem_intermediate, p7b}` | the certificate and its chain |
| `POST /acme`, `GET /acme/list`, `PUT /acme/acme_id/{ID}/revoke`, `GET /acme/organization/list` | the ACME source |

Not used: `/tool/decoder/csr`, `/tool/decoder/certificate`, `/tool/ocsp` (acme
reads requests and certificates itself, and checks OCSP itself).

## The API key (Czech: *API klíč*)

In the customer administration (*Zákaznická administrace*): the account's
settings (*Nastavení účtu*) → **Přístup k účtu přes API** (*Account access via
API*) → switch it on; the key is shown there. Put it in **API key** of either
source. It belongs to the legal account: everything ordered with it is paid from
that account's credit (*kredit*) and shows in its orders (*Objednávky*). Keep it
secret - with it anybody can buy certificates on your account.

*SSLmarket* chooses the shop the account is at (SSLmarket.cz for Czech
accounts). There is **no public sandbox**: *Another address* is for a test
system SSLmarket gives you; otherwise test with *Try it*, the actions and a cheap
DV product.

## Filled in from the account

With an account already there, **Find the settings from the account** (over
the source's form; `acme --source-discover NAME`) asks only the API key and
the shop. It reads - nothing is ordered - the products (*Product code*), the
orders still running (*Order to reuse*, never picked by itself) and, from the
detail of the last order, the owner, the contact, the invoice data and the DCV
method; an account with no order gives the owner and contact of its
organisation (`/acme/organization/list`). `sslmarket_acme` offers the ACME keys
of the account (choosing one fills its product, validity and organisation), the
products and the organisations. What the form has already is never replaced
unless ticked; Save keeps it.

## Orders and reissues (`sslmarket`)

### What happens

1. **Reissue or buy?** With *At a renewal* = *Reissue…* (the default) and an
   order known - *Order to reuse*, or the one acme made last for this certificate
   - the order's detail is read. A renewed order (`has_child`) is followed to its
   newest `child_id`.
   * its certificate is issued and the order runs (`expired`) more than *Reissue
     while the order runs at least* (30 days): **reissue** (`POST …/reissue`,
     `{csr}`) - free, said in the job as *free, nothing is bought*;
   * it has no certificate yet (bought in the administration, waiting for a CSR):
     acme puts its request and DCV method into it (`PUT /order/order_id/{ID}`) and
     waits for it - nothing is bought;
   * it ends sooner, or it is cancelled / rejected: a **new order** is needed.
2. **A new order** is a purchase: made only when *Allow new orders (paid)* is on.
   Off, the job stops with *nothing ordered: … a new order would be a purchase.
   Paid orders are not allowed for this source* and acme does not try again by
   itself. `POST /order/certificate/{PRODUCT_CODE}` carries the request, the first
   name as `domain`, the others as `dns_names`, `years`, `dv_auth_method`, the
   owner, the contact (as `auth_*` and `tech_*`) and the invoice (the owner's
   address and the contact's e-mail when left empty) - every field the
   specification requires. The 201 has no body in the specification: an
   `order_id` in it is taken, else the new order is found in `/order/list` (the
   same domain and product, not in the list read just before). The order number
   is kept at once, so it is never bought twice.
3. **DCV** (`dv_auth_method`):
   * **DNS** / **FILE** - `dv_auth_content` of the order's detail (asked until it
     is there) is shown in the job and put in place for every name by the
     certificate's validation module: DNS as a TXT record (by every DNS module),
     FILE as `/.well-known/pki-validation/…` (by *HTTP over SSH*; under
     `/.well-known/acme-challenge/` by every HTTP-01 module). What a module cannot
     write (a CNAME record; a TXT record with *acme's own DNS server*, which only
     answers `_acme-challenge` names) is said in the job, to be made by hand.
   * **Email** - the CA writes to **admin@, administrator@, hostmaster@,
     postmaster@ and webmaster@** of each domain (the specification; no other
     address can be chosen). Somebody has to confirm it; *Send the DCV e-mail
     again* sends it once more. No validation module is needed.

   The records **stay until the certificate is issued** (a CA checks in its own
   time) and are taken away then, or when the order fails.
4. **Waiting.** The detail is asked every *Ask again every* (15 s, longer each
   time, at most 2 minutes) for *Wait for the certificate* (600 s). Issued means:
   `certificate_serial_number` set, no `reissue_pending` - and after a reissue,
   another serial than before. OV/EV takes the CA hours or days: the job ends *the
   order N waits at SSLmarket … nothing is ordered again*, the certificate is
   *failed* until a later try finds it issued (5 minutes, doubled each time). The
   order, its DCV records and the key it was made with are kept (the key sealed);
   a later try takes that key, so certificate and key always go together.
5. **Download**: `pem_server` (the certificate for the request's key is taken),
   `pem_intermediate` (else `p7b`) for the chain.

### The settings

| Field | |
|---|---|
| SSLmarket / API address / API key | see above |
| Product code | the `product_code` (*Load the products* lists those of your account with kind, validation, years, SANs; a code not there is warned about) |
| Order term (years) | `years` of a new order (checked against the product's `max_years`). A certificate lives at most 200 days (CA/B Forum, since March 2026): a longer order is served by free reissues |
| Domain validation | DNS / FILE / Email |
| Owner | name, street, city, post code, country (ISO 3166 two letters), phone **as +420.123456789** - required for every order (OV/EV: as in the commercial register) |
| Contact | title, first and last name, e-mail, phone - sent as the organisation contact and the technical contact |
| Invoice | name, street, city, post code, country, e-mail, IČO, DIČ - empty: the owner's and the contact's |
| At a renewal | *Reissue inside the order while it runs* (default) / *Always a new order (paid)* |
| Allow new orders (paid) | **off by default** |
| Order to reuse / for the twin | an order bought already. A dual certificate (ECDSA + RSA) has an order for each: the one whose CSR has the request's kind of key is used |
| Allow a second (paid) order for a dual certificate | off: no twin from this source; on: the twin is its own order (bought only when paid orders are allowed) |
| More | voucher, *More order fields* (`key=value`, e.g. another `tech_email`), the TXT label (`_dnsauth`; `@` the name itself), the waits |

### Pricing caution (*Pozor na cenu*)

* A new order is paid from the credit (*kredit*) or invoiced (*faktura*). Look
  at the products and prices before switching paid orders on.
* A **reissue** (*znovuvydání*) inside a running order is free and keeps the
  order's parameters and end ("the same parameters and expiration date as the
  original"); a multi-year order bought once is served by reissues until it ends.
  That is the default, and the job says *free, nothing is bought* each time.
* SSLmarket's renewal of an order is a new order (shown as `has_child`); acme
  follows it.
* Revocation (*revokace*) refunds nothing; through the API only DigiCert Client
  Premium certificates can be revoked - a TLS certificate is revoked in the
  customer administration.

### Orders bought already: Import from a source

*Certificates → Import from a source* with an `sslmarket` source lists the
account's orders (`GET /order/list` - nothing is ordered) and brings in the
certificates of those picked (`…/format/pem_server` and `pem_intermediate`):
each keeps its order number, and its renewals reissue that order - no "Order to
reuse" needed. Its key is added in the certificate's window, or the first
renewal makes a new one (docs/certificates.md "Import from a source").
`sslmarket_acme` cannot list: ACME has no list of what it issued.

## SSLmarket ACME (`sslmarket_acme`)

1. The first certificate (or *Make an ACME key*) makes an ACME key at SSLmarket:
   `POST /acme` with the *ACME product code*, the key's *Name*, the *Certificate
   validity* (1-199 days) and - for OV/EV products - the *Organisation*
   (`organization_id`, see *Load the organisations*: the organisations and their
   validations). The answer's `acme_directory_url`, `ext_act_kid` and
   `ext_act_hmac` are kept in the module's state (the HMAC sealed).
2. From then on it is the `acme` source's own code against that directory: an
   ACME account made once with that EAB, each order proved by DNS-01 / HTTP-01,
   ARI, revocation by ACME. Renewals ask nothing of SSLmarket's API.
3. The EAB is shown by SSLmarket only when the key is made. A key made in the
   administration: paste its EAB key id and HMAC under More - its directory URL is
   found in `/acme/list` by its name. A key by that name of which acme has no EAB
   is not reused: a new one is made (said in the job), or, with *Make the ACME key
   when there is none* off, the job says so.
4. Changing product, name, validity or organisation means another key.
   *Revoke the ACME key* revokes the kept one (`PUT /acme/acme_id/{ID}/revoke`);
   certificates issued with it stay valid. *Load the ACME keys* lists them.

The plain `acme` source with *CA* = *DigiCert (EAB)* and the EAB pasted does the
same where the key was made by hand.

## What is not certain

The specification leaves these open; how acme reads them:

* `dns_names` is "An array of domains included as SANs" of type *string*: sent
  as the names joined by commas (as `/order/list` gives them back).
* The 201 of a new order has no body: the order is found in the order list when
  the answer carries no `order_id`.
* `state` has no list of values ("Issued" is the only one named). Issued is told
  by `certificate_serial_number` and `reissue_pending`; failed by the words
  cancel / reject / revoke / storno / zamítnuto / zrušeno; anything else is
  waiting. The order's end is `expired` ("Date of order's expiration").
* `dv_auth_content` ("the string required for authentication") has no format: a
  record line (`NAME [TTL] [IN] TXT|CNAME VALUE`), JSON with name/value, a URL
  and the file's content, a path and content, or a bare value are understood. A
  bare value goes to TXT `_dnsauth.NAME` (DigiCert; *Label of the DNS TXT record*)
  or `/.well-known/pki-validation/fileauth.txt` (DigiCert). Whatever it is, it is
  shown in the job - words acme cannot read are left to be done by hand.
* The reissue's `csr` is "in Base64": the PEM request is sent (base64 inside its
  lines).
* `ext_act_hmac` is taken as the CA shows EAB keys (base64url).

## When it fails

| The job says | Do |
|---|---|
| *SSLmarket refuses the API key (401)* | the key; *Account access via API* switched on |
| *nothing ordered: … Paid orders are not allowed for this source* | set *Order to reuse* to an order you bought, or switch on *Allow new orders (paid)* |
| *SSLmarket refused the order (400): …* | what SSLmarket's message says (a missing field, the phone format, the product's SANs) |
| *SSLmarket does not know the order N (404)* | the order number |
| *the order N waits at SSLmarket* | OV/EV: answer the CA (phone, documents); DNS/FILE: is the record visible? Email: confirm the mail |
| *put in place by hand, for the CA: …* | make that DNS record / file yourself; the next try asks again |
| *the certificate of order N is for another key* | another reissue of the order was made meanwhile (in the administration) - try again |
| *SSLmarket took the order but it cannot be found in the order list* | look in the administration first - a second order would be paid again |
| *…revokes only DigiCert Client Premium…* | revoke in the customer administration |
| *there is no ACME key for this source* | *Make an ACME key*, or switch on *Make the ACME key when there is none* |
