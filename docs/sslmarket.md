# Commercial certificates from SSLmarket (DigiCert, GeoTrust, Thawte, RapidSSL, Sectigo)

The `sslmarket` issuer (Sources → Add → *SSLmarket.cz (DigiCert, Sectigo,
GeoTrust…)*) orders, reissues and downloads commercial certificates through the
REST API of **SSLmarket** - the Czech reseller run by ZONER a.s., one platform
behind SSLmarket.cz, .sk, .com, .de, .at, .ch, .hu and .co.uk. The key and the
CSR are made by acme as for every other source; the DCV (domain control
validation) record or file is put in place by the certificate's own challenge
module, so acme's DNS server, deSEC, Cloudflare, Route 53, HTTP over SSH… work
for commercial certificates as they do for Let's Encrypt.

Commercial certificates cost money. **acme never buys anything unless the source
says it may** (*Allow new orders (paid)*), and by default a renewal is a free
**reissue** inside the order that is paid already.

## Where the API's description comes from

| Source | What it says |
|---|---|
| <https://www.sslmarket.com/ssl/sslmarket-api-for-ordering-certificates> (also .co.uk, .cz: *API SSLmarketu pro objednávání certifikátů*) | the API key goes in the header `X-Auth-Token`; example `GET /api/order/list`; 2XX on success, 4XX with the error's kind and description; the functions: product list, new order, order list, order detail, order change, reissue (and its cancelling), revocation, certificate download, DCV e-mail again, CSR / certificate decoder, OCSP |
| <https://www.sslmarket.cz/api/swagger-ui/> | the API's OpenAPI (Swagger) - **the reference to compare with** (see *What is not certain*) |
| <https://www.sslmarket.com/ssl/manual-work-with-api-using-the-postman-tool>, <https://www.sslmarket.cz/blog/nebojte-se-api-usetri-vam-cas> | the API by hand, with Postman |
| <https://www.sslmarket.cz/blog/vyuzijte-vylepsenou-api-pro-objednani-vsech-typu-certifikatu> | 2020: the second generation, all kinds of certificates, downloads |
| the older API page (`…/sslmarket-api-for-ordering-certificates-old`) | `GET /product/list`, `POST /order/certificate/{PRODUCT_CODE}` |
| <https://github.com/SSLmarket-from-ZONER/SSLmarket-API> (2015, archived) | the first API: a form POST to `/api` with customer number and password; the names of an order's fields (below). It could not download certificates and is not spoken |
| <https://www.sslmarket.com/ssl/automate-certificate-issue-and-installation-acme-protocol>, <https://www.sslmarket.com/blog/acme-and-eab-support-for-web-servers-2025> | DigiCert certificates by ACME with EAB (see *ACME instead*) |

## The API key (Czech: *API klíč*)

In the customer administration of SSLmarket (*Zákaznická administrace*): the
account's settings (*Nastavení účtu*) → **Přístup k účtu přes API** (*Account
access via API*) → switch it on; the key is shown there. Put it in **API key**.
It belongs to the legal account (*účet*): everything ordered with it is paid from
that account's credit (*kredit*) and shows in its orders (*Objednávky*). Keep it
secret - with it anybody can buy certificates on your account.

*SSLmarket* chooses the shop the account is at (SSLmarket.cz for Czech
accounts, prices in CZK). There is **no public sandbox**: *Another address* is for
a test system SSLmarket gives you; otherwise test with *Try it*, the actions and a
cheap DV product.

## What happens on an order

1. **Reissue or buy?** With *At a renewal* = *Reissue…* (the default) and an
   order known - *Order to reuse*, or the one acme made last for this
   certificate - its detail is read. While its subscription runs for more than
   *Reissue while the subscription runs at least* (30 days), the certificate is
   **reissued** (`POST /order/reissue/{order}` with the new CSR) - free, said in
   the job. Otherwise a purchase would be needed: a **renewal order**
   (`method=renew`), or a **new order** for the first certificate - made only when
   *Allow new orders (paid)* is on. Off, the job stops with *nothing ordered: … a
   renewal order would be a purchase. Paid orders are not allowed for this source*
   and acme does not try again by itself (it would not help).
2. **The order** (`POST /order/certificate/{product}`): the CSR, the names
   (`domain` = the first, `sans` the others), the subscription years, the DCV
   method, the contact person and - for OV/EV - the organisation. The order
   number is kept at once, so whatever happens after, it is not bought twice.
3. **DCV.** The record or file the answer asks for (or the order's detail) is put
   in place by the certificate's challenge module (Certificates → the
   certificate → validation, as for ACME), then waited for until visible:
   * DNS TXT - by every DNS module (their `add_txt`), at the name the API says, or
     `_dnsauth.NAME` when it says none (*Label of the DNS TXT record*; `@` for NAME
     itself). A CNAME at that name is followed, as for `_acme-challenge`. With
     *acme's own DNS server*, the record must be `_acme-challenge.NAME` (the only
     name it is delegated) - otherwise the record is said in the job to be made by
     hand.
   * HTTP file - `/.well-known/pki-validation/…` (DigiCert: `fileauth.txt`) is
     written by *HTTP over SSH* (next to its `acme-challenge` folder); a file under
     `/.well-known/acme-challenge/` by every HTTP-01 module. *HTTP-01 on this
     server* serves only `acme-challenge`.
   * DNS CNAME (Sectigo) - no challenge module writes CNAME records: the job says
     the record to make by hand, and the order waits for it.
   * E-mail - the CA writes to the approver address (`admin@`, `hostmaster@`… or
     WHOIS); somebody has to click. No challenge module is needed.

   The records **stay in place until the certificate is issued** (a CA checks in
   its own time), and are taken away then - or when the order is rejected.
4. **Waiting.** The order's detail is asked every *Ask again every* (15 s, longer
   each time, at most 2 minutes) for *Wait for the certificate* (600 s). DV is
   usually done in minutes. **OV/EV** takes the CA hours or days (it checks the
   company register and may phone the contact): the job ends *the order N waits
   at SSLmarket … acme asks for the certificate again at the next try - nothing is
   ordered again*, and the certificate is *failed* until a later try (5 minutes,
   doubled each time) finds it issued. The order, its DCV records and the key it
   was made with are kept in the module's state (`sslmarket-pending:<certificate
   id>`, the key sealed); a later try takes that key, not the new one the renewer
   made, so the certificate and key always go together.
5. **Download** (`GET /order/download/{order}`): PEM, PKCS#7 or JSON holding
   them; the certificate for the request's key is taken, the chain put in order.

## The settings

| Field | |
|---|---|
| SSLmarket / API address | the shop of the account; *Another address* for a test system |
| API key | see above |
| Product | the common products by the codes of SSLmarket's documentation; *Another product* + *Product code* for any other (*Load the products* lists your account's codes and prices) |
| Subscription (years) | what a new order buys (1-5). A certificate lives at most 200 days since March 2026 (CA/B Forum; 398 before, shorter from 2027): a longer subscription is served by reissues |
| Kind of validation | DV / OV / EV - OV and EV need the organisation (name, street, city, post code, country, IČO, phone) |
| Domain validation (DCV) | DNS TXT, DNS CNAME, HTTP file, e-mail (+ approver) |
| Contact | first and last name, e-mail, phone of the person asking (the CA's contact for OV/EV) |
| At a renewal | *Reissue inside the order while its subscription runs* (default) / *Always a renewal order (paid)* / *Always a new order (paid)* |
| Allow new orders (paid) | **off by default** - see above |
| Order to reuse | an order bought already (in the administration, or a multi-year subscription): the certificate is reissued in it |
| More | voucher, *More order fields* (`key=value` lines added to every order and reissue, e.g. `invoice_vat_id=CZ12345678`), the waits, JSON or form fields, the header of the key, and **every path** of the API |

Set *Keep the key* on a certificate only when you want it; it is not needed for
pending orders (acme keeps their key itself).

## Pricing caution (*Pozor na cenu*)

* A new order and a renewal order are paid from the account's credit (*kredit*)
  or invoiced (*faktura*) - VAT included as the account says. Look at the prices
  with *Load the products* before switching on paid orders.
* A **reissue** (*reissue / znovuvydání*) inside a running subscription is free;
  a multi-year subscription (*vícerokové předplatné*) bought once is renewed by
  reissues until it ends. That is the default here, and the job says *free,
  nothing is bought* each time.
* Changing the names of a certificate may not be a reissue (more SANs cost more):
  the API then refuses the reissue, and the job says so.
* Revocation (*revokace*) does not refund an order.

## Revocation, trying it, actions

* **Revoke** (`POST /order/revoke/{order}`) - the order is the one the
  certificate came from (acme remembers it by the serial), else *Order to reuse*.
* **Try it** reads the product list and, where the API says it, the account's
  credit: *signed in…; N products; the product X is offered; credit …; new paid
  orders not allowed (reissues only)*. Nothing is ordered.
* **Load the products** lists codes, names and prices in the job (and keeps them).
* **List the orders** lists the account's orders with their state and the end of
  their subscription - to find the *Order to reuse*.

## What is not certain

The Swagger could not be read when this module was written; what is documented
publicly is the authentication (`X-Auth-Token`), `GET /api/order/list`, `GET
/product/list`, `POST /order/certificate/{PRODUCT_CODE}` and the list of
functions. So:

* **The paths** of order detail, reissue, download, revocation and account are
  the module's best guess (`/order/detail/{order}`, `/order/reissue/{order}`,
  `/order/download/{order}`, `/order/revoke/{order}`, `/account/detail`); each is a
  setting under *More* (`{order}` and `{product}` filled in). A 404 says *the path
  under More differs from the API's Swagger*.
* **The order's field names** are those of the documented first API (`domain`,
  `sans`, `sans_count`, `years`, `csr`, `dv_auth_method` = `DNS` / `FILE` /
  `Email` / `CNAME` (a guess), `verify_mailbox`, `owner_*`, `auth_*`, `tech_*`,
  `voucher`, `method` = `new` / `renew`); sent as JSON (or form fields, *Sent
  as*). What else the API wants goes in *More order fields*.
* **The answers** are read tolerantly: the order number from `order_id`, `id`,
  `order_number`…; the state from `status` / `state` (issued, active, completed,
  vydáno… / rejected, cancelled, revoked… / anything else: waiting); the end of the
  subscription from `subscription_end`, `valid_to`, `expires`…; the DCV from
  `dcv` / `validation` lists or per-domain maps with `record_name` / `host`,
  `record_value` / `value` / `token`, `file_path` / `file_url`, `file_content`.
* **The product codes** of today may differ from the documented ones (Symantec
  became DigiCert): use *Load the products*.

Before the first paid order: compare the Swagger with the paths and fields above,
order a cheap DV certificate with *Allow new orders (paid)* on, and switch it off
again if renewals should only be reissues.

## ACME instead (DigiCert with EAB)

SSLmarket also sells DigiCert certificates through **ACME with External Account
Binding**: the customer administration hands out the EAB key id and HMAC key, the
directory URL is DigiCert's. That path needs no `sslmarket` source: use the `acme`
source with *CA* = **DigiCert (EAB - CertCentral, SSLmarket)**
(`https://acme.digicert.com/v2/acme/directory/`; a regional or other URL
SSLmarket gives you as *Another ACME server*) and the EAB key id / HMAC key from
SSLmarket. DigiCert validates the organisation once after the ACME account is
activated (OV/EV); then each order is the ACME flow of `acme-issuers.md` (DNS-01
or HTTP-01, ARI). What it costs is agreed with SSLmarket for the ACME account, not
per order through this module.

## When it fails

| The job says | Do |
|---|---|
| *SSLmarket refuses the API key (401)* | the key; *Account access via API* switched on |
| *nothing ordered: … Paid orders are not allowed for this source* | set *Order to reuse* to an order you bought, or switch on *Allow new orders (paid)* |
| *SSLmarket: not enough credit for the order (402)* | top up the credit (*dobít kredit*) |
| *SSLmarket answers 404 for … the path under More differs* | compare the path with the Swagger |
| *the order N waits at SSLmarket* | OV/EV: answer the CA (phone, documents); DCV: is the record visible? e-mail: click |
| *put in place by hand, for the CA: …* | make that DNS record / file yourself; the next try asks again |
| *the certificate of order N is for another key* | another reissue of the order was made meanwhile (in the administration) - try again |
| *SSLmarket took the order but said no order number* | look in the administration first - a second order would be paid again |
