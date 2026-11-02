# Commercial certificates from SSLS.cz (AlpiroSSL, Sectigo, PositiveSSL, Certum…)

SSLS.cz (<https://www.ssls.cz/>) - the Czech certificate shop of ZONER a.s. -
sells AlpiroSSL, Sectigo, PositiveSSL, Certum, GeoTrust, DigiCert, Thawte and
RapidSSL certificates, and has an API for ordering them, *SAPI v2*. acme speaks
it with the source **SSLS.cz (AlpiroSSL, Sectigo, Certum…)** (`ssls`, Sources →
Add):

| What it does | Renewals |
|---|---|
| orders a certificate (paid - only when allowed), reissues it inside its subscription (free), puts SSLS.cz's DCV record or file in place by the certificate's own validation, downloads the certificate and its chain | a free reissue (`quickReissue`) while the subscription runs; a new order (paid, when allowed) after |

The key and the CSR are made by acme - the private key never leaves it. The DCV
records are put in place (and taken away again) by the certificate's own
validation module - acme's DNS server, deSEC, Cloudflare, HTTP over SSH… - as for
any other source. Another ZONER shop with another API is SSLmarket
([sslmarket.md](sslmarket.md)).

## The API

*SAPI v2.3.3* (SSLS.cz's PDF, Czech, and its PHP client; the tests in
`test/test_ssls.py` check every call of this source against it):

* `https://api.ssls.cz/v2/{method}/` - **the method's name is case-sensitive**
  (`csrGen`, not `csrgen`), HTTPS only;
* every request is a **POST of a form** - the PHP client sends
  `http_build_query()`: `application/x-www-form-urlencoded`, nested values as
  `dcv[method]=dns`, `admin[firstname]=…`, `san[0]=…`;
* the parameter **`token`** is in every request (never in the address);
  `accountDetail=true` adds the account's state - its credit - to an answer;
* JSON back. A request with a mistake gets `"errors": {"isError": true,
  "errorCode": 1002, "errorMessage": "Invalid token"}` and is not done. acme says
  it in words: *SSLS.cz refuses the API token (…)*, *SSLS.cz does not allow the
  API from this server's address (…)*, *SSLS.cz refused the order: … (error N)*;
* **at most 60 requests a minute and 2000 an hour**: over them the API is blocked
  for 15 minutes, then an hour, then a day. acme asks `certStatus` every 30 s at
  the least, more slowly the longer it waits (at most every 5 minutes), and a
  try that waits longer than *Wait for the certificate* (15 minutes) ends and is
  tried again later - nothing ordered again.

| Method | Used for |
|---|---|
| `allProducts` | the form's product list (*Load the list*), *Try it* (with `accountDetail`: the credit), *Load the products* |
| `servers` | the form's list of server types for the product (optional) |
| `emails` | DCV by e-mail: the approver address of each domain |
| `newOrder` | a new order (`orderType` new) or a renewal (`orderType` renew) - **paid** |
| `quickReissue` | the free reissue with the new CSR (`dcv[method]` file/dns where set) |
| `certStatus` | the state (`P`, `A`, `R`, `C`, `U`, `N`, `E`), the certificate's end `NVA` and the subscription's end `SNVA` |
| `getCert` | the certificate and the intermediate certificates |
| `myCerts` | *List the certificates* |

Not used: `csrGen` (acme makes the key itself), `csr` (acme reads requests
itself), `productDetail` (old). There is no method for revocation.

## The token (Czech: *API nastavení*)

At www.ssls.cz: **Můj účet → API nastavení** - switch the API on, generate the
**token**, and put in the **IPv4 addresses** the API may be used from (several
separated by spaces): the public address acme reaches the internet from (behind
NAT: the router's; a cluster: both nodes'). Put the token in **API token**. It
belongs to the account: everything ordered with it is paid from the account's
credit. Keep it secret - acme keeps it sealed, sends it only in the body of a
request, and never writes it into a job's steps or events.

*Try it* (Sources → Test) reads `allProducts` with `accountDetail`: it says
whether the token and the address are let in, how many products the account can
order, the credit, whether the chosen product is among them and whether paid
orders are allowed. It never orders anything.

## The form

| Field | |
|---|---|
| API token | above |
| **Product** | *Load the list* asks SSLS.cz (`allProducts`, with the token typed or kept - nothing ordered) and fills the choice: name, authority, validation, years. Picking one fills in *Validation of the product*, *Authority of the product* and *The product needs the organisation's details* by themselves. A saved source loads its list when its form opens |
| Subscription (years) | `period` of a new order (1-5, at most what the product sells; checked against the list before ordering). A certificate lives at most 200 days (CA/B Forum, since March 2026): a longer subscription is served by free reissues |
| Domain validation (DCV) | **DNS** / **FILE** / **E-mail** - below |
| Approver mailbox | e-mail only: `admin@` (default), `administrator@`, `hostmaster@`, `postmaster@`, `webmaster@`, or *the first address SSLS.cz offers* |
| Contact | first and last name, e-mail, phone **as 00420123456789** (00 instead of +, digits only), country (two letters) - `admin.*` of every order (and the technical contact) |
| The product needs the organisation's details | OV, EV and every Certum certificate: then *Organisation*, city, street, post code (required), phone, IČO (Certum OV/EV: required), D-U-N-S, e-mail (Certum: required - acme's CSRs hold no e-mail) |
| At a renewal | *Reissue inside the subscription while it runs* (default) / *Always a new order (paid)* |
| **Allow new orders (paid)** | **off by default** |
| Certificate to reuse (SSLS ID) | a certificate bought already (at www.ssls.cz): acme reissues it with its own request. *List the certificates* shows the IDs |
| More | *Product code typed* (only where the list cannot be loaded), *Server type* (`servers` of the product; empty: Apache+OpenSSL - the certificate comes as PEM either way), *A new order for a certificate that had one* (renew / new), *DNS record the CA asks for* (by the product / CNAME / TXT), *Label of the DNS TXT record* (`@`), *Reissue while the subscription runs at least* (30 days), *More order fields* (`tech[email]=…`), the waits, the twin's certificate, *Allow a second (paid) order for a dual certificate* |

The product list is a field of the type `catalog` (`acmelib/plugins/base.py`):
the page asks `POST /api/sources/catalog` (`acmelib/certs/api_catalog.py`), which
runs the module's read-only `catalog('products')` with the form as it is.

## What happens

1. **Reissue or buy?** With *At a renewal* = *Reissue…* and a certificate known -
   *Certificate to reuse*, or the one acme ordered last for this certificate -
   its `certStatus` is read:
   * issued (`A`, `R`), not Certum, and its subscription (`SNVA`; without one
     the certificate's own end `NVA`) runs more than 30 days: **`quickReissue`**
     with the new CSR - free, said as *free, nothing is bought*;
   * still being validated (`P`, `U`): nothing is done, asked again later;
   * cancelled, expired, Certum, or ending sooner: a **new order** is needed.
2. **A new order is a purchase**: only when *Allow new orders (paid)* is on.
   Off, the job stops with *nothing ordered: a new order would be a purchase, and
   paid orders are not allowed for this source…* - no `newOrder` is sent and
   acme does not try again by itself. On, the product is checked against
   `allProducts` (years, SANs), then `newOrder` carries the CSR (its common name
   is the first name), the other names as `san[0]`, `san[1]`…, `period`,
   `dcv[method]`, the contact and - where needed - the organisation. A
   certificate that had an order before is ordered as `orderType=renew` (the
   days left may be carried over), Certum always as a new one. The `certID` (the
   *SSLS ID*) is kept at once with the request's key (sealed), so nothing is
   bought twice and the certificate always comes with the key it was asked for.
3. **DCV** - only `newOrder` and `quickReissue` answer with what the CA wants
   (`certStatus` names only the method), so it is kept with the waiting order:
   * **DNS** - `dnsAuth`: AlpiroSSL, Sectigo, PositiveSSL a **CNAME**
     (`_HASH.example.com CNAME HASH.HASH.sectigo.com`), put at the same label
     under every domain of the certificate; Certum a **TXT** code, put at the
     domain itself (*Label of the DNS TXT record*). Validations that can: those
     that write any record - deSEC, Cloudflare, RFC 2136, … (Readiness and the
     certificate's form say which fit: a CNAME needs a module that writes
     CNAMEs).
   * **FILE** - `fileAuth`: `http://DOMAIN/.well-known/pki-validation/NAME`
     holding the content, for every domain (HTTP over SSH, acme's own port 80).
     The CA fetches it over plain http, with no redirect.
   * **E-mail** - for each domain the approver address is picked from `emails`
     (the product and the domain): the chosen mailbox at the domain itself, else
     at the domain above it, else the first offered; the common name's goes in
     `dcv[email]`, the others' in `dcv[emails]` in the order of `san`. Somebody
     has to click the CA's mail. **No validation module is needed.**

   What acme puts in place stays until the certificate is issued (the CA checks
   in its own time) and is taken away then, or when the order fails. What no
   validation of the certificate can write is said in the job, to be made by hand.
4. **Waiting**: `certStatus` every 30 s (longer each time, at most 5 minutes) for
   *Wait for the certificate* (15 minutes). SSLS.cz recommends checking DV every
   30 minutes, OV every 3 hours, EV every 8 hours - a try that waits longer ends
   with *the certificate N waits at SSLS.cz … nothing is ordered again*, and a
   later try (5 minutes, doubled each time) asks again.
5. **Download**: `getCert` - the certificate for the request's key is taken
   (after a reissue, until the new one is there, the old one is still given:
   acme waits), the intermediates put in order (nearest first).

Push notifications (SSLS.cz posts to a URL of yours when an AlpiroSSL
certificate is issued) are not used: polling is enough, and acme's pages need
not be reachable from the internet.

## Money (*Pozor na cenu*)

* A new order is paid from the credit. Look at the products and prices at
  www.ssls.cz before switching *Allow new orders (paid)* on.
* A **reissue** inside a running subscription is free; a multi-year
  subscription bought once is served by reissues until it ends. That is the
  default, and the job says *free, nothing is bought* each time.
* A dual certificate (ECDSA + RSA) is two orders: the twin is ordered only with
  *Allow a second (paid) order for a dual certificate* (and paid orders allowed).

## What is not certain

The documentation leaves these open; how acme reads them:

* **`allProducts`** has no documented answer. Every object holding a
  `productCode` is a product, wherever it is (a list, or grouped by the
  authority - then the group's name is its authority); its name, authority,
  validation (DV/OV/EV), longest period and SAN count are read from the keys that
  say so. A product acme cannot classify can still be picked; set *Validation of
  the product* and *The product needs the organisation's details* by hand then.
* The **credit** with `accountDetail` has no documented shape either: the first
  value whose key says *credit* / *kredit* is shown.
* `dnsAuth` is described for one domain. For Sectigo the CNAME is made of the
  CSR alone, so the same label and target are put under every domain; Certum's
  TXT code goes at each domain itself. `fileAuth` is put on every domain.
* `dcv.emails`: the example in the documentation lists fewer addresses than
  domains; the table says *for every SAN domain, in the order of san.n* - the
  common name's address is in `dcv.email`.
* The error codes are not listed ("replaced by errorMessage"): a refused token
  is known by code 1002 or the word *token*, a refused address by *IP*, the rate
  limit by *too many requests* / *blokováno*, the credit by *credit* / *kredit*;
  anything else is said as SSLS.cz says it.

## When it fails

| The job says | Do |
|---|---|
| *SSLS.cz refuses the API token* | the token; the API switched on in *API nastavení* |
| *SSLS.cz does not allow the API from this server's address* | add acme's public IPv4 address in *API nastavení* |
| *nothing ordered: a new order would be a purchase…* | set *Certificate to reuse* to a certificate you bought, or switch on *Allow new orders (paid)* |
| *an order needs the …* | fill in the contact (and for OV/EV/Certum the organisation) |
| *SSLS.cz refused the order: … (error N)* | what SSLS.cz's message says |
| *the certificate N waits at SSLS.cz* | OV/EV: answer the CA; DNS/FILE: is the record visible? E-mail: confirm the mail |
| *put in place by hand, for the CA: …* | make that DNS record / file yourself; the next try asks again |
| *SSLS.cz blocks the API for a while* | wait (15 minutes the first time); fewer sources / certificates asking at once |
| *the API of SSLS.cz cannot revoke a certificate* | revoke at www.ssls.cz (*Moje certifikáty*) |
