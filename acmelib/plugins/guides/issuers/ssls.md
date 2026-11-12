# SSLS.cz - setup for acme

The **SSLS.cz (AlpiroSSL, Sectigo, Certum…)** source gets commercial certificates (AlpiroSSL, Sectigo, PositiveSSL, Certum, GeoTrust, DigiCert, Thawte, RapidSSL) from SSLS.cz - the Czech certificate shop of ZONER a.s. - through its API *SAPI v2* (`https://api.ssls.cz/v2/{method}/`, a form POST with the **token**). acme **reissues** a certificate inside its subscription with its own CSR (`quickReissue` - free) while it runs, or - only when *Allow new orders (paid)* is on - **buys** a new order or renewal (`newOrder`). The **DCV** record or file the CA asks for (a CNAME for AlpiroSSL/Sectigo/PositiveSSL, a TXT for Certum, or a file in `/.well-known/pki-validation/`) is put in place by the certificate's own validation and taken away after issuance; or the CA e-mails an approver. acme polls `certStatus` and downloads with `getCert`. **The private key never leaves acme.** There is no revocation method in the API. The API allows at most **60 requests a minute and 2000 an hour** - over that it blocks for 15 minutes, then longer.

## What you need

- An account at www.ssls.cz with the **API switched on**, a **token** and acme's public **IPv4 address(es)** allowed.
- Credit on the account for new orders, or certificates bought already to reissue (their *SSLS ID*).
- HTTPS access **from acme** to `api.ssls.cz` port 443.
- A validation in acme that can place the DCV proof: a DNS module that writes **CNAME** records (Sectigo family) or TXT (Certum), or HTTP on port 80 for the file (no redirect) - or a person for e-mail.

## Set up SSLS.cz

1. At www.ssls.cz: **Můj účet → API nastavení** (*My account → API settings*) - switch the API on, **generate the token**, and enter the **IPv4 addresses** the API may be used from, separated by spaces: the public address acme reaches the internet from (behind NAT the router's; a cluster both nodes'). **Keep the token secret** - everything ordered with it is paid from the account's credit.
2. Look at the certificates bought already (**Můj účet**) and note the *SSLS ID* of one acme may reissue, or decide whether acme may buy.
3. For OV, EV and every Certum product prepare the organisation's details (name, city, street, post code; Certum OV/EV: IČO and e-mail required).
4. CAA records, if any: allow the CA of the product (`sectigo.com`, `certum.pl`, `digicert.com` ...).

## Fill in acme

Sources → **Add** → **SSLS.cz (AlpiroSSL, Sectigo, Certum…)**.

| acme field | What to put there |
|---|---|
| API token | from step 1 |
| Product | *Load the list* (`allProducts`) - fills *Validation* and *Authority of the product* and *The product needs the organisation's details* |
| Subscription (years) | 1-5 (a certificate lives at most 200 days - longer subscriptions are served by free reissues) |
| Domain validation (DCV) | *DNS*, *FILE* or *E-mail* + *Approver mailbox* |
| Contact: first name / last name / e-mail / phone / country | phone **as `00420123456789`** (00 instead of +, digits only) |
| The product needs the organisation's details, Organisation ... | for OV, EV and Certum |
| At a renewal | *Reissue inside the subscription while it runs* (default) or *Always a new order (paid)* |
| Allow new orders (paid) | **off by default** |
| Certificate to reuse (SSLS ID) / for the twin | a certificate bought already; *List the certificates* shows the IDs |
| Product code typed, Server type, A new order for a certificate that had one, DNS record the CA asks for, Label of the DNS TXT record, Reissue while the subscription runs at least, More order fields, Waits (advanced) | as needed; defaults fit most |

## Check it

- Sources → the source → **Test** (Try it): `allProducts` with the account's state - whether the token and address are let in, the products, the credit. Nothing is ordered.
- At www.ssls.cz the certificate shows its state and DCV.

## Common problems

| Problem | Fix |
|---|---|
| *SSLS.cz refuses the API token* (`1002 Invalid token`) | generate the token again and paste it |
| *SSLS.cz does not allow the API from this server's address* | add acme's public IPv4 in API nastavení |
| *nothing ordered: a new order would be a purchase* | set *Certificate to reuse*, or switch *Allow new orders (paid)* on |
| API blocked for 15 minutes / an hour | too many requests from other tools on the same token; acme itself stays under the limits - wait |
| CNAME not made | the certificate's validation cannot write CNAMEs - choose a DNS module that can, or make it by hand as the job says |
| FILE DCV fails | the CA fetches over plain http with no redirect - port 80 must serve the file directly |
| A Certum certificate is never reissued | expected: Certum is always a new order |
