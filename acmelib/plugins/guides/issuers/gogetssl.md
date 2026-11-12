# GoGetSSL (reseller API) - setup for acme

The **GoGetSSL (reseller API)** source gets certificates bought through GoGetSSL's reseller API: acme **reissues inside an order bought already** (free) or - only when *Allow new orders (paid)* is on - places a new order (a purchase) with its own CSR, puts the **domain validation (DCV)** record or file in place through the certificate's own validation (a DNS CNAME or an HTTP file in `/.well-known/pki-validation/`), or lets the CA e-mail an approver, then downloads the certificate. **The private key never leaves acme.** The API has **no revocation**: the action *Cancel the order to reuse* asks GoGetSSL to cancel (and refund) an order, reviewed by GoGetSSL in 2-48 hours. *Import from a source* lists the account's orders. No IP addresses. (GoGetSSL has no confirmed ACME directory of its own.)

## What you need

- A GoGetSSL reseller account with **API access**, its client-area **login** and **API password**.
- Balance on the account for new orders, or orders bought already to reissue in.
- HTTPS access **from acme** to `my.gogetssl.com` port 443.
- A validation in acme that can place the DCV proof (DNS for CNAME, HTTP for the file), or a person for e-mail.

## Set up GoGetSSL

1. Sign in to the GoGetSSL client area → **Reseller Modules → API settings**: enable API access and set the **API password** (separate from your account password). Add acme's public IP to the API's allowed addresses where the page offers it.
2. Note the **order ID** of a certificate acme may reissue (e.g. `1332864`), or top up the balance and decide whether acme may buy.
3. For OV/EV products, prepare the organization fields the product needs (`org_name`, `org_division`, `org_addressline1`, ... as GoGetSSL's API asks) - they go into *More fields of a new order*.
4. CAA records, if any: allow the CA of the product you buy (e.g. `sectigo.com`, `digicert.com`).

## Fill in acme

Sources → **Add** → **GoGetSSL (reseller API)**.

| acme field | What to put there |
|---|---|
| User | the client-area login |
| API password | from step 1 |
| Order to reuse | an order bought already; empty: the order acme made last |
| Allow new orders (paid) | **off** unless acme may buy |
| Product of a new order | *Load the list* (`/products/ssl`) or a product ID |
| Period of a new order (months) | `12` (up to 60) |
| Server licences (advanced) | `1` (`-1` unlimited) |
| Domain validation (DCV) | *DNS CNAME record*, *HTTP file* (no wildcards), or *E-mail* + *Approver mailbox* |
| Contact: first name / last name / phone / title / e-mail | the order's contact (required) |
| More fields of a new order (advanced) | `name=value` lines, e.g. `org_name=Example s.r.o.` |
| API address, Waits (advanced) | default; `600` / `300` / `20` |

## Check it

- Sources → the source → **Test** (Try it): signs in and reads the account - orders nothing.
- In the client area: **Orders** shows the order, its DCV state and the certificate.

## Common problems

| Problem | Fix |
|---|---|
| Authentication error | wrong login or API password (not the account password), or API access not enabled / acme's IP not allowed |
| *a purchase would be needed* | set *Order to reuse*, or switch *Allow new orders (paid)* on |
| Insufficient balance | top up the account |
| DCV pending | the CNAME / file was not visible yet - raise the wait; for e-mail someone must approve |
| Wildcard with HTTP DCV refused | use DNS DCV |
| OV/EV order refused for missing fields | add them in *More fields of a new order* |
| A certificate must be revoked | not in the API: *Cancel the order to reuse*, or GoGetSSL support |
