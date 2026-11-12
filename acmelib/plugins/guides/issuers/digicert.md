# DigiCert CertCentral (API) - setup for acme

The **DigiCert CertCentral (API)** source gets commercial **DigiCert, GeoTrust, Thawte and RapidSSL** certificates through the CertCentral Services API v2 (header `X-DC-DEVKEY`). acme **reissues** the certificate with its own CSR inside an order paid already (`/order/certificate/{order}/reissue` - free), or - only when *Allow new orders (paid)* is on - places a new order (`/order/certificate/{product}`, a purchase; a renewal order when the order ends). Domain validation (DCV): acme gets DigiCert's random value, puts the **TXT/CNAME record or file** in place through the certificate's own validation, asks DigiCert to check at once (`check-dcv`) and removes it after issuance; or DigiCert sends an approval e-mail. **The private key never leaves acme.** *Import from a source* lists the orders. Where plain DV or OV of an already validated organization is enough, the ACME source with the *DigiCert (EAB)* preset is fully automatic and simpler; this source is for OV/EV orders of a chosen organization, multi-year plans, a product chosen by name, DCV by e-mail. No IP addresses.

## What you need

- A CertCentral account (US or Europe) with balance or a payment method, and a user whose role may request and reissue certificates.
- An **API key** of that user.
- For OV/EV: the **organization** validated in CertCentral (its ID).
- An order to reuse (a multi-year plan), or permission for acme to buy.
- A validation in acme that can place the DCV proof (a DNS provider for TXT/CNAME, HTTP for the file) - or a person for e-mail DCV.
- HTTPS access **from acme** to `www.digicert.com` (or `certcentral.digicert.eu`) port 443, directly or through Settings → Proxy.

## Set up CertCentral

1. A user for acme (or your own): **Account → Users** - a role allowed to order and reissue (e.g. *Manager* or *Administrator*; check what your account's roles allow).
2. **Automation → API Keys → Add API Key**: name `acme`, the user, and under *API key restrictions* a restriction that still allows ordering and reissuing (e.g. *Orders, Domains, Organizations* - not *View Only*). Copy the key (shown once).
3. OV/EV: **Certificates → Organizations** - the organization validated (OV/EV); its **ID** goes into acme (or use the action *List the organizations* in acme).
4. Domains: pre-validating them in **Certificates → Domains** lets acme skip DCV while it holds (*Skip domains validated already*).
5. CAA records, if any: `0 issue "digicert.com"`.

Check the key:

```sh
curl -s -H "X-DC-DEVKEY: $DIGICERT_KEY" https://www.digicert.com/services/v2/user/me
```

## Fill in acme

Sources → **Add** → **DigiCert CertCentral (API)**.

| acme field | What to put there |
|---|---|
| CertCentral | *CertCentral* (US), *CertCentral Europe*, or *Another address* + API address |
| API key | from step 2 |
| Order to reuse | an order bought already (e.g. `12345678`) - reissued inside it, free; empty: the order acme made last |
| Allow new orders (paid) | **off** unless acme may buy |
| Product of a new order / Product name_id | e.g. *DigiCert Basic OV* (`ssl_basic`); *List the products* shows what the account may order |
| Organization ID | for OV/EV (*List the organizations*) |
| Order validity (years) | 1-3 (a multi-year plan, reissued inside as each certificate ends) |
| Payment of a new order (advanced) | *Account balance*, *Credit card on file*, or as the account sets it |
| Domain validation (DCV) | *DNS TXT record* (default), *DNS CNAME record*, *HTTP file* (no wildcards), *E-mail* |
| Label of the DNS TXT record / Shape of the DNS CNAME record / DCV for (advanced) | `_dnsauth`; `_dnsauth.DOMAIN → RANDOM.dcv.digicert.com`; each name or the registered domain |
| Skip domains validated already (advanced) | on |
| Waits, Ask again every (advanced), Path: ... (advanced) | `600` / `300` / `15`; the API paths need no change |
| Allow a second (paid) order for a dual certificate (advanced) | off unless you want ECDSA + RSA twins, each paid |

## Check it

- Sources → the source → **Test** (Try it), then the actions **List the products**, **List the organizations**, **List the validated domains** - all read only.
- In CertCentral: **Certificates → Orders** shows the reissue and its DCV status.

## Common problems

| Problem | Fix |
|---|---|
| `401` / `invalid_api_key` | wrong key, or the wrong CertCentral (US vs Europe) |
| `403` / access denied | the key's restriction or the user's role does not allow ordering / reissuing |
| *a purchase would be needed* | set *Order to reuse*, or switch *Allow new orders (paid)* on |
| OV/EV order refused | set the *Organization ID* of a validated organization |
| DCV pending | the record was not visible yet (acme asks DigiCert to check again); for e-mail, someone must approve |
| Wildcard with HTTP file refused | use DNS DCV for wildcards |
| The product takes no wildcard | the job refuses before ordering - choose a product that does |
