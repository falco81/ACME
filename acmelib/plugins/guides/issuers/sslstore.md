# The SSL Store (REST API) - setup for acme

The **The SSL Store (REST API)** source gets certificates through the REST API of The SSL Store (TheSSLStore.com, a reseller of Sectigo, DigiCert and other brands): acme **reissues** the certificate with its own CSR inside an order bought already (free), or - only when *Allow new orders (paid)* is on - places a new order (a purchase). The **domain validation (DCV)** record or file the order answers with (a DNS CNAME, or an HTTP file in `/.well-known/pki-validation/`) is put in place by the certificate's own validation, or the CA e-mails an approver; acme downloads the certificate once the order is complete. **The private key never leaves acme.** Revocation is included; *Import from a source* lists the account's orders. Every call carries the **partner code** and **auth token**. No IP addresses.

## What you need

- A The SSL Store partner (reseller) account with **API access**, its **partner code** and an **auth token**.
- Funds for new orders, or orders bought already (their *TheSSLStoreOrderID*).
- HTTPS access **from acme** to `api.thesslstore.com` (Europe: `api.thesslstore.eu`; sandbox: `sandbox-wbapi.thesslstore.com`) port 443.
- A validation in acme that can place the DCV proof (DNS for CNAME, HTTP for the file), or a person for e-mail.

## Set up The SSL Store

1. Sign in to your The SSL Store account → **API Settings**: note the **partner code**, create an **auth token** for acme. Where the page offers an IP allow-list, add acme's public IP.
2. The sandbox account has its own partner code and token and only dummy products - use it for a first test.
3. Note the order IDs (`TSSL-...`) acme will reissue in, or fund the account and decide whether acme may buy.
4. CAA records, if any: allow the CA of the product (e.g. `sectigo.com`, `digicert.com`).

Check the credentials:

```sh
curl -s https://api.thesslstore.com/rest/health/validate -H 'Content-Type: application/json' \
  -d '{"PartnerCode":"<code>","AuthToken":"<token>"}'
```

## Fill in acme

Sources → **Add** → **The SSL Store (REST API)**.

| acme field | What to put there |
|---|---|
| Partner code / Auth token | from step 1 |
| Environment | *Live*, *Live, Europe* or *Sandbox* |
| Order to reuse | `TSSL-9876543` - reissued inside; empty: the order acme made last |
| Allow new orders (paid) | **off** unless acme may buy |
| Product of a new order | *Load the list* (`product/query`) or a code, e.g. `positivessl` |
| Validity of a new order (months) | `12` (one of the product's terms) |
| Server licences, Web server type (advanced) | `1`, `Other` |
| Domain validation (DCV) | *DNS CNAME record* (default), *HTTP file* (no wildcards), or *E-mail* + *Approver mailbox* |
| Contact: first name / last name / phone (numbers only) / e-mail / title | the order's contact (required) |
| API address, Waits (advanced) | empty; `600` / `300` / `60` |

## Check it

- Sources → the source → **Test** (Try it): `health/validate` - the partner code and token checked.
- In The SSL Store's portal the order shows its DCV state and status (*Active* when issued).

## Common problems

| Problem | Fix |
|---|---|
| `isError: true` - authentication | wrong partner code / token, or sandbox credentials on live (or the other way) |
| *a purchase would be needed* | set *Order to reuse*, or switch *Allow new orders (paid)* on |
| Insufficient funds | top up the account |
| DCV pending | the CNAME / file was not visible yet; The SSL Store refreshes order details every 5 minutes - raise the wait |
| Wildcard with HTTP DCV refused | use DNS (CNAME) |
| Phone refused | digits only (e.g. `420123456789`) |
