# SSL.com (SWS API) - setup for acme

The **SSL.com (SWS API)** source gets certificates from SSL.com through its SSL Web Services (SWS) API (`sws.sslpki.com`): acme **rekeys** the certificate with its own CSR inside an order or voucher bought already (`PUT /certificate/{ref}`), or - only when *Allow new orders (paid)* is on - orders a new one (`POST /certificates`, a purchase). The **domain validation (DCV)** file SSL.com answers with is put in place by the certificate's own HTTP validation (`/.well-known/pki-validation/`), or SSL.com e-mails an approver; acme reads the order until the certificate is issued. **The private key never leaves acme.** Revocation by serial is included; *Import from a source* lists the account's orders. A DNS DCV method is not offered (its value is not documented). For SSL.com by ACME (EAB) use the ACME source's *SSL.com* presets. No IP addresses.

## What you need

- An SSL.com account with **API credentials** (account key + secret key) and funds or orders/vouchers bought already.
- HTTPS access **from acme** to `sws.sslpki.com` (sandbox: `sws-test.sslpki.com`, a separate account) port 443.
- For HTTP DCV: an HTTP validation in acme that can place a file at `http://<name>/.well-known/pki-validation/` (port 80 from the internet; no wildcards). For e-mail DCV: a person reading the approver mailbox.

## Set up SSL.com

1. Sign in to the SSL.com dashboard → **API credentials** (the account's developer / API page): copy the **account_key** and **secret_key** (regenerate if needed). The same page shows the ACME credentials - not needed here.
2. Buy the certificates acme will rekey and note each **order reference** (e.g. `co-ac1ecm200`), or fund the account and decide whether acme may buy.
3. For the sandbox, create an account on `sandbox.ssl.com` - it has its own keys.
4. CAA records, if any: `0 issue "ssl.com"`.

Check the credentials:

```sh
curl -s "https://sws.sslpki.com/certificates?account_key=$AK&secret_key=$SK&per_page=1"
```

## Fill in acme

Sources → **Add** → **SSL.com (SWS API)**.

| acme field | What to put there |
|---|---|
| Account key / Secret key | from step 1 |
| Environment | *Production* or *Sandbox* |
| Order to reuse | an order (or voucher) reference - rekeyed with acme's request; empty: the one acme made last |
| Allow new orders (paid) | **off** unless acme may buy |
| Product of a new order | *Load the list* or a code (e.g. `106` Basic; only 100, 102 and 107 take more than one name) |
| Period of a new order (days) | `365` (up to `1826`; 30/90 for Free SSL) |
| Server software (code) (advanced) | `1` (OTHER) |
| Domain validation (DCV) | *HTTP file* (default) or *E-mail* + *Approver mailbox* |
| Contact: first name / last name / e-mail / phone / country | the order's contact (required) |
| API address, Waits (advanced) | empty; `600` / `300` / `30` |

## Check it

- Sources → the source → **Test** (Try it): signs in and reads the orders - buys nothing.
- In the dashboard the order shows its validation state and the issued certificate.

## Common problems

| Problem | Fix |
|---|---|
| `401` / invalid credentials | wrong account_key / secret_key, or production keys used on the sandbox (or the other way) |
| *a purchase would be needed* | set *Order to reuse*, or switch *Allow new orders (paid)* on |
| A multi-name certificate refused | the product takes one name - choose 100, 102 or 107 |
| DCV file not found | port 80 of the name not reachable from the internet, or a redirect elsewhere - check `/.well-known/pki-validation/` |
| Wildcard refused | HTTP DCV cannot validate wildcards - use e-mail, or the ACME source |
| Waits for validation | e-mail DCV: someone must approve; OV/EV: SSL.com's vetting |
