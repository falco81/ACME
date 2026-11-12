# ZeroSSL (REST API) - setup for acme

The **ZeroSSL (REST API)** source gets certificates from ZeroSSL through its REST API (`https://api.zerossl.com`), not ACME: acme creates the certificate with its own CSR (`POST /certificates`), puts the **domain validation (DCV)** record or file in place through the certificate's own validation - a DNS CNAME (`CNAME_CSR_HASH`), an HTTP file in `/.well-known/pki-validation/` (`HTTP_CSR_HASH`) - or lets ZeroSSL send an approval e-mail, asks ZeroSSL to verify, waits until it is `issued` and downloads it with the CA bundle. **The private key never leaves acme.** Revocation is `POST /certificates/{id}/revoke`; *Import from a source* lists the account's certificates. For ZeroSSL by ACME (free 90-day certificates with EAB) use the ACME source's *ZeroSSL* preset instead; this source is for the account's plan as seen in the dashboard: annual certificates where the plan sells them, DCV by e-mail. No IP addresses.

## What you need

- A ZeroSSL account with a **plan** that covers the certificates (number of certificates, multi-domain, wildcard, annual).
- The account's **API access key**.
- HTTPS access **from acme** to `api.zerossl.com:443`, directly or through Settings → Proxy.
- A validation in acme that can put the DCV proof in place: a DNS provider (CNAME records) or HTTP (port 80 of each name reachable from the internet; no wildcards) - or a person who reads the approver mailbox (e-mail).
- `CAA` records, if the domain has any, allowing `sectigo.com` (ZeroSSL issues from Sectigo's CA).

## Set up ZeroSSL

1. Sign in to the ZeroSSL dashboard → **Developer** → copy the **API access key** (*Reset key* makes a new one and invalidates the old).
2. Check the plan (**Billing / Plans**): free plans have a small quota of 90-day certificates and no multi-domain/wildcard; choose a plan that fits.
3. For e-mail DCV, make sure an approver address exists for each domain (`admin@`, `administrator@`, `hostmaster@`, `postmaster@`, `webmaster@`).
4. Allow the CA in DNS where CAA is used:

   ```text
   example.com.  CAA 0 issue "sectigo.com"
   ```

Check the key:

```sh
curl -s -H "Authorization: ApiKey $ZEROSSL_KEY" 'https://api.zerossl.com/certificates?limit=1'
```

## Fill in acme

Sources → **Add** → **ZeroSSL (REST API)**.

| acme field | What to put there |
|---|---|
| API key | from step 1 |
| How the API key is sent | *In the header Authorization: ApiKey* (default); the `access_key` parameter only for an older account that still wants it |
| Validity | `90 days`; *Annual - 200* only where the plan sells annual certificates |
| Domain validation (DCV) | *DNS CNAME record*, *HTTP file* (no wildcards) or *E-mail* |
| Approver mailbox | with e-mail: `admin@` ... or the first ZeroSSL offers |
| API address (advanced) | `https://api.zerossl.com` |
| Wait for the certificate / Wait for the DCV record to be visible / Ask again every (s) (advanced) | `600` / `300` / `15` |

The certificate's validation must be able to place the chosen proof: a DNS validation for CNAME, an HTTP validation for the file.

## Check it

- Sources → the source → **Test** (Try it): signs in and reads the account - orders nothing.
- In the dashboard the certificate goes *Draft → Pending validation → Issued*.

## Common problems

| Problem | Fix |
|---|---|
| `invalid_access_key` / `missing_access_key` | wrong key, or the key is sent the other way - switch *How the API key is sent* |
| `domain_control_validation_failed` | the CNAME / file was not visible yet; acme verifies again at the next try - check the record in public DNS |
| Quota or plan error (`certificate_limit_reached`, ...) | the plan's limit - upgrade or remove drafts |
| Wildcard with HTTP DCV refused | use CNAME (DNS) for wildcards |
| CAA error | allow `sectigo.com` in CAA |
| E-mail validation never finishes | nobody approved the mail - check the approver mailbox |
