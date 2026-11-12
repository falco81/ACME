# SSLmarket ACME (DigiCert) - setup for acme

The **SSLmarket ACME (DigiCert, EAB made through the API)** source makes an **ACME key** at SSLmarket through its REST API (`POST /acme` with the ACME product, the key's name, the certificate validity and - for OV/EV - the organisation) and keeps the answer's ACME directory URL and EAB (key id + HMAC). From then on every certificate is ordered by **ACME** from DigiCert, each name proved by DNS-01 or HTTP-01 like Let's Encrypt, renewed in the CA's ARI window - no orders and no SSLmarket DCV. **The private key never leaves acme.** Actions: *Load the ACME keys*, *Load the organisations*, *Make an ACME key*, *Revoke the ACME key*. The plain ACME source with *DigiCert (EAB)* does the same when you paste a key made by hand.

## What you need

- A customer account at SSLmarket (.cz, .sk, .com, .de, .at, .ch, .hu, .co.uk) with **API access** and its **API key**; credit or invoicing for the ACME product.
- An **ACME product** of the account (its code); for OV/EV the **organisation** validated at SSLmarket.
- HTTPS access **from acme** to `www.sslmarket.<tld>` and to DigiCert's ACME server (`acme.digicert.com` or the regional one in the directory URL), port 443.
- A validation for the names: DNS-01 (a DNS provider's API) or HTTP-01 (port 80 reachable from the internet).

## Set up SSLmarket

1. **Zákaznická administrace** → **Nastavení účtu** → **Přístup k účtu přes API** (*Account access via API*) → switch on and copy the **API key**. Keep it secret.
2. Choose the ACME product (its *product code*) - *Find the settings from the account* in acme lists them - and check its price.
3. OV/EV: the organisation must be validated at SSLmarket; *Load the organisations* shows its id and validations.
4. A key made earlier in the administration: SSLmarket shows its EAB **only when the key is made** - copy the EAB key id and HMAC then; acme finds the directory URL by the key's name.
5. CAA records, if any: `0 issue "digicert.com"`.

## Fill in acme

Sources → **Add** → **SSLmarket ACME (DigiCert, EAB made through the API)**.

| acme field | What to put there |
|---|---|
| SSLmarket / API address | the shop of your account |
| API key | from step 1 |
| ACME product code | the ACME product |
| Name of the ACME key | e.g. `acme-prod` - how the key is called at SSLmarket |
| Certificate validity (days) | 1-199 |
| Organisation | the organisation id for OV/EV (*Load the organisations*) |
| Make the ACME key when there is none | on - the first certificate makes it; off: the job says so instead |
| EAB key id / EAB HMAC of a key made elsewhere (advanced) | for a key made in the administration |

Changing product, name, validity or organisation means another ACME key. The usual ACME settings (contacts, account key, waits) are the ACME source's.

## Check it

- Sources → the source → **Test** (Try it), then **Load the ACME keys** - the key, its product, validity and state.
- Issue a certificate: the job shows the ACME steps (order, DNS-01/HTTP-01 proofs, finalize).

## Common problems

| Problem | Fix |
|---|---|
| `401` / `403` from SSLmarket | wrong API key, API access off, or the wrong shop |
| *a key by that name of which acme has no EAB* | acme makes a new key (or, with making off, says so) - paste the EAB of the existing one, or use another name |
| EAB refused by the ACME server | the key was revoked at SSLmarket, or the HMAC was copied wrong |
| OV/EV refused | set *Organisation* to a validated organisation |
| Challenge failures | as for any ACME CA: the TXT record not visible (DNS-01), port 80 not reachable (HTTP-01), CAA not allowing DigiCert |
| A key must stop working | *Revoke the ACME key* - certificates issued with it stay valid |
