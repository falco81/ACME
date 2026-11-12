# SSLmarket (orders and reissues) - setup for acme

The **SSLmarket.cz (DigiCert, Sectigo, GeoTrust…)** source gets commercial certificates (DigiCert, GeoTrust, Thawte, RapidSSL, Sectigo) through the REST API of SSLmarket - the reseller run by ZONER a.s. behind SSLmarket.cz, .sk, .com, .de, .at, .ch, .hu and .co.uk (`https://www.sslmarket.<tld>/api`, header `X-Auth-Token`). acme **reissues** the certificate with its own CSR inside an order that still runs (`POST /certificate/order_id/{ID}/reissue` - free), fills its request into an order bought but not issued yet, or - only when *Allow new orders (paid)* is on - **buys** a new order (`POST /order/certificate/{PRODUCT_CODE}`). The **DCV** string of the order is put in place by the certificate's own validation (a DNS TXT record, or a file in `/.well-known/pki-validation/`), or the CA e-mails `admin@`, `administrator@`, `hostmaster@`, `postmaster@`, `webmaster@`. OV/EV orders waiting at the CA are fetched at later tries. **The private key never leaves acme.** *Import from a source* lists the account's orders. For fully automatic DigiCert DV/OV by ACME use the **SSLmarket ACME** source instead.

## What you need

- A customer account at SSLmarket with **API access** switched on and its **API key** - it belongs to the legal account: everything ordered with it is paid from that account's credit.
- Orders bought already to reissue in, or credit / invoicing for new orders.
- HTTPS access **from acme** to `www.sslmarket.<tld>` port 443.
- A validation in acme that can place the DCV proof: a DNS module for TXT (acme's own DNS server only answers `_acme-challenge` names), *HTTP over SSH* for the file - or a person for e-mail.
- There is **no public sandbox** - test with *Try it* and a cheap DV product.

## Set up SSLmarket

1. Sign in to the customer administration (**Zákaznická administrace**) → account settings (**Nastavení účtu**) → **Přístup k účtu přes API** (*Account access via API*) → switch it on; the **API key** is shown there. **Keep it secret** - with it anybody can buy certificates on your account.
2. Look at **Objednávky** (*Orders*): note an order acme may reissue in (its ID), or buy one in the administration (acme fills in its request).
3. Check products and prices before allowing paid orders; note the **product code** (*Load the products* in acme shows them).
4. Prepare the **owner** (name, address, country, phone as `+420.123456789` - as in the commercial register for OV/EV), the **contact** and optionally the **invoice** data - required for every new order.
5. CAA records, if any: allow the CA of the product (`digicert.com`, `sectigo.com`).

Check the key:

```sh
curl -s -H "X-Auth-Token: $SSLMARKET_KEY" https://www.sslmarket.cz/api/product/list
```

## Fill in acme

Sources → **Add** → **SSLmarket.cz (DigiCert, Sectigo, GeoTrust…)**. *Find the settings from the account* fills products, orders, owner and contact from the account (read only).

| acme field | What to put there |
|---|---|
| SSLmarket / API address | the shop of your account (SSLmarket.cz ...); *Another address* only for a test system SSLmarket gave you |
| API key | from step 1 |
| Product code / Order term (years) | e.g. a DV product's code; years of a new order (a certificate lives at most 200 days - longer orders are served by free reissues) |
| Domain validation (DCV) | *DNS* (TXT), *FILE* (HTTP file) or *Email* |
| Owner ..., Owner's phone | required for new orders; phone as `+420.123456789` |
| Contact: title / first name / last name / e-mail / phone | the organisation and technical contact |
| Invoice: ... | empty: the owner's and the contact's |
| At a renewal | *Reissue inside the order while it runs* (default) or *Always a new order (paid)* |
| Allow new orders (paid) | **off by default** |
| Order to reuse / Order to reuse for the twin | an order bought already (one per key type for a dual certificate) |
| Reissue while the order runs at least (days) | `30` |
| Discount voucher, More order fields, Label of the DNS TXT record, Waits (advanced) | as needed; TXT label `_dnsauth` |
| Allow a second (paid) order for a dual certificate (advanced) | off unless you want ECDSA + RSA twins, each its own order |

## Check it

- Sources → the source → **Test** (Try it): `GET /product/list` - nothing ordered.
- In the administration: **Objednávky** shows the reissue (*znovuvydání*) and the certificate.

## Common problems

| Problem | Fix |
|---|---|
| `401` / `403` | wrong API key, API access switched off, or the wrong shop (.cz vs .sk ...) |
| *nothing ordered: ... a new order would be a purchase* | set *Order to reuse*, or switch *Allow new orders (paid)* on |
| `SSLmarket refused the order (400): ...` | the message names the field: owner / contact data, phone format, product years |
| DCV record not made | the validation cannot write it (a CNAME, or acme's own DNS server for a TXT) - make it by hand as the job says, or use another validation |
| OV/EV waits for days | expected: the CA validates the organisation; acme checks again later |
| Revocation | through the API only DigiCert Client Premium; revoke TLS certificates in the administration |
