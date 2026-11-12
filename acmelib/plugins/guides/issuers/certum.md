# Certum (partner API) - setup for acme

The **Certum (partner API)** source gets certificates from Certum (Asseco) through its SOAP **partner API** (`gs.certum.pl/service/PartnerApi`): acme orders with its own CSR - only when *Allow new orders (paid)* is on - or **reissues inside an order bought already** (free, within the product's validity), puts the **domain validation (DCV)** record or file in place through the certificate's own validation (TXT or CNAME at `_certum.<domain>` or the domain itself, or the file `/.well-known/pki-validation/certum.txt`), and fetches the certificate. Revocation is included; *Import from a source* lists the account's orders. **The private key never leaves acme.** For Certum's ACME (an ACME product, kid + HMAC) use the ACME source's *Certum* preset instead. No IP addresses.

## What you need

- A **partner account** of Certum's API (agreed with Certum), its **partner login** and password, and the **customer** the certificates are for.
- acme's public **IP address registered** for the partner account - the API answers only registered addresses.
- Products to order from, or orders bought already to reissue in.
- HTTPS access **from acme** to `gs.certum.pl` (test: `gs.test.certum.pl`) port 443.
- A validation in acme that can place the DCV proof (DNS for TXT/CNAME, HTTP for the file).

## Set up Certum

1. Agree API access with Certum (partner / reseller programme): you get a **partner login** (an SSO account) and its password, and access to the test environment if wanted.
2. Give Certum the **public IP address(es)** acme goes out from (the proxy's, when acme uses Settings → Proxy) to register them for the API.
3. Note the **customer** (its ID or SimplySign login) the certificates are ordered for.
4. Buy the orders acme will reissue in (note an order ID), or decide whether acme may buy new ones.
5. For OV/EV products: the requestor's details and the organization's tax ID are needed in acme.
6. CAA records, if any: `0 issue "certum.pl"`.

## Fill in acme

Sources → **Add** → **Certum (partner API)**.

| acme field | What to put there |
|---|---|
| Certum | *Production (gs.certum.pl)* or *Test* |
| Partner login / Password | from step 1 |
| Customer | the customer's ID or SimplySign login - not the partner login |
| Product of a new order | *Load the list* (getProductList), or a product code |
| Allow new orders (paid) | **off** unless acme may buy |
| Order to reuse | a Certum order ID; empty: the order acme made last |
| Domain validation (DCV) | TXT at `_certum.DOMAIN` (default), TXT at the domain, CNAME at `_certum.DOMAIN` or the domain, or the HTTP file (no wildcards) |
| Requestor (OV/EV), Tax identification number (OV/EV) (advanced) | `email=`, `firstName=`, `lastName=`, `phone=` lines; the tax ID |
| Language, Orders listed (days back), API address, Waits (advanced) | `en`, `825`, empty, `600` / `300` / `20` |

## Check it

- Sources → the source → **Test** (Try it): signs in and reads the products - orders nothing.
- In Certum's partner panel the order shows its DCV state and the certificate.

## Common problems

| Problem | Fix |
|---|---|
| No answer / access denied from the API | acme's public IP is not registered for the partner account |
| Authentication error | wrong partner login or password, or the test vs production environment |
| *a purchase would be needed* | set *Order to reuse*, or switch *Allow new orders (paid)* on |
| Customer not found | *Customer* must be the customer's ID or SimplySign login |
| DCV not verified | the record was not visible yet - raise the wait; check `_certum.<domain>` in public DNS |
| Wildcard with the HTTP file refused | use DNS DCV for wildcards |
| OV/EV order refused | fill in *Requestor* and *Tax identification number* |
