# GlobalSign MSSL (GCC API) - setup for acme

The **GlobalSign MSSL (GCC API)** source gets certificates of a GlobalSign **Managed SSL** account in the GlobalSign Certificate Center (GCC) through its SOAP API. MSSL validates **domains**, not certificates: the names must be in a domain approved in the account's **MSSL profile** - acme finds it there (`GetDomains`), or, with the DNS method, adds and verifies a domain itself (`AddDomainToProfile`, the TXT record put in place by the certificate's validation, `VerifyMsslDomain`). The CSR is then **reissued inside an order bought already** (`ReIssue`, free) or, only when *Allow new orders (paid)* is on, ordered (`PVOrder` - a purchase). acme reads the order until it is issued; revocation is `RevokeMSSLOrder`; *Import from a source* lists the account's orders. **The private key never leaves acme.** No IP addresses. For GlobalSign Atlas use the `globalsign_atlas` source.

## What you need

- A GCC account with **MSSL** and API access enabled by GlobalSign, and the **API user** and password.
- An **MSSL profile** with the organization vetted and the domains approved (or a DNS validation in acme that can put TXT records in the domain's zone).
- An order to reuse (or money / credit for new orders, if you allow them).
- HTTPS access **from acme** to `system.globalsign.com:443` (test: `test-gcc.globalsign.com`), directly or through Settings → Proxy.

## Set up GCC

1. Ask GlobalSign (your account manager or support) to **enable API access** for the MSSL account. They set up an **API user** - a user name for the API, separate from your portal sign-in - and may restrict it to acme's public IP address. A test account on `test-gcc.globalsign.com` is available on request.
2. In GCC, **MSSL → Manage Domains & Profiles**: note the **MSSL profile ID** (e.g. `01_SSL_1234`), and check that the domains of your certificates are **approved** (an approved domain covers its names for 199 days, then is re-vetted).
3. For domains not yet approved, either approve them in GCC (add domain → DNS / e-mail / HTTP verification), or let acme add them by DNS: give the certificates a DNS-01 validation that can write the domain's zone.
4. Note an existing **order number** whose certificate acme may reissue (e.g. `CE20261103123456`), or decide whether acme may buy new orders.

## Fill in acme

Sources → **Add** → **GlobalSign MSSL (GCC API)**.

| acme field | What to put there |
|---|---|
| API user / Password | from step 1 |
| Environment | *Production* or *Test* |
| MSSL profile | *Load the list* (GetMSSLProfiles), or type the ID |
| Domain validation (DCV) | *approved in the profile already*, or *DNS TXT record* (acme adds and verifies the domain) |
| Domain to add | with DNS: e.g. `example.com`; empty: each name without `*.` and `www.` |
| Order to reuse | an order bought already - reissued with acme's request; empty: the one acme made last |
| Allow new orders (paid) | **off** unless acme may buy - otherwise it stops with words where a purchase would be needed |
| Product of a new order / Validity of a new order | e.g. `PV_SHA2`, `6 months` - only for new orders |
| Contact: first name / last name / phone / e-mail | the order's contact (required by the API) |
| Orders listed (days back), Wait for the certificate, Wait for the DCV record, Ask again every (advanced) | `400`, `300`, `300`, `20` |

## Check it

- Sources → the source → **Test** (Try it): signs in and reads the profiles - orders nothing.
- In GCC: **MSSL → Order history** shows the reissued order and its status.

## Common problems

| Problem | Fix |
|---|---|
| `-1` with an authentication error | wrong API user/password, API access not enabled, or acme's IP not allowed |
| The name's domain is not approved | approve it in the profile, or switch DCV to *DNS TXT record* with a DNS validation |
| *a purchase would be needed* | set *Order to reuse*, or switch *Allow new orders (paid)* on |
| Domain verification fails | the TXT record was not visible in public DNS in time - raise the DCV wait |
| IP address refused | MSSL does not issue for IP addresses here |
| Order stays at status 2 (phishing check) | GlobalSign reviews it; acme asks again at the next try |
