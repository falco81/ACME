# ACME CA (Let's Encrypt and others) - setup for acme

The **ACME (Let's Encrypt and others)** source orders certificates from any CA that speaks ACME (RFC 8555): Let's Encrypt (the default), ZeroSSL, Google Trust Services, Buypass, SSL.com, DigiCert, Actalis, Certum, Sectigo, and by its directory URL HARICA, SwissSign, step-ca or your own ACME server. acme makes (or reuses) an **account** at the CA, sends `newOrder` with all names, proves each name by the certificate's validation (DNS-01 or HTTP-01), finalizes with its own CSR - **the private key never leaves acme** - and renews inside the CA's ARI window. On the CA side you only need an account binding (EAB) where the CA asks for one, and CAA records that allow the CA.

## What you need

- HTTPS access **from acme** to the CA's ACME server (e.g. `acme-v02.api.letsencrypt.org:443`), directly or through Settings → Proxy.
- A validation (Validations) for the names: DNS-01 (a DNS provider's API, RFC 2136...) or HTTP-01 (port 80 of each name reachable from the internet).
- **EAB credentials** (key id + HMAC key) for CAs that require External Account Binding: ZeroSSL, Google, SSL.com, DigiCert, Actalis, Certum, Sectigo, HARICA - not for Let's Encrypt or Buypass.
- DNS `CAA` records (if the domain has any) that allow the CA.

## Set up the CA account

1. **Let's Encrypt / Buypass**: nothing to set up - acme makes the account itself. Test first on *Let's Encrypt staging*.
2. **ZeroSSL**: acme can fetch the EAB itself from the first *Contact e-mail*; or take it from the dashboard: **Developer → EAB Credentials → Generate**.
3. **Google Trust Services**: in a Google Cloud project enable the Public CA API, then

   ```sh
   gcloud publicca external-account-keys create --project=<project>
   ```

   It prints `keyId` and `b64MacKey`. A key is used once, for one account.
4. **SSL.com**: the account's API credentials page (ACME credentials). **DigiCert CertCentral**: **Automation → ACME** → add an ACME directory URL (product, organization, validity) → copy the key id and HMAC key. **Sectigo**: from Sectigo (Certificate Manager: **Enrollment → ACME**). **Actalis**: customer area → Manage with ACME → ACME Credentials. **Certum**: the kid and HMAC in the details of the ACME product order. **HARICA**: CertManager (ACME) gives the directory URL and the EAB together.
5. **step-ca** (your own): an ACME provisioner, `step ca provisioner add acme --type ACME`; the directory is `https://ca.example.local/acme/acme/directory`; give acme step-ca's root as *CA certificate of the ACME server*.
6. Allow the CA in DNS, e.g. `example.com. CAA 0 issue "letsencrypt.org"` (`"sectigo.com"`, `"pki.goog"`, `"digicert.com"`...).

## Fill in acme

Sources → **Add** → **ACME (Let's Encrypt and others)**.

| acme field | What to put there |
|---|---|
| CA | a preset (Let's Encrypt, ZeroSSL, Google, Buypass, SSL.com, DigiCert, Actalis, Certum, Sectigo DV/OV) or *Another ACME server* |
| Directory URL | with *Another ACME server*: e.g. `https://acme-v02.harica.gr/acme/<account id>/directory` |
| Contact e-mails | e.g. `pki@example.com` - expiry and policy mails; ZeroSSL needs one to make the EAB |
| EAB key id / EAB HMAC key | from the CA (base64url, exactly as shown); empty for Let's Encrypt |
| Account key (advanced) | ECDSA P-256 (default); **changing it makes a new account** |
| ACME profile (advanced) | Let's Encrypt: `classic`, `tlsserver`, `shortlived` (6-day, needed for IP addresses) |
| Preferred chain (advanced) | e.g. `ISRG Root X1` |
| CA certificate of the ACME server / Check the server's TLS certificate (advanced) | for your own ACME server with a private TLS certificate |
| Wait for the proof to be visible / for the CA to check / for the certificate (s), Ask again every (s) (advanced) | `300` / `180` / `300` / `5`; raise the first for slow DNS |

## Check it

- Sources → the source → **Test** (Try it): reads the directory, finds or makes the account; says the profiles offered and whether the CA has ARI.
- Order a certificate on the staging CA first. By hand: `curl -s https://acme-v02.api.letsencrypt.org/directory`.

## Common problems

| Problem | Fix |
|---|---|
| *this CA needs External Account Binding* | set the EAB key id and HMAC key |
| EAB refused / `unauthorized` | the HMAC was copied wrong, or the key id was already used for another account |
| *a CAA record in DNS does not allow this CA* | add `0 issue "<ca domain>"` to the CAA record |
| *the proof ... is not visible after 300 s* | DNS-01: the TXT record is not in the zone the world sees; raise the wait |
| *the CA could not reach the server for the challenge* | HTTP-01: open port 80 from the internet to each name |
| *the CA's rate limit is reached* | wait; test on staging (Let's Encrypt: 5 certificates a week for the same names) |
| *the CA will not issue for this kind of name* | IP addresses at Let's Encrypt need the `shortlived` profile |
