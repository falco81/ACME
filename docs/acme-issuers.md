# Certificates from ACME CAs: Let's Encrypt and the others

The `acme` issuer (Sources → Add → *ACME (Let's Encrypt and others)*) orders
certificates from any CA that speaks ACME (RFC 8555). Let's Encrypt is the
default; ZeroSSL, Google Trust Services, Buypass, SSL.com and your own ACME
server (step-ca, an internal CA, pebble) work the same way.

This is about the certificates acme *manages*. The appliance's own web
certificate has its own page (see `acme.md`).

## What happens on an order

1. The account is found in the module's state (`acme-account:<directory>:<hash>`,
   with the key sealed), or made at the CA: a new key of the chosen kind,
   `newAccount` with the contacts, terms agreed, and EAB where the CA wants it.
2. `newOrder` with every name (DNS names, IP addresses as `ip` identifiers), the
   ACME profile where the CA offers it, and for a renewal `replaces` (ARI).
3. For each authorization the CA hands back, the challenge chosen for that name
   (DNS-01 or HTTP-01, from the certificate's challenge or its per-name map) puts
   the proof in place: the TXT record `_acme-challenge.<name>` =
   base64url(SHA-256(key authorization)), or the file
   `/.well-known/acme-challenge/<token>`. All proofs are put in place first (a
   wildcard and its bare name have two TXT values at one name), then acme waits
   until each is visible, asks the CA to check, and waits for the verdict.
   The proofs are always taken away again, whatever the outcome.
4. `finalize` with the CSR acme made, then the certificate and its chain are
   downloaded - the alternate chain ending at your *preferred chain* where the
   CA offers one.

Each step is a line in the job. A stale nonce (`badNonce`) is asked again; a
short `rateLimited` wait (≤ 60 s) is waited out, a longer one is reported with
the time to try again.

## The settings

| Field | |
|---|---|
| CA | Let's Encrypt, its staging, ZeroSSL, Google (and staging), Buypass, SSL.com RSA / ECC, or another ACME server by its directory URL |
| Contact e-mails | told to the CA with the account; changing them updates the account |
| EAB key id / HMAC key | External Account Binding - see below |
| Account key | ECDSA P-256 (default), P-384, RSA 2048/3072/4096. **Changing it makes a new account** |
| ACME profile | Let's Encrypt: `classic`, `tlsserver`, `shortlived` (6-day certificates; needed for IP addresses). A certificate's own profile (`acme_profile`) wins. A profile the CA does not offer is said in the job and its default used |
| Preferred chain | the common name of the root/intermediate the chain should end at (e.g. `ISRG Root X1`) |
| CA certificate / check TLS | for an ACME server with a private TLS certificate |
| Waits | for the proof to be visible (DNS propagation, 300 s), for the CA's check (180 s), for the certificate (300 s) |

## The CAs

| CA | Directory | EAB |
|---|---|---|
| Let's Encrypt | `https://acme-v02.api.letsencrypt.org/directory` | no |
| Let's Encrypt staging | `https://acme-staging-v02.api.letsencrypt.org/directory` | no - use it to test; its certificates are not trusted, its limits much higher |
| ZeroSSL | `https://acme.zerossl.com/v2/DV90` | yes - acme fetches it itself from the first contact e-mail when none is set, or take it from the dashboard (Developer → EAB Credentials) |
| Google Trust Services | `https://dv.acme-v02.api.pki.goog/directory` | yes - `gcloud publicca external-account-keys create` (a key is used once, for one account) |
| Buypass Go SSL | `https://api.buypass.com/acme/directory` | no |
| SSL.com | `https://acme.ssl.com/sslcom-dv-rsa` / `-ecc` | yes - the account's API credentials page |
| Sectigo | choose *Another ACME server*; e.g. `https://acme.sectigo.com/v2/DV` (or OV/EV, or your Sectigo Certificate Manager URL) | yes - from Sectigo |
| step-ca (Smallstep) | `https://ca.example.local/acme/<provisioner>/directory`, with its root as *CA certificate* | only when the provisioner has `requireEAB` |

EAB: the HMAC key is given as base64url, exactly as the CA shows it. An EAB key
id usually makes only one account - the account kept in acme's state is reused
from then on, so the key id is not needed again unless the account is lost.

## Renewals, ARI and `replaces`

`renewal_window` asks the CA's `renewalInfo` (RFC 9773) with the certificate's
ARI id - base64url(Authority Key Identifier) `.` base64url(serial) - and acme's
scheduler renews inside the window it suggests (earlier, where the CA says so
after a revocation), never later than its own *renew days*.

A renewal tells the CA which certificate it replaces. Only the account that
ordered a certificate may say so: after a change of account (another key type,
another CA, the account forgotten by the CA) the order is refused, and acme
orders again without `replaces` - still a valid renewal, just not counted as one
(see `acme-ari-replaces-check.md`).

## The account

* Found by the directory URL, the EAB key id and the account key type; any of
  these changed means another account.
* A CA that no longer knows the account (`accountDoesNotExist`, a deactivated
  account) gets a new one made at once and the request asked again.
* *Try it* (Sources → Test) reads the directory and finds or makes the account;
  it says the profiles and whether the CA has ARI.

## Revocation

`revoke` signs with the account; where another account ordered the certificate
and acme has its key, with the certificate's own key. Reasons: unspecified,
keyCompromise, affiliationChanged, superseded, cessationOfOperation.

## When it fails

| The job says | Do |
|---|---|
| *a CAA record in DNS does not allow this CA* | add `0 issue "letsencrypt.org"` (or the CA's name) to the CAA record of the domain |
| *the proof … is not visible after 300 s* | DNS-01: is the record in the zone the world sees? (a CNAME to another zone, a delegated zone, a slow secondary). Raise the wait |
| *the CA could not reach the server for the challenge* | HTTP-01: port 80 from the internet to the name's address |
| *the CA saw a wrong answer* | an old TXT record left, another server on port 80 |
| *the CA's rate limit is reached - try again after …* | wait; test on staging. Let's Encrypt: 5 certificates a week for the same names, 50 a week per registered domain, 300 new orders in 3 hours |
| *this CA needs External Account Binding* | set the EAB key id and HMAC key |
| *the CA will not issue for this kind of name* | IP addresses at Let's Encrypt need the `shortlived` profile |
| *the CA does not take this kind of key* | another key type for the certificate |
