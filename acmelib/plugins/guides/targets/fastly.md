# Fastly - setup for acme

acme puts your own certificate (a customer-provided certificate, not one Fastly issues) on Fastly TLS through the Fastly API (`https://api.fastly.com`). On every deployment it uploads the new private key under a dated name, then **replaces in place** the certificate it put there before, so its activations (which domains it serves, on which TLS configuration) stay. The very first time there is nothing to replace: acme adds a new certificate and **you activate it once** in Fastly. Older acme keys that no certificate uses any more are deleted.

## What you need

- A Fastly account with TLS management for your own certificates (Fastly TLS with customer-provided certificates).
- A Fastly user who may manage TLS (a role that can manage the account's TLS, e.g. superuser or engineer - check your account's roles).
- HTTPS access from acme to `api.fastly.com` port 443 (directly or through the proxy of acme's Settings → Proxy).

## Set up Fastly

1. Sign in to the Fastly control panel as the user acme will act as (ideally a dedicated user).
2. Open **Account → API tokens** (Personal API tokens) and create a new token:
   - **Name**: e.g. `acme`
   - **Scope**: `global` - TLS management needs it (the read-only and purge scopes are not enough).
   - **Service access**: all services (TLS certificates are account-wide objects).
   - Expiration: as your policy allows; remember to renew the token before it expires.
3. Copy the token - it is shown only once.
4. The first time: run a deployment in acme (see below), then in Fastly go to **Secure → TLS management**, find the certificate acme added (named `acme-…`) and **activate** it for its domains on the TLS configuration you want. Every renewal after that replaces the same certificate and keeps the activations.

You can check the token from a shell:

```sh
curl -s -H "Fastly-Key: $FASTLY_TOKEN" \
     -H "Accept: application/vnd.api+json" \
     "https://api.fastly.com/tls/certificates?page%5Bsize%5D=100"
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | the token from step 2 |
| Through the proxy | on when acme reaches the internet only through the proxy of Settings → Proxy (default on) |
| Timeout (s) | API timeout, 30 is fine |
| Fastly certificate ID (deployment, advanced) | empty: acme finds its own certificate by name, or adds a new one; or the ID of an existing Fastly TLS certificate to replace (e.g. one you uploaded by hand before) |
| Previous versions to keep | how many older acme keys stay at Fastly before they are deleted |
| Check what is served | `host:443` of a domain on Fastly, one a line - acme checks the new certificate is served |
| SNI name for the check | empty: the certificate's first name |

## Check it

- In acme, press **Test** on the target: it signs in and lists the TLS certificates (`signed in to Fastly; N TLS certificates`).
- After a deployment, in Fastly **Secure → TLS management** the certificate shows the new expiry date, and:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate
```

## Common problems

| Problem | Fix |
|---|---|
| 401 / 403 when signing in | the token is wrong, expired or lacks the `global` scope; or the user may not manage TLS |
| `added the certificate … - activate it once` | expected on the first run: activate it in Secure → TLS management |
| `there is no TLS certificate <id> at Fastly` | the *Fastly certificate ID* is wrong; leave it empty or copy the ID from the TLS management page |
| The key upload is refused | Fastly rejects key types it does not support; check the key type of the certificate in acme |
| Old certificate still served | the new certificate was added but never activated, or the domain is activated on another certificate |
| `the older key … stays` | the key is still used by a certificate; it is deleted on a later run |
