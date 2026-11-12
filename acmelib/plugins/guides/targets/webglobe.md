# Webglobe hosting - setup for acme

acme stores the certificate as the **own SSL certificate** of a domain hosted at Webglobe,
through the Webglobe API (`api.webglobe.com`). It signs in (`POST /auth/login` with the
login and an API key, or the password), finds the domain by name (`GET /domains`), lets
Webglobe check the certificate, key and chain first (`POST /{domainId}/ssl/validate`), then
stores them (`POST /{domainId}/ssl/own-certificate`). Optionally it turns the http → https
redirect on or off (`POST /{domainId}/ssl/httpsRedirect`). acme deletes nothing: older own
certificates can be removed in the Webglobe administration.

**Webglobe accepts customers' own certificates only with its paid support.** Without it the
API refuses with code 3 ("Access to requested module is denied") and acme says so.

The sign-in is the same as for the Webglobe DNS validation.

## What you need

- A Webglobe account with the domain's **web hosting** and the paid support that allows own
  certificates.
- Outbound HTTPS from acme to `api.webglobe.com` (**TCP 443**).
- acme's **public IP address** (or network) - Webglobe API keys work only from allowed IPs.

## Set up Webglobe

1. Recommended: create a sub-account that sees only the domains acme needs: Webglobe
   administration → **My account → Users** → add a user and give it access to the domain.
2. Sign in as that user and create an API key: **My account → API keys** → new key → allow
   acme's public IP address (or network). Webglobe refuses a key from any other address,
   and a key with no address. **The key is shown only once** - copy it.
3. If you cannot use an API key, the password works only for an account **without
   two-factor sign-in**.
4. Note the domain exactly as the administration lists it (or its numeric ID).

## Fill in acme

| acme field | What to put there |
|---|---|
| Login | The login (e-mail) of the (sub-)account, e.g. `you@example.cz` |
| Sign in with | *an API key* (recommended; works with two-factor) or *the password* |
| API key | The key from step 2 |
| Password | Only for password sign-in |
| API (advanced) | `api.webglobe.com` (production) |
| API address (advanced) | Empty |
| Domain | The hosted domain, e.g. `example.cz` (or its ID) |
| Let Webglobe check it first (deploy) | On (default) |
| Redirect http to https (deploy) | *leave as it is*, *on* or *off* |
| Check what is served | e.g. `www.example.cz:443` |

## Check it

- Press **Try** on the target: acme signs in, finds the domain and reads its certificates
  (changes nothing): `Webglobe: signed in; the domain example.cz is ID 12345, N certificate(s) there`.
- In the Webglobe administration the domain's SSL section shows the new own certificate.
- From any machine:

  ```sh
  openssl s_client -connect www.example.cz:443 -servername www.example.cz </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| `Webglobe refused ...: ... paid support (code 3)` | Own certificates need Webglobe's paid support - order it or use Webglobe's own certificate. |
| Sign-in refused with an API key | acme's public IP is not allowed on the key, or the login does not match the key. |
| Sign-in refused with a password | The account has two-factor sign-in - use an API key. |
| `the domain ... is not in this Webglobe account` | Wrong spelling, or the sub-account cannot see it. |
| Webglobe's check fails | Key and certificate do not match, or the chain is incomplete - see the job's detail. |
