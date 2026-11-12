# DNSimple - setup for acme

acme proves names by DNS-01 at DNSimple: through the DNSimple API v2 it adds a TXT record `_acme-challenge.NAME` to the zone and deletes only its own record afterwards. It signs in with an API access token - best an **account token**, which knows its account.

## What you need

- The zone in a DNSimple account (hosted DNS active for the domain).
- Outbound HTTPS from acme to `api.dnsimple.com` (port 443) - or `api.sandbox.dnsimple.com` for the sandbox.

## Set up DNSimple

1. Sign in at `dnsimple.com` and switch to the account that holds the zone.
2. **Account → Access tokens → New access token** (an *account* access token, not a user token).
3. Name it e.g. `acme` and copy the token (shown only once).
4. DNSimple account tokens are not scoped to single zones: to limit what the token can reach, keep the zones acme manages in a separate DNSimple account.
5. A **user** token (User settings → Access tokens) sees all accounts of the user - then also note the **Account ID** (the number in the account's address, `dnsimple.com/a/<ID>/…`).

## Fill in acme

| acme field | What to put there |
|---|---|
| API access token | The token |
| Account ID | (advanced) Empty for an account token; the account number for a user token |
| Zone | e.g. `example.com`; empty = the longest zone of the account the name is in |
| TTL (s) | (advanced) Default `60` |
| Endpoint | (advanced) `api.dnsimple.com`, or the sandbox |

## Check it

- **Test** in acme lists the zones of the account. It changes nothing.
- With curl:

  ```sh
  curl -s -H "Authorization: Bearer $TOKEN" https://api.dnsimple.com/v2/whoami
  dig +short TXT _acme-challenge.example.com @ns1.dnsimple.com
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401 Authentication failed` | Wrong or revoked token; a sandbox token used with production (or the other way round). |
| The account is unknown | A user token: set *Account ID*. |
| `402` / `403` | The account's plan does not include API access or the zone's DNS is not active. |
| The zone is not found | It is in another account; set *Zone* exactly. |
