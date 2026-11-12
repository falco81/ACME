# Domeneshop - setup for acme

acme proves names by DNS-01 at Domeneshop (domene.shop, Norway): through the Domeneshop API v0 it adds a TXT record `_acme-challenge.NAME` to the domain's DNS and deletes only its own record afterwards. It signs in with an API token and secret (HTTP basic authentication).

## What you need

- A domain at Domeneshop that uses Domeneshop's DNS service.
- Outbound HTTPS from acme to `api.domeneshop.no` (port 443).

## Set up Domeneshop

1. Sign in at `domene.shop` → **My page → API access** (`https://domene.shop/admin?view=api`).
2. Create new API credentials. You get a **token** and a **secret** - copy both; the secret is shown only once.
3. Domeneshop's API credentials act for the whole account; they cannot be limited to one domain. Delete them under *API access* if they leak.

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | The token |
| API secret | The secret |
| Domain | e.g. `example.no`; empty = the longest domain of the account the name is in |
| TTL (s) | (advanced) Default `60` (60 at least) |
| API address | (advanced) Default `https://api.domeneshop.no/v0` |

## Check it

- **Test** in acme lists the account's domains. It changes nothing.
- With curl:

  ```sh
  curl -s -u "$TOKEN:$SECRET" https://api.domeneshop.no/v0/domains
  dig +short TXT _acme-challenge.example.no @ns1.hyp.net
  ```

  (use one of the domain's name servers from `dig NS example.no`).

## Common problems

| Problem | Fix |
|---|---|
| `401` | Wrong token or secret, or the credentials were deleted. |
| The domain is not found | It is in another account, or its DNS is not Domeneshop's. |
| The CA does not see the record | Check that the domain uses Domeneshop's name servers; raise *Wait at least (seconds)*. |
