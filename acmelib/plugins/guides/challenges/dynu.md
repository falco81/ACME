# Dynu - setup for acme

acme proves names by DNS-01 at Dynu: through the Dynu API v2 (`api.dynu.com`) it adds a TXT record `_acme-challenge.NAME` to the domain and deletes only its own record afterwards. It signs in with the account's API key.

## What you need

- The domain (or a Dynu dynamic DNS name) in your Dynu account, with DNS served by Dynu.
- Outbound HTTPS from acme to `api.dynu.com` (port 443).

## Set up Dynu

1. Sign in at `dynu.com` → **Control Panel → API Credentials**.
2. Copy the **API key** (generate/reset it there if needed). The key acts for the whole account; Dynu has no key limited to one domain.
3. If you reset the key later, update acme.

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | The API key |
| Domain | e.g. `example.com`; empty = the longest domain of the account the name is in |
| TTL (s) | (advanced) Default `60` |
| API address | (advanced) Default `https://api.dynu.com/v2` |

## Check it

- **Test** in acme lists the account's domains. It changes nothing.
- With curl:

  ```sh
  curl -s -H "API-Key: $KEY" -H 'Accept: application/json' https://api.dynu.com/v2/dns
  dig +short TXT _acme-challenge.example.com @ns1.dynu.com
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` | Wrong or reset API key. |
| The domain is not found | It is not in this Dynu account; set *Domain* exactly. |
| The CA does not see the record | Check that the domain uses Dynu's name servers; raise *Wait at least (seconds)*. |
