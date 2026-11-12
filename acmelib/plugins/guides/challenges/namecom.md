# Name.com - setup for acme

acme proves names by DNS-01 in a domain at Name.com, through the Name.com **API v4** (`https://api.name.com/v4`) with basic authentication (user name + API token). It lists the domains, adds one TXT record per value (`POST /v4/domains/{domain}/records`) and deletes that record by its id afterwards. Other values at the same name stay.

Name.com has announced a newer "Core API"; while v4 answers this module uses it. When v4 is retired, the address goes under *API address* (and the calls may then differ).

## What you need

- A domain at Name.com using Name.com's name servers.
- HTTPS (TCP 443) from acme to `api.name.com`.

## Set up Name.com

1. Sign in at `name.com`.
2. **Account → Settings → Security → API access** (API Token Management).
3. Turn API access on and **create a production token** (named e.g. `acme`). A *test* token only works against `api.dev.name.com` with a user name ending in `-test`.
4. Copy the token - it is shown once. The user name is your account's user name.
5. If two-step verification is on for the account, Name.com may require API access to be confirmed once - follow what the page asks.

Name.com tokens are not limited to DNS: keep the token only in acme.

Optional check:

```sh
curl -u 'USERNAME:TOKEN' https://api.name.com/v4/domains
```

## Fill in acme

| acme field | What to put there |
|---|---|
| User name | the Name.com account user name |
| API token | the production token |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 300 (Name.com takes nothing lower; advanced) |
| API address | `https://api.name.com/v4` (advanced; `https://api.dev.name.com/v4` for the test API) |

## Check it

- In acme press **Test**: it lists the domains of the account; nothing is changed.
- After an order: **My Domains →** the domain → **Manage DNS Records**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| `401 Unauthorized` | Wrong user name or token, or a test token against production. |
| `403` "Permission Denied" | API access is off for the account, or not yet confirmed. |
| Domain not found | The domain is in another account or uses other name servers. |
| TTL refused | Keep *TTL (s)* at 300 or more. |
