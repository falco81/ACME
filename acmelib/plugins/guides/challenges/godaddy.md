# GoDaddy - setup for acme

acme proves names by DNS-01 at GoDaddy: through the GoDaddy **Domains API v3** it adds a TXT record `_acme-challenge.NAME` and deletes only its own record afterwards (by its `recordId`). It signs in with a **personal access token**. The older Domains API v1 with an API key and secret (`sso-key`) stays selectable for settings made with it; GoDaddy has deprecated it for domains.

## What you need

- The domain at GoDaddy using GoDaddy's DNS.
- **An eligible account**: GoDaddy answers its domain management API only for accounts that hold at least one domain or are on a plan that grants API access; others get `403` with a `code` saying why.
- Outbound HTTPS from acme to `api.godaddy.com` (port 443) - or `api.ote-godaddy.com` for GoDaddy's test environment (OTE).
- TTLs of **600 s or more**.

## Set up GoDaddy

1. Sign in at `developer.godaddy.com` with the account that owns the domain.
2. **Personal Access Token → Create** (in the developer portal).
3. Scopes: only **`domains.domain:read`** and **`domains.dns:update`**.
4. Set an **expiry** you will remember, and copy the token (shown only once).
5. Only for the older v1: **API Keys → Create New API Key** (Production), and copy the key and secret.

## Fill in acme

| acme field | What to put there |
|---|---|
| API | `Domains API v3 with a personal access token` (or v1 for an older key) |
| Personal access token | The token (v3) |
| API key / API secret | The older key and secret (v1 only) |
| Domain | e.g. `example.com`; empty = the longest domain of the account the name is in |
| TTL (s) | (advanced) Default `600`; 600 or more |
| Endpoint | (advanced) `api.godaddy.com`, or `api.ote-godaddy.com` (the test environment) |

## Check it

- **Test** in acme lists the account's active domains. It changes nothing.
- With curl (v3):

  ```sh
  curl -s -H "Authorization: Bearer $PAT" \
    'https://api.godaddy.com/v3/domains/zones/example.com/dns-records?type=TXT&pageSize=10'
  ```

## Common problems

| Problem | Fix |
|---|---|
| `403` with a code such as `ACCESS_DENIED` | The account is not eligible for the API, or the token lacks a scope - read the code in the job. |
| `401` | Wrong or expired token; or an `sso-key` used with v3 (it works only with v1). |
| TTL refused | Set *TTL (s)* to 600 or more. |
| OTE keys against production | Set *Endpoint* to match the key. |
