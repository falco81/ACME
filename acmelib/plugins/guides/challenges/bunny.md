# bunny.net DNS - setup for acme

acme proves names by DNS-01 in a bunny.net DNS zone: through the bunny.net API (`api.bunny.net`) it adds a TXT record `_acme-challenge.NAME` to the zone and deletes only its own record afterwards. Every value is a record of its own, so parallel orders do not disturb each other.

## What you need

- The zone added under **DNS** in the bunny.net dashboard, with the domain delegated to bunny.net's name servers.
- The account's API key. **bunny.net has no key limited to DNS: this key can do everything in the account** - keep it as secret as your password.
- Outbound HTTPS from acme to `api.bunny.net` (port 443).

## Set up bunny.net

1. Sign in to `dash.bunny.net`.
2. Go to **Account settings → API key** (in newer dashboards: your account menu → **Account settings → API**).
3. Copy the API key. If you ever suspect it leaked, reset it there and update acme.
4. Consider a separate bunny.net account (or a team member account, if your plan offers one) that holds only the DNS zones, so the key cannot reach your CDN and storage.

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | The account's API key |
| Zone | e.g. `example.com`; empty = the longest zone of the account the name is in |
| TTL (s) | (advanced) Default `60` |
| Wait until it is seen by, Wait at least, Resolvers | (advanced) how acme waits for the record - defaults are fine |

## Check it

- **Test** in acme lists the account's DNS zones. It changes nothing.
- With curl:

  ```sh
  curl -s -H "AccessKey: $BUNNY_API_KEY" 'https://api.bunny.net/dnszone?page=1&perPage=10'
  dig +short TXT _acme-challenge.example.com @kiki.bunny.net
  ```

  (use one of the zone's name servers from `dig NS example.com`).

## Common problems

| Problem | Fix |
|---|---|
| `401` | Wrong API key, or it was reset - copy it again. |
| The zone is not found | The zone is not in this bunny.net account; set *Zone* exactly. |
| The CA does not see the record | The domain is not delegated to bunny.net's name servers - check `dig NS example.com`. |
