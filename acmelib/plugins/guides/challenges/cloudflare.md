# Cloudflare - setup for acme

acme proves names by DNS-01 at Cloudflare: through the Cloudflare API v4 it adds a TXT record `_acme-challenge.NAME` (with the comment `acme DNS-01`) to the zone and deletes only its own record afterwards. For a commercial CA's validation it can also write a CNAME (never proxied). It signs in with a scoped **API token** - not the Global API Key.

## What you need

- The zone active at Cloudflare (on any plan).
- Access to the Cloudflare dashboard to create an API token.
- Outbound HTTPS from acme to `api.cloudflare.com` (port 443).

## Set up Cloudflare

1. Dashboard → **My Profile → API Tokens → Create Token**.
2. Use the template **Edit zone DNS**, or a custom token with these permissions:
   - **Zone → DNS → Edit**
   - **Zone → Zone → Read** (so acme can find the zone by its name; not needed when you set *Zone ID*)
3. **Zone Resources**: *Include → Specific zone → example.com* (repeat for each zone acme may change). Avoid *All zones*.
4. Optional: **Client IP Address Filtering** - *Is in* acme's public address.
5. Optional: a **TTL** (expiry date) for the token - remember to renew it.
6. **Continue to summary → Create Token** and copy the token (shown only once). Cloudflare shows a `curl` command to verify it.

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | The token |
| Zone ID | (advanced) The zone's ID (Overview page → API, right column); empty = found by the name |
| TTL (s) | (advanced) Default `60`; `1` is Cloudflare's "auto" |
| API address | (advanced) Default `https://api.cloudflare.com/client/v4` |

## Check it

- **Test** in acme lists the zones the token sees (or reads the zone set by *Zone ID*). It changes nothing.
- With curl:

  ```sh
  curl -s -H "Authorization: Bearer $CF_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify
  curl -s -H "Authorization: Bearer $CF_TOKEN" 'https://api.cloudflare.com/client/v4/zones?name=example.com'
  ```

## Common problems

| Problem | Fix |
|---|---|
| `the token works but sees no zone` | Add **Zone:Read** and **DNS:Edit** for the zone under *Zone Resources*. |
| `Authentication error (10000)` | Wrong or expired token; or acme's address is not in the token's IP filter. |
| `Cloudflare has no zone for NAME that this token may see` | The zone is in another account, or not included in the token - or set *Zone ID*. |
| The CA does not see the record | The domain's name servers are not Cloudflare's (a partial/CNAME setup): check `dig NS example.com`. |
