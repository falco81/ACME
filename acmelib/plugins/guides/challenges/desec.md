# deSEC - setup for acme

acme proves names by DNS-01 at deSEC.io (also for `dedyn.io` names): through the deSEC REST API it reads the TXT RRset at `_acme-challenge.NAME`, adds its value and writes the set back (`PATCH .../rrsets/`); cleanup takes only its value away. Because deSEC's name servers are anycast, acme waits a little longer after both have the record. For a commercial CA's validation it can also write a CNAME.

## What you need

- The domain (or `dedyn.io` name) in your deSEC account.
- Outbound HTTPS from acme to `desec.io` (port 443).
- Patience with the TTL: **deSEC takes no TTL under the domain's minimum TTL** (3600 s for most accounts).

## Set up deSEC

1. Sign in at `desec.io` → **Token management → +** (create a token). Copy the token value (shown only once).
2. Restrict the token (recommended):
   - **Allowed subnets**: acme's public address (e.g. `203.0.113.10/32`).
   - Optional **max age / max unused period**.
3. Add **token policies** so the token can only write the challenge records. A default policy (no domain, no subname, no type) with write permission **off**, plus one per domain:

   | Domain | Subname | Type | Write |
   |---|---|---|---|
   | (default) | (any) | (any) | no |
   | `example.com` | `_acme-challenge` | `TXT` | yes |

   Add a row for each `_acme-challenge.SUB` you use (e.g. `_acme-challenge.www`). The token still needs to read the list of domains.

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | The token |
| Domain | e.g. `example.dedyn.io`; empty = the longest domain of the account the name is in |
| TTL (s) | (advanced) Default `3600`; lower values are raised to the domain's minimum |
| Wait after it is seen (seconds) | (advanced) Default `60` - extra time for anycast name servers |
| API address | (advanced) Default `https://desec.io/api/v1` |

## Check it

- **Test** in acme lists the domains (or reads the set domain and its minimum TTL). It changes nothing.
- With curl:

  ```sh
  curl -s -H "Authorization: Token $TOKEN" https://desec.io/api/v1/domains/
  dig +short TXT _acme-challenge.example.dedyn.io @ns1.desec.io
  ```

## Common problems

| Problem | Fix |
|---|---|
| `403` on write | A token policy does not allow `TXT` at that subname - add a row for it. |
| `403` / `401` for everything | Wrong token, or acme's address is not in the token's allowed subnets. |
| `429 Too Many Requests` | deSEC throttles; acme waits it out - just slower. |
| The CA sees nothing | Give it more time: raise *Wait after it is seen (seconds)*. |
