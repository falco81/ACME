# Infomaniak - setup for acme

acme proves names by DNS-01 in a zone hosted at Infomaniak (Switzerland). It uses the Infomaniak API v2 (`https://api.infomaniak.com/2/zones/...`) with a bearer API token: it finds the zone by asking `/2/zones/{name}/exists` name by name, adds one TXT record per value at `_acme-challenge.NAME` and deletes that record by its id afterwards. Other values at the same name stay.

## What you need

- A domain whose DNS zone is at Infomaniak (Infomaniak's name servers).
- HTTPS (TCP 443) from acme to `api.infomaniak.com`.
- An Infomaniak account that may manage the domain.

## Set up Infomaniak

1. Sign in at `manager.infomaniak.com`.
2. Open your profile menu → **Developer** → **API tokens** → **Create a token**.
3. Give it a name such as `acme` and choose the scopes:
   - **`domain:read`** and **`dns:write`** - nothing else is needed.
   - (Older tokens used the scopes `accounts` and `domain` instead.)
4. Choose a validity that suits you (an unlimited token saves you renewing it; a limited one must be replaced in acme before it expires).
5. Copy the token - it is shown only once.

Optional check from a shell:

```sh
curl -H 'Authorization: Bearer TOKEN' https://api.infomaniak.com/2/zones/example.ch/exists
# {"result":"success","data":true}
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | the token from step 5 |
| Zone | the zone, e.g. `example.ch` - recommended, so *Test* can check it; empty: acme asks name by name |
| TTL (s) | 300 (Infomaniak takes nothing lower; advanced) |
| API address | `https://api.infomaniak.com` (advanced, leave as is) |

## Check it

- In acme press **Test**: with *Zone* set it asks Infomaniak whether the token sees that zone. Without a zone it can only say the token is set (the API lists products, not zones).
- After an order, in the Manager: **Domains →** the domain → **DNS zone**: the `_acme-challenge` TXT record appears and is removed again.

```sh
dig +short TXT _acme-challenge.www.example.ch @ns11.infomaniak.ch
```

## Common problems

| Problem | Fix |
|---|---|
| "Infomaniak said no ..." (a rights error) | The token lacks `dns:write` / `domain:read` - make a new one with those scopes. |
| "Infomaniak has no zone for ... that this token may see" | The domain is in another Infomaniak account or organisation, or its DNS is not at Infomaniak. |
| TTL refused | Keep *TTL (s)* at 300 or more. |
| `401` after some months | The token expired - create a new one and paste it. |
