# Gandi LiveDNS - setup for acme

acme proves names by DNS-01 at Gandi: through the LiveDNS API v5 it adds its value to the TXT record set `_acme-challenge.NAME` (`PATCH … add_rrset_values`, or `POST` for a new set) and removes only its value afterwards (`remove_rrset_values`). It signs in with a **personal access token** (an older API key still works).

## What you need

- A domain at Gandi that uses **LiveDNS** (Gandi's name servers).
- Outbound HTTPS from acme to `api.gandi.net` (port 443).
- TTLs of **300 s or more** - Gandi takes nothing shorter.

## Set up Gandi

1. Sign in at `admin.gandi.net` → **Organizations → (your organization) → Sharing → Personal Access Tokens → Create a token** (or *User settings → Authentication options* for a personal one).
2. Choose the organization, a **name** (`acme`) and an **expiry** (remember to renew it before it expires).
3. **Resources**: *Restrict to selected products* → only the domains acme may change.
4. **Permissions**: only **Manage domain name technical configurations**.
5. Create and copy the token (shown only once).

## Fill in acme

| acme field | What to put there |
|---|---|
| Signs in with | `a personal access token` (or `an API key (older)`) |
| Token | The token |
| Domain | e.g. `example.com`; empty = the longest domain of the account the name is in |
| TTL (s) | (advanced) Default `300`; 300 or more |
| API address | (advanced) Default `https://api.gandi.net/v5/livedns` |

## Check it

- **Test** in acme lists the LiveDNS domains the token sees. It changes nothing.
- With curl:

  ```sh
  curl -s -H "Authorization: Bearer $TOKEN" https://api.gandi.net/v5/livedns/domains
  curl -s -H "Authorization: Bearer $TOKEN" \
    https://api.gandi.net/v5/livedns/domains/example.com/records/_acme-challenge/TXT
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` | Wrong or expired token; or *Signs in with* does not match the kind of credential. |
| `403` | The token lacks *Manage domain name technical configurations* or the domain is not among its resources. |
| The domain is not listed | It does not use LiveDNS (external name servers) - switch it to LiveDNS or use another validation. |
| TTL refused | Set *TTL (s)* to 300 or more. |
