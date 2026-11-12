# DigitalOcean - setup for acme

acme proves names by DNS-01 in a DigitalOcean domain (Networking → Domains): through the DigitalOcean API v2 it adds a TXT record `_acme-challenge.NAME` and deletes only its own record afterwards. It signs in with a personal access token.

## What you need

- The domain added under **Networking → Domains** and delegated to `ns1/ns2/ns3.digitalocean.com`.
- Outbound HTTPS from acme to `api.digitalocean.com` (port 443).

## Set up DigitalOcean

1. Control panel → **API → Tokens → Generate New Token**.
2. Name it e.g. `acme`, choose an **expiration**, and under scopes pick **Custom Scopes** → **domain**: `read`, `create`, `delete` (or **Full Access** / *Write*, which is broader than needed).
3. If you have several teams, create the token in the team that owns the domain.
4. Copy the token (shown only once).

## Fill in acme

| acme field | What to put there |
|---|---|
| Personal access token | The token (`dop_v1_…`) |
| Domain | e.g. `example.com`; empty = found by the name |
| TTL (s) | (advanced) Default `60`; DigitalOcean takes 30 or more |

## Check it

- **Test** in acme lists the domains the token sees. It changes nothing.
- With `doctl` or curl:

  ```sh
  doctl compute domain records list example.com
  curl -s -H "Authorization: Bearer $DO_TOKEN" https://api.digitalocean.com/v2/domains
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401 Unable to authenticate you` | Wrong or expired token. |
| `403` when adding the record | The token lacks `domain:create` / `domain:delete` (a read-only token). |
| The domain is not found | It belongs to another team; or set *Domain* exactly. |
| The CA does not see the record | The domain is not delegated to DigitalOcean's name servers. |
