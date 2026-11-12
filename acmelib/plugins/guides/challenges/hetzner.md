# Hetzner DNS - setup for acme

acme proves names by DNS-01 in a DNS zone at Hetzner, through the **Hetzner Console / Cloud API** (`api.hetzner.cloud`), where Hetzner DNS has moved: it adds its value to the TXT RRset `_acme-challenge.NAME` (`add_records`) and on cleanup removes exactly its value (`remove_records`), waiting for each action to finish. **The old DNS Console API (`dns.hetzner.com`) was switched off on 2026-05-27; its tokens do not work.**

## What you need

- The zone in a project of the Hetzner Console (zones from the old DNS Console have to be migrated there).
- Outbound HTTPS from acme to `api.hetzner.cloud` (port 443).

## Set up Hetzner

1. Hetzner Console → the **project that holds the zone** → **Security → API tokens → Generate API token**.
2. Description `acme`, permission **Read & Write** (Hetzner tokens are per project; read-only cannot change records).
3. Copy the token (shown only once).
4. A token can do everything in its project: keep the DNS zones in a project of their own if the project also holds servers.

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | The project's token |
| Zone | e.g. `example.com`; empty = found by the name |
| TTL (s) | (advanced) Default `60`; used only for a new RRset (an existing one keeps its own) |

## Check it

- **Test** in acme lists the zones the token sees. It changes nothing.
- With the `hcloud` CLI or curl:

  ```sh
  curl -s -H "Authorization: Bearer $HCLOUD_TOKEN" 'https://api.hetzner.cloud/v1/zones?name=example.com'
  dig +short TXT _acme-challenge.example.com @hydrogen.ns.hetzner.com
  ```

  (use one of the zone's name servers from `dig NS example.com`).

## Common problems

| Problem | Fix |
|---|---|
| A refusal saying the old DNS Console is gone | Use a Hetzner Console project token, not a `dns.hetzner.com` token. |
| `401 unauthorized` | Wrong token, or a token from another project. |
| `403 forbidden` | A read-only token - create one with Read & Write. |
| `423 locked` | Another action is running on the zone; acme tries again. |
| No zone found | The zone is in another project. |
