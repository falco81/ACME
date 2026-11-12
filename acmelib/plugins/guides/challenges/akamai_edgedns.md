# Akamai Edge DNS - setup for acme

acme proves names by DNS-01 at Akamai Edge DNS (formerly Fast DNS): through the Edge DNS **Zone Management API v2** (`/config-dns/v2`), signed with EdgeGrid, it reads the TXT record set `_acme-challenge.NAME`, adds its value and writes the set back; cleanup takes only its value away. **Primary zones only** (secondary and alias zones cannot be written).

## What you need

- An Akamai contract with Edge DNS and the zone as a **PRIMARY** zone.
- Access to Akamai Control Center to create an API client.
- Outbound HTTPS from acme to your API host `akab-xxxxxxxx.luna.akamaiapis.net` (port 443).

## Set up Akamai

1. Control Center → **Identity and access → API clients → Create API client** (a client for acme, not your own user's client).
2. Under the API services, give it **DNS—Zone Record Management** with access **READ-WRITE**. Nothing else is needed.
3. If your contract has several groups, limit the client to the group that holds the zones acme may change.
4. Create the credential and download it (or copy the `.edgerc` section). It holds four values:

   ```text
   [default]
   host = akab-xxxxxxxx.luna.akamaiapis.net
   client_token = akab-...
   client_secret = ...
   access_token = akab-...
   ```

5. If you use IP allow-lists on API clients, add acme's public address.

## Fill in acme

| acme field | What to put there |
|---|---|
| API host | `host` from `.edgerc`, e.g. `akab-xxxxxxxx.luna.akamaiapis.net` |
| Client token | `client_token` |
| Client secret | `client_secret` |
| Access token | `access_token` |
| Zone | The zone, e.g. `example.com`; empty = the longest primary zone the client sees that the name is in |
| TTL (s) | (advanced) Default `60` (30 at least) |

## Check it

- **Test** in acme signs a request and lists the primary zones the client may see. It changes nothing.
- After a run, ask one of the zone's own name servers (from `dig NS example.com`):

  ```sh
  dig +short NS example.com
  dig +short TXT _acme-challenge.example.com @<one of those name servers>
  ```

- In Control Center, the zone's record list (Edge DNS → the zone) shows the `_acme-challenge` TXT record while a run is in progress.

## Common problems

| Problem | Fix |
|---|---|
| `401` / signature errors | A value from `.edgerc` was copied with spaces or swapped; or the acme machine's clock is off (EdgeGrid signs the time) - check NTP. |
| `403` | The client lacks *DNS—Zone Record Management* READ-WRITE, or is limited to another group. |
| The zone is not listed | It is a secondary or alias zone - only primary zones can be written. |
| `no API host is set` | Fill in *API host* (without `https://`). |
