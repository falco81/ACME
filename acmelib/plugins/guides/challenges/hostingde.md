# hosting.de / http.net - setup for acme

acme proves names by DNS-01 at hosting.de (and http.net, the same platform): through the hosting.de JSON DNS API it adds a TXT record `_acme-challenge.NAME` with `zoneUpdate` (`recordsToAdd`) and removes exactly its value afterwards (`recordsToDelete`). Other values at the name stay.

## What you need

- The zone hosted in the hosting.de (or http.net) DNS.
- Outbound HTTPS from acme to `secure.hosting.de` (or `partner.http.net`), port 443.

## Set up hosting.de

1. Sign in to the hosting.de control panel → **Profile → API keys → New API key**.
2. Name it `acme` and give it only the DNS rights: **list zones**, **list records** and **edit zones** (the exact labels are in the DNS section of the rights list).
3. If offered, restrict the key to acme's public address.
4. Copy the key.

For **http.net**, do the same in the http.net partner panel.

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | The key |
| Zone | e.g. `example.de`; empty = the longest zone the key sees that the name is in |
| TTL (s) | (advanced) Default `120` |
| API address | (advanced) Default `https://secure.hosting.de/api/dns/v1/json`; http.net: `https://partner.http.net/api/dns/v1/json` |

## Check it

- **Test** in acme lists the zones the key sees - or, with *Zone* set, reads only that zone's configuration. It changes nothing.
- With curl:

  ```sh
  curl -s -X POST https://secure.hosting.de/api/dns/v1/json/zoneConfigsFind \
    -H 'Content-Type: application/json' \
    -d "{\"authToken\":\"$KEY\",\"filter\":{\"field\":\"zoneName\",\"value\":\"example.de\"}}"
  ```

## Common problems

| Problem | Fix |
|---|---|
| `status: error` with an authentication code | Wrong key, or acme's address is not allowed for it. |
| A rights error on `zoneUpdate` | Give the key *edit zones*. |
| Test cannot list all zones | Set *Zone* - Test then asks only for that zone. |
| An "already exists" message | A value from an earlier run is still there; acme treats it as done. |
