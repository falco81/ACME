# NS1 (IBM NS1 Connect) - setup for acme

acme proves names by DNS-01 in a zone at NS1 / IBM NS1 Connect, through API v1 (`https://api.nsone.net/v1`, header `X-NSONE-Key`). It lists the zones, reads the TXT record at `_acme-challenge.NAME`, adds its answer and writes the record back (`PUT` to create, `POST` to change), and on cleanup takes only its answer away again (`DELETE` when none is left). Other answers are written back exactly as read.

NS1 has no call that removes one answer, so a change made to the **same** TXT record elsewhere in the same second can be lost.

## What you need

- The zone at NS1 (managed DNS), with the registrar pointing at NS1's name servers.
- HTTPS (TCP 443) from acme to `api.nsone.net` (or your private NS1 DDI deployment's address).

## Set up NS1

1. Sign in to the NS1 portal (`my.nsone.net` / IBM NS1 Connect).
2. **Account settings → Users & teams → API keys → Add key**, named `acme`.
3. Permissions - grant only:
   - **DNS → View zones**
   - **DNS → Manage zones**
   - everything else (Data, Monitoring, Account, Security…) off.
4. Under the key's **zone restrictions** (allow list) select only the zones acme may change.
5. Optionally restrict the key to acme's IP address (**IP whitelist**).
6. Save and copy the key.

Optional check:

```sh
curl -H 'X-NSONE-Key: KEY' https://api.nsone.net/v1/zones
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | the key |
| Zone | empty (the longest zone of the account the name is in), or the zone |
| TTL (s) | 60 (advanced) |
| API address | `https://api.nsone.net/v1`; your own for a private NS1 (DDI) deployment (advanced) |

## Check it

- In acme press **Test**: it lists the zones the key sees; nothing is changed.
- After an order: portal → **Zones →** the zone: the `_acme-challenge…` TXT record appears with acme's answer and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| `401` "Unauthorized" | Key wrong, deleted, or used from an address not on its IP whitelist. |
| `403` on PUT/POST | The key lacks **Manage zones**, or the zone is not in its allow list. |
| Zone missing from the list | The key's zone restrictions leave it out, or it is in another account. |
