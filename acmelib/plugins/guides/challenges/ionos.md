# IONOS (Hosting API) - setup for acme

acme proves names by DNS-01 in a zone at IONOS, through the **IONOS Hosting DNS API** (`https://api.hosting.ionos.com/dns/v1`). It lists the zones, adds one TXT record per value at `_acme-challenge.NAME` and deletes that record by its id afterwards; other values stay.

This is the API for domains in IONOS hosting/domain contracts. **IONOS Cloud DNS (DCD) is a different API** and does not work with this module.

## What you need

- A domain in an IONOS contract whose DNS is at IONOS.
- HTTPS (TCP 443) from acme to `api.hosting.ionos.com`.
- Access to the IONOS developer portal with the contract's login.

## Set up IONOS

1. Open `developer.hosting.ionos.com` and sign in with your IONOS account.
2. Go to **Get started → API keys → Create** (or *API-Keys → Erstellen* in German).
3. Give the key a description such as `acme`.
4. Copy both halves shown: the **public prefix** and the **secret**. The secret is shown only once.

IONOS keys are not limited to DNS: keep the key only in acme.

Optional check from a shell (prefix and secret joined by a dot):

```sh
curl -H 'X-API-Key: PREFIX.SECRET' https://api.hosting.ionos.com/dns/v1/zones
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Public prefix | the key's public prefix |
| Secret | the key's secret |
| Zone | empty (the longest zone of the account the name is in), or the zone |
| TTL (s) | 60 by default (advanced) |

## Check it

- In acme press **Test**: it lists the zones of the account; no record is changed.
- After an order, in the IONOS control panel: **Domains & SSL →** the domain → **DNS**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| `401 Unauthorized` | Prefix or secret wrong or swapped - acme sends `prefix.secret`. |
| Zone not found | The domain uses other name servers, or is an IONOS Cloud (DCD) zone - this module cannot reach those. |
| The CA does not see the record | IONOS name servers can take a few minutes; keep *Wait until it is seen by* at the zone's name servers. |
