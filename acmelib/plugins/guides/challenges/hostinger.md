# Hostinger - setup for acme

acme proves names by DNS-01 in a domain's DNS zone at Hostinger: through the Hostinger API (`developers.hostinger.com`) it adds its value to the TXT RRset `_acme-challenge.NAME` (`PUT` with `overwrite: false`) and on cleanup writes the RRset back without it (`overwrite: true`) - or deletes the RRset when its value was the last one.

## What you need

- The domain using Hostinger's DNS (in your Hostinger domain portfolio).
- Outbound HTTPS from acme to `developers.hostinger.com` (port 443).

## Set up Hostinger

1. Sign in to **hPanel → Account → API** (the account menu → *API*).
2. **New token**: name it `acme`, choose an **expiry** (remember to renew it).
3. If hPanel offers a choice of resources, give the token only the domains acme needs.
4. Copy the token (shown only once).

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | The token |
| Domain | e.g. `example.com`; empty = the longest domain of the account the name is in |
| TTL (s) | (advanced) Default `300` |
| API address | (advanced) Default `https://developers.hostinger.com` |

## Check it

- **Test** in acme lists the domains of the portfolio - or, with *Domain* set, counts that zone's record sets. It changes nothing.
- With curl:

  ```sh
  curl -s -H "Authorization: Bearer $TOKEN" https://developers.hostinger.com/api/dns/v1/zones/example.com
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` | Wrong or expired token. |
| The domain is not found | Its DNS is not at Hostinger, or it is in another account; set *Domain*. |
| `422` on the write | Check the TTL (at least 60) and that the domain's DNS zone is active. |
| The CA does not see the record | Check the domain uses Hostinger's name servers; raise *Wait at least (seconds)*. |
