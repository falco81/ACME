# Constellix - setup for acme

acme proves names by DNS-01 at Constellix (DigiCert): through the Constellix DNS API v1 (`api.dns.constellix.com`) it adds its value to the TXT record `_acme-challenge.NAME` (Constellix keeps all values of a name in one record) and on cleanup writes the record back without its value - or deletes it when its value was the last one.

## What you need

- The domain hosted in Constellix DNS.
- The account's API key and secret key.
- Outbound HTTPS from acme to `api.dns.constellix.com` (port 443).
- **A correct clock on the acme machine**: every request carries a token made from the current time.

## Set up Constellix

1. Sign in to Constellix → your account's profile → **API keys** (Edit My Profile / API Access, depending on the interface version).
2. Generate (or view) the **API key** and the **secret key**. Copy both.
3. If your account has several users, create a dedicated user for acme with rights only on the DNS domains acme may change, and use that user's keys - the keys act with the user's rights.

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | The API key |
| Secret key | The secret key |
| Domain | e.g. `example.com`; empty = the longest domain of the account the name is in |
| TTL (s) | (advanced) Default `60` |
| API address | (advanced) Default `https://api.dns.constellix.com` |

## Check it

- **Test** in acme signs a request and lists the domains (`/v1/domains`). It changes nothing.
- After a run, ask one of the domain's name servers:

  ```sh
  dig +short NS example.com
  dig +short TXT _acme-challenge.example.com @<one of those name servers>
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` / `403` on every request | Wrong key or secret, or the acme machine's clock is off - check NTP (`timedatectl`). |
| The domain is not listed | The keys belong to a user without rights on it; set *Domain* exactly. |
| The CA does not see the record | Raise *Wait at least (seconds)*. |
