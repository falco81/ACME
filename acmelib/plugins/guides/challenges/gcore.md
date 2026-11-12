# Gcore DNS - setup for acme

acme proves names by DNS-01 at Gcore Managed DNS: through the Gcore DNS API v2 (`api.gcore.com/dns`) it reads the TXT record set `_acme-challenge.NAME`, adds its value and writes the set back (`POST`/`PUT`); cleanup takes only its value away (or deletes the set when its value was the last). It signs in with a **permanent API token**.

## What you need

- The zone in Gcore Managed DNS, with the domain delegated to Gcore's name servers.
- Outbound HTTPS from acme to `api.gcore.com` (port 443).

## Set up Gcore

1. Gcore portal → **Profile → API tokens → Create token**.
2. Name it `acme`, set an **expiration** (or none - then rotate it yourself).
3. Choose a **role** that may edit DNS zones but as little else as possible. If your account has users with limited roles, create a separate user for acme with DNS access only and create the token as that user.
4. Copy the token (shown only once).

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | The permanent token |
| Zone | e.g. `example.com`; empty = the longest zone of the account the name is in |
| TTL (s) | (advanced) Default `120` |
| API address | (advanced) Default `https://api.gcore.com/dns` |

## Check it

- **Test** in acme lists the zones the token sees. It changes nothing.
- With curl:

  ```sh
  curl -s -H "Authorization: APIKey $TOKEN" 'https://api.gcore.com/dns/v2/zones?limit=10'
  curl -s -H "Authorization: APIKey $TOKEN" \
    https://api.gcore.com/dns/v2/zones/example.com/_acme-challenge.example.com/TXT
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` | Wrong or expired token. |
| `403` | The token's role may not edit DNS zones. |
| The zone list fails | acme then asks zone by zone - set *Zone* to skip it. |
| The CA does not see the record | Check the domain uses Gcore's name servers; raise *Wait at least (seconds)*. |
