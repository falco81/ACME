# bunny.net CDN - setup for acme

acme puts your own certificate on the **custom hostnames of a bunny.net pull zone**
instead of bunny's free one, through the bunny.net API (`https://api.bunny.net`, the
account's API key in the `AccessKey` header). The pull zone is found by its ID or name;
each hostname - those you list, or every one the certificate covers - gets the full chain
and key (`POST /pullzone/<id>/addCertificate`). bunny keeps one certificate per hostname:
the new one replaces the one before, nothing is left to clean up.

For bunny.net CDN pull zones (any plan with custom hostnames).

## What you need

- A bunny.net account and the pull zone (name or ID).
- The custom hostnames **already added** to the pull zone, with their DNS CNAME pointing
  at the zone (acme does not add hostnames).
- Outbound HTTPS from acme to `api.bunny.net` (TCP 443), directly or through the proxy.

## Set up bunny.net

1. Sign in to the bunny.net dashboard.
2. Open **Account settings → API key** (the account API key) and copy it.
   **This key gives full access to the account** - bunny.net has no narrower key for
   pull zones; keep it only in acme and rotate it if it leaks.
3. Open **CDN → the pull zone → Hostnames** and make sure each hostname is listed.
   Note the pull zone's name or ID (in the URL of the pull zone page).

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | The account API key from step 2 |
| Through the proxy (advanced) | On by default: out through Settings → Proxy |
| Timeout (s) (advanced) | Default 30 |
| Pull zone (deploy) | Its name or ID, e.g. `www-example` |
| Hostnames (deploy) | One a line, e.g. `cdn.example.com`; empty: each hostname the certificate covers |
| Check what is served | e.g. `cdn.example.com:443` |

The action **List the pull zones** shows the pull zones and their hostnames, and whether
each has a certificate - it changes nothing.

## Check it

- **Try**: `signed in to bunny.net; N pull zones`.
- In the dashboard: **Pull zone → Hostnames** shows the certificate on each hostname.

  ```sh
  openssl s_client -connect cdn.example.com:443 -servername cdn.example.com </dev/null | openssl x509 -noout -issuer -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| 401 on Try | Wrong API key - use the account key (Account settings → API key), not a storage zone password |
| `no pull zone is set` / not found | Wrong name or ID - use *List the pull zones* |
| Hostname not touched | It is not a hostname of the pull zone, or the certificate does not cover it |
| The free certificate still served | Wait a minute for the edge, then check again |
| Cannot reach `api.bunny.net` | Allow outbound HTTPS or set up the proxy |
