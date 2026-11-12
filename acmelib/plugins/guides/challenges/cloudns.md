# ClouDNS - setup for acme

acme proves names by DNS-01 at ClouDNS: through the ClouDNS HTTP API (`api.cloudns.net`) it adds a TXT record `_acme-challenge.NAME` (`add-record.json`) and deletes only its own record afterwards (`delete-record.json`). It signs in as an API user or, better, an API **sub-user** limited to the zones acme may change.

## What you need

- The zone hosted at ClouDNS, on a plan that includes API access.
- Outbound HTTPS from acme to `api.cloudns.net` (port 443); acme's public IP address, because **the API answers only the addresses the API user allows**.

## Set up ClouDNS

1. Sign in at `cloudns.net` → **API & Resellers**.
2. Best: **API sub-users → Add new sub-user**: set a password and **allowed IP** = acme's public address. Then give the sub-user only the zones acme may change (the sub-user's zone delegation / *Add zone* in its settings).
3. Or: **API users → Add new user** (the main API user, `auth-id`) with acme's IP allowed - this user can change every zone of the account.
4. Note the **ID** of the (sub-)user and its password.

## Fill in acme

| acme field | What to put there |
|---|---|
| Signs in as | `an API sub-user (sub-auth-id)` or `the main API user (auth-id)` |
| Auth ID | The (sub-)user's ID, e.g. `1234` |
| Auth password | Its password |
| Zone | e.g. `example.com`; empty = the longest zone of the account the name is in |
| TTL (s) | (advanced) Default `60`; ClouDNS knows only 60, 300, 900, 1800, 3600 … - another value is raised to the next |

## Check it

- **Test** in acme signs in (`login.json`) and lists the zones. It changes nothing.
- With curl (sub-user):

  ```sh
  curl -s -d 'sub-auth-id=1234' -d "auth-password=$PASS" https://api.cloudns.net/dns/login.json
  dig +short TXT _acme-challenge.example.com @ns1.cloudns.net
  ```

## Common problems

| Problem | Fix |
|---|---|
| `Invalid authentication, incorrect auth-id or auth-password` | Wrong ID/password, or *Signs in as* does not match (sub-user vs. main user). |
| Sign-in refused from acme | acme's public IP is not in the user's allowed IPs. |
| The zone is not listed | The sub-user was not given that zone. |
| The CA does not see the record | Raise *Wait at least (seconds)*; check `dig NS example.com` points to ClouDNS. |
