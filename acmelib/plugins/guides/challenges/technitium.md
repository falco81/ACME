# Technitium DNS Server - setup for acme

acme proves names by DNS-01 in a primary zone of a **Technitium DNS Server**, through its HTTP API (form POSTs with an API token): `/api/zones/list`, `/api/zones/records/get`, `/api/zones/records/add` (type TXT) and `/api/zones/records/delete` with the value - only acme's value is taken away; other TXT values at the name stay.

## What you need

- Technitium DNS Server (a version with API tokens and per-zone permissions) that is authoritative for the zone (a **Primary** zone there).
- HTTP(S) from acme to the web console: `http://HOST:5380` or `https://HOST:53443`.

## Set up Technitium

1. Sign in to the web console as an administrator.
2. **Administration → Users → Add User**: user `acme`, a long random password. Do not put it in the *Administrators* group.
3. Give it **Modify** on the zone(s) acme may change: **Zones →** the zone → **Permissions** (or **Administration → Permissions → Zones**) → add user `acme` with *View* and *Modify*.
4. Create a token for that user: **Administration → Sessions → Create Token** → user `acme`, token name `acme`. (Or sign in as `acme` and use *your user* → **Create API Token**.) Copy the token - it is shown once.
5. Restrict who can reach the console port to acme and your admins (a firewall), and prefer HTTPS (**Settings → Web Service → Enable HTTPS**).

Optional check:

```sh
curl -s 'https://dns.example.local:53443/api/zones/list?token=TOKEN'
# {"response":{"zones":[...]},"status":"ok"}
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Server address | `https://dns.example.local:53443` (or `http://HOST:5380`) |
| API token | the token |
| Zone | empty (the longest primary zone of the server the name is in), or the zone |
| TTL (s) | 60 (advanced) |
| Check the server's certificate | on; off only for a self-signed console certificate (advanced) |

## Check it

- In acme press **Test**: it lists the zones the token sees; nothing is changed.
- After an order: web console → **Zones →** the zone: the `_acme-challenge` TXT record appears and is removed again.

```sh
dig +short TXT _acme-challenge.www.example.com @dns.example.local
```

## Common problems

| Problem | Fix |
|---|---|
| `invalid-token` | Token wrong or deleted - create a new one. |
| "Access was denied" on add | The user lacks **Modify** on that zone. |
| Zone not found | It is a secondary/stub/forwarder zone - acme writes only into primary zones. |
| Certificate error | Self-signed console certificate: install a proper one, or switch the check off. |
