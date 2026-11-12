# UltraDNS - setup for acme

acme proves names by DNS-01 in a **primary zone at UltraDNS** (Vercara, now DigiCert), through its REST API (`https://api.ultradns.com`). It signs in with a user name and password (`POST /v1/authorization/token`, `grant_type=password`) and keeps the bearer token for its lifetime, lists the zones (`GET /v3/zones`), reads the TXT RRset at `_acme-challenge.NAME`, adds or removes its value and writes the RRset back (`POST` to create, `PUT` to change, `DELETE` when ours was the last value). Other values at the name are written back as read.

## What you need

- The zone as a **primary** zone in UltraDNS.
- HTTPS (TCP 443) from acme to `api.ultradns.com`.
- An UltraDNS account admin who can create users and set permissions.

## Set up UltraDNS

1. Sign in to the UltraDNS portal (`portal.ultradns.com`) as an account administrator.
2. **Accounts → Users → Add User**: a user of its own for acme (e.g. `acme-dns01`), a long random password. Do not enable a second factor for this user if it would block API sign-in (the API uses user name + password only).
3. Create a group with only the rights acme needs and put the user in it: **Accounts → Groups** → a group with **record** permissions (create / update / delete records) on the zones acme may change, and read access to those zones. Do not give account, user or zone-creation rights.
4. Optionally restrict the user to acme's IP address if your account offers IP restrictions.

Optional check:

```sh
curl -s -d 'grant_type=password&username=acme-dns01&password=PASSWORD' \
  https://api.ultradns.com/v1/authorization/token
```

## Fill in acme

| acme field | What to put there |
|---|---|
| User name | the acme user |
| Password | its password |
| Zone | empty (the longest zone the user sees that the name is in), or the zone |
| TTL (s) | 60 (advanced) |
| API address | `https://api.ultradns.com` (advanced) |

## Check it

- In acme press **Test**: it signs in and lists the zones the user sees; nothing is changed.
- After an order: portal → **Zones →** the zone → records: the TXT RRset at `_acme-challenge…` gains acme's value and loses it again.

## Common problems

| Problem | Fix |
|---|---|
| `401` / "invalid_grant" at sign-in | Wrong user name or password, user locked, or a second factor required. |
| Error 60001 "invalid token" | The token expired - acme signs in again by itself; if it repeats, check the password. |
| `403` on POST/PUT | The user's group lacks record create/update/delete on that zone. |
| Zone not found | It is a secondary or alias zone, or the user cannot see it. |
