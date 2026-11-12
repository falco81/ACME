# Joker.com - setup for acme

acme proves names by DNS-01 in a zone served by Joker.com's name servers, through **DMAPI** (`https://dmapi.joker.com/request/...`). It signs in (`login`, giving an Auth-SID), lists the zones (`dns-zone-list`), reads the zone (`dns-zone-get`), adds its one line (`_acme-challenge.www TXT 0 "<value>" 300`) or removes only its own TXT line, and writes the zone back (`dns-zone-put`).

**`dns-zone-put` replaces the whole zone.** acme writes every other line back exactly as read, one change of a zone at a time, never writes a zone it read empty, and reads the zone again after each write. Do not edit the zone by hand in the very second a certificate is ordered.

## What you need

- Domains whose DNS is served by Joker.com (Joker's name servers, "Joker.com DNS").
- HTTPS (TCP 443) from acme to `dmapi.joker.com` (or `dmapi.ote.joker.com` for the OT&E test system).
- A Joker.com account with DMAPI access (DMAPI is documented for reseller accounts - check with Joker.com if your account is a plain customer account).

## Set up Joker.com

1. Sign in at `joker.com`.
2. Open **My Profile → Manage Joker.com API access keys**.
3. Create a new API key with the permission **"modifications only"** (enough to read and write zones; a read-only key cannot write the zone).
4. Copy the key - store it only in acme.

Alternative: sign in with the account's user name and password (choose *user name and password* in acme). A key is better: it can be revoked alone.

## Fill in acme

| acme field | What to put there |
|---|---|
| Sign in with | `a DMAPI API key` |
| API key | the key from step 3 |
| User name / Password | only with *user name and password* |
| Zone | empty (picked from Joker's list, or found by SOA), or the zone |
| TTL (s) | 300 (DMAPI takes nothing lower; advanced) |
| API | `dmapi.joker.com`; OT&E only for tests (advanced) |

## Check it

- In acme press **Test**: it signs in; with *Zone* set it reads the zone and counts its records, otherwise it lists the zones. Nothing is written.
- After an order: Joker.com → **My Domains →** the domain → **DNS**: the `_acme-challenge` TXT record appears and is removed again; all other records are unchanged.

```sh
dig +short TXT _acme-challenge.www.example.com @a.ns.joker.com
```

## Common problems

| Problem | Fix |
|---|---|
| Login refused / `Error: authorization` | Wrong or revoked key; make a new one. |
| Write refused with a key | The key is read-only - create one with "modifications only". |
| Zone not in `dns-zone-list` | The domain uses other name servers, or is in another Joker.com account. |
| TTL error | Keep *TTL (s)* at 300 or more. |
| A hand-made change disappeared | It was made while acme wrote the zone (read-modify-write); make it again and avoid editing during renewals. |
