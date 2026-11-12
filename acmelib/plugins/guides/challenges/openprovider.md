# Openprovider - setup for acme

acme proves names by DNS-01 in a DNS zone at Openprovider, through its REST API (`https://api.openprovider.eu/v1beta`). It signs in (`POST /v1beta/auth/login`, a bearer token kept a few hours), lists the zones, reads the zone's TXT records, and adds or removes only its own value with `PUT /v1beta/dns/zones/{zone}` (`records: {add: […]}` / `{remove: […]}`). Other values at the name stay.

Works with both Openprovider DNS and Premium DNS (Sectigo).

## What you need

- A zone in Openprovider's DNS (standard or Premium DNS).
- HTTPS (TCP 443) from acme to `api.openprovider.eu`.
- The public IP address acme calls from.

## Set up Openprovider

1. Sign in to the Openprovider control panel (`cp.openprovider.eu`).
2. Create a dedicated user for acme: **Account → Users** (contacts with login) → add a user `acme`, with a long random password.
3. Allow **API access** for that user and restrict it to acme's IP address (the API access / IP whitelist settings of the user or account).
4. Keep two-factor sign-in off for this API user if it would block API login (check Openprovider's settings: API logins use user name + password only).

**Warning:** Openprovider users are not limited to DNS - this user can act on the reseller account. Keep the password only in acme and the IP restriction tight.

Optional check:

```sh
curl -s -H 'Content-Type: application/json' \
  -d '{"username":"acme","password":"PASSWORD"}' https://api.openprovider.eu/v1beta/auth/login
```

## Fill in acme

| acme field | What to put there |
|---|---|
| User name | the acme user |
| Password | its password |
| DNS | `Openprovider DNS`, or `Premium DNS (Sectigo)` for zones there |
| Zone | empty (the longest zone of the account the name is in), or the zone |
| TTL (s) | 600 (advanced) |
| API address | `https://api.openprovider.eu` (advanced) |

## Check it

- In acme press **Test**: it signs in and lists the zones; nothing is changed.
- After an order: control panel → **DNS management → DNS zones →** the zone: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| `401` at login | Wrong user or password, API access not allowed, or acme's address not whitelisted. |
| Zone not found | The zone is on the other *DNS* (standard vs Premium) - change *DNS*. |
| PUT refused | The user has no right to change DNS zones of this account. |
