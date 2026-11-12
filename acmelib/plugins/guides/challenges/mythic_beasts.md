# Mythic Beasts - setup for acme

acme proves names by DNS-01 in a zone hosted by Mythic Beasts (UK), through its **DNS API v2** (`https://api.mythic-beasts.com/dns/v2`). It gets a short-lived token from `https://auth.mythic-beasts.com/login` with the API key ID and secret (OAuth2 client credentials), lists the zones, adds a TXT value at `_acme-challenge.NAME` and removes exactly that value again (`DELETE .../TXT?data=VALUE`), so other values at the name stay.

## What you need

- A domain whose DNS is hosted by Mythic Beasts.
- HTTPS (TCP 443) from acme to `auth.mythic-beasts.com` and `api.mythic-beasts.com`.

## Set up Mythic Beasts

1. Sign in to the Mythic Beasts **control panel**.
2. Open **API keys** and create a new key, named e.g. `acme`.
3. Give the key **DNS API** access to the zone(s) acme may change. Tighter (recommended): limit it to
   - records whose host matches `_acme-challenge` (and `_acme-challenge.*` for names below the apex),
   - record type **TXT**.
4. Save, and copy the **key ID** and the **secret** - the secret is shown only once.

Optional check:

```sh
curl -u 'KEYID:SECRET' -d grant_type=client_credentials https://auth.mythic-beasts.com/login
# {"access_token":"...","expires_in":...}
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API key ID | the key ID |
| API secret | the secret |
| Zone | empty (the longest zone the key sees that the name is in), or the zone |
| TTL (s) | 60 (advanced) |
| API address / Sign-in address | leave the defaults (advanced) |

## Check it

- In acme press **Test**: it signs in and lists the zones the key sees; nothing is changed.
- After an order: control panel → **DNS** → the zone: the `_acme-challenge` TXT record appears and is removed again.

```sh
dig +short TXT _acme-challenge.www.example.co.uk @ns1.mythic-beasts.com
```

## Common problems

| Problem | Fix |
|---|---|
| `401` at sign-in | Key ID or secret wrong, or the key was deleted. |
| `403` on a record | The key's DNS permission does not cover this zone, host or type - widen it (TXT at `_acme-challenge…`). |
| Zone not listed | The key has no access to that zone, or the zone is in another account. |
