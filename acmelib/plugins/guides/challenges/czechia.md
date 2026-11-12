# CZECHIA.COM (ZONER) - setup for acme

acme proves names by DNS-01 at CZECHIA.COM (ZONER's registrar and DNS): through its REST API (`api.czechia.com`) it adds a TXT record `_acme-challenge.NAME` (`POST /api/DNS/{domain}/TXT`, published at once) and removes exactly its own value afterwards. Other values at the name stay.

## What you need

- A domain with DNS hosted at CZECHIA.COM.
- Access to the CZECHIA.COM administration to create a REST API token.
- Outbound HTTPS from acme to `api.czechia.com` (port 443).

## Set up CZECHIA.COM

1. Sign in to the CZECHIA.COM administration → **your account → REST API** (the help page *Aktivace REST API* at napoveda.czechia.com describes it).
2. Create a token of the kind **ACME** - it may only change the TXT records of DNS and works from any address. This is the minimal and recommended kind.
3. A **full-access** token also works, but only from the IP addresses you allow there - then add acme's public address.
4. Copy the token.

With an ACME token, the list of domains may be refused - that is expected: acme finds the zone by its SOA, or set *Domain*.

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | The token |
| Domain | e.g. `example.cz`; empty = found by its SOA |
| TTL (s) | (advanced) Default `300`; 120 to 172800 |
| API address | (advanced) Default `https://api.czechia.com/api` |

## Check it

- **Test** in acme: with *Domain* set it reads that zone and counts its TXT records; without it, it lists the account's domains (an ACME token may not - Test then says to set the domain). It changes nothing.
- With curl:

  ```sh
  curl -s -H "authorizationToken: $TOKEN" https://api.czechia.com/api/DNS/example.cz
  dig +short TXT _acme-challenge.example.cz @<one of the domain's name servers>
  ```

## Common problems

| Problem | Fix |
|---|---|
| `no API token is set` | Fill in *API token*. |
| `CZECHIA.COM has no DNS zone ... for this token` | The domain is in another account or its DNS is not at CZECHIA.COM; check *Domain*. |
| `401` / `403` with a full-access token | acme's address is not allowed for the token - allow it, or use an ACME token. |
| TTL refused | Keep *TTL (s)* between 120 and 172800. |
