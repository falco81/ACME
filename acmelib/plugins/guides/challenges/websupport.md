# Websupport - setup for acme

acme proves names by DNS-01 in a domain at **Websupport** (websupport.sk / websupport.cz), through REST API v1 (`https://rest.websupport.sk/v1/user/self/zone/...`). Every request is signed HMAC-SHA1 with the API secret over `METHOD PATH UNIXTIME`, sent as basic authentication `KEY:SIGNATURE` with a `Date` header. acme lists the zones, reads the records, adds one TXT record per value and deletes that record by its id. Other values at the name stay.

## What you need

- A domain at Websupport using Websupport's DNS.
- HTTPS (TCP 443) from acme to `rest.websupport.sk`.
- acme's **clock right** (NTP) - the signature carries the time.

## Set up Websupport

1. Sign in at `admin.websupport.sk` (or `admin.websupport.cz`).
2. Click your name → **Security and login → API access → Generate new access**.
3. Where offered, **limit the access to the IP address** acme calls from.
4. Copy the **identifier** (API key) and the **secret** - the secret is shown only once.

**Warning:** the API key acts on the whole Websupport account (not only DNS) - keep it only in acme and restrict it by IP.

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | the identifier |
| API secret | the secret |
| Domain | empty (the longest domain of the account the name is in), or the domain, e.g. `example.sk` |
| TTL (s) | 600 (advanced) |
| API address | `https://rest.websupport.sk` (advanced) |

## Check it

- In acme press **Test**: it lists the zones of the account; nothing is changed.
- After an order: admin → the domain → **DNS**: the `_acme-challenge` TXT record appears and is removed again.

```sh
dig +short TXT _acme-challenge.www.example.sk @ns1.websupport.sk
```

## Common problems

| Problem | Fix |
|---|---|
| `401` | Key and secret do not belong together, or acme's clock is off (check NTP). |
| `403` | acme's address is not allowed for the key. |
| Zone not found | The domain uses other name servers or is in another Websupport account. |
| v1 no longer answers | Websupport has a v2 API beside it; point *API address* elsewhere only if Websupport announces it. |
