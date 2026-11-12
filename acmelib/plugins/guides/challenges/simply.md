# Simply.com - setup for acme

acme proves names by DNS-01 in a domain at **Simply.com** (formerly UnoEuro), through its REST API v2 (`https://api.simply.com/2`). It lists the products (domains), reads the DNS records, adds one TXT record per value (`POST /my/products/{object}/dns/records/`) and deletes that record by its id. Other values at the name stay.

It signs in with the **account number + API key** (basic authentication) or, for the newer keys, with the **API key alone** (bearer token).

## What you need

- A domain at Simply.com using Simply.com's name servers.
- HTTPS (TCP 443) from acme to `api.simply.com`.

## Set up Simply.com

1. Sign in to the Simply.com **control panel**.
2. Go to **Account → API**.
3. Note the **account number** shown there (`S123456`) and create / show the **API key**.
4. If the page offers a newer key type that works alone (a bearer key), you may use it without the account number.

**Warning:** the API key acts on the whole Simply.com account (all products) - keep it only in acme.

Optional check:

```sh
curl -u 'S123456:APIKEY' https://api.simply.com/2/my/products/
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Account number | `S123456`; empty when the key is a bearer key used alone |
| API key | the API key |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 120 (advanced) |
| API address | `https://api.simply.com/2` (advanced) |

## Check it

- In acme press **Test**: it lists the domains of the account; nothing is changed.
- After an order: control panel → the domain → **DNS**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| `401` / "Unauthorized" | Account number and key do not belong together, or a bearer-only key was sent with an account number (leave it empty) - or the reverse. |
| Domain not found | The domain is in another Simply.com account or uses other name servers. |
| CA does not see the record yet | Keep *Wait until it is seen by* at the zone's name servers. |
