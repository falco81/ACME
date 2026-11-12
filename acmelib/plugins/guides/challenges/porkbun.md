# Porkbun - setup for acme

acme proves names by DNS-01 in a domain at Porkbun, through Porkbun **API v3** (`https://api.porkbun.com/api/json/v3`, every call a POST with the API key and secret in the JSON body). It checks the keys (`/ping`), lists the domains (`/domain/listAll`), reads TXT records at the name (`/dns/retrieveByNameType/...`), creates one record per value (`/dns/create/{domain}`) and deletes it by id (`/dns/delete/{domain}/{id}`). Other values at the name stay.

## What you need

- A domain registered at Porkbun using Porkbun's name servers.
- HTTPS (TCP 443) from acme to `api.porkbun.com`.

## Set up Porkbun

1. Sign in at `porkbun.com`.
2. **Account → API Access → Create API Key**; name it `acme`.
3. Copy the **API key** (`pk1_…`) and the **secret API key** (`sk1_…`) - the secret is shown only once.
4. **For each domain** acme may change: **Domain Management →** the domain → **Details → API Access** → switch it **on**. Without it Porkbun refuses with "domain is not opted in to API access".

Leaving API Access off on all other domains is how you limit the key - the key works only on opted-in domains.

Optional check:

```sh
curl -s -H 'Content-Type: application/json' \
  -d '{"apikey":"pk1_…","secretapikey":"sk1_…"}' https://api.porkbun.com/api/json/v3/ping
# {"status":"SUCCESS","yourIp":"203.0.113.10"}
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | `pk1_…` |
| Secret API key | `sk1_…` |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 600 (Porkbun's usual minimum; advanced) |
| API address | `https://api.porkbun.com/api/json/v3` (advanced) |

## Check it

- In acme press **Test**: it pings Porkbun (and shows the address acme calls from) and lists the domains; nothing is changed.
- After an order: **Domain Management →** the domain → **DNS**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| "Invalid API key" | Key or secret wrong, swapped, or the key was deleted. |
| "Domain is not opted in to API access" | Switch **API Access** on for that domain. |
| TTL refused | Keep *TTL (s)* at 600 or more (your account's minimum). |
| Domain not listed | It is in another Porkbun account or uses other name servers. |
