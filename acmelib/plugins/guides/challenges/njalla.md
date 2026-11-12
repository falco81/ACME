# Njalla - setup for acme

acme proves names by DNS-01 in a domain at Njalla, through Njalla's JSON-RPC API (`https://njal.la/api/1/`, header `Authorization: Njalla <token>`). It calls `list-domains`, `list-records`, `add-record` (one TXT record per value) and `remove-record` by the record's id. Other values at the same name stay.

## What you need

- A domain at Njalla using Njalla's DNS.
- HTTPS (TCP 443) from acme to `njal.la`.
- Best: the public IP address acme calls from, to restrict the token.

## Set up Njalla

1. Sign in at `njal.la`.
2. Go to **Settings → API access → Add token**.
3. Give it a comment such as `acme` and, if offered, restrict it to the address acme calls from.
4. Copy the token.

**Warning:** a Njalla token works for every domain of the account - keep it only in acme and restrict it by address where you can.

Optional check:

```sh
curl -H 'Authorization: Njalla TOKEN' -H 'Content-Type: application/json' \
  -d '{"method":"list-domains","params":{}}' https://njal.la/api/1/
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | the token |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 60 (advanced) |
| API address | `https://njal.la/api/1/` (advanced) |

## Check it

- In acme press **Test**: it lists the domains of the account; nothing is changed.
- After an order: Njalla → **Domains →** the domain → **DNS**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| "Permission denied" / invalid token | Token wrong or deleted, or calls come from an address the token does not allow. |
| Domain not found | The domain is in another Njalla account or uses other name servers. |
| `{error: {code, message}}` on add | acme shows Njalla's message - check the domain and the TTL. |
