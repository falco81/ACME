# NameSilo - setup for acme

acme proves names by DNS-01 in a domain at NameSilo, through the NameSilo API (`https://www.namesilo.com/api/...`, GET requests with the key in the query): `listDomains`, `dnsListRecords`, `dnsAddRecord` (one TXT record per value) and `dnsDeleteRecord` by the record's id. Other values at the same name stay.

NameSilo takes no TTL under **3600**, and its name servers often need **15 minutes or more** to publish a change - acme waits for them before the CA is asked.

## What you need

- A domain at NameSilo using NameSilo's name servers.
- HTTPS (TCP 443) from acme to `www.namesilo.com`.
- Best: the public IP address acme calls from, to restrict the key.

## Set up NameSilo

1. Sign in at `namesilo.com`.
2. Open **Account → API Manager** (`https://www.namesilo.com/account/api-manager`).
3. Generate a new API key:
   - Leave the *read-only* option **off** (acme has to add and delete records).
   - Restrict the key to acme's public IP address if the page offers it.
4. Copy the key.

**Warning:** a NameSilo key can do anything the API can (including domain operations) - restrict it by IP and keep it only in acme.

Optional check:

```sh
curl 'https://www.namesilo.com/api/listDomains?version=1&type=json&key=KEY'
# ..."code":300,"detail":"success"...
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | the key |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 3600 (NameSilo takes nothing lower; advanced) |
| API address | `https://www.namesilo.com/api` (advanced) |
| Wait until it is seen by | keep *the zone's own name servers* (advanced) |

## Check it

- In acme press **Test**: it lists the domains of the account; nothing is changed.
- After an order: **Domain Manager →** the domain → **Manage DNS**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| code 110 | The key is wrong, or calls come from an address the key is not allowed. |
| code 200 | The domain is not in this account. |
| code 280 | NameSilo did not take the value (e.g. a TTL under 3600). |
| The order times out | NameSilo's name servers are slow: give the ACME issuer a longer waiting time (20-30 minutes). |
