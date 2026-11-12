# Vultr - setup for acme

acme proves names by DNS-01 in a domain in **Vultr DNS**, through Vultr API v2 (`https://api.vultr.com/v2`, bearer API key). It lists the domains, reads the records, adds one TXT record per value (`POST /domains/{domain}/records`) and deletes that record by its id. Other values at the name stay.

## What you need

- The domain added under Vultr **Network → DNS**, with the registrar pointing at Vultr's name servers (`ns1.vultr.com`, `ns2.vultr.com`).
- HTTPS (TCP 443) from acme to `api.vultr.com`.
- The **public IP address** acme reaches the internet from - Vultr refuses the key from any other.

## Set up Vultr

1. Sign in at `my.vultr.com`.
2. **Account → API → Enable API**. Copy the **API key**.
3. Under **Access Control** add acme's public address (IPv4 `/32` and, if acme uses IPv6, its `/128` or `/64`) and **remove "Allow All"** if present.
4. Better than the account's own key: make a sub-user for acme - **Account → Users → Add User** with only the **DNS** permission and **API** enabled, and use that user's API key (with its own Access Control).

Find acme's public address if unsure:

```sh
curl -4 https://ifconfig.me; curl -6 https://ifconfig.me
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | the (sub-user's) API key |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 60 (advanced) |

## Check it

- In acme press **Test**: it lists the domains; nothing is changed.
- After an order: **Network → DNS →** the domain: the `_acme-challenge` TXT record appears and is removed again.

```sh
curl -H 'Authorization: Bearer APIKEY' https://api.vultr.com/v2/domains
```

## Common problems

| Problem | Fix |
|---|---|
| `401` "Unauthorized IP address" | acme calls from an address not in Access Control (check IPv6 too). |
| `401` "Invalid API token" | Key wrong or regenerated. |
| `403` on records | The sub-user lacks the DNS permission. |
| Domain not found | Not added under Network → DNS, or in another account. |
