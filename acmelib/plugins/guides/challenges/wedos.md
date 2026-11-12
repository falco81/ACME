# WEDOS - setup for acme

acme proves names by DNS-01 in a domain in **WEDOS DNS**, through WAPI (`https://api.wedos.com/wapi/json`, JSON). Every call is authenticated with `sha1(login + sha1(WAPI password) + the hour in Europe/Prague)`. acme checks the sign-in (`ping`), lists the domains (`dns-domains-list`), reads the rows (`dns-rows-list`), adds one TXT row per value (`dns-row-add`) or deletes only its own (`dns-row-delete`), and makes the change live with `dns-domain-commit`. Other values at the name stay.

## What you need

- A domain using WEDOS DNS, as a **primary, active** domain there (a secondary one is refused).
- HTTPS (TCP 443) from acme to `api.wedos.com`.
- The **public IP address** acme calls from - WAPI answers only allowed addresses.
- acme's **clock right** (NTP) - the authentication carries the current hour.

## Set up WEDOS

1. Sign in to the WEDOS customer administration (`client.wedos.com`).
2. **Customer → WAPI interface** (Czech UI: *Zákazník → WAPI rozhraní*).
3. Order WAPI (it is free) if it is not active.
4. Set a **WAPI password** - its own, not the account's password.
5. Choose the **JSON** protocol.
6. Add the **IP address** acme calls from to the allowed addresses.

**Warning:** WAPI gives access to the whole customer account (domains, orders), not only DNS. More than 10 invalid requests (wrong auth, address not allowed) block the address for a while - acme then pauses WAPI calls instead of retrying.

Find acme's public address if unsure:

```sh
curl -4 https://ifconfig.me
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Login | the e-mail you sign in to the customer administration with |
| WAPI password | the WAPI password from step 4 |
| Domain | empty (the longest domain in WEDOS DNS the name is in), or the domain, e.g. `example.cz` |
| TTL (s) | 300 (WEDOS takes nothing lower; advanced) |

## Check it

- In acme press **Test**: it sends `ping` and lists the domains; nothing is changed.
- After an order: administration → **DNS →** the domain: the `_acme-challenge` TXT row appears and is removed again. WEDOS's name servers take a few minutes after the commit.

```sh
dig +short TXT _acme-challenge.www.example.cz @ns.wedos.net
```

## Common problems

| Problem | Fix |
|---|---|
| Codes 2050-2053 (authentication) | Wrong login or WAPI password, IP address not allowed, or acme's clock is off by an hour (time zone / NTP). |
| Address blocked for a while | Too many invalid requests - fix the cause and wait; WAPI unblocks by itself. |
| Code 2318 | The domain is secondary in WEDOS DNS - only primary domains can be written. |
| CA does not see the record yet | Keep *Wait until it is seen by* at the zone's name servers; WEDOS needs a few minutes. |
