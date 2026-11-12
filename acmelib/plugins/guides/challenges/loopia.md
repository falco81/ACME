# Loopia - setup for acme

acme proves names by DNS-01 in a domain at Loopia (Sweden; also Loopia Serbia and Norway), through **LoopiaAPI** (XML-RPC at `https://api.loopia.se/RPCSERV`). It calls `getDomains`, `getZoneRecords`, `addSubdomain` and `addZoneRecord` to add one TXT record per value, then `removeZoneRecord` (only ours) and `removeSubdomain` once no record is left in the `_acme-challenge` subdomain.

## What you need

- A domain at Loopia using Loopia's name servers.
- HTTPS (TCP 443) from acme to `api.loopia.se` (`api.loopia.rs` for Loopia Serbia).
- Access to Loopia's customer zone.

## Set up Loopia

1. Sign in to the **Loopia customer zone** (Kundzon).
2. Go to **Account settings → LoopiaAPI** and create a new API user. Its name ends in `@loopiaapi` (e.g. `acme@loopiaapi`); set a long random password.
3. Allow that API user exactly these functions:
   - `getDomains`
   - `getZoneRecords`
   - `addSubdomain`
   - `addZoneRecord`
   - `removeZoneRecord`
   - `removeSubdomain`
4. Leave every other function off (no ordering, payment or domain-transfer functions).

## Fill in acme

| acme field | What to put there |
|---|---|
| API user | `acme@loopiaapi` |
| API password | its password |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 300 (Loopia takes nothing lower; advanced) |
| API address | `https://api.loopia.se/RPCSERV`; `https://api.loopia.rs/RPCSERV` for Loopia Serbia (advanced) |

## Check it

- In acme press **Test**: it calls `getDomains` and lists the domains; nothing is changed.
- After an order: customer zone → the domain → **DNS editor**: the `_acme-challenge` subdomain with its TXT record appears and disappears again.

```sh
dig +short TXT _acme-challenge.www.example.se @ns1.loopia.se
```

## Common problems

| Problem | Fix |
|---|---|
| `AUTH_ERROR` | Wrong API user or password, or the function is not allowed for the API user - tick it under LoopiaAPI. |
| `RATE_LIMITED` | Too many calls; acme waits and retries - avoid many validations with the same API user at once. |
| `BAD_INDATA` | The domain or name is not in the account; check *Domain*. |
| CA does not see the record in time | Loopia's name servers can take many minutes: keep *Wait until it is seen by* at the zone's name servers and give the issuer enough waiting time. |
