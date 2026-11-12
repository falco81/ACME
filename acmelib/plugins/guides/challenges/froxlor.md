# froxlor - setup for acme

acme proves names by DNS-01 in the DNS of a froxlor server: through the froxlor API (`api.php`, JSON over HTTPS, basic authentication with an API key and secret) it adds a TXT entry `_acme-challenge.NAME` to the domain's zone (`DomainZones.add`) and deletes only its own entries afterwards (`DomainZones.delete`). froxlor writes zones through its cron (`REBUILD_DNS`), so the record reaches the name servers only after the next cron run - acme waits until every name server has it. For froxlor 2.x with the external API.

## What you need

- A froxlor server that serves the domain's DNS (froxlor's DNS server enabled, *DNS* on for the domain).
- Outbound HTTPS from acme to the froxlor panel (port 443).
- The froxlor cron running regularly (it publishes the zone).

## Set up froxlor

1. As admin: **Settings → System settings → Enable external API usage** - on.
2. Sign in as the **customer** who owns the domain (or as an admin - an admin's key can see all domains; a customer's key is the smaller choice).
3. **(your name) → API keys → Create** (top right menu → *API keys*).
4. Edit the new key: limit **Allowed from** to acme's public address, and set an expiry if you like.
5. Copy the **API key** and **secret**.
6. Make sure the customer may edit DNS (*DNS editor* allowed for the customer and the domain).

## Fill in acme

| acme field | What to put there |
|---|---|
| froxlor address | The panel, e.g. `froxlor.example.com` or `https://…/`; acme calls `api.php` there |
| API key | The key |
| API secret | Its secret |
| Zone | Load the list and pick it, or type it; empty = the longest main domain with DNS the name is in |
| TTL (s) | (advanced) Default `60` |
| Check the server's certificate | (advanced) leave on |

## Check it

- **Test** in acme lists the domains - or, with *Zone* set, counts the zone's own entries. It changes nothing.
- With curl:

  ```sh
  curl -s -u "$KEY:$SECRET" -H 'Content-Type: application/json' \
    -d '{"command":"DomainZones.listing","params":{"domainname":"example.com"}}' \
    https://froxlor.example.com/api.php
  ```

## Common problems

| Problem | Fix |
|---|---|
| `403` / API not enabled | Turn on *Enable external API usage* in the system settings. |
| `401` | Wrong key/secret, or acme's address is not in the key's *Allowed from*. |
| The zone has no DNS | Enable DNS for the domain (and the DNS editor for the customer). |
| The record takes long to appear | The froxlor cron has not run yet; run it more often or raise *Wait at least (seconds)*. |
