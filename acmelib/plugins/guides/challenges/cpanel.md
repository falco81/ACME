# cPanel - setup for acme

acme proves names by DNS-01 in the DNS of a cPanel account: through cPanel's **UAPI** (port 2083) it reads the zone (`DNS::parse_zone`), adds a TXT record `_acme-challenge.NAME` with `DNS::mass_edit_zone` (with the zone's current SOA serial) and on cleanup removes only the TXT lines holding its value. It signs in as the cPanel user with an **API token**. For cPanel & WHM versions that have API tokens and the `DNS::mass_edit_zone` UAPI function (current releases).

## What you need

- A cPanel account whose domains use the server's DNS (the zone is served by this cPanel/WHM server or its DNS cluster).
- The cPanel user name and access to cPanel to create an API token.
- Outbound HTTPS from acme to the cPanel server on **port 2083** (or the port you give).

## Set up cPanel

1. Sign in to cPanel as the account that owns the domains.
2. **Security → Manage API Tokens → Create**.
3. Name it e.g. `acme`, set an **expiry date** if you like (remember to renew it), and leave it **not restricted to read-only** - acme must edit the zone. Copy the token (shown only once).
4. If the server uses cPHulk or a firewall (CSF, Imunify360) that restricts port 2083, allow acme's public address.
5. The hosting provider must allow the account to edit its DNS zone (the *Zone Editor* feature enabled for the account's package).

## Fill in acme

| acme field | What to put there |
|---|---|
| cPanel address | The server as the account reaches it: `cpanel.example.com`, `host:port` or `https://…`; port 2083 when not given |
| User name | The cPanel account name |
| API token | The token |
| Zone | Load the list and pick it, or type it; empty = the longest of the account's domains the name is in (else by its SOA) |
| TTL (s) | (advanced) Default `300` |
| Check the server's certificate | (advanced) leave on; off only if the server has a self-signed certificate |

## Check it

- **Test** in acme signs in and lists the domains - or, with a *Zone* set, reads that zone and tells its serial and TXT records. It changes nothing.
- With curl:

  ```sh
  curl -s -H "Authorization: cpanel alice:$TOKEN" \
    'https://cpanel.example.com:2083/execute/DomainInfo/list_domains'
  ```

- In cPanel: **Domains → Zone Editor → Manage** shows the `_acme-challenge` TXT record during a run.

## Common problems

| Problem | Fix |
|---|---|
| `401` / `Access denied` | Wrong user or token, or the token expired. |
| Connection refused / timeout | Port 2083 is blocked by the server's firewall, or the hosting uses another address - ask the provider. |
| TLS error | The server's certificate does not match the name used - use the name on its certificate, or turn off *Check the server's certificate*. |
| The zone cannot be read | The account may not edit DNS (Zone Editor disabled), or the domain is a subdomain inside its parent's zone - pick the parent zone. |
| Changes refused repeatedly | Someone else edits the zone at the same time (the serial moves on); try again. |
