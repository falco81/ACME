# ISPConfig - setup for acme

acme proves names by DNS-01 in a DNS zone kept by an **ISPConfig 3** panel. It uses the panel's Remote API (JSON transport, `https://PANEL:8080/remote/json.php`): `login`, `dns_zone_get` (the zone), `dns_rr_get_all_by_zone` (the records), `dns_txt_add` with `update_serial: true` (our value, the SOA serial raised), `dns_txt_delete` by the record's id, and `logout`. Other values at the same name stay. ISPConfig applies changes through its server cron, about a minute later; acme waits until the zone's name servers answer the value.

Checked against ISPConfig 3.3.2p1; other 3.x releases with the JSON remote API work the same way.

## What you need

- An ISPConfig 3 panel whose DNS module serves the zone (the server's BIND/PowerDNS is authoritative for it).
- HTTPS from acme to the panel, usually **TCP 8080**.
- Panel admin access to create a remote user.

## Set up ISPConfig

1. Sign in to the panel as **admin**.
2. **System → Remote Users → Add new user**:
   - *Username* `acme`, a long random *Password*.
   - **Remote Access**: tick it and enter the address acme calls from in the allowed addresses (*Remote Access IPs / Hostnames*).
   - **Functions**: tick only **DNS zone functions** and **DNS txt functions**.
3. Make sure the Remote API is allowed in the panel's security settings (`/usr/local/ispconfig/security/security_settings.ini`, the `remote_api_allowed` setting - it is `yes` by default).
4. If the zone belongs to a client and you want the records counted against that client, note the client's ID (**Client →** the client; see *Client ID* below).

Check from acme's network that the API answers:

```sh
curl -s https://panel.example.com:8080/remote/json.php?login \
  -d '{"username":"acme","password":"PASSWORD"}'
# {"code":"ok","message":"","response":"<session id>"}
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Panel address | `panel.example.com:8080` (name, name:port or `https://…`; port 8080 if not given) |
| Remote user | `acme` |
| Password | the remote user's password |
| Zone | empty (picked from the panel's list or found), or the zone |
| Client ID | `0` = the remote user's own (advanced); an ISPConfig client ID if needed |
| TTL (s) | 60 (the lowest ISPConfig takes; advanced) |
| Check the panel's certificate | on; off only for a panel with a self-signed certificate you cannot replace |

## Check it

- In acme press **Test**: it signs in and, with *Zone* set, counts the zone's records; otherwise it lists the zones the user may see. Nothing is changed.
- After an order: **DNS →** the zone → **Records**: a TXT record `_acme-challenge...` appears and is deleted again.

## Common problems

| Problem | Fix |
|---|---|
| `remote_fault` "The login failed" | Wrong user/password, or acme's address not in the remote user's allowed addresses. |
| "You do not have the permissions to access this function" | Tick **DNS zone functions** and **DNS txt functions** for the remote user. |
| Connection refused / timeout | Port 8080 blocked by a firewall between acme and the panel. |
| Record in the panel but not in DNS | The server cron has not run yet, or the DNS server is not reloaded - check `/var/log/ispconfig/cron.log`. |
| Certificate error | The panel uses a self-signed certificate: install a proper one, or switch *Check the panel's certificate* off. |
