# DirectAdmin - setup for acme

acme proves names by DNS-01 in the DNS of a DirectAdmin server: through DirectAdmin's legacy API (`CMD_API_DNS_CONTROL`, port 2222) it adds a TXT record `_acme-challenge.NAME` and removes it again by its name and value; every change is read back. DirectAdmin's new API (`/api/…`) has no DNS calls, so the legacy one is used. It signs in as the DirectAdmin user with a **login key**.

## What you need

- A DirectAdmin user that owns the domains, with DNS management allowed (the server serves the zone, or its DNS cluster does).
- Outbound HTTPS from acme to the server's panel port **2222** (or the port you give).
- No TTL is sent: the record gets the zone's TTL.

## Set up DirectAdmin

1. Sign in to DirectAdmin as the user that owns the domains.
2. **Account Manager → Login Keys → Create Key** (in older skins: *Login Keys* under Advanced Features).
3. Fill in:
   - **Key Name**: `acme`; set a long random **Key Value** (or let it generate one) and copy it.
   - **Expires On**: a date, or never - remember to renew.
   - **Allowed Commands**: only `CMD_API_SHOW_DOMAINS` and `CMD_API_DNS_CONTROL`.
   - **Allowed IPs**: acme's public address.
4. Confirm with the user's password and save.
5. An admin or reseller can act for a user: user name `admin|alice` with the admin's login key.

## Fill in acme

| acme field | What to put there |
|---|---|
| DirectAdmin address | The panel as it is reached: `server.example.com`, `host:port` or `https://…`; port 2222 when not given |
| User name | The user the domains belong to (or `admin|user`) |
| Login key | The login key's value (the user's password works too, but is not recommended) |
| Domain | Load the list and pick it, or type it; empty = the longest of the user's domains the name is in |
| Check the server's certificate | (advanced) leave on; off only if the panel has a self-signed certificate |

## Check it

- **Test** in acme signs in and lists the domains - or, with *Domain* set, counts its TXT records. It changes nothing.
- With curl:

  ```sh
  curl -s -u "alice:$LOGIN_KEY" 'https://server.example.com:2222/CMD_API_SHOW_DOMAINS'
  curl -s -u "alice:$LOGIN_KEY" 'https://server.example.com:2222/CMD_API_DNS_CONTROL?domain=example.com&urlencoded=yes'
  ```

## Common problems

| Problem | Fix |
|---|---|
| Sign-in refused / `401` | Wrong user or key, the key expired, or acme's IP is not among its *Allowed IPs*. |
| `error=1` … command not allowed | Add `CMD_API_DNS_CONTROL` (and `CMD_API_SHOW_DOMAINS`) to the key's *Allowed Commands*. |
| Connection refused / timeout | Port 2222 is blocked by the server's firewall (CSF etc.) for acme's address. |
| The job says the record is still there after the delete | Remove it by hand in **DNS Management**, and report the DirectAdmin version. |
