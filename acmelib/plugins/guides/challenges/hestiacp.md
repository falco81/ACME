# HestiaCP - setup for acme

acme proves names by DNS-01 in the DNS of a HestiaCP server: through the HestiaCP API (`https://SERVER:8083/api/`, each call one `v-*` command) it adds a TXT record `_acme-challenge.NAME` (`v-add-dns-record`) and deletes only its own records afterwards (`v-delete-dns-record` by ID). Each command raises the zone's serial, rewrites the zone and reloads the DNS server itself. For HestiaCP versions with access keys (1.6 and later).

## What you need

- A HestiaCP server whose DNS server serves the domain (DNS domain added for the user).
- The API enabled on the server, and acme's address allowed to use it.
- Outbound HTTPS from acme to the panel port **8083** (or the port you give).

## Set up HestiaCP

1. As admin: **Server settings → Configure → Security → API**: enable the API and add acme's public address to the **allowed IP addresses** (or on the shell: `v-change-sys-api enable`).
2. Create an access key for the user that owns the DNS domains, allowed only the four DNS commands. In the panel: the user → **Access keys → Add** and tick the commands; or on the shell as root:

   ```sh
   v-add-access-key alice 'v-list-dns-domains,v-list-dns-records,v-add-dns-record,v-delete-dns-record' acme json
   ```

   (check `v-add-access-key` without arguments for the exact usage of your version).
3. Copy the **access key ID** and the **secret key** (shown only once).
4. An administrator's key works too, acting for the user named in acme - a user's own key is the smaller choice.

## Fill in acme

| acme field | What to put there |
|---|---|
| HestiaCP address | The server: `server.example.com`, `host:port` or `https://…`; port 8083 when not given |
| User | The HestiaCP user the DNS domains belong to (default `admin`) |
| Access key | The access key ID |
| Secret key | Its secret |
| Zone | Load the list and pick it, or type it; empty = the longest of the user's DNS domains the name is in |
| TTL (s) | (advanced) `0` = the zone's own TTL |
| Check the server's certificate | (advanced) leave on; off only if the panel has a self-signed certificate |

## Check it

- **Test** in acme signs in and lists the user's DNS domains - or, with *Zone* set, counts its records. It changes nothing.
- On the server:

  ```sh
  v-list-dns-records alice example.com
  ```

## Common problems

| Problem | Fix |
|---|---|
| `E_FORBIDEN` (10) | The key may not run that command, or acme's IP is not allowed for the API. |
| `E_NOTEXIST` (3) | The user or DNS domain does not exist - check *User* and *Zone*. |
| `E_DISABLED` (11) | The API (or the user) is disabled - enable it. |
| Connection refused / timeout | Port 8083 is blocked for acme's address by the firewall. |
