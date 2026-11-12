# PowerDNS (HTTP API) - setup for acme

acme proves names by DNS-01 in a zone of a **PowerDNS Authoritative** server, through its built-in HTTP API (`/api/v1`, header `X-API-Key`). It reads the server's version, lists the zones and changes the TXT RRset at `_acme-challenge.NAME` with `PATCH`:

- PowerDNS **4.9.12+ (in 4.9), 5.0.2+ and later**: `EXTEND` adds only our value, `PRUNE` removes only our value - nothing else is written.
- Older servers: the RRset is read and written whole with `REPLACE` (its TTL kept), one change at a time; `DELETE` only when ours was the last value.

## What you need

- PowerDNS Authoritative 4.x or 5.x with a backend that holds the zone (gsqlite3, gmysql, gpgsql, LMDB …) - not a BIND-backend-only setup (zone files are read-only for the API).
- HTTP(S) from acme to the PowerDNS webserver, usually **TCP 8081**.

## Set up PowerDNS

1. Enable the API in `pdns.conf` (`/etc/powerdns/pdns.conf` or `/etc/pdns/pdns.conf`):

   ```text
   api=yes
   api-key=<a long random string>
   webserver=yes
   webserver-address=0.0.0.0
   webserver-port=8081
   webserver-allow-from=127.0.0.1,203.0.113.10/32
   ```

   - `webserver-allow-from` must contain **acme's address** and as little else as possible.
   - Since 4.6 the key can be stored hashed: `pdnsutil hash-password` prints a value to put in `api-key=` (acme still gets the clear key).
2. Restart PowerDNS:

   ```sh
   systemctl restart pdns
   ```

3. The API key is **not** limited to one zone - it can change every zone of the server. Put TLS in front (a reverse proxy) when acme reaches the API across a network you do not trust.

Check from acme's network:

```sh
curl -H 'X-API-Key: KEY' http://pdns.example.com:8081/api/v1/servers/localhost
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API address | `http://pdns.example.com:8081` (or the `https://` address of the proxy) |
| API key | the clear `api-key` |
| Server id | `localhost` (advanced) |
| Zone | empty (the longest zone of the server the name is in), or the zone |
| TTL (s) | 60 (advanced) |
| Check the API's certificate | on for an `https://` address (advanced) |

## Check it

- In acme press **Test**: it reads the daemon type and version and lists the zones; nothing is changed. The version tells whether EXTEND/PRUNE are used.
- On the server:

```sh
pdnsutil list-zone example.com | grep _acme-challenge
dig +short TXT _acme-challenge.www.example.com @127.0.0.1
```

## Common problems

| Problem | Fix |
|---|---|
| `401 Unauthorized` | Wrong key, or a hashed key pasted into acme - acme needs the clear one. |
| Connection refused / `403` | `webserver=yes` missing, wrong `webserver-address`, or acme not in `webserver-allow-from`. |
| `422` "RRset … is not in canonical format" | A broken value in the RRset written by hand; fix the record. |
| Zone not found | The zone is in a BIND backend, or *Server id* is not `localhost`. |
| Secondaries do not get the change | The zone's SOA-EDIT-API / NOTIFY settings - set `SOA-EDIT-API` (e.g. `DEFAULT`) so the serial rises. |
