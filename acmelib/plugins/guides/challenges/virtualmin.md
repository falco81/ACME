# Virtualmin - setup for acme

acme proves names by DNS-01 in the DNS (BIND) of a **Virtualmin** server, through its Remote API (`POST https://SERVER:10000/virtual-server/remote.cgi`), which runs Virtualmin's command-line programs: `list-domains --with-feature dns` (the zones), `modify-dns --add-record-with-ttl` to add our TXT value, `modify-dns --remove-record "NAME. TXT VALUE"` - **always with the value**, so other values at the name stay - and `get-dns --type TXT` to read the zone back after each change. `modify-dns` raises the serial and reloads BIND itself.

## What you need

- A Virtualmin server (GPL or Pro) whose BIND is authoritative for the domain, the virtual server having the **DNS domain** feature on.
- HTTPS from acme to Webmin/Virtualmin, usually **TCP 10000**.
- The **master administrator** credentials - Virtualmin opens its Remote API to the master administrator only. It has no token or API key of its own.

## Set up Virtualmin

1. Decide which master administrator acme uses: `root`, or a dedicated Webmin user that Virtualmin treats as master administrator (Webmin → **Webmin Users** → a user with full access to the *Virtualmin Virtual Servers* module; acme's **Test** tells whether the Remote API accepts it).
2. Two-factor authentication must be **off** for that user (the Remote API uses HTTP basic authentication).
3. Limit who can reach Webmin to acme and your admins: **Webmin → Webmin Configuration → IP Access Control** → *Only allow from listed addresses*, add acme's address.
4. Make sure the domain has DNS: **Virtualmin →** the virtual server → **Edit Virtual Server → Enabled features → DNS domain enabled**.

Check from acme's network:

```sh
curl -u 'root:PASSWORD' -d 'program=list-domains&with-feature=dns&name-only=' \
  https://server.example.com:10000/virtual-server/remote.cgi
# example.com ... Exit status: 0
```

**Warning:** the master administrator controls the whole server - keep the password only in acme and the IP access control tight.

## Fill in acme

| acme field | What to put there |
|---|---|
| Virtualmin address | `server.example.com` (port 10000 when not given; `https://…` allowed) |
| Master administrator | `root` (or your master admin user) |
| Password | its password |
| Virtual server | the domain whose zone holds the name (load the list and pick it); empty: found |
| TTL (s) | 60 (advanced) |
| Check the server's certificate | on; off only for Webmin's self-signed certificate (advanced) |

## Check it

- In acme press **Test**: it signs in; with *Virtual server* set it reads the zone's TXT records with `get-dns`, otherwise it lists the virtual servers with DNS. Nothing is changed.
- After an order: **Virtualmin →** the server → **DNS Settings → DNS Records**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| `401` / login page returned | Wrong password, 2FA on, or the user is not the master administrator. |
| Connection refused | Port 10000 blocked, or acme's address not in Webmin's IP Access Control. |
| "change did not happen" in the job | The name is not in that virtual server's zone - a sub-server keeps records in its parent's zone: set *Virtual server* to the parent. |
| `Exit status: 1` from `modify-dns` | The virtual server has no DNS feature, or BIND failed to reload - see Webmin's BIND module. |
