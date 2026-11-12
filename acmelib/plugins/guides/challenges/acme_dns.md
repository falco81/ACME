# acme-dns - setup for acme

acme proves names by DNS-01 through an [acme-dns](https://github.com/joohoi/acme-dns) server: it sends the TXT value to the server's `/update` API, and the acme-dns server answers the CA's DNS question itself. Your own DNS only needs a CNAME `_acme-challenge.NAME` → the account's *fulldomain*, put in once per name. Works with any acme-dns server (self-hosted, or a public one such as `auth.acme-dns.io`).

## What you need

- An acme-dns server reachable from acme over HTTPS (the API, usually port 443) and from the internet on **port 53 (UDP and TCP)** - the CA asks it.
- One acme-dns account per name, or per two names at most: **an account keeps only the newest two TXT values**, so a certificate with more names needs one account per name (the *Accounts by name (JSON)* field).
- Access to your DNS to add the CNAME records once.

## Set up acme-dns

1. If you run your own server, follow the acme-dns README: its `config.cfg` sets the zone it answers for (e.g. `auth.example.org`), its listen addresses and the API; delegate that zone to it with an `NS` record (and an `A` record for the server) in the parent zone.
2. Register an account. Limit it to acme's address with `allowfrom` (CIDR):

   ```sh
   curl -s -X POST https://auth.example.org/register \
        -H 'Content-Type: application/json' \
        -d '{"allowfrom": ["203.0.113.10/32"]}'
   ```

   The answer holds `username`, `password`, `subdomain` and `fulldomain`. Keep the password - acme-dns shows it only once.
3. In the DNS of each name, add once:

   ```text
   _acme-challenge.example.com.  3600  IN  CNAME  d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.org.
   ```

   (the right side is the account's `fulldomain`). For `example.com` and `*.example.com` the same CNAME serves both.
4. For several names, repeat the registration per name and collect the accounts as JSON (the format acme-dns-client and lego use):

   ```text
   {"example.com": {"username": "...", "password": "...", "subdomain": "...", "fulldomain": "..."},
    "example.org": {"username": "...", "password": "...", "subdomain": "...", "fulldomain": "..."}}
   ```

## Fill in acme

| acme field | What to put there |
|---|---|
| acme-dns server | The API address, e.g. `https://auth.example.org` |
| Username | `username` from `/register` |
| Password (API key) | `password` from `/register` |
| Subdomain | `subdomain` from `/register` |
| Full domain | `fulldomain` from `/register` - what the CNAME points to |
| Accounts by name (JSON) | (advanced) several accounts, one per name, as above - instead of the four fields |
| Check the server's certificate | (advanced) leave on; off only for a self-signed test server |
| Wait until it is seen by, Wait at least, Resolvers | (advanced) how acme waits for the record - defaults are fine |

## Check it

- **Test** in acme asks the server's `/health` and shows the CNAME to put in.
- Check the CNAME and the server:

  ```sh
  dig +short CNAME _acme-challenge.example.com
  curl -s https://auth.example.org/health
  dig @auth.example.org TXT d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.org
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` / `forbidden` from `/update` | Wrong username/password, or acme's address is not in the account's `allowfrom`. |
| `no acme-dns account for NAME` | The name is not a key in *Accounts by name (JSON)* - add it (or `*.NAME`). |
| The CA sees an old value | More than two names on one account: use one account per name. |
| The CA cannot find the TXT | The CNAME is missing or points elsewhere; or port 53 of the acme-dns server is closed to the internet. |
| TLS error | The server's certificate is not trusted - fix it, or (test only) turn off *Check the server's certificate*. |
