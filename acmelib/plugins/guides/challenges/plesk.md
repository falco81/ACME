# Plesk - setup for acme

acme proves names by DNS-01 in the DNS of a **Plesk** server (Plesk Obsidian and Onyx with the XML API), through its XML API (`POST https://PLESK:8443/enterprise/control/agent.php`). It finds the domain (`site get`), reads its records (`dns get_rec`), adds one TXT record per value (`dns add_rec`) and deletes that record by its id (`dns del_rec`). Other values at the name stay.

## What you need

- A Plesk server whose DNS server (BIND) is authoritative for the domain - the domain's name servers point at Plesk.
- HTTPS from acme to the Plesk panel, usually **TCP 8443**.
- Either a Plesk login allowed to manage the domain's DNS (an administrator, or the **customer** owning the domain), or an XML API **secret key**.

## Set up Plesk

**Option A - a secret key (recommended):** on the Plesk server, as root, create a key tied to acme's address:

```sh
plesk bin secret_key --create -ip-address 203.0.113.10 -description "acme DNS-01"
```

The command prints the key. It is accepted only from that IP address. (List keys with `plesk bin secret_key --list`, remove one with `plesk bin secret_key --delete -key KEY`.)

**Option B - a login and password:** use the **customer** account that owns the domain rather than `admin`:

1. **Customers →** the customer → make sure *Access to Customer Panel* is on and the customer has the permission **DNS zone management** (Service Plan → **Permissions → Management of DNS zone**).
2. Use that customer's login and password in acme.

Also check that DNS for the domain is enabled: **Websites & Domains →** the domain → **DNS Settings** (the zone is not switched off and not *Secondary*).

## Fill in acme

| acme field | What to put there |
|---|---|
| Plesk address | `plesk.example.com` (port 8443 if not given; `https://…` allowed) |
| Sign in with | `a secret key` or `login and password` |
| Secret key | the key from option A |
| Login / Password | the customer's (or an administrator's) credentials, option B |
| Domain | empty (the longest domain of the server the name is in), or the domain |
| Check the server's certificate | on; off only for a self-signed panel certificate (advanced) |

## Check it

- In acme press **Test**: it signs in and lists the domains; nothing is changed.
- After an order: **Websites & Domains →** the domain → **DNS Settings**: the `_acme-challenge` TXT record appears and is removed again. On the server:

```sh
dig +short TXT _acme-challenge.www.example.com @localhost
```

## Common problems

| Problem | Fix |
|---|---|
| Error 1001 "Authentication failed" | Wrong login/password, or the secret key is used from another IP than it was created for. |
| Permission denied on `add_rec` | The customer lacks *Management of DNS zone* in its plan. |
| Domain not found | The domain belongs to another customer, or the name is an alias / subdomain of another site - set *Domain*. |
| Record in Plesk but not public | The registrar does not point at Plesk's name servers, or the zone is disabled/secondary. |
