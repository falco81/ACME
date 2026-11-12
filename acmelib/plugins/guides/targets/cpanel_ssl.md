# cPanel / WHM - setup for acme

acme installs the certificate, its key and CA bundle on websites (virtual hosts) of a
cPanel server, one of two ways:

- **cPanel (UAPI)**: as the account itself, `SSL::install_ssl` on the account's own sites
  (port 2083). Older certificates acme installed that no site uses any more are deleted
  from the account's SSL storage.
- **WHM API 1**: as root or a reseller, `installssl` on any account's domain (port 2087).

cPanel replaces the certificate of the virtual host and restarts the web server itself.

For cPanel & WHM with API tokens (11.64 and later; checked against 11.138).

## What you need

- HTTPS from acme to the server: **2083** (cPanel) or **2087** (WHM).
- An **API token** of the cPanel account (UAPI), or of root / a reseller (WHM).
- The account's **SSL/TLS** feature enabled (WHM → Feature Manager) for UAPI.
- The websites (domains) already exist on the account.

## Set up cPanel / WHM

**cPanel account (UAPI)**

1. Sign in to cPanel as the account → **Security → Manage API Tokens → Create**.
2. Name it (e.g. `acme`), optionally an expiry date, **Create**, copy the token (shown
   once). cPanel tokens have the account's full rights - keep it only in acme.

**WHM (root or reseller)**

1. WHM → **Development → Manage API Tokens → Generate Token**.
2. Name it `acme`; untick **All Features** and grant only the SSL privileges - **SSL Site
   Management** (`ssl`) and **SSL Information** (`ssl-info`); names as WHM lists them on
   your version. Optionally restrict it to the acme server's IP (*Allowed IP addresses*,
   newer versions).
3. Save and copy the token.

**Both**

- If cPHulk or a firewall (CSF) blocks unknown addresses, whitelist acme's IP.
- AutoSSL may replace certificates it considers due; if it touches these sites, exclude
  them (cPanel → **SSL/TLS Status → Exclude from AutoSSL**).

Test a cPanel token from a shell:

```sh
curl -s -H "Authorization: cpanel acct:<token>" https://server.example.com:2083/execute/SSL/installed_hosts | head
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The cPanel or WHM server, e.g. `server.example.com` |
| Through | `cPanel (UAPI) - the account's own sites` or `WHM API 1 - root or a reseller, any account` |
| HTTPS port | Empty: 2083 for cPanel, 2087 for WHM |
| User | The cPanel account (UAPI), or `root` / the reseller (WHM) |
| API token | The token from above |
| Check the device's certificate / CA certificate | As for every HTTPS server |
| Domain (deploy) | The website's main domain, picked from the list or typed; empty (UAPI): every site the certificate covers |
| More domains (deploy) | One a line, e.g. `shop.example.com` |
| Send the CA bundle (deploy, advanced) | On; off: cPanel works the bundle out itself |
| Previous versions to keep (advanced) | Default 1 (UAPI SSL storage) |
| Check what is served | e.g. `www.example.com:443` |

The action **List the websites** lists the virtual hosts and the certificate each has -
it changes nothing.

## Check it

- **Try**: `signed in to ... as acct (cPanel); N websites with SSL`.
- In cPanel: **Security → SSL/TLS → Manage SSL sites**, or WHM → **SSL/TLS → Manage SSL
  Hosts**.

## Common problems

| Problem | Fix |
|---|---|
| 401 / `Access denied` | Wrong user or token, or the token expired |
| 403 on a WHM function | The token lacks the SSL privileges (ACL) |
| `The SSL/TLS feature is disabled` | Enable SSL/TLS for the account's feature list |
| Connection refused / blocked | Port 2083/2087 blocked or acme's IP blocked by cPHulk/CSF |
| Domain not found | Not a site of this account (UAPI) - use WHM, or the right account |
| Certificate replaced later by AutoSSL | Exclude the domains from AutoSSL |
