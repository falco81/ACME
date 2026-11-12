# Plesk - setup for acme

acme uses the Plesk **XML API** (`POST https://<host>:8443/enterprise/control/agent.php`)
to install the certificate, its key and the CA chain into a **certificate repository** -
a subscription's or the server's (*Tools & Settings*) - under a dated name
`acme-<name>-<date>-<serial>`.

**acme does not assign the certificate to the website**: Plesk's XML API has no documented
call for that. After each renewal choose the new certificate for the site in Plesk (or with
the CLI, below); the job says so. Older acme certificates are removed only if you set
*Previous versions to keep* (default `-1`, keep all), because Plesk does not tell whether
one is still assigned.

For Plesk Obsidian on Linux or Windows.

## What you need

- Network access from acme to the Plesk panel: **TCP 8443**.
- An administrator or reseller login, or an XML API **secret key**.
- The subscription (its main domain) whose repository should get the certificate, or use
  the server's repository.

## Set up Plesk

1. Allow acme to reach port 8443 (Plesk Firewall: **Tools & Settings → Firewall**, or your
   network firewall); limit it to the acme server's IP.
2. Choose how acme signs in:
   - **Secret key** (recommended - no password stored, bound to acme's IP). On the Plesk
     server:

     ```sh
     plesk bin secret_key --create -ip-address <acme-IP> -description "acme"
     ```

     The command prints the key. List keys with `plesk bin secret_key --list`.
   - **Login and password**: the `admin` account or a **reseller** that owns the
     subscription. The certificate operator acts as that account.
3. If *Tools & Settings → Restrict Administrative Access* is on, add the acme server's IP.
4. Note the subscription's domain (*Websites & Domains*).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The Plesk host, e.g. `plesk.example.com` |
| HTTPS port | `8443` |
| Sign in with | *a secret key* or *login and password* |
| Secret key | The key from step 2 |
| Login / Password | `admin` or the reseller, and its password |
| Check the device's certificate | On; off only while the panel has a self-signed certificate |
| CA certificate (advanced) | The CA of the panel's certificate, if not public |
| Repository (deploy) | *the subscription's* or *the server's (Tools & Settings)* |
| Subscription (deploy) | The subscription's domain, e.g. `example.com` |
| Previous versions to keep (advanced) | `-1` (default, keep all); set a number only if you know older ones are no longer assigned |
| Check what is served | e.g. `www.example.com:443` |

## After each renewal: assign it

In Plesk: **Websites & Domains → <domain> → SSL/TLS Certificates** → choose the new
`acme-...` certificate for the domain (or *Hosting Settings → Certificate*). Or on the
server:

```sh
plesk bin subscription -u example.com -certificate-name acme-example.com-20261112-1a2b3c4d
```

## Check it

- Press **Try** on the target: acme lists the server's repository and answers
  `signed in to Plesk ...; N certificates in the server's repository`.
- After a deployment the certificate appears in the repository you chose; the job ends
  with `installed ... - assign it to the website in Plesk`.

## Common problems

| Problem | Fix |
|---|---|
| `Plesk said ... authentication failed` | Wrong login/password, or the secret key was created for another IP. |
| `no subscription is set` | Fill in *Subscription*, or choose the server's repository. |
| `Plesk said ... domain does not exist` | The subscription name is not the subscription's main domain. |
| Connection refused / timeout | Port 8443 blocked, or *Restrict Administrative Access* excludes acme. |
| Site still serves the old certificate | Expected: assign the new one (see above). |
| `the older ... stays` | Plesk refused to remove it (probably still assigned); remove it by hand. |
