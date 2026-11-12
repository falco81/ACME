# froxlor - setup for acme

acme sets the SSL certificate of froxlor domains through froxlor's API (`api.php`, JSON-RPC style). For each domain it reads the current certificate (`Certificates.get`), then adds it the first time (`Certificates.add`) or replaces it (`Certificates.update`), with the certificate, key and chain as PEM text. froxlor's own **cron** then writes the web server's configuration - the new certificate is served after the next cron run. Written against froxlor 2.x (checked with 2.3.16).

## What you need

- froxlor 2.x with the external API turned on.
- HTTPS access from acme to the froxlor panel (where `api.php` is), usually port 443.
- An API key and secret of a froxlor account allowed to use the API and to manage the domains' certificates (an admin, or the customer that owns the domains).
- The domains must **not** use froxlor's own Let's Encrypt - froxlor refuses a certificate for a domain it manages itself.

## Set up froxlor

1. As a froxlor admin, turn the API on: **System → Settings → froxlor API** (enable the API) and save. Check the cron of froxlor is running (`froxlor_master_cronjob` / the `froxlor-cli` cron, as installed).
2. Allow API access for the account acme will use: in **Resources → Admins** (or **Resources → Customers**) edit the account and enable **API access**. Use the least privileged account that owns the domains: a customer for its own domains, an admin only when domains of several customers are needed.
3. Sign in as that account and create the key: **(your name, top right) → API keys → Create new key**. Set **Allowed from** to the acme server's IP address, and a validity if you want one. Copy the **API key** and **API secret**.
4. For each domain: **Domains → (domain) → Edit → SSL** - turn **off** "Let's Encrypt" for the domain (otherwise acme's certificate is refused) and keep SSL enabled for it.

Test the key from the acme server:

```sh
curl -s -u "$API_KEY:$API_SECRET" -H 'Content-Type: application/json' \
     -d '{"command":"Froxlor.listFunctions"}' https://froxlor.example.com/api.php
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Panel address | the froxlor URL, e.g. `https://froxlor.example.com` (acme calls `api.php` there) |
| API key | the key from step 3 |
| API secret | the secret from step 3 |
| Check the device's certificate | on; off only while the panel has a self-signed certificate |
| CA certificate (advanced) | the CA of the panel's certificate, when not public |
| Domains (deployment) | the froxlor domain names, one a line, exactly as named in froxlor |
| Check what is served | `www.example.com:443`, one a line - only after froxlor's cron has run |

## Check it

- **Test** in acme calls `Froxlor.listFunctions` and reports how many API functions are allowed.
- After a deployment, in froxlor **Domains → (domain) → SSL** shows the new certificate; after the cron has run:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

On the froxlor server you can run the cron at once instead of waiting (path and options as installed - check `froxlor-cli list` of your version), e.g.:

```sh
sudo /var/www/froxlor/bin/froxlor-cli froxlor:cron --force
```

## Common problems

| Problem | Fix |
|---|---|
| `froxlor does not let acme in (401/403)` | wrong key/secret, the API is off, the account has no API access, or *Allowed from* does not include acme's IP |
| `froxlor said 406 … sslcertificateisletsencryptmanaged` | the domain uses froxlor's Let's Encrypt - turn it off for the domain |
| `froxlor said 404/406` for a domain | the domain name is not froxlor's or does not belong to the account |
| Certificate set but old one still served | froxlor's cron has not run yet (or is broken) - check the cron |
| `no domain is set` | fill in *Domains* in the deployment |
