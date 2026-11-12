# ISPConfig - setup for acme

acme writes the certificate, its key and chain into the SSL settings of ISPConfig 3 websites through the **Remote API** (JSON transport, `https://<panel>:8080/remote/json.php`). For each website it reads the site (`sites_web_domain_get`) and updates it (`sites_web_domain_update`) with SSL on, the panel's own Let's Encrypt **off** for that site, and `ssl_action=save`. The server's ISPConfig **cron** then writes the files and reloads the web server, usually within a minute or two. Written against ISPConfig 3.3 (checked with 3.3.2p1).

## What you need

- ISPConfig 3 (3.2 or later recommended) with the panel reachable over HTTPS from acme - by default port **8080**.
- A **remote user** with the function group **Sites Domain functions**.
- The ISPConfig server cron running (it does the actual work).

## Set up ISPConfig

1. Sign in to the panel as `admin`.
2. Go to **System → Remote Users → Add new user**:
   - **Username**: `acme`, a strong **Password**;
   - **Remote Access**: on, and **Remote Access IPs / Hostnames**: the acme server's address (only it may use this user);
   - **Functions**: tick only **Sites Domain functions**.
3. Save.
4. Note the domains of the websites to get the certificate (**Sites → Websites**). For each, acme turns ISPConfig's own Let's Encrypt off - **do not turn it on again**, or ISPConfig replaces acme's certificate.

Test the remote user from the acme server:

```sh
curl -s https://panel.example.com:8080/remote/json.php?login \
     -H 'Content-Type: application/json' \
     -d '{"username":"acme","password":"…"}'
```

The answer must be `{"code":"ok", … "response":"<session id>"}`.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the panel's host name, e.g. `panel.example.com` |
| HTTPS port | 8080 (ISPConfig's default panel port) |
| Remote user | `acme` |
| Password | its password |
| Check the device's certificate | on; off only while the panel has a self-signed certificate |
| CA certificate (advanced) | the CA of the panel's certificate, when not public |
| Website (deployment) | the website's domain, picked from the list or typed |
| More websites | more website domains, one a line |
| Client ID for the update (advanced) | `0`, as in ISPConfig's example |
| Check what is served | `www.example.com:443`, one a line - it may take a minute or two for the cron |

## Check it

- **Test** in acme signs in to the Remote API.
- In the panel: **Sites → Websites → (site) → SSL** shows the new certificate; **Monitor → Show Jobqueue** (or **System → Server Services**) shows whether the cron has processed the change.
- After the cron has run:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Common problems

| Problem | Fix |
|---|---|
| `ISPConfig gave no JSON (is the Remote API on, and the address the panel's?)` | wrong address/port, or a web page answers instead of the panel |
| `ISPConfig said remote_fault - …` on sign-in | wrong user/password, Remote Access off, or the acme IP is not in Remote Access IPs |
| `ISPConfig said remote_fault - You do not have the permissions …` | tick **Sites Domain functions** for the remote user |
| `ISPConfig has no website "…"` | use the website's main domain as in Sites → Websites |
| Saved, but the old certificate is served | the cron has not run yet, or it failed (check the job queue and `/var/log/ispconfig/`) |
| The site's certificate is replaced by Let's Encrypt | someone turned ISPConfig's Let's Encrypt on again for the site |
