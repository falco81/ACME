# Sophos Firewall (SFOS / XG) - setup for acme

acme uses the Sophos Firewall **XML API** (`https://<fw>:4444/webconsole/APIController`).
It uploads the certificate as PKCS#12 under a new dated name (`UploadCertificate` - SFOS
does not let a certificate in use be replaced), points each listed **firewall (WAF) rule**
(web server protection) at it, and removes older acme certificates beyond *Previous
versions to keep* (one still referenced stays).

Not changed by acme: the admin/user portal certificate, SSL VPN and hotspot certificates.

For Sophos Firewall SFOS 18 to 22 (XG and XGS).

## What you need

- Network access from acme to the firewall's admin console: **TCP 4444**.
- The XML API enabled with acme's IP allowed.
- An administrator whose profile may change **Certificates** (and **firewall / web server
  protection rules** when you list WAF rules).
- The WAF rules that should use the certificate already exist, with HTTPS.

## Set up Sophos Firewall

1. Allow HTTPS admin access from the zone acme comes from: **Administration → Device
   access** → tick *HTTPS* for that zone (or add a local service ACL exception rule for the
   acme IP only).
2. Enable the API: **Backup & firmware → API** → *API configuration*: on; add the acme
   server's IP under *Allowed IP address*. Apply.
3. Create a device access profile: **Profiles → Device access → Add**, e.g. `acme-api`,
   *None* everywhere except **Read-write** on the certificates area and on firewall /
   web server protection (only if WAF rules are used). The grouping of these items differs
   between SFOS versions - check that *Certificates* is included.
4. Create the administrator: **Authentication → Users → Add**, *User type*
   **Administrator**, *Profile* `acme-api`, e.g. user `acme` with a strong password.
5. Note the exact names of the WAF rules (**Rules and policies → Firewall rules**).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The firewall's admin address, e.g. `fw.example.local` |
| HTTPS port | `4444` |
| User | `acme` (default) |
| Password | Its password |
| Check the device's certificate | On; off only while the admin console has its self-signed certificate |
| CA certificate (advanced) | The CA of the admin console certificate, if not public (e.g. the firewall's appliance CA) |
| Firewall (WAF) rules (deploy) | One rule name a line, e.g. `WAF www.example.com` |
| Previous versions to keep (advanced) | Default 1, `-1` keeps all |
| Check what is served | e.g. `www.example.com:443` |

## Check it

- Press **Try** on the target: acme lists the certificates and answers
  `signed in to ...; N certificates there`.
- In the web admin after a deployment: **Certificates → Certificates** lists `acme-...`;
  the WAF rule shows it as *HTTPS certificate*.
- The API calls are in **Log viewer → Admin**.

## Common problems

| Problem | Fix |
|---|---|
| `the firewall does not let acme in` | API off, acme's IP not under *Allowed IP address*, wrong password. |
| Connection refused on 4444 | HTTPS admin not allowed from that zone (*Device access*). |
| `the firewall said <code> - ...` on upload | The profile has no write right to certificates. |
| `there is no firewall rule "..."` | The name differs (exact, case-sensitive). |
| `the rule ... has no certificate` | Not a WAF rule with HTTPS. |
| `the old ... stays (still used?)` | Something else still uses it (VPN, portal); switch it and it is removed later. |
