# Omnissa Unified Access Gateway - setup for acme

acme replaces the TLS server certificate of an Omnissa (formerly VMware) **Unified Access Gateway (UAG)** through its **admin REST API** on port 9443. You choose which certificate:

- **Internet-facing (`END_USER`)** - the default: the HTTPS proxy and the PCoIP / Blast Secure Gateway, i.e. what Horizon clients and browsers see on 443;
- **Admin interface (`ADMIN`)** - the certificate of the admin interface on 9443;
- **Both** - the admin one is sent last, because its connector restarts with it.

For each, acme sends the key and the certificate with its intermediates in one request (`PUT /rest/v1/config/certs/ssl/end_user` or `/admin`). It signs in with a token (`POST /rest/v1/jwt/login`), or with HTTP basic authentication on an older UAG. The same certificate is sent again only when the UAG no longer has it.

## What you need

- A UAG appliance (3.x or later; current Omnissa releases use the token sign-in, older ones HTTP basic).
- HTTPS access from acme to the UAG admin interface, port **9443** (on a 2- or 3-NIC deployment: the management NIC).
- A UAG admin user with full admin rights (certificate replacement is an admin task; a monitoring-only role is not enough).
- An RSA or ECDSA key (RSA is the safest choice for older UAG versions).

## Set up the UAG

1. Sign in to the UAG admin UI: `https://uag01.example.local:9443/admin`.
2. Optionally create a separate admin for acme: **Advanced Settings → Account Settings** (in recent versions) → add an admin user, e.g. `acme`, with the full admin role (not *Monitoring*). Otherwise use `admin`. Note password expiry settings - **an expired password stops renewals**; choose a password policy accordingly or watch it.
3. Restrict who reaches port 9443: allow it only from your admin network and the acme server (firewall in front of the UAG's management NIC).
4. For a pair of UAGs behind a load balancer: create **one acme target per UAG**.

Test the sign-in from the acme server:

```sh
curl -s -X POST https://uag01.example.local:9443/rest/v1/jwt/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"…","refreshTokenExpiryInHours":3}'
```

The answer must contain an `accessToken`.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the UAG (its management address) |
| HTTPS port | 9443 |
| Admin user | `admin` or the admin from step 2 |
| Password | its password |
| Sign-in (advanced) | a token (current versions); HTTP basic for an older UAG |
| Check the device's certificate | off (or give its CA) until the admin interface has a trusted certificate; on afterwards |
| CA certificate (advanced) | the CA of the admin interface's certificate |
| Which certificate (deployment) | Internet-facing (END_USER), Admin interface (ADMIN), or Both |
| Key format (advanced) | RSA / EC private key (default, as the UAG documentation sends), or PKCS#8 |
| Check what is served | the public name on port 443, e.g. `desktop.example.com:443` |

## Check it

- **Test** in acme reads the UAG's system settings and shows its name (`signed in to the UAG … (uagName)`).
- In the admin UI: **Advanced Settings → TLS Server Certificate Settings** shows the certificate in use.
- From a shell:

```sh
openssl s_client -connect desktop.example.com:443 -servername desktop.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Common problems

| Problem | Fix |
|---|---|
| `the UAG gave no token at sign-in` / 401 | wrong user/password, expired password, or an older UAG: set *Sign-in* to HTTP basic |
| 403 | the user is not a full admin |
| TLS error to port 9443 | the admin interface still has a self-signed certificate: give its CA or switch off the check until *Both* has replaced it |
| PUT refused (400) | the key and certificate do not match, or the key format is not taken: try the other *Key format*, or an RSA key |
| Browsers still see the old certificate | a load balancer in front terminates TLS, or the other UAG of the pair was not updated |
| Admin UI briefly unreachable after *Both* | expected: the admin connector restarts with its new certificate |
