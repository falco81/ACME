# Kong Gateway - setup for acme

acme deploys certificates to Kong Gateway through the **Kong Admin API**. Each renewal adds a **new certificate object** (`POST /certificates`, full chain and key, tagged `acme`, `acme-<name>`, `acme-fp-…`, `acme-at-…`), then points each **SNI** at it (`PUT /snis/<name>` - an SNI that does not exist yet is created). Older acme certificate objects of this certificate that no SNI uses any more are deleted. A dual certificate (ECDSA + RSA of the same names) goes into one object as `cert` / `cert_alt`, and Kong serves each client the kind it supports.

For Kong Gateway (OSS or Enterprise) with a database. **Kong in DB-less mode cannot be changed through the Admin API**, and Kong Konnect (hosted control plane) is not covered.

## What you need

- Kong Gateway 2.x / 3.x running with a database (PostgreSQL), so the Admin API can write.
- Network access from acme to the Admin API (e.g. `http://kong:8001` or `https://kong:8444`).
- Kong Gateway Enterprise with RBAC: an RBAC user token that may change certificates and SNIs in the workspace.

## Set up Kong

1. Make the Admin API reachable from the acme server **only**. In `kong.conf` (or `KONG_ADMIN_LISTEN`), e.g.:

```text
admin_listen = 10.0.0.5:8001, 10.0.0.5:8444 ssl
```

   and allow port 8001/8444 only from acme (and your admins) in the firewall. **An open Admin API without RBAC lets anyone reconfigure Kong.** Prefer the HTTPS listener (8444) when acme is on another machine.

2. Kong Gateway Enterprise with RBAC: create a role limited to certificates and SNIs, and a user for acme (as a super-admin, in the workspace acme uses):

```sh
ADMIN=https://kong.example.local:8444; H="Kong-Admin-Token: $SUPER_TOKEN"
curl -s -X POST $ADMIN/rbac/roles -H "$H" -d name=acme-certs
for ep in /certificates /certificates/* /snis /snis/*; do
  curl -s -X POST $ADMIN/rbac/roles/acme-certs/endpoints -H "$H" \
       -d endpoint="$ep" -d actions=read,create,update,delete -d workspace=default
done
curl -s -X POST $ADMIN/rbac/users -H "$H" -d name=acme -d user_token="$ACME_TOKEN"
curl -s -X POST $ADMIN/rbac/users/acme/roles -H "$H" -d roles=acme-certs
```

   Check the endpoint list against your Kong version's RBAC documentation; acme also reads `GET /` for **Test**.

3. Kong OSS has no RBAC: leave the token empty and protect the Admin API by network only.

## Fill in acme

| acme field | What to put there |
|---|---|
| Admin API | the Admin API address with scheme and port, e.g. `http://kong.example.local:8001` |
| Admin token | Enterprise with RBAC: the acme user's token (`Kong-Admin-Token`); empty without RBAC |
| Workspace (advanced) | Enterprise: the workspace; empty: the default one |
| Check the device's certificate | for an `https://` Admin API: on, unless it has a self-signed certificate |
| CA certificate (advanced) | the CA of the Admin API's certificate, when not public |
| SNIs (deployment) | the server names, one a line (`www.example.com`, `*.example.com`); empty: the certificate's names |
| Previous versions to keep | older acme certificate objects kept |
| Check what is served | the proxy address with a name, e.g. `www.example.com:443`, one a line |

## Check it

- **Test** in acme reads the version (`GET /`) and one certificate (`Kong 3.x at …`).
- On the Admin API:

```sh
curl -s http://kong.example.local:8001/snis/www.example.com
curl -s "http://kong.example.local:8001/certificates?tags=acme"
```

- On the proxy: `openssl s_client -connect kong.example.local:8443 -servername www.example.com </dev/null | openssl x509 -noout -subject -enddate`

## Common problems

| Problem | Fix |
|---|---|
| `… (Kong runs without a database: its Admin API cannot change anything)` | DB-less Kong: change the declarative config instead, or run Kong with a database |
| `… does not answer as a Kong Admin API` | the address is the proxy port (8000/8443), not the Admin API (8001/8444) |
| 401 / 403 | Enterprise RBAC: missing or wrong token, or the role lacks `/certificates` or `/snis` |
| 404 on every call | wrong *Workspace* |
| `no SNI to point at the certificate` | fill in *SNIs*, or the certificate has no names Kong takes |
| `the older certificate … stays: SNIs still use it` | some SNI not listed in *SNIs* still points to it; add it or move it by hand |
