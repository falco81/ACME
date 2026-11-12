# Cloudflare Origin CA - setup for acme

The **Cloudflare Origin CA** source gets certificates for a server behind Cloudflare's proxy (the *origin*) from Cloudflare's Origin CA: trusted by **Cloudflare's edge only, not by browsers**. acme sends its CSR with the hostnames, the kind (`origin-ecc` / `origin-rsa`) and the validity (`POST /client/v4/certificates`); the certificate comes back at once and acme puts the Origin CA root above it. **The private key never leaves acme.** Revocation is `DELETE /client/v4/certificates/{id}`; *Try it* verifies the API token; *Import from a source* lists a zone's Origin CA certificates. Free, up to 15 years. No IP addresses; wildcards allowed.

## What you need

- A Cloudflare account with the zones of the names (Cloudflare refuses names outside the account's zones).
- An **API token** limited to those zones (preferred), or the account's **Origin CA Key**.
- HTTPS access **from acme** to `api.cloudflare.com` and `developers.cloudflare.com` (the root) on port 443, directly or through Settings → Proxy.
- On Cloudflare, the zone's SSL/TLS mode **Full (strict)** to make the edge check the origin's certificate.

## Set up Cloudflare

1. **My Profile → API Tokens → Create Token → Create Custom Token**:
   - Permissions: **Zone → SSL and Certificates → Edit**; add **Zone → Zone → Read** so acme can list the zones (for *Import from a source*).
   - Zone Resources: **Include → Specific zone** (each zone acme issues for) - or all zones of an account.
   - Client IP Address Filtering (optional): acme's public IP.
   - TTL: as your policy says - renew the token before it ends.
2. Copy the token (shown once).
3. Or the legacy way: **My Profile → API Tokens → Origin CA Key → View** - it can issue for every zone of the user, so prefer the token.
4. In each zone: **SSL/TLS → Overview → Full (strict)** once the origin serves the Origin CA certificate.

Check the token:

```sh
curl -s -H "Authorization: Bearer $CF_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify
```

## Fill in acme

Sources → **Add** → **Cloudflare Origin CA**.

| acme field | What to put there |
|---|---|
| Signing in | *API token (Zone - SSL and Certificates - Edit)* or *Origin CA Key* |
| API token / Origin CA Key | from step 2 / 3 |
| Validity | `90 days` (default); 7 days - 15 years |
| Kind of the certificate (advanced) | *as the key* (ECDSA → `origin-ecc`, RSA → `origin-rsa`) |
| Zone (for importing) | only for *Import from a source* - *Load the list*, pick the zone |
| Zone ID typed (advanced) | the zone ID from its Overview page, where the list cannot be loaded (Origin CA Key) |
| Put the Origin CA root above the certificate (advanced) | on |
| API address (advanced) | `https://api.cloudflare.com/client/v4` |

## Check it

- Sources → the source → **Test** (Try it): the token is verified.
- After issuing, Cloudflare: **SSL/TLS → Origin Server** lists the certificate. From the origin side (bypassing the proxy):

```sh
openssl s_client -connect <origin IP>:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -enddate     # issuer: CloudFlare Origin ... CA
```

## Common problems

| Problem | Fix |
|---|---|
| `Authentication error` / `10000` | the token lacks *SSL and Certificates → Edit* on that zone, or it expired |
| A hostname refused | it is not in a zone of the account (or not one the token includes) |
| Browsers say *not trusted* when reaching the origin directly | expected: Origin CA is trusted only by Cloudflare's proxy - keep the record proxied (orange cloud) |
| Cloudflare `526 Invalid SSL certificate` | the origin serves another certificate, or the hostname is not in it |
| IP address refused | Origin CA does not issue for IP addresses |
| `Load the list` of zones empty | add *Zone → Zone → Read* to the token, or type the Zone ID |
