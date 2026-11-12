# Cloudflare custom certificate - setup for acme

acme uploads the certificate as a **custom certificate** of a Cloudflare zone (`POST
/zones/<id>/custom_certificates`) and on each renewal **replaces it** (`PATCH
.../custom_certificates/<id>`), which Cloudflare swaps on its edge without a gap. For
`sni_custom` the PATCH returns a **new id** and deletes the previous one; acme keeps the
new id for the next renewal. A certificate acme does not know yet is found by its names.

For zones on the **Business or Enterprise** plan, or with the **Advanced Certificate
Manager** add-on - custom certificates are not available otherwise.

## What you need

- A Cloudflare zone with custom certificates available (see above).
- Outbound HTTPS from acme to `api.cloudflare.com` (TCP 443), directly or through the
  proxy.
- An **API token** (not the Global API Key) scoped to that zone.

## Set up Cloudflare

1. **My Profile → API Tokens → Create Token → Create Custom Token**.
2. Permissions:
   - **Zone → SSL and Certificates → Edit**
   - **Zone → Zone → Read** (only needed when you give the zone by its name)
3. **Zone Resources → Include → Specific zone →** your zone (e.g. `example.com`).
4. Optionally **Client IP Address Filtering**: allow only the acme server's public IP.
5. Create, copy the token (shown once). Test it:

   ```sh
   curl -s -H "Authorization: Bearer <token>" https://api.cloudflare.com/client/v4/user/tokens/verify
   ```

6. The zone's ID is on the zone's **Overview** page (right column, *API → Zone ID*).

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | The token from step 5 |
| Zone | The zone's name (`example.com`) or its zone ID (32 hex characters) |
| Through the proxy (advanced) | On by default: out through Settings → Proxy |
| Chain (deploy) | `as acme gives it (force)` (default), `ubiquitous` or `optimal` |
| Served to (deploy, advanced) | `clients with SNI (sni_custom)` (default) or `every client (legacy_custom)` |
| Check what is served | e.g. `www.example.com:443` |

## Check it

- **Try**: `signed in: zone example.com (Business plan), N custom certificates`.
- In Cloudflare: **SSL/TLS → Edge Certificates** lists the custom certificate and its
  expiry.

  ```sh
  openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null | openssl x509 -noout -issuer -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| 403 / `Authentication error` | The token lacks *SSL and Certificates → Edit*, or is not for this zone |
| Zone not found by name | Add *Zone → Zone → Read*, or give the zone ID |
| Custom certificates not allowed | The zone is on Free/Pro without Advanced Certificate Manager |
| Cloudflare's own certificate still served | Universal/advanced certificates may have priority for some hosts - check Edge Certificates |
| `Chain` errors on upload | Try `ubiquitous` so Cloudflare builds the chain |
| Blocked by IP filtering | Add acme's current public IP to the token's filter |
