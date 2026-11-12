# DigitalOcean Load Balancer - setup for acme

acme uploads the certificate to DigitalOcean as a **custom certificate** under a dated
name (`POST /v2/certificates`), then reads each load balancer you list and sends it back
whole (`PUT /v2/load_balancers/<id>` - DigitalOcean replaces a load balancer as a whole)
with its **HTTPS forwarding rules** (`https`, `http2`, `http3`; not TLS passthrough; all,
or those of the entry ports you list) pointed at the new certificate. Older acme
certificates beyond *keep* are deleted; one still in use is refused and stays.

For DigitalOcean (regional) Load Balancers through the public API v2.

## What you need

- A DigitalOcean team and the load balancers (name or ID), with HTTPS forwarding rules
  already set up (acme does not create rules).
- Outbound HTTPS from acme to `api.digitalocean.com` (TCP 443), directly or through the
  proxy.

## Set up DigitalOcean

1. **API → Tokens → Generate New Token** (Personal access tokens).
2. Name it `acme`, choose an expiry, and **Custom Scopes**:
   - **certificate**: `create`, `read`, `delete`
   - **load_balancer**: `read`, `update`
   Nothing else is needed.
3. Copy the token (shown once). Test it:

   ```sh
   curl -s -H "Authorization: Bearer <token>" "https://api.digitalocean.com/v2/load_balancers?per_page=200" | head
   ```

   or with `doctl`:

   ```sh
   doctl auth init --access-token <token>
   doctl compute load-balancer list
   ```

4. Note the load balancers' names or IDs (**Networking → Load Balancers**).

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | The token from step 3 |
| Through the proxy (advanced) | On by default: out through Settings → Proxy |
| Load balancers (deploy) | One a line: the name or ID of each load balancer, e.g. `lb-www` |
| Entry ports (deploy) | One a line, e.g. `443`; empty: every HTTPS rule that is not TLS passthrough |
| Previous versions to keep (advanced) | Default 1 |
| Check what is served | e.g. `www.example.com:443` |

The action **List the load balancers** shows them and their HTTPS forwarding rules - it
changes nothing.

## Check it

- **Try**: `signed in to DigitalOcean; N load balancers`.
- In DigitalOcean or with `doctl`:

  ```sh
  doctl compute certificate list
  doctl compute load-balancer get <id> --format Name,ForwardingRules
  ```

## Common problems

| Problem | Fix |
|---|---|
| 401 `Unable to authenticate you` | Wrong or expired token |
| 403 on certificates or load balancers | A scope is missing (certificate create/read/delete, load_balancer read/update) |
| Load balancer not found | Wrong name or ID - use *List the load balancers* |
| No rule changed | The rules are TLS passthrough or other entry ports - check *Entry ports* |
| Older certificate not deleted | Still used by a load balancer; it goes later |
| Let's Encrypt certificate of DigitalOcean replaced | Expected: the rule now uses acme's custom certificate |
