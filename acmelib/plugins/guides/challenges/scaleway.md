# Scaleway - setup for acme

acme proves names by DNS-01 in a Scaleway DNS zone, through the **Domains and DNS API v2beta1** (`https://api.scaleway.com/domain/v2beta1`, header `X-Auth-Token` with an API key's secret key). It lists the DNS zones, reads TXT records at the name, and adds or deletes only its own value with `PATCH .../dns-zones/{zone}/records` (`add` / `delete` by id). A zone that is a subdomain (`dev.example.com`) is found as such.

## What you need

- The zone in **Scaleway Domains and DNS** (Scaleway's name servers), in a known project.
- HTTPS (TCP 443) from acme to `api.scaleway.com`.
- IAM rights in the Scaleway organization to create an application and a policy.

## Set up Scaleway

1. Sign in at `console.scaleway.com`.
2. **IAM → Applications → Create application**, named `acme`.
3. **IAM → Policies → Create policy**:
   - *Principal*: the application `acme`.
   - *Rule*: scope **Access to resources** → the **project** that holds the DNS zone.
   - *Permission sets*: **DomainsDNSFullAccess** (the DNS permission sets as Scaleway names them; nothing else).
4. Open the application → **API keys → Generate an API key**. Copy the **secret key** (shown only once); the access key is not needed by acme.

Optional check:

```sh
curl -H 'X-Auth-Token: SECRET_KEY' 'https://api.scaleway.com/domain/v2beta1/dns-zones?page_size=100'
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Secret key | the API key's secret key |
| Zone | empty (the longest zone the key may see that the name is in), or the zone |
| TTL (s) | 60 (advanced) |

## Check it

- In acme press **Test**: it lists the DNS zones the key sees; nothing is changed.
- After an order: console → **Domains and DNS →** the domain → **DNS zones →** the zone → **Records**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| `401` "authentication is denied" | Wrong secret key, or the access key was pasted instead. |
| `403` "insufficient permissions" | The policy is missing, scoped to another project, or lacks the DNS permission set. |
| Zone not found | The zone is in another project or organization - adjust the policy's project. |
