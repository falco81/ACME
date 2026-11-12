# Netlify DNS - setup for acme

acme proves names by DNS-01 in a zone hosted on **Netlify DNS**, through Netlify's API v1 (`https://api.netlify.com/api/v1`) with a personal access token. It lists the DNS zones (`dns_zones`), adds one TXT record per value (`POST .../dns_zones/{id}/dns_records`) and deletes that record by its id afterwards. Other values at the same name stay.

## What you need

- The domain added to Netlify as a **DNS zone** (Netlify DNS), with the registrar pointing at Netlify's name servers (`dns1.p0X.nsone.net` …, as Netlify shows them).
- HTTPS (TCP 443) from acme to `api.netlify.com`.

## Set up Netlify

1. Sign in at `app.netlify.com` as a user who can manage the team's domains.
2. **User settings → Applications → Personal access tokens → New access token**.
3. Description `acme`; choose an expiration (or none - a token that expires must be replaced in acme in time).
4. **Generate token** and copy it - it is shown only once.

**Warning:** a Netlify personal access token has the full rights of your user (sites, deploys, DNS) - Netlify has no DNS-only scope. Consider a dedicated Netlify user that is a member only of the team holding the domain.

Optional check:

```sh
curl -H 'Authorization: Bearer TOKEN' https://api.netlify.com/api/v1/dns_zones
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Personal access token | the token |
| Zone | empty (the longest zone of the account the name is in), or the zone |
| TTL (s) | 60 (advanced) |
| API address | `https://api.netlify.com/api/v1` (advanced) |

## Check it

- In acme press **Test**: it lists the DNS zones the token sees; nothing is changed.
- After an order: **Domains →** the domain → **DNS records**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| `401 Unauthorized` | Token wrong, revoked or expired. |
| Zone not found | The domain is only a site's custom domain, not a Netlify DNS zone - add it under **Domains → Add or register domain** and use Netlify DNS. |
| Record created but the CA does not see it | The registrar still points at other name servers. |
