# Vercel DNS - setup for acme

acme proves names by DNS-01 in a domain that uses **Vercel DNS**, through Vercel's REST API (`https://api.vercel.com`, bearer token; `?teamId=…` for a team's domains). It lists the domains (`/v5/domains`), reads the records (`/v4/domains/{domain}/records`), adds one TXT record per value (`POST /v2/domains/{domain}/records`) and deletes that record by its id. Other values at the name stay.

## What you need

- The domain in your Vercel account or team, with Vercel's name servers (`ns1.vercel-dns.com`, `ns2.vercel-dns.com`).
- HTTPS (TCP 443) from acme to `api.vercel.com`.

## Set up Vercel

1. Sign in at `vercel.com`.
2. **Account Settings → Tokens → Create**:
   - name `acme`;
   - **Scope**: the **team** that holds the domains (or your personal account);
   - an expiration that suits you (a token that expires must be replaced in acme in time).
3. Copy the token - it is shown once.
4. For a team's domains, copy the **Team ID**: the team → **Settings → General → Team ID** (`team_…`).

**Warning:** a Vercel token has your full rights in its scope (projects, deployments, domains) - Vercel has no DNS-only token. Scope it to the one team that holds the domains.

Optional check:

```sh
curl -H 'Authorization: Bearer TOKEN' 'https://api.vercel.com/v5/domains?teamId=team_…'
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Access token | the token |
| Team ID | `team_…` for a team's domains; empty for your own |
| Domain | empty (the longest domain the token sees that the name is in), or the domain |
| TTL (s) | 60 (advanced) |
| API address | `https://api.vercel.com` (advanced) |

## Check it

- In acme press **Test**: it lists the domains the token sees; nothing is changed.
- After an order: the team → **Domains →** the domain → **DNS Records**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| `403` "forbidden" / "not_authorized" | The token is scoped to another team, or *Team ID* is missing / wrong. |
| Domain not found | The domain uses other name servers (not Vercel DNS), or belongs to another team. |
| `401` after a while | The token expired - create a new one. |
