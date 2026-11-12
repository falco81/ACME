# Linode (Akamai Cloud) - setup for acme

acme proves names by DNS-01 in a domain of Linode's DNS Manager (now Akamai Cloud), through API v4 (`https://api.linode.com/v4/domains`). It lists the domains, adds one TXT record per value at `_acme-challenge.NAME` and deletes that record by its id afterwards. Other values at the same name stay.

## What you need

- The domain in **Domains** of your Linode / Akamai Cloud account, with the registrar pointing at Linode's name servers (`ns1.linode.com` … `ns5.linode.com`).
- HTTPS (TCP 443) from acme to `api.linode.com`.

## Set up Linode

1. Sign in at `cloud.linode.com`.
2. Click your user name (top right) → **API Tokens** → **Create a Personal Access Token**.
3. *Label* `acme`; *Expiry* as you like (a token that expires must be replaced in acme in time).
4. Set **Domains** to **Read/Write** and every other scope to **No Access**.
5. **Create Token** and copy it - it is shown only once.

Optional check:

```sh
curl -H 'Authorization: Bearer TOKEN' https://api.linode.com/v4/domains
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Personal access token | the token from step 5 |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 300 (Linode rounds to the values it knows, 300 at least; advanced) |

## Check it

- In acme press **Test**: it lists the domains the token sees; no record is changed.
- After an order: **Domains →** the domain: the `_acme-challenge` TXT record appears and is removed again.

```sh
dig +short TXT _acme-challenge.www.example.com @ns1.linode.com
```

## Common problems

| Problem | Fix |
|---|---|
| `401 Invalid Token` | Token wrong or expired - create a new one. |
| `403` / "Unauthorized" on create | The token has Domains *Read Only* - it needs **Read/Write**. |
| Domain not found | The domain is in another Linode account, or not added under Domains. |
| CA does not see the record | Linode's name servers update every few minutes; keep the propagation check on. |
