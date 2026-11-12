# DNS Made Easy - setup for acme

acme proves names by DNS-01 at DNS Made Easy: through its REST API V2.0 (`api.dnsmadeeasy.com`), each request signed with HMAC-SHA1 of the current date, it adds a TXT record `_acme-challenge.NAME` to a managed domain and deletes only its own record afterwards.

## What you need

- The domain as a **managed domain** at DNS Made Easy.
- The API key and secret key of a user with access to the domain.
- Outbound HTTPS from acme to `api.dnsmadeeasy.com` (port 443) - or `api.sandbox.dnsmadeeasy.com` for the sandbox.
- **A correct clock on the acme machine** - the request date is checked.

## Set up DNS Made Easy

1. Sign in to the DNS Made Easy control panel.
2. Best: create a dedicated user for acme (**Config → Users**, if your account has user management) with access only to the domains acme may change.
3. Sign in as that user → **Account Information** (Config → Account Information): the **API key** and **secret key** are shown there; generate them if empty.
4. If your account restricts API access by IP, allow acme's public address.

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | The API key |
| Secret key | The secret key |
| Domain | e.g. `example.com`; empty = the longest managed domain the name is in |
| TTL (s) | (advanced) Default `60` (30 at least) |
| API address | (advanced) Default `https://api.dnsmadeeasy.com/V2.0`; `https://api.sandbox.dnsmadeeasy.com/V2.0` for the sandbox |

## Check it

- **Test** in acme lists the managed domains. It changes nothing.
- After a run, ask one of the domain's name servers:

  ```sh
  dig +short NS example.com
  dig +short TXT _acme-challenge.example.com @<one of those name servers>
  ```

## Common problems

| Problem | Fix |
|---|---|
| `403` / invalid request date | The acme machine's clock is off - check NTP (`timedatectl`). |
| `403` / invalid API key | Wrong key or secret, or sandbox keys used against production. |
| The domain is not listed | The user has no access to it; or set *Domain* exactly. |
