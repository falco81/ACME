# Webglobe - setup for acme

acme proves names by DNS-01 in a domain at **Webglobe** (webglobe.cz / webglobe.sk, the Yegon group), through the Webglobe API (`https://api.webglobe.com`). It signs in (`POST /auth/login` with the login and an API key, giving a JWT), finds the domain (`GET /domains`, or by name), writes one TXT record (`POST /{domainId}/dns`) and keeps its id; cleanup deletes that id only (`DELETE /{domainId}/dns/{id}`), and only while it still is a TXT record holding acme's value at that name - never another record.

## What you need

- A domain at Webglobe using Webglobe's DNS.
- HTTPS (TCP 443) from acme to `api.webglobe.com`.
- The **public IP address** (or network) acme calls from - Webglobe refuses an API key from any other address, and a key without one.

## Set up Webglobe

1. Best: a **sub-account** for acme that sees only the domains acme needs - Webglobe administration → **My account → Users** → add a user, give it access to those domains.
2. Sign in as that login, then **My account → API keys → a new key**:
   - allow the public IP address (or network) acme calls from;
   - copy the key - it is shown **only once**.
3. Use the API key even when the account has **two-factor sign-in** (SMS, OTP, e-mail codes): a password cannot sign in from a machine then.

Find acme's public address if unsure:

```sh
curl -4 https://ifconfig.me
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Login | the e-mail of the login, e.g. `you@example.cz` |
| Sign in with | `an API key` |
| API key | the key from step 2 |
| Password | only with *the password* (an account without two-factor sign-in) |
| Domain | empty (the longest domain the name is in), or the domain, e.g. `example.cz` |
| Domain ID | only if the domain list cannot be read - the domain's numeric ID (advanced) |
| TTL (s) | 300 (advanced) |
| API / API address | `api.webglobe.com`; staging only for tests (advanced) |

## Check it

- In acme press **Test**: it signs in; with *Domain* set it counts the domain's DNS records, otherwise it lists the domains. Nothing is changed.
- After an order: Webglobe administration → the domain → **DNS**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| Error 5 (bad login) | Wrong login or API key. |
| Key refused | acme calls from an address not allowed for the key - add it under My account → API keys. |
| Codes 1034 / 24 / 1382 | Two-factor sign-in with a password - use an API key. |
| Error 51 | The account is suspended. |
| Error 3 "Access to requested module is denied" | The sub-account lacks access to that domain or its DNS. |
| Domain not found | Set *Domain* (or *Domain ID*); the sub-account may not see it. |
