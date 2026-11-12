# INWX - setup for acme

acme proves names by DNS-01 in a domain whose DNS is at INWX. It uses the INWX JSON-RPC API (DomRobot, `https://api.domrobot.com/jsonrpc/`): it signs in with `account.login` (and `account.unlock` with a TOTP code when the account has two-factor sign-in), lists the domains (`nameserver.list`), adds one TXT record per value (`nameserver.createRecord`) and deletes that record by its id (`nameserver.deleteRecord`). Other values at the same name stay.

## What you need

- A domain at INWX using INWX's name servers.
- HTTPS (TCP 443) from acme to `api.domrobot.com` (or `api.ote.domrobot.com` for INWX's test system).
- Best: an extra INWX user for acme **without two-factor sign-in**.

## Set up INWX

1. Sign in at `www.inwx.com` with the main account.
2. Go to **Account → Account access** (extra users / sub-accounts) and create a new user for acme.
3. Give that user **DNS rights only** (nameserver / DNS management); no domain transfer, contact or billing rights.
4. Leave **two-factor sign-in off** for that user. If you must use an account with 2FA, keep the **base32 secret** shown when 2FA was set up (the text under the QR code) - acme computes the 6-digit codes from it. A one-time 6-digit code is of no use.
5. Set a long random password.

**Warning:** a two-factor secret is as powerful as the password - give it only for an account limited to DNS.

## Fill in acme

| acme field | What to put there |
|---|---|
| User name | the extra INWX user |
| Password | its password |
| Two-factor secret | empty, or the base32 2FA key (not a 6-digit code) |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 300 (INWX takes nothing lower; advanced) |
| Endpoint | `api.domrobot.com`; `api.ote.domrobot.com` only for INWX's test system (advanced) |

## Check it

- In acme press **Test**: it signs in, lists the domains and signs out; no record is changed.
- After an order: INWX → **Domains → Nameserver (DNS)** → the domain: the `_acme-challenge` TXT record appears and is removed again.

```sh
dig +short TXT _acme-challenge.www.example.com @ns.inwx.de
```

## Common problems

| Problem | Fix |
|---|---|
| Code 2200 / "authentication error" | Wrong user or password, or the user is locked after too many tries (wait, then retry). |
| Sign-in asks for a TAN / two-factor | Give the *Two-factor secret*, or use a user without 2FA. |
| Wrong 2FA code although the secret is right | acme's clock is off - TOTP needs the time correct to about 30 s (check NTP). |
| Code 2303 "object does not exist" | The domain is not in this account, or not on INWX's name servers. |
| Permission error on `createRecord` | The extra user has no DNS rights for that domain. |
