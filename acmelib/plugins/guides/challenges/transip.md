# TransIP - setup for acme

acme proves names by DNS-01 in a domain at **TransIP**, through REST API v6 (`https://api.transip.nl/v6`). It signs in with `POST /v6/auth`, the request signed RSA-SHA512 with the account's **key pair** (the private key never leaves acme; openssl signs), and gets a short-lived token. Then it lists the domains, reads the DNS entries, adds one TXT entry per value and deletes exactly that entry. Other values at the name stay.

## What you need

- A domain at TransIP using TransIP's name servers.
- HTTPS (TCP 443) from acme to `api.transip.nl`.
- The public IP address acme calls from, if you whitelist it.

## Set up TransIP

1. Sign in to the TransIP **control panel**.
2. **Account → API**: switch the API **on** (*API settings: On*).
3. Optional but recommended: under **IP whitelist** add the public address acme calls from.
4. **Key pairs → Generate a new key pair**:
   - label `acme`;
   - **Accept only from whitelisted IP addresses**: on if you did step 3 (then set acme's *The key pair is not limited to whitelisted addresses* **off**), or off (leave that acme field **on**).
5. Copy the **private key** shown - it is shown **only once**. Paste it whole, including the `-----BEGIN …-----` and `-----END …-----` lines.

**Warning:** the key pair gives full API access to the TransIP account (domains, VPS, …) - TransIP has no DNS-only key. Prefer the IP whitelist.

## Fill in acme

| acme field | What to put there |
|---|---|
| Login | the TransIP account name |
| Private key | the private key (PEM), whole |
| The key pair is not limited to whitelisted addresses | on = the key works from any address; off = whitelisted addresses only - as the key pair was made (advanced) |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 60 (TransIP knows 60, 300, 3600, 86400; another is raised; advanced) |

## Check it

- In acme press **Test**: it signs in and lists the domains; nothing is changed.
- After an order: control panel → **Domains →** the domain → **DNS**: the `_acme-challenge` TXT entry appears and is removed again.

```sh
dig +short TXT _acme-challenge.www.example.nl @ns0.transip.net
```

## Common problems

| Problem | Fix |
|---|---|
| "Signature not valid" / `401` at sign-in | Login and key pair do not belong together, or the key was pasted incompletely. |
| "This key pair may only be used from whitelisted IPs" | Add acme's address to the whitelist, or set the acme field to match the key pair. |
| API refused although the key is right | The API is switched off in **Account → API**. |
| Domain not listed | The domain is in another TransIP account or uses other name servers. |
