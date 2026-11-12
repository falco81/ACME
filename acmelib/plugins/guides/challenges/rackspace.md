# Rackspace Cloud DNS - setup for acme

acme proves names by DNS-01 in a domain at **Rackspace Cloud DNS**, through its API v1.0. It signs in at `https://identity.api.rackspacecloud.com/v2.0/tokens` with a user name and API key, takes the `rax:dns` endpoint from the service catalog, lists the domains, reads the TXT records, adds one record per value and deletes only its own. Each change is an asynchronous job: acme follows its `callbackUrl` until it is `COMPLETED` (or shows the `ERROR`).

## What you need

- A Rackspace Cloud account with the domain in **Cloud DNS** and the registrar pointing at Rackspace's name servers (`dns1.stabletransit.com`, `dns2.stabletransit.com`).
- HTTPS (TCP 443) from acme to `identity.api.rackspacecloud.com` and `dns.api.rackspacecloud.com`.

## Set up Rackspace

1. Sign in to the **Cloud Control Panel** (`login.rackspace.com` / `mycloud.rackspace.com`) as the account owner or an admin.
2. **Account → User Management → Create User**: user name `acme`, an e-mail, and product access:
   - **DNS**: **Admin** (needed to create and delete records; "Creator" may also allow it - check Rackspace's role descriptions for your account),
   - every other product: **No Access**.
3. Open the new user → **Rackspace API Key → Show** (or *Generate*), and copy it.

The API key is a long-lived secret; keep it only in acme. Removing the user or resetting its key revokes acme's access.

## Fill in acme

| acme field | What to put there |
|---|---|
| User name | `acme` |
| API key | the user's API key |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 300 (Rackspace takes nothing lower; advanced) |
| Identity address | `https://identity.api.rackspacecloud.com/v2.0` (advanced) |

## Check it

- In acme press **Test**: it signs in and lists the domains; nothing is changed.
- After an order: Cloud Control Panel → **Networking → Cloud DNS →** the domain: the `_acme-challenge` TXT record appears and is removed again.

```sh
dig +short TXT _acme-challenge.www.example.com @dns1.stabletransit.com
```

## Common problems

| Problem | Fix |
|---|---|
| `401` at sign-in | Wrong user name or API key, or the user is disabled. |
| `403` on POST/DELETE | The user's DNS role allows only reading - give it the DNS **Admin** role. |
| No `rax:dns` endpoint | The account has no Cloud DNS (e.g. a dedicated-only account). |
| Job `ERROR` | acme shows Rackspace's message - often a TTL under 300 or a name outside the domain. |
