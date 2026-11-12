# Mail-in-a-Box - setup for acme

acme proves names by DNS-01 in the DNS that a **Mail-in-a-Box** server serves itself (its nsd), through the box's control panel API (`https://BOX/admin`). It reads the zones (`GET /admin/dns/zones`), adds a TXT value with `POST /admin/dns/custom/{qname}/TXT` (next to the values already there) and removes exactly that value with `DELETE` and the value as the body. The box then rewrites its zone files and reloads nsd; it keeps the TTL itself.

## What you need

- A Mail-in-a-Box server that is the authoritative DNS for the domain (its "box" name servers set at the registrar).
- HTTPS (TCP 443) from acme to the box.
- An **administrator account without two-factor sign-in** (basic authentication cannot carry a TOTP code).

## Set up Mail-in-a-Box

1. Sign in to the control panel `https://box.example.com/admin` as an administrator.
2. **Mail → Users → Add a mail user**: e-mail such as `acme@example.com`, a long random password, privilege **Administrator**.
   (The control panel API is open to administrators only; there is no DNS-only role.)
3. Do **not** enable two-factor authentication (**System → Two-Factor Authentication**) for this user.
4. Optional: if you do not want mail for that address, simply never use its mailbox.

**Warning:** this user is a full administrator of the box - keep its password only in acme.

Check that the API answers:

```sh
curl -u 'acme@example.com:PASSWORD' https://box.example.com/admin/dns/zones
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Box address | `box.example.com` (or `https://box.example.com`) |
| Administrator e-mail | `acme@example.com` |
| Password | its password |
| Zone | empty (the longest zone of the box the name is in), or the zone |
| Check the server's certificate | on (the box has its own Let's Encrypt certificate; advanced) |

## Check it

- In acme press **Test**: it signs in and lists the box's zones; nothing is changed.
- After an order: control panel → **System → Custom DNS**: the `_acme-challenge` TXT record appears and is removed again.

```sh
dig +short TXT _acme-challenge.www.example.com @box.example.com
```

## Common problems

| Problem | Fix |
|---|---|
| `401` / "invalid-credentials" | Wrong e-mail or password. |
| "missing-totp-token" | The user has two-factor sign-in - use an administrator without it. |
| `403` | The user is not an administrator. |
| Zone not found | The domain is not served by this box (add a user or alias at that domain so the box creates its zone). |
