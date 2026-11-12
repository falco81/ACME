# DirectAdmin - setup for acme

acme replaces the TLS certificate of a **DirectAdmin domain**. It signs in with HTTP basic
authentication and a **login key**:

- **The new API** (`/api/domain-tls`, or `/api/admin-domain-tls` as an administrator):
  it lists the domain's certificate slots, picks the slot (the one set, the only one, or
  the one whose names cover the certificate), checks the files with a **dry run**, then
  replaces them in place and - by default - puts the domain on the ACME skip list so
  DirectAdmin's own ACME (Let's Encrypt) leaves it alone.
- **The legacy API** (older DirectAdmin): `CMD_API_SSL` with `type=paste`, then the CA
  certificate (`type=cacert`).

DirectAdmin reloads the web server itself. There are no older copies to clean up: the
slot is replaced.

For DirectAdmin with the new API (recent 1.6x releases) or, with *legacy*, older ones.

## What you need

- HTTPS from acme to DirectAdmin's port, **2222** by default.
- The domain already exists in DirectAdmin and, for the new API, **has a certificate slot**
  (a certificate made once in DirectAdmin - acme replaces a slot, it does not make one;
  otherwise use the legacy API).
- A login key of the domain's user, or of an admin / reseller acting for that user.

## Set up DirectAdmin

1. Sign in as the domain's user (or the admin / reseller who will act for the user).
2. Open **Login Keys** (user level: *Advanced Features → Login Keys*; admin: in the
   account menu) → **Create Key**.
3. Key name `acme`, a long random key value, an expiry if you want one, and **Allowed IPs**:
   the acme server's address. Where the form lets you restrict commands, allow only what
   acme uses (legacy: `CMD_API_SSL`); check that the new API is reachable with the key
   (**Try**).
4. Make sure the domain has SSL enabled (**Account Manager → Domain Setup → the domain →
   Secure SSL**), and for the new API, that a certificate exists for it (**SSL
   Certificates**).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | The DirectAdmin server, e.g. `server.example.com` / `2222` |
| User | The domain's user, or the admin / reseller acting for them |
| Login key | The login key from step 3 (or the password) |
| Act as the user (advanced) | With an admin / reseller: the user (sign-in as `admin\|user`) |
| API | `the new API (/api/domain-tls)`, `the new API as an administrator`, or `the legacy CMD_API_SSL` |
| Check the device's certificate / CA certificate | As for every HTTPS server |
| Domain (deploy) | The DirectAdmin domain, e.g. `example.com` |
| Certificate slot (deploy) | Picked from the list (new API); empty: the only one, or the one whose names cover the certificate |
| Keep DirectAdmin's ACME off it (deploy) | On: DirectAdmin's own ACME does not replace it |
| Check what is served | e.g. `www.example.com:443` |

## Check it

- **Try**: `signed in to DirectAdmin ... as <user>` (legacy: `reached DirectAdmin ...`).
- In DirectAdmin: **SSL Certificates** of the domain shows the new certificate.

  ```sh
  openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null | openssl x509 -noout -issuer -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| `DirectAdmin does not let acme in (401/403)` | Wrong key, key expired, or acme's IP not in *Allowed IPs* |
| Too many failed logins / IP blocked | DirectAdmin's brute-force monitor blocked acme - unblock and fix the key |
| No certificate slot | Make a certificate for the domain in DirectAdmin first, or use the legacy API |
| 409 on the PUT | The certificate and key do not match or the slot is in use - see the detail |
| DirectAdmin's Let's Encrypt replaced it | Turn on *Keep DirectAdmin's ACME off it* |
| 404 on `/api/...` | Older DirectAdmin: use *API* = legacy |
