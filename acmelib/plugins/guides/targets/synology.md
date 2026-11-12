# Synology DSM - setup for acme

acme signs in to the DSM web API (`SYNO.API.Auth`, session `Certificate`) and imports the
certificate, key and intermediates with `SYNO.Core.Certificate` `import`. It **replaces the
certificate with the same description** each time, so the services you assigned to it
(DSM, Synology Drive, WebDAV, reverse proxy...) keep it. It can make it the default
certificate; one that is already the default stays the default.

For DSM 6.2 and DSM 7.x. The sign-in call is documented by Synology; the certificate calls
are unofficial (as used by acme.sh) and work on current DSM.

## What you need

- Network access from acme to DSM over HTTPS: **TCP 5001** (or your DSM HTTPS port).
- A DSM user in the **administrators** group **without 2-step verification** (acme does
  not support it).

## Set up DSM

1. Create a dedicated user: **Control Panel → User & Group → User → Create**, e.g.
   `acme`, a strong password.
2. Add it to the **administrators** group (DSM allows certificate import only to
   administrators). In the same wizard you can deny it access to shared folders and
   applications it does not need.
3. Make sure 2-step verification is **not** enforced for it (**Control Panel → Security →
   Account → 2-Factor Authentication**: not enforced for this user / group).
4. If you use **Control Panel → Security → Firewall** or *Auto Block*, allow / whitelist
   the acme server's IP for the DSM HTTPS port.
5. Optional, first run: leave *Make it the default certificate* off, deploy once, then in
   **Control Panel → Security → Certificate → Settings** assign the new certificate
   (`acme <name>`) to the services you want. Later renewals replace it in place.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The NAS name or IP, e.g. `nas.example.local` |
| HTTPS port | `5001` |
| User / Password | The `acme` user |
| Check the device's certificate | On; off only while DSM still has its self-signed certificate |
| CA certificate (advanced) | The CA of DSM's current certificate, if not public |
| Description on the NAS (deploy) | The certificate's description acme replaces each time; empty: `acme <name>` |
| Make it the default certificate (deploy) | On to make it DSM's default |
| Check what is served | e.g. `nas.example.local:5001` |

**Do not change the description** after the first deployment, or acme imports a new
certificate instead of replacing the assigned one.

## Check it

- Press **Try** on the target: acme signs in and lists the certificates, answering
  `signed in to ..., N certificates`.
- In DSM: **Control Panel → Security → Certificate** shows `acme <name>` with the new expiry
  date.

## Common problems

| Problem | Fix |
|---|---|
| `DSM said error 400` on signing in | Wrong user or password. |
| `DSM said error 403` / `406` | 2-step verification is on for the user - turn it off for `acme`. |
| `DSM said error 402` / permission error | The user is not in *administrators*. |
| Sign-in blocked after failures | *Auto Block* blocked acme's IP - unblock and allow-list it. |
| Services keep the old certificate | They are assigned to another certificate - assign `acme <name>` once in *Settings*. |
