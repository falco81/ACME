# AVM FRITZ!Box - setup for acme

acme uploads the certificate of the FRITZ!Box's own web pages - which the box also uses for MyFRITZ!/remote access and VPN - the same way the box's own page does it: it signs in through `login_sid.lua` (the PBKDF2 challenge of FRITZ!OS 7.24 and later, or the old MD5 one), posts the key and the full chain to `/cgi-bin/firmwarecfg`, and signs out. When the box already serves the certificate, nothing is uploaded.

## What you need

- A FRITZ!Box with FRITZ!OS 7.x (7.24 or later recommended; older FRITZ!OS takes **RSA keys only** - issue the certificate with an RSA key there).
- HTTPS access from acme to the box: usually from the home network to `fritz.box` (or its LAN IP) port 443. From the internet only if remote access over HTTPS is enabled (then use its port, e.g. the MyFRITZ! port).
- A FRITZ!Box user for acme.

## Set up the FRITZ!Box

1. Sign in to the FRITZ!Box user interface (`https://fritz.box`) as an administrator.
2. Go to **System → FRITZ!Box Users → Add User**:
   - **User name**: `acme`, a strong **password**;
   - rights: tick **FRITZ!Box settings** only (no NAS, Smart Home, VPN or other rights are needed);
   - access from the internet is not needed when acme is in the home network.
3. Turn off the extra confirmation for this user's settings changes: in **System → FRITZ!Box Users → Login to the Home Network**, the option to confirm the execution of certain settings and functions additionally (by pressing a button or a phone code) must be **off** - acme cannot press a button on the box. **This lowers the protection of settings changes; keep the `acme` password strong.** (The exact wording differs between FRITZ!OS versions.)
4. Apply the settings (the box may ask you to confirm this change once by pressing a button).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | `fritz.box` or the box's LAN IP |
| HTTPS port | 443 (or the remote-access HTTPS port, when acme reaches it from the internet) |
| User | `acme` |
| Password | its password |
| Check the device's certificate | off for the first run while the box has its self-signed certificate (or give its CA); on afterwards |
| CA certificate (advanced) | the CA of the box's current certificate, when not public |
| Check what is served | `fritz.box:443` (or your MyFRITZ! name and port), one a line |

## Check it

- **Test** in acme signs in to the box (a wrong password is reported, with the block time when the box blocks sign-ins).
- After a deployment, open `https://fritz.box` in a browser and look at the certificate, or:

```sh
openssl s_client -connect fritz.box:443 -servername fritz.box </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate
```

- On the box, **Internet → Permit Access → FRITZ!Box Services** shows the certificate in use for remote access (in recent FRITZ!OS).

## Common problems

| Problem | Fix |
|---|---|
| `the FRITZ!Box gave no challenge` | the address is not a FRITZ!Box or a proxy is in the way |
| `does not let acme in: wrong user or password (it blocks sign-ins for N s)` | fix the user/password; wait for the block time - every failed try makes it longer |
| `the FRITZ!Box did not take the certificate` | older FRITZ!OS needs an RSA key; or the extra confirmation of settings changes is still on |
| Upload seems to work, old certificate stays | the confirmation by button is on - turn it off for the user (step 3) |
| TLS error on the next run | turn *Check the device's certificate* back on only once the box serves the new certificate whose name matches *Address* |
