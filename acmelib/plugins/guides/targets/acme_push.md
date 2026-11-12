# Applications of ours (acme push) - setup for acme

acme puts the certificate on another application of the same family - **otp, isemon,
zigmon or another acme** - through that application's own **Settings → Certificates and
TLS → Certificates from acme**. It talks HTTPS to the application's administration pages;
every request is signed with acme's Ed25519 key and the private key travels sealed to the
application (X25519 + HKDF-SHA256 + AES-256-GCM). The certificate goes into the *slots*
you name: each node's pages, the VIP address's, a server in front, a broker.

For application versions that have *Certificates from acme* (acme push protocol 1).

## What you need

- The application's administration reachable from acme over **HTTPS** (normally TCP 443),
  for example `https://otp.example.com/admin/` or `https://isemon.example.com/`.
- **acme's address allowed to reach that administration**: the application's own access
  list for its administration pages (the nginx `allow` lines) applies to acme too.
- An administrator of the application, to switch the feature on and make a pairing code.

## Set up the application

1. Sign in to the application's administration.
2. Open **Settings → Certificates and TLS → Certificates from acme** and switch on
   **Take certificates from acme**.
3. Make sure acme's IP address is among the addresses allowed to the administration
   pages (the application's access settings).
4. Click **Pair with an acme**. A one-time code like `ABCD-EFGH-JKMN-PQRS` is shown -
   valid **15 minutes, once**. Copy it.
   - Alternative: paste **acme's key** there (*Or paste acme's key*). acme's **Try**
     prints it when not paired; it looks like `acme-push-ed25519 BASE64... comment`.
     This way needs *Check the application's certificate* on in acme.
5. Optional: allow **Take certificates of other names** only if you really want to push
   a certificate that does not hold the slot's names.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address of its administration | As opened in a browser: `https://NAME/admin/` for otp and acme, `https://NAME/` for isemon and zigmon |
| Pairing code | The code from step 4; needed only for the first **Try** (pairing) |
| Check the application's certificate | On; off only while it still has a self-signed certificate (the pairing code still proves who answers) |
| CA certificate (advanced) | The CA of the application's current certificate, when not public |
| Timeout (s) (advanced) | Default 30 |
| Slots (deploy) | `auto` (each slot whose names the certificate holds), `nodes`, `vip`, `this`, or slot ids from **Discover** such as `node:otp1`, `vip`, `front`, `broker` - one a line |
| The certificate must hold the slot's names (deploy, advanced) | On; off is taken only where the application allows other names |

Command line example:

```sh
acme --target-add otp --kind acme_push --set url=https://otp.example.com/admin/ --set pair_code=ABCD-EFGH-JKMN-PQRS
acme --deploy-add otp.example.com otp --set slots=auto
```

## Check it

- **Try** says hello, pairs (when a code is given) and reads the inventory - nothing is
  changed. It answers like `otp 1.2 answers, paired (code); slots: ...`.
- **Discover** lists the application's slots, the names each must hold and what it has
  now, and can create the certificates and deployments for them.
- In the application, *Certificates from acme* shows *Paired with* and the slots.
- Attach an HTTPS test to the application's address to check what is served after a
  deployment.

## Common problems

| Problem | Fix |
|---|---|
| `... does not speak acme push (HTTP 404)` | Wrong address: use the administration URL (`/admin/` for otp and acme) |
| `... takes no certificates from acme` | Switch on *Take certificates from acme* in the application |
| Cannot be reached / HTTP 403 | acme's address is not allowed to the administration pages |
| `not paired yet` | Make a pairing code and put it in *Pairing code*, or paste acme's key there |
| `the first pairing without a pairing code needs "Check the application's certificate" on` | Use a pairing code, or turn the check on |
| `... is not the one paired (its keys changed ...)` | The application was set up again: make a new pairing code and **Try** again |
| Code refused | It expired (15 minutes), was used, or was mistyped 5 times - make a new one |
| The certificate lacks the slot's names | Add the names to the certificate, or allow other names in the application |
