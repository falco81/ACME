# Smallstep step-ca (JWK provisioner) - setup for acme

The **Smallstep step-ca (JWK provisioner)** source asks step-ca for certificates by its own API, without ACME validation - for internal names ACME cannot prove. Each request (`POST /1.0/sign`) carries the CSR acme made and a **one-time token**: a JWT signed with a JWK provisioner's private key (`iss` the provisioner, `aud` `https://<ca>/1.0/sign`, `sub` the first name, `sans` all names, valid 5 minutes, the root's fingerprint). Revocation is `POST /1.0/revoke` the same way. **The certificate's private key never leaves acme.** For step-ca with an ACME provisioner use the ACME source (*Another ACME server*) instead.

## What you need

- step-ca reachable **from acme** over HTTPS (often port `9000` or `443`).
- A **JWK provisioner** for acme and its private key, decrypted.
- step-ca's root certificate (`root_ca.crt`).
- The `step` CLI on a machine with admin access to the CA, to make the provisioner.

## Set up step-ca

1. Add a JWK provisioner for acme (it asks for a password that encrypts the key):

   ```sh
   step ca provisioner add acme-jwk --type JWK --create
   ```

   Set its limits as your policy says, e.g. the certificate durations in `ca.json` (`claims`: `maxTLSCertDuration`, `defaultTLSCertDuration`) and, where wanted, an X.509 policy limiting the names (`--x509-allow-dns "*.example.com"` on step-ca 0.24+).
2. Reload/restart step-ca if it does not pick up the change (`systemctl restart step-ca`).
3. Get the provisioner's private key, decrypted:

   ```sh
   step ca provisioner list | jq -r '.[] | select(.name=="acme-jwk") | .encryptedKey' \
     | step crypto jwe decrypt        # asks the provisioner's password, prints the JWK
   ```

   **Keep this JWK secret** - anyone who holds it can get certificates for any name the provisioner allows.
4. Take the root: `$(step path)/certs/root_ca.crt` on the CA host, or `step ca root root_ca.crt`.

## Fill in acme

Sources → **Add** → **Smallstep step-ca (JWK provisioner)**.

| acme field | What to put there |
|---|---|
| step-ca address | `https://ca.example.local:9000` |
| Root certificate of the CA | `root_ca.crt` - step-ca's TLS is checked against it and its fingerprint goes in the token |
| Provisioner | `acme-jwk` (as `step ca provisioner list` shows) |
| Provisioner key | the decrypted JWK JSON from step 3 (EC or RSA), or a PEM key |
| Key ID (advanced) | empty: the JWK's `kid`, else asked of the CA |
| Check the CA's TLS certificate (advanced) | on |

Wildcards and IP addresses are allowed where the provisioner's policy allows them; a certificate's days become the requested validity within the provisioner's limits.

## Check it

- Sources → the source → **Test** (Try it).
- On the CA host: `step ca provisioner list` shows `acme-jwk`; `step ca health` answers `ok`.
- After issuing: `step certificate inspect cert.pem --short`.

## Common problems

| Problem | Fix |
|---|---|
| `401` / token invalid | wrong provisioner name, wrong key (not decrypted, or another provisioner's), or acme's clock is off (the token is valid 5 minutes) |
| TLS verify failed | the *Root certificate of the CA* is not step-ca's root |
| Requested duration refused | outside the provisioner's `minTLSCertDuration` / `maxTLSCertDuration` |
| A name refused | the provisioner's or authority's X.509 policy does not allow it |
| `Key ID` mismatch | leave *Key ID* empty, or copy the `kid` from `step ca provisioner list` |
