# Self-signed certificate - setup for acme

The **Self-signed** source makes a certificate signed by its own key, at once and inside acme - no CA, no account, no network. Nothing trusts such a certificate except what is told to: a client that pins its fingerprint, a test system, a device that only wants *some* certificate. For anything that must be trusted by browsers or by all machines of a company, use a public CA (the ACME source) or acme's own certification authority (the *Own certificate authority* source).

## What you need

- Nothing on the CA side - acme signs it itself.
- On every client that must accept it: a way to trust this one certificate (pinning its SHA-256 fingerprint, or adding the certificate itself to the client's trust store).
- Remember: **each renewal is a new self-signed certificate** with a new fingerprint (and with a new key, unless the certificate keeps its key) - every client that pinned the old one must be told again.

## Set up the clients

1. Make the certificate in acme (below), then download it (the certificate's window → download, PEM).
2. Give it to what must trust it, for example:

   ```sh
   # RHEL / AlmaLinux / Rocky
   cp device.example.local.pem /etc/pki/ca-trust/source/anchors/
   update-ca-trust
   # Debian / Ubuntu
   cp device.example.local.pem /usr/local/share/ca-certificates/device.example.local.crt
   update-ca-certificates
   ```

   ```powershell
   Import-Certificate -FilePath .\device.example.local.cer -CertStoreLocation Cert:\LocalMachine\Root
   ```

3. Or pin the fingerprint in the client that supports it (an API client, a monitoring check):

   ```sh
   openssl x509 -in device.example.local.pem -noout -fingerprint -sha256
   ```

4. Where many machines must trust many such certificates, prefer acme's own CA: one root to distribute, certificates renewed without touching the clients.

## Fill in acme

Sources → **Add** → **Self-signed**.

| acme field | What to put there |
|---|---|
| Validity (days) | `365` (default); a certificate's own days win |
| Extended key usage (advanced) | `serverAuth`, `clientAuth` (default); `codeSigning`, `emailProtection` or an OID where needed |

Wildcards and IP addresses are allowed; RSA and ECDSA keys (and both, as a dual certificate).

## Check it

- Sources → the source → **Test** (Try it): there is nothing to ask - it says the source is ready.
- After issuing, the certificate's issuer equals its subject:

```sh
openssl x509 -in cert.pem -noout -subject -issuer -dates -ext subjectAltName
```

## Common problems

| Problem | Fix |
|---|---|
| Browsers say *not trusted* / `self-signed certificate` | expected: trust it on the client, or use a CA |
| A client stopped working after a renewal | it pinned the old fingerprint or trusted the old certificate: give it the new one, or switch to acme's own CA |
| A client wants the CA flag or a chain | a self-signed leaf is not a CA: use the *Own certificate authority* source instead |
| `Validity (days)` too long for a client | Apple and browsers refuse server certificates longer than 398 days even when trusted - keep it at most `397` |
