# Own certificate authority - setup for acme

The **Own certificate authority** source has a certificate signed at once by one of acme's own certification authorities (Settings → Authorities): for internal names (`*.corp.local`), private IP addresses, devices and clients, servers that must not appear in Certificate Transparency. Nothing leaves acme - the authority, its key and the signing are all inside. The counterpart to set up is **every client that must trust the certificates**: they need the authority's root.

## What you need

- An authority in acme: Settings → Authorities (needs the `fulladmin` role). The intended shape is a root (signs only intermediates) and an issuing intermediate under it that signs the servers.
- A way to put the root certificate into the trust stores of the clients: Group Policy, MDM, configuration management, the Java truststore.
- Where clients check revocation: the CRL address put into the certificates must be reachable by them (acme publishes CRLs at `http://<acme>/pki/` when *Publish on acme* is on).

## Set up the authority and the clients

1. In acme, Settings → Authorities → make a **root** (e.g. `ec-384`, 10-20 years, path length 1), then an **issuing CA** with the root as *Parent* (path length 0). Add *Name constraints* (e.g. `corp.example`, `IP:10.0.0.0/8`) to limit what it may sign. Or make the intermediate *under a CA elsewhere* (your AD CS root) - then nothing new has to be trusted.
2. Download the root's certificate (the authority → `cert` / `cert-der`) and distribute it:

   ```powershell
   # one Windows machine (Group Policy: Computer Configuration → Policies → Windows Settings →
   # Security Settings → Public Key Policies → Trusted Root Certification Authorities → Import)
   Import-Certificate -FilePath .\corp-root.cer -CertStoreLocation Cert:\LocalMachine\Root
   ```

   ```sh
   cp corp-root.pem /etc/pki/ca-trust/source/anchors/ && update-ca-trust          # RHEL family
   cp corp-root.pem /usr/local/share/ca-certificates/corp-root.crt && update-ca-certificates   # Debian
   keytool -importcert -cacerts -alias corp-root -file corp-root.pem              # Java
   ```

3. Servers must send the **intermediate** with their certificate (acme puts the chain with it; deploy the full chain).
4. Allow clients to reach the CRL / CA certificate addresses (HTTP to acme, port 80) where they check revocation.

## Fill in acme

Sources → **Add** → **Own certificate authority**.

| acme field | What to put there |
|---|---|
| Certificate authority | the authority that signs - the issuing intermediate, not the root |
| Validity (days) | `397` (default); never past the end of the authority itself |
| Extended key usage (advanced) | `serverAuth`, `clientAuth` (default); `codeSigning`, `emailProtection` or an OID |

Wildcards, IP addresses, RSA and ECDSA keys are allowed. *Certificates → Import from a source* lists what the authority signed.

## Check it

- Sources → the source → **Test** (Try it).
- On a client that has the root:

```sh
openssl verify -CAfile corp-root.pem -untrusted issuing-ca.pem server.pem
openssl s_client -connect www.corp.example:443 -servername www.corp.example </dev/null | grep 'Verify return code'
```

## Common problems

| Problem | Fix |
|---|---|
| `unable to get local issuer certificate` on a client | the root is not in the client's store, or the server does not send the intermediate |
| A name is refused before signing | it is outside the authority's *Name constraints* |
| The validity is shorter than asked | it is cut at the end of the authority; renew the authority in time |
| Browsers refuse a long-lived certificate | keep server certificates at most 397 days |
| Revocation check fails on clients | the CRL address is not reachable from them (port 80 to acme, or a CRL address of your own) |
