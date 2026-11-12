# SCEP server (NDES, EJBCA, step-ca...) - setup for acme

The **SCEP (NDES, EJBCA, step-ca, ...)** source gets certificates from any CA that speaks SCEP (RFC 8894): Microsoft NDES, EJBCA, Smallstep step-ca, Cisco IOS, FortiAuthenticator, Palo Alto, Jamf, OpenXPKI. acme asks `GetCACaps` and `GetCACert`, then sends a `PKIOperation` **PKCSReq**: its own CSR with the *challenge password*, encrypted to the CA/RA certificate and signed with a short-lived self-signed certificate of the request's key. A **PENDING** answer is polled with CertPoll, and asked again at later tries. **The private key never leaves acme**; SCEP needs an **RSA** key (2048+) - no ECDSA.

## What you need

- The SCEP URL reachable **from acme** (HTTP or HTTPS, often port 80).
- A **challenge password** the CA accepts - and, for automatic renewals, one that does not expire after one use.
- The **CA certificate's fingerprint** (SHA-256): SCEP often runs over plain HTTP, and the fingerprint is what protects against someone in between.
- Certificates with an RSA key in acme.

## Set up the SCEP server

**Microsoft NDES** (Windows Server, role *Network Device Enrollment Service*):

1. The template NDES issues from is in the registry `HKLM\Software\Microsoft\Cryptography\MSCEP` (`EncryptionTemplate`, `GeneralPurposeTemplate`, `SignatureTemplate`): set them to a template with *Subject Name: Supply in the request* (a copy of *Web Server*), on which the NDES service account has Read + Enroll, published on the CA.
2. The challenge from `https://ndes.example.local/certsrv/mscep_admin` is **one-time and expires** (60 minutes by default). For automatic renewals use a fixed password:

   ```powershell
   $k = 'HKLM:\Software\Microsoft\Cryptography\MSCEP'
   New-Item "$k\UseSinglePassword" -Force | Out-Null
   Set-ItemProperty "$k\UseSinglePassword" -Name UseSinglePassword -Value 1 -Type DWord
   Set-ItemProperty "$k\UseSinglePassword" -Name Password -Value '<long random password>'
   iisreset
   ```

   (or `EnforcePassword` = 0 only on a closed network). Check the exact registry layout in Microsoft's NDES documentation for your Windows version.

**EJBCA**: System Configuration → SCEP Configuration → add an alias (RA mode, the end entity / certificate profiles); the URL is `.../ejbca/publicweb/apply/scep/<alias>/pkiclient.exe`; the challenge is the end entity's enrollment code (or the alias's RA authentication password).

**step-ca**: a SCEP provisioner with a challenge:

```sh
step ca provisioner add scep-acme --type SCEP --challenge '<secret>'
```

URL `https://ca.example.local/scep/scep-acme`.

The fingerprint of the CA certificate:

```sh
curl -s 'http://ndes.example.local/certsrv/mscep/mscep.dll/pkiclient.exe?operation=GetCACert' -o ca.p7b
openssl pkcs7 -inform DER -in ca.p7b -print_certs | openssl x509 -noout -fingerprint -sha256
```

(NDES sends the RA certificates too - take the CA's.)

## Fill in acme

Sources → **Add** → **SCEP (NDES, EJBCA, step-ca, ...)**.

| acme field | What to put there |
|---|---|
| SCEP address | NDES `https://ndes.example.local/certsrv/mscep/mscep.dll`; EJBCA `.../ejbca/publicweb/apply/scep/<alias>/pkiclient.exe`; step-ca `https://ca.example.local/scep/<provisioner>` |
| Challenge password | NDES: the fixed password (or one from `mscep_admin`); EJBCA: the enrollment code; step-ca: the provisioner's challenge |
| CA fingerprint | SHA-256 of the CA certificate - **set it** |
| CA identifier (advanced) | where one server hosts several CAs (EJBCA: the CA name) |
| Encryption / Digest (advanced) | *As the CA says*; 3DES / SHA-1 only for old servers |
| CA certificate of the web server / Check the web server's TLS certificate (advanced) | for HTTPS with a private CA |
| Wait for approval (s) / Ask again every (s) (advanced) | `60` / `10` |

## Check it

- Sources → the source → **Test** (Try it): GetCACaps and GetCACert, the CA checked against the fingerprint.
- By hand: `curl 'http://ndes.example.local/certsrv/mscep/mscep.dll/pkiclient.exe?operation=GetCACaps'`.

## Common problems

| Problem | Fix |
|---|---|
| `... badRequest` | the challenge password is wrong, used or expired; or the CA does not allow the names |
| `... badMessageCheck` | the server could not check the signature or decrypt - the RA certificate changed? |
| `... badAlg` | choose 3DES / SHA-1 under the advanced settings (old servers) |
| `... badTime` | acme's clock |
| the CA certificate is not the one of the fingerprint | someone in between, or the CA was renewed: compare and set the new fingerprint |
| SCEP needs an RSA key | set the certificate's key type to RSA |
| Renewals fail on NDES, the first one worked | the one-time password expired: use `UseSinglePassword` |
