# Lenovo XClarity Administrator - setup for acme

XClarity Administrator (LXCA) takes **only a certificate signed for a CSR it made itself** -
Lenovo's REST reference: the certificate uploaded *must have been created from the certificate
signing request*; no private key and no PKCS#12 can be imported. So **LXCA makes the key**: at
every issue and renewal acme asks it for a new key and CSR over its REST API
(`POST /certificateSigningRequest`), has the CSR signed by the certificate's source, adds the CA
certificates to LXCA's trust store and uploads the certificate right away
(`POST /serverCertificate/tmp`). The key never leaves LXCA; acme holds none. It is the
certificate of LXCA's web interface and REST API - and the one LXCA shows its managed devices
and XClarity Orchestrator.

**This version** is for **LXCA 3.x and 4.x** (checked against LXCA 4.3) - the calls are the
same. LXCA 4.0 and later restart the web server after the upload and end every session.
XClarity Orchestrator and XClarity One are not covered: Lenovo documents their server
certificate only in their web interfaces.

## What you need

- From acme to LXCA: **TCP 443** (HTTPS, REST API with Basic authentication).
- An LXCA account for acme in the role group **LXC-SECURITY-ADMIN** (below).
- A source that signs a CSR made elsewhere - acme's own authority or an enterprise CA is the
  usual choice: LXCA wants **both EKUs, Server Authentication and Client Authentication**
  (it proves itself to its devices with the certificate too), Key Usage *Digital Signature,
  Key Encipherment, Key Agreement*, SHA-256 or SHA-384. Public ACME CAs no longer issue client
  authentication. Not *Self-signed*.
- The names: the name LXCA reaches its devices by first (the common name), its FQDN and its
  IP address (an IP is put in the CSR as an IP address).
- The key: LXCA makes an **RSA** key, **2048** or **3072** bits by its cryptographic mode (no
  ECDSA) - give the certificate one of these key types; acme cannot choose it.
- **Before the first change:** managed devices online and trusted (*Hardware → Servers /
  Chassis*, no *Offline* or *Untrusted*), their firmware current.

## Set up LXCA

1. A local user in the role group **LXC-SECURITY-ADMIN** (*Administration → Security → Users
   and Groups → Local Users → Create*), or a custom role made from `lxc-security-admin`
   (*Administration → Security → Roles → Create*). Over the REST API, as a supervisor:

   ```sh
   curl -k -u admin:'<admin password>' -X POST https://lxca.example.local/userAccounts \
     -H 'Content-Type: application/json' \
     -d '{"userName":"svc-cert","userPw":"<password>","description":"acme certificates","groups":["LXC-SECURITY-ADMIN"],"PasswordChangeFirstAccess":false}'
   ```

2. The REST API is always on - nothing to switch on.
3. If the CA is new to LXCA, acme adds its root and intermediates to **Trusted Certificates**
   before the upload (the deployment option, on by default); LXCA then hands the CA out to its
   managed devices in a job.

## Fill in acme

The target (**Targets → Add → Lenovo XClarity Administrator**):

| acme field | What to put there |
|---|---|
| Address | LXCA's name or IP, e.g. `lxca.example.local` |
| HTTPS port | `443` |
| User / Password | The account from step 1 (`svc-cert`) |
| Country, State, City, Organization | What LXCA puts in every CSR (it asks for them); the certificate's own subject (its profile) wins |
| Unit | Optional |
| Check the device's certificate | Off for the first issue (LXCA still has its own certificate), on afterwards |

Then the certificate: **Add a certificate** → in the step **Key** choose **Key made by the
device** → pick this target (or, in the target's window, **Make its certificate**). Its names:
LXCA's FQDN and its IP address. Key type: RSA 2048 (or RSA 3072 in NIST strict mode). acme
makes the deployment to LXCA by itself; it runs right after each issue. From the command line:

```sh
acme --cert-add lxca --names lxca.example.local,10.0.0.60 --issuer "Internal CA" --key-type rsa-2048 --csr-from lxca
acme --renew lxca
```

The deployment's options: **Add the CA certificates to the trust store** (on: the root and
each intermediate go to *Trusted Certificates* first, as Lenovo asks) and **Root CA
certificate** - the root the chain ends in, when the chain does not carry it: LXCA wants the
whole chain, root included.

## Check it

- **Test** on the target signs in and reads the server certificate - nothing is changed.
- **Renew now** on the certificate: the job says *the key and the CSR are made by the device*,
  the issue, the trust store and the upload. LXCA restarts its web server (sign in again in the
  browser); the tests after the deployment wait for it.

  ```sh
  openssl s_client -connect lxca.example.local:443 -servername lxca.example.local -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  curl -k -u svc-cert:'<password>' https://lxca.example.local/serverCertificate/details
  curl -k -u svc-cert:'<password>' https://lxca.example.local/trustedCertificates/details
  ```

  In LXCA: *Hardware → Servers* - no device *Offline* or *Untrusted*.

## Common problems

| Problem | Fix |
|---|---|
| `401` | Wrong user or password. |
| `403` | The account is not in LXC-SECURITY-ADMIN (or LXC-SUPERVISOR). |
| `LXCA makes RSA keys only` | Give the certificate the key type RSA 2048 or 3072. |
| `LXCA did not take the certificate` | It was not signed for LXCA's last CSR (a CSR made by hand since drops the key) - **Renew now**; or the EKU *Client Authentication* is missing, or ECDSA / RSA-PSS / SHA-1 is used. |
| `no root CA certificate` (a warning) | Give the root in the deployment's option *Root CA certificate*. |
| Devices turn *Untrusted* / *Offline* after the change | The CA job failed for them: put them right, then resume the installation in LXCA (*Administration → Security → Server Certificate*). |
| XClarity Orchestrator over LXCA stops working | LXCA's certificate needs both EKUs, and Orchestrator must trust the new CA. |
| Deployments held | LXCA keeps its old certificate; the next issue asks it for a new key and CSR. |
