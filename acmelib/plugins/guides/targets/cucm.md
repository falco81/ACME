# Cisco Unified Communications Manager (CUCM 14 / 15) - setup for acme

CUCM takes **only a certificate signed for a CSR it made itself**: Cisco Unified OS
Administration uploads a certificate or a chain for `tomcat` / `CallManager`, never a private
key - the key is always made on CUCM by *Generate CSR*. So **CUCM makes the key**: at every
issue and renewal acme signs in to the **platform CLI over SSH**, has CUCM make a new key and
CSR (`set csr gen tomcat`), reads it (`show csr own tomcat/tomcat.csr`), has the CSR signed by
the certificate's source and right away imports the CA certificates (`set cert import trust
tomcat-trust`) and the certificate (`set cert import own tomcat tomcat-trust/<CA>.pem`), then
restarts the unit's services. The key never leaves CUCM; acme holds none.

**Versions:** CUCM 14 and 15 with every SU (the CLI is the same). One **node** and one
**unit** a target: `tomcat` (web administration, AXL, UDS, Jabber sign-in, SAML SP),
`tomcat-ECDSA`, `CallManager` (SIP / SCCP TLS) or `CallManager-ECDSA`. Cisco documents no REST
API for these certificates that acme builds on, and a **multi-server (SAN)** certificate is
uploaded in the OS Administration GUI only (14SU2 and later) - give every node its own target.

## What you need

- From acme to every node: **TCP 22** (SSH to the platform CLI) and TCP 8443 for the test of
  what is served.
- A **platform (OS) account** of **privilege level 1** - an application user of CM
  Administration cannot sign in to the CLI.
- A source that signs a CSR made elsewhere - an ACME CA (with a DNS-01 validation for the
  node's name), acme's own authority, a commercial CA. Not *Self-signed*, CMP or SCEP. The
  CA's root and intermediates must be imported into `tomcat-trust` - acme does it.
- A maintenance window: a restart of Cisco Tomcat stops the web, AXL and Jabber sign-in of
  the node for minutes; a restart of Cisco CallManager registers its phones again.

## Set up CUCM

1. Sign in to the CLI as the platform administrator (the account made at installation,
   privilege 4) and make the account for acme - privilege **1** is enough for `set csr gen`,
   `set cert import` and `show cert` (Cisco's CLI reference):

   ```text
   admin: set account name svc-cert
   Please enter the privilege level :1
   Allow this user to be able to modify the system? (yes/no) : no
   Please enter the password : ********
   ```

   Sign in once as `svc-cert` (`ssh svc-cert@cucm-pub.example.local`) and change the password
   if CUCM asks - before acme uses the account.
2. Look at what CUCM puts into a CSR - acme needs the certificate to have **exactly these
   names** (CUCM's CLI takes no names from acme):

   ```text
   admin: set csr gen tomcat
   admin: show csr own tomcat/tomcat.csr
   ```

   ```sh
   openssl req -noout -text -in tomcat.csr | grep -A1 'Subject Alternative Name'
   ```

   Usually the node's FQDN (and the parent domain where CUCM adds it). An alternate host name
   is set once with `set web-security` (see Cisco's CLI reference - it changes what every
   later CSR holds). No wildcard; at most 4096 bits.
3. Note the root (and intermediate) CA of your source - acme imports them into
   `tomcat-trust` before the certificate. For Let's Encrypt paste **ISRG Root X1** in the
   deployment's *Root CA certificate*.

## Fill in acme

The target (**Targets → Add → Cisco Unified Communications Manager (CUCM)**):

| acme field | What to put there |
|---|---|
| Address | The node, e.g. `cucm-pub.example.local` |
| SSH port | `22` |
| User | The platform account, `svc-cert` |
| Sign in with / Password | *a password* and its password |
| Host key | The node's known_hosts line (or *Trust the first host key seen*) |
| Certificate | `tomcat` (or `tomcat-ECDSA`, `CallManager`, `CallManager-ECDSA`) |
| Time for a CLI command (s) | `600` - CUCM's CLI starts slowly, a restart takes minutes |

Then the certificate: **Add a certificate → Key → Key made by the device → pick this
target** (or, in the target's window, **Make its certificate**). Its names: exactly those of
step 2. The key type: **RSA 2048** for `tomcat` / `CallManager`, **EC** for the `-ECDSA` units.
acme makes the deployment to CUCM by itself; it runs right after each issue. From the command
line:

```sh
acme --cert-add cucm-pub --names cucm-pub.example.local --key-type rsa-2048 --issuer "Let's Encrypt" --csr-from cucm-pub
acme --renew cucm-pub
```

The deployment's options:

| Option | Meaning |
|---|---|
| Restart the services | On: `utils service restart Cisco Tomcat` and `Cisco Tftp` (tomcat), `Cisco CallManager`, `Cisco CTIManager` and `Cisco HAProxy` (CallManager). Off: you restart them; CUCM serves the old certificate until then |
| Root CA certificate | The root the chain ends in, imported into `<unit>-trust` with the intermediates |
| CA file in the trust store | Empty: the issuer found in `show cert list trust`; else e.g. `tomcat-trust/Example_Issuing_CA.pem` |

## Check it

- **Test** on the target signs in and says CUCM's version and whether the unit is there -
  nothing is changed.
- **Renew now** on the certificate: the job shows the CSR made by CUCM, the issue, the
  imports and the restarts. Then:

  ```sh
  # tomcat (RSA) - Cisco Tomcat serves tomcat-ECDSA on 8443 too, by what the client offers;
  # for tomcat-ECDSA give -sigalgs ECDSA+SHA256 (acme's test asks the same way - TLS 1.2, the unit's key)
  openssl s_client -connect cucm-pub.example.local:8443 -servername cucm-pub.example.local -tls1_2 -sigalgs RSA+SHA256 -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

  ```text
  admin: show cert list own
  admin: show cert own tomcat/tomcat.pem
  admin: utils service list
  ```

- Take a **DRS backup** afterwards - a restore must hold the new certificates.

## Common problems

| Problem | Fix |
|---|---|
| `CUCM puts ... into its CSR` | The certificate's names differ from CUCM's: give it exactly the names of `show csr own` (step 2). |
| `CUCM makes RSA keys for tomcat` | Choose RSA 2048 for `tomcat` / `CallManager`, EC for the `-ECDSA` units. |
| `Permission denied` on SSH | The account is not a platform account, or its first password change is pending - sign in once by hand. |
| `Executed command unsuccessfully` at `set cert import own` | The CA is missing in `<unit>-trust` or the file name differs - look at `show cert list trust` and give *CA file in the trust store*; or CUCM made a newer CSR since (another *Generate CSR*): **Renew now**. |
| Phones get the old certificate | Cisco TFTP was not restarted (switch *Restart the services* on, or restart it). |
| Mixed mode after a CallManager certificate | Update the CTL file: `utils ctl update CTLFile`. |
| SAML SSO stops after a tomcat certificate | Re-provision the SP metadata in the IdP (disable / enable SSO). |
| Deployments held | CUCM keeps its old certificate; the next issue asks it for a new key and CSR. |
