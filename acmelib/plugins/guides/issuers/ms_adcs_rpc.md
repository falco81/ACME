# Microsoft AD CS (RPC, as certreq) - setup for acme

The **Microsoft AD CS (RPC, as certreq)** source asks an Active Directory Certificate Services CA **directly**, as `certreq.exe` does: the CSR acme made goes over DCE/RPC to the CA's `ICertPassage` interface (MS-ICPR) with the template, the certificate and its chain come back. **The private key never leaves acme.** acme signs in with **Kerberos** (AES; the default) or **NTLMv2**, and every call is **encrypted** (packet privacy). No IIS, no Web Enrollment, nothing installed on Windows. A request the template holds for a certificate manager's approval is remembered and fetched at later tries. Kerberos needs the Python package `cryptography` on acme (python3-cryptography); NTLM does not.

## What you need

- An Enterprise CA reachable **from acme** on TCP **135** (endpoint mapper) and its RPC port (**49152-65535**, or a fixed one) - and the domain controllers on TCP **88** for Kerberos.
- A service account for acme with **Read** and **Enroll** on the template and **Request Certificates** on the CA.
- A **template** with *Subject Name: Supply in the request*, published on the CA.
- For Kerberos: the CA server's **full DNS name** (its computer account's), DNS SRV records `_kerberos._tcp.<domain>` resolvable from acme (or the domain controllers typed in), and **acme's clock within 5 minutes** of the domain's.

## Set up AD CS

1. A service account, e.g. `svc-acme` (a normal domain user; for Kerberos it needs AES keys - set its password once more if it is very old):

   ```powershell
   New-ADUser -Name svc-acme -AccountPassword (Read-Host -AsSecureString) -Enabled $true -PasswordNeverExpires $true
   Set-ADUser svc-acme -KerberosEncryptionType AES128,AES256
   ```

2. The template - **certtmpl.msc** → *Web Server* → **Duplicate Template**:
   - *General*: a name, e.g. `acmeWebServer` (the **template name**, without spaces, is what acme needs).
   - *Subject Name*: **Supply in the request**.
   - *Cryptography*: for RSA and ECDSA choose a *Key Storage Provider* (schema 2+).
   - *Security*: `svc-acme` → **Read** and **Enroll**.
   - *Issuance Requirements*: leave *CA certificate manager approval* off for automatic renewals.
3. Publish it: **certsrv.msc → the CA → Certificate Templates → New → Certificate Template to Issue**, or

   ```powershell
   Add-CATemplate -Name acmeWebServer -Force
   ```

4. CA security (certsrv.msc → the CA → Properties → Security): `svc-acme` (or Authenticated Users) has **Request Certificates**.
5. The firewall of the CA server: TCP 135 and the dynamic RPC range from acme's address - or a static port for *CertSrv Request* (dcomcnfg → DCOM Config → CertSrv Request → Endpoints), set as *Fixed port* in acme.
6. The CA's name: `certutil -config -` (or `certutil -dump`) shows `ca01.example.local\EXAMPLE-CA01-CA` - acme needs the part after the backslash.

## Fill in acme

Sources → **Add** → **Microsoft AD CS (RPC, as certreq)**.

| acme field | What to put there |
|---|---|
| CA server | `ca01.example.local` - the full DNS name |
| CA name | `EXAMPLE-CA01-CA` |
| Template | `acmeWebServer` - the name, not the display name; a certificate's own template wins |
| Signing in | *Kerberos, NTLM where Kerberos cannot be used* (default), *Kerberos only*, *NTLM (v2) only* |
| Domain | `EXAMPLE.LOCAL` (the AD domain's DNS name; empty: from the CA server's name) |
| User / Password | `svc-acme` (or `svc-acme@example.local`; `EXAMPLE\svc-acme` for NTLM), its password |
| Domain controllers (KDC) (advanced) | `dc01.example.local` - empty: DNS SRV |
| Service name of the CA server (SPN) (advanced) | empty: `host/<CA server>` |
| Fixed port (advanced) | the CA's static RPC port; empty: asked from the endpoint mapper |
| More attributes / CA chain (advanced) | extra request attributes; the CA's chain when its answer carries none |
| Key types the template takes | *RSA and ECDSA* (KSP template), *RSA only*, *ECDSA only* |

## Check it

- Sources → the source → **Test** (Try it): the endpoint mapper, the sign-in and the bind - it says the port, how it signed in (Kerberos AES256 or NTLMv2) and that the connection is encrypted; no certificate is asked for.
- On the CA: `certutil -view -restrict "RequesterName=EXAMPLE\svc-acme" -out "RequestID,CommonName,Disposition"`.

## Common problems

| Problem | Fix |
|---|---|
| cannot be reached at …:135 | firewall: TCP 135 and the RPC range (or the fixed port) |
| the endpoint mapper knows no ICertPassage | CertSvc not running there, or not the CA server |
| the domain knows no service host/… | the CA server's full DNS name (not an alias or an address), or the SPN under advanced |
| clocks differ by N minutes | NTP on acme pointed at a domain controller |
| the password is wrong / access is denied (NTLM) | the user and password; a locked account |
| `0x80094012` - may not enroll for this template | template → Security: Read + Enroll for the account |
| `0x80094011` - the CA's permissions | CA → Properties → Security: Request Certificates |
| `0x80094800` - the CA does not offer this template | publish it on the CA; the template name |
| `0x80070057` | the CA name (after the backslash of `certutil -config`) |
| Request pending | approve it in certsrv.msc → Pending Requests; set **Keep the key** on the certificate |

Tested against protocol test vectors, MIT Kerberos and mock servers - not against a real Windows CA here; see `docs/ms-adcs-rpc.md`.
