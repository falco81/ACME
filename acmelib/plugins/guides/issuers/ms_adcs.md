# Microsoft AD CS (Web Enrollment) - setup for acme

The **Microsoft AD CS (Web Enrollment)** source gets certificates from an Active Directory Certificate Services CA through its **Web Enrollment** pages (`/certsrv`), the way a browser does: the CSR acme made is posted to `certfnsh.asp` with the template, the certificate is fetched from `certnew.cer` and the chain from `certnew.p7b`. **The private key never leaves acme.** A request the template holds for a certificate manager's approval is remembered and fetched at later tries. acme signs in with **Windows (NTLMv2)**, **Basic** over HTTPS, or a **client certificate**. Windows Server 2012 R2 - 2025. CES/CEP web services are not spoken; Kerberos-only sites are not supported.

## What you need

- An Enterprise CA with the role service **Certification Authority Web Enrollment** installed (IIS, `/certsrv`), reachable **from acme** over HTTPS (`443`) - NTLM and client-certificate connections go directly, not through Settings → Proxy.
- A service account for acme with **Read** and **Enroll** on the template and **Request Certificates** on the CA.
- A **template** with *Subject Name: Supply in the request*, published on the CA.
- The internal root that signed the IIS certificate of the CA (for *CA certificate of the web server*).

## Set up AD CS

1. Install Web Enrollment (on the CA or another server):

   ```powershell
   Install-WindowsFeature ADCS-Web-Enrollment
   Install-AdcsWebEnrollment -Force
   ```

   Give the `Default Web Site` an HTTPS binding with a certificate (Web Enrollment wants HTTPS).
2. A service account, e.g. `svc-acme` (a normal domain user; password that does not expire, or rotated with acme):

   ```powershell
   New-ADUser -Name svc-acme -AccountPassword (Read-Host -AsSecureString) -Enabled $true -PasswordNeverExpires $true
   ```

3. The template - **certtmpl.msc** → *Web Server* → **Duplicate Template**:
   - *General*: a name, e.g. `acmeWebServer` (the **template name**, without spaces, is what acme needs).
   - *Subject Name*: **Supply in the request**.
   - *Cryptography*: for RSA and ECDSA choose a *Key Storage Provider* (schema 2+); minimum key size as your policy says.
   - *Security*: `svc-acme` → **Read** and **Enroll** (not Autoenroll).
   - *Issuance Requirements*: leave *CA certificate manager approval* off for automatic renewals.
4. Publish it: **certsrv.msc → the CA → Certificate Templates → New → Certificate Template to Issue**, or

   ```powershell
   Add-CATemplate -Name acmeWebServer -Force
   ```

5. IIS authentication for `/certsrv` (**IIS Manager → Default Web Site → CertSrv → Authentication**): *Windows Authentication* on (providers Negotiate and NTLM) for NTLM; or *Basic Authentication* (HTTPS only); or *SSL Settings: Require* client certificates with a mapping to `svc-acme`.
6. CA security (certsrv.msc → the CA → Properties → Security): `svc-acme` (or Authenticated Users) has **Request Certificates**.

## Fill in acme

Sources → **Add** → **Microsoft AD CS (Web Enrollment)**.

| acme field | What to put there |
|---|---|
| Web Enrollment address | `https://ca01.example.local/certsrv` |
| Template | `acmeWebServer` - the name, not the display name; *Load the list* reads what the CA offers the user; a certificate's own template wins |
| Signing in | *Windows (NTLM)*, *Basic (over HTTPS)* or *Client certificate* |
| User / Password / Domain | `svc-acme` (or `EXAMPLE\svc-acme`), its password, the NetBIOS domain (empty: as the server says) |
| Client certificate / its key | for client-certificate sign-in |
| CA certificate of the web server (advanced) | your internal root, for the IIS TLS |
| Check the web server's TLS certificate (advanced) | on |
| More attributes (advanced) | extra `CertAttrib` lines, e.g. `SAN:dns=www.example.com` (only where the CA allows) |
| Key types the template takes | *RSA and ECDSA* (KSP template), *RSA only* (schema 1, e.g. the original WebServer), *ECDSA only* |
| Wait for approval (s) (advanced) | `0`; a pending request is fetched again at later tries |

## Check it

- Sources → the source → **Test** (Try it), and *Load the list* beside *Template* - it must list your template.
- On the CA: `certutil -view -restrict "RequesterName=EXAMPLE\svc-acme" -out "RequestID,CommonName,Disposition"`.

## Common problems

| Problem | Fix |
|---|---|
| `0x80094800` - the CA does not offer this template | publish it on the CA; give the template name, not the display name |
| `0x80094012` - the user may not enroll | template → Security: Read + Enroll for the user |
| `0x80094005` / `0x80094004` - names refused | template → Subject Name: Supply in the request |
| `0x80094009` - key too small | a bigger key type, or lower the template's minimum |
| `401` | user, password, domain; Windows Authentication on for `/certsrv`; Kerberos-only providers do not work - add NTLM |
| ECDSA refused | the template uses a legacy CSP (schema 1): set *Key types* to RSA only, or make a KSP template |
| Request pending | approve it in certsrv.msc → Pending Requests; set **Keep the key** on the certificate |
