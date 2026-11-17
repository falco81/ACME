# Certificates from a Microsoft CA over RPC (as certreq)

The `ms_adcs_rpc` source - *Microsoft AD CS (RPC, as certreq)* - asks an Active
Directory Certificate Services CA **directly**, the way `certreq.exe` does: no IIS,
no Web Enrollment, nothing installed on the Windows side. The request (the CSR acme
made - **the private key never leaves acme**) goes over DCE/RPC to the CA's
`ICertPassage` interface (MS-ICPR), signed in with **Kerberos** (the default) or
**NTLMv2**, and every call is **encrypted** (RPC authentication level *packet
privacy*). Since 1.0.125.

Its siblings: [ms-adcs.md](ms-adcs.md) (Web Enrollment over HTTPS) and
[ms-adcs-agent.md](ms-adcs-agent.md) (certreq run by acme-agent on a Windows member
server, no password in acme).

## What it does

1. **The port.** The CA listens for RPC on a dynamic port. acme asks the CA
   server's **endpoint mapper** (TCP **135**, `ept_map`, opnum 3) where the interface
   `91ae6020-9e3c-11cf-8d7c-00aa00c091be` v0.0 listens over `ncacn_ip_tcp` - or uses
   the **fixed port** set under *More*.
2. **Kerberos** (unless *NTLM only*): a ticket-granting ticket for the user from a
   domain controller (AS-REQ on TCP **88**; the salt from the KDC's
   PREAUTH_REQUIRED, then pre-authenticated with an encrypted timestamp), then a
   service ticket for the CA server's name, `host/<CA server>` (RPCSS/ is the same
   computer account; another SPN can be set under *More*). AES256 and AES128 only
   (aes256/aes128-cts-hmac-sha1-96, RFC 3962). The domain controllers come from
   *More → Domain controllers* or from DNS (`_kerberos._tcp.<domain>` SRV records).
3. **The bind** to ICertPassage with an auth verifier at
   `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`:
   * Kerberos: auth type 16 (`RPC_C_AUTHN_GSS_KERBEROS`), the AP-REQ with mutual
     authentication in DCE style (MS-KILE), the CA's AP-REP (it proves itself and
     sends the session's subkey), acme's AP-REP back in an AUTH3. Where the CA takes
     only Negotiate, the same AP exchange goes inside SPNEGO (auth type 9).
   * NTLMv2: auth type 10, NEGOTIATE / CHALLENGE / AUTHENTICATE (with a MIC and key
     exchange), then MS-NLMP sealing (RC4, HMAC-MD5 over the whole PDU).
4. **CertServerRequest** (opnum 0) with the CA's name, the flags `CR_IN_PKCS10`, the
   attributes `CertificateTemplate:<template>` (plus *More attributes*) and the CSR
   (DER) - sealed: RFC 4121 Wrap tokens (Kerberos) or NTLM sealing.
5. **The answer:**
   * *issued* (3): the certificate (it must be for the CSR's key - one for another
     key is refused) and its chain from the PKCS#7 the CA sends with it; else the CA
     chain set under *More*, else the certificate's AIA address (http).
   * *under submission* (5, the template wants a certificate manager's approval): the
     request ID is kept in the module's state with the request's key (sealed) and the
     job says so; every later try asks the CA for that request ID with no request
     (MS-WCCE's retrieval) until it is issued or denied. Set **Keep the key** on such
     certificates.
   * *denied* (2) or an error code: said in words, the CA's own message with it
     (e.g. `0x80094012`: the user may not enroll for the template).

**Try it** (Sources → Test) asks the endpoint mapper, signs in and binds - it asks for
no certificate.

**What happens** (the run plan) lists these steps - the endpoint mapper, the tickets
asked for, the bind (how it signs in, packet privacy), CertServerRequest with the CA
name, the template and the CSR's size - and connects to nothing; the password is
never in it.

## Fill in acme

Sources → **Add** → **Microsoft AD CS (RPC, as certreq)**.

| acme field | What to put there |
|---|---|
| CA server | the **full DNS name** of the server the CA runs on, `ca01.example.local` (Kerberos needs the name its computer account has; an IP address works with NTLM only) |
| CA name | the CA's own name: `certutil -config -` / `certutil -dump` shows `ca01.example.local\EXAMPLE-CA01-CA` - the part after the backslash (`server\CA` as a whole is taken too) |
| Template | the template's **name** (not its display name), e.g. `acmeWebServer`; a certificate's own template wins |
| Signing in | *Kerberos, NTLM where Kerberos cannot be used* (default), *Kerberos only*, *NTLM (v2) only* |
| Domain | the AD domain's DNS name = the Kerberos realm, `EXAMPLE.LOCAL` (empty: the CA server's name without its first label) |
| User / Password | `svc-acme` (or `svc-acme@example.local`, `EXAMPLE\svc-acme` for NTLM); the password is a secret, sealed as every other one, never logged |
| Domain controllers (More) | `dc01.example.local, dc02.example.local` (TCP 88); empty: DNS SRV |
| Service name (More) | empty: `host/<CA server>` |
| Fixed port (More) | the CA's RPC port when you fixed it; empty: from the endpoint mapper |
| Timeout, More attributes, CA chain, Key types | as for Web Enrollment |

When *Kerberos, NTLM where Kerberos cannot be used* falls back to NTLM it says why in
the job's steps: no domain controller answered, no SRV records, the CA server given
as an address, no AES key for the account, no such service name, the CA refusing
Kerberos. A wrong password, a locked account or **a clock off by more than five
minutes** are not hidden behind NTLM - they are said as they are.

## On the Windows side

1. **A service account**, e.g. `svc-acme` - a normal domain user. For Kerberos it
   needs AES keys: any account whose password was set on a domain at 2008 level or
   later has them (set it once more if unsure; *This account supports Kerberos AES
   256 bit encryption*).
2. **The template** (certtmpl.msc → *Web Server* → *Duplicate Template*): *Subject
   Name: Supply in the request*; *Security*: `svc-acme` → **Read** and **Enroll**;
   *Cryptography*: a Key Storage Provider for ECDSA; no manager approval for
   automatic renewals. Publish it: certsrv.msc → *Certificate Templates* → *New* →
   *Certificate Template to Issue* (or `Add-CATemplate -Name acmeWebServer`).
3. **The CA's security** (certsrv.msc → the CA → *Properties* → *Security*):
   `svc-acme` (or *Authenticated Users*) has **Request Certificates**.
4. **The firewall** of the CA server, from acme: TCP **135** (endpoint mapper) and
   the dynamic RPC range (**49152-65535**) - or fix the CA's port and open only it
   and 135. The usual way to fix it is the *CertSrv Request* application's endpoint
   (dcomcnfg → *Component Services* → *DCOM Config* → *CertSrv Request* →
   *Properties* → *Endpoints* → a static TCP port, then restart CertSvc); *Try it*
   shows the port the endpoint mapper then says - set that as *Fixed port* here if 135
   is to stay closed. To the domain controllers: TCP **88** (Kerberos).
5. **Kerberos needs names and time:** the CA server's DNS name must be its computer
   account's name (its SPN `HOST/ca01.example.local`; check with
   `setspn -L CA01`), the domain's SRV records must resolve from acme (or set the
   domain controllers), and **acme's clock must be within 5 minutes** of the domain's
   (chrony/NTP pointed at a domain controller). A skew is said as *acme is N minutes
   ahead/behind*.
6. Encryption is always on: AD CS enforces it for ICertPassage
   (`IF_ENFORCEENCRYPTICERTREQUEST`, `certutil -getreg CA\InterfaceFlags`) - acme
   never asks for less.

## What it needs on acme's side

Kerberos needs the Python package **cryptography** (python3-cryptography: `dnf
install python3-cryptography` or `apt install python3-cryptography`) for AES; without
it the source says so and, with the default setting, signs in with NTLM, which needs
nothing (MD4, RC4 and HMAC-MD5 are acme's own). Nothing else is installed - no
impacket, no Kerberos library, no keytab, no krb5.conf.

## When it fails

| It says | Fix |
|---|---|
| cannot be reached at …:135 / does not answer | the firewall: TCP 135 and the RPC range (or the fixed port) from acme |
| the endpoint mapper knows no ICertPassage | the CA service (CertSvc) is not running on that server, or it is not the CA |
| the domain knows no service host/… | give the CA server's full DNS name (its computer account's), not an alias or an address; or set the SPN under *More* |
| the password is wrong (KDC_ERR_PREAUTH_FAILED) | the password; for NTLM a wrong password shows as *access is denied* at the first call |
| clocks differ by N minutes | set acme's time from the domain (NTP) |
| no AES key / KDC_ERR_ETYPE_NOSUPP | set the account's password once more, or tick AES 256 on the account |
| `0x80094012` - may not enroll for this template | template → Security: Read + Enroll for the account |
| `0x80094011` - the CA's permissions | CA → Properties → Security: Request Certificates |
| `0x80094800` - the CA does not offer this template | publish it on the CA; the template name, not the display name |
| `0x80070057` - a parameter is wrong | the CA name (the part after the backslash of `certutil -config`) |
| `0x80094005` / `0x80094004` - names refused | template → Subject Name: Supply in the request |
| the CA holds the request N | approve it (certsrv.msc → Pending Requests → Issue); acme fetches it at the next try |

## How it was made and tested

Written from the specifications: RFC 4120/4121 (Kerberos 5, GSS-API Wrap tokens),
RFC 3961/3962 (n-fold, string-to-key, AES-CTS, HMAC-SHA1-96), C706 (DCE/RPC, NDR),
MS-RPCE, MS-KILE (DCE style), MS-NLMP (NTLMv2 sealing), MS-ICPR and MS-WCCE
(CertServerRequest, dispositions); impacket's and Certipy's public sources were read
for how Windows behaves (the third leg of the DCE style, the Wrap token rotated by
RRC + EC, the retrieval of a pending request). No code was taken from them; nothing
but `cryptography` (optional) is used.

What is verified and how (`test/test_ms_adcs_rpc.py`):

* **Against published vectors:** RFC 3961 A.1 (n-fold), RFC 3962 B (string-to-key for
  AES128/AES256, AES-CTS), MIT krb5's AES encrypt and checksum vectors, MS-NLMP
  4.2.4.4 (NTLMv2 sealing keys, sealed message and signature), the NDR of
  CertServerRequest.
* **Against MIT Kerberos** (run when krb5kdc and libgssapi_krb5 are installed): the AS
  and TGS exchanges with a real MIT KDC (and its wrong-password, unknown-service and
  clock-skew errors); the DCE-style AP exchange accepted by MIT's GSS-API; acme's Wrap
  tokens unwrapped by MIT and MIT's unwrapped by acme.
* **Against mocks of the tests' own** (a KDC and an AD CS with the endpoint mapper,
  Kerberos auth types 16 and 9, NTLM auth type 10, sealing, fragments): issued,
  pending then retrieved, denied, template denied, wrong CA name, wrong password,
  clock skew, the NTLM fallback, a certificate for another key refused, *Try it*, the
  run plan - and that the password is in no step, error or plan.

**It has not been tried against a real Windows CA here.** The DCE/RPC and NTLM sides
and Windows' own Kerberos acceptor are covered by the specifications and the mocks
only; if a real CA answers differently, the job's steps say what it answered.
