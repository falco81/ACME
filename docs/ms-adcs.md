# Certificates from a Microsoft CA (AD CS Web Enrollment)

The `ms_adcs` issuer gets certificates from an Active Directory Certificate
Services CA through its **Web Enrollment** pages (`/certsrv`), the way a browser
does: the CSR acme made is posted with the template, the certificate fetched.
Nothing is installed on the Windows side beyond the *Certification Authority
Web Enrollment* role service.

## What it does

1. `POST /certsrv/certfnsh.asp` with `Mode=newreq`, the CSR (`CertRequest`) and
   `CertAttrib=CertificateTemplate:<template>` (plus any *More attributes* lines).
2. Issued at once: `certnew.cer?ReqID=N&Enc=b64` gives the certificate,
   `certnew.p7b?ReqID=N&Enc=b64` the chain (else the CA's own chain,
   `certnew.p7b?ReqID=CACert`).
3. **Pending** (the template needs a certificate manager's approval): the
   request id is kept in the module's state, under the request's public key. The
   job ends with *the CA holds the request N … acme asks for it again at the next
   try*; every later try asks `certnew.cer?ReqID=N` until it is issued (or
   denied). Set **Keep the key** on certificates whose template needs approval:
   a new key makes a new request (the old pending one is for a key acme no
   longer uses).
4. The certificate is checked to be for the request's key before it is taken.

## Signing in

| Way | IIS (Default Web Site → CertSrv → Authentication) |
|---|---|
| **Windows (NTLM)** - default | *Windows Authentication* on (providers *Negotiate* and/or *NTLM*). acme speaks NTLMv2 (pure Python, MD4 included), with a MIC and, over HTTPS, the channel binding Extended Protection wants. Kerberos-only (`Negotiate:Kerberos`) servers are not supported |
| **Basic** | *Basic Authentication* on, HTTPS only. Through acme's HTTP proxy settings like any other call |
| **Client certificate** | *SSL Settings: Require*, and the certificate mapped to an AD account (IIS client certificate mapping) |

The user: `user`, `DOMAIN\user` or `user@domain.local`; *Domain* is the NetBIOS
name (empty: the one the server says). The account needs **Read** and **Enroll**
on the template, and *Request Certificates* on the CA.

NTLM authenticates a TCP connection, not a request, so this module keeps its
own HTTP connections for NTLM and client certificates (they do not go through
the proxy of Settings → Proxy); Basic uses acme's HTTP like every module.

## The template

* Give the template's **name**, not its display name (*Web Server* is
  `WebServer`; a copy is usually `WebServer2` or what you named it).
* *Subject Name: Supply in the request* - acme's CSR carries the names; a
  template that builds the subject from AD refuses it (0x80094005 / 0x80094004).
* *Request Handling: Allow private key to be exported* is not needed (the key
  never leaves acme).
* The CA must offer it: CA → *Certificate Templates* → New → *Certificate
  Template to Issue*.

## When it fails

| The job says | Code | Do |
|---|---|---|
| the CA does not offer this template | 0x80094800 | publish the template on the CA, or use its name, not the display name |
| the user may not enroll for this template | 0x80094012 | template → Security: Read + Enroll for the user |
| the CA refused the request's names | 0x80094005 | template: Supply in the request |
| the request has a key smaller than the template wants | 0x80094009 | a bigger key type |
| the CA does not let the user in (401) | | user, password, domain; Windows Authentication on for /certsrv |
| the CA's TLS certificate is not trusted | | put your internal root under *CA certificate of the web server* |

CES/CEP (the SOAP enrollment web services) are not spoken.
