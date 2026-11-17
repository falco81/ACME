# Microsoft AD CS (through acme-agent) - setup for acme

The **Microsoft AD CS (through acme-agent)** source gets certificates from an Active Directory Certificate Services CA **without any web service**: acme sends its CSR to the **acme-agent of a Windows member server** of the domain, which submits it to the CA natively (the CA's request interface over RPC - what `certreq -submit` does) as its **computer account (Kerberos)**, and returns the certificate and its chain. **acme holds no credential of the domain at all**, and the agent asks only for the CAs and templates its own policy names. **The private key never leaves acme.** A request waiting for a certificate manager is asked for again at later tries.

## What you need

- A **domain-joined Windows Server** (2016 or later) with **acme-agent** installed and joined - a target *Windows server with acme-agent* in acme.
- A **template** with *Subject Name: Supply in the request*, published on the CA.
- The server's **computer account** (`EXAMPLE\WIN1$`, or a group with it) with **Read** and **Enroll** on the template and **Request Certificates** on the CA.
- From the server to the CA: TCP 135 and the RPC dynamic ports.

## Set up Windows

1. The template - **certtmpl.msc** → *Web Server* → **Duplicate Template**: a name (e.g. `acmeWebServer`), *Subject Name*: **Supply in the request**, *Cryptography*: a Key Storage Provider, *Security*: the computer account → **Read** + **Enroll**. Publish it:

   ```powershell
   Add-CATemplate -Name acmeWebServer -Force
   ```

2. The CA (certsrv.msc → Properties → Security): the computer account → **Request Certificates**. Keep the CA's RPC encryption on (the default):

   ```powershell
   certutil -getreg CA\InterfaceFlags     # IF_ENFORCEENCRYPTICERTREQUEST
   ```

3. On the member server, in an elevated prompt - list the CAs and templates, then allow the one acme may ask for:

   ```bat
   acme-agent adcs cas
   acme-agent allow adcs "ca01.example.local\Example Issuing CA" template=acmeWebServer
   ```

   Several templates: `template=acmeWebServer,acmeWebServer2`; any template of that CA: `template=*`. `acme-agent allow adcs-read` lets acme list every CA and its templates (read-only).

## Fill in acme

Sources → **Add** → **Microsoft AD CS (through acme-agent)**.

| acme field | What to put there |
|---|---|
| Windows server with acme-agent | the target of that member server |
| Certification authority | `ca01.example.local\Example Issuing CA` - *Load the list* asks the agent |
| Template | `acmeWebServer` (its name, not its display name) - *Load the list*; a certificate's own template wins |
| Key types the template takes | *RSA and ECDSA* (KSP template), *RSA only* (schema 1), *ECDSA only* |
| Send the names as a SAN attribute too (advanced) | off |
| Timeout (s) (advanced) | `120` |

There is no password or certificate to enter.

## Check it

- Sources → the source → **Test**: the agent lists the CA's templates and says whether yours is offered and allowed.
- The certificate's **What happens** shows the signed job to the agent and the policy's verdict.

## Common problems

| Problem | Fix |
|---|---|
| not allowed by the policy of this machine | run the `acme-agent allow adcs ...` line the error names on the server |
| `0x80094012` - may not enroll | template → Security: Read + Enroll for the computer account (a group: restart the server) |
| `0x80070005` - access denied | CA → Security: Request Certificates for the computer account |
| `0x800706ba` - RPC server unavailable | the CA's DNS name, the firewall (135 and the dynamic ports) |
| Request pending | approve it in certsrv.msc → Pending Requests; set **Keep the key** on the certificate |
