# Certificates from a Microsoft CA through acme-agent (no web service)

The `ms_adcs_agent` source (*Microsoft AD CS (through acme-agent)*, 1.0.125) gets
certificates from an Active Directory Certificate Services CA **without any web
service**: no Web Enrollment (`/certsrv`), no CES/CEP, no IIS. acme sends the CSR it
made to a **Windows member server of the domain running acme-agent**
([target-agent.md](target-agent.md), target *Windows server with acme-agent*). The
agent's root side (LocalSystem) submits the request to the CA natively, over the
CA's own request interface, and returns the certificate and its chain.

The web-service way stays as it was: [ms-adcs.md](ms-adcs.md) (`ms_adcs`).

## Why it is more secure

| | Web Enrollment (`ms_adcs`) | Through acme-agent (`ms_adcs_agent`) |
|---|---|---|
| Credentials in acme | a domain user and its password (NTLM, Basic) or a client certificate | **none** - not a user, not a password, not a certificate of the domain |
| Signing in to the CA | NTLM / Basic over HTTP(S) to IIS | **Kerberos as the computer account** of the member server (RPC/DCOM, MS-ICPR) |
| What runs on the CA side | IIS with the Web Enrollment role (often plain HTTP, NTLM relay target - ESC8) | nothing more than the CA itself |
| What may be asked | whatever the account may enroll for | only the CAs and templates **the agent's policy** names (`allow adcs`), checked on the server for every job |
| What travels | the CSR and the password / NTLM exchange | a **signed job** (Ed25519, never replayed) over **mutual TLS 1.3**; the CSR only |
| Encryption to the CA | that of the HTTPS binding (if any) | RPC packet privacy, as the CA enforces it (`IF_ENFORCEENCRYPTICERTREQUEST`, on by default) |

A stolen acme database holds nothing that lets anybody enroll; a compromised acme can
only ask the agent for what the server's own policy allows - for the templates named,
with only the names of the CSR (no free attributes, no Windows sign-in names).

## How it works

1. acme makes the key and the CSR, as for every source - **the private key never
   leaves acme**.
2. It sends a signed job `adcs` (action `submit`: the CA, the template, the CSR) to the
   agent of the server chosen.
3. The agent's root side checks the job (signature, time, nonce, its id) and then its
   policy: the CA must be named by an `allow adcs` line, the template by its
   `template=` (or `template=*`). Anything else is refused with the exact line that
   would allow it - nothing is asked of the CA.
4. It checks the CSR: a PKCS#10 whose signature is good, naming only DNS names,
   addresses, e-mail or URIs - **a CSR with a Windows sign-in name (UPN, otherName) is
   refused**.
5. It submits it - what `certreq -submit -config "HOST\CA Name" -attrib
   "CertificateTemplate:NAME" request.csr` does - through the CA's request interface
   (`ICertRequest::Submit` over RPC/DCOM) from a **fixed PowerShell script**; the
   values go to the script through a JSON file in the agent's protected stage folder
   (`root\stage`, SYSTEM and the Administrators only), deleted after - nothing is ever
   put into the script's text, and no `certreq` arguments come from acme. The request
   carries only the CSR and the attribute `CertificateTemplate:NAME` (with *Send the
   names as a SAN attribute too*: also `SAN:dns=...&dns=...`, made **on the server** of
   the CSR's own DNS names and addresses).
6. **Issued**: the certificate and its chain (PKCS#7, as `certreq`'s `.p7b`) come back.
   acme checks the certificate is for **the key of its request** (another key: refused)
   and puts the chain in order.
7. **Pending** (the template needs a certificate manager's approval): the request id is
   kept in the source's state with the request's key and CSR (as `ms_adcs` keeps it);
   the job says *ca01…\Example CA holds the request 4711 for a certificate manager to
   approve*; every later try asks for it again (action `retrieve`, what `certreq
   -retrieve -config ... 4711` does) - no new request is filed meanwhile.
8. **Denied** (or any other refusal of the CA): said in words - the CA's code, what it
   means, its message (*denied the request 4711: the computer account of this server
   may not enroll for this template … Denied by Policy Module - 0x80094012*); the kept
   request is let go.

## What to set on the Windows side

1. **A member server of the domain** (Windows Server 2016 or later) with
   **acme-agent** installed and joined ([target-agent.md](target-agent.md), *Install on
   Windows*). It does not have to be the CA; a server of its own is better.
2. **The template** (certtmpl.msc → a copy of *Web Server*):
   - *Subject Name*: **Supply in the request**;
   - *Security*: the **computer account** of that server (`EXAMPLE\WIN1$`) - or a group
     it is a member of (restart the server, or `klist -li 0x3e7 purge`, after adding it
     to a group) - **Read** and **Enroll**;
   - *Cryptography*: a Key Storage Provider for RSA and ECDSA (schema 2+);
   - publish it: certsrv.msc → *Certificate Templates* → *New* → *Certificate Template
     to Issue*, or `Add-CATemplate -Name acmeWebServer -Force`.
3. **The CA** (certsrv.msc → the CA → Properties → *Security*): that computer account
   (or its group) has **Request Certificates**. If the CA restricts enrollment agents or
   uses *Restrict enrollees*, allow it there too.
4. **Encryption**: keep the CA's flag `IF_ENFORCEENCRYPTICERTREQUEST` on (the default
   since Windows Server 2012; `certutil -getreg CA\InterfaceFlags` shows it,
   `certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST` and a restart of
   CertSvc sets it).
5. **Kerberos, not NTLM**: the agent reaches the CA by its name (`HOST` of the config
   string - use its DNS name, e.g. `ca01.example.local`), so Negotiate picks Kerberos for
   the computer account. To forbid NTLM to the CA altogether use the domain's *Network
   security: Restrict NTLM* policies.
6. **Network** from the member server to the CA: TCP 135 and the RPC dynamic ports
   (49152-65535), or the fixed port the CA's DCOM is set to.
7. **The agent's policy** (an elevated prompt on that server):

   ```bat
   acme-agent adcs cas
   acme-agent allow adcs "ca01.example.local\Example Issuing CA" template=acmeWebServer
   ```

   `acme-agent adcs cas` lists the CAs of the domain, the templates each one offers
   (name and display name) and the line that would allow them; `acme-agent adcs
   templates --config "HOST\CA Name"` one CA's templates (`--json` for both). They run
   as the administrator who types them - read-only.

## The policy lines

```
allow adcs "HOST\CA Name" template=NAME,NAME     that CA, those templates (by name)
allow adcs "HOST\CA Name" template=*             that CA, any template it offers
allow adcs-read                                  list every CA of the domain and its templates
```

- **One line a CA**; several CAs are several lines. There is no wildcard for the CA:
  every CA the agent may ask is named. A CA said twice has the templates of both lines;
  `template=*` with names beside it is not read.
- **Several templates** in one line, comma between them (`template=WebServer,WebServer2`);
  names compare without regard to case. The template's **name** (cn), not its display
  name. A name with a space is quoted, the whole list in one pair of quotes:
  `template="Web Server 2,WebServer"` (the agent writes it so).
- `acme-agent allow adcs "HOST\CA" template=X` **adds** X to the templates the CA's line
  has (one line kept); `acme-agent deny adcs "HOST\CA" template=X` takes X away (the
  line goes with the last one); `acme-agent deny adcs "HOST\CA"` takes the CA away.
- **Reading the lists** (the form's *Load the list*, the policy designer, the API, the
  CLI) is read-only and allowed too: with `allow adcs-read` every CA of the domain and
  its templates; without it only the CAs the `allow adcs` lines name, and only their
  templates. With neither, a list is refused with `acme-agent allow adcs-read`. Each
  template listed says whether the policy allows it.
- On Linux these lines are not read (an agent on Linux refuses every `adcs` job: *a
  Microsoft CA is asked only by acme-agent on Windows*).

## Fill in acme

Sources → **Add** → **Microsoft AD CS (through acme-agent)**.

| acme field | What to put there |
|---|---|
| Windows server with acme-agent | the target of that member server (Targets → *Windows server with acme-agent*) |
| Certification authority | `ca01.example.local\Example Issuing CA` - *Load the list*: the CAs the agent lists |
| Template | `acmeWebServer` - *Load the list*: the templates the CA offers, each marked when the agent's policy does not allow it; a certificate's own template (its profile) wins |
| Key types the template takes | as for `ms_adcs` |
| Send the names as a SAN attribute too (advanced) | off - only for a CA with `EDITF_ATTRIBUTESUBJECTALTNAME2` (which is better off) |
| Timeout (advanced) | 120 s |

No user, no password, no certificate: there is nothing secret to fill in.

*Test* (Try it) asks the agent for the CA's templates and says whether the template is
offered and allowed - nothing is requested.

## In acme's other places

- **What happens** (the run plan) of a certificate of this source shows *Sends a signed
  job (adcs submit) to the agent of WIN1*, then *The agent runs certreq -submit -config
  "…" with the template …* with what the agent's policy, as it last said it, makes of
  it - and the `acme-agent allow adcs ...` line when it does not allow it.
- **The policy designer** of the Windows server (Targets → the agent's card → *Design its
  policy…*): the section **Microsoft CA (AD CS)** - *Load the CAs and templates from the
  agent* lists them; a click on a template (or *every template (\*)*) adds it to the
  CA's line; *acme may list every CA* is `allow adcs-read`. *What the deployments need*
  lists the sources asking through this server with their CA and templates (their
  certificates' own templates too); the template *Microsoft CA (AD CS)* adds an example.
- **API**: `GET /api/agents/adcs?target=NAME[&ca=HOST\CA]` (certificate administrator)
  → `{cas: [{config, name, server, allowed, templates: [{name, display, allowed}],
  problem}], said, needs}` - read-only, through the agent, as its policy lets it list.
- **Command line**: `acme --target-agent NAME adcs-templates [HOST\CA] [--json]`.

## Common problems

| Problem | Fix |
|---|---|
| *not allowed by the policy of this machine: a certificate of the template X from the CA Y* | run the line the error names on the server (`acme-agent allow adcs "Y" template=…,X`) |
| *'adcs' is not an operation of this agent* | the agent is older than 1.0.125: update it |
| `0x80094012` - may not enroll | the template's Security: Read + Enroll for the computer account (or its group - then restart the server or purge its tickets) |
| `0x80070005` - access denied | the CA's Security: Request Certificates for the computer account |
| `0x800706ba` - RPC server unavailable | the CA's name, DNS, the firewall (135 and the dynamic ports) |
| `0x80094800` - the CA does not offer the template | publish it on the CA; give its name, not its display name |
| pending | approve it (certsrv.msc → Pending Requests → Issue); set **Keep the key** on the certificate |
