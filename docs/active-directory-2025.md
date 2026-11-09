# Domain controllers on Windows Server 2025

What acme does with Active Directory, checked against what changes when the domain
controllers are replaced by Windows Server 2025 (and against the Kerberos and NTLM
changes Windows brings to older controllers too).

## Where acme talks to Windows

| What | How | Ready for 2025 |
|---|---|---|
| Sign-in of administrators and of the certificate portal (Settings → Accounts → directories) | its own LDAP client: a **simple bind**, LDAPS (636, the default) or STARTTLS, or plain LDAP | yes with LDAPS / STARTTLS; **plain LDAP is refused** by a controller that requires signing |
| MS AD CS (Web Enrollment) as a source of certificates | HTTP(S) with **NTLMv2** (a MIC, and the channel binding of Extended Protection over HTTPS), or a client certificate | yes - never NTLMv1, nothing of Kerberos |
| Backups to a Windows share | `smbclient`, **SMB2 at least**, SMB3 encryption by default, signing as the server asks | yes - never SMB1 |
| Windows targets (certificates put on IIS, RDP, WinRM... and **the LDAPS certificate of a domain controller**, NTDS\Personal) | over SSH to the Windows machine | yes - but a controller that is a target and is replaced needs its SSH set up again (below) |
| Kerberos | not used | - |

## What is checked for you

**Settings → Accounts → the directory → Check it** tries every controller from every node and
also says what will not work once the controllers are new (1.0.61):

- **Plain LDAP** - Windows Server 2025 requires LDAP signing by default; a simple bind over
  port 389 without TLS is refused with `strongerAuthRequired` (result 8). acme now says so in
  words and tells to switch to LDAPS or STARTTLS.
- **A controller given by its address** - its certificate names it by its name (the FQDN), so
  the check of the certificate fails on an address. Give `dc1.example.com`, not `10.0.0.10`.
- **The server's own certificate kept as the authority** (a certificate with `CA:FALSE`) - that
  is pinning one controller's certificate; a replaced controller has a new one. Keep the
  company's root (and intermediate) authority instead.
- **"Take old, weak certificates"** still on - Windows Server 2025 speaks TLS 1.2 and 1.3 only,
  it is not needed any more.

## What acme already does right

- The certificate is checked against the authority **and** the server's name (no `CERT_NONE`
  unless switched off by hand, which the high-security check reports).
- TLS 1.2 or newer (Python's default context); TLS 1.0 only with "weak" on.
- **Several controllers** per directory: the one that answered last first, one that does not
  answer is passed over for 30 s - while one controller is being replaced, the others serve.
- **Paged searches** (1000 a page is AD's limit): every group and person is read.
- Timeouts on every connection; the LDAP result code and the controller's name are in the
  message and the log.
- The reading account's password is sealed in the database, never in a file or a log.

## A domain controller that is a target of acme

When acme puts the LDAPS certificate on a controller itself (a target *Windows over SSH* with
the role *LDAPS of a domain controller*), the new VM under the old name and address is another
machine to SSH:

1. Install OpenSSH Server on it again and put acme's public key back
   (`C:\ProgramData\ssh\administrators_authorized_keys` for an administrator).
2. It has a **new host key**: the deployment stops with "shows another host key than the one
   trusted". Clear the target's *Host key* (with *Trust the first host key seen* on) or paste its
   new known_hosts line, then **Deploy again** - the new controller gets its certificate.

## Before the change

1. On the current controllers, event **2889** (Directory Service log) names the clients that
   bind without signing - acme's nodes must not be among them (they are not with LDAPS).
2. **Check it** on each directory: no warning left.
3. After the first controller is replaced, **Check it** again - it asks every controller by
   name, the new one too.
