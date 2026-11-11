# Tests of what the servers serve

A deployment puts a certificate on a target; a **test** looks whether the
server really serves it. acme connects as a client of the server's protocol
would - a browser, a mail client, a Remote Desktop client - and compares the
certificate chain it is sent with the certificate acme keeps.

Tests are **defined as targets are**: Certificates → **Tests** lists them,
*Add a test* picks the kind (HTTPS, SMTP, RDP…, or a connector over SSH) and
its settings, *Test* tries it, *Try it on a certificate* compares what is served
with a certificate before anything is kept. They are **attached to
certificates as targets are**: the certificate's window → **Tests** → *Attach
a test* ticks the tests defined; each attached test shows how it went last and
what the server sent (*Run it now*, *Switch it off here*, *Take it off*). A
test may be attached to many certificates. *What happens* shows the tests as a
phase of their own, one at a time or side by side, as the deployments.

Empty *Connect to*: the test connects to the first name of the certificate it
is attached to - one HTTPS test serves every web certificate.

## What a test says

| | |
|---|---|
| **serves it** | the current version (or the twin of a dual certificate) |
| **serves it - but** | the right one, but: it ends within `certs_checks_warn_days`, the name checked is not one of its names, the server sends no intermediate (unless *Check the chain sent* is off), or it is not trusted by this machine's CAs (failing only with *Fail when not trusted here*) |
| **an old version** | an earlier version of the same certificate: the renewal did not reach the server - a service not restarted, another node behind the balancer |
| **another certificate** | one acme did not deploy there. The other half of a dual certificate acme does not keep (the same names, the other key type - ECDSA where acme has only the RSA one) is said as that: import it into the certificate as its twin, or set *Key asked for* |
| **wrong answer** | HTTPS asked over HTTP: the status or the words are not as set |
| **not reached** | no connection, no STARTTLS, no TLS |

**Side by side** (1.0.34): a test's result - *Try it*, the eye in a
certificate's Tests - draws what acme keeps (both halves of a dual
certificate) beside what the server sent, each line ticked where they agree and
red where not: names, issuer, validity, key, SHA-256. A test that fails says
the same in the job's log (`✗ key: acme RSA 4096 | sent EC 384`, `= names:
...`), in the event, and in the mail it sends (a table *In acme / The server
sent*).

*What the server served* shows the subject, issuer, validity, names, SHA-256,
the TLS version and cipher, the chain length, whether it is trusted here,
where it connected and the HTTP answer.

## When they run

- **After the deployments** (`certs_checks_after_deploy`, on): the
  certificate's tests, once its deployments are done, tried three times over
  half a minute while the services restart. A failed test makes the job say so;
  the deployments themselves went as they say.
  Which deployments run a test is chosen when it is attached, as a deployment's
  options are (the certificate's window → Tests → **Attach a test** → *Options on this
  certificate*, or the gear of an attached one; 1.0.65): **The targets chosen** - one
  target, the default (a test is mostly of one server), or several - or **Every
  deployment**, as every test attached before 1.0.65 is. Deploying on rpki1 then tests
  rpki1, not rpki2.
- **By themselves** (`certs_checks_auto`, off; `certs_checks_every_min`, 360):
  every test, on the node that leads.
- **Asked**: the certificate's window, or the command line.

A test that starts failing is an event and a notification - mail and SMS to the
addresses of Settings → Certificates (`certs_checks_alert`), in the words of
Settings → Message texts (*A test of a server failed*); one that works again is
said too (*A test of a server works again*). A test that keeps failing is said
once, not at every run.

## The tests there are

| Kind | Protocol | Port |
|---|---|---|
| `https` | HTTPS - with an HTTP request when asked | 443 |
| `tls` | TLS at once, any port | 443 |
| `smtp` / `smtps` | SMTP with STARTTLS (587 for submission) / at once | 25 / 465 |
| `imap` / `imaps` | IMAP with STARTTLS / at once | 143 / 993 |
| `pop3` / `pop3s` | POP3 with STLS / at once | 110 / 995 |
| `ftp` / `ftps` | FTP with AUTH TLS / at once | 21 / 990 |
| `ldap` / `ldaps` | LDAP StartTLS (extended operation) / at once | 389 / 636 |
| `rdp` | Remote Desktop: X.224 negotiation, then TLS | 3389 |
| `postgres` | PostgreSQL SSLRequest | 5432 |
| `mysql` | MySQL / MariaDB SSLRequest | 3306 |
| `mssql` | Microsoft SQL Server: PRELOGIN, TLS inside TDS | 1433 |
| `xmpp` | XMPP STARTTLS | 5222 |
| `mqtts`, `sips`, `dot` | MQTT, SIP, DNS over TLS | 8883, 5061, 853 |
| `ssh_relay` | a connector: tests of the above, run from a Linux server over SSH | 22 |

## Settings of every test

| Setting | |
|---|---|
| *Connect to* | the name or IP connected to - one node behind a load balancer, say. Empty: the target's address |
| *Port* | |
| *Name asked for (SNI)* | sent in TLS, whatever address was connected to. Empty: the certificate's first name; `-`: none |
| *Name the certificate must hold* | looked for among the names served. Empty: the SNI |
| *The certificate expected* | the version deployed now (or its twin), the main one only, the twin only, any version |
| *Key asked for* | whichever the server picks, RSA, ECDSA, or both - a server with a dual certificate sends the one asked for. RSA or ECDSA is TLS 1.2 with ciphers of that key only (Python cannot ask for a key type in TLS 1.3), so the server must still speak TLS 1.2. Both: connected twice, once for each; it passes when each half is the right one (with *The certificate expected* as set), and the worse of the two is the result |
| *TLS at least / at most* | TLS 1.0 - 1.3 - at most 1.2 to see what an older client gets |
| *Ciphers* | OpenSSL's list (TLS 1.2 and older): RSA ones only to get the RSA one of a dual certificate |
| *ALPN* | `h2, http/1.1` |
| *Address family*, *From the address* | IPv4 / IPv6 only; the local address connected from |
| *Time limit*, *Fail when not trusted here* | |

HTTPS also: *Ask over HTTP too*, *Method* (HEAD, GET, OPTIONS), *Path*, *Host
header* (a virtual host other than the SNI), *More headers*, *Status expected*
(`200,301-302`), *The answer holds* (GET).

## Through an SSH server

A **connector** (*Tests on a server over SSH*, `ssh_relay`) is a test of its
own: it signs in to a Linux server of yours (AlmaLinux, RHEL, Rocky… - any with
OpenSSH) with its address, port, user and key or password - the same key card
as a Linux / Unix (SSH) target: *Make a key*, *Use my own*, *Try reaching it*,
*How to set it up on the server*. Its *Tests run from there* tick tests already
defined (HTTPS of an internal site, SMTP of a relay, RDP of a Windows server…).
Attached to a certificate, every one of them is run from that server through
`ssh -W host:port` - nothing installed there, nothing left behind
(`AllowTcpForwarding` must not be `no`) - and compared with that certificate;
the worst of them is the result, every one shown under it.

## Your own tests

A test is a module like a source or a target: see
[writing-a-module.md](writing-a-module.md#a-test-of-a-server). It appears on the
page Modules, can be overridden, have versions and be uploaded.
