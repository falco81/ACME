# Signing in with a certificate (a smart card, a YubiKey)

As in otp 1.0.275, since acme 1.0.100. A person with a certificate of the domain's authority (AD
CS) - on a smart card, a YubiKey (PIV) or in the computer - opens the administration (`/admin/`)
or the certificate portal (`/`), presses **Sign in with a certificate**, picks the certificate
(Windows asks for the card's PIN) and is signed in without typing a name or a password.

**Two parts, each with its own switches** - the administration and the portal can be switched on
each by itself, or both, or neither. **Off by default**: nothing changes until an administrator
switches it on. The authorities are put in once, for both parts and every node. It is built the
same way as [signing in with Windows](kerberos-sso.md) and can be on beside it.

## The rules it keeps

1. **A port of its own.** nginx asks for a certificate on `certlogin_port` (8443) only - never
   on 443, so nobody who opens the pages is ever asked for one (with `ssl_verify_client optional`
   on 443 every visitor with a certificate of these authorities - a domain computer's own - would
   get a chooser on every page). Nothing but the sign-in is served on that port: every other
   address there answers 404.
2. **acme checks the certificate, not nginx.** nginx sends the authorities' names (so the browser
   offers only fitting certificates) and hands the certificate on (`optional_no_ca`); acme
   checks: the chain to the authorities put in - **and nothing else**: openssl is told to use no
   store of the system's (`-no-CApath -no-CAstore`; `openssl verify -CAfile` alone still trusts
   the system's folder of roots, which the kit this was taken from did), the dates, a key usage
   for signing in (*Client Authentication* or *Smart Card Logon*), no critical extension it does
   not know, not an authority's own certificate, revocation, and the UPN in the Subject
   Alternative Name.
3. **Revocation fails closed.** The CRL at the certificate's CRL Distribution Point (http only,
   no link-local address) is fetched **only for a certificate whose chain is good** - never an
   address written into anybody's certificate - kept until its next update, its signature and
   its dates checked by openssl. A CDP that does not answer: the last CRL while it is still good,
   then no sign-in. It can be switched off per part (`*_certlogin_crl`): a lost card then signs
   in until its account is switched off in AD - the card says so.
4. **One person, one account.** The UPN is looked up in that part's directory
   (`userPrincipalName`); the account is then found by its **sAMAccountName**, exactly as a
   password or a Kerberos ticket finds it, and **the two entries must be the same DN**. Whichever
   way the person signed in first, it is the same account here.
5. **The SID (KB5014754).** Since May 2022 AD CS writes the account's SID into each certificate it
   issues from AD (`szOID_NTDS_CA_SECURITY_EXT`, 1.3.6.1.4.1.311.25.2). A UPN can be given to
   somebody else; the SID cannot be moved. *Which account a certificate is*
   (`*_certlogin_match`): **compat** (the default) - the SID must be the account's `objectSid`
   when it is in the certificate; **strong** - it must be there (Microsoft's full enforcement);
   **upn** - the UPN alone.
6. **Only accounts of the directory**, by the same rules as a password: the administration - the
   role of the first group of a role they are in (an account switched off, locked, expired, more
   than one entry: refused; a local account of acme of the same name keeps its password); the
   portal - *Who may sign in*, the groups, the role *Enrolment pages only*.
7. **The second step stays.** The certificate takes the place of the *password* only: the
   administration's second step ([admin-second-step.md](admin-second-step.md)) and the portal's
   one-time code are asked after it every time.
8. **Login CSRF closed.** The button first asks the page (POST, the page's own JSON) for a nonce:
   random, bound by a MAC to the part (keyed with the daemon's API token), five minutes, in an
   `HttpOnly SameSite=Strict` cookie of the page's path, one use. On the port the nonce of the
   address must be the cookie's, compared in constant time - a link of somebody else's signs
   nobody in with whatever certificate the browser has.
9. **Refused - said by kind only.** Back on 443 the page says *Certificate sign-in refused:* and
   one of *certificate not accepted*, *revoked*, *run out*, *not allowed*, *not available just
   now* (or *not started from this sign-in page*). The address carries only that kind
   (`?certsaid=revoked`), never words: a link of anybody's cannot put a sentence on the page.
   The reason itself - which group, which SID, which CDP - is in *Events* (*Sign-ins*,
   *Portal*), and *Try my certificate* says it to an administrator. No private part of a
   certificate is written anywhere: its subject and serial at most.
10. **"No password at all - only Windows or a certificate"** (`admin_password_off`,
    `portal_password_off` - one switch for both ways): switched on only from a sign-in made with
    Windows or a certificate (for the portal: an administrator's own portal sign-in in the same
    browser, as with Kerberos); in effect only while one of them can sign anybody in - this part
    on with authorities put in, or Kerberos on with a keytab. Not known after a start whether
    they are put in: in effect (closed, never open). The way back, as root:
    `acme --set admin_password_off=0`.
11. **Sign-ins end with what opened them.** The sessions say how they were made (`how:
    certificate`, shown by `whoami`). This part switched off, or its last authority taken away,
    ends the sign-ins made with a certificate - but the one of whoever did it; "no password at
    all" coming into effect ends those made with a password.

## What the person sees

- **The sign-in page**: the form, and under it *or* and **Sign in with a certificate** (beside
  *Sign in with Windows* when that is on too). With "no password at all", the buttons only.
- The browser goes to `https://<the name>:8443/...`, shows its certificate chooser (Windows: the
  card's PIN), and comes back to the page on 443 **signed in** - then the second step or the
  one-time code, as after a password.
- **Refused**: back on the sign-in page, the kind said under the button; the form stays.

## The settings

### The administration - *Settings → Accounts → Signing in with a certificate*

| Setting | Default | What |
|---|---|---|
| `admin_certlogin` - *Sign administrators in with a certificate* | off | The switch; means something only once a directory is chosen for administrators. |
| `certlogin_port` - *The certificate's own port* | 8443 | **One port for both parts** (the nonce and the address say which part). 80, 443, 22, 53, 161, 1812, 5432, 3306, acme's API, its SSH gate, its DNS server's and SNMP's ports are refused, and so is a port **another program listens on** (below). 8443 is SELinux's `http_port_t` already; another port is given to nginx with `semanage port -a -t http_port_t`. |
| `admin_certlogin_match` - *Which account a certificate is* | compat | compat / strong / upn (rule 5). |
| `admin_certlogin_crl` - *Check that a certificate is not revoked (CRL)* | on | Rule 3. |
| `admin_password_off` - *No password at all - only Windows or a certificate* | off | Rule 10 (in *Accounts*, beside the directory). |

### The portal - *Settings → The enrolment pages → Signing in with a certificate*

| Setting | Default | What |
|---|---|---|
| `portal_certlogin` - *Sign people in with a certificate* | off | The portal's own switch; the portal must be on, and a directory set for it. |
| `portal_certlogin_match`, `portal_certlogin_crl` | compat, on | As the administration's, for the portal. |
| `portal_password_off` | off | As the administration's, for the portal. |

**Alerts**: *Alerts and reports → Sign-ins with a certificate refused* (`alerts_certlogin`, off)
mails each refusal, of either part.

Why one port for both parts: a second port would be a second hole in the firewall and a second
server per name for nothing - the part is known from the page that made the nonce, the cookie's
name and path (`acme_certn_admin` on `/admin/`, `acme_certn_portal` on `/`) and the address on the
port (`/admin/` or `/`), and the parts' switches stay independent: the port serves only the parts
switched on, the other part's address there answers that it is off.

### The card

Under each part's switches, as otp's (*the authorities* are shared):

- each fact of that part: the port, the directory, how a certificate is matched, revocation, the
  second step or code after it, a password offered or not, Windows on or off, the other part;
- **the authorities** - subject, issued by, valid to, SHA-256; **Put in an authority…** (PEM,
  DER or `.p7b`; a person's certificate is refused; the same one twice changes nothing) and
  **taken away one by one** (a full administrator). Where the people's certificates come from an
  authority of acme's own (*Certificates → Authorities*), **Trust acme's own authority X** puts it
  in with the chain above it;
- **Try my certificate** - opens the port in a new tab: the browser offers its certificate, and
  the tab comes back to this card saying who it would sign in to *this part* and as what (or
  why not, in full) - nobody is signed in. It works for a part not switched on yet, as long as
  the port is served (one part on); the best way to find a wrong template first;
- **the CRLs fetched** - address, good or not had, fetched, next update;
- **each node** - heard from, the authorities written out (the same set as the database's),
  nginx listening on the port, or **the program that holds the port there**;
- the guides: the AD CS template, a YubiKey, the browsers and the network.

## How it works

```
browser (443)                    browser (:8443)                     acme daemon
 │ "Sign in with a certificate"
 │ POST ?api=cert-nonce ──► nonce in an HttpOnly SameSite=Strict cookie, the URL of :8443 with it
 │ location.href = https://name:8443/admin/?api=cert-login&n=<nonce>
 │                               │ TLS: nginx sends the authorities' names (CertificateRequest);
 │                               │ the browser offers a certificate of them - the card's PIN
 │                               │ nginx (optional_no_ca) ─► the page: ACME_CERT_PEM (escaped)
 │                               │ the page: the nonce == the cookie, its MAC, its age?
 │                               │   POST /api/auth/cert {cert} ──────────────► │ chain (authorities only)
 │                               │                                              │ dates, EKU, no CA
 │                               │                                              │ the CRL at its CDP (cached)
 │                               │                                              │ UPN ─► AD ─► sAMAccountName,
 │                               │                                              │   the same DN, on, groups
 │                               │                                              │ SID ext == objectSid
 │                               │ ◄────────────────────── {token, mfa}        │ session (how: certificate)
 │                               │ Set-Cookie session (no port in a cookie: good on 443 too)
 │ ◄──── 303 https://name/admin/ (signed in, or ?certsaid=<kind>)
 │ mfa? → the second step (the portal: the one-time code)
```

- **The page** (`acme_cert_nonce`, `acme_cert_port` in `web/acme-api.php`): on 443
  `?api=cert-nonce` (both pages) and `?api=cert-try-nonce` (the card); on the port only
  `?api=cert-login` and `?api=cert-try` - told by nginx's `ACME_CERT_PORT`, a parameter of that
  server, never a header of the browser's. A certificate longer than 64 kB escaped is said to be
  too large, never cut and sent on.
- **The daemon** (`acmelib/engine/393_signing_in_with_a_certificate.py`): `POST /api/auth/cert`
  (the administration), `POST /api/portal/cert` (the portal; let through while the nodes are
  apart, as its password sign-in), `POST /api/certlogin/try`, `GET/POST /api/certlogin` (the
  card; put in, take away). The directory lookups and the session are the code Kerberos uses
  (`sso_admin_would`, `sso_portal_would`, `sso_admin_open`).
- **The authorities** are kept in the database (`meta` row `certlogin:cas`), signed under *the
  database's word, signed* (`db_guard`): an authority written into the database past acme is not
  taken. Each node writes them out itself to `/var/lib/acme/certlogin/cas.pem` (0600, the
  service's own user, the folder 0700) within seconds - a node put back from a backup, joined
  later, a database put back: the same. nginx's copy is root's (`/etc/nginx/certs/acme-certlogin-ca.pem`, 0600).
- **nginx**: the root helper (`deploy/acme_web.py`) writes `/etc/nginx/conf.d/acme_certlogin.conf`
  - a server for **this node's name** and one for **the VIP address's**, each with the
  certificate that name has on 443, listening on the port; who may reach it as who may reach that
  part's pages (*Settings → Firewall → Who may reach the pages*); `ssl_client_certificate` the
  authorities; `ssl_verify_client optional_no_ca`; `error_page 495` to the page (a certificate
  nginx refuses itself - run out - is said as *run out*, not nginx's own 400 page); only the
  sign-in's two addresses, with exactly the query the page builds; everything else 404. Switched
  off, the file and the authorities' copy are taken away. `nginx -t` before the reload; after it
  the port is checked to answer - when it does not, the servers are taken away again, never left
  for nginx to fail on at its next start.
- **The firewall**: while either part is on, *What acme lets in by itself* has **Signing in with
  a certificate** - tcp `certlogin_port` from the networks that may reach the pages of the parts
  switched on (from everybody when one of them is for everybody); gone when both are off.
- **The sign-in protection** is the same as for passwords and tickets
  ([sign-in-protection.md](sign-in-protection.md)): refused certificates are counted per address
  (`certlogin`, `portal-certlogin` under *Locked out*), *Block a place that keeps guessing*
  counts them, every refusal and every sign-in is an event - and so goes to isemon and the SIEM.

## Another program on the port

Before the port is given to nginx it is checked on every node: is anything other than nginx
listening on it (`/proc/net/tcp` and `tcp6`, the owning process found by its socket)? A WAF's
agent, another web server, a monitoring tool:

- **saving** a port (or switching a part on) that another program holds on this node is refused:
  *port 8443 is used by haproxy (pid 1234) on acme1 - choose another port*;
- **the root helper** of every node checks again before it writes nginx's server: a port taken
  there is not given to nginx (nginx would not start again with it) and the card's *Each node*
  says which program has it;
- after the reload the port must answer, or nginx's servers for it are taken away again.

acme's own pieces never listen on 8443: its API is on 127.0.0.1:9861 (`api_port`), its SSH gate
on 127.0.0.1:18129-18199, SNMP on udp 161, its DNS server on 53, ACME's HTTP-01 and the CRLs
(`/pki/`) on nginx's port 80, certificates pushed here (acme push) and the portal's sign-in by a
load balancer on 443 - none of them can be chosen as the certificate's port either. The tests'
servers (php -S, the demo) use ports of their own.

## Behind a load balancer or a WAF

- **The port must reach the nodes as TCP (passthrough)**: TLS has to end on the node, which alone
  can ask for and see the client's certificate. A balancer or WAF that ends TLS (an HTTP/HTTPS
  profile, an "SSL offload") cannot hand the client's certificate on - the sign-in sees none.
  Give the port a **TCP / SSL-bridge (L4) listener**: HAProxy `mode tcp`, F5 a Standard virtual
  server with no client SSL profile (or *Performance (Layer 4)*), NetScaler `TCP`/`SSL_BRIDGE`,
  FortiWeb/FortiADC a layer-4 virtual server.
- **The balancer's own ports do not clash** with the nodes': its listener of 8443 is on *its*
  address - another machine. The live check above is about each node only.
- The balancer's health check of the port is a TCP connect (nginx asks for a certificate only
  when one is offered; there is nothing to fetch there).
- **acme's sign-in by a load balancer** ([portal-sso.md](portal-sso.md), `portal_sso`) stays on
  443 and does not touch this: both may be on, each by its own switch.
- The name the browser uses on the port is the one it opened the pages by (the VIP's or a
  node's): each has its server on every node, with the certificate it has on 443.

## Setting up AD CS and a YubiKey

1. **A template** from *Smartcard Logon* (or *User*): *Subject Name* built from Active Directory
   with the *User principal name (UPN)* in the SAN; *Extensions*: Client Authentication, Smart Card
   Logon; published on the issuing authority. Since KB5014754 the authority writes the SID
   extension by itself for an online template built from AD.
2. **The authority's Extensions**: a CRL Distribution Point over **http**, reachable from the
   nodes (the default `http://<server>/CertEnroll/...` is).
3. **A YubiKey (PIV)**: enrolled from Windows (the template's smart card enrolment, `certreq`), or
   with YubiKey Manager - a CSR from slot 9a signed by the authority, imported back to 9a:
   ```
   ykman piv keys generate --algorithm ECCP256 9a pub.pem
   ykman piv certificates request --subject "CN=jnovak" 9a pub.pem req.csr
   certreq -submit -attrib "CertificateTemplate:SmartcardLogon" req.csr person.cer
   ykman piv certificates import 9a person.cer
   ```
4. **acme**: put in the issuing authority and its root (*Put in an authority…*, or
   `acme --cert-login-ca issuing-and-root.p7b`).
5. **The browsers** need no setting. Edge and Chrome may pick the certificate by policy
   (`AutoSelectCertificateForUrls`, `{"pattern":"https://acme.corp.example:8443","filter":{"ISSUER":{"CN":"Corp Issuing CA"}}}`);
   Firefox reads a card through its PKCS#11 module (OpenSC) or the certificates of Windows with
   `security.osclientcerts.autoload`.

## Switching it on

1. AD CS and the cards as above; the authorities put in.
2. One part switched on (the port is served from then on), *Try my certificate* on the card of
   each part: "Would sign in nested@corp.example → nested, full admin". It says why not when not
   - a template without the UPN, a CDP the nodes cannot reach, a group missing.
3. The other part's switch when wanted. The button is on its sign-in page from then on.

## The command line

```
acme --cert-login                     each part on or off, the port, the authorities, the CRLs
                                      fetched, each node (--json)
acme --cert-login-ca FILE             put in authorities (PEM, DER or .p7b) - every node writes them out
acme --cert-login-ca-off SHA256 --yes take one away (the first 12 characters of it or more)
acme --set admin_certlogin=1          the switches as any other setting: portal_certlogin,
acme --set certlogin_port=8443          admin_certlogin_match, admin_certlogin_crl, ...
acme --set admin_password_off=0       the way back from "no password at all" (switched on only from the pages)
```

## Backups, the configuration, the cluster

- **The cluster**: the authorities and the switches are rows of the shared database; each node
  writes its copy and its nginx server itself (the node's name and the VIP address's). The card
  shows each node's.
- **Backups** carry the database: a node put back from one writes the authorities out by itself,
  and its root helper gives nginx the port again.
- **The exported configuration** (`acme --export-config FILE`; the pages' export) carries the
  authorities whole (`certlogin.cas`, public certificates); read back, each is checked before
  anything is applied, a person's certificate refused. A file read back never switches "no
  password at all" on.

## Testing without a domain

`test/test_cert_login.py` makes an AD CS of its own with openssl (the kit's `testing/pki.sh`):
a root, an issuing authority, its CRL served on a port of its own, and a certificate of each
case - right, a full admin, no SID, another account's SID, revoked, run out, Server
Authentication only, no UPN, no group, switched off in AD, not in AD, another authority (whose
root is put into the system's store for the test: still refused), a CDP that does not answer.
It checks: off → no button, no port, no firewall rule; the authorities (a person's refused, DER
and `.p7b` read, written 0600, taken away one by one); the port (443, 80 and acme's own refused,
a port held by another program refused with its name); signed in with the right role; every
refusal with its kind, the reason in Events, nothing of it to the caller; compat / strong / upn;
revocation off; the second step; "no password at all" from a certificate's sign-in only, the
passwords then refused and the certificates' sign-ins ended when switched off; the portal by
itself; Try my certificate; the command line and the export; through the pages (php -S as nginx
hands them the certificate): no nonce, a wrong one, another part's, one use, the cookie, back to
443; and **a real nginx with php-fpm** with the servers the root helper writes: the authorities'
names sent on the port, 443 asking nobody, nothing but the sign-in served, an expired
certificate (nginx's 495) said as *run out*, signed in to both parts.

A real browser: Playwright's `newContext({clientCertificates: [{origin: 'https://name:8443',
certPath, keyPath}]})`.
