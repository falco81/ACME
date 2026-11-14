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
3. **Revocation fails closed - and is seen within ten minutes.** The CRL at the certificate's
   CRL Distribution Point is fetched **only for a certificate whose chain is good** - never an
   address written into anybody's certificate - and so is the CRL of **every authority above
   it** but the root (`openssl verify -crl_check_all`: an issuing authority its root revoked signs
   nobody in; a root, its own anchor, needs no CDP - an issuing authority whose certificate names
   no http CDP is refused, as a person's is). Where the certificate or its CRL names a **delta CRL**
   (*Freshest CRL*, 2.5.29.46 - AD CS publishes a base CRL weekly and a delta daily by default) it
   is fetched as well and applied (`-use_deltas`); one named and not to be had is no sign-in. A
   CRL is kept **ten minutes at most** (`CL_CRL_FRESH_S`), or until its next update when that is
   sooner, then fetched again; its signature and dates are checked by openssl. **The lag**: a
   certificate revoked at the authority stops signing in once the authority has *published* a CRL
   (base or delta) with it, plus at most ten minutes - so with AD CS's defaults up to a day (the
   delta's period) unless a CRL is published by hand (`certutil -CRL`) after revoking a lost
   card. A CDP that does not answer: the last good CRL until its next update, then no sign-in.
   Where a CRL is fetched from: **http only**, no user or password in it, and **every address its
   name resolves to** is checked as it is fetched - no loopback, link-local (169.254.0.0/16,
   fe80::/10 - a cloud's metadata service), multicast, unspecified or reserved address, no
   metadata name (`metadata.google.internal`, ...), numbers in any form (`2852039166`,
   `0251.0376.0251.0376`) read as the resolver reads them; **private addresses (RFC 1918,
   fc00::/7) are fetched from** - AD CS's CDPs are inside. The connection goes to the address
   checked (never looked up again), **no redirect is followed**, 8 MB and 15 s at most. It can be
   switched off per part (`*_certlogin_crl`): a lost card then signs in until its account is
   switched off in AD - the card says so.
4. **One person, one account.** The UPN is looked up in that part's directory
   (`userPrincipalName`); the account is then found by its **sAMAccountName**, exactly as a
   password or a Kerberos ticket finds it, and **the two entries must be the same DN**. Whichever
   way the person signed in first, it is the same account here.
5. **The SID (KB5014754).** Since May 2022 AD CS writes the account's SID into each certificate it
   issues from AD (`szOID_NTDS_CA_SECURITY_EXT`, 1.3.6.1.4.1.311.25.2). A UPN can be given to
   somebody else; the SID cannot be moved. *Which account a certificate is*
   (`*_certlogin_match`): **strong** (the default) - it must be there and be the account's
   `objectSid` (Microsoft's full enforcement, what Windows' domain controllers require since
   September 2025); **compat** - it must be the account's when it is in the certificate; **upn**
   - the UPN alone. compat and upn are **opt-downs**, warned on the card (*Not strong*): on any
   template of an authority put in that has Client Authentication and lets the requester supply
   the subject or the SAN (ESC1), the authority adds no SID extension, and whoever may enrol
   signs in as whatever UPN they write - a full administrator too. **Only the extension counts**:
   a SID in the Subject Alternative Name (an otherName 1.3.6.1.4.1.311.25.2.1, or the URL
   `tag:microsoft.com,2022-09-14:sid:<SID>`) is written by the requester and is never taken for
   it - strong refuses a certificate with no SID extension whatever its SAN says; one whose SAN
   SID is not the extension's is refused in every mode, and compat refuses one whose SAN SID is
   not the account's.
6. **Only accounts of the directory**, by the same rules as a password: the administration - the
   role of the first group of a role they are in (an account switched off, locked, expired, more
   than one entry: refused; a local account of acme of the same name keeps its password); the
   portal - *Who may sign in*, the groups, the role *Enrolment pages only*.
7. **The second step stays.** The certificate takes the place of the *password* only: the
   administration's second step ([admin-second-step.md](admin-second-step.md)) and the portal's
   one-time code are asked after it every time.
8. **Login CSRF closed.** The button first asks the page (POST, the page's own JSON) for a nonce:
   random, five minutes, bound by a MAC (keyed with the daemon's API token) to the part **and to
   a random value of this browser's own** in a `__Host-acme_certn_<part>` cookie (`HttpOnly`,
   `SameSite=Strict`, `Secure`, path `/`, no `Domain`: neither a sibling name nor a page over
   http can plant one). On the port the nonce's MAC must be good for the cookie's value - a link
   of somebody else's, or a nonce of another browser with its cookie planted, signs nobody in.
   **Once in the whole cluster**: the daemon keeps the nonce's random part (as Kerberos'
   authenticator, a row of each node in the shared database, five minutes and a half) - sent
   again, from wherever, it is refused (*the nonce of the page was used already*).
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
    certificate`, shown by `whoami`) and, for a certificate, the authorities of its chain. This
    part switched off, or its last authority taken away, ends the sign-ins made with a
    certificate; **an authority taken away** ends those made with a certificate of it (in both
    parts); **certificates taken more strictly** - revocation switched on, the matching made
    stricter (upn → compat → strong) - end that part's sign-ins made with a certificate. Always
    but the one of whoever did it. "No password at all" coming into effect ends those made with a
    password.
12. **Name constraints, for the UPN too.** openssl applies an authority's `nameConstraints` to
    the names it knows (DNS, e-mail, ...) - **not to the UPN**, an otherName: an authority
    constrained to `partner.example` would still sign in `nested@corp.example`. acme does it:
    an authority of the chain constraining rfc822Name, dNSName (or the UPN's own otherName)
    takes the UPN only within one permitted subtree of those (`partner.example` - that host;
    `.partner.example` - under it; a dNSName - the domain and under it) and in none excluded.
    Other kinds of constraints (a directory name, an address) are left to openssl.

## What the person sees

- **The sign-in page**: the form, and under it *or* and **Sign in with a certificate** (beside
  *Sign in with Windows* when that is on too). With "no password at all", the buttons only.
- **At once when the page opens** (`admin_certlogin_auto`, `portal_certlogin_auto`, off): the
  page says *Going to your certificate…* and goes to the port by itself - the chooser, the PIN -
  without a click; *Use a password instead* under the form stops it (the address then says
  `?nocert`, and the tab stays with the password). Never by itself again in that tab after **Sign
  out**, after a **refusal** or a **certificate not chosen** (back with `?certsaid=`), nor with
  `?nocert`; and in any case at most once in ten minutes and three times a tab - a setup where
  the sign-in never sticks (or the browser's own error page and Back) never loops. With Windows
  by itself too: see *The sign-in page - the variants* below.
- The browser goes to `https://<the name>:8443/...`, shows its certificate chooser (Windows: the
  card's PIN), and comes back to the page on 443 **signed in** - then the second step or the
  one-time code, as after a password.
- **Refused**: back on the sign-in page, the kind said under the button; the form stays.

## The settings

### The administration - *Settings → Accounts → Signing in with a certificate*

| Setting | Default | What |
|---|---|---|
| `admin_certlogin` - *Sign administrators in with a certificate* | off | The switch; means something only once a directory is chosen for administrators. |
| `admin_certlogin_auto` - *...by itself when the sign-in page opens* | off | On: the page goes to the certificate at once (above); off: the button. |
| `certlogin_port` - *The certificate's own port* | 8443 | **One port for both parts** (the nonce and the address say which part). 80, 443, 22, 53, 161, 1812, 5432, 3306, acme's API, its SSH gate, its DNS server's and SNMP's ports are refused, and so is a port **another program listens on** (below). 8443 is SELinux's `http_port_t` already; another port is given to nginx with `semanage port -a -t http_port_t`. |
| `admin_certlogin_match` - *Which account a certificate is* | strong | strong / compat / upn (rule 5) - compat and upn are opt-downs, warned on the card. |
| `admin_certlogin_crl` - *Check that a certificate is not revoked (CRL)* | on | Rule 3. |
| `admin_password_off` - *No password at all - only Windows or a certificate* | off | Rule 10. In the card **The sign-in page** (*Accounts*) - one switch of both ways. |

### The portal - *Settings → The enrolment pages → Signing in with a certificate*

| Setting | Default | What |
|---|---|---|
| `portal_certlogin` - *Sign people in with a certificate* | off | The portal's own switch; the portal must be on, and a directory set for it. |
| `portal_certlogin_auto` - *...by itself when the portal opens* | off | As the administration's, for the portal. |
| `portal_certlogin_match`, `portal_certlogin_crl` | strong, on | As the administration's, for the portal. |
| `portal_password_off` - *No password at all on the portal - only Windows or a certificate* | off | As the administration's, in the portal's card **The sign-in page**. |

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
  second step or code after it, the other part;
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

## The sign-in page - the variants

A password, Windows (Kerberos) and a certificate fit on one sign-in page; each part (the
administration, the portal) by its own switches. The rules, whatever is set:

1. **Everything new is off by default** - an installation that sets nothing has the name and
   password form and nothing else.
2. **The password stays** until it is switched off on purpose (*No password at all*); Windows and
   the certificate are added beside the form.
3. **One person, one account**: a password, a Windows ticket and a certificate all land in the
   same account of the directory (its `sAMAccountName`); a local account of the same name keeps
   its password and is never signed in by Windows or a certificate.
4. **The second step** (the administration) **or the one-time code** (the portal) is asked after
   every way, every time - and the other ways' buttons are not on that screen.
5. **Nothing is tried by itself twice**: per browser tab (`sessionStorage`: Windows tried, the
   certificate tried, signed out), never after *Sign out*, never after a refusal; `?certsaid=`
   is shown as text and taken out of the address.
6. **Refusals say why** on the page (the kind - *not allowed*, *revoked*, ...), the whole reason
   in *Events*.
7. **Never locked out**: *No password at all* is in effect only while Windows or a certificate is
   on; the keytab, or the last authority, cannot be taken away while it alone signs people in to
   a part with no password; the way back as root is `acme --set admin_password_off=0`
   (`portal_password_off=0`).

The variants (the same for `/admin/` and the portal):

| | The page |
|---|---|
| 1. Only the password (the default) | the form, nothing else |
| 2. The password and Windows | *Sign in with Windows* under the form, after *or* - a button, or tried by itself (silently: outside the domain nothing is said and the form stays) |
| 3. The password and a certificate | *Sign in with a certificate* under the form - a button, or gone to by itself (the chooser, the PIN; back to the form with the reason when it did not work). With people who often type a password, keep it a button |
| 4. The password, Windows and a certificate | both buttons under the form; what is tried by itself below |
| 5. No password at all | the buttons only, no form; with Windows the only way on, Windows is tried by itself whatever its own switch says; a certificate alone stays a prominent button unless its switch says otherwise |

When the page opens, with both ways on:

| Windows (`*_krb_auto`) | A certificate (`*_certlogin_auto`) | When the page opens |
|---|---|---|
| a button | a button | nothing - the person chooses |
| by itself | a button | Windows, silently; outside the domain the form and the certificate's button stay |
| a button | by itself | the certificate at once; back to the form if it does not work |
| by itself | by itself | **Windows first, silently**; the certificate **only when this computer has no Windows ticket** (outside the domain, with a smart card) |

**A refusal of either is not a reason to try the other**: a person whom Windows refuses (no
group, switched off) is told so, and nothing else starts - only "this computer has no ticket at
all" moves on to the certificate. *Use a password instead* (`?nocert`) under the form keeps the
certificate from going by itself in that tab; and however a setup is broken, the certificate is
gone to by itself at most once in ten minutes and three times a tab.

**No ticket in this browser** (a computer outside the domain): when Windows tried by itself
ends with no Kerberos ticket at all - the browser sent nothing, its own *Sign in* dialog was
cancelled, or NTLM or a password typed into that dialog came instead (the daemon's category
*no Kerberos ticket*, `code: no_ticket` to the page - the words stay the generic ones) - the
browser remembers it (`localStorage`, per part, with the time) for **30 days**: Windows is not
tried by itself there any more, so the browser's dialog does not pop up on every visit; the
certificate by itself (if on) follows as after no ticket. The button keeps working, and a Windows
sign-in clears the memory. A computer of the domain is not concerned (a real ticket signs in,
nothing is remembered), and a refusal of a real ticket is never remembered. With no password and
Windows the only way, the page then shows the button and says *this browser had no Windows ticket
- press the button to try again* instead of trying by itself.

**The settings**: each way's card keeps its own switches (*...by itself when the sign-in page
opens* among them - "Not in use while ... is off", and not to be changed, until its way is on);
the card **The sign-in page** (one in *Accounts*, one in *The enrolment pages*) holds the switch
both share - *No password at all - only Windows or a certificate* - and says what a person meets
now: name and password offered or not, each way off, a button or by itself, what is tried when
the page opens, after a refusal and after *Sign out*, and the way back.

**How the page decides**: `/api/health` (the administration) and `/api/portal/info` (the portal)
carry `signin: {on, auto, cert, cert_port, cert_auto, only}` (and `password`, `windows`,
`certificate` - `off` / `button` / `auto` - and `order`); `acme --kerberos` and `acme --cert-login`
print the same line. The page: a second step owed - that only; else Windows by itself (not tried
in this tab, not signed out) - signed in, refused (said, stop), or no ticket (on to the
certificate when it goes by itself); else the certificate by itself (not tried, not signed out,
not just refused); else the name field.

## How it works

```
browser (443)                    browser (:8443)                     acme daemon
 │ "Sign in with a certificate"
 │ POST ?api=cert-nonce ──► the URL of :8443 with a nonce; its MAC bound to a __Host- cookie's value
 │ location.href = https://name:8443/admin/?api=cert-login&n=<nonce>
 │                               │ TLS: nginx sends the authorities' names (CertificateRequest);
 │                               │ the browser offers a certificate of them - the card's PIN
 │                               │ nginx (optional_no_ca) ─► the page: ACME_CERT_PEM (escaped)
 │                               │ the page: the nonce's MAC for the cookie's value, its age?
 │                               │   POST /api/auth/cert {cert, once} ────────► │ the nonce once (cluster)
 │                               │                                              │ chain (authorities only)
 │                               │                                              │ dates, EKU, no CA, UPNs
 │                               │                                              │ name constraints (UPN)
 │                               │                                              │ CRL + delta of each
 │                               │                                              │   in the chain (10 min)
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

Before the port is given to nginx it is checked on every node: is anything other than **acme's
nginx** listening on it (`/proc/net/tcp` and `tcp6`, the owning process found by its socket)? A
WAF's agent, another web server, a monitoring tool - or **another nginx** (a container's, another
product's): a process named nginx is acme's only when it is the master the system's pid file
names (`/run/nginx.pid`) or a worker of it, started with the system's configuration
(`/etc/nginx/nginx.conf`, no other `-c` or `-p`); any other is *nginx that is not acme's*:

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
- **Lockouts behind an L4 balancer.** A layer-4 listener hands the nodes the balancer's address,
  not the client's: every refused certificate is then counted against that one address, and
  *Block a place that keeps guessing* (`certlogin`, `portal-certlogin`) would lock everybody out
  at once - or, with the balancer's address trusted, nobody. Either let the balancer keep the
  client's address (HAProxy `mode tcp` with `source 0.0.0.0 usesrc clientip` - transparent, the
  nodes' route back through it; F5 SNAT off), or send the **PROXY protocol** and have nginx read
  it: `listen 8443 ssl proxy_protocol;` with `set_real_ip_from <the balancer>;` and
  `real_ip_header proxy_protocol;` in the port's server - not written by acme's root helper
  today: added by hand, it is overwritten at the next change of the port's servers. Until one of
  them is in place, raise the limits of *Sign-ins* or keep the port reachable from inside only.
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
   nodes (the default `http://<server>/CertEnroll/...` is) - with *Include in the CDP extension
   of issued certificates* **and** *Include in CRLs. Clients use this to find Delta CRL
   locations* ticked for that http location, so that the delta CRL is found too. The **issuing
   authority's own certificate** needs an http CDP as well (the root's CRL - set on the root
   before it issued it), since the issuing authority's revocation is checked too; the root needs
   none. After revoking a lost card, publish a CRL (`certutil -CRL`, or *Revoked Certificates →
   All Tasks → Publish*): acme sees it within ten minutes.
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
acme --set certlogin_port=8443          admin_certlogin_auto, admin_certlogin_match, admin_certlogin_crl, ...
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

The security review's cases (1.0.100) are in it too, the PKI made for them: the root's CRL and
an issuing authority the root revokes (refused - F4); a SID in the SAN only (ESC1: refused by
strong), one not the extension's or the account's (F1); five UPNs, the fifth another's (F6); a
person revoked after its CRL was fetched - taken from the cache, refused once ten minutes have
gone by; a revocation in the delta CRL only, a delta named and not to be had, the CDP down (the
last good CRL until its next update) (F3); where a CRL is fetched from - `localhost`,
`2852039166`, a redirect to 169.254.169.254, a CRL too large (F5); the nonce sent twice, a nonce
of another browser (F7); a partner's authority constrained to `partner.example` with a corpnet
UPN, which openssl alone takes; sign-ins ended by an authority taken away and by rules made
stricter; a process named nginx that is not the system's on the port (F8). The tests' CRLs are
served on 127.0.0.1: `ACME_CDP_LOOPBACK_OK=1` in the test daemon's environment lets loopback be
a CDP there - never set by acme.

`test/test_signin_modes.py` puts the two ways together (the realm of `test_kerberos.py`, the PKI
of this one): what the pages are told of each part, the order, both sign-ins with "no password at
all" and a password refused, the pages through php -S; and the page's own logic run with node -
Windows first, no loop after a refusal, a certificate not chosen, Sign out, `?nocert`, or a setup
that never signs in.

A real browser: Playwright's `newContext({clientCertificates: [{origin: 'https://name:8443',
certPath, keyPath}]})`.
