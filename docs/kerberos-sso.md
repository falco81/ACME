# Signing in with Windows (Kerberos SSO)

As in otp 1.0.274, since acme 1.0.99. A person signed in to Windows on a computer of the domain
opens the administration (`/admin/`) or the certificate portal (`/`) and presses **Sign in with
Windows** - or is signed in at once - without typing a name or a password. The browser sends a
Kerberos ticket for the name in its address bar, got from the domain controller with the
person's Windows sign-in; acme checks it with the key of that name from a keytab. No domain
controller is asked for it, nothing is installed: the system's GSS-API library (MIT Kerberos,
`libgssapi_krb5`) through Python's standard library.

**With a certificate** (a smart card, a YubiKey) the same pages are signed in to on a port of
its own since 1.0.100 - [certificate-sign-in.md](certificate-sign-in.md); both may be on, and
"no password at all" is one switch for both (*only Windows or a certificate*) - see *The sign-in page -
the variants* below.

**Two parts, each with its own switches** - the administration and the portal can be switched
on each by itself, or both, or neither. **Off by default**: nothing changes until an
administrator switches it on. One keytab serves both.

## The rules it keeps

1. **Never NTLM.** Only Kerberos 5. A token of NTLM - bare, inside SPNEGO, or as its own
   `Authorization: NTLM` - is refused, and so is any other mechanism of SPNEGO (checked after the
   library accepted the token). There is no setting for it.
2. **The second step stays.** Kerberos takes the place of the *password*, nothing more: the
   administration's second step ([admin-second-step.md](admin-second-step.md)) is asked after it
   every time, and the portal's one-time code by mail or SMS (*A one-time code at every sign-in*)
   is sent after it every time.
3. **Only accounts of the directory**, by the same rules as a password: the administration - the
   role of the first group of a role they are in; the portal - *Who may sign in*, the groups,
   the role *Enrolment pages only*. A local account of acme keeps its password (a ticket of the
   same name is refused). **The entry found is of the ticket's realm**: the `DC=` parts of its
   DN (or, without them, the suffix of its `userPrincipalName`) are the realm's domain - with a
   forest-wide base, `novak@CHILD.CORP.EXAMPLE` is never the `novak` of `CORP.EXAMPLE`.
4. **Once in the cluster.** A token used once is refused again on the same node and on the other
   one, also after the VIP address moved - also sent again in another wrapper (bare instead of
   SPNEGO, SPNEGO with another list of mechanisms): the key is the Kerberos request itself.
5. **Refused with 403, never a second 401** - a second 401 would make the browser try again,
   offer NTLM, or open a password window of its own. The page says only *Windows sign-in
   refused* and the kind - *not allowed*, *ticket not accepted*, *replay*, *not available just
   now*; the reason is written in *Events*, for the administrators.
6. **"No password at all"** (optional, each part its own; one switch with the certificate's
   sign-in): switched on only from a sign-in made with Windows or a certificate, in effect only
   while Kerberos is on with a keytab, or the certificate with authorities (from the first
   moment after every start); the way back for root is `acme --set admin_password_off=0`
   (`portal_password_off=0`).
7. **Sign-ins end with what opened them.** "No password at all" coming into effect ends that
   part's sign-ins made with a password; Kerberos switched off or the keytab taken away ends those
   made with Windows. Whoever made the change keeps their own sign-in.

## What the person sees

- **The sign-in page**: the usual form, and under it *or* and **Sign in with Windows**. One
  press: no name, no password. With *...by itself when the sign-in page opens*, the page tries at
  once and shows the form only when it did not work (a computer outside the domain sees the form,
  and nothing else is said). After *Sign out* it is never tried by itself again in that tab -
  otherwise signing out would sign the person straight back in.
- **Signed in** with the role of the AD groups (the administration) or to their certificates
  (the portal).
- **Refused** - *Windows sign-in refused: not allowed* (the directory or the groups do not let
  them in, another realm, a local account of that name), *...: ticket not accepted* (NTLM, a
  name not in the keytab, a token that is no Kerberos request), *...: replay* (the ticket was
  used already), *...: not available just now* (no keytab, the directory not answering). Nothing
  more to somebody not signed in: why exactly ("known to the directory, and none of the groups
  given a role here holds them", "not found in keytab") is in *Events*, and *Try my browser's
  ticket* on the card says it to an administrator. The form stays.
- **The second step** (the administration) or **the code that was sent** (the portal), exactly as
  after a password.
- **"No password at all"**: no name and no password on the page at all - only *Sign in with
  Windows* (and *Sign in with a certificate*, when that is on too).
  In the administration no *A new password* in *Your account*, no password for an account; the
  server refuses a change of a password too.

## The settings

### The administration - *Settings → Accounts → Signing in with Windows (Kerberos)*

| Setting | Default | What |
|---|---|---|
| `admin_krb` - *Sign administrators in with Windows (Kerberos)* | off | The switch. Means something only once a directory is chosen in *Sign administrators in against the directory*. |
| `admin_krb_auto` - *...by itself when the sign-in page opens* | off | The page tries Windows at once; the form only when it did not work. Never again in that tab after *Sign out*. With the certificate by itself too: Windows first (below). |
| `admin_krb_realm` - *Kerberos realm* | empty | The realm whose people may sign in, in capitals. Empty: taken from the directory's base DN (`DC=corp,DC=example` → `CORP.EXAMPLE`). Any other realm is refused - compared exactly, as realms are case-sensitive. A realm that is neither the base DN's domain nor one under it is warned of on the card: nobody of it is found in the directory. |
| `admin_password_off` - *No password at all - only Windows or a certificate* | off | In the card **The sign-in page** - one switch of both ways. See *No password at all* below. |

### The portal - *Settings → The enrolment pages → Signing in with Windows (Kerberos)*

| Setting | Default | What |
|---|---|---|
| `portal_krb` - *Sign people in with Windows (Kerberos)* | off | The portal's own switch; the portal must be on, and a directory set for it (*Which directory*, else the administrators'). |
| `portal_krb_auto` - *...by itself when the portal opens* | off | As the administration's, for the portal. |
| `portal_krb_realm` - *Kerberos realm of the portal* | empty | Its own: empty is the realm of the **portal's** directory's base DN - which may be another domain than the administrators'. |
| `portal_password_off` - *No password at all on the portal - only Windows or a certificate* (the portal's card *The sign-in page*) | off | As the administration's, for the portal; acme's own accounts then do not sign in to the portal either. |

The person is looked up in the **portal's directory** (`portal_directory`, else the
administrators'), and let in by `portal_who` / `portal_groups` and the group of the enrolment-only
accounts exactly as with a password.

**With a load balancer that signs people in** ([portal-sso.md](portal-sso.md)): both can be on.
They do not touch each other - a browser that comes through the balancer is signed in by it, a
browser of the domain that reaches the portal directly by Windows; each has its own switch, its
own refusals in *Events*. Switching one off ends only its own sign-ins.

**Alerts**: *Alerts and reports → Sign-ins with Windows (Kerberos) refused* (`alerts_kerberos`,
off by default) mails each refusal, of either part.

### The card

Under each part's switches:

- each fact of that part: the realm and where it comes from, the directory, the second step or
  code after it, NTLM never taken, and whether the other part is on;
- **the keytab** - its principals, key versions and kinds of key; never a key. Only **AES keys
  of web services** (`HTTP/name@REALM`) are kept and written out: an RC4 or DES key, a key of
  another service (`host/`, `cifs/`) or of a person is left out - said when it is put in, and
  listed on the card under *Left out of the file put in*. A keytab with nothing left is refused;
- **Put in a keytab… / Take the keytab away** (a full administrator only) - for both parts;
- **Try my browser's ticket** - asks this browser for its ticket and says who it would sign in
  to *this part* and as what, without signing anybody in. It works before the part is switched
  on: the best way to find a wrong SPN first;
- **the names the pages are opened by** - the VIP address's, each node's (as acme knows them:
  the names of their certificates, and the name each node says it has) and the one this page was
  opened by, with their SPN and whether the keytab has that name or (only) a key of the account;
- **each node** - heard from, the keytab written out (the same one as the database's), the
  Kerberos library there;
- **the commands for AD** (`setspn`, `ktpass`) filled in with these names and the realm;
- **the browsers' settings** filled in with these names.

## How it works

```
browser                         nginx + PHP (the relay)              acme daemon
   │ GET /admin/  or  /                │                                  │
   │◄── sign-in page + the button ─────┤◄─ /api/health, /api/portal/info ─┤ {kerberos: {on, auto, only}}
   │ POST ?api=kerberos-login          │── {} ───────────────────────────►│ off? 404 - the page too
   │                                   │◄── 401 ──────────────────────────│
   │◄── 401 WWW-Authenticate: Negotiate│                                  │
   │ (the browser gets a ticket for HTTP/<the name in the address bar>    │
   │  from the domain controller, with the person's Windows sign-in)      │
   │ POST, Authorization: Negotiate …  │── {header} ─────────────────────►│ NTLM? refused
   │                                   │                                  │ gss_accept_sec_context(keytab)
   │                                   │                                  │ the mechanism Kerberos 5?
   │                                   │                                  │ user@REALM - the part's realm?
   │                                   │                                  │ once in the cluster? (the database)
   │                                   │                                  │ the part's directory, by sAMAccountName:
   │                                   │                                  │   on, not locked, not expired, one entry
   │                                   │                                  │   - admin: groups → role
   │                                   │                                  │   - portal: who may sign in
   │                                   │◄── {token, who, mfa | gate} ─────│ the session (how: Kerberos)
   │◄── 200, Set-Cookie (HttpOnly, SameSite=Strict)                       │
   │ mfa / gate? → the second step / the code : reload                    │
   │ refused → 403 (never 401 again)                                       │
```

- **The relay** (`acme_kerberos_relay` in `web/acme-api.php`, `?api=kerberos-login` on both
  pages, `?api=kerberos-try` for the card) decides nothing: without `Authorization` it asks the
  daemon (off → 404 and nothing more; on → 401 with `WWW-Authenticate: Negotiate`); with it, the
  header goes to the daemon as it came (more than 65 000 characters: said so, never cut and sent
  on - the daemon's own cap is the same, `KRB_HEADER_MAX`); every refusal is 403. The ticket is never written anywhere.
- **The daemon** (`acmelib/engine/392_signing_in_with_windows.py`): `POST /api/auth/kerberos`
  (the administration), `POST /api/portal/kerberos` (the portal), `POST /api/kerberos/try`
  (the card), `GET/POST /api/kerberos` (the card's view; put in, take away).
- **The keytab** is kept in the database (`meta` row `krb:keytab`) sealed with the installation's
  key, and signed under *the database's word, signed* (`db_guard`): a keytab written into the
  database past acme is not taken. Each node writes it out itself to
  `/var/lib/acme/kerberos/http.keytab` (0600, the service's own user, the folder 0700) within
  seconds - a node put back from a backup, a node joined later, a database put back: the same.
  Taken away, every node deletes its copy. The library's own replay cache is in the same folder.
- **Once in the cluster**: `sha256` of the AP-REQ's authenticator (the cipher octets of its
  `EncryptedData`) kept a day in `meta` rows `krbonce:<hash>@@<node>`, one row per node, checked
  across all of them before anybody is signed in. SPNEGO's `NegTokenInit` and the GSS-API header
  are taken off first (the DER read strictly: a token that cannot be taken apart is refused), so
  the same request sent bare, or with another list of mechanisms, is the same key - and nobody
  can change those octets without the ticket's session key. MIT's own replay cache is one
  host's; behind the VIP address a token caught on its way could otherwise be sent to the other
  node. The portal's `/api/portal/kerberos` is let through while the nodes are apart, as its
  password sign-in.
- **The sign-in protection** is the same as for passwords ([sign-in-protection.md](sign-in-protection.md)):
  refused tickets are counted per address (`kerberos`, `portal-kerberos` under *Locked out*),
  *Block a place that keeps guessing* counts them too, every refusal and every sign-in is an
  event (*Sign-ins*, *Portal*) and so goes to isemon and the SIEM as the other sign-ins do.
- **The session records how it was opened**: `how: Kerberos` (shown by `whoami`), and it stays
  after the second step is given.
- **nginx**: a ticket of a person in many AD groups (a large PAC) is more than nginx's 8 kB header
  buffer; acme's nginx file has `large_client_header_buffers 4 64k;` - AD's largest token
  (`MaxTokenSize`, 48 000 bytes) is 64 000 characters in base64, one line of it; acme takes
  tokens up to that size (`KRB_TOKEN_MAX`). `install.sh` puts it into an older file at the
  upgrade (and raises acme's own `4 32k` of before), the pages' root helper into the HTTPS server
  if it is missing. The sign-in is limited per address as the password sign-in is.

## Setting up AD

On a domain controller, as a domain administrator (the card shows these filled in):

1. **A service account of its own** (`svc-acme-http`): a normal user, *Password never expires*,
   *This account supports Kerberos AES 256 bit encryption*.
2. **An SPN for every name the pages are opened by** - the VIP address's name and each node's:
   ```
   setspn -S HTTP/acme.corp.example  CORP\svc-acme-http
   setspn -S HTTP/acme1.corp.example CORP\svc-acme-http
   setspn -S HTTP/acme2.corp.example CORP\svc-acme-http
   ```
3. **The keytab** (AES only) - one, of the first name; the others are served by the same key:
   ```
   ktpass -princ HTTP/acme.corp.example@CORP.EXAMPLE -mapuser CORP\svc-acme-http ^
          -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -pass * -out acme-http.keytab
   ```
4. **Put it in**: *Settings → Accounts → Signing in with Windows → Put in a keytab…*, or
   `acme --kerberos-keytab acme-http.keytab` as root. Once, for both parts and every node.

Changing the account's password later makes a new key version: make the keytab again and put it
in. Do not make a keytab per node - one key serves every name: MIT's acceptor, given no name of
its own, takes a ticket for any principal whose key is in the keytab.

## Setting up the browsers

- **Edge and Chrome on Windows** (group policy): `AuthServerAllowlist` = the names, comma
  separated. Or *Internet Options → Security → Local intranet → Sites*.
- **Firefox**: `network.negotiate-auth.trusted-uris` = the names (policy or `about:config`).
- Open the pages by the **name** - never by an address: there is no SPN for an address, and
  Windows then offers NTLM, which is refused.

## Switching it on

1. AD and the browsers as above; the keytab put in.
2. *Try my browser's ticket* on the card of the part, from a computer of the domain: "Would sign
   in jnovak@CORP.EXAMPLE → jnovak, full admin". If it says no ticket was sent, the name is not
   among the browser's intranet sites (or the page was opened by an address); if the keytab does
   not have the name, its SPN is missing on the service account.
3. The part's switch on, and saved. The button is on its sign-in page from then on.

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

## No password at all

*No password at all - only Windows or a certificate* (`admin_password_off`,
`portal_password_off`) - one switch of both ways, in the card *The sign-in page* of each part
(beside the cards of Windows and of the certificate):

- switched on **only by somebody signed in with Windows** (or a certificate) to that part - so whoever switches it
  on has seen it work for them. For the portal: an administrator of the directory signed in to
  the portal with Windows **as themselves** in the same browser (the page passes that sign-in's
  cookie with the save; its directory entry must be the administrator's own - somebody else's
  portal sign-in in that browser is refused). Never from the command line or from a
  configuration file read back - there it is only switched off;
- **in effect only while Kerberos can sign anybody in** - the part switched on, a directory, a
  keytab - **or the certificate** (on, with authorities). Switching Kerberos off brings the
  passwords back at once when the certificate is not on either. **The keytab cannot be taken
  away** (nor the last authority of the certificates) while it alone signs people in to a part
  with no password at all - refused with words (409), `acme --kerberos-keytab-off` too;
- with Windows **the only way** on (no certificate), Windows is tried by itself on the sign-in
  page whatever *...by itself* says - the page has nothing else to offer;
  Whether a keytab is there is read before the daemon serves anybody after a start; not known,
  "no password at all" counts as in effect (closed, never open);
- coming into effect, it **ends that part's sign-ins made with a password** (the one switching
  it on is signed in with Windows); Kerberos going off ends the sign-ins made with Windows, but
  that of whoever switched it off;
- in effect: no password field on that part's sign-in page, every password sign-in refused
  (403), no password changed or set (*Your account*, *Accounts*, the portal's own change). The
  other part is not concerned.

**The way back, as root** on a node:

```
acme --set admin_password_off=0       # the administration takes passwords again
acme --set portal_password_off=0      # the portal
acme --set admin_krb=0                # or Kerberos off altogether
```

## The command line

```
acme --kerberos                     each part on or off, the realm, the keytab's principals, the
                                    names and their SPNs, each node (--json)
acme --kerberos-keytab FILE         put in the keytab - every node writes it out itself
acme --kerberos-keytab-off --yes    take it away
acme --set admin_krb=1              the switches as any other setting: admin_krb_auto,
acme --set portal_krb=1               admin_krb_realm, portal_krb_auto, portal_krb_realm
acme --set admin_password_off=0     the way back from "no password at all" (switched on only from the pages)
```

## Backups, the configuration, the cluster

- **The cluster**: the keytab and the switches are rows of the shared database - replicated as
  every other; each node writes its copy itself. The card shows each node's.
- **Backups** carry the database and the installation's key: a node put back from one writes the
  keytab out by itself.
- **The exported configuration** (`acme --export-config FILE`, `--with-secrets`; the pages' export) carries what
  the keytab holds always, and the keytab itself only in a file **with the secrets** (sealed again
  with the key of the machine it is put in on). A file read back never switches "no password at
  all" on.

## Testing without a domain

`test/test_kerberos.py` makes an MIT realm of its own (krb5-kdc on a free port): the people of
`test/mockldap.py`'s directory, the web service's names, a name in no keytab, two names sharing
one key - and checks: off → 404 and no button (each part); no ticket → 401 Negotiate; the right
person → their role, or their portal; no group, not in the directory, locked out, switched off
in AD, a local account of the same name, another realm, a ticket for a name not in the keytab,
the same ticket again (on the same node, and on "the other node" through the database - also
wrapped again: bare, SPNEGO with another list of mechanisms), NTLM bare, as its own scheme and
inside SPNEGO, garbage, a 20 kB header → refused (403 through the pages, the kind only, the
reason in Events); a person of the right name in another domain of the directory; one key for
two names; the second step and the portal's code after it; "only Windows" refused from a
password sign-in (and with somebody else's portal sign-in), switched on from a Kerberos one,
passwords refused then - from the first answer after a restart too - and the password sign-ins
ended, Kerberos off brings them back and ends its own sign-ins (but the switcher's), root's way
back; the parts independent; a keytab with RC4 and other services' keys kept to its AES keys of
HTTP/; a configuration with a bad keytab changing nothing; the keytab written out, put in from
the command line, exported, taken away.

A real browser: Chromium with `--auth-server-allowlist=acme.corpnet.loc`, `KRB5_CONFIG` and
`KRB5CCNAME` in its environment, the name in `/etc/hosts` (with `--host-resolver-rules` Chromium
asks for `HTTP/127.0.0.1` instead) and no proxy in its environment.
`curl --negotiate -u : https://acme.corp.example/admin/?api=kerberos-login -X POST -H
'Content-Type: application/json' -d '{}'` does the whole 401 round as a browser does.
