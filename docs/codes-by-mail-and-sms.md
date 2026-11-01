# Codes by e-mail and SMS - the VPN's second window

Since 1.0.76 a token does not have to be an app on a phone. A realm can offer
three kinds, and the person chooses on the enrolment pages:

| Kind | What the person has | How they sign in |
|---|---|---|
| **The app** (TOTP) - as always | an authenticator app with a QR code scanned | as the realm says: the code alone, the password followed by the code, or the code in a second window |
| **A code by e-mail** | an address that was proven, recovery codes | the directory password; the VPN then shows a second window and a code is mailed |
| **A code by SMS** | a number that was proven, recovery codes | the same, the code goes by SMS |

Tokens of every kind work side by side in one realm and on one VPN. Nothing
changes for anybody who keeps the app.

## How the second window works (RADIUS Challenge/Response)

1. The person types their directory name and password into the VPN client
   (Cisco Secure Client, and others).
2. The VPN sends an `Access-Request` with that password.
3. acme checks the realm, the account in the directory (switched off,
   expired), the password and the groups - exactly as for an app token. A
   wrong password ends here: **no code is sent**.
4. acme makes a code, sends it by e-mail or SMS and answers with an
   `Access-Challenge`: a `State` and a `Reply-Message` such as
   *"Type the code sent by SMS to +420\*\*\*\*\*\*222"*.
5. The VPN client shows a second window. The code comes back in a second
   `Access-Request` carrying that `State`.
6. acme compares it and answers `Access-Accept` - with the realm's and the
   group's reply attributes, worked out in step 3 - or asks again.

Rules:

- A code is good for *Codes by e-mail and SMS → A sent code is good for*
  (300 s) and **once**.
- A wrong code is asked again; after *Wrong codes before it has to be sent
  again* (3) the person signs in again and gets a new code. Every wrong
  code counts towards the token's lockout, as a wrong code from the app
  does.
- At most *Codes sent to one person* (5) codes in *… in (minutes)* (15) are
  sent, so nobody fills a mailbox or a phone by signing in again and again.
- **A recovery code** works in the second window in place of the sent code.
- The challenge is kept in the database: in a cluster the code may be typed
  into either node (the VPN with two RADIUS servers in its group).
- The code itself is never stored - only a keyed hash of it.

### A realm in the "second window" mode for the app too

*Realms → The password is → the directory password; the code in a second
window* makes the app's tokens sign in the same way: the password alone,
then *"Type the code from the app on your phone"*. Useful when the VPN users
should all see the same two windows. In the other modes the app's tokens
work exactly as before, and only the mail and SMS tokens get the second
window.

## Setting it up

1. **Mail** (Settings → Mail) for codes by e-mail - the same settings as a
   token's QR code by mail.
2. **SMS** (Settings → Codes by e-mail and SMS → How SMS is sent):
   - *an SMS gateway with an HTTP API* - the address (`{to}`, `{to_digits}`,
     `{text}`, `{token}`), GET or POST, a body (JSON when it starts with
     `{`, a form otherwise), headers (`Authorization: Bearer {token}`), the
     key kept sealed, and optionally a word the answer holds when the
     message was really sent;
   - *a modem on this machine* - acme writes each message into the spool
     folder of **smstools3** (`/var/spool/sms/outgoing`): a file
     `To: 420603123456`, an empty line, the text. The service runs as
     `acme`: give it write access to the folder (a group and `chmod g+w`).
     gammu-smsd can read the same files with its files backend.
   - *a Teltonika gateway* (TRB140, RUT… - the box zigmon sends its texts
     through): its address, HTTPS, a user that may use its API and its
     password, and the interface - RutOS 7's own API (the default) or the
     older Post/Get SMS service (switched on by hand under Services → Mobile
     Utilities → SMS gateway). Only sending; nothing is read from it.
   - *Without accents* (on by default) keeps the code in one SMS: one
     accented letter makes the whole message 70 characters a part.
   - *Send a test SMS* shows what the gateway answered.
3. **The realm** (Realms → edit → *People may choose*): tick the app, a code
   by e-mail, a code by SMS. Mail and SMS need the realm's directory - a
   code is only ever sent after the directory password. A way of sending
   that is not set up is not offered on the enrolment pages.

From the command line:

```
acme --add-realm example.cz --methods totp,mail,sms
acme --add-realm example.cz --mode challenge          # the app in the second window too
acme --enroll novak@example.cz --by sms --to "+420 603 123 456"
acme --enroll novak@example.cz --by mail --to novak@example.cz
acme --radtest novak@example.cz 'directory-password'   # asks for the code of the second window
```

`radtest` from freeradius-utils cannot send the State back; `acme --radtest`
and the Test tab can. With `radclient`:

```
echo 'User-Name = "novak@example.cz", User-Password = "123456", State = 0x6f7470…' \
  | radclient -x acme1:1812 auth <secret>
```

## When a code does not arrive

- **Test the connection** under the Teltonika gateway (*Settings → Codes by
  e-mail and SMS*) signs in to the gateway with what is saved and lists its
  modems: operator, network, signal (RSSI/RSRP/RSRQ/SINR), the SIM, which modem
  sends the codes, and how long each step took. Nothing is sent. A test SMS
  goes from a token's card (*Send a test*).
- **Debug log → ...every code sent by e-mail and SMS** (*Settings → About*,
  on with *Debug log*) writes every request to the SMS gateway and its answer,
  with how long it took, and every line of the conversation with the mail
  server into `/var/log/acme/acme.log` (lines `sms: ...` and `mail ...`).
  Passwords, the gateway's token and the messages themselves are never
  written.
- *The Teltonika could not be reached: The read operation timed out* - the
  gateway took the connection but did not answer in time (15 s for signing
  in, 20 s for an SMS). A sign-in is asked again once by itself. Seen often:
  the box is busy (another program sending through it, a modem
  re-registering) or its RutOS API is slow - the debug log shows which
  request waited. A send that timed out is not sent again: the SMS has most
  likely gone, and a second one would arrive twice.

## Enrolling (the enrolment pages)

1. The person signs in with their directory name and password. Only who
   passes the realm's group filter (and *Who may enrol*) gets further, as
   for the app.
2. They choose a way among those the realm offers. For e-mail and SMS the
   address or the number from the directory (`mail`, `mobile` /
   `telephoneNumber`) is filled in; they can change it.
3. A code is sent there; they type it back. Only then is the token made -
   with the address or the number and the recovery codes (shown once, when
   *Show the recovery codes* (Settings → The enrolment pages) is on). Nothing to scan.
4. Changing the address, the number or the way later: password and a code
   sent to the current address or number (*Send me a code*) - or a recovery
   code. The old token goes on working until the new one is made. Moving
   from the app to e-mail or SMS works the same way, with a code from the
   app.

An administrator can make such a token directly (Tokens → Make a token →
*The codes come from*), change where the codes go, send a test message, or
turn it into an app token (*The app instead*).

### Recovery codes after sign-in

*People may look at their recovery codes again* (*Settings → The enrolment
pages*, off by default) adds a card under the token: the person types a code
from the token - the app's, or one sent by mail or SMS with *Send me a code* -
and sees their recovery codes, the used ones crossed out, to copy or print. The
directory password alone never shows them: with it alone the second factor
would be one click away. Each look is written into Events; wrong codes count
towards the same pause as wrong passwords (*Settings → Accounts → Locked out*).
Tokens whose codes were never kept sealed (brought over from totpcgi, say) cannot show them;
the administrator makes new ones.

## Cisco ASA

```
aaa-server ACME protocol radius
aaa-server ACME (inside) host 10.0.0.50
 key <the shared secret>
 timeout 60
 authentication-port 1812
 accounting-port 1813
aaa-server ACME (inside) host 10.0.0.51
 key <the shared secret>
 timeout 60

tunnel-group VPN-USERS general-attributes
 authentication-server-group ACME
```

- **Leave `password-management` off** on the tunnel group: with it the ASA
  asks with MS-CHAPv2 and a code can only travel as PAP; the second window
  breaks.
- `timeout 60` - a mail or an SMS gateway can take a while; the RADIUS
  timeout is for the first answer.
- UDP 1812/1813 from the ASA to both nodes.

## Cisco FTD (FMC)

1. Objects → Object Management → AAA Server → RADIUS Server Group: both
   nodes, the shared secret, timeout 60 s.
2. Devices → Remote Access → Connection Profile → AAA: Authentication
   Method *AAA Only*, Authentication Server that group.
3. Deploy. Secure Client shows the second window by itself.

## What to keep in mind

- **E-mail is the weaker second factor.** Where the mailbox opens with the
  same directory password (OWA), whoever stole the password reads the code
  too. Prefer SMS or the app where possible.
- The VPN log (Log → RADIUS) shows the first request as *asked for the
  code* (`Access-Challenge`) and the answer as *let in* or *refused*; the
  token's history shows *sent by SMS*, *code by SMS* and failures to send.
- A failure to send (no mail server, the gateway refusing, the spool folder
  not writable) is written into Events at once.
