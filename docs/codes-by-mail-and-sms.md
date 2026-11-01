# Codes by e-mail and SMS

(1.0.76.) acme sends a code by e-mail or SMS for the second step of an
administrator's sign-in, when it is not the app
([admin-second-step.md](admin-second-step.md)), and to check an address or a
number before it is used for that. The settings are under *Settings → Codes by
e-mail and SMS*; the words of each message under *Settings → Message texts*.

## The codes

- A code is good for *A sent code is good for* (`code_ttl_s`, 300 s) and
  **once**; it is *Digits of a code* (`code_digits`, 6) long.
- A wrong code is asked again; after *Wrong codes before it has to be sent
  again* (`code_tries`, 3) the person signs in again and gets a new code.
- At most *Codes sent to one person* (`code_send_max`, 5) codes in *… in
  (minutes)* (`code_send_window_min`, 15) are sent, so nobody fills a mailbox
  or a phone by signing in again and again.
- The code itself is never stored - only a keyed hash of it.

## Setting it up

1. **Mail** (Settings → Mail) for codes by e-mail - [mail.md](mail.md).
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
   - *Try an SMS → Send a test SMS* shows what the gateway answered.
3. **The administration's second step** (Settings → Accounts): which ways are
   offered. A way of sending that is not set up is not offered.

From the command line:

```
acme --sms-test "+420 603 123 456"      # a test SMS now, said what the gateway answered
```

## When a code does not arrive

- **Test the connection** under the Teltonika gateway (*Settings → Codes by
  e-mail and SMS*) signs in to the gateway with what is saved and lists its
  modems: operator, network, signal (RSSI/RSRP/RSRQ/SINR), the SIM, which modem
  sends the codes, and how long each step took. Nothing is sent; a test SMS
  goes from *Try an SMS*.
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
- A failure to send (no mail server, the gateway refusing, the spool folder
  not writable) is written into Events at once, and the alerts say when the
  SMS gateway keeps failing.

## What to keep in mind

- **E-mail is the weaker second step.** Where the mailbox opens with the
  same directory password (OWA), whoever stole the password reads the code
  too. Prefer the app, or SMS; high security refuses both mail and SMS
  for the administration ([high-security.md](high-security.md)).
