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
     `acme`: give it write access to the folder (a group and `chmod g+w`). With a
     group of its own (not acme's), each file is written readable by that group
     only (0660, 1.0.44) - smsd reads it as root or as a member of the group;
     otherwise as before (0664).
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

## The settings by key

Settings → Codes by e-mail and SMS - also `acme --set KEY=VALUE`:

| Setting | Default | |
|---------|---------|--|
| Language of the codes (`code_lang`) | *empty* | The language of the mail or SMS with the code - unless the page it was asked from is in another one (the language of the page is taken then). (`''` - as the mail (Language of the mail); `cs` - Čeština; `en` - English) |
| A mail with a code is (`code_mail_fmt`) | `html` | HTML in the look of acme's other mails, the plain text always beside it - or plain text alone, for mail systems that strip HTML or people who want it so. (`html` - HTML, as acme's other mails look - with the plain text beside it; `text` - plain text only) |
| How SMS is sent (`sms_mode`) | `off` | An SMS gateway with an HTTP API (most operators and services), or a GSM modem on this machine run by smstools3 or gammu-smsd: acme writes each message as a file into its spool folder, or a Teltonika gateway (TRB140, RUT…) on the network through its own API, the way zigmon sends its texts. Off: no code and no alert goes by SMS. (`off` - off - no SMS is sent; `http` - an SMS gateway with an HTTP API; `spool` - a modem on this machine - a file into the spool of smstools / gammu; `teltonika` - a Teltonika gateway (TRB140, RUT…) on the network - as zigmon uses it) |
| Country code for numbers written without one (`sms_prefix`) | `+420` | A number typed as 603 123 456 becomes +420603123456. Empty: a number has to be typed with its country code. |
| Without accents (one SMS, not two) (`sms_plain`) | `1` | A letter with an accent makes the whole SMS the wide alphabet, 70 characters a part instead of 160: the code goes in one message when the accents are left out (kód → kod). |
| The gateway's address (URL) (`sms_url`) | *empty* | Where the message is sent. {to} is the number (+420…), {to_digits} the number without + , {text} the message, {token} the key below - each written as an address needs it. https://sms.example.cz/api/send?to={to}&text={text} |
| HTTP method (`sms_method`) | `POST` | POST sends the body below; GET only the address. (`POST` - POST; `GET` - GET) |
| The gateway's key ({token}) (`sms_token`) | *empty* | The gateway's API key or password, kept sealed in the database and put where {token} is written. Never shown again. |
| The gateway said it was sent when the answer holds (`sms_ok_status`) | *empty* | Some gateways answer 200 to everything: a word their answer holds only when it was sent - "ok", ""status":"sent"". Empty: any 2xx answer. |
| What is sent (body) (`sms_body`) | *empty* | For POST. Starting with { it is JSON and the values are written as JSON strings: {"to": "{to}", "text": "{text}"}; otherwise a form: to={to}&text={text}. Empty: the address alone. |
| Headers (`sms_headers`) | *empty* | One a line, Name: value - Authorization: Bearer {token}. Content-Type is set by itself. |
| The spool folder (`sms_spool_dir`) | `/var/spool/sms/outgoing` | smstools3: /var/spool/sms/outgoing. A file "To: 420…" and the text is written there and the modem's daemon sends it. The service runs as acme: that user needs to be able to write into the folder (a group, chmod g+w). |
| The Teltonika's address (`sms_tel_host`) | *empty* | The gateway on the network: 192.168.1.1, or host:port. The same box zigmon sends its texts through can send these too. |
| Its interface (`sms_tel_api`) | `rest` | RutOS 7 offers its own API out of the box; the older Post/Get service has to be switched on by hand under Services → Mobile Utilities → SMS gateway. (`rest` - RutOS's own API (/api, RutOS 7 - the default); `cgi` - the older Post/Get SMS service (/cgi-bin/sms_send)) |
| Its modem (`sms_tel_modem`) | *empty* | Which modem sends - 1-1, 3-1… Empty: the one the gateway names first. |
| Over HTTPS (`sms_tel_https`) | `1` | A TRB serves both; HTTPS keeps its password and the codes off the wire. |
| Its user (`sms_tel_user`) | `admin` | An account of the gateway that may use its API (admin, or one made for this under System → Administration → User settings). |
| Its password (`sms_tel_password`) | *empty* | Its password, kept sealed in the database. Never shown again. |
| Check its certificate (`sms_tel_verify`) | `0` | Checked against the certificates imported below - the gateway's own (read from it with one click) or the authority and chain that signed it; with none imported, against the authorities this machine trusts. Off: any certificate is taken. |

The debug log of the codes (*Settings → About*, with *Debug log* on): see *When a code does not arrive* above.
