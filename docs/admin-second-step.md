# A second step for the administration pages

*Settings → Accounts → A second step when signing in to these pages*
(`admin_2fa`, off by default). On, every account of the administration - a
local one or one from the directory - gives a code after its password. It is
the account's own, set up for these pages.

## The ways

| Setting | Offered |
|---|---|
| `admin_2fa_app` | a code from an authenticator app (Google or Microsoft Authenticator, FreeOTP…) - offered anyway when nothing else is |
| `admin_2fa_mail` | a code by e-mail - only while mail is set up (Settings → Mail) |
| `admin_2fa_sms` | a code by SMS - only while sending SMS is set up (Settings → Codes by e-mail and SMS) |
| `admin_2fa_passkey` | **Face ID, Touch ID, Windows Hello or a security key** (a passkey, WebAuthn) - off by default; see [Face ID and passkeys](#face-id-and-passkeys) |

When more than one way is offered, the account chooses the one it wants when it sets the step
up - the first time it signs in after the second step was switched on.

## Signing in

1. The name and the password, as always. Right, the sign-in can do nothing
   yet but its second step: every other page and every API call answers
   *the second step of signing in is not done yet*; the pages that take a
   file (a database, a package) see no role.
2. **The first time** the account chooses one of the ways offered and sets it
   up on the sign-in page:
   - *app*: a QR code (and its key as text) is scanned, and the six digits the
     app shows are typed;
   - *e-mail / SMS*: an address or a phone number is typed, a code is sent
     there, and typed back - proving it is the account's.
3. **Afterwards** it gives the code each time: the app's (each code is good
   once), or one sent by *Send the code* (at most one every 30 s, five per
   sign-in; good for `code_ttl_s`).

Wrong codes count as wrong passwords do (`login_tries`, `login_wait_min`) and
show in Accounts → Locked out. Every step is an event (Sign-ins, Accounts).

Turned on, sign-ins already open stay open; turned off, a sign-in waiting for
its second step goes straight in.

## Its messages

The codes it sends have words of their own - four messages in
*Settings → Message texts*, edited like the others:

- *The administration: a sign-in code by mail* / *…by SMS* - each sign-in;
- *The administration: checking an address* / *…a number* - when it is set up.

They are written in the language of the sign-in page.

## On and off on the command line

```bash
acme --admin-2fa on       # every account gives the second step from its next sign-in
acme --admin-2fa off
acme --admin-2fa status   # on or off, the ways offered, who has set it up
```

The same as the setting on the pages (`acme --set admin_2fa=1` works too).

## Reset

A lost or new phone, another address: *Accounts → the shield button* (Reset
the second step), or on the server

```bash
acme --reset-2fa NAME
acme --users            # who has which way
```

The way is taken away and the account's sign-ins end; at its next sign-in it
chooses and sets it up again - with the password alone, so reset it only when
you know who asks.

## Where it is kept

`meta` row `adm2fa:<name>`, in the database (and so on both nodes of a
cluster): the way, the app's key sealed with the installation's key, or the
address / number. In copies, dumps and backups like everything else.

## Face ID and passkeys

`admin_2fa_passkey` (1.0.51) adds one more way of giving the second step: the face, the finger
or the PIN of the device - Face ID or Touch ID on an iPad, iPhone or Mac, Windows Hello, an
Android phone, a security key. **It is a second step only, never the sign-in itself**: the name
and the password are asked first, always, and the passkey is asked after them in place of a code.

- **Setting it up:** the first sign-in after the second step was switched on offers *Face ID /
  Touch ID* beside the other ways. *Set it up with this device* asks the device for the face (or
  the finger, the PIN); on an iPad or iPhone the passkey goes into the iCloud Keychain, so the
  person's other Apple devices have it too. The server keeps only its public part, its id and
  its counter - nothing secret.
- **Signing in:** after the password, *Use Face ID / Touch ID* - one look.
- **Your account → Passkeys - Face ID, Touch ID** (while `admin_2fa` and `admin_2fa_passkey` are
  on): the account's passkeys - the name, the name of the pages it is for, when it was added and
  last used; renamed in place (the pencil, Enter), taken away (the bin, asked in the row; the last
  one stays - an administrator resets the second step instead), and *Add a passkey of this
  device* for one more (an iPad and a Windows PC, say). An account giving its second step another
  way may add one here too: the passkey then takes the place of that way. At most 20.
- **Reset:** as for the other ways - *Accounts → Reset the second step*, or
  `acme --reset-2fa NAME` as root. The passkey on the device is left there (Settings → Passwords
  on an iPad) and no longer opens anything.

What it takes:

| | |
|---|---|
| HTTPS with a certificate the browser trusts | WebAuthn is not there at all otherwise |
| the pages opened by their **name**, not by an address | a passkey is bound to the name (its RP ID) |
| the same name each time | one set up on `acme.example.cz` (the VIP's name) does not work on `acme1.example.cz` - open the pages by the name you use every day |
| on an iPad, the iCloud Keychain on | without it the iPad offers a security key or another device's QR code only |

What the server checks, every time: the question is its own, once, within five minutes and for
this name; the page asking is `https://` that name; the device saw the person (UP) **and knew
them by face, finger or PIN (UV)** - without UV it is refused, as it would be no second step;
the signature over the device's data, with the key kept (ES256, RS256 or Ed25519, checked by
openssl); the counter going on (a passkey whose counter goes back may have been copied - refused,
and said in the events as *bad*). Wrong answers count as wrong codes do (Sign-in protection).

A passkey of 1Password or another password manager works too - the manager opens instead of
Face ID and is unlocked by it.

## The home screen of an iPad

The pages carry an icon (`apple-touch-icon`) and a manifest: Safari → *Share → Add to Home
Screen* puts acme's shield on the home screen; opened from there it runs in a window of its own,
without Safari's bars. Its cookies are its own: sign in there once more.
