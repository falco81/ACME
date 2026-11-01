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
