# Mail

acme can send a new token to the person it is for: the QR code, the key
written out, how to set the phone up and - if ticked - the recovery codes.
The mail is HTML with a plain-text copy, in Czech or English.

## Setting it up

*Settings → Mail*:

| setting | |
|---|---|
| Sending mail (`mail_mode`) | `off`, `smtp` (through your mail server) or `direct` (straight to the server of the recipient's domain, by its MX record) |
| Mail server, Port (`smtp_host`, `smtp_port`) | port 0 picks 587 / 465 / 25 by the encryption |
| Encryption (`smtp_security`) | `starttls`, `tls` (SMTPS), `starttls-if` (if offered), `none` |
| Signing in (`smtp_auth`) | `auto`, `plain`, `login`, `cram-md5`, `xoauth2`, `none` |
| Account, Password (`smtp_user`, `smtp_password`) | the password is sealed in the database with the tokens' key; for XOAUTH2 it is the access token |
| Check the certificate (`smtp_verify`) | on, unless you are testing |
| Sender (`mail_from`, `mail_from_name`), Reply to, EHLO name | |
| Mail language, Recovery codes in the mail | defaults for *Make a token* |

The same from the command line: `acme --set mail_mode=smtp --set smtp_host=smtp.example.cz
--set smtp_password=- …` (one `--set` for each; the password asked for, never written out).

A server whose certificate a private authority signed: paste the authority
(or the whole chain), or load a .crt / .pem / .cer file, in the
*Certificate authority* card under the settings - as for Active Directory.

**Direct** needs port 25 open outwards and a sender domain whose SPF lists
this machine, and this machine's address should resolve back to its EHLO
name - otherwise the receiving side will most likely refuse or bin the mail.

The recipients' MX records are asked of the DNS servers in /etc/resolv.conf
(or with dnspython, if installed); the addresses of those servers come from
the system's resolver. Where that resolver will not answer, name others in
*DNS servers for the recipients' domains* (`mail_dns`, e.g. `1.1.1.1, 8.8.8.8`):
then both the MX records and the servers' A/AAAA addresses are asked of them.
Only mail sent direct uses them - Active Directory, the SMTP relay, isemon
and the database always use the system's resolver. A resolver that refuses or fails is never taken for
"no MX record": *Try it* then says which server answered what.

## Trying it

*Try it* sends a short mail by the same road and lists each step: the
connection, TLS, the sign-in, the hand-over, with what the server said.

## Making a token and mailing it

*Tokens → Make a token*: type part of a name, pick the person - their mail
address is read from the directory, and can be changed. Tick *Send the QR
code*, choose whether the recovery codes go too and the language. The token
is made whatever happens to the mail; if the mail fails, the window says why.

Whoever reads that mail can make the person's codes. Send it only to the
person's own mailbox.

## Taking tokens away as .totp files

*Settings → Export and import → Taking tokens away to another server*: all
tokens, or those a search picks, as totpcgi `.totp` files in one ZIP. One
token: its window, *For another server → Export .totp*. Full administrators
only, with *Administrators may show a token's QR code and key* on; each
export is an event. The files hold the keys: keep them as passwords.

Locked by default (1.0.167): the ZIP is AES-256 (WinZip AE-2) with a
passphrase of 8 characters at least - 7-Zip, WinRAR, PeaZip and `7z x` open
it, and *Bringing tokens over* reads it back, asking for the passphrase.
*Not locked* gives a plain ZIP (one token: the `.totp` file itself) - only
when chosen, and the event says NOT LOCKED. ZIPs locked the old ZipCrypto way
are not read; AES-256 ones made by 7-Zip or WinZip are.

The whole backup (`.json`, every kind of token) is locked the same way unless
*not locked* is chosen (1.0.168). *Settings → Tokens → High security* takes
*not locked* away from every export: the page does not offer it and the
daemon refuses it.
