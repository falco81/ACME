# Mail

acme mails the alerts and the report (certificates running out, a renewal or
a deployment that failed, a node gone - [monitoring.md](monitoring.md)), the
codes of the administration's second step and of checking an address
([codes-by-mail-and-sms.md](codes-by-mail-and-sms.md)), and the tests. The
mail is HTML with a plain-text copy, in Czech or English.

## Setting it up

*Settings → Mail*:

| setting | |
|---|---|
| Sending mail (`mail_mode`) | `off`, `smtp` (through your mail server) or `direct` (straight to the server of the recipient's domain, by its MX record) |
| Mail server, Port (`smtp_host`, `smtp_port`) | port 0 picks 587 / 465 / 25 by the encryption |
| Encryption (`smtp_security`) | `starttls`, `tls` (SMTPS), `starttls-if` (if offered), `none` |
| Signing in (`smtp_auth`) | `auto`, `plain`, `login`, `cram-md5`, `xoauth2`, `none` |
| Account, Password (`smtp_user`, `smtp_password`) | the password is sealed in the database; for XOAUTH2 it is the access token |
| Check the certificate (`smtp_verify`) | on, unless you are testing |
| Sender (`mail_from`, `mail_from_name`), Reply to, EHLO name | |
| Mail language (`mail_lang`) | the language of the codes, the tests, the alerts and the report unless they say otherwise |
| Try a mail not delivered for, Keep the list for (`mail_retry_hours`, `mail_keep_days`) | a mail the receiving side did not take yet (greylisting, a server away) waits and is tried again |

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

## Outgoing mail

Every mail sent - an alert, a report, a code to sign in with - and what became
of it is under *Outgoing mail*: sent, waiting for another try, failed. One can
be sent again or taken away by hand. What a mail holds (a code) is sealed
while it waits and thrown away once it went.
