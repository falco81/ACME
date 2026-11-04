# High security (1.0.168)

*Settings → High security*, for a full administrator, off by default. On, it
switches off every way of doing something less safely, on every node.

## Switching it on

Switching it on first looks over everything - the settings, the directories,
the backup destinations, the TLS of the pages, who may
reach the administration, and the SSH server as each node's sshd says it is.
What stands against it is listed in a window, each with what to set and a
link to where; it is refused (the daemon too, HTTP 409 with the list) until
the list is empty. The same list is on the page itself, with *Look again*.

## What stands against it

| Where | Refused |
|---|---|
| Active Directory | plain LDAP; the certificate not checked; old, weak TLS |
| Mail | to the server unencrypted or only if offered (`smtp_security` none, starttls-if); the certificate not checked; direct delivery unencrypted where the recipient's server offers no TLS |
| SMS | the HTTP gateway over `http://`; the telephone gateway without HTTPS or without checking its certificate |
| Database, cluster | MariaDB/PostgreSQL over the network without `verify-ca`/`verify-full`; the replication likewise |
| Backups | plain FTP; FTPS not checking the certificate; SMB not encrypted |
| Syslog | UDP or TCP servers (only `tls://`); the certificate not checked; isemon over plain syslog, or its certificate not checked |
| The pages | TLS other than *standard* (ECDHE, AEAD) or *modern* (TLS 1.3); the administration reachable from everybody |
| SSH | passwords (or keyboard-interactive); root with a password; more than 4 tries |
| Accounts | no second step for the administration, or one by mail or SMS; the administrators' app codes taken more than one step either side; sign-ins lasting over 8 hours or idle over 30 minutes |
| The enrolment pages | anyone in the directory may sign in |
| Other | debugging; a private key or the configuration exported not locked; a proxy without a password |

While it is on, each of these is refused wherever it is changed - the pages,
the API, `acme --set` - and greyed out on the pages, with why.

## Exceptions (1.0.169)

Every rule has a switch on its right: *Exception*. A rule made an exception
stops nothing and is not enforced while high security is on - the rest stay.
While high security is on, an exception is taken back only once the rule is kept
(else high security would stand against itself). Each change is an event. The
rules kept are listed too, folded, each with its switch.

## The security check

What is not as it should be now - the firewall off, no backup going to another
machine or none tried, a backup that cannot be put back, security updates or a
restart waiting, certificates running out - is listed apart, and never stops
high security.

Switching it off is always possible, and written down as every setting is.

## SELinux

Under the settings, a card for each node says how SELinux stands there - the mode, acme's
module, the labels, booleans and ports acme needs, what was refused - with the steps to make it
ready, enforcing, or permissive again. Where SELinux is on, the security check lists what keeps
a node from being protected as it should; where it is disabled, it says nothing. See
[selinux.md](selinux.md).
