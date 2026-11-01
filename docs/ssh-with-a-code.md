# SSH to the nodes with a code from acme

*Settings → SSH server → Signing in with a code from acme* (1.0.178). sshd of
every node then asks for a code where it would ask for the account's password -
from the account's **SSH token**: tokens of their own (1.0.181), kept apart from
the VPN's as the second step of the administration is. They are in no realm,
no RADIUS client asks for them, they are not in the RADIUS log. Both nodes and a
node alone alike: each node's `pam_radius` asks acme's **gate** on 127.0.0.1 of that
node, so a node whose partner is down still lets you in.

It needs *acme sets the SSH server* on, and it is put in on trial like every
other change there: keep the session you have open, open a new one, then
*Keep it*.

## What acme does on each node

- Installs `pam_radius` if it is not there - `dnf -y install pam_radius` (RHEL
  and the like: from **EPEL**, so `dnf install epel-release` first) or
  `apt-get -y install libpam-radius-auth`.
- Opens its gate: a RADIUS listener of the daemon on **127.0.0.1 only**, in a
  thread of its own (RADIUS of the VPN is not touched by it), with a long random
  secret of its own (kept sealed). Each node finds a free port for it in
  **18129-18199** - never one of the kernel's ports for outgoing connections
  (`/proc/sys/net/ipv4/ip_local_port_range`), never one something else has -
  remembers it, and tells its own pam_radius; *Settings → SSH server* shows each
  node's (*acme's gate for SSH*).
- Writes `/etc/acme/pam_radius.conf` (mode 0600, root) with the gate's secret and
  the node's port; when the port or the secret changes, only this file is put
  right. The secret never goes on a command line.
- Puts a block of its own into `/etc/pam.d/sshd`, before its first `auth` line,
  between the lines `# acme: SSH with a code from acme (RADIUS) ... (begin)` and
  `(end)`:

  ```
  auth [success=1 default=ignore] pam_succeed_if.so quiet user = root
  auth [success=done new_authtok_reqd=done ignore=ignore default=die] pam_radius_auth.so conf=/etc/acme/pam_radius.conf localifdown
  ```

  With *Only these accounts* the first line is `user notin a:b` instead; with
  passwords off a `auth requisite pam_deny.so` follows, and there is no
  `localifdown`.
- Sets `UsePAM yes` and `KbdInteractiveAuthentication yes` in its drop-in, so
  sshd asks through PAM.

Switched off (or *acme sets the SSH server* off, or the trial not kept): the
block, the file and the drop-in's lines go; `/etc/pam.d/sshd` is exactly as it
was before.

## The settings

| Setting | |
|---|---|
| Ask for a code from acme | on / off |
| Only these accounts | separated by spaces; empty: everybody (but root, below) |
| Root too | off: root signs in as before - your way in if acme itself is in trouble |
| The system password when acme does not answer | `localifdown`: pam_radius steps aside and the account's own password is asked. Only with passwords on |

## SSH tokens

*Settings → SSH server → SSH tokens → Add an SSH token…*: the account's name as on
the nodes (the name typed at `ssh`), a note, and where the codes come from. **An
app**: the QR code and the key are shown **once**, right then - scan them into the
authenticator app. *A new one…* makes
the secret anew (the one in the app stops working), *Remove* takes it away. Full
administrators only; each is an event.

**By mail or SMS** (where sending is set up; in Czech or English, chosen for each
token - *Settings → Mail*, *Codes by e-mail
and SMS*): choose *By mail* or *By SMS* and the address or number.

**One prompt, no `Password:`** (1.0.188): pam_radius runs with `skip_passwd`, so
sshd asks nothing first - acme's gate asks for the code itself: *Code from the app:*
for an app's token, or a code is sent and asked for at once (*Type the code mailed
to f\*\*\*\*@example.cz:*) - RADIUS's Access-Challenge, as the VPN's second
window. A block put in by an older version is given `skip_passwd` by itself. A
wrong code is asked again, three times. Every code sent to the account and still
good (5 min) is taken, each once - a mail that came late, after a later sign-in
sent another, still lets in. Signing in again within 20 s sends no second code:
the one sent is asked for again (a new one goes if none is good any more). The
prompt says when the code went (*... (11:16):*). Every wrong code is an event
(*ssh*) saying why: a code that ran out (when it went, when it stopped being
good), none sent to the account in the last hour, or not digits at all. A code goes at most every 20 s and five in 15
minutes per account, so a name typed at `ssh` is no way to send SMS. The words are their own
under *Settings → Message texts* (*SSH: a sign-in code by mail / by SMS*). The
sending happens in a thread of its own; pam_radius waits up to 30 s for it.

A code is good once; five wrong ones for a name in five minutes and that name is
refused for five minutes. Every sign-in, let in or not, is an event (*ssh*) - and
goes to isemon and the SIEM as events do. Both nodes see the same tokens.

An account with no SSH token gets no code: with *The system password when acme
does not answer* off, it gets in with a key only.

## A key, and then the code (1.0.183)

Off (the default), a key alone still lets in: sshd asks PAM - and so the code -
only where it would ask for a password. With passwords off, an account with a
key gets in with the key alone; one without a key, with the code alone.

*A key, and then the code* on: sshd wants both - the key first, then the code
(`AuthenticationMethods publickey,keyboard-interactive`) - from the accounts the
code is asked of; the others (root, unless *Root too*) sign in as before. acme
writes it as a `Match User` block at the end of its own drop-in and checks with
`sshd -T` that the block reaches nothing of the system's own settings (sshd 8.2
and later end a Match at the end of the file it is in); where it would, the
change is refused and everything stays as it was. Each of those accounts needs a
key of its own in `~/.ssh/authorized_keys` on every node.

**Root signing in with a key only** (*Root signs in: With a key only*, `PermitRootLogin
prohibit-password`) and the code asked of root too (1.0.191): sshd hands PAM the
fake password `"\b\n\r\177INCORRECT"` for whatever root types, wherever root may
not sign in with a password - every code was refused. acme gives root a block of
its own: `Match User root` with `PermitRootLogin yes`, `PasswordAuthentication no`
and `AuthenticationMethods publickey,keyboard-interactive` - root needs the key
and the code, never a password alone; with *the system password when acme does
not answer*, root still gets none (a line of acme's PAM block refuses it). A node
upgraded writes its files anew once by itself, with no trial (nothing chosen
differently).

**Hide the code as it is typed** (1.0.191): pam_radius takes RADIUS's Prompt
attribute (`prompt_attribute`), and the gate asks with echo off - the SSH client
shows nothing as the code is typed, as for a password. PuTTY and OpenSSH show
no stars for it: that is the client's, not the server's. Every prompt ends with
": " - a space after the colon.

From 1.0.178-1.0.180 (a RADIUS client and the VPN's tokens): the client *SSH of
the nodes - pam_radius* is removed by itself and each node's pam_radius is told
the gate. Make an SSH token for every account that signed in with a code.

## High security

The rule *SSH: passwords* turns passwords off - and with them the fallback: with
acme not answering nobody but a key gets in. Root left out keeps the way in.

## Things that break it

- **A kernel booted with `ipv6.disable=1`.** pam_radius 2.0 opens an IPv6 socket
  first and gives up without one - every sign-in fails as *authentication
  information cannot be recovered*. Boot with IPv6 (it may stay unconfigured).
- SELinux keeps sshd from asking RADIUS while the boolean `authlogin_radius` is
  off - acme turns it on (`setsebool -P authlogin_radius on`) when it puts the
  block in, and leaves it on when the block goes.
- A `/etc/pam.d/sshd` changed by hand between the two marker lines is
  overwritten.

## Checking

*Settings → SSH server* says per node whether the code is asked (pam_radius),
not asked, or pam_radius is not there, and the gate's port. The SSH tokens list
says when each was last used and on which node; *Events* has every sign-in.

## The gate's port

*Settings → SSH server → acme's gate for SSH*: the port tried first (18129). Where
something else has it, each node takes the next free one of 18129-18199 by
itself, remembers it and tells its pam_radius; each node's card says which. The
gate listens on 127.0.0.1 only - nothing to open in the firewall.
