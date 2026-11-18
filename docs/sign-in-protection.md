# Sign-in protection

Two counts hold back somebody guessing passwords on these pages:

- **Wrong passwords from one address** (*Settings → Accounts*: `login_tries`,
  `login_wait_min`; on the enrolment pages `portal_tries`, `portal_wait_min`):
  each node counts the wrong passwords that reach it, by address and by name, and
  makes the address wait after so many.
- **Wrong directory passwords per person** (below, as otp 1.0.230 - 1.0.234): one
  count for the whole cluster, in the database, of the wrong passwords given for
  one person of the directory - so that the guesses made here never lock their
  account in Active Directory.

Both are shown, and cleared, under *Settings → Sign-in protection → Counted and
blocked now* (with a filter) and *Settings → Accounts → Locked out* (every kind)
(`acme --lockouts`, `acme --lockouts-clear`).

Signing in with Windows (Kerberos, 1.0.99, [kerberos-sso.md](kerberos-sso.md)) is held to the
same: each refused ticket counts per address (kinds `kerberos` and `portal-kerberos`, at least
20 before a pause - one office behind one address signs in with it all at once), *Block a place
that keeps guessing* counts it as a wrong sign-in, and every refusal is an event. No directory
password is tried by it, so it never adds to the count per person.

Signing in with a certificate (1.0.100, [certificate-sign-in.md](certificate-sign-in.md)) the
same: each refused certificate counts per address (kinds `certlogin` and `portal-certlogin`, at
least 20 before a pause), *Block a place that keeps guessing* counts it, every refusal is an
event (*Sign-ins*, *Portal*; mailed with `alerts_certlogin`).

## 1. Wrong directory passwords per person

A directory password is tried against Active Directory at each sign-in to the
enrolment pages (the certificate portal) and at each sign-in of an administrator
from the directory. Each of these has a count of its own, per address and per
name, held in each node's memory: from many addresses, and on two nodes, a name
could get dozens of wrong passwords through to the directory in a quarter of an
hour - more than its lockout threshold (typically 5 to 10), and the account was
locked there: mail, the VPN, the PC.

| Setting | Default | |
|---------|---------|--|
| `dir_pw_tries` | `0` | Wrong directory passwords for one person, from anywhere and on any node, before the directory is no longer asked for them. **0 = no cap of its own, as until now.** |
| `dir_pw_window_min` | `30` | How long one counts. As long as the directory's *Reset account lockout counter after*, or longer. |

Set `dir_pw_tries` **below** the directory's lockout threshold - 3 for a
threshold of 5 to 10. Over the cap, the person gets *too many wrong passwords for
this name: try again in N min* and the directory is not asked at all - the
account in Active Directory stays unlocked; only these pages wait. A right
password does not count. The count is kept in the database: both nodes of an HA
pair and every node on one database count together.

- **Counted by the account**: the person's entry in the directory, whatever name
  was typed - `novakj` (sAMAccountName), `jan.novak@corp.cz` (UPN) and
  `CORP\novakj` are one count. *Locked out* shows it as the first part of the
  account's DN and a short hash of it (`jan novak#3f2a9c1e|corp`).
- **A name the directory does not have** is counted as typed, the same way, and so
  are an account that is switched off, locked or answered by two entries - the
  answer never tells which names exist.
- A password refused before the directory is asked (empty, or with a control
  character) does not count.
- The address's own count keeps its place too: the tries spent on a held-back
  name do not come back to the address.

acme has no "block a place that keeps guessing" switch of its own (otp's is for
RADIUS): the cap is in use whenever `dir_pw_tries` (or a directory's own cap) is
more than 0.

```bash
acme --set dir_pw_tries=3
```
```bash
acme --set dir_pw_window_min=30
```

## 2. Per directory, and the domain's own policy

Under *Settings → Sign-in protection → Wrong directory passwords - each directory* every
configured directory has a card of its own: its servers, whether the link is
encrypted, and how it is capped.

- **As the setting above** - `dir_pw_tries` and `dir_pw_window_min` (the default).
- **Its own** - a cap and a window for this directory alone.
- **No cap** - this directory is never held back here, whatever the setting above
  says.

Each directory is counted on its own: `novak` of one domain and `novak` of
another are two people. A directory renamed keeps its own cap; one taken away
takes it with it.

**Read the domain's policy** (full administrators; a directory switched on) connects
to the directory with its own bind account and reads what the domain itself says:
the *Account lockout* (threshold, how long one counts, how long it locks), the
*Password policy* (length, complexity, history, the longest and shortest age) and
every *Fine-grained password policy* (PSO) in
`CN=Password Settings Container,CN=System` that the bind account may read. It
recommends a cap: two under the lowest threshold when that is over 3, else one
under (at least 1), over the longest window of them - so the person always has
some tries left before the domain locks them. *Use it* only fills it in on the
card; nothing changes until **Save the changes** at the bottom of the page. A
domain that does not lock accounts at all (threshold 0) is said so; 10 in 30
minutes is recommended then all the same - it still slows down guessing.

What was read is kept beside the caps and shown again the next time the page is
opened, with when it was read.

```bash
acme --dir-caps                  # the setting and each directory's own cap, and its policy as read
```
```bash
acme --dir-cap corp=3/30         # its own: 3 wrong passwords in 30 min; corp=setting, corp=none
```
```bash
acme --dir-policy corp           # read the domain's policy now, and the cap recommended
```

The console has them under *Directories (Active Directory, LDAP)*.

## The settings by key

Settings → Sign-in protection and Settings → Accounts - also `acme --set KEY=VALUE`:

| Setting | Default | |
|---------|---------|--|
| Block a place that keeps guessing (`login_guard`) | `0` | Off: only each address and each name count their own wrong passwords on each kind of sign-in - from one place somebody may still try every name a few times. On: the place each sign-in comes from - the address it connects from - is counted too, over these pages and the certificate portal together. Too many refusals from one place, or too many different names refused from it, and it is blocked for a while: its sign-ins are refused at once, nothing of them is checked, no directory is asked. Each node counts what reaches it; who is counted and who is blocked is below, each cleared by hand. Wrong directory passwords per person go with it: off, no cap is applied. |
| Wrong sign-ins from one place before it is blocked (`login_guard_tries`) | `20` | Refusals from one place within the time below after which it is blocked - wrong passwords, wrong codes, names nobody has. Not counted: refusals that are this server's trouble (a directory away). |
| Different names refused from one place before it is blocked (`login_guard_names`) | `5` | Different names refused from one place within the time below after which it is blocked - somebody trying many people's passwords. 0: not counted. |
| ...counted over (min) (`login_guard_window_min`) | `15` | The time over which the refusals of one place are counted. |
| Blocked for (min) (`login_guard_block_min`) | `30` | How long a place is blocked. Clear it by hand below to let it in at once. |
| Never blocked (`login_guard_trusted`) | *empty* | Addresses or networks never blocked, one or more, separated by spaces or commas: an office whose people all come from one address, a monitor that signs in now and then. Example: 198.51.100.7 203.0.113.0/24 |
| A sign-in lasts (h) (`session_hours`) | `12` | How long an administrator stays signed in, however busy. |
| Group of full administrators (`admin_group_full`) | *empty* | Members may change everything. By name or by whole DN. |
| Group of certificate administrators (`admin_group_cert`) | *empty* | Members may look at everything and look after the certificates - add, import, renew, deploy, export (no private keys) - and change no setting. |
| Group of read-only accounts (`admin_group_readonly`) | *empty* | Members may look at everything and change nothing. |
| Czech and Slovak letters in names (`names_czsk_letters`) | `0` | The letters of Czech and Slovak with their accents (á č ď é ě í ľ ĺ ň ó ô ŕ ř š ť ú ů ý ž ä) in the names of accounts. With both this and the one beside it off, a name takes letters without accents, digits, . _ - and @ only, and one with any other letter is refused: on the enrolment pages, when an account is made and when an administrator from the directory signs in. Most directories keep their sign-in names so (novak), and only the display names have accents - those are never checked. |
| Letters of other languages in names (`names_any_letters`) | `0` | Letters of every other language in names - Cyrillic, Greek, Polish ł, German ß and ö, and the rest. A name that only looks like another (a Cyrillic а for a Latin a) is one way to pass for somebody: switch it on only where such names are really used. On, it takes the Czech and Slovak letters too. |
