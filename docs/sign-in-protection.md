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
