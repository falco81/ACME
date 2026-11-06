# What waits for a person

Some things acme cannot do by itself: a command to run as root on a node after
an update, SELinux switched off behind its back, the root helper not set up.
Since 1.0.54 each of these is said in one place, the same way, until it is done.

## Where it is said

- **At the top of every page** of the administration, under the header: a red
  band (something is off) or a yellow one (something is older than it should
  be), one per thing and node - what it is, on which node, why it matters, and
  the command to run as root with a **Copy the command** button. **Open it**
  goes to the part of Settings it belongs to; **Not now** hides it in this
  browser for a day (it comes back while it is not done). The band looks as
  isemon's. The state pill in the header says "running, with trouble" while
  one is there.
- **`acme status`** on the command line and the **console** (`acme run`) list
  them too, with the command.
- **Alerts and reports** (Settings → Alerts and reports → *A step waiting for a
  person*, on by default): a mail and an SNMP trap, as any other problem, and a
  mail again when it is done.
- **Events**: when one appears, a line "waits for a person on NODE: …".

It goes away by itself: the check finds the thing done the next time it looks
(within a minute) - nothing is clicked away.

## What is checked

Each node checks itself once a minute - only files and `/sys`, no program run -
and keeps what it found in its own row of the database (`attention:NODE`), so
every node's is seen from any node's pages. A node gone for two days says
nothing any more.

| id | level | when |
|----|-------|------|
| `selinux-off` | red | SELinux was seen enforcing on this node and is permissive or disabled now. A node never seen enforcing (set up so) says nothing. The command: `setenforce 1` and `SELINUX=enforcing` in `/etc/selinux/config` (disabled: a relabel and a restart). |
| `helper-missing` | red | An installed node without the root helper (`/var/lib/acme/web` or `acme-web.path`) - the network, the firewall, the users, the updates cannot be done from the pages. The command: `install.sh --upgrade`. |
| `nginx-manifest` | yellow | `/etc/nginx/conf.d/acme.conf` older than 1.0.51 (no `webmanifest`): the home-screen icon is served without its type. The command: `install.sh --upgrade`. |

## Adding one in a release

A version that needs a step by hand adds it, and it shows on every node that
has not taken it yet.

**The simple kind** - a file that must contain something - is one entry in
`HAND_STEPS` (`acmelib/engine/469_things_to_do_by_hand.py`):

```python
{'id': 'nginx-manifest', 'since': '1.0.51', 'file': '/etc/nginx/conf.d/acme.conf',
 'has': 'webmanifest', 'level': 'warn', 'pane': 'web',
 'title': "nginx's file for acme is older than the pages",
 'words': 'What is wrong while it is not done, and what the step does.',
 'cmd': 'sudo bash /usr/local/lib/acme/current/install.sh --upgrade',
 'cs': {'title': '…', 'words': '…'}},
```

It is wanted while `file` is there and does not contain `has`.

**Anything else** is a function with `@hand_check`: it gets the store and
returns a list of `{id, level ('bad'|'warn'), title, words, cmd, pane, cs}` -
an empty list when there is nothing to do. Keep it cheap (it runs every minute
on every node), read files rather than run programs, and never put a secret in
the words or the command. A check that fails is written to the log once an
hour and the others go on.

- `id` - short and fixed: the alert's key is `hand:ID:NODE`.
- `cmd` - what to run as root, whole, ready to paste (`sudo …`), or `''`.
- `pane` - the part of Settings that **Open it** goes to (`web`, `hisec`, …).
- `cs` - the Czech `title` and `words` for the mails; the pages translate
  through `web/lang/cs.json`, so add the same texts there (`addcs.py`).

Add the entry to the table above and a test to `test/test_hand.py`.
