# What waits for a person

Some things acme cannot do by itself: a command to run as root on a node after
an update, SELinux switched off behind its back, the root helper not set up.
Since 1.0.54 each of these is said in one place, the same way, until it is done.

## Where it is said

- **Settings → Upgrades and maintenance → To be done by hand** (the card is
  always there; green "Nothing is to be done by hand." when nothing is): one
  band per thing and node, red (something is off) or yellow - what it is, on
  which node, why it matters, the command to run as root with **Copy**, and
  since when it waits. A band that can be checked has **Look again** (every
  node looks at once - this one now, the others within 5 s) and goes by itself;
  a step that cannot be checked has **Done** (who pressed it and when are
  kept). **Open it** goes to the part of Settings it belongs to.
  **Done lately** under them: what went away, on which node, how (done, or
  gone by itself), who, when - the 10 newest, each node keeping its last 20.
  **Clear** at the right of its heading empties it: exactly the rows the page
  shows (one come meanwhile stays), and never what is still to be done; the
  events say who cleared how many. With nothing done lately there is no table
  and no Clear.
- **Only the full administrators** are told: `/api/status` carries none of it
  for another role, and `/api/attention` is theirs alone.
- **The menu**: a count on *Upgrades and maintenance* - a red ring on its icon
  while the menu is shut. The header's pill says "running, with trouble" and
  its tooltip says where to look. The other problems stay under the header as
  before.
- **`acme --status`** on the command line and the **console** (`acme run`)
  list them too, with the command. `acme --hand` lists them with their ids and
  Done lately (`--json` too), `acme --hand-done ID@NODE` presses Done (who: the
  command line), `acme --hand-clear` empties Done lately.
- **Alerts and reports** (Settings → Alerts and reports → *A step waiting for a
  person*, on by default): a mail and an SNMP trap, as any other problem, and a
  mail again when it is done.
- **Events**: "waits for a person on NODE: …", and "done" / "gone by itself"
  when it goes.

## What is checked

Each node checks itself once a minute - only files and `/sys`, no program run -
and keeps what it found in its own row of the database (`attention:NODE`; what
went away in `handlog:NODE`; what Clear took in `handclear`, as no node writes
another node's row), so
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

**A step no check can see** (somebody must say it was done): `'manual': True`
and no `file` - shown until **Done** is pressed (kept in `handdone:ID:NODE`),
on a node where `if_file` is there when it is given (an install, not a test):

```python
{'id': 'run-new-step', 'manual': True, 'if_file': '/etc/systemd/system/acme.service',
 'level': 'bad', 'pane': 'upgrade', 'title': 'Run the new step of the installer',
 'words': '…', 'cmd': 'sudo bash /usr/local/lib/acme/current/install.sh --upgrade',
 'cs': {'title': '…', 'words': '…'}},
```

Prefer a check whenever one can be written: a manual step pressed Done by
mistake says nothing again.

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
