# Trash, history and saved views

Since 1.0.138 acme keeps what was deleted for a while (the **trash**), writes down every change
of its configuration (the **history** of each object) and lets every person keep the filters,
sort and columns of a list under a name (**saved views**). Nothing else changes: an object is
saved and deleted exactly as before; the trash and the history only look at what was done.

Settings → **Trash and history** holds both settings and the two views:

| Setting | Default | |
|---|---|---|
| Keep what was deleted (days) `history_trash_days` | 30 | 0: no trash - what is deleted is gone at once, as before 1.0.138 |
| Keep the history of changes (days) `history_keep_days` | 365 | 0: no history is written |

What ran out is forgotten every hour by the node that leads (and never shown after its time).

## What is kept

| Object | History | Trash | Comes back with it |
|---|---|---|---|
| Target | yes | yes | the deployments taken off with it ("take it off everywhere first") |
| Source, validation | yes | yes | - |
| Test | yes | yes | its attachments to certificates taken off with it |
| Deployment | yes | yes | - |
| Test of a certificate (attachment) | yes | yes | - |
| Request profile | yes | yes | - |
| Owner (team, person, unit), role, tag | yes | yes | - |
| DNS set | yes | yes | the functions that asked it (Settings → DNS) |
| DNS record of acme's DNS server (one of your own) | yes | yes | - |
| Certificate | its settings | its settings only - see below | its deployments and tests |

Only what a person changes is written down: a change made through the pages, the command line
or the API. What acme writes by itself - a state, a last error, when something last ran, what
was deployed - is not a change. A DNS record acme puts in for a challenge is not kept either.
An authority of acme's own (Authorities) is never put in the trash: its key is its identity.

### Certificates

A certificate is kept in the trash **without its private key and without its certificates**:
only its settings (its names, source, validation, key type, renewal, profile, owner, tags,
note) and its deployments and tests. Restored, it comes back as a request **added, not issued**
(Issue now issues a new one with a new key) - a deleted key never comes back, and a certificate
that was revoked and deleted cannot be put back into use. Its restore is a normal "Add a
certificate": a name held by another owner, or its team's limits, refuse it as they would refuse a
new one.

Not kept: a certificate revoked and deleted in one job (the revocation already ended it), a
certificate without a source (imported, from an outside CA's CSR - nothing could issue it
again), and a request of the portal that waits for approval or was declined.

## The secrets

A secret (a password, a token, a key pasted into a module's settings, a PFX password of a
deployment) is kept in the trash and in the history **sealed exactly as it was** - never opened,
never sent to a page, never logged. The history says of a secret only that it was set, changed
or taken away. When something is restored, the daemon opens the secret for the route that saves
the object, which seals it again for its new place - the value never leaves the daemon.

## The trash

Settings → Trash and history → **Trash** lists what was deleted, newest first: the kind, the
name, who deleted it, when, from which address, what went with it and how many days are left.
Filters: a name, the kind, who deleted it, when.

**Restore…** shows first what comes back: its settings (secrets as "sealed"), what comes back
with it, and what is wrong:

- **Its name is taken since** - another object has that name now: it comes back under another
  name, offered ("web1 2") and changeable.
- **It needs what is not here** - a deployment whose target, a test attachment whose test, a team
  whose parent team was deleted: when that is in the trash too, "Restore what it needs too" brings
  it back first; otherwise it cannot come back.
- Notes - a certificate comes back as a request; an agent's target comes back unpaired (its agent
  was let go when it was deleted - pair it again); a source uses the account it had at its CA again
  when it still opens.

A restore runs the route that saves that kind of object (POST /api/targets/save,
/api/deploys/save, /api/teams/save...), with every check of who may and of what is given - as
if the object were saved anew by the person restoring it. What came back with it that cannot
(its target gone, say) stays in the trash on its own and is said.

**Delete for good** (one item) and **Empty the trash** are a full administrator's.

Who sees the trash: a full administrator everything; a certificate administrator the
certificates, deployments and test attachments of the teams where they may change them; a
read-only account nothing.

## The history

Every object's **History** (the button with the clock in the head of a certificate's window and
of a source's, validation's, target's or test's form; the right-click menu; Ctrl+K; or Settings
→ Trash and history → **Latest changes**) shows every change, newest first: who, when, from which
address, and field by field what it was and what it became - the module's settings and a
deployment's options each by its label, lists (names, members, tags) as what was added and what
was taken away, a text of several lines line by line.

**Restore this version** shows what would change and saves the object as it was after that
change - through its own route, checked as any save, and written down as a new version ("the
version of ... restored"). The secrets it has now stay, unless "Also put back the secrets of that
version" is ticked. Who may: whoever may save that object (a full administrator for targets,
sources, validations, tests, profiles, owners, roles, tags and DNS sets; a certificate
administrator with the right on the certificate's team for a certificate and its deployments).
Seeing a history needs what seeing the object needs: the certificate's team for a certificate, a
deployment and a test attachment; anybody signed in for the rest.

Latest changes filters by kind, by who and by when, and finds a name.

## The command line and the console

`acme --history [--limit N]` (the latest changes), `acme --history TYPE NAME` (one object's),
`acme --history-restore ENTRY [--yes]`, `acme --trash`, `acme --trash-restore ID [--name NEW]`
and `acme --trash-purge ID|all [--yes]` - as the pages, run as `command line` (a full
administrator) - [command-line.md](command-line.md). What the command line changes or deletes is
written down and put in the trash as the pages' changes are. In the console: **h** → *The latest
changes* (Enter: its whole history, or that version again) and *The trash* (Enter: bring it back,
under another name, delete it for good). Saved views are the pages' lists: no command line.

## Saved views

By the filters of every list (Certificates, Sources, Validation, Targets, Tests, Jobs, Events,
the lists of Settings) a small menu **Views**:

- **Save this view…** keeps the filters set now, the sort and the columns (cols.js's layout of
  that list) under a name: **only me**, **a team** (everybody who may see the team - the
  capability team.view; sharing with a team needs it too) or **everybody** (a full
  administrator's).
- Picking a view sets its filters and columns; **Back to the list as it comes** leaves it. The
  person's own column layout is never overwritten - it is back when the view is left, and while
  "Edit the columns" is switched on a view changes the filters only.
- The **star** opens a view by itself with the page (for that person, per list).
- **Update**, **Rename or share…** and **Delete** of one's own views (a full administrator also
  of a team's and of everybody's).

They are kept by the daemon (table saved_views; the default per person in meta
`views:default:<person>:<list>`), so they follow the person to every browser and node.

## Where it is kept

Three tables of the database, made at the start of 1.0.138 on SQLite, MariaDB and PostgreSQL:
`obj_history`, `obj_trash`, `saved_views`. As every other table they are in every backup and
are replicated between the nodes of a cluster; the history is a log (a copy put back without its
logs leaves it as it is). They are not part of Export of the configuration.

## For developers

- One hook in the store layer: `acmelib/certs/history.py` puts itself on `Db.query` and, while
  a route of `api.api` runs (`history.acting`), notes the row of a configuration table before an
  UPDATE or a DELETE and the number an INSERT made; when the route is over, each row is compared
  with what it is now. No route was changed.
- Routes: `acmelib/certs/api_history.py` (GET /api/history, /api/trash, /api/views; POST
  history/preview, history/restore, trash/preview, trash/restore, trash/purge, views/save,
  views/delete, views/default).
- The pages: `web/assets/history.js` and `history.css`, `web/assets/savedviews.js`; cols.js tells
  savedviews.js when a table is laid out (`window.ACME_COLS_HOOK(table, key)`).
- For other scripts: `window.acmeHistory.open(type, id)` (type: cert, target, source,
  validation, test, deploy, check, profile, team, role, tag, dnsset, dnsrecord; id a number or
  `{name: '...'}`) and `window.acmeTrash.open([type])`.
