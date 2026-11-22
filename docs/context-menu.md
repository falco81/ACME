# The right button, the acme clipboard and Ctrl+K

From 1.0.138 the administration has a menu on the right mouse button over everything it lists -
a row of any table, a team in the tree of *Owners and teams*, a role's heading in the roles'
matrix, a request profile's card, an agent's tile - with what can be done with that object; rows
can be picked together and acted on at once; objects can be copied, pasted and cloned between
lists and between browser tabs; and **Ctrl+K** (⌘K on a Mac) finds anything and goes there or does
it. The portal has the menu too, for its tables (copy and filter).

Nothing of this changes what the pages did before: a left click, the row's own buttons, the
search boxes and the column layout behave exactly as they did. Every action of the menu runs the
code the page runs for it - the row's own button pressed, or the function that button and the
object's window call - so the same checks, the same questions and the same permissions apply.

## When the menu opens - and when the browser's own does

| | |
|---|---|
| right button on a row, a tree item, a card | the menu of that object |
| right button on the empty part of a list (its card, its heading, its note) | the list's menu: *Add a new one*, *Paste as new*, *Copy the whole list* |
| **Shift** + right button | always the browser's own menu |
| right button in a box to type in (input, textarea, select, anything editable), on a link, or over text you have selected | the browser's own menu (copy, paste, open in a new tab) |
| right button anywhere else | the browser's own menu |
| **Edit the columns** switched on (your account's popup) | inside a table, the column menu exactly as before (hide, show, add an empty column); the new menu does not open in tables until the switch is off |
| the **Menu** key or **Shift+F10** on a focused row | the menu of that row, opened at the row |
| a long press on a phone or a tablet | the menu, as a sheet from the bottom of the screen |

The menu is a real menu for the keyboard and for screen readers (`role="menu"`): ↑ ↓ move, Home /
End go to the first / last item, → or Enter opens a sub-menu, ← or Esc closes it, Esc closes the
menu and gives the focus back to the row it was opened on; the first letter of an item jumps to
it. On a narrow screen a sub-menu takes the place of its menu, with the way back on top.

What you may not do is not offered as if you could: somebody who may only look sees no action at
all, only what copies and filters; an administrator sees an action their role or their teams do
not allow greyed out, with the reason under it ("Only a full administrator may do that", "Your
teams do not give you that on this certificate", "It is not deployed anywhere yet").

## The menu of a row (M1)

- **Open** (Enter on the row does the same): the certificate's window, the target's, the job's
  log, the form of a source...
- **The object's actions** - for a certificate *Renew now*, *Deploy now*, *Run its tests…*,
  *Export…*, *Edit…*, *Revoke…*, *Delete…*; for a source, validation, target or test *Test it
  now*, its module's own actions (*Say hello*, *Prepare*...), *Edit…*, *Make it the default*,
  *Take it away…*; for a deployment, a DNS set, a user of the nodes, a job: the row's own buttons.
  The dangerous ones (delete, revoke, take away) are last, in red, and ask as they always do.
- **Copy “the cell”** - what the cell under the pointer shows.
- **Copy ▸** - the row *as text* (heading: value, a line each), *as CSV* (a value that a
  spreadsheet would run as a formula is quoted), *as JSON* (the object as the page has it, never
  a secret); the object's identifiers (a certificate's name, common name, names, serial,
  SHA-256 fingerprint and id; a target's name, kind and address...); and *as a CLI command* and
  *as an API call* (below).
- **Filter by “value”** / **Leave out “value”** - in a list with a search box of its own, the
  matching field is added to it (`name:web`, `-kind:fortigate`, `state:failing`, `dns:a.example.cz`,
  `source:LetsEncrypt`, `renew:no`; in Events `kind:`, `who:`, `node:`) and the list is asked
  again; in a table without one, the rows are hidden or kept by that column's value, and the
  filter is shown at the bottom of the window with a × to take it away. A list the daemon pages
  (Certificates, Jobs, Events) is filtered only through its search box.
- **Show in Events** (the events searched for its name) and **Show in Jobs** (the jobs of that
  certificate).
- **History…**, where the page has the history of objects ([history-and-trash.md](history-and-trash.md)).
- **Select ▸** - this row, or every row of the list (below).

## Picking several rows and acting on them (M3)

**Ctrl+click** (⌘-click) picks a row or puts it back; **Shift+click** picks every row from the
last one picked to this one; *Select ▸ Every row of the list* picks them all. Rows picked are
marked and a bar at the bottom of the window says how many, with **Actions** (the same menu, for
a phone) and × (or **Esc**) to clear them. A refresh of the list keeps them picked. A click with
Ctrl or Shift never opens the row.

The right button on one of the picked rows opens the menu for all of them: copy them (text, CSV,
JSON), copy their names, put them on the acme clipboard, and what their kind can do together -
for certificates *Renew them now*, *Deploy them now*, *Renew them by themselves* / *only when
asked*, *Give them to a team*, *Add a tag to them*, *Paste the deployment*, *Delete them* (each
revoked first unless switched off); for sources, validations, targets and tests *Test them now*,
*Switch them on* / *off*, and for targets *Add the tags*.

Each first shows **what will happen**: every object, what is done to it, and those left as they
are with why (no source, not in this state, your teams do not give you that on it, already so).
Nothing happens until it is confirmed. Then they are done one after another, each marked done or
failed with what the daemon said, and the dialog ends with **one result** for all of them ("All 4
done", "3 done, 1 failed", the jobs started and a way to Jobs). Each object goes through the same
route as when it is done alone, so each is checked and written in Events as before.

## The acme clipboard: copy, paste, clone (M2)

**Copy to the acme clipboard** (Ctrl+Shift+C on a focused row) keeps the object - as JSON,
**without any secret** - in this browser, for every tab of it (`localStorage`; a private window
or a browser that refuses it keeps it for the tab). The bar at the bottom of the window shows what
is on it, with × to empty it. Nothing goes to the server.

What is never on it: passwords, tokens, private keys and every field a module keeps sealed (they
are dots on the page anyway, and dots are dropped too), a certificate or its key, and a
member list of a team.

- **Paste** (Ctrl+Shift+V on a focused row) - what fits the row: a **deployment** onto a
  certificate (onto one: its form opens filled in, saved only with Save; onto several picked: what
  will happen, then one deployment each, made with the options copied - a secret option is never
  copied, and a deployment that needs one is refused and said), the **tags** of a target onto
  certificates or targets (added beside theirs), the **limits** of a team onto another team
  (*Copy its limits*, then *Paste the limits*: they replace the team's own, after a confirmation).
- **Paste as new** - on the empty part of a list (or on a row of the same kind): the object's
  own form opens, filled in, with a name of its own ("Copy of …"; "Kopie …" in Czech); nothing is
  saved until Save.
- **Clone…** - the same at once, from the row: the object's form filled in as this one, saved only
  with Save.
  - a **certificate**: the wizard of a new certificate with the same names, source, validation,
    key type, renewal, profile, owner and tags - never the same key: a new one is made when it is
    issued;
  - a **source, validation, target or test** that keeps a password, a token or a key asks first:
    **Use the same credentials** - the copy is saved through `POST /api/<list>/save_copy` with the
    id of the original, and the daemon copies its sealed secrets to the copy, sealing them again
    for the copy's own place; they never come to the page - or **Enter new credentials** (the copy
    starts without them). Changing them later changes only the copy;
  - a **team**: its kind, place in the tree, description, contacts, note and limits - no member;
  - a **role**: its capabilities (a built-in role through its own *Copy it to a role of your own*);
  - a **request profile**: through its own *Duplicate*; pasted from another tab, a dialog with
    its name and what it gives;
  - a **DNS set**: its form with the servers, protocol, timeout and note;
  - a **deployment**: the form of a new deployment with the same target and options, for a
    certificate chosen there;
  - a **user of the nodes**: *Add a user* with the same full name, shell and sudo, and a password
    of its own.

Who may: whoever may save that object - the same check as its own form (a full administrator
for sources, validations, targets, tests, teams, roles, profiles, DNS sets and users of the
nodes; a certificate administrator, within their teams, for certificates and deployments).

## Copy as a command or an API call (M4)

*Copy ▸ As a CLI command* copies the `acme …` command that makes the object again
([command-line.md](command-line.md)): `--cert-add NAME --names … --issuer … --challenge …
--key-type … --owner … --set tags=… --set profile.…`, `--target-add NAME --kind KIND --set
KEY=VALUE …` (and `--source-add`, `--validation-add`, `--check-add`), `--deploy-add CERT TARGET
--set …`, `--dns-set-add …`, `--team-add … --policy … --members …`, `--role-add … --caps …`,
`--tag-add …`; a request profile, which has no option of its own, as `acme --api POST
/api/reqprofiles/save -` with its JSON on stdin. A secret is never written out: it is `KEY=-`,
which the command line asks for on the terminal (it refuses a secret written on the command line),
with a comment `# KEY: <fill in>` under the command.

*Copy ▸ As an API call (curl)* copies `curl … '?api=<route>'` with the object's JSON as its body
(the route the page itself uses), the session cookie as `<fill in>` and every secret as
`<fill in>`.

## The command palette: Ctrl+K (M5)

**Ctrl+K** (⌘K) opens one box over the page; Esc closes it and gives the focus back. Type
anything: the certificates (by name, names, serial, owner), targets, agents, sources,
validations, tests, teams and request profiles; every page and every pane of Settings (by its name
and what it is for: "ha", "dns", "trash"); and the page's own buttons (*Add a certificate*,
*Import*, *Self-signed*, *Run the tests*...). Letters in order match too ("fwpr" finds "fw-praha"),
but never across words; the page's language and English both find.

A **verb first** acts on what is found: *renew web*, *deploy mail*, *test fw1*, *edit vpn*, *clone
web*, *history fw1*, *open …* - in Czech too (*obnov*, *nasaď*, *otestuj*, *uprav*, *klonuj*,
*historie*). What the account may not do is shown as not possible.

↑ ↓ move, Enter opens or does it, Esc closes. With nothing typed it shows the last things chosen
(kept in this browser), the pages and the actions. The lists are asked of the daemon only once
the palette is opened, and kept for a minute.

### Searching everything (1.0.140)

What is typed (two characters or more, not a verb) is also asked of the server - `GET
/api/search?q=` (`acmelib/certs/api_search.py`) - a breath after the last key. Its finds join the
page's own in their groups, each object once:

| | |
|---|---|
| Certificates | by name, any of its names (SANs), common name, serial (`5D:D2:A1` or `5dd2a1`), SHA-256 fingerprint - also those past the first 1000 the page holds |
| Deployments | a certificate's deployment by the certificate's or the target's name (*intranet → fw1*) |
| Targets, agents | by name, module, host, tags - never by what a secret holds |
| Sources, authorities, validations, tests | by name and module; an authority by its subject |
| Request profiles, teams | by name and description |
| Accounts | by name - a full administrator only; never a mail, a phone or a group |
| Events | the last 30 days, newest first, by their words |

Enter opens the object's own card: a certificate's (a deployment's certificate), a target's,
the source's form, an authority's, the profile in Settings → Request profiles, the team in Owners
and teams, the account's row in Settings → Accounts, the Events page searched for that event.

The server keeps every answer to what the account may see: a member kept to their teams finds only
their teams' certificates, deployments and teams (`teams.where`, as the Certificates list), a
target of another team not at all, and only the events the Events page would show them. At most
100 characters are searched for, 8 of each kind (`limit`, 20 at most), and an account asking more
than 30 times in 10 seconds is answered 429. While it is asked, *Searching every certificate,
deployment and event…* is said under what is found already.

Two actions are new: **The expiry calendar** (Certificates → Calendar, [expiry-calendar.md](expiry-calendar.md))
and, for a full administrator, **A request profile from a template**.

**The search box in the header** (*Find anything…*, with the keys beside it) opens the same palette
for those who reach for the mouse; on a phone it is a magnifying glass.

## For the parts of the page (developers)

`web/assets/ctxmenu.js` is the menu, the picking, the dock, the clipboard, the bulk dialog and
the command and API call text; `web/assets/ctxmenu-registry.js` says, per kind of object, how a
row is read and what can be done with it (`ACME_CTX.type(name, def)` and `ACME_CTX.scope({sel,
row, type, read, filter, area})`); `web/assets/palette.js` is Ctrl+K. A table nobody registered
still gets the menu every row has (open, copy, filter, its own buttons). Another script can add
items to every object's menu with `ACME_CTX.addItems(function (type, obj, ctx) { return [...]; })`.
certs.js lends the functions its rows' buttons call as `ACME_CERTS.ctx`; dnssets.js its form as
`ACME_DNSSETS.edit(null, copy)`.
