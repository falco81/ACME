# Owners, teams, tags - and who may see and do what

Settings → Certificates → **Owners and teams** keeps two catalogs: the owners of
certificates (teams and persons) and the tags. A certificate no longer carries an
owner or a tag typed as free text: it is given one of those defined here, picked
from a list. What a team's members may do with the certificates the team owns is
said on the team, member by member.

The code: `acmelib/certs/teams.py` (the catalogs, the rights, the guard),
`acmelib/certs/api_teams.py` (the routes, the command line), `web/assets/teams.js`
(the pane, the owner select and the tag picker used everywhere else).

## The catalogs

### Owners (`cert_teams`)

| column | what |
|---|---|
| `name` | unique; letters, digits, spaces and `. _ @ + -` (as every other name in acme) |
| `kind` | `team` or `person` - only how it is shown; both have members |
| `members` | JSON: `[{"who": "...", "rights": ["view", "request", "manage", "approve"]}]` |
| `contact_mail` | addresses told about the team's certificates (comma between them) |
| `contact_phone` | optional, shown only |
| `note`, `created(_by)`, `updated(_by)` | |

A **member** (`who`) is one of

- `local:NAME` - an account of acme's own (Settings → Accounts), signed in on the
  administration or (with the portal's local accounts) on the portal;
- a directory user - its sAMAccountName, UPN or mail;
- a directory group - `group:NAME` (its cn) or its whole DN; nested membership counts.

A certificate's `owner` is the team's **name**. Renaming a team renames it on its
certificates in the same step. A team that owns certificates is not deleted: it is
refused with the count, or deleted with `reassign` (another team, or `''` for nobody)
which moves its certificates first.

### Tags (`cert_tags`)

`name` (one word: letters, digits and `. _ : + -`), `colour` (one of the page's tones:
dim, info, ok, warn, crit, violet; since 1.0.24 also teal, cyan, indigo, pink, rose, orange,
amber, lime, brown, slate), `description`. Certificates and targets pick their
tags from it (chips). Renaming a tag renames it on every certificate and target;
a tag in use is deleted only with `strip` (taken off them) - never silently.

### Legacy values

What certificates said before (free-text owners, tags not in the catalog) stays as it
was: it is shown marked *not defined*, with one click to make it a team or a tag.
**Make teams and tags from what certificates say now** on the pane does all of them at
once: each free-text owner becomes a team whose single member is that text (so the
portal shows the certificate to the same person or group as before; `view` and
`request`), its certificates then owned by the team. Nothing is done by itself on
upgrade, and nothing is lost.

Both catalogs are part of the configuration: backed up, exported and imported
(Export and import), replicated to the other node (`CERT_CARRY_TABLES`).

## Rights

| right | gives |
|---|---|
| `view` | see the team's certificates: list, detail, jobs, deployments, download on the portal |
| `request` | ask for a new certificate owned by the team (portal, or the wizard for a certificate administrator) - implies `view` |
| `manage` | edit, renew, deploy, revoke, export, delete, answer a CSR of the team's certificates; create new ones owned by it - implies `view` and `request` |
| `approve` | approve or decline the portal requests of the team - implies `view` |

## Who sees what

One function decides, for the pages, the API and the portal alike:
`teams.scope(store, session, right)` - `None` (every certificate) or the set of team
names the session holds `right` for.

| who | sees / may |
|---|---|
| **full administrator** | always everything, every right - never scoped, whatever is set |
| the command line (root) | as a full administrator |
| **certificate administrator** | with *Certificate administrators manage every certificate* on (`certs_certadmin_all`, **default on** - as before): everything. Off: only the certificates of teams where they hold the right asked for; certificates without an owner only a full administrator sees |
| **read-only account** | with *Read-only accounts see every certificate* on (`certs_readonly_all`, **default on** - as before): sees everything. Off: only the teams where they hold `view` |
| a person on the **portal** | the certificates owned by them as before (their name, UPN, mail, `local:NAME`, a group they are in), plus those of teams where they hold `view`; asks only for the teams where they hold `request` (or for themselves, as before). With `manage` on a team's certificate (1.0.16): *Renew now*, renewed by itself on/off, *Revoke* (`/api/portal/cert_renew`, `cert_auto`, `cert_revoke`); with `approve` (or `manage`): *Approve* / *Decline* its waiting requests (`/api/portal/cert_approve`). The certificate's dialog says what they may (*You may*). An account of acme's own with the role of an administrator sees all (`portal_admins_all`, the portal's own setting) |

A session is matched against the members by: `local:NAME` for an account of acme's own;
for an account that signs in from the directory its name, its DN and the groups it was
in at its sign-in (`accounts.group_list`); on the portal the directory's name, UPN, mail
and its groups (nested).

Scoped (a setting off) the following are filtered or refused, with a `403` in words and
an event (`warn`) saying who was refused what:

- `GET /api/certs`, `/api/certs/overview` (the soonest and the recent jobs),
  `/api/certs/jobs`, `/api/deploys` - filtered;
- `GET /api/certs/one`, `/api/certs/job` - `view`;
- `/api/certs/save` (an existing one), `auto`, `delete`, `renew`, `deploy`, `revoke`,
  `export`, `csr_answer`, `plan`, `check`, `dry_run`, `add_key`, `job_stop`,
  `/api/deploys/save|delete|run|dry_run` - `manage`;
- a new certificate (`save` without id, `csr`, `import`, each one of `online_import`
  (Import from a source), the portal's request) - its
  owner must be a team the person holds `request` (or `manage`) for; without an owner
  it is refused (only a full administrator makes certificates without one);
- changing a certificate's owner - `manage` on the old team and `request`/`manage` on
  the new one;
- `/api/certs/approve` - `approve` (or `manage`) on the certificate's team.

What is not about one certificate stays as it is: sources, validations, targets,
authorities and the settings are for certificate and full administrators as before
(their own roles), the catalogs are changed by a full administrator and read by
everybody signed in (the owner select needs them).

## Owner and tags on a certificate, without a new certificate

The certificate's detail has **Details** with a pencil: owner, tags, note, renewed by
itself, days before the end, keep the key on renewal, name in acme, switched on - all
saved at once by `POST /api/certs/save` with only those fields. None of them is in the
certificate itself, so nothing is issued and nothing is checked against the source.

What *is* in the certificate - its names, its key, its source, its validation, its
profile - is changed in the wizard (Edit). It takes effect at the next renewal: saving
does not issue by itself. Saving such a change on a certificate already issued asks
**Renew now with the new names, or at the next renewal?** in the page's own window.

## Notices

A failed renewal, a failed deployment, a certificate about to end or ended: mailed to
`certs_notify_mail` as before **and** to the owner team's `contact_mail`.

## Enterprise teams (1.0.125)

For a company of thousands: the global administrators delegate work to teams arranged in a
tree (regions, sites, departments), each getting exactly what it should. **Nothing changes
for an installation that does not use it**: every new column is empty, a team without a
parent, limits or roles works as described above, the four rights stay.

The code: `acmelib/certs/teams.py` (capabilities, roles, the tree, the limits),
`acmelib/certs/teampolicy.py` (the checks of the limits, the approvals),
`acmelib/certs/api_teams.py` (the routes, the directory, the command line).

### The tree

`cert_teams` has three more columns: `parent` (the team above; empty - the top level),
`policy` (the team's own limits, JSON) and `description`. The kind may also be `unit` (an
organisational unit: a region, a site - shown with another icon, it is a team in every
other way).

- A team is never put under itself or under a team below it (refused on save).
- Renaming a team renames it on its certificates, in the `parent` of the teams below it,
  on the devices it owns and on its enrollment codes.
- A team with teams below it is deleted only with `reparent` (the team they move under, or
  `''` for the top level). The devices it owns go to `reassign` (or become acme's own).

### Capabilities

What a member may do is a set of capabilities:

| capability | gives |
|---|---|
| `cert.view` | see the team's certificates, their jobs and deployments |
| `cert.request` | ask for new certificates owned by the team |
| `cert.renew` | renew now |
| `cert.auto` | switch renewing by itself on or off (and hold deployments) |
| `cert.edit` | change the team's certificates (names, source, validation, details), export without the key |
| `cert.revoke` | revoke |
| `cert.delete` | delete |
| `cert.key` | download a file with the private key |
| `cert.approve` | approve or decline the team's requests |
| `deploy.view` / `deploy.run` / `deploy.manage` | see / run / add, change, delete deployments |
| `target.view` / `target.manage` / `target.test` | see / add, change, delete (and confirm agents) / test the team's devices |
| `test.view` / `test.manage` | see / add, change, delete and run the team's tests (1.0.128, "Tests of a team" below) |
| `team.view` | see the team, its members and its limits |
| `team.members` | add, change and remove members - never giving more than one holds oneself |
| `team.policy` | change the limits of the teams **below** (never one's own team's, never wider) |
| `team.create` | create, rename and delete teams below |
| `team.activity` | see what happened in the team |

The old rights are capabilities too - a member with an old right holds exactly what it gave:
`view` = cert.view, deploy.view, target.view, team.view; `request` = view + cert.request;
`manage` = request + cert.renew, cert.auto, cert.edit, cert.revoke, cert.delete, cert.key,
deploy.run, deploy.manage; `approve` = view + cert.approve.

The guard checks each route for its own capability: renew - `cert.renew`, revoke -
`cert.revoke`, delete - `cert.delete`, deploy - `deploy.run`, `deploys/save|delete|dry_run`
- `deploy.manage`, `deploys/run` - `deploy.run`, export with a key - `cert.key` (otherwise
`cert.edit`), saving an existing one, `csr_answer`, `plan`, `check`, `keep`, `add_key` -
`cert.edit`, `auto`, `hold` - `cert.auto`, `dry_run`, `job_stop` - `cert.renew`, approve -
`cert.approve` (or the old `manage`). A member with `manage` holds all of them.
`teams.scope(store, s, right)` works as before; `teams.scope_cap(store, s, cap)` is the same
for a capability.

### Roles

A member (`members` JSON) is `{"who", "rights": [...], "roles": [...], "until": epoch,
"note"}` - `roles`, `until` and `note` only where given. Its capabilities are those of its
rights and of its roles. Once `until` has passed the membership gives nothing (it stays in
the list, marked expired).

Built-in roles (in the code, not changed, not deleted):

| role | capabilities |
|---|---|
| Viewer | cert.view, deploy.view, target.view, team.view, test.view |
| Requester | Viewer + cert.request |
| Renewer | Viewer + cert.renew, cert.auto |
| Deployer | Viewer + deploy.run |
| Device manager | Viewer + target.manage, target.test, deploy.manage, deploy.run, test.manage |
| Certificate manager | Requester + Renewer + cert.edit, cert.revoke, cert.delete, cert.key, deploy.run, deploy.manage - it does not approve (that is the Approver's); a member with the OLD right `manage` still approves, as before |
| Approver | Viewer + cert.approve |
| Team manager | Viewer + team.members, team.policy, team.create, team.activity |
| Team owner | every capability |

`test.view` (1.0.128) is part of the Viewer, so of every role built on it; the old rights give
exactly what they gave before (none of them gives a test capability).

Roles of one's own are kept in `cert_roles` (`name`, `description`, `caps`) - part of the
configuration: backed up, exported and imported, replicated (`CERT_CARRY_TABLES`). Renaming
one renames it on every member; one given to members is deleted only with `strip`.

### Inheritance

A member's capabilities on a team apply to that team and every team below it: a
certificate manager of *Europe* manages the certificates of *Prague* and of *Prague web*.
The tree and each person's capabilities are computed once (per version of the teams and the
roles, and per person) - 2000 teams and people in hundreds of nested groups stay fast.

### Limits (policy)

Every key is optional; a key not said is no limit from that team.

| key | meaning |
|---|---|
| `profiles` | the request profiles it may ask from |
| `free_form` | may ask without a profile (the portal's free form) - default true |
| `issuers` | the sources its certificates may come from |
| `validations` | the validations they may use |
| `pairs` | the sources with their validations (1.0.128): `{"acme-le": ["dns-web"]}` - below |
| `target_kinds` | the target modules of its devices (`["ssh", "agent", "f5"]`) |
| `test_kinds` | the test modules of its tests (`["https", "smtp"]`, 1.0.128) |
| `suffixes` | the names its certificates must be under |
| `wildcards` | its certificates may have a wildcard name (`*.example.com`) - default true (1.0.128) |
| `max_certs` | the most certificates the team, with the teams below it, may own |
| `max_days` | the longest validity it may ask for |
| `key_download` | files with the private key may be downloaded - default true |
| `agents` | it may have target agents - default true |
| `agents_auto_confirm` | its enrollment codes may confirm servers by themselves - default false |
| `approval` | the approval rule (below); the old words `"profile"` / `"always"` are read too |
| `approve_actions` | other actions that wait for an approval: `revoke`, `delete`, `key`, `device` |

The limits in force are the **intersection** of the team's own and of every team above it:
a team below only narrows (lists intersected - a suffix under another taken as the narrower,
the smallest number, a switch off anywhere is off, a source with a validation only where every
level allows the pair). A refusal names the team whose limit
refused it ("the team Europe does not allow it: ...", `403`) and is an event.

They are checked where a team member acts: the portal's request (free form and request
profiles, the names of a CSR), a new CSR with other names, a certificate a scoped certificate
administrator makes or changes, the download of a key on the portal, a device, a test and a
deployment of the team (`teampolicy.need_*`, used by the portal's team pages). A full
administrator is never limited.

#### No wildcards (`wildcards`, 1.0.128)

`"wildcards": false` - no name of the team's certificates starts with `*.`: refused (`403`, an
event, the team named) on the portal's free form, from a request profile, in a CSR sent to one,
in a new CSR with other names, and for a scoped certificate administrator making a certificate
or changing its names. False on any team above - false below, whatever the team below says.
The pre-approved envelope of `approval` (`outside`) takes `"wildcards": false` too: a wildcard
is not refused, it waits for an approval.

#### Sources with their validations (`pairs`, 1.0.128)

`"pairs": {"SOURCE": ["VALIDATION", ...]}` - a certificate from a source named here is proved
only by the validations listed for it (its own validation and each name's own one); `[]` - that
source with no validation (an authority of acme's own). The rule, per team:

- a team without `pairs` says nothing of it (as before);
- a team with `pairs`: a source in it - with its validations only; a source not in it - only
  where **the same team's** `issuers` lists it (then with any validation `validations` allows);
  any other source is refused;
- in force is the pair every level allows: `pairs` of a team below is intersected with those
  above it (sources both name, validations both list) - `issuers` of another level never opens
  what one level's `pairs` closed.

A new certificate saved without a source is checked with the default source (and its default
validation) it will get. `issuers` and `validations` are still checked on their own. A source or validation renamed is
renamed in `pairs` too. Checked where `issuers` and `validations` are (above); the portal's free
form offers a team only the sources it may use with the portal's validation.

#### Tests of a team (`test_kinds`, 1.0.128)

A test (Certificates → Tests, `cert_tests`) has an `owner` like a target: a team, or empty -
acme's own, as before (an older database is given the column empty; the column is replicated
and exported with the table). Its members work with them on the portal, *Tests* in the team
workspace: `test.view` lists them (its own and, with "below", the teams' below), `test.manage`
adds, changes, deletes and runs them - only of the modules `test_kinds` allows, through a
connector of the team only, never another team's test nor acme's own, and never a secret
shown back (only whether it is set). A full administrator sets the owner of any test
(`POST /api/tests/save {owner}`, `acme --check-edit NAME --owner TEAM`). In the administration
the Tests tab stays as before - a full administrator's (no scoping of tests or targets there).
Renaming or deleting a team takes its tests along as its devices.

    GET  /api/portal/tests?team=[&below=1]   GET /api/portal/test?id=   GET /api/portal/test_kinds?team=
    POST /api/portal/test_save {id?, team, name, kind, config, note, enabled}
    POST /api/portal/test_delete {id}        POST /api/portal/test_run {id}
    GET  /api/portal/policy_catalog?team=    the names of the sources and validations (team.policy)

### Approvals

`approval` is `{"mode", "approvers", "count", "self", "outside"}`:

- `mode`: `none` - the team's requests never wait (self-service within its limits; a name
  another owner's certificate holds still waits for that owner); `profile` - as before, the
  request profile (or the portal's settings) decides; `always` - every request waits, also a
  certificate a scoped certificate administrator makes; `outside` - self-service while the
  request stays inside `outside` (`profiles`, `suffixes`, `max_days`, `key_types`), anything
  else waits.
- `approvers`: `team` - members holding cert.approve on the team itself (its leads);
  `parent` - on the team above it; `team_or_parent`; `both` - the team's lead first, then
  one of the team above.
- `count`: `2` - two different people approve (four eyes).
- `self`: whether the person who asked may approve it (default false - never).
- `outside` is `{profiles, suffixes, max_days, key_types, wildcards}` - `"wildcards": false`:
  a wildcard name is outside the envelope (it waits).

Each approval and decline is recorded with the request (who, when, words) and shown in its
timeline; the request goes on once the rule is met; one decline declines it. The approvers
wanted are told by mail (the team's contact addresses) and find it under "Waiting for you".
A full administrator counts as an approver at every level - one approval. Without a rule
nothing changes: one approval of an approver lets it through, as before.

A rule below never weakens one above: the stricter `mode` stays, `count` the larger, `self`
only where every level allows it, the `approvers` of both (`team` above and `parent` below are
`both`), and the envelope of `outside` what both let through. Actions waiting for an approval
(`approve_actions`) are approved - and declined - only at the level the rule names, and an
approved key is taken once.

### Devices and agents of a team

A target has an `owner` (a team; empty - acme's own, as before). An enrollment code of the
target agents may carry a team (`POST /api/agents/enroll {..., team}`): every server that
enrolls with it becomes a target owned by that team, waiting to be confirmed - confirmed by
itself only where the code says so **and** the team's limits allow it
(`agents_auto_confirm`).

### On the portal

Members work for their teams on the portal - the team workspace (docs/certificate-portal.md
"Teams"): their teams and the teams below, certificates with the actions their capabilities
give, *Waiting for you* (requests and actions to approve, with their timelines), the team's
devices (added with the module's own fields; secrets never shown back, only whether they are
set), agents (join and enrollment codes, waiting agents confirmed or refused, the server's
facts, the policy designer), deployments (What happens, run), members, teams below and their
limits, activity. Every route checks the capability on the team (inherited downwards) and the
team's limits; nobody gives more than they hold, nor raises their own membership, nor touches
a team above theirs. A person in no team: the portal as before.

### The directory

- The member picker searches the directory's users and groups (`GET /api/dir/search`, 50 at
  most a page; what is typed is never put into a filter as text) and shows a group's size
  and first members (`GET /api/dir/group`).
- **Access check** (`GET /api/teams/access?who=`): a person (local:NAME, their UPN, account or
  mail) is looked up, their groups read (nested), and every team they reach is said with its
  capabilities, the limits in force and why - which membership, role and group, and whether
  it is inherited from a team above.
- **Teams from directory groups** (`POST /api/teams/from_groups`): the groups whose name fits
  a filter (`PKI-*`) each made a team (or a unit) with the group as its member in a chosen
  role, under a chosen team - previewed first (`dry_run`). Since 1.0.128 groups can also be
  picked from the directory beside the filter (`groups`: their DNs or names, 200 at most); with
  the filter left empty only those are made, and a group named that the directory does not know
  is said in `missing`.
- **Pick from the directory** (1.0.128): every box of the pages that holds a name of the
  directory - the access check, Teams from directory groups, the settings' groups of the
  administrators and of the portal, the directory's look-up and "Try a sign-in", the
  certificate look-up for a person, the portal's member dialog - has a small search button
  beside it. It asks the same search as the member picker (`/api/dir/search`, on the portal
  `dir-search`, which needs `team.members` somewhere) and puts what is picked into the box in
  the form the box already takes (a DN as one more line, a login, `group:NAME`); what is typed
  by hand, wildcards too, works as before. It is shown only to those who may search (a
  certificate administrator or a full one), and says so when no directory is set up.

### Activity

`GET /api/teams/activity?team=` - the events about the team: its own changes (members added,
removed, changed, its limits, where it is in the tree, the teams made or moved under it), its
certificates' and its devices'. Names are matched whole: the activity of `Web` never shows the
events of `WebDev` or `Web2`, nor those of a certificate `web10` for `web1`.

`GET /api/teams` gives every team its `counts` - `certs`, `certs_below` (with the teams below
it), `expiring` (within the notice days), `failing`, `waiting`, `devices`, `agents`,
`agents_waiting` - in the one answer; a scoped account of the teams it sees only.

## The command line

    acme --teams                                   the owners and the tags, and how many certificates each
    acme --team-add NAME [--team-kind person] [--members 'local:jan=manage,group:Web=view'] [--contact-mail a@b] [--note ..]
    acme --team-edit NAME [--name NEW] [--members ...] [--contact-mail ...]
    acme --team-del NAME [--reassign OTHER|-]
    acme --tag-add NAME [--colour info] [--note ..] / --tag-del NAME [--strip]
    acme --teams-adopt                             teams and tags from what certificates say now

A member written without `=rights` gets `view,request`.

Enterprise teams (1.0.125):

    acme --team-add NAME [--parent TEAM] [--team-kind unit] [--description ..] [--policy '{"max_days": 90, "approval": "always"}']
    acme --team-edit NAME [--parent TEAM|-] [--policy '{}'] [--members 'group:Web=Requester+Deployer,local:jan=manage@2026-12-31']
    acme --team-del NAME [--parent TEAM|-]          its teams below moved there (- the top level)
    acme --roles                                   the roles and their capabilities
    acme --role-add NAME --caps cert.view,cert.renew [--description ..] / --role-del NAME [--strip]
    acme --team-access WHO                         what a person may in which team, and why
    acme --team-activity NAME [--below] [--limit N]   what happened in the team (its Activity tab)
    acme --teams-from-groups 'PKI-*' [--member-role Requester] [--parent TEAM] [--team-kind unit] [--yes]
                                                   teams from directory groups: the preview, made with --yes
    acme --target-edit NAME --owner TEAM|-         a team's device (- acme's own); --target-add too
    acme --check-edit NAME --owner TEAM|-          a team's test (1.0.128); --check-add too
    acme --target-agent enroll new --owner TEAM    a team's enrollment code

In `--members` the old rights stay rights, other words are roles, `@YYYY-MM-DD` ends the
membership (at the end of that day).

What that simple form cannot say - a group given by its DN (its commas and `=`), a role with `+`
or a comma in its name, a member's note, an end at an exact time - `--members` takes as a JSON
list (anything starting with `[`); the list replaces the members, as the simple form does:

    acme --team-edit Web --members '[{"who": "CN=PKI-Web,OU=Groups,DC=example,DC=com", "roles": ["Requester"]},
                                     {"who": "local:jan", "rights": ["manage"], "until": "2026-12-31 18:00", "note": "until the audit"},
                                     "group:Web"]'

Each member is `{"who", "rights", "roles", "until", "note"}` (only `who` needed: without
rights and roles it gets `view,request`) or just its `who`; `until` is an epoch,
`YYYY-MM-DD` (the end of that day) or `YYYY-MM-DD HH:MM` (that time). The console writes the
members this way when one of them needs it.

    acme --team-show NAME [--json]                 one team whole: its members with their roles,
                                                   ends and notes, its limits (--teams cuts the
                                                   members and limits columns at 48 characters)

`--note ''` and `--description ''` with `--team-edit` take the note or the description away.

## Typical setup

A team that runs its own servers: creates its devices and tests of some kinds only, asks for
certificates of its domain only, from one source with one validation, never a wildcard, and may
not make sources or validations (nobody on a team can - those stay the administrators').

    acme --team-edit Web --policy '{
      "target_kinds": ["ssh", "iis"],
      "test_kinds": ["https", "smtp"],
      "issuers": ["acme-le"],
      "pairs": {"acme-le": ["dns-web"]},
      "suffixes": ["web.example.com"],
      "wildcards": false
    }'
    acme --team-edit Web --members '[{"who": "group:Web-Admins", "roles": ["Device manager", "Requester"]}]'
    acme --team-show Web

On the pages: Settings → Certificates → **Owners and teams** → the team → **Limits** → *Set
limits* (or the pencil): *Requests* - **Sources** (Only these: acme-le), **Sources with their
validations** (Only these, *add a source…* acme-le, then *add…* dns-web), **Domains**
(web.example.com), **Wildcard names** (Forbidden); *Keys, devices and agents* - **Target
modules** and **Test modules** (Only these, from the catalog); **Save the limits**. A team
manager above it does the same on the portal: *Sub-teams & limits* → the team → *Limits*.

## What the roles mean for keys and the network (read before delegating)

* A member who may manage the team's devices **and** its deployments (the role *Device manager*,
  or `target.manage` with `deploy.manage`) can deploy a team certificate to a server of their own
  and so hold its private key there - even where the team's limits say *no key downloads*
  (`key_download: false`) and without `cert.key`. Give these two together only to people you
  would give the keys to; limit what they may deploy to with *Target modules* (`target_kinds`).
* A team's devices are acme's targets: acme connects to the address typed in them (SSH, HTTPS
  APIs, webhooks). Whoever may add devices may make acme connect to an internal address. Allow
  only the modules the team needs (`target_kinds`) and keep acme's firewall (Settings → Firewall
  and access) and the outgoing proxy rules in mind.

