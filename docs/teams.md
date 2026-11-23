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
    acme --teams-from-groups - --group 'CN=PKI-Web,OU=Groups,DC=example,DC=com' [--group PKI-Db]
                                                   only the groups picked (by DN or name); beside a FILTER too
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


## Governance (1.0.138)

What keeps the access of an organisation of thousands in order: who may do what and why, viewing
the pages as a member, temporary roles, access reviews, separation of duties, templates and bulk
import, the team's own channels with an escalation chain, and the teams' health. **Everything here
is off and empty by default**: a team that sets none of it works exactly as before, no new
capability exists (the managers of a team - `team.members` - are the ones who approve temporary
roles and confirm members in reviews; nothing else is implied by an existing role).

The code: `acmelib/certs/teamgov.py` (temporary roles, reviews, separation of duties, templates,
CSV, channels, health, the tick), `acmelib/certs/teamaccess.py` (who may do what and why),
`acmelib/certs/viewas.py` (view as), `acmelib/certs/api_teamgov.py` (the routes of the
administration), the portal's routes at the end of `acmelib/certs/portal_teams.py`; the pages:
`web/assets/teams.js` ("Governance" section, views *Who may*, *Health*, *Requests*,
*Templates*, the team's tab *Governance*), `web/assets/portal-teams.js` (*Health*, *Access*).

The command line and the console have all of it but *View as* (a sign-in of the pages):
`acme --team-health`, `--team-gov`, `--team-gov-set TEAM JSON|-`, `--team-notify-test`,
`--who-may`, `--who-can`, `--elevations`, `--elevation-approve/-decline/-end`, `--reviews`,
`--review-open`, `--review-answer`, `--team-templates`, `--team-template-save TEAM NAME
[--template-members]`, `--team-from-template`, `--team-template-del`, `--teams-import-csv`
([command-line.md](command-line.md)); the webhooks are set sealed through `acme --api POST
/api/teams/hooks -` (the body on stdin). In the console: **o** (the teams' health, requests to
decide, reviews open, who may, team templates, who can, teams from a CSV file) and a team's own
menu (its health, governance in forms, reviews, temporary roles, channels tried, saved as a
template) - [console.md](console.md).

### Where it is kept

| what | where |
|---|---|
| a team's reviews, temporary roles, separation of duties, channels | `cert_teams.extras` (JSON: `review`, `jit`, `sod`, `notify`; NULL - none) |
| a team's webhook addresses | `cert_teams.hooks_sealed` - sealed (`cert_teams:<id>:hooks_sealed`), never returned to a page, left out of an export without the secrets |
| templates | `cert_team_templates` (`name`, `description`, `config`) - configuration: backed up, exported, replicated (`CERT_CARRY_TABLES`) |
| requests for a temporary role | `cert_team_elevations` (who, the names they are known by, team, role, hours, reason, state, who decided, until) |
| access reviews and their answers | `cert_team_reviews` (team, started, due, state, `items`: each member with its answer, by whom, when) |

An older database is given the columns and tables at its first start (empty: as before). Renaming
a team takes its requests and reviews along; deleting it ends its waiting and granted roles and
closes its open review.

`teamgov.tick(store)` runs with the renewer's scan, on the node that leads (so once in a cluster),
at most every four minutes: roles whose time is up end by themselves, requests nobody answered
in a week end, reviews are opened on schedule and closed at their deadline, and the escalation
chain sends what is due.

### Who may do what - and why (T1)

Settings → Owners and teams → **Who may** (a certificate administrator, as the access check):

- **A person** - their teams (rows) × every capability (columns, grouped as Certificates,
  Deployments, Devices, Tests, The team). Each dot says how it is held: on the team itself
  (solid), inherited from a team above (a ring), a temporary role (a diamond); a red mark - held,
  but the team's limits still narrow it (no key downloads, waits for an approval, only from a
  request profile). A dot opens **why**: which membership (the person, or the group they are in),
  which role or old right, on which team, inherited from where, ending when, and the reason of a
  temporary role. Their account's role is said beside (a full administrator, or a certificate
  administrator with *Certificate administrators manage every certificate* on, holds everything
  whatever the teams say); a full administrator may open **View as** / **Open the portal as**
  from here.
- **A team** - everybody who holds anything on it: its members, those of the teams above, the
  temporary roles in force, and the accounts that hold capabilities by their role (full
  administrators; certificate administrators and read-only accounts while their settings give
  every certificate), × the capabilities, each with its why.
- **Who may…** - the reverse: `cap` on a team or on a certificate (its owner team) → everybody
  who may, with the membership that gives it; a group can be opened (who is in it, from the
  directory); a certificate without a team: only those who see every certificate.

It is computed from the same tree, roles and per-version caches the guard uses (`teams.explain`,
`person_caps`): what it says is what is enforced, and it stays fast with thousands of teams and
people. Routes: `GET /api/teams/whomay?who=` | `?team=`, `GET /api/teams/whocan?cap=&team=|cert=`
(certificate administrator; a scoped one sees only the teams it sees). On the portal a member with
`team.members` sees *Who may do what* of that team (`GET /api/portal/whomay?team=`, without the
administrators).

### View as (T2)

A **full administrator** sees the pages as a chosen member would, **read-only**:

- **The administration** (`POST /api/teams/view_as {who}`; on a member's row the eye, then *The
  administration*): the administrator's own sign-in then answers every route as the member's
  account would - their role, name and groups (an account of acme's own, or a person of the
  directory whose groups give a role here); `/api/auth/whoami` says their role, so the pages draw
  what they would. A member who signs in to the portal only is refused here ("open the portal as
  them").
- **The portal** (`POST /api/teams/view_as_portal {who}` → a one-time link `/?viewas=CODE`, two
  minutes, used once): a portal sign-in of the member's own is made (two hours at most) - the same
  teams, caps and limits they have. It ends at once when the full administrator who opened it is
  one no longer (another role, disabled or deleted). Another member's link opened in the same
  browser replaces it; behind a load balancer (`portal_sso`) it goes on while the balancer names
  the administrator who opened it, and ends when it names somebody else.

While viewing as, **every write is refused on the server** before any route runs (`403`
"read-only: you are viewing the pages as … - nothing is changed"), and so are the downloads of
the database, a backup, the configuration and a periodic report's file; only *Stop viewing as*
and *Sign out* go through. A certificate the member may not see, looked at meanwhile, is noted as
refused to you (viewing as them), never as the member's own attempt.
A banner on every page says whom you see as, with **Stop viewing as** (the portal's: Sign out).
Starting, stopping and every write refused are events (naming the member's teams, so they are in
each team's Activity too). A certificate administrator may not view as anybody.

### Temporary roles - just-in-time elevation (T3)

A team's **Governance → Temporary roles** (full administrator): the roles that may be asked for
and the most hours (`extras.jit = {roles, max_hours}`). Set on a team, it holds for the teams below
it too, unless one of them sets its own.

- A **member** of the team (holding anything on it) asks on the portal (*Access → Ask for a role*)
  or in the administration (*Requests*): a role of those allowed, for N hours, with a reason.
  `POST /api/teams/elevate` / `POST /api/portal/elevate`.
- It is approved or declined (a decline says why) by someone holding **`team.members`** on the
  team (or a full administrator), **never by the one who asked**, and only for a role whose
  capabilities the approver holds there. Separation of duties is checked when it is given.
  `POST …/elevate_decide {id, ok, why}`.
- Granted, it is a membership of its own with an `until` (now + the hours): the person holds the
  role on that team and every team below it until then - in the guard, the portal and *Who may*
  alike - and it **ends by itself**. The one who asked takes a waiting request back, or ends a
  granted role early; a team manager can end it too (`…/elevate_end`).
- Asked, given, declined and ended are events, and told on the team's channels (below).

### Access reviews (T4)

A team's **Governance → Access reviews** (full administrator): `extras.review = {every_days,
answer_days, action}` - every N days (default 90) a review of the team's own members opens; its
managers (`team.members`, inherited) confirm each member and their roles, or take them out (taken
out at once). Nobody confirms their own membership (nor that of a group they are in). A review
can also be started by hand. By the deadline (`answer_days`, default 14), what is not answered is
`report` - the review becomes **overdue**, an event and the manager are told, it stays open for
answers - or `expire` - those memberships get `until` = now (kept in the list, marked ended and
"not confirmed in the access review") and the review closes. Every answer is kept (who, when, a
note): the team's **History** and **Download the report (CSV)** for an audit.
`GET /api/teams/reviews?team=` (none: the reviews open in the teams this account sees),
`POST /api/teams/review_open {team}`, `POST /api/teams/review_answer {id, who, keep, note}`; the
portal's `reviews`, `review_open`, `review_answer` the same.

### Separation of duties (T5)

A team's **Governance → Separation of duties** (full administrator), `extras.sod`:

- `no_self_approval: true` - the one who asked never approves their own request, **whatever the
  approval rule's `self` says** - certificate requests (portal and administration), actions waiting
  for an approval (`approve_actions`), temporary roles (never self-approved anyway).
- `exclusive: [[A, B], ...]` - two roles (or old rights, or capabilities) never held by the same
  person on the team: a membership holding both is **refused when members are saved** (the
  administration, the portal, the command line, a template), a temporary role that would make
  someone hold both is refused when it is given, and an **approver holding both is refused** when
  they approve (and not offered the request). A role is held when its distinctive capabilities
  (those beyond a Viewer's) are; a Team owner holds every role.

Rules of a team hold for the teams below it too (inherited; the refusal names the team whose rule
it is). Members who already hold both when a rule is set are listed after the save (the rule holds
for what is changed from then on).

### Templates and bulk import (T6)

Settings → Owners and teams → **Templates** (seen and changed by a full administrator only - a template may name members):

- **Save a team as a template**: its kind, description, limits (with the request profiles they
  name), contact addresses and governance (reviews, temporary roles, separation of duties, channels)
  - optionally its members. A webhook's address is never copied (it is a secret).
- A template can be edited as JSON (`kind, description, members, policy, contact_mail, extras`);
  `{team}` in a member or the description is the new team's name (`group:{team}-Admins`).
- **Make a team** from it: a name and where it stands (`POST /api/teams/from_template`).
- **Import from CSV** (`POST /api/teams/import_csv {csv, dry_run}`): a header naming the columns
  `name,parent,kind,template,description,contact_mail,members` (only `name` needed; `,` or `;`),
  members as on the command line (`local:jan=Requester+Deployer; group:Web=view`). A parent may
  come later in the file; the teams are made top-down. The preview marks each line new, there
  already (left as it is) or wrong (why); nothing is made while a line is wrong.

### Channels and escalation (T7)

A team's **Governance → Notifications and escalation** (full administrator), `extras.notify`:
the team's mail (empty: its contact addresses), the manager's, on-call's; Microsoft Teams and
Slack incoming webhooks (sealed, write-only - the page shows only whether they are set; an
address with a user or password is refused); and the chain:

| when | who |
|---|---|
| a certificate of the team ends within `expiry_days` (14) | the team (and its webhooks) |
| within `manager_days` (3) | the manager |
| a deployment failed | `deploy_failed`: on-call (default), the manager, the team, or nobody |
| temporary roles asked/given/ended, reviews opened/overdue | the team (switchable) |

Set on a team, the channels hold for the teams below it unless they set their own. Each message
goes once (per certificate and stage, per failed deployment and try), in the language of the
alerts; failed deployments from before the channels were set are not told. Mail goes through the
mail queue as every other notice (Settings → Mail); webhooks through the outgoing proxy rules.
**Try every channel now** (`POST /api/teams/notify_test`) sends a test and says what went. Without
channels nothing changes: the team's contact addresses are told as before (Notices).

### Health (T8)

Settings → Owners and teams → **Health**, the team's Overview, and the portal's **Health**: per
team (with the teams below it) - certificates running out (within the notice days), expired,
failed renewals, failed deployments, **outside the team's limits** (a source, validation or pair
not allowed, a name outside the suffixes, a wildcard where forbidden, a validity longer than
`max_days`), **weak keys** (RSA under 2048 bits, EC under 256, DSA) and the **quota** (`max_certs`
of the team that set it, with the teams below it). A score of 100 minus capped penalties
(expired/expiring 30, failed renewals 25, failed deployments 20, outside 15, weak 15, quota at
80/90/100 % 3/8/15) - good ≥ 90, fair ≥ 70, else poor; for the leadership the score of all teams
together (weighted by their certificates). A card opens the certificates behind each number.
`GET /api/teams/health[?team=]` (the teams this account sees), `GET /api/portal/health` (the teams
whose certificates the person sees). Computed in one pass, kept a minute.

### The digest by mail (T12, 1.0.140)

A team's page → **Digest**: off for every team until it is switched on. On the chosen day and
hour (weekly, or every day) one mail goes to the team's contact address and/or the members
chosen, with what needs the team - its own and that of the teams below it (unless *With the
teams below* is off):

- the certificates ending within N days (30), and those already ended;
- the renewals and deployments that failed since the last digest, and the deployments failing
  now;
- what waits: certificates waiting for approval, requests for a temporary role, access reviews
  open or overdue;
- the temporary roles granted (new, ending soon) and ended;
- the team's target agents that need a look (quiet, refused, waiting for confirmation, their
  own certificate ending, a blocked job).

The mail is HTML (tables and inline styles, as acme's other mails - Outlook draws it) with a
plain-text copy and links into acme, in each recipient's language where acme knows it (their
account's language; else the digest's; else the mails'), one mail per language. A member is
reached at the address of their account (a group: each member of it who signed in and has an
address; a membership that ended gets nothing). Nothing secret is in it: names, dates, states
and what the jobs said. A digest with nothing in it is not sent (*Not sent when empty*, on by
default). The first one goes at the next moment chosen after it was switched on - never at once.

**Show the preview** (anybody who sees the team) shows the mail as it would go now; **Send a
preview to me** mails it to one's own account address only. A full administrator **sets** it
and may **Send now** (to its recipients at once, an empty one too). The node that leads the
cluster sends it, once per period (`meta` `digest:period:<team id>`); with mail switched off
nothing is sent and the event says so; a digest that did not go (mail off, the mail server
refused it) leaves its time to the next one, so nothing that failed in between is left out.
Every sending (and every one not sent) is an event naming
the team - its Activity shows it. The settings are kept in the team's `extras` (`digest`), so
they go with the team into backups, the configuration's export and replication.

`GET /api/teams/digest?team=` · `POST /api/teams/digest_save {team, digest{on, every
weekly|daily, day 1-7, hour, contact, members[], days, skip_empty, below, lang}}` (full) ·
`POST /api/teams/digest_preview {team, digest?, lang?}` · `POST /api/teams/digest_send_me
{team}` · `POST /api/teams/digest_send {team}` (full). The command line: `acme --team-digest`,
`--team-digest-set`, `--team-digest-preview`, `--team-digest-send`; the console: **p** → *A
team's digest*.
