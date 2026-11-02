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
dim, info, ok, warn, crit, violet), `description`. Certificates and targets pick their
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

## The command line

    acme --teams                                   the owners and the tags, and how many certificates each
    acme --team-add NAME [--team-kind person] [--members 'local:jan=manage,group:Web=view'] [--contact-mail a@b] [--note ..]
    acme --team-edit NAME [--name NEW] [--members ...] [--contact-mail ...]
    acme --team-del NAME [--reassign OTHER|-]
    acme --tag-add NAME [--colour info] [--note ..] / --tag-del NAME [--strip]
    acme --teams-adopt                             teams and tags from what certificates say now

A member written without `=rights` gets `view,request`.
