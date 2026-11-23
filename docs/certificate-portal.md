# The certificate portal

The pages at `/` (`web/index.php`) are the **certificate portal**: people who
are no administrators sign in there with their directory name and password
and see the certificates that are theirs, download them, and ask for new
ones. It is the "enrolment pages" of the engine acme was built on, with the
same sign-in, look and settings pane (Settings → The portal), turned to
certificates.

## Who signs in

Settings → The portal (`sect-portal`, `PANES['portal']`):

| key | default | |
|---|---|---|
| `portal` | 1 | the pages are open (certificates on them only with `portal_cert`, below) |
| `portal_directory` | | the directory people sign in against (else the administrators' one) |
| `portal_who`, `portal_groups` | anyone | anybody the directory lets in, or only members of these groups |
| `portal_session_min`, `portal_tries`, `portal_wait_min` | 15, 5, 15 | how long a sign-in lasts; wrong passwords before a pause |
| `portal_title`, `portal_hint`, `portal_help` | | the words on the pages |
| `portal_local` | 0 | acme's own accounts (Settings → Accounts) may sign in too |
| `portal_admins_all` | 1 | (with `portal_local`) their certificate and full administrators see every certificate |
| `portal_local_code` | same | the one-time code for acme's own accounts: as `portal_code`, off, or `mail` / `sms` / `sms_mail` / `mail_sms` |
| `portal_enrolers` | 1 | accounts of the role *enrolment pages only* sign in (acme's own, and the directory's group `admin_group_portal`) |
| `portal_krb`, `portal_krb_auto`, `portal_krb_realm` | 0, 0, | **signing in with Windows (Kerberos)** - the portal's own switches, independent of the administration's ([kerberos-sso.md](kerberos-sso.md)) |
| `portal_certlogin`, `portal_certlogin_match`, `portal_certlogin_crl` | 0, strong, 1 | **signing in with a certificate** (a smart card, a YubiKey) - the portal's own switches, on the certificate's port shared with the administration ([certificate-sign-in.md](certificate-sign-in.md)) |
| `portal_password_off` | 0 | *No password at all on the portal - only Windows or a certificate* |

**Signing in with Windows** (1.0.99): with `portal_krb` on and a keytab put in, a browser of the
domain signs its person in without a password - *Sign in with Windows* under the form, or at
once with `portal_krb_auto`. The person is looked up in this pane's directory by
sAMAccountName, and `portal_who` / `portal_groups` and the enrolment-only group decide as for a
password; the one-time code (`portal_code`) is sent after it every time. *...and no password at
all on the portal* takes the form away. Signed in by a load balancer ([portal-sso.md](portal-sso.md))
may be on beside it - each by itself. The whole of it in [kerberos-sso.md](kerberos-sso.md).

**Signing in with a certificate** (1.0.100): with `portal_certlogin` on and the authorities put
in, *Sign in with a certificate* takes the browser to the certificate's own port (8443) and back
signed in. The UPN in the certificate is looked up in this pane's directory, the account by its
sAMAccountName (the same DN), and `portal_who` / `portal_groups` decide as for a password; the
one-time code is sent after it every time. [certificate-sign-in.md](certificate-sign-in.md).

The sign-in is the engine's (`acmelib/engine/390_the_portal_sign_in.py`):
a session of kind `portal`, the same on both nodes of a cluster. Its data
carries `{kind: "directory" | "local", role}`.

* **The cookie** (1.0.101): `__Host-acme_portal` over https (the administration's
  `__Host-acme_session`) - Secure, `Path=/`, no `Domain`, HttpOnly, SameSite=Strict - so a
  sibling host (`Domain=.example.local`) or a page over http cannot plant one beside it. A
  request that carries two cookies of the same name is taken as signed out. Over plain http
  (a test server) the names stay `acme_portal` / `acme_session`. Cookies of before 1.0.101
  are not read over https any more: people sign in again after the upgrade.
* **The one-time code typed** (1.0.101): the portal hands a new sign-in (a new cookie), as the
  second step does - the one the password opened is ended.
* **With `db_guard` on** (1.0.101) the portal's sign-ins are signed as the administration's,
  and the portal's directory and settings (who may sign in, the keys handed out) are taken
  only as acme wrote them - [high-security.md](high-security.md).

### acme's own accounts (`portal_local`)

Off by default: only the directory's people sign in. On, the sign-in tries
**an account of acme's own first** (Settings → Accounts, the name as it is
written there - not `DOMAIN\name` or a UPN), then the directory:

* the same password check as the administration's; a wrong one goes on to the
  directory (somebody there may have the same name), and every wrong
  password counts towards `portal_tries` / `portal_wait_min`;
* an account **switched off** cannot sign in (said as a wrong password, and
  counted as one); one that must change its password changes it here, on the
  page after the password, before anything else (`POST /api/portal/password`,
  relayed as `?api=password`; also *Change the password* under the name);
* **the portal's one-time code** (1.0.44, `portal_local_code`, Settings → The
  portal → *A one-time code for acme's own accounts*): a setting of its own,
  not the administration's second step - `same` (the default: as
  `portal_code`, the directory people's), `off`, `mail`, `sms`, `sms_mail`,
  `mail_sms`. The code goes to the e-mail address or the mobile number the
  account has (Settings → Accounts → the envelope button, or
  `acme --user-contact NAME --mail ADDRESS --mobile NUMBER`; else the
  address or number of its administration's second step by mail or SMS).
  An account without what the way chosen needs cannot sign in here (by
  e-mail and no address; by SMS and no number - unless the way falls back to
  the other); the list of accounts marks those. While it is on, the portal
  does not ask the administration's second step. The address and the number
  are signed with the account (`db_guard`) once given;
* **the second step** (with the portal's code off) exactly as the administration's (`admin_2fa`): the code
  from the authenticator app, or a code sent by mail or SMS - the account's
  own way, the same one it uses at `/admin/`. With none set up yet the
  sign-in page sets one up, as the administration's does. Until it is given
  the sign-in can do nothing else (`GET/POST /api/portal/mfa`, relayed as
  `?api=mfa`; wrong codes count as wrong passwords). Switched on (`admin_2fa`), or the
  portal's code taken away while it is on, the sign-ins of acme's own accounts made without
  it end (1.0.101) - as the administration's do;
* High security: it keeps the second step on (`admin_2fa`) and allows only
  the app, so it holds for these sign-ins too - the portal's code by mail or
  SMS is not used then, the app is asked;
* the account's role is read again at every request: switched off, removed,
  or `portal_local` switched off, and the sign-in ends;
* events of kind `sign-ins`, as the administration's.

Without any directory set up and `portal_local` on, the pages let in acme's
own accounts only.

### The role *enrolment pages only* (`portal`, `portal_enrolers`)

A role of its own for people who should use these pages and nothing else:

* **acme's own account** (Settings → Accounts → role *enrolment pages only*,
  or `acme --add-user NAME --role portal`): signs in here whether
  `portal_local` is on or not (`portal_enrolers` decides); its first password
  it changes here;
* **from the directory**: the members of *Group of enrolment-only accounts*
  (`admin_group_portal`, Settings → Accounts, next to the other role groups,
  picked with *Find the groups*, or with the search button beside the box -
  1.0.128, as `portal_groups` - which puts the group's DN in as one more line)
  are let in here even with `portal_who` = groups and in none of
  `portal_groups`; no account is made for them;
* **never into the administration**: `/admin/` says "this account signs in on
  the enrolment pages only" (counted as a wrong password); an administrator's
  sign-in given this role (or put into that group) ends at its next request;
* **what they see and may ask for** comes from the teams they are members of
  (Settings → Owners and teams: `local:NAME`, the person, or a group, with the
  rights *see*, *ask for new*, ...) and from certificates owned by them -
  never every certificate, `portal_admins_all` does not apply to them.

## Who sees which certificate

What a person sees on the portal is decided by the **owner** of each
certificate (the `owner` field):

| owner | seen by |
|---|---|
| a person: `novak`, `novak@corp.cz` (UPN or mail) | that person of the directory - their sAMAccountName, UPN, mail or the name they signed in with |
| an account here: `spravce` or `local:spravce` | the account of acme's own with that name (`portal_local`); `local:` keeps a person of the directory with the same name out |
| a group: `CERT_USERS`, its DN, or `group:CERT_USERS` | every member of that directory group (nested groups too) |
| a team of Settings → Owners and teams (its name) | every member of the team with the right *see* - an account here as `local:NAME`, a person or a group of the directory; members with *ask for new* may ask for certificates owned by the team ([teams.md](teams.md)) |
| empty | nobody - but see below |

**Administrators see everything** (`portal_admins_all`, on by default): an
account of acme's own with the role **certadmin** or **fulladmin**, signed in
on the portal, sees **every** certificate kept here (and may download or ask
as the other portal settings allow). A **readonly** account, and everybody
from the directory, sees only the certificates they own. Off, administrators
see only their own too.

Where the owner is set:

* the certificate wizard, step **Names → Owner**;
* a certificate's **Edit** (the same field);
* the command line: `acme --cert-edit NAME --set owner=novak` (or
  `--set owner=group:CERT_USERS`, `--set owner=local:spravce`);
  An account of acme's own owns a certificate whose owner is its name alone (no `local:`)
  only where no directory signs in on these pages (1.0.88): with one, that name may be the
  directory's person of the same name, whose certificates and keys it took.
* a certificate asked for on the portal is owned by whoever asked (an account
  here as `local:NAME`).

In the administration the owner is shown in the certificate's detail; pointing
at it says who sees it on the portal.

## What they see

With `portal_cert` on, under "Your certificates":

* every certificate whose `owner` is them (see *Who sees which certificate*
  above) - their name as signed in, their
  account (sAMAccountName), UPN or mail - **or a directory group they are
  in** (nested groups too): the owner is then the group's name (`CERT_USERS`),
  its DN, or `group:CERT_USERS`. Their groups are asked of the directory at
  most every 10 minutes and kept in the session;
* for each: its state, names, source (issuer), when it runs out and the days
  left, and - in its detail - serial, key, the issuing CA and its latest job,
  step by step, followed live while it runs;
* download: certificate (PEM, DER), chain, full chain, P7B - and, only with
  `portal_cert_keys` on, a **PFX with the private key**, locked with a
  password of the person's own (8 characters at least). That is an event of
  level `warn`.

## Asking for a certificate

"Ask for a certificate": the names (one a line; each must be one of
`portal_cert_suffixes` or under it - checked as they type and again by the
daemon), the source (one of `portal_cert_issuers`), the key type, a note.

* `portal_cert_auto` on: the certificate is made (state `new`) and issued at
  once by a job; the page opens it with the job's steps live.
* `portal_cert_auto` off (the default): it is kept in the state
  **`pending-approval`** and is never renewed by itself (`auto_renew` 0) until
  an administrator approves it.

A source that proves names (ACME) uses the validation named in
`portal_cert_challenge`; own authorities and self-signed need none.

`portal_cert_max` is how many requests one person may make (rows of
`certs` with `created_by = portal:<them>`); declined ones and deleted ones do
not count.

### From a request profile

A full administrator can define **request profiles** (Settings → Request
profiles, [request-profiles.md](request-profiles.md)): kinds of certificates
with the source, the validation, the names allowed, the key or a CSR, the
subject, renewal, approval and owner set beforehand. When the person may use
any, *Ask for a certificate* first shows them as cards (and *Something else* -
the form above - only when `portal_cert_suffixes` and `portal_cert_issuers` are
set); a profile's form asks only what it leaves to them. A CSR sent in is
decoded and checked against the profile before it is asked for. With no
profile defined the portal asks exactly as above.

## Approving

In the administration, Certificates: a badge "N waiting for approval" next
to the buttons (and the state filter "waiting for approval") lists them.
In a certificate's detail, **Approve** (a word to the person, optional) issues
it at once and shows its job; **Decline** (why - required) puts it in the
state **`declined`**, with the reason shown to the person on the portal.

A request that left the waiting state but whose approval was never recorded
(a stop at the wrong moment before 1.0.106) is tagged **approval missing** in
the list; its detail - in the administration and on the portal, for those who
may approve it - offers **Approve** (its approval recorded; issued if it never
was) and **Decline** as for a waiting one, by the same checks: never by the one
who asked, names another owner holds by that owner's approver, and not
declined once it has a certificate (revoke it instead). Each such row carries
`stuck: true`, `may_approve`/`approve_why` and `may_decline`/`decline_why` -
an off button says why. `acme --decline NAME --why TEXT` still declines one too.

`POST /api/certs/approve {id, ok, why}` (role `certadmin`) →
`{job_id, message}`.

## Telling the person

When their certificate is issued, approved or declined, the person gets a
mail - if the directory gave a mail for them when they asked (kept in `meta`
as `certs:portal:<id>`). It goes through the engine's outgoing mail
(`mail_deliver`: sent at once, else kept and tried again, visible under
Settings → Mail), in the language of `ui_lang` (Czech or English).

Every request, approval, decline, download and mail is an event of kind
`certificates`.

## The API

Relayed by `web/index.php` (`?api=…`) with the person's portal session:

| | |
|---|---|
| `certs` → `GET /api/portal/certs` | `{rows, suffixes, issuers, formats, key_types, most, used, auto, keys, groups, may_request, sees_all, kind}`; each row with `via` (`me`, the group, or `*` when seen as an administrator) and `job` (the latest) |
| `mfa` → `GET/POST /api/portal/mfa` | the second step of an account of acme's own, as `/api/auth/mfa` |
| `cert-job&id=` → `GET /api/portal/cert_job` | one job of one of their certificates, its steps (no debug lines) |
| `cert-download` → `POST /api/portal/cert_download` | `{id, format, password?}` → `{filename, mime, data_b64}` |
| `cert-request` → `POST /api/portal/cert_request` | `{names[], issuer, key_type, note}` → `{id, name, job_id, state, waits}`; with `profile` see [request-profiles.md](request-profiles.md) |
| `csr-decode` → `POST /api/portal/csr_decode` | `{profile, csr \| csr_b64}` → the CSR decoded and checked against the profile |
| `cert-csr` → `POST /api/portal/cert_csr` | `{id, csr \| csr_b64}` → a new CSR for one issued for a CSR (right *manage*), issued again |

`certs` takes optional arguments (1.0.125): `team` (a team's name, `me` their own), `below=1`
(the teams below it too), `q` (text in the name, the names, the owner, the source), `state` (a
certificate's state or `expiring` / `failing` / `waiting` / `mine`), `page`, `per` (50, at most
200) - then one page is answered with `total, page, per, pages`. Without them the answer is as
before. Every row also carries `caps`: the capabilities the person holds on it.

## Teams - the team workspace (1.0.125)

A person who is a member of a team (Settings → Owners and teams, [teams.md](teams.md)
"Enterprise teams") works for it on the portal - and for every team below it. What they may
do is decided by their **capabilities** on that team (their memberships by name, `local:NAME`
or a directory group, their roles and old rights, inherited downwards) and limited by the
team's **limits** (its policy, narrowed by every team above). A refusal is `403` in words
naming what was missing, and an event `<who> was refused on the portal: ...`.

A person in **no team** sees exactly the portal as before: `GET teams` answers no teams and
every route below refuses them.

The existing actions map to capabilities: *Renew now* - `cert.renew`, renewed by itself on/off
- `cert.auto`, *Revoke* - `cert.revoke`, a PFX with the key - `cert.key` (and the team's
`key_download`), *Approve* / *Decline* - `cert.approve` (with the approval rule of the team:
the team's lead and/or the team above it, two approvers, never one's own unless `self`), new:
*Delete* - `cert.delete` (`POST /api/portal/cert_delete {id}`, not revoked). The old right
`manage` holds every one of them (and approves, as it did). Where the team's policy lists an
action in `approve_actions` (revoke, delete, key, device), it is **asked for** instead: the
answer is `{waits: true, action: {...}}`, the team's approvers find it under *Waiting for you*
and approve it (`action_approve`) - a revocation or deletion is then done, a key is then taken
once with the approval's id (`cert_download {..., action: ID}`). An administrator approves or
declines them too, by the same checks: `acme --team-actions`, `--team-action-approve ID`,
`--team-action-decline ID --why TEXT` (the console: **o** → *Actions of the teams waiting for an
approval*).

| route (`?api=`) | needs | what |
|---|---|---|
| `teams` → `GET teams` | - | the person's teams (with those below): kind, parent, description, `caps`, `direct`, `policy` (in force, with `from`), `own_policy`, `counts` (certs, expiring in 30 days, failing, devices, agents waiting, waiting for them), `children` |
| `inbox` → `GET inbox` | - | *Waiting for you*: `requests` (each with its `timeline`), `actions`; and what they asked for (`asked`, `asked_actions`) |
| `timeline&id=` → `GET timeline` | sees it | a request's timeline: asked, each approval / decline, let through, issued |
| `action-approve` → `POST action_approve` | an approver of the team | `{id, ok, why}` (why needed to decline) |
| `devices&team=` → `GET devices` | `target.view` | the team's devices (`below=1` those below too); each secret `''`, `secrets: {key: set?}` |
| `device&id=` → `GET device` | `target.view` | one device, its agent (state, server facts), the deployments to it |
| `kinds&team=` → `GET kinds` | `target.view` | the modules the team may use (policy `target_kinds`, `agents`; never `local`) with the fields the administration's form draws - a field choosing a connector lists the team's own only |
| `device-save` → `POST device_save` | `target.manage` | `{id?, team, name, kind, config, note, enabled, tags}` - the module's own checks (`api.family_save`), owned by the team; a device keeping secrets is not pointed elsewhere without typing them again; it goes through (`via`, `ssh_via`, ...) a connector of the team only (by its name), never acme's own nor another team's |
| `device-delete` → `POST device_delete` | `target.manage` | refused (409) while deployments use it |
| `device-test` → `POST device_test` | `target.test` | the module's test, as saved |
| `agent-code` → `POST agent_code` | `target.manage` | a one-time join code of a team's agent target |
| `enroll-code` → `POST enroll_code` | `target.manage` | a team enrollment code (`ACAE1.`): servers enrolling with it become the team's devices, waiting; `auto` only where the team's limits say `agents_auto_confirm` |
| `enroll-revoke` → `POST enroll_revoke` | `target.manage` | `{id}` |
| `agents-waiting&team=` → `GET agents_waiting` | `target.view` | agents asking to join, the team's enrollment codes |
| `agent-confirm` / `agent-refuse` → `POST agent_confirm` / `agent_refuse` | `target.manage` | `{id, fp}` / `{id}` - refused: forgotten, a device an enrollment made for it (never joined, unused) deleted |
| `agent&id=` / `agent-builder&id=` → `GET agent` / `agent_builder` | `target.view` | the agent's state and its server's facts; the policy designer's data |
| `agent-design` / `agent-update` → `POST agent_design` / `agent_update` | `target.manage` | a design saved (documentation only), the agent updated (as the administration) |
| `deploys&team=` → `GET deploys` | `deploy.view` | the deployments of the team's certificates |
| `deploy-save` → `POST deploy_save` | `deploy.manage` | `{id?, cert_id, target, options, enabled, note}` - a certificate of the team to a device of the team (or one above/below it), a module its limits allow; checked as a certificate administrator's (commands, scripts and where the key goes stay a full administrator's) |
| `deploy-delete` / `deploy-run` → `POST` | `deploy.manage` / `deploy.run` | `{id}` |
| `deploy-dry-run` → `POST deploy_dry_run` | `deploy.view` (`test`: `deploy.run`) | `{id}` What happens (the run plan, nothing contacted); `{id, test: 1}` the module's own test on the device |
| `members&team=` → `GET members` | `team.members` | the members (caps, expired, `me`, `may_change`), those of the teams above, the roles and rights with `givable` |
| `member-save` / `member-delete` → `POST` | `team.members` | `{team, who, roles[], rights[], until, note}` / `{team, who}` |
| `dir-search&q=&kind=` → `GET dir_search` | `team.members` somewhere | users / groups of the directory, 20 at most - the member dialog's typing and its *Pick from the directory* button (1.0.128) |
| `team-save` → `POST team_save` | `team.create` / `team.policy` on the team above | `{name, parent, kind, description, policy}` a team below one of theirs; `{old_name, ...}` renamed, moved, its limits |
| `team-delete` → `POST team_delete` | `team.create` on the team above | `{name, reparent?, reassign?}` (both default to the team above) |
| `activity&team=&page=` → `GET activity` | `team.activity` | what happened in the team (50 a page, `below=1`) |

**No escalation.** A member is given only roles and rights whose capabilities the giver holds
on that team; a member holding more than the giver is neither changed nor removed; nobody adds
themselves (or a group of theirs), raises or lengthens their own membership; the teams above
are never touched. A team's own limits are changed by those who hold `team.policy` on the team
**above** it - never their own team's - and never wider than those in force above (a wider
list, a larger number, true where above says false, a weaker approval, `agents_auto_confirm`
which only administrators allow, fewer approvers, a wider envelope of `outside`): refused in
words. A team made or renamed here never takes a name certificates or devices already carry as
their owner (it would own them), nor a person's (a mail or UPN, a user of the directory); a
team moved with new limits needs `team.policy` on its new place too; another's membership is
never made one's own; the old right *manage* approves, so it is given only by one who holds
`cert.approve`.

The relay (`web/index.php`) passes each GET's own arguments only (200 characters each) and
POST bodies of 256 KB at most.

The code: `acmelib/certs/portal.py` (the routes, the approval, the mail),
`acmelib/certs/portal_teams.py` (the team workspace),
`web/assets/certs-portal.js` and `certs-portal.css` (the page's part, plugged
into `portal.js` through `window.ACME_PORTAL_PARTS`), the settings in
`acmelib/engine/900_certificates.py`.
