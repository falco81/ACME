# Request profiles

Settings → **Request profiles** (in *Certificates*, under *Owners and teams*) holds kinds of certificates people may ask for on the
enrolment pages with everything but the names given beforehand. The person
picks a profile, gives its names (or sends their CSR) and what the profile
leaves to them; the rest is as it says. Profiles are added beside the portal's
free form (`portal_cert_suffixes`, `portal_cert_issuers`): with none defined,
nothing changes.

A full administrator adds, changes and deletes them, each in its own dialog
with its own Save; every other account of the administration sees them.
Deleting one leaves the certificates asked for from it as they are.

## What a profile holds

Everything is picked from its catalog - Certificates → Sources and
Validation, the key types, Owners and teams, the tags - never typed, except
the domains.

| | |
|---|---|
| Name, what it is for, offered | shown to people on the portal; off: kept, not shown |
| Source, names proved by | a source of Certificates → Sources; the validation only for one that proves names (ACME) |
| Under these domains, wildcards, names in one certificate | a name must be one of the domains or under it; `*.` only when wildcards are on (and the source gives them); at most this many names |
| acme makes the key / the person may send a CSR | either or both. A CSR is not offered by a source that signs only a key acme holds: self-signed, CMP, SCEP |
| Key types allowed, offered first | of a key made here, and of a CSR sent in; only those the source signs |
| The subject: O, OU, L, ST, C, e-mail | each *not used*, *fixed by the profile* (its value, whatever a CSR says) or *filled by the person* (what they type or what their CSR says, the value as the default). The common name is the first name |
| Renew by itself, days before the end, valid for, used for | renewal as a certificate's; the validity only where the source lets it be chosen; the extended key usages |
| When asked for | issued at once, or waits for approval |
| Whose it is | the person who asks; a team they pick among those where they hold *request*; or a team of the profile |
| Tags | put on every certificate asked for from it, beside `portal` |
| Who may use it | teams of Owners and teams: their members with the right *request* (or *manage*). None: everybody who may sign in to the enrolment pages. An administrator of acme's own who sees everything there (`portal_admins_all`) may use every profile |
| PFX with the key | the person may download a PFX with the private key - only for a key acme made |

The profile is checked as it is saved: what does not fit together (the
source, the validation, a name under each domain, a wildcard, each key type)
is refused in words, as a certificate is (`compat.py`). A profile whose
source is gone or switched off, or whose team is gone, says so in the list and
is not offered on the portal.

Renaming an owner or a tag in Owners and teams renames it in the profiles; a
tag deleted is taken off them.

## Versions

Every saved change of a profile is a new version (table
`cert_req_profile_versions`): who, when, what changed (the fields) and why - a
restore, a profile ending, its base deleted. A save that changes nothing makes
none. A profile made before 1.0.138 is version 1 as it is; its first change
writes it as it was (version 1, *as it was before versions were kept*), then
the change (version 2).

*History* on a profile's card shows the versions as a timeline - who, when,
the fields changed, how many certificates were asked for from each. *What
changed* compares one with the one before, *Compare … with …* any two (or one
with now): field by field side by side, a list's items taken away struck out
red and added green, the fields that are the same folded away. A full
administrator *restores* a version: the profile becomes as it said, written as
a new version (nothing is lost); its name, and whether it ends, stay as they
are now. The restore is checked as every save is.

A certificate asked for from a profile keeps the version it was asked for from
(and those of the profile's bases): the portal shows it beside the profile's
name (*Web servers · v3*); the history counts the certificates of each version.
Renamed, a profile keeps its versions; deleted, they go with it. The versions are
backed up, replicated and carried in the configuration's export with the
profiles (an imported version is matched by its `uid`, never doubled).

## A base profile

A profile may be *based on* another (*General → Based on*): each field is then
either **inherited** - it is the base's, read-only in the editor, and a change
of the base applies to it at once - or **overridden** - its own value. Each
field (each group: the source with its validation, the domains, wildcards, the
number of names, the key made here, the CSR, the key types with the one offered
first, renewal, days before the end, the validity, the extended key usages,
approval, whose it is with its team, the tags, who may use it, the PFX, and
each subject field) has its *inherited* / *overridden* toggle beside its label.
Chosen first, a base gives everything but the domains and the teams - "Company
web" as the base (the source, the key, the subject's O and C), the profiles
based on it change only their domains and teams. Name, description and
*offered* are always the profile's own.

Kept is only what a profile overrides (`config` holds `base` and `inherit`,
the list of inherited groups); what it inherits is read from its base when it
is used, so the portal, a CSR's check and a dry run always see the profile as
it works now. A base may have a base (8 at most); no circle - a profile is
never based on itself or on one based on it. A change of a base that would
make a profile based on it no longer fit together (its source taking no CSR
when the profile overrides *the person may send a CSR*, ...) is refused,
naming that profile.

**Deleting a base** is refused while profiles are based on it; the dialog
offers *Delete it* that first makes each of them stand alone - it takes what it
inherited as its own (a new version of it, *its base … was deleted: it stands
alone*) - so nothing they give changes. A base gone any other way (an import)
is said on the profile, which is then not offered.

A team or tag renamed or deleted follows into every profile as before; a
profile whose teams become none through its base is switched off, as one whose
own only team is deleted.

## The compliance check

*Compliance* (beside *Add a profile*) checks every profile, and every
certificate asked for from one, on any date (today by default):

- **The CA/Browser Forum's schedule** of the longest validity of a publicly
  trusted TLS certificate (Baseline Requirements 6.3.2, ballot SC-081v3):
  398 days, **200 days** from 15 March 2026, **100 days** from 15 March 2027,
  **47 days** from 15 March 2029. Only for a public source (an ACME CA such as
  Let's Encrypt, a commercial CA): a private CA - an authority of acme's own,
  AD CS - is not bound by it. A profile that sets its validity is checked
  against the step of each date; one that leaves it to the CA is said to (the
  CA keeps to the schedule itself). Its *days before the end* at least as long
  as a step's validity is a warning (it would be renewed again at once).
- **Keys and algorithms**: RSA below 2048 bits, an EC key below 256, a
  signature with SHA-1 (of a certificate issued), Ed25519 at a public CA.
- **The company's own rules** (*The company's own rules*, saved by a full
  administrator; none by default): the longest validity of any certificate of a
  profile (a private CA's too), the shortest RSA key (2048, 3072, 4096), key
  types forbidden, wildcards only with approval, no PFX with the key, the most
  names in one certificate.

Each finding says from when: now, or a date. The schedule is shown as steps
(today, 15 March 2027, 15 March 2029) with how many profiles / certificates
stop complying at each; a click on a step (or the date box) shows the report on
that date: each profile *complies*, *does not comply* (now) or *stops
complying* (complies today, not on that date), with its findings and its
certificates (their version of the profile, until when, theirs).

## A dry run

*Dry run* on a profile's card: names (or, where the profile takes one, a CSR),
the key type, the subject fields left to the person and the team - and *Try
it* shows what would be issued, without issuing, asking a CA or keeping
anything (no event either): would it be issued or refused (each reason), the
subject as it would be (CN and each field), the names, the key (made by acme or
the CSR's), the extended key usages, the validity (the profile's, the source's,
or what the CA gives; until about when; the public limit now), the source,
approval (at once, or waits - and for whom: the profile, a team's approval
rule, names held by another owner), whose it is, the tags, renewal, the PFX,
and what the compliance check says of it. The teams' limits are checked as a
request is.

## A profile that ends

*End it…* (a full administrator) marks a profile as ending, with its
**successor** (another profile that does not end) and a note. From then:

- the portal no longer offers it (a request from it is refused);
- each certificate asked for from it takes the successor's settings **at its
  next renewal** - the source and validation, the key type (where the
  certificate's is not among the successor's; never for a CSR's key), the
  subject (the successor's fixed fields, the person's own kept), the extended
  key usages, the validity, days before the end, the successor's tags added -
  and its request then says the successor (and its version). A certificate the
  successor cannot give (a name outside its domains, more names, a CSR it does
  not take, a CSR's key it does not take, a source gone) is renewed as it is,
  and the job says why. A successor that ends itself passes them on to its
  own.

The dialog shows **the impact** before anything is done: each certificate, when
it is renewed, whether it moves and what changes (from → to), or why it
cannot. Ending is **reversible**: *Offer it again* takes it back - the profile
is offered again and nothing more moves; certificates that moved already stay
with the successor. Ending and taking it back are versions of the profile. The
successor of an ending profile cannot be deleted.

## On the portal

*Ask for a certificate* shows the profiles the person may use as cards -
name, what it is for, what it gives - and *Something else* (the free form)
only when that is set up. A profile's form shows what the profile fixes,
read-only (*What this profile gives*), and asks only for the rest: the names
(checked as they are typed against the domains, wildcards and how many),
the key type among those allowed, the subject fields left to the person, the
team when the person picks it, a note.

With a CSR allowed: *Send a CSR* - pasted (PEM) or a file (PEM or DER). It is
first decoded by the daemon and shown: the subject (each RDN), the names as
chips, the key type and size, the signature algorithm and whether the
signature is valid, key usage and extended key usage, must-staple - and each
check against the profile (every name allowed or not, how many, the key
type, what the source and the validation say) and, field by field, what the
CSR says beside what the certificate will say. Only a CSR that fits can be
asked for.

The limit of requests one person may make (`portal_cert_max`) counts these
too. Approval is as for the free form: the certificate administrators in the
administration, and on the portal the members of the owner team with the
right *approve* (or *manage*).

## A certificate from a CSR

acme never has its key. The CSR is kept with the certificate
(`certs.csr_given`) and sent again at every renewal - so the same key. To
change the key, a member with the right *manage* sends a new CSR from the
certificate's dialog (*Send a new CSR*): it is checked against the profile and
the certificate is issued again at once. With the profile deleted, a new CSR is
refused - ask for a new certificate from another profile. A revoked one is not issued again with the same CSR: a new CSR
is needed.

The subject is the one the profile says (an authority of acme's own puts it
in, whatever the CSR says; an ACME CA puts only the names). The certificate
issued must be for the CSR's key, or the renewal fails.

A PFX or any other file with the key is refused - on the portal and in the
administration - in words that say why. A deployment to a target that needs
the key fails with the same words; one that takes only the certificate works.
The sources that can sign it: an authority of acme's own, ACME, and every
other source that sends a CSR to its CA - not self-signed, CMP or SCEP.

## The API

| | |
|---|---|
| `GET /api/reqprofiles` | the profiles (`problems`, `used`) and `options` - what a profile picks from |
| `POST /api/reqprofiles/save` | `{name, old_name?, description, enabled, issuer, challenge, suffixes[], wildcards, max_names, make_key, csr, key_types[], key_default, subject{F: {mode, value}}, auto_renew, renew_days, days, eku[], approval, owner, owner_team, tags[], teams[], pfx}` (full administrator) |
| `POST /api/reqprofiles/save` (1.0.138) | also `base` (a profile's name, '' none) and `inherit[]` (the groups taken from it: `source`, `suffixes`, `wildcards`, `max_names`, `make_key`, `csr`, `key_types`, `auto_renew`, `renew_days`, `days`, `eku`, `approval`, `owner`, `tags`, `teams`, `pfx`, `subject.O` …); the list adds `base`, `inherit`, `children`, `version`, `ends` |
| `POST /api/reqprofiles/delete` | `{name, detach?}` (full administrator) - the base of others: 409 with `children`, unless `detach` |
| `GET /api/reqprofiles/versions?name=` | `{profile, current, versions[{version, at, by, why, changes[], certs, snapshot}]}` |
| `GET /api/reqprofiles/diff?name=&a=&b=` | two versions (`now`: as it is) - `rows[{key, a, b, same}]`, `changes[{key, a, b, added?, removed?}]` |
| `POST /api/reqprofiles/restore` | `{name, version}` (full administrator) - as a new version |
| `GET /api/reqprofiles/compliance?at=YYYY-MM-DD` | `{today, at, limit_now, limit_at, schedule, steps[], rules, profiles[{name, public, days, status, findings[{rule, level, said, from}]}], certs[...], count, cert_count}` |
| `POST /api/reqprofiles/rules` | `{max_days, min_rsa, forbid_keys[], wildcards_approval, no_pfx, max_names}` (full administrator) |
| `POST /api/reqprofiles/dryrun` | `{profile, names[] \| csr \| csr_b64, key_type, subject{F: value}, team, who}` → `{fits, refused[], subject, sans, eku, key, validity, issuer, approval{waits, why, approver}, owner, tags, renew, pfx, findings, version, chain}` - nothing kept |
| `GET /api/reqprofiles/impact?name=&successor=` | the certificates asked for from it: `{moves, why, changes[{field, from, to}], renews}` each |
| `POST /api/reqprofiles/ends` | `{name, successor, note}` or `{name, undo: true}` (full administrator) |
| `GET /api/portal/certs` | adds `profiles` (those the person may use), `free_form`, `may_ask`; each row `formats`, `req_profile`, `req_profile_version`, `from_csr` |
| `POST /api/portal/cert_request` | with `profile`: `{profile, names[], key_type, subject{F: value}, team, note}` or `{profile, csr \| csr_b64, team, note}` |
| `POST /api/portal/csr_decode` | `{profile, csr \| csr_b64}` → `{csr, names, cn, key_type, checks[{what, ok, said}], subject[{field, csr, cert, how}], will, eku, fits}` - nothing kept |
| `POST /api/portal/cert_csr` | `{id, csr \| csr_b64}` - a new CSR (right *manage*), issued again |

The tables are `cert_req_profiles` (its own settings in `config`, JSON) and
`cert_req_profile_versions` (1.0.138) - backed up, replicated and carried in the
configuration's export as every other; the company's rules are kept in `meta`
(`certs:reqprofiles:rules`), the version a certificate was asked for from in its
request (`certs:portal:<id>`: `profile_version`, `base_versions`, and
`moved_from` once it moved to a successor). The code:
`acmelib/certs/reqprofiles.py` (with the base), `reqprofiles_more.py` (versions,
compliance, dry run, ending - and `migrate_on_renew`, called by
`renewer.renew_cert`), `api_reqprofiles.py`, `web/assets/reqprofiles.js` (the
pane), `reqprofiles-more.js` (its history, compliance, dry run and ending
dialogs), `web/assets/certs-portal.js` (the portal).
