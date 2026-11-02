# Request profiles

Settings → **Request profiles** (in *Messages and the portal*, next to *The
enrolment pages*) holds kinds of certificates people may ask for on the
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
certificate's dialog (*Send a new CSR*): it is checked against the profile (or,
the profile gone, it must name the same names) and the certificate is issued
again at once. A revoked one is not issued again with the same CSR: a new CSR
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
| `POST /api/reqprofiles/delete` | `{name}` (full administrator) |
| `GET /api/portal/certs` | adds `profiles` (those the person may use), `free_form`, `may_ask`; each row `formats`, `req_profile`, `from_csr` |
| `POST /api/portal/cert_request` | with `profile`: `{profile, names[], key_type, subject{F: value}, team, note}` or `{profile, csr \| csr_b64, team, note}` |
| `POST /api/portal/csr_decode` | `{profile, csr \| csr_b64}` → `{csr, names, cn, key_type, checks[{what, ok, said}], subject[{field, csr, cert, how}], will, eku, fits}` - nothing kept |
| `POST /api/portal/cert_csr` | `{id, csr \| csr_b64}` - a new CSR (right *manage*), issued again |

The table is `cert_req_profiles` (its settings in `config`, JSON) - backed up,
replicated and carried in the configuration's export as every other. The code:
`acmelib/certs/reqprofiles.py`, `api_reqprofiles.py`, `web/assets/reqprofiles.js`
(the pane), `web/assets/certs-portal.js` (the portal).
