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
| `portal` | 0 | the pages are open |
| `portal_directory` | | the directory people sign in against (else the administrators' one) |
| `portal_who`, `portal_groups` | anyone | anybody the directory lets in, or only members of these groups |
| `portal_session_min`, `portal_tries`, `portal_wait_min` | 15, 5, 15 | how long a sign-in lasts; wrong passwords before a pause |
| `portal_title`, `portal_hint`, `portal_help` | | the words on the pages |

The sign-in is the engine's (`acmelib/engine/390_the_portal_sign_in.py`):
a session of kind `portal`, the same on both nodes of a cluster.

## What they see

With `portal_cert` on, under "Your certificates":

* every certificate whose `owner` is them - their name as signed in, their
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

## Approving

In the administration, Certificates: a badge "N waiting for approval" next
to the buttons (and the state filter "waiting for approval") lists them.
In a certificate's detail, **Approve** (a word to the person, optional) issues
it at once and shows its job; **Decline** (why - required) puts it in the
state **`declined`**, with the reason shown to the person on the portal.

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
| `certs` → `GET /api/portal/certs` | `{rows, suffixes, issuers, formats, key_types, most, used, auto, keys, groups, may_request}`; each row with `via` (`me` or the group) and `job` (the latest) |
| `cert-job&id=` → `GET /api/portal/cert_job` | one job of one of their certificates, its steps (no debug lines) |
| `cert-download` → `POST /api/portal/cert_download` | `{id, format, password?}` → `{filename, mime, data_b64}` |
| `cert-request` → `POST /api/portal/cert_request` | `{names[], issuer, key_type, note}` → `{id, name, job_id, state, waits}` |

The code: `acmelib/certs/portal.py` (the routes, the approval, the mail),
`web/assets/certs-portal.js` and `certs-portal.css` (the page's part, plugged
into `portal.js` through `window.ACME_PORTAL_PARTS`), the settings in
`acmelib/engine/900_certificates.py`.
