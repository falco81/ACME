# The expiry calendar

When certificates run out, and when acme plans to renew them (1.0.140) - as a month, as a year
of squares, as a file for a calendar program and as a link a calendar program subscribes to.
Nothing changes until it is used: it only reads.

## Where it is

- **The administration**: *Certificates* → **List | Calendar** (the switch above the filters;
  the choice is kept in this browser). *Ctrl+K* → *The expiry calendar* opens it too.
- **The portal**: **Calendar** beside *Your certificates* (and beside *Ask for a certificate* in
  the team workspace) - the person's own certificates, those of their groups and teams, exactly
  as the portal lists them.

## What it shows

- **The tiles**: how many run out within 7, 30 and 60 days, the renewals acme plans in the next
  30 days and those that have run out already - each a click from its list.
- **Month**: a week a row (Monday first), each day with how many run out (its colour how soon:
  red within 7 days or run out, amber within 30, blue within 60, green later), the planned
  renewals (↻) and the first names. ‹ › and *Today* move between months.
- **Year**: 53 weeks from this one, a square a day (its colour how soon, its strength how many -
  *few … many*), a ring where only a renewal is planned; under each week its count. On a phone the
  squares scroll sideways within their own box.
- **The list** beside (under, on a phone): with nothing chosen *Next to run out*; a day, a week or a
  tile chosen - what runs out then and what acme renews then. Each certificate - its names, its
  owner, the day and how far off - opens **the certificate's own card** (on the portal its window
  there).

A **planned renewal** is shown only for a certificate renewed by itself, switched on, with a
source and not waiting for approval: its end less its renewal window (its renew days, never more
than a third of its life) - or the ARI window its CA suggested, if sooner. Revoked, switched off and
declined certificates are left out.

**The keyboard**: Tab to the days, the arrows move a day (in the year: ← → a week, ↑ ↓ a day), Page
Up / Page Down a month, Home / End the week's start and end, Enter or Space lists the day; Esc
closes a window.

## The filters (the administration)

*Team* (its certificates and those of the teams below it), *Source*, *Target* (deployed there),
**Only mine** (owned by you - `local:NAME`, your directory names - or added by you). The lists
offer only the teams, sources and targets of the certificates you may see.

**Who sees what**: exactly what the Certificates list shows the account (`teams.where`): a member
kept to their teams sees only their teams' certificates in the calendar, the file and the
subscription. At most 5000 certificates are drawn at once (the earliest); more is said.

## A file and a subscription

**Download .ics** writes the certificates of the calendar (with its filters; a month back and two
years ahead) as an iCalendar file (RFC 5545) for Outlook, Google Calendar, Apple Calendar or
Thunderbird: each end an all-day event with a reminder a week before, each planned renewal an
event of its own, in the page's language.

**Subscribe…** makes a **private link** (`https://NAME/calendar.ics?t=SECRET`) the calendar
program asks by itself (every 6 hours by default). The link:

- is the account's own - one per account; a new link replaces the old one, *Take it back* ends it;
- shows what the account may see **now** - its role and teams as they are when it is asked; an
  account switched off, deleted or no longer of the administration gets nothing (404);
- is shown once; acme keeps only its SHA-256 (`meta` `certs:calfeed:<hash>`, beside
  `certs:calfeed-of:<account>`), carried in backups and replication with the rest of `meta`;
- is answered by `calendar.php` (nginx `location = /calendar.ics`, never logged, its own rate
  limit), the same answer for a minute.

A full administrator sees who has a link (`acme --calendar-feeds`, the API) and takes any back.
Viewing as a member makes no link. The portal offers the file only.

## The command line and the console

| | |
|---|---|
| `acme --calendar [--from YYYY-MM-DD] [--weeks N] [--team TEAM] [--issuer SOURCE] [--target TARGET] [--json]` | the weeks (13 by default) with how many run out and are renewed, as bars, then each certificate: the day, how far off, when renewed, owner, source, names |
| `acme --calendar-ics FILE\|- [--lang cs] [the same filters]` | the iCalendar file (104 weeks, from 30 days back) |
| `acme --calendar-feeds [--json]` | the accounts with a link: when made, last fetched, its language (never the secret) |
| `acme --calendar-feed-revoke WHO\|all [--yes]` | take a link back |

The console: *Certificates → The expiry calendar* (`y`).

## The API

| | |
|---|---|
| `GET /api/calendar?from=&to=&team=&issuer=&target=&mine=1` | `{from, to, certs[{id, name, names, n_names, owner, issuer, state, not_after, renew_at, days_left, auto_renew, urgency}], count, capped, today, counts{day: {ends, renews, worst}}, weeks[{week, ends, renews}], options{teams, issuers, targets}, feed{on, made, used, may}}` - 800 days at most |
| `GET /api/calendar/ics` | the same filters, `lang` → `{text, filename, count}` |
| `POST /api/calendar/feed_link` | `{action: new, lang}` → `{token, path}` (shown once) · `{action: revoke}` - one's own |
| `GET /api/calendar/feeds` · `POST /api/calendar/feeds_revoke` | `{who}` or `{all: true}` - a full administrator |
| `GET /api/calendar/feed` | header `X-Acme-Calfeed: SECRET` → `{text}` (what calendar.php asks) |
| `GET /api/portal/calendar` · `GET /api/portal/calendar_ics` | the portal's: `{certs, rows, count, counts}` / `{text, filename, count}` |

The code: `acmelib/certs/expirycal.py`, `web/assets/calendar.js`, `calendar.css`,
`web/calendar.php`.
