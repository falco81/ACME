# Periodic reports for management and audit (Settings → Reports, 1.0.140)

A report is defined once and made by hand or on its day - weekly or monthly - as **CSV** and/or
**PDF**, kept to download again and mailed to whom you choose. **Nothing is made or mailed until
a report is defined**; an installation that defines none works exactly as before. (A team's
digest by mail: [teams.md](teams.md#the-digest-by-mail-t12-10140).)

| Kind | What it holds |
|---|---|
| Certificate inventory (`inventory`) | every certificate in scope: team, names, source, key, tags, state, end, days left, whether it renews itself, its deployments (and how many failed) |
| Expiry outlook (`expiry`) | what ends within N days (`options.days`, 90) - those already ended too, soonest first - with how each is renewed and its last error; a table by month |
| Compliance with the CA/B rules (`compliance`) | each issued certificate checked as the request profiles' compliance check does ([request-profiles.md](request-profiles.md)): the CA/Browser Forum's longest validity for a public CA and its schedule, RSA/EC key sizes, SHA-1, the company's own rules - *complies*, *does not comply*, *complies until a rule changes* |
| Agents and their health (`agents`) | the target agents: platform, mode, state (answers, quiet, refused, joining…), version, last heard from, when its own certificate ends, what needs a look |
| Teams and access (`access`) | each team's members with their roles or rights and ends, the temporary roles granted now, each team's last access review |

| Setting | |
|---|---|
| Name, kind | the name is unique |
| Teams | every team (also what has no team), or chosen teams - each with every team below it |
| Formats | PDF (A4 landscape: a heading, tiles of numbers, the table over as many pages as it needs with its head on each, "page N of M") and/or CSV (UTF-8 with its mark; a cell a spreadsheet would read as a formula gets a leading `'`) |
| Made by itself | by hand only, weekly (day 1-7, hour) or monthly (day 1-28, hour); the first run is the next moment chosen after it was set - never at once |
| Mailed to | addresses (at most 20); empty: kept here only |
| Language | Czech, English, or the mails' (`report_lang`, else `mail_lang`) - the words through the pages' translation, as the alerts' |
| Runs kept | 1-100 (12): the newest runs with their files |
| Schedule active | off pauses the schedule; Run now still works |

The PDF is written by acme itself (no library, `acmelib/certs/pdfwriter.py`): the standard
Helvetica fonts, Czech and Slovak letters by their glyph names, nothing embedded. A PDF holds the
first 5 000 rows, the CSV every row (at most 50 000).

- **Preview** shows what the report says now as a page - nothing kept or mailed - in Czech or
  English. **Run now** makes it and keeps it; asked to, mails it with its files attached (an
  HTML summary with its tiles and first rows, and a plain-text copy). **Runs** lists the runs
  kept, each file to download.
- On its day and hour the **node that leads** the cluster (the renewer's lease) makes and mails
  it; `meta` `reports:period:<id>` is claimed once per week or month, so two nodes never both
  send, and a node that was down catches up later in the same period.
- With **mail switched off**, nothing is mailed: the run is made and kept and says *mail is
  switched off*; the pane says so too.
- Each save, run, mailing, download and deletion is an event (kind *certificates*).
- **Who may**: a full administrator everything; a certificate administrator sees, previews and
  downloads the reports whose teams are all teams they manage (every report while *Certificate
  administrators manage every certificate* is on) - no recipients shown (nor the addresses a
  run went to), nothing changed or run, and only the runs made of teams they manage (a report
  whose teams were narrowed keeps its older runs from the full administrator alone); a
  read-only account nothing (the pane is not shown).
- `cert_reports` (the definitions) is in the configuration's export and import; with
  `cert_report_runs` (the runs and their files) in every backup and replicated like every other
  table. An older database gets both, empty, when the new version starts.

| API | |
|---|---|
| `GET /api/reports` | the reports one may see, each with its last run and next time; the kinds |
| `GET /api/reports/one?id=` · `GET /api/reports/runs?id=` | one with its runs · its runs |
| `POST /api/reports/save` | `{id?, name, kind, teams[], formats[], schedule{every, day, hour}, recipients, lang, keep, options{days}, enabled, note}` (full) |
| `POST /api/reports/delete` | `{id}` (full) |
| `POST /api/reports/preview` | `{id}` or `{draft}` (a draft: full), `lang?` → `{preview}` |
| `POST /api/reports/run` | `{id, send, to?}` → `{run}` (full) |
| `GET /api/reports/download?run=&format=csv\|pdf` | `{filename, mime, data_b64}` |

The command line: `acme --reports`, `--report-add/-edit/-del/-show/-run/-runs/-get`
([command-line.md](command-line.md)); the console: **p** in the main menu.

The team digest by mail (one team, weekly) is in [teams.md](teams.md).
