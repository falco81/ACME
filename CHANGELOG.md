# Changes in acme

Newest first. Each version's section is what the pages show before an
upgrade (and, going back, what is given up), so it says what changed for
the people who run acme - one `## X.Y.Z - date` heading per version.

## 1.0.139 - not released

- **Czech: the built-in roles by their Czech names in events.** "roli Schvalovatel", not "roli Approver", where an event or a message names a built-in role (Approver, Viewer, Requester, Renewer, Deployer); a role of your own keeps its name.
- **Czech: the team rules' refusals in Czech.** A temporary-role request or an access review decided already, a team you may not see, viewing as yourself: whole Czech sentences instead of English or half-English words ("už je granted").
- **Viewing the portal as a member ends with the administrator's role.** A portal sign-in opened with *Open the portal as…* ends at once when the full administrator who opened it is one no longer (another role, disabled, deleted) - it no longer stays for its two hours.
- **Target agents: the key schedule tries a refusing agent again.** An agent that refused acme's new command key once (changed less than an hour ago, busy) was left out of *Change on a schedule* until *Rotate now…*; it is tried again a day later.
- **Target agents: no false alarm in the audit chain after a restore.** The jobs acme sent between the moment a backup was made and its restore were shown as "a job acme never sent" with an alert; they are marked *between a backup and its restore* now.
- **Settings → DNS at phone width.** The row's buttons (Test, Edit) stay at the right edge with their column's header, as in every other table, instead of covering the Timeout column.

## 1.0.138 - 2026-11-21

- **Target agents: a tamper-evident audit chain.** With the new policy line `audit chain` (`sudo acme-agent audit on` - root decides) the agent writes every job it takes, does or refuses into an append-only log in which each entry holds the hash of the one before, and each entry also goes to the journal (Windows: the Application event log); `acme-agent audit show | verify` on the server. Switched on per agent on its card (*Watching this agent → Audit chain*), acme compares the chain with the jobs it sent and raises an event and an alert for a job it never sent, a gap or a chain written anew, until a full administrator has looked at it; the card shows the audit timeline with verified marks. Off by default - nothing changes until it is switched on.
- **Target agents: anomaly alerts.** Per agent, off by default: the agent coming from a new network, its policy changed or widened on the server (a new folder, unit, test, script, connection...), drift from its saved design or its fleet template, its clock off, silence, an older version, a command key acme does not know - as events, alerts and badges on the card and on Settings → Target agents; *Take it as its usual…* accepts what is there now.
- **Target agents: key rotation and key age.** acme's command key can be changed - the new key announced in a job signed by the old one and proven by itself, the old one still taken for three days, then retired once no agent pins it - and the agent's key for secrets made anew. *Rotate now…* on the agent's card (a full administrator), an optional schedule per agent (every 30-365 days), and *Keys and their age* on Settings → Target agents. Every key is kept sealed in the database as the command key is (backups, both nodes). Nothing changes until used.
- **Target agents: "deployed, but the service still serves the old certificate".** Switched on per agent on its card (*What the service serves*; off by default), acme asks the agent after a deployment and every six hours which certificate the service on the server itself serves, and shows a forgotten reload as a warning on the deployment, the agent's card and an alert. It works only where the agent's policy already allows `allow probe local` - no permission is taken. Nothing changes until it is switched on.
- **Agent fleet: every target agent at a glance.** Settings → *Agent fleet* shows the agents' health as a ring, what needs a look, the agents by kind (Linux, Windows, Kubernetes) and the versions as a chart; groups of agents as cards (health, members, the template they follow and how many drifted, versions) with *Ask now*, *Update* and *Compare* on all their agents; every agent chosen for actions on many (ask now, update, compare with the template, a template, a group). Nothing changes until a group or a template is made; who may: read-only looks, a certificate administrator asks and takes over, a full administrator changes groups, templates and updates.
- **Policy templates for the agents.** Built-in templates (nginx web, Apache for RHEL and Debian, HAProxy, Postfix + Dovecot, Exim, OpenLDAP, PostgreSQL, IIS, Remote Desktop, IIS + Remote Desktop) and your own - *Save as a fleet template* in the policy builder keeps the policy clicked together (versions, in every backup and on both nodes). The builder's *Templates* offers them as *Fleet templates*: one click adds a whole one. A template is documentation, as a design is: acme never sends a policy.
- **The drift of each agent from its template.** A group (or an agent itself) names the template its agents follow; the fleet says *matches* or *drifted* with the lines missing on the server and those it has besides, and copies one block that makes the server match (`acme-agent policy apply`). Other parts of acme read the template an agent follows (`fleet.agent_template`).
- **Agent updates in rings.** *Updates → An update in rings*: the canary group (or 5 % of the agents) is updated first; after the wait (60 minutes by default) the rest follows - only when every canary agent runs the new version and answers, else the rollout is held with who and why (*Go on anyway*, *Stop*). Only acme's own signed agent, only where the policy says `allow self-update`, as before.
- **Certificates found on the servers that acme does not manage - and their take-over.** *Agent fleet → Not managed* lists, across every server's last discovery, the certificates acme does not manage, the most urgent first (expired, ending this week, within 30 or 60 days, self-signed). *Take over…* previews what happens - the certificate in acme with the same names, a deployment to the same place through the agent, each policy line it needs (allowed or the `acme-agent allow` line to copy) - and makes them only when confirmed; it issues at once only when the agent's policy allows all of it, and nothing is written on the server before that.
- **acme-agent for Kubernetes.** `deploy/agent/k8s`: an image, manifests (a namespace, a ServiceAccount, RBAC only for the Secrets and Deployments named, a Deployment that never runs as root, on a read-only file system) and acme-agent's Kubernetes side: the same join, signed jobs and sealed keys as acme-agent, writing `kubernetes.io/tls` Secrets and restarting a Deployment only where its policy (a ConfigMap acme cannot change) says `allow secret NAMESPACE/NAME` and `allow restart NAMESPACE/NAME`; the whole job checked before anything is written, the Secrets as they were put back when the cluster refuses a step; discovery of the TLS Secrets. In acme it is a target *Server with acme-agent* (docs/agent-fleet.md, deploy/agent/k8s/README.md).
- **Who may do what - and why.** Settings → Owners and teams → *Who may*: a person's teams, or a team's people, against every capability - each dot says why (which role or right, on which team, inherited from where, a temporary role, ending when) and where the team's limits still narrow it; *Who may…* answers the reverse ("who may download the key of this certificate?"). Built on the same caches the server enforces with, fast with thousands of teams. Members who manage a team see it on the portal too. Nothing changes until it is opened.
- **View as a member, read-only.** A full administrator opens the administration - or the portal, in a new tab - as a chosen member sees it (their role, teams and limits). Every write is refused by the server meanwhile, a banner says whom you see as with *Stop viewing as*, and it is written in the events and the team's activity.
- **Temporary roles (just-in-time).** A team may let its members ask for a role for a few hours with a reason (*Governance → Temporary roles*: which roles, how long at most); a manager of the team approves it - never the one who asked - and it ends by itself. On the portal (*Access*) and in the administration (*Requests*), audited and told. Off by default.
- **Access reviews.** Every N days (e.g. 90) the managers of a team confirm its members and their roles, or take them out; what is not confirmed by the deadline is reported or expires, as the team says. History and a CSV report for the audit. Off by default.
- **Separation of duties.** Per team (and inherited below): the one who asks never approves their own request whatever the approval rule says, and pairs of roles never held by the same person - refused when members are saved, when a temporary role is given and when somebody approves, in plain words. Off by default.
- **Team templates and CSV import.** A team saved as a template (roles, limits, profiles, notifications - never a secret), a new team made from it in one step, and a whole structure imported from a CSV file with a preview first. Templates are part of the configuration (backup, export, replication).
- **Team channels and escalation.** A team's own e-mail addresses and Microsoft Teams / Slack webhooks (kept sealed, never shown again) with an escalation chain: a certificate ending in 14 days → the team, in 3 days → the manager, a failed deployment → on-call; *Try every channel now*. Without channels the team is told as before.
- **Team health.** A card per team - running out, expired, failed renewals and deployments, certificates outside the team's limits, weak keys, quota use - and one score for the leadership; on the teams page, the team's overview and the portal's *Health*.
- **Request profiles: versions, a diff and restore.** Every saved change of a request profile is a new version - who, when, which fields changed and why. *History* on a profile's card shows them as a timeline with how many certificates were asked for from each; *What changed* and *Compare … with …* put any two versions (or one and now) side by side, field by field, what went struck out red and what came in green. A full administrator restores a version as a new one, nothing lost. A certificate asked for from a profile keeps the version it came from (the portal shows *Web servers · v3*). The versions are backed up, replicated and carried in the configuration's export with the profiles. A profile made before is version 1 as it is; nothing changes until it is changed.
- **Request profiles: a base profile.** A profile may be based on another (*General → Based on*): each field is *inherited* - the base's, read-only, and a change of the base applies to it at once - or *overridden* with a value of its own, with a toggle beside every field. "Company web" as the base (source, key, subject), the profiles based on it change only their domains and teams. No circles; a change of a base that would break a profile based on it is refused, naming it; deleting a base first makes the profiles based on it stand alone with what they inherited, so nothing they give changes. Without a base nothing changes.
- **Request profiles: the compliance check.** *Compliance* checks every profile and every certificate asked for from one against the CA/Browser Forum's schedule of public TLS validity (398 days; 200 from 15 March 2026, 100 from 15 March 2027, 47 from 15 March 2029 - only for publicly trusted sources, not an authority of acme's own or AD CS), against short keys and SHA-1, and against the company's own rules (the longest validity, the shortest RSA key, key types forbidden, wildcards only with approval, no PFX with the key, the most names - none set by default). The report shows on any date which profiles and certificates comply, do not, or stop complying then, step by step through the schedule. It only reads.
- **Request profiles: a dry run.** *Dry run* on a profile's card shows what it would issue for given names (or a CSR): the subject, the names, the key, the extended key usages, the validity, the source, whether it waits for approval and for whom, whose it is, the tags and renewal - or each reason it would be refused. Nothing is issued, asked of a CA or kept.
- **Request profiles: ending a profile with a successor.** *End it…* marks a profile as ending, with its successor: the portal stops offering it, and each certificate asked for from it takes the successor's settings at its next renewal (one the successor cannot give is renewed as it is, the job says why). The dialog lists the certificates first - when each is renewed, whether it moves and what changes. *Offer it again* takes it back. Nothing changes until a profile is ended.
- **The right button over every list.** A right click on a row of any table of the administration - certificates, sources, validations, targets, tests, jobs, events, deployments, DNS sets, users of the nodes, and a team in the tree of Owners and teams, a role of the roles' matrix, a request profile, an agent's tile - opens a menu of that object: Open, its actions (Renew now, Deploy now, Run its tests, Test it now, Edit, Make it the default, Delete…: the same code as its buttons, the same questions and checks), Copy the cell, Copy the row as text, CSV or JSON (never a secret), its identifiers (name, serial, fingerprint…), Filter by this value / Leave out this value (through the list's own search box where it has one), Show in Events / Jobs and its History. What your role or your teams do not allow is greyed with why; somebody who may only look sees no action. Shift + the right button, a box to type in, a link and selected text keep the browser's own menu; while *Edit the columns* is on, a table keeps the column menu exactly as before. The Menu key or Shift+F10 opens it on the focused row, a long press on a phone; arrows, Enter, Esc. The portal's tables have it too (copy, filter). See docs/context-menu.md.
- **Several rows at once.** Ctrl+click (⌘-click) and Shift+click pick rows, a bar at the bottom says how many (Esc clears them); the right button on them renews, deploys, switches renewal by itself on or off, gives them to a team, adds a tag, pastes a deployment or deletes certificates, and tests or switches sources, validations, targets and tests on or off - each first showing what will happen to which (and which are left as they are, and why), then one result for all of them.
- **The acme clipboard: copy, paste, clone.** An object goes on the acme clipboard as JSON without any secret, in every tab of the browser; pasted on the empty part of its list it opens its own form filled in under a name of its own, saved only with Save. Clone does the same from the row: a certificate as a new request with the same names and settings (never the same key), a source, validation, target or test with **the same credentials** - copied and sealed again on the server, never sent to the page - or new ones, a team without its members, a role, a request profile, a DNS set, a user of the nodes. A deployment copied from one certificate is pasted onto another or onto several picked at once; a target's tags and a team's limits are pasted onto others. Nothing changes until it is used.
- **Copy as a CLI command or as an API call.** Any object's menu copies the `acme …` command that makes it again (`--cert-add`, `--target-add … --set`, `--deploy-add`, `--dns-set-add`, `--team-add`, `--role-add`…) and the `curl` call of the page's own route; a secret is always `KEY=-` (asked for by the command line) or `<fill in>`.
- **Ctrl+K: find and do anything.** One box over the page finds certificates, targets, agents, sources, validations, tests, teams, request profiles, every page and every pane of Settings, and the page's own buttons; a verb first acts on what it finds ("renew web", "test fw1", "obnov web"); the last ones chosen come first. Keyboard only, if you like.
- **Trash: what is deleted can be restored for 30 days.** A target, deployment, test, source, validation, request profile, owner, role, tag, DNS set, DNS record of your own or certificate deleted on the pages, on the command line or through the API goes to Settings → Trash and history → Trash, with what went with it (a certificate's deployments and tests, a target's deployments, a DNS set's functions). Restore… shows first what comes back - its secrets sealed as they were, never shown - offers another name when its name was taken since, and brings back what it needs (a deployment's target) when that is in the trash too; it is saved through the object's own route, with every check of who may. A certificate is kept without its key and its certificates and comes back as a request, not issued - a deleted key never comes back. Delete for good and Empty the trash are a full administrator's. Kept 30 days (Keep what was deleted, 0 = no trash, as before); in every backup and replicated between the nodes.
- **History of every object, with the difference and "Restore this version".** Every change of those objects is written down - who, when, from which address and, field by field, what it was and what it became (a secret only as "changed"). The History button in the head of a certificate's window and of a source's, validation's, target's or test's form, and Settings → Trash and history → Latest changes (filtered by kind, person and time) show it; Restore this version shows what would change and saves it again as any change, checked and written down as a new version (the current secrets stay unless asked otherwise). Kept 365 days (Keep the history of changes, 0 = none written). Nothing changes in how anything is saved.
- **Saved views of the lists.** By the filters of the certificates, sources, validations, targets, tests, jobs, events and the lists of Settings a small menu Views keeps the filters, the sort and the columns under a name - for yourself, shared with a team (who may see the team) or, by a full administrator, for everybody - picked again from the menu, and one opened by itself with the page (the star). Kept by the daemon, so they follow you to every browser; your own column layout is never overwritten. Nothing changes until a view is saved.
- **Going back to an older version: refused below 1.0.138 while a target agent still pins an earlier command key.** An older acme signs with the current key only, so such an agent would refuse every job; going back names the agents and asks to let them move to the current key first.
- **Going back to an older version: refused below 1.0.138 while base profiles or team governance are in use.** An older version would read a profile on a base profile without what it inherits, and drop a team's separation of duties, temporary roles, reviews and channels without a word; going back names them and asks to let the profiles stand alone and switch the governance off first. With neither in use, going back is as before.

## 1.0.137 - 2026-11-20

- **FortiGate guides: the order of the key formats as it is.** The guides (and the 1.0.136 notes) said the *automatic* key format tries PKCS#8 encrypted with a one-time password first and PBKDF2 2048 second, and that a refusal changes nothing. acme tries PKCS#8 encrypted with PBKDF2 2048 first, then PBKDF2 600000, traditional encrypted, PKCS#8 and traditional; over SSH the plain key goes first. On FortiOS 7.4 a refused PUT may still change the key kept, which is why a certificate of a VDOM's range gets no trial PUT there. Only the text changed.
- FortiGate: replace in place with a private key that is not the certificate's stopped only after the intermediates had been imported as CA certificates and acme's own copy of the certificate deleted (REST API and SSH), while saying "nothing was sent"; the key is now checked before anything is written.
- FortiGate: a "Management VDOM" typed on the target that differs from the one the FortiGate says (a token that reads system global) was taken, so a certificate of a VDOM's range could be put through the global range in a VDOM that is not the management one (which empties it on FortiOS 7.4); the FortiGate's own is now taken, and a typed name that is not one of the FortiGate's VDOMs counts as not known (said as a warning).
- FortiGate: a token limited to one VDOM (cmdb system vdom lists only that one) was taken for a FortiGate without VDOMs; one VDOM listed that is not root now means VDOMs are on, and a lone root is checked against system global.
- Guard against writes to the database: switched on on a node where it had never been on, the backups' targets and settings and the uploaded modules were not checked until the next hourly adoption, which then signed whatever had been written there meanwhile as acme's word; they are checked from the moment the guard is switched on, as the rows it signs then (security).
- Database agent: a `dbagent:addr:NODE` row that was not a JSON object stopped the other node's new address from being let in through acme-db-agent (an error every 30 s); such a row is skipped and the others are still read.
- Database agent: a `load:db:NODE` row that was not a JSON object, or had a time that was not a number, broke the meter's list of database servers; it is skipped.
- External database, changing a node's address: a network job that stopped after the database server's agent had been told the new address (`dbagent:addr`) left it there - the other node's agent let in, and in layout B pointed keepalived, the firewall and chrony at, an address the node never took. The job now tells the old address again, as it does for the other node's HA settings.
- Targets: a "Previous versions to keep" left empty was read as 2, not as the target's own default - a Plesk deployment (default: keep all) deleted the older certificates of its repository; an empty value is now the field's default.
- Deployments: the preview and the test of a deployment to a target that holds one certificate at a time used the RSA one of a dual certificate whatever "Which certificate (when it is dual)" said; they now use the one the deployment chose, as the deployment itself does.
- Settings: the help of "Test the servers after each deployment" said a failed test only makes the deployment a warning; it says now that it fails the deployment on its target, as it does since 1.0.77.
- Targets: a target's window listed a choice of its settings by the value kept ("SSH: sign in with: password", English in the Czech page too); it shows the choice's words, translated.
- Targets: FortiGate's "Management VDOM" took a line break or ".." on save although the field refuses them - only a deployment's options were checked against a field's pattern; a module setting with a pattern is now checked when it is given or changed.
- FortiGate: Czech for the messages of "Management VDOM" (typed one differs from the FortiGate's, or is not a VDOM there), of the version checks and of the CLI's trial with the key format; the step of "When it is not there" names the field as the form does.

## 1.0.136 - 2026-11-20

- **FortiGate, replace in place: a name the FortiGate does not have is created under that name.** A name typed by hand (or chosen earlier and since deleted) stopped every deployment with "there is no local certificate … on the FortiGate". The new option *When it is not there* (replace mode) creates it by default - the certificate imported under exactly that name with its intermediates - and every deployment after it replaces it in place; *stop* keeps the old behaviour.
- **FortiGate, replace in place: the key format is chosen, or tried in turn.** A FortiGate-40F on FortiOS 7.4.13 refused the replacement with "Input is not a valid/matched certificate" although the key belonged to the certificate. The new option *Key format* (advanced) is *automatic* by default: the key goes as PKCS#8 encrypted with a one-time password first, and when FortiOS says the key is not right the next format is tried - PKCS#8 encrypted with PBKDF2 2048, traditional (PKCS#1 / SEC1) encrypted, PKCS#8, traditional. Every refusal changes nothing on the FortiGate; the job says which format was taken. Over SSH the same formats are tried, each first ended with `abort`.
- **FortiGate over SSH: "get system status was not answered as FortiOS answers it" on a real FortiGate.** With no terminal FortiOS writes its answer right after the prompt on the same line, an administrator of a profile has the prompt `$`, and a console set to page stops at `--More--`; the answer was not recognized and the SSH test and every SSH deployment failed. The answer is now read through all of it, the pager is gone through, and a certificate read back with `show` survives a page break inside its PEM.
- **FortiGate 7.4 with VDOMs: replace in place of a certificate of a VDOM's range.** FortiOS 7.4.13 refuses every PUT of another certificate into a local certificate of a VDOM's range ("Input is not a valid/matched certificate", whatever the key - measured on a FortiGate 40F). acme now puts it in through the global range and back (`range global`, then `range vdom`) with the same token; the name and every binding stay. The range not set back is said as a warning (the certificate works, of the global range).
- **FortiGate, replace in place: the pair is checked before anything is sent, the result after.** FortiOS 7.4.13 takes a key that is not the certificate's (or a wrong password) on a certificate of the global range without a word. acme checks that the key opens with its password and is the certificate's before it sends anything, reads the fingerprints with `scope=vdom` whenever there is a VDOM (`scope=global` left the VDOM's certificates - and a copy among them - out), and after the write checks the fingerprint and the key size; a 200 with the old certificate still there stops the deployment, not tried again by itself. *Key format* automatic now starts with PKCS#8 encrypted with PBKDF2 2048 (what every library reads).
- **FortiGate 7.4 with VDOMs: no switch through the global range outside the management VDOM.** Measured on a FortiGate 40F (7.4.13): in a VDOM other than the management one, switching a certificate of that VDOM's range to global empties it, and its range cannot be set back - the certificate is broken. acme takes that way only in the management VDOM (read from `system global`, which the `vpngrp` token reads); elsewhere it stops before writing anything, or replaces the certificate in the FortiOS CLI when the target has an SSH sign-in. A certificate of the global range is always written in the management VDOM; an emptied entry after any write is said as broken (not tried again); a copy of the global range is deleted in every VDOM; a created name is read back (FortiOS cuts names over 35 characters without a word).
- **FortiGate with VDOMs, from the second round on a real 40F (7.4.13):** a token of `vpngrp` alone reads `system global` with its defaults, so the VDOMs looked off and the management VDOM was a guess - the CLI way then sent its lines outside `config vdom` ("Unknown action 3") and every SSH replacement in another VDOM failed. The VDOMs are now taken from `cmdb system vdom` (which `vpngrp` reads), `system global` is trusted only with a hostname in it, and the management VDOM is never guessed: the target's new advanced field *Management VDOM* gives it when the token cannot read it. An administrator of a profile without the "Virtual domain configuration" line is asked in the CLI itself. On FortiOS before 7.6 a certificate of a VDOM's range gets no trial PUT any more (a refused one could still change the key kept): straight through the global range in the management VDOM, straight to the CLI elsewhere. In the CLI the key goes plain first (an existing certificate refuses `set password`). A copy of the global range is now deleted in every VDOM. The guides give the least SSH profile (`vpngrp` read-write, `netgrp read`, `cli-get`, `cli-config`).
- **FortiGate with VDOMs: a replacement that stops writes nothing.** When a certificate of a VDOM's range cannot be replaced over the REST API (another VDOM than the management one, or the management VDOM not known) the decision is now taken before anything else: the intermediate CA certificates were imported first and stayed on the FortiGate after the "nothing was changed" stop (third round on the 40F).

## 1.0.135 - 2026-11-19

- **The addresses a node tells the other node's database agent are under the guard against writes (security).** With `db_guard` on, a `dbagent:addr:NODE` row written into the database past acme is no longer acted on: acme-db-agent let its address into the database (`pg_hba.conf`, MariaDB's account) and through the server's firewall as root, so anybody able to write the database could have had another address let in. The rows already there are signed once as they are when every node of the cluster runs 1.0.135 (until then they are taken as before), and again after going back to an older version and up again. With `db_guard` off nothing changes.

## 1.0.134 - 2026-11-19

- What happens (FortiGate): a dry run of "Replace an existing certificate in place" for a certificate whose name starts with acme- (an earlier import of the default mode, the case of the 1.0.128 report) said "there is no local certificate" while the real run replaces it; the canned FortiGate now answers the certificate read for replacing whatever its name, the default mode's new name is still not there.
- FortiGate, replace in place: a copy of the new certificate under another deployment's acme name that only started like this one's (a longer label) was taken for this deployment's own and deleted; only names this deployment made (its label, a date and a serial) are now.
- Load balancer (PROXY protocol): a `listen 127.0.0.1:443` / `[::1]:443` line of the admin's own in acme.conf was given `proxy_protocol` too, so the node's own checks (the VIP address's health check, install.sh) failed on both nodes; such a line is now left without it (and cleaned where an earlier version gave it), and the VIP address's server made from that block keeps one listen of the address instead of two that nginx refused.
- Load balancer guide: the red line "The administration pages are published through the balancer: without the PROXY protocol..." was worded differently from its Czech pattern and stayed in English; it now matches and is translated.
- Load balancer guide (security): with TLS passed through, the PROXY protocol on 443 was taken as "the client's address" even when the balancer typed in is not among the balancers named - nginx then judges the balancer's own address, and an administration published to everybody was shown green; it is now red (or the "without the PROXY protocol" warning) until the balancer is named.
- Load balancer guide: with TLS ended on the balancer while 443 takes only the PROXY protocol, it said "the nodes already take the client's own address from X-Forwarded-For" although nginx refuses every request the balancer sends; it now says so in red, with the command that sets the header back. A balancer inside a network named in web_proxy_from now counts as named (it was told to replace the whole list with itself).
- Load balancer guide (security): the HAProxy, F5 and NetScaler "enrolment pages only" blocks match the path as sent, so /assets/../admin/ (or %2e%2e) passed the filter and reached /admin/ on the nodes; they now answer 404 to a path with "/." or "%" in it. The HAProxy and nginx blocks no longer send /pki/ on port 80 to HTTPS (CRL fetchers seldom follow that redirect - the nodes serve it plainly for that reason); docs/load-balancers.md says so.
- Teams from directory groups: after a preview, changing the filter, the role, where they go or what they are and pressing "Make the teams" made teams that were never shown (a preview of CN=PKI-Web, then CN=PKI-* typed, made every PKI- team); any change now asks for the preview again, and what was previewed is what is made.
- Request profiles: the search did not find a domain written as its card and the table show it for a profile with wildcards (*.example.com); it does now, and the plain domain as before.
- Teams: a scoped certificate administrator making a certificate without saying its source or validation got the default source and the source's default validation unchecked - a team's `issuers`, `validations` and `pairs` were bypassed by not sending them; the source and validation the certificate will really get are now checked (security).
- Teams: a team's test going through a connector was checked in the order a device's run looks connectors up, not a test's - a device of the team named as acme's own connector of the tests passed, and the test then ran through acme's own connector; it is now checked as the test's run finds it (a connector of the tests first) (security).
- Portal: the free form offered a team every source even where its limits refused them all (the free form off for it, or the portal's validation not among its `validations`) - each was refused only once asked; it now offers none there.
- Portal: the limits designer said "self → " with nothing after it for a source paired above with no validation; it now says "no validation".
- CLI: `acme --check-edit` with nothing to change did not name `--owner` among what it takes.
- Certificates: switching "Renews" in a certificate's window left the list saying "auto"/"by hand" as before and Details saying the old way it renews (the refresh asked for window.CT, which nothing sets); the list and Details now follow at once.
- Certificates: the list filtered "has expired" missed a certificate whose renewal failed past its end (it stays "renewal failed"), so the Overview's tile Expired said 1 and opened an empty list; the filter now holds everything run out that is not revoked or switched off, as the tile counts.
- Certificates: the state filter had no "added, not issued" nor "revocation failed", though the list shows both; they are offered now.
- Deployments: a certificate administrator could not save a deployment of files (local, SSH, Windows) as it was - the page sends the interpreter's default "bash" of one saved without it, refused as "only a full administrator may change the commands"; an option never set now counts as the module's default.
- Deployments: a deployment saved with its options unchanged (or only switched on or off in its window) turned from "deployed" to "options changed"; it now says so only when the options really changed.
- Jobs: the job of a certificate deleted since (Delete with revoke) still offered "The certificate", which opened "there is no certificate N"; it is offered only while the certificate is there.
- Owners and teams: a team or tag renamed or deleted did not redraw the certificates list (it asked for window.CT, which nothing sets); it does now.
- FortiManager: an intermediate CA the FortiManager refused for another reason than "there already" (-2) - no permission, invalid data - was said as an info step "not added (there already?)" and the deployment read as clean; -2 is now said as there already, any other refusal as a warning.
- Cisco ISE: an intermediate ISE refused to import as trusted for another reason than "already exists" was said as an info step "(there already?)"; it is now a warning (the system certificate's import then fails on a chain ISE does not trust).
- Aruba ClearPass: a CA of the chain ClearPass refused for another reason than "already exists" was said as an info step "(there already?)"; it is now a warning, one there already is said as such.
- MikroTik (REST API): an old certificate RouterOS would not remove (one an IPsec identity or a hotspot still uses) failed the whole deployment after the services were bound, and as it was never remembered every renewal failed the same way; it is now a warning and the old certificate stays, as over SSH.
- Certificates: a deployment failed by a test after it said "acme tries again in -" in its notice (and no wait in its job step); it now says the deployment's own wait.
- Certificates: the renewer's "Deploying X failed" notice said "acme tries again in -" (the certificate's next try, none after the renewal); it now says when its failed deployments are tried again.
- Certificates: Deploy now for the whole certificate while a dry run of it was at work was given the dry run's job and deployed nothing; it now says the certificate is busy with that job (409), as Renew now does.
- Deployments: an error a module marks as lasting (FortiGate's -324 on a FortiGate-VM EVAL with an RSA chain) was tried again by itself every few minutes to hours although it fails the same each time (1.0.133 said it was not); it is not tried again by itself now - a new certificate or Deploy now tries it - and the step and the notice say so.
- Passkeys (your account): the password asked again before a passkey is added, for an account of the directory, was not counted when wrong - from a session left open the owner's directory password could be guessed without limit - and was answered with 401, which the page took for being signed out; a wrong one is now counted as every password is (the pause after five) and said as "the password is not right". (security)
- Directory sign-in (admin_group_*, portal groups): a group given by its sAMAccountName (pre-Windows 2000 name) whose cn is different matched nobody, so its members got no role (or a lower one); it is now matched by the DN the directory says it is, as a group given by its cn is.
- Sign-in protection: a sign-in refused because it was this server's trouble - the directory away (password, Windows, certificate), no keytab, a CRL or OCSP answer not to be had - was counted as a wrong password and by "Block a place that keeps guessing", so an office signing in rightly during a directory outage was locked out and its address blocked for half an hour; such refusals are no longer counted, as the setting says.
- Portal sign-in with Windows or a certificate, and the card's and Windows' Try it: a refusal for this server's own trouble (the directory away, no keytab, no CRL or OCSP answer) was counted as a wrong try and could lock the address out; it is not counted now, as on the administration's sign-in.
- Target agents: a server enrolled with a team's enrollment code whose target was moved to another team since, enrolling again with the same code, got a second target of the first team for the same server - it is now refused (nothing made, nothing confirmed in the other team's target; the new owner's code still finds its target).
- Target agents: a target whose join code ran out unused showed "joining" for ever - it shows "not joined" again.
- Target agents: confirming a passive agent on its card or in the waiting list said "the agent is confirmed" even when acme could not hand it its certificate - it now says what went wrong.
- Alerts: a report (or a report of the tests) that was refused held every alert back for 15 minutes, and a mail to the alerts' addresses that went (a test alert) did not end that wait; only a failed alert or test alert holds the alerts now, and one that went ends the wait.
- Teams: the mail asking a team's approvers in Czech said who is wanted in English ("čeká na schválení: an approver of the team Web"); it says it in Czech now (the events stay in English).
- Settings → Message texts: the titles of the certificates' notifications were half English on the Czech page ("Certificates: Certifikát brzy vyprší"); they have their Czech words now.
- Own CAs: an intermediate revoked by the authority above it (or one under a revoked or expired authority) went on signing certificates every CRL-checking client refused; it now refuses to sign or to make authorities under it until it is renewed (or its hold released), its CRL still made.
- Own CAs: after a root was renewed for fewer days than its intermediates, what they signed (and new intermediates under them) got dates past the end of the root; the validity is now cut at the earliest end of every acme authority up the chain.
- Own authorities: creating one took any CRL validity (0, or thousands of days); 1 to 365 days now, as editing it already said.
- Certificate requests (security): a request whose signature was not made by its own key was taken as signed - OpenSSL 3's req -verify answers success for a bad signature too, saying only "verify failure"; its words are read now. This is the proof that whoever sends a CSR holds its key (CSRs on the portal and in request profiles, device-made keys, own authorities' sub-CA requests), and the target agents' enrollment, which now checks it too: a request of someone else's key put in a server's place is refused.
- Sources, Validation, Targets: picking another version of a module in its form (FortiGate 6.0 instead of 7.0) emptied a secret already typed (the API token) and dropped the tags chosen; both now stay.
- "Find the settings from the account": a secret typed in the form came up empty in the popup and "Find out" asked for it again; it is now carried over, and the version of the module the form shows is sent too (the saved or default version was asked before).
- Sources, Validation, Targets: a target with acme-agent named by a source "Microsoft CA through acme-agent", a passive agent other targets go through, and a validation named by a dns-persist-01 validation (fallback, writer) could be deleted at once, breaking what named them; the delete dialog now lists them as "change it there first" and the delete is refused.
- Sources, Validation, Targets: renaming such a target or validation left the old name in the source or validation that named it; those settings now follow the new name.
- Jobs: a running job's window stopped updating once its certificate had been opened over it ("The certificate") and closed again - it said "running, 13 s so far" with Stop it for good, long after the job ended. It now goes on updating and shows how the job ended.
- Jobs: the tab's count of running jobs was taken from the page shown, so a list filtered ("went well", one certificate) or a page further back took the "1" off the tab while a job ran. It now counts every running job.
- Jobs: with the live updates paused in the header, the Jobs list was still asked and drawn again every 2.5 s while a job ran. It now waits until live updates are switched back on.
- Overview: "What needs a look" and "Running out soonest" stopped at 520 px with a scrollbar of their own inside the page's (a dozen alerts did it at a phone's width). They are now part of the page; the list still shows at most 30 alerts, the rest behind "+ N more".
- Database: a validation with an old unsafe name (a letter outside ASCII or a quote) renamed at start (names made safe) stayed under its old name in the certificates' per-name validations and their own settings of it on PostgreSQL and MariaDB - both took the backslash of the JSON (é, \") for LIKE's escape and found nothing, and those certificates lost their validation; the pattern is now escaped the same way on every engine (like_escaped, ESCAPE '!').
- Validations: "used by" counted certificates with LIKE alone - `_` matched any letter and SQLite ignored case, so dns_a was "used by" the certificate of dns-a, and an unused dns-persist-01 validation could not be deleted with its records ("in use (1)"); it now counts only the certificates that really name it.
- Own authorities, publishing: "Check it" said a published CRL's signature was the authority's when it was not - openssl crl -CAfile ends with 0 for a bad signature too (OpenSSL 3 says only "verify failure"); its words now decide, and a forged CRL is said "its signature does not verify". (security)
- Certificate viewer: a CRL whose signature is bad was shown as signed by its authority (the same openssl crl exit code); it now shows the signature as not good. (security)
- Agent (Windows), AD CS: the check that a CSR is signed by its own key took a forged CSR (openssl req -verify ends with 0 for a bad signature); its words now decide, and a forged CSR is refused before it reaches the CA. (security)
- Backups: a backup locked before 1.0.139 could not be opened about once in 256 - openssl enc -d takes a wrong password now and then (its padding happens to read right), so the old password was never tried and the backup was called "not a backup of acme"; what comes out must be a .tar.gz, else the next password is tried and a wrong one is said so.
- Portal, asking from a request profile: in a team's workspace, a profile that gives the certificate to the person asking was marked "approved first" (and its button said "Ask for it") whenever the team's rule made every request wait - and it was issued at once; the team's rule is now said only of a profile whose certificate becomes the team's.
- Portal, Requests (team workspace): declining a request said "The person who asked is told why, by mail" and "declined - the person who asked is told" when no mail goes (no address of theirs, or mail switched off); it now says so as the certificate's own Decline does.
- Portal, a key download approved by the team: the approver was told "approved - portal:jan may take the key now"; now the person by name.
- Portal, team overview: drawn right after the sign-in before what waits was known, it said "Waiting for you 0" and "All is well - nothing waits for you" beside Requests 1, and an approved key was not offered to take, until the minute's refresh; it is drawn again once that is known.
- Portal, Czech: the team's "Also approved first: revoking" read "odvolává se" (the state's word) - now "odvolání certifikátu"; the CSR check "names the profile does not give (the source takes the CSR as it is)" had no Czech.
- ACME: a finalize the CA had taken but whose answer was lost (a 5xx of a proxy in front of it) was sent again, the CA said "orderNotReady" for the order already processing and the job failed - the next try ordered another certificate (rate limits, a paid order). Now the order is asked and, when it is processing or valid, its certificate is waited for and taken.
- HTTP-01 on this server: in a cluster the token reaches the other node's database by replication, but the CA was asked at once and could be told 404 by the other node (the VIP held there, a balancer). Now each node is asked by its address until it answers the token (20 s at most; a node that cannot be asked from here is not waited for).
- Command line: `acme --check-show NAME` did not say the team whose test it is (`--check-add/--check-edit --owner TEAM`), only `--json` did; it says `owner` now, as `--target-show`.
- Console: Certificates → Tests could neither show nor set a test's team; the list has an owner column, a new test asks whose it is and "Its owner" changes it, as Targets do. Deleting a team that owned only tests did not ask where they go (they became acme's own); its tests are counted and asked for with its certificates and devices.
- Console: the form of a deployment made with no options of its own (`acme --deploy-add CERT TARGET`), opened and left as it was, saved every default (a FortiGate's mode=new, replace_via=api, admin=0, sslvpn=0) - its options changed and it was deployed again; only what was changed is saved now.
- Command line: `acme --teams-from-groups` could not take groups picked from the directory (the API's `groups`, 1.0.128); `--group DN|NAME` (again for more) adds them, FILTER `-` takes only those, and the ones the directory does not know are said.
- DigiCert: the orders acme made since 1.0.80 (kept per key type as digicert-order:ID:FAMILY) were not recognised as acme's in Certificates → Import from a source; the certificate id is now read from both the old and the new key.
- SCEP: a server that announces only "SCEPStandard" (which implies AES, POST and SHA-256) got its request encrypted with 3DES; "As the CA says" now picks AES-256 for it, as the documentation already said.
- DNS providers: a "rate limit" refusal with HTTP 403 was reported as wrong credentials, and a 400/403 slow-down was said to be tried again while marked as permanent; it is now said as a slow-down and marked to be tried again.
- Hetzner DNS: with a zone set, a name outside it (the _acme-challenge CNAME followed into another zone of the project) was looked for in the zone set and refused; the zone set is now used only for names in it, others are found by their own zone.
- Shared DNS code: the registrable domain of a name under a common second-level suffix not listed (com.vn, co.id, co.th, com.ph, co.ae and others) was taken one label too short (com.vn), e.g. for DigiCert's base domain and the zone guessed for a name; more suffixes are known now.
- Windows agent: the AD CS check of a CSR (1.0.134) looked for "verify OK" on openssl's error output only - OpenSSL 3.2 and later print it on the standard output, and every good request was refused as "its signature is not good"; openssl's own line is read on either output now.
- Own CA and CSR checks: a SHA-1 request where the crypto policy refuses SHA-1 (RHEL 9/10 with OpenSSL 3.0 - 3.2, which answer 0 and say only "verify failure") was taken for a forged one since 1.0.134 ("not signed by its own key"); it is verified again with the configuration that lets SHA-1 through, as before, and said to be refused by the policy when even that cannot verify SHA-1.
- Czech: the deployment steps of ClearPass, Cisco ISE and FortiManager about a CA already there or not added, and the own CA's refusals of a revoked or run-out authority above and of crl_days, were shown in English.

## 1.0.133 - 2026-11-18

- FortiGate, replace in place: error -324 on importing the intermediate CA is now said plainly (measured on a FortiGate-VM with an EVAL licence: it takes no RSA authority over 512 bits) - with the intermediate's key and name, nothing replaced, and not tried again by itself (it would fail the same). 1.0.132 replaced the certificate without its chain in that case; that is undone. A FortiGate-VM EVAL (serial FGVMEV...) and an RSA intermediate over 512 bits not on it are refused before anything is written; an EC (ECDSA) certificate goes through. The guides say to use EC on an EVAL FortiGate.

## 1.0.132 - 2026-11-18

- FortiGate, replace in place over the REST API: an intermediate CA certificate FortiOS refused to import (error -324 on a FortiGate-VM with an EVAL licence, an RSA authority) stopped the deployment with nothing replaced; the VDOM scope is tried as well, then the certificate is replaced all the same with a warning (as the default mode does) - the guides say so, and how to import the authority by hand.

## 1.0.131 - 2026-11-18

- FortiGate setup guides (every version, EN and CS): "Replace an existing certificate in place" now gives the least rights for replacing over the REST API as commands - an admin profile `acme-replace` with nothing but VPN (`vpngrp`) read-write, the REST API admin with it and its token - and what to add when FortiOS answers 403.

## 1.0.130 - 2026-11-18

- **FortiGate: replace in place over the REST API again - fixed, and the default.** Measured on FortiOS 7.6.8 build 3744: the `PUT cmdb vpn.certificate/local/<name>` works; what 1.0.128 failed at (`-651`) was a **duplicate** - the same certificate already on the box under another name (an `acme-...` import of the default mode), not the PEM. A new deployment option *How to replace* (`replace_via`): **REST API** (default; the token only, its profile needing VPN `vpngrp` read-write) or **SSH** (the FortiOS CLI of 1.0.129, unchanged, with the target's optional SSH sign-in). The API way: read the certificate (`with_meta`), read the SHA-256 of every certificate (`monitor/system/available-certificates`), import the intermediates not there as CA certificates **before** the PUT (FortiOS keeps the leaf only and serves the chain from its CA store), delete acme's own copy of the new certificate, PUT the leaf and the key (PKCS#8 encrypted with a one-time password), read it back (the fingerprint must be the new one; a changed count of uses is a warning). A refused PUT changes nothing and says why: duplicated / invalid private key or password / a key of another certificate / its error lines.
- FortiGate replace in place, duplicates (both ways): found by fingerprint in `available-certificates` (the cmdb listing has `certificate` empty on 7.6, so 1.0.129 never found the copy there); only this deployment's own `acme-<label>-...` copies are deleted, a copy acme did not make (or another deployment's) stops it; FortiOS's `-23` on the DELETE ("currently being used" - cmdb `q_ref` does not count the admin GUI) stops it with the target untouched; the replaced certificate is never deleted and replace mode never imports under a new name.
- FortiGate *Find on the device*: CN, expiry, issuer and the start of the SHA-256 again on FortiOS 7.6 (from `available-certificates`, else the listing's PEM, else each read), the uses counting the admin GUI; the ★ suggestion, factory ones left out and typing by hand as before; the VDOM offer of *Find the settings* unchanged.
- FortiGate CA import: `-328` means "there already" (now measured) - said once, the CA list no longer read to check it; another refusal is said as "the CA certificate is not imported: ...".
- FortiGate: the SSH sign-in fields say they are used only when *How to replace* is SSH; FortiOS answers kept in the job drop the short base64 stubs (`MIIBjTCCA`) too. *What happens* shows the API way step by step (reads, CA imports, copies, PUT, check). Docs and setup guides (EN/CS, every module version): the API way, `vpngrp` read-write, the duplicate rule, leaf-only storage, renaming impossible in FortiOS.

## 1.0.129 - 2026-11-18

- FortiGate, "Replace an existing certificate in place" (1.0.128) failed on FortiOS 7.4.13: the REST
- FortiGate replace in place: duplicates. FortiOS refuses a local certificate identical to another
- FortiGate: an error answer of FortiOS is kept as its error lines only - its cli_error had said
- FortiGate guides and docs: replace in place needs an SSH admin with vpngrp read-write; why the

## 1.0.128 - 2026-11-18

- **FortiGate: replace an existing certificate in place.** A deployment's new option *Certificate on the FortiGate → Replace an existing certificate in place* with *The certificate on the FortiGate* updates a local certificate the FortiGate already has (`PUT cmdb/vpn.certificate/local/<name>`: `private-key` encrypted with a one-time `password`, plain PEM when refused, and `certificate`) instead of importing it under a new dated name - its name stays, so every policy, VIP, ZTNA rule or user-auth setting bound to it keeps it, and nothing is re-pointed but what the deployment lists. In every module version (FortiOS 6.0 - 8.0). Off by default: existing deployments are unchanged.
- **FortiGate: Find on the device.** The deployment dialog lists the FortiGate's local certificates (name, CN, expiry, issuer, global/vdom, count of uses), suggests (★) the one with the certificate's names and leaves Fortinet factory ones out; *Type it yourself…* always works, and a listing that fails says why (e.g. the token's `vpngrp` read). A list field (`catalog`) may now name its button (`load_label`) and suggest a pick; a deployment's form sends the certificate's names for that.
- **FortiGate: replace in place is safe.** A name not on the box (or a factory one) fails before anything changes; a refused update fails with FortiOS's answer and says the old certificate is untouched (read back; never deleted); cleanup of older `acme-...` certificates never takes the replaced one. *What happens* says which certificate is replaced and that its uses stay.
- **FortiGate: a CA certificate there already is no longer an error-looking line per certificate.** FortiOS answers the import of a CA it holds with 500 / error `-328`; acme checks the CA list once and says "the intermediate CA certificate is on the FortiGate already" once.
- A deployment's list field (`catalog`) no longer loses the target's own setting of the same name when the deployment leaves it empty (a FortiGate's VDOM).
- (security) Behind a load balancer with TLS passed through, acme now writes the PROXY protocol into nginx itself: `web_proxy_header=proxy_protocol` (with `web_proxy=1` and `web_proxy_from`) gives the 443 listen lines of this node's server and the VIP address's (IPv4 and IPv6) `proxy_protocol`, with `set_real_ip_from` the balancers and `real_ip_header proxy_protocol` - checked with `nginx -t`, put back when refused, per node in a cluster, taken out again (only acme's own lines) when switched off. Before, the guide told people to edit acme.conf by hand; without it every client was the balancer's address, and a balancer inside the administration's allow list (the default private networks) published the administration to everybody. Port 80 (HTTP-01, /pki/) is never given it. 127.0.0.1 and ::1 keep a 443 line without it for the node's own checks; the look at the other node's /healthz while the nodes are apart sends `PROXY UNKNOWN` first.
- (security) The certificate sign-in's own port (`certlogin_port`) behind an L4 balancer: its servers in acme_certlogin.conf take the client's address from the PROXY protocol - with the header `proxy_protocol`, or alone with the new `certlogin_proxy_protocol=1` (443 ended on the balancer, the port passed through). Without it every card refused counted against the balancer's one address (everybody's sign-in pause) and who may reach the port was decided by the balancer's address. Off by default: the port's servers as until now.
- (security) Settings -> High availability -> Load balancer says the truth about the administration: who may reach it, read from nginx; in red when TLS is passed through and the administration pages are for everybody, the balancer's own address may reach them without the PROXY protocol, or the nodes believe X-Forwarded-For from a balancer that cannot write it - with a link to Firewall and access.
- The balancer guide: "Ended on the balancer" blocks publish only the enrolment pages (/, /index.php, /favicon.ico, /assets/, /pki/) and answer 404 to /admin/, /healthz and /metrics (HAProxy acl, nginx locations, Apache LocationMatch, F5 iRule, NetScaler responder policy); "Passed through" shows L4 with the PROXY protocol for nginx (stream), F5 and NetScaler too, and the nodes' side as `acme --set web_proxy_header=proxy_protocol` instead of a hand edit; a part for the certificate sign-in's port per kind (HAProxy mode tcp + send-proxy-v2, nginx stream, F5 Standard VS without clientssl + PROXY iRule or no SNAT, NetScaler TCP with a PROXY TCP profile) when it is on. In Czech too.
- docs/load-balancers.md: "Is the administration published through the balancer?" and "The certificate sign-in port"; docs/certificate-sign-in.md and docs/high-availability.md say what acme now writes; the settings table lists web_proxy, web_proxy_from, web_proxy_header, web_proxy_recursive and certlogin_proxy_protocol. No pages-only node port (otp's web_proxy_port): acme's allow lists are per page and see the client once the PROXY protocol is written.
- Teams: a new limit `wildcards` (default true): false - no name of the team's certificates starts with "*." - refused (403, an event naming the team) on the portal's free form, from a request profile, in a CSR, in a new CSR with other names, and for a scoped certificate administrator making or changing a certificate; off on any team above - off below. The approval envelope (`approval.outside`) takes `wildcards: false` too: a wildcard then waits for an approval. A switch in the limit editor (Settings → Owners and teams → Limits, "Wildcard names") and in the portal's limit designer.
- Teams: a new limit `pairs` - the sources with their validations, `{"acme-le": ["dns-web"]}`: a certificate from a paired source is proved only by its validations (its own and each name's); a source not paired only where the same team's `issuers` lists it; in force is the pair every team above allows too. Followed when a source or a validation is renamed. Edited in the admin limit editor and the portal designer (a source from the catalog, then its validations); the portal's free form offers a team only the sources it may use.
- Teams: the team's tests - tests (Certificates → Tests) have an `owner` (a team; empty: acme's own as before, an older database given the column empty); new capabilities `test.view` (the Viewer and every role built on it) and `test.manage` (the Device manager, the Team owner), a new limit `test_kinds`; the portal's team workspace has *Tests*: list, add, change, delete and run the team's tests, of the allowed modules, through the team's own connectors, never a secret shown back (`/api/portal/tests`, `test`, `test_kinds`, `test_save`, `test_delete`, `test_run`). `acme --check-add/--check-edit --owner TEAM`; renaming or deleting a team takes its tests along.
- Teams: `acme --team-edit --policy` and `--team-show` know the new keys (`wildcards`, `pairs`, `test_kinds`); docs/teams.md "Typical setup" shows a team limited to its devices and tests of some kinds, one domain, one source with one validation and no wildcards.
- Pages: a "Pick from the directory" search button beside every box that holds a directory name - the administrators' and the portal's groups in Settings, "Try a sign-in" and "Look a name up" of a directory, the certificate look-up for a person, the teams' access check, Teams from directory groups and the portal's member dialog. It searches people and/or groups as one types, shows each one's name, description or DN and whether the account is switched off, and puts what is picked into the box in the form the box already takes (a DN as one more line of the list, a login, group:NAME). Typing by hand, wildcards too, works as before.
- Pages: the picker is shown only to those who may search the directory (a certificate administrator or a full one; on the portal, those who manage a team's members), and says so in the page's language when no directory is set up or the search fails.
- Teams: Teams from directory groups takes groups picked from the directory beside the name filter (`groups` in POST /api/teams/from_groups, 200 at most); with the filter left empty only those are made, and names the directory does not know come back in `missing`. The filter alone works as before.
- Settings: Request profiles moved from Messages and the portal to Certificates, under Owners and teams.
- Settings → Request profiles redone in the look of Owners and teams: a bar with the views Cards and Table, a search over names, descriptions, sources, domains and teams, and cards with the source and validation, the domains, wildcards, key types, approval, who may use it and the teams whose limits name the profile; an empty state with "Add the first profile"; Edit, Duplicate (a new profile filled in with the copy) and Delete on each.
- The request profile's editor in sections with icons (General, Where it comes from, Names, The key, The subject, Use and renewal, Approval and owner, Who may use it), a side navigation of them, domains and teams as chips (typed domains still work: Enter, a comma or a space adds one, what is left typed is saved too), segmented choices for the subject's fields, Offered first, When asked for and Whose it is, and "On the portal" - what a person will see there, kept up to date while editing. One scrolling body; the same API calls, fields, defaults and checks as before.
- Settings → Owners and teams → Roles: the matrix has no scrollbar of its own any more. It is part of the pane and the pane's scrollbar is the only one. Its headings stick to the top of the pane. When it is wider than the pane it scrolls sideways in its box, and the headings stay in view as the pane scrolls.
- Pages: a table no longer stops at 66 % of the window with a scrollbar inside a page that also scrolls. It is part of the page. Only a list alone on its tab, held to the window, scrolls its rows inside.
- Dialogs: the lists inside a dialog no longer have a scrollbar of their own beside the dialog's. This covers the portal's certificate picker for a deployment, the teams' pickers and directory search results, the targets offered for a deployment, the tests to run, certificates found at a CA account, the deploy templates, agents confirmed at once, the cluster's history and errors, RESTORE.md, and a directory entry's attributes. The dialog scrolls as one. In the deploy-template dialog, what was chosen stays in view beside the list.
- Tests: test/test_no_double_scroll.py and test/no_double_scroll_page.js check every tab, Settings pane, the teams' views, the main dialogs and the portal at 2000×1100, 1400, 768 and 390 px with long lists. They report any scrolling box inside another scrolling area. The exceptions are side rails, popovers and log/code viewers.

## 1.0.127 - 2026-11-18

- Root helper (security): a PostgreSQL error that shows the statement (a database account made for acme) could show the account's password in the message; it is hidden now.
- Backups: a backup sent did not record how many certificates it held, so each node's card on Settings → Backups showed an empty "Certificates"; it is recorded now and shown.
- Backups: Put one back… on a file sent from the computer always showed "Certificates –" (the page read a field no manifest has); it shows the backup's count of certificates now.
- Backups (security): a copy opened on the command line with its key (secrets.key in clear beside it), the files the command line took in to read, and backup or database files sent from the pages and never put back stayed in the state folder for good when nothing came after them; they are taken away at the next start (the uploads after an hour, the others after six).
- DNS-01: one SOA question the resolvers did not answer while acme waited for the TXT record to be seen (a validation whose provider does not say the zone, e.g. Cloudflare, acme-dns) failed the whole order; now it counts as "not seen yet" and the resolvers decide.
- DNS-01, "A script of your own": a CA's DCV TXT record (DigiCert, Sectigo...) failed with "no attribute '_name'", or ran the script with the name of the order before; now the script gets the name and record being placed.
- acme's own DNS server: a zone written with national letters (acme.příklad.cz) was answered REFUSED for every question and the validation wrote its records under the Unicode name; zones, name servers and records are now kept in their IDNA (xn--) form, as DNS asks for them.
- Portal, sign-in through the load balancer: a balancer header that was not taken at all (not from a balancer named, or without its key - e.g. a key made anew and the balancer not yet told) signed out whoever was signed in on that browser, so a person who signed in with their password was signed straight out on the next page and told to "sign in with your password". Such a refusal now says it is about the header (`untrusted`) and the page keeps the sign-in; a refusal of the person (the directory) still ends it.
- Portal, one-time code at sign-in: the code box always said "000 000" whatever the code's length (code_digits 4-10), and nine or ten digits did not fit the box (the last ones scrolled away). It now shows as many digits as the code has, and long codes fit.
- Portal, sign-in: "nobody can sign in here yet: no directory is set up for these pages..." (a new install without a directory) came out half Czech; it has its translation now.
- Settings: a value not of its setting's kind (a number box emptied, "abc" for a number, "maybe" for a switch) was refused without the setting's name ("a number is needed, and nothing was given"), so the save bar could not mark the box or say which change it was; the refusal now starts with the setting's name and the box is marked.
- Settings → High availability: at phone width the copy buttons of the load balancer's guides (and "As it comes" of the message texts) were squeezed by their titles and their words ran out of them; they keep their size now.
- Settings → High availability: in "Each node's own settings" at 390 px "The cluster's" ran over the first node's name and a long node name or Czech word made the page wider than the phone; the headings and setting names wrap in their columns now.
- Settings → High availability: "Heard from" of the nodes (and in the cluster's card) was worked out by the browser's clock - a node answering said "10 min ago" on a computer ten minutes ahead; it is the age the daemon measured now, as the settings' pill shows it.
- Settings → High availability: the two notes of "Each node's own settings" were shown in English on a Czech page (their text had changed); translated again.
- Target agent (Linux): a test, reload or script that ended at once but left a process in the background holding its output (`app &`) was reported as "did not end in N s" only after the whole timeout, and the deployment that had worked was undone; the agent now waits for the command itself to end and reads its output for a moment more.
- Target agent: a self-update whose files could not all be written (a full disk, say) left the agent half new and half old, with a half-written temporary file beside it; the update now installs every file or none and puts back the old ones.
- Teams: declining a team's action said the person who asked is told (by mail), but no mail is sent for an action; it now says they see why in the team's actions.
- Prometheus: /metrics refused an IPv4 client seen through a socket of both kinds (::ffff:10.1.2.3) although its network was among those set (metrics_from); it is taken as the IPv4 address it is, as the SNMP agent and the sign-ins take it.
- SNMP: the node's own test ("Ask it") asked over IPv4 whatever the agent listened on - with the agent bound to an IPv6 address it failed ("Address family for hostname not supported"); it asks over IPv6 there.
- isemon and syslog (SIEM): the lines held for a TCP/TLS server that was down, and its trouble ("tried again in 15 s") with the alert "the logs do not reach ...", waited for the next event - days on a quiet machine; they are sent, and the trouble cleared, as soon as the wait is over and the server answers.
- Prometheus: a certificate deployed twice to one target (two files, two services) gave two samples of one series of acme_cert_deploy_state and acme_cert_deploy_last_ok_timestamp_seconds, and one of them was lost; those rows carry the deployment's id too.
- Certificate requests: declining one answered "<owner> is told" even when nobody was - the person who asked had no e-mail address, or mail was switched off - and named the owning team instead of the person who asked; it now names the person who asked and says whether a mail tells them, or why not (the portal's toast too).
- Portal: a request waiting for approval said "You are told by mail when they have" (and the approver's note "They are told by mail") to a person with no e-mail address or with mail switched off; the portal is now told whether a mail goes (told_by_mail) and says to look on the portal instead. The Ask for a certificate note and the administration's Decline dialog no longer promise a mail either.
- Portal: after a certificate was opened from the team workspace's overview, Ask for a certificate offered the free form with no domains and no source and none of the request profiles; it now fetches what may be asked for first.
- Command line: `acme --cert-add NAME --owner TEAM` and `acme --cert-edit NAME --owner TEAM` took the option (added in 1.0.126 for targets and enrollment codes) and silently left the owner out ("added" with no owner, or "nothing to change"); they now set the certificate's owner, as `--set owner=TEAM` does (`-` for none).
- Outgoing mail: a certificate administrator kept to some teams could delete or resend every team's queued mail (Delete failed, Delete sent, Send again, or by a mail's id), including sign-in codes, though the list hides those mails from them; they now act on the mail they are shown only. (security)
- Deployments: a certificate administrator kept to some teams could move one of the team's deployments to another team's device by saving it with its id and the new target alone (no certificate in the request) - the team's device limits were checked only when the certificate was named; they are now checked with the deployment's own certificate too. (security)
- Deployments: Test (dry run) of a deployment made acme sign in to another team's device and write a team's certificate and key into a folder there for a certificate administrator kept to some teams; the team's device limits are now checked on the test as on a save. (security)
- Certificates: two jobs proving one shared authorization of a CA put the same DNS-01 TXT record into acme's own DNS server, and the first job to finish removed the other job's record too, while the CA could still be checking it; each job now removes only its own record (a leftover from no current job is still removed as before).
- Certificates: two jobs proving one shared authorization of a CA serve the same HTTP-01 token on port 80, and the first job to finish removed the answer the other job still needed; the answer now stays until the last job using it is done.
- ACME sources: with "Preferred chain" set, the CA's default chain was taken whenever it contained the named root anywhere, even when that root was only cross-signed by an older one (the long chain); a chain whose top is issued by the named CA is now chosen first, as certbot does, and only then a chain that contains it anywhere.
- Aruba AOS-CX (security): a refused sign-in hid only the raw password in its error, not the URL-encoded form the login address carries; both are hidden now.
- Docker Swarm: a file name in the container with a comma or "=" added fields to the secret given to the service; such a name is refused now with a clear message.
- Settings → Accounts → A new account: the note under Role always described "enrolment pages only", though cert admin is chosen at first; it shows only while that role is chosen now.
- This machine (files): a script or command that failed put the previous files back with the new file's mode - a key the service's group read (0640) came back 0600 and the service could not read it; the previous mode is put back with the bytes now.
- Linux / Unix (SSH) and the targets writing files over SSH (HAProxy, strongSwan, Caddy, ESXi, Traefik, Zimbra...): a write that failed half-way (an owner chown refused) left the copy of the old key made only for putting it back (<file>.acme-prev) beside it; it is taken away now. (security)
- Settings → Request profiles: on a phone the table laid every column out at its narrowest word, so a profile's name and description stood one word a line; its first column keeps a readable width there now (other tables and wider screens unchanged).
- High availability: a replicated pair upgraded one node after the other to a version with a new table (1.0.125's custom roles) lost what the node upgraded first wrote there in between - the other node's subscription took the table without its rows, and they were missing there for good (and after a failover); they are copied over now where that table is still empty on the other node.
- Upgrades (security): an nginx file kept from before 1.0.99 never got the sign-in limit for signing in with Windows and with a certificate (api=kerberos-login, api=cert-nonce) - only a new file had it, so either could be asked for at 10 a second; install.sh adds the two lines once, and a second run changes nothing.
- Windows (OpenSSH) target: the IIS binding was looked up by port and host only, and an empty host matched any host - a line for the default binding could put the certificate on another site name's binding; it is found exactly now (the address too when the line says one).
- Portal teams: the team workspace did not start at all (a JavaScript syntax error in the decline dialog's text left the page empty after signing in); it loads again.
- Portal teams: a declined action (a device's deletion, a revocation, a key) never showed the person who asked why it was declined, though the one declining was told they would see it; "Your requests" now shows who declined it and why.
- Portal teams: a waiting action showed acme's English words ("delete the device web1") on the Czech page; a revocation's reason is now shown in the page's language and the words that only repeated the title are left out.
- Portal teams: "Enrol servers" named a code made for a team below "Servers of <the team open>" and did not list it afterwards; the code is named after the team it is for, and the codes of the teams below are listed (and can be revoked) there.
- Root helper: the folders of PostgreSQL's files (pg_hba.conf's, the data folder) were checked and then used again by their path - the postgres account could put a link to another folder (/etc/profile.d) in place of the checked one while root waited on PostgreSQL's answer, and root wrote pg_hba.conf's text there (or read a file of root's from there); now the folder is used through one descriptor and refused when it is not the one that was checked (security).
- Root helper: the list of ports acme labelled for nginx (selinux-ports) was read and written by its path in the acme account's web folder - a link put in place of that folder had root write it in any folder; now through the web folder's one descriptor, as every other file there (security).
- Windows agent: IIS bindings were looked up by site, port and host only (Get-WebBinding takes an empty host as any host and the address was never compared), so a binding on 10.0.0.5:443 or without a host name could get the certificate of *:443 or of another host's binding, and the undo removed by port and host; the agent now finds exactly IP:PORT:HOST and removes only the binding it made.
- Windows agent and acme: the "allow" lines to type in an elevated PowerShell put a name with $ or a backtick in "...", which PowerShell expanded ("Shop $live" became "Shop "); such a word is now put in '...'.
- Windows discovery: a certificate an IIS binding takes from the Web Hosting store, or the Remote Desktop listener's own certificate in the Remote Desktop store, was said "not in the machine store"; it is now read from that store.
- Command line: `acme --certs --owner TEAM` and `--certs --issuer SOURCE` listed every certificate (both options were taken and ignored); they now filter the list as the page's filters do.
- Command line: `acme --import FILE --owner TEAM --note TEXT` imported the certificate without its owner and note; both are now saved, as the page's Import saves them, and with `--into` they are refused (a new version keeps the certificate's own).
- Command line: options that only go with certain others (`--owner`, `--parent`, `--description`, `--caps`, `--strip`, `--below`, `--members`, `--policy`, `--colour`, `--reassign`, `--member-role`, `--team-kind`, `--contact-mail`) were accepted beside any other option and silently ignored (`--selfsigned X --owner T`, `--ca-create X --parent CA`, `--tag-add T --description ..`, `--team-add T --caps ..`); they are now refused before anything is done, naming the options they go with.
- Command line: `--set` beside `--selfsigned`, `--import`, `--check-names`, `--cert-check` or `--dry-run` was let through - the certificate was made or imported, or the job run, and only then "nothing of it was saved" (exit 2); it is now refused before anything is done.
- Console: a member's end typed as a day that does not exist (2026-13-45) passed the form's check and crashed with a traceback; the form now refuses it.
- Docs: four links between the docs led to headings that are not there (acme push's "for an application on this engine", operations' "Certificates and the VIP address" four times, target agents' "Linux / Unix server over SSH"); they lead to the right headings now.
- Docs: the certificate portal's table said the enrolment pages are off by default (`portal` 0) and that the portal's certificate sign-in matches `compat` by default; the code's defaults are 1 and `strong`, and the table says so now.
- Docs: operations offered `--secret -` for typing a secret, an option acme does not have; it names `--bind-pw -` and `--set KEY=-` (also a module's secret) now.
- Docs: 107 settings a person can change (SMS and codes, SNMPv3, alerts and the report, remote backups, sign-in protection, the administrators' groups, updates and restarts on a schedule, SIEM, the proxy, the debug log, the target agents' active mode, high security and others) were named in no doc; each doc now ends with its settings by key, with the default and what it does.
- Docs: the target agents' enrollment API left out `team` (a team's enrollment code), and the tag colours listed only six of the sixteen; both say what the code takes now.
- Teams: the same person asking again for the same action while it waited (a second press of Delete, or a second call of the API) made a second waiting action; the one already waiting is given back now.
- Teams: a member's end after the year 9999 was kept, and every view of the team (--team-show, the console) failed on it; it is refused now.
- Portal, team workspace: deleting a device that waits for an approval left the device's dialog open, and its Delete clicked again asked a second time (two of the same waiting for the approvers); the dialog now closes and the page is refreshed. The same for a certificate's Delete.
- Portal: downloading a file with the private key (PFX) that waits for an approval asked again on every click of its Download; the button is now off once asked.
- Portal: a request profile of a team whose rule makes every request wait (or none) said what the profile alone says ("issued at once", "Ask and issue") - the request then waited; it now says what the team's rule does.
- Portal, members: at tablet width the change and remove buttons of a member with several roles wrapped to the left under the roles; they now stay on the right, as for every other member.
- Portal: on a phone a person signed in had no way to change the language (the header has no room for it) but to sign out; their account dialog (their name in the header) now offers it too.
- Windows agent: since the exact IIS binding look-up of this version, a deployment whose IIS line names no address no longer found a binding on a specific address (10.0.0.5:443) and made a second one on *:443 beside it, the old certificate staying on the first; with no address the binding of that host and port is taken on any address again, the *: one first.
- Windows (OpenSSH) target: the IIS binding look-up without an address compared the host name with its case - "www.Example.cz" in the line missed the binding www.example.cz and the deployment failed on a duplicate binding; compared in any case now.

## 1.0.126 - 2026-11-18

- Microsoft CA through acme-agent: a template name with a space ("Web Server 2") was written into the agent's policy unquoted (allow adcs, the line a refusal names, acme-agent adcs cas, acme --target-agent adcs-templates), so the policy's own line read back was refused and the CA's line lost; the list is now quoted (template="Web Server 2,WebServer").
- Microsoft CA through acme-agent: the agent's script said the CA's error codes sign-extended (0xffffffff80094012), so none was explained in words and the code was cut short; codes are now 32-bit (0x80094012) and say what to fix.
- Microsoft CA through acme-agent: the template list of a CA dropped the empty OID line of schema 1 templates (WebServer) before pairing names and OIDs, losing every other template from the list; the OID lines are now skipped by what they are.
- Microsoft AD CS (RPC): a certificate's template with a line break added request attributes of its own (e.g. SAN:dns=...) for a CA that takes names from attributes; such a template is now refused (security).
- Microsoft AD CS (RPC): a domain controller given as an IPv6 address without brackets (2001:db8::10) was asked at a wrong host and port; it is now that address on port 88.
- Agent discovery: nginx includes and ssl_certificate paths given relative were taken from /etc/nginx even when nginx.conf is elsewhere (/usr/local/nginx/conf) - nothing was found there; they are now of the folder of nginx.conf.
- Agent discovery: a file included in several places (an nginx snippet in two server blocks, an Apache file in two VirtualHosts, Dovecot) was read only for the first, so the other services lost their certificate files, and deep include chains dropped files; includes are now stopped only on a real loop (a file including itself), with a bound on the includes in all, and a block read twice is told once.
- Agent discovery: HAProxy found in /usr/local/etc/haproxy proposed a test of /etc/haproxy/haproxy.cfg; the test now checks the configuration found.
- Agent discovery: Dovecot 2.4 (ssl_server_cert_file / ssl_server_key_file) was not found; it is now.
- Agent discovery: a certificate file whose path holds a space (Apache's quoted "/etc/ssl/my cert.pem") broke the whole discovery view (an error instead of the cards) and would have made an invalid output line; such a file is left out of "Make a deployment" and its policy lines.
- Agent discovery: "Watch it" took nginx's .example.com or ~regex server names as the name to ask for (SNI); it now takes a host name only.
- Portal teams: a member who manages a team's devices still made a one-time join code for the team's agent target, and confirmed an agent asking to join, after the administrators' limits took the team's agents away (agents off, or device modules without it) - while its enrollment code was refused; both are refused now in words naming the team (refusing an agent still works). (security)
- Portal teams: saving a sub-team's limits on the portal dropped what the editor does not show of its approval rule - the "outside" envelope set by an administrator and whether the asker may approve too - so every request of such a team waited for approval; they are kept now.
- Portal teams: in Czech a device's module ("Server with acme-agent") stayed in English on its card, in its dialog and in the deployment's device list; it is in the page's language now.
- Portal teams: a device's settings showed a choice by its raw value ("passive") and a switch as 1/0; they read in the module's own words (and yes / no) now.
- Teams: a team that was only below a circle of parents written by hand (an import, another node) was put at the top level and lost the capabilities and limits it inherited; now only a team of the circle itself is cut loose.
- Teams: a team whose parent team was gone (an import, another node) could not be saved at all ("there is no team ... to put it under") - even its members or note; it is now kept at the top level, as the tree already showed it.
- Teams: a certificate a scoped certificate administrator gave to another team was checked against that team's limits only for what the save changed, so a certificate with names and a source the team may not use was moved into it; its names, source and validation as they are are now checked too (security).
- Teams: renaming a source, a validation or a request profile left the teams' limits (issuers, validations, profiles, the pre-approved envelope) naming the old name, so the team was refused what it was allowed; they now follow the rename.
- Target agents: a team whose limits allow only Windows agents (target_kinds: agent_windows) could not make an enrollment code (Settings and the portal checked the kind agent only); either agent kind the team allows now suffices, and each enrolling server is still checked against the team's kinds (a Windows server becomes agent_windows).
- Target agents: a server waiting in one team's enrolled target, enrolled again (same name, same key) with another team's code that confirms by itself, was confirmed in the first team's target, passing over that team's confirmation by a person (agents_auto_confirm off); a code now finds only a target of its own team (acme's own for a code without one). (security)
- Target agents: a Windows agent's policy as acme kept it lost its folders, the machine store, IIS sites, Remote Desktop, roles, read on the key and the roles the agent knows - a deployment with a Windows role was refused as if the agent were too old, the pages, the deployment's needs and the policy designer said none of them, and a saved design always "differed"; they are kept now.
- Target agents: an active agent with more than 20 jobs waiting got 20, and the rest were marked as sent but never handed over (each waited out its time); they now wait for the next poll.
- Policy designer: a Microsoft CA line whose template names have a space or brackets was written unquoted, and the agent refused the whole line; the names are quoted as the agent writes them.
- Owners and teams: the preview of "Teams from directory groups" (POST /api/teams/from_groups, dry run) told a certificate administrator limited to some teams which other teams each directory group is a member of, though the list of teams hides those teams' members from them; it names only the teams they see now. (security)
- Portal team workspace: the policy builder of a team's agent device (GET /api/portal/agent_builder), and the agent's own view, named every certificate deployed to the device - acme's own and other teams' - to a member who may only see devices; they now say "another owner's certificate", as the device does. (security)
- Target agents: the administration page cut a discovery through an agent (and loading the Microsoft CAs and templates an agent reads) after 60 s with "the daemon is not answering" while the agent was still being asked; it now waits as long as the agent may take (and the policy builder no longer gives up on the CA list after 20 s).
- Portal: a discovery through a team's agent (up to 240 s) was cut by the web server after 120 s (504); the portal now waits 300 s - an existing nginx-acme.conf is changed by the upgrade.
- Portal teams: an action of a team approved in full (a deletion, a revocation) that could not be done at that moment (a job working on the certificate) stayed "approved" for ever - never done, and every approval after it refused as "approved already"; it now waits again and is done when approved again.
- Teams approvals: a request that waited again (a new CSR with other names) still counted the approvals it had before, so one more approval let it through where its team wants two (and its earlier approvers were refused); the earlier approvals now stay in its timeline only, and the team's approvers are told it waits. (security)
- Request profiles: a new CSR with other names for a team's certificate was issued at once, past the team's limits (names under its suffixes) and its approval rule ("every request is approved"); it is now checked and waits (or is refused) as a new request of the team. (security)
- Teams approvals: a waiting request moved to another team (its team deleted with reassign, or its owner changed) kept its first team's approvals, so one approver of the new team let it through where that team wants two; only the approvals given for its team count now (a renamed team keeps them). (security)
- What happens: a request waiting for approval was said to be "renewed only when somebody asks"; it now says it is issued once approved, and a declined one that it is never issued.
- Owners and teams: after choosing another team in the tree, "New team" said it made a unit and "New unit" said it made a team (the two hints were swapped), and both still named the team chosen first to a screen reader; each now says what it makes, under the team chosen now.
- Owners and teams: a team's Certificates tab showed the bare state ("ok", "expired") - English on the Czech page; it now says it in words as the list of certificates does (valid, has expired, ...).
- Owners and teams: for a certificate administrator who sees only some teams, the Activity tab of a team outside them asked the daemon anyway and showed its refusal (and an error in the browser's console); it now says the activity is not theirs to see.
- Owners and teams: the "No" of a yes/no limit (agents confirmed by themselves) and the warning of the delete dialog of a team owning certificates stayed English on the Czech page.
- Command line: acme --roles and acme --team-access cut the capabilities at 48 characters, so most of a Team owner's or a Certificate manager's were never said; they are said whole now, and --team-access also says the limits in force and the team each comes from (its --json has groups_count, as the API).
- Command line: a team's device and a team's enrollment code could be made only on the pages; `--owner TEAM` (`-` acme's own) now goes with --target-add, --target-edit and --target-agent enroll new, --target-show says the team owning a target, enroll list and waiting say the team.
- Command line: the team's Activity and Teams from directory groups had no command line; `acme --team-activity NAME [--below] [--limit N]` and `acme --teams-from-groups FILTER [--member-role ROLE] [--parent TEAM] [--team-kind team|unit]` (a preview, made with --yes).
- Command line: acme --target-agent NAME discover cached, with no discovery asked yet, said "0 services found" as if one had found nothing; it says no discovery was asked yet.
- Command line: acme --target-agent NAME adcs-templates ended 0 when the agent refused without naming a policy line (an agent older than 1.0.125, the CA not reached); it ends 1, as look does.
- Command line: acme --role-del of a role that is not there asked for --yes first, and refusals named the API's words ("delete it with reparent", "with strip"); they are checked first and say --parent TEAM (- the top level) and --strip.
- Backups: a dump of PostgreSQL made by an older version (before 1.0.125's cert_roles) could not be put back at all - pg_restore failed dropping the function the newer table's trigger uses; it is put back now, and a table the dump (PostgreSQL or MariaDB) does not have is emptied as a copy empties it, instead of its rows (the custom roles) staying beside the dump's data.
- Owners and teams: a team whose parent team is gone was still refused "there is no team ... to put it under" when its members or note were saved from the administration's page (the page sends the parent it has); a save that keeps the parent it had now keeps it at the top level, and only a gone team named as a new parent is refused.
- Portal team workspace: a discovery through a team's agent (and the policy builder's "From discovery") named the certificate acme holds that was found on the server - acme's own or another team's - with its id to a member who may only see devices; it now says "another owner's certificate", as the device and the builder do. (security)
- Target agents: an active agent with more than 20 jobs waiting got them in whatever order the database returned; the ones queued first are handed over first now.
- Windows agent: a script the policy allows (allow script C:\Scripts\Reload.ps1) named by a deployment in another case (c:\scripts\reload.ps1 - the same file on Windows) was refused as not allowed; the plan now finds it whatever the case, as the root side already did when running it.
- Windows agent: allow role ccs path= took a device path (\\.\C:\Windows\System32) as a network share and so went past the places no job ever writes; \\.\ and \\?\ paths are now refused there as everywhere else (security).
- Windows agent: a discovery that asked for the roles could run PowerShell for up to 120 s + 300 s while acme waits 180 s for the answer; the roles' detection now gets only what is left of 150 s (at least 15 s).
- Windows agent: with its output redirected (acme-agent discover > file, a pipe, a scheduled task) a name the ANSI code page has no letter for (Č in cp1252, a Cyrillic CA name) ended the command with a UnicodeEncodeError; such a letter is now written as \u010c.
- Target agents, policy designer: "Save as this agent's design" sent the designer's state as `state`, which the API reads as text only - every save from the page (and from the portal's team workspace) was refused with "state is a piece of text here"; the state is sent as `design_state` now and the design is saved with it.
- Target agents, policy designer of a Windows server: with "From discovery" shown, the section menu lost its "Folders" button and had two buttons for the services ("Services" and "Units"); the menu matches the sections again.
- Target agents, policy designer: a design or a version opened from its text (saved from the command line) dropped every word with "=" from its test commands (postconf smtpd_tls_cert_file=/x became postconf), so the designer proposed a different command; the test keeps its words.
- Target agents, agent card: "What its policy allows" of a Windows agent left out the machine store, IIS sites, Remote Desktop, roles, read on the key, the Microsoft CA and discovery (a policy of only those said "Nothing is allowed yet"), and showed its folders as "IIS_IUSRS:" 0666; it lists all of them, discovery too on Linux, and a Windows folder with its readers.
- Target agents, agent card: the lines that allow a deployment its policy blocked were shown with "sudo" and "as root" for a Windows agent too; on Windows they are shown without sudo, for an elevated prompt.
- Target agents, policy designer: the saved design's time ("0 s ago") and many of the designer's words about a Windows policy (protected folders, UNC paths, batch files, roles that take nothing more, sites said twice, readers) stayed in English on the Czech page; they are translated.
- Certificates, Overview: the tile Failing counting failed renewals and failed deployments (e.g. 3 = 2 + 1) opened the failed renewals alone (2); it opens every certificate whose renewal or a deployment failed now (GET /api/certs?state=failing).
- Certificates: a tile of the Overview and the button "N waiting for approval" opened the list with the search, source, owner and tag chosen there before still applied (the tile said 3, the list showed 1); they open every certificate they counted now.
- Certificates, Details: a certificate whose owner was written in other letters than its team ("web" of the team Web, as the API and the command line take it) showed "nobody" in the owner box and lost its owner when only its note, tags or renewal were changed; the box shows the team and the owner is kept.
- Certificates, deployments: a certificate administrator of some teams was offered, for a team's certificate, the devices of other teams (in "Deploy it on a target" and the wizard's Deployments) - refused only on Save; only the devices of the team (above or below it) and of acme's own are offered now.
- Console: Owners and teams was missing (the pages and the command line had it since 1.0.125); the main menu now has it (o): the tree of teams and units, a team shown with its members, roles and limits, a team or unit added, changed, moved, its limits, its members added / changed / taken away with their roles and end dates, the roles, the access check of a person, what happened in a team, and a team deleted with where its teams below, certificates and devices go - each one acme --teams, --team-add/-edit/-del, --roles, --team-access, --team-activity.
- Console: a certificate's owner was typed as text, so a misspelt team made a free-text owner that no team's members or limits reach; it is now chosen from the teams as on the page (nobody, the teams, or the one typed before, kept as it is), also when a certificate is added.
- Console: a target's owner (the team whose device it is) could not be seen or set; the targets list shows it, a new target is asked for it, a target's menu changes it, and an enrollment code can be made for a team.
- Console: the acme-agent menu had no Microsoft CA templates (adcs-templates, of all CAs or one) and no last discovery (discover cached) or discovery of some kinds only; it has them now (the CA templates only for a Windows agent).
- Console: a secret of several lines (the Microsoft CA source's client certificate key, a step-ca provisioner key, a service account's JSON) was a one-line hidden box, so a pasted PEM key ended at its first line and only that line was saved; it is now read from a file on the server, as a PEM is (empty keeps it).
- ZeroSSL (REST API): a domain validation that failed once (domain_control_validation_failed) put its CNAME record or file in place a second time at the next try, the first one's handle lost and never taken away (and an answer without the validation part refused the certificate for good); the records in place are now checked again, and records of a DCV method changed meanwhile are taken away before new ones are placed.
- ACME: when the CA refused an order as the renewal (ARI "replaces") and acme ordered a new certificate instead, the certificate's details still said it replaced the one before; they no longer do.
- AD CS (Web Enrollment): the client certificate's key was a one-line password box, so a pasted PEM key lost its line breaks and signing in by client certificate always failed with "the client certificate and key do not go together"; the field is now a multi-line secret box, and a key saved on one line before is read too.
- Certificates: a certificate administrator limited to some teams who only views a team's certificates (role Viewer) was offered Renew, Delete, Change, Export, Deploy, the row's Renew and Run its tests on them, all refused by the server; GET /api/certs/one and the list's rows now say the account's capabilities on each certificate (caps), and the page offers only those.
- Certificates: a certificate without renewal days of its own was said to renew "30 days before the end" (list tooltip, renewal label, the wizard's summary) whatever Settings → Renewal and notices said; the page is told the setting (renew_days_default) and says its days.
- Validations: a dry run stopped while it waited for its test record left that record in DNS (or the test file on the web server) when taking it away had to wait for the provider, or went over SSH - the cleanup now runs as tidying after a stop, as an order's proofs do.
- HTTP-01 over SSH (nginx): a server block with "listen ADDRESS;" (no port, which nginx serves on port 80) was taken for one that does not answer port 80, so "Prepare the hosts" left it without the acme-challenge include and the CA could not fetch the token - it is now port 80.
- Teams: a scoped certificate administrator could prove a team's names by a validation the team's limits do not allow, by choosing it per name (challenge_map) instead of as the certificate's validation; each validation of the per-name choices is now checked too, also when a certificate is moved to another team (security).
- Teams (command line): `--members` split every member at its commas and `=`, so a group given by its DN (which the help allowed), a role with `+` in its name, a member's note or an end at an exact time could not be given; it now also takes a JSON list (`[{"who": "CN=..", "roles": [..], "until": "YYYY-MM-DD HH:MM", "note": ".."}, "group:Web"]`), the simple form parsing exactly as before.
- Teams (command line): `--team-edit NAME --note ''` left the note as it was; it now takes it away (as `--description ''` does).
- Teams (command line): `--teams` cuts the members and limits columns at 48 characters with no way to read them whole but `--json`; the new `acme --team-show NAME [--json]` shows one team whole (members with their roles, ends and notes, its limits), the old table unchanged.
- Console (Owners and teams): a team with a member given by its DN, a role with `+`, or a member's note refused any change to its members ("change them on the pages"); it now writes them back as the JSON list, keeps a member's note when the member is changed, and a group's DN can be typed as a member.
- Console (Owners and teams): changing a team's members rounded every other member's end at an exact time (set on the pages) to the end of that day; exact times are kept, and an end left on its day when the member is edited keeps its time.
- Console (Owners and teams): a team's note emptied in Change was kept ("not taken away"); it is now taken away.
- Target agent / policy designer: a unit name with a backslash (a systemd escape, `a\x2d.service`) was written into the policy, `acme-agent allow unit` and the designer's `sudo acme-agent allow unit` lines unquoted, and read back as `ax2d.service` - another unit than the one allowed; it is now quoted on both sides, as files and tests are.
- F5 BIG-IP: a key or certificate the BIG-IP refused to install stayed uploaded in /var/config/rest/downloads (the key in clear); the upload is now removed whatever the install did. (security)
- Windows (SSH): an import into the machine store that failed half-way left the PKCS#12 with the key in the machine's temporary folder; it is now deleted after a failed import too. (security)
- MikroTik (RouterOS 6, SSH): with "Deploy now", a refused removal of the certificate of the same name left the uploaded key file on the router; the uploaded files are now always removed. (security)
- QNAP: writing stunnel.pem / uca.pem that failed half-way (disk full, a file refused) left the new or a cut stunnel.pem beside the old uca.pem, read at stunnel's next restart; the copies made just before are now put back.

## 1.0.125 - 2026-11-18

- Enterprise teams - Settings → Owners and teams rebuilt as an organisation: a tree of units and teams (search, counts, a drawer on phones), each team's page with Overview, Members (directory search, roles, expiry), Limits (every limit with where it comes from), Devices, Certificates and Activity; the Roles matrix; Access check (what a person may and why); teams from directory groups. Nothing changes for an installation that does not use them (docs/teams.md).
- The certificate portal rebuilt around the team workspace: a team switcher, Overview, Certificates (paged and searched on the server, actions by what the person may), Requests with *Waiting for you* and the approval timeline, Devices with acme-agents (enrolment codes, waiting agents, the server's panel, its policy, what was found on it), Deployments with What happens, Members, Sub-teams and limits, Activity; a person in no team keeps *Your certificates* in the new look (docs/certificate-portal.md).
- **Enterprise teams - teams in a tree** (docs/teams.md "Enterprise teams"): a team may stand under another (`parent`), regions and sites are teams of the kind `unit`, every team has a `description`. A circle is refused; renaming a team renames it in the teams below it, on its devices and its enrollment codes; a team with teams below it is deleted only with `reparent`. A team saved as before keeps the new columns empty - nothing changes for an installation that does not use them.
- **Capabilities and roles**: what a member may do is a set of 20 capabilities (cert.view ... team.activity). The old rights view / request / manage / approve stay and give exactly what they gave; members may also carry roles - nine built in (Viewer, Requester, Renewer, Deployer, Device manager, Certificate manager, Approver, Team manager, Team owner) and roles of your own (`cert_roles`, backed up, exported, replicated). A membership may end (`until`). The guard checks each route for its own capability (renew - cert.renew, revoke - cert.revoke, a key - cert.key ...); a member with the old manage keeps everything.
- **Inheritance**: a member's capabilities on a team apply to every team below it; the teams and each person's capabilities are computed once per version - 2000 teams and people in hundreds of nested groups stay fast.
- **Limits of a team** (`policy`): request profiles, the free form, sources, validations, target modules, name suffixes, the most certificates, the longest validity, key download, target agents - the intersection of the team's own and those of every team above it. Checked on the portal's request (free form and profiles), the portal's key download, a certificate a scoped certificate administrator makes or changes; a refusal names the team whose limit refused it.
- **Approval workflows**: per team `approval` {mode none / profile / always / outside the pre-approved envelope, approvers team / parent / team_or_parent / both, count 2 (four eyes), self}; every approval and decline recorded with the request (its timeline), the request let through once the rule is met, the approvers wanted told by mail. `always` also makes a scoped certificate administrator's new certificate wait. Other actions may wait for an approval too (`approve_actions`). The old words "profile" / "always" are read.
- **Devices and agents of a team**: a target may be owned by a team (`owner`); an enrollment code of the target agents may carry a team - the servers enrolling with it become that team's targets, confirmed by themselves only where the team's limits allow it (`agents_auto_confirm`).
- **The directory for the teams**: `GET /api/dir/search` (users and groups for the member picker, 50 a page), `GET /api/dir/group` (how many are in a group, nested, and the first 20), **access check** `GET /api/teams/access?who=` (a person's teams, capabilities, limits and why - which membership, role, group, inherited from where), **teams from directory groups** `POST /api/teams/from_groups` (a preview first). Team activity: `GET /api/teams/activity?team=`; every change of a team (members added, removed, changed, its limits, its place in the tree) is an event naming it.
- Command line: `acme --team-add/--team-edit --parent TEAM --policy JSON --description`, members `who=Role+Role@YYYY-MM-DD` beside the old `who=view+request`, `acme --team-del NAME --parent TEAM|-`, `acme --roles`, `--role-add NAME --caps ...`, `--role-del NAME [--strip]`, `acme --team-access WHO`.
- **The portal's team workspace - the API** (docs/certificate-portal.md "Teams"): a member of a team works for it, and for every team below it, on the portal - their teams with capabilities, limits in force and counts (certificates, expiring, failing, devices, agents waiting, waiting for them); *Waiting for you* (requests and actions to approve, each with its timeline); the team's devices (added and edited with the module's own fields and checks, tested, deleted - refused while deployments use them; secrets never shown back, only whether they are set); target agents (join codes, team enrollment codes, agents waiting confirmed or refused, the server's facts, the policy designer, update); deployments of the team's certificates to the team's devices (What happens, the module's test, run); members; teams below and their limits; activity. Every route checks the person's capability on the team and the team's limits; a refusal is said in words and is an event.
- **The portal's certificate actions by capability**: *Renew now* needs cert.renew, renewed by itself cert.auto, *Revoke* cert.revoke, a PFX with the key cert.key, *Approve* cert.approve - a Renewer renews without being able to revoke. New *Delete* (cert.delete). Where a team's policy names them in `approve_actions`, a revocation, a deletion, a key or deleting a device waits for an approver of the team first. The old right manage keeps everything it gave.
- **No escalation on the portal**: a member is given only what the giver holds on the team; a member holding more is not changed or removed; nobody adds themselves, raises or lengthens their own membership; teams above are never touched; the limits of a team below are never set wider than those in force above it (and agents confirmed by themselves stay the administrators' to allow).
- **Thousands of certificates on the portal**: `GET /api/portal/certs` pages and searches on the server when asked (`team`, `q`, `state` incl. expiring / failing / waiting, `page`, `per`); without them it answers as before.
- Fixed: with the team's lead and then the team above approving (`approvers: both`), another lead of the team was offered the request after the first lead approved it - and refused.
- A person in no team sees the portal exactly as before.
- New source **Microsoft AD CS (through acme-agent)** (`ms_adcs_agent`, docs/ms-adcs-agent.md): certificates from a Microsoft CA without any web service - acme sends its CSR to the acme-agent of a Windows member server of the domain, which submits it to the CA natively (the CA's request interface over RPC, as `certreq -submit` does) as its computer account (Kerberos) and returns the certificate with its chain. acme holds no credential of the domain at all. A request waiting for a certificate manager is asked for again at later tries (`certreq -retrieve`); a denied one is said in words; a certificate for another key is refused. The form's *Load the list* of the CA and the template asks the agent. The Web Enrollment source (`ms_adcs`) is unchanged.
- Target agent (Windows): new operation `adcs` and the policy entries `allow adcs "HOST\CA Name" template=A,B` (several templates in one line, `template=*` any template of that CA, one line a CA) and `allow adcs-read` (every CA and its templates listed, read-only); a job for a CA or template not allowed is refused with the line that allows it, a CSR naming a Windows sign-in name (UPN) is refused, and acme never passes arguments or attributes of its own. `acme-agent allow|deny adcs ...` keeps one line a CA; `acme-agent adcs cas` and `acme-agent adcs templates --config "HOST\CA"` list the CAs and templates on the server. An agent on Linux refuses the operation. (security: no password for the CA in acme)
- Target agents: the Microsoft CAs and templates a Windows server's agent reads - `GET /api/agents/adcs?target=NAME`, `acme --target-agent NAME adcs-templates [--json]`, and in the policy designer a section *Microsoft CA (AD CS)* that loads them and ticks CAs and templates (or every template) into `allow adcs` lines; *What the deployments need* lists the sources asking through the server.
- What happens: a certificate of the new source shows the signed job to the agent ("Sends a signed job (adcs submit) to the agent of …", "The agent runs certreq -submit -config … with the template …") with the agent policy's verdict and the line that allows it.
- New source *Microsoft AD CS (RPC, as certreq)* (`ms_adcs_rpc`): certificates asked from an AD CS CA directly over RPC, the way certreq.exe does (MS-ICPR CertServerRequest over DCE/RPC on TCP: the endpoint mapper on port 135, or a fixed port) - no IIS, no Web Enrollment, nothing installed on Windows. Signed in with Kerberos (AES256/AES128, the domain controllers set or found in DNS, mutual authentication) or NTLMv2 - Kerberos falling back to NTLM where it cannot be used, said in the job's steps - and every call encrypted (packet privacy, as AD CS enforces). The template per source or per certificate; a request held for approval is kept and fetched at later tries; the certificate must be for the request's key; wrong password, clock skew, a template the user may not enroll for and the CA's other refusals are said in words. Try it signs in and binds only; What happens shows the conversation step by step without the password. Kerberos needs python3-cryptography (NTLM does not). Tested against the RFC 3961/3962 and MS-NLMP vectors, MIT Kerberos and mock servers - not yet against a real Windows CA. See docs/ms-adcs-rpc.md.
- What happens (the run plan): a source that speaks a protocol of its own (Kerberos, DCE/RPC) can now have its steps written down instead of showing "went around acme's connection layer".
- Target agents: discovery (docs/target-agent.md "Discovery") - what a server runs that takes certificates, read by its agent, off unless its policy says `allow discover` (every kind) or `allow discover KIND,KIND`; without it the agent refuses and says the exact line. Read-only and bounded: configurations read by the root side, of each certificate only subject, names, issuer, end, thumbprint and serial; a key file is never opened, a keystore password never said.
- Linux: nginx (includes, conf.d, sites-enabled), Apache (Include, IncludeOptional, chain files), HAProxy (crt files and folders), Postfix, Dovecot (!include, local_name), Exim (Debian's macros), Tomcat (server.xml keystores and PEM files), Proxmox VE, Proxmox Backup Server, OpenLDAP, Grafana, Cockpit, Webmin, vsftpd, MySQL/MariaDB and certificate files in the folders the policy allows; each with its unit, names, files (owner, mode), the certificate served, the preset that fits and its test and reload. Windows: IIS sites and their https bindings, the Remote Desktop listener, the roles (SQL Server instances, WinRM HTTPS listeners, LDAPS, FTP, AD FS, RD Gateway with their certificates; the others found), the machine store - which certificates acme imported.
- acme-agent discover [--kind K,K] [--json] on the server; acme-agent allow / deny discover [KIND,KIND].
- acme: GET /api/agents/discover?target=NAME[&kind=][&cached=1] (certificate administrators; the answer kept with the target), acme --target-agent NAME discover [cached] [--kind K,K] [--json], an item in the console's agent menu.
- The target's card: "Found on this server" - a card per service with what it serves (days left, issuer, acme's or not); Make a deployment opens the deployment dialog prefilled (preset, the files at the paths found with their owners and modes, test, reload; Windows: machine store, IIS bindings, listener, role and instance; acme's certificate chosen when it is the one served); Add to the policy opens the designer with the lines ticked; Watch it a test of what it serves; the certificates acme does not manage with Watch it and Import…. Without the policy line: the line, and "Allow it in the policy designer…".
- The policy designer: a Discovery section (every kind or kinds one by one, the agent's own line) and, after a discovery, "From discovery" with each service's lines to add.
- Target agents: a join, join-state or enrollment request whose proof had a letter beyond ASCII stopped with an error of the daemon (and a wrong join was not counted as a try); it is refused with 403 and counted now. (security)
- Target agents: a renewal of an agent's certificate that the agent did not take put back the old certificate but kept the new one's end - acme thought it renewed for 30 days and the certificate in use ran out without a renewal or an alert; its end is put back too, and the renewal is tried again.
- Target agents: after a renewal whose answer was lost (the agent had taken the new certificate), the next renewal no longer let in the certificate the agent uses - it was locked out; acme now keeps the certificate the agent was last seen with as the one let in beside the new one.
- Target agents: the key check of an agent's certificate request read the whole request, so a subject naming "NIST CURVE: P-256" let a weak RSA key (1024 bits) through; only the key itself is read now. (security)
- Target agent (Linux): a broad `allow file /etc` (or `/usr/local`, `/usr/share`) still let a job write places whose files give root - `/etc/tmpfiles.d`, `/etc/sudo.conf`, `/etc/ld.so.cache`, `/etc/binfmt.d`, D-Bus (`/etc/dbus-1`, `/usr/share/dbus-1`), `/usr/share/polkit-1`, `/usr/local/lib` (Python's site-packages, and the release keys an update is checked with) and Debian's `/etc/python3.X/sitecustomize.py` (run by every Python as root, the agent's root side too); they are now never written nor taken away, whatever the policy says. (security)
- Target agent: `acme-agent deny script PATH` of a script changed or deleted since it was allowed was refused ("no such entry" / "cannot be read") - it is now taken away by its path; `acme-agent allow script PATH` again after a change replaces the line of that path instead of adding a second one.
- Target agent: `acme-agent allow file DIR --owner` (or `--mode`) with no value after it stopped with a Python traceback - it now says how the command goes.
- Overview: at a phone's width the page opened about 540 px down, under the header (the account and Sign out out of sight) - the certificates' tiles drawn in front of isemon's tile pushed down what the redraw keeper held and the page was scrolled after it; a page at its very top now stays at its top.
- Overview: the tile The database said "naposledy před copy 2 min" in Czech ("last copy 2 min ago" taken by another sentence); it now says "poslední kopie před 2 min".
- Jobs: the count of running jobs on the tab stayed "1" for good once the job ended while the Overview was shown; the Overview now keeps it up to date too.
- Overview: the tile Failing (and a failed deployment under What needs a look) opened Jobs at "deployment · failed", which showed no job when the deployment failed inside an issue or a renewal; it now opens every failed job, and a certificate chosen in the Jobs filter before no longer hides them.
- Log: a clock stepped back (NTP) silenced every warning and error written "once in a while" (the database away, a tick that broke) until the clock caught up - a day back, a day without a word; such a line is written again at once.
- Certificate jobs: a stop asked from the other node or from the pages, and the steps written while a job runs, were timed on the wall clock - with the clock stepped back the stop was not seen (and the steps not written) for as long; they are timed on the monotonic clock now.
- Certificate jobs: a job the pool refused (its pool shut down by another thread as certs_parallel changed, or acme stopping) stayed "queued" and kept its certificate busy until acme was restarted; it is given to the pool under the pool's lock now, and one still refused is ended as failed with its certificate free.
- Settings: a directory saved (or the configuration put in) on this node while a change from the other node or the command line was not yet read here wrote over its mark and took it as read - that change never came into effect here until the next restart or save; it is read in now.
- Czech: a number before a noun said the same word whatever the number ("zbývá 1 dní", "Přesunout 1 tokenů", "vypršel před 1 dny", "1 neuložených změn bylo zahozeno", "poslední 2 dní", "úplný – 5 certifikáty"); about 100 texts now use the word, and the verb, that fits the number ("zbývají 3 dny", "3 tokeny přesunuty").
- Czech: about 100 messages of the daemon that reach the pages (refused requests, failed restores, the database agent, SSH tokens, users of the nodes...) had no translation or came out half Czech, half English ("klíč that came with it cannot be zapsán do ..."); they are translated now.
- Czech: "Take every certificate of the mail server away" said "adresáře the mail server"; the note on groups that may sign in to the portal, the note of the configuration import and "signed out" were in English; "Login key" and "Distinguished name" were left untranslated.
- Pages in another language: a short pattern such as "{0} of {1}" took English words with "a" among them for a name ("not a backup of acme" became "not a backup z acme"); such a text now stays wholly in English unless it is translated whole.
- ACME (Settings → Automatic certificates): every request to a CA whose address held "cert" (acme.cert.example, /certificate-authority/...) asked for a PEM chain instead of JSON; only the certificate's own download asks for it now.
- Sources GoGetSSL and SSLS.cz: Revoke was offered for their certificates although their APIs cannot revoke, and the job always failed; Revoke is no longer offered for them (the reason is shown instead).
- Microsoft AD CS source: a request held for approval and then denied by the certificate manager was asked for again at every try for 90 days, each refused, and no new request could be made; the denied request is now let go, so the next try files a new one.
- acme-agent: a key the agent made of type Ed25519 written as key-traditional failed the deployment (no traditional form exists); it is written as PKCS#8, as acme does.
- Own CA: a path length of -1 ("no limit") for an intermediate under an authority with a path length made it one with no limit, and acme then let authorities be made under it whose certificates every client refused (path length constraint exceeded); -1 now means the most the parent allows, and a root or request with -1 has no limit (no "pathlen:-1" in the request).
- Own CA: a certificate that is not an authority (CA:FALSE) was signed with keyCertSign or cRLSign in its key usage when a profile asked for them; it is refused now.
- Own CA: Import an authority ignored the chain pasted in the dialog (chain_pem) - an intermediate from elsewhere was kept without the authorities above it and what it signed was handed out without them; the chain is kept now.
- Certificates: the key-traditional format of an Ed25519 certificate failed ("unsupported public key type") and so did a deployment asking for it; Ed25519 has no traditional format, so the key is now handed out as PKCS#8.
- Certificates: importing or parsing a PEM file saved as UTF-16 (Notepad's "Unicode", PowerShell 5's > and Out-File) said "not a format acme knows", although the certificate viewer read it; import now reads it too.
- Certificates: a PKCS#12 friendly name with letters past ASCII (Ålias) came back as replacement characters when a PFX was read; it is now read correctly.
- Web TLS: a certificate uploaded as fullchain.pem with chain.pem as its chain put the intermediate into nginx's chain twice, and a leaf pasted again with Windows line ends went into the chain; each certificate is now taken once.

## 1.0.124 - 2026-11-17

- Target agents: an agent confirmed a second time (two people at once, a page not drawn again, the same server twice in *Confirm selected*) was signed a new certificate - an active agent that had already taken the first one was refused at its first poll and locked out. A confirmed agent now stays as it was confirmed.
- Target agents: a refused enrollment request (a wrong proof, a code used up) wrote the enrollment code back as it was read before the check - a revocation made in that moment could be undone. It is re-read first now. (security)
- Target agents: the hash of acme_agent.py (the program as a Linux agent updated from 1.0.119 says it) was read and computed again for every agent of Settings → Target agents on every refresh; it is kept with the program's hash now.
- Target agents: *Update all agents* and the card of a Windows agent told to run `sudo acme-agent allow self-update` - Windows has no sudo; a Windows agent's line is `acme-agent allow self-update` (in an elevated prompt).
- Upgrades: `install.sh` cut a text for the upgrade's progress file after escaping it - a cut through an escape (a long message ending in \ or ") left a broken `.upgrade.json`; it now cuts first.
- Target agents: `acme --target-agent NAME system` said a time zone half an hour behind UTC as UTC+00:30 - now UTC-00:30.
- What happens: a PKCS#12 / keystore file with a password made by acme (pfx_password_mode "generate") on a server with acme-agent was said to get "a new password each time"; it says now that acme made one and keeps it sealed with the deployment - the same at every renewal.
- What happens: "Next renewal" of a short-lived certificate (shorter than three times its renew days, e.g. a 6-day one) was said to be at once; it says now when the renewer really renews it - a third of its life before its end.
- What happens: with "Keep the key" and the key type changed, the plan said the key it has is kept; it says now that a new key of the type asked is made, as the renewal does.
- SELinux: "Download the report" in a cluster waited three minutes for a node not heard from, and then said "every node's report is in it" while that node's report was an old one or none; a node not heard from is no longer waited for, and the nodes that made no new report are named.
- SELinux: with a node not heard from (its first look or a step asked of it pending), the card was asked for and drawn again every two seconds for as long as the pane stayed open; such a node is no longer waited for.
- Upgrades: for ten minutes after an upgrade was done (or failed), a daemon not answering was not said on the pages - no red bar, the pill as it was - because root's file of that upgrade hid it; only an upgrade still running does now.
- Agent (Windows): a deployment's stale file whose path differed from a file written in the same deployment only in letter case (C:\Certs\a.pem vs C:\certs\a.pem, e.g. after the path's case was changed in acme) was taken away right after the new certificate was written - the same file on Windows; paths are now compared case-insensitively on Windows (and the same file twice is refused).
- Agent (Windows): an upgrade or repair of the MSI run with JOINCODE= (the documented Intune/SCCM line, a GPO transform) joined acme anew, replacing the agent's key and leaving its confirmed target behind; an agent that has joined already now keeps its identity (acme-agent join CODE still joins anew).
- Agent (Windows): the MSI's join action did not set HideTarget, so a verbose install log (/l*v) could hold the join or enrollment code from its command line; the bit is now set after wixl builds the MSI. (security)
- Agent (Windows): an import into the machine store that found no private key left the imported certificate in LocalMachine\My; it is taken out again before the deployment fails.
- Certificates: a certificate edited in its wizard (Change names, key, source…) and saved without a change got 30 days before the end of its own and serverAuth alone as its key usage when it had neither (an imported one, one made by the command line or the API) - it stopped following Renewal and notices and lost clientAuth at its next issue; both stay as they were now unless changed.
- Sources, Validation, Targets, Tests: a read-only account was offered "Read from a file" beside a box it cannot change; not offered now.
- What happens: on a phone the lead over several deployments ("Pick a deployment...") was crossed by the plan's lines; it stands beside them now.
- Czech: the key of a Windows agent's deployment in What happens, "the agent has no key to seal to (join it again)" and the roles' note of a Windows agent's deployment stayed in English; translated.
- Backups: a backup put back (or a node started on another machine under its old name) did the backup's last SELinux step again at once - a "permissive" or "enforce" asked months before, even with high security on; the node now only looks at SELinux again.
- High availability: the database server row of a node forgotten or renamed stayed for good - a server of nobody's on the HA and database cards and in the metrics, and its alerts (agent not answering, certificate ending) could not be taken away; only the nodes of the cluster are listed now.
- Validation (acme-dns) (security): an incomplete answer of the acme-dns server to a new account was quoted in the error with its password - the password is dots now.
- Settings (TLS): an HSTS age that is not a number reached the root helper as an error of its own instead of being refused with the reason.
- Validations (HTTP-01 over SSH): "Check by the name" for a certificate of an IPv6 address fetched http://2001:db8::1/... (no brackets, an address no client reads) and waited until the order failed; the address is now put in brackets.
- Validations (a commercial CA's DCV file): the check that the file is served built the same broken URL for an IPv6 address; it is now put in brackets.
- acme's own DNS server (validation): three failed looks at the record in all - spread over the whole wait, or one moment without an answer for a certificate of three names - failed the order at once; now it takes three failures in a row for the same record.
- Command line: `acme --selinux fix ... --json` and `acme --selinux rules --take-away ID --json` printed what root would do and each line it said around the JSON, so the output was not JSON; the plan now goes to stderr and stdout holds the JSON alone.
- Command line: `acme --target-agent NAME look` ended with exit code 0 when the agent could not be reached or refused (the error only in "said"); it now ends with 1.
- Command line: `acme --target-agent NAME code` of a Windows target said to run `acme-agent join` "as root"; it now says an elevated prompt (Run as administrator), the MSI's Join step or `msiexec ... JOINCODE=`, as the target's card does.
- Console: Certificates → Target agents had no *Update all agents* as the pages have; it now has it (asked first, then `acme --target-agent all update`).
- Syslog (SIEM): one event that could not be put into a syslog line kept "the logs do not reach syslog" up until the settings were saved again; the next line made clears it.
- Portal (Czech): two refusals stayed in English (a key made by a device; signing in through the load balancer switched off), and "by itself, N days before the end" had the wrong gender in Czech.
- Report: the "Events by day" bars are the calendar's days - a month with the clocks put back showed one day twice and lost its last, and the events after the change were counted into the day before; the period "so far" now also shows the day going on.
- Alerts: a file system running out of inodes is "bad" from 95 % like one out of room, and the alert says how full its inodes are (it was only a warning saying e.g. "40 % full").
- Prometheus/SNMP: the counts of certificates and deployments by state add the rows without a state to the "new" ones instead of one replacing the other.
- Settings → Monitoring: the prometheus.yml shown puts a node's IPv6 address in brackets, so Prometheus takes the target.
- Certificate portal: a certificate not issued yet that nothing issues (not renewed by itself, or its approval never recorded) still said "being issued" and pulsed for good in its state tag, in the list and in its dialog (1.0.119 had put only the Expires column right) - it now says "not issued yet", as the administration does; one a job is issuing still says "being issued".
- Windows server (OpenSSH): the old acme certificates were removed from the machine store when only IIS did not use them - one still used by the Remote Desktop listener, SQL Server, WinRM or an http.sys binding (AD FS, WAP, SSTP...) went; now every use is looked at, as the roles' clean-up and acme-agent do, and such a one is kept.
- Windows server (OpenSSH): when the script after the files failed, the previous files were put back but the copy kept only for that (<file>.acme-prev, the old key) stayed beside each file; it is removed now, as on Linux.
- Deployment form: a read-only account could still click the script's and the password's modes, "As text" (and type into it), the placeholders, "From a template..." and type into the module's other options of a target that writes files; nothing of it can be clicked or changed now (saving was already refused).
- Mail: with Signing in left at "auto" (the default) and no account or password set, every mail through a relay that needs no sign-in failed ("SMTP AUTH extension not supported", or with "STARTTLS if offered" a refusal to send "the password" in plain text) - no alert and no sign-in code went until Signing in was set to "none"; "auto" with no account now sends without signing in, and the steps say so.
- Second step of the administration: a code by e-mail or SMS asked from a page whose language was never chosen in that browser went in the language of the codes (code_lang / mail_lang) instead of the page's (ui_lang) - an English page got its code in Czech; it now follows the page as the setting's help says.
- Docs: admin-second-step.md said sign-ins already open stay open when the second step is switched on; they end (all but the one switching it on), as the code has done since 1.0.149.
- VIP address: after an upgrade the VIP's copy of the HTTPS server (acme_vip.conf) was not written again - the locations the new version gives acme.conf (/metrics, /healthz, /pki...) were missing on the VIP address until a TLS or VIP setting changed; a new version now asks root once again.
- Certificate portal: on a phone "Your certificates" was a table 450-670 px wide in a ~308 px box - Expires and the download button only after a sideways scroll nobody was told of; now each certificate is a card there (name, state, Expires, download), the desktop's table as before.
- Certificate portal: the sign-in form's `required` fields had the browser say what was missing in its own bubble, in the browser's language, so the page's translated "type your name" / "type your password" never appeared; now the page says it.
- Certificate portal: Revoke was offered for a certificate whose source cannot revoke it (a self-signed one) and its job then failed "Self-signed cannot revoke a certificate"; the list now carries why not (revoke_no, as the administration's) and Revoke is not offered there.
- Certificate portal: "The portal is switched off. Ask the administrator." on the sign-in page was not translated; now it is (Czech).
- Local users (password policy): each time the policy was put in and taken out again, /etc/login.defs got one more empty line at its end (and PASS_WARN_AGE was put after it); the file is now exactly as it was.
- Time (chrony): with the time servers not set by acme (only the time zone saved), the system's own chrony.conf was rewritten when its line endings differed, a copy kept and chronyd restarted; the file is now left as it is.
- Administration sign-in: an empty name or password got the browser's own bubble in the browser's language (the form had `required` and no check of its own); the page now says "type your name" / "type your password" in the page's language, as the portal does.
- Settings → Find a setting: "Sign in with a password" of the administration and of the portal named its place "adminsignin" / "portalsignin" and opened the first pane; it now says Accounts / The enrolment pages and opens them at the setting.
- Settings → Find a setting: a read-only or certificate administrator was offered the settings of panes and cards only a full administrator opens (Alerts and reports, Proxy, the firewall's settings…) and choosing one opened the first pane; only what the account can open is found now.
- Certificates: What happens of a certificate whose renewal (or first issue) failed said its next renewal at the end of its renew window (or "at the next look") - it now says when it is really tried again (next_try); one made due for a new issue says now.
- Configuration import (security): a file imported "replacing all" that took a target of an agent away left its agent paired and let in, and a target put in later under the same number took that agent over; the agent is now let go as when the target is deleted on the pages.
- AWS ACM target: removing one half of a dual (RSA + EC) certificate deleted the ARN kept by the certificate's name alone - the half imported first, maybe the other one; it now deletes the ARN of its own key type (an ARN kept by the name alone only when ACM says it holds that key type) and forgets the deleted ARN.

## 1.0.123 - 2026-11-17

- What happens of a server with acme-agent (Linux and Windows): the steps in the order the agent takes them (before, files, machine store, bindings, PowerShell after the import, test, script, restarts, read on the key and the roles, after); how a PKCS#12, JKS or encrypted key is protected (the deployment's password, a new one each time, none) and a JKS's alias - never the password; the machine store's PKCS#12 format (legacy or AES-256); whether the Central Certificate Store's PFX files have a password; and *Leave a file alone when it is the same* off said (every file written again, the commands run) instead of the opposite.

## 1.0.122 - 2026-11-17

- SELinux in a cluster: every node a card of its own, side by side (one under the other on a phone) - each with its own findings and its own buttons at the bottom (put in what acme needs, switch to enforcing, back to permissive). *Look again* at the top looks again on every node at once; *Download the report* gives one file with every node's report.
- Target agents: a Linux agent updated from 1.0.119 to 1.0.120 by *Update* no longer says "Another program than the one this acme ships" - it updated itself with the files it knew (acme_agent.py; the Windows files are not needed on Linux) and runs exactly the program acme ships. A program really changed is still said.

## 1.0.121 - 2026-11-17

- Docs: how to build the Windows agent (the MSI) yourself from the repository on Linux - tools, download, build, signing (docs/target-agent.md, "Build the Windows agent yourself").

## 1.0.120 - 2026-11-17

- Upgrades: every page shows an upgrade going on in a band under the header - to which version, from which, who asked, how long, a bar and the step (*step 7 of 9*); in a cluster a row for each node (its step, how far, what happened, when), whichever node answers behind the VIP address. The pill says *in maintenance*, the cards *maintenance* and *upgrading*. Going back says *taken back to*.
- Upgrades: while the API, nginx and PHP restart the pages no longer turn red - no "not answering" bar, no red messages; the band says how long it has not answered and asks again every two seconds. Once every node is done the page loads the new version by itself, once (with changes not saved: a *Load it again* link instead). A failure is a red band with the reason and a link to Settings → Upgrades, hidden with ×.
- Upgrades: the sign-in page shows the upgrade too, and loads itself again once the API answers; nobody is signed out by an upgrade.
- Upgrades: root says how far it is in `/var/www/acme/.upgrade.json` (acme_upgrade.py, and `install.sh --upgrade` at each step - also when it is typed in, and `failed` when it is stopped); `acme --upgrade-follow` shows *step N of M*, and follows an `install.sh --upgrade` of this node too. `install.sh --upgrade` has a step of its own for restarting the service.
- `/healthz` says *being upgraded* after its first word during an upgrade; its status codes and first words are as before (balancers, keepalived and the other node read the same).
- While an upgrade runs the alerts "a node is not heard from" and "the nodes run different versions" wait, and the checks of what waits for a person are made only once root has finished on that node.
- SELinux has a section of its own: Settings → SELinux (it was a card under High security). A read-only account sees it too, without a button.
- SELinux: *What SELinux refuses* - each node's root reads every refusal since the machine started (AVC, USER_AVC, SELINUX_ERR, with the program, the whole path, the port), groups them and sorts them by what puts them right: a boolean, a label, a port, a rule of acme's, not for a button (with why), not acme's (grey). Each with the program, `SRC → TGT class { perms }`, the path or port, how often and when, and the command.
- SELinux: *Put in what is selected* - the page sends only the ids; the node's root works out every fix itself (setsebool, restorecon, semanage port, acme's own local module `acme_local` with one optional rule each), lists exactly what it will do before, writes every step in Events and looks again at once - under enforcing too. *acme's local rules* lists each rule with *Take it away*.
- SELinux in a cluster: one node at a time on the card (a pill for each node, a dot for how it stands); a fix, a rule taken away, a step and the report are the node's own and never done on the other; a step asked while the other node is in the middle of one is taken as before, with a warning in the log. *Switch to enforcing* stays locked while anything that can be put right or is not for a button is left.
- SELinux: acme's module lets the daemon start ssh, ssh-keygen, ping, ip, hostname and chronyc under NoNewPrivileges (they would not run under enforcing) and labels keepalived's check of the VIP address; `install.sh --uninstall` takes `acme_local` away too.
- SELinux: the report is of the node shown, and has the whole machine besides acme's part: every process, boolean, port type and module, what was changed locally, `semanage export`, the listening sockets.
- Command line: `acme --selinux look`, `fix ID...` / `fix --all`, `rules [--take-away ID]`, `report [FILE]` (the old `--selinux STEP`, `--selinux-check`, `--selinux-report` as before); the console has them too. *To be done by hand*: "SELinux refuses acme something - N can be put right on the card".

## 1.0.119 - 2026-11-17

- Settings → Time ("Its time") and Backups ("Next"): dd-mm-yyyy hh:mm:ss as everywhere else, not the browser's own format.
- Settings → Message texts: a save on a single node says "saved" - it said both nodes send the words now.
- Settings → High security: a rule made an exception (or enforced again) is shown at once on the settings of the other panes - "not allowed" stayed until the page was loaded again.
- Settings → Sign-in protection: a directory taken away while a change to its password cap waited no longer stops the page with an error.
- On a phone: SSH server's choices (Root signs in) wrap inside their frame instead of running past it; an account's buttons on one line; a source's or validation's window keeps its words the width of it, "default" in one piece; Show a certificate has the sides of every other window; a note under a table or buttons no longer sits right on it (on every screen).
- Command line: `--renew all` says which certificates wait for their approval - with every one due waiting it printed nothing; `--export NAME --format X` names a format there is not, before asking for `--out`.
- Command line: `--set KEY-=VALUE` takes VALUE out of a list (tags, a module's list) - it said "has no tags-"; a module's number given as `nan` or `inf` is refused, not a traceback; `--target-agent NAME forget|confirm|update`, `design text|forget` and `--console-users` / `--console-at-login on|off` answer JSON with `--json`; `NO_COLOR` set but empty no longer turns colour off.
- Console: the menus are not coloured with `--no-color` or `NO_COLOR`; the live log shows acme.log once it is made (opened before it was there, it stayed empty); a new account's name beginning with `-` or `.` is refused in the form; a target's acme-agent has *The policy designed for it* (`design show`), as the command line.
- Settings → The database: the card of this machine's database no longer says a MySQL 8.4 or later is not running (it has no `@@have_ssl`; its TLS is read from `performance_schema`).
- Certificates → Import (and a CSR's answer), Show a certificate (API): a file that is no base64 says "data_b64 is not base64" instead of a vague error (or "nothing was given").
- Settings → DNS: Test in a set's form with no servers in it says so - it tried the set as saved.
- Settings → Request profiles: a profile whose source was deleted says so in its form and keeps it until another is chosen - the box showed no source, without a word.
- Guides: a link whose address has spaces or brackets is kept after a save.
- Settings: a read-only account opening SSH keys or Modules from a link gets the first section it may open, not the section and a 403. Monitoring opens for it as before (the SNMP downloads).
- Settings → Message texts: the portal's and SSH's sign-in codes are listed by their whole titles - both were "The sign-in code by mail" (and "… by SMS").
- Settings → Backups: the times of the backups sent, of those at a destination and of the one to put back are dd-mm-yyyy hh:mm:ss as everywhere else, not the browser's own format; once a backup is put back, the settings and the pane are drawn again.
- Settings → Accounts on a phone: the box to find the directory's groups no longer makes the page wider than the screen.
- Certificates: a revoked certificate says "revoked" in red in the list and the overview, its window no "… days left" in green; a serial typed with colons (`1F:AB:…`) is found; the window says the key's size once ("RSA 2048", not "RSA 2048 · 2048 bits").
- Import: a key dropped with an earlier certificate is not taken for a new certificate dropped alone.
- CSR for an outside CA: when the certificate was kept but its CSR could not be made, pressing the button again makes the CSR of that certificate - it said "there is a certificate called … already".
- Deployments: the chain file of a self-signed certificate is shown empty (0 B) with a warning that it is written empty - What happens showed a chain of its own (~600 B), the form guessed one.
- HAProxy: the previous certificate file is kept until HAProxy took the new one; when the Runtime API refuses it (and no reload command is set, or it fails), the previous file is put back - the new one stayed.
- This machine: a deployment stopped after its files and before its script or command (acme stopped) runs them the next time - the files found the same, nothing was run.
- acme push: a deployment saved with no slots (automatically, on the server) shows Automatically and saves - it said "Nothing chosen" and was refused.
- Taking a target away: "taken off with it" is shown once "Take it off everywhere first" is on.
- Database TLS (pg_hba.conf): a line PostgreSQL could not read already, not of acme's, no longer refuses acme's own change of it (TLS for the other node, its new address, joining a pair) - nor, through acme-db-agent, every address acme adds.
- acme-db-agent: MySQL 8.4 and later (no `@@have_ssl`) is seen running, its TLS read from its TLS channel - it was taken for stopped and TLS refused; MariaDB without `have_ssl` no longer makes the agent look silent.
- DNS server: a record of your own with TTL 0 keeps 0 (it was given the default TTL) and the list shows 0, not "–"; a value the server cannot answer with (an MX of a name alone, an SRV of three numbers) is refused when added, with an example - it was kept and never answered.
- SSH keys: a host that begins with `-` is a host to ssh-keyscan, never one of its options.
- Settings → DNS: a set chosen for a function and then renamed or deleted before Save - Save said "there is no DNS set"; the choice follows the new name, or goes with the set.
- Owners and teams: *Make it an owner* / *Make it a tag* pressed twice asks once (the second said "there is an owner … already").
- Deployments (security): the password of the PKCS#12 / keystore files printed by the script after the files (an echo, `set -x`) is dots in the job and the jobs' log - it stood there in clear for anyone who may read jobs (this machine, SSH, Windows).
- This machine (files): a file's path given whole under the target's folder is shown where it is written - the preview, What happens and the test said `<folder>/<folder>/<file>`.
- Deployment form: a path with a placeholder that is not one names that one, not the first of the path (`{name}`); a deployment opened from a target's window shows its certificate's state and names (it said "web –").
- Target agents: an active agent whose certificate answer was lost (or that failed to take it) is answered again until its first poll - it was refused "no such join" and stuck while acme said it joined; a passive agent that took its certificate, its answer lost, is seen as joined instead of asked again and again.
- Target agents: a join sent again by the same agent with a new request (each one is signed anew) is taken - the key is compared, not the request's text; another key with a used code is still refused.
- acme-agent: `policy apply` keeps the ten newest copies of the policy - a copy named …-10 went before …-2 and the newer one was deleted.
- Target agents: the pane no longer reads and hashes the agent's package for every agent listed; *Download* of the package is shown only to those who may download it; *Design its policy…* clicked twice opens the builder once; a tile's update in progress keeps saying so when the pane is drawn again; the pane that could not be asked says it without leaving what is below it as if it were now.
- Database server card and firewall: a MariaDB server with an agent showed PostgreSQL's port 5432; it shows MariaDB's own now.
- acme-db-agent: MariaDB given a certificate that did not come back after its restart (or came back without TLS) is started again with its old files, not left stopped.
- acme-db-agent: `--forget NAME` of a node not joined says so (exit 1) instead of "no longer let in".
- Joining a database agent at a bare IPv6 address (2001:db8::5) took 2001:db8: at port 5; the wizard no longer says an agent typed as [IPv6]:PORT replaces the same one.
- `install.sh --db-agent` again without `--db-agent-port` opens and says the port the agent keeps, not 9443.
- This machine's database shown as a database server, switched off and on again: its card is back at once, not after 30 s.
- acme-agent (security): of `A || B` only the alternatives the policy allows run - one it did not allow ran as root beside (or instead of) an allowed one.
- acme-agent: a deployment whose test, script or reload could not even be started puts the previous files back (they stayed replaced); a sealed variable with a NUL is left out.
- Target agents: the same join sent again after its fingerprint was confirmed no longer undoes the confirmation; an agent's policy of odd shapes (a number for a list, Infinity) no longer stops acme with an error.
- Policy builder: a design's title is one line in Events; the needs card's `acme-agent allow file|script` lines are quoted for the shell (a path with a space).
- acme-agent: `install.sh --join` without a code and `acme-agent join CODE --listen` without an address say so (the latter before the agent's keys are replaced).
- Target agents: *Update all agents…* always has its button to start the update - offered but not pressed, with why (and the `allow self-update` line to copy), when no agent can be updated now; it had Close only.
- Target agents: a tile's *Design its policy…* (and the card's actions) sit in a row of their own at the foot, set off from the chips; tiles side by side line up.
- Target agents: a tile's *Update* clicked twice, or *Update all* while one runs, no longer sends the same agent the update twice; the join wizard asks one round at a time after *It is the same - confirm*.
- Join wizard on a phone: the steps' words no longer run over the next step.
- Policy builder: a command typed with an open quotation is red and left out of the file (the line before it stayed in, "the agent takes all of it"); it is not saved.
- Policy builder: what was clicked together (a template, a need, a switch) and not copied, downloaded or saved is asked about before Close or Escape take it away.
- Policy builder: the template search stays when a template is clicked; an emptied limit no longer shows "NaN KiB"; the output's tabs say which is selected to a screen reader; after a save *Start from* offers the saved design.
- Policy builder: an earlier version of a design saved without its state (the command line) opens with its lines, not empty.
- Certificate portal: a certificate whose owner is `group:` and a directory group's DN is in its members' list (it could be downloaded, but was not listed).
- Certificate portal: *Ask for a certificate*, on again after the limit, no longer keeps saying (tooltip, screen reader) that the limit is reached.
- Certificate portal: a certificate not issued yet that nothing issues (not renewed by itself, or its approval missing) no longer says "being issued…" and is no longer asked about every 3 s.
- Certificate portal: with a certificate as the only way to sign in, "your sign-in has run out" is said again on the sign-in page.
- Database server card: on a phone the title of the card's summary no longer squeezes beside its state, which goes under it; *Last heard* of a database server is red when it was not heard from lately, not because its database is down.
- Joining a database agent that did not answer in time once joined no longer says "Nothing was changed on this node" (it was joined): the join is kept, and the agent is looked at again shortly.
- install.sh --db-server mariadb: with no folder of MariaDB's configuration it says to set `bind-address` by hand instead of writing into a folder that is not there.
- Certificate portal: a sign-in left from before the one-time code was switched on is no longer drawn signed in for a moment; Settings → the sign-in's picture: *Save* with your own picture taken away and still picked is refused before the picture is taken away.
- Certificate portal: the request limit counts the requests of a person with a long sign-in name (over 180 characters); an administrator who sees every certificate no longer has a team's certificate of their own name shown as theirs.
- Certificates: *Import* of a wildcard certificate (or one whose common name has brackets) offers a name acme takes (`wildcard.example.com`) - the common name offered was refused by Import.
- Certificates: Enter on a row's button (*Renew it now*, *Run its tests…*, an authority's star) does what the button does - it opened the certificate (the authority) instead.
- Certificates: a certificate made by *CSR for an outside CA* says it comes from an outside CA (it said "–"); its answer dropped no longer asks "Leave what was typed here?".
- Certificate's window: on a phone its sections are no longer cut at the right edge; *Renews* says the same in both its sections (an imported one said "only when asked", a revoked one "by itself").
- Certificates: the names in the list are no longer a letter a line between a phone's width and a wide screen; *Add a certificate*: "Deployments" no longer runs into "Review"; Authorities: the buttons of *Published on acme* line up when they wrap.
- Sign-in (security): *whoami* reads the account as every other route does - with db_guard on, a role written into the database past acme (or a role of the enrolment pages) is nobody there; the pages' own gates (nginx's question before a big body, a new version or a database sent) took that role.
- Behind a load balancer (security): *The load balancers and WAFs* never takes every address (`0.0.0.0/0`, `::/0`) - anybody's X-Forwarded-For was then the client's address, each wrong password from an address of its choosing, past the counts and the sign-in protection; a configuration file of an earlier version with it is imported without it (and without *behind a load balancer* where none is named here).
- Sign-in cookies (security): a cookie planted beside the session's under another spelling of its name (`acme.session`, which PHP reads as `acme_session`) counts as a second one - and the sign-in is refused as with two of the same name; it was taken for the session.

## 1.0.118 - 2026-11-17

- **Target agents: the policy builder** (docs/target-agent.md, *Designing the policy*). *Design
  its policy…* on the agent's card, on its tile in Settings → Target agents and on what a
  deployment needs opens a builder of the whole policy: it starts from the agent's policy (or
  its saved design), offers templates (nginx, Apache, HAProxy, Postfix, Dovecot, Exim, Tomcat,
  Squid, Caddy, Traefik, lighttpd, OpenLDAP, PostgreSQL, MySQL/MariaDB, Grafana, Cockpit, Webmin,
  Proxmox VE/PBS, Mosquitto, vsftpd/ProFTPD, GitLab, Zimbra, Docker, any systemd service, a
  folder - the deployment presets' own paths) and everything the target's deployments need,
  one click each; folders with an rwx grid, units, tests, scripts, hashes, addresses, probes,
  connections, self-update, limits - checked live as the agent checks it (protected places,
  files the policy runs, shells, unknown words). It gives the policy file in the agent's format,
  the `acme-agent allow` lines and one block to paste (`sudo acme-agent policy apply -
  <<'EOF'`), with what changes against the server. acme never sends it.
- acme-agent: `acme-agent policy check FILE|-` and `acme-agent policy apply FILE|-` (root):
  checked first - nothing written on a line the agent would not read, a protected folder, a
  link, a script not there with its hash - then written root:root 0644 atomically, the one
  before kept as `policy.DATE` (the last ten), the diff said.
- The designed policy can be **saved with the target** in acme (documentation only: who, when,
  a title, a note, ten versions); the card says whether the server's policy matches it (with the
  lines that differ). `acme --target-agent NAME design show|text|forget`, Events for saving and
  deleting.
- The agent's policy shown is the one on the server: the agent sends its hash with every poll
  and answer, acme asks for the policy at once when it changed; the card asks again when what it
  has is older than a minute, and *Ask it now* asks an active agent too - a policy with
  `allow self-update` showed "Nothing is allowed yet", and no way to update.
- **Update the agent now** on the card (asked first, its progress, the new version when it
  answers), **Update all agents…** on Settings → Target agents (who will be updated and who not,
  and why), *Update* on each tile; `acme --target-agent all update`. Always acme's own signed
  package. "Another program than the one this acme ships" is no longer said of an older version
  a newer agent is offered to.

## 1.0.117 - 2026-11-16

- Settings → Target agents is drawn again by itself after active mode or the agents' port is
  saved, and asked every few seconds until each node's nginx has taken the port (or let it go) -
  it stayed as it was until the page was loaded again.
- acme-agent: `sudo acme-agent ...` now works on RHEL too - sudo's own PATH has no
  /usr/local/sbin, so install.sh links /usr/sbin/acme-agent to it (and takes the link away on
  uninstall). A fingerprint given to `acme-agent join` in place of the join code (the Copy of
  *acme's agent authority* on Settings → Target agents) is said to be one, with where the join code
  is made; the pane's install steps say the same under *Join*.

## 1.0.116 - 2026-11-16

- **Target agents: a server that takes its certificates without acme holding any of its
  credentials** (docs/target-agent.md). A new target, *Server with acme-agent*: a small agent on
  the server (`acme-agent`, Python 3 standard library, two processes - the network side as an
  account of its own without any privilege, the root side never on the network) does what its
  own policy (`/etc/acme-agent/policy`, root's - acme can never change it; it allows nothing until
  you allow it) lets it: files in the folders it names with the owners and modes it names, the
  units it may reload, the tests and scripts by their SHA-256. Whoever steals acme's database or a
  backup gets nothing of the server; whoever controls acme can do there only what the policy
  allows. The deployment is the SSH server's - formats, presets, before / test / script / reload /
  after, the copies, the same certificate again changes nothing, the previous files back when the
  test or the reload fails - with no shell: each command is read as a unit's verb, a fixed command
  or a script, each allowed by the policy. Every job is signed (Ed25519, a nonce, its time, the
  agent's id), the private keys are sealed to the agent, TLS 1.3 with certificates both ways from
  acme's new agent authority (sealed, in every backup, the same on every node).
- **Two modes, per target**: *passive* (acme connects to the agent on 8446; nothing to open on
  acme) and *active* (the agent connects to acme and nothing listens on the server; its jobs wait
  in the database, so either node of a cluster hands them over, and the agent fails over between
  the nodes).
- **Settings → Target agents**, a new pane: active mode (off by default - while off nothing of it
  exists: no port, no server of nginx, no firewall rule; on: nginx's server on its port, 8444,
  and acme's firewall lets it in on every node; off again: all of it taken away), the agents'
  state, the install package (signed with the release, its SHA-256 and the lines to install it,
  with copy buttons) and the agent authority's fingerprint.
- **The join**: a one-time code made on the target's card (an hour, once), `acme-agent join CODE`
  on the server, and the agent's fingerprint confirmed in acme by a full administrator - only then
  is its certificate signed (30 days, renewed over the channel by itself). A target switched off,
  deleted, forgotten or joined again is refused at once.
- **What a deployment needs, before it runs**: its form says for every file, command and script
  whether the agent's policy allows it - and the `acme-agent allow ...` line to run on the server
  where it does not.
- Events for every join, confirmation, refusal, renewal and policy change; alerts for an agent not
  heard from and its certificate ending; `acme --target-agent NAME show|code|confirm|look|policy|
  renew|forget`.
- The release builds `acme-agent-X.Y.Z.tar.gz` too, signed by the same key (inside acme's package
  and beside it in `release/`).
- **Target agents, phase 3 - keys made on the server**: a certificate used only on one server can
  have its key made there (*Key made by the agent, on the server*, or *Make a certificate with its
  key made here* on the agent's card): at every issue the agent's root side makes the key (or keeps
  the one in use, *Keep the key*), checks first that its policy allows the files that will hold
  it, and answers only the CSR; the deployment right after puts the key into those files itself
  (key-pem, traditional, DER, combined-pem, pfx/p12) - only for a certificate of that very key. acme
  never holds it. A certificate on several targets keeps acme's key, sealed to each agent.
- **Tests through the agent**: `allow probe HOST:PORT` / `allow probe local` in its policy lets a
  test (Certificates → Tests) connect from the server (TLS, or STARTTLS of SMTP, IMAP, POP3, FTP,
  XMPP, LDAP, PostgreSQL, MySQL) and send back the chain served; acme judges it as any test. The
  tests made from a deployment on an agent target go through it, at 127.0.0.1, by default.
- **The agent as a connector** (off by default): `allow connect HOST:PORT` lets SSH targets be
  reached through a passive agent (*Through a connector* offers it, marked) - a tunnel over acme's
  TLS connection to the agent, only to what the policy names. A passive agent itself can be
  reached through a Connector over SSH (`ssh -W`).
- **What happens** of an agent target: the signed job and the way it goes, the key made there,
  every file with its owner and mode, every command and script - each with the verdict of the
  agent's policy and the `acme-agent allow` line where it is missing.
- **Phase 4 - signed self-update**: acme says a newer agent is offered; with `allow self-update`
  a full administrator can send it (*Update the agent*, `acme --target-agent NAME update`): the
  agent checks MANIFEST and its Ed25519 signature against the release keys installed with it
  (install.sh now puts them beside it) and that the version is newer, then replaces itself.
- **Monitoring**: SNMP `acmeAgentTable` (ACME-MIB REVISION 202611161200Z), Prometheus
  `acme_agent_*`, the Zabbix discovery *Target agents* with its triggers, isemon / SIEM
  `action=agent_*` fields, and a new alert: **the agent's policy blocks a deployment** (until one
  goes through). The agent authority, the command key, the agents' states and their queued jobs
  come back with a backup and work on the other node (tested).
- Fixed (unreleased): files in the formats `key-traditional` and `key-pem-enc` went to an agent
  base64 under TLS only - now sealed to the agent like every other key format.
- (security) **Target agents, reviewed as an attacker would** (docs/target-agent.md, *Threat
  model*; each tried in `test/test_target_agent.py` Hunt*):
  - the agent never writes nor takes away its own places (its policy, `agent.json` with the
    command key it pinned and the `systemctl` its root side runs, its state, its program) nor the
    places whose files give root (sudoers, cron, systemd, PAM, `ld.so`, profile, `/etc/ssh`,
    `/root`, any `.ssh`, `/usr/bin`...) - whatever folder its policy allows: `allow file /etc`
    let a compromised acme rewrite the policy, or write into `/etc/sudoers.d`;
  - nor a file the policy runs (a script it allows, a path in a test's command line), and a file
    it writes is never executable - an allowed folder holding `check.sh` of `allow test -- /bin/sh
    .../check.sh` gave acme its own code run as root;
  - the policy and `agent.json` are believed only when root alone may change them and their
    folder, opened without following a link and checked on the open file (a group-writable
    `agent.json` was believed whole); a word of an entry it does not know (`mod=0600`, a typo)
    or one said twice now makes the line unread instead of allowing the default 0644;
  - a job whose time is NaN passed the five-minute check; a package of an update with endless
    entries was read whole into root's memory (now 256 entries at most); the copy kept of a
    file replaced carries no setuid / setgid bit;
  - an active agent pins acme's addresses only when acme proved them with the join code's secret
    (somebody between could have made it poll an address of theirs for good);
  - `allow from` turns others away before the TLS handshake, the passive port takes 64
    connections at once (a flood held a thread each), `TasksMax` on the network side;
  - in acme: what an agent says is one line wherever it goes (a host name with a line break wrote
    an event of its own making into Events, the SIEM and the log), `Infinity` / `NaN` and a
    malformed tunnel answer are refusals, not errors, and an agent asking for its certificate
    renewed is heard once an hour (it had one signed, and an event, at every poll).
- Fixed (unreleased): **target agents, tried end to end as the pages, the command line and the
  console use them** (`test/test_target_agent_ui.py`, `test/agents_page.js`):
  - every service preset (nginx, Apache, HAProxy, Postfix, Tomcat...) on an agent target failed -
    its form's preview with "the request is not in the shape this takes", its deployment with a
    TypeError (the SSH target's preset files were taken as a method of the agent's);
  - the new certificate's wizard with *Key made by the agent* showed the key file as a file acme
    sends and a Java keystore as allowed: its preview now knows the key is made there (the files
    that hold it marked, a format the agent cannot make it in refused); what the agent cannot do
    at all (a line of a shell - the Kubernetes preset) is a problem of the form, and its policy
    card no longer says "allows all of it" for that, nor for a form with no file yet;
  - choosing a preset with no test of its own (UniFi, Tomcat...) kept the test of the one chosen
    before ("doveconf -n") - every target with files and presets;
  - joining an agent again in the wizard waited forever for a passive agent (acme never reached
    it), and an active one was said to have joined before it had taken its certificate;
  - *Ask it now* on a passive agent with a join code made and not used (Join again… closed)
    answered "not here" for that code's hour instead of asking the agent;
  - an active agent's policy stays known: asked once it is heard from (just joined, acme started
    again) - its deployments' forms judged nothing until somebody pressed *Ask it now*;
  - `acme --target-agent NAME policy` left out `allow probe ...`; `show` says what the card says
    (its address, system, a join code waiting, tests from there, connections, updates, a newer
    agent, the policy blocking with its lines, the keys made there) with "1 folder", not "1
    folders"; the console has the agent's menu on such a target;
  - What happens of a key made there showed a made-up fingerprint (0000…); the job of a key made
    there said it in the agent's words ("made here - it stays on this machine");
  - a file the agent never writes whatever its policy says (under `/usr/lib`, `/etc/sudoers.d`...)
    was shown with "sudo <the reason>" to copy as if it were a command: now the reason, and no
    line (the UniFi preset's keystore in `/usr/lib/unifi` is such a file);
  - the agents' events of a target with a space in its name lost their `target` for isemon / the
    SIEM;
  - the agents' port could be set to a port acme already serves (its API, the sign-in with a
    certificate, the gate for SSH): nginx on every node, or the daemon, could not listen - now
    refused as the certificate sign-in's port is, both ways;
  - Settings → Target agents no longer jumps while it is asked; Czech for the agents' events and
    alerts, "tests from here", "connections", and "vytváří 2 klíče" (was "2 klíčů").
  - With no address set for the agents, an active agent was given this node's own name even when
    that was `localhost` - it would have polled itself; such a name is now skipped for the node's
    address. `acme-agent status` of an active agent no longer shows a listening port it does not have.

## 1.0.115 - 2026-11-16

- (security) **The card watched: "cannot be checked" no way out of the lock.** With *A browser
  that cannot be checked* = *Not watched* (the default), a sign-in whose card was out, or held
  because its page had stopped checking, was let out by one request of its own page saying "no
  picture" - and was never watched again; any first check without the card (no certificate,
  nginx refusing once, no cookie) left a sign-in unwatched for good, and a sign-in made before the
  watch was switched on, its person away with the card, went unwatched at its first check. Now
  only the page's "no answer at all" makes a browser *cannot be checked*, never for a sign-in held
  or whose card is out, only for one made while the watch was on; everything else is a card taken
  out. And it is no longer for ever: the page checks once a minute and when it wakes, and a check
  that finds the card watches the sign-in again. Under *Not watched* a browser can still opt out
  by failing every check from the first one - *Sign out, as a card taken out* is the setting that
  enforces the watch for every browser (an iPad then cannot be used with it). Sign-ins made before
  this version are taken as made before the watch was switched on.
- (security) **The card watched: whoever made a certificate rule stricter** (revocation, the
  matching, OCSP) kept their sign-in - and it was no longer watched: the card could be taken out
  for good. It is watched as any other now.
- (security) **The card's check answers this name's page only**: a page of a sibling host (the
  same site - its pictures get the session cookie too) could make a signed-in person's browser
  check the card and read the answer (signed in or not, the card in or out) - and, the card away,
  end or lock the sign-in. The check's picture is asked with its Origin now, and only
  `https://<this name>` is answered.
- **The card watched: nginx's own errors are no card taken out.** The checks shared the pages'
  limit (10 a second per address): behind a busy NAT, or with many tabs, nginx refused some with
  a 429 page - as a 502 while PHP restarted - and the page took the failed picture for the card
  taken out. The checks have a limit of their own now, and nginx's 429 and 5xx (and a daemon not
  answering) say "try later" - asked again at the next check. Off, nginx's server of the port is
  as before.
- **The card watched, an upgrade half way:** a page of 1.0.114 left open (or the nodes of a
  cluster upgraded one by one) asks its check without an Origin, got a 403 for it and was signed
  out. It gets a picture that says nothing now (the same for everybody - nothing asked, nothing
  renewed) and is told to load itself again; this version's page whose check fails asks once more
  without its Origin, so a node of 1.0.114 (no CORS) is still understood.
- **The card watched: a check left without an answer for 20 s** is taken as one that got no
  answer at all - an iPad may leave the picture waiting rather than fail it: *cannot be checked*
  under the same conditions, no longer always the card taken out.
- **The card watched: switched on from an iPad**, the administrator who saved it was signed out
  at once: their own sign-in counts as made while the watch is on (not watched, or signed out
  with *Sign out, as a card taken out* - the setting's help says so).
- **The card watched: a client the part's allow list refuses** got the checks' "try later" (200)
  once its checks were refused for their number - 403 now, as the rest.
- **The card watched, the kit's 4th edition** (isemon 1.10.356-358, found on Windows 10 + Chrome
  and an iPad):
  - **A policy header blocking the check** - an `add_header Content-Security-Policy` put into
    nginx by hand, or one of a proxy, balancer, WAF or Apache in front: a browser holds to every
    policy it gets, so one that does not name the certificate's port blocked every check, and
    every browser looked like one that cannot be checked (or, with *Sign out*, was signed out).
    The page now sees the browser's refusal and says so (`csp`): never the card out nor *cannot
    be checked* - an event and a warning on the card's facts. acme's own nginx sends no such
    header; the docs say every one must let the port's https picture in.
  - **Windows' "Insert a smart card" and the certificate chooser**: a check waiting over 4 s
    shows the countdown at once, behind the window (not after Cancel, up to 20 s later), and the
    server is told (`waiting`) - the card out only for a browser already proven to be checked,
    never *cannot be checked*; for one not yet proven the notice goes again. Under the countdown:
    *put the card back and press OK there - not Cancel* (after Cancel Chrome and Edge offer no
    card to the port until restarted).
  - **A change of the mode** (off, signout, grace) starts every sign-in's count afresh - a time
    out counted under grace no longer ends a sign-in at once under signout, nor an old one after
    switching off and on - and root is asked for nginx's lines at once.
  - **No word of a failed check** (neither *cannot be checked* nor the card out) before root has
    confirmed the port serves the watch - right after switching on, the port's 404 judged the
    browser for good.
  - **A held sign-in** (the card out, its page asleep): whoami and the portal's `me` give nothing
    of the person (no full name, preferences or columns); the second step's question and the
    portal's password change are refused (423) as the rest.
  - **The sign-in already ended on the server** (its tab asleep): the page says why and tries
    neither the certificate nor Windows by itself (before: it just loaded itself again).
  - **A page opened by an IPv6 address** lets `https:` in for pictures - a CSP takes no `[v6]`
    address, and every check was blocked.
  - **The iPad**: "cannot be checked (as an iPad cannot)" was the kit's mistake (the CSP header
    above); the page's words, the setting's help and the docs no longer name the iPad - *A
    browser that cannot be checked* stays as a safety net. With the watch off nothing changes.
- **The card watched: the port given to another program** (a WAF's agent listening there, or
  nginx unable to listen on it) was taken as serving the check - root's last run had applied
  what was wanted, only without the port - and every browser's failed picture judged it: the
  card taken out (or, with *Sign out*, signed out), or *cannot be checked*. No word of a failed
  check is taken while root says the port is not nginx's (or is another one).
- (security) **The card watched: *A browser that cannot be checked* made *Sign out*** - the
  setting that enforces the watch for every browser - left the sign-ins found not checkable
  under *Not watched* unwatched until their idle time ended them. They are watched again (said
  in Events): their next check without the card signs them out; the sign-in of whoever saved it
  stays as it is.
- (security) **A sign-in held for its card** (the card out, or its page no longer checking) is
  no longer told the details of an error (a domain controller's name and its TLS, the database's
  address) - as a sign-in without its second step has not been since 1.0.149. With the watch
  off nothing changes.
- **The database's own trouble** (the alert, `acmeDbTrouble`) counts SQLite's *file is not a
  database* and *database disk image is malformed*; MariaDB's read-only, table full, out of
  memory, disconnected for inactivity and out-of-sync errors; and PostgreSQL's by its SQLSTATE
  (the connection, resources, a shutdown or a cancelled statement, system and internal errors, a
  deadlock, a lock not to be had, a standby) - no longer every error its driver files as
  operational or internal (a constraint, a missing column).
- **SNMP: the newest backup on a cluster with one database** is the cluster's (any node's, or
  the night's), not the node's own - the node that did not make the night's copy said "no recent
  backup" for good. **The CRL table's rows** are numbered by the whole address, not its first 255
  characters.
- **The card's notice over a popup**: Escape closed the popup behind it (or asked *Leave it?*
  under it) and Tab went round the popup's boxes - nothing behind the notice answers now, and the
  focus goes back where it was (the box half typed in) when the card is back. Its seconds agree
  with the number (*1 second*; in Czech *1 sekunda, 3 sekundy, 30 sekund*). The card's events,
  the reasons a check came without it and the lockout of sign-ins with a certificate are in Czech.
- **Settings -> Accounts and Portal ask nothing while left alone again**: with a node not
  listening on the certificate's port, every visit asked the Kerberos and certificate cards
  every 3 s for a minute (1.0.105 asked nothing). Only a change made on the page - or what is not
  settled having changed since the last look - watches the nodes now.
- **Settings -> Firewall without a database agent** no longer asks for the database servers every
  few seconds: the answer "none" is kept for 10 minutes.
- **Smaller things on the pages**: the database server's load on its card with the page's decimal
  mark (*0,52 / 0,48* in Czech); the note of the DNS set *Public* in the page's language while it
  is as shipped; the password policy's switch no longer jumps 118 px up (the open *With SSH keys*
  paragraphs above it closed at each redraw); on a phone, scrolling a popup to its end no longer
  scrolls the page under it.
- **The card's notice on a low screen** (a phone on its side, a small laptop window): taller
  since its hint about the card's window, it was cut off above and below and could not be
  scrolled - *Sign out* out of reach. It scrolls in itself now, and its ring is smaller there.
- **Settings -> High security**: an exception switched in the open *Kept as high security wants
  it* list closed the list - the page under the pointer jumped up. It stays open.
- **Settings -> Accounts, *Ask an OCSP responder*** in Czech: its choices *first* and *only*
  were in English, and the note under *Own OCSP responder* said *"off"* - in the page's language
  now, as its list shows them.

- **"The database is in trouble" says something again**: since the RADIUS server was taken out
  nothing wrote down the database's own trouble - the alert, `acmeDbTrouble` and the Zabbix trigger never
  fired. Every statement of the daemon that fails with it (locked, full, gone, a lock or a statement
  that ran out) is now written down; it leaves the health row 5 minutes after the last one. A
  statement's own mistake (a column that is not there) is not counted.
- **Look a person up for a certificate**: the openssl request has exactly the values of the
  directory - `' " # $ \` in the CN, the UPN or the address were taken away, cut the line off or
  failed it (escaped now); a value with a line break makes no request (said why); certreq's INF
  leaves out a SAN whose UPN or address holds `&` or `"` (it split or ended it) and says so.
  `DOMAIN\name` is checked against the directory's own domain (NetBIOS name or DNS name, any
  case) - another domain's name is refused in words (it was looked up without its domain), on the
  Kerberos card's service account too. A UPN or an address with `+ / =` is taken. A CN with
  `\0A`-style escapes in its DN is read as the characters; the YubiKey's `ykman --subject` escapes
  the CN for its parser and the shell.
- **The Kerberos card**: the domain's names that could not be read are said "unreachable" or "not
  readable" as they failed, also from the 5-minute memory (it said "not readable" for both).
- **SNMP**: the rows of the tables of the alerts, the certificates of the pages, the nodes, the
  metrics, the disks, the places of the backups, the CRLs and the log shipping are numbered by
  what names them (CRC-32 of the name, the path, the URL), no longer by their place in the list -
  a disk or a node that comes or goes no longer gives its number to another, and Zabbix's history
  of a row stays that row's (the OIDs are the same, only the index values change: a template's
  discovered items are found again once). The node table's columns all come from one list.
  `acmeBackupAge` with no backup ever made: the time since acme started (was 0 - "No recent
  backup" never fired). `acmeReplState` says `down(4)` when the nodes are replicated and neither
  the subscription nor the slot is there (was 0, "not replicated"), with a Zabbix trigger
  *Replication down*. ACME-MIB revision 202611160000Z.


- (security) **The database agent: the side that faces the network never sees a node's signing
  key.** At a join the finish carried the node's signing key (and the join code's secret) in
  clear through the agent's unprivileged network side - one taken over could keep it and ask
  root as that node (any operation of the closed set). The agent now has a key pair of its own
  (root's, `enroll.key`), its fingerprint in the join code (`k`); the node checks the key the
  agent gives against it and seals the code's secret, its signing key and its certificate's
  fingerprint to it (RSA-OAEP, `openssl`). A join in clear is refused (*sealed to its own key*):
  **upgrade the agents** (`./install.sh --db-agent` on each database server) together with acme;
  a code of an older agent is refused by the node (upgrade it, then make a new code).
- (security) **One database server, one cluster's TLS.** Two nodes of two authorities joined to
  one agent each put their own certificate into the server (Database -> TLS, and its renewal by
  itself), the second replacing the first's and `/etc/pki/acme/ha-ca.pem` - the first's
  verify-full failed. The agent remembers which node (and authorities) put the server's
  certificate in; a node of another authority is refused, the refusal says whose it is; the same
  authority (the other node of that cluster) and a node renewing its own may. And a node takes
  only itself off the agent's list (`clients drop` of another node is refused). Which authority
  a node is of is the one that **signed the client certificate it asks with** (checked with that
  authority's key) - not the authorities it lists, where `trust` (and the join) take any: a node
  listing the owner's authority beside its own got through. A join under the name of a node of
  another authority heard from in the last 30 days is refused (it took that node's place); the
  node joining again may. With no owner recorded (the first certificate after the upgrade) the
  node putting it in becomes the owner. **A cluster's authority rolled** no longer splits the
  cluster: the agent knew a node's authorities only from its last client-certificate renewal, so
  after a roll the other node's certificate renewed under the new authority was refused as
  *another cluster's*. Each node now tells its agent its cluster's authorities again (`trust`,
  no new certificate) whenever they change - the daemon looks every 30 s and at once after a
  roll here; and a node once let in with a certificate of the owner's authority (the agent keeps
  every authority it checked, `issuers_seen`) is the owner's cluster. A node's own list still
  counts only for itself. A node that joined its agent standalone and then a cluster
  (`--ha-join`, layout B) tells the agent the cluster's authority at the end of the join - its
  next join was refused as *another cluster's*; one refused from the address it joined from is
  told its authority changed and to `--forget NODE` on the database server first.
- **Layout B (each node its own database server): this node's own address, not its database
  server's.** `ha_address` is the node's database server there, yet keepalived was told it as its
  own address (`unicast_src_ip`), the other node's firewall let it in instead of the node, and the
  other database server's clock was taken for the other node's. The node's own address is kept in
  `agent.json` at `--ha-setup` / `--ha-join` (`node_address`; worked out toward the other node for
  a cluster made before); the clock is said as *the database server of NODE*. The network job
  moving the node to another address updates it, and one the machine no longer has is not used
  (the address toward the other node now is) - keepalived and the other node's firewall stayed
  on the old address.
- **Layout B: the agent is not forgotten while the replication runs through it** - *Forget the
  agent* is gone from the card there, and `acme --db-agent-forget` / the API refuse it (as joining
  another agent does): forgotten, the other node fell back to the other database server. Only
  layout B: two nodes on one database server (a shared pair) may forget it.
- **The agent waits for no node gone for good.** A node forgetting the agent, moving its database
  off its server, joining another one or leaving it (`acme --db-agent-leave --yes`, refused in
  layout B) now tells it (`leave`) - `install.sh --uninstall` keeps the join, as it keeps
  `/var/lib/acme`, and says how to leave; one not heard from for 30 days is no longer waited for
  (a node enrolled before the agent kept when it was heard from counts as heard from at the
  upgrade, not as gone) before the agent switches to
  its next certificate, and is listed (*Not heard from* on the card, `acme --status`,
  `acme_db_agent.py --status`). The alert on the agent's certificate says what it does by itself
  (*switches by itself 7 days before the end*) and comes only when that did not happen.
- **One node's long operation no longer makes the agent look dead to the others**: the agent
  answers several requests at once - a restart or a certificate (up to 240 s) for one node, the
  other nodes' looks meanwhile (and `status` says *busy with pg_restart for acme1*). When its
  listening side starts again (a node joined or left, new authorities, its next certificate)
  it goes on answering everybody until what root works on is answered - it answered 503 to
  everything for up to 300 s - and lets a node that just joined in at once; the listening socket
  is root's, kept across, so connections wait for the next side instead of being refused. A stop or restart of
  the service waits for the operation under way (300 s at most, `TimeoutStopSec=360`) instead of
  cutting it off; root works on 16 requests at most at once. The side ending waits for the
  connections it took (a slow client's request was cut off when it returned), an answer from a
  root before 1.0.115 (no request id, the program upgraded under it) ends it at once instead of
  every request waiting 900 s, it sets `PR_SET_PDEATHSIG` again after giving root up (`setuid`
  cleared it: root killed, the side lived on), and a side already ended is never signalled by its
  old process number.
- **A node with several addresses** is let into its database server (pg_hba, the firewall, at
  the join, `dbmake`, `pg_prepare`) by the address it reaches that server from, not the one it
  reaches the outside with.
- **The agent's version: its program compared, not a number.** The agent says the sha256 of its
  program (`acme_db_agent.py`, `acme_pg_ops.py` and the root helper `acme_web.py` it runs) and
  each node compares it with the one it ships: an acme release that did not change
  the agent no longer asks for an upgrade, a newer agent says to upgrade acme (not the agent),
  and nothing is bumped by hand at a release (the agent's version is the one `install.sh` wrote
  beside it).
- **`install.sh --db-agent` run again (an upgrade) prints no join code** - only a new install or
  `--new-code` does: a code is a key to the agent, and the nodes stay joined. `--new-code`
  without `--db-agent` / `--db-server` is refused with what to run.
- **This machine's database as a database server** (Settings → The database, *Show this
  machine's database as a database server*, off by default): PostgreSQL or MariaDB on the same
  machine as acme gets the card *Database server* above *Encryption to the database server*, as
  a server with acme-db-agent does - a tile for each node's own (in a pair with each node its own
  PostgreSQL, acme1 and acme2; a shared pair, its one server): the engine and its version, the
  address, running and for how long, TLS and its certificate's end, the connections, the data's
  disk and the RAM as bars, the processors and the load, up for, the state and when it was last
  heard from. Each node looks at its own every 30 s with its own connection and /proc, and tells
  the other in its row of the database (`dblocal:node:NODE`) - no agent, nothing more opened or
  allowed. Actions only those acme has for a database here: *Look now*, *Renew the certificate*
  (the one acme gave PostgreSQL - the link's between the databases or Encryption to the database
  server's, the same steps as there), *Restart the database…* (for the
  server's own settings waiting for it, where install.sh let acme restart it). Off, nothing of it
  is read, written or drawn, and `GET /api/db-agent` is as it was (`local` only when on).

## 1.0.114 - 2026-11-16

- **Signing in with a certificate - the card taken out, as the kit "card-removal-watch"** (its
  merge notes; docs/certificate-sign-in.md, *The card taken out*). Off (the default) changes
  nothing: nginx's server of the certificate's port, the pages' policy (CSP) and every answer are
  byte for byte as before. Fixed against 1.0.113:
  - **Two nodes, a restart**: the state of the watch is in the sign-in's own row (`card_seen`,
    `card_out`), nothing in a daemon's memory and nothing in `meta` (1.0.113 kept a note of each
    ended sign-in there - tidied away): either node answers a check, a restart forgets nothing.
  - **A failed handshake** (the usual card taken out: nothing to sign with) is said by the page
    over 443: the events say why, and with *Lock, wait for the card* the server answers nothing
    of the sign-in (HTTP 423, code `card` - not only the page covered) until the card is back;
    whoami gives it no role meanwhile, so the pages' own PHP gates (an upload, a new version)
    refuse it too.
  - **One lost connection is not a card taken out**: a check that got nothing is asked once more
    after 1.5 s (was: twice, 3 s apart); a check with no answer for 20 s counts (was 8 s).
  - **Kind to the card**: one check at a time, one for all the tabs of a browser, out: every 5 s
    and 10 s after a check that waited on a window of the card's (was every 3 s, whatever the last
    one did) - Windows' "Insert a smart card" no longer comes back again and again.
  - **The reason is never in the address**: *Signed out: your card was removed* came from
    `?certsaid=removed`; now a word of the tab's own (out, late, other) with the sign-in page's own
    sentence - *Signed out: the card you signed in with was taken out.* / *...was not put back in
    time.* / *...another card than the one you signed in with was offered.*
  - **Asleep is not out** (an iPad's screen locked, a browser in the background): a page that
    stopped checking has its sign-in held (423) until a check finds the card - not signed out
    after two minutes; the page checks the moment it wakes (visibilitychange, pageshow, focus,
    online). *No check of the card for* (`*_certlogin_card_stale`) is no setting any more - still
    taken by `--set`, a configuration or a backup, and left out.
  - **Switched on while the pages are open**: a sign-in made with a certificate keeps its card's
    fingerprint (only that) whatever the setting, so switching on watches it instead of ending it;
    its page learns it within a minute and loads itself again (or says so, with changes not
    saved). Sign-ins made before 1.0.114 end as before.
  - **The check is a picture** (`<img>`, its width the answer: no CORS, nothing for another site to
    read; another site's picture refused), let in by the page's policy (`img-src`) only for a
    watched sign-in - `connect-src` is `'self'` again.
  - **The notice** (design B): the seconds left, large, in a ring that empties - drawn every second
    (was: at each check) - *Put the card back*, *Signed out in N s unless the card is back*, *Sign
    out* in red; the page behind it inert. Back in time: the notice goes and the page goes on
    where it was (was: loaded again). The first check 1.5 s after the page loads.
  - **The port's nginx** drops every `ssl_session_*` line it inherits (a ticket key too), not only
    the three it knew. Measured with `openssl s_client -reconnect` (TLS 1.2: every handshake new)
    and `-sess_in` (TLS 1.3: no ticket) on a real nginx, once a reload has settled (`nginx -s
    reload` is asynchronous - docs).
  - **The settings**: *When the card is taken out* off / signout / grace (1.0.113's `lock` still
    taken, and a saved one read, as grace); *Check the card every* 5-300 s (15; was a choice of
    5-60, 10); *The card put back within* 5-600 s (30; was 15-600, 60). The card's facts say *When
    the card is taken out - a notice, then signed out unless it is back within 30 s (checked every
    15 s)*. The help and the docs say what to know: an iPad, Windows' "Insert a smart card", a
    YubiKey with touch or PIN policy *always*, the Group Policy *Smart card removal behavior*, a
    load balancer only as TCP passthrough.
- **The card taken out - a browser that cannot be checked (an iPad)**, as the kit's 3rd edition
  (isemon 1.10.355; docs/certificate-sign-in.md, *A browser that cannot be checked*). Found on a
  real iPad: Safari on iPadOS signs no connection for a page in the background - the card is in,
  yet the check never comes, and the iPad was signed out at its first check, every time.
  - A sign-in keeps whether a check **in the background** has ever found its card in this
    browser (the sign-in itself does not count). Until one has, a check without the card means
    *this browser cannot be checked*: with the new setting *A browser that cannot be checked*
    (`admin_certlogin_card_unable`, `portal_certlogin_card_unable`; shown while the card is
    watched) at **allow** (the default) that sign-in is not watched from then on - an event says
    so and why, the page stops checking and says *This browser cannot have the card checked (as
    an iPad cannot): this sign-in is not watched.*, whoami gives it no `card`, and it is never
    held for its card (423), asleep or not; at **signout** it is signed out as a card taken out.
    Once found, a check without the card is a card taken out, as always. The card's facts say
    which.
  - **No cookie with the check** is said as such: the port's picture is 6 px wide (was a 403,
    which looked like the card out) and the page tells the server over 443, where its cookie
    comes; *this browser cannot be checked* is 7 px (acme's 3-5 px were taken already - the kit's
    3 and 4).
  - **The events name the reason** of a check without the card: *no certificate came with the
    check*, *the browser sent no cookie with the check*, *the check got no answer at all (the
    browser did not sign the connection)* (the page's `cert-lost` now says which - `why`).

## 1.0.113 - 2026-11-15

- **The database on a server of its own, looked after as one on the same machine**
  (docs/external-database.md). A small agent on the database server, **acme-db-agent**, does
  there what the root helper does on acme's own machine - the database's certificate from
  acme's authority and its renewal, `pg_hba.conf`, `ssl`, the settings and the restart, the
  replication's settings and log, the database and its account for a move, the firewall for
  the database's port - and nothing else: a closed set of operations, over HTTPS (the agent's
  own certificate pinned by every node, each node's client certificate enrolled by its
  fingerprint), every request signed (HMAC, time, nonce), its network side a program of its own
  under an account of its own that never holds a signing key, an audit log (refusals too). Without it nothing changes: every path
  is the one it was, nothing new runs, nothing new is said.
- **Two layouts**: one acme server with its database on a server of its own (PostgreSQL or
  MariaDB), and **high availability with two database servers** - acme1 on db1, acme2 on db2,
  db1 and db2 replicating both ways, set up, encrypted (verify-full, `hostssl`) and watched by
  acme as today; the VIP address, the leader, the split handling are the nodes' own as ever.
  Replicated HA stays PostgreSQL 16 or later.
- **Joining an agent**: `acme --db-agent-join -` with the code pasted on its standard input
  (or in `ACME_DB_AGENT_CODE` - never on a command line; printed on the database server, one
  hour, the agent's certificate pinned by it); `acme --db-agent-status`, `--db-agent-renew`,
  `--db-agent-restart`, `--db-agent-mariadb-tls`, `--db-agent-forget`; `--ha-setup --ha-peer
  DB2 --ha-peer-node ACME2` for the replicated pair. Several nodes may join one agent. The
  agent renews its own certificate (the next one announced to every node 60 days before the
  end, put in use once every node took it in); the node's client certificate is renewed by
  itself 45 days before it ends.
- **Watched**: an alert when a node's agent has not answered for 90 s, or answers while its
  database does not; Prometheus `acme_db_agent_up`, `acme_db_server_up`; a line in
  `acme --status`; the database servers in the meter of the header (`/api/load` →
  `dbservers`), on High availability and Database → TLS (`dbservers`, shaped as the nodes'
  dots with `kind: "db"`); `GET/POST /api/db-agent`.
- **`install.sh --db-server postgres|mariadb [--acme-node ADDRESS ...]`** on the database
  server: PostgreSQL 16 (EL 9/10 AppStream or PGDG, Debian/Ubuntu PGDG or Ubuntu 24.04's own)
  initialised, started, listening, `wal_level = logical`, the database and the account, the
  nodes let in (pg_hba, firewalld); or MariaDB, secured, the database and the account; then
  the agent and a join code. `--db-agent` for the agent alone, `--uninstall` with either takes
  the agent away (the database stays). `--dry-run`, and safe to run again. The usual install is
  not changed.
- **The database servers on the pages.** *Settings → The database → Database server*: where
  this node's database is (the agent's server, still this machine, another server), a tile per
  database server (engine and version, running, TLS, connections, the data's disk and RAM,
  processors and load, up for, the agent's version and certificate, this node's client
  certificate, last heard), *Look now*, *Renew the certificates*, *Restart the database…*,
  MariaDB's *Turn TLS on*, *Forget the agent…*. **Connect a database server…**: a three-step
  popup - the commands for the database server with this node's addresses filled in and copy
  buttons, the join code checked as it is pasted (the agent's address, engine and certificate
  said), the agent's address and *Use it as this node's database*, then the join and the
  server - and *Move the database onto it…*.
- **The database servers' dots** on the cards whose settings reach them (Database → TLS, the
  link and replication, the server's own settings, the firewall's database port), each with
  what its agent said; none on the other cards. **High availability** lists the two database
  servers - the direction each sends in, what waits to go over, the link's TLS, its agent - and,
  in *Making it two*, the commands for each node's database on a server of its own
  (`--ha-peer` the other database server, `--ha-peer-node` the other acme node).
- **The meter in the header** has a row for each database server (`db1`, or `db · acme1`) in
  the same look, its database on hover: version, connections, what waits to go over, the size.
- The alerts of the database agents in good words, in the mail's language too; MariaDB's
  certificate from acme renewed by itself through the agent 45 days before it ends.
- Nothing of it is drawn without an agent: the pages are as they were (a page test compares
  the DOM).
- **Reviewed before the release** (the agent's security and what it touched):
  - `acme --db-agent-*` read config.json before opening the database: they opened the
    defaults' SQLite file - on a node already on PostgreSQL or MariaDB a new one, with an
    authority of its own written over `/etc/pki/acme/ha-ca.pem`, the certificates issued from
    it, what was written lost. `acme --db-move` had the same fault from before: it moved the
    defaults' `acme.db`, not the database config.json names (from MariaDB, PostgreSQL or another
    SQLite file the move carried an old or empty file over it).
  - A second node joining an agent locked the first out (its certificate for the agent
    replaced the one the first pinned, its authorities replaced the first's). The agent now
    answers every node with a certificate it made itself, renews it itself with an overlap
    (the next one announced in the signed `status`, pinned by each node, put in use once every
    node took it in), and lets a node in by its client certificate's fingerprint; each node's
    authorities are its own - `trust` changes the asking node's only, refuses an empty set and
    one its current certificate would not pass.
  - The side of the agent that faces the network is a program started afresh (not a copy of
    root's memory) and never holds a signing key: root works the fingerprint out of the
    client's certificate itself, checks the signature and signs the answer.
  - `install.sh --db-server postgres` wrote `pg_hba.conf` with `cp`/redirects in a folder of the
    postgres account (a link put there made root write over any file): now through the agent's
    link-safe code. Passwords are no longer on command lines (psql and mariadb read the
    statement on standard input, not logged, masked under `--dry-run`); `--db-password-file`.
  - Wrong join codes no longer burn every code alive: counted per address (ten an hour), and
    against a code only when its id is right; failures do block an address for a while (they
    never did). A finish belongs to its own begin (a token).
  - The agent is asked only when this node's database IS the one on its server - an agent
    joined while the database is still on this machine leaves every path the root helper's.
  - A node's new address (the network job) is let into its database server and its firewall
    through the agent before the network changes, and the other node's agent lets it in too.
    The join opens the agent's firewall to the node; without `--acme-node`, `install.sh` prints
    the `firewall-cmd` lines for the agent's port and the database's.
  - Layout B: what is the nodes' own (the clocks' peers, the addresses the firewall always lets
    in, the VIP's other node, the split's look at the other machine) takes the other acme node
    (`--ha-peer-node`), not the other database server (`ha_peer`).
  - The nonces seen are kept across a restart of the agent; an alert 14 days before the node's
    client certificate ends; the agent's version compared with acme's (card, `--status`, an
    alert: upgrade it with `install.sh --db-agent`); `--ha-join` says the agent does not answer
    instead of "install PostgreSQL there"; `pg_prepare` says `pg_restart_needed` (its
    `restart` was read as the agent's own restart).
  - `acme-db-agent.service`: `ProtectSystem=strict` with the folders it writes,
    `PrivateDevices`, `RestrictAddressFamilies`, a `CapabilityBoundingSet`; the network side
    runs as `acme-db-agent` (made by `install.sh`), never `nobody`.
- **Moving between engines with the database servers' agents** (docs/external-database.md,
  *Moving between engines*): PostgreSQL on an agent's server → MariaDB on another agent's and
  back, onto this machine's PostgreSQL / MariaDB or SQLite, from the wizard and `acme --db-move`.
  **One agent a node**: joining another replaces the one there was (`agent.json.replaced`, and
  said when the database is still on its server; refused for a node of a cluster whose
  database is there); a move off the agent's server lets the agent go (`db_admin` local,
  `agent.json.forgotten`, said in the move) - nothing is asked of it afterwards and its server
  leaves the cards and the meter. *Make the database and the account for me* in the wizard on
  the agent's server too (it was refused off 127.0.0.1), `acme --db-move ... --db-make` on the
  command line (this machine's root helper or the agent; the password made up unless given).
  - `acme --db-move` no longer carries `db_tls` / `db_tls_ca` to another database server: a
    move from a verify-full PostgreSQL to a MariaDB without TLS wrote verify-full into
    config.json and ran in the clear; the next step (Database → Encryption) is said.
  - A MariaDB connection asked for TLS is refused when the server does not offer it (PyMySQL
    went on unencrypted, the daily dump failed).
  - The old server's rows (its certificate from acme's authority, its agent's last word, the
    meter's reading) are not carried into the new database.
  - The wizard opened from the database server's card is filled in with the database's own
    port there (it was 5432 - another server - when the server had not been looked at yet, and
    3306 for every MariaDB).
  - The move's refusal on a node of a replicated cluster with each node's database on a server
    of its own says so.
  - `acme --db-agent-join CODE` (the code as an argument) warns that every account sees it in
    `ps` - paste it on standard input: `acme --db-agent-join -`. A request to an agent that
    never left (a reset, the old certificate answering for a moment after the agent restarts
    its listening side) is sent once more. The alert of the agent's certificate says it renews
    60 days before its end (it said 45). The reply signature in the docs is the code's (the
    body's SHA-256 as raw bytes). High availability's node settings no longer make the pane
    wider than a phone's screen (the cells' buttons go under their value).
- **Signing in with a certificate: the card taken out signs you out** (or locks the page) -
  per part, *When the card is taken out*: **Off** (the default - nothing of it runs, nginx's
  certificate port is as it was), **Sign out at once**, or **Lock, wait for the card** (the page
  covered, a countdown, nothing of it answered until the card is back within *The lock waits
  for the card*, 15 s to 10 minutes; signed out after it). No browser tells a page a card was
  taken out, so the page proves the card every few seconds (*Check the card*, 5-60 s) with a
  request of its own to the certificate's port, where nginx - only while a part watches the
  card - resumes no TLS session and keeps no connection, so each check is a full handshake the
  card's key signs; it must be the same certificate the sign-in was made with. No good check
  for too long (*No check of the card for*: by itself three missed and 30 s, two minutes at
  least) and the server ends the sign-in - a tab closed, a computer asleep. The sign-in page
  then says *Signed out: your card was removed*. Only sign-ins made with a certificate are
  watched; switched on, the ones made before end. `acme --set admin_certlogin_card_watch=lock`
  and the others as any setting. docs/certificate-sign-in.md, *The card taken out*.

## 1.0.112 - 2026-11-15

- **Revocation lists (CRL): the columns in proportion.** The address took every free pixel and the
  "Issued by" of a list not fetched yet was a whole DN wrapped over four lines; the address has
  its share, the authority is shown by its name (the whole DN on hover).

## 1.0.111 - 2026-11-15

- **Values for a person's certificate: room around "Make a CSR…".** The heading "What to put into the
  request" and its button sat right on the box above and below; they have their space now.

## 1.0.110 - 2026-11-15

- **Look up a person for their certificate**: *Look up a person…* on the card *Signing in with a
  certificate* (the administration's and the enrolment pages') finds an account in the directory
  (`novak`, `DOMAIN\novak`, a UPN or an e-mail address) and shows what goes into their
  certificate request, each value with its own Copy button: the CN, the UPN of the SAN (otherName
  msUPN), the SAN URL of the strong mapping `tag:microsoft.com,2022-09-14:sid:<SID>`
  (KB5014754), the SID, the sAMAccountName, the DN and the mail; whether the account is enabled,
  locked or expired, the role it gets here (or whether the portal lets it in), whether a
  certificate from AD CS and one with the SAN URL only would sign in and under which *Which
  account* mode; and the request itself for openssl (a `.cnf`) and certreq (an INF). Read only,
  for a certificate administrator; written to the events. `acme --cert-login-lookup NAME [--part
  admin|portal] [--json]` the same (docs/certificate-sign-in.md).
- **Make a CSR… in the browser**: from the person found, a second popup with the key (RSA 2048 by
  default, 3072, 4096, ECDSA P-256, P-384), the subject and the SAN filled in from AD (the UPN, the
  strong-mapping URL, the mail, a DNS name - each ticked or not) and the key usages (Client
  Authentication and Smart Card Logon ticked); the key pair is made by the browser (WebCrypto) and
  the request written and signed in the page - the private key never leaves it - and both are
  downloaded: the `.csr` and the `.key` (PKCS#8, encrypted with the passphrase typed, or not when
  so ticked). For a smart card or a YubiKey it shows the commands that make it on the card.
- **The Kerberos card's commands use the domain's real NetBIOS name**: `setspn` and `ktpass
  -mapuser` said `MERIT\svc-acme-http` for `merit.cz` where the domain is `MERIT_NT` - the name is
  now read from the directory (the domain's crossRef: nETBIOSName, dnsRoot), and where it cannot
  be read the card says it is guessed. The service account can be typed on the card and checked in
  AD: its UPN, AES 256 allowed, password never expires, its SPNs (docs/kerberos-sso.md).

## 1.0.109 - 2026-11-15

- **The Zabbix 7.0 template, tried on a real Zabbix 7.0.32** polling a running acme over SNMPv3:
  it imports (a real server refused it before: the walk of the certificates was longer than
  Zabbix's 512 characters - the table is walked whole now), every item and discovered item gets
  values, none is *not supported*, the triggers fire as they should and none stays *unknown*
  (docs/monitoring.md, Zabbix).
- **Its dashboard puts the certificates first**: *Certificates* (counts, each certificate's days
  left and state, its problems with owner and source), *Deployments and tests* (each deployment
  and test by its result, their problems), *Authorities and CRLs*, then the system, the cluster
  and backups, sign-in. Tiles plain, red or orange only when something is wrong; graphs in the
  colours of the states.
- **Its problems say one thing once**: a certificate expired, expiring within 7 or within 30
  days - one of them at a time; *renewal failed* also for a certificate not renewed by itself;
  a failed deployment or test a problem of its own (not again on its certificate), a test's
  warning and a failing module only information; SELinux not looked at yet (unknown) no longer "not enforcing".
  Value maps in words (*pending approval*, not *pendingApproval*); a deployment's target tagged
  `deploy` (the template's `target: acme` took the name).

## 1.0.108 - 2026-11-15

- **A Zabbix 7.0 template, and SNMP says all the pages say.** *Settings → Monitoring → SNMPv3*
  has *Zabbix 7 template* and *ACME-MIB* to download (any role - nothing secret; also `acme
  --snmp-zabbix-template --out FILE`, `acme --snmp-mib`). "acme by SNMP" is made from the MIB
  each time: SNMP walks with everything dependent on them, eleven discoveries (certificates,
  deployments, tests, modules, authorities, the pages' certificates, nodes, file systems, backup
  places, CRLs, log destinations) with item, trigger and graph prototypes, about 75 triggers
  (a certificate ending within `{$ACME.CERT.WARN}` / `{$ACME.CERT.CRIT}` days - per certificate
  with a context -, a renewal or deployment failed, a test failing, a node down, the replication
  lost or behind, the nodes apart, no recent backup, a newer acme, the keytab or a CRL...), value
  maps for every state, tags, the traps, and a dashboard of five pages (docs/monitoring.md,
  Zabbix). ACME-MIB gains, without moving anything: `acmeSystem` (disks, CPU, load, memory,
  disk and network bytes, the clock, SELinux, the firewall, the updates of the system),
  `acmeBackup`, `acmeSignIn` (accounts, sessions, lockouts, Kerberos keytab, certificate
  sign-in and its CRLs), `acmeServices` (isemon and syslog, the mail queue, directories, SMS),
  `acmeDnsServer`, more of the cluster (VIP holders, replication, split, each node's version and
  role) and of the database (size, guard), each alert's level, node and area, a certificate's
  owner, last renewal, failures, error and serial, every state as a number with a textual
  convention, conformance groups. Prometheus has the same new facts. The MIB loads in net-snmp
  again: two comments ended early (`--`) and `snmptranslate -m +ACME-MIB` stopped at them.
- **A popup is as tall as what is in it, and stays so.** Some popups grew and shrank by
  themselves: *Targets → Add a target* with a module picked from the list scrolled down (the
  Barracuda WAF's form) had over a hundred pixels of nothing above its buttons and lost it a few
  seconds later, a few pixels up and down again on every refresh of the page; a part of a popup
  waiting for its data kept its old height for four seconds. What keeps the page from jumping
  under the reader (1.0.105) no longer keeps room or a height in a popup or anything else that
  floats over the page, holds what was clicked in a popup rather than its whole body, and measures
  it within the popup, not on the screen where the popup moves as it is centred again.
- **Root's SSH keys are only shown on the pages.** *Settings → SSH keys* for root lists the keys
  of `/root/.ssh/authorized_keys` on every node and exports each, and no longer makes, adds or
  takes one away: a note says to change them on the server itself. The pages' API answers 403 to
  such a change (the command line's `--api` too), the daemon asks none of the nodes, and each
  node's root helper refuses one whatever asks it - a row of the database, signed or not, or a
  file laid in its folder. Keys of root made on the pages before stay in the file; a node built
  again on another machine no longer puts them on again - its page says their fingerprints.
- **A key for a normal user is made as root's was.** The card *A key for USER* has *The key for*
  in a cluster - the same key on every node the user is on, or only on one node - with the words
  and the Ed25519 / RSA 4096 choice root's had; *Add a key* and taking a key away as before, on
  the nodes chosen. Still only for users who may sign in (UID 1000 and up, a login shell), their
  file written as they are, never through a link.
- **The cards of signing in follow a change without F5.** *Signing in with Windows (Kerberos)*,
  *Signing in with a certificate* and *The sign-in page* (*Settings → Accounts* and the portal's)
  look again by themselves for a short while after a change: what the nodes do next - nginx taking
  the certificate's port a few seconds later, or finding it taken, the keytab and the authorities
  written out on the other node - shows on the card, where it stayed *not listening* until the
  page was opened again. A keytab put in or taken away also brings the certificate's card the new
  facts of Windows (and an authority Windows'), each card's *No password at all* with them; an
  older answer no longer draws over a newer one; and *No password at all* coming into effect or
  going reaches *Users* (*Set a new password*, *Add*) at once.

## 1.0.107 - 2026-11-15

- **A request stuck without its approval is approved or declined on the pages.** One asked for
  on the portal that left the waiting state but whose approval was never recorded could be
  declined only with `acme --decline`. Now the certificate list tags it "approval missing", and
  its detail - in the administration and on the portal - says so and offers Approve and Decline
  through the same dialogs as a waiting one, by the same checks (not by the one who asked, names
  another owner holds by that owner's approver, the right approve); a button that would be
  refused is off with the reason, and one with a certificate issued is revoked instead of
  declined.

## 1.0.106 - 2026-11-15

- (security) **The sign-in with a certificate: a forged OCSP answer is no longer taken.** The
  answer's signature was told good by the words "Response verify OK" anywhere in openssl's output
  - its printout of the answer too, where the responder names itself: a responder of anybody's
  named so was taken in `first` and `only`, and a revoked person signed in. Now openssl checks it
  without printing it, and only its return code and its own line count.
- (security) **The sign-in with a certificate: an authority renewed with a new key.** AD CS keeps
  the name of an authority renewed with a new key; with both certificates put in, the issuer was
  the first of that name - the OCSP request named the old key and was answered of another
  certificate ("good"), and the old certificate run out counted as in the chain (everybody
  refused). The issuer is now the one whose key signed it (its key identifier, its signature),
  and OCSP answers are kept by the issuer's key. Renewed with the same key (two certificates of
  one name and key), the one valid now is taken - the old one run out is taken only when no other
  signed it (with OCSP on, the expired one put in first refused everybody).
- (security) **The sign-in with a certificate: a delta CRL of a newer base CRL.** openssl leaves
  such a delta out without a word, and who it lists as revoked signed in. The base CRL is fetched
  again; still older than the delta's, nobody signs in (*not available just now*).
- (security) **The sign-in with a certificate: an OCSP answer without a next update** is taken 15
  minutes from when it was made - an old "good" one replayed on the plain http path was taken
  however old. An answer whose next update has passed is said to be *out of date* (it was "says
  nothing of this certificate").
- (security) **A certificate asked for on the portal is never issued past its approval.** *Give
  out a CSR*, an import into it or a CSR's answer took a request that waits for approval - or one
  declined - out of the wait (*pending*, *valid*), and *Renew now* issued it: past the team
  holding its names, and past "never your own request". These are refused now with "approve it
  first" (409), and a request that needed an approval is issued, renewed or imported into only
  once it was approved (kept with it; one issued before this version counts as approved). Its
  approval is noted in one step with its state, and a CSR or names sent at that moment no longer
  write over it (on MariaDB too, where the retry read the old row and gave up with 409); a new
  CSR with other names puts it back to waiting and takes its approval back in one step. A request
  left out of the wait without its approval noted is taken by *Approve* again - or *Decline*d (it
  said "not waiting for approval", and the request stayed "never approved" for good); a declined
  one is noted as not approved.
- (security) **The portal: a new CSR for a certificate whose request profile was deleted is
  refused** ("its request profile is gone - ask again with another one"). Only its DNS names were
  compared - an e-mail or URI name, any extended key usage and any subject went to the source
  unchecked.
- **The sign-in with a certificate: a CRL that cannot be had is fetched again after a minute**,
  not at every sign-in, and one fetch of an address at a time (sign-ins together wait for it);
  *Fetch now* fetches it at once. A CRL in the directory only under `CN=Configuration` followed
  by the forest's `DC=` alone; no CRL or OCSP answer is fetched from Azure's WireServer
  (168.63.129.16), Oracle's metadata address (192.0.0.192) or such an address carried in an IPv6
  one (6to4, Teredo, NAT64). A NAT64 address (64:ff9b::/96) is judged by the IPv4 address in it:
  on an IPv6-only host with DNS64 every CRL's address was refused as reserved.
- **Asks of every node are queued.** Two of a kind within a few seconds - *Clear* of one CRL, then
  of another - the second replaced the first on the other nodes, and the first page waited for an
  answer that never came. Each is now done once on every node and answered for its own page -
  one after another, the oldest first. Of the encryption to the database server's switches only
  the latest of a step is done (the earlier ones answered as left out: run together, an older one
  could finish last), and a node restarted does again none it answered, and of a test only the
  latest. Two nodes asking at the same moment both keep their ask (one wrote over the other's).
- **The team that held a request's names stays its approver only while its certificate holds
  them.** Kept from when the request began to wait, it was its only approver for good - with its
  certificate revoked, run out or deleted since.
- **PKCS#12 with openssl 1.1.1** is made again: it has no `-iter`, and every PFX failed there. It
  gets openssl's own count (2048 rounds, said in the log once); 3.0 and later 250,000 as before.
- **A SHA-1 CSR on a system whose openssl.cnf is in a folder with `$`, a backslash, a quote or
  `#` in its name** is verified - the file was not read by the configuration made for it.
- **--uninstall no longer leaves nginx unable to start.** The certificate's own port's server
  (`acme_certlogin.conf`) stayed in `/etc/nginx/conf.d` with `acme-certlogin-ca.pem`, and it uses a
  limit acme.conf defined: `nginx -t` failed, and after the next reboot nginx did not start. Every
  file of conf.d acme wrote is taken away now with the authorities, `nginx -t` is asked before
  nginx is reloaded (what it still names is said), and the SELinux ports acme labelled are listed
  with how to take them out.
- **The sign-in with a certificate: the port.** A listener on two addresses (`0.0.0.0` and `[::]`)
  was one program plus "a program that cannot be told" - the real cause of 1.0.102's "used by ?";
  every socket of a process is matched now, and such a listener counts as acme's only while every
  one that can be told is the system's nginx. nginx listening on the node's own address or on
  IPv6 only was "could not listen": the port was taken away and nginx reloaded twice at every
  request - its listeners are looked at on every address now. **Another site of nginx on the same
  port** was taken for acme's own, and acme's `listen … ssl` made that plain-HTTP site TLS only:
  refused now, its file named (*another site of nginx listens on …*) - only a file nginx loads
  (`nginx -T`; not one in `sites-available` or a folder below `conf.d`) with a `listen` on the
  port on every address or on one of this node's (not another address) - a `listen` in a quoted
  string, after a word's apostrophe (`don't`) or after a line in a file that looks like `nginx -T`'s
  own `# configuration file …:` does not count. The card says *nginx could
  not listen* or *another site of nginx* rather than *taken by another program*, and root's words
  only for the port asked for.
- **A port refused as taken is really asked for again.** 1.0.103 said it would every 15 minutes;
  Events said "the certificate nginx has … is not the one saved: put in again" every 30 minutes and
  nothing was asked (a certificate nginx did not have was not put in again either). Both are asked
  for now, the port with its own words and its own 15 minutes - *nginx could not listen* (nginx
  reloaded twice each time) less often while root answers the same, up to every 6 hours.
- **nginx's reload is said as it went** ("nginx reloaded" was said whatever systemctl answered); an
  nginx that failed to start (its port taken at boot) is started again once acme's server is out;
  one the administrator stopped (exactly *inactive*) is left stopped, and said so - one
  activating, deactivating or reloading is checked for listening as any other.
- **SELinux: a port another service has is never taken from it** (`semanage port -m` relabelled it
  `http_port_t`); it is said, choose another port.
- **The page that stays where it is (1.0.105) no longer gets in the reader's way.** The mouse wheel
  stuck in 14 Settings panes: the help shown under the pointer was drawn before the scroll was
  heard of, and the scroll was undone. A scroll the reader made is now kept whatever is drawn at
  that moment, and help, toasts and popups floating over the page are not looked at. The empty
  room kept under a shortened end went along to every other pane (a whole frame of nothing): it
  is now never more than half a frame in all, gone with the pane it was for, given back as the
  end grows again or the reader scrolls up out of it - and after 8 seconds only the part below
  the frame (the room on the screen taken away, after a resize or by the wheel turned down,
  moved everything up by its height). The focus is put back only when a redraw took it - not after a click
  on the page, where Space opened and closed a CRL row instead of turning the page. A popup whose
  main button cannot be pressed (*Approve* of a request not yours) focuses its *Close*.
- **The sign-in with a certificate's card, in Czech and on a phone.** What the daemon says there -
  the trouble of a node, a CRL's or an OCSP answer's last error, a node's answer to *Fetch now* or
  *Ask again* - is translated (its address, name and time kept as they are) and in red; the OCSP
  refusals, the ports' and CRL addresses' words were English in Czech. A node's authorities are
  *zapsány* (it said *ZÁPIS*), cleared answers *vymazáno*. The OCSP table no longer runs past the
  card (the serial cut short with …), a CRL's address no longer under its two buttons on a phone,
  and *Each node* is a block a node there, not a table to scroll sideways. A Settings pane chosen
  on the rail opens at its top - it opened where the one before was scrolled to; *Find a setting*
  still goes to the setting, and a pane drawn again stays where it is.

## 1.0.105 - 2026-11-14

- **The sign-in with a certificate: OCSP, and CRLs from the directory.** Each part (Settings →
  Accounts, and the enrolment pages → *Signing in with a certificate*) can ask an **OCSP
  responder** (AD CS *Online Responder*) - *Ask an OCSP responder*: `off` (the default: the CRLs
  alone, exactly as before), `first` (the CRL only when the responder does not answer), `only`,
  `both` - for the certificate and every authority above it but the root, at the address each
  certificate names or at *OCSP responder of its own*. The answer is checked by openssl against
  the authorities put in only (a forged one is no answer), kept ten minutes at most or until its
  next update, the last good one while the responder does not answer; revoked or unknown refuses,
  no answer refuses except in `first`. **CRLs from the directory (LDAP) too** reads AD CS's
  default `ldap:///…,CN=CDP,CN=Public Key Services,…` CDP with acme's own directory connection
  (that part's directory, never the host in the address; only CDP objects, base scope, the CRL
  attributes) after up to three http ones. The card shows the order as steps under *Revocation*,
  an **LDAP** row in the CRL table, and a new table **Online status (OCSP)** with *Ask again* and
  *Clear* on every node (a full administrator; written to Events). `acme --cert-login-ocsp
  [--json]`, `--cert-login-ocsp-fetch`, `--cert-login-ocsp-clear`. The person is told only
  *revoked*, *not available just now* or *certificate not accepted*; the rest goes to Events.
- **The page no longer scrolls under your hands.** Whatever is redrawn - a card refreshing by
  itself, the answers of Fetch now coming in, a row opened or closed, a switch turned - what you
  are looking at (the thing you just clicked, else what is in the middle of the screen) stays
  exactly where it is on the screen, on every page of the administration and the certificate
  portal, on a desk and on a phone. Opening a CRL row in Settings → Accounts → *Signing in with a
  certificate* moved the page by 595 px (972 px on a phone) and Fetch now by 490 px; a switch
  near the end of a settings page pulled the page up by 40-80 px. Only you move the page now (the
  wheel, a finger, the keys, the scrollbar), and the page itself where it means to (a jump to a
  row, a box focused out of sight). The answers of Fetch now / Clear are shown under the CRL
  table rather than over it, a box waiting for "Loading…" keeps its height, the focus stays on
  the row that was redrawn, and the CRL table fits the card in Czech too (a long address is
  shortened with … instead of pushing Fetch/Clear past the card's edge).

## 1.0.104 - 2026-11-14

- **The sign-in with a certificate: the CRLs on the card, Fetch now and Clear.** Settings →
  Accounts (and the enrolment pages) → *Signing in with a certificate* lists every CRL a node
  keeps and every one the authorities put in name (not fetched yet, until then): its address (to
  copy), issuer, base or delta, the next update as a pill (good, within a day or its last fetch
  failed, not had or run out), the revoked entries and when it was fetched; a row opens to its
  this update, number, size, the signature checked by openssl against the authorities, and each
  node's fetch and last error. **Fetch now** and **Clear** (all, or one row; a full
  administrator; in Events) are done by every node of the cluster itself, the card following
  their answers; a fetch that fails loosens nothing - the last good CRL until its next update,
  else no sign-in, as before. The same from the command line: `acme --cert-login-crl`,
  `--cert-login-crl-fetch [URL]`, `--cert-login-crl-clear [URL]`.

## 1.0.103 - 2026-11-14

- **The sign-in with a certificate: "port 8443 taken by another program" when it was acme's own
  nginx.** Root could not tell which process held the port (its /proc not readable at that moment
  - "used by ?") and so did not give the port to nginx, while acme's earlier server of it stayed
  loaded and nginx went on listening; the card then called it another program's. Now a listener
  root cannot tell, while nginx runs with acme's own server of that port, is acme's; the system's
  nginx is also known by the service's main process; the card shows root's own words (the
  program and its pid); when the port is truly taken acme's earlier server of it is taken away
  (nginx would not start again with it); and a port refused as taken is asked for again every
  15 minutes, so a node fixes itself after the upgrade.

## 1.0.102 - 2026-11-14

- (security) **Every secret sealed for its place.** The settings' secrets (the proxy, SMTP, SMS, DNS and
  SNMP passwords and keys, the portal's SSO key) and the directories' passwords were sealed
  without the place they belong to, and a value never sealed was taken as it was: somebody who
  could write the database without `secrets.key` (what the guard against writes is for) copied
  the sealed proxy password into a module's secret field pointed at their own server, or wrote a
  key they knew, in clear, over a certificate's. Once every node runs 1.0.102, every secret kept
  is sealed again for its place (the settings for their names, a directory's password for its
  row, the keys, the modules' secrets and the ACME accounts held) - said in the events - and from
  then on one sealed without a place, or kept in clear, is refused there (in words in the log).
  A secret written in clear into `config.json` is still taken; a setting found in clear in the
  database is sealed and named in the log; a module's secret field still in clear (its module
  not loaded then, or the field marked secret later) is taken and sealed at its next use. A
  backup or copy made before is sealed so when it is put back (tried again at the next tick if a
  step fails); the backup's check, the configuration's export and import and the cluster's
  replication are unchanged. Until every node of a cluster runs 1.0.102 nothing changes; then
  every node reads its settings again - one that read them before is never left with every
  secret empty (mail, SMS, the proxy, the remote backup) until a restart. The secrets of the
  metrics and of SNMPv3 are under the guard against writes too (signed once as they are - and
  still checked when the guard is switched on as the first thing a process does, which lost
  this node's marks of the rows taken under the guard). A secret is read from its own row only,
  never from a node's (`key@node`), and a row that is no better is asked for again only once the
  settings are read again. An export without the secrets carries a module's secret still kept
  in clear as dots too.
- **An ACME account key, or a key held at a commercial source, is never kept in clear** inside
  acme: a key that cannot be sealed (`secrets.key` missing) stops the order in words, before
  anything is ordered. Only a tool of its own outside acme keeps it as it is.
- **The own CA refuses weak requests:** an RSA key under 2048 bits, DSA, a curve other than
  P-256, P-384 or P-521 (Ed25519 is signed), a request signed with MD2, MD4 or MD5 (SHA-1 is
  taken: a request's signature only proves the key, and the CA signs with its own - also where
  the system's crypto policy refuses SHA-1, as RHEL 9/10's DEFAULT does; if it still refuses, it
  says so instead of "not signed by its own key"). An authority
  imported, or its certificate installed, with such a key (or signed with MD5/SHA-1 by the CA
  above) is refused too. The portal and devices' keys were checked already.
- (security) **Name constraints read as OpenSSL reads them.** A wildcard is compared as written:
  `*.corp.example` is signed under a permitted `.corp.example` (it was refused), and
  `*.example.com` refused under an excluded `.example.com` (it was signed, and every client
  refused it). A URI's host is the one a URI parser finds - `https://evil.com#.corp.example`
  passed `.corp.example`; a URI without a host is refused under URI constraints.
- **Keys and PKCS#12 files locked with a password are harder to guess:** a key exported
  encrypted (`key-pem-enc`, an authority's key) takes PBKDF2-HMAC-SHA256 with 600,000 rounds,
  `pfx`/`p12` 250,000 rounds each for the key, the certificates and the MAC (openssl's default
  was 2048) - under the limits of .NET 9's loader (300,000 each, 1,000,000 together).
  Windows 10 1709 / Server 2019 and Java 8u301 and later read them; `p12-legacy` is unchanged
  for older devices. The ZIP for isemon (WinZip AES) keeps the 1,000 rounds its format fixes -
  the docs now say to give it a long random passphrase.
- (security) **What an issuer gives back is checked:** a certificate whose names are not the ones asked
  for (a name missing or one more - the `www.` twin or the base of a wildcard a commercial CA
  adds is taken; e-mail addresses and UPNs compared whatever their case, as AD CS writes the
  directory's), or that does not verify against the chain it came with, is refused in words
  and not tried again by itself. An ACME CA asking to prove a name that was not ordered is
  refused before any TXT record or HTTP file is written for it.
- (security) **SCEP with a CA fingerprint trusts only what that CA signed.** An RA sent next to
  the genuine CA by someone in between (plain HTTP) got the request and its challenge password,
  and a CertRep signed by it with a certificate of an impostor CA of the same name was taken.
  Now the RA, the answer's signer and the certificate that comes are checked by their signatures
  against the pinned CA (signatures, not dates: a certificate dated a little ahead by the CA's
  clock is taken, an expired RA is said as expired; a certificate refused keeps the request held,
  asked for again at the next try). Without a fingerprint, plain HTTP trusts the first answer
  (the field's help says so).
- **A DigiCert order whose DCV record could not be placed** (the DNS API down, a stop) places it
  and asks for the check at the next try - it waited "pending" for 120 days. **Sectigo SCM**
  takes its placed records away when the validation's submit fails.
- **"Seen by the zone's own name servers" waits for those it cannot ask** (IPv6-only, a
  firewalled secondary): not "every name server" while some are not asked; after 3 minutes the
  resolvers decide, and the job says which servers were not asked. The end of a CNAME chain is
  checked as a record name before anything is written there.
- **AWS Private CA keeps the request it holds** on a 5xx or throttling while fetching it - the
  next try made a new (paid) certificate. **DNS Made Easy, Constellix and Gcore** read every page
  of their zone lists.
- **Tests:** SNI "-" sends none in the MSSQL test and opens XMPP without `to=`; the HTTPS test
  refuses a line break in the method, path or Host header, and its answer is read in 120 s at most.
- **A key revoked is known after a configuration's export and import.** A certificate put
  in from the file has no versions, so a revoke there changed none, and after a failed new issue
  "keep the key" issued the revoked key again. The public keys and fingerprints revoked are now
  kept with the certificate (in the file too): never kept again, never deployed.
- **A renewal killed at the command line** (`acme --renew` and the ssh session closed) no longer
  leaves the certificate "renewing" for good: the scan marks its job failed, the certificate
  "failed" (alerted and mailed as a failed renewal) and tried again. A lease left by a process
  of this node that is gone is taken over at once - no 409 "a job is already working on that
  certificate" for a minute after a restart.
- **Issued again after a revoke** ("Renew now"), a certificate is renewed by itself again if
  it was before the revoke - it stayed "by hand" and ran out.
- **The answer to a CSR is checked for its names**, as an import into a certificate is: one for
  other names is refused in words (`force` takes it anyway; `acme --csr-answer ... --force`).
  A CSR given out before a configuration's export can be answered after the import (its key
  goes in the file with the secrets).
- **Two asks at once from a request profile** no longer give a 500: the next free name is taken,
  as the portal's own form does.
- **Alerts of failed deployments go** when nothing will try them again: the certificate switched
  off or revoked, its target switched off.
- **The deployment option "Which certificate (when it is dual)"** is checked when saved - a value
  that is none of its choices failed every deployment.
- **"Renew now" while a deployment runs** says so (409), instead of answering with the
  deployment's job as the renewal.
- **The command line as the pages:** a first issue is logged as an issue; `--revoke` is refused
  where the pages refuse it (imported, moved, self-signed, being revoked now); new `--revoke NAME
  --reissue`, `--cert-del NAME --revoke-first`, `--cert-keep NAME`, `--approve NAME` and
  `--decline NAME --why TEXT` (docs/command-line.md).
- (security) **Nobody approves a request of their own - on either side.** One who sends a new CSR or other
  names for a request is one of those who asked for it: a member who may manage sent his own CSR
  with a name of another team's for someone else's request, and approved it himself. The
  administration's Approve now refuses the one who asked too (by the account's name, its DN, its
  mail, its sAMAccountName without the domain - matched against every name the asker is known by
  on the portal: the UPN, the sAMAccountName and the DN; a UPN or mail only as it is, an account
  of acme's own only as local:NAME, never a person of the directory of the same name) - a
  certificate administrator who also signs
  in to the portal approved his own wildcard there and took its key on the portal. A full
  administrator is no exception: one who needs a certificate adds it in the administration, and
  one who gave a waiting request other names has another administrator approve or decline it.
- (security) **A name another team's certificate holds is approved by that team.** A request that waits
  because of it is approved only by someone who may approve (or manage) for the team holding
  the name, or by a full administrator - an approver of the asker's own team let it through and
  the asker took the key. A certificate without an owner, one run out, revoked or declined holds
  no names (a request for a name of one without an owner still waits for approval, by any
  approver). The approval windows (portal and administration) say whose names they are; the
  holding team is told (an event, and a mail to its contact address).
- (security) **A new CSR sent on the portal while a job works on the certificate** is refused (409) with
  nothing of it kept - it was kept, and the job running then issued the old one.
- (security) **CSRs made to get past a request profile are refused:** two extension requests (acme checked
  the last, OpenSSL and a CA taking the CSR as it is read the first - a UPN with smart-card
  logon), an extension request or challenge password twice, an extension twice, a UPN
  or another otherName, a directory name, an OID,
  an x400 or EDI party name or a name that does not read, a certificate authority asked for
  (`CA:TRUE`), and - for a source that takes the CSR as it is - extended key usages the profile
  does not give. Other attributes may repeat: a Windows certreq or ConfigMgr CSR writes each
  enrollment name-value pair as an attribute of its own. A CSR carrying Microsoft's old
  extension request (msExtReq) is refused when it comes in (portal, a new CSR, a device's key,
  signing by acme's CA) - AD CS read its names, acme did not. A CSR kept from before is still
  read and renewed with.
- (security) **A scoped session is not told of another team's certificates:** the targets' list says
  "another owner's certificate" for the one whose key a device makes and a generic phrase for a
  target's last error naming one; a name taken by another team's certificate, or a device making
  its key, is refused without naming it.
- (security) **A scoped certificate administrator gives no names another team's certificates hold** to a
  certificate in the administration (refused in words, as the portal makes such a request wait) -
  only the names given to it now are looked at, unless it is given to another owner; a full
  administrator, or one who sees every certificate, may.
- (security) **The floor for going back is 1.0.102.** 1.0.101 shut holes of the root helper
  and left the floor at 1.0.44: the acme account, which writes root's helper its asks, could take
  the server back to 1.0.100 and its holes. A version with an entry marked "(security)" here now
  raises the floor to itself (a test fails otherwise; docs/releasing.md).
- **An upgrade keeps how many logs are kept.** install.sh wrote `/etc/logrotate.d/acme` back to
  30 logs of 200 MB, and logrotate's next run deleted every log beyond 30 before the daemon set
  *Settings → Disks and logs* again (6 hours later): the values there are carried over, and the
  daemon writes them again at once after a version change.
- **A notice at the console keeps its backslashes** when a change of sshd on trial is put back -
  each put-back doubled them.
- (security) **`install.sh --uninstall` takes acme's certificate authorities out of the system's
  trust** (`acme-*` anchors, then `update-ca-trust` / `update-ca-certificates`) - curl, dnf and
  LDAPS trusted them after acme was gone. Its password policy, time servers, journald drop-in and
  sysctl file go too (acme's block in `chrony.conf` only when whole - with its begin or its end
  line lost it is named and left, and Settings - Time refuses to rewrite the file, in words,
  instead of guessing which lines were acme's); sshd's drop-in, the firewall chain `ACME-IN` and the cluster's authorities
  (`/etc/pki/acme/ha-ca.pem`) are named, with how to take them out.
- (security) **The plugin examples are written through the folder itself**, opened without following a
  link and checked root's: a link put in place of `/etc/acme/plugins` had root delete and write
  an `examples/` wherever it pointed.

## 1.0.101 - 2026-11-14

- (security) **More of root's ways only from acme's signed word, each done once.** With `db_guard` on, the
  root helper now also makes a local user, gives one a password or `sudo`, and adds a key of a
  member of wheel/sudo only from a signed row of the database (`host:users:want:*`,
  `host:sshkeys:want:*`), as it does root's own keys. Each signed ask is done once: a cleared
  list of asks done (`host:sshkeys:now:*`, `host:users:now:*`) no longer has an ask of the last
  hour done again - a key taken away put back. A key of root's added while something else was
  asked of the node at the same moment (the page's own refresh) was refused as "not signed" and
  never added: the row is now read again with its signatures, and an ask refused for its
  signature is asked again (three times) instead of being marked done.
- **Renaming a target whose device makes the key** no longer made the version that device made
  count as "fits no key": refused for deployment and issued again.
- **Requests held at SSLmarket and SSLS.cz** with the key of a version revoked since are no
  longer finished: dropped, and a new request with a new key sent. At a revoke, a request held
  at any source is dropped only when it has the key revoked (or its key cannot be told) - one
  held for a new key stays, so the next renewal does not pay for a second order.
- **During a rolling upgrade to 1.0.101** a portal sign-in made on a node still on 1.0.100 is no
  longer ended by the first request that lands on an upgraded node: the portal's sign-ins are
  checked against their signatures once every node runs 1.0.101 (as the portal's settings).
- **`guard.json` no longer grows with every sign-in.** The counters seen of sign-ins that are
  over are taken out with their signatures.
- (security) **`/healthz` no longer says the node's name** to anybody: `ok up`, `maintenance`,
  `degraded: replication ...`, `down: ...`. A balancer matching `^ok ` (as the guides say) is
  unaffected; the balancer guide's check on the pages shows the new answers.
- **An IP address on a validation that proves names in DNS only** (DNS-01) is refused when the
  certificate is saved, in words, not later by the CA. A pattern of names (`.0.1`, `*.0.0.1`)
  never chooses the validation of an IP address - only the address's own key does.
- (security) **A key of root's only from acme's signed word, with the guard against writes to the
  database on.** The root helper (`acme_web.py`) added any key line the `acme` account wrote
  into its folder to root's `authorized_keys`. With `db_guard` on, it now adds one only when the
  ask carries the database row it comes from (`host:sshkeys:want:*`) with acme's signature of
  it, and checks that signature itself: the row must hold that very ask (its id, add, root, the
  same line, at most an hour old). An ask laid in the folder by itself, or written into the
  database past acme, is refused and nothing is added. A `config.json` that cannot be read
  counts as on. Keys made or added on the pages work as before; taking a key away and the keys
  of normal users need no signature. With `db_guard` off nothing changes, and the docs now say
  plainly that the `acme` account can then add a key of root's (*SSH keys*, *High security* -
  *What the acme account can do as root*). Even with the guard on this is defence in depth:
  `acme` holds `secrets.key` and may write `config.json`.
- (security) **Less said without a sign-in.** `GET /api/acme-push/hello` (relayed with no sign-in) no
  longer gives the exact version while *Certificates from acme* is switched off; switched on,
  it says as much as the protocol always has. The daemon's `/api/health` asked without the API
  token no longer says the node's name or whether any account exists. The pages and
  `/healthz` ask with the token and are unchanged.
- **Signing out of the portal ends a portal sign-in only.** `POST /api/portal/logout` ended
  any sign-in whose token it was given, an administrator's too.
- (security) **The portal under the guard against writes to the database.** With `db_guard` on, only the
  administration's sign-ins were signed: a portal sign-in written into the database past acme
  (with `portal_cert_keys` set the same way) handed out every certificate's private key. Every
  sign-in is signed now and checked at each request; the portal's directory is asked only as
  acme wrote it (every way of signing in to the portal, and the recheck); the portal's settings
  (`portal`, `portal_directory`, `portal_who`, `portal_groups`, `portal_enrolers`,
  `portal_local`, `portal_local_code`, `portal_code`, `portal_admins_all`, `portal_cert`,
  `portal_cert_keys`, `portal_cert_auto`, `portal_cert_issuers`, `portal_cert_suffixes`,
  `portal_cert_challenge`, `portal_cert_max`, `portal_session_min`, `portal_tries`,
  `portal_wait_min`, `code_digits`, `code_tries`, `code_ttl_s`) are signed, taken under the
  guard once every node runs 1.0.101; a portal sign-in of the directory without its DN is
  refused. **Upgrading with the guard on, the portal's open sign-ins end** - people sign in to
  the portal again. Gone back below 1.0.101 and up again, the portal's settings saved meanwhile
  (unsigned) are signed once more as they are - each node keeps in `guard.json` the version
  that wrote it last - instead of being refused as written past acme (*High security*).
- (security) **Session cookies `__Host-acme_session` and `__Host-acme_portal` over https.** A cookie of the
  same name planted by a sibling host or over http was sent first and taken: the person then
  worked in somebody else's account. The cookies are `__Host-` now (Secure, `Path=/` - the
  administration's no longer of `/admin/` alone - no `Domain`), and a request with two cookies
  of one name counts as signed out. Plain http (a test server) keeps the old names. **After the
  upgrade everybody signs in again** (the old cookies are not read over https).
- (security) **The portal's one-time code typed, a new sign-in.** As the second step does, the sign-in the
  password opened is ended and a new one handed out.
- (security) **The second step switched on ends the portal sign-ins without it.** `admin_2fa` switched on
  (or the portal's code for acme's own accounts taken away while it is on) ended the
  administration's sign-ins only; a portal sign-in of acme's own account, made with the password
  alone, kept seeing - with *Administrators see every certificate* - every certificate.
- **While the nodes are apart, the portal's certificate requests wait as other changes do.**
  The free path `/api/portal/cert` (the sign-in with a certificate) let every portal
  certificate write through on the frozen node; the paths are matched whole now. The portal's
  one-time code, the balancer's sign-in and the portal's own password change go on there
  (as `/api/auth/*` does).
- **Your passkeys ask the sign-in as every page does.** An account that must change its
  password first, or given the role of the enrolment pages only, could still list and change
  its passkeys.

- **A request held at the CA is never finished with a revoked key.** With "Keep the key", a
  renewal waiting at the CA (DigiCert, Sectigo, Certum, GoGetSSL, SSL.com, The SSL Store,
  Namecheap, GlobalSign, AWS Private CA, EST, SCEP, AD CS, Venafi...) held the key it had; revoked
  for keyCompromise and issued again, the job said "a new key" and the source finished the held
  order with the compromised one. A revoke now drops every request the source holds for the
  certificate (its DCV records taken away), and a source refuses a held request whose key is
  that of any revoked version (`CertRequest.no_held_key`).
- **Switched from one device to another, the version made for the first one's key is no fit.**
  A certificate whose key device A made, switched to device B, took the version made for A's key
  as fitting B: Deploy now (and the scan, once the new issue failed) put it on B. The record of
  the device that made the version is compared with the one that makes the key now; "renew it
  by hand" is said again for the new device.
- **An override started from a version overrides that version.** "Start from the whole code of"
  FortiGate 6.0, 7.0 or 7.4.2 in override mode gave a file that overrode the plain module; it
  now says the version asked for (and is named `fortigate_7_0.py`, as the upload dialog names it).
- **An IPv6 address can have a validation of its own.** The names of a certificate's own
  validations (`challenge_map`) took an IPv4 address but refused an IPv6 one; an address is
  accepted and written as the names are (`2001:DB8:0::10` as `2001:db8::10`), and What happens
  checks a draft's map the same way (it took it unchecked).
- (security) **What happens hands no secret that is JSON to the module.** Only members with secret-sounding
  names (password, private_key, ..._token) of a secret written as JSON were stand-ins: `pwd`,
  `apiToken`, `accessKey` and a list of passwords reached the module as they were. Every string
  in it is a stand-in now, but for those that say where and who (URLs, e-mails, domains, the
  type, the project), and the real one is masked out however it is written. A module opening
  an HTTP connection of its own (`putrequest`/`endheaders`) is shown as going around acme too.
- **`acme --ha-resync` and `acme --ha-join` start the guard's counts again.** With `db_guard`
  on, a node rebuilt from the other one on the command line kept the newest signatures it had
  seen in its own `guard.json`: every guarded row it had seen newer (settings such as the proxy,
  the firewall, sshd and the sign-in switches, accounts, sign-ins) was refused as "an older one
  put back", and the node went on acting on its own old values - after the restart too. Both
  commands now forget them, as the rebuild on the pages has done; a node joining a shared
  cluster (pages or command line), whose `secrets.key` is replaced, starts from an empty
  `guard.json` as well.
- (security) **What happens: the recording's process kept in bounds.** A module's own code runs there. Its
  memory is limited (1 GB of memory it writes, `ACME_PLAN_MEM_MB` - not of its address space,
  so a module may start threads; two malloc arenas at most), its processor time and the
  size of a file it writes too; what the daemon reads back from it is capped (the process is
  stopped beyond it). What a module prints (`print()`, stdout, stderr) is no longer mixed into
  the recording's answer - one `print()` lost the whole plan, a module writing to stdout in a
  loop took the daemon to gigabytes of memory: it is kept aside (4000 characters a module) and
  shown with the debug details as *What the module printed*.
- **`api_port` is never the certificate sign-in's port.** `acme --set api_port=8443` was taken,
  though `certlogin_port=9861` was refused the other way round: nginx listens on the
  certificate's port on every address, and at the next start the daemon could not (or the sign-in
  with a certificate was lost). Refused now on every node - a node's own `api_port`, the
  cluster's value, and `certlogin_port` against every node's `api_port`.
- **Going back below a sign-in setting switched on is refused, and says which.** Going back to a
  version older than the one that brought `admin_krb` / `portal_krb` / `admin_password_off` /
  `portal_password_off` (1.0.99) or `admin_certlogin` / `portal_certlogin` (1.0.100) while it is
  on dropped it without a word - with "no password" on, passwords signed people in again. The
  list of older versions and `acme --downgrade` now name the settings to switch off first; and
  with the guard against writes to the database on, the portal's sign-in settings stand in the
  way of 1.0.100 (its settings are signed only from 1.0.101).
- (security) **A deployment's option of text is one line.** A certificate administrator could put a line
  break into Cisco Catalyst 9800's *Webauth parameter map*; it went into the controller's
  configuration mode as more lines (a privilege-15 user, say) at the next deployment. Saving a
  deployment now refuses a line break or another control character in any text option of any
  module, and in each line of a list (a tab is let through there), whoever saves it; the
  parameter map's name is letters, digits, `_ . -` (64 at most), checked again before anything
  is copied to the controller. A module's field can now say the form the device takes
  (`pattern=`), checked for a value given or changed only (as a number's minimum and maximum:
  a value saved before that the device took does not block every later save of the
  deployment); the test of a deployment checks the same.
- (security) **MOMCertImport.exe is a full administrator's.** Operations Manager's *MOMCertImport.exe* is
  run as Administrator; a certificate administrator could point it at another program, or one
  on a share (`\\host\share\x.exe`). It is set by a full administrator only now, as the
  commands and the Windows Admin Center installer are, and it must be a path on a drive of the
  server ending in `\MOMCertImport.exe` - no share, no WebDAV, no `..`.
- (security) **A part of a device's address is one part.** Options that become a part of the path of a
  device's API - Kubernetes' namespace, secret and deployments to restart, NetScaler's certkey
  and virtual servers, F5's partition and profiles, A10's templates, FortiGate's virtual IPs
  and profiles, NSX's virtual servers, Barracuda WAF's services, NGINX Unit's listeners,
  Proxmox's nodes, Azure's web app, gateway and listeners, Kong's SNIs - are encoded whole (a
  `/`, `?`, `#` or `%` in a name the device allows goes through as part of it: NetScaler's
  `www#2026`, a FortiGate VIP `vip-10.0.0.5/443`) and refused as `.` / `..` or with a control
  character when saved (and by the module). Kubernetes' names are its own (`a-z 0-9 - .`), F5's
  are letters, digits, `_ . - :` in folders; Kubernetes' deployment
  `x/../../namespaces/kube-system/...` restarted one in another namespace. A OneView enclosure
  given as a URI is `/rest/enclosures/<id>` (its name may hold any character but a control
  one), a
  DigitalOcean load balancer is taken as an id only when it is a whole one. Besides, acme
  itself no longer asks any address with a `.` or `..` part in its path, a space or a control
  character, and reads at most 64 MB of an answer.
- **AD CS: the name of the service asked is the CA's address.** NTLM's target name
  (`MsvAvTargetName`) was `HTTP/` and the name the server's own challenge said; a relay
  forwarding the real CA's challenge got a name the CA accepted. It is the host of the address
  given now. Over https with the check of the certificate on, channel binding protected already.
- (security) **AD CS: the CA certificate of the web server is the only one trusted.** It was trusted
  besides the system's CAs, unlike everywhere else in acme; a public CA's certificate for the
  name was taken too. When given, it is the only one (the field's help says so); empty, the
  system's CAs as before.
- **A certificate's own subject is checked as the CSR will have it.** Saved with C "Czech
  Republic" or an e-mail that is none, it was taken, What happens drew a CSR with it, and every
  renewal failed. A subject given or changed (a save, a draft in What happens) is refused in
  words now: C two letters, each field to RFC 5280's length (L and ST 128 characters, the
  e-mail 255, the rest 64), no control characters, an e-mail `local@domain` without spaces
  (`pki@corp` too). One saved before is not checked again while it stays as it is - the page
  sends it back with every save. A request profile's subject fields take the same lengths.
- **SCEP, EST, CMP: a malformed answer said in words.** A cut certificate, a month 13 or a byte
  that is not ASCII in a time was an `IndexError` or `UnicodeDecodeError` from deep in the
  parsing; it is "a certificate the CA sent does not read" now.

## 1.0.100 - 2026-11-14

- **Signing in with a certificate** (a smart card, a YubiKey, a certificate in the computer), as
  otp 1.0.275 - to the administration and to the certificate portal, **each by its own
  switches** (`admin_certlogin`, `portal_certlogin`; off by default). nginx asks for a
  certificate on **a port of its own** (`certlogin_port`, 8443 - one for both parts), never on
  443, and serves nothing else there; a server for each node's name and the VIP address's, with
  the certificate each has on 443, written by the root helper, and the port opened in the
  firewall for the networks that may reach those pages - taken away again when switched off.
  acme checks the certificate itself: the chain to the authorities put in **and no store of the
  system's** (`openssl verify -no-CApath -no-CAstore`: `-CAfile` alone still trusts the system's
  roots - the kit's reference did), the dates, Client Authentication or Smart Card Logon, the
  CRL at its CDP and its **delta CRL** (Freshest CRL), and those of **every authority above it**
  but the root (`-crl_check_all -use_deltas`: an issuing authority its root revoked signs nobody
  in) - fetched only for a certificate whose chain is good, **kept ten minutes at most** (a
  revocation is seen within ten minutes of the authority publishing a CRL with it), the last
  good one until its next update while the CDP does not answer, no CRL no sign-in;
  `*_certlogin_crl` switches it off. Fetched over http only, **every address of the CDP's name
  checked** as it is fetched (no loopback, link-local, metadata, multicast or unspecified address
  in any form; private addresses allowed - AD CS's are inside), no redirect followed, 8 MB and
  15 s at most. **Every UPN** of the certificate looked at (more than one person: refused), the
  **name constraints** of its authorities applied to the UPN (openssl does not), the UPN looked
  up in the part's directory and the account found by its sAMAccountName as a password finds it
  (the same DN), and the SID of KB5014754 against `objectSid` - **`strong` by default**
  (`*_certlogin_match`; `compat` and `upn` are opt-downs, *Not strong* warned on the card) and
  **only from its extension**: a SID in the Subject Alternative Name (otherName or the
  `tag:microsoft.com,2022-09-14:sid:` URL) is the requester's word, never strong, refused when it
  is not the extension's or the account's. The second step / the portal's one-time code after it
  every time. A nonce of the page against login CSRF - five minutes, MAC-bound to the part and to
  a random value in a `__Host-` cookie of this browser (`HttpOnly`, `SameSite=Strict`), **used
  once in the whole cluster** (kept by the daemon). Refusals say the kind only (*certificate not accepted*, *revoked*, *run
  out*, *not allowed*, *not available just now*), the reason in Events; counted per address,
  *Block a place that keeps guessing*, `alerts_certlogin`. The authorities put in on the card
  (PEM, DER, `.p7b`; a person's certificate refused; taken away one by one; acme's own authority
  offered), kept signed in the database (`db_guard`), written out 0600 by each node; *Try my
  certificate*; the CRLs fetched and each node (written out, nginx listening, **a port another
  program holds named** - refused at the save and by the root helper, nginx never left unable
  to start). `acme --cert-login`, `--cert-login-ca FILE`, `--cert-login-ca-off SHA256`; carried
  by the exported configuration, backups and the cluster ([docs/certificate-sign-in.md](docs/certificate-sign-in.md)).
- **No password at all - only Windows or a certificate**: `admin_password_off` /
  `portal_password_off` are one switch for both ways now, in a card of its own, **The sign-in
  page** (one in *Accounts*, one in *The enrolment pages*, beside the cards of Windows and of the
  certificate): switched on only from a sign-in made with Windows or a certificate, in
  effect while either can sign anybody in (fail closed at the start), the way back for root
  `acme --set admin_password_off=0`. The keytab, or the last authority, cannot be taken away
  while it alone signs people in to a part with no password at all; with Windows the only way,
  Windows is tried by itself whatever its own switch says. Sessions made with a certificate (`how: certificate`) end
  when certificates are switched off or the last authority taken away, when **an authority of
  their chain** is taken away, and when **certificates are taken more strictly** (revocation
  switched on, the matching made stricter) - but the switcher's.
- **The certificate's port, another nginx**: a port held by a process named nginx counts as
  acme's only when it is the system's nginx (the master its pid file names, the system's
  configuration) - any other nginx is refused like any other program. Behind a layer-4 balancer
  the lockouts see the balancer's address: the PROXY protocol (or a transparent balancer) is
  described in [docs/certificate-sign-in.md](docs/certificate-sign-in.md).
- **Upgrading** (from a build of 1.0.100 before this change): *Which account a certificate is*
  is **strong** by default. A value saved (`upn`, or `strong` - a row of the settings) is kept as
  it is - only the default changes; `compat`, the default until now, was never kept as a row, so
  an installation on it takes strong - choose compat again on the card to keep certificates
  without the SID extension (a template where the requester supplies the subject, an offline
  template) signing in, knowingly. From now on a matching chosen is kept as a row even when it
  is the default, so a later change of the default leaves it as chosen. The issuing authority's
  own certificate needs an http CDP (the root's CRL) while revocation is checked.
- **The certificate at once when the sign-in page opens** (`admin_certlogin_auto`,
  `portal_certlogin_auto`; off by default), as Windows' `*_krb_auto`: the page goes to the
  certificate's port by itself - the chooser, the PIN - and shows the form only when it did not
  sign in. Never by itself again in that tab after *Sign out*, after a refusal or a certificate
  not chosen, nor with `?nocert` (*Use a password instead* under the form); at most once in ten
  minutes and three times a tab whatever happens - a setup that never signs in cannot loop.
- **The sign-in page - the variants** (as isemon 1.10.343): a password, Windows and a certificate
  on one page, the administration and the portal alike. Both ways on: both buttons under the
  form (with no password at all, both buttons and no form); both by themselves - **Windows first,
  silently**, the certificate only when this computer has **no Windows ticket at all**; a refusal
  by either is said and nothing else starts; one by itself, the other a button. The second step /
  the one-time code after every way, with no other way's button on its screen. The card **The
  sign-in page** says what a person meets now (name and password, each way off / a button / by
  itself, what is tried when the page opens, after a refusal, after Sign out), and
  `/api/health`, `/api/portal/info` (`signin: {on, auto, cert, cert_port, cert_auto, only, ...}`),
  `acme --kerberos` and `acme --cert-login` say the same. A setting that depends on a switch
  that is off is "Not in use while ... is off" **and cannot be changed** until it is on (every
  pane). A browser that had **no Windows ticket at all** when Windows was tried by itself (outside
  the domain: nothing sent, the browser's own dialog cancelled, NTLM or a password typed into it -
  the new refusal category *no Kerberos ticket*) remembers it for 30 days and does not try Windows
  by itself again - no browser dialog on every visit; the button stays, a Windows sign-in clears
  it. ([docs/certificate-sign-in.md](docs/certificate-sign-in.md), *The sign-in page - the
  variants*.)
- The directory's `objectSid` is read (as bytes) with every account.

## 1.0.99 - 2026-11-14

- **Signing in with Windows (Kerberos SSO)**, as otp 1.0.274 - to the administration and to the
  certificate portal, **each by its own switches** (both, either or neither; off by default). A
  browser on a computer of the domain signs its person in without a password: *Sign in with
  Windows* under the form, or at once when the page opens (never again in that tab after *Sign
  out*). Kerberos 5 only - NTLM, bare or inside SPNEGO, is never taken, and the mechanism is
  checked after the ticket is accepted. Only the directory's people, by the same rules as a
  password: the administration - the role of their AD groups, looked up by sAMAccountName
  (switched off, locked, expired, more than one entry, a computer: refused), the second step
  asked after it every time; the portal - its own directory and realm, *Who may sign in* and the
  groups, the one-time code sent after it every time. A local account keeps its password. Every
  refusal is 403 (never a second 401), said on the page and written in Events; refused tickets
  count towards the sign-in protection as wrong passwords do; *Alerts → Sign-ins with Windows
  (Kerberos) refused* (off by default).
- The keytab is put in once on the pages (*Settings → Accounts → Signing in with Windows*) or with
  `acme --kerberos-keytab FILE`: kept in the database sealed with the installation's key and
  signed (db_guard), written out by each node itself (0600, the service's user) - a node put back
  from a backup or joined later too; its principals, key versions and kinds of key shown, never a
  key. A ticket is taken once in the whole cluster (a day, in the shared database), also after the
  VIP address moved. The card: the keytab, *Try my browser's ticket* (who it would sign in to that
  part, and as what - nobody signed in), the names the pages are opened by with their SPN, each
  node, the `setspn` / `ktpass` commands and the browsers' settings filled in. `acme --kerberos`
  says all of it.
- **"Only Windows"** for each part (`admin_password_off`, `portal_password_off`): no password on
  the sign-in page, none taken, set or changed - switched on only from a sign-in made with Windows,
  in effect only while Kerberos can sign anybody in; root's way back is `acme --set
  admin_password_off=0`. Never switched on by a configuration file read back.
- The session says how it was opened (`how: Kerberos`). The exported configuration carries the
  keytab with the secrets only. nginx takes headers up to 64 kB (`large_client_header_buffers 4
  64k` - a ticket of a person in many groups is more than 8 kB, and AD's largest is 64 kB in
  base64): new installations, the upgrade and the pages' root helper put it in.
- Kept tight: the cluster's "once" is the Kerberos request itself (the same one sent in another
  wrapper is refused on the other node too); "only Windows" in effect from the first moment after
  a start, ending the part's password sign-ins when it comes into effect - and Kerberos off or
  the keytab taken away ending those made with Windows (whoever did it keeps theirs); the keytab
  keeps only AES keys of HTTP/ names (the rest left out, said); the person found must be of the
  ticket's realm (compared exactly); the portal's proof is the administrator's own portal
  sign-in; a configuration with a keytab that would be refused changes nothing; the caller of a
  refused sign-in is told only the kind (not allowed, ticket not accepted, replay), the reason is
  in Events.

## 1.0.98 - 2026-11-13

- **What happens shows everything, for every module** - checked module by module (every target,
  version, source, validation and test): the run takes the real renewal path (the certificate
  there already found, the device serving an earlier one, replaced, the older ones cleaned up,
  first issue and later renewals told apart), every decision the module makes is a step, and
  with *Show debug details* every request is shown exactly as sent - method, address, every
  header (also those the connection adds), the body (JSON, form, multipart, XML; a certificate
  and a key named, never shown) - and the answer (status, headers, body); SSH commands with
  their input, output and exit code, lines typed into a device's command line, files put with
  the command that writes them. The ACME source is recorded whole (directory, account, order,
  authorizations, challenges, finalize, the chain; JWS decoded, signatures hidden; ARI and
  replaces at renewals where the CA offers them). One rule hides secrets everywhere (headers,
  addresses, bodies, command lines, passwords made for the run) and nothing that is not one. A
  module going around acme's connections is stopped and shown in red; a call with no prepared
  answer is marked. The window: copy buttons the same everywhere, files as cards on a phone,
  long values wrapped, no English left in Czech.
- *Your account*, the password to choose first and the enrolment pages change your own password
  in one form: the one you have now, the new one and the new one again side by side (one under
  the other on a phone), each with an eye to show what is typed; under the new ones, as you type,
  whether it has 8 characters, is not the one you have now and is typed the same again. *Change
  the password* is pressed only then (Enter too), and a refusal is said under the boxes. The
  daemon checks the one typed again as well, also where an administrator types one in (a new
  account's first password is typed twice now).
- Settings - SSH server: *Who may sign in* without root while root may sign in is saved when you
  say so (the page asks first) - root then signs in nowhere over SSH, said under the field, on
  the node cards and on SSH keys (not counted as "root with a password" by High security). Root
  with no key is no refusal then; a warning when none of the accounts is on the nodes, or
  passwords are off.
- Fixed: *Download a start* of a module whose file holds several versions (FortiGate: plain,
  6.0, 7.0, 7.4.2) gave a file that, uploaded, replaced every shipped version of that file
  instead of adding one - and a new version made from 6.0, 7.0 or 7.4.2 kept the old number.
  Now the start holds only the version it was made from (the others imported as they are);
  checked for every module and version, on the server's disk (/etc/acme/plugins) and uploaded.
- Fixed: *What happens* for a version of your own made from a shipped one (dell_ome 3.0,
  FortiGate 6.0 / 7.0, IOS XE / 9800 17.3, Redfish iDRAC / iLO, VCF Operations 9.1) ended in an
  error: it now gets the answers of the version it was made from.

## 1.0.97 - 2026-11-13

- **The VIP address with real VRRP, tested end to end** (two nodes, keepalived 2.2.8, acme's own
  file and check script): it moves on maintenance, a lost node or a stopped keepalived, and is
  never on both. keepalived now restarts by itself when it dies (a systemd drop-in acme puts in
  with the VIP) - a killed keepalived left the address on its node while the other took it too.
- Fixed: the alert "keepalived is not running" never came for a stopped keepalived (it says
  STOP), nor for a killed one (now its process is looked for); the HA card shows "keepalived
  stopped".

## 1.0.96 - 2026-11-13

**Targets from a collection of vendors' guides** - each checked against the official documents
it cites, with a setup guide (English and Czech) for every target and version, and its run
shown in *What happens*. Versions only where the calls differ; an existing target that already
did the documented versions the same way got no copy (docs/targets.md, "From the vendors'
guides"):

- **New targets**: HPE OneView / Synergy Composer, HPE Alletra 5000/6000 and Nimble; Dell
  PowerScale OneFS, PowerStore, Unity, Unisphere for PowerMax; Fujitsu iRMC, Infrastructure
  Manager (ISM), ETERNUS DX / AF; Supermicro BMC, Cisco IMC, Huawei / xFusion iBMC; VMware NSX
  Manager (its own certificate), SDDC Manager (trust store), Aria Suite Lifecycle, Aria
  Automation, Cloud Director, Live Site Recovery / vSphere Replication, vSphere Supervisor;
  Omnissa Horizon Connection Server; Cisco IOS XE, Catalyst 9800, NX-OS, Catalyst Center;
  HPE Aruba AOS-CX, ClearPass, Central, ArubaOS 8 controllers and Instant AP (over SSH, through a
  staging server; the CLI's exact form unverified on a device - said in the guide); Barracuda CloudGen Firewall, Infoblox NIOS,
  FortiManager / FortiAnalyzer; Windows WSUS, Hyper-V Replica, Reporting Services, Operations
  Manager, Office Online Server; NetApp ONTAP, Pure Storage FlashArray and FlashBlade, QNAP,
  Cockpit; Veeam Backup & Replication, Cloud Connect, Backup for Microsoft 365.
- **New versions of targets there were**: `redfish` HPE iLO 5/6/7 (HPE's own import - iLO 6
  takes a key from 1.30) and Dell iDRAC9 6.00.02+ / iDRAC10 (Dell's own upload); `esxi` 8.0 U3
  - 9.1 through vCenter (no SSH, no restart); `vcenter` 8.0 U2 - 9.1 (no restart waited for);
  `cisco_fmc` 7.7 - 10.0 (device certificates by enrolment); `nutanix` Prism Central 7.3 - 7.5
  (v4.4 API, API key); NetApp ONTAP 9.6 - 9.9 and 9.10+; IOS XE / 9800 before and from 17.12;
  vSphere Supervisor on vCenter 9.0 and 9.1.
- Fixed in targets there were (each confirmed by two sources): `esxi` saves the new
  certificate to the boot bank (`auto-backup.sh`) - a host rebooted within the hour came
  back with the old one; `redfish` no longer says iLO 6 takes no key, and its guide no longer
  promises Lenovo XCC, which takes only a certificate of its own request.
- **The device makes the key** (a new kind of certificate, docs/certificates.md *Key made by
  the device*): for devices that take only a certificate for a key they made themselves, acme
  asks the device for a new key and CSR at every issue and renewal, has it signed by the
  certificate's source and puts the certificate back on the device in the same job - acme never
  holds the key, the certificate goes only to that device. In the certificate's form: *Who makes
  the key* - acme, or the device (its target picked; only the key types it makes; only sources
  that sign a CSR made elsewhere); a device's window: *Make its certificate*; the command line:
  `--csr-from TARGET`; What happens shows the device making the key. Targets: **Lenovo XClarity
  Controller** (XCC3; XCC / XCC2), **Lenovo XClarity Administrator**, **Dell OpenManage
  Enterprise** (3.0 - 3.9, 3.10+), **HPE Synergy** (Composer and enclosures), **HPE iLO keeping
  its own key** (older firmware, HighSecurity / FIPS / CNSA), **HPE Alletra MP / 9000**, **Cisco
  CUCM** (tomcat, CallManager), **VMware VCF component certificates** (SDDC Manager API; VCF
  Operations 9.1+).
- Products where acme's key cannot go at all (Unisphere for PowerMax's own HTTPS,
  PRIMEQUEST MMB, ETERNUS LT / CS8000, Barracuda Load Balancer and Email Security...) have a
  guide of how to do it by hand in docs/vendor-guides/.
- **Tests made from a deployment follow it**: when a deployment's options or its target's
  settings change where the certificate is served, the test acme made for it follows (a new
  place gets its test, one no longer served is taken off); acme's own tests go with their
  certificate or target when those are deleted. A test you changed in any way is yours and
  stays. A target serving RSA and ECDSA certificates side by side (CUCM) gets a test that asks
  for the right key.
- Deployment options with a range (copies kept, a bay) are checked when saved and in the
  form - only values that changed, so a deployment saved earlier still saves.
- A device whose deployment keeps failing (it lost its pending key) gets its certificate issued
  anew once; with renewal by hand acme says to renew it by hand.
- Fixed: files with the key left on a device after a failed step (ETERNUS, ISM, ArubaOS 8,
  Cockpit, Horizon, QNAP, Veeam B&R); a client secret or PKCS#12 password in the debug log;
  checks of what is served on IPv6 addresses; NX-OS saving its configuration while NX-API
  restarts; VCF failing a deployment on one bad poll; a certificate only added said to be issued
  by itself in *What happens*; version names untranslated on Czech pages; the Modules filter
  `version:` matching nothing.

## 1.0.95 - 2026-11-12

- **The setup guide and its editor take the screen they are given**: the text was held to
  960 px inside a window of at most 1500 / 1680 px - narrow on a large screen. Larger screens
  get a slightly larger letter and wider contents and assistant; a phone the whole screen.
- **What happens shows what 1.0.93 - 1.0.95 changed**: each deployment says whether a test
  checks what it serves (or that none does); a test acme made from a deployment says so -
  not reached from here it warns, a wrong certificate fails the deployment - and how many
  times it asks while a slow target restarts; every module there has its **Setup guide**.

Bug hunt (four parts: the setup guides, the certificates' logic, the daemon/HA/security, the
pages):

- **With the guard against writes to the database on**: a module's code written into the
  database past acme was run by every node (the uploaded modules are signed now, taken under
  the guard once the whole cluster runs 1.0.95); a configuration put in signed everything the
  database held - a sign-in or a firewall row written past acme with it (only what it wrote is
  signed now); an administrator with a second step was locked out after the first sign-in;
  a directory's authorities changed on the page stopped its administrators signing in.
- Switching TLS between the databases off never told the other node straight (the value and
  the key were the other way round).
- **A test acme made from a deployment** that cannot reach the server (a target behind a proxy,
  a network acme does not see) warns and no longer fails a deployment that went through - every
  push of an ESXi or a vCenter through a proxy was failed and retried for good; a host given as
  an address (https://vc:8443) is its name and port. A person's "only by its schedule" and a test
  taken off stay (every save of the deployment's options undid them). A BMC waits minutes only
  when it is reset. The command line's preset no longer makes a test of a host called "{host}".
- **Discover → Apply** gives a slot up only for a choice that stands: a certificate that does
  not hold its names left the slot empty. An empty choice of slots is refused by the API and
  the command line too. The one-time changes of 1.0.77/1.0.93 run once only (two pages asking
  at once gave a certificate the same test twice). Stopped during the tests after a deployment,
  what went through is still said deployed.
- **The guide editor**: Close, its x and Escape ask before throwing changes away, the question
  starts on No; "Back to the default" asks in the editor (it closed it); Enter in the link's
  words no longer saves the guide; backslashes in tables are kept (EXAMPLE\acme-admin), as are
  backticks in code, lines starting like a heading or list, links with brackets, and code pasted
  from an editor; a version of your own of a shipped kind gets the shipped guide; guides in a
  configuration file are checked as acme writes them.
- **The pages**: the searches find the Czech words they show (targets, modules, pickers, the
  states of tests and certificates); the deployments' search finds a target's kind; a window's
  search is kept when a dialog over it closes; the Modules count says how many the filters left;
  the certificate picker says where a certificate is deployed already; the deploy dialog keeps
  the options typed when the same target is picked again; the accounts' role read whole, on a
  phone not under the buttons; a dialog whose first box cannot take the focus gives it to its
  buttons; FortiGate and other modules' texts in Czech.

## 1.0.94 - 2026-11-12

- **FortiGate in versions by FortiOS's API**: *FortiOS 6.0 - 6.4*, *7.0 - 7.4.1* and
  *7.4.2 - 8.0* (the inspection profile's and the VIP's certificate fields changed shape), and
  the plain one that finds the version itself. A version that does not fit is refused before
  anything changes, and says which to choose.
- **Setup guides for every module and version** - how to set up the other side (FortiGate's
  `config`/`set` commands, an API account and least rights, DNS providers' tokens, CAs, the
  servers a test checks), in English and Czech. A button *Setup guide* in the forms, the
  windows of targets and tests and on the page *Modules* shows it over almost the whole page,
  with contents, the module's versions and both languages. **Every block of commands has its
  Copy button**, and a command, path or value in the text is copied by a click on it.
- **A guide is written over on the page Modules** in a new editor: *Visual* (like a document,
  no Markdown needed), *Markdown*, side by side, preview; an assistant putting parts of a guide
  in (the outline with the module's fields, steps, commands, warnings, tips, tables) and
  starting from acme's own text, the other language or another version. *Back to the default*
  gives the shipped text back. Modules of your own carry their own (`guide`, `guide_cs` or
  `<name>.md` / `<name>.cs.md`); written guides are in backups and the configuration file.

## 1.0.93 - 2026-11-12

Bug hunt (four parts: the recent changes, the certificates' logic, the daemon/HA/CLI, the pages):

- **A deployment failed by its test** was tried again every five minutes for good (its count
  of failures put back to 0 by the deployment that went through) and each time said
  *deployed* - event and notice - before *failed*. The wait now doubles, and *deployed* is said
  only after the tests passed.
- **Since 1.0.92 the checks of what is served are the attached tests only** - so a target whose
  module checked its own address (ESXi, vCenter, a BMC/Redfish, UniFi OS, TrueNAS, FRITZ!Box,
  an SSH preset with a port, a domain controller's LDAPS on 636) now gets **that as a test
  attached** with a new deployment (or one moved, or its options changed), and once for the
  deployments made before. The tests after a deployment wait as long as the module did where
  it restarts for long (vCenter, a BMC: 20 × 15 s). The deployment says whether a test checks
  it or none does.
- The answer to a CSR taken kept the **deploy hold** no more (it deployed everywhere and ended
  the hold) and failed after keeping the version on a switched-off certificate.
- **Discover → Apply** stopped half way when a certificate could not be pushed now (left said,
  the rest done); a slot covered by another certificate's deployment no longer gets a second
  one taking turns with it (a deployment naming the slot gives it up; one by auto/nodes/vip is
  said); switched-off certificates are not offered. An empty choice of slots is refused (it
  went to *auto*).
- **web_tick stopped for good** on a certificate whose CN is no host name (a label over 63
  characters): the self-check raised at every tick and nothing reached nginx any more.
- **The guard against writes to the database switched on by itself** (a node joining a cluster
  whose other node has it) re-signed everything the database held - a row written past acme
  included. Now it signs nothing, only follows a heartbeat the other node signed, and a person
  switching it off is kept in the node's own config.json (a meta row could be deleted).
- The VIP's self-check is done again when the address comes to a node (keepalived), and a node
  without it shows none (an old one was shown after a failover). Its failure no longer skips
  the guard's sync (own try).
- The TLS to the database switched off on one node was switched on again ten minutes later by
  the cluster's wish - kept off now.
- A server without its intermediate: the one fetched is kept a day and fetched again when it no
  longer fits (a certificate renewed from another intermediate failed until a restart). A chain
  that fails for another reason (expired, no roots on the machine) is said as it is, not as a
  missing link with *Complete the chain*. The ECDSA certificate's chain state is kept.
- Importing a configuration without the secrets kept the ECDSA second certificate of acme's
  own pages no more.
- `--tls-selfsigned --days 0` made 825 days; a negative one an openssl error - 1 to 3650 now.
- Import from a source named another team's certificate to a scoped account in its job.
- Pages: the search of a certificate's Deployments and Tests takes the states as shown
  (`state:selhalo`), its suggestions stay on the screen; the tests' names are not squeezed;
  *Discover* in an application's window too; a toast "choose the target" goes once one is
  chosen; Discover says when acme is to give a slot a certificate not there yet; the events of
  the chain, of the command line's certificates and of the self-check translated.
## 1.0.92 - 2026-11-12

- **A certificate's window: a search over its Deployments and its Tests** (once there are more
  than three): small, in the section's heading on the right, the same query as every list of
  the pages (`target:`, `state:failed`, `options~/etc/nginx`, `test:`, `where~10.0.`…,
  suggested as typed); the test counts stay those of all of them.
- **What is served is checked by the attached tests only.** A deployment no longer runs a
  check of its module's own after it (a handshake to names it guessed: an application of ours
  to each slot's name, the older *Check what is served* lines): the tests attached to the
  certificate run after it (on that target) and, failing, fail it - as the certificate's Tests
  show. *What happens* shows the same. The deployment says *in place - what it serves is
  checked by the tests attached*.
## 1.0.91 - 2026-11-12

- **An application of ours (acme push): the check after the push** asks first at the
  application's own address (the target's) for the slot's name, then at the name itself. A
  slot named `merit.cz` while `merit.cz` is another server (the company's web) and isemon is
  `monitor.merit.cz`: the certificate was put in and served, and the deployment still failed
  with *serves another certificate*.
## 1.0.90 - 2026-11-12

- **Deploy a certificate**: the target is picked from a list drawn as *Attach a test* draws the
  tests - the search, each target with its icon, kind and address, the default first, where the
  certificate is deployed already said - one at a time (a radio); picked, its options show as
  before, and *Change* brings the list back. From a target's window (*Deploy a certificate
  here*) the certificate is picked the same way (its state, source, names and end), and the
  one given shows as the same row - every way to it looks alike.
- **An application of ours (acme push) - the slots picked, not typed**: *Find the slots* asks the
  application (as Discover) and lists *Automatically / Every node / The VIP address / This one*
  and each slot with its names, what it has now and who keeps it - ticked; a slot not there any
  more stays and is said, another can be added by its id. The command line types the lines as before.
- **Discover on an application of ours**: each slot its own choice - left as it is, **a
  certificate acme has already** (only those holding the slot's names are offered; its
  deployment to the target takes the slot, or one is made) or **a new one** from the source and
  validation chosen for that slot; *One certificate for the new slots* and *Push the existing
  certificates now*. It is the same deployment as one made in the certificate's window - both
  show it.
## 1.0.89 - 2026-11-12

- **The whole chain of acme's own web certificates** (Settings → Certificates and TLS, every
  node and the VIP address): whatever comes - upload, PFX, a signed request, ACME, acme push,
  `--tls-import` - is checked against the system's roots as curl and the other applications
  check it, and a missing intermediate is fetched from the certificate's CA Issuers address
  (trusted only as a link to a system root; a root never sent). The card's *Chain* line says
  it in green or red; **Complete the chain** / **Check the chain**, **Upload the missing
  authority** (a dialog naming the authority missing; a private CA's root kept to check with).
  What nginx has in its file is checked too, and after nginx is given its part acme connects
  to it as a client that fetches nothing - a refusal is an event; for the VIP address on the
  node that holds it. CLI: `--tls-chain`, `--tls-chain-add FILE`. See
  [tls-and-vip.md](docs/tls-and-vip.md#the-whole-chain-1089).
## 1.0.88 - 2026-11-12

- A server that sends its certificate **without the intermediate authority** (isemon with a
  RapidSSL certificate uploaded by hand: *unable to get local issuer certificate* on pairing,
  while browsers said nothing): acme now fetches the missing intermediate from the
  certificate's AIA address as browsers do, and trusts it only as a link to a root of the
  system. The job warns that the server should send its whole chain. Every HTTPS call of
  the modules (targets, sources, checks). What isemon should change:
  [isemon-full-chain.md](docs/isemon-full-chain.md).
- New target **Flowmon** (`flowmon`, Flowmon OS REST API 13.1): the certificate and its key
  into a certificate pair of a reusable TLS setting (what the probes decrypt with), made
  when missing, and/or into the collector's listening ports over TLS. Checked against the
  API document only - the form of the multipart uploads can be switched (*Form of the
  uploads*) should the appliance refuse it. The API has no call for Flowmon's own web
  certificate. See [targets.md](docs/targets.md#flowmon---flowmon-rest-api).
- A cluster put back from a (remote) backup and built again is the same as at the backup:
  the TLS of the connections to the databases comes back as it was set (the wish is kept in
  the database, each node applies it), and the *Guard against writes to the database*
  switches itself on on a node that joins a cluster where it is on (unless switched off by
  hand on that node). Tried end to end with PostgreSQL 16, TLS, VIP, SELinux enforcing
  and the guard on (`test/test_remote_backup_ha.py`).
- Overview → *When certificates run out*: a click on a bar shows the certificates that end
  then, each opening its window. The bars came without their certificates, and a click opened
  the whole list unfiltered. The bar's tip names them too.

- One icon for every Import and one for every Export in the whole application: an open box
  with the arrow going in, or coming out. *Import* had the upload arrow, *Import from a
  source* the download one, and *Export* the download one. The button's words decide, so
  a new button gets the right one. The boxes to drop a file on show the Import icon.
- Bug hunt I, round 1:
  - Security:
    - a certificate administrator of one team could hold or let go the deployments of
      another team's certificate;
    - `acme --api` printed an authority's private key (`cas/export` with a key format).
  - A dual certificate retried for its twin alone took the revoked twin's key again (after
    *Revoke and issue a new one* whose twin failed).
  - A stop or a restart during a renewal:
    - a proof in DNS or a token file put there over SSH is now taken away even after a stop;
    - the copies of a key in /tmp on a target go too (they stayed for good);
    - it is no longer counted as a failed renewal with a backoff and a "Renewing failed"
      notice.
  - Windows over SSH: a script past cmd.exe's 8191 characters (three IIS bindings and RDP,
    a few lines after the import) failed every time. It now goes up as a .ps1.
  - A certificate's own *dual order* setting is read by the regular look too. Off for the
    certificate but on for the source, a job that did nothing started every few minutes.
  - A job gives back only its own lease of a certificate. The second give took away the
    lease of the job after it.
  - Deploy hold:
    - held again, the version waiting stays held;
    - a move to *by hand* ends a hold;
    - the box counts only the targets without the new one.
  - Popups:
    - *Take it out of service* is not a red "cannot be taken back" button;
    - a non-red confirmation (*Forget them*) stays non-red;
    - a button the page had hidden stays hidden after *No, leave it*.
  - *What happens* does not say a test runs after a deployment when tests after deployments
    are switched off.
  - The UI:
    - Esc (or Close) in *Change the source* and *Change names, key, source…* goes back to the
      certificate's window; it closed everything;
    - *The certificate* in a job opened from the certificate's window goes back to it, not
      a second one over it;
    - *What happens*: Close and *Work it out again* in the common order;
    - a certificate's window on a phone: its many buttons three a row and smaller (they took a
      third of the screen);
    - *Find out* on a phone: the table scrolls, not the whole dialog;
    - the hints of boxes marked as data (placeholders, labels) are translated;
    - the note "made from what certificates said" of an owner is translated;
    - *Cancel* is *Close* in every dialog, as everywhere else.
- Bug hunt I, round 2:
  - Import of the configuration with *replace*: a certificate taken away left its versions,
    tests, finished jobs and its rows in meta (hold, move, the portal's requester). A
    certificate given its number later inherited them: held, mailed to a stranger, revoke
    refused, old versions shown. They go with it now.
  - An import without the secrets of an older file put an older certificate over the key of
    the newer one here: the key no longer opened, and nothing could be deployed, exported or
    renewed with the key kept. A certificate's material stays as it is when the file does not
    carry its key.
  - The configuration's file carries a certificate's hold of its deployments, its move and
    its portal requester, under its number there. They were lost: a held certificate was
    deployed after the import.
  - The enrolment pages:
    - an account of acme's own named like a person of the directory got that person's
      team rights (their certificates and keys); it is a member only as `local:NAME`;
    - the person who asked is told when the certificate is issued even when the first try
      failed and the renewer issued it later;
    - the mails to the person who asked (issued, declined) are in the words of Settings →
      Message texts, which were never used.
  - "Certificate renewed" (when notices of what went well are on) is sent for the first issue
    and for a new one after a revoke too.
  - Czech in the alert mails: "2 dny", "1 den" (it said "2 dní"); "obnovení certifikátu X
    selhalo".
  - acme's own DNS server answers a wildcard record (`*.x`) for every name under it (RFC 4592).
    It could be saved and was never served. A record at `@` with several zones set is put at
    the first of them, not at a name made of the whole list.
  - The command line:
    - a private key could not be exported with `--out FILE` at all since 1.0.80 (`--export`
      of a key format, `--ca-export --what key`): the refusal meant for `--api`, which prints
      what it gets, refused every option. A key goes into a file again, and into a pipe with
      `--out -` - not onto a screen;
    - `--import FILE --into NAME` took a certificate of other names (its key dropped), and the
      next deployment put it on the servers. Its names must cover the certificate's, or
      `--force`;
    - two options that do something (`--deploy-hold … --deploy …`) are refused; the first ran
      and the rest were dropped. `--set` beside an option that takes none is refused before
      anything is done, not after;
    - `--check-switch` of a test that is not there says so;
    - `--target-del` of a target in use is refused before the question, and says `--force`;
    - `--deploy NAME` ends a hold set by hand too; the job's words no longer say the hold came
      from a change of the source;
    - `--jobs --limit` 0 or less is refused, as for `--events`;
    - `--json` with `--maintenance`, `--restart-nodes`, `--updates`, `--hand-clear`,
      `--add-directory` and `--mail-test` gives JSON.
  - The console: a certificate's deploy hold on and off; a target or test in use is taken off
    everywhere and deleted when asked.
- Bug hunt I, round 3 - targets:
  - AWS ACM: the EC and the RSA half of a dual certificate (deployments with `variant`)
    in one region get an ARN each. The second found the first one's ARN and was refused.
    A deployment there before keeps its ARN.
  - Cisco ASA: a PKCS#12 import that failed takes its new trustpoint away again. Left empty, the
    next try bound ssl to a trustpoint with no certificate.
  - A10: the key is imported again when the certificate went up and the key did not; the chain
    file is named by the whole chain.
  - Cisco FMC and FDM: a deployment to the devices that failed after the switch runs again on
    the next try. It was never run again and the job said done.
  - Kubernetes: what acme put in a secret and sends no more (a twin gone, `ca.crt` switched off)
    is taken out.
  - Kemp: `[IPv6]:port:protocol` is read right.
- Bug hunt I, round 3 - root's helper and installation:
  - A path PostgreSQL names (its data folder, pg_hba.conf) is written by root only when it is
    postgres's own. A server pretending on postgres's socket could have root write a key into
    the system's CA folder or a line into /etc/sudoers.
  - *Make the database*: an account that is there is not taken over when it is in a role with
    rights over the server (SET ROLE postgres, pg_execute_server_program) or is a group role.
    A database that is there and someone else's is not taken over. MariaDB: likewise, for
    rights over every database or on `mysql`.
  - Modules of your own loaded as root (the console, the command line) are read through
    handles held from their folder down. Checked and then opened by name, a folder swapped
    in between by the acme account was loaded as root.
  - install.sh reads config.json without following a link or waiting on a pipe. A FIFO there
    hung an upgrade.
- Bug hunt I, round 3 - the fixes reviewed:
  - `--ca-sign CA --csr FILE` works again: its `--csr` is not a second action.
  - An account of acme's own on the portal owns a certificate whose owner is its bare name only
    where no directory signs in there. With one, a local "novak" owned the directory novak's
    certificates and could take their keys.
  - The console's deploy hold is in the certificate's menu (it was in the modules' menu).
  - A literal default in a box (`root`, `default`) is not translated. Only the hints of
    boxes marked as words are.
  - A stop while the twin of a dual certificate was issued is a stop, not a failure of the
    twin.
  - A job gives its lease back before its certificate is free here.
  - `--json` with `--mail-test` and `--updates check|start` is JSON only.
  - `--dns-del @` with several zones looks at the first.
  - Importing another certificate's names into one on the page asks first, red, and does it
    if you want (*Import it anyway*).
  - Windows over SSH: the temporary folder with the key is cleaned up after a stop too.
- Bug hunt I, round 3 - the pages, by use:
  - *Take it away* of a module in use with *Take it off everywhere first* asks "Really?" once
    more, as every delete. It went at the first click.
  - Export: *PKCS#1* is offered for an RSA key only, also after another choice in the dialog
    (it came back on for an EC key, and the download was refused).
  - Settings: *Notices by mail* takes mail addresses only, *by SMS* phone numbers only, the
    address of the published CRLs a URL. Anything was saved. A refused setting says why under
    its field and in the page's language; the toast said it only in English, and gone in a
    moment.
  - Czech: a test taken off a certificate said "Pořízeno z" (now "Odebráno"); "before" of the
    hold box was in the wrong place; why a certificate cannot be revoked by its new source;
    the profile's name refused.
  - A request profile saved: its own name is not translated in the message.
  - A request declined on the portal: the person is named without `local:`.
- Bug hunt I, round 4:
  - The difference of the clocks between the nodes is forgotten when there is nothing to
    measure against any more (HA off), or after an hour without a measurement. The alert and
    the metric stayed for ever.
  - The report counts every sign-in and every refused one. It counted the newest 400 only,
    and refused ones earlier in the week were missing.
  - Lines to a SIEM / syslog server are cleaned of secrets, as isemon's are. A password or an
    access key in an event went out in clear.
  - The outgoing mail is kept to a session's teams, as the events are. A certificate
    administrator of one team saw another team's notices and addresses.
  - `acme_cert_renewals_total` and `acme_cert_deployments_total` are gauges, as they are
    counted from the jobs kept and go down when old ones go. The first issues count too.
  - An import of the configuration leaves out a setting that is refused here and says so.
    The whole file was refused. *Notices by mail* takes an address of the machine too
    (`root@localhost`).
  - Kubernetes: what is no more sent is taken out of the secret even when the certificate is
    the same. Cisco FDM: marked before the first switch.

## 1.0.87 - 2026-11-12

- Restart and power off: each node's card shows how long the machine (the OS) has been up
  as well as how long acme has run. It showed only acme's own uptime, which a restart of
  the service set back to seconds. Each node's heartbeat carries it, so the other node of
  a cluster shows it too. `acme --restarts` lists both.

## 1.0.86 - 2026-11-12

- *Change the source* asks what happens to the new certificate (**Then**). The default is
  *Keep it - I deploy it myself*: the certificate is issued and kept, and the targets keep
  the one in use until *Deploy now*. Nothing deploys it by itself meanwhile, neither the
  regular look nor a renewal. The certificate's window says so and offers *Deploy now* or
  *Deploy by itself from now on*. *Deploy it everywhere at once* is what the move always
  did. The hold is also available on the command line (`--deploy-hold NAME on|off`,
  shown in `--cert`) and in the API (`POST /api/certs/hold`). *What happens* shows it.

## 1.0.85 - 2026-11-12

- *What happens* says everything a renewal and its deployments do. It now also shows how
  each test runs for the certificate: after every deployment, only after one on the
  targets ticked (a failure there fails that deployment), or by its schedule only. The
  phase said "after the deployments" for every test. It also shows a test switched off
  for the certificate or as a test, and a certificate switched off or holding a revoked
  one (nothing deployed). Per target it shows a target or a deployment switched off,
  which certificate of a dual one goes there, and a PKCS#12 password acme makes. Under
  *After* it shows the SMS of the notices, the alerts by mail, the SNMP traps,
  Prometheus and isemon, and the longest wait between tries of a failed deployment.

## 1.0.84 - 2026-11-12

- The targets a test of a certificate runs after (*After a deployment on…*) show their whole
  names - they ended in "…" after about 20 characters, and targets named alike ("Linux Unix
  server SSH - …") could not be told apart. A long name wraps; the whole one is also under
  the pointer. The same for the certificates in *Take it away*'s list and in the tests'
  overview.

## 1.0.83 - 2026-11-12

- A source, validation, target or test in use is not deleted, and *Take it away* now
  shows where: each certificate (a click opens it), test, connection, request profile or
  portal setting, with what it does there and whether it can go with it. For a target's
  deployments and a test's attachments the switch *Take it off everywhere first* takes
  them off (each an event) and then deletes it; a certificate issued or validated by it
  is changed first. The refusal names the places (it said "in use (3)"). The same on the
  command line (the places listed; `--force` takes them off) and in the API
  (`GET /api/<list>/uses`, `delete {force: 1}`).
- One order and look for the buttons of every popup: what takes something away red, asked
  again and on the far left; *Close*, the rest and the main one on the right. What starts
  at once - a deployment, an issue, a restart, a switch-over, a move - asks first ("It
  starts at once - go on?"); tests do not. The row's *Deploy it there again now* asked
  nothing; *Revoke* is red now, and *Take it off* of a deployment no longer asks twice.

## 1.0.82 - 2026-11-12
- A deployment's *What it serves*: *A new test…* opens the popup of *Tests → Add a test* (the
  kinds, then the test's every setting) over the deployment's window, which is never closed
  underneath and is back as it was once the test is saved; *Attach a test* lists it then.
  (*Make a test in Tests…* left both windows and went to the Tests tab.)

## 1.0.81 - 2026-11-12
- Overview: *Running out soonest* and *What needs a look* no longer scroll sideways (1.0.80 gave
  the lists a height and a scroll of their own, and their rows' edges overflowed it).

## 1.0.80 - 2026-11-12
- **Backups checked whole** - built rich, put back on a clean installation, compared table by
  table, file by file, and used (secrets, the own authority, renewals, deployments, sign-ins
  with the second step). Fixed:
  - a copy put back by hand (`acme --restore`, the pages) on a new machine said that machine's
    SSH server, time, firewall and console were in place and never put them in - forgotten
    now as by a backup put back; `--restore` also makes the machine the copy's node again
    (`--keep-node-name` keeps it), switches the guard against writes back on and carries the
    settings of its `config.json`;
  - the settings kept only in `config.json` (the site's name, which every backup's file name
    and the "own" backups go by, a language set by hand) come back with a backup;
  - the console at login switched on from the command line or the console comes back;
  - the files of your own modules beside their `.py` and the programs of "script"
    validations (`/etc/acme/hooks`) are in the backup and put back;
  - an older version's copy put back empties the tables it did not have (a mix of the two
    installations before); signatures under a node's old name are taken away;
  - `--export-config` carries the tests and where they are bound, an authority's renewals,
    and the mail and phone of the accounts (what belongs to a person or this key - second
    steps, SSH tokens, destinations, uploaded modules - is said not to be in it).
- **Hunt H, round 1** - fixed:
  - **Deployments over SSH (and Caddy, ESXi, HAProxy, strongSwan, Traefik, Zimbra)**: the new
    file and the copy of the old one are made under names nobody can guess, never through a
    link - a link laid at `<file>.acme-new` by an account that may write the folder had root
    write the private key through it, with its mode and owner; dated copies pruned without
    following a name with a line break; the "not finished" mark is the deployment's own
    (another deployment to the same server took it away); Azure (and every module with long
    settings) keeps each deployment's record apart.
  - **Certificates**: one whose new issue failed after "revoke and issue a new one" is not
    deployed nor taken as current by its tests (it held the revoked one); a key compromise
    revokes the twin's older versions with the same key too; a twin whose revoke failed can
    be revoked again from the pages and the portal; the portal holds a name under another
    owner's wildcard (or a wildcard over another owner's name) for approval.
  - **Cluster and system**: an OS update stopped while a node was updating is followed to its
    end, a node only drained comes back into service; a plan whose node went silent ends
    failed (it kept the cluster's alerts quiet for good - now six hours at most); a node keeps
    the maintenance a person set; a node switched on again after a power-off comes out of
    maintenance; an upgrade waits for an OS update or a restart going on; the alert of a long
    maintenance says its real length; `dns_port`/`snmp_port` equal to the API's refused; a
    directory's authority or weak TLS changed asks for its password again.
  - **The version line** of 1.0.80 was written with double quotes, which the installer, the
    release tool and the root's upgrade check could not read (an older package would have
    gone in as a newer one): back in single quotes, every reader takes either, and an
    upgrade is refused when the installed version cannot be read.
  - **Command line and console**: `--api` refuses a private key written out (in any field,
    also base64) and does not print private keys; the SSH key `--out` and `--export-config`
    never write through a link and set 0600 on a file there before; a new version of a
    certificate from a file (`--import FILE --into CERT`, the console's *A new version*);
    replacing an SSH key and revoking what an authority signed are asked first; console
    forms scroll (a form of 28 fields showed 14 and was typed into blind); no trace without
    a terminal; `--limit` capped; `--note ""` empties a certificate's note; `--debug` alone
    from a script no longer starts the daemon; `--json` for `--console-at-login status` and
    `--ssh-token-add`; existence checked before `--yes` for `--ca-revoke` and
    `--os-roots-remove`; the installer leaves masked and switched-off PHP-FPM units alone;
    the sandbox's `ReadWritePaths` documented for folder backups and *This machine* targets.
  - **Pages and mails**: the weekly report and the alert mails are in their language - the
    events, alerts and certificate lines through the pages' own translation, on the server
    (`acmelib/i18n_mail.py`); "Connection refused" and the other errors of the network in
    Czech everywhere; numbers and their words agree where they stand apart (3 testy, 3
    kroky, 45 certifikátů, 3 selhávají); the portal's window is fresh after a revoke or a
    decline, its rights read "Smíte: vidět, spravovat…", a revoked certificate says so;
    Enter in a popup's box presses its one main button (and in the portal's new password);
    the overview lists past eight what needs attention; one Czech name for the enrolment
    pages; Owners and teams no longer says nothing may be asked for when request profiles
    exist; wording (Vyřadit z provozu, Poslední, Hesla se neshodují, …).
- **Hunt H, round 2** - the fixes of round 1 gone over again, the sources' modules, the pages
  end to end, the data and what runs at once; fixed:
  - **Two jobs on one certificate**: a job takes its certificate in the database, in one
    statement - the command line beside the daemon, or the other node on a shared database,
    both passed the check of their own process and both ordered (the second one's certificate,
    perhaps paid for, was lost); version numbers taken again when another took the same.
  - **Files on targets**: written with umask 077 under names nobody can guess (round 1's
    noclobber made the new key readable by others for a moment); a failed deployment takes
    away only its own temporary files, never another job's in the folder; zone files of
    "SSH + zone file" validations the same way.
  - **Sources**: AD CS and SCEP keep a request waiting for approval by the certificate, with its
    key and CSR - a renewal (a new key each try) filed a new request each time and an approved
    one was never fetched; DigiCert's twin of a dual certificate is an order of its own.
  - **Accounts**: an administrator's reset of the second step can no longer be written back
    over by a sign-in or a passkey change going on at that moment; accounts with Czech
    capitals are found on a PostgreSQL database with the C character type.
  - **Bounds**: a portal request of a million names refused before it is read (it took the
    processor for hours); a team's events read in bounds; one ACME account per source made
    when its first renewals run at once.
  - **Import and restore**: `--import-config` matches an authority's renewals and a
    certificate's tests by what they are (by number, it wrote over another authority's
    history); a restore leaves this machine's listen addresses alone; marks and long keys kept
    by 1.0.79 are still found.
  - **Pages**: Enter never sets a deployment or an issue going (a half-typed path was
    deployed); *Try again* of a failed job deploys again when only the deployment failed,
    else asks first; a deployment with no file is not saved; an account kept to its teams sees
    only its own certificates' events (not the accounts', the portal's, nor a deleted
    certificate of another team); the portal offers no *Approve* of one's own request; *Revoke*
    again for a twin whose revoke failed, on the pages and the portal; the Options column with
    the files again; the forced password change takes Enter; *Stop* is heard while a job
    waits for its tests; a pattern the same in Czech still has its parts translated; the
    report and alert mails translated by the same rules as the pages; the installer always
    starts the php-fpm acme's pool is in.

## 1.0.79 - 2026-11-11
- **Hunt G** - the whole application gone through again, not only the latest changes; fixed:
  - **Deployments**: a deployment whose files were written and whose reload or restart was then
    cut off (the SSH session dropped, the job stopped) is finished the next time - every file
    found the same no longer means "nothing to run" while the last one here did not go through
    (Linux/Unix over SSH, Caddy, ESXi, strongSwan, Traefik, Zimbra, Kubernetes with restarts);
    Vault writes again when *Include the private key* changes, Azure Key Vault when PEM/PFX
    changes; Windows (WAP, LDAPS, Exchange) and Docker Swarm take only their own old
    certificates by the whole name (*acme-www-* took *acme-www-api-…* too); Docker Swarm keeps
    the owner and mode a service had for the file; Nutanix keeps what was deployed per cluster;
    MikroTik over SSH keeps an old certificate still in use; WHM `installssl` sends the key in
    a POST form, not in the address (WHM's access log); HAProxy's temporary file has a name
    nobody can guess; Cloudflare lists past the first 50 certificates.
  - **Validations**: IPv6 addresses taken (HTTP-01 proves IP certificates); OCI DNS and Vercel
    read every page; a record made is taken away by its id too; the built-in DNS probe asks the
    way the DNS set says (host:port, DoT, TCP).
  - **Certificates**: a switched-off certificate is not renewed or deployed by anything; a
    revocation not done in full stops "revoke and renew"; a revoked main or twin certificate is
    not "the current one" for tests; a sub-CA may only sign for what the authorities above it
    may (name constraints); a certificate's name from the portal or a request profile is made
    one the rules take; an id written as `1.0` no longer reached another team's certificate.
  - **Teams**: a scoped account no longer sees other teams' free-text owners, the certificates
    behind a push target's slots, or other teams' certificates under an authority.
  - **Sign-in and accounts**: adding a passkey asks for the password (a session left open, or
    its cookie, put the owner's app away for a second step of its own); the list of passkeys is
    not told before the second step nor to a switched-off account; deleting or switching off a
    local account ends its sign-ins on the enrolment pages too (a new account of the same name
    took them over); the address a portal code went to is masked in Events.
  - **Cluster, backups, alerts**: replication is healthy only with the other node's slot active;
    MariaDB with *verify-full* and no CA named checks the name against the system's
    authorities; a backup cut short is not counted as one (and its leftovers go); a restore
    keeps the larger SNMP start count; a node whose restart or OS update failed comes out of
    maintenance; maintenance silences the cluster alerts for six hours at most, never after a
    rebuild that failed - and a node long in maintenance is an alert; events older than the
    last look are not mailed as new after alerts are switched back on.
  - **Command line**: `--api` refuses every secret a module or directory keeps sealed when it is
    written out (`bind_pw`, `eab_hmac`, `service_account`...); `--set` beside another option is
    refused (it was dropped); an empty name (`--cert-del ""`) and an option given alone say so
    in one line, not the whole help - and never start the daemon in the foreground; the server
    of a kept secret is changed with the secret in the same command, and the console asks for it
    in the same window; `--api GET /api/db/download` is refused (it raised, after writing
    "downloaded"); the private half of an SSH key needs `--out`; `--status/--check --json` say
    `ok` as the exit code does; `--status` asks the daemon on the port it runs on; `--json` for
    `--set`, `--tidy`, `--version`; things that are not there are said before `--yes` is asked;
    `--tls-hsts` and `--hours` out of range refused; *The pages (nginx, PHP)* in the console
    finds `php8.x-fpm`; the console's *Change it* of a certificate sends only what changed;
    after new names, `--cert-edit` says `--renew` issues it now.
  - **Pages**: *Clear* in Events puts back the page's own window (all history), not the last
    24 hours; Jobs filtered to *running now* counts and pages only those, and says *No job
    matches the filter*; *Save and deploy now* is the person's job, not "renewed by itself" as
    well; the first issue of a new certificate is an *issue* job, not a renewal; the Options of
    a deployment show its files, not `skip_same true / backup_format dated`; *Try it* of a test,
    the isemon/SIEM trouble lines, *This would do:*, a key's bits, the name and monogram of a
    new module, "Connection refused" and the like, and a name of capitalised words before
    *deleted* are in Czech; the end of a time window is *Do*, not *Komu*; one name for a job of
    tests (*test run*); the placeholders of a new intermediate authority; *Nothing matches* in
    the module picker; Enter sets the octal mode of a file.

## 1.0.78 - 2026-11-11
- **Deployments that write files: nothing replaced, nothing run.** Each file is compared by
  SHA-256 also on *Deploy now* (before, it wrote every file again; only *Leave a file alone…*
  switched off does now), and each file is said in the job - *the same SHA-256 (…) - left as it
  is*, *SHA-256 there …, new … - replaced*, *not there yet - written*. When no file is replaced,
  no command, test, script or reload runs and the deployment is fine (*unchanged … nothing
  replaced, nothing run*); when at least one is, they all run. Linux/Unix over SSH, this
  machine, Caddy, ESXi, strongSwan, Traefik, Zimbra (Windows: the files; its store import as
  before).
- A deployment's *What it serves* attaches the tests of Certificates → Tests and binds them to
  the target; a test is made there only (*Make a test in Tests…*), with every setting it has -
  the quick form with five of them is gone.
- **Monitoring (SNMP, Prometheus)**: each deployment (`acmeDeployTable`,
  `acme_cert_deploy_state`), each test of a certificate (`acmeTestTable`,
  `acme_cert_test_state`, `acme_cert_tests_failing`), each source, validation, target and test
  (`acmeModuleTable`, `acme_module_failing`), each authority of acme's own with its CRL
  (`acmeCaTable`, `acme_ca_*`), the key and the twin of a dual certificate and its failing tests
  in `acmeManagedCertTable`, more counts (tests, failing, jobs running, modules failing,
  authorities ending, deployments), and this node's disks, newest backup and clock
  (`acme_disk_used_ratio`, `acme_backup_last_timestamp_seconds`, `acme_clock_*`) - all in
  `acmeMetricTable` too. A **failing test is among what the alerts see**: an SNMP trap, the
  overview, `acme_alert` - not mailed a second time (its own notice says it). ACME-MIB updated;
  `acmeManagedCertStateNum` has a number for revoke-failed, deleting, pending-approval,
  declined and held (they were 0, "new").
- Hunt F, fixed:
  - a certificate administrator could make a test with any host, port and connector (*A new
    test of this target*: the route is gone; `verify` in a deployment's options is a full
    administrator's), and could try settings nobody saved through discovery, a module's
    catalog and the SSH key's *Try* - acme connected anywhere and said back what answered
    (refused, as *Test* is);
  - a certificate administrator could write the private key where they chose with the format
    words `haproxy`, `combined` or `rsa` (seen as the key now);
  - a validation renamed: the certificates' own settings of it were lost, and saving their
    profile refused;
  - a module that did not load: saving its form wrote the dots over a kept secret, and a new
    one unsealed (refused now - its name, note and switch can be changed);
  - a deployment taken away or moved: its tests still named the old target and never ran
    again;
  - "Check what is served" made into tests: a bare IPv6 address was split wrong, a target's
    own port (Proxmox 8006, Synology 5001...) became 443, a deployment moved lost it, a test was
    left attached to nothing, and a test run after every deployment did not fail the
    deployment; a deployment failed by a test is said (event, notice) and not failed twice;
  - importing a configuration with `split_mode=arbiter` stopped the import;
  - SNMP: one failed trap kept the alert "traps do not go" open until a restart; GETBULK
    answers past the manager's size (or UDP's) are cut or *tooBig*;
  - a log file that could not be written stayed "in trouble" after writing files was switched
    off;
  - `--node` with a node not heard of waited 90 s and said "no answer" (said at once now);
  - the local target failed every deployment when the place of its copy was a link.
  - the page: a job of tests titled "check #N" in English; the tests' events (saved, attached,
    taken off), a test's note made from a deployment and the deployments' new file lines in
    English; a test without *Connect to* shown as "its first name:443"; the chart's note half in
    English after a reload; a test switched off and on again for a target no longer "after every
    deployment"; "on its schedule only" said while the regular runs are off (nothing runs it -
    said so now); the names of the copies cut off in their list (shorter now); *Make a test in
    Tests…* a link among buttons; on a phone the tests of a target overlapped and the facts of a
    target or certificate went a letter a line or were cut off.

## 1.0.77 - 2026-11-11
- **Check what is served is a test now**: a deployment's window has *What it serves - tests*
  and *Add a test of what it serves* (the protocol - TLS, HTTPS, SMTP, IMAP, LDAP...; the
  server, by default the target's address; the port; the SNI; the connector, by default the
  target's own). The test is attached to the certificate and runs after each deployment on
  that target - **one that fails fails the deployment** (tried again, alerted), as the old
  check did - and also on its schedule, with its history, the chain and names checked, in the
  report and in isemon. The old field could not reach a target behind a connector, checked
  only which certificate, and had to be filled in twice. The `verify` of every deployment
  became such tests on the first start (`--set verify=HOST:PORT` still makes one); a test may
  go through a connector of the targets too.
- A deployment's *What it serves* is the certificate's tests seen from that target - the same
  binding as the test's own window, nothing of its own: a switch on each test (runs after a
  deployment here, or not - it stays on the certificate), a bin to take it off the certificate
  altogether (asked first), *Attach a test* (of Certificates → Tests) and *A new test of this
  target…*. A test's *When it runs for this certificate* is three cards to choose from (after
  every deployment, after a deployment on…, on its schedule only) with the targets as cards
  to tick, under a head of what the test is, where it asks and how it went last.
- Overview → *When certificates run out*: the window to choose - the next 4 weeks (by day), 12
  weeks, 6 months, a year, 2 years (by month), 5 years (by quarter); kept in the browser.
- **Every target that writes files** on the machine it reaches - Linux/Unix over SSH, this
  machine, Windows over SSH, Caddy (files), ESXi, HAProxy, strongSwan, Traefik, Zimbra - has
  the same two choices, both on by default and each can be switched off:
  - **Leave a file alone when it is the same (SHA-256)**: each file compared with the one
    there by its SHA-256 first (`sha256sum`, `Get-FileHash`); only those that differ are
    replaced. The job says which were left (*left as they are, the same SHA-256 there
    already*) and the deployment is fine (green), never failed - when every file is the same
    and acme had deployed it there, nothing is done at all; when the files are the same but
    the last deployment did not get to its reload, nothing is written and the commands run.
    Before, one changed file had all of them written again.
  - **Keep a copy of a file replaced**, with **Name of the copy** to choose:
    `name.20261111-153000.bak` (the default: its original name, the date and time, `.bak`),
    `name.2026-11-11.bak` (one a day), `.acme-backup/name.20261111-153000.bak` (in a folder
    beside it - the default of HAProxy and strongSwan, which load their folders whole, and of
    the HAProxy preset) or `name.bak` (the last one only); *Copies kept* (5) deletes the older
    dated copies. A failing test or reload still puts the previous files back either way. The
    old switch *Keep the previous files as .bak* is read as this switch. A temporary
    `.acme-prev` copy is no longer left behind after the files were put back.
- Settings → Accounts: *Czech and Slovak letters in names* and *Letters of other languages in
  names* side by side (one stood before the groups, the other after them).
- Console (`acme --console`) - what the pages do, also there: **Tests** (add, change, try, run,
  the SSH key), a certificate's tests (attach, run, after which deployment, switched off for
  that certificate, take off), **Run the tests** with a report by mail / SMS, import a
  certificate or a new version, a self-signed one, a certificate switched off and on, **Change
  the source** (keeping its deployments and tests), the SSH key of a target / validation / test,
  isemon's first full sync, and a directory's certificate check, weak certificates and CA.
- Console, fixed: a choice whose value is not offered now (a CA switched off) was changed to
  the first one and saved on any edit - it is kept, marked so; fields under *More* that
  depend on a main one (a DNS server's flavour: rndc, named.conf, the serial...) were never
  shown; an SSH key field was a plain text box (the key on the command line, refused there); a
  value of several lines broke the form; a connector was offered as a place to deploy to;
  *Deploy it now* after adding one deployment ran every deployment of the certificate; *DNS
  sets* drew over the menu; *These users…* asked over the screen; Ctrl+C ended the whole
  console (now: back, as Esc); the items' letters (`c`, `k`...) did not choose them; a list
  whose command failed said "none yet"; *Check names* offered a dry run after a failure; a
  directory changed from LDAPS to StartTLS kept port 636; `q` went back in some lists and left
  the console in others (now it leaves everywhere); a by-hand certificate offered *Renew it
  now*.
- Command line: `--check-after ID any|-|TARGETS`, `--check-switch ID on|off`, `--check-run ...
  --report-to ADDR|alerts --sms-to NUM` (the report of *Run the tests*), `--plugin
  check/KIND` (the tests' modules), `--verify-cert on|off` for a directory (`--no-verify`
  could only switch it off). `--check-run all|cert:|test:` no longer runs a test switched off.
- Tests: a test connector without its old list of tests broke every list of tests (`acme
  --tests`, the page's Tests) - `(x in None) or []`.
- Hunt E, fixed:
  - a certificate stuck in *deleting* when its job was cancelled, stopped or the daemon
    restarted: it goes to *revoke-failed*, to be deleted again;
  - a deployment moved to another certificate or target kept the old one's "deployed" state;
    a connector could be saved as a deployment's target;
  - a certificate switched off could still be renewed or deployed by hand; one switched on
    again after its end said *ok* instead of *expired*;
  - revoking a certificate imported, made from a CSR, or of an earlier source than the one it
    was moved to, asked the wrong authority;
  - a target renamed: the tests that run after a deployment on it, and the targets going
    through it as a connector, kept the old name;
  - the SSH session to a target through a connector left the connector's session (and its
    key in a temporary file) open when the target refused; the key scan of a target behind a
    connector tried it directly;
  - Settings: a change that ended the two-factor sign-ins was made before the settings were
    in force; the split choices of the High availability card could be set from elsewhere
    while the nodes were apart;
  - sending the logs: a target removed from the list stayed "in trouble" (isemon, syslog), a
    log file written again stayed in trouble, and the last lines could be cut at a stop;
  - `acme --isemon-test` / `--isemon-sync` said done when nothing was sent (exit 1 now);
    `--ha-renamed` checked nothing; a few options took an empty value; the 2FA message of the
    command line was wrong.
- The page: a module's vendor (*Public CA*, *Connector*, *Protocol*, *Standards*), the targets
  and validations in the deployment and *Change the source* windows, the templates *A Docker
  container* / *Any systemd service*, notes acme writes itself (*made on the first start*,
  *command line*, the seeded sources' descriptions), the SSH banner's example and the root
  helper's message are in the page's language; Czech for the events of the moves, the isemon
  sync, the tests' "after", the report, the isemon trouble ("lines held for it") and the header's
  problems; *4 testy ze 2 certifikátů* in Run the tests; the count over Targets / Tests is of
  the view shown (a connector is not counted among the targets); a test attached to nothing
  says *not attached* instead of *failing*; a connector's icon says SSH; a CA's *What it
  signed* fits its window (the names went a letter a line); the files of a deployment have
  more room; on a phone the buttons of a window are two a row, all in sight (the row that
  scrolled sideways opened with Delete and Close out of sight).

## 1.0.76 - 2026-11-11
- Tests: a test switched off on Tests (for every certificate) no longer runs after a
  deployment. Before, only its switch on the certificate was looked at there; the tests run by
  themselves already looked at both.
- A certificate's deployments: a switch for each - *Switch it off here* - as each of its
  tests has one. It concerns only this certificate on that target: kept with its options, and
  not deployed there until it is on again. The target and its other certificates go on as
  before.
- Tests: **each test chooses its connector itself** - *More → Through a connector*, as a
  target does. It is then connected from that server (`ssh -W`). The tests' connector is now
  called *Connector over SSH*; its old list *Tests run from there* moved under More and still
  works the older way. Only a connector with tests ticked is offered when a test is attached.
- Targets and Tests: a switch above the table - *Targets | Connectors* and *Tests | Connectors*,
  each with its count. A connector's row counts what goes through it, and its settings column
  says *through the connector X*.
- *Add a target* and *Add a test*: the connectors in a group of their own, first.

## 1.0.75 - 2026-11-11
- One scroll everywhere. Sources, Validation, Targets and Tests are as tall as the window: the
  heading, the search and the pages stay and only the rows scroll, as on Certificates, Jobs and
  Events. Before, the page and the table scrolled one inside the other. Events has one scroll
  too: the daemon's own log, a second card under them, is now a button that opens it in a
  window. In Settings a table no longer scrolls inside its pane (People, The database), and
  neither does the configuration sample of High availability.
- Certificates: the row of one renewed by hand (imported) no longer offers *Renew it now*. It
  only ended in "it has no issuer"; it is renewed by importing a new one.
- Targets: a connector of their own - **Connector over SSH** (`ssh_connector`), a Linux server
  defined under Targets. A target over SSH chooses it in *More → Through a connector*, so the
  connectors of the deployments and of the tests can be different servers (the tests' ones are
  still offered, marked). Nothing is deployed on a connector: it is left out of the targets a
  certificate can go to, and a deployment on it is refused.

## 1.0.74 - 2026-11-11
- Targets over SSH: **Through a connector** (More). A server only another network reaches is
  deployed to through a connector of the tests (a Linux server, *Tests on a server over SSH*).
  acme signs in there first, reads the target's host key there and reaches the target with
  `ssh -W` (ProxyCommand). Nothing is installed on the connector. This works for every target
  that signs in over SSH: Linux, Windows over SSH, HAProxy, Caddy, ESXi, pfSense and the rest.
  *What happens* and the job say it.

## 1.0.73 - 2026-11-11
- Certificates: **Run the tests…**, for every certificate (a button above the list) or for one
  (▶ in its row). A popup lists the tests with how each went last. Choose **Only run them**, or
  **Run them and send a report**. The report is a mail with every result grouped by
  certificate, and the subject says how many are fine, warned and failed. It goes to the
  report's addresses or those typed. With SMS on, one line can also go to the numbers given. It
  is sent once the tests are done, and a report that cannot go is said in the job, not
  failing it.

## 1.0.72 - 2026-11-11
- The files on a Linux target: **After the files → From a template…**, a picker of 28
  applications (nginx, Apache RHEL/Debian, HAProxy, Caddy, Postfix, Dovecot, Exim, OpenLDAP,
  PostgreSQL, MySQL, MariaDB, Proxmox, Grafana, GitLab, Tomcat… and any systemd service).
  Choose how each takes the new certificate: **Reload** (no downtime), **Restart**, or **Hard
  restart** (the configuration tested, the service stopped, its leftover processes ended or
  killed, started and checked). It fills the test, the reload and the check after it, shown
  before they are used; the unit and process name can be changed.

## 1.0.71 - 2026-11-11
- isemon: **First full sync** (Settings → isemon, or `acme --isemon-sync [DAYS]`). It sends
  everything acme holds of its certificates once: every certificate, deployment, attached
  test, target, source, validation and authority as it is now, then the history of the
  certificates' events and every job step by step, each with its own time (365 days by
  default, 0-3650). The lines are `acme-jobs`, `kind=sync`, each with `sync=<id>`. Nothing
  secret goes, and the sending is paced so no live line is dropped. The pages show how far it
  got. docs/isemon.md describes every field.

## 1.0.70 - 2026-11-11
- A new target: **Omnissa Unified Access Gateway (UAG)** (`omnissa_uag`). It replaces the
  certificate of its Internet-facing services (END_USER - Horizon, Web Reverse Proxy, Tunnel),
  of its admin interface (ADMIN), or both (admin last), through the UAG admin REST API on 9443
  (`PUT /rest/v1/config/certs/ssl/{end_user|admin}`, the key and full chain as PEM). It signs in
  by a JWT token (`/rest/v1/jwt/login`) or HTTP basic for an older UAG. The same certificate is
  sent again only when the UAG no longer has it. Test says the UAG's name. Built from the UAG's
  OpenAPI document and VMware's documentation (docs/targets.md).

## 1.0.69 - 2026-11-11
- A certificate's window → **Change the source…**: a wizard that moves a certificate in use to
  another source. An imported one goes to Let's Encrypt or an authority, an issued one to
  another source or to by hand (renewed by importing). It shows the source now → the source
  from now on, what stays (the certificate in use, its deployments, tests, versions, owner,
  tags) and what changes. It asks for the key, the validation (checked as when adding), the
  source's settings and the renewal, then whether the first certificate comes now or at the
  next renewal. The move is an event of its own. A certificate the new source never issued is
  not offered for revoking at it.

## 1.0.68 - 2026-11-11
- The files on a target: the owner[:group] field wider (at least 150 px), so www-data:www-data
  fits.

## 1.0.67 - 2026-11-11
- The files on a target: the button of a file's mode as tall and wide as the fields beside it
  (it was a thin strip).

## 1.0.66 - 2026-11-11
- A certificate's tests: **No deployment** beside *Every deployment* and *The targets chosen*
  (Attach a test → Options on this certificate, or the gear of one attached) - no deployment
  runs the test; only the regular runs of the tests (and Run it now) do, alerting as ever.

## 1.0.65 - 2026-11-11
- The files on a target: the mode of a file chosen in a popup of tick boxes as chmod's (read,
  write, run for the owner, the group and the others; set user/group ID, sticky) with its octal
  number, both ways - any mode (0700, 0750, 0755...), or the default; only six were to be chosen.
- A certificate's tests tied to its deployments, chosen when a test is attached as a
  deployment's options are (Attach a test → Options on this certificate, or the gear of one
  attached): after a deployment on **one target** (the default), on **several targets**, or after
  **every deployment** (every test attached before is so). Deploying on rpki1 tested rpki2 too,
  waiting for its own deployment. The tests' table says which.
- The TLS tests (https, smtp, imap... ldaps): **Check the chain sent**, on by default. Off, a
  server sending its certificate without the intermediates is no longer a warning - for a server
  whose clients have them.

## 1.0.64 - 2026-11-11
- The files on a target: a quick layout **Full chain, chain, key** - the certificate with its
  intermediates where the server sends it from (nginx's ssl_certificate, Apache 2.4.8+'s
  SSLCertificateFile), the chain alone beside it (nginx's ssl_trusted_certificate for OCSP
  stapling) and the key. A server sending only its own certificate is what the test after a
  deployment says as "the server sends no intermediate certificate".

## 1.0.63 - 2026-11-11
- **The SSH key of a target, a validation or a test works again** - Make a key, Use my own,
  Download, Forget and Try reaching it all said: there is no target module (an empty name). A list
  field's own variable in the form hid the form's options, so the key card knew neither its
  module nor its row (nor did the catalog picker of a form).

## 1.0.62 - 2026-11-09
- Bug hunt over what came since 1.0.53:
  - Trusted roots of the system: the system's tool is run again after it failed (a removed
    authority stayed trusted while every node said "applied"), and a node is "applied" only when
    every authority is in the system's list itself; one large authority no longer stops the whole
    set at root.
  - Cluster: a row only one node may make (the cluster's authority for isemon's TLS too, the
    1.0.42 password policy taken over, the daily look for new versions) is made by the lead once
    the other node is heard - both upgraded at once took each other for gone and both made it,
    stopping replication; a setting not saved after root took a new network no longer sends the
    job back to the old address while the machine restarts onto the new one; the split rule waits
    long enough for the other node's /healthz; tries again after a step of the clock back.
  - To be done by hand: Back to permissive asked on these pages is not "SELinux was switched off";
    a forgotten node takes its bands with it; Look again and Done stay usable; the header's
    tooltip counts problems and steps apart; the events' words in Czech.
  - Smaller: the AD 2025 warnings drawn as warnings, an old (v1) root not taken for a server's own
    certificate, "120 authorities" in Czech with its number.

## 1.0.61 - 2026-11-09
- Active Directory on Windows Server 2025 (docs/active-directory-2025.md): a sign-in refused for
  want of LDAP signing (result 8, strongerAuthRequired - a plain-LDAP directory) is said in words
  with what to do; a controller given by its address whose certificate names it by name is told
  to be given by its FQDN; the directory's "Check it" warns of what will not work once the
  controllers are new - plain LDAP, an address, the server's own certificate kept as the
  authority, "Take old, weak certificates" still on.

## 1.0.60 - 2026-11-08
- SELinux → the report: the domains the programs run in (processes.txt) were empty - `ps -eZo`
  is refused by procps; now listed, and what ps said is written if none of acme's programs is.

## 1.0.59 - 2026-11-08
- **Settings → Certificates and TLS → Trusted roots of the system**: your company's root and
  intermediate authorities trusted by the whole operating system of every node - curl, dnf, LDAPS
  to a domain controller, mail, syslog over TLS and acme's own connections. Added beside the
  distribution's list by the system's own way of local additions (update-ca-trust on RHEL, Alma,
  Rocky; update-ca-certificates on Debian, Ubuntu), which goes on coming with the system's
  updates; only acme's own files (`acme-<fingerprint>`) are ever written or taken away, what
  somebody else put there is shown and left. Checked as it is pasted (a server's own certificate
  or a private key refused; ran out, SHA-1, a short key, an intermediate without its root said);
  in a cluster the set is the cluster's and each node says whether it has it. Also `acme
  --os-roots`, `--os-roots-add FILE`, `--os-roots-remove FINGERPRINT` and the console
  (docs/trusted-roots.md).
- SELinux, as otp 1.0.265 has it: the other node's PostgreSQL port labelled (asked last, so one
  refused stops nothing else) and PostgreSQL allowed to read the authority of the link's TLS - under
  enforcing, replication between the nodes stopped; the module put in on a node without the pages
  too; a port type the root helper does not know yet (a newer daemon mid-upgrade) left out with a
  word instead of refusing everything; Back to permissive refused under high security; a look or a
  report never takes the place of a step not done yet; "applied at" kept in root's folder alone;
  the report says the ports of the DNS server, SNMP and the SSH gate.

## 1.0.58 - 2026-11-07
- Cluster: a subscription left on the other node's old address (a move that failed half way) is
  put right by "Change the addresses" again - acme read the address from PostgreSQL where its
  account may not (only the superuser may), and always found "nothing to change"; it keeps the
  address it set now. In the split rule's priority mode the preferred node is taken for down only
  when its own /healthz says its database (or its daemon) is down - a connection to 443 alone was
  enough, and with 5432 refused by a firewall (a node re-addressed, its old address let in only)
  both nodes served. acme 1.0.42's password policy is taken over by one node of a replicated
  cluster only (both upgraded at once wrote the one row twice and replication stopped). A signed
  row deleted goes with its signatures.
- The certificate manager's jobs are a log: forgotten with the events and logs older than N days
  (Settings → The database) - never one queued or running - and a copy put back without its logs
  keeps the jobs here as they are, dropping a queued one (it named a certificate of the data
  replaced). They were only ever forgotten after "Jobs kept (days)".

## 1.0.57 - 2026-11-07
- The database's encryption and the link's: one certificate, renewed by the link alone - a
  certificate of Settings → The database made before the link's TLS was switched on was renewed
  beside it at each of the link's renewals, from another list of names. A connection to the
  database on the same machine moved back to no TLS (its certificate not good for a while) goes
  encrypted again by itself once it works - every 10 minutes it is tried; it stayed without TLS
  for good. The card says so after a restart too.

## 1.0.56 - 2026-11-07
- **Re-addressing a node of a cluster** (Settings → Network → Change it and restart), the findings
  of otp's test matrix gone through in acme:
  - a node whose host name is short (`acme1`) could not be re-addressed at all: root refused the
    name the machine has (a new short name is still refused);
  - the other node's address compared as text: 10.0.0.1 was "in" 10.0.0.12 and refused, an IPv6
    address in another form taken for another; the node's own certificate kept naming its old IPv6
    address;
  - Keep dropped the other node's pg_hba line in use after a change of the gateway, the DNS or the
    name (old address = new one); root also leaves such a line alone;
  - a second IPv4 address of the profile is kept (it vanished), and the other node is told the new
    address only when the nodes replicate over the one changed; an IPv6 change taking away the
    address the nodes replicate over is refused; the SNMP agent's own address moves with the change,
    saved once root has taken it;
  - the order: maintenance and the VIP address leaving first, then the other node told; a change is
    refused while the other node answers but is out of service or its own network is on trial, and
    going back after a trial waits (up to 30 min) while nobody else serves; going back is never
    refused for its gateway (an on-link one outside the subnet);
  - a failure half way, a restart of the service in the middle or the one-hour give-up put back the
    settings, config.json and the certificate as they were (they stayed on the new address); a
    failed tell after going back is tried again until the other node is told.
- Cluster: a planned change (a node changing its network, a restart) is said as expected (warn) in
  the history and quiets the alerts, not reported as failures; the preferred node of the split rule
  being re-addressed lets the other serve; in a shared-database cluster keepalived follows the other
  node's published address; a VIP of another address family than the nodes' no longer leaves the
  web part refused for good; the cluster's authority for the database's TLS is made by one node
  only (both made it, replication stopped); the link's TLS waiting only for the other node finishes
  once it passes (it waited an hour); the preferred node is not changed while the nodes are apart;
  `acme --ha-forget` keeps the maintenance rows of a node still answering; a node steps aside for
  the directory only toward a node whose clock is right too; only the lead looks for new versions
  in a replicated cluster; nginx's certificates read where root puts them.

## 1.0.55 - 2026-11-06
- To be done by hand → Done lately: **Clear** at the right of its heading - exactly the rows shown
  are taken (one come meanwhile stays), never what is still to be done; said in the events. On the
  command line: `acme --hand` (what waits, with ids, and Done lately), `acme --hand-done ID@NODE`,
  `acme --hand-clear`. What waits is told to the full administrators only (the status of another
  role carries none of it).

## 1.0.54 - 2026-11-06
- **To be done by hand** (Settings → Upgrades and maintenance, as upsmon's): what acme cannot do
  by itself - a command to run as root after an update, SELinux switched off (seen enforcing, now
  permissive or disabled), the root helper not set up, nginx's file older than the pages - one band
  per thing and node with the command to copy and since when it waits; Look again (every node at
  once) for what is checked, Done (who, when) for a step that cannot be; Done lately under them. A
  count on Upgrades in the menu (a red ring on its icon), the header's pill, `acme --status`, the
  console, the events and the alerts (mail, SNMP; Settings → Alerts → A step waiting for a person,
  on). The problems under the header stay as they were. A release that needs a step by hand adds
  one check (docs/things-to-do-by-hand.md).

## 1.0.53 - 2026-11-06
- The performance meter in a cluster: the graphs of every node drawn with one delay, so they move
  together; the other node's details are kept in its row (written every 30 s while watched), so
  its panel shows them at once instead of "reading..."; back on the page, the other node's last
  reading is shown at once (dimmed while it is old) and taken anew as it writes again.
- **Your account → Passkeys - Face ID, Touch ID** (while a passkey is a way of the second step):
  the account's passkeys - for which name, added, last used - renamed in place, taken away (never
  the last one), and one of this device added; on the administration only.

## 1.0.52 - 2026-11-06
- Pages: Backups → Download one here says to set the password first when there is none (an
  unlocked backup is never given, the page offered it); a phone's dialog keeps its row of buttons
  whole and the Settings find list follows its box; the API port's help, "cannot look for
  updates", "a passkey (…)" and the meter's "load" are in Czech; the portal's reads refuse
  another site as the admin pages' do; a POST with Origin null is another site's.
- Round 3: "no time limit" counted under the database's lock (two threads at once left it off
  for good); a portal CSR with other names for a certificate issued already is a new request,
  not put to approval (declined, the certificate in use stopped renewing); the portal's way back
  through the balancer is taken from the same site too.
- Cluster: a rebuild never copies from a node whose own rebuild failed half way (both had lost
  their rows); a step of the wall clock is no longer taken for the other node gone (apart at
  once, the VIP moved); the copy's end is read from this database's subscription only; a row of a
  node gone no longer stands for the other node in the clock guard and the split watch; the
  order of acme's own web certificate is taken in one conditional write, not by both nodes at
  once.
- The pages' PHP: a session cookie with a newline at its end no longer ends the request to the
  daemon early (the administrator could not sign in until the cookie was cleared); an Origin of
  another port or scheme of the same host is another site; a name cut in the middle of a letter is
  no longer "a number too big"; the reads of the pages refuse another site first; the portal's
  "sign in through the balancer again" is taken from its own page only; an upgraded nginx gets the
  manifest's type.
- The database: "no time limit" for long work stays off for the whole of it (the indexes made at
  start ran limited again) and on MariaDB lifts the socket's wait too (a long restore was cut);
  a COMMIT is sent inside its transaction (a failed one could be sent again on a new connection,
  the whole lost); MariaDB counts the rows an UPDATE matched as the others do; a target, source or
  validation named with digits only is found by its name, not taken for the one of that id.
- Teams and request profiles: a profile whose only team is deleted is switched off, not opened
  to everybody; a new CSR with other names from the portal waits for approval where its profile
  asks it or another owner's certificate holds a name; a fixed country is kept in capitals.
- Pages: Settings' find box is there on a phone too; Settings → Certificates says how many renew
  by themselves (it said 0); a module's Connector group, the GHz of the cores and the API port's
  help are in the page's language; a select in a dialog's row stays within it; row buttons wrap
  in a column of their own only where there are five or more.
- A look for system updates on a node without the root helper is said once, not asked again
  every 5 s for a quarter of an hour (a line in the log each time); Network → Read it again says
  the helper is not set up instead of a 500.
- Passkeys: Ed25519 is offered only where this machine's openssl checks it (a FIPS one has
  none - a key of it locked the account out); a counter back to 0 after one above it is refused;
  odd answers are refused as wrong tries, not errors; each question is checked as it was taken;
  the signature is checked outside the lock; the question is asked when the form is drawn, so
  the tap calls Face ID at once (Safari); a cancel or a time-out says so.
- "What happens": header lines with a token (a webhook's, an HTTPS test's) are not shown.
- A server serving an expired certificate (or one not valid yet) fails its test; a name with
  accents is matched; a test of a text protocol ends after 2 minutes and 2000 lines whatever the
  server does; a file nested too deep is refused, not a 500.
- Alerts: what was not mailed (the mail server down) is kept and said with the next mail; only
  the lead node checks and mails, one look at a time; SNMP traps keep what the mails hold while
  the cluster is worked on; Integer32 dates after 2038 and DisplayStrings over 255 octets are
  kept in their range; an empty OID is answered; a notice's mail failing no longer stops its SMS.
- Upgrades: the trees before are taken away only once the upgrade has run, and previous is put
  back by a rescue (it pointed at the current one, the one before deleted); the same version
  put in again and failing no longer leaves a working node in maintenance.
- The command line: the console's Delete of an account, a directory and an SSH token works (they
  were refused for want of --yes); --sso-key and --ha-forget ask as every step that cannot be taken
  back; --job --json exits 1 for a failed job; a CA's key never goes to stdout; the TLS and isemon
  exports keep their mode over a file that was there and follow no link; --export-config empties
  the file only when the export is there to write.

## 1.0.51 - 2026-11-05
- **Face ID, Touch ID and passkeys as the second step of the administration**
  (`admin_2fa_passkey`, off by default; Settings → Accounts): after the password, never instead
  of it - one more way beside the app, the code by e-mail and the code by SMS, chosen by the
  account when it sets its second step up at the first sign-in, reset as the others are
  (Accounts, `acme --reset-2fa NAME`). WebAuthn checked by the server itself (the name, the face
  or finger - UV - every time, the signature by openssl, the counter, each question once);
  only on the pages opened by their name over HTTPS (docs/admin-second-step.md).
- The home screen of an iPad: the pages open in a window of their own (apple-mobile-web-app-
  capable), turning with the iPad.
- A home-screen icon: Safari on an iPad or iPhone ("Add to Home Screen") and Android take acme's
  shield (apple-touch-icon, PNG icons, a manifest for the admin pages and the portal) instead of a
  picture of the page.
- Round 3: delete with revoke keeps a dual certificate whose twin was not revoked; a request a CA
  holds is kept for the main certificate and its twin apart; a file whose key is of no
  certificate in it is refused, not imported without its key; an ACME rate limit's Retry-After
  is waited for; the CSR given out for issuing by hand has the profile's e-mail and URI names;
  ZeroSSL's address for EAB is encoded; badSignatureAlgorithm is not tried again for ever.
- Signing in: the portal checks that an account row is acme's own as the admin pages do; a
  directory administrator's session ends when the name belongs to another person now; a
  password that must be changed cannot be "changed" to itself; how long a wrong sign-in takes no
  longer tells which names exist.
- Remote backups: a failed upload no longer leaves its hidden part behind (folder, FTP).
- Round-2 fixes put right: names cut short are as they were (a mark of the whole renamed the files
  of existing deployments - left out); a certificate of a CSR revoked can be issued again for a
  new CSR; --out /dev/stdout and /dev/null work, and /dev/null keeps its mode; a CSR's subject is
  not checked for an ACME source; a signed DNS update's refusal says the server's words; Caddy
  takes a numeric owner; a network change put back restores its DNS setting and the host name;
  the performance meter asks its last two minutes again after a reset.
- Deployments, for a certificate administrator (round 2): Caddy's files and owner, Kubernetes'
  namespace and secret, Vault's mount, path and namespace, strongSwan's folder and file, Traefik's
  folder, the Docker services given the key and the names in an Azure key vault are where the key
  goes - a full administrator's. A haproxy deployment (its file required) or one with Windows'
  store of shared certificates is now made by a full administrator. Caddy refuses a file name or
  owner with a space or a line break in it.
- pfSense and NGINX Unit no longer take another certificate's objects for this one's (a name
  only starting the same); FortiGate keeps a profile's or a VIP's other certificates when it sets
  its own.
- TrueNAS: the private key is no longer on a command line while it is imported.
- MikroTik: the key's file is taken off the router whatever the import came to; an old certificate
  still bound to SSTP or OpenVPN is kept.
- HestiaCP says plainly when a domain was left with no SSL; Proxmox node names cannot change the
  API path; Synology's session id is masked in the debug log.
- Fixes of round 1 put right: the first host key is kept for plain "hostkey" fields too (and under
  the host's name), never from settings only tried, from Discover or from a catalogue; Test in the
  editor of a saved target keeps it again; a dry run checks the key's password too; a certificate
  of a CSR revoked and then failed once is not issued again for that key; a command-line job's
  mark checks the process's start, not only its number; the certificates of a validation are
  filtered before the list is cut.
- acme's DNS server: its settings no longer read the database for every packet; names with an
  escaped dot are matched by their labels; ANY over UDP answers one set of records (RFC 8482);
  TCP connections are counted per /24 or /56.
- The public CRL and certificates of acme's authorities: a limit for each source, not one for all.
- acme-dns: one name at a time (an account keeps two values); RFC 2136: an answer to a signed
  update must be signed.
- An authority renewed with a path length shorter than the authorities under it need is refused;
  renaming an authority keeps it the default one.
- The portal: nobody approves their own request; an approve and a decline at once no longer both
  go through; a name another owner's certificate holds waits for approval; a CSR for a source
  that takes it as it is must have a CN among its names and only the subject the profile gives.
- acme push: Discover works again (it had the modules' path); the names are ordered only as they
  were shown; the first pairing without a code needs the application's certificate checked.
- The command line writes a key file with its mode even over a file that was there, never through
  a link; a notification's subject is one line, and a failure to draw one no longer holds the next
  for six hours.
- The server: SSH is not moved to a port SELinux gives another service; a network change failing
  half way puts the profile back; a host name is 64 characters at most; the API port is not one of
  another service (and the help says it takes a restart); the EHLO name must be a host name; the
  SSH port sshd listens on is always let in; the time servers' file no longer gains a space each
  time; a time zone is checked as the root helper checks it, and against the machine's zones;
  asks of the root helper of one kind go one at a time.
- The performance meter starts its graphs again when another node answers or the server's clock
  was stepped.

- Revoking a certificate the CA had revoked already (an answer lost on the way, or a twin's
  revoke tried again) is done, not a failure that never ends: its twin and its state follow.
- A renewal after a revoke that failed once never takes the revoked key again (keep the key on).
- A certificate the CA issued is never thrown away by a stop or a restart of the daemon between
  the CA's answer and the version kept (a paid order, a rate limit).
- The CRL of acme's own authority is made one at a time: a revoke no longer goes missing from it
  when a refresh crosses it, nor two CRLs carry one number.
- Names with ß, ς or the joiners are refused (give the xn-- form): written the old way (IDNA 2003)
  faß.de became fass.de - a certificate for another domain.
- In a cluster a long scan no longer starts renewals once the other node has taken over.
- A renewal running at the command line is no longer marked failed by the daemon starting, nor
  taken for left behind by a stop from the pages.
- An import or a CSR's answer no longer keeps the renewal window of the version before (renewed
  at once).
- Deployments, for a certificate administrator: the Windows Admin Center installer is a command
  (a full administrator's), the Windows store of shared certificates (its folder and password),
  who may read the key, the key exportable and haproxy's file and crt-list are where the key
  goes (a full administrator's); a deployment that runs commands or writes the key where a full
  administrator set is no longer moved to another target by them; a dry run checks where the key
  goes as a save does.
- The first host key seen ("trust the first key") is kept for tests, validations over SSH and
  OPNsense too (its ssh_hostkey) - those took any key on every run; settings tried before they
  are saved keep no key; @revoked and @cert-authority lines are no longer trusted as the host's.
- Windows: the old certificates taken away are only this certificate's own ("vpn" took "vpn-2"'s).
- The local target puts the files back when one of them, or its command, fails.
- Validations: the certificates using one are only those the account sees; no secret setting in
  the open.
- A certificate administrator of some teams no longer makes a certificate for any team (or none)
  by sending an id of 0.
- Read-only accounts no longer see the mail, phone, groups, note and last address of every account.
- A request from a request profile keeps to the most one person may ask for when two come at once.
- Cluster: a node stepped aside (by its heartbeat) is seen as out by the rolling upgrade and the
  rolling restart - both went on and took the last node in service out.
- The nightly portable copy (where pg_dump or mariadb-dump is missing) is kept for as many nights
  as the others, not for ever.
- A copy put back from the pages or acme --restore no longer leaves certificates "renewing" and
  jobs "running" for good.
- What an interrupted try of a backup, restore or upload left in the state folder (a copy
  unlocked, secrets.key) is taken away as the rest is.
- Forgetting a try of a backup no longer rewrites the other node's row; "try it after" works for
  a destination switched off.

## 1.0.50 - 2026-11-05

- The graphs of the performance meter move on smoothly, of this node and of the other node of a
  cluster alike: drawn on a line of time a few seconds behind, each reading where its time puts
  it, so neither the line jumping ahead when another node's readings come (every 5 s, two at
  once) nor a step when a reading comes is seen any more; their scale no longer jumps when a
  peak leaves the graph but goes back down slowly. Nothing more is read or written for it.

## 1.0.49 - 2026-11-05

- The performance meter sits on the row of the name and the state of the node, in a cluster too
  (each node's numbers one under the other there); only when it would push the account's buttons
  off that row does it go to a row of its own under it.

## 1.0.48 - 2026-11-05

- **The performance meter: switched on in Settings → About, and every node of a cluster.** Off by
  default for everybody (`perf_meter`); on, each full administrator chooses its look in Your
  account. In a cluster every node has its row of numbers and its panels - through the database,
  only while a page watches: no more queries than the daemon makes anyway, a node's reading written
  every 5 s while watched, nothing at all while nobody watches or the meter is off.
- **The performance meter, with what plexmon 2.7.1-2.7.4 found in it:** free space only of the kernel's own filesystems (a network share away hung the meter, FUSE and FAT
  could reach the disks); every thread shows its core's temperature (by the topology - with
  hyperthreading half of them had none); nothing of a bar at 0 %, and a process's bar is its real
  share. The graphs go on after F5 (the last two minutes kept by the daemon), and the look chosen
  is kept with the account.
- **The performance meter** (from ai 1.0.72-1.0.76, [docs/performance-meter.md](docs/performance-meter.md)):
  how busy this node is - the processor, the memory, the disks, the network - in the header,
  every 3 s while the page is shown, in four looks; pointing at a number opens its details in five
  styles (each core with its MHz and temperature, the sensors, each disk, the filesystems, each
  network card, the processes taking the most). **Off unless chosen**, by each full administrator
  in Your account → Performance meter, each look shown there as it will look. A full
  administrator's only (`GET /api/load`); `/proc` and `/sys` read when asked, nothing in the
  background, the details only while a panel is open.

- **A hunt, round 1 (security):**
  - A certificate administrator could run their own PowerShell as Administrator on a Windows
    target: a site, host or path of IIS, Exchange, the central certificate store or SharePoint
    with a curly quote (’) ended its quoted string there. Every PowerShell string doubles the
    curly quotes now, as the scripts' did since 1.0.45 (and the DNS over SSH's).
  - Where a deployment writes the private key - its files, the PKCS#12's password and how it
    is made, "send the private key", the key's file - is changed by a full administrator only,
    as its commands are: a certificate administrator wrote any key to a path of their choosing
    and took it, past the export that is a full administrator's. A service name with a path in
    it likewise.
  - The script of a Windows deployment (-EncodedCommand, only base64 of it, with the passwords
    in it) is no longer in the job's debugging steps nor in what isemon gets.
  - Trying a module's or a test's settings that nobody saved is a full administrator's, as
    saving them is: it made acme connect anywhere for a certificate administrator. They try the
    one saved, as it is saved.
  - A certificate administrator of a team no longer sees other teams' certificates in a
    validation's setup, nor the result of another's import from a source.
- **A hunt, round 3 (what rounds 1 and 2 changed, looked at again):**
  - A certificate administrator may again pick a module's preset and change what does not carry
    the key: only the lines of the files that carry the key, the PKCS#12's password, its key file
    are a full administrator's (round 1 refused a preset, a layout, even a note); switching to a
    generated password or not sending the key stays theirs.
  - "Deploy now" of one deployment is no longer answered with the job of others.
  - A revoked twin whose renewal failed stays revoked, and is due again.
  - Events kept to a team are paged and counted as kept, never shown all on a fault, and a
    certificate called "web" no longer hides every event with the word.
  - A node renamed takes away only its asks, not its counters of sign-ins; a copy whose key is
    the one in use is put back where the key's folder cannot be written; a tag with `*` is
    found as it is.
- **A hunt, round 2 (the pages, in Czech, on a phone):**
  - Czech for what was left: the forms of several sources and validations, the portal's sign-in
    events, steps of jobs, "changed: …" and "The owner …" with a name of their own (a weak
    pattern refused a name with a digit or an underscore as a sentence).
  - The portal: an empty name or password is asked for, not answered "wrong password"; a form's
    error is scrolled to; a sign-in run out keeps what was typed in a popup and says so, and the
    sign-in page says why it is shown.
  - On a phone, a table's row buttons stay at its right edge as it scrolls sideways; what is
    pressed is 36 px at least on a touch screen; the focus is seen on every control; a box with
    only a placeholder is named by it for a screen reader.
- **A hunt, round 2 (the certificates):**
  - A renewal stopped after its new version was saved (in the twin, the deployments, a
    restart) no longer puts the old state back over it: "failed" over a new version had it
    ordered again, "new" left its deployments undone.
  - A revoked twin is no longer deployed with the main certificate; a twin that could not be
    revoked is said so ("revoke-failed") and not shown as revoked; revoked for a compromised
    key, the versions before with the same key are revoked too.
  - A failed deployment puts back only the files it had put in place - the ones after the
    failure, never touched, were deleted (a live key among them).
  - A deployment that stopped between its files and the reload is done again (the reload with
    it), not taken as done because the files are the same.
  - "Keep the key" keeps it only while it is of the key type asked - changed to RSA, it came out
    EC again.
  - A certificate alone imported into one there keeps its key only when it fits.
  - The twin's end and its failures are in the alerts.
  - A reason of revocation ACME's CAs do not take is said, not sent as "unspecified".
  - The chain of a CSR's answer is kept nearest first, as an import's.
- **A hunt, round 2 (backups, the command line, the databases):**
  - The retention of a destination never takes away the backup just sent, nor counts one
    stamped in the future (a wrong clock) as the newest.
  - A MariaDB dump that fails half way puts back what was there (its DROP TABLEs cannot be
    undone); the key that comes with a copy is checked writable before anything is replaced.
  - The nightly dumps are pruned among themselves, of each engine - a dump made by hand or
    before a move went first.
  - "Try the newest" tries this installation's backup only, and wants the key whole.
  - A move of the database no longer carries its events twice.
  - `--local-user drop` asks (or wants `--yes`) without a terminal too - from a script it took
    the account and its home away unasked.
  - `--json` alone with `--rbackup-now`, `--restore`, `--ha-tls-off/--ha-tls-repair` and
    `--split`; `--split-try` exits 1 when a node does not reach its arbiter.
  - A tag of other letters ("účetní") is found by the search, and on MariaDB by the filter.
- **A hunt, round 1 (the pages):**
  - Jobs at 100 a page showed 50, and the rest of the page was out of reach (paged twice).
  - "Save and deploy now" deployed twice - the look had started on the deployment just saved,
    and the button ran it again after; it gets that job now. A deployment's job names its
    target.
  - A certificate administrator kept to a team no longer sees other teams' certificates in
    Events.
  - An account that must change its password first is asked for it again, not told "the daemon
    is not answering".
  - The export no longer offers PKCS#1 for an EC key (refused after the click).
  - Words alone in the certificates' search find their tags and owner too.
  - A setting's name in an error ("“Wrong sign-ins from one place…” must be between…") is in
    the page's language; a new module's suggested name too.
  - The approval of a portal request says whether it renews by itself, and where a local
    account is told.
  - A popup opens on its first box to type in - never on a switch (the certificate's opened on
    "renew automatically", and a Space turned it off) nor on a hidden file box (Import).
  - The deployments of a target show where they go, not the module's inner switches; a space
    between who and when; Czech words and forms.
- **A hunt, round 1 (the cluster):**
  - A rebuild from the other node that fails half way on the command line (`--ha-resync`,
    `--ha-join`) leaves the node in maintenance, as from the pages - it started again answering
    with emptied tables.
  - A rolling upgrade, and a rolling restart, wait for the other node to be in service - not
    only alive with its maintenance row off: stepped aside for its clock or a split, rebuilt or
    restored, it was out too, and both were.
  - The renewer reads the lease again right before it looks for due certificates: after the VIP
    address went to the other node, both renewed for up to half a minute.
  - While another thread is asking whether the other node is alive, the answer is "alive" -
    "dead" had this node take the lead beside it for that moment.
  - Only the day's own copies are a node's own claims: a node called "day" took the system
    updates' daily claim as its own, and both nodes ran them.
  - A node renamed carries its day's copies over (made twice before) and takes away what it had
    written under its old name.

## 1.0.47 - 2026-11-05

- **The password policy of the local users explained as on otp:** every rule has its (i) - and
  its name the same words: what it does and in which file or module (pam_pwquality,
  pam_pwhistory, pam_faillock, login.defs), the command line's name of it
  (`acme --local-policy-set KEY=…`) and its built-in default. A click on the (i) by a switch
  does not turn the switch.
- `acme --local-policy-set dictcheck=off` (or `usercheck=no`) switched the check on - a word was
  taken as on. The switches are on/off, yes/no, 1/0 now; another word is refused.

## 1.0.46 - 2026-11-05

- **A hunt, round 6 (rows of another shape, the cluster's upgrade, what 1.0.45 changed):**
  - Where "'str' object has no attribute 'get'" came from: 1.0.42 kept the password policy of
    the local users as its signature (a text) where 1.0.43 keeps the policy itself. Every row of
    that kind is now read as an object or as nothing (122 places), so a row of another shape -
    an older version's - is written anew instead of breaking each look for good; setting a local
    user's password no longer fails on such a row either. What the root helper says, the
    backups' lists and the nodes' heartbeats likewise.
  - Rows newly under the guard are taken under it, and accounts signed with their e-mail, mobile
    and second step, only once every node of the last day runs the new version - not only the
    ones alive just then: a node of 1.0.43 restarting during the upgrade came back to rows and
    accounts refused. Until then an account is signed as before.
  - Asks written for a node since forgotten (the users' with their sealed password hashes, SSH
    keys, system updates, the console, SELinux, the network) are taken away; Back up now asks of
    a node renamed or forgotten too, and of a node with a name over 63 characters.
  - A scheduled backup tried again goes only to the destinations that failed (one NAS away sent
    it to all of them, and each kept only so many). A line of the backups forgotten stays so.
  - A job of no certificate (a target's test) - or of one deleted - is looked at, stopped and its
    test read only by those who see every certificate and by the one who started it.
  - A download that fails comes back to the pane it was started from; no mbstring needed; a
    daemon away or a session over is said as such.
  - A setting, an account or a directory taken away stays refused on the lights (only rows of
    meta that are gone leave the list).
  - In Czech: the line under *Test* in a module's form, the kinds of destination in the
    wizard's deployment step, "downloading…", and the portal's sign-in events are translated;
    *Renews: automatically*; *Passphrase* in the download of a copy. The reminder to keep the
    passphrase apart is no longer covered at once by "downloading…".
  - The first issue of a certificate just added is by the one who added it, not by the renewer.
  - A node without its root helper set up says so, not a Python error with a path in it.

- **"1 refused" by the guard against writes that stayed:** a refused row was taken off the list
  only when it was found good again - an old unsigned *Back up now* of a node still on 1.0.43,
  taken away by that node after its upgrade, stayed "on - 1 refused" on the lights until the
  daemon restarted. Rows that are gone now leave the list within the hour.

## 1.0.45 - 2026-11-05

- **Seen on a cluster upgraded from 1.0.43 to 1.0.44:**
  - "the local users: 'str' object has no attribute 'get'" every few seconds: a row of the
    local users of a shape not expected stopped every look, and was never written anew - taken
    as none now, so the node writes it again. Such a warning now says where it broke.
  - "a row of the database not written by acme is not acted on: meta rbackup:now:..." every
    ten minutes: a *Back up now* asked by the node still on 1.0.43 (unsigned) was refused for
    good on the upgraded one. Such asks are checked only once every node runs 1.0.44 (as the
    other rows newly guarded), and a node takes its asks away once they are over.
- **Round 3 (the pages, in Czech):** the alerts of the Overview are translated (they were
  drawn as data); 17 texts reworded since (the sealed keys, every private key, Settings →
  Accounts, The directories) translated again; of several patterns that fit a sentence the
  one that says most of it is taken ("deploying x to y failed: ..." was half English); a node's
  name before its own sentence no longer stops that sentence's translation; "used by" of a
  module's version; "kept in ... - a database cannot hold its own address" for any config
  path; durations with the language's decimal comma; the whole message of a job on hover where
  the table cuts it; the sections of the certificate's window fit a phone's width; the portal
  says which of the e-mail address or the mobile number the account lacks.
- **The command line and the console:** `--selfsigned NAME` over a certificate there already
  (one of Let's Encrypt's) asks first - it made it self-signed without a word; `--days 825`
  was taken as not given (825 was the option's default), and `--days` takes 1 to 36500;
  `--restore-bundle` of a file that is no backup says so (it ended in a traceback); the
  questions asked of the nodes exit 1 with `--json` too when one failed; `--renew all --json`
  is one JSON document; a modifier alone (`--role`, `--yes`, `--note`...) no longer starts the
  daemon when no terminal is there; `--status` says the daemon's start and uptime, not the
  command's; the console no longer breaks on a setting edited in a terminal of three rows.
- **Round 4 (backups, the cluster):**
  - Moving the database: the work was held only after the copy was made - what was written
    meanwhile (minutes on a big database: a renewal with its new key, a change on the pages)
    stayed in the old database and was lost with the switch. Held before the copy now.
  - A copy made by a newer acme is not put back into an older one (what the older one has no
    column for was dropped without a word): install that version or newer first.
  - A scheduled backup to another machine that failed (every destination away) is tried again
    each hour that day, three times - it waited a day, or a whole week.
  - How each destination went last is each node's own row: both nodes rewrote the one shared
    list after a run and kept each other's (an administrator's change could be undone); the
    history of backups is forgotten by each node for its own lines only.
- **Round 2 (the certificates, the modules, the flows end to end):**
  - Revoked with a new one at once, a dual certificate's twin was issued again with the
    revoked key; it was shown as still good after the revocation; and it was renewed and
    deployed in states where nothing renews (waiting for approval, declined, being deleted).
  - A CSR sent to a request profile carried e-mail, UPN and URI names to a source that takes
    the CSR as it is (AD CS, Vault, EJBCA...) - refused now but for acme's own CA.
  - A certificate administrator wrote PowerShell run as Administrator on Windows targets (its
    *PowerShell after*); quoted values could end at PowerShell's curly quotes.
  - Two renewals of one certificate could start at once (two orders); several portal requests
    at once gave errors and went past the person's limit.
  - *Renew now* issued a portal request waiting for approval, or declined, past the approval.
  - A new source, validation, target or test refused when saved was left half made (and every
    try after said "there is one called X already"). Renamed, a source or a validation is
    followed by the request profiles, the portal's settings and the module's own kept values (an
    ACME source's account); one used by a profile is not deleted; a deleted owner is taken out
    of the profiles naming it.
  - A deployment (or its target) is not deleted while a job deploys it; a target switched off
    no longer starts a job at every scan; a deployment's options are checked for their kind.
  - An export of a version and a variant that do not go together is refused (it gave the main
    one); an IPv6 zone id is no name of a certificate; `true` is no id.
- **A hunt, round 1 (the rights of the API, the root helper):**
  - A certificate administrator signed in on the portal took the private key (PFX) of any
    certificate - the administration refuses it that; and, scoped to its teams there, it saw and
    managed every team's on the portal. Now the portal follows the administration's rights.
  - Approving a portal request: an id written as `" 5"` or `5.0` went past the check of the
    teams. A job of no certificate (a target's test) was readable by a scoped account.
  - A portal sign-in still waiting for its one-time code could change the password (and lock
    the owner out); an account with a password to change could never type its code - the code
    comes first now, the password after.
  - A wildcard asked for on the portal waits for an administrator, whatever *issued without
    approval* says. The owner names of a portal sign-in come from the directory, not from the
    name as typed.
  - The root helper: a balancer's address with an IPv6 scope id went into nginx's configuration
    (a line of its own); the SELinux labels of a user's `~/.ssh` are put right without `-R`; the
    database server's own accounts and databases are refused for the cluster's access; the
    SELinux report keeps no command lines of other programs; root loads only modules of its
    own from `/etc/acme/plugins`.
- **A hunt, round 1 (the pages):** a download that fails (a copy gone, a destination not
  reached) is said on the page - it replaced the page with its JSON, and what was not saved was
  lost; the downloads of copies and backups are started only by the page itself (a link or an
  image on another page of the same site made the daemon build a whole backup); a translation
  escaped where it went into the page as HTML; the Monitoring lede translated again; two
  missing values no longer break a page or log a warning.
- **Round 5 (what the rounds before changed, looked at again):**
  - A download of a copy or a backup is the browser's own again - saved as it comes, not held
    whole in the page's memory first: the page asks for a short ticket (two minutes, of this
    session and this download) and the browser fetches the file with it; when no file comes,
    the page says why.
  - The one who started a renewal sees how it goes, as before round 1.
  - A failed scheduled backup is tried again only after a scheduled one (a failed *Back up now*
    of one destination is no reason), and only while backups are on, to a destination switched on.
  - A line of the other node taken off the backups' list stays off - noted in this node's own
    row, as the other node's row is never rewritten here.
  - A request waiting for its approval, or declined, is not renewed - by the command line's
    `renew --all` neither, which now goes on past a certificate that fails and says it in
    `--json`. A renewal that hung over two hours no longer keeps a destination from being
    deleted. *Renew automatically* is kept on a revoked certificate. An export asked with the
    old name of a variant is no longer refused.
  - A node's name before a sentence ("acme1: ...") no longer takes the place of a pattern that
    says the whole of it.

## 1.0.44 - 2026-11-04

- **What was left of the hunt, shut too:**
  - isemon and the SIEM no longer lose the lines written while a TCP/TLS receiver cannot be
    reached (a restart of isemon, a network cut): the last 5 000 of each are held and sent in
    their order, with their own time, once it answers.
  - The history of the backups sent away is each node's own row: two backups at once on the
    two nodes wrote the one row over each other, and one was gone from the list and the alerts.
  - An account whose second step was set up says so in its signed row: its second step deleted
    in the database (past acme) no longer lets the next sign-in set up a new one with the
    password alone - it is refused until an administrator resets it.
  - install.sh takes `/etc/acme/plugins` only as root's own: a folder put there by another
    account (the acme account may rename root's away - `/etc/acme` is its group's) is moved
    aside, not made root's with what is in it; a link put there meanwhile stops it.

- **isemon gets the certificates' work in detail** (Settings → isemon → *Send the certificates'
  work in detail*, on by default): every job - an order or a renewal with its validations, a
  deployment, the tests, an import from a source, a revocation, a dry run - its start, every
  step with the module that said it, every HTTPS request of a module (host, path, the answer,
  how long), every validation (the name, the way, presented / valid / invalid, how long), its
  end, and every test's result with what it found, as `acme-jobs` lines with fields of their
  own for isemon's analytics (also `/var/log/acme/acme-jobs.log`). Nothing secret leaves: keys,
  passwords, tokens, a URL's user and its secret parameters, JWS and long blobs are taken out
  of every line - the `acme-certs` and `acme` lines too. The rule for isemon's rsyslog
  (`deploy/isemon/11-acme.conf`) files `acme-jobs` too: copy it again.

- **The portal's one-time code for acme's own accounts too.** With *A one-time code at every
  sign-in* on, the directory's people needed the code - and an account of acme's own (the role
  *enrolment pages only*, or with *acme's own accounts may sign in too*) got in with its password
  alone. A setting of its own now, Settings → The portal → *A one-time code for acme's own
  accounts*: as for the people of the directory (the default), off, by e-mail, by SMS, or one
  with the other to fall back to - not tied to the administration's second step, which the
  portal no longer asks while it is on (High security keeps the app there). The code goes to
  the e-mail address or the mobile number the account has: Accounts has both now (when it is
  made, and the envelope button; `acme --user-contact NAME --mail … --mobile …`), signed with
  the account by the database guard. An account without what the way needs cannot sign in on
  the portal - the list of accounts marks it. **Before upgrading** with that code on: give the
  portal's own accounts their address or number (an administration's second step by mail or
  SMS counts), or set the new setting to *off* to keep things as they were.

- **A hunt for bugs and holes, round 1** (the root helper, the daemon's API and sign-ins, the
  pages, the changes of 1.0.40-1.0.43). Shut:
  - *Make the database and the account for me* could be asked for the database server's own
    accounts and databases: `postgres` / `root` given a password the acme account knew (and
    through PostgreSQL's superuser a shell as postgres), or ALL on `mysql`. Refused now - the
    server's accounts and databases, and an account there with rights over the whole server.
  - The password policy's list of authselect features acme switched on was in the acme
    account's own folder: a list written there had root take out any feature
    (`without-nullok`, `with-pamaccess`...). Root's own folder now, and only the two features
    the policy uses are ever taken out. A feature that failed halfway is written down too.
  - The PostgreSQL helpers took the data folder and pg_hba.conf where PostgreSQL said they were,
    and read the old certificate through a link: only a path owned by root or postgres, no link,
    written by nobody else.
  - The SELinux report was written, and the time acme's needs went in was read, through the acme
    account's folder (a link swapped in, a time in the future hiding every refusal): through the
    helper's own descriptor, and root's own file for the time.
  - pam_radius's secret file was in /etc/acme (the acme account's): another server and secret,
    or a FIFO hanging every sign-in, could be put in its place. In /etc/security now (moved
    on its own on the next look of each node, the PAM block with it).
  - The SSH server: an AllowUsers naming no account of the machine is refused (nobody would
    sign in). A user's own authorized_keys of 50 000 lines had root run ssh-keygen as often:
    300 lines looked at. A list of ciphers starting with "-" is refused (an option of openssl).
    Unlocking a local user gives back the day the account ends, as it was before the lock.
  - Signing in over SSH with a code: the wrong codes are counted for the whole cluster (they
    were counted in memory on each node - five tries a node, forgotten at a restart).
  - The second step's codes while it is set up were sent without the cluster's cap: an SMS to
    any number, again and again with a new sign-in. The portal's cap now.
  - A one-time code sent for the portal counted as a refused sign-in for the sign-in guard
    (five people of one office blocked its address); the load balancer is not blocked by the
    guard for its own SSO sign-ins.
  - Changing your own password ends your sign-ins on the enrolment pages too.
  - Users SSH asks a code of and who may not use sudo were given the policy's password aging
    again (since 1.0.43): sshd's account step then asked them for a password they need not
    know. Left out again; given or taken sudo, in or out.
  - *Make them again* made each user with the lowest free UID, not the one it had: the UID it
    had, or the one of its twin on the other node.
  - A backup put back: the certificate of the node's PostgreSQL was no longer renewed
    (`dbtls:server:` forgotten), a Keep from before kept the SSH server's trial on the new
    machine at once, and a first start there wrote a new SNMP engine ID over the backup's.
  - The 1.0.42 policy with only the days between changes (or the warning) set was not taken
    over. A long name typed at a sign-in gave a 500 on MariaDB (the key of its row too long).
    *Look again* of a settings card wrote one row on both nodes (the replication could stop on
    it) and could be asked in a loop: a row each, once in five seconds.
  - The pages: a read (`?api=`) asked from another page of the same site is refused (an image
    elsewhere made the daemon build a whole backup); the previews of mails are sandboxed; names
    escaped in two windows; a target's user and host escaped in a module's guide, and only an
    account's name in the commands to copy.
- **Round 2** (the certificates, the secrets and the network services). Shut:
  - A certificate administrator could run any command as root on an SSH target: the service
    name of a preset (`docker restart {service}`) was put into the command as typed
    (`web; id #`). The service / container name is now a name - letters, digits and
    `_ @ . : + = / -` - on SSH, Windows-over-SSH and local targets.
  - The backups sent to another machine: their destinations, the password of the backups and
    the DNS / ACME settings are now under the database guard (a row written past acme no longer
    sends the backups, and their password, elsewhere); every destination is checked again when
    it is used (an account `-o…`, `!` or `$` in a folder), and `--` ends ssh's, sftp's and scp's
    options.
  - A deployment stopped half way (a restart, an upgrade) stayed *deploying* and was never tried
    again until the next renewal - a month after the old certificate ran out; Stop of a job no
    process ran left its certificate *renewing* for good. Both are failed and tried again soon,
    and a deployment *deploying* for two hours is tried again.
  - A short-lived certificate (Let's Encrypt's 6-day profile, an own CA's few days) is renewed
    a third of its life before its end - with 30 renew days it was issued again at every scan.
  - The tests of the certificates keep to the teams: a scoped account sees, attaches, takes off,
    switches and runs only its team's.
  - The CRL as `crl-pem` needed a certificate administrator like the other names of it; a CRL
    is never signed on both halves of a split cluster - the public CRL served the one there.
  - The internal DNS server over TCP: eight connections at most from one address, a message
    must arrive whole within 10 s, a connection lasts two minutes, and its questions are rate
    limited as over UDP.
  - The SSH gate: a name without a token is counted in memory only (every name a scanner tried
    was a replicated row for good), the old counts are tidied, and the gate and the DNS server
    go on when no thread can be started.
  - The waits after a failure (the database, the logs to isemon and the SIEM, the ACME work, the
    other node's codes) go by the machine's steady clock - a clock stepped back froze them.
  - The alerts from the events read only the kinds they look at (a flood of refused sign-ins
    left them hours behind) and also the other node's rows that came over late.
  - The SIEM stamps an event with when it happened, not when it was sent.
  - Deleting a module named `dc_1` deleted the stored values of `dc-1` too (SQL LIKE).
  - Mail debugging no longer writes the password of the mail server's sign-in into the log; a
    text in the SMS spool is readable by the spool folder's group only (0660).
  - A backup put back cannot unpack itself into the whole disk, nor a single line of it into
    memory.
- **Round 3** (upgrades, the cluster, the command line, and what rounds 1 and 2 broke). Shut:
  - **Going back is not possible below 1.0.44** any more (the floor was 1.0.0): an older signed
    package put in by the acme account brought back the root helper with the holes 1.0.44
    shuts.
  - An upgrade whose new version does not run (or that stops after the switch) goes back to
    the version that ran, with its pages; the check after the restart waits 15 s of the same
    run (it took a version restarted every 5 s for a running one). A failed tree is never made
    *previous* (a second try deleted the last good one); one install.sh at a time;
    `install.sh --upgrade` does not take out the last node in service. A running daemon no
    longer loads code from the new tree before its restart.
  - The cluster: the node holding the VIP is asked in its own database before the other one
    leads (one way of the replication stopped, both renewed and deployed); a node in
    maintenance or stepped aside by the clock guard leads, renews and signs no more (and
    the other leads meanwhile), and the DNS server of a node aside by its clock is silent;
    a renewal left by a node that is gone is tried again (the certificate stayed *renewing*
    for good, ran out without a word); the age of the other node's heartbeat is judged by
    its database's clock; a setting is never stamped earlier than the value it changes (a
    node with its clock behind had its change thrown away by the other); after a split an
    older certificate's row coming over does not replace a newer one; the nonces of pushed
    certificates are kept for both nodes; notes of a split report that never came are tidied.
  - The guard's new rows (round 2) are taken under it only once every node runs 1.0.44,
    with the mark of it in the node's own file (a mark in the database, deleted with the
    signatures, made the next start sign whatever was put there).
  - Rounds 1 and 2 put right: SSH with a code works again with pam_radius before 3.0 (it sends
    no Message-Authenticator - a wrong one is still refused); a service name may be several
    (`nginx php-fpm`), and Windows' are not checked (no shell: `MSSQL$SQLEXPRESS`); the
    password policy's record of 1.0.43 is taken over from its old place; the SMS spool files
    stay readable where the folder's group is acme's; a PostgreSQL data folder behind root's
    link is taken; Unlock gives back the day the account ends only if it is still ahead; the
    alerts do not stall in a flood of events; DNS over TCP is not rate limited like UDP; the
    renewal of the pages' certificate is not held for an hour after a boot; destinations of
    the backups saved before keep working (only what is dangerous for their kind is
    refused); the 1.0.42 policy of only the days between changes is taken over where 1.0.43
    had run; the command line names whose sudo it was in the events again.

## 1.0.43 - 2026-11-04

- isemon: the rsyslog rule for the isemon machine (`deploy/isemon/11-acme.conf`) filed the
  program `acme-certs` only - acme's other events (`isemon_events`, program `acme`) and the
  test line of `acme --isemon-test` were filed nowhere. Both now, `acme.log` beside
  `acme-certs.log`.
- **Settings → Local users → Password policy, and a user's own password aging - as otp
  1.0.245 - 1.0.246.** One policy for every local user of the cluster, put in by each node into
  the system's own files, so it holds however a password is changed (passwd, a password run out
  at sign-in, these pages): pam_pwquality's drop-in `pwquality.conf.d/50-acme.conf`, acme's lines
  between marks in `pwhistory.conf` and `faillock.conf` (root never locked), `login.defs`' aging
  (what it had kept in it, put back when off), and with authselect the features `with-pwhistory`
  / `with-faillock` (only those acme switched on are taken out again). Off by default - nothing
  written. Three columns of rules (the password, how long it is good, wrong passwords), *Save
  the policy*, a light of each node in the card's heading (*as set here*, *being put in…*,
  *refused*, *not answering*), *In effect on the nodes* (read from each node's files and PAM).
  A password from the pages is checked by `pwscore` where it is there, by the rules otherwise.
  The policy's row is signed by the guard of root's actions; one it refuses changes nothing.
  - A user's popup: *Password aging* (good for, warned before, the least days between two
    changes, *Save the aging*), and when the password runs out. A user made with no password
    gets no aging; adding one with sudo and no password is refused, and the popup says when a
    user may use sudo but has no password.
  - `acme --local-policy`, `acme --local-policy-set KEY=VALUE…`, `acme --local-user aging NAME
    --local-max-days N --local-min-days N --local-warn-days N`; two items in `acme --console`.
  - It replaces the password policy of 1.0.42 (its settings on the card *The password policy*
    are gone): what was set there is taken over once as this policy (managed, the same length,
    kinds, the name and days), and its file `pwquality.conf.d/90-acme.conf` is taken out.
  - Users made again from the list of a machine built again get sudo back only once they have
    a password (sudo asks for it).

- **A backup put back on a clean machine, and a cluster built from it - everything as it
  was**, checked end to end now (`test/test_restore_ha.py`: an installation, its backup put
  back on a clean PostgreSQL node, a replicated cluster built with a second clean node - every
  row on both, the sealed secrets opened on the second). What it found, put right:
  - The guard against writes to the database was off after the putting back (it is kept in
    config.json): on again, as it was.
  - The SNMP engine got a new ID (and its count of starts began again) on the new machine -
    a trap receiver told the old ID took nothing: both kept in the database too.
  - What the old machine said it had in place came back with the database, so the new one
    was taken to have it: the SSH server, the time, the console at login and the password
    policy were never put in there. Forgotten when a backup is put back (for every node of
    it) and when a node starts on another machine than last time - each is read anew and
    what is wanted put in.
  - The keys of root made on the pages are put on the new machine again.
  - The local users of the machine are not in any backup (no password is kept anywhere):
    *Settings → Local users* lists the users each node's machine had - *Make them again*
    (the same name, UID, full name, shell and sudo, no password) or *Forget them*; *SSH keys*
    shows the fingerprints of root's keys the machine had that are not on it now.
  - RESTORE.md in every backup and docs/backup-and-recovery.md (7.3) say what comes back by
    itself and what does not.

## 1.0.42 - 2026-11-04

- **Settings in a cluster: in effect on every node?** Every card of Settings has a thin pill
  at the right of its heading: a dot a node - green, it has in what is saved; amber, not yet;
  red, not heard from; grey, a version that does not say it - a thin line and a refresh icon.
  Pointed at, the dots say it a node a line (*in effect · read in 9 s ago*, *not yet*…); the
  icon asks both nodes again at once. Looked at every 15 s while Settings is open, every 3 s
  while a node is behind or just after a save - a node now says at once that it read a change
  in. Each node's heartbeat carries the mark of the settings it read and when
  (`GET /api/settings/nodes`). Standalone: nothing drawn.
  The lights of their own under *High security* and *Guard against writes to the database*
  (1.0.41) and on *The password policy* are gone: the pill of the card says it - a node's
  dot amber or red when what the card is about is not as it should be there (high
  security not in yet, rows refused, the guard with no key, the policy not put in), its
  popup a node a line for each.

- **The password policy of the local users** (*Settings → Local users → The password
  policy*): characters at least (8 and up), kinds of characters (small letters, capitals,
  digits, the others - any, two, three or all four), not the user's name in it (backwards
  too), good for so many days (then changed at the next sign-in), changed again after so
  many days at the soonest, told so many days before it runs out. A password typed for a
  local user is checked as it is typed - each rule ticked in the window - and again by
  the daemon before its hash is made. The days are put by each node's root helper on every
  normal user (`chage -M/-m/-W`), and on a user made or given a new password; the table says
  until when each password is good (amber near the end, red once it ran out). *The same
  rules for passwd on the machines* also writes them into
  `/etc/security/pwquality.conf.d/90-acme.conf` and the `PASS_` lines of `/etc/login.defs`
  (taken away again when off). As until now unless changed: 8 characters, any, always good -
  nothing on the machines is touched until a rule is changed.
  In a cluster the rules are the cluster's and every node puts them on itself; the pill of
  the card says of each node whether they are in effect there, being put in, could not be
  (and why), or that it runs a version before 1.0.42.
  Left out of the days - always good - are a user with no password (a key only) and one
  SSH asks a code of (*Settings → SSH server*) who may not use sudo: with the password run
  out, PAM's account step makes sshd ask for the old one first, even after a key or a code -
  and they may never have been told it. One who signs in with a key and a code and may use
  sudo (for `sudo acme --console`) keeps the days: sudo asks for that password, so they know
  it and change it when sshd asks. Given or taken sudo, a user is put in or out of the days
  at once. The other rules (length, kinds, the name) hold for everybody.
- SELinux: MariaDB of the node on a port of its own (not 3306) - the port is given
  `mysqld_port_t` with the rest of what acme needs (*Put in what acme needs*), as
  PostgreSQL's was already; enforcing, MariaDB could not listen there.
- A window with a long list (*The database* from the overview: *What it holds*) has one
  scroll bar - the window's; the list had one of its own beside it.
- acme.service starts after the database of the machine and stops before it: at a restart
  of the machine (a system update) its "acme stopped" could not be written any more -
  PostgreSQL was gone already.

## 1.0.41 - 2026-11-04

- **Six more pictures for the sign-in** (*Settings → The enrolment pages → The picture
  on the sign-in*, for the enrolment pages and the administration each), of
  certificates and their automation, drawn as the four there were (in the page's own
  colours, nothing fetched, the same size, still with reduced motion): *An ACME
  order, step by step* (ordered, the challenge, proved, issued), *The name proved in
  the DNS* (the `_acme-challenge` TXT record looked up by the authority, no port
  opened), *The key, the request, the signature* (the private key never leaves the
  server), *What the servers serve, looked at again and again* (the name, the chain,
  the days left), *Revoked and replaced* (a new key, put in place) and *The next one
  long before the last runs out* (never a gap). In Czech too.
- **Pictures of their own for each sign-in**: five more for the enrolment pages only,
  as the people who ask for certificates see it - *Asked for on the pages, approved,
  issued to you*, *Your certificate, downloaded as your server takes it* (PEM, PFX, the
  chain), *Your certificates, and how long each one has* (and a mail before one runs
  out), *Your password, then a code by mail or SMS*, *Your team's certificates* - and
  five for the administration only, as those who run acme see it - *Everything at a
  glance*, *Two nodes, one address, one database*, *Every authority, into one place*,
  *The jobs, by themselves and on time*, *Every change written down, every failure
  told*. Each tab of the picker offers the fifteen drawings that may go on its sign-in
  (the ten above for both, and its own five); the other sign-in's own are refused when
  saved, and one in an imported configuration is put in as that sign-in's default.
- *Settings → High security*: under *High security* and *Guard against writes to the
  database*, a light for every node saying what is in effect there - on (green), off,
  not there yet / still on after a change (amber, looked at again every few seconds),
  the guard on with rows refused (amber) or with no key to check them (red), a node not
  heard from (red). The guard is each node's own: the light says where it is still off.
  In a cluster only (both nodes, a line each); standalone the switch says it all.
- *Local users*: a user made, changed or taken away is in *SSH keys → Whose keys* at once
  - it was there only after reloading the page (F5).
- *Local users*: the windows have on/off switches, as every other page, where they had
  check boxes (to be changed at the first sign-in, sudo, the nodes, the home folder too).

- **`acme --get KEY`**, the counterpart of `--set`: one setting's value alone (for a
  script), again for more (`KEY=VALUE` a line, as `--set` takes them), `--json` as
  `{key: value}`. A secret shown hidden, as `--settings` shows it; a key that is no
  setting refused, nothing printed.

- *acme's gate for SSH: the port tried first* was shown under every pane of Settings
  (the page had no place for it): now only under *SSH server and notices*, in a card
  of its own (*acme's gate for SSH*), as otp has it. A test now sees that every pane's
  settings have their place on the page.

## 1.0.40 - 2026-11-04

Taken over from otp 1.0.230-1.0.243: everything of those versions that is not about RADIUS, the
tokens or the enrolment of otp - the local users of the machines, the SSH keys of every user,
SELinux, the guard against writes to the database, behind a load balancer and signed in by it,
wrong directory passwords per person, the alerts of everything the nodes see, and otp's two bug
hunts. Every new switch is off - as until now - unless said otherwise.

- **Local users of the machines** (*Settings → Local users*, full administrators; as otp 1.0.243).
  The users of each node's own system, one row a user and a column a node: made, given a
  password, sudo (wheel / sudo), locked (the password and the account - no SSH key lets them in
  either) or unlocked, their full name and shell changed, taken away with or without the home
  folder - on every node of a cluster at once or on the ones ticked, the same UID on each; a user
  on one node only made on the others with a click. **root is shown only**, never changed from
  the pages (the API refuses it); accounts of the system and of the services (acme, acme-web,
  postgres, mysql, nginx, sshd…) are neither shown nor changed - by the daemon and by the root
  helper both. A password typed on the page goes to the nodes as its sealed SHA-512 hash only,
  to `chpasswd -e` on its standard input, and is taken out of the database once done (after 15
  minutes in any case). Also `acme --local-users`, `acme --local-user
  add|password|lock|unlock|sudo-on|sudo-off|drop|drop-home NAME` (a password asked at the
  terminal, never on the command line) and four items in `acme --console`. See
  docs/local-users.md.
- **SSH keys of every user who may sign in** (*Settings → SSH keys*, was *SSH keys of root*; as
  otp 1.0.240). *Whose keys*: root as until now, or any normal user of the nodes (UID 1000 and
  up, a login shell) - their own `~/.ssh/authorized_keys` read from every node, a key added, made
  here (the private half shown once, kept nowhere), exported or taken away, on the nodes where
  the user is. Read and written **as that user** by a child of the root helper with their UID,
  GID and groups: `~/.ssh` 0700 and the file 0600, theirs; a link in their home is refused and
  never followed. Every change in Events with the user's name. docs/ssh-keys.md.
- **The console at login for normal users too** (*Settings → About → The console at login*:
  *normal users: nobody / every one / these…*; `acme --console-users "alice bob"`, `'*'` or
  `none`; on the console under The service). Off by default - root only, as until now. Named
  users land in the console **through sudo, with their own password**: only who may become root
  with sudo gets it; anybody else named gets one line saying so and the ordinary shell. What is
  done from such a console is in Events as `command line (sudo alice)`.
  `/etc/acme-console-login` gets a second line (`users: …`); root's own switch is kept apart.
  docs/console.md.
- **Accounts picked, not typed** (*SSH server and notices → Who may sign in*, *About → the
  console at login's normal users*; as otp 1.0.242): lists of the accounts of the nodes - root
  and every user who may sign in there - several at once, or everybody (nobody / every normal
  user for the console); chips to take one away, a search when the list is long. One set before
  that the nodes do not list (a pattern of sshd's) stays, said so.
- **A key shown once, shown big**: Prometheus's token, made on *Monitoring*, is in a large box
  across the dialog, picked whole with one click, with Copy beside it (as otp 1.0.240).
- **Behind a load balancer or WAF** (*Settings → Firewall and access*; off by default - nginx as
  until now; as otp 1.0.237 and 1.0.238). Switched on, nginx takes the client's own address from
  the header the balancer sends (`X-Forwarded-For`, or the one named: `X-Real-IP`,
  `True-Client-IP`...) - only for requests from the balancers' addresses named, never anybody
  else's - so that the sign-in pause, the caps, who may reach which page, nginx's limits and every
  log see the client, not the balancer. In this node's server and the VIP address's, on every
  node, through the root helper (`nginx -t`, put back when refused). It takes the place of what
  `acme --trusted-proxy` wrote while on; off, only its own lines go - the 0 kept as a row of its
  own, so that "switched off" is not read as "never switched on". Refused on without the
  balancers named; `acme --trusted-proxy` refuses while it is set on the pages.
  docs/load-balancers.md.
- **Signed in by a load balancer or WAF (SSO)** on the certificate portal (*Settings → The
  enrolment pages*; off by default - the portal as until now; as otp 1.0.239). The portal
  published to the internet through a NetScaler, an F5 APM or another balancer that signs people
  in against the directory first: who it signed in comes in a header (`X-Acme-User`, or one
  named), and the portal asks no password again. Believed only on a connection from the
  balancers named - the machine the request really came from (nginx's `$realip_remote_addr`,
  passed to the page as `ACME_PEER`), never the client's address from `X-Forwarded-For` - and
  only with the key in `X-Acme-Sso-Key` (made on the pages or with `acme --sso-key`, shown once
  in a large box, kept sealed, compared in constant time). Everything after the password as it
  was: the portal's directory asked who it is, *Who may sign in* decides. The same person on the
  next page goes on in the same sign-in, another one on the same browser ends it; switched off,
  a sign-in by the balancer ends. *Sign out* goes to the balancer's own sign-out when one is set,
  or holds the sign-in by the balancer until asked again. Every refusal in *Events* with its
  reason, and - for who wants it - mailed (*Alerts and reports → Sign-ins by the load balancer
  refused*, off by default). The card shows the last sign-in by the balancer each node saw and -
  switched on - the configuration of NetScaler (nFactor/LDAP, rewrite of the headers, `/admin`
  dropped, the Web App Firewall), F5 APM (access profile, iRule) and nginx / oauth2-proxy,
  filled in with this server's values, with Copy buttons. Each node's root helper adds one line
  to the portal's `location = /` (checked with `nginx -t`); off, only that line goes. The
  administration pages are not concerned. `acme --sso-status`, `acme --sso-key`; in the console
  under *Encryption, sending out, time, network, high security*. docs/portal-sso.md.
- **The VIP address no longer lost for good when its name was taken away** (as otp 1.0.242).
  With a certificate of the VIP address's own kept and its name (*FQDN*) emptied afterwards,
  each node's root helper refused the whole request ("a certificate of its own needs the name it
  is for") - and no change of nginx, keepalived or the firewall reached the node again. The
  node's certificate now serves the address until a name is given again (said in the log); given
  a name, its own certificate is back on it. A part of nginx the helper cannot put in (the
  balancer's lines above) is said and holds up nothing else of the request either.
- **Dual certificates in and out of acme's own TLS** (*Settings → TLS and the VIP address*; as
  otp 1.0.240): an RSA and an ECDSA certificate of the same names uploaded together - both keys
  in the PEM, two PFX files, or one of each; on the command line `acme --tls-import rsa.pfx
  ecdsa.pfx` - are both put in, the RSA one the main and the ECDSA one beside it, as ACME's
  "both" keeps them (nginx gives each client the one it takes). One alone is as until now, and a
  second one there before is dropped. Two RSA, other names or a key without its certificate are
  refused. *Download* of such a certificate asks which: RSA, ECDSA, or both (a .zip of the two in
  the format chosen - not only PEM as before - each key locked with the password); in Events
  which and with what.
- **SELinux** (*Settings → High security → SELinux*, a card for each node; `acme --selinux-check`),
  as in otp 1.0.233-1.0.238. Nothing changes unless asked: a machine with SELinux disabled stays so,
  and acme runs on it as before.
  - acme's module `acme_server` (`deploy/acme_server.cil`): the labels of `/run/acme` **and**
    `/var/run/acme` and the API token as the web server's own run files, so the pages (php-fpm,
    `httpd_t`) can read the token under enforcing; and one narrow rule - systemd may change the
    owner and mode of what is in `/run/acme` before every command of the unit (`systemctl reload
    acme` too). Put in by install.sh and every upgrade where SELinux is on (only when it changed,
    compared with the one last put in), taken out by `--uninstall`. The tools (`policycoreutils`,
    `libselinux-utils`, `policycoreutils-python-utils`, `audit`, `selinux-policy-targeted`) put in
    where missing on RHEL, Rocky and AlmaLinux - the mode is not touched - and auditd started
    where SELinux is on.
  - The card: the mode now and after a restart, the module, the labels of acme's files, the boolean
    (`httpd_can_network_connect`) and ports (sshd's own, a local PostgreSQL's) acme needs, and what
    SELinux refused since the machine started, grouped and counted - only since acme's needs were
    last put in, and not what the policy loaded now allows (`audit2why`: *refused before, allowed
    now*). auditd not running is said, and enforcing refused. Looked at two minutes after the
    start and every half hour (at the lowest priority), and on *Look again*.
  - The steps, each asked of one node and done by its root helper: *Make it ready (permissive)* -
    the configuration, every file labelled at the next start, `selinux=0` off the kernel's command
    line, the module; the machine is not restarted. *Put in what acme needs*. *Switch to
    enforcing* - from permissive only, with nothing missing and nothing refused. *Back to
    permissive*. Each in Events.
  - *Download the report (all nodes)* (`acme --selinux-report`): every node gathers what SELinux
    says there - what it refused (raw, readable, `audit2why`, `audit2allow`'s suggestion), the
    labels and what the policy says they should be, domains, ports, booleans, versions, what acme
    uses on the node (nothing secret) - in one file; nothing is changed to make it, kept sealed in
    the database an hour. Sent on, it becomes rules of `acme_server`.
  - The security check lists what keeps a node where SELinux is on from being protected; the
    alert *SELinux refusing* (`alerts_selinux`, off by default) mails it.
  - `acme --selinux check|prepare|apply|enforce|permissive` (asked first unless `--yes`), and the
    console (*Encryption, sending out, time, network, high security*). docs/selinux.md.
- **Root's actions only from rows acme signed - the guard against writes to the database**
  (*Settings → High security → Guard against writes to the database*, `db_guard`; off by
  default - as until now; from otp 1.0.231-1.0.236). What a node does as root - the firewall,
  sshd and root's SSH keys, the network, a restart, the system's updates and their proxy, the
  time servers, nginx's certificates, the VIP, the TLS of the database link - follows rows of
  the database, and so do the accounts and sign-ins of these pages. Anybody who could write the
  database (its server, a db_password found out, a copy put back) could have had the node do any
  of it.
  - Every such row is signed when acme writes it - an HMAC with a key from secrets.key, in no
    database - in a row of its own beside it (`sig:<kind>:<hash>:<node>`; each node writes only
    its own), in one transaction with the row.
  - On: a sign-in, an account, the administrators' directory, a setting that reaches root, a row
    of meta root acts on, another node's heartbeat - not written by acme, or an older one put
    back - is not acted on; settings keep their last good value. Said in the log, in Events and
    in the security check. The certificates, renewals and deployments are never held up by it.
  - Kept in this node's config.json, not in the database; switched off only on the node itself,
    taken by the running service at once (`acme --set db_guard=1`). A copy put back, an import,
    the database moved and a node renamed are signed again afterwards; a node rebuilt from the
    other only forgets what it had seen. Going back below 1.0.40 is refused while it is on on any
    node. `acme --guard-status` (and on the console under high security) lists every row that
    reaches root not as acme wrote it. docs/high-security.md.
- **`systemctl reload acme` took the pages off the node** (as otp 1.0.232): systemd gives
  `/run/acme` back to `acme:acme` before a reload; the pages could not read the API token,
  `/healthz` said 503 and keepalived moved the VIP address away. The daemon gives `/run/acme` and
  the token back to `acme-web` the moment the reload arrives, and checks it every 5 seconds.
- A change of the settings made on the other node while this one was reading its own was missed
  until the next change: the mark of the change is read before the settings now (otp 1.0.234).
- **Bug hunts A and B of otp (1.0.234-1.0.235), carried over:**
  - **The VIP address switched off by a name not answered**: with `ha_peer` (or `ha_address`) a
    host name and DNS away for a moment, the node stopped keepalived and took its configuration
    away. It goes on with the addresses last known now; a name not answered is asked again in
    half a minute. Its database gone, the node says so to keepalived at once.
  - **A change of sshd on trial** whose time ran out while the machine restarted was kept for
    good: its timer does not outlive a restart. The root helper puts it back at its next run;
    the timer is armed before the change goes in.
  - **SSH on another service's port** (443, 5432, 53…) refused - sshd could not bind it and
    stopped.
  - **Moving into another database**: what was written while it was carried, or after - a
    certificate added, a password changed - was left behind, and *Start using it* did not see it.
    It compares the certificates, their versions, sources, validations, targets, deployments,
    tests, DNS, teams, tags, profiles, accounts, settings and directories now, and refuses an older
    copy. The codes of the administrators' app used meanwhile stay used, there and when a copy is
    put back.
  - **Backups to other machines**: room for them checked first (twice the database); an unlocked
    archive fetched from a destination refused even where no password is in play; the weekly check reads the newest
    *nightly* copy (it read the hand-made ones, and passed with nothing read); locking or opening
    a large one is not cut off after two minutes.
  - **acme's own certificate by ACME**: two nodes with the manual DNS step take turns instead of
    cancelling each other; any failure of an order is written down.
  - **Mail**: a code being sent is not taken back for another try before one try can have ended
    (it went out twice), nor tried in its last half minute; a redirect to another host does not
    carry the gateway's credentials; the weekly or monthly report missed on its day goes on a
    later day of the period.
  - Smaller: the SNMPv3 count of starts written whole (cut short, it went back); a time zone or
    interface name that reads as an option refused; a sign-in that counted twice in one request
    gives both places back; a node stopped half way through a write no longer holds its rows on
    a database server for hours.
- **A code typed as the mail shows it** (as otp 1.0.224-1.0.227): the administrators' second
  step takes "821 275", "821-275" or any dash, a no-break space, full-width digits and the top
  row of a Czech keyboard without Shift; a 10-digit code is no longer cut short in its box.
- **Wrong directory passwords per person capped** (*Settings → Sign-in protection → Wrong
  directory passwords per person*, `dir_pw_tries`; 0 by default - as until now), as
  otp 1.0.230 - 1.0.234. A directory password is tried against Active Directory at
  each sign-in to the enrolment pages (the certificate portal) and at each sign-in of
  an administrator from the directory - each with a count of its own, on each node
  alone: from many addresses, enough wrong ones for a name reached the directory to
  lock the account there. Set below the directory's lockout threshold (3 for 5 to
  10): after so many wrong passwords for one person within `dir_pw_window_min` (30
  min), from anywhere, on any node, the directory is no longer asked for them - only
  the pages wait, the account in Active Directory stays unlocked.
  - Counted **by the account the directory resolves**, not by the name typed:
    `novakj`, `jan.novak@corp.cz` and `CORP\novakj` are one count. A name the
    directory lacks - or an account switched off, locked or answered twice - is held
    back the same way, so the answer does not tell which names exist. A right
    password does not count, nor one never asked of the directory (empty, with a
    control character); the address's own count keeps its place too. One count for
    the cluster, in the database.
  - **Each directory** on a card of its own (*Wrong directory passwords - each
    directory*): *As the setting above*, *Its own* (a cap and a window for it alone)
    or *No cap*. A directory renamed keeps its cap, one taken away takes it with it.
  - **Read the domain's policy** (full administrators) connects with the
    directory's own account and shows the domain's *Account lockout*, *Password
    policy* and every *Fine-grained password policy* it may read, and recommends a
    cap below the lowest threshold over the longest window. *Use it* only fills it
    in - nothing changes until *Save the changes*.
  - Shown and cleared under *Locked out*. `acme --dir-caps`,
    `acme --dir-cap NAME=3/30|setting|none`, `acme --dir-policy NAME`; on the
    console under *Directories*. docs/sign-in-protection.md says all of it.
  - The card of a directory: its two sections side by side, of the same width,
    across the whole width - a third, empty column left them narrow.
- **Alerts for what the nodes already see** (*Alerts and reports*), as otp
  1.0.242 - mailed now, each with a switch of its own, on by default: the key that
  opens the sealed secrets missing on a node and two nodes under one name (under *A
  node down*); **logs not reaching isemon or the syslog servers** (with the lines
  dropped); **the SNMP agent not listening** or its traps not going; **a certificate
  of a node or of the VIP address the CA did not renew** - at once, not only once it
  is about to run out (the certificates the certificate manager keeps are said by
  it, as before); the certificates of **PostgreSQL's TLS and the link between the
  nodes** running out (with *A certificate running out within*); **the update of
  the system failed**, or a node that cannot look for updates; **an upgrade of acme
  that failed**; **a change on trial that went back** (the network, the firewall,
  the SSH server - the network's going back is in Events now too); **rows of the
  database not written by acme** refused (the guard against writes); **mails with a
  code or a notice of certificates that do not go**; a clock out of sync on a node
  without chrony. Off by default, for who wants them: the replication behind by more
  than N MB, SELinux, the security check, each sign-in by the load balancer
  refused. *The nodes apart* and *the clock guard* have switches of their own too
  (on, as they were). Fixed on the way: with no event at all when the alerts first
  looked, what happened later was never mailed.
- **The alerts in a cluster** (as otp 1.0.234): "quiet while a node is worked on"
  was one row both nodes wrote - two first rows at once stop the replication; each
  node writes its own now. A test alert or *Forget* on the node that does not send
  no longer writes back an older copy of what was sent (the same alerts again).
  The weekly or monthly report missed on its day goes on a later day of the period.

- **Sign-in protection** (*Settings → Sign-in protection*, as otp's pane). **Block a place that
  keeps guessing** (`login_guard`; off by default - as until now): the sign-ins to these pages and
  to the certificate portal counted by the address they come from too; too many refusals from
  one place, or too many different names refused from it, and it is blocked for a while
  (`login_guard_tries`, `_names`, `_window_min`, `_block_min`; `login_guard_trusted` never
  blocked) - its sign-ins refused at once, no directory asked. With it: the cap of wrong
  directory passwords per person (one switch for the guessing guards, as otp 1.0.241), each directory's own cap with *Read the domain's policy*, and
  *Counted and blocked now* - the sign-ins to these pages and the portal, the codes sent and the
  names held back, with a filter and *Clear*. For every directory set in *Accounts → The
  directories administrators sign in against*: the administrators' sign-ins and the portal's.
- **Where a person's e-mail address and mobile number are read from the directory - on each
  directory's card** (*Settings → Accounts → The directories administrators sign in against →
  edit*, *A person's e-mail and mobile number*; as otp 1.0.229). As until now by default: `mail`,
  and `mobile` with `telephoneNumber` when that is empty. Any attribute, or several in order (the
  first with a value is taken); `proxyAddresses` read as Exchange keeps it (the primary SMTP:
  address). Used for the codes by e-mail and SMS and for what the portal knows of a person.
  *Show a person's attributes*: the whole entry of one person, from the card as it is now (saved
  or not), with what the boxes would read, the attributes that can hold an e-mail address and
  those that can hold a phone number each with *Use*, and every attribute of the entry listed. A
  full administrator only; written into Events. `acme --dir-sample NAME USER`, and on the console.
- **A one-time code at every sign-in to the certificate portal** (*Settings → The enrolment
  pages → A one-time code at every sign-in*, `portal_code`; off by default - as until now): a
  person of the directory signs in with their name and password - or is signed in by the load
  balancer in front (SSO) - and a code goes to the e-mail address or the mobile number the
  directory has for them (read where the directory's card says), at **every** sign-in, not only
  the first as otp has it. Until it is typed nothing else can be done and nothing of the person
  is shown. The page as otp's: where the code went (masked), the box, *Confirm*, *Send it again*
  and *Back*; pasted as the mail or the SMS has it ("482 913"). By e-mail, by SMS, or one with
  the other where the directory lacks it; saved only with the mail or the SMS gateway set up.
  Its own words in *Settings → Message texts* (a mail and an SMS). Each code sent, each wrong one,
  the sign-in with it in Events - never the code. The portal's own accounts keep their second
  step as before.

- **Signing in over SSH with a code from acme** (*Settings → SSH server and notices →
  Signing in with a code from acme*; off by default - as until now), as otp 1.0.178 -
  1.0.243. sshd of every node asks for a code where it would ask for the account's
  password: `pam_radius` asks a small gate of the acme daemon on 127.0.0.1 of that
  node (a port of 18129-18199 each node finds for itself, a long secret of its own,
  sealed), so a node alone still lets you in. The gate understands only what
  pam_radius sends (an Access-Request with User-Name, User-Password,
  Message-Authenticator and State) and answers nothing from elsewhere or signed with
  another secret. Needs *acme sets the SSH server*; put in on trial like every change
  there, checked with `sshd -t` first, and put back by itself unless kept.
  - *Only these accounts* (picked from the accounts of the nodes; none: *Everybody but
    root (unless Root too)*), *Root too*, *A key, and then the code*
    (`AuthenticationMethods publickey,keyboard-interactive` for those asked; root with
    a key only gets a `Match User root` block of its own), *The system password when
    acme does not answer* (`localifdown`, only with passwords on) and *Hide the code as
    it is typed* (echo off).
  - **SSH tokens**, a list of their own under the card (*Account, Note, The codes, Made,
    Last used*; *A new one…*, *Remove*; *Add an SSH token…*): one for each account of
    the nodes - root, or a user who may sign in there; one that has a token is not
    offered, and the daemon checks the name again. Codes **from an app** (the QR code
    and the key shown once), or **sent by mail or SMS** where sending is set up, in
    Czech or English (*Settings → Message texts → SSH: a sign-in code by mail / by
    SMS*). One prompt, no `Password:` first; a wrong code asked again three times; a
    code good once on either node; five wrong ones for a name in five minutes and it
    is refused for five minutes; a code by mail or SMS at most every 20 s and five in
    15 minutes per account. Every sign-in and every wrong code is an event (*ssh*),
    never with the code in it.
  - The root helper writes only `127.0.0.1` and a port of 18129-18199 into
    `/etc/acme/pam_radius.conf` (0600), its own block into `/etc/pam.d/sshd` between
    two marker lines (taken out whole when switched off), installs `pam_radius` where
    it is missing (RHEL: from EPEL) and turns SELinux's `authlogin_radius` on;
    *Settings → SELinux* lists it and the gate's port (`radius_port_t`, UDP
    18129-18199 only).
  - High security: with the code asked and no system password when acme does not
    answer, keyboard-interactive is no longer counted as a password sign-in, nor
    root's own block as root signing in with a password (as otp 1.0.242).
  - Each node's card says whether pam_radius asks for the code and where the gate
    listens - otp read it from where it is not, and showed "–" always.
  - Also `acme --ssh-tokens`, `acme --ssh-token-add NAME [--by mail|sms --to …]
    [--no-qr] [--invert]`, `acme --ssh-token-del NAME` and three items in
    `acme --console`. See docs/ssh-with-a-code.md.
  - *Settings → Message texts → SSH: what it asks for the code*: what ssh shows when it
    asks for the code - by mail, by SMS, from the app, and a wrong code asked again - in
    Czech and English, each shown in a terminal's window with its size (at most 253 bytes,
    as RADIUS carries it; longer or empty is refused when saved).

## 1.0.39 - 2026-11-04

- The nightly dumps of the database were never seen: they are called
  acme-ENGINE-..., and only the names of otp (otp-, opt-) were taken. So
  the card The database on Overview counted only the copies made by hand
  or before an upgrade and turned yellow ("last copy 3 days ago") beside a
  dump of last night; Settings → The database did not list them, they could
  not be downloaded, and they were never kept to "Copies kept" - they piled
  up. Now they are counted, listed, downloadable, and the oldest go once
  there are more than "Copies kept" (at the next night's dump).
- The card The database says why it is not green, under its number and at
  the top of its popup: no copy every day, the last one failed (and what it
  said), made by the other node of a cluster on one database, the first one
  still to come, or late - with when the last one was made and when the
  next one is due. Its list of copies has the nightly dumps in it too.

## 1.0.38 - 2026-11-03

- A popup over another one - what the server served, What happens, Export,
  Import and the rest - no longer throws the one underneath back to its top
  when it is closed: it stays scrolled where it was, also while its parts are
  asked for again. A popup opened afresh still opens at its top.

## 1.0.37 - 2026-11-03

- What happens records what a module does on its own too, not through acme's
  Context: HTTP over http.client or urllib (MS AD CS, a module of your own) -
  each request whole, its proxy said; FTP and FTPS over ftplib (the HTTP-01 over
  FTP validation) - the connection, whether the server's certificate is checked,
  every command (PASS ••••), each upload with its size; a socket of its own - UDP
  with every byte it sends (SNMP, say), TCP with where it connects (what it says
  there cannot be told). Still nothing is reached.
- What happens, with its debug details: bytes taken apart as Wireshark shows a
  packet (acmelib/certs/dissect.py) - each field named, its value read and said
  (flags one by one), the bytes it comes from; the bytes under it, the ones of
  the field pointed at lit up. What the tests send before TLS: LDAP's StartTLS
  (BER), PostgreSQL's and MySQL's SSLRequest (its capability flags), TDS
  PRELOGIN (its options), RDP's TPKT / X.224 / RDP_NEG_REQ (the protocols asked
  for); what a module sends over UDP: SNMP (BER: version, PDU, varbinds - the
  community, a password in effect, never shown), DNS (header flags, questions),
  syslog (priority). A packet cut short: what could be read, then said so.
- What happens: *Show debug details* (off by default, kept in the browser). Off,
  the page is as it was - the headers a module sets, the steps of a test in
  short; on, everything below: each request as it goes on the wire, how each
  connection is made, the ssh command with its options, a test's every fact.
  The other steps' facts too: the TLS handshake after a deployment (its
  address, SNI, the key asked for, how it is compared), a DNS question (its
  servers, port, transport), a command run here (as whom, in which folder, its
  variables, no shell).

- What happens shows each HTTP request as it goes on the wire: the request line,
  every header in the order sent - the ones acme and Python add (Accept-Encoding,
  Content-Length, Host, Content-Type, User-Agent, Connection) dimmed - and the
  body as sent; *Copy the whole request*. Above it how it is connected: the
  address and port, TLS, the name sent as SNI (none to an address), how the
  device's certificate is checked (this machine's CAs, the CA set, or not at
  all), a client certificate, the proxy, the time limit. Secrets left out as
  before (a password, a token, a header that signs in: ••••). A module of your
  own, never seen here, is shown the same: what it really sends, recorded.
- What happens over SSH: the ssh command as it runs, every option (the host key
  checked against the one kept, its time limits, how it signs in, BatchMode)
  - its temporary files said, a password never in it - folded under the
  connection's facts; the options made in one place for the connection and the
  plan (runtime.ssh_options). A DNS UPDATE: its server, port, transport and
  TSIG key's name (not the key).
- What happens for a test: the connection (address, port, address family, from
  the address, time limit), what it says before TLS line by line (SMTP's EHLO and
  STARTTLS, IMAP, POP3, FTP, XMPP; the bytes of LDAP, PostgreSQL, MySQL, TDS and
  RDP's start), the ClientHello's settings (SNI, TLS versions, ciphers, ALPN, the
  key asked for - both: two connections), and an HTTPS test's request whole, its
  headers too (Authorization, Cookie and API keys: ••••); what counts as right
  (the version, the name it must hold, trust, the days before its end, the HTTP
  status and words). A test's talk() is held to what it really sends by
  test/test_checks_protocols.py; a test of your own without one is said so.

## 1.0.36 - 2026-11-03

- Tests: *Key asked for: both* - connected twice, once for RSA and once for
  ECDSA, each judged and drawn side by side (the half of acme's certificate it is
  set against only); the worse of the two is the result, the job's log and the
  mail say each. A result says what counted as right (*Expected*), and the half
  of acme's certificate set against what was sent is drawn first - the card of
  what was sent beside it, not below the other half.

- Settings → Upgrades → *Look now* just after a release found nothing new:
  raw.githubusercontent.com keeps a branch's index.json 5 minutes (and an
  address with ?anything does not get past it). The look asks GitHub's API for
  the branch's newest commit (one question) and reads the index of that commit,
  an address that never goes stale; where the API does not answer, the branch's
  index as before.

## 1.0.35 - 2026-11-03

- Two files of your own saying the same kind and version (an upload of
  `netscaler_14_1 (1).py` beside `netscaler_14_1.py`, say): the module's window
  says which is used (the later by name) and which not, with *Take the unused
  one away* - it was silent. `shadowed` in `GET /api/plugins` and
  `/api/modules`.

- Modules → a module → *Make it the default* on any of its versions: what every
  source, validation, target or test that names no version uses - kept in the
  database (both nodes, every backup), over `default_version` in the code; the
  window says first how many follow it; *As the code says* takes it away.
  `POST /api/modules/default`.
- *Upload it* for another version needs no version typed - the file says its
  own; once checked, the file is named by its kind and version
  (`netscaler_14_1.py`), not by the name of the file brought
  (`netscaler_14_1 (1).py` became `netscaler_14_1__1_.py`).

## 1.0.34 - 2026-11-03

- /etc/acme/plugins: install.sh makes `checks/` too (tests of your own had no
  folder), and writes `README` (where modules come from, which one wins, how
  they are kept on both nodes and in backups) and `examples/` again at every
  install - working examples as `*.py.example`, not loaded: a new target,
  another version of a shipped target, an override, a new test, a version of a
  validation and of a source (each loaded by test/test_plugin_examples.py).
  docs/writing-a-module.md: *Where modules come from, and which one wins*, in a
  cluster and in backups. A full backup and its restore are tested with a test
  of your own on the disk, an uploaded module and a mark.

- A test's result drawn side by side: what acme keeps (both halves of a dual
  certificate) beside what the server sent - a card each, the lines that agree
  ticked, the ones that do not red (names, issuer, validity, key, SHA-256), and
  how it was reached under them. A test that fails says the same in the job's
  log (a line for each: `✗ key: acme RSA 4096 | sent EC 384`), in the event, and
  in its mail (a table *In acme / The server sent*). The cards stand level, the
  one sent in the row of the one it is set against. A key said once (RSA 4096,
  not ec-256 256). The import window: a ZIP offered, its parts apart.

- Import of a dual certificate (RSA and ECDSA of the same names): a file
  holding both halves with their keys - a PEM, a ZIP (two PFX, .crt and .key,
  folders), or the two files dropped together (rsa.pfx + ec.pfx: `more` on the
  API) - is imported as the certificate and its twin at once, the twin shown
  next to it; the other half imported into a certificate later is kept as its
  twin (the same names, the other key type - guessed, or *Kept as* in the
  window, `"as": "alt"` on the API), not as its next version, which put the
  first half away.
- A certificate's *Export* of a dual one: *both* besides the main one and its
  twin - one PEM file holding the two (with both keys in *Key and full
  chain*), which acme imports again as the pair. A PFX holds one key only.
- Settings → Certificates and TLS → *Download* of a dual certificate asks which:
  the main one, the second one beside it, or both in one PEM - it gave the main
  one only, so the second could not be had.

- Tests: a server sending the other half of a dual certificate acme keeps only
  one half of (the same names, ECDSA where acme has the RSA one) is said as
  that - "serves the ECDSA twin of this certificate ... import it as its twin,
  or set Key asked for" - not as a stranger's certificate. A test's new *Key
  asked for* (whichever, RSA, ECDSA): TLS 1.2 with ciphers of that key only, so
  a dual server sends that one.

- Modules → a module → *Download a start* asks first: only a start (a few
  lines that take the module as it is) or the whole code of a version - the
  shipped one, any of yours, or the shipped original under a replacement - its
  class already saying the version and label you named (or, for a replacement,
  the shipped version): change a line and upload it. A file of two modules
  (tls.py: tls and https) copies only the one asked for. The upload window has
  *Start from the whole code of* too.
- A shipped module replaced: its original stays listed under your replacement
  - "shipped original - replaced, not used", its own *Download this code* (the
  shipped code, not yours). Every row says *Download this code*; the
  replacement's upload button is *Upload a new replacement*; the card says what
  is in use instead of what.
- A long popup opens at its top: a box far down (the version of a module of
  your own) is not focused, so the window does not open scrolled to it.

- A name box just opened is not red yet ("it needs a name" said before anything
  was typed - a new authority, say): said once something is typed or the box is
  left; the main button is off meanwhile, as before.
- A test's window is called "Test mail-smtp" in Czech (it stayed "The test
  mail-smtp": a name with a hyphen in it). "No tag." in Czech in a form's tags.

## 1.0.33 - 2026-11-03

- Settings → Accounts: an account's role is changed in its own column - beside
  the buttons the row ran past its card. About: a node's name apart from its tag.

- A module's tags (own, uploaded, override, version, marks) look one way
  everywhere - the same height, corners and letters, apart by a gap - and in the
  "Add a …" tiles they sit in a row of their own at the bottom left.

- Import of a PEM with its key locked: the password is asked for above what was
  read (it said "no private key in the file", and asked nothing); typed in the
  file's password box, the file is read again; the key's password works for a
  key inside the file too. A key in a file of its own, dropped beside it, is
  said as "its key: …", not "no key". A wrong password says so, not "give its
  password". The read notes in Czech.
- Modules → a module: making one of your own said as two ways - another version
  beside it (named: as many as needed, each with its version and label) or the
  shipped one replaced - each "Download a start" and "Upload it". A file of your
  own starts from the shipped module, never from another uploaded one. An
  uploaded version: "Upload a new file" replaces it. The window is drawn again
  after an upload, a mark or a file taken away (it showed what was there
  before). The upload window: its parts apart. The list: every module's icon
  in one column under its heading, a stripe (your own, the row under the
  pointer) beside it, not over it.

- Import of a certificate did nothing: the Import button broke on a box of
  its window (the owner) it could not see. It imports again.
- Tests on a server over SSH: can be saved with no test chosen yet; the tests
  it runs are a table with "Add a test" under it, as a certificate's
  deployments are, not ticks.
- A certificate's Tests: a table as its Deployments - test, state, where, last
  run - its buttons under it on the left; what the server served opens from
  the row.
- Tests: switched on and off right in the list, as targets are.
- HTTPS test: "Ask over HTTP too" says that it brings the method, path, Host
  header and other headers.

- Settings → Modules: its icon in the rail; the pane as tall as the window, only
  its list scrolls (there were two scroll bars); no lede said twice. A
  module's window: its sections apart as in every other window.

## 1.0.32 - 2026-11-03

- **Tests of what the servers serve**: Certificates → **Tests** defines
  them as targets are defined - a module, its settings, *Test* - and the
  certificate's window attaches them as it deploys (*Attach a test*). A test
  connects as a client of its protocol would and compares the chain it is sent
  with the certificate: the version deployed (or an old one - the renewal did
  not reach the server - or another certificate), the names, the chain, how
  long it runs, trust here; HTTPS also asks over HTTP with its own Host header,
  path and status expected. Modules: HTTPS, TLS on any port, SMTP (STARTTLS) and
  SMTPS, IMAP / IMAPS, POP3 / POP3S, FTP (AUTH TLS) / FTPS, LDAP (StartTLS) /
  LDAPS, RDP, PostgreSQL, MySQL / MariaDB, Microsoft SQL Server (TLS in TDS),
  XMPP, MQTT, SIP and DNS over TLS - and a **connector** that signs in over SSH
  to a Linux server (the key card of an SSH target) and runs the tests chosen
  for it from there (`ssh -W`). Every setting can be set: the address connected
  to (an IP), the SNI, the name looked for, the certificate expected, TLS
  versions, ciphers, ALPN, the address family and source. Run after the
  certificate's deployments, by themselves (Settings → Renewal and notices:
  *Test the servers by themselves*, every 360 min), or now; a test that starts
  failing is an event, a mail and an SMS (Settings → Message texts: *A test of
  a server failed* / *works again*). *What happens* shows them as a phase of
  their own, one test at a time or side by side. Command line: `--tests`,
  `--check-add` … `--check-attach CERT TEST`, `--checks`, `--check-run`.
  Tests are modules as any: overridden, versioned, uploaded (docs/checks.md,
  docs/writing-a-module.md).
- **Settings → Modules** (was a tab of its own).

- **The page Modules**: every module sources, validations and targets are
  made of - shipped, your own on the disk of a node, uploaded on the page -
  with where it comes from, its versions, how many use each and its marks;
  tiles to filter by origin, the families as chips, a search box as every
  other. *Download* gives the source of any module (a shipped one to start an
  override from); *Make one of your own* a file that subclasses it; *Upload a
  module* takes a `.py` file, checks it in a process of its own and shows
  what it would add or replace before it is kept. Uploading, marking and
  taking away are a full administrator's, written to the events.
- **Versions of a module**: several classes of one kind, each with its
  `module_version` (an API version of a device); each source, validation or
  target chooses its version in its form (cards under *Settings of the
  module*), kept as `_version`; the default by `default_version`. A version
  that is gone is said in red and the default one used meanwhile. Works for
  overrides too - a shipped module without versions can get two of your own.
- **Overrides said**: a module of your own with the kind and version of a
  shipped one replaces it - tagged *override* (orange) wherever the module is
  drawn: its form, the lists, the module picker; one of your own *own module*
  or *uploaded* (violet), a version in blue.
- **Marks**: *tested* (cyan), *works* (green), *problem* (red) on a version of
  a module - set by a full administrator (also `acme --module-mark`), kept
  with the file's sha256 (a file changed since is said), and shipped with a
  release in `acmelib/plugins/verified.json` (outlined, with a shield);
  `acme --module-marks-export` writes the marks of an installation in that
  shape.
- **Modules of your own are backed up**: uploaded ones live in the database -
  in every copy and on both nodes, each node writing them into its own folder;
  the files on the disk (`/etc/acme/plugins`) are kept in the database too,
  in every copy (they were only in a full backup), compared between the nodes
  (the page warns when they differ) and written back by `acme --plugins-sync
  NODE`.

## 1.0.31 - 2026-11-03

- **NetScaler (Citrix ADC): a certkey not there yet is added.** NITRO says
  "not there" as HTTP 599 with an errorcode - `1540 Certificate does not
  exist` for `GET sslcertkey/NAME`, `258 No such resource` - where acme looked
  for 404 only, so the first deployment stopped at *reading acme-NAME: the
  device said 599 - Certificate does not exist* before anything was
  uploaded. Those two codes are read as "not there" for the certkey, its CA
  certkeys and the SSL virtual servers; any other 599 is still an error. A
  copy of the module put in /etc/acme/plugins/targets/ to get round it can be
  deleted after the upgrade (it would go on overriding the one shipped).

## 1.0.30 - 2026-11-03

- **dns-persist-01: a record at each name - a switch.** Let's Encrypt looks the
  record up only at the name it validates (Boulder, va/dns_persist.go:
  `_validation-persist.<the name>`, no look at the domains above): staging
  refused pokus.example.com - *NXDOMAIN looking up TXT for
  _validation-persist.pokus.example.com* - although
  _validation-persist.example.com with policy=wildcard was there, which the
  draft says covers every name under the domain. The new switch **A record at
  each name (Let's Encrypt today)**, off by default - turn it on for Let's
  Encrypt as it is now: each name of a certificate gets, and is checked for,
  its own `_validation-persist.NAME`
  (`policy=wildcard` covers that name and `*.NAME`); *Write the records to DNS*
  and an order write the missing ones through the chosen validation; the
  readiness check says a name without its record is not ready. Off (the
  default): the draft's way - one record of the domain covers the names under
  it, as before. "Domains with the record" is *Names with the
  record*.

## 1.0.29 - 2026-11-03

- Find the settings from the account: a failure is said in its own words
  (it showed "HTTP 200"), with every step of the job; SSLmarket orders that
  cannot be read are a note, the rest is still found.
- Finding the settings from the account on the command line and in the
  console too: `acme --source-discover NAME` (`--validation-discover`,
  `--target-discover`; `-` with `--kind` and `--set` for one not saved) shows
  what the account says beside what is set; `--fill` saves it into the
  settings left empty - nothing set is replaced, a list is chosen with
  `--set`. The console offers it in the menu of each module that has it, and
  `acme --plugin KIND` says what it asks.

## 1.0.28 - 2026-11-03

- **Find the settings from the account** (discovery): over the form of a
  source, a validation or a target, a button opens a popup that asks only the
  sign-in (an API key, a user and password, the address). acme asks the
  account's API - read-only: nothing is ordered, changed or saved - and offers
  what it found beside what the form says: values the form has none of are
  ticked, values it has otherwise are not, lists are a choice. "Fill in the
  ticked ones" puts them into the form; Save keeps them. Every field stays
  settable by hand. SSLmarket takes the product list, the orders and - from
  the last order (or the account's organisation) - the owner, contact, invoice
  data and DCV method; SSLmarket ACME its ACME keys, products and
  organisations. Other sources: their organisations, profiles, products,
  templates, CAs, mounts and roles, the account's contacts, orders to reuse
  (never picked by themselves). DNS validations: the zones the account sees,
  and zone ids, resource groups, servers and views where a module has them
  (Cloudflare, Route 53, Azure, Google Cloud, OVH, PowerDNS, Hetzner,
  DigitalOcean, Infoblox, EfficientIP...). Targets: FortiGate VDOM, F5
  partitions, PAN-OS vsys, Check Point API version and domain, FMC domain,
  Avi version, Azure resource groups, Google Cloud locations, Cloudflare
  zones, Vault KV mounts, Nutanix clusters. Modules with nothing to find show
  no button.

- **Six new DNS-01 validations**, written from the vendors' own documentation:
  Forpsi F-DNS (the paid DNS-as-a-service only - ordinary Forpsi DNS has no
  API), ISPConfig, HestiaCP, Virtualmin, froxlor and Windows DNS (PowerShell
  over OpenSSH, Remove-DnsServerResourceRecord always with -RecordData; the
  Windows flavour of the DNS server over SSH now does the same).
- **Twenty validations re-checked** against the same documentation: Hetzner
  drops the old DNS Console API (switched off in May 2026) and waits for its
  actions; GoDaddy speaks Domains API v3 with a personal access token (v1 kept
  for settings that have a key and secret); PowerDNS uses EXTEND/PRUNE from
  4.9.12 / 5.0.2; Gandi adds and removes values with PATCH; Azure DNS writes
  with the record set's etag; Cloudflare compares TXT values unquoted (a value
  could be left behind); OVH, NS1, Porkbun, Google Cloud DNS and Akamai got
  smaller fixes.
- Active24 and Websupport send the signature's time as X-Date as well (REST API
  v2 asks for it; Date stays); Active24's old API (api.active24.com) is marked
  as the old platform, no longer working. WEDOS lists only the TXT records of
  the name (row_name, rdtype - the whole zone again on an older WAPI, never
  after a refused sign-in) and gives our TXT the TTL a TXT of that name has
  already, as records of one name and type share one there.

- **New sources**, written from the vendors' own API documents: SSL.com (SWS
  API), The SSL Store (REST API) and GlobalSign MSSL (GCC SOAP API). Each
  rekeys or reissues inside an order already bought, places a new paid order
  only with "Allow new orders (paid)", has the certificate's validation put the
  documented record or file in place, downloads with the chain, revokes and
  lists the account's orders for *Import from a source*.
- Sources re-checked against the same documents: ZeroSSL orders annual
  certificates as 200 days and downloads as JSON; Venafi Cloud's EU region is
  api.eu.venafi.cloud and renewals say USER_PROVIDED_CSR; Venafi TPP sends
  Base64 and TypeName as documented; Keyfactor sends IP SANs as "ip" and its
  own revocation codes; GlobalSign Atlas lists certificates 30 days at a time.

- **Targets re-checked against the vendors' own API documents** (16 changed,
  15 confirmed): Kemp keeps a virtual service's other certificates (CertFile is
  the whole list) and stays under 30 calls in 3 s; AWS ACM refuses a renewal of
  another key type in words; Azure Key Vault can keep the certificate as
  PKCS#12 (for Application Gateway); Sophos reads its certificate list from the
  tar the XML API answers with and sets a WAF rule's HTTPSCertificate;
  OPNsense and pfSense replace in place on Force (OPNsense optionally at every
  renewal), pfSense keeps old ones still used by OpenVPN, IPsec or the captive
  portal; A10 takes its older certificate out of a client-SSL template;
  FortiGate picks a VIP's certificate field by FortiOS version (a list from
  7.4.2); Redfish posts to the action target the controller gives and says
  when a controller (HPE iLO 6) cannot take a key; vCenter takes AlreadyExists
  as served already; PAN-OS partial commits as documented; Google Certificate
  Manager warns when an in-place update changes the names.

- **Nine more targets**, written from the vendors' own API documents
  (docs/targets.md names the files and what stays less certain): Cisco FTD
  managed by its Device Manager, Cisco ASA (HTTP Interface for Automation -
  answers read for errors, as the ASA says 200 regardless), Juniper SRX (Junos
  REST API, one commit), Azure Application Gateway (PKCS#12 or a Key Vault
  secret without a version, listeners switched), ISPConfig, HestiaCP (its
  documented commands over SSH), Virtualmin, froxlor and Proxmox Backup Server.
  Not added, and why: Cisco Catalyst 9800, WatchGuard, SonicWall, Meraki,
  pfSense's API.

## 1.0.27 - 2026-11-03

- **New sources**, written only from the vendors' own API documentation
  (docs/sources.md names the files): Sectigo Certificate Manager (Admin API:
  domains validated by CNAME, TXT, HTTP file or e-mail - the record put in place
  by the certificate's validation, domains validated already skipped - a
  certificate profile from a list, collected, renewed or replaced, revoked),
  Certum (SOAP partner API: reissued inside an order, a new order only with
  "Allow new orders (paid)", TXT/CNAME at the domain or `_certum.`, or the file
  certum.txt), GoGetSSL (API v1: reissue, or a paid order when allowed; its API
  cannot revoke - an action asks to cancel the order) and Namecheap SSL (a
  bought certificate activated or reissued, a new one bought only when allowed,
  CNAME or HTTP validation). All four can *Import from a source*.
- AWS Private CA: the template is a list of the 18 end-entity templates AWS
  documents (still typeable, per certificate too). EJBCA: the CA, end entity
  profile and certificate profile are lists (the profile lists likely need
  EJBCA Enterprise; a typed name always works), and an enrollment waiting for
  approval is said as such. DigiCert downloads the certificate by its id, as
  documented. Entrust Certificate Services is not added: its public
  certificates ended on 8 September 2025.

- **Nine new targets**, written from the vendors' own API documents
  (docs/targets.md names the files and what stays less certain): Check Point
  (Management API: a server certificate as PKCS#12, HTTPS Inspection rules and
  gateway portals, publish and install-policy), VMware NSX load balancer (a new
  certificate, the virtual servers' client SSL binding switched, the old one
  deleted), Barracuda WAF (a new certificate, the services' SSL security),
  FortiWeb, FortiADC, Cisco Secure Firewall Management Center (a new Internal
  Certificate, decryption rules switched, deployed), cPanel / WHM
  (SSL::install_ssl / installssl), DirectAdmin and Plesk (into its certificate
  repository; assigned to the site by hand).
- **A deployment's form picks from a list the target fetches** (virtual
  servers, services, rules, policies) - and a value can always be typed.

- **Five new DNS-01 validations**, each written only from the vendor's own
  documentation (docs/validation.md names the files): cPanel (UAPI
  DNS::parse_zone / DNS::mass_edit_zone with the zone's serial, only our record
  removed by its line), Joker.com (DMAPI: the zone read, our line added or taken
  away, every other line untouched), Netim (REST 1.0: the exact record deleted
  by subdomain, type and value; asynchronous operations followed until done),
  Huawei Cloud DNS (record sets, AK/SK signing) and DirectAdmin
  (CMD_API_DNS_CONTROL, deleted by name and value, every change read back).
  Their zone can be loaded as a list or typed; when the list cannot be read, it
  is found by its SOA. What the documentation leaves open is listed as "Less
  certain". BlueCat and Dynadot are left out for now (their deploy call / REST
  DNS calls are not in their public documentation).

## 1.0.26 - 2026-11-02

- **Check again checks again**, and says so: in *Add a certificate* it gave back
  the answer of a moment ago, and the zones found were kept two minutes (a
  delegation just set right still showed as it was); now everything is asked
  anew, and beside the buttons a quiet line says when it was checked, how long
  ago, how long it took and how it came out.

- **A deployment taken off from its row**: beside its Edit, a button that asks
  once in a popup and takes it off (what is on the target stays there).

- **Add only adds, and issues nothing**: the certificate waits as *added, not
  issued* until *Issue now* is pressed in its window (the look right after the
  save issued it at once before).
- **A job's window, opened again**: the certificate's window has *Its running
  job* / *Its last job*, and *Last job* in the list of certificates opens it - a
  job closed while it ran was nowhere to be found.

- **Escape closes a popup at the first press**, everywhere: a help shown by the
  pointer resting on a card or a button took the first Escape, and the popup
  needed a second.

- **A certificate's own web root** (or folder, container, bucket) of an HTTP-01
  validation - *Add a certificate → Settings* - set by a full administrator
  only, as on the module itself; a certificate administrator does not see it,
  and saving the certificate keeps it as it was set. Commands, scripts and sudo
  stay the module's alone.

## 1.0.25 - 2026-11-02

- **Lists loaded from the CA, in the source's form and for each certificate in
  *Add a certificate → Settings*** (one can always be typed): the roles of a
  Vault PKI mount (LIST roles), the certificate profiles of FreeIPA
  (certprofile_find) and the certificate templates of Google CA Service
  (certificateTemplates.list).

- The directory's groups (Settings → Administrators and the teams' members):
  *narrow this list* reads `name:`, `dn~`, `about:` with its funnel too, and the
  box stays as it is while the list under it is drawn again.

- **A search box's fields open only when asked**: by the funnel at the right
  of the box (beside the clearing cross, in its colour) or Ctrl+Space - never by
  themselves, when a popup opens or something is typed; once open they follow
  what is typed. Over a word already typed, a field picked is put after it.

## 1.0.24 - 2026-11-02

- **CZECHIA.COM (ZONER)** checked against its own swagger.json: the zone is read
  (GET /api/DNS/{zone}) before a value is added or taken away, *Test* reads it
  (or lists the domains) instead of saying only a dry run can tell, and the
  TTL is at least 120 s, as the API takes (60 was sent).

- **Active24: both of its APIs**, checked against Active24's own descriptions -
  the REST API v2 (rest.active24.cz: *Test* asks /v2/check, a Service ID alone
  gives its domain by /v2/service/{id}/dns/zone, a domain missing from the
  list of services is asked for itself) and the Active24 API (api.active24.com,
  with a token - chosen under *API*).

- **Tags: sixteen colours**, ten more (teal, cyan, indigo, pink, rose, orange,
  amber, lime, brown, slate), picked from the tag itself shown in each colour.

- **Every search box reads `field:value` and offers as one types**, as Events
  and the outgoing mail did (and otp does): Certificates (`state:failed`,
  `dns:*.example.cz`, `-tag:test`, `source:"Let's Encrypt"`, `renew:no` -
  read by the daemon, the values offered counted over the certificates one may
  see), Sources, Validation and Targets (name, kind, state, use, and every
  setting of their modules as a field: `zone:example.cz`, `product:alpiro*`),
  the records of acme's DNS server, the modules to pick from, Import from a
  source and what an authority signed. `field:a,b`, `-field:x`, `field~part`,
  `*`, `>`/`<`, ranges, `(a OR b)` and NOT as everywhere; what does not read is
  said under the box. Sources and Validation have the search box beside *Add*,
  as Targets.

- **Each certificate its own settings of its source and validations** - no
  second source for each template, product or zone. *Add a certificate* has
  the step *Settings*: every setting of the chosen source and of the
  validations its names use, with what they use, and *Own* to give this
  certificate a value of its own (an AD CS template loaded from the CA, an
  SSLS.cz product, a DNS zone, a TTL...). It follows what is chosen, and the
  renewal, *What happens* and the check of what fits use it. Secrets, where
  and as whom a module signs in, and anything that runs a command or writes a
  file stay the module's (a full administrator's).

- **New sources**, each written from its vendor's own API client (the files
  are named in docs/sources.md): ZeroSSL (REST API, not ACME - CNAME, file or
  e-mail validation, revocation), CyberArk Certificate Manager Self-Hosted
  (Venafi TPP - a policy folder, renewed in place), CyberArk Certificate
  Manager SaaS (Venafi Cloud - an application and its issuing template),
  Keyfactor Command (CSR enrollment with a template and CA, Basic or OAuth)
  and Cloudflare Origin CA (for servers behind Cloudflare). All five can
  *Import from a source*; their forms load the vendor's lists (folders,
  templates, CAs, zones).
- **New validations (DNS-01)**: Hostinger, Constellix, UltraDNS (Vercara),
  Mail-in-a-Box, EfficientIP SOLIDserver, Openprovider, easyDNS, Plesk (XML
  API) and Rackspace Cloud DNS - each from the vendor's own SDK or API
  description, listed in docs/validation.md. acme adds its value beside any
  others and removes only its own; Test changes nothing.
- **New targets**, each checked against the vendor's own code, SDK, Ansible
  collection, Terraform provider or REST specification (docs/targets.md):
  Kong Gateway (SNIs repointed, dual certificates), Nginx Proxy Manager
  (proxy, redirection and 404 hosts), VMware Avi / NSX ALB (virtual services
  or the portal, dual certificates), A10 Thunder (client-SSL templates, write
  memory), Hetzner Cloud and DigitalOcean load balancers (with *List the load
  balancers*), Azure App Service (SNI bindings), bunny.net pull-zone
  hostnames, Fastly TLS (replaced in place, its activations kept) and Nutanix
  (the cluster certificate through Prism Central v4, the cluster picked from
  a list).
- A header an API sends twice (two Set-Cookie) is kept whole.
- Active24: the signed requests of its REST API v2 carry the date as RFC 3339.
  Hetzner was checked against the new Hetzner Cloud DNS API (already used).

- **Microsoft AD CS: the templates loaded from the CA.** *Template* is picked
  from the list the CA offers the user (its Web Enrollment page
  *certrqxt.asp*, read only) - in the source's form, and for each certificate
  in *Add a certificate → Settings*. One not listed (a schema 3 template) can
  still be typed: *Type it yourself…*.
- **Every list a module loads can also be typed** (*Type it yourself…*): a
  product of SSLS.cz, a server type, a template.
- Saving the wizard no longer drops a Vault role or a template set by the API: they are
  the source's settings of the certificate now (*Settings*).
- **Import from a source: each certificate set up like a new one.** After the
  import the wizard of *Add a certificate* opens for it (for several: *Set it
  up* at each, or *Set up each one*): validation, key, renewal, profile,
  deployments - everything the source supports, as for a certificate added
  there. It starts from what the certificate says (its subject, key usages
  and must-staple are kept as its profile); saving keeps the certificate in
  use as it is and makes its next renewal so. Until set up it is marked *to set
  up* in the list.

## 1.0.23 - 2026-11-02

- An upgrade added no column declared last before a table's own rule (UNIQUE):
  the certificate an own authority signs (cert_ca_issued) was not kept.
- **Import from a source** (Certificates, beside *Import*): the certificates
  your account already has at SSLS.cz, SSLmarket, DigiCert CertCentral, Vault,
  EJBCA, FreeIPA, Google CA Service, GlobalSign Atlas or an authority of acme's
  own are listed (only asked - nothing is ordered or changed there), each with
  its names, product, state, validity, what is paid and its id there, *already
  in acme* marked; the ones ticked are imported in one job with an owner, tags,
  a validation and *Renew by itself*, and the popup says what was imported,
  skipped or failed and why. Each stays bound to its source with its own id
  there: a renewal reissues that very SSLS ID or order (free while it runs; a
  new order only with *Allow new orders (paid)*) - no *Certificate to reuse*
  needed. ACME sources cannot list what they issued (docs/certificates.md).
- **Add its private key** in a certificate's window, for one acme holds no key
  of (imported from a source, or from a file without it): pasted PEM or a
  .key/.pem/.pfx/.p12 file, checked to belong to the certificate, then kept
  sealed (a dual certificate's twin too). Until then a deployment that needs the
  key is refused in those words; one that needs only the certificate works. The
  first renewal of an imported certificate makes a new key, held by acme.
- **The clocks of the nodes** (Settings → Time, the card of otp): a node whose
  clock is off refuses right codes of the second step and keeps the VIP
  address. Chosen there: *As until now* (the default - nothing of it runs),
  *Measure and warn* (each node asks the time servers itself over SNTP and
  measures the other node's clock through its database; alerts), or *Step
  aside when not well* (the node whose clock is off steps aside - no lead, no
  DNS answers, the VIP address and /healthz go to the other node - only while
  the other is well, never both). Switches: the codes, the heartbeats and the
  lead's lease, the pauses after wrong tries by the corrected time; step aside
  when the directory cannot be reached. docs/clock-guard.md.
- **When the nodes lose each other**, as otp 1.0.224-1.0.227: the report
  waits for the other node's rows to come over (10 min at most) and counts
  only this time apart, each thing once; with *Only the preferred node* the
  other node goes on when the preferred node's database refuses (PostgreSQL
  shutting down or starting up, or refusing while its machine answers), is
  in maintenance, or stepped aside for its clock; a node that steps aside is
  silent at once; and the question before a code, held off after the other
  database did not answer, is asked every 2 s again - in every mode.
- **A target switched on and off right in its list** (a switch in Targets; off
  asks first when certificates are deployed there). Its deployments are kept;
  on the Certificates list a certificate says "N target(s) off", and in its
  dialog the deployment says "target switched off" - nothing is put there until
  it is on again.
- A switch drawn on was taken as an edit of the person's: a live redraw of a list
  put it back on after it was turned off (the target's switch, and any switch
  whose value changed meanwhile).
- **Show a certificate** (Certificates, beside *Import* - for everybody, read-only
  too): drop any file or paste its text - PEM with any number of blocks, DER,
  PKCS#7 (.p7b/.p7c), PFX/P12 (modern and legacy, a Java PKCS12 keystore too),
  JKS and JCEKS keystores, a CSR, a CRL, a private or public key, base64 without
  its lines, a ZIP of them - and see everything in it in the largest popup. On
  top the chain as a rail, leaf to root: each certificate a station, the
  signature of each link checked, the root in this server's trust store or not,
  a missing issuer said; a keystore's entries by alias. Below, the one picked in
  cards over the whole width: subject and issuer by each part, validity with a
  bar, key, serial (hex and decimal), fingerprints, names, key usage and EKU,
  basic and name constraints, policies (DV/OV/EV), CRL and OCSP addresses, key
  ids, CT SCTs, must-staple, any other extension as its OID and bytes, the PEM
  to copy or download. A locked file asks for its password in the popup (a
  wrong one is said); a JKS shows its certificates even without one. A private
  key is only described - its type, whether it was encrypted, which certificate
  it fits - never sent back. Nothing is kept and nothing changes.
- **Sign a CSR** (Authorities): the request is read as soon as it is pasted or
  read from a file and shown beside the form - its subject, names, key, whether
  it is signed by its own key, the extensions it asks for - with what the
  certificate will get (the issuer, from and until with the authority's end,
  names, key usage, what it is used for). The signed certificate is shown in
  the same viewer with its chain, with *Copy* and *Download*; a CSR in DER (read
  from a file) is signed too.

- What happens with several deployments: a junction - the plan's line branches
  into a track to each deployment's station (its target, module, host, how
  many steps, whether it holds the key); the one picked is shown below over the
  whole width, "All of them" lays them out side by side. On a phone nothing of
  the plan runs wider than the screen any more.

- What happens: a PowerShell command sent as `-EncodedCommand` is shown as the
  script it runs, readable (a password written into it as dots); the encoded
  command as sent stays below, folded.

- The root helper (acme-web.service) writes in the journal each of its parts
  that takes 3 s or more (`journalctl -u acme-web.service`) - a page that waits
  on one of them shows which one held it up.

- Delete with revoke: the certificate stays in the list as "being revoked, then
  deleted" until its CA has it, and only then goes; a revocation that fails
  leaves it "revocation failed" with the reason - nothing deleted, not renewed
  or deployed by itself - with *Delete* (again, with or without revoking) and
  *Keep it* in its dialog.

## 1.0.22 - 2026-11-02

- Settings → SSH server: an error of one read ("the root helper of this node
  did not answer in 60 s", e.g. while the node was being upgraded) no longer
  stays on the node's card after the reads that worked since; a change that
  failed still stays said until one works.
- DNS-PERSIST-01: *Test* says what is still to do as numbered steps (make the
  account, write the record through the chosen validation, choose a fallback)
  and fails only when a certificate would fail - not for an account to be made
  at the first order or a CA not looked at yet.
- DNS-PERSIST-01: a record is read from the zone's own name servers first - a
  record just written read as "not in DNS yet" for up to an hour while the
  resolvers kept the "no such record" of the look before it.
- Each action of a module (a validation's, a source's, a target's) has its own
  icon in the lists - make the record, look, check, write, take away, products,
  discover… - instead of the same gear for every one.

## 1.0.21 - 2026-11-02

- An authority of acme's own keeps every certificate it signs (also a CSR
  signed by hand), so it can be imported later.

- WEDOS (WAPI) as its documentation says: the record's comment sent as
  `author_comment` (was `auth_comment`), every page of the domains (50 a page
  before - an account with more did not find its domain), only primary, active
  domains written to, 2316 ("already exists") taken as done, the rows read in
  either shape, and a refused sign-in holds every call to WAPI for 5 minutes -
  more wrong requests block the address at WEDOS.
- **acme never runs into the limits of the services it talks to**: a
  validation signs in **once** for all the certificates it covers - "What to
  set up" of a Webglobe validation with six certificates signed in six times
  and Webglobe answered *Too Many Attempts*. Sign-in tokens (Webglobe, Azure,
  Google, TransIP, Mythic Beasts, netcup, INWX) are kept for their lifetime per
  validation and settings, a refused sign-in is not tried again for a minute,
  lists of zones and a validation's test are shared for a little while (*Check
  again* right after asks nothing again). Every remote host gets at most two
  requests at once and four a second, from every job together; a `429`, `503`
  or *Too Many Attempts* is waited out (Retry-After, else a growing wait) and
  asked again only where that is safe, the host left alone meanwhile - and the
  job says so. Let's Encrypt's limits for new accounts and orders are kept.
- **Readiness lists are compact**: "6 certificates · 4 ready · 2 need
  attention" on top, what needs attention open and first, what is ready one row
  each (a click opens it), several ready ones folded into one row - in a
  validation's "What to set up", a certificate's *Check* and *Dry run* and the
  wizard. A check opened again within half a minute is not asked again.
- **dns-persist-01 writes its record itself**: *Write the record through*
  picks one of your DNS validations (Active24, Webglobe, Cloudflare, SSH
  DNS…); *Check the records* says per domain whether it is there, missing or
  another value, *Write the records to DNS* writes only what is missing (only
  acme's own older value is replaced, other records are left alone), *Take the
  records away* removes exactly what acme wrote. With *Write it by itself when
  missing* an order writes a missing record first; *What happens* shows it.
  Taking the validation away asks in a popup, with *Also remove its records
  from DNS*.
- *Take it away* in a validation's (source's, target's) own popup asks first -
  it deleted at once.
- A new deployment whose Save is refused (a field missing, a right missing) is
  no longer left behind: every failed Save added another one to the certificate.
- Saving a deployment (or a source, validation, target) no longer asks for a
  required field of a part switched off - "Folder of the store is needed" with
  the IIS Central Certificate Store role off on a Windows server.
- **Delete asks in a popup and revokes first**: *Revoke it first* is ticked
  (with the reason, "no longer used"); the certificate is revoked at its CA and
  then deleted, in one job - a revocation that fails deletes nothing. Where it
  cannot be revoked (not issued, revoked already, self-signed, no source) the
  popup says so. *Revoke* alone stays its own button.
- **SSLS.cz** (`ssls`, docs/ssls.md): a new source for the certificates SSLS.cz
  sells (AlpiroSSL, Sectigo, PositiveSSL, Certum, GeoTrust, DigiCert…) through
  its API SAPI v2. The product is picked from the list SSLS.cz gives (*Load the
  list* in the form - nothing is ordered); DCV by DNS (a CNAME, Certum a TXT) or
  FILE is put in place by the certificate's own validation and taken away
  after, DCV by e-mail needs no validation (the approver address picked from
  those SSLS.cz offers). Renewals are free reissues (`quickReissue`) while the
  subscription runs; a new order is a purchase and is made only with *Allow new
  orders (paid)* on (off by default). *Try it* checks the token and the allowed
  IP address and shows the credit. A form field can now be a list the module
  loads live (the type `catalog`).

## 1.0.20 - 2026-11-02

- *What happens*: a certificate says, step by step, everything a renewal of it
  does - the key and the request (made new or kept, the CSR sent in), every
  call to its source (the ACME protocol in order with its signed payloads, an
  authority of acme's own with the extensions it signs, any other source as
  its module calls it), how each name is proved (the record or file, the
  provider's API calls, the DNS questions, the wait, the cleanup), and for
  each deployment how acme connects (host, port, user, key or password, the
  host key pinned or not, TLS checked or not) and every call with its method,
  address and body, every file with its path, mode and size, every command,
  the check after it - what only the first time does marked, and who is told.
  A button in an opened certificate, and on the last step of Add a
  certificate - from what is set there, nothing saved. It is worked
  out by running each module's own code in a process that can reach nothing
  and change nothing: no device, DNS server or CA is contacted, no file is
  written; passwords, keys and tokens are never shown.

## 1.0.19 - 2026-11-02

- *Wrong codes before it has to be sent again* (Settings → Codes by e-mail and
  SMS) was never asked: a code of the second step sent by mail or SMS could be
  tried any number of times while it was good. It is gone after that many wrong
  tries, and another has to be sent.
- A CA certificate pasted for isemon, for syslog or for another ACME CA lost its
  line breaks in a box of one line - and was then refused when it was used; the
  records of acme's own DNS server could be given only one. These are boxes of
  several lines now.
- An account's role in Settings → Accounts waits for Save in the bar at the
  bottom, as every other change there - it was given the moment the list changed.
- Settings → Time and Upgrades no longer scroll sideways on a phone; a list
  narrower than its words there (the nodes of Upgrades) scrolls in its own box
  rather than laying one cell's tags over the next; a long message (an error
  with a path in it) or address breaks inside its box instead of running off it.
- In Czech: what a screen reader is told of a setting whose help has a name or
  an address in it, the words of *Give the disk back*, of the Teltonika check,
  of restarting PostgreSQL, of stopping a system update and *on the VIP address
  only* (DNS server) are translated.
- SSH DNS: the server nsupdate sends to is checked (one host and a port);
  Microsoft AD CS: more attributes saved as text are read line by line.
- Route 53, PowerDNS, Azure DNS and Google Cloud DNS validations write the TXT
  values at a name as a whole: two jobs at once (two certificates, or a
  certificate and a dry run) could each write over the other's value, and one
  validation failed. They now write one after another.
- A certificate administrator who changed a saved source's, validation's or
  target's settings (the API address, the host) and tried them (Test, *Try
  reaching it*, *Find out what runs there*) had them tried with the API key,
  password or TSIG kept for it - which could so be sent elsewhere. Settings not
  saved are tried with the kept secrets by a full administrator only (tried as
  saved, or with the secrets typed in again, as before).
- With debug on, the steps of a job showed each address a module asked in
  full - with the token of Duck DNS or the API key of DreamHost in it. The
  secrets in an address are shown as dots.
- Behind a NAT with a split DNS (the web server 192.168.43.17 inside, the name
  published with the public address), the check before the CA is asked held
  an HTTP-01 certificate back: here the name resolved to the private address.
  Where the validation's resolvers give private addresses only, the public view
  (Settings → DNS) is asked as well, and its answer - what the CA sees -
  counts; with the public address set, a name the internet sees elsewhere is
  no longer taken as right because it resolves to the server here.
- A commercial CA's DCV records (DigiCert, SSLmarket) put in place before an
  error other than a refusal (a broken connection, say) are taken away again.

- A backup put back that was made while a job ran no longer leaves its
  certificate busy for hours: those jobs come back marked failed.
- The key on the enrolment pages is also given to the person who asked for the
  certificate in a request profile that offers it (for a team).
- The commands a deployment runs on the target (before, test, reload, after,
  the script on the machine) are changed only by a full administrator, as the
  script written here already was; a certificate administrator keeps them.
- Running one deployment while another job works on the certificate waits for
  that job and then runs it (the other job's result was given before).
- Delete in a certificate's dialog goes once; its finished jobs go with it.
- A local folder target no longer writes its files again every time when the
  paths name the folder.
- A scoped account sees the members and addresses of its own teams only.
- The key of a certificate (a PFX) is given on the enrolment pages only to its
  owner, a member of its team who may manage it, or an administrator who sees
  all - no longer to a member who may only see it.
- A person of the directory signed in on the enrolment pages is asked about
  again every ten minutes: switched off there or no longer in the groups that
  let them in, and the sign-in ends.
- An account of the enrolment pages only could not give its second step there
  with *acme's own accounts* (portal_local) switched off - it was told it had
  none to give, and the sign-in page reloaded for good.
- A new password set for an account (Accounts, `acme --passwd`, a configuration
  read back), or its second step reset, now ends its sign-ins on the enrolment
  pages too - not only in the administration.
- A request waiting for approval, or declined, can no longer be switched to
  *renewed by itself* (on the portal or in the administration): the renewer then
  issued it, past the approval or the decline. The switch is not shown for a
  declined one.
- A certificate owned by a team is seen on the portal by the team's members
  only: a directory group or a person with the same name as the team saw it
  too - and could download its key where the PFX is offered.
- Wrong passwords of acme's own accounts on the enrolment pages count while the
  directory cannot be reached (they were given back with the 503, so guessing
  had no limit); a name typed there is cut at 190 characters, as in the
  administration.
- A request profile renamed keeps what was asked for from it (its count, the
  profile shown, a new CSR checked against it); a certificate deleted takes who
  asked for it on the portal with it.
- *Revoke* with *a new one at once* is refused, before anything is revoked, for
  a certificate issued for a CSR sent in (it needs a new CSR); the portal no
  longer shows what a CA said of a failed twin.
- A certificate administrator or read-only account kept to its teams could act
  on another team's certificate by giving its number written differently
  (" 5", 5.0), and take over another team's deployment by saving it with a
  certificate of its own; the Overview showed it every team's numbers and named
  the others' certificates in its alerts, and the list of jobs left its own out
  where they were past the first page of everybody's.
- *Renew now* (and revoking, deploying a new deployment at once) opens the job's
  log over the certificate again: the certificate drawn afresh took the log's
  place, and the log was lost.
- A revoked certificate switched off and on again (*In use*) no longer comes
  back as valid, nor a request waiting for approval (or declined) as one to
  issue - the renewer then issued it, past the approval.
- *Save and deploy now* pressed again after the deployment was refused (not
  issued yet) saves the same deployment again instead of adding a second one;
  the same in the wizard when a deployment of a new certificate is refused.
- The alias asked for in *Export* of a Java keystore is the alias in the file
  (it was always the certificate's name).
- Hints left in English on a Czech page: the name boxes of the wizard, the
  import, a self-signed certificate and a CSR, the secret boxes of the modules
  and the PKCS#12 password, *choose one…* of a new deployment, *default* of a
  file's mode, a script's arguments, a tag's meaning.
- A configuration read back into an installation that has certificates or
  authorities of its own keeps each deployment with its certificate (and what an
  authority signed, an authority's parent): a certificate given another number
  here left its deployments on whichever certificate had its number - another
  certificate was deployed there.
- A backup tried (*Try it*, after every backup, weekly) is no longer "not good"
  because a job, a sign-in or a code used once was written while its copy was
  made.
- Two nodes apart: a node stepped aside (or held back with *Renewals only on the
  preferred node*) no longer signs with acme's own authorities when a hold is
  released, a CRL is made by hand, an authority is renewed or one is made under
  another; and what only reads - the progress of a job, a copy downloaded, the
  wizard's choices, a preview, a check of the database - goes on on the node
  whose changes wait, and is not in the report as a change done on both.
- The preferred node renamed stays the preferred node; one that is not a node of
  the cluster can no longer be saved (`acme --set`, a configuration read back) -
  with *priority* both nodes then stepped aside while apart.
- *Stop* of a job left running by a node of the cluster that is gone (or was
  renamed) marks it stopped: it was asked of that node for ever, and the
  certificate stayed busy for two hours.
- `acme --job`, `--cert`, `--ca-show` and the others with a number beyond 64
  bits say there is none (a traceback on SQLite); `acme --events --limit` below 1
  is refused (every event, or the database's error).

## 1.0.18 - 2026-11-02

- *Renew now* asks first, in the administration and on the enrolment pages:
  what it does (a new certificate now, the one in use stays valid), from
  where, its key, and that it is put in place again.
- Running a deployment while a job works on the certificate gives that job to
  watch instead of an error.
- **Request profiles** (Settings → Request profiles, docs/request-profiles.md):
  kinds of certificates people may ask for on the enrolment pages with the
  source, the validation, the domains (wildcards, how many names), the key or
  their own CSR, the subject (each field not used, fixed or filled by the
  person), renewal, validity, usage, approval, owner, tags, who may use it and
  the PFX set beforehand - the person gives only the names. Each is picked from
  the catalogs and checked as it is saved. With none defined the portal asks as
  before.
- **A CSR sent in is decoded and shown first** on the portal - its subject, its
  names, key, signature (valid or not), usages - with every check against the
  profile and what the certificate will say beside what the CSR says; only a
  CSR that fits is asked for. Such a certificate holds no key: the CSR is kept
  and used again at every renewal (same key); *Send a new CSR* changes the key.
  A PFX or a deployment that needs the key is refused in words.

## 1.0.17 - 2026-11-02

- **Popups are wider on a wide screen**: every popup grows with the window -
  about two thirds to three quarters of it on a big screen (a certificate's
  details 1480 px at 2000 px), never the whole of it; below 1400 px as before,
  on a phone the whole width.

## 1.0.16 - 2026-11-02

- **A team's rights work on the enrolment pages**, not only in the
  administration: *manage* gives *Renew now*, renewed by itself on/off and
  *Revoke* in the certificate's dialog; *approve* (or *manage*) gives *Approve*
  and *Decline* of the team's waiting requests. The dialog says what the person
  may (*You may*), the list says *team X* for a team's certificate.
- *Ask for a certificate* is shown dimmed, with the reason, to whoever may ask
  for a team while the enrolment pages do not say yet which names and sources
  may be asked for (before: missing). Owners and teams says so too.

## 1.0.15 - 2026-11-02

- The enrolment pages no longer go blank while *Certificates on the portal* is
  off: they say that certificates are not offered yet and where the
  administrator switches them on. Settings → Owners and teams says the same
  (the members would see nothing there), with a button to the setting.

## 1.0.14 - 2026-11-02

- **A role for the enrolment pages only** ("enrolment pages only"): an account
  that never gets into the administration, signs in on the enrolment pages and
  sees and asks for what its teams give it (Owners and teams). For acme's own
  accounts (Accounts → role) and from the directory (*Group of
  enrolment-only accounts*, picked with *Find the groups*). Settings → The
  enrolment pages → *Accounts of the role Enrolment pages only may sign in*
  (on). Its first password - and any later one - is changed on the enrolment
  pages.
- **Split brain protection** for a cluster of two, as otp's: what each node
  does when it cannot reach the other (step aside, an arbiter, the preferred
  node, renewals only there, half the tries, frozen changes, the report of
  what was done apart). Default: as until now, nothing runs.
- **Validation over SSH straight on the DNS server** (BIND, PowerDNS, Knot,
  NSD, dnsmasq, Unbound, Windows): *Find what runs there* only reads, and
  fills in the server, the zones, the keys - every field stays editable.
- A certificate's details are first, with *Change*: what can be changed without
  a new certificate is said, the wizard marks the steps that make one.

## 1.0.13 - 2026-11-01

- The line on a target's form saying where files, script and roles are set is
  as quiet as the help under a field (small, dimmed), not a bright paragraph.

## 1.0.12 - 2026-11-01

- The form of an SSH, Windows or local target says where its files, their
  format, the script after them and (Windows) the roles of the server are set:
  in each certificate's deployment ("Deploy it on a target").

## 1.0.11 - 2026-11-01

- The self-signed and the CSR dialogs pick the owner and the tags from Settings
  → Owners and teams too (a certificate administrator limited to their teams
  makes certificates there as well).

## 1.0.10 - 2026-11-01

- **Deployment designer** (SSH, Windows, this machine): the files on the target
  by quick layouts or rows - format in plain words, path with {name} {cn}
  {service} {date} {alt}, mode, owner; the PKCS#12/keystore password none, set,
  or made by acme (24 characters, sealed, the same across renewals); after the
  files a script already on the machine, or written here - uploaded on every
  deployment, run with ACME_* variables (ACME_FILE_KEY_PEM, ACME_PASSWORD,
  ACME_NAMES ...), then deleted; the previous files put back when it fails. A
  live preview of the real paths and the variables, and a dry run
  (ACME_DRY_RUN=1, files into a temporary folder). Only a full administrator
  changes a script.
- **Windows roles**: RDS (Connection Broker), RD Gateway, AD FS, Web Application
  Proxy, SQL Server, LDAPS, WinRM HTTPS, SSTP VPN, IIS Central Certificate Store,
  IIS FTP, Exchange (every service), Skype for Business, SharePoint SE (beta),
  Windows Admin Center; read on the key for accounts; Test says which roles a
  server has; the PowerShell shown before it runs.
- **Owners and teams, a tag catalog, rights**: owners and teams with members
  (acme's accounts, directory users and groups) and rights (view, request,
  manage, approve); tags with a colour; nothing typed as free text any more.
  Full administrators always see and do everything; certificate administrators
  and read-only accounts see everything unless that is switched off (then only
  their teams'). Expiry and failure mails also to the team's address.
- **A certificate's details edited without a new certificate** (owner, tags,
  note, renewal, reuse of the key, name, on/off); after changed names or key
  "renew now, or at the next renewal?".
- **The certificate portal**: acme's own accounts may sign in (with their
  second factor); administrators see every certificate, others what is theirs
  or their team's.
- **Certificates from acme**: the card as in ai, every change through the save
  bar.
- **Backups**: modules of your own (/etc/acme/plugins) in them; a cluster's
  backup put back says the exact steps to make it two again; a test proves a
  backup on a clean installation is the installation it came from.
- **Czech everywhere**: every message of the daemon shown in the pages.

## 1.0.9 - 2026-11-01

- **Columns of a list no longer jump** when it is drawn again - a switch in a
  row, the auto refresh, "2 min ago" become "3 min ago": the widths it had
  first are kept (as shares, so a window made wider or narrower still fits);
  a long word that does not fit is laid out once more before the page is
  painted. A layout set by hand (the columns editor) comes first.
- **Add and issue now** shows the job already issuing a new certificate (the
  look starts it as soon as it is saved) instead of "a job is working"; the
  popup closes whatever the issuing says. "Renew now" on a certificate being
  worked on shows that job too.
- HTTP-01 over SSH guide: a CNAME to the name that has the public address is
  suggested, or a redirect of /.well-known/acme-challenge/ from another web
  server; a name acme's own block adds by itself is not a thing to set up.

## 1.0.8 - 2026-11-01

- **acme-dns: Register an account** from the validation's form - one, or one a
  name into "Accounts by name" (an acme-dns account keeps two TXT values), with
  the CNAMEs to put into your DNS; nothing saved until Save.
- SSLmarket: the DCV records of an order that waited across the upgrade to
  1.0.5 are taken away too.
- Tests: the HA and database move suites run against real PostgreSQL and
  MariaDB again; the SSLmarket suite runs all its tests.

## 1.0.7 - 2026-11-01

- **The QR code of the second factor is right again.** 1.0.6 drew it wrong:
  a helper of acme push had the name of the QR code's own (the engine's parts
  share one namespace), so an authenticator app could not read a new QR code.
  Every name is defined once now, and the engine's lint and a test say so.
- A second `db_trouble` (the words for an unreachable PostgreSQL when joining
  a cluster) renamed `ha_db_trouble` - it had taken the place of the one that
  tells a database error.
- docs/acme-push-protocol.md: **additive only** - every existing way of
  managing certificates in an application stays as it is; acme push is off by
  default and only one more way in.

## 1.0.6 - 2026-11-01

- **acme push - certificates for our other applications** (otp, isemon,
  zigmon and acme itself): a target that pairs with the application once
  (a one-time code shown there, Settings → Certificates and TLS →
  "Certificates from acme"), then installs each certificate and its renewals
  with signed requests, the private key sealed to the application.
  **Discover** reads the application's certificate slots (each node, the VIP
  address, zigmon's front server and broker) and makes the certificates and
  deployments for those not covered. The receiving side is in the engine;
  docs/acme-push-protocol.md is the specification for the other projects.
- HTTP-01 over SSH **behind NAT**: the guide never suggests a private address
  (the public one, from a name it knows); "Public addresses (NAT, load
  balancer)"; port 80 checked with the name; a name nginx does not answer said
  as such; the name validated added to acme's own block.
- Settings → DNS: **Public is built in** - always there, changed, never deleted.

## 1.0.5 - 2026-11-01

- **HTTP-01 on web servers over SSH where nginx answers port 80 already**:
  "Prepare the hosts" puts one line, `include
  /etc/nginx/snippets/acme-challenge.conf;`, at the top of each port-80 server
  block - nothing else in them changes (a certbot redirect to HTTPS goes on as
  before). Every file is checked unchanged since it was read, copied to
  /var/backups/acme-nginx/, and put back when nginx -t fails. With names
  given and no block answering them, acme's own block listens for those
  names only (not the default server). "I put it in myself": "Download the
  nginx config" gives the file and the line, and Prepare only checks.
- "Set nginx up by itself" (before Test and every validation) and "Open port
  80 in their firewall" (firewalld, ufw); a port 80 closed by the firewall is
  said as such ("No route to host" while SSH works).
- The check before the CA is asked can be made **at other addresses** - a load
  balancer, the public IP, NAT; https:// too - with the certificate's name as
  Host and SNI; "Name for Test".
- **Try reaching it fills in the host keys** of the form (every form with an SSH
  key); a different key pinned already is shown with a warning and "Replace
  with the key seen", never replaced by itself. Kept by Save.
- **Webglobe**: DNS-01 validation (login + API key; only the record it made is
  taken away) and a target uploading your own certificate to a hosted domain.
- The nginx config for HTTP-01 printed by `acme --validation-action NAME
  nginx_files`.
- Settings → DNS: a function's set waits for Save on the bar (Put back undoes
  it); Test of a set opens over its form and gives the form back as it was.
- High security: a refused exception switch turns back instead of an error.

## 1.0.4 - 2026-11-01

- **Renewal by itself switched on and off** from the list of certificates and
  from a certificate - nothing is revoked, it stays valid and deployed.
- **Revoking**: a dual certificate's both keys (ECDSA and RSA) are revoked, the
  dialog says so; "Issue a new one at once" gives a new certificate with a new
  key in the same job, deployed where the revoked one was. A revoked one has
  "Issue a new one". The old "Switch renewal off" switch did nothing - gone.
- **dns-persist-01**: one TXT record at `_validation-persist.DOMAIN`, set once,
  for any certificate of the domain (subdomains and wildcards with
  `policy=wildcard`). acme writes the exact record for each ACME account,
  checks it, and uses it as soon as the CA offers it (Google Trust Services
  does; Let's Encrypt has announced it) - a fallback validation until then.
- **What fits together is checked before the CA is asked**: names, source,
  validation, key type and twin, in one place - the wizard greys out what does
  not fit and says why; a public CA refuses single labels, .local/.test and
  private addresses.
- **SAN editor**: typed SANs (DNS, IP, e-mail, URI), the CN apart with "CN is
  also a SAN", many pasted at once.
- **DigiCert, GeoTrust, Thawte, RapidSSL** products, with domain validation by
  TXT, CNAME, HTTP file or e-mail placed by the validation; SSLmarket uses the
  same.
- **Settings → DNS**: named sets of DNS servers (UDP, TCP, DNS over TLS) given
  to validation, public checks, APIs, targets, ACME and mail; the system's by
  default.
- **Own authorities edited** without removing them: settings, the name (the old
  /pki/ addresses still served), the certificate renewed with the same key, its
  history. A switched-off authority still publishes its CRL.
- Name constraints written as "permitted DNS:…" are read too.
- SSLmarket reworked after its API description, and SSLmarket ACME.
- The authorities' tree drawn with joined lines; "until" of a CRL translated.

## 1.0.3 - 2026-11-01

- **The pages after an upgrade are the new ones**: they said otp's version
  (1.0.209) for every acme release, so browsers kept core.js and admin.js from
  before - the default buttons without their star, errors of old scripts on
  new pages after F5. Every script and stylesheet is keyed by its own file now,
  and a release keeps the pages' version equal to acme's.
- acme's own DNS server answering on the VIP only: the validation's Test and
  its wait ask the VIP, not 127.0.0.1 where the server does not listen then.
- The SQLite file's setting is on The database pane, not under every pane; a
  test keeps every setting on a pane of its own.
- A button after words on the same line keeps its gap ("… is there" [every
  step]).

## 1.0.2 - 2026-11-01

- **Validation that tells you what to do, and tests itself.** For every name of
  a certificate acme says what has to be in place and where - the exact CNAME,
  NS or TXT record with Copy buttons, where an HTTP-01 name must point - and
  checks it live. "Dry run" puts a real test record or file in place, sees it
  from outside and takes it away, without asking the CA. Names are grouped by
  domain, with a validation suggested for each (a certificate may span many
  domains, each proved its own way). Before a first certificate - and after a
  failed validation - the CA is not asked while something is missing.
- **More sources**: EST, CMPv2, HashiCorp Vault PKI, EJBCA, step-ca, AWS Private
  CA, Google CAS, FreeIPA, GlobalSign Atlas, DigiCert CertCentral, SSLmarket.cz;
  Actalis, Certum, Sectigo and DigiCert (EAB) among the ACME CAs. A paid order
  is never placed without "Allow new orders (paid)".
- **More validations** (deSEC, WEDOS, Active24, Websupport, Subreg/Gransy,
  CZECHIA.COM and some 45 more DNS providers), HTTP-01 by FTP/FTPS/SFTP, S3,
  Azure Blob and WebDAV.
- **More targets**: AWS ACM, Azure Key Vault, Google Certificate Manager,
  Cloudflare, vCenter, ESXi, Redfish (iDRAC, iLO, XCC), Sophos, Kemp, Cisco
  ISE, HAProxy (runtime API), Traefik, Caddy, NGINX Unit, Zimbra, TrueNAS,
  Docker Swarm, strongSwan, FRITZ!Box, UniFi OS.
- **Dual certificates**: ECDSA and RSA under one certificate, renewed in one
  job (the second ACME order needs no second validation) and deployed together
  where the target serves both (nginx, Apache, HAProxy, Postfix, F5, acme's own
  pages...), the variant chosen for the others.
- **acme's DNS server**: answers on the VIP address, the nodes, or both (and
  from the address it was asked at); the firewall lets it in by itself when it
  is switched on.
- **CRLs on acme**: every authority of acme's own publishes its CRL and its
  certificate over HTTP at /pki/ on every node and the VIP, refreshed by
  itself; new authorities put those URLs in what they sign.
- **The SSH key card of isemon** wherever acme signs in over SSH: make a key
  here, use your own, download, forget, try reaching it, how to set it up.
- **The database move wizard**: target, connection, checks, what happens, the
  move live, done - SQLite, MariaDB and PostgreSQL in every direction; not on a
  node of a cluster.
- A default in every list (sources, validations, targets, authorities); the
  lists are current without reloading; names made safe everywhere (the
  defaults of 1.0.0/1.0.1 are renamed with every reference to them).
- The overview as in otp: the certificates' tiles first, then the server's,
  each opening what it counts.
- Fixed: backups checked "not good" after an upgrade from the pages and with
  keys of authorities (the backups themselves were whole); the configuration's
  export left the authorities' and certificates' keys out; the encrypted link
  between the databases could not be switched on (otp's version floor).

## 1.0.1 - 2026-11-01

- **High availability: joining does everything by itself, on both sides.**
  - The node a bundle is made for is let through the firewall of the first
    node at once (for a day, until it has joined; a firewall change on trial
    never takes it back), and the joining node opens its own firewall to the
    first one before it reaches the database or copies anything - acme's own
    chain (ACME-IN) and firewalld alike, each opening checked and said
    truthfully ("does NOT let ..." with the command, when it did not work).
  - The bundle made on the pages prepares PostgreSQL on the first node as
    `acme --ha-setup` does: it listens on the node's address, the joining
    node is in pg_hba.conf, PostgreSQL is restarted - each step shown.
  - A node's PostgreSQL lets in its own address too: the replicated join
    stopped half way on "no pg_hba.conf entry for host <own address>".
  - Every failure of a join is named with its fix: connection refused (not
    listening there), timed out / no route (a firewall), pg_hba, password,
    name. "Check from here" tries it before joining. A half-done join is said
    to be one, and running it again finishes it cleanly.
  - Shared mode writes `ha_mode` on both nodes (they ran as two single
    servers on one database).
  - `--ha-status` and the page saw the outgoing replication as missing while
    both directions ran (the slots were looked for under otp's names); the
    cluster counted as unhealthy for /healthz?check=all and the alerts.
  - The Make the bundle and Join a cluster popups redrawn: a drop zone and
    what the bundle holds, the passphrase checked as typed, live steps.
- **Secrets as otp shows them, everywhere**: a stored password is dots and
  its last two characters to a full administrator, dots only to everybody
  else, and only dots while it is typed - the certificate manager's sources,
  validations, targets and deployments included. The SSH keys of validations
  and the acme-dns accounts are sealed now; the configuration export carries
  module secrets only when it is locked with a password.
- **Czech everywhere**: every tab, settings pane, popup and module form of
  the certificate manager, the job steps and the errors.
- No browser dialogs: the contact e-mail of the ACME sources is asked in
  acme's own popup.
- As in otp: "The enrolment pages" keeps its name; the balancer's health
  check offers "+ DNS server listening" (`/healthz?check=dns`) where otp
  offered RADIUS; the certificate manager's retention is on The database.

## 1.0.0 - 2026-11-01

The first version of **acme**: certificates kept, renewed and put in place by
themselves.

acme is built on the engine of **otp 1.0.209** (the one-time password server):
its platform - settings, the database (SQLite, MariaDB, PostgreSQL), sealed
secrets, the two-node cluster with its VIP address, mail and SMS, backups, the
firewall, the network, time, upgrades, the API, the command line and the
console - taken over, renamed `otp` → `acme` everywhere, and the single
`otp.py` split into a package. RADIUS, the tokens and the enrolment of otp
are not part of acme.

- **The certificate manager** (`acmelib/certs`): certificates kept with every
  version they had, renewed before they run out (or when the CA says so, ARI),
  deployed to every place they are used, one node at a time in a cluster, every
  step of every job written down.
- **Issuers**: ACME (Let's Encrypt and any ACME CA), acme's own certificate
  authorities (root and intermediate, CRLs), self-signed, Microsoft AD CS,
  SCEP.
- **Challenges**: DNS-01 with acme's own DNS server (UDP and TCP 53), RFC 2136,
  and the APIs of Cloudflare, Route 53, Azure, Google Cloud, Hetzner, OVH,
  DigitalOcean, PowerDNS and others; HTTP-01 here (nginx → `acme.php` on
  port 80) or on another web server over SSH.
- **Targets**: Linux and Windows over SSH, F5, NetScaler, MikroTik, FortiGate,
  Palo Alto, pfSense, OPNsense, Proxmox, Synology, Kubernetes, Vault, a
  webhook, and more - and your own modules in `/etc/acme/plugins/`.
- **The layout**: `acme.py` (the launcher) and `acmelib/` (the engine in
  numbered parts, the certificate manager, the modules, colorama carried
  along).
- **Python 3.14 and PHP 8.3** from the start: install.sh installs or requires
  `python3.14` (AppStream on EL, the deadsnakes PPA on Ubuntu) and PHP-FPM
  8.3, and refuses an older Python unless `--python PATH` says otherwise.
- **The installed tree**: `/usr/local/lib/acme/versions/X.Y.Z-STAMP/`, compiled,
  with `current` switched to a new one in a single step on an upgrade and the
  one before kept as `previous` (`acme_upgrade.py --previous` puts it back).
- **Releases**: `tools/release.py` builds `release/acme-X.Y.Z.tar.gz` - the
  tree with a MANIFEST of SHA-256 sums signed with Ed25519 by acme's own release
  key (`deploy/release-keys/acme-release-1.pub`; otp's key is not trusted) -
  keeps the last ten, and writes `release/index.json` and `release/LATEST`,
  which the servers read for new versions (`upgrade_url`).
