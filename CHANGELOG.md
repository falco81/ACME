# Changes in acme

Newest first. Each version's section is what the pages show before an
upgrade (and, going back, what is given up), so it says what changed for
the people who run acme - one `## X.Y.Z - date` heading per version.

## 1.0.74 - not released
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
