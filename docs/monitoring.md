# Monitoring: Prometheus (1.0.173)

*Settings → Monitoring*, for a full administrator. Off until switched on.

Each node answers `https://NODE/metrics` in Prometheus' text format, for itself -
ask every node by its own address (the VIP address is one node at a time).

| Setting | |
|---|---|
| `metrics` | on/off |
| `metrics_token` | what Prometheus sends as `Authorization: Bearer ...` - *Make a token…* makes one and shows it once; kept sealed |
| `metrics_from` | the addresses or networks Prometheus asks from (`10.0.5.0/24, 2001:db8::/64`); empty: anywhere that reaches the pages, with the token |

nginx sends `/metrics` to `metrics.php`, which hands the token to the daemon; the
daemon checks it (and where the request comes from) before it says anything. A
wrong or missing token is a 401, a network not let in a 403, metrics switched off
a 404. An upgrade puts the `location = /metrics` into an nginx file of an older
version by itself.

## prometheus.yml

```yaml
scrape_configs:
  - job_name: acme
    scheme: https
    metrics_path: /metrics
    bearer_token_file: /etc/prometheus/acme.token      # the token, 0600, Prometheus' own
    tls_config:
      ca_file: /etc/prometheus/acme-ca.pem              # the CA of the nodes' certificates, if not a public one
    static_configs:
      - targets: ['10.0.5.11:443', '10.0.5.12:443']
```

The page shows this with the nodes' addresses filled in, and *What this node answers
now*.

## What it says

| Metric | |
|---|---|
| `acme_info{version,node,site,engine}` | 1 |
| `acme_start_time_seconds` | when the daemon started |
| `acme_database_up`, `acme_database_seconds` | the database answers, and how long `SELECT 1` took |
| `acme_directories` | how many directories |
| `acme_events_last_day{level}` | events of the last 24 hours (the database's - both nodes) |
| `acme_certs{state}` | the certificates acme keeps, by state |
| `acme_cert_state{name,state}` | each certificate's state (1) |
| `acme_cert_not_after_timestamp_seconds{name,cn,issuer}` | when each certificate ends (unix time) |
| `acme_cert_expiry_seconds{name}` | seconds until each certificate ends |
| `acme_cert_expiring` | certificates that end within `certs_notify_days` |
| `acme_cert_renewals_total{result}`, `acme_cert_deployments_total{result}` | renewals (first issues too) and deployment jobs that went well / failed, of the jobs kept (`certs_keep_jobs_days`) - gauges: old jobs pruned make them go down |
| `acme_cert_jobs_24h{kind,result}`, `acme_cert_jobs_failed_24h` | certificate jobs of the last 24 hours |
| `acme_cert_deploys{state}`, `acme_cert_deploys_failed` | deployments by state; those whose last try failed |
| `acme_cert_last_job_timestamp_seconds{kind,result}` | when the last job of each kind ended |
| `acme_cert_last_scan_timestamp_seconds{node}` | when the leader last looked for what is due |
| `acme_cert_leader{node}`, `acme_cert_leader_info{node}` | whether this node renews and deploys (1) or not (0); the node that does |
| `acme_dns_up`, `acme_dns_queries_total{proto}`, `acme_dns_answers_total{rcode}`, `acme_dns_records` | acme's own DNS server on this node (when it is on) |
| `acme_ha_node_up{node}`, `acme_ha_heartbeat_age_seconds{node}` | the cluster |
| `acme_ha_replication_running{name}`, `acme_ha_replication_errors_total{name}`, `acme_ha_replication_behind_bytes{name}` | replication, as this node's PostgreSQL sees it |
| `acme_pages_certificate_expiry_timestamp_seconds{target,name}` | the pages' own certificates - each node's and the VIP address's |
| `acme_mail_queue{state}` | mail waiting or failed |
| `acme_isemon_sent_total{target}`, `acme_isemon_trouble{target}`, `acme_isemon_dropped_total` | isemon |
| `acme_siem_sent_total{target}`, `acme_siem_trouble{target}`, `acme_siem_dropped_total` | syslog / SIEM |
| `acme_alerts_open{level}`, `acme_alert{key,level}` | what the alerts see wrong now |
| `acme_cert_alt_not_after_timestamp_seconds{name}` | when the twin of each dual certificate ends (1.0.78) |
| `acme_cert_deploy_state{cert,target,state,enabled}`, `acme_cert_deploy_last_ok_timestamp_seconds{cert,target}` | each deployment: its state (1), when it last went through (1.0.78) |
| `acme_cert_test_state{cert,test,kind,state,enabled}`, `acme_cert_test_last_timestamp_seconds{cert,test}`, `acme_cert_tests_failing` | each test of a certificate: how it went last (`none`: not run yet), when it ran; how many fail (1.0.78) |
| `acme_module_failing{family,name,kind,enabled}` | each source, validation, target and test: 1 when its last use failed (1.0.78) |
| `acme_ca_not_after_timestamp_seconds{name}`, `acme_ca_crl_next_timestamp_seconds{name}` | acme's own authorities: when each ends, when its CRL is due again (1.0.78) |
| `acme_cert_jobs_running` | certificate jobs queued or running (1.0.78) |
| `acme_disk_used_ratio{path}`, `acme_backup_last_timestamp_seconds`, `acme_clock_skew_seconds{of}`, `acme_clock_reference_offset_seconds{ref}` | this node: how full its disks are, its newest backup, its clock (1.0.78) |
| `acme_high_security` | high security on |
| `acme_scrape_seconds` | how long the answer took |

## Alerts, for example

```yaml
groups:
  - name: acme
    rules:
      - alert: AcmeDown
        expr: up{job="acme"} == 0 or acme_database_up == 0
        for: 2m
      - alert: AcmeReplication
        expr: acme_ha_replication_running == 0 or acme_ha_replication_behind_bytes > 100e6
        for: 5m
      - alert: AcmeCertificate
        expr: acme_cert_expiry_seconds < 14 * 86400
      - alert: AcmeDeploy
        expr: acme_cert_deploys_failed > 0
        for: 30m
      - alert: AcmeAlerts
        expr: acme_alerts_open{level="bad"} > 0
        for: 10m
```

## SNMPv3 (1.0.182)

Each node answers SNMPv3 itself: an agent of the acme daemon, in a thread of its
own - no snmpd, nothing in the renewals' way. *Settings → Monitoring → SNMPv3*.

- **authPriv only.** One user (securityName), the same on every node, with a
  passphrase for authentication and one for encryption (12 characters at least,
  kept sealed like every secret of acme). noAuthNoPriv and authNoPriv are not
  answered. Authentication HMAC-SHA-256 (default), -SHA-512 or -SHA-1 (RFC 3414,
  RFC 7860); encryption AES-128 (default) or AES-256 (RFC 3826; AES-256 with the
  key extended as net-snmp and Zabbix do it - their `AES256`, not Cisco's
  `AES256C`).
- **Each node an engine of its own** - its engine ID made once and kept in
  `/var/lib/acme/snmp-engine`, the engine boots counted in `snmp-boots`. The page
  shows each node's engine ID (click to copy) - a trap receiver needs it.
- **Port 161/udp** on every address of the node (or one, *Listen on*, set for each
  node). Binding 161 needs `CAP_NET_BIND_SERVICE`: `acme.service` has it from
  1.0.182 (`install.sh --upgrade` puts the unit in); nothing else is given to the
  daemon. Where the system's snmpd has 161 already, give acme another port.
- **Only from**: the networks the monitoring asks from; the firewall lets in these
  only (or everybody when none is set) - by itself while SNMPv3 is on, where acme
  looks after the firewall (*Settings → Firewall and access*), and the rule goes
  when it is switched off. Anything else is not answered at all.
- *Settings → Firewall and access* shows it among what acme lets in by itself
  (*SNMPv3*: the port, from where) while it is on.
- Read only: GET, GETNEXT and GETBULK. A SET is refused (notWritable).
- *Ask it* on each node's card: the node asks its own agent on 127.0.0.1 as a
  manager would - discovery, then a GET authPriv.

### What it answers

| OID | |
|---|---|
| `1.3.6.1.2.1.1` | the system group: sysDescr (acme, the version, the node), sysObjectID, sysUpTime, sysContact, sysName, sysLocation |
| `1.3.6.1.6.3.10.2.1` | the engine: its ID, boots, time |
| `1.3.6.1.6.3.15.1.1` | usmStats: unknown users, wrong digests, not in the time window... |
| `1.3.6.1.4.1.8072.9999.9999.7` | **ACME-MIB** (`deploy/ACME-MIB.txt`): the version, node, database engine, high security, in a cluster or not, uptime; the database (up, latency); the alerts (how many bad and warn, and a table of each); the pages' certificates (days left); the certificates the manager keeps (`acmeManagedCertTable`: index = the certificate's id, name, CN, notAfter, daysLeft, state, issuer, state as a number, renewed by itself, deployments failed; its key, the twin's key, notAfter and days left of a dual one, tests failing; and `acmeManagedCounts`: total, ok, failed, expired, expiring, deployments failed, this node leads, jobs failed in 24 h, DNS queries, waiting, tests, tests failing, jobs running, modules failing, authorities ending within 90 days, deployments); since 1.0.78 also **`acmeDeployTable`** (`.6.4`: each deployment - certificate, target, state, in use, version deployed, last OK, last try, failures, last error), **`acmeTestTable`** (`.6.5`: each test of a certificate - its kind, state, in use, after which deployments, last run, last pass, failures, what it said), **`acmeModuleTable`** (`.6.6`: each source, validation, target and test - in use, last OK, last error; index = family × 1000000 + id) and **`acmeCaTable`** (`.6.7`: each authority of acme's own - subject, notAfter, days left, in use, signs here, CRL due); the nodes of the cluster; and `acmeMetricTable` - every sample of `/metrics`, name, labels and value |
| `.7.1`, `.7.3` (1.0.108) | more of acme: the newest version offered and whether it is newer (`acmeUpdateAvailable`), when the daemon started, in maintenance, whether this node sends the alerts, when the upgrades were looked for; the database's size (`acmeDbSize`, bytes), its guard on and the rows it refused in the last hour, what the database said when the daemon lost it |
| `.7.5` (1.0.108) | `acmeAlertsWorst` (ok, info, warn, bad as a number) and three new columns of `acmeAlertTable`: the level as a number, the node, the part of Settings |
| `.7.6` (1.0.108) | of each certificate kept also its owner, source, last renewal, last try, failures in a row, last error, next try, version, serial, deployments, tests, valid from, number of names and the state with the names of the states (`acmeManagedCertTable` .16-.29); the counts of the last 24 hours (jobs done, renewals done and failed, deployments done and failed), the last look for what is due, revoked, waiting for an approval (`acmeManagedCounts` .17-.24); each deployment's and test's state as a number (`acmeDeployStateNum`, `acmeTestStateNum`), a module failing (`acmeModuleFailing`), an authority only known here and the hours until its CRL is due; **`acmeDnsServer`** (`.6.8`: on, answers, records, answers, refused, failed, rate limited) |
| `.7.7` (1.0.108) | each node's version, maintenance, VIP address held, keepalived's role, this node, started, address (`acmeNodeTable` .5-.11); the cluster: its mode, the VIP address, how many hold it and who, the replication (not replicated, healthy, broken, lost), how far behind, its errors, the split (inactive, together, apart) and what this node does then, the node that renews, nodes up and known |
| `.7.10` (1.0.108) | **`acmeSystem`** - this node's machine: `acmeDiskTable` (each file system acme lives on: size, used, free, % used, % inodes), cores, CPU busy %, the load averages (× 100), memory total and used, swap used, bytes read and written by the disks and through the network cards (Counter64), when it started, the clock's skew and offset (ms) and whether it is in sync, SELinux's mode and denials, acme's firewall on, the updates of the system waiting (all, security), a restart needed, when they were looked for, sshd as acme set it, the sealing key missing, a name clash, this agent's requests, answers and traps, things to do by hand |
| `.7.11` (1.0.108) | **`acmeBackup`**: the newest backup kept on the node and its age, how many, every night or not; the backups sent away (on, last, last good, result, error) and `acmeRemoteBackupTable` (each place: result, sent, last good, error); the last try of putting one back |
| `.7.12` (1.0.108) | **`acmeSignIn`**: accounts (local), sign-ins open, addresses and names locked out, wrong sign-ins counted; Windows (Kerberos): usable, keytab written here, its keys, its error; a certificate: usable, its port open, the authorities, its error, and `acmeCrlTable` (each CRL kept: kept, fetched, next update, hours left, error) |
| `.7.13` (1.0.108) | **`acmeServices`**: `acmeShipTable` (each place the logs go - isemon, syslog: lines sent, in trouble and why), isemon and syslog on, lines dropped; mails waiting, failed and sent; directories and those not answering; SMS failed in a row |

Every state is a number with a textual convention of the MIB (`AcmeTruth`, `AcmeCertState`,
`AcmeDeployStatus`, `AcmeTestResult`, `AcmeSeverity`, `AcmeResult`, `AcmeReplication`,
`AcmeSplit`, `AcmeVrrpRole`, `AcmeSelinux`, `AcmeTimeSync`); the module has conformance groups
(`acmeConformance`, `.7.20`) and passes `smilint -l 6` but for the indexes, which are readable on
purpose (a walk says each row's id). Nothing of before moved: 1.0.108 only adds. Prometheus has
the same facts (`acme_load`, `acme_memory_bytes`, `acme_os_updates`, `acme_os_reboot_needed`,
`acme_update_available`, `acme_accounts`, `acme_sessions`, `acme_signin_locked`,
`acme_backups_kept`, `acme_rbackup_last_result`, `acme_backup_verify_result`,
`acme_vip_holders`, `acme_split_apart`, `acme_selinux_mode`, `acme_firewall_on`,
`acme_directories_down`, `acme_certlogin_crl_next_timestamp_seconds`...) - read once for both.

acme has no enterprise number of its own: its objects are under net-snmp's
`netSnmpPlaypen` (`.1.3.6.1.4.1.8072.9999.9999`), `.7`. Load `ACME-MIB.txt` into
the monitoring (it imports `NET-SNMP-MIB`, which net-snmp and Zabbix have) - or
use the numbers.

```
snmpwalk -v3 -l authPriv -u acmemon -a SHA-256 -A '...' -x AES -X '...' acme1 1.3.6.1.4.1.8072.9999.9999.7
snmpget  -v3 -l authPriv -u acmemon -a SHA-256 -A '...' -x AES -X '...' acme1 \
         1.3.6.1.4.1.8072.9999.9999.7.5.1.0 1.3.6.1.4.1.8072.9999.9999.7.3.1.0
```

The MIB is on the page too: *Settings → Monitoring → SNMPv3 → ACME-MIB* (or
`acme --snmp-mib --out ACME-MIB.txt`). For Zabbix there is a whole template - below.

### Traps

*Traps when something is wrong*: an SNMPv2-Trap, authPriv, from the node that
sends the alerts (the one with the VIP address, or the first alive) to every
receiver in *Where traps go* (`host` or `host:port`, 162 by default):

- `acmeAlertRaised` (`.7.0.1`) when something goes wrong - what the alerts see
  (*Alerts and reports*), after their delay - and again when a warning becomes
  bad;
- `acmeAlertCleared` (`.7.0.2`) when it is right again;
- a **test that fails** (what a server serves is not the certificate, or it
  cannot be reached) is among what the alerts see since 1.0.78 - a trap, the
  overview, `acme_alert` - but not mailed by the alerts: the test's own notice
  (*Renewal and notices*) says it, once;
- `acmeTestTrap` (`.7.0.3`) from *Send a test trap*.

Each carries `acmeTrapKey`, `acmeTrapLevel`, `acmeTrapTitle`, `acmeTrapSaid` and
`acmeTrapNode`. Their own record of what was said, apart from the mails: traps go
whether the alerts' mails are on or not.

The receiver knows the user with **each node's engine ID** (a trap is sent by the
node's own engine), in `snmptrapd.conf`:

```
createUser -e 0x80001f8805... acmemon SHA-256 '...' AES '...'
createUser -e 0x80001f8805... acmemon SHA-256 '...' AES '...'
authUser log,execute acmemon priv
```

The page writes those lines with the engine IDs filled in.

## Zabbix 7.0 (1.0.108)

*Settings → Monitoring → SNMPv3 → Zabbix 7 template* downloads **"acme by SNMP"**
(`acme_zabbix7_template.yaml`, Zabbix 7.0's YAML export) - or `acme --snmp-zabbix-template
--out acme_zabbix7_template.yaml` on any node (it asks nothing of the daemon). It is made from
`ACME-MIB.txt` each time: every OID, unit, value map and description is the MIB's, so the two
always agree. Any role may download it - nothing secret is in it.

What it holds:

- **SNMP walks, everything else dependent on them** (Zabbix 7.0's `walk[...]` items, *SNMP walk
  value*, *SNMP walk to JSON*): one bulk walk of the node every `{$ACME.INTERVAL}` (1m), one of
  each table every `{$ACME.INTERVAL.TABLES}` (5m) - not a GET for each value. A table is
  walked by its columns, or whole (the certificates: their columns do not fit in Zabbix's
  `snmp_oid` of 512 characters).
- **Items of the node** (about 150): version and a newer one, uptime, maintenance; the database
  (up, latency, size, guard); the alerts (bad, warnings, the worst, and *Alerts now* - the list,
  one a line); the certificates counted; acme's DNS server; the cluster (mode, VIP address and
  who holds it, replication, split, the node that renews); CPU, load, memory, disks, network,
  clock, SELinux, firewall, the updates of the system; the backups; the sign-ins (accounts,
  sessions, lockouts, Kerberos keytab, certificate sign-in); logs, mails, directories, SMS;
  calculated: memory %, load per core, certificates valid %; *SNMP agent availability*.
- **Discoveries** (11), each with item, trigger and graph prototypes: *Certificates*
  (`{#CERT.NAME}`, `{#CERT.CN}`, `{#CERT.ISSUER}`, `{#CERT.OWNER}`...: days left, expires,
  state, renewed by itself, deployments and tests failing, failures in a row, last error, last
  renewal, serial, how it came, the twin of a dual one - only discovered for a dual
  certificate),
  *Deployments*, *Tests*, *Sources, validations, targets and tests* (the modules),
  *Authorities*, *Certificates of the pages*, *Cluster nodes*, *File systems*, *Backup places*,
  *CRLs* of the sign-in with a certificate, *Log destinations*. Filters by macros
  (`{$ACME.CERT.NAME.MATCHES}`, `{$ACME.CERT.NAME.NOT_MATCHES}`, `{$ACME.CERT.OWNER.MATCHES}`,
  `{$ACME.TARGET.MATCHES}`..., those switched off left out unless `{$ACME.*.ENABLED.MATCHES}`
  is `.*`).
- **Triggers** (about 75), the certificates' clearest and worst: *Certificate web has expired*
  (disaster), *...expires in less than 7 days* (high, `{$ACME.CERT.CRIT}`) or *...in less than 30
  days* (warning, `{$ACME.CERT.WARN}`) - three ranges, one problem for a certificate at a time;
  per certificate with a context, `{$ACME.CERT.WARN:"web"}` = 60; *Certificate api: renewal
  failed* (high, the error as its operational data - whether it renews by itself or not);
  *Deployment of www to old-appliance failed* (high, the target's words); *Test SMTP relay of
  mail fails* (average; unreachable, another certificate...), *...warns* (information), not
  run lately; a deployment waiting a day; a module whose last use failed (information - its
  deployment, test or renewal is the problem); an authority ending (`{$ACME.CA.WARN}`, `{$ACME.CA.CRIT}`)
  or its CRL late; the certificate of the pages ending; a node not heard from, on another
  version, keepalived in fault; the VIP address held by no node or both; replication broken,
  lost or behind (`{$ACME.REPL.BEHIND.MAX}`); the nodes apart; the database down, slow, lost
  lately, rows refused by its guard; the alerts of acme (bad: high, a warning: warning);
  a newer acme; CPU, memory, load; a file system full (`{$ACME.DISK.PUSED.WARN}` 85,
  `{$ACME.DISK.PUSED.CRIT}` 95, per path), inodes; the clock not in sync or off
  (`{$ACME.CLOCK.OFFSET.MAX}`); security updates waiting, a restart needed; the sealing key
  missing; a name clash; things to do by hand; SELinux not enforcing; no recent backup
  (`{$ACME.BACKUP.AGE.MAX}`), a backup sent away failed or none lately
  (`{$ACME.RBACKUP.AGE.MAX}`), a backup that cannot be put back, a place that failed; the
  keytab not written; the certificate sign-in's port closed; a CRL out of date or not fetched;
  a directory not answering; mails not going; the SMS gateway; logs not reaching isemon or
  syslog, lines dropped; the daemon restarted; no SNMP data collection; and the traps.
- **Value maps** for every state (the MIB's textual conventions), **graphs** (CPU, load,
  memory, disk I/O, network, certificates by state, the jobs of 24 hours, deployments and tests,
  alerts, database latency and size, replication, the agent's requests, the DNS server,
  sign-ins, the mail queue) and graph prototypes (a certificate's days left and failures, a
  file system's space as a pie, an authority's days left...).
- **Tags** on everything: `component` (certificate, deployment, test, module, authority, web,
  cluster, storage, backup, signin, logs, cpu, memory...), and `cert`, `owner`, `issuer`,
  `deploy` (the target of a deployment), `test`, `authority`, `crl`, `place`, `node`,
  `filesystem` on what was discovered (problems carry them: the certificate, its owner and
  source in *Problems*); `scope` on the triggers.
- **A dashboard** (*acme*, on each host linked: *Monitoring → Hosts → Dashboards*), the
  certificates first, six pages:
  1. *Certificates* - tiles of the certificates kept, valid, expiring soon, expired, whose
     renewal failed, renewals failed in 24 h (plain, orange or red only when there is
     something); a honeycomb of every certificate's days left (red within 7 days or expired,
     orange within 30) and one of their states; *Certificate problems* - expired, expiring,
     renewal failed, worst first, with the certificate, its owner and source; a pie and a graph
     of the states.
  2. *Deployments and tests* - tiles of the deployments, failed, done and failed in 24 h, the
     tests and those failing; a honeycomb of every deployment (certificate > target) and every
     test (certificate: test) coloured by its result; their problems with the target's or the
     test's words; the jobs of 24 hours; the modules (red: their last use failed).
  3. *Authorities and CRLs* - acme's authorities (days left, hours to the next CRL), the CRLs
     of the sign-in with a certificate, the certificate of the pages; their problems.
  4. *System*, 5. *Cluster and backups* (with the places backups go), 6. *Sign-in and
     services*.
  A honeycomb of states shows the name alone, its colour the state (the colours in its title):
  Zabbix 7.0's honeycomb shows a number, not the words of a value map.

### Importing it

1. Zabbix 7.0: *Data collection → Templates → Import*, choose the file, *Import*. (Imported
   again after an upgrade of acme, it updates itself - the same UUIDs; tick *Delete missing* to
   drop what a newer template no longer has.)
2. *Data collection → Hosts → Create host* for **each node** (by its own address, not the VIP
   address - each node answers for itself): *Templates*: `acme by SNMP`; *Interfaces → Add →
   SNMP*: the node's address, port 161 (or the one set), *SNMP version* SNMPv3, *Security name*
   the user of *Settings → Monitoring*, *Security level* authPriv, *Authentication protocol*
   SHA256 (SHA1, SHA512 - as set), *Privacy protocol* AES128 (or AES256 - net-snmp's AES256,
   which acme speaks; not AES256C), the two passphrases, *Use combined requests* on. The fields
   can hold the template's macros: `{$ACME.SNMP.USER}`, `{$ACME.SNMP.AUTHPASS}` and
   `{$ACME.SNMP.PRIVPASS}` (secret text), set on the host. acme answers no SNMPv1 or v2c.
3. *Only from* (*Settings → Monitoring*) must take the Zabbix server's (or proxy's) address.
4. *Macros*: the thresholds above, per host or per context.

An importable host, for the API or a second import (*Data collection → Hosts → Import*):

```yaml
zabbix_export:
  version: '7.0'
  host_groups:
    - uuid: 6f6799aa69e844b4b3918f779f2abf08
      name: acme
  hosts:
    - host: acme1
      name: 'acme1 (node 1)'
      templates:
        - name: 'acme by SNMP'
      groups:
        - name: acme
      interfaces:
        - type: SNMP
          ip: 192.0.2.11
          port: '161'
          details:
            version: SNMPV3
            securityname: '{$ACME.SNMP.USER}'
            securitylevel: AUTHPRIV
            authprotocol: SHA256
            authpassphrase: '{$ACME.SNMP.AUTHPASS}'
            privprotocol: AES128
            privpassphrase: '{$ACME.SNMP.PRIVPASS}'
          interface_ref: if1
      macros:
        - macro: '{$ACME.SNMP.USER}'
          value: acmemon
        - macro: '{$ACME.SNMP.AUTHPASS}'
          type: SECRET_TEXT
          value: '...'
        - macro: '{$ACME.SNMP.PRIVPASS}'
          type: SECRET_TEXT
          value: '...'
```

### The traps in Zabbix

The template's *SNMP traps of acme* (`snmptrap["acmeAlertRaised|..."]`, a log) takes
`acmeAlertRaised`, `acmeAlertCleared` and `acmeTestTrap`; *Trap: something went wrong* (high) and
*Trap: a warning* raise a problem for each trap (closed by hand), *Trap: the test trap came*
says the receiver works. *SNMP traps (fallback)* keeps the rest. On the Zabbix server (or
proxy):

1. snmptrapd with the users of each node's engine (the page writes the lines, above) and
   Zabbix's receiver: `perl do "/usr/share/zabbix/zabbix_trap_receiver.pl";` (or
   `traphandle default /usr/sbin/zabbix_trap_handler.sh`) in `snmptrapd.conf`; load
   `ACME-MIB.txt` (`mibs +ACME-MIB`, the file in `/usr/share/snmp/mibs`) to see names, not
   numbers - the template takes both.
2. `zabbix_server.conf`: `StartSNMPTrapper=1`, `SNMPTrapperFile=` the receiver's file
   (`/var/log/snmptrap/snmptrap.log`).
3. *Settings → Monitoring → SNMPv3*: *Traps when something is wrong* on, *Where traps go* the
   Zabbix server, then *Send a test trap* - *Trap: the test trap came* opens for
   `{$ACME.TRAP.TEST.WINDOW}` (10m).

The trap is matched to the host by its source address: the node's own.

### What was checked

The template is made the same way each time and checked by `test/test_snmp.py`: YAML that
parses, every UUID a UUIDv4 of its own, every key once, every OID it walks or reads an object of
ACME-MIB and answered by a running agent, every value map, item, graph and macro it names
there, every table of the MIB discovered, the walks within Zabbix's 512 characters, the widgets'
fields within 255.

**On a real Zabbix 7.0.32 (1.0.109)** - the official server, web and PostgreSQL 16 images - polling
a running acme over SNMPv3 (authPriv, SHA-256/AES-128, the user and passphrases as the host's
macros) with certificates valid, expiring in 11 and 2 days, expired, a renewal failed, an own
authority with its CRL, deployments to targets that work and one that fails, tests that pass,
warn, are unreachable or find another certificate, backups sent to two places (one failing) and
two CRLs of the sign-in (one out of date): `configuration.import` with every rule (create,
update, delete missing - dashboards, value maps, discoveries, graphs, triggers) takes it; every
item and item prototype gets values, none *not supported*; the discoveries find their rows (7
certificates, 6 deployments, 7 tests, 15 modules, the authority, 2 backup places, 2 CRLs, the
file system; no nodes, log destinations or pages' certificate on a single node without them);
the triggers fire as they should (the expired certificate, the two expiring, the failed
renewal, the failed deployment, the failing and warning tests, the failed backup place, the
out-of-date CRL, a full disk) and none stays *unknown*; value maps, units and the dashboards
were looked at in the frontend. Not tried there: the traps (no snmptrapd), a cluster.

## The alerts of the database and of the VIP address (1.0.194)

*Settings → Alerts and reports* has a switch for each:

- **The database and its replication**: the replication stopped, or the database
  of a node in trouble (the daemon could not use it).
- **The VIP address (VRRP)**: the VIP address on no node, or on both (the nodes do
  not see each other over VRRP), a node whose keepalived gave it up (FAULT), or
  keepalived not running on a node - stopped (its last word STOP), or killed (no
  `keepalived` process alive, looked at by the node itself once a minute; see
  [tls-and-vip.md](tls-and-vip.md)).

Neither is mailed while the cluster is worked on - a node in maintenance, an
upgrade, the system's updates or a restart going on - nor for 10 minutes after
the last of them, while the replication catches up and the VIP address settles.
The same outside of them is mailed as any alert, after *Only once it has lasted*.
One already mailed is not said to be over because maintenance started: it is
kept as it was until it is looked at again.

## Alerts for what the nodes already see (as otp 1.0.242)

*Settings → Alerts and reports* mails, besides the nodes, the database, the VIP
address, the backups, the certificates of the nodes, the disks, the clock, the
updates, the directories and the SMS gateway, what each node sees and writes in
its health row every minute - each with a switch of its own, **on by default**
(they are failures):

| Switch | Mailed when |
|--------|-------------|
| `alerts_nodes` (as before) | also: the key that opens the sealed secrets (secrets.key - the private keys, the passwords kept) missing on a node; two nodes under one name |
| `alerts_shipping` | the logs of a node not reaching isemon or the syslog servers (SIEM) - not reached, refused, or lines dropped |
| `alerts_snmp` | SNMPv3 switched on and its agent on a node not listening, or its traps not going out |
| `alerts_acme` | ACME ordered the certificate of a node or of the VIP address (*Automatic certificates*) and none came - at once, not only once it is about to run out. The certificates the certificate manager keeps are said by it, as before (a renewal or a deployment that failed) |
| `alerts_cert_days` (as before) | also: the certificates of PostgreSQL's TLS and of the link between the nodes running out |
| `alerts_updates` (as before) | also: the update of the system that failed, a node that cannot look for updates |
| `alerts_upgrade` | an upgrade of acme that failed on a node, or one left stuck |
| `alerts_trial` | a change of the network, the firewall or the SSH server on trial that was not kept and went back by itself - whoever made it may have lost the way in (said as it happens, from Events) |
| `alerts_dbguard` | with the guard against writes to the database on: rows that reach root not as acme wrote them, refused |
| `alerts_mailq` | codes and notices of certificates by mail that failed or ran out in the outgoing queue |
| `alerts_split` | the nodes apart (with *What the nodes do when they lose each other* set to report it) |
| `alerts_clock` | what the clock guard sees (with the clocks of the nodes watched) |
| `alerts_time` (as before) | also on a node without chrony: what timedatectl says |

**Off by default**, for who wants them:

| Switch | Mailed when |
|--------|-------------|
| `alerts_repl_behind_mb` | the replication running, but the other node more than this many MB behind (0: never) |
| `alerts_selinux` | the SELinux card of a node finds something not as acme needs it |
| `alerts_hisec` | Settings → High security finds something less safe than it could be |
| `alerts_sso` | each sign-in by the load balancer or WAF the enrolment pages refuse, as it is refused |

What is said as it happens (a change on trial gone back, a refused sign-in by
the balancer) is read from the events since the last look. With no event at all
at the very first look, nothing that happened later was ever mailed - it is now.

**The quiet while a node is worked on** is each node's own row
(`alerts:quiet:NODE`): both wrote one row - the metrics, SNMP and the pages ask it
on every node - and two first rows at once stopped the replication. A test alert
or *Forget* on the node that does not send no longer writes back an older copy of
what was sent.
