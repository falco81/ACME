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
| `acme_cert_expiry_seconds{name}` | seconds until each certificate ends |
| `acme_cert_deploys_failed` | deployments whose last try failed |
| `acme_cert_jobs_failed_24h` | certificate jobs that failed in the last 24 hours |
| `acme_cert_leader{node}` | whether this node renews and deploys (1) or not (0) |
| `acme_ha_node_up{node}`, `acme_ha_heartbeat_age_seconds{node}` | the cluster |
| `acme_ha_replication_running{name}`, `acme_ha_replication_errors_total{name}`, `acme_ha_replication_behind_bytes{name}` | replication, as this node's PostgreSQL sees it |
| `acme_pages_certificate_expiry_timestamp_seconds{target,name}` | the pages' own certificates - each node's and the VIP address's |
| `acme_mail_queue{state}` | mail waiting or failed |
| `acme_isemon_sent_total{target}`, `acme_isemon_trouble{target}`, `acme_isemon_dropped_total` | isemon |
| `acme_siem_sent_total{target}`, `acme_siem_trouble{target}`, `acme_siem_dropped_total` | syslog / SIEM |
| `acme_alerts_open{level}`, `acme_alert{key,level}` | what the alerts see wrong now |
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
| `1.3.6.1.4.1.8072.9999.9999.7` | **ACME-MIB** (`deploy/ACME-MIB.txt`): the version, node, database engine, high security, in a cluster or not, uptime; the database (up, latency); the alerts (how many bad and warn, and a table of each); the pages' certificates (days left); the nodes of the cluster; and `acmeMetricTable` - every sample of `/metrics`, name, labels and value |

acme has no enterprise number of its own: its objects are under net-snmp's
`netSnmpPlaypen` (`.1.3.6.1.4.1.8072.9999.9999`), `.7`. Load `ACME-MIB.txt` into
the monitoring (it imports `NET-SNMP-MIB`, which net-snmp and Zabbix have) - or
use the numbers.

```
snmpwalk -v3 -l authPriv -u acmemon -a SHA-256 -A '...' -x AES -X '...' acme1 1.3.6.1.4.1.8072.9999.9999.7
snmpget  -v3 -l authPriv -u acmemon -a SHA-256 -A '...' -x AES -X '...' acme1 \
         1.3.6.1.4.1.8072.9999.9999.7.5.1.0 1.3.6.1.4.1.8072.9999.9999.7.3.1.0
```

Zabbix: an SNMP interface on each node, SNMPv3, security level authPriv, the
user, *SHA256* and *AES128* (or what was chosen) with the passphrases; items with
the OIDs above (`acmeAlertsBad.0` > 0, `acmeDbUp.0` = 0...).

### Traps

*Traps when something is wrong*: an SNMPv2-Trap, authPriv, from the node that
sends the alerts (the one with the VIP address, or the first alive) to every
receiver in *Where traps go* (`host` or `host:port`, 162 by default):

- `acmeAlertRaised` (`.7.0.1`) when something goes wrong - what the alerts see
  (*Alerts and reports*), after their delay - and again when a warning becomes
  bad;
- `acmeAlertCleared` (`.7.0.2`) when it is right again;
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

## The alerts of the database and of the VIP address (1.0.194)

*Settings → Alerts and reports* has a switch for each:

- **The database and its replication**: the replication stopped, or the database
  of a node in trouble (the daemon could not use it).
- **The VIP address (VRRP)**: the VIP address on no node, or on both (the nodes do
  not see each other over VRRP), a node whose keepalived gave it up (FAULT), or
  keepalived not running on a node.

Neither is mailed while the cluster is worked on - a node in maintenance, an
upgrade, the system's updates or a restart going on - nor for 10 minutes after
the last of them, while the replication catches up and the VIP address settles.
The same outside of them is mailed as any alert, after *Only once it has lasted*.
One already mailed is not said to be over because maintenance started: it is
kept as it was until it is looked at again.
