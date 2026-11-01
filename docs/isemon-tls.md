# isemon over TLS (1.0.172)

acme sends isemon its `acme-certs` lines (and, with `isemon_events`, its other
events) over syslog. Plain UDP/TCP goes over the network readable by anyone on
the way: which certificates, for which names, on which targets, what failed. Over TLS (RFC 5425, port 6514/tcp) it is
encrypted, and acme checks that it is isemon that answers; with **mutual TLS**
isemon checks too that it is one of acme's nodes that sends.

Everything on the acme side is done in **Settings → isemon → Encrypted sending
(TLS)**. On the isemon machine it is a few files and one rsyslog configuration -
acme makes them for you.

## 1. On acme: the wizard

*Settings → isemon → Encrypted sending → Encrypt…*

| Field | |
|---|---|
| isemon's address | as the nodes reach it - the name (or address) its certificate is for |
| Port | 6514 (syslog over TLS) |
| isemon's certificate | **acme makes isemon a certificate** (from acme's own authority - the one of the link between the databases), **isemon has one from its own CA** (paste that CA's certificate, PEM), or **a public CA** (the system's authorities) |
| isemon takes acme's nodes only (mutual TLS) | each node shows isemon a certificate of its own from acme's authority, made and renewed by the node itself (825 days, renewed 60 days before the end) |
| Check isemon's certificate | on; off only to try it (high security does not allow it off) |

With **acme makes isemon a certificate**: *Make the file for isemon…* asks for a
passphrase (12 characters at least) and saves `isemon-tls.zip`, every entry
locked with AES-256:

```
ca.pem           acme's own authority - it signed isemon.crt and (mutual TLS) the nodes' certificates
isemon.crt       isemon's certificate, for the names given, good for five years
isemon.key       its key - for rsyslog alone
10-acme-tls.conf  the rsyslog configuration
README.txt       these steps
```

acme does not keep isemon's key: a lost file is made again (*Make the file for
isemon…*), and the new one goes in the same way. acme says in the events 60 days
before isemon's certificate ends.

## 2. On the isemon machine

As root (AlmaLinux / RHEL 9, rsyslog 8.2106 or later):

```bash
dnf install -y rsyslog-gnutls p7zip        # p7zip from EPEL: unzip cannot open AES
7z x isemon-tls.zip                         # asks for the passphrase
install -d -m 0750 /etc/pki/rsyslog/acme
install -m 0644 ca.pem isemon.crt /etc/pki/rsyslog/acme/
install -m 0600 isemon.key /etc/pki/rsyslog/acme/
restorecon -R /etc/pki/rsyslog
install -m 0644 10-acme-tls.conf /etc/rsyslog.d/
rsyslogd -N1 && systemctl restart rsyslog
firewall-cmd --permanent --add-port=6514/tcp && firewall-cmd --reload
shred -u isemon.key isemon-tls.zip          # the copies left in the folder
```

`10-acme-tls.conf`, as acme writes it (here with mutual TLS, nodes `acme1`, `acme2`):

```
global(
  DefaultNetstreamDriverCAFile="/etc/pki/rsyslog/acme/ca.pem"
  DefaultNetstreamDriverCertFile="/etc/pki/rsyslog/acme/isemon.crt"
  DefaultNetstreamDriverKeyFile="/etc/pki/rsyslog/acme/isemon.key"
)
module(load="imtcp")
input(type="imtcp" port="6514" name="acme-tls"
      StreamDriver.Name="gtls"
      StreamDriver.Mode="1"
      StreamDriver.AuthMode="x509/name"
      PermittedPeer=["acme1", "acme2"])
```

- **imtcp loaded twice** - rsyslog refuses a second `module(load="imtcp")`: if
  `/etc/rsyslog.conf` (or another file) loads it already for plain TCP on 514,
  take that line out of `10-acme-tls.conf`. The plain input on 514 stays as it is
  until nothing sends to it any more.
- **`PermittedPeer`** - the nodes' names as their certificates carry them (acme's
  node names). A node added later: make the file again (it lists every node), or
  add its name here.
- **Without mutual TLS** the input has `StreamDriver.AuthMode="anon"`: isemon
  checks nobody, acme still checks isemon.
- **The rule that files the lines** - `11-acme.conf` from `deploy/isemon/` - stays
  as it is: lines that arrive over TLS are filed the same way, into
  `/var/log/remote/<host>/acme-certs.log`.
- **SELinux** - 6514/tcp is `syslog_tls_port_t`, which rsyslog may listen on;
  nothing to change. `restorecon` above labels the key and certificates.
- **rsyslog older than 8.2106** (RHEL/AlmaLinux 8): the stream driver settings
  are the module's, not the input's - `module(load="imtcp" StreamDriver.Name="gtls"
  StreamDriver.Mode="1" StreamDriver.AuthMode="x509/name" PermittedPeer=[...])`
  - which makes every imtcp input TLS: plain TCP on 514 then needs a second
  rsyslog or goes away.

### isemon with its own certificate

When isemon's rsyslog has a certificate from your own CA or a public one: point
`DefaultNetstreamDriverCertFile` / `KeyFile` at it, choose *isemon has one from
its own CA* (paste the CA) or *a public CA* in the wizard. For mutual TLS,
isemon's `DefaultNetstreamDriverCAFile` must trust acme's authority as well - put
acme's `ca.pem` (from the file the wizard makes, or *High availability → the
cluster's authority*) into it beside your own CA.

### In isemon's own settings

Nothing changes in isemon itself: *Settings → The ACME logs* reads the same files
from the same folders. If isemon's UI lets you manage rsyslog inputs, the input
above is what it should have; otherwise the file in `/etc/rsyslog.d/` is it.

## 3. Back on acme: try it, switch over

*Try it on every node* - each node connects to isemon with these settings and
says how far it got: connected, TLS and isemon's certificate (its name, its
issuer, its end), and - with mutual TLS - whether isemon kept the connection
after seeing the node's certificate (a test line is sent; isemon files it, it
reads nothing from it). A node that fails says where.

*Switch over* - every node sends to `isemon:6514/tls` from then on (the target
of the same host replaced, other targets kept), checks isemon's certificate with
the authority chosen, and - mutual TLS - shows its own. *Send a test line* on
each node's card shows it arrive.

`Switch TLS off…` goes back to plain TCP on 514 (not under high security).

## When nothing arrives

- acme: Settings → isemon, each node's card - *trouble* says why (a certificate
  not trusted, a name that does not match, connection refused).
- isemon: `journalctl -u rsyslog` - `gnutls` errors name the cause:
  `not permitted to talk to peer` (PermittedPeer - the node's name), `unknown CA`
  (`ca.pem` is not acme's), `certificate expired`.
- `openssl s_client -connect isemon:6514 -CAfile ca.pem` from a node shows the
  certificate isemon answers with.
- High security: isemon is sent to over TLS only, with its certificate checked.
