# The system's trusted roots

*Settings → Certificates and TLS → Trusted roots of the system* (1.0.59, as otp 1.0.265); on
the server `acme --os-roots`. Certificate authorities of your own - your company's root, an
intermediate - trusted by **the whole operating system** of every node: curl, dnf, LDAPS to a
domain controller, SMTP, syslog over TLS and acme's own connections - every program that uses
the system's trust.

## What it does, and what it never does

* **The distribution's list is never touched.** It keeps coming with the system's updates (the
  `ca-certificates` package). acme's certificates are added **beside it**, the way the system
  itself takes local additions, which every run of the system's tool - also the one an update
  of `ca-certificates` runs - merges with the distribution's list. Both keep working at once.
* Only files named `acme-<the first 16 hex of the SHA-256>.pem` (`.crt` on Debian and Ubuntu)
  are ever written or taken away. Anything else in that folder was put there by somebody else:
  the card shows it (*Added by somebody else - acme leaves them as they are*) and acme never
  changes it. A link there is shown as a link and never followed.
* In a cluster the set is the **cluster's**: changed on either node's pages, both nodes put it
  in within a minute, and each says how it went.

| Family | Local additions | Tool | The resulting list | Package |
|---|---|---|---|---|
| RHEL / AlmaLinux / Rocky | `/etc/pki/ca-trust/source/anchors/*.pem` | `update-ca-trust extract` | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | `rpm -q ca-certificates` |
| Debian / Ubuntu | `/usr/local/share/ca-certificates/*.crt` | `update-ca-certificates` | `/etc/ssl/certs/ca-certificates.crt` | `dpkg-query -W ca-certificates` |

Which one a node is, it finds out by itself (the RHEL folder or tool, else the Debian ones);
two nodes on different distributions each use their own. Under SELinux a new file is
labelled as its folder (`restorecon -F`; the anchors folder is `cert_t`).

## What is taken

A certificate in PEM (one, or a chain file - each authority in it is added) or one in DER
(`.cer`). Each is read by `openssl` - on the pages, and again by root on every node.

**Not taken:**

* a text with a private key, an encrypted block, PKCS#7 or a `TRUSTED CERTIFICATE` in it (the
  whole text);
* a certificate that says nothing of being an authority (no `basicConstraints`), or says it is
  not one (`CA:FALSE`) - a server's own certificate does not go here;
* one whose key usage does not let it sign certificates (no `keyCertSign`);
* anything not base64, empty, or larger than a certificate is (16 kB as PEM).

**Taken, and said (amber):**

* it ran out, or is valid only from a later day;
* an intermediate signed with SHA-1 or MD5, an RSA key under 2048 bits - the system's crypto
  policy (`DEFAULT`) refuses them;
* an intermediate whose root is neither in the set nor in the same paste - programs that take a
  partial chain (curl, Python 3.13 on) trust it by itself, others want its root too.

At most **50** certificates. As one types in *Add an authority*, every certificate is shown
with what it is, and what stands against it, before anything is added.

## How each node puts it in

The pages (or the command line) write the set into the database; every node's daemon sees it
within seconds and has its **root helper** (`acme_web.py`, through `osroots.ask` and
`acme-web.path`) bring the machine to exactly that set: what is missing written (root's,
`0644`, written beside and renamed into place), what is acme's and no longer wanted taken
away, and the system's tool run - **only when something changed**. Then it reads what the
machine has: acme's files, **whether each is really in the resulting list**, the others'
files, how many the system's own list holds, when it was made and by which package. Root
checks every certificate again and writes nothing into a folder that is a link, not root's,
or writable by anyone else.

The machine is read again every half hour and at the start of the daemon; *Read it again on
every node* asks at once. A set that failed is tried again after ten minutes.

| A node says | Meaning |
|---|---|
| **as wanted** (green) | it has the set, in its system's list |
| **waiting** (amber) | not done yet - *not answering* when the node is down (it catches up when it starts); after five minutes the hint: is it of this version, is `acme-web.path` running there |
| **failed** (red) | the reason: the helper's, the tool's own words, a certificate root did not take |
| **nothing added by acme** (grey) | no set was ever written - only what the machine has is shown |

During an upgrade a node of an older version has no helper for `osroots.ask`: it stays
*waiting* until it is upgraded too; nothing is lost.

## acme's own connections

acme's own TLS clients (the directory, mail, syslog, SMS, ACME, isemon, the remote backups) use
OpenSSL's default places. A Python with an OpenSSL of its own may look where there is nothing;
then, at the start, if `SSL_CERT_FILE` and `SSL_CERT_DIR` are not set, acme points
`SSL_CERT_FILE` at the system's list - and what is added here reaches acme too. The card says
whether acme's own connections use the system's list. A client with a CA file of its own (the
database's `sslrootcert`, a directory's own authority) keeps using that.

## The command line and the console

```bash
acme --os-roots                          # the set and every node's state (--json too)
acme --os-roots-add company-root.pem     # the file read as root first (it may be in /root); asked before adding
acme --os-roots-remove 6433b38639c3f329  # by the SHA-256 fingerprint (12 characters of it at least)
```

`--yes` answers the question ahead. The console (*The pages' certificates, updates, restarts,
tests*) has the same three items.

## Under the hood

| Row of `meta` | Written by | What |
|---|---|---|
| `oscerts:want:<node>` | the node whose pages (or command line) changed the set | `{v, certs: [{pem, fp, cn, kind, by, at}], by, at, what}` |
| `oscerts:node:<node>` | that node's daemon only | `{at, v, hash, ok, error, said, refused, python, state}` - what its helper did and what the machine has (no PEMs) |
| `oscerts:again:<node>` | any node | a time: every node reads again |

The newest `v` of all `want` rows is the set (`v` is counted above every `v` seen, so the order
does not hang on the nodes' clocks; a tie goes by the row's name). Each node writes only rows of
its own, so the two databases never write over each other. `oscerts:want:` is signed by the
database guard (`db_guard`) as every row that reaches root. Every change is an event (who added
or took away what), and so is what each node did.

API: `GET /api/osroots` - any administrator (certificates of authorities are nothing secret);
`POST /api/osroots` - a full administrator: `{action: check, text}`, `{action: add, text}`,
`{action: remove, fp}`, `{action: refresh}`.
