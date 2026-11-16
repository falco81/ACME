# Target agents (acme-agent)

A target of the kind **Server with acme-agent** (`agent`) takes its certificates from acme
**without acme holding any of its credentials** - no SSH key, no password, no sudo. A small
agent on the server does the work, and only what the server's own policy allows.

> acme proposes, the target decides.

* Whoever steals acme's database or a backup gets nothing of the server: there is no secret of
  it to get. The private keys acme sends are sealed to the agent's own key.
* Whoever controls a running acme can do on the server only what its policy allows - write
  certificate files into the folders it names, with the owners and modes it names, reload the
  units it names, run the tests and scripts it lists by their hash.
* The deployments work as they do on a [Linux / Unix server over SSH](targets.md#ssh): the same
  files and formats, the presets, before / test / script / reload / after, templates, the copies
  kept, the same certificate again changes nothing, the previous files back when the test or the
  reload fails.

Phases 1 and 2 brought the agent (Linux; the protocol, the policy, both modes, the join);
phases 3 and 4 the keys made on the server, tests and connections through the agent, What
happens for every step, signed self-update and the monitoring (all in 1.0.116, below).

## Threat model

| Who | What they have | What they get of a server with acme-agent |
|---|---|---|
| Somebody with acme's **database or a backup** (stolen, a replica, a dump) | the agent authority's and the command key's sealed keys, without the sealing key; the agents' public keys and certificates; jobs waiting for an active agent (their keys sealed to the agent) | nothing: no credential of the server is in acme. With the sealing key too (a whole machine stolen) they can sign jobs - which the agent's policy still bounds, as below |
| Somebody **controlling a running acme** (its root, a full administrator, a bug) | acme's command key and agent authority | what each server's policy allows, and nothing else: files in its allowed folders with its owners and modes, its allowed units' verbs, its tests and scripts by hash. They cannot change the policy, read files, run a shell, open another port, or reach another server through it - and, however broad the policy, never write the agent's own places, the places that give root, a file the policy runs, or an executable (below) |
| Somebody **controlling the target** | that server | that server's certificates (they had them anyway). Not acme: the agent's reports are untrusted input (sizes and shapes checked, shown as text), its certificate lets it in only as itself, and it can only ask for its own jobs |
| Somebody **on the network between** | the traffic | nothing: TLS 1.3 with certificates both ways, pinned; every job signed (Ed25519) with a nonce, its time and the agent's id - a replay or a job for another agent is refused; private keys sealed (X25519 + HKDF-SHA256 + AES-256-GCM) on top. The join, before anything is pinned, is proven both ways by the code's secret - acme's addresses an active agent is given too |
| The agent's **network side** taken over (a bug in TLS, in Python's HTTP) | the account `acme-agent`: no privileges, no capabilities, a read-only system, its own state folder | its TLS key (it can pose as the agent towards acme) - not root: the root side checks acme's signature on every job itself, and the policy |
| Somebody who **may write the policy's folder** or `agent.json` (a mistake of the server's) | - | nothing: a policy or `agent.json` that somebody but root may change (the file or its folder), or a link, is not believed - nothing is allowed, no job is taken |

### What holds whatever the policy says (1.0.116 review)

The policy is the server's word, but some places are never written nor taken away by a job, and
some things are never done, however broad an entry is:

* **the agent's own places**: `/etc/acme-agent` (the policy, `agent.json` - the command key root
  pinned and the `systemctl` it runs -, `ca.pem`), `/var/lib/acme-agent`,
  `/var/lib/acme-agent-root`, `/run/acme-agent`, the program's folder. `allow file /etc` does not
  let acme rewrite the policy;
* **places whose files give root**: sudoers (`/etc/sudoers`, `.d`), cron (`/etc/crontab`,
  `/etc/cron.*`, `/var/spool/cron`), systemd (`/etc/systemd`, `/usr/lib/systemd`, `/run/systemd`),
  `/etc/init.d`, `/etc/rc.d`, PAM and `/etc/security`, `ld.so` (`.preload`, `.conf`, `.conf.d`),
  the shells' profiles, `/etc/environment`, `passwd` / `shadow` / `group`, `/etc/ssh`, `/root`, any
  `.ssh` folder, polkit, udev, modprobe, sysctl, SELinux, audit, the package sources, logrotate,
  `/boot`, `/proc`, `/sys`, `/dev`, and the programs' folders (`/bin`, `/sbin`, `/lib*`, `/usr/bin`,
  `/usr/sbin`, `/usr/lib*`, `/usr/libexec`, `/usr/local/bin`, `/usr/local/sbin`);
* **a file the policy runs**: a script it allows by path, and every absolute path in a test's
  command line (`allow test -- /bin/sh /opt/app/check.sh` - `check.sh` is never written, even
  when `/opt/app` is allowed);
* **no file is executable**, no setuid / setgid / sticky bit; the copy kept of a replaced file
  carries none either;
* every folder walked from `/` without following a link; a job's time a finite number within five
  minutes; an update's package 4 MiB and 256 entries at most, read in memory.

What the policy still decides - allow the **narrowest** folder that holds only certificates:

* a folder of **configuration** (`/etc/nginx`, `/etc/httpd`) lets acme write the configuration a
  service then reads as root (`load_module`, `include`): allow its `ssl` or `certs` sub-folder;
* a script allowed (by path or by hash) runs with the **arguments acme gives** it: write it to
  take them as untrusted (or to take none);
* `allow probe local` lets acme learn which ports of 127.0.0.1 / ::1 answer (each probe says how
  long it took and why it failed); `allow probe HOST:PORT` and `allow connect HOST:PORT` with a
  **name** go where DNS says that name is when they run - name an address where that matters;
* whoever holds a **join code** (an hour, once) can join their own agent as the target - it is in
  force only once a full administrator confirms its fingerprint, which they compare with the one
  the server printed; somebody who sees the code's id on the network can use up its five tries
  (a new code is made).

### What the agent's answers can do in acme

What an agent sends is untrusted (`clean_result`, `clean_policy`): known keys of known shapes, cut
to size, one line wherever it goes - Events, the SIEM, the log, the alerts (a host name or an answer
with a line break cannot make an event of its own); the steps of a deployment keep their lines
and are shown as text; `Infinity`, `NaN`, a malformed answer are refusals, not errors. An agent's
certificate is signed with acme's own subject (`CN=acme-agent:<id>`, no extension of its CSR),
only for the key pinned at the join; an agent asking for its renewal is heard once an hour. A
key made on the server is issued only for the names and the key type of the certificate (the
device's CSR checked as any device's). An active agent gets only its own jobs and can answer only
those; acme's addresses it pins are those of the code or those acme proved with the code's
secret.

## How it is built

```
  acme (every node)                                    the server
  ──────────────────────────────────────               ───────────────────────────────────────────
  targets/agent.py  ─┐                                  acme-agent.service     (user acme-agent)
  certs/agents.py    │  passive: acme → :8446 ───TLS──▶  network side: TLS 1.3, mTLS, the protocol
  (CA, command key,  │  active:  agent → :8444 ──TLS──▶     │ Unix socket (its uid checked)
   sealing, queue)   │     nginx (acme_agents.conf)         ▼
                     │     → web/agent.php → daemon     acme-agent-root.service (root, no network)
                     └── jobs in meta (either node)      checks signature, nonce, time, policy;
                                                         stage, install, test, reload, rollback
```

* **acme** (`acmelib/certs/agents.py`, `acmelib/certs/api_agents.py`,
  `acmelib/plugins/targets/agent.py`) keeps, in `meta` (so in every backup, on every node, put
  back by a restore as everything else):
  * **the agent authority** (`agents:ca`, ECDSA P-256, ten years, key sealed): it signs each
    agent's certificate (CN `acme-agent:<agent id>`, 30 days) and acme's own (`agents:ctl`, CN
    `acme-agents`, two years, made again 60 days before its end) - the client certificate of a
    passive call and the server certificate of the agents' port;
  * **the command key** (`agents:cmd`, Ed25519, sealed): every job is signed with it;
  * **each target's agent** (`agents:t:<id>`): its mode, agent id, the fingerprints of its key and
    certificate, its X25519 public key, its version, when it was last heard from, the policy it
    last said; `agents:id:<agent>` says which target an agent id is;
  * **jobs for an active agent** (`agentq:<target>:<job>`) until it takes them, and their results
    (`agentr:<job>`) - in the database, so a job queued by one node is handed over by whichever
    node the agent reaches.
* **The agent** (`deploy/agent/acme_agent.py`, one file, the Python 3 standard library; the
  `cryptography` module is used when it is there; `openssl` for its key and requests) runs as two
  processes:
  * **the network side** (`acme-agent serve`, `acme-agent.service`): the account `acme-agent`,
    never root (it refuses), `NoNewPrivileges`, an empty `CapabilityBoundingSet`,
    `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
    `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service`,
    `MemoryDenyWriteExecute`; it writes only `/var/lib/acme-agent`. It holds its TLS key (made on
    the server, never leaving it) and speaks TLS and the protocol;
  * **the root side** (`acme-agent root`, `acme-agent-root.service`): a Unix socket
    (`/run/acme-agent/root.sock`, root:acme-agent 0660, the peer's uid checked) and a closed set
    of operations. It never opens a network connection. It checks **every** job again - acme's
    signature with the command key pinned at the join, the agent's id, a nonce never seen (kept
    across restarts), the job's time (five minutes), at most 60 jobs a minute - and then every
    file, owner, mode, unit, command and script against the policy, read anew for each job.

Every operation, refusals too, goes to the journal (`journalctl -t acme-agent`) and to
`/var/lib/acme-agent-root/audit.log` - names, paths and hashes, never what a file holds.

## The policy

`/etc/acme-agent/policy`, root:root 0644. acme can never change it; a policy file that somebody
but root may write - the file or its folder -, or a link, is not read at all (nothing is allowed).
The default allows **nothing**. A line with a word its entry does not know (`mod=0600`) or one
said twice is not read (said by `acme-agent policy show`).
Change it with the command line (as root) or by hand, one entry a line:

| Entry | Command | What it allows |
|---|---|---|
| `allow file DIR owner=U:G mode=0640` | `acme-agent allow file DIR --owner U:G --mode 0640` | files in DIR and its sub-folders (made when missing), owned by U:G, at most that mode (never executable, no setuid, setgid or sticky bit ever; never the places above). DIR is kept as its real path |
| `allow unit NAME reload,restart` | `acme-agent allow unit nginx reload,restart` | `systemctl VERB NAME` for those verbs (reload, restart, try-reload-or-restart, reload-or-restart, try-restart); after it, `systemctl is-active` is said |
| `allow test -- ARGV...` | `acme-agent allow test -- nginx -t` | that command line, exactly, as a test, a reload or a command before / after - never through a shell |
| `allow script PATH sha256=HEX` | `acme-agent allow script /usr/local/bin/x.sh` (pins its SHA-256 now) | that script; its hash is checked when it runs, and it runs from a copy root keeps (changed meanwhile: refused) |
| `allow script-hash HEX` | `acme-agent allow script-hash HEX` | a script written in acme (the deployment's "After the files"), by its SHA-256 |
| `allow from ADDR[/BITS]` | `acme-agent allow from 192.0.2.10` | passive: acme only from there (else from anywhere with acme's certificate); anybody else is turned away before the TLS handshake |
| `allow probe HOST:PORT` | `acme-agent allow probe www.example.cz:443` | a test of what HOST:PORT serves, connected from this server (the tests "through the agent") |
| `allow probe local` | `acme-agent allow probe local` | the same for anything on 127.0.0.1, ::1 or localhost (any port) |
| `allow connect HOST:PORT` | `acme-agent allow connect 10.0.5.21:22` | acme reaches HOST:PORT through this agent (a passive one): the agent as the connector of SSH targets |
| `allow self-update` | `acme-agent allow self-update` | acme may send a newer agent - only a package signed by a release key this agent was installed with, only a newer version |
| `limit files N` / `limit size BYTES` | `acme-agent limit files 30` | files in one deployment (20), bytes of one file (1 MiB) |

`acme-agent deny ...` takes an entry away (the same words); `acme-agent policy show [--json]`
says what is allowed, and which lines could not be read.

**acme says what a deployment needs before it runs.** The agent reports its policy (and its
hash) with every answer; the deployment's form shows, for each file, command and script, whether
the policy allows it (green), does not (red - with the `acme-agent allow ...` line to copy), or is
not known yet (amber). A deployment the policy does not allow is refused whole by the agent,
before anything is written, with the same lines in the job.

### The commands of a deployment

The agent runs no shell. Each line of before / test / reload / after is read as what it asks for:

| The line | Run as | Allowed by |
|---|---|---|
| `systemctl reload nginx` (`restart`, `try-reload-or-restart`, ...) | that verb of `nginx.service` | `allow unit nginx reload` |
| `service nginx reload` | the same | the same |
| `nginx -t`, `postfix check`, `doveconf -n >/dev/null` | that argv exactly (`>/dev/null`, `2>/dev/null` dropped) | `allow test -- nginx -t` |
| `/usr/local/bin/x.sh ARGS` | that script with those arguments | `allow script /usr/local/bin/x.sh` |
| `A || B` | A, else B (each one of the above) | each its own |

Anything else (a pipe, `;`, `$`, a redirection into a file - the Kubernetes preset, say) is
refused before anything is sent: put it into a script and allow the script.

## Modes and ports

Chosen per target (`mode`). The protocol is the same; only who opens the connection differs.

| | passive (default) | active |
|---|---|---|
| who connects | acme → the agent | the agent → acme |
| open on the server | TCP 8446 (to acme only: your firewall, and `allow from`; 64 connections at once at most) | nothing |
| open on acme | nothing (it connects out) | TCP 8444 on every node (Settings → Target agents) |
| TLS | TLS 1.3; the agent shows its certificate of the agent authority (acme checks its fingerprint is the one it pinned); acme shows its own (CN `acme-agents`), the agent lets in only certificates of the authority it pinned with that name | TLS 1.3; nginx asks for a client certificate of the agent authority alone (`ssl_verify_client optional` - the join comes without one - and the poll is refused by nginx without one that passed); acme checks the fingerprint and the agent id against what it pinned on every request; the agent checks acme's certificate is of its authority with CN `acme-agents` |
| jobs | posted to the agent, answered at once | queued in the database; the agent long-polls (20 s held at most, three polls held at once a node, the rest told to come back in 8 s) and posts the results with its next poll |

**Active mode is off by default** (Settings → Target agents → *Agents may connect to acme*).
While it is off nothing of it exists: no port, no server of nginx, no rule in acme's firewall,
`request.json` to the root helper as before - an installation that never uses it is byte for
byte as before. Switched on, every node's root helper writes `acme_agents.conf` (a server on the
port with TLS 1.3, the agent authority as its only client CA, acme's certificate of it,
`/agent/v1/join`, `/agent/v1/join/status` and `/agent/v1/poll` only, relayed by `web/agent.php`
to the daemon's `/api/agent-wire/*`, which the pages' relay does not reach), SELinux is told the
port is nginx's, and acme's firewall lets the port in on every node (a card of its own under
"What acme lets in by itself"). Switched off again, all of it is taken away. An active target
cannot be saved while it is off.

**High availability**: an active agent is given every address in *Addresses the agents connect
to* (by default the VIP address, then each node's) and tries the next one when one does not
answer, backing off up to a minute. Its jobs are in the database, so either node hands them over;
the authority and the keys are the same on both.

## Enrollment (the join)

1. Make the target (Targets → Add → Server with acme-agent: its address for a passive one), open
   its card → **Join the agent…**. The wizard shows the package to install and makes a **one-time
   join code** (an hour, once): `ACAG1.` and base64 of the target, the mode, acme's addresses (active)
   or the port (passive), the code's id and secret, **the fingerprint of the agent authority** and
   **of the command key**.
2. On the server, as root: `acme-agent join CODE` (or `./install.sh --join CODE`). The agent makes
   its own TLS key (ECDSA P-256, never leaving the server) and an X25519 key for secrets, and
   prints the fingerprint of its TLS key (SHA-256 of its public key, in sixteen groups of four).
   Root keeps the two fingerprints of the code: it pins acme's authority and command key itself,
   only if they are the ones the code names.
3. The join: the agent (active) or acme (passive, it reaches the agent at its address) sends the
   request: the CSR, the X25519 public key, an HMAC of the code's secret over them; acme answers
   with the authority, the command key and the agent's id, with an HMAC of its own - each end
   proves it has the code, and nobody in between can put another key in. Passive: acme also
   checks the TLS key the agent answers with is the one in the CSR. The code is used up.
4. acme shows the same fingerprint on the target's card. **A full administrator confirms it**
   only when it is the same as the one on the server. Only then does acme sign the agent's
   certificate (30 days) and hand it over (active: at the agent's next question; passive: acme
   posts it to the agent).

A code run out, used, or tried five times with a wrong proof is refused; a fingerprint that is
not the agent's is refused (and said in Events). **Join again** replaces the agent: the new
agent id and key are in force once confirmed, the old certificate no longer let in.
**Forget** (the card, or `acme --target-agent NAME forget`) refuses the agent at once;
`acme-agent forget` on the server takes its side away (its keys, certificate and pins; the policy
stays). A target switched off or deleted is refused on the next request.

**Its certificate** is renewed over the channel 10 days before its end (by the node that leads,
or at once on the card): the agent makes a CSR of its own key, acme signs it, the agent puts it in
use; the one before is let in a while yet.

## The protocol

A job (from acme, JSON, canonical):

```
{"v":1, "agent":"ag-…", "job":"<24 hex>", "ts":<unix>, "nonce":"<32 hex>", "op":"…", "args":{…}}
sig = Ed25519(command key, "acme-agent/1 job\n" + the JSON as sent)
sent as {"job": "<the JSON>", "sig": "<base64>"}
```

Operations: `hello` / `policy` (version, the policy and its hash, the host), `fingerprints`
(SHA-256 of files in allowed folders), `check` (a deployment against the policy - the test,
nothing written), `deploy`, `csr` and `cert` (the agent's certificate renewed - the network
side's, checked by root first), `keygen` (a key made by root for a deployment, its CSR answered),
`probe` and `connect` (checked by root against `allow probe` / `allow connect`, done by the
network side - root never opens a network connection), `update` (root: signed, newer, allowed).

`deploy` carries the files (each with its path, mode, owner; a file holding a key **sealed**:
X25519 + HKDF-SHA256 + AES-256-GCM to the agent's key, as acme push's section 7, its aad binding
the agent's id and the file's path), the stale files acme wrote before, the commands as operations,
the script (inline with its interpreter, or a path), the `ACME_*` variables (`ACME_PASSWORD`
sealed), the copies (dated / daily / bak / folder / none, how many kept), whether to leave the
same file alone, whether the last one did not finish. The root side: checks it all against the
policy (refused whole otherwise, with what is missing); compares each file with the one there
(the same bytes, owner and mode: left alone; all the same and nothing pending: nothing run); runs
"before"; writes each file under a random name in its folder (`O_EXCL|O_NOFOLLOW`, 0600, owner and
mode set, synced) and renames it over, a copy of the old one kept as asked; takes the stale ones
away; runs the test, the script, the reload - any failing puts every file back (and runs the
reload again); runs "after" (a warning only); prunes the dated copies. Every folder is opened
from `/` without following a link, so a link anywhere on the way, or where the file goes, is
refused. The answer says each step and the SHA-256 of each file - acme checks they are what it
sent.

What the agent sends is untrusted in acme: at most 4 MiB, only the keys and shapes acme knows
(`clean_result`, `clean_policy`), every word of it shown as text.

## Install

The package is on Settings → Target agents (and with every release in `release/`):
`acme-agent-X.Y.Z.tar.gz`, signed by acme's release key (MANIFEST and MANIFEST.sig inside, as
acme's own package; one made from a source tree is said to be unsigned). The pane shows its
SHA-256 and the lines:

```
sha256sum acme-agent-X.Y.Z.tar.gz
tar xzf acme-agent-X.Y.Z.tar.gz
cd acme-agent-X.Y.Z && sudo ./install.sh          # checks the signature, allows nothing
sudo acme-agent join CODE
```

Red Hat Enterprise Linux 8-10 and its rebuilds, Debian 11+, Ubuntu 20.04+; Python 3.7 or later
(RHEL 8: `dnf install python39` - install.sh picks it), systemd, openssl. `install.sh --uninstall`
takes it away (the policy stays; `--purge` takes that and the account too).

| Where | What |
|---|---|
| `/usr/local/lib/acme-agent/acme_agent.py`, `/usr/local/sbin/acme-agent` | the program |
| `/etc/acme-agent/policy` | the policy (root:root 0644) |
| `/etc/acme-agent/agent.json`, `ca.pem` | what root pinned at the join: the agent id, the mode, acme's addresses, the authority, the command key |
| `/var/lib/acme-agent/` (acme-agent 0700) | the TLS key and certificate |
| `/var/lib/acme-agent-root/` (root 0700) | the X25519 key, the nonces seen, the audit log, the scripts' copies while they run |
| `/run/acme-agent/root.sock` | the two sides' socket |

## In acme

* **Settings → Target agents**: active mode and its port, what the agents are given; the agents
  of every target with their state (answers · N s ago / not heard from / refused / joining), mode,
  version, when heard from, their certificate's end (amber under 14 days), their policy in short;
  the package with its SHA-256 and the install lines; the agent authority's fingerprint.
* **The target's card**: the same of its agent, its policy in full, Join the agent… / Join again…
  (the three-step wizard), Ask it now, Renew its certificate, Forget….
* **Events** for every code made, join asked, confirmation, refusal, renewal, policy changed on
  the server, agent not heard from and heard from again; **alerts** for an agent not heard from
  for ten minutes and its certificate ending within seven days.
* **Command line**: `acme --target-agent NAME show | code | confirm FP | look | policy | renew |
  update | forget` - `show` says what the card says; the console (`acme`): Targets → the target →
  *Its acme-agent*.
* **API**: `GET /api/agents`, `GET /api/agents/one?id=`, `POST /api/agents/{code,look,confirm,
  renew,update,forget}`, `GET /api/agents/package`.

## Keys made by the agent (phase 3)

A certificate used only on one server can have its key **made there**: the certificate's *Key*
step offers *Key made by the agent, on the server* (`csr_from` = the target, as "The device makes
the key" - `docs/writing-a-module.md`; the agent target's module says `device_key_optional`: it is
chosen per certificate, and the target takes certificates with acme's key too). The card of an
agent target has **Make a certificate with its key made here**, which opens the wizard with it
chosen. A certificate deployed to several targets keeps acme's key, sealed to each agent.

* **At every issue** acme sends the job `keygen` (the deployment's id as its *slot*, the key type,
  the names, the files that will hold the key). The root side checks those files against the
  policy first (no key is made for a deployment that may not run), makes the key with openssl
  (`/var/lib/acme-agent-root/keys/<slot>.pending`, root 0600) and answers **only its CSR**. acme
  checks the CSR as any device's (every name, no other; the key type) and issues for it.
* **The deployment right after it** carries the certificate (and its chain) and, for each file of a
  key format, only the mark `agent_key`. Root takes the key whose public half is the certificate's
  (the pending one, or the one in use) - any other certificate is refused - and writes the file
  itself: `key-pem`, `key-traditional`, `key-rsa`, `key-der`, `combined-pem` (the key with the
  certificate files acme sent), `pfx`/`p12` (openssl pkcs12, the password sealed to the agent).
  `jks`, `p12-legacy` and `key-pem-enc` are made by acme only. Once in place the pending key is the
  key in use (`<slot>.key`); until then the service keeps its old key and certificate.
* **Renewal**: a new key each time; with *Keep the key* the agent makes a CSR of the key in use.
* acme never holds the key: not in its database, its backups, its logs or its jobs.

## Tests through the agent (phase 3)

A test (Certificates → Tests) can go *Through a connector* = a server with acme-agent: the
agent's network side runs `openssl s_client` to HOST:PORT (TLS at once, or the protocol's STARTTLS:
SMTP, IMAP, POP3, FTP, XMPP, LDAP, PostgreSQL, MySQL) and sends back the chain it was given; acme
judges it as any test's (the version, the names, the chain; trust with acme's own roots). RDP and
TDS are refused in words. Root checks the job and the policy first: only `allow probe HOST:PORT`
or `allow probe local` - nothing else is ever probed. **The tests made from a deployment on an
agent target go through its agent by default**, at `127.0.0.1` on the preset's port (with the
certificate's name as SNI) - `allow probe local` is all they need.

## The agent as a connector (phase 3)

Off unless the policy says `allow connect HOST:PORT`. *Through a connector* of an SSH target
offers passive agents too, marked *(through its acme-agent)*. ssh's ProxyCommand talks to a Unix
socket of the session (a 0700 folder of its own); each connection becomes a TLS connection to the
agent (its certificate pinned), the signed job `connect` on `/v1/tunnel`, root's yes (the policy
names exactly that host and port), then the bytes both ways (ten idle minutes at most). The host
key is read the same way (ssh with `accept-new` into a file of the session, no authentication).
An active agent cannot be a connector (nothing connects to it).

**A passive agent behind an SSH connector**: the agent target's *Through a connector* (advanced)
names a Connector over SSH; acme reaches the agent's port from there (`ssh -W`), the join too.

## What happens (phase 3)

The run plan shows every step of an agent target: the signed job and how it gets there (passive:
the address; active: queued for the poll), the key made there (keygen) with the files it will go
to, each file with its path, format, owner and mode (keys sealed / made there marked), each
command as the operation it becomes, the script, the copies, the stale files - and for **each item
the verdict of the policy the agent last said**: allowed, not allowed (with the
`acme-agent allow ...` line), or not known yet; then a summary (all allowed / the agent refuses the
job). The tests through the agent show the probe and its verdict. An SSH target through an agent
says so.

## Updates of the agent (phase 4)

acme offers the agent of its own version. A target's card and the pane say **a newer agent is
offered** when the agent runs an older version. With `allow self-update` in the policy a full
administrator can **Update the agent** (`POST /api/agents/update`, `acme --target-agent NAME
update`): acme sends its **signed** package (a release; a source tree's package is never sent).
The root side reads it in memory (one folder, plain files, 4 MiB), checks every file against
MANIFEST and MANIFEST.sig (Ed25519) against the release keys **installed with the agent**
(`/usr/local/lib/acme-agent/release-keys/`, put there by install.sh - never taken from the package
being installed), and that its version is **newer** than its own; then replaces the program and
`release` atomically and restarts both services. Without the entry the agent refuses with the line
that would allow it, and the card shows how to install the package by hand.

## Monitoring (phase 4)

* **SNMP**: `acmeAgentTable` (`acmeCertificates 9`): index (the target's id), name, mode, state,
  last seen, the days its certificate has left, version, state as a number (`AcmeAgentCondition`),
  newer offered, policy blocks a deployment. ACME-MIB REVISION 202611161200Z.
* **Prometheus**: `acme_agent_up`, `acme_agent_state`, `acme_agent_last_seen_timestamp_seconds`,
  `acme_agent_cert_not_after_timestamp_seconds`, `acme_agent_info`, `acme_agent_update_available`,
  `acme_agent_policy_blocks` - only where there is an agent target.
* **Zabbix template**: the discovery *Target agents* with its items and triggers (not heard from,
  refused, its certificate ending, the policy blocking, a newer agent offered).
* **isemon / SIEM**: the agents' events carry `action=agent_policy_blocks | agent_policy_changed |
  agent_quiet | agent_back | agent_updated | agent_update | agent_cert_renewed | agent_joined |
  agent_forgotten`, `target`, `target_kind=agent` (and `version`, `blocked`).
* **Alerts**: not heard from for ten minutes, its certificate ending within seven days, and (phase 4)
  **its policy blocks a deployment** - until a deployment there goes through.

## Backup, restore and HA

The agent authority, the command key, acme's certificate of the authority, each agent's state and
the jobs queued are rows of `meta` - in every backup, sealed with the node's sealing key that the
backup carries. A backup put back on a clean installation (or the other node of a cluster) is the
same acme to the agents: it signs with the same command key and shows the same certificate
(`test_target_agent.py BackupAndSecondNode`).

## Later

* Windows.
