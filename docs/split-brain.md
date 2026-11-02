# When the two nodes lose each other - split brain (1.0.14)

## Shrnutí česky

**Split brain** je situace, kdy dva uzly replikovaného clusteru acme přestanou vidět jeden
druhého, ale oba dál běží. Každý si myslí, že druhý umřel, a pokračuje sám. U acme se dvěma
replikovanými PostgreSQL to znamená:

1. **oba uzly vedou** - oba obnovují a nasazují certifikáty (dvě verze téhož certifikátu,
   placený zaplacený dvakrát, limity CA započtené dvakrát), vlastní autorita acme podepisuje
   v obou polovinách (CRL a čítače se rozejdou),
2. **špatná hesla a kódy se počítají v každé polovině zvlášť** - útočník má dvojnásobek
   pokusů do pauzy,
3. **změny adminů se rozejdou** - co se na každé straně změní, jde vlastní cestou a po
   spojení jedna verze tiše vyhraje,
4. kód z aplikace (druhý krok přihlášení) může během svých 30 s projít na obou.

Se dvěma uzly a bez třetího stroje se split brain **vyloučit nedá**. Dá se ale zvolit, **kdo
pokračuje**, a **zmírnit, co se mezitím děje**. Na kartě **Nastavení → Vysoká dostupnost →
Když se uzly ztratí**:

**Kdo obsluhuje, když se uzly nevidí** (jedna ze tří): *Jako dosud: pokračují oba uzly*
(výchozí - se všemi přepínači vypnutými neběží vůbec nic), *Uzel, který stále vidí síť*
(arbitr: kdo nevidí druhý uzel ani svého arbitra, ustoupí stranou), *Jen upřednostněný uzel*.

**A zatímco jsou odděleně** (libovolná kombinace):

- **Obnovy jen na upřednostněném uzlu** - obnovuje, nasazuje a podepisuje (vlastní autority)
  jen upřednostněný uzel; druhý odmítne i obnovu či podpis zadaný ručně a na portálu
  (v otp je na tomto místě „Záchranné kódy jen s potvrzením druhého uzlu“ - acme záchranné
  kódy nemá),
- **Poloviční pokusy** - pauza po špatných heslech a kódech (administrace i portál) přijde
  na každém uzlu po polovině pokusů,
- **Změny jen na upřednostněném uzlu** - jinde stránky jen čtou (karta jde měnit vždy),
- **Upozornit během oddělení, report potom** - alert, a po spojení report: co který uzel
  udělal bez vědomí druhého (obnovy, revokace, podpisy, změny, přihlášení) a co se udělalo
  na obou (jménem).

**„Ustoupit stranou“** = údržba, kterou nikdo nezapnul a která sama skončí: uzel nevede
(žádné obnovy, nasazení, CRL ani podpisy), DNS server acme na něm neodpovídá (záznamy NS
jmenují oba uzly, resolvery se zeptají druhého), VIP adresa i /healthz pro balancer odejdou
na druhý uzel, stránky zůstávají.

**Výchozí stav = „Jako dosud“ se všemi přepínači vypnutými** - nespouští se nic nového:
žádný dotaz na databázi druhého uzlu, žádný ping arbitra, nic se nezapisuje, žádné
upozornění. Upgrade chování nemění; karta to říká („Přesně jako před 1.0.14: nic z toho
neběží“).

**Od 1.0.21** (jako otp 1.0.224-1.0.227): report po spojení se udělá, až z druhého uzlu
replikací dorazí jeho stavový řádek zapsaný po tom, co tento uzel znovu našel (nejpozději za
10 min); počítá se od prvního kódu či úkonu, na který se druhého uzlu nešlo zeptat (řádky
dřívějšího krátkého výpadku se vynechají), každý jednou. Spojení z doby před výpadkem se
zavřou. A v jakémkoli režimu, i „Jako dosud“: dokud je dotaz před puštěním kódu odložený
(databáze druhého uzlu neodpověděla), ptá se hlídka každé 2 s a odklad zruší, jakmile
odpoví. **Upřednostněnému uzlu spadla jen databáze**: odmítnutí od samotného PostgreSQL
(„shutting down“, „starting up“) není přerušené spojení - druhý uzel pak v režimu priority
neustoupí; holé „connection refused“ jen tehdy, když stroj upřednostněného uzlu přijme TCP
spojení na 443, 22 nebo 80 (firewall s REJECT říká totéž). Stejně, když upřednostněný uzel
naposledy hlásil údržbu, nebo že kvůli hodinám ustoupil stranou - to jen dokud je jeho řádek
čerstvý (< 32 s podle změřeného rozdílu hodin). Uzel, který ustoupí, je zticha hned (VIP
adresa i /healthz, bez „dobíhání“).

Karta je stejná jako v otp 1.0.218-1.0.221: živý stav obou uzlů, tři volby jako dlaždice
s plusy a mínusy, čtyři přepínače (vždy dva a dva), tabulka **„Co se stane“** spočítaná
z voleb ještě před uložením (pevné šířky sloupců) a report posledního oddělení. Ukládá se
lištou dole; arbitra je nutné před uložením vyzkoušet ze všech uzlů (**Vyzkoušet ze všech
uzlů**).

---

## 1. What it is about

Two nodes, each with its own PostgreSQL, replicating both ways. Either node answers the
pages and acme's DNS server; **one node leads** (`certs:leader`, see
[high-availability.md](high-availability.md#who-renews-and-deploys)): it renews, deploys,
makes the CRLs fresh. With two databases the lease row cannot be the judge, so the leader
is decided by a rule both nodes reach alone: the node holding the VIP address, else the
first by name of the nodes alive.

When the two nodes cannot reach each other each takes the other for gone - and **both
lead**. Its costs:

| cost | why |
|---|---|
| a certificate renewed on both halves | each node leads; two versions, two orders at the CA (rate limits, a paid certificate paid twice), one of the two lost after the heal |
| an own authority signing on both halves | its serials, its issued list and its CRL number go two ways |
| twice the wrong tries | each half counts its own failures (each node always counts its own; apart, an attacker can use both) |
| changes going two ways | an admin on each half changes the same thing; after the heal, the later change wins per row |
| an app code let in twice | each half checks only its own rows of `used_once` (30 s window) |
| the VIP address on both | keepalived of each node cannot hear the other's VRRP |

**Not solvable with two nodes:** from inside one node, "the other is dead" and "I am cut
off" look the same. Only a third point of view - an *arbiter* - tells them apart: something
already there (the default gateway, the router, the load balancer).

**One shared database** (`ha_mode = shared`): no split brain of the data at all - the
database decides. The card says so and offers nothing.

## 2. Words used

| word | meaning |
|---|---|
| **apart** | the other node's database has not answered for `split_after_s` seconds |
| **together** | it answers again |
| **step aside** | not lead, stop acme's DNS server, let the VIP address and /healthz go - as maintenance, but automatic and ending by itself |
| **held back** | apart with `split_renew` on and not the preferred node: it answers, but does not lead |
| **preferred node** | the one chosen (`split_prefer`), else the first node of the cluster (`ha_slot` 1) |
| **arbiter** | addresses a node pings (or `host:port` it connects to) to know whether *it* is cut off |

## 3. Settings

Cluster-wide, except `split_arbiter`, which each node has its own (`split_arbiter@NODE`).
They are on the High availability pane, drawn and saved by its card only (never as boxes of
their own - as otp 1.0.219).

| key | range | default | meaning |
|---|---|---|---|
| `split_mode` | `off` \| `arbiter` \| `priority` | `off` | who answers while apart |
| `split_prefer` | a node's name, or empty | `''` | the preferred node; empty = `ha_slot` 1 |
| `split_arbiter` | text, per node | `''` | up to 5 targets: `192.0.2.1`, `gw.example.cz:443`, `[2001:db8::1]:53`, `2001:db8::2`; empty = the default gateway |
| `split_after_s` | 5-300 | 20 | seconds without the other database before "apart" |
| `split_renew` | 0/1 | 0 | renewals, deployments and signing only on the preferred node while apart |
| `split_halve` | 0/1 | 0 | half the tries to the pause while apart |
| `split_freeze` | 0/1 | 0 | changes only on the preferred node while apart |
| `split_report` | 0/1 | 0 | alert while apart, report afterwards |

**"As until now"** - `split_mode = off` and all four switches 0, the defaults - is exactly the
behaviour before 1.0.14: the watch does nothing at all (no question to the other database,
no arbiter, no row written, no limit changed, nothing frozen or held back,
`split_engaged()` false).

Saving `split_mode = arbiter` (from another mode) is **refused unless the arbiter was tried
from every node** and every node reached its own.

## 4. The watch - how "apart" is told

A thread of its own (`acme-split`), started by the daemon's loop, every **2 s**:

1. Not a replicating pair, or "as until now": never apart, nothing asked, nothing written.
2. **Ask the other node's database** on a connection of its own (2 s connect, 2 s
   statement), `SELECT 1`, waited for 3.5 s at most - the very database asked before a code
   of the second step is let in.
3. **Ask the arbiter** - every step in `arbiter` mode, otherwise every 30 s (for the card).
4. **apart = now - last answer > split_after_s**.
5. Transitions are events (Events, kind *ha*) and log lines; a report is due 30 s after
   together - made only once the other node's state row written after it found this one
   again has come over by replication (its earlier rows, the `split:took` ones among them,
   come before it), at the latest 10 min later (1.0.21, as otp 1.0.224: after a long cut the
   replication took 40 s, and what was done on both was not found). On together the pooled
   connections to the other node's database from before the cut are closed
   (`once_peer_forget`). And in any mode, "as until now" included: while the question
   before a code of the second step is let in is held off (`ONCE_PEER.down_until` - the
   other node's database did not answer), the watch asks every 2 s and lifts the hold the
   moment it answers. With no hold, as until now asks nothing.
6. **Decide** the role; on a change the maintenance cache is flushed and the renewer woken
   (it lets its lead go and stops its DNS server at once).
7. Every 10 s (and on every change) this node's state goes into meta `split:state:<node>`.

## 5. The arbiter

`split_arbiter` of this node; empty → the default gateway (`/proc/net/route`). `host:port`
→ TCP connect, 1 s (refused counts as reached - it answered). An address or a name → one
ICMP echo, 1 s: a datagram ICMP socket (any user in `net.ipv4.ping_group_range`), a raw
socket, `/usr/bin/ping`; none possible → **"cannot be asked"**, which never makes a node
step aside. Any one reached → reached.

Choose something both nodes reach **by another way than they reach each other**: the
router, the load balancer, a DNS resolver - not the other node.

## 6. The decision

```
not apart                -> serve
priority: preferred      -> serve;  else aside
arbiter:  arbiter False  -> aside   (neither the other node nor the arbiter)
          None / True    -> serve
off                      -> serve
```

No tie-break in arbiter mode: "the link between us broke" and "the other node died" look the
same from inside.

### 6.1 The preferred node's database down, its machine there (1.0.21, as otp 1.0.226/1.0.227)

"Apart" is "the other node's database does not answer". With `priority` that stepped the
other node aside even when only the preferred node's database was down (stopped,
restarting) - and the preferred node, without its database, answered nobody either. Now the
other node (`split_preferred_unable`) takes the preferred node for unable, and goes on, when:

- **PostgreSQL itself answered** that it does not take connections: "the database system is
  shutting down", "starting up", "not yet accepting connections", "in recovery mode";
- **a bare "connection refused"** - and the preferred node's machine takes a TCP connection
  on 443, 22 or 80 (asked at most every 10 s). A firewall between the nodes that rejects
  (nftables `reject`, iptables `REJECT`) gives the same words while the preferred node is up
  and answering: refused alone is not enough;
- its last word (its rows, as they came over) is that it is **in maintenance**
  (`maint:<node>` on), or that it **stepped aside for its clock** (`clock:state:<node>` role
  aside, Settings -> Time, docs/clock-guard.md) - that only while its row is younger than
  32 s by the measured difference of the clocks: aside for its clock, it answers again once
  the other node's row reads stale to it (25 s), and the other node gives way a few seconds
  after.

No answer at all is a cut link, as before: the other node steps aside. `split_decide(mode,
apart, arbiter, preferred, unable)`.

**Silent at once.** A node that steps aside (for the split or its clock) drops the
maintenance cache and the second of `/healthz`'s cache at once, and the VIP check says
"in maintenance" at its next look (acme has said maintenance at once since 1.0.186 - no
"draining" for a node that steps aside; the 20 s of an upgrade's turn are for maintenance
asked for).

## 7. What changes while apart

### 7.1 Stepping aside

`maintenance_now()` returns `{'on': True, 'why': 'stepped aside: …', 'split': True}`. Hence:
the VIP check says "in maintenance" (keepalived moves the address), `/healthz` and the
heartbeat say maintenance (the load balancer takes the node out), the pages keep working.
And, acme's own:

- **the renewer does not lead** (`renewer.lease_tick` lets the lease go): no renewals, no
  deployments, no CRLs, no tidying;
- **a renewal, a revocation or a signature asked by hand** (the pages, the portal's
  certificate requests, *Sign a CSR*) is refused with the words why;
- **acme's DNS server stops answering** on this node (`dns_state().said = 'stepped aside'`)
  and starts again by itself.

The stored maintenance (`maint:<node>`) is not touched.

### 7.2 Renewals only on the preferred node (`split_renew`)

Apart, switched on, not the preferred node: **held back** - it answers (VIP, DNS, pages),
but does not lead, and refuses renewals, revocations and signing by hand. The preferred
node renews; certificates due on the other wait (renewals start days before the end).
Without it, in `off` and `arbiter` modes both halves may lead (as before 1.0.14).

### 7.3 Half the tries (`split_halve`)

`login_tries` (administration, password changes, the second step) and `portal_tries`
(portal) are read through `split_limit()`: apart and switched on → `max(1, ceil(v/2))`.

### 7.4 Changes only on the preferred node (`split_freeze`)

In the API dispatcher, before a POST runs: apart, switched on, this node aside or not the
preferred node → **409** `{"ok": false, "split": true, "error": "the two nodes cannot reach
each other: changes are made on <preferred> only until they do (…)"}`. Always allowed:
`/api/auth/*`, `/api/split`, `/api/ha*`, `/api/power`, `/api/acme-push/*`, `/api/health`,
`/api/alerts`, `/api/logs`, the portal's sign-in (`/api/portal/login|logout|mfa`),
`/api/console-login`, a node into maintenance (`/api/upgrade` action `maintenance`), and what
only reads (`/api/certs/parse|dry_run|export`, `/api/cas/export|pki_check`,
`/api/deploys/dry_run|preview`, `/api/sshkey/show|download`, `/api/portal/cert_download`,
`/api/certs/compat`, the actions that only read of `/api/db` (`job`, `download_ticket`,
`check`, `tune_plan`), `/api/rbackup` (`job`, `list`, `verified`, `restore_md`), `/api/texts`
and `/api/metrics` (`preview`), `/api/firewall` (`rule_check`), `/api/directories`
(`lookup`)). GET is never refused. What only reads is not
written down for the report either.

### 7.5 Warning and report (`split_report`)

- **While apart**: an alert `split:<node>` (bad): "<node> cannot reach the other node [and
  stepped aside]" - "The other node's database has not answered since … This node does not
  renew, deploy or answer DNS / answers but leaves the renewals to the preferred node /
  renews, deploys and answers DNS alone."
- **Written down while apart** (meta `split:took:<node>:<key>` = `{name, kind, at}`, the key
  the same on both nodes for the same thing):

  | kind | when | key |
  |---|---|---|
  | `renew` | a certificate issued or renewed | `renew:<certificate id>` |
  | `revoke` | a certificate revoked | `revoke:<certificate id>` |
  | `sign` | an own authority signed anything | `sign:<authority id>` |
  | `change` | a POST of the pages that changes something | `change:<hash of route, action, id>` |
  | `signin` | a sign-in to the administration or the portal | `signin:admin|portal:<name>` |
  | `step` | an app code let in while the other database could not be asked (apart or not) | the code's `used_once` key |

- **The report** (on the preferred node, after together, the other node's rows having come
  over - see 4.5): counted from the first thing the other node could not be asked about in
  this time apart (the rows older than when it last answered, less 5 s and the measured
  difference of the clocks, are an earlier short outage's: left out, and removed), each key
  once per node: grouped by key; a key from both nodes = **done on both** (a sign-in on each
  half is not a clash). A code is written down under its `used_once` key only - acme has no
  second row of the same code (otp counted one again by its token's `#id`). Meta `split:report`
  = `{at, since, taken: {node: n}, kinds: {node: {kind: n}}, twice: [{name, kind, nodes,
  at}], twice_n}`; the rows deleted; an event; an alert `split:twice` (warn) for 24 h.

What to do with *done on both*: `renew` - two versions of the certificate were made; the one
kept on both is the later; check the deployments (`acme --cert NAME`), deploy again if a
target has the other. `sign` - check the authority's issued list and make its CRL again.
`change` - look at the thing on both nodes. `step` - one person's code accepted twice.

## 8. What happens - the matrix

A = the preferred node, B = the other. "answers" = VIP, DNS, leads.

| what fails | off | arbiter | priority |
|---|---|---|---|
| **B fails** | A answers | A answers | A answers |
| **A fails** | B answers | B answers | **nobody** (B aside) |
| **B loses the network** | A answers; B answers whatever reaches it (risks) | A answers; B aside | A answers; B aside |
| **A loses the network** | B answers; A answers whatever reaches it (risks) | B answers; A aside | **nobody reachable** |
| **only the link A-B breaks** | both answer (risks) | both answer (risks) | A answers; B aside |

With `split_renew` on, wherever B answers while A is away, **renewals wait until A is back**.
"Risks" = a certificate renewed on both (not with `split_renew`), an app code on both within
its 30 s, twice the wrong tries (not with `split_halve`), changes two ways (not with
`split_freeze`). The card draws this table live from the choices.

## 9. API and command line

The routes are otp's:

- `GET /api/split` (any administrator): `{active, engaged, ha_mode, conf: {split_*},
  preferred, me, nodes: [{name, me, alive, fresh, arbiter, state}], report}` (`fresh`: the
  node's state row is under 60 s old).
- `POST /api/split` (full administrator):
  - `{"action": "save", "conf": {split_* keys}, "arbiter": {"acme1": "...", ...}, "checked":
    true|false}` → `{message, view}`; 409 when switching to `arbiter` without `checked`;
    400 on a bad mode, an unknown node, a bad arbiter. Never frozen.
  - `{"action": "try", "targets": {"acme1": "...", ...}}` → every node checks its own
    (`ask:want:split_arbiter`); `{id, nodes}`.
  - `{"action": "poll", "id": "..."}` → `{nodes: {acme1: {ok, verdict, gateway, targets} | null}}`.

The page's relay passes `?api=split` on (GET and POST) - without it the card shows only its
title (otp 1.0.218 shipped so).

Command line (`acme --help`, HIGH AVAILABILITY):

```
acme --split                                  what each node does now, the choices, the last report
acme --split-mode off|arbiter|priority        (arbiter: tried from every node first, saved only if all reach)
acme --split-prefer NODE|first   --split-after S
acme --split-arbiter NODE=TARGETS ...         (NODE= alone: its gateway)
acme --split-renew|--split-halve|--split-freeze|--split-report on|off
acme --split-try                              each node's arbiter, from that node
acme --split --json
```

## 10. What is kept in the database (meta, replicated)

| key | written by | what |
|---|---|---|
| `split:state:<node>` | that node, every 10 s and on change | its state |
| `split:took:<node>:<key>` | that node, while apart | `{name, kind, at}` |
| `split:report` | the preferred node, after together | the last report |
| settings `split_*`, `split_arbiter@<node>` | the card | as in 3 |
| `ask:want:split_arbiter`, `ask:got:split_arbiter:<node>` | the card / each node | Try it |

Nothing of this is a secret.

## 11. The card

On *Settings → High availability*, after the VIP address card (`#ha-split-card`), drawn only
in a cluster. HTML, CSS and JavaScript are otp's (1.0.218-1.0.221; `web/admin/index.php`,
`web/assets/acme.css` "When the nodes lose each other", `web/assets/admin.js` `loadSplit` /
`drawSplit`), the words acme's where the meaning is acme's (renewals instead of codes, the
column *Renewals and DNS* instead of *Sign-ins*, `split_renew` in place of `split_scratch`),
the Czech texts otp's where the English is the same.

- **Draft and save bar**: every click changes a draft and draws the card again; a draft
  different from the view is a pending change of the page's save bar (`pendingSet('split',
  {pane: 'ha', ...})`). Nothing is sent before *Save*; *Put them back* drops it.
- **The page stays where it is**: the card is drawn again whole; the scroll position of every
  scrolled box around it is kept and put back (`scrollHeld` / `scrollBack`; `drawSplit` wraps
  `drawSplitIn`) - and once more after the page's words are put in its language (the English
  is taller). Without it a switch clicked half-way down sent the page up (otp 1.0.218-1.0.219).
- **Arbiter first tried**: *Try it from every node* sends the arbiters as typed, polls every
  second (up to 20 s); saving to `arbiter` is blocked until every node reached its own.
- **The switches** are always two by two (one column below 720 px).
- **What happens** has fixed column widths (25/13/13/17/32 %), at least 1060 px (otp: 760 -
  too narrow for "ustoupí stranou"), scrolled sideways in its box below that; the tags never
  wrap. The lists' own column steadying is not used for it.
- **Who may**: a full administrator changes it; everybody else sees it disabled.

## 12. Tests

`test/test_split.py` (in one process, SQLite; the other node and the arbiter played by the
test - `split_step(store, now, peer=True|'words', arbiter=True|False|None)`): the decision of
every mode; "as until now" running nothing (the peer probe and the arbiter never called,
also by the watch's own thread; no row; no limit; nothing frozen or held; no alert; the lease
taken as before); one node / shared never apart; priority and arbiter stepping aside and back;
`maintenance_now()`; the lease let go; renewals, revocations and signing refused by hand;
acme's DNS server silent and back; half the tries (the routes ask the halved number); the
real dispatcher refusing changes on the other node and letting through sign-ins, the card, a
GET and maintenance; the report (done on both, a sign-in not a clash, rows gone, alert;
made only once the other node's row has come over, at the latest after 10 min; an earlier
short outage left out; the pooled connections closed); the hold on the question before a
code lifted by the watch in every mode; the preferred node's database refusing (PostgreSQL's
words, a bare refusal with and without its machine there, no answer, its maintenance, its
clock aside fresh and stale); /healthz told at once; an
app code let in unasked written down; the alert while apart; TCP / ping / the parser; the API
(view, save, refused saves, per-node arbiters, try and poll answered by the node's loop); the
settings not drawn as boxes; the card's pieces and the relay in the pages; the Czech texts.

## 13. For the administrator

**Which to choose**

- *As until now* (the default): nothing runs. Switching on *Warn while apart, report
  afterwards* and *Renewals only on the preferred node* is the gentlest step: both nodes
  still answer, you learn of a split, and no certificate is issued twice.
- *The node that still sees the network*: the usual choice when each node has a default
  gateway it reaches by the network, not by the other node. Add *Renewals only…* and *Half
  the tries* for the case where only the link between the nodes breaks.
- *Only the preferred node*: when two answering halves must never happen and a person is
  there to change it if the preferred node dies for long (the card can always be changed,
  even frozen).

**While apart** (the card says *apart now*, an alert came): look at the two tiles; mend the
link (PostgreSQL's port both ways); the nodes find each other within two seconds of the other
database answering, a node that stepped aside answers again by itself; read the report 30 s
or more later (once the other node's rows have come over).

**What it does not do**: tell "the link broke" from "the other node died" without an arbiter;
hold the VIP address on one node when VRRP cannot pass and both serve; protect a shared
database cluster (it needs none).
