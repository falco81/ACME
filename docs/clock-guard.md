# The clocks and the health of the nodes - gray failures (1.0.21)

## Shrnutí česky

**Šedé selhání** je uzel, který běží, odpovídá okamžitě - a špatně. Když jdou uzlu
**hodiny špatně** (nedostupné časové servery, hypervizor, který hodiny přepisuje, zastavený
chronyd, `date -s` zapomenuté po ladění), odmítá správné kódy druhého kroku přihlášení
(aplikace, `admin_2fa` - administrace i portál), jeho heartbeat i jeho vedení obnov (lease)
vypadají na druhém uzlu mrtvé nebo věčně živé, pauzy po špatných pokusech jsou posunuté - a
uzel přitom dál drží VIP adresu, takže nikoho na druhý uzel nepošle. Uzel, který **nedosáhne
na adresář**, odmítá stejně každé heslo.

Na kartě **Nastavení → Čas → Hodiny uzlů** (stejná karta jako v otp 1.0.222):

- **Jako dosud: nic se nesleduje** (výchozí) - nic z toho neběží: žádný SNTP dotaz, žádné
  měření, žádný řádek, žádné upozornění, kódy, pauzy i heartbeaty jako dřív.
- **Měřit a varovat** - každý uzel se sám ptá referenčních časových serverů (SNTP, každých
  30 s; vlastní, nebo časové servery této stránky) a měří hodiny druhého uzlu přes jeho
  databázi (každých 5 s); ukáže to a upozorní.
- **Ustoupit stranou, když není v pořádku** - a navíc uzel, jehož hodiny jdou víc než o limit,
  ustoupí stranou (stejně jako u split brain: nevede, DNS server acme mlčí, VIP adresa a
  /healthz odejdou na druhý uzel, stránky zůstanou) - jen dokud je druhý uzel v pořádku,
  nikdy oba.

Přepínače: **Kódy podle opraveného času**, **Heartbeaty podle změřeného rozdílu** (i lease
obnov), **Pauzy a zámky podle opraveného času**, **Ustoupit stranou, když není dosažitelný
adresář** (adresář administrátorů a portálu). Ukládá se lištou dole; *Ustoupit stranou* jde
uložit jen po **Vyzkoušet ze všech uzlů**.

---

## 1. What it is about

A failure that stops a node is easy: the other node takes the VIP address and the work. A
**gray failure** is a node that is up and answers wrongly - nothing in the cluster notices.

- **The clock.** A code of the second step from an app (TOTP, RFC 6238) is worked out from the
  time; acme accepts its step and `totp_window` either side. A clock off by more than about
  30-45 s refuses every right code. And: the heartbeats (`node:<name>` = `{at}`) and the lead's
  lease (`certs:leader` = `{node, until}`) are judged by `now - at` on the other node - a node
  10 min behind looks dead, one ahead lives for ever; the pauses after wrong passwords and
  codes are timed with the clock.
- **The directory.** A node that cannot reach the directory the administrators (or the
  portal's people) sign in against refuses every password.

## 2. Settings

| Setting | Values | Default | |
|---|---|---|---|
| `clock_mode` | off / watch / guard | off | as until now / measure and warn / step aside when not well |
| `clock_warn_s` | 1-60 | 2 | off by more: an alert (warn), the correction applies |
| `clock_aside_s` | 5-600 | 20 | off by more: alert bad, guard steps aside; more than `clock_warn_s` (refused otherwise - the card, the API, `acme --set`) |
| `clock_ref` (per node, `clock_ref@<node>`) | up to five `name`, `name:port`, `[v6]:port` | empty | empty: the time servers of Settings → Time (`ntp:conf`) |
| `clock_codes` | 0/1 | 0 | the second step's codes by the corrected time |
| `clock_beat` | 0/1 | 0 | the other node's heartbeat and lease by the measured difference |
| `clock_locks` | 0/1 | 0 | the pauses after wrong passwords and codes by the corrected time |
| `health_dir` | 0/1 | 0 | guard: step aside when the directory cannot be reached and the other node reaches it |

The switches act only with watch or guard. On the Time pane (`PANES['time']`), drawn only by
the card (`CARD_DRAWN` - never as boxes of a pane).

## 3. Measuring

- **The reference** (`sntp_offset`, `clock_ref_check`): a plain SNTP client (RFC 4330) - one
  UDP packet of 48 bytes, LI 0, VN 4, mode 3, our transmit time in bytes 40-47; the answer must
  echo it as its originate time (bytes 24-31), be mode 4 or 5 and stratum 1-15 (0 - kiss of
  death, unsynchronised - is not believed). `offset = ((t1 - t0) + (t2 - t3)) / 2` (> 0: this
  clock is behind), `delay = (t3 - t0) - (t2 - t1)`; 1.5 s a server, asked again once when lost;
  the **median** of those that answered. Every 30 s; a round with no answer keeps the last
  measurement until it is 4 min old (on the monotonic clock), dropped at once when the
  machine's clock was stepped since. None given, none answering: no reference - never judged,
  only warned of.
- **The other node** (`clock_peer_skew`): replicated - the other node's own PostgreSQL
  (`ha_peer_conf`), `SELECT extract(epoch from clock_timestamp())`; one shared PostgreSQL or
  MariaDB server (`UNIX_TIMESTAMP(NOW(6))` in UTC) - each node against the server, the other's
  minus this one's is the difference of the two rows. The shortest of three round trips, in a
  helper thread joined for 3.5 s. Every 5 s.
- **The directory** (`clock_dir_check`, with `health_dir` only, every 15 s): `admin_directory`
  and (with the portal on) `portal_directory`, each reached on one of its servers as the
  sign-ins reach it - connected, TLS made, the reading account let in, 3 s a server; nobody's
  password is sent.
- **The state row** `clock:state:<node>` every 10 s (and on a change of role): ref, refs,
  skew, skew_of, dir_ok, dirs, role, why, codes_fixed, correction. The other node judges it
  fresh by its age corrected by the measured skew (younger than 25 s, its heartbeat alive).

## 4. The decision

`clock_decide(mode, ref, aside_s, codes_fixed, dir_ok, health_dir, peer, aside_now, back_s,
peer_newer)` - pure, tested row by row:

| This node | The other node | Result |
|---|---|---|
| clock within `aside_s` | anything | serve |
| clock off, `clock_codes` on | anything | serve (its codes are right) |
| clock off | well, its clock right | **aside** |
| clock off | its clock off too / not fresh / aside itself / in maintenance / no reference | serve |
| no reference | anything | serve |
| aside, back within `aside_s - warn_s` | anything | serve (hysteresis) |
| clock off, the other's word older than this node's own | well | serve until it measured again |
| directory not reached, `health_dir` | well, reaches it | **aside** |
| directory not reached | does not reach it either / no `health_dir` | serve |

Never both: each steps aside only for the other being better. Every 5 s; each change of role
an event (kind *time*) and a log line.

## 5. Stepping aside

Through the one gate (`maintenance_now()`, after the split's own): `{'on': True, 'why':
'stepped aside: …', 'clock': True}` - the renewer lets its lead go (no renewals, deployments,
CRLs, signing), acme's DNS server stops answering, the VIP check says "in maintenance" (the
address moves) and `/healthz` says maintenance - at once (the maintenance cache, `/healthz`'s
second of cache and the renewer told on the change, no "draining"). The pages stay.
Switched off while aside: the daemon's loop puts it back at once, nothing measured kept.

The split card (docs/split-brain.md 6.1) reads it too: with *Only the preferred node*, a
preferred node aside for its clock (its row younger than 32 s) lets the other go on.

What otp 1.0.223 adds and acme does not: *a single sign-in that meets the directory
unreachable left unanswered* - a VPN asks its other RADIUS server on no answer; a browser does
not, so acme answers it as before (and the node steps aside at the next check).

## 6. The corrected time and the measured difference

- `clock_now('codes')` - the administrators' and the portal's second step (`totp_match` in
  `_mfa_act`, enrolment and check): `time.time() + correction` with `clock_codes`, the
  correction being the reference's offset when known, fresh and larger than `clock_warn_s`.
  The "used once" step is kept in steps of the corrected time: both nodes agree on them.
- `clock_now('locks')` - the `t` of `ApiHandler.throttle` (administration, portal, codes) and
  of the lockout list.
- `clock_their_time(store, node, at)` - another node's heartbeat (`ha_nodes`) and the lead's
  lease (`renewer.lease_tick`, `renewer.leader`) in this node's time, with `clock_beat`.

## 7. Alerts (pane *time*), only with the mode not off

| Key | Level | When |
|---|---|---|
| `clock:aside:<node>` | bad | stepped aside (why) |
| `clock:ref:<node>` | warn | no reference server answered |
| `clock:skew:<node>` | warn / bad past `clock_aside_s` | off the reference by more than `clock_warn_s`, whether the codes are corrected |
| `clock:peer:<node>` | warn | the two nodes' clocks differ by more than `clock_warn_s` |
| `clock:dir:<node>` | bad | with `health_dir`: the directory not reached |

## 8. API

`GET /api/clock` (full administrator): `{engaged, ha_mode, cluster, conf, me, nodes: [{name,
me, alive, fresh, ref, state}], common}`. `POST /api/clock`: `save` (`conf`, `refs` {node:
servers}, `checked`; 400 a bad value, a node that is not, a bad server, `clock_aside_s <=
clock_warn_s`; 409 guard without `checked: true`), `try` (`refs` - every node asks its own
reference, the other side's clock and its directory: `node_ask 'clock_try'`), `poll` (`id`).
The pages' relay passes `clock` on (reads and writes).

## 9. The card

Settings → Time, below the tiles of chrony, the time sources and the time servers: the split
card's look (`split-*` classes): the tiles of now with the link between them, the three modes
as cards, the said line, the two numbers (the second outlined red when not more than the
first), the reference box with *Try it from every node*, the four switches two by two (one
column under 720 px), the table *What happens - with the choices above* of fixed widths
(`listTable(…, {free: true})`). Every choice waits for the save bar; a redraw keeps the page
where it was.

## 10. Tests

`test/test_clock.py` (one process, SQLite, a fake SNTP server on localhost, a mock LDAP
server): SNTP (right, 300 s ahead, stratum 0, silent, a forged answer, the median of three,
asked again once); the reference servers; every row of the decision and "never both"; as
until now (no SNTP packet, no database question, no directory, no thread, no row, no alert,
the codes, the pauses, the heartbeats and the lease as before); watch (measured, written,
alerts in English and Czech, nothing corrected); the second step's code through the real
route, refused 300 s off without `clock_codes`, let in with it, the machine's own wrong code
refused, no correction within the warning or from an old measurement or after a step of the
clock; the pauses; the heartbeats (behind, ahead, one shared database server) and the lease;
guard (aside, `maintenance_now`, alert, event, back when the other goes quiet or the clock is
mended, never with `clock_codes`, the other's row fresh by the skew, one node never); the
directory; switched off while aside; the watch's thread; the API; the card's pieces, the
relay and the Czech texts. `test/test_split.py` covers the preferred node aside for its clock.

## 11. For the administrator

- *As until now* - nothing of this runs; the tiles above the card still show chrony.
- *Measure and warn* - the gentlest step, and the one for a single node; add *Codes by the
  corrected time* there (nothing can step aside).
- *Step aside when not well* - for a pair. Add *Step aside when the directory cannot be
  reached* when the two nodes reach the directory by different ways.
- *Heartbeats…* and *Pauses…* change nothing while the clocks are right.

Before guard: *Try it from every node* - each node must reach its reference (UDP 123 out);
give each node an NTP server inside the network as *Reference of <node>* where the internet's
are blocked. When a node is off: its tile says *behind by 312 s*; look at chrony's tile above
(synchronised? which sources?), *Step it now* (chronyc makestep) puts it right; a node that
stepped aside answers again by itself.

What it does not do: put the clock right (chrony's job - the correction is applied to the
codes, pauses and judging of the other node only); judge a node whose reference cannot be
asked; help when both clocks are equally wrong and the codes are not corrected.
