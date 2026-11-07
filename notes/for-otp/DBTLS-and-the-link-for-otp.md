# The daemon's own database connection and the link between the databases: one certificate, renewed by itself? Two gaps found in acme 1.0.56, for otp

For the developers of **otp**: acme runs the same HA and database-TLS code. These are the
functions in acme's engine parts; otp's are expected to have the same names.

| acme | where |
|---|---|
| `hatls_*` (the link between the databases: the steps, renewal, the cluster's authority) | `280_the_link_between_the.py` |
| `dbtls_*` (Settings → The database → Encryption: the wizard, the rescue, the renewal of its own) | `325_something_asked_of_every.py` |
| root's side (`pgtls` asks: `server`, `server_off`, `hba_*`) | `deploy/acme_web.py` |

## The question

Settings → High availability → *The link between the two databases is encrypted and checked
(verify-full)*, and Settings → The database → *Every node reaches its database encrypted and
checked* ("the link's certificate"). Is it one certificate, and does the link's automatic renewal
keep the daemon's own connection working with no person involved?

## What works as designed (checked, nothing to port)

* **One certificate, one file of authorities.** With the link on (`ha_mode: replicated`,
  `ha_tls: verify-full`), `dbtls_apply` phase `server` is skipped ("its PostgreSQL has the
  certificate of the link between the databases, renewed with it"). The connect phase takes
  `db_tls_ca = HA_CA_FILE`, the same file the subscriptions use (`_dbtls_ca_for`, kinds
  `replicated` and `local`).
* **The names.** `hatls_names()` always has `localhost`, `127.0.0.1`, `::1` and the node's
  name beside its addresses. `hatls_san()` writes each address twice, as an IP SAN and as a DNS
  SAN, for libpq 13. So `verify-full` to `127.0.0.1` passes on every libpq.
* **The node's certificate renewal** (730 days, renewed 45 days before its end, `_hatls_tick`).
  The `server` step comes first: a new certificate and a PostgreSQL reload with no restart.
  libpq reads `sslrootcert` at each new connection, so the daemon's next connection checks the
  new certificate. The connections already open stay as they are.
* **The authority roll** (7300 days, a new one 730 days before its end). `hatls_ca_make` puts the
  new authority in front and keeps the old ones until they end. Root writes every authority
  still good into `HA_CA_FILE` (`trust`). During the roll, a certificate of either authority is
  trusted by both the daemon and the subscriptions. `hatls_check()` (every 10 min) puts back a
  `HA_CA_FILE` that lacks the newest authority.
* **The link switched off.** In `_hatls_off_tick` step `off_server`, the certificate stays when
  the daemon's own connection uses `HA_CA_FILE`, and a `dbtls:server:NODE` row is written. From
  then on Settings → The database renews it (`dbtls_tick`).

## Gap 1 — the rescue never goes back: the connection stays without TLS for good

**Symptom.** The daemon's connection to its own PostgreSQL stops because of its TLS: a
certificate run out, the authority file not yet rewritten, or a PostgreSQL put back from a
backup without its certificate. `_dbtls_rescue()` then moves it to no TLS. That is right: it
never leaves the machine, and acme goes on. An event of level *bad* says so. Then the link
repairs itself (`hatls_check` → its steps → a good certificate), and the connection **stays
without TLS until somebody runs the wizard again**. After a restart of the daemon, the page no
longer says that it was rescued either (`DBTLS_WORK['rescued']` is kept only in memory).

**Fix (acme 1.0.57).**
* The rescue keeps what it moved back from in a row of the node's own: `dbtls:rescued:NODE` =
  `{at, was, ca, why}`.
* `dbtls_tick` calls the new `_dbtls_again()`. Every 10 minutes it probes `(was, ca)` apart
  (`dbtls_probe`). Once that goes, it moves back with `dbtls_switch(daemon, was, ca, 'acme (it
  works with TLS again)')`. That is the same live move as the wizard's: tried apart first, put
  back at once if the first statement on it does not go. The info event says so.
* The row is dropped when `db_tls` was set by hand since (the wizard, or switched off on
  purpose), when the database is no longer `local` or `replicated`, and by every successful
  `dbtls_switch`.
* `dbtls_publish` reads the row when memory has nothing, so the page still says "rescued" after
  a restart.

```python
def _dbtls_again(daemon):
    store = daemon.store
    k = 'dbtls:rescued:' + node_name()
    r = _meta_obj(store, k)
    if not r:
        return
    if CONFIG.get('db_tls') or not r.get('was') or dbtls_kind() not in ('local', 'replicated'):
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))     # set by hand since: as it is
        return
    now = time.time()
    if now - float(r.get('tried') or r.get('at') or 0) < DBTLS_AGAIN_S:      # 600
        return
    r['tried'] = now
    store.set_meta(k, json.dumps(r))
    if not dbtls_probe(r['was'], str(r.get('ca') or ''))['ok']:
        return
    try:
        dbtls_switch(daemon, r['was'], str(r.get('ca') or ''), 'acme (it works with TLS again)')
    except ValueError as e:
        log_sparing('dbtls-again', '... going back to TLS did not go: %s' % e, 'warn', every=3600)
```

Under high security, the rescue does not move the connection at all (`hisec_enforced('db:tls')`),
so there is nothing to go back from.

## Gap 2 — two renewals of the one certificate at the same moment

**Symptom and scenario.** The database's TLS was set up on a node **before** the link's TLS. The
wizard's `server` phase wrote `dbtls:server:NODE` with that certificate's end. Later the link's
TLS is switched on: from then on the link gives PostgreSQL its certificate. Nothing drops the old
`dbtls:server` row, whose `cert_end` is now long in the past. `dbtls_tick` skips its own renewal
only while `_dbtls_link_has()`, i.e. while the link's step is `done`. Every time the link renews
(steps `names` → `server` → `link` → `hba`, minutes to hours when the other node is away),
`dbtls_tick` therefore sees "its own certificate ends soon". It starts `_dbtls_server_cert`
**at the same time**, with `hatls_names()` only: no `peer_host` and no `peer_lacks` of the
link's list. Root gets two `server` asks, and the last one wins. When the database's one wins,
the link's next `hatls_check` finds a name missing and makes the certificate again. That is a
needless round, and an event *warn* "put right by itself" on each renewal.

**Fix (acme 1.0.57).** `dbtls_tick` also stays out while the link is **set** on, not only while
it is `done`:

```python
def _dbtls_link_on(store):
    return CONFIG.get('ha_mode') == 'replicated' and CONFIG.get('ha_tls') == 'verify-full' and \
        not (hatls_want(store) or {}).get('off')

# in dbtls_tick:
if not srv or _dbtls_link_has(daemon.store) or _dbtls_link_on(daemon.store):
    return
```

When the link goes off, `ha_tls` is cleared in step `off_link`, before `off_server` writes the
`dbtls:server` row. So the database's renewal takes over exactly when the link stops renewing.

## How to test

`test/test_dbtls_auto.py` in acme (pure Python, `dbtls_probe`, `dbtls_switch` and
`_dbtls_server_cert` replaced by fakes):

* a rescued connection is not moved while the probe fails, nor twice within 10 minutes, and is
  moved back once the probe goes;
* a rescued row is dropped, with no move, when `db_tls` was set by hand since;
* with the link set on, an old `dbtls:server` row does not renew; with the link off, it does;
* the rescue's row is written and read back for the page.

By hand on a pair:
* Gap 1: stop the link's renewal and move `HA_CA_FILE` aside. The daemon's connection is
  rescued (a *bad* event). Put the file back: within about 10 minutes the event says "acme (it
  works with TLS again): the connection of NODE to its database is encrypted".
* Gap 2: set the database's TLS first, then the link's TLS, then force a renewal of the link
  (`hatls:node:NODE` `cert_end` near). Only the link's steps give PostgreSQL its certificate.
