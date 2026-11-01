# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Two servers, both answering: high availability, active/active (1.0.13)
# ---------------------------------------------------------------------------
# Both nodes open the same PostgreSQL and keep nothing that matters anywhere
# else, so that a load balancer may send any request - a page, the second
# half of a sign-in - to either, round robin and without stickiness:
#
#   * every setting, account, directory and certificate is in the database,
#     and a node that sees another node's change (`conf_serial`) reads it in
#     within five seconds;
#   * a sign-in is a row in the database, and so is what belongs to it (the
#     "Edit the columns" switch); a job's progress (a move, an erase) is in
#     the database too, so the bar keeps moving whichever node is asked;
#   * an administrator's code from the app is used up with a row of its own
#     in used_once that nothing ever writes over (1.0.101). With two
#     replicating databases (ha_mode "replicated") a node also looks in the
#     other node's database before it takes a code - so the same code sent to
#     both nodes at the same moment is taken once, not once on each. Only
#     while the other node's database cannot be reached at all is a code
#     checked against this node's rows alone (said in the log);
#   * the nightly dump is claimed by one node, with one conditional UPDATE -
#     and so is whatever only one node is to do (ha_lead, claim_once);
#   * the key that seals the secrets is the same file on both, carried to the
#     second node once in a bundle locked with a passphrase.
#
# Each node writes a heartbeat into the database every fifteen seconds; the
# pages show the nodes and how long since each was heard from.

HA_KIND = 'acme-ha-join'
HA_STORE = {'store': None}
HEARTBEAT_S = 15
# One subscription of this database by its name (1.0.170): pg_subscription is
# the whole server's catalog - a second database on the same PostgreSQL (or one
# left from before) has subscriptions of the same names, and they were taken
# for this one's: ALTER SUBSCRIPTION ... does not exist.
SUB_HERE_SQL = ('SELECT 1 FROM pg_subscription WHERE subdbid = (SELECT oid FROM pg_database '
                'WHERE datname = current_database()) AND subname = ?')


def node_name():
    return this_node_name()


def node_address():
    """The address this machine uses to reach the outside - what a peer would
    use to reach it."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('192.0.2.1', 9))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return ''


# Set while this node is rebuilt from the other (1.0.44): it answers nothing
# and writes nothing until every row has come over.
HA_REBUILDING = threading.Event()
HA_REBUILD_LOCK = 7_011_959     # pg advisory lock: one rebuild in the cluster (1.0.59)
HA_REBUILDER = [None]          # the thread that rebuilds; the only one that writes meanwhile


FW_NOW_SENT = {}


def fw_now_publish(store, asked=False):
    """This node's whole firewall into its row for the other node's pages
    (1.0.71): when root read it again, and every 10 minutes all the same -
    a row lost on the way (a rebuild, a restore) was never written again.
    The other node's page may ask for it to be read again: 'fw:ask:<node>'."""
    me = node_name()
    try:
        ask = float(store.get_meta('fw:ask:' + me) or 0)
    except (TypeError, ValueError):
        ask = 0
    if ask and ask > FW_NOW_SENT.get('asked', 0):
        FW_NOW_SENT['asked'] = ask
        fw_now_ask(wait=0)              # root reads it within a second or two
    got = fw_now_read()
    at = got.get('full_at')
    if not at:
        return
    if FW_NOW_SENT.get('at') == at and time.time() - FW_NOW_SENT.get('when', 0) < 600:
        return
    store.set_meta('fw:now:' + me, json.dumps({'full': got.get('full') or {}, 'full_at': at}))
    FW_NOW_SENT.update(at=at, when=time.time())


def heartbeat(store, daemon=None):
    if HA_REBUILDING.is_set():
        return {}                       # nothing written while the rows come over (1.0.44)
    beat = {'at': time.time(), 'version': __version__, 'address': node_address(),
            'host': socket.gethostname(), 'started': daemon.started if daemon else None,
            'engine': store.db.engine,
            'maintenance': bool(maintenance_now(store).get('on')),
            # What its own settings are in effect (1.0.67), its config.json's
            # among them, for the other node's pages to show as they are.
            'own': {k: (CONFIG.get(k) if not isinstance(CONFIG.get(k), bytes) else '')
                    for k in NODE_KEYS},
            'own_file': sorted(k for k in NODE_KEYS if k in (FILE_KEYS or ()))}
    try:
        beat['software'] = software_info(store)  # for the other node's About (1.0.99)
    except Exception:                                   # noqa: BLE001
        pass
    try:
        beat['web'] = web_state(store)          # TLS and the VIP address (1.0.47)
        # The whole firewall goes in a row of its own, when it changed
        # (1.0.67) - not into a heartbeat written every 15 s.
        for k in ('full', 'full_at', 'full_backend'):
            (beat['web'].get('fw') or {}).pop(k, None)
        fw_now_publish(store)
    except Exception:                                   # noqa: BLE001
        pass
    beat['mid'] = machine_id()
    name_clash_check(store, beat)
    store.set_meta('node:' + node_name(), json.dumps(beat))
    return beat


# Two machines with one name (1.0.110): both wrote the same heartbeat row, so
# the other looked gone and the VIP address "on both". Each row now carries
# the machine it came from; a row from another machine, fresh, under this
# node's name is said loudly - in the log, on every page and in --ha-status.
NAME_CLASH = {}
NAME_CLASH_SEEN = []


def machine_id():
    """This installation: the machine's id, its host name and where its state
    is - a VM cloned with its machine-id still tells itself apart by its
    host name."""
    got = ''
    for f in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            got = Path(f).read_text().strip()
        except OSError:
            continue
        if got:
            break
    return hashlib.sha256(('%s|%s|%s' % (got, socket.gethostname(), STATE_DIR)).encode()
                          ).hexdigest()[:24]


def name_clash_check(store, beat):
    try:
        was = json.loads(store.get_meta('node:' + node_name()) or '{}')
    except ValueError:
        was = {}
    now = time.time()
    other = was.get('mid')
    if other and other != beat['mid'] and now - float(was.get('at') or 0) < HEARTBEAT_S * 3:
        # Seen twice before it is said: once is this machine's own row from
        # before a new host name, overwritten by the beat after this one.
        NAME_CLASH_SEEN.append(now)
        del NAME_CLASH_SEEN[:-2]
        if len(NAME_CLASH_SEEN) < 2:
            return
        first = not NAME_CLASH
        NAME_CLASH.update(name=node_name(), address=was.get('address') or '?',
                          host=was.get('host') or '?', at=now)
        if first or now - NAME_CLASH.get('said', 0) > 600:
            NAME_CLASH['said'] = now
            log('two machines call themselves %s: this one (%s, %s) and %s (%s) - give '
                'one of them its own name: acme --set node_name=NAME on it, then systemctl '
                'restart acme (docs/renaming-and-readdressing.md)'
                % (node_name(), beat.get('address'), beat.get('host'), NAME_CLASH['address'],
                   NAME_CLASH['host']), 'error')
    elif now - (NAME_CLASH_SEEN or [0])[-1] > HEARTBEAT_S * 4:
        NAME_CLASH.clear()
        del NAME_CLASH_SEEN[:]


def name_clash_words():
    if not NAME_CLASH or NAME_CLASH.get('name') != node_name():
        return ''
    return ('two machines call themselves %s: this one and %s (%s) - each node needs a name '
            'of its own (acme --set node_name=NAME on one of them, then systemctl restart acme)'
            % (NAME_CLASH['name'], NAME_CLASH['address'], NAME_CLASH['host']))


def node_name_taken(store, want):
    """Another machine, answering now, already called want? (1.0.110)"""
    want = str(want or '').strip()
    if not want or want == node_name():
        return None
    mine = machine_id()
    for n in ha_nodes(store):
        if n['name'] == want and n.get('alive') and n.get('mid', '') != mine:
            return n
    return None


def ha_nodes(store):
    out = []
    try:
        rows = store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'node:%'")
    except Exception:                                   # noqa: BLE001
        rows = []
    now = time.time()
    for r in rows:
        try:
            beat = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        name = r['k'][5:]
        age = now - float(beat.get('at') or 0)
        beat.update(name=name, age=age, me=name == node_name(),
                    alive=age < HEARTBEAT_S * 3)
        out.append(beat)
    out.sort(key=lambda b: (not b['me'], b['name']))
    return out


def ha_forget(store, name):
    if name == node_name():
        raise ValueError('this is the node answering: it would write itself back at once')
    store.db.run('DELETE FROM meta WHERE k = ?', ('node:' + name,))


def ha_lead(store):
    """Whether this node is the one of a replicated pair that does what one
    node does for both (1.0.147): the first by name of the nodes heard from,
    this one when it hears no other."""
    if CONFIG.get('ha_mode') != 'replicated':
        return True
    return lead_of(store)


LEAD_FAR = {}
LEAD_FAR_LOCK = threading.Lock()


def _alive_far(name):
    """A node whose heartbeat looks stale here, asked in its own database
    (1.0.207): with one way of the replication stopped (an error, a paused
    subscription, the rolling upgrade) the network is fine - the node that
    got nothing took the lead, and the other kept it too. Asked every 15 s
    while it answers, every 60 s while it does not; one asks at a time."""
    if CONFIG.get('ha_mode') != 'replicated':
        return False
    was = LEAD_FAR.get(name)
    if was and time.monotonic() - was[0] < (15 if was[1] else 60):
        return was[1]
    if not LEAD_FAR_LOCK.acquire(blocking=False):
        return bool(was and was[1])
    try:
        alive = bool(_peer_alive_there(name))
    except Exception:                                   # noqa: BLE001
        alive = False
    finally:
        LEAD_FAR_LOCK.release()
    LEAD_FAR[name] = (time.monotonic(), alive)
    return alive


def lead_of(store):
    """The first by name of the nodes heard from - this one when it hears no
    other. A node that sorts before this one and only looks stale here is
    asked in its own database first."""
    me = node_name()
    alive = sorted(n['name'] for n in ha_nodes(store)
                   if n.get('alive') or n.get('me') or (n['name'] < me and _alive_far(n['name'])))
    return not alive or alive[0] == me


def claim_once(store, key, value):
    """True for exactly one node: the one whose conditional UPDATE changed the
    row. A key not there yet is made first; two nodes making it at the same
    moment cannot both insert it (it is the primary key).

    Two replicated databases are two tables, though: each node's INSERT went
    in, and replication then stopped on the other's for good; each UPDATE
    took the day too. A key of both nodes (not one of this node's own,
    'NAME:NODE') is claimed by one node alone since 1.0.147 - see ha_lead -
    so only that one ever writes its row."""
    if CONFIG.get('ha_mode') == 'replicated' and not key.endswith(':' + node_name()) and \
            not ha_lead(store):
        return False
    if store.get_meta(key) is None:
        try:
            store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (key, ''))
        except Exception:                               # noqa: BLE001
            pass
    return bool(store.db.run('UPDATE meta SET v = ? WHERE k = ? AND (v IS NULL OR v <> ?)',
                             (str(value), key, str(value))))


def sub_connection_set(store, sub, conninfo):
    """ALTER SUBSCRIPTION ... CONNECTION, its password kept out of PostgreSQL's
    log (1.0.136) and the text as it is - a ? in a password was taken for a
    parameter (1.0.139). Raises ValueError, the password scrubbed."""
    for quiet in ("SET log_statement = 'none'", "SET log_min_error_statement = 'panic'"):
        try:
            store.db.run(quiet)
        except Exception:                               # noqa: BLE001
            pass
    try:
        store.db.run(RawSql("ALTER SUBSCRIPTION %s CONNECTION '%s'"
                            % (sub, conninfo.replace("'", "''"))))
    except Exception as e:                              # noqa: BLE001
        raise ValueError('the subscription %s could not be changed: %s'
                         % (sub, scrub_secret(str(e).split('\n')[0][:300])))
    finally:
        for back in ('RESET log_statement', 'RESET log_min_error_statement'):
            try:
                store.db.run(back)
            except Exception:                           # noqa: BLE001
                pass


# ---- a job's progress, where both nodes can read it ------------------------------
def job_publish(job):
    store = HA_STORE.get('store')
    if not store or HA_REBUILDING.is_set():
        return
    try:
        store.set_meta('db_job:' + node_name(), json.dumps(dict(job, node=node_name(),
                                                                at=time.time()),
                                                           default=str))
    except Exception:                                   # noqa: BLE001
        pass


def job_read():
    """The job as the database has it - this node's, or the other's."""
    if DB_JOB.get('running') or DB_JOB.get('ended'):
        here = dict(DB_JOB, node=node_name())
    else:
        here = None
    store = HA_STORE.get('store')
    there = None
    if store:
        try:
            for r in store.db.rows("SELECT v FROM meta WHERE k LIKE 'db!_job:%' ESCAPE '!'"):
                one = json.loads(r['v'] or 'null')
                # Going on, by the word of a node that has not said so for
                # five minutes - or of this node, which is not running it:
                # it ended with the process that ran it (1.0.37).
                if one and one.get('running') and (
                        time.time() - float(one.get('at') or one.get('began') or 0) > 300 or
                        (one.get('node') == node_name() and not DB_JOB.get('running'))):
                    one = dict(one, running=False, ended=float(one.get('at') or 0),
                               error=one.get('error') or 'it stopped with the service that '
                               'ran it (restarted, or the database was changed)')
                if one and (not there or float(one.get('began') or 0) >
                            float(there.get('began') or 0)):
                    there = one
        except Exception:                               # noqa: BLE001
            there = None
    if here and (not there or float(here.get('began') or 0) >= float(there.get('began') or 0)):
        return here
    return there or dict(DB_JOB)


# ---- the bundle that carries a cluster to its second node --------------------------
def _bundle_key(passphrase, salt):
    return hashlib.scrypt(str(passphrase).encode('utf-8'), salt=salt, n=2 ** 15, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)


def bundle_lock(data, passphrase, kind=None):
    salt = secrets.token_bytes(16)
    key = _bundle_key(passphrase, salt)
    raw = json.dumps(data).encode('utf-8')
    nonce = secrets.token_bytes(16)
    hide = hmac.new(key, b'hide', hashlib.sha256).digest()
    sign = hmac.new(key, b'sign', hashlib.sha256).digest()
    body = bytes(a ^ b for a, b in zip(raw, _seal_stream(hide, nonce, len(raw))))
    # Format 2 (1.0.101): what kind of bundle it is is signed too, so a
    # locked export cannot be handed in as a cluster's bundle, nor the
    # other way round.
    tag = hmac.new(sign, (kind or HA_KIND).encode('utf-8') + b'\n' + salt + nonce + body,
                   hashlib.sha256).digest()
    return {'kind': kind or HA_KIND, 'format': 2, 'made': time.time(), 'from': node_name(),
            'version': __version__,
            'locked': base64.b64encode(salt + nonce + body + tag).decode('ascii')}


def bundle_open(bundle, passphrase, kinds=None):
    if isinstance(bundle, str):
        try:
            bundle = json.loads(bundle)
        except ValueError:
            raise ValueError('that is not a bundle made by acme --ha-bundle: it is not JSON')
    if not isinstance(bundle, dict) or bundle.get('kind') not in (kinds or (HA_KIND, 'opt-ha-join')):
        raise ValueError('that is not a bundle made by acme --ha-bundle')
    try:
        raw = base64.b64decode(bundle.get('locked') or '')
    except (ValueError, TypeError):
        raise ValueError('the bundle is damaged')
    if len(raw) < 16 + 16 + 32:
        raise ValueError('the bundle is damaged')
    salt, nonce, body, tag = raw[:16], raw[16:32], raw[32:-32], raw[-32:]
    key = _bundle_key(passphrase, salt)
    sign = hmac.new(key, b'sign', hashlib.sha256).digest()
    signed = salt + nonce + body
    if int(bundle.get('format') or 1) >= 2:
        signed = str(bundle.get('kind')).encode('utf-8') + b'\n' + signed
    if not hmac.compare_digest(tag, hmac.new(sign, signed, hashlib.sha256).digest()):
        raise ValueError('the passphrase is not the one the bundle was locked with')
    hide = hmac.new(key, b'hide', hashlib.sha256).digest()
    data = json.loads(bytes(a ^ b for a, b in zip(body, _seal_stream(hide, nonce, len(body))))
                      .decode('utf-8'))
    data['_from'] = bundle.get('from')
    data['_made'] = bundle.get('made')
    return data


def ha_passphrase():
    words = 'abcdefghijkmnopqrstuvwxyz23456789'
    return '-'.join(''.join(secrets.choice(words) for _ in range(5)) for _ in range(5))


def ha_checks(store):
    """What has to be true before a second node can join, each with its
    answer: the database, its address as the other node will see it, the
    key."""
    db = store.db
    host = str(CONFIG.get('db_host') or '')
    local = host in ('', 'localhost', '127.0.0.1', '::1')
    mode = CONFIG.get('ha_mode') or ''
    # Made here if the daemon never ran yet, as the replicated wizard does
    # (1.0.140): `acme --ha-setup --ha-shared` on a node whose daemon had not
    # started once stopped at "the key that seals the secrets is missing".
    if db.engine == 'postgres':
        try:
            sealing_key(make=True)
        except OSError:
            pass
    out = [
        {'key': 'engine', 'ok': db.engine == 'postgres',
         'says': 'the database is PostgreSQL' if db.engine == 'postgres' else
         'the database is %s: a cluster needs PostgreSQL, which both nodes open - move to it '
         'first (Settings → The database)' % ENGINE_WORDS.get(db.engine, db.engine)},
        {'key': 'key', 'ok': bool(sealing_key()),
         'says': 'the key that seals the secrets is there' if sealing_key() else
         'the key that seals the secrets is missing'},
    ]
    if mode == 'replicated' and db.engine == 'postgres':
        # Made two already (1.0.43): each node has its own PostgreSQL here,
        # and the other node never opens it - nothing to warn of.
        out.append({'key': 'address', 'ok': True,
                    'says': 'this node is one of two already: each has its own PostgreSQL '
                            'and they replicate to each other'})
        return out
    out += [
        {'key': 'address', 'ok': not local or db.engine != 'postgres',
         'warn': local and db.engine == 'postgres',
         'says': ('PostgreSQL is reached at %s, which the other node can use as well' % host)
         if not local else ('PostgreSQL is on this machine (%s): the other node reaches it at '
                            'this machine\'s address - it has to listen there and let the other '
                            'node in (acme --ha-setup does both, as root)' % (host or 'localhost'))},
    ]
    return out


def ha_bundle_data(store, peer_db_host='', with_tls=None):
    """What the second node needs and nothing else: how to open the
    database, the key that opens the sealed secrets, and the name of the
    cluster."""
    if store.db.engine != 'postgres':
        raise ValueError('a cluster needs PostgreSQL: move to it first (Settings → The database)')
    key = sealing_key(make=True)
    if not key:
        raise ValueError('the key that seals the secrets is missing')
    db = {k: CONFIG.get(k) for k in DB_KEYS}
    host = str(db.get('db_host') or '')
    if peer_db_host:
        db['db_host'] = peer_db_host
    elif host in ('', 'localhost', '127.0.0.1', '::1'):
        db['db_host'] = node_address()
    data = {'db': db, 'key': key.hex(), 'cluster': CONFIG.get('site_name') or 'acme',
            'mode': 'shared', 'peer': {'name': node_name(), 'address': node_address()}}
    if with_tls:
        data['tls'] = with_tls
    # This node is one of two on this database from now on (ha_mode "shared"):
    # nothing set it before, so a shared pair ran as two single servers - the
    # VIP address never watched, the firewall not opened to the other node, a
    # Back up now never asked of it.
    if not CONFIG.get('ha_mode'):
        write_file_settings({'ha_mode': 'shared'})
        CONFIG['ha_mode'] = FILE_CONFIG['ha_mode'] = 'shared'
    return data


def ha_replicated_bundle_data(store):
    """The bundle of a node already replicating: for the other one, made
    again after it was lost or reinstalled - its slot the other one's, and
    nothing on this node changed (1.0.207: the command line made this node
    the first one again, slot 1, and restarted it)."""
    me = int(CONFIG.get('ha_slot') or 1)
    data = {'mode': 'replicated', 'key': sealing_key(make=True).hex(),
            'pg_major': int(store.db.value('SHOW server_version_num')) // 10000,
            'slot': 3 - me,
            'db': {'db_name': CONFIG.get('db_name'), 'db_user': CONFIG.get('db_user'),
                   'db_password': CONFIG.get('db_password')},
            'peer': {'name': node_name(), 'slot': me,
                     'address': CONFIG.get('ha_address') or node_address(),
                     'port': int(CONFIG.get('db_port') or 5432)},
            'cluster': CONFIG.get('site_name') or 'acme'}
    data['db']['db_host'] = data['peer']['address']
    return data


def ha_join(data, name='', even_if_data=False, by='', say=None, root_now=False):
    """This node into the cluster: the database's address into config.json and
    the key beside it. The daemon starts again on it afterwards. Before the
    database is tried, this node's firewall lets the first node in (1.0.210)."""
    say = say or (lambda step, ok, words: None)
    db = data.get('db') or {}
    if db.get('db_engine') != 'postgres':
        raise ValueError('the bundle does not name a PostgreSQL')
    # Every value checked as the settings are (1.0.57) before it goes into
    # config.json: they reach command lines, option files and pg_hba.conf.
    try:
        db = {k: check_setting(k, v) for k, v in db.items() if k in DB_KEYS}
        if name:
            name = check_setting('node_name', name)
    except BadSetting as e:
        raise ValueError('the bundle or the name will not do: %s' % e)
    key_hex = str(data.get('key') or '')
    if not re.match(r'^[0-9a-f]{64}\Z', key_hex):
        raise ValueError('the bundle holds no key')
    fw = ha_join_open(HA_STORE.get('store'), data, by, root_now)
    say('firewall', fw['state'] in ('done', 'off'), fw['said'])
    got = db_try(db)
    if not got.get('reached'):
        why = db_trouble(got.get('trouble') or '', db, fw)
        say('db', False, why['says'])
        raise ValueError('the database in the bundle cannot be reached from here: %s - %s'
                         % (why['says'], why['fix']))
    say('db', True, 'the database answers: %s, %s record(s)' % (db_where(db), got.get('rows')))
    now = sealing_key()
    if now and now.hex() != key_hex and not even_if_data:
        # This node has a key of its own: whatever it sealed would be lost.
        store = HA_STORE.get('store')
        mine = False
        if store and store.db.engine == 'sqlite':
            try:
                mine = sealed_held(store.db)
            except Exception:                           # noqa: BLE001
                mine = False
        if mine:
            raise ValueError('this node holds secrets of its own (private keys, passwords), '
                             'sealed with another key; joining replaces both its database and '
                             'its key. Say so to go on (--discard-local, or tick it on the page)')
    if now and now.hex() != key_hex:
        backup = sealing_key_path().with_name('secrets.key.before-join')
        write_replacing(backup, now.hex() + '\n', 0o600)
    write_replacing(sealing_key_path(), key_hex + '\n', 0o600)
    changes = {k: db.get(k) for k in DB_KEYS if k in db}
    # One of two on one database (ha_mode "shared"): it was never written, and
    # the second node ran as a server alone on the cluster's database.
    # The first node by its address (1.0.210): ha_peer was written empty, so
    # this node never knew it - the firewall's item for the other node and
    # the VIP address waited for its heartbeat.
    peer = str((data.get('peer') or {}).get('address') or '')
    try:
        peer = str(plain_ip(peer, 'address')) if peer else ''
    except ValueError:
        peer = ''
    changes.update(ha_mode='shared', ha_slot=0, ha_peer=peer,
                   ha_address=CONFIG.get('ha_address') or node_address())
    if name:
        changes['node_name'] = name
    write_file_settings(changes)
    say('key', True, 'the key that opens the sealed secrets is the cluster\'s now')
    return {'where': db_where(db), 'rows': got.get('rows'), 'peer': data.get('peer') or {},
            'message': 'this node joins the cluster: it starts again on %s' % db_where(db)}


def ha_bundle_about(data):
    """What the bundle is, outside its lock (1.0.210): for the page that is
    given the file to show before the passphrase is typed - the cluster, the
    first node and the database's address; never the key, never a password."""
    db = data.get('db') or {}
    peer = data.get('peer') or {}
    return {'cluster': str(data.get('cluster') or ''), 'mode': data.get('mode') or 'shared',
            'node': str(peer.get('name') or ''), 'address': str(peer.get('address') or ''),
            'db': '%s:%s/%s' % (db.get('db_host') or peer.get('address') or '',
                                db.get('db_port') or peer.get('port') or 5432,
                                db.get('db_name') or ''),
            'joining': str(data.get('joining') or '')}


def ha_bundle_view(data):
    """An opened bundle as the pages may show it: what it says, never the
    key nor the password."""
    out = ha_bundle_about(data)
    db = data.get('db') or {}
    out.update(made=data.get('_made'), made_by=data.get('_from') or '',
               db_user=str(db.get('db_user') or ''), has_key=bool(data.get('key')),
               tls=bool(data.get('tls')))
    return out


def ha_join_open(store, data, by='', root_now=False):
    """The first node let into this one's firewall before its database is
    tried (1.0.210): its address and the database's, from the bundle, as a
    node being joined - at once, waited for until the root helper put it in."""
    if store is None:
        return {'state': 'off', 'said': 'the firewall was not looked at (no database here)'}
    db = data.get('db') or {}
    want = []
    for a in ((data.get('peer') or {}).get('address'), db.get('db_host')):
        a = str(a or '').strip()
        if a and a not in ('localhost', '127.0.0.1', '::1') and not a.startswith('/') \
                and a not in want:
            want.append(a)
    if not want:
        return {'state': 'off', 'said': 'the bundle names no address to let in'}
    got = []
    for a in want:
        try:
            got += ha_pending_add(store, a, by, 'the cluster being joined (%s)' % (
                (data.get('peer') or {}).get('name') or '?'))
        except ValueError as e:
            return {'state': 'failed', 'said': str(e)}
    out = fw_apply_wait(store, 60, run_helper=root_now)
    if out['state'] == 'done':
        out['said'] = 'this node lets %s in (PostgreSQL, the pages, the health check)' % \
            ', '.join(sorted(set(got)))
    out['addresses'] = sorted(set(got))
    return out


def db_trouble(trouble, db, fw=None):
    """Why a PostgreSQL could not be reached, in words that say what to do
    (1.0.210): {kind, says, fix}."""
    t = str(trouble or '')
    low = t.lower()
    host = str(db.get('db_host') or '')
    port = int(db.get('db_port') or 5432)
    where = '%s:%d' % (host, port)
    fw_open = (fw or {}).get('state') in ('done', 'off')
    if 'connection refused' in low:
        return {'kind': 'refused', 'says': 'PostgreSQL at %s refused the connection: it does not '
                'listen on that address (listen_addresses), or it is not running' % where,
                'fix': 'on the first node, press Make the bundle… again with this node\'s address '
                '(it prepares PostgreSQL: listen_addresses, pg_hba.conf, a restart) - or as root '
                'there:  acme --ha-setup --ha-shared --ha-peer THIS-NODE'}
    if 'timeout' in low or 'timed out' in low or 'no route to host' in low or \
            'network is unreachable' in low:
        return {'kind': 'timeout', 'says': 'PostgreSQL at %s did not answer at all (%s)' % (
            where, 'timed out' if 'time' in low else 'no route'),
                'fix': ('this node\'s firewall and the first node\'s are opened by acme, so '
                        'something in between drops it: a firewall of the network, a security '
                        'group, or the first node\'s own firewall not managed by acme '
                        '(firewalld) - let TCP %d through from this node to %s' % (port, host))
                if fw_open else ('this node\'s firewall could not be opened to it (%s); then '
                                 'look at the network in between' % (fw or {}).get('said'))}
    if 'no pg_hba.conf entry' in low:
        return {'kind': 'hba', 'says': 'PostgreSQL at %s answers, but pg_hba.conf has no line '
                'for this node' % where,
                'fix': 'on the first node, press Make the bundle… again giving this node\'s '
                'address as PostgreSQL sees it (it adds the line) - or add  host %s %s '
                'THIS-ADDRESS/32 scram-sha-256  to pg_hba.conf there and reload PostgreSQL' % (
                    db.get('db_name') or 'acme', db.get('db_user') or 'acme')}
    if 'password authentication failed' in low:
        return {'kind': 'password', 'says': 'PostgreSQL at %s answers, but does not take the '
                'password of the account %s' % (where, db.get('db_user') or '?'),
                'fix': 'the bundle is older than a change of that password: make a new bundle on '
                'the first node'}
    if 'does not exist' in low:
        return {'kind': 'missing', 'says': 'PostgreSQL at %s answers: %s' % (where, t[:200]),
                'fix': 'make a new bundle on the first node - it names its own database'}
    if 'could not translate host name' in low or 'name or service not known' in low:
        return {'kind': 'name', 'says': 'the name %s is not known here' % host,
                'fix': 'make the bundle again on the first node with its address in place of '
                'the name, or put the name into this node\'s DNS or /etc/hosts'}
    return {'kind': 'other', 'says': t[:300] or 'no answer', 'fix': 'see the first node\'s '
            'PostgreSQL log'}


def ha_pg_local(store):
    """Whether this node's PostgreSQL is on this machine - the one the other
    node of a shared pair has to reach here (1.0.210)."""
    host = str(CONFIG.get('db_host') or '')
    return store.db.engine == 'postgres' and host in ('', 'localhost', '127.0.0.1', '::1') \
        and CONFIG.get('ha_mode') != 'replicated'


def ha_pg_view(store):
    """For the page: whether PostgreSQL here still has to be opened to the
    node being joined, and what was done last."""
    if not ha_pg_local(store):
        return None
    listen = ''
    try:
        listen = str(store.db.value('SHOW listen_addresses') or '')
    except Exception:                                   # noqa: BLE001
        pass
    words = [w.strip() for w in listen.split(',') if w.strip()]
    only_local = bool(words) and all(w in ('localhost', '127.0.0.1', '::1') for w in words)
    return {'listen': listen, 'only_local': only_local or not words,
            'last': _json_meta(store, 'ha:pgopen:' + node_name()) or {}}


def ha_pg_open(store, peer, by='', wait=150):
    """PostgreSQL on this machine opened to the node being joined (1.0.210),
    through the root helper: [{key, ok, said}]."""
    if not ha_pg_local(store):
        return [{'key': 'pg', 'ok': True, 'said': 'PostgreSQL is not on this machine (%s): it '
                 'has to let %s in itself' % (CONFIG.get('db_host'), peer)}]
    peer = str(peer_address(peer))
    listen = str(CONFIG.get('ha_address') or node_address())
    if not WEB_DIR.is_dir():
        return [{'key': 'pg', 'ok': False, 'said': 'the root helper is not installed here: as '
                 'root,  acme --ha-setup --ha-shared --ha-peer %s' % peer}]
    ask = secrets.token_hex(8)
    pgtls_send({'id': ask, 'do': 'ha_open', 'port': int(CONFIG.get('db_port') or 5432),
                'db': str(CONFIG.get('db_name') or 'acme'),
                'user': str(CONFIG.get('db_user') or 'acme'), 'peer': peer, 'listen': listen,
                'ca_file': str(HA_CA_FILE)})
    end = time.time() + wait
    got = None
    while time.time() < end:
        try:
            one = json.loads((WEB_DIR / PGTLS_FILE).read_text())
        except (OSError, ValueError):
            one = None
        if isinstance(one, dict) and one.get('id') == ask:
            got = one
            break
        time.sleep(0.5)
    if got is None:
        steps = [{'key': 'pg', 'ok': False, 'said': 'the root helper did not answer in %d s - '
                  'is acme-web.path running?  systemctl status acme-web.path' % wait}]
    elif not got.get('ok'):
        steps = [{'key': 'pg', 'ok': False, 'said': str(got.get('said') or 'the root helper '
                                                          'said no')[:400]}]
    else:
        steps = [x for x in got.get('steps') or [] if isinstance(x, dict)][:8] or \
            [{'key': 'pg', 'ok': True, 'said': str(got.get('said') or '')[:400]}]
    store.set_meta('ha:pgopen:' + node_name(), json.dumps(
        {'at': time.time(), 'peer': peer, 'listen': listen, 'by': by,
         'ok': all(x.get('ok') for x in steps), 'steps': steps}))
    store.add_event('settings', '%s: PostgreSQL on %s opened to the node being joined (%s): %s'
                    % (by or 'acme', node_name(), peer, '; '.join(
                        str(x.get('said')) for x in steps)[:600]),
                    'warn' if not all(x.get('ok') for x in steps) else 'info', who=by or '')
    return steps


# ---- the PostgreSQL side, as root on the machine it runs on ------------------------
def pg_local_admin(sql, secret=False):
    """A statement run as the postgres account on this machine (root only).
    The SQL goes in on standard input, never on the command line, where
    every process on the machine could read it; `secret` marks one that
    carries a password, which is then kept out of PostgreSQL's own log."""
    for runner in (['runuser', '-u', 'postgres', '--'], ['su', '-s', '/bin/sh', 'postgres', '-c']):
        if not shutil.which(runner[0]):
            continue
        if runner[0] == 'su':
            args = runner + ['psql -XAtq -v ON_ERROR_STOP=1 -f -']
        else:
            args = runner + ['psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-f', '-']
        got = subprocess.run(args, capture_output=True, text=True, timeout=30,
                             input=pg_script(sql, secret))
        if got.returncode == 0:
            return got.stdout.strip()
        raise ValueError(scrub_secret((got.stderr or got.stdout).strip()[:300]) or 'psql failed')
    raise ValueError('neither runuser nor su is here')


PG_QUIET = "SET log_statement = 'none'; SET log_min_error_statement = 'panic';\n"


def pg_script(sql, secret=False):
    """The statement as psql reads it from its standard input - for one with
    a password in it, after switching the logging of statements off for the
    session, so the password lands in no log."""
    return (PG_QUIET if secret else '') + str(sql).rstrip().rstrip(';') + ';\n'


def shlex_quote(s):
    import shlex
    return shlex.quote(s)


def peer_address(text):
    """The other node's address - one address, never a range: ValueError
    otherwise."""
    said = str(text or '').strip()
    if not said:
        raise ValueError('the other node\'s address is needed')
    try:
        return ipaddress.ip_address(said)
    except ValueError:
        raise ValueError('%s is not an address (one address, not a range or a name)' % said)


def peer_net(text):
    """That address as the one-address network pg_hba.conf takes."""
    a = peer_address(text)
    return '%s/%d' % (a, 32 if a.version == 4 else 128)


def pg_open_to(peer, db_name, db_user):
    """PostgreSQL on this machine listening beyond localhost and letting the
    other node's address in for this one database and account. Returns what
    was done, in words."""
    # Both go into pg_hba.conf as root: a name with a space or a new line
    # in config.json wrote a line of its own there (1.0.139).
    for what, v in (('db_name', db_name), ('db_user', db_user)):
        if not DB_IDENT.fullmatch(str(v or '')):
            raise ValueError('%s is letters, digits and _ only, starting with a letter' % what)
    done = []
    listen = pg_local_admin('SHOW listen_addresses')
    if listen not in ('*', '0.0.0.0') and '*' not in listen.split(','):
        pg_local_admin("ALTER SYSTEM SET listen_addresses = '*'")
        done.append("listen_addresses = '*' (was %s) - takes effect at the next start" % listen)
    hba = pg_local_admin('SHOW hba_file')
    line = 'host    %s    %s    %s    scram-sha-256' % (db_name, db_user, peer_net(peer))
    try:
        text = Path(hba).read_text()
    except OSError as e:
        raise ValueError('%s could not be read: %s' % (hba, e))
    if line not in text:
        # In front of whatever is there: pg_hba.conf is read top down, and a
        # "reject" or an "ident" line further up would win otherwise.
        Path(hba).write_text('# acme high availability: the other node (%s)\n%s\n%s'
                             % (datetime.now().strftime('%Y-%m-%d'), line, text))
        done.append('%s: %s' % (hba, line))
    pg_local_admin('SELECT pg_reload_conf()')
    return done


