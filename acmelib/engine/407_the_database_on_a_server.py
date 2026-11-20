# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the database on a server of its own, looked after by acme-db-agent (1.0.113) ----------
# docs/external-database.md. Until now acme looked after a PostgreSQL (or MariaDB) only on its
# own machine, through the root helper (acme_web.py): the certificate of the database, its
# pg_hba.conf, its settings and restarts, the replication's TLS. With the database on a server
# of its own, a small agent there (deploy/acme_db_agent.py, installed with install.sh
# --db-server / --db-agent) does the same closed set of things for this node, over HTTPS - the
# agent's own certificate pinned, this node let in by its client certificate's fingerprint -
# and every request signed.
#
# Which one does it is this node's own choice, kept in a file of its own (never in config.json
# or the database, so nothing of it moves with a backup or to the other node):
#   /var/lib/acme/db-agent/agent.json   {"db_admin": "agent:HOST:PORT", ...}
# Without that file - every installation until now - db_admin is 'local': nothing here runs,
# nothing is asked, nothing is said; every path is the one it was.
DBAGENT_DIR = STATE_DIR / 'db-agent'
DBAGENT_FILE = DBAGENT_DIR / 'agent.json'
DBAGENT_CACHE = {'key': None, 'conf': None}
DBAGENT_EVERY = float(os.environ.get('ACME_DBAGENT_EVERY') or 30)
DBAGENT_DOWN_S = float(os.environ.get('ACME_DBAGENT_DOWN_S') or 90)
DBAGENT_RENEW_DAYS = 45
DBAGENT_CERT_DAYS = 730
DBAGENT_PROTO = 'acme-db-agent/1'
DBAGENT_LOCK = threading.Lock()
DBAGENT_PGTLS_LOCK = threading.Lock()
DBAGENT_STATE = {'ok': None, 'down_since': 0.0, 'fails': 0, 'facts': {}, 'at': 0.0,
                 'load': None, 'load_at': 0.0}


def db_agent():
    """This node's agent (its agent.json), or None: the database is looked after here."""
    try:
        st = os.stat(str(DBAGENT_FILE))
    except OSError:
        return None
    key = (st.st_mtime_ns, st.st_size)
    if DBAGENT_CACHE['key'] != key:
        try:
            conf = json.loads(DBAGENT_FILE.read_text())
        except (OSError, ValueError):
            conf = None
        if not isinstance(conf, dict) or not str(conf.get('db_admin') or '').startswith('agent:'):
            conf = None
        DBAGENT_CACHE.update(key=key, conf=conf)
    return DBAGENT_CACHE['conf']


def db_agent_on():
    return db_agent() is not None


def db_admin():
    """'local' (the root helper on this machine, as ever) or 'agent:HOST:PORT'."""
    a = db_agent()
    return str(a['db_admin']) if a else 'local'


def db_agent_db_host():
    a = db_agent() or {}
    return str(a.get('db_host') or a.get('host') or '')


def db_agent_here(c=None):
    """The database this node uses is the one on its agent's server - not merely an agent
    joined (1.0.113): a node that joined one but still has its database on this machine (or
    on a server no agent looks after) is looked after as it always was. During an --ha-join
    that puts this node's database on its agent's server (DBAGENT_STATE['target']) it is too."""
    if not db_agent_on():
        return False
    if DBAGENT_STATE.get('target'):
        return True
    try:
        return db_agent_is_target(CONFIG if c is None else c)
    except Exception:                                   # noqa: BLE001
        return False


def ha_peer_node():
    """The other acme node's address, for what is the nodes' own (the clocks' peers, the
    addresses the firewall always lets in, the VIP address's other node, the split's look at
    its machine). ha_peer, but with each node's database on a server of its own (layout B,
    1.0.113) ha_peer is the other database server - then the other node is --ha-peer-node."""
    a = db_agent() or {}
    if a.get('peer_node') and CONFIG.get('ha_mode') == 'replicated' and db_agent_here():
        return str(a['peer_node'])
    return str(CONFIG.get('ha_peer') or '')


def db_agent_layout_b():
    """Each node's database on a server of its own, replicating (layout B): this node's agent
    looks after its database and the other acme node is --ha-peer-node."""
    a = db_agent() or {}
    return bool(a.get('peer_node')) and CONFIG.get('ha_mode') == 'replicated' and db_agent_here()


def ha_own_node():
    """This node's own address, for what is the nodes' own (keepalived's unicast_src_ip, the
    address the other node's firewall lets in). ha_address - but in layout B ha_address is this
    node's database server (the replication's), and this node is the address kept at
    --ha-setup / --ha-join (node_address in agent.json: the one toward the other node, kept up
    to date by the network job, db_agent_node_moved) while this machine still has it, else the
    one toward the other node now - the route's source address (1.0.115: an address kept but
    gone from the machine left keepalived and the other node's firewall on it)."""
    if db_agent_layout_b():
        a = db_agent() or {}
        own = str(a.get('node_address') or '')
        if own:
            try:
                have = local_addresses()
            except Exception:                           # noqa: BLE001
                have = set()
            if not have or own in have:
                return own
        live = db_agent_route_source(a.get('peer_node'))
        return live or own or node_address()
    return str(CONFIG.get('ha_address') or node_address())


def db_agent_my_address(toward=None):
    """This machine's address as a server at `toward` sees it: the source address of the route
    to it (a node with several addresses - another network for its database server - is let
    in there by the one it comes from, 1.0.115). `toward`: by default this node's database
    server. node_address() when there is no route or no name."""
    return db_agent_route_source(toward) or node_address()


def db_agent_route_source(toward=None):
    """The source address of the route to `toward` (by default this node's database server),
    or '' when there is no route or no name."""
    a = db_agent() or {}
    host = str(toward or a.get('db_host') or a.get('host') or '').strip().strip('[]')
    if host:
        try:
            infos = socket.getaddrinfo(host, 9, 0, socket.SOCK_DGRAM)
        except (OSError, UnicodeError):
            infos = []
        for fam, _t, _p, _c, sa in infos[:4]:
            try:
                s = socket.socket(fam, socket.SOCK_DGRAM)
                try:
                    s.connect(sa)
                    ip = str(s.getsockname()[0]).split('%')[0]
                finally:
                    s.close()
            except OSError:
                continue
            if ip and ip not in ('0.0.0.0', '::'):
                return ip
    return ''


def db_agent_put(changes):
    a = dict(db_agent() or {})
    a.update(changes)
    DBAGENT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_replacing(DBAGENT_FILE, json.dumps(a, indent=1, sort_keys=True) + '\n', 0o600)
    _db_agent_own(DBAGENT_FILE)
    DBAGENT_CACHE['key'] = None
    return a


def _db_agent_own(path, mode=0o600):
    try:
        chown_to_service(path, mode)
    except NameError:
        pass


# ---- the join code -------------------------------------------------------------------------
def db_agent_code(code):
    """ADBA1.<base64url JSON {h, p, s, f, e}>: the agent's address and port, the one-time
    secret, the fingerprint of the certificate it answers with, its engine."""
    code = str(code or '').strip()
    if not code.startswith('ADBA1.'):
        raise ValueError('that is not a join code of acme-db-agent (it starts with ADBA1.)')
    raw = code[6:]
    try:
        data = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)).decode())
    except (ValueError, UnicodeDecodeError):
        raise ValueError('the join code is cut short or mistyped')
    if not isinstance(data, dict) or not re.fullmatch(r'[0-9a-f]{64}', str(data.get('f') or '')) \
            or not data.get('s') or not data.get('h'):
        raise ValueError('the join code is cut short or mistyped')
    try:
        data['p'] = int(data.get('p') or 9443)
    except (TypeError, ValueError):
        raise ValueError('the join code is cut short or mistyped')
    if data.get('k') and not re.fullmatch(r'[0-9a-f]{64}', str(data['k'])):
        raise ValueError('the join code is cut short or mistyped')
    return data


# ---- talking to it ----------------------------------------------------------------------
def _db_agent_ctx(with_client=True):
    """The agent is known by the fingerprint of its certificate, pinned (from the join code
    on, then as its signed answers announce the next one): it makes that certificate itself,
    no authority stands behind it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if with_client:
        ctx.load_cert_chain(str(DBAGENT_DIR / 'client.crt'), str(DBAGENT_DIR / 'client.key'))
    return ctx


class DbAgentNotSent(ValueError):
    """The request never left: no connection, the handshake failed, or the certificate
    answering is not pinned - safe to send once more (the agent's old listening side still
    answers for a moment after it starts a new one)."""


def _db_agent_http(host, port, path, body, ctx, pins, headers=None, timeout=90):
    """One request, the agent's certificate pinned: (status, body bytes, headers)."""
    import http.client
    conn = http.client.HTTPSConnection(host, int(port), context=ctx, timeout=timeout)
    try:
        try:
            conn.connect()
        except (OSError, ssl.SSLError) as e:
            raise DbAgentNotSent(str(e)) from e
        fp = hashlib.sha256(conn.sock.getpeercert(True) or b'').hexdigest()
        if fp not in pins:
            raise DbAgentNotSent('the agent at %s:%s answers with a certificate acme did not pin '
                                 '(%s…) - not the agent that joined, or somebody in between' % (
                                     host, port, fp[:16]))
        conn.request('POST' if body is not None else 'GET', path, body=body,
                     headers=dict(headers or {}, **{'Content-Type': 'application/json'}))
        r = conn.getresponse()
        return r.status, r.read(1 << 22), dict(r.getheaders())
    finally:
        conn.close()


def db_agent_sign_key(conf=None):
    """The key this node signs its requests with: a file of its own beside its client key
    (0600, the daemon's) - not sealed with secrets.key, which a join or a backup put back
    replaces."""
    try:
        key = (DBAGENT_DIR / 'sign.key').read_text().strip()
    except OSError:
        return None
    return key if re.fullmatch(r'[0-9a-f]{64}', key) else None


def _db_agent_signed(key, node, body):
    ts = '%.3f' % time.time()
    nonce = secrets.token_hex(16)
    text = '\n'.join([DBAGENT_PROTO, 'POST', '/v1/op', node, ts, nonce,
                      hashlib.sha256(body).hexdigest()]).encode()
    return {'X-Acme-Node': node, 'X-Acme-Time': ts, 'X-Acme-Nonce': nonce,
            'X-Acme-Sign': hmac.new(bytes.fromhex(key), text, 'sha256').hexdigest()}


def _db_agent_pins_from(agent, conf):
    """The pins as the agent's signed `status` says them: the certificate it answers with and
    the next one it announced (taken in now, so it can be put in use) - only for this node's
    own agent. The new agent.json, or None when nothing changed."""
    cur = str((agent or {}).get('cert_fp') or '')
    nxt = str((agent or {}).get('cert_next_fp') or '')
    if not re.fullmatch(r'[0-9a-f]{64}', cur):
        return None
    want = [cur] + ([nxt] if re.fullmatch(r'[0-9a-f]{64}', nxt) and nxt != cur else [])
    a = db_agent()
    if not a or str(a.get('host')) != str(conf.get('host')) or \
            str(a.get('port')) != str(conf.get('port')):
        return None
    if list(a.get('pins') or []) == want and (not agent.get('cert_end') or
                                              a.get('agent_cert_end') == agent.get('cert_end')):
        return None
    return db_agent_put({'pins': want, 'agent_cert_end': agent.get('cert_end') or
                         a.get('agent_cert_end')})


def db_agent_call(op, args=None, timeout=90, conf=None, _ack=True):
    """One of the agent's operations, signed; its answer (a dict) or ValueError."""
    a = conf or db_agent()
    if not a:
        raise ValueError('this node has no database agent (db_admin is local)')
    key = db_agent_sign_key(a)
    if not key:
        raise ValueError('the signing key of the database agent is not in %s - join the '
                         'agent again (acme --db-agent-join)' % DBAGENT_DIR)
    args = dict(args or {})
    if op == 'status':
        # Which of the agent's certificates this node pins: once every node took the next one
        # in, the agent puts it in use.
        args['pins'] = list(a.get('pins') or [])
    body = json.dumps({'op': op, 'args': args}).encode()
    node = str(a.get('node') or node_name())
    last = None
    for attempt in (0, 1):
        hd_out = _db_agent_signed(key, node, body)
        try:
            st, got, hd = _db_agent_http(a['host'], a['port'], '/v1/op', body, _db_agent_ctx(),
                                         list(a.get('pins') or []), hd_out, timeout)
            break
        except Exception as e:                          # noqa: BLE001  (http.client's too)
            last = e
            # the agent starting its listening side again (a new certificate, a node joined):
            # its old side still answers for a moment - a reset or a certificate not pinned
            # before anything was sent, or a look, is tried once more (1.0.113)
            if attempt == 0 and (op in ('status', 'load') or isinstance(e, DbAgentNotSent)):
                time.sleep(1.5)
                continue
            raise ValueError('the database agent at %s:%s does not answer: %s'
                             % (a['host'], a['port'], str(e)[:200]))
    else:
        raise ValueError('the database agent at %s:%s does not answer: %s'
                         % (a['host'], a['port'], str(last)[:200]))
    try:
        out = json.loads(got.decode() or '{}')
    except ValueError:
        raise ValueError('the database agent answered what is not JSON (HTTP %d)' % st)
    if st == 200:
        want = hmac.new(bytes.fromhex(key), ('reply\n%s\n' % hd_out['X-Acme-Nonce']).encode() +
                        hashlib.sha256(got).digest(), 'sha256').hexdigest()
        if not hmac.compare_digest(want, str(hd.get('X-Acme-Sign') or '')):
            raise ValueError('the database agent\'s answer is not signed with this node\'s key')
    if st != 200 or not out.get('ok'):
        raise ValueError('the database agent said: %s' % (out.get('said') or 'HTTP %d' % st))
    out.pop('ok', None)
    if out.pop('agent_restart', False) and op != 'leave':
        # Its listening side starts again with what it was given (or its next certificate):
        # waited for.
        time.sleep(0.8)
        end = time.time() + 30
        while True:
            try:
                db_agent_call('status', timeout=10, conf=db_agent() or conf)
                break
            except ValueError:
                if time.time() > end:
                    raise
                time.sleep(0.5)
    elif op == 'status':
        new = _db_agent_pins_from(out.get('agent') or {}, a)
        if new and _ack and (out.get('agent') or {}).get('cert_next_fp'):
            # The next certificate taken in: said to the agent at once.
            return db_agent_call('status', args, timeout, conf=new, _ack=False)
    return out


DBAGENT_CODE_CACHE = {'key': None, 'code': ''}


def db_agent_code_ours():
    """sha256 of the agent's program this acme ships (deploy/acme_db_agent.py,
    deploy/acme_pg_ops.py and deploy/acme_web.py - the agent's AGENT_FILES, which install.sh
    copies unchanged beside it - hashed as the agent hashes itself), or '' when they are not
    here."""
    folder = Path(__file__).resolve().parent / 'deploy'
    files = [folder / n for n in ('acme_db_agent.py', 'acme_pg_ops.py', 'acme_web.py')]
    try:
        key = tuple((f.stat().st_mtime_ns, f.stat().st_size) for f in files)
    except OSError:
        return ''
    if DBAGENT_CODE_CACHE['key'] != key:
        h = hashlib.sha256()
        for f in files:
            h.update(hashlib.sha256(f.read_bytes()).digest())
        DBAGENT_CODE_CACHE.update(key=key, code=h.hexdigest())
    return DBAGENT_CODE_CACHE['code']


def _version_tuple(v):
    m = re.match(r'\d+(?:\.\d+)*', str(v or ''))
    return tuple(int(x) for x in m.group(0).split('.')) if m else ()


def db_agent_version_skew(agent):
    """The agent's program against the one this acme ships (1.0.115): {} when it is the same -
    an acme release that did not change the agent says nothing - else {agent, acme, how}:
    'older' (upgrade the agent), 'newer' (it came with a newer acme than this one: upgrade
    acme), 'other' (the same release, another program: changed there by hand). An agent
    before 1.0.115 says no `code`: its version is compared."""
    agent = agent or {}
    theirs, ours = str(agent.get('version') or ''), str(__version__)
    code, mine = str(agent.get('code') or ''), db_agent_code_ours()
    if code and mine and hmac.compare_digest(code, mine):
        return {}
    if not code and (not theirs or _version_tuple(theirs) == _version_tuple(ours)):
        return {}
    if not mine and code:
        return {}                       # nothing here to compare with
    t, o = _version_tuple(theirs), _version_tuple(ours)
    how = 'older' if t and o and t < o else ('newer' if t and o and t > o else
                                             ('other' if code else 'older'))
    return {'agent': theirs or '?', 'acme': ours, 'how': how}


def db_agent_skew_words(skew, cs=False):
    """What to do about it, in English or Czech."""
    a, m, how = skew.get('agent'), skew.get('acme'), skew.get('how') or 'older'
    if how == 'newer':
        return ('acme-db-agent %s je novější než toto acme %s - aktualizujte acme na tomto uzlu '
                '(nebo na databázovém serveru vraťte agenta této verze: ./install.sh --db-agent '
                'z instalace této verze acme)' % (a, m)) if cs else \
            ('acme-db-agent %s is newer than this acme %s - upgrade acme on this node (or put '
             'the agent of this version back on the database server: ./install.sh --db-agent '
             'from this version of acme)' % (a, m))
    if how == 'other':
        return ('program agenta (acme-db-agent %s) není ten, který dodává acme %s (změněn na '
                'serveru nebo z jiného sestavení) - vraťte ho: ./install.sh --db-agent z instalace '
                'této verze acme' % (a, m)) if cs else \
            ('the agent\'s program (acme-db-agent %s) is not the one acme %s ships (changed there, '
             'or from another build) - put it back: ./install.sh --db-agent from this version of '
             'acme' % (a, m))
    return ('acme-db-agent %s, acme %s - aktualizujte agenta na databázovém serveru: '
            './install.sh --db-agent (z instalace této verze acme)' % (a, m)) if cs else \
        ('acme-db-agent %s, acme %s - upgrade the agent on the database server: ./install.sh '
         '--db-agent (from this version of acme)' % (a, m))


# ---- joining an agent ------------------------------------------------------------------
def _db_agent_fp(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.strip() + '\n')).hexdigest()


def db_agent_code_read(code):
    """The join code as given: '-' (or nothing) reads ACME_DB_AGENT_CODE, else a line of
    standard input - so it is never on a command line, in `ps` for every account to read."""
    code = str(code or '').strip()
    if code in ('', '-'):
        code = os.environ.get('ACME_DB_AGENT_CODE', '').strip()
        if not code:
            if sys.stdin.isatty():
                sys.stderr.write('The join code (acme_db_agent.py --new-code printed it): ')
                sys.stderr.flush()
            code = (sys.stdin.readline() or '').strip()
    if not code:
        raise ValueError('no join code: paste it on standard input (acme --db-agent-join -) or '
                         'put it in ACME_DB_AGENT_CODE')
    return code


def db_agent_join(store, code, addr='', db_host='', by='command line', say=None):
    """This node joins the agent of a code: a client certificate of this node's own from
    acme's authority and a signing key given to it - and from then on the database server is
    looked after through it (db_admin = agent:HOST:PORT). The agent's own certificate is the
    one pinned by the code: it is the same for every node that joins it, so a second node
    joining (or a node joining again) changes nothing for the others."""
    say = say or (lambda t: None)
    data = db_agent_code(code)
    host, port = data['h'], data['p']
    if addr:
        raw = str(addr).strip()
        if raw.count(':') > 1 and not raw.startswith('['):
            # An IPv6 address without brackets holds no port (1.0.119): 2001:db8::5 was taken
            # as the host 2001:db8: at the port 5.
            host = raw
        else:
            m = re.fullmatch(r'\[?([^\]]+?)\]?(?::(\d{1,5}))?', raw)
            if not m:
                raise ValueError('the agent\'s address is HOST or HOST:PORT')
            host, port = m.group(1), int(m.group(2) or port)
    # One agent per node (1.0.113): another one joined replaces the one there is - refused
    # while this node is one of a cluster whose database is on that one's server (the
    # replication runs through it).
    prev = db_agent()
    other = bool(prev) and (str(prev.get('host')), str(prev.get('port'))) != (str(host), str(port))
    if other and CONFIG.get('ha_mode') and db_agent_here():
        raise ValueError('this node is one of a cluster and its database is on %s, looked after '
                         'by the agent at %s:%s: another agent is not joined instead - take the '
                         'cluster apart first (Settings -> High availability)'
                         % (prev.get('db_host') or prev.get('host'), prev.get('host'),
                            prev.get('port')))
    was_here = other and db_agent_here()
    node = node_name()
    boot = [data['f']]
    if not data.get('k'):
        raise ValueError('the join code holds no key of the agent to seal the join to: the agent '
                         'is older than this acme - upgrade it on the database server '
                         '(./install.sh --db-agent, of this version), then make a new code')

    def enroll(path, body):
        st, got, _ = _db_agent_http(host, port, path, json.dumps(body).encode(),
                                    _db_agent_ctx(with_client=False), boot, timeout=60)
        try:
            out = json.loads(got.decode() or '{}')
        except ValueError:
            out = {}
        if st != 200 or not out.get('ok'):
            raise ValueError('the database agent said: %s' % (out.get('said') or 'HTTP %d' % st))
        return out
    cid = str(data.get('i') or '')
    ask = {'code_id': cid, 'node': node}
    try:
        try:
            # The agent's own key (1.0.115), the one whose fingerprint the code holds: the
            # code's secret and this node's signing key are sealed to it - the side of the agent
            # that faces the network passes them on and never sees them.
            st, got, _ = _db_agent_http(host, port, '/v1/enroll/key', None,
                                        _db_agent_ctx(with_client=False), boot, timeout=30)
            try:
                pub = str(json.loads(got.decode() or '{}').get('pub') or '')
            except ValueError:
                pub = ''
            if st != 200 or not pub:
                raise ValueError('the database agent at %s:%s gives no key to seal the join to '
                                 '(HTTP %s): it is older than this acme - upgrade it on the '
                                 'database server (./install.sh --db-agent)' % (host, port, st))
            if not hmac.compare_digest(_db_agent_pub_fp(pub), str(data['k'])):
                raise ValueError('the database agent at %s:%s gives a key to seal the join to that '
                                 'is not the one of the code - not the agent that made it, or '
                                 'somebody in between' % (host, port))
            began = enroll('/v1/enroll/begin', dict(ask, seal=_db_agent_seal(
                pub, ['begin', cid, node, data['s']])))
        except DbAgentNotSent as e:
            if e.__cause__ is None:
                raise                                   # a certificate not the code's
            raise e.__cause__
    except (OSError, ssl.SSLError) as e:
        raise ValueError('the database agent at %s:%s cannot be reached: %s - is its port open '
                         'to this node? (on the database server: firewall-cmd --permanent '
                         '--add-rich-rule=\'rule family="ipv4" source address="%s" port '
                         'port="%s" protocol="tcp" accept\' && firewall-cmd --reload)'
                         % (host, port, e, db_agent_my_address(host) or 'THIS-NODE', port))
    say('the agent at %s:%s answers (acme-db-agent %s, %s) and is the one of the code'
        % (host, port, began.get('version'), began.get('engine')))
    skew = db_agent_version_skew(began)
    if skew:
        say('NOTE: %s' % db_agent_skew_words(skew))
    hatls_ca_ensure(store, by)
    ckey, ccrt = hatls_issue(store, [], eku='clientAuth', days=DBAGENT_CERT_DAYS,
                             cn='acme-' + node)
    trust = hatls_trust(hatls_ca(store))
    sign_key = secrets.token_hex(32)
    enroll('/v1/enroll/finish', dict(ask, token=began.get('token') or '', client_cert=ccrt,
                                     ca=trust, seal=_db_agent_seal(pub, [
                                         'finish', cid, node, data['s'], sign_key,
                                         _db_agent_fp(ccrt)])))
    say('the agent knows this node by its client certificate from acme\'s authority')
    if other:
        # The agent there was is told this node is no longer its (1.0.115) - with the key it
        # knows this node by, before that is replaced: it then waits for it no more.
        try:
            db_agent_call('leave', {}, timeout=20, conf=prev)
            left_old = True
        except ValueError:
            left_old = False
    else:
        left_old = False
    DBAGENT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, text, mode in (('client.key', ckey, 0o600), ('client.crt', ccrt, 0o644),
                             ('client-ca.pem', trust, 0o644), ('sign.key', sign_key + '\n', 0o600)):
        write_replacing(DBAGENT_DIR / name, text, mode)
        _db_agent_own(DBAGENT_DIR / name, mode)
    ids = service_ids()
    if os.geteuid() == 0 and ids:
        # the daemon's folder: it renews the certificates and writes agent.json in it
        os.chown(str(DBAGENT_DIR), ids[0], ids[1])
        os.chmod(str(DBAGENT_DIR), 0o700)
    engine = 'mariadb' if began.get('engine') == 'mariadb' else 'postgres'
    pins = [data['f']]
    nxt = str(began.get('cert_next_fp') or '')
    if re.fullmatch(r'[0-9a-f]{64}', nxt) and nxt not in pins:
        pins.append(nxt)
    replaced = None
    if other:
        # The one there was, kept aside as it was (agent.json.replaced): nothing of it - its
        # pins, its other node, its certificate's end - is taken over by this one.
        replaced = {'db_admin': prev.get('db_admin'), 'db_host': prev.get('db_host') or
                    prev.get('host'), 'engine': prev.get('engine'), 'had_database': was_here,
                    'left': left_old}
        try:
            os.replace(str(DBAGENT_FILE), str(DBAGENT_FILE) + '.replaced')
        except OSError:
            pass
        DBAGENT_CACHE['key'] = None
    a = db_agent_put({'db_admin': 'agent:%s:%d' % (host, port), 'host': host, 'port': port,
                      'node': node, 'pins': pins,
                      'engine': engine, 'pg_port': int(began.get('pg_port') or 5432),
                      'my_port': int(began.get('my_port') or 3306),
                      'db_host': db_host or host, 'at': time.time(), 'by': by,
                      'client_cert_end': _cert_end(ccrt),
                      'trust_sent': _db_agent_set_hash(trust)})
    # The agent starts its listening side again with this node in: waited for.
    # Not answering in time is no failure of the join (1.0.119): agent.json and the keys are
    # written already - this node is joined, and the agent is watched and looked at again.
    end = time.time() + 20
    late = ''
    while True:
        try:
            got = db_agent_call('status', conf=a)
            break
        except ValueError as e:
            if time.time() > end:
                got, late = {}, str(e)
                say('NOTE: the agent did not answer since it was joined (%s) - this node is '
                    'joined all the same; it is looked at again shortly' % late)
                break
            time.sleep(0.5)
    # Its firewall opened to this node (the database's port and the agent's), where firewalld
    # runs there - joined without --acme-node, nothing else would.
    try:
        for line in db_agent_fw([db_agent_my_address(db_host or host)], agent=True).get('said') or []:
            say('the database server: %s' % line)
    except ValueError as e:
        say('the database server\'s firewall was not opened to this node: %s' % e)
    db_agent_ha_ca_local(trust)
    store.add_event('settings', '%s: %s looks after its database server %s through acme-db-agent '
                    '(%s:%d) from now on' % (by, node, db_host or host, host, port), 'warn', who=by)
    if replaced:
        say('NOTE: %s' % db_agent_replaced_words(replaced))
        store.add_event('settings', '%s: %s' % (by, db_agent_replaced_words(replaced)), 'warn',
                        who=by)
    return {'host': host, 'port': port, 'facts': got.get('facts') or {},
            'agent': got.get('agent') or {}, 'replaced': replaced, 'late': late,
            'replaced_said': db_agent_replaced_words(replaced) if replaced else ''}


def db_agent_left_words(left, where=''):
    """Whether the agent let go took this node off its list (1.0.115: `leave`)."""
    if left:
        return 'that agent took this node off its list'
    return ('that agent did not answer: it keeps this node\'s certificate until acme_db_agent.py '
            '--forget %s there%s' % (node_name(), (' (%s)' % where) if where else ''))


def db_agent_replaced_words(r):
    """What joining another agent did to the one there was (one agent per node)."""
    old = str(r.get('db_admin') or '')[len('agent:'):]
    if r.get('had_database'):
        return ('this node\'s database is still on %s, whose agent (%s) acme no longer asks: '
                'move the database onto the new server next (acme --db-move, or Settings -> The '
                'database -> Move) - until then nothing of that server is looked after (its '
                'certificate is not renewed); %s' % (r.get('db_host'), old,
                                                    db_agent_left_words(r.get('left'))))
    return ('the agent joined before (%s) is no longer this node\'s - one agent a node; %s'
            % (old, db_agent_left_words(r.get('left'))))


def _db_agent_pub_fp(pem):
    """sha256 of a public key's DER (SubjectPublicKeyInfo), as the join code holds it."""
    body = ''.join(x.strip() for x in str(pem or '').splitlines()
                   if x.strip() and not x.startswith('-----'))
    try:
        return hashlib.sha256(base64.b64decode(body)).hexdigest()
    except (ValueError, binascii.Error):
        return ''


def _db_agent_seal(pub, fields):
    """`fields` (lines) sealed to the agent's own key, RSA-OAEP with SHA-256 (openssl): only
    root on the agent opens them."""
    if any('\n' in str(x) for x in fields):
        raise ValueError('a line of the join holds a line break')
    text = '\n'.join(['acme-db-agent-seal/1'] + [str(x) for x in fields]).encode()
    with tempfile.TemporaryDirectory(prefix='acme-seal-') as t:
        path = os.path.join(t, 'pub.pem')
        with open(path, 'w') as f:
            f.write(pub)
        got = subprocess.run(['openssl', 'pkeyutl', '-encrypt', '-pubin', '-inkey', path,
                              '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256',
                              '-pkeyopt', 'rsa_mgf1_md:sha256'], input=text, capture_output=True)
    if got.returncode != 0 or not got.stdout:
        raise ValueError('the join could not be sealed to the agent\'s key: %s'
                         % got.stderr.decode(errors='replace').strip()[-200:])
    return base64.b64encode(got.stdout).decode()


def db_agent_ha_ca_local(trust):
    """acme's authorities on this node too, at the path the database servers have them
    (/etc/pki/acme/ha-ca.pem): the daemon checks its database with it (verify-full), as
    the replication's workers check the other server with the agent's copy."""
    if not trust:
        return
    try:
        if os.geteuid() == 0:
            made = not HA_CA_FILE.parent.exists()
            HA_CA_FILE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            ids = service_ids()
            if made and ids:
                # a folder made for it here: the daemon's own, so it can renew the file
                os.chown(str(HA_CA_FILE.parent), ids[0], ids[1])
            write_replacing(HA_CA_FILE, trust, 0o644)
            _db_agent_own(HA_CA_FILE, 0o644)
            return
        try:
            write_replacing(HA_CA_FILE, trust, 0o644)
        except PermissionError:
            # root's folder, the file the daemon's own (--db-agent-join): written in place
            fd = os.open(str(HA_CA_FILE), os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            with os.fdopen(fd, 'w') as f:
                f.write(trust)
    except OSError as e:
        log_sparing('dbagent-ca', 'acme\'s authorities could not be written to %s here: %s'
                    % (HA_CA_FILE, e), 'warn', every=3600)


def db_agent_forget_refused():
    """Why this node's agent may not be let go now ('' when it may): in layout B its database
    is on the agent's server and the replication runs through it - forgotten, ha_peer_node()
    would fall back to ha_peer, the other DATABASE server, as the other node (the VIP address,
    the firewall, the clocks), and nothing of the server would be looked after (1.0.115)."""
    a = db_agent()
    if not a or not db_agent_layout_b():
        return ''          # layout A, shared or not: nothing of the cluster rests on the agent
    return ('this node is one of a cluster and its database is on %s, looked after by the agent '
            'at %s:%s: the agent is not let go - take the cluster apart first (Settings -> High '
            'availability)' % (a.get('db_host') or a.get('host'), a.get('host'), a.get('port')))


def db_agent_forget(store=None, by='command line', why='', drop_rows=True, leave=True,
                    force=False):
    """Back to looking after a database on this machine (db_admin local). The agent is told
    this node is no longer its (`leave`, 1.0.115 - only this node is taken off its list); one
    that does not answer keeps this node's certificate until acme_db_agent.py --forget NODE
    there. Returns False when there was no agent, else whether the agent took it in (True) or
    did not answer (None). ValueError while db_agent_forget_refused() says why not (unless
    `force`: the node is being taken away, or its database has just moved off)."""
    a = db_agent()
    if not a:
        return False
    refused = '' if force else db_agent_forget_refused()
    if refused:
        raise ValueError(refused)
    left = None
    if leave:
        try:
            db_agent_call('leave', {}, timeout=20, conf=a)
            left = True
        except ValueError as e:
            log('the database agent %s was not told this node leaves it: %s'
                % (a.get('db_admin'), str(e)[:200]), 'warn')
    try:
        os.replace(str(DBAGENT_FILE), str(DBAGENT_FILE) + '.forgotten')
    except OSError:
        DBAGENT_FILE.unlink()
    DBAGENT_CACHE['key'] = None
    DBAGENT_STATE.update(ok=None, down_since=0.0, fails=0, facts={}, at=0.0, load=None)
    if store is not None:
        # Its server's rows go with it: the cards and the meter no longer draw it. (Not after a
        # move: the database left behind is never touched - the move took them out of the
        # new one.)
        if drop_rows:
            db_agent_rows_drop(store.db)
        store.add_event('settings', '%s: %s no longer looks after its database server through '
                        'acme-db-agent (%s)%s; %s' % (by, node_name(), a.get('db_admin'),
                                                       (' - ' + why) if why else '',
                                                       db_agent_left_words(left)), 'warn', who=by)
    return True if left else None


def db_agent_rows_drop(db, node=None):
    """This node's database server's rows (what its agent said, the meter's reading)."""
    n = node or node_name()
    for k in ('dbagent:node:' + n, 'load:db:' + n):
        try:
            db.run('DELETE FROM meta WHERE k = ?', (k,))
        except Exception:                               # noqa: BLE001
            pass


def db_agent_after_move(store, was_here, c, by):
    """The database moved (config.json switched to `c`): moved off the agent's server - onto
    this machine, a file, a server no agent looks after - and the agent is no longer this
    node's (db_admin local, its file kept as agent.json.forgotten): nothing is asked of it
    any more, its server leaves the cards and the meter. Moved onto it, or the database was
    never there: nothing changes. The words said, or ''."""
    a = db_agent()
    if not a or not was_here or db_agent_is_target(c):
        return ''
    left = db_agent_forget(store, by, 'the database was moved off its server', drop_rows=False,
                           force=True)
    return ('acme-db-agent at %s:%s no longer looks after this node\'s database (it is %s now): '
            'db_admin is local again; %s' % (a.get('host'), a.get('port'), db_where(c),
                                             db_agent_left_words(left, a.get('db_host') or
                                                                 a.get('host'))))


# ---- what the root helper did, done by the agent ------------------------------------------
def db_agent_link_peers():
    """Who the link's pg_hba lines are for, on a database server of its own: the other
    database server (it subscribes from here) and the other acme node (it asks here)."""
    out = []
    a = db_agent() or {}
    for x in (CONFIG.get('ha_peer'), a.get('peer_node')):
        x = str(x or '').strip()
        try:
            x = str(plain_ip(x, 'address')) if x else ''
        except ValueError:
            x = ''
        if x and x not in out:
            out.append(x)
    return out


def db_agent_pgtls_send(data):
    """pgtls_send for a database on a server of its own: the same request, done by the agent
    in a thread, its answer written where the root helper's goes (pgtls.json) - every reader
    of it (the link's steps, Database -> TLS, a new address) as it was."""
    data = dict(data)

    def work():
        with DBAGENT_PGTLS_LOCK:
            out = {'at': time.time(), 'ok': False, 'id': str(data.get('id') or '')[:40]}
            try:
                req = dict(data)
                req.pop('port', None)
                if req.get('do') in ('hba', 'hba_off'):
                    req['peers'] = db_agent_link_peers() or ([req['peer']] if req.get('peer') else [])
                got = db_agent_call('pgtls', req, timeout=240)
                if req.get('do') == 'server' and req.get('trust'):
                    db_agent_ha_ca_local(req['trust'])
                out.update(got)
                out['ok'] = True
            except Exception as e:                      # noqa: BLE001
                out['said'] = str(e)[:400]
            try:
                WEB_DIR.mkdir(parents=True, exist_ok=True)
                write_replacing(WEB_DIR / PGTLS_FILE, json.dumps(out), 0o640)
            except OSError as e:
                log('the database agent\'s answer could not be written: %s' % e, 'error')
    threading.Thread(target=work, name='dbagent-pgtls', daemon=True).start()


def db_agent_pglog():
    try:
        got = db_agent_call('pglog', {}, timeout=30)
    except ValueError as e:
        return {'at': time.time(), 'entries': [], 'said': str(e)[:300]}
    got.setdefault('at', time.time())
    return got


def db_agent_prepare(peer, name, user, password, say, extra=()):
    """pg_prepare_local on the agent's server: the peers are the other database server, the
    other acme node, and this node (it opens its database from its own address)."""
    a = db_agent() or {}
    peers = []
    for x in [peer, a.get('peer_node'), db_agent_my_address(), '127.0.0.1'] + list(extra):
        x = str(x or '').strip()
        try:
            x = str(plain_ip(x, 'address')) if x else ''
        except ValueError:
            x = ''
        if x and x not in peers:
            peers.append(x)
    got = db_agent_call('pg_prepare', {'db': name, 'user': user, 'password': password,
                                       'peers': peers}, timeout=120)
    for line in got.get('said') or []:
        say(line)
    # pg_restart_needed (1.0.113): `restart` read here was the agent's own word once.
    return bool(got.get('pg_restart_needed')), int(got.get('major') or 16)


def db_agent_restart(say=None):
    got = db_agent_call('pg_restart' if (db_agent() or {}).get('engine') != 'mariadb'
                        else 'my_restart', {}, timeout=240)
    if say:
        say(got.get('said') or 'the database server started again')
    return got


def db_agent_publication(name):
    return db_agent_call('pg_publication', {'db': name})


def db_agent_fw(peers, agent=False):
    args = {'peers': [p for p in peers if p]}
    if agent:
        args['agent'] = True            # the agent's own port too (a node that joined)
    return db_agent_call('fw_allow', args)


def db_agent_running():
    try:
        return bool((db_agent_call('status', timeout=20).get('facts') or {}).get('running'))
    except ValueError:
        return False


def db_agent_dbmake(c):
    """The database and its account made on the agent's server, let in from this node."""
    # This node by the address its database server sees it from (1.0.115: a node with several
    # addresses was let in by the one it reaches the outside with).
    me = db_agent_my_address(c.get('db_host'))
    peers = [x for x in (me, '127.0.0.1') if x]
    got = db_agent_call('dbmake', {'name': c['db_name'], 'user': c['db_user'],
                                   'password': c['db_password'], 'peers': peers}, timeout=120)
    said = list(got.get('said') or [])
    # The database's port opened to this node where firewalld runs there (1.0.113).
    try:
        said += list(db_agent_fw([me]).get('said') or [])
    except ValueError as e:
        said.append('the firewall of the database server was not opened to this node: %s' % e)
    return said


def db_agent_is_target(c):
    """The database `c` names is the one this node's agent looks after: its engine, its
    address (the database server's or the agent's), its port."""
    a = db_agent()
    if not a:
        return False
    eng = str(c.get('db_engine') or '')
    if eng not in ('postgres', 'mariadb') or eng != (a.get('engine') or 'postgres'):
        return False
    host = str(c.get('db_host') or '').strip('[]').lower()
    if host not in (str(a.get('db_host') or '').lower(), str(a.get('host') or '').lower()):
        return False
    want = a.get('pg_port') if eng == 'postgres' else a.get('my_port')
    try:
        port = int(c.get('db_port') or (5432 if eng == 'postgres' else 3306))
        return not want or port == int(want)
    except (TypeError, ValueError):
        return False


# ---- MariaDB on a server of its own: its TLS (layout A) --------------------------------------
def db_agent_mariadb_tls(store, by):
    """MariaDB given a certificate from acme's authority through the agent (and renewed the
    same way); this node then reaches it with verify-full through Database -> TLS ('acme')."""
    a = db_agent()
    if not a or a.get('engine') != 'mariadb':
        raise ValueError('this node\'s database agent does not look after a MariaDB')
    hatls_ca_ensure(store, by)
    names = [x for x in (db_agent_db_host(), a.get('host')) if x]
    key, crt = hatls_issue(store, names, days=HATLS_CERT_DAYS, cn='mariadb')
    got = db_agent_call('my_tls', {'cert': crt, 'key': key,
                                   'trust': hatls_trust(hatls_ca(store))}, timeout=240)
    store.set_meta('dbtls:server:' + node_name(), json.dumps(
        {'cert_end': got.get('cert_end') or _cert_end(crt), 'at': time.time(), 'by': by,
         'names': names, 'engine': 'mariadb'}))
    store.add_event('settings', '%s: the MariaDB of %s was given a certificate from acme\'s '
                    'authority (acme-db-agent)' % (by, node_name()), 'info', who=by)
    return got


def db_agent_mariadb_renew(store, by='acme (renewed)'):
    """The MariaDB's certificate from acme's authority renewed through its agent 45 days before
    it ends (1.0.113) - as a PostgreSQL's is: only one acme gave it (Database -> TLS or
    acme --db-agent-mariadb-tls), never one its administrator put in."""
    a = db_agent()
    if not a or a.get('engine') != 'mariadb':
        return None
    had = _meta_obj(store, 'dbtls:server:' + node_name())
    if had.get('engine') != 'mariadb' or not had.get('cert_end'):
        return None
    if float(had['cert_end']) - time.time() >= HATLS_RENEW_DAYS * 86400:
        return None
    return db_agent_mariadb_tls(store, by)


# ---- renewing the agent's certificate and this node's ---------------------------------------
def db_agent_renew(store, by='acme (renewed)', force=False):
    """The agent renews its own certificate (60 days before its end; asked now with force):
    the next one is announced in its signed `status`, pinned here beside the one in use, and
    put in use by the agent once every node joined took it in. This node's client certificate
    from acme's authority is renewed here 45 days before its end: its next one announced to the
    agent with the authorities that issued it (this node's own - another node's are never
    touched), then used."""
    a = db_agent()
    if not a:
        return []
    now = time.time()
    done = []
    if force:
        got = db_agent_call('agent_renew', {})
        nxt = str(got.get('cert_next_fp') or '')
        if re.fullmatch(r'[0-9a-f]{64}', nxt):
            a = db_agent_put({'pins': [x for x in a.get('pins') or [] if x != nxt][:1] + [nxt]})
        # Said to the agent at once: with every node's word it is put in use.
        db_agent_call('status')
        a = db_agent() or a
        done.append('the agent\'s certificate: the next one announced to every node%s' % (
            '' if nxt not in (a.get('pins') or [])[:1] else ', in use now'))
    if force or float(a.get('client_cert_end') or 0) - now < DBAGENT_RENEW_DAYS * 86400:
        ckey, ccrt = hatls_issue(store, [], eku='clientAuth', days=DBAGENT_CERT_DAYS,
                                 cn='acme-' + str(a.get('node') or node_name()))
        trust = hatls_trust(hatls_ca(store))
        try:
            old = (DBAGENT_DIR / 'client-ca.pem').read_text()
        except OSError:
            old = ''
        # The authority of the certificate in use stays beside the new ones until it is
        # replaced: the agent refuses a set its current certificate would not pass.
        both = trust + ''.join(c for c in re.findall(
            r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----\s*', old)
            if c.strip() not in trust)
        db_agent_call('trust', {'ca': both, 'client_cert_new': ccrt})
        for name, text, mode in (('client.key', ckey, 0o600), ('client.crt', ccrt, 0o644),
                                 ('client-ca.pem', trust, 0o644)):
            write_replacing(DBAGENT_DIR / name, text, mode)
            _db_agent_own(DBAGENT_DIR / name, mode)
        db_agent_call('status')         # the new one used once: the agent forgets the old
        db_agent_put({'client_cert_end': _cert_end(ccrt)})
        done.append('this node\'s client certificate')
    if done:
        store.add_event('settings', '%s: renewed for acme-db-agent: %s' % (by, ', '.join(done)),
                        who=by)
    return done


def db_agent_trust_set(store):
    """(the cluster's authorities now, the set told to the agent): every authority of the
    cluster still good, with the one of the client certificate in use beside them (client-ca.pem,
    what it was issued under) - the agent refuses a set it would not pass."""
    trust = hatls_trust(hatls_ca(store))
    try:
        old = (DBAGENT_DIR / 'client-ca.pem').read_text()
    except OSError:
        old = ''
    return trust, trust + ''.join(c for c in re.findall(
        r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----\s*', old)
        if c.strip() not in trust)


def _db_agent_set_hash(pem):
    """The set's own hash: which certificates, in any order."""
    got = sorted(set(re.sub(r'\s+', '', c) for c in re.findall(
        r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----', pem or '')))
    return hashlib.sha256('\n'.join(got).encode()).hexdigest()


def db_agent_trust_sync(store, force=False):
    """This node's agent told its cluster's authorities again (`trust`, no new certificate)
    whenever they differ from what it last told it (1.0.115): a new authority rolled in
    (hatls_ca_make here, or come over from the other node), the node joined a cluster
    (--ha-join). The agent knows which cluster the server's certificate is by them: without
    it the other node's certificate renewed under the new authority was refused as another
    cluster's until this node renewed its own. True when told."""
    a = db_agent()
    if not a:
        return False
    trust, both = db_agent_trust_set(store)
    if not trust.strip():
        return False
    h = _db_agent_set_hash(both)
    if not force and a.get('trust_sent') == h:
        return False
    db_agent_call('trust', {'ca': both})
    db_agent_put({'trust_sent': h})
    return True


# ---- this node at another address (the network job, 1.0.113) -----------------------------------
def db_agent_node_moved(store, old_ip, new_ip, say=None):
    """This node's own address changes while its database is on its agent's server: the new
    address let into the database there (pg_hba.conf, or MariaDB's account at it) and through
    its firewall - before the network is switched, or the node could not reach its database
    afterwards - and the other node told (dbagent:addr:NODE), whose agent lets it in too. The
    old address's lines stay (the network may still go back). Raises ValueError."""
    if not db_agent_here():
        return []
    say = say or (lambda t: None)
    a = db_agent() or {}
    try:
        new_ip = str(plain_ip(str(new_ip), 'address'))
    except ValueError:
        raise ValueError('the new address is one plain address, not %r' % str(new_ip)[:60])
    c = CONFIG
    said = []
    if a.get('engine') == 'mariadb':
        got = db_agent_call('my_allow', {'db': c.get('db_name') or 'acme',
                                         'user': c.get('db_user') or 'acme',
                                         'password': c.get('db_password') or '',
                                         'peers': [new_ip]})
    else:
        got = db_agent_call('pg_allow', {'db': c.get('db_name') or 'acme',
                                         'user': c.get('db_user') or 'acme', 'peers': [new_ip]})
    said += list(got.get('said') or [])
    said += list(db_agent_fw([new_ip], agent=True).get('said') or [])
    for line in said:
        say('the database server: %s' % line)
    store.set_meta('dbagent:addr:' + node_name(), json.dumps(
        {'address': new_ip, 'old': str(old_ip or ''), 'at': time.time()}))
    # Layout B: this node's own address kept (keepalived's unicast_src_ip, the other node's
    # firewall - ha_own_node) follows when it is the one changed (1.0.115); the job going back
    # changes it back the same way.
    own = str(a.get('node_address') or '')
    if db_agent_layout_b() and own and own == str(old_ip or ''):
        db_agent_put({'node_address': new_ip})
    return said


def db_agent_peer_moved(store):
    """The other node said its new address (dbagent:addr:NODE): this node's agent lets it into
    the database and through the firewall (layout B: it opens the other server's database
    from its own address), and peer_node follows. Once for each address."""
    a = db_agent()
    if not a or not db_agent_here() or CONFIG.get('ha_mode') != 'replicated':
        return None
    me = node_name()
    # Only those acme wrote (1.0.135): with db_guard on, one written past acme is not acted on
    # - the agent lets the address in as root.
    rows = store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'dbagent:addr:%'")
    for r in dbguard_rows(store.db, [dict(x) for x in rows]):
        if str(r['k']) == 'dbagent:addr:' + me:
            continue
        try:
            v = json.loads(r['v'] or '{}')
            if not isinstance(v, dict):
                continue                # not one acme wrote: the rows after it still read
            new = str(plain_ip(str(v.get('address') or ''), 'address'))
        except (ValueError, TypeError):
            continue
        had = str(a.get('peer_node') or '')
        if not had or new == had or (v.get('old') and str(v['old']) != had):
            continue
        c = CONFIG
        if a.get('engine') == 'mariadb':
            db_agent_call('my_allow', {'db': c.get('db_name') or 'acme',
                                       'user': c.get('db_user') or 'acme',
                                       'password': c.get('db_password') or '', 'peers': [new]})
        else:
            db_agent_call('pg_allow', {'db': c.get('db_name') or 'acme',
                                       'user': c.get('db_user') or 'acme', 'peers': [new]})
        db_agent_fw([new])
        db_agent_put({'peer_node': new})
        store.add_event('ha', 'the other node is at %s now (was %s): its database server lets '
                        'it in through acme-db-agent' % (new, had), 'info')
        return new
    return None


# ---- watching it (only on a node that has an agent) ----------------------------------------
def db_agent_look(store):
    """One look: is the agent there, what is its server - written into this node's row
    ('dbagent:node:NODE') for every node's pages and alerts."""
    a = db_agent()
    if not a:
        return None
    now = time.time()
    row = {'at': now, 'node': node_name(), 'db_admin': a['db_admin'], 'host': a.get('host'),
           'port': a.get('port'), 'db_host': a.get('db_host'), 'engine': a.get('engine'),
           'agent_cert_end': a.get('agent_cert_end'), 'client_cert_end': a.get('client_cert_end')}
    try:
        got = db_agent_call('status', timeout=20)
        was_down = DBAGENT_STATE['ok'] is False
        DBAGENT_STATE.update(ok=True, fails=0, down_since=0.0, facts=got.get('facts') or {},
                             at=now)
        row.update(ok=True, facts=got.get('facts') or {}, agent=got.get('agent') or {})
        a = db_agent() or a
        row.update(agent_cert_end=(got.get('agent') or {}).get('cert_end') or
                   a.get('agent_cert_end'))
        # The agent of another version than this acme (1.0.113): said on the card, in the
        # status and as an alert - it is upgraded on its server (install.sh --db-agent).
        skew = db_agent_version_skew(got.get('agent') or {})
        row['version_skew'] = skew or None
        if was_down:
            store.add_event('ha', 'the database agent of %s (%s:%s) answers again'
                            % (node_name(), a.get('host'), a.get('port')))
    except ValueError as e:
        DBAGENT_STATE['fails'] += 1
        if not DBAGENT_STATE['down_since']:
            DBAGENT_STATE['down_since'] = now
        row.update(ok=False, said=str(e)[:300], down_since=DBAGENT_STATE['down_since'],
                   fails=DBAGENT_STATE['fails'])
        if DBAGENT_STATE['ok'] is not False and DBAGENT_STATE['fails'] >= 2:
            DBAGENT_STATE['ok'] = False
            store.add_event('ha', 'the database agent of %s (%s:%s) does not answer: %s'
                            % (node_name(), a.get('host'), a.get('port'), str(e)[:200]), 'warn')
        prev = _meta_obj(store, 'dbagent:node:' + node_name())
        if prev.get('facts'):
            row['facts'] = prev['facts']            # the last known, said as old
    store.set_meta('dbagent:node:' + node_name(), json.dumps(row, default=str))
    return row


def db_agent_watch(daemon):
    """The thread of a node with an agent: a look every 30 s, the certificates renewed 45 days
    before they end, the meter's reading of the database server while a page watches."""
    with DBAGENT_LOCK:
        if DBAGENT_STATE.get('watching'):
            return                      # one of them per process
        DBAGENT_STATE['watching'] = True
    last_look = last_renew = 0.0
    while True:
        try:
            if not db_agent_on():
                time.sleep(10)
                continue
            now = time.time()
            if now - last_look >= DBAGENT_EVERY:
                last_look = now
                db_agent_look(daemon.store)
                try:
                    db_agent_peer_moved(daemon.store)
                except Exception as e:                  # noqa: BLE001
                    log_sparing('dbagent-peer', 'letting the other node in at its new address '
                                'through the database agent: %s' % e, 'warn', every=600)
                DBAGENT_STATE['trust_due'] = True
            if DBAGENT_STATE.get('trust_due'):
                # The cluster's authorities told the agent again when they changed (a new one
                # rolled in here or on the other node): every look, at once after a roll here.
                DBAGENT_STATE['trust_due'] = False
                try:
                    db_agent_trust_sync(daemon.store)
                except Exception as e:                  # noqa: BLE001
                    log_sparing('dbagent-trust', 'telling the database agent the cluster\'s '
                                'authorities: %s' % e, 'warn', every=600)
            if now - last_renew >= 3600:
                last_renew = now
                try:
                    db_agent_renew(daemon.store)
                except Exception as e:                  # noqa: BLE001
                    log_sparing('dbagent-renew', 'renewing the database agent\'s certificates: '
                                '%s' % e, 'warn', every=3600)
                try:
                    db_agent_mariadb_renew(daemon.store)
                except Exception as e:                  # noqa: BLE001
                    log_sparing('dbagent-mytls', 'renewing the certificate of MariaDB through '
                                'its agent: %s' % e, 'warn', every=3600)
            if CONFIG.get('perf_meter') and CONFIG.get('ha_mode') and any(
                    float(v.get('until') or 0) > now for v in LOAD_WATCH['rows'].values()):
                db_agent_load_put(daemon.store)
        except Exception as e:                          # noqa: BLE001
            log_sparing('dbagent-watch', 'watching the database agent: %s' % e, 'warn', every=600)
        time.sleep(2)


@hook('daemon_start')
def _db_agent_start(daemon):
    if not db_agent_on():
        return                          # db_admin local: nothing of it runs
    log('the database server is looked after through acme-db-agent (%s)' % db_admin())
    threading.Thread(target=db_agent_watch, args=(daemon,), name='dbagent', daemon=True).start()


# ---- the meter in the header: the database servers beside the nodes ---------------------------
def db_agent_load(fresh=False):
    """This node's database server, in the shape of server_load() (and its database's own)."""
    now = time.time()
    if not fresh and DBAGENT_STATE['load'] and now - DBAGENT_STATE['load_at'] < 2.5:
        return DBAGENT_STATE['load']
    got = db_agent_call('load', {'db': CONFIG.get('db_name') or 'acme'}, timeout=10)
    got.pop('said', None)
    DBAGENT_STATE.update(load=got, load_at=now)
    return got


def db_agent_load_put(store):
    if time.time() - float(DBAGENT_STATE.get('put_at') or 0) < 4:
        return
    DBAGENT_STATE['put_at'] = time.time()
    try:
        v = dict(db_agent_load())
    except ValueError as e:
        v = {'at': time.time(), 'down': True, 'said': str(e)[:200]}
    v.update(kind='db', node=node_name(), host=db_agent_db_host())
    store.set_meta('load:db:' + node_name(), json.dumps(v, default=str))


def db_agent_load_rows(store):
    """The database servers for /api/load: this node's read now, the others' from their rows -
    each {kind: 'db', name: 'db of NODE', node, host, cpu, mem_used, ... , db: {...}}."""
    out = []
    me = node_name()
    if db_agent_on():
        try:
            v = dict(db_agent_load())
        except ValueError as e:
            v = {'at': time.time(), 'down': True, 'said': str(e)[:200]}
        v.update(kind='db', node=me, host=db_agent_db_host(), age=0.0)
        out.append(v)
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'load:db:%'"):
        n = str(r['k'])[len('load:db:'):]
        if n == me:
            continue
        try:
            v = json.loads(r['v'] or '{}')
            if not isinstance(v, dict):
                continue
            age = time.time() - float(v.get('at') or 0)
        except (ValueError, TypeError):
            continue
        if age > 3600:
            continue
        v.update(kind='db', node=n, age=round(age, 1))
        out.append(v)
    for v in out:
        v['name'] = 'db:%s' % v['node']
        # The server's own short name, for the meter's row (1.0.113): from its agent's facts.
        f = _meta_obj(store, 'dbagent:node:' + v['node']).get('facts') or {}
        v['server'] = str(f.get('host') or '').split('.')[0][:40]
        v.setdefault('engine', f.get('engine') or '')
    out.sort(key=lambda x: x['node'])
    return out


# ---- what the pages and the cards are given ---------------------------------------------------
def db_agent_servers(store):
    """Every database server looked after by an agent, in the shape of a node of the cards'
    dots (name, me, alive) with kind 'db': [{kind, name, node, me, alive, host, db_host, port,
    engine, ok, said, down_since, at, facts{version, running, ssl, wal_level, connections,
    disk{total, free}, ram, cpus, load, uptime}, agent{version, cert_end, clients}, ...}]."""
    out = []
    try:
        rows = store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'dbagent:node:%'")
    except Exception:                                   # noqa: BLE001
        rows = []
    # Of the nodes of this cluster only (hunt R2, as db_local_rows): the row of a node forgotten
    # (acme --ha-forget, the HA card) or renamed stayed for good - a server of nobody's on the
    # cards and in the metrics, and its alerts (its agent "not answering", its certificate
    # "ending") with nothing that could take them away.
    try:
        nodes = set(host_nodes(store))
    except Exception:                                   # noqa: BLE001
        nodes = None
    now = time.time()
    for r in rows:
        try:
            v = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if not isinstance(v, dict):
            continue
        n = str(r['k'])[len('dbagent:node:'):]
        if nodes is not None and n not in nodes:
            continue
        fresh = now - float(v.get('at') or 0) < max(3 * DBAGENT_EVERY, 120)
        v.update(kind='db', name='db:%s' % n, node=n, me=n == node_name(),
                 alive=bool(v.get('ok')) and fresh, stale=not fresh)
        out.append(v)
    out.sort(key=lambda x: x['node'])
    return out


def db_agent_view(store):
    a = db_agent()
    view = {'db_admin': db_admin(), 'node': node_name(), 'servers': db_agent_servers(store)}
    if a:
        view.update(host=a.get('host'), port=a.get('port'), db_host=a.get('db_host'),
                    engine=a.get('engine'),
                    # the database's own port there, as the agent said it at the join (1.0.113):
                    # the move wizard opened from the card is filled in with it
                    db_port=a.get('my_port' if a.get('engine') == 'mariadb' else 'pg_port'), joined_at=a.get('at'), joined_by=a.get('by'),
                    peer_node=a.get('peer_node') or '',
                    # layout B: the agent is not let go (1.0.115) - the card hides Forget
                    forget_refused=db_agent_forget_refused(),
                    agent_cert_end=a.get('agent_cert_end'),
                    client_cert_end=a.get('client_cert_end'),
                    state={'ok': DBAGENT_STATE['ok'], 'down_since': DBAGENT_STATE['down_since'],
                           'fails': DBAGENT_STATE['fails'], 'at': DBAGENT_STATE['at']})
    # Which settings reach a database server too (their cards draw it beside the nodes).
    view['applies'] = DBAGENT_APPLIES
    # For the card of Settings -> The database and its wizard (1.0.113): where the database is
    # now - this machine, the agent's server, or a server no agent looks after - and the
    # addresses of this node the database server lets in (install.sh --acme-node).
    view['where'] = db_agent_where()
    view['ha_mode'] = CONFIG.get('ha_mode') or ''
    view['addresses'] = db_agent_node_addresses(store)
    # This machine's database as a database server (1.0.115, db_local_card): `local` only with
    # the setting on and no agent - off, the view is as it was.
    return db_local_into(store, view)


def db_agent_where():
    c = CONFIG
    engine = str(c.get('db_engine') or 'sqlite')
    host = str(c.get('db_host') or '')
    local = engine == 'sqlite' or host.strip('[]').lower() in ('', 'localhost', '127.0.0.1', '::1') \
        or host.startswith('/')
    out = {'engine': engine, 'host': host, 'port': c.get('db_port') or '',
           'name': c.get('db_name') or '', 'local': local, 'agent': False}
    try:
        out['agent'] = bool(db_agent_on() and engine != 'sqlite' and db_agent_is_target(c))
    except Exception:                                   # noqa: BLE001
        pass
    if out['agent']:
        out['kind'] = 'agent'           # a server of its own, looked after by its agent
    elif local and engine != 'sqlite':
        out['kind'] = 'here'            # PostgreSQL or MariaDB on this machine (the root helper)
    elif engine == 'sqlite':
        out['kind'] = 'file'
    else:
        out['kind'] = 'unmanaged'       # a server elsewhere, its administrator's
    return out


def db_agent_node_addresses(store=None):
    """This node's own addresses, the one it reaches the outside with first (no loopback, no
    link-local, not the VIP address)."""
    out = []
    first = node_address()
    if first:
        out.append(first)
    try:
        vip = str((vip_conf(store) or {}).get('address') or '').split('/')[0] if store else ''
    except Exception:                                   # noqa: BLE001
        vip = ''
    try:
        more = sorted(local_addresses(), key=lambda x: (':' in x, x))
    except Exception:                                   # noqa: BLE001
        more = []
    for x in more:
        try:
            ip = ipaddress.ip_address(x)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or x == vip or x in out:
            continue
        out.append(x)
    return out[:6]


# The cards whose dots show the database servers too (docs/external-database.md, "The pages").
DBAGENT_APPLIES = {
    'dbtls': 'the database\'s certificate from acme\'s authority, ssl on, its renewal',
    'ha_link': 'the link between the databases: certificate, verify-full, pg_hba hostssl',
    'ha_replication': 'wal_level, listen_addresses, the account, the publication',
    'db_firewall': 'the database\'s port opened to the acme nodes and the other server',
    'db_tune': 'the database server\'s own settings and their restart',
    'db_errors': 'PostgreSQL\'s log of the replication',
    'perf_meter': 'how busy the database server is',
}


@route('GET', '/api/db-agent')
def _db_agent_get(h):
    h.me('readonly')
    return db_agent_view(h.store)


@route('POST', '/api/db-agent')
def _db_agent_post(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    by = s['name']
    try:
        if act == 'join':
            got = db_agent_join(h.store, str(b.get('code') or ''), str(b.get('address') or ''),
                                str(b.get('db_host') or ''), by=by)
            threading.Thread(target=db_agent_watch, args=(h.d,), name='dbagent',
                             daemon=True).start()
            return dict(got, view=db_agent_view(h.store))
        if act == 'look':
            if not db_agent_on() and db_local_on():
                # this machine's database server, looked at now (1.0.115, db_local_card)
                return {'row': db_local_look(h.store), 'view': db_agent_view(h.store)}
            return {'row': db_agent_look(h.store), 'view': db_agent_view(h.store)}
        if act == 'renew':
            return {'done': db_agent_renew(h.store, by, force=True), 'view': db_agent_view(h.store)}
        if act == 'restart':
            got = db_agent_restart()
            h.store.add_event('settings', '%s restarted the database server through its agent'
                              % by, 'warn', who=by)
            return {'message': got.get('said') or '', 'view': db_agent_view(h.store)}
        if act == 'mariadb_tls':
            return {'message': db_agent_mariadb_tls(h.store, by).get('said') or '',
                    'view': db_agent_view(h.store)}
        if act == 'forget':
            refused = db_agent_forget_refused()
            if refused:
                raise ApiError(409, refused)
            left = db_agent_forget(h.store, by)
            return {'view': db_agent_view(h.store), 'left': bool(left),
                    'message': db_agent_left_words(left)}
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'the action is join, look, renew, restart, mariadb_tls or forget')


# ---- alerts, metrics, status (only with an agent) ---------------------------------------------
@hook('alerts')
def _db_agent_alerts(store, lang='en'):
    """The database servers looked after by agents (1.0.113), in the alert's language: the
    pages read them in English and say them in the page's own; a mail goes in alerts_lang()."""
    out = []
    if not db_agent_on() and not CONFIG.get('ha_mode'):
        return out
    now = time.time()
    cs = lang == 'cs'
    for v in db_agent_servers(store) if db_agent_on() else []:
        n = v['node']
        where = '%s:%s' % (v.get('host'), v.get('port'))
        if v.get('ok') is False and now - float(v.get('down_since') or now) >= DBAGENT_DOWN_S:
            since = datetime.fromtimestamp(float(v['down_since'])).strftime('%Y-%m-%d %H:%M')
            out.append({'key': 'dbagent:' + n, 'level': 'bad', 'node': n, 'pane': 'db',
                        'title': ('Agent databázového serveru uzlu %s neodpovídá' % n) if cs else
                                 ('The database agent of %s does not answer' % n),
                        'words': ('acme-db-agent na %s neodpovídá od %s: %s. Databázový server '
                                  'teď acme nemůže obnovovat ani měnit (certifikát, nastavení, '
                                  'restart); databáze sama může běžet dál - podívejte se na '
                                  'server (systemctl status acme-db-agent).'
                                  % (where, since, v.get('said') or '?')) if cs else
                                 ('acme-db-agent at %s has not answered since %s: %s. acme can '
                                  'neither renew nor change its database server meanwhile (the '
                                  'certificate, the settings, a restart); the database itself may '
                                  'well go on - look at the server (systemctl status '
                                  'acme-db-agent).' % (where, since, v.get('said') or '?'))})
        elif v.get('ok') and (v.get('facts') or {}).get('running') is False:
            said = (v.get('facts') or {}).get('said') or '?'
            out.append({'key': 'dbserver:' + n, 'level': 'bad', 'node': n, 'pane': 'db',
                        'title': ('Databázový server uzlu %s neběží' % n) if cs else
                                 ('The database server of %s is down' % n),
                        'words': ('jeho agent (%s) odpovídá, databáze ne: %s' % (where, said))
                                 if cs else ('its agent (%s) answers, the database does not: %s'
                                             % (where, said))})
        elif v.get('ok') and db_agent_cert_late(v, now):
            end = datetime.fromtimestamp(float(v['agent_cert_end'])).strftime('%Y-%m-%d')
            days = int((v.get('agent') or {}).get('force_days') or DBAGENT_FORCE_DAYS)
            out.append({'key': 'dbagent:cert:' + n, 'level': 'warn', 'node': n, 'pane': 'db',
                        'title': ('Certifikát agenta databázového serveru uzlu %s brzy vyprší'
                                  % n) if cs else
                                 ('The certificate of the database agent of %s ends soon' % n),
                        'words': ('vyprší %s; agent si další dělá sám 60 dní předem a sám na něj '
                                  'přejde %d dní před koncem (dřív, jakmile ho vzaly všechny uzly), '
                                  'a to se nestalo - Nastavení → Databáze → Databázový server → '
                                  'Obnovit certifikáty' % (end, days)) if cs else
                                 ('it ends %s; the agent makes the next one by itself 60 days '
                                  'before and switches by itself %d days before the end (sooner, '
                                  'once every node took it in), and that did not happen - '
                                  'Settings → The database → Database server → Renew the '
                                  'certificates' % (end, days))})
        if v.get('ok') and float(v.get('client_cert_end') or now + 1e9) - now < 14 * 86400:
            # This node's client certificate too (1.0.113): ended, the agent no longer lets the
            # node in.
            end = datetime.fromtimestamp(float(v['client_cert_end'])).strftime('%Y-%m-%d')
            out.append({'key': 'dbagent:client:' + n, 'level': 'warn', 'node': n, 'pane': 'db',
                        'title': ('Klientský certifikát uzlu %s pro agenta databázového serveru '
                                  'brzy vyprší' % n) if cs else
                                 ('The client certificate of %s for its database agent ends soon'
                                  % n),
                        'words': ('vyprší %s; obnovuje se sám 45 dní předem, a to se nepovedlo - '
                                  'bez něj agent uzel nepustí. Nastavení → Databáze → Databázový '
                                  'server → Obnovit certifikáty (acme --db-agent-renew)' % end)
                                 if cs else
                                 ('it ends %s; it is renewed by itself 45 days before, and that '
                                  'did not work - without it the agent no longer lets the node '
                                  'in. Settings → The database → Database server → Renew the '
                                  'certificates (acme --db-agent-renew)' % end)})
        skew = v.get('version_skew') or {}
        if v.get('ok') and skew.get('agent'):
            how = skew.get('how') or 'older'
            out.append({'key': 'dbagent:version:' + n, 'level': 'warn', 'node': n, 'pane': 'db',
                        'title': ({'newer': 'Agent databázového serveru uzlu %s je novější než '
                                            'acme',
                                   'other': 'Agent databázového serveru uzlu %s není ten, který '
                                            'acme dodává'}.get(how, 'Agent databázového serveru '
                                                              'uzlu %s má jinou verzi než acme')
                                  % n) if cs else
                                 ({'newer': 'The database agent of %s is newer than acme',
                                   'other': 'The database agent of %s is not the one acme '
                                            'ships'}.get(how, 'The database agent of %s is '
                                                          'another version than acme') % n),
                        'words': db_agent_skew_words(skew, cs)})
    return out


DBAGENT_FORCE_DAYS = 7          # the agent's AGENT_FORCE_DAYS: it switches by itself then


def db_agent_cert_late(v, now=None):
    """The agent's certificate ends within 14 days and the agent did not do what it does by
    itself (1.0.115, as the agent does it): no next one announced - or one announced and the
    switch to it, due 7 days before the end at the latest, not done. Within 14 days with the
    next one announced is no alert: it switches by itself."""
    now = time.time() if now is None else now
    end = float(v.get('agent_cert_end') or now + 1e9)
    if end - now >= 14 * 86400:
        return False
    ag = v.get('agent') or {}
    days = float(ag.get('force_days') or DBAGENT_FORCE_DAYS)
    if ag.get('cert_next_fp') and end - now > days * 86400 - 3600:
        return False
    return True


@hook('metrics')
def _db_agent_metrics(store):
    if not db_agent_on():
        return []
    rows = db_agent_servers(store)
    return [('acme_db_agent_up', 'Whether the database agent of a node answers (1) or not (0)',
             'gauge', [({'node': v['node'], 'host': str(v.get('host') or '')},
                        1 if v.get('alive') else 0) for v in rows]),
            ('acme_db_server_up', 'Whether the database server behind the agent runs',
             'gauge', [({'node': v['node']}, 1 if (v.get('facts') or {}).get('running') else 0)
                       for v in rows])]


@hook('status')
def _db_agent_status_lines(store, pal):
    a = db_agent()
    if not a:
        return []
    row = _meta_obj(store, 'dbagent:node:' + node_name())
    f = row.get('facts') or {}
    ok = row.get('ok')
    words = '  database server: %s through acme-db-agent %s:%s - %s' % (
        a.get('db_host'), a.get('host'), a.get('port'),
        ('answers; %s %s' % (f.get('engine'), f.get('version') or '')) if ok else
        ('does NOT answer: %s' % (row.get('said') or '?')) if ok is False else 'not looked at yet')
    out = [words]
    skew = row.get('version_skew') or {}
    if ok and skew.get('agent'):
        out.append('  database agent: %s' % db_agent_skew_words(skew))
    ag = row.get('agent') or {}
    gone = [x.get('name') for x in ag.get('clients') or [] if isinstance(x, dict) and
            x.get('stale')]
    if ok and gone:
        out.append('  database agent: not heard from for %s days, not waited for: %s - take a '
                   'node gone for good away there (acme_db_agent.py --forget NODE)'
                   % (ag.get('stale_days') or 30, ', '.join(map(str, gone))))
    if ok and ag.get('busy'):
        b = ag['busy']
        out.append('  database agent: busy with %s for %s since %s' % (
            b.get('op'), b.get('node'), datetime.fromtimestamp(float(b.get('since') or 0))
            .strftime('%H:%M:%S')))
    return out


# ---- the command line -------------------------------------------------------------------------
@hook('cli_args')
def _db_agent_cli_args(p):
    g = p.add_argument_group('THE DATABASE ON A SERVER OF ITS OWN (acme-db-agent)')
    g.add_argument('--db-agent-join', metavar='-', nargs='?', const='-', help='this node joins '
                   'the database agent of a code (acme_db_agent.py --new-code on the database '
                   'server prints it), read from standard input (or ACME_DB_AGENT_CODE) - never '
                   'put on the command line, where every account sees it; its database server '
                   'is looked after through it from then on (as root)')
    g.add_argument('--db-agent', metavar='HOST[:PORT]', help='--db-agent-join: the agent\'s '
                   'address as this node reaches it, when not the one in the code')
    g.add_argument('--db-agent-db-host', metavar='HOST', help='--db-agent-join: the database '
                   'server\'s address as this node reaches it (the agent\'s by default)')
    g.add_argument('--db-agent-status', action='store_true', help='this node\'s database agent '
                   'and its server: answering, versions, certificates (--json)')
    g.add_argument('--db-agent-renew', action='store_true', help='the agent\'s certificate and '
                   'this node\'s client certificate renewed now')
    g.add_argument('--db-agent-restart', action='store_true', help='the database server '
                   'started again through its agent')
    g.add_argument('--db-agent-mariadb-tls', action='store_true', help='MariaDB on the agent\'s '
                   'server given a certificate from acme\'s authority')
    g.add_argument('--db-agent-forget', action='store_true', help='back to looking after a '
                   'database on this machine (db_admin local), the agent told this node leaves '
                   'it - with --yes; refused while this node\'s database is on the agent\'s '
                   'server in a cluster')
    g.add_argument('--db-agent-leave', action='store_true', help='this node is being taken '
                   'away for good (before install.sh --uninstall, which keeps the join): the '
                   'agent takes it off its list and the node forgets it - with --yes; refused '
                   'in layout B, as --db-agent-forget is')
    g.add_argument('--ha-peer-node', metavar='ADDRESS', help='--ha-setup with the databases on '
                   'servers of their own: the other acme node\'s address (its database server '
                   'is --ha-peer)')


@hook('cli_run')
def _db_agent_cli(args):
    if not any(getattr(args, k, None) for k in (
            'db_agent_join', 'db_agent_status', 'db_agent_renew', 'db_agent_restart',
            'db_agent_mariadb_tls', 'db_agent_forget', 'db_agent_leave')):
        return None
    ok_line = (lambda t: print('  ok   ' + t))
    os.environ['ACME_STAY_ROOT'] = '1'
    # config.json first, as cli_store() does (1.0.113): the database it names is opened - not
    # the defaults' SQLite file, made anew on a node whose database is elsewhere, with an
    # authority of its own written over /etc/pki/acme/ha-ca.pem and certificates issued from it.
    load_config(saved=None)
    try:
        store = Storage(open_db())
    except DbError as e:
        raise SystemExit('acme: %s' % e)
    load_config(saved=store.settings_saved())
    HA_STORE['store'] = store
    if args.db_agent_join:
        if os.geteuid() != 0 and not os.environ.get('ACME_DBAGENT_ANY_USER'):
            raise SystemExit('acme: run this as root - it writes this node\'s keys')
        if str(args.db_agent_join).strip() not in ('', '-'):
            # Still taken, for what was written before (1.0.113) - but said.
            print('acme: WARNING: the join code was given on the command line, where every '
                  'account on this machine sees it (ps) and the shell keeps it in its history - '
                  'paste it on standard input instead: acme --db-agent-join -', file=sys.stderr)
        try:
            got = db_agent_join(store, db_agent_code_read(args.db_agent_join), args.db_agent or '',
                                args.db_agent_db_host or '', say=ok_line)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        f = got.get('facts') or {}
        if not got.get('late'):
            ok_line('the database server: %s %s, %s' % (
                f.get('engine'), f.get('version') or '',
                'running' if f.get('running') else 'NOT running'))
        ok_line('db_admin = agent:%s:%s (%s)' % (got['host'], got['port'], DBAGENT_FILE))
        if not os.environ.get('ACME_HA_NO_RESTART') and os.geteuid() == 0:
            subprocess.run(['systemctl', 'restart', 'acme'], capture_output=True)
        return 0
    if args.db_agent_forget or getattr(args, 'db_agent_leave', False):
        if not db_agent_on():
            print('acme: db_admin was local already')
            return 0
        # --db-agent-leave too (1.0.115): never in layout B, whatever is asked - the other
        # node, the VIP address and the replication rest on this node's agent there.
        refused = db_agent_forget_refused()
        if refused:
            raise SystemExit('acme: %s' % refused)
        if not args.yes:
            raise SystemExit('acme: the database server is then looked after as one on this '
                             'machine (the root helper) - again with --yes')
        try:
            left = db_agent_forget(store, 'command line', 'this node is being taken away'
                                   if getattr(args, 'db_agent_leave', False) else '')
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        print('acme: db_admin is local again; %s' % db_agent_left_words(left))
        return 0
    if not db_agent_on():
        raise SystemExit('acme: this node has no database agent (db_admin is local)')
    try:
        if args.db_agent_renew:
            for x in db_agent_renew(store, 'command line', force=True):
                ok_line('renewed: %s' % x)
            return 0
        if args.db_agent_restart:
            ok_line(db_agent_restart().get('said') or 'started again')
            return 0
        if args.db_agent_mariadb_tls:
            ok_line(db_agent_mariadb_tls(store, 'command line').get('said') or 'done')
            return 0
        row = db_agent_look(store)
    except ValueError as e:
        raise SystemExit('acme: %s' % e)
    if args.json:
        print(json.dumps(db_agent_view(store), indent=1, default=str))
        return 0 if row.get('ok') else 1
    f = row.get('facts') or {}
    ag = row.get('agent') or {}
    print('db_admin: %s' % db_admin())
    print('  agent:    %s' % ('answers, acme-db-agent %s, its certificate ends %s' % (
        ag.get('version'), datetime.fromtimestamp(float(ag['cert_end'])).strftime('%Y-%m-%d')
        if ag.get('cert_end') else '?') if row.get('ok') else 'does NOT answer: %s'
        % row.get('said')))
    if (row.get('version_skew') or {}).get('agent'):
        print('  NOTE:     %s' % db_agent_skew_words(row['version_skew']))
    for x in ag.get('clients') or []:
        if isinstance(x, dict):
            print('  node:     %s%s' % (x.get('name'), ' - not heard from for %s days, not waited '
                                         'for (acme_db_agent.py --forget %s there if it is gone)'
                                         % (ag.get('stale_days') or 30, x.get('name'))
                                         if x.get('stale') else ''))
    if f:
        print('  server:   %s %s on %s - %s, TLS %s' % (
            f.get('engine'), f.get('version') or '', f.get('host'),
            'running' if f.get('running') else 'NOT running', 'on' if f.get('ssl') else 'off'))
        if f.get('disk'):
            print('  disk:     %s free of %s' % (bytes_words(f['disk'].get('free')),
                                                bytes_words(f['disk'].get('total'))))
    return 0 if row.get('ok') else 1
