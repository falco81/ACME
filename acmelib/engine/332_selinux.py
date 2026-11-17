# ---------------------------------------------------------------------------
# SELinux (as otp 1.0.233 - 1.0.238; 1.0.59: as otp 1.0.265)
# ---------------------------------------------------------------------------
# Settings → High security, a card per node. The page writes 'host:selinux:want:NODE'
# (check, prepare, enforce, permissive, report); that node's daemon has its root helper do it
# and says how SELinux is there in 'host:selinux:now:NODE' - looked at again every half hour.
# Nothing changes unless somebody asks: a machine with SELinux disabled stays so.
# The first look two minutes after the start, not at once: the helper's semanage and
# ausearch take a core for seconds, beside a daemon that has just begun to answer.
SE_WORK = {'busy': False, 'seen': time.time() - 1800 + 120, 'tried': ''}
SE_ACTIONS = ('check', 'prepare', 'enforce', 'permissive', 'report', 'fix', 'rule_drop')
SE_STEPS = ('prepare', 'enforce', 'permissive')
# What SELinux refuses, put right by the ids the node found it under (1.0.120, as fake-igd's kit):
# ids are a node's own - each node finds, and puts right, only what its own audit log says.
SE_ID_RE = re.compile(r'^[0-9a-f]{12}\Z')
SE_FIX_MOST = 200
SE_REPORT_KEEP_S = 3600        # a report in the database an hour at most
SE_REPORT_MOST = 4 * 1024 * 1024
SE_EVERY = 1800


def selinux_want(store):
    """What acme needs of SELinux on this node: the booleans and the ports, and why."""
    bools = [{'name': 'httpd_can_network_connect',
              'why': 'the pages ask the daemon on 127.0.0.1:%s' % (CONFIG.get('api_port') or 9861)}]
    ports = []
    try:
        if ssh_gate_wanted(store):
            # Signing in over SSH with a code (316): sshd's pam_radius asks acme's gate.
            bools.append({'name': 'authlogin_radius', 'why': 'SSH asks acme for the code'})
            p = ssh_gate_port(store)
            if p not in (1812, 1813, 1645, 1646):
                ports.append({'port': p, 'proto': 'udp', 'type': 'radius_port_t',
                              'why': 'SSH asks acme for the code on this port'})
    except Exception:                                   # noqa: BLE001
        pass
    try:
        now = _meta_obj(store, 'host:sshd:now:' + node_name())
        sp = int((now.get('values') or {}).get('port') or 22)
        if sp != 22:
            ports.append({'port': sp, 'proto': 'tcp', 'type': 'ssh_port_t',
                          'why': 'the SSH server listens on it'})
    except (TypeError, ValueError):
        pass
    eng = CONFIG.get('db_engine')
    host = str(CONFIG.get('db_host') or '').strip().lower()
    try:
        dp = int(CONFIG.get('db_port') or 0)
    except (TypeError, ValueError):
        dp = 0
    if eng == 'postgres' and host in ('', '127.0.0.1', 'localhost', '::1') and dp not in (0, 5432):
        ports.append({'port': dp, 'proto': 'tcp', 'type': 'postgresql_port_t',
                      'why': 'PostgreSQL of this node listens on it'})
    # MariaDB of this node on a port of its own (1.0.42): mysqld_t may bind only mysqld_port_t.
    if eng == 'mariadb' and host in ('', '127.0.0.1', 'localhost', '::1') and dp not in (0, 3306):
        ports.append({'port': dp, 'proto': 'tcp', 'type': 'mysqld_port_t',
                      'why': 'MariaDB of this node listens on it'})
    # acme's own listeners - the API (api_port), the DNS server (dns_port), the SNMP agent
    # (snmp_port), the gate for SSH - are the daemon's, unconfined_service_t: SELinux does not
    # hold them to a port type, nothing to label. nginx listens on 80 and 443 only (no port of a
    # balancer of its own), which http_port_t has already.
    # The other node's PostgreSQL (1.0.59, as otp 1.0.265): this node's subscription is
    # PostgreSQL's own worker (postgresql_t), which may connect only to a port labelled
    # postgresql_port_t here - the other node on a port other than 5432 stops replication under
    # enforcing ("postgresql_t -> unreserved_port_t tcp_socket { name_connect }"). Asked last: a
    # port of another service is refused and stops the ports after it.
    pp = _se_int(CONFIG.get('ha_peer_port') or 5432)
    if eng == 'postgres' and CONFIG.get('ha_mode') == 'replicated' and CONFIG.get('ha_peer') and \
            pp != 5432 and 1 <= pp <= 65535 and \
            not any(p['port'] == pp and p['proto'] == 'tcp' for p in ports):
        ports.append({'port': pp, 'proto': 'tcp', 'type': 'postgresql_port_t',
                      'why': 'PostgreSQL of this node replicates from the other node\'s on it'})
    return {'booleans': bools, 'ports': ports, 'node': node_name(), 'facts': selinux_facts(store),
            'mine': selinux_mine(store)}


def selinux_mine(store):
    """acme's own ports on this node (1.0.120), for root's analysis of what SELinux refuses: whose a
    refusal is - acme's or another program's. Never a fix: root works those out itself."""
    out = []

    def add(p, proto, why):
        p = _se_int(p)
        if 1 <= p <= 65535 and not any(x['port'] == p and x['proto'] == proto for x in out):
            out.append({'port': p, 'proto': proto, 'why': why})
    add(CONFIG.get('api_port') or 9861, 'tcp', 'the API (the pages ask the daemon on it)')
    if CONFIG.get('snmp'):
        add(CONFIG.get('snmp_port') or 161, 'udp', 'acme\'s SNMP agent')
    if CONFIG.get('dns_server'):
        add(CONFIG.get('dns_port') or 53, 'udp', 'acme\'s DNS server')
        add(CONFIG.get('dns_port') or 53, 'tcp', 'acme\'s DNS server')
    gp = _se_gate_port(store)
    if gp:
        add(gp, 'udp', 'the gate for SSH with a code')
    if CONFIG.get('admin_certlogin') or CONFIG.get('portal_certlogin'):
        add(CONFIG.get('certlogin_port') or 8443, 'tcp', 'the certificate sign-in')
    try:
        now = _meta_obj(store, 'host:sshd:now:' + node_name())
        add((now.get('values') or {}).get('port') or 22, 'tcp', 'sshd (the console)')
    except (TypeError, ValueError, AttributeError):
        pass
    if CONFIG.get('ha_mode') and CONFIG.get('ha_peer'):
        add(CONFIG.get('ha_peer_port') or 5432, 'tcp', 'the other node\'s PostgreSQL (the replication)')
    if str(CONFIG.get('db_host') or '').strip().lower() in ('', '127.0.0.1', 'localhost', '::1') and \
            CONFIG.get('db_engine') in ('postgres', 'mariadb'):
        add(CONFIG.get('db_port') or (5432 if CONFIG.get('db_engine') == 'postgres' else 3306), 'tcp',
            'the database of this node')
    return out[:32]


def _se_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def selinux_facts(store):
    """What acme uses on this node, for the report: switches and ports only - nothing secret."""
    def on(k):
        return bool(CONFIG.get(k))
    try:
        kinds = sorted({str(t.get('kind') or '') for t in rb_targets(store) if t.get('enabled')})
    except Exception:                                   # noqa: BLE001
        kinds = []
    return {'acme': __version__, 'ha_mode': CONFIG.get('ha_mode') or '',
            'db_engine': CONFIG.get('db_engine'),
            'db_local': str(CONFIG.get('db_host') or '').strip().lower() in ('', '127.0.0.1', 'localhost', '::1'),
            'db_port': CONFIG.get('db_port') or 0, 'api_port': CONFIG.get('api_port') or 9861,
            'isemon': on('isemon'), 'siem': on('siem'), 'metrics': on('metrics'),
            'snmp': on('snmp'), 'tls_by_acme': on('acme'), 'acme_challenge': CONFIG.get('acme_challenge') or '',
            'mail_mode': CONFIG.get('mail_mode') or '', 'sms_mode': CONFIG.get('sms_mode') or '',
            'proxy': on('proxy'), 'remote_backups': kinds, 'db_guard': on('db_guard'),
            'high_security': on('high_security'), 'ssh_with_a_code': _se_gate(store),
            # acme's own listeners and the link to the other node (1.0.59): ports only.
            'dns_server': on('dns_server'), 'dns_port': CONFIG.get('dns_port') or 53,
            'snmp_port': CONFIG.get('snmp_port') or 161, 'ssh_gate_port': _se_gate_port(store),
            'ha_peer_port': CONFIG.get('ha_peer_port') or 0, 'ha_tls': CONFIG.get('ha_tls') or ''}


def _se_gate_port(store):
    try:
        return ssh_gate_port(store) if ssh_gate_wanted(store) else 0
    except Exception:                                   # noqa: BLE001
        return 0


def _se_gate(store):
    try:
        return bool(ssh_gate_wanted(store))
    except Exception:                                   # noqa: BLE001
        return False


def selinux_view(store):
    """Every node's SELinux as that node found it (1.0.120: with what it refuses, sorted) - each
    node's own: in a cluster nothing of one is ever done on the other."""
    beats = {n['name']: n for n in ha_nodes(store)}
    nodes = [node_name()] + [n for n in beats if n != node_name()]
    out = []
    for n in nodes:
        now = _meta_obj(store, 'host:selinux:now:' + n)
        want = _meta_obj(store, 'host:selinux:want:' + n)
        pending = want.get('do') if want and want.get('id') != now.get('done') else ''
        out.append({'name': n, 'me': n == node_name(), 'state': now.get('data') or {},
                    'at': now.get('at'), 'error': now.get('error') or '',
                    'said': now.get('said') or [], 'action': now.get('action') or '',
                    'alive': True if n == node_name() else bool((beats.get(n) or {}).get('alive')),
                    'pending': pending, 'pending_ids': (want.get('ids') or []) if pending else [],
                    'by': now.get('by') or ''})
    return {'nodes': out, 'reports': selinux_reports(store), 'cluster': len(out) > 1}


def _se_pending(store, node):
    """What was asked of a node and is not done yet (within the hour): its row, or {}."""
    was = _meta_obj(store, 'host:selinux:want:' + node)
    now = _meta_obj(store, 'host:selinux:now:' + node)
    try:
        at = float(was.get('at') or 0)
    except (TypeError, ValueError):
        at = 0.0
    return was if was and was.get('id') != now.get('done') and time.time() - at < 3600 else {}


def selinux_ids(store, node, action, ids):
    """The ids asked for, checked against what that node itself found: a fix only of what its own
    look found fixable, a rule taken away only of its own local module. An id of the other node's is
    refused - each node's ids are its own."""
    if not isinstance(ids, list) or not ids or len(ids) > SE_FIX_MOST or \
            not all(isinstance(i, str) and SE_ID_RE.match(i) for i in ids):
        raise ValueError('ids: 1 to %d ids of what was found, each 12 of 0-9 a-f' % SE_FIX_MOST)
    ids = list(dict.fromkeys(ids))
    data = _meta_obj(store, 'host:selinux:now:' + node).get('data') or {}
    if action == 'fix':
        have = {f.get('id') for f in data.get('findings') or [] if f.get('fixable')}
    else:
        have = {r.get('id') for r in (data.get('local') or {}).get('rules') or []}
    bad = [i for i in ids if i not in have]
    if bad:
        raise ValueError('%s did not find %s %s - look again on that node (each node puts right only what '
                         'it found itself)' % (node, 'anything to put right under' if action == 'fix'
                                              else 'a local rule of', ', '.join(bad[:5])))
    return ids


def selinux_ask(store, node, action, by, ids=None):
    known = [node_name()] + [n['name'] for n in ha_nodes(store)]
    if node not in known:
        raise ValueError('there is no node %s' % node)
    if action == 'look':
        action = 'check'
    if action not in SE_ACTIONS:
        raise ValueError('check, prepare, enforce or permissive')
    if action in ('fix', 'rule_drop'):
        ids = selinux_ids(store, node, action, ids)
        was = _se_pending(store, node)
        if was.get('do') in SE_STEPS + ('fix', 'rule_drop'):
            raise ValueError('%s has not done what was asked of it yet (%s) - in a moment' % (node, was.get('do')))
    elif ids:
        raise ValueError('ids go with fix or rule_drop only')
    if action in SE_STEPS:
        # One node at a time (1.0.120, advice): a step of SELinux on one node of a cluster while the other is
        # in the middle of one could leave neither able to take the cluster's address - look at the
        # cluster (both nodes, the replication, the VIP) between them.
        for other in known:
            if other != node and _se_pending(store, other).get('do') in SE_STEPS:
                # Said, not refused: asking both nodes at once worked before 1.0.120 and still does.
                log('SELinux: %s is in the middle of a step of SELinux (%s) - one node at a time is safer: '
                    'look at the cluster between them' % (other, _se_pending(store, other)['do']), 'warn')
                break
    if action == 'permissive' and _hs_on():
        # A step down (1.0.59, as otp 1.0.249): refused while high security is on - from the
        # pages, the API and the command line alike.
        raise ValueError('high security is on: SELinux is not switched to permissive - switch high '
                         'security off first')
    # A step asked and not done yet is not put aside by a look or a report (1.0.59, as otp
    # 1.0.248): its one row was written over, and "enforcing" never happened - said nowhere.
    was = _meta_obj(store, 'host:selinux:want:' + node)
    now = _meta_obj(store, 'host:selinux:now:' + node)
    try:
        was_at = float(was.get('at') or 0)
    except (TypeError, ValueError):
        was_at = 0.0
    if action in ('check', 'report') and was.get('do') in ('prepare', 'enforce', 'permissive') and \
            was.get('id') != now.get('done') and time.time() - was_at < 3600:
        if action == 'check':
            return          # the step looks again when it is done
        raise ValueError('%s has not done the step asked of it yet (%s) - ask for the report after it'
                         % (node, was.get('do')))
    row = {'id': secrets.token_hex(6), 'do': action, 'by': by, 'at': time.time()}
    if ids:
        row['ids'] = ids
    store.set_meta('host:selinux:want:' + node, json.dumps(row))
    if action == 'fix':
        store.add_event('settings', '%s asked SELinux on %s: put right %d thing(s) it found - %s' % (
            by, node, len(ids), ', '.join(ids[:12]) + (' ...' if len(ids) > 12 else '')), 'warn', who=by)
    elif action == 'rule_drop':
        store.add_event('settings', '%s asked SELinux on %s: take away acme\'s local rule(s) %s' % (
            by, node, ', '.join(ids[:12])), 'warn', who=by)
    elif action == 'report':
        store.add_event('settings', '%s asked for the SELinux report of %s' % (by, node), 'info', who=by)
    elif action != 'check':
        store.add_event('settings', '%s asked SELinux on %s: %s' % (by, node, {
            'prepare': 'made ready, permissive', 'enforce': 'enforcing',
            'permissive': 'permissive again'}[action]), 'warn', who=by)


def selinux_tick(daemon):
    """Every few seconds: a step asked for this node done; how it is, looked at now and then."""
    store = daemon.store
    me = node_name()
    try:
        selinux_report_tidy(store)
    except Exception:                                   # noqa: BLE001
        pass
    want = _meta_obj(store, 'host:selinux:want:' + me)
    now = _meta_obj(store, 'host:selinux:now:' + me)
    # A step tried is not tried again: with its answer not written (the database away), it
    # ran again every 5 s - "enforce" and "prepare" over and over.
    asked = bool(want) and want.get('id') != now.get('done') and want.get('id') != SE_WORK['tried']
    if SE_WORK['busy'] or not (asked or time.time() - SE_WORK['seen'] > SE_EVERY):
        return
    SE_WORK['busy'] = True
    SE_WORK['seen'] = time.time()
    if asked:
        SE_WORK['tried'] = want.get('id') or ''
    do = want.get('do') if asked and want.get('do') in SE_ACTIONS else 'check'
    if do in ('fix', 'rule_drop') and not want.get('ids'):
        do = 'check'

    def go():
        try:
            err = ''
            data = (now.get('data') or {}) if do != 'check' else {}
            said = []
            try:
                if do in ('fix', 'rule_drop'):
                    # The ids alone (1.0.120): root finds them again in this machine's audit log and
                    # works out every fix itself - never a rule, a path or a command from here.
                    ask = {'do': do, 'ids': [i for i in (want.get('ids') or []) if SE_ID_RE.match(str(i))],
                           'by': str(want.get('by') or '')[:60]}
                else:
                    ask = dict(selinux_want(store), do=do)
                data = root_ask('selinux.ask', 'selinux.json', ask, 120 if do == 'check' else 600)
                said = data.pop('said', []) if isinstance(data, dict) else []
                if isinstance(data, dict):
                    data = selinux_trim(data)
            except ValueError as e:
                err = str(e)[:400]
                if do not in ('check', 'report'):
                    log('SELinux on %s: %s' % (me, err), 'warn')
            if do == 'report':
                # Kept sealed in the database an hour, so the pages of any node give it.
                rep = {'id': want.get('id'), 'at': time.time(), 'error': err, 'bytes': 0, 'data': ''}
                if not err:
                    try:
                        raw = (WEB_DIR / 'selinux-report.tar.gz').read_bytes()
                        if len(raw) > SE_REPORT_MOST:
                            raise ValueError('the report is %d MB - too large to pass on; '
                                             'acme --selinux-report on the node itself' % (len(raw) >> 20))
                        rep.update(bytes=len(raw), data=seal_secret(base64.b64encode(raw).decode('ascii'),
                                                                     'selinux:report'))
                    except (OSError, ValueError) as e:
                        rep['error'] = str(e)[:400]
                    try:
                        (WEB_DIR / 'selinux-report.tar.gz').unlink()
                    except OSError:
                        pass
                store.set_meta('host:selinux:report:' + me, json.dumps(rep))
                data = (now.get('data') or {})
            if do in ('fix', 'rule_drop') and not err:
                # Every step root took, in Events (1.0.120): each on a line of its own.
                for line in said[:30] or ['done']:
                    store.add_event('settings', 'SELinux on %s: %s' % (me, line), 'warn',
                                    who=str(want.get('by') or '') or None)
                log('SELinux on %s: %s' % (me, '; '.join(said) or 'done'), 'warn')
            elif do not in ('check', 'report'):
                store.add_event('settings', 'SELinux on %s: %s' % (
                    me, err or '; '.join(said) or 'done'), 'bad' if err else 'warn')
                if not err:
                    log('SELinux on %s: %s' % (me, '; '.join(said) or 'done'), 'warn')
            store.set_meta('host:selinux:now:' + me, json.dumps({
                'data': data if isinstance(data, dict) else {}, 'at': time.time(),
                'done': want.get('id') if asked else now.get('done'), 'error': err,
                'said': said, 'action': do, 'by': str(want.get('by') or '') if asked else ''}))
        except Exception as e:                          # noqa: BLE001
            log_sparing('selinux', 'SELinux: %s' % e, 'warn', every=600)
        finally:
            SE_WORK['busy'] = False
    threading.Thread(target=go, name='acme-selinux', daemon=True).start()


def selinux_trim(data):
    """What a node keeps of its look in the database: every finding of acme's, and of other
    programs' at most 60 - the row goes to the other node with the replication."""
    fs = data.get('findings')
    if isinstance(fs, list):
        mine = [f for f in fs if isinstance(f, dict) and f.get('kind') != 'other']
        other = [f for f in fs if isinstance(f, dict) and f.get('kind') == 'other']
        data = dict(data, findings=mine[:240] + other[:60])
        if len(other) > 60 or len(mine) > 240:
            data['findings_left'] = max(0, len(other) - 60) + max(0, len(mine) - 240)
    return data


def selinux_counts(store, node=None):
    """How many of what a node found SELinux refuses can be put right on the card, and how many are
    not for a button: (fixable, nobutton) - (0, 0) where SELinux is not on."""
    d = _meta_obj(store, 'host:selinux:now:' + (node or node_name())).get('data') or {}
    if d.get('mode') not in ('Enforcing', 'Permissive'):
        return 0, 0
    fs = [f for f in d.get('findings') or [] if isinstance(f, dict)]
    return (sum(1 for f in fs if f.get('fixable') and f.get('kind') in ('boolean', 'label', 'port', 'rule')),
            sum(1 for f in fs if f.get('kind') == 'nobutton'))


def selinux_problems(store, node=None):
    """For the security check: what keeps SELinux from protecting a node as it should -
    nothing at all where it is disabled (as until now) or not on the machine."""
    now = _meta_obj(store, 'host:selinux:now:' + (node or node_name()))
    d = now.get('data') or {}
    if d.get('mode') not in ('Enforcing', 'Permissive'):
        return []
    out = list(d.get('problems') or [])
    fixable, nobutton = selinux_counts(store, node)
    if fixable or nobutton:
        # As the card says it (1.0.120): how many of it can be put right there.
        out = [p for p in out if not str(p).startswith('SELinux refused ')]
        out.insert(0, 'SELinux refuses acme something - %d can be put right on the card (Settings - SELinux)%s'
                   % (fixable, '; %d not for a button - each says why' % nobutton if nobutton else ''))
    if d.get('mode') == 'Permissive' and not out:
        out.append('SELinux is permissive: nothing is refused - acme is ready for enforcing')
    return out


def selinux_report_tidy(store):
    """This node's report taken out of the database once it is an hour old."""
    k = 'host:selinux:report:' + node_name()
    rep = _meta_obj(store, k)
    if rep and time.time() - float(rep.get('at') or 0) > SE_REPORT_KEEP_S:
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))


def selinux_reports(store):
    """Every node's report as the pages show it: {node: {'at', 'bytes', 'error', 'id'}}."""
    out = {}
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'host:selinux:report:%'"):
        try:
            rep = json.loads(r['v'] or '{}')
        except (TypeError, ValueError):
            continue
        out[r['k'][len('host:selinux:report:'):]] = {k: rep.get(k) for k in ('at', 'bytes', 'error', 'id')}
    return out


def selinux_report_one(store, node):
    """One node's report as it made it: (bytes, '') or (None, why not)."""
    rep = _meta_obj(store, 'host:selinux:report:' + node)
    if not rep:
        return None, '%s has no report - Download the report asks it for one first' % node
    if rep.get('error'):
        return None, '%s: %s' % (node, rep['error'])
    got = unseal_secret(rep.get('data') or '', 'selinux:report') if rep.get('data') else None
    try:
        raw = base64.b64decode(got) if got else None
    except (ValueError, TypeError):
        raw = None
    return (raw, '') if raw else (None, '%s: its report could not be read' % node)


def selinux_report_bundle(store):
    """One archive with each node's report in it, and a word on those that have none."""
    buf = io.BytesIO()
    missing = []
    nodes = [node_name()] + [n['name'] for n in ha_nodes(store) if n['name'] != node_name()]
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        for n in nodes:
            rep = _meta_obj(store, 'host:selinux:report:' + n)
            raw = None
            if rep.get('data'):
                got = unseal_secret(rep['data'], 'selinux:report')
                try:
                    raw = base64.b64decode(got) if got else None
                except (ValueError, TypeError):
                    raw = None
            if not raw:
                missing.append('%s: %s' % (n, rep.get('error') or 'no report (the node did not answer)'))
                continue
            info = tarfile.TarInfo('acme-selinux-report-%s.tar.gz' % re.sub(r'[^A-Za-z0-9._-]', '', n))
            info.size, info.mtime, info.mode = len(raw), int(rep.get('at') or time.time()), 0o600
            tf.addfile(info, io.BytesIO(raw))
        words = ('acme %s - the SELinux report of each node, made %s.\n\n' % (__version__, time.strftime('%Y-%m-%d %H:%M')) +
                 ('Missing:\n' + '\n'.join('  ' + m for m in missing) + '\n' if missing else 'Every node is in it.\n'))
        data = words.encode('utf-8')
        info = tarfile.TarInfo('README.txt')
        info.size, info.mtime, info.mode = len(data), int(time.time()), 0o600
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue(), missing
