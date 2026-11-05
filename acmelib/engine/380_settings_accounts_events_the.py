# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- settings, accounts, events, the database --------------------------------------------
def beat_asked_last(store):
    """The newest "say what you have, now" of any node (1.0.44: a row each)."""
    try:
        rows = store.db.rows("SELECT v FROM meta WHERE k LIKE 'beat_asked:%'")
    except Exception:                                   # noqa: BLE001
        return ''
    return max((str(r['v'] or '') for r in rows), default='')


def settings_in_effect(store, ask=False, daemon=None):
    """Whether every node has in what is saved (1.0.42): the mark of the last change of the
    settings, and the one each node said it read. Asked again: this node says it at once,
    the other within five seconds."""
    if ask:
        # A row of the asking node's own (1.0.44): one row both nodes wrote, at the same moment,
        # was the same key inserted twice - and the replication between them stopped on it.
        store.set_meta('beat_asked:' + node_name(), '%.6f:%s' % (time.time(), node_name()))
    serial = store.get_meta('conf_serial', '0')
    out = []
    for b in ha_nodes(store):
        known = 'conf_seen' in b
        if b.get('me') and daemon is not None:
            # This node as it is, not as its last heartbeat said.
            b = dict(b, conf_seen=daemon.conf_serial, conf_seen_at=daemon.conf_loaded_at)
            known = True
        out.append({'name': b['name'], 'me': bool(b.get('me')), 'alive': bool(b.get('alive')),
                    'age': round(float(b.get('age') or 0), 1), 'version': b.get('version') or '',
                    'known': known, 'seen': known and b.get('conf_seen') == serial,
                    'seen_at': b.get('conf_seen_at')})
    return {'serial': serial, 'cluster': bool(CONFIG.get('ha_mode')) and len(out) > 1,
            'nodes': out, 'at': time.time()}


@route('GET', '/api/settings/nodes')
def _settings_nodes(h):
    h.me()
    return settings_in_effect(h.store, daemon=h.d)


SETTINGS_ASKED = {'at': 0.0}


@route('POST', '/api/settings/nodes')
def _settings_nodes_again(h):
    h.me()
    # Once in five seconds at most (1.0.44): asked in a loop, every node wrote its heartbeat at
    # once, again and again - by anybody signed in, read only too.
    if time.time() - SETTINGS_ASKED['at'] < 5:
        return settings_in_effect(h.store, daemon=h.d)
    SETTINGS_ASKED['at'] = time.time()
    if CONFIG.get('ha_mode'):
        heartbeat(h.store, h.d)                 # this node's, now
    return settings_in_effect(h.store, ask=True, daemon=h.d)


@route('GET', '/api/settings')
def _settings(h):
    s = h.me()
    full = s['role'] == 'fulladmin'
    return {'settings': h.d.settings_state(full), 'may_change': full, 'panes': PANES,
            'only_when': ONLY_WHEN, 'config_file': str(CONFIG_FILE),
            'database': h.store.db.where(), 'directories': [d['name'] for d in
                                                            h.store.directories()],
            'isemon': h.d.shipper.state() if h.d.shipper else {},
            'node': node_name(), 'nodes': h.d.cluster_nodes(),
            'cluster': bool(CONFIG.get('ha_mode')) or len(h.d.cluster_nodes()) > 1}


@route('POST', '/api/settings')
def _settings_do(h):
    s = h.me('fulladmin')
    b = h.body()
    asked = b.get('settings') or {}
    moved = [k for k in asked if k in ('db_engine', 'db_host', 'db_port', 'db_name', 'db_user',
                                         'db_password', 'db_path') and
             not (k == 'db_password' and is_masked(asked[k])) and
             str(asked[k]) != str(CONFIG.get(k) if CONFIG.get(k) is not None else '')]
    ha = [k for k in asked if k in ('ha_mode', 'ha_slot', 'ha_peer', 'ha_peer_port', 'ha_address',
                                    'ha_tls', 'ha_tls_ca')
          and str(asked[k]) != str(CONFIG.get(k) if CONFIG.get(k) is not None else '')]
    if ha:
        # The cluster is made and taken apart by its own steps (1.0.57).
        raise ApiError(400, 'the cluster is changed on Settings - High availability or with '
                            'acme --ha-setup / --ha-join / --ha-standalone (%s not saved)'
                       % ', '.join(ha))
    if moved:
        # Saved here, the next restart opened a database nothing had been
        # carried into (1.0.37). The way to another one is the four steps.
        raise ApiError(400, 'the database is changed on Settings - The database - Move to '
                            'another database…, which carries everything across first '
                            '(%s not saved)' % ', '.join(moved))
    try:
        # The other sign-ins ended when the second step is switched on: in
        # save_settings, the one saving it kept.
        return h.d.save_settings(asked, by=s['name'], node=b.get('node'),
                                 drawn_by=b.get('drawn_by'), keep_session=s.get('id'))
    except NodeMoved as e:
        raise ApiError(409, str(e))
    except HiSecConflict as e:
        raise ApiError(409, str(e), detail={'hisec': e.findings})
    except BadSetting as e:
        raise ApiError(400, str(e))


@route('GET', '/api/hisec')
def _hisec(h):
    h.me('fulladmin')
    return hisec_view(h.store)


@route('POST', '/api/hisec')
def _hisec_do(h):
    s = h.me('fulladmin')
    b = h.body()
    if str(b.get('action') or '') != 'waive':
        raise ApiError(400, 'no such thing to do')
    try:
        hisec_waive(h.store, str(b.get('rule') or ''), bool(b.get('on')), s['name'])
    except ValueError as e:
        raise ApiError(400, str(e))
    return hisec_view(h.store)


@route('POST', '/api/isemon')
def _isemon_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    if act == 'result':
        return {'nodes': node_ask_results(h.store, 'isemon', str(b.get('id') or ''))}
    if act.startswith('tls_'):
        try:
            return _isemon_tls_do(h, s, b, act)
        except (ValueError, BadSetting) as e:
            raise ApiError(400, str(e))
    if not CONFIG.get('isemon'):
        raise ApiError(400, 'sending to isemon is off')
    # From every node (1.0.169): each sends its own test line.
    who = str(b.get('as_user') or '').strip()
    if who and not re.match(r'^[A-Za-z0-9._@-]{1,64}\Z', who):
        raise ApiError(400, 'the name is letters, digits and . _ @ - only')
    return node_ask(h.d, 'isemon', {'by': s['name'], 'only': str(b.get('node') or ''),
                                    'as_user': who, 'ok': bool(b.get('ok', True))}, s['name'])


def _isemon_tls_target(b):
    host = str(b.get('host') or '').strip().strip('[]')
    if not re.match(r'^[A-Za-z0-9.:\-]{1,253}\Z', host):
        raise ValueError('isemon\'s address is a name or an address')
    try:
        port = int(b.get('port') or 6514)
    except (TypeError, ValueError):
        raise ValueError('the port is a number')
    if not 0 < port < 65536:
        raise ValueError('the port is 1 to 65535')
    return host, port


def _isemon_tls_do(h, s, b, act):
    """Encrypted sending to isemon (1.0.172): try it on every node, the
    bundle for isemon, switch over, switch off."""
    store = h.store
    if act == 'tls_result':
        return {'nodes': node_ask_results(store, 'isemon_tls', str(b.get('id') or '')),
                'tls': isemon_tls_view(store)}
    src = str(b.get('ca_source') or 'acme')
    if src not in ('acme', 'given', 'system'):
        raise ValueError('the authority is acme\'s, given, or the system\'s')
    pem = str(b.get('ca_pem') or '').strip()
    if src == 'given' and '-----BEGIN CERTIFICATE-----' not in pem:
        raise ValueError('isemon\'s authority is a PEM certificate (-----BEGIN CERTIFICATE-----)')
    if act == 'tls_probe':
        host, port = _isemon_tls_target(b)
        return node_ask(h.d, 'isemon_tls', {'host': host, 'port': port, 'ca_source': src,
                                            'ca_pem': pem if src == 'given' else '',
                                            'verify': bool(b.get('verify', True)),
                                            'mtls': bool(b.get('mtls'))}, s['name'])
    if act == 'tls_bundle':
        _host, port = _isemon_tls_target(b)
        names = [x for x in re.split(r'[\s,;]+', str(b.get('names') or '')) if x]
        blob = isemon_tls_bundle(store, names, port, bool(b.get('mtls')),
                                 str(b.get('passphrase') or ''), s['name'])
        return {'name': 'isemon-tls.zip', 'file': base64.b64encode(blob).decode(),
                'tls': isemon_tls_view(store)}
    if act == 'tls_apply':
        host, port = _isemon_tls_target(b)
        verify = bool(b.get('verify', True))
        if not verify and hisec_enforced('isemon', store):
            raise ValueError('high security is on: isemon\'s certificate is checked')
        keep = [t for t in syslog_targets(CONFIG.get('isemon_targets')) if t[0] != host]
        targets = [syslog_target_text(*t) for t in keep] + [syslog_target_text(host, port, 'tls')]
        ca = hatls_trust(hatls_ca(store)) if src == 'acme' else (pem if src == 'given' else '')
        h.d.save_settings({'isemon': 1, 'isemon_targets': ', '.join(targets), 'isemon_ca': ca,
                           'isemon_verify': 1 if verify else 0,
                           'isemon_mtls': 1 if b.get('mtls') else 0}, by=s['name'])
        store.add_event('settings', '%s: isemon at %s:%d is sent to over TLS%s' % (
            s['name'], host, port, ', each node showing its own certificate' if b.get('mtls')
            else ''), 'info', who=s['name'])
        return {'message': 'isemon at %s:%d is sent to over TLS from now on' % (host, port),
                'tls': isemon_tls_view(store)}
    if act == 'tls_off':
        host = str(b.get('host') or '').strip().strip('[]')
        targets = [syslog_target_text(*((t[0], 514, 'tcp') if t[2] == 'tls' and (not host or t[0] == host)
                                        else t)) for t in syslog_targets(CONFIG.get('isemon_targets'))]
        if hisec_enforced('isemon', store):
            raise ValueError('high security is on: isemon is sent to over TLS only')
        h.d.save_settings({'isemon_targets': ', '.join(targets), 'isemon_mtls': 0}, by=s['name'])
        store.add_event('settings', '%s: isemon is sent to over plain TCP again' % s['name'],
                        'warn', who=s['name'])
        return {'message': 'isemon is sent to over plain TCP (514) again', 'tls': isemon_tls_view(store)}
    raise ValueError('no such thing to do')


@route('GET', '/api/isemon')
def _isemon(h):
    """What each node sends to isemon (1.0.169): this one as it is now, the
    other as its own row of the last minute says."""
    h.me()
    nodes = [n['name'] for n in ha_nodes(h.store)] if CONFIG.get('ha_mode') else [node_name()]
    out = []
    for n in sorted(set(nodes) | {node_name()}):
        row = _meta_obj(h.store, 'host:health:' + n)
        st = (h.d.shipper.state() if h.d.shipper else {}) if n == node_name() else \
            (row.get('isemon') or {})
        out.append(dict(st, node=n, me=n == node_name(),
                        at=time.time() if n == node_name() else row.get('at')))
    return {'nodes': out, 'on': bool(CONFIG.get('isemon')),
            'tls': isemon_tls_view(h.store) if h.me().get('role') == 'fulladmin' else None}


@route('GET', '/api/users')
def _users(h):
    s = h.me()
    mfa = mfa_all(h.store)
    users = h.store.accounts()
    for u in users:
        u['mfa'] = mfa.get(str(u.get('name') or '').lower())
    return {'users': users, 'may_change': s['role'] == 'fulladmin',
            'mfa_on': bool(CONFIG.get('admin_2fa')),
            # The portal's code for acme's own accounts (1.0.44): which ways, so the list can say
            # who would not get in for want of an address or a number.
            'portal_code_ways': list(portal_local_ways()) if CONFIG.get('portal') else [],
            'portal_local': bool(CONFIG.get('portal_local')),
            'portal_enrolers': bool(CONFIG.get('portal_enrolers', 1)),
            'roles': [{'role': r, 'words': ROLE_WORDS[r]} for r in ROLES_ALL]}


@route('POST', '/api/users')
def _users_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act, name = b.get('action'), str(b.get('name') or '').strip()
    who = s['name']
    if act == 'add':
        mail, mobile = account_contact_checked(b)
        h.store.add_account(name, b.get('role') or 'readonly', b.get('password'),
                            note=b.get('note') or '', must_change=b.get('must_change', 1))
        if mail or mobile:
            h.store.set_account(name, mail=mail, mobile=mobile)
        h.store.add_event('accounts', '%s made the account %s (%s)' % (who, name,
                                                                         b.get('role')), who=who)
        return {'message': 'the account %s is made' % name}
    acc = h.store.account(name)
    if not name:
        raise ApiError(400, 'which account?')                          # 1.0.103
    if not acc:
        raise ApiError(404, 'there is no account called %s' % name)
    if act in ('delete', 'disable') or (act == 'role' and b.get('role') != 'fulladmin'):
        if acc['role'] == 'fulladmin' and not h.store.fulladmins_left(but=name):
            raise ApiError(400, 'that is the last full administrator who can sign in')
    if act == 'delete':
        h.store.drop_account(name)
        h.store.add_event('accounts', '%s removed the account %s' % (who, name), 'warn', who=who)
        return {'message': 'the account %s is gone' % name}
    if act == 'role':
        h.store.set_account(name, role=b.get('role'))
        h.store.add_event('accounts', '%s made %s %s' % (who, name,
                                                         ROLE_WORDS.get(b.get('role'))), who=who)
        return {'message': 'saved'}
    if act == 'mfa_reset':
        had = mfa_reset(h.store, acc['name'], who)
        h.store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                       ('admin', acc['name'].lower()))
        account_portal_end(h.store, acc['name'])
        return {'message': ('the second step of %s is reset: they set it up again at the next '
                            'sign-in; their sign-ins are ended' if had else
                            '%s had no second step set up') % acc['name']}
    if act == 'contact':
        # Where the portal's one-time code goes (1.0.44): acme's own accounts only - the
        # directory's people have theirs in the directory.
        if acc.get('source') == 'directory':
            raise ApiError(400, 'the e-mail address and the mobile number of %s are the '
                                'directory\'s' % acc['name'])
        mail, mobile = account_contact_checked(b)
        h.store.set_account(acc['name'], mail=mail, mobile=mobile)
        h.store.add_event('accounts', '%s set the e-mail address (%s) and the mobile number (%s) '
                          'of %s' % (who, mail or 'none', mobile or 'none', acc['name']), who=who)
        return {'message': 'saved'}
    if act == 'reset_cols':
        h.store.put_user_cols(acc['name'], {})
        h.store.add_event('accounts', '%s put the columns of every table back as they come '
                          'for %s' % (who, acc['name']), who=who)
        return {'message': 'the columns of %s are back as they come; they see it at their '
                           'next page load' % acc['name']}
    if act == 'password':
        h.store.set_account(name, password=b.get('password'), must_change=int(bool(
            b.get('must_change', 1))))
        h.store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                       ('admin', name.lower()))
        account_portal_end(h.store, name)
        h.store.add_event('accounts', '%s set a new password for %s; their sign-ins are ended'
                          % (who, name), 'warn', who=who)
        return {'message': 'the password is set'}
    if act in ('disable', 'enable'):
        h.store.set_account(name, disabled=1 if act == 'disable' else 0)
        if act == 'disable':
            h.store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                           ('admin', name.lower()))
        h.store.add_event('accounts', '%s switched %s %s' % (who, name, 'off' if
                                                            act == 'disable' else 'on'), who=who)
        return {'message': 'saved'}
    raise ApiError(400, 'no such thing to do to an account')


def account_contact_checked(b):
    """The e-mail address and the mobile number of an account of acme's own, as given (empty:
    none) - checked as the codes check them."""
    mail = str(b.get('mail') or '').strip()
    mobile = str(b.get('mobile') or '').strip()
    try:
        mail = dest_checked('mail', mail) if mail else ''
    except ValueError as e:
        raise ApiError(400, 'the e-mail address: %s' % e)
    try:
        mobile = dest_checked('sms', mobile) if mobile else ''
    except ValueError as e:
        raise ApiError(400, 'the mobile number: %s' % e)
    return mail, mobile


def account_portal_end(store, name):
    """The sign-ins of an account of acme's own on the enrolment pages ended too (1.0.19):
    a new password set for it, or its second step reset, left them open - for an account
    of the enrolment pages only, the only ones it has. A person of the directory of the
    same name signed in there keeps theirs."""
    for r in store.db.rows('SELECT id, data FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                           ('portal', str(name).lower())):
        try:
            data = json.loads(r.get('data') or '{}')
        except ValueError:
            data = {}
        if isinstance(data, dict) and data.get('kind') == 'local':
            store.session_drop(r['id'])


@route('GET', '/api/sessions')
def _sessions(h):
    h.me('fulladmin')
    # The list is of who could still ask: the ones that sat too long are
    # tidied first (1.0.15), not shown as signed in for hours.
    h.store.sessions_tidy(int(CONFIG.get('session_idle_min') or 120) * 60,
                          int(CONFIG.get('portal_session_min') or 15) * 60)
    return {'sessions': h.store.sessions()}


@route('POST', '/api/sessions')
def _sessions_do(h):
    s = h.me('fulladmin')
    ident = int(h.body().get('id') or 0)
    row = h.store.db.row('SELECT kind, name, ip FROM sessions WHERE id = ?', (ident,))
    if not row:
        # Gone already (1.0.61): not written down as "ended the sign-in of ?".
        raise ApiError(404, 'that sign-in has ended already')
    h.store.session_drop(ident)
    h.store.add_event('sign-ins', '%s ended the sign-in of %s%s' % (
        s['name'], (row or {}).get('name') or '?', (' from %s' % row['ip']) if row and
        row.get('ip') else ''), 'warn', who=s['name'])
    return {'message': 'ended'}


def time_span(h, lq):
    """The time picker's window (1.0.53), `from` and `to` as seconds since
    1970, added to what the search box asked."""
    since, until = h.num('from', 0, 0, 10 ** 11), h.num('to', 0, 0, 10 ** 11)
    parts, args = ([lq.sql] if lq.sql else []), list(lq.args or [])
    if since:
        parts.append('ts >= ?')
        args.append(since)
    if until:
        parts.append('ts < ?')
        args.append(until)
    lq.sql, lq.args = ' AND '.join('(%s)' % x for x in parts), args
    return since, until


@route('GET', '/api/events')
def _events(h):
    h.me()
    lq, bad = list_query('events', h.arg('q'))
    if bad:
        return {'rows': [], 'total': 0, 'q_error': bad, 'kinds': h.reader.event_kinds()}
    time_span(h, lq)
    rows, total = h.reader.events(h.num('limit', 100, 1, 1000), h.num('offset', 0),
                                 lq.words, h.arg('kind'), extra=(lq.sql, lq.args))
    return {'rows': rows, 'total': total, 'kinds': h.reader.event_kinds()}


def mailq_said(e):
    """A mail that did not go now, and what happens to it (1.0.95)."""
    if getattr(e, 'queued', None) == 'waiting':
        return ('not taken yet: %s - it waits in the outgoing mail and is tried again by '
                'itself (Settings → Mail)' % e)
    return str(e)


def mail_reply_words(steps):
    """What the receiving server said when it took the message, for the
    event: its queue id is what its own log can be searched by."""
    last = (steps or [{}])[-1].get('said', '') if steps else ''
    return (' - the server said: %s' % last.split(' · ', 1)[1]) if ' · ' in last else ''


@route('GET', '/api/mail')
def _mail(h):
    h.me()
    return {'mode': CONFIG.get('mail_mode') or 'off', 'ca_list': describe_certificates(
        mail_ca_pem(h.store)), 'from': CONFIG.get('mail_from') or '',
        'sms_ca_list': describe_certificates(sms_ca_pem(h.store)),
        'lang': CONFIG.get('mail_lang') or 'cs'}


@route('POST', '/api/mail')
def _mail_do(h):
    b = h.body()
    act = str(b.get('action') or '')
    if act == 'test':
        s = h.me('fulladmin')
        to = str(b.get('to') or '').strip()
        if not re.match(r'^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+\Z', to):
            raise ApiError(400, 'a mail address to send it to')
        began = time.time()
        try:
            lang = str(b.get('lang') or 'cs')
            if b.get('kind') in ('code', 'verify'):
                # The mail of an administrator's sign-in code, or of checking an
                # address (1.0.78) - with a code that opens nothing.
                msg = code_message('mail', to, code_new(),
                                   'admin' if b.get('kind') == 'code' else 'verify',
                                   lang=lang if lang in CODE_TEXTS else None,
                                   name='novak@example.cz',
                                   display='Jan Novák' if lang == 'cs' else 'John Doe')
            else:
                msg = test_mail(to, lang)
            # Through the outgoing mail, as codes go (1.0.103): tried now, and
            # if the other side does not take it yet (greylisting) tried again
            # by itself - or straight, once, with every step said here.
            queued = str(b.get('via') or '') == 'queue'
            if queued:
                steps = mail_deliver(h.store, msg, [to], kind='test', by=s['name'],
                                     purpose='test')
            else:
                steps = mail_send(h.store, msg, [to])
        except MailError as e:
            h.store.add_event('mail', 'a test mail to %s failed: %s' % (to, e), 'warn',
                              who=s['name'])
            return {'sent': False, 'said': str(e), 'steps': e.steps,
                    'queued': getattr(e, 'queued', None) if str(b.get('via') or '') == 'queue'
                    else None,
                    'took_ms': int((time.time() - began) * 1000)}
        h.store.add_event('mail', '%s sent a test mail%s to %s%s' % (
            s['name'], {'code': ' shaped as a sign-in code\'s',
                        'verify': ' shaped as an address check\'s'}.get(b.get('kind'), ''), to,
            mail_reply_words(steps)), who=s['name'])
        return {'sent': True, 'said': 'sent to %s' % to, 'steps': steps,
                'queued': 'sent' if str(b.get('via') or '') == 'queue' else None,
                'took_ms': int((time.time() - began) * 1000)}
    if act == 'sms_test':
        # An SMS the way a code goes (1.0.76), with a code that opens
        # nothing, and what the gateway said.
        s = h.me('fulladmin')
        try:
            to = phone_checked(b.get('to'))
        except ValueError as e:
            raise ApiError(400, str(e))
        began = time.time()
        try:
            said = sms_send(to, code_message('sms', to, code_new(), 'verify'))
        except SmsError as e:
            h.store.add_event('settings', 'a test SMS to %s failed: %s' % (to, e), 'warn',
                              who=s['name'])
            return {'sent': False, 'said': str(e), 'took_ms': int((time.time() - began) * 1000)}
        h.store.add_event('settings', '%s sent a test SMS to %s' % (s['name'], to), who=s['name'])
        return {'sent': True, 'said': said, 'to': to,
                'took_ms': int((time.time() - began) * 1000)}
    if act == 'sms_ca':
        # The Teltonika gateway's certificates (1.0.89).
        s = h.me('fulladmin')
        mode = str(b.get('mode') or 'add')
        try:
            got = sms_ca_set(h.store, b.get('ca'), mode, str(b.get('fingerprint') or ''))
        except ValueError as e:
            raise ApiError(400, str(e))
        h.store.add_event('settings', '%s %s the certificates of the SMS gateway'
                          % (s['name'], {'add': 'added to', 'drop': 'took one out of'}.get(
                              mode, 'emptied')), who=s['name'])
        return {'ca_list': got, 'message': 'the SMS gateway is checked against %d certificate(s)'
                % len(got)}
    if act == 'tel_test':
        # The Teltonika tried without sending anything (1.0.113).
        s = h.me('fulladmin')
        began = time.time()
        got = tel_test()
        got['took_ms'] = int((time.time() - began) * 1000)
        bad = [x for x in got['steps'] if not x['ok']]
        h.store.add_event('settings', '%s tried the SMS gateway %s: %s' % (
            s['name'], got.get('host') or '?', 'it answers' if got['ok'] else
            (bad[0]['said'] if bad else 'it did not answer')), 'info' if got['ok'] else 'warn',
            who=s['name'])
        return got
    if act == 'sms_ca_fetch':
        # What the gateway shows, for the administrator to look at and trust.
        h.me('fulladmin')
        try:
            pem = tel_peer_chain()
        except SmsError as e:
            raise ApiError(502, str(e))
        return {'pem': pem, 'certs': describe_certificates(pem)}
    if act == 'ca':
        s = h.me('fulladmin')
        mode = str(b.get('mode') or 'add')
        try:
            got = mail_ca_set(h.store, b.get('ca'), mode, str(b.get('fingerprint') or ''))
        except ValueError as e:
            raise ApiError(400, str(e))
        h.store.add_event('settings', '%s %s the certificate authorities of the mail server'
                          % (s['name'], {'add': 'added to', 'drop': 'took one out of'}.get(
                              mode, 'emptied')), who=s['name'])
        return {'ca_list': got, 'message': 'the mail server keeps %d certificate(s)' % len(got)}
    if act == 'mail_of':
        # A person's mail address out of the directory administrators sign in
        # against (1.0.20) - for a box that wants one (alerts, an owner).
        h.me('certadmin')
        who = str(b.get('user') or '').strip()
        ad = h.d.dirs.get(str(CONFIG.get('admin_directory') or '').lower())
        if not ad:
            return {'mail': '', 'display': ''}
        bare, how = admin_name_parts(who)
        try:
            entry = ad.find_user(bare, how)
        except Exception:
            entry = None
        return {'mail': (entry or {}).get('mail') or '', 'display': (entry or {}).get('display')
                or '', 'mobile': (entry or {}).get('mobile') or ''}
    raise ApiError(400, 'no such thing to do')


@route('GET', '/api/log')
def _log(h):
    h.me('fulladmin')
    return {'lines': log_tail(h.num('lines', 400, 10, 5000)), 'file': str(LOG_DIR / 'acme.log')}


def _db_files(h):
    db = h.store.db
    disk, grew, parts = db_disk(h.store)
    return {'copies': kept_copies(), 'dumps': kept_dumps(db.engine), 'dump': dump_info(db.engine),
            'keep': int(CONFIG.get('backup_keep') or 14), 'disk': disk, 'growth': grew,
            'parts': parts, 'cache': db_cache(h.store), 'drivers': drivers_state(),
            'erasable': db_erasable(h.store), 'tune': tune_state(h.store),
            'backup_dir': str(BACKUP_DIR), 'dump_dir': str(DUMP_DIR)}


# The tables people change, as a move must not leave them behind - not the jobs, the events
# and the sign-ins, which change as acme is used.
FINGERPRINT_TABLES = ('certs', 'cert_versions', 'cert_cas', 'cert_ca_versions', 'cert_ca_issued',
                      'cert_issuers', 'cert_challenges', 'cert_targets', 'cert_deploys',
                      'dns_records', 'dns_sets', 'dns_set_uses', 'cert_teams', 'cert_tags',
                      'cert_req_profiles', 'cert_tests', 'cert_checks')
FINGERPRINT_WORDS = {'settings': 'the settings', 'accounts': 'the accounts',
                     'directories': 'the directories', 'certs': 'the certificates',
                     'cert_versions': 'the versions of the certificates',
                     'cert_cas': 'the own authorities', 'cert_ca_versions': 'the authorities\' versions',
                     'cert_ca_issued': 'what the own authorities signed', 'cert_issuers': 'the sources',
                     'cert_challenges': 'the validations', 'cert_targets': 'the targets',
                     'cert_deploys': 'the deployments', 'dns_records': 'the DNS records',
                     'dns_sets': 'the DNS sets', 'dns_set_uses': 'the DNS sets in use',
                     'cert_teams': 'the teams', 'cert_tags': 'the tags',
                     'cert_req_profiles': 'the request profiles', 'cert_tests': 'the tests',
                     'cert_checks': 'the tests attached'}


def db_fingerprint(db):
    """What a database holds that a move must not leave behind (otp 1.0.234): the number of rows
    and the newest of each table people change - not what changes as acme is used."""
    def one(sql):
        try:
            v = db.value(sql)
            return round(float(v)) if v is not None else None
        except (TypeError, ValueError):
            return None
        except Exception:                               # noqa: BLE001 - a table not there yet
            return None
    out = {'settings': (one('SELECT COUNT(*) FROM settings'), one('SELECT MAX(at) FROM settings')),
           'directories': (one('SELECT COUNT(*) FROM directories'),
                           one('SELECT MAX(created) FROM directories'))}
    for t in FINGERPRINT_TABLES:
        out[t] = (one('SELECT COUNT(*) FROM %s' % t), one('SELECT MAX(id) FROM %s' % t))
    acc = sorted('%s|%s|%s|%s' % (str(r['name']).lower(), r['role'] or '', r['pw'] or '',
                                  int(r['disabled'] or 0))
                 for r in db.rows('SELECT name, role, pw, disabled FROM accounts'))
    out['accounts'] = (len(acc), hashlib.sha256('\n'.join(acc).encode('utf-8')).hexdigest())
    return out


def db_fingerprint_diff(here, far):
    """The tables that differ between this database and the one carried into."""
    a, b = db_fingerprint(here), db_fingerprint(far)
    return [FINGERPRINT_WORDS.get(k, k) for k in a if a[k] != b.get(k)]


@route('GET', '/api/db')
def _db(h):
    h.me()
    db = h.store.db
    files = _db_files(h)
    return dict(files, **{'engine': db.engine, 'words': ENGINE_WORDS.get(db.engine), 'where': db.where(),
            'version': db.version(), 'size': db.size(), 'free': db_free_inside(db),
            'counts': h.store.counts(), 'tables': db_table_sizes(db), 'backups': backups(),
            'key': str(sealing_key_path()), 'key_there': bool(sealing_key()),
            'config_file': str(CONFIG_FILE), 'job': job_read(), 'node': node_name(),
            'tuned': bool(json.loads(h.store.get_meta('tune_before:' + node_name()) or '{}')),
            'move': db_move_state(), 'move_guard': db_move_guard(h.store),
            'retain': {k: CONFIG.get(k) for k in ('retain_events_days',)},
            'nightly': nightly_state(h.store)})


def _kept_path(name, kind):
    name = os.path.basename(str(name or ''))
    if not NAME_RE.match(name):
        raise ApiError(404, 'there is no such file')
    folder = DUMP_DIR if kind == 'dump' else BACKUP_DIR
    path = folder / name
    if not path.is_file():
        raise ApiError(404, 'there is no such file: %s' % name)
    return path


def copy_with_key(src_path, dst_path, key_hex):
    """A copy with the key that opens its tokens written into its first line."""
    import gzip
    if not re.match(r'^[0-9a-f]{64}\Z', str(key_hex or '')):
        raise ApiError(409, 'the key beside the copy does not read')
    with gzip.open(str(src_path), 'rt', encoding='utf-8') as src, \
            gzip.open(str(dst_path), 'wt', encoding='utf-8') as dst:
        head = json.loads(src.readline())
        head['key'] = key_hex
        dst.write(json.dumps(head, default=str) + '\n')
        shutil.copyfileobj(src, dst, 1 << 20)


@route('GET', '/api/db/download')
def _db_download(h):
    s = h.me('fulladmin')
    # Made by the page's question first (1.0.123): the file with its key,
    # waiting for this one browser - the passphrase never in an address.
    if h.arg('ticket'):
        v = dbkey_ticket_take(h.arg('ticket'), s['name'])
        if not v:
            raise ApiError(404, 'that download is not waiting any more: ask for it again')
        try:
            h.send_file(v['path'], v['name'])
        finally:
            shutil.rmtree(str(v['dir']), ignore_errors=True)
        return None
    name, kind = h.arg('name'), h.arg('kind')
    if name:
        path = _kept_path(name, kind)
        h.store.add_event('backups', '%s downloaded %s, without the key that opens its tokens'
                          % (s['name'], path.name), who=s['name'])
        h.send_file(path, path.name)
        return None
    # Made now, for the machine somebody is sitting at, and not kept here.
    tmp = Path(tempfile.mkdtemp(prefix='acme-download-', dir=str(STATE_DIR)))
    try:
        path = _db_made_now(h, kind, tmp)
        h.store.add_event('backups', '%s downloaded %s, made for it, without the key that opens '
                          'its tokens' % (s['name'], path.name), who=s['name'])
        h.send_file(path, path.name)
    finally:
        shutil.rmtree(str(tmp), ignore_errors=True)
    return None


def _db_made_now(h, kind, folder):
    if kind == 'dump':
        return make_dump(h.store, 'download', folder=folder)
    path = Path(folder) / ('acme-copy-%s-download.json.gz' % _stamp())
    dump_tables(h.store.db, path)
    return path


def _db_download_ticket(h, s, b):
    """The file asked for - kept or made now - with the key that opens its
    secrets, locked with the passphrase given: made, and left for the browser
    to fetch with the ticket."""
    by = s['name']
    dbkey_passphrase_checked(b.get('passphrase'))
    kind = 'dump' if b.get('kind') == 'dump' else ''
    work = Path(tempfile.mkdtemp(prefix='acme-dl-', dir=str(STATE_DIR)))
    os.chmod(str(work), 0o700)
    try:
        if b.get('name'):
            src = _kept_path(b.get('name'), kind)
            keyf = _key_beside(src)
            # The key beside a kept one is the one that opens it - the one in
            # use now may be newer.
            if keyf.is_file() and sealing_key() and \
                    keyf.read_text().strip() != sealing_key().hex():
                raise ApiError(409, 'the key beside %s is not the one in use now: download it '
                                    'without the key, and the .key beside it from the machine'
                                    % src.name)
        else:
            src = _db_made_now(h, kind, work)
        out = dbkey_bundle(src, src.name, b.get('passphrase'), work)
        if src.parent == work:
            src.unlink()
    except ApiError:
        shutil.rmtree(str(work), ignore_errors=True)
        raise
    except ValueError as e:
        shutil.rmtree(str(work), ignore_errors=True)
        raise ApiError(400, str(e))
    h.store.add_event('backups', '%s downloaded %s WITH the key that opens its tokens, locked with '
                      'a passphrase' % (by, out.name), 'warn', who=by)
    return {'ticket': dbkey_ticket_put(out, out.name, by), 'name': out.name}


@route('POST', '/api/db/restore')
def _db_restore(h):
    s = h.me('fulladmin')
    fd, tmp = tempfile.mkstemp(prefix='acme-upload-', dir=str(STATE_DIR))
    os.close(fd)
    tmp = Path(tmp)
    try:
        h.body_to_file(tmp, 4 * 1024 ** 3)
        if dbkey_is_bundle(tmp):
            # With its key, locked (1.0.123): kept here, opened with the
            # passphrase once it is given.
            work = Path(tempfile.mkdtemp(prefix='acme-peek-', dir=str(STATE_DIR)))
            try:
                inner, _k, head = dbkey_open(tmp, work)
                said, why = db_file_peek(inner, h.store.db.engine)
            except ValueError as e:
                raise ApiError(400, str(e))
            finally:
                shutil.rmtree(str(work), ignore_errors=True)
            if said is None:
                raise ApiError(400, why)
            return {'says': said, 'upload': dbkey_keep_upload(tmp), 'locked': True,
                    'file': head.get('file')}
        if h.arg('check'):
            said, why = db_file_peek(tmp, h.store.db.engine)
            if said is None:
                raise ApiError(400, why)
            return {'says': said}
        try:
            got = db_file_restore(h.store, tmp, s['name'], from_name='the page')
        except ValueError as e:
            raise ApiError(400, str(e))
        h.d.reload_all('a database was put back') if hasattr(h.d, 'reload_all') else None
        return got
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


@route('POST', '/api/db')
def _db_do(h):
    s = h.me('fulladmin')
    act = h.body().get('action')
    if act == 'backup':
        out = make_backup(h.store, 'by %s' % s['name'])
        return {'message': 'a copy was made: %s' % out.name}
    if act == 'tidy':
        return {'message': 'tidied: %s' % h.store.tidy()}
    b = h.body()
    if act == 'job':
        return {'job': job_read()}
    if act == 'dump':
        try:
            out = make_dump(h.store, 'by-hand')
        except ValueError as e:
            raise ApiError(400, str(e))
        return {'name': out.name, 'bytes': out.stat().st_size,
                'message': 'made: %s' % out.name}
    if act == 'download_ticket':
        return _db_download_ticket(h, s, b)
    if act == 'upload_restore':
        try:
            src = dbkey_upload(b.get('upload'))
        except ValueError as e:
            raise ApiError(400, str(e))
        passphrase = str(b.get('passphrase') or '')
        if b.get('check'):
            work = Path(tempfile.mkdtemp(prefix='acme-peek-', dir=str(STATE_DIR)))
            os.chmod(str(work), 0o700)
            try:
                inner, _k, _head = dbkey_open(src, work, passphrase)
                said, why = db_file_peek(inner, h.store.db.engine)
            except ValueError as e:
                raise ApiError(400, str(e))
            finally:
                shutil.rmtree(str(work), ignore_errors=True)
            if said is None:
                raise ApiError(400, why)
            said['with_key'] = True
            return {'says': said}
        # Put back as a job the page follows (1.0.123): a big database takes
        # longer than a page waits for an answer.
        store, daemon, by = h.store, h.d, s['name']

        def work_(progress):
            work = Path(tempfile.mkdtemp(prefix='acme-putback-', dir=str(STATE_DIR)))
            os.chmod(str(work), 0o700)
            try:
                progress(1, 3, 'the file opened with its passphrase')
                inner, keyf, head = dbkey_open(src, work, passphrase)
                progress(2, 3, 'put back')
                got = db_file_restore(store, inner, by, key_file=keyf,
                                      from_name=head.get('file') or 'a file with its key')
                progress(3, 3, 'done')
                try:
                    daemon.reload_all('a database was put back')
                except Exception:                       # noqa: BLE001
                    pass
                return got
            finally:
                shutil.rmtree(str(work), ignore_errors=True)
                try:
                    src.unlink()
                except OSError:
                    pass
        try:
            db_job('putting a database back with its key', work_)
        except ValueError as e:
            raise ApiError(409, str(e))
        return {'message': 'the database is being put back', 'job': job_read()}
    if act in ('restore_kept', 'delete'):
        path = _kept_path(b.get('name'), b.get('kind'))
        if act == 'delete':
            for f in (path, _key_beside(path)):
                try:
                    f.unlink()
                except OSError:
                    pass
            h.store.add_event('backups', '%s deleted %s' % (s['name'], path.name), 'warn',
                              who=s['name'])
            return {'message': '%s is deleted' % path.name}
        if b.get('check'):
            said, why = db_file_peek(path, h.store.db.engine)
            if said is None:
                raise ApiError(400, why)
            return {'says': said}
        try:
            got = db_file_restore(h.store, path, s['name'], key_file=_key_beside(path),
                                  from_name=path.name)
        except ValueError as e:
            raise ApiError(400, str(e))
        if hasattr(h.d, 'reload_all'):
            h.d.reload_all('a database was put back')
        return got
    if act == 'erase':
        try:
            return {'job': db_erase_job(h.store, list(b.get('groups') or []),
                                        bool(b.get('tidy')), s['name'])}
        except ValueError as e:
            raise ApiError(400, str(e))
    if act == 'tune_restart':
        try:
            return tune_restart(h.store, s['name'])
        except ValueError as e:
            raise ApiError(400, str(e))
    if str(act or '').startswith('wiz_'):
        # The wizard: Settings → The database → Move to another database (1.0.210).
        try:
            return db_move_api(h, s, act, b)
        except ApiError:
            raise
        except ValueError as e:
            raise ApiError(400, str(e))
    if act in ('move', 'use', 'empty'):
        # Not on a node of a cluster, nor under another node using this database
        # (1.0.210: a peer heard, or ha_mode set).
        db_move_refuse(h.store)
    try:
        if act in ('try', 'setup', 'empty', 'move', 'use'):
            c = engine_asked(b.get('settings') or {})
            words = ENGINE_WORDS.get(c['db_engine'])
            if act == 'try':
                got = db_try(c)
                got['in_use'] = same_database(c, h.store.db)
                return got
            if act == 'setup':
                if c['db_engine'] == 'sqlite':
                    raise ApiError(400, 'the file on this machine needs no setting up')
                first = db_try(c) if c.get('db_password') else {'reached': False}
                fresh = ''
                if first.get('reached') and first.get('writable'):
                    made = ['the database and the account are there already, and it gets in']
                else:
                    who = str(b.get('admin_user') or '').strip()
                    if not who:
                        raise ApiError(400, 'an administrator of that server is needed to make '
                                            'a database and an account on it')
                    if not c.get('db_password'):
                        fresh = c['db_password'] = db_password_made()
                    made = db_make(c, who, str(b.get('admin_password') or ''))
                keep = {k: c[k] for k in DB_KEYS if k != 'db_engine'}
                write_file_settings(keep)
                far = db_open(c)
                try:
                    far.make_tables()
                    far.add_missing_columns()
                finally:
                    far.close()
                got = db_try(c)
                h.store.add_event('settings', '%s set up %s at %s' % (s['name'], words,
                                                                       db_where(c)), who=s['name'])
                return {'made': made, 'password': fresh, 'kept_in': str(CONFIG_FILE),
                        'try': got, 'message': '%s at %s is ready' % (words, db_where(c))}
            if same_database(c, h.store.db) and act in ('empty', 'move'):
                raise ApiError(400, 'that is the database in use; this only ever touches the '
                                    'other one')
            if act == 'empty':
                got = db_try(c)
                if not got.get('reached'):
                    raise ApiError(400, got.get('trouble') or 'it cannot be reached')
                gone = db_empty(c)
                h.store.add_event('settings', '%s emptied %s at %s' % (s['name'], words,
                                                                        db_where(c)), 'warn',
                                  who=s['name'])
                return {'message': 'emptied: %d table(s) thrown away' % len(gone)}
            if act == 'move':
                got = db_try(c)
                if not got.get('reached'):
                    raise ApiError(400, got.get('trouble') or 'it cannot be reached')
                if not got.get('writable'):
                    raise ApiError(400, 'that account may not write to it')
                if got.get('rows'):
                    raise ApiError(400, 'there are %d record(s) in it already. Moving into a '
                                        'database that is not empty would mix two '
                                        'installations; empty it first if it really is spare.'
                                   % got['rows'])
                return {'job': db_move(h.store, c, s['name'])}
            if act == 'use':
                if same_database(c, h.store.db):
                    raise ApiError(400, 'that is the database in use already')
                got = db_try(c)
                if not got.get('reached'):
                    raise ApiError(400, got.get('trouble') or 'it cannot be reached')
                if not got.get('rows') and not b.get('even_empty'):
                    raise ApiError(400, 'it is empty: carry everything across first')
                # An older copy is not taken for this one (1.0.37): going back
                # to a database left behind by an earlier move opened what it
                # held then, and everything since was out of sight.
                if not b.get('even_older'):
                    try:
                        # The newest event of each (a code's time step is good a
                        # minute at most: not waited for).
                        def newest(db):
                            return float(db.value('SELECT MAX(ts) FROM events') or 0)
                        far = db_open(c)
                        try:
                            there = newest(far)
                        finally:
                            far.close()
                        here = newest(h.store.db)
                    except Exception:                   # noqa: BLE001
                        there = here = 0
                    # What the rows hold, not only the events (otp 1.0.234): the events written
                    # while it was carried were carried too, so a certificate added or a password
                    # changed meanwhile was left behind - and the check below passed.
                    try:
                        far = db_open(c)
                        try:
                            moved = db_fingerprint_diff(h.store.db, far)
                        finally:
                            far.close()
                    except Exception:                   # noqa: BLE001
                        moved = []
                    if moved:
                        raise ApiError(409, 'it holds an older copy: %s changed here since it was '
                                            'carried. Carry everything across again, so nothing '
                                            'written since is left behind.' % ', '.join(moved))
                    if there and here and there < here - 60:
                        raise ApiError(409, 'it holds an older copy: its newest event is from '
                                            '%s, this one\'s from %s. Empty it and carry '
                                            'everything across first, so nothing written '
                                            'since is left behind.' % (
                                                datetime.fromtimestamp(there).strftime(
                                                    '%d-%m-%Y %H:%M'),
                                                datetime.fromtimestamp(here).strftime(
                                                    '%d-%m-%Y %H:%M')))
                # The codes used up here since the carry, used up there too (otp 1.0.224): the
                # minute allowed above for events let a code of the app used meanwhile be good
                # again on the new database.
                try:
                    far = db_open(c)
                    try:
                        sql = {'mariadb': 'INSERT IGNORE INTO used_once (k, node, ts) VALUES (?, ?, ?)',
                               'sqlite': 'INSERT OR IGNORE INTO used_once (k, node, ts) VALUES (?, ?, ?)'}.get(
                            far.engine, 'INSERT INTO used_once (k, node, ts) VALUES (?, ?, ?) '
                                        'ON CONFLICT DO NOTHING')
                        for r in h.store.db.rows('SELECT k, node, ts FROM used_once WHERE ts > ?',
                                                 (time.time() - 3 * 86400,)):
                            far.run(sql, (r['k'], r['node'], r['ts']))
                    finally:
                        far.close()
                except Exception as e:                  # noqa: BLE001
                    log('the codes used lately could not be carried across: %s' % e, 'warn')
                write_file_settings({k: c[k] for k in DB_KEYS})
                h.store.add_event('settings', '%s switched the database to %s at %s; the '
                                  'daemon starts again on it' % (s['name'], words, db_where(c)),
                                  'warn', who=s['name'])
                log('the database is now %s; starting again on it' % db_where(c), 'warn')
                # systemd starts it again (Restart=always), on the new one.
                threading.Timer(1.5, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()
                return {'message': 'the daemon starts again on %s in a moment' % words,
                        'restarting': True}
        if act == 'check':
            own = db_own(h.store)
            try:
                got = db_check(own or h.store.db)
            finally:
                if own:
                    own.close()
            h.store.add_event('settings', '%s checked the database: %s' % (
                s['name'], 'nothing broken' if got['ok'] else 'TROUBLE'),
                'info' if got['ok'] else 'warn', who=s['name'])
            return got
        if act == 'statistics':
            own = db_own(h.store)
            try:
                return {'message': db_statistics(own or h.store.db)}
            finally:
                if own:
                    own.close()
        if act == 'give_back':
            by = s['name']

            def work(progress):
                got = db_give_back(h.store, progress)
                h.store.add_event('settings', '%s gave the disk back: %s -> %s'
                                  % (by, got['before'], got['after']), who=by)
                return got
            return {'job': db_job('giving the disk back', work)}
        if act == 'prune':
            days = 0 if b.get('everything') else int(b.get('days') or 0)
            if days < 1 and not b.get('everything'):
                raise ApiError(400, 'older than how many days? 1 at least')
            gone = db_prune(h.store, days)
            h.store.add_event('settings', '%s forgot the events and logs older than %d '
                              'day(s): %s' % (s['name'], days, gone), 'warn', who=s['name'])
            return {'message': 'forgotten: %s' % (', '.join(
                '%d of %s' % (n, t) for t, n in sorted(gone.items())) or 'nothing'),
                    'gone': gone}
        if act == 'tune_plan':
            return tune_plan_for(h.store, b.get('machine') or {})
        if act == 'tune_apply':
            return tune_apply(h.store, b.get('machine') or {}, str(b.get('admin_user') or ''),
                              str(b.get('admin_password') or ''), s['name'])
        if act == 'tune_undo':
            return tune_undo(h.store, str(b.get('admin_user') or ''),
                             str(b.get('admin_password') or ''), s['name'])
    except ApiError:
        raise
    except ValueError as e:
        raise ApiError(400, str(e))
    except Exception as e:
        raise ApiError(400, str(e).split('\n')[0][:300])
    raise ApiError(400, 'no such thing to do to the database')


@route('GET', '/api/export')
def _export(h):
    s = h.me('fulladmin')
    whole = h.arg('secrets') == '1'
    out = config_export(h.store, whole)
    if whole:
        # Locked with a passphrase made here (1.0.136), as the cluster's
        # bundle is: the file leaves this machine with every shared secret,
        # password and private key in it.
        phrase = ha_passphrase()
        h.store.add_event('settings', 'the configuration was exported with the secrets in it '
                          '(locked with a passphrase)', 'warn', who=s['name'])
        return {'bundle': bundle_lock({'config': out}, phrase, kind=CONFIG_BUNDLE_KIND),
                'passphrase': phrase}
    return {'config': out}


@route('POST', '/api/import')
def _import(h):
    s = h.me('fulladmin')
    conf = h.body().get('config') or {}
    if isinstance(conf, dict) and conf.get('kind') == CONFIG_BUNDLE_KIND:
        try:
            conf = bundle_open(conf, str(h.body().get('passphrase') or ''),
                               kinds=(CONFIG_BUNDLE_KIND,)).get('config') or {}
        except ValueError as e:
            raise ApiError(400, str(e))
    if isinstance(conf, dict) and isinstance(conf.get('config'), dict):
        conf = conf['config']           # the command line's file, whole (1.0.62)

    def not_me_out(acc):
        access_not_me_out(h, h.store, acc, {})
    said = config_import(h.store, h.d, conf, s['name'], keep_account=s['name'],
                         access_check=not_me_out, replace=bool(h.body().get('replace')))
    return {'message': 'imported: %s%s' % (
        ', '.join('%s %d' % kv for kv in sorted(said.items()) if ':' not in kv[0]) or 'nothing',
        ''.join('; %d %s' % (v, k) for k, v in sorted(said.items()) if ':' in k)),
            'imported': dict(said)}


