# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- clients, realms, directories -----------------------------------------------------
@route('GET', '/api/clients')
def _clients(h):
    s = h.me()
    clients = h.store.clients()
    if s['role'] != 'fulladmin':
        # Not even the last two characters to whoever cannot change it (1.0.33).
        for c in clients:
            c['secret'] = '••••••' if c.get('secret') else ''
    return {'clients': clients, 'realms': [r['name'] + ' (' + (r['suffix'] or '-')
                                                     + ')' for r in h.store.realms()],
            'suffixes': [r['suffix'] for r in h.store.realms() if r['suffix'] not in ('*', '')],
            'may_change': s['role'] == 'fulladmin'}


@route('POST', '/api/clients')
def _clients_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = b.get('action')
    if act == 'save':
        c = b.get('client') or {}
        ident = h.store.client_save(c, s['name'])
        h.store.add_event('clients', '%s saved the RADIUS client %s (%s)' % (
            s['name'], c.get('name'), c.get('address')), who=s['name'])
        h.d.changed('clients')
        return {'id': ident, 'message': 'the client %s is saved' % c.get('name')}
    if act == 'delete':
        one = next((c for c in h.store.clients() if c['id'] == _int_id(b.get('id'))), None)
        if not one:
            raise ApiError(404, 'there is no such client')     # 1.0.103
        h.store.client_drop(one['id'])
        h.store.add_event('clients', '%s took away the RADIUS client %s' % (
            s['name'], one.get('name')), 'warn', who=s['name'])
        h.d.changed('clients')
        return {'message': 'the client is gone'}
    if act == 'secret':
        h.me('fulladmin')
        one = next((c for c in h.store.clients(with_secret=True)
                    if c['id'] == int(b.get('id') or 0)), None)
        if not one:
            raise ApiError(404, 'no such client')
        h.store.add_event('clients', '%s looked at the shared secret of %s' % (
            s['name'], one['name']), who=s['name'])
        return {'secret': one['secret']}
    raise ApiError(400, 'no such thing to do to a client')


def realm_alias_tokens(store, realm):
    """Tokens kept under one of the realm's other suffixes (1.0.117) - made
    before it was one - with the name each would have now, and whether a
    token is there already under it."""
    out = []
    if realm.get('token_name') == 'bare' or realm.get('suffix') in (None, '', '*'):
        return out
    for al in realm.get('aliases') or []:
        for row in store.db.rows('SELECT name FROM tokens WHERE LOWER(name) LIKE ? '
                                 'ORDER BY name', ('%@' + al,)):
            to = norm_name(realm_main_name(row['name'], realm))
            out.append({'name': row['name'], 'to': to, 'clash': bool(store.token(to))})
            if len(out) >= 500:
                return out
    return out


@route('GET', '/api/realms')
def _realms(h):
    s = h.me()
    realms = h.store.realms()
    for r in realms:
        if r.get('aliases'):
            r['alias_tokens'] = realm_alias_tokens(h.store, r)
    return {'realms': realms, 'directories': [d['name'] for d in
                                                       h.store.directories()],
            'reply_attrs': list(REPLY_ATTRS), 'reply_catalogue': reply_catalogue(),
            'channels': code_channels(),            # mail, sms - set up (1.0.76)
            'may_change': s['role'] == 'fulladmin'}


@route('POST', '/api/realms')
def _realms_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = b.get('action')
    if act == 'save':
        r = b.get('realm') or {}
        absorb = [str(x) for x in (b.get('absorb') or []) if str(x).strip()][:10]
        before = {x['name'] for x in h.store.realms()}
        ident = h.store.realm_save(r, s['name'], absorb=absorb)
        gone = sorted(before - {x['name'] for x in h.store.realms()} - {r.get('name')})
        h.store.add_event('realms', '%s saved the realm %s%s' % (
            s['name'], r.get('name'), ('; taken into it: %s - their suffixes are its own now, '
                                       'their groups follow its own' % ', '.join(gone))
            if gone else ''), 'warn' if gone else 'info', who=s['name'])
        h.d.changed('realms')
        return {'id': ident, 'message': 'the realm %s is saved' % r.get('name')}
    if act == 'delete':
        one = next((r for r in h.store.realms() if r['id'] == _int_id(b.get('id'))), None)
        if not one:
            raise ApiError(404, 'there is no such realm')      # 1.0.103
        h.store.realm_drop(one['id'])
        h.store.add_event('realms', '%s took away the realm %s' % (s['name'], one['name']),
                          'warn', who=s['name'])
        h.d.changed('realms')
        return {'message': 'the realm is gone'}
    if act == 'move_alias_tokens':
        # Under the realm's own suffix (1.0.117), each as a rename is: the
        # key sealed again, the recovery codes kept, the log following it.
        # One that would land on a token already there is left as it is.
        one = next((r for r in h.store.realms() if r['id'] == _int_id(b.get('id'))), None)
        if not one:
            raise ApiError(404, 'there is no such realm')
        moved, left = [], []
        for t in realm_alias_tokens(h.store, one):
            if t['clash']:
                left.append(t['name'])
                continue
            names = sorted({t['name'], t['to']})
            locks = {id(lk): lk for lk in (h.d.tokens.lock_of(n) for n in names)}
            try:
                with contextlib.ExitStack() as held:
                    for key in sorted(locks):
                        held.enter_context(locks[key])
                    _token_act(h, s, {'to': t['to']}, 'rename', t['name'], s['name'])
                moved.append(t['name'])
            except ApiError as e:
                left.append('%s (%s)' % (t['name'], e))
        h.store.add_event('realms', '%s moved %d token(s) under @%s in the realm %s%s' % (
            s['name'], len(moved), one['suffix'], one['name'],
            ('; left as they are: %s' % ', '.join(left[:20])) if left else ''), who=s['name'])
        return {'moved': moved, 'left': left, 'message': '%d token(s) moved under @%s%s' % (
            len(moved), one['suffix'], ('; %d left as they are - a token is there under the '
                                       'new name already' % len(left)) if left else '')}
    if act == 'try':
        name = Authenticator.full_name(str(b.get('user') or ''), str(b.get('realm') or ''))
        realm = h.store.realm_for(name)
        return {'name': name, 'realm': realm['name'] if realm else None}
    raise ApiError(400, 'no such thing to do to a realm')


@route('GET', '/api/directories')
def _dirs(h):
    s = h.me()
    dirs = h.store.directories()
    if s['role'] != 'fulladmin':
        for d in dirs:
            if d.get('bind_pw'):
                d['bind_pw'] = '••••••'
    return {'directories': dirs, 'may_change': s['role'] == 'fulladmin'}


@route('POST', '/api/directories')
def _dirs_do(h):
    b = h.body()
    act = b.get('action')
    if act in ('save', 'delete'):
        s = h.me('fulladmin')
        if act == 'save':
            one = b.get('directory') or {}
            ident = h.store.directory_save(one, s['name'])
            h.store.add_event('directories', '%s saved the directory %s' % (
                s['name'], one.get('name')), who=s['name'])
            h.d.changed('directories')
            return {'id': ident, 'message': 'the directory %s is saved' % one.get('name')}
        one = next((x for x in h.store.directories() if x['id'] == _int_id(b.get('id'))), None)
        if not one:
            raise ApiError(404, 'there is no such directory')  # 1.0.103
        h.store.directory_drop(one['id'])
        h.store.add_event('directories', '%s took away the directory %s' % (s['name'], one['name']),
                          'warn', who=s['name'])
        h.d.changed('directories')
        return {'message': 'the directory is gone'}
    if act == 'whois':
        # What the directory says about one person - an account here (asked of
        # the directory administrators sign in against) or the owner of a
        # token (asked of the directory of the realm the name falls in).
        h.me('tokenadmin')      # as its siblings (1.0.57), not every reader
        who = str(b.get('user') or '').strip()
        if not who:
            raise ApiError(400, 'who?')
        realm = None
        if b.get('kind') == 'account':
            dname = str(CONFIG.get('admin_directory') or '')
        else:
            realm = h.store.realm_for(who)
            dname = (realm or {}).get('directory') or ''
        ad = h.d.dirs.get(dname.lower()) if dname else None
        if not ad:
            raise ApiError(404, 'no directory answers for %s' % who)
        bare, how = admin_name_parts(who)
        if realm and realm.get('lookup') in ('upn', 'sam'):
            how = realm['lookup']
            bare = who if how == 'upn' else who.split('@', 1)[0]
        t = time.time()
        try:
            entry = ad.find_user(bare, how)
            groups = ad.groups_of(entry, True) if entry else []
        except LdapUnreachable as e:
            log('the directory could not be reached: %s' % e, 'warn')
            raise ApiError(503, 'the directory cannot be reached just now')
        # Each group with where it lives and what it gives here (1.0.19, as
        # isemon's person card): an administrators' role, or the way into a
        # realm - the ones that matter are drawn first, as cards.
        listed = []
        seen = set()
        realms = [r for r in h.store.realms() if r.get('enabled')]
        for dn, cn in sorted(groups, key=lambda g: str(g[1]).lower()):
            if dn.lower() in seen:
                continue
            seen.add(dn.lower())
            gives = []
            for key, role in ROLE_GROUP_KEYS:
                if group_matches(dn_list(CONFIG.get(key)), [(dn, cn)], ad):
                    gives.append({'role': role})
            for r in realms:
                if r.get('groups') and group_matches(r['groups'], [(dn, cn)], ad):
                    gives.append({'realm': r['name']})
            listed.append({'name': cn, 'dn': dn, 'gives': gives})
        acc = h.store.account(who) if b.get('kind') == 'account' else None
        tok = h.store.token(who) if b.get('kind') != 'account' else None
        return {'entry': entry, 'groups': sorted({cn for _, cn in groups}, key=str.lower),
                'group_list': listed, 'realm': (realm or {}).get('name') or '',
                'role': (acc or {}).get('role') or '', 'token': bool(tok),
                'token_state': (tok or {}).get('state') or '',
                'directory': ad.name, 'took_ms': int((time.time() - t) * 1000)}
    if act == 'people':
        # People in the directory of a realm whose names hold what is typed -
        # what the boxes offer while somebody types a name (1.0.19).
        h.me('tokenadmin')
        like = str(b.get('like') or '').strip()
        rname = str(b.get('realm') or '').strip().lower()
        realm = next((r for r in h.store.realms() if r['name'].lower() == rname
                      or str(r.get('suffix') or '').lower() == rname.lstrip('@')), None)
        if not realm:
            realm = h.store.realm_for(like) if '@' in like else None
        dname = str(b.get('directory') or '').strip()
        if dname:
            # One directory by its name, as the Look a name up box asks it:
            # the people as that directory names them.
            ad = h.d.dirs.get(dname.lower())
            if not ad:
                return {'people': []}
            try:
                found = ad.find_users(like.split('@', 1)[0], max(1, min(50, int(b.get('limit') or 20))))
            except LdapUnreachable as e:
                log('the directory could not be reached: %s' % e, 'warn')
                raise ApiError(503, 'the directory cannot be reached just now')
            return {'people': [{'name': (u['upn'] or u['sam'] or '').lower(),
                                'display': u['display'], 'mail': u['mail'],
                                'mobile': u.get('mobile') or '',
                                'disabled': u['disabled'], 'token': ''} for u in found]}
        if not realm or not realm.get('directory'):
            return {'people': [], 'realm': (realm or {}).get('name') or ''}
        ad = h.d.dirs.get(str(realm['directory']).lower())
        if not ad:
            return {'people': [], 'realm': realm['name']}
        try:
            found = ad.find_users(like.split('@', 1)[0], max(1, min(50, int(b.get('limit') or 20))))
        except LdapUnreachable as e:
            log('the directory could not be reached: %s' % e, 'warn')
            raise ApiError(503, 'the directory cannot be reached just now')
        suffix = str(realm.get('suffix') or '')
        out = []
        for u in found:
            if realm.get('lookup') == 'upn' and u['upn']:
                name = u['upn'].lower()
            elif suffix and suffix != '*':
                name = '%s@%s' % ((u['sam'] or '').lower(), suffix.lower())
            else:
                name = (u['upn'] or u['sam'] or '').lower()
            if realm.get('token_name') == 'bare':
                name = name.split('@', 1)[0]
            # A name this realm does not take is no use (1.0.103): a UPN with
            # another suffix (pkolar@corpnet.loc for the realm corpnet.cz) made
            # a token no realm answers for, and the VPN refused it.
            if name and realm.get('token_name') != 'bare':
                took = h.store.realm_for(name)
                if not took or took.get('id') != realm.get('id'):
                    continue
            tok = h.store.token(name) if name else None
            out.append({'name': name, 'display': u['display'], 'mail': u['mail'],
                        'mobile': u.get('mobile') or '',
                        'disabled': u['disabled'], 'token': (tok or {}).get('state') or ''})
        return {'people': out, 'realm': realm['name']}
    if act == 'ca':
        s = h.me('fulladmin')
        one = next((x for x in h.store.directories() if x['id'] == int(b.get('id') or 0)), None)
        if not one:
            raise ApiError(404, 'there is no such directory')
        pem = str(b.get('ca') or '').strip()
        mode = str(b.get('mode') or ('add' if pem else 'clear'))
        before = len(one.get('ca_list') or [])
        try:
            h.store.directory_set_ca(one['id'], pem, mode, str(b.get('fingerprint') or ''))
        except ValueError as e:
            raise ApiError(400, str(e))
        after = next((x for x in h.store.directories() if x['id'] == one['id']), {})
        n = len(after.get('ca_list') or [])
        words = {'add': 'added %d certificate(s) to' % max(0, n - before),
                 'set': 'replaced', 'drop': 'took a certificate out of',
                 'clear': 'took away'}.get(mode, 'changed')
        h.store.add_event('directories', '%s %s the certificate authorities of %s (%d kept)' % (
            s['name'], words, one['name'], n), who=s['name'])
        h.d.changed('directories')
        if mode == 'add' and n == before:
            msg = 'every one of those certificates is kept already'
        else:
            msg = '%s keeps %d certificate(s)' % (one['name'], n)
        return {'message': msg, 'ca_list': after.get('ca_list') or []}
    if act == 'try':
        who = h.me('fulladmin')['name']
        if not CONFIG.get('admin_directory'):
            raise ApiError(400, 'no directory signs administrators in yet: choose one in '
                                '"Sign administrators in against the directory" and save')
        # Counted and written down (1.0.139), as a radtest is: each try is a
        # directory password, and wrong ones lock the account there.
        user = str(b.get('user') or '')
        # A person's password tried 5 times in 15 minutes at most (1.0.149):
        # 80 in 5 was a guessing tool for anybody's directory password.
        key = h.throttle('radtest', 20, 15, name='%s>%s' % (who, user[:120]), ip_tries=100,
                         name_tries=RADTEST_NAME_TRIES)
        said = admin_ask_directory(h, user, str(b.get('password') or ''))
        if said is None:
            raise ApiError(404, 'the directory %s is not set up' % CONFIG.get('admin_directory'))
        said.pop('entry', None)
        if not said.get('ok'):
            h.failed(key)
        h.store.add_event('accounts', '%s tried the directory sign-in of %s: %s' % (
            who, user[:120], 'it would sign in' if said.get('ok') else 'refused'), who=who)
        return {'tried': said}
    h.me('tokenadmin')
    # The connection to a directory tried from every node (1.0.169): each node
    # reaches the domain controllers on its own.
    if act == 'check_all':
        if str(b.get('name') or '').lower() not in h.d.dirs:
            raise ApiError(404, 'there is no directory called %s (switched on)' % b.get('name'))
        return node_ask(h.d, 'dircheck', {'name': str(b.get('name') or '')}, h.me()['name'])
    if act == 'result':
        return {'nodes': node_ask_results(h.store, 'dircheck', str(b.get('id') or ''))}
    if act not in ('check', 'groups', 'lookup'):
        raise ApiError(400, 'no such thing to do with a directory')     # 1.0.103
    ad = h.d.dirs.get(str(b.get('name') or '').lower())
    if not ad:
        raise ApiError(404, 'there is no directory called %s (switched on)' % b.get('name'))
    if act == 'check':
        return {'check': ad.check()}
    if act == 'groups':
        groups = ad.find_groups(str(b.get('like') or ''), limit=5000)
        return {'groups': groups, 'capped': len(groups) >= 5000}
    if act == 'lookup':
        who = str(b.get('user') or '').strip()
        how = str(b.get('how') or ('upn' if '@' in who else 'sam'))
        t = time.time()
        entry = ad.find_user(who, how)
        groups = ad.groups_of(entry, True) if entry else []
        return {'entry': entry, 'groups': [cn for _, cn in groups],
                'took_ms': int((time.time() - t) * 1000)}
    raise ApiError(400, 'no such thing to do with a directory')


