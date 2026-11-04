# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the directories (administrators signing in from Active Directory / LDAP) ---------
# A person's directory password tried this often in 15 minutes at most
# (1.0.149): more was a guessing tool for anybody's directory password.
DIRTRY_NAME_TRIES = 5


@route('GET', '/api/directories')
def _dirs(h):
    s = h.me()
    dirs = h.store.directories()
    if s['role'] != 'fulladmin':
        for d in dirs:
            if d.get('bind_pw'):
                d['bind_pw'] = secret_shown(d['bind_pw'], last=False)    # dots alone
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
        # What the directory administrators sign in against says about one
        # person: who they are, their groups, and the role each group gives.
        h.me('certadmin')      # as its siblings (1.0.57), not every reader
        who = str(b.get('user') or '').strip()
        if not who:
            raise ApiError(400, 'who?')
        dname = str(CONFIG.get('admin_directory') or '')
        ad = h.d.dirs.get(dname.lower()) if dname else None
        if not ad:
            raise ApiError(404, 'no directory answers for %s - choose one in "Sign '
                                'administrators in against the directory"' % who)
        bare, how = admin_name_parts(who)
        t = time.time()
        try:
            entry = ad.find_user(bare, how)
            groups = ad.groups_of(entry, True) if entry else []
        except LdapUnreachable as e:
            log('the directory could not be reached: %s' % e, 'warn')
            raise ApiError(503, 'the directory cannot be reached just now')
        # Each group with where it lives and the role it gives here (1.0.19,
        # as isemon's person card) - the ones that matter are drawn first.
        listed = []
        seen = set()
        for dn, cn in sorted(groups, key=lambda g: str(g[1]).lower()):
            if dn.lower() in seen:
                continue
            seen.add(dn.lower())
            gives = []
            for key, role in ROLE_GROUP_KEYS:
                if group_matches(dn_list(CONFIG.get(key)), [(dn, cn)], ad):
                    gives.append({'role': role})
            listed.append({'name': cn, 'dn': dn, 'gives': gives})
        acc = h.store.account(who)
        return {'entry': entry, 'groups': sorted({cn for _, cn in groups}, key=str.lower),
                'group_list': listed, 'role': (acc or {}).get('role') or '',
                'directory': ad.name, 'took_ms': int((time.time() - t) * 1000)}
    if act == 'people':
        # People in a directory whose names hold what is typed - what the
        # boxes offer while somebody types a name (1.0.19). The directory by
        # its name, else the one administrators sign in against.
        h.me('certadmin')
        like = str(b.get('like') or '').strip()
        dname = str(b.get('directory') or CONFIG.get('admin_directory') or '').strip()
        ad = h.d.dirs.get(dname.lower()) if dname else None
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
                            'disabled': u['disabled']} for u in found]}
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
        # Counted and written down (1.0.139), as every guess is: each try is a
        # directory password, and wrong ones lock the account there.
        user = str(b.get('user') or '')
        # A person's password tried 5 times in 15 minutes at most (1.0.149):
        # 80 in 5 was a guessing tool for anybody's directory password.
        key = h.throttle('dirtry', 20, 15, name='%s>%s' % (who, user[:120]), ip_tries=100,
                         name_tries=DIRTRY_NAME_TRIES)
        said = admin_ask_directory(h, user, str(b.get('password') or ''))
        if said is None:
            raise ApiError(404, 'the directory %s is not set up' % CONFIG.get('admin_directory'))
        said.pop('entry', None)
        if not said.get('ok'):
            h.failed(key)
        h.store.add_event('accounts', '%s tried the directory sign-in of %s: %s' % (
            who, user[:120], 'it would sign in' if said.get('ok') else 'refused'), who=who)
        return {'tried': said}
    h.me('certadmin')
    if act == 'pw_caps':
        # Each directory with its own cap of wrong passwords, and the setting's (otp 1.0.232).
        h.me('fulladmin')
        return dir_pw_caps_list(h.store)
    if act == 'pw_caps_save':
        s = h.me('fulladmin')
        try:
            said = dir_pw_caps_set(h.store, b.get('caps') or {}, s['name'])
        except ValueError as e:
            raise ApiError(400, str(e))
        return {'message': 'saved' if said else 'nothing changed', 'saved': said}
    if act == 'policy':
        h.me('fulladmin')
        ad = h.d.dirs.get(str(b.get('name') or '').lower())
        if not ad:
            raise ApiError(404, 'there is no directory called %s (switched on)' % b.get('name'))
        try:
            return {'policy': dir_policy_read(h.store, ad)}
        except LdapUnreachable as e:
            raise ApiError(503, 'the directory cannot be reached: %s' % e)
        except LdapError as e:
            raise ApiError(400, 'the directory said: %s' % e)
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


