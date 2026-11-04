# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- High security (1.0.168) -------------------------------------------------------------
# Settings → High security: every way of doing something less safely switched
# off. It is switched on only once nothing stands against it - what does is
# listed, each with where it is set; while it is on, what would stand against
# it is refused wherever it is changed (the pages, the API, the command line)
# and greyed out on the pages. Any rule can be made an exception (1.0.169):
# then it stops nothing and is not enforced. The security check - updates
# waiting, certificates running out, backups - is listed beside it.
#
# Each rule of a setting: (what is wrong with the value, or '') for a value
# and the configuration around it; `forbid`/`most`/`least` tell the pages
# which values to grey out.
def _hs_on():
    return bool(CONFIG.get('high_security'))


HISEC_SETTINGS = {
    'smtp_security': {'forbid': ['none', 'starttls-if'], 'pane': 'mail',
                      'when': lambda c: c.get('mail_mode') == 'smtp',
                      'why': 'mail goes to the mail server unencrypted, or encrypted only if it '
                             'offers to'},
    'smtp_verify': {'forbid': [0], 'pane': 'mail', 'when': lambda c: c.get('mail_mode') != 'off',
                    'why': 'the mail server\'s certificate is not checked'},
    'sms_url': {'pane': 'codes', 'when': lambda c: c.get('sms_mode') == 'http',
                'test': lambda v, c: str(v or '').strip().lower().startswith('http://'),
                'why': 'the SMS gateway is asked over plain http://'},
    'sms_tel_https': {'forbid': [0], 'pane': 'codes',
                      'when': lambda c: c.get('sms_mode') == 'teltonika',
                      'why': 'the telephone gateway is asked over plain HTTP'},
    'sms_tel_verify': {'forbid': [0], 'pane': 'codes',
                       'when': lambda c: c.get('sms_mode') == 'teltonika',
                       'why': 'the telephone gateway\'s certificate is not checked'},
    'siem_verify': {'forbid': [0], 'pane': 'siem', 'when': lambda c: bool(c.get('siem')),
                    'why': 'the syslog server\'s certificate is not checked'},
    'siem_targets': {'pane': 'siem', 'when': lambda c: bool(c.get('siem')),
                     'test': lambda v, c: any(p != 'tls' for _h, _p, p in siem_targets(v)),
                     'why': 'syslog goes over UDP or TCP unencrypted - only tls:// servers'},
    'isemon': {'pane': 'isemon', 'when': lambda c: bool(c.get('isemon')),
               'test': lambda v, c: any(p != 'tls' for _h, _p, p in
                                        syslog_targets(c.get('isemon_targets'))),
               'why': 'isemon is sent plain syslog (UDP/TCP) - only over TLS (1.0.172)'},
    'isemon_verify': {'forbid': [0], 'pane': 'isemon', 'when': lambda c: bool(c.get('isemon')),
                      'why': 'isemon\'s certificate is not checked'},
    'debug': {'forbid': [1, True], 'pane': 'about',
              'why': 'debugging writes the details of requests into the log'},
    'totp_window': {'most': 1, 'pane': 'people',
                    'why': 'the codes of the administrators\' app are taken more than one step '
                           '(30 s) either side'},
    'mail_direct_tls': {'forbid': ['if-offered'], 'pane': 'mail',
                        'when': lambda c: c.get('mail_mode') == 'direct',
                        'why': 'mail is delivered unencrypted where the recipient\'s server '
                               'does not offer TLS'},
    'admin_2fa': {'forbid': [0, False], 'pane': 'people',
                  'why': 'the administration is opened with a password alone - no second step'},
    'admin_2fa_mail': {'forbid': [1, True], 'when': lambda c: bool(c.get('admin_2fa')), 'pane': 'people',
                       'why': 'the second step of the administration may come by mail - an app '
                              'is safer'},
    'admin_2fa_sms': {'forbid': [1, True], 'when': lambda c: bool(c.get('admin_2fa')), 'pane': 'people',
                      'why': 'the second step of the administration may come by SMS - an app '
                             'is safer'},
    'portal_who': {'forbid': ['anyone'], 'when': lambda c: bool(c.get('portal')), 'pane': 'portal',
                   'why': 'anyone in the directory may sign in to the enrolment pages'},
    'session_hours': {'most': 8, 'pane': 'people',
                      'why': 'a sign-in to the administration lasts more than 8 hours'},
    'session_idle_min': {'most': 30, 'pane': 'people',
                         'why': 'a sign-in to the administration stays open idle more than 30 min'},
    'proxy_user': {'test': lambda v, c: bool(c.get('proxy')) and not str(v or '').strip(),
                   'pane': 'proxy', 'why': 'the proxy is used without a user name and password'},
}

# What is not a setting: the directories, the destinations, the TLS of the
# pages, the SSH server, the exports - one rule each, its details
# (which directory, which node) listed under it.
HISEC_RULES = [
    ('dir:tls', 'a directory reached over plain LDAP - passwords go over the network unencrypted',
     'LDAPS or STARTTLS', 'dir'),
    ('dir:verify', 'a directory whose certificate is not checked',
     'check the certificate (give its CA)', 'dir'),
    ('dir:weak', 'a directory spoken to with old, weak TLS', 'switch the old TLS off', 'dir'),
    ('db:tls', 'the database reached without TLS that checks its certificate',
     'TLS: verify-ca or verify-full', 'db'),
    ('ha:tls', 'the replication between the nodes without TLS that checks the certificate',
     'TLS for the replication', 'ha'),
    ('backup:ftp', 'a backup destination over plain FTP - its password goes unencrypted',
     'SFTP, SCP or FTPS', 'backup'),
    ('backup:ftps', 'a backup destination over FTPS whose certificate is not checked',
     'check it: the system, a CA or a pin', 'backup'),
    ('backup:smb', 'a backup destination over SMB without encryption', 'SMB encryption on',
     'backup'),
    ('web:tls', 'the TLS of the pages other than standard (ECDHE, AEAD) or modern (TLS 1.3)',
     'standard or modern', 'web'),
    ('fw:admin', 'the administration reachable from anywhere', 'only from the networks that '
     'need it', 'fw'),
    ('sshd:password', 'SSH lets people in with a password', 'keys only', 'sshd'),
    ('sshd:root', 'root may sign in over SSH with a password', 'root: with a key only, or not '
     'at all', 'sshd'),
    ('sshd:tries', 'SSH allows more than 4 tries a connection', '4 tries at most', 'sshd'),
    # Kept by whatever exports (a module's private keys: hisec_enforced('export:unlocked')).
    ('export:unlocked', 'a private key or the configuration exported not locked',
     'an export is always locked with a passphrase', 'import'),
]
HISEC_RULE = {r[0]: r for r in HISEC_RULES}


# Exceptions (1.0.169): a rule switched off by hand stops nothing and is not
# enforced - kept in the database for the whole cluster, each change an event.
_HS_WAIVE = {'at': 0.0, 'v': frozenset(), 'store': [None]}


def hisec_waived(store=None):
    store = store or _HS_WAIVE['store'][0]
    if store is None:
        return _HS_WAIVE['v']
    if time.time() - _HS_WAIVE['at'] > 2:
        got = _meta_json(store, 'hisec:waive') or []
        _HS_WAIVE.update(at=time.time(), v=frozenset(x for x in got if isinstance(x, str)))
        _HS_WAIVE['store'][0] = store
    return _HS_WAIVE['v']


def hisec_enforced(rule, store=None):
    """Whether high security is on and this rule is not an exception."""
    return _hs_on() and rule not in hisec_waived(store)



def _hs_bad(rule, value, conf):
    if rule.get('when') and not rule['when'](conf):
        return False
    if 'test' in rule:
        try:
            return bool(rule['test'](value, conf))
        except (ValueError, TypeError, BadSetting):
            return True
    if 'forbid' in rule:
        return value in rule['forbid'] or (isinstance(value, bool) and int(value) in rule['forbid'])
    if 'most' in rule:
        try:
            return int(value or 0) > rule['most']
        except (TypeError, ValueError):
            return True
    if 'least' in rule:
        try:
            return int(value or 0) < rule['least']
        except (TypeError, ValueError):
            return True
    return False


def hisec_setting_refused(key, value, conf=None):
    """What high security has against this value of a setting, or ''."""
    rule = HISEC_SETTINGS.get(key)
    if not rule:
        return ''
    conf = dict(CONFIG if conf is None else conf)
    conf[key] = value
    return rule['why'] if _hs_bad(rule, value, conf) else ''


def hisec_ui(key):
    """For the pages: what to grey out while it is on - nothing for an exception."""
    rule = HISEC_SETTINGS.get(key)
    if not rule or key in hisec_waived():
        return None
    out = {'why': rule['why']}
    for k in ('forbid', 'most', 'least'):
        if k in rule:
            out[k] = rule[k]
    return out


def _hs_item(kind, what, fix, pane, key='', rule=''):
    return {'kind': kind, 'what': what, 'fix': fix, 'pane': pane, 'key': key,
            'rule': rule or key}


def hisec_rules(store, conf=None):
    """Every rule, as it stands now: {id, kind, what, fix, pane, key, bad, details}."""
    conf = dict(CONFIG if conf is None else conf)
    out = []
    for key, rule in HISEC_SETTINGS.items():
        out.append({'rule': key, 'kind': 'setting', 'what': rule['why'], 'fix': NAMES.get(key, key),
                    'pane': rule['pane'], 'key': key, 'details': [],
                    'bad': _hs_bad(rule, conf.get(key), conf)})
    hit = {r[0]: [] for r in HISEC_RULES}
    for d in store.directories():
        if not d.get('enabled', 1):
            continue
        if d.get('tls') == 'none':
            hit['dir:tls'].append(d['name'])
        elif not d.get('verify', 1):
            hit['dir:verify'].append(d['name'])
        if d.get('weak'):
            hit['dir:weak'].append(d['name'])
    if conf.get('db_engine') in ('mariadb', 'postgres') and \
            str(conf.get('db_host') or '').strip() and not str(conf['db_host']).startswith('/') and \
            conf.get('db_tls') not in ('verify-ca', 'verify-full'):
        hit['db:tls'].append(str(conf.get('db_host')))
    if conf.get('ha_mode') == 'replicated' and ha_link_tls(conf)[0] not in ('verify-ca', 'verify-full'):
        hit['ha:tls'].append(str(conf.get('ha_peer') or ''))
    try:
        targets = rb_targets(store)
    except Exception:                                   # noqa: BLE001
        targets = []
    for t in targets:
        if not t.get('enabled', 1):
            continue
        if t.get('kind') == 'ftp':
            hit['backup:ftp'].append(t.get('name'))
        elif t.get('kind') == 'ftps' and t.get('tls_check') == 'none':
            hit['backup:ftps'].append(t.get('name'))
        elif t.get('kind') == 'smb' and not t.get('smb_encrypt', 1):
            hit['backup:smb'].append(t.get('name'))
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'web:tls:%'"):
        try:
            prof = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if isinstance(prof, dict) and prof.get('cert') and \
                (prof.get('preset') or 'standard') not in ('standard', 'modern'):
            hit['web:tls'].append('%s (%s)' % (r['k'][len('web:tls:'):], prof.get('preset')))
    a = (access_conf(store) or {}).get('admin') or {'any': True}
    if a.get('any', True):
        hit['fw:admin'].append('everybody')
    for n in host_nodes(store):
        v = (sshd_now(store, n) or {}).get('values') or {}
        if v.get('passwordauthentication') == 'yes' or v.get('kbdinteractiveauthentication') == 'yes':
            hit['sshd:password'].append(n)
        if v.get('permitrootlogin') == 'yes':
            hit['sshd:root'].append(n)
        try:
            if v and int(v.get('maxauthtries') or 6) > 4:
                hit['sshd:tries'].append(n)
        except ValueError:
            pass
    for rid, what, fix, pane in HISEC_RULES:
        out.append({'rule': rid, 'kind': rid.split(':', 1)[0], 'what': what, 'fix': fix,
                    'pane': pane, 'key': '', 'details': [x for x in hit[rid] if x],
                    'bad': bool(hit[rid])})
    w = hisec_waived(store)
    for r in out:
        r['waived'] = r['rule'] in w
    return out


def hisec_findings(store, conf=None):
    """{'block', 'waived', 'warn', 'rules'}: what stands against high security now -
    the rules not kept and not exceptions; the security check apart."""
    rules = hisec_rules(store, conf)
    block = [dict(r, title=r['what'], what=r['what'] + (': ' + ', '.join(r['details']) if r['details']
                                                      else ''))
             for r in rules if r['bad'] and not r['waived']]
    waived = [r for r in rules if r['waived']]
    warn = []
    for n in host_nodes(store):
        if not (sshd_now(store, n) or {}).get('values'):
            warn.append(_hs_item('check', 'the SSH server of %s has not said yet how it is set' % n,
                                 'look again', 'sshd'))
    # Rows of the database refused as root's word (1.0.231): somebody else wrote them.
    g = dbguard_view()
    if g['on'] and g['refused']:
        warn.append(_hs_item('check', '%d row(s) of the database that would reach root were not '
                             'written by acme and are not acted on: %s' % (
                                 len(g['refused']), '; '.join('%s (%s)' % (r['what'], r['why'])
                                                            for r in g['refused'][:5])),
                             'look who can write the database', 'hisec'))
    # SELinux (as otp 1.0.233): where it is on, what keeps it from protecting the node; where it
    # is disabled, nothing - as until now.
    for n in host_nodes(store):
        for p in selinux_problems(store, n)[:6]:
            warn.append(_hs_item('check', 'SELinux on %s: %s' % (n, p), 'SELinux', 'hisec'))
    # The security check (1.0.169): what is not as it should be now - as the
    # alerts see it, and the rest. It never stops high security.
    if not fw_conf(store).get('on'):
        warn.append(_hs_item('check', 'the machine\'s firewall is off - acme\'s own rules are not '
                             'in force', 'the firewall on', 'fw'))
    try:
        targets = [t for t in rb_targets(store) if t.get('enabled')]
    except Exception:                                   # noqa: BLE001
        targets = []
    if not targets:
        warn.append(_hs_item('check', 'no backup goes to another machine', 'a destination for '
                             'the backups', 'backup'))
    elif not rb_verified(store):
        warn.append(_hs_item('check', 'no backup has been tried yet - whether one can be put '
                             'back is not known', 'Try the newest, or try them weekly', 'backup'))
    try:
        seen = alert_problems(store, 'en')
    except Exception:                                   # noqa: BLE001
        seen = {}
    for k, p in sorted(seen.items()):
        if k.split(':', 1)[0] in ('cert', 'sec', 'reboot', 'rbverify', 'rbackup'):
            warn.append(_hs_item('check', p['title'], p['said'], p.get('pane') or ''))
    return {'block': block, 'waived': waived, 'warn': warn, 'rules': rules}


def hisec_waive(store, rule, on, by):
    """An exception made, or taken back - taken back only where the rule is
    kept, while high security is on: it would stand against it at once."""
    if rule not in HISEC_SETTINGS and rule not in HISEC_RULE:
        raise ValueError('there is no such rule: %s' % rule)
    w = set(_meta_json(store, 'hisec:waive') or [])
    if not on and rule in w and _hs_on():
        now = [r for r in hisec_rules(store) if r['rule'] == rule]
        if now and now[0]['bad']:
            raise ValueError('high security is on and this is not as it wants it - put it right '
                             'first (%s), then take the exception back' % now[0]['fix'])
    (w.add if on else w.discard)(rule)
    store.set_meta('hisec:waive', json.dumps(sorted(w)))
    _HS_WAIVE['at'] = 0.0
    title = HISEC_SETTINGS[rule]['why'] if rule in HISEC_SETTINGS else HISEC_RULE[rule][1]
    store.add_event('settings', '%s %s an exception to high security: %s' % (
        by, 'made' if on else 'took back', title), 'warn', who=by)
    return sorted(w)


class HiSecConflict(BadSetting):
    def __init__(self, findings):
        BadSetting.__init__(self, 'high security cannot be switched on, %d thing(s) stand '
                                  'against it: %s' % (len(findings['block']), '; '.join(
                                      x['what'] for x in findings['block'])))
        self.findings = findings


def hisec_guard_settings(store, checked):
    """Before settings are saved: switching it on only with nothing against
    it; while it is on, no value it stands against."""
    after = dict(CONFIG)
    after.update(checked)
    if checked.get('high_security') and not CONFIG.get('high_security'):
        got = hisec_findings(store, after)
        if got['block']:
            raise HiSecConflict(got)
    if after.get('high_security'):
        for key in HISEC_SETTINGS:
            if key in hisec_waived(store):
                continue
            if key in checked or any(k in checked for k in ('mail_mode', 'sms_mode', 'siem',
                                                            'admin_2fa', 'portal', 'proxy')):
                why = hisec_setting_refused(key, after.get(key), after)
                if why:
                    raise BadSetting('%s: not while high security is on - %s'
                                     % (NAMES.get(key, key), why))


def hisec_refuse(what, rule=''):
    """A change of a directory, a destination... while it is on -
    unless that rule is an exception."""
    if _hs_on() and what and (not rule or rule not in hisec_waived()):
        raise ValueError('not while high security is on (Settings - High security): %s' % what)


def hisec_directory(row):
    if row.get('tls') == 'none':
        hisec_refuse('a directory over plain LDAP - LDAPS or STARTTLS', 'dir:tls')
    if not row.get('verify', 1):
        hisec_refuse('a directory whose certificate is not checked', 'dir:verify')
    if row.get('weak'):
        hisec_refuse('old, weak TLS to a directory', 'dir:weak')


def hisec_backup_target(t):
    if not t.get('enabled', 1):
        return
    if t.get('kind') == 'ftp':
        hisec_refuse('plain FTP - SFTP, SCP or FTPS', 'backup:ftp')
    if t.get('kind') == 'ftps' and t.get('tls_check') == 'none':
        hisec_refuse('FTPS without checking the certificate', 'backup:ftps')
    if t.get('kind') == 'smb' and not t.get('smb_encrypt', 1):
        hisec_refuse('SMB without encryption', 'backup:smb')


def hisec_tls(prof):
    if (prof.get('preset') or 'standard') not in ('standard', 'modern'):
        hisec_refuse('TLS other than standard (ECDHE, AEAD) or modern (TLS 1.3)', 'web:tls')


def hisec_access(a):
    if ((a or {}).get('admin') or {'any': True}).get('any', True):
        hisec_refuse('the administration reachable from anywhere - list the networks', 'fw:admin')


def hisec_sshd(c):
    if not c.get('manage'):
        return
    if c.get('password'):
        hisec_refuse('SSH with passwords - keys only', 'sshd:password')
    if c.get('permit_root') == 'yes':
        hisec_refuse('root over SSH with a password', 'sshd:root')
    if int(c.get('tries') or 4) > 4:
        hisec_refuse('more than 4 SSH tries a connection', 'sshd:tries')


def hisec_view(store):
    got = hisec_findings(store)
    return dict(got, on=_hs_on(), guard=dbguard_view())

