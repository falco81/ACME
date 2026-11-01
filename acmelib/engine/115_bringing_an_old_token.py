# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Bringing an old token server over: totpcgi and its FreeRADIUS
# ---------------------------------------------------------------------------
# The server this replaces kept a file per person (`name@realm.totp`, the
# google-authenticator format: the key, a few `" OPTION` lines, the recovery
# codes), its RADIUS clients in clients.conf, the realm a client's names
# belong to in hints, and the directory and its groups in a YAML file beside
# the Perl handler. All of it is read here so that nobody has to enrol again.

def parse_totp_file(text):
    """(secret, options, recovery codes) out of one google-authenticator file."""
    lines = [l.strip() for l in str(text or '').splitlines() if l.strip()]
    if not lines:
        raise ValueError('the file is empty')
    secret = lines[0]
    # At least 80 bits, as google-authenticator writes them (1.0.36): any
    # word at all was taken for a key, and a file of rubbish made an active
    # token with a 35-bit key.
    if len(b32_clean(secret)) < 10:
        raise ValueError('the first line is not a key of at least 16 base32 characters')
    opts, codes = {}, []
    for line in lines[1:]:
        if line.startswith('"'):
            bits = line[1:].split()
            if bits:
                opts[bits[0].upper()] = bits[1:]
        elif re.match(r'^[0-9]{6,12}\Z', line):     # as long as scratch_digits allows (1.0.207)
            codes.append(line)
    if 'HOTP_COUNTER' in opts:
        raise ValueError('a counter (HOTP) token, not a time one: it would not give the '
                         'same codes here')
    return re.sub(r'[\s\-=]', '', secret).upper(), opts, codes


TOKEN_WINDOW_MOST = 20     # the most the pages allow (1.0.101)


TOKEN_NAME_RE = re.compile(r'^[^\s@,;=\x00-\x1f\x7f]+(@[A-Za-z0-9.-]+)?\Z')


def token_name_problem(name):
    """Why `name` is not a token's name, or '' - the rule of a new token's and a
    rename's, for the imports too (1.0.146): a file '.totp' made a token with no
    name, which no page could open or take away."""
    if not name or len(name) > 180 or not TOKEN_NAME_RE.match(name):
        return ('%r is not a name: a name, or a name@realm - no spaces, commas, semicolons '
                'or =, 180 characters at most' % str(name)[:60])
    return ''


def import_totp(store, name, text, by='import', replace=False):
    """One person's token, from the old server's file. Returns what happened."""
    secret, opts, codes = parse_totp_file(text)
    name = norm_name(name)
    bad = token_name_problem(name)
    if bad:
        return 'not taken: %s' % bad
    if store.token(name) and not replace:
        return 'kept (there is a token for %s already)' % name
    window = -1
    if 'WINDOW_SIZE' in opts and opts['WINDOW_SIZE']:
        try:
            # As many steps either side as the pages allow, never more
            # (1.0.101): WINDOW_SIZE 200001 took codes from days back.
            window = min(TOKEN_WINDOW_MOST, max(0, (int(opts['WINDOW_SIZE'][0]) - 1) // 2))
        except ValueError:
            window = -1
    # The step, the digits, the hash and the state as the file says (1.0.207): a
    # google-authenticator -S 60 token, or acme's own export of an 8-digit one, came
    # in as 6 digits every 30 s and refused every code; one switched off or never
    # confirmed came back in use.
    period, digits, algo, state = 30, 6, 'SHA1', 'active'
    try:
        if opts.get('STEP_SIZE'):
            period = int(opts['STEP_SIZE'][0])
        if opts.get('ACME_DIGITS'):
            digits = int(opts['ACME_DIGITS'][0])
    except ValueError:
        return 'not taken: its STEP_SIZE or ACME_DIGITS is not a number'
    if not 10 <= period <= 300 or digits not in (6, 7, 8):
        return 'not taken: a step of %d s or %d digits is not one this server takes' % (period, digits)
    if opts.get('ACME_ALGORITHM'):
        algo = str(opts['ACME_ALGORITHM'][0]).upper()
        if algo not in ('SHA1', 'SHA256', 'SHA512'):
            return 'not taken: the hash %s is not one this server takes' % algo
    if opts.get('ACME_STATE') and opts['ACME_STATE'][0] in ('active', 'disabled', 'pending'):
        state = opts['ACME_STATE'][0]
    store.token_write(name, {
        'secret': seal_secret(secret, token_bind(name)), 'digits': digits, 'period': period,
        'algorithm': algo,
        'window_steps': window, 'state': state, 'last_step': 0,
        'scratch': json.dumps([scratch_hash(name, c) for c in codes]),
        'scratch_sealed': seal_codes(codes, token_bind(name)),
        'scratch_left': len(codes), 'created': time.time(), 'created_by': by,
        'activated': time.time(), 'failures': 0, 'fail_times': '[]', 'locked_until': None,
        'pending_secret': None, 'pending_scratch': None, 'pending_at': None, 'pending_by': None,
        'issuer': str(CONFIG.get('totp_issuer') or ''), 'label': name,
        # An app's key now (1.0.146): put over a token whose codes came by
        # mail or SMS, it stayed one - sending to the old address.
        'kind': '', 'dest': '',
        'note': 'brought over from totpcgi' + ('' if 'TOTP_AUTH' in opts else
                                               ' (the file was not marked TOTP_AUTH)')})
    try:
        store.db.run('DELETE FROM meta WHERE k = ?', ('staged:' + name,))
    except Exception:                                   # noqa: BLE001
        pass
    return 'imported, %d recovery code(s)' % len(codes)


# ---- a whole backup of tokens, of every kind (1.0.96) -------------------------------
# What a token is - its key, its recovery codes (used and not), how its codes
# come (the app, mail, SMS) and where to, its language, its state - as one
# file, locked with a passphrase if one is given (the same lock as the HA
# bundle: scrypt, then a keyed stream and an HMAC). Read back on this
# server or another acme: all of them, or the ones picked. The keys are in
# it in the clear (inside the lock): the sealing key of this machine is not
# needed on the other.

TOKENS_KIND = 'acme-tokens'


def token_backup_row(tok, store=None):
    """One token as the backup keeps it, or None when its key cannot be
    opened here."""
    name = tok['name']
    kind = token_kind(tok)
    out = {'name': name, 'kind': kind, 'state': tok.get('state') or 'active'}
    # What a token switched off goes back to (1.0.207): one never confirmed came
    # back in use once switched on again after a restore.
    was = store.get_meta('disabled_from:' + norm_name(name)) \
        if store is not None and out['state'] == 'disabled' else None
    if was:
        out['was'] = str(was)
    if kind == 'totp':
        secret = unseal_secret(tok.get('secret') or '', token_bind(name))
        if not secret:
            return None
        out.update(secret=re.sub(r'[\s\-=]', '', str(secret)).upper(),
                   digits=int(tok.get('digits') or 6),
                   period=int(tok.get('period') or 30),
                   algorithm=str(tok.get('algorithm') or 'SHA1').upper())
    else:
        out['dest'] = tok.get('dest') or ''
    # As the rest reads them (1.0.207): the sealed list alone can still say unused a
    # code the other node has used - it came back to life in the copy.
    codes = codes_open(tok)
    out['codes'] = [{'c': c['c'], 'used': c.get('used')} for c in (codes or [])]
    if codes is None and int(tok.get('scratch_left') or 0):
        out['codes_lost'] = int(tok.get('scratch_left') or 0)
    for k in ('window_steps', 'last_step'):
        if tok.get(k) is not None:
            out[k] = int(tok.get(k))
    for k in ('lang', 'mail_fmt', 'note', 'display', 'issuer', 'label', 'created_by',
              'last_from', 'last_how'):
        if tok.get(k):
            out[k] = str(tok.get(k))
    for k in ('created', 'activated', 'last_used'):
        if tok.get(k):
            out[k] = float(tok.get(k))
    return out


def tokens_backup(store, names, by=''):
    rows, lost = [], []
    for n in names:
        tok = store.token(n)
        if not tok:
            continue
        one = token_backup_row(tok, store)
        if one is None:
            lost.append(n)
        else:
            rows.append(one)
    return {'kind': TOKENS_KIND, 'format': 1, 'made': time.time(), 'by': by,
            'node': node_name(), 'version': __version__, 'count': len(rows),
            'lost': lost, 'tokens': rows}


def tokens_backup_open(text, passphrase=''):
    """The backup in a file: plain, or locked (then the passphrase opens it).
    None when the file is no backup at all (a .totp file, say)."""
    try:
        got = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(got, dict) or got.get('kind') != TOKENS_KIND:
        return None
    if got.get('locked'):
        if not passphrase:
            raise PermissionError('the backup is locked: its passphrase opens it')
        got = bundle_open(got, passphrase, kinds=(TOKENS_KIND,))
    if not isinstance(got.get('tokens'), list):
        raise ValueError('the backup holds no list of tokens')
    return got


def token_restore(store, t, by='restore', replace=False):
    """One token out of a backup. Returns what happened."""
    if not isinstance(t, dict):
        raise ValueError('not a token')
    name = norm_name(t.get('name'))
    bad = token_name_problem(name)
    if bad:
        raise ValueError(bad)
    kind = str(t.get('kind') or 'totp')
    if kind not in ('totp', 'mail', 'sms'):
        raise ValueError('a kind this version does not know: %s' % kind)
    if store.token(name) and not replace:
        return 'kept (there is a token for %s already)' % name
    state = str(t.get('state') or 'active')
    if state not in ('active', 'pending', 'disabled'):
        state = 'active'
    codes = []
    for c in t.get('codes') or []:
        code = str((c or {}).get('c') if isinstance(c, dict) else c)
        if not re.fullmatch(r'[0-9]{6,12}', code):          # (1.0.207)
            raise ValueError('a recovery code that is not one')
        codes.append({'c': code, 'used': (c or {}).get('used') if isinstance(c, dict) else None})
    left = [c['c'] for c in codes if not c.get('used')]
    row = {'state': state, 'kind': '' if kind == 'totp' else kind, 'dest': '',
           'scratch': json.dumps([scratch_hash(name, c) for c in left]),
           'scratch_sealed': seal_codes(codes, token_bind(name)) if codes else '',
           'scratch_left': len(left), 'failures': 0, 'fail_times': '[]', 'locked_until': None,
           'pending_secret': None, 'pending_scratch': None, 'pending_at': None,
           'pending_by': None, 'created': float(t.get('created') or time.time()),
           'created_by': str(t.get('created_by') or by)[:190],
           'activated': t.get('activated') or (time.time() if state == 'active' else None),
           'last_used': t.get('last_used'), 'last_from': str(t.get('last_from') or '')[:190],
           'last_how': str(t.get('last_how') or '')[:190],
           'note': str(t.get('note') or '')[:2000], 'display': str(t.get('display') or '')[:300],
           'issuer': str(t.get('issuer') or CONFIG.get('totp_issuer') or '')[:190],
           'label': str(t.get('label') or name)[:190],
           'lang': t.get('lang') if t.get('lang') in ('cs', 'en') else '',
           'mail_fmt': t.get('mail_fmt') if t.get('mail_fmt') in ('html', 'text') else ''}
    if kind == 'totp':
        secret = re.sub(r'[\s\-=]', '', str(t.get('secret') or '')).upper()
        try:
            if len(b32_clean(secret)) < 10:
                raise ValueError
        except ValueError:
            raise ValueError('the key is not a key of at least 16 base32 characters')
        digits, period = int(t.get('digits') or 6), int(t.get('period') or 30)
        algo = str(t.get('algorithm') or 'SHA1').upper()
        if digits not in (6, 7, 8) or not 10 <= period <= 300 or \
                algo not in ('SHA1', 'SHA256', 'SHA512'):
            raise ValueError('digits, period or algorithm this version does not take')
        row.update(secret=seal_secret(secret, token_bind(name)), digits=digits, period=period,
                   algorithm=algo, window_steps=max(-1, min(TOKEN_WINDOW_MOST, int(t['window_steps'])))
                   if t.get('window_steps') is not None else -1,
                   last_step=int(t.get('last_step') or 0))
    else:
        row.update(secret='', dest=dest_checked(kind, t.get('dest')), digits=6, period=30,
                   algorithm='SHA1', window_steps=-1, last_step=0)
    store.token_write(name, row)
    if state == 'disabled' and str(t.get('was') or '') in ('pending', 'active'):
        store.set_meta('disabled_from:' + name, str(t['was']))    # (1.0.207)
    try:
        store.db.run('DELETE FROM meta WHERE k = ?', ('staged:' + name,))
    except Exception:                                   # noqa: BLE001
        pass
    return 'restored (%s, %d recovery code(s) left)' % (
        {'totp': 'the app', 'mail': 'codes by mail', 'sms': 'codes by SMS'}[kind], len(left))


def names_letters_kept(daemon):
    """Once, on the first start of a version that checks the letters of names
    (1.0.155): where tokens or accounts with accents or other languages' letters
    are there already and nobody chose either setting, they are switched on as
    those names need - so an upgrade does not shut those people out of the VPN.
    A new server starts with both off. One node of a cluster does it; the other
    gets it by replication."""
    store = daemon.store
    key = 'names:letters:checked'
    if store.get_meta(key) is not None or not ha_lead(store):
        return
    saved = store.settings_saved()
    if 'names_czsk_letters' in saved:
        store.set_meta(key, '1')
        return
    home = other = 0
    for table in ('tokens', 'accounts'):
        for r in store.db.rows('SELECT name FROM %s' % table):
            n = str(r['name'] or '')
            if all(ord(c) < 128 for c in n):
                continue
            if all(ord(c) < 128 or c in NAME_LETTERS_HOME for c in n):
                home += 1
            else:
                other += 1
    want = {}
    if other and 'names_any_letters' not in saved:
        # (1.0.154 took Czech and Slovak letters by itself, and others only
        # when names_any_letters was switched on - a choice made then stays.)
        want['names_any_letters'] = 1
    if home or (other and 'names_any_letters' in saved):
        want['names_czsk_letters'] = 1
    if want:
        daemon.save_settings(want, by='acme (upgrade)')
        store.add_event('settings', 'names with %s are here already (%d token(s) and account(s)): '
                        '%s switched on so that they still sign in - switch it off on Settings - '
                        'The tokens if they should not' % (
                            'letters of other languages' if other else 'Czech or Slovak letters',
                            home + other, ', '.join(sorted(want))), 'warn', who='acme')
    store.set_meta(key, '1')


STALE_WORK = ('acme-rbackup-', 'acme-putback-', 'acme-download-', 'acme-dl-', 'acme-peek-',
              'acme-fetch-')


def stale_work_away(older=6 * 3600):
    """What a backup, a download or a putting back left in the state folder
    when the program stopped in the middle of it (1.0.146) - a copy of the
    database, unlocked, for nobody. Hours old only: the command line may be
    at one just now."""
    try:
        items = list(STATE_DIR.iterdir())
    except OSError:
        return
    for p in items:
        if not p.name.startswith(STALE_WORK):
            continue
        try:
            if time.time() - p.lstat().st_mtime < older:
                continue
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(str(p), ignore_errors=True)
            else:
                p.unlink()
            log('left from before, taken away: %s' % p.name, 'info')
        except OSError:
            pass


def _legacy_root(root):
    root = Path(root)
    for cand in (root, root / 'acme', root / 'acme' / 'acme'):
        if (cand / 'etc' / 'raddb').is_dir() or (cand / 'etc' / 'totpcgi').is_dir():
            return cand
    raise ValueError('%s holds no etc/raddb or etc/totpcgi' % root)


def _conf_no_comments(text):
    """FreeRADIUS text without its # comments - a # inside quotes kept (1.0.146):
    secret = "has#hash" is a secret, not "has"."""
    out, quote = [], ''
    for line in str(text or '').splitlines():
        keep, i = [], 0
        while i < len(line):
            ch = line[i]
            if quote:
                keep.append(ch)
                if ch == '\\' and i + 1 < len(line):
                    keep.append(line[i + 1])
                    i += 1
                elif ch == quote:
                    quote = ''
            elif ch in '"\'':
                quote = ch
                keep.append(ch)
            elif ch == '#':
                break
            else:
                keep.append(ch)
            i += 1
        quote = ''                      # a quote never runs over a line
        out.append(''.join(keep))
    return '\n'.join(out)


def parse_clients_conf(text):
    """FreeRADIUS clients.conf as [{name, address, secret, shortname}]. Only
    what is set at the top of a client block counts: a block inside it
    (limit { ... }) is passed over (1.0.146) - it used to end the client
    there and leave its secret behind."""
    out = []
    body = _conf_no_comments(text)
    for m in re.finditer(r'(?m)^\s*client\s+(\S+)\s*\{', body):
        key, depth, i, top = m.group(1), 1, m.end(), []
        quote = ''
        while i < len(body) and depth:
            ch, was = body[i], depth
            if quote:
                if ch == '\\':
                    if depth == 1:
                        top.append(body[i:i + 2])
                    i += 2
                    continue
                if ch == quote or ch == '\n':
                    quote = ''
            elif ch in '"\'':
                quote = ch
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if not depth:
                    break
            if depth == 1 and was == 1:
                top.append(ch)
            i += 1
        inside = ''.join(top)
        vals = {}
        for a, b in re.findall(r'^\s*([A-Za-z_0-9]+)\s*=\s*(.+?)\s*$', inside, re.M):
            b = b.strip()
            if len(b) >= 2 and b[0] == b[-1] and b[0] in '"\'':
                b = b[1:-1].replace('\\' + b[0], b[0])
            vals[a.strip().lower()] = b
        addr = vals.get('ipaddr') or vals.get('ipv4addr') or vals.get('ipv6addr') or key
        out.append({'name': vals.get('shortname') or key, 'address': addr,
                    'secret': vals.get('secret', ''),
                    'require_ma': 1 if vals.get('require_message_authenticator') == 'yes'
                    else 0})
    return out


def parse_hints(text):
    """The realm FreeRADIUS's hints file adds to names, by NAS address."""
    out = {}
    lines = str(text or '').splitlines()
    for i, line in enumerate(lines):
        m = re.match(r'^\s*DEFAULT\s+NAS-IP-Address\s*==\s*"?([0-9a-fA-F.:]+)"?', line)
        if not m:
            continue
        for nxt in lines[i + 1:i + 4]:
            r = re.search(r'User-Name\s*:?=\s*"%\{User-Name\}@([^"]+)"', nxt)
            if r:
                out[m.group(1)] = r.group(1)
                break
    return out


def parse_handler_yaml(text):
    """What the old Perl handler was told about the directory."""
    got = {'hosts': [], 'groups': []}
    in_list = None
    for raw in str(text or '').splitlines():
        line = _conf_no_comments(raw).rstrip()
        if not line.strip():
            continue
        m = re.match(r'^(\w+)\s*:\s*(.*)\Z', line.strip())
        if m and not line.startswith(' '):
            k, v = m.group(1), m.group(2).strip().strip("'\"")
            in_list = k if not v else None
            got[k] = v
            continue
        m = re.match(r'^\s*-\s*[\'"]?(.*?)[\'"]?\s*\Z', line)
        if m and in_list:
            got.setdefault(in_list + '_list', []).append(m.group(1))
    hosts = got.get('ldaphosts_list') or []
    got['hosts'] = [re.sub(r'^ldaps?://', '', h).rstrip('/') for h in hosts]
    got['tls'] = 'ldaps' if any(h.startswith('ldaps') for h in hosts) else 'none'
    groups = []
    for f in got.get('groupSearch_list') or []:
        m = re.search(r'\(cn=([^)]+)\)', f, re.I)
        if m:
            groups.append(m.group(1))
    got['groups'] = groups
    return got


def bind_tokens(store):
    """Every token's secrets sealed again tied to its name (1.0.33), where
    they were sealed the old way, without it; then the old way is no longer
    taken for a token at all. Run at start and after a restore."""
    cols = ('secret', 'pending_secret', 'scratch_sealed', 'pending_scratch')
    done = left = 0
    try:
        # ...and one never sealed at all (1.0.101): sealed now, so that from
        # here on a value not sealed is taken for no token - a row written
        # into the database (by replication, by a restore) with a key its
        # writer knows no longer opens the door.
        rows = store.db.rows("SELECT id, name, %s FROM tokens WHERE %s"
                             % (', '.join(cols), ' OR '.join(
                                 "%s LIKE 'sealed:1:%%' OR (%s <> '' AND %s NOT LIKE 'sealed:%%')"
                                 % (c, c, c) for c in cols)))
    except Exception as e:                              # noqa: BLE001
        log('the tokens could not be read to seal them again: %s' % e, 'warn')
        return
    for r in rows:
        fields = {}
        for c in cols:
            v = r.get(c)
            if isinstance(v, str) and v.startswith(SEALED):
                plain = unseal_secret(v)
                if plain is None:
                    left += 1
                    continue
                fields[c] = seal_secret(plain, token_bind(r['name']))
            elif isinstance(v, str) and v and not v.startswith('sealed:'):
                fields[c] = seal_secret(v, token_bind(r['name']))
        if fields:
            # Only if still as read: the other node may have done it already.
            sets = ', '.join('%s = ?' % c for c in fields)
            conds = ' AND '.join('%s = ?' % c for c in fields)
            store.db.run('UPDATE tokens SET %s WHERE id = ? AND %s' % (sets, conds),
                         list(fields.values()) + [r['id']] + [r[c] for c in fields])
            done += 1
    if done:
        log('%d token(s) sealed again, tied to their names' % done)
    if not left:
        BIND_STRICT['tokens'] = True
    else:
        log('%d sealed value(s) of tokens do not open with this key and were left as they are'
            % left, 'warn')


def import_legacy(store, root, by='import', replace=False, say=print):
    """Everything the old server held, into this one. Returns counts."""
    base = _legacy_root(root)
    done = collections.Counter()
    raddb = base / 'etc' / 'raddb'
    hints = parse_hints((raddb / 'hints').read_text(errors='replace')) \
        if (raddb / 'hints').exists() else {}
    realms_seen = set(hints.values())
    # ---- the directory and the realm -----------------------------------
    yaml_file = raddb / 'totpcgi-handler.yaml'
    directory = ''
    if yaml_file.exists():
        y = parse_handler_yaml(yaml_file.read_text(errors='replace'))
        if y['hosts'] and y.get('userSearchBase'):
            directory = 'AD'
            if not store.directory(directory) or replace:
                old = store.directory(directory)
                store.directory_save({
                    'id': old['id'] if old else None, 'name': directory,
                    'hosts': ', '.join(y['hosts']), 'tls': y['tls'],
                    'port': 636 if y['tls'] == 'ldaps' else 389, 'verify': 1,
                    'base': y.get('userSearchBase'), 'bind_dn': y.get('bindDN', ''),
                    'bind_pw': y.get('bindPassword', ''), 'user_attr': 'sAMAccountName',
                    'nested': 0,
                    'note': 'brought over from totpcgi-handler.yaml'}, by)
                done['directories'] += 1
                say('directory %s: %s (base %s, signing in as %s). Its certificate is '
                    'checked: import the certificate authority that signed the domain '
                    'controllers’ certificates, or switch the check off.'
                    % (directory, ', '.join(y['hosts']), y.get('userSearchBase'),
                       y.get('bindDN')))
            lookup = 'upn' if 'userPrincipalName' in str(y.get('search') or
                                                          y.get('userAttribute') or '') \
                else 'sam'
            for suffix in sorted(realms_seen) or ['*']:
                if any(str(r.get('suffix')) == suffix for r in store.realms()) and not replace:
                    continue
                old = next((r for r in store.realms() if r.get('suffix') == suffix), None)
                store.realm_save({
                    'id': old['id'] if old else None, 'name': suffix if suffix != '*'
                    else 'default', 'suffix': suffix, 'directory': directory,
                    'lookup': lookup, 'auth_mode': 'acme', 'check_disabled': 1, 'nested': 0,
                    'groups': [{'group': g, 'reply': ''} for g in y['groups']],
                    'token_name': 'whole',
                    'note': 'brought over: the code alone, then the user filter and the '
                            'group filter the old handler applied'}, by)
                done['realms'] += 1
                say('realm %s: %d group(s), looked up by %s' % (suffix, len(y['groups']),
                                                                lookup))
    # ---- the clients ---------------------------------------------------------
    if (raddb / 'clients.conf').exists():
        for c in parse_clients_conf((raddb / 'clients.conf').read_text(errors='replace')):
            try:
                net = address_net(c['address'])
            except ValueError:
                say('client %s: %r is not an address, left out' % (c['name'], c['address']))
                continue
            plain = str(net.network_address) if net.num_addresses == 1 else str(net)
            realm = hints.get(plain, '')
            if plain in ('127.0.0.1', '::1') and not realm:
                realm = hints.get('127.0.0.1', '')
            name = c['name'] if c['name'] != c['address'] else (
                'localhost' if plain == '127.0.0.1' else plain)
            old = next((x for x in store.clients() if x['name'].lower() == name.lower()), None)
            if old and not replace:
                say('client %s: there is one already, left as it is' % name)
                continue
            # Another client at the very same address (1.0.103): two of the
            # same width, the one named first wins - the NAS already here
            # would have been answered with the imported one's secret.
            same = next((x for x in store.clients() if (not old or x['id'] != old['id']) and
                         str(x.get('address') or '').strip().lower() == plain.lower()), None)
            if same:
                say('client %s: %s is the address of the client %s here already, left out'
                    % (name, plain, same['name']))
                continue
            try:
                store.client_save({'id': old['id'] if old else None, 'name': name,
                                   'address': plain, 'secret': c['secret'], 'realm': realm,
                                   'require_ma': c['require_ma'], 'enabled': 1,
                                   'note': 'brought over from clients.conf'}, by)
            except ValueError as e:
                # One client this cannot take (no secret, a name it refuses)
                # leaves the others to come over (1.0.146).
                say('client %s: left out - %s' % (name, e))
                continue
            done['clients'] += 1
            say('client %s: %s%s' % (name, plain, (', names get @' + realm) if realm else ''))
    # ---- the settings ----------------------------------------------------------
    prov = base / 'etc' / 'totpcgi' / 'provisioning.conf'
    if prov.exists():
        text = prov.read_text(errors='replace')
        def ini(key):
            m = re.search(r'^\s*%s\s*=\s*(.+?)\s*$' % key, text, re.M)
            return m.group(1) if m else None
        changes = {}
        if ini('totp_issuer'):
            changes['totp_issuer'] = ini('totp_issuer')
        if ini('window_size'):
            try:
                changes['totp_window'] = max(0, (int(ini('window_size')) - 1) // 2)
            except ValueError:
                pass
        if ini('rate_limit'):
            m = re.match(r'(\d+)\s*,\s*(\d+)', ini('rate_limit'))
            if m:
                changes['rate_limit_tries'] = int(m.group(1))
                changes['rate_limit_s'] = int(m.group(2))
        if ini('scratch_tokens_n'):
            try:
                changes['scratch_count'] = int(ini('scratch_tokens_n'))
            except ValueError:
                pass
        if realms_seen:
            r = sorted(realms_seen)[0]
            changes['portal_realm'] = r
            changes['portal_hint'] = 'login@%s' % r
        # Each one by itself, brought into the range this version takes, and
        # one saved here already kept unless --replace (1.0.103): a window of
        # 25 stopped the import half done, with no token brought over.
        saved = store.settings_saved()
        taken = {}
        for k, v in changes.items():
            if k in saved and not replace:
                say('setting %s: set here already (%s), left as it is' % (k, saved[k]))
                continue
            shape = TUNABLE.get(k)
            if isinstance(shape, tuple) and len(shape) == 2 and all(
                    isinstance(x, int) for x in shape) and isinstance(v, int):
                if not shape[0] <= v <= shape[1]:
                    say('setting %s: %s is more than this version takes - %s'
                        % (k, v, min(max(v, shape[0]), shape[1])))
                    v = min(max(v, shape[0]), shape[1])
            try:
                v = check_setting(k, v)
            except BadSetting as e:
                say('setting %s: left out (%s)' % (k, e))
                continue
            store.save_setting(k, v, by)
            CONFIG[k] = v
            taken[k] = v
            done['settings'] += 1
        if taken:
            say('settings: %s' % ', '.join('%s=%s' % kv for kv in sorted(taken.items())))
    # ---- the tokens -------------------------------------------------------------
    for folder in (base / 'etc' / 'totpcgi' / 'totp',):
        if not folder.is_dir():
            continue
        for f in sorted(folder.glob('*.totp')):
            name = f.name[:-5]
            try:
                said = import_totp(store, name, f.read_text(errors='replace'), by, replace)
                done['tokens' if said.startswith('imported') else 'tokens_kept'] += 1
            except ValueError as e:
                say('%s: %s' % (f.name, e))
                done['tokens_bad'] += 1
    loose = sorted((base / 'etc' / 'totpcgi').glob('*.totp')) \
        if (base / 'etc' / 'totpcgi').is_dir() else []
    if loose:
        say('left alone, outside the totp folder the old server read: %s'
            % ', '.join(f.name for f in loose))
    store.add_event('import', 'brought over from %s: %s' % (
        root, ', '.join('%s %d' % kv for kv in sorted(done.items())) or 'nothing'), who=by)
    return done


