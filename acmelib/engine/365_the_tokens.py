# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the tokens -----------------------------------------------------------------------
@route('GET', '/api/tokens')
def _tokens(h):
    h.me()
    lq, bad = list_query('tokens', h.arg('q'))
    if bad:
        return {'rows': [], 'total': 0, 'q_error': bad, 'counts': h.store.token_counts()}
    rows, total = h.store.tokens(q=lq.words, extra=(lq.sql, lq.args), state=h.arg('state'),
                                 limit=h.num('limit', 100, 1, 5000), offset=h.num('offset', 0),
                                 sort=h.arg('sort', 'name'), desc=h.arg('desc') == '1',
                                 kind=h.arg('kind'))
    for r in rows:
        r['last_client'] = h.store.client_name_of(r)
    # What "as the setting" is, for the table to show (1.0.85).
    return {'rows': rows, 'total': total, 'counts': h.store.token_counts(),
            'lang_default': code_lang(),
            'fmt_default': 'text' if CONFIG.get('code_mail_fmt') == 'text' else 'html'}


def totp_file_text(tok):
    """One token as the file totpcgi (google-authenticator) keeps for it:
    the key, its options, the recovery codes not used yet - what the import
    reads back (1.0.20)."""
    secret = unseal_secret(tok.get('secret') or '', token_bind(tok.get('name')))
    if not secret:
        return None
    lines = [secret]
    tries = int(CONFIG.get('rate_limit_tries') or 0)
    if tries:
        lines.append('" RATE_LIMIT %d %d' % (tries, int(CONFIG.get('rate_limit_s') or 30)))
    # Its own window only (1.0.207): the setting's, written down, came back as the
    # token's own, and it no longer followed the setting.
    if tok.get('window_steps') is not None and int(tok.get('window_steps')) >= 0:
        w = Tokens.window(tok)     # the same as the check uses: 0 is 0 (1.0.36)
        lines.append('" WINDOW_SIZE %d' % (w * 2 + 1))
    if CONFIG.get('totp_disallow_reuse'):
        lines.append('" DISALLOW_REUSE')
    # What an import reads back to give the same codes (1.0.207): STEP_SIZE as
    # google-authenticator writes it, the rest acme's own - other tools pass them by.
    if int(tok.get('period') or 30) != 30:
        lines.append('" STEP_SIZE %d' % int(tok.get('period') or 30))
    if int(tok.get('digits') or 6) != 6:
        lines.append('" ACME_DIGITS %d' % int(tok.get('digits') or 6))
    if str(tok.get('algorithm') or 'SHA1').upper() != 'SHA1':
        lines.append('" ACME_ALGORITHM %s' % str(tok.get('algorithm')).upper())
    if tok.get('state') in ('disabled', 'pending'):
        lines.append('" ACME_STATE %s' % tok['state'])
    lines.append('" TOTP_AUTH')
    for c in codes_open(tok) or []:
        if isinstance(c, dict):
            if not c.get('used'):
                lines.append(str(c.get('c')))
        else:
            lines.append(str(c))
    return '\n'.join(lines) + '\n'


def _export_out(h, s, files, base, what, lock, phrase, single_text=None):
    """The export as the page saves it: a ZIP locked with the passphrase
    (AES-256, 1.0.167), or - asked for in so many words - not locked."""
    if lock:
        data, name, mime = zip_aes_write(files, phrase), base + '.zip', 'application/zip'
    elif single_text is not None:
        data, name, mime = single_text.encode('utf-8'), files[0][0], 'text/plain; charset=utf-8'
    else:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            for n, d in files:
                z.writestr(n, d)
        data, name, mime = buf.getvalue(), base + '.zip', 'application/zip'
    h.store.add_event('tokens', '%s exported %s%s' % (
        s['name'], what, ', locked with a passphrase' if lock else ' - NOT LOCKED'),
        'warn', who=s['name'])
    return {'name': name, 'file': base64.b64encode(data).decode('ascii'), 'mime': mime,
            'locked': bool(lock)}


@route('POST', '/api/tokens/export')
def _tokens_export(h):
    """Tokens as totpcgi files: one token as its .totp, several as a ZIP of
    them. Every key in it signs its owner in, so: a full administrator only,
    where showing keys is allowed, and every export written down. Locked with
    a passphrase unless the page says, as asked, it is not to be (1.0.167)."""
    s = h.me('fulladmin')
    if not CONFIG.get('admin_show_key'):
        raise ApiError(403, 'showing the keys of tokens is switched off (Settings - Tokens)')
    b = h.body()
    lock = b.get('lock', True) is not False
    phrase = str(b.get('passphrase') or '')
    if not lock and hisec_enforced('export:unlocked', h.store):
        raise ApiError(403, 'high security is on (Settings - High security): tokens are only exported '
                            'locked with a passphrase')
    if lock and len(phrase) < 8:
        raise ApiError(400, 'a passphrase of 8 characters at least - or choose not locked')
    arg = lambda k: str(b.get(k) or '')     # noqa: E731
    one = norm_name(arg('name'))
    if one:
        tok = h.store.token(one)
        if not tok:
            raise ApiError(404, 'there is no token for %s' % one)
        if token_kind(tok) != 'totp':
            raise ApiError(400, '%s gets its codes by mail or SMS: there is no key to export' % one)
        text = totp_file_text(tok)
        if text is None:
            raise ApiError(409, 'the key of this token cannot be opened on this machine')
        return dict(_export_out(h, s, [(totp_file_name(one), text.encode('utf-8'))],
                                totp_file_name(one)[:-5], 'the token of %s as a .totp file' % one,
                                lock, phrase, single_text=text), count=1)
    lq, bad = list_query('tokens', arg('q'))
    if bad:
        raise ApiError(400, bad)
    rows, _ = h.store.tokens(q=lq.words, extra=(lq.sql, lq.args), state=arg('state'),
                             limit=100000)
    files = []
    done, lost, odd = 0, [], []
    if True:
        for r in rows:
            tok = h.store.token(r['name'])
            if token_kind(tok) != 'totp':
                continue                # codes by mail or SMS: no key to take away (1.0.76)
            text = totp_file_text(tok or {})
            if text is None:
                lost.append(r['name'])
                continue
            if int(tok.get('digits') or 6) != 6 or int(tok.get('period') or 30) != 30 or \
                    str(tok.get('algorithm') or 'SHA1').upper() != 'SHA1':
                odd.append('%s (%s digits, %s s, %s)' % (r['name'], tok.get('digits'),
                                                         tok.get('period'), tok.get('algorithm')))
            files.append((totp_file_name(r['name']), text.encode('utf-8')))
            done += 1
        notes = ['%d token(s) exported by %s on %s at %s.' % (
            done, s['name'], node_name(), time.strftime('%Y-%m-%d %H:%M:%S')), '',
            'Each file is what totpcgi (google-authenticator) keeps for one person: the key,',
            'its options and the recovery codes not used yet. acme reads them back under',
            'Settings - Bringing tokens over, or: acme --import-totpcgi DIR', '']
        if odd:
            notes += ['Not 6 digits, 30 s and SHA-1 - totpcgi itself cannot check these:'] + \
                     ['  ' + x for x in odd] + ['']
        if lost:
            notes += ['Left out - their keys cannot be opened on this machine:'] + \
                     ['  ' + x for x in lost] + ['']
        notes += ['Every key here signs its owner in. Keep this file as you keep passwords.']
        files.append(('README.txt', ('\n'.join(notes) + '\n').encode('utf-8')))
    return dict(_export_out(h, s, files, 'acme-tokens-%s' % time.strftime('%Y%m%d-%H%M%S'),
                            '%d token(s) as .totp files%s' % (
                                done, (' (filter: %s)' % arg('q')) if arg('q') else ''),
                            lock, phrase), count=done, lost=lost)


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


def mailed_get(store, name):
    """Where a token's mail last went, and how (1.0.27): {to, lang, codes,
    at, by}, or {} when it never was mailed."""
    try:
        got = json.loads(store.get_meta('mailed:' + norm_name(name), '') or '{}')
        return got if isinstance(got, dict) else {}
    except ValueError:
        return {}


def mailed_set(store, name, to, lang, codes, by):
    store.set_meta('mailed:' + norm_name(name), json.dumps(
        {'to': to, 'lang': lang, 'codes': bool(codes), 'at': int(time.time()), 'by': by}))


def mailed_drop(store, name):
    store.db.run('DELETE FROM meta WHERE k = ?', ('mailed:' + norm_name(name),))


@route('GET', '/api/token')
def _token(h):
    h.me()
    name = norm_name(h.arg('name'))
    tok = h.store.token(name)
    checks, _ = h.store.acme_rows(hours=24 * 365, name=name, limit=30)
    reqs, _ = h.store.radius_rows(hours=24 * 365, user=name, limit=30)
    if not reqs and '@' not in name:
        reqs, _ = h.store.radius_rows(hours=24 * 365, q=name, limit=30)
    shown = h.store.token_shown(tok) if tok else None
    if shown:
        shown['last_client'] = h.store.client_name_of(tok)
    return {'token': shown, 'checks': checks, 'requests': reqs,
            'name': name, 'mailed': mailed_get(h.store, name) if tok else {}}


SEND_TEST_LOCK = threading.Lock()
SEND_TEST_SEEN = {}


@route('POST', '/api/token')
def _token_do(h):
    s = h.me('tokenadmin')
    b = h.body()
    act = str(b.get('action') or '')
    name = norm_name(b.get('name'))
    who = s['name']
    if act == 'fill_names':
        h.me('tokenadmin')
        got = h.d.fill_names(by=who)
        return dict(got, message='%d token(s) given their owner\'s name; %d not found in the '
                    'directory, %d with no directory to ask, %d could not be asked'
                    % (got['filled'], got['not_found'], got['no_directory'], got['trouble']))
    if not name:
        raise ApiError(400, 'which token?')
    if act == 'enroll' and not h.store.token(name):
        # A new token under its realm's own suffix (1.0.117): made for
        # novak@dpmo.local, it is novak@dpmo.cz where dpmo.local is another
        # suffix of that realm - the name RADIUS looks it up by.
        main = norm_name(realm_main_name(name, h.store.realm_for(name)))
        if main != name:
            name = main
    # One at a time per name, as a confirm is (1.0.61): switching off a
    # waiting token while its owner confirmed it switched it back on; a
    # rename takes the new name's lock as well, the two in one order.
    names = sorted({name, norm_name(b.get('to'))} if act == 'rename' and b.get('to')
                   else {name})
    locks = {id(lk): lk for lk in (h.d.tokens.lock_of(one) for one in names)}
    with contextlib.ExitStack() as held:
        for key in sorted(locks):       # always in one order, whoever takes two
            held.enter_context(locks[key])
        h._token_locks = [locks[key] for key in sorted(locks)]
        try:
            return _token_act(h, s, b, act, name, who)
        finally:
            h._token_locks = []


@contextlib.contextmanager
def token_locks_let_go(h):
    """The token's lock let go while a mail or a code is sent (1.0.206): RADIUS
    checks a code under it, and a person's sign-in waited on the SMS gateway or
    the mail server - 20 s and more - while the helpdesk sent them something."""
    held = list(getattr(h, '_token_locks', None) or [])
    saved = []
    for lk in reversed(held):
        saved.append((lk, lk._release_save()))
    try:
        yield
    finally:
        for lk, st in reversed(saved):
            lk._acquire_restore(st)


def token_same_person(store, name):
    """Another name of the same person with a token in use - one RADIUS would
    stop using once `name` has one (1.0.139): under another suffix of the
    realm, or the same account in another realm on the same directory."""
    if '@' not in name:
        return ''
    realm = store.realm_for(name)
    if not realm:
        return ''
    cands = realm_names(name, realm)[1:]
    if realm.get('lookup') == 'sam' and realm.get('directory'):
        who = name.rpartition('@')[0]
        here = str(realm.get('directory') or '').lower()
        for r in store.realms():
            if r['id'] != realm['id'] and r.get('lookup') == 'sam' and \
                    str(r.get('directory') or '').lower() == here and \
                    r.get('suffix') not in (None, '', '*'):
                cands.append(Authenticator.token_name('%s@%s' % (who, r['suffix']), r))
    for c in cands:
        c = norm_name(c)
        t = store.token(c) if c != name else None
        if t and t.get('state') != 'pending':
            return c
    return ''


def _token_act(h, s, b, act, name, who):
    tk = h.d.tokens
    if act in ('disable', 'enable', 'unlock', 'note', 'window', 'drop_staged') and \
            not h.store.token(name):
        # Written by name, these made an empty token of a name that had none.
        # (1.0.36)
        raise ApiError(404, 'there is no token %s' % name)
    if act == 'enroll':
        had = h.store.token(name)
        if had and had.get('state') != 'pending' and s['role'] != 'fulladmin':
            # Replacing a token in use hands out a working key for somebody
            # else (1.0.57): a full administrator's to do. A token
            # administrator makes new ones.
            raise ApiError(403, '%s already has a token in use: only a full administrator '
                                'replaces it (or the person, on the enrolment pages)' % name)
        other = token_same_person(h.store, name) if s['role'] != 'fulladmin' else ''
        if other:
            # The same person under another name (1.0.139): the new token
            # would be the one RADIUS takes - a working key for somebody else.
            raise ApiError(403, '%s is the same person as %s, who has a token in use: only a '
                                'full administrator replaces it' % (name, other))
        display = str(b.get('display') or '').strip()
        note = b.get('note')
        if had and not str(note or '').strip():
            note = None             # a new key keeps the note it had (1.0.36)
        kind = str(b.get('kind') or 'totp')
        if kind in ('mail', 'sms'):
            # A token that gets its codes by mail or SMS (1.0.76): where they
            # go, and recovery codes - nothing to scan.
            try:
                got = tk.enroll_sent(name, 'admin:' + who, kind, b.get('dest'), display=display,
                                     note=note, lang=b.get('lang'))
            except ValueError as e:
                raise ApiError(400, str(e))
            if not display and not (had or {}).get('display'):
                try:
                    h.d.fill_names([name], quiet=True)
                except Exception:                       # noqa: BLE001
                    pass
            h.store.add_event('tokens', '%s %s a token for %s: codes by %s to %s' % (
                who, 'replaced' if had else 'made', name, 'mail' if kind == 'mail' else 'SMS',
                got['dest']), 'warn' if had else 'info', who=who)
            return {'made': got, 'message': 'the token for %s is made: its codes go by %s to %s'
                    % (name, 'mail' if kind == 'mail' else 'SMS', got['dest'])}
        if kind != 'totp':
            raise ApiError(400, 'a token is totp, mail or sms')
        got = tk.enroll(name, 'admin:' + who, pending=bool(b.get('pending')),
                        note=note, display=display)
        if not display and not (had or {}).get('display'):
            # The person's name from the directory at once (1.0.20), not when
            # somebody next presses Names from the directory.
            try:
                h.d.fill_names([name], quiet=True)
            except Exception:                           # noqa: BLE001
                pass
        h.store.add_event('tokens', '%s %s a token for %s' % (
            who, 'replaced' if had else 'made', name), 'warn' if had else 'info', who=who)
        out = {'made': got, 'message': 'the token for %s is made' % name}
        to = str(b.get('mail_to') or '').strip()
        if b.get('mail') and to:
            # Its QR code - and the recovery codes, where asked - to the person
            # it is for (1.0.20). The token stays made whatever the mail does.
            if not re.match(r'^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+\Z', to):
                out['mail_error'] = '%s is not a mail address' % to
                return out
            lang = str(b.get('mail_lang') or CONFIG.get('mail_lang') or 'cs')
            lang = lang if lang in MAIL_WORDS else 'cs'
            tokrow = h.store.token(name) or {}
            try:
                msg = token_mail(to, name, got, codes=got.get('scratch') if b.get('mail_codes')
                                 else None, lang=lang, display=str(b.get('display') or
                                                                   tokrow.get('display') or ''),
                                 by=who, pending=bool(b.get('pending')),
                                 portal_url=h.portal_link())
                with token_locks_let_go(h):
                    steps = mail_deliver(h.store, msg, [to], kind='token', name=name, by=who,
                                         purpose='made')
                out['mail_steps'] = steps
                out['message'] += '; the QR code was sent to %s' % to
                h.store.add_event('mail', '%s sent the token of %s to %s%s%s' % (
                    who, name, to, ' with its recovery codes' if b.get('mail_codes') else '',
                    mail_reply_words(steps)), who=who)
                mailed_set(h.store, name, to, lang, b.get('mail_codes'), who)
            except MailError as e:
                out['mail_error'] = mailq_said(e)
                out['mail_steps'] = e.steps
                out['mail_queued'] = e.queued == 'waiting'
                h.store.add_event('mail', 'the token of %s could not be sent to %s: %s' % (
                    name, to, mailq_said(e)), 'warn', who=who)
        return out
    if not h.store.token(name):
        raise ApiError(404, 'there is no token for %s' % name)
    kind_now = token_kind(h.store.token(name))
    if kind_now != 'totp' and act in ('code_now', 'show', 'mail', 'stage'):
        raise ApiError(400, '%s gets its codes by %s: there is no key or QR code to show or send'
                       % (name, 'mail' if kind_now == 'mail' else 'SMS'))
    if act == 'dest':
        # Where a mail or SMS token's codes go (1.0.76). Of a token in use,
        # a full administrator's to change (1.0.94): it sends somebody's
        # sign-in codes elsewhere, as replacing the token would.
        if (h.store.token(name) or {}).get('state') != 'pending' and s['role'] != 'fulladmin':
            raise ApiError(403, 'the codes of a token in use go elsewhere only by a full '
                                'administrator\'s hand (or the person\'s, on the enrolment pages)')
        try:
            dest = tk.dest_change(name, b.get('dest'))
        except ValueError as e:
            raise ApiError(400, str(e))
        h.store.add_event('tokens', '%s changed where the codes of %s go: %s' % (who, name, dest),
                          'warn', who=who)
        return {'message': 'the codes of %s go to %s now' % (name, dest), 'dest': dest}
    if act in ('lang', 'mail_fmt'):
        # The language of a token's codes and questions, and whether its mail
        # is HTML or plain text (1.0.82). Empty: as the settings say.
        v = str(b.get('value') or '')
        if v not in (('', 'cs', 'en') if act == 'lang' else ('', 'html', 'text')):
            raise ApiError(400, 'no such choice: %s' % v)
        h.store.token_update(h.store.token(name)['id'], {act: v})
        h.store.add_event('tokens', '%s set the %s of %s: %s' % (
            who, 'language' if act == 'lang' else 'mail format', name, v or 'as the settings say'),
            who=who)
        return {'message': 'saved'}
    if act == 'send_test':
        # A message the way a code would go, with a code that opens nothing.
        tok = h.store.token(name)
        # Not without end (1.0.136): one a token in 30 s, ten in an hour -
        # a phone flooded, or a bill run up, from the pages.
        now = time.time()
        with SEND_TEST_LOCK:
            seen = [t for t in SEND_TEST_SEEN.get(name, []) if now - t < 3600]
            if seen and now - seen[-1] < 30:
                raise ApiError(429, 'a test went to %s a moment ago - wait half a minute' % name)
            if len(seen) >= 10:
                raise ApiError(429, 'ten tests went to %s in the last hour - that is enough'
                               % name)
            SEND_TEST_SEEN[name] = seen + [now]
            if len(SEND_TEST_SEEN) > 5000:
                SEND_TEST_SEEN.clear()
        began = time.time()
        try:
            with token_locks_let_go(h):
                said = code_send(h.store, kind_now, tok.get('dest') or '', code_new(), 'signin',
                                 name=name)
        except (MailError, SmsError, ValueError) as e:
            h.store.add_event('tokens', 'a test code for %s could not be sent: %s' % (name, e),
                              'warn', who=who)
            raise ApiError(502, 'it could not be sent: %s' % e)
        h.store.add_event('tokens', '%s sent a test message to where the codes of %s go'
                          % (who, name), who=who)
        return {'message': 'sent to %s in %.1f s - %s' % (tok.get('dest'), time.time() - began,
                                                         said)}
    if act == 'code_now':
        # The code the phone shows right now (1.0.40): a full administrator
        # only - it signs that person in for half a minute - and every look
        # written down. Not the key: the code ages out by itself.
        h.me('fulladmin')
        # As the key itself (1.0.44): the code signs that person in, so it is
        # shown only where the key may be.
        if not CONFIG.get('admin_show_key'):
            raise ApiError(403, 'showing the key of a token is switched off '
                                '(Settings -> The tokens)')
        tok = h.store.token(name)
        if not tok:
            raise ApiError(404, 'there is no token %s' % name)
        secret = unseal_secret(tok.get('secret') or '', token_bind(tok.get('name')))
        if not secret:
            raise ApiError(409, 'the key of this token cannot be opened on this machine')
        key = b32_clean(secret)
        digits = int(tok.get('digits') or 6)
        period = int(tok.get('period') or 30)
        algo = tok.get('algorithm') or 'SHA1'
        now = time.time()
        step = totp_step(now, period)
        # Written down whatever the page says (1.0.44): once per person and
        # token in five minutes, so the page asking for the next code every
        # half minute does not fill the events.
        seen_key = (who, name)
        with CODE_NOW_LOCK:
            last = CODE_NOW_SEEN.get(seen_key, 0)
            if b.get('first') or now - last > 300:
                CODE_NOW_SEEN[seen_key] = now
                fresh = True
            else:
                fresh = False
            if len(CODE_NOW_SEEN) > 2000:
                CODE_NOW_SEEN.clear()
        if fresh:
            h.store.add_event('tokens', '%s looked at the code the token of %s shows now'
                              % (who, name), 'warn', who=who)
        return {'code': hotp(key, step, digits, algo), 'next': hotp(key, step + 1, digits, algo),
                'period': period, 'digits': digits, 'now': now,
                'ends': (step + 1) * period, 'state': tok.get('state')}
    if act == 'show':
        # The key of somebody's second factor: a full administrator only,
        # where the setting allows it, and every look written down.
        h.me('fulladmin')
        if not CONFIG.get('admin_show_key'):
            raise ApiError(403, 'showing the key of a token is switched off '
                                '(Settings -> The tokens)')
        tok = h.store.token(name)
        staged = bool(tok.get('pending_secret')) and b.get('which') == 'waiting'
        secret = unseal_secret((tok.get('pending_secret') if staged else tok.get('secret')) or '',
                               token_bind(tok.get('name')))
        if not secret:
            raise ApiError(409, 'the key of this token cannot be opened (the key file of the '
                                'database is not the one it was sealed with)')
        if staged:
            # The waiting key in its own shape (1.0.32), not the old token's.
            sh = tk.staged_shape(name)
            got = tk.picture(name, secret, sh['digits'], sh['period'], sh['algorithm'],
                             sh['issuer'] or None)
        else:
            got = tk.picture(name, secret, tok.get('digits'), tok.get('period'),
                             tok.get('algorithm'), tok.get('issuer'))
        got['name'] = name
        got['scratch'] = []
        h.store.add_event('tokens', '%s looked at the key of the %stoken of %s'
                          % (who, 'waiting ' if staged else '', name), 'warn', who=who)
        return {'made': got}
    if act == 'codes':
        # The recovery codes left, shown again: the same rule as the key.
        h.me('fulladmin')
        if not CONFIG.get('admin_show_key'):
            raise ApiError(403, 'showing the key of a token is switched off '
                                '(Settings -> The tokens)')
        tok = h.store.token(name)
        codes = codes_open(tok)
        if codes is None:
            raise ApiError(409, 'the recovery codes of this token were not kept to be shown '
                                'again (it was made by an older version); make new ones')
        h.store.add_event('tokens', '%s looked at the recovery codes of %s' % (who, name),
                          'warn', who=who)
        return {'scratch': codes}
    if act == 'mail':
        # The token's QR code mailed again (1.0.27). The key leaves the
        # machine as when it is shown, so the same rule: a full administrator,
        # where showing keys is allowed.
        h.me('fulladmin')
        if not CONFIG.get('admin_show_key'):
            raise ApiError(403, 'showing - and so mailing - the key of a token is switched off '
                                '(Settings -> The tokens)')
        to = str(b.get('mail_to') or '').strip()
        if not re.match(r'^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+\Z', to):
            raise ApiError(400, '%s is not a mail address' % (to or 'nothing'))
        tok = h.store.token(name)
        secret = unseal_secret(tok.get('secret') or '', token_bind(tok.get('name')))
        if not secret:
            raise ApiError(409, 'the key of this token cannot be opened (the key file of the '
                                'database is not the one it was sealed with)')
        got = tk.picture(name, secret, tok.get('digits'), tok.get('period'),
                         tok.get('algorithm'), tok.get('issuer'))
        codes = None
        if b.get('mail_codes'):
            kept = codes_open(tok)
            if kept is None:
                raise ApiError(409, 'the recovery codes of this token were not kept to be sent '
                                    'again; send it without them, or make new ones first')
            codes = [c['c'] for c in kept if not c.get('used')]
        lang = str(b.get('mail_lang') or CONFIG.get('mail_lang') or 'cs')
        lang = lang if lang in MAIL_WORDS else 'cs'
        try:
            msg = token_mail(to, name, got, codes=codes, lang=lang,
                             display=str(tok.get('display') or ''), by=who,
                             pending=tok.get('state') == 'pending',
                             portal_url=h.portal_link())
            with token_locks_let_go(h):
                steps = mail_deliver(h.store, msg, [to], kind='token', name=name, by=who,
                                     purpose='again')
        except MailError as e:
            h.store.add_event('mail', 'the token of %s could not be sent to %s: %s' % (
                name, to, mailq_said(e)), 'warn', who=who)
            return {'sent': False, 'said': mailq_said(e), 'steps': e.steps,
                    'queued': e.queued == 'waiting'}
        mailed_set(h.store, name, to, lang, codes, who)
        h.store.add_event('mail', '%s sent the token of %s to %s again%s%s' % (
            who, name, to, ' with its recovery codes' if codes else '',
            mail_reply_words(steps)), 'warn', who=who)
        return {'sent': True, 'steps': steps, 'message': 'sent to %s' % to,
                'mailed': mailed_get(h.store, name)}
    if act in ('disable', 'enable'):
        if act == 'enable' and (h.store.token(name) or {}).get('state') != 'disabled':
            # Not switched off: nothing to switch on (1.0.61) - a waiting
            # token was made active by it.
            return {'message': 'it is not switched off'}
        h.store.token_write(name, {'state': token_switch_state(h.store, name, act == 'enable'),
                                   'failures': 0, 'fail_times': '[]', 'locked_until': None})
        h.store.add_event('tokens', '%s switched the token of %s %s' % (
            who, name, 'off' if act == 'disable' else 'on'), who=who)
        return {'message': 'switched %s' % ('off' if act == 'disable' else 'on')}
    if act == 'delete':
        # A token in use taken away, then made anew, was a token administrator's
        # way round the rule that only a full administrator replaces one
        # (1.0.94): switching it off is theirs, taking it away is not.
        if (h.store.token(name) or {}).get('state') not in ('pending', None) and \
                s['role'] != 'fulladmin':
            raise ApiError(403, 'only a full administrator takes away a token in use - '
                                'switch it off instead')
        h.store.token_drop(name)
        mailed_drop(h.store, name)
        tk._staged_forget(name)
        token_meta_forget(h.store, name)
        h.store.add_event('tokens', '%s took away the token of %s' % (who, name), 'warn',
                          who=who)
        return {'message': 'the token of %s is gone' % name}
    if act == 'scratch':
        # New recovery codes are working credentials of somebody else that
        # leave no trace on their phone (1.0.33): the same rule as showing a
        # key - a full administrator, where that is allowed - and a warning
        # in the events.
        h.me('fulladmin')
        if not CONFIG.get('admin_show_key'):
            raise ApiError(403, 'new recovery codes are shown to whoever makes them, and showing '
                                'codes and keys is switched off (Settings -> The tokens)')
        codes = tk.new_scratch(name, who)
        h.store.add_event('tokens', '%s made new recovery codes for %s' % (who, name), 'warn',
                          who=who)
        return {'scratch': codes, 'message': '%d new recovery codes' % len(codes)}
    if act == 'unlock':
        h.store.token_write(name, {'failures': 0, 'fail_times': '[]', 'locked_until': None})
        scratch_guard_give_back(h.store, name)
        h.store.add_event('tokens', '%s let %s try again at once' % (who, name), who=who)
        return {'message': 'the wrong codes are forgotten'}
    if act == 'rename':
        h.me('fulladmin')       # with a key known, a rename makes it somebody else's (1.0.57)
        # Into another realm: the part after the @ changes, and with it the
        # name the VPN has to send. The key and the history stay; the
        # recovery codes are made again under the new name where they were
        # kept to be shown, since their hashes are of the name too. (1.0.11)
        to = norm_name(b.get('to'))
        # The same rule as a new token's (1.0.44).
        if not to or not re.match(r'^[^\s@,;=\x00-\x1f\x7f]+(@[A-Za-z0-9.-]+)?\Z', to) or \
                len(to) > 180 or not isinstance(b.get('to'), str):
            raise ApiError(400, 'that is not a name: a name, or a name@realm - no spaces, '
                                'commas, semicolons or =, 180 characters at most')
        if to == norm_name(name):
            raise ApiError(400, 'that is the name it has')
        # The letters a name may have, as a new token's (1.0.207): renamed past them,
        # RADIUS refused the token for good.
        bad_letters = name_letters_problem(to)
        if bad_letters:
            raise ApiError(400, bad_letters)
        if h.store.token(to):
            raise ApiError(409, 'there is a token for %s already' % to)
        tok = h.store.token(name)
        if tok.get('pending_secret'):
            raise ApiError(409, 'a new key is waiting for a code from it: confirm it or throw it '
                                'away first')
        fields = {'name': to}
        codes = codes_open(tok)
        kept = True
        # Its sealed secrets are tied to its name: sealed again for the new
        # one (1.0.33), or they would no longer open.
        plain = unseal_secret(tok.get('secret') or '', token_bind(tok.get('name')))
        if plain:
            fields['secret'] = seal_secret(plain, token_bind(to))
        if codes is not None:
            fields['scratch'] = json.dumps([scratch_hash(to, c['c']) if isinstance(c, dict)
                                            else scratch_hash(to, c) for c in codes
                                            if not (isinstance(c, dict) and c.get('used'))])
            fields['scratch_sealed'] = seal_codes(codes, token_bind(to))
            fields['scratch_left'] = len(json.loads(fields['scratch']))     # 1.0.61
        elif tok.get('scratch_left'):
            kept = False
            fields.update(scratch='[]', scratch_left=0)
        # Moved to somebody else, the owner's name is theirs now (1.0.19).
        if norm_name(to).split('@', 1)[0] != norm_name(name).split('@', 1)[0]:
            fields['display'] = ''
        h.store.db.update('tokens', tok['id'], fields)
        h.store.db.run('UPDATE acme_log SET name = ? WHERE name = ?', (to, tok['name']))
        # What was kept aside under the old name goes with it (1.0.61).
        h.store.db.run('UPDATE meta SET k = ? WHERE k = ?',
                       ('disabled_from:' + norm_name(to), 'disabled_from:' + norm_name(name)))
        # Where its mail went goes with it - but only within the same
        # person: somebody else's token is not mailed to the old address.
        was = mailed_get(h.store, name)
        mailed_drop(h.store, name)
        if was and not fields.get('display') == '':
            mailed_set(h.store, to, was.get('to'), was.get('lang'), was.get('codes'),
                       was.get('by'))
        if fields.get('display') == '':
            h.d.fill_names_later([to])
        h.store.add_event('tokens', '%s moved the token of %s to %s' % (who, tok['name'], to),
                          'warn', who=who)
        return {'name': to, 'message': 'the token is now %s%s' % (
            to, '' if kept else '; its recovery codes were not kept to be made again under the '
                                'new name, so make new ones')}
    if act == 'note':
        h.store.token_write(name, {'note': str(b.get('note') or '')[:400]})
        h.store.add_event('tokens', '%s changed the note of %s' % (who, name), who=who)
        return {'message': 'the note is saved'}
    if act == 'window':
        w = int(b.get('window', -1))
        if not -1 <= w <= 20:
            raise ApiError(400, 'the window is -1 (the setting) or 0 to 20 steps')
        h.store.token_write(name, {'window_steps': w})
        h.store.add_event('tokens', '%s set the clock drift of %s to %s' % (
            who, name, 'the setting' if w < 0 else '%d step(s)' % w), who=who)
        return {'message': 'saved'}
    if act == 'test':
        # Counted per administrator and token (1.0.57): a dry test counts
        # nothing on the token, and so could be asked without end.
        h.throttle('code-test', 10, 5, name='%s>%s' % (who, name), name_tries=10)
        ok, said, facts = tk.check(name, str(b.get('code') or ''), how='test',
                                   src=h.client_ip(), dry=not b.get('use'))
        if not ok:
            h.failed('code-test')
        return {'good': ok, 'said': said, 'facts': facts}
    if act == 'confirm':
        ok, said = tk.confirm(name, str(b.get('code') or ''), how='admin', src=h.client_ip())
        if ok:
            h.store.add_event('tokens', '%s confirmed the token of %s' % (who, name), who=who)
        return {'good': ok, 'said': said}
    if act == 'drop_staged':
        tk.drop_staged(name)
        h.store.add_event('tokens', '%s threw away the replacement waiting for %s' % (who, name),
                          who=who)
        return {'message': 'the waiting replacement is gone; the old token stays'}
    raise ApiError(400, 'no such thing to do to a token: %s' % act)


def totp_file_name(name):
    """The file a token goes into, and its name read back from it (1.0.146):
    jan+1@x.cz and jan_1@x.cz were both jan_1@x.cz.totp - one lost in the ZIP
    - and o'neil@x.cz came back as o_neil@x.cz, which RADIUS never looks up."""
    from urllib.parse import quote
    return quote(str(name), safe='@.-_') + '.totp'


def totp_file_owner(fname):
    from urllib.parse import unquote
    fname = os.path.basename(str(fname or ''))
    return unquote(fname[:-5] if fname.endswith('.totp') else fname)


def totp_files_in_zip(b64, label, out, phrase=''):
    """The .totp files inside a ZIP the page sent (1.0.33) - a totpcgi
    folder zipped, or another acme's export. Read in memory with limits on
    everything: how big, how many, how far it unpacks. Nothing is written to
    disk and no name inside is used as a path."""
    try:
        raw = base64.b64decode(str(b64), validate=True)
    except (ValueError, binascii.Error):
        out.append({'name': label, 'said': 'not imported: not a ZIP the page could send'})
        return []
    got = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            infos = z.infolist()
            if len(infos) > 50000:
                raise ValueError('more than 50 000 files in it')
            total = 0
            for info in infos:
                base = info.filename.replace('\\', '/').rsplit('/', 1)[-1]
                if info.is_dir() or not base.endswith('.totp') or base.startswith('.') or \
                        '__MACOSX/' in info.filename:
                    continue
                if info.file_size > 64 * 1024:
                    out.append({'name': base, 'said': 'not imported: too big for a .totp file'})
                    continue
                total += info.file_size
                if total > 64 * 1024 * 1024:
                    raise ValueError('it unpacks to more than 64 MB')
                if info.flag_bits & 1:
                    # Locked (1.0.167): opened with the passphrase given.
                    if not phrase:
                        raise PermissionError('%s is locked - its passphrase opens it' % label)
                    data = zip_aes_open(raw, info, phrase)
                else:
                    with z.open(info) as f:
                        data = f.read(64 * 1024 + 1)
                if len(data) > 64 * 1024:
                    out.append({'name': base, 'said': 'not imported: too big for a .totp file'})
                    continue
                got.append({'name': base, 'text': data.decode('utf-8', 'replace')})
    except (zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError) as e:
        out.append({'name': label, 'said': 'not imported: %s' % e})
        return []
    if not got:
        out.append({'name': label, 'said': 'not imported: no .totp file in it'})
    return got


@route('POST', '/api/tokens/backup')
def _tokens_backup(h):
    """Every token chosen, of every kind, as one file (1.0.96): locked with
    a passphrase when one is given. A full administrator's, where keys may
    be shown, and written down."""
    s = h.me('fulladmin')
    if not CONFIG.get('admin_show_key'):
        raise ApiError(403, 'showing the keys of tokens is switched off (Settings - Tokens)')
    b = h.body()
    lq, bad = list_query('tokens', str(b.get('q') or ''))
    if bad:
        raise ApiError(400, bad)
    kind = str(b.get('kind') or '')
    rows, _ = h.store.tokens(q=lq.words, extra=(lq.sql, lq.args), state=str(b.get('state') or ''),
                             limit=1000000, kind=kind if kind in ('totp', 'mail', 'sms') else '')
    data = tokens_backup(h.store, [r['name'] for r in rows], s['name'])
    phrase = str(b.get('passphrase') or '')
    # Locked unless asked otherwise in so many words, and never under high
    # security (1.0.168): every key and recovery code is in it.
    lock = b.get('lock', True) is not False
    if not lock and hisec_enforced('export:unlocked', h.store):
        raise ApiError(403, 'high security is on (Settings - High security): tokens are only exported '
                            'locked with a passphrase')
    if lock and len(phrase) < 8:
        raise ApiError(400, 'a passphrase of 8 characters at least: the file holds every key')
    if not lock:
        phrase = ''
    text = json.dumps(bundle_lock(data, phrase, kind=TOKENS_KIND) if phrase else data, indent=1)
    h.store.add_event('tokens', '%s backed up %d token(s)%s%s' % (
        s['name'], data['count'], ' locked with a passphrase' if phrase else ' - NOT LOCKED',
        (' - %d left out, their keys cannot be opened here' % len(data['lost']))
        if data['lost'] else ''), 'warn', who=s['name'])
    return {'file': text, 'count': data['count'], 'lost': data['lost'], 'locked': bool(phrase),
            'name': 'acme-tokens-%s-%s.json' % (re.sub(r'[^A-Za-z0-9_-]', '_', node_name()),
                                               time.strftime('%Y%m%d-%H%M'))}


@route('POST', '/api/token/import')
def _token_import(h):
    s = h.me('fulladmin')
    b = h.body()
    out = []
    files = []
    # A whole backup (1.0.96): looked into first ("peek"), then all of it
    # or the tokens picked read back. .totp files and ZIPs of them as ever.
    phrase = str(b.get('passphrase') or '')
    want = set(norm_name(x) for x in (b.get('names') or []) if isinstance(x, str))
    repl_names = set(norm_name(x) for x in (b.get('replace_names') or []) if isinstance(x, str))
    backups = []
    for one in b.get('files') or []:
        if not isinstance(one, dict) or one.get('zip'):
            continue
        try:
            got = tokens_backup_open(str(one.get('text') or ''), phrase)
        except PermissionError as e:
            raise ApiError(423, str(e))
        except ValueError as e:
            raise ApiError(400, '%s: %s' % (one.get('name') or 'the file', e))
        if got is not None:
            backups.append((one, got))
    others = [one for one in b.get('files') or [] if isinstance(one, dict) and
              not any(one is x for x, _g in backups)]
    if backups and others:
        # Said, not passed over (1.0.207): the .totp files and ZIPs sent with a
        # backup were left out without a word.
        raise ApiError(400, 'a backup and .totp files or ZIPs together: bring them over one '
                            'kind at a time - %s left out otherwise' % ', '.join(
                                str(x.get('name') or 'a file') for x in others[:5]))
    if backups:
        if b.get('action') == 'peek':
            seen = []
            cols = sorted(set([c for c, _k in LIST_FIELDS['tokens'].values() if c] +
                              list(LIST_WORD_COLUMNS['tokens'])))
            nums = set(c for c, k in LIST_FIELDS['tokens'].values() if k == 'num')
            table = 'CREATE TABLE t (i INTEGER, %s)' % ', '.join(
                '%s %s' % (c, 'INTEGER' if c in nums else 'TEXT') for c in cols)
            mem = []
            for one, got in backups:
                for t in got['tokens']:
                    if not isinstance(t, dict):
                        continue
                    n = norm_name(t.get('name'))
                    seen.append({'name': n, 'kind': t.get('kind') or 'totp',
                                 'dest': t.get('dest') or '', 'state': t.get('state') or '',
                                 'codes': len([c for c in t.get('codes') or []
                                               if not (isinstance(c, dict) and c.get('used'))]),
                                 'display': t.get('display') or '', 'here': bool(h.store.token(n))})
                    left = len([c for c in t.get('codes') or []
                                if not (isinstance(c, dict) and c.get('used'))])
                    mem.append({'name': n, 'state': t.get('state') or '',
                                'kind': '' if (t.get('kind') or 'totp') == 'totp' else t.get('kind'),
                                'dest': t.get('dest') or '', 'lang': t.get('lang') or '',
                                'mail_fmt': t.get('mail_fmt') or '', 'note': t.get('note') or '',
                                'display': t.get('display') or '',
                                'created_by': t.get('created_by') or '',
                                'last_from': t.get('last_from') or '',
                                'last_how': t.get('last_how') or '', 'scratch_left': left,
                                'failures': 0, 'digits': int(t.get('digits') or 6)})
            # Searched with the words of the token list (1.0.96).
            q = str(b.get('q') or '')
            if q.strip():
                try:
                    keep = set(memory_search('tokens', table, cols, mem, q))
                except ListQueryError as e:
                    return {'q_error': str(e), 'backup': {'tokens': [], 'count': len(seen)}}
                seen = [x for i, x in enumerate(seen) if i in keep]
            first = backups[0][1]
            return {'backup': {'count': len(mem), 'shown': len(seen), 'made': first.get('made') or first.get('_made'),
                               'by': first.get('by'), 'node': first.get('node') or first.get('_from'),
                               'version': first.get('version'), 'lost': first.get('lost') or [],
                               'tokens': seen}}
        for one, got in backups:
            for t in got['tokens']:
                n = norm_name((t or {}).get('name') if isinstance(t, dict) else '')
                if want and n not in want:
                    continue
                try:
                    # Replaced one by one as the page chose (1.0.100), or all.
                    said = token_restore(h.store, t, 'restore:' + s['name'],
                                         replace=bool(b.get('replace')) or n in repl_names)
                except (ValueError, TypeError) as e:
                    said = 'not restored: %s' % e
                out.append({'name': n, 'said': said})
        h.store.add_event('tokens', '%s restored %d token(s) from a backup' % (
            s['name'], len([o for o in out if str(o['said']).startswith('restored')])),
            'warn', who=s['name'])
        return {'done': out}
    for one in b.get('files') or []:
        if one.get('zip'):
            try:
                files.extend(totp_files_in_zip(one.get('zip'), str(one.get('name') or 'the ZIP'),
                                               out, phrase))
            except PermissionError as e:
                raise ApiError(423, str(e))
        else:
            files.append(one)
    for one in files:
        fname = os.path.basename(str(one.get('name') or ''))
        name = totp_file_owner(fname)
        if want and norm_name(name) not in want:
            continue
        try:
            said = import_totp(h.store, name, str(one.get('text') or ''), 'import:' + s['name'],
                               replace=bool(b.get('replace')))
        except ValueError as e:
            said = 'not imported: %s' % e
        out.append({'name': norm_name(name), 'said': said})
    h.store.add_event('tokens', '%s imported %d token file(s)' % (s['name'], len(out)),
                      who=s['name'])
    # Their owners' names from the directory, as an enrolment on the pages
    # would have given them - in the background, the list is not kept waiting.
    h.d.fill_names_later([o['name'] for o in out if str(o['said']).startswith('imported')],
                         by=s['name'])
    return {'done': out}


