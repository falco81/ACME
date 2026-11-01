# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the texts of the messages (1.0.103) -------------------------------------------
def text_mail(to, drawn):
    """A mail of what text_render drew ({'subject', 'html', 'text'})."""
    site = str(CONFIG.get('site_name') or socket.gethostname())
    sender = mail_sender()
    if not sender:
        raise MailError('no sender address is set - Settings → Mail → From (address)')
    msg = EmailMessage()
    msg['Subject'] = str(drawn.get('subject') or site)
    msg['From'] = formataddr((str(CONFIG.get('mail_from_name') or site), sender))
    msg['To'] = to
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=sender.rsplit('@', 1)[-1] or None)
    msg['Auto-Submitted'] = 'auto-generated'
    msg.set_content(str(drawn.get('text') or ''))
    if drawn.get('html'):
        msg.add_alternative(str(drawn['html']), subtype='html')
    return msg


@route('GET', '/api/texts')
def _texts(h):
    s = h.me()
    mid = h.arg('render')
    if mid:
        if not text_message(mid):
            raise ApiError(404, 'no such message')
        lang = h.arg('lang') if h.arg('lang') in TEXT_LANGS else 'cs'
        return text_render(h.store, mid, lang, mark=h.arg('mark') == '1')
    return {'messages': text_state(h.store), 'placeholders': TEXT_PLACEHOLDERS,
            'langs': list(TEXT_LANGS), 'may_change': s['role'] == 'fulladmin',
            'samples': {lang: text_samples(lang) for lang in TEXT_LANGS},
            'sender': '%s <%s>' % (CONFIG.get('mail_from_name') or CONFIG.get('site_name') or
                                   socket.gethostname(), CONFIG.get('mail_from') or ''),
            'sms_plain': bool(CONFIG.get('sms_plain', 1)), 'node': node_name(),
            'ha': bool(CONFIG.get('ha_mode'))}


@route('POST', '/api/texts')
def _texts_do(h):
    b = h.body()
    act = str(b.get('action') or '')
    s = h.me('fulladmin') if act in ('save', 'reset', 'test') else h.me()
    mid = str(b.get('id') or '')
    m = text_message(mid)
    lang = str(b.get('lang') or '')
    if not m or lang not in TEXT_LANGS:
        raise ApiError(400, 'no such message or language')
    fields = b.get('fields') if isinstance(b.get('fields'), dict) else {}
    if act == 'preview':
        # What the editor holds now, each field checked and cleaned as a
        # save would - and said which one is wrong, not saved.
        clean, bad = {}, {}
        for f in m['fields']:
            if f[0] in fields:
                try:
                    clean[f[0]] = text_check(f, fields[f[0]])
                except ValueError as e:
                    bad[f[0]] = str(e)
        out = text_render(h.store, mid, lang, clean)
        out['bad'] = bad
        out['clean'] = clean
        return out
    if act == 'save':
        try:
            new = text_save(h.store, mid, lang, fields, s['name'],
                            was_at=b.get('was_at') if 'was_at' in b else None)
        except TextConflict as e:
            raise ApiError(409, str(e))
        except ValueError as e:
            raise ApiError(400, str(e))
        h.store.add_event('settings', '%s changed the texts of “%s” (%s)'
                          % (s['name'], m['title'], lang.upper()), who=s['name'])
        return {'message': 'saved - both nodes send these words now', 'saved': new,
                'state': text_state(h.store, mid)[0]}
    if act == 'reset':
        keys = [str(k) for k in (b.get('keys') or []) if isinstance(k, str)]
        text_reset(h.store, mid, lang, keys or None)
        h.store.add_event('settings', '%s put %s of “%s” (%s) back as it comes'
                          % (s['name'], 'the texts' if not keys else ', '.join(keys), m['title'],
                             lang.upper()), 'warn', who=s['name'])
        return {'message': 'put back as it comes', 'state': text_state(h.store, mid)[0]}
    if act == 'test':
        key = h.throttle('texts-test', 10, 15, name=s['name'])
        h.failed(key)
        to = str(b.get('to') or '').strip()
        clean = {}
        for f in m['fields']:
            if f[0] in fields:
                try:
                    clean[f[0]] = text_check(f, fields[f[0]])
                except ValueError as e:
                    raise ApiError(400, str(e))
        w = text_words(mid, lang, clean)
        smp = text_samples(lang)
        try:
            if m['kind'] == 'sms':
                to = dest_checked('sms', to)
                said = sms_send(to, sms_plain(w[m['fields'][0][0]].format(**smp)))
            elif m['kind'] == 'mail':
                to = dest_checked('mail', to)
                if m['group'] == 'code':
                    msg = code_message('mail', to, smp['code'], m['purpose'], lang=lang,
                                       name=smp['account'], display=smp['name'], fmt='html', w=w)
                elif callable(m.get('render')):
                    # A module's own mail: the preview it draws, sent as it is.
                    msg = text_mail(to, m['render'](w, smp, lang) or {})
                else:
                    raise ApiError(400, 'this message has no mail to send')
                steps = mail_deliver(h.store, msg, [to], kind='test', by=s['name'],
                                     purpose='texts')
                last = [x for x in steps if x.get('ok')]
                said = (last[-1].get('said') or 'sent') if last else 'sent'
            else:
                raise ApiError(400, 'this text is not sent by itself - it is part of a page')
        except ValueError as e:
            raise ApiError(400, str(e))
        except (MailError, SmsError) as e:
            raise ApiError(502, str(e))
        h.store.add_event('settings', '%s sent a sample of “%s” (%s) to %s'
                          % (s['name'], m['title'], lang.upper(), to), who=s['name'])
        return {'message': 'sent to %s with sample values: %s' % (to, said)}
    raise ApiError(400, 'no such thing to do with the texts')
# ---- a second step for the administration (1.0.125) ---------------------------------
# With admin_2fa on, a password right for these pages opens a sign-in that can
# do nothing yet but its second step (MFA_ALLOWED): a code from an app, or one
# sent by mail or SMS. The first time the account chooses how and proves it
# (enrol); after that it gives the code each time (check). The way chosen is
# the account's own, kept in meta 'adm2fa:<name>':
#   {'kind': 'app'|'mail'|'sms', 'secret': sealed (app), 'dest': (mail/sms),
#    'at', 'step': the last app code's step, used once}
# Accounts → Reset the second step and acme --reset-2fa NAME take it away.
MFA_ALLOWED = ('/api/auth/mfa', '/api/auth/logout', '/api/auth/whoami')
MFA_SEND_GAP_S = 30
MFA_SEND_MOST = 5
MFA_LOCK = threading.Lock()


def mfa_key(name):
    return 'adm2fa:' + str(name or '').strip().lower()


def mfa_get(store, name):
    try:
        got = json.loads(store.get_meta(mfa_key(name)) or 'null')
    except ValueError:
        return None
    return got if isinstance(got, dict) else None


def mfa_all(store):
    out = {}
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'adm2fa:%'"):
        try:
            v = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        out[r['k'][len('adm2fa:'):]] = {'kind': v.get('kind'), 'at': v.get('at'),
                                        'dest': dest_masked(v.get('kind'), v.get('dest'))}
    return out


def mfa_reset(store, name, by):
    had = mfa_get(store, name)
    store.db.run('DELETE FROM meta WHERE k = ?', (mfa_key(name),))
    store.add_event('accounts', '%s reset the second step of signing in of %s%s' % (
        by, name, ' (it was %s)' % MFA_KIND_WORDS.get(had.get('kind'), had.get('kind'))
        if had else ' (none was set up)'), 'warn', who=by)
    return bool(had)


MFA_KIND_WORDS = {'app': 'an authenticator app', 'mail': 'a code by e-mail',
                  'sms': 'a code by SMS'}


def mfa_lang(h):
    """The language of the page the code was asked from - its cookie - or
    the codes' own."""
    got = str(h.headers.get('X-Acme-Lang') or '')
    if not got:
        m = re.search(r'(?:^|;\s*)acme_lang=([a-z]{2})', str(h.headers.get('Cookie') or ''))
        got = m.group(1) if m else ''
    return got if got in CODE_TEXTS else None


def mfa_methods():
    """The ways offered when an account sets up its second step."""
    out = []
    ch = code_channels()
    if CONFIG.get('admin_2fa_app', 1):
        out.append('app')
    if CONFIG.get('admin_2fa_mail', 1) and 'mail' in ch:
        out.append('mail')
    if CONFIG.get('admin_2fa_sms', 1) and 'sms' in ch:
        out.append('sms')
    return out or ['app']


def mfa_stage(store, name):
    rec = mfa_get(store, name)
    if rec and rec.get('kind') in ('app', 'mail', 'sms'):
        # A way switched off since is still the account's, and the only one
        # (1.0.136): mail or SMS that can no longer be sent was set up anew
        # - by whoever had the password. Now that waits for a reset (the
        # accounts page, or acme --reset-2fa NAME as root).
        return 'check'
    return 'enrol'


def mfa_pending(s):
    """The sign-in's second step, if it is still to be done."""
    if not CONFIG.get('admin_2fa'):
        return ''
    return str(((s or {}).get('data') or {}).get('mfa') or '')


def _mfa_session(h, kind='admin'):
    s = h.session(kind)
    if not s:
        raise ApiError(401, 'not signed in, or the sign-in has run out')
    if kind == 'portal':
        # On the enrolment pages only an account of acme's own has a second
        # step (portal_local): a directory sign-in has none to give.
        if (s.get('data') or {}).get('kind') != 'local' or not CONFIG.get('portal') or \
                not CONFIG.get('portal_local'):
            raise ApiError(401, 'this sign-in has no second step to give')
    acc = h.store.account(s['name'])
    if not acc or acc.get('disabled') or (kind == 'portal' and acc.get('source') == 'directory'):
        raise ApiError(401, 'that account may no longer sign in')
    return s, acc


def _mfa_throttle(h, kind, name):
    """Wrong codes counted as the wrong passwords of the same sign-in are."""
    if kind == 'portal':
        return h.throttle('portal', int(CONFIG.get('portal_tries') or 5),
                          int(CONFIG.get('portal_wait_min') or 15), name=name,
                          what='wrong codes')
    return h.throttle('admin', int(CONFIG.get('login_tries') or 5),
                      int(CONFIG.get('login_wait_min') or 15), name=name, what='wrong codes')


def _mfa_code_ok(saved, code):
    if not saved or time.time() > float(saved.get('exp') or 0):
        return False
    return hmac.compare_digest(code_hash(saved.get('salt') or '', str(code or '').strip()),
                               str(saved.get('hash') or ''))


def _mfa_send(h, s, kind, dest, field):
    data = s.get('data') or {}
    t = time.time()
    if t - float(data.get('mfa_sent_at') or 0) < MFA_SEND_GAP_S:
        raise ApiError(429, 'a code went a moment ago - wait half a minute for another')
    n = int(data.get('mfa_sent') or 0)
    if n >= MFA_SEND_MOST:
        raise ApiError(429, 'that is %d codes for this sign-in: sign in again for more'
                       % MFA_SEND_MOST)
    code, salt = code_new(), secrets.token_hex(8)
    saved = {'hash': code_hash(salt, code), 'salt': salt,
             't': t, 'exp': t + int(CONFIG.get('code_ttl_s') or 300)}
    try:
        acc = h.store.account(s['name']) or {}
        said = code_send(h.store, kind, dest, code, purpose='admin_verify' if field == 'mfa_new'
                         else 'admin', name=s['name'], display=acc.get('display') or '',
                         lang=mfa_lang(h))
    except (MailError, SmsError, ValueError) as e:
        h.store.add_event('sign-ins', 'the code of the second step for %s could not be sent '
                          '(%s): %s' % (s['name'], kind, e), 'warn', who=s['name'])
        raise ApiError(502, 'the code could not be sent: %s' % e)
    # Kept only once it went: a refused one leaves the last code good.
    new = dict(saved, kind=kind, dest=dest) if field == 'mfa_new' else saved
    h.store.session_merge(s['id'], {field: new, 'mfa_sent_at': t, 'mfa_sent': n + 1})
    log('the second step of %s: a code sent by %s to %s (%s)' % (
        s['name'], kind, dest_masked(kind, dest), said))
    return dest_masked(kind, dest)


def _mfa_done(h, s, how, kind='admin'):
    """The second step given: a sign-in of its own from here on (1.0.149) - the
    one the password alone opened is ended, not made whole: whoever had seen
    its cookie had the pages once the code was given."""
    data = {k: v for k, v in (s.get('data') or {}).items()
            if k not in ('mfa', 'mfa_new', 'mfa_code', 'mfa_sent_at', 'mfa_sent')}
    hours = max(0.05, (float(s.get('expires') or 0) - time.time()) / 3600.0)
    token = h.store.session_new(kind, s['name'], s['role'], h.client_ip(), hours, data=data)
    h.store.session_drop(s['id'])
    h.store.add_event('sign-ins', '%s gave the second step (%s) from %s%s' % (
        s['name'], how, h.client_ip(), ' on the enrolment pages' if kind == 'portal' else ''),
        who=s['name'])
    return token


@route('GET', '/api/auth/mfa')
def _mfa(h):
    return _mfa_view(h, 'admin')


@route('GET', '/api/portal/mfa')
def _portal_mfa(h):
    # The same second step, for an account of acme's own signed in on the
    # enrolment pages (portal_local).
    return _mfa_view(h, 'portal')


@route('POST', '/api/portal/mfa')
def _portal_mfa_do(h):
    return _mfa_act(h, 'portal')


def _mfa_view(h, kind):
    s, acc = _mfa_session(h, kind)
    stage = mfa_pending(s)
    rec = mfa_get(h.store, s['name']) or {}
    new = (s.get('data') or {}).get('mfa_new') or {}
    return {'name': acc['name'], 'display': acc.get('display') or '', 'stage': stage,
            'methods': mfa_methods(), 'kind': rec.get('kind') if stage == 'check' else '',
            'dest': dest_masked(rec.get('kind'), rec.get('dest')) if stage == 'check' else '',
            'started': {'kind': new.get('kind'),
                        'dest': dest_masked(new.get('kind'), new.get('dest'))} if new else None,
            'digits': 6 if (stage == 'check' and rec.get('kind') == 'app') else
            int(CONFIG.get('code_digits') or 6)}


@route('POST', '/api/auth/mfa')
def _mfa_do(h):
    return _mfa_act(h, 'admin')


def _mfa_act(h, kind):
    s, acc = _mfa_session(h, kind)
    stage = mfa_pending(s)
    if not stage:
        raise ApiError(409, 'this sign-in has no second step to give')
    b = h.body()
    act = b.get('action')
    name = acc['name']
    data = s.get('data') or {}
    # The account as it is now, not as it was at this sign-in (1.0.139): a
    # sign-in kept waiting from before the second step was set up could set
    # up its own, over the one in use.
    if act in ('enrol_start', 'enrol_confirm') and stage == 'enrol' and \
            mfa_stage(h.store, name) != 'enrol':
        raise ApiError(409, 'this account has its second step set up already - sign in again')
    if act == 'enrol_start':
        if stage != 'enrol':
            raise ApiError(409, 'this account has its second step set up already')
        kind = str(b.get('kind') or '')
        if kind not in mfa_methods():
            raise ApiError(400, 'that way is not offered here')
        if kind == 'app':
            secret = b32_new(20)
            h.store.session_merge(s['id'], {'mfa_new': {
                'kind': 'app', 'secret': seal_secret(secret, 'adm2fa-new:' + name.lower())}})
            site = str(CONFIG.get('site_name') or socket.gethostname())
            uri = otpauth_uri(secret, name, '%s (administration)' % site)
            return {'kind': 'app', 'qr': qr_data_uri(uri), 'uri': uri,
                    'secret': ' '.join(secret[i:i + 4] for i in range(0, len(secret), 4))}
        try:
            dest = dest_checked(kind, b.get('dest'))
        except ValueError as e:
            raise ApiError(400, str(e))
        return {'kind': kind, 'sent_to': _mfa_send(h, s, kind, dest, 'mfa_new')}
    if act == 'enrol_confirm':
        if stage != 'enrol':
            raise ApiError(409, 'this account has its second step set up already')
        new = data.get('mfa_new') or {}
        if not new.get('kind'):
            raise ApiError(400, 'choose a way first')
        key = _mfa_throttle(h, kind, name)
        code = re.sub(r'\s', '', str(b.get('code') or ''))
        rec = {'kind': new['kind'], 'at': time.time(), 'by': name}
        if new['kind'] == 'app':
            secret = unseal_secret(new.get('secret'), 'adm2fa-new:' + name.lower())
            step = totp_match(secret, code, digits=6, window=mfa_window()) \
                if secret else None
            if step is None:
                h.failed(key)
                raise ApiError(400, 'that code is not right - the one the app shows now')
            rec.update(secret=seal_secret(secret, mfa_key(name)), step=step)
        else:
            if not _mfa_code_ok(new, code):
                h.failed(key)
                raise ApiError(400, 'that code is not right, or no longer good - send another')
            rec['dest'] = new['dest']
        with MFA_LOCK:
            if mfa_stage(h.store, name) != 'enrol':
                raise ApiError(409, 'this account has its second step set up already - sign '
                                    'in again')
            h.store.set_meta(mfa_key(name), json.dumps(rec))
        token = _mfa_done(h, s, 'set up now: %s' % MFA_KIND_WORDS.get(rec['kind']), kind)
        h.store.add_event('accounts', '%s set up the second step of signing in: %s%s' % (
            name, MFA_KIND_WORDS.get(rec['kind']),
            ' (%s)' % dest_masked(rec['kind'], rec.get('dest')) if rec.get('dest') else ''),
            who=name)
        return {'message': 'the second step is set up', 'done': True, 'token': token}
    if act == 'send':
        if stage != 'check':
            raise ApiError(409, 'set the second step up first')
        rec = mfa_get(h.store, name) or {}
        if rec.get('kind') not in ('mail', 'sms'):
            raise ApiError(400, 'the code comes from the app - nothing is sent')
        if rec['kind'] not in code_channels():
            raise ApiError(503, 'codes by %s cannot be sent from here now: another full '
                                'administrator resets your second step (Accounts), or root '
                                'with  acme --reset-2fa %s' % ('mail' if rec['kind'] == 'mail'
                                                              else 'SMS', name))
        return {'sent_to': _mfa_send(h, s, rec['kind'], rec.get('dest'), 'mfa_code')}
    if act == 'check':
        if stage != 'check':
            raise ApiError(409, 'set the second step up first')
        rec = mfa_get(h.store, name) or {}
        key = _mfa_throttle(h, kind, name)
        code = re.sub(r'\s', '', str(b.get('code') or ''))
        if rec.get('kind') == 'app':
            # Read, checked and written under one lock (1.0.136): two requests
            # with the same code at once both passed the check.
            with MFA_LOCK:
                rec = mfa_get(h.store, name) or {}
                secret = unseal_secret(rec.get('secret'), mfa_key(name))
                step = totp_match(secret, code, digits=6,
                                  window=mfa_window()) if secret else None
                # A code is good once, and on either node (1.0.205): the step
                # taken in used_once - the other node's own lock did not keep a
                # code used here from being used there too.
                if step is not None and step > int(rec.get('step') or 0) and \
                        not once_take(h.store, 'step', 'adm2fa:' + name, step):
                    h.failed(key)
                    raise ApiError(400, 'that code was used already - wait for the next one')
                if step is None or step <= int(rec.get('step') or 0):
                    h.failed(key)
                    raise ApiError(400, 'that code is not right' if step is None else
                                   'that code was used already - wait for the next one')
                rec['step'] = step
                h.store.set_meta(mfa_key(name), json.dumps(rec))
        else:
            if not _mfa_code_ok(data.get('mfa_code'), code) or \
                    not h.store.session_take(s['id'], 'mfa_code'):
                h.failed(key)
                raise ApiError(400, 'that code is not right, or no longer good - send another')
        token = _mfa_done(h, s, MFA_KIND_WORDS.get(rec.get('kind')), kind)
        return {'message': 'signed in', 'done': True, 'token': token}
    raise ApiError(400, 'no such thing to do')


def mfa_window():
    """The steps either side a code is taken from (1.0.205): 0 as it is set -
    `or 1` made the strict window the usual one."""
    v = CONFIG.get('totp_window')
    try:
        return max(0, int(v)) if v is not None and v != '' else 1
    except (TypeError, ValueError):
        return 1



