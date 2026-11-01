# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The tokens themselves
# ---------------------------------------------------------------------------
# The words a check of a code ends in are totpcgi's own, letter for letter:
# isemon reads them out of the token log and turns them into its own words
# (`ACME_SAYS`), and anything that already watches a token server knows them.
SAY_OK = 'Valid token used'
SAY_OK_DRIFT = 'Valid token within window size used'
SAY_SCRATCH = 'Scratch-token used'
SAY_BAD = 'Not a valid token'
SAY_REUSED = 'Token has already been used once'
SAY_RATE = 'Rate-limit reached, please try again later'
SAY_LOCKED = 'Locked out after too many wrong codes, please try again later'
SAY_NONE = 'No token is enrolled for this account'
SAY_OFF = 'This token is switched off'
SAY_PENDING = 'This token has not been confirmed yet'
SAY_LOST = 'The key of this token cannot be opened on this machine'


def seal_codes(codes, bind=None):
    """Recovery codes kept so that an administrator can show them again -
    each with when it was used, if it was: sealed with the key of the tokens,
    beside their hashes, which are what a code is checked against."""
    if not codes:
        return ''
    out = []
    for c in codes:
        out.append(dict(c) if isinstance(c, dict) else {'c': str(c), 'used': None})
    return seal_secret(json.dumps(out), bind)


def open_codes(value, bind=None):
    """The codes `seal_codes` kept, as [{c, used}] - also the plain JSON list
    an older version left in pending_scratch. None when none are kept."""
    if not value:
        return None
    text = unseal_secret(value, bind)
    if text is None and str(value).lstrip().startswith('['):
        text = value
    try:
        got = json.loads(text) if text else None
    except ValueError:
        return None
    if not isinstance(got, list):
        return None
    return [dict(x) if isinstance(x, dict) else {'c': str(x), 'used': None} for x in got]


# The checks of a code a RADIUS worker makes, kept until its answer went (1.0.186).
ACME_LOG_LATER = threading.local()


class Tokens(object):
    """Making, checking and looking after tokens."""

    def __init__(self, store):
        self.store = store
        # A fixed row of locks, a name always to the same one: two checks of
        # one token wait for each other, and the row cannot grow however
        # many names are tried.
        self.locks = [threading.RLock() for _ in range(1024)]  # re-entered (1.0.59)
        self.on_check = None                       # (name, ok, said, how, src, rid)

    def lock_of(self, name):
        return self.locks[zlib.crc32(str(name).encode('utf-8')) % len(self.locks)]

    # ---- made ------------------------------------------------------------------
    def label_for(self, name):
        tpl = str(CONFIG.get('totp_label') or '{user}')
        return tpl.replace('{user}', name).replace('{name}', name.split('@', 1)[0])[:190]

    def fresh(self):
        """A new key and new recovery codes, not yet anybody's."""
        secret = b32_new(20)
        codes = scratch_new(int(CONFIG.get('scratch_count') or 0),
                            int(CONFIG.get('scratch_digits') or 8))
        return secret, codes

    def picture(self, name, secret, digits=None, period=None, algorithm=None, issuer=None):
        """What the person scans, in every shape a page wants it."""
        digits = int(digits or CONFIG.get('totp_digits') or 6)
        period = int(period or CONFIG.get('totp_period') or 30)
        algorithm = str(algorithm or CONFIG.get('totp_algorithm') or 'SHA1')
        issuer = issuer if issuer is not None else str(CONFIG.get('totp_issuer') or '')
        uri = otpauth_uri(secret, self.label_for(name), issuer, digits, period, algorithm)
        return {'uri': uri, 'qr': qr_data_uri(uri), 'secret': secret,
                'secret_spaced': ' '.join(secret[i:i + 4] for i in range(0, len(secret), 4)),
                'issuer': issuer, 'label': self.label_for(name), 'digits': digits,
                'period': period, 'algorithm': algorithm}

    def enroll(self, name, by, pending=False, secret=None, codes=None, display='', note=None):
        """A token for `name`, replacing any there was. `pending` makes it wait
        for a code before it is used. Returns the picture and the codes."""
        # One at a time per name, with confirm (1.0.59): a confirm landing on
        # a key written meanwhile made an unproven key active.
        with self.lock_of(norm_name(name)):
            return self._enroll(name, by, pending, secret, codes, display, note)

    def _enroll(self, name, by, pending=False, secret=None, codes=None, display='', note=None,
                extra=None):
        name = norm_name(name)
        if not name:
            raise ValueError('a token needs a name')
        # 180 at most (1.0.44): staged:NAME and mailed:NAME have to fit a key.
        # No control character either (1.0.103): a NUL is stored as U+FFFD,
        # and the key sealed to the name as sent never opened again.
        if not re.match(r'^[^\s,;=\x00-\x1f\x7f]{1,180}\Z', name):
            raise ValueError('a name has no spaces, commas, semicolons or = in it, and '
                             'is 180 characters at most')
        if secret is None:
            secret, codes = self.fresh()
        codes = list(codes or [])
        # The picture first (1.0.103): one that cannot be made (an issuer too
        # long for a QR code) refused before the token's key was replaced -
        # the old key gone and the new one never shown.
        out = self.picture(name, secret)
        fields = {
            'secret': seal_secret(secret, token_bind(name)),
            'digits': int(CONFIG.get('totp_digits') or 6),
            'period': int(CONFIG.get('totp_period') or 30),
            'algorithm': str(CONFIG.get('totp_algorithm') or 'SHA1'),
            'state': 'pending' if pending else 'active', 'last_step': 0,
            'scratch': json.dumps([scratch_hash(name, c) for c in codes]),
            'scratch_sealed': seal_codes(codes, token_bind(name)),
            'scratch_left': len(codes), 'created': time.time(), 'created_by': str(by)[:190],
            'activated': None if pending else time.time(), 'failures': 0,
            'fail_times': '[]', 'locked_until': None,
            'issuer': str(CONFIG.get('totp_issuer') or ''),
            'label': self.label_for(name), 'pending_secret': None, 'pending_scratch': None,
            'pending_at': None, 'pending_by': None, 'last_used': None, 'last_from': '',
            'last_how': '', 'kind': '', 'dest': ''}
        if display:
            fields['display'] = str(display)[:300]
        if note is not None:
            fields['note'] = str(note)[:400]
        if extra:
            fields.update(extra)
        self.store.token_write(name, fields)
        self._staged_forget(name)
        try:                            # a new token was never switched off (1.0.61)
            self.store.db.run('DELETE FROM meta WHERE k = ?', ('disabled_from:' + name,))
        except Exception:                               # noqa: BLE001
            pass
        out['scratch'] = codes
        out['name'] = name
        return out

    def enroll_sent(self, name, by, kind, dest, display='', note=None, lang=None,
                    mail_fmt=None):
        """A token that gets its codes sent (1.0.76): by mail or SMS to
        `dest`. No key anybody scans - one is kept all the same, never shown,
        so everything that reads a token's columns reads this one too - and
        recovery codes as any token has. In use at once: the address or the
        number was proven by the one who made it."""
        if kind not in ('mail', 'sms'):
            raise ValueError('a token that gets codes sent is mail or sms')
        dest = dest_checked(kind, dest)
        name = norm_name(name)
        with self.lock_of(name):
            out = self._enroll(name, by, pending=False, display=display, note=note,
                               extra=dict({'kind': kind, 'dest': dest,
                                           'digits': int(CONFIG.get('code_digits') or 6),
                                           'issuer': '', 'label': ''},
                                          **dict({'lang': lang} if lang in ('cs', 'en') else {},
                                                 **({'mail_fmt': mail_fmt}
                                                    if mail_fmt in ('html', 'text') else {}))))
        return {'name': name, 'kind': kind, 'dest': dest, 'scratch': out.get('scratch') or []}

    def dest_change(self, name, dest):
        """Where a mail or SMS token's codes go."""
        name = norm_name(name)
        with self.lock_of(name):
            tok = self.store.token(name)
            kind = token_kind(tok)
            if not tok or kind == 'totp':
                raise ValueError('%s has no token that gets codes sent' % name)
            dest = dest_checked(kind, dest)
            self.store.token_update(tok['id'], {'dest': dest})
        return dest

    def used_sent(self, name, how):
        """A sent code was right: written on the token as a code from the
        phone would be."""
        self.store.db.run("UPDATE tokens SET last_used = ?, failures = 0, fail_times = '[]', "
                          'last_how = ? WHERE name = ?', (time.time(), how, norm_name(name)))

    # ---- the shape of a key waiting beside an old one (1.0.32) ----------
    # A replacement is made with the settings of the day - digits, period,
    # hash - which need not be the old token's: an imported SHA-1 six-digit
    # token replaced while the settings say SHA-512 and eight digits. The
    # token's own columns describe the old key until the new one is
    # confirmed, so the new key's shape is kept beside it.
    def staged_shape(self, name):
        try:
            got = json.loads(self.store.get_meta('staged:' + norm_name(name), '') or '{}')
        except ValueError:
            got = {}
        return {'digits': int(got.get('digits') or CONFIG.get('totp_digits') or 6),
                'period': int(got.get('period') or CONFIG.get('totp_period') or 30),
                'algorithm': str(got.get('algorithm') or CONFIG.get('totp_algorithm') or 'SHA1'),
                'issuer': str(got.get('issuer') if got.get('issuer') is not None
                              else CONFIG.get('totp_issuer') or ''),
                'fails': int(got.get('fails') or 0),
                'fail_times': got.get('fail_times') if isinstance(got.get('fail_times'), list)
                else []}

    def _staged_forget(self, name):
        try:
            self.store.db.run('DELETE FROM meta WHERE k = ?', ('staged:' + norm_name(name),))
        except Exception:                               # noqa: BLE001
            pass

    def stage_replacement(self, name, by):
        """A new key for somebody who has a token already, kept beside the
        old one until a code from the new one proves it was scanned. The old
        one goes on working until then."""
        name = norm_name(name)
        with self.lock_of(name):
            return self._stage_replacement(name, by)

    def _stage_replacement(self, name, by):
        if not self.store.token(name):
            raise ValueError('%s has no token to replace' % name)
        secret, codes = self.fresh()
        shape = {'digits': int(CONFIG.get('totp_digits') or 6),
                 'period': int(CONFIG.get('totp_period') or 30),
                 'algorithm': str(CONFIG.get('totp_algorithm') or 'SHA1'),
                 'issuer': str(CONFIG.get('totp_issuer') or '')}
        out = self.picture(name, secret, shape['digits'], shape['period'], shape['algorithm'],
                           shape['issuer'] or None)        # first (1.0.103)
        self.store.set_meta('staged:' + name, json.dumps(shape))
        self.store.token_write(name, {
            'pending_secret': seal_secret(secret, token_bind(name)),
            'pending_scratch': seal_codes(codes, token_bind(name)), 'pending_at': time.time(),
            'pending_by': str(by)[:190]})
        out['scratch'] = codes
        out['name'] = name
        return out

    def confirm(self, name, code, how='portal', src=''):
        """A code from a token that is waiting - a new one, or a replacement
        staged beside an old one. (ok, words)."""
        name = norm_name(name)
        # One at a time per name, as a check is (1.0.33).
        with self.lock_of(name):
            return self._confirm(name, code, how, src)

    def _confirm(self, name, code, how='portal', src=''):
        tok = self.store.token(name)
        if not tok:
            return False, SAY_NONE
        staged = bool(tok.get('pending_secret'))
        # Only a token that waits is confirmed: a new one, or one with a
        # replacement staged. A token an administrator switched off is not
        # brought back by its owner's code (1.0.15), and an active one with
        # nothing staged has nothing to confirm.
        if tok.get('state') == 'disabled':
            return False, SAY_OFF
        if not staged and tok.get('state') != 'pending':
            return False, 'There is nothing to confirm: this token is in use already'
        sealed = tok['pending_secret'] if staged else tok['secret']
        secret = unseal_secret(sealed or '', token_bind(name))
        if not secret:
            return False, SAY_LOST
        # A staged key is checked with its own shape, not the old token's.
        shape = self.staged_shape(name) if staged else {
            'digits': tok['digits'] or 6, 'period': tok['period'] or 30,
            'algorithm': tok['algorithm'] or 'SHA1', 'issuer': tok.get('issuer') or ''}
        # Throttled like a sign-in (1.0.33): the same pause after wrong codes,
        # so the page cannot be used to guess a waiting key's codes quickly.
        t = time.time()
        try:
            # A waiting replacement counts its wrong codes beside its own
            # shape (1.0.61): in the token's own they paused the token still
            # in use as well.
            fails = [float(x) for x in (shape.get('fail_times') if staged
                                        else json.loads(tok.get('fail_times') or '[]')) or []]
        except (ValueError, TypeError):
            fails = []
        tries = int(CONFIG.get('rate_limit_tries') or 0)
        fails = [x for x in fails if t - x < int(CONFIG.get('rate_limit_s') or 30)]
        if float(tok.get('locked_until') or 0) > t:
            self._said(name, False, SAY_LOCKED + ' (confirming a new token)', how, src, '')
            return False, SAY_LOCKED
        if tries and len(fails) >= tries:
            self._said(name, False, SAY_RATE + ' (confirming a new token)', how, src, '')
            return False, SAY_RATE
        step = totp_match(secret, code, None, shape['digits'], shape['period'],
                          shape['algorithm'], self.window(tok))
        if step is None and staged:
            # A replacement's wrong codes do not lock the token still in use
            # (1.0.59) - the phone answering with the old account is the
            # usual wrong code here. They are counted against the waiting key:
            # past the lockout count it is thrown away, to be made again.
            shape['fail_times'] = fails + [t]
            shape['fails'] = int(shape.get('fails') or 0) + 1
            after = int(CONFIG.get('lockout_after') or 0)
            if after and shape['fails'] >= after:
                self.drop_staged(name)
                self._said(name, False, SAY_BAD + ' (confirming a new token - too many, '
                           'the new key is thrown away)', how, src, '')
                return False, (SAY_BAD + '. Too many wrong codes: the new key was thrown '
                               'away - the token in use goes on working; make a new one.')
            self.store.set_meta('staged:' + name, json.dumps(shape))
            self._said(name, False, SAY_BAD + ' (confirming a new token)', how, src, '')
            return False, SAY_BAD + '. ' + self.why_wrong(secret, code, shape)
        if step is None:
            # Counted toward the lockout as well (1.0.44), not only the short
            # pause: a waiting key could be guessed at day after day.
            n = self._failure_counted(tok['id'])
            # The same lock as a wrong code to sign in with (1.0.101).
            mins = lockout_minutes(n)
            self._fail_noted(tok['id'], t, int(CONFIG.get('rate_limit_s') or 30), mins)
            if mins:
                lockout_said(self.store, name, n, mins)
            self._said(name, False, SAY_BAD + ' (confirming a new token)', how, src, '')
            return False, SAY_BAD + '. ' + self.why_wrong(secret, code, shape)
        # last_step never goes down for the same key: its code of a step
        # already used stays used. A new key starts from its own step
        # (1.0.33): steps of another period are not comparable - a 30 s
        # token replaced by a 60 s one refused every code after.
        fields = {'state': 'active', 'activated': time.time(),
                  'last_step': int(step) if staged else max(int(step),
                                                             int(tok.get('last_step') or 0)),
                  'failures': 0, 'fail_times': '[]', 'locked_until': None}
        if staged:
            codes = [x['c'] for x in (open_codes(tok.get('pending_scratch'),
                                                 token_bind(name)) or [])]
            # A token that got codes sent becomes the app's (1.0.76).
            fields.update({'kind': '', 'dest': ''})
            fields.update({'secret': tok['pending_secret'], 'pending_secret': None,
                           'pending_scratch': None, 'pending_at': None, 'pending_by': None,
                           'scratch': json.dumps([scratch_hash(name, c) for c in codes]),
                           'scratch_sealed': seal_codes(codes, token_bind(name)),
                           'scratch_left': len(codes), 'created': time.time(),
                           'created_by': tok.get('pending_by') or how,
                           'digits': shape['digits'], 'period': shape['period'],
                           'algorithm': shape['algorithm'],
                           'label': self.label_for(name),
                           'issuer': shape['issuer'],
                           # The old key's use is not the new one's (1.0.36).
                           'last_used': None, 'last_from': '', 'last_how': ''})
        self.store.token_update(tok['id'], fields)
        if staged:
            self._staged_forget(name)
        self._said(name, True, 'Token confirmed', how, src, '')
        return True, 'Token confirmed'

    @staticmethod
    def why_wrong(secret, code, tok):
        """What a wrong code most likely means, for the person typing it."""
        period = int(tok.get('period') or 30)
        far = totp_match(secret, code, None, tok.get('digits') or 6, period,
                         tok.get('algorithm') or 'SHA1', 40)
        if far is not None:
            off = (far - totp_step(None, period)) * period
            return ('It is this token\'s code, but from %d s %s: the clock of the phone is '
                    'wrong - set it to the network\'s time.' % (abs(off), 'ago' if off < 0
                                                                 else 'ahead'))
        return ('It is not a code of this token. If the application shows several accounts '
                'of this name, an older one is answering - type the code of the newest, or '
                'take the old one out of the application.')

    def drop_staged(self, name):
        with self.lock_of(norm_name(name)):
            self._drop_staged(name)

    def _drop_staged(self, name):
        tok = self.store.token(name)
        if not tok:
            self._staged_forget(name)
            return
        self.store.token_update(tok['id'], {'pending_secret': None, 'pending_scratch': None,
                                      'pending_at': None, 'pending_by': None})
        self._staged_forget(name)

    def new_scratch(self, name, by=''):
        name = norm_name(name)
        if not self.store.token(name):
            raise ValueError('%s has no token' % name)
        codes = scratch_new(int(CONFIG.get('scratch_count') or 0) or 5,
                            int(CONFIG.get('scratch_digits') or 8))
        row = {'scratch': json.dumps([scratch_hash(name, c) for c in codes]),
               'scratch_sealed': seal_codes(codes, token_bind(name)),
               'scratch_left': len(codes)}
        if (self.store.token(name) or {}).get('pending_secret'):
            # A new key waiting to be confirmed (1.0.207): its own codes took the
            # place of these at the confirmation, and the ones just handed out were
            # wrong from then on - the same ones for it.
            row['pending_scratch'] = seal_codes(codes, token_bind(name))
        self.store.token_write(name, row)
        return codes

    @staticmethod
    def window(tok):
        w = tok.get('window_steps')
        if w is None or int(w) < 0:
            return int(CONFIG.get('totp_window') or 0)
        return int(w)

    # ---- checked ---------------------------------------------------------------
    def check(self, name, code, how='radius', src='127.0.0.1', rid='', dry=False, quiet=False):
        """Whether `code` is right for the token of `name`. (ok, words, facts)
        - the words totpcgi would have said. `quiet`: not written down - the
        probe that finds where a password ends and its code begins."""
        name = norm_name(name)
        code = str(code or '').strip()
        with self.lock_of(name):
            ok, said, facts = self._check(name, code, dry)
        # A dry check - the administrator's test - is written down like any
        # other, marked as such; the only thing it leaves alone is the code,
        # which stays usable.
        if not quiet:
            self._said(name, ok, said, how + '-dry' if dry else how, src, rid, facts.get('off'))
        return ok, said, facts

    def _failure_counted(self, tok_id):
        """One more wrong code on the token, and which one it is - each
        wrong code its own number (1.0.101). Counted up and read back, two
        at once both read 11 and neither was the 10th: the lock at every
        tenth was skipped."""
        for _round in range(16):
            n = int(self.store.db.value('SELECT COALESCE(failures, 0) FROM tokens WHERE id = ?',
                                        (tok_id,)) or 0)
            if self.store.db.run('UPDATE tokens SET failures = ? WHERE id = ? AND '
                                 'COALESCE(failures, 0) = ?', (n + 1, tok_id, n)):
                return n + 1
        self.store.db.run('UPDATE tokens SET failures = COALESCE(failures, 0) + 1 WHERE id = ?',
                          (tok_id,))
        return int(self.store.db.value('SELECT failures FROM tokens WHERE id = ?',
                                       (tok_id,)) or 0)

    def _fail_noted(self, tok_id, t, span, mins):
        """The time of a wrong code added to the token's recent ones, and the
        lock set - by a conditional update (1.0.101): two nodes each reading
        the list and writing it back with their own time added lost one of
        them, and a guesser sending to both nodes at once got twice the
        tries the pause allows."""
        for _round in range(8):
            was = self.store.db.value('SELECT fail_times FROM tokens WHERE id = ?', (tok_id,))
            try:
                fails = [float(x) for x in json.loads(was or '[]')]
            except (ValueError, TypeError):
                fails = []
            fails = [x for x in fails if t - x < span] + [t]
            # As many as the pause counts (1.0.139): rate_limit_tries goes to
            # 100, and with more than 50 the pause never came.
            keep = max(50, int(CONFIG.get('rate_limit_tries') or 0))
            sets, args = 'fail_times = ?', [json.dumps(fails[-keep:])]
            if mins:
                sets += ', locked_until = ?'
                args.append(t + 60 * mins)
            if was is None:
                hit = self.store.db.run('UPDATE tokens SET %s WHERE id = ? AND fail_times IS NULL'
                                        % sets, tuple(args) + (tok_id,))
            else:
                hit = self.store.db.run('UPDATE tokens SET %s WHERE id = ? AND fail_times = ?'
                                        % sets, tuple(args) + (tok_id, was))
            if hit:
                break
        else:
            fields = {'fail_times': json.dumps([t])}
            if mins:
                fields['locked_until'] = t + 60 * mins
            self.store.token_update(tok_id, fields)

    def blocked(self, name):
        """What the token would say before any code is looked at - locked out,
        paused, switched off - or None. Asked before the directory password
        (1.0.57), so a locked token is not a free way to guess AD passwords."""
        tok = self.store.token(norm_name(name))
        if not tok:
            return None
        t = time.time()
        if tok.get('state') == 'disabled':
            return SAY_OFF
        if float(tok.get('locked_until') or 0) > t:
            return SAY_LOCKED
        tries = int(CONFIG.get('rate_limit_tries') or 0)
        span = int(CONFIG.get('rate_limit_s') or 30)
        try:
            fails = [float(x) for x in json.loads(tok.get('fail_times') or '[]')]
        except (ValueError, TypeError):
            fails = []
        if tries and len([x for x in fails if t - x < span]) >= tries:
            return SAY_RATE
        return None

    def _check(self, name, code, dry):
        tok = self.store.token(name)
        facts = {}
        if not tok:
            return False, SAY_NONE, facts
        if tok.get('state') == 'disabled':
            return False, SAY_OFF, facts
        if tok.get('state') == 'pending':
            return False, SAY_PENDING, facts
        t = time.time()
        try:
            fails = [float(x) for x in json.loads(tok.get('fail_times') or '[]')]
        except (ValueError, TypeError):
            fails = []
        tries = int(CONFIG.get('rate_limit_tries') or 0)
        span = int(CONFIG.get('rate_limit_s') or 30)
        fails = [x for x in fails if t - x < span]
        # A lockout after many wrong codes in a row, however slowly they
        # came (1.0.33): the short pause alone let a patient guesser try
        # thousands of codes a day.
        if float(tok.get('locked_until') or 0) > t:
            return False, SAY_LOCKED, facts
        if tries and len(fails) >= tries:
            return False, SAY_RATE, facts
        secret = unseal_secret(tok.get('secret') or '', token_bind(name))
        # Only a token of the app needs its key (1.0.149): one by mail or SMS
        # put back from a backup has none, and its recovery codes were
        # refused as "cannot be opened".
        if not secret and token_kind(tok) == 'totp':
            return False, SAY_LOST, facts
        digits = int(tok.get('digits') or 6)
        # Digits 0-9 and nothing else: \d also takes Arabic-Indic and other
        # digits, which then broke the comparison and left the request
        # unanswered and unwritten (1.0.33).
        plain = re.fullmatch(r'[0-9]+', code, re.ASCII) is not None

        def failed(said):
            # A dry check - the administrator's test, or the probe that finds
            # where a password ends and its code begins - counts nothing
            # (1.0.33): it is not somebody trying to sign in, and it counted
            # one typo three times.
            if dry:
                return False, said, facts
            # Counted in the database itself (1.0.44): two nodes reading
            # n and both writing n+1 lost one wrong code each time.
            n = self._failure_counted(tok['id'])
            mins = lockout_minutes(n)
            self._fail_noted(tok['id'], t, span, mins)
            if mins:
                lockout_said(self.store, name, n, mins)
            return False, said, facts
        if not plain:
            return failed(SAY_BAD)

        def scratch_try():
            """A recovery code: used once. None when it is not one."""
            if scratch_guarded(self.store, name):
                return None             # resting after many guesses (1.0.101)
            try:
                kept = json.loads(tok.get('scratch') or '[]')
            except ValueError:
                kept = []
            key = sealing_key()
            hit, h = scratch_find(name, code, kept, key)
            if hit:
                was = tok.get('scratch') or '[]'
                if not dry:
                    kept.remove(hit)
                    shown = codes_open(tok)
                    if shown is not None:
                        for one in shown:
                            if not one.get('used') and hmac.compare_digest(
                                    scratch_hash(name, one['c'], key), h):
                                one['used'] = t
                        # The rest, which were kept in the old shape too if
                        # this one was, written in the new one.
                        # (Without a sealed copy the others stay as they
                        # are until each is used.)
                        if hit != h:
                            kept = [scratch_hash(name, one['c'], key) for one in shown
                                    if not one.get('used')]
                    # Only if the codes are still the ones read: a recovery
                    # code used on the other node at the same moment is not
                    # used twice. (1.0.13)
                    won = self.store.db.run(
                        'UPDATE tokens SET scratch = ?, scratch_sealed = ?, scratch_left = ?, '
                        "last_used = ?, last_how = 'scratch', failures = 0, fail_times = '[]' "
                        'WHERE id = ? AND scratch = ?',
                        (json.dumps(kept), seal_codes(shown, token_bind(name)) if shown is not None else
                         (tok.get('scratch_sealed') or ''), len(kept), t, tok['id'], was))
                    if not won:
                        return False, SAY_REUSED, facts
                    # And used once anywhere (1.0.101): the row above can be
                    # written back by the other node's older copy of it.
                    if not once_take(self.store, 'scratch', name, h):
                        return False, SAY_REUSED, facts
                elif hit != h:
                    # Dry, so the code stays; but an entry in the old shape is
                    # rewritten in the new one now that it is known.
                    kept[kept.index(hit)] = h
                    self.store.db.run('UPDATE tokens SET scratch = ? WHERE id = ? AND scratch = ?',
                                      (json.dumps(kept), tok['id'], was))
                facts['scratch_left'] = len(kept)
                return True, SAY_SCRATCH, facts
            return None
        if token_kind(tok) != 'totp':
            # A token that gets its codes sent (1.0.76): what is checked here
            # is only ever a recovery code - the sent code is the
            # challenge's, and the key it keeps is never on any phone.
            got = scratch_try()
            return got if got is not None else failed(SAY_BAD)
        if len(code) != digits:
            got = scratch_try()
            return got if got is not None else failed(SAY_BAD)
        step = totp_match(secret, code, t, digits, tok.get('period') or 30,
                          tok.get('algorithm') or 'SHA1', self.window(tok))
        if step is None:
            # A recovery code as long as a code from the phone (1.0.33): with
            # the two lengths set alike, recovery codes were never tried.
            got = scratch_try()
            return got if got is not None else failed(SAY_BAD)
        facts['off'] = step - totp_step(t, tok.get('period') or 30)
        if CONFIG.get('totp_disallow_reuse', 1) and step <= int(tok.get('last_step') or 0):
            # Refused, but not counted as a wrong code (1.0.57): it is the
            # right code a second time - a NAS that sent the request again,
            # or to the other node - and counting it locked people out.
            return False, SAY_REUSED, facts
        if not dry:
            if CONFIG.get('totp_disallow_reuse', 1):
                # Used up with one conditional UPDATE: of two nodes asked for
                # the same code at the same moment, only one changes the row.
                won = self.store.db.run(
                    'UPDATE tokens SET last_step = ?, last_used = ?, failures = 0, '
                    "fail_times = '[]', last_how = 'code' WHERE id = ? AND "
                    'COALESCE(last_step, 0) < ?', (step, t, tok['id'], step))
                if not won:
                    return False, SAY_REUSED, facts
                # The step used once anywhere (1.0.101): on two replicating
                # nodes the UPDATE above holds only on its own database.
                # Tied to this key - the key itself, through an HMAC: the same
                # on both nodes whatever its sealed form, new with every key.
                if not once_take(self.store, 'step', name, '%s:%s:%s' % (
                        tok['id'], hmac.new(sealing_key() or b'', str(secret).encode(),
                                            hashlib.sha256).hexdigest()[:16], step)):
                    return False, SAY_REUSED, facts
            else:
                self.store.token_update(tok['id'], {'last_step': step, 'last_used': t,
                                                    'failures': 0, 'fail_times': '[]',
                                                    'last_how': 'code'})
        return True, (SAY_OK if facts['off'] == 0 else SAY_OK_DRIFT), facts

    def mark_from(self, name, src, client=''):
        # One UPDATE (1.0.33): read and written again, it was two round trips
        # on every request let in. With the RADIUS client it came through
        # (1.0.58).
        self.store.db.run('UPDATE tokens SET last_from = ?, last_client = ? WHERE name = ?',
                          (str(src or '')[:120], str(client or '')[:120], norm_name(name)))

    def _said(self, name, ok, said, how, src, rid, off=None):
        row = {'ts': time.time(), 'name': name, 'ok': 1 if ok else 0, 'said': said, 'how': how,
               'src': str(src or '')[:120], 'rid': str(rid or '')[:120],
               'step_off': int(off) if off is not None else None}
        later = getattr(ACME_LOG_LATER, 'rows', None)
        if later is not None:
            # A RADIUS worker's: written once the answer went (1.0.186).
            later.append(row)
        else:
            try:
                self.store.acme_add(row)
            except Exception as e:
                log('the check of a code could not be written down: %s' % e, 'warn')
        if self.on_check:
            try:
                self.on_check(name, ok, said, how, src, rid)
            except Exception as e:
                log('the check of a code could not be sent on: %s' % e, 'warn')


