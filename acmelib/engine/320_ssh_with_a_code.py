# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- SSH with a code: tokens of their own (1.0.181) --------------------------------------
# The codes for SSH are not the VPN's: a list of their own on Settings → SSH
# server (the account on the nodes and an app's secret), kept like the second
# step of the administration - meta 'sshotp:u:<name>', the secret sealed, the
# step of the last code used (once). pam_radius asks a gate of its own: a
# RADIUS listener of this daemon on 127.0.0.1 only, with a secret of its own
# ('sshotp:gate', sealed) - not a RADIUS client, not a realm, not in the log of
# RADIUS; every sign-in an event. Both nodes see the same list (meta).
SSHOTP_NAME_RE = re.compile(r'^[A-Za-z0-9._][A-Za-z0-9._@-]{0,63}\Z')
SSHOTP_LOCK = threading.Lock()
SSHOTP_FAILS = collections.defaultdict(list)
SSHOTP_TRIES, SSHOTP_WINDOW_S = 5, 300
SSH_GATE_STATE = {'port': 0, 'listening': False, 'error': '', 'since': 0.0, 'answered': 0,
                  'let_in': 0, 'refused': 0}


def sshotp_key(name):
    return 'sshotp:u:' + str(name or '').strip().lower()


def sshotp_name(name):
    name = str(name or '').strip()
    if not SSHOTP_NAME_RE.match(name):
        raise ValueError('the account is its name on the nodes: letters, digits and . _ @ - '
                         '(up to 64)')
    return name


def sshotp_get(store, name):
    try:
        got = json.loads(store.get_meta(sshotp_key(name)) or 'null')
    except ValueError:
        return None
    return got if isinstance(got, dict) else None


def sshotp_all(store):
    out = []
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'sshotp:u:%'"):
        try:
            v = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        out.append({'name': v.get('name') or r['k'][len('sshotp:u:'):], 'at': v.get('at'),
                    'kind': v.get('kind') or 'app', 'lang': v.get('lang') or '',
                    'dest': dest_masked(v.get('kind'), v.get('dest')) if v.get('dest') else '',
                    'by': v.get('by') or '', 'note': v.get('note') or '',
                    'used_at': v.get('used_at'), 'used_on': v.get('used_on') or '',
                    'failed_at': v.get('failed_at')})
    return sorted(out, key=lambda x: x['name'].lower())


def sshotp_make(store, name, by, note='', replace=False, kind='app', dest='', lang=''):
    """A new SSH token for `name`: an app's (the QR and the secret shown this
    once), or codes sent by mail or SMS (1.0.181) where sending is set up."""
    name = sshotp_name(name)
    note = re.sub(r'[\r\n\t]', ' ', str(note or ''))[:120]
    kind = str(kind or 'app')
    if kind not in ('app', 'mail', 'sms'):
        raise ValueError('an SSH token is an app\'s, or gets its codes by mail or SMS')
    if kind != 'app':
        if kind not in code_channels():
            raise ValueError('sending %s is not set up (Settings → %s)' % (
                ('mail', 'Mail') if kind == 'mail' else ('SMS', 'Codes by e-mail and SMS')))
        dest = dest_checked(kind, dest)
    # The language of its mails and SMS (1.0.183): Czech or English.
    lang = str(lang or '') if str(lang or '') in CODE_TEXTS else code_lang()
    with SSHOTP_LOCK:
        had = sshotp_get(store, name)
        if had and not replace:
            raise ValueError('%s has an SSH token already - make a new one in its place, or '
                             'remove it' % name)
        # The language of its prompt in SSH too, an app's as well (1.0.188).
        rec = {'name': name, 'kind': kind, 'at': time.time(), 'by': by, 'note': note, 'step': 0,
               'lang': lang}
        if kind == 'app':
            secret = b32_new(20)
            rec['secret'] = seal_secret(secret, sshotp_key(name))
        else:
            rec.update(dest=dest, lang=lang)
        store.set_meta(sshotp_key(name), json.dumps(rec))
    store.add_event('settings', '%s made %s SSH token for %s%s' % (
        by, 'a new' if had else 'an', name, '' if kind == 'app' else ' (codes by %s to %s)' % (
            'mail' if kind == 'mail' else 'SMS', dest_masked(kind, dest))),
        'warn' if had else 'info', who=by)
    if kind != 'app':
        return {'name': name, 'kind': kind, 'dest': dest_masked(kind, dest), 'lang': lang}
    site = str(CONFIG.get('site_name') or short_host())
    uri = otpauth_uri(secret, name, '%s (SSH)' % site)
    return {'name': name, 'kind': 'app', 'qr': qr_data_uri(uri), 'uri': uri,
            'secret': ' '.join(secret[i:i + 4] for i in range(0, len(secret), 4))}


def sshotp_remove(store, name, by):
    name = sshotp_name(name)
    if not sshotp_get(store, name):
        raise ValueError('%s has no SSH token' % name)
    store.db.run('DELETE FROM meta WHERE k = ?', (sshotp_key(name),))
    store.add_event('settings', '%s removed the SSH token of %s' % (by, name), 'warn', who=by)


def _sshotp_fails(name, now):
    fails = [t for t in SSHOTP_FAILS[name.lower()] if now - t < SSHOTP_WINDOW_S]
    SSHOTP_FAILS[name.lower()] = fails
    return fails


def _sshotp_used(store, name, ok):
    """The token's own row: when it was last used, or last failed."""
    rec = sshotp_get(store, name)
    if rec:
        if ok:
            rec.update(used_at=time.time(), used_on=node_name())
        else:
            rec['failed_at'] = time.time()
        store.set_meta(sshotp_key(name), json.dumps(rec))


def sshotp_check(store, name, code):
    """(let in, what is said) - an app's code, good once, wrong ones counted
    per name."""
    name = str(name or '').strip()
    if not SSHOTP_NAME_RE.match(name):
        return False, 'no such account'
    now = time.time()
    with SSHOTP_LOCK:
        fails = _sshotp_fails(name, now)
        if len(fails) >= SSHOTP_TRIES:
            return False, 'too many wrong codes - wait %d min' % (SSHOTP_WINDOW_S // 60)
        rec = sshotp_get(store, name)
        if not rec:
            fails.append(now)
            return False, 'no SSH token for this account'
        if rec.get('kind', 'app') != 'app':
            return False, 'this token gets its codes sent'
        secret = unseal_secret(rec.get('secret'), sshotp_key(name))
        code = ssh_code_typed(code)
        step = totp_match(secret, code, digits=6, window=mfa_window()) if secret else None
        # Good once on either node (1.0.206): the step taken in token_once, as a
        # token's - each node's own row let a code seen on one in on the other.
        if step is not None and step > int(rec.get('step') or 0) and \
                not once_take(store, 'step', 'sshotp:' + name.lower(), step):
            step = int(rec.get('step') or 0)
        if step is None or step <= int(rec.get('step') or 0):
            fails.append(now)
            rec['failed_at'] = now
            store.set_meta(sshotp_key(name), json.dumps(rec))
            return False, ('the code is not right' if step is None
                           else 'the code was used already - wait for the next one')
        rec.update(step=step, used_at=now, used_on=node_name())
        store.set_meta(sshotp_key(name), json.dumps(rec))
        SSHOTP_FAILS.pop(name.lower(), None)
        return True, 'signed in'


SSH_GATE_PORTS = range(18129, 18200)


def ssh_gate_ephemeral():
    """The ports the kernel hands out for outgoing connections - never the gate's."""
    try:
        lo, hi = (int(x) for x in open('/proc/sys/net/ipv4/ip_local_port_range').read().split())
        return lo, hi
    except (OSError, ValueError):
        return 32768, 60999


def ssh_gate_candidates(store):
    """The port set first, then the one this node took before, then the rest
    of 18129-18199 - none of the kernel's own for outgoing connections."""
    lo, hi = ssh_gate_ephemeral()
    out = []
    try:
        was = int(store.get_meta('sshotp:port:' + node_name()) or 0)
    except (TypeError, ValueError):
        was = 0
    try:
        want = int(CONFIG.get('ssh_gate_port') or 18129)
    except (TypeError, ValueError):
        want = 18129
    for p in [want, was] + list(SSH_GATE_PORTS):
        if 1024 < p < 65536 and not lo <= p <= hi and p not in out:
            out.append(p)
    return out


SSHOTP_SENT = collections.defaultdict(list)       # name -> [when a code went]
SSHOTP_SEND_GAP_S, SSHOTP_SEND_MOST, SSHOTP_SEND_WINDOW_S = 20, 5, 900
SSHOTP_CHALLENGES = {}                             # State -> what was sent, on this node
SSHOTP_GONE = collections.defaultdict(list)        # name -> the codes sent the last hour


def sshotp_send(store, name):
    """A code by mail or SMS for `name`'s SSH token: (State, what to ask) or
    raises ValueError with what is said. Not more often than every 20 s, and 5
    in 15 min - a name typed at ssh must not become a way to send SMS."""
    rec = sshotp_get(store, name) or {}
    kind = rec.get('kind')
    if kind not in ('mail', 'sms'):
        raise ValueError('no SSH token by mail or SMS for this account')
    if kind not in code_channels():
        raise ValueError('sending %s is not set up now' % ('mail' if kind == 'mail' else 'SMS'))
    now = time.time()
    ask = code_words('ask_mail' if kind == 'mail' else 'ask_sms', lang=rec.get('lang') or None,
                     dest=dest_masked(kind, rec['dest']))
    with SSHOTP_LOCK:
        sent = [t for t in SSHOTP_SENT[name.lower()] if now - t < SSHOTP_SEND_WINDOW_S]
        SSHOTP_SENT[name.lower()] = sent
        good = [v for v in SSHOTP_CHALLENGES.values()
                if v.get('name') == name and v.get('hash') and now <= v['exp']]
        if sent and now - sent[-1] < SSHOTP_SEND_GAP_S and good:
            # Signed in again at once (1.0.188): the code that went a moment ago
            # is asked for again, not refused - and no second one sent. None
            # good any more (1.0.189: it ran out): a new one goes.
            state = secrets.token_hex(16)
            SSHOTP_CHALLENGES[state] = {'name': name, 'exp': max(v['exp'] for v in good), 'tries': 0}
            return state, ask
        if len(sent) >= SSHOTP_SEND_MOST:
            raise ValueError('%d codes in %d min - wait' % (SSHOTP_SEND_MOST,
                                                            SSHOTP_SEND_WINDOW_S // 60))
        sent.append(now)
        for k in [k for k, v in SSHOTP_CHALLENGES.items() if now > v['exp'] + 60]:
            SSHOTP_CHALLENGES.pop(k, None)
    code, salt = code_new(), secrets.token_hex(8)
    try:
        code_send(store, kind, rec['dest'], code, purpose='ssh', name=name,
                  lang=rec.get('lang') or None)
    except (MailError, SmsError) as e:
        store.add_event('ssh', 'the SSH code for %s could not be sent (%s): %s' % (
            name, kind, e), 'warn', who=name)
        raise ValueError('the code could not be sent')
    state = secrets.token_hex(16)
    with SSHOTP_LOCK:
        SSHOTP_CHALLENGES[state] = {'name': name, 'hash': code_hash(salt, code), 'salt': salt,
                                    'exp': now + int(CONFIG.get('code_ttl_s') or 300),
                                    'tries': 0}
        # Kept an hour (1.0.188), to say why a code typed was refused: run out, or
        # never sent here.
        SSHOTP_GONE[name.lower()] = [x for x in SSHOTP_GONE[name.lower()] if now - x['at'] < 3600][-20:] + [
            {'hash': code_hash(salt, code), 'salt': salt, 'at': now,
             'exp': now + int(CONFIG.get('code_ttl_s') or 300)}]
    return state, ask


def sshotp_answer(store, state, name, code):
    """The code typed after a challenge: (let in, what is said, ask again)."""
    now = time.time()
    with SSHOTP_LOCK:
        ch = SSHOTP_CHALLENGES.get(state)
        if not ch or ch['name'] != name or now > ch['exp']:
            SSHOTP_CHALLENGES.pop(state, None)
            # Its prompt gone, a code still good of the same account is taken.
            ch = {'name': name, 'tries': 3, 'exp': now}
            if not any(v.get('name') == name and v.get('hash') and now <= v['exp']
                       for v in SSHOTP_CHALLENGES.values()):
                return False, 'the code is no longer good - sign in again', False
        fails = _sshotp_fails(name, now)
        if len(fails) >= SSHOTP_TRIES:
            SSHOTP_CHALLENGES.pop(state, None)
            return False, 'too many wrong codes - wait %d min' % (SSHOTP_WINDOW_S // 60), False
        raw = str(code or '').strip()
        typed = ssh_code_typed(raw)
        # Any code still good that went to this account (1.0.188), each once: a
        # mail come late was the one typed, while a later sign-in had sent
        # another - and the right code was refused.
        mine = [(k, v) for k, v in SSHOTP_CHALLENGES.items()
                if v.get('name') == name and v.get('hash') and now <= v['exp']]
        if any(hmac.compare_digest(code_hash(v['salt'], typed), v['hash']) for _k, v in mine):
            for k, _v in mine:
                SSHOTP_CHALLENGES.pop(k, None)
            SSHOTP_FAILS.pop(name.lower(), None)
            ok = True
        else:
            fails.append(now)
            ch['tries'] += 1
            ok = False
            again = ch['tries'] < 3
            if not again:
                SSHOTP_CHALLENGES.pop(state, None)
    _sshotp_used(store, name, ok)
    if ok:
        return True, 'signed in', False
    return False, 'the code is not right (%s)' % sshotp_why(name, typed, now, raw), again


SSH_CZ_ROW = dict(zip('+ěščřžýáíéĚŠČŘŽÝÁÍÉ', '1234567890' + '234567890'))


def ssh_code_typed(code):
    """The code as typed, read as the digits meant (1.0.190): the top row of a Czech
    keyboard without Shift gives +ěščřžýáíé, not 1234567890 - "794872" came as
    "ýíčáěý" and was refused; digits of other scripts and full-width ones too."""
    import unicodedata
    out = []
    for ch in str(code or '').strip():
        if ch in SSH_CZ_ROW:
            out.append(SSH_CZ_ROW[ch])
            continue
        try:
            out.append(str(unicodedata.digit(ch)))
        except (TypeError, ValueError):
            out.append(ch)
    return ''.join(out).replace(' ', '')


def sshotp_why(name, typed, now, raw=None):
    """Why a code typed was not one still good - for the event, never the code."""
    raw = typed if raw is None else raw
    shape = '%d digits' % len(raw) if raw.isdigit() and raw.isascii() else \
        '%d characters, not digits only (%s)' % (len(raw), ' '.join(
            'U+%04X' % ord(c) for c in raw[:12]) or 'nothing at all')
    with SSHOTP_LOCK:
        hist = list(SSHOTP_GONE.get(name.lower()) or [])
    for x in reversed(hist):
        if hmac.compare_digest(code_hash(x['salt'], typed), x['hash']):
            return 'typed %s: the code sent at %s, good until %s - it ran out %d s before' % (
                shape, time.strftime('%H:%M:%S', time.localtime(x['at'])),
                time.strftime('%H:%M:%S', time.localtime(x['exp'])), int(now - x['exp']))
    good = [x for x in hist if now <= x['exp']]
    return 'typed %s: none of the codes sent to %s in the last hour (%d, %d still good%s)' % (
        shape, name, len(hist), len(good),
        ', the newest at %s' % time.strftime('%H:%M:%S', time.localtime(hist[-1]['at'])) if hist else '')


def sshotp_ask_app(store, name):
    """pam_radius with skip_passwd (1.0.188) asks with no password: the app's code is
    asked for here, in the one prompt sshd shows - not after a "Password:"."""
    rec = sshotp_get(store, name) or {}
    now = time.time()
    state = secrets.token_hex(16)
    with SSHOTP_LOCK:
        for k in [k for k, v in SSHOTP_CHALLENGES.items() if now > v['exp'] + 60]:
            SSHOTP_CHALLENGES.pop(k, None)
        SSHOTP_CHALLENGES[state] = {'name': name, 'app': True, 'exp': now + 300, 'tries': 0}
    return state, code_words('ssh_ask_app', lang=rec.get('lang') or None)


def sshotp_app_answer(store, state, name, code):
    """The app's code typed after that prompt: (let in, what is said, ask again)."""
    now = time.time()
    with SSHOTP_LOCK:
        ch = SSHOTP_CHALLENGES.get(state)
        if not ch or ch['name'] != name or now > ch['exp']:
            SSHOTP_CHALLENGES.pop(state, None)
            return False, 'the code is no longer good - sign in again', False
    ok, said = sshotp_check(store, name, code)
    with SSHOTP_LOCK:
        ch['tries'] += 1
        again = not ok and ch['tries'] < 3 and 'too many' not in said
        if ok or not again:
            SSHOTP_CHALLENGES.pop(state, None)
    return ok, said, again


def ssh_prompt_attr(words, hide=False):
    """Reply-Message with the prompt as it is - attr_bytes strips the space after
    the ":" (1.0.191), and the code was typed right against it - and Prompt
    (76): 0 where the code is hidden as it is typed (pam_radius prompt_attribute)."""
    raw = ssh_prompt(words).encode('utf-8')[:253]
    return bytes([18, len(raw) + 2]) + raw + bytes([76, 6]) + struct.pack('!I', 0 if hide else 1)


def ssh_code_hidden(store):
    """Settings -> SSH server: the code hidden as it is typed (1.0.191)."""
    try:
        return bool(json.loads(store.get_meta('host:sshd:conf') or '{}').get('radius_hide'))
    except (ValueError, TypeError, AttributeError):
        return False


def ssh_prompt(words):
    """A prompt ending as one does - the code typed after ": ", not stuck to the text."""
    words = str(words or '').rstrip()
    return words if words.endswith((':', '?')) else words + ': '


def ssh_gate_port(store=None):
    """The port the gate of this node listens on - what its pam_radius is told."""
    if SSH_GATE_STATE.get('listening') and SSH_GATE_STATE.get('port'):
        return int(SSH_GATE_STATE['port'])
    if store is not None:
        got = ssh_gate_candidates(store)
        if got:
            return got[0]
    try:
        return int(CONFIG.get('ssh_gate_port') or 18129)
    except (TypeError, ValueError):
        return 18129


def ssh_gate_secret(store, make=False):
    try:
        rec = json.loads(store.get_meta('sshotp:gate') or '{}')
    except ValueError:
        rec = {}
    got = unseal_secret(rec.get('secret'), 'sshotp:gate') if rec.get('secret') else ''
    if not got and make:
        got = secrets.token_urlsafe(32)
        store.set_meta('sshotp:gate', json.dumps({'secret': seal_secret(got, 'sshotp:gate'),
                                                  'at': time.time()}))
    return got or ''


def ssh_gate_fp(secret, port):
    """What says pam_radius has this secret and port - never the secret itself."""
    return hashlib.sha256(('%d %s' % (int(port), secret)).encode()).hexdigest()[:12]


def ssh_gate_wanted(store):
    c = _meta_json(store, 'host:sshd:conf') or {}
    return bool(c.get('manage') and c.get('radius'))


def ssh_gate_old_client(store):
    """The RADIUS client 1.0.178-1.0.180 made for pam_radius: no longer asked."""
    for c in store.clients():
        if c.get('name') == SSH_RADIUS_CLIENT and str(c.get('address') or '') == '127.0.0.1':
            store.client_drop(c['id'])
            store.add_event('settings', 'the RADIUS client "%s" is gone - SSH asks a gate of its '
                            'own now, with SSH tokens of their own (Settings → SSH server)'
                            % SSH_RADIUS_CLIENT, 'info')


SSHGATE_AT_ONCE = threading.BoundedSemaphore(32)


class SshGate(object):
    """pam_radius's acme: on 127.0.0.1, in a thread of its own - RADIUS of the
    VPN is not touched by it, nor it by RADIUS."""

    def __init__(self, daemon):
        self.d = daemon
        self.sock = None
        self.port = 0
        self.looked = 0.0
        self.stop_flag = False
        self.lock = threading.Lock()
        self.seen = {}
        self.thread = threading.Thread(target=self.run, name='acme-sshgate', daemon=True)
        self.thread.start()

    def configure(self):
        store = self.d.store
        try:
            want = ssh_gate_wanted(store)
            if want:
                ssh_gate_old_client(store)
        except Exception as e:                          # noqa: BLE001
            log_sparing('sshgate', 'the SSH gate: %s' % e, 'warn', every=600)
            return
        # The port set changed (1.0.183): listened on again, the new one first.
        try:
            asked = int(CONFIG.get('ssh_gate_port') or 18129)
        except (TypeError, ValueError):
            asked = 18129
        if self.sock and want and asked != getattr(self, 'asked', asked) and asked != self.port:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            SSH_GATE_STATE.update(listening=False, port=0)
        self.asked = asked
        if self.sock and not want:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            SSH_GATE_STATE.update(listening=False, port=0)
        if want and not self.sock:
            # A port nothing else has (1.0.181): the one taken before, else the
            # next free of 18129-18199 - remembered per node, and pam_radius
            # of this node told of it (sshd_tick, pamconf).
            tried = []
            for port in ssh_gate_candidates(store):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.bind(('127.0.0.1', port))
                except OSError as e:
                    s.close()
                    tried.append('%d (%s)' % (port, e.strerror or e))
                    continue
                s.settimeout(1.0)
                self.sock, self.port = s, port
                SSH_GATE_STATE.update(listening=True, port=port, error='', since=time.time())
                if store.get_meta('sshotp:port:' + node_name()) != str(port):
                    store.set_meta('sshotp:port:' + node_name(), str(port))
                log('the gate for SSH with a code listens on 127.0.0.1:%d%s' % (
                    port, ' (taken: %s)' % ', '.join(tried[:5]) if tried else ''))
                break
            else:
                SSH_GATE_STATE.update(listening=False, port=0,
                                      error='no free port of 18129-18199 on 127.0.0.1')
                log_sparing('sshgate-bind', 'the gate for SSH with a code: no free port of '
                            '18129-18199 on 127.0.0.1', 'bad', every=600)

    def run(self):
        while not self.stop_flag:
            if time.time() - self.looked > 10:
                self.looked = time.time()
                try:
                    self.configure()
                except Exception as e:          # noqa: BLE001
                    # Never the thread with it (1.0.206): a database away while
                    # the gate was set up ended it, and SSH waited on a socket
                    # nobody read until the service started again.
                    log_sparing('ssh-gate-conf', 'the SSH gate: %s' % e, 'warn', every=600)
            s = self.sock
            if not s:
                time.sleep(1.0)
                continue
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                time.sleep(0.5)
                continue
            # Each request in a thread of its own (a code by mail can take
            # seconds); pam_radius sending the same one again while it is
            # worked on, or after, gets the same answer, never a second code.
            key = data[1:2] + data[4:20] + repr(addr).encode()
            with self.lock:
                for k in [k for k, v in self.seen.items() if time.time() - v[0] > 60]:
                    self.seen.pop(k, None)
                was = self.seen.get(key)
                if was is not None:
                    if was[1]:
                        try:
                            s.sendto(was[1], addr)
                        except OSError:
                            pass
                    continue
                self.seen[key] = (time.time(), None)
            # As many at once as the codes sent may be (1.0.209): a slow database
            # or mail server piled a thread up for each request.
            if not SSHGATE_AT_ONCE.acquire(blocking=False):
                with self.lock:
                    self.seen.pop(key, None)
                log_sparing('sshgate-busy', 'the gate for SSH with a code: too many requests at '
                            'once - one left unanswered (asked again, it is answered)', 'warn',
                            every=300)
                continue
            threading.Thread(target=self.serve, args=(s, data, addr, key), name='acme-sshgate-req',
                             daemon=True).start()

    def serve(self, s, data, addr, key):
        try:
            self._serve(s, data, addr, key)
        finally:
            SSHGATE_AT_ONCE.release()

    def _serve(self, s, data, addr, key):
        try:
            out = self.answer(data, addr)
            with self.lock:
                if out:
                    self.seen[key] = (time.time(), out)
                else:
                    self.seen.pop(key, None)    # asked again, answered again (1.0.207)
            if out:
                s.sendto(out, addr)
        except Exception as e:                          # noqa: BLE001
            # Not kept as asked (1.0.207): pam_radius's repeats were passed over for a
            # minute, and the sign-in timed out though the database was back at once.
            with self.lock:
                self.seen.pop(key, None)
            log_sparing('sshgate-req', 'the gate for SSH with a code: %s' % e, 'warn',
                        every=300)

    def answer(self, data, addr):
        if not ipaddress.ip_address(addr[0]).is_loopback:
            return None
        p = Packet.parse(data)
        if p.code != 1:
            return None
        secret = ssh_gate_secret(self.d.store).encode()
        if not secret or p.message_authenticator_ok(secret) is False:
            return None
        user = p.text(1)
        try:
            code = p.password(secret) or ''
        except RadiusError:
            return None
        store = self.d.store
        who = re.sub(r'[^\w.@-]', '?', user)[:64]
        state = (p.get(24) or b'').decode('ascii', 'replace')
        rec = sshotp_get(store, user) if SSHOTP_NAME_RE.match(user or '') else None
        lang = (rec or {}).get('lang') or None
        if state:
            with SSHOTP_LOCK:
                app = (SSHOTP_CHALLENGES.get(state) or {}).get('app')
            ok, said, again = (sshotp_app_answer if app else sshotp_answer)(store, state, user, code)
            if again:
                # Each wrong code an event too (1.0.189), with why - not only the last.
                store.add_event('ssh', '%s typed a wrong code for SSH on %s (asked again): %s'
                                % (who, node_name(), said), 'warn', who=who)
                return build_reply(p, 11, [ssh_prompt_attr(code_words('again', lang=lang), ssh_code_hidden(store)),
                                           bytes([24, len(state) + 2]) + state.encode()], secret)
        elif rec and rec.get('kind', 'app') == 'app' and not code:
            st, ask = sshotp_ask_app(store, user)
            return build_reply(p, 11, [ssh_prompt_attr(ask, ssh_code_hidden(store)),
                                       bytes([24, len(st) + 2]) + st.encode()], secret)
        elif rec and rec.get('kind') in ('mail', 'sms'):
            # By mail or SMS (1.0.181): whatever was typed first, a code is
            # sent and asked for in a second prompt (Access-Challenge).
            try:
                st, ask = sshotp_send(store, user)
            except ValueError as e:
                ok, said = False, str(e)
            else:
                log('SSH: a code for %s went by %s' % (who, rec['kind']))
                # When it went (1.0.189): with mails come late, which one is the code.
                with SSHOTP_LOCK:
                    sent = [x['at'] for x in SSHOTP_GONE.get(user.lower()) or []]
                if sent:
                    ask = '%s (%s)' % (str(ask).rstrip(' :'), time.strftime('%H:%M', time.localtime(sent[-1])))
                return build_reply(p, 11, [ssh_prompt_attr(ask, ssh_code_hidden(store)),
                                           bytes([24, len(st) + 2]) + st.encode()], secret)
        else:
            ok, said = sshotp_check(store, user, code)
        SSH_GATE_STATE['answered'] += 1
        SSH_GATE_STATE['let_in' if ok else 'refused'] += 1
        store.add_event('ssh', '%s %s SSH on %s with a code%s' % (
            who, 'signed in to' if ok else 'was not let into', node_name(),
            '' if ok else ': ' + said), 'info' if ok else 'warn', who=who)
        return build_reply(p, 2 if ok else 3,
                           [attr_bytes('Reply-Message', 'acme: ' + said)], secret)


