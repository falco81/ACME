# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The API the web pages ask
# ---------------------------------------------------------------------------
# On 127.0.0.1 only, and only for whoever holds the token in /run/acme - which
# is the web server's group and nobody else. The PHP pages relay to it and
# add nothing: the session travels as a header, and this decides what that
# session may have. Two kinds of session: an administrator's (`admin`) and a
# person signed in to the enrolment pages (`portal`), which reaches only what
# a route of those pages gives it.

ROLE_RANK = {'readonly': 1, 'certadmin': 2, 'fulladmin': 3}


class ApiError(Exception):
    def __init__(self, status, words, detail=''):
        Exception.__init__(self, words)
        self.status = status
        self.detail = detail


def api_token(make=False):
    if make:
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        token = secrets.token_urlsafe(32)
        write_replacing(TOKEN_FILE, token + '\n', 0o640)
        try:
            import grp
            gid = grp.getgrnam(WEB_GROUP).gr_gid
            os.chown(str(TOKEN_FILE), -1, gid)
            os.chmod(str(RUN_DIR), 0o750)
            os.chown(str(RUN_DIR), -1, gid)
        except (KeyError, OSError, ImportError):
            pass
        return token
    try:
        return TOKEN_FILE.read_text().strip()
    except OSError:
        return ''


def _int_id(v):
    """An id from a request: a whole number, or ValueError said plainly."""
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        raise ValueError('an id is a number')


BODY_WORDS = ('name', 'to', 'mail_to', 'dest', 'note', 'code', 'password', 'passphrase', 'lang',
              'kind', 'action', 'mail_fmt', 'display', 'user', 'old', 'new', 'q',
              'state', 'via', 'mode', 'fingerprint', 'label')


def _no_constant(word):
    raise ValueError('%s is not a number' % word)


class ApiHandler(BaseHTTPRequestHandler):
    server_version = 'acme'
    protocol_version = 'HTTP/1.1'
    # A connection that says nothing for a minute is closed (1.0.101): each
    # held a thread for ever, and any program on this machine could open
    # thousands without the key.
    timeout = 60

    def log_message(self, fmt, *args):
        if debugging('api'):
            log('api %s' % (fmt % args), 'debug')

    # ---- the plumbing ---------------------------------------------------------
    @property
    def d(self):
        return self.server.daemon

    @property
    def store(self):
        return self.server.daemon.store

    @property
    def reader(self):
        """The long lists' own connection (1.0.101)."""
        return self.server.daemon.reader()

    def client_ip(self):
        said = str(self.headers.get('X-Acme-Client') or '').strip()
        return said if re.match(r'^[0-9a-fA-F:.]{2,45}\Z', said) else self.client_address[0]

    def send_json(self, data, status=200):
        body = json.dumps(data, default=str, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        if hasattr(self, '_body'):
            return self._body
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            raise ApiError(400, 'the length of the body is not a number')
        if n < 0:
            raise ApiError(400, 'the length of the body is not a number')
        if n > 8 * 1024 * 1024:
            raise ApiError(413, 'that is more than this takes')
        raw = self.rfile.read(n) if n else b''
        try:
            # NaN and Infinity are not numbers anybody means (1.0.103).
            self._body = json.loads(raw.decode('utf-8'), parse_constant=_no_constant) \
                if raw else {}
        except (ValueError, RecursionError):            # [[[[... too (1.0.139)
            raise ApiError(400, 'the body is not JSON')
        if not isinstance(self._body, dict):
            raise ApiError(400, 'the body is not an object')
        # What is a word is a word (1.0.103): a list where a name belongs was
        # made into the text "['x']" - an account by that name, a mail to it.
        for k in BODY_WORDS:
            v = self._body.get(k)
            if isinstance(v, (list, dict, bool)):
                raise ApiError(400, '%s is a piece of text here' % k)
            if isinstance(v, float) and k != 'code':
                raise ApiError(400, '%s is a piece of text here' % k)
        return self._body

    def body_to_file(self, path, most):
        """A request body that is a file, written down a lump at a time."""
        n = int(self.headers.get('Content-Length') or 0)
        if n <= 0:
            raise ApiError(400, 'no file arrived')
        if n > most:
            raise ApiError(413, 'that file is bigger than this takes')
        left = n
        with open(str(path), 'wb') as out:
            while left > 0:
                lump = self.rfile.read(min(left, 1 << 20))
                if not lump:
                    raise ApiError(400, 'the file did not arrive whole')
                out.write(lump)
                left -= len(lump)
        self._body = {}
        return n

    def send_bytes(self, data, name, kind='application/octet-stream'):
        self.send_response(200)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Disposition', 'attachment; filename="%s"' % name)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, path, name):
        # Opened before a header is sent (1.0.61): a file it may not read -
        # a copy root made on the command line - went out as "200" and then
        # a 500 in the middle of the download.
        try:
            f = open(str(path), 'rb')
        except PermissionError:
            raise ApiError(403, '%s cannot be read by the service (made by root on the command '
                                'line?): chown acme:acme it, then again' % name)
        except FileNotFoundError:
            raise ApiError(404, 'there is no such file: %s' % name)
        with f:
            self._send_open_file(f, name)

    def _send_open_file(self, f, name):
        size = os.fstat(f.fileno()).st_size
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="%s"' % name)
        self.send_header('Content-Length', str(size))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        shutil.copyfileobj(f, self.wfile, 1 << 18)

    def do_GET(self):
        self.route('GET')

    def do_POST(self):
        self.route('POST')

    def route(self, method):
        # A body of its own for each request (1.0.146): on a kept-alive
        # connection the handler is the same, and the last one's was read again.
        self.__dict__.pop('_body', None)
        url = urlparse(self.path)
        self.args = {k: v[-1] for k, v in parse_qs(url.query).items()}
        path = url.path.rstrip('/')
        self.route_path = path
        if path != '/api/health':
            want = api_token()
            given = str(self.headers.get('X-Acme-Token') or '')
            # As bytes (1.0.149): an API key with a letter beyond ASCII raised
            # TypeError there, and the connection was dropped with a trace.
            if not want or not hmac.compare_digest(want.encode('utf-8'),
                                                   given.encode('utf-8', 'replace')):
                return self.send_json({'ok': False, 'error': 'not this API’s token'}, 403)
        fn = ROUTES.get((method, path))
        if not fn:
            return self.send_json({'ok': False, 'error': 'no such endpoint: %s %s'
                                   % (method, path)}, 404)
        self._held = None
        self._failed = False
        try:
            got = fn(self)
            if got is not None:
                self.send_json(got if 'ok' in got else dict(ok=True, **got))
        except ApiError as e:
            # What went wrong in detail - a domain controller's name, a bind
            # DN - only to somebody signed in (1.0.33); the rest is in the log.
            detail = e.detail if self._signed_in() else None
            if e.detail and not detail:
                log('%s %s: %s (%s)' % (method, path, e, e.detail), 'info')
            self.send_json({'ok': False, 'error': str(e), 'detail': detail}, e.status)
        except (ValueError, BadSetting) as e:
            said = str(e)
            if said.startswith(('invalid literal for int()', 'could not convert string to float',
                                'cannot convert float')):
                # Python's words for a field that is not a number (1.0.103).
                said = 'a field that is a number holds something else'
            self.send_json({'ok': False, 'error': said}, 400)
        except LdapError as e:
            # The domain controller's name and its TLS - only to somebody
            # signed in (1.0.136), as an ApiError's detail is.
            if self._signed_in():
                self.send_json({'ok': False, 'error': str(e), 'detail': e.detail}, 502)
            else:
                log('%s %s: the directory: %s (%s)' % (method, path, e, e.detail), 'warn')
                self.send_json({'ok': False, 'error': 'the directory could not be asked just '
                                'now - try again in a moment', 'detail': None}, 502)
        except DbError as e:
            # Where the database is, only to somebody signed in (1.0.146).
            if self._signed_in():
                self.send_json({'ok': False, 'error': str(e)}, 503)
            else:
                log('%s %s: the database: %s' % (method, path, e), 'warn')
                self.send_json({'ok': False, 'error': 'the database cannot be reached just now '
                                                      '- try again in a moment'}, 503)
        except (TypeError, AttributeError, KeyError) as e:
            # A field of the wrong kind - null where a number goes, a list
            # where an object does (1.0.44): the request's fault, said so,
            # and the trace kept in case it was not.
            log('%s %s could not be read: %s\n%s' % (method, path, e, traceback.format_exc()),
                'warn')
            self.send_json({'ok': False, 'error': 'the request is not in the shape this '
                                                  'takes (a field of the wrong kind)'}, 400)
        except (BrokenPipeError, ConnectionResetError):
            # The page went away before its answer did (1.0.61): nothing broke.
            pass
        except Exception as e:
            # A value the database cannot keep - a number out of its range, a
            # text too long for its column (1.0.103): the request's fault.
            kind = type(e).__name__
            if kind in ('DataError', 'NumericValueOutOfRange', 'StringDataRightTruncation',
                        'InvalidTextRepresentation', 'OverflowError') or \
                    (kind == 'OperationalError' and 'out of range' in str(e).lower()):
                log('%s %s: a value the database cannot keep: %s' % (method, path, e), 'info')
                self.send_json({'ok': False, 'error': 'a value is too big or of the wrong kind '
                                                      'for the database'}, 400)
                return
            log('the API broke on %s %s: %s\n%s' % (method, path, e, traceback.format_exc()),
                'error')
            # The words of the exception stay in the log (1.0.33).
            self.send_json({'ok': False, 'error': 'it broke - the reason is in the log of the '
                                                  'service (/var/log/acme/acme.log)'}, 500)
        finally:
            self._release()

    def _signed_in(self):
        token = str(self.headers.get('X-Acme-Session') or '')
        if not token:
            return False
        try:
            # Only a look: an error must not keep a session alive. (1.0.36)
            # An administrator past the second step only (1.0.149): a portal
            # user, or a password without its code, was told the directory's
            # and the database's addresses with every error.
            s = self.store.session_get(
                token, 'admin', int(CONFIG.get('session_idle_min') or 120) * 60, touch=False)
            return bool(s) and not mfa_pending(s)
        except Exception:                               # noqa: BLE001
            return False

    def arg(self, name, default=''):
        return self.args.get(name, default)

    def num(self, name, default, lo=0, hi=10 ** 9):
        try:
            return max(lo, min(hi, int(float(self.args.get(name, default)))))
        except (TypeError, ValueError, OverflowError):
            return default

    # ---- who is asking ----------------------------------------------------------
    def session(self, kind):
        token = str(self.headers.get('X-Acme-Session') or '')
        if kind == 'admin':
            idle = int(CONFIG.get('session_idle_min') or 120) * 60
        else:
            idle = int(CONFIG.get('portal_session_min') or 15) * 60
        return self.store.session_get(token, kind, idle)

    def me(self, role='readonly'):
        s = self.session('admin')
        if not s:
            raise ApiError(401, 'not signed in, or the sign-in has run out')
        acc = self.store.account(s['name'])
        if not acc or acc.get('disabled'):
            self.store.session_end(self.headers.get('X-Acme-Session'))
            raise ApiError(401, 'that account may no longer sign in')
        if acc.get('source') == 'directory':
            acc = self.directory_recheck(acc)
        s['role'] = acc['role']
        # The second step first (1.0.125): until it is given, the sign-in may
        # do that and nothing else.
        if mfa_pending(s) and getattr(self, 'route_path', '') not in MFA_ALLOWED:
            raise ApiError(401, 'the second step of signing in is not done yet')
        if acc.get('must_change') and getattr(self, 'route_path', '') not in MUST_CHANGE_ALLOWED:
            raise ApiError(403, 'change the password first')
        if ROLE_RANK.get(s['role'], 0) < ROLE_RANK[role]:
            raise ApiError(403, {'fulladmin': 'only a full administrator may do that',
                                 'certadmin': 'only a certificate administrator may do that'}
                           .get(role, 'that account may not do that'))
        s['account'] = acc
        return s

    def portal_link(self):
        """The enrolment pages' address, for a mail that links to them: from the
        name the pages were reached by, never from what the page sent (1.0.33)."""
        host = str(self.headers.get('X-Acme-Host') or '')
        if not re.fullmatch(r'([A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(:[0-9]{1,5})?', host):
            return ''
        return 'https://%s/' % host

    DIR_CHECKED = {}
    DIR_CHECK_S = 600

    def directory_recheck(self, acc):
        """Somebody signed in from the directory, asked about again every ten
        minutes (1.0.33): switched off there, or out of every group that gives
        a role, and the sign-in ends - not hours later when it runs out. A
        directory that cannot be reached leaves them as they are."""
        name = acc['name']
        t = time.time()
        if t - self.DIR_CHECKED.get(name.lower(), 0) < self.DIR_CHECK_S:
            return acc
        ad = self.d.dirs.get(str(CONFIG.get('admin_directory') or '').lower())
        if not ad:
            self.end_all(name, 'the directory administrators sign in against is gone')
        try:
            who, how = admin_name_parts(name)
            entry = ad.find_user(who, how)
            role = None
            if entry and not entry.get('many') and not entry_unusable(entry, locked=False):
                role = admin_role_for(ad.groups_of(entry, True), ad)
        except Exception as e:                          # noqa: BLE001
            # Asked again in a minute, not on every click: a directory that
            # does not answer would hold each page for its whole timeout. (1.0.36)
            self.DIR_CHECKED[name.lower()] = t - self.DIR_CHECK_S + 60
            log('the directory could not be asked about %s: %s' % (name, e), 'warn')
            return acc
        self.DIR_CHECKED[name.lower()] = t
        if not role:
            self.end_all(name, 'the directory no longer gives %s a role here' % name)
        if role != acc.get('role'):
            self.store.set_account(name, role=role)
            self.store.add_event('accounts', 'the directory gives %s the role %s now (was %s)'
                                 % (name, role, acc.get('role')), 'warn')
            acc = self.store.account(name)
        return acc

    def end_all(self, name, why):
        self.store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                          ('admin', name.lower()))
        self.store.add_event('accounts', '%s: signed out everywhere' % why, 'warn')
        raise ApiError(401, 'that account may no longer sign in')

    THROTTLE_LOCK = threading.Lock()
    THROTTLE_TIDIED = [0.0]

    def throttle(self, kind, tries, wait_min, name='', ip_tries=None, name_tries=None,
                 what='wrong passwords'):
        """A sign-in attempt, counted before the password is asked (1.0.33):
        thirty at once from one address all slipped past a count made after
        the slow check. The attempt holds a place until it is known to have
        gone well, and gives it back then. Counted per address and, more
        loosely, per name, so many addresses cannot share out the guessing
        of one password."""
        ip = self.client_ip()
        try:
            a = ipaddress.ip_address(str(ip).split('%')[0])
            if a.version == 6 and not a.ipv4_mapped:
                # One /64 is one machine's to choose from (1.0.101): counted
                # per address, each guess came from a new one.
                ip = str(ipaddress.ip_network('%s/64' % a, strict=False))
        except ValueError:
            pass
        keys = [(kind, ip)]
        if name:
            # Counted per person, not per spelling (1.0.44): DOMAIN\\novak,
            # novak@anything and Novak are all novak here.
            who = str(name).strip().lower()
            # "admin>person" (a test of somebody's sign-in) keeps its admin
            # (1.0.146): CORP\\novak made it novak alone, one count for all.
            # Only for those tests (1.0.147): a name typed at a sign-in is
            # never split there - a>CORP\\novak, b>CORP\\novak... was a fresh
            # count each time for novak's password.
            pre = sep = ''
            if kind in ('code-test', 'dirtry'):
                pre, sep, who = who.rpartition('>')
            who = who.split('\\', 1)[-1].rsplit('@', 1)[0].strip()
            keys.append((kind + '-name', (pre + sep + who)[:190]))
        t = time.time()
        span = wait_min * 60
        with self.THROTTLE_LOCK:
            for i, key in enumerate(keys):
                # Each limit its own where asked (1.0.103): a code typed on the
                # enrolment pages is one person's, and five typos of one
                # person locked the whole office behind its address out.
                limit = (ip_tries or tries) if i == 0 else (name_tries or tries * 4)
                fails = [x for x in self.d.login_fails[key] if t - x < span]
                self.d.login_fails[key] = fails
                info = self.d.login_info.setdefault(key, {'others': []})
                info.update(limit=limit, span=span, what=what, at=t)
                other = (str(name).strip()[:120] if i == 0 else str(ip)) if name or i else ''
                if other:
                    if other in info['others']:
                        info['others'].remove(other)
                    info['others'] = (info['others'] + [other])[-6:]
                if len(fails) >= limit:
                    raise ApiError(429, 'too many %s %s: try again in %s'
                                   % (what, 'from %s' % ip if i == 0 else 'for this name',
                                      human_span(span - (t - fails[0]))))
            for key in keys:
                self.d.login_fails[key].append(t)
            # Tidied at most every 30 s (1.0.59): past 20 000 names all still
            # waiting, every sign-in scanned the whole map under this lock.
            # Past 50 000 the oldest half goes - memory has an end.
            fl = self.d.login_fails
            if len(fl) > 20000 and t - self.THROTTLE_TIDIED[0] > 30:
                self.THROTTLE_TIDIED[0] = t
                # Kept for the longest wait of any kind (1.0.61), not this
                # kind's: a 5 min kind tidied away 15 min lockouts.
                keep_s = max(span, 6 * 3600)
                for k in [k for k, v in fl.items() if not v or t - v[-1] > keep_s]:
                    fl.pop(k, None)
                    self.d.login_info.pop(k, None)
                if len(fl) > 50000:
                    # Addresses go before names (1.0.61): many addresses must
                    # not flush the count of the one name being guessed.
                    order = sorted(fl, key=lambda k: (str(k[0]).endswith('-name'),
                                                      fl[k][-1] if fl[k] else 0))
                    for k in order[:len(fl) // 2]:
                        if k not in keys:
                            fl.pop(k, None)
                            self.d.login_info.pop(k, None)
        self._held = (keys, t)
        return keys

    def failed(self, key):
        """The attempt went wrong: the place it holds stays taken."""
        self._failed = True

    def _release(self):
        held = getattr(self, '_held', None)
        if not held or getattr(self, '_failed', False):
            return
        keys, t = held
        with self.THROTTLE_LOCK:
            for key in keys:
                got = self.d.login_fails.get(key)
                if got and t in got:
                    got.remove(t)
        self._held = None


ROUTES = {}
# What an administrator who still has to change their password may do.
MUST_CHANGE_ALLOWED = ('/api/auth/password', '/api/auth/logout', '/api/auth/whoami')


def route(method, path):
    def wrap(fn):
        ROUTES[(method, path)] = fn
        return fn
    return wrap


