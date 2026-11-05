# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- how many were sent ------------------------------------------------------------
# Rows counted for a person by every node (1.0.146): each node writes a key of
# its own - 'codesent:NAME@@NODE' - and reads them all. One key for both made
# by both at once (its first INSERT on each node) came over to the other as a
# second row with the same key, and replication stopped for good.
NODE_KEY_SEP = '@@'


def nk_name(prefix, name):
    """The name as a row's key holds it: a long one cut and told apart by a hash (1.0.44) - the
    key of MariaDB's meta is 190 characters, and a long name typed at a sign-in gave a 500."""
    n = norm_name(name)
    full = str(name or '').strip().lower()
    if len(prefix) + len(full) + len(NODE_KEY_SEP) + 66 > 185:
        n = '%s#%s' % (n[:60], hashlib.sha256(full.encode('utf-8')).hexdigest()[:20])
    return n


def node_key(prefix, name):
    return '%s:%s%s%s' % (prefix, nk_name(prefix, name), NODE_KEY_SEP, node_name()[:63])


# Asks one node writes for another (1.0.46): taken away by their writer once the node they are
# for is forgotten - an ask of the users kept its sealed password hashes there for good.
NODE_ASK_PREFIXES = ('host:users:want', 'host:sshkeys:want', 'host:osup:checkwant',
                     'console:want', 'host:selinux:want', 'net:want', 'readdress:dropold',
                     'rbackup:now')


def node_asks_of_gone_tidy(store):
    """This node's asks for a node no longer in the cluster, deleted. Only in a cluster, and
    only while this node's own heartbeat is there (the list of nodes is the real one)."""
    if not CONFIG.get('ha_mode'):
        return 0
    try:
        known = {str(n.get('name') or '')[:63] for n in ha_nodes(store)}
    except Exception:                                   # noqa: BLE001
        return 0
    me = node_name()[:63]
    if me not in known:
        return 0
    n = 0
    for prefix in NODE_ASK_PREFIXES:
        for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE ? ESCAPE '!'",
                               (prefix.replace('!', '!!').replace('%', '!%').replace('_', '!_')
                                + ':%' + NODE_KEY_SEP + me,)):
            k = str(r['k'])
            target = k[len(prefix) + 1:-len(NODE_KEY_SEP + me)]
            if target and target not in {nk_name(prefix, x) for x in known}:
                n += bool(store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (k, r['v'])))
    return n


def node_key_rows(store, prefix, name):
    """Every node's row for `name` (and one written before 1.0.146)."""
    n = nk_name(prefix, name)
    return dbguard_rows(store.db, store.db.rows("SELECT k, v FROM meta WHERE k = ? OR k LIKE ? ESCAPE '!'",
                                              ('%s:%s' % (prefix, n),
                                               '%s:%s%s%%' % (prefix, n.replace('!', '!!').replace('%', '!%')
                                                              .replace('_', '!_'), NODE_KEY_SEP))))


def node_key_name(prefix, k):
    """The name a key is counted for, its node taken off."""
    return str(k)[len(prefix) + 1:].split(NODE_KEY_SEP, 1)[0]


def node_key_times(store, prefix, name):
    """The times in every node's row for `name`."""
    out = []
    for r in node_key_rows(store, prefix, name):
        try:
            out += [float(x) for x in json.loads(r['v'] or '[]')]
        except (ValueError, TypeError):
            continue
    return sorted(out)


def node_key_add(store, prefix, name, keep, most=None, limit=None):
    """`time.time()` added to this node's own row for `name`, written only over
    what was read; the times older than `keep` seconds dropped. True once
    written. With `limit`: False, nothing written, when every node's rows
    together already hold that many - counted again at each try, so of
    requests at once only as many as the limit get past (1.0.147)."""
    k = node_key(prefix, name)
    for _ in range(8):
        t = time.time()
        raw = store.get_meta(k)
        try:
            times = [float(x) for x in json.loads(raw or '[]')]
        except (ValueError, TypeError):
            times = []
        times = [x for x in times if t - x < keep]
        if limit is not None:
            others = 0
            for r in node_key_rows(store, prefix, name):
                if r['k'] == k:
                    continue
                try:
                    others += len([x for x in json.loads(r['v'] or '[]') if t - float(x) < keep])
                except (ValueError, TypeError):
                    continue
            if others + len(times) >= limit:
                return False
        times.append(t)
        if most:
            times = times[-most:]
        new = json.dumps(times)
        if raw is None:
            try:
                store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (k, new))
                return _node_key_recount(store, prefix, name, k, t, keep, limit)
            except Exception:                           # noqa: BLE001
                continue
        if store.db.run('UPDATE meta SET v = ? WHERE k = ? AND v = ?', (new, k, raw)):
            return _node_key_recount(store, prefix, name, k, t, keep, limit)
    return False


def _node_key_recount(store, prefix, name, k, t, keep, limit):
    """Counted again once written (otp 1.0.225): two nodes reading the other's row at the
    same moment both got under the limit - one more than it allows. Over it now: this one
    taken back, and not let past."""
    if limit is None:
        return True
    # By order, not by count (otp 1.0.226): of two written at the same moment both saw one
    # too many and gave back - fewer let past than the limit allows. The first `limit` of
    # all, by their time and their row, keep theirs: of two at once exactly one.
    every = []
    for r in node_key_rows(store, prefix, name):
        try:
            every += [(float(x), r['k']) for x in json.loads(r['v'] or '[]') if t - float(x) < keep]
        except (ValueError, TypeError):
            continue
    every.sort()
    if (t, k) in every[:limit]:
        return True
    node_key_give_back(store, prefix, name, t)
    return False


def node_key_give_back(store, prefix, name, when=None):
    """This node's entry at `when` (or its newest) taken out again."""
    k = node_key(prefix, name)
    for _ in range(8):
        raw = store.get_meta(k)
        try:
            times = [float(x) for x in json.loads(raw or '[]')]
        except (ValueError, TypeError):
            return False
        if not times:
            return False
        if when is not None and when in times:
            times.remove(when)
        elif when is None:
            times.remove(max(times))
        else:
            return False
        if store.db.run('UPDATE meta SET v = ? WHERE k = ? AND v = ?', (json.dumps(times), k, raw)):
            return True
    return False


def node_key_drop(store, prefix, name):
    n = 0
    for r in node_key_rows(store, prefix, name):
        n += store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],)) or 0
    return n


def code_send_allowed(store, name):
    """Whether one more code may be sent to `name` now; counted in the
    database so both nodes count together - each in a row of its own
    (1.0.146), written only over what was read (1.0.94)."""
    span = 60 * int(CONFIG.get('code_send_window_min') or 15)
    return node_key_add(store, 'codesent', name, span,
                        limit=int(CONFIG.get('code_send_max') or 5))


def code_send_wait_min(store, name):
    """How many minutes until one more code may go to `name` (1.0.116) - not
    the whole window, which the page said even when a minute was left."""
    span = 60 * int(CONFIG.get('code_send_window_min') or 15)
    limit = int(CONFIG.get('code_send_max') or 5)
    try:
        times = node_key_times(store, 'codesent', name)
    except (ValueError, TypeError):
        times = []
    t = time.time()
    times = [x for x in times if t - x < span]
    if len(times) < limit:
        return 1
    return max(1, int(-(-(times[len(times) - limit] + span - t) // 60)))


# ---- sending -------------------------------------------------------------------------
class SmsError(RuntimeError):
    pass


def sms_plain(text):
    """The text without accents (1.0.81): one letter outside the GSM
    alphabet makes the whole SMS the wide one, 70 characters a part."""
    if not CONFIG.get('sms_plain', 1):
        return text
    import unicodedata
    out = unicodedata.normalize('NFKD', str(text))
    out = ''.join(c for c in out if not unicodedata.combining(c))
    return out.replace('–', '-').replace('—', '-').replace('„', '"').replace('“', '"')


# ---- a Teltonika gateway (TRB140, RUT…), as zigmon speaks to it (1.0.81) -----------
TELTONIKA = {'token': None, 'until': 0.0, 'modem': None, 'last': 0.0}
TELTONIKA_LOCK = threading.Lock()


def _tel_url(path, params=None):
    host = str(CONFIG.get('sms_tel_host') or '').strip().rstrip('/')
    if not host:
        raise SmsError('no address of the Teltonika gateway is set - Settings → Codes by e-mail '
                       'and SMS')
    scheme = 'https' if CONFIG.get('sms_tel_https', 1) else 'http'
    if '://' in host:
        scheme, host = host.split('://', 1)
    url = '%s://%s%s' % (scheme, host, path)
    if params:
        url += '?' + urllib.parse.urlencode(params)
    return url


SMS_CA_META = 'sms_ca'          # the gateway's certificates trusted (1.0.89)


def sms_ca_pem(store=None):
    store = store or HA_STORE.get('store')
    if store is None:
        return ''
    try:
        return str(store.get_meta(SMS_CA_META) or '')
    except Exception:                                   # noqa: BLE001
        return ''


def sms_ca_set(store, pem, mode='add', fingerprint=''):
    """The certificates the Teltonika gateway is checked against - each added
    and taken out by itself, as the mail server's."""
    pem = str(pem or '').strip()
    have = split_certificates(sms_ca_pem(store))
    if mode == 'add':
        new = split_certificates(pem)
        if not new or not all(describe_certificate(b) for b in new):
            raise ValueError('that is not a certificate this can read: a PEM certificate '
                             'starts -----BEGIN CERTIFICATE-----')
        seen = {c['fingerprint'] for c in describe_certificates('\n'.join(have))}
        have += [b for b, c in zip(new, describe_certificates('\n'.join(new)))
                 if c['fingerprint'] not in seen]
    elif mode == 'drop':
        keep = [b for b, c in zip(have, describe_certificates('\n'.join(have)))
                if c['fingerprint'] != fingerprint]
        if len(keep) == len(have):
            raise ValueError('that certificate is not among the ones kept')
        have = keep
    elif mode == 'clear':
        have = []
    else:
        raise ValueError('add, drop or clear?')
    store.set_meta(SMS_CA_META, '\n'.join(have))
    return describe_certificates('\n'.join(have))


def _tel_is_name(host):
    host = host.split('://', 1)[-1].split('/')[0]
    if host.startswith('['):
        return False
    host = host.rsplit(':', 1)[0] if host.count(':') == 1 else host
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def _tel_ssl():
    if not CONFIG.get('sms_tel_verify'):
        # A TRB makes its own certificate; nothing can check it.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    pem = sms_ca_pem()
    if not pem.strip():
        return ssl.create_default_context()
    # Only what was imported (1.0.89): the gateway's own certificate, or the
    # authority of your own that signed it. A gateway reached by its address
    # has no name to check against - its certificate is: the chain must end
    # in one of these.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ctx.load_verify_locations(cadata=pem)
    except (ssl.SSLError, ValueError) as e:
        raise SmsError('the certificates kept for the gateway cannot be read: %s' % e)
    # Any certificate imported is an anchor of its own (1.0.92): a TRB sends
    # only its own certificate, signed by a "ca" it never shows, and that
    # certificate alone - read from it - was refused as "unable to get local
    # issuer certificate". The strict checks of 3.13 are left out too: a
    # gateway's own certificate is not a web server's.
    ctx.verify_flags |= getattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN', 0x80000)
    ctx.verify_flags &= ~getattr(ssl, 'VERIFY_X509_STRICT', 0x20)
    ctx.check_hostname = _tel_is_name(str(CONFIG.get('sms_tel_host') or ''))
    return ctx


def tel_peer_chain():
    """The certificates the gateway shows, read without checking them - for
    an administrator to look at and trust (1.0.89)."""
    host = str(CONFIG.get('sms_tel_host') or '').strip().rstrip('/')
    if not host:
        raise SmsError('no address of the Teltonika gateway is set')
    host = host.split('://', 1)[-1].split('/')[0]
    port = 443
    if host.startswith('['):
        name, _, rest = host[1:].partition(']')
        if rest.startswith(':'):
            port = int(rest[1:])
    elif host.count(':') == 1:
        name, port = host.split(':')
        port = int(port)
    else:
        name = host
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((name, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=name if _tel_is_name(name) else None) as tls:
                chain = []
                if hasattr(tls, 'get_unverified_chain'):
                    try:
                        chain = [c if isinstance(c, bytes) else c.public_bytes(1)
                                 for c in tls.get_unverified_chain() or []]
                    except Exception:                   # noqa: BLE001
                        chain = []
                if not chain:
                    chain = [tls.getpeercert(binary_form=True)]
    except (OSError, ssl.SSLError) as e:
        raise SmsError('%s:%d could not be reached over TLS: %s' % (name, port, e))
    pems = [ssl.DER_cert_to_PEM_cert(d).strip() for d in chain if d]
    return '\n'.join(pems)


def _tel_password():
    pw = CONFIG.get('sms_tel_password') or ''
    return (unseal_secret(pw) or '') if pw else ''


class _TelAnswer(object):
    """An answer already read - so that it could be written into the log."""

    def __init__(self, status, body):
        self.status, self._body = status, body

    def read(self, n=-1):
        got = self._body if n is None or n < 0 else self._body[:n]
        self._body = b'' if n is None or n < 0 else self._body[n:]
        return got

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_TEL_TEXT = threading.local()     # the text being sent, kept out of the debug log


def _tel_hidden(words):
    """A request or an answer as the debug log may hold it: no password,
    no token (1.0.113), and not the text with its live code (1.0.146)."""
    text = getattr(_TEL_TEXT, 'v', '') or ''
    if text:
        for form in {text, urllib.parse.quote(text, safe=''), urllib.parse.quote_plus(text),
                     json.dumps(text)[1:-1], json.dumps(text, ensure_ascii=False)[1:-1]}:
            if form:
                words = words.replace(form, '<the text, %d characters>' % len(text))
    # The secrets themselves, in each form they travel in (1.0.207): a password
    # with a " in it ended the pattern below early, and a gateway that echoed its
    # key as api_key=... was written down whole.
    for k in ('sms_tel_password', 'sms_token'):
        try:
            sec = unseal_secret(CONFIG.get(k) or '') or ''
        except Exception:                               # noqa: BLE001
            sec = ''
        if len(sec) >= 4:
            for form in {sec, urllib.parse.quote(sec, safe=''), urllib.parse.quote_plus(sec),
                         json.dumps(sec)[1:-1], json.dumps(sec, ensure_ascii=False)[1:-1]}:
                if form:
                    words = words.replace(form, '***')
    words = re.sub(r'(?i)("(?:password|token)"\s*:\s*")(?:\\.|[^"\\])*', r'\1***', words)
    words = re.sub(r'(?i)((?:password|token)=)[^&\s]*', r'\1***', words)
    return re.sub(r'(?i)(Bearer )\S+', r'\1***', words)


def _tel_open(req, timeout=20.0):
    loud = debugging('codes')
    began = time.time()
    if loud:
        body = req.data.decode('utf-8', 'replace') if isinstance(req.data, bytes) else ''
        log('sms: -> %s %s%s (waits %d s)' % (req.get_method(), _tel_hidden(req.full_url),
                                             (' ' + _tel_hidden(body)[:300]) if body else '',
                                             timeout), 'debug')
    try:
        r = url_open(req, timeout=timeout, context=_tel_ssl()
                     if req.full_url.startswith('https') else None, purpose='sms')
        if not loud:
            return r
        with r:
            body = r.read(65536)
            status = getattr(r, 'status', 200)
        log('sms: <- HTTP %s in %.2f s: %s' % (status, time.time() - began, _tel_hidden(
            body.decode('utf-8', 'replace'))[:400]), 'debug')
        return _TelAnswer(status, body)
    except urllib.error.URLError as e:
        if loud:
            _tel_said_failed(e, began)
        # The certificate refused (1.0.89): nothing was sent, and the page
        # says what to do about it.
        if isinstance(getattr(e, 'reason', None), ssl.SSLCertVerificationError):
            raise SmsError('the gateway\'s certificate did not pass the check (%s): import its '
                           'certificate or the authority that signed it under Settings → Codes '
                           'by e-mail and SMS, or switch Check its certificate off'
                           % (getattr(e.reason, 'verify_message', '') or e.reason))
        raise
    except Exception as e:                              # noqa: BLE001
        if loud:
            _tel_said_failed(e, began)
        raise


def _tel_said_failed(e, began):
    extra = ''
    if isinstance(e, urllib.error.HTTPError):
        try:
            said = e.read(400)
            extra = ': ' + _tel_hidden(said.decode('utf-8', 'replace'))
            e.read = (lambda b: (lambda n=-1: b))(said)         # the caller reads it too
        except Exception:                               # noqa: BLE001
            pass
    log('sms: <- FAILED after %.2f s: %s %s%s' % (time.time() - began, type(e).__name__,
                                               getattr(e, 'reason', e), extra), 'debug')


def _tel_never_arrived(e):
    """Whether a failed request certainly never reached the gateway - a
    refused or reset connection. A read that timed out did reach it: the box
    took the message and has not answered, and sending it again is a second
    SMS on the person's phone (zigmon's lesson)."""
    if isinstance(e, socket.timeout):
        return False
    reason = getattr(e, 'reason', e)
    if isinstance(reason, socket.timeout):
        return False
    words = str(e).lower()
    if 'timed out' in words or 'timeout' in words:
        return False
    return isinstance(reason, (ConnectionRefusedError, ConnectionResetError,
                               ConnectionAbortedError, socket.gaierror)) or \
        any(w in words for w in ('refused', 'reset by peer', 'not known', 'no route',
                                 'broken pipe'))


def _tel_who():
    """What a login is for: another address, user or password is another
    login - a token kept from before a change is not used after it."""
    return hashlib.sha256(('%s|%s|%s|%s' % (CONFIG.get('sms_tel_host'), CONFIG.get('sms_tel_https'),
                                            CONFIG.get('sms_tel_user'), _tel_password()))
                          .encode('utf-8')).hexdigest()


def _tel_logout(token, who=None):
    """A login given back (1.0.152): every new one used to be left to run out
    on the box, which lists each as a session of its own until it does. Best
    effort, a few seconds at most - an older RutOS without it only says no."""
    if not token:
        return
    try:
        req = urllib.request.Request(_tel_url('/api/logout'), data=b'{}', method='POST',
                                     headers={'Content-Type': 'application/json',
                                              'Authorization': 'Bearer ' + token})
        with _tel_open(req, 4) as r:
            r.read(200)
    except Exception:                                   # noqa: BLE001
        pass


def _tel_drop_token():
    """The login in hand given back and forgotten."""
    old, TELTONIKA['token'] = TELTONIKA.get('token'), None
    _tel_logout(old)


def _tel_end_of_process():
    # A command that sent or tried something gives its login back as it ends
    # (1.0.152); the daemon keeps its one and renews it.
    if DAEMON_DB[0] is None and TELTONIKA.get('token'):
        _tel_drop_token()


import atexit as _atexit                                # noqa: E402
_atexit.register(_tel_end_of_process)


def _tel_token(fresh=False):
    """A login on RutOS's own API: a token that lasts five minutes, renewed a
    minute before - one at a time: the one before is given back first."""
    now = time.time()
    if TELTONIKA.get('who') != _tel_who():
        # Another box or user: the old login is not this one's to give back
        # with its address gone - it runs out by itself there.
        TELTONIKA.update(token=None, modem=None, who=_tel_who())
    if not fresh and TELTONIKA['token'] and now < TELTONIKA['until']:
        return TELTONIKA['token']
    _tel_drop_token()
    body = json.dumps({'username': CONFIG.get('sms_tel_user') or 'admin',
                       'password': _tel_password()}).encode()
    tries = 0
    while True:
        tries += 1
        req = urllib.request.Request(_tel_url('/api/login'), data=body, method='POST',
                                     headers={'Content-Type': 'application/json'})
        try:
            with _tel_open(req, 15) as r:
                answer = json.loads(r.read() or b'{}')
            break
        except urllib.error.HTTPError as e:
            raise SmsError('the Teltonika would not let acme in (HTTP %d) - check its user and '
                           'password, and that the user may use the API' % e.code)
        except (urllib.error.URLError, OSError, ValueError) as e:
            # Signing in is asked again once (1.0.113): a box busy with the
            # modem leaves a login unanswered now and then, and asking again
            # sends nothing twice.
            if tries < 2 and not isinstance(e, ValueError):
                log('sms: the Teltonika did not answer the sign-in (%s) - asked again'
                    % getattr(e, 'reason', e), 'warn')
                time.sleep(1)
                continue
            raise SmsError('the Teltonika could not be reached%s: %s' % (
                ' (asked twice)' if tries > 1 else '', getattr(e, 'reason', e)))
    data = answer.get('data') or {}
    token = data.get('token') or answer.get('token') or ''
    if not token:
        raise SmsError('the Teltonika gave no token: %s' % json.dumps(answer)[:150])
    TELTONIKA['token'] = token
    TELTONIKA['until'] = now + max(30.0, float(data.get('expires') or 299) - 60)
    return token


def _tel_rest(path, method='GET', payload=None, timeout=20.0, again=True):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(_tel_url('/api' + path), data=data, method=method,
                                 headers={'Content-Type': 'application/json',
                                          'Authorization': 'Bearer ' + _tel_token()})
    try:
        with _tel_open(req, timeout) as r:
            answer = json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        said = ''
        try:
            said = e.read(300).decode('utf-8', 'replace')
        except Exception:                               # noqa: BLE001
            pass
        if e.code in (401, 403) and again:
            TELTONIKA['token'] = None                   # gone stale - nothing to give back
            return _tel_rest(path, method, payload, timeout, again=False)
        raise SmsError('the Teltonika answered %s %s with HTTP %d %s' % (method, path, e.code,
                                                                         said))
    if answer.get('success') is False:
        raise SmsError('the Teltonika refused %s: %s' % (path, json.dumps(
            answer.get('errors') or answer)[:200]))
    return answer.get('data', answer)


def _tel_modem():
    if CONFIG.get('sms_tel_modem'):
        return str(CONFIG['sms_tel_modem']).strip()
    if TELTONIKA.get('who') != _tel_who():
        TELTONIKA.update(token=None, modem=None, who=_tel_who())
    if TELTONIKA['modem']:
        return TELTONIKA['modem']
    rows = _tel_rest('/modems/status') or []
    if isinstance(rows, dict):
        rows = [rows]
    first = next((r for r in rows if isinstance(r, dict) and r.get('id')), None)
    if not first:
        raise SmsError('the Teltonika named no modem')
    TELTONIKA['modem'] = str(first['id'])
    return TELTONIKA['modem']


def tel_send(to, text):
    """One SMS through a Teltonika, one at a time: the box sends one message
    after another, and a second asked for at once is taken and then left
    unanswered for a minute."""
    waited = time.time()
    with TELTONIKA_LOCK:
        gap = 2.0 - (time.time() - TELTONIKA['last'])
        if gap > 0:
            time.sleep(gap)
        loud = debugging('codes')
        if loud:
            log('sms: to %s, %d characters, through the Teltonika %s (%s), after %.1f s in the '
                'queue' % (to[:-3] + '***' if len(to) > 6 else to, len(text),
                           CONFIG.get('sms_tel_host'), CONFIG.get('sms_tel_api') or 'rest',
                           time.time() - waited), 'debug')
        began = time.time()
        _TEL_TEXT.v = text
        try:
            said = _tel_send(to, text)
            if loud:
                log('sms: done in %.1f s - %s' % (time.time() - began, said), 'debug')
            return said
        except Exception as e:
            if loud:
                log('sms: FAILED after %.1f s - %s' % (time.time() - began, e), 'debug')
            raise
        finally:
            _TEL_TEXT.v = ''
            TELTONIKA['last'] = time.time()


def _tel_send(to, text):
    parts = 1 if len(text) <= (160 if all(ord(c) < 128 for c in text) else 70) else 2
    timeout = 20.0 * parts
    if (CONFIG.get('sms_tel_api') or 'rest') == 'cgi':
        number = '00' + to.lstrip('+')                  # Teltonika's CGI wants 00420…
        url = _tel_url('/cgi-bin/sms_send', {'username': CONFIG.get('sms_tel_user') or '',
                                             'password': _tel_password(), 'number': number,
                                             'text': text})
        tries = 0
        while True:
            tries += 1
            try:
                with _tel_open(urllib.request.Request(url), timeout) as r:
                    said = r.read(400).decode('utf-8', 'replace').strip()
                break
            except urllib.error.HTTPError as e:
                raise SmsError('the Teltonika answered HTTP %d: %s' % (
                    e.code, e.read(200).decode('utf-8', 'replace')))
            except (urllib.error.URLError, OSError) as e:
                if tries < 3 and _tel_never_arrived(e):
                    time.sleep(tries)
                    continue
                if not _tel_never_arrived(e):
                    return 'no answer from the Teltonika in %d s - the SMS has most likely gone' \
                        % timeout
                raise SmsError('the Teltonika could not be reached: %s' % getattr(e, 'reason', e))
        if 'error' in said.lower() and not said.lower().startswith('ok'):
            raise SmsError('the Teltonika said: %s' % said[:200])
        return 'the Teltonika said: %s' % (said[:120] or 'OK')
    tries = 0
    while True:
        tries += 1
        try:
            # How long each step took, said with the answer (1.0.109): a
            # test that took long tells whether it was the login, finding
            # the modem or the sending itself - RutOS answers the send only
            # once the modem has given the SMS to the network.
            t0 = time.time()
            _tel_token()
            t1 = time.time()
            modem = _tel_modem()
            t2 = time.time()
            out = _tel_rest('/messages/actions/send', 'POST',
                            {'data': {'number': to, 'message': text, 'modem': modem}},
                            timeout=timeout)
            t3 = time.time()
            steps = []
            if t1 - t0 > 0.05:
                steps.append('signing in %.1f s' % (t1 - t0))
            if t2 - t1 > 0.05:
                steps.append('finding the modem %.1f s' % (t2 - t1))
            steps.append('the modem sending it %.1f s' % (t3 - t2))
            return 'the Teltonika took it (%s; %s)' % (', '.join(steps), json.dumps(out)[:60])
        except SmsError:
            raise
        except (urllib.error.URLError, OSError) as e:
            if tries < 3 and _tel_never_arrived(e):
                TELTONIKA['until'] = 0                  # a new connection, a new login
                time.sleep(tries)
                continue
            if not _tel_never_arrived(e):
                return 'no answer from the Teltonika in %d s - the SMS has most likely gone' \
                    % timeout
            raise SmsError('the Teltonika could not be reached: %s' % getattr(e, 'reason', e))


def tel_check():
    """Whether the gateway is there and takes the password - nothing sent."""
    if (CONFIG.get('sms_tel_api') or 'rest') == 'cgi':
        url = _tel_url('/cgi-bin/sms_list', {'username': CONFIG.get('sms_tel_user') or '',
                                             'password': _tel_password()})
        try:
            with _tel_open(urllib.request.Request(url), 15) as r:
                said = r.read(300).decode('utf-8', 'replace')
        except (urllib.error.URLError, OSError) as e:
            raise SmsError('the Teltonika could not be reached: %s' % getattr(e, 'reason', e))
        if 'error' in said.lower() and 'no messages' not in said.lower():
            raise SmsError('the Teltonika said: %s' % said.strip()[:150])
        return 'the Teltonika answered and took the password'
    _tel_token(fresh=True)
    TELTONIKA['modem'] = None
    return 'the Teltonika let acme in; its modem is %s' % _tel_modem()


# What a modem's status says, in the order shown (1.0.113). RutOS 7 names
# them so; a field it does not have is left out.
TEL_MODEM_FIELDS = (
    ('name', 'Modem'), ('model', 'Model'), ('operator', 'Operator'),
    ('ntype', 'Network'), ('conntype', 'Connection'), ('band', 'Band'),
    ('state', 'State'), ('operator_state', 'Registered'), ('netstate', 'Network state'),
    ('active_sim', 'SIM in use'), ('simstate', 'SIM'), ('pinstate', 'PIN'),
    ('signal_quality', 'Signal quality (%)'), ('rssi', 'RSSI (dBm)'), ('rsrp', 'RSRP (dBm)'),
    ('rsrq', 'RSRQ (dB)'), ('sinr', 'SINR (dB)'), ('temperature', 'Temperature (C)'),
    ('volte', 'VoLTE'), ('sms_center_address', 'SMS centre'), ('imei', 'IMEI'),
    ('version', 'Modem firmware'))


def tel_modem_words(row):
    out = [('id', str(row.get('id') or ''))]
    for k, words in TEL_MODEM_FIELDS:
        v = row.get(k)
        if v in (None, '', [], {}):
            continue
        if isinstance(v, (dict, list)):
            v = json.dumps(v)[:80]
        out.append((words, str(v)[:80]))
    if len(out) < 4:
        # Another firmware, other names: what it said, plainly.
        for k, v in list(row.items())[:12]:
            if k != 'id' and isinstance(v, (str, int, float)) and str(v) != '':
                out.append((str(k)[:30], str(v)[:80]))
    return out


def tel_test():
    """The gateway tried, step by step, without sending anything (1.0.113):
    reached, signed in, its modems and what each says about the network."""
    mode = (CONFIG.get('sms_tel_api') or 'rest')
    host = str(CONFIG.get('sms_tel_host') or '').strip()
    out = {'ok': False, 'steps': [], 'modems': [], 'api': mode, 'host': host,
           'https': bool(CONFIG.get('sms_tel_https')),
           'checked': bool(CONFIG.get('sms_tel_https') and CONFIG.get('sms_tel_verify'))}
    if not host:
        out['steps'].append({'what': 'the address', 'ok': False, 'secs': 0,
                             'said': 'no address of the gateway is saved'})
        return out

    def step(what, fn):
        t = time.time()
        try:
            got = fn()
        except SmsError as e:
            out['steps'].append({'what': what, 'ok': False, 'secs': round(time.time() - t, 2),
                                 'said': str(e)})
            return None, False
        out['steps'].append({'what': what, 'ok': True, 'secs': round(time.time() - t, 2),
                             'said': got if isinstance(got, str) else ''})
        return got, True

    with TELTONIKA_LOCK:
        if mode == 'cgi':
            _x, ok = step('signing in (Post/Get)', tel_check)
            out['ok'] = ok
            return out
        TELTONIKA['modem'] = None
        _x, ok = step('signing in', lambda: (_tel_token(fresh=True) and 'let in as %s'
                                            % (CONFIG.get('sms_tel_user') or 'admin')))
        if not ok:
            return out
        rows, ok = step('its modems', lambda: _tel_rest('/modems/status'))
        if not ok:
            return out
        if isinstance(rows, dict):
            rows = [rows]
        rows = [r for r in (rows or []) if isinstance(r, dict)]
        want = str(CONFIG.get('sms_tel_modem') or '').strip()
        chosen = want or (str(rows[0].get('id')) if rows and rows[0].get('id') else '')
        for r in rows[:6]:
            out['modems'].append({'id': str(r.get('id') or ''), 'sends': str(r.get('id')) == chosen,
                                  'fields': tel_modem_words(r)})
        out['steps'][-1]['said'] = '%d modem(s)' % len(rows)
        if want and not any(str(r.get('id')) == want for r in rows):
            out['steps'].append({'what': 'the modem set', 'ok': False, 'secs': 0,
                                 'said': 'the gateway has no modem %s - it has %s' % (
                                     want, ', '.join(str(r.get('id')) for r in rows) or 'none')})
            return out
        if not chosen:
            out['steps'].append({'what': 'the modem', 'ok': False, 'secs': 0,
                                 'said': 'the gateway named no modem'})
            return out
        TELTONIKA['modem'] = chosen
        out['ok'] = True
    return out


def sms_send(to, text):
    """One SMS. Returns what the gateway said; raises SmsError."""
    mode = CONFIG.get('sms_mode') or 'off'
    if mode == 'off':
        raise SmsError('sending SMS is switched off - Settings → Codes by mail and SMS')
    text = sms_plain(text)
    if mode == 'teltonika':
        return tel_send(to, text)
    if mode == 'spool':
        folder = Path(str(CONFIG.get('sms_spool_dir') or '').strip())
        if not folder.is_dir():
            raise SmsError('the spool folder %s is not there' % folder)
        # smstools3: a file "To: 420…", an empty line, the text. Written
        # beside and renamed in, so the daemon never reads half of one.
        body = 'To: %s\nAlphabet: UTF-8\n\n%s\n' % (to.lstrip('+'), text)
        name = 'acme-%d-%s' % (int(time.time()), secrets.token_hex(4))
        tmp = folder / ('.' + name)
        try:
            # Not readable by everyone (1.0.44): the text is a sign-in code. smstools3 runs
            # in the group of its spool folder - the group may read and take it, the rest not.
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o660)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(body)
            gid = folder.stat().st_gid
            try:
                os.chown(str(tmp), -1, gid)                     # the folder's group: smsd's
            except OSError:
                pass
            # 0660 only where that group is the folder's own and not acme's: otherwise smsd,
            # in another group, could no longer read it - and no code went out.
            mine = os.stat(str(tmp)).st_gid == gid and gid != os.getgid()
            os.chmod(str(tmp), 0o660 if mine else 0o664)
            os.rename(str(tmp), str(folder / name))
        except OSError as e:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise SmsError('it could not be written into %s: %s' % (folder, e))
        return 'written into %s as %s' % (folder, name)
    url = str(CONFIG.get('sms_url') or '').strip()
    if not url:
        raise SmsError('no gateway address is set - Settings → Codes by mail and SMS')
    token = unseal_secret(CONFIG.get('sms_token') or '') or '' if CONFIG.get('sms_token') else ''
    vals = {'to': to, 'to_digits': to.lstrip('+'), 'text': text, 'token': token}

    def fill(tpl, how):
        def one(m):
            k = m.group(1)
            v = vals.get(k)
            if v is None:
                return m.group(0)
            if how == 'url':
                return urllib.parse.quote(v, safe='')
            if how == 'json':
                return json.dumps(v)[1:-1]
            return v
        return re.sub(r'\{(to|to_digits|text|token)\}', one, tpl)
    full = fill(url, 'url')
    method = (CONFIG.get('sms_method') or 'POST').upper()
    tpl = str(CONFIG.get('sms_body') or '')
    data, ctype = None, None
    if method == 'POST':
        if tpl.strip().startswith('{'):
            data, ctype = fill(tpl, 'json').encode('utf-8'), 'application/json'
        elif tpl.strip():
            data, ctype = fill(tpl, 'url').encode('utf-8'), 'application/x-www-form-urlencoded'
        else:
            data = b''
    req = urllib.request.Request(full, data=data, method=method)
    if ctype:
        req.add_header('Content-Type', ctype)
    for line in str(CONFIG.get('sms_headers') or '').splitlines():
        if ':' in line:
            k, _, v = line.partition(':')
            if k.strip():
                req.add_header(k.strip(), fill(v.strip(), 'raw'))
    try:
        with url_open(req, timeout=15, purpose='sms') as r:
            said = r.read(4000).decode('utf-8', 'replace')
            status = r.status
    except urllib.error.HTTPError as e:
        _TEL_TEXT.v = text
        try:
            body = _tel_hidden(e.read(300).decode('utf-8', 'replace'))
        finally:
            _TEL_TEXT.v = ''
        raise SmsError('the gateway answered %d: %s' % (e.code, body))
    except (urllib.error.URLError, OSError) as e:
        raise SmsError('the gateway could not be reached: %s' % getattr(e, 'reason', e))
    want = str(CONFIG.get('sms_ok_status') or '').strip()
    # A gateway that says back what it was sent (1.0.147): not the code
    # into the events and the log with it.
    _TEL_TEXT.v = text
    try:
        said = _tel_hidden(said)
    finally:
        _TEL_TEXT.v = ''
    if want and want.lower() not in said.lower():
        raise SmsError('the gateway answered %d without "%s": %s' % (status, want, said[:300]))
    return 'the gateway answered %d%s' % (status, (': ' + said[:200]) if said.strip() else '')


def code_mail_html(code, purpose, lang, name='', display='', w=None):
    """The mail of a code in the shape and colours of acme's other mails
    (1.0.79): the blue band, the white card, the code in a grey box, the
    warning in orange - tables and styles on each element, as every mail
    program shows them alike. Its words as Settings → Message
    texts has them (1.0.103), or `w` - the editor's, not yet saved."""
    lang = lang if lang in CODE_TEXTS else code_lang()
    if w is None:
        w = texts_for('code', lang)
    h = lambda t: html.escape(str(t or ''), quote=True)
    site = str(CONFIG.get('site_name') or socket.gethostname())
    issuer = site
    minutes = max(1, int(CONFIG.get('code_ttl_s') or 300) // 60)
    # name@domain kept plain text, not made a link by the mail program.
    acc = ('<span style="white-space:nowrap">%s</span>' % h(name).replace('@', '@&#8205;')
           if name else '')
    font = "font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
    rows = []
    cp = code_purpose(purpose)
    v = cp['p']
    hello = (w['h_%shello' % v].format(name=h(display)) if display
             else w['h_%shello_anon' % v].format())
    if hello.strip():
        rows.append('<p style="margin:0 0 6px;font-size:16px;color:#111827">%s</p>' % hello)
    lede = (w['h_%slede' % v].format(account=acc) if name
            else w['h_%slede_anon' % v].format())
    facts, note, warn = w['h_%sfacts' % v], w[cp['note']], cp['warn']
    if lede.strip():
        rows.append('<p style="margin:0 0 18px;font-size:15px;line-height:1.55;color:#374151">'
                    '%s</p>' % lede)
    spaced = ' '.join(code[i:i + 3] for i in range(0, len(code), 3)) if len(code) == 6 else code
    rows.append('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                'border="0" style="margin:0 0 10px"><tr><td align="center">'
                '<table role="presentation" cellspacing="0" cellpadding="0" border="0"><tr>'
                '<td align="center" bgcolor="#f3f4f6" style="padding:16px 30px;background:#f3f4f6;'
                'border:1px solid #e5e7eb;border-radius:12px;font-family:Consolas,Menlo,'
                '\'Courier New\',monospace;font-size:34px;font-weight:700;letter-spacing:6px;'
                'color:#111827;white-space:nowrap">%s</td></tr></table></td></tr></table>' % h(spaced))
    if facts.strip():
        rows.append('<p style="margin:0 0 22px;font-size:13.5px;line-height:1.5;color:#6b7280;'
                    'text-align:center;%s">%s</p>' % (font, facts.format(minutes=minutes)))
    else:
        rows.append('<div style="height:12px;line-height:12px;font-size:1px">&nbsp;</div>')
    note = note.format()
    if not note.strip():
        pass
    elif warn:
        rows.append('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                    'border="0"><tr><td bgcolor="#fff7ed" style="padding:12px 16px;'
                    'background:#fff7ed;border-left:4px solid #f59e0b;font-size:13px;'
                    'line-height:1.5;color:#7c2d12;%s">%s</td></tr></table>' % (font, note))
    else:
        rows.append('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                    'border="0"><tr><td bgcolor="#eff6ff" style="padding:12px 16px;'
                    'background:#eff6ff;border-left:4px solid #2563eb;font-size:13px;'
                    'line-height:1.5;color:#1e3a8a;%s">%s</td></tr></table>' % (font, note))
    subject = w[cp['subject']].format(code=code, site=site, minutes=minutes)
    title = w['h_%stitle' % v].format(site=site)
    foot = w['h_%sfoot' % v].format(site=h(site))
    return ('<!doctype html><html lang="%s" xmlns:v="urn:schemas-microsoft-com:vml" '
            'xmlns:o="urn:schemas-microsoft-com:office:office"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>'
            '<!--[if mso]><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch>'
            '</o:OfficeDocumentSettings></xml><![endif]--></head>'
            '<body style="margin:0;padding:0;background:#f3f4f6;%s">'
            '<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
            'border="0" bgcolor="#f3f4f6" style="background:#f3f4f6"><tr><td align="center" '
            'style="padding:28px 12px">'
            '<table role="presentation" width="560" cellspacing="0" cellpadding="0" border="0" '
            'bgcolor="#ffffff" style="max-width:560px;width:100%%;background:#ffffff;'
            'border-radius:14px;overflow:hidden;border:1px solid #e5e7eb">'
            '<tr><td bgcolor="#1e3a8a" style="background:#1e3a8a;padding:20px 28px;'
            'color:#ffffff;%s">'
            '<p style="margin:0;font-size:12px;letter-spacing:1.5px;text-transform:uppercase;'
            'color:#c7d2fe">%s</p><p style="margin:4px 0 0;font-size:20px;font-weight:700;'
            'color:#ffffff">%s</p></td></tr>'
            '<tr><td style="padding:26px 28px;%s">%s</td></tr>'
            '<tr><td style="padding:14px 28px 22px;font-size:12px;color:#9ca3af;%s;'
            'border-top:1px solid #f3f4f6">%s</td></tr></table></td></tr></table></body></html>'
            % (lang, h(subject), font, font, h(issuer), h(title), font, ''.join(rows),
               font, foot))


def code_message(kind, to, code, purpose='admin', lang=None, name='', display='', fmt=None,
                 w=None):
    """The mail or the SMS text of a code. `w`: the words to use instead of
    those saved - the message texts editor's test (1.0.103)."""
    cp = code_purpose(purpose)
    if kind == 'sms':
        return code_words(cp['sms'], lang=lang, w=w, code=code)
    site = str(CONFIG.get('site_name') or socket.gethostname())
    msg = EmailMessage()
    msg['Subject'] = code_words(cp['subject'], lang=lang, w=w, code=code)
    sender = mail_sender()
    if not sender:
        raise MailError('no sender address is set - Settings → Mail → From (address)')
    msg['From'] = formataddr((str(CONFIG.get('mail_from_name') or site), sender))
    msg['To'] = to
    if CONFIG.get('mail_reply_to'):
        msg['Reply-To'] = str(CONFIG.get('mail_reply_to'))
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=sender.rsplit('@', 1)[-1] or None)
    msg['Auto-Submitted'] = 'auto-generated'
    msg.set_content(code_words(cp['body'], lang=lang,
                               w=w, code=code))
    if (fmt or ('text' if CONFIG.get('code_mail_fmt') == 'text' else 'html')) != 'text':
        msg.add_alternative(code_mail_html(code, purpose, lang, name, display, w=w),
                            subtype='html')
    return msg


def code_send(store, kind, to, code, purpose='admin', name='', lang=None, fmt=None,
              display=None):
    """code_send_now, with the code taken out of whatever the server said
    (1.0.136): an SMS gateway that echoes the message put a live code into
    the events and the log."""
    def hide(t):
        return str(t).replace(str(code), '******') if code else str(t)
    try:
        got = hide(code_send_now(store, kind, to, code, purpose, name, lang, fmt, display))
        if kind == 'sms':
            sms_health(True)                    # for the alerts (1.0.162)
        return got
    except MailError as e:
        new = MailError(hide(e), steps=e.steps, permanent=e.permanent)
        for k, v in vars(e).items():
            if k not in ('steps', 'permanent'):
                setattr(new, k, v)
        raise new
    except SmsError as e:
        sms_health(False, hide(e))
        raise SmsError(hide(e))


def code_send_now(store, kind, to, code, purpose='admin', name='', lang=None, fmt=None,
                  display=None):
    """A code sent now; what the server said, or raises MailError/SmsError.
    `name` is the account it is for, `display` its name as people read it."""
    lang = lang if lang in CODE_TEXTS else None
    if kind == 'mail':
        msg = code_message('mail', to, code, purpose, lang=lang, name=name,
                           display=display or '', fmt=fmt)
        # Through the outgoing mail (1.0.95): greylisted, it is tried again
        # while the code is good - and the person gets it a minute later
        # rather than never.
        try:
            steps = mail_deliver(store, msg, [to], kind=code_purpose(purpose)['queue'],
                                 name=name, purpose=purpose,
                                 expires=time.time() + int(CONFIG.get('code_ttl_s') or 300))
        except MailError as e:
            if e.queued == 'waiting':
                return 'not taken yet (%s) - it waits in the outgoing mail and is tried again' % e
            raise
        last = [s for s in steps if s.get('ok')]
        return (last[-1].get('said') or 'sent') if last else 'sent'
    if kind == 'sms':
        return sms_send(to, code_message('sms', to, code, purpose, lang=lang))
    raise ValueError('a code goes by mail or SMS, not by %s' % kind)
