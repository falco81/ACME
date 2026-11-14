# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- signing in with Windows: Kerberos SSO (1.0.99, as otp 1.0.274) ---------------------------
# A browser on a computer in the domain sends a Kerberos ticket for HTTP/<the name in its address
# bar>, got from the domain controller with the person's Windows sign-in; it is checked here with
# the key of that name, from a keytab - no KDC is asked, no password typed. Two parts, each with
# its own switches: the administration (admin_krb...) and the certificate portal (portal_krb...);
# one keytab for both (one service account in AD, an SPN for every name the pages are opened by).
#
# The rules, kept whatever is set:
#   - Kerberos 5 only: a token of NTLM - bare, or inside SPNEGO - is refused, and so is any other
#     mechanism of SPNEGO; the mechanism is checked after the library accepted it, as a library
#     with gss-ntlmssp installed would take NTLM inside SPNEGO happily. There is no setting for it.
#   - The ticket replaces the password, nothing more: the person is looked up in that part's
#     directory by sAMAccountName (switched off, locked, expired, more than one, a computer:
#     refused), who may sign in decides as for a password, and the second step (the
#     administration's) or the one-time code (the portal's) is asked after it every time.
#   - Once in the cluster: sha256 of the whole token kept a day in the shared database (a row of
#     each node, read across all of them) - MIT's own replay cache is one host's, and behind the
#     VIP address a token caught on its way could be sent to the other node.
#   - The keytab is put in on the pages (or acme --kerberos-keytab), kept in the database sealed
#     with the installation's key and signed (db_guard), and written out by each node itself
#     (0600, the service's own user) - a node put back from a backup or joined later too.
#   - Every refusal: 401 here, which the page turns into 403 for the browser - never a second 401
#     with Negotiate, which would make the browser try again, offer NTLM or open a password
#     window of its own.
#   - "Only Windows" (admin_password_off, portal_password_off): switched on only by somebody signed
#     in with Windows to that part, in effect only while Kerberos is on with a keytab - switching
#     Kerberos off (as root) brings the passwords back.
#
# The system's GSS-API library (libgssapi_krb5, MIT Kerberos) through ctypes: nothing to install.

import ctypes          # noqa: E402  (the system's GSS-API library, 1.0.99)
import ctypes.util     # noqa: E402

KRB5_MECH = bytes.fromhex('2a864886f712010202')          # 1.2.840.113554.1.2.2 (Kerberos 5)
KRB_TOKEN_MAX = 65536                                     # bytes: more than any ticket with a PAC
KRB_HEADER_MAX = 90000                                    # its base64 and "Negotiate "
KRB_KEYTAB_MAX = 64 * 1024
KRB_META = 'krb:keytab'
KRB_BIND = 'krb:keytab'
KRB_NODE_META = 'krb:node:'
KRB_ONCE = 'krbonce'
KRB_ONCE_S = 86400
KRB_PARTS = ('admin', 'portal')
KRB_ENCTYPES = {1: 'des-cbc-crc', 3: 'des-cbc-md5', 16: 'des3-cbc-sha1', 17: 'aes128-cts-hmac-sha1-96',
                18: 'aes256-cts-hmac-sha1-96', 19: 'aes128-cts-hmac-sha256-128',
                20: 'aes256-cts-hmac-sha384-192', 23: 'rc4-hmac', 24: 'rc4-hmac-exp'}
KRB_WEAK = (1, 3, 16, 23, 24)
KRB_ONLY_SAID = 'only Windows: these pages take no password - sign in with Windows'
KRB_PROOF_SAID = {
    'admin': 'admin_password_off: "only Windows" is switched on only from a sign-in made with '
             'Windows (Kerberos) to these pages - sign in with Windows first, so it is seen to '
             'work for you',
    'portal': 'portal_password_off: "only Windows" on the portal is switched on only by somebody '
              'signed in to the portal with Windows in this browser - open the portal, sign in '
              'with Windows there first, then switch it on here'}


class KrbError(Exception):
    """A ticket not taken; the words say why (never anything secret)."""


class KrbRefused(Exception):
    """A sign-in with a ticket refused: `said` for the person, `why` for Events."""

    def __init__(self, said, why=None, status=401):
        Exception.__init__(self, said)
        self.said = said
        self.why = why or said
        self.status = status


class _KrbBuf(ctypes.Structure):
    _fields_ = [('length', ctypes.c_size_t), ('value', ctypes.c_void_p)]


class _KrbOid(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('elements', ctypes.c_void_p)]


KRB_LIB = {'lib': None, 'err': '', 'tried': False, 'ident': None}
# One ticket at a time: the acceptor's keytab is the process's (registered once per file), and
# the library's replay cache is a file - a few milliseconds each, never a queue worth having.
KRB_LOCK = threading.Lock()
KRB_STATE = {'have': None, 'sha': None, 'checked': 0.0, 'said_at': 0.0, 'said': None,
             'error': '', 'written': False,
             # The daemon writes the file, never the command line run as root: a folder of
             # root's there and the service could no longer write the keytab it is given.
             'writer': False}


def krb_lib():
    """The system's libgssapi_krb5, its functions declared - or None (KRB_LIB['err'] says why)."""
    if KRB_LIB['tried']:
        return KRB_LIB['lib']
    KRB_LIB['tried'] = True
    # The library's own replay cache beside the keytab (the service's folder, made by the
    # daemon when it writes the keytab out), not /var/tmp.
    os.environ.setdefault('KRB5RCACHEDIR', str(krb_keytab_path().parent))
    try:
        lib = ctypes.CDLL(ctypes.util.find_library('gssapi_krb5') or 'libgssapi_krb5.so.2')
        P, U, V = ctypes.POINTER, ctypes.c_uint32, ctypes.c_void_p
        lib.gss_accept_sec_context.argtypes = [P(U), P(V), V, P(_KrbBuf), V, P(V), P(P(_KrbOid)),
                                               P(_KrbBuf), P(U), P(U), P(V)]
        lib.gss_accept_sec_context.restype = U
        lib.gss_display_name.argtypes = [P(U), V, P(_KrbBuf), P(P(_KrbOid))]
        lib.gss_display_name.restype = U
        lib.gss_display_status.argtypes = [P(U), U, ctypes.c_int, V, P(U), P(_KrbBuf)]
        lib.gss_display_status.restype = U
        lib.gss_release_buffer.argtypes = [P(U), P(_KrbBuf)]
        lib.gss_release_name.argtypes = [P(U), P(V)]
        lib.gss_delete_sec_context.argtypes = [P(U), P(V), V]
        # The keytab named for the acceptor by the library itself, not by KRB5_KTNAME in the
        # environment of a threaded daemon.
        lib.krb5_gss_register_acceptor_identity.argtypes = [ctypes.c_char_p]
        lib.krb5_gss_register_acceptor_identity.restype = U
        KRB_LIB['lib'] = lib
    except (OSError, AttributeError) as e:
        KRB_LIB['err'] = 'the Kerberos library (libgssapi_krb5) is not there: %s' % e
    return KRB_LIB['lib']


def krb_lib_state():
    lib = krb_lib()
    return {'there': lib is not None, 'said': '' if lib is not None else KRB_LIB['err']}


def _krb_words(lib, major, minor):
    out = []
    for code, kind in ((major, 1), (minor, 2)):
        if not code:
            continue
        ctx = ctypes.c_uint32(0)
        for _ in range(8):
            m, buf = ctypes.c_uint32(), _KrbBuf()
            if lib.gss_display_status(ctypes.byref(m), code, kind, None, ctypes.byref(ctx),
                                      ctypes.byref(buf)):
                break
            try:
                w = ctypes.string_at(buf.value, buf.length).decode('utf-8', 'replace').strip()
            finally:
                lib.gss_release_buffer(ctypes.byref(m), ctypes.byref(buf))
            if w and w not in out:
                out.append(w)
            if not ctx.value:
                break
    return '; '.join(out)[:300] or 'GSS-API status %#x/%d' % (major, minor)


def krb_is_ntlm(token):
    """NTLM - bare ("NTLMSSP\\0" at its start) or carried inside SPNEGO."""
    return b'NTLMSSP\x00' in bytes(token or b'')


def krb_accept(token, keytab):
    """The principal a ticket proves ('novak@CORP.EXAMPLE'), checked with the keys of `keytab`
    (a file) - or KrbError. Any principal whose key is in the keytab is taken (no name of our
    own given to the library): one key of the service account serves every name it has an SPN
    for."""
    token = bytes(token or b'')
    if not token:
        raise KrbError('no ticket')
    if len(token) > KRB_TOKEN_MAX:
        raise KrbError('larger than any Kerberos ticket')
    if krb_is_ntlm(token):
        raise KrbError('NTLM is never taken - only Kerberos')
    lib = krb_lib()
    if lib is None:
        raise KrbError(KRB_LIB['err'])
    with KRB_LOCK:
        ident = str(keytab)
        if KRB_LIB['ident'] != ident:
            if lib.krb5_gss_register_acceptor_identity(ident.encode('utf-8')):
                raise KrbError('the keytab could not be given to the Kerberos library')
            KRB_LIB['ident'] = ident
        minor, ctx = ctypes.c_uint32(), ctypes.c_void_p()
        src, flags = ctypes.c_void_p(), ctypes.c_uint32()
        raw = ctypes.create_string_buffer(token, len(token))
        inb = _KrbBuf(len(token), ctypes.cast(raw, ctypes.c_void_p))
        mech, out = ctypes.POINTER(_KrbOid)(), _KrbBuf()
        try:
            major = lib.gss_accept_sec_context(
                ctypes.byref(minor), ctypes.byref(ctx), None, ctypes.byref(inb), None,
                ctypes.byref(src), ctypes.byref(mech), ctypes.byref(out), ctypes.byref(flags),
                None, None)
            if major == 1:                  # GSS_S_CONTINUE_NEEDED: SPNEGO wants another round
                raise KrbError('more than one round - not Kerberos')
            if major != 0:
                raise KrbError('not taken: %s' % _krb_words(lib, major, minor.value))
            # The mechanism after accepting (as otp 1.0.274): SPNEGO may carry anything.
            if not mech or ctypes.string_at(mech.contents.elements,
                                            mech.contents.length) != KRB5_MECH:
                raise KrbError('a mechanism that is not Kerberos 5')
            name, m2 = _KrbBuf(), ctypes.c_uint32()
            if lib.gss_display_name(ctypes.byref(m2), src, ctypes.byref(name), None):
                raise KrbError('no name that can be read')
            try:
                return ctypes.string_at(name.value, name.length).decode('utf-8', 'replace')
            finally:
                lib.gss_release_buffer(ctypes.byref(m2), ctypes.byref(name))
        finally:
            m3 = ctypes.c_uint32()
            if out.value:
                lib.gss_release_buffer(ctypes.byref(m3), ctypes.byref(out))
            if src.value:
                lib.gss_release_name(ctypes.byref(m3), ctypes.byref(src))
            if ctx.value:
                lib.gss_delete_sec_context(ctypes.byref(m3), ctypes.byref(ctx), None)


def krb_split(principal):
    """('novak', 'CORP.EXAMPLE') of a person; a service (HTTP/x@R), a computer (PC1$) or an odd
    name refused."""
    p = str(principal or '')
    if p.count('@') != 1 or '/' in p or '\\' in p or re.search(r'[\x00-\x1f\x7f]', p):
        raise KrbError('%s is not the name of a person' % p[:200])
    user, realm = p.split('@', 1)
    if not user or not realm or user.endswith('$') or len(user) > 190:
        raise KrbError('%s is not the name of a person' % p[:200])
    return user, realm.upper()


def krb_token_from_header(value):
    """The bytes of "Negotiate <base64>", or KrbError."""
    v = str(value or '').strip()
    if len(v) > KRB_HEADER_MAX:
        raise KrbError('the header is larger than any Kerberos ticket')
    scheme = v.split(None, 1)[0].lower() if v else ''
    if scheme == 'ntlm':
        raise KrbError('NTLM is never taken - only Kerberos')
    if scheme != 'negotiate' or len(v.split(None, 1)) != 2:
        raise KrbError('no Negotiate ticket in the header')
    body = v.split(None, 1)[1].strip()
    if not re.match(r'^[A-Za-z0-9+/]{8,}={0,2}\Z', body):
        raise KrbError('the ticket is not base64')
    try:
        return base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        raise KrbError('the ticket is not base64')


def keytab_entries(raw):
    """[{principal, kvno, kind, weak}] of a keytab (format 0x0502) - the keys skipped, never
    kept or shown. ValueError when it is no keytab."""
    raw = bytes(raw or b'')
    if len(raw) < 2 or raw[0] != 5 or raw[1] != 2:
        raise ValueError('that is not a keytab (a keytab starts with the bytes 05 02)')
    out, i = [], 2
    while i + 4 <= len(raw):
        size = struct.unpack('>i', raw[i:i + 4])[0]
        i += 4
        if size == 0:
            break
        if size < 0:                        # a hole of a deleted entry
            i += -size
            continue
        end = i + size
        if end > len(raw):
            raise ValueError('the keytab ends in the middle of an entry')
        rec, j = raw[i:end], [0]

        def take(n):
            if j[0] + n > len(rec):
                raise ValueError('the keytab ends in the middle of an entry')
            b = rec[j[0]:j[0] + n]
            j[0] += n
            return b
        count = struct.unpack('>H', take(2))[0]
        realm = take(struct.unpack('>H', take(2))[0]).decode('utf-8', 'replace')
        comps = [take(struct.unpack('>H', take(2))[0]).decode('utf-8', 'replace')
                 for _ in range(count)]
        take(4)                             # the name type
        take(4)                             # when it was made
        kvno = take(1)[0]
        enc = struct.unpack('>H', take(2))[0]
        take(struct.unpack('>H', take(2))[0])     # the key itself: skipped
        if len(rec) - j[0] >= 4:
            kvno = struct.unpack('>I', rec[j[0]:j[0] + 4])[0] or kvno
        out.append({'principal': '%s@%s' % ('/'.join(comps), realm), 'kvno': kvno,
                    'kind': KRB_ENCTYPES.get(enc, 'type %d' % enc), 'weak': enc in KRB_WEAK})
        i = end
    if not out:
        raise ValueError('the keytab holds no key')
    if len(out) > 200:
        raise ValueError('the keytab holds %d keys - one service account\'s are a handful'
                         % len(out))
    return out


# ---- the keytab, kept in the database --------------------------------------------------------
def krb_keytab_row(store):
    """What the database keeps of the keytab ({sealed, sha, entries, at, by}) - its row read as
    signed (with db_guard on, one not written by acme reads as not there) - or None."""
    try:
        got = json.loads(store.get_meta(KRB_META) or 'null')
    except (ValueError, TypeError):
        return None
    return got if isinstance(got, dict) and got.get('sealed') else None


def krb_keytab_raw(store, row=None):
    """The keytab's bytes, unsealed - None when there is none or this node's key does not open
    it (another installation's database put in)."""
    row = row or krb_keytab_row(store)
    if not row:
        return None
    b64 = unseal_secret(str(row.get('sealed') or ''), KRB_BIND)
    if not b64:
        return None
    try:
        return base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None


def krb_keytab_view(row):
    if not row:
        return None
    return {'entries': row.get('entries') or [], 'at': row.get('at'), 'by': row.get('by') or '',
            'sha': str(row.get('sha') or '')[:12], 'name': row.get('name') or ''}


def krb_keytab_put(store, raw, by, name=''):
    """A keytab put in (the pages, acme --kerberos-keytab, a configuration file): checked, sealed
    and signed in the database; this node writes it out at once, the others within seconds."""
    raw = bytes(raw or b'')
    if not raw:
        raise ValueError('the keytab is empty')
    if len(raw) > KRB_KEYTAB_MAX:
        raise ValueError('the keytab is %s - one service account\'s is a few hundred bytes'
                         % bytes_words(len(raw)))
    entries = keytab_entries(raw)
    services = [e for e in entries if e['principal'].upper().startswith('HTTP/')]
    if not services:
        raise ValueError('the keytab holds no key of a web service (HTTP/name@REALM) - it has: %s'
                         % ', '.join(sorted({e['principal'] for e in entries}))[:300])
    if all(e['weak'] for e in services):
        raise ValueError('the keytab holds only weak keys (DES or RC4) - make it with '
                         '-crypto AES256-SHA1, and switch on "This account supports Kerberos AES '
                         '256 bit encryption" on the service account')
    row = {'sealed': seal_secret(base64.b64encode(raw).decode('ascii'), KRB_BIND),
           'sha': hashlib.sha256(raw).hexdigest(), 'entries': entries, 'at': time.time(),
           'by': str(by or '')[:120], 'name': os.path.basename(str(name or ''))[:120]}
    store.set_meta(KRB_META, json.dumps(row))
    KRB_STATE.update(have=True, checked=0.0)
    store.add_event('settings', '%s put in the keytab of the sign-in with Windows: %s'
                    % (by, ', '.join(sorted({'%s (kvno %s)' % (e['principal'], e['kvno'])
                                              for e in services}))[:600]), 'warn', who=by)
    if KRB_STATE['writer']:
        try:
            krb_write_out(store)
        except Exception as e:                          # noqa: BLE001
            log('the keytab could not be written out on %s: %s' % (node_name(), e), 'warn')
    return krb_keytab_view(row)


def krb_keytab_drop(store, by):
    had = krb_keytab_row(store) is not None or store.db.value(
        'SELECT 1 FROM meta WHERE k = ?', (KRB_META,))
    meta_drop(store, KRB_META)
    KRB_STATE.update(have=False, checked=0.0)
    if had:
        store.add_event('settings', '%s took the keytab of the sign-in with Windows away - nobody '
                        'signs in with Windows until another is put in' % by, 'warn', who=by)
    if KRB_STATE['writer']:
        try:
            krb_write_out(store)
        except Exception as e:                          # noqa: BLE001
            log('the keytab could not be taken away on %s: %s' % (node_name(), e), 'warn')
    return bool(had)


def krb_export(store, whole):
    """The keytab in an exported configuration: what it holds always, the keytab itself (in the
    clear, as every secret of a file with the secrets) only with them."""
    row = krb_keytab_row(store)
    if not row:
        return None
    out = {'entries': row.get('entries') or [], 'name': row.get('name') or '', 'at': row.get('at')}
    if whole:
        raw = krb_keytab_raw(store, row)
        if raw:
            out['keytab'] = base64.b64encode(raw).decode('ascii')
    return out


def krb_keytab_path():
    return Path(STATE_DIR) / 'kerberos' / 'http.keytab'


def krb_write_out(store):
    """The keytab as the database has it, written to this node's own file (0600, the service's
    user, the folder 0700) - or the file taken away when there is none. True when the file is
    as the database says."""
    path = krb_keytab_path()
    row = krb_keytab_row(store)
    if not row:
        if path.exists():
            path.unlink()
            log('the keytab of the sign-in with Windows is taken away on %s' % node_name())
        KRB_STATE.update(have=False, sha=None, written=False, error='')
        return True
    KRB_STATE['have'] = True
    raw = krb_keytab_raw(store, row)
    if raw is None:
        KRB_STATE.update(written=False, error='the keytab in the database does not open with '
                                              'this node\'s key (secrets.key) - put it in again')
        return False
    sha = hashlib.sha256(raw).hexdigest()
    try:
        now = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    except OSError:
        now = None
    if now != sha:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(path.parent), 0o700)
        fd, tmp = tempfile.mkstemp(prefix='.http.keytab.', dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(raw)
            os.replace(tmp, str(path))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        log('the keytab of the sign-in with Windows is written out on %s (%s)'
            % (node_name(), ', '.join(sorted({e['principal'] for e in row.get('entries') or []}))[:300]))
    KRB_STATE.update(sha=sha, written=True, error='')
    return True


def krb_tick(d):
    """Every node: the keytab written out as the database has it (put in on the other node, put
    back from a backup, taken away), the replay rows of past days tidied, and this node's state
    published for the card."""
    KRB_STATE['writer'] = True
    now = time.time()
    if now - KRB_STATE['checked'] < 15:
        return
    KRB_STATE['checked'] = now
    try:
        krb_write_out(d.store)
    except Exception as e:                              # noqa: BLE001
        KRB_STATE.update(written=False, error=str(e)[:300])
    lib = krb_lib_state()
    said = {'written': bool(KRB_STATE['written']), 'sha': str(KRB_STATE['sha'] or '')[:12],
            'lib': lib['there'], 'lib_said': lib['said'], 'error': KRB_STATE['error'],
            'fqdn': fqdn_cached(), 'version': __version__}
    if said != KRB_STATE['said'] or now - KRB_STATE['said_at'] > 300:
        d.store.set_meta(KRB_NODE_META + node_name(), json.dumps(dict(said, at=now)))
        KRB_STATE.update(said=said, said_at=now)
        krb_once_tidy(d.store)


def krb_once_tidy(store):
    """This node's rows of tickets taken, once their day is over."""
    t = time.time()
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE ?", (KRB_ONCE + ':%',)):
        if not str(r['k']).endswith(NODE_KEY_SEP + node_name()[:63]):
            continue
        try:
            times = [float(x) for x in json.loads(r['v'] or '[]')]
        except (ValueError, TypeError):
            times = []
        if not any(t - x < KRB_ONCE_S for x in times):
            store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (r['k'], r['v']))


def krb_have(store=None):
    """Whether a keytab is put in - as this node last read it (the health check asks it often)."""
    if KRB_STATE['have'] is None and store is not None:
        KRB_STATE['have'] = krb_keytab_row(store) is not None
    return bool(KRB_STATE['have'])


# ---- each part's switches ------------------------------------------------------------------
def krb_directory_name(part):
    if part == 'admin':
        return str(CONFIG.get('admin_directory') or '').strip()
    return str(CONFIG.get('portal_directory') or CONFIG.get('admin_directory') or '').strip()


def krb_on(part):
    """Whether a part signs people in with Windows: its switch, and a directory to find them in
    (the portal: the portal switched on as well)."""
    if part == 'admin':
        return bool(CONFIG.get('admin_krb') and krb_directory_name('admin'))
    return bool(CONFIG.get('portal') and CONFIG.get('portal_krb') and krb_directory_name('portal'))


def krb_password_off(part, store=None):
    """"Only Windows" in effect: switched on, and Kerberos able to sign anybody in - on, with a
    keytab. Off, or Kerberos off (the way back), and passwords are taken again."""
    return bool(CONFIG.get(part + '_password_off') and krb_on(part) and krb_have(store))


def krb_page_info(part):
    """What a sign-in page shows of it: the button, tried by itself, no password - nothing else
    (asked before anybody is signed in)."""
    on = krb_on(part) and krb_have()
    return {'on': bool(on), 'auto': bool(on and CONFIG.get(part + '_krb_auto')),
            'only': bool(on and krb_password_off(part))}


def realm_from_base(base):
    """CORP.EXAMPLE of DC=corp,DC=example (the directory's base DN)."""
    dcs = [x.split('=', 1)[1].strip() for x in re.split(r'(?<!\\),', str(base or ''))
           if x.strip().lower().startswith('dc=') and '=' in x]
    return '.'.join(dcs).upper()


def krb_realm(d, part):
    """(realm, where from): the one set, else the one of the part's directory's base DN."""
    own = str(CONFIG.get(part + '_krb_realm') or '').strip().upper()
    if own:
        return own, 'set'
    ad = d.dirs.get(krb_directory_name(part).lower())
    if ad is None:
        row = d.store.directory(krb_directory_name(part)) if krb_directory_name(part) else None
        base = (row or {}).get('base') or ''
    else:
        base = ad.base
    got = realm_from_base(base)
    return got, ('directory' if got else '')


def krb_proof_of(h, s):
    """Whether this save may switch "only Windows" on, part by part: the administrator's own
    sign-in made with Windows; for the portal, a sign-in to the portal made with Windows in the
    same browser (its cookie, passed on by the page as X-Acme-Portal-Session)."""
    proof = {'admin': str((s.get('data') or {}).get('how') or '') == 'Kerberos', 'portal': False}
    token = str(h.headers.get('X-Acme-Portal-Session') or '')
    if token:
        try:
            ps = h.store.session_get(token, 'portal', int(CONFIG.get('portal_session_min') or 15)
                                     * 60, touch=False)
        except Exception:                               # noqa: BLE001
            ps = None
        data = (ps or {}).get('data') or {}
        proof['portal'] = bool(ps and data.get('how') == 'Kerberos' and not data.get('gate_wait'))
    return proof


# ---- a ticket taken -------------------------------------------------------------------------
def krb_ticket(h, part, b, try_only=False):
    """The checks both parts share: the header read, the ticket accepted with the keytab (written
    out first if this node has not yet), the realm the part takes, and the ticket never seen
    before in the cluster. (user, principal), or KrbRefused."""
    if b.get('too_big'):
        raise KrbRefused('the browser sent a header larger than any Kerberos ticket')
    header = str(b.get('header') or '')
    try:
        token = krb_token_from_header(header)
    except KrbError as e:
        raise KrbRefused(str(e))
    row = krb_keytab_row(h.store)
    if not row:
        raise KrbRefused('no keytab is put in yet (Settings → Accounts → Signing in with Windows)',
                         status=503)
    if not KRB_STATE.get('written') or KRB_STATE.get('sha') != row.get('sha'):
        try:
            krb_write_out(h.store)
        except Exception as e:                          # noqa: BLE001
            raise KrbRefused('the keytab could not be written out on this node', str(e), 503)
        if not KRB_STATE.get('written'):
            raise KrbRefused('the keytab could not be written out on this node',
                             KRB_STATE.get('error') or '', 503)
    try:
        principal = krb_accept(token, krb_keytab_path())
        user, realm = krb_split(principal)
    except KrbError as e:
        raise KrbRefused(str(e))
    want, _ = krb_realm(h.d, part)
    if not want:
        raise KrbRefused('the realm is not known: set it, or a base DN of the directory',
                         status=503)
    if realm != want:
        raise KrbRefused('%s is of the realm %s, and only %s signs in here' % (principal, realm,
                                                                               want))
    # Once in the whole cluster (as otp 1.0.274): a hash of the whole token - unique to one
    # request, it carries an authenticator of its own - kept a day.
    if not node_key_add(h.store, KRB_ONCE, hashlib.sha256(token).hexdigest(), KRB_ONCE_S,
                        limit=1):
        raise KrbRefused('this ticket was used already (sent again?)',
                         'the ticket of %s was used already - sent again (a replay?)' % principal)
    return user, principal


def krb_refused_event(h, part, why, principal=''):
    kind = 'sign-ins' if part == 'admin' else 'portal'
    log_sparing('krb-refused:%s:%s' % (part, str(why)[:40]),
                'a sign-in with Windows to %s from %s was refused: %s'
                % ('these pages' if part == 'admin' else 'the enrolment pages', h.client_ip(), why),
                'warn', every=300)
    h.store.add_event(kind, 'a sign-in with Windows (Kerberos) was refused (from %s%s): %s'
                      % (h.client_ip(), ', for %s' % principal if principal else '', why), 'warn',
                      who=principal.split('@', 1)[0] if principal else None)


def krb_local_same(h, user):
    """A local account of the same name keeps its password (as otp 1.0.274): the ticket of a
    directory person never signs in as it."""
    acc = h.store.account(user)
    return bool(acc and acc.get('source') != 'directory')


def krb_admin_would(h, user, principal):
    """Who the ticket signs in to the administration, and as what - nothing made. KrbRefused."""
    if krb_local_same(h, user):
        raise KrbRefused('%s is an account of this server - it signs in with its password' % user)
    said = admin_ask_directory(h, user, None, ticket=True)
    if said is None:
        raise KrbRefused('no directory is set (or switched on) for administrators', status=503)
    if not said['ok']:
        raise KrbRefused('the directory does not let %s in: %s' % (user, said.get('said') or '?'))
    if said['role'] == 'portal':
        raise KrbRefused('%s signs in on the enrolment pages only, not here' % principal,
                         status=403)
    if not said['role']:
        raise KrbRefused('%s is known to the directory, and none of the groups given a role here '
                         'holds them' % principal)
    bad = name_letters_problem(said['name'])
    if bad:
        raise KrbRefused('%s: %s' % (principal, bad))
    return said


def krb_portal_would(h, user, principal):
    """Who the ticket signs in to the portal - the portal's directory, its rules of who may - and
    the entry; nothing made. KrbRefused."""
    if krb_local_same(h, user):
        raise KrbRefused('%s is an account of this server - it signs in with its password' % user)
    ad = portal_directory(h)
    if not ad:
        raise KrbRefused('no directory is set (or switched on) for the enrolment pages', status=503)
    try:
        entry = ad.find_user(user, 'sam')
    except LdapUnreachable:
        raise KrbRefused('the directory cannot be reached just now', status=503)
    if not entry:
        raise KrbRefused('the directory does not let %s in: there is no such account' % user)
    if entry.get('many'):
        raise KrbRefused('the directory does not let %s in: more than one account answers to '
                         'that name' % user)
    if entry_unusable(entry):
        raise KrbRefused('the directory does not let %s in: %s' % (user, entry_unusable(entry)))
    bad = name_letters_problem(user)
    if bad:
        raise KrbRefused('%s: %s' % (principal, bad))
    groups = []
    if (CONFIG.get('portal_who') or 'anyone') == 'groups':
        wanted = [{'group': g} for g in dn_list(CONFIG.get('portal_groups'))]
        if CONFIG.get('portal_enrolers', 1):
            wanted += [{'group': g} for g in dn_list(CONFIG.get('admin_group_portal'))]
        have = ad.groups_of(entry, True)
        for w in wanted:
            try:
                if group_matches([w], have, ad):
                    groups.append(cn_of(w['group']) or w['group'])
            except Exception:                           # noqa: BLE001
                pass
        if not groups:
            raise KrbRefused('%s is known to the directory, and in none of the groups that may '
                             'use the enrolment pages' % principal, status=403)
    return ad, entry, groups


def krb_body(h):
    b = h.body()
    if len(str(b.get('header') or '')) > KRB_HEADER_MAX + 100:
        b = {'too_big': True}
    return b


@route('POST', '/api/auth/kerberos')
def _auth_kerberos(h):
    """The administration's sign-in with a ticket: {header} as the browser sent it ("Negotiate
    ...") - relayed by the page, which turns every 401 here into 403."""
    if not krb_on('admin'):
        raise ApiError(404, 'signing in with Windows is switched off here')
    b = krb_body(h)
    if not b.get('header') and not b.get('too_big'):
        # The first round: the page answers 401 with Negotiate and the browser sends its ticket.
        raise ApiError(401, 'the browser sent no Kerberos ticket')
    tries = max(20, 4 * split_limit('login_tries', 5))
    key = h.throttle('kerberos', tries, int(CONFIG.get('login_wait_min') or 15),
                     what='refused sign-ins with Windows')
    principal = ''
    try:
        user, principal = krb_ticket(h, 'admin', b)
        said = krb_admin_would(h, user, principal)
        acc = admin_directory_account(h, said)
        if not acc:
            raise KrbRefused('%s is an account of this server - it signs in with its password'
                             % user)
        if acc.get('disabled'):
            raise KrbRefused('%s is switched off here (Accounts)' % acc['name'])
        if acc.get('role') == 'portal':
            raise KrbRefused(PORTAL_ONLY_SAID, status=403)
    except KrbRefused as e:
        h.failed(key)
        krb_refused_event(h, 'admin', e.why, principal)
        raise ApiError(401 if e.status == 403 else e.status, e.said)
    # The second step, as after a password (1.0.125): Kerberos takes the password's place only.
    stage = mfa_stage(h.store, acc['name']) if CONFIG.get('admin_2fa') else ''
    if stage == 'lost':
        h.failed(key)
        h.store.add_event('sign-ins', '%s could not sign in with Windows from %s: the second step '
                          'it had set up is gone without a reset' % (acc['name'], h.client_ip()),
                          'bad')
        raise ApiError(401, MFA_LOST_SAID)
    data = {'how': 'Kerberos', 'principal': principal}
    if stage:
        data['mfa'] = stage
    token = h.store.session_new('admin', acc['name'], acc['role'], h.client_ip(),
                                CONFIG.get('session_hours') or 12, data=data)
    h.store.set_account(acc['name'], last_in=time.time(), last_from=h.client_ip())
    h.store.add_event('sign-ins', '%s signed in from %s with Windows (Kerberos, %s)%s' % (
        acc['name'], h.client_ip(), principal, {'check': ' - the second step to give',
                                                 'enrol': ' - the second step to set up'}
        .get(stage, '')), who=acc['name'])
    split_note(h.store, 'signin', acc['name'], 'signin:admin:' + str(acc['name']).lower())
    return {'token': token, 'who': {'name': acc['name'], 'role': acc['role'] if not stage else ''},
            'must_change': False, 'mfa': stage, 'how': 'Kerberos'}


@route('POST', '/api/portal/kerberos')
def _portal_kerberos(h):
    """The portal's sign-in with a ticket - its own switch, its own directory and rules."""
    if not krb_on('portal'):
        raise ApiError(404, 'signing in with Windows is switched off here')
    b = krb_body(h)
    if not b.get('header') and not b.get('too_big'):
        raise ApiError(401, 'the browser sent no Kerberos ticket')
    tries = max(20, 4 * split_limit('portal_tries', 5))
    key = h.throttle('portal-kerberos', tries, int(CONFIG.get('portal_wait_min') or 15),
                     what='refused sign-ins with Windows')
    principal = ''
    try:
        user, principal = krb_ticket(h, 'portal', b)
        ad, entry, _groups = krb_portal_would(h, user, principal)
    except KrbRefused as e:
        h.failed(key)
        krb_refused_event(h, 'portal', e.why, principal)
        raise ApiError(401 if e.status == 403 else e.status, e.said)
    # Somebody else signed in in this browser before (a shared machine): that one ends.
    if h.headers.get('X-Acme-Session'):
        h.store.session_end(h.headers.get('X-Acme-Session'))
    try:
        got = portal_open_dir(h, key, user, ad, entry, how='Kerberos')
    except ApiError as e:
        krb_refused_event(h, 'portal', str(e), principal)
        raise ApiError(401 if e.status in (401, 403) else e.status, str(e))
    return dict(got, how='Kerberos')


@route('POST', '/api/kerberos/try')
def _kerberos_try(h):
    """Try my browser's ticket (the card): who it would sign in to that part, and as what -
    nobody signed in. Works before the part is switched on: the way to find a wrong SPN first."""
    h.me('readonly')
    b = krb_body(h)
    part = str(b.get('part') or 'admin')
    if part not in KRB_PARTS:
        raise ApiError(400, 'admin or portal')
    if not b.get('header') and not b.get('too_big'):
        raise ApiError(401, 'the browser sent no Kerberos ticket')
    key = h.throttle('kerberos', max(20, 4 * split_limit('login_tries', 5)),
                     int(CONFIG.get('login_wait_min') or 15), what='refused sign-ins with Windows')
    out = {'part': part, 'on': krb_on(part)}
    try:
        user, principal = krb_ticket(h, part, b, try_only=True)
    except KrbRefused as e:
        h.failed(key)
        return dict(out, ok=False, ticket=False, said=e.said)
    out.update(ticket=True, principal=principal)
    try:
        if part == 'admin':
            said = krb_admin_would(h, user, principal)
            out.update(ok=True, name=said['name'], role=said['role'],
                       display=said.get('display') or '',
                       second=bool(CONFIG.get('admin_2fa')))
        else:
            _ad, entry, groups = krb_portal_would(h, user, principal)
            out.update(ok=True, name=str(entry.get('upn') or entry.get('sam') or user).lower(),
                       role='portal', display=entry.get('display') or '', groups=groups[:10],
                       second=portal_gate_needed())
    except KrbRefused as e:
        out.update(ok=False, said=e.said)
    return out


# ---- the card ---------------------------------------------------------------------------------
def krb_names(store, here=''):
    """The names the pages are opened by: the VIP address's, each node's (as acme orders their
    certificates, and as each node says its own), and the one this page was opened by."""
    out = []

    def add(name, of):
        n = str(name or '').strip().lower().rstrip('.')
        if not n or not re.match(r'^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?\Z', n):
            return
        if '.' not in n or n.startswith('localhost'):
            return                          # a name of the machine alone: the browsers' SPN is the full one
        try:
            ipaddress.ip_address(n)
            return                          # an address has no SPN (Windows then offers NTLM)
        except ValueError:
            pass
        if n in [x['name'] for x in out]:
            return
        out.append({'name': n, 'of': of})
    try:
        if vip_conf(store).get('on') or vip_conf(store).get('address'):
            add(acme_name_of(store, 'vip'), 'vip')
    except Exception:                                   # noqa: BLE001
        pass
    nodes = sorted(set([node_name()] + [n['name'] for n in ha_nodes(store)]))
    for n in nodes:
        try:
            add(acme_name_of(store, n), n)
        except Exception:                               # noqa: BLE001
            pass
        st = krb_node_state(store, n)
        add(st.get('fqdn'), n)
    host = str(here or '').strip().lower()
    host = re.sub(r':\d+\Z', '', host)
    add(host, 'this page')
    return out


def krb_node_state(store, n):
    try:
        got = json.loads(store.get_meta(KRB_NODE_META + n) or '{}')
    except (ValueError, TypeError):
        got = {}
    return got if isinstance(got, dict) else {}


def krb_view(h):
    store = h.store
    row = krb_keytab_row(store)
    keytab = krb_keytab_view(row)
    principals = {e['principal'].upper() for e in (row or {}).get('entries') or []}
    parts = {}
    for part in KRB_PARTS:
        realm, where = krb_realm(h.d, part)
        parts[part] = {
            'on': krb_on(part), 'switch': bool(CONFIG.get(part + '_krb')),
            'auto': bool(CONFIG.get(part + '_krb_auto')),
            'password_off': bool(CONFIG.get(part + '_password_off')),
            'only_in_effect': krb_password_off(part, store),
            'realm': realm, 'realm_from': where, 'directory': krb_directory_name(part),
            'second': bool(CONFIG.get('admin_2fa')) if part == 'admin' else portal_gate_needed()}
    parts['portal']['portal'] = bool(CONFIG.get('portal'))
    parts['portal']['who'] = CONFIG.get('portal_who') or 'anyone'
    parts['portal']['sso'] = bool(CONFIG.get('portal_sso'))
    realms = sorted({p['realm'] for p in parts.values() if p['realm']})
    names = []
    for one in krb_names(store, h.headers.get('X-Acme-Host') or ''):
        spn = 'HTTP/%s' % one['name']
        by_name = [r for r in realms if ('%s@%s' % (spn, r)).upper() in principals]
        one.update(spn=spn, in_keytab='name' if by_name else ('key' if principals else ''))
        names.append(one)
    nodes = []
    now = time.time()
    for n in sorted(set([node_name()] + [x['name'] for x in ha_nodes(store)])):
        st = krb_node_state(store, n)
        if n == node_name() and KRB_STATE['writer']:      # the daemon's own, as it is now
            lib = krb_lib_state()
            st = dict(st, lib=lib['there'], lib_said=lib['said'],
                      written=bool(KRB_STATE['written']), error=KRB_STATE['error'],
                      sha=str(KRB_STATE['sha'] or '')[:12], at=st.get('at') or now)
        nodes.append({'node': n, 'me': n == node_name(),
                      'heard': bool(st) and now - float(st.get('at') or 0) < 900,
                      'at': st.get('at'), 'written': bool(st.get('written')),
                      'same': bool(keytab and st.get('sha') and st.get('sha') == keytab['sha']),
                      'lib': bool(st.get('lib')), 'lib_said': st.get('lib_said') or '',
                      'error': st.get('error') or '', 'version': st.get('version') or ''})
    domain = realms[0].split('.', 1)[0] if realms else 'CORP'
    return {'keytab': keytab, 'parts': parts, 'names': names, 'nodes': nodes, 'realms': realms,
            'domain': domain, 'account': 'svc-acme-http', 'lib': krb_lib_state(),
            'ntlm': 'never taken'}


@route('GET', '/api/kerberos')
def _kerberos_view(h):
    h.me('readonly')
    return krb_view(h)


@route('POST', '/api/kerberos')
def _kerberos_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    if act == 'put':
        data = str(b.get('data') or '')
        if data.startswith('data:'):
            data = data.split(',', 1)[-1]
        try:
            raw = base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            raise ApiError(400, 'the keytab did not arrive whole')
        try:
            krb_keytab_put(h.store, raw, s['name'], str(b.get('name') or ''))
        except ValueError as e:
            raise ApiError(400, str(e))
        return {'message': 'the keytab is put in', 'view': krb_view(h)}
    if act == 'drop':
        if not krb_keytab_drop(h.store, s['name']):
            raise ApiError(404, 'there is no keytab to take away')
        return {'message': 'the keytab is taken away', 'view': krb_view(h)}
    raise ApiError(400, 'no such thing to do')
